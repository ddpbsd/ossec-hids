/* Copyright (C) 2019 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations */

#include <event.h>

#include "shared.h"
#include "os_net/os_net.h"
#include "maild.h"
#include "mail_list.h"
#include "os_dns.h"

#ifdef USE_LIBTLS
#include <tls.h>
#endif	//USE_LIBTLS

/* Return codes (from SMTP server) */
#define VALIDBANNER     "220"
#define VALIDMAIL       "250"
#define VALIDDATA       "354"

/* Default values used to connect */
#define SMTP_DEFAULT_PORT   "25"
#define MAILFROM            "Mail From: <%s>\r\n"
#define RCPTTO              "Rcpt To: <%s>\r\n"
#define DATAMSG             "DATA\r\n"
#define FROM                "From: OSSEC HIDS <%s>\r\n"
#define TO                  "To: <%s>\r\n"
#define REPLYTO             "Reply-To: OSSEC HIDS <%s>\r\n"
/*#define CC                "Cc: <%s>\r\n"*/
#define SUBJECT             "Subject: %s\r\n"
#define ENDHEADER           "\r\n"
#define ENDDATA             "\r\n.\r\n"
#define QUITMSG             "QUIT\r\n"
#define XHEADER             "X-IDS-OSSEC: %s\r\n"

/* Error messages - Can be translated */
#define INTERNAL_ERROR  "os_maild (1760): ERROR: Memory/configuration error"
#define BANNER_ERROR    "os_sendmail(1762): WARN: Banner not received from server"
#define HELO_ERROR      "os_sendmail(1763): WARN: Hello not accepted by server"
#define FROM_ERROR      "os_sendmail(1764): WARN: Mail from not accepted by server"
#define TO_ERROR        "os_sendmail(1765): WARN: RCPT TO not accepted by server - '%s'."
#define DATA_ERROR      "os_sendmail(1766): WARN: DATA not accepted by server"
#define END_DATA_ERROR  "os_sendmail(1767): WARN: End of DATA not accepted by server"

#define MAIL_DEBUG_FLAG     0
#define MAIL_DEBUG(x,y,z) if(MAIL_DEBUG_FLAG) merror(x,y,z)

int os_sock, istls;

void os_sendmail_cb(int fd, short ev, void *arg) {

    if (fd) { }
    if (ev) {}


    /* Have to get the *arg stuff */
    ssize_t n;
    struct imsg imsg;
    struct imsgbuf *ibuf = (struct imsgbuf *)arg;

    if ((n = imsg_read(ibuf) == -1 && errno != EAGAIN)) {
        ErrorExit("%s: ERROR: imsg_read() failed: %s", ARGV0, strerror(errno));
    }
    if (n == 0) {
        //debug2("%s: DEBUG: n == 0", ARGV0);
        //return; //XXX
    }
    if (n == EAGAIN) {
        merror("%s: DEBUG: n == EAGAIN (os_sendmail_cb())", ARGV0);
        return; //XXX
    }

    if ((n = imsg_get(ibuf, &imsg)) == -1) {
        merror("%s: ERROR: imsg_get() failed: %s", ARGV0, strerror(errno));
        return;
    }
    if (n == 0) {
        //debug2("%s: DEBUG: n == 0", ARGV0);
        return;
    }

    switch(imsg.hdr.type) {
        case DNS_RESP:
            os_sock = imsg.fd;
            break;
        case DNS_FAIL:
            merror("%s: ERROR: DNS failure for smtpserver", ARGV0);
            break;;
        default:
            merror("%s: ERROR Wrong imsg type.", ARGV0);
            break;
    }



    return;
}



int OS_Sendmail(MailConfig *mail, struct tm *p)
{

#if __OpenBSD__
    setproctitle("[OS_Sendmail]");
#endif

    FILE *sendmail = NULL;
    os_sock = -1;
    unsigned int i = 0;
    char *msg;
    char snd_msg[128];
    istls = 0;

    MailNode *mailmsg;

    /* If there is no sms message, attempt to get from the email list */
    mailmsg = OS_PopLastMail();

    if (mailmsg == NULL) {
        merror("%s: No email to be sent. Inconsistent state.", ARGV0);
        return (OS_INVALID);
    }


    if (mail->smtpserver[0] == '/') {
        sendmail = popen(mail->smtpserver, "w");
        if (!sendmail) {
            return (OS_INVALID);
        }
    } else {
        /* Try to use os_dns =] */

        /* setup the libevent stuff */
        struct event_base *eb;
        eb = event_init();
        if (!eb) {
            ErrorExit("%s: ERROR: event_init() failed.", ARGV0);
        }

#ifdef USE_LIBTLS
        struct tls_config *cfg = NULL;
        struct tls *ctx = NULL;

        if (mail->use_tls == 1) {
            /* initialize tls context */
            if ((tls_init()) == -1) {
                merror("%s: use_tls() failed.", ARGV0);
                return (OS_INVALID);
            }
            if ((cfg = tls_config_new()) == NULL) {
                merror("%s: tls_config_new() failed.", ARGV0);
                return (OS_INVALID);
            }
            if (tls_config_set_ca_file(cfg, mail->ca_file) != 0) {
                merror("%s: Cannot set ca file.", ARGV0);
                return (OS_INVALID);
            }
            if ((ctx = tls_client()) == NULL) {
                merror("%s: tls_client() failed.", ARGV0);
                return(OS_INVALID);
            }
            /* Apply the ctx to cfg */
            if (tls_configure(ctx, cfg) != 0) {
                merror("%s: tls_configure() failed.", ARGV0);
                return(OS_INVALID);
            }

        }
#endif //USE_LIBTLS

        struct event ev_accept;
        struct timeval event_tv;
        event_tv.tv_sec = 10;
        event_tv.tv_usec = 0;
        event_set(&ev_accept, mail->ibuf.fd, EV_READ, os_sendmail_cb, &mail->ibuf);
        if ((event_add(&ev_accept, &event_tv)) == -1) {
            merror("%s [OS_Sendmail]: ERROR: event_add error: %s", ARGV0, strerror(errno));
        }

        ssize_t n;
        int idata = 42;

        if ((imsg_compose(&mail->ibuf, DNS_REQ, 0, 0, -1, &idata, sizeof(idata))) == -1) {
            merror("%s: ERROR: imsg_compose() error: %s", ARGV0, strerror(errno));
        }

        if ((n = msgbuf_write(&mail->ibuf.w)) == -1 && errno != EAGAIN) {
            merror("%s: ERROR: msgbuf_write() error: %s", ARGV0, strerror(errno));
        }
        if (n == 0) {
            //debug2("%s: INFO: (write) n == 0", ARGV0);
        }

        event_dispatch();

        if (os_sock <= 0) {
            //ErrorExit("ossec-maild: ERROR: No socket.");
            merror("ossec-maild: ERROR: No socket.");
            return (OS_INVALID);
        }

        /* Receive the banner */
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
        free(msg);

        /* Send HELO message */
        memset(snd_msg, '\0', 128);
        if (mail->heloserver) {
            snprintf(snd_msg, 127, "Helo %s\r\n", mail->heloserver);
        } else {
            snprintf(snd_msg, 127, "Helo %s\r\n", "notify.ossec.net");
        }
        OS_SendTCP(os_sock, snd_msg);
        msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(os_sock);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(os_sock);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(os_sock);
                return (OS_INVALID);
            }
        }

        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

#ifdef USE_LIBTLS
        if(mail->use_tls == 1) {
            /* Try to STARTTLS */
            OS_SendTCP(os_sock, "STARTTLS\r\n");
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
                merror("%s: ERROR: Cannot STARTTLS", ARGV0);
                close(os_sock);
                return (OS_INVALID);
            } else {
                istls = 1;
            }
            /* Resend the HELO */
            if ((tls_write(ctx, snd_msg, sizeof(snd_msg))) == -1) {
                merror("%s: ERROR: Cannot send second HELO.", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, msg, sizeof(msg))) == -1) {
                merror("%s: ERROR: Cannot read HELO banner.", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror("%s:%s", HELO_ERROR, "null");
                close(os_sock);
                return (OS_INVALID);
            }
        }
#endif //USE_LIBTLS

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, MAILFROM, mail->from);
#ifdef USE_TLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, sizeof(snd_msg))) == -1) {
                merror(FROM_ERROR);
                if (msg) {
                    free(msg);
                }
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, msg, OS_SIZE_1024)) == -1) {
                merror("%s: ERROR: Cannot tls_read MAILFROM", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(FROM_ERROR);
                if (msg) {
                   free(msg);
                }
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_TLS

            OS_SendTCP(os_sock, snd_msg);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(FROM_ERROR);
                if (msg) {
                    free(msg);
                }
                close(os_sock);
                return (OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS

        /* Build "RCPT TO" msg */
        while (1) {
            if (mail->to[i] == NULL) {
                if (i == 0) {
                    merror(INTERNAL_ERROR);
                    close(os_sock);
                    return (OS_INVALID);
                }
                break;
            }
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, mail->to[i++]);
#ifdef USE_LIBTLS
            if (istls == 1) {
                if ((tls_write(ctx, snd_msg, sizeof(snd_msg))) == -1) {
                    merror("%s: ERROR: rcpt to failed.", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
                if ((tls_read(ctx, msg, sizeof(msg))) == -1) {
                    merror("%s: ERROR: cannot read rcpt to response.", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
            } else {
#endif //USE_LIBTLS
                OS_SendTCP(os_sock, snd_msg);
                msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
#ifdef USE_LIBTLS
            }
#endif //USE_LIBTLS
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(TO_ERROR, mail->to[i - 1]);
                if (msg) {
                    free(msg);
                }
                close(os_sock);
                return (OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);
        }

        /* Additional RCPT to */
        if (mail->gran_to) {
            i = 0;
            while (mail->gran_to[i] != NULL) {
                if (mail->gran_set[i] != FULL_FORMAT) {
                    i++;
                    continue;
                }

                memset(snd_msg, '\0', 128);
                snprintf(snd_msg, 127, RCPTTO, mail->gran_to[i]);
#ifdef USE_LIBTLS
                if (istls == 1) {
                    if ((tls_write(ctx, snd_msg, sizeof(snd_msg))) == -1) {
                        merror("%s: ERROR: Cannot send rcptto", ARGV0);
                        close(os_sock);
                        return(OS_INVALID);
                    }
                    if ((tls_read(ctx, msg, sizeof(msg))) == -1) {
                        merror("%s: ERROR: Cannot receive rcptto response.", ARGV0);
                        close(os_sock);
                        return (OS_INVALID);
                    }
                } else {
#endif //USE_LIBTLS
                    OS_SendTCP(os_sock, snd_msg);
                    msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
#ifdef USE_LIBTLS
                }
#endif //USE_LIBTLS
                if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                    merror(TO_ERROR, mail->gran_to[i]);
                    if (msg) {
                        free(msg);
                    }

                    i++;
                    continue;
                }

                MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
                free(msg);
                i++;
                continue;
            }
        }

        /* Send the "DATA" msg */
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, DATAMSG, sizeof(DATAMSG))) == -1) {
                merror("%s: ERROR: Cannot send DATAMSG", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, msg, sizeof(msg))) == -1) {
                merror("%s: ERROR: Cannot receive DATAMSG response.", ARGV0);
                close(os_sock);
                return (OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS

            OS_SendTCP(os_sock, DATAMSG);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
#ifdef USE_LIBTLS
        }
#endif //USE_TLS
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
        free(msg);
    }

    /* Building "From" and "To" in the e-mail header */
    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, TO, mail->to[0]);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                merror("%s: ERROR: Cannot send To", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS
    }

    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, FROM, mail->from);

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                merror("%s: ERROR: Cannot send From", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
        }
#endif
    }

    /* Send reply-to if set */
    if (mail->reply_to){
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, REPLYTO, mail->reply_to);
        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
#ifdef USE_LIBTLS
            if (istls == 1) {
                if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                    merror("%s: ERROR: Cannot send reply_to", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
            } else {
#endif //USE_LIBTLS
                OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
            }
#endif //USE_LIBTLS
        }
    }

    /* Add CCs */
    if (mail->to[1]) {
        i = 1;
        while (1) {
            if (mail->to[i] == NULL) {
                break;
            }

            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, TO, mail->to[i]);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
#ifdef USE_LIBTLS
                if (istls == 1) {
                    if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                        merror("%s: ERROR: Cannot send mail to cc", ARGV0);
                        close(os_sock);
                        return(OS_INVALID);
                    }
                } else {
#endif //USE_LIBTLS
                    OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
                }
#endif //USE_LIBTLS
            }

            i++;
        }
    }

    /* More CCs - from granular options */
    if (mail->gran_to) {
        i = 0;
        while (mail->gran_to[i] != NULL) {
            if (mail->gran_set[i] != FULL_FORMAT) {
                i++;
                continue;
            }

            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, TO, mail->gran_to[i]);

            if (sendmail) {
                fprintf(sendmail, "%s", snd_msg);
            } else {
#ifdef USE_LIBTLS
                if (istls == 1) {
                    if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                        merror("%s: ERROR: Cannot send granular to", ARGV0);
                        close(os_sock);
                        return(OS_INVALID);
                    }
                } else {
#endif //USE_LIBTLS
                    OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
                }
#endif //USE_LIBTLS
            }

            i++;
            continue;
        }
    }

    /* Send date */
    memset(snd_msg, '\0', 128);

    /* Solaris doesn't have the "%z", so we set the timezone to 0 */
#ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
    } else {
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                merror("%s: ERROR: Cannot send date", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS
    }

    if (mail->idsname) {
        /* Send server name header */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, XHEADER, mail->idsname);

        if (sendmail) {
            fprintf(sendmail, "%s", snd_msg);
        } else {
#ifdef USE_LIBTLS
            if (istls == 1) {
                if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                    merror("%s: ERROR: Cannot send idsname", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
            } else {
#endif //USE_LIBTLS
                OS_SendTCP(os_sock, snd_msg);
#ifdef USE_LIBTLS
            }
#endif //USE_LIBTLS
        }
    }

    /* Send subject */
    memset(snd_msg, '\0', 128);

    /* Check if global subject is available */
    if ((_g_subject_level != 0) && (_g_subject[0] != '\0')) {
        snprintf(snd_msg, 127, SUBJECT, _g_subject);

        /* Clear global values */
        _g_subject[0] = '\0';
        _g_subject_level = 0;
    } else {
        snprintf(snd_msg, 127, SUBJECT, mailmsg->mail->subject);
    }

    if (sendmail) {
        fprintf(sendmail, "%s", snd_msg);
        fprintf(sendmail, ENDHEADER);
    } else {
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, strnlen(snd_msg, OS_SIZE_1024))) == -1) {
                merror("%s: ERROR: Cannot send subject", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_write(ctx, ENDHEADER, strnlen(ENDHEDER, 1024))) == -1) {
                merror("%s: ERROR: Cannot send ENDHEADER", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, snd_msg);
            OS_SendTCP(os_sock, ENDHEADER);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS
    }

    /* Send body */

    /* Send multiple emails together if we have to */
    do {
        if (sendmail) {
            fprintf(sendmail, "%s", mailmsg->mail->body);
        } else {
#ifdef USE_LIBTLS
            if (istls == 1) {
                if ((tls_write(ctx, mailmsg->mail->body, sizeof(mailmsg->mail->body))) == -1) {
                    merror("%s: ERROR: Cannot send body", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
            } else {
#endif //USE_LIBTLS
                OS_SendTCP(os_sock, mailmsg->mail->body);
#ifdef USE_LIBTLS
            }
#endif //USE_LIBTLS
        }
        mailmsg = OS_PopLastMail();
    } while (mailmsg);

    if (sendmail) {
        if (pclose(sendmail) == -1) {
            merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
        }
    } else {
        /* Send end of data \r\n.\r\n */
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, ENDDATA, strnlen(ENDDATA))) == -1) {
                merror("%s: ERROR: Cannot send ENDDATA", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, msg, sizeof(msg))) == -1) {
                merror("%s: ERROR: Cannot receive ENDDATA response.", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, ENDDATA);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS
        if (mail->strict_checking && ((msg == NULL) || (!OS_Match(VALIDMAIL, msg)))) {
            merror(END_DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(os_sock);
            return (OS_INVALID);
        }

        /* Check msg, since it may be null */
        if (msg) {
            free(msg);
        }

        /* Quit and close os_sock */
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, QUITMSG, strnlen(QUITMSG, 1024))) == -1) {
                merror("%s: ERROR: Cannot send QUITMSG", ARGV0);
            }
            if ((tls_write(ctx, msg, sizeof(msg))) == -1) {
                merror("%s: ERROR: Cannot receive QUITMSG response.", ARGV0);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, QUITMSG);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS

        if (msg) {
            free(msg);
        }

        close(os_sock);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}
