/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations */

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
char tls_msg[1024];

int OS_Sendmail(MailConfig *mail, struct tm *p)
{

merror("XXX os_sendmail() start");

#if __OpenBSD__
    setproctitle("[OS_Sendmail]");
#endif

    debug1("ossec-maild [OS_Sendmail]: DEBUG: OS_Sendmail()");

    FILE *sendmail = NULL;
    int socket = -1;
    unsigned int i = 0;
    char *msg;
    char snd_msg[128];
    istls = 0;

#ifdef USE_LIBTLS
    struct tls_config *cfg = NULL;
    struct tls *ctx = NULL;
#endif //USE_LIBTLS

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

#ifdef USE_LIBTLS
        merror("XXX os_sendmail() init tls");
        if (mail->smtp_use_tls == 1) {
            merror("%s: DEBUG: Configuring tls", ARGV0);
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

        ssize_t n;
        int idata = 42;
merror("XXX os_sendmail() imsg_compose");

        if ((imsg_compose(&mail->ibuf, DNS_REQ, 0, 0, -1, &idata, sizeof(idata))) == -1) {
            merror("%s: ERROR: imsg_compose() error: %s", ARGV0, strerror(errno));
        }
        if ((imsg_flush(&mail->ibuf)) == -1) {
            merror("ossec-maild [OS_Sendmail]: ERROR: imsg_flush() failed.");
        }

        merror("XXX os_sendmail() imsg sent");
        sleep(1);
        ssize_t m = 0;
        int ddplc = 0;
        if ((m = imsg_read(&mail->ibuf)) == -1 && errno != EAGAIN) {
            // Loop here until something happens
            merror("XXX loop loop loop ERROR");
        }
merror("XXX os_sendmail() after loop loop loop %zu", m);

        struct imsg imsg;
        ddplc = 0;
        for (;;) {
            m = imsg_get(&mail->ibuf, &imsg);
            if (m == -1) {
                merror("XXX imsg_get error");
            }
            if (m == 0) {
                merror("XXX m == 0");
            }

merror("XXX after imsg_get");

        switch(imsg.hdr.type) {
            case DNS_RESP:
                os_sock = imsg.fd;
                break;
            case DNS_FAIL:
                merror("%s: ERROR: DNS failure for smtpserver", ARGV0);
                return(OS_INVALID);
                break;;
            default:
                merror("%s: ERROR Wrong imsg type. (%u)", ARGV0, imsg.hdr.type);
                break;
        }
        }


        if (os_sock <= 0) {
            merror("ossec-maild: ERROR: No socket.");
            return (OS_INVALID);
        }

merror("XXX os_Sendmail() beginning to send the mail");

        /* Receive the banner */
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
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
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(socket, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(socket);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(socket);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(socket);
                return (OS_INVALID);
            }
        }

        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

#ifdef USE_LIBTLS
        if(mail->smtp_use_tls == 1) {
            /* Try to STARTTLS */
            OS_SendTCP(os_sock, "STARTTLS\r\n");
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
                merror("%s: ERROR: Cannot STARTTLS", ARGV0);
                close(os_sock);
                return (OS_INVALID);
            } else {
                istls = 1;

                if ((tls_connect_socket(ctx, os_sock, mail->smtpserver)) == -1) {
                    merror("%s: ERROR: tls_connect_socker() failed.", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }

                /* Resend the HELO */
                if ((tls_write(ctx, snd_msg, strnlen(snd_msg, 1024))) == -1) {
                    merror("%s: ERROR: Cannot send second HELO:%s", ARGV0, tls_error(ctx));
                    close(os_sock);
                    return(OS_INVALID);
                }
bzero(&tls_msg, 1024);
                if ((tls_read(ctx, &tls_msg, 1024)) == -1) {
                    merror("%s: ERROR: Cannot read HELO banner.", ARGV0);
                    debug1("%s: DEBUG: response: %s", ARGV0, msg);
                    close(os_sock);
                    return(OS_INVALID);
                }
                if ((!OS_Match(VALIDMAIL, tls_msg))) {
                    merror("%s:%s", HELO_ERROR, "null");
                    close(os_sock);
                    return (OS_INVALID);
                }
            }
        }
#endif //USE_LIBTLS

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, MAILFROM, mail->from);
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, snd_msg, strnlen(snd_msg, 1024))) == -1) {
                merror(FROM_ERROR);
/*
                if (msg) {
                    free(msg);
                }
*/
                close(os_sock);
                return(OS_INVALID);
            }
bzero(&tls_msg, 1024);
            if ((tls_read(ctx, &tls_msg, 1024)) == -1) {
                merror("%s: ERROR: Cannot tls_read MAILFROM", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((!OS_Match(VALIDMAIL, tls_msg))) {
                merror(FROM_ERROR);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
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
                    close(socket);
                    return (OS_INVALID);
                }
                break;
            }
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, mail->to[i++]);
#ifdef USE_LIBTLS
            if (istls == 1) {
                if ((tls_write(ctx, snd_msg, strnlen(snd_msg, 1024))) == -1) {
                    merror("%s: ERROR: rcpt to failed.", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
                if ((tls_read(ctx, &tls_msg, sizeof(tls_msg))) == -1) {
                    merror("%s: ERROR: cannot read rcpt to response.", ARGV0);
                    close(os_sock);
                    return(OS_INVALID);
                }
                if((!OS_Match(VALIDMAIL, tls_msg))) {
                    merror(TO_ERROR, mail->to[i = 1]);
                    close(os_sock);
                    return(OS_INVALID);
                }
            } else {
#endif //USE_LIBTLS
                OS_SendTCP(os_sock, snd_msg);
                msg = OS_RecvTCP(os_sock, OS_SIZE_1024);

                if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                    merror(TO_ERROR, mail->to[i - 1]);
                    if (msg) {
                        free(msg);
                    }
                    close(os_sock);
                    return (OS_INVALID);
                }
                free(msg);
#ifdef USE_LIBTLS
            }
#endif //USE_LIBTLS
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
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
                    if ((tls_write(ctx, snd_msg, strnlen(snd_msg, 1024))) == -1) {
                        merror("%s: ERROR: Cannot send rcptto", ARGV0);
                        close(os_sock);
                        return(OS_INVALID);
                    }
                    if ((tls_read(ctx, &tls_msg, sizeof(tls_msg))) == -1) {
                        merror("%s: ERROR: Cannot receive rcptto response.", ARGV0);
                        close(os_sock);
                        return (OS_INVALID);
                    }
                    if ((!OS_Match(VALIDMAIL, tls_msg))) {
                        merror(TO_ERROR, mail->gran_to[i]);
                        i++;
                        continue;
                    }
                } else {
#endif //USE_LIBTLS
                    OS_SendTCP(os_sock, snd_msg);
                    msg = OS_RecvTCP(os_sock, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror(TO_ERROR, mail->gran_to[i]);
                        if (msg) {
                            free(msg);
                        }

                        i++;
                        continue;
                    }
                    free(msg);
#ifdef USE_LIBTLS
                }
#endif //USE_LIBTLS

                MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
                i++;
                continue;
            }
        }

        /* Send the "DATA" msg */
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, DATAMSG, strnlen(DATAMSG, 1024))) == -1) {
                merror("%s: ERROR: Cannot send DATAMSG", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, &tls_msg, sizeof(tls_msg))) == -1) {
                merror("%s: ERROR: Cannot receive DATAMSG response.", ARGV0);
                close(os_sock);
                return (OS_INVALID);
            }
            if ((!OS_Match(VALIDDATA, tls_msg))) {
                merror(DATA_ERROR);
                close(os_sock);
                return(OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS

            OS_SendTCP(os_sock, DATAMSG);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);

            if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
                merror(DATA_ERROR);
                if (msg) {
                    free(msg);
                }
                close(os_sock);
                return (OS_INVALID);
            }
            free(msg);
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
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
            if ((tls_write(ctx, ENDHEADER, strnlen(ENDHEADER, 1024))) == -1) {
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
                if ((tls_write(ctx, mailmsg->mail->body, strnlen(mailmsg->mail->body, 1024))) == -1) {
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
            if ((tls_write(ctx, ENDDATA, strnlen(ENDDATA, 1024))) == -1) {
                merror("%s: ERROR: Cannot send ENDDATA", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if ((tls_read(ctx, &tls_msg, sizeof(tls_msg))) == -1) {
                merror("%s: ERROR: Cannot receive ENDDATA response.", ARGV0);
                close(os_sock);
                return(OS_INVALID);
            }
            if (mail->strict_checking && (!OS_Match(VALIDMAIL, tls_msg))) {
                merror(END_DATA_ERROR);
                close(os_sock);
                return (OS_INVALID);
            }
        } else {
#endif //USE_LIBTLS
            OS_SendTCP(os_sock, ENDDATA);
            msg = OS_RecvTCP(os_sock, OS_SIZE_1024);

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
#ifdef USE_LIBTLS
        }
#endif //USE_LIBTLS

        /* Quit and close os_sock */
#ifdef USE_LIBTLS
        if (istls == 1) {
            if ((tls_write(ctx, QUITMSG, strnlen(QUITMSG, 1024))) == -1) {
                merror("%s: ERROR: Cannot send QUITMSG", ARGV0);
            }
            if ((tls_write(ctx, msg, strnlen(msg, 1024))) == -1) {
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

        close(socket);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}
