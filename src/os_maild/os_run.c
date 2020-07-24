/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "maild.h"
#include "mail_list.h"

#include "os_net/os_net.h"
#include "os_dns.h"

#ifndef ARGV0
#define ARGV0 "ossec-maild"
#endif

static int errcnt2 = 0;

/* Read the queue and send the appropriate alerts
 * Not supposed to return
 */
void OS_Run2(MailConfig *mail) {
    MailMsg *msg;
    MailMsg *s_msg = NULL;
    MailMsg *msg_sms = NULL;

    merror("%s: DEBUG: smtp_use_tls: %d", ARGV0, mail->smtp_use_tls);

    time_t tm;
    struct tm *p;

    int i = 0;
    int mailtosend = 0;
    int childcount = 0;
    int thishour = 0;

    int n_errs = 0;

    file_queue *fileq;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);
    thishour = p->tm_hour;

    /* Initialize file queue */
    i = 0;
    i |= CRALERT_MAIL_SET;
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, i);

    /* Create the list */
    OS_CreateMailList(MAIL_LIST_SIZE);

    /* Set default timeout */
    mail_timeout = DEFAULT_TIMEOUT;

    /* Clear global variables */
    _g_subject_level = 0;
    memset(_g_subject, '\0', SUBJECT_SIZE + 2);

    while (1) {
        tm = time(NULL);
        p = localtime(&tm);


        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if ((mail_timeout == NEXTMAIL_TIMEOUT) && (p->tm_hour == thishour)) {
            /* Get more messages */
        }

        /* Hour changed: send all suppressed mails */
        else if (((mailtosend < mail->maxperhour) && (mailtosend != 0)) ||
                 ((p->tm_hour != thishour) && (childcount < MAXCHILDPROCESS))) {
            MailNode *mailmsg;
            pid_t pid;

            /* Check if we have anything to send */
            mailmsg = OS_CheckLastMail();
            if (mailmsg == NULL) {
                /* Don't fork in here */
                goto snd_check_hour;
            }

            fflush(fileq->fp);
            if (OS_Sendmail(mail, p) < 0) {
                merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                merror("SNDMAIL_ERROR 1");
                errcnt2++;
                if (errcnt2 > 5) {
                    ErrorExit("%s: ERROR: Too many failures. Exiting.", ARGV0);
                }
            } else {
                errcnt2 = 0;
            }

            /* Clean the memory */
            mailmsg = OS_PopLastMail();
            do {
                FreeMail(mailmsg);
                mailmsg = OS_PopLastMail();
            } while (mailmsg);

            /* Clear global variables */
            _g_subject[0] = '\0';
            _g_subject[SUBJECT_SIZE - 1] = '\0';
            _g_subject_level = 0;

            /* Clean up set values */
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (s_msg && mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    } else {
                        mail->gran_set[i] = 0;
                    }
                    i++;
                }
            }

snd_check_hour:
            /* If we sent everything */
            if (p->tm_hour != thishour) {
                thishour = p->tm_hour;

                mailtosend = 0;
            }
        }

        /* Saved message for the do_not_group option */
        if (s_msg) {
            /* Set the remaining do no group to full format */
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    }
                    i++;
                }
            }

            OS_AddMailtoList(s_msg);

            s_msg = NULL;
            mailtosend++;
            continue;
        }

        /* Receive message from queue */
        if ((msg = OS_RecvMailQ(fileq, p, mail, &msg_sms)) != NULL) {
            /* If the e-mail priority is do_not_group,
             * flush all previous entries and then send it.
             * Use s_msg to hold the pointer to the message while we flush it.
             */
            if (mail->priority == DONOTGROUP) {
                s_msg = msg;
            } else {
                OS_AddMailtoList(msg);
            }

            /* Change timeout to see if any new message is coming shortly */
            if (mail->groupping) {
                /* If priority is set, send email now */
                if (mail->priority) {
                    mail_timeout = DEFAULT_TIMEOUT;

                    /* If do_not_group is set, we do not increase the list count */
                    if (mail->priority != DONOTGROUP) {
                        mailtosend++;
                    }
                } else {
                    /* 5 seconds only */
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            } else {
                /* Send message by itself */
                mailtosend++;
            }
        } else {
            if (mail_timeout == NEXTMAIL_TIMEOUT) {
                mailtosend++;

                /* Default timeout */
                mail_timeout = DEFAULT_TIMEOUT;
            }
        }

        /* Wait for the children */
        while (childcount) {
            int wp;
            int p_status;
            wp = waitpid((pid_t) - 1, &p_status, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
                n_errs++;
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            } else {
                if (p_status != 0) {
                    merror(CHLDWAIT_ERROR, ARGV0, p_status);
                    merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                    merror("SNDMAIL_ERROR 2");
                    n_errs++;
                }
                childcount--;
            }

            /* Too many errors */
            if (n_errs > 6) {
                merror(TOOMANY_WAIT_ERROR, ARGV0);
                merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                merror("SNDMAIL_ERROR 3");
                exit(1);
            }
        }

    }
}

