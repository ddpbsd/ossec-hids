#ifndef WIN32

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <err.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <event.h>

#include "tls_remoted.h"


int tr_debug = 0;
char *ruser = "ossec";
char *rgroup = "ossec";
char *rpath = "/var/ossec";


static void help_tls_remoted(void) __attribute__((noreturn));
static void help_tls_remoted(void) {
    printf("Blah blah\n");
    exit(1);
}


int main(int argc, char **argv) {
    int c;


    while ((c = getopt(argc, argv, "hv")) != -1) {
        switch (c) {
            case 'h':
                help_tls_remoted();
                break;
            case 'v':
                tr_debug++;
                break;
            default:
                exit(1);
                break;
        }
    }

    if (tr_debug > 0) {
        printf("Starting.\n");
    }


    /* Signal work */
    os_signal();

    /* Setup imsg */
    struct imsgbuf os_remoted_ibuf, os_remoted_ibuf_server;
    int imsg_fds[2];
    if ((socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds)) == -1) {
        err(1, "Could not create socket pair: ");
    }
    if (tls_setnonblock(imsg_fds[0]) < 0) {
        err(1, "Could not set imsg_fds[0] to nonblock");
    }
    if (tls_setnonblock(imsg_fds[1]) < 0) {
        err(1, "Could not set imsg_fds[1] to nonblock");
    }

    /* Fork child processes */
    switch(fork()) {
        case -1:
            err(1, "Could not fork ");
        case 0:
            close(imsg_fds[0]);
            imsg_init(&os_remoted_ibuf, imsg_fds[1]);
            exit(os_run_proc(&os_remoted_ibuf));
     }


     /* Setup imsg for the main process */
     close(imsg_fds[1]);
     imsg_init(&os_remoted_ibuf_server, imsg_fds[0]);

     /* Priviledge separation */

}


#endif	//WIN32

