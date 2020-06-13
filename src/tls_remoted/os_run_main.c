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
#include <pwd.h>
#include <grp.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <event.h>

#include "tls_remoted.h"

/* Here we'll open the socket and wait for requests.
 * Requests will be sent over imsg to the next process for decryption
 */
int os_run_main(struct config *rconfig, struct imsgbuf imsg_remoted_ibuf_server) {
    printf("[main]: starting main process.");

    int ossock;




    /* libevent */
    struct event_base *eb;
    eb = event_init();
    if (!eb) {
        printf("event_init() failed.\n");
        exit(1);
    }

    struct event ev_accept;
    event_set(&ev_accept, ossock, EV_READ|EV_PERSIST, os_main_accept, &imsg_remoted_ibuf_server);

    event_add(&ev_accept, NULL);
    event_dispatch();



    return(0);
}

void os_main_accept(int fd, short ev, void *arg) {
    return;
}

#endif	//WIN32

