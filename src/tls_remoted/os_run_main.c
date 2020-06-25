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

    /* Try to re-use as much of os_bindport() as possible without
     * going crazy.
     */
    ossock = os_bindport2("1514", "127.0.0.1");
    if (ossock == -1) {
        /* XXX error */
        exit(1);
    }
    if ((listen(ossock, 32)) == -1) {
        /* XXX error listen */
        close(ossock);
        exit(errno);
    }

    if ((tls_setnonblock(ossock)) == -1) {
        /* XXX setnonblock error */
        exit(1);
    }

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

/* Accept the connection and pass it to os_run_proc()
 * where it will be tls decrypted and the message passed
 * to another process for processing.
 */
void os_main_accept(int fd, short ev, void *arg) {

    struct imsgbuf *ibuf;
    ssize_t n, datalen;

    ibuf = (struct imsgbuf *)arg;

    struct sockaddr_storage client;
    socklen_t clientlen;
    memset(&client, 0, sizeof(client));
    clientlen = sizeof(client);

    int ossock = accept(fd, (struct sockaddr *) &client, &clientlen);
    if (ossock == -1) {
        /* XXX accept error */
        return;
    }

    int rc, data;
    data = 42;
    rc = imsg_compose(ibuf, CONN, 0, 0, ossock, &data, sizeof(&data));
    if (rc == -1) {
        /* XXX imsg_compose() error */
        return;
    }
    if ((imsg_flush(ibuf)) == -1) {
        /* XXX imsg_flush() error */
        return;
    }

    return;
}

#endif	//WIN32

