#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>

/* Requires libevent */
#include <event.h>

#include "headers/privsep_op.h"
#include "headers/debug_op.h"
#include "os_net/os_net.h"
#include "os_dns.h"

char *dname = NULL;

void osdns_accept(int fd, short ev, void *arg) {

    /* sssssssh */
    if (fd) { }
    if (ev) { }

    /* temporary things */
    char *protocol = "tcp";


    /* We have a request from ossec-maild */
    struct os_dns_request dnsr;
    ssize_t n, datalen;
    struct imsg imsg;
    struct imsgbuf *ibuf = (struct imsgbuf *)arg;


    if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
        ErrorExit("%s [dns]: ERROR: imsg_read() failed: %s", dname, strerror(errno));
        return;
    }
    if (n == 0) {
        merror("%s [dns]: DEBUG: n == 0", dname);
    }

    if ((n = imsg_get(ibuf, &imsg)) == -1) {
        merror("%s [dns]: ERROR: imsg_get() failed: %s", dname, strerror(errno));
        return;
    }
    if (n == 0) {
        merror("%s [dns]: DEBUG: imsg_get() n == 0", dname);
    }


    datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

    switch(imsg.hdr.type) {
        case DNS_REQ:
            memcpy(&dnsr, imsg.data, sizeof(dnsr));
            int idata = 42;
            struct addrinfo hints, *result, *rp = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            if (strncmp(protocol, "tcp", 3) == 0) {
                hints.ai_socktype = SOCK_STREAM;
            } else if (strncmp(protocol, "udp", 3) == 0) {
                hints.ai_socktype = SOCK_DGRAM;
            }

            /* socket */
            int sock;
            sock = getaddrinfo(dnsr.hostname, "smtp", &hints, &result);
            if (sock != 0) {
                merror("%s [dns]: ERROR: getaddrinfo() error: %s\n", dname, gai_strerror(sock));

                struct os_dns_error os_dns_err;
                os_dns_err.code = sock;
                os_dns_err.msg = gai_strerror(sock);

                imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &os_dns_err, sizeof(&os_dns_err));
                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                    merror("%s [dns]: ERROR: msgbuf_write() failed (DNS_FAIL): %s", dname, strerror(errno));
                }
                if (n == 0) {
                    merror("%s [dns]: DEBUG: DNS_FAIL n == 0", dname);
                }
                if (n == EAGAIN) {
                    merror("%s [dns]: DEBUG: EAGAIN 1", dname);
                }
            }

            sock = -1;
            for(rp = result; rp; rp = rp->ai_next) {
                sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sock == -1) {
                    merror("%s [dns]: ERROR: socket() error", dname);
                } else {
                    if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
                        merror("%s [dns]: ERROR: connect() failed.", dname);
                        //XXX return error to caller
                    } else {
                        if ((imsg_compose(ibuf, DNS_RESP, 0, 0, sock, &idata, sizeof(idata))) == -1) {
                            merror("%s [dns]: ERROR: DNS_RESP imsg_compose() failed: %s", dname, strerror(errno));
                            freeaddrinfo(result);
                            return;
                        } else {
                            if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                                merror("%s [dns]: ERROR: DNS_RESP msgbuf_write() failed: %s", dname, strerror(errno));
                                freeaddrinfo(result);
                                return;
                            }
                            if (n == 0) {
                                merror("%s [dns]: DEBUG: DNS_RESP n == 0", dname);
                            }
                            freeaddrinfo(result);
                            return;
                        }
                    }
                }
            }
            break;
        default:
            merror("%s [dns]: ERROR: Unknown imsg type", dname);
            if ((imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &idata, sizeof(idata))) == -1) {
                merror("%s [dns]: ERROR: DNS_FAIL imsg_compose() failed: %s", dname, strerror(errno));
                return;
            } else {
                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                    merror("%s [dns]: ERROR: DNS_FAIL msgbuf_write failed: %s", dname, strerror(errno));
                    return;
                }
                if (n == 0) {
                    merror("%s [dns]: DEBUG: DNS_FAIL n == 0", dname);
                    return;
                }
            }
            return;
    }


    return;
}

/* osdns() is simple, it received the ibuf and
 * sets up the event loop for the parent to query.
 * osdns_accept() will pass a socket back to the 
 * parent with the connection established.
 *
 * Focusing on TCP right now.
 */
int osdns(struct imsgbuf *ibuf, char *os_name) {

    dname = os_name;

#if __OpenBSD__
    setproctitle("[dns]");
#endif

    merror("%s [dns]: INFO: Starting osdns", os_name);

    /* setuid() ossecm */
    /* This is static ossecm for now, I'll figure out the trick later */
    char *login = "ossecm";
    struct passwd *pw;


    pw = getpwnam(login);


    if (Privsep_SetGroup(pw->pw_gid) < 0) {
        ErrorExit("%s [dns]: ERROR: Cannot setgid.", os_name);
    }
    if (Privsep_SetUser(pw->pw_uid) < 0) {
        ErrorExit("%s [dns]: ERROR: Cannot setuid.", os_name);
    }

    /* Setup libevent */
    struct event_base *eb;
    eb = event_init();
    if (!eb) {
        ErrorExit("%s [dns]: event_init() failed.", os_name);
    }

    merror("%s [dns]: INFO: Starting libevent.", os_name);
    struct event ev_accept;
    event_set(&ev_accept, ibuf->fd, EV_READ|EV_PERSIST, osdns_accept, ibuf);
    event_add(&ev_accept, NULL);
    event_dispatch();



    return(0);
}






