#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>






int os_bindport2(char *port, const char *ip) {
    int ossock = 0, s;
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(struct addrinfo));

   /*
    * If you cannot bind both IPv4 and IPv6, the problem is likely due to the
    * AF_INET6 family with the AI_V4MAPPED flag. Alter your Makefile to use the
    * NOV4MAP define and it should work like a breeze. All of the *BSDs fall
    * into this category even though AI_V4MAPPED exists in netdb.h (true for
    * all modern OS's). This should work with all Linux versions too, but the
    * original code for AF_INET6 was left for Linux because it works.
    *
    * d. stoddard - 4/19/2018
    */

#if defined(__linux__) && !defined(NOV4MAP)
#if defined (AI_V4MAPPED)
    hints.ai_family = AF_INET6;         /* Allow IPv4 and IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED;
#else
    /* handle as normal IPv4 and IPv6 multi request */
    hints.ai_family = AF_UNSPEC;        /* Allow IPv4 or IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG;
#endif /* AI_V4MAPPED */
#else
    /* FreeBSD, OpenBSD, NetBSD, and others */
    hints.ai_family = AF_UNSPEC;        /* Allow IPv4 or IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG;
#endif

    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    s = getaddrinfo(ip, port, &hints, &result);

    /* Try to support legacy ipv4 only hosts */
    if ((s == EAI_FAMILY) || (s == EAI_NONAME)) {
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
        s = getaddrinfo(ip, port, &hints, &result);
    }


    if (s != 0) {
        /* XXX error */
        return (-1);
    }

   /*
    * getaddrinfo() returns a list of address structures.  We try each
    * address and attempt to connect to it.  If a socket(2) or bind(2) fails,
    * we close the socket and try the next address. We repeat this for every
    * address getaddrinfo() returns in the addrinfo linked list.
    */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		ossock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (ossock == -1) {
			/* XXX error */
			continue;
		}

		int flag = 1;
		if (setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0) {
			/* XXX setsockopt error */
			if (ossock > 0) {
				close(ossock);
			}
			continue;
		}

		if (bind(ossock, rp->ai_addr, rp->ai_addrlen) == -1) {
			if (errno == EADDRINUSE) {
				close(ossock);
				continue;
			}
			/* XXX bind error */
			close(ossock);
			continue;
		} else {
            freeaddrinfo(result);
            return(ossock);
        }


	}

    return(-1);

}

