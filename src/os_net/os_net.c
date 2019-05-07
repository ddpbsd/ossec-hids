/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library
 * APIs for many network operations
 */

#include <errno.h>
#include "shared.h"
#include "os_net.h"
agent *agt;

/* Prototypes */
static OSNetInfo *OS_Bindport(char *_port, unsigned int _proto, const char *_ip);
static int OS_Connect(char *_port, unsigned int protocol, const char *_ip);
static int OS_DecodeAddrinfo (struct addrinfo *res);
static char *OS_DecodeSockaddr (struct sockaddr *sa);
static char *DecodeFamily (int val);
static char *DecodeSocktype (int val);
static char *DecodeProtocol (int val);

/* Unix socket -- not for windows */
#ifndef WIN32
static struct sockaddr_un n_us;
static socklen_t us_l = sizeof(n_us);

/* UNIX SOCKET */
#ifndef SUN_LEN
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
                     + strlen ((ptr)->sun_path))
#endif /* Sun_LEN */

#else /* WIN32 */
/*int ENOBUFS = 0;*/
#ifndef ENOBUFS
#define ENOBUFS 0
#endif

#endif /* WIN32*/


/* Bind all relevant ports */
OSNetInfo *OS_Bindport(char *_port, unsigned int _proto, const char *_ip)
{
    int ossock = 0, s;
    struct addrinfo hints, *result, *rp;
    OSNetInfo *ni;			/* return data */

    /* Allocate the return data structure and initialize it. */
    ni = malloc (sizeof (OSNetInfo));
    memset(ni, 0, sizeof (OSNetInfo));
    FD_ZERO (&(ni->fdset));
    ni->fdmax  = 0;
    ni->fdcnt  = 0;
    ni->status = 0;
    ni->retval = 0;

    /* init hints for getaddrinfo() */
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
    hints.ai_family = AF_INET6;		/* Allow IPv4 and IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED;
#else
    /* handle as normal IPv4 and IPv6 multi request */
    hints.ai_family = AF_UNSPEC;	/* Allow IPv4 or IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG;
#endif /* AI_V4MAPPED */
#else
    /* FreeBSD, OpenBSD, NetBSD, and others */
    hints.ai_family = AF_UNSPEC;	/* Allow IPv4 or IPv6 */
    hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG;
#endif

    hints.ai_protocol = _proto;
    if (_proto == IPPROTO_UDP) {
        hints.ai_socktype = SOCK_DGRAM;
    } else if (_proto == IPPROTO_TCP) {
        hints.ai_socktype = SOCK_STREAM;
    } else {
        ni->status = -1;
        ni->retval = OS_INVALID;
        return(ni);
    }

    /* get linked list of adresses */
    s = getaddrinfo(_ip, _port, &hints, &result);

    /* Try to support legacy ipv4 only hosts */
    if((s == EAI_FAMILY) || (s == EAI_NONAME)) {
        hints.ai_family = AF_INET;
        hints.ai_flags  = AI_PASSIVE | AI_ADDRCONFIG;
        s = getaddrinfo(_ip, _port, &hints, &result);
    }

    if (s != 0) {
        verbose("getaddrinfo: %s", gai_strerror(s));
        ni->status = -1;
        ni->retval = OS_INVALID;
        return(ni);
    }

    /* log the list of connections available */
    OS_DecodeAddrinfo (result);

   /*
    * getaddrinfo() returns a list of address structures.  We try each
    * address and attempt to connect to it.  If a socket(2) or bind(2) fails,
    * we close the socket and try the next address. We repeat this for every
    * address getaddrinfo() returns in the addrinfo linked list.
    */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        ossock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ossock == -1) {
            verbose ("socket error: family %s type %s protocol %s: %s",
                     DecodeFamily (rp->ai_family),
                     DecodeSocktype (rp->ai_socktype),
                     DecodeProtocol (rp->ai_protocol),
                     strerror(errno));
            continue;
        }

        if (_proto == IPPROTO_TCP) {
            int flag = 1;
            if (setsockopt(ossock, SOL_SOCKET, SO_REUSEADDR,
                          (char *)&flag, sizeof(flag)) < 0) {
                verbose ("setsockopt error: SO_REUSEADDR %d: %s",
                         errno, strerror(errno));
                if(ossock > 0) {
                    OS_CloseSocket(ossock);
                }
                continue;
            }
        }

        if (bind(ossock, rp->ai_addr, rp->ai_addrlen) == -1) {
           /*
            * Don't issue an error message if the address and port is already
            * bound.  This can happen when 0.0.0.0 or :: are bound in a
            * previous iteration of this loop.
            */
            if (errno == EADDRINUSE) {
                close (ossock);
                continue;
            }

            /* tell them why this address failed */
            verbose ("Bind failed on socket for %s: %s",
                     OS_DecodeSockaddr (rp->ai_addr), strerror (errno));
            close (ossock);
            continue;
        }

        if (_proto == IPPROTO_TCP) {
            if (listen(ossock, 32) < 0) {
                verbose ("Request to listen() failed on socket for %s: %s",
                          OS_DecodeSockaddr (rp->ai_addr), strerror (errno));
                close (ossock);
                continue;
            }
            verbose ("Request for TCP listen() succeeded.");
        }

        /* success - accumulate data for select call */
        verbose ("Socket bound for %s", OS_DecodeSockaddr (rp->ai_addr));

        /* save bound socket info for select() */
        ni->fds[ni->fdcnt++] = ossock;  /* increment after use! */
        FD_SET (ossock, &(ni->fdset));
        if (ossock > ni->fdmax) {
          ni->fdmax = ossock;
        }
    }

    /* check to see if at least one address succeeded */
    if (ni->fdcnt == 0) {
        verbose ("Request to allocate and bind sockets failed.");
        ni->status = -1;
        ni->retval = OS_SOCKTERR;
        if(result) {
            freeaddrinfo(result);
        }
        return(ni);
    }

    freeaddrinfo(result);		/* No longer needed */
    ni->fdmax += 1;			/* prep for use with select() */
    return (ni);
}


/* Bind a TCP port, using the OS_Bindport */
OSNetInfo *OS_Bindporttcp(char *_port, const char *_ip)
{
    return (OS_Bindport(_port, IPPROTO_TCP, _ip));
}

/* Bind a UDP port, using the OS_Bindport */
OSNetInfo *OS_Bindportudp(char *_port, const char *_ip)
{
    return (OS_Bindport(_port, IPPROTO_UDP, _ip));
}

#ifndef WIN32
/* Bind to a Unix domain, using DGRAM sockets */
int OS_BindUnixDomain(const char *path, mode_t mode, int max_msg_size)
{
    int len;
    int ossock = 0;
    socklen_t optlen = sizeof(len);

    /* Make sure the path isn't there */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        return (OS_SOCKTERR);
    }

    if (bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Change permissions */
    if (chmod(path, mode) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Get current maximum size */
    if (getsockopt(ossock, SOL_SOCKET, SO_RCVBUF, &len, &optlen) == -1) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Set socket opt */
    if (len < max_msg_size) {
        len = max_msg_size;
        if (setsockopt(ossock, SOL_SOCKET, SO_RCVBUF, &len, optlen) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

    return (ossock);
}

/* Open a client Unix domain socket
 * ("/tmp/lala-socket",0666));
 */
int OS_ConnectUnixDomain(const char *path, int max_msg_size)
{
    int len;
    int ossock = 0;
    socklen_t optlen = sizeof(len);

    memset(&n_us, 0, sizeof(n_us));

    n_us.sun_family = AF_UNIX;

    /* Set up path */
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        return (OS_SOCKTERR);
    }

    /* Connect to the UNIX domain */
    if (connect(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Get current maximum size */
    if (getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1) {
        OS_CloseSocket(ossock);
        return (OS_SOCKTERR);
    }

    /* Set maximum message size */
    if (len < max_msg_size) {
        len = max_msg_size;
        if (setsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, optlen) < 0) {
            OS_CloseSocket(ossock);
            return (OS_SOCKTERR);
        }
    }

    return (ossock);
}

int OS_getsocketsize(int ossock)
{
    int len = 0;
    socklen_t optlen = sizeof(len);

    /* Get current maximum size */
    if (getsockopt(ossock, SOL_SOCKET, SO_SNDBUF, &len, &optlen) == -1) {
        OS_CloseSocket(ossock);
        return(OS_SOCKTERR);
    }

    return (len);
}

#endif

/* Open a TCP/UDP client socket */
int OS_Connect(char *_port, unsigned int protocol, const char *_ip)
{
    int ossock = 0, s;
    struct addrinfo hints, *result, *rp, *local_ai = NULL;
    char tempaddr[INET6_ADDRSTRLEN];

    if ((_ip == NULL)||(_ip[0] == '\0')) {
        OS_CloseSocket(ossock);
        return(OS_INVALID);
    }

    if (agt) {
        if (agt->lip) {
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_flags = AI_NUMERICHOST;
            s = getaddrinfo(agt->lip, NULL, &hints, &result);
            if (s != 0) {
                verbose("getaddrinfo: %s", gai_strerror(s));
            }
            else {
                local_ai = result;
            }
        }
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    /* Allow IPv4 or IPv6 if local_ip isn't specified */
    hints.ai_family = AF_UNSPEC;
    if (agt) {
        if (agt->lip) {
            hints.ai_family = local_ai->ai_family;
        }
    }
    hints.ai_protocol = protocol;
    if (protocol == IPPROTO_TCP) {
        hints.ai_socktype = SOCK_STREAM;
    } else if (protocol == IPPROTO_UDP) {
        hints.ai_socktype = SOCK_DGRAM;
    } else {
        return(OS_INVALID);
    }
    hints.ai_flags = 0;

    s = getaddrinfo(_ip, _port, &hints, &result);
    if (s != 0) {
        verbose("getaddrinfo: %s", gai_strerror(s));
        if(result) {
            freeaddrinfo(result);
        }
        return(OS_INVALID);
    }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        ossock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ossock == -1) {
            continue;
        }

        if (agt) {
            if (agt->lip) {
                if (bind(ossock, local_ai->ai_addr, local_ai->ai_addrlen)) {
                    verbose("Unable to bind to local address %s.  Ignoring. (%s)",
                            agt->lip, strerror(errno));
                }
                else verbose("Connecting from local address %s", agt->lip);
            }
        }

        if (connect(ossock, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;                  /* Success */
        }
    }
    if (rp == NULL) {               /* No address succeeded */
        if (ossock > 0) {
            OS_CloseSocket(ossock);
        }
        if(result) {
            freeaddrinfo(result);
        }
        return(OS_SOCKTERR);
    }
    satop(rp->ai_addr, tempaddr, sizeof tempaddr);
    verbose("INFO: Connected to %s at address %s, port %s", _ip,
            tempaddr, _port);

    freeaddrinfo(result);           /* No longer needed */

    #ifdef HPUX
    {
    int flags;
    flags = fcntl(ossock,F_GETFL,0);
    fcntl(ossock, F_SETFL, flags | O_NONBLOCK);
    }
    #endif

    return(ossock);
}


/* Open a TCP socket */
int OS_ConnectTCP(char *_port, const char *_ip)
{
    return (OS_Connect(_port, IPPROTO_TCP, _ip));
}

/* Open a UDP socket */
int OS_ConnectUDP(char *_port, const char *_ip)
{
    return (OS_Connect(_port, IPPROTO_UDP, _ip));
}

/* Send a TCP packet (through an open socket) */
int OS_SendTCP(int socket, const char *msg)
{
    if ((send(socket, msg, strlen(msg), 0)) <= 0) {
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a TCP packet of a specific size (through a open socket) */
int OS_SendTCPbySize(int socket, int size, const char *msg)
{
    if ((send(socket, msg, size, 0)) < size) {
        return (OS_SOCKTERR);
    }

    return (0);
}

/* Send a UDP packet of a specific size (through an open socket) */
int OS_SendUDPbySize(int socket, int size, const char *msg)
{
    unsigned int i = 0;

    /* Maximum attempts is 5 */
    while ((send(socket, msg, size, 0)) < 0) {
        if ((errno != ENOBUFS) || (i >= 5)) {
            return (OS_SOCKTERR);
        }

        i++;
        merror("%s: INFO: Remote socket busy, waiting %d s.", __local_name, i);
        sleep(i);
    }

    return (0);
}

/* Accept a TCP connection */
int OS_AcceptTCP(int socket, char *srcip, size_t addrsize)
{
    int clientsocket;
    struct sockaddr_storage _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

    if ((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                               &_ncl)) < 0) {
        return (-1);
    }

    satop((struct sockaddr *) &_nc, srcip, addrsize -1);
    srcip[addrsize -1] = '\0';

    return (clientsocket);
}

/* Receive a TCP packet (from an open socket) */
char *OS_RecvTCP(int socket, int sizet)
{
    char *ret;

    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
        return (NULL);
    }

    if (recv(socket, ret, sizet - 1, 0) <= 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
}

/* Receive a TCP packet (from an open socket) */
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet)
{
    int retsize;

    if ((retsize = recv(socket, buffer, sizet - 1, 0)) > 0) {
        buffer[retsize] = '\0';
        return (retsize);
    }
    return (-1);
}

/* Receive a UDP packet */
char *OS_RecvUDP(int socket, int sizet)
{
    char *ret;

    ret = (char *) calloc((sizet), sizeof(char));
    if (ret == NULL) {
        return (NULL);
    }

    if ((recv(socket, ret, sizet - 1, 0)) < 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
}

/* Receives a message from a connected UDP socket */
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size)
{
    int recv_b;

    recv_b = recv(socket, buffer, buffer_size, 0);
    if (recv_b < 0) {
        return (0);
    }

    buffer[recv_b] = '\0';

    return (recv_b);
}

#ifndef WIN32
/* Receive a message from a Unix socket */
int OS_RecvUnix(int socket, int sizet, char *ret)
{
    ssize_t recvd;
    if ((recvd = recvfrom(socket, ret, sizet - 1, 0,
                          (struct sockaddr *)&n_us, &us_l)) < 0) {
        return (0);
    }

    ret[recvd] = '\0';
    return ((int)recvd);
}

/* Send a message using a Unix socket
 * Returns the OS_SOCKETERR if it fails
 */
int OS_SendUnix(int socket, const char *msg, int size)
{
    if (size == 0) {
        size = strlen(msg) + 1;
    }

    if (send(socket, msg, size, 0) < size) {
        if (errno == ENOBUFS) {
            return (OS_SOCKBUSY);
        }

        return (OS_SOCKTERR);
    }

    return (OS_SUCCESS);
}
#endif

/* Calls getaddrinfo (tries x attempts) */
char *OS_GetHost(const char *host, unsigned int attempts)
{
    unsigned int i = 0;
    int error;

    char *ip;
    struct addrinfo *hai, *result;

    if (host == NULL) {
        return (NULL);
    }

    while (i <= attempts) {
        if ((error = getaddrinfo(host, NULL, NULL, &result)) != 0) {
            sleep(i++);
            continue;
        }

        if ((ip = (char *) calloc(IPSIZE, sizeof(char))) == NULL) {
            if (result) {
                freeaddrinfo(result);
            }
            return (NULL);
        }

        hai = result;
        satop(hai->ai_addr, ip, IPSIZE);

        freeaddrinfo(result);
        return (ip);
    }

    return (NULL);
}

/* satop(struct sockaddr *sa, char *dst, socklen_t size)
 * Convert a sockaddr to a printable address.
 */
int satop(struct sockaddr *sa, char *dst, socklen_t size)
{
    sa_family_t af;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
#ifdef WIN32
    int newlength;
#endif

    af = sa->sa_family;

    switch (af)
    {
    case AF_INET:
        sa4 = (struct sockaddr_in *) sa;
#ifdef WIN32
        newlength = size;
        WSAAddressToString((LPSOCKADDR) sa4, sizeof(struct sockaddr_in),
                           NULL, dst, (LPDWORD) &newlength);
#else
        inet_ntop(af, (const void *) &(sa4->sin_addr), dst, size);
#endif
        return(0);
    case AF_INET6:
        sa6 = (struct sockaddr_in6 *) sa;
#ifdef WIN32
        newlength = size;
        WSAAddressToString((LPSOCKADDR) sa6, sizeof(struct sockaddr_in6),
                           NULL, dst, (LPDWORD) &newlength);
#else
        inet_ntop(af, (const void *) &(sa6->sin6_addr), dst, size);
#endif
        if (IN6_IS_ADDR_V4MAPPED(&(sa6->sin6_addr)))
        {  /* extract the embedded IPv4 address */
            memmove(dst, dst+7, size-7);
        }
        return(0);
    default:
        *dst = '\0';
        return(-1);
    }
}

int OS_CloseSocket(int socket)
{
#ifdef WIN32
    return (closesocket(socket));
#else
    return (close(socket));
#endif /* WIN32 */
}


/*
 * OS_DecodeAddrinfo() will decode the contents of an addrinfo structure and
 * log the IP version, address, and port number for each item in the
 * linked list of addrinfo structs.
 */

int OS_DecodeAddrinfo (struct addrinfo *res) {
    struct addrinfo *p;			/* pointer to addrinfo structs */

    for (p = res; p != NULL; p = p->ai_next)
        verbose ("%s",OS_DecodeSockaddr (p->ai_addr));
    return 0;
}


/*
 * OS_DecodeSockaddr() will decode a socket address and return a string with
 * the IP version, address, and port number.
 */

char *OS_DecodeSockaddr (struct sockaddr *sa) {
    int rc;				/* return code */
    char ipaddr[INET6_ADDRSTRLEN];	/* printed address */
    char ipport[NI_MAXSERV];		/* printed port */
    static char buf[256];		/* message buffer */

#if defined(__linux__) || defined (WIN32)
    /* most Linux systems do not have sa_len in the sockaddr struct */
    socklen_t slen = 0;
    switch(sa->sa_family) {
        case AF_INET:
            slen = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            slen = sizeof(struct sockaddr_in6);
            break;
        default:
            // XXX WTF
            break;
    }
    rc = getnameinfo ((struct sockaddr *) sa, slen, ipaddr,
                      sizeof (ipaddr), ipport, sizeof (ipport),
                      NI_NUMERICHOST | NI_NUMERICSERV);
#else
    /* BSD systems require the value in sa->sa_len or error 4 occurs */
    rc = getnameinfo ((struct sockaddr *) sa, sa->sa_len, ipaddr,
                      sizeof (ipaddr), ipport, sizeof (ipport),
                      NI_NUMERICHOST | NI_NUMERICSERV);
#endif

    if (rc) {
        sprintf (buf, "Error %d on getnameinfo: %s", rc, gai_strerror (rc));
        return (buf);
    }

    sprintf (buf, "%s: %s on port %s",
             DecodeFamily (sa->sa_family), ipaddr, ipport);
    return buf;
}


/*
 * DecodeFamily() is used to convert the IP family into a string for info
 * and debugging purposes.
 */

char *DecodeFamily (int val) {
    static char buf[32];		/* response */

    switch (val) {
        case AF_INET:
            strcpy (buf,"IPv4");
            break;
        case AF_INET6:
            strcpy (buf,"IPv6");
            break;
        default:
            sprintf (buf, "Unknown Family %d", val);
            break;
    }

    return (buf);
}


/*
 * DecodeSocktype() is used to convert the IP socket type into a string for
 * info and debugging purposes.
 */

char *DecodeSocktype (int val) {
    static char buf[32];		/* response */

    switch (val) {
        case SOCK_STREAM:
            strcpy (buf,"STREAM");
            break;
        case SOCK_DGRAM:
            strcpy (buf,"DGRAM");
            break;
        case SOCK_RAW:
            strcpy (buf,"RAW");
            break;
        default:
            sprintf (buf, "Unknown Sock Type %d", val);
            break;
    }

    return (buf);
}


/*
 * DecodeProtocol() is used to convert the IP protocol into a string for info
 * and debugging purposes.
 */

char *DecodeProtocol (int val) {
    static char buf[32];		/* response */

    switch (val) {
        case IPPROTO_IP:
            strcpy (buf,"IP");
            break;
        case IPPROTO_ICMP:
            strcpy (buf,"ICMP");
            break;
        case IPPROTO_TCP:
            strcpy (buf,"TCP");
            break;
        case IPPROTO_UDP:
            strcpy (buf,"UDP");
            break;
        default:
            sprintf (buf, "Unknown Protocol %d", val);
            break;
    }

    return (buf);
}

