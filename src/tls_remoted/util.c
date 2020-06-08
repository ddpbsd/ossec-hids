#ifndef WIN32

#include <stdio.h>
#include <fcntl.h>

/* Set a socket to be non-blocking */
int tls_setnonblock(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        return -1;
    }

    return 0;
}


#endif //WIN32

