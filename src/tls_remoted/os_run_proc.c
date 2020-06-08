#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>

int os_run_proc(struct imsgbuf *osremoted_ibuf) {

#ifdef __OpenBSD__
    setproctitle("[os_run_proc]");
#endif

    return(0);
}
