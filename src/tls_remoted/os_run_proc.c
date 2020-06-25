#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <errno.h>
#include <imsg.h>

#include <event.h>
#include <tls.h>

#include "tls_remoted.h"


/* First process to decrypt the tls packets
 * will then send the data to the next process
 * for processing
 */

int os_run_proc(struct config *rconfig) {

#ifdef __OpenBSD__
    setproctitle("[os_run_proc]");
#endif

    //sleep(100);


    /* dup2 stdin and stuff */

    /* Need to do chroot/priv drop */

    if ((chdir(rconfig->chroot_dir_proc)) == -1) {
        /* XXX chdir error */
        return(errno);
    }
    if ((chroot(rconfig->chroot_dir_proc)) == -1) {
        /* XXX chroot error */
        return(errno);
    }
    if ((chdir("/")) == -1) {
        /* XXX chdir error */
        return(errno);
    }

    if ((setgid(rconfig->gid)) == -1) {
        printf("setgid failed: %s\n", strerror(errno));
        exit(1);
    }
    if ((setuid(rconfig->uid)) == -1) {
        printf("setuid failed: %s\n", strerror(errno));
        exit(1);
    }



    /* Setup the libtls stuff */

    struct proc_config pconfig;
    uint8_t *mem;
    size_t mem_len;


    if ((tls_init()) == -1) {
        /* tls_init error */
        return(-1);
    }

    pconfig.cfg = tls_config_new();
    if (pconfig.cfg == NULL) {
        /* config failed */
        return(-1);
    }

    /* Set the root cert */
    if ((mem = tls_load_file("/etc/CA/ca.lab.wafflelab.online.crt", &mem_len, NULL)) == NULL) {
        /* load ca file err */
        printf("tls_load_file failed\n");
        return(-1);
    } else
        printf("SUCCESS 1\n");
    if (tls_config_set_ca_mem(pconfig.cfg, mem, mem_len) != 0) {
        /* config set ca err */
        printf("tls_config_set_ca_mem() failed\n");
        return(-1);
    } else
        printf("SUCCESS 2\n");



    /* event it */
    struct event_base *eb;
    eb = event_init();
    if (!eb) {
        /* XXX error */
        exit(1);
    }

    int test = 42;

    struct event ev_accept;
    event_set(&ev_accept, rconfig->os_remoted_ibuf.fd, EV_READ|EV_PERSIST, os_proc_accept, &pconfig);

    event_add(&ev_accept, NULL);
    event_dispatch();



    return(0);
}

void os_proc_accept(int fd, short ev, void *arg) {
    return;
}

