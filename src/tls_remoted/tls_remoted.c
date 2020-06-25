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

#ifdef __OpenBSD__
    setproctitle("[main]");
#endif

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

    /* Configuration */
    struct config rconfig;
    rconfig.chroot_dir_main = "/var/ossec/empty";
    rconfig.chroot_dir_proc = "/var/ossec";

    /* Get uid/gid */
    /* XXX using ossecr and ossec for now */
    rconfig.user_name = "ossecr";
    rconfig.group_name = "ossec";
    struct passwd *pw;
    pw = getpwnam(rconfig.user_name);
    if (pw == NULL) {
        printf("getpwnam failed.\n");
        exit(1);
    } else {
        rconfig.uid = pw->pw_uid;
    }
    struct group *grp;
    grp = getgrnam(rconfig.group_name);
    if (grp == NULL) {
        printf("getgrnam failed.\n");
        exit(1);
    } else {
        rconfig.gid = grp->gr_gid;
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
           imsg_init(&rconfig.os_remoted_ibuf, imsg_fds[1]);
           exit(os_run_proc(&rconfig));
    }


    /* Setup imsg for the main process */
    close(imsg_fds[1]);
    imsg_init(&os_remoted_ibuf_server, imsg_fds[0]);

    /* chroot */
    if ((chdir(rconfig.chroot_dir_main)) == -1) {
        printf("chdir failed: %s\n", strerror(errno));
        exit(errno);
    }
    if ((chroot(rconfig.chroot_dir_main)) == -1) {
        printf("chroot failed: %s\n", strerror(errno));
        exit(errno);
    }
    if ((chdir("/")) == -1) {
        printf("chdir failed: %s\n", strerror(errno));
        exit(errno);
    }


    /* Priviledge separation */
    if ((setgid(rconfig.gid)) == -1) {
        printf("setgid failed: %s\n", strerror(errno));
        exit(1);
    }
    if ((setuid(rconfig.uid)) == -1) {
        printf("setuid failed: %s\n", strerror(errno));
        exit(1);
    }

    /* end of upkeep, go to main phase */
    printf("whew! that was rough!\n");
    char *buf;
    printf("I am: %u/%u, and I am in %s\n", getuid(), geteuid(), getcwd(buf, 128));
    free(buf);


    /* Do stuff */
    int orm = os_run_main(&rconfig, os_remoted_ibuf_server);
    return(0);
}


#endif	//WIN32

