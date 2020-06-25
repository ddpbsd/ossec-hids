#ifndef WIN32

#include <stdio.h>
#include <imsg.h>

struct config {
    char *user_name;
    char *group_name;
    uid_t uid;
    gid_t gid;
    char *chroot_dir_main;
    char *chroot_dir_sub;
    char *chroot_dir_proc;
    char *ca_file;
    char *server_key;
    char *server_cert;
    struct imsgbuf os_remoted_ibuf;
    struct imsgbuf os_remoted_ibuf_server;
    struct tls *ctx;
    struct proc_config *pconfig;
};

struct proc_config {
    struct tls_config *cfg;
    struct tls *ctx;
    struct tls *cctx;
};

enum imsg_type {
    CONN
};

void os_signal();
int tls_setnonblock(int fd);
int os_run_proc(struct config *rconfig);
int os_run_main(struct config *rconfig, struct imsgbuf os_remoted_ibuf_server);
void os_main_accept(int fd, short ev, void *arg);
void os_proc_accept(int fd, short ev, void *arg);
int os_bindport2(char *port, const char *ip);

#endif //WIN32
