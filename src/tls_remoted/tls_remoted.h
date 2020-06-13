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
	struct imsgbuf os_remoted_ibuf;
	struct imsgbuf os_remoted_ibuf_server;
};


void os_signal();
int tls_setnonblock(int fd);
int os_run_proc(struct config *rconfig);
int os_run_main(struct config *rconfig, struct imsgbuf os_remoted_ibuf_server);
void os_main_accept(int fd, short ev, void *arg);

#endif //WIN32
