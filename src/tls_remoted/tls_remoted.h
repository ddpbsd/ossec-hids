#ifndef WIN32

#include <stdio.h>
#include <imsg.h>

void os_signal() {
	return;
}

int tls_setnonblock(int fd);
int os_run_proc(struct imsgbuf *osremoted_ibuf);

#endif //WIN32
