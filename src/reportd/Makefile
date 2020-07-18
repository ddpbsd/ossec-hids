
OSSEC_CFLAGS=${CFLAGS}

all:
	cc -DARGV0=\"ossec-reportd\" -I../headers -I.. -I/usr/local/include -L/usr/local/lib -lpcre2-8 ${CFLAGS} report.c report_op.c ../shared/file_op.c ../shared/privsep_op.c ../shared/debug_op.c ../shared/help.c ../shared/store_op.c ../shared/list_op.c ../shared/file-queue.c ../shared/read-alert.c ../shared/mem_op.c ../shared/sig_op.c ../os_regex.a -o ossec-reportd

clean:
	rm -f ossec-reportd


install:
	install -g wheel -o root -m 500 ./ossec-reportd /usr/local/bin/ossec-reportd

