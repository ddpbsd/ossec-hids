all:
	cc -ggdb -I/usr/local/include -lm -lutil -ltls -lssl -lcrypto -levent -o tlsremoted tls_remoted.c util.c os_run_proc.c os_signal.c os_run_main.c os_bind.c

clean:
	rm -f *.core tlsremoted

