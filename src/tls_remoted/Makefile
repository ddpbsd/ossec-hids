all:
	cc -ggdb -lm -lutil -ltls -lssl -lcrypto -o tlsremoted tls_remoted.c util.c os_run_proc.c os_signal.c os_run_main.c

clean:
	rm -f *.core tlsremoted

