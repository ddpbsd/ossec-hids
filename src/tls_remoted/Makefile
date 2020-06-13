all:
	cc -ggdb -lm -lutil -ltls -lssl -lcrypto -o tlsremoted tls_remoted.c util.c os_run_proc.c os_signal.c

clean:
	rm -f *.core tlsremoted

