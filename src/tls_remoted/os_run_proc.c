#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>

#include "tls_remoted.h"


/* First process to decrypt the tls packets
 * will then send the data to the next process
 * for processing
 */

int os_run_proc(struct config *rconfig) {

#ifdef __OpenBSD__
    setproctitle("[os_run_proc]");
#endif

    sleep(100);
    return(0);
}
