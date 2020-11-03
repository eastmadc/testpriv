/*
 * $QNXLicenseC:
 * Copyright 2014, QNX Software Systems. All Rights Reserved.
 *
 * You must obtain a written license from and pay applicable
 * license fees to QNX Software Systems before you may reproduce,
 * modify or distribute this software, or any work that includes
 * all or part of this software.   Free development licenses are
 * available for evaluation and non-commercial purposes.  For more
 * information visit http://licensing.qnx.com or email
 * licensing@qnx.com.
 *
 * This file may contain contributions from others.  Please review
 * this entire file for other proprietary rights or license notices,
 * as well as the QNX Development Suite License Guide at
 * http://licensing.qnx.com/license-guide/ for other information.
 * $
 */

#include <netdrvr/nicsupport.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <unistd.h>

#define _KERNEL
#include <sys/proc.h>
#include <sys/param_bsd.h>
#include <sys/kernel.h>
#include <nw_thread.h>


void
nic_delay(unsigned msec) {
    int ret;

    if (nw_thread_istracked() == NULL) {
	/* No io-pkt special magic, simple delay() */
        while(msec) {
            msec = delay(msec);
        }
	return;
    }

    /* Check for proc0 first to catch the bad code */
    if (curproc == stk_ctl.proc0) {
        panic("%s() called from proc0!", __FUNCTION__);
    }

    if (msec == 0) {
	/*
	 * We were asked to not delay.
	 * An ltsleep() would block forever until wakeup().
	 */
        return;
    }

    /* Do an ltsleep() and log any error */
    ret = ltsleep(&msec, PWAIT, NULL, ((msec*hz)/1000)?:1, NULL);
    if (ret != EWOULDBLOCK) {
	slogf(_SLOGC_NETWORK, _SLOG_ERROR, "%s(): ltsleep returned %d",
	      __FUNCTION__, ret);
    }
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/nic_delay.c $ $Rev: 768071 $")
#endif
