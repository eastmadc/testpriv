/*
 * $QNXLicenseC:
 * Copyright 2007, QNX Software Systems. All Rights Reserved.
 * 
 * You must obtain a written license from and pay applicable license fees to QNX 
 * Software Systems before you may reproduce, modify or distribute this software, 
 * or any work that includes all or part of this software.   Free development 
 * licenses are available for evaluation and non-commercial purposes.  For more 
 * information visit http://licensing.qnx.com or email licensing@qnx.com.
 *  
 * This file may contain contributions from others.  Please review this entire 
 * file for other proprietary rights or license notices, as well as the QNX 
 * Development Suite License Guide at http://licensing.qnx.com/license-guide/ 
 * for other information.
 * $
 */





#ifndef __NW_CPU_MISC_H_INCLUDED
#define __NW_CPU_MISC_H_INCLUDED

#include <sys/kercalls.h>


/* XXX Taken from kernel/objects.h */
struct sigstack_entry {
	struct _sighandler_info info;
	sigset_t                sig_blocked;
	sync_t                  *mutex;
	unsigned                old_flags;
	uint64_t                timeout_time;
	unsigned                timeout_flags;
	unsigned                mutex_timeout_flags;
	struct sigevent         timeout_event;
};

#if defined(__X86__)
#include "target/x86/nw_cpu_misc.h"
#elif defined(__PPC__)
#include "target/ppc/nw_cpu_misc.h"
#elif defined(__ARM__)
#include "target/arm/nw_cpu_misc.h"
#elif defined(__SH__)
#include "target/sh/nw_cpu_misc.h"
#elif defined(__MIPS__)
#include "target/mips/nw_cpu_misc.h"
#else
#error nw_cpu_misc.h not defined for cpu
#endif

/*
 * A fallback for when the following two aren't defined by
 * the cpu specific includes above.  This should probably
 * be just an aid for bringing up a new arch as these most
 * likely will keep interrupts disabled longer.
 */
#ifndef CPU_RCV_LOOP_CTXT_STORE
#define CPU_RCV_LOOP_CTXT_STORE(wtp)					\
do {									\
	struct inter_thread *itp;					\
	if (_setjmp((wtp)->rx_loop_ctxt.rx_loop_jmp_buf) != 0) {	\
		itp = &iopkt_selfp->inter_threads[(wtp)->tidx_irupt];	\
		NW_INTR_UNLK(itp);					\
	}								\
} while (/* CONSTCOND */ 0)
#endif

#ifndef CPU_RCV_LOOP_CTXT_RESTORE
#define CPU_RCV_LOOP_CTXT_RESTORE(wtp) _longjmp((wtp)->rx_loop_ctxt.rx_loop_jmp_buf, 1)
#endif

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/nw_cpu_misc.h $ $Rev: 680336 $")
#endif
