/*
 * $QNXtpLicenseC:
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

/*	$NetBSD: kern_kthread.c,v 1.15 2003/01/18 10:06:26 thorpej Exp $	*/

/*-
 * Copyright (c) 1998, 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: kern_kthread.c,v 1.15 2003/01/18 10:06:26 thorpej Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#ifdef __QNXNTO__
#include <sys/mbuf.h>
#include <sys/mman.h>
#endif

#ifndef __QNXNTO__
/*
 * note that stdarg.h and the ansi style va_start macro is used for both
 * ansi and traditional c complers.
 * XXX: this requires that stdarg.h define: va_alist and va_dcl
 */
#include <machine/stdarg.h>

int	kthread_create_now;
#endif

/*
 * Fork a kernel thread.  Any process can request this to be done.
 * The VM space and limits, etc. will be shared with proc0.
 */
int
kthread_create1(void (*func)(void *), void *arg,
    struct proc **newpp, const char *fmt, ...)
{
	struct proc *p2;
#ifndef __QNXNTO__
	int error;
	va_list ap;

	/* First, create the new process. */
	error = fork1(&lwp0, FORK_SHAREVM | FORK_SHARECWD | FORK_SHAREFILES |
	    FORK_SHARESIGS, SIGCHLD, NULL, 0, func, arg, NULL, &p2);
	if (__predict_false(error != 0))
		return (error);

	/*
	 * Mark it as a system process and not a candidate for
	 * swapping.  Set P_NOCLDWAIT so that children are reparented
	 * to init(8) when they exit.  init(8) can easily wait them
	 * out for us.
	 */
	p2->p_flag |= P_SYSTEM | P_NOCLDWAIT;
	LIST_FIRST(&p2->p_lwps)->l_flag |= L_INMEM;

	/* Name it as specified. */
	va_start(ap, fmt);
	vsnprintf(p2->p_comm, MAXCOMLEN, fmt, ap);
	va_end(ap);
#else
	if (ISIRUPT)
		panic("kthread_create1");

	if ((p2 = stk_ctl.freeprocs) == NULL)
		return EAGAIN;
	/* Use the message event priority that started this execution.
	 * In pulse processing, PROC0 does not contain the message context
	 * so we will have to refer back to the proc structure receiving
	 * the original pulse. As we are creating a pseudo thread environment
	 * for callback functions to have a stack context environment, the
	 * receive buffer should be maintained as the context cannot yeild
	 * execution.
	 * This assumes kthread_create1() is only applied in callback operations
	 * which are message driven.
	 */
	p2->p_ctxt.info.priority = stk_ctl.recv_procp->p_ctxt.info.priority;
	stk_ctl.freeprocs = LWP_TO_PR(PR_TO_LWP(p2)->l_forw);
	PR_TO_LWP(p2)->l_forw = NULL;

	pcreat(p2, func, arg);
#endif

	/* All done! */
	if (newpp != NULL)
		*newpp = p2;
	return (0);
}

#ifdef __QNXNTO__
static void bigstack_clean (void *stk)
{
	struct nw_stk_ctl	*sctlp;
	sctlp = &stk_ctl;
	
	munmap(stk, sctlp->bigstack_size);
}
#endif

/*
 * Cause a kernel thread to exit.  Assumes the exiting thread is the
 * current context.
 */
void
kthread_exit(int ecode)
{

#ifndef __QNXNTO__
	/*
	 * XXX What do we do with the exit code?  Should we even bother
	 * XXX with it?  The parent (proc0) isn't going to do much with
	 * XXX it.
	 */
	if (ecode != 0)
		printf("WARNING: thread `%s' (%d) exits with status %d\n",
		    curproc->p_comm, curproc->p_pid, ecode);

	exit1(curlwp, W_EXITCODE(ecode, 0));

	/*
	 * XXX Fool the compiler.  Making exit1() __noreturn__ is a can
	 * XXX of worms right now.
	 */
	for (;;);
#else
	struct lwp		*l;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	void			*stk;

	wtp = WTP;
	if (ISIRUPT_P(wtp))
		panic("kthread_exit");

	l = curlwp;
	p = LWP_TO_PR(l);
	sctlp = &stk_ctl;

	if (p->p_flags & P_BIGSTACK) {

		/* Recover the actual base */
		stk = (void*)((uintptr_t)p->p_stkbase + sctlp->stacksize -
		    sctlp->bigstack_size);
		if (*(unsigned*)((uintptr_t)stk +
		    P_BIGSTACK_EXTRA) != PROC_STACK_TEST_PAT) {
			panic("tcpip: blown stack handling %#x. "
			    "See \"bigstack\" option.", p->p_curmsg);
		}

		/* Cleanup the proc */
		p->p_flags &= ~P_BIGSTACK;
		p->p_stkbase = p->p_stksaved;
		p->p_stksaved = NULL;

		/* Set a callout to unmap later */
		callout_init((struct callout*)stk);
		callout_msec((struct callout*)stk, 1, bigstack_clean, stk);

	} else if (*((unsigned*)p->p_stkbase) != PROC_STACK_TEST_PAT) {
		panic("tcpip: blown stack handling %#x. "
		    "See \"stacksize\" option.", p->p_curmsg);
	}

	l->l_stat = LEMPTY;
	l->l_fp = NULL;
	sctlp->nprocs_used--;

	p->p_curmsg = 0;
	m_freem(p->p_mbuf);
	p->p_mbuf = NULL;

	l->l_forw = PR_TO_LWP(sctlp->freeprocs);
	sctlp->freeprocs = p;

	curlwp = NULL;
	sched();
#endif
}

#ifndef __QNXNTO__
struct kthread_q {
	SIMPLEQ_ENTRY(kthread_q) kq_q;
	void (*kq_func)(void *);
	void *kq_arg;
};

SIMPLEQ_HEAD(, kthread_q) kthread_q = SIMPLEQ_HEAD_INITIALIZER(kthread_q);

/*
 * Defer the creation of a kernel thread.  Once the standard kernel threads
 * and processes have been created, this queue will be run to callback to
 * the caller to create threads for e.g. file systems and device drivers.
 */
void
kthread_create(void (*func)(void *), void *arg)
{
	struct kthread_q *kq;

	if (kthread_create_now) {
		(*func)(arg);
		return;
	}

	kq = malloc(sizeof(*kq), M_TEMP, M_NOWAIT);
	if (kq == NULL)
		panic("unable to allocate kthread_q");
	memset(kq, 0, sizeof(*kq));

	kq->kq_func = func;
	kq->kq_arg = arg;

	SIMPLEQ_INSERT_TAIL(&kthread_q, kq, kq_q);
}

void
kthread_run_deferred_queue(void)
{
	struct kthread_q *kq;

	/* No longer need to defer kthread creation. */
	kthread_create_now = 1;

	while ((kq = SIMPLEQ_FIRST(&kthread_q)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&kthread_q, kq_q);
		(*kq->kq_func)(kq->kq_arg);
		free(kq, M_TEMP);
	}
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/kern_kthread.c $ $Rev: 832191 $")
#endif
