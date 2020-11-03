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




#include "opt_oob.h"
#include "opt_sigev.h"
#include <sys/param_bsd.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/netmgr.h>
#include <quiesce.h>
#include <nw_datastruct.h>
#include <nw_thread.h>
#include <pthread.h>
#include <siglock.h>
#include <process.h>
#include <receive.h>

#ifndef VARIANT_uni
static struct  {
	pthread_mutex_t mutex;
	pthread_cond_t  cond_stack;
	pthread_cond_t  cond_threads;

	int go_quiescent;
	int nthreads_quiesced;
	int stack_waiting;
} qu_state;
#endif


int
quiesce_init(void)
{
#ifndef VARIANT_uni
	int	ret, how;

	if ((ret = pthread_mutex_init(&qu_state.mutex, NULL)) != EOK) {
		log(LOG_ERR, "quiesce_ithreads_init: pthread_mutex_init: %d\n", ret);
		how = 1;
		goto fail;
	}

	if ((ret = pthread_cond_init(&qu_state.cond_stack, NULL)) != EOK) {
		log(LOG_ERR, "quiesce_ithreads_init: pthread_cond_init: %d\n", ret);

		how = 2;
		goto fail;
	}

	if ((ret = pthread_cond_init(&qu_state.cond_threads, NULL)) != EOK) {
		log(LOG_ERR, "quiesce_ithreads_init: pthread_cond_init: %d\n", ret);

		how = 3;
		goto fail;
	}

	return 0;
fail:
	/* FALLTHROUGH all */
	switch (how) {
	case 3:
		pthread_cond_destroy(&qu_state.cond_stack);
	case 2:
		pthread_mutex_destroy(&qu_state.mutex);
	case 1:
	default:
		break;
	}

	return ret;
#else /* VARIANT_uni */
	return 0;
#endif
}

void
quiesce_fini(void)
{
#ifndef VARIANT_uni
	pthread_cond_destroy(&qu_state.cond_threads);
	pthread_cond_destroy(&qu_state.cond_stack);
	pthread_mutex_destroy(&qu_state.mutex);
#endif
}

void
quiesce_all(void)
{
	return quiesce_all_arg(0, 0);
}

/*
 * Quiesce all the threads we're aware of.
 * The io-net shim may have others buzzing
 * around but hopefully they're not looking
 * at any of our structures.
 */
void
quiesce_all_arg(int die, int mask)
{
	struct nw_stk_ctl	*sctlp;
	struct _iopkt_self	*iopkt;
	struct nw_work_thread	*wtp;
	struct inter_thread	*itp_us;
#ifndef VARIANT_uni
	struct nw_work_thread	*wtp_cur;
	int			i, requested;
#endif

	sctlp = &stk_ctl;
	iopkt = sctlp->iopkt;

	wtp = WTP;

	if (wtp->am_stack == 0 || (wtp->flags & WT_CORE) == 0)
		panic("quiesce_all: not stack");

	itp_us = &iopkt->inter_threads[wtp->tidx_irupt];

	/*
	 * We only keep a global quiesce count, not a per 
	 * thread quiesce count.  The reason is that we
	 * currently only allow a particular thread to be
	 * reaped and don't allow a particular thread to be
	 * quiesced (you can only quiesce_all()).  If we
	 * ever add to a quiesce_one(), this will have to be
	 * revisited.
	 *
	 * XXX
	 * There's also assumptions in quiesce_core() that
	 * may make any attempt at quiesce_one() difficult
	 * if using pulses (can quiesce_one() but it might
	 * not be the one you want).
	 */

	if (die) {
		/*
		 * They can't exit if already quiesced. 
		 *
		 * Quiesce is supposed to be a short term
		 * state.  Shouldn't get back to top of loop
		 * with a quiesce in place.
		 */
		if (sctlp->quiesce_count != 0)
			panic("quiesce_all: die");
	}

	if (sctlp->quiesce_count++ != 0)
		return;

	NW_INTR_LK(itp_us);
	/*
	 * Make ourselves immune from interrupt
	 * signals.  Note this may already be set
	 * if using pulses for notification.
	 */
	itp_us->working = 1;

	NW_INTR_UNLK(itp_us);

	/* We can't take an interrupt signal now */
	wtp->intr_sighot = _ISIG_QUIESCED;

#ifndef VARIANT_uni
	pthread_mutex_lock(&qu_state.mutex);
	qu_state.go_quiescent = 1;
	pthread_mutex_unlock(&qu_state.mutex);
	
	requested = 0;
	/*
	 * XXX
	 * There's an assumption in quiesce_core()
	 * that we're walking this list in this
	 * order when using pulses.
	 */
	for (i = 0; i < sctlp->nwork_threads; i++) {
		wtp_cur = sctlp->work_threads[i];
		if (wtp_cur == NULL || wtp_cur == wtp ||
		    (mask != 0 && (wtp_cur->flags & mask) == 0))
			continue;

		requested++;
		wtp_cur->quiesce_callout(wtp_cur->quiesce_arg, die);


		/*
		 * Inside the loop in case the quiesce_callout
		 * uses static data that is shared across threads.
		 */
		pthread_mutex_lock(&qu_state.mutex);
		while (qu_state.nthreads_quiesced < requested) {
			qu_state.stack_waiting = 1;
			pthread_cond_wait(&qu_state.cond_stack, &qu_state.mutex);
			qu_state.stack_waiting = 0;
		}
		pthread_mutex_unlock(&qu_state.mutex);
	}

	if (die != 0) {
		pthread_mutex_lock(&qu_state.mutex);
		/* reset */
		qu_state.nthreads_quiesced = 0;
		pthread_mutex_unlock(&qu_state.mutex);

		for (i = 0; i < sctlp->nwork_threads; i++) {
			if ((wtp_cur = sctlp->work_threads[i]) == NULL ||
			    wtp_cur == wtp ||
			    (mask != 0 && (wtp_cur->flags & mask) == 0))
				continue;
			pthread_join(NW_TIDX_TO_TID(wtp_cur->tidx_wt), NULL);
			nw_pthread_cleanup(wtp_cur);
		}
	}
#endif

	return;
}

void
unquiesce_all(void)
{
	struct nw_stk_ctl	*sctlp;
	struct _iopkt_self	*iopkt;
	struct nw_work_thread	*wtp;

	sctlp = &stk_ctl;
	iopkt = sctlp->iopkt;

	wtp = WTP;
	if (wtp->am_stack == 0)
		panic("unquiesce_all: not stack");

	if (--sctlp->quiesce_count != 0)
		return;


#ifndef VARIANT_uni
	pthread_mutex_lock(&qu_state.mutex);
	qu_state.go_quiescent = 0;
	pthread_cond_broadcast(&qu_state.cond_threads);
	while (qu_state.nthreads_quiesced > 0) {
		qu_state.stack_waiting = 1;
		pthread_cond_wait(&qu_state.cond_stack, &qu_state.mutex);
		qu_state.stack_waiting = 0;
	}
	pthread_mutex_unlock(&qu_state.mutex);
#endif
	wtp->intr_sighot = _ISIG_COLD;
	process_interrupts(wtp);
}


#ifndef VARIANT_uni
void
quiesce_block(int die)
{
	struct nw_work_thread *wtp;

	wtp = WTP;

	/*
	 * If we're a core thread, we're already processing
	 * interrupts (our itp->working is set). Therefore
	 * we can't get another interrupt signal and can
	 * use plain mutexes.
	 */
	pthread_mutex_lock(&qu_state.mutex);

	qu_state.nthreads_quiesced++;
	while (qu_state.go_quiescent) {
		if (qu_state.stack_waiting)
			pthread_cond_signal(&qu_state.cond_stack);
		if (die || (wtp->flags & WT_DYING)) {
			pthread_mutex_unlock(&qu_state.mutex);
			pthread_exit(NULL);
		}
		else {
			pthread_cond_wait(&qu_state.cond_threads, &qu_state.mutex);
		}
	}
	if (--qu_state.nthreads_quiesced == 0 && qu_state.stack_waiting)
		pthread_cond_signal(&qu_state.cond_stack);

	pthread_mutex_unlock(&qu_state.mutex);
}
#endif

int
quiesce_force_exit(int tidx, struct nw_work_thread **wtpp)
{
#ifdef VARIANT_uni
	return EINVAL;
#else
	struct nw_work_thread	*wtp, *wtp_cur;
	struct nw_stk_ctl	*sctlp;

	sctlp = &stk_ctl;
	wtp = WTP;
	
	if (wtp->am_stack == 0 || (wtp->flags & WT_CORE) == 0)
		return EPERM;


	if (tidx >= sctlp->nwork_threads ||
	    (wtp_cur = sctlp->work_threads[tidx]) == NULL)
		return ESRCH;

	if (wtp_cur->flags & WT_CORE)
		return EINVAL;

	NW_SIGLOCK_P(&qu_state.mutex, iopkt_selfp, wtp);
	if (sctlp->quiesce_count > 0) {
		wtp_cur->flags |= WT_DYING;
		pthread_cond_broadcast(&qu_state.cond_threads);
		NW_SIGUNLOCK_P(&qu_state.mutex, iopkt_selfp, wtp);
	}
	else {
		qu_state.go_quiescent = 1;
		NW_SIGUNLOCK_P(&qu_state.mutex, iopkt_selfp, wtp);

		wtp_cur->quiesce_callout(wtp_cur->quiesce_arg, 1);

		NW_SIGLOCK_P(&qu_state.mutex, iopkt_selfp, wtp);
		while (qu_state.nthreads_quiesced < 1) {
			qu_state.stack_waiting = 1;
			pthread_cond_wait(&qu_state.cond_stack, &qu_state.mutex);
			qu_state.stack_waiting = 0;
		}
		qu_state.go_quiescent = 0;
		NW_SIGUNLOCK_P(&qu_state.mutex, iopkt_selfp, wtp);

	}
	/* It won't be coming back */
	qu_state.nthreads_quiesced--;
	/* Make sure we don't try to quiesce it again */
	sctlp->work_threads[tidx] = NULL;

	*wtpp = wtp_cur;

	return EOK;
#endif
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/quiesce.c $ $Rev: 775442 $")
#endif
