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
#include "init_main.h"

#include <malloc.h> /* The QNX one */
#include <nw_intr.h>
#include <nw_thread.h>
#include <quiesce.h>
#include <receive.h>
#include <nw_datastruct.h>
#include <pthread.h>
#include <ucontext.h>
#include <sys/param_bsd.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/netmgr.h>
#include <sys/malloc.h>
#include <process.h>
#include "siglock.h"

#include <sys/syslog.h>
#include <sys/nw_cpu_misc.h>

/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
#ifndef __atomic_fool_gcc
struct __gcc_fool { int __fool[100]; };
#define __atomic_fool_gcc(__x) (*(volatile struct __gcc_fool *)__x)
#endif

#define DEAD_IRUPT_PRIO		21

#define INTR_SMOOTH_SCALE	32
#define INTR_SMOOTH_SHIFT	5
#define INTR_SAMPLE_SIZE	128
/*
 * The smoothed average has five points after
 * binary point (shifted left 5).  This lim works
 * out to approx 7.5% of the max:
 * INTR_COL_SMOOTHLIM / (INTR_SAMPLE_SIZE << 5) == 7.5%
 */
#define INTR_COL_SMOOTHLIM 	307

/*
 * Delay up to this many complete sample cycles
 * before checking again if we detect there's
 * no other thread under a sufficiently small
 * interrupt load so as to accept migrated
 * interrupt entries.
 */
#define INTR_BACKOFF_MAX	16

static struct sigevent ev_dead_thread;

#ifdef OPT_SIGEV_SIGNAL_TID
static void interrupt_non_critical(struct nw_work_thread *);
#endif

struct _iopkt_inter *inter_all;


static pid_t mypid;


#ifndef NDEBUG
static int *intr_received;
#endif

static struct {
	struct inter_thread	**ii_corethreads;
	int			ii_coremax;
	int			ii_corecur;
	int			ii_nentries_thread_unsafe;
	int			ii_tidx_next;
	int			ii_prio_override;	/* been passed a custom prio */
	int			ii_prio_default;	/* been forced to fall back to default */
} iinfo;


#ifndef VARIANT_uni
extern char *__progname;
#endif



int
interrupt_pre_main_init(void)
{
	size_t size;

	iinfo.ii_coremax = stk_ctl.nthreads_core_max;
	size = iinfo.ii_coremax * sizeof(*iinfo.ii_corethreads);
	if ((iinfo.ii_corethreads = (malloc)(size)) == NULL)
		return ENOMEM;

	memset(iinfo.ii_corethreads, 0x00, size);

	return EOK;
}

void
interrupt_pre_main_fini(void)
{
	(free)(iinfo.ii_corethreads);
}

int
interrupt_init(void)
{
#ifndef NDEBUG
	int			irupt_max;

	irupt_max = stk_ctl.nthreads_core_max + stk_ctl.nthreads_oob_max;

	intr_received = malloc(irupt_max * sizeof(*intr_received), M_TEMP, M_NOWAIT);
	if (intr_received == NULL)
		return ENOMEM;
	memset(intr_received, 0x00, irupt_max * sizeof(*intr_received));
#endif
	SIGEV_PULSE_INIT(&ev_dead_thread, stk_ctl.coid, DEAD_IRUPT_PRIO,
	    NW_DEF_PULSE_CODE_DEAD_IRUPT, 0);

	mypid = getpid();

	return 0;
}

void
interrupt_fini(void)
{
#ifndef NDEBUG
	free(intr_received, M_TEMP);
#endif
}




void
process_interrupts(struct nw_work_thread *wtp)
{
	struct inter_thread	*itp_us;

#ifndef NDEBUG
	if ((wtp->flags & WT_IRUPT) == 0)
		panic("process_interrupts");
#endif

#ifdef MANAGE_STACKBASE_ON_INTR
	wtp->saved_stackbase = wtp->tls->stackaddr;
#endif
	/* Move to our interrupt stack */
	CPU_STACK_INTERRUPT(wtp);

	itp_us = process_interrupts_noswitch(wtp);

	CPU_STACK_RESTORE(wtp);

	NW_INTR_UNLK(itp_us);

	return;
}

#ifndef VARIANT_uni
static __inline struct inter_thread *
irupt_smooth_sample(struct inter_thread *itp)
{
	int			i, delta;
	struct inter_thread	*itp_migrate;

	/* Scale intr_collisions to INTR_SMOOTH_SCALE then divide by 8. */
	delta = itp->intr_collisions << (INTR_SMOOTH_SHIFT - 3);
	/* Subtract off one eigth of the current smoothed value */
	delta -= itp->intr_collisions_smoothed >> 3;
	itp->intr_collisions_smoothed += delta;
	/*
	 * All the above was the equivalent of:
	 * smoothed = 7/8 smoothed + 1/8 collisions
	 */

	itp->intr_samples = 0;
	itp->intr_collisions = 0;

	if (itp->intr_mig_backoff_lim &&
	    ++itp->intr_mig_backoff < itp->intr_mig_backoff_lim)
		return itp; /* See comment below. */

	itp->intr_mig_backoff = 0;

	if (itp->intr_collisions_smoothed >= INTR_COL_SMOOTHLIM) {
		for (i = 0; i < iinfo.ii_corecur; i++) {

			/*Skip over the dedicated stack context thread
			 *occupying the first corethread slot. It will
			 *not have an interrupt load.
			 */

			if (stk_ctl.dedicated_stack_context && (i == 0))
				continue;
			if ((itp_migrate = iinfo.ii_corethreads[i]) == NULL
#if 0
			    /* XXX
			     * The check below also filters ourselves
			     * out but watch if it changes.
			     */
			    || itp_migrate == itp
#endif
			    )
				continue;

			/*
			 * Another check to avoid migrating entries
			 * back and forth.
			 *
			 * This is really only valid if the entry that
			 * ends up being migrated is one of two on the
			 * list and both contribute 50% of the total
			 * load.  If we have have a situation where two
			 * (or more) are on the list but contributing
			 * unequally to the load, we may miss
			 * opportunities to move a less active entry
			 * over or incorrectly move a more active entry
			 * over (it (or another) may come back).  If the
			 * latter case occurs, and the load per entry is
			 * on average constant, we should eventually
			 * converge to a more distributed load
			 *
			 * This stems from not tracking load on a per
			 * entry basis.
			 */
			if (itp_migrate->intr_collisions_smoothed <=
			    (itp->intr_collisions_smoothed >> 1)) {
				itp->intr_mig_backoff_lim = 0;
				return itp_migrate;
			}
		}

		/*
		 * We didn't find another candidate under a small
		 * enough total load to make migration worthwhile.
		 * The check itself is expensive so try to avoid
		 * futile attempts by backing off.
		 */
		if (itp->intr_mig_backoff_lim == 0)
			itp->intr_mig_backoff_lim = 1;
		else {
			itp->intr_mig_backoff_lim <<= 1;
			itp->intr_mig_backoff_lim =
			    min(itp->intr_mig_backoff_lim, INTR_BACKOFF_MAX);
		}
	}

	return itp;
}
#endif

const struct sigevent *
interrupt_queue(struct _iopkt_self *iopkt, struct _iopkt_inter *ient)
{
	struct inter_thread	*itp;
	const struct sigevent	*evp;

	evp = NULL;

	if (ient->on_list == 0) {
		/* Snapshot as ient->tidx may change. */
		itp = &iopkt->inter_threads[ient->tidx];

		NW_INTR_LK(itp);

		/* In most driver architectures, there is only one code path
		 * calling interrupt_queue() at one time. For example, in
		 * the ISR in a typical IRQ based driver. Some drivers do not
		 * have an interrupt for I/O events. The architecture of these
		 * drivers have potential to create a race condition where
		 * interrupt_queue may be called by more than one posix thread
		 * simultaneously. In case this is occuring, check on_list
		 * again after the lock is obtained. If we are on_list, release
		 * the lock and exit. on_list is set in interrupt_queue() before
		 * the lock is released.
		 */
		if (ient->on_list != 0) {
			NW_INTR_UNLK(itp);
			return NULL;
		}

		*itp->inter_tail = ient;
		itp->inter_tail  = &ient->next;

		ient->on_list = 1;

		if (itp->working == 0) {
			evp = itp->event;
			itp->working = 1;
		}

		__cpu_membarrier();
		NW_INTR_UNLK(itp);
	}
	else {

		/*
		 * Shared interrupt.
		 *
		 * If the caller has no first level cause filter we
		 * may be getting several that aren't detected.  We
		 * know this particular one is spurious because it
		 * came in while ours is masked.
		 *
		 * If there is a first level cause filter the sum
		 * of the ones detected here and by the first level
		 * filter should be pretty close.
		 */
		ient->spurious++;
	}

	return evp;
}

struct inter_thread *
process_interrupts_noswitch(struct nw_work_thread *wtp)
{
	struct _iopkt_inter	*ient_cur;
	struct _iopkt_inter	*ient_head, **ient_tail;
	volatile struct inter_thread	*itp;
#ifndef VARIANT_uni
	volatile struct inter_thread	*itp_new;

	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];
	itp_new = itp;
#else
	/*
	 * No other handler to migrate interrupt entries to so
	 * itp_new would always work out to itp;
	 */
	itp = &iopkt_selfp->inter_threads[0];
#endif


#ifndef NDEBUG
	if ((wtp->flags & WT_IRUPT) == 0)
		panic("process_interrupts_noswitch");
#endif


	ient_head = NULL;
	ient_tail = &ient_head;

	for (;;) {
		NW_INTR_LK((struct inter_thread *)itp);

		*ient_tail = itp->inter_head;
		ient_tail = itp->inter_tail;

		itp->inter_head = NULL;
		itp->inter_tail = (struct _iopkt_inter **)&itp->inter_head;

		if (ient_head == NULL)
			break;

		__cpu_membarrier();
		NW_INTR_UNLK((struct inter_thread *)itp);

		while (itp->inter_head == NULL && (ient_cur = ient_head)) {
			ient_head = ient_cur->next;
			ient_cur->next = NULL;

			if (ient_head == NULL)
				ient_tail = &ient_head;
#ifndef VARIANT_uni
			else
				itp->intr_collisions++;


			if ((wtp->flags & WT_CORE) != 0 &&
			    ++itp->intr_samples == INTR_SAMPLE_SIZE) {
				/*
				 * Calculate our collision load and
				 * migrate if necesary.
				 */
				itp_new = irupt_smooth_sample((struct inter_thread *)itp);
			}
#endif

			if ((*ient_cur->func)(ient_cur->arg, wtp)) {
#ifndef VARIANT_uni
				if (itp_new != itp) {
					log(LOG_INFO, "ient %p from %d to %d",
					    ient_cur,
					    itp - iopkt_selfp->inter_threads,
					    itp_new - iopkt_selfp->inter_threads);
					/*
					 * See comment in interrupt_entry_remove()
					 * for why this has to happen exactly here.
					 */
					ient_cur->tidx =
					    itp_new - iopkt_selfp->inter_threads;

					/*
					 * Our load has changed.  Throw away
					 * our smoothed average and let it
					 * re-converge.
					 */
					itp->intr_collisions_smoothed = 0;
					itp_new = itp;
				}
#endif

				ient_cur->on_list = 0;
				/*
				 * make sure on_list = 0 is always
				 * pushed out before unmask() callout.
				 */
				__cpu_membarrier();
				wtp->poke_stack |= ient_cur->enable(ient_cur->arg);
			}
			else {
				*ient_tail = ient_cur;
				ient_tail = &ient_cur->next;
			}
		}
	}
#ifdef MANAGE_STACKBASE_ON_INTR
	/* We're about to give up our interrupt stack */
	wtp->tls->stackaddr = wtp->saved_stackbase;
#endif

	/*
	 * Mark ourselves as being able to process
	 * further interrupts.  The interrupt lock
	 * is still held here so can't actually get a
	 * signal yet.
	 */
	wtp->intr_sighot = _ISIG_HOT;

	itp->working = 0;
	__cpu_membarrier();
	return (struct inter_thread *)itp;
}

/*
 * The logic is interrupt_entry_init() should be called once
 * per interrupt.  stack_interrupt_remove() can be called
 * multiple times with a NULL ev but only once with a non
 * NULL ev (remove and destroy).
 *
 * Distribute them evenly by number per thread at startup.
 * The hard part is keeping them evenly distributed by load
 * per thread.  See comment in process_interrupt_noswitch().
 */
int
interrupt_entry_init(struct _iopkt_inter *ient, int flags,
    struct sigevent **ev_out, int prio)
{
	int			i, ret, tidx_cur;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	struct inter_thread	*itp, **itpp;

	sctlp = &stk_ctl;

	wtp = WTP;

	if (wtp->am_stack == 0)
		panic("interrupt_entry_init: unexpected context");

	ient->flags = flags;
	ient->tidx = -1;
	if (ev_out)
		*ev_out = NULL;
#ifdef VARIANT_uni
	/* uni expects one thread always */
	if (flags & (IRUPT_OOB_LOW | IRUPT_OOB_HIGH))
		return EOPNOTSUPP;

#else
	if (flags & (IRUPT_OOB_LOW | IRUPT_OOB_HIGH)) {
#if !defined(OOB_THREAD_HIGH) && !defined(OOB_THREAD_LOW)
		return EOPNOTSUPP;
#else
		int err, i;
		pthread_t tid;
		struct nw_oob_msg msg;
		struct nw_oob_ctl *soob;
		struct oob_info *oobi;

		if ((flags & (IRUPT_OOB_LOW | IRUPT_OOB_HIGH)) ==
		    (IRUPT_OOB_LOW | IRUPT_OOB_HIGH)) {
			return EINVAL;
		}

		if (flags & IRUPT_OOB_HIGH) {
#ifndef OOB_THREAD_HIGH
			return EOPNOTSUPP;
#else
			soob = &oob_ctl_high;
#endif
		}
		else {
#ifndef OOB_THREAD_LOW
			return EOPNOTSUPP;
#else
			soob = &oob_ctl_low;
#endif
		}


		if (soob->init == 0 && (err = nw_pthread_create(&tid, NULL,
		    receive_loop_oob, soob, WT_FLOW | WT_OOB | WT_IRUPT,
		    oob_init, soob)) != EOK) {
			return err;
		}

		if (ev_out == NULL) {
			/* They're isr based and don't need a separate event */
			ient->tidx = sctlp->work_threads[NW_TID_TO_TIDX(tid)]->tidx_irupt;
			ient->next_all = inter_all;
			inter_all = ient;
			return 0;
		}
		/*
		 * We are the stack and only the stack creates / destroys
		 * oob entries so OK to walk this here.
		 */

		for (i = 0; i < soob->noob; i++) {
			if (soob->oob_infop[i].ev == NULL)
				break;
		}

		if (i == soob->noob) {
			if ((oobi = malloc((i + 1) * sizeof(*oobi), M_SOFTINTR, M_NOWAIT)) == NULL)
				return ENOMEM;

			memset(oobi, 0x00, (i + 1) * sizeof(*oobi));
			memcpy(oobi, soob->oob_infop, i * sizeof(*oobi));
		}
		else {
			oobi = soob->oob_infop;
		}

		if ((oobi[i].ev = malloc(sizeof(*oobi[i].ev), M_SOFTINTR, M_NOWAIT)) == NULL) {
			if (i == soob->noob)
				free(oobi, M_SOFTINTR);
			return ENOMEM;
		}


		/*
		 * There are 2 ways for the thread created above to find ient when an 
		 * event is raised.  If the event is raised by an isr, they're supposed
		 * to put ient on the thread in question's list and index to the event
		 * based on ient->tidx.  This event has the magic IRUPT_OOB_ISR flag in
		 * the value.  If they're not isr based and don't put themselves on the
		 * thread in question's list, they should use the event returned out of
		 * this func which allows the thread to index to ient from its
		 * soob->oob_infop array.
		 */
		SIGEV_PULSE_INIT(oobi[i].ev, soob->coid, soob->prio, NW_DEF_PULSE_CODE_IRUPT_OOB, i);
		oobi[i].inter = ient;
		/*
		 * This shouldn't be used to index to
		 * iopkt_self->inter_threads
		 */
		ient->tidx = -1;
		ient->next_all = inter_all;
		inter_all = ient;
		*ev_out = oobi[i].ev;

		if (oobi != soob->oob_infop) {
			msg.type = NW_DEF_MSG_OOBNEW;
			msg.noob = i + 1;
			msg.oob_infop = oobi;
			MsgSend(soob->coid, &msg, sizeof(msg), NULL, 0);
		}

		return 0;
#endif
	}
#endif


	if ((flags & IRUPT_NOTHREAD) != 0) {
	       	if (++iinfo.ii_nentries_thread_unsafe == 1) {
			quiesce_all_arg(1, WT_CORE);
			unquiesce_all(); /* ourselves, others forced to die */
		}
	}
	else if (iinfo.ii_corecur < iinfo.ii_coremax &&
	    (ret = nw_pthread_create(NULL, NULL, receive_loop_multi, NULL,
	    WT_COREFLAGS, receive_loop_init, NULL)) != EOK) {
		log(LOG_ERR, "irupt thread creation: %d", ret);
	}

	/*
	 * Attempt to keep them spread out at startup.
	 * The load balancing code may move things around...
	 */

	if (prio == IRUPT_PRIO_DEFAULT) {
		prio = sctlp->rx_prio;
	}
	else {
	       	if (iinfo.ii_prio_default) {
			prio = sctlp->rx_prio;
		}
		else if (prio < 1 || prio > nw_max_prio) {
			log(LOG_ERR, "invalid prio: %d, ignored", prio);
			prio = sctlp->rx_prio;
		}
		else {
			iinfo.ii_prio_override = 1;
		}
	}

	for (i = 0; i < iinfo.ii_corecur; i++) {

		/* If we want to have a dedicated stack context worker
		 * thread, lets take the first corethread slot. The idea
		 * being is that we want a core available for stack context
		 * processing while other cores are handling interrupts. We
		 * will reserve one of the core slots for this purpose.
		 * If you are not the endpoint of traffic and are primarily
		 * forwarding between interfaces, you should still specify
		 * this option as IP flows are created in the stack context
                 * and you do not want this ability blocked due to CPU core
                 * being exhausted servicing the hardware.
		 */

		if (sctlp->dedicated_stack_context)
			/* Skip the first slot */
			tidx_cur = (iinfo.ii_tidx_next % (iinfo.ii_corecur - 1)) + 1;
		else
			tidx_cur = iinfo.ii_tidx_next % iinfo.ii_corecur;
		if ((itp = iinfo.ii_corethreads[tidx_cur]) != NULL) {
			ient->tidx = itp - iopkt_selfp->inter_threads;
			/* XXX This should work with both signal / pulse */
			itp->intr_ev.sigev_priority = prio;
		}
		if (ient->tidx != -1) {
			if (iinfo.ii_tidx_next >= iinfo.ii_corecur &&
			    iinfo.ii_prio_override && !iinfo.ii_prio_default) {
				/*
				 * We've assigned > 1 interrupt source to
				 * at least one interrupt thread.  This throws
				 * any previous custom priority settings out
				 * the window:
				 * - The first source assigned to this thread
				 *   just inherited this custom priority.
				 * - Even if you decide the above is OK, this
				 *   source may float to another handling
				 *   thread via the interrupt load balancing
				 *   scheme and not bring along its priority.
				 *
				 * This can be worked around by specifing
				 * the -t option to be >= number of interrupt
				 * sources.  The tradeoff is that by not
				 * sharing sources amongst handling threads,
				 * more notifications may be generated under
				 * load.
				 */
				iinfo.ii_prio_default = 1;
				log(LOG_INFO, "More interrupt sources than "
				    "handling threads.  Defaulting all "
				    "previous priority overrides.");
				for (itpp = &iinfo.ii_corethreads[0];
				    itpp < &iinfo.ii_corethreads[iinfo.ii_corecur];
				    itpp++) {
					itp = *itpp;
					if (itp == NULL)
						continue;
					itp->intr_ev.sigev_priority = sctlp->rx_prio;
				}
			}
			iinfo.ii_tidx_next++;
			break;
		}
		iinfo.ii_tidx_next++;
	}

	if (ient->tidx == -1)
		return EAGAIN;

	ient->next_all = inter_all;
	inter_all = ient;

	return 0;
}


int
interrupt_thread_reg(struct nw_work_thread *wtp_reg, int iscore)
{
	int			search_idx, i, irupt_max;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp_tmp;

	sctlp = &stk_ctl;

	irupt_max = sctlp->nthreads_core_max + sctlp->nthreads_oob_max;

	search_idx = 0;
	for (;;) {
		for (i = 0; i < sctlp->nwork_threads; i++) {
			if ((wtp_tmp = sctlp->work_threads[i]) == NULL ||
			    (wtp_tmp->flags & WT_IRUPT) == 0)
				continue;
			if (wtp_tmp->tidx_irupt == search_idx)
				break;

		}
		if (i >= sctlp->nwork_threads)
			break;
		if (++search_idx >= irupt_max)
			return EAGAIN;
	}
	/* If here, search_idx slot is unused */
	wtp_reg->tidx_irupt = search_idx;
	if (iscore) {
		/*
		 * Can't simply use search_idx as there
		 * may be an oob thread in the middle that
		 * we don't want to migrate interrupt
		 * entries to.
		 */
		if (iinfo.ii_corecur == iinfo.ii_coremax ||
		    iinfo.ii_corethreads[iinfo.ii_corecur] != NULL) {
			log(LOG_ERR, "irupt core reg");
		}

		iinfo.ii_corethreads[iinfo.ii_corecur++] =
		    &iopkt_selfp->inter_threads[search_idx];
	}

	return EOK;
}

/*
 * This thread which is handling interrupts is going
 * away.  We need to update any interrupt entries
 * with this idx and migrate any that are currently
 * in flight.
 */
void
interrupt_thread_dereg(struct nw_work_thread *wtp_dead)
{
	struct nw_work_thread	*wtp;
	struct _iopkt_inter	*ient, *ient_head, **ient_tail;
	struct inter_thread	*itp, *itp_dead;
	int			i;

	wtp = WTP;

	/* Make sure we're quiesced if not already. */
	quiesce_all();

	/*
	 * Move the entry's handling thread to ourself.
	 *
	 * Note:
	 * There's a window where an ISR could snap the old
	 * handling thread from the entry, then we flip it
	 * and lock the old handling thread's intrspin before
	 * the ISR (ISR may put it's ient on the old ithread's
	 * list).  Because of this we move the old ithread's
	 * event to one which will indicate such an occurance
	 * before unlocking its intrspin.
	 *
	 * Note:
	 * This may also move ients which had registered with
	 * an oob ithread to ourselves which must be non oob.
	 */
	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];
	itp_dead = &iopkt_selfp->inter_threads[wtp_dead->tidx_irupt];

	for (ient = inter_all; ient != NULL; ient = ient->next_all) {
		if (ient->tidx == wtp_dead->tidx_irupt)
			ient->tidx = wtp->tidx_irupt;
	}
	NW_INTR_LK(itp_dead);
	ient_head = itp_dead->inter_head;
	ient_tail = itp_dead->inter_tail;
	itp_dead->inter_head = NULL;
	itp_dead->inter_tail = &itp_dead->inter_head;
	/*
	 * We can't just do itp_dead->event = itp->event
	 * as doing so would open itp up to being hit while
	 * intr_sighot == 0.  Plus doing so would give no
	 * indication to look at itp_old's list.
	 */
	itp_dead->event = &ev_dead_thread;
	NW_INTR_UNLK(itp_dead);

	if (ient_head != NULL) {
		/* Will be processed when we unquiesce */
		NW_INTR_LK(itp);
		*itp->inter_tail = ient_head;
		itp->inter_tail = ient_tail;
		NW_INTR_UNLK(itp);
	}

	if ((wtp_dead->flags & WT_CORE) != 0) {
		for (i = 0; i < iinfo.ii_corecur; i++) {
			if (iinfo.ii_corethreads[i] ==
			    &iopkt_selfp->inter_threads[wtp_dead->tidx_irupt]) {
				break;
			}
		}

		if (i == iinfo.ii_corecur)
			log(LOG_ERR, "irupt core dereg");

		else {
			memmove(&iinfo.ii_corethreads[i],
			    &iinfo.ii_corethreads[i + 1],
			    (iinfo.ii_corecur - (i + 1)) *
			    sizeof(*iinfo.ii_corethreads));
			iinfo.ii_corethreads[iinfo.ii_corecur - 1] = NULL;
			iinfo.ii_corecur--;
		}
	}


	unquiesce_all();
}

void
interrupt_process_dead(struct nw_work_thread *wtp)
{
	int			i, lim;
	struct inter_thread	*itp, *itp_dead;
	struct _iopkt_inter	*ient_head, **ient_tail;

	log(LOG_INFO, "dead itp");

	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];

	lim = stk_ctl.nthreads_core + stk_ctl.nthreads_oob;

	for (i = 0; i < lim; i++) {
		itp_dead = &iopkt_selfp->inter_threads[i];
		if (itp_dead->event != &ev_dead_thread)
			continue;
		NW_INTR_LK(itp_dead);
		ient_head = itp_dead->inter_head;
		ient_tail = itp_dead->inter_tail;
		itp_dead->inter_head = NULL;
		itp_dead->inter_tail = &itp_dead->inter_head;
		NW_INTR_UNLK(itp_dead);

		if (ient_head != NULL) {
			NW_INTR_LK(itp);
			*itp->inter_tail = ient_head;
			itp->inter_tail = ient_tail;
			NW_INTR_UNLK(itp);
		}
	}

	process_interrupts(wtp);
}

/*
 * Make sure an interrupt callout isn't on any of our lists.
 */
int
interrupt_entry_remove(struct _iopkt_inter *rem, struct sigevent *ev)
{
	struct _iopkt_self	*iopkt;
	struct _iopkt_inter	*ient, **ientp;
	struct nw_stk_ctl	*sctlp;
	struct inter_thread	*itp;
	int			found, ret;
#if defined(OOB_THREAD_HIGH) || defined(OOB_THREAD_LOW)
	int			i;
	struct oob_info		*oobi;
#endif

	iopkt = iopkt_selfp;
	sctlp = &stk_ctl;

	if (!ISSTACK)
		panic("stack_interrupt_remove: unexpected context");

	found = 0;
	for (ientp = &inter_all; (ient = *ientp) != NULL;
	    ientp = &ient->next_all) {
		if (ient == rem) {
			*ientp = ient->next_all;
			found = 1;
			break;
		}
	}

	if (found == 0)
		return EINVAL;

	/* Make sure we're quiesced if not already. */
	quiesce_all();

	/*
	 * We are quiesced so rem->tidx shouldn't be changing.
	 *
	 * Note: this also means that if we do change rem->tidx,
	 * we must do so while it's not on a list, but before
	 * we knock down (struct _iopkt_inter).on_list.
	 */

	/*
	 * The following check is to weed out oob ients
	 * that requested a separate event.
	 */
	if ((unsigned)rem->tidx < sctlp->nthreads_core + sctlp->nthreads_oob) {
		itp = &iopkt->inter_threads[rem->tidx];

		NW_INTR_LK(itp);

		for (ientp = &itp->inter_head; (ient = *ientp) != NULL;
		    ientp = &ient->next) {
			if (ient == rem) {
				if ((*ientp = rem->next) == NULL)
					itp->inter_tail = ientp;
				break;
			}
		}

		NW_INTR_UNLK(itp);
	}


	if (ev == NULL) {
		/*
		 * They either:
		 * - aren't using an OOB thread.
		 * - using OOB but isr based (no separare event).
		 * - using OOB with separate event but only quieting
		 *   (have the event cached and may start up again).
		 */
		unquiesce_all();

		if ((rem->flags & IRUPT_NOTHREAD) != 0 &&
		    --iinfo.ii_nentries_thread_unsafe == 0) {
			found = 0;
			for (ient = inter_all; ient != NULL;
			    ient = ient->next_all) {
				if ((ient->flags & IRUPT_NOTHREAD) != 0) {
					log(LOG_ERR, "irupt rem nothread mismatch");
					continue;
				}
				if ((ient->flags &
				    (IRUPT_OOB_HIGH | IRUPT_OOB_LOW)) != 0) {
					continue;
				}
				if (++found == 1) {
					/*
					 * First one can always be handled by
					 * us proper.
					 */
					continue;
				}

				if (iinfo.ii_corecur < iinfo.ii_coremax) {
					if ((ret = nw_pthread_create(NULL, NULL,
					    receive_loop_multi, NULL,
					    WT_COREFLAGS,
					    receive_loop_init, NULL)) != EOK) {
						log(LOG_ERR, "irupt thread creation: %d", ret);
					}
					/*
					 * Hope the interrupt load sharing code
					 * spreads stuff around evenly.
					 */
				}
			}
		}

		return EOK;
	}
	
	found = 0;
#ifdef OOB_THREAD_HIGH
	for (i = 0, oobi = oob_ctl_high.oob_infop; i < oob_ctl_high.noob; i++, oobi++) {
		if (oobi->ev == ev) {
			if (oobi->inter != rem)
				log(LOG_WARNING, "oob rem mismatch\n"); /* very bad */
			oobi->inter = NULL;
			if (found++ == 0)
				free(ev, M_SOFTINTR);
			oobi->ev = NULL;
		}
	}
#endif
#ifdef OOB_THREAD_LOW
	for (i = 0, oobi = oob_ctl_low.oob_infop; i < oob_ctl_low.noob; i++, oobi++) {
		if (oobi->ev == ev) {
			if (oobi->inter != rem)
				log(LOG_WARNING, "oob rem mismatch\n"); /* very bad */
			oobi->inter = NULL;
			if (found++ == 0)
				free(ev, M_SOFTINTR);
			oobi->ev = NULL;
		}
	}
#endif

	if (found != 1)
		log(LOG_WARNING, "oob rem found count: %d\n", found); /* very bad */

	unquiesce_all();

	return EOK;
}


#ifdef OPT_SIGEV_SIGNAL_TID
static void
interrupt_non_critical(struct nw_work_thread *wtp)
{
	struct _iopkt_self	*iopkt;
	struct nw_stk_ctl	*sctlp;
	struct inter_thread	*itp_us;

	sctlp = &stk_ctl;

	iopkt = iopkt_selfp;

	itp_us = process_interrupts_noswitch(wtp);


	/* The InterruptLock is still held. */

	/*
	 * We are currently marked as being able to process 
	 * further interrupts (itp->working = 0 and
	 * wtp->intr_sighot == 1) but can't get a signal 
	 * until the 'extended' InterruptUnlock().
	 * below.
	 */

	/* restore */
	wtp->tls->errptr = &wtp->tls->errval;

	if (wtp->blocking &&
	    (wtp->inreceive == 0 || sctlp->recv_procp->p_ctxt.msg->type == NW_DEF_MSG_DEAD)) {
		CPU_RCV_LOOP_CTXT_RESTORE(wtp);
	}

	/* Go back to where we came from */
#if defined(__X86__)
	{
	struct intrspin __attribute__((__unused__)) *__check = (&itp_us->spin);
	__asm__ __volatile__ (
		/* XXX what about ss? */

#ifndef VARIANT_uni
		/*
		 * Clear the spin lock.  Other
		 * threads / interrupts on other cpus
		 * can then operate on intr_ctrl.ic_intr
		 * but we can't be swapped off of this
		 * cpu until the iret below.
		 */
		"movl $0, %0\n\t"
#endif
		/*
		 * If we were changing privity levels we
		 * could just do popa, iret but we aren't
		 * so iret only pops off eip, cs, efl and
		 * not sp.
		 */
		"movl %1, %%esp\n\t"
		"popa\n\t"
		"movl %%esp, %%eax\n\t"
		"movl 12(%%eax), %%esp\n\t"
		/*
		 * Following three are popped off by iret.
		 * We know flags have interrupt bit set
		 * so they'll be re-enabled.
		 */
		"pushl 8(%%eax)\n\t"	/* push saved flags */
		"pushl 4(%%eax)\n\t"	/* push cs */
		"pushl 0(%%eax)\n\t"	/* push eip */
		"movl -4(%%eax), %%eax\n\t"
		"iret\n\t"
			: "=m" (__atomic_fool_gcc(&itp_us->spin))
			: "r" (&wtp->jp->cpu)
			: "memory");
	}
#elif defined(__ARM__)
	itp_us->spin.value = 0;
	{
	void *ret_addr, *tmp;
	__asm__ __volatile__ (
		/*
		 * If our return addr is label 3, we're handling an
		 * interrupt signal that came in between the msr and
		 * ldmia instructions.  In that case, restore the
		 * 'real' saved context.
		 */
		"ldr %0, [%2, #60];" /* get context pc in reg */
		"adr %1, 3f;"        /* get label 3 addr in reg */
		"teq %0, %1;"
		"bne 1f;"
		/*
		 * jp->cpu (%2) isn't the real context we want to restore.
		 * We know the real one's addr is in jp->cpu[ARM_REG_R0]
		 * (see below).  The real one is either back on our entry
		 * (non interrupt) stack or stored in wtp->rx_loop_ctxt.
		 */

		/*
		 * We're using our interrupt stack here.  Reset sp from the
		 * previous context to eliminate any possibility of recursion.
		 * This is the wtp->saved_stack from the _first_ signal (ie
		 * not one generated between the msr and ldmia instructions).
		 */
		"ldr sp, [%2, #52];"
		"ldr %2, [%2, #0];"	/* make %2 point to _real_ context */
		"b 2f;"
		"1:;"
	    	/*
		 * We're using our interrupt stack here.  We need to
		 * restore sp before interrupts are enabled because if
		 * we get a signal between the msr and ldmia instructions,
		 * the kernel will place the context to restore on the
		 * interrupt stack which we then rewind (said context
		 * may be overwritten).  Note this doesn't rewind our entry
		 * stack past the original (real) context we may be trying
		 * to restore.
		 */
		"mov sp, %3;"
		"2:;"
		/*
		 * Save the _real_ context in r0.  This allows
		 * us to find it again if we get a signal between
		 * the msr and ldmia instructions (see above).
		 *
		 * Note: this works because the context we're trying
		 *       to restore is on our entry (non interrupt)
		 *       stack.
		 *
		 * XXX If someone can figure out how to force %2
		 *     to a particular register (input constraint),
		 *     this op can be removed as well as r0 from
		 *     the clobbers list.
		 */
		"mov r0, %2;"
		"ldr %1, [%2, #64];"   /* get context cpsr in reg */
//		"bic %1, %1, #0xc0;"   /* enable interrupts on msr (think these should already be cleared) */
		"msr cpsr, %1;"
		"3:;"
		"ldmia %2, {r0-r15};"
		: "=r&" (ret_addr),
		  "=r&" (tmp)
		: "r" (&wtp->jp->cpu),
		  "r" (wtp->saved_sp)
		: "r0" );
	}

#elif defined(__PPC__)
	{
	void *tmp;
	__asm__ __volatile__ (
			/* clear the spinlock */
#ifndef VARIANT_uni
		"sync;"

		"li %0, 0;"
		"stw %0, 0(%2);"
#endif
			
		"mr %%r1, %1;"
			
		"lwz %%r2, 128(%%r1);"
		"mtctr %%r2;"

		"lwz %%r2, 132(%%r1);"
		"mtlr %%r2;"

		"lwz %%r2, 136(%%r1);"	/* Move saved msr to SRR1 (restored to msr on rfi) */
		"mtspr 27, %%r2;"	/* SPR27 <-> SRR1 */

		"lwz %%r2, 140(%%r1);"	/* Move saved iar (pc) to SRR0 (restored to pc on rfi) */
		"mtspr 26, %%r2;"	/* SPR26 <-> SRR0 */

		"lwz %%r2, 144(%%r1);"
		"mtcr %%r2;"

		"lwz %%r2, 148(%%r1);"
		"mtxer %%r2;"

		"lmw %%r2, 8(%%r1);"	/* Restore gpr[2 - 31] */
		"lwz %%r0, 0(%%r1);"	/* Restore gpr[0]      */
		"lwz %%r1, 4(%%r1);"	/* Restore gpr[1]      */

		"rfi;"
		: "=r&" (tmp)
		: "r" (&wtp->jp->cpu),
		  "b" (&itp_us->spin)
	);
	}
#elif defined(__SH__)
	itp_us->spin.value = 0;
	__asm__ __volatile__ (
		"mov	%0, r11;"
		"mov.l	@r11, r0;"
		"mov.l	@(4,r11), r1;"
		"mov.l	@(8,r11), r2;"
		"mov.l	@(12,r11), r3;"
		"mov.l	@(16,r11), r4;"
		"mov.l	@(20,r11), r5;"
		"mov.l	@(24,r11), r6;"
		"mov.l	@(28,r11), r7;"
		"mov.l	@(32,r11), r8;"
		"mov.l	@(36,r11), r9;"
		"mov.l	@(40,r11), r10;"
		"mov.l	@(48,r11), r12;"
		"mov.l	@(52,r11), r13;"
		"mov.l	@(56,r11), r14;"
		"mov.l	@(60,r11), r15;"
		"add	#64, r11;"
		"ldc.l	@r11+, ssr;"
		"ldc.l	@r11+, spc;"
		"ldc.l	@r11+, gbr;"
		"lds.l	@r11+, mach;"
		"lds.l	@r11+, macl;"
		"lds.l	@r11+, pr;"
		"add	#-44, r11;"
		"mov.l	@r11, r11;"
		"rte;"
		:
		: "r" (&wtp->jp->cpu)
	);
#else
#error return from interrupt not defined for cpu.
#endif
}

void
interrupt_sig_handler(int signo, siginfo_t *sinfo, void *other)
{
	mcontext_t		*jp;
	ucontext_t		*context;
	struct nw_work_thread	*wtp;
	struct nw_stk_ctl	*sctlp;
	struct sigstack_entry	*ss;
	int			intr_errval;

	if (sinfo->si_pid != mypid)
		panic("someone's faking up signals: %d", sinfo->si_pid);

	/*
	 * XXX Not public info.
	 */
	ss = (struct sigstack_entry *)sinfo;

	context = other; /* XXX is this doc'd? */

	sctlp = &stk_ctl;

	wtp = sinfo->si_value.sival_ptr;

	jp = &context->uc_mcontext;


#ifndef NDEBUG
#if defined(__ARM__)
	/*
	 * Top 4 bits are flags.  Bits 6 and 7 are fast
	 * interrupt disable, interrupt disable respectively.
	 * When here we expect those to be 0 (both enabled).
	 * Bottom 5 bits are mode which we expect to be 1f.
	 * Bits 5 and 8 <-> 27 are unused and are expected to
	 * be 0.
	 */
		
	if ((jp->cpu.spsr & 0xc0) != 0) {
		panic("spsr: %x", jp->cpu.spsr);
	}
#endif


	intr_received[wtp->tidx_irupt]++;

	if (wtp->intr_sighot == _ISIG_COLD) {
		/*
		 * Bad interrupt handler that didn't
		 * set or honour itp->working?
		 */
		panic("Thread received unexpected interrupt signal.");
	}
	/*
	 * See comments in iopkt_siglock()
	 * WRT why we must not have mutex
	 * contention here and a iopkt_siglock()
	 * must be applied.
	 * Recall:
	 * - If a mutex is
	 *   local to the stack, it's never contested
	 *   and and therefore the kernel is never
	 *   entered while locking it.  This in turn
	 *   means ss->mutex will never contain its
	 *   value.
	 * - The interrupt signal is held off while
	 *   in the interrupt context.  Therefore
	 *   mutex accesses in the interrupt context
	 *   will never be interrupted.
	 */

	if (ss->mutex && wtp->wt_critical == 0)
		panic("Unprotected contested mutex detected: %p", ss->mutex);
	
	if (wtp->tls->errptr != &wtp->tls->errval)
		panic("tls errno");
#endif

	cpu_sigcontext_validate(ss, jp);

	wtp->intr_sighot = _ISIG_COLD; /* At least this is what we expect */

	if (wtp->wt_critical == 0) {
		/*
		 * We want to handle interrupts with a different stack to avoid
		 * having to grow each coroutine's stack sufficiently large.
		 * This way we only need one interrupt stack per real thread.
		 */

		/*
		 * tls->errptr currently points to tls->errval.
		 * Move it over for the interrupt so errno is
		 * not munged on return.
		 */
		wtp->tls->errptr = &intr_errval;

#ifdef MANAGE_STACKBASE_ON_INTR
		/*
		 * I'm not sure this is worth it. &tls->errptr
		 * and &tls->stackaddr are sufficiently spread
		 * to possibly be on different cache lines.
		 */
		wtp->saved_stackbase = wtp->tls->stackaddr;
#endif

		wtp->jp = jp; 

		/* May or may not save current stack depending on arch */
		CPU_STACK_INTERRUPT_NON_CRITICAL(wtp);

		/*
		 * Our stack frame is no longer valid so
		 * perform a call to set up a new one.
		 */

		interrupt_non_critical(wtp);
	}
	else {
		/*
		 * Even though interrupts are enabled below, this
		 * thread can't get a signal as we haven't knocked
		 * down our itp->working yet (provided isr's honour
		 * itp->working).
		 */
		wtp->wt_intr_pending = 1;
#if defined(__X86__)
		__asm__ __volatile__ (
			/* XXX what about cs, ss? */
			"movl %0, %%esp\n\t"
			"popa\n\t"
			"movl %%esp, %%eax\n\t"
			"movl 12(%%eax), %%esp\n\t"
			"pushl 0(%%eax)\n\t"		/* push return addr */
			"pushl 8(%%eax)\n\t"		/* push saved flags */
			"movl -4(%%eax), %%eax\n\t"
			"popf\n\t"
			"ret"
			:
			: "r" (&jp->cpu));
#elif defined(__ARM__)
		{
		void *tmp;
		__asm__ __volatile__ (
			"ldr %0, [%1, #64];"  /* get context cpsr in reg */
//			"bic %0, %0, #0xc0;"  /* enable interrupts on msr (think these should already be cleared) */
			"msr cpsr, %0;"
			"ldmia %1, {r0-r15};"
			: "=r&" (tmp)
			: "r" (&jp->cpu));
		}
#elif defined(__PPC__)
		/*
		 * The only way I'm aware of to do a branch without having
		 * a dirty register is through the rfi instruction.  However
		 * in order to use this without SRR0 SRR1 changing we need
		 * to disable interrupts on this CPU.  Note that reaching
		 * here (signaled while in critical section) is low runner.
		 */

		__asm__ __volatile__ (
			"mr %%r1, %0;"
			"lwz %%r0, 0(%%r1);"	/* Restore gpr[0]      */
			"lmw %%r3, 12(%%r1);"	/* Restore gpr[3 - 31] */
			
			"lwz %%r2, 128(%%r1);"
			"mtctr %%r2;"

			"lwz %%r2, 132(%%r1);"
			"mtlr %%r2;"

			"lwz %%r2, 144(%%r1);"
			"mtcr %%r2;"

			"lwz %%r2, 148(%%r1);"
			"mtxer %%r2;"

			/*
			 * Disable interrupts while changing SRR0, SRR1.
			 * Re-enabled on rfi.
			 */
			"mfmsr %%r2;"
			"rlwinm %%r2, %%r2, 0, 17, 15;"
			"mtmsr %%r2;"

			"lwz %%r2, 136(%%r1);"	/* Move saved msr to SRR1 (restored to msr on rfi) */
			"mtspr 27, %%r2;"	/* SPR27 <-> SRR1 */

			"lwz %%r2, 140(%%r1);"	/* Move saved iar (pc) to SRR0 (restored to pc on rfi) */
			"mtspr 26, %%r2;"	/* SPR26 <-> SRR0 */

			"lwz %%r2, 8(%%r1);"	/* Restore gpr[2] */
			"lwz %%r1, 4(%%r1);"	/* Restore gpr[1]      */

			"rfi;"
			:
			: "r" (&jp->cpu));
#elif defined(__SH__)
#error needs testing
		/*
		 * The only way I'm aware of to do a branch without having
		 * a dirty register is through the rfe instruction.  However
		 * in order to use this without ssr spc changing we need
		 * to disable interrupts on this CPU.  Note that reaching
		 * here (signaled while in critical section) is low runner.
		 */

		InterruptDisable();
		__asm__ __volatile__ (
			"mov	%0, r11;"
			"mov.l	@r11, r0;"
			"mov.l	@(4,r11), r1;"
			"mov.l	@(8,r11), r2;"
			"mov.l	@(12,r11), r3;"
			"mov.l	@(16,r11), r4;"
			"mov.l	@(20,r11), r5;"
			"mov.l	@(24,r11), r6;"
			"mov.l	@(28,r11), r7;"
			"mov.l	@(32,r11), r8;"
			"mov.l	@(36,r11), r9;"
			"mov.l	@(40,r11), r10;"
			"mov.l	@(48,r11), r12;"
			"mov.l	@(52,r11), r13;"
			"mov.l	@(56,r11), r14;"
			"mov.l	@(60,r11), r15;"
			"add	#64, r11;"
			"ldc.l	@r11+, ssr;"
			"ldc.l	@r11+, spc;"
			"ldc.l	@r11+, gbr;"
			"lds.l	@r11+, mach;"
			"lds.l	@r11+, macl;"
			"lds.l	@r11+, pr;"
			"add	#-44, r11;"
			"mov.l	@r11, r11;"
			"rte;"
			:
			: "r" (&jp->cpu)
		);
#else
	#error return from sig not defined for cpu
#endif
	}
}
#endif /* OPT_SIGEV_SIGNAL_TID */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/interrupt.c $ $Rev: 902838 $")
#endif
