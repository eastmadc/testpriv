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




#include <malloc.h>

#include "opt_sigev.h"
#include "opt_oob.h"

#include "qnet.h"

#include <sys/param_bsd.h>
#include <sys/siginfo.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/types_bsd.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/mbuf.h>
#include <sys/callout.h>
#include <sys/systm.h>
#include <sys/netmgr.h>
#include <string.h>
#include <sys/nw_cpu_misc.h>
#include <net/if.h>
#include <netinet/ip_var.h>
#include "nw_datastruct.h"
#include "nw_dl.h"
#include "nw_intr.h"
#include "siglock.h"
#include "quiesce.h"
#include "receive.h"
#include "nw_thread.h"
#include "nw_tls.h"
#include "init_main.h"

extern char *__progname;

#if defined(FAKE_UP_WRITES) || (defined(USE_PULSE) && defined(TRACK_DELTAS))
static int dbug_receive(resmgr_context_t *ctp, int chid, struct nw_stk_ctl *sctlp);
static void * do_memcpy(void *dst, void *src, size_t len);
#endif

static void lowres_log(int, int);
static void network_read(resmgr_context_t *, struct nw_stk_ctl *, struct nw_work_thread *);
void quiesce_core(void *, int);
#if defined(OOB_THREAD_HIGH) || defined(OOB_THREAD_LOW)
void quiesce_oob(void *, int);
#endif


#undef NW_SIGUNHOLD_P

#define NW_SIGUNHOLD_P(wtp) do {		\
	--(wtp)->wt_critical;			\
	assert((wtp)->wt_critical == 0);	\
	if ((wtp)->wt_intr_pending) {		\
		(wtp)->wt_intr_pending = 0;	\
		process_interrupts((wtp));	\
	}					\
} while (0)


#include "delta.h"
#if defined(USE_PULSE) && defined(TRACK_DELTAS)
struct task_time task_times[TASK_TIME_TOT] = {
	{"Time between msg being sent and msg being rcvd"}, /* TASK_TIME_MSG_SEND           */
	{"Time in process_interrupts()"},                   /* TASK_TIME_PROCESS_INTERRUPTS */
	{"Time in softclock()"},                            /* TASK_TIME_SOFTCLOCK          */
	{"Time in resmgr layer"}                            /* TASK_TIME_RESMGR             */
};
#endif
#ifdef FAKE_UP_WRITES
static struct {
	int todo;
	int rcvid;
	struct _msg_info info;
	struct sendto_dbug sendto_dbug;
} fake_write;
#endif

extern void _resmgr_handler(resmgr_context_t *ctp);
static pid_t mypid;
static int rargs_sigev_type;

/*
 * _resmgr_unblock_handler() likes to MsgRead() openfd
 * messages sometimes and assumes at least this much space.
 */
static union {
	struct _pulse     no_res_pulse;
	struct _io_openfd no_res_openfd;
} no_res_msg_buf;

#ifdef OPT_SIGEV_PULSE
struct pulse_intr_into {
	int			tidx_handler;
	int			chid;
	int			coid;
	struct pulse_intr_into	*next;
} *pii_list;

#define wt_piip wt_specialized.sival_ptr
#endif

struct stk_callback_2 {
	void				(*func)(void *);
	void				*arg;
	struct device			*dev;
	TAILQ_ENTRY(stk_callback_2)	entries;
};
TAILQ_HEAD(, stk_callback_2) stk_callback_2_head;
static pthread_mutex_t stk_cb_2_mutex = PTHREAD_MUTEX_INITIALIZER;

extern pthread_t cleanup_stack_tid;
extern int in_cleanup;

static void
dodie(void)
{
	int			die;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;

	die = 1;
	sctlp = &stk_ctl;
	wtp = WTP;

	/*
	 * cleanup_stack_tid is both the addr that we're supposed
	 * to signal and where we're supposed to store
	 * the tid of the last thread to exit (us).
	 */
	pthread_sleepon_lock();
	if (in_cleanup) {
		cleanup_stack_tid = NW_TIDX_TO_TID(wtp->tidx_wt);
		pthread_sleepon_signal(&cleanup_stack_tid);
	}
	else {
		log(LOG_WARNING, "Spurious dodie pulse ignored");
		pthread_sleepon_unlock();
		return;
	}
	pthread_sleepon_unlock();

	doshutdownhooks();
	quiesce_all_arg(die, 0);
	main_fini(-1, EOK, NULL);

	pthread_exit(NULL);
}


static void
replenish_recv_buf(struct nw_stk_ctl *sctlp, struct nw_work_thread *wtp)
{
	int i;
	uintptr_t up;
	struct mbuf *m;
	iov_t *iovp;

	i = sctlp->recv_max - sctlp->recv_avail;
	if (i) {
		/* Undo, see below */
		if (i < sctlp->recv_max &&
		    ((m = sctlp->recv_mbuf[sctlp->recv_start])->m_flags & M_PKTHDR)) {
			m->m_flags &= ~M_PKTHDR;
			m->m_len += NW_DEF_HDR_LEN;
			m->m_data -= NW_DEF_HDR_LEN;

			iovp = &sctlp->recv_iov[sctlp->recv_start];

			iovp->iov_len += NW_DEF_HDR_LEN;
			up = (uintptr_t)iovp->iov_base;
			up -= NW_DEF_HDR_LEN;
			iovp->iov_base = (void *)up;
		}

		do {
			m = m_getcl_wtp(M_DONTWAIT, MT_DATA, 0, wtp);
			if (m == NULL)
				break;

			/*
			 * reset this in tcpip_write()?
			 * We'll need to vary first (depending on
			 * type of write (_IO_XTYPE) and last (depending on
			 * total length).
			 */
			m->m_len = MCLBYTES;

			m->m_next = sctlp->recv_mbuf[i];

			sctlp->recv_start = --i;

			sctlp->recv_mbuf[i] = m;
			SETIOV(&sctlp->recv_iov[i], m->m_data, MCLBYTES);

			sctlp->recv_avail++;
		} while(i);
	}

	if (sctlp->recv_avail > 0 &&
	    ((m = sctlp->recv_mbuf[sctlp->recv_start])->m_flags & M_PKTHDR) == 0) {
		m->m_flags |= M_PKTHDR;
		m->m_pkthdr.len        = 0;
		m->m_pkthdr.rcvif      = NULL;
		m->m_pkthdr.csum_data  = 0;
		m->m_pkthdr.csum_flags = 0;
		SLIST_INIT(&m->m_pkthdr.tags);

		m->m_len  -= NW_DEF_HDR_LEN;
		m->m_data += NW_DEF_HDR_LEN;

		iovp = &sctlp->recv_iov[sctlp->recv_start];

		iovp->iov_len -= NW_DEF_HDR_LEN;
		up = (uintptr_t)iovp->iov_base;
		up += NW_DEF_HDR_LEN;
		iovp->iov_base = (void *)up;
	}

	return;
}

static int
process_pkts(struct nw_stk_ctl *sctlp, struct nw_work_thread *wtp)
{
	struct ifqueue *ifq;
	int done = 0;
	struct mbuf *m;

	for (;;) {
		NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		if ((ifq = sctlp->pkt_rx_q) == NULL)
			break;

		sctlp->pkt_rx_q = ifq->ifq_next;
		if (ifq->ifq_dequeue == NULL)
			IF_DEQUEUE(ifq, m); /* should never fail */
		else
			m = (*ifq->ifq_dequeue)(ifq);
		/*
		 * XXX 
		 * We've used m here as IF_DEQUEUE() expects
		 * a struct mbuf but m may not actually point
		 * at one if it was returned out by ifq_dequeue()
		 * above so don't dereference it.
		 */
		if (ifq->ifq_len == 0) {
			if (ifq->ifq_next == ifq) {
				sctlp->pkt_rx_q = NULL;
			}
			else {
				ifq->ifq_next->ifq_prev = ifq->ifq_prev;
				*ifq->ifq_prev = ifq->ifq_next;

				ifq->ifq_next = ifq;
				ifq->ifq_prev = &ifq->ifq_next;
			}
		}
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		(*ifq->ifq_intr)(m);
		done++;
	}

	return done;
}

static void
process_msg(struct nw_stk_ctl *sctlp, struct nw_work_thread *wtp)
{
	resmgr_context_t *ctp;
	int ret;

	ctp = &sctlp->recv_procp->p_ctxt;

	if (ctp->rcvid == 0) {
		/*
		 * Should be a pulse.  _resmgr_handler() does the 
		 * validity checking to make sure this is so.  The
		 * two pulses we're interested in are msg->pulse.code ==
		 *  _PULSE_CODE_DISCONNECT / _PULSE_CODE_UNBLOCK.
		 */

		switch (ctp->msg->pulse.code) {
		case NW_DEF_PULSE_CODE_DODIE:
			/*
			 * We let the stack clean up to avoid any races with creation
			 * of oob threads (created by stack).
			 */
			dodie();  /* Doesn't return */
			break;

		case NW_DEF_PULSE_CODE_PROGMGR_EVENT:
			/* always NULL terminates. ret includes NULL */
			ret = confstr(_CS_HOSTNAME, hostname,  sizeof(hostname));
			/* strlen(hostname) */
			hostnamelen = min(ret, sizeof(hostname)) - 1;
			return;

		case NW_DEF_PULSE_CODE_IRUPT_CORE: {
			/*
			 * This thread shouldn't get this code if
			 * we're only using signals.
			 */
#ifdef OPT_SIGEV_PULSE
			struct inter_thread *itp;

			itp = process_interrupts_noswitch(wtp);
			NW_INTR_UNLK(itp);
#endif
			return;
		}

		case NW_DEF_PULSE_CODE_DEAD_IRUPT:
			interrupt_process_dead(wtp);
			break;

		case NW_DEF_PULSE_CODE_POKE_PKT:
		case NW_DEF_PULSE_CODE_TIMER:
			/* We've been poked.  Nothing else to do here. */
			return;

		case NW_DEF_PULSE_CODE_CALLBACK: {
			struct stk_callback *cb;
			struct stk_callback_2 *scb;

			cb = ctp->msg->pulse.value.sival_ptr;
			if (cb == 0) {
				/* New version */
				pthread_mutex_lock(&stk_cb_2_mutex);
				scb = TAILQ_FIRST(&stk_callback_2_head);
				if (scb) {
					TAILQ_REMOVE(&stk_callback_2_head,
						     scb, entries);
					pthread_mutex_unlock(&stk_cb_2_mutex);
					scb->func(scb->arg);
					(free)(scb);
				} else {
					pthread_mutex_unlock(&stk_cb_2_mutex);
					log(LOG_ERR, "Empty stack callback queue");
				}
			} else {
				/*
				 * Some drivers pulse manually so
				 * need to keep this method available
				 */
				cb->func(cb->arg);
			}
			return;
		}

		case NW_DEF_PULSE_CODE_TIMER_GROUP: {
			callout_group(ctp->msg->pulse.value.sival_int);
			return;
		}
			
		default:
			break;
		}

		/*
		 * Pulse operations shall not block.
		 * This includes _IO_CLOSE handling
		 * which may be faked up by code that
		 * handles disconnect pulses.
		 */
		PR_TO_LWP(sctlp->recv_procp)->l_prio.prio = ctp->info.priority;
		sctlp->recv_procp->p_curmsg = _IO_RSVD_UNBLOCK;
		_resmgr_handler(ctp);

		/*
		 * Don't need to manipulate recv_loaded_proc.
		 * If it non NULL it will be used for next msg
		 * which is OK since the above didn't block.
		 */
	}
	else {
		/* We know recv_proc == recv_loaded_proc since not a pulse */
		sctlp->recv_loaded_proc = NULL;
		if ((sctlp->bigstack_size != 0) &&
		    (ctp->msg->type == _IO_CONNECT) &&
		    (ctp->msg->connect.subtype == _IO_CONNECT_MOUNT)) {
			pcreat_setbigstack(sctlp->recv_procp);
		}
		pcreat(sctlp->recv_procp, startproc, sctlp);
	}
}


#ifndef VARIANT_uni

/*
 * Expects to be called with pkt_ex locked.  Returns
 * with it unlocked.
 */
void
poke_stack_pkt_q(void)
{
	struct nw_stk_ctl			*sctlp;

	sctlp = &stk_ctl;
	/*
	 * We check stack_inuse with pkt_ex rather than
	 * stack_ex because receive_loop_uniprocessor()
	 * assumes exclusive access to stack status flags
	 * and never locks stack_ex.  However, we make sure
	 * in all cases that stack_inuse moves from 1 -> 0
	 * with pkt_ex locked.  This means there's a small
	 * window where a false wakeup can occur but no
	 * window where processing of rx packets generated
	 * by this oob loop can be held off for a timer
	 * tick.
	 */
	if (sctlp->stack_inuse == 0 &&
	    sctlp->pkt_rx_q != NULL &&
	    sctlp->pkt_rx_q->ifq_next == sctlp->pkt_rx_q &&
	    sctlp->pkt_rx_q->ifq_len == 1) {
		/* The stack's not busy and this is the first packet queued */

		/*
		 * Unlock before sending pulse, in case we're running at
		 * prio < rx_pulse_prio (extra context switches).
		 */
		NW_EX_UNLK(&sctlp->pkt_ex, iopkt_selfp);
		MsgSendPulse(sctlp->coid, sctlp->rx_prio, NW_DEF_PULSE_CODE_POKE_PKT, 0);
	}
	else
		NW_EX_UNLK(&sctlp->pkt_ex, iopkt_selfp);
}


/*
 * Call a function from stack context. No need for any kind of stack locking.
 */

int
stk_context_callback(struct stk_callback *cb)
{
	return MsgSendPulse(stk_ctl.coid, stk_ctl.rx_prio,
			    NW_DEF_PULSE_CODE_CALLBACK, (int)cb);
}

int
stk_context_callback_2 (void (*func)(void *), void *arg, struct device* dev)
{
	struct stk_callback_2 *scb;
	int rc;

	scb = (malloc)(sizeof(*scb));
	if (scb == NULL) {
		errno = ENOMEM;
		return -1;
	}
        scb->func = func;
        scb->arg = arg;
        scb->dev = dev;
	pthread_mutex_lock(&stk_cb_2_mutex);
	TAILQ_INSERT_TAIL(&stk_callback_2_head, scb, entries);
	pthread_mutex_unlock (&stk_cb_2_mutex);
	rc = MsgSendPulse(stk_ctl.coid, stk_ctl.rx_prio,
			  NW_DEF_PULSE_CODE_CALLBACK, 0);
	if (rc == -1) {
		/* Failed to send pulse so remove the queued callback */
		pthread_mutex_lock(&stk_cb_2_mutex);
		TAILQ_REMOVE(&stk_callback_2_head, scb, entries);
		(free)(scb);
		pthread_mutex_unlock (&stk_cb_2_mutex);
	}
	return rc;
}

void stk_context_callback_2_clean (struct device* dev)
{
	struct stk_callback_2 *scb, *next_scb;

	pthread_mutex_lock(&stk_cb_2_mutex);
	scb = TAILQ_FIRST(&stk_callback_2_head);
	while (scb != NULL) {
		next_scb = TAILQ_NEXT(scb, entries);
		if (scb->dev == dev) {
			TAILQ_REMOVE(&stk_callback_2_head, scb, entries);
			(free)(scb);
		}
		scb = next_scb;
	}
	pthread_mutex_unlock(&stk_cb_2_mutex);
}

static void
lowres_log(int nothread, int nobuf)
{
	static int thread_exhaust_logged;
	static int buf_exhaust_logged;

	if (nothread && !thread_exhaust_logged) {
		log(LOG_WARNING, "Threads exhausted."
		  "  See \"threads_max\" option");
		thread_exhaust_logged = 1;
	}
	if (nobuf && !buf_exhaust_logged) {
		log(LOG_WARNING, "Mbufs exhausted."
		  "  May be temporarily unable to handle userland IO");
		buf_exhaust_logged = 1;
	}
}


/*
 * multiple threads can become 'the stack'.
 * stack_ex comes into play.
 */
void *
receive_loop_multi(void *arg)
{
	struct nw_work_thread	*wtp;
	struct proc		*proc0, *p2;
	resmgr_context_t	*ctp;
	int			incr, msg_max_size_tot;
	int			chid, do_msg, notify_type;
	struct nw_stk_ctl	*sctlp;
	struct rcv_loop_args	*rargs;
#ifdef OPT_SIGEV_PULSE
	struct pulse_intr_into	*piip;
	struct inter_thread	*itp;
#endif
	struct _pulse		not_used; /* Required by MsgReceivePulse() */

	rargs = arg;
	wtp = WTP;
	notify_type = iopkt_selfp->inter_threads[wtp->tidx_irupt].event->sigev_notify;
	sctlp = &stk_ctl;
#ifdef OPT_SIGEV_PULSE
	wtp->wt_piip = piip = NULL;
#endif

	/* ragrs is non null only the first time through. */
	if (rargs != NULL) {
		int ret;

		/* Make sure no thread receives a message */
		if (!wtp->am_stack)
			panic("rloop init");

		/*
		 * Make sure proc0 pulse msg buffer is initialized before
		 * first msg is received.
		 */
		sctlp->proc0->p_ctxt.msg          = (resmgr_iomsgs_t *)&no_res_msg_buf;
		sctlp->proc0->p_ctxt.msg_max_size = sizeof(no_res_msg_buf);

		mypid = getpid();

		/*
		 * We need to start other threads here rather
		 * than our init func since the parent thread
		 * doesn't return until the init function does.
		 */
		if (rargs->preseed_threads) {
			while (sctlp->nthreads_core < sctlp->nthreads_core_max) {
				if ((ret = nw_pthread_create(NULL, NULL,
				    receive_loop_multi, NULL, WT_COREFLAGS,
				    receive_loop_init, rargs)) != EOK) {
					log(LOG_ERR, "rloop thread create: %d", ret);
				}
			}
		}

	}

	/* First one (not on sctlp->freeprocs list) */
	proc0 = sctlp->proc0;
	chid  = sctlp->chid;

	/*
	 * Load drivers and modules specified on the command line
	 * This is a kthread_create1() but setting the bigstack flag
	 * if it is needed.
	 */
	if (rargs) {
		p2 = sctlp->freeprocs;
		if (p2 == NULL) {
			panic("No freeprocs");
		}
		sctlp->freeprocs = LWP_TO_PR(PR_TO_LWP(p2)->l_forw);
		PR_TO_LWP(p2)->l_forw = NULL;
		p2->p_ctxt.info.priority = sctlp->rx_prio;
		if (sctlp->bigstack_size != 0) {
			pcreat_setbigstack(p2);
		}
		pcreat(p2, load_drivers, rargs);
	}

#ifdef OPT_SIGEV_SIGNAL_TID
	/*
	 * The top of our loop which will be jumped 
	 * to to wake us out of a blocked state.
	 */
	CPU_RCV_LOOP_CTXT_STORE(wtp);
#endif
#ifdef OPT_SIGEV_PULSE
again:
#endif
	wtp->blocking = 0;

#ifdef OPT_SIGEV_PULSE
	if (piip != NULL) {
		/* Using pulses */
		wtp->tidx_irupt = piip->tidx_handler;
		itp = process_interrupts_noswitch(wtp);
		NW_INTR_UNLK(itp);
	}
#endif

	NW_SIGLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);

	if (wtp->inreceive == 1) {
		wtp->inreceive = 0;
		sctlp->thread_inreceive = 0;
	}

	if (sctlp->dedicated_stack_context) {
		if (wtp->flags & WT_STACKCONTEXT) {
			sctlp->stack_inuse = 1;
			wtp->am_stack = 1;
		}
	} else {
		if (sctlp->stack_inuse == 0) {
			sctlp->stack_inuse = 1;
			wtp->am_stack = 1;
		}
	}

	switch (notify_type) {
#ifdef OPT_SIGEV_PULSE
	case SIGEV_PULSE:
		if (wtp->am_stack == 0) {
		       	if (piip == NULL) {
				wtp->wt_piip = piip = pii_list;
				pii_list = piip->next;
			}
		}
		else {
			wtp->tidx_irupt = 0;
			if (piip != NULL) {
				piip->next = pii_list;
				pii_list = piip;
				wtp->wt_piip = piip = NULL;
			}
		}
		break;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
	case SIGEV_SIGNAL_TID:
		/* nothing */
		break;
#endif
	default:
		panic("rloop multi");
		break;
	}

	NW_SIGUNLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);

	do_msg = 0;
	while (wtp->am_stack) {
		/*
		 * The order really is packets before
		 * timeouts before io messages.  Trying
		 * hardclock() first makes it possible
		 * to avoid and extra lock / unlock of
		 * pkt_ex when no packets pending
		 * (hardclock() always earlies out anyway).
		 */
		if (hardclock(sctlp)) {
			process_pkts(sctlp, wtp);
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			continue;
		}

		if (do_msg) {
			/*
			 * Will handle immediately if pulse (pulses never freed),
			 * otherwise will Q to sctlp->proc_prio.prio_all.
			 */
			process_msg(sctlp, wtp);

			if (sctlp->nprocs_used >= sctlp->nprocs_cur_max &&
			    (incr = min(sctlp->nprocs_incr, sctlp->nprocs_max - sctlp->nprocs_cur_max))) {
				add_procs(sctlp, incr, incr);
			}

			do_msg = 0;
		}

		if (sctlp->proc_prio.prio_all.tail) {
			if (sctlp->pkt_rx_q) {
				process_pkts(sctlp, wtp);
				NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
				continue;
			}
			/*
			 * If we just became the stack, this following will
			 * overwrite the previous value.
			 */
			proc0->p_stkbase = wtp->tls->NW_TLS_STACKADDR;
			PR_TO_LWP(proc0)->l_stat = LREADY;
			resched(proc0);
		}


		/*
		 * Process pkts may ready some procs, or one that
		 * was serviced during resched() above may have 
		 * noticed pkts were pending and earlied out.
		 */

		if (process_pkts(sctlp, wtp) >= NW_DEF_SOFTCLOCK_PKT_LIM || sctlp->proc_prio.prio_all.tail) {
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			continue;
		}


		NW_EX_LK(&sctlp->stack_ex, iopkt_selfp);
		if (sctlp->msg_outstanding) {
			sctlp->msg_outstanding = 0;
			NW_EX_UNLK(&sctlp->stack_ex, iopkt_selfp);
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			do_msg = 1;
			continue;
		}

		/*
		 * Knock this down before pkt_ex unlocked for
		 * oob thread(s) if present.
		 */
		sctlp->stack_inuse = 0;

		/* If we are the dedicated stack context thread, we
		 * are always am_stack, but not stack_inuse while
		 * idle so the poke is triggered.
		 */

		if (!sctlp->dedicated_stack_context)
			wtp->am_stack = 0;
		if (sctlp->thread_inreceive) {
			switch (notify_type) {
#ifdef OPT_SIGEV_PULSE
			case SIGEV_PULSE:
				wtp->wt_piip = piip = pii_list;
				pii_list = piip->next;
				piip->next = NULL;
				break;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
			case SIGEV_SIGNAL_TID:
				/* nothing */
				break;
#endif
			default:
				panic("rloop multi");
				break;
			}

			NW_EX_UNLK(&sctlp->stack_ex, iopkt_selfp);
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			break;
		}
		sctlp->thread_inreceive = 1;

		/*
		 * Preload proc for next message before unlocking stack mutex
		 * because procs can become unblocked, finish and be put back
		 * on freeprocs list while in process_pkts() which does not
		 * follow the MsgReceive(), pass to stack and process_msg()
		 * lock step.  ie. as soon as we unlock, process_pkts() can
		 * proceed which may manipulate freeprocs list independent
		 * of a new msg being received.
		 *
		 * Wait to increment nprocs_used in pcreat().
		 */
		if (sctlp->recv_loaded_proc == NULL && (sctlp->recv_loaded_proc = sctlp->freeprocs) != NULL) {
			sctlp->freeprocs = LWP_TO_PR(PR_TO_LWP(sctlp->recv_loaded_proc)->l_forw);
			PR_TO_LWP(sctlp->recv_loaded_proc)->l_forw = NULL;
		}

		NW_EX_UNLK(&sctlp->stack_ex, iopkt_selfp);
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);

		/*
		 * OK to manipulate sctlp->recv_* here with no mutex
		 * because we know:
		 * - mbuf / mcluster pools themselves are thread safe.
		 * - No outstanding messages so stack won't be looking
		 *   at them. 
		 * - Noone else in MsgReceive() to seed a message for
		 *   stack to look at.
		 * - When stack does process_msg(), sctlp->recv_* are all 
		 *   updated before blocking (ltsleep()) so we don't get 
		 *   into the window where process_pkts() can unblock a 
		 *   struct proc while another thread is manipulating
		 *   sctlp->recv_* here.
		 */
		replenish_recv_buf(sctlp, wtp);

		if (sctlp->recv_avail != 0 && sctlp->recv_loaded_proc != NULL) {
			ctp = &sctlp->recv_loaded_proc->p_ctxt;

			ctp->msg = sctlp->recv_iov[sctlp->recv_start].iov_base;
			/*
			 * The resmgr library likes stuff in one continuous buf
			 * so restrict it to first iov.
			 */
			ctp->msg_max_size = MCLBYTES - NW_DEF_HDR_LEN;
			/* The real length */
			msg_max_size_tot = (sctlp->recv_avail * MCLBYTES) - NW_DEF_HDR_LEN;

			/*
			 * This is for the case where we
			 * unlock and get an interrupt signal
			 * before we block.  In that case we
			 * want to make sure we process_pkts()
			 * before blocking.  If msg.type gets
			 * flipped before we re-lock, we know
			 * we got a message and we can't go to
			 * the top out loop or we lose the rcvid.
			 *
			 * Note there always the chance someone
			 * sends a message of type NW_DEF_MSG_DEAD.
			 * and we lose their rcvid.  In that
			 * case we'll still get the unblock pulse
			 * eventually (let them wait if they're
			 * sending garbage).
			 */
			ctp->msg->type = NW_DEF_MSG_DEAD;
			ctp->rcvid = -1;

			/*
			 * Save which proc we're working with because if 
			 * we get a pulse, it may not be in recv_loaded_proc
			 * even if non NULL if we're out of memory.
			 */
			sctlp->recv_procp = sctlp->recv_loaded_proc;

#ifndef NDEBUG
			assert(wtp->wt_critical == 0);
#endif
			/*
			 * Watch the order.  As soon as blocking is set
			 * we may jump to top of loop.   We need inreceive
			 * at top of loop so we knock down
			 * sctlp->thread_inreceive.
			 */
			wtp->inreceive = 1;
			wtp->blocking = 1;
#if !defined(FAKE_UP_WRITES) && !(defined(USE_PULSE) && defined(TRACK_DELTAS))
			ctp->rcvid = MsgReceivev(chid, &sctlp->recv_iov[sctlp->recv_start],
				sctlp->recv_avail, &ctp->info);
#else
			ctp->rcvid = dbug_receive(ctp, chid, sctlp);
#endif
			wtp->blocking = 0;
			wtp->inreceive = 0;

			/*
			 * If doing a network transaction and not all
			 * the message was sent, must get the remainder.
			 *
			 * rcvid == 0 implies a pulse in which case the
			 * msglen fields are not valid.
			 */
			if (ctp->rcvid > 0 &&
			    ctp->info.srcmsglen > ctp->info.msglen &&
			    ctp->info.msglen < msg_max_size_tot) {
				network_read(ctp, sctlp, wtp);
			}
		}
		else {
			lowres_log(sctlp->recv_loaded_proc == NULL,
			    sctlp->recv_avail == 0);
			sctlp->recv_procp = proc0;
			/*
			 * proc0 must always be SREADY if here (pulse
			 * operations shalt not block).
			 */
			ctp = &proc0->p_ctxt;
			ctp->msg->type = NW_DEF_MSG_DEAD;
			ctp->rcvid = -1;

#ifndef NDEBUG
			assert(wtp->wt_critical == 0);
#endif
			/* See note on order above */
			wtp->inreceive = 1;
			wtp->blocking = 1;

			ctp->rcvid = MsgReceivePulse(chid, ctp->msg, sizeof(struct _pulse), &ctp->info);

			wtp->blocking = 0;
			wtp->inreceive = 0;
		}


		NW_SIGLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);
		sctlp->thread_inreceive = 0;


                if (!sctlp->dedicated_stack_context) {
                    if (sctlp->stack_inuse == 0) {
                        sctlp->stack_inuse = 1;
                        wtp->am_stack = 1;
                        if (ctp->rcvid != -1)
                            do_msg = 1;
#ifdef OPT_SIGEV_PULSE
                        wtp->tidx_irupt = 0;
#endif
                    }
                    else {
                        if (ctp->rcvid != -1)
                            sctlp->msg_outstanding = 1;

                        switch (notify_type) {
#ifdef OPT_SIGEV_PULSE
                            case SIGEV_PULSE:
                                wtp->wt_piip = piip = pii_list;
                                pii_list = piip->next;
                                piip->next = NULL;
                                break;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
                            case SIGEV_SIGNAL_TID:
                                /* Nothing */
                                break;
#endif
                            default:
                                panic("rloop multi");
                                break;
                        }
                    }
                } else {
                    sctlp->stack_inuse = 1;
                    if (ctp->rcvid != -1)
                        do_msg = 1;
                    wtp->tidx_irupt = 0;
                }
		NW_SIGUNLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);
	}

	wtp->blocking = 1;
	switch (notify_type) {
#ifdef OPT_SIGEV_PULSE
	case SIGEV_PULSE:
		MsgReceivePulse(piip->chid, &not_used, sizeof(not_used), NULL);
		goto again;
		break;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
	case SIGEV_SIGNAL_TID:
		/* Wait for interrupt to generate signal */
		pause();
		break;
#endif
	default:
		panic("rloop multi");
		break;
	}
	/* Should never get here */
	panic("longjmp from sighandler.\n");

	return NULL;
}
#endif

/*
 * Only one thread here, not necessarily
 * one thread overall since oob thread(s)
 * may be present.
 * - Only one thread here so we don't need
 *   stack_ex.  We're still diligent about
 *   keep sctlp->stack_inuse inline for the
 *   oob thread(s) if present.
 * - Note: we still use SIGLOCK on pkt_ex 
 *   in case oob thread(s) present.  The
 *   mutex part will be a true no-op if
 *   we're actually VARIANT_uni and oob
 *   thread creation is disabled.
 */
void *
receive_loop_uni(void *arg)
{
	struct nw_work_thread	*wtp;
	struct proc		*proc0, *p2;
	resmgr_context_t	*ctp;
	int			incr, msg_max_size_tot;
	int			chid, again;
	struct nw_stk_ctl	*sctlp;
	struct rcv_loop_args	*rargs;

	rargs = arg;

	wtp = WTP;
	sctlp = &stk_ctl;

	/* First one (not on sctlp->freeprocs list) */
	proc0 = sctlp->proc0;

	/*
	 * Make sure proc0 pulse msg buffer
	 * is initialized before first msg
	 * is received.
	 */
	proc0->p_ctxt.msg          = (resmgr_iomsgs_t *)&no_res_msg_buf;
	proc0->p_ctxt.msg_max_size = sizeof(no_res_msg_buf);

	mypid = getpid();

	chid  = sctlp->chid;

	/*
	 * Only this thread will ever be the stack
	 * so we only need to set proc0 once.
	 */
	proc0->p_stkbase = wtp->tls->NW_TLS_STACKADDR;

	/*
	 * Load drivers and modules specified on the command line
	 * This is a kthread_create1() but setting the bigstack flag
	 * if it is needed.
	 */
	if ((p2 = sctlp->freeprocs) == NULL) {
		panic("No freeprocs");
	}
	sctlp->freeprocs = LWP_TO_PR(PR_TO_LWP(p2)->l_forw);
	PR_TO_LWP(p2)->l_forw = NULL;
	p2->p_ctxt.info.priority = sctlp->rx_prio;
	if (sctlp->bigstack_size != 0) {
		pcreat_setbigstack(p2);
	}
	pcreat(p2, load_drivers, rargs);

	/*
	 * The top of our loop which will be jumped 
	 * to to wake us out of a blocked state.
	 */
#ifdef OPT_SIGEV_SIGNAL_TID
	CPU_RCV_LOOP_CTXT_STORE(wtp);
#endif

	wtp->am_stack = 1;
	sctlp->stack_inuse = 1;

	wtp->blocking = 0;
	wtp->inreceive = 0;
	sctlp->thread_inreceive = 0;

	for (;;) {
		/*
		 * The order really is packets before
		 * timeouts before io messages.  Trying
		 * hardclock() first makes it possible
		 * to avoid and extra lock / unlock of
		 * pkt_ex when no packets pending
		 * (hardclock() always earlies out anyway).
		 */
		TASK_TIME_START(TASK_TIME_SOFTCLOCK);
		again = hardclock(sctlp);
		TASK_TIME_STOP(TASK_TIME_SOFTCLOCK);

		if (!again && sctlp->proc_prio.prio_all.tail) {
			PR_TO_LWP(proc0)->l_stat = LREADY;
			again = resched(proc0);
		}

		/*
		 * hardclock() or resched() may have earlied out if
		 * they noticed pending packets, or process_pkts()
		 * may ready some procs.
		 */

		if ((again += process_pkts(sctlp, wtp)) >= NW_DEF_SOFTCLOCK_PKT_LIM || sctlp->proc_prio.prio_all.tail) {
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			continue;
		}

		/*
		 * Knock this down before pkt_ex unlocked for
		 * oob thread(s) if present
		 */
		sctlp->stack_inuse = 0;
		wtp->am_stack = 0;
#ifndef NDEBUG
		assert(sctlp->thread_inreceive == 0);
#endif

		/*
		 * Preload proc for next message before unlocking stack mutex
		 * because procs can become unblocked, finish and be put back
		 * on freeprocs list while in process_pkts() which does not
		 * follow the MsgReceive(), pass to stack and process_msg()
		 * lock step.  ie. as soon as we unlock, process_pkts() can
		 * proceed which may manipulate freeprocs list independent
		 * of a new msg being received.
		 *
		 * Wait to increment nprocs_used in pcreat().
		 */
		if (sctlp->recv_loaded_proc == NULL && (sctlp->recv_loaded_proc = sctlp->freeprocs) != NULL) {
			sctlp->freeprocs = LWP_TO_PR(PR_TO_LWP(sctlp->recv_loaded_proc)->l_forw);
			PR_TO_LWP(sctlp->recv_loaded_proc)->l_forw = NULL;
		}

		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		/*
		 * Ok to manipulate sctlp->recv_* here with no mutex
		 * because we know:
		 * - mbuf / mcluster pools themselves are thread safe.
		 * - No outstanding messages so stack won't be looking
		 *   at them. 
		 * - Noone else in MsgReceive() to seed a message for
		 *   stack to look at.
		 * - When stack does process_msg(), sctlp->recv_* are all 
		 *   updated before blocking (ltsleep()) so we don't get 
		 *   into the window where process_pkts() can unblock a 
		 *   struct proc while another thread is manipulating
		 *   sctlp->recv_* here.
		 */
		replenish_recv_buf(sctlp, wtp);

		if (sctlp->recv_avail != 0 && sctlp->recv_loaded_proc != NULL) {
			ctp = &sctlp->recv_loaded_proc->p_ctxt;

			ctp->msg = sctlp->recv_iov[sctlp->recv_start].iov_base;
			/*
			 * The resmgr library likes stuff in one continuous buf
			 * so restrict it to first iov.
			 */
			ctp->msg_max_size = MCLBYTES - NW_DEF_HDR_LEN;
			/* The real length */
			msg_max_size_tot = (sctlp->recv_avail * MCLBYTES) - NW_DEF_HDR_LEN;

			/*
			 * This is for the case where we
			 * unlock and get an interrupt signal
			 * before we block.  In that case we
			 * want to make sure we process_pkts()
			 * before blocking.  If msg.type gets
			 * flipped before we re-lock, we know
			 * we got a message and we can't go to
			 * the top out loop or we lose the rcvid.
			 *
			 * Note there always the chance someone
			 * sends a message of type NW_DEF_MSG_DEAD.
			 * and we lose their rcvid.  In that
			 * case we'll still get the unblock pulse
			 * eventually (let them wait if they're
			 * sending garbage).
			 */
			ctp->msg->type = NW_DEF_MSG_DEAD;
			ctp->rcvid = -1;

			/*
			 * Save which proc we're working with because if 
			 * we get a pulse, it may not be in recv_loaded_proc
			 * even if non NULL if we're out of memory.
			 */
			sctlp->recv_procp = sctlp->recv_loaded_proc;

			sctlp->thread_inreceive = 1;
			/*
			 * As soon as blocking is set we may
			 * jump to top of loop.
			 */
			wtp->inreceive = 1;
			wtp->blocking = 1;
#ifndef NDEBUG
			assert(wtp->wt_critical == 0);
#endif
#if !defined(FAKE_UP_WRITES) && !(defined(USE_PULSE) && defined(TRACK_DELTAS))
			ctp->rcvid = MsgReceivev(chid, &sctlp->recv_iov[sctlp->recv_start],
				sctlp->recv_avail, &ctp->info);
#else
			ctp->rcvid = dbug_receive(ctp, chid, sctlp);
#endif
		}
		else {
			lowres_log(sctlp->recv_loaded_proc == NULL,
			    sctlp->recv_avail == 0);
			sctlp->recv_procp = proc0;
			/*
			 * proc0 must always be SREADY if here (pulse
			 * operations shalt not block).
			 */
			ctp = &proc0->p_ctxt;
			ctp->msg->type = NW_DEF_MSG_DEAD;
			ctp->rcvid = -1;

			msg_max_size_tot = proc0->p_ctxt.msg_max_size;

			sctlp->thread_inreceive = 1;
			/*
			 * As soon as blocking is set we may
			 * jump to top of loop.
			 */
			wtp->inreceive = 1;
			wtp->blocking = 1;
#ifndef NDEBUG
			assert(wtp->wt_critical == 0);
#endif
			ctp->rcvid = MsgReceivePulse(chid, ctp->msg, sizeof(struct _pulse), &ctp->info);
		}

		wtp->blocking = 0;
		wtp->inreceive = 0;
		sctlp->thread_inreceive = 0;
		sctlp->stack_inuse = 1;
		wtp->am_stack = 1;

		if (ctp->rcvid == -1)
			continue;

		/*
		 * If doing a network transaction and not all
		 * the message was sent, must get the remainder.
		 *
		 * rcvid == 0 implies a pulse in which case the
		 * msglen fields are not valid.
		 */
		if (ctp->rcvid > 0 &&
		    ctp->info.srcmsglen > ctp->info.msglen &&
		    ctp->info.msglen < msg_max_size_tot) {
			network_read(ctp, sctlp, wtp);
			if (ctp->rcvid == -1)
				continue;
		}


		/*
		 * Will handle immediately if pulse (pulses never freed),
		 * otherwise will Q to sctlp->proc_prio.prio_all.
		 */
		process_msg(sctlp, wtp);

		if (sctlp->nprocs_used >= sctlp->nprocs_cur_max &&
		    (incr = min(sctlp->nprocs_incr, sctlp->nprocs_max - sctlp->nprocs_cur_max))) {
			add_procs(sctlp, incr, incr);
		}
	}

	return NULL;
}


#if defined(OOB_THREAD_HIGH) || defined(OOB_THREAD_LOW)
int
oob_init(void *arg)
{
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	struct nw_oob_ctl	*soob;
	int			chid, coid;
	struct inter_thread	*itp;
	struct sigevent		*evp;

	pthread_setname_np(gettid(), "io-pkt oob");

	soob = arg;

	sctlp = &stk_ctl;
	wtp = WTP;

	wtp->wt_oob = soob;

	if ((chid = ChannelCreate_r(_NTO_CHF_UNBLOCK | _NTO_CHF_DISCONNECT)) < 0)
		    return -chid;

	if ((coid = ConnectAttach_r(ND_LOCAL_NODE, 0, chid, _NTO_SIDE_CHANNEL, 0)) < 0) {
		ChannelDestroy(chid);
		return -coid;
	}

	soob->chid = chid;
	soob->coid = coid;
	soob->init = 1;

	wtp->wt_zone_mbuf.max = mbuf_cache_max;
	wtp->wt_zone_packet.max = pkt_cache_max;

	wtp->quiesce_callout = quiesce_oob;
	wtp->quiesce_arg = wtp;
	
	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];
	evp = &itp->intr_ev;
	SIGEV_PULSE_INIT(evp, soob->coid, soob->prio, NW_DEF_PULSE_CODE_IRUPT_OOB, IRUPT_OOB_ISR);

	itp->event = evp;

	/*
	 * We just set the event so we have to
	 * process_interrupts so none are missed.
	 */
	process_interrupts_noswitch(wtp);
	NW_INTR_UNLK(itp);
	wtp->intr_sighot = _ISIG_COLD; /* We keep this clear */

	return EOK;
}

void
oob_fini(struct nw_oob_ctl *soob)
{
	int i;

	ConnectDetach(soob->coid);
	ChannelDestroy(soob->chid);

	if (soob->noob > 0) {
		for (i = 0; i < soob->noob; i++) {
			if (soob->oob_infop[i].inter != NULL ||
			    soob->oob_infop[i].ev != NULL) {
				/*
				 * This is an outstanding non ISR event.  Presumeably
				 * someone has done an InterruptAttachEvent with this.
				 * The event can no longer be raised and serviced (the
				 * chid / coid are no longer valid).  At a minimum this
				 * probably means the interrupt will never be unmasked.
				 * We won't free ev so it's a memory leak but might avoid
				 * a crash.
				 */
				log(LOG_ERR, "oob_fini: outstanding registrants");
			}
		}
		free(soob->oob_infop, M_SOFTINTR);
		soob->noob = 0;
	}
	soob->init = 0;
}


void *
receive_loop_oob(void *arg)
{
	struct nw_oob_ctl *soob;
	struct _msg_info info;
	struct _iopkt_inter *i_ent;
	struct nw_work_thread *wtp;
	struct nw_stk_ctl *sctlp = &stk_ctl;
	struct inter_thread	*itp;
	pid_t mypid;
	int rcvid;
	int value;
	union {
		struct _pulse pulse;
		struct nw_oob_msg oob;
	} msg;

	soob = arg;
	mypid = getpid();


	wtp = WTP;
	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];


	for (;;) {
		rcvid = MsgReceive(soob->chid, &msg, sizeof(msg), &info);

		if (rcvid == 0) {
			if (msg.pulse.code != NW_DEF_PULSE_CODE_IRUPT_OOB)
				continue;

			value = msg.pulse.value.sival_int;
			if (value & IRUPT_OOB_ISR) {
				process_interrupts_noswitch(wtp);
				NW_INTR_UNLK(itp);
				wtp->intr_sighot = _ISIG_COLD; /* We keep this clear */
			}
			else {
				if (value >= soob->noob || (i_ent = soob->oob_infop[value].inter) == NULL)
					continue;

				(*i_ent->func)(i_ent->arg, wtp);
				wtp->poke_stack = (*i_ent->enable)(i_ent->arg);
			}

			if (wtp->poke_stack == 0) {
				/* No rx packets Q'd */
				continue;
			}

			wtp->poke_stack = 0;

			NW_EX_LK(&sctlp->pkt_ex, iopkt_selfp);
			poke_stack_pkt_q();

			continue;
		}

		/* A real message.  We only handle one type */
		if (msg.oob.type != NW_DEF_MSG_OOBNEW || info.pid != mypid) {
			MsgError(rcvid, ENOSYS);
		}
		else {
			free(soob->oob_infop, M_SOFTINTR);
			soob->noob = msg.oob.noob;
			soob->oob_infop = msg.oob.oob_infop;
			MsgReply(rcvid, EOK, NULL, 0);
		}
	}
}
#endif


static void
network_read(resmgr_context_t *ctp, struct nw_stk_ctl *sctlp, struct nw_work_thread *wtp)
{
	int advance, index, n, niov;
	iov_t *iovp;
	uintptr_t up;

	advance = ctp->info.msglen;
	index   = 0;

	/*
	 * rcvid > 0 means it wasn't a pulse so we
	 * don't need to worry about message possibly
	 * having been received into proc0's context.
	 */
	iovp = &sctlp->recv_iov[sctlp->recv_start];
	niov = sctlp->recv_avail;

	/*
	 * Should never walk off array since checked
	 * ctp->info.msglen < msg_max_size_tot
	 */
	while (advance >= iovp[index].iov_len) {
		advance -= iovp[index].iov_len;
		index++;
	}

	/* Adjust */
	iovp[index].iov_len -= advance;
	up = (uintptr_t)iovp[index].iov_base;
	up += advance;
	iovp[index].iov_base = (void *)up;

	n = MsgReadv_r(ctp->rcvid, iovp + index, niov - index, ctp->info.msglen);
		
	/* Restore */
	iovp[index].iov_len += advance;
	up = (uintptr_t)iovp[index].iov_base;
	up -= advance;
	iovp[index].iov_base = (void *)up;

	if (n < 0) {
		MsgError(ctp->rcvid, -n);
		ctp->rcvid = -1;
	}
	else
		ctp->info.msglen += n;

	return;
}


#if defined(FAKE_UP_WRITES) || (defined(USE_PULSE) && defined(TRACK_DELTAS))

#ifdef FAKE_UP_WRITES
/* so it shows up separately on a profile */
static void *
do_memcpy(void *dst, void *src, size_t len)
{
	return memcpy(dst, src, len);
}
#endif

static int
dbug_receive(resmgr_context_t *ctp, int chid, struct nw_stk_ctl *sctlp)
{
#if defined(FAKE_UP_WRITES)
	if (fake_write.todo) {
		ctp->rcvid                        = fake_write.rcvid;
		ctp->info                         = fake_write.info;
		*((struct sendto_dbug *)ctp->msg) = fake_write.sendto_dbug;

		if (fake_cpy_buf) {
			int todo, avail, len;
			iov_t *iovp;
			void *base;

			todo = ctp->msg->write.i.nbytes;
			iovp = &sctlp->recv_iov[sctlp->recv_start];
			avail = sctlp->recv_avail;

			base = (char *)iovp->iov_base + sizeof(struct sendto_dbug);
			len  = iovp->iov_len - sizeof(struct sendto_dbug);

			while (todo) {
				len = min(len, avail);
				do_memcpy(base, fake_cpy_buf, len);
				todo -= len;
				if (--avail == 0)
					break;
				iovp++;
				base = iovp->iov_base;
				len  = iovp->iov_len;
			}
		}
		if (--fake_write.todo == 0) {
			/* Poke the reply finally */
			ctp->msg->write.i.xtype = _IO_XTYPE_NONE;
		}
	}
	else {
#endif
#if defined(USE_PULSE) && defined(TRACK_DELTAS)
		struct sendto_dbug *msg;
		uint64_t cycles_rcv_start;
		cycles_rcv_start = ClockCycles();
#endif

		ctp->rcvid = MsgReceivev(chid, &sctlp->recv_iov[sctlp->recv_start],
			sctlp->recv_avail, &ctp->info);

#if defined(USE_PULSE) && defined(TRACK_DELTAS)
		task_times[TASK_TIME_MSG_SEND].cycles_stop = ClockCycles();
		if (ctp->msg->type == _IO_WRITE && ctp->msg->write.i.xtype == _IO_XTYPE_TCPIP_DBUG) {
			msg = (struct sendto_dbug *)ctp->msg;

			if (msg->msg.i.flags & MSG_TIME) {
				/*
				 * Only want to time the send, not include time where client
				 * was send blocked before we got to MsgReceive().
				 */
				if (cycles_rcv_start < msg->send_start) {
					task_times[TASK_TIME_MSG_SEND].cycles_start = msg->send_start;
					TASK_TIME_STOP(TASK_TIME_MSG_SEND);
				}
			}
		}
#endif
#if defined(FAKE_UP_WRITES)
		if (ctp->msg->type == _IO_WRITE && ctp->msg->write.i.xtype == _IO_XTYPE_TCPIP_DBUG) {
			fake_write.rcvid       = ctp->rcvid;
			fake_write.info        = ctp->info;
			fake_write.sendto_dbug = *((struct sendto_dbug *)ctp->msg);

			fake_write.todo  = nfake;
		}
	}
#endif
	return ctp->rcvid;
}
#endif



int
receive_loop_init(void *arg)
{
	struct sigevent		*evp;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	struct inter_thread	*itp;
	struct rcv_loop_args	*rargs;
	int			err;
#ifdef OPT_SIGEV_PULSE
	struct pulse_intr_into	*piip;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
	sigset_t		signals;
#endif
	struct mtag_list	*ml;

	rargs = arg;

	sctlp = &stk_ctl;
	wtp = WTP;

	/* Not really, signal is blocked */
	wtp->intr_sighot = _ISIG_HOT;

#ifdef OPT_SIGEV_PULSE
	piip = NULL;
#endif

	err = EOK;
	if (wtp->tidx_wt == 0) {
		/* The first thread through */
		err = main_init(rargs->proto_opts, rargs->main_argc,
		    rargs->main_argv);
		/* default rx_prio may be overriden by main_init() */
		rargs_sigev_type = rargs->sigev_type;
		TAILQ_INIT(&stk_callback_2_head);
		if (sctlp->dedicated_stack_context) {
			wtp->flags |= WT_STACKCONTEXT;
			pthread_setname_np(gettid(), "STACK_CONTEXT");
		}
	}
#ifdef OPT_SIGEV_PULSE
	else {
		if ((piip = malloc(sizeof(*piip), M_INIT,
		    M_NOWAIT)) == NULL) {
			err = ENOMEM;
		}
		else if ((piip->chid = ChannelCreate_r(0)) < 0) {
			err = -piip->chid;
			free(piip, M_INIT);
		}
		else if ((piip->coid = ConnectAttach_r(ND_LOCAL_NODE, 0,
		    piip->chid, _NTO_SIDE_CHANNEL, 0)) < 0) {
			err = -piip->coid;
			ChannelDestroy(piip->chid);
			free(piip, M_INIT);
		}

		/*
		 * Can only associate a pulse with a channel
		 * unlike a signal which can be associated to
		 * a thread.
		 *
		 * If using pulses, associate a struct pulse_intr_info
		 * with each channel and store a unique index
		 * into iopkt_selfp->inter_threads[] therein
		 * (similar to wtp->tidx_irupt[] when using signals).
		 * The actual thread receiving on each channel can
		 * change so we change wtp->tidx_irupt to match
		 * the channel it actually received on.  This
		 * ensures only one thread looking at a particular
		 * iopkt_selfp->inter_threads[] slot at a time.
		 * 
		 */
		if (err == EOK)
			piip->tidx_handler = wtp->tidx_irupt;
	}
#endif

	if (err != EOK) {
		log(LOG_ERR, "rloop init: %d", err);
		return err;
	}

	wtp->wt_zone_mbuf.max = mbuf_cache_max;
	wtp->wt_zone_packet.max = pkt_cache_max;
	ml = (struct mtag_list *)wtp->wt_zone_mbuf.p;
	ml->max = mtag_cache_max;

	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];

	wtp->quiesce_callout = quiesce_core;
	wtp->quiesce_arg = wtp;


	evp = &itp->intr_ev;

	switch (rargs_sigev_type) {
#ifdef OPT_SIGEV_SIGNAL_TID
	case SIGEV_SIGNAL_TID:
		evp->sigev_notify          = SIGEV_SIGNAL_TID;
		evp->sigev_signo           = NW_INTR_SIG;
		evp->sigev_value.sival_ptr = wtp;
		evp->sigev_tid             = pthread_self();
		if (evp->sigev_priority == 0)
			evp->sigev_priority = sctlp->rx_prio;
		/* XXX prio not currently honoured. */
		break;
#endif

#ifdef OPT_SIGEV_PULSE
	case SIGEV_PULSE:
		SIGEV_PULSE_INIT(evp, piip == NULL ? sctlp->coid : piip->coid,
		    evp->sigev_priority == 0 ? sctlp->rx_prio :
		    evp->sigev_priority, NW_DEF_PULSE_CODE_IRUPT_CORE, 0);
		break;
#endif

	default:
		panic("Unknown or disabled event type %d", rargs_sigev_type);
		break;
	}

	/*
	 * Drivers may be loaded at this point
	 * (main_init()).  This means interrupts may
	 * be queueing for thread to process.
	 * They shouldn't be generating events
	 * since our itp->event is still NULL;
	 */
#ifdef OPT_SIGEV_SIGNAL_TID
	sigemptyset(&signals);
	sigaddset(&signals, NW_INTR_SIG);
	pthread_sigmask(SIG_UNBLOCK, &signals, NULL);
#endif

	/*
	 * After setting this we can get hit with interrupt
	 * signals.  ISR's may have fired before this and
	 * set our working bit but returned a NULL event.
	 * Because of this we need to process_interrupts()
	 * below as part of our initialization so none
	 * are missed.
	 */
	itp->event = evp;
	process_interrupts(wtp);
#ifdef OPT_SIGEV_PULSE
	if (piip != NULL) {
		NW_SIGLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);
		piip->next = pii_list;
		pii_list = piip;
		NW_SIGUNLOCK_P(&sctlp->stack_ex, iopkt_selfp, wtp);
	}
#endif

	return EOK;
}


#ifndef VARIANT_uni
static struct _iopkt_inter intr_struct;

static int intr_enable(void *arg);
static int intr_callout(void *arg, struct nw_work_thread *);
#endif

void
quiesce_core(void *arg, int die)
{
#ifndef VARIANT_uni
	struct nw_stk_ctl	*sctlp;
	struct _iopkt_self	*iopkt;
	struct nw_work_thread	*wtp;
	struct sigevent		*evp, *ev0p;
	struct inter_thread	*itp;

	wtp = arg;

	if ((wtp->flags & (WT_CORE | WT_IRUPT)) != (WT_CORE | WT_IRUPT)) {
		panic("quiesce_core: invalid");
	}

	sctlp = &stk_ctl;
	iopkt = sctlp->iopkt;

	/*
	 * OK to reuse this because we know any previous users
	 * are blocked in intr_callout(), at which point this
	 * struct is not on any list etc...
	 */
	intr_struct.func   = intr_callout;
	intr_struct.enable = intr_enable;
	intr_struct.arg    = 0;

	intr_struct.arg = (void *)die;

	if (intr_struct.on_list == 1)
		panic("quiesce_core on list");
	intr_struct.tidx = wtp->tidx_irupt; /* For completeness */


	/*
	 * Slot 0 is always initially assigned to the first wtp
	 * created which is always a core thread.  If using pulses,
	 * the channel to which ev0p's pulse is delivered is always
	 * the stack's main channel.
	 */
	ev0p = iopkt_selfp->inter_threads[0].event;
	switch (ev0p->sigev_notify) {
#ifdef OPT_SIGEV_SIGNAL_TID
	case SIGEV_SIGNAL_TID:
		itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];
		break;
#endif
#ifdef OPT_SIGEV_PULSE
	case SIGEV_PULSE: {
		int			iteration, i;
		struct nw_work_thread	*wtp_cur, *wtp_us;
		/* This is sooooo much easier with signals. */

		/*
		 * This issue is there's no way to target a particular
		 * thread with a pulse as they may migrate to different
		 * channels.
		 */

		wtp_us = WTP;
		/*
		 * First find out how many times we've been called
		 * in this particular of quiesce_all().
		 * XXX
		 * 	this assumes quiesce_all() is walking the
		 * 	sctlp->work_threads array as below and
		 * 	that this func, quiesce_core(), is only
		 * 	called for core threads (we've verified
		 * 	the latter above).
		 */
		iteration = 0;
		for (i = 0; i < sctlp->nwork_threads; i++) {
		        wtp_cur = sctlp->work_threads[i];
			if (wtp_cur == NULL || wtp_cur == wtp_us)
				continue;
			if (wtp_cur == wtp)
				break;
			if ((wtp_cur->flags & WT_CORE) != 0)
				iteration++;
		}

		if (iteration == 0) {
			/*
			 * Even though we are 'the stack' we may have
			 * become so after having been poked to process
			 * interrupts on a channel other than the main
			 * stack channel. ie there may still be a thread
			 * blocked on said channel.  Poke it so it migrates
			 * to another channel.  If there's no thread there,
			 * we'll get the pulse when we get back to
			 * MsgReceive.  Whichever thread gets this pulse
			 * will do no work because of it (spurious wakeup)
			 * as we don't put any interrupt callout on the
			 * iopkt_selfp->inter_threads[0] list which is
			 * always associated with this main channel.
			 */
			MsgSendPulse(ev0p->sigev_coid, ev0p->sigev_priority,
			    ev0p->sigev_code, ev0p->sigev_value.sival_int);

			/*
			 * All threads should now eventually migrate to a
			 * channel other than that of the main stack.
			 */
		}

		/*
		 * Now find the channel at the same slot number.
		 * We skip slot 0 as we're sure no core thread
		 * is blocked on the main stack thread (see above).
		 *
		 * XXX
		 * Note we send the pulse to the channel but thread
		 * wtp (the one passed in to this func) may not actually
		 * receive and process it.  This works because there's
		 * only quiesce_all() and no quiesce_one() so the order
		 * they quiesce isn't currently important as long as they
		 * all sleep at some point.
		 */
		for (itp = &iopkt_selfp->inter_threads[1];; itp++) {
			if (itp == NULL)
				continue;
			if (itp->event->sigev_notify == SIGEV_PULSE &&
			    itp->event->sigev_code == NW_DEF_PULSE_CODE_IRUPT_CORE) {
				if (iteration-- <= 0)
					break;
			}
		}
		break;
	}
#endif
	default:
		panic("quiesce_core");
		break;
	}


	evp = NULL;
	NW_INTR_LK(itp);

	*itp->inter_tail = &intr_struct;
	itp->inter_tail  = &intr_struct.next;

	intr_struct.on_list = 1;

	if (itp->working == 0) {
		evp = itp->event;
		itp->working = 1;
	}

	NW_INTR_UNLK(itp);
	
	if (evp != NULL) {
		/*
		 * Raise an event in the same manner as when
		 * evp is returned from an isr.
		 */
		switch (evp->sigev_notify) {
#ifdef OPT_SIGEV_SIGNAL_TID
		case SIGEV_SIGNAL_TID:
			SignalKill_r(ND_LOCAL_NODE, getpid(),
		 	   NW_TIDX_TO_TID(wtp->tidx_wt), NW_INTR_SIG, SI_USER,
			   (int)wtp);
			break;
#endif
#ifdef OPT_SIGEV_PULSE
		case SIGEV_PULSE:
			MsgSendPulse(evp->sigev_coid, evp->sigev_priority,
			    evp->sigev_code, evp->sigev_value.sival_int);
			break;
#endif
		default:
			panic("quiesce_core");
			break;
		}
	}

#endif /* VARIANT_uni */

	return;

}

#if defined(OOB_THREAD_HIGH) || defined(OOB_THREAD_LOW)
void
quiesce_oob(void *arg, int die)
{
	struct nw_stk_ctl	*sctlp;
	struct _iopkt_self	*iopkt;
	struct nw_work_thread	*wtp;
	struct sigevent		*evp;
	struct inter_thread	*itp;
	int			raise;

	wtp = arg;

	if ((wtp->flags & (WT_OOB | WT_IRUPT)) != (WT_OOB | WT_IRUPT))
		panic("quiesce_oob: invalid");

	sctlp = &stk_ctl;
	iopkt = sctlp->iopkt;

	intr_struct.arg = (void *)die;


	/*
	 * OK to reuse this because we know any previous users
	 * are blocked in intr_callout(), at which point this
	 * struct is not on any list etc...
	 */
	if (intr_struct.on_list == 1)
		panic("quiesce_oob on list");
	intr_struct.tidx = wtp->tidx_irupt; /* For completeness */


	itp = &iopkt_selfp->inter_threads[wtp->tidx_irupt];


	raise = 0;
	NW_INTR_LK(itp);

	*itp->inter_tail = &intr_struct;
	itp->inter_tail  = &intr_struct.next;

	intr_struct.on_list = 1;

	if (itp->working == 0) {
		evp = itp->event;
		itp->working = 1;
		raise = 1;
	}

	NW_INTR_UNLK(itp);
	
	if (raise) {
		/*
		 * This pulse is the equivalent event as when
		 * evp is returned from an isr.
		 */
		/*
		 * If an oob thread hasn't been created yet 
		 * its tidx will be 0.  We know i is > 0
		 * here so an unitialized oob thread won't
		 * be mistakenly checked.  We always send
		 * the pulse at the default high priority.
		 */

		/*
		 * Note: there's a window where evp is NULL
		 * at oob thread startup.
		 */
		MsgSendPulse(wtp->wt_oob->coid, NW_DEF_OOB_PRIO_HIGH,
		    NW_DEF_PULSE_CODE_IRUPT_OOB, IRUPT_OOB_ISR);
	}

	return;

}
#endif



#ifndef VARIANT_uni
static int
intr_callout(void *arg, struct nw_work_thread *wtp)
{
	int			die;

	die = (int)arg;

	/*
	 * Our spurious interrupt detector.  A little
	 * different in that we knock it down in the
	 * callout itself but spurious shouldn't be an
	 * issue as quiesce_all() is only called by the
	 * stack itself and not raised asynchronously.
	 * Plus we always return 1 below...
	 */
	intr_struct.on_list = 0;

	if (die == 1) {
#if defined(OOB_THREAD_HIGH) || defined(OOB_THREAD_LOW)
	       	if ((wtp->flags & WT_OOB) != 0)
			oob_fini(wtp->wt_oob);
#endif
#ifdef OPT_SIGEV_PULSE
		if (wtp->wt_piip != NULL) {
			struct pulse_intr_into	*piip;
			piip = wtp->wt_piip;

			ConnectDetach(piip->coid);
			ChannelDestroy(piip->chid);
			free(piip, M_INIT);
			wtp->wt_piip = NULL;
		}
#endif
	}
	quiesce_block(die);

	return 1;
}

static int
intr_enable(void *arg)
{
	return 0;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/receive.c $ $Rev: 902838 $")
#endif
