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

#include "bridge.h"

#include <malloc.h> /* The QNX one, see nw_thread_alloc_contexts */
#include <nw_thread.h>
#include <sys/param_bsd.h>
#include <sys/systm.h>
#include <sys/io-pkt.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <siglock.h>
#include <nw_datastruct.h>
#include <quiesce.h>
#include <net/if.h>
#include <netinet/ip_var.h>
#include <net/if_ether.h>
#if NBRIDGE > 0
#include <net/if_bridgevar.h>
#endif
#include <siglock.h>

#define NW_TIDX_DEAD (-1)


static int nw_thread_alloc_contexts(pthread_t);
static void nw_thread_clear_mzones(struct nw_work_thread *);

static int nw_thread_reg_flow(struct nw_work_thread *);
static int nw_thread_dereg_flow(struct nw_work_thread *);
#if NBRIDGE > 0
static int nw_thread_reg_bridge(struct nw_work_thread *);
static int nw_thread_dereg_bridge(struct nw_work_thread *);
#endif
static int nw_thread_reg_irupt(struct nw_work_thread *, int);


/*
 * Per thread cache limits.
 * We instantiate them here but leave it
 * up to the threads' init funcs to set
 * their private values since the defaults
 * are probably alright for core threads
 * but overkill for ppp (for example).
 */
int mbuf_cache_max = MBUF_CACHE_MAX;
int pkt_cache_max = PKT_CACHE_MAX;
int mtag_cache_max = MTAG_CACHE_MAX;


/*
 * Only one thread can create threads at
 * any point in time.  The parent thread
 * handshakes args with the child thread 
 * until they're no longer looked at.
 * This means we can pass args through a
 * global struct.
 */
static pthread_mutex_t th_mutex;
static pthread_cond_t th_cond;

#ifndef VARIANT_uni
static struct nw_work_thread **contexts_to_free;
#endif

static struct {
	int child_to_proceed;
	int child_return;

	struct nw_work_thread *wtp;

	void *(*funcp)(void *);
	void *arg;
	int (*init_func)(void *);
	void *init_arg;
} child_args;

static void * thread_init(void *arg);


/*
 * We always lock for VARIANT_smp and never do for
 * VARIANT_uni so we have to export what we follow
 * internally.  This allows generally compiled drivers
 * to work with any stack but not vice versa.
 */ 

/*
 * If there's a chance a thread will ever be created, we
 * have to create our mutexes up front.  Note OOB* aren't
 * defined for VARIANT_uni.
 * 
 * smp variant always locks so again make sure they're
 * created up front.
 */

/*
 * This makes the interop matrix look like:
 *
 * DLL       stack         interop     Why
 * --------------------------------------------------------------------
 * uni       general       No          general stack may create threads.
 * smp       general       Yes
 * general   general       Yes
 *
 * uni       uni           Yes
 * smp       uni           No          uni stack doesn't create mutexes
 * general   uni           Yes
 *
 * uni       smp           No          smp stack may create threads.
 * smp       smp           Yes
 * general   smp           Yes
 */
static int
exclusion_init(pthread_mutex_t *exp)
{
#ifndef VARIANT_uni
	/* General or smp case */
	return pthread_mutex_init(exp, NULL);
#else
	return EOK;
#endif
}

static int
exclusion_destroy(pthread_mutex_t *exp)
{
#ifndef VARIANT_uni
	/* General or smp case */
	return pthread_mutex_destroy(exp);
#else
	return EOK;
#endif
}


static void
exclusion_lock_up(pthread_mutex_t *exp)
{
	return;
}

static void
exclusion_unlock_up(pthread_mutex_t *exp)
{
	return;
}



#ifndef VARIANT_uni

static void
exclusion_lock_mp(pthread_mutex_t *exp)
{
#ifndef NDEBUG
	int ret;

	ret = pthread_mutex_lock(exp);
	if (ret != 0)
		panic("unexpected ret from pthread_mutex_lock: %d\n", ret);
#else
	_mutex_lock(exp);
#endif
}


static void
exclusion_unlock_mp(pthread_mutex_t *exp)
{
	/* Same as inline version from siglock.h */
#ifndef NDEBUG
	int ret;

	ret = pthread_mutex_unlock(exp);
	if (ret != 0)
		panic("unexpected ret from pthread_mutex_unlock: %d\n", ret);
#else
	_mutex_unlock(exp);
#endif
}
#endif


int
nw_thread_init(void)
{
	int ret;

	if ((ret = pthread_mutex_init(&th_mutex, NULL)) != EOK)
		return ret;

	if ((ret = pthread_cond_init(&th_cond, NULL)) != EOK) {
		pthread_mutex_destroy(&th_mutex);
		return ret;
	}

	iopkt_selfp->ex_init = exclusion_init;
	iopkt_selfp->ex_destroy = exclusion_destroy;
	/* Start with uniprocessor */
	iopkt_selfp->ex_lk = exclusion_lock_up;
	iopkt_selfp->ex_unlk = exclusion_unlock_up;

	return EOK;
}

void
nw_thread_fini(void)
{
}


static void
multithread_func_enable(void)
{
#ifdef VARIANT_uni
	panic("uni multithread");
#else
	iopkt_selfp->ex_lk = exclusion_lock_mp;
	iopkt_selfp->ex_unlk = exclusion_unlock_mp;
#endif
}

static void
multithread_func_disable(void)
{
#ifdef VARIANT_uni
	panic("uni multithread");
#else
	iopkt_selfp->ex_lk = exclusion_lock_up;
	iopkt_selfp->ex_unlk = exclusion_unlock_up;
#endif
}

int
nw_thread_untracked_add(void)
{
#ifndef VARIANT_uni
	struct nw_stk_ctl       *sctlp;

	sctlp = &stk_ctl;

	if (!ISSTACK)
		return EPERM;

	if (sctlp->nthreads_untracked++ == 0 && sctlp->nthreads_cur == 1)
		multithread_func_enable();

	return EOK;
#else /* VARIANT_uni */
	return ENOSYS;
#endif
}


int
nw_thread_untracked_sub(void)
{
#ifndef VARIANT_uni
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	**cur;

	sctlp = &stk_ctl;
	if (!ISSTACK)
	       return EPERM;

	if (sctlp->nthreads_untracked <= 0)
		return EINVAL;

	if (--sctlp->nthreads_untracked == 0) {
		NW_SIGHOLD;
		while ((cur = contexts_to_free) != NULL) {
			contexts_to_free = (struct nw_work_thread **)cur[0];
			(free)(cur);
		}
		NW_SIGUNHOLD;
		if (sctlp->nthreads_cur == 1)
			multithread_func_disable();
	}

	return EOK;
#else /* VARIANT_uni */
	return ENOSYS;
#endif
}

/*
 * Should only be needed by code that may be
 * called by threads created by pthread_create()
 * or nw_pthread_create() (code called by both
 * tracked and untracked threads).
 */
struct nw_work_thread *
nw_thread_istracked(void)
{
	struct nw_work_thread		*wtp;
	int				self;

	self = NW_TID_TO_TIDX(LIBC_TLS_TID());

	if (self < stk_ctl.nwork_threads)
		wtp = stk_ctl.work_threads[self]; /* May be NULL */
	else
		wtp = NULL;

	return wtp;
}

/*For nw_thread_clear_mzones, during the execution of io-pkt it
 *serves no purpose as we never destroy io-pkt worker threads once they are
 *created and nw_pthread_create (of non-worker threads) do not have the cache
 *code enabled. Where this does come into play is on shutdown. On shutdown,
 *the code allocates the mbuf/cluster and then frees it to remove it from
 *the cache. The cache objects are not necesarily released
 *to the pools, but can be free to the cache of the calling worker thread as
 *m_free_wtp will attempt to do this before freeing objects to the pool.
 */

static void
nw_thread_clear_mzones(struct nw_work_thread *wtp_dead)
{
	int i;
	struct mbuf_zone *mz;
	struct mbuf_zone *mbufz;
	struct mbuf *m;
	struct mtag_list *ml;
	struct m_tag *mtag;

	mbufz = &wtp_dead->wt_mzones[0]; /* mbuf zone cache pointer */

	for (i = 0; i < sizeof(wtp_dead->wt_mzones) / sizeof(wtp_dead->wt_mzones[0]); i++) {
		mz = &wtp_dead->wt_mzones[i];

		/* The mtag cache occupies the first mbuf in the mbuf
		 * cache, so we will skip the first mbuf.
		 */

		while ((m = (mz == mbufz ? mz->p->m_next : mz->p)) != NULL) {
			if (m->m_flags & M_CLUSTER)
				m = m_getcl_wtp(M_DONTWAIT, MT_DATA, M_PKTHDR, wtp_dead);
			else
				m = m_get_wtp(M_DONTWAIT, MT_DATA, wtp_dead);
			m_free(m);
		}
		if (mz->avail != 0)
			log(LOG_ERR, "mzone out of sync: %d", i);
	}

	/* The above code releases the mbufs and clusters from the cache
	 * by requesting them via the allocation calls, and then freeing
	 * the object. That will skip over the mtag cache occupying the first
	 * mbuf of the mbuf cache. Free the mtag cache below.
	 */

	ml = (struct mtag_list *)wtp_dead->wt_zone_mbuf.p;
	while ((mtag = SLIST_FIRST(&ml->tags))) {
		mtag = m_tag_get_wtp(PR_NOWAIT, wtp_dead);
		m_tag_free(mtag);
	}
}

int
nw_pthread_cleanup(struct nw_work_thread *wtp_dead)
{
	struct nw_work_thread	*wtp;
	struct nw_stk_ctl	*sctlp;

	sctlp = &stk_ctl;

	/*
	 * Excluding check for first thread lets this be
	 * called at startup before any contexts exist.
	 */
	if (ISSTART) {
		wtp = NULL;
	}
	else {
		wtp = WTP;
		if (!ISSTACK_P(wtp))
			return EPERM;
		quiesce_all();
	}

	/*
	 * Shouldn't have to worry about the start thread
	 * calling m_free as the only reason it would get
	 * here is if the child failed to come up.  In such
	 * a case the child should have no zones.
	 */
	nw_thread_clear_mzones(wtp_dead);

	if (--sctlp->nthreads_cur == 1 && sctlp->nthreads_untracked == 0)
		 multithread_func_disable();

	if ((wtp_dead->flags & WT_CORE) != 0)
		sctlp->nthreads_core--;
	else if ((wtp_dead->flags & WT_OOB) != 0)
		sctlp->nthreads_oob--;

	nw_thread_dereg_flow(wtp_dead);
#if NBRIDGE > 0
	nw_thread_dereg_bridge(wtp_dead);
#endif

	if (wtp_dead->tidx_wt != NW_TIDX_DEAD) {
		if (wtp != NULL && (wtp_dead->flags & WT_IRUPT))
			interrupt_thread_dereg(wtp_dead);

		sctlp->work_threads[wtp_dead->tidx_wt] = NULL;
	}


	wtp_dead->flags &= ~(WT_CORE | WT_OOB | WT_IRUPT);

	/* This gets set for core threads before WT_CORE set */
	if (wtp_dead->intr_stack_base != NULL) {
		(free)(wtp_dead->intr_stack_base);
		wtp_dead->intr_stack_base = wtp_dead->intr_stack_tos = NULL;
	}

	(free)(wtp_dead->wt_zone_mbuf.p);

	(free)(wtp_dead->wtp_alloc);

	if (wtp != NULL)
		unquiesce_all();

	return EOK;
}

int
nw_pthread_create(pthread_t *tidp, pthread_attr_t *attrp,
    void *(*funcp)(void *), void *arg,
    int flags, int (*init_func)(void *), void *init_arg)
{
	struct nw_work_thread	*wtp, *wtp_child;
	struct nw_stk_ctl	*sctlp;
	int			ret, detachstate, child_tidx;
	pthread_t		child_tid;
	void			*v;

	sctlp = &stk_ctl;

	/*
	 * Excluding check for first thread lets this be
	 * called at startup before any contexts exist.
	 */
	if (ISSTART) {
		/* This means we don't need to quiesce either */
		wtp = NULL;
	}
	else {
		wtp = WTP;
		if (!ISSTACK_P(wtp))
			return EPERM;
	}

#ifdef VARIANT_uni
	/* We only allow one thread at startup */
	if (wtp != NULL)
		return ENOSYS;
#endif

	/*
	 * They must provide an init func which
	 * must at least set wtp->quiesce_callout.
	 */
	if (init_func == NULL)
		return EINVAL;
	
	/* Can't be both code and oob */
	if ((flags & (WT_CORE | WT_OOB)) == (WT_CORE | WT_OOB))
		return EINVAL;

	if (attrp != NULL) {
		pthread_attr_getdetachstate(attrp, &detachstate);
		if (detachstate == PTHREAD_CREATE_DETACHED) {
			/* We like to join in places for synchronization */
			return EINVAL;
		}
	}

	if (((flags & WT_CORE) && sctlp->nthreads_core >= sctlp->nthreads_core_max) ||
	    ((flags & WT_OOB) && sctlp->nthreads_oob >= sctlp->nthreads_oob_max))
		return EAGAIN;


	/* Queisce before malloc / free */
	if (wtp != NULL)
		quiesce_all();

	if ((v = (malloc)(sizeof *wtp_child + NET_CACHELINE_SIZE)) == NULL) {
		if (wtp != NULL)
			unquiesce_all();
		return ENOMEM;
	}

	wtp_child = NET_CACHELINE_ALIGN(v);

	memset(wtp_child, 0x00, sizeof *wtp_child);

	/* Allocation for the MTAG cache occurs here. Note that it is
	 * initialized to zero (max = 0). The mbuf and packet caches are
	 * only enabled in io-pkt worker threads, so mtag will be the same.
	 * The cache max are initialized to a non zero value in
	 * receive_loop_init() when the worker thread is initialized.
	 *
	 * This does have an impact in driver thread creation as
	 * nw_pthread_create() does allow mbuf and cluster allocation and free
	 * but does not allow use of the cache. If a driver can allocate and
	 * free in a worker thread, it has the advantage of using the cache.
	 */

	if ((wtp_child->wt_zone_mbuf.p = (calloc)(1, sizeof(struct mtag_list))) == NULL) {
		if (wtp != NULL)
			unquiesce_all();
		(free)(v);
		return ENOMEM;
	}

	wtp_child->wtp_alloc = v;

	wtp_child->tidx_wt = NW_TIDX_DEAD;


	/*
	 * Enable these before thread creation, plus
	 * nw_pthread_cleanup() always undoes this.
	 */
	if (sctlp->nthreads_cur++ == 1 && sctlp->nthreads_untracked == 0) {
		/*
		 * We're single threaded at this point
		 * so no need to quiesce.
		 */
		multithread_func_enable();
	}

	memset(&child_args, 0x00, sizeof child_args);

	if ((flags & WT_IRUPT) &&
	    (ret = nw_thread_reg_irupt(wtp_child,
	    (flags & WT_CORE) != 0) != EOK)) {
		goto BAD;
	}

	/* Only the core threads need interrupt stacks */
	if (flags & WT_CORE) {
		if ((wtp_child->intr_stack_base =
		    (malloc)(NW_DEF_INTR_STACKSIZE)) == NULL) {
			ret = ENOMEM;
			goto BAD;
		}

		wtp_child->intr_stack_tos = wtp_child->intr_stack_base +
		    NW_DEF_INTR_STACKSIZE - NW_DEF_STACK_CALLSPACE;
	}


	if (flags & WT_FLOW) {
		if ((ret = nw_thread_reg_flow(wtp_child)) != EOK) {
			flags &= ~WT_FLOW;
			/* soft error if not core */
			if (flags & WT_CORE)
				goto BAD;
		}
	}

	if (flags & WT_BRIDGE) {
#if NBRIDGE > 0
		if ((ret = nw_thread_reg_bridge(wtp_child)) != EOK) {
			flags &= ~WT_BRIDGE;
			/* soft error if not core */
			if (flags & WT_CORE)
				goto BAD;
		}
#else
		flags &= ~WT_BRIDGE;
#endif
	}


	if (flags & WT_CORE)
		sctlp->nthreads_core++;
	else if (flags & WT_OOB)
		sctlp->nthreads_oob++;


	wtp_child->flags = flags;
	child_args.wtp = wtp_child;
	child_args.funcp = funcp;
	child_args.arg = arg;
	child_args.init_func = init_func;
	child_args.init_arg = init_arg;


	child_args.child_to_proceed = 1;
	pthread_mutex_lock(&th_mutex);

	if ((ret = pthread_create(&child_tid, attrp, thread_init,
	    NULL)) != EOK) {
		pthread_mutex_unlock(&th_mutex);
		goto BAD;
	}

	/*
	 * Allocate the context array based on child_tid
	 * before releasing the mutex and the child starts
	 * looking at it.
	 */

	child_tidx = NW_TID_TO_TIDX((int)child_tid);
	if ((ret = nw_thread_alloc_contexts(child_tidx + 1)) != EOK) {
		child_args.child_to_proceed = 0;
		pthread_mutex_unlock(&th_mutex);
		pthread_join(child_tid, NULL);
		goto BAD;
	}

	if (sctlp->work_threads[child_tidx] != NULL)
		panic("Thread cleanup");
	sctlp->work_threads[child_tidx] = wtp_child;
	wtp_child->tidx_wt = child_tidx;

	pthread_cond_wait(&th_cond, &th_mutex);

	pthread_mutex_unlock(&th_mutex);

	if ((ret = child_args.child_return) != EOK) {
		pthread_join(child_tid, NULL);
		goto BAD;
	}


	if (wtp != NULL)
		unquiesce_all();

	if (tidp != NULL)
		*tidp = child_tid;

	return EOK;

BAD:
	nw_pthread_cleanup(wtp_child);

	if (wtp != NULL)
		unquiesce_all();


	return ret;

}

int
nw_pthread_reap(pthread_t tid)
{
	int			ret;
	struct nw_work_thread	*wtp_cur;

	if ((ret = quiesce_force_exit(NW_TID_TO_TIDX(tid), &wtp_cur)) != EOK)
		return ret;

	pthread_join(tid, NULL);
	nw_pthread_cleanup(wtp_cur);
	return ret;
}

/*
 * We only want the stack to manipulate sctlp 
 * itself so we have it allocate the work thread
 * array up front before the new thread is
 * created.  The allocation and initialization of
 * the wtp itself is done by the newly created
 * thread.
 */
static int
nw_thread_alloc_contexts(int num)
{
	size_t			size_new, size_old;
	struct nw_work_thread	**new, ***tmp;
	struct nw_stk_ctl	*sctlp;


	sctlp = &stk_ctl;

	if (num <= sctlp->nwork_threads)
		return EOK;

	/*
	 * We use the standard malloc() instead of malloc_bsd()
	 * as the latter requires a context and this is called
	 * by the first thread before any contexts exist.  We
	 * are quiesced in subsequent calls so there should be
	 * no issues with not being wrapped in a SIGHOLD (malloc
	 * has a mutex).
	 */

	num += 3;

	size_old = sctlp->nwork_threads * sizeof(*sctlp->work_threads);
	size_new = num * sizeof(*sctlp->work_threads);
#ifndef VARIANT_uni
	if (sctlp->nthreads_untracked > 0) {
		/*
		 * All this is for nw_thread_istracked().  We
		 * can't put a mutex in that func because if the
		 * calling thread is tracked, it would also need
		 * SIGHOLD before the mutex and that requires
		 * the thread to find its context.  However the
		 * point of that func is to find out if the calling
		 * thread has a context (is tracked).  Also,
		 * untracked threads don't quiesce so they may
		 * call the func at any time.  This all means we
		 * can never really free our array if any
		 * untracked threads are present as they might snap
		 * the old array while it's changing below and
		 * without knowing how they're scheduled, they
		 * might keep this old value for any length of
		 * time.
		 *
		 * The assumptions made below are
		 * - The first thread up is always tracked so
		 *   sctlp->work_threads can not be NULL here.
		 * - Any thread looking at the array now is
		 *   untracked since all others should be quiesced.
		 *   Untracked threads should only be looking at
		 *   untracked slots in the array so we are free
		 *   to modify slot 0, again since the first thread
		 *   is tracked and the array must be non NULL.
		 * - We set the new array before the size since the 
		 *   array only grows and nw_thread_istracked()
		 *   snaps its references in the reverse order.
		 *   This means that if the func snaps the old
		 *   size but the new array, no foul which is
		 *   not the case the other way around.
		 * 
		 */
		if ((new = (malloc)(size_new)) == NULL)
			return ENOMEM;

		memcpy(new, sctlp->work_threads, size_old);

		tmp = (struct nw_work_thread ***)(&sctlp->work_threads[0]);
		*tmp = contexts_to_free;
		contexts_to_free = sctlp->work_threads;
	}
	else
#endif
		if ((new = (realloc)(sctlp->work_threads, size_new)) == NULL)
			return ENOMEM;

	memset(&new[sctlp->nwork_threads], 0x00, size_new - size_old);
	    

	sctlp->work_threads = new;
	sctlp->nwork_threads = num;

	return EOK;
}


static void *
thread_init(void *arg)
{
	struct nw_work_thread	*wtp;
	void *			(*funcp)(void *);
	int			err, tidx;
	struct nw_stk_ctl	*sctlp;

	sctlp = &stk_ctl;

	pthread_mutex_lock(&th_mutex);

	tidx = NW_TID_TO_TIDX(pthread_self());

	/* 
	 * Set thread name. 
	 * This can be overridden by the thread's init function or later.
	 * Save a little stack using static for this array.
	 */
	static char threadname[strlen("io-pkt#0x") + sizeof(tidx)*2 + 1];
	snprintf(threadname, sizeof(threadname), "io-pkt#0x%.2x", tidx);
	pthread_setname_np(gettid(), threadname);

	if (child_args.child_to_proceed == 0) {
		/* Parent never got to cond_wait, no need to signal */
		pthread_mutex_unlock(&th_mutex);
		return NULL;
	}

	wtp = child_args.wtp;

	wtp->tls = __tls();


	if (child_args.init_func != NULL &&
	    (err = (*child_args.init_func)(child_args.init_arg)) != EOK)
		goto BAD;

	/* init func must set the quiesce callout */
	if (wtp->quiesce_callout == NULL) {
		err = EINVAL;
		goto BAD;
	}

	funcp = child_args.funcp;
	arg = child_args.arg;

	pthread_setspecific(sctlp->work_thread_key, wtp);

	child_args.child_return = EOK;
	pthread_cond_signal(&th_cond);
	pthread_mutex_unlock(&th_mutex);

	return (*funcp)(arg);

BAD:
	child_args.child_return = err;
	pthread_cond_signal(&th_cond);
	pthread_mutex_unlock(&th_mutex);
	return NULL;
}



void
nw_thread_log_noflow(void)
{
	static			uint64_t logmask;
	struct nw_stk_ctl	*sctlp;
	int			self;
	struct nw_work_thread	*wtp;

	sctlp = &stk_ctl;
	self = pthread_self();

	self = NW_TID_TO_TIDX(self);
	self = min(self, sizeof(logmask) * CHAR_BIT - 1);
	if (logmask & (1 << self))
		return;

	logmask |= 1 << self;

	/*
	 * Check for shim thread.  We'll silently
	 * fail these as there's little chance
	 * they'll ever flow.
	 */
	if (self >= sctlp->nwork_threads || (wtp = WTP) == NULL) {
#if 0
		/* log_init() here's as there's no context */
		log_init(LOG_WARNING, "no flow: %d", self);
#endif
		return;
	}

	log(LOG_WARNING, "no flow: %d", self);
}

static int
nw_thread_reg_irupt(struct nw_work_thread *wtp_reg, int iscore)
{
	struct nw_stk_ctl	*sctlp;
	int			ret;

	sctlp = &stk_ctl;

	if (wtp_reg->flags & WT_IRUPT)
		return EALREADY;

	if ((ret = interrupt_thread_reg(wtp_reg, iscore)) != EOK)
		return ret;


	wtp_reg->flags |= WT_IRUPT;

	return EOK;
}

static int
nw_thread_reg_flow(struct nw_work_thread *wtp_reg)
{
	struct nw_stk_ctl	*sctlp;
	int			ret;

	sctlp = &stk_ctl;

	if (wtp_reg->flags & WT_FLOW)
		return EALREADY;

	if ((ret = ipflow_register(&wtp_reg->flowctl)) != EOK)
		return ret;

	wtp_reg->flags |= WT_FLOW;

	return EOK;
}

static int
nw_thread_dereg_flow(struct nw_work_thread *wtp_reg)
{
	void (*logp)(int, const char *, ...);
	int ret;

	if ((wtp_reg->flags & WT_FLOW) == 0)
		return EOK;

	if ((ret = ipflow_deregister(wtp_reg->flowctl)) != EOK) {
		if (ISSTART)
			logp = log_init;
		else
			logp = log;
		(*logp)(LOG_ERR, "dereg_flow: %d", ret);

		return ret;
	}

	wtp_reg->flowctl = NULL;
	wtp_reg->flags &= ~WT_FLOW;

	return EOK;
}

#if NBRIDGE > 0
static int
nw_thread_reg_bridge(struct nw_work_thread *wtp_reg)
{
	struct nw_stk_ctl	*sctlp;
	int			ret;

	sctlp = &stk_ctl;

	if (wtp_reg->flags & WT_BRIDGE)
		return EALREADY;

	if ((ret = bridge_register(&wtp_reg->wt_brctl)) != EOK)
		return ret;

	wtp_reg->flags |= WT_BRIDGE;

	return EOK;
}

static int
nw_thread_dereg_bridge(struct nw_work_thread *wtp_reg)
{
	void (*logp)(int, const char *, ...);
	int ret;

	if ((wtp_reg->flags & WT_BRIDGE) == 0)
		return EOK;

	if ((ret = bridge_deregister(wtp_reg->wt_brctl)) != EOK) {
		if (ISSTART)
			logp = log_init;
		else
			logp = log;
		(*logp)(LOG_ERR, "dereg_bridge: %d", ret);

		return ret;
	}

	wtp_reg->wt_brctl = NULL;
	wtp_reg->flags &= ~WT_BRIDGE;

	return EOK;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_thread.c $ $Rev: 858532 $")
#endif
