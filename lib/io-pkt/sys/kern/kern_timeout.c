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

/*	$NetBSD: kern_timeout.c,v 1.19 2006/11/01 10:17:58 yamt Exp $	*/

/*-
 * Copyright (c) 2003 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
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

/*
 * Copyright (c) 2001 Thomas Nordin <nordin@openbsd.org>
 * Copyright (c) 2000-2001 Artur Grabowski <art@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: kern_timeout.c,v 1.19 2006/11/01 10:17:58 yamt Exp $");

/*
 * Adapted from OpenBSD: kern_timeout.c,v 1.15 2002/12/08 04:21:07 art Exp,
 * modified to match NetBSD's pre-existing callout API.
 */

#ifndef _CALLOUT_PRIVATE
#define _CALLOUT_PRIVATE
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/callout.h>
#ifdef __QNXNTO__
#include "nw_datastruct.h"
#include <net/netbyte.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <dlfcn.h>
#include <gtimer/gtimer.h>
#endif

#ifdef DDB
#include <machine/db_machdep.h>
#include <ddb/db_interface.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_output.h>
#endif

/*
 * Timeouts are kept in a hierarchical timing wheel. The c_time is the value
 * of the global variable "hardclock_ticks" when the timeout should be called.
 * There are four levels with 256 buckets each. See 'Scheme 7' in
 * "Hashed and Hierarchical Timing Wheels: Efficient Data Structures for
 * Implementing a Timer Facility" by George Varghese and Tony Lauck.
 */
#define BUCKETS 1024
#define WHEELSIZE 256
#define WHEELMASK 255
#define WHEELBITS 8

static struct callout_circq timeout_wheel[BUCKETS];	/* Queues of timeouts */
static struct callout_circq timeout_todo;		/* Worklist */

#if defined(__QNXNTO__) && defined(CALLOUT_DBG)
static void db_show_callout(void);
static void checktimo(int);
#endif

#define MASKWHEEL(wheel, time) (((time) >> ((wheel)*WHEELBITS)) & WHEELMASK)

#define BUCKET(rel, abs)						\
    (((rel) <= (1 << (2*WHEELBITS)))					\
    	? ((rel) <= (1 << WHEELBITS))					\
            ? &timeout_wheel[MASKWHEEL(0, (abs))]			\
            : &timeout_wheel[MASKWHEEL(1, (abs)) + WHEELSIZE]		\
        : ((rel) <= (1 << (3*WHEELBITS)))				\
            ? &timeout_wheel[MASKWHEEL(2, (abs)) + 2*WHEELSIZE]		\
            : &timeout_wheel[MASKWHEEL(3, (abs)) + 3*WHEELSIZE])

#define MOVEBUCKET(wheel, time)						\
    CIRCQ_APPEND(&timeout_todo,						\
        &timeout_wheel[MASKWHEEL((wheel), (time)) + (wheel)*WHEELSIZE])

/*
 * All wheels are locked with the same lock (which must also block out all
 * interrupts).
 */
#ifndef __QNXNTO__

static struct simplelock callout_slock;

#define	CALLOUT_LOCK(s)							\
do {									\
	s = splsched();							\
	simple_lock(&callout_slock);					\
} while (/*CONSTCOND*/0)

#define	CALLOUT_UNLOCK(s)						\
do {									\
	simple_unlock(&callout_slock);					\
	splx((s));							\
} while (/*CONSTCOND*/0)
#else

#define CALLOUT_NEXT_CLEAR(type)		\
do {						\
	callout_next_all[(type)].nc = NULL;	\
	callout_next_all[(type)].nt = 0;	\
	callout_next_msk |= 1<<(type);		\
} while (0)

#define	SEQ_LEQ(a,b)	((int)((unsigned)(a)-(unsigned)(b)) <= 0)
#define	SEQ_LT(a,b)	((int)((unsigned)(a)-(unsigned)(b)) < 0)

struct nextt {
	struct callout	*nc;
	int		nt;
};
static void nexttimo(struct nextt *, unsigned *);
static void callout_offbucket(struct callout *);
int callout_dbg;
char *gtimerlib;
unsigned callout_dbg_msk = 1<<_CALLOUT_CLK_DEFAULT; /* XXX sysctl */
static unsigned callout_next_msk;
static struct nextt callout_next_all[_CALLOUT_CLK_MAX];
static void callout_reset_lock(struct callout *, int, void (*)(void *), void *,
    int, enum callout_clock_type, int);
static const char * funcname(void *, Dl_info *);
#define BITS_PER_INT (sizeof(int) * CHAR_BIT)
/* Enough ints to hold bitmask of size BUCKETS */
int wheelmsk[BUCKETS/BITS_PER_INT];
int tickstop_min, tickstop_max;
static void settime_default(int, int, struct callout *);
static void settime_group(int, int, struct callout *);

static void (*callout_settime[_CALLOUT_CLK_MAX])(int, int, struct callout *) = {
	settime_default,
	settime_group,		/* wifi */
	settime_group,		/* cellular */
	NULL,
};

#include <siglock.h>
static pthread_mutex_t callout_mtx;

#define	CALLOUT_LOCK(s)							\
do {									\
	s = splsched();							\
	NW_SIGLOCK_P(&callout_mtx, iopkt_selfp, wtp);			\
} while (/*CONSTCOND*/0)

#define	CALLOUT_UNLOCK(s)						\
do {									\
	NW_SIGUNLOCK_P(&callout_mtx, iopkt_selfp, wtp);			\
	splx((s));							\
} while (/*CONSTCOND*/0)
#endif

/*
 * Circular queue definitions.
 */

#define CIRCQ_INIT(list)						\
do {									\
        (list)->cq_next_l = (list);					\
        (list)->cq_prev_l = (list);					\
} while (/*CONSTCOND*/0)

#define CIRCQ_INSERT_HEAD(elem, list)					\
do {									\
	(elem)->cq_prev_l = (list);					\
        (elem)->cq_next_e = (list)->cq_next_e;				\
	(list)->cq_next_l->cq_prev_l = (elem);				\
	(list)->cq_next_l = (elem);					\
} while (/*CONSTCOND*/0)

#define CIRCQ_INSERT_TAIL(elem, list)					\
do {									\
        (elem)->cq_prev_e = (list)->cq_prev_e;				\
        (elem)->cq_next_l = (list);					\
        (list)->cq_prev_l->cq_next_l = (elem);				\
        (list)->cq_prev_l = (elem);					\
} while (/*CONSTCOND*/0)

#define CIRCQ_INSERT(elem, list)	CIRCQ_INSERT_TAIL((elem), (list))


#define CIRCQ_APPEND(fst, snd)						\
do {									\
        if (!CIRCQ_EMPTY(snd)) {					\
                (fst)->cq_prev_l->cq_next_l = (snd)->cq_next_l;		\
                (snd)->cq_next_l->cq_prev_l = (fst)->cq_prev_l;		\
                (snd)->cq_prev_l->cq_next_l = (fst);			\
                (fst)->cq_prev_l = (snd)->cq_prev_l;			\
                CIRCQ_INIT(snd);					\
        }								\
} while (/*CONSTCOND*/0)

#define CIRCQ_REMOVE(elem)						\
do {									\
        (elem)->cq_next_l->cq_prev_e = (elem)->cq_prev_e;		\
        (elem)->cq_prev_l->cq_next_e = (elem)->cq_next_e;		\
} while (/*CONSTCOND*/0)

#define CIRCQ_FIRST(list)	((list)->cq_next_e)
#define CIRCQ_NEXT(elem)	((elem)->cq_next_e)
#define CIRCQ_LAST(elem,list)	((elem)->cq_next_l == (list))
#define CIRCQ_EMPTY(list)	((list)->cq_next_l == (list))

/*
 * Some of the "math" in here is a bit tricky.
 *
 * We have to beware of wrapping ints.
 * We use the fact that any element added to the queue must be added with a
 * positive time. That means that any element `to' on the queue cannot be
 * scheduled to timeout further in time than INT_MAX, but c->c_time can
 * be positive or negative so comparing it with anything is dangerous.
 * The only way we can use the c->c_time value in any predictable way
 * is when we calculate how far in the future `to' will timeout -
 * "c->c_time - hardclock_ticks". The result will always be positive for
 * future timeouts and 0 or negative for due timeouts.
 */

#ifdef CALLOUT_EVENT_COUNTERS
static struct evcnt callout_ev_late;
#endif


#ifdef __QNXNTO__
static struct gtime {
	void		*gt_hdl;
	int		(*gt_settime)(gtimer_t *, int, struct gitimerspec *, struct gitimerspec *);
	int		(*gt_delete)(gtimer_t *);
	gtimer_t	*gt_gtime[_CALLOUT_CLK_MAX];
} gt;

static void callout_startup_gtimer(void);

static void
callout_startup_gtimer(void)
{
	gtimer_t * (*gt_create)(clockid_t , struct sigevent *);
	int (*gt_ass)(gtimer_t *, char *);
	int (*gt_name)(gtimer_t *, char *);
	struct sigevent	ev;

	if (gtimerlib == NULL)
		return;

	if ((gt.gt_hdl = dlopen(gtimerlib, RTLD_WORLD)) == NULL)
		goto fail;

	if ((gt_create = dlsym(gt.gt_hdl, "gtimer_create")) == NULL ||
	    (gt.gt_delete = dlsym(gt.gt_hdl, "gtimer_delete")) == NULL ||
	    (gt_ass = dlsym(gt.gt_hdl, "gtimer_associate")) == NULL ||
	    (gt_name = dlsym(gt.gt_hdl, "gtimer_set_name")) == NULL ||
	    (gt.gt_settime = dlsym(gt.gt_hdl, "gtimer_settime")) == NULL) {
		goto fail;
	}

	SIGEV_PULSE_INIT(&ev, stk_ctl.coid, stk_ctl.timer_pulse_prio,
	    NW_DEF_PULSE_CODE_TIMER_GROUP, _CALLOUT_CLK_WIFI);
	    
	if ((gt.gt_gtime[_CALLOUT_CLK_WIFI] = (*gt_create)(CLOCK_MONOTONIC,
	    &ev)) == NULL) {
		goto fail;;
	}

	if ((*gt_ass)(gt.gt_gtime[_CALLOUT_CLK_WIFI], "wifi") == -1)
		goto fail;

	(*gt_name)(gt.gt_gtime[_CALLOUT_CLK_WIFI], "io-pkt wifi timer");

	SIGEV_PULSE_INIT(&ev, stk_ctl.coid, stk_ctl.timer_pulse_prio,
	    NW_DEF_PULSE_CODE_TIMER_GROUP, _CALLOUT_CLK_CELLULAR);

	if ((gt.gt_gtime[_CALLOUT_CLK_CELLULAR] = (*gt_create)(CLOCK_MONOTONIC,
	    &ev)) == NULL) {
		goto fail;;
	}

	if ((*gt_ass)(gt.gt_gtime[_CALLOUT_CLK_CELLULAR], "cellular") == -1)
		goto fail;

	(*gt_name)(gt.gt_gtime[_CALLOUT_CLK_CELLULAR], "io-pkt cellular timer");

	log(LOG_INFO, "group timers initialized");
	return;
fail:
	log(LOG_INFO, "no group timers");
	if (gt.gt_gtime[_CALLOUT_CLK_WIFI] != NULL) {
		(*gt.gt_delete)(gt.gt_gtime[_CALLOUT_CLK_WIFI]);
		gt.gt_gtime[_CALLOUT_CLK_WIFI] = NULL;
	}
	if (gt.gt_gtime[_CALLOUT_CLK_CELLULAR] != NULL) {
		(*gt.gt_delete)(gt.gt_gtime[_CALLOUT_CLK_CELLULAR]);
		gt.gt_gtime[_CALLOUT_CLK_CELLULAR] = NULL;
	}
	
	if (gt.gt_hdl != NULL)
		dlclose(gt.gt_hdl);
	gt.gt_hdl = NULL;
	return;
	
}
#endif

/*
 * callout_startup:
 *
 *	Initialize the callout facility, called at system startup time.
 */
void
callout_startup(void)
{
	int b;

	/*
	 * This is a compile time check that these two match in size.
	 * If they don't it'll warn about pointer from integer and
	 * at -Werror compilation will fail.
	 */
	__attribute__ ((__unused__))char* p = (sizeof(struct callout_impl) != sizeof(callout_t));

	CIRCQ_INIT(&timeout_todo);
	for (b = 0; b < BUCKETS; b++)
		CIRCQ_INIT(&timeout_wheel[b]);
#ifndef __QNXNTO__
	simple_lock_init(&callout_slock);
#else
	pthread_mutex_init(&callout_mtx, NULL);
	callout_startup_gtimer();
#endif

#ifdef CALLOUT_EVENT_COUNTERS
	evcnt_attach_dynamic(&callout_ev_late, EVCNT_TYPE_MISC,
	    NULL, "callout", "late");
#endif
}

/*
 * callout_init:
 *
 *	Initialize a callout structure.
 */
void
callout_init(struct callout *c)
{

	memset(c, 0, sizeof(*c));
}

void
callout_init_new(callout_t *co, u_int flags)
{
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;

	c->c_func = NULL;
	ci->c_bkt = -1;

	c->c_flags = flags | CALLOUT_EXT;
	ci->c_type = _CALLOUT_CLK_DEFAULT;
}

#ifdef __QNXNTO__
/*
 * callout_reset() semantics are to reset the timeout to the new value if the
 * timeout has been extended.  Use this variant if you only want to change
 * it if it's shorter.
 */
void
callout_reset_newer(struct callout *c, int to_ticks, void (*func)(void *), void *arg)
{
	int s;
	struct nw_work_thread *wtp;

	wtp = WTP;

	CALLOUT_LOCK(s);
	if (!callout_pending(c) || to_ticks + hardclock_snap() < c->c_time) {
		callout_reset_lock(c, to_ticks, func, arg, 0,
		    _CALLOUT_CLK_DEFAULT, 0);
	}
	CALLOUT_UNLOCK(s);
}

static void
callout_checkearly(struct callout *c, enum callout_clock_type type)
{
	struct _itimer tmo;
	int err;
	pid_t pid;
	struct proc *p;
	const char *name;
	Dl_info dl;
	int callout_next;

	callout_next = callout_next_all[_CALLOUT_CLK_DEFAULT].nt;

	if (callout_next == 0 || c->c_time < callout_next) {
		if (callout_next != 0) {
			if (callout_dbg) {
				struct nw_work_thread *wtp;
				wtp = WTP;

				p = curproc;
				if (ISIRUPT_P(wtp) || p == stk_ctl.proc0)
					pid = 0;
				else
					pid = p->p_ctxt.info.pid;
				if (callout_dbg > 1) {
					name = funcname(c->c_func, &dl);
				} else {
					name = NULL;
				}
				log(LOG_INFO, "callout_dbg: Wakeup early.  pid: %d: %s", pid, name);
			}
			tmo.nsec = TIMER_PULSE_PERIOD;
			tmo.interval_nsec = TIMER_PULSE_PERIOD;
			if ((err = TimerSettime_r(stk_ctl.timer_int_id, 0, &tmo, NULL)) != 0) {
				log(LOG_ERR, "callout_dbg: timer error: %d", err);
			}
		}
		CALLOUT_NEXT_CLEAR(_CALLOUT_CLK_DEFAULT);
	}
	if (c->c_flags & CALLOUT_EXT) {
		callout_impl_t *ci;
		struct nextt *np;

		ci = (callout_impl_t *)c;
		np = &callout_next_all[type];
		if (np->nt == 0 || SEQ_LT(c->c_time, np->nt) || np->nc == c) {
			CALLOUT_NEXT_CLEAR(type);
		}
	}
}
#endif

void
callout_reset_new(callout_t *co, int to_ticks, void (*func)(void *), void *arg,
    enum callout_clock_type type, int range)
{
	callout_impl_t *ci = (callout_impl_t *)co;

	if (gt.gt_gtime[type] == NULL)
		type = _CALLOUT_CLK_DEFAULT;

	return callout_reset_lock(&ci->c_callout, to_ticks, func, arg, 1,
	    type, range);
}

/*
 * callout_reset:
 *
 *	Reset a callout structure with a new function and argument, and
 *	schedule it to run.
 */
void
callout_reset(struct callout *c, int to_ticks, void (*func)(void *), void *arg)
#ifdef __QNXNTO__
{
	return callout_reset_lock(c, to_ticks, func, arg, 1,
	    _CALLOUT_CLK_DEFAULT, 0);
}

static void
callout_reset_lock(struct callout *c, int to_ticks, void (*func)(void *),
    void *arg, int lock, enum callout_clock_type type, int range)
#endif
{
	int s, old_time;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	wtp = WTP;
	callout_impl_t *ci;
#endif

	KASSERT(to_ticks >= 0);

#ifdef __QNXNTO__
	if (lock)
#endif
	CALLOUT_LOCK(s);

	/* Initialize the time here, it won't change. */
	old_time = c->c_time;
#ifndef __QNXNTO__
	c->c_time = to_ticks + hardclock_ticks;
#else
	c->c_time = to_ticks + hardclock_snap();
#endif
	c->c_flags &= ~(CALLOUT_FIRED|CALLOUT_INVOKING);

	if (func != NULL) {
		c->c_func = func;
		c->c_arg = arg;
	}
#ifdef __QNXNTO__
	callout_checkearly(c, type);
#endif

	/*
	 * If this timeout is already scheduled and now is moved
	 * earlier, reschedule it now. Otherwise leave it in place
	 * and let it be rescheduled later.
	 */
	if (callout_pending(c)) {
		if (c->c_time - old_time < 0) {
			CIRCQ_REMOVE(&c->c_list);
			callout_offbucket(c);
			/*
			 * Only set type when off bucket in case
			 * it changes.
			 */
			if (c->c_flags & CALLOUT_EXT) {
				ci = (callout_impl_t *)c;
				ci->c_type = type;
				if (c->c_flags & (CALLOUT_RANGE_EARLY | CALLOUT_RANGE_LATE))
					ci->c_range = range;
				else
					ci->c_range = 0;
			}
			CIRCQ_INSERT(&c->c_list, &timeout_todo);
		}
	} else {
		c->c_flags |= CALLOUT_PENDING;
		if (c->c_flags & CALLOUT_EXT) {
			ci = (callout_impl_t *)c;
			ci->c_type = type;
			if (c->c_flags & (CALLOUT_RANGE_EARLY | CALLOUT_RANGE_LATE))
				ci->c_range = range;
			else
				ci->c_range = 0;
		}
		CIRCQ_INSERT(&c->c_list, &timeout_todo);
	}

#ifdef __QNXNTO__
	if (lock)
#endif
	CALLOUT_UNLOCK(s);
}

#ifdef __QNXNTO__
void
callout_msec(struct callout *c, int msec, void (*func)(void *), void *arg)
{
	callout_reset(c, msec * hz / 1000 + 1, func, arg);
	return;
}
#endif

/*
 * callout_schedule:
 *
 *	Schedule a callout to run.  The function and argument must
 *	already be set in the callout structure.
 */
void
callout_schedule(struct callout *c, int to_ticks)
{
	return callout_reset_lock(c, to_ticks, NULL, NULL, 1, _CALLOUT_CLK_DEFAULT, 0);
}

void
callout_schedule_new(callout_t *co, int to_ticks, enum callout_clock_type type,
    int range)
{
	callout_impl_t *ci = (callout_impl_t *)co;

	if (gt.gt_gtime[type] == NULL)
		type = _CALLOUT_CLK_DEFAULT;

	return callout_reset_lock(&ci->c_callout, to_ticks, NULL, NULL, 1,
	    type, range);
}

void
callout_setfunc_new(callout_t *co, void (*func)(void *), void *arg)
{
	callout_impl_t *ci = (callout_impl_t *)co;

	ci->c_callout.c_func = func;
	ci->c_callout.c_arg = arg;
}

bool
callout_invoking_new(callout_t *co)
{
	int s, rv;
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;
	struct nw_work_thread *wtp;

	wtp = WTP;

	CALLOUT_LOCK(s);
	rv = ((c->c_flags & CALLOUT_INVOKING) != 0);
	CALLOUT_UNLOCK(s);

	return rv;
}

void
callout_ack_new(callout_t *co)
{
	int s;
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;
	struct nw_work_thread *wtp;

	wtp = WTP;

	CALLOUT_LOCK(s);
	c->c_flags &= ~CALLOUT_INVOKING;
	CALLOUT_UNLOCK(s);
}

bool
callout_active_new(callout_t *co)
{
	int s, rv;
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;
	struct nw_work_thread *wtp;

	wtp = WTP;

	CALLOUT_LOCK(s);
	rv = ((c->c_flags & (CALLOUT_PENDING|CALLOUT_FIRED)) != 0);
	CALLOUT_UNLOCK(s);

	return rv;
}

void
callout_runnow(callout_t *co, void *arg)
{
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;

	(*c->c_func)(arg);
}

bool
callout_stop_new(callout_t *co)
{
	callout_impl_t *ci = (callout_impl_t *)co;
	struct callout *c = &ci->c_callout;
	int s;
	struct nw_work_thread *wtp;
	wtp = WTP;
	bool expired;

	CALLOUT_LOCK(s);

	if (callout_pending(c)) {
		CIRCQ_REMOVE(&c->c_list);
		callout_offbucket(c);
		if (callout_next_all[ci->c_type].nc == c) {
			CALLOUT_NEXT_CLEAR(ci->c_type);
		}
	}

	expired = ((c->c_flags & CALLOUT_FIRED) != 0);
	c->c_flags &= ~(CALLOUT_PENDING|CALLOUT_FIRED);

	CALLOUT_UNLOCK(s);
	return expired;

}
/*
 * callout_stop:
 *
 *	Cancel a pending callout.
 */
void
callout_stop(struct callout *c)
{
	int s;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	wtp = WTP;
#endif

	CALLOUT_LOCK(s);

	if (callout_pending(c)) {
		CIRCQ_REMOVE(&c->c_list);
		callout_offbucket(c);
	}

	c->c_flags &= ~(CALLOUT_PENDING|CALLOUT_FIRED);

	CALLOUT_UNLOCK(s);
}

#ifdef __QNXNTO__
static int
nextbyte(int *set, unsigned char *bitp, int *jp)
{
	unsigned char bit;
	int j, found;

	bit = *bitp;
	j = *jp;
	found = 0;
	while (j < WHEELSIZE) {
		if (FD_ISSET(bit, (fd_set *)set)) {
			found = 1;
			break;
		}
		bit++;
		j++;
		if ((bit & (CHAR_BIT - 1)) == 0)
			break;
	}
	*bitp = bit;
	*jp = j;
	return found;
}

static int
nextint(int *set, unsigned char *bitp, int *jp)
{
	unsigned char bit, *cp;
	int idx, wrk, j;

	/*
	 * We know we're byte aligned with room for at least
	 * one byte at calltime.
	 */
	bit = *bitp;
	j = *jp;
	idx = bit / (sizeof(int) * CHAR_BIT);
	wrk = htole32(set[idx]);
	idx = (bit % (sizeof(int) * CHAR_BIT)) / CHAR_BIT;
	cp = (unsigned char *)&wrk;
	do {
		if (cp[idx] != 0 || WHEELSIZE - j < CHAR_BIT) {
			*bitp = bit;
			*jp = j;
			return nextbyte(set, bitp, jp);
		}
		idx++;
		bit += CHAR_BIT;
		j += CHAR_BIT;
	} while (bit & (sizeof(int) * CHAR_BIT -1));
	*bitp = bit;
	*jp = j;
	return 0;
}

static void
nexttimo(struct nextt *np, unsigned *mskp)
{

	static const int multiplier[4] = {
		1,
		WHEELSIZE,
		WHEELSIZE*WHEELSIZE,
		WHEELSIZE*WHEELSIZE*WHEELSIZE,
	};
	static const int nwheels = BUCKETS / WHEELSIZE;
	int setidx, i, found, ticks_tot, j;
	unsigned char bit, bit_start, span;
	int *set;
	struct callout *cp;
	unsigned msk_saved;

	msk_saved = *mskp;
	msk_saved &= ~(1<<_CALLOUT_CLK_DEFAULT);
	ticks_tot = 0;
	cp = NULL;
	for (i = 0; i < nwheels; i++) {
		bit_start = MASKWHEEL(i, hardclock_ticks) + 1;
		bit = bit_start;
		set = wheelmsk + i*(WHEELSIZE/(sizeof(int) * CHAR_BIT));
		j = 0;
again:
		found = 0;
		for (; !found && j < WHEELSIZE;) {
			if ((bit & (CHAR_BIT - 1)) ||
			    WHEELSIZE - j < CHAR_BIT) {
				found = nextbyte(set, &bit, &j);
				continue;
			}
			if ((bit & (sizeof(int) * CHAR_BIT -1)) ||
			    WHEELSIZE - j < (CHAR_BIT * sizeof(int))) {
				found = nextint(set, &bit, &j);
				continue;
			}
			setidx = bit / (sizeof(int) * CHAR_BIT);
			if (set[setidx] == 0) {
				bit += sizeof(int) * CHAR_BIT;
				j += sizeof(int) * CHAR_BIT;
				continue;
			}
			found = nextint(set, &bit, &j);
		}
		if (found) {
			int idx, *set_next, ticks_loc, k;
			callout_impl_t *ci;
			struct callout_circq *chead;

			idx = i*WHEELSIZE + bit;
			chead = timeout_wheel + idx;
			if (CIRCQ_EMPTY(chead)) {
				/*
				 * This can happen if callout was
				 * cancelled via callout_stop()
				 */
				FD_CLR(bit, (fd_set *)set);
				goto again;
			}

			span = bit - bit_start;
			cp = CIRCQ_FIRST(chead);

			idx =  (MASKWHEEL(i+1,hardclock_ticks) + 1) & WHEELMASK;
			set_next = set +  WHEELSIZE/(sizeof(int) * CHAR_BIT);
			/*
			 * -1 just below to undo the +1 in the assignment of bit_start
			 *  at the top of the outer loop below.
			 */
			if (bit < (unsigned char)(bit_start - 1) && i+1 < nwheels &&
			    FD_ISSET(idx, (fd_set *)set_next) &&
			    !CIRCQ_EMPTY(&timeout_wheel[idx + (i+1)*WHEELSIZE])) {
				/* Special case */
				chead = &timeout_wheel[idx + (i+1)*WHEELSIZE];
				cp = CIRCQ_FIRST(chead);
				span = (unsigned char)0 - bit_start;
			}

			ticks_loc = ticks_tot + span * multiplier[i];

			if (*mskp & (1<<_CALLOUT_CLK_DEFAULT)) {
				np[_CALLOUT_CLK_DEFAULT].nt = hardclock_ticks + ticks_loc + 1;
				np[_CALLOUT_CLK_DEFAULT].nc = cp;
				*mskp &= ~(1<<_CALLOUT_CLK_DEFAULT);
				if (*mskp == 0)
					break;
			}

			/*
			 * We let _CALLOUT_CLK_DEFAULT handle any re-hashing.  This means
			 * that the first, non _CALLOUT_CLK_DEFAULT timeout we find may
			 * not actually be the next to expire so we have to walk the
			 * entire list.  Save the initial msk to facilitate this.
			 */

			ci = (callout_impl_t *)cp;
			/*
			 * It's an extended struct and this bucket contains one
			 * or more of the types we're looking for.
			 */
			if ((cp->c_flags & CALLOUT_EXT) && (msk_saved & ci->c_type_msk)) {
				unsigned testb;

				/*
				 * start at 1, not 0, since _CALLOUT_CLK_DEFAULT
				 * was checked above.
				 */
				k = _CALLOUT_CLK_DEFAULT + 1;
				testb = 1<<k;
				for (; k < _CALLOUT_CLK_MAX; k++, testb <<= 1) {
					if ((testb & msk_saved) == 0 || (testb & ci->c_type_msk) == 0)
						continue;
					for (;;) {
						if (ci->c_type == k && (np[k].nt == 0 ||
						    SEQ_LT(cp->c_time, np[k].nt))) {
							/*
							 * For non _CALLOUT_CLK_DEFAULT
							 * we store the absolute time,
							 * not the hashed time.
							 * _CALLOUT_CLK_DEFAULT will
							 * handle any rehashes.
							 *
							 * XXX for the special case
							 * above is this actually
							 * always the earliest timeout?
							 * Again _CALLOUT_CLK_DEFAULT
							 * will handle misses.
							 */
							np[k].nt = cp->c_time;
							np[k].nc = cp;
							*mskp &= ~testb;
						}


						if (CIRCQ_LAST(&cp->c_list, chead))
							break;
						cp = CIRCQ_NEXT(&cp->c_list);
						if ((cp->c_flags & CALLOUT_EXT) == 0) {
							break;
						}
						ci = (callout_impl_t *)cp;
					}
					cp = CIRCQ_FIRST(chead);
					ci = (callout_impl_t *)cp;
				}
			}


			/*
			 * What does this found mean exactly?
			 *
			 * Recall the timeout_wheel is a hash of the absolute
			 * time of the timeout.  What this means then is that
			 * what we've found is the next time an evaluation is to
			 * be performed and the timeout in question may be moved
			 * to a new, earlier slot in the timeout_wheel and not
			 * actually fired.  This is more of an issue with longer
			 * timeouts so if our tickstop_max is low enough we may
			 * be OK.  If we find we're not actually sleeping when
			 * we could (see "callout_dbg: couldn't sleep" debug
			 * message below), we may have to:
			 * - walk all CIRCQ entries in this timeout_wheel slot.
			 * - check if any match our current value of ticks_tot
			 *   and if not continue.
			 */

			bit++;
			j++;
			goto again;
		}
		span = (unsigned char)0 - bit_start;
		ticks_tot += span * multiplier[i];
	}
}
#endif

/*
 * This is called from hardclock() once every tick.
 * We return !0 if we need to schedule a softclock.
 */
int
callout_hardclock(int lim)
{
	int s;
	int needsoftclock;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	wtp = WTP;
	int callout_next;
#endif

	CALLOUT_LOCK(s);

	hardclock_ticks++; /* while locked */

	callout_next = callout_next_all[_CALLOUT_CLK_DEFAULT].nt;

	if (callout_next != 0) {
		/*
		 * If we've slept for a while, past the next timeout, jump
		 * directly to it.  Similarly, snap to the current value
		 * if we know we won't pass a timeout so we don't fall into
		 * the loop directly below which would cause callout_next
		 * to be re-evaluated continuously to the same value.
		 *
		 * We use SEQ_LEQ() to handle roll over.
		 */
		if (SEQ_LEQ(callout_next, lim)) {
			hardclock_ticks = callout_next;
		}
		else {
			hardclock_ticks = lim;
		}
	}

	if (hardclock_ticks == callout_next) {
		CALLOUT_NEXT_CLEAR(_CALLOUT_CLK_DEFAULT);
	}


	MOVEBUCKET(0, hardclock_ticks);
#ifdef __QNXNTO__
	FD_CLR(MASKWHEEL(0, hardclock_ticks) + 0*WHEELSIZE, (fd_set *)wheelmsk);
#endif
	if (MASKWHEEL(0, hardclock_ticks) == 0) {
		MOVEBUCKET(1, hardclock_ticks);
#ifdef __QNXNTO__
		FD_CLR(MASKWHEEL(1, hardclock_ticks) + 1*WHEELSIZE, (fd_set *)wheelmsk);
#endif
		if (MASKWHEEL(1, hardclock_ticks) == 0) {
			MOVEBUCKET(2, hardclock_ticks);
#ifdef __QNXNTO__
			FD_CLR(MASKWHEEL(2, hardclock_ticks) + 2*WHEELSIZE, (fd_set *)wheelmsk);
#endif
			if (MASKWHEEL(2, hardclock_ticks) == 0) {
				MOVEBUCKET(3, hardclock_ticks);
#ifdef __QNXNTO__
				FD_CLR(MASKWHEEL(3, hardclock_ticks) + 3*WHEELSIZE, (fd_set *)wheelmsk);
#endif
			}
		}
	}

#ifdef __QNXNTO__
	if (!CIRCQ_EMPTY(&timeout_todo)) {
		struct callout *c;
		callout_impl_t *ci;

		for (c = CIRCQ_FIRST(&timeout_todo);; c = CIRCQ_NEXT(&c->c_list)) {
			if (c->c_flags & CALLOUT_EXT) {
				ci = (callout_impl_t *)c;
				ci->c_bkt = -1;
			}

			if (CIRCQ_LAST(&c->c_list, &timeout_todo))
				break;
		}
	}

#endif

	needsoftclock = !CIRCQ_EMPTY(&timeout_todo);
	CALLOUT_UNLOCK(s);

	return needsoftclock;
}

static void
callout_offbucket(struct callout *c)
{
	callout_impl_t *ci, *ci2;
	struct callout *c2;
	if (c->c_flags & CALLOUT_EXT) {
		ci = (callout_impl_t *)c;
		if (ci->c_bkt != -1 && !CIRCQ_EMPTY(&timeout_wheel[ci->c_bkt])) {
			c2 = CIRCQ_FIRST(&timeout_wheel[ci->c_bkt]);
			if (c2->c_flags & CALLOUT_EXT) {
				ci2 = (callout_impl_t *)c2;
				if (ci->c_type_msk != 0) {
					/* The head was removed.  Move them over */
					ci2->c_type_counts.c_type_all = ci->c_type_counts.c_type_all;
					ci2->c_type_msk = ci->c_type_msk;
				}
				assert(ci2->c_type_counts.c_type_each[ci->c_type] > 0);
				if (--ci2->c_type_counts.c_type_each[ci->c_type] == 0) {
					ci2->c_type_msk &= ~(1<<ci->c_type);
				}
			}
		}
		ci->c_bkt = -1;
	}
}

#ifdef __QNXNTO__
void
timer_adjust(void)
{
	int s;
	unsigned saved_msk, bit;

	struct callout *cp;
	int next, i;
	Dl_info dl;
	struct nw_work_thread *wtp;
	const char *name;
	static struct timeval stoptime_warnlast;
	static const struct timeval stoptime_ratecap = {
		.tv_sec = CALLOUT_DBG_RATELIM,
		.tv_usec = 0,
	};

	wtp = WTP;
	CALLOUT_LOCK(s);

	/*
	 * We need to make sure timeout_todo is empty) since softclock() may
	 * re-hash callouts back on the callwheels after our callout_next calc
	 * making it bogus.
	 */
	if (tickstop_max == 0 || callout_next_msk == 0 ||
	    !CIRCQ_EMPTY(&timeout_todo)) {
		CALLOUT_UNLOCK(s);
		return;
	}


	saved_msk = callout_next_msk;
	nexttimo(callout_next_all, &callout_next_msk);
	for (i = 0; i < _CALLOUT_CLK_MAX; i++) {
		bit = 1<<i;
		cp = NULL;
		if ((saved_msk & bit) != 0 && (callout_next_msk & bit) == 0) {
			/* We were looking for it and it was found */
			next = callout_next_all[i].nt - hardclock_ticks;
			if (i == _CALLOUT_CLK_DEFAULT) {
				if (next > tickstop_max) {
					next = tickstop_max;
					callout_next_all[i].nt = next + hardclock_ticks;
				}
#ifdef CALLOUT_DBG
				if (callout_dbg > 2) {
					checktimo(next);
				}
#endif
			}
			cp = callout_next_all[i].nc;
		}
		else if (i == _CALLOUT_CLK_DEFAULT && (saved_msk & bit)) {
			/*
			 * We were looking for next _CALLOUT_CLK_DEFAULT
			 * but it wasn't found.
			 */
			next = tickstop_max;
			callout_next_all[i].nt = next + hardclock_ticks;
		}
		else {
			continue;
		}

		if (next < tickstop_min) {
			if (callout_dbg &&
			    ratecheck(&stoptime_warnlast, &stoptime_ratecap) &&
			    i == _CALLOUT_CLK_DEFAULT && cp != NULL) {
				name = funcname(cp->c_func, &dl);
				log(LOG_INFO, "callout_dbg: couldn't sleep: %s next %d c_time %d",
				    name, next, cp->c_time - hardclock_ticks);
			}
		}
		else {
			if (callout_dbg && (callout_dbg_msk & bit)) {
				struct timespec ts;

				if (cp == NULL)
					name = NULL;
				else
					name = funcname(cp->c_func, &dl);

				nsec2timespec(&ts, (uint64_t)next << NTO_TSHIFT);
				log(LOG_INFO, "callout_dbg: sleeping for %d sec %lu msec.  Next: %d  %s  callout_next: %d c_time: %d",
				    ts.tv_sec, ts.tv_nsec / 1000000 , next, name, callout_next_all[i].nt, cp != NULL ? cp->c_time : -1);
				/* Warn again after sleeping */
				stoptime_warnlast.tv_sec = 0;
				stoptime_warnlast.tv_usec = 0;

			}
			(*callout_settime[i])(next, i, cp);
		}
	}
	/* Don't check again until something changes */
	callout_next_msk = 0;

	CALLOUT_UNLOCK(s);
}


static void
settime_default(int next, int type, struct callout *c)
{
	struct _itimer	tmo;
	int		err;

	tmo.nsec = (uint64_t)next << NTO_TSHIFT;
	tmo.interval_nsec = TIMER_PULSE_PERIOD;
	if ((err = TimerSettime_r(stk_ctl.timer_int_id, 0, &tmo, NULL)) != 0) {
		log(LOG_ERR, "callout_dbg: failed to sleep: %d", err);
	}
}

static void
settime_group(int next, int type, struct callout *c)
{
	struct gitimerspec	gts;
	callout_impl_t		*ci;
	int			range;

	if (c == NULL)
		return;

	assert(c->c_flags & CALLOUT_EXT);

	ci = (callout_impl_t *)c;

	range = ci->c_range;

	if (gt.gt_gtime[type] == NULL) {
		return; /* default timer will catch this */
	}

	if (c->c_flags & CALLOUT_RANGE_EARLY) {
		gts.expiry_type = GTIMER_EXPIRE_EARLY;
		if (range > 2) {
			/*
			 * There's an early range on it anyway.
			 * Fudging this couple of ticks increases
			 * the chance this is actually operated
			 * on by the group timer, not the
			 * _CALLOUT_CLK_DEFAULT timer.
			 */
			next -= 2;
			range -= 2;
		}
	}
	else if (c->c_flags & CALLOUT_RANGE_LATE)
		gts.expiry_type = GTIMER_EXPIRE_LATE;
	else
		gts.expiry_type = 0;

	nsec2timespec(&gts.it_value, (uint64_t)next << NTO_TSHIFT);

	nsec2timespec(&gts.it_range, (uint64_t)range << NTO_TSHIFT);

	gts.it_interval.tv_sec = 0;
	gts.it_interval.tv_nsec = 0;


	if ((*gt.gt_settime)(gt.gt_gtime[type], 0, &gts, NULL) == -1) {
		if (errno == EINVAL) {
			/*
			 * Can happen if the range / expiry are too tight.
			 * Soft error.
			 */
		}
		else {
			gt.gt_delete(gt.gt_gtime[type]);
			gt.gt_gtime[type] = NULL;
		}
		if (callout_dbg)
			log(LOG_ERR, "gtimer_settime failed: %d", errno);
		CALLOUT_NEXT_CLEAR(type);
	}
}

void
callout_group(int type)
{
	int			s;
	struct callout		*c;
	struct nw_work_thread	*wtp;
	callout_impl_t		*ci;

	wtp = WTP;
	CALLOUT_LOCK(s);
	if ((c = callout_next_all[type].nc) != NULL &&
	    (c->c_flags & (CALLOUT_EXT | CALLOUT_PENDING)) ==
	    (CALLOUT_EXT | CALLOUT_PENDING)) {
		ci = (callout_impl_t *)c;
#if 0
		/*
		 * There's a bug in gtimer manager where the range we
		 * specify is ignored so we can't check its validity
		 * here.
		 */
		int	gnow;

		gnow = hardclock_snap();
		if (c->c_time - gnow <= 0 ||
		    ((c->c_flags & CALLOUT_RANGE_EARLY) &&
		    (unsigned)c->c_time - (unsigned)gnow <= ci->c_range)) {
			CIRCQ_REMOVE(&c->c_list);
			callout_offbucket(c);
			CIRCQ_INSERT(&c->c_list, &timeout_todo);
			/* Run it now */
			c->c_time = hardclock_ticks;
		}
#else
		CIRCQ_REMOVE(&c->c_list);
		callout_offbucket(c);
		CIRCQ_INSERT(&c->c_list, &timeout_todo);
		/* Run it now */
		c->c_time = hardclock_ticks;
#endif
	}
	CALLOUT_NEXT_CLEAR(type);

	CALLOUT_UNLOCK(s);
}

#endif

/* ARGSUSED */
#ifndef __QNXNTO__
void
#else
int
#endif
softclock(void *v)
{
	struct callout *c;
	void (*func)(void *);
	void *arg;
	int s;
#ifdef __QNXNTO__
	struct nw_stk_ctl *sctlp = v;
	struct nw_work_thread *wtp;
	wtp = WTP;
	callout_impl_t *ci, *ci_org;
#endif

	CALLOUT_LOCK(s);

	while (!CIRCQ_EMPTY(&timeout_todo)) {
#ifdef __QNXNTO__
		if (sctlp->pkt_rx_q != NULL) {
			CALLOUT_UNLOCK(s);
			return 1;
		}
#endif
		c = CIRCQ_FIRST(&timeout_todo);
		CIRCQ_REMOVE(&c->c_list);

		/* If due run it, otherwise insert it into the right bucket. */
		if (c->c_time - hardclock_ticks > 0) {
#ifndef __QNXNTO__
			CIRCQ_INSERT(&c->c_list,
			    BUCKET((c->c_time - hardclock_ticks), c->c_time));
#else
			struct callout_circq *bp;
			int bit;
			bp = BUCKET((c->c_time - hardclock_ticks), c->c_time);
			bit = bp - timeout_wheel;
			if (c->c_flags & CALLOUT_EXT) {
				ci = (struct callout_impl *)c;
				ci->c_type_counts.c_type_all = 0;
				ci->c_type_msk = 0;
				assert(ci->c_bkt == -1);
				ci->c_bkt = bit;

				if (!CIRCQ_EMPTY(bp)) {
					ci_org = (struct callout_impl *)CIRCQ_FIRST(bp);
					if (ci_org->c_callout.c_flags & CALLOUT_EXT) {
						ci->c_type_counts.c_type_all =
						    ci_org->c_type_counts.c_type_all;
						ci->c_type_msk = ci_org->c_type_msk;

						ci_org->c_type_counts.c_type_all = 0;
						ci_org->c_type_msk = 0;
					}
				}
				ci->c_type_counts.c_type_each[ci->c_type]++;
				ci->c_type_msk |= 1 << ci->c_type;
				CIRCQ_INSERT_HEAD(&c->c_list, bp);
			}
			else {
				CIRCQ_INSERT_TAIL(&c->c_list, bp);
			}
			FD_SET(bit, (fd_set *)wheelmsk);
#endif
		} else {
#ifdef CALLOUT_EVENT_COUNTERS
			if (c->c_time - hardclock_ticks < 0)
				callout_ev_late.ev_count++;
#endif
			c->c_flags = (c->c_flags  & ~CALLOUT_PENDING) |
			    (CALLOUT_FIRED|CALLOUT_INVOKING);

			if (c->c_flags & CALLOUT_EXT) {
				ci = (struct callout_impl *)c;
				if (callout_next_all[ci->c_type].nc == c) {
					CALLOUT_NEXT_CLEAR(ci->c_type);
				}
			}

			func = c->c_func;
			arg = c->c_arg;
			
			if(func != NULL) {
				CALLOUT_UNLOCK(s);
				(*func)(arg);
				CALLOUT_LOCK(s);
			} else {
				printf("%s(): function pointer in callout entry is NULL(c_arg=%p, c_flag=0x%X, c_time=0x%X). Ignored.",
                                __FUNCTION__, c->c_arg, c->c_flags, c->c_time);
			}
		}
	}

	CALLOUT_UNLOCK(s);
#ifdef __QNXNTO__
	return 0;
#endif
}

#ifdef __QNXNTO__
static const char *
funcname(void *func, Dl_info *dl)
{
	static const char question[] = "?";

	if (dladdr(func, dl) == 0)
		return question;
	return dl->dli_sname;
}
#endif

#ifdef CALLOUT_DBG
static void
db_show_callout_bucket(struct callout_circq *bucket)
{
	struct callout *c;
#ifndef __QNXNTO__
	db_expr_t offset;
	const char *name;
	static char question[] = "?";
#else
	Dl_info dl;
	const char *name;
#endif

	if (CIRCQ_EMPTY(bucket))
		return;

	for (c = CIRCQ_FIRST(bucket); /*nothing*/; c = CIRCQ_NEXT(&c->c_list)) {
#ifndef __QNXNTO__
		db_find_sym_and_offset((db_addr_t)(intptr_t)c->c_func, &name,
		    &offset);
		name = name ? name : question;

#ifdef _LP64
#define	POINTER_WIDTH	"%16lx"
#else
#define	POINTER_WIDTH	"%8lx"
#endif
		db_printf("%9d %2d/%-4d " POINTER_WIDTH "  %s\n",
		    c->c_time - hardclock_ticks,
		    (int)((bucket - timeout_wheel) / WHEELSIZE),
		    (int)(bucket - timeout_wheel), (u_long) c->c_arg, name);

#else
		name = funcname(c->c_func, &dl);
		log(LOG_INFO, "%9d %2d/%-4d %p  %s\n",
		    c->c_time - hardclock_ticks,
		    (int)((bucket - timeout_wheel) / WHEELSIZE),
		    (int)(bucket - timeout_wheel), c->c_arg, name);
#endif
		if (CIRCQ_LAST(&c->c_list, bucket))
			break;
	}
}

#ifndef __QNXNTO__
void
db_show_callout(db_expr_t addr, int haddr, db_expr_t count, const char *modif)
{
	int b;

	db_printf("hardclock_ticks now: %d\n", hardclock_ticks);
#ifdef _LP64
	db_printf("    ticks  wheel               arg  func\n");
#else
	db_printf("    ticks  wheel       arg  func\n");
#endif

	/*
	 * Don't lock the callwheel; all the other CPUs are paused
	 * anyhow, and we might be called in a circumstance where
	 * some other CPU was paused while holding the lock.
	 */

	db_show_callout_bucket(&timeout_todo);
	for (b = 0; b < BUCKETS; b++)
		db_show_callout_bucket(&timeout_wheel[b]);
}
#else
static void
db_show_callout(void)
{
	int b;

	log(LOG_INFO, "hardclock_ticks now: %d\n", hardclock_ticks);
	log(LOG_INFO, "    ticks  wheel       arg  func\n");

	/*
	 * Don't lock the callwheel; all the other CPUs are paused
	 * anyhow, and we might be called in a circumstance where
	 * some other CPU was paused while holding the lock.
	 */

	db_show_callout_bucket(&timeout_todo);
	for (b = 0; b < BUCKETS; b++)
		db_show_callout_bucket(&timeout_wheel[b]);
}

static void
checktimo(int next)
{
	int i;
	struct callout_circq *bp;
	for (i = 1;; i++) {
		bp = &timeout_wheel[MASKWHEEL((0), (hardclock_ticks + i)) + (0)*WHEELSIZE];
		if (!CIRCQ_EMPTY(bp))
			break;
		if (MASKWHEEL(0, hardclock_ticks + i) == 0) {
			bp = &timeout_wheel[MASKWHEEL((1), (hardclock_ticks + i)) + (1)*WHEELSIZE];
			if (!CIRCQ_EMPTY(bp))
				break;
			if (MASKWHEEL(1, hardclock_ticks + i) == 0) {
				bp = &timeout_wheel[MASKWHEEL((2), (hardclock_ticks + i)) + (2)*WHEELSIZE];
				if (!CIRCQ_EMPTY(bp))
					break;
				if (MASKWHEEL(2, hardclock_ticks + i) == 0) {
					bp = &timeout_wheel[MASKWHEEL((3), (hardclock_ticks + i)) + (3)*WHEELSIZE];
					if (!CIRCQ_EMPTY(bp))
						break;
				}
			}
		}
	}
	if (i != next && !(i > tickstop_max && next == tickstop_max)) {
		log(LOG_INFO, "callout_dbg: MISCALC: hardclock_ticks: %d i: %d next: %d", hardclock_ticks, i, next);
		db_show_callout();
	}
}
#endif
#endif /* CALLOUT_DBG */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/kern_timeout.c $ $Rev: 797934 $")
#endif

