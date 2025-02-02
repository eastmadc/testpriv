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

/*	$NetBSD: kern_clock.c,v 1.104 2006/11/01 10:17:58 yamt Exp $	*/

/*-
 * Copyright (c) 2000, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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

/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_clock.c	8.5 (Berkeley) 1/21/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: kern_clock.c,v 1.104 2006/11/01 10:17:58 yamt Exp $");

#include "opt_ntp.h"
#include "opt_multiprocessor.h"
#ifndef __QNXNTO__
#include "opt_perfctrs.h"
#else
#include "nw_defs.h"
#include "siglock.h"
#include <netinet/tcp_var.h>
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/timex.h>
#include <sys/sched.h>
#include <sys/time.h>
#ifdef __HAVE_TIMECOUNTER
#include <sys/timetc.h>
#endif

#include <machine/cpu.h>
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
#include <machine/intr.h>
#endif

#ifdef GPROF
#include <sys/gmon.h>
#endif

#ifdef __QNXNTO__
#include <sys/syspage.h>
#include <sys/syslog.h>

int hardclock_ticks;

static struct kern_clockticks {
	struct _iopkt_self *iopkt;
	struct nw_stk_ctl *sctlp;
	struct qtime_entry *qtp;
	unsigned intr_pending;
	int hardclock_ticks_new;
} kc;

#ifdef USE_TIMER_INTR
static const struct sigevent *
clock_int_handler(void *area, int id)
{
	struct kern_clockticks *kcp = area;
	struct _iopkt_self *iopkt = kcp->iopkt;
	const struct sigevent *evp = NULL;
	struct inter_thread *itp;

	/* XXX NTO which tidx should we check? */
	itp = &iopkt->inter_threads[0];

	/*
	 * Assumptions about how this is intended to work:
	 * - qtp->nsec shouldn't be changing because this
	 *   is called from timer interrupt itself.
	 * - If hardclock_ticks is changing it's because
	 *   softclock() is currently running.  The worst
	 *   that can happen is either a spurious sigevent
	 *   is returned or a tick is missed.
	 */

	/*
	 * Only pulse every 50ms when quiet (thus the 50 / 1000).
	 */
	if ((kcp->qtp->nsec >> NTO_TSHIFT) - kcp->hardclock_ticks_new >
	    (50 * NTO_HZ) / 1000 && kcp->intr_pending == 0) {
		NW_INTR_LK(itp);
		if (itp->working == 0) {
			evp = itp->event;
			itp->working = 1;
		}
		kcp->intr_pending = 1;
		NW_INTR_UNLK(itp);
	}

	return evp;
}
#endif

int
clock_intr_init(void *arg)
{
	struct nw_stk_ctl *sctlp = arg;
	struct qtime_entry *qtp;
	int ret;
#ifndef USE_TIMER_INTR
	int ret2;
	struct sigevent *evp;
	struct _itimer tmo;

	evp = &sctlp->timer_ev;
	tmo.nsec = 50 * 1000000;
	tmo.interval_nsec = 50 * 1000000;
#endif

	qtp = SYSPAGE_ENTRY(qtime);

	kc.sctlp = sctlp;
	kc.iopkt = sctlp->iopkt;
	kc.qtp   = qtp;

	/*
	 * Initialize these together.  We update hardclock_tics off nsec
	 * timer in syspage scaled to NTO_HZ Hz.  softclock() continuously
	 * brings softclock_ticks up to date with hardclock_ticks making
	 * necessary callouts along the way.
	 */
	kc.hardclock_ticks_new = currtime_nto(0) >> NTO_TSHIFT;
	hardclock_ticks = kc.hardclock_ticks_new;

#ifdef USE_TIMER_INTR
	ret = InterruptAttach_r(qtp->intr, clock_int_handler, &kc,
				sizeof(kc), _NTO_INTR_FLAGS_TRK_MSK );
#else
	ret = TimerCreate_r(CLOCK_MONOTONIC, evp); /*XX CLOCK_REALTIME/SOFTTIME? */
	if (ret >= 0 && (ret2 = TimerSettime_r(ret, 0, &tmo, NULL)) != 0) {
		TimerDestroy(ret);
		ret = -ret2;
	}

	if (ret >= 0 && sctlp->timertol) {
		tmo.nsec = sctlp->timertol * 1000000;
		tmo.interval_nsec = 0;
		if ((ret2 = TimerSettime_r(ret, TIMER_TOLERANCE, &tmo, NULL)) != 0) {
			log(LOG_ERR, "tcpip: TIMER_TOLERANCE failed: %d", ret2);
			TimerDestroy(ret);
			ret = -ret2;
		}
		else {
			log(LOG_INFO, "tcpip: TIMER_TOLERANCE set to %dms", sctlp->timertol);
		}
	}
#endif
	if (ret < 0) {
		sctlp->timer_int_id = -1;
		ret = -ret;
	}
	else {
		shutdownhook_establish(clock_intr_destroy, sctlp);
		sctlp->timer_int_id = ret;
		ret = 0;
	}

	return ret;
}

void
clock_intr_destroy(void *arg)
{
	struct nw_stk_ctl	*sctlp;

	sctlp = arg;

	if (sctlp->timer_int_id != -1) {
#ifdef USE_TIMER_INTR
		InterruptDetach_r(sctlp->timer_int_id);
#else
		TimerDestroy(sctlp->timer_int_id);
#endif
		sctlp->timer_int_id = -1;
	}
	return;
}

int
hardclock_snap(void)
{
	return currtime_nto(0) >> NTO_TSHIFT;
}

int
hardclock(void *arg)
{
	struct nw_stk_ctl *sctlp = arg;
	int ret;

	kc.hardclock_ticks_new = hardclock_snap();

	ret = 0;
	softclock(sctlp);
	/*
	 * hardclock_ticks is incremented in callout_hardclock() while locked
	 * but we test here while unlocked.  This is safe because we want to
	 * prevent changing it while other threads are looking at it but only
	 * this thread ever changes so that's not an issue here.
	 */
	while (hardclock_ticks != kc.hardclock_ticks_new) {
		if (callout_hardclock(kc.hardclock_ticks_new) && softclock(sctlp)) {
			ret = NW_DEF_SOFTCLOCK_PKT_LIM;
			break;
		}
	}
	tcp_now_snap(); /* driven off hardclock_ticks */
	if (ret == 0)
		timer_adjust();

	kc.intr_pending = 0;

	return ret;
}
#else /* !__QNXNTO__ */
/*
 * Clock handling routines.
 *
 * This code is written to operate with two timers that run independently of
 * each other.  The main clock, running hz times per second, is used to keep
 * track of real time.  The second timer handles kernel and user profiling,
 * and does resource use estimation.  If the second timer is programmable,
 * it is randomized to avoid aliasing between the two clocks.  For example,
 * the randomization prevents an adversary from always giving up the CPU
 * just before its quantum expires.  Otherwise, it would never accumulate
 * CPU ticks.  The mean frequency of the second timer is stathz.
 *
 * If no second timer exists, stathz will be zero; in this case we drive
 * profiling and statistics off the main clock.  This WILL NOT be accurate;
 * do not do it unless absolutely necessary.
 *
 * The statistics clock may (or may not) be run at a higher rate while
 * profiling.  This profile clock runs at profhz.  We require that profhz
 * be an integral multiple of stathz.
 *
 * If the statistics clock is running fast, it must be divided by the ratio
 * profhz/stathz for statistics.  (For profiling, every tick counts.)
 */

#ifndef __HAVE_TIMECOUNTER
#ifdef NTP	/* NTP phase-locked loop in kernel */
/*
 * Phase/frequency-lock loop (PLL/FLL) definitions
 *
 * The following variables are read and set by the ntp_adjtime() system
 * call.
 *
 * time_state shows the state of the system clock, with values defined
 * in the timex.h header file.
 *
 * time_status shows the status of the system clock, with bits defined
 * in the timex.h header file.
 *
 * time_offset is used by the PLL/FLL to adjust the system time in small
 * increments.
 *
 * time_constant determines the bandwidth or "stiffness" of the PLL.
 *
 * time_tolerance determines maximum frequency error or tolerance of the
 * CPU clock oscillator and is a property of the architecture; however,
 * in principle it could change as result of the presence of external
 * discipline signals, for instance.
 *
 * time_precision is usually equal to the kernel tick variable; however,
 * in cases where a precision clock counter or external clock is
 * available, the resolution can be much less than this and depend on
 * whether the external clock is working or not.
 *
 * time_maxerror is initialized by a ntp_adjtime() call and increased by
 * the kernel once each second to reflect the maximum error bound
 * growth.
 *
 * time_esterror is set and read by the ntp_adjtime() call, but
 * otherwise not used by the kernel.
 */
int time_state = TIME_OK;	/* clock state */
int time_status = STA_UNSYNC;	/* clock status bits */
long time_offset = 0;		/* time offset (us) */
long time_constant = 0;		/* pll time constant */
long time_tolerance = MAXFREQ;	/* frequency tolerance (scaled ppm) */
long time_precision = 1;	/* clock precision (us) */
long time_maxerror = MAXPHASE;	/* maximum error (us) */
long time_esterror = MAXPHASE;	/* estimated error (us) */

/*
 * The following variables establish the state of the PLL/FLL and the
 * residual time and frequency offset of the local clock. The scale
 * factors are defined in the timex.h header file.
 *
 * time_phase and time_freq are the phase increment and the frequency
 * increment, respectively, of the kernel time variable.
 *
 * time_freq is set via ntp_adjtime() from a value stored in a file when
 * the synchronization daemon is first started. Its value is retrieved
 * via ntp_adjtime() and written to the file about once per hour by the
 * daemon.
 *
 * time_adj is the adjustment added to the value of tick at each timer
 * interrupt and is recomputed from time_phase and time_freq at each
 * seconds rollover.
 *
 * time_reftime is the second's portion of the system time at the last
 * call to ntp_adjtime(). It is used to adjust the time_freq variable
 * and to increase the time_maxerror as the time since last update
 * increases.
 */
long time_phase = 0;		/* phase offset (scaled us) */
long time_freq = 0;		/* frequency offset (scaled ppm) */
long time_adj = 0;		/* tick adjust (scaled 1 / hz) */
long time_reftime = 0;		/* time at last adjustment (s) */

#ifdef PPS_SYNC
/*
 * The following variables are used only if the kernel PPS discipline
 * code is configured (PPS_SYNC). The scale factors are defined in the
 * timex.h header file.
 *
 * pps_time contains the time at each calibration interval, as read by
 * microtime(). pps_count counts the seconds of the calibration
 * interval, the duration of which is nominally pps_shift in powers of
 * two.
 *
 * pps_offset is the time offset produced by the time median filter
 * pps_tf[], while pps_jitter is the dispersion (jitter) measured by
 * this filter.
 *
 * pps_freq is the frequency offset produced by the frequency median
 * filter pps_ff[], while pps_stabil is the dispersion (wander) measured
 * by this filter.
 *
 * pps_usec is latched from a high resolution counter or external clock
 * at pps_time. Here we want the hardware counter contents only, not the
 * contents plus the time_tv.usec as usual.
 *
 * pps_valid counts the number of seconds since the last PPS update. It
 * is used as a watchdog timer to disable the PPS discipline should the
 * PPS signal be lost.
 *
 * pps_glitch counts the number of seconds since the beginning of an
 * offset burst more than tick/2 from current nominal offset. It is used
 * mainly to suppress error bursts due to priority conflicts between the
 * PPS interrupt and timer interrupt.
 *
 * pps_intcnt counts the calibration intervals for use in the interval-
 * adaptation algorithm. It's just too complicated for words.
 *
 * pps_kc_hardpps_source contains an arbitrary value that uniquely
 * identifies the currently bound source of the PPS signal, or NULL
 * if no source is bound.
 *
 * pps_kc_hardpps_mode indicates which transitions, if any, of the PPS
 * signal should be reported.
 */
struct timeval pps_time;	/* kernel time at last interval */
long pps_tf[] = {0, 0, 0};	/* pps time offset median filter (us) */
long pps_offset = 0;		/* pps time offset (us) */
long pps_jitter = MAXTIME;	/* time dispersion (jitter) (us) */
long pps_ff[] = {0, 0, 0};	/* pps frequency offset median filter */
long pps_freq = 0;		/* frequency offset (scaled ppm) */
long pps_stabil = MAXFREQ;	/* frequency dispersion (scaled ppm) */
long pps_usec = 0;		/* microsec counter at last interval */
long pps_valid = PPS_VALID;	/* pps signal watchdog counter */
int pps_glitch = 0;		/* pps signal glitch counter */
int pps_count = 0;		/* calibration interval counter (s) */
int pps_shift = PPS_SHIFT;	/* interval duration (s) (shift) */
int pps_intcnt = 0;		/* intervals at current duration */
void *pps_kc_hardpps_source = NULL; /* current PPS supplier's identifier */
int pps_kc_hardpps_mode = 0;	/* interesting edges of PPS signal */

/*
 * PPS signal quality monitors
 *
 * pps_jitcnt counts the seconds that have been discarded because the
 * jitter measured by the time median filter exceeds the limit MAXTIME
 * (100 us).
 *
 * pps_calcnt counts the frequency calibration intervals, which are
 * variable from 4 s to 256 s.
 *
 * pps_errcnt counts the calibration intervals which have been discarded
 * because the wander exceeds the limit MAXFREQ (100 ppm) or where the
 * calibration interval jitter exceeds two ticks.
 *
 * pps_stbcnt counts the calibration intervals that have been discarded
 * because the frequency wander exceeds the limit MAXFREQ / 4 (25 us).
 */
long pps_jitcnt = 0;		/* jitter limit exceeded */
long pps_calcnt = 0;		/* calibration intervals */
long pps_errcnt = 0;		/* calibration errors */
long pps_stbcnt = 0;		/* stability limit exceeded */
#endif /* PPS_SYNC */

#ifdef EXT_CLOCK
/*
 * External clock definitions
 *
 * The following definitions and declarations are used only if an
 * external clock is configured on the system.
 */
#define CLOCK_INTERVAL 30	/* CPU clock update interval (s) */

/*
 * The clock_count variable is set to CLOCK_INTERVAL at each PPS
 * interrupt and decremented once each second.
 */
int clock_count = 0;		/* CPU clock counter */

#ifdef HIGHBALL
/*
 * The clock_offset and clock_cpu variables are used by the HIGHBALL
 * interface. The clock_offset variable defines the offset between
 * system time and the HIGBALL counters. The clock_cpu variable contains
 * the offset between the system clock and the HIGHBALL clock for use in
 * disciplining the kernel time variable.
 */
extern struct timeval clock_offset; /* Highball clock offset */
long clock_cpu = 0;		/* CPU clock adjust */
#endif /* HIGHBALL */
#endif /* EXT_CLOCK */
#endif /* NTP */

/*
 * Bump a timeval by a small number of usec's.
 */
#define BUMPTIME(t, usec) { \
	volatile struct timeval *tp = (t); \
	long us; \
 \
	tp->tv_usec = us = tp->tv_usec + (usec); \
	if (us >= 1000000) { \
		tp->tv_usec = us - 1000000; \
		tp->tv_sec++; \
	} \
}
#endif /* !__HAVE_TIMECOUNTER */

int	stathz;
int	profhz;
int	profsrc;
int	schedhz;
int	profprocs;
int	hardclock_ticks;
static int statscheddiv; /* stat => sched divider (used if schedhz == 0) */
static int psdiv;			/* prof => stat divider */
int	psratio;			/* ratio: prof / stat */
#ifndef __HAVE_TIMECOUNTER
int	tickfix, tickfixinterval;	/* used if tick not really integral */
#ifndef NTP
static int tickfixcnt;			/* accumulated fractional error */
#else
int	fixtick;			/* used by NTP for same */
int	shifthz;
#endif

/*
 * We might want ldd to load the both words from time at once.
 * To succeed we need to be quadword aligned.
 * The sparc already does that, and that it has worked so far is a fluke.
 */
volatile struct	timeval time  __attribute__((__aligned__(__alignof__(quad_t))));
volatile struct	timeval mono_time;
#endif /* !__HAVE_TIMECOUNTER */

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
void	*softclock_si;
#endif

#ifdef __HAVE_TIMECOUNTER
static u_int get_intr_timecount(struct timecounter *);

static struct timecounter intr_timecounter = {
	get_intr_timecount,	/* get_timecount */
	0,			/* no poll_pps */
	~0u,			/* counter_mask */
	0,		        /* frequency */
	"clockinterrupt",	/* name */
	0,			/* quality - minimum implementation level for a clock */
	NULL,			/* prev */
	NULL,			/* next */
};

static u_int
get_intr_timecount(struct timecounter *tc)
{

	return (u_int)hardclock_ticks;
}
#endif

/*
 * Initialize clock frequencies and start both clocks running.
 */
void
initclocks(void)
{
	int i;

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	softclock_si = softintr_establish(IPL_SOFTCLOCK, softclock, NULL);
	if (softclock_si == NULL)
		panic("initclocks: unable to register softclock intr");
#endif

	/*
	 * Set divisors to 1 (normal case) and let the machine-specific
	 * code do its bit.
	 */
	psdiv = 1;
#ifdef __HAVE_TIMECOUNTER
	/*
	 * provide minimum default time counter
	 * will only run at interrupt resolution
	 */
	intr_timecounter.tc_frequency = hz;
	tc_init(&intr_timecounter);
#endif
	cpu_initclocks();

	/*
	 * Compute profhz/stathz/rrticks, and fix profhz if needed.
	 */
	i = stathz ? stathz : hz;
	if (profhz == 0)
		profhz = i;
	psratio = profhz / i;
	rrticks = hz / 10;
	if (schedhz == 0) {
		/* 16Hz is best */
		statscheddiv = i / 16;
		if (statscheddiv <= 0)
			panic("statscheddiv");
	}

#ifndef __HAVE_TIMECOUNTER
#ifdef NTP
	switch (hz) {
	case 1:
		shifthz = SHIFT_SCALE - 0;
		break;
	case 2:
		shifthz = SHIFT_SCALE - 1;
		break;
	case 4:
		shifthz = SHIFT_SCALE - 2;
		break;
	case 8:
		shifthz = SHIFT_SCALE - 3;
		break;
	case 16:
		shifthz = SHIFT_SCALE - 4;
		break;
	case 32:
		shifthz = SHIFT_SCALE - 5;
		break;
	case 50:
	case 60:
	case 64:
		shifthz = SHIFT_SCALE - 6;
		break;
	case 96:
	case 100:
	case 128:
		shifthz = SHIFT_SCALE - 7;
		break;
	case 256:
		shifthz = SHIFT_SCALE - 8;
		break;
	case 512:
		shifthz = SHIFT_SCALE - 9;
		break;
	case 1000:
	case 1024:
		shifthz = SHIFT_SCALE - 10;
		break;
	case 1200:
	case 2048:
		shifthz = SHIFT_SCALE - 11;
		break;
	case 4096:
		shifthz = SHIFT_SCALE - 12;
		break;
	case 8192:
		shifthz = SHIFT_SCALE - 13;
		break;
	case 16384:
		shifthz = SHIFT_SCALE - 14;
		break;
	case 32768:
		shifthz = SHIFT_SCALE - 15;
		break;
	case 65536:
		shifthz = SHIFT_SCALE - 16;
		break;
	default:
		panic("weird hz");
	}
	if (fixtick == 0) {
		/*
		 * Give MD code a chance to set this to a better
		 * value; but, if it doesn't, we should.
		 */
		fixtick = (1000000 - (hz*tick));
	}
#endif /* NTP */
#endif /* !__HAVE_TIMECOUNTER */
}

/*
 * The real-time timer, interrupting hz times per second.
 */
void
hardclock(struct clockframe *frame)
{
	struct lwp *l;
	struct proc *p;
	struct cpu_info *ci = curcpu();
	struct ptimer *pt;
#ifndef __HAVE_TIMECOUNTER
	int delta;
	extern int tickdelta;
	extern long timedelta;
#ifdef NTP
	int time_update;
	int ltemp;
#endif /* NTP */
#endif /* __HAVE_TIMECOUNTER */

	l = curlwp;
	if (l) {
		p = l->l_proc;
		/*
		 * Run current process's virtual and profile time, as needed.
		 */
		if (CLKF_USERMODE(frame) && p->p_timers &&
		    (pt = LIST_FIRST(&p->p_timers->pts_virtual)) != NULL)
			if (itimerdecr(pt, tick) == 0)
				itimerfire(pt);
		if (p->p_timers &&
		    (pt = LIST_FIRST(&p->p_timers->pts_prof)) != NULL)
			if (itimerdecr(pt, tick) == 0)
				itimerfire(pt);
	}

	/*
	 * If no separate statistics clock is available, run it from here.
	 */
	if (stathz == 0)
		statclock(frame);
	if ((--ci->ci_schedstate.spc_rrticks) <= 0)
		roundrobin(ci);

#if defined(MULTIPROCESSOR)
	/*
	 * If we are not the primary CPU, we're not allowed to do
	 * any more work.
	 */
	if (CPU_IS_PRIMARY(ci) == 0)
		return;
#endif

	hardclock_ticks++;

#ifdef __HAVE_TIMECOUNTER
	tc_ticktock();
#else /* __HAVE_TIMECOUNTER */
	/*
	 * Increment the time-of-day.  The increment is normally just
	 * ``tick''.  If the machine is one which has a clock frequency
	 * such that ``hz'' would not divide the second evenly into
	 * milliseconds, a periodic adjustment must be applied.  Finally,
	 * if we are still adjusting the time (see adjtime()),
	 * ``tickdelta'' may also be added in.
	 */
	delta = tick;

#ifndef NTP
	if (tickfix) {
		tickfixcnt += tickfix;
		if (tickfixcnt >= tickfixinterval) {
			delta++;
			tickfixcnt -= tickfixinterval;
		}
	}
#endif /* !NTP */
	/* Imprecise 4bsd adjtime() handling */
	if (timedelta != 0) {
		delta += tickdelta;
		timedelta -= tickdelta;
	}

#ifdef notyet
	microset();
#endif

#ifndef NTP
	BUMPTIME(&time, delta);		/* XXX Now done using NTP code below */
#endif
	BUMPTIME(&mono_time, delta);

#ifdef NTP
	time_update = delta;

	/*
	 * Compute the phase adjustment. If the low-order bits
	 * (time_phase) of the update overflow, bump the high-order bits
	 * (time_update).
	 */
	time_phase += time_adj;
	if (time_phase <= -FINEUSEC) {
		ltemp = -time_phase >> SHIFT_SCALE;
		time_phase += ltemp << SHIFT_SCALE;
		time_update -= ltemp;
	} else if (time_phase >= FINEUSEC) {
		ltemp = time_phase >> SHIFT_SCALE;
		time_phase -= ltemp << SHIFT_SCALE;
		time_update += ltemp;
	}

#ifdef HIGHBALL
	/*
	 * If the HIGHBALL board is installed, we need to adjust the
	 * external clock offset in order to close the hardware feedback
	 * loop. This will adjust the external clock phase and frequency
	 * in small amounts. The additional phase noise and frequency
	 * wander this causes should be minimal. We also need to
	 * discipline the kernel time variable, since the PLL is used to
	 * discipline the external clock. If the Highball board is not
	 * present, we discipline kernel time with the PLL as usual. We
	 * assume that the external clock phase adjustment (time_update)
	 * and kernel phase adjustment (clock_cpu) are less than the
	 * value of tick.
	 */
	clock_offset.tv_usec += time_update;
	if (clock_offset.tv_usec >= 1000000) {
		clock_offset.tv_sec++;
		clock_offset.tv_usec -= 1000000;
	}
	if (clock_offset.tv_usec < 0) {
		clock_offset.tv_sec--;
		clock_offset.tv_usec += 1000000;
	}
	time.tv_usec += clock_cpu;
	clock_cpu = 0;
#else
	time.tv_usec += time_update;
#endif /* HIGHBALL */

	/*
	 * On rollover of the second the phase adjustment to be used for
	 * the next second is calculated. Also, the maximum error is
	 * increased by the tolerance. If the PPS frequency discipline
	 * code is present, the phase is increased to compensate for the
	 * CPU clock oscillator frequency error.
	 *
 	 * On a 32-bit machine and given parameters in the timex.h
	 * header file, the maximum phase adjustment is +-512 ms and
	 * maximum frequency offset is a tad less than) +-512 ppm. On a
	 * 64-bit machine, you shouldn't need to ask.
	 */
	if (time.tv_usec >= 1000000) {
		time.tv_usec -= 1000000;
		time.tv_sec++;
		time_maxerror += time_tolerance >> SHIFT_USEC;

		/*
		 * Leap second processing. If in leap-insert state at
		 * the end of the day, the system clock is set back one
		 * second; if in leap-delete state, the system clock is
		 * set ahead one second. The microtime() routine or
		 * external clock driver will insure that reported time
		 * is always monotonic. The ugly divides should be
		 * replaced.
		 */
		switch (time_state) {
		case TIME_OK:
			if (time_status & STA_INS)
				time_state = TIME_INS;
			else if (time_status & STA_DEL)
				time_state = TIME_DEL;
			break;

		case TIME_INS:
			if (time.tv_sec % 86400 == 0) {
				time.tv_sec--;
				time_state = TIME_OOP;
			}
			break;

		case TIME_DEL:
			if ((time.tv_sec + 1) % 86400 == 0) {
				time.tv_sec++;
				time_state = TIME_WAIT;
			}
			break;

		case TIME_OOP:
			time_state = TIME_WAIT;
			break;

		case TIME_WAIT:
			if (!(time_status & (STA_INS | STA_DEL)))
				time_state = TIME_OK;
			break;
		}

		/*
		 * Compute the phase adjustment for the next second. In
		 * PLL mode, the offset is reduced by a fixed factor
		 * times the time constant. In FLL mode the offset is
		 * used directly. In either mode, the maximum phase
		 * adjustment for each second is clamped so as to spread
		 * the adjustment over not more than the number of
		 * seconds between updates.
		 */
		if (time_offset < 0) {
			ltemp = -time_offset;
			if (!(time_status & STA_FLL))
				ltemp >>= SHIFT_KG + time_constant;
			if (ltemp > (MAXPHASE / MINSEC) << SHIFT_UPDATE)
				ltemp = (MAXPHASE / MINSEC) <<
				    SHIFT_UPDATE;
			time_offset += ltemp;
			time_adj = -ltemp << (shifthz - SHIFT_UPDATE);
		} else if (time_offset > 0) {
			ltemp = time_offset;
			if (!(time_status & STA_FLL))
				ltemp >>= SHIFT_KG + time_constant;
			if (ltemp > (MAXPHASE / MINSEC) << SHIFT_UPDATE)
				ltemp = (MAXPHASE / MINSEC) <<
				    SHIFT_UPDATE;
			time_offset -= ltemp;
			time_adj = ltemp << (shifthz - SHIFT_UPDATE);
		} else
			time_adj = 0;

		/*
		 * Compute the frequency estimate and additional phase
		 * adjustment due to frequency error for the next
		 * second. When the PPS signal is engaged, gnaw on the
		 * watchdog counter and update the frequency computed by
		 * the pll and the PPS signal.
		 */
#ifdef PPS_SYNC
		pps_valid++;
		if (pps_valid == PPS_VALID) {
			pps_jitter = MAXTIME;
			pps_stabil = MAXFREQ;
			time_status &= ~(STA_PPSSIGNAL | STA_PPSJITTER |
			    STA_PPSWANDER | STA_PPSERROR);
		}
		ltemp = time_freq + pps_freq;
#else
		ltemp = time_freq;
#endif /* PPS_SYNC */

		if (ltemp < 0)
			time_adj -= -ltemp >> (SHIFT_USEC - shifthz);
		else
			time_adj += ltemp >> (SHIFT_USEC - shifthz);
		time_adj += (long)fixtick << shifthz;

		/*
		 * When the CPU clock oscillator frequency is not a
		 * power of 2 in Hz, shifthz is only an approximate
		 * scale factor.
		 *
		 * To determine the adjustment, you can do the following:
		 *   bc -q
		 *   scale=24
		 *   obase=2
		 *   idealhz/realhz
		 * where `idealhz' is the next higher power of 2, and `realhz'
		 * is the actual value.  You may need to factor this result
		 * into a sequence of 2 multipliers to get better precision.
		 *
		 * Likewise, the error can be calculated with (e.g. for 100Hz):
		 *   bc -q
		 *   scale=24
		 *   ((1+2^-2+2^-5)*(1-2^-10)*realhz-idealhz)/idealhz
		 * (and then multiply by 1000000 to get ppm).
		 */
		switch (hz) {
		case 60:
			/* A factor of 1.000100010001 gives about 15ppm
			   error. */
			if (time_adj < 0) {
				time_adj -= (-time_adj >> 4);
				time_adj -= (-time_adj >> 8);
			} else {
				time_adj += (time_adj >> 4);
				time_adj += (time_adj >> 8);
			}
			break;

		case 96:
			/* A factor of 1.0101010101 gives about 244ppm error. */
			if (time_adj < 0) {
				time_adj -= (-time_adj >> 2);
				time_adj -= (-time_adj >> 4) + (-time_adj >> 8);
			} else {
				time_adj += (time_adj >> 2);
				time_adj += (time_adj >> 4) + (time_adj >> 8);
			}
			break;

		case 50:
		case 100:
			/* A factor of 1.010001111010111 gives about 1ppm
			   error. */
			if (time_adj < 0) {
				time_adj -= (-time_adj >> 2) + (-time_adj >> 5);
				time_adj += (-time_adj >> 10);
			} else {
				time_adj += (time_adj >> 2) + (time_adj >> 5);
				time_adj -= (time_adj >> 10);
			}
			break;

		case 1000:
			/* A factor of 1.000001100010100001 gives about 50ppm
			   error. */
			if (time_adj < 0) {
				time_adj -= (-time_adj >> 6) + (-time_adj >> 11);
				time_adj -= (-time_adj >> 7);
			} else {
				time_adj += (time_adj >> 6) + (time_adj >> 11);
				time_adj += (time_adj >> 7);
			}
			break;

		case 1200:
			/* A factor of 1.1011010011100001 gives about 64ppm
			   error. */
			if (time_adj < 0) {
				time_adj -= (-time_adj >> 1) + (-time_adj >> 6);
				time_adj -= (-time_adj >> 3) + (-time_adj >> 10);
			} else {
				time_adj += (time_adj >> 1) + (time_adj >> 6);
				time_adj += (time_adj >> 3) + (time_adj >> 10);
			}
			break;
		}

#ifdef EXT_CLOCK
		/*
		 * If an external clock is present, it is necessary to
		 * discipline the kernel time variable anyway, since not
		 * all system components use the microtime() interface.
		 * Here, the time offset between the external clock and
		 * kernel time variable is computed every so often.
		 */
		clock_count++;
		if (clock_count > CLOCK_INTERVAL) {
			clock_count = 0;
			microtime(&clock_ext);
			delta.tv_sec = clock_ext.tv_sec - time.tv_sec;
			delta.tv_usec = clock_ext.tv_usec -
			    time.tv_usec;
			if (delta.tv_usec < 0)
				delta.tv_sec--;
			if (delta.tv_usec >= 500000) {
				delta.tv_usec -= 1000000;
				delta.tv_sec++;
			}
			if (delta.tv_usec < -500000) {
				delta.tv_usec += 1000000;
				delta.tv_sec--;
			}
			if (delta.tv_sec > 0 || (delta.tv_sec == 0 &&
			    delta.tv_usec > MAXPHASE) ||
			    delta.tv_sec < -1 || (delta.tv_sec == -1 &&
			    delta.tv_usec < -MAXPHASE)) {
				time = clock_ext;
				delta.tv_sec = 0;
				delta.tv_usec = 0;
			}
#ifdef HIGHBALL
			clock_cpu = delta.tv_usec;
#else /* HIGHBALL */
			hardupdate(delta.tv_usec);
#endif /* HIGHBALL */
		}
#endif /* EXT_CLOCK */
	}

#endif /* NTP */
#endif /* !__HAVE_TIMECOUNTER */

	/*
	 * Update real-time timeout queue.
	 * Process callouts at a very low CPU priority, so we don't keep the
	 * relatively high clock interrupt priority any longer than necessary.
	 */
	if (callout_hardclock()) {
		if (CLKF_BASEPRI(frame)) {
			/*
			 * Save the overhead of a software interrupt;
			 * it will happen as soon as we return, so do
			 * it now.
			 */
			spllowersoftclock();
			KERNEL_LOCK(LK_CANRECURSE|LK_EXCLUSIVE);
			softclock(NULL);
			KERNEL_UNLOCK();
		} else {
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
			softintr_schedule(softclock_si);
#else
			setsoftclock();
#endif
		}
	}
}

#ifdef __HAVE_TIMECOUNTER
/*
 * Compute number of hz until specified time.  Used to compute second
 * argument to callout_reset() from an absolute time.
 */
int
hzto(struct timeval *tvp)
{
	struct timeval now, tv;

	tv = *tvp;	/* Don't modify original tvp. */
	getmicrotime(&now);
	timersub(&tv, &now, &tv);
	return tvtohz(&tv);
}
#endif /* __HAVE_TIMECOUNTER */
#endif /* !__QNXNTO__ */

/*
 * Compute number of ticks in the specified amount of time.
 */
int
tvtohz(struct timeval *tv)
{
	unsigned long ticks;
	long sec, usec;

	/*
	 * If the number of usecs in the whole seconds part of the time
	 * difference fits in a long, then the total number of usecs will
	 * fit in an unsigned long.  Compute the total and convert it to
	 * ticks, rounding up and adding 1 to allow for the current tick
	 * to expire.  Rounding also depends on unsigned long arithmetic
	 * to avoid overflow.
	 *
	 * Otherwise, if the number of ticks in the whole seconds part of
	 * the time difference fits in a long, then convert the parts to
	 * ticks separately and add, using similar rounding methods and
	 * overflow avoidance.  This method would work in the previous
	 * case, but it is slightly slower and assumes that hz is integral.
	 *
	 * Otherwise, round the time difference down to the maximum
	 * representable value.
	 *
	 * If ints are 32-bit, then the maximum value for any timeout in
	 * 10ms ticks is 248 days.
	 */
	sec = tv->tv_sec;
	usec = tv->tv_usec;

	if (usec < 0) {
		sec--;
		usec += 1000000;
	}

	if (sec < 0 || (sec == 0 && usec <= 0)) {
		/*
		 * Would expire now or in the past.  Return 0 ticks.
		 * This is different from the legacy hzto() interface,
		 * and callers need to check for it.
		 */
		ticks = 0;
	} else if (sec <= (LONG_MAX / 1000000))
		ticks = (((sec * 1000000) + (unsigned long)usec + (tick - 1))
		    / tick) + 1;
	else if (sec <= (LONG_MAX / hz))
		ticks = (sec * hz) +
		    (((unsigned long)usec + (tick - 1)) / tick) + 1;
	else
		ticks = LONG_MAX;

	if (ticks > INT_MAX)
		ticks = INT_MAX;

	return ((int)ticks);
}

#ifndef __HAVE_TIMECOUNTER
/*
 * Compute number of hz until specified time.  Used to compute second
 * argument to callout_reset() from an absolute time.
 */
int
hzto(struct timeval *tv)
{
	unsigned long ticks;
	long sec, usec;
	int s;

	/*
	 * If the number of usecs in the whole seconds part of the time
	 * difference fits in a long, then the total number of usecs will
	 * fit in an unsigned long.  Compute the total and convert it to
	 * ticks, rounding up and adding 1 to allow for the current tick
	 * to expire.  Rounding also depends on unsigned long arithmetic
	 * to avoid overflow.
	 *
	 * Otherwise, if the number of ticks in the whole seconds part of
	 * the time difference fits in a long, then convert the parts to
	 * ticks separately and add, using similar rounding methods and
	 * overflow avoidance.  This method would work in the previous
	 * case, but it is slightly slower and assume that hz is integral.
	 *
	 * Otherwise, round the time difference down to the maximum
	 * representable value.
	 *
	 * If ints are 32-bit, then the maximum value for any timeout in
	 * 10ms ticks is 248 days.
	 */
	s = splclock();
	sec = tv->tv_sec - TIME.tv_sec;
	usec = tv->tv_usec - TIME.tv_usec;
	splx(s);

	if (usec < 0) {
		sec--;
		usec += 1000000;
	}

	if (sec < 0 || (sec == 0 && usec <= 0)) {
		/*
		 * Would expire now or in the past.  Return 0 ticks.
		 * This is different from the legacy hzto() interface,
		 * and callers need to check for it.
		 */
		ticks = 0;
	} else if (sec <= (LONG_MAX / 1000000))
		ticks = (((sec * 1000000) + (unsigned long)usec + (tick - 1))
		    / tick) + 1;
	else if (sec <= (LONG_MAX / hz))
		ticks = (sec * hz) +
		    (((unsigned long)usec + (tick - 1)) / tick) + 1;
	else
		ticks = LONG_MAX;

	if (ticks > INT_MAX)
		ticks = INT_MAX;

	return ((int)ticks);
}
#endif /* !__HAVE_TIMECOUNTER */

#ifndef __QNXNTO__
/*
 * Compute number of ticks in the specified amount of time.
 */
int
tstohz(struct timespec *ts)
{
	struct timeval tv;

	/*
	 * usec has great enough resolution for hz, so convert to a
	 * timeval and use tvtohz() above.
	 */
	TIMESPEC_TO_TIMEVAL(&tv, ts);
	return tvtohz(&tv);
}

/*
 * Start profiling on a process.
 *
 * Kernel profiling passes proc0 which never exits and hence
 * keeps the profile clock running constantly.
 */
void
startprofclock(struct proc *p)
{

	if ((p->p_flag & P_PROFIL) == 0) {
		p->p_flag |= P_PROFIL;
		/*
		 * This is only necessary if using the clock as the
		 * profiling source.
		 */
		if (++profprocs == 1 && stathz != 0)
			psdiv = psratio;
	}
}

/*
 * Stop profiling on a process.
 */
void
stopprofclock(struct proc *p)
{

	if (p->p_flag & P_PROFIL) {
		p->p_flag &= ~P_PROFIL;
		/*
		 * This is only necessary if using the clock as the
		 * profiling source.
		 */
		if (--profprocs == 0 && stathz != 0)
			psdiv = 1;
	}
}

#if defined(PERFCTRS)
/*
 * Independent profiling "tick" in case we're using a separate
 * clock or profiling event source.  Currently, that's just
 * performance counters--hence the wrapper.
 */
void
proftick(struct clockframe *frame)
{
#ifdef GPROF
        struct gmonparam *g;
        intptr_t i;
#endif
	struct proc *p;

	p = curproc;
	if (CLKF_USERMODE(frame)) {
		if (p->p_flag & P_PROFIL)
			addupc_intr(p, CLKF_PC(frame));
	} else {
#ifdef GPROF
		g = &_gmonparam;
		if (g->state == GMON_PROF_ON) {
			i = CLKF_PC(frame) - g->lowpc;
			if (i < g->textsize) {
				i /= HISTFRACTION * sizeof(*g->kcount);
				g->kcount[i]++;
			}
		}
#endif
#ifdef PROC_PC
                if (p && (p->p_flag & P_PROFIL))
                        addupc_intr(p, PROC_PC(p));
#endif
	}
}
#endif

/*
 * Statistics clock.  Grab profile sample, and if divider reaches 0,
 * do process and kernel statistics.
 */
void
statclock(struct clockframe *frame)
{
#ifdef GPROF
	struct gmonparam *g;
	intptr_t i;
#endif
	struct cpu_info *ci = curcpu();
	struct schedstate_percpu *spc = &ci->ci_schedstate;
	struct proc *p;
	struct lwp *l;

	/*
	 * Notice changes in divisor frequency, and adjust clock
	 * frequency accordingly.
	 */
	if (spc->spc_psdiv != psdiv) {
		spc->spc_psdiv = psdiv;
		spc->spc_pscnt = psdiv;
		if (psdiv == 1) {
			setstatclockrate(stathz);
		} else {
			setstatclockrate(profhz);
		}
	}
	l = curlwp;
	p = (l ? l->l_proc : NULL);
	if (CLKF_USERMODE(frame)) {
		KASSERT(p != NULL);

		if ((p->p_flag & P_PROFIL) && profsrc == PROFSRC_CLOCK)
			addupc_intr(p, CLKF_PC(frame));
		if (--spc->spc_pscnt > 0)
			return;
		/*
		 * Came from user mode; CPU was in user state.
		 * If this process is being profiled record the tick.
		 */
		p->p_uticks++;
		if (p->p_nice > NZERO)
			spc->spc_cp_time[CP_NICE]++;
		else
			spc->spc_cp_time[CP_USER]++;
	} else {
#ifdef GPROF
		/*
		 * Kernel statistics are just like addupc_intr, only easier.
		 */
		g = &_gmonparam;
		if (profsrc == PROFSRC_CLOCK && g->state == GMON_PROF_ON) {
			i = CLKF_PC(frame) - g->lowpc;
			if (i < g->textsize) {
				i /= HISTFRACTION * sizeof(*g->kcount);
				g->kcount[i]++;
			}
		}
#endif
#ifdef LWP_PC
		if (p && profsrc == PROFSRC_CLOCK && (p->p_flag & P_PROFIL))
			addupc_intr(p, LWP_PC(l));
#endif
		if (--spc->spc_pscnt > 0)
			return;
		/*
		 * Came from kernel mode, so we were:
		 * - handling an interrupt,
		 * - doing syscall or trap work on behalf of the current
		 *   user process, or
		 * - spinning in the idle loop.
		 * Whichever it is, charge the time as appropriate.
		 * Note that we charge interrupts to the current process,
		 * regardless of whether they are ``for'' that process,
		 * so that we know how much of its real time was spent
		 * in ``non-process'' (i.e., interrupt) work.
		 */
		if (CLKF_INTR(frame)) {
			if (p != NULL)
				p->p_iticks++;
			spc->spc_cp_time[CP_INTR]++;
		} else if (p != NULL) {
			p->p_sticks++;
			spc->spc_cp_time[CP_SYS]++;
		} else
			spc->spc_cp_time[CP_IDLE]++;
	}
	spc->spc_pscnt = psdiv;

	if (p != NULL) {
		++p->p_cpticks;
		/*
		 * If no separate schedclock is provided, call it here
		 * at about 16 Hz.
		 */
		if (schedhz == 0)
			if ((int)(--ci->ci_schedstate.spc_schedticks) <= 0) {
				schedclock(l);
				ci->ci_schedstate.spc_schedticks = statscheddiv;
			}
	}
}
#endif /* !__QNXNTO__ */

#ifndef __HAVE_TIMECOUNTER
#ifndef __QNXNTO__
#ifdef NTP	/* NTP phase-locked loop in kernel */
/*
 * hardupdate() - local clock update
 *
 * This routine is called by ntp_adjtime() to update the local clock
 * phase and frequency. The implementation is of an adaptive-parameter,
 * hybrid phase/frequency-lock loop (PLL/FLL). The routine computes new
 * time and frequency offset estimates for each call. If the kernel PPS
 * discipline code is configured (PPS_SYNC), the PPS signal itself
 * determines the new time offset, instead of the calling argument.
 * Presumably, calls to ntp_adjtime() occur only when the caller
 * believes the local clock is valid within some bound (+-128 ms with
 * NTP). If the caller's time is far different than the PPS time, an
 * argument will ensue, and it's not clear who will lose.
 *
 * For uncompensated quartz crystal oscillatores and nominal update
 * intervals less than 1024 s, operation should be in phase-lock mode
 * (STA_FLL = 0), where the loop is disciplined to phase. For update
 * intervals greater than thiss, operation should be in frequency-lock
 * mode (STA_FLL = 1), where the loop is disciplined to frequency.
 *
 * Note: splclock() is in effect.
 */
void
hardupdate(long offset)
{
	long ltemp, mtemp;

	if (!(time_status & STA_PLL) && !(time_status & STA_PPSTIME))
		return;
	ltemp = offset;
#ifdef PPS_SYNC
	if (time_status & STA_PPSTIME && time_status & STA_PPSSIGNAL)
		ltemp = pps_offset;
#endif /* PPS_SYNC */

	/*
	 * Scale the phase adjustment and clamp to the operating range.
	 */
	if (ltemp > MAXPHASE)
		time_offset = MAXPHASE << SHIFT_UPDATE;
	else if (ltemp < -MAXPHASE)
		time_offset = -(MAXPHASE << SHIFT_UPDATE);
	else
		time_offset = ltemp << SHIFT_UPDATE;

	/*
	 * Select whether the frequency is to be controlled and in which
	 * mode (PLL or FLL). Clamp to the operating range. Ugly
	 * multiply/divide should be replaced someday.
	 */
	if (time_status & STA_FREQHOLD || time_reftime == 0)
		time_reftime = time.tv_sec;
	mtemp = time.tv_sec - time_reftime;
	time_reftime = time.tv_sec;
	if (time_status & STA_FLL) {
		if (mtemp >= MINSEC) {
			ltemp = ((time_offset / mtemp) << (SHIFT_USEC -
			    SHIFT_UPDATE));
			if (ltemp < 0)
				time_freq -= -ltemp >> SHIFT_KH;
			else
				time_freq += ltemp >> SHIFT_KH;
		}
	} else {
		if (mtemp < MAXSEC) {
			ltemp *= mtemp;
			if (ltemp < 0)
				time_freq -= -ltemp >> (time_constant +
				    time_constant + SHIFT_KF -
				    SHIFT_USEC);
			else
				time_freq += ltemp >> (time_constant +
				    time_constant + SHIFT_KF -
				    SHIFT_USEC);
		}
	}
	if (time_freq > time_tolerance)
		time_freq = time_tolerance;
	else if (time_freq < -time_tolerance)
		time_freq = -time_tolerance;
}

#ifdef PPS_SYNC
/*
 * hardpps() - discipline CPU clock oscillator to external PPS signal
 *
 * This routine is called at each PPS interrupt in order to discipline
 * the CPU clock oscillator to the PPS signal. It measures the PPS phase
 * and leaves it in a handy spot for the hardclock() routine. It
 * integrates successive PPS phase differences and calculates the
 * frequency offset. This is used in hardclock() to discipline the CPU
 * clock oscillator so that intrinsic frequency error is cancelled out.
 * The code requires the caller to capture the time and hardware counter
 * value at the on-time PPS signal transition.
 *
 * Note that, on some Unix systems, this routine runs at an interrupt
 * priority level higher than the timer interrupt routine hardclock().
 * Therefore, the variables used are distinct from the hardclock()
 * variables, except for certain exceptions: The PPS frequency pps_freq
 * and phase pps_offset variables are determined by this routine and
 * updated atomically. The time_tolerance variable can be considered a
 * constant, since it is infrequently changed, and then only when the
 * PPS signal is disabled. The watchdog counter pps_valid is updated
 * once per second by hardclock() and is atomically cleared in this
 * routine.
 */
void
hardpps(struct timeval *tvp,		/* time at PPS */
	long usec			/* hardware counter at PPS */)
{
	long u_usec, v_usec, bigtick;
	long cal_sec, cal_usec;

	/*
	 * An occasional glitch can be produced when the PPS interrupt
	 * occurs in the hardclock() routine before the time variable is
	 * updated. Here the offset is discarded when the difference
	 * between it and the last one is greater than tick/2, but not
	 * if the interval since the first discard exceeds 30 s.
	 */
	time_status |= STA_PPSSIGNAL;
	time_status &= ~(STA_PPSJITTER | STA_PPSWANDER | STA_PPSERROR);
	pps_valid = 0;
	u_usec = -tvp->tv_usec;
	if (u_usec < -500000)
		u_usec += 1000000;
	v_usec = pps_offset - u_usec;
	if (v_usec < 0)
		v_usec = -v_usec;
	if (v_usec > (tick >> 1)) {
		if (pps_glitch > MAXGLITCH) {
			pps_glitch = 0;
			pps_tf[2] = u_usec;
			pps_tf[1] = u_usec;
		} else {
			pps_glitch++;
			u_usec = pps_offset;
		}
	} else
		pps_glitch = 0;

	/*
	 * A three-stage median filter is used to help deglitch the pps
	 * time. The median sample becomes the time offset estimate; the
	 * difference between the other two samples becomes the time
	 * dispersion (jitter) estimate.
	 */
	pps_tf[2] = pps_tf[1];
	pps_tf[1] = pps_tf[0];
	pps_tf[0] = u_usec;
	if (pps_tf[0] > pps_tf[1]) {
		if (pps_tf[1] > pps_tf[2]) {
			pps_offset = pps_tf[1];		/* 0 1 2 */
			v_usec = pps_tf[0] - pps_tf[2];
		} else if (pps_tf[2] > pps_tf[0]) {
			pps_offset = pps_tf[0];		/* 2 0 1 */
			v_usec = pps_tf[2] - pps_tf[1];
		} else {
			pps_offset = pps_tf[2];		/* 0 2 1 */
			v_usec = pps_tf[0] - pps_tf[1];
		}
	} else {
		if (pps_tf[1] < pps_tf[2]) {
			pps_offset = pps_tf[1];		/* 2 1 0 */
			v_usec = pps_tf[2] - pps_tf[0];
		} else  if (pps_tf[2] < pps_tf[0]) {
			pps_offset = pps_tf[0];		/* 1 0 2 */
			v_usec = pps_tf[1] - pps_tf[2];
		} else {
			pps_offset = pps_tf[2];		/* 1 2 0 */
			v_usec = pps_tf[1] - pps_tf[0];
		}
	}
	if (v_usec > MAXTIME)
		pps_jitcnt++;
	v_usec = (v_usec << PPS_AVG) - pps_jitter;
	if (v_usec < 0)
		pps_jitter -= -v_usec >> PPS_AVG;
	else
		pps_jitter += v_usec >> PPS_AVG;
	if (pps_jitter > (MAXTIME >> 1))
		time_status |= STA_PPSJITTER;

	/*
	 * During the calibration interval adjust the starting time when
	 * the tick overflows. At the end of the interval compute the
	 * duration of the interval and the difference of the hardware
	 * counters at the beginning and end of the interval. This code
	 * is deliciously complicated by the fact valid differences may
	 * exceed the value of tick when using long calibration
	 * intervals and small ticks. Note that the counter can be
	 * greater than tick if caught at just the wrong instant, but
	 * the values returned and used here are correct.
	 */
	bigtick = (long)tick << SHIFT_USEC;
	pps_usec -= pps_freq;
	if (pps_usec >= bigtick)
		pps_usec -= bigtick;
	if (pps_usec < 0)
		pps_usec += bigtick;
	pps_time.tv_sec++;
	pps_count++;
	if (pps_count < (1 << pps_shift))
		return;
	pps_count = 0;
	pps_calcnt++;
	u_usec = usec << SHIFT_USEC;
	v_usec = pps_usec - u_usec;
	if (v_usec >= bigtick >> 1)
		v_usec -= bigtick;
	if (v_usec < -(bigtick >> 1))
		v_usec += bigtick;
	if (v_usec < 0)
		v_usec = -(-v_usec >> pps_shift);
	else
		v_usec = v_usec >> pps_shift;
	pps_usec = u_usec;
	cal_sec = tvp->tv_sec;
	cal_usec = tvp->tv_usec;
	cal_sec -= pps_time.tv_sec;
	cal_usec -= pps_time.tv_usec;
	if (cal_usec < 0) {
		cal_usec += 1000000;
		cal_sec--;
	}
	pps_time = *tvp;

	/*
	 * Check for lost interrupts, noise, excessive jitter and
	 * excessive frequency error. The number of timer ticks during
	 * the interval may vary +-1 tick. Add to this a margin of one
	 * tick for the PPS signal jitter and maximum frequency
	 * deviation. If the limits are exceeded, the calibration
	 * interval is reset to the minimum and we start over.
	 */
	u_usec = (long)tick << 1;
	if (!((cal_sec == -1 && cal_usec > (1000000 - u_usec))
	    || (cal_sec == 0 && cal_usec < u_usec))
	    || v_usec > time_tolerance || v_usec < -time_tolerance) {
		pps_errcnt++;
		pps_shift = PPS_SHIFT;
		pps_intcnt = 0;
		time_status |= STA_PPSERROR;
		return;
	}

	/*
	 * A three-stage median filter is used to help deglitch the pps
	 * frequency. The median sample becomes the frequency offset
	 * estimate; the difference between the other two samples
	 * becomes the frequency dispersion (stability) estimate.
	 */
	pps_ff[2] = pps_ff[1];
	pps_ff[1] = pps_ff[0];
	pps_ff[0] = v_usec;
	if (pps_ff[0] > pps_ff[1]) {
		if (pps_ff[1] > pps_ff[2]) {
			u_usec = pps_ff[1];		/* 0 1 2 */
			v_usec = pps_ff[0] - pps_ff[2];
		} else if (pps_ff[2] > pps_ff[0]) {
			u_usec = pps_ff[0];		/* 2 0 1 */
			v_usec = pps_ff[2] - pps_ff[1];
		} else {
			u_usec = pps_ff[2];		/* 0 2 1 */
			v_usec = pps_ff[0] - pps_ff[1];
		}
	} else {
		if (pps_ff[1] < pps_ff[2]) {
			u_usec = pps_ff[1];		/* 2 1 0 */
			v_usec = pps_ff[2] - pps_ff[0];
		} else  if (pps_ff[2] < pps_ff[0]) {
			u_usec = pps_ff[0];		/* 1 0 2 */
			v_usec = pps_ff[1] - pps_ff[2];
		} else {
			u_usec = pps_ff[2];		/* 1 2 0 */
			v_usec = pps_ff[1] - pps_ff[0];
		}
	}

	/*
	 * Here the frequency dispersion (stability) is updated. If it
	 * is less than one-fourth the maximum (MAXFREQ), the frequency
	 * offset is updated as well, but clamped to the tolerance. It
	 * will be processed later by the hardclock() routine.
	 */
	v_usec = (v_usec >> 1) - pps_stabil;
	if (v_usec < 0)
		pps_stabil -= -v_usec >> PPS_AVG;
	else
		pps_stabil += v_usec >> PPS_AVG;
	if (pps_stabil > MAXFREQ >> 2) {
		pps_stbcnt++;
		time_status |= STA_PPSWANDER;
		return;
	}
	if (time_status & STA_PPSFREQ) {
		if (u_usec < 0) {
			pps_freq -= -u_usec >> PPS_AVG;
			if (pps_freq < -time_tolerance)
				pps_freq = -time_tolerance;
			u_usec = -u_usec;
		} else {
			pps_freq += u_usec >> PPS_AVG;
			if (pps_freq > time_tolerance)
				pps_freq = time_tolerance;
		}
	}

	/*
	 * Here the calibration interval is adjusted. If the maximum
	 * time difference is greater than tick / 4, reduce the interval
	 * by half. If this is not the case for four consecutive
	 * intervals, double the interval.
	 */
	if (u_usec << pps_shift > bigtick >> 2) {
		pps_intcnt = 0;
		if (pps_shift > PPS_SHIFT)
			pps_shift--;
	} else if (pps_intcnt >= 4) {
		pps_intcnt = 0;
		if (pps_shift < PPS_SHIFTMAX)
			pps_shift++;
	} else
		pps_intcnt++;
}
#endif /* PPS_SYNC */
#endif /* NTP  */

/* timecounter compat functions */
void
nanotime(struct timespec *ts)
{
	struct timeval tv;

	microtime(&tv);
	TIMEVAL_TO_TIMESPEC(&tv, ts);
}
#endif /* !__QNXNTO__ */

void
getbinuptime(struct bintime *bt)
{
	struct timeval tv;

	microtime(&tv);
	timeval2bintime(&tv, bt);
}

#ifndef __QNXNTO__
void
nanouptime(struct timespec *tsp)
{
	int s;

	s = splclock();
	TIMEVAL_TO_TIMESPEC(&mono_time, tsp);
	splx(s);
}

void
getnanouptime(struct timespec *tsp)
{
	int s;

	s = splclock();
	TIMEVAL_TO_TIMESPEC(&mono_time, tsp);
	splx(s);
}

void
getmicrouptime(struct timeval *tvp)
{
	int s;

	s = splclock();
	*tvp = mono_time;
	splx(s);
}

void
getnanotime(struct timespec *tsp)
{
	int s;

	s = splclock();
	TIMEVAL_TO_TIMESPEC(&time, tsp);
	splx(s);
}

void
getmicrotime(struct timeval *tvp)
{
	int s;

	s = splclock();
	*tvp = time;
	splx(s);
}
#endif /* !__QNXNTO__ */
#endif /* !__HAVE_TIMECOUNTER */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/kern_clock.c $ $Rev: 691213 $")
#endif
