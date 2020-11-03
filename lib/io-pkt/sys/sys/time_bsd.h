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



/*	$NetBSD: time.h,v 1.56 2006/06/18 21:09:24 uwe Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)time.h	8.5 (Berkeley) 5/4/95
 */

#ifndef __TIME_BSD_H_INCLUDED
#define	__TIME_BSD_H_INCLUDED

#include <sys/featuretest.h>
#ifndef __QNXNTO__
#include <sys/types.h>
#ifdef _KERNEL
#include <sys/callout.h>
#include <sys/signal.h>
#include <sys/queue.h>
#endif
#else
#include <sys/types_bsd.h>
#include <sys/time.h>  /* The QNX one */
#include <time.h>  /* The QNX one */
#endif

#ifndef __QNXNTO__
/*
 * Structure returned by gettimeofday(2) system call,
 * and used in other calls.
 */
struct timeval {
	long    tv_sec;		/* seconds */
	long    tv_usec;	/* and microseconds */
};

/*
 * Structure defined by POSIX.1b to be like a timeval.
 */
struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};
#endif

#if defined(_NETBSD_SOURCE) || (defined(__QNXNTO__) && defined(__EXT_BSD))
#define	TIMEVAL_TO_TIMESPEC(tv, ts) do {				\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
} while (/*CONSTCOND*/0)
#define	TIMESPEC_TO_TIMEVAL(tv, ts) do {				\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
} while (/*CONSTCOND*/0)

#ifndef __QNXNTO__
/*
 * Note: timezone is obsolete. All timezone handling is now in
 * userland. Its just here for back compatibility.
 */
struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

/* Operations on timevals. */
#define	timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0
#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp)						\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define	timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#endif /* !__QNXNTO__ */

#ifdef _KERNEL
struct bintime {
	time_t	sec;
	uint64_t frac;
};

static __inline void
bintime_addx(struct bintime *bt, uint64_t x)
{
	uint64_t u;

	u = bt->frac;
	bt->frac += x;
	if (u > bt->frac)
		bt->sec++;
}

static __inline void
bintime_add(struct bintime *bt, const struct bintime *bt2)
{
	uint64_t u;

	u = bt->frac;
	bt->frac += bt2->frac;
	if (u > bt->frac)
		bt->sec++;
	bt->sec += bt2->sec;
}

static __inline void
bintime_sub(struct bintime *bt, const struct bintime *bt2)
{
	uint64_t u;

	u = bt->frac;
	bt->frac -= bt2->frac;
	if (u < bt->frac)
		bt->sec--;
	bt->sec -= bt2->sec;
}

/*-
 * Background information:
 *
 * When converting between timestamps on parallel timescales of differing
 * resolutions it is historical and scientific practice to round down rather
 * than doing 4/5 rounding.
 *
 *   The date changes at midnight, not at noon.
 *
 *   Even at 15:59:59.999999999 it's not four'o'clock.
 *
 *   time_second ticks after N.999999999 not after N.4999999999
 */

static __inline void
bintime2timespec(const struct bintime *bt, struct timespec *ts)
{

	ts->tv_sec = (/* XXX NetBSD not SUS compliant - MUST FIX */time_t)bt->sec;
	ts->tv_nsec =
	    (long)(((uint64_t)1000000000 * (uint32_t)(bt->frac >> 32)) >> 32);
}

static __inline void
timespec2bintime(const struct timespec *ts, struct bintime *bt)
{

	bt->sec = ts->tv_sec;
	/* 18446744073 = int(2^64 / 1000000000) */
	bt->frac = ts->tv_nsec * (uint64_t)18446744073LL; 
}

static __inline void
bintime2timeval(const struct bintime *bt, struct timeval *tv)
{

	tv->tv_sec = bt->sec;
	tv->tv_usec =
	    (long)(((uint64_t)1000000 * (uint32_t)(bt->frac >> 32)) >> 32);
}

static __inline void
timeval2bintime(const struct timeval *tv, struct bintime *bt)
{

	bt->sec = (/* XXX NetBSD not SUS compliant - MUST FIX */time_t)tv->tv_sec;
	/* 18446744073709 = int(2^64 / 1000000) */
	bt->frac = tv->tv_usec * (uint64_t)18446744073709LL;
}
#endif /* _KERNEL */

/* Operations on timespecs. */
#define	timespecclear(tsp)	(tsp)->tv_sec = (time_t)((tsp)->tv_nsec = 0L)
#define	timespecisset(tsp)	((tsp)->tv_sec || (tsp)->tv_nsec)
#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#define	timespecadd(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)
#endif /* _NETBSD_SOURCE || (__QNXNTO__ && __EXT_BSD) */

#ifndef __QNXNTO__
/*
 * Names of the interval timers, and structure
 * defining a timer setting.
 */
#define	ITIMER_REAL	0
#define	ITIMER_VIRTUAL	1
#define	ITIMER_PROF	2

struct	itimerval {
	struct	timeval it_interval;	/* timer interval */
	struct	timeval it_value;	/* current value */
};

/*
 * Structure defined by POSIX.1b to be like a itimerval, but with
 * timespecs. Used in the timer_*() system calls.
 */
struct	itimerspec {
	struct	timespec it_interval;
	struct	timespec it_value;
};

#define	CLOCK_REALTIME	0
#define	CLOCK_VIRTUAL	1
#define	CLOCK_PROF	2
#define	CLOCK_MONOTONIC	3

#define	TIMER_RELTIME	0x0	/* relative timer */
#define	TIMER_ABSTIME	0x1	/* absolute timer */
#endif

#ifdef _KERNEL
#include <sys/timevar.h>
#ifdef __QNXNTO__
/*
 * 100 is the default value of HZ (hz) in NetBSD (10ms).
 * There appear to actually be some timers that want this granularity
 * (eg TBF_REPROCESS in netinet/ip_mroute.c) so good to have
 * something in this range.  I think it could be overkill on some
 * processors to have the kernel hit us with a proper timing pulse
 * this frequently so my thoughts right now are to make this an
 * _average_ frequency at which softclock() is called.  The heavier
 * load we are under, the closer it will be.  If we are quiescent
 * and only getting lower frequency timer pulses, it will only be
 * close in the average.
 */

/*
 * We actually choose 119 because we drive everything of the ns
 * clock of the (QNX) kernel.  Using the shift operator to keep
 * things fast (bit 23 increments every 2^23 ns):
 *
 * 2^23ns = 2^23ns * (1000ms / 10^9ns) = 8.39ms = 119.209Hz
 */
#define NTO_TSHIFT 23
#define NTO_HZ 119
#define NTO_mHZ 119209

void	init_time(void);
uint64_t currtime_nto(int);
#endif

#else /* !_KERNEL */
#ifndef __QNXNTO__
#ifndef _STANDALONE
#if (_POSIX_C_SOURCE - 0) >= 200112L || \
    (defined(_XOPEN_SOURCE) && defined(_XOPEN_SOURCE_EXTENDED)) || \
    (_XOPEN_SOURCE - 0) >= 500 || defined(_NETBSD_SOURCE)
#include <sys/select.h>
#endif

#include <sys/cdefs.h>
#include <time.h>

__BEGIN_DECLS
#if (_POSIX_C_SOURCE - 0) >= 200112L || \
    defined(_XOPEN_SOURCE) || defined(_NETBSD_SOURCE)
int	getitimer(int, struct itimerval *);
int	gettimeofday(struct timeval * __restrict, void * __restrict);
int	setitimer(int, const struct itimerval * __restrict,
	    struct itimerval * __restrict);
int	utimes(const char *, const struct timeval [2]);
#endif /* _POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE || _NETBSD_SOURCE */

#if defined(_NETBSD_SOURCE)
int	adjtime(const struct timeval *, struct timeval *);
int	futimes(int, const struct timeval [2]);
int	lutimes(const char *, const struct timeval [2]);
int	settimeofday(const struct timeval * __restrict,
	    const void * __restrict);
#endif /* _NETBSD_SOURCE */
__END_DECLS

#endif	/* !_STANDALONE */
#endif /* !__QNXNTO__ */
#endif /* !_KERNEL */
#endif /* !_SYS_TIME_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/time_bsd.h $ $Rev: 812397 $")
#endif
