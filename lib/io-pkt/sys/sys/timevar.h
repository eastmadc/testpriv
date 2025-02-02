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

/*	$NetBSD: timevar.h,v 1.6 2006/07/23 22:06:14 ad Exp $	*/

/*
 *  Copyright (c) 2005 The NetBSD Foundation.
 *  All rights reserved.
 *
 *  This code is derived from software contributed to the NetBSD Foundation
 *   by Quentin Garnier.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this software
 *     must display the following acknowledgement:
 *         This product includes software developed by the NetBSD
 *         Foundation, Inc. and its contributors.
 *  4. Neither the name of The NetBSD Foundation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 *  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 *  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

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

#ifndef _SYS_TIMEVAR_H_
#define _SYS_TIMEVAR_H_

#include <sys/callout.h>
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/systm.h>

#ifndef __QNXNTO__
/*
 * Structure used to manage timers in a process.
 */
struct 	ptimer {
	union {
		struct	callout	pt_ch;
		struct {
			LIST_ENTRY(ptimer)	pt_list;
			int	pt_active;
		} pt_nonreal;
	} pt_data;
	struct	sigevent pt_ev;
	struct	itimerval pt_time;
	struct	ksiginfo pt_info;
	int	pt_overruns;	/* Overruns currently accumulating */
	int	pt_poverruns;	/* Overruns associated w/ a delivery */
	int	pt_type;
	int	pt_entry;
	struct proc *pt_proc;
};

#define pt_ch	pt_data.pt_ch
#define pt_list	pt_data.pt_nonreal.pt_list
#define pt_active	pt_data.pt_nonreal.pt_active

#define	TIMER_MAX	32	/* See ptimers->pts_fired if you enlarge this */
#define	TIMERS_ALL	0
#define	TIMERS_POSIX	1

LIST_HEAD(ptlist, ptimer);

struct	ptimers {
	struct ptlist pts_virtual;
	struct ptlist pts_prof;
	struct ptimer *pts_timers[TIMER_MAX];
	int pts_fired;
};

/*
 * Functions for looking at our clock: [get]{bin,nano,micro}[up]time()
 *
 * Functions without the "get" prefix returns the best timestamp
 * we can produce in the given format.
 *
 * "bin"   == struct bintime  == seconds + 64 bit fraction of seconds.
 * "nano"  == struct timespec == seconds + nanoseconds.
 * "micro" == struct timeval  == seconds + microseconds.
 *              
 * Functions containing "up" returns time relative to boot and
 * should be used for calculating time intervals.
 *
 * Functions without "up" returns GMT time.
 *
 * Functions with the "get" prefix returns a less precise result
 * much faster than the functions without "get" prefix and should
 * be used where a precision of 10 msec is acceptable or where
 * performance is priority. (NB: "precision", _not_ "resolution" !) 
 * 
 */
#endif

#ifdef __HAVE_TIMECOUNTER
void	binuptime(struct bintime *);
void	nanouptime(struct timespec *);
void	microuptime(struct timeval *);

void	bintime(struct bintime *);
void	nanotime(struct timespec *);
void	microtime(struct timeval *);

void	getbinuptime(struct bintime *);
void	getnanouptime(struct timespec *);
void	getmicrouptime(struct timeval *);

void	getbintime(struct bintime *);
void	getnanotime(struct timespec *);
void	getmicrotime(struct timeval *);
#else /* !__HAVE_TIMECOUNTER */
/* timecounter compat functions */
void	microtime(struct timeval *);
void	nanotime(struct timespec *);

void	nanouptime(struct timespec *);
void	getbinuptime(struct bintime *);
void	getnanouptime(struct timespec *);
void	getmicrouptime(struct timeval *);

void	getnanotime(struct timespec *);
void	getmicrotime(struct timeval *);
#endif /* !__HAVE_TIMECOUNTER */

#ifdef __QNXNTO__
void	microtime_accurate(struct timeval *);
#endif

/* Other functions */
int	adjtime1(const struct timeval *, struct timeval *, struct proc *);
#ifndef __QNXNTO__
int	clock_settime1(struct proc *, clockid_t, const struct timespec *);
int	dogetitimer(struct proc *, int, struct itimerval *);
int	dosetitimer(struct proc *, int, struct itimerval *);
int	dotimer_gettime(int, struct proc *, struct itimerspec *);
int	dotimer_settime(int, struct itimerspec *, struct itimerspec *, int,
	    struct proc *);
#endif
int	hzto(struct timeval *);
void	inittimecounter(void);
#ifndef __QNXNTO__
int	itimerdecr(struct ptimer *, int);
void	itimerfire(struct ptimer *);
#endif
int	itimerfix(struct timeval *tv);
int	ppsratecheck(struct timeval *, int *, int);
int	ratecheck(struct timeval *, const struct timeval *);
#ifndef __QNXNTO__
void	realtimerexpire(void *);
int	settime(struct proc *p, struct timespec *);
int	settimeofday1(const struct timeval *, const struct timezone *,
	    struct proc *);
int	timer_create1(timer_t *, clockid_t, struct sigevent *, copyin_t,
	    struct lwp *);
void	timer_gettime(struct ptimer *, struct itimerval *);
void	timer_settime(struct ptimer *);
void	timers_alloc(struct proc *);
void	timers_free(struct proc *, int);
#endif
int	tstohz(struct timespec *);
int	tvtohz(struct timeval *);
int	inittimeleft(struct timeval *, struct timeval *);
int	gettimeleft(struct timeval *, struct timeval *);

#ifdef __HAVE_TIMECOUNTER
extern time_t time_second;	/* current second in the epoch */
extern time_t time_uptime;	/* system uptime in seconds */
#else /* !__HAVE_TIMECOUNTER */
extern volatile struct timeval mono_time;
#ifndef __QNXNTO__
extern volatile struct timeval time;
#define	time_second	time.tv_sec
#else
extern volatile struct timeval TIME;
#define	time_second	TIME.tv_sec
#endif
#define	time_uptime	mono_time.tv_sec
#endif /* !__HAVE_TIMECOUNTER */

#endif /* !_SYS_TIMEVAR_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/timevar.h $ $Rev: 738885 $")
#endif
