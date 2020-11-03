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

/*	$NetBSD: kernel.h,v 1.25 2006/06/08 17:23:11 drochner Exp $	*/

/*-
 * Copyright (c) 1990, 1993
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
 *	@(#)kernel.h	8.3 (Berkeley) 1/21/94
 */

#ifndef _SYS_KERNEL_H_
#define _SYS_KERNEL_H_

#if defined(_KERNEL) || defined(_STANDALONE)
/* Global variables for the kernel. */

extern long hostid;
extern char hostname[MAXHOSTNAMELEN];
extern int hostnamelen;
extern char domainname[MAXHOSTNAMELEN];
extern int domainnamelen;

extern struct timeval boottime;

extern int rtc_offset;		/* offset of rtc from UTC in minutes */

extern int cold;		/* still working on startup */
extern int tick;		/* usec per tick (1000000 / hz) */
extern int tickadj;		/* "standard" clock skew, us./tick */
extern int hardclock_ticks;	/* # of hardclock ticks */
#ifdef __QNXNTO__
extern int callout_dbg;
extern char *gtimerlib;
#define CALLOUT_DBG_RATELIM 10 /* Seconds to ratelim dbg messages */
#define TIMER_PULSE_PERIOD (50 * 1000000)	/* 5*10^7 ns = 50 ms */
#endif
#ifndef __HAVE_TIMECOUNTER
extern int tickfix;		/* periodic tick adj. tick not integral */
extern int tickfixinterval;	/* interval at which to apply adjustment */
#endif
extern int hz;			/* system clock's frequency */
extern int stathz;		/* statistics clock's frequency */
extern int profhz;		/* profiling clock's frequency */
extern int lbolt;		/* once a second sleep address */

extern int profsrc;		/* profiling source */

#define PROFSRC_CLOCK	0

#endif

#ifdef __QNXNTO__
/*
 * Time domain conversion funcs.
 *
 * Outside of _KERNEL ifdef so netstat can see them
 * as well.
 *
 * To avoid the 64 bit division and multiplication,
 * we approximate with bit shifting when grabbing
 * the nsec counter from the syspage.  This means
 * we end up dividing by 1073741824 (2<<30) rather
 * than 1000000000 which in turn means our mono_time
 * and TIME (time in NetBSD) progress at 93% the rate
 * of real time.  This is usually OK for small timeouts
 * but becomes significant when passing clock realtime
 * values in and out of the stack.
 * 
 * For adding 'small' offsets to monotime or TIME, one
 * can either take the hit or use tireal_ti_small()  which
 * comes closer without 64bit math.
 *
 */

time_t tireal_ti_small(time_t);
time_t ti_tireal_small(time_t);

/* Convert real nsec value to stack domin time_t */
static __inline time_t nsecreal_ti(uint64_t);
static __inline time_t
nsecreal_ti(uint64_t nsec)
{
	return ((time_t)(nsec >> 30));
}

/* Convert stack domain time_t to real nsec value */
static __inline uint64_t ti_nsecreal(time_t);
static __inline uint64_t
ti_nsecreal(time_t ti)
{
	return ((uint64_t)ti << 30);
}

/* Convert real time_t to stack domain time_t */
static __inline time_t tireal_ti(time_t);
static __inline time_t
tireal_ti(time_t ti)
{
	return (nsecreal_ti((uint64_t)ti * (uint64_t)1000000000));
}

/* Convert stack domain time_t to real time_t */
static __inline time_t ti_tireal(time_t);
static __inline time_t
ti_tireal(time_t ti)
{
	return ((time_t)(ti_nsecreal(ti) / (uint64_t)1000000000));
}
#endif

#endif /* _SYS_KERNEL_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/kernel.h $ $Rev: 691213 $")
#endif
