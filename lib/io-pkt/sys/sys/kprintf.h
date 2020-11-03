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

/*	$NetBSD: kprintf.h,v 1.7 2005/12/11 12:25:20 christos Exp $	*/

/*-
 * Copyright (c) 1986, 1988, 1991, 1993
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
 */

#ifndef _SYS_KPRINTF_H_
#define	_SYS_KPRINTF_H_

#ifndef __QNXNTO__
#include "opt_multiprocessor.h"
#include <sys/lock.h>

/*
 * Implementation internals of the kernel printf.  Exposing them here
 * allows other subsystems to implement precisely the printf semantics
 * they need.
 */

#if defined(MULTIPROCESSOR)

extern struct simplelock kprintf_slock;

/*
 * Use cpu_simple_lock() and cpu_simple_unlock().  These are the actual
 * atomic locking operations, and never attempt to print debugging
 * information.
 */
#define	KPRINTF_MUTEX_ENTER(s)						\
do {									\
	(s) = splhigh();						\
	__cpu_simple_lock(&kprintf_slock.lock_data);			\
} while (/*CONSTCOND*/0)

#define	KPRINTF_MUTEX_EXIT(s)						\
do {									\
	__cpu_simple_unlock(&kprintf_slock.lock_data);			\
	splx((s));							\
} while (/*CONSTCOND*/0)

#else

#define	KPRINTF_MUTEX_ENTER(s)	(s) = splhigh()
#define	KPRINTF_MUTEX_EXIT(s)	splx((s))

#endif /* MULTIPROCESSOR */
#else /* __QNXNTO__ */
#define	KPRINTF_MUTEX_ENTER(s)	((void)0)
#define	KPRINTF_MUTEX_EXIT(s)	((void)0)
#endif

/* flags for kprintf */
#define	TOCONS		0x0001	/* to the console */
#define	TOTTY		0x0002	/* to the process' tty */
#define	TOLOG		0x0004	/* to the kernel message buffer */
#define	TOBUFONLY	0x0008	/* to the buffer (only) [for snprintf] */
#define	TODDB		0x0010	/* to ddb console */
#define	NOLOCK		0x1000	/* don't acquire a tty lock */

/*
 * NOTE: the kprintf mutex must be held when these functions are called!
 */
int	kprintf(const char *, int, void *, char *, _BSD_VA_LIST_);
void	klogpri(int);

#endif /* _SYS_KPRINTF_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/kprintf.h $ $Rev: 680336 $")
#endif
