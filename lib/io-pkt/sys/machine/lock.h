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

/*	$NetBSD: lock.h,v 1.5 2003/10/27 13:43:48 junyoung Exp $	*/

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
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
 * Machine-dependent spin lock operations.
 */

#ifndef _I386_LOCK_H_
#define	_I386_LOCK_H_

#ifndef __QNXNTO__
#if defined(_KERNEL_OPT)
#include "opt_lockdebug.h"
#endif

#include <machine/cpufunc.h>

/*
 * compiler barrier: prevent reordering of instructions.
 * XXX something similar will move to <sys/cdefs.h>
 * or thereabouts.
 * This prevents the compiler from reordering code around
 * this "instruction", acting as a sequence point for code generation.
 */

#define __lockbarrier() __asm __volatile("": : :"memory")

#ifdef LOCKDEBUG

extern void __cpu_simple_lock_init(__cpu_simple_lock_t *);
extern void __cpu_simple_lock(__cpu_simple_lock_t *);
extern int __cpu_simple_lock_try(__cpu_simple_lock_t *);
extern void __cpu_simple_unlock(__cpu_simple_lock_t *);

#else

#include <machine/atomic.h>

static __inline void __cpu_simple_lock_init(__cpu_simple_lock_t *)
	__attribute__((__unused__));
static __inline void __cpu_simple_lock(__cpu_simple_lock_t *)
	__attribute__((__unused__));
static __inline int __cpu_simple_lock_try(__cpu_simple_lock_t *)
	__attribute__((__unused__));
static __inline void __cpu_simple_unlock(__cpu_simple_lock_t *)
	__attribute__((__unused__));

static __inline void
__cpu_simple_lock_init(__cpu_simple_lock_t *lockp)
{

	*lockp = __SIMPLELOCK_UNLOCKED;
	__lockbarrier();
}

#if !defined(__QNXNTO__)
static __inline void
__cpu_simple_lock(__cpu_simple_lock_t *lockp)
{

	while (x86_atomic_testset_i(lockp, __SIMPLELOCK_LOCKED)
	    != __SIMPLELOCK_UNLOCKED)
		x86_pause();
	__lockbarrier();
}

static __inline int
__cpu_simple_lock_try(__cpu_simple_lock_t *lockp)
{
	int r = (x86_atomic_testset_i(lockp, __SIMPLELOCK_LOCKED)
	    == __SIMPLELOCK_UNLOCKED);

	__lockbarrier();

	return (r);
}

static __inline void
__cpu_simple_unlock(__cpu_simple_lock_t *lockp)
{

	__lockbarrier();
	*lockp = __SIMPLELOCK_UNLOCKED;
}
#else
#if 0
static __inline void
__cpu_simple_lock(__cpu_simple_lock_t *alp)
{

	while (_smp_cmpxchg((unsigned *)&alp, (unsigned)__SIMPLELOCK_UNLOCKED, (unsigned)__SIMPLELOCK_LOCKED) != __SIMPLELOCK_UNLOCKED);
}

static __inline int
__cpu_simple_lock_try(__cpu_simple_lock_t *alp)
{

	return (_smp_cmpxchg((unsigned *)&alp, (unsigned)__SIMPLELOCK_UNLOCKED, (unsigned)__SIMPLELOCK_LOCKED) != __SIMPLELOCK_UNLOCKED);
}

void
__cpu_simple_unlock(__cpu_simple_lock_t *alp)
{

	*alp = __SIMPLELOCK_UNLOCKED;
}
#endif
#endif /* __QNXNTO__ */

#endif /* !LOCKDEBUG */

#ifdef _KERNEL
#define	SPINLOCK_SPIN_HOOK	x86_pause()
#endif
#endif

#endif /* _I386_LOCK_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/machine/lock.h $ $Rev: 680336 $")
#endif
