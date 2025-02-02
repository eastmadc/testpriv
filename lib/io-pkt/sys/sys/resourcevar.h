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

/*	$NetBSD: resourcevar.h,v 1.32 2006/07/17 11:38:56 martin Exp $	*/

/*
 * Copyright (c) 1991, 1993
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
 *	@(#)resourcevar.h	8.4 (Berkeley) 1/9/95
 */

#ifndef	_SYS_RESOURCEVAR_H_
#define	_SYS_RESOURCEVAR_H_

#ifdef __QNXNTO__
#include <sys/resource.h> /* The QNX one */
#endif
#include <sys/lock.h>

/*
 * Kernel per-process accounting / statistics
 * (not necessarily resident except when running).
 */
struct pstats {
#define	pstat_startzero	p_ru
	struct	rusage p_ru;		/* stats for this proc */
	struct	rusage p_cru;		/* sum of stats for reaped children */
#define	pstat_endzero	pstat_startcopy

#define	pstat_startcopy	p_timer
	struct	itimerval p_timer[3];	/* virtual-time timers */

	struct uprof {			/* profile arguments */
		caddr_t	pr_base;	/* buffer base */
		size_t  pr_size;	/* buffer size */
		u_long	pr_off;		/* pc offset */
		u_int   pr_scale;	/* pc scaling */
		u_long	pr_addr;	/* temp storage for addr until AST */
		u_long	pr_ticks;	/* temp storage for ticks until AST */
	} p_prof;
#define	pstat_endcopy	p_start
	struct	timeval p_start;	/* starting time */
};

/*
 * Kernel shareable process resource limits.  Because this structure
 * is moderately large but changes infrequently, it is normally
 * shared copy-on-write after forks.  If a group of processes
 * ("threads") share modifications, the PL_SHAREMOD flag is set,
 * and a copy must be made for the child of a new fork that isn't
 * sharing modifications to the limits.
 */
struct plimit {
	struct	rlimit pl_rlimit[RLIM_NLIMITS];
	char	*pl_corename;
#define	PL_SHAREMOD	0x01		/* modifications are shared */
	int	p_lflags;
	int	p_refcnt;		/* number of references */
#ifndef __QNXNTO__
	struct simplelock p_slock;	/* mutex for p_refcnt */
#endif
};

/* add user profiling from AST */
#define	ADDUPROF(p)							\
	do {								\
		addupc_task(p,						\
		    (p)->p_stats->p_prof.pr_addr,			\
		    (p)->p_stats->p_prof.pr_ticks);			\
		(p)->p_stats->p_prof.pr_ticks = 0;			\
	} while (/* CONSTCOND */ 0)

#ifdef _KERNEL
#ifndef __QNXNTO__
/*
 * Structure associated with user caching.
 */
struct uidinfo {
	LIST_ENTRY(uidinfo) ui_hash;
	uid_t	ui_uid;
	long	ui_proccnt;	/* Number of processes */
	long	ui_lockcnt;	/* Number of locks */
	rlim_t	ui_sbsize;	/* socket buffer size */
	struct simplelock ui_slock; /* mutex for everything */

};
#define	UIHASH(uid)	(&uihashtbl[(uid) & uihash])
#define UILOCK(uip, s) \
    do { \
	s = splsoftnet(); \
	simple_lock(&uip->ui_slock); \
    } while (/*CONSTCOND*/0)
#define UIUNLOCK(uip, s) \
    do { \
	simple_unlock(&uip->ui_slock); \
	splx(s); \
    } while (/*CONSTCOND*/0)
#else
struct uidinfo {
	uid_t	ui_uid;
	rlim_t	ui_sbsize;	/* socket buffer size */
};
#endif

extern LIST_HEAD(uihashhead, uidinfo) *uihashtbl;
extern u_long uihash;		/* size of hash table - 1 */
int       chgproccnt(uid_t, int);
int       chgsbsize(struct uidinfo *, u_long *, u_long, rlim_t);
struct uidinfo *uid_find(uid_t);

extern char defcorename[];

extern int security_setidcore_dump;
extern char security_setidcore_path[];
extern uid_t security_setidcore_owner;
extern gid_t security_setidcore_group;
extern mode_t security_setidcore_mode;

void	 addupc_intr(struct proc *, u_long);
void	 addupc_task(struct proc *, u_long, u_int);
void	 calcru(struct proc *, struct timeval *, struct timeval *,
	    struct timeval *);
struct plimit *limcopy(struct plimit *);
void limfree(struct plimit *);
void	ruadd(struct rusage *, struct rusage *);
struct	pstats *pstatscopy(struct pstats *);
void 	pstatsfree(struct pstats *);
extern rlim_t maxdmap;
extern rlim_t maxsmap;
#endif
#endif	/* !_SYS_RESOURCEVAR_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/resourcevar.h $ $Rev: 680336 $")
#endif
