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

/*	$NetBSD: eventvar.h,v 1.6 2005/12/11 12:25:20 christos Exp $	*/
/*-
 * Copyright (c) 1999,2000 Jonathan Lemon <jlemon@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/sys/sys/eventvar.h,v 1.4 2000/07/18 19:31:48 jlemon Exp $
 */

#ifndef __EVENTVAR_H_INCLUDED
#define	__EVENTVAR_H_INCLUDED

#ifndef __IOFUNC_H_INCLUDED
#include <sys/iofunc.h>
#endif

#ifdef __QNXNTO__
#define KEVENT_COPIED_OUT (int)(~0u ^ (~0u >> 1))
#endif

#ifndef __QNXNTO__
#define	KQ_NEVENTS	8		/* minimize copy{in,out} calls */
#endif
#define	KQ_EXTENT	256		/* linear growth by this amount */
#define	KFILTER_MAXNAME	256		/* maximum size of a filter name */
#define	KFILTER_EXTENT	8		/* grow user_kfilters by this amt */

#ifdef __QNXNTO__
/*
 * We don't have the concept of a struct filedesc.  We 
 * pull out what need for kqueues and hang it off the 
 * struct kqueue directly (see NetBSD's <sys/filedesc.h>).
 */
struct kq_fdinfo {
	int		fd_knlistsize;	/* size of fd_knlist */
	struct klist	*fd_knlist;	/*
					 * list of attached fd knotes,
					 * indexed by fd number
					 */
	u_long		fd_knhashmask;	/* size of fd_knhash */
	struct klist	*fd_knhash;	/*
					 * hash table for attached
					 * non-fd knotes
					 */
};
#endif

struct kqueue {
	TAILQ_HEAD(kqlist, knote) kq_head;	/* list of pending event */
	int		kq_count;		/* number of pending events */
#ifndef __QNXNTO__
	struct simplelock kq_lock;		/* mutex for queue access */
#endif
	struct selinfo	kq_sel;
#ifndef __QNXNTO__
	struct filedesc *kq_fdp;
#else
	/*
	 * We don't have the concept of a struct filedesc.  Store
	 * the relevant info off this struct proper.  This is safe
	 * because in NetBSD the struct filedesc in question is
	 * per process and kqueue's aren't inherited across fork().
	 */
	int		kq_scoid;   
	struct		kq_fdinfo kq_fd;
#endif
	int		kq_state;
#define	KQ_SLEEP	0x01
#ifndef __QNXNTO__
	struct kevent	kq_kev[KQ_NEVENTS];
#else
	iofunc_notify_t kq_notify[3];
#endif
};

#endif /* !__EVENTVAR_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/eventvar.h $ $Rev: 680336 $")
#endif
