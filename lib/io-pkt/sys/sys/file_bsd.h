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

/*	$NetBSD: file.h,v 1.56 2006/05/14 21:38:18 elad Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)file.h	8.3 (Berkeley) 1/9/95
 */

#ifndef _SYS_FILE_H_
#define	_SYS_FILE_H_

#include <sys/fcntl.h>
#include <sys/unistd.h>

#ifdef _KERNEL
#include <sys/mallocvar.h>
#include <sys/queue.h>
#include <sys/lock.h>

MALLOC_DECLARE(M_FILE);
MALLOC_DECLARE(M_IOCTLOPS);

struct proc;
struct lwp;
struct uio;
struct iovec;
struct stat;
struct knote;

/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 */
struct file {
	LIST_ENTRY(file) f_list;	/* list of active files */
	int		f_flag;		/* see fcntl.h */
	int		f_iflags;	/* internal flags; FIF_* */
	int		f_advice;	/* access pattern hint; UVM_ADV_* */
#define	DTYPE_VNODE	1		/* file */
#define	DTYPE_SOCKET	2		/* communications endpoint */
#define	DTYPE_PIPE	3		/* pipe */
#define	DTYPE_KQUEUE	4		/* event queue */
#define	DTYPE_MISC	5		/* misc file descriptor type */
#define	DTYPE_CRYPTO	6		/* crypto */
#define DTYPE_NAMES \
    "0", "file", "socket", "pipe", "kqueue", "misc", "crypto"
	int		f_type;		/* descriptor type */
	u_int		f_count;	/* reference count */
	u_int		f_msgcount;	/* references from message queue */
	int		f_usecount;	/* number active users */
	kauth_cred_t 	f_cred;		/* creds associated with descriptor */
	const struct fileops {
		int	(*fo_read)	(struct file *, off_t *, struct uio *,
					    kauth_cred_t, int);
		int	(*fo_write)	(struct file *, off_t *, struct uio *,
					    kauth_cred_t, int);
		int	(*fo_ioctl)	(struct file *, u_long, void *,
					    struct lwp *);
		int	(*fo_fcntl)	(struct file *, u_int, void *,
					    struct lwp *);
		int	(*fo_poll)	(struct file *, int, struct lwp *);
		int	(*fo_stat)	(struct file *, struct stat *,
					    struct lwp *);
		int	(*fo_close)	(struct file *, struct lwp *);
		int	(*fo_kqfilter)	(struct file *, struct knote *);
#ifdef __QNXNTO__
		/* fo_close above is last close where below is close_dup */
		int	(*fo_close1)	(struct file *, struct lwp *);
#endif
	} *f_ops;
	off_t		f_offset;
	void		*f_data;	/* descriptor data, e.g. vnode/socket */
	struct simplelock f_slock;
#ifdef __QNXNTO__
	struct msg_open_info *f_path_info;
	struct lwp *f_slpq;
	time_t f_atime;
	time_t f_ctime;
	time_t f_mtime;
	int    f_timeflags;
#endif
};

#define	FIF_WANTCLOSE		0x01	/* a close is waiting for usecount */
#define	FIF_LARVAL		0x02	/* not fully constructed; don't use */

#define	FILE_IS_USABLE(fp)	(((fp)->f_iflags &			\
				  (FIF_WANTCLOSE|FIF_LARVAL)) == 0)

#define	FILE_SET_MATURE(fp)						\
do {									\
	(fp)->f_iflags &= ~FIF_LARVAL;					\
} while (/*CONSTCOND*/0)

#ifdef DIAGNOSTIC
#define	FILE_USE_CHECK(fp, str)						\
do {									\
	if ((fp)->f_usecount < 0)					\
		panic(str);						\
} while (/* CONSTCOND */ 0)
#else
#define	FILE_USE_CHECK(fp, str)		/* nothing */
#endif

/*
 * FILE_USE() must be called with the file lock held.
 * (Typical usage is: `fp = fd_getfile(..); FILE_USE(fp);'
 * and fd_getfile() returns the file locked)
 */
#define	FILE_USE(fp)							\
do {									\
	(fp)->f_usecount++;						\
	FILE_USE_CHECK((fp), "f_usecount overflow");			\
	simple_unlock(&(fp)->f_slock);					\
} while (/* CONSTCOND */ 0)

#ifndef __QNXNTO__
#define	FILE_UNUSE_WLOCK(fp, l, havelock)				\
do {									\
	if (!(havelock))						\
		simple_lock(&(fp)->f_slock);				\
	if ((fp)->f_iflags & FIF_WANTCLOSE) {				\
		simple_unlock(&(fp)->f_slock);				\
		/* Will drop usecount */				\
		(void) closef((fp), (l));				\
		break;							\
	} else {							\
		(fp)->f_usecount--;					\
		FILE_USE_CHECK((fp), "f_usecount underflow");		\
	}								\
	simple_unlock(&(fp)->f_slock);					\
} while (/* CONSTCOND */ 0)
#else
/* We never set FIF_WANTCLOSE and our simple locks currently do nothing */
#ifdef MULTIPROCESSOR
/* simple_lock isn't enabled in <sys/lock.h> */
#error "FILE_UNUSE_WLOCK doesn't lock"
#endif
#define	FILE_UNUSE_WLOCK(fp, l, havelock)				\
do {									\
	(fp)->f_usecount--;						\
	FILE_USE_CHECK((fp), "f_usecount underflow");			\
} while (/* CONSTCOND */ 0)
#endif
#define	FILE_UNUSE(fp, l)		FILE_UNUSE_WLOCK(fp, l, 0)
#define	FILE_UNUSE_HAVELOCK(fp, l)	FILE_UNUSE_WLOCK(fp, l, 1)

/*
 * Flags for fo_read and fo_write.
 */
#define	FOF_UPDATE_OFFSET	0x01	/* update the file offset */

LIST_HEAD(filelist, file);
extern struct filelist	filehead;	/* head of list of open files */
extern int		maxfiles;	/* kernel limit on # of open files */
extern int		nfiles;		/* actual number of open files */

extern const struct fileops vnops;	/* vnode operations for files */

int	dofileread(struct lwp *, int, struct file *, void *, size_t,
	    off_t *, int, register_t *);
int	dofilewrite(struct lwp *, int, struct file *, const void *,
	    size_t, off_t *, int, register_t *);

int	dofilereadv(struct lwp *, int, struct file *,
	    const struct iovec *, int, off_t *, int, register_t *);
int	dofilewritev(struct lwp *, int, struct file *,
	    const struct iovec *, int, off_t *, int, register_t *);

#ifndef __QNXNTO__
int	fsetown(struct proc *, pid_t *, int, const void *);
#else
int	fsetown(struct proc *, pid_t *, int *, int, const void *);
#endif
int	fgetown(struct proc *, pid_t, int, void *);
void	fownsignal(pid_t, int, int, int, void *);

#ifndef __QNXNTO__
int	fdclone(struct lwp *, struct file *, int, int, const struct fileops *,
    void *);
#endif

/* Commonly used fileops */
int	fnullop_fcntl(struct file *, u_int, void *, struct lwp *);
int	fnullop_poll(struct file *, int, struct lwp *);
int	fnullop_kqfilter(struct file *, struct knote *);
#ifdef __QNXNTO__
int	fnullop_stat(struct file *, struct stat *, struct lwp *);
int	fnullop_read(struct file *, off_t *, struct uio *, kauth_cred_t, int);
int	fnullop_write(struct file *, off_t *, struct uio *, kauth_cred_t, int);
#endif
int	fbadop_stat(struct file *, struct stat *, struct lwp *);

#endif /* _KERNEL */

#endif /* !__FILE_BSD_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/file_bsd.h $ $Rev: 680336 $")
#endif
