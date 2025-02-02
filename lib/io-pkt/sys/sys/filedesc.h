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

/*	$NetBSD: filedesc.h,v 1.36 2006/07/23 22:06:14 ad Exp $	*/

/*
 * Copyright (c) 1990, 1993
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
 *	@(#)filedesc.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_FILEDESC_H_
#define	_SYS_FILEDESC_H_

#include <sys/lock.h>

/*
 * This structure is used for the management of descriptors.  It may be
 * shared by multiple processes.
 *
 * A process is initially started out with NDFILE descriptors stored within
 * this structure, selected to be enough for typical applications based on
 * the historical limit of 20 open files (and the usage of descriptors by
 * shells).  If these descriptors are exhausted, a larger descriptor table
 * may be allocated, up to a process' resource limit; the internal arrays
 * are then unused.  The initial expansion is set to NDEXTENT; each time
 * it runs out, it is doubled until the resource limit is reached. NDEXTENT
 * should be selected to be the biggest multiple of OFILESIZE (see below)
 * that will fit in a power-of-two sized piece of memory.
 */
#define	NDFILE		20
#define	NDEXTENT	50		/* 250 bytes in 256-byte alloc */
#define	NDENTRIES	32		/* 32 fds per entry */
#define	NDENTRYMASK	(NDENTRIES - 1)
#define	NDENTRYSHIFT	5		/* bits per entry */
#define	NDLOSLOTS(x)	(((x) + NDENTRIES - 1) >> NDENTRYSHIFT)
#define	NDHISLOTS(x)	((NDLOSLOTS(x) + NDENTRIES - 1) >> NDENTRYSHIFT)

#ifndef __QNXNTO__
struct filedesc {
	struct file	**fd_ofiles;	/* file structures for open files */
	char		*fd_ofileflags;	/* per-process open file flags */
	int		fd_nfiles;	/* number of open files allocated */
	uint32_t	*fd_himap;	/* each bit points to 32 fds */
	uint32_t	*fd_lomap;	/* bitmap of free fds */
	int		fd_lastfile;	/* high-water mark of fd_ofiles */
	int		fd_freefile;	/* approx. next free file */
	int		fd_refcnt;	/* reference count */

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
	struct simplelock fd_slock;	/* mutex. Note on locking order:
					 * acquire this lock first when
					 * also locking an associated
					 * `struct file' lock.
					 */
};
#else
/*
 * We pull out what we need for kqueues and put
 * it in <sys/eventvar.h> directly.
 */
#endif

#ifndef __QNXNTO__
struct cwdinfo {
	struct vnode	*cwdi_cdir;	/* current directory */
	struct vnode	*cwdi_rdir;	/* root directory */
	u_short		cwdi_cmask;	/* mask for file creation */
	u_short		cwdi_refcnt;	/* reference count */
	struct simplelock cwdi_slock;	/* mutex */
};


/*
 * Basic allocation of descriptors:
 * one of the above, plus arrays for NDFILE descriptors.
 */
struct filedesc0 {
	struct filedesc	fd_fd;
	/*
	 * These arrays are used when the number of open files is
	 * <= NDFILE, and are then pointed to by the pointers above.
	 */
	struct file	*fd_dfiles[NDFILE];
	char		fd_dfileflags[NDFILE];
	/*
	 * These arrays are used when the number of open files is
	 * <= 1024, and are then pointed to by the pointers above.
	 */
	uint32_t	fd_dhimap[NDENTRIES >> NDENTRYSHIFT];
	uint32_t	fd_dlomap[NDENTRIES];
};
#endif

/*
 * Per-process open flags.
 */
#define	UF_EXCLOSE 	0x01		/* auto-close on exec */

/*
 * Storage required per open file descriptor.
 */
#define	OFILESIZE (sizeof(struct file *) + sizeof(char))

#ifdef _KERNEL
/*
 * Kernel global variables and routines.
 */
#ifndef __QNXNTO__
int	dupfdopen(struct lwp *, int, int, int, int);
int	fdalloc(struct proc *, int, int *);
void	fdexpand(struct proc *);
int	falloc(struct lwp *, struct file **, int *);
#else
int	falloc(struct lwp *, struct file **);
#endif
void	ffree(struct file *);
#ifndef __QNXNTO__
struct filedesc *fdcopy(struct proc *);
struct filedesc *fdinit(struct proc *);
void	fdshare(struct proc *, struct proc *);
void	fdunshare(struct lwp *);
void	fdinit1(struct filedesc0 *);
void	fdclear(struct lwp *);
void	fdfree(struct lwp *);
void	fdremove(struct filedesc *, int);
#endif
int	fdrelease(struct lwp *, int);
#ifndef __QNXNTO__
void	fdcloseexec(struct lwp *);
int	fdcheckstd(struct lwp *);

struct file *fd_getfile(struct filedesc *, int);

struct cwdinfo *cwdinit(struct proc *);
void	cwdshare(struct proc *, struct proc *);
void	cwdunshare(struct proc *);
void	cwdfree(struct cwdinfo *);
#define GETCWD_CHECK_ACCESS 0x0001
int	getcwd_common(struct vnode *, struct vnode *, char **, char *, int,
    int, struct lwp *);
#endif

int	closef(struct file *, struct lwp *);
#ifndef __QNXNTO__
int	getsock(struct filedesc *, int, struct file **);
#else
int	getsock(struct lwp *, int, struct file **);
#define getsock(a, b, c) getsock(&a, b, c)
#endif
#endif /* _KERNEL */

#endif /* !_SYS_FILEDESC_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/filedesc.h $ $Rev: 724903 $")
#endif
