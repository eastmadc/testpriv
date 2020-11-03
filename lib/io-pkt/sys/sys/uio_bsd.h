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



/*	$NetBSD: uio.h,v 1.34 2006/03/01 12:38:32 yamt Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993, 1994
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
 *	@(#)uio.h	8.5 (Berkeley) 2/22/94
 */

#ifndef _SYS_UIO_H_
#define	_SYS_UIO_H_

#ifdef _KERNEL
#ifndef __UIO_EXPOSE
#define __UIO_EXPOSE
#endif
#endif

#ifdef __QNXNTO__
#include <sys/platform.h>
#include <sys/uio.h> /* The QNX one */
#else
#include <machine/ansi.h>
#include <sys/featuretest.h>

#ifdef	_BSD_SIZE_T_
typedef	_BSD_SIZE_T_	size_t;
#undef	_BSD_SIZE_T_
#endif

#ifdef	_BSD_SSIZE_T_
typedef	_BSD_SSIZE_T_	ssize_t;
#undef	_BSD_SSIZE_T_
#endif

struct iovec {
	void	*iov_base;	/* Base address. */
	size_t	 iov_len;	/* Length. */
};
#endif /* !__QNXNTO__ */

#if defined(_NETBSD_SOURCE) || (defined(__QNXNTO__) && defined(__EXT_BSD))
#ifndef __QNXNTO__
#include <sys/ansi.h>

#ifndef	off_t
typedef	__off_t		off_t;	/* file offset */
#define	off_t		__off_t
#endif
#endif /* __QNXNTO__ */

enum	uio_rw { UIO_READ, UIO_WRITE };

/* Segment flag values. */
enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE		/* from system space */
};

#ifdef __UIO_EXPOSE

struct uio {
	struct	iovec *uio_iov;	/* pointer to array of iovecs */
	int	uio_iovcnt;	/* number of iovecs in array */
	off_t	uio_offset;	/* offset into file this uio corresponds to */
	size_t	uio_resid;	/* residual i/o count */
	enum	uio_rw uio_rw;	/* see above */
	struct	vmspace *uio_vmspace;
};
#define	UIO_SETUP_SYSSPACE(uio)	uio_setup_sysspace(uio)

#endif /* __UIO_EXPOSE */
#ifndef __QNXNTO__

/*
 * Limits
 */
/* Deprecated: use IOV_MAX from <limits.h> instead. */
#define UIO_MAXIOV	1024		/* max 1K of iov's */
#endif /* !__QNXNTO__ */
#endif /* _NETBSD_SOURCE || (__QNXNTO__ && __EXT_BSD) */

#ifdef _KERNEL
#include <sys/mallocvar.h>

MALLOC_DECLARE(M_IOV);

#ifndef __QNXNTO__
#define UIO_SMALLIOV	8		/* 8 on stack, else malloc */
#endif

void uio_setup_sysspace(struct uio *);
#endif

#ifndef	_KERNEL
#include <sys/cdefs.h>

__BEGIN_DECLS
#if defined(_NETBSD_SOURCE) || (defined(__QNXNTO__) && defined(__EXT_BSD))
ssize_t preadv(int, const struct iovec *, int, off_t);
ssize_t pwritev(int, const struct iovec *, int, off_t);
#endif /* _NETBSD_SOURCE || (__QNXNTO__ && __EXT_BSD) */
ssize_t	readv(int, const struct iovec *, int);
ssize_t	writev(int, const struct iovec *, int);
__END_DECLS
#else
int ureadc(int, struct uio *);
#endif /* !_KERNEL */

#endif /* !_SYS_UIO_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/uio_bsd.h $ $Rev: 680336 $")
#endif
