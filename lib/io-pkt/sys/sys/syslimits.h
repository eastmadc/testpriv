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



/*	$NetBSD: syslimits.h,v 1.23 2005/12/11 12:25:21 christos Exp $	*/

/*
 * Copyright (c) 1988, 1993
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
 *	@(#)syslimits.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_SYSLIMITS_H_
#define _SYS_SYSLIMITS_H_

#ifdef __QNXNTO__
#include <limits.h> /* The QNX one */
#endif

#include <sys/featuretest.h>

#if defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE) || \
    defined(_NETBSD_SOURCE) || (defined(__QNXNTO__) && defined(__EXT_BSD))
#ifndef __QNXNTO__
#define	ARG_MAX		 (256 * 1024)	/* max bytes for an exec function */
#endif
#ifndef CHILD_MAX
#define	CHILD_MAX		  160	/* max simultaneous processes */
#endif
#define	GID_MAX		   2147483647U	/* max value for a gid_t (2^31-2) */
#ifndef __QNXNTO__
#define	LINK_MAX		32767	/* max file link count */
#endif
#define	MAX_CANON		  255	/* max bytes in term canon input line */
#define	MAX_INPUT		  255	/* max bytes in terminal input */
#define	NAME_MAX		  255	/* max bytes in a file name */
#ifndef __QNXNTO__
#define	NGROUPS_MAX		   16	/* max supplemental group id's */
#endif
#define	UID_MAX		   2147483647U	/* max value for a uid_t (2^31-2) */
#ifndef OPEN_MAX
#define	OPEN_MAX		   64	/* max open files per process */
#endif
#define	PATH_MAX		 1024	/* max bytes in pathname */
#ifndef __QNXNTO__
#define	PIPE_BUF		  512	/* max bytes for atomic pipe writes */

#define	BC_BASE_MAX	      INT_MAX	/* max ibase/obase values in bc(1) */
#define	BC_DIM_MAX		65535	/* max array elements in bc(1) */
#define	BC_SCALE_MAX	      INT_MAX	/* max scale value in bc(1) */
#define	BC_STRING_MAX	      INT_MAX	/* max const string length in bc(1) */
#endif
#define	COLL_WEIGHTS_MAX	    2	/* max weights for order keyword */
#define	EXPR_NEST_MAX		   32	/* max expressions nested in expr(1) */
#define	LINE_MAX		 2048	/* max bytes in an input line */
#define	RE_DUP_MAX		  255	/* max RE's in interval notation */

/*
 * IEEE Std 1003.1c-95, adopted in X/Open CAE Specification Issue 5 Version 2
 */
#ifndef __QNXNTO__
#if (_POSIX_C_SOURCE - 0) >= 199506L || (_XOPEN_SOURCE - 0) >= 500 || \
    defined(_NETBSD_SOURCE)
#define	LOGIN_NAME_MAX		   17	/* max login name length incl. NUL */
#endif
#endif /* !__QNXNTO__ */

/*
 * X/Open CAE Specification Issue 5 Version 2
 */
#if defined(_XOPEN_SOURCE) || defined(_NETBSD_SOURCE)
#define	IOV_MAX			 1024	/* max # of iovec's for readv(2) etc. */
#define	NZERO			   20	/* default "nice" */
#endif /* _XOPEN_SOURCE || _NETBSD_SOURCE */

#endif /* !_ANSI_SOURCE */

#endif /* !_SYS_SYSLIMITS_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/syslimits.h $ $Rev: 680336 $")
#endif
