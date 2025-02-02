/*	$NetBSD: sysctlbyname.c,v 1.3 2005/06/12 05:21:27 lukem Exp $ */

/*-
 * Copyright (c) 2003,2004 The NetBSD Foundation, Inc.
 *	All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Brown.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The NetBSD Foundation nor the names of its
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

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: sysctlbyname.c,v 1.3 2005/06/12 05:21:27 lukem Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <sys/param.h>
#include <sys/sysctl.h>

#ifdef __weak_alias
__weak_alias(sysctlbyname,_sysctlbyname)
#endif

/*
 * trivial sysctlbyname() function for the "lazy".
 */
int
sysctlbyname(const char *gname, void *oldp, size_t *oldlenp, void *newp,
	     size_t newlen)
#ifdef __QNXNTO__
{
	return sysctlbyname_fib(gname, oldp, oldlenp, newp, newlen, -1);
}
int
sysctlbyname_fib(const char *gname, void *oldp, size_t *oldlenp, void *newp,
	     size_t newlen, int fib)
#endif
{
	int name[CTL_MAXNAME], rc;
	u_int namelen;

#ifndef __QNXNTO__
	rc = sysctlgetmibinfo(gname, &name[0], &namelen, NULL, NULL, NULL,
			      SYSCTL_VERSION);
#else
	rc = sysctlgetmibinfo_fib(gname, &name[0], &namelen, NULL, NULL, NULL,
			      SYSCTL_VERSION, fib);
#endif
	if (rc == 0)
#ifndef __QNXNTO__
		rc = sysctl(&name[0], namelen, oldp, oldlenp, newp, newlen);
#else
	rc = sysctl_fib(&name[0], namelen, oldp, oldlenp, newp, newlen, fib);
#endif
	return (rc);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/gen/sysctlbyname.c $ $Rev: 680336 $")
#endif
