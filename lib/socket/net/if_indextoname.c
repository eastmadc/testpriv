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

/*	$NetBSD: if_indextoname.c,v 1.5 2006/11/25 23:09:11 elad Exp $	*/
/*	$KAME: if_indextoname.c,v 1.7 2000/11/08 03:09:30 itojun Exp $	*/

/*-
 * Copyright (c) 1997, 2000
 *	Berkeley Software Design, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY Berkeley Software Design, Inc. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Berkeley Software Design, Inc. BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	BSDI Id: if_indextoname.c,v 2.3 2000/04/17 22:38:05 dab Exp
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: if_indextoname.c,v 1.5 2006/11/25 23:09:11 elad Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef __QNXNTO__
#include <nbutil.h>
#endif

#ifdef __weak_alias
__weak_alias(if_indextoname,_if_indextoname)
#endif

/*
 * From RFC 2533:
 *
 * The second function maps an interface index into its corresponding
 * name.
 *
 *    #include <net/if.h>
 *
 *    char  *if_indextoname(unsigned int ifindex, char *ifname);
 *
 * The ifname argument must point to a buffer of at least IF_NAMESIZE
 * bytes into which the interface name corresponding to the specified
 * index is returned.  (IF_NAMESIZE is also defined in <net/if.h> and
 * its value includes a terminating null byte at the end of the
 * interface name.) This pointer is also the return value of the
 * function.  If there is no interface corresponding to the specified
 * index, NULL is returned, and errno is set to ENXIO, if there was a
 * system error (such as running out of memory), if_indextoname returns
 * NULL and errno would be set to the proper value (e.g., ENOMEM).
 */

char *
if_indextoname(unsigned int ifindex, char *ifname)
#ifdef QNX_MFIB
{
	return if_indextoname_fib(ifindex, ifname, -1);
}
char *
if_indextoname_fib(unsigned int ifindex, char *ifname, int fib)
#endif
{
	struct ifaddrs *ifaddrs, *ifa;
	int error = 0;

#ifndef QNX_MFIB
	if (getifaddrs(&ifaddrs) < 0)
#else
	if (getifaddrs_fib(&ifaddrs, fib) < 0)
#endif
		return(NULL);	/* getifaddrs properly set errno */

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr &&
		    ifa->ifa_addr->sa_family == AF_LINK &&
		    ifindex == ((struct sockaddr_dl*)
			(void *)ifa->ifa_addr)->sdl_index)
			break;
	}

	if (ifa == NULL) {
		error = ENXIO;
		ifname = NULL;
	}
	else
		strlcpy(ifname, ifa->ifa_name, IFNAMSIZ);

	freeifaddrs(ifaddrs);

	errno = error;
	return(ifname);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/if_indextoname.c $ $Rev: 680336 $")
#endif
