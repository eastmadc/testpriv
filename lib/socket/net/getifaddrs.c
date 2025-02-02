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



/*	$NetBSD: getifaddrs.c,v 1.10 2002/08/09 04:29:29 itojun Exp $	*/

/*
 * Copyright (c) 1995, 1999
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
 *	BSDI getifaddrs.c,v 2.12 2000/02/23 14:51:59 dab Exp
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: getifaddrs.c,v 1.10 2002/08/09 04:29:29 itojun Exp $");
#endif /* LIBC_SCCS and not lint */

#if (!defined(__QNXNTO__) && defined(_LIBC)) || (defined(__QNXNTO__) && defined(_LIBSOCKET))
#include "namespace.h"
#endif
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/param.h>
#include <net/route.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>

#include <assert.h>
#ifdef __QNXNTO__
#define _DIAGASSERT(x) ((void)0)
/* aways query 'kernel' */
#define ALIGNBYTES __cmsg_alignbytes()
#define ALIGN(p) __CMSG_ALIGN((uintptr_t)p)
#endif
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>

#ifdef __weak_alias
__weak_alias(getifaddrs,_getifaddrs)
__weak_alias(freeifaddrs,_freeifaddrs)
#endif

#define	SALIGN	(sizeof(long) - 1)
#define	SA_RLEN(sa)	((sa)->sa_len ? (((sa)->sa_len + SALIGN) & ~SALIGN) : (SALIGN + 1))

#ifdef __QNXNTO__
#define MAX_SYSCTL_TRY 5  /*From FreeBSD getifaddrs.c */
#endif

int
getifaddrs(struct ifaddrs **pif)
#ifdef __QNXNTO__
{
	return getifaddrs_fib(pif, -1);
}
int
getifaddrs_fib(struct ifaddrs **pif, int fib)
#endif
{
	int icnt = 1;
	int dcnt = 0;
	int ncnt = 0;
#ifdef __QNXNTO__
	int ntry = 0;
#endif
	int mib[6];
	size_t needed;
	char *buf;
	char *next;
	struct ifaddrs *cif = 0;
	char *p, *p0;
	struct rt_msghdr *rtm;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_dl *dl;
	struct sockaddr *sa;
	struct ifaddrs *ifa, *ift;
	u_short idx = 0;
	int i;
	size_t len, alen;
	char *data;
	char *names;

	_DIAGASSERT(pif != NULL);

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;             /* protocol */
	mib[3] = 0;             /* wildcard address family */
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;             /* no flags */
#ifndef __QNXNTO__
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
		return (-1);
	if ((buf = malloc(needed)) == NULL)
		return (-1);
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
#else
	do {
		/*
		 * We'll try to get addresses several times in case that
		 * the number of addresses is unexpectedly increased during
		 * the two sysctl calls. This should rarely happen, but we'll
		 * try to do our best for applications that assume success of
		 * this library (which should usually be the case).
		 * Portability note: since FreeBSD does not add margin of
		 * memory at the first sysctl, the possbility of failure on
		 * the second sysctl call is a bit higher.
		 */
#ifndef __QNXNTO__
		if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
#else
		if (sysctl_fib(mib, 6, NULL, &needed, NULL, 0, fib) < 0)
#endif
			return (-1);
		if ((buf = malloc(needed)) == NULL)
			return (-1);
#ifndef __QNXNTO__
		if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
#else
		if (sysctl_fib(mib, 6, buf, &needed, NULL, 0, fib) < 0)
#endif
			{
			if (errno != ENOMEM || ++ntry >= MAX_SYSCTL_TRY) {
				free(buf);
				return (-1);
			}
			free(buf);
			buf = NULL;
		}
	} while (buf == NULL);
#endif
	for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(void *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			ifm = (struct if_msghdr *)(void *)rtm;
			if (ifm->ifm_addrs & RTA_IFP) {
				idx = ifm->ifm_index;
				++icnt;
				dl = (struct sockaddr_dl *)(void *)(ifm + 1);
				dcnt += SA_RLEN((struct sockaddr *)(void*)dl) +
				    ALIGNBYTES;
				dcnt += sizeof(ifm->ifm_data);
				ncnt += dl->sdl_nlen + 1;
			} else
				idx = 0;
			break;

		case RTM_NEWADDR:
			ifam = (struct ifa_msghdr *)(void *)rtm;
			if (idx && ifam->ifam_index != idx)
				abort();	/* this cannot happen */

#define	RTA_MASKS	(RTA_NETMASK | RTA_IFA | RTA_BRD)
			if (idx == 0 || (ifam->ifam_addrs & RTA_MASKS) == 0)
				break;
			p = (char *)(void *)(ifam + 1);
			++icnt;
			/* Scan to look for length of address */
			alen = 0;
			for (p0 = p, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_IFA) {
					alen = len;
					break;
				}
				p += len;
			}
			for (p = p0, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_NETMASK && sa->sa_len == 0)
					dcnt += alen;
				else
					dcnt += len;
				p += len;
			}
			break;
		}
	}

	if (icnt + dcnt + ncnt == 1) {
		*pif = NULL;
		free(buf);
		return (0);
	}
	data = malloc(sizeof(struct ifaddrs) * icnt + dcnt + ncnt);
	if (data == NULL) {
		free(buf);
		return(-1);
	}

	ifa = (struct ifaddrs *)(void *)data;
	data += sizeof(struct ifaddrs) * icnt;
	names = data + dcnt;

	memset(ifa, 0, sizeof(struct ifaddrs) * icnt);
	ift = ifa;

	idx = 0;
	for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(void *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			ifm = (struct if_msghdr *)(void *)rtm;
			if (ifm->ifm_addrs & RTA_IFP) {
				idx = ifm->ifm_index;
				dl = (struct sockaddr_dl *)(void *)(ifm + 1);

				cif = ift;
				ift->ifa_name = names;
				ift->ifa_flags = (int)ifm->ifm_flags;
				memcpy(names, dl->sdl_data,
				    (size_t)dl->sdl_nlen);
				names[dl->sdl_nlen] = 0;
				names += dl->sdl_nlen + 1;

				ift->ifa_addr = (struct sockaddr *)(void *)data;
				memcpy(data, dl, (size_t)((struct sockaddr *)
				    (void *)dl)->sa_len);
				data += SA_RLEN((struct sockaddr *)(void *)dl);

				/* ifm_data needs to be aligned */
				ift->ifa_data = data = (void *)ALIGN(data);
				memcpy(data, &ifm->ifm_data, sizeof(ifm->ifm_data));
 				data += sizeof(ifm->ifm_data);

				ift = (ift->ifa_next = ift + 1);
			} else
				idx = 0;
			break;

		case RTM_NEWADDR:
			ifam = (struct ifa_msghdr *)(void *)rtm;
			if (idx && ifam->ifam_index != idx)
				abort();	/* this cannot happen */

			if (idx == 0 || (ifam->ifam_addrs & RTA_MASKS) == 0)
				break;
			ift->ifa_name = cif->ifa_name;
			ift->ifa_flags = cif->ifa_flags;
			ift->ifa_data = NULL;
			p = (char *)(void *)(ifam + 1);
			/* Scan to look for length of address */
			alen = 0;
			for (p0 = p, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_IFA) {
					alen = len;
					break;
				}
				p += len;
			}
			for (p = p0, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				switch (i) {
				case RTAX_IFA:
					ift->ifa_addr =
					    (struct sockaddr *)(void *)data;
					memcpy(data, p, len);
					data += len;
					break;

				case RTAX_NETMASK:
					ift->ifa_netmask =
					    (struct sockaddr *)(void *)data;
					if (sa->sa_len == 0) {
						memset(data, 0, alen);
						data += alen;
						break;
					}
					memcpy(data, p, len);
					data += len;
					break;

				case RTAX_BRD:
					ift->ifa_broadaddr =
					    (struct sockaddr *)(void *)data;
					memcpy(data, p, len);
					data += len;
					break;
				}
				p += len;
			}


			ift = (ift->ifa_next = ift + 1);
			break;
		}
	}

	free(buf);
	if (--ift >= ifa) {
		ift->ifa_next = NULL;
		*pif = ifa;
	} else {
		*pif = NULL;
		free(ifa);
	}
	return (0);
}

void
freeifaddrs(struct ifaddrs *ifp)
{

	_DIAGASSERT(ifp != NULL);

	free(ifp);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/getifaddrs.c $ $Rev: 680336 $")
#endif
