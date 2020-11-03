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

/*	$NetBSD: route.c,v 1.76 2006/11/16 01:33:40 christos Exp $	*/

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Kevin M. Lahey of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1980, 1986, 1991, 1993
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
 *	@(#)route.c	8.3 (Berkeley) 1/9/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: route.c,v 1.76 2006/11/16 01:33:40 christos Exp $");


#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#ifdef RADIX_MPATH
#include <net/if_dl.h>
#endif
#endif
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/ioctl.h>
#include <sys/pool.h>

#include <net/if.h>
#ifdef RADIX_MPATH
#include <net/radix.h>
#include <net/radix_mpath.h>
#endif
#include <net/route.h>
#include <net/raw_cb.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#ifdef QNX_MFIB
#include <sys/kauth.h>
#endif


struct	route_cb route_cb;
struct	rtstat	rtstat;
#ifndef QNX_MFIB
struct	radix_node_head *rt_tables[AF_MAX+1];
#else
struct	radix_node_head *rt_tables_mfib[FIBS_MAX][AF_MAX+1];
#endif
#ifdef __QNXNTO__
NLIST_EXPORT(rtstat, rtstat);
#ifndef QNX_MFIB
NLIST_EXPORT(rt_tables, rt_tables);
#else
NLIST_EXPORT(rt_tables, rt_tables_mfib);
#endif // qnx vrf
#endif

int	rttrash;		/* routes not in table but not freed */
struct	sockaddr wildcard;	/* zero valued cookie for wildcard searches */

POOL_INIT(rtentry_pool, sizeof(struct rtentry), 0, 0, 0, "rtentpl", NULL);
POOL_INIT(rttimer_pool, sizeof(struct rttimer), 0, 0, 0, "rttmrpl", NULL);

struct callout rt_timer_ch; /* callout for rt_timer_timer() */

static int rtdeletemsg(struct rtentry *);
#ifndef QNX_MFIB
static int rtflushclone1(struct radix_node *, void *);
#else
static int rtflushclone1(struct radix_node *, void *, int);
#endif
static void rtflushclone(struct radix_node_head *, struct rtentry *);

void
rtable_init(void **table)
{
	struct domain *dom;
	DOMAIN_FOREACH(dom)
		if (dom->dom_rtattach)
			dom->dom_rtattach(&table[dom->dom_family],
			    dom->dom_rtoffset);
}

void
route_init(void)
{

	rn_init();	/* initialize all zeroes, all ones, mask table */
#ifndef __QNXNTO__
	rtable_init((void **)rt_tables);
#else
	/* GCC type-punned alias warning */
#ifndef QNX_MFIB
	rtable_init((void *)rt_tables);
#else
	int fib;
	int af;
	for (fib = 0; fib < FIBS_MAX; fib++) {
		rtable_init((void *)rt_tables_mfib[fib]);
		for (af=0 ; af< AF_MAX+1; af++)
			if (rt_tables_mfib[fib][af])
				rt_tables_mfib[fib][af]->rnh_fib = fib;
	}
#endif
#endif
}

/*
 * Packet routing routines.
 */

void
#ifndef __QNXNTO__
rtalloc(struct route *ro)
#else
#ifndef QNX_MFIB
(rtalloc)(struct route *ro, void *hint)
#else
(rtalloc)(struct route *ro, void *hint, int fib)

#endif
#endif
{
	if (ro->ro_rt != NULL) {
		if (ro->ro_rt->rt_ifp != NULL &&
#ifdef QNX_MFIB
		    (fib == ro->ro_rt->fib) &&
#endif
		    (ro->ro_rt->rt_flags & RTF_UP) != 0)
			return;
		RTFREE(ro->ro_rt);
	}
#ifndef __QNXNTO__
	ro->ro_rt = rtalloc1(&ro->ro_dst, 1);
#else
#ifndef QNX_MFIB
	ro->ro_rt = (rtalloc1)(&ro->ro_dst, 1, hint);
#else
	ro->ro_rt = (rtalloc1)(&ro->ro_dst, 1, hint, fib);
#endif
#endif
}

struct rtentry *
#ifndef __QNXNTO__
rtalloc1(const struct sockaddr *dst, int report)
#else
#ifndef QNX_MFIB
(rtalloc1)(const struct sockaddr *dst, int report, void *hint)
#else
(rtalloc1)(const struct sockaddr *dst, int report, void *hint, int fib)
#endif
#endif
{
#ifndef QNX_MFIB
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
#else
	struct radix_node_head *rnh = rt_tables_mfib[fib][dst->sa_family];
#endif
	struct rtentry *rt;
	struct radix_node *rn;
	struct rtentry *newrt = NULL;
	struct rt_addrinfo info;
	int  s = splsoftnet(), err = 0, msgtype = RTM_MISS;

	if (rnh && (rn = rnh->rnh_matchaddr(dst, rnh
#ifdef __QNXNTO__
	    , hint
#endif
	    )) &&
	    ((rn->rn_flags & RNF_ROOT) == 0)) {
		newrt = rt = (struct rtentry *)rn;
		if (report && (rt->rt_flags & RTF_CLONING)) {
#ifndef QNX_MFIB
			err = rtrequest(RTM_RESOLVE, dst, NULL, NULL, 0,
			    &newrt);
#else
			err = rtrequest(RTM_RESOLVE, dst, NULL, NULL, 0,
			    &newrt, fib);
#endif
			if (err) {
				newrt = rt;
				rt->rt_refcnt++;
				goto miss;
			}
			KASSERT(newrt != NULL);
			if ((rt = newrt) && (rt->rt_flags & RTF_XRESOLVE)) {
				msgtype = RTM_RESOLVE;
				goto miss;
			}
			/* Inform listeners of the new route */
			memset(&info, 0, sizeof(info));
			info.rti_info[RTAX_DST] = rt_key(rt);
			info.rti_info[RTAX_NETMASK] = rt_mask(rt);
			info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
			if (rt->rt_ifp != NULL) {
				info.rti_info[RTAX_IFP] =
				    rt->rt_ifp->if_dl->ifa_addr;
				info.rti_info[RTAX_IFA] = rt->rt_ifa->ifa_addr;
			}
			rt_missmsg(RTM_ADD, &info, rt->rt_flags, 0);
		} else
			rt->rt_refcnt++;
	} else {
		rtstat.rts_unreach++;
	miss:	if (report) {
			memset((caddr_t)&info, 0, sizeof(info));
			info.rti_info[RTAX_DST] = dst;
			rt_missmsg(msgtype, &info, 0, err);
		}
	}
	splx(s);
	return (newrt);
}

void
rtfree(struct rtentry *rt)
{
	struct ifaddr *ifa;

	if (rt == NULL)
		panic("rtfree");
	rt->rt_refcnt--;
	if (rt->rt_refcnt <= 0 && (rt->rt_flags & RTF_UP) == 0) {
		if (rt->rt_nodes->rn_flags & (RNF_ACTIVE | RNF_ROOT))
			panic ("rtfree 2");
		rttrash--;
		if (rt->rt_refcnt < 0) {
			printf("rtfree: %p not freed (neg refs)\n", rt);
			return;
		}
		rt_timer_remove_all(rt, 0);
		ifa = rt->rt_ifa;
		IFAFREE(ifa);
		Free(rt_key(rt));
		pool_put(&rtentry_pool, rt);
	}
}

void
ifafree(struct ifaddr *ifa)
{

#ifdef DIAGNOSTIC
	if (ifa == NULL)
		panic("ifafree: null ifa");
	if (ifa->ifa_refcnt != 0)
		panic("ifafree: ifa_refcnt != 0 (%d)", ifa->ifa_refcnt);
#endif
#ifdef IFAREF_DEBUG
	printf("ifafree: freeing ifaddr %p\n", ifa);
#endif
	free(ifa, M_IFADDR);
}

/*
 * Force a routing table entry to the specified
 * destination to go through the given gateway.
 * Normally called as a result of a routing redirect
 * message from the network layer.
 *
 * N.B.: must be called at splsoftnet
 */
void
rtredirect(const struct sockaddr *dst, const struct sockaddr *gateway,
	const struct sockaddr *netmask, int flags, const struct sockaddr *src,
	struct rtentry **rtp
#ifdef QNX_MFIB
	, struct ifnet * ifp
#endif
	)
{
	struct rtentry *rt;
	int error = 0;
	u_quad_t *stat = NULL;
	struct rt_addrinfo info;
	struct ifaddr *ifa;

#ifndef QNX_MFIB
	/* verify the gateway is directly reachable */
	if ((ifa = ifa_ifwithnet(gateway)) == NULL) {
		error = ENETUNREACH;
		goto out;
	}
#else
	/*
	 * verify the gateway is directly reachable from one of the fibs this interface is part of
	 */
	int fib = -1;
	while ((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX) {
		if ((ifa = ifa_ifwithnet(gateway)) != NULL) {
			break;
		}
	}
	if (ifa == NULL) {
		error = ENETUNREACH;
		goto out;
	}
#endif
#ifndef QNX_MFIB
	rt = rtalloc1(dst, 0);
#else
	rt = rtalloc1(dst, 0, NULL, fib); /* MFIB: send on the fib we found the ifa in */
#endif
	/*
	 * If the redirect isn't from our current router for this dst,
	 * it's either old or wrong.  If it redirects us to ourselves,
	 * we have a routing loop, perhaps as a result of an interface
	 * going down recently.
	 */
#define	equal(a1, a2) \
	((a1)->sa_len == (a2)->sa_len && \
	 memcmp((a1), (a2), (a1)->sa_len) == 0)
	if (!(flags & RTF_DONE) && rt &&
	     (!equal(src, rt->rt_gateway) || rt->rt_ifa != ifa))
		error = EINVAL;
	else if (ifa_ifwithaddr(gateway))
		error = EHOSTUNREACH;
	if (error)
		goto done;
	/*
	 * Create a new entry if we just got back a wildcard entry
	 * or the lookup failed.  This is necessary for hosts
	 * which use routing redirects generated by smart gateways
	 * to dynamically build the routing tables.
	 */
	if ((rt == NULL) || (rt_mask(rt) && rt_mask(rt)->sa_len < 2))
		goto create;
	/*
	 * Don't listen to the redirect if it's
	 * for a route to an interface.
	 */
	if (rt->rt_flags & RTF_GATEWAY) {
		if (((rt->rt_flags & RTF_HOST) == 0) && (flags & RTF_HOST)) {
			/*
			 * Changing from route to net => route to host.
			 * Create new route, rather than smashing route to net.
			 */
		create:
			if (rt)
				rtfree(rt);
			flags |=  RTF_GATEWAY | RTF_DYNAMIC;
			info.rti_info[RTAX_DST] = dst;
			info.rti_info[RTAX_GATEWAY] = gateway;
			info.rti_info[RTAX_NETMASK] = netmask;
			info.rti_ifa = ifa;
			info.rti_flags = flags;
			rt = NULL;
#ifdef __QNXNTO__
			info.rti_ifp = ifa->ifa_ifp;
#endif
#ifndef QNX_MFIB
			error = rtrequest1(RTM_ADD, &info, &rt);
#else
			error = rtrequest1(RTM_ADD, &info, &rt, fib);
#endif
			if (rt != NULL)
				flags = rt->rt_flags;
			stat = &rtstat.rts_dynamic;
		} else {
			/*
			 * Smash the current notion of the gateway to
			 * this destination.  Should check about netmask!!!
			 */
			rt->rt_flags |= RTF_MODIFIED;
			flags |= RTF_MODIFIED;
			stat = &rtstat.rts_newgateway;
			rt_setgate(rt, rt_key(rt), gateway);
		}
	} else
		error = EHOSTUNREACH;
done:
	if (rt) {
		if (rtp && !error)
			*rtp = rt;
		else
			rtfree(rt);
	}
out:
	if (error)
		rtstat.rts_badredirect++;
	else if (stat != NULL)
		(*stat)++;
	memset((caddr_t)&info, 0, sizeof(info));
	info.rti_info[RTAX_DST] = dst;
	info.rti_info[RTAX_GATEWAY] = gateway;
	info.rti_info[RTAX_NETMASK] = netmask;
	info.rti_info[RTAX_AUTHOR] = src;
	rt_missmsg(RTM_REDIRECT, &info, flags, error);
}

/*
 * Delete a route and generate a message
 */
static int
rtdeletemsg(struct rtentry *rt)
{
	int error;
	struct rt_addrinfo info;

	/*
	 * Request the new route so that the entry is not actually
	 * deleted.  That will allow the information being reported to
	 * be accurate (and consistent with route_output()).
	 */
	memset((caddr_t)&info, 0, sizeof(info));
	info.rti_info[RTAX_DST] = rt_key(rt);
	info.rti_info[RTAX_NETMASK] = rt_mask(rt);
	info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
	info.rti_flags = rt->rt_flags;
#ifdef __QNXNTO__
	info.rti_ifp = rt->rt_ifp;
#endif
#ifndef QNX_MFIB
	error = rtrequest1(RTM_DELETE, &info, &rt);
#else
	error = rtrequest1(RTM_DELETE, &info, &rt, rt->fib);
#endif

	rt_missmsg(RTM_DELETE, &info, info.rti_flags, error);

	/* Adjust the refcount */
	if (error == 0 && rt->rt_refcnt <= 0) {
		rt->rt_refcnt++;
		rtfree(rt);
	}
	return (error);
}

static int
#ifndef QNX_MFIB
rtflushclone1(struct radix_node *rn, void *arg)
#else
rtflushclone1(struct radix_node *rn, void *arg, int fib)
#endif
{
	struct rtentry *rt, *parent;

	rt = (struct rtentry *)rn;
	parent = (struct rtentry *)arg;
	if ((rt->rt_flags & RTF_CLONED) != 0 && rt->rt_parent == parent)
		rtdeletemsg(rt);
	return 0;
}

static void
rtflushclone(struct radix_node_head *rnh, struct rtentry *parent)
{

#ifdef DIAGNOSTIC
	if (!parent || (parent->rt_flags & RTF_CLONING) == 0)
		panic("rtflushclone: called with a non-cloning route");
	if (!rnh->rnh_walktree)
		panic("rtflushclone: no rnh_walktree");
#endif
	rnh->rnh_walktree(rnh, rtflushclone1, (void *)parent);
}

/*
 * Routing table ioctl interface.
 */
int
rtioctl(u_long req, caddr_t data, struct lwp *l)
{
	return (EOPNOTSUPP);
}

struct ifaddr *
ifa_ifwithroute(int flags, const struct sockaddr *dst,
#ifndef QNX_MFIB
	const struct sockaddr *gateway)
#else
	const struct sockaddr *gateway, int fib)
#endif
{
	struct ifaddr *ifa;
	if ((flags & RTF_GATEWAY) == 0) {
		/*
		 * If we are adding a route to an interface,
		 * and the interface is a pt to pt link
		 * we should search for the destination
		 * as our clue to the interface.  Otherwise
		 * we can use the local address.
		 */
		ifa = NULL;
		if (flags & RTF_HOST)
			ifa = ifa_ifwithdstaddr(dst);
		if (ifa == NULL)
			ifa = ifa_ifwithaddr(gateway);
	} else {
		/*
		 * If we are adding a route to a remote net
		 * or host, the gateway may still be on the
		 * other end of a pt to pt link.
		 */
		ifa = ifa_ifwithdstaddr(gateway);
	}
	if (ifa == NULL)
		ifa = ifa_ifwithnet(gateway);
	if (ifa == NULL) {
#ifndef QNX_MFIB
		struct rtentry *rt = rtalloc1(dst, 0);
#else
		struct rtentry *rt = rtalloc1(dst, 0, NULL, fib);
#endif
		if (rt == NULL)
			return NULL;
		rt->rt_refcnt--;
		if ((ifa = rt->rt_ifa) == NULL)
			return NULL;
	}
	if (ifa->ifa_addr->sa_family != dst->sa_family) {
		struct ifaddr *oifa = ifa;
		ifa = ifaof_ifpforaddr(dst, ifa->ifa_ifp);
		if (ifa == 0)
			ifa = oifa;
	}
	return (ifa);
}

#define ROUNDUP(a) (a>0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#ifndef QNX_MFIB
int
rtrequest(int req, const struct sockaddr *dst, const struct sockaddr *gateway,
	const struct sockaddr *netmask, int flags, struct rtentry **ret_nrt)
#else
int
rtrequest(int req, const struct sockaddr *dst, const struct sockaddr *gateway,
	const struct sockaddr *netmask, int flags, struct rtentry **ret_nrt, int fib)
#endif
{
	struct rt_addrinfo info;

	memset(&info, 0, sizeof(info));
	info.rti_flags = flags;
	info.rti_info[RTAX_DST] = dst;
	info.rti_info[RTAX_GATEWAY] = gateway;
	info.rti_info[RTAX_NETMASK] = netmask;
#ifndef QNX_MFIB
	return rtrequest1(req, &info, ret_nrt);
#else
	return rtrequest1(req, &info, ret_nrt, fib);
#endif
}

int
#ifndef QNX_MFIB
rt_getifa(struct rt_addrinfo *info)
#else
rt_getifa(struct rt_addrinfo *info, int fib)
#endif
{
	struct ifaddr *ifa;
	const struct sockaddr *dst = info->rti_info[RTAX_DST];
	const struct sockaddr *gateway = info->rti_info[RTAX_GATEWAY];
	const struct sockaddr *ifaaddr = info->rti_info[RTAX_IFA];
	const struct sockaddr *ifpaddr = info->rti_info[RTAX_IFP];
	int flags = info->rti_flags;

	/*
	 * ifp may be specified by sockaddr_dl when protocol address
	 * is ambiguous
	 */
	if (info->rti_ifp == NULL && ifpaddr != NULL
	    && ifpaddr->sa_family == AF_LINK &&
	    (ifa = ifa_ifwithnet((const struct sockaddr *)ifpaddr)) != NULL)
		info->rti_ifp = ifa->ifa_ifp;
	if (info->rti_ifa == NULL && ifaaddr != NULL)
		info->rti_ifa = ifa_ifwithaddr(ifaaddr);
	if (info->rti_ifa == NULL) {
		const struct sockaddr *sa;

		sa = ifaaddr != NULL ? ifaaddr :
		    (gateway != NULL ? gateway : dst);
		if (sa != NULL && info->rti_ifp != NULL)
			info->rti_ifa = ifaof_ifpforaddr(sa, info->rti_ifp);
		else if (dst != NULL && gateway != NULL)
#ifndef QNX_MFIB
			info->rti_ifa = ifa_ifwithroute(flags, dst, gateway);
#else
			info->rti_ifa = ifa_ifwithroute(flags, dst, gateway, fib);
#endif
		else if (sa != NULL)
#ifndef QNX_MFIB
			info->rti_ifa = ifa_ifwithroute(flags, sa, sa);
#else
			info->rti_ifa = ifa_ifwithroute(flags, sa, sa, fib);
#endif
	}
	if ((ifa = info->rti_ifa) == NULL)
		return ENETUNREACH;
	if (ifa->ifa_getifa != NULL)
		info->rti_ifa = ifa = (*ifa->ifa_getifa)(ifa, dst);
	if (info->rti_ifp == NULL)
		info->rti_ifp = ifa->ifa_ifp;
	return 0;
}

int
#ifndef QNX_MFIB
rtrequest1(int req, struct rt_addrinfo *info, struct rtentry **ret_nrt)
#else
rtrequest1(int req, struct rt_addrinfo *info, struct rtentry **ret_nrt, int fib)
#endif
{
	int s = splsoftnet();
	int error = 0;
	struct rtentry *rt, *crt;
	struct radix_node *rn;
	struct radix_node_head *rnh;
	struct ifaddr *ifa;
	struct sockaddr *ndst;
	struct sockaddr_storage deldst;
	const struct sockaddr *dst = info->rti_info[RTAX_DST];
	const struct sockaddr *gateway = info->rti_info[RTAX_GATEWAY];
	const struct sockaddr *netmask = info->rti_info[RTAX_NETMASK];
	int flags = info->rti_flags;
#ifdef __QNXNTO__
	void *hint = info->rti_ifp;
#endif
#define senderr(x) { error = x ; goto bad; }

#ifndef QNX_MFIB
	if ((rnh = rt_tables[dst->sa_family]) == NULL)
#else
	if ((rnh = rt_tables_mfib[fib][dst->sa_family]) == NULL)
#endif
		senderr(ESRCH);
	if (flags & RTF_HOST)
		netmask = NULL;
	switch (req) {
	case RTM_DELETE:
		if (netmask) {
			rt_maskedcopy(dst, (struct sockaddr *)&deldst, netmask);
			dst = (struct sockaddr *)&deldst;
		}
#ifndef __QNXNTO__
		if ((rn = rnh->rnh_lookup(dst, netmask, rnh)) == NULL)
#else
		if ((rn = rnh->rnh_lookup(dst, netmask, rnh, hint)) == NULL)
#endif
			senderr(ESRCH);
		rt = (struct rtentry *)rn;
#ifdef RADIX_MPATH
		/*
		 * if we got multipath routes, we require users to specify
		 * a matching RTAX_GATEWAY.
		 */
		if (rn_mpath_capable(rnh)) {
#ifndef __QNXNTO__
			rt = rt_mpath_matchgate(rt, gateway);
#else
			struct ifnet *info_ifp =  NULL;
			const struct sockaddr *ifpaddr = info->rti_info[RTAX_IFP];
			if (ifpaddr) {
#ifndef QNX_MFIB
				info_ifp = rt_mpath_ifpaddrtoifp((struct sockaddr_dl *)ifpaddr);
#else
				info_ifp = rt_mpath_ifpaddrtoifp((struct sockaddr_dl *)ifpaddr, fib);
#endif
				if (!info_ifp) senderr(ESRCH);
			}
			rt = rt_mpath_matchgate(rt, gateway, info_ifp, rnh);
#endif
			rn = (struct radix_node *)rt;
			if (!rt)
				senderr(ESRCH);
		}
#endif
		if ((rt->rt_flags & RTF_CLONING) != 0) {
			/* clean up any cloned children */
			rtflushclone(rnh, rt);
		}
#ifdef RADIX_MPATH
		if ((rn = rnh->rnh_deladdr(dst, netmask, rnh, rn)) == NULL)
#else
		if ((rn = rnh->rnh_deladdr(dst, netmask, rnh)) == NULL)
#endif
			senderr(ESRCH);
		if (rn->rn_flags & (RNF_ACTIVE | RNF_ROOT))
			panic ("rtrequest delete");
		rt = (struct rtentry *)rn;
		if (rt->rt_gwroute) {
			RTFREE(rt->rt_gwroute);
			rt->rt_gwroute = NULL;
		}
		if (rt->rt_parent) {
			rt->rt_parent->rt_refcnt--;
			rt->rt_parent = NULL;
		}
		rt->rt_flags &= ~RTF_UP;
		if ((ifa = rt->rt_ifa) && ifa->ifa_rtrequest)
#ifndef QNX_MFIB
			ifa->ifa_rtrequest(RTM_DELETE, rt, info);
#else
			ifa->ifa_rtrequest(RTM_DELETE, rt, info, rt->fib);
#endif
		rttrash++;
		if (ret_nrt)
			*ret_nrt = rt;
		else if (rt->rt_refcnt <= 0) {
			rt->rt_refcnt++;
			rtfree(rt);
		}
		break;

	case RTM_RESOLVE:
		if (ret_nrt == NULL || (rt = *ret_nrt) == NULL)
			senderr(EINVAL);
		if ((rt->rt_flags & RTF_CLONING) == 0)
			senderr(EINVAL);
		ifa = rt->rt_ifa;
		flags = rt->rt_flags & ~(RTF_CLONING | RTF_STATIC);
		flags |= RTF_CLONED;
		gateway = rt->rt_gateway;
		if ((netmask = rt->rt_genmask) == NULL)
			flags |= RTF_HOST;
		goto makeroute;

	case RTM_ADD:
#ifndef QNX_MFIB
		if (info->rti_ifa == NULL && (error = rt_getifa(info)))
#else
		if (info->rti_ifa == NULL && (error = rt_getifa(info, fib)))
#endif
			senderr(error);
		ifa = info->rti_ifa;
	makeroute:
		/* Already at splsoftnet() so pool_get/pool_put are safe */
		rt = pool_get(&rtentry_pool, PR_NOWAIT);
		if (rt == NULL)
			senderr(ENOBUFS);
		Bzero(rt, sizeof(*rt));
		rt->rt_flags = RTF_UP | flags;
#ifdef QNX_MFIB
		rt->fib = fib;
		if (ifa->ifa_ifp && !if_get_fib_enabled(ifa->ifa_ifp, fib)) {
			/*
			 *  attempt to add a route to an interface that doesn't exist in this fib
			 *  - this can happen if the caller specifies an interface when manually adding a route
			 *  - the callers credentials are checked before performing this op, so the user must be root or equivalent
			 */
			pool_put(&rtentry_pool, rt);
			senderr(ESRCH);
		}
#endif
		LIST_INIT(&rt->rt_timer);
		if (rt_setgate(rt, dst, gateway)) {
			pool_put(&rtentry_pool, rt);
			senderr(ENOBUFS);
		}
		ndst = rt_key(rt);
		if (netmask) {
			rt_maskedcopy(dst, ndst, netmask);
		} else
			Bcopy(dst, ndst, dst->sa_len);
		rt_set_ifa(rt, ifa);
		rt->rt_ifp = ifa->ifa_ifp;
		if (req == RTM_RESOLVE) {
			rt->rt_rmx = (*ret_nrt)->rt_rmx; /* copy metrics */
			rt->rt_parent = *ret_nrt;
			rt->rt_parent->rt_refcnt++;
		}
#ifdef RADIX_MPATH
		/* do not permit exactly the same dst/mask/gw pair */
		if (rn_mpath_capable(rnh) &&
				rt_mpath_conflict(rnh, rt, netmask)) {
			IFAFREE(ifa);
			if ((rt->rt_flags & RTF_CLONED) != 0 && rt->rt_parent)
				rtfree(rt->rt_parent);
			if (rt->rt_gwroute)
				rtfree(rt->rt_gwroute);
			Free(rt_key(rt));
			pool_put(&rtentry_pool, rt);
			senderr(EEXIST);
		}
#endif
		rn = rnh->rnh_addaddr(ndst, netmask, rnh, rt->rt_nodes);
#ifndef QNX_MFIB
		if (rn == NULL && (crt = rtalloc1(ndst, 0)) != NULL)
#else
		if (rn == NULL && (crt = rtalloc1(ndst, 0, NULL, fib)) != NULL)
#endif
		{
			/* overwrite cloned route */
			if ((crt->rt_flags & RTF_CLONED) != 0) {
				rtdeletemsg(crt);
				rn = rnh->rnh_addaddr(ndst,
				    netmask, rnh, rt->rt_nodes);
			}
			RTFREE(crt);
		}
		if (rn == NULL) {
			IFAFREE(ifa);
			if ((rt->rt_flags & RTF_CLONED) != 0 && rt->rt_parent)
				rtfree(rt->rt_parent);
			if (rt->rt_gwroute)
				rtfree(rt->rt_gwroute);
			Free(rt_key(rt));
			pool_put(&rtentry_pool, rt);
			senderr(EEXIST);
		}
		if (ifa->ifa_rtrequest)
#ifndef QNX_MFIB
			ifa->ifa_rtrequest(req, rt, info);
#else
			ifa->ifa_rtrequest(req, rt, info, rt->fib);
#endif
		if (ret_nrt) {
			*ret_nrt = rt;
			rt->rt_refcnt++;
		}
		if ((rt->rt_flags & RTF_CLONING) != 0) {
			/* clean up any cloned children */
			rtflushclone(rnh, rt);
		}
		break;
	}
bad:
	splx(s);
	return (error);
}

int
rt_setgate( struct rtentry *rt0, const struct sockaddr *dst,
	const struct sockaddr *gate)
{
	char *new, *old;
	u_int dlen = ROUNDUP(dst->sa_len), glen = ROUNDUP(gate->sa_len);
	struct rtentry *rt = rt0;

	if (rt->rt_gateway == NULL || glen > ROUNDUP(rt->rt_gateway->sa_len)) {
		old = (caddr_t)rt_key(rt);
		R_Malloc(new, caddr_t, dlen + glen);
		if (new == NULL)
			return 1;
		Bzero(new, dlen + glen);
		rt->rt_nodes->rn_key = new;
	} else {
		new = __UNCONST(rt->rt_nodes->rn_key); /*XXXUNCONST*/
		old = NULL;
	}
	Bcopy(gate, (rt->rt_gateway = (struct sockaddr *)(new + dlen)), glen);
	if (old) {
		Bcopy(dst, new, dlen);
		Free(old);
	}
	if (rt->rt_gwroute) {
		RTFREE(rt->rt_gwroute);
		rt->rt_gwroute = NULL;
	}
	if (rt->rt_flags & RTF_GATEWAY) {
#ifndef QNX_MFIB
		rt->rt_gwroute = rtalloc1(gate, 1);
#else
		rt->rt_gwroute = rtalloc1(gate, 1, NULL, rt0->fib);
#endif
		/*
		 * If we switched gateways, grab the MTU from the new
		 * gateway route if the current MTU, if the current MTU is
		 * greater than the MTU of gateway.
		 * Note that, if the MTU of gateway is 0, we will reset the
		 * MTU of the route to run PMTUD again from scratch. XXX
		 */
		if (rt->rt_gwroute
		    && !(rt->rt_rmx.rmx_locks & RTV_MTU)
		    && rt->rt_rmx.rmx_mtu
		    && rt->rt_rmx.rmx_mtu > rt->rt_gwroute->rt_rmx.rmx_mtu) {
			rt->rt_rmx.rmx_mtu = rt->rt_gwroute->rt_rmx.rmx_mtu;
		}
	}
	return 0;
}

void
rt_maskedcopy(const struct sockaddr *src, struct sockaddr *dst,
	const struct sockaddr *netmask)
{
	const u_char *cp1 = (const u_char *)src;
	u_char *cp2 = (u_char *)dst;
	const u_char *cp3 = (const u_char *)netmask;
	u_char *cplim = cp2 + *cp3;
	u_char *cplim2 = cp2 + *cp1;

	*cp2++ = *cp1++; *cp2++ = *cp1++; /* copies sa_len & sa_family */
	cp3 += 2;
	if (cplim > cplim2)
		cplim = cplim2;
	while (cp2 < cplim)
		*cp2++ = *cp1++ & *cp3++;
	if (cp2 < cplim2)
		memset(cp2, 0, (unsigned)(cplim2 - cp2));
}

/*
 * Set up or tear down a routing table entry, normally
 * for an interface.
 */
int
#ifndef QNX_MFIB
rtinit(struct ifaddr *ifa, int cmd, int flags)
#else
rtinit(struct ifaddr *ifa, int cmd, int flags, int fib)
#endif
{
	struct rtentry *rt;
	struct sockaddr *dst, *odst;
	struct sockaddr_storage deldst;
	struct rtentry *nrt = NULL;
	int error;
	struct rt_addrinfo info;

	dst = flags & RTF_HOST ? ifa->ifa_dstaddr : ifa->ifa_addr;
	if (cmd == RTM_DELETE) {
		if ((flags & RTF_HOST) == 0 && ifa->ifa_netmask) {
			/* Delete subnet route for this interface */
			odst = dst;
			dst = (struct sockaddr *)&deldst;
			rt_maskedcopy(odst, dst, ifa->ifa_netmask);
		}
#ifndef __QNXNTO__
		if ((rt = rtalloc1(dst, 0)) != NULL)
#else
#ifndef QNX_MFIB
		if ((rt = rtalloc1(dst, 0, ifa->ifa_ifp)) != NULL)
#else
		if ((rt = rtalloc1(dst, 0, ifa->ifa_ifp, fib)) != NULL)
#endif
#endif
		{
			rt->rt_refcnt--;
			if (rt->rt_ifa != ifa)
				return (flags & RTF_HOST ? EHOSTUNREACH
							: ENETUNREACH);
		}
	}
	memset(&info, 0, sizeof(info));
	info.rti_ifa = ifa;
	info.rti_flags = flags | ifa->ifa_flags;
	info.rti_info[RTAX_DST] = dst;
	info.rti_info[RTAX_GATEWAY] = ifa->ifa_addr;
	/*
	 * XXX here, it seems that we are assuming that ifa_netmask is NULL
	 * for RTF_HOST.  bsdi4 passes NULL explicitly (via intermediate
	 * variable) when RTF_HOST is 1.  still not sure if i can safely
	 * change it to meet bsdi4 behavior.
	 */
	info.rti_info[RTAX_NETMASK] = ifa->ifa_netmask;
#ifdef __QNXNTO__
	info.rti_ifp = (ifa) ? ifa->ifa_ifp:NULL;
#endif
#ifndef QNX_MFIB
	error = rtrequest1(cmd, &info, &nrt);
#else
	error = rtrequest1(cmd, &info, &nrt, fib);
#endif
	if (cmd == RTM_DELETE && error == 0 && (rt = nrt)) {
		rt_newaddrmsg(cmd, ifa, error, nrt);
		if (rt->rt_refcnt <= 0) {
			rt->rt_refcnt++;
			rtfree(rt);
		}
	}
	if (cmd == RTM_ADD && error == 0 && (rt = nrt)) {
		rt->rt_refcnt--;
		if (rt->rt_ifa != ifa) {
			printf("rtinit: wrong ifa (%p) was (%p)\n", ifa,
				rt->rt_ifa);
			if (rt->rt_ifa->ifa_rtrequest)
#ifndef QNX_MFIB
				rt->rt_ifa->ifa_rtrequest(RTM_DELETE, rt, NULL);
#else
				rt->rt_ifa->ifa_rtrequest(RTM_DELETE, rt, NULL, rt->fib);
#endif
			rt_replace_ifa(rt, ifa);
			rt->rt_ifp = ifa->ifa_ifp;
			if (ifa->ifa_rtrequest)
#ifndef QNX_MFIB
				ifa->ifa_rtrequest(RTM_ADD, rt, NULL);
#else
				ifa->ifa_rtrequest(RTM_ADD, rt, NULL, rt->fib);
#endif
		}
		rt_newaddrmsg(cmd, ifa, error, nrt);
	}
	return (error);
}

/*
 * Route timer routines.  These routes allow functions to be called
 * for various routes at any time.  This is useful in supporting
 * path MTU discovery and redirect route deletion.
 *
 * This is similar to some BSDI internal functions, but it provides
 * for multiple queues for efficiency's sake...
 */

LIST_HEAD(, rttimer_queue) rttimer_queue_head;
static int rt_init_done = 0;

#ifndef QNX_MFIB
#define RTTIMER_CALLOUT(r)	do {					\
		if (r->rtt_func != NULL) {				\
			(*r->rtt_func)(r->rtt_rt, r);			\
		} else {						\
			rtrequest((int) RTM_DELETE,			\
				  (struct sockaddr *)rt_key(r->rtt_rt),	\
				  0, 0, 0, 0);				\
		}							\
	} while (/*CONSTCOND*/0)
#else
#define RTTIMER_CALLOUT(r, fib)	do {					\
		if (r->rtt_func != NULL) {				\
			(*r->rtt_func)(r->rtt_rt, r);			\
		} else {						\
			rtrequest((int) RTM_DELETE,			\
				  (struct sockaddr *)rt_key(r->rtt_rt),	\
				  0, 0, 0, 0, fib);				\
		}							\
	} while (/*CONSTCOND*/0)
#endif
/*
 * Some subtle order problems with domain initialization mean that
 * we cannot count on this being run from rt_init before various
 * protocol initializations are done.  Therefore, we make sure
 * that this is run when the first queue is added...
 */

void
rt_timer_init(void)
{
	assert(rt_init_done == 0);

	LIST_INIT(&rttimer_queue_head);
	callout_init(&rt_timer_ch);
	callout_reset(&rt_timer_ch, hz, rt_timer_timer, NULL);
	rt_init_done = 1;
}

struct rttimer_queue *
rt_timer_queue_create(u_int timeout)
{
	struct rttimer_queue *rtq;

	if (rt_init_done == 0)
		rt_timer_init();

	R_Malloc(rtq, struct rttimer_queue *, sizeof *rtq);
	if (rtq == NULL)
		return (NULL);
	Bzero(rtq, sizeof *rtq);

	rtq->rtq_timeout = timeout;
	rtq->rtq_count = 0;
	TAILQ_INIT(&rtq->rtq_head);
	LIST_INSERT_HEAD(&rttimer_queue_head, rtq, rtq_link);

	return (rtq);
}

void
rt_timer_queue_change(struct rttimer_queue *rtq, long timeout)
{

	rtq->rtq_timeout = timeout;
}

void
rt_timer_queue_remove_all(struct rttimer_queue *rtq, int destroy)
{
	struct rttimer *r;

	while ((r = TAILQ_FIRST(&rtq->rtq_head)) != NULL) {
		LIST_REMOVE(r, rtt_link);
		TAILQ_REMOVE(&rtq->rtq_head, r, rtt_next);
		if (destroy)
#ifndef QNX_MFIB
			RTTIMER_CALLOUT(r);
#else
		{
			int fib;
			for (fib=0; fib < FIBS_MAX; fib++) {
				RTTIMER_CALLOUT(r, fib);
			}
		}
#endif
		/* we are already at splsoftnet */
		pool_put(&rttimer_pool, r);
		if (rtq->rtq_count > 0)
			rtq->rtq_count--;
		else
			printf("rt_timer_queue_remove_all: "
			    "rtq_count reached 0\n");
	}
}

void
rt_timer_queue_destroy(struct rttimer_queue *rtq, int destroy)
{

	rt_timer_queue_remove_all(rtq, destroy);

	LIST_REMOVE(rtq, rtq_link);

	/*
	 * Caller is responsible for freeing the rttimer_queue structure.
	 */
}

unsigned long
rt_timer_count(struct rttimer_queue *rtq)
{
	return rtq->rtq_count;
}

void
rt_timer_remove_all(struct rtentry *rt, int destroy)
{
	struct rttimer *r;

	while ((r = LIST_FIRST(&rt->rt_timer)) != NULL) {
		LIST_REMOVE(r, rtt_link);
		TAILQ_REMOVE(&r->rtt_queue->rtq_head, r, rtt_next);
		if (destroy)
#ifndef QNX_MFIB
			RTTIMER_CALLOUT(r);
#else
		{
			int fib;
			for (fib=0; fib < FIBS_MAX; fib++) {
				RTTIMER_CALLOUT(r, fib);
			}
		}
#endif
		if (r->rtt_queue->rtq_count > 0)
			r->rtt_queue->rtq_count--;
		else
			printf("rt_timer_remove_all: rtq_count reached 0\n");
		/* we are already at splsoftnet */
		pool_put(&rttimer_pool, r);
	}
}

int
rt_timer_add(struct rtentry *rt,
	void (*func)(struct rtentry *, struct rttimer *),
	struct rttimer_queue *queue)
{
	struct rttimer *r;
	int s;

	/*
	 * If there's already a timer with this action, destroy it before
	 * we add a new one.
	 */
	for (r = LIST_FIRST(&rt->rt_timer); r != NULL;
	     r = LIST_NEXT(r, rtt_link)) {
		if (r->rtt_func == func) {
			LIST_REMOVE(r, rtt_link);
			TAILQ_REMOVE(&r->rtt_queue->rtq_head, r, rtt_next);
			if (r->rtt_queue->rtq_count > 0)
				r->rtt_queue->rtq_count--;
			else
				printf("rt_timer_add: rtq_count reached 0\n");
			s = splsoftnet();
			pool_put(&rttimer_pool, r);
			splx(s);
			break;  /* only one per list, so we can quit... */
		}
	}

	s = splsoftnet();
	r = pool_get(&rttimer_pool, PR_NOWAIT);
	splx(s);
	if (r == NULL)
		return (ENOBUFS);
	Bzero(r, sizeof(*r));

	r->rtt_rt = rt;
	r->rtt_time = time_uptime;
	r->rtt_func = func;
	r->rtt_queue = queue;
	LIST_INSERT_HEAD(&rt->rt_timer, r, rtt_link);
	TAILQ_INSERT_TAIL(&queue->rtq_head, r, rtt_next);
	r->rtt_queue->rtq_count++;
#ifdef __QNXNTO__
	callout_reset_newer(&rt_timer_ch, hz * queue->rtq_timeout, rt_timer_timer, NULL);
#endif

	return (0);
}

/* ARGSUSED */
void
rt_timer_timer(void *arg)
{
	struct rttimer_queue *rtq;
	struct rttimer *r;
	int s;
#ifdef __QNXNTO__
	int nextimo = -1;
#endif

	s = splsoftnet();
	for (rtq = LIST_FIRST(&rttimer_queue_head); rtq != NULL;
	     rtq = LIST_NEXT(rtq, rtq_link)) {
		while ((r = TAILQ_FIRST(&rtq->rtq_head)) != NULL &&
		    (r->rtt_time + rtq->rtq_timeout) < time_uptime) {
			LIST_REMOVE(r, rtt_link);
			TAILQ_REMOVE(&rtq->rtq_head, r, rtt_next);
#ifndef QNX_MFIB
			RTTIMER_CALLOUT(r);
#else
			{
				int fib;
				for (fib=0; fib < FIBS_MAX; fib++) {
					RTTIMER_CALLOUT(r, fib);
				}
			}
#endif
			pool_put(&rttimer_pool, r);
			if (rtq->rtq_count > 0)
				rtq->rtq_count--;
			else
				printf("rt_timer_timer: rtq_count reached 0\n");
		}
#ifdef __QNXNTO__
		if (r != NULL) {
			nextimo = ulmin(nextimo, r->rtt_time + rtq->rtq_timeout - time_uptime + 1);
		}
#endif
	}
	splx(s);

#ifndef __QNXNTO__
	callout_reset(&rt_timer_ch, hz, rt_timer_timer, NULL);
#else
	if (nextimo > 0)
		callout_reset(&rt_timer_ch, hz * nextimo, rt_timer_timer, NULL);
#endif
}

#ifdef __QNXNTO__
int
rt_check(struct rtentry **rtp, struct rtentry **rt0p, struct sockaddr *dst,
    int irupt)
{
#define senderr(x) { error = x ; goto bad; }
	struct rtentry	*rt0, *rt, *rtg;
	int		error;


	rt0 = rt = *rt0p;

	if ((rt->rt_flags & RTF_UP) == 0) {
		if (irupt) /* QNX */
			senderr(EHOSTUNREACH);
#ifndef QNX_MFIB
		if ((rt0 = rt = rtalloc1(dst, 1)) != NULL)
#else
		if ((rt0 = rt = rtalloc1(dst, 1, NULL, rt0->fib)) != NULL)
#endif
		{
			rt->rt_refcnt--;
			/* XXX iface change. */
		} else
			senderr(EHOSTUNREACH);
	}
	if ((rt->rt_flags & RTF_GATEWAY) && dst->sa_family != AF_NS) {
		/*
		 * QNX
		 *
		 * Snap rt_gwroute.  If we're in the ipflow
		 * code we have incremented the gateway's refcnt
		 * so the rt_gwroute itself can't be freed out
		 * from under us; however, if the final dst
		 * (rt) is deleted (RTM_DELETE), the rt->rt_gwroute
		 * member may be NULL'd out.  This can happen
		 * at any point.
		 */
		if ((rtg = rt->rt_gwroute) == 0) {
			if (irupt) {
				/*
				 * QNX
				 *
				 * Don't get into routing manipulation
				 * if in unsafe interrupt context since
				 * there's no locking of any kind on
				 * the radix trees.  Note: ipflow code
				 * (only case this can happen?) should
				 * detect this and go through the full
				 * path.
				 */
				senderr(EHOSTUNREACH);
			}
			goto lookup;
		}
		rt = rtg;
		if ((rt->rt_flags & RTF_UP) == 0) {
			if (irupt) /* QNX  as above */
				senderr(EHOSTUNREACH);
			rtfree(rt); rt = rt0;
		lookup:
#ifndef QNX_MFIB
			rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1);
#else
			rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1, NULL, rt0->fib);
#endif
			if ((rt = rt->rt_gwroute) == 0)
				senderr(EHOSTUNREACH);
			/* the "G" test below also prevents rt == rt0 */
			if ((rt->rt_flags & RTF_GATEWAY)) {
				rt->rt_refcnt--;
				rt0->rt_gwroute = 0;
				senderr(EHOSTUNREACH);
			}
		}
	}
	if (rt->rt_flags & RTF_REJECT)
		if (rt->rt_rmx.rmx_expire == 0 ||
		    (u_long) time_uptime < rt->rt_rmx.rmx_expire)
			senderr(rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);

	*rtp = rt;
	*rt0p = rt0;

	return EOK;

bad:
	return error;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/route.c $ $Rev: 898338 $")
#endif
