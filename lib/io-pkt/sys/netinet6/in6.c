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

/*	$NetBSD: in6.c,v 1.119.2.1 2008/10/03 10:31:59 jdc Exp $	*/
/*	$KAME: in6.c,v 1.198 2001/07/18 09:12:38 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: in6.c,v 1.119.2.1 2008/10/03 10:31:59 jdc Exp $");

#include "opt_inet.h"
#include "opt_pfil_hooks.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <net/if_ether.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>
#ifdef __QNXNTO__
#include <netinet/in_pcb.h>
#endif

#include <net/net_osdep.h>

#ifdef PFIL_HOOKS
#include <net/pfil.h>
#endif

#ifdef QNX_MFIB
void in6_ifremloop_fib(struct ifaddr *ifa, int fib);
#endif

MALLOC_DEFINE(M_IP6OPT, "ip6_options", "IPv6 options");

/* enable backward compatibility code for obsoleted ioctls */
#define COMPAT_IN6IFIOCTL

/*
 * Definitions of some constant IP6 addresses.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
const struct in6_addr in6addr_nodelocal_allnodes =
	IN6ADDR_NODELOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allnodes =
	IN6ADDR_LINKLOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allrouters =
	IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

const struct in6_addr in6mask0 = IN6MASK0;
const struct in6_addr in6mask32 = IN6MASK32;
const struct in6_addr in6mask64 = IN6MASK64;
const struct in6_addr in6mask96 = IN6MASK96;
const struct in6_addr in6mask128 = IN6MASK128;

const struct sockaddr_in6 sa6_any = {sizeof(sa6_any), AF_INET6,
				     0, 0, IN6ADDR_ANY_INIT, 0};

static int in6_lifaddr_ioctl(struct socket *, u_long, caddr_t,
	struct ifnet *, struct lwp *);
static
int in6_ifinit(struct ifnet *, struct in6_ifaddr *,
	struct sockaddr_in6 *, int
#ifdef QNX_MFIB
	, int
#endif
	);

static void in6_unlink_ifa(struct in6_ifaddr *, struct ifnet *);

/*
 * Subroutine for in6_ifaddloop() and in6_ifremloop().
 * This routine does actual work.
 */
static void
in6_ifloop_request(int cmd, struct ifaddr *ifa
#ifdef QNX_MFIB
		, int fib
#endif
		)
{
	struct sockaddr_in6 lo_sa;
	struct sockaddr_in6 all1_sa;
	struct rtentry *nrt = NULL;
	int e;

	bzero(&lo_sa, sizeof(lo_sa));
	bzero(&all1_sa, sizeof(all1_sa));
	lo_sa.sin6_family = all1_sa.sin6_family = AF_INET6;
	lo_sa.sin6_len = all1_sa.sin6_len = sizeof(struct sockaddr_in6);
	lo_sa.sin6_addr = in6addr_loopback;
	all1_sa.sin6_addr = in6mask128;

	/*
	 * We specify the address itself as the gateway, and set the
	 * RTF_LLINFO flag, so that the corresponding host route would have
	 * the flag, and thus applications that assume traditional behavior
	 * would be happy.  Note that we assume the caller of the function
	 * (probably implicitly) set nd6_rtrequest() to ifa->ifa_rtrequest,
	 * which changes the outgoing interface to the loopback interface.
	 */
	e = rtrequest(cmd, ifa->ifa_addr, ifa->ifa_addr,
#ifndef QNX_MFIB
	    (struct sockaddr *)&all1_sa, RTF_UP|RTF_HOST|RTF_LLINFO, &nrt);
#else
	    (struct sockaddr *)&all1_sa, RTF_UP|RTF_HOST|RTF_LLINFO, &nrt, fib);
#endif
	if (e != 0) {
		log(LOG_ERR, "in6_ifloop_request: "
		    "%s operation failed for %s (errno=%d)\n",
		    cmd == RTM_ADD ? "ADD" : "DELETE",
		    ip6_sprintf(&((struct in6_ifaddr *)ifa)->ia_addr.sin6_addr),
		    e);
	}

	/*
	 * Make sure rt_ifa be equal to IFA, the second argument of the
	 * function.
	 * We need this because when we refer to rt_ifa->ia6_flags in
	 * ip6_input, we assume that the rt_ifa points to the address instead
	 * of the loopback address.
	 */
	if (cmd == RTM_ADD && nrt && ifa != nrt->rt_ifa)
		rt_replace_ifa(nrt, ifa);

	/*
	 * Report the addition/removal of the address to the routing socket.
	 * XXX: since we called rtinit for a p2p interface with a destination,
	 *      we end up reporting twice in such a case.  Should we rather
	 *      omit the second report?
	 */
	if (nrt) {
		rt_newaddrmsg(cmd, ifa, e, nrt);
		if (cmd == RTM_DELETE) {
			if (nrt->rt_refcnt <= 0) {
				/* XXX: we should free the entry ourselves. */
				nrt->rt_refcnt++;
				rtfree(nrt);
			}
		} else {
			/* the cmd must be RTM_ADD here */
			nrt->rt_refcnt--;
		}
	}
}

/*
 * Add ownaddr as loopback rtentry.  We previously add the route only if
 * necessary (ex. on a p2p link).  However, since we now manage addresses
 * separately from prefixes, we should always add the route.  We can't
 * rely on the cloning mechanism from the corresponding interface route
 * any more.
 */
void
in6_ifaddloop(struct ifaddr *ifa
#ifdef QNX_MFIB
		, int fib
#endif
		)
{
	struct rtentry *rt;

	/* If there is no loopback entry, allocate one. */
#ifndef QNX_MFIB
	rt = rtalloc1(ifa->ifa_addr, 0);	/* XXX - does this need an ifp hint? */
#else
	rt = rtalloc1(ifa->ifa_addr, 0, NULL, fib); /* XXX - does this need an ifp hint? */
#endif
	if (rt == NULL || (rt->rt_flags & RTF_HOST) == 0 ||
	    (rt->rt_ifp->if_flags & IFF_LOOPBACK) == 0)
		in6_ifloop_request(RTM_ADD, ifa
#ifdef QNX_MFIB
				, fib
#endif
				);
	if (rt)
		rt->rt_refcnt--;
}

/*
 * Remove loopback rtentry of ownaddr generated by in6_ifaddloop(),
 * if it exists.
 */
void
in6_ifremloop(struct ifaddr *ifa)
#ifdef QNX_MFIB
{
	in6_ifremloop_fib(ifa, -1);
}
void
in6_ifremloop_fib(struct ifaddr *ifa, int fib)
#endif
{
	struct in6_ifaddr *ia;
	struct rtentry *rt;
	int ia_count = 0;

	/*
	 * Some of BSD variants do not remove cloned routes
	 * from an interface direct route, when removing the direct route
	 * (see comments in net/net_osdep.h).  Even for variants that do remove
	 * cloned routes, they could fail to remove the cloned routes when
	 * we handle multple addresses that share a common prefix.
	 * So, we should remove the route corresponding to the deleted address.
	 */

	/*
	 * Delete the entry only if exact one ifa exists.  More than one ifa
	 * can exist if we assign a same single address to multiple
	 * (probably p2p) interfaces.
	 * XXX: we should avoid such a configuration in IPv6...
	 */
	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (IN6_ARE_ADDR_EQUAL(IFA_IN6(ifa), &ia->ia_addr.sin6_addr)) {
#ifdef QNX_MFIB
			if (fib != -1) {
				if (ia->ia_ifp != ifa->ifa_ifp) {
					/* different interface, check if both are member of this fib */
					if (!if_get_fib_enabled(ia->ia_ifp, fib)) {
						/* only count i/fs that are members of this fib*/
						continue;
					}
				}
			}
#endif
			ia_count++;
			if (ia_count > 1)
				break;
		}
	}

	if (ia_count == 1) {
		/*
		 * Before deleting, check if a corresponding loopbacked host
		 * route surely exists.  With this check, we can avoid to
		 * delete an interface direct route whose destination is same
		 * as the address being removed.  This can happen when removing
		 * a subnet-router anycast address on an interface attahced
		 * to a shared medium.
		 */
#ifndef QNX_MFIB
		rt = rtalloc1(ifa->ifa_addr, 0);	/* XXX - does this need an ifp hint? */
#else
		int maxloops = (fib == -1)? FIBS_MAX:1; /* if fib != -1, RTM_DELETE only for that fib */
		if (fib == -1) {
			fib = if_get_next_fib(ifa->ifa_ifp, fib);
		}
		while (fib < FIBS_MAX && maxloops > 0) {
			maxloops--;
			rt = rtalloc1(ifa->ifa_addr, 0, NULL, fib);	/* XXX - does this need an ifp hint? */
#endif
		if (rt != NULL && (rt->rt_flags & RTF_HOST) != 0 &&
		    (rt->rt_ifp->if_flags & IFF_LOOPBACK) != 0) {
			rt->rt_refcnt--;
			in6_ifloop_request(RTM_DELETE, ifa
#ifdef QNX_MFIB
					, fib
#endif
					);
		}
#ifdef QNX_MFIB
		fib = if_get_next_fib(ifa->ifa_ifp, fib);
		}
#endif
	}
}

int
in6_mask2len(mask, lim0)
	struct in6_addr *mask;
	u_char *lim0;
{
	int x = 0, y;
	u_char *lim = lim0, *p;

	/* ignore the scope_id part */
	if (lim0 == NULL || lim0 - (u_char *)mask > sizeof(*mask))
		lim = (u_char *)mask + sizeof(*mask);
	for (p = (u_char *)mask; p < lim; x++, p++) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < 8; y++) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/*
	 * when the limit pointer is given, do a stricter check on the
	 * remaining bits.
	 */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return -1;
		for (p = p + 1; p < lim; p++)
			if (*p != 0)
				return -1;
	}

	return x * 8 + y;
}

#define ifa2ia6(ifa)	((struct in6_ifaddr *)(ifa))
#define ia62ifa(ia6)	(&((ia6)->ia_ifa))

int
in6_control(so, cmd, data, ifp, l)
	struct	socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
	struct lwp *l;
{
	struct	in6_ifreq *ifr = (struct in6_ifreq *)data;
	struct	in6_ifaddr *ia = NULL;
	struct	in6_aliasreq *ifra = (struct in6_aliasreq *)data;
	struct sockaddr_in6 *sa6;
	int error, privileged;

	privileged = 0;
	if (l && !kauth_authorize_generic(l->l_cred,
	    KAUTH_GENERIC_ISSUSER, &l->l_acflag))
		privileged++;

	switch (cmd) {
	/*
	 * XXX: Fix me, once we fix SIOCSIFADDR, SIOCIFDSTADDR, etc.
	 */
	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
#ifdef SIOCSIFCONF_X26
	case SIOCSIFCONF_X25:
#endif
		return EOPNOTSUPP;
	case SIOCGETSGCNT_IN6:
	case SIOCGETMIFCNT_IN6:
		return mrt6_ioctl(cmd, data);
	}

	if (ifp == NULL)
		return EOPNOTSUPP;

	switch (cmd) {
	case SIOCSNDFLUSH_IN6:
	case SIOCSPFXFLUSH_IN6:
	case SIOCSRTRFLUSH_IN6:
#ifdef __QNXNTO__
	case SIOCSPFXFLUSHIF_IN6:
	case SIOCSRTRFLUSHIF_IN6:
#endif
	case SIOCSDEFIFACE_IN6:
	case SIOCSIFINFO_FLAGS:
	case SIOCSIFINFO_IN6:
		if (!privileged)
			return EPERM;
		/* FALLTHROUGH */
	case OSIOCGIFINFO_IN6:
	case SIOCGIFINFO_IN6:
	case SIOCGDRLST_IN6:
	case SIOCGPRLST_IN6:
	case SIOCGNBRINFO_IN6:
	case SIOCGDEFIFACE_IN6:
		return nd6_ioctl(cmd, data, ifp);
	}

	switch (cmd) {
	case SIOCSIFPREFIX_IN6:
	case SIOCDIFPREFIX_IN6:
	case SIOCAIFPREFIX_IN6:
	case SIOCCIFPREFIX_IN6:
	case SIOCSGIFPREFIX_IN6:
	case SIOCGIFPREFIX_IN6:
		log(LOG_NOTICE,
		    "prefix ioctls are now invalidated. "
		    "please use ifconfig.\n");
		return EOPNOTSUPP;
	}

	switch (cmd) {
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		if (!privileged)
			return EPERM;
		/* FALLTHROUGH */
	case SIOCGLIFADDR:
		return in6_lifaddr_ioctl(so, cmd, data, ifp, l);
	}

	/*
	 * Find address for this interface, if it exists.
	 *
	 * In netinet code, we have checked ifra_addr in SIOCSIF*ADDR operation
	 * only, and used the first interface address as the target of other
	 * operations (without checking ifra_addr).  This was because netinet
	 * code/API assumed at most 1 interface address per interface.
	 * Since IPv6 allows a node to assign multiple addresses
	 * on a single interface, we almost always look and check the
	 * presence of ifra_addr, and reject invalid ones here.
	 * It also decreases duplicated code among SIOC*_IN6 operations.
	 */
	switch (cmd) {
	case SIOCAIFADDR_IN6:
	case SIOCSIFPHYADDR_IN6:
		sa6 = &ifra->ifra_addr;
		break;
	case SIOCSIFADDR_IN6:
	case SIOCGIFADDR_IN6:
	case SIOCSIFDSTADDR_IN6:
	case SIOCSIFNETMASK_IN6:
	case SIOCGIFDSTADDR_IN6:
	case SIOCGIFNETMASK_IN6:
	case SIOCDIFADDR_IN6:
	case SIOCGIFPSRCADDR_IN6:
	case SIOCGIFPDSTADDR_IN6:
	case SIOCGIFAFLAG_IN6:
	case SIOCSNDFLUSH_IN6:
	case SIOCSPFXFLUSH_IN6:
	case SIOCSRTRFLUSH_IN6:
#ifdef __QNXNTO__
	case SIOCSPFXFLUSHIF_IN6:
	case SIOCSRTRFLUSHIF_IN6:
#endif
	case SIOCGIFALIFETIME_IN6:
	case SIOCSIFALIFETIME_IN6:
	case SIOCGIFSTAT_IN6:
	case SIOCGIFSTAT_ICMP6:
		sa6 = &ifr->ifr_addr;
		break;
	default:
		sa6 = NULL;
		break;
	}
	if (sa6 && sa6->sin6_family == AF_INET6) {
		if (sa6->sin6_scope_id != 0)
			error = sa6_embedscope(sa6, 0);
		else
			error = in6_setscope(&sa6->sin6_addr, ifp, NULL);
		if (error != 0)
			return error;
		ia = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);
	} else
		ia = NULL;

	switch (cmd) {
	case SIOCSIFADDR_IN6:
	case SIOCSIFDSTADDR_IN6:
	case SIOCSIFNETMASK_IN6:
		/*
		 * Since IPv6 allows a node to assign multiple addresses
		 * on a single interface, SIOCSIFxxx ioctls are deprecated.
		 */
		return EINVAL;

	case SIOCDIFADDR_IN6:
		/*
		 * for IPv4, we look for existing in_ifaddr here to allow
		 * "ifconfig if0 delete" to remove the first IPv4 address on
		 * the interface.  For IPv6, as the spec allows multiple
		 * interface address from the day one, we consider "remove the
		 * first one" semantics to be not preferable.
		 */
		if (ia == NULL)
			return EADDRNOTAVAIL;
		/* FALLTHROUGH */
	case SIOCAIFADDR_IN6:
		/*
		 * We always require users to specify a valid IPv6 address for
		 * the corresponding operation.
		 */
		if (ifra->ifra_addr.sin6_family != AF_INET6 ||
		    ifra->ifra_addr.sin6_len != sizeof(struct sockaddr_in6))
			return EAFNOSUPPORT;
		if (!privileged)
			return EPERM;

		break;

	case SIOCGIFADDR_IN6:
		/* This interface is basically deprecated. use SIOCGIFCONF. */
		/* FALLTHROUGH */
	case SIOCGIFAFLAG_IN6:
	case SIOCGIFNETMASK_IN6:
	case SIOCGIFDSTADDR_IN6:
	case SIOCGIFALIFETIME_IN6:
		/* must think again about its semantics */
		if (ia == NULL)
			return EADDRNOTAVAIL;
		break;
	case SIOCSIFALIFETIME_IN6:
	    {
		struct in6_addrlifetime *lt;

		if (!privileged)
			return EPERM;
		if (ia == NULL)
			return EADDRNOTAVAIL;
		/* sanity for overflow - beware unsigned */
		lt = &ifr->ifr_ifru.ifru_lifetime;
		if (lt->ia6t_vltime != ND6_INFINITE_LIFETIME
		 && lt->ia6t_vltime + time_second < time_second) {
			return EINVAL;
		}
		if (lt->ia6t_pltime != ND6_INFINITE_LIFETIME
		 && lt->ia6t_pltime + time_second < time_second) {
			return EINVAL;
		}
		break;
	    }
	}

	switch (cmd) {

	case SIOCGIFADDR_IN6:
		ifr->ifr_addr = ia->ia_addr;
		if ((error = sa6_recoverscope(&ifr->ifr_addr)) != 0)
			return error;
		break;

	case SIOCGIFDSTADDR_IN6:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return EINVAL;
		/*
		 * XXX: should we check if ifa_dstaddr is NULL and return
		 * an error?
		 */
		ifr->ifr_dstaddr = ia->ia_dstaddr;
		if ((error = sa6_recoverscope(&ifr->ifr_dstaddr)) != 0)
			return error;
		break;

	case SIOCGIFNETMASK_IN6:
		ifr->ifr_addr = ia->ia_prefixmask;
		break;

	case SIOCGIFAFLAG_IN6:
		ifr->ifr_ifru.ifru_flags6 = ia->ia6_flags;
		break;

	case SIOCGIFSTAT_IN6:
		if (ifp == NULL)
			return EINVAL;
		bzero(&ifr->ifr_ifru.ifru_stat,
		    sizeof(ifr->ifr_ifru.ifru_stat));
		ifr->ifr_ifru.ifru_stat =
		    *((struct in6_ifextra *)ifp->if_afdata[AF_INET6])->in6_ifstat;
		break;

	case SIOCGIFSTAT_ICMP6:
		if (ifp == NULL)
			return EINVAL;
		bzero(&ifr->ifr_ifru.ifru_icmp6stat,
		    sizeof(ifr->ifr_ifru.ifru_icmp6stat));
		ifr->ifr_ifru.ifru_icmp6stat =
		    *((struct in6_ifextra *)ifp->if_afdata[AF_INET6])->icmp6_ifstat;
		break;

	case SIOCGIFALIFETIME_IN6:
		ifr->ifr_ifru.ifru_lifetime = ia->ia6_lifetime;
#ifndef __QNXNTO__
		if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
			time_t maxexpire;
			struct in6_addrlifetime *retlt =
			    &ifr->ifr_ifru.ifru_lifetime;

			/*
			 * XXX: adjust expiration time assuming time_t is
			 * signed.
			 */
			maxexpire = ((time_t)~0) &
			    ~((time_t)1 << ((sizeof(maxexpire) * 8) - 1));
			if (ia->ia6_lifetime.ia6t_vltime <
			    maxexpire - ia->ia6_updatetime) {
				retlt->ia6t_expire = ia->ia6_updatetime +
#ifndef __QNXNTO__
				    ia->ia6_lifetime.ia6t_vltime;
#else
				    tireal_ti_small(ia->ia6_lifetime.ia6t_vltime);
#endif
			} else
				retlt->ia6t_expire = maxexpire;
		}
		if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
			time_t maxexpire;
			struct in6_addrlifetime *retlt =
			    &ifr->ifr_ifru.ifru_lifetime;

			/*
			 * XXX: adjust expiration time assuming time_t is
			 * signed.
			 */
			maxexpire = ((time_t)~0) &
			    ~((time_t)1 << ((sizeof(maxexpire) * 8) - 1));
			if (ia->ia6_lifetime.ia6t_pltime <
			    maxexpire - ia->ia6_updatetime) {
				retlt->ia6t_preferred = ia->ia6_updatetime +
#ifndef __QNXNTO__
				    ia->ia6_lifetime.ia6t_pltime;
#else
				    tireal_ti_small(ia->ia6_lifetime.ia6t_pltime);
#endif
			} else
				retlt->ia6t_preferred = maxexpire;
		}
#else
		/*
		 * Convert then check that doing so didn't roll over.
		 * Might already be 0 (infinite).
		 */
		ifr->ifr_ifru.ifru_lifetime.ia6t_expire =
		    ti_tireal(ifr->ifr_ifru.ifru_lifetime.ia6t_expire);
		if (ifr->ifr_ifru.ifru_lifetime.ia6t_expire < time_second) {
			ifr->ifr_ifru.ifru_lifetime.ia6t_expire = 0;
			ifr->ifr_ifru.ifru_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		}

		ifr->ifr_ifru.ifru_lifetime.ia6t_preferred =
		    ti_tireal(ifr->ifr_ifru.ifru_lifetime.ia6t_preferred);
		if (ifr->ifr_ifru.ifru_lifetime.ia6t_preferred < time_second) {
			ifr->ifr_ifru.ifru_lifetime.ia6t_preferred = 0;
			ifr->ifr_ifru.ifru_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
		}
#endif
		break;

	case SIOCSIFALIFETIME_IN6:
		ia->ia6_lifetime = ifr->ifr_ifru.ifru_lifetime;
		/* for sanity */
		if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
			ia->ia6_lifetime.ia6t_expire =
#ifndef __QNXNTO__
				time_second + ia->ia6_lifetime.ia6t_vltime;
#else
				time_second + tireal_ti_small(ia->ia6_lifetime.ia6t_vltime);
				if (ia->ia6_lifetime.ia6t_expire < time_second) {
					ia->ia6_lifetime.ia6t_expire = 0;
					ia->ia6_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
				}
#endif
		} else
			ia->ia6_lifetime.ia6t_expire = 0;
		if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
			ia->ia6_lifetime.ia6t_preferred =
#ifndef __QNXNTO__
				time_second + ia->ia6_lifetime.ia6t_pltime;
#else
				time_second + tireal_ti_small(ia->ia6_lifetime.ia6t_pltime);
				if (ia->ia6_lifetime.ia6t_preferred < time_second) {
					ia->ia6_lifetime.ia6t_preferred = 0;
					ia->ia6_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
				}
#endif
		} else
			ia->ia6_lifetime.ia6t_preferred = 0;
#ifdef __QNXNTO__
		nd6_timer_kick();
#endif
		break;

	case SIOCAIFADDR_IN6:
	{
		int i;
		struct nd_prefixctl pr0;
		struct nd_prefix *pr;

		/* reject read-only flags */
		if ((ifra->ifra_flags & IN6_IFF_DUPLICATED) != 0 ||
		    (ifra->ifra_flags & IN6_IFF_DETACHED) != 0 ||
		    (ifra->ifra_flags & IN6_IFF_NODAD) != 0 ||
		    (ifra->ifra_flags & IN6_IFF_AUTOCONF) != 0) {
			return EINVAL;
		}
		/*
		 * first, make or update the interface address structure,
		 * and link it to the list.
		 */
		if ((error = in6_update_ifa(ifp, ifra, ia, 0)) != 0)
			return error;
		if ((ia = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr))
		    == NULL) {
		    	/*
			 * this can happen when the user specify the 0 valid
			 * lifetime.
			 */
			break;
		}

		/*
		 * then, make the prefix on-link on the interface.
		 * XXX: we'd rather create the prefix before the address, but
		 * we need at least one address to install the corresponding
		 * interface route, so we configure the address first.
		 */

		/*
		 * convert mask to prefix length (prefixmask has already
		 * been validated in in6_update_ifa().
		 */
		bzero(&pr0, sizeof(pr0));
		pr0.ndpr_ifp = ifp;
		pr0.ndpr_plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr,
		    NULL);
		if (pr0.ndpr_plen == 128) {
			break;	/* we don't need to install a host route. */
		}
		pr0.ndpr_prefix = ifra->ifra_addr;
		/* apply the mask for safety. */
		for (i = 0; i < 4; i++) {
			pr0.ndpr_prefix.sin6_addr.s6_addr32[i] &=
			    ifra->ifra_prefixmask.sin6_addr.s6_addr32[i];
		}
		/*
		 * XXX: since we don't have an API to set prefix (not address)
		 * lifetimes, we just use the same lifetimes as addresses.
		 * The (temporarily) installed lifetimes can be overridden by
		 * later advertised RAs (when accept_rtadv is non 0), which is
		 * an intended behavior.
		 */
		pr0.ndpr_raf_onlink = 1; /* should be configurable? */
		pr0.ndpr_raf_auto =
		    ((ifra->ifra_flags & IN6_IFF_AUTOCONF) != 0);
		pr0.ndpr_vltime = ifra->ifra_lifetime.ia6t_vltime;
		pr0.ndpr_pltime = ifra->ifra_lifetime.ia6t_pltime;

		/* add the prefix if not yet. */
		if ((pr = nd6_prefix_lookup(&pr0)) == NULL) {
			/*
			 * nd6_prelist_add will install the corresponding
			 * interface route.
			 */
			if ((error = nd6_prelist_add(&pr0, NULL, &pr)) != 0)
				return error;
			if (pr == NULL) {
				log(LOG_ERR, "nd6_prelist_add succeeded but "
				    "no prefix\n");
				return EINVAL; /* XXX panic here? */
			}
		}

		/* relate the address to the prefix */
		if (ia->ia6_ndpr == NULL) {
			ia->ia6_ndpr = pr;
			pr->ndpr_refcnt++;

			/*
			 * If this is the first autoconf address from the
			 * prefix, create a temporary address as well
			 * (when required).
			 */
			if ((ia->ia6_flags & IN6_IFF_AUTOCONF) &&
			    ip6_use_tempaddr && pr->ndpr_refcnt == 1) {
				int e;
				if ((e = in6_tmpifadd(ia, 1, 0)) != 0) {
					log(LOG_NOTICE, "in6_control: failed "
					    "to create a temporary address, "
					    "errno=%d\n", e);
				}
			}
		}

		/*
		 * this might affect the status of autoconfigured addresses,
		 * that is, this address might make other addresses detached.
		 */
		pfxlist_onlink_check();

#ifdef PFIL_HOOKS
		(void)pfil_run_hooks(&if_pfil, (struct mbuf **)SIOCAIFADDR_IN6,
#ifndef QNX_MFIB
		    ifp, PFIL_IFADDR);
#else
	        ifp, PFIL_IFADDR, if_get_first_fib(ifp));
#endif
#endif
#ifdef __QNXNTO__
		nd6_timer_kick();
#endif

		break;
	}

	case SIOCDIFADDR_IN6:
	{
		struct nd_prefix *pr;

		/*
		 * If the address being deleted is the only one that owns
		 * the corresponding prefix, expire the prefix as well.
		 * XXX: theoretically, we don't have to worry about such
		 * relationship, since we separate the address management
		 * and the prefix management.  We do this, however, to provide
		 * as much backward compatibility as possible in terms of
		 * the ioctl operation.
		 * Note that in6_purgeaddr() will decrement ndpr_refcnt.
		 */
		pr = ia->ia6_ndpr;
		in6_purgeaddr(&ia->ia_ifa);
		if (pr && pr->ndpr_refcnt == 0)
			prelist_remove(pr);
#ifdef PFIL_HOOKS
		(void)pfil_run_hooks(&if_pfil, (struct mbuf **)SIOCDIFADDR_IN6,
#ifndef QNX_MFIB
		    ifp, PFIL_IFADDR);
#else
	        ifp, PFIL_IFADDR, if_get_first_fib(ifp));
#endif
#endif
		break;
	}

	default:
		if (ifp == NULL || ifp->if_ioctl == 0)
			return EOPNOTSUPP;
		error = ((*ifp->if_ioctl)(ifp, cmd, data));
		return error;
	}

	return 0;
}

/*
 * Update parameters of an IPv6 interface address.
 * If necessary, a new entry is created and linked into address chains.
 * This function is separated from in6_control().
 * XXX: should this be performed under splnet()?
 */
int
in6_update_ifa(ifp, ifra, ia, flags)
	struct ifnet *ifp;
	struct in6_aliasreq *ifra;
	struct in6_ifaddr *ia;
	int flags;
{
	int error = 0, hostIsNew = 0, plen = -1;
	struct in6_ifaddr *oia;
	struct sockaddr_in6 dst6;
	struct in6_addrlifetime *lt;
	struct in6_multi_mship *imm;
	struct in6_multi *in6m_sol;
	struct rtentry *rt;
	int dad_delay;

	in6m_sol = NULL;

	/* Validate parameters */
	if (ifp == NULL || ifra == NULL) /* this maybe redundant */
		return EINVAL;

	/*
	 * The destination address for a p2p link must have a family
	 * of AF_UNSPEC or AF_INET6.
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0 &&
	    ifra->ifra_dstaddr.sin6_family != AF_INET6 &&
	    ifra->ifra_dstaddr.sin6_family != AF_UNSPEC)
		return EAFNOSUPPORT;
	/*
	 * validate ifra_prefixmask.  don't check sin6_family, netmask
	 * does not carry fields other than sin6_len.
	 */
	if (ifra->ifra_prefixmask.sin6_len > sizeof(struct sockaddr_in6))
		return EINVAL;
	/*
	 * Because the IPv6 address architecture is classless, we require
	 * users to specify a (non 0) prefix length (mask) for a new address.
	 * We also require the prefix (when specified) mask is valid, and thus
	 * reject a non-consecutive mask.
	 */
	if (ia == NULL && ifra->ifra_prefixmask.sin6_len == 0)
		return EINVAL;
	if (ifra->ifra_prefixmask.sin6_len != 0) {
		plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr,
		    (u_char *)&ifra->ifra_prefixmask +
		    ifra->ifra_prefixmask.sin6_len);
		if (plen <= 0)
			return EINVAL;
	} else {
		/*
		 * In this case, ia must not be NULL.  We just use its prefix
		 * length.
		 */
		plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL);
	}
	/*
	 * If the destination address on a p2p interface is specified,
	 * and the address is a scoped one, validate/set the scope
	 * zone identifier.
	 */
	dst6 = ifra->ifra_dstaddr;
	if ((ifp->if_flags & (IFF_POINTOPOINT|IFF_LOOPBACK)) != 0 &&
	    (dst6.sin6_family == AF_INET6)) {
		struct in6_addr in6_tmp;
		u_int32_t zoneid;

		in6_tmp = dst6.sin6_addr;
		if (in6_setscope(&in6_tmp, ifp, &zoneid))
			return EINVAL; /* XXX: should be impossible */

		if (dst6.sin6_scope_id != 0) {
			if (dst6.sin6_scope_id != zoneid)
				return EINVAL;
		} else		/* user omit to specify the ID. */
			dst6.sin6_scope_id = zoneid;

		/* convert into the internal form */
		if (sa6_embedscope(&dst6, 0))
			return EINVAL; /* XXX: should be impossible */
	}
	/*
	 * The destination address can be specified only for a p2p or a
	 * loopback interface.  If specified, the corresponding prefix length
	 * must be 128.
	 */
	if (ifra->ifra_dstaddr.sin6_family == AF_INET6) {
#ifdef FORCE_P2PPLEN
		int i;
#endif

		if ((ifp->if_flags & (IFF_POINTOPOINT|IFF_LOOPBACK)) == 0) {
			/* XXX: noisy message */
			nd6log((LOG_INFO, "in6_update_ifa: a destination can "
			    "be specified for a p2p or a loopback IF only\n"));
			return EINVAL;
		}
		if (plen != 128) {
			nd6log((LOG_INFO, "in6_update_ifa: prefixlen should "
			    "be 128 when dstaddr is specified\n"));
#ifdef FORCE_P2PPLEN
			/*
			 * To be compatible with old configurations,
			 * such as ifconfig gif0 inet6 2001::1 2001::2
			 * prefixlen 126, we override the specified
			 * prefixmask as if the prefix length was 128.
			 */
			ifra->ifra_prefixmask.sin6_len =
			    sizeof(struct sockaddr_in6);
			for (i = 0; i < 4; i++)
				ifra->ifra_prefixmask.sin6_addr.s6_addr32[i] =
				    0xffffffff;
			plen = 128;
#else
			return EINVAL;
#endif
		}
	}
	/* lifetime consistency check */
	lt = &ifra->ifra_lifetime;
	if (lt->ia6t_pltime > lt->ia6t_vltime)
		return EINVAL;
	if (lt->ia6t_vltime == 0) {
		/*
		 * the following log might be noisy, but this is a typical
		 * configuration mistake or a tool's bug.
		 */
		nd6log((LOG_INFO,
		    "in6_update_ifa: valid lifetime is 0 for %s\n",
		    ip6_sprintf(&ifra->ifra_addr.sin6_addr)));

		if (ia == NULL)
			return 0; /* there's nothing to do */
	}

	/*
	 * If this is a new address, allocate a new ifaddr and link it
	 * into chains.
	 */
	if (ia == NULL) {
		hostIsNew = 1;
		/*
		 * When in6_update_ifa() is called in a process of a received
		 * RA, it is called under an interrupt context.  So, we should
		 * call malloc with M_NOWAIT.
		 */
		ia = (struct in6_ifaddr *) malloc(sizeof(*ia), M_IFADDR,
		    M_NOWAIT);
		if (ia == NULL)
			return ENOBUFS;
		bzero((caddr_t)ia, sizeof(*ia));
		LIST_INIT(&ia->ia6_memberships);
		/* Initialize the address and masks, and put time stamp */
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
#ifdef __QNXNTO__
		/* set the rtrequest function to create llinfo */
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
#endif
		ia->ia_addr.sin6_family = AF_INET6;
		ia->ia_addr.sin6_len = sizeof(ia->ia_addr);
		ia->ia6_createtime = time_second;
		if ((ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) != 0) {
			/*
			 * XXX: some functions expect that ifa_dstaddr is not
			 * NULL for p2p interfaces.
			 */
			ia->ia_ifa.ifa_dstaddr =
			    (struct sockaddr *)&ia->ia_dstaddr;
		} else {
			ia->ia_ifa.ifa_dstaddr = NULL;
		}
		ia->ia_ifa.ifa_netmask =
		    (struct sockaddr *)&ia->ia_prefixmask;

		ia->ia_ifp = ifp;
		if ((oia = in6_ifaddr) != NULL) {
			for ( ; oia->ia_next; oia = oia->ia_next)
				continue;
			oia->ia_next = ia;
		} else
			in6_ifaddr = ia;
		/* gain a refcnt for the link from in6_ifaddr */
		IFAREF(&ia->ia_ifa);

#ifndef __QNXNTO__
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, &ia->ia_ifa,
				  ifa_list);
		/* gain another refcnt for the link from if_addrlist */
		IFAREF(&ia->ia_ifa);
#else /* brought in later link level routines */
		ifa_insert(ifp, &ia->ia_ifa);
#endif
	}

#ifndef __QNXNTO__
	/* update timestamp */
	ia->ia6_updatetime = time_second;
#endif

	/* set prefix mask */
	if (ifra->ifra_prefixmask.sin6_len) {
		/*
		 * We prohibit changing the prefix length of an existing
		 * address, because
		 * + such an operation should be rare in IPv6, and
		 * + the operation would confuse prefix management.
		 */
		if (ia->ia_prefixmask.sin6_len &&
		    in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL) != plen) {
			nd6log((LOG_INFO, "in6_update_ifa: the prefix length of an"
			    " existing (%s) address should not be changed\n",
			    ip6_sprintf(&ia->ia_addr.sin6_addr)));
			error = EINVAL;
			goto unlink;
		}
		ia->ia_prefixmask = ifra->ifra_prefixmask;
#ifdef __QNXNTO__
		/*
		 * If called as a result of SIOCAIFADDR_IN6, userland may
		 * not have set this in ifra->ifra_prefixmask.sin6_family.
		 * We set it ourselves when attaching loopback so make
		 * this consistent.
		 */
		ia->ia_prefixmask.sin6_family = AF_INET6;
#endif
	}

	/*
	 * If a new destination address is specified, scrub the old one and
	 * install the new destination.  Note that the interface must be
	 * p2p or loopback (see the check above.)
	 */
	if (dst6.sin6_family == AF_INET6 &&
	    !IN6_ARE_ADDR_EQUAL(&dst6.sin6_addr, &ia->ia_dstaddr.sin6_addr)) {
#ifdef QNX_MFIB
		/*
		 * nuke the old addr on all fibs this ifp it a member of
		 */
		int fib = -1;
		while((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX) {
#endif
		if ((ia->ia_flags & IFA_ROUTE) != 0 &&
#ifndef QNX_MFIB
		    rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST) != 0) {
#else
		    rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST, fib) != 0) {
#endif
			nd6log((LOG_ERR, "in6_update_ifa: failed to remove "
			    "a route to the old destination: %s\n",
			    ip6_sprintf(&ia->ia_addr.sin6_addr)));
			/* proceed anyway... */
		} else
			ia->ia_flags &= ~IFA_ROUTE;
#ifdef QNX_MFIB
		}
#endif
		ia->ia_dstaddr = dst6;
	}

	/*
	 * Set lifetimes.  We do not refer to ia6t_expire and ia6t_preferred
	 * to see if the address is deprecated or invalidated, but initialize
	 * these members for applications.
	 */
	ia->ia6_lifetime = ifra->ifra_lifetime;
#ifdef __QNXNTO__
	nd6_timer_kick();
#endif
	if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_expire =
#ifndef __QNXNTO__
		    time_second + ia->ia6_lifetime.ia6t_vltime;
#else
		    time_second + tireal_ti_small(ia->ia6_lifetime.ia6t_vltime);
		    if (ia->ia6_lifetime.ia6t_expire < time_second) {
		        ia->ia6_lifetime.ia6t_expire = 0;
			ia->ia6_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		    }
#endif
	} else
		ia->ia6_lifetime.ia6t_expire = 0;
	if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_preferred =
#ifndef __QNXNTO__
		    time_second + ia->ia6_lifetime.ia6t_pltime;
#else
		    time_second + tireal_ti_small(ia->ia6_lifetime.ia6t_pltime);
		    if (ia->ia6_lifetime.ia6t_preferred < time_second) {
			ia->ia6_lifetime.ia6t_preferred = 0;
			ia->ia6_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
		    }
#endif
	} else
		ia->ia6_lifetime.ia6t_preferred = 0;

	/* reset the interface and routing table appropriately. */
	if ((error = in6_ifinit(ifp, ia, &ifra->ifra_addr, hostIsNew
#ifdef QNX_MFIB
			, -1
#endif
	)) != 0)
		goto unlink;

	/*
	 * configure address flags.
	 */
	ia->ia6_flags = ifra->ifra_flags;
	/*
	 * backward compatibility - if IN6_IFF_DEPRECATED is set from the
	 * userland, make it deprecated.
	 */
	if ((ifra->ifra_flags & IN6_IFF_DEPRECATED) != 0) {
		ia->ia6_lifetime.ia6t_pltime = 0;
		ia->ia6_lifetime.ia6t_preferred = time_second;
	}

	/*
	 * Make the address tentative before joining multicast addresses,
	 * so that corresponding MLD responses would not have a tentative
	 * source address.
	 */
	ia->ia6_flags &= ~IN6_IFF_DUPLICATED;	/* safety */
	if (hostIsNew && in6if_do_dad(ifp)) 
		ia->ia6_flags |= IN6_IFF_TENTATIVE;

	/*
	 * We are done if we have simply modified an existing address.
	 */
	if (!hostIsNew)
		return error;

	/*
	 * Beyond this point, we should call in6_purgeaddr upon an error,
	 * not just go to unlink.
	 */

	/* join necessary multicast groups */
	if ((ifp->if_flags & IFF_MULTICAST) != 0) {
		struct sockaddr_in6 mltaddr, mltmask;
		struct in6_addr llsol;

		/* join solicited multicast addr for new host id */
		bzero(&llsol, sizeof(struct in6_addr));
		llsol.s6_addr16[0] = htons(0xff02);
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] = ifra->ifra_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;
		if ((error = in6_setscope(&llsol, ifp, NULL)) != 0) {
			/* XXX: should not happen */
			log(LOG_ERR, "in6_update_ifa: "
			    "in6_setscope failed\n");
			goto cleanup;
		}
		dad_delay = 0;
		if ((flags & IN6_IFAUPDATE_DADDELAY)) {
			/*
			 * We need a random delay for DAD on the address
			 * being configured.  It also means delaying
			 * transmission of the corresponding MLD report to
			 * avoid report collision.
			 * [draft-ietf-ipv6-rfc2462bis-02.txt]
			 */
			dad_delay = arc4random() %
			    (MAX_RTR_SOLICITATION_DELAY * hz);
		}

#define	MLTMASK_LEN  4	/* mltmask's masklen (=32bit=4octet) */
		/* join solicited multicast addr for new host id */
		imm = in6_joingroup(ifp, &llsol, &error, dad_delay);
		if (!imm) {
			nd6log((LOG_ERR,
			    "in6_update_ifa: addmulti "
			    "failed for %s on %s (errno=%d)\n",
			    ip6_sprintf(&llsol), if_name(ifp), error));
			goto cleanup;
		}
		LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);
		in6m_sol = imm->i6mm_maddr;

		bzero(&mltmask, sizeof(mltmask));
		mltmask.sin6_len = sizeof(struct sockaddr_in6);
		mltmask.sin6_family = AF_INET6;
		mltmask.sin6_addr = in6mask32;

		/*
		 * join link-local all-nodes address
		 */
		bzero(&mltaddr, sizeof(mltaddr));
		mltaddr.sin6_len = sizeof(struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_linklocal_allnodes;
		if ((error = in6_setscope(&mltaddr.sin6_addr, ifp, NULL)) !=
		    0)
			goto cleanup; /* XXX: should not fail */

		/*
		 * XXX: do we really need this automatic routes?
		 * We should probably reconsider this stuff.  Most applications
		 * actually do not need the routes, since they usually specify
		 * the outgoing interface.
		 */
#ifndef QNX_MFIB
		rt = rtalloc1((struct sockaddr *)&mltaddr, 0);	/* XXX - does this need an ifp hint? */
#else
		int fib = -1;
		while ((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX) {
			rt = rtalloc1((struct sockaddr *)&mltaddr, 0, NULL, fib);	/* XXX - does this need an ifp hint? */
#endif
		if (rt) {
			if (memcmp(&mltaddr.sin6_addr,
			    &((struct sockaddr_in6 *)rt_key(rt))->sin6_addr,
			    MLTMASK_LEN)) {
				RTFREE(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			struct rt_addrinfo info;

			bzero(&info, sizeof(info));
			info.rti_info[RTAX_DST] = (struct sockaddr *)&mltaddr;
			info.rti_info[RTAX_GATEWAY] =
			    (struct sockaddr *)&ia->ia_addr;
			info.rti_info[RTAX_NETMASK] =
			    (struct sockaddr *)&mltmask;
			info.rti_info[RTAX_IFA] =
			    (struct sockaddr *)&ia->ia_addr;
			/* XXX: we need RTF_CLONING to fake nd6_rtrequest */
			info.rti_flags = RTF_UP | RTF_CLONING;
#ifdef __QNXNTO__
			info.rti_ifp = ifp;
#endif
#ifndef QNX_MFIB
			error = rtrequest1(RTM_ADD, &info, NULL);
#else
			error = rtrequest1(RTM_ADD, &info, NULL, fib);
#endif
			if (error)
				goto cleanup;
		} else {
			RTFREE(rt);
		}
#ifdef QNX_MFIB
		}
#endif
		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error, 0);
		if (!imm) {
			nd6log((LOG_WARNING,
			    "in6_update_ifa: addmulti failed for "
			    "%s on %s (errno=%d)\n",
			    ip6_sprintf(&mltaddr.sin6_addr),
			    if_name(ifp), error));
			goto cleanup;
		}
		LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);

#ifndef __QNXNTO__
		/*
		 * join node information group address
		 */
		dad_delay = 0;
		if ((flags & IN6_IFAUPDATE_DADDELAY)) {
			/*
			 * The spec doesn't say anything about delay for this
			 * group, but the same logic should apply.
			 */
			dad_delay = arc4random() %
			    (MAX_RTR_SOLICITATION_DELAY * hz);
		}
		if (in6_nigroup(ifp, hostname, hostnamelen, &mltaddr) == 0) {
			imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error,
			    dad_delay); /* XXX jinmei */
			if (!imm) {
				nd6log((LOG_WARNING, "in6_update_ifa: "
				    "addmulti failed for %s on %s (errno=%d)\n",
				    ip6_sprintf(&mltaddr.sin6_addr),
				    if_name(ifp), error));
				/* XXX not very fatal, go on... */
			} else {
				LIST_INSERT_HEAD(&ia->ia6_memberships,
				    imm, i6mm_chain);
			}
		}
#endif


		/*
		 * join interface-local all-nodes address.
		 * (ff01::1%ifN, and ff01::%ifN/32)
		 */
		mltaddr.sin6_addr = in6addr_nodelocal_allnodes;
		if ((error = in6_setscope(&mltaddr.sin6_addr, ifp, NULL))
		    != 0) 
			goto cleanup; /* XXX: should not fail */

		/* XXX: again, do we really need the route? */
#ifndef QNX_MFIB
		rt = rtalloc1((struct sockaddr *)&mltaddr, 0);	/* XXX - does this need an ifp hint? */
#else
		fib = -1;
		while ((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX) {
			rt = rtalloc1((struct sockaddr *)&mltaddr, 0, NULL, fib);	/* XXX - does this need an ifp hint? */
#endif
		if (rt) {
			/* 32bit came from "mltmask" */
			if (memcmp(&mltaddr.sin6_addr,
			    &((struct sockaddr_in6 *)rt_key(rt))->sin6_addr,
			    32 / 8)) {
				RTFREE(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			struct rt_addrinfo info;

			bzero(&info, sizeof(info));
			info.rti_info[RTAX_DST] = (struct sockaddr *)&mltaddr;
			info.rti_info[RTAX_GATEWAY] =
			    (struct sockaddr *)&ia->ia_addr;
			info.rti_info[RTAX_NETMASK] =
			    (struct sockaddr *)&mltmask;
			info.rti_info[RTAX_IFA] =
			    (struct sockaddr *)&ia->ia_addr;
			info.rti_flags = RTF_UP | RTF_CLONING;
#ifdef __QNXNTO__
			info.rti_ifp = ifp;
#endif
#ifndef QNX_MFIB
			error = rtrequest1(RTM_ADD, &info, NULL);
#else
			error = rtrequest1(RTM_ADD, &info, NULL, fib);
#endif
			if (error)
				goto cleanup;
#undef	MLTMASK_LEN
		} else {
			RTFREE(rt);
		}
#ifdef QNX_MFIB
		} /* while if_get_next_fib() */
#endif
		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error, 0);
		if (!imm) {
			nd6log((LOG_WARNING, "in6_update_ifa: "
			    "addmulti failed for %s on %s (errno=%d)\n",
			    ip6_sprintf(&mltaddr.sin6_addr),
			    if_name(ifp), error));
			goto cleanup;
		} else {
			LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);
		}
	}

	/*
	 * Perform DAD, if needed.
	 * XXX It may be of use, if we can administratively
	 * disable DAD.
	 */
	if (hostIsNew && in6if_do_dad(ifp) &&
	    ((ifra->ifra_flags & IN6_IFF_NODAD) == 0) &&
	    (ia->ia6_flags & IN6_IFF_TENTATIVE))
	{
		int mindelay, maxdelay;

		dad_delay = 0;
		if ((flags & IN6_IFAUPDATE_DADDELAY)) {
			/*
			 * We need to impose a delay before sending an NS
			 * for DAD.  Check if we also needed a delay for the
			 * corresponding MLD message.  If we did, the delay
			 * should be larger than the MLD delay (this could be
			 * relaxed a bit, but this simple logic is at least
			 * safe).
			 */
			mindelay = 0;
			if (in6m_sol != NULL &&
			    in6m_sol->in6m_state == MLD_REPORTPENDING) {
				mindelay = in6m_sol->in6m_timer;
			}
			maxdelay = MAX_RTR_SOLICITATION_DELAY * hz;
			if (maxdelay - mindelay == 0)
				dad_delay = 0;
			else {
				dad_delay =
				    (arc4random() % (maxdelay - mindelay)) +
				    mindelay;
			}
		}
		nd6_dad_start((struct ifaddr *)ia, dad_delay);
	}

	return error;

  unlink:
	/*
	 * XXX: if a change of an existing address failed, keep the entry
	 * anyway.
	 */
	if (hostIsNew)
		in6_unlink_ifa(ia, ifp);
	return error;

  cleanup:
	in6_purgeaddr(&ia->ia_ifa);
	return error;
}

void
in6_purgeaddr(ifa)
	struct ifaddr *ifa;
{
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_ifaddr *ia = (struct in6_ifaddr *) ifa;
	struct in6_multi_mship *imm;

	/* stop DAD processing */
	nd6_dad_stop(ifa);
#ifdef __QNXNTO__
	inpcblist_unbindif(ifp, (struct sockaddr *)&ia->ia_addr);
#endif

	/*
	 * delete route to the destination of the address being purged.
	 * The interface must be p2p or loopback in this case.
	 */
	if ((ia->ia_flags & IFA_ROUTE) != 0 && ia->ia_dstaddr.sin6_len != 0) {
		int e;
#ifdef QNX_MFIB
		int fib = -1;
		while((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX) {
#endif
#ifndef QNX_MFIB
		if ((e = rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST))
#else
		if ((e = rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST, fib))
#endif
		    != 0) {
			log(LOG_ERR, "in6_purgeaddr: failed to remove "
			    "a route to the p2p destination: %s on %s, "
			    "errno=%d\n",
			    ip6_sprintf(&ia->ia_addr.sin6_addr), if_name(ifp),
			    e);
			/* proceed anyway... */
		} else
			ia->ia_flags &= ~IFA_ROUTE;
#ifdef QNX_MFIB
		}
#endif
	}

	/* Remove ownaddr's loopback rtentry, if it exists. */
	in6_ifremloop(&(ia->ia_ifa));

	/*
	 * leave from multicast groups we have joined for the interface
	 */
	while ((imm = LIST_FIRST(&ia->ia6_memberships)) != NULL) {
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
	}

	in6_unlink_ifa(ia, ifp);
}

static void
in6_unlink_ifa(ia, ifp)
	struct in6_ifaddr *ia;
	struct ifnet *ifp;
{
	struct in6_ifaddr *oia;
	int	s = splnet();

#ifndef __QNXNTO__
	TAILQ_REMOVE(&ifp->if_addrlist, &ia->ia_ifa, ifa_list);
	/* release a refcnt for the link from if_addrlist */
	IFAFREE(&ia->ia_ifa);
#else /* brought in later link level routines */
	ifa_remove(ifp, &ia->ia_ifa);
#endif

	oia = ia;
	if (oia == (ia = in6_ifaddr))
		in6_ifaddr = ia->ia_next;
	else {
		while (ia->ia_next && (ia->ia_next != oia))
			ia = ia->ia_next;
		if (ia->ia_next)
			ia->ia_next = oia->ia_next;
		else {
			/* search failed */
			printf("Couldn't unlink in6_ifaddr from in6_ifaddr\n");
		}
	}

	if (!LIST_EMPTY(&oia->ia6_multiaddrs)) {
		/*
		 * XXX thorpej@NetBSD.org -- if the interface is going
		 * XXX away, don't save the multicast entries, delete them!
		 */
		if (oia->ia_ifa.ifa_ifp->if_output == if_nulloutput) {
			struct in6_multi *in6m;

			while ((in6m =
			    LIST_FIRST(&oia->ia6_multiaddrs)) != NULL)
				in6_delmulti(in6m);
		} else
			in6_savemkludge(oia);
	}

	/*
	 * Release the reference to the base prefix.  There should be a
	 * positive reference.
	 */
	if (oia->ia6_ndpr == NULL) {
		nd6log((LOG_NOTICE, "in6_unlink_ifa: autoconf'ed address "
		    "%p has no prefix\n", oia));
	} else {
		oia->ia6_ndpr->ndpr_refcnt--;
		oia->ia6_ndpr = NULL;
	}

	/*
	 * Also, if the address being removed is autoconf'ed, call
	 * pfxlist_onlink_check() since the release might affect the status of
	 * other (detached) addresses.
	 */
	if ((oia->ia6_flags & IN6_IFF_AUTOCONF) != 0)
		pfxlist_onlink_check();

	/*
	 * release another refcnt for the link from in6_ifaddr.
	 * Note that we should decrement the refcnt at least once for all *BSD.
	 */
	IFAFREE(&oia->ia_ifa);

	splx(s);
}

void
in6_purgeif(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ifa, *nifa;

	for (ifa = TAILQ_FIRST(&ifp->if_addrlist); ifa != NULL; ifa = nifa) {
		nifa = TAILQ_NEXT(ifa, ifa_list);
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		in6_purgeaddr(ifa);
	}

	in6_ifdetach(ifp);
}

/*
 * SIOC[GAD]LIFADDR.
 *	SIOCGLIFADDR: get first address. (?)
 *	SIOCGLIFADDR with IFLR_PREFIX:
 *		get first address that matches the specified prefix.
 *	SIOCALIFADDR: add the specified address.
 *	SIOCALIFADDR with IFLR_PREFIX:
 *		add the specified prefix, filling hostid part from
 *		the first link-local address.  prefixlen must be <= 64.
 *	SIOCDLIFADDR: delete the specified address.
 *	SIOCDLIFADDR with IFLR_PREFIX:
 *		delete the first address that matches the specified prefix.
 * return values:
 *	EINVAL on invalid parameters
 *	EADDRNOTAVAIL on prefix match failed/specified address not found
 *	other values may be returned from in6_ioctl()
 *
 * NOTE: SIOCALIFADDR(with IFLR_PREFIX set) allows prefixlen less than 64.
 * this is to accommodate address naming scheme other than RFC2374,
 * in the future.
 * RFC2373 defines interface id to be 64bit, but it allows non-RFC2374
 * address encoding scheme. (see figure on page 8)
 */
static int
in6_lifaddr_ioctl(so, cmd, data, ifp, l)
	struct socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
	struct lwp *l;
{
	struct if_laddrreq *iflr = (struct if_laddrreq *)data;
	struct ifaddr *ifa;
	struct sockaddr *sa;

	/* sanity checks */
	if (!data || !ifp) {
		panic("invalid argument to in6_lifaddr_ioctl");
		/* NOTREACHED */
	}

	switch (cmd) {
	case SIOCGLIFADDR:
		/* address must be specified on GET with IFLR_PREFIX */
		if ((iflr->flags & IFLR_PREFIX) == 0)
			break;
		/* FALLTHROUGH */
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		/* address must be specified on ADD and DELETE */
		sa = (struct sockaddr *)&iflr->addr;
		if (sa->sa_family != AF_INET6)
			return EINVAL;
		if (sa->sa_len != sizeof(struct sockaddr_in6))
			return EINVAL;
		/* XXX need improvement */
		sa = (struct sockaddr *)&iflr->dstaddr;
		if (sa->sa_family && sa->sa_family != AF_INET6)
			return EINVAL;
		if (sa->sa_len && sa->sa_len != sizeof(struct sockaddr_in6))
			return EINVAL;
		break;
	default: /* shouldn't happen */
#if 0
		panic("invalid cmd to in6_lifaddr_ioctl");
		/* NOTREACHED */
#else
		return EOPNOTSUPP;
#endif
	}
	if (sizeof(struct in6_addr) * 8 < iflr->prefixlen)
		return EINVAL;

	switch (cmd) {
	case SIOCALIFADDR:
	    {
		struct in6_aliasreq ifra;
		struct in6_addr *xhostid = NULL;
		int prefixlen;

		if ((iflr->flags & IFLR_PREFIX) != 0) {
			struct sockaddr_in6 *sin6;

			/*
			 * xhostid is to fill in the hostid part of the
			 * address.  xhostid points to the first link-local
			 * address attached to the interface.
			 */
			ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp, 0);
			if (!ifa)
				return EADDRNOTAVAIL;
			xhostid = IFA_IN6(ifa);

		 	/* prefixlen must be <= 64. */
			if (64 < iflr->prefixlen)
				return EINVAL;
			prefixlen = iflr->prefixlen;

			/* hostid part must be zero. */
			sin6 = (struct sockaddr_in6 *)&iflr->addr;
			if (sin6->sin6_addr.s6_addr32[2] != 0
			 || sin6->sin6_addr.s6_addr32[3] != 0) {
				return EINVAL;
			}
		} else
			prefixlen = iflr->prefixlen;

		/* copy args to in6_aliasreq, perform ioctl(SIOCAIFADDR_IN6). */
		bzero(&ifra, sizeof(ifra));
		bcopy(iflr->iflr_name, ifra.ifra_name, sizeof(ifra.ifra_name));

		bcopy(&iflr->addr, &ifra.ifra_addr,
		    ((struct sockaddr *)&iflr->addr)->sa_len);
		if (xhostid) {
			/* fill in hostid part */
			ifra.ifra_addr.sin6_addr.s6_addr32[2] =
			    xhostid->s6_addr32[2];
			ifra.ifra_addr.sin6_addr.s6_addr32[3] =
			    xhostid->s6_addr32[3];
		}

		if (((struct sockaddr *)&iflr->dstaddr)->sa_family) { /* XXX */
			bcopy(&iflr->dstaddr, &ifra.ifra_dstaddr,
			    ((struct sockaddr *)&iflr->dstaddr)->sa_len);
			if (xhostid) {
				ifra.ifra_dstaddr.sin6_addr.s6_addr32[2] =
				    xhostid->s6_addr32[2];
				ifra.ifra_dstaddr.sin6_addr.s6_addr32[3] =
				    xhostid->s6_addr32[3];
			}
		}

		ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		in6_prefixlen2mask(&ifra.ifra_prefixmask.sin6_addr, prefixlen);

		ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
		ifra.ifra_flags = iflr->flags & ~IFLR_PREFIX;
		return in6_control(so, SIOCAIFADDR_IN6, (caddr_t)&ifra, ifp, l);
	    }
	case SIOCGLIFADDR:
	case SIOCDLIFADDR:
	    {
		struct in6_ifaddr *ia;
		struct in6_addr mask, candidate, match;
		struct sockaddr_in6 *sin6;
		int cmp;

		bzero(&mask, sizeof(mask));
		if (iflr->flags & IFLR_PREFIX) {
			/* lookup a prefix rather than address. */
			in6_prefixlen2mask(&mask, iflr->prefixlen);

			sin6 = (struct sockaddr_in6 *)&iflr->addr;
			bcopy(&sin6->sin6_addr, &match, sizeof(match));
			match.s6_addr32[0] &= mask.s6_addr32[0];
			match.s6_addr32[1] &= mask.s6_addr32[1];
			match.s6_addr32[2] &= mask.s6_addr32[2];
			match.s6_addr32[3] &= mask.s6_addr32[3];

			/* if you set extra bits, that's wrong */
			if (bcmp(&match, &sin6->sin6_addr, sizeof(match)))
				return EINVAL;

			cmp = 1;
		} else {
			if (cmd == SIOCGLIFADDR) {
				/* on getting an address, take the 1st match */
				cmp = 0;	/* XXX */
			} else {
				/* on deleting an address, do exact match */
				in6_prefixlen2mask(&mask, 128);
				sin6 = (struct sockaddr_in6 *)&iflr->addr;
				bcopy(&sin6->sin6_addr, &match, sizeof(match));

				cmp = 1;
			}
		}

		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (!cmp)
				break;

			/*
			 * XXX: this is adhoc, but is necessary to allow
			 * a user to specify fe80::/64 (not /10) for a
			 * link-local address.
			 */
			bcopy(IFA_IN6(ifa), &candidate, sizeof(candidate));
			in6_clearscope(&candidate);
			candidate.s6_addr32[0] &= mask.s6_addr32[0];
			candidate.s6_addr32[1] &= mask.s6_addr32[1];
			candidate.s6_addr32[2] &= mask.s6_addr32[2];
			candidate.s6_addr32[3] &= mask.s6_addr32[3];
			if (IN6_ARE_ADDR_EQUAL(&candidate, &match))
				break;
		}
		if (!ifa)
			return EADDRNOTAVAIL;
		ia = ifa2ia6(ifa);

		if (cmd == SIOCGLIFADDR) {
			int error;

			/* fill in the if_laddrreq structure */
			bcopy(&ia->ia_addr, &iflr->addr, ia->ia_addr.sin6_len);
			error = sa6_recoverscope(
			    (struct sockaddr_in6 *)&iflr->addr);
			if (error != 0)
				return error;

			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &iflr->dstaddr,
				    ia->ia_dstaddr.sin6_len);
				error = sa6_recoverscope(
				    (struct sockaddr_in6 *)&iflr->dstaddr);
				if (error != 0)
					return error;
			} else
				bzero(&iflr->dstaddr, sizeof(iflr->dstaddr));

			iflr->prefixlen =
			    in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL);

			iflr->flags = ia->ia6_flags;	/* XXX */

			return 0;
		} else {
			struct in6_aliasreq ifra;

			/* fill in6_aliasreq and do ioctl(SIOCDIFADDR_IN6) */
			bzero(&ifra, sizeof(ifra));
			bcopy(iflr->iflr_name, ifra.ifra_name,
			    sizeof(ifra.ifra_name));

			bcopy(&ia->ia_addr, &ifra.ifra_addr,
			    ia->ia_addr.sin6_len);
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &ifra.ifra_dstaddr,
				    ia->ia_dstaddr.sin6_len);
			} else {
				bzero(&ifra.ifra_dstaddr,
				    sizeof(ifra.ifra_dstaddr));
			}
			bcopy(&ia->ia_prefixmask, &ifra.ifra_dstaddr,
			    ia->ia_prefixmask.sin6_len);

			ifra.ifra_flags = ia->ia6_flags;
			return in6_control(so, SIOCDIFADDR_IN6, (caddr_t)&ifra,
			    ifp, l);
		}
	    }
	}

	return EOPNOTSUPP;	/* just for safety */
}

/*
 * Initialize an interface's internet6 address
 * and routing table entry.
 */
static
int
in6_ifinit(ifp, ia, sin6, newhost
#ifdef QNX_MFIB
		, fib
#endif
		)
	struct ifnet *ifp;
	struct in6_ifaddr *ia;
	struct sockaddr_in6 *sin6;
	int newhost;
#ifdef QNX_MFIB
	int fib;
#endif
{
	int	error = 0, plen, ifacount = 0;
	int	s = splnet();
	struct ifaddr *ifa;
#ifdef QNX_MFIB
	int doall = 0;
	if(fib == -1) {
		doall = 1;
	}
#endif
	/*
	 * Give the interface a chance to initialize
	 * if this is its first address,
	 * and to validate the address if necessary.
	 */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		ifacount++;
	}

	ia->ia_addr = *sin6;

	if (ifacount <= 1 && ifp->if_ioctl &&
	    (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia))) {
		splx(s);
		return error;
	}
	splx(s);

	ia->ia_ifa.ifa_metric = ifp->if_metric;

	/* we could do in(6)_socktrim here, but just omit it at this moment. */

	/*
	 * Special case:
	 * If the destination address is specified for a point-to-point
	 * interface, install a route to the destination as an interface
	 * direct route.
	 */
	plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL); /* XXX */
	if (plen == 128 && ia->ia_dstaddr.sin6_family == AF_INET6) {
#ifdef QNX_MFIB
		/*
		 * initialize on all fibs this ifp is a member of
		 */
		if(doall) {
			fib = if_get_next_fib(ifp, fib); /* find first fib*/
			if (fib >= FIBS_MAX) {
				panic("in6_ifinit: ifp with no fib set");
			}
		}
		do {
#endif
		if ((error = rtinit(&(ia->ia_ifa), (int)RTM_ADD,
#ifndef QNX_MFIB
				    RTF_UP | RTF_HOST)) != 0)
#else
					RTF_UP | RTF_HOST, fib)) != 0)
#endif
			return error;
		ia->ia_flags |= IFA_ROUTE;
#ifdef QNX_MFIB
		} while(doall && (fib = if_get_next_fib(ifp, fib)) < FIBS_MAX);
#endif
	}

	/* Add ownaddr as loopback rtentry, if necessary (ex. on p2p link). */
	if (newhost) {
#ifndef __QNXNTO__
		/* set the rtrequest function to create llinfo */
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
#endif
#ifndef QNX_MFIB
		in6_ifaddloop(&(ia->ia_ifa));
#else
		if (doall) {
			fib = if_get_next_fib(ifp, -1);
			if (fib >= FIBS_MAX) {
				panic("in6_ifinit: ifp with no fib set");
			}
		}
		do {
			in6_ifaddloop(&(ia->ia_ifa), fib);
		} while (doall && ((fib = if_get_next_fib(ifp, fib)) < FIBS_MAX));
#endif
	}

	if (ifp->if_flags & IFF_MULTICAST)
		in6_restoremkludge(ia, ifp);

	return error;
}

/*
 * Find an IPv6 interface link-local address specific to an interface.
 */
struct in6_ifaddr *
in6ifa_ifpforlinklocal(ifp, ignoreflags)
	struct ifnet *ifp;
	int ignoreflags;
{
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa))) {
			if ((((struct in6_ifaddr *)ifa)->ia6_flags &
			     ignoreflags) != 0)
				continue;
			break;
		}
	}

	return (struct in6_ifaddr *)ifa;
}


/*
 * find the internet address corresponding to a given interface and address.
 */
struct in6_ifaddr *
in6ifa_ifpwithaddr(ifp, addr)
	struct ifnet *ifp;
	struct in6_addr *addr;
{
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			break;
	}

	return (struct in6_ifaddr *)ifa;
}

/*
 * find the internet address on a given interface corresponding to a neighbor's
 * address.
 */
struct in6_ifaddr *
in6ifa_ifplocaladdr(const struct ifnet *ifp, const struct in6_addr *addr)
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia;

	IFADDR_FOREACH(ifa, ifp) {
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		ia = (struct in6_ifaddr *)ifa;
		if (IN6_ARE_MASKED_ADDR_EQUAL(addr,
				&ia->ia_addr.sin6_addr,
				&ia->ia_prefixmask.sin6_addr))
			return ia;
	}

	return NULL;
}

/*
 * Convert IP6 address to printable (loggable) representation.
 */
static int ip6round = 0;
char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static char ip6buf[8][48];
	int i;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		*cp++ = hexdigits[*d >> 4];
		*cp++ = hexdigits[*d++ & 0xf];
		*cp++ = hexdigits[*d >> 4];
		*cp++ = hexdigits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return ip6buf[ip6round];
}

/*
 * Determine if an address is on a local network.
 */
int
#ifndef QNX_MFIB
in6_localaddr(in6)
#else
in6_localaddr(in6, fib)
	int fib;
#endif
	struct in6_addr *in6;
{
	struct in6_ifaddr *ia;

	if (IN6_IS_ADDR_LOOPBACK(in6) || IN6_IS_ADDR_LINKLOCAL(in6))
		return 1;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next)
		if (IN6_ARE_MASKED_ADDR_EQUAL(in6, &ia->ia_addr.sin6_addr,
					      &ia->ia_prefixmask.sin6_addr))
#ifdef QNX_MFIB
			if (if_get_fib_enabled(ia->ia_ifp, fib))
#endif
			return 1;

	return 0;
}

int
in6_is_addr_deprecated(sa6)
	struct sockaddr_in6 *sa6;
{
	struct in6_ifaddr *ia;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr,
		    &sa6->sin6_addr) &&
#ifdef SCOPEDROUTING
		    ia->ia_addr.sin6_scope_id == sa6->sin6_scope_id &&
#endif
		    (ia->ia6_flags & IN6_IFF_DEPRECATED) != 0)
			return 1; /* true */

		/* XXX: do we still have to go thru the rest of the list? */
	}

	return 0;		/* false */
}

/*
 * return length of part which dst and src are equal
 * hard coding...
 */
int
in6_matchlen(src, dst)
struct in6_addr *src, *dst;
{
	int match = 0;
	u_char *s = (u_char *)src, *d = (u_char *)dst;
	u_char *lim = s + 16, r;

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < 128) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return match;
}

/* XXX: to be scope conscious */
int
in6_are_prefix_equal(p1, p2, len)
	struct in6_addr *p1, *p2;
	int len;
{
	int bytelen, bitlen;

	/* sanity check */
	if (len < 0 || len > 128) {
		log(LOG_ERR, "in6_are_prefix_equal: invalid prefix length(%d)\n",
		    len);
		return 0;
	}

	bytelen = len / 8;
	bitlen = len % 8;

	if (bcmp(&p1->s6_addr, &p2->s6_addr, bytelen))
		return 0;
	if (bitlen != 0 &&
	    p1->s6_addr[bytelen] >> (8 - bitlen) !=
	    p2->s6_addr[bytelen] >> (8 - bitlen))
		return 0;

	return 1;
}

void
in6_prefixlen2mask(maskp, len)
	struct in6_addr *maskp;
	int len;
{
	static const u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (len < 0 || len > 128) {
		log(LOG_ERR, "in6_prefixlen2mask: invalid prefix length(%d)\n",
		    len);
		return;
	}

	bzero(maskp, sizeof(*maskp));
	bytelen = len / 8;
	bitlen = len % 8;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

/*
 * return the best address out of the same scope. if no address was
 * found, return the first valid address from designated IF.
 */
struct in6_ifaddr *
in6_ifawithifp(ifp, dst)
	struct ifnet *ifp;
	struct in6_addr *dst;
{
	int dst_scope =	in6_addrscope(dst), blen = -1, tlen;
	struct ifaddr *ifa;
	struct in6_ifaddr *besta = 0;
	struct in6_ifaddr *dep[2];	/* last-resort: deprecated */

	dep[0] = dep[1] = NULL;

	/*
	 * We first look for addresses in the same scope.
	 * If there is one, return it.
	 * If two or more, return one which matches the dst longest.
	 * If none, return one of global addresses assigned other ifs.
	 */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST)
			continue; /* XXX: is there any case to allow anycast? */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY)
			continue; /* don't use this interface */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DETACHED)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated)
				dep[0] = (struct in6_ifaddr *)ifa;
			continue;
		}

		if (dst_scope == in6_addrscope(IFA_IN6(ifa))) {
			/*
			 * call in6_matchlen() as few as possible
			 */
			if (besta) {
				if (blen == -1)
					blen = in6_matchlen(&besta->ia_addr.sin6_addr, dst);
				tlen = in6_matchlen(IFA_IN6(ifa), dst);
				if (tlen > blen) {
					blen = tlen;
					besta = (struct in6_ifaddr *)ifa;
				}
			} else
				besta = (struct in6_ifaddr *)ifa;
		}
	}
	if (besta)
		return besta;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST)
			continue; /* XXX: is there any case to allow anycast? */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY)
			continue; /* don't use this interface */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DETACHED)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated)
				dep[1] = (struct in6_ifaddr *)ifa;
			continue;
		}

		return (struct in6_ifaddr *)ifa;
	}

	/* use the last-resort values, that are, deprecated addresses */
	if (dep[0])
		return dep[0];
	if (dep[1])
		return dep[1];

	return NULL;
}

/*
 * perform DAD when interface becomes IFF_UP.
 */
void
in6_if_up(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		ia = (struct in6_ifaddr *)ifa;
		if (ia->ia6_flags & IN6_IFF_TENTATIVE) {
			/*
			 * The TENTATIVE flag was likely set by hand
			 * beforehand, implicitly indicating the need for DAD.
			 * We may be able to skip the random delay in this
			 * case, but we impose delays just in case.
			 */
			nd6_dad_start(ifa,
			    arc4random() % (MAX_RTR_SOLICITATION_DELAY * hz));
		}
	}

	/*
	 * special cases, like 6to4, are handled in in6_ifattach
	 */
	in6_ifattach(ifp, NULL);
}

int
in6if_do_dad(ifp)
	struct ifnet *ifp;
{
	if ((ifp->if_flags & IFF_LOOPBACK) != 0)
		return 0;

	switch (ifp->if_type) {
	case IFT_FAITH:
		/*
		 * These interfaces do not have the IFF_LOOPBACK flag,
		 * but loop packets back.  We do not have to do DAD on such
		 * interfaces.  We should even omit it, because loop-backed
		 * NS would confuse the DAD procedure.
		 */
		return 0;
	default:
		/*
		 * Our DAD routine requires the interface up and running.
		 * However, some interfaces can be up before the RUNNING
		 * status.  Additionaly, users may try to assign addresses
		 * before the interface becomes up (or running).
		 * We simply skip DAD in such a case as a work around.
		 * XXX: we should rather mark "tentative" on such addresses,
		 * and do DAD after the interface becomes ready.
		 */
		if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) !=
		    (IFF_UP|IFF_RUNNING))
			return 0;

		return 1;
	}
}

/*
 * Calculate max IPv6 MTU through all the interfaces and store it
 * to in6_maxmtu.
 */
void
in6_setmaxmtu()
{
	unsigned long maxmtu = 0;
	struct ifnet *ifp;

	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list))
	{
		/* this function can be called during ifnet initialization */
		if (!ifp->if_afdata[AF_INET6])
			continue;
#ifndef __QNXNTO__
		if ((ifp->if_flags & IFF_LOOPBACK) == 0 &&
#else
		if (((ifp->if_flags & (IFF_UP|IFF_LOOPBACK)) == IFF_UP) &&
#endif
		    IN6_LINKMTU(ifp) > maxmtu)
			maxmtu = IN6_LINKMTU(ifp);
	}
	if (maxmtu)	     /* update only when maxmtu is positive */
		in6_maxmtu = maxmtu;
}

/*
 * Provide the length of interface identifiers to be used for the link attached
 * to the given interface.  The length should be defined in "IPv6 over
 * xxx-link" document.  Note that address architecture might also define
 * the length for a particular set of address prefixes, regardless of the
 * link type.  As clarified in rfc2462bis, those two definitions should be
 * consistent, and those really are as of August 2004.
 */
int
in6_if2idlen(ifp)
	struct ifnet *ifp;
{
	switch (ifp->if_type) {
	case IFT_ETHER:		/* RFC2464 */
	case IFT_PROPVIRTUAL:	/* XXX: no RFC. treat it as ether */
	case IFT_L2VLAN:	/* ditto */
	case IFT_IEEE80211:	/* ditto */
	case IFT_FDDI:		/* RFC2467 */
	case IFT_ISO88025:	/* RFC2470 (IPv6 over Token Ring) */
	case IFT_PPP:		/* RFC2472 */
	case IFT_ARCNET:	/* RFC2497 */
	case IFT_FRELAY:	/* RFC2590 */
	case IFT_IEEE1394:	/* RFC3146 */
	case IFT_GIF:		/* draft-ietf-v6ops-mech-v2-07 */
	case IFT_LOOP:		/* XXX: is this really correct? */
		return 64;
	default:
		/*
		 * Unknown link type:
		 * It might be controversial to use the today's common constant
		 * of 64 for these cases unconditionally.  For full compliance,
		 * we should return an error in this case.  On the other hand,
		 * if we simply miss the standard for the link type or a new
		 * standard is defined for a new link type, the IFID length
		 * is very likely to be the common constant.  As a compromise,
		 * we always use the constant, but make an explicit notice
		 * indicating the "unknown" case.
		 */
		printf("in6_if2idlen: unknown link type (%d)\n", ifp->if_type);
		return 64;
	}
}

void *
in6_domifattach(ifp)
	struct ifnet *ifp;
{
	struct in6_ifextra *ext;

	ext = (struct in6_ifextra *)malloc(sizeof(*ext), M_IFADDR, M_WAITOK);
	bzero(ext, sizeof(*ext));

	ext->in6_ifstat = (struct in6_ifstat *)malloc(sizeof(struct in6_ifstat),
	    M_IFADDR, M_WAITOK);
	bzero(ext->in6_ifstat, sizeof(*ext->in6_ifstat));

	ext->icmp6_ifstat =
	    (struct icmp6_ifstat *)malloc(sizeof(struct icmp6_ifstat),
	    M_IFADDR, M_WAITOK);
	bzero(ext->icmp6_ifstat, sizeof(*ext->icmp6_ifstat));

	ext->nd_ifinfo = nd6_ifattach(ifp);
	ext->scope6_id = scope6_ifattach(ifp);
	return ext;
}

void
in6_domifdetach(struct ifnet *ifp, void *aux)
{
	struct in6_ifextra *ext = (struct in6_ifextra *)aux;

	nd6_ifdetach(ext->nd_ifinfo);
	free(ext->in6_ifstat, M_IFADDR);
	free(ext->icmp6_ifstat, M_IFADDR);
	scope6_ifdetach(ext->scope6_id);
	free(ext, M_IFADDR);
}

#ifdef QNX_MFIB
void in6_add_fib(struct ifnet *ifp, int fib)
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia6;
	IFADDR_FOREACH(ifa, ifp) {
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			ia6 = (struct in6_ifaddr *)ifa;
			in6_ifinit(ifp, ia6, &(ia6->ia_addr), 1, fib);
		}
	}
	nd6_add_prefixes2fib(ifp, fib);

}

static void in6_ifscrub_fib(struct ifnet*ifp, struct in6_ifaddr *ia, int fib) {
	if ((ia->ia_flags & IFA_ROUTE) != 0 && ia->ia_dstaddr.sin6_len != 0) {
		int e;
		if ((e = rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST, fib))
				!= 0) {
			log(LOG_ERR, "in6_purgeaddr: failed to remove "
					"a route to the p2p destination: %s on %s, "
					"errno=%d\n",
					ip6_sprintf(&ia->ia_addr.sin6_addr), if_name(ifp),
					e);
			/* proceed anyway... */
		} else
			ia->ia_flags &= ~IFA_ROUTE;
	}
}

void in6_del_fib(struct ifnet *ifp, int fib) {
	struct in_ifaddr *ia;
	int ifa_route;
	struct ifaddr *ifa, *next;

	if (!ifp)
		return;

	/* kill any neighbor prefix routes for this fib */
	nd6_purge_fib(ifp, fib);

	for (ifa = TAILQ_FIRST(&ifp->if_addrlist); ifa; ifa = next) {
		next = TAILQ_NEXT(ifa, ifa_list);
		ia = ifatoia(ifa);

		ifa_route = ia->ia_flags & IFA_ROUTE;

		switch(ifa->ifa_addr->sa_family) {
		case AF_INET6:
			in6_ifremloop_fib(&(ia->ia_ifa), fib);
			in6_ifscrub_fib(ifp, (struct in6_ifaddr *)ia, fib);
			break;
		default:
			continue;
		}

		ia->ia_flags &= ~(IFA_ROUTE);
		ia->ia_flags |= ifa_route; /* this is not the last fib, restore the flag post-remove */
	}

}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/in6.c $ $Rev: 839788 $")
#endif
