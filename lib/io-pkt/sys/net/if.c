/*
 * $QNXtpLicenseC:
 * Copyright 2007, 2009, QNX Software Systems. All Rights Reserved.
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


/*	$NetBSD: if.c,v 1.178 2006/11/20 04:09:25 dyoung Exp $	*/

/*-
 * Copyright (c) 1999, 2000, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by William Studenmund and Jason R. Thorpe.
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
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)if.c	8.5 (Berkeley) 1/9/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if.c,v 1.178 2006/11/20 04:09:25 dyoung Exp $");

#include "opt_inet.h"

#include "opt_compat_linux.h"
#include "opt_compat_svr4.h"
#include "opt_compat_ultrix.h"
#include "opt_compat_43.h"
#include "opt_atalk.h"
#include "opt_natm.h"
#include "opt_pfil_hooks.h"
#ifdef __QNXNTO__
#include "opt_ionet_compat.h"
#include "bridge.h"
#endif

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#include <nw_dl.h>
#include <nw_msg.h>
#include <quiesce.h>
#include <device_qnx.h>
#include <sys/device.h>
#include <sys/dcmd_misc.h>
#include <net/if_extra.h>
#endif
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net/if_types.h>
#include <net/radix.h>
#include <net/route.h>
#include <net/netisr.h>
#ifdef NETATALK
#include <netatalk/at_extern.h>
#include <netatalk/at.h>
#endif
#include <net/pfil.h>

#ifdef __QNXNTO__
#include <netinet/if_tcp_conf.h>
#endif
#ifdef INET6
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#ifdef __QNXNTO__
#include <netinet6/ip6_ifconf.h>
#endif
#endif

#ifdef __QNXNTO__
#if NBRIDGE > 0
#include <net/if_bridgevar.h>
#endif
#ifdef IONET_COMPAT
#include <sys/syslog.h>
#endif
#include <stdbool.h> /* old gcc */
#endif
#include "carp.h"
#if NCARP > 0
#include <netinet/ip_carp.h>
#endif

#include <compat/sys/sockio.h>
#include <compat/sys/socket.h>

MALLOC_DEFINE(M_IFADDR, "ifaddr", "interface address");
MALLOC_DEFINE(M_IFMADDR, "ether_multi", "link-level multicast address");

int	ifqmaxlen = IFQ_MAXLEN;
struct	callout if_slowtimo_ch;

int netisr;			/* scheduling bits for network */

#ifndef QNX_MFIB
static int	if_rt_walktree(struct radix_node *, void *);
#else
static int	if_rt_walktree(struct radix_node *, void *, int);
static void if_set_if_fib(struct ifnet *ifp, int dest_fib);
#endif

#ifndef __QNXNTO__
static
#endif
struct if_clone *if_clone_lookup(const char *, int *);
static int	if_clone_list(struct if_clonereq *);

static void if_activate_sadl(struct ifnet *, struct ifaddr *,
    const struct sockaddr_dl *);

static LIST_HEAD(, if_clone) if_cloners = LIST_HEAD_INITIALIZER(if_cloners);
static int if_cloners_count;

#ifdef PFIL_HOOKS
struct pfil_head if_pfil;	/* packet filtering hook for interfaces */
#endif

static void if_detach_queues(struct ifnet *, struct ifqueue *);
#ifdef __QNXNTO__
#ifdef IONET_COMPAT
#ifndef QNX_MFIB
static struct ifnet * ifunit_iter(const char *, int);
#else
static struct ifnet * ifunit_iter(const char *, int, int);
#endif
#endif
static int if_getptrembed(u_long, caddr_t);
static void if_start_cb(void *arg);
static void linkstate_intr(void *);
static void link_wakeup_from_stack(unsigned, int);
struct	ifqueue linkstate_intrq = {
	.ifq_intr = linkstate_intr,
	.ifq_next = &linkstate_intrq,
	.ifq_prev = &linkstate_intrq.ifq_next,
	.ifq_maxlen = IFQ_MAXLEN,
};
int ionet_enmap; /* always instantiate. readonly if !IONET_COMPAT */

struct linkstate_intr_arg {
	unsigned	index;
	int		link_state;
};
#endif

#ifndef NDEBUG
int if_debug_ioctl(u_long pid, u_long cmd, caddr_t data, int error
#ifdef QNX_MFIB
			, int fib
#endif
			);
#endif

#ifdef __QNXNTO__
struct ifnet *ipsec_globalifp;
static char ipsec_globalifp_candidate[IFNAMSIZ];

char *
ipsec_input_set_globalif(struct ifnet *ifp)
{
	if (ifp == NULL) {
		/* return current value */
		if (ipsec_globalifp != NULL) {
			/* Name may have changed since set.  Return current val */
			strlcpy(ipsec_globalifp_candidate, ipsec_globalifp->if_xname,
			    sizeof(ipsec_globalifp_candidate));
		}
		return ipsec_globalifp_candidate;
	}
	
	/* set new value */
	if (strncmp(ifp->if_xname, ipsec_globalifp_candidate,
	    sizeof(ifp->if_xname)) == 0 ) {
		ipsec_globalifp = ifp;
		printf("ipsec_input_set_globalif: global private interface='%s'\n",
		    ipsec_globalifp->if_xname);
	}
	return NULL;
}

void
ipsec_input_clear_globalif(struct ifnet *ifp)
{
	if (ifp == ipsec_globalifp) {
		printf("ipsec_input_clear_globalif: private global interface='%s'\n",
			ipsec_globalifp->if_xname);
		ipsec_globalifp = NULL;
	}
}
#endif
/*
 * Network interface utility routines.
 *
 * Routines with ifa_ifwith* names take sockaddr *'s as
 * parameters.
 */
void
ifinit(void)
{

	callout_init(&if_slowtimo_ch);
#ifndef __QNXNTO__ /* started if needed on if_attach() under qnx */
	if_slowtimo(NULL);
#endif
#ifdef PFIL_HOOKS
	if_pfil.ph_type = PFIL_TYPE_IFNET;
	if_pfil.ph_ifnet = NULL;
	if (pfil_head_register(&if_pfil) != 0)
		printf("WARNING: unable to register pfil hook\n");
#endif
}

void
if_initname(struct ifnet *ifp, const char *name, int unit)
{
	(void)snprintf(ifp->if_xname, sizeof(ifp->if_xname),
	    "%s%d", name, unit);
}

/*
 * Null routines used while an interface is going away.  These routines
 * just return an error.
 */

int
if_nulloutput(struct ifnet *ifp, struct mbuf *m,
    struct sockaddr *so, struct rtentry *rt)
{

	return (ENXIO);
}

void
if_nullinput(struct ifnet *ifp, struct mbuf *m)
{

	/* Nothing. */
}

void
if_nullstart(struct ifnet *ifp)
{

	/* Nothing. */
}

int
if_nullioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{

	return (ENXIO);
}

int
if_nullinit(struct ifnet *ifp)
{

	return (ENXIO);
}

void
if_nullstop(struct ifnet *ifp, int disable)
{

	/* Nothing. */
}

void
if_nullwatchdog(struct ifnet *ifp)
{

	/* Nothing. */
}

void
if_nulldrain(struct ifnet *ifp)
{

	/* Nothing. */
}

#ifndef __QNXNTO__
static u_int if_index = 1;
struct ifnet_head ifnet;
#else
static u_int if_index = 0;
struct ifnet_head ifnet = TAILQ_HEAD_INITIALIZER(ifnet);
NLIST_EXPORT(ifnet, ifnet);
#endif
size_t if_indexlim = 0;
struct ifaddr **ifnet_addrs = NULL;
struct ifnet **ifindex2ifnet = NULL;
#ifndef QNX_MFIB
struct ifnet *lo0ifp;
#else
struct ifnet *lo0ifp[FIBS_MAX];
#endif
void
if_set_sadl(struct ifnet *ifp, const void *lla, u_char addrlen)
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;

	ifp->if_addrlen = addrlen;
	if_alloc_sadl(ifp);
	ifa = ifp->if_dl;
	sdl = satosdl(ifa->ifa_addr);

	(void)sockaddr_dl_setaddr(sdl, sdl->sdl_len, lla, ifp->if_addrlen);
	/* TBD routing socket */
}

struct ifaddr *
if_dl_create(const struct ifnet *ifp, const struct sockaddr_dl **sdlp)
{
	unsigned socksize, ifasize;
	int addrlen, namelen;
	struct sockaddr_dl *mask, *sdl;
	struct ifaddr *ifa;

	namelen = strlen(ifp->if_xname);
	addrlen = ifp->if_addrlen;
	socksize = roundup(sockaddr_dl_measure(namelen, addrlen), sizeof(long));
	ifasize = sizeof(*ifa) + 2 * socksize;
	ifa = (struct ifaddr *)malloc(ifasize, M_IFADDR, M_WAITOK|M_ZERO);

	sdl = (struct sockaddr_dl *)(ifa + 1);
	mask = (struct sockaddr_dl *)(socksize + (char *)sdl);

	sockaddr_dl_init(sdl, socksize, ifp->if_index, ifp->if_type,
	    ifp->if_xname, namelen, NULL, addrlen);
	mask->sdl_len = sockaddr_dl_measure(namelen, 0);
	memset(&mask->sdl_data[0], 0xff, namelen);
	ifa->ifa_rtrequest = link_rtrequest;
	ifa->ifa_addr = (struct sockaddr *)sdl;
	ifa->ifa_netmask = (struct sockaddr *)mask;

	*sdlp = sdl;

	return ifa;
}

static void
if_sadl_setrefs(struct ifnet *ifp, struct ifaddr *ifa)
{
	const struct sockaddr_dl *sdl;
	ifnet_addrs[ifp->if_index] = ifa;
	IFAREF(ifa);
	ifp->if_dl = ifa;
	IFAREF(ifa);
	sdl = satosdl(ifa->ifa_addr);
	ifp->if_sadl = sdl;
}

/*
 * Allocate the link level name for the specified interface.  This
 * is an attachment helper.  It must be called after ifp->if_addrlen
 * is initialized, which may not be the case when if_attach() is
 * called.
 */
void
if_alloc_sadl(struct ifnet *ifp)
{
	struct ifaddr *ifa;
	const struct sockaddr_dl *sdl;

	/*
	 * If the interface already has a link name, release it
	 * now.  This is useful for interfaces that can change
	 * link types, and thus switch link names often.
	 */
	if (ifp->if_sadl != NULL)
		if_free_sadl(ifp);

	ifa = if_dl_create(ifp, &sdl);

	ifa_insert(ifp, ifa);
	if_sadl_setrefs(ifp, ifa);
}

static void
if_deactivate_sadl(struct ifnet *ifp)
{
	struct ifaddr *ifa;

	KASSERT(ifp->if_dl != NULL);

	ifa = ifp->if_dl;

	ifp->if_sadl = NULL;

	ifnet_addrs[ifp->if_index] = NULL;
	IFAFREE(ifa);
	ifp->if_dl = NULL;
	IFAFREE(ifa);
}

static void
if_activate_sadl(struct ifnet *ifp, struct ifaddr *ifa,
    const struct sockaddr_dl *sdl)
{
	int s;

	s = splnet();

	if_deactivate_sadl(ifp);

	if_sadl_setrefs(ifp, ifa);
	splx(s);
	rt_ifmsg(ifp);
}

/*
 * Free the link level name for the specified interface.  This is
 * a detach helper.  This is called from if_detach() or from
 * link layer type specific detach functions.
 */
void
if_free_sadl(struct ifnet *ifp)
{
	struct ifaddr *ifa;
	int s;

	ifa = ifnet_addrs[ifp->if_index];
	if (ifa == NULL) {
		KASSERT(ifp->if_sadl == NULL);
		KASSERT(ifp->if_dl == NULL);
		return;
	}

	KASSERT(ifp->if_sadl != NULL);
	KASSERT(ifp->if_dl != NULL);

	s = splnet();
#ifdef QNX_MFIB
	int fib=-1;
	while((fib=if_get_next_fib(ifp, fib)) < FIBS_MAX) {
#endif
#ifndef QNX_MFIB
	rtinit(ifa, RTM_DELETE, 0);
#else
	rtinit(ifa, RTM_DELETE, 0, fib);
#endif
#ifdef QNX_MFIB
	}
#endif

	ifa_remove(ifp, ifa);

	if_deactivate_sadl(ifp);
	splx(s);
}

/*
 * Attach an interface to the
 * list of "active" interfaces.
 */
void
if_attach(struct ifnet *ifp)
{
#ifndef __QNXNTO__
	int indexlim = 0;
#else
	int i, ret;

	if ((ret = (*iopkt_selfp->ex_init)(&ifp->if_snd_ex)) != EOK) {
		panic("if_attach: ex_init: %d", ret);
	}
	// DEBUG
#ifdef QNX_MFIB
	/*
	 * If a fib is set, don't overwrite it.
	 * Loopback interface set their fib value prior to hitting this code.
	 */
	if (ifp->if_fibmask == 0)
		if_set_fib(ifp, 0); /* If no fib is set, start in fib 0 */
#endif
#endif

#ifndef __QNXNTO__
	if (if_indexlim == 0) {
		TAILQ_INIT(&ifnet);
		if_indexlim = 8;
	}
	TAILQ_INIT(&ifp->if_addrlist);
	TAILQ_INSERT_TAIL(&ifnet, ifp, if_list);
	ifp->if_index = if_index;
	if (ifindex2ifnet == 0)
		if_index++;
	else
		while (ifp->if_index < if_indexlim &&
		    ifindex2ifnet[ifp->if_index] != NULL) {
			++if_index;
			if (if_index == 0)
				if_index = 1;
			/*
			 * If we hit USHRT_MAX, we skip back to 0 since
			 * there are a number of places where the value
			 * of if_index or if_index itself is compared
			 * to or stored in an unsigned short.  By
			 * jumping back, we won't botch those assignments
			 * or comparisons.
			 */
			else if (if_index == USHRT_MAX) {
				/*
				 * However, if we have to jump back to
				 * zero *twice* without finding an empty
				 * slot in ifindex2ifnet[], then there
				 * there are too many (>65535) interfaces.
				 */
				if (indexlim++)
					panic("too many interfaces");
				else
					if_index = 1;
			}
			ifp->if_index = if_index;
		}

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 *	struct ifadd **ifnet_addrs
	 *	struct ifnet **ifindex2ifnet
	 */
	if (ifnet_addrs == 0 || ifindex2ifnet == 0 ||
	    ifp->if_index >= if_indexlim) {
		size_t m, n, oldlim;
		caddr_t q;

		oldlim = if_indexlim;
		while (ifp->if_index >= if_indexlim)
			if_indexlim <<= 1;

		/* grow ifnet_addrs */
		m = oldlim * sizeof(struct ifaddr *);
		n = if_indexlim * sizeof(struct ifaddr *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		memset(q, 0, n);
		if (ifnet_addrs) {
			bcopy((caddr_t)ifnet_addrs, q, m);
			free((caddr_t)ifnet_addrs, M_IFADDR);
		}
		ifnet_addrs = (struct ifaddr **)q;

		/* grow ifindex2ifnet */
		m = oldlim * sizeof(struct ifnet *);
		n = if_indexlim * sizeof(struct ifnet *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		memset(q, 0, n);
		if (ifindex2ifnet) {
			bcopy((caddr_t)ifindex2ifnet, q, m);
			free((caddr_t)ifindex2ifnet, M_IFADDR);
		}
		ifindex2ifnet = (struct ifnet **)q;
	}
#else
	/*
	 * Looks like historically, slot 0 is unused.
	 * Some code actually depends on this (see nd6_setdefaultiface()).
	 */
	TAILQ_INIT(&ifp->if_addrlist);
	TAILQ_INSERT_TAIL(&ifnet, ifp, if_list);
	for (i = 1; i < if_indexlim; i++) {
		if (ifindex2ifnet[i] == NULL) {
			/* Interface went away (umounted), so reuse slot */
			ifp->if_index = i;
			break;
		}
	}

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 *	struct ifadd **ifnet_addrs
	 *	struct ifnet **ifindex2ifnet
	 */
	if (i >= if_indexlim) {
		size_t n, oldlim;
		caddr_t q;

		/*
		 * There are a number of places where the value
		 * of if_index or if_index itself is compared
		 * to to or stored in an unsigned short.  Don't
		 * allow those assignments or comparisons to be
		 * botched.
		 */
		if (if_indexlim == USHRT_MAX)
			panic("too many interfaces");

		oldlim = if_indexlim;
		if_indexlim = min(if_indexlim + 8, USHRT_MAX);

		/* grow ifnet_addrs */
		n = if_indexlim * sizeof(struct ifaddr *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		memset(q, 0, n);
		if (ifnet_addrs) {
			memcpy(q, ifnet_addrs, oldlim * sizeof(struct ifaddr *));
			free((caddr_t)ifnet_addrs, M_IFADDR);
		}
		ifnet_addrs = (struct ifaddr **)q;

		/* grow ifindex2ifnet */
		n = if_indexlim * sizeof(struct ifnet *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		memset(q, 0, n);
		if (ifindex2ifnet) {
			memcpy(q, ifindex2ifnet, oldlim * sizeof(struct ifnet *));
			free((caddr_t)ifindex2ifnet, M_IFADDR);
		}
		ifindex2ifnet = (struct ifnet **)q;
	}

	if_index = max(i, if_index); /* Max we've seen */

	ifp->if_index = i;
#endif

	ifindex2ifnet[ifp->if_index] = ifp;

	/*
	 * Link level name is allocated later by a separate call to
	 * if_alloc_sadl().
	 */

	if (ifp->if_snd.ifq_maxlen == 0)
		ifp->if_snd.ifq_maxlen = ifqmaxlen;
	ifp->if_broadcastaddr = 0; /* reliably crash if used uninitialized */

	ifp->if_link_state = LINK_STATE_UNKNOWN;

#ifndef __QNXNTO__
	ifp->if_capenable = 0;
#else
	ifp->if_capenable_tx = 0;
	ifp->if_capenable_rx = 0;
#endif
	ifp->if_csum_flags_tx = 0;
	ifp->if_csum_flags_rx = 0;

#ifdef ALTQ
	ifp->if_snd.altq_type = 0;
	ifp->if_snd.altq_disc = NULL;
	ifp->if_snd.altq_flags &= ALTQF_CANTCHANGE;
	ifp->if_snd.altq_tbr  = NULL;
	ifp->if_snd.altq_ifp  = ifp;
#endif

#ifdef PFIL_HOOKS
	ifp->if_pfil.ph_type = PFIL_TYPE_IFNET;
	ifp->if_pfil.ph_ifnet = ifp;
	if (pfil_head_register(&ifp->if_pfil) != 0)
		printf("%s: WARNING: unable to register pfil hook\n",
		    ifp->if_xname);
	(void)pfil_run_hooks(&if_pfil,
#ifndef QNX_MFIB
	    (struct mbuf **)PFIL_IFNET_ATTACH, ifp, PFIL_IFNET);
#else
		(struct mbuf **)PFIL_IFNET_ATTACH, ifp, PFIL_IFNET, if_get_first_fib(ifp)); /* ifnet attach currently doesn't care about fib*/
#endif
#endif

	if (!STAILQ_EMPTY(&domains))
		if_attachdomain1(ifp);

#ifdef __QNXNTO__
	if_extra_init(ifp);
	if_tcp_ifconf_add(ifp);
#ifdef INET6
	if_ip6_ifconf_add(ifp);
#endif
	if (ifp->if_watchdog != NULL) {
		/* Start the periodic timer.  Currently never stops */
		if_slowtimo(NULL);
	}
#endif
	/* Announce the interface. */
	rt_ifannouncemsg(ifp, IFAN_ARRIVAL);
}

void
if_attachdomain(void)
{
	struct ifnet *ifp;
	int s;

	s = splnet();
	TAILQ_FOREACH(ifp, &ifnet, if_list)
		if_attachdomain1(ifp);
	splx(s);
}

void
if_attachdomain1(struct ifnet *ifp)
{
	struct domain *dp;
	int s;

	s = splnet();

	/* address family dependent data region */
	memset(ifp->if_afdata, 0, sizeof(ifp->if_afdata));
	DOMAIN_FOREACH(dp) {
		if (dp->dom_ifattach)
			ifp->if_afdata[dp->dom_family] =
			    (*dp->dom_ifattach)(ifp);
	}

	splx(s);
}

/*
 * Deactivate an interface.  This points all of the procedure
 * handles at error stubs.  May be called from interrupt context.
 */
void
if_deactivate(struct ifnet *ifp)
{
	int s;

	s = splnet();

	ifp->if_output	 = if_nulloutput;
	ifp->if_input	 = if_nullinput;
	ifp->if_start	 = if_nullstart;
	ifp->if_ioctl	 = if_nullioctl;
	ifp->if_init	 = if_nullinit;
	ifp->if_stop	 = if_nullstop;
	ifp->if_watchdog = if_nullwatchdog;
	ifp->if_drain	 = if_nulldrain;

	/* No more packets may be enqueued. */
	ifp->if_snd.ifq_maxlen = 0;

	splx(s);
}

/*
 * Detach an interface from the list of "active" interfaces,
 * freeing any resources as we go along.
 *
 * NOTE: This routine must be called with a valid thread context,
 * as it may block.
 */
void
if_detach(struct ifnet *ifp)
{
	struct socket so;
	struct ifaddr *ifa;
#ifdef IFAREF_DEBUG
	struct ifaddr *last_ifa = NULL;
#endif
	struct domain *dp;
	const struct protosw *pr;
	struct radix_node_head *rnh;
	int s, i, family, purged;
#ifdef QNX_MFIB
	int fib;
#endif

#ifdef __QNXNTO__
	quiesce_all();
#endif
	/*
	 * XXX It's kind of lame that we have to have the
	 * XXX socket structure...
	 */
	memset(&so, 0, sizeof(so));

	s = splnet();

	/*
	 * Do an if_down() to give protocols a chance to do something.
	 */
	if_down(ifp);

#ifdef ALTQ
	if (ALTQ_IS_ENABLED(&ifp->if_snd))
		altq_disable(&ifp->if_snd);
	if (ALTQ_IS_ATTACHED(&ifp->if_snd))
		altq_detach(&ifp->if_snd);
#endif


#if NCARP > 0
	/* Remove the interface from any carp group it is a part of.  */
	if (ifp->if_carp && ifp->if_type != IFT_CARP)
		carp_ifdetach(ifp);
#endif

#ifdef PFIL_HOOKS
	(void)pfil_run_hooks(&if_pfil,
#ifndef QNX_MFIB
	    (struct mbuf **)PFIL_IFNET_DETACH, ifp, PFIL_IFNET);
#else
        (struct mbuf **)PFIL_IFNET_DETACH, ifp, PFIL_IFNET, if_get_first_fib(ifp));
#endif
	(void)pfil_head_unregister(&ifp->if_pfil);
#endif

	/*
	 * Rip all the addresses off the interface.  This should make
	 * all of the routes go away.
	 *
	 * pr_usrreq calls can remove an arbitrary number of ifaddrs
	 * from the list, including our "cursor", ifa.  For safety,
	 * and to honor the TAILQ abstraction, I just restart the
	 * loop after each removal.  Note that the loop will exit
	 * when all of the remaining ifaddrs belong to the AF_LINK
	 * family.  I am counting on the historical fact that at
	 * least one pr_usrreq in each address domain removes at
	 * least one ifaddr.
	 */
again:
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		family = ifa->ifa_addr->sa_family;
#ifdef IFAREF_DEBUG
		printf("if_detach: ifaddr %p, family %d, refcnt %d\n",
		    ifa, family, ifa->ifa_refcnt);
		if (last_ifa != NULL && ifa == last_ifa)
			panic("if_detach: loop detected");
		last_ifa = ifa;
#endif
		if (family == AF_LINK)
			continue;
		dp = pffinddomain(family);
#ifdef DIAGNOSTIC
		if (dp == NULL)
			panic("if_detach: no domain for AF %d",
			    family);
#endif
		/*
		 * XXX These PURGEIF calls are redundant with the
		 * purge-all-families calls below, but are left in for
		 * now both to make a smaller change, and to avoid
		 * unplanned interactions with clearing of
		 * ifp->if_addrlist.
		 */
		purged = 0;
		for (pr = dp->dom_protosw;
		     pr < dp->dom_protoswNPROTOSW; pr++) {
			so.so_proto = pr;
			if (pr->pr_usrreq != NULL) {
				(void) (*pr->pr_usrreq)(&so,
				    PRU_PURGEIF, NULL, NULL,
				    (struct mbuf *) ifp, curlwp);
				purged = 1;
			}
		}
		if (purged == 0) {
			/*
			 * XXX What's really the best thing to do
			 * XXX here?  --thorpej@NetBSD.org
			 */
			printf("if_detach: WARNING: AF %d not purged\n",
			    family);
			ifa_remove(ifp, ifa);
		}
		goto again;
	}

	if_free_sadl(ifp);

	/* Walk the routing table looking for straglers. */
	for (i = 0; i <= AF_MAX; i++) {
#ifndef QNX_MFIB
		if ((rnh = rt_tables[i]) != NULL)
#else
		for (fib=0; fib < FIBS_MAX; fib++) {
			if (if_get_fib_enabled(ifp, fib) && ((rnh = rt_tables_mfib[fib][i]) != NULL)) {

#endif
			while ((*rnh->rnh_walktree)(rnh, if_rt_walktree, ifp) == ERESTART)
				continue;
#ifdef QNX_MFIB
			}
		}
#endif
	}

	DOMAIN_FOREACH(dp) {
		if (dp->dom_ifdetach && ifp->if_afdata[dp->dom_family])
			(*dp->dom_ifdetach)(ifp,
			    ifp->if_afdata[dp->dom_family]);

		/*
		 * One would expect multicast memberships (INET and
		 * INET6) on UDP sockets to be purged by the PURGEIF
		 * calls above, but if all addresses were removed from
		 * the interface prior to destruction, the calls will
		 * not be made (e.g. ppp, for which pppd(8) generally
		 * removes addresses before destroying the interface).
		 * Because there is no invariant that multicast
		 * memberships only exist for interfaces with IPv4
		 * addresses, we must call PURGEIF regardless of
		 * addresses.  (Protocols which might store ifnet
		 * pointers are marked with PR_PURGEIF.)
		 */
		for (pr = dp->dom_protosw;
		     pr < dp->dom_protoswNPROTOSW; pr++) {
			so.so_proto = pr;
			if (pr->pr_usrreq != NULL &&
			    pr->pr_flags & PR_PURGEIF)
				(void) (*pr->pr_usrreq)(&so,
				    PRU_PURGEIF, NULL, NULL,
				    (struct mbuf *) ifp, curlwp);
		}
	}

	/* Announce that the interface is gone. */
	rt_ifannouncemsg(ifp, IFAN_DEPARTURE);

#ifdef __QNXNTO__
	if_tcp_ifconf_remove(ifp);
#ifdef INET6
	if_ip6_ifconf_remove(ifp);
#endif
#endif
	ifindex2ifnet[ifp->if_index] = NULL;

	TAILQ_REMOVE(&ifnet, ifp, if_list);

	/*
	 * remove packets that came from ifp, from software interrupt queues.
	 */
	DOMAIN_FOREACH(dp) {
		for (i = 0; i < __arraycount(dp->dom_ifqueues); i++) {
			if (dp->dom_ifqueues[i] == NULL)
				break;
			if_detach_queues(ifp, dp->dom_ifqueues[i]);
		}
	}
#ifdef __QNXNTO__
#if NBRIDGE > 0
	if_detach_queues(ifp, &bridgeintrq);
#endif
	(*iopkt_selfp->ex_destroy)(&ifp->if_snd_ex);
	if (ifp == ipsec_globalifp)
		ipsec_globalifp = NULL;
	if_extra_destroy(ifp);
	unquiesce_all();
#endif

	splx(s);
}

static void
if_detach_queues(struct ifnet *ifp, struct ifqueue *q)
{
	struct mbuf *m, *prev, *next;
#ifdef __QNXNTO__
	struct nw_stk_ctl *sctlp;
	struct ifqueue *ifq;

	sctlp = &stk_ctl;
#endif

	prev = NULL;
	for (m = q->ifq_head; m; m = next) {
		next = m->m_nextpkt;
#ifdef DIAGNOSTIC
		if ((m->m_flags & M_PKTHDR) == 0) {
			prev = m;
			continue;
		}
#endif
		if (m->m_pkthdr.rcvif != ifp) {
			prev = m;
			continue;
		}

		if (prev)
			prev->m_nextpkt = m->m_nextpkt;
		else
			q->ifq_head = m->m_nextpkt;
		if (q->ifq_tail == m)
			q->ifq_tail = prev;
		q->ifq_len--;

		m->m_nextpkt = NULL;
		m_freem(m);
		IF_DROP(q);
	}
#ifdef __QNXNTO__
	/*
	 * If the queue is now empty then remove it from the pkt_rx_q to
	 * avoid dequeueing NULLs in process_pkts(). if_detach_queues is only
	 * called from if_detach() which has already quiesced so no need to
	 * take locks.
	 */
	KASSERT(sctlp->quiesce_count > 0);

	if ((q->ifq_len == 0) && (sctlp->pkt_rx_q != NULL)) {

	    ifq = sctlp->pkt_rx_q;

	    for (;;) {
		if (ifq == q) {
		    if (ifq->ifq_next == ifq) {
			sctlp->pkt_rx_q = NULL;
		    } else {
			ifq->ifq_next->ifq_prev = ifq->ifq_prev;
			*ifq->ifq_prev = ifq->ifq_next;

			ifq->ifq_next = ifq;
			ifq->ifq_prev = &ifq->ifq_next;
		    }
		    break;
		}
		ifq = ifq->ifq_next;
		if (ifq == sctlp->pkt_rx_q) {
		    /* Walked circular queue and didn't find it */
		    break;
		}
	    }
	}
#endif
}

/*
 * Callback for a radix tree walk to delete all references to an
 * ifnet.
 */
static int
#ifndef QNX_MFIB
if_rt_walktree(struct radix_node *rn, void *v)
#else
if_rt_walktree(struct radix_node *rn, void *v, int fib)
#endif
{
	struct ifnet *ifp = (struct ifnet *)v;
	struct rtentry *rt = (struct rtentry *)rn;
	int error;

#ifndef __QNXNTO__
	if (rt->rt_ifp == ifp) {
		/* Delete the entry. */
		error = rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway,
		    rt_mask(rt), rt->rt_flags, NULL);
		if (error)
			printf("%s: warning: unable to delete rtentry @ %p, "
			    "error = %d\n", ifp->if_xname, rt, error);
	}
	return (0);
#else
	/* It may be that rtrequest has caused a recursive rn_walktree to occur
	 * to find all the children of this entry (RTF_CLONED). If we
	 * delete the entry, return an error so that rn_walktree returns. 
	 * We will walk the tree again from the start in if_detach(), just
	 * in case the context of the initial rn_walktree is no longer valid. 
	 */

	if (rt->rt_ifp != ifp)
		return 0;

	/* Delete the entry. */
	error = rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway,
#ifndef QNX_MFIB
	    rt_mask(rt), rt->rt_flags, NULL);
#else
	    rt_mask(rt), rt->rt_flags, NULL, fib);
#endif
	if (error)
		printf("%s: warning: unable to delete rtentry @ %p, "
		    "error = %d\n", ifp->if_xname, rt, error);

	return ERESTART;
#endif
}

/*
 * Create a clone network interface.
 */
int
#ifndef QNX_MFIB
if_clone_create(const char *name)
#else
if_clone_create(const char *name, int fib)
#endif
{
	struct if_clone *ifc;
	int unit;

	ifc = if_clone_lookup(name, &unit);
	if (ifc == NULL)
		return (EINVAL);

#ifndef QNX_MFIB
	if (ifunit(name) != NULL)
#else
	/* 
	 * MFIB: Interfaces in general are globally unique, except loopbacks. So need special case 
	 * to look for existing loopbacks in the right FIB, but others in any FIB. 
	 */
	if (strcmp(ifc->ifc_name, "lo") != 0)
		fib = ANY_FIB;
	if (ifunit(name, fib) != NULL)
#endif
		return (EEXIST);

	return ((*ifc->ifc_create)(ifc, unit));
}

/*
 * Destroy a clone network interface.
 */
int
#ifndef QNX_MFIB
if_clone_destroy(const char *name)
#else
if_clone_destroy(const char *name, int fib)
#endif
{
	struct if_clone *ifc;
	struct ifnet *ifp;

	ifc = if_clone_lookup(name, NULL);
	if (ifc == NULL)
		return (EINVAL);

#ifndef QNX_MFIB
	ifp = ifunit(name);
#else
	/* 
	 * MFIB: Interfaces in general are globally unique, except loopbacks. So need special case 
	 * to find loopbacks in the right FIB but others in any FIB. 
	 */
	if (strcmp(ifc->ifc_name, "lo") != 0)
		fib = ANY_FIB;
	ifp = ifunit(name, fib);
#endif
	if (ifp == NULL)
		return (ENXIO);

	if (ifc->ifc_destroy == NULL)
		return (EOPNOTSUPP);

	return ((*ifc->ifc_destroy)(ifp));
}

/*
 * Look up a network interface cloner.
 */
#ifndef __QNXNTO__
static
#endif
struct if_clone *
if_clone_lookup(const char *name, int *unitp)
{
	struct if_clone *ifc;
	const char *cp;
	int unit;

	/* separate interface name from unit */
	for (cp = name;
	    cp - name < IFNAMSIZ && *cp && (*cp < '0' || *cp > '9');
	    cp++)
		continue;

	if (cp == name || cp - name == IFNAMSIZ || !*cp)
		return (NULL);	/* No name or unit number */

	LIST_FOREACH(ifc, &if_cloners, ifc_list) {
		if (strlen(ifc->ifc_name) == cp - name &&
		    !strncmp(name, ifc->ifc_name, cp - name))
			break;
	}

	if (ifc == NULL)
		return (NULL);

	unit = 0;
	while (cp - name < IFNAMSIZ && *cp) {
		if (*cp < '0' || *cp > '9' || unit > INT_MAX / 10) {
			/* Bogus unit number. */
			return (NULL);
		}
		unit = (unit * 10) + (*cp++ - '0');
	}

	if (unitp != NULL)
		*unitp = unit;
	return (ifc);
}

/*
 * Register a network interface cloner.
 */
void
if_clone_attach(struct if_clone *ifc)
{

	LIST_INSERT_HEAD(&if_cloners, ifc, ifc_list);
	if_cloners_count++;
}

/*
 * Unregister a network interface cloner.
 */
void
if_clone_detach(struct if_clone *ifc)
{

	LIST_REMOVE(ifc, ifc_list);
	if_cloners_count--;
}

/*
 * Provide list of interface cloners to userspace.
 */
static int
if_clone_list(struct if_clonereq *ifcr)
{
	char outbuf[IFNAMSIZ], *dst;
	struct if_clone *ifc;
	int count, error = 0;

	ifcr->ifcr_total = if_cloners_count;
	if ((dst = ifcr->ifcr_buffer) == NULL) {
		/* Just asking how many there are. */
		return (0);
	}

	if (ifcr->ifcr_count < 0)
		return (EINVAL);

	count = (if_cloners_count < ifcr->ifcr_count) ?
	    if_cloners_count : ifcr->ifcr_count;

#ifdef __QNXNTO__
	dst = (char *)(ifcr + 1);
	count = imin(count, (curproc->p_ctxt.msg_max_size - (dst - (char *)curproc->p_ctxt.msg)) / IFNAMSIZ);
#endif
	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL && count != 0;
	     ifc = LIST_NEXT(ifc, ifc_list), count--, dst += IFNAMSIZ) {
		(void)strncpy(outbuf, ifc->ifc_name, sizeof(outbuf));
		if (outbuf[sizeof(outbuf) - 1] != '\0')
			return ENAMETOOLONG;
#ifdef __QNXNTO__
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
#endif
		error = copyout(outbuf, dst, sizeof(outbuf));
		if (error)
			break;
	}

	return (error);
}

void
ifa_insert(struct ifnet *ifp, struct ifaddr *ifa)
{
	ifa->ifa_ifp = ifp;
	TAILQ_INSERT_TAIL(&ifp->if_addrlist, ifa, ifa_list);
	IFAREF(ifa);
}

void
ifa_remove(struct ifnet *ifp, struct ifaddr *ifa)
{
	KASSERT(ifa->ifa_ifp == ifp);
	TAILQ_REMOVE(&ifp->if_addrlist, ifa, ifa_list);
	IFAFREE(ifa);
}

static inline int
equal(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	return sockaddr_cmp(sa1, sa2) == 0;
}

/*
 * Locate an interface based on a complete address.
 */
/*ARGSUSED*/
struct ifaddr *
#ifndef __QNXNTO__
ifa_ifwithaddr(const struct sockaddr *addr)
#else
(ifa_ifwithaddr)(const struct sockaddr *addr, struct ifnet *if_mask
#ifdef QNX_MFIB
		, int fib
#endif
#endif
)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_output == if_nulloutput)
			continue;
#ifdef __QNXNTO__
		if (if_mask != NULL && ifp != if_mask)
			continue;
#ifdef QNX_MFIB
		if (!if_get_fib_enabled(ifp, fib))
			continue;
#endif
#endif
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (equal(addr, ifa->ifa_addr))
				return (ifa);
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    (equal(ifa->ifa_broadaddr, addr)
#ifdef __QNXNTO__
			    || (if_mask != NULL && addr->sa_family == AF_INET &&
			    satosin(addr)->sin_addr.s_addr == INADDR_BROADCAST)
#endif
			    ))
				return (ifa);
		}
	}
	return (NULL);
}

/*
 * Locate the point to point interface with a given destination address.
 */
/*ARGSUSED*/
#ifndef __QNXNTO__
struct ifaddr *
ifa_ifwithdstaddr(const struct sockaddr *addr)
#else
struct ifaddr *
(ifa_ifwithdstaddr)(const struct sockaddr *addr, struct ifnet *if_mask
#ifdef QNX_MFIB
		, int fib
#endif
)
#endif
{
	struct ifnet *ifp;
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_output == if_nulloutput)
			continue;
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			continue;
#ifdef __QNXNTO__
		if (if_mask != NULL && ifp != if_mask)
			continue;
#ifdef QNX_MFIB
		if (!if_get_fib_enabled(ifp, fib))
			continue;
#endif
#endif
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			if (ifa->ifa_addr->sa_family != addr->sa_family ||
			    ifa->ifa_dstaddr == NULL)
				continue;
			if (equal(addr, ifa->ifa_dstaddr))
				return (ifa);
		}
	}
	return (NULL);
}

/*
 * Find an interface on a specific network.  If many, choice
 * is most specific found.
 */
#ifndef __QNXNTO__
struct ifaddr *
ifa_ifwithnet(const struct sockaddr *addr)
#else
struct ifaddr *
(ifa_ifwithnet)(const struct sockaddr *addr, struct ifnet *if_mask
#ifdef QNX_MFIB
		, int fib
#endif
)
#endif
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	const struct sockaddr_dl *sdl;
	struct ifaddr *ifa_maybe = 0;
	u_int af = addr->sa_family;
	const char *addr_data = addr->sa_data, *cplim;

	if (af == AF_LINK) {
		sdl = (const struct sockaddr_dl *)addr;
		if (sdl->sdl_index && sdl->sdl_index < if_indexlim &&
		    ifindex2ifnet[sdl->sdl_index] &&
		    ifindex2ifnet[sdl->sdl_index]->if_output != if_nulloutput)
			return (ifnet_addrs[sdl->sdl_index]);
	}
#ifdef NETATALK
	if (af == AF_APPLETALK) {
		const struct sockaddr_at *sat, *sat2;
		sat = (const struct sockaddr_at *)addr;
		TAILQ_FOREACH(ifp, &ifnet, if_list) {
			if (ifp->if_output == if_nulloutput)
				continue;
			ifa = at_ifawithnet((const struct sockaddr_at *)addr, ifp);
			if (ifa == NULL)
				continue;
			sat2 = (struct sockaddr_at *)ifa->ifa_addr;
			if (sat2->sat_addr.s_net == sat->sat_addr.s_net)
				return (ifa); /* exact match */
			if (ifa_maybe == NULL) {
				/* else keep the if with the right range */
				ifa_maybe = ifa;
			}
		}
		return (ifa_maybe);
	}
#endif
	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_output == if_nulloutput)
			continue;
#ifdef __QNXNTO__
		if (if_mask != NULL && ifp != if_mask)
			continue;
#ifdef QNX_MFIB
		if (!if_get_fib_enabled(ifp, fib))
			continue;
#endif
#endif
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			const char *cp, *cp2, *cp3;

			if (ifa->ifa_addr->sa_family != af ||
			    ifa->ifa_netmask == 0)
 next:				continue;
			cp = addr_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = (const char *)ifa->ifa_netmask +
			    ifa->ifa_netmask->sa_len;
			while (cp3 < cplim) {
				if ((*cp++ ^ *cp2++) & *cp3++) {
					/* want to continue for() loop */
					goto next;
				}
			}
			if (ifa_maybe == 0 ||
			    rn_refines((caddr_t)ifa->ifa_netmask,
			    (caddr_t)ifa_maybe->ifa_netmask))
				ifa_maybe = ifa;
		}
	}
	return (ifa_maybe);
}

/*
 * Find the interface of the addresss.
 */
#ifndef __QNXNTO__
struct ifaddr *
ifa_ifwithladdr(const struct sockaddr *addr)
{
	struct ifaddr *ia;

	if ((ia = ifa_ifwithaddr(addr)) || (ia = ifa_ifwithdstaddr(addr)) ||
	    (ia = ifa_ifwithnet(addr)))
		return (ia);
	return (NULL);
}
#else
struct ifaddr *
(ifa_ifwithladdr)(const struct sockaddr *addr, struct ifnet *ifp_mask
#ifdef QNX_MFIB
		, int fib
#endif
		)
{
	struct ifaddr *ia;

	if ((ia = (ifa_ifwithaddr)(addr, ifp_mask
#ifdef QNX_MFIB
			, fib
#endif
			)) || (ia = (ifa_ifwithdstaddr)(addr, ifp_mask
#ifdef QNX_MFIB
			, fib
#endif
			)) ||
	    (ia = (ifa_ifwithnet)(addr, ifp_mask
#ifdef QNX_MFIB
	    		, fib
#endif
	    		)))
		return (ia);
	return (NULL);
}
#endif

/*
 * Find an interface using a specific address family
 */
struct ifaddr *
ifa_ifwithaf(int af
#ifdef QNX_MFIB
		, int fib
#endif
)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_output == if_nulloutput)
			continue;
#ifdef QNX_MFIB
		if (!if_get_fib_enabled(ifp, fib))
			continue;
#endif
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			if (ifa->ifa_addr->sa_family == af)
				return ifa;
		}
	}
	return NULL;
}

/*
 * Find an interface address specific to an interface best matching
 * a given address.
 */
struct ifaddr *
ifaof_ifpforaddr(const struct sockaddr *addr, struct ifnet *ifp)
{
	struct ifaddr *ifa;
	const char *cp, *cp2, *cp3;
	const char *cplim;
	struct ifaddr *ifa_maybe = 0;
	u_int af = addr->sa_family;

	if (ifp->if_output == if_nulloutput)
		return (NULL);

	if (af >= AF_MAX)
		return (NULL);

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != af)
			continue;
		ifa_maybe = ifa;
		if (ifa->ifa_netmask == 0) {
			if (equal(addr, ifa->ifa_addr) ||
			    (ifa->ifa_dstaddr &&
			     equal(addr, ifa->ifa_dstaddr)))
				return (ifa);
			continue;
		}
		cp = addr->sa_data;
		cp2 = ifa->ifa_addr->sa_data;
		cp3 = ifa->ifa_netmask->sa_data;
		cplim = ifa->ifa_netmask->sa_len + (char *)ifa->ifa_netmask;
		for (; cp3 < cplim; cp3++) {
			if ((*cp++ ^ *cp2++) & *cp3)
				break;
		}
		if (cp3 == cplim)
			return (ifa);
	}
	return (ifa_maybe);
}

/*
 * Default action when installing a route with a Link Level gateway.
 * Lookup an appropriate real ifa to point to.
 * This should be moved to /sys/net/link.c eventually.
 */
void
#ifndef QNX_MFIB
link_rtrequest(int cmd, struct rtentry *rt, struct rt_addrinfo *info)
#else
link_rtrequest(int cmd, struct rtentry *rt, struct rt_addrinfo *info, int fib)
#endif
{
	struct ifaddr *ifa;
	struct sockaddr *dst;
	struct ifnet *ifp;

	if (cmd != RTM_ADD || ((ifa = rt->rt_ifa) == 0) ||
	    ((ifp = ifa->ifa_ifp) == 0) || ((dst = rt_key(rt)) == 0))
		return;
	if ((ifa = ifaof_ifpforaddr(dst, ifp)) != NULL) {
		rt_replace_ifa(rt, ifa);
		if (ifa->ifa_rtrequest && ifa->ifa_rtrequest != link_rtrequest)
#ifndef QNX_MFIB
			ifa->ifa_rtrequest(cmd, rt, info);
#else
		ifa->ifa_rtrequest(cmd, rt, info, fib);
#endif
	}
}

#ifdef __QNXNTO__
static void
linkstate_intr(void *arg)
{
	struct mbuf			*m;
	struct ifnet			*ifp;
	struct linkstate_intr_arg	*lia;


	m = arg;
	lia = mtod(m, struct linkstate_intr_arg *);

	if ((ifp = ifindex2ifnet[lia->index]) != NULL) {
		if_link_state_change(ifp, lia->link_state);
	}

	m_freem(m);
}

static void
link_wakeup_from_stack(unsigned index, int link_state)
{
	struct mbuf			*m;
	struct linkstate_intr_arg	*lia;
	struct ifqueue			*inq;
	struct nw_work_thread		*wtp;
	struct nw_stk_ctl		*sctlp;

	if ((m = m_get(M_DONTWAIT, MT_DATA)) == NULL)
		return;

	wtp = WTP;
	sctlp = &stk_ctl;

	lia = mtod(m, struct linkstate_intr_arg *);
	lia->index = index;
	lia->link_state = link_state;

	inq = &linkstate_intrq;

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		m_freem(m);
	} else {
		IF_ENQUEUE(inq, m);

		if (inq->ifq_len == 1) {
			if (sctlp->pkt_rx_q == NULL) {
				sctlp->pkt_rx_q = inq;
			}
			else {
				/* make this new one the tail */
				inq->ifq_next = sctlp->pkt_rx_q;
				inq->ifq_prev = sctlp->pkt_rx_q->ifq_prev;
				*sctlp->pkt_rx_q->ifq_prev = inq;
				sctlp->pkt_rx_q->ifq_prev  = &inq->ifq_next;
			}
		}
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}

}
#endif

/*
 * Handle a change in the interface link state.
 */
void
if_link_state_change(struct ifnet *ifp, int link_state)
{
#ifdef __QNXNTO__
	if (ISIRUPT) {
		link_wakeup_from_stack(ifp->if_index, link_state);
		return;
	}
#endif
	/* Notify that the link state has changed. */
	if (ifp->if_link_state != link_state) {
		ifp->if_link_state = link_state;
		rt_ifmsg(ifp);
#if NCARP > 0
		if (ifp->if_carp)
			carp_carpdev_state(ifp);
#endif
	}
}

/*
 * Mark an interface down and notify protocols of
 * the transition.
 * NOTE: must be called at splsoftnet or equivalent.
 */
void
if_down(struct ifnet *ifp)
{
	struct ifaddr *ifa;

	ifp->if_flags &= ~IFF_UP;
	microtime(&ifp->if_lastchange);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
		pfctlinput(PRC_IFDOWN, ifa->ifa_addr);
	IFQ_PURGE(&ifp->if_snd);
#if NCARP > 0
	if (ifp->if_carp)
		carp_carpdev_state(ifp);
#endif
	rt_ifmsg(ifp);
}

/*
 * Mark an interface up and notify protocols of
 * the transition.
 * NOTE: must be called at splsoftnet or equivalent.
 */
void
if_up(struct ifnet *ifp)
{
#ifdef notyet
	struct ifaddr *ifa;
#endif

	ifp->if_flags |= IFF_UP;
	microtime(&ifp->if_lastchange);
#ifdef notyet
	/* this has no effect on IP, and will kill all ISO connections XXX */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
		pfctlinput(PRC_IFUP, ifa->ifa_addr);
#endif
#if NCARP > 0
	if (ifp->if_carp)
		carp_carpdev_state(ifp);
#endif
	rt_ifmsg(ifp);
#ifdef INET6
	in6_if_up(ifp);
#endif
}

/*
 * Handle interface watchdog timer routines.  Called
 * from softclock, we decrement timers (if set) and
 * call the appropriate interface routine on expiration.
 */
void
if_slowtimo(void *arg)
{
	struct ifnet *ifp;
	int s = splnet();

	TAILQ_FOREACH(ifp, &ifnet, if_list) {
#ifndef __QNXNTO__
		if (ifp->if_timer == 0 || --ifp->if_timer)
			continue;
#else
		/* There's a window where this can be canceled between tests */
		if ((int)ifp->if_timer <= 0 || --ifp->if_timer)
			continue;
#endif
		if (ifp->if_watchdog)
			(*ifp->if_watchdog)(ifp);
	}
	splx(s);
	callout_reset(&if_slowtimo_ch, hz / IFNET_SLOWHZ,
	    if_slowtimo, NULL);
}

/*
 * Set/clear promiscuous mode on interface ifp based on the truth value
 * of pswitch.  The calls are reference counted so that only the first
 * "on" request actually has an effect, as does the final "off" request.
 * Results are undefined if the "off" and "on" requests are not matched.
 */
int
ifpromisc(struct ifnet *ifp, int pswitch)
{
	int pcount, ret;
	short flags;
	struct ifreq ifr;

	pcount = ifp->if_pcount;
	flags = ifp->if_flags;
	if (pswitch) {
		/*
		 * Allow the device to be "placed" into promiscuous
		 * mode even if it is not configured up.  It will
		 * consult IFF_PROMISC when it is is brought up.
		 */
		if (ifp->if_pcount++ != 0)
			return (0);
		ifp->if_flags |= IFF_PROMISC;
		if ((ifp->if_flags & IFF_UP) == 0)
			return (0);
	} else {
		if (--ifp->if_pcount > 0)
			return (0);
		ifp->if_flags &= ~IFF_PROMISC;
		/*
		 * If the device is not configured up, we should not need to
		 * turn off promiscuous mode (device should have turned it
		 * off when interface went down; and will look at IFF_PROMISC
		 * again next time interface comes up).
		 */
		if ((ifp->if_flags & IFF_UP) == 0)
			return (0);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = ifp->if_flags;
	ret = (*ifp->if_ioctl)(ifp, SIOCSIFFLAGS, (caddr_t) &ifr);
	/* Restore interface state if not successful. */
	if (ret != 0) {
		ifp->if_pcount = pcount;
		ifp->if_flags = flags;
	}
	return (ret);
}

/*
 * Map interface name to
 * interface structure pointer.
 */
struct ifnet *
#ifndef QNX_MFIB
ifunit(const char *name)
#else
ifunit(const char *name, int fib)
#endif
{
#if defined(__QNXNTO__) && defined(IONET_COMPAT)
#ifndef QNX_MFIB
	return ifunit_iter(name, 0);
#else
	return ifunit_iter(name, 0, fib);
#endif
}

static struct ifnet *
#ifndef QNX_MFIB
ifunit_iter(const char *name, int iter)
#else
ifunit_iter(const char *name, int iter, int fib)
#endif
{
	char buf[IFNAMSIZ];
	int j;
#endif
	struct ifnet *ifp;
	const char *cp = name;
	u_int unit = 0;
	u_int i;

	/*
	 * If the entire name is a number, treat it as an ifindex.
	 */
	for (i = 0; i < IFNAMSIZ && *cp >= '0' && *cp <= '9'; i++, cp++) {
		unit = unit * 10 + (*cp - '0');
	}

	/*
	 * If the number took all of the name, then it's a valid ifindex.
	 */
	if (i == IFNAMSIZ || (cp != name && *cp == '\0')) {
		if (unit >= if_indexlim)
			return (NULL);
		ifp = ifindex2ifnet[unit];
		if (ifp == NULL || ifp->if_output == if_nulloutput)
			return (NULL);
		return (ifp);
	}

	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_output == if_nulloutput)
			continue;
#ifdef QNX_MFIB
		/* fib == -1 means don't use fib as search scope */
		if ((fib != -1) && (!if_get_fib_enabled(ifp, fib)))
			continue;
#endif
	 	if (strcmp(ifp->if_xname, name) == 0)
			return (ifp);
	}
#if defined(__QNXNTO__) && defined(IONET_COMPAT)
	if (!ionet_enmap || iter > 0)
		return NULL;

	cp = name;
	if (strncmp(cp, "en", 2) != 0)
		return NULL;

	unit = 0;
	cp += 2;
	for (i = 2; i < IFNAMSIZ && *cp >= '0' && *cp <= '9'; i++, cp++)
		unit = unit * 10 + (*cp - '0');

	if (i != IFNAMSIZ && (i == 2 || *cp != '\0'))
		return NULL;

	/* They're looking for an en<unit> which wasn't found */

	i = unit;
	/*
	 * i is now how many non enX slots we need to find.
	 * The i'th will be mapped to en<unit>.
	 */
	for (j = 0; j < unit; j++) {
		snprintf(buf, sizeof(buf), "en%d", j);
#ifndef QNX_MFIB
		if (ifunit_iter(buf, iter + 1) != NULL)
#else
		if (ifunit_iter(buf, iter + 1, fib) != NULL)
#endif
			i--;
	}


	for (ifp = TAILQ_FIRST(&ifnet); ifp != NULL;
	     ifp = TAILQ_NEXT(ifp, if_list)) {
		/*
		 * We count up the ethernet ifaces in the
		 * order we find them.  This can become non
		 * intuitive in a mix of shim and native
		 * drivers: eg. a mapped en1 may be found 
		 * before a real en0.  Also, mappings may 
		 * change if drivers are loaded / unloaded.
		 * Toggle ionet_enmap to disable all
		 * this.
		 */
#ifdef QNX_MFIB
		if ((fib != -1) && (!if_get_fib_enabled(ifp, fib)))
			continue;
#endif
		cp = ifp->if_xname;
		if (ifp->if_type != IFT_ETHER || (strncmp(cp, "en", 2) == 0 &&
		    cp[2] >= '0' && cp[2] <= '9')) {
			continue;
		}

		if (i-- > 0)
			continue;

		return ifp;
	}
#endif
	return (NULL);
}

/* common */
int
ifioctl_common(struct ifnet *ifp, u_long cmd, void *data)
{
	bool isactive, mkactive;
	int error, s;
	struct ifreq *ifr;
	struct ifcapreq *ifcr;
	struct ifdatareq *ifdr;
	struct if_laddrreq *iflr;
	struct ifaddr *ifa;
	union {
		struct sockaddr sa;
		struct sockaddr_dl sdl;
		struct sockaddr_storage ss;
	} u;
	const struct sockaddr_dl *asdl, *nsdl;

	switch (cmd) {
	case SIOCSIFCAP:
		ifcr = data;
#ifndef __QNXNTO__
		if ((ifcr->ifcr_capenable & ~ifp->if_capabilities) != 0)
			return EINVAL;

		if (ifcr->ifcr_capenable == ifp->if_capenable)
			return 0;
#else
		if ((ifcr->ifcr_capenable_rx & ~ifp->if_capabilities_rx) != 0 ||
		    (ifcr->ifcr_capenable_tx & ~ifp->if_capabilities_tx) != 0)
			return EINVAL;
		if (ifcr->ifcr_capenable_rx == ifp->if_capenable_rx &&
		    ifcr->ifcr_capenable_tx == ifp->if_capenable_tx)
			return 0;
#endif

#ifndef __QNXNTO__
		ifp->if_capenable = ifcr->ifcr_capenable;

		/* Pre-compute the checksum flags mask. */
		ifp->if_csum_flags_tx = 0;
		ifp->if_csum_flags_rx = 0;
		if (ifp->if_capenable & IFCAP_CSUM_IPv4_Tx) {
			ifp->if_csum_flags_tx |= M_CSUM_IPv4;
		}
		if (ifp->if_capenable & IFCAP_CSUM_IPv4_Rx) {
			ifp->if_csum_flags_rx |= M_CSUM_IPv4;
		}

		if (ifp->if_capenable & IFCAP_CSUM_TCPv4_Tx) {
			ifp->if_csum_flags_tx |= M_CSUM_TCPv4;
		}
		if (ifp->if_capenable & IFCAP_CSUM_TCPv4_Rx) {
			ifp->if_csum_flags_rx |= M_CSUM_TCPv4;
		}

		if (ifp->if_capenable & IFCAP_CSUM_UDPv4_Tx) {
			ifp->if_csum_flags_tx |= M_CSUM_UDPv4;
		}
		if (ifp->if_capenable & IFCAP_CSUM_UDPv4_Rx) {
			ifp->if_csum_flags_rx |= M_CSUM_UDPv4;
		}

		if (ifp->if_capenable & IFCAP_CSUM_TCPv6_Tx) {
			ifp->if_csum_flags_tx |= M_CSUM_TCPv6;
		}
		if (ifp->if_capenable & IFCAP_CSUM_TCPv6_Rx) {
			ifp->if_csum_flags_rx |= M_CSUM_TCPv6;
		}

		if (ifp->if_capenable & IFCAP_CSUM_UDPv6_Tx) {
			ifp->if_csum_flags_tx |= M_CSUM_UDPv6;
		}
		if (ifp->if_capenable & IFCAP_CSUM_UDPv6_Rx) {
			ifp->if_csum_flags_rx |= M_CSUM_UDPv6;
		}
#else
		if ((ifp->if_flags & IFF_UP) != 0) {
			/*
			 * Bring it down to avoid any races with packet
			 * reception.  Brought back up below.
			 */
			ifp->if_stop(ifp, 1);
		}

		ifp->if_capenable_rx = ifcr->ifcr_capenable_rx;
		ifp->if_capenable_tx = ifcr->ifcr_capenable_tx;

		/* Pre-compute the checksum flags mask. */
		ifp->if_csum_flags_tx = 0;
		ifp->if_csum_flags_rx = 0;
		if (ifp->if_capenable_rx & IFCAP_CSUM_IPv4)
			ifp->if_csum_flags_rx |= M_CSUM_IPv4;
		if (ifp->if_capenable_tx & IFCAP_CSUM_IPv4)
			ifp->if_csum_flags_tx |= M_CSUM_IPv4;

		if (ifp->if_capenable_rx & IFCAP_CSUM_TCPv4)
			ifp->if_csum_flags_rx |= M_CSUM_TCPv4;
		if (ifp->if_capenable_tx & IFCAP_CSUM_TCPv4)
			ifp->if_csum_flags_tx |= M_CSUM_TCPv4;

		if (ifp->if_capenable_rx & IFCAP_CSUM_UDPv4)
			ifp->if_csum_flags_rx |= M_CSUM_UDPv4;
		if (ifp->if_capenable_tx & IFCAP_CSUM_UDPv4)
			ifp->if_csum_flags_tx |= M_CSUM_UDPv4;

		if (ifp->if_capenable_rx & IFCAP_CSUM_TCPv6)
			ifp->if_csum_flags_rx |= M_CSUM_TCPv6;
		if (ifp->if_capenable_tx & IFCAP_CSUM_TCPv6)
			ifp->if_csum_flags_tx |= M_CSUM_TCPv6;

		if (ifp->if_capenable_rx & IFCAP_CSUM_UDPv6)
			ifp->if_csum_flags_rx |= M_CSUM_UDPv6;
		if (ifp->if_capenable_tx & IFCAP_CSUM_UDPv6)
			ifp->if_csum_flags_tx |= M_CSUM_UDPv6;
#endif
		if (ifp->if_flags & IFF_UP)
			return ENETRESET;
		return 0;
	case SIOCSIFFLAGS:
		ifr = data;
		if ((ifp->if_flags & IFF_UP) && (ifr->ifr_flags & IFF_UP) == 0) {
			s = splnet();
			if_down(ifp);
			splx(s);
		}
		if ((ifr->ifr_flags & IFF_UP) && (ifp->if_flags & IFF_UP) == 0) {
			s = splnet();
			if_up(ifp);
			splx(s);
		}
		ifp->if_flags = (ifp->if_flags & IFF_CANTCHANGE) |
			(ifr->ifr_flags &~ IFF_CANTCHANGE);
		break;
#ifdef __QNXNTO__
	case SIOCSIFNAME: {
		char new_name[IFNAMSIZ], base[IFNAMSIZ];
		char *ep, c;
		int i, unit;

		ifr = data;
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		error = copyin(ifr + 1, new_name, sizeof(new_name));
		if (error)
			return error;

		if ((ep = memchr(new_name, '\0', sizeof(new_name))) == NULL ||
			ep == new_name) {
			return EINVAL;
		}

#ifndef QNX_MFIB
		if (ifunit(new_name) != NULL)
#else
		if (ifunit(new_name, ANY_FIB) != NULL)
#endif
			return EEXIST;

		for (ep--; isdigit(*ep) && ep != new_name; ep--)
			continue;

		if (ep == new_name || *(++ep) == '\0')
			return EINVAL;

		unit = 0;
		c = *ep;
		*ep = '\0';
		strlcpy(base, new_name, sizeof(base));
		*ep = c;
		for(i = 0; *ep != '\0'; ep++, i++) {
			unit *= 10;
			unit += *ep - '0';
		}

		error = dev_update_name(ifp->if_xname, new_name, base, unit);
		/* Not all interfaces have an assoicated dev */
		if (error && error != ENXIO)
			return error;
		rt_ifannouncemsg(ifp, IFAN_DEPARTURE);
#ifdef PFIL_HOOKS
		(void)pfil_run_hooks(&if_pfil,
		    (struct mbuf **)PFIL_IFNET_DETACH, ifp, PFIL_IFNET
#ifdef QNX_MFIB
		    , if_get_first_fib(ifp)
#endif
		    );
		(void)pfil_head_unregister(&ifp->if_pfil);
#endif
		strlcpy(ifp->if_xname, new_name, sizeof(ifp->if_xname));
#ifdef PFIL_HOOKS
		(void)pfil_head_register(&ifp->if_pfil);
		(void)pfil_run_hooks(&if_pfil,
		    (struct mbuf **)PFIL_IFNET_ATTACH, ifp, PFIL_IFNET
#ifdef QNX_MFIB
		    , if_get_first_fib(ifp) /* ifnet attach currently doesn't care about fib*/
#endif
		    ); 
#endif
		rt_ifannouncemsg(ifp, IFAN_ARRIVAL);

		for (;;) {
			IFADDR_FOREACH(ifa, ifp) {
				if (ifa->ifa_addr->sa_family != AF_LINK)
					continue;
				asdl = satocsdl(ifa->ifa_addr);

				if (asdl->sdl_nlen == strlen(ifp->if_xname) &&
				    memcmp(asdl->sdl_data, new_name,
				    asdl->sdl_nlen) == 0)
					continue;

				if (sockaddr_dl_init(&u.sdl, sizeof(u.ss), ifp->if_index,
				    ifp->if_type, ifp->if_xname, strlen(ifp->if_xname),
				    CLLADDR(asdl), asdl->sdl_alen) == NULL)
					return EINVAL;

				if (ifa == ifp->if_dl) {
					isactive = 1;
				}

				rt_newaddrmsg(RTM_DELETE, ifa, 0, NULL);
				ifa_remove(ifp, ifa);

				if ((ifa = if_dl_create(ifp, &nsdl)) == NULL) {
					error = ENOMEM;
					break;
				}
				sockaddr_copy(ifa->ifa_addr,
				    ifa->ifa_addr->sa_len, &u.sa);
				ifa_insert(ifp, ifa);
				rt_newaddrmsg(RTM_ADD, ifa, 0, NULL);

				if (isactive)
					if_activate_sadl(ifp, ifa, nsdl);
				break;
			}
			if (ifa == NULL)
				break;
		}
		break;
	}
#endif
	case SIOCGIFFLAGS:
		ifr = data;
#ifdef __QNXNTO__
		/*
		 * ionet_enmap support.
		 *
		 * SIOCGIFFLAGS is the one ioctl that
		 * will overwrite the passed in name
		 * with the result of tha mapping.  If
		 * ionet_enmap is disabled / deprecated
		 * this should be a no-op.
		 */
		memcpy(ifr->ifr_name, ifp->if_xname,
		    min(sizeof(ifr->ifr_name), sizeof(ifp->if_xname)));
#endif
		ifr->ifr_flags = ifp->if_flags;
		break;

	case SIOCGIFMETRIC:
		ifr = data;
		ifr->ifr_metric = ifp->if_metric;
		break;

	case SIOCGIFMTU:
		ifr = data;
		ifr->ifr_mtu = ifp->if_mtu;
		break;

	case SIOCGIFDLT:
		ifr = data;
		ifr->ifr_dlt = ifp->if_dlt;
		break;

	case SIOCGIFCAP:
		ifcr = data;
#ifndef __QNXNTO__
		ifcr->ifcr_capabilities = ifp->if_capabilities;
		ifcr->ifcr_capenable = ifp->if_capenable;
#else
		ifcr->ifcr_capabilities_rx = ifp->if_capabilities_rx;
		ifcr->ifcr_capabilities_tx = ifp->if_capabilities_tx;
		ifcr->ifcr_capenable_rx = ifp->if_capenable_rx;
		ifcr->ifcr_capenable_tx = ifp->if_capenable_tx;
#endif
		break;

	case SIOCSIFMETRIC:
		ifr = data;
		ifp->if_metric = ifr->ifr_metric;
		break;

	case SIOCGIFDATA:
		ifdr = data;
#ifndef __QNXNTO__
		ifdr->ifdr_data = ifp->if_data;
#else
		if_data_gather(&ifdr->ifdr_data, ifp);
#endif
		break;

	case SIOCZIFDATA:
		ifdr = data;
#ifndef __QNXNTO__
		ifdr->ifdr_data = ifp->if_data;
		/*
		 * Assumes that the volatile counters that can be
		 * zero'ed are at the end of if_data.
		 */
		memset(&ifp->if_data.ifi_ipackets, 0, sizeof(ifp->if_data) -
		    offsetof(struct if_data, ifi_ipackets));
#else
		if_data_gather(&ifdr->ifdr_data, ifp);
		if_data_clr(ifp);
#endif
		break;
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
#ifdef __QNXNTO__
		if(ifp->if_flags & IFF_SHIM)
			return ENOTTY;

		iflr = data;
		asdl = satocsdl(sstocsa(&iflr->addr));
		if((memcmp(LLADDR(asdl), "\0\0\0\0\0\0", ETHER_ADDR_LEN) == 0) || ETHER_IS_MULTICAST(LLADDR(asdl)))
			return EINVAL;

		/* To support the concept of VLANs with a different MAC address from
		 * the parent interface, link addresses added to a vlan interface will
		 * also be added to the parent ifp, so the HW can receive the packets.
		 *
		 * We will now set ENETRESET for all add and delete cmds as all MAC
		 * addresses listed under either address or link
		 * under ifconfig for the parent interface will be accepted by the
		 * HW if this functionality is enabled in the HW.
		 */
#endif
	case SIOCGLIFADDR:
		iflr = data;

		if (iflr->addr.ss_family != AF_LINK)
			return ENOTTY;

		asdl = satocsdl(sstocsa(&iflr->addr));

		if (asdl->sdl_alen != ifp->if_addrlen)
			return EINVAL;

		if (sockaddr_dl_init(&u.sdl, sizeof(u.ss), ifp->if_index,
		    ifp->if_type, ifp->if_xname, strlen(ifp->if_xname),
		    CLLADDR(asdl), asdl->sdl_alen) == NULL)
			return EINVAL;

		if ((iflr->flags & IFLR_PREFIX) == 0)
			;
		else if (iflr->prefixlen != NBBY * ifp->if_addrlen)
			return EINVAL;	/* XXX match with prefix */

		error = 0;

		s = splnet();

		IFADDR_FOREACH(ifa, ifp) {
			if (sockaddr_cmp(&u.sa, ifa->ifa_addr) == 0)
				break;
		}

		switch (cmd) {
		case SIOCGLIFADDR:
			if ((iflr->flags & IFLR_PREFIX) == 0) {
				IFADDR_FOREACH(ifa, ifp) {
					if (ifa->ifa_addr->sa_family == AF_LINK)
						break;
				}
			}
			if (ifa == NULL) {
				error = EADDRNOTAVAIL; 
				break;
			}

			if (ifa == ifp->if_dl)
				iflr->flags = IFLR_ACTIVE;
			else
				iflr->flags = 0;

			sockaddr_copy(sstosa(&iflr->addr), sizeof(iflr->addr),
			    ifa->ifa_addr);

			break;
		case SIOCDLIFADDR:
			if (ifa == NULL)
				error = EADDRNOTAVAIL;
			else if (ifa == ifp->if_dl)
				error = EBUSY;
			else {
				/* TBD routing socket */
				rt_newaddrmsg(RTM_DELETE, ifa, 0, NULL);
				ifa_remove(ifp, ifa);
			}
#ifdef __QNXNTO__
			if (error != EOK)
				break;

			error = ENETRESET; /* Be prepared to update the HW */

			/* If this is a VLAN, the parent will handle the update.
			 * Also if_init is not set for a VLAN
			 */

			if (ifp->if_ioctl != NULL) {
				int err;

				err = (*ifp->if_ioctl)(ifp, cmd, data);

				/* If the ioctl callback did not recognise the
				 * command, continue with ENETRESET and call
				 * the init callback as before. Otherwise if
				 * EOK it was handled, or an error is returned.
				 */

				if (err != ENOTTY && err != EINVAL)
					error = err;

			}
#endif
			break;
		case SIOCALIFADDR:
			if (ifa != NULL)
				;
			else if ((ifa = if_dl_create(ifp, &nsdl)) == NULL) {
				error = ENOMEM;
				break;
			} else {
				sockaddr_copy(ifa->ifa_addr,
				    ifa->ifa_addr->sa_len, &u.sa);
				ifa_insert(ifp, ifa);
				rt_newaddrmsg(RTM_ADD, ifa, 0, NULL);
			}

			mkactive = (iflr->flags & IFLR_ACTIVE) != 0;
			isactive = (ifa == ifp->if_dl);

			if (!isactive && mkactive) {
				if_activate_sadl(ifp, ifa, nsdl);
#ifndef __QNXNTO__
				error = ENETRESET;
			}
#else
			}

			error = ENETRESET; /* Be prepared to update the HW */

			/* If this is a VLAN, the parent will handle the update.
			 * Also if_init is not set for a VLAN
			 */

			if (ifp->if_ioctl != NULL) {
				int err;

				err = (*ifp->if_ioctl)(ifp, cmd, data);

				/* If the ioctl callback did not recognise the
				 * command, continue with ENETRESET and call the
				 * init callback as before. Otherwise if EOK it
				 * was handled, or an error is returned.
				 */

				if (err != ENOTTY && err != EINVAL)
					error = err;
			}
#endif
			break;
		}
		splx(s);
		if (error != ENETRESET)
			return error;
		else if ((ifp->if_flags & IFF_RUNNING) != 0)
			return (*ifp->if_init)(ifp);
		else
			return 0;
	default:
		return EOPNOTSUPP;
	}
	return 0;
}


#ifdef __QNXNTO__
static int if_getptrembed(u_long cmd, caddr_t data) {
	int                          len = 0;
	caddr_t                      ptr;
	struct proc		    *p;
	resmgr_context_t	    *ctp;
	io_devctl_t                 *msg;
	struct __ioctl_getptrembed  *embedmsg;

	if (cmd != DCMD_MISC_GETPTREMBED) {
		return EINVAL;
	}

	/* Need to parse from the top of msg to find the original cmd and its data */
	p = curproc;
	ctp = &p->p_ctxt;
	msg = (io_devctl_t *)ctp->msg;
	embedmsg =  (struct __ioctl_getptrembed *) _DEVCTL_DATA(msg->i);

	data = (caddr_t) (embedmsg + 1) + embedmsg->niov * sizeof(iov_t);
	cmd = embedmsg->dcmd;

	switch (cmd) {
	case SIOCIFGCLONERS:
		{
			struct if_clonereq *ifcr = (struct if_clonereq *) data;
			ptr = ifcr->ifcr_buffer;
			len = ifcr->ifcr_count * IFNAMSIZ;
			break;
		}
	case SIOCGIFMEDIA:
		{
			struct ifmediareq *ifmr = (struct ifmediareq *) data;
			ptr = (caddr_t)ifmr->ifm_ulist;
			len = ifmr->ifm_count * sizeof(int);
			break;
		}

	case SIOCSIFNAME: {
		struct ifreq	*ifr;

		ifr = (struct ifreq *)data;
		ptr = ifr->ifr_data;
		len = IFNAMSIZ;
		break;
	}

	default:
		/* No support for embeddeded pointers for other ioctl commands */
		return EINVAL; /* XX EOPNOSUPP?? */
	}

	if (ptr == NULL)
		return EFAULT;

	return ioctl_getptrembed(msg, ptr, len, embedmsg->niov);
}
#endif

/*
 * Interface ioctls.
 */
int
ifioctl(struct socket *so, u_long cmd, caddr_t data, struct lwp *l)
{
	struct ifnet *ifp;
	struct ifreq *ifr;
	struct ifcapreq *ifcr;
	struct ifdatareq *ifdr;
	int error = 0;
#if defined(COMPAT_OSOCK) || defined(COMPAT_OIFREQ)
	u_long ocmd = cmd;
#endif
	short oif_flags;
#ifdef COMPAT_OIFREQ
	struct ifreq ifrb;
	struct oifreq *oifr = NULL;
#endif
#ifdef QNX_MFIB
	int fib = so->so_fibnum;
#endif

	switch (cmd) {
#ifdef COMPAT_OIFREQ
#ifndef __QNXNTO__
	case OSIOCGIFCONF:
#else
	case NOSIOCGIFCONF:
#endif
	case OOSIOCGIFCONF:
		return compat_ifconf(cmd, data);
#endif
	case SIOCGIFCONF:
#ifndef QNX_MFIB
		return ifconf(cmd, data);
#else
		return ifconf(cmd, data, fib);
#endif
	}

#ifdef COMPAT_OIFREQ
	cmd = compat_cvtcmd(cmd);
	if (cmd != ocmd) {
		oifr = (void *)data;
		ifr = &ifrb;
		data = (void *)ifr;
		ifreqo2n(oifr, ifr);
	} else
#endif
                ifr = (struct ifreq *)data;

#ifdef __QNXNTO__
        /* embedded pointer message */
	if (cmd == DCMD_MISC_GETPTREMBED) {
		struct __ioctl_getptrembed *embed = (struct __ioctl_getptrembed *) data;
		switch (embed->dcmd) {
		case SIOCIFGCLONERS:
		case SIOCGIFMEDIA:
		case SIOCSIFNAME:
			return if_getptrembed(cmd, data);
		default:
			ifr = (struct ifreq *)(data + sizeof(struct __ioctl_getptrembed) + embed->niov*sizeof(iov_t));
			/* Pass message to other (lower level) modules */
		}
	}
#endif

	ifcr = (struct ifcapreq *)data;
	ifdr = (struct ifdatareq *)data;

#ifndef QNX_MFIB
	ifp = ifunit(ifr->ifr_name); /* XX this is invalid if data was if_clonereq and not an ifreq! */
#else
	ifp = ifunit(ifr->ifr_name, fib); /* XX this is invalid if data was if_clonereq and not an ifreq! */
#endif
	switch (cmd) {
	case SIOCIFCREATE:
	case SIOCIFDESTROY:
		if (l) {
			error = kauth_authorize_network(l->l_cred,
			    KAUTH_NETWORK_INTERFACE,
			    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp,
			    (void *)cmd, NULL);
			if (error)
				return error;
		}
#ifndef __QNXNTO__
		return ((cmd == SIOCIFCREATE) ?
			if_clone_create(ifr->ifr_name) :
			if_clone_destroy(ifr->ifr_name));
#else
		if (cmd == SIOCIFDESTROY) {
			/* Settle threads down */

			/*
			 * Allow any interface that has supports detach
			 * to be taken out.  detach has precedence over
			 * a clone destroy func.
			 */
			if ((ifp = ifunit(ifr->ifr_name
#ifdef QNX_MFIB
			    , fib
#endif
			    )) == NULL ||
			    (error = dev_detach_name(ifp->if_xname, DETACH_FORCE)) != EOK) {
				quiesce_all();
				error = if_clone_destroy(ifr->ifr_name
#ifdef QNX_MFIB
				, fib
#endif
				);
				unquiesce_all();
			}

		}
		else {
#ifndef QNX_MFIB
			error = if_clone_create(ifr->ifr_name);
#else
			error = if_clone_create(ifr->ifr_name, fib);
#endif
		}
		return error;
#ifdef QNX_MFIB
	case SIOCDIFFIB: {
		int dest_fib, i;
		struct radix_node_head *rnh;

		if (ifp == NULL)
			ifp = ifunit(ifr->ifr_name, ANY_FIB);
		if (ifp == NULL)
			return ENXIO;

		if (l) {
			error = kauth_authorize_network(l->l_cred,
			    KAUTH_NETWORK_INTERFACE,
			    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp,
			    (void *)cmd, NULL);
			if (error)
				return error;
		}
		ifr = (struct ifreq *)data;
		dest_fib = ifr->ifr_value;

		if (dest_fib >= FIBS_MAX || dest_fib < 0) {
			return EINVAL;
		}
		/* do not allow the last fib to be removed from an interface */
		if (if_get_fib_count(ifp) == 1) {
			return EBUSY; /* last fib on the interface is "locked". Need to delete interface. "if_down()" instead? */
		}

		if (!if_get_fib_enabled(ifp, fib)) {
			return EINVAL; /* fib not enabled, can't remove */
		}
		/* Walk the routing table looking for stragglers. */
		for (i = 0; i <= AF_MAX; i++) {
			if (if_get_fib_enabled(ifp, dest_fib) && ((rnh = rt_tables_mfib[dest_fib][i]) != NULL))
				(void) (*rnh->rnh_walktree)(rnh, if_rt_walktree, ifp);
		}

		/* further processing in the in*.c */

		break;
	}
	case SIOCSIFFIB: {
		/*
		 * This is now complicated enough it probably deserves its own func
		 */
		int dest_fib;

		if (ifp == NULL)
			ifp = ifunit(ifr->ifr_name, ANY_FIB);
		if (ifp == NULL)
			return ENXIO;

		if (l) {
			error = kauth_authorize_network(l->l_cred,
			    KAUTH_NETWORK_INTERFACE,
			    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp,
			    (void *)cmd, NULL);
			if (error)
				return error;
		}
		/*
		 * 2 pieces of data interface and destination_fib
		 *   - The ifp is the interface...
		 *   - The destination fib is the value give in ifr->ifr_value
		 */
		ifr = (struct ifreq *)data;
		dest_fib = ifr->ifr_value;

		if (dest_fib >= FIBS_MAX || dest_fib < 0) {
			return EINVAL;
		}
		if_set_if_fib(ifp, dest_fib);

		return(error);
	}
	case SIOCGIFFIB: {
		struct ifreq *ifr = (struct ifreq *)data;
		error = 0;

		if (ifp == NULL)
			ifp = ifunit(ifr->ifr_name, ANY_FIB);
		if (ifp == NULL)
			return ENXIO;

		if (l) {
			if(kauth_authorize_network(l->l_cred,
					KAUTH_NETWORK_INTERFACE,
					KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp,
					(void *)cmd, NULL) == KAUTH_RESULT_ALLOW) {
				/* we're root, search all fibs for the named interface */
				ifr->ifr_fibmask = ifp->if_fibmask;
				return (error);
			} else {
				/* we're a non-priv user, search only users fibs' for the interface data */
				int i;
				int usermask = 0;
				for (i = 0; i<FIBS_MAX; i++) {
					if (kauth_chkfib4cred(l->l_cred, i) == KAUTH_RESULT_ALLOW) {
						usermask |= 1<<i;
					}
				}
				ifr->ifr_fibmask = usermask;
				return (error);
			}
		}

		return ENXIO; /* no cred or couldn't find requested i/f in the scoped fib, error */
	}
#endif

#endif

	case SIOCIFGCLONERS:
		return (if_clone_list((struct if_clonereq *)data));
	}

	if (ifp == 0)
		return (ENXIO);

	switch (cmd) {
	case SIOCSIFFLAGS:
	case SIOCSIFCAP:
	case SIOCSIFMETRIC:
	case SIOCZIFDATA:
	case SIOCSIFMTU:
	case SIOCSIFPHYADDR:
	case SIOCDIFPHYADDR:
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif
	case SIOCSLIFPHYADDR:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCSIFMEDIA:
	case SIOCSDRVSPEC:
	case SIOCS80211NWID:
	case SIOCS80211NWKEY:
	case SIOCS80211POWER:
	case SIOCS80211BSSID:
	case SIOCS80211CHANNEL:
		if (l) {
			error = kauth_authorize_network(l->l_cred,
			    KAUTH_NETWORK_INTERFACE,
			    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp,
			    (void *)cmd, NULL);
			if (error)
				return error;
		}
	}

	oif_flags = ifp->if_flags;
	switch (cmd) {

	case SIOCSIFFLAGS:
		ifioctl_common(ifp, cmd, data);
		if (ifp->if_ioctl)
			(void) (*ifp->if_ioctl)(ifp, cmd, data);
		break;


#ifdef __QNXNTO__ /* Until class ioctl (eg ether_ioctl) is changed to call ifioctl_common */
	case SIOCSIFCAP: {

		if ((error = ifioctl_common(ifp, cmd, data)) == 0 ||
		    error != ENETRESET) {
			break;
		}

		error = (*ifp->if_init)(ifp);
		break;
	 }

	case SIOCSIFMTU:
	{
		u_long oldmtu = ifp->if_mtu;

		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		error = (*ifp->if_ioctl)(ifp, cmd, data);

		/*
		 * If the link MTU changed, do network layer specific procedure.
		 */
		if (ifp->if_mtu != oldmtu) {
#ifdef INET6
			nd6_setmtu(ifp);
#endif
		}
		break;
	}
#endif
	case SIOCSIFPHYADDR:
	case SIOCDIFPHYADDR:
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif
	case SIOCSLIFPHYADDR:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCSIFMEDIA:
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGLIFPHYADDR:
	case SIOCGIFMEDIA:
		if (ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		break;

	case SIOCSDRVSPEC:
	case SIOCS80211NWID:
	case SIOCS80211NWKEY:
	case SIOCS80211POWER:
	case SIOCS80211BSSID:
	case SIOCS80211CHANNEL:
	default:
		error = ifioctl_common(ifp, cmd, data);
		if (error != EOPNOTSUPP)
			break;
		if (so->so_proto == 0)
			return (EOPNOTSUPP);
#ifdef COMPAT_OSOCK
		error = compat_ifioctl(so, ocmd, cmd, data, l);
#else
		error = ((*so->so_proto->pr_usrreq)(so, PRU_CONTROL,
		    (struct mbuf *)cmd, (struct mbuf *)data,
		    (struct mbuf *)ifp, l));
#endif
		break;
	}

	if (((oif_flags ^ ifp->if_flags) & IFF_UP) != 0) {
#ifdef INET6
		if ((ifp->if_flags & IFF_UP) != 0) {
			int s = splnet();
			s = splnet();
			in6_if_up(ifp);
			splx(s);
		}
#endif
	}
#ifdef COMPAT_OIFREQ
	if (cmd != ocmd)
		ifreqn2o(oifr, ifr);
#endif

	return (error);
}

/*
 * Return interface configuration
 * of system.  List may be used
 * in later ioctl's (above) to get
 * other information.
 *
 * Each record is a struct ifreq.  Before the addition of
 * sockaddr_storage, the API rule was that sockaddr flavors that did
 * not fit would extend beyond the struct ifreq, with the next struct
 * ifreq starting sa_len beyond the struct sockaddr.  Because the
 * union in struct ifreq includes struct sockaddr_storage, every kind
 * of sockaddr must fit.  Thus, there are no longer any overlength
 * records.
 *
 * Records are added to the user buffer if they fit, and ifc_len is
 * adjusted to the length that was written.  Thus, the user is only
 * assured of getting the complete list if ifc_len on return is at
 * least sizeof(struct ifreq) less than it was on entry.
 *
 * If the user buffer pointer is NULL, this routine copies no data and
 * returns the amount of space that would be needed.
 *
 * Invariants:
 * ifrp points to the next part of the user's buffer to be used.  If
 * ifrp != NULL, space holds the number of bytes remaining that we may
 * write at ifrp.  Otherwise, space holds the number of bytes that
 * would have been written had there been adequate space.
 */
/*ARGSUSED*/
int
#ifndef QNX_MFIB
ifconf(u_long cmd, caddr_t data)
#else
ifconf(u_long cmd, caddr_t data, int fib)
#endif
{
	struct ifconf *ifc = (struct ifconf *)data;
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifreq ifr, *ifrp;
	int space, error = 0;
	const int sz = (int)sizeof(struct ifreq);

	if ((ifrp = ifc->ifc_req) == NULL) {
		space = 0;
	} else {
		space = ifc->ifc_len;
#ifdef __QNXNTO__
		/* Point it into our context */

		/* Don't ask,  that's how libc laid out the reply */
		ifrp = (void *)(&ifc->ifc_len + 1);
#endif
	}
	IFNET_FOREACH(ifp) {
#ifdef QNX_MFIB
		if (!if_get_fib_enabled(ifp, fib)) /* skip i/f not on caller's fib */
			continue;
#endif
		(void)strncpy(ifr.ifr_name, ifp->if_xname,
		    sizeof(ifr.ifr_name));
		if (ifr.ifr_name[sizeof(ifr.ifr_name) - 1] != '\0')
			return ENAMETOOLONG;
		if ((ifa = TAILQ_FIRST(&ifp->if_addrlist)) == NULL) {
			/* Interface with no addresses - send zero sockaddr. */
			memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
			if (ifrp == NULL) {
				space += sz;
				continue;
			}
			if (space >= sz) {
				error = copyout(&ifr, ifrp, sz);
				if (error != 0)
					return error;
				ifrp++;
				space -= sz;
			}
		}

		for (; ifa != 0; ifa = TAILQ_NEXT(ifa, ifa_list)) {
			struct sockaddr *sa = ifa->ifa_addr;
			/* all sockaddrs must fit in sockaddr_storage */
			KASSERT(sa->sa_len <= sizeof(ifr.ifr_ifru));

			if (ifrp == NULL) {
				space += sz;
				continue;
			}
			memcpy(&ifr.ifr_space, sa, sa->sa_len);
			if (space >= sz) {
				error = copyout(&ifr, ifrp, sz);
				if (error != 0)
					return (error);
				ifrp++; space -= sz;
			}
		}
	}
	if (ifrp != NULL)
		ifc->ifc_len -= space;
	else
		ifc->ifc_len = space;
	return (error);
}

int
ifreq_setaddr(const u_long cmd, struct ifreq *ifr, const struct sockaddr *sa)
{
	uint8_t len;
	u_long ncmd;
	const uint8_t osockspace = sizeof(ifr->ifr_addr);
	const uint8_t sockspace = sizeof(ifr->ifr_ifru.ifru_space);

#ifdef INET6
	if (cmd == SIOCGIFPSRCADDR_IN6 || cmd == SIOCGIFPDSTADDR_IN6)
		len = MIN(sizeof(struct sockaddr_in6), sa->sa_len);
	else
#endif /* INET6 */
	if ((ncmd = compat_cvtcmd(cmd)) != cmd)
		len = MIN(osockspace, sa->sa_len);
	else
		len = MIN(sockspace, sa->sa_len);
	if (len < sa->sa_len)
		return EFBIG;
	sockaddr_copy(&ifr->ifr_addr, len, sa);
	return 0;
}

/*
 * Queue message on interface, and start output if interface
 * not yet active.
 */
#ifndef __QNXNTO__
int
ifq_enqueue(struct ifnet *ifp, struct mbuf *m
    ALTQ_COMMA ALTQ_DECL(struct altq_pktattr *pktattr))
{
	int len = m->m_pkthdr.len;
	int mflags = m->m_flags;
	int s = splnet();
	int error;

	IFQ_ENQUEUE(&ifp->if_snd, m, pktattr, error);
	if (error) {
		splx(s);
		return error;
	}
	ifp->if_obytes += len;
	if (mflags & M_MCAST)
		ifp->if_omcasts++;
	if ((ifp->if_flags & IFF_OACTIVE) == 0)
		(*ifp->if_start)(ifp);
	splx(s);
	return error;
}
#else
int
ifq_enqueue(struct ifnet *ifp, struct mbuf *m
    ALTQ_COMMA ALTQ_DECL(struct altq_pktattr *pktattr))
{
	return ifq_enqueue_wtp(ifp, m ALTQ_COMMA ALTQ_DECL(pktattr), WTP);
}

int
ifq_enqueue_wtp(struct ifnet *ifp, struct mbuf *m
    ALTQ_COMMA ALTQ_DECL(struct altq_pktattr *pktattr),
    struct nw_work_thread *wtp)
{
	int len = m->m_pkthdr.len;
	int mflags = m->m_flags;
	int error;

	NW_SIGLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
	/*
	 * Queue message on interface, and start output if interface
	 * not yet active.
	 */
	IFQ_ENQUEUE(&ifp->if_snd, m, pktattr, error);
	/*
	 * If error, mbuf is already freed
	 * but we still want to tickle the
	 * driver.
	 */
	if (error == 0) {
		ifp->if_obytes += len;
		if (mflags & M_MCAST)
			ifp->if_omcasts++;
	}
	if ((ifp->if_flags_tx & IFF_OACTIVE) == 0)
		(*ifp->if_start)(ifp); /* This must release the lock */
	else
		NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
	return error;
}
#endif

/*
 * Queue message on interface, possibly using a second fast queue
 */
int
ifq_enqueue2(struct ifnet *ifp, struct ifqueue *ifq, struct mbuf *m
    ALTQ_COMMA ALTQ_DECL(struct altq_pktattr *pktattr))
{
	int error = 0;

	if (ifq != NULL
#ifdef ALTQ
	    && ALTQ_IS_ENABLED(&ifp->if_snd) == 0
#endif
	    ) {
		if (IF_QFULL(ifq)) {
			IF_DROP(&ifp->if_snd);
			m_freem(m);
			if (error == 0)
				error = ENOBUFS;
		}
		else
			IF_ENQUEUE(ifq, m);
	} else
		IFQ_ENQUEUE(&ifp->if_snd, m, pktattr, error);
	if (error != 0) {
		++ifp->if_oerrors;
		return error;
	}

	return 0;
}


#if defined(INET) || defined(INET6)
static void
sysctl_net_ifq_setup(struct sysctllog **clog,
		     int pf, const char *pfname,
		     int ipn, const char *ipname,
		     int qid, struct ifqueue *ifq)
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, pfname, NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, ipname, NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, ipn, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "ifq",
		       SYSCTL_DESCR("Protocol input queue controls"),
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, ipn, qid, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_INT, "len",
		       SYSCTL_DESCR("Current input queue length"),
		       NULL, 0, &ifq->ifq_len, 0,
		       CTL_NET, pf, ipn, qid, IFQCTL_LEN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxlen",
		       SYSCTL_DESCR("Maximum allowed input queue length"),
		       NULL, 0, &ifq->ifq_maxlen, 0,
		       CTL_NET, pf, ipn, qid, IFQCTL_MAXLEN, CTL_EOL);
#ifdef notyet
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_INT, "peak",
		       SYSCTL_DESCR("Highest input queue length"),
		       NULL, 0, &ifq->ifq_peak, 0,
		       CTL_NET, pf, ipn, qid, IFQCTL_PEAK, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_INT, "drops",
		       SYSCTL_DESCR("Packets dropped due to full input queue"),
		       NULL, 0, &ifq->ifq_drops, 0,
		       CTL_NET, pf, ipn, qid, IFQCTL_DROPS, CTL_EOL);
}

#ifdef INET
SYSCTL_SETUP(sysctl_net_inet_ip_ifq_setup,
	     "sysctl net.inet.ip.ifq subtree setup")
{
	extern struct ifqueue ipintrq;

	sysctl_net_ifq_setup(clog, PF_INET, "inet", IPPROTO_IP, "ip",
			     IPCTL_IFQ, &ipintrq);
}
#endif /* INET */

#ifdef INET6
SYSCTL_SETUP(sysctl_net_inet6_ip6_ifq_setup,
	     "sysctl net.inet6.ip6.ifq subtree setup")
{
	extern struct ifqueue ip6intrq;

	sysctl_net_ifq_setup(clog, PF_INET6, "inet6", IPPROTO_IPV6, "ip6",
			     IPV6CTL_IFQ, &ip6intrq);
}
#endif /* INET6 */
#endif /* INET || INET6 */


#ifdef __QNXNTO__
void
if_data_gather(struct if_data *dst, struct ifnet *ifp)
{

	dst->ifi_mtu = ifp->if_mtu;
	dst->ifi_type = ifp->if_type;
	dst->ifi_addrlen = ifp->if_addrlen;
	dst->ifi_hdrlen = ifp->if_hdrlen;
	dst->ifi_metric = ifp->if_metric;
	dst->ifi_link_state = ifp->if_link_state;
	dst->ifi_baudrate = ifp->if_baudrate;
	dst->ifi_ipackets = ifp->if_ipackets;
	dst->ifi_ierrors = ifp->if_ierrors;
	dst->ifi_opackets = ifp->if_opackets;
	dst->ifi_oerrors = ifp->if_oerrors;
	dst->ifi_collisions = ifp->if_collisions;
	dst->ifi_ibytes = ifp->if_ibytes;
	dst->ifi_obytes = ifp->if_obytes;
	dst->ifi_imcasts = ifp->if_imcasts;
	dst->ifi_omcasts = ifp->if_omcasts;
	dst->ifi_iqdrops = ifp->if_iqdrops;
	dst->ifi_noproto = ifp->if_noproto;
	dst->ifi_lastchange = ifp->if_lastchange;
}


/*
 * Clear the 'volatile' counters.
 */
void
if_data_clr(struct ifnet *ifp)
{
	ifp->if_ipackets = 0;
	ifp->if_ierrors = 0;
	ifp->if_opackets = 0;
	ifp->if_oerrors = 0;
	ifp->if_collisions = 0;
	ifp->if_ibytes = 0;
	ifp->if_obytes = 0;
	ifp->if_imcasts = 0;
	ifp->if_omcasts = 0;
	ifp->if_iqdrops = 0;
	ifp->if_noproto = 0;
	ifp->if_lastchange.tv_sec = ifp->if_lastchange.tv_usec = 0;
}

/* Expects to be called with if->if_snd_ex locked */
int
if_ctxt_check(struct ifnet *ifp, struct stk_callback *cb)
{
	if (ISSTACK)
		return 0;

	if (ifp->if_snd.ifq_len > 1) {
		/* callback or tx_done interrupt should be pending */
		return 1;
	}

	cb->func = if_start_cb;
	cb->arg = (void *)((uintptr_t)ifp->if_index);

	stk_context_callback(cb);
	return 1;
}

static void
if_start_cb(void *arg)
{
	struct ifnet	*ifp;

	if ((ifp = ifindex2ifnet[(uintptr_t)arg]) == NULL)
		return;

	NW_SIGLOCK(&ifp->if_snd_ex, iopkt_selfp);
	ifp->if_start(ifp);
}
#endif

#ifndef NDEBUG
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>

#define PROC_BASE "/proc"

int proc_fd, status;

// Structure used to get the process info
struct dinfo_s {
	procfs_debuginfo info;
	char pathbuffer[1024];
};

static int getprocname(u_long pid, char *namebuf, int namelen) {
	struct dinfo_s dinfo;
	char buf[1024];

	/* Open up the proc namespace to find our process info */
	snprintf( buf, 1024, "%s/%d/as", PROC_BASE, (int)pid );
	if( (proc_fd = open(buf, O_RDONLY)) == -1 ) {
		fprintf( stderr, "%s: Error opening path to %s.\n",
				__FUNCTION__, buf );
		close(proc_fd);
		return(0);
	}

	memset(&dinfo, 0, sizeof(dinfo));
	/* Get the info from procmgr */
	status = devctl( proc_fd, DCMD_PROC_MAPDEBUG_BASE, &dinfo,
			sizeof(dinfo), 0);
	if( status != EOK ) {
		close(proc_fd);
		return(0);
	}

	strncpy(namebuf,dinfo.info.path,namelen);
	close(proc_fd);

	return 1;
}

extern int debug_net_so_ioctl_verbosity; /* 0 = off, 1 = errors only, 2+ = everything */

int if_debug_ioctl(u_long pid, u_long cmd, caddr_t data, int error
#ifdef QNX_MFIB
		, int fib
#endif
) {
	char procname[1024];
	char *cmdname= "Unknown";
	int idx, gotname = 0;
	char *ifname = "";

	if ((debug_net_so_ioctl_verbosity == 0) || ((debug_net_so_ioctl_verbosity == 1) && (error == 0) ))
		goto done;

	memset(procname, 0, sizeof(procname));
	gotname = getprocname(pid, procname,1024);
	if (!gotname) {
		procname[0] = '\0';
	} else {
		if ((idx = strnlen(procname, 1024)) >= 16) {
			idx = idx - 15; /* print only the last 15 chars of the path */
		} else
			idx = 0; /* print the whole thing */
	}

	/* decode and print cmd and error with fib-info */
	switch(cmd) {

	case FIONSPACE:
		cmdname = "FIONSPACE";
		break;
	case FIONWRITE:
		cmdname = "FIONWRITE";
		break;
	case SIOCADDRT:
		cmdname = "IOCADDRT";
		break;
#ifdef COMPAT_OIFREQ
#ifndef __QNXNTO__
	case OSIOCGIFCONF:
		cmdname = "OSIOCGIFCONF";
		break;
#else
	case NOSIOCGIFCONF:
		cmdname = "NOSIOCGIFCONF";
		break;
#endif
#endif
	case OOSIOCGIFCONF:
		cmdname = "OOSIOCGIFCONF";
		break;
	case SIOCADDMULTI:
		cmdname = "SIOCADDMULTI";
		break;
	case SIOCAIFADDR:
		cmdname = "SIOCAIFADDR";
		break;
#ifdef QNX_MFIB
	case SIOCAIFFIB:
		cmdname = "SIOCAIFFIB";
		break;
#endif
	case SIOCALIFADDR:
		cmdname = "SIOCALIFADDR";
		break;
	case SIOCATMARK:
		cmdname = "SIOCATMARK";
		break;
	case SIOCDARP:
		cmdname = "SIOCDARP";
		break;
	case SIOCDELMULTI:
		cmdname = "SIOCDELMULTI";
		break;
	case SIOCDELRT:
		cmdname = "SIOCDELRT";
		break;
	case SIOCDIFADDR:
		cmdname = "SIOCDIFADDR";
		break;
#ifdef QNX_MFIB
	case SIOCDIFFIB:
		cmdname = "SIOCDIFFIB";
		break;
#endif
	case SIOCDIFPHYADDR:
		cmdname = "SIOCDIFPHYADDR";
		break;
	case SIOCDLIFADDR:
		cmdname = "SIOCDLIFADDR";
		break;
	case SIOCGARP:
		cmdname = "SIOCGARP";
		break;
	case SIOCGDRVCOM:
		cmdname = "SIOCGDRVCOM";
		break;
	case SIOCGDRVSPEC:
		cmdname = "SIOCGDRVSPEC";
		break;
#if 0 /* needs access to decl's in ip_mroute.h. Don't include for now. */
	case SIOCGETSGCNT:
		cmdname = "SIOCGETSGCNT";
		break;
	case SIOCGETVIFCNT:
		cmdname = "SIOCGETVIFCNT";
		break;
#endif
	case SIOCGHIWAT:
		cmdname = "SIOCGHIWAT";
		break;
	case SIOCGIFADDR:
		cmdname = "SIOCGIFADDR";
		break;
	case SIOCGIFADDRPREF:
		cmdname = "SIOCGIFADDRPREF";
		break;
	case SIOCGIFALIAS:
		cmdname = "SIOCGIFALIAS";
		break;
	case SIOCGIFBRDADDR:
		cmdname = "SIOCGIFBRDADDR";
		break;
	case SIOCGIFCAP:
		cmdname = "SIOCGIFCAP";
		break;
	case SIOCGIFCONF:
		cmdname = "SIOCGIFCONF";
		break;
	case SIOCGIFDATA:
		cmdname = "SIOCGIFDATA";
		break;
	case SIOCGIFDLT:
		cmdname = "SIOCGIFDLT";
		break;
	case SIOCGIFDSTADDR:
		cmdname = "SIOCGIFDSTADDR";
		break;
#ifdef QNX_MFIB
	case SIOCGIFFIB:
		cmdname = "SIOCGIFFIB";
		break;
#endif
	case SIOCGIFFLAGS:
		cmdname = "SIOCGIFFLAGS";
		break;
	case SIOCGIFGENERIC:
		cmdname = "SIOCGIFGENERIC";
		break;
	case SIOCGIFMEDIA:
		cmdname = "SIOCGIFMEDIA";
		break;
	case SIOCGIFMETRIC:
		cmdname = "SIOCGIFMETRIC";
		break;
	case SIOCGIFMTU:
		cmdname = "SIOCGIFMTU";
		break;
	case SIOCGIFNETMASK:
		cmdname = "SIOCGIFNETMASK";
		break;
	case SIOCGIFPDSTADDR:
		cmdname = "SIOCGIFPDSTADDR";
		break;
	case SIOCGIFPSRCADDR:
		cmdname = "SIOCGIFPSRCADDR";
		break;
	case SIOCGLIFADDR:
		cmdname = "SIOCGLIFADDR";
		break;
	case SIOCGLIFPHYADDR:
		cmdname = "SIOCGLIFPHYADDR";
		break;
	case SIOCGLOWAT:
		cmdname = "SIOCGLOWAT";
		break;
	case SIOCGPGRP:
		cmdname = "SIOCGPGRP";
		break;
	case SIOCGVH:
		cmdname = "SIOCGVH";
		break;
	case SIOCIFCREATE:
		cmdname = "SIOCIFCREATE";
		break;
	case SIOCIFDESTROY:
		cmdname = "SIOCIFDESTROY";
		break;
	case SIOCIFGCLONERS:
		cmdname = "SIOCIFGCLONERS";
		break;
	case SIOCS80211BSSID:
		cmdname = "SIOCS80211BSSID";
		break;
	case SIOCS80211CHANNEL:
		cmdname = "SIOCS80211CHANNEL";
		break;
	case SIOCS80211NWID:
		cmdname = "SIOCS80211NWID";
		break;
	case SIOCS80211NWKEY:
		cmdname = "SIOCS80211NWKEY";
		break;
	case SIOCS80211POWER:
		cmdname = "SIOCS80211POWER";
		break;
	case SIOCSARP:
		cmdname = "SIOCSARP";
		break;
	case SIOCSDRVSPEC:
		cmdname = "SIOCSDRVSPEC";
		break;
	case SIOCSHIWAT:
		cmdname = "SIOCSHIWAT";
		break;
	case SIOCSIFADDR:
		cmdname = "SIOCSIFADDR";
		break;
	case SIOCSIFADDRPREF:
		cmdname = "SIOCSIFADDRPREF";
		break;
	case SIOCSIFBRDADDR:
		cmdname = "SIOCSIFBRDADDR";
		break;
	case SIOCSIFCAP:
		cmdname = "SIOCSIFCAP";
		break;
	case SIOCSIFDSTADDR:
		cmdname = "SIOCSIFDSTADDR";
		break;
	case SIOCSIFFIB:
		cmdname = "SIOCSIFFIB";
		break;
	case SIOCSIFFLAGS:
		cmdname = "SIOCSIFFLAGS";
		break;
	case SIOCSIFGENERIC:
		cmdname = "SIOCSIFGENERIC";
		break;
	case SIOCSIFMEDIA:
		cmdname = "SIOCSIFMEDIA";
		break;
	case SIOCSIFMETRIC:
		cmdname = "SIOCSIFMETRIC";
		break;
	case SIOCSIFMTU:
		cmdname = "SIOCSIFMTU";
		break;
	case SIOCSIFNAME:
		cmdname = "SIOCSIFNAME";
		break;
	case SIOCSIFNETMASK:
		cmdname = "SIOCSIFNETMASK";
		break;
	case SIOCSIFPHYADDR:
		cmdname = "SIOCSIFPHYADDR";
		break;
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
		cmdname = "SIOCSIFPHYADDR_IN6";
		break;
#endif
	case SIOCSLIFPHYADDR:
		cmdname = "SIOCSLIFPHYADDR";
		break;
	case SIOCSLOWAT:
		cmdname = "SIOCSLOWAT";
		break;
	case SIOCSPGRP:
		cmdname = "SIOCSPGRP";
		break;
	case SIOCSVH:
		cmdname = "SIOCSVH";
		break;
	case SIOCZIFDATA:
		cmdname = "SIOCZIFDATA";
		break;

	}

	switch (cmd) {
#ifdef COMPAT_OIFREQ
#ifndef __QNXNTO__
	case OSIOCGIFCONF:
#else
	case NOSIOCGIFCONF:
#endif
	case OOSIOCGIFCONF:
#endif
	case SIOCGIFCONF:
		ifname = "---";
		break;
	default: 	{
		struct ifreq *ifr;
		struct ifreq ifrb;
		struct oifreq *oifr = NULL;
	#if defined(COMPAT_OSOCK) || defined(COMPAT_OIFREQ)
		u_long ocmd = cmd;
	#endif
#ifdef COMPAT_OIFREQ
		cmd = compat_cvtcmd(cmd);
		if (cmd != ocmd) {
			oifr = (void *)data;
			ifr = &ifrb;
			data = (void *)ifr;
			ifreqo2n(oifr, ifr);
		} else
#endif
			ifr = (struct ifreq *)data;
		/* embedded pointer message */
		if (cmd == DCMD_MISC_GETPTREMBED) {
			struct __ioctl_getptrembed *embed = (struct __ioctl_getptrembed *) data;
			switch (embed->dcmd) {
			case SIOCIFGCLONERS:
			case SIOCGIFMEDIA:
			case SIOCSIFNAME:
				ifname = "***";
			default:
				ifr = (struct ifreq *)(data + sizeof(struct __ioctl_getptrembed) + embed->niov*sizeof(iov_t));
				/* Pass message to other (lower level) modules */
			}
		}
		ifname = ifr->ifr_name;
		break;
	  }
	}

#ifndef QNX_MFIB
	printf("pid[%12lu=%16.16s]::%16.16s/%3ld::cmd[0x%08lx]: i/f=%16.16 error = %4d/%s\n", pid, &(procname[idx]), cmdname, cmd&0xff, cmd, ifname, error, strerror(error));
#else
	printf("pid[%12lu=%16.16s] @ fib[%2d]::%16.16s/%3ld::cmd[0x%08lx]: i/f=%16.16s error = %4d/%s\n",pid, &(procname[idx]), fib, cmdname, cmd&0xff, cmd, ifname, error, strerror(error));
#endif

done:
	return error;
}
#endif

#ifdef QNX_MFIB
/*
 * MFIB helper routines
 */

/*inline*/ int if_get_fib_count(struct ifnet *ifp) {
	int i, cnt=0;
	for (i = 0; i< FIBS_MAX; i++) {
		if (if_get_fib_enabled(ifp, i))
			cnt++;
	}
	return cnt;
}

/*inline*/ int if_get_next_fib(struct ifnet *ifp, int start_fib) {
	int fibnum = start_fib+1;
	while((ifp->if_fibmask & (0x1UL << fibnum)) == 0 && fibnum < FIBS_MAX) {
		fibnum++;
	}
	return fibnum;
}

/*inline*/ int if_get_first_fib(struct ifnet *ifp) {
	int fib = if_get_next_fib(ifp, -1);
	if (fib < 0 || fib >= FIBS_MAX)
		panic("fib out of range for interface %s", ifp->if_xname);
	return fib;
}

/*inline*/ int if_get_fib_enabled(struct ifnet *ifp, int fib) {
	if ((ifp->if_fibmask & (0x1UL << fib)) == 0) {
		return 0;
	} else {
		return 1;
	}
}

void if_set_fib(struct ifnet *ifp, int fib) {
	ifp->if_fibmask = 1UL<<fib;
}
void if_add_fib(struct ifnet *ifp, int fib) {
	if (if_get_fib_enabled(ifp, fib)) {
		panic("fib mask set before calling");
	}
	ifp->if_fibmask |= 1UL<<fib;

#ifdef INET6
	in6_add_fib(ifp, fib);
#endif
}
void if_del_fib(struct ifnet *ifp, int fib) {
	int i;
	struct radix_node_head *rnh;

#ifdef INET6
	in6_del_fib(ifp, fib);
#endif

	/* Crush all routes on all address families to this ifp in this fib */
	for (i = 0; i <= AF_MAX; i++) {
		if ((rnh = rt_tables_mfib[fib][i]) != NULL)
			while ((*rnh->rnh_walktree)(rnh, if_rt_walktree, ifp) == ERESTART) {
				continue;
			}
	}

	ifp->if_fibmask &= ~(1UL<<fib);
}

static void if_set_if_fib(struct ifnet *ifp, int dest_fib)
{
	struct ifaddr *ifa;
	const struct protosw *pr;
	int i, family, purged;
	struct domain *dp;
	struct socket so;
	struct radix_node_head *rnh;
	int tmp_fib;
	/*
	 * 1) if_down, if_detach the interface from given fib
	 */
	if_down(ifp);
	if (ifp->if_stop != NULL) /* interfaces like loopbacks may not have an if_stop callback. */
		ifp->if_stop(ifp, 0);
	/*
	 * Rip all the addresses off the interface.  This should make
	 * all of the routes go away.
	 *
	 * pr_usrreq calls can remove an arbitrary number of ifaddrs
	 * from the list, including our "cursor", ifa.  For safety,
	 * and to honor the TAILQ abstraction, I just restart the
	 * loop after each removal.  Note that the loop will exit
	 * when all of the remaining ifaddrs belong to the AF_LINK
	 * family.  I am counting on the historical fact that at
	 * least one pr_usrreq in each address domain removes at
	 * least one ifaddr.
	 */
	again:
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		family = ifa->ifa_addr->sa_family;
#ifdef IFAREF_DEBUG
		printf("if_detach: ifaddr %p, family %d, refcnt %d\n",
				ifa, family, ifa->ifa_refcnt);
		if (last_ifa != NULL && ifa == last_ifa)
			panic("if_detach: loop detected");
		last_ifa = ifa;
#endif
		if (family == AF_LINK)
			continue;
		dp = pffinddomain(family);
#ifdef DIAGNOSTIC
		if (dp == NULL)
			panic("if_detach: no domain for AF %d",
					family);
#endif
		/*
		 * XXX These PURGEIF calls are redundant with the
		 * purge-all-families calls below, but are left in for
		 * now both to make a smaller change, and to avoid
		 * unplanned interactions with clearing of
		 * ifp->if_addrlist.
		 */
		purged = 0;
		memset(&so, 0, sizeof(so));
		for (pr = dp->dom_protosw;
				pr < dp->dom_protoswNPROTOSW; pr++) {
			so.so_proto = pr;
			if (pr->pr_usrreq != NULL) {
				(void) (*pr->pr_usrreq)(&so,
						PRU_PURGEIF, NULL, NULL,
						(struct mbuf *) ifp, curlwp);
				purged = 1;
			}
		}
		if (purged == 0) {
			/*
			 * XXX What's really the best thing to do
			 * XXX here?  --thorpej@NetBSD.org
			 */
			printf("if_detach: WARNING: AF %d not purged\n",
					family);
			ifa_remove(ifp, ifa);
		}
		goto again;
	}
	/* Walk the routing table looking for stragglers. */
	for (i = 0; i <= AF_MAX; i++) {
		for (tmp_fib=0; tmp_fib < FIBS_MAX; tmp_fib++) {
			if (if_get_fib_enabled(ifp, tmp_fib) && ((rnh = rt_tables_mfib[tmp_fib][i]) != NULL))
				(void) (*rnh->rnh_walktree)(rnh, if_rt_walktree, ifp);
		}
	}
	/*
	 * 2) if_attach the interface to the new fib
	 */
	if_set_fib(ifp, dest_fib);
	if (ifp->if_init != NULL)
		ifp->if_init(ifp);
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if.c $ $Rev: 822252 $")
#endif
