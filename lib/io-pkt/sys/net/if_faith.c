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

/*	$NetBSD: if_faith.c,v 1.37 2006/11/16 01:33:40 christos Exp $	*/
/*	$KAME: if_faith.c,v 1.21 2001/02/20 07:59:26 itojun Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
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
 */
/*
 * derived from
 *	@(#)if_loop.c	8.1 (Berkeley) 6/10/93
 * Id: if_loop.c,v 1.22 1996/06/19 16:24:10 wollman Exp
 */

/*
 * IPv6-to-IPv4 TCP relay capturing interface
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_faith.c,v 1.37 2006/11/16 01:33:40 christos Exp $");

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <machine/cpu.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/if_faith.h>

#ifdef	INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#endif

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#include "bpfilter.h"

#include <net/net_osdep.h>

static int	faithioctl(struct ifnet *, u_long, caddr_t);
static int	faithoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
			    struct rtentry *);
static void	faithrtrequest(int, struct rtentry *, struct rt_addrinfo *);

void	faithattach(int);

static int	faith_clone_create(struct if_clone *, int);
static int	faith_clone_destroy(struct ifnet *);

static struct if_clone faith_cloner =
    IF_CLONE_INITIALIZER("faith", faith_clone_create, faith_clone_destroy);

#define	FAITHMTU	1500

/* ARGSUSED */
void
faithattach(int count)
{

	if_clone_attach(&faith_cloner);
}

static int
faith_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet *ifp;

	ifp = malloc(sizeof(*ifp), M_DEVBUF, M_WAITOK | M_ZERO);

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "%s%d",
	    ifc->ifc_name, unit);

	ifp->if_mtu = FAITHMTU;
	/* Change to BROADCAST experimentaly to announce its prefix. */
	ifp->if_flags = /* IFF_LOOPBACK */ IFF_BROADCAST | IFF_MULTICAST;
	ifp->if_ioctl = faithioctl;
	ifp->if_output = faithoutput;
	ifp->if_type = IFT_FAITH;
	ifp->if_hdrlen = 0;
	ifp->if_addrlen = 0;
	ifp->if_dlt = DLT_NULL;
	if_attach(ifp);
	if_alloc_sadl(ifp);
#if NBPFILTER > 0
	bpfattach(ifp, DLT_NULL, sizeof(u_int));
#endif
	return (0);
}

int
faith_clone_destroy(struct ifnet *ifp)
{

#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	if_detach(ifp);
	free(ifp, M_DEVBUF);

	return (0);
}

int
faithoutput(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	int s, isr;
	struct ifqueue *ifq = 0;

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("faithoutput no HDR");
#if NBPFILTER > 0
	/* BPF write needs to be handled specially */
	if (dst->sa_family == AF_UNSPEC) {
		dst->sa_family = *(mtod(m, int *));
		m->m_len -= sizeof(int);
		m->m_pkthdr.len -= sizeof(int);
		m->m_data += sizeof(int);
	}

	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, dst->sa_family, m);
#endif

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		m_freem(m);
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		        rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}
	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;
	switch (dst->sa_family) {
#ifdef INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		ifq = &ip6intrq;
		isr = NETISR_IPV6;
		break;
#endif
	default:
		m_freem(m);
		return EAFNOSUPPORT;
	}

	/* XXX do we need more sanity checks? */

	m->m_pkthdr.rcvif = ifp;
	s = splnet();
#ifndef __QNXNTO__
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		m_freem(m);
		splx(s);
		return (ENOBUFS);
	}
	IF_ENQUEUE(ifq, m);
#else
	{
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;

	sctlp = &stk_ctl;
	wtp = WTP;

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		m_freem(m);
		return (ENOBUFS);
	}
	IF_ENQUEUE(ifq, m);

	if (ifq->ifq_len == 1) {
		if (sctlp->pkt_rx_q == NULL) {
			sctlp->pkt_rx_q = ifq;
		}
		else {
			/* make this new one the tail */
			ifq->ifq_next = sctlp->pkt_rx_q;
			ifq->ifq_prev = sctlp->pkt_rx_q->ifq_prev;
			*sctlp->pkt_rx_q->ifq_prev = ifq;
			sctlp->pkt_rx_q->ifq_prev  = &ifq->ifq_next;
		}
	}
	NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}
#endif
	schednetisr(isr);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	splx(s);
	return (0);
}

/* ARGSUSED */
static void
faithrtrequest(int cmd, struct rtentry *rt,
    struct rt_addrinfo *info)
{
	if (rt)
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu; /* for ISO */
}

/*
 * Process an ioctl request.
 */
/* ARGSUSED */
static int
faithioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		ifa = (struct ifaddr *)data;
		ifa->ifa_rtrequest = faithrtrequest;
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:
			break;
#endif
#ifdef INET6
		case AF_INET6:
			break;
#endif

		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;

#ifdef SIOCSIFMTU
	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		break;
#endif

	case SIOCSIFFLAGS:
		break;

	default:
		error = EINVAL;
	}
	return (error);
}

#ifdef INET6
/*
 * XXX could be slow
 * XXX could be layer violation to call sys/net from sys/netinet6
 */
int
faithprefix(struct in6_addr *in6)
{
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	int ret;

	if (ip6_keepfaith == 0)
		return 0;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_addr = *in6;
	rt = rtalloc1((struct sockaddr *)&sin6, 0);
	if (rt && rt->rt_ifp && rt->rt_ifp->if_type == IFT_FAITH &&
	    (rt->rt_ifp->if_flags & IFF_UP) != 0)
		ret = 1;
	else
		ret = 0;
	if (rt)
		RTFREE(rt);
	return ret;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_faith.c $ $Rev: 680336 $")
#endif
