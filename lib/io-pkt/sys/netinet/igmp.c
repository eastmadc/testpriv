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

/*	$NetBSD: igmp.c,v 1.43 2006/10/05 17:35:19 tls Exp $	*/

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
 * Internet Group Management Protocol (IGMP) routines.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 *
 * MULTICAST Revision: 1.3
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: igmp.c,v 1.43 2006/10/05 17:35:19 tls Exp $");

#include "opt_mrouting.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>

#include <machine/stdarg.h>

#define IP_MULTICASTOPTS	0

POOL_INIT(igmp_rti_pool, sizeof(struct router_info), 0, 0, 0, "igmppl", NULL);
struct igmpstat igmpstat;
#ifdef __QNXNTO__
NLIST_EXPORT(igmpstat, igmpstat);
#endif
int igmp_timers_are_running;
static LIST_HEAD(, router_info) rti_head = LIST_HEAD_INITIALIZER(rti_head);

void igmp_sendpkt(struct in_multi *, int);
static int rti_fill(struct in_multi *);
static struct router_info *rti_find(struct ifnet *);
static void rti_delete(struct ifnet *);

static int
rti_fill(struct in_multi *inm)
{
	struct router_info *rti;

	/* this function is called at splsoftnet() */
	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_ifp == inm->inm_ifp) {
			inm->inm_rti = rti;
			if (rti->rti_type == IGMP_v1_ROUTER)
				return (IGMP_v1_HOST_MEMBERSHIP_REPORT);
			else
				return (IGMP_v2_HOST_MEMBERSHIP_REPORT);
		}
	}

	rti = pool_get(&igmp_rti_pool, PR_NOWAIT);
	if (rti == NULL)
		return 0;
	rti->rti_ifp = inm->inm_ifp;
	rti->rti_type = IGMP_v2_ROUTER;
	LIST_INSERT_HEAD(&rti_head, rti, rti_link);
#ifdef __QNXNTO__
	pfslowtimo_kick();
#endif
	inm->inm_rti = rti;
	return (IGMP_v2_HOST_MEMBERSHIP_REPORT);
}

static struct router_info *
rti_find(struct ifnet *ifp)
{
	struct router_info *rti;
	int s = splsoftnet();

	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_ifp == ifp)
			return (rti);
	}

	rti = pool_get(&igmp_rti_pool, PR_NOWAIT);
	if (rti == NULL) {
		splx(s);
		return NULL;
	}
	rti->rti_ifp = ifp;
	rti->rti_type = IGMP_v2_ROUTER;
	LIST_INSERT_HEAD(&rti_head, rti, rti_link);
#ifdef __QNXNTO__
	pfslowtimo_kick();
#endif
	splx(s);
	return (rti);
}

static void
rti_delete(struct ifnet *ifp)	/* MUST be called at splsoftnet */
{
	struct router_info *rti;

	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_ifp == ifp) {
			LIST_REMOVE(rti, rti_link);
			pool_put(&igmp_rti_pool, rti);
			return;
		}
	}
}

void
igmp_input(struct mbuf *m, ...)
{
	int proto;
	int iphlen;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip *ip = mtod(m, struct ip *);
	struct igmp *igmp;
	u_int minlen;
	struct in_multi *inm;
	struct in_multistep step;
	struct router_info *rti;
	struct in_ifaddr *ia;
	u_int timer;
	va_list ap;
	u_int16_t ip_len;

	va_start(ap, m);
	iphlen = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	++igmpstat.igps_rcv_total;

	/*
	 * Validate lengths
	 */
	minlen = iphlen + IGMP_MINLEN;
	ip_len = ntohs(ip->ip_len);
	if (ip_len < minlen) {
		++igmpstat.igps_rcv_tooshort;
		m_freem(m);
		return;
	}
	if (((m->m_flags & M_EXT) && (ip->ip_src.s_addr & IN_CLASSA_NET) == 0)
	    || m->m_len < minlen) {
		if ((m = m_pullup(m, minlen)) == 0) {
			++igmpstat.igps_rcv_tooshort;
			return;
		}
		ip = mtod(m, struct ip *);
	}

	/*
	 * Validate checksum
	 */
	m->m_data += iphlen;
	m->m_len -= iphlen;
	igmp = mtod(m, struct igmp *);
	/* No need to assert alignment here. */
	if (in_cksum(m, ip_len - iphlen)) {
		++igmpstat.igps_rcv_badsum;
		m_freem(m);
		return;
	}
	m->m_data -= iphlen;
	m->m_len += iphlen;

	switch (igmp->igmp_type) {

	case IGMP_HOST_MEMBERSHIP_QUERY:
		++igmpstat.igps_rcv_queries;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (igmp->igmp_code == 0) {
			rti = rti_find(ifp);
			if (rti == NULL)
				break;
			rti->rti_type = IGMP_v1_ROUTER;
#ifdef __QNXNTO__
			pfslowtimo_kick();
#endif
			rti->rti_age = 0;

			if (ip->ip_dst.s_addr != INADDR_ALLHOSTS_GROUP) {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}

			/*
			 * Start the timers in all of our membership records
			 * for the interface on which the query arrived,
			 * except those that are already running and those
			 * that belong to a "local" group (224.0.0.X).
			 */
			IN_FIRST_MULTI(step, inm);
			while (inm != NULL) {
				if (inm->inm_ifp == ifp &&
				    inm->inm_timer == 0 &&
				    !IN_LOCAL_GROUP(inm->inm_addr.s_addr)) {
					inm->inm_state = IGMP_DELAYING_MEMBER;
					inm->inm_timer = IGMP_RANDOM_DELAY(
					    IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ);
					igmp_timers_are_running = 1;
#ifdef __QNXNTO__
					pffasttimo_kick();
#endif
				}
				IN_NEXT_MULTI(step, inm);
			}
		} else {
			if (!IN_MULTICAST(ip->ip_dst.s_addr)) {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}

			timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
			if (timer == 0)
				timer =1;

			/*
			 * Start the timers in all of our membership records
			 * for the interface on which the query arrived,
			 * except those that are already running and those
			 * that belong to a "local" group (224.0.0.X).  For
			 * timers already running, check if they need to be
			 * reset.
			 */
			IN_FIRST_MULTI(step, inm);
			while (inm != NULL) {
				if (inm->inm_ifp == ifp &&
				    !IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
				    (ip->ip_dst.s_addr == INADDR_ALLHOSTS_GROUP ||
				     in_hosteq(ip->ip_dst, inm->inm_addr))) {
					switch (inm->inm_state) {
					case IGMP_DELAYING_MEMBER:
						if (inm->inm_timer <= timer)
							break;
						/* FALLTHROUGH */
					case IGMP_IDLE_MEMBER:
					case IGMP_LAZY_MEMBER:
					case IGMP_AWAKENING_MEMBER:
						inm->inm_state =
						    IGMP_DELAYING_MEMBER;
						inm->inm_timer =
						    IGMP_RANDOM_DELAY(timer);
						igmp_timers_are_running = 1;
#ifdef __QNXNTO__
						pffasttimo_kick();
#endif
						break;
					case IGMP_SLEEPING_MEMBER:
						inm->inm_state =
						    IGMP_AWAKENING_MEMBER;
						break;
					}
				}
				IN_NEXT_MULTI(step, inm);
			}
		}

		break;

	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(igmp->igmp_group.s_addr) ||
		    !in_hosteq(igmp->igmp_group, ip->ip_dst)) {
			++igmpstat.igps_rcv_badreports;
			m_freem(m);
			return;
		}

		/*
		 * KLUDGE: if the IP source address of the report has an
		 * unspecified (i.e., zero) subnet number, as is allowed for
		 * a booting host, replace it with the correct subnet number
		 * so that a process-level multicast routing daemon can
		 * determine which subnet it arrived from.  This is necessary
		 * to compensate for the lack of any way for a process to
		 * determine the arrival interface of an incoming packet.
		 */
		if ((ip->ip_src.s_addr & IN_CLASSA_NET) == 0) {
			IFP_TO_IA(ifp, ia);		/* XXX */
			if (ia)
				ip->ip_src.s_addr = ia->ia_subnet;
		}

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			switch (inm->inm_state) {
			case IGMP_IDLE_MEMBER:
			case IGMP_LAZY_MEMBER:
			case IGMP_AWAKENING_MEMBER:
			case IGMP_SLEEPING_MEMBER:
				inm->inm_state = IGMP_SLEEPING_MEMBER;
				break;
			case IGMP_DELAYING_MEMBER:
				if (inm->inm_rti->rti_type == IGMP_v1_ROUTER)
					inm->inm_state = IGMP_LAZY_MEMBER;
				else
					inm->inm_state = IGMP_SLEEPING_MEMBER;
				break;
			}
		}

		break;

	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
#ifdef MROUTING
		/*
		 * Make sure we don't hear our own membership report.  Fast
		 * leave requires knowing that we are the only member of a
		 * group.
		 */
		IFP_TO_IA(ifp, ia);			/* XXX */
		if (ia && in_hosteq(ip->ip_src, ia->ia_addr.sin_addr))
			break;
#endif

		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(igmp->igmp_group.s_addr) ||
		    !in_hosteq(igmp->igmp_group, ip->ip_dst)) {
			++igmpstat.igps_rcv_badreports;
			m_freem(m);
			return;
		}

		/*
		 * KLUDGE: if the IP source address of the report has an
		 * unspecified (i.e., zero) subnet number, as is allowed for
		 * a booting host, replace it with the correct subnet number
		 * so that a process-level multicast routing daemon can
		 * determine which subnet it arrived from.  This is necessary
		 * to compensate for the lack of any way for a process to
		 * determine the arrival interface of an incoming packet.
		 */
		if ((ip->ip_src.s_addr & IN_CLASSA_NET) == 0) {
#ifndef MROUTING
			IFP_TO_IA(ifp, ia);		/* XXX */
#endif
			if (ia)
				ip->ip_src.s_addr = ia->ia_subnet;
		}

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			switch (inm->inm_state) {
			case IGMP_DELAYING_MEMBER:
			case IGMP_IDLE_MEMBER:
			case IGMP_AWAKENING_MEMBER:
				inm->inm_state = IGMP_LAZY_MEMBER;
				break;
			case IGMP_LAZY_MEMBER:
			case IGMP_SLEEPING_MEMBER:
				break;
			}
		}

		break;

	}

	/*
	 * Pass all valid IGMP packets up to any process(es) listening
	 * on a raw IGMP socket.
	 */
	rip_input(m, iphlen, proto);
	return;
}

int
igmp_joingroup(struct in_multi *inm)
{
	int report_type;
	int s = splsoftnet();

	inm->inm_state = IGMP_IDLE_MEMBER;

	if (!IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
	    (inm->inm_ifp->if_flags & IFF_LOOPBACK) == 0) {
		report_type = rti_fill(inm);
		if (report_type == 0) {
			splx(s);
			return ENOMEM;
		}
		igmp_sendpkt(inm, report_type);
		inm->inm_state = IGMP_DELAYING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(
		    IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ);
		igmp_timers_are_running = 1;
#ifdef __QNXNTO__
		pffasttimo_kick();
#endif
	} else
		inm->inm_timer = 0;
	splx(s);
	return 0;
}

void
igmp_leavegroup(struct in_multi *inm)
{

	switch (inm->inm_state) {
	case IGMP_DELAYING_MEMBER:
	case IGMP_IDLE_MEMBER:
		if (!IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
		    (inm->inm_ifp->if_flags & IFF_LOOPBACK) == 0)
			if (inm->inm_rti->rti_type != IGMP_v1_ROUTER)
				igmp_sendpkt(inm, IGMP_HOST_LEAVE_MESSAGE);
		break;
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_SLEEPING_MEMBER:
		break;
	}
}

#ifndef __QNXNTO__
void
#else
int
#endif
igmp_fasttimo(void)
{
	struct in_multi *inm;
	struct in_multistep step;
	int s;

	/*
	 * Quick check to see if any work needs to be done, in order
	 * to minimize the overhead of fasttimo processing.
	 */
	if (!igmp_timers_are_running)
#ifndef __QNXNTO__
		return;
#else
		return 0;
#endif

	s = splsoftnet();
	igmp_timers_are_running = 0;
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		if (inm->inm_timer == 0) {
			/* do nothing */
		} else if (--inm->inm_timer == 0) {
			if (inm->inm_state == IGMP_DELAYING_MEMBER) {
				if (inm->inm_rti->rti_type == IGMP_v1_ROUTER)
					igmp_sendpkt(inm,
					    IGMP_v1_HOST_MEMBERSHIP_REPORT);
				else
					igmp_sendpkt(inm,
					    IGMP_v2_HOST_MEMBERSHIP_REPORT);
				inm->inm_state = IGMP_IDLE_MEMBER;
			}
		} else {
			igmp_timers_are_running = 1;
		}
		IN_NEXT_MULTI(step, inm);
	}
	splx(s);
#ifdef __QNXNTO__
	return igmp_timers_are_running;
#endif
}

#ifndef __QNXNTO__
void
#else
int
#endif
igmp_slowtimo(void)
{
	struct router_info *rti;
	int s;

#ifdef __QNXNTO__
	int toage = 0;
#endif
	s = splsoftnet();
	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_type == IGMP_v1_ROUTER &&
		    ++rti->rti_age >= IGMP_AGE_THRESHOLD) {
			rti->rti_type = IGMP_v2_ROUTER;
		}
#ifdef __QNXNTO__
		else if (rti->rti_type == IGMP_v1_ROUTER)
			toage++;
#endif
	}
	splx(s);
#ifdef __QNXNTO__
	return toage;
#endif
}

void
igmp_sendpkt(struct in_multi *inm, int type)
{
	struct mbuf *m;
	struct igmp *igmp;
	struct ip *ip;
	struct ip_moptions imo;
#ifdef MROUTING
	extern struct socket *ip_mrouter;
#endif /* MROUTING */

	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return;
	/*
	 * Assume max_linkhdr + sizeof(struct ip) + IGMP_MINLEN
	 * is smaller than mbuf size returned by MGETHDR.
	 */
	m->m_data += max_linkhdr;
	m->m_len = sizeof(struct ip) + IGMP_MINLEN;
	m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(struct ip) + IGMP_MINLEN);
	ip->ip_off = htons(0);
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src = zeroin_addr;
	ip->ip_dst = inm->inm_addr;

	m->m_data += sizeof(struct ip);
	m->m_len -= sizeof(struct ip);
	igmp = mtod(m, struct igmp *);
	igmp->igmp_type = type;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = in_cksum(m, IGMP_MINLEN);
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	imo.imo_multicast_ifp = inm->inm_ifp;
	imo.imo_multicast_ttl = 1;
#ifdef RSVP_ISI
	imo.imo_multicast_vif = -1;
#endif
	/*
	 * Request loopback of the report if we are acting as a multicast
	 * router, so that the process-level routing demon can hear it.
	 */
#ifdef MROUTING
	imo.imo_multicast_loop = (ip_mrouter != NULL);
#else
	imo.imo_multicast_loop = 0;
#endif /* MROUTING */

#ifndef QNX_MFIB
	ip_output(m, (struct mbuf *)NULL, (struct route *)NULL,
	    IP_MULTICASTOPTS, &imo, (struct socket *)NULL);
#else
	ip_output(m, if_get_first_fib(inm->inm_ifp), (struct mbuf *)NULL,
	    (struct route *)NULL,
	    IP_MULTICASTOPTS, &imo, (struct socket *)NULL);
#endif
	++igmpstat.igps_snd_reports;
}

void
igmp_purgeif(struct ifnet *ifp)	/* MUST be called at splsoftnet() */
{
	rti_delete(ifp);	/* manipulates pools */
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/igmp.c $ $Rev: 732279 $")
#endif
