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

/*	$NetBSD: icmp6.c,v 1.123.2.3 2008/10/03 09:04:30 jdc Exp $	*/
/*	$KAME: icmp6.c,v 1.217 2001/06/20 15:03:29 jinmei Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: icmp6.c,v 1.123.2.3 2008/10/03 09:04:30 jdc Exp $");

#include "opt_inet.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#ifdef QNX_MFIB
#include <sys/file_bsd.h>
#endif
#endif
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/domain.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/key.h>
#endif


#include "faith.h"
#if defined(NFAITH) && 0 < NFAITH
#include <net/if_faith.h>
#endif

#include <net/net_osdep.h>

extern struct domain inet6domain;

struct icmp6stat icmp6stat;
#ifdef __QNXNTO__
NLIST_EXPORT(icmp6stat, icmp6stat);
extern int ip_checkinterface;
#endif

extern struct inpcbtable raw6cbtable;
extern int icmp6errppslim;
static int icmp6errpps_count = 0;
static struct timeval icmp6errppslim_last;
extern int icmp6_nodeinfo;

/*
 * List of callbacks to notify when Path MTU changes are made.
 */
struct icmp6_mtudisc_callback {
	LIST_ENTRY(icmp6_mtudisc_callback) mc_list;
	void (*mc_func) __P((struct in6_addr *));
};

LIST_HEAD(, icmp6_mtudisc_callback) icmp6_mtudisc_callbacks =
    LIST_HEAD_INITIALIZER(&icmp6_mtudisc_callbacks);

static struct rttimer_queue *icmp6_mtudisc_timeout_q = NULL;
extern int pmtu_expire;

/* XXX do these values make any sense? */
static int icmp6_mtudisc_hiwat = 1280;
static int icmp6_mtudisc_lowat = 256;

#ifdef __QNXNTO__
static int icmp6_fragment_reply=1;
#endif

/*
 * keep track of # of redirect routes.
 */
static struct rttimer_queue *icmp6_redirect_timeout_q = NULL;

/* XXX experimental, turned off */
static int icmp6_redirect_hiwat = -1;
static int icmp6_redirect_lowat = -1;

static void icmp6_errcount __P((struct icmp6errstat *, int, int));
static int icmp6_rip6_input __P((struct mbuf **, int));
static int icmp6_ratelimit __P((const struct in6_addr *, const int, const int));
static const char *icmp6_redirect_diag __P((struct in6_addr *,
	struct in6_addr *, struct in6_addr *));
static struct mbuf *ni6_input __P((struct mbuf *, int));
static struct mbuf *ni6_nametodns __P((const char *, int, int));
static int ni6_dnsmatch __P((const char *, int, const char *, int));
static int ni6_addrs __P((struct icmp6_nodeinfo *, struct mbuf *,
			  struct ifnet **, char *));
static int ni6_store_addrs __P((struct icmp6_nodeinfo *, struct icmp6_nodeinfo *,
				struct ifnet *, int));
static int icmp6_notify_error __P((struct mbuf *, int, int, int));
#ifndef QNX_MFIB
static struct rtentry *icmp6_mtudisc_clone __P((struct sockaddr *));
#else
static struct rtentry *icmp6_mtudisc_clone __P((struct sockaddr *, int));
#endif
static void icmp6_mtudisc_timeout __P((struct rtentry *, struct rttimer *));
static void icmp6_redirect_timeout __P((struct rtentry *, struct rttimer *));


void
icmp6_init()
{
	mld_init();
	icmp6_mtudisc_timeout_q = rt_timer_queue_create(pmtu_expire);
	icmp6_redirect_timeout_q = rt_timer_queue_create(icmp6_redirtimeout);
}

static void
icmp6_errcount(stat, type, code)
	struct icmp6errstat *stat;
	int type, code;
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			stat->icp6errs_dst_unreach_noroute++;
			return;
		case ICMP6_DST_UNREACH_ADMIN:
			stat->icp6errs_dst_unreach_admin++;
			return;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			stat->icp6errs_dst_unreach_beyondscope++;
			return;
		case ICMP6_DST_UNREACH_ADDR:
			stat->icp6errs_dst_unreach_addr++;
			return;
		case ICMP6_DST_UNREACH_NOPORT:
			stat->icp6errs_dst_unreach_noport++;
			return;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		stat->icp6errs_packet_too_big++;
		return;
	case ICMP6_TIME_EXCEEDED:
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			stat->icp6errs_time_exceed_transit++;
			return;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			stat->icp6errs_time_exceed_reassembly++;
			return;
		}
		break;
	case ICMP6_PARAM_PROB:
		switch (code) {
		case ICMP6_PARAMPROB_HEADER:
			stat->icp6errs_paramprob_header++;
			return;
		case ICMP6_PARAMPROB_NEXTHEADER:
			stat->icp6errs_paramprob_nextheader++;
			return;
		case ICMP6_PARAMPROB_OPTION:
			stat->icp6errs_paramprob_option++;
			return;
		}
		break;
	case ND_REDIRECT:
		stat->icp6errs_redirect++;
		return;
	}
	stat->icp6errs_unknown++;
}

/*
 * Register a Path MTU Discovery callback.
 */
void
icmp6_mtudisc_callback_register(func)
	void (*func) __P((struct in6_addr *));
{
	struct icmp6_mtudisc_callback *mc;

	for (mc = LIST_FIRST(&icmp6_mtudisc_callbacks); mc != NULL;
	     mc = LIST_NEXT(mc, mc_list)) {
		if (mc->mc_func == func)
			return;
	}

	mc = malloc(sizeof(*mc), M_PCB, M_NOWAIT);
	if (mc == NULL)
		panic("icmp6_mtudisc_callback_register");

	mc->mc_func = func;
	LIST_INSERT_HEAD(&icmp6_mtudisc_callbacks, mc, mc_list);
}

/*
 * A wrapper function for icmp6_error() necessary when the erroneous packet
 * may not contain enough scope zone information.
 */
void
icmp6_error2(m, type, code, param, ifp)
	struct mbuf *m;
	int type, code, param;
	struct ifnet *ifp;
{
	struct ip6_hdr *ip6;

	if (ifp == NULL)
		return;

	if (m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return;
	}

	ip6 = mtod(m, struct ip6_hdr *);

	if (in6_setscope(&ip6->ip6_src, ifp, NULL) != 0)
		return;
	if (in6_setscope(&ip6->ip6_dst, ifp, NULL) != 0)
		return;

	icmp6_error(m, type, code, param
#ifdef QNX_MFIB
		    , if_get_first_fib(ifp)
#endif
	);
}

/*
 * Generate an error packet of type error in response to bad IP6 packet.
 */
void
icmp6_error(m, type, code, param
#ifdef QNX_MFIB
		, fib
#endif
		)
	struct mbuf *m;
	int type, code, param;
#ifdef QNX_MFIB
	int fib;
#endif
{
	struct ip6_hdr *oip6, *nip6;
	struct icmp6_hdr *icmp6;
	u_int preplen;
	int off;
	int nxt;
#ifdef __QNXNTO__
	struct in6_ifaddr *ifa;
	struct in6_addr test_addr;
#endif

	icmp6stat.icp6s_error++;

	/* count per-type-code statistics */
	icmp6_errcount(&icmp6stat.icp6s_outerrhist, type, code);

	if (m->m_flags & M_DECRYPTED) {
		icmp6stat.icp6s_canterror++;
		goto freeit;
	}

	if (m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return;
	}
	oip6 = mtod(m, struct ip6_hdr *);

	/*
	 * If the destination address of the erroneous packet is a multicast
	 * address, or the packet was sent using link-layer multicast,
	 * we should basically suppress sending an error (RFC 2463, Section
	 * 2.4).
	 * We have two exceptions (the item e.2 in that section):
	 * - the Pakcet Too Big message can be sent for path MTU discovery.
	 * - the Parameter Problem Message that can be allowed an icmp6 error
	 *   in the option type field.  This check has been done in
	 *   ip6_unknown_opt(), so we can just check the type and code.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST) ||
	     IN6_IS_ADDR_MULTICAST(&oip6->ip6_dst)) &&
	    (type != ICMP6_PACKET_TOO_BIG &&
	     (type != ICMP6_PARAM_PROB ||
	      code != ICMP6_PARAMPROB_OPTION)))
		goto freeit;

	/*
	 * RFC 2463, 2.4 (e.5): source address check.
	 * XXX: the case of anycast source?
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&oip6->ip6_src) ||
	    IN6_IS_ADDR_MULTICAST(&oip6->ip6_src))
		goto freeit;

#ifdef __QNXNTO__
	/*
	 * Can be called from output side, skip anycast check in that case
	 * otherwise we will crash in in6_ifawithifp()
	 */
	if (m->m_pkthdr.rcvif == NULL) {
	    goto skip_anycast;
	}

	/* Need to know the subnet length to work out if src was anycast */
	ifa = in6_ifawithifp(m->m_pkthdr.rcvif, &oip6->ip6_src);

	/* Zero the prefix part of the source address */
	for (off = 0; off < 4; off++) {
	    test_addr.s6_addr32[off] = oip6->ip6_src.s6_addr32[off] &
	      (~ifa->ia_prefixmask.sin6_addr.s6_addr32[off]);
	}

	/* Check for subnet router anycast source */
	if (IN6_IS_ADDR_UNSPECIFIED(&test_addr)) {
	    goto freeit;
	}

	/* Set to all 1's the prefix part of the source address */
	for (off = 0; off < 4; off++) {
	    test_addr.s6_addr32[off] = oip6->ip6_src.s6_addr32[off] |
	      ifa->ia_prefixmask.sin6_addr.s6_addr32[off];
	}

	/* EUI-64 has 0 in local/universal */
	off = in6_mask2len(&ifa->ia_prefixmask.sin6_addr, NULL);
	if (off == 64) {
	    test_addr.s6_addr8[8] ^= 2;
	}

	/* Check for reserved anycast source */
	for (off = 0; off < 15; off++) {
	    if (test_addr.s6_addr8[off] != 0xff) {
		goto skip_anycast;
	    }
	}
	if ((test_addr.s6_addr[15] & 0x80) == 0x80) {
	    goto freeit;
	}
skip_anycast:
#endif

	/*
	 * If we are about to send ICMPv6 against ICMPv6 error/redirect,
	 * don't do it.
	 */
	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off >= 0 && nxt == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icp;

		IP6_EXTHDR_GET(icp, struct icmp6_hdr *, m, off,
			sizeof(*icp));
		if (icp == NULL) {
			icmp6stat.icp6s_tooshort++;
			return;
		}
		if (icp->icmp6_type < ICMP6_ECHO_REQUEST ||
		    icp->icmp6_type == ND_REDIRECT) {
			/*
			 * ICMPv6 error
			 * Special case: for redirect (which is
			 * informational) we must not send icmp6 error.
			 */
			icmp6stat.icp6s_canterror++;
			goto freeit;
		} else {
			/* ICMPv6 informational - send the error */
		}
	}
#if 0 /* controversial */
	else if (off >= 0 && nxt == IPPROTO_ESP) {
		/*
		 * It could be ICMPv6 error inside ESP.  Take a safer side,
		 * don't respond.
		 */
		icmp6stat.icp6s_canterror++;
		goto freeit;
	}
#endif
	else {
		/* non-ICMPv6 - send the error */
	}

	oip6 = mtod(m, struct ip6_hdr *); /* adjust pointer */

	/* Finally, do rate limitation check. */
	if (icmp6_ratelimit(&oip6->ip6_src, type, code)) {
		icmp6stat.icp6s_toofreq++;
		goto freeit;
	}

	/*
	 * OK, ICMP6 can be generated.
	 */

	if (m->m_pkthdr.len >= ICMPV6_PLD_MAXLEN)
		m_adj(m, ICMPV6_PLD_MAXLEN - m->m_pkthdr.len);

	preplen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	M_PREPEND(m, preplen, M_DONTWAIT);
	if (m && m->m_len < preplen)
		m = m_pullup(m, preplen);
	if (m == NULL) {
		nd6log((LOG_DEBUG, "ENOBUFS in icmp6_error %d\n", __LINE__));
		return;
	}

	nip6 = mtod(m, struct ip6_hdr *);
	nip6->ip6_src  = oip6->ip6_src;
	nip6->ip6_dst  = oip6->ip6_dst;

	in6_clearscope(&oip6->ip6_src);
	in6_clearscope(&oip6->ip6_dst);

	icmp6 = (struct icmp6_hdr *)(nip6 + 1);
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = code;
	icmp6->icmp6_pptr = htonl((u_int32_t)param);

	/*
	 * icmp6_reflect() is designed to be in the input path.
	 * icmp6_error() can be called from both input and output path,
	 * and if we are in output path rcvif could contain bogus value.
	 * clear m->m_pkthdr.rcvif for safety, we should have enough scope
	 * information in ip header (nip6).
	 */
	m->m_pkthdr.rcvif = NULL;

	icmp6stat.icp6s_outhist[type]++;
	icmp6_reflect(m, sizeof(struct ip6_hdr)
#ifdef QNX_MFIB
			, fib
#endif
			); /* header order: IPv6 - ICMPv6 */

	return;

  freeit:
	/*
	 * If we can't tell whether or not we can generate ICMP6, free it.
	 */
	m_freem(m);
}

/*
 * Process a received ICMP6 message.
 */
int
icmp6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp, *n;
	struct ip6_hdr *ip6, *nip6;
	struct icmp6_hdr *icmp6, *nicmp6;
	int off = *offp;
	int icmp6len = m->m_pkthdr.len - *offp;
	int code, sum, noff;
#ifdef QNX_MFIB
	int fib = if_get_first_fib(m->m_pkthdr.rcvif);
#endif

#define ICMP6_MAXLEN (sizeof(*nip6) + sizeof(*nicmp6) + 4)
	KASSERT(ICMP6_MAXLEN < MCLBYTES);
	icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_msg);

	/*
	 * Locate icmp6 structure in mbuf, and check
	 * that not corrupted and of at least minimum length
	 */

	ip6 = mtod(m, struct ip6_hdr *);
	if (icmp6len < sizeof(struct icmp6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_error);
		goto freeit;
	}

	/*
	 * calculate the checksum
	 */
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		/* m is invalid */
		/*icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_error);*/
		return IPPROTO_DONE;
	}
	KASSERT(IP6_HDR_ALIGNED_P(icmp6));
	code = icmp6->icmp6_code;

	if ((sum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len)) != 0) {
		nd6log((LOG_ERR,
		    "ICMP6 checksum error(%d|%x) %s\n",
		    icmp6->icmp6_type, sum, ip6_sprintf(&ip6->ip6_src)));
		icmp6stat.icp6s_checksum++;
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_error);
		goto freeit;
	}

#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6->ip6_dst)) {
		/*
		 * Deliver very specific ICMP6 type only.
		 * This is important to deliver TOOBIG.  Otherwise PMTUD
		 * will not work.
		 */
		switch (icmp6->icmp6_type) {
		case ICMP6_DST_UNREACH:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_TIME_EXCEEDED:
			break;
		default:
			goto freeit;
		}
	}
#endif

	icmp6stat.icp6s_inhist[icmp6->icmp6_type]++;

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_dstunreach);
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			code = PRC_UNREACH_NET;
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_adminprohib);
			code = PRC_UNREACH_PROTOCOL; /* is this a good code? */
			break;
		case ICMP6_DST_UNREACH_ADDR:
			code = PRC_HOSTDEAD;
			break;
#ifdef COMPAT_RFC1885
		case ICMP6_DST_UNREACH_NOTNEIGHBOR:
			code = PRC_UNREACH_SRCFAIL;
			break;
#else
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			/* I mean "source address was incorrect." */
			code = PRC_UNREACH_NET;
			break;
#endif
		case ICMP6_DST_UNREACH_NOPORT:
			code = PRC_UNREACH_PORT;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PACKET_TOO_BIG:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_pkttoobig);

		/*
		 * MTU is checked in icmp6_mtudisc.
		 */
		code = PRC_MSGSIZE;

		/*
		 * Updating the path MTU will be done after examining
		 * intermediate extension headers.
		 */
		goto deliver;

	case ICMP6_TIME_EXCEEDED:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_timeexceed);
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			code = PRC_TIMXCEED_INTRANS;
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			code = PRC_TIMXCEED_REASS;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PARAM_PROB:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_paramprob);
		switch (code) {
		case ICMP6_PARAMPROB_NEXTHEADER:
			code = PRC_UNREACH_PROTOCOL;
			break;
		case ICMP6_PARAMPROB_HEADER:
		case ICMP6_PARAMPROB_OPTION:
			code = PRC_PARAMPROB;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_ECHO_REQUEST:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_echo);
		if (code != 0)
			goto badcode;
		/*
		 * Copy mbuf to send to two data paths: userland socket(s),
		 * and to the querier (echo reply).
		 * m: a copy for socket, n: a copy for querier
		 *
		 * If the first mbuf is shared, or the first mbuf is too short,
		 * copy the first part of the data into a fresh mbuf.
		 * Otherwise, we will wrongly overwrite both copies.
		 */
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* Give up local */
			n = m;
			m = NULL;
		} else if (M_READONLY(n) ||
		    n->m_len < off + sizeof(struct icmp6_hdr)) {
			struct mbuf *n0 = n;

			/*
			 * Prepare an internal mbuf.  m_pullup() doesn't
			 * always copy the length we specified.
			 */
			if ((n = m_dup(n0, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
				/* Give up local */
				n = m;
				m = NULL;
			}
			m_freem(n0);
		}
        IP6_EXTHDR_GET(nicmp6,struct icmp6_hdr *, n, off, sizeof(*nicmp6));
		nicmp6->icmp6_type = ICMP6_ECHO_REPLY;
		nicmp6->icmp6_code = 0;
		if (n) {
			icmp6stat.icp6s_reflect++;
			icmp6stat.icp6s_outhist[ICMP6_ECHO_REPLY]++;
			icmp6_reflect(n, off
#ifdef QNX_MFIB
					, fib
#endif
			);
		}
		if (!m)
			goto freeit;
		break;

	case ICMP6_ECHO_REPLY:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_echoreply);
		if (code != 0)
			goto badcode;
		break;

	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
		if (icmp6len < sizeof(struct mld_hdr))
			goto badlen;
		if (icmp6->icmp6_type == MLD_LISTENER_QUERY) /* XXX: ugly... */
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mldquery);
		else
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mldreport);
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			mld_input(m, off);
			m = NULL;
			goto freeit;
		}
		mld_input(n, off);
		/* m stays. */
		break;

	case MLD_LISTENER_DONE:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mlddone);
		if (icmp6len < sizeof(struct mld_hdr))	/* necessary? */
			goto badlen;
		break;		/* nothing to be done in kernel */

	case MLD_MTRACE_RESP:
	case MLD_MTRACE:
		/* XXX: these two are experimental.  not officially defined. */
		/* XXX: per-interface statistics? */
		break;		/* just pass it to applications */

	case ICMP6_WRUREQUEST:	/* ICMP6_FQDN_QUERY */
	    {
		enum { WRU, FQDN } mode;

		if (!icmp6_nodeinfo)
			break;

		if (icmp6len == sizeof(struct icmp6_hdr) + 4)
			mode = WRU;
		else if (icmp6len >= sizeof(struct icmp6_nodeinfo))
			mode = FQDN;
		else
			goto badlen;

		if (mode == FQDN) {
			n = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
			if (n)
				n = ni6_input(n, off);
			/* XXX meaningless if n == NULL */
			noff = sizeof(struct ip6_hdr);
		} else {
			u_char *p;
			int maxhlen;

			if ((icmp6_nodeinfo & 5) != 5)
				break;

			if (code != 0)
				goto badcode;
			MGETHDR(n, M_DONTWAIT, m->m_type);
			if (n && ICMP6_MAXLEN > MHLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				/* Give up remote */
				break;
			}
			n->m_pkthdr.rcvif = NULL;
			n->m_len = 0;
			maxhlen = M_TRAILINGSPACE(n) - ICMP6_MAXLEN;
			if (maxhlen > hostnamelen)
				maxhlen = hostnamelen;
			/*
			 * Copy IPv6 and ICMPv6 only.
			 */
			nip6 = mtod(n, struct ip6_hdr *);
			bcopy(ip6, nip6, sizeof(struct ip6_hdr));
			nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
			bcopy(icmp6, nicmp6, sizeof(struct icmp6_hdr));
			p = (u_char *)(nicmp6 + 1);
			bzero(p, 4);
			bcopy(hostname, p + 4, maxhlen); /* meaningless TTL */
			noff = sizeof(struct ip6_hdr);
			M_COPY_PKTHDR(n, m); /* just for rcvif */
			n->m_pkthdr.len = n->m_len = sizeof(struct ip6_hdr) +
				sizeof(struct icmp6_hdr) + 4 + maxhlen;
			nicmp6->icmp6_type = ICMP6_WRUREPLY;
			nicmp6->icmp6_code = 0;
		}
#undef hostnamelen
		if (n) {
			icmp6stat.icp6s_reflect++;
			icmp6stat.icp6s_outhist[ICMP6_WRUREPLY]++;
			icmp6_reflect(n, noff
#ifdef QNX_MFIB
					, fib
#endif
			);
		}
		break;
	    }

	case ICMP6_WRUREPLY:
		if (code != 0)
			goto badcode;
		break;

	case ND_ROUTER_SOLICIT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_routersolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_solicit))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_rs_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_rs_input(n, off, icmp6len);
		/* m stays. */
		break;

	case ND_ROUTER_ADVERT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_routeradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_advert))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_ra_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ra_input(n, off, icmp6len);
		/* m stays. */
		break;

	case ND_NEIGHBOR_SOLICIT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_neighborsolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_solicit))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_ns_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ns_input(n, off, icmp6len);
		/* m stays. */
		break;

	case ND_NEIGHBOR_ADVERT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_neighboradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_advert))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_na_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_na_input(n, off, icmp6len);
		/* m stays. */
		break;

	case ND_REDIRECT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_redirect);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_redirect))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			icmp6_redirect_input(m, off);
			m = NULL;
			goto freeit;
		}
		icmp6_redirect_input(n, off);
		/* m stays. */
		break;

	case ICMP6_ROUTER_RENUMBERING:
		if (code != ICMP6_ROUTER_RENUMBERING_COMMAND &&
		    code != ICMP6_ROUTER_RENUMBERING_RESULT)
			goto badcode;
		if (icmp6len < sizeof(struct icmp6_router_renum))
			goto badlen;
		break;

	default:
		nd6log((LOG_DEBUG,
		    "icmp6_input: unknown type %d(src=%s, dst=%s, ifid=%d)\n",
		    icmp6->icmp6_type, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst),
		    m->m_pkthdr.rcvif ? m->m_pkthdr.rcvif->if_index : 0));
		if (icmp6->icmp6_type < ICMP6_ECHO_REQUEST) {
			/* ICMPv6 error: MUST deliver it by spec... */
			code = PRC_NCMDS;
			/* deliver */
		} else {
			/* ICMPv6 informational: MUST not deliver */
			break;
		}
	deliver:
		if (icmp6_notify_error(m, off, icmp6len, code)) {
			/* In this case, m should've been freed. */
			return (IPPROTO_DONE);
		}
		break;

	badcode:
		icmp6stat.icp6s_badcode++;
		break;

	badlen:
		icmp6stat.icp6s_badlen++;
		break;
	}

	/* deliver the packet to appropriate sockets */
	icmp6_rip6_input(&m, *offp);

	return IPPROTO_DONE;

 freeit:
	m_freem(m);
	return IPPROTO_DONE;
}

static int
icmp6_notify_error(m, off, icmp6len, code)
	struct mbuf *m;
	int off, icmp6len, code;
{
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *eip6;
	u_int32_t notifymtu;
	struct sockaddr_in6 icmp6src, icmp6dst;

	if (icmp6len < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		goto freeit;
	}
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off,
		       sizeof(*icmp6) + sizeof(struct ip6_hdr));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		return (-1);
	}
	eip6 = (struct ip6_hdr *)(icmp6 + 1);

	/* Detect the upper level protocol */
	{
		void (*ctlfunc) __P((int, struct sockaddr *, void *));
		u_int8_t nxt = eip6->ip6_nxt;
		int eoff = off + sizeof(struct icmp6_hdr) +
			sizeof(struct ip6_hdr);
		struct ip6ctlparam ip6cp;
		struct in6_addr *finaldst = NULL;
		int icmp6type = icmp6->icmp6_type;
		struct ip6_frag *fh;
		struct ip6_rthdr *rth;
		struct ip6_rthdr0 *rth0;
		int rthlen;

		while (1) { /* XXX: should avoid infinite loop explicitly? */
			struct ip6_ext *eh;

			switch (nxt) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_AH:
				IP6_EXTHDR_GET(eh, struct ip6_ext *, m,
					       eoff, sizeof(*eh));
				if (eh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}

				if (nxt == IPPROTO_AH)
					eoff += (eh->ip6e_len + 2) << 2;
				else
					eoff += (eh->ip6e_len + 1) << 3;
				nxt = eh->ip6e_nxt;
				break;
			case IPPROTO_ROUTING:
				/*
				 * When the erroneous packet contains a
				 * routing header, we should examine the
				 * header to determine the final destination.
				 * Otherwise, we can't properly update
				 * information that depends on the final
				 * destination (e.g. path MTU).
				 */
				IP6_EXTHDR_GET(rth, struct ip6_rthdr *, m,
					       eoff, sizeof(*rth));
				if (rth == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}
				rthlen = (rth->ip6r_len + 1) << 3;
				/*
				 * XXX: currently there is no
				 * officially defined type other
				 * than type-0.
				 * Note that if the segment left field
				 * is 0, all intermediate hops must
				 * have been passed.
				 */
				if (rth->ip6r_segleft &&
				    rth->ip6r_type == IPV6_RTHDR_TYPE_0) {
					int hops;

					IP6_EXTHDR_GET(rth0,
						       struct ip6_rthdr0 *, m,
						       eoff, rthlen);
					if (rth0 == NULL) {
						icmp6stat.icp6s_tooshort++;
						return (-1);
					}
					/* just ignore a bogus header */
					if ((rth0->ip6r0_len % 2) == 0 &&
					    (hops = rth0->ip6r0_len/2))
						finaldst = (struct in6_addr *)(rth0 + 1) + (hops - 1);
				}
				eoff += rthlen;
				nxt = rth->ip6r_nxt;
				break;
			case IPPROTO_FRAGMENT:
				IP6_EXTHDR_GET(fh, struct ip6_frag *, m,
					       eoff, sizeof(*fh));
				if (fh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}
				/*
				 * Data after a fragment header is meaningless
				 * unless it is the first fragment, but
				 * we'll go to the notify label for path MTU
				 * discovery.
				 */
				if (fh->ip6f_offlg & IP6F_OFF_MASK)
					goto notify;

				eoff += sizeof(struct ip6_frag);
				nxt = fh->ip6f_nxt;
				break;
			default:
				/*
				 * This case includes ESP and the No Next
				 * Header.  In such cases going to the notify
				 * label does not have any meaning
				 * (i.e. ctlfunc will be NULL), but we go
				 * anyway since we might have to update
				 * path MTU information.
				 */
				goto notify;
			}
		}
	  notify:
		IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off,
			       sizeof(*icmp6) + sizeof(struct ip6_hdr));
		if (icmp6 == NULL) {
			icmp6stat.icp6s_tooshort++;
			return (-1);
		}

		/*
		 * retrieve parameters from the inner IPv6 header, and convert
		 * them into sockaddr structures.
		 * XXX: there is no guarantee that the source or destination
		 * addresses of the inner packet are in the same scope zone as
		 * the addresses of the icmp packet.  But there is no other
		 * way to determine the zone.
		 */
		eip6 = (struct ip6_hdr *)(icmp6 + 1);

		bzero(&icmp6dst, sizeof(icmp6dst));
		icmp6dst.sin6_len = sizeof(struct sockaddr_in6);
		icmp6dst.sin6_family = AF_INET6;
		if (finaldst == NULL)
			icmp6dst.sin6_addr = eip6->ip6_dst;
		else
			icmp6dst.sin6_addr = *finaldst;
		if (in6_setscope(&icmp6dst.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
		bzero(&icmp6src, sizeof(icmp6src));
		icmp6src.sin6_len = sizeof(struct sockaddr_in6);
		icmp6src.sin6_family = AF_INET6;
		icmp6src.sin6_addr = eip6->ip6_src;
		if (in6_setscope(&icmp6src.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
		icmp6src.sin6_flowinfo =
			(eip6->ip6_flow & IPV6_FLOWLABEL_MASK);

		if (finaldst == NULL)
			finaldst = &eip6->ip6_dst;
		ip6cp.ip6c_m = m;
		ip6cp.ip6c_icmp6 = icmp6;
		ip6cp.ip6c_ip6 = (struct ip6_hdr *)(icmp6 + 1);
		ip6cp.ip6c_off = eoff;
		ip6cp.ip6c_finaldst = finaldst;
		ip6cp.ip6c_src = &icmp6src;
		ip6cp.ip6c_nxt = nxt;

		if (icmp6type == ICMP6_PACKET_TOO_BIG) {
			notifymtu = ntohl(icmp6->icmp6_mtu);
			ip6cp.ip6c_cmdarg = (void *)&notifymtu;
		}

		ctlfunc = (void (*) __P((int, struct sockaddr *, void *)))
			(inet6sw[ip6_protox[nxt]].pr_ctlinput);
		if (ctlfunc) {
			(void) (*ctlfunc)(code, (struct sockaddr *)&icmp6dst,
					  &ip6cp);
		}
	}
	return (0);

  freeit:
	m_freem(m);
	return (-1);
}

void
icmp6_mtudisc_update(ip6cp, validated)
	struct ip6ctlparam *ip6cp;
	int validated;
{
	unsigned long rtcount;
	struct icmp6_mtudisc_callback *mc;
	struct in6_addr *dst = ip6cp->ip6c_finaldst;
	struct icmp6_hdr *icmp6 = ip6cp->ip6c_icmp6;
	struct mbuf *m = ip6cp->ip6c_m;	/* will be necessary for scope issue */
	u_int mtu = ntohl(icmp6->icmp6_mtu);
	struct rtentry *rt = NULL;
	struct sockaddr_in6 sin6;

	/*
	 * The MTU should not be less than the minimal IPv6 MTU except for the
	 * hack in ip6_output/ip6_setpmtu where we always include a frag header.
	 * In that one case, the MTU might be less than 1280.  
	 */
	if (__predict_false(mtu < IPV6_MMTU - sizeof(struct ip6_frag))) {
		/* is the mtu even sane? */
		if (mtu < sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + 8)
			return;
#ifndef __QNXNTO__
		if (!validated)
			return;
#endif
		mtu = IPV6_MMTU - sizeof(struct ip6_frag);
	}

	/*
	 * allow non-validated cases if memory is plenty, to make traffic
	 * from non-connected pcb happy.
	 */
	rtcount = rt_timer_count(icmp6_mtudisc_timeout_q);
	if (validated) {
		if (0 <= icmp6_mtudisc_hiwat && rtcount > icmp6_mtudisc_hiwat)
			return;
		else if (0 <= icmp6_mtudisc_lowat &&
		    rtcount > icmp6_mtudisc_lowat) {
			/*
			 * XXX nuke a victim, install the new one.
			 */
		}
	} else {
		if (0 <= icmp6_mtudisc_lowat && rtcount > icmp6_mtudisc_lowat)
			return;
	}

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = PF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_addr = *dst;
	if (in6_setscope(&sin6.sin6_addr, m->m_pkthdr.rcvif, NULL))
		return;

#ifndef QNX_MFIB
	rt = icmp6_mtudisc_clone((struct sockaddr *)&sin6);
#else
	rt = icmp6_mtudisc_clone((struct sockaddr *)&sin6, if_get_first_fib(m->m_pkthdr.rcvif));
#endif

	if (rt && (rt->rt_flags & RTF_HOST) &&
	    !(rt->rt_rmx.rmx_locks & RTV_MTU) &&
	    (rt->rt_rmx.rmx_mtu > mtu || rt->rt_rmx.rmx_mtu == 0)) {
		if (mtu < IN6_LINKMTU(rt->rt_ifp)) {
			icmp6stat.icp6s_pmtuchg++;
			rt->rt_rmx.rmx_mtu = mtu;
		}
	}
	if (rt) { /* XXX: need braces to avoid conflict with else in RTFREE. */
		RTFREE(rt);
	}

	/*
	 * Notify protocols that the MTU for this destination
	 * has changed.
	 */
	for (mc = LIST_FIRST(&icmp6_mtudisc_callbacks); mc != NULL;
	     mc = LIST_NEXT(mc, mc_list))
		(*mc->mc_func)(&sin6.sin6_addr);
}

/*
 * Process a Node Information Query packet, based on
 * draft-ietf-ipngwg-icmp-name-lookups-07.
 *
 * Spec incompatibilities:
 * - IPv6 Subject address handling
 * - IPv4 Subject address handling support missing
 * - Proxy reply (answer even if it's not for me)
 * - joins NI group address at in6_ifattach() time only, does not cope
 *   with hostname changes by sethostname(3)
 */
#ifndef offsetof		/* XXX */
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif
static struct mbuf *
ni6_input(m, off)
	struct mbuf *m;
	int off;
{
	struct icmp6_nodeinfo *ni6, *nni6;
	struct mbuf *n = NULL;
	u_int16_t qtype;
	int subjlen;
	int replylen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
	struct ni_reply_fqdn *fqdn;
	int addrs;		/* for NI_QTYPE_NODEADDR */
	struct ifnet *ifp = NULL; /* for NI_QTYPE_NODEADDR */
	struct sockaddr_in6 sin6; /* ip6_dst */
	struct in6_addr in6_subj; /* subject address */
	struct ip6_hdr *ip6;
	int oldfqdn = 0;	/* if 1, return pascal string (03 draft) */
	char *subj = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
	IP6_EXTHDR_GET(ni6, struct icmp6_nodeinfo *, m, off, sizeof(*ni6));
	if (ni6 == NULL) {
		/* m is already reclaimed */
		return NULL;
	}

	/*
	 * Validate IPv6 destination address.
	 *
	 * The Responder must discard the Query without further processing
	 * unless it is one of the Responder's unicast or anycast addresses, or
	 * a link-local scope multicast address which the Responder has joined.
	 * [icmp-name-lookups-07, Section 4.]
	 */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&ip6->ip6_dst, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
	/* XXX scopeid */
#ifndef __QNXNTO__
	if (ifa_ifwithaddr((struct sockaddr *)&sin6))
#else
	if ((ifa_ifwithaddr)((struct sockaddr *)&sin6, ip_checkinterface ? m->m_pkthdr.rcvif : NULL
#ifdef QNX_MFIB
			, if_get_first_fib(m->m_pkthdr.rcvif)
#endif
			))
#endif
		; /* unicast/anycast, fine */
	else if (IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr))
		; /* link-local multicast, fine */
	else
		goto bad;

	/* validate query Subject field. */
	qtype = ntohs(ni6->ni_qtype);
	subjlen = m->m_pkthdr.len - off - sizeof(struct icmp6_nodeinfo);
	switch (qtype) {
	case NI_QTYPE_NOOP:
	case NI_QTYPE_SUPTYPES:
		/* 07 draft */
		if (ni6->ni_code == ICMP6_NI_SUBJ_FQDN && subjlen == 0)
			break;
		/* FALLTHROUGH */
	case NI_QTYPE_FQDN:
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
#if ICMP6_NI_SUBJ_IPV6 != 0
		case 0:
#endif
			/*
			 * backward compatibility - try to accept 03 draft
			 * format, where no Subject is present.
			 */
			if (qtype == NI_QTYPE_FQDN && ni6->ni_code == 0 &&
			    subjlen == 0) {
				oldfqdn++;
				break;
			}
#if ICMP6_NI_SUBJ_IPV6 != 0
			if (ni6->ni_code != ICMP6_NI_SUBJ_IPV6)
				goto bad;
#endif

			if (subjlen != sizeof(sin6.sin6_addr))
				goto bad;

			/*
			 * Validate Subject address.
			 *
			 * Not sure what exactly "address belongs to the node"
			 * means in the spec, is it just unicast, or what?
			 *
			 * At this moment we consider Subject address as
			 * "belong to the node" if the Subject address equals
			 * to the IPv6 destination address; validation for
			 * IPv6 destination address should have done enough
			 * check for us.
			 *
			 * We do not do proxy at this moment.
			 */
			/* m_pulldown instead of copy? */
			m_copydata(m, off + sizeof(struct icmp6_nodeinfo),
			    subjlen, (caddr_t)&in6_subj);
			if (in6_setscope(&in6_subj, m->m_pkthdr.rcvif, NULL))
				goto bad;

			subj = (char *)&in6_subj;
			if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &in6_subj))
				break;

			/*
			 * XXX if we are to allow other cases, we should really
			 * be careful about scope here.
			 * basically, we should disallow queries toward IPv6
			 * destination X with subject Y, if scope(X) > scope(Y).
			 * if we allow scope(X) > scope(Y), it will result in
			 * information leakage across scope boundary.
			 */
			goto bad;

		case ICMP6_NI_SUBJ_FQDN:
			/*
			 * Validate Subject name with gethostname(3).
			 *
			 * The behavior may need some debate, since:
			 * - we are not sure if the node has FQDN as
			 *   hostname (returned by gethostname(3)).
			 * - the code does wildcard match for truncated names.
			 *   however, we are not sure if we want to perform
			 *   wildcard match, if gethostname(3) side has
			 *   truncated hostname.
			 */
			n = ni6_nametodns(hostname, hostnamelen, 0);
			if (!n || n->m_next || n->m_len == 0)
				goto bad;
			IP6_EXTHDR_GET(subj, char *, m,
			    off + sizeof(struct icmp6_nodeinfo), subjlen);
			if (subj == NULL)
				goto bad;
			if (!ni6_dnsmatch(subj, subjlen, mtod(n, const char *),
					n->m_len)) {
				goto bad;
			}
			m_freem(n);
			n = NULL;
			break;

		case ICMP6_NI_SUBJ_IPV4:	/* XXX: to be implemented? */
		default:
			goto bad;
		}
		break;
	}

	/* refuse based on configuration.  XXX ICMP6_NI_REFUSED? */
	switch (qtype) {
	case NI_QTYPE_FQDN:
		if ((icmp6_nodeinfo & 1) == 0)
			goto bad;
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		if ((icmp6_nodeinfo & 2) == 0)
			goto bad;
		break;
	}

	/* guess reply length */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		break;		/* no reply data */
	case NI_QTYPE_SUPTYPES:
		replylen += sizeof(u_int32_t);
		break;
	case NI_QTYPE_FQDN:
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		break;
	case NI_QTYPE_NODEADDR:
		addrs = ni6_addrs(ni6, m, &ifp, subj);
		if ((replylen += addrs * (sizeof(struct in6_addr) +
					  sizeof(u_int32_t))) > MCLBYTES)
			replylen = MCLBYTES; /* XXX: will truncate pkt later */
		break;
	case NI_QTYPE_IPV4ADDR:
		/* unsupported - should respond with unknown Qtype? */
		goto bad;
	default:
		/*
		 * XXX: We must return a reply with the ICMP6 code
		 * `unknown Qtype' in this case.  However we regard the case
		 * as an FQDN query for backward compatibility.
		 * Older versions set a random value to this field,
		 * so it rarely varies in the defined qtypes.
		 * But the mechanism is not reliable...
		 * maybe we should obsolete older versions.
		 */
		qtype = NI_QTYPE_FQDN;
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		oldfqdn++;
		break;
	}

	/* allocate an mbuf to reply. */
	MGETHDR(n, M_DONTWAIT, m->m_type);
	if (n == NULL) {
		m_freem(m);
		return (NULL);
	}
	M_MOVE_PKTHDR(n, m); /* just for rcvif */
	if (replylen > MHLEN) {
		if (replylen > MCLBYTES) {
			/*
			 * XXX: should we try to allocate more? But MCLBYTES
			 * is probably much larger than IPV6_MMTU...
			 */
			goto bad;
		}
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			goto bad;
		}
	}
	n->m_pkthdr.len = n->m_len = replylen;

	/* copy mbuf header and IPv6 + Node Information base headers */
	bcopy(mtod(m, caddr_t), mtod(n, caddr_t), sizeof(struct ip6_hdr));
	nni6 = (struct icmp6_nodeinfo *)(mtod(n, struct ip6_hdr *) + 1);
	bcopy((caddr_t)ni6, (caddr_t)nni6, sizeof(struct icmp6_nodeinfo));

	/* qtype dependent procedure */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = 0;
		break;
	case NI_QTYPE_SUPTYPES:
	{
		u_int32_t v;
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = htons(0x0000);	/* raw bitmap */
		/* supports NOOP, SUPTYPES, FQDN, and NODEADDR */
		v = (u_int32_t)htonl(0x0000000f);
		bcopy(&v, nni6 + 1, sizeof(u_int32_t));
		break;
	}
	case NI_QTYPE_FQDN:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		fqdn = (struct ni_reply_fqdn *)(mtod(n, caddr_t) +
						sizeof(struct ip6_hdr) +
						sizeof(struct icmp6_nodeinfo));
		nni6->ni_flags = 0; /* XXX: meaningless TTL */
		fqdn->ni_fqdn_ttl = 0;	/* ditto. */
		/*
		 * XXX do we really have FQDN in variable "hostname"?
		 */
		n->m_next = ni6_nametodns(hostname, hostnamelen, oldfqdn);
		if (n->m_next == NULL)
			goto bad;
		/* XXX we assume that n->m_next is not a chain */
		if (n->m_next->m_next != NULL)
			goto bad;
		n->m_pkthdr.len += n->m_next->m_len;
		break;
	case NI_QTYPE_NODEADDR:
	{
		int lenlim, copied;

		nni6->ni_code = ICMP6_NI_SUCCESS;
		n->m_pkthdr.len = n->m_len =
		    sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
		lenlim = M_TRAILINGSPACE(n);
		copied = ni6_store_addrs(ni6, nni6, ifp, lenlim);
		/* XXX: reset mbuf length */
		n->m_pkthdr.len = n->m_len = sizeof(struct ip6_hdr) +
			sizeof(struct icmp6_nodeinfo) + copied;
		break;
	}
	default:
		break;		/* XXX impossible! */
	}

	nni6->ni_type = ICMP6_NI_REPLY;
	m_freem(m);
	return (n);

  bad:
	m_freem(m);
	if (n)
		m_freem(n);
	return (NULL);
}
#undef hostnamelen

#define isupper(x) ('A' <= (x) && (x) <= 'Z')
#define isalpha(x) (('A' <= (x) && (x) <= 'Z') || ('a' <= (x) && (x) <= 'z'))
#define isalnum(x) (isalpha(x) || ('0' <= (x) && (x) <= '9'))
#define tolower(x) (isupper(x) ? (x) + 'a' - 'A' : (x))

/*
 * make a mbuf with DNS-encoded string.  no compression support.
 *
 * XXX names with less than 2 dots (like "foo" or "foo.section") will be
 * treated as truncated name (two \0 at the end).  this is a wild guess.
 */
static struct mbuf *
ni6_nametodns(name, namelen, old)
	const char *name;
	int namelen;
	int old;	/* return pascal string if non-zero */
{
	struct mbuf *m;
	char *cp, *ep;
	const char *p, *q;
	int i, len, nterm;

	if (old)
		len = namelen + 1;
	else
		len = MCLBYTES;

	/* because MAXHOSTNAMELEN is usually 256, we use cluster mbuf */
	MGET(m, M_DONTWAIT, MT_DATA);
	if (m && len > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0)
			goto fail;
	}
	if (!m)
		goto fail;
	m->m_next = NULL;

	if (old) {
		m->m_len = len;
		*mtod(m, char *) = namelen;
		bcopy(name, mtod(m, char *) + 1, namelen);
		return m;
	} else {
		m->m_len = 0;
		cp = mtod(m, char *);
		ep = mtod(m, char *) + M_TRAILINGSPACE(m);

		/* if not certain about my name, return empty buffer */
		if (namelen == 0)
			return m;

		/*
		 * guess if it looks like shortened hostname, or FQDN.
		 * shortened hostname needs two trailing "\0".
		 */
		i = 0;
		for (p = name; p < name + namelen; p++) {
			if (*p && *p == '.')
				i++;
		}
		if (i < 2)
			nterm = 2;
		else
			nterm = 1;

		p = name;
		while (cp < ep && p < name + namelen) {
			i = 0;
			for (q = p; q < name + namelen && *q && *q != '.'; q++)
				i++;
			/* result does not fit into mbuf */
			if (cp + i + 1 >= ep)
				goto fail;
			/*
			 * DNS label length restriction, RFC1035 page 8.
			 * "i == 0" case is included here to avoid returning
			 * 0-length label on "foo..bar".
			 */
			if (i <= 0 || i >= 64)
				goto fail;
			*cp++ = i;
			if (!isalpha(p[0]) || !isalnum(p[i - 1]))
				goto fail;
			while (i > 0) {
				if (!isalnum(*p) && *p != '-')
					goto fail;
				if (isupper(*p)) {
					*cp++ = tolower(*p);
					p++;
				} else
					*cp++ = *p++;
				i--;
			}
			p = q;
			if (p < name + namelen && *p == '.')
				p++;
		}
		/* termination */
		if (cp + nterm >= ep)
			goto fail;
		while (nterm-- > 0)
			*cp++ = '\0';
		m->m_len = cp - mtod(m, char *);
		return m;
	}

	panic("should not reach here");
	/* NOTREACHED */

 fail:
	if (m)
		m_freem(m);
	return NULL;
}

/*
 * check if two DNS-encoded string matches.  takes care of truncated
 * form (with \0\0 at the end).  no compression support.
 * XXX upper/lowercase match (see RFC2065)
 */
static int
ni6_dnsmatch(a, alen, b, blen)
	const char *a;
	int alen;
	const char *b;
	int blen;
{
	const char *a0, *b0;
	int l;

	/* simplest case - need validation? */
	if (alen == blen && bcmp(a, b, alen) == 0)
		return 1;

	a0 = a;
	b0 = b;

	/* termination is mandatory */
	if (alen < 2 || blen < 2)
		return 0;
	if (a0[alen - 1] != '\0' || b0[blen - 1] != '\0')
		return 0;
	alen--;
	blen--;

	while (a - a0 < alen && b - b0 < blen) {
		if (a - a0 + 1 > alen || b - b0 + 1 > blen)
			return 0;

		if ((signed char)a[0] < 0 || (signed char)b[0] < 0)
			return 0;
		/* we don't support compression yet */
		if (a[0] >= 64 || b[0] >= 64)
			return 0;

		/* truncated case */
		if (a[0] == 0 && a - a0 == alen - 1)
			return 1;
		if (b[0] == 0 && b - b0 == blen - 1)
			return 1;
		if (a[0] == 0 || b[0] == 0)
			return 0;

		if (a[0] != b[0])
			return 0;
		l = a[0];
		if (a - a0 + 1 + l > alen || b - b0 + 1 + l > blen)
			return 0;
		if (bcmp(a + 1, b + 1, l) != 0)
			return 0;

		a += 1 + l;
		b += 1 + l;
	}

	if (a - a0 == alen && b - b0 == blen)
		return 1;
	else
		return 0;
}

/*
 * calculate the number of addresses to be returned in the node info reply.
 */
static int
ni6_addrs(struct icmp6_nodeinfo *ni6, struct mbuf *m,
    struct ifnet **ifpp, char *subj)
{
	struct ifnet *ifp;
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	struct sockaddr_in6 *subj_ip6 = NULL; /* XXX pedant */
	int addrs = 0, addrsofif, iffound = 0;
	int niflags = ni6->ni_flags;

	if ((niflags & NI_NODEADDR_FLAG_ALL) == 0) {
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
			if (subj == NULL) /* must be impossible... */
				return (0);
			subj_ip6 = (struct sockaddr_in6 *)subj;
			break;
		default:
			/*
			 * XXX: we only support IPv6 subject address for
			 * this Qtype.
			 */
			return (0);
		}
	}

	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list))
	{
		addrsofif = 0;
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next)
		{
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((niflags & NI_NODEADDR_FLAG_ALL) == 0 &&
			    IN6_ARE_ADDR_EQUAL(&subj_ip6->sin6_addr,
					       &ifa6->ia_addr.sin6_addr))
				iffound = 1;

			/*
			 * IPv4-mapped addresses can only be returned by a
			 * Node Information proxy, since they represent
			 * addresses of IPv4-only nodes, which perforce do
			 * not implement this protocol.
			 * [icmp-name-lookups-07, Section 5.4]
			 * So we don't support NI_NODEADDR_FLAG_COMPAT in
			 * this function at this moment.
			 */

			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0)
					continue;
				break;
			default:
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0)
				continue; /* we need only unicast addresses */

			addrsofif++; /* count the address */
		}
		if (iffound) {
			*ifpp = ifp;
			return (addrsofif);
		}

		addrs += addrsofif;
	}

	return (addrs);
}

static int
ni6_store_addrs(ni6, nni6, ifp0, resid)
	struct icmp6_nodeinfo *ni6, *nni6;
	struct ifnet *ifp0;
	int resid;
{
	struct ifnet *ifp = ifp0 ? ifp0 : TAILQ_FIRST(&ifnet);
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	struct ifnet *ifp_dep = NULL;
	int copied = 0, allow_deprecated = 0;
	u_char *cp = (u_char *)(nni6 + 1);
	int niflags = ni6->ni_flags;
	u_int32_t ltime;

	if (ifp0 == NULL && !(niflags & NI_NODEADDR_FLAG_ALL))
		return (0);	/* needless to copy */

  again:

	for (; ifp; ifp = TAILQ_NEXT(ifp, if_list))
	{
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next)
		{
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) != 0 &&
			    allow_deprecated == 0) {
				/*
				 * prefererred address should be put before
				 * deprecated addresses.
				 */

				/* record the interface for later search */
				if (ifp_dep == NULL)
					ifp_dep = ifp;

				continue;
			}
			else if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) == 0 &&
				 allow_deprecated != 0)
				continue; /* we now collect deprecated addrs */

			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0)
					continue;
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0)
					continue;
				break;
			default:
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0)
				continue;

			/* now we can copy the address */
			if (resid < sizeof(struct in6_addr) +
			    sizeof(u_int32_t)) {
				/*
				 * We give up much more copy.
				 * Set the truncate flag and return.
				 */
				nni6->ni_flags |= NI_NODEADDR_FLAG_TRUNCATE;
				return (copied);
			}

			/*
			 * Set the TTL of the address.
			 * The TTL value should be one of the following
			 * according to the specification:
			 *
			 * 1. The remaining lifetime of a DHCP lease on the
			 *    address, or
			 * 2. The remaining Valid Lifetime of a prefix from
			 *    which the address was derived through Stateless
			 *    Autoconfiguration.
			 *
			 * Note that we currently do not support stateful
			 * address configuration by DHCPv6, so the former
			 * case can't happen.
			 *
			 * TTL must be 2^31 > TTL >= 0.
			 */
			if (ifa6->ia6_lifetime.ia6t_expire == 0)
				ltime = ND6_INFINITE_LIFETIME;
			else {
				if (ifa6->ia6_lifetime.ia6t_expire >
				    time_second)
					ltime = ifa6->ia6_lifetime.ia6t_expire -
					    time_second;
				else
					ltime = 0;
			}
			if (ltime > 0x7fffffff)
				ltime = 0x7fffffff;
#ifdef __QNXNTO__
			else
				ltime = ti_tireal_small(ltime);
#endif
			ltime = htonl(ltime);

			bcopy(&ltime, cp, sizeof(u_int32_t));
			cp += sizeof(u_int32_t);

			/* copy the address itself */
			bcopy(&ifa6->ia_addr.sin6_addr, cp,
			      sizeof(struct in6_addr));
			in6_clearscope((struct in6_addr *)cp); /* XXX */
			cp += sizeof(struct in6_addr);

			resid -= (sizeof(struct in6_addr) + sizeof(u_int32_t));
			copied += (sizeof(struct in6_addr) + sizeof(u_int32_t));
		}
		if (ifp0)	/* we need search only on the specified IF */
			break;
	}

	if (allow_deprecated == 0 && ifp_dep != NULL) {
		ifp = ifp_dep;
		allow_deprecated = 1;

		goto again;
	}

	return (copied);
}

/*
 * XXX almost dup'ed code with rip6_input.
 */
static int
icmp6_rip6_input(mp, off)
	struct	mbuf **mp;
	int	off;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct inpcb_hdr *inph;
	struct in6pcb *in6p;
	struct in6pcb *last = NULL;
	struct sockaddr_in6 rip6src;
	struct icmp6_hdr *icmp6;
	struct mbuf *opts = NULL;

	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		/* m is already reclaimed */
		return IPPROTO_DONE;
	}

	/*
	 * XXX: the address may have embedded scope zone ID, which should be
	 * hidden from applications.
	 */
	bzero(&rip6src, sizeof(rip6src));
	rip6src.sin6_len = sizeof(struct sockaddr_in6);
	rip6src.sin6_family = AF_INET6;
	rip6src.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&rip6src)) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

	CIRCLEQ_FOREACH(inph, &raw6cbtable.inpt_queue, inph_queue) {
		in6p = (struct in6pcb *)inph;
		if (in6p->in6p_af != AF_INET6)
			continue;
		if (in6p->in6p_ip6.ip6_nxt != IPPROTO_ICMPV6)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (in6p->in6p_icmp6filt
		    && ICMP6_FILTER_WILLBLOCK(icmp6->icmp6_type,
				 in6p->in6p_icmp6filt))
			continue;
		if (last) {
			struct	mbuf *n;
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (last->in6p_flags & IN6P_CONTROLOPTS)
					ip6_savecontrol(last, &opts, ip6, n);
				/* strip intermediate headers */
				m_adj(n, off);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
						 (struct sockaddr *)&rip6src,
						 n, opts) == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts)
						m_freem(opts);
				} else
					sorwakeup(last->in6p_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS)
			ip6_savecontrol(last, &opts, ip6, m);
		/* strip intermediate headers */
		m_adj(m, off);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				(struct sockaddr *)&rip6src, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
		} else
			sorwakeup(last->in6p_socket);
	} else {
		m_freem(m);
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}

/*
 * Reflect the ip6 packet back to the source.
 * OFF points to the icmp6 header, counted from the top of the mbuf.
 *
 * Note: RFC 1885 required that an echo reply should be truncated if it
 * did not fit in with (return) path MTU, and KAME code supported the
 * behavior.  However, as a clarification after the RFC, this limitation
 * was removed in a revised version of the spec, RFC 2463.  We had kept the
 * old behavior, with a (non-default) ifdef block, while the new version of
 * the spec was an internet-draft status, and even after the new RFC was
 * published.  But it would rather make sense to clean the obsoleted part
 * up, and to make the code simpler at this stage.
 */
void
icmp6_reflect(m, off
#ifdef QNX_MFIB
		, fib
#endif
)
	struct	mbuf *m;
	size_t off;
#ifdef QNX_MFIB
	int fib;
#endif
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct in6_ifaddr *ia;
	int plen;
	int type, code;
#ifdef __QNXNTO__
	int output_flags = IPV6_MINMTU;
#endif
	struct ifnet *outif = NULL;
	struct in6_addr origdst, *src = NULL;

	/* too short to reflect */
	if (off < sizeof(struct ip6_hdr)) {
		nd6log((LOG_DEBUG,
		    "sanity fail: off=%lx, sizeof(ip6)=%lx in %s:%d\n",
		    (u_long)off, (u_long)sizeof(struct ip6_hdr),
		    __FILE__, __LINE__));
		goto bad;
	}

	/*
	 * If there are extra headers between IPv6 and ICMPv6, strip
	 * off that header first.
	 */
#ifdef DIAGNOSTIC
	if (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) > MHLEN)
		panic("assumption failed in icmp6_reflect");
#endif
	if (off > sizeof(struct ip6_hdr)) {
		size_t l;
		struct ip6_hdr nip6;

		l = off - sizeof(struct ip6_hdr);
		m_copydata(m, 0, sizeof(nip6), (caddr_t)&nip6);
		m_adj(m, l);
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m = m_pullup(m, l)) == NULL)
				return;
		}
		bcopy((caddr_t)&nip6, mtod(m, caddr_t), sizeof(nip6));
	} else /* off == sizeof(struct ip6_hdr) */ {
		size_t l;
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m = m_pullup(m, l)) == NULL)
				return;
		}
	}
	plen = m->m_pkthdr.len - sizeof(struct ip6_hdr);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);
	type = icmp6->icmp6_type; /* keep type for statistics */
	code = icmp6->icmp6_code; /* ditto. */

	origdst = ip6->ip6_dst;
	/*
	 * ip6_input() drops a packet if its src is multicast.
	 * So, the src is never multicast.
	 */
	ip6->ip6_dst = ip6->ip6_src;

	/*
	 * If the incoming packet was addressed directly to us (i.e. unicast),
	 * use dst as the src for the reply.
	 * The IN6_IFF_NOTREADY case should be VERY rare, but is possible
	 * (for example) when we encounter an error while forwarding procedure
	 * destined to a duplicated address of ours.
	 * Note that ip6_getdstifaddr() may fail if we are in an error handling
	 * procedure of an outgoing packet of our own, in which case we need
	 * to search in the ifaddr list.
	 */
	if (!IN6_IS_ADDR_MULTICAST(&origdst)) {
		if ((ia = ip6_getdstifaddr(m))) {
			if (!(ia->ia6_flags &
			    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY)))
				src = &ia->ia_addr.sin6_addr;
		} else {
			struct sockaddr_in6 d;

			bzero(&d, sizeof(d));
			d.sin6_family = AF_INET6;
			d.sin6_len = sizeof(d);
			d.sin6_addr = origdst;
			ia = (struct in6_ifaddr *)
#ifndef __QNXNTO__
			    ifa_ifwithaddr((struct sockaddr *)&d);
#else
			    (ifa_ifwithaddr)((struct sockaddr *)&d, ip_checkinterface ? m->m_pkthdr.rcvif : NULL
#ifdef QNX_MFIB
			    		, fib
#endif
			    		);
#endif
			if (ia &&
			    !(ia->ia6_flags &
			    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY))) {
				src = &ia->ia_addr.sin6_addr;
			}
		}
	}

	if (src == NULL) {
		int e;
		struct sockaddr_in6 sin6;
		struct route_in6 ro;

		/*
		 * This case matches to multicasts, our anycast, or unicasts
		 * that we do not own.  Select a source address based on the
		 * source address of the erroneous packet.
		 */
		bzero(&sin6, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_addr = ip6->ip6_dst; /* zone ID should be embedded */

		bzero(&ro, sizeof(ro));
#ifndef __QNXNTO__
		src = in6_selectsrc(&sin6, NULL, NULL, &ro, NULL, &outif, &e);
#else
#ifndef QNX_MFIB
		src = in6_selectsrc(&sin6, NULL, NULL, &ro, NULL, &outif, &e, m->m_pkthdr.rcvif);
#else
		src = in6_selectsrc(&sin6, NULL, NULL, &ro, NULL, &outif, &e, m->m_pkthdr.rcvif, fib);
#endif
#endif
		if (ro.ro_rt) { /* XXX: see comments in icmp6_mtudisc_update */
			RTFREE(ro.ro_rt); /* XXX: we could use this */
		}
		if (src == NULL) {
			nd6log((LOG_DEBUG,
			    "icmp6_reflect: source can't be determined: "
			    "dst=%s, error=%d\n",
			    ip6_sprintf(&sin6.sin6_addr), e));
			goto bad;
		}
	}

	ip6->ip6_src = *src;
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	if (m->m_pkthdr.rcvif) {
		/* XXX: This may not be the outgoing interface */
		ip6->ip6_hlim = ND_IFINFO(m->m_pkthdr.rcvif)->chlim;
	} else
		ip6->ip6_hlim = ip6_defhlim;

	m->m_pkthdr.csum_flags = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in6_cksum(m, IPPROTO_ICMPV6,
					sizeof(struct ip6_hdr), plen);

	/*
	 * XXX option handling
	 */

	m->m_flags &= ~(M_BCAST|M_MCAST);

#ifdef __QNXNTO__
	/*
	 * Don't always force echo replies to be fragmented to IPv6 min MTU.
	 */
	if ((icmp6_fragment_reply == 0) && (type == ICMP6_ECHO_REPLY)) {
		output_flags = 0;
	}


	if (ip6_output(m, NULL, NULL, output_flags, NULL, NULL, &outif,
	    m->m_pkthdr.rcvif, NULL
#ifdef QNX_MFIB
	    , fib
#endif
	    ) != 0 &&
	    outif)
#else
	/*
	 * To avoid a "too big" situation at an intermediate router
	 * and the path MTU discovery process, specify the IPV6_MINMTU flag.
	 * Note that only echo and node information replies are affected,
	 * since the length of ICMP6 errors is limited to the minimum MTU.
	 */
	if (ip6_output(m, NULL, NULL, IPV6_MINMTU, NULL, NULL, &outif) != 0 &&
	    outif)
#endif
		icmp6_ifstat_inc(outif, ifs6_out_error);

	if (outif)
		icmp6_ifoutstat_inc(outif, type, code);

	return;

 bad:
	m_freem(m);
	return;
}

static const char *
icmp6_redirect_diag(src6, dst6, tgt6)
	struct in6_addr *src6;
	struct in6_addr *dst6;
	struct in6_addr *tgt6;
{
	static char buf[1024];
	snprintf(buf, sizeof(buf), "(src=%s dst=%s tgt=%s)",
		ip6_sprintf(src6), ip6_sprintf(dst6), ip6_sprintf(tgt6));
	return buf;
}

void
icmp6_redirect_input(m, off)
	struct mbuf *m;
	int off;
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_redirect *nd_rd;
	int icmp6len = ntohs(ip6->ip6_plen);
	char *lladdr = NULL;
	int lladdrlen = 0;
	struct rtentry *rt = NULL;
	int is_router;
	int is_onlink;
	struct in6_addr src6 = ip6->ip6_src;
	struct in6_addr redtgt6;
	struct in6_addr reddst6;
	union nd_opts ndopts;

	if (!ifp)
		return;

	/* XXX if we are router, we don't update route by icmp6 redirect */
#ifndef __QNXNTO__
	if (ip6_forwarding)
#else
	if (IP6FORWARDING(ifp))
#endif
		goto freeit;
	if (!icmp6_rediraccept)
		goto freeit;

	IP6_EXTHDR_GET(nd_rd, struct nd_redirect *, m, off, icmp6len);
	if (nd_rd == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
	redtgt6 = nd_rd->nd_rd_target;
	reddst6 = nd_rd->nd_rd_dst;

	if (in6_setscope(&redtgt6, m->m_pkthdr.rcvif, NULL) ||
	    in6_setscope(&reddst6, m->m_pkthdr.rcvif, NULL)) {
		goto freeit;
	}

	/* validation */
	if (!IN6_IS_ADDR_LINKLOCAL(&src6)) {
		nd6log((LOG_ERR,
			"ICMP6 redirect sent from %s rejected; "
			"must be from linklocal\n", ip6_sprintf(&src6)));
		goto bad;
	}
	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
			"ICMP6 redirect sent from %s rejected; "
			"hlim=%d (must be 255)\n",
			ip6_sprintf(&src6), ip6->ip6_hlim));
		goto bad;
	}
    {
	/* ip6->ip6_src must be equal to gw for icmp6->icmp6_reddst */
	struct sockaddr_in6 sin6;
	struct in6_addr *gw6;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sin6.sin6_addr, sizeof(reddst6));
#ifndef __QNXNTO__
	rt = rtalloc1((struct sockaddr *)&sin6, 0);
#else
#ifndef QNX_MFIB
	rt = (rtalloc1)((struct sockaddr *)&sin6, 0, m->m_pkthdr.rcvif);
#else
	rt = (rtalloc1)((struct sockaddr *)&sin6, 0, m->m_pkthdr.rcvif, if_get_first_fib(ifp)); /* XX MFIB: redirect only on one fib */
#endif
#endif
	if (rt) {
		if (rt->rt_gateway == NULL ||
		    rt->rt_gateway->sa_family != AF_INET6) {
			nd6log((LOG_ERR,
			    "ICMP6 redirect rejected; no route "
			    "with inet6 gateway found for redirect dst: %s\n",
			    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			RTFREE(rt);
			goto bad;
		}

		gw6 = &(((struct sockaddr_in6 *)rt->rt_gateway)->sin6_addr);
		if (bcmp(&src6, gw6, sizeof(struct in6_addr)) != 0) {
			nd6log((LOG_ERR,
				"ICMP6 redirect rejected; "
				"not equal to gw-for-src=%s (must be same): "
				"%s\n",
				ip6_sprintf(gw6),
				icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			RTFREE(rt);
			goto bad;
		}
	} else {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"no route found for redirect dst: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	RTFREE(rt);
	rt = NULL;
    }
	if (IN6_IS_ADDR_MULTICAST(&reddst6)) {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"redirect dst must be unicast: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	is_router = is_onlink = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&redtgt6))
		is_router = 1;	/* router case */
	if (bcmp(&redtgt6, &reddst6, sizeof(redtgt6)) == 0)
		is_onlink = 1;	/* on-link destination case */
	if (!is_router && !is_onlink) {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"neither router case nor onlink case: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	/* validation passed */

	icmp6len -= sizeof(*nd_rd);
	nd6_option_init(nd_rd + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO, "icmp6_redirect_input: "
			"invalid ND option, rejected: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
			"icmp6_redirect_input: lladdrlen mismatch for %s "
			"(if %d, icmp6 packet %d): %s\n",
			ip6_sprintf(&redtgt6), ifp->if_addrlen, lladdrlen - 2,
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	/* RFC 2461 8.3 */
	nd6_cache_lladdr(ifp, &redtgt6, lladdr, lladdrlen, ND_REDIRECT,
			 is_onlink ? ND_REDIRECT_ONLINK : ND_REDIRECT_ROUTER);

	if (!is_onlink) {	/* better router case.  perform rtredirect. */
		/* perform rtredirect */
		struct sockaddr_in6 sdst;
		struct sockaddr_in6 sgw;
		struct sockaddr_in6 ssrc;
		unsigned long rtcount;
		struct rtentry *newrt = NULL;

		/*
		 * do not install redirect route, if the number of entries
		 * is too much (> hiwat).  note that, the node (= host) will
		 * work just fine even if we do not install redirect route
		 * (there will be additional hops, though).
		 */
		rtcount = rt_timer_count(icmp6_redirect_timeout_q);
		if (0 <= icmp6_redirect_hiwat && rtcount > icmp6_redirect_hiwat)
			return;
		else if (0 <= icmp6_redirect_lowat &&
		    rtcount > icmp6_redirect_lowat) {
			/*
			 * XXX nuke a victim, install the new one.
			 */
		}

		bzero(&sdst, sizeof(sdst));
		bzero(&sgw, sizeof(sgw));
		bzero(&ssrc, sizeof(ssrc));
		sdst.sin6_family = sgw.sin6_family = ssrc.sin6_family = AF_INET6;
		sdst.sin6_len = sgw.sin6_len = ssrc.sin6_len =
			sizeof(struct sockaddr_in6);
		bcopy(&redtgt6, &sgw.sin6_addr, sizeof(struct in6_addr));
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		bcopy(&src6, &ssrc.sin6_addr, sizeof(struct in6_addr));
		rtredirect((struct sockaddr *)&sdst, (struct sockaddr *)&sgw,
			   (struct sockaddr *)NULL, RTF_GATEWAY | RTF_HOST,
			   (struct sockaddr *)&ssrc,
			   &newrt
#ifdef QNX_MFIB
			   , m->m_pkthdr.rcvif
#endif
			   );

		if (newrt) {
			(void)rt_timer_add(newrt, icmp6_redirect_timeout,
			    icmp6_redirect_timeout_q);
			rtfree(newrt);
		}
	}
	/* finally update cached route in each socket via pfctlinput */
	{
		struct sockaddr_in6 sdst;

		bzero(&sdst, sizeof(sdst));
		sdst.sin6_family = AF_INET6;
		sdst.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&sdst);
#if defined(IPSEC) || defined(FAST_IPSEC)
if (QNXNTO_IPSEC_ENABLED) {
		key_sa_routechange((struct sockaddr *)&sdst);
}
#endif
	}

 freeit:
	m_freem(m);
	return;

 bad:
	icmp6stat.icp6s_badredirect++;
	m_freem(m);
}

void
icmp6_redirect_output(m0, rt)
	struct mbuf *m0;
	struct rtentry *rt;
{
	struct ifnet *ifp;	/* my outgoing interface */
	struct in6_addr *ifp_ll6;
	struct in6_addr *nexthop;
	struct ip6_hdr *sip6;	/* m0 as struct ip6_hdr */
	struct mbuf *m = NULL;	/* newly allocated one */
	struct ip6_hdr *ip6;	/* m as struct ip6_hdr */
	struct nd_redirect *nd_rd;
	size_t maxlen;
	u_char *p;
	struct sockaddr_in6 src_sa;

	icmp6_errcount(&icmp6stat.icp6s_outerrhist, ND_REDIRECT, 0);

#ifndef __QNXNTO__
	/* if we are not router, we don't send icmp6 redirect */
	if (!ip6_forwarding)
		goto fail;
#endif

	/* sanity check */
	if (!m0 || !rt || !(rt->rt_flags & RTF_UP) || !(ifp = rt->rt_ifp))
		goto fail;

#ifdef __QNXNTO__
#ifndef QNX_MFIB
	/* if we are not router, we don't send icmp6 redirect */
	if (!IP6FORWARDING(ifp))
		goto fail;
#else
	/* if we are not router, we don't send icmp6 redirect */
	if (!IP6FORWARD_FIB(ifp, rt->fib))
		goto fail;
#endif
#endif

	/*
	 * Address check:
	 *  the source address must identify a neighbor, and
	 *  the destination address must not be a multicast address
	 *  [RFC 2461, sec 8.2]
	 */
	sip6 = mtod(m0, struct ip6_hdr *);
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = sip6->ip6_src;
	if (nd6_is_addr_neighbor(&src_sa, ifp
#ifdef QNX_MFIB
			, rt->fib
#endif
	) == 0)
		goto fail;
	if (IN6_IS_ADDR_MULTICAST(&sip6->ip6_dst))
		goto fail;	/* what should we do here? */

	/* rate limit */
	if (icmp6_ratelimit(&sip6->ip6_src, ND_REDIRECT, 0))
		goto fail;

	/*
	 * Since we are going to append up to 1280 bytes (= IPV6_MMTU),
	 * we almost always ask for an mbuf cluster for simplicity.
	 * (MHLEN < IPV6_MMTU is almost always true)
	 */
#ifndef __QNXNTO__
#if IPV6_MMTU >= MCLBYTES
# error assumption failed about IPV6_MMTU and MCLBYTES
#endif
#else
/* Where (1<<MCLSHIFT_NTOMIN) is the minimum */
#if IPV6_MMTU >= (1<<MCLSHIFT_NTOMIN)
# error assumption failed about IPV6_MMTU and MCLBYTES
#endif
#endif
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && IPV6_MMTU >= MHLEN)
		MCLGET(m, M_DONTWAIT);
	if (!m)
		goto fail;
	m->m_pkthdr.rcvif = NULL;
	m->m_len = 0;
	maxlen = M_TRAILINGSPACE(m);
	maxlen = min(IPV6_MMTU, maxlen);
	/* just for safety */
	if (maxlen < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
	    ((sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7)) {
		goto fail;
	}

	{
		/* get ip6 linklocal address for ifp(my outgoing interface). */
		struct in6_ifaddr *ia;
		if ((ia = in6ifa_ifpforlinklocal(ifp,
						 IN6_IFF_NOTREADY|
						 IN6_IFF_ANYCAST)) == NULL)
			goto fail;
		ifp_ll6 = &ia->ia_addr.sin6_addr;
	}

	/* get ip6 linklocal address for the router. */
	if (rt->rt_gateway && (rt->rt_flags & RTF_GATEWAY)) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)rt->rt_gateway;
		nexthop = &sin6->sin6_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(nexthop))
			nexthop = NULL;
	} else
		nexthop = NULL;

	/* ip6 */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	/* ip6->ip6_src must be linklocal addr for my outgoing if. */
	bcopy(ifp_ll6, &ip6->ip6_src, sizeof(struct in6_addr));
	bcopy(&sip6->ip6_src, &ip6->ip6_dst, sizeof(struct in6_addr));

	/* ND Redirect */
	nd_rd = (struct nd_redirect *)(ip6 + 1);
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	if (rt->rt_flags & RTF_GATEWAY) {
		/*
		 * nd_rd->nd_rd_target must be a link-local address in
		 * better router cases.
		 */
		if (!nexthop)
			goto fail;
		bcopy(nexthop, &nd_rd->nd_rd_target,
		      sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		      sizeof(nd_rd->nd_rd_dst));
	} else {
		/* make sure redtgt == reddst */
		nexthop = &sip6->ip6_dst;
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_target,
		      sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		      sizeof(nd_rd->nd_rd_dst));
	}

	p = (u_char *)(nd_rd + 1);

	{
		/* target lladdr option */
		struct rtentry *rt_nexthop = NULL;
		int len;
		struct sockaddr_dl *sdl;
		struct nd_opt_hdr *nd_opt;
		char *lladdr;

		rt_nexthop = nd6_lookup(nexthop, 0, ifp);
		if (!rt_nexthop)
			goto nolladdropt;
		len = sizeof(*nd_opt) + ifp->if_addrlen;
		len = (len + 7) & ~7;	/* round by 8 */
		/* safety check */
		if (len + (p - (u_char *)ip6) > maxlen)
			goto nolladdropt;
		if (!(rt_nexthop->rt_flags & RTF_GATEWAY) &&
		    (rt_nexthop->rt_flags & RTF_LLINFO) &&
		    (rt_nexthop->rt_gateway->sa_family == AF_LINK) &&
		    (sdl = (struct sockaddr_dl *)rt_nexthop->rt_gateway) &&
		    sdl->sdl_alen) {
			nd_opt = (struct nd_opt_hdr *)p;
			nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
			nd_opt->nd_opt_len = len >> 3;
			lladdr = (char *)(nd_opt + 1);
			bcopy(LLADDR(sdl), lladdr, ifp->if_addrlen);
			p += len;
		}
	}
  nolladdropt:;

	m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

	/* just to be safe */
	if (m0->m_flags & M_DECRYPTED)
		goto noredhdropt;
	if (p - (u_char *)ip6 > maxlen)
		goto noredhdropt;

	{
		/* redirected header option */
		int len;
		struct nd_opt_rd_hdr *nd_opt_rh;

		/*
		 * compute the maximum size for icmp6 redirect header option.
		 * XXX room for auth header?
		 */
		len = maxlen - (p - (u_char *)ip6);
		len &= ~7;

		/*
		 * Redirected header option spec (RFC2461 4.6.3) talks nothing
		 * about padding/truncate rule for the original IP packet.
		 * From the discussion on IPv6imp in Feb 1999,
		 * the consensus was:
		 * - "attach as much as possible" is the goal
		 * - pad if not aligned (original size can be guessed by
		 *   original ip6 header)
		 * Following code adds the padding if it is simple enough,
		 * and truncates if not.
		 */
		if (len - sizeof(*nd_opt_rh) < m0->m_pkthdr.len) {
			/* not enough room, truncate */
			m_adj(m0, (len - sizeof(*nd_opt_rh)) -
			    m0->m_pkthdr.len);
		} else {
			/*
			 * enough room, truncate if not aligned.
			 * we don't pad here for simplicity.
			 */
			size_t extra;

			extra = m0->m_pkthdr.len % 8;
			if (extra) {
				/* truncate */
				m_adj(m0, -extra);
			}
			len = m0->m_pkthdr.len + sizeof(*nd_opt_rh);
		}

		nd_opt_rh = (struct nd_opt_rd_hdr *)p;
		bzero(nd_opt_rh, sizeof(*nd_opt_rh));
		nd_opt_rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
		nd_opt_rh->nd_opt_rh_len = len >> 3;
		p += sizeof(*nd_opt_rh);
		m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

		/* connect m0 to m */
		m->m_pkthdr.len += m0->m_pkthdr.len;
		m_cat(m, m0);
		m0 = NULL;
	}
noredhdropt:
	if (m0) {
		m_freem(m0);
		m0 = NULL;
	}

	/* XXX: clear embedded link IDs in the inner header */
	in6_clearscope(&sip6->ip6_src);
	in6_clearscope(&sip6->ip6_dst);
	in6_clearscope(&nd_rd->nd_rd_target);
	in6_clearscope(&nd_rd->nd_rd_dst);

	ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(struct ip6_hdr));

	nd_rd->nd_rd_cksum = 0;
	nd_rd->nd_rd_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), ntohs(ip6->ip6_plen));

	/* send the packet to outside... */
	if (ip6_output(m, NULL, NULL, 0,
		(struct ip6_moptions *)NULL, (struct socket *)NULL, NULL
#ifdef __QNXNTO__
		, ifp, NULL
#ifdef QNX_MFIB
		, if_get_first_fib(ifp)
#endif
#endif
		) != 0)
		icmp6_ifstat_inc(ifp, ifs6_out_error);

	icmp6_ifstat_inc(ifp, ifs6_out_msg);
	icmp6_ifstat_inc(ifp, ifs6_out_redirect);
	icmp6stat.icp6s_outhist[ND_REDIRECT]++;

	return;

fail:
	if (m)
		m_freem(m);
	if (m0)
		m_freem(m0);
}

/*
 * ICMPv6 socket option processing.
 */
int
icmp6_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
	int error = 0;
	int optlen;
	struct in6pcb *in6p = sotoin6pcb(so);
	struct mbuf *m = *mp;

	optlen = m ? m->m_len : 0;

	if (level != IPPROTO_ICMPV6) {
		if (op == PRCO_SETOPT && m)
			(void)m_free(m);
		return EINVAL;
	}

	switch (op) {
	case PRCO_SETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter *p;

			if (optlen != sizeof(*p)) {
				error = EMSGSIZE;
				break;
			}
			p = mtod(m, struct icmp6_filter *);
			if (!p || !in6p->in6p_icmp6filt) {
				error = EINVAL;
				break;
			}
			bcopy(p, in6p->in6p_icmp6filt,
				sizeof(struct icmp6_filter));
			error = 0;
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m)
			(void)m_freem(m);
		break;

	case PRCO_GETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter *p;

			if (!in6p->in6p_icmp6filt) {
				error = EINVAL;
				break;
			}
			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			m->m_len = sizeof(struct icmp6_filter);
			p = mtod(m, struct icmp6_filter *);
			bcopy(in6p->in6p_icmp6filt, p,
				sizeof(struct icmp6_filter));
			error = 0;
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}

	return (error);
}

/*
 * Perform rate limit check.
 * Returns 0 if it is okay to send the icmp6 packet.
 * Returns 1 if the router SHOULD NOT send this icmp6 packet due to rate
 * limitation.
 *
 * XXX per-destination/type check necessary?
 */
static int
icmp6_ratelimit(
	const struct in6_addr *dst,	/* not used at this moment */
	const int type,		/* not used at this moment */
	const int code)		/* not used at this moment */
{
	int ret;

	ret = 0;	/* okay to send */

	/* PPS limit */
	if (!ppsratecheck(&icmp6errppslim_last, &icmp6errpps_count,
	    icmp6errppslim)) {
		/* The packet is subject to rate limit */
		ret++;
	}

	return ret;
}

static struct rtentry *
#ifndef QNX_MFIB
icmp6_mtudisc_clone(dst)
#else
icmp6_mtudisc_clone(dst, fib)
	int fib;
#endif
	struct sockaddr *dst;
{
	struct rtentry *rt;
	int    error;

#ifndef QNX_MFIB
	rt = rtalloc1(dst, 1);
#else
	rt = rtalloc1(dst, 1, NULL, fib);
#endif
	if (rt == 0)
		return NULL;

	/* If we didn't get a host route, allocate one */
	if ((rt->rt_flags & RTF_HOST) == 0) {
		struct rtentry *nrt;

		error = rtrequest((int) RTM_ADD, dst,
		    (struct sockaddr *) rt->rt_gateway,
		    (struct sockaddr *) 0,
#ifndef QNX_MFIB
		    RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC, &nrt);
#else
				    RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC, &nrt, fib);
#endif
		if (error) {
			rtfree(rt);
			return NULL;
		}
		nrt->rt_rmx = rt->rt_rmx;
		rtfree(rt);
		rt = nrt;
	}
	error = rt_timer_add(rt, icmp6_mtudisc_timeout,
			icmp6_mtudisc_timeout_q);
	if (error) {
		rtfree(rt);
		return NULL;
	}

	return rt;	/* caller need to call rtfree() */
}

static void
icmp6_mtudisc_timeout(struct rtentry *rt, struct rttimer *r)
{
	if (rt == NULL)
		panic("icmp6_mtudisc_timeout: bad route to timeout");
	if ((rt->rt_flags & (RTF_DYNAMIC | RTF_HOST)) ==
	    (RTF_DYNAMIC | RTF_HOST)) {
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
#ifndef QNX_MFIB
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
#else
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0, rt->fib);
#endif
	} else {
		if (!(rt->rt_rmx.rmx_locks & RTV_MTU))
			rt->rt_rmx.rmx_mtu = 0;
	}
}

static void
icmp6_redirect_timeout(struct rtentry *rt, struct rttimer *r)
{
	if (rt == NULL)
		panic("icmp6_redirect_timeout: bad route to timeout");
	if ((rt->rt_flags & (RTF_GATEWAY | RTF_DYNAMIC | RTF_HOST)) ==
	    (RTF_GATEWAY | RTF_DYNAMIC | RTF_HOST)) {
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
#ifndef QNX_MFIB
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
#else
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0, rt->fib);
#endif
	}
}

/*
 * sysctl helper routine for the net.inet6.icmp6.nd6 nodes.  silly?
 */
static int
sysctl_net_inet6_icmp6_nd6(SYSCTLFN_ARGS)
{
	(void)&name;
	(void)&l;
	(void)&oname;
#ifdef QNX_MFIB
	struct file *fp = l->l_fp;
	struct socket *so = (struct socket *)fp->f_data;
	int fib = so->so_fibnum;
#endif

	if (namelen != 0)
		return (EINVAL);

	return (nd6_sysctl(rnode->sysctl_num, oldp, oldlenp,
	    /*XXXUNCONST*/
	    __UNCONST(newp), newlen
#ifdef QNX_MFIB
	    , fib
#endif
	    ));
}

SYSCTL_SETUP(sysctl_net_inet6_icmp6_setup,
	     "sysctl net.inet6.icmp6 subtree setup")
{
	extern int nd6_maxqueuelen; /* defined in nd6.c */

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "inet6", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET6, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "icmp6",
		       SYSCTL_DESCR("ICMPv6 related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("ICMPv6 transmission statistics"),
		       NULL, 0, &icmp6stat, sizeof(icmp6stat),
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_STATS, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rediraccept",
		       SYSCTL_DESCR("Accept and process redirect messages"),
		       NULL, 0, &icmp6_rediraccept, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_REDIRACCEPT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "redirtimeout",
		       SYSCTL_DESCR("Redirect generated route lifetime"),
		       NULL, 0, &icmp6_redirtimeout, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_REDIRTIMEOUT, CTL_EOL);
#if 0 /* obsoleted */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "errratelimit", NULL,
		       NULL, 0, &icmp6_errratelimit, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ERRRATELIMIT, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_prune",
		       SYSCTL_DESCR("Neighbor discovery prune interval"),
		       NULL, 0, &nd6_prune, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_PRUNE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_delay",
		       SYSCTL_DESCR("First probe delay time"),
		       NULL, 0, &nd6_delay, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_DELAY, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_umaxtries",
		       SYSCTL_DESCR("Number of unicast discovery attempts"),
		       NULL, 0, &nd6_umaxtries, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_UMAXTRIES, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_mmaxtries",
		       SYSCTL_DESCR("Number of multicast discovery attempts"),
		       NULL, 0, &nd6_mmaxtries, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_MMAXTRIES, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_useloopback",
		       SYSCTL_DESCR("Use loopback interface for local traffic"),
		       NULL, 0, &nd6_useloopback, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_USELOOPBACK, CTL_EOL);
#if 0 /* obsoleted */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_proxyall", NULL,
		       NULL, 0, &nd6_proxyall, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_PROXYALL, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nodeinfo",
		       SYSCTL_DESCR("Respond to node information requests"),
		       NULL, 0, &icmp6_nodeinfo, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_NODEINFO, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "errppslimit",
		       SYSCTL_DESCR("Maximum ICMP errors sent per second"),
		       NULL, 0, &icmp6errppslim, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ERRPPSLIMIT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_maxnudhint",
		       SYSCTL_DESCR("Maximum neighbor unreachable hint count"),
		       NULL, 0, &nd6_maxnudhint, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_MAXNUDHINT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mtudisc_hiwat",
		       SYSCTL_DESCR("Low mark on MTU Discovery route timers"),
		       NULL, 0, &icmp6_mtudisc_hiwat, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_MTUDISC_HIWAT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mtudisc_lowat",
		       SYSCTL_DESCR("Low mark on MTU Discovery route timers"),
		       NULL, 0, &icmp6_mtudisc_lowat, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_MTUDISC_LOWAT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "nd6_debug",
		       SYSCTL_DESCR("Enable neighbor discovery debug output"),
		       NULL, 0, &nd6_debug, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_DEBUG, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "nd6_drlist",
		       SYSCTL_DESCR("Default router list"),
		       sysctl_net_inet6_icmp6_nd6, 0, NULL, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_DRLIST, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "nd6_prlist",
		       SYSCTL_DESCR("Prefix list"),
		       sysctl_net_inet6_icmp6_nd6, 0, NULL, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_PRLIST, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxqueuelen",
		       SYSCTL_DESCR("max packet queue len for a unresolved ND"),
		       NULL, 1, &nd6_maxqueuelen, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_ND6_MAXQLEN, CTL_EOL);
#ifdef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "fragechoreplies",
		       SYSCTL_DESCR("Fragment icmpv6 echo reply msgs to min IPv6 MTU"),
		       NULL, 0, &icmp6_fragment_reply, 0,
		       CTL_NET, PF_INET6, IPPROTO_ICMPV6,
		       ICMPV6CTL_FRAGECHO_REPLY, CTL_EOL);
#endif
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/icmp6.c $ $Rev: 854166 $")
#endif
