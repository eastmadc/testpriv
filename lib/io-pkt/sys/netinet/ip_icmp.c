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

/*	$NetBSD: ip_icmp.c,v 1.105 2006/11/16 01:33:45 christos Exp $	*/

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

/*-
 * Copyright (c) 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Public Access Networks Corporation ("Panix").  It was developed under
 * contract to Panix by Eric Haszlakiewicz and Thor Lancelot Simon.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of Zembu Labs, Inc.
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
__KERNEL_RCSID(0, "$NetBSD: ip_icmp.c,v 1.105 2006/11/16 01:33:45 christos Exp $");

#include "opt_ipsec.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#ifndef __QNXNTO__
#include <sys/time.h>
#else
#include <sys/time_bsd.h>
#endif
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/in_proto.h>
#include <netinet/icmp_var.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/key.h>
#endif	/* FAST_IPSEC*/

#include <machine/stdarg.h>

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */

int	icmpmaskrepl = 0;
int	icmpbmcastecho = 0;
#ifdef ICMPPRINTFS
int	icmpprintfs = 0;
#endif
int	icmpreturndatabytes = 8;

struct icmpstat	icmpstat;
#ifdef __QNXNTO__
int	icmptstamprepl = 1;
NLIST_EXPORT(icmpstat, icmpstat);
#endif

/*
 * List of callbacks to notify when Path MTU changes are made.
 */
struct icmp_mtudisc_callback {
	LIST_ENTRY(icmp_mtudisc_callback) mc_list;
	void (*mc_func)(struct in_addr);
};

LIST_HEAD(, icmp_mtudisc_callback) icmp_mtudisc_callbacks =
    LIST_HEAD_INITIALIZER(&icmp_mtudisc_callbacks);

#if 0
static u_int	ip_next_mtu(u_int, int);
#else
/*static*/ u_int	ip_next_mtu(u_int, int);
#endif

extern int icmperrppslim;
static int icmperrpps_count = 0;
static struct timeval icmperrppslim_last;
static int icmp_rediraccept = 1;
static int icmp_redirtimeout = 600;
static struct rttimer_queue *icmp_redirect_timeout_q = NULL;

static void icmp_mtudisc_timeout(struct rtentry *, struct rttimer *);
static void icmp_redirect_timeout(struct rtentry *, struct rttimer *);

static int icmp_ratelimit(const struct in_addr *, const int, const int);


void
icmp_init(void)
{
	/*
	 * This is only useful if the user initializes redirtimeout to
	 * something other than zero.
	 */
	if (icmp_redirtimeout != 0) {
		icmp_redirect_timeout_q =
			rt_timer_queue_create(icmp_redirtimeout);
	}
}

/*
 * Register a Path MTU Discovery callback.
 */
void
icmp_mtudisc_callback_register(void (*func)(struct in_addr))
{
	struct icmp_mtudisc_callback *mc;

	for (mc = LIST_FIRST(&icmp_mtudisc_callbacks); mc != NULL;
	     mc = LIST_NEXT(mc, mc_list)) {
		if (mc->mc_func == func)
			return;
	}

	mc = malloc(sizeof(*mc), M_PCB, M_NOWAIT);
	if (mc == NULL)
		panic("icmp_mtudisc_callback_register");

	mc->mc_func = func;
	LIST_INSERT_HEAD(&icmp_mtudisc_callbacks, mc, mc_list);
}

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
void
icmp_error(struct mbuf *n, int type, int code, n_long dest,
    int destmtu)
{
	struct ip *oip = mtod(n, struct ip *), *nip;
	unsigned oiplen = oip->ip_hl << 2;
	struct icmp *icp;
	struct mbuf *m;
	struct m_tag *mtag;
	unsigned icmplen, mblen;

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		printf("icmp_error(%p, type:%d, code:%d)\n", oip, type, code);
#endif
	if (type != ICMP_REDIRECT)
		icmpstat.icps_error++;
	/*
	 * Don't send error if the original packet was encrypted.
	 * Don't send error if not the first fragment of message.
	 * Don't error if the old packet protocol was ICMP
	 * error message, only known informational types.
	 */
	if (n->m_flags & M_DECRYPTED)
		goto freeit;
	if (oip->ip_off &~ htons(IP_MF|IP_DF))
		goto freeit;
	if (oip->ip_p == IPPROTO_ICMP && type != ICMP_REDIRECT &&
	  n->m_len >= oiplen + ICMP_MINLEN &&
	  !ICMP_INFOTYPE(((struct icmp *)((caddr_t)oip + oiplen))->icmp_type)) {
		icmpstat.icps_oldicmp++;
		goto freeit;
	}
	/* Don't send error in response to a multicast or broadcast packet */
	if (n->m_flags & (M_BCAST|M_MCAST))
		goto freeit;

	/*
	 * First, do a rate limitation check.
	 */
	if (icmp_ratelimit(&oip->ip_src, type, code)) {
		/* XXX stat */
		goto freeit;
	}

	/*
	 * Now, formulate icmp message
	 */
	icmplen = oiplen + min(icmpreturndatabytes,
	    ntohs(oip->ip_len) - oiplen);
	/*
	 * Defend against mbuf chains shorter than oip->ip_len - oiplen:
	 */
	mblen = 0;
	for (m = n; m && (mblen < icmplen); m = m->m_next)
		mblen += m->m_len;
	icmplen = min(mblen, icmplen);

	/*
	 * As we are not required to return everything we have,
	 * we return whatever we can return at ease.
	 *
	 * Note that ICMP datagrams longer than 576 octets are out of spec
	 * according to RFC1812; the limit on icmpreturndatabytes below in
	 * icmp_sysctl will keep things below that limit.
	 */

	KASSERT(ICMP_MINLEN <= MCLBYTES);

	if (icmplen + ICMP_MINLEN > MCLBYTES)
		icmplen = MCLBYTES - ICMP_MINLEN;

	m = m_gethdr(M_DONTWAIT, MT_HEADER);
	if (m && (icmplen + ICMP_MINLEN > MHLEN)) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (m == NULL)
		goto freeit;
	MCLAIM(m, n->m_owner);
	m->m_len = icmplen + ICMP_MINLEN;
	if ((m->m_flags & M_EXT) == 0)
		MH_ALIGN(m, m->m_len);
	icp = mtod(m, struct icmp *);
	if ((u_int)type > ICMP_MAXTYPE)
		panic("icmp_error");
	icmpstat.icps_outhist[type]++;
	icp->icmp_type = type;
	if (type == ICMP_REDIRECT)
		icp->icmp_gwaddr.s_addr = dest;
	else {
		icp->icmp_void = 0;
		/*
		 * The following assignments assume an overlay with the
		 * zeroed icmp_void field.
		 */
		if (type == ICMP_PARAMPROB) {
			icp->icmp_pptr = code;
			code = 0;
		} else if (type == ICMP_UNREACH &&
		    code == ICMP_UNREACH_NEEDFRAG && destmtu)
			icp->icmp_nextmtu = htons(destmtu);
	}

	icp->icmp_code = code;
	m_copydata(n, 0, icmplen, (caddr_t)&icp->icmp_ip);

	/*
	 * Now, copy old ip header (without options)
	 * in front of icmp message.
	 */
	if (m->m_data - sizeof(struct ip) < m->m_pktdat)
		panic("icmp len");
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);
	m->m_pkthdr.len = m->m_len;
	m->m_pkthdr.rcvif = n->m_pkthdr.rcvif;
	nip = mtod(m, struct ip *);
	/* ip_v set in ip_output */
	nip->ip_hl = sizeof(struct ip) >> 2;
	nip->ip_tos = 0;
	nip->ip_len = htons(m->m_len);
	/* ip_id set in ip_output */
	nip->ip_off = htons(0);
	/* ip_ttl set in icmp_reflect */
	nip->ip_p = IPPROTO_ICMP;
	nip->ip_src = oip->ip_src;
	nip->ip_dst = oip->ip_dst;
	/* move PF_GENERATED m_tag to new packet, if it exists */
	mtag = m_tag_find(n, PACKET_TAG_PF_GENERATED, NULL);
	if (mtag != NULL) {
		m_tag_unlink(n, mtag);
		m_tag_prepend(m, mtag);
	}
#ifdef __QNXNTO__
	mtag = m_tag_find(n, PACKET_TAG_PF_MFIB, NULL);
	if (mtag != NULL) {
		m_tag_unlink(n, mtag);
		m_tag_prepend(m, mtag);
	} 
#endif
	icmp_reflect(m);

freeit:
	m_freem(n);
}

struct sockaddr_in icmpsrc = {
	.sin_len = sizeof (struct sockaddr_in),
	.sin_family = AF_INET,
};
static struct sockaddr_in icmpdst = {
	.sin_len = sizeof (struct sockaddr_in),
	.sin_family = AF_INET,
};
static struct sockaddr_in icmpgw = {
	.sin_len = sizeof (struct sockaddr_in),
	.sin_family = AF_INET,
};
struct sockaddr_in icmpmask = { 
	.sin_len = 8,
	.sin_family = 0,
};

/*
 * Process a received ICMP message.
 */
void
icmp_input(struct mbuf *m, ...)
{
	int proto;
	struct icmp *icp;
	struct ip *ip = mtod(m, struct ip *);
	int icmplen;
	int i;
	struct in_ifaddr *ia;
	void *(*ctlfunc)(int, struct sockaddr *, void *);
	int code;
	int hlen;
	va_list ap;
	struct rtentry *rt;

	va_start(ap, m);
	hlen = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	/*
	 * Locate icmp structure in mbuf, and check
	 * that not corrupted and of at least minimum length.
	 */
	icmplen = ntohs(ip->ip_len) - hlen;
#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		printf("icmp_input from `%s' to ", inet_ntoa(ip->ip_src));
		printf("`%s', len %d\n", inet_ntoa(ip->ip_dst), icmplen);
	}
#endif
	if (icmplen < ICMP_MINLEN) {
		icmpstat.icps_tooshort++;
		goto freeit;
	}
	i = hlen + min(icmplen, ICMP_ADVLENMIN);
	if ((m->m_len < i || M_READONLY(m)) && (m = m_pullup(m, i)) == 0) {
		icmpstat.icps_tooshort++;
		return;
	}
	ip = mtod(m, struct ip *);
	m->m_len -= hlen;
	m->m_data += hlen;
	icp = mtod(m, struct icmp *);
	/* Don't need to assert alignment, here. */
	if (in_cksum(m, icmplen)) {
		icmpstat.icps_checksum++;
		goto freeit;
	}
	m->m_len += hlen;
	m->m_data -= hlen;

#ifdef ICMPPRINTFS
	/*
	 * Message type specific processing.
	 */
	if (icmpprintfs)
		printf("icmp_input(type:%d, code:%d)\n", icp->icmp_type,
		    icp->icmp_code);
#endif
	if (icp->icmp_type > ICMP_MAXTYPE)
		goto raw;
	icmpstat.icps_inhist[icp->icmp_type]++;
	code = icp->icmp_code;
	switch (icp->icmp_type) {

	case ICMP_UNREACH:
		switch (code) {
			case ICMP_UNREACH_NET:
				code = PRC_UNREACH_NET;
				break;

			case ICMP_UNREACH_HOST:
				code = PRC_UNREACH_HOST;
				break;

			case ICMP_UNREACH_PROTOCOL:
				code = PRC_UNREACH_PROTOCOL;
				break;

			case ICMP_UNREACH_PORT:
				code = PRC_UNREACH_PORT;
				break;

			case ICMP_UNREACH_SRCFAIL:
				code = PRC_UNREACH_SRCFAIL;
				break;

			case ICMP_UNREACH_NEEDFRAG:
				code = PRC_MSGSIZE;
				break;

			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_TOSNET:
				code = PRC_UNREACH_NET;
				break;

			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_TOSHOST:
				code = PRC_UNREACH_HOST;
				break;

			default:
				goto badcode;
		}
		goto deliver;

	case ICMP_TIMXCEED:
		if (code > 1)
			goto badcode;
		code += PRC_TIMXCEED_INTRANS;
		goto deliver;

	case ICMP_PARAMPROB:
		if (code > 1)
			goto badcode;
		code = PRC_PARAMPROB;
		goto deliver;

	case ICMP_SOURCEQUENCH:
		if (code)
			goto badcode;
		code = PRC_QUENCH;
		goto deliver;

	deliver:
		/*
		 * Problem with datagram; advise higher level routines.
		 */
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    icp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2)) {
			icmpstat.icps_badlen++;
			goto freeit;
		}
		if (IN_MULTICAST(icp->icmp_ip.ip_dst.s_addr))
			goto badcode;
#ifdef ICMPPRINTFS
		if (icmpprintfs)
			printf("deliver to protocol %d\n", icp->icmp_ip.ip_p);
#endif
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
		ctlfunc = inetsw[ip_protox[icp->icmp_ip.ip_p]].pr_ctlinput;
		if (ctlfunc)
			(void) (*ctlfunc)(code, sintosa(&icmpsrc),
			    &icp->icmp_ip);
		break;

	badcode:
		icmpstat.icps_badcode++;
		break;

	case ICMP_ECHO:
		if (!icmpbmcastecho &&
		   (m->m_flags & (M_MCAST | M_BCAST)) != 0) {
			icmpstat.icps_bmcastecho++;
			break;
		}
		icp->icmp_type = ICMP_ECHOREPLY;
		goto reflect;

	case ICMP_TSTAMP:
#ifdef __QNXNTO__
		if (icmptstamprepl == 0)
			break;
#endif
		if (icmplen < ICMP_TSLEN) {
			icmpstat.icps_badlen++;
			break;
		}

		if (!icmpbmcastecho &&
		   (m->m_flags & (M_MCAST | M_BCAST)) != 0) {
			icmpstat.icps_bmcasttstamp++;
			break;
		}

		icp->icmp_type = ICMP_TSTAMPREPLY;
		icp->icmp_rtime = iptime();
		icp->icmp_ttime = icp->icmp_rtime;	/* bogus, do later! */
		goto reflect;

	case ICMP_MASKREQ:
		if (icmpmaskrepl == 0)
			break;
		/*
		 * We are not able to respond with all ones broadcast
		 * unless we receive it over a point-to-point interface.
		 */
		if (icmplen < ICMP_MASKLEN) {
			icmpstat.icps_badlen++;
			break;
		}
		if (ip->ip_dst.s_addr == INADDR_BROADCAST ||
		    in_nullhost(ip->ip_dst))
			icmpdst.sin_addr = ip->ip_src;
		else
			icmpdst.sin_addr = ip->ip_dst;
		ia = ifatoia(ifaof_ifpforaddr(sintosa(&icmpdst),
		    m->m_pkthdr.rcvif));
		if (ia == 0)
			break;
		icp->icmp_type = ICMP_MASKREPLY;
		icp->icmp_mask = ia->ia_sockmask.sin_addr.s_addr;
		if (in_nullhost(ip->ip_src)) {
			if (ia->ia_ifp->if_flags & IFF_BROADCAST)
				ip->ip_src = ia->ia_broadaddr.sin_addr;
			else if (ia->ia_ifp->if_flags & IFF_POINTOPOINT)
				ip->ip_src = ia->ia_dstaddr.sin_addr;
		}
reflect:
		icmpstat.icps_reflect++;
		icmpstat.icps_outhist[icp->icmp_type]++;
		icmp_reflect(m);
		return;

	case ICMP_REDIRECT:
		if (code > 3)
			goto badcode;
		if (icmp_rediraccept == 0)
			goto freeit;
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    icp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2)) {
			icmpstat.icps_badlen++;
			break;
		}
		/*
		 * Short circuit routing redirects to force
		 * immediate change in the kernel's routing
		 * tables.  The message is also handed to anyone
		 * listening on a raw socket (e.g. the routing
		 * daemon for use in updating its tables).
		 */
		icmpgw.sin_addr = ip->ip_src;
		icmpdst.sin_addr = icp->icmp_gwaddr;
#ifdef	ICMPPRINTFS
		if (icmpprintfs) {
			printf("redirect dst `%s' to `%s'\n",
			    inet_ntoa(icp->icmp_ip.ip_dst),
			    inet_ntoa(icp->icmp_gwaddr));
		}
#endif
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
		rt = NULL;
		rtredirect(sintosa(&icmpsrc), sintosa(&icmpdst),
		    (struct sockaddr *)0, RTF_GATEWAY | RTF_HOST,
		    sintosa(&icmpgw), (struct rtentry **)&rt
#ifdef QNX_MFIB
		    , m->m_pkthdr.rcvif
#endif
		    );
		if (rt != NULL && icmp_redirtimeout != 0) {
			i = rt_timer_add(rt, icmp_redirect_timeout,
					 icmp_redirect_timeout_q);
			if (i)
				log(LOG_ERR, "ICMP:  redirect failed to "
				    "register timeout for route to %x, "
				    "code %d\n",
				    icp->icmp_ip.ip_dst.s_addr, i);
		}
		if (rt != NULL)
			rtfree(rt);

		pfctlinput(PRC_REDIRECT_HOST, sintosa(&icmpsrc));
#if defined(IPSEC) || defined(FAST_IPSEC)
if (QNXNTO_IPSEC_ENABLED) {
		key_sa_routechange((struct sockaddr *)&icmpsrc);
}
#endif
		break;

	/*
	 * No kernel processing for the following;
	 * just fall through to send to raw listener.
	 */
	case ICMP_ECHOREPLY:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQREPLY:
	case ICMP_MASKREPLY:
	default:
		break;
	}

raw:
	rip_input(m, hlen, proto);
	return;

freeit:
	m_freem(m);
	return;
}

/*
 * Reflect the ip packet back to the source
 */
void
icmp_reflect(struct mbuf *m)
{
	struct ip *ip = mtod(m, struct ip *);
	struct in_ifaddr *ia;
	struct ifaddr *ifa;
	struct sockaddr_in *sin = 0;
	struct in_addr t;
	struct mbuf *opts = 0;
	int optlen = (ip->ip_hl << 2) - sizeof(struct ip);
#ifdef QNX_MFIB
	int fib; 

	if (m->m_pkthdr.rcvif != NULL)
		fib = if_get_first_fib(m->m_pkthdr.rcvif); /* when i/f member of multiple fibs, just need to echo on 1 */
	else {
		struct m_tag	*mtag;
		if ((mtag = m_tag_find(m, PACKET_TAG_PF_MFIB, NULL)) == NULL)
			fib = -1;
		else
			fib = *(int *)(mtag + 1);
	}
#endif

	if (!in_canforward(ip->ip_src) &&
	    ((ip->ip_src.s_addr & IN_CLASSA_NET) !=
	     htonl(IN_LOOPBACKNET << IN_CLASSA_NSHIFT))) {
#ifdef __QNXNTO__
		ipstat.ips_badaddr++;
#endif
		m_freem(m);	/* Bad return address */
		goto done;	/* ip_output() will check for broadcast */
	}
	t = ip->ip_dst;
	ip->ip_dst = ip->ip_src;
	/*
	 * If the incoming packet was addressed directly to us, use
	 * dst as the src for the reply.  Otherwise (broadcast or
	 * anonymous), use an address which corresponds to the
	 * incoming interface, with a preference for the address which
	 * corresponds to the route to the destination of the ICMP.
	 */

	/* Look for packet addressed to us */
	INADDR_TO_IA(t, ia);

	/* look for packet sent to broadcast address */
	if (ia == NULL && m->m_pkthdr.rcvif &&
	    (m->m_pkthdr.rcvif->if_flags & IFF_BROADCAST)) {
		IFADDR_FOREACH(ifa, m->m_pkthdr.rcvif) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			if (in_hosteq(t,ifatoia(ifa)->ia_broadaddr.sin_addr)) {
				ia = ifatoia(ifa);
				break;
			}
		}
	}

	if (ia)
		sin = &ia->ia_addr;

	icmpdst.sin_addr = t;

	/*
	 * if the packet is addressed somewhere else, compute the
	 * source address for packets routed back to the source, and
	 * use that, if it's an address on the interface which
	 * received the packet
	 */
	if (sin == (struct sockaddr_in *)0 && m->m_pkthdr.rcvif) {
		struct sockaddr_in sin_dst;
		struct route icmproute;
		int errornum;

		sin_dst.sin_family = AF_INET;
		sin_dst.sin_len = sizeof(struct sockaddr_in);
		sin_dst.sin_addr = ip->ip_dst;
		bzero(&icmproute, sizeof(icmproute));
		errornum = 0;
		sin = in_selectsrc(&sin_dst, &icmproute, 0, NULL, &errornum);
		/* errornum is never used */
		if (icmproute.ro_rt)
			RTFREE(icmproute.ro_rt);
		/* check to make sure sin is a source address on rcvif */
		if (sin) {
			t = sin->sin_addr;
			sin = (struct sockaddr_in *)0;
			INADDR_TO_IA(t, ia);
			while (ia) {
				if (ia->ia_ifp == m->m_pkthdr.rcvif) {
					sin = &ia->ia_addr;
					break;
				}
				NEXT_IA_WITH_SAME_ADDR(ia);
			}
		}
	}

	/*
	 * if it was not addressed to us, but the route doesn't go out
	 * the source interface, pick an address on the source
	 * interface.  This can happen when routing is asymmetric, or
	 * when the incoming packet was encapsulated
	 */
	if (sin == (struct sockaddr_in *)0 && m->m_pkthdr.rcvif) {
		IFADDR_FOREACH(ifa, m->m_pkthdr.rcvif) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			sin = &(ifatoia(ifa)->ia_addr);
			break;
		}
	}

	/*
	 * The following happens if the packet was not addressed to us,
	 * and was received on an interface with no IP address:
	 * We find the first AF_INET address on the first non-loopback
	 * interface.
	 */
	if (sin == (struct sockaddr_in *)0)
		TAILQ_FOREACH(ia, &in_ifaddrhead, ia_list) {
			if (ia->ia_ifp->if_flags & IFF_LOOPBACK)
				continue;
			sin = &ia->ia_addr;
			break;
		}

	/*
	 * If we still didn't find an address, punt.  We could have an
	 * interface up (and receiving packets) with no address.
	 */
	if (sin == (struct sockaddr_in *)0) {
		m_freem(m);
		goto done;
	}

	ip->ip_src = sin->sin_addr;
	ip->ip_ttl = MAXTTL;

	if (optlen > 0) {
		u_char *cp;
		int opt, cnt;
		u_int len;

		/*
		 * Retrieve any source routing from the incoming packet;
		 * add on any record-route or timestamp options.
		 */
		cp = (u_char *) (ip + 1);
		if ((opts = ip_srcroute()) == 0 &&
		    (opts = m_gethdr(M_DONTWAIT, MT_HEADER))) {
			MCLAIM(opts, m->m_owner);
			opts->m_len = sizeof(struct in_addr);
			*mtod(opts, struct in_addr *) = zeroin_addr;
		}
		if (opts) {
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    printf("icmp_reflect optlen %d rt %d => ",
				optlen, opts->m_len);
#endif
		    for (cnt = optlen; cnt > 0; cnt -= len, cp += len) {
			    opt = cp[IPOPT_OPTVAL];
			    if (opt == IPOPT_EOL)
				    break;
			    if (opt == IPOPT_NOP)
				    len = 1;
			    else {
				    if (cnt < IPOPT_OLEN + sizeof(*cp))
					    break;
				    len = cp[IPOPT_OLEN];
				    if (len < IPOPT_OLEN + sizeof(*cp) ||
				        len > cnt)
					    break;
			    }
			    /*
			     * Should check for overflow, but it "can't happen"
			     */
			    if (opt == IPOPT_RR || opt == IPOPT_TS ||
				opt == IPOPT_SECURITY) {
				    bcopy((caddr_t)cp,
					mtod(opts, caddr_t) + opts->m_len, len);
				    opts->m_len += len;
			    }
		    }
		    /* Terminate & pad, if necessary */
		    if ((cnt = opts->m_len % 4) != 0) {
			    for (; cnt < 4; cnt++) {
				    *(mtod(opts, caddr_t) + opts->m_len) =
					IPOPT_EOL;
				    opts->m_len++;
			    }
		    }
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    printf("%d\n", opts->m_len);
#endif
		}
		/*
		 * Now strip out original options by copying rest of first
		 * mbuf's data back, and adjust the IP length.
		 */
		ip->ip_len = htons(ntohs(ip->ip_len) - optlen);
		ip->ip_hl = sizeof(struct ip) >> 2;
		m->m_len -= optlen;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= optlen;
		optlen += sizeof(struct ip);
		bcopy((caddr_t)ip + optlen, (caddr_t)(ip + 1),
			 (unsigned)(m->m_len - sizeof(struct ip)));
	}
	m_tag_delete_nonpersistent(m);
	m->m_flags &= ~(M_BCAST|M_MCAST);

	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.csum_flags = 0;

#ifndef QNX_MFIB
	icmp_send(m, opts);
#else
	icmp_send(m, opts, fib);
#endif
done:
	if (opts)
		(void)m_free(opts);
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
void
#ifndef QNX_MFIB
icmp_send(struct mbuf *m, struct mbuf *opts)
#else
icmp_send(struct mbuf *m, struct mbuf *opts, int fib)
#endif
{
	struct ip *ip = mtod(m, struct ip *);
	int hlen;
	struct icmp *icp;

	hlen = ip->ip_hl << 2;
	m->m_data += hlen;
	m->m_len -= hlen;
	icp = mtod(m, struct icmp *);
	icp->icmp_cksum = 0;
	icp->icmp_cksum = in_cksum(m, ntohs(ip->ip_len) - hlen);
	m->m_data -= hlen;
	m->m_len += hlen;
#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		printf("icmp_send to destination `%s' from `%s'\n",
		    inet_ntoa(ip->ip_dst), inet_ntoa(ip->ip_src));
	}
#endif
#ifndef QNX_MFIB
	(void) ip_output(m, opts, NULL, 0,
	    (struct ip_moptions *)NULL, (struct socket *)NULL);
#else
	(void) ip_output(m, fib, opts, NULL, 0,
	    (struct ip_moptions *)NULL, (struct socket *)NULL);
#endif
}

n_time
iptime(void)
{
	struct timeval atv;
	u_long t;

	microtime(&atv);
	t = (atv.tv_sec % (24*60*60)) * 1000 + atv.tv_usec / 1000;
	return (htonl(t));
}

/*
 * sysctl helper routine for net.inet.icmp.returndatabytes.  ensures
 * that the new value is in the correct range.
 */
static int
sysctl_net_inet_icmp_returndatabytes(SYSCTLFN_ARGS)
{
	int error, t;
	struct sysctlnode node;

	node = *rnode;
	node.sysctl_data = &t;
	t = icmpreturndatabytes;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	if (t < 8 || t > 512)
		return (EINVAL);
	icmpreturndatabytes = t;

	return (0);
}

/*
 * sysctl helper routine for net.inet.icmp.redirtimeout.  ensures that
 * the given value is not less than zero and then resets the timeout
 * queue.
 */
static int
sysctl_net_inet_icmp_redirtimeout(SYSCTLFN_ARGS)
{
	int error, tmp;
	struct sysctlnode node;

	node = *rnode;
	node.sysctl_data = &tmp;
	tmp = icmp_redirtimeout;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);
	if (tmp < 0)
		return (EINVAL);
	icmp_redirtimeout = tmp;

	/*
	 * was it a *defined* side-effect that anyone even *reading*
	 * this value causes these things to happen?
	 */
	if (icmp_redirect_timeout_q != NULL) {
		if (icmp_redirtimeout == 0) {
			rt_timer_queue_destroy(icmp_redirect_timeout_q,
			    TRUE);
			icmp_redirect_timeout_q = NULL;
		} else {
			rt_timer_queue_change(icmp_redirect_timeout_q,
			    icmp_redirtimeout);
		}
	} else if (icmp_redirtimeout > 0) {
		icmp_redirect_timeout_q =
		    rt_timer_queue_create(icmp_redirtimeout);
	}

	return (0);
}

SYSCTL_SETUP(sysctl_net_inet_icmp_setup, "sysctl net.inet.icmp subtree setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "inet", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "icmp",
		       SYSCTL_DESCR("ICMPv4 related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maskrepl",
		       SYSCTL_DESCR("Respond to ICMP_MASKREQ messages"),
		       NULL, 0, &icmpmaskrepl, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_MASKREPL, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "returndatabytes",
		       SYSCTL_DESCR("Number of bytes to return in an ICMP "
				    "error message"),
		       sysctl_net_inet_icmp_returndatabytes, 0,
		       &icmpreturndatabytes, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_RETURNDATABYTES, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "errppslimit",
		       SYSCTL_DESCR("Maximum number of outgoing ICMP error "
				    "messages per second"),
		       NULL, 0, &icmperrppslim, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_ERRPPSLIMIT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rediraccept",
		       SYSCTL_DESCR("Accept ICMP_REDIRECT messages"),
		       NULL, 0, &icmp_rediraccept, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_REDIRACCEPT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "redirtimeout",
		       SYSCTL_DESCR("Lifetime of ICMP_REDIRECT generated "
				    "routes"),
		       sysctl_net_inet_icmp_redirtimeout, 0,
		       &icmp_redirtimeout, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_REDIRTIMEOUT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("ICMP statistics"), 
		       NULL, 0, &icmpstat, sizeof(icmpstat),
		       CTL_NET, PF_INET, IPPROTO_ICMP, ICMPCTL_STATS,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
			CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
			CTLTYPE_INT, "bmcastecho",
			SYSCTL_DESCR("Respond to ICMP_ECHO or ICMP_TIMESTAMP "
				     "message to the broadcast or multicast"),
			NULL, 0, &icmpbmcastecho, 0,
			CTL_NET, PF_INET, IPPROTO_ICMP, ICMPCTL_BMCASTECHO,
			CTL_EOL);
#ifdef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "tstamprepl",
		       SYSCTL_DESCR("Respond to ICMP_TSTAMP messages"),
		       NULL, 0, &icmptstamprepl, 0,
		       CTL_NET, PF_INET, IPPROTO_ICMP,
		       ICMPCTL_TSTAMPREPL, CTL_EOL);
#endif
}

/* Table of common MTUs: */

static const u_int mtu_table[] = {
	65535, 65280, 32000, 17914, 9180, 8166,
	4352, 2002, 1492, 1006, 508, 296, 68, 0
};

void
#ifndef QNX_MFIB
icmp_mtudisc(struct icmp *icp, struct in_addr faddr)
#else
icmp_mtudisc(struct icmp *icp, struct in_addr faddr, int fib)
#endif
{
	struct icmp_mtudisc_callback *mc;
	struct sockaddr *dst = sintosa(&icmpsrc);
	struct rtentry *rt;
	u_long mtu = ntohs(icp->icmp_nextmtu);  /* Why a long?  IPv6 */
	int    error;

#ifndef QNX_MFIB
	rt = rtalloc1(dst, 1);
#else
	rt = rtalloc1(dst, 1, NULL, fib);
#endif
	if (rt == 0)
		return;

	/* If we didn't get a host route, allocate one */

	if ((rt->rt_flags & RTF_HOST) == 0) {
		struct rtentry *nrt;

#ifndef QNX_MFIB
		error = rtrequest((int) RTM_ADD, dst,
		    (struct sockaddr *) rt->rt_gateway,
		    (struct sockaddr *) 0,
		    RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC, &nrt);
#else
		error = rtrequest((int) RTM_ADD, dst,
		    (struct sockaddr *) rt->rt_gateway,
		    (struct sockaddr *) 0,
		    RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC, &nrt, fib);
#endif
		if (error) {
			rtfree(rt);
			return;
		}
		nrt->rt_rmx = rt->rt_rmx;
		rtfree(rt);
		rt = nrt;
	}
#ifndef QNX_MFIB
	error = rt_timer_add(rt, icmp_mtudisc_timeout, ip_mtudisc_timeout_q);
#else
	error = rt_timer_add(rt, icmp_mtudisc_timeout, ip_mtudisc_timeout_q[fib]);
#endif
	if (error) {
		rtfree(rt);
		return;
	}

	if (mtu == 0) {
		int i = 0;

		mtu = ntohs(icp->icmp_ip.ip_len);
		/* Some 4.2BSD-based routers incorrectly adjust the ip_len */
		if (mtu > rt->rt_rmx.rmx_mtu && rt->rt_rmx.rmx_mtu != 0)
			mtu -= (icp->icmp_ip.ip_hl << 2);

		/* If we still can't guess a value, try the route */

		if (mtu == 0) {
			mtu = rt->rt_rmx.rmx_mtu;

			/* If no route mtu, default to the interface mtu */

			if (mtu == 0)
				mtu = rt->rt_ifp->if_mtu;
		}

		for (i = 0; i < sizeof(mtu_table) / sizeof(mtu_table[0]); i++)
			if (mtu > mtu_table[i]) {
				mtu = mtu_table[i];
				break;
			}
	}

	/*
	 * XXX:   RTV_MTU is overloaded, since the admin can set it
	 *	  to turn off PMTU for a route, and the kernel can
	 *	  set it to indicate a serious problem with PMTU
	 *	  on a route.  We should be using a separate flag
	 *	  for the kernel to indicate this.
	 */

	if ((rt->rt_rmx.rmx_locks & RTV_MTU) == 0) {
		if (mtu < 296 || mtu > rt->rt_ifp->if_mtu)
			rt->rt_rmx.rmx_locks |= RTV_MTU;
		else if (rt->rt_rmx.rmx_mtu > mtu ||
			 rt->rt_rmx.rmx_mtu == 0) {
			icmpstat.icps_pmtuchg++;
			rt->rt_rmx.rmx_mtu = mtu;
		}
	}

	if (rt)
		rtfree(rt);

	/*
	 * Notify protocols that the MTU for this destination
	 * has changed.
	 */
	for (mc = LIST_FIRST(&icmp_mtudisc_callbacks); mc != NULL;
	     mc = LIST_NEXT(mc, mc_list))
		(*mc->mc_func)(faddr);
}

/*
 * Return the next larger or smaller MTU plateau (table from RFC 1191)
 * given current value MTU.  If DIR is less than zero, a larger plateau
 * is returned; otherwise, a smaller value is returned.
 */
u_int
ip_next_mtu(u_int mtu, int dir)	/* XXX */
{
	int i;

	for (i = 0; i < (sizeof mtu_table) / (sizeof mtu_table[0]); i++) {
		if (mtu >= mtu_table[i])
			break;
	}

	if (dir < 0) {
		if (i == 0) {
			return 0;
		} else {
			return mtu_table[i - 1];
		}
	} else {
		if (mtu_table[i] == 0) {
			return 0;
		} else if (mtu > mtu_table[i]) {
			return mtu_table[i];
		} else {
			return mtu_table[i + 1];
		}
	}
}

static void
icmp_mtudisc_timeout(struct rtentry *rt, struct rttimer *r)
{
	if (rt == NULL)
		panic("icmp_mtudisc_timeout:  bad route to timeout");
	if ((rt->rt_flags & (RTF_DYNAMIC | RTF_HOST)) ==
	    (RTF_DYNAMIC | RTF_HOST)) {
#ifndef QNX_MFIB
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
#else
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0, rt->fib);
#endif
	} else {
		if ((rt->rt_rmx.rmx_locks & RTV_MTU) == 0) {
			rt->rt_rmx.rmx_mtu = 0;
		}
	}
}

static void
icmp_redirect_timeout(struct rtentry *rt, struct rttimer *r)
{
	if (rt == NULL)
		panic("icmp_redirect_timeout:  bad route to timeout");
	if ((rt->rt_flags & (RTF_DYNAMIC | RTF_HOST)) ==
	    (RTF_DYNAMIC | RTF_HOST)) {
#ifndef QNX_MFIB
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
#else
		rtrequest((int) RTM_DELETE, (struct sockaddr *)rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0, rt->fib);
#endif
	}
}

/*
 * Perform rate limit check.
 * Returns 0 if it is okay to send the icmp packet.
 * Returns 1 if the router SHOULD NOT send this icmp packet due to rate
 * limitation.
 *
 * XXX per-destination/type check necessary?
 */
static int
icmp_ratelimit(const struct in_addr *dst, const int type,
    const int code)
{

	/* PPS limit */
	if (!ppsratecheck(&icmperrppslim_last, &icmperrpps_count,
	    icmperrppslim)) {
		/* The packet is subject to rate limit */
		return 1;
	}

	/* okay to send */
	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/ip_icmp.c $ $Rev: 800199 $")
#endif
