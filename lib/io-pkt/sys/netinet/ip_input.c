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



/*	$NetBSD: ip_input.c,v 1.303 2012/11/29 02:07:20 christos Exp $	*/

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
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Public Access Networks Corporation ("Panix").  It was developed under
 * contract to Panix by Eric Haszlakiewicz and Thor Lancelot Simon.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *	@(#)ip_input.c	8.2 (Berkeley) 1/4/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ip_input.c,v 1.303 2012/11/29 02:07:20 christos Exp $");

#include "opt_inet.h"
#include "opt_gateway.h"
#include "opt_pfil_hooks.h"
#include "opt_ipsec.h"
#include "opt_mrouting.h"
#include "opt_mbuftrace.h"
#include "opt_inet_csum.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/pool.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_proto.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
/* just for gif_ttl */
#include <netinet/in_gif.h>
#include "gif.h"
#include <net/if_gre.h>
#include "gre.h"

#ifdef MROUTING
#include <netinet/ip_mroute.h>
#endif
#include <netinet/portalgo.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/key.h>
#endif	/* FAST_IPSEC*/

#if defined(__QNXNTO__) &&			\
    (defined(IPSEC) || defined(FAST_IPSEC)) &&	\
    defined(PFIL_HOOKS)
extern int pfil_ipsec;
#endif

#ifndef	IPFORWARDING
#ifdef GATEWAY
#ifndef __QNXNTO__
#define	IPFORWARDING	1	/* forward IP packets not for us */
#else
#define	IPFORWARDING	0
#endif /* __QNXNTO__ */
#else /* GATEWAY */
#define	IPFORWARDING	0	/* don't forward IP packets not for us */
#endif /* GATEWAY */
#endif /* IPFORWARDING */
#ifndef	IPSENDREDIRECTS
#define	IPSENDREDIRECTS	1
#endif
#ifndef IPFORWSRCRT
#define	IPFORWSRCRT	0	/* don't forward source-routed packets */
#endif
#ifndef IPALLOWSRCRT
#define	IPALLOWSRCRT	0	/* don't allow source-routed packets */
#endif
#ifndef IPMTUDISC
#define IPMTUDISC	1
#endif
#ifndef IPMTUDISCTIMEOUT
#define IPMTUDISCTIMEOUT (10 * 60)	/* as per RFC 1191 */
#endif

/*
 * Note: DIRECTED_BROADCAST is handled this way so that previous
 * configuration using this option will Just Work.
 */
#ifndef IPDIRECTEDBCAST
#ifdef DIRECTED_BROADCAST
#define IPDIRECTEDBCAST	1
#else
#define	IPDIRECTEDBCAST	0
#endif /* DIRECTED_BROADCAST */
#endif /* IPDIRECTEDBCAST */
int	ipforwarding = IPFORWARDING;
#ifdef QNX_MFIB
int	ipforwarding_mfibmask = 0;
#endif
int	ipsendredirects = IPSENDREDIRECTS;
int	ip_defttl = IPDEFTTL;
int	ip_forwsrcrt = IPFORWSRCRT;
int	ip_directedbcast = IPDIRECTEDBCAST;
int	ip_allowsrcrt = IPALLOWSRCRT;
int	ip_mtudisc = IPMTUDISC;
int	ip_mtudisc_timeout = IPMTUDISCTIMEOUT;
#ifdef DIAGNOSTIC
int	ipprintfs = 0;
#endif

int	ip_do_randomid = 0;

/*
 * XXX - Setting ip_checkinterface mostly implements the receive side of
 * the Strong ES model described in RFC 1122, but since the routing table
 * and transmit implementation do not implement the Strong ES model,
 * setting this to 1 results in an odd hybrid.
 *
 * XXX - ip_checkinterface currently must be disabled if you use ipnat
 * to translate the destination address to another local interface.
 *
 * XXX - ip_checkinterface must be disabled if you add IP aliases
 * to the loopback interface instead of the interface where the
 * packets for those addresses are received.
 */
int	ip_checkinterface = 0;
#ifdef __QNXNTO__
/* The transmit implementation has been enhanced to support Strong ES model
 * together with "Sticky" sockets which stay on the interface they started 
 * their connection. Needs to have multi-path (multiple leaves) support in
 * routing table to work well as it needs routes to go out the interface
 * even though the best route may not go through the same interface any more.
 */
int	ip_bindinterface = 0;
#endif


#ifndef QNX_MFIB
struct rttimer_queue *ip_mtudisc_timeout_q = NULL;
#else
struct rttimer_queue *ip_mtudisc_timeout_q[FIBS_MAX];
#endif

int	ipqmaxlen = IFQ_MAXLEN;
u_long	in_ifaddrhash;				/* size of hash table - 1 */
int	in_ifaddrentries;			/* total number of addrs */
struct	in_ifaddrhashhead *in_ifaddrhashtbl;
struct in_ifaddrhead in_ifaddrhead;
u_long	in_multihash;				/* size of hash table - 1 */
int	in_multientries;			/* total number of addrs */
struct	in_multihashhead *in_multihashtbl;
struct	ifqueue ipintrq;
struct	ipstat	ipstat;
#ifdef __QNXNTO__
NLIST_EXPORT(ipintrq, ipintrq);
NLIST_EXPORT(ipstat, ipstat);
#endif
uint16_t ip_id;

#ifdef PFIL_HOOKS
struct pfil_head inet_pfil_hook;
#endif

/*
 * Cached copy of nmbclusters. If nbclusters is different,
 * recalculate IP parameters derived from nmbclusters.
 */
static int	ip_nmbclusters;			/* copy of nmbclusters */
static void	ip_nmbclusters_changed(void);	/* recalc limits */
#ifdef __QNXNTO__
static void	ip_intr(void *);
#endif

#define CHECK_NMBCLUSTER_PARAMS()				\
do {								\
	if (__predict_false(ip_nmbclusters != nmbclusters))	\
		ip_nmbclusters_changed();			\
} while (/*CONSTCOND*/0)

/* IP datagram reassembly queues (hashed) */
#define IPREASS_NHASH_LOG2      6
#define IPREASS_NHASH           (1 << IPREASS_NHASH_LOG2)
#define IPREASS_HMASK           (IPREASS_NHASH - 1)
#define IPREASS_HASH(x,y) \
	(((((x) & 0xF) | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPREASS_HMASK)
struct ipqhead ipq[IPREASS_NHASH];
int	ipq_locked;
static int	ip_nfragpackets;	/* packets in reass queue */
static int	ip_nfrags;		/* total fragments in reass queues */

int	ip_maxfragpackets = 200;	/* limit on packets. XXX sysctl */
int	ip_maxfrags;		        /* limit on fragments. XXX sysctl */


/*
 * Additive-Increase/Multiplicative-Decrease (AIMD) strategy for
 * IP reassembly queue buffer managment.
 *
 * We keep a count of total IP fragments (NB: not fragmented packets!)
 * awaiting reassembly (ip_nfrags) and a limit (ip_maxfrags) on fragments.
 * If ip_nfrags exceeds ip_maxfrags the limit, we drop half the
 * total fragments in  reassembly queues.This AIMD policy avoids
 * repeatedly deleting single packets under heavy fragmentation load
 * (e.g., from lossy NFS peers).
 */
static u_int	ip_reass_ttl_decr(u_int ticks);
static void	ip_reass_drophalf(void);


static inline int ipq_lock_try(void);
static inline void ipq_unlock(void);

static inline int
ipq_lock_try(void)
{
	int s;

	/*
	 * Use splvm() -- we're blocking things that would cause
	 * mbuf allocation.
	 */
	s = splvm();
	if (ipq_locked) {
		splx(s);
		return (0);
	}
	ipq_locked = 1;
	splx(s);
	return (1);
}

static inline void
ipq_unlock(void)
{
	int s;

	s = splvm();
	ipq_locked = 0;
	splx(s);
}

#ifdef DIAGNOSTIC
#define	IPQ_LOCK()							\
do {									\
	if (ipq_lock_try() == 0) {					\
		printf("%s:%d: ipq already locked\n", __FILE__, __LINE__); \
		panic("ipq_lock");					\
	}								\
} while (/*CONSTCOND*/ 0)
#define	IPQ_LOCK_CHECK()						\
do {									\
	if (ipq_locked == 0) {						\
		printf("%s:%d: ipq lock not held\n", __FILE__, __LINE__); \
		panic("ipq lock check");				\
	}								\
} while (/*CONSTCOND*/ 0)
#else
#define	IPQ_LOCK()		(void) ipq_lock_try()
#define	IPQ_LOCK_CHECK()	/* nothing */
#endif

#define	IPQ_UNLOCK()		ipq_unlock()

POOL_INIT(inmulti_pool, sizeof(struct in_multi), 0, 0, 0, "inmltpl", NULL);
POOL_INIT(ipqent_pool, sizeof(struct ipqent), 0, 0, 0, "ipqepl", NULL);

#ifdef INET_CSUM_COUNTERS
#include <sys/device.h>

struct evcnt ip_hwcsum_bad = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "inet", "hwcsum bad");
struct evcnt ip_hwcsum_ok = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "inet", "hwcsum ok");
struct evcnt ip_swcsum = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "inet", "swcsum");

#define	INET_CSUM_COUNTER_INCR(ev)	(ev)->ev_count++

EVCNT_ATTACH_STATIC(ip_hwcsum_bad);
EVCNT_ATTACH_STATIC(ip_hwcsum_ok);
EVCNT_ATTACH_STATIC(ip_swcsum);

#else

#define	INET_CSUM_COUNTER_INCR(ev)	/* nothing */

#endif /* INET_CSUM_COUNTERS */

/*
 * We need to save the IP options in case a protocol wants to respond
 * to an incoming packet over the same route if the packet got here
 * using IP source routing.  This allows connection establishment and
 * maintenance when the remote end is on a network that is not known
 * to us.
 */
int	ip_nhops = 0;
static	struct ip_srcrt {
	struct	in_addr dst;			/* final destination */
	char	nop;				/* one NOP to align */
	char	srcopt[IPOPT_OFFSET + 1];	/* OPTVAL, OLEN and OFFSET */
	struct	in_addr route[MAX_IPOPTLEN/sizeof(struct in_addr)];
} ip_srcrt;

static void save_rte(u_char *, struct in_addr);

#ifdef MBUFTRACE
struct mowner ip_rx_mowner = MOWNER_INIT("internet", "rx");
struct mowner ip_tx_mowner = MOWNER_INIT("internet", "tx");
#endif

/*
 * Compute IP limits derived from the value of nmbclusters.
 */
static void
ip_nmbclusters_changed(void)
{
	ip_maxfrags = nmbclusters / 4;
	ip_nmbclusters =  nmbclusters;
}

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init(void)
{
	const struct protosw *pr;
	int i;

	pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
	if (pr == 0)
		panic("ip_init");
	for (i = 0; i < IPPROTO_MAX; i++)
		ip_protox[i] = pr - inetsw;
	for (pr = inetdomain.dom_protosw;
	    pr < inetdomain.dom_protoswNPROTOSW; pr++)
		if (pr->pr_domain->dom_family == PF_INET &&
		    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW)
			ip_protox[pr->pr_protocol] = pr - inetsw;

	for (i = 0; i < IPREASS_NHASH; i++)
	    	LIST_INIT(&ipq[i]);

	ip_id = time_second & 0xfffff;
#ifdef __QNXNTO__
	ipintrq.ifq_intr = ip_intr;
	ipintrq.ifq_next = &ipintrq;
	ipintrq.ifq_prev = &ipintrq.ifq_next;
#endif

	ipintrq.ifq_maxlen = ipqmaxlen;
	ip_nmbclusters_changed();

	TAILQ_INIT(&in_ifaddrhead);
	in_ifaddrhashtbl = hashinit(IN_IFADDR_HASH_SIZE, HASH_LIST, M_IFADDR,
	    M_WAITOK, &in_ifaddrhash);
	in_multihashtbl = hashinit(IN_IFADDR_HASH_SIZE, HASH_LIST, M_IPMADDR,
	    M_WAITOK, &in_multihash);
#ifndef QNX_MFIB
	ip_mtudisc_timeout_q = rt_timer_queue_create(ip_mtudisc_timeout);
#else
	int fib;
	for (fib=0;fib<FIBS_MAX;fib++)
	{
		ip_mtudisc_timeout_q[fib] = rt_timer_queue_create(ip_mtudisc_timeout);
	}
#endif
#ifdef GATEWAY
	ipflow_init();
#endif

#ifdef PFIL_HOOKS
	/* Register our Packet Filter hook. */
	inet_pfil_hook.ph_type = PFIL_TYPE_AF;
	inet_pfil_hook.ph_af   = AF_INET;
	i = pfil_head_register(&inet_pfil_hook);
	if (i != 0)
		printf("ip_init: WARNING: unable to register pfil hook, "
		    "error %d\n", i);
#endif /* PFIL_HOOKS */

#ifdef MBUFTRACE
	MOWNER_ATTACH(&ip_tx_mowner);
	MOWNER_ATTACH(&ip_rx_mowner);
#endif /* MBUFTRACE */
}

struct	sockaddr_in ipaddr = {
	.sin_len = sizeof(ipaddr),
	.sin_family = AF_INET,
};
struct	route ipforward_rt;

#ifndef __QNXNTO__
/*
 * IP software interrupt routine
 */
void
ipintr(void)
{
	int s;
	struct mbuf *m;

	while (1) {
		s = splnet();
		IF_DEQUEUE(&ipintrq, m);
		splx(s);
		if (m == 0)
			return;
#ifdef __QNXNTO__
		/*
		 * Move MCLAIM() into ip_input() proper.
		 * Oh, it's there already...
		 */
#endif
		MCLAIM(m, &ip_rx_mowner);
		ip_input(m);
	}
}
#else
static void
ip_intr(void *arg)
{
	struct mbuf	*m;

	m = arg;
	ip_input(m);
}
#endif /* !__QNXNTO__ */

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
	struct ip *ip = NULL;
	struct ipq *fp;
	struct in_ifaddr *ia;
	struct ifaddr *ifa;
	struct ipqent *ipqe;
	int hlen = 0, mff, len;
	int downmatch;
	int checkif;
	int srcrt = 0;
	int s;
	u_int hash;
#ifdef FAST_IPSEC
	struct m_tag *mtag;
	struct tdb_ident *tdbi;
	struct secpolicy *sp;
	int error;
#endif /* FAST_IPSEC */

	MCLAIM(m, &ip_rx_mowner);
#ifdef	DIAGNOSTIC
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("ipintr no HDR");
#endif

	/*
	 * If no IP addresses have been set yet but the interfaces
	 * are receiving, can't do anything with incoming packets yet.
	 */
	if (TAILQ_FIRST(&in_ifaddrhead) == 0)
		goto bad;
	ipstat.ips_total++;
	/*
	 * If the IP header is not aligned, slurp it up into a new
	 * mbuf with space for link headers, in the event we forward
	 * it.  Otherwise, if it is aligned, make sure the entire
	 * base IP header is in the first mbuf of the chain.
	 */
	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		if ((m = m_copyup(m, sizeof(struct ip),
				  (max_linkhdr + 3) & ~3)) == NULL) {
			/* XXXJRT new stat, please */
			ipstat.ips_toosmall++;
			return;
		}
	} else if (__predict_false(m->m_len < sizeof (struct ip))) {
		if ((m = m_pullup(m, sizeof (struct ip))) == NULL) {
			ipstat.ips_toosmall++;
			return;
		}
	}
	ip = mtod(m, struct ip *);
	if (ip->ip_v != IPVERSION) {
		ipstat.ips_badvers++;
		goto bad;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		ipstat.ips_badhlen++;
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0) {
			ipstat.ips_badhlen++;
			return;
		}
		ip = mtod(m, struct ip *);
	}

	/*
	 * RFC1122: packets with a multicast source address are
	 * not allowed.
	 */
#ifdef __QNXNTO__
	/* RFC1122: packets with a limited broadcast source address are
	 * not allowed.
	 */
	if (IN_MULTICAST(ip->ip_src.s_addr) ||
		ip->ip_src.s_addr == INADDR_BROADCAST) {
#else
	if (IN_MULTICAST(ip->ip_src.s_addr)) {
#endif
		ipstat.ips_badaddr++;
		goto bad;
	}

	/* 127/8 must not appear on wire - RFC1122 */
	if ((ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    (ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0) {
			ipstat.ips_badaddr++;
			goto bad;
		}
	}

	switch (m->m_pkthdr.csum_flags &
		((m->m_pkthdr.rcvif->if_csum_flags_rx & M_CSUM_IPv4) |
		 M_CSUM_IPv4_BAD)) {
	case M_CSUM_IPv4|M_CSUM_IPv4_BAD:
		INET_CSUM_COUNTER_INCR(&ip_hwcsum_bad);
		goto badcsum;

	case M_CSUM_IPv4:
		/* Checksum was okay. */
		INET_CSUM_COUNTER_INCR(&ip_hwcsum_ok);
		break;

	default:
		/*
		 * Must compute it ourselves.  Maybe skip checksum on
		 * loopback interfaces.
		 */
		if (__predict_true(!(m->m_pkthdr.rcvif->if_flags &
				     IFF_LOOPBACK) || ip_do_loopback_cksum)) {
			INET_CSUM_COUNTER_INCR(&ip_swcsum);
			if (in_cksum(m, hlen) != 0)
				goto badcsum;
		}
		break;
	}

	/* Retrieve the packet length. */
	len = ntohs(ip->ip_len);

	/*
	 * Check for additional length bogosity
	 */
	if (len < hlen) {
	 	ipstat.ips_badlen++;
		goto bad;
	}

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len < len) {
		ipstat.ips_tooshort++;
		goto bad;
	}
	if (m->m_pkthdr.len > len) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = len;
			m->m_pkthdr.len = len;
		} else
			m_adj(m, len - m->m_pkthdr.len);
	}

#if defined(IPSEC)
	/* ipflow (IP fast forwarding) is not compatible with IPsec. */
#ifndef __QNXNTO__
	m->m_flags &= ~M_CANFASTFWD;
#else
	if (QNXNTO_IPSEC_ENABLED)
		m->m_flags &= ~M_CANFASTFWD;
	else
		m->m_flags |= M_CANFASTFWD;
#endif
#else
	/*
	 * Assume that we can create a fast-forward IP flow entry
	 * based on this packet.
	 */
	m->m_flags |= M_CANFASTFWD;
#endif

#ifdef PFIL_HOOKS
	/*
	 * Run through list of hooks for input packets.  If there are any
	 * filters which require that additional packets in the flow are
	 * not fast-forwarded, they must clear the M_CANFASTFWD flag.
	 * Note that filters must _never_ set this flag, as another filter
	 * in the list may have previously cleared it.
	 */
	/*
	 * let ipfilter look at packet on the wire,
	 * not the decapsulated packet.
	 */
#ifdef IPSEC
  #ifndef __QNXNTO__
	if (!ipsec_getnhist(m))
  #else
	if (!QNXNTO_IPSEC_ENABLED || pfil_ipsec || !ipsec_getnhist(m))
  #endif
#elif defined(FAST_IPSEC)
  #ifndef __QNXNTO__
	if (!ipsec_indone(m))
  #else

#define IPSEC_PROTO(p)	((p == IPPROTO_IPV4)	|| \
			 (p == IPPROTO_IPV6)	|| \
			 (p == IPPROTO_ESP)	|| \
			 (p == IPPROTO_AH)	|| \
			 (p == IPPROTO_IPCOMP))

	if (pfil_ipsec && (m->m_flags & M_DECRYPTENCAP) &&
	    !IPSEC_PROTO(ip->ip_p)) {
	    /* All the IPSec encapsulation is finally stripped */
	    m->m_flags &= ~ M_DECRYPTENCAP;
	}

	if (!QNXNTO_IPSEC_ENABLED || !ipsec_indone(m) ||
	    (pfil_ipsec && !(m->m_flags & M_DECRYPTENCAP)))
  #endif
#else
	if (1)
#endif
	{
		struct in_addr odst;

		odst = ip->ip_dst;
#ifdef QNX_MFIB
		/*
		 * XX MFIB: how do we decide which set of fibs to enforce PF rules on? For now choose first fib.
		 * Future? enhance PF to have "common rx rules" and "post-fib assoc rx rules"
		 */
#endif
		if (pfil_run_hooks(&inet_pfil_hook, &m, m->m_pkthdr.rcvif,
#ifndef QNX_MFIB
		    PFIL_IN) != 0)
#else
		    PFIL_IN, if_get_first_fib(m->m_pkthdr.rcvif)) != 0)
#endif
			return;
		if (m == NULL)
			return;
#ifdef __QNXNTO__
#ifdef FAST_IPSEC
		/* 
		 * pfil has seen it once, don't send it again until all
		 * IPSec encapsulation has been stripped from it.
		 */
		m->m_flags |= M_DECRYPTENCAP;
#endif
#endif
		ip = mtod(m, struct ip *);
		hlen = ip->ip_hl << 2;
		/*
		 * XXX The setting of "srcrt" here is to prevent ip_forward()
		 * from generating ICMP redirects for packets that have
		 * been redirected by a hook back out on to the same LAN that
		 * they came from and is not an indication that the packet
		 * is being inffluenced by source routing options.  This
		 * allows things like
		 * "rdr tlp0 0/0 port 80 -> 1.1.1.200 3128 tcp"
		 * where tlp0 is both on the 1.1.1.0/24 network and is the
		 * default route for hosts on 1.1.1.0/24.  Of course this
		 * also requires a "map tlp0 ..." to complete the story.
		 * One might argue whether or not this kind of network config.
		 * should be supported in this manner...
		 */
		srcrt = (odst.s_addr != ip->ip_dst.s_addr);
	}
#ifdef __QNXNTO__
#ifdef FAST_IPSEC
	/* IPv6 in an IPv4 tunnel, clear the flag so ipv6_input calls pf */
	if (pfil_ipsec && (ip->ip_p == IPPROTO_IPV6)) {
	    m->m_flags &= ~ M_DECRYPTENCAP;
	}
#endif
#endif
#endif /* PFIL_HOOKS */

#ifdef ALTQ
	/* XXX Temporary until ALTQ is changed to use a pfil hook */
	if (altq_input != NULL && (*altq_input)(m, AF_INET) == 0) {
		/* packet dropped by traffic conditioner */
		return;
	}
#endif

	/*
	 * Process options and, if not destined for us,
	 * ship it on.  ip_dooptions returns 1 when an
	 * error was detected (causing an icmp message
	 * to be sent and the original packet to be freed).
	 */
	ip_nhops = 0;		/* for source routed packets */
	if (hlen > sizeof (struct ip) && ip_dooptions(m))
		return;

	/*
	 * Enable a consistency check between the destination address
	 * and the arrival interface for a unicast packet (the RFC 1122
	 * strong ES model) if IP forwarding is disabled and the packet
	 * is not locally generated.
	 *
	 * XXX - Checking also should be disabled if the destination
	 * address is ipnat'ed to a different interface.
	 *
	 * XXX - Checking is incompatible with IP aliases added
	 * to the loopback interface instead of the interface where
	 * the packets are received.
	 *
	 * XXX - We need to add a per ifaddr flag for this so that
	 * we get finer grain control.
	 */
	checkif = ip_checkinterface && (ipforwarding == 0) &&
	    (m->m_pkthdr.rcvif != NULL) &&
#ifdef QNX_MFIB
		(ipforwarding_mfibmask & m->m_pkthdr.rcvif->if_fibmask) == 0 &&
#endif
#ifdef __QNXNTO__
		/* Bypass the check if we've done IPsec processing, the security policy
		 * processing will take place later to ensure it isn't bypassed
		 */
		(m->m_flags & (M_DECRYPTED|M_AUTHIPHDR|M_AUTHIPDGM)) == 0 &&
#endif
	    ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0);

	/*
	 * Check our list of addresses, to see if the packet is for us.
	 *
	 * Traditional 4.4BSD did not consult IFF_UP at all.
	 * The behavior here is to treat addresses on !IFF_UP interface
	 * as not mine.
	 */
	downmatch = 0;
	LIST_FOREACH(ia, &IN_IFADDR_HASH(ip->ip_dst.s_addr), ia_hash) {
		if (in_hosteq(ia->ia_addr.sin_addr, ip->ip_dst)) {
			if (checkif && ia->ia_ifp != m->m_pkthdr.rcvif)
				continue;
			if ((ia->ia_ifp->if_flags & IFF_UP) != 0)
				break;
			else
				downmatch++;
		}
	}
	if (ia != NULL)
		goto ours;
	if (m->m_pkthdr.rcvif && m->m_pkthdr.rcvif->if_flags & IFF_BROADCAST) {
		IFADDR_FOREACH(ifa, m->m_pkthdr.rcvif) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			ia = ifatoia(ifa);
			if (in_hosteq(ip->ip_dst, ia->ia_broadaddr.sin_addr) ||
			    in_hosteq(ip->ip_dst, ia->ia_netbroadcast) ||
			    /*
			     * Look for all-0's host part (old broadcast addr),
			     * either for subnet or net.
			     */
			    ip->ip_dst.s_addr == ia->ia_subnet ||
			    ip->ip_dst.s_addr == ia->ia_net)
				goto ours;
			/*
			 * An interface with IP address zero accepts
			 * all packets that arrive on that interface.
			 */
			if (in_nullhost(ia->ia_addr.sin_addr))
				goto ours;
		}
	}
	if (IN_MULTICAST(ip->ip_dst.s_addr)) {
		struct in_multi *inm;
#ifdef MROUTING
		extern struct socket *ip_mrouter;

		if (ip_mrouter) {
			/*
			 * If we are acting as a multicast router, all
			 * incoming multicast packets are passed to the
			 * kernel-level multicast forwarding function.
			 * The packet is returned (relatively) intact; if
			 * ip_mforward() returns a non-zero value, the packet
			 * must be discarded, else it may be accepted below.
			 *
			 * (The IP ident field is put in the same byte order
			 * as expected when ip_mforward() is called from
			 * ip_output().)
			 */
			if (ip_mforward(m, m->m_pkthdr.rcvif) != 0) {
				ipstat.ips_cantforward++;
				m_freem(m);
				return;
			}

			/*
			 * The process-level routing demon needs to receive
			 * all multicast IGMP packets, whether or not this
			 * host belongs to their destination groups.
			 */
			if (ip->ip_p == IPPROTO_IGMP)
				goto ours;
			ipstat.ips_forward++;
		}
#endif
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		IN_LOOKUP_MULTI(ip->ip_dst, m->m_pkthdr.rcvif, inm);
		if (inm == NULL) {
			ipstat.ips_cantforward++;
			m_freem(m);
			return;
		}
		goto ours;
	}
	if (ip->ip_dst.s_addr == INADDR_BROADCAST ||
	    in_nullhost(ip->ip_dst))
		goto ours;

	/*
	 * Not for us; forward if possible and desirable.
	 */
	if (ipforwarding == 0
#ifdef QNX_MFIB
		&& ((m->m_pkthdr.rcvif == NULL) || (ipforwarding_mfibmask & m->m_pkthdr.rcvif->if_fibmask) == 0)
#endif
		) {
		ipstat.ips_cantforward++;
		m_freem(m);
	} else {
		/*
		 * If ip_dst matched any of my address on !IFF_UP interface,
		 * and there's no IFF_UP interface that matches ip_dst,
		 * send icmp unreach.  Forwarding it will result in in-kernel
		 * forwarding loop till TTL goes to 0.
		 */
		if (downmatch) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0, 0);
			ipstat.ips_cantforward++;
			return;
		}
#ifdef IPSEC
if (QNXNTO_IPSEC_ENABLED) {
		if (ipsec4_in_reject(m, NULL)) {
			ipsecstat.in_polvio++;
			goto bad;
		}
}
#endif
#ifdef FAST_IPSEC
if (QNXNTO_IPSEC_ENABLED) {
		mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL);
		s = splsoftnet();
		if (mtag != NULL) {
			tdbi = (struct tdb_ident *)(mtag + 1);
			sp = ipsec_getpolicy(tdbi, IPSEC_DIR_INBOUND
#ifdef __QNXNTO__
					, m->m_pkthdr.rcvif
#endif
					);
		} else {
			sp = ipsec_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error
#ifdef __QNXNTO__
					, m->m_pkthdr.rcvif
#endif
					);
		}
		if (sp == NULL) {	/* NB: can happen if error */
			splx(s);
			/*XXX error stat???*/
			DPRINTF(("ip_input: no SP for forwarding\n"));	/*XXX*/
			goto bad;
		}

		/*
		 * Check security policy against packet attributes.
		 */
		error = ipsec_in_reject(sp, m);
		KEY_FREESP(&sp);
		splx(s);
		if (error) {
			ipstat.ips_cantforward++;
			goto bad;
		}

		/*
		 * Peek at the outbound SP for this packet to determine if
		 * it's a Fast Forward candidate.
		 */
		mtag = m_tag_find(m, PACKET_TAG_IPSEC_PENDING_TDB, NULL);
		if (mtag != NULL)
			m->m_flags &= ~M_CANFASTFWD;
		else {
			s = splsoftnet();
			sp = ipsec4_checkpolicy(m, IPSEC_DIR_OUTBOUND,
			    (IP_FORWARDING |
			     (ip_directedbcast ? IP_ALLOWBROADCAST : 0)),
			     &error, NULL
#ifdef __QNXNTO__
			     , m->m_pkthdr.rcvif
#endif
			     );
			if (sp != NULL) {
				m->m_flags &= ~M_CANFASTFWD;
				KEY_FREESP(&sp);
			}
			splx(s);
		}
}
#endif	/* FAST_IPSEC */

		ip_forward(m, srcrt);
	}
	return;

ours:
	/*
	 * If offset or IP_MF are set, must reassemble.
	 * Otherwise, nothing need be done.
	 * (We could look in the reassembly queue to see
	 * if the packet was previously fragmented,
	 * but it's not worth the time; just let them time out.)
	 */
	if (ip->ip_off & ~htons(IP_DF|IP_RF)) {

		/*
		 * Look for queue of fragments
		 * of this datagram.
		 */
		IPQ_LOCK();
		hash = IPREASS_HASH(ip->ip_src.s_addr, ip->ip_id);
		/* XXX LIST_FOREACH(fp, &ipq[hash], ipq_q) */
		for (fp = LIST_FIRST(&ipq[hash]); fp != NULL;
		     fp = LIST_NEXT(fp, ipq_q)) {
			if (ip->ip_id == fp->ipq_id &&
			    in_hosteq(ip->ip_src, fp->ipq_src) &&
			    in_hosteq(ip->ip_dst, fp->ipq_dst) &&
			    ip->ip_p == fp->ipq_p)
				goto found;

		}
		fp = 0;
found:

		/*
		 * Adjust ip_len to not reflect header,
		 * set ipqe_mff if more fragments are expected,
		 * convert offset of this to bytes.
		 */
		ip->ip_len = htons(ntohs(ip->ip_len) - hlen);
		mff = (ip->ip_off & htons(IP_MF)) != 0;
		if (mff) {
		        /*
		         * Make sure that fragments have a data length
			 * that's a non-zero multiple of 8 bytes.
		         */
			if (ntohs(ip->ip_len) == 0 ||
			    (ntohs(ip->ip_len) & 0x7) != 0) {
				ipstat.ips_badfrags++;
				IPQ_UNLOCK();
				goto bad;
			}
		}
		ip->ip_off = htons((ntohs(ip->ip_off) & IP_OFFMASK) << 3);

		/*
		 * If datagram marked as having more fragments
		 * or if this is not the first fragment,
		 * attempt reassembly; if it succeeds, proceed.
		 */
		if (mff || ip->ip_off != htons(0)) {
			ipstat.ips_fragments++;
			s = splvm();
			ipqe = pool_get(&ipqent_pool, PR_NOWAIT);
			splx(s);
			if (ipqe == NULL) {
				ipstat.ips_rcvmemdrop++;
				IPQ_UNLOCK();
				goto bad;
			}
			ipqe->ipqe_mff = mff;
			ipqe->ipqe_m = m;
			ipqe->ipqe_ip = ip;
			m = ip_reass(ipqe, fp, &ipq[hash]);
			if (m == 0) {
				IPQ_UNLOCK();
				return;
			}
			ipstat.ips_reassembled++;
			ip = mtod(m, struct ip *);
			hlen = ip->ip_hl << 2;
			ip->ip_len = htons(ntohs(ip->ip_len) + hlen);
		} else
			if (fp)
				ip_freef(fp);
		IPQ_UNLOCK();
	}

#if defined(IPSEC)
if (QNXNTO_IPSEC_ENABLED) {
	/*
	 * enforce IPsec policy checking if we are seeing last header.
	 * note that we do not visit this with protocols with pcb layer
	 * code - like udp/tcp/raw ip.
	 */
	if ((inetsw[ip_protox[ip->ip_p]].pr_flags & PR_LASTHDR) != 0 &&
	    ipsec4_in_reject(m, NULL)) {
		ipsecstat.in_polvio++;
		goto bad;
	}
}
#endif
#ifdef FAST_IPSEC
if (QNXNTO_IPSEC_ENABLED) {
	/*
	 * enforce IPsec policy checking if we are seeing last header.
	 * note that we do not visit this with protocols with pcb layer
	 * code - like udp/tcp/raw ip.
	 */
	if ((inetsw[ip_protox[ip->ip_p]].pr_flags & PR_LASTHDR) != 0) {
		/*
		 * Check if the packet has already had IPsec processing
		 * done.  If so, then just pass it along.  This tag gets
		 * set during AH, ESP, etc. input handling, before the
		 * packet is returned to the ip input queue for delivery.
		 */
		mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL);
		s = splsoftnet();
		if (mtag != NULL) {
			tdbi = (struct tdb_ident *)(mtag + 1);
			sp = ipsec_getpolicy(tdbi, IPSEC_DIR_INBOUND
#ifdef __QNXNTO__
					, m->m_pkthdr.rcvif
#endif
					);
		} else {
			sp = ipsec_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error
#ifdef __QNXNTO__
					, m->m_pkthdr.rcvif
#endif
					);
		}
		if (sp != NULL) {
			/*
			 * Check security policy against packet attributes.
			 */
			error = ipsec_in_reject(sp, m);
			KEY_FREESP(&sp);
		} else {
			/* XXX error stat??? */
			error = EINVAL;
DPRINTF(("ip_input: no SP, packet discarded\n"));/*XXX*/
		}
		splx(s);
		if (error)
			goto bad;
	}
}
#endif /* FAST_IPSEC */

	/*
	 * Switch out to protocol's input routine.
	 */
#if IFA_STATS
	if (ia && ip)
		ia->ia_ifa.ifa_data.ifad_inbytes += ntohs(ip->ip_len);
#endif
	ipstat.ips_delivered++;
    {
	int off = hlen, nh = ip->ip_p;

	(*inetsw[ip_protox[nh]].pr_input)(m, off, nh);
	return;
    }
bad:
	m_freem(m);
	return;

badcsum:
	ipstat.ips_badsum++;
	m_freem(m);
}

/*
 * Take incoming datagram fragment and try to
 * reassemble it into whole datagram.  If a chain for
 * reassembly of this datagram already exists, then it
 * is given as fp; otherwise have to make a chain.
 */
struct mbuf *
ip_reass(struct ipqent *ipqe, struct ipq *fp, struct ipqhead *ipqhead)
{
	struct mbuf *m = ipqe->ipqe_m;
	struct ipqent *nq, *p, *q;
	struct ip *ip;
	struct mbuf *t;
	int hlen = ipqe->ipqe_ip->ip_hl << 2;
	int i, next, s;

	IPQ_LOCK_CHECK();

	/*
	 * Presence of header sizes in mbufs
	 * would confuse code below.
	 */
	m->m_data += hlen;
	m->m_len -= hlen;

#ifdef	notyet
	/* make sure fragment limit is up-to-date */
	CHECK_NMBCLUSTER_PARAMS();

	/* If we have too many fragments, drop the older half. */
	if (ip_nfrags >= ip_maxfrags)
		ip_reass_drophalf(void);
#endif

	/*
	 * We are about to add a fragment; increment frag count.
	 */
	ip_nfrags++;
#ifdef __QNXNTO__
	pfslowtimo_kick();
#endif

	/*
	 * If first fragment to arrive, create a reassembly queue.
	 */
	if (fp == 0) {
		/*
		 * Enforce upper bound on number of fragmented packets
		 * for which we attempt reassembly;
		 * If maxfrag is 0, never accept fragments.
		 * If maxfrag is -1, accept all fragments without limitation.
		 */
		if (ip_maxfragpackets < 0)
			;
		else if (ip_nfragpackets >= ip_maxfragpackets)
			goto dropfrag;
		ip_nfragpackets++;
		MALLOC(fp, struct ipq *, sizeof (struct ipq),
		    M_FTABLE, M_NOWAIT);
		if (fp == NULL)
			goto dropfrag;
		LIST_INSERT_HEAD(ipqhead, fp, ipq_q);
		fp->ipq_nfrags = 1;
		fp->ipq_ttl = IPFRAGTTL;
		fp->ipq_p = ipqe->ipqe_ip->ip_p;
		fp->ipq_id = ipqe->ipqe_ip->ip_id;
		TAILQ_INIT(&fp->ipq_fragq);
		fp->ipq_src = ipqe->ipqe_ip->ip_src;
		fp->ipq_dst = ipqe->ipqe_ip->ip_dst;
		p = NULL;
		goto insert;
	} else {
		fp->ipq_nfrags++;
	}

	/*
	 * Find a segment which begins after this one does.
	 */
	for (p = NULL, q = TAILQ_FIRST(&fp->ipq_fragq); q != NULL;
	    p = q, q = TAILQ_NEXT(q, ipqe_q))
		if (ntohs(q->ipqe_ip->ip_off) > ntohs(ipqe->ipqe_ip->ip_off))
			break;

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if (p != NULL) {
		i = ntohs(p->ipqe_ip->ip_off) + ntohs(p->ipqe_ip->ip_len) -
		    ntohs(ipqe->ipqe_ip->ip_off);
		if (i > 0) {
			if (i >= ntohs(ipqe->ipqe_ip->ip_len))
				goto dropfrag;
			m_adj(ipqe->ipqe_m, i);
			ipqe->ipqe_ip->ip_off =
			    htons(ntohs(ipqe->ipqe_ip->ip_off) + i);
			ipqe->ipqe_ip->ip_len =
			    htons(ntohs(ipqe->ipqe_ip->ip_len) - i);
		}
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	for (; q != NULL &&
	    ntohs(ipqe->ipqe_ip->ip_off) + ntohs(ipqe->ipqe_ip->ip_len) >
	    ntohs(q->ipqe_ip->ip_off); q = nq) {
		i = (ntohs(ipqe->ipqe_ip->ip_off) +
		    ntohs(ipqe->ipqe_ip->ip_len)) - ntohs(q->ipqe_ip->ip_off);
		if (i < ntohs(q->ipqe_ip->ip_len)) {
			q->ipqe_ip->ip_len =
			    htons(ntohs(q->ipqe_ip->ip_len) - i);
			q->ipqe_ip->ip_off =
			    htons(ntohs(q->ipqe_ip->ip_off) + i);
			m_adj(q->ipqe_m, i);
			break;
		}
		nq = TAILQ_NEXT(q, ipqe_q);
		m_freem(q->ipqe_m);
		TAILQ_REMOVE(&fp->ipq_fragq, q, ipqe_q);
		s = splvm();
		pool_put(&ipqent_pool, q);
		splx(s);
		fp->ipq_nfrags--;
		ip_nfrags--;
	}

insert:
	/*
	 * Stick new segment in its place;
	 * check for complete reassembly.
	 */
	if (p == NULL) {
		TAILQ_INSERT_HEAD(&fp->ipq_fragq, ipqe, ipqe_q);
	} else {
		TAILQ_INSERT_AFTER(&fp->ipq_fragq, p, ipqe, ipqe_q);
	}
	next = 0;
	for (p = NULL, q = TAILQ_FIRST(&fp->ipq_fragq); q != NULL;
	    p = q, q = TAILQ_NEXT(q, ipqe_q)) {
		if (ntohs(q->ipqe_ip->ip_off) != next)
			return (0);
		next += ntohs(q->ipqe_ip->ip_len);
	}
	if (p->ipqe_mff)
		return (0);

	/*
	 * Reassembly is complete.  Check for a bogus message size and
	 * concatenate fragments.
	 */
	q = TAILQ_FIRST(&fp->ipq_fragq);
	ip = q->ipqe_ip;
	if ((next + (ip->ip_hl << 2)) > IP_MAXPACKET) {
		ipstat.ips_toolong++;
		ip_freef(fp);
		return (0);
	}
	m = q->ipqe_m;
	t = m->m_next;
	m->m_next = 0;
	m_cat(m, t);
	nq = TAILQ_NEXT(q, ipqe_q);
	s = splvm();
	pool_put(&ipqent_pool, q);
	splx(s);
	for (q = nq; q != NULL; q = nq) {
		t = q->ipqe_m;
		nq = TAILQ_NEXT(q, ipqe_q);
		s = splvm();
		pool_put(&ipqent_pool, q);
		splx(s);
		m_cat(m, t);
	}
	ip_nfrags -= fp->ipq_nfrags;

	/*
	 * Create header for new ip packet by
	 * modifying header of first packet;
	 * dequeue and discard fragment reassembly header.
	 * Make header visible.
	 */
	ip->ip_len = htons(next);
	ip->ip_src = fp->ipq_src;
	ip->ip_dst = fp->ipq_dst;
	LIST_REMOVE(fp, ipq_q);
	FREE(fp, M_FTABLE);
	ip_nfragpackets--;
	m->m_len += (ip->ip_hl << 2);
	m->m_data -= (ip->ip_hl << 2);
	/* some debugging cruft by sklower, below, will go away soon */
	if (m->m_flags & M_PKTHDR) { /* XXX this should be done elsewhere */
		int plen = 0;
		for (t = m; t; t = t->m_next)
			plen += t->m_len;
		m->m_pkthdr.len = plen;
		m->m_pkthdr.csum_flags = 0;
	}
	return (m);

dropfrag:
	if (fp != 0)
		fp->ipq_nfrags--;
	ip_nfrags--;
	ipstat.ips_fragdropped++;
	m_freem(m);
	s = splvm();
	pool_put(&ipqent_pool, ipqe);
	splx(s);
	return (0);
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
ip_freef(struct ipq *fp)
{
	struct ipqent *q, *p;
	u_int nfrags = 0;
	int s;

	IPQ_LOCK_CHECK();

	for (q = TAILQ_FIRST(&fp->ipq_fragq); q != NULL; q = p) {
		p = TAILQ_NEXT(q, ipqe_q);
		m_freem(q->ipqe_m);
		nfrags++;
		TAILQ_REMOVE(&fp->ipq_fragq, q, ipqe_q);
		s = splvm();
		pool_put(&ipqent_pool, q);
		splx(s);
	}

	if (nfrags != fp->ipq_nfrags)
	    printf("ip_freef: nfrags %d != %d\n", fp->ipq_nfrags, nfrags);
	ip_nfrags -= nfrags;
	LIST_REMOVE(fp, ipq_q);
	FREE(fp, M_FTABLE);
	ip_nfragpackets--;
}

/*
 * IP reassembly TTL machinery for  multiplicative drop.
 */
static u_int	fragttl_histo[(IPFRAGTTL+1)];


/*
 * Decrement TTL of all reasembly queue entries by `ticks'.
 * Count number of distinct fragments (as opposed to partial, fragmented
 * datagrams) in the reassembly queue.  While we  traverse the entire
 * reassembly queue, compute and return the median TTL over all fragments.
 */
static u_int
ip_reass_ttl_decr(u_int ticks)
{
	u_int nfrags, median, dropfraction, keepfraction;
	struct ipq *fp, *nfp;
	int i;

	nfrags = 0;
	memset(fragttl_histo, 0, sizeof fragttl_histo);

	for (i = 0; i < IPREASS_NHASH; i++) {
		for (fp = LIST_FIRST(&ipq[i]); fp != NULL; fp = nfp) {
			fp->ipq_ttl = ((fp->ipq_ttl  <= ticks) ?
				       0 : fp->ipq_ttl - ticks);
			nfp = LIST_NEXT(fp, ipq_q);
			if (fp->ipq_ttl == 0) {
				ipstat.ips_fragtimeout++;
				ip_freef(fp);
			} else {
				nfrags += fp->ipq_nfrags;
				fragttl_histo[fp->ipq_ttl] += fp->ipq_nfrags;
			}
		}
	}

	KASSERT(ip_nfrags == nfrags);

	/* Find median (or other drop fraction) in histogram. */
	dropfraction = (ip_nfrags / 2);
	keepfraction = ip_nfrags - dropfraction;
	for (i = IPFRAGTTL, median = 0; i >= 0; i--) {
		median +=  fragttl_histo[i];
		if (median >= keepfraction)
			break;
	}

	/* Return TTL of median (or other fraction). */
	return (u_int)i;
}

void
ip_reass_drophalf(void)
{

	u_int median_ticks;
	/*
	 * Compute median TTL of all fragments, and count frags
	 * with that TTL or lower (roughly half of all fragments).
	 */
	median_ticks = ip_reass_ttl_decr(0);

	/* Drop half. */
	median_ticks = ip_reass_ttl_decr(median_ticks);

}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
#ifndef __QNXNTO__
void
#else
int
#endif
ip_slowtimo(void)
{
	static u_int dropscanidx = 0;
	u_int i;
	u_int median_ttl;
	int s = splsoftnet();
#ifdef __QNXNTO__
	int ret;
#endif

	IPQ_LOCK();

	/* Age TTL of all fragments by 1 tick .*/
	median_ttl = ip_reass_ttl_decr(1);

	/* make sure fragment limit is up-to-date */
	CHECK_NMBCLUSTER_PARAMS();

	/* If we have too many fragments, drop the older half. */
	if (ip_nfrags > ip_maxfrags)
		ip_reass_ttl_decr(median_ttl);

	/*
	 * If we are over the maximum number of fragmented packets
	 * (due to the limit being lowered), drain off
	 * enough to get down to the new limit. Start draining
	 * from the reassembly hashqueue most recently drained.
	 */
	if (ip_maxfragpackets < 0)
		;
	else {
		int wrapped = 0;

		i = dropscanidx;
		while (ip_nfragpackets > ip_maxfragpackets && wrapped == 0) {
			while (LIST_FIRST(&ipq[i]) != NULL)
				ip_freef(LIST_FIRST(&ipq[i]));
			if (++i >= IPREASS_NHASH) {
				i = 0;
			}
			/*
			 * Dont scan forever even if fragment counters are
			 * wrong: stop after scanning entire reassembly queue.
			 */
			if (i == dropscanidx)
			    wrapped = 1;
		}
		dropscanidx = i;
	}
#ifdef __QNXNTO__
	ret = ip_nfrags;
#endif
	IPQ_UNLOCK();
#ifdef GATEWAY
#ifndef __QNXNTO__
	ipflow_slowtimo();
#else
	ret += ipflow_slowtimo();
#endif
#endif
	splx(s);
#ifdef __QNXNTO__
	return ret;
#endif
}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain(void)
{

	/*
	 * We may be called from a device's interrupt context.  If
	 * the ipq is already busy, just bail out now.
	 */
	if (ipq_lock_try() == 0)
		return;

	/*
	 * Drop half the total fragments now. If more mbufs are needed,
	 *  we will be called again soon.
	 */
	ip_reass_drophalf();

	IPQ_UNLOCK();
}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
int
ip_dooptions(struct mbuf *m)
{
	struct ip *ip = mtod(m, struct ip *);
	u_char *cp, *cp0;
	struct ip_timestamp *ipt;
	struct in_ifaddr *ia;
	int opt, optlen, cnt, off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr dst;
	n_time ntime;

	dst = ip->ip_dst;
	cp = (u_char *)(ip + 1);
	cnt = (ip->ip_hl << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
		}
		switch (opt) {

		default:
			break;

		/*
		 * Source routing with record.
		 * Find interface with current destination address.
		 * If none on this machine then drop if strictly routed,
		 * or do nothing if loosely routed.
		 * Record interface address and bring up next address
		 * component.  If strictly routed make sure next
		 * address is on directly accessible net.
		 */
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if (ip_allowsrcrt == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_NET_PROHIB;
				goto bad;
			}
			if (optlen < IPOPT_OFFSET + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			ipaddr.sin_addr = ip->ip_dst;
#ifndef QNX_MFIB
			ia = ifatoia(ifa_ifwithaddr(sintosa(&ipaddr)));
#else
			{
				int fib = -1;
				while ((fib = if_get_next_fib(m->m_pkthdr.rcvif, fib)) < FIBS_MAX) {
					ia = ifatoia(ifa_ifwithaddr(sintosa(&ipaddr)));
					if (ia)
						break;
				}
			}
#endif
			if (ia == 0) {
				if (opt == IPOPT_SSRR) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				}
				/*
				 * Loose routing, and not at next destination
				 * yet; nothing to do except forward.
				 */
				break;
			}
			off--;			/* 0 origin */
			if ((off + sizeof(struct in_addr)) > optlen) {
				/*
				 * End of source route.  Should be for us.
				 */
				save_rte(cp, ip->ip_src);
				break;
			}
			/*
			 * locate outgoing interface
			 */
			bcopy((caddr_t)(cp + off), (caddr_t)&ipaddr.sin_addr,
			    sizeof(ipaddr.sin_addr));
#ifndef QNX_MFIB
			if (opt == IPOPT_SSRR)
				ia = ifatoia(ifa_ifwithladdr(sintosa(&ipaddr)));
			else
				ia = ip_rtaddr(ipaddr.sin_addr);
#else
			{
				/*
				 *  try all fibs this i/f is a member of:
				 *   - lookup is in only the specified fib, so can't accidentally crossforward
				 */
				int fib;
				for (fib = 0; fib < FIBS_MAX; fib++) {
					if (!if_get_fib_enabled(m->m_pkthdr.rcvif, fib))
						continue;
					if (opt == IPOPT_SSRR)
						ia = ifatoia(ifa_ifwithladdr(sintosa(&ipaddr)));
					else
						ia = ip_rtaddr(ipaddr.sin_addr, fib);
					if (ia != 0)
						break;
				}
			}
#endif
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			bcopy((caddr_t)&ia->ia_addr.sin_addr,
			    (caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			/*
			 * Let ip_intr's mcast routing check handle mcast pkts
			 */
			forward = !IN_MULTICAST(ip->ip_dst.s_addr);
			break;

		case IPOPT_RR:
			if (optlen < IPOPT_OFFSET + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			/*
			 * If no space remains, ignore.
			 */
			off--;			/* 0 origin */
			if ((off + sizeof(struct in_addr)) > optlen)
				break;
			bcopy((caddr_t)(&ip->ip_dst), (caddr_t)&ipaddr.sin_addr,
			    sizeof(ipaddr.sin_addr));
			/*
			 * locate outgoing interface; if we're the destination,
			 * use the incoming interface (should be same).
			 */
#ifndef QNX_MFIB
			if ((ia = ifatoia(ifa_ifwithaddr(sintosa(&ipaddr))))
			    == NULL &&
			    (ia = ip_rtaddr(ipaddr.sin_addr)) == NULL) {
#else
				{
					int fib;
					for (fib = 0; fib < FIBS_MAX; fib++) {
						if (!if_get_fib_enabled(m->m_pkthdr.rcvif, fib))
							continue;
						/*
						 *  try all fibs this i/f is a member of:
						 *   - lookup is in only the specified fib, so can't accidentally crossforward
						 */
						if ((ia = ifatoia(ifa_ifwithaddr(sintosa(&ipaddr))))
								== NULL) {
							ia = ip_rtaddr(ipaddr.sin_addr, fib);
						}
						if (ia != 0)
							break;
					}
				}
				if (ia == NULL) {
#endif
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_HOST;
				goto bad;
			}
			bcopy((caddr_t)&ia->ia_addr.sin_addr,
			    (caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)cp;
			if (ipt->ipt_len < 4 || ipt->ipt_len > 40) {
				code = (u_char *)&ipt->ipt_len - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr < 5) {
				code = (u_char *)&ipt->ipt_ptr - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr > ipt->ipt_len - sizeof (int32_t)) {
				if (++ipt->ipt_oflw == 0) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				break;
			}
			cp0 = (cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				ipaddr.sin_addr = dst;
				ia = ifatoia(ifaof_ifpforaddr(sintosa(&ipaddr),
				    m->m_pkthdr.rcvif));
				if (ia == 0)
					continue;
				bcopy(&ia->ia_addr.sin_addr,
				    cp0, sizeof(struct in_addr));
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				bcopy(cp0, &ipaddr.sin_addr,
				    sizeof(struct in_addr));
#ifndef QNX_MFIB
				if (ifatoia(ifa_ifwithaddr(sintosa(&ipaddr)))
				    == NULL)
					continue;
#else
				{
					int fib = -1;
					int found = 0;
					while ((fib = if_get_next_fib(m->m_pkthdr.rcvif, fib)) < FIBS_MAX) {
						if (ifatoia(ifa_ifwithaddr(sintosa(&ipaddr)))
						    == NULL) {
							continue;
						} else {
							found = 1;
							break;
						}
					}
					if (!found)
						continue;
				}
#endif
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				/* XXX can't take &ipt->ipt_flg */
				code = (u_char *)&ipt->ipt_ptr -
				    (u_char *)ip + 1;
				goto bad;
			}
			ntime = iptime();
			cp0 = (u_char *) &ntime; /* XXX grumble, GCC... */
			bcopy(cp0, (caddr_t)cp + ipt->ipt_ptr - 1,
			    sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward) {
		if (ip_forwsrcrt == 0) {
			type = ICMP_UNREACH;
			code = ICMP_UNREACH_SRCFAIL;
			goto bad;
		}
		ip_forward(m, 1);
		return (1);
	}
	return (0);
bad:
	icmp_error(m, type, code, 0, 0);
	ipstat.ips_badoptions++;
	return (1);
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
struct in_ifaddr *
#ifndef QNX_MFIB
ip_rtaddr(struct in_addr dst)
#else
ip_rtaddr(struct in_addr dst, int fib)
#endif
{
	struct sockaddr_in *sin;

	sin = satosin(&ipforward_rt.ro_dst);

	if (ipforward_rt.ro_rt == 0 || !in_hosteq(dst, sin->sin_addr)
#ifdef QNX_MFIB
		|| ipforward_rt.ro_rt->fib != fib
#endif
		) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = dst;
#ifndef QNX_MFIB
		rtalloc(&ipforward_rt);
#else
		rtalloc(&ipforward_rt, NULL, fib);
#endif
	}
	if (ipforward_rt.ro_rt == 0)
		return ((struct in_ifaddr *)0);
	return (ifatoia(ipforward_rt.ro_rt->rt_ifa));
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(u_char *option, struct in_addr dst)
{
	unsigned olen;

	olen = option[IPOPT_OLEN];
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf("save_rte: olen %d\n", olen);
#endif /* 0 */
	if (olen > sizeof(ip_srcrt) - (1 + sizeof(dst)))
		return;
	bcopy((caddr_t)option, (caddr_t)ip_srcrt.srcopt, olen);
	ip_nhops = (olen - IPOPT_OFFSET - 1) / sizeof(struct in_addr);
	ip_srcrt.dst = dst;
}

/*
 * Retrieve incoming source route for use in replies,
 * in the same form used by setsockopt.
 * The first hop is placed before the options, will be removed later.
 */
struct mbuf *
ip_srcroute(void)
{
	struct in_addr *p, *q;
	struct mbuf *m;

	if (ip_nhops == 0)
		return ((struct mbuf *)0);
	m = m_get(M_DONTWAIT, MT_SOOPTS);
	if (m == 0)
		return ((struct mbuf *)0);

	MCLAIM(m, &inetdomain.dom_mowner);
#define OPTSIZ	(sizeof(ip_srcrt.nop) + sizeof(ip_srcrt.srcopt))

	/* length is (nhops+1)*sizeof(addr) + sizeof(nop + srcrt header) */
	m->m_len = ip_nhops * sizeof(struct in_addr) + sizeof(struct in_addr) +
	    OPTSIZ;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf("ip_srcroute: nhops %d mlen %d", ip_nhops, m->m_len);
#endif

	/*
	 * First save first hop for return route
	 */
	p = &ip_srcrt.route[ip_nhops - 1];
	*(mtod(m, struct in_addr *)) = *p--;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf(" hops %x", ntohl(mtod(m, struct in_addr *)->s_addr));
#endif

	/*
	 * Copy option fields and padding (nop) to mbuf.
	 */
	ip_srcrt.nop = IPOPT_NOP;
	ip_srcrt.srcopt[IPOPT_OFFSET] = IPOPT_MINOFF;
	bcopy((caddr_t)&ip_srcrt.nop,
	    mtod(m, caddr_t) + sizeof(struct in_addr), OPTSIZ);
	q = (struct in_addr *)(mtod(m, caddr_t) +
	    sizeof(struct in_addr) + OPTSIZ);
#undef OPTSIZ
	/*
	 * Record return path as an IP source route,
	 * reversing the path (pointers are now aligned).
	 */
	while (p >= ip_srcrt.route) {
#ifdef DIAGNOSTIC
		if (ipprintfs)
			printf(" %x", ntohl(q->s_addr));
#endif
		*q++ = *p--;
	}
	/*
	 * Last hop goes to final destination.
	 */
	*q = ip_srcrt.dst;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf(" %x\n", ntohl(q->s_addr));
#endif
	return (m);
}

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * XXX should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(struct mbuf *m, struct mbuf *mopt)
{
	int i;
	struct ip *ip = mtod(m, struct ip *);
	caddr_t opts;
	int olen;

	olen = (ip->ip_hl << 2) - sizeof (struct ip);
	opts = (caddr_t)(ip + 1);
	i = m->m_len - (sizeof (struct ip) + olen);
	bcopy(opts  + olen, opts, (unsigned)i);
	m->m_len -= olen;
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.len -= olen;
	ip->ip_len = htons(ntohs(ip->ip_len) - olen);
	ip->ip_hl = sizeof (struct ip) >> 2;
}

const int inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 * The srcrt parameter indicates whether the packet is being forwarded
 * via a source route.
 */
void
ip_forward(struct mbuf *m, int srcrt)
{
	struct ip *ip = mtod(m, struct ip *);
	struct sockaddr_in *sin;
	struct rtentry *rt;
	int error, type = 0, code = 0, destmtu = 0;
	struct mbuf *mcopy;
	n_long dest;
#ifdef QNX_MFIB
	int fib=-1;
#endif

	/*
	 * We are now in the output path.
	 */
	MCLAIM(m, &ip_tx_mowner);

	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	m->m_pkthdr.csum_flags = 0;

	dest = 0;
#ifdef DIAGNOSTIC
	if (ipprintfs) {
		printf("forward: src %s ", inet_ntoa(ip->ip_src));
		printf("dst %s ttl %x\n", inet_ntoa(ip->ip_dst), ip->ip_ttl);
	}
#endif
	if (m->m_flags & (M_BCAST|M_MCAST) || in_canforward(ip->ip_dst) == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
		return;
	}
	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return;
	}

	sin = satosin(&ipforward_rt.ro_dst);
	if ((rt = ipforward_rt.ro_rt) == 0 ||
	    !in_hosteq(ip->ip_dst, sin->sin_addr)
#ifdef QNX_MFIB
	    || !if_get_fib_enabled(m->m_pkthdr.rcvif, ipforward_rt.ro_rt->fib)
#endif
	    ) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		sin->sin_addr = ip->ip_dst;

#ifndef QNX_MFIB
		rtalloc(&ipforward_rt);
#else
		/*
		 * See if we can find a rt on one of the fibs this interface is a member
		 */
		ipforward_rt.ro_rt = 0;
		for (fib=0; fib < FIBS_MAX; fib++) {
			if (if_get_fib_enabled(m->m_pkthdr.rcvif, fib) &&
				(ipforwarding || (ipforwarding_mfibmask & (1UL << fib)))) {
				rtalloc(&ipforward_rt, NULL, fib);
				if (ipforward_rt.ro_rt != 0) {
					break;
				}
			}
		}
#endif
		if (ipforward_rt.ro_rt == 0) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_NET, dest, 0);
			return;
		}
		rt = ipforward_rt.ro_rt;
	}

	/*
	 * Save at most 68 bytes of the packet in case
	 * we need to generate an ICMP message to the src.
	 * Pullup to avoid sharing mbuf cluster between m and mcopy.
	 */
	mcopy = m_copym(m, 0, imin(ntohs(ip->ip_len), 68), M_DONTWAIT);
	if (mcopy)
		mcopy = m_pullup(mcopy, ip->ip_hl << 2);

	ip->ip_ttl -= IPTTLDEC;

	/*
	 * If forwarding packet using same interface that it came in on,
	 * perhaps should send a redirect to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * and if packet was not source routed (or has any options).
	 * Also, don't send redirect if forwarding using a default route
	 * or a route modified by a redirect.
	 */
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
	    (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0 &&
	    !in_nullhost(satosin(rt_key(rt))->sin_addr) &&
	    ipsendredirects && !srcrt) {
		if (rt->rt_ifa &&
		    (ip->ip_src.s_addr & ifatoia(rt->rt_ifa)->ia_subnetmask) ==
		    ifatoia(rt->rt_ifa)->ia_subnet) {
			if (rt->rt_flags & RTF_GATEWAY)
				dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
			else
				dest = ip->ip_dst.s_addr;
			/*
			 * Router requirements says to only send host
			 * redirects.
			 */
			type = ICMP_REDIRECT;
			code = ICMP_REDIRECT_HOST;
#ifdef DIAGNOSTIC
			if (ipprintfs)
				printf("redirect (%d) to %x\n", code,
				    (u_int32_t)dest);
#endif
		}
	}

#ifndef QNX_MFIB
	error = ip_output(m, (struct mbuf *)0, &ipforward_rt,
#else
	error = ip_output(m, ipforward_rt.ro_rt->fib, (struct mbuf *)0, &ipforward_rt,
#endif
	    (IP_FORWARDING | (ip_directedbcast ? IP_ALLOWBROADCAST : 0)),
	    (struct ip_moptions *)NULL, (struct socket *)NULL);

	if (error)
		ipstat.ips_cantforward++;
	else {
		ipstat.ips_forward++;
		if (type)
			ipstat.ips_redirectsent++;
		else {
			if (mcopy) {
#ifdef GATEWAY
				if (mcopy->m_flags & M_CANFASTFWD)
					ipflow_create(&ipforward_rt, mcopy);
#endif
				m_freem(mcopy);
			}
			return;
		}
	}
	if (mcopy == NULL)
		return;

	switch (error) {

	case 0:				/* forwarded, but need redirect */
		/* type, code set above */
		break;

	case ENETUNREACH:		/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		break;

	case EMSGSIZE:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_NEEDFRAG;

		if (ipforward_rt.ro_rt) {
#if defined(IPSEC) || defined(FAST_IPSEC)
			/*
			 * If the packet is routed over IPsec tunnel, tell the
			 * originator the tunnel MTU.
			 *	tunnel MTU = if MTU - sizeof(IP) - ESP/AH hdrsiz
			 * XXX quickhack!!!
			 */

			struct secpolicy *sp;
			int ipsecerror;
			size_t ipsechdr;
			struct route *ro;

if (QNXNTO_IPSEC_ENABLED) {
			sp = ipsec4_getpolicybyaddr(mcopy,
			    IPSEC_DIR_OUTBOUND, IP_FORWARDING,
#ifndef __QNXNTO__
			    &ipsecerror);
#else
			    &ipsecerror, m->m_pkthdr.rcvif);
#endif
}
#endif

			destmtu = ipforward_rt.ro_rt->rt_ifp->if_mtu;
#if defined(IPSEC) || defined(FAST_IPSEC)
if (QNXNTO_IPSEC_ENABLED) {
			if (sp != NULL && sp->policy == IPSEC_POLICY_IPSEC) {
				/* count IPsec header size */
				ipsechdr = ipsec4_hdrsiz(mcopy,
				    IPSEC_DIR_OUTBOUND, NULL);

				/*
				 * find the correct route for outer IPv4
				 * header, compute tunnel MTU.
				 */

				if (sp->req != NULL
				 && sp->req->sav != NULL
				 && sp->req->sav->sah != NULL) {
					ro = &sp->req->sav->sah->sa_route;
					if (ro->ro_rt && ro->ro_rt->rt_ifp) {
						destmtu =
						    ro->ro_rt->rt_rmx.rmx_mtu ?
						    ro->ro_rt->rt_rmx.rmx_mtu :
						    ro->ro_rt->rt_ifp->if_mtu;
						destmtu -= ipsechdr;
					}
				}

#ifdef	IPSEC
				key_freesp(sp);
#else
				KEY_FREESP(&sp);
#endif
			}
}
#endif /*defined(IPSEC) || defined(FAST_IPSEC)*/
		}
		ipstat.ips_cantfrag++;
		break;

	case ENOBUFS:
#if 1
		/*
		 * a router should not generate ICMP_SOURCEQUENCH as
		 * required in RFC1812 Requirements for IP Version 4 Routers.
		 * source quench could be a big problem under DoS attacks,
		 * or if the underlying interface is rate-limited.
		 */
		if (mcopy)
			m_freem(mcopy);
		return;
#else
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;
#endif
	}
	icmp_error(mcopy, type, code, dest, destmtu);
}

void
ip_savecontrol(struct inpcb *inp, struct mbuf **mp, struct ip *ip,
    struct mbuf *m)
{

	if (inp->inp_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		microtime(&tv);
		*mp = sbcreatecontrol((void *) &tv, sizeof(tv),
		    SCM_TIMESTAMP, SOL_SOCKET);
		if (*mp)
			mp = &(*mp)->m_next;
	}
	if (inp->inp_flags & INP_RECVDSTADDR) {
		*mp = sbcreatecontrol((void *) &ip->ip_dst,
		    sizeof(struct in_addr), IP_RECVDSTADDR, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}

	if (inp->inp_flags & INP_RECVPKTINFO) {
		struct in_pktinfo ipi;
		ipi.ipi_addr = ip->ip_src;
		ipi.ipi_ifindex = m->m_pkthdr.rcvif->if_index;
		*mp = sbcreatecontrol((void *) &ipi,
		    sizeof(ipi), IP_RECVPKTINFO, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
	if (inp->inp_flags & INP_PKTINFO) {
		struct in_pktinfo ipi;
		ipi.ipi_addr = ip->ip_dst;
		ipi.ipi_ifindex = m->m_pkthdr.rcvif->if_index;
		*mp = sbcreatecontrol((void *) &ipi,
		    sizeof(ipi), IP_PKTINFO, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
#ifdef notyet
	/*
	 * XXX
	 * Moving these out of udp_input() made them even more broken
	 * than they already were.
	 *	- fenner@parc.xerox.com
	 */
	/* options were tossed already */
	if (inp->inp_flags & INP_RECVOPTS) {
		*mp = sbcreatecontrol((void *) opts_deleted_above,
		    sizeof(struct in_addr), IP_RECVOPTS, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
	/* ip_srcroute doesn't do what we want here, need to fix */
	if (inp->inp_flags & INP_RECVRETOPTS) {
		*mp = sbcreatecontrol((void *) ip_srcroute(),
		    sizeof(struct in_addr), IP_RECVRETOPTS, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
#endif
	if (inp->inp_flags & INP_RECVIF) {
		struct sockaddr_dl sdl;

		sdl.sdl_len = offsetof(struct sockaddr_dl, sdl_data[0]);
		sdl.sdl_family = AF_LINK;
		sdl.sdl_index = m->m_pkthdr.rcvif ?
		    m->m_pkthdr.rcvif->if_index : 0;
		sdl.sdl_nlen = sdl.sdl_alen = sdl.sdl_slen = 0;
		*mp = sbcreatecontrol(&sdl, sdl.sdl_len, IP_RECVIF, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
}

/*
 * sysctl helper routine for net.inet.ip.forwsrcrt.
 */
static int
sysctl_net_inet_ip_forwsrcrt(SYSCTLFN_ARGS)
{
	int error, tmp;
	struct sysctlnode node;

	node = *rnode;
	tmp = ip_forwsrcrt;
	node.sysctl_data = &tmp;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_FORWSRCRT,
	    0, NULL, NULL, NULL))
		return (EPERM);

	ip_forwsrcrt = tmp;

	return (0);
}

/*
 * sysctl helper routine for net.inet.ip.mtudisctimeout.  checks the
 * range of the new value and tweaks timers if it changes.
 */
static int
sysctl_net_inet_ip_pmtudto(SYSCTLFN_ARGS)
{
	int error, tmp;
	struct sysctlnode node;

	node = *rnode;
	tmp = ip_mtudisc_timeout;
	node.sysctl_data = &tmp;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);
	if (tmp < 0)
		return (EINVAL);

	ip_mtudisc_timeout = tmp;
#ifndef QNX_MFIB
	rt_timer_queue_change(ip_mtudisc_timeout_q, ip_mtudisc_timeout);
#else
	int fib;
	for (fib=0;fib<FIBS_MAX;fib++)
		rt_timer_queue_change(ip_mtudisc_timeout_q[fib], ip_mtudisc_timeout);
#endif

	return (0);
}

#ifdef GATEWAY
/*
 * sysctl helper routine for net.inet.ip.maxflows.  apparently if
 * maxflows is even looked up, we "reap flows".
 */
static int
sysctl_net_inet_ip_maxflows(SYSCTLFN_ARGS)
{
	int s;

	s = sysctl_lookup(SYSCTLFN_CALL(rnode));
	if (s)
		return (s);

	s = splsoftnet();
	ipflow_reap(0);
	splx(s);

	return (0);
}
#endif /* GATEWAY */


SYSCTL_SETUP(sysctl_net_inet_ip_setup, "sysctl net.inet.ip subtree setup")
{
	extern int subnetsarelocal, hostzeroisbroadcast;

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "inet",
		       SYSCTL_DESCR("PF_INET related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "ip",
		       SYSCTL_DESCR("IPv4 related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET, IPPROTO_IP, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "forwarding",
		       SYSCTL_DESCR("Enable forwarding of INET datagrams"),
		       NULL, 0, &ipforwarding, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_FORWARDING, CTL_EOL);
#ifdef QNX_MFIB
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "forwarding_mfibmask",
		       SYSCTL_DESCR("Enable forwarding in select FIBs (subordinate to forwarding)"),
		       NULL, 0, &ipforwarding_mfibmask, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_FORWARDING_MFIBMASK, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "redirect",
		       SYSCTL_DESCR("Enable sending of ICMP redirect messages"),
		       NULL, 0, &ipsendredirects, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_SENDREDIRECTS, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "ttl",
		       SYSCTL_DESCR("Default TTL for an INET datagram"),
		       NULL, 0, &ip_defttl, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_DEFTTL, CTL_EOL);
#ifdef IPCTL_DEFMTU
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT /* |CTLFLAG_READWRITE? */,
		       CTLTYPE_INT, "mtu",
		       SYSCTL_DESCR("Default MTA for an INET route"),
		       NULL, 0, &ip_mtu, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_DEFMTU, CTL_EOL);
#endif /* IPCTL_DEFMTU */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "forwsrcrt",
		       SYSCTL_DESCR("Enable forwarding of source-routed "
				    "datagrams"),
		       sysctl_net_inet_ip_forwsrcrt, 0, &ip_forwsrcrt, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_FORWSRCRT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "directed-broadcast",
		       SYSCTL_DESCR("Enable forwarding of broadcast datagrams"),
		       NULL, 0, &ip_directedbcast, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_DIRECTEDBCAST, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "allowsrcrt",
		       SYSCTL_DESCR("Accept source-routed datagrams"),
		       NULL, 0, &ip_allowsrcrt, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_ALLOWSRCRT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "subnetsarelocal",
		       SYSCTL_DESCR("Whether logical subnets are considered "
				    "local"),
		       NULL, 0, &subnetsarelocal, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_SUBNETSARELOCAL, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mtudisc",
		       SYSCTL_DESCR("Use RFC1191 Path MTU Discovery"),
		       NULL, 0, &ip_mtudisc, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_MTUDISC, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "anonportmin",
		       SYSCTL_DESCR("Lowest ephemeral port number to assign"),
		       sysctl_net_inet_ip_ports, 0, &anonportmin, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_ANONPORTMIN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "anonportmax",
		       SYSCTL_DESCR("Highest ephemeral port number to assign"),
		       sysctl_net_inet_ip_ports, 0, &anonportmax, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_ANONPORTMAX, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mtudisctimeout",
		       SYSCTL_DESCR("Lifetime of a Path MTU Discovered route"),
		       sysctl_net_inet_ip_pmtudto, 0, &ip_mtudisc_timeout, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_MTUDISCTIMEOUT, CTL_EOL);
#ifdef GATEWAY
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxflows",
		       SYSCTL_DESCR("Number of flows for fast forwarding"),
		       sysctl_net_inet_ip_maxflows, 0, &ip_maxflows, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_MAXFLOWS, CTL_EOL);
#endif /* GATEWAY */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "hostzerobroadcast",
		       SYSCTL_DESCR("All zeroes address is broadcast address"),
		       NULL, 0, &hostzeroisbroadcast, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_HOSTZEROBROADCAST, CTL_EOL);
#if NGIF > 0
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "gifttl",
		       SYSCTL_DESCR("Default TTL for a gif tunnel datagram"),
		       NULL, 0, &ip_gif_ttl, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_GIF_TTL, CTL_EOL);
#endif /* NGIF */
#ifndef IPNOPRIVPORTS
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "lowportmin",
		       SYSCTL_DESCR("Lowest privileged ephemeral port number "
				    "to assign"),
		       sysctl_net_inet_ip_ports, 0, &lowportmin, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_LOWPORTMIN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "lowportmax",
		       SYSCTL_DESCR("Highest privileged ephemeral port number "
				    "to assign"),
		       sysctl_net_inet_ip_ports, 0, &lowportmax, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_LOWPORTMAX, CTL_EOL);
#endif /* IPNOPRIVPORTS */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxfragpackets",
		       SYSCTL_DESCR("Maximum number of fragments to retain for "
				    "possible reassembly"),
		       NULL, 0, &ip_maxfragpackets, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_MAXFRAGPACKETS, CTL_EOL);
#if NGRE > 0
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "grettl",
		       SYSCTL_DESCR("Default TTL for a gre tunnel datagram"),
		       NULL, 0, &ip_gre_ttl, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_GRE_TTL, CTL_EOL);
#elif defined(__QNXNTO__) && !defined(VARIANT_sig)
	/*
	 * We've gotten rid of IPCTL_EXTERNAL_ARP which happened to map
	 * to what is now IPCTL_GRE_TTL.  The 6.3 arp utility tested a
	 * successful IPCTL_EXTERNAL_ARP request against a value of 1 to
	 * see if it was enabled.  Therefore as long as ip_gre_ttl != 1
	 * when NGRE > 1, the 6.3 arp utility should happen to work.  We
	 * choose this at this single spot rather than bringing along
	 * the legacy IPCTL_EXTERNAL_ARP throughout.
	 */
	{
		static int gre_replacement = 0;

		sysctl_createv(clog, 0, NULL, NULL,
			       CTLFLAG_PERMANENT|CTLFLAG_READONLY,
			       CTLTYPE_INT, "grettl",
			       SYSCTL_DESCR("Default TTL for a gre tunnel datagram"),
			       NULL, 0, &gre_replacement, 0,
			       CTL_NET, PF_INET, IPPROTO_IP,
			       IPCTL_GRE_TTL, CTL_EOL);
	}
#endif /* NGRE */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "checkinterface",
		       SYSCTL_DESCR("Enable receive side of Strong ES model "
				    "from RFC1122"),
		       NULL, 0, &ip_checkinterface, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_CHECKINTERFACE, CTL_EOL);
#ifdef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "bindinterface",
		       SYSCTL_DESCR("Enable transmit side of Strong ES model "
				    "from RFC1122"),
		       NULL, 0, &ip_bindinterface, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_BINDINTERFACE, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "random_id",
		       SYSCTL_DESCR("Assign random ip_id values"),
		       NULL, 0, &ip_do_randomid, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_RANDOMID, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "do_loopback_cksum",
		       SYSCTL_DESCR("Perform IP checksum on loopback"),
		       NULL, 0, &ip_do_loopback_cksum, 0,
		       CTL_NET, PF_INET, IPPROTO_IP,
		       IPCTL_LOOPBACKCKSUM, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("IP statistics"),
		       NULL, 0, &ipstat, sizeof(ipstat),
		       CTL_NET, PF_INET, IPPROTO_IP, IPCTL_STATS,
		       CTL_EOL);

	/* anonportalgo RFC6056 subtree */
	const struct sysctlnode *portalgo_node;
	sysctl_createv(clog, 0, NULL, &portalgo_node,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "anonportalgo",
		       SYSCTL_DESCR("Anonymous Port Algorithm Selection (RFC 6056)"),
	    	       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET, IPPROTO_IP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &portalgo_node, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRING, "available",
		       SYSCTL_DESCR("available algorithms"),
		       sysctl_portalgo_available, 0, NULL, PORTALGO_MAXLEN,
		       CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &portalgo_node, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_STRING, "selected",
		       SYSCTL_DESCR("selected algorithm"),
		       sysctl_portalgo_selected4, 0, NULL, PORTALGO_MAXLEN,
		       CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &portalgo_node, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_STRUCT, "reserve",
		       SYSCTL_DESCR("bitmap of reserved ports"),
		       sysctl_portalgo_reserve4, 0, NULL, 0,
		       CTL_CREATE, CTL_EOL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/ip_input.c $ $Rev: 880688 $")
#endif
