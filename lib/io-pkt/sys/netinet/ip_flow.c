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



/*	$NetBSD: ip_flow.c,v 1.36 2006/10/06 03:20:47 mrg Exp $	*/

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by the 3am Software Foundry ("3am").  It was developed by Matt Thomas.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ip_flow.c,v 1.36 2006/10/06 03:20:47 mrg Exp $");

#ifdef __QNXNTO__
#include "opt_ionet_compat.h"
#include <malloc.h> /* The QNX one */
#include <sys/syspage.h>
#include <sys/syslog.h>
#include <siglock.h>
#include <nw_thread.h>
#include <net/cacheline.h>
#include <net/if_types.h>
#endif

#include <sys/param.h>
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

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#ifdef __QNXNTO__
#include <netinet/if_inarp.h>
#endif

#ifndef __QNXNTO__
POOL_INIT(ipflow_pool, sizeof(struct ipflow), 0, 0, 0, "ipflowpl", NULL);
#else
/* Our size is not constant */
struct pool ipflow_pool;
#endif

LIST_HEAD(ipflowhead, ipflow);

#define	IPFLOW_TIMER		(5 * PR_SLOWHZ)
#define	IPFLOW_HASHSIZE		(1 << IPFLOW_HASHBITS)

static struct ipflowhead ipflowtable[IPFLOW_HASHSIZE];
static struct ipflowhead ipflowlist;
static int ipflow_inuse;

#ifdef __QNXNTO__
static struct ipflow * ipflow_start_rem(struct ipflow *);
static void ipflow_walk_freelist(void);

#ifndef VARIANT_uni
static void ipflow_walk_destroy_q(struct ipflow_threadinfo *, int);
#endif

#ifndef DIAGNOSTIC
static struct ipflow * ipflow_lookup_self(const struct ip *,
    struct ipflow_threadinfo *, struct nw_work_thread *);
#else
static struct ipflow *_ipflow_lookup_self(const struct ip *,
    struct ipflow_threadinfo *, struct nw_work_thread *, int);
#define ipflow_lookup_self(a, b, c)		\
	_ipflow_lookup_self((a), (b), (c), __LINE__)
#endif

#ifndef DIAGNOSTIC
#define	IPFLOW_SELF_CHECK(wtp, line)	/* nothing */
#else /* DIAGNOSTIC */
#define IPFLOW_SELF_CHECK(wtp, line_from)				\
do {									\
	if ((wtp)->intr_sighot != _ISIG_COLD && (wtp)->wt_critical == 0)\
		panic("ipflow: unexpected context: cur: %d  from: %d",	\
		    __LINE__, (line_from));				\
} while (0 /* CONSTCOND */)
#endif

#ifndef IONET_COMPAT
#define IPFLOW_SELF_ENTER(wtp, line_from)	IPFLOW_SELF_CHECK((wtp), (line_from))
#define IPFLOW_SELF_EXIT(wtp)			/* nothing */
#else /* IONET_COMPAT */
#define IPFLOW_SELF_ENTER(wtp, line_from)				\
do {									\
	NW_SIGHOLD_P(wtp);						\
	IPFLOW_SELF_CHECK((wtp), (line_from));				\
} while (0 /* CONSTCOND */)
#define IPFLOW_SELF_EXIT(wtp)	NW_SIGUNHOLD_P(wtp)
#endif /* IONET_COMPAT */
#endif /* __QNXNTO__ */

#define	IPFLOW_INSERT(bucket, ipf) \
do { \
	LIST_INSERT_HEAD((bucket), (ipf), ipf_hash); \
	LIST_INSERT_HEAD(&ipflowlist, (ipf), ipf_list); \
} while (/*CONSTCOND*/ 0)

#define	IPFLOW_REMOVE(ipf) \
do { \
	LIST_REMOVE((ipf), ipf_hash); \
	LIST_REMOVE((ipf), ipf_list); \
} while (/*CONSTCOND*/ 0)

#ifdef __QNXNTO__
#ifdef VARIANT_uni
#define IPFLOW_PAD             0
#else
#define IPFLOW_PAD              8  /* 8  * sizeof(struct ipf_thread) == 64 bytes */
static struct ipflowhead ipflow_free_list;

MALLOC_DECLARE(M_IPFLOW);
MALLOC_DEFINE(M_IPFLOW, "ipflow", "ipflow init struct");
#endif


#define IPFLOW_INSERT_HEAD_HASH_PRIVATE(ipftip, ipf, idx)	\
	LIST_INSERT_HEAD(&(ipftip)->ipfti_table[(ipf)->hash], (ipf), ipf_thread[(idx)].ipf_th_hash)
#define IPFLOW_REMOVE_HASH_PRIVATE(ipf, idx)	LIST_REMOVE((ipf), ipf_thread[(idx)].ipf_th_hash)

#ifndef VARIANT_uni
static pthread_mutex_t ipflow_ex;
static struct tpass_reminfo ipflow_tpass_reminfo;
static int ipflow_initialized;

static void
ipf_thread_decref(struct tpass_entry *tpass, int idx)
{
	struct ipflow *ipf;

	ipf = (struct ipflow *)tpass;
	IPFLOW_REMOVE_HASH_PRIVATE(ipf, idx);
}
#endif /* !VARIANT_uni */
#endif /* __QNXNTO__ */

#ifndef IPFLOW_MAX
#define	IPFLOW_MAX		256
#endif
int ip_maxflows = IPFLOW_MAX;

#ifdef __QNXNTO__
TPASS_QUEUES_DECLARE(ipflow_passq, ipflow);
struct ipflow_threadinfo {
	int			ipfti_inuse;
	union ipflow_passq	ipfti_tpqu;
#define ipfti_tpq ipfti_tpqu.tpq_local
	/* The index into ipflow_threads etc... */
	int			ipfti_idx;
	/* Per thread hash to avoid mutexing / contention in steady state. */
	struct ipflowhead	ipfti_table[IPFLOW_HASHSIZE];
}
#ifndef VARIANT_uni
__attribute__((aligned (NET_CACHELINE_SIZE)))
#endif
;


/*
 * Note:
 * The max number of flows is intended to be 'small' as
 * this array is walked for each add / remove event.
 * We could keep a list of entries that are actually
 * registered to avoid hitting ones that aren't inuse
 * but there shouldn't be too many such entries unless the
 * 'small' rule isn't followed.
 */
struct ipflow_threadinfo *ipflow_threads;



#ifndef NDEBUG
static int
ipflow_thread_isempty(struct ipflow_threadinfo *ipftip)
{
	int i;

	/*
	 * Entries on the create Q are OK.
	 * Other stragglers means the previous
	 * thread didn't clean up on exit.
	 */

	if (!LIST_EMPTY(&ipftip->ipfti_tpq.tpq_destroy_q))
	    return 0;

	for (i = 0; i < IPFLOW_HASHSIZE; i++) {
		if (!LIST_EMPTY(&ipftip->ipfti_table[i]))
		    return 0;
	}

	return 1;
}
#endif

/*
 * This is called before the first thread is
 * created so we need to use the standard malloc / free.
 */
int
ipflow_pre_main_init(void)
{
	size_t			size;
	struct nw_stk_ctl	*sctlp;
	int			lim, i;

	sctlp = &stk_ctl;
	lim = sctlp->nthreads_flow_max;

	size = lim * sizeof(*ipflow_threads);
	if ((ipflow_threads = (malloc)(size)) == NULL)
		return ENOMEM;

	memset(ipflow_threads, 0x00, size);
	for (i = 0; i < lim; i++)
		ipflow_threads[i].ipfti_idx = i;

	return EOK;
}

void
ipflow_pre_main_fini(void)
{
	(free)(ipflow_threads);
}


/* May be called by start thread (no context) so watch logging / panic */
int
ipflow_register(struct ipflow_threadinfo **retp)
{
	struct nw_stk_ctl		*sctlp;
	int				i;
	struct ipflow_threadinfo	*ipftip;

	sctlp = &stk_ctl;

	if (!ISSTART && !ISSTACK)
		return EPERM;

	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		ipftip = &ipflow_threads[i];
		if (ipftip->ipfti_inuse == 0) {
#ifndef NDEBUG
			if (ipflow_thread_isempty(ipftip) == 0)
			    log(LOG_WARNING, "ipflow stragglers");
#endif
			ipftip->ipfti_inuse = 1;
			*retp = ipftip;
			return EOK;
		}
	}

	return EAGAIN;
}




/* May be called by start thread (no context) so watch logging / panic */
int
ipflow_deregister(struct ipflow_threadinfo *ipftip)
{
	struct nw_stk_ctl	*sctlp;
	int			idx;

	if (!ISSTART && !ISSTACK)
		return EPERM;

	sctlp = &stk_ctl;

	idx = ipftip->ipfti_idx;

	if ((unsigned)idx > sctlp->nthreads_flow_max ||
	    &ipflow_threads[idx] != ipftip || ipftip->ipfti_inuse == 0)
		return EINVAL;


#ifndef VARIANT_uni
	if (ipflow_initialized) {
		ipflow_destroy(ipftip);
	}
#endif

	ipftip->ipfti_inuse = 0;

	return EOK;
}

#ifndef VARIANT_uni
/* May be called by start thread (no context) so watch logging / panic */
int
ipflow_destroy(struct ipflow_threadinfo *ipftip)
{
	int			idx, i;
	struct ipflow		*ipf;
	struct nw_work_thread	*wtp;

	idx = ipftip->ipfti_idx;

	/*
	 * We're walking another thread's qs but it's going away
	 * and therefore shouldn't be looking at them.
	 */
	wtp = WTP;
	NW_SIGLOCK_P(&ipflow_ex, iopkt_selfp, wtp);
	ipflow_walk_destroy_q(ipftip, idx);

	/*
	 * We move them back to the create q to simulate
	 * the dying thread never having seen the request
	 * to seed its private cache.  This avoids having to
	 * remove / reseed the entries from every thread.
	 */
	for (i = 0; i < IPFLOW_HASHSIZE; i++) {
		while ((ipf = LIST_FIRST(&ipftip->ipfti_table[i])) != NULL) {
			IPFLOW_REMOVE_HASH_PRIVATE(ipf, idx);

			LIST_INSERT_HEAD(&ipftip->ipfti_tpq.tpq_create_q, ipf,
			    ipf_thread[idx].ipf_th_passlist);
			ipf->ipf_tpe.tpe_nthreads_creating++;
			ipftip->ipfti_tpq.tpq_items_changing++;
		}
	}

	NW_SIGUNLOCK_P(&ipflow_ex, iopkt_selfp, wtp);

	return EOK;
}
#endif /* VARIANT_uni */
#endif /* __QNXNTO__ */

#ifndef __QNXNTO__
static unsigned
ipflow_hash(struct in_addr dst,	struct in_addr src, unsigned tos)
{
	unsigned hash = tos;
	int idx;
	for (idx = 0; idx < 32; idx += IPFLOW_HASHBITS)
		hash += (dst.s_addr >> (32 - idx)) + (src.s_addr >> idx);
	return hash & (IPFLOW_HASHSIZE-1);
}

static struct ipflow *
ipflow_lookup(const struct ip *ip)
{
	unsigned hash;
	struct ipflow *ipf;

	hash = ipflow_hash(ip->ip_dst, ip->ip_src, ip->ip_tos);

	LIST_FOREACH(ipf, &ipflowtable[hash], ipf_hash) {
		if (ip->ip_dst.s_addr == ipf->ipf_dst.s_addr
		    && ip->ip_src.s_addr == ipf->ipf_src.s_addr
		    && ip->ip_tos == ipf->ipf_tos)
			break;
	}
	return ipf;
}

void
ipflow_init(void)
{
	int i;

	LIST_INIT(&ipflowlist);
	for (i = 0; i < IPFLOW_HASHSIZE; i++)
		LIST_INIT(&ipflowtable[i]);
}
#else /* __QNXNTO__ */
static unsigned
ipflow_hash(uint32_t dst, uint32_t src, unsigned tos)
{
	unsigned hash = tos;
	int idx;

	for (idx = 0; idx < 32; idx += IPFLOW_HASHBITS)
		hash += (dst >> (32 - idx)) + (src >> idx);
	return hash & (IPFLOW_HASHSIZE-1);
}

static struct ipflow *
ipflow_lookup(const struct ip *ip, struct ipflowhead *iph)
{
	unsigned hash;
	struct ipflow *ipf;
	uint32_t dst, src;

	dst = UNALIGNED_RET32(&ip->ip_dst.s_addr);
	src = UNALIGNED_RET32(&ip->ip_src.s_addr);

	hash = ipflow_hash(dst, src, ip->ip_tos);

	LIST_FOREACH(ipf, &iph[hash], ipf_hash) {
		if (dst == ipf->ipf_dst.s_addr
		    && src == ipf->ipf_src.s_addr
		    && ip->ip_tos == ipf->ipf_tos)
			break;
	}
	return ipf;
}


static struct ipflow *
#ifndef DIAGNOSTIC
ipflow_lookup_self(const struct ip *ip, struct ipflow_threadinfo *ipftip,
    struct nw_work_thread *wtp)
#else
_ipflow_lookup_self(const struct ip *ip, struct ipflow_threadinfo *ipftip,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	unsigned hash;
	struct ipflow *ipf;
	struct ipflow_thread *ipfth;
	uint32_t dst, src;
	struct ipflowhead *iph;
	int self;

	IPFLOW_SELF_ENTER(wtp, line_from);

	iph = ipftip->ipfti_table;
	self = ipftip->ipfti_idx;

	dst = UNALIGNED_RET32(&ip->ip_dst.s_addr);
	src = UNALIGNED_RET32(&ip->ip_src.s_addr);

	hash = ipflow_hash(dst, src, ip->ip_tos);

	ipf = LIST_FIRST(&iph[hash]);
	while (ipf != NULL) {
		if (dst == ipf->ipf_dst.s_addr
		    && src == ipf->ipf_src.s_addr
		    && ip->ip_tos == ipf->ipf_tos)
			break;
		ipfth = &ipf->ipf_thread[self];
		ipf = LIST_NEXT(ipfth, ipf_th_hash);
	}
	/*
	 * The ipf entries themselves are aligned but
	 * the per thread next pointers are not.  If
	 * one considers the usual forwarding semantics,
	 * packets destined for a particular dst are
	 * usually received on the same interface and
	 * the thread handling this interface shouldn't
	 * change (often).  If we happen to have two
	 * dsts that are handled by different threads
	 * but hash to the same index, we may bring in
	 * unneeded cache lines by walking this list.
	 * Therefore we always move our particular entries
	 * to the front.
	 */
	if (ipf != NULL && ipf != LIST_FIRST(&iph[hash])) {
		IPFLOW_REMOVE_HASH_PRIVATE(ipf, self);
		IPFLOW_INSERT_HEAD_HASH_PRIVATE(ipftip, ipf, self);
	}
	IPFLOW_SELF_EXIT(wtp);
	return ipf;
}

void
ipflow_init(void)
{
	struct nw_stk_ctl	*sctlp;
	size_t			size;
	int			pad;

	sctlp = &stk_ctl;

	size = offsetof(struct ipflow, ipf_thread) +
	    sctlp->nthreads_flow_max * sizeof(struct ipflow_thread);
#ifndef VARIANT_uni
	if ((pad = size % NET_CACHELINE_SIZE) > 0)
		pad = NET_CACHELINE_SIZE - pad;
#else
	pad = 0;
#endif
	size += pad;
	pool_init(&ipflow_pool, size, 0, 0, 0, "ipflowpl", NULL);

#ifndef VARIANT_uni
	(*iopkt_selfp->ex_init)(&ipflow_ex);
#endif

	LIST_INIT(&ipflowlist);
#ifndef VARIANT_uni
	LIST_INIT(&ipflow_free_list);

	ipflow_tpass_reminfo.tpr_tlist_first_offset =
	    offsetof(struct ipflow, ipf_thread[0].ipf_th_tplu.tpl_private);
	/* The tpass_list entries are in an array of struct ipflow_thread */
	ipflow_tpass_reminfo.tpr_tlist_next_offset =
	    sizeof(struct ipflow_thread);

	/* The tpass_qs entries are in an array of struct ipflow_threadinfo */
	ipflow_tpass_reminfo.tpr_pq_next_offset =
	    sizeof(struct ipflow_threadinfo);

	ipflow_tpass_reminfo.tpr_rem_self = ipf_thread_decref;
	ipflow_tpass_reminfo.tpr_lim = stk_ctl.nthreads_flow_max;
	ipflow_tpass_reminfo.tpr_mtx = &ipflow_ex;
	ipflow_initialized = 1;
#endif
}
#endif /* __QNXNTO__ */

int
ipflow_fastforward(struct mbuf *m)
{
#ifndef __QNXNTO__
	struct ip *ip, ip_store;
#else
	struct ip *ip;
#endif
	struct ipflow *ipf;
	struct rtentry *rt;
	struct sockaddr *dst;
	int error;
	int iplen;
#ifdef __QNXNTO__
	int self;
	struct ipflow_threadinfo *ipftip;
	struct nw_work_thread *wtp;
	struct nw_stk_ctl *sctlp;
	struct rtentry *rt2;
#ifndef VARIANT_uni
	struct ipflow_thread *ipfth;
#endif

	wtp = WTP;
	if ((ipftip = wtp->flowctl) == NULL) {
		nw_thread_log_noflow();
		return 0;
	}
	self = ipftip->ipfti_idx;
#ifndef VARIANT_uni
	sctlp = &stk_ctl;

	if (ipftip->ipfti_tpq.tpq_items_changing > 0) {

		NW_SIGLOCK_P(&ipflow_ex, iopkt_selfp, wtp);

		if (LIST_FIRST(&ipftip->ipfti_tpq.tpq_destroy_q) != NULL)
			ipflow_walk_destroy_q(ipftip, self);

		while ((ipf = LIST_FIRST(&ipftip->ipfti_tpq.tpq_create_q)) != NULL) {
			ipfth = &ipf->ipf_thread[self];
			LIST_FIRST(&ipftip->ipfti_tpq.tpq_create_q) =
			    LIST_NEXT(ipfth, ipf_th_passlist);

			IPF_MARK_OFFLIST(ipfth);

			ipftip->ipfti_tpq.tpq_items_changing--;

			IPFLOW_INSERT_HEAD_HASH_PRIVATE(ipftip, ipf, self);

			ipf->ipf_tpe.tpe_nthreads_creating--;
		}

		NW_SIGUNLOCK_P(&ipflow_ex, iopkt_selfp, wtp);
	}
#endif
	if (sctlp->fastforward == 0)
		return 0;
#endif /* __QNXNTO__ */

	/*
	 * Are we forwarding packets?  Big enough for an IP packet?
	 */
	if (
#ifndef QNX_MFIB
		!ipforwarding
#else
		(ipforwarding == 0 && (ipforwarding_mfibmask & m->m_pkthdr.rcvif->if_fibmask) == 0)
#endif
		|| ipflow_inuse == 0 || m->m_len < sizeof(struct ip))
		return 0;

	/*
	 * Was packet received as a link-level multicast or broadcast?
	 * If so, don't try to fast forward..
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST)) != 0)
		return 0;

	/*
	 * IP header with no option and valid version and length
	 */
#ifndef __QNXNTO__
	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)))
		ip = mtod(m, struct ip *);
	else {
		memcpy(&ip_store, mtod(m, caddr_t), sizeof(ip_store));
		ip = &ip_store;
	}
#else
	/*
	 * ipflow_lookup() takes care of 32 bit alignment.
	 * (should be at least 16 bit aligned).
	 */
	ip = mtod(m, struct ip *);
#endif
	iplen = ntohs(ip->ip_len);
	if (ip->ip_v != IPVERSION || ip->ip_hl != (sizeof(struct ip) >> 2) ||
	    iplen < sizeof(struct ip) || iplen > m->m_pkthdr.len)
		return 0;
	/*
	 * Find a flow.
	 */
#ifndef __QNXNTO__
	if ((ipf = ipflow_lookup(ip)) == NULL)
#else
	ipf = ipflow_lookup_self(ip, ipftip, wtp);
	if (ipf == NULL)
#endif
		return 0;

	/*
	 * Verify the IP header checksum.
	 */
	switch (m->m_pkthdr.csum_flags &
		((m->m_pkthdr.rcvif->if_csum_flags_rx & M_CSUM_IPv4) |
		 M_CSUM_IPv4_BAD)) {
	case M_CSUM_IPv4|M_CSUM_IPv4_BAD:
		return (0);

	case M_CSUM_IPv4:
		/* Checksum was okay. */
		break;

	default:
		/* Must compute it ourselves. */
		if (in_cksum(m, sizeof(struct ip)) != 0)
			return (0);
		break;
	}

	/*
	 * Route and interface still up?
	 */
	rt = ipf->ipf_ro.ro_rt;
	if ((rt->rt_flags & RTF_UP) == 0 ||
	    (rt->rt_ifp->if_flags & IFF_UP) == 0 ||
	    (rt->rt_flags & (RTF_BLACKHOLE | RTF_BROADCAST)) != 0)
		return 0;

#ifdef __QNXNTO__
	rt2 = rt;
	if (ipf->ipf_gw != NULL) {
		/*
		 * Don't think rt->rt_gwroute member
		 * can change valid values but it can
		 * be NULL'd out at any time if rt is
		 * deleted (RTM_DELETE).  rt can't
		 * actually be freed out from under us
		 * as we've incremented its refcnt
		 * when we stored our ipf_gw reference
		 * to it.
		 */
		rt2 = ipf->ipf_gw;
		if (rt->rt_gwroute != rt2)
		       return 0;
	}

	switch (rt2->rt_ifp->if_type) {
	/*
	 * GACK.
	 *
	 * Layer 2 will free the mbuf on error.  We want to have
	 * the full path through the stack handle arp (for example).
	 */
	case IFT_ETHER:
	case IFT_L2VLAN:
		if (!arp_isresolved(rt2))
			return 0;
		break;

	default:
		return 0;
	}
#endif
	/*
	 * Packet size OK?  TTL?
	 */
	if (m->m_pkthdr.len > rt->rt_ifp->if_mtu || ip->ip_ttl <= IPTTLDEC)
		return 0;

	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	m->m_pkthdr.csum_flags = 0;

	/*
	 * Everything checks out and so we can forward this packet.
	 * Modify the TTL and incrementally change the checksum.
	 *
	 * This method of adding the checksum works on either endian CPU.
	 * If htons() is inlined, all the arithmetic is folded; otherwise
	 * the htons()s are combined by CSE due to the const attribute.
	 *
	 * Don't bother using HW checksumming here -- the incremental
	 * update is pretty fast.
	 */
	ip->ip_ttl -= IPTTLDEC;
	if (ip->ip_sum >= (u_int16_t) ~htons(IPTTLDEC << 8))
		ip->ip_sum -= ~htons(IPTTLDEC << 8);
	else
		ip->ip_sum += htons(IPTTLDEC << 8);

#ifndef __QNXNTO__
	/*
	 * Done modifying the header; copy it back, if necessary.
	 */
	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0)
		memcpy(mtod(m, caddr_t), &ip_store, sizeof(ip_store));
#endif

	/*
	 * Trim the packet in case it's too long..
	 */
	if (m->m_pkthdr.len > iplen) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = iplen;
			m->m_pkthdr.len = iplen;
		} else
			m_adj(m, iplen - m->m_pkthdr.len);
	}

	/*
	 * Send the packet on it's way.  All we can get back is ENOBUFS
	 */
#ifdef __QNXNTO__
	/*
	 * XXX
	 * Atomicity.  It's possible (unlikely) that multiple
	 * threads may have a reference to ipf here.  As such
	 * these (non critical) counts may drift.
	 */
#endif
	ipf->ipf_uses++;
	PRT_SLOW_ARM(ipf->ipf_timer, IPFLOW_TIMER);

	if (rt->rt_flags & RTF_GATEWAY)
		dst = rt->rt_gateway;
	else
		dst = &ipf->ipf_ro.ro_dst;

	if ((error = (*rt->rt_ifp->if_output)(rt->rt_ifp, m, dst, rt)) != 0) {
		if (error == ENOBUFS)
			ipf->ipf_dropped++;
		else
			ipf->ipf_errors++;
	}
	return 1;
}

static void
ipflow_addstats(struct ipflow *ipf)
{
	ipf->ipf_ro.ro_rt->rt_use += ipf->ipf_uses;
	ipstat.ips_cantforward += ipf->ipf_errors + ipf->ipf_dropped;
	ipstat.ips_total += ipf->ipf_uses;
	ipstat.ips_forward += ipf->ipf_uses;
	ipstat.ips_fastforward += ipf->ipf_uses;
}

static void
ipflow_free(struct ipflow *ipf)
{
	int s;
#ifndef __QNXNTO__
	/*
	 * Remove the flow from the hash table (at elevated IPL).
	 * Once it's off the list, we can deal with it at normal
	 * network IPL.
	 */
	s = splnet();
	IPFLOW_REMOVE(ipf);
	splx(s);
	ipflow_addstats(ipf);
	RTFREE(ipf->ipf_ro.ro_rt);
	ipflow_inuse--;
#else
	RTFREE(ipf->ipf_ro.ro_rt);
	if (ipf->ipf_gw != NULL)
		RTFREE(ipf->ipf_gw);
#endif
	s = splnet();
	pool_put(&ipflow_pool, ipf);
	splx(s);
}

struct ipflow *
ipflow_reap(int just_one)
{
	while (just_one || ipflow_inuse > ip_maxflows) {
		struct ipflow *ipf, *maybe_ipf = NULL;
#ifndef __QNXNTO__
		int s;
#endif

		ipf = LIST_FIRST(&ipflowlist);
		while (ipf != NULL) {
			/*
			 * If this no longer points to a valid route
			 * reclaim it.
			 */
			if ((ipf->ipf_ro.ro_rt->rt_flags & RTF_UP) == 0)
				goto done;
			/*
			 * choose the one that's been least recently
			 * used or has had the least uses in the
			 * last 1.5 intervals.
			 */
			if (maybe_ipf == NULL ||
			    ipf->ipf_timer < maybe_ipf->ipf_timer ||
			    (ipf->ipf_timer == maybe_ipf->ipf_timer &&
			     ipf->ipf_last_uses + ipf->ipf_uses <
			         maybe_ipf->ipf_last_uses +
			         maybe_ipf->ipf_uses))
				maybe_ipf = ipf;
			ipf = LIST_NEXT(ipf, ipf_list);
		}
		ipf = maybe_ipf;
	    done:
		/*
		 * Remove the entry from the flow table.
		 */
#ifndef __QNXNTO__
		s = splnet();
		IPFLOW_REMOVE(ipf);
		splx(s);
		ipflow_addstats(ipf);
		RTFREE(ipf->ipf_ro.ro_rt);
		if (just_one)
			return ipf;
		pool_put(&ipflow_pool, ipf);
		ipflow_inuse--;
#else
		ipf = ipflow_start_rem(ipf);
		/* ipf may be NULL */
		if (just_one)
			return ipf;
		if (ipf != NULL)
			ipflow_free(ipf);
#endif
	}
	return NULL;
}

#ifdef __QNXNTO__
static void
ipflow_walk_freelist(void)
{
	struct ipflow		*ipf, *next_ipf;
	struct nw_work_thread	*wtp = WTP;

	wtp = WTP;

	if ((ipf = LIST_FIRST(&ipflow_free_list)) != NULL) {

		NW_SIGLOCK_P(&ipflow_ex, iopkt_selfp, wtp);
		next_ipf = LIST_FIRST(&ipflow_free_list);
		LIST_INIT(&ipflow_free_list);
		NW_SIGUNLOCK_P(&ipflow_ex, iopkt_selfp, wtp);

		while ((ipf = next_ipf) != NULL) {
			next_ipf = LIST_NEXT(ipf, ipf_list);
			ipflow_free(ipf);
		}
	}
}
#endif

#ifndef __QNXNTO__
void
#else
int
#endif
ipflow_slowtimo(void)
{
	struct ipflow *ipf, *next_ipf;

#if defined(__QNXNTO__)
	ipflow_walk_freelist();
#endif

	for (ipf = LIST_FIRST(&ipflowlist); ipf != NULL; ipf = next_ipf) {
		next_ipf = LIST_NEXT(ipf, ipf_list);
		if (PRT_SLOW_ISEXPIRED(ipf->ipf_timer)) {
#ifdef __QNXNTO__
			if ((ipf = ipflow_start_rem(ipf)) != NULL)
#endif
			ipflow_free(ipf);
		} else {
			ipf->ipf_last_uses = ipf->ipf_uses;
			ipf->ipf_ro.ro_rt->rt_use += ipf->ipf_uses;
			ipstat.ips_total += ipf->ipf_uses;
			ipstat.ips_forward += ipf->ipf_uses;
			ipstat.ips_fastforward += ipf->ipf_uses;
			ipf->ipf_uses = 0;
		}
	}
#ifdef __QNXNTO__
	return !LIST_EMPTY(&ipflowlist) || !LIST_EMPTY(&ipflow_free_list);
#endif
}

#ifndef __QNXNTO__
void
ipflow_create(const struct route *ro, struct mbuf *m)
{
	const struct ip *const ip = mtod(m, struct ip *);
	struct ipflow *ipf;
	unsigned hash;
	int s;

	/*
	 * Don't create cache entries for ICMP messages.
	 */
	if (ip_maxflows == 0 || ip->ip_p == IPPROTO_ICMP)
		return;
	/*
	 * See if an existing flow struct exists.  If so remove it from it's
	 * list and free the old route.  If not, try to malloc a new one
	 * (if we aren't at our limit).
	 */
	ipf = ipflow_lookup(ip);
	if (ipf == NULL) {
		if (ipflow_inuse >= ip_maxflows) {
			ipf = ipflow_reap(1);
		} else {
			s = splnet();
			ipf = pool_get(&ipflow_pool, PR_NOWAIT);
			splx(s);
			if (ipf == NULL)
				return;
			ipflow_inuse++;
		}
		bzero((caddr_t) ipf, sizeof(*ipf));
	} else {
		s = splnet();
		IPFLOW_REMOVE(ipf);
		splx(s);
		ipflow_addstats(ipf);
		RTFREE(ipf->ipf_ro.ro_rt);
		ipf->ipf_uses = ipf->ipf_last_uses = 0;
		ipf->ipf_errors = ipf->ipf_dropped = 0;
	}

	/*
	 * Fill in the updated information.
	 */
	ipf->ipf_ro = *ro;
	ro->ro_rt->rt_refcnt++;
	ipf->ipf_dst = ip->ip_dst;
	ipf->ipf_src = ip->ip_src;
	ipf->ipf_tos = ip->ip_tos;
	PRT_SLOW_ARM(ipf->ipf_timer, IPFLOW_TIMER);
	ipf->ipf_start = time_uptime;
	/*
	 * Insert into the approriate bucket of the flow table.
	 */
	hash = ipflow_hash(ip->ip_dst, ip->ip_src, ip->ip_tos);
	s = splnet();
	IPFLOW_INSERT(&ipflowtable[hash], ipf);
	splx(s);
}
#else /* __QNXNTO__ */
void
ipflow_create(const struct route *ro, struct mbuf *m)
{
	const struct ip			*ip;
	struct ipflow			*ipf;
	unsigned			hash;
	struct nw_work_thread		*wtp;
	int				self, if_type;
	struct ipflow_threadinfo	*ipftip;
	struct nw_stk_ctl		*sctlp;
	struct rtentry			*rt0, *rt;
#ifndef VARIANT_uni
	struct ipflow_threadinfo	*ipftip_tmp;
	int i;
#endif

	wtp = WTP;
	ipftip = wtp->flowctl;
	self = ipftip->ipfti_idx;
	sctlp = &stk_ctl;

	ipflow_walk_freelist();

	ip = mtod(m, struct ip *);

	if (sctlp->fastforward == 0)
		return;
	/*
	 * Don't create cache entries for ICMP messages.
	 */
	if (ip_maxflows == 0 || ip->ip_p == IPPROTO_ICMP)
		return;

	/*
	 * We (QNX) don't have any locking on any routing
	 * structures so we have to make sure they're only
	 * referenced in the stack context.  To this end we
	 * put a restriction on the target interface type
	 * and make sure the final link address is fully
	 * resolved before setting up the flow: we don't want
	 * arpresolve() called from an interrupt context for
	 * example.
	 *
	 * This will have to be looked at on a per target
	 * interface type for performance impact.  If one
	 * considers forwarding out a tunnel interface, they
	 * often call ip_output() again at some point (also not
	 * interrupt context safe) so the extra overhead of
	 * coming in through the stack proper rather than the
	 * fast flow path becomes less significant.
	 */

	rt0 = rt = ro->ro_rt;
	if ((rt->rt_flags & RTF_UP) == 0)
		return;

	if (rt->rt_flags & RTF_GATEWAY) {
		if (rt->rt_gwroute == 0)
			return;
		if ((rt = rt->rt_gwroute) == NULL ||
		    (rt->rt_flags & RTF_UP) == 0)
			return;
	}

	if (rt->rt_ifp == NULL || (rt->rt_flags & RTF_REJECT))
		return;

	if_type = rt->rt_ifp->if_type;
	switch (if_type) {
	case IFT_ETHER:
	case IFT_L2VLAN:
		if (!arp_isresolved(rt))
			return;
		break;

	default:
		return;
	}



	/*
	 * See if an existing flow struct exists.  If so
	 * remove it from its list and free the old route.
	 * If not, try to malloc a new one (if we aren't at
	 * our limit).
	 */

	/* lookup in master (stack's) hash table */
	if (((ipf = ipflow_lookup(ip, ipflowtable)) != NULL &&
	    (ipf = ipflow_start_rem(ipf)) != NULL) ||
	    (ipflow_inuse >= ip_maxflows && (ipf = ipflow_reap(1)) != NULL)) {
		RTFREE(ipf->ipf_ro.ro_rt);
		if (ipf->ipf_gw != NULL)
			RTFREE(ipf->ipf_gw);
		ipf->ipf_uses = ipf->ipf_last_uses = 0;
		ipf->ipf_errors = ipf->ipf_dropped = 0;
	} else {
		ipf = pool_get(&ipflow_pool, PR_NOWAIT);
		if (ipf == NULL)
			return;
		/*
		 * Watch out.
		 *
		 * We don't memset the variable number of pass / hash list
		 * entries at the end of the ipflow structure.  This means
		 * we have to be deligent about resetting the members we're
		 * interested in as ipflow entries are removed from these per 
		 * thread lists.  Currently that's ipf_thread.ipf_pass.le_prev.
		 */
		memset(ipf, 0x00, offsetof(struct ipflow, ipf_thread));
	}
	ipflow_inuse++;

	/*
	 * Fill in the updated information.
	 */
	ipf->ipf_ro = *ro;
	ro->ro_rt->rt_refcnt++;
	if (rt != rt0) {
		ipf->ipf_gw = rt;
		rt->rt_refcnt++;
	}
	else {
		ipf->ipf_gw = NULL;
	}
	ipf->ipf_dst = ip->ip_dst;
	ipf->ipf_src = ip->ip_src;
	ipf->ipf_tos = ip->ip_tos;
	PRT_SLOW_ARM(ipf->ipf_timer, IPFLOW_TIMER);
	ipf->ipf_start = TIME.tv_sec;
	/*
	 * Insert into the approriate bucket of the flow table.
	 */
	hash = ipflow_hash(ip->ip_dst.s_addr, ip->ip_src.s_addr, ip->ip_tos);
	ipf->hash = hash;
	IPFLOW_INSERT(&ipflowtable[hash], ipf); /* hash of stack proper */
	pfslowtimo_kick();

	NW_SIGHOLD_P(wtp);
#ifndef VARIANT_uni
	NW_EX_LK(&ipflow_ex, iopkt_selfp);

	/* Poke each thread into seeding their private hash */
	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		/*
		 * We don't check inuse.  If start_rem()
		 * sees that this never makes it off the
		 * createq, it's done.  If it sees it's
		 * not on any q, it assumes it's inuse by
		 * this thread.
		 */
		ipftip_tmp = &ipflow_threads[i];
		if (ipftip_tmp == ipftip)
			continue;

		LIST_INSERT_HEAD(&ipftip_tmp->ipfti_tpq.tpq_create_q, ipf,
		    ipf_thread[i].ipf_th_passlist);
		ipf->ipf_tpe.tpe_nthreads_creating++;
		ipftip_tmp->ipfti_tpq.tpq_items_changing++;
	}

	NW_EX_UNLK(&ipflow_ex, iopkt_selfp);
#endif
	IPFLOW_INSERT_HEAD_HASH_PRIVATE(wtp->flowctl, ipf, self);

	NW_SIGUNHOLD_P(wtp);
}
#endif /* __QNXNTO__ */

void
ipflow_invalidate_all(void)
{
	struct ipflow *ipf, *next_ipf;
	int s;

	s = splnet();
	for (ipf = LIST_FIRST(&ipflowlist); ipf != NULL; ipf = next_ipf) {
		next_ipf = LIST_NEXT(ipf, ipf_list);
#ifdef __QNXNTO__
		if ((ipf = ipflow_start_rem(ipf)) != NULL)
#endif
		ipflow_free(ipf);
	}
	splx(s);
}

#ifdef __QNXNTO__
#ifndef VARIANT_uni
static void
ipflow_walk_destroy_q(struct ipflow_threadinfo *ipftip, int idx)
{
	struct ipflow		*ipf;
	struct ipflow_thread	*ipfth;

	while ((ipf = LIST_FIRST(&ipftip->ipfti_tpq.tpq_destroy_q)) != NULL) {
		ipfth = &ipf->ipf_thread[idx];

		LIST_FIRST(&ipftip->ipfti_tpq.tpq_destroy_q) =
		    LIST_NEXT(ipfth, ipf_th_passlist);
		IPF_MARK_OFFLIST(ipfth);

		ipftip->ipfti_tpq.tpq_items_changing--;

		IPFLOW_REMOVE_HASH_PRIVATE(ipf, idx);

		if (--ipf->ipf_tpe.tpe_nthreads_destroying == 0) {
			/*
			 * Could ipflow_free() if we're also
			 * the stack but probably better to
			 * do as little work as possible with
			 * the mutex in either case.
			 */
			LIST_INSERT_HEAD(&ipflow_free_list, ipf, ipf_list);
			pfslowtimo_kick();
		}
	}
}
#endif


static struct ipflow *
ipflow_start_rem(struct ipflow *ipf)
{
	int self;
	struct nw_work_thread *wtp;
	struct ipflow_threadinfo *ipftip;
#ifndef VARIANT_uni
	union ipflow_passq return_q;
	struct ipflow_thread *ipfth;
#endif

	wtp = WTP;
	ipftip = wtp->flowctl;
	self = ipftip->ipfti_idx;

	if (!ISSTACK_P(wtp))
		panic("ipflow: remove started without stack.\n");

	IPFLOW_REMOVE(ipf);
	ipflow_addstats(ipf);
	ipflow_inuse--;

#ifdef VARIANT_uni
	NW_SIGHOLD_P(wtp);
	/*
	 * The work done by the ipf_thread_decref() passed
	 * to tpass_start_rem() in non uni variant below.
	 */
	IPFLOW_REMOVE_HASH_PRIVATE(ipf, self);
	NW_SIGUNHOLD_P(wtp);
#else
	tpass_start_rem(&ipf->ipf_tpe,
	    &ipflow_threads[0].ipfti_tpqu.tpq_private,
	    &return_q.tpq_private,
	    self, &ipflow_tpass_reminfo);

	while ((ipf = LIST_FIRST(&return_q.tpq_local.tpq_destroy_q)) != NULL) {
		ipfth = &ipf->ipf_thread[self];
		LIST_FIRST(&return_q.tpq_local.tpq_destroy_q) =
		    LIST_NEXT(ipfth, ipf_th_passlist);
		IPF_MARK_OFFLIST(ipfth);

		return_q.tpq_local.tpq_items_changing--;

		if (LIST_EMPTY(&return_q.tpq_local.tpq_destroy_q))
			break;

		ipflow_free(ipf);
	}
#endif

	return ipf;
}
#endif /* __QNXNTO__ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/ip_flow.c $ $Rev: 884515 $")
#endif
