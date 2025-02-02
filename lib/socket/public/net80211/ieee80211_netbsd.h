/* $NetBSD: ieee80211_netbsd.h,v 1.10 2006/03/02 03:38:48 dyoung Exp $ */
/*-
 * Copyright (c) 2003-2005 Sam Leffler, Errno Consulting
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net80211/ieee80211_freebsd.h,v 1.6 2005/08/08 18:46:36 sam Exp $
 */
#ifndef _NET80211_IEEE80211_NETBSD_H_INCLUDED
#define _NET80211_IEEE80211_NETBSD_H_INCLUDED

#ifndef _NET_IF_H_INCLUDED
#include <net/if.h>
#endif
#ifndef _INTTYPES_H_INCLUDED
#include <inttypes.h>
#endif
#ifndef __QUEUE_H_INCLUDED
#include <sys/queue.h>
#endif

struct mbuf;

#ifdef _KERNEL
#define	IASSERT(__cond, __complaint)	 	\
	do {				 	\
		if (!(__cond))		 	\
			panic __complaint ;	\
	} while (0)

void if_printf(struct ifnet *, const char *, ...)
    __attribute__((__format__(__printf__,2,3)));
#endif

struct ieee80211_lock {
	int count;
	int ipl;
};
#ifdef _KERNEL
#define	IEEE80211_LOCK_INIT_IMPL(_ic, _name, _member)	\
	do {						\
		(_ic)->_member.count = 0;		\
	} while (0)
#define	IEEE80211_LOCK_IMPL(_ic, _member)		\
	do {						\
		int __s = splnet();			\
		if ((_ic)->_member.count++ == 0)	\
			(_ic)->_member.ipl = __s;	\
	} while (0)
#define IEEE80211_IS_LOCKED_IMPL(_ic, _member)          \
        ((_ic)->_member.count != 0)
#define	IEEE80211_UNLOCK_IMPL(_ic, _member)		\
	do {						\
		if (--(_ic)->_member.count == 0)	\
			splx((_ic)->_member.ipl);	\
	} while (0)
#define	IEEE80211_LOCK_ASSERT_IMPL(_ic, _member)	\
	IASSERT((_ic)->_member.count > 0,		\
	    ("%s: IEEE80211_LOCK not held", __func__));
#endif

/*
 * Beacon locking definitions.
 */
typedef struct ieee80211_lock ieee80211_beacon_lock_t;
#ifdef _KERNEL
#define	IEEE80211_BEACON_LOCK_INIT(_ic, _name)		\
	IEEE80211_LOCK_INIT_IMPL(_ic, _name, ic_beaconlock)
#define	IEEE80211_BEACON_LOCK_DESTROY(_ic)
#define	IEEE80211_BEACON_LOCK(_ic)			\
	IEEE80211_LOCK_IMPL(_ic, ic_beaconlock)
#define	IEEE80211_BEACON_UNLOCK(_ic)			\
	IEEE80211_UNLOCK_IMPL(_ic, ic_beaconlock)
#define	IEEE80211_BEACON_LOCK_ASSERT(_ic)		\
	IEEE80211_LOCK_ASSERT_IMPL(_ic, ic_beaconlock)
#endif

/*
 * Node locking definitions.
 * NB: MTX_DUPOK is because we don't generate per-interface strings.
 */
typedef struct ieee80211_lock ieee80211_node_lock_t;
#ifdef _KERNEL
#define	IEEE80211_NODE_LOCK_INIT(_nt, _name)		\
	IEEE80211_LOCK_INIT_IMPL(_nt, _name, nt_nodelock)
#define	IEEE80211_NODE_LOCK_DESTROY(_nt)
#define	IEEE80211_NODE_LOCK(_nt)			\
	IEEE80211_LOCK_IMPL(_nt, nt_nodelock)
#define IEEE80211_NODE_IS_LOCKED(_nt)                   \
        IEEE80211_IS_LOCKED_IMPL(_nt, nt_nodelock)
#define	IEEE80211_NODE_UNLOCK(_nt)			\
	IEEE80211_UNLOCK_IMPL(_nt, nt_nodelock)
#define	IEEE80211_NODE_LOCK_ASSERT(_nt)			\
	IEEE80211_LOCK_ASSERT_IMPL(_nt, nt_nodelock)
#endif

/*
 * Node table scangen locking definitions.
 */
typedef struct ieee80211_lock ieee80211_scan_lock_t;
#ifdef _KERNEL
#define	IEEE80211_SCAN_LOCK_INIT(_nt, _name)		\
	IEEE80211_LOCK_INIT_IMPL(_nt, _name, nt_scanlock)
#define	IEEE80211_SCAN_LOCK_DESTROY(_nt)
#define	IEEE80211_SCAN_LOCK(_nt)			\
	IEEE80211_LOCK_IMPL(_nt, nt_scanlock)
#define	IEEE80211_SCAN_UNLOCK(_nt)			\
	IEEE80211_UNLOCK_IMPL(_nt, nt_scanlock)
#define	IEEE80211_SCAN_LOCK_ASSERT(_nt)			\
	IEEE80211_LOCK_ASSERT_IMPL(_nt, nt_scanlock)

/*
 * Per-node power-save queue definitions. 
 */
#define	IEEE80211_NODE_SAVEQ_INIT(_ni, _name) do {		\
	(_ni)->ni_savedq.ifq_maxlen = IEEE80211_PS_MAX_QUEUE;	\
} while (0)
#define	IEEE80211_NODE_SAVEQ_DESTROY(_ni)
#define	IEEE80211_NODE_SAVEQ_QLEN(_ni)	((_ni)->ni_savedq.ifq_len)
#define	IEEE80211_NODE_SAVEQ_LOCK(_ni)
#define	IEEE80211_NODE_SAVEQ_UNLOCK(_ni)
#define	IEEE80211_NODE_SAVEQ_DEQUEUE(_ni, _m, _qlen) do {	\
	IEEE80211_NODE_SAVEQ_LOCK(_ni);				\
	IF_DEQUEUE(&(_ni)->ni_savedq, _m);			\
	(_qlen) = IEEE80211_NODE_SAVEQ_QLEN(_ni);		\
	IEEE80211_NODE_SAVEQ_UNLOCK(_ni);			\
} while (0)
#define	IEEE80211_NODE_SAVEQ_DRAIN(_ni, _qlen) do {		\
	IEEE80211_NODE_SAVEQ_LOCK(_ni);				\
	(_qlen) = IEEE80211_NODE_SAVEQ_QLEN(_ni);		\
	IF_PURGE(&(_ni)->ni_savedq);				\
	IEEE80211_NODE_SAVEQ_UNLOCK(_ni);			\
} while (0)
/* XXX could be optimized */
#define	_IEEE80211_NODE_SAVEQ_DEQUEUE_HEAD(_ni, _m) do {	\
	IF_DEQUEUE(&(_ni)->ni_savedq, m);			\
} while (0)
#define	_IEEE80211_NODE_SAVEQ_ENQUEUE(_ni, _m, _qlen, _age) do {\
	(_m)->m_nextpkt = NULL;					\
	if ((_ni)->ni_savedq.ifq_tail != NULL) { 		\
		_age -= M_AGE_GET((_ni)->ni_savedq.ifq_tail);	\
		(_ni)->ni_savedq.ifq_tail->m_nextpkt = (_m);	\
	} else { 						\
		(_ni)->ni_savedq.ifq_head = (_m); 		\
	}							\
	M_AGE_SET(_m, _age);					\
	(_ni)->ni_savedq.ifq_tail = (_m); 			\
	(_qlen) = ++(_ni)->ni_savedq.ifq_len; 			\
} while (0)
#endif

/*
 * 802.1x MAC ACL database locking definitions.
 */
typedef struct ieee80211_lock acl_lock_t;
#ifdef _KERNEL
#define	ACL_LOCK_INIT(_as, _name)	\
	IEEE80211_LOCK_INIT_IMPL(_as, _name, as_lock)
#define	ACL_LOCK_DESTROY(_as)
#define	ACL_LOCK(_as)			IEEE80211_LOCK_IMPL(_as, as_lock)
#define	ACL_UNLOCK(_as)			IEEE80211_UNLOCK_IMPL(_as, as_lock)
#define	ACL_LOCK_ASSERT(_as)		IEEE80211_LOCK_ASSERT_IMPL(_as, as_lock)

/*
 * Node reference counting definitions.
 *
 * ieee80211_node_initref	initialize the reference count to 1
 * ieee80211_node_incref	add a reference
 * ieee80211_node_decref	remove a reference
 * ieee80211_node_dectestref	remove a reference and return 1 if this
 *				is the last reference, otherwise 0
 * ieee80211_node_refcnt	reference count for printing (only)
 */

#define ieee80211_node_initref(_ni) \
	do { ((_ni)->ni_refcnt = 1); } while (0)
#define ieee80211_node_incref(_ni) \
	do { (_ni)->ni_refcnt++; } while (0)
#define	ieee80211_node_decref(_ni) \
	do { (_ni)->ni_refcnt--; } while (0)
struct ieee80211_node;
int ieee80211_node_dectestref(struct ieee80211_node *ni);
#define	ieee80211_node_refcnt(_ni)	(_ni)->ni_refcnt

struct mbuf *ieee80211_getmgtframe(uint8_t **frm, unsigned pktlen);
#define	M_PWR_SAV	M_PROTO1		/* bypass PS handling */
#define	M_MORE_DATA	M_LINK3			/* more data frames to follow */
#define	M_FRAG		M_LINK4			/* 802.11 fragment */
#define	M_FIRSTFRAG	M_LINK5			/* first 802.11 fragment */
#define	M_FF		M_LINK6			/* "fast frames" */
/*
 * Encode WME access control bits in the PROTO flags.
 * This is safe since it's passed directly in to the
 * driver and there's no chance someone else will clobber
 * them on us.
 */
#define	M_WME_AC_MASK	(M_LINK1|M_LINK2)
/* XXX 5 is wrong if M_LINK* are redefined */
#define	M_WME_AC_SHIFT	13

#define	M_WME_SETAC(m, ac) \
	((m)->m_flags = ((m)->m_flags &~ M_WME_AC_MASK) | \
		((ac) << M_WME_AC_SHIFT))
#define	M_WME_GETAC(m)	(((m)->m_flags >> M_WME_AC_SHIFT) & 0x3)

/*
 * Mbufs on the power save queue are tagged with an age and
 * timed out.  We reuse the hardware checksum field in the
 * mbuf packet header to store this data.
 */
#define	M_AGE_SET(m,v)		(m->m_pkthdr.csum_data = v)
#define	M_AGE_GET(m)		(m->m_pkthdr.csum_data)
#define	M_AGE_SUB(m,adj)	(m->m_pkthdr.csum_data -= adj)
#endif /* _KERNEL */

struct ieee80211com;

/* XXX this stuff belongs elsewhere */
/*
 * Message formats for messages from the net80211 layer to user
 * applications via the routing socket.  These messages are appended
 * to an if_announcemsghdr structure.
 */
struct ieee80211_join_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_leave_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_replay_event {
	uint8_t		iev_src[6];	/* src MAC */
	uint8_t		iev_dst[6];	/* dst MAC */
	uint8_t		iev_cipher;	/* cipher type */
	uint8_t		iev_keyix;	/* key id/index */
	uint64_t	iev_keyrsc;	/* RSC from key */
	uint64_t	iev_rsc;	/* RSC from frame */
};

struct ieee80211_michael_event {
	uint8_t		iev_src[6];	/* src MAC */
	uint8_t		iev_dst[6];	/* dst MAC */
	uint8_t		iev_cipher;	/* cipher type */
	uint8_t		iev_keyix;	/* key id/index */
};

#define	RTM_IEEE80211_ASSOC	100	/* station associate (bss mode) */
#define	RTM_IEEE80211_REASSOC	101	/* station re-associate (bss mode) */
#define	RTM_IEEE80211_DISASSOC	102	/* station disassociate (bss mode) */
#define	RTM_IEEE80211_JOIN	103	/* station join (ap mode) */
#define	RTM_IEEE80211_LEAVE	104	/* station leave (ap mode) */
#define	RTM_IEEE80211_SCAN	105	/* scan complete, results available */
#define	RTM_IEEE80211_REPLAY	106	/* sequence counter replay detected */
#define	RTM_IEEE80211_MICHAEL	107	/* Michael MIC failure detected */
#define	RTM_IEEE80211_REJOIN	108	/* station re-associate (ap mode) */

#define	__offsetof	offsetof
#define	ticks	hardclock_ticks
#define	ovbcopy(__src, __dst, __n)	((void)memmove(__dst, __src, __n))

void	if_printf(struct ifnet *, const char *, ...);
void	m_align(struct mbuf *, int);
int	m_append(struct mbuf *, int, const caddr_t);
void	get_random_bytes(void *, size_t);

void	ieee80211_sysctl_attach(struct ieee80211com *);
void	ieee80211_sysctl_detach(struct ieee80211com *);
void	ieee80211_load_module(const char *);

void	ieee80211_init(void);
#define	IEEE80211_CRYPTO_SETUP(name)				\
	static void name(void);					\
	__link_set_add_text(ieee80211_funcs, name);		\
	static void name(void)

#endif /* !_NET80211_IEEE80211_NETBSD_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/net80211/ieee80211_netbsd.h $ $Rev: 680336 $")
#endif
