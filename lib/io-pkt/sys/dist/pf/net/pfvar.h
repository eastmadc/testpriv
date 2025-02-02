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

/*	$NetBSD: pfvar.h,v 1.12 2006/06/07 22:33:38 kardel Exp $	*/
/*	$OpenBSD: pfvar.h,v 1.213 2005/03/03 07:13:39 dhartmei Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _NET_PFVAR_H_INCLUDED
#define _NET_PFVAR_H_INCLUDED

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <net/radix.h>
#ifdef __OpenBSD__
#include <net/route.h>
#include <netinet/ip_ipsp.h>
#include <sys/mbuf.h>
#else
#include <netinet/in.h>
#endif
#include <netinet/tcp_fsm.h>

#if defined(__NetBSD__) || defined(__QNXNTO__)
union sockaddr_union {
	struct sockaddr         sa;
	struct sockaddr_in      sin;
	struct sockaddr_in6     sin6;
};
#endif

struct ip;

#define	PF_TCPS_PROXY_SRC	((TCP_NSTATES)+0)
#define	PF_TCPS_PROXY_DST	((TCP_NSTATES)+1)

enum	{ PF_INOUT, PF_IN, PF_OUT };
enum	{ PF_LAN_EXT, PF_EXT_GWY, PF_ID };
enum	{ PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
	  PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP };
enum	{ PF_RULESET_SCRUB, PF_RULESET_FILTER, PF_RULESET_NAT,
	  PF_RULESET_BINAT, PF_RULESET_RDR, PF_RULESET_MAX };
enum	{ PF_OP_NONE, PF_OP_IRG, PF_OP_EQ, PF_OP_NE, PF_OP_LT,
	  PF_OP_LE, PF_OP_GT, PF_OP_GE, PF_OP_XRG, PF_OP_RRG };
enum	{ PF_DEBUG_NONE, PF_DEBUG_URGENT, PF_DEBUG_MISC, PF_DEBUG_NOISY };
enum	{ PF_CHANGE_NONE, PF_CHANGE_ADD_HEAD, PF_CHANGE_ADD_TAIL,
	  PF_CHANGE_ADD_BEFORE, PF_CHANGE_ADD_AFTER,
	  PF_CHANGE_REMOVE, PF_CHANGE_GET_TICKET };
/*
 * Note about PFTM_*: real indices into pf_rule.timeout[] come before
 * PFTM_MAX, special cases afterwards. See pf_state_expires().
 */
enum	{ PFTM_TCP_FIRST_PACKET, PFTM_TCP_OPENING, PFTM_TCP_ESTABLISHED,
	  PFTM_TCP_CLOSING, PFTM_TCP_FIN_WAIT, PFTM_TCP_CLOSED,
	  PFTM_UDP_FIRST_PACKET, PFTM_UDP_SINGLE, PFTM_UDP_MULTIPLE,
	  PFTM_ICMP_FIRST_PACKET, PFTM_ICMP_ERROR_REPLY,
	  PFTM_OTHER_FIRST_PACKET, PFTM_OTHER_SINGLE,
	  PFTM_OTHER_MULTIPLE, PFTM_FRAG, PFTM_INTERVAL,
	  PFTM_ADAPTIVE_START, PFTM_ADAPTIVE_END, PFTM_SRC_NODE,
	  PFTM_TS_DIFF, PFTM_MAX, PFTM_PURGE, PFTM_UNTIL_PACKET };

/* PFTM default values */
#define PFTM_TCP_FIRST_PACKET_VAL	120	/* First TCP packet */
#define PFTM_TCP_OPENING_VAL		30	/* No response yet */
#define PFTM_TCP_ESTABLISHED_VAL	24*60*60/* Established */
#define PFTM_TCP_CLOSING_VAL		15 * 60	/* Half closed */
#define PFTM_TCP_FIN_WAIT_VAL		45	/* Got both FINs */
#define PFTM_TCP_CLOSED_VAL		90	/* Got a RST */
#define PFTM_UDP_FIRST_PACKET_VAL	60	/* First UDP packet */
#define PFTM_UDP_SINGLE_VAL		30	/* Unidirectional */
#define PFTM_UDP_MULTIPLE_VAL		60	/* Bidirectional */
#define PFTM_ICMP_FIRST_PACKET_VAL	20	/* First ICMP packet */
#define PFTM_ICMP_ERROR_REPLY_VAL	10	/* Got error response */
#define PFTM_OTHER_FIRST_PACKET_VAL	60	/* First packet */
#define PFTM_OTHER_SINGLE_VAL		30	/* Unidirectional */
#define PFTM_OTHER_MULTIPLE_VAL		60	/* Bidirectional */
#define PFTM_FRAG_VAL			30	/* Fragment expire */
#define PFTM_INTERVAL_VAL		10	/* Expire interval */
#define PFTM_SRC_NODE_VAL		0	/* Source tracking */
#define PFTM_TS_DIFF_VAL		30	/* Allowed TS diff */

enum	{ PF_NOPFROUTE, PF_FASTROUTE, PF_ROUTETO, PF_DUPTO, PF_REPLYTO };
enum	{ PF_LIMIT_STATES, PF_LIMIT_SRC_NODES, PF_LIMIT_FRAGS, PF_LIMIT_MAX };
#define PF_POOL_IDMASK		0x0f
enum	{ PF_POOL_NONE, PF_POOL_BITMASK, PF_POOL_RANDOM,
	  PF_POOL_SRCHASH, PF_POOL_ROUNDROBIN };
enum	{ PF_ADDR_ADDRMASK, PF_ADDR_NOROUTE, PF_ADDR_DYNIFTL,
	  PF_ADDR_TABLE, PF_ADDR_RTLABEL };
#define PF_POOL_TYPEMASK	0x0f
#define PF_POOL_STICKYADDR	0x20
#define	PF_WSCALE_FLAG		0x80
#define	PF_WSCALE_MASK		0x0f

struct pf_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} pfa;		    /* 128-bit address */
#define v4	pfa.v4
#define v6	pfa.v6
#define addr8	pfa.addr8
#define addr16	pfa.addr16
#define addr32	pfa.addr32
};

#define	PF_TABLE_NAME_SIZE	 32

#define PFI_AFLAG_NETWORK	0x01
#define PFI_AFLAG_BROADCAST	0x02
#define PFI_AFLAG_PEER		0x04
#define PFI_AFLAG_MODEMASK	0x07
#define PFI_AFLAG_NOALIAS	0x08

#ifndef RTLABEL_LEN
#define RTLABEL_LEN	32
#endif

struct pf_addr_wrap {
	union {
		struct {
			struct pf_addr		 addr;
			struct pf_addr		 mask;
		}			 a;
		char			 ifname[IFNAMSIZ];
		char			 tblname[PF_TABLE_NAME_SIZE];
		char			 rtlabelname[RTLABEL_LEN];
		uint32_t		 rtlabel;
	}			 v;
	union {
		struct pfi_dynaddr	*dyn;
		struct pfr_ktable	*tbl;
		int			 dyncnt;
		int			 tblcnt;
	}			 p;
	uint8_t			 type;		/* PF_ADDR_* */
	uint8_t			 iflags;	/* PFI_AFLAG_* */
};

#if defined(__NetBSD__) || defined(__QNXNTO__)
struct hook_desc {
	TAILQ_ENTRY(hook_desc) hd_list;
	void	(*hd_fn)(void *);
	void	*hd_arg;
};
TAILQ_HEAD(hook_desc_head, hook_desc);
#endif

#ifdef _KERNEL

struct pfi_dynaddr {
	struct pf_addr		 pfid_addr4;
	struct pf_addr		 pfid_mask4;
	struct pf_addr		 pfid_addr6;
	struct pf_addr		 pfid_mask6;
	struct pfr_ktable	*pfid_kt;
	struct pfi_kif		*pfid_kif;
	void			*pfid_hook_cookie;
	int			 pfid_net;	/* optional mask, or 128 */
	int			 pfid_acnt4;	/* address count, IPv4 */
	int			 pfid_acnt6;	/* address count, IPv6 */
	sa_family_t		 pfid_af;	/* rule address family */
	u_int8_t		 pfid_iflags;	/* PFI_AFLAG_* */
};

/*
 * Address manipulation macros
 */

#ifdef INET
#ifndef INET6
#define PF_INET_ONLY
#endif /* ! INET6 */
#endif /* INET */

#ifdef INET6
#ifndef INET
#define PF_INET6_ONLY
#endif /* ! INET */
#endif /* INET6 */

#ifdef INET
#ifdef INET6
#define PF_INET_INET6
#endif /* INET6 */
#endif /* INET */

#else

#define PF_INET_INET6

#endif /* _KERNEL */

/* Both IPv4 and IPv6 */
#ifdef PF_INET_INET6

#define PF_AEQ(a, b, c) \
	((c == AF_INET && (a)->addr32[0] == (b)->addr32[0]) || \
	((a)->addr32[3] == (b)->addr32[3] && \
	(a)->addr32[2] == (b)->addr32[2] && \
	(a)->addr32[1] == (b)->addr32[1] && \
	(a)->addr32[0] == (b)->addr32[0])) \

#define PF_ANEQ(a, b, c) \
	((c == AF_INET && (a)->addr32[0] != (b)->addr32[0]) || \
	((a)->addr32[3] != (b)->addr32[3] || \
	(a)->addr32[2] != (b)->addr32[2] || \
	(a)->addr32[1] != (b)->addr32[1] || \
	(a)->addr32[0] != (b)->addr32[0])) \

#define PF_AZERO(a, c) \
	((c == AF_INET && !(a)->addr32[0]) || \
	(!(a)->addr32[0] && !(a)->addr32[1] && \
	!(a)->addr32[2] && !(a)->addr32[3] )) \

#define PF_MATCHA(n, a, m, b, f) \
	pf_match_addr(n, a, m, b, f)

#define PF_ACPY(a, b, f) \
	pf_addrcpy(a, b, f)

#define PF_AINC(a, f) \
	pf_addr_inc(a, f)

#define PF_POOLMASK(a, b, c, d, f) \
	pf_poolmask(a, b, c, d, f)

#else

/* Just IPv6 */

#ifdef PF_INET6_ONLY

#define PF_AEQ(a, b, c) \
	((a)->addr32[3] == (b)->addr32[3] && \
	(a)->addr32[2] == (b)->addr32[2] && \
	(a)->addr32[1] == (b)->addr32[1] && \
	(a)->addr32[0] == (b)->addr32[0]) \

#define PF_ANEQ(a, b, c) \
	((a)->addr32[3] != (b)->addr32[3] || \
	(a)->addr32[2] != (b)->addr32[2] || \
	(a)->addr32[1] != (b)->addr32[1] || \
	(a)->addr32[0] != (b)->addr32[0]) \

#define PF_AZERO(a, c) \
	(!(a)->addr32[0] && \
	!(a)->addr32[1] && \
	!(a)->addr32[2] && \
	!(a)->addr32[3] ) \

#define PF_MATCHA(n, a, m, b, f) \
	pf_match_addr(n, a, m, b, f)

#define PF_ACPY(a, b, f) \
	pf_addrcpy(a, b, f)

#define PF_AINC(a, f) \
	pf_addr_inc(a, f)

#define PF_POOLMASK(a, b, c, d, f) \
	pf_poolmask(a, b, c, d, f)

#else

/* Just IPv4 */
#ifdef PF_INET_ONLY

#define PF_AEQ(a, b, c) \
	((a)->addr32[0] == (b)->addr32[0])

#define PF_ANEQ(a, b, c) \
	((a)->addr32[0] != (b)->addr32[0])

#define PF_AZERO(a, c) \
	(!(a)->addr32[0])

#define PF_MATCHA(n, a, m, b, f) \
	pf_match_addr(n, a, m, b, f)

#define PF_ACPY(a, b, f) \
	(a)->v4.s_addr = (b)->v4.s_addr

#define PF_AINC(a, f) \
	do { \
		(a)->addr32[0] = htonl(ntohl((a)->addr32[0]) + 1); \
	} while (0)

#define PF_POOLMASK(a, b, c, d, f) \
	do { \
		(a)->addr32[0] = ((b)->addr32[0] & (c)->addr32[0]) | \
		(((c)->addr32[0] ^ 0xffffffff ) & (d)->addr32[0]); \
	} while (0)

#endif /* PF_INET_ONLY */
#endif /* PF_INET6_ONLY */
#endif /* PF_INET_INET6 */

#ifndef QNX_MFIB
#define	PF_MISMATCHAW(aw, x, af, neg)				\
	(							\
		(((aw)->type == PF_ADDR_NOROUTE &&		\
		    pf_routable((x), (af))) ||			\
		((aw)->type == PF_ADDR_RTLABEL &&		\
		    !pf_rtlabel_match((x), (af), (aw))) ||	\
		((aw)->type == PF_ADDR_TABLE &&			\
		    !pfr_match_addr((aw)->p.tbl, (x), (af))) ||	\
		((aw)->type == PF_ADDR_DYNIFTL &&		\
		    !pfi_match_addr((aw)->p.dyn, (x), (af))) || \
		((aw)->type == PF_ADDR_ADDRMASK &&		\
		    !PF_AZERO(&(aw)->v.a.mask, (af)) &&		\
		    !PF_MATCHA(0, &(aw)->v.a.addr,		\
		    &(aw)->v.a.mask, (x), (af)))) !=		\
		(neg)						\
	)
#else
#define	PF_MISMATCHAW(aw, x, af, neg)				\
	(							\
		(((aw)->type == PF_ADDR_NOROUTE &&		\
		    pf_routable((x), (af), (fib))) ||			\
		((aw)->type == PF_ADDR_RTLABEL &&		\
		    !pf_rtlabel_match((x), (af), (aw), (fib))) ||	\
		((aw)->type == PF_ADDR_TABLE &&			\
		    !pfr_match_addr((aw)->p.tbl, (x), (af))) ||	\
		((aw)->type == PF_ADDR_DYNIFTL &&		\
		    !pfi_match_addr((aw)->p.dyn, (x), (af))) || \
		((aw)->type == PF_ADDR_ADDRMASK &&		\
		    !PF_AZERO(&(aw)->v.a.mask, (af)) &&		\
		    !PF_MATCHA(0, &(aw)->v.a.addr,		\
		    &(aw)->v.a.mask, (x), (af)))) !=		\
		(neg)						\
	)
#endif

struct pf_rule_uid {
	uid_t		 uid[2];
	uint8_t		 op;
};

struct pf_rule_gid {
	uid_t		 gid[2];
	uint8_t		 op;
};

struct pf_rule_addr {
	struct pf_addr_wrap	 addr;
	uint16_t		 port[2];
	uint8_t			 neg;
	uint8_t			 port_op;
};

struct pf_pooladdr {
	struct pf_addr_wrap		 addr;
	TAILQ_ENTRY(pf_pooladdr)	 entries;
	char				 ifname[IFNAMSIZ];
	struct pfi_kif			*kif;
};

TAILQ_HEAD(pf_palist, pf_pooladdr);

struct pf_poolhashkey {
	union {
		uint8_t			key8[16];
		uint16_t		key16[8];
		uint32_t		key32[4];
	} pfk;		    /* 128-bit hash key */
#define key8	pfk.key8
#define key16	pfk.key16
#define key32	pfk.key32
};

struct pf_pool {
	struct pf_palist	 list;
	struct pf_pooladdr	*cur;
	struct pf_poolhashkey	 key;
	struct pf_addr		 counter;
	int			 tblidx;
	uint16_t		 proxy_port[2];
	uint8_t			 port_op;
	uint8_t			 opts;
};


/* A packed Operating System description for fingerprinting */
typedef uint32_t pf_osfp_t;
#define PF_OSFP_ANY	((pf_osfp_t)0)
#define PF_OSFP_UNKNOWN	((pf_osfp_t)-1)
#define PF_OSFP_NOMATCH	((pf_osfp_t)-2)

struct pf_osfp_entry {
	SLIST_ENTRY(pf_osfp_entry) fp_entry;
	pf_osfp_t		fp_os;
	int			fp_enflags;
#define PF_OSFP_EXPANDED	0x001		/* expanded entry */
#define PF_OSFP_GENERIC		0x002		/* generic signature */
#define PF_OSFP_NODETAIL	0x004		/* no p0f details */
#define PF_OSFP_LEN	32
	char			fp_class_nm[PF_OSFP_LEN];
	char			fp_version_nm[PF_OSFP_LEN];
	char			fp_subtype_nm[PF_OSFP_LEN];
};
#define PF_OSFP_ENTRY_EQ(a, b) \
    ((a)->fp_os == (b)->fp_os && \
    memcmp((a)->fp_class_nm, (b)->fp_class_nm, PF_OSFP_LEN) == 0 && \
    memcmp((a)->fp_version_nm, (b)->fp_version_nm, PF_OSFP_LEN) == 0 && \
    memcmp((a)->fp_subtype_nm, (b)->fp_subtype_nm, PF_OSFP_LEN) == 0)

/* handle pf_osfp_t packing */
#define _FP_RESERVED_BIT	1  /* For the special negative #defines */
#define _FP_UNUSED_BITS		1
#define _FP_CLASS_BITS		10 /* OS Class (Windows, Linux) */
#define _FP_VERSION_BITS	10 /* OS version (95, 98, NT, 2.4.54, 3.2) */
#define _FP_SUBTYPE_BITS	10 /* patch level (NT SP4, SP3, ECN patch) */
#define PF_OSFP_UNPACK(osfp, class, version, subtype) do { \
	(class) = ((osfp) >> (_FP_VERSION_BITS+_FP_SUBTYPE_BITS)) & \
	    ((1 << _FP_CLASS_BITS) - 1); \
	(version) = ((osfp) >> _FP_SUBTYPE_BITS) & \
	    ((1 << _FP_VERSION_BITS) - 1);\
	(subtype) = (osfp) & ((1 << _FP_SUBTYPE_BITS) - 1); \
} while(0)
#define PF_OSFP_PACK(osfp, class, version, subtype) do { \
	(osfp) = ((class) & ((1 << _FP_CLASS_BITS) - 1)) << (_FP_VERSION_BITS \
	    + _FP_SUBTYPE_BITS); \
	(osfp) |= ((version) & ((1 << _FP_VERSION_BITS) - 1)) << \
	    _FP_SUBTYPE_BITS; \
	(osfp) |= (subtype) & ((1 << _FP_SUBTYPE_BITS) - 1); \
} while(0)

/* the fingerprint of an OSes TCP SYN packet */
typedef uint64_t	pf_tcpopts_t;
struct pf_os_fingerprint {
	SLIST_HEAD(pf_osfp_enlist, pf_osfp_entry) fp_oses; /* list of matches */
	pf_tcpopts_t		fp_tcpopts;	/* packed TCP options */
	uint16_t		fp_wsize;	/* TCP window size */
	uint16_t		fp_psize;	/* ip->ip_len */
	uint16_t		fp_mss;		/* TCP MSS */
	uint16_t		fp_flags;
#define PF_OSFP_WSIZE_MOD	0x0001		/* Window modulus */
#define PF_OSFP_WSIZE_DC	0x0002		/* Window don't care */
#define PF_OSFP_WSIZE_MSS	0x0004		/* Window multiple of MSS */
#define PF_OSFP_WSIZE_MTU	0x0008		/* Window multiple of MTU */
#define PF_OSFP_PSIZE_MOD	0x0010		/* packet size modulus */
#define PF_OSFP_PSIZE_DC	0x0020		/* packet size don't care */
#define PF_OSFP_WSCALE		0x0040		/* TCP window scaling */
#define PF_OSFP_WSCALE_MOD	0x0080		/* TCP window scale modulus */
#define PF_OSFP_WSCALE_DC	0x0100		/* TCP window scale dont-care */
#define PF_OSFP_MSS		0x0200		/* TCP MSS */
#define PF_OSFP_MSS_MOD		0x0400		/* TCP MSS modulus */
#define PF_OSFP_MSS_DC		0x0800		/* TCP MSS dont-care */
#define PF_OSFP_DF		0x1000		/* IPv4 don't fragment bit */
#define PF_OSFP_TS0		0x2000		/* Zero timestamp */
	uint8_t			fp_optcnt;	/* TCP option count */
	uint8_t			fp_wscale;	/* TCP window scaling */
	uint8_t			fp_ttl;		/* IPv4 TTL */
#define PF_OSFP_MAXTTL_OFFSET	40
/* TCP options packing */
#define PF_OSFP_TCPOPT_NOP	0x0		/* TCP NOP option */
#define PF_OSFP_TCPOPT_WSCALE	0x1		/* TCP window scaling option */
#define PF_OSFP_TCPOPT_MSS	0x2		/* TCP max segment size opt */
#define PF_OSFP_TCPOPT_SACK	0x3		/* TCP SACK OK option */
#define PF_OSFP_TCPOPT_TS	0x4		/* TCP timestamp option */
#define PF_OSFP_TCPOPT_BITS	3		/* bits used by each option */
#define PF_OSFP_MAX_OPTS \
    (sizeof(((struct pf_os_fingerprint *)0)->fp_tcpopts) * 8) \
    / PF_OSFP_TCPOPT_BITS

	SLIST_ENTRY(pf_os_fingerprint)	fp_next;
};

struct pf_osfp_ioctl {
	struct pf_osfp_entry	fp_os;
	pf_tcpopts_t		fp_tcpopts;	/* packed TCP options */
	uint16_t		fp_wsize;	/* TCP window size */
	uint16_t		fp_psize;	/* ip->ip_len */
	uint16_t		fp_mss;		/* TCP MSS */
	uint16_t		fp_flags;
	uint8_t			fp_optcnt;	/* TCP option count */
	uint8_t			fp_wscale;	/* TCP window scaling */
	uint8_t			fp_ttl;		/* IPv4 TTL */

	int			fp_getnum;	/* DIOCOSFPGET number */
};


union pf_rule_ptr {
	struct pf_rule		*ptr;
	uint32_t		 nr;
};

#define	PF_ANCHOR_NAME_SIZE	 64

struct pf_rule {
	struct pf_rule_addr	 src;
	struct pf_rule_addr	 dst;
#define PF_SKIP_IFP		0
#define PF_SKIP_DIR		1
#define PF_SKIP_AF		2
#define PF_SKIP_PROTO		3
#define PF_SKIP_SRC_ADDR	4
#define PF_SKIP_SRC_PORT	5
#define PF_SKIP_DST_ADDR	6
#define PF_SKIP_DST_PORT	7
#define PF_SKIP_COUNT		8
	union pf_rule_ptr	 skip[PF_SKIP_COUNT];
#define PF_RULE_LABEL_SIZE	 64
	char			 label[PF_RULE_LABEL_SIZE];
#define PF_QNAME_SIZE		 16
	char			 ifname[IFNAMSIZ];
	char			 qname[PF_QNAME_SIZE];
	char			 pqname[PF_QNAME_SIZE];
#define	PF_TAG_NAME_SIZE	 16
	char			 tagname[PF_TAG_NAME_SIZE];
	char			 match_tagname[PF_TAG_NAME_SIZE];

	char			 overload_tblname[PF_TABLE_NAME_SIZE];

	TAILQ_ENTRY(pf_rule)	 entries;
	struct pf_pool		 rpool;

	uint64_t		 evaluations;
	uint64_t		 packets;
	uint64_t		 bytes;

	struct pfi_kif		*kif;
	struct pf_anchor	*anchor;
	struct pfr_ktable	*overload_tbl;

	pf_osfp_t		 os_fingerprint;

	uint32_t		 timeout[PFTM_MAX];
	uint32_t		 states;
	uint32_t		 max_states;
	uint32_t		 src_nodes;
	uint32_t		 max_src_nodes;
	uint32_t		 max_src_states;
	uint32_t		 max_src_conn;
	struct {
		uint32_t		limit;
		uint32_t		seconds;
	}			 max_src_conn_rate;
	uint32_t		 qid;
	uint32_t		 pqid;
	uint32_t		 rt_listid;
	uint32_t		 nr;
	uint32_t		 prob;

	uint16_t		 return_icmp;
	uint16_t		 return_icmp6;
	uint16_t		 max_mss;
	uint16_t		 tag;
	uint16_t		 match_tag;

	struct pf_rule_uid	 uid;
	struct pf_rule_gid	 gid;

	uint32_t		 rule_flag;
	uint8_t			 action;
	uint8_t			 direction;
	uint8_t			 log;
	uint8_t			 quick;
	uint8_t			 ifnot;
	uint8_t			 match_tag_not;
	uint8_t			 natpass;

#define PF_STATE_NORMAL		0x1
#define PF_STATE_MODULATE	0x2
#define PF_STATE_SYNPROXY	0x3
	uint8_t			 keep_state;
	sa_family_t		 af;
	uint8_t			 proto;
	uint8_t			 type;
	uint8_t			 code;
	uint8_t			 flags;
	uint8_t			 flagset;
	uint8_t			 min_ttl;
	uint8_t			 allow_opts;
	uint8_t			 rt;
	uint8_t			 return_ttl;
	uint8_t			 tos;
#ifdef __QNXNTO__
	uint8_t			 set_tos;
#endif
	uint8_t			 anchor_relative;
	uint8_t			 anchor_wildcard;

#define PF_FLUSH		0x01
#define PF_FLUSH_GLOBAL		0x02
	uint8_t			 flush;
};

/* rule flags */
#define	PFRULE_DROP		0x0000
#define	PFRULE_RETURNRST	0x0001
#define	PFRULE_FRAGMENT		0x0002
#define	PFRULE_RETURNICMP	0x0004
#define	PFRULE_RETURN		0x0008
#define	PFRULE_NOSYNC		0x0010
#define PFRULE_SRCTRACK		0x0020  /* track source states */
#define PFRULE_RULESRCTRACK	0x0040  /* per rule */

/* scrub flags */
#define	PFRULE_NODF		0x0100
#define	PFRULE_FRAGCROP		0x0200	/* non-buffering frag cache */
#define	PFRULE_FRAGDROP		0x0400	/* drop funny fragments */
#define PFRULE_RANDOMID		0x0800
#define PFRULE_REASSEMBLE_TCP	0x1000
#ifdef __QNXNTO__
#define PFRULE_SET_TOS			0x2000
#endif
/* rule flags again */
#define PFRULE_IFBOUND		0x00010000	/* if-bound */
#define PFRULE_GRBOUND		0x00020000	/* group-bound */

#define PFSTATE_HIWAT		10000	/* default state table size */


struct pf_threshold {
	uint32_t	limit;
#define	PF_THRESHOLD_MULT	1000
#define PF_THRESHOLD_MAX	0xffffffff / PF_THRESHOLD_MULT
	uint32_t	seconds;
	uint32_t	count;
	uint32_t	last;
};

struct pf_src_node {
	RB_ENTRY(pf_src_node) entry;
	struct pf_addr	 addr;
	struct pf_addr	 raddr;
	union pf_rule_ptr rule;
	struct pfi_kif	*kif;
	uint32_t	 bytes;
	uint32_t	 packets;
	uint32_t	 states;
	uint32_t	 conn;
	struct pf_threshold	conn_rate;
	uint32_t	 creation;
	uint32_t	 expire;
	sa_family_t	 af;
	uint8_t		 ruletype;
};

#define PFSNODE_HIWAT		10000	/* default source node table size */

struct pf_state_scrub {
	struct timeval	pfss_last;	/* time received last packet	*/
	uint32_t	pfss_tsecr;	/* last echoed timestamp	*/
	uint32_t	pfss_tsval;	/* largest timestamp		*/
	uint32_t	pfss_tsval0;	/* original timestamp		*/
	uint16_t	pfss_flags;
#define PFSS_TIMESTAMP	0x0001		/* modulate timestamp		*/
#define PFSS_PAWS	0x0010		/* stricter PAWS checks		*/
#define PFSS_PAWS_IDLED	0x0020		/* was idle too long.  no PAWS	*/
#define PFSS_DATA_TS	0x0040		/* timestamp on data packets	*/
#define PFSS_DATA_NOTS	0x0080		/* no timestamp on data packets	*/
	uint8_t		pfss_ttl;	/* stashed TTL			*/
	uint8_t		pad;
	uint32_t	pfss_ts_mod;	/* timestamp modulation		*/
};

struct pf_state_host {
	struct pf_addr	addr;
	uint16_t	port;
	uint16_t	pad;
};

struct pf_state_peer {
	uint32_t	seqlo;		/* Max sequence number sent	*/
	uint32_t	seqhi;		/* Max the other end ACKd + win	*/
	uint32_t	seqdiff;	/* Sequence number modulator	*/
	uint16_t	max_win;	/* largest window (pre scaling)	*/
	uint8_t		state;		/* active state level		*/
	uint8_t		wscale;		/* window scaling factor	*/
	uint16_t	mss;		/* Maximum segment size option	*/
	struct pf_state_scrub	*scrub;	/* state is scrubbed		*/
};

TAILQ_HEAD(pf_state_queue, pf_state);

struct pf_state {
	uint64_t	 id;
	union {
		struct {
			RB_ENTRY(pf_state)	 entry_lan_ext;
			RB_ENTRY(pf_state)	 entry_ext_gwy;
			RB_ENTRY(pf_state)	 entry_id;
			TAILQ_ENTRY(pf_state)	 entry_updates;
			struct pfi_kif		*kif;
		} s;
		char	 ifname[IFNAMSIZ];
	} u;
	struct pf_state_host lan;
	struct pf_state_host gwy;
	struct pf_state_host ext;
	struct pf_state_peer src;
	struct pf_state_peer dst;
	union pf_rule_ptr rule;
	union pf_rule_ptr anchor;
	union pf_rule_ptr nat_rule;
	struct pf_addr	 rt_addr;
	struct pfi_kif	*rt_kif;
	struct pf_src_node	*src_node;
	struct pf_src_node	*nat_src_node;
	uint32_t	 creation;
	uint32_t	 expire;
	uint32_t	 pfsync_time;
	uint32_t	 packets[2];
	uint32_t	 bytes[2];
	uint32_t	 creatorid;
	uint16_t	 tag;
	sa_family_t	 af;
	uint8_t		 proto;
	uint8_t		 direction;
	uint8_t		 log;
	uint8_t		 allow_opts;
	uint8_t		 timeout;
	uint8_t		 sync_flags;
#define	PFSTATE_NOSYNC	 0x01
#define	PFSTATE_FROMSYNC 0x02
#define	PFSTATE_STALE	 0x04
#ifndef QNX_MFIB
	uint8_t		 pad;
#else
	uint8_t		pf_fib;
#endif
};

TAILQ_HEAD(pf_rulequeue, pf_rule);

struct pf_anchor;

struct pf_ruleset {
	struct {
		struct pf_rulequeue	 queues[2];
		struct {
			struct pf_rulequeue	*ptr;
			uint32_t		 ticket;
			int			 open;
		}			 active, inactive;
	}			 rules[PF_RULESET_MAX];
	struct pf_anchor	*anchor;
	uint32_t		 tticket;
	int			 tables;
	int			 topen;
};

RB_HEAD(pf_anchor_global, pf_anchor);
RB_HEAD(pf_anchor_node, pf_anchor);
struct pf_anchor {
	RB_ENTRY(pf_anchor)	 entry_global;
	RB_ENTRY(pf_anchor)	 entry_node;
	struct pf_anchor	*parent;
	struct pf_anchor_node	 children;
	char			 name[PF_ANCHOR_NAME_SIZE];
	char			 path[MAXPATHLEN];
	struct pf_ruleset	 ruleset;
	int			 refcnt;	/* anchor rules */
};
RB_PROTOTYPE(pf_anchor_global, pf_anchor, entry_global, pf_anchor_compare);
RB_PROTOTYPE(pf_anchor_node, pf_anchor, entry_node, pf_anchor_compare);

#define PF_RESERVED_ANCHOR	"_pf"

#define PFR_TFLAG_PERSIST	0x00000001
#define PFR_TFLAG_CONST		0x00000002
#define PFR_TFLAG_ACTIVE	0x00000004
#define PFR_TFLAG_INACTIVE	0x00000008
#define PFR_TFLAG_REFERENCED	0x00000010
#define PFR_TFLAG_REFDANCHOR	0x00000020
#define PFR_TFLAG_USRMASK	0x00000003
#define PFR_TFLAG_SETMASK	0x0000003C
#define PFR_TFLAG_ALLMASK	0x0000003F

struct pfr_table {
	char			 pfrt_anchor[MAXPATHLEN];
	char			 pfrt_name[PF_TABLE_NAME_SIZE];
	uint32_t		 pfrt_flags;
	uint8_t			 pfrt_fback;
};

enum { PFR_FB_NONE, PFR_FB_MATCH, PFR_FB_ADDED, PFR_FB_DELETED,
	PFR_FB_CHANGED, PFR_FB_CLEARED, PFR_FB_DUPLICATE,
	PFR_FB_NOTMATCH, PFR_FB_CONFLICT, PFR_FB_MAX };

struct pfr_addr {
	union {
		struct in_addr	 _pfra_ip4addr;
		struct in6_addr	 _pfra_ip6addr;
	}		 pfra_u;
	uint8_t		 pfra_af;
	uint8_t		 pfra_net;
	uint8_t		 pfra_not;
	uint8_t		 pfra_fback;
};
#define	pfra_ip4addr	pfra_u._pfra_ip4addr
#define	pfra_ip6addr	pfra_u._pfra_ip6addr

enum { PFR_DIR_IN, PFR_DIR_OUT, PFR_DIR_MAX };
enum { PFR_OP_BLOCK, PFR_OP_PASS, PFR_OP_ADDR_MAX, PFR_OP_TABLE_MAX };
#define PFR_OP_XPASS	PFR_OP_ADDR_MAX

struct pfr_astats {
	struct pfr_addr	 pfras_a;
	uint64_t	 pfras_packets[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	uint64_t	 pfras_bytes[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	long		 pfras_tzero;
};

enum { PFR_REFCNT_RULE, PFR_REFCNT_ANCHOR, PFR_REFCNT_MAX };

struct pfr_tstats {
	struct pfr_table pfrts_t;
	uint64_t	 pfrts_packets[PFR_DIR_MAX][PFR_OP_TABLE_MAX];
	uint64_t	 pfrts_bytes[PFR_DIR_MAX][PFR_OP_TABLE_MAX];
	uint64_t	 pfrts_match;
	uint64_t	 pfrts_nomatch;
	long		 pfrts_tzero;
	int		 pfrts_cnt;
	int		 pfrts_refcnt[PFR_REFCNT_MAX];
};
#define	pfrts_name	pfrts_t.pfrt_name
#define pfrts_flags	pfrts_t.pfrt_flags

SLIST_HEAD(pfr_kentryworkq, pfr_kentry);
struct pfr_kentry {
	struct radix_node	 pfrke_node[2];
	union sockaddr_union	 pfrke_sa;
	uint64_t		 pfrke_packets[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	uint64_t		 pfrke_bytes[PFR_DIR_MAX][PFR_OP_ADDR_MAX];
	SLIST_ENTRY(pfr_kentry)	 pfrke_workq;
	long			 pfrke_tzero;
	uint8_t			 pfrke_af;
	uint8_t			 pfrke_net;
	uint8_t			 pfrke_not;
	uint8_t			 pfrke_mark;
	uint8_t			 pfrke_intrpool;
};

SLIST_HEAD(pfr_ktableworkq, pfr_ktable);
RB_HEAD(pfr_ktablehead, pfr_ktable);
struct pfr_ktable {
	struct pfr_tstats	 pfrkt_ts;
	RB_ENTRY(pfr_ktable)	 pfrkt_tree;
	SLIST_ENTRY(pfr_ktable)	 pfrkt_workq;
	struct radix_node_head	*pfrkt_ip4;
	struct radix_node_head	*pfrkt_ip6;
	struct pfr_ktable	*pfrkt_shadow;
	struct pfr_ktable	*pfrkt_root;
	struct pf_ruleset	*pfrkt_rs;
	long			 pfrkt_larg;
	int			 pfrkt_nflags;
};
#define pfrkt_t		pfrkt_ts.pfrts_t
#define pfrkt_name	pfrkt_t.pfrt_name
#define pfrkt_anchor	pfrkt_t.pfrt_anchor
#define pfrkt_ruleset	pfrkt_t.pfrt_ruleset
#define pfrkt_flags	pfrkt_t.pfrt_flags
#define pfrkt_cnt	pfrkt_ts.pfrts_cnt
#define pfrkt_refcnt	pfrkt_ts.pfrts_refcnt
#define pfrkt_packets	pfrkt_ts.pfrts_packets
#define pfrkt_bytes	pfrkt_ts.pfrts_bytes
#define pfrkt_match	pfrkt_ts.pfrts_match
#define pfrkt_nomatch	pfrkt_ts.pfrts_nomatch
#define pfrkt_tzero	pfrkt_ts.pfrts_tzero

RB_HEAD(pf_state_tree_lan_ext, pf_state);
RB_PROTOTYPE(pf_state_tree_lan_ext, pf_state,
    u.s.entry_lan_ext, pf_state_compare_lan_ext)

RB_HEAD(pf_state_tree_ext_gwy, pf_state);
RB_PROTOTYPE(pf_state_tree_ext_gwy, pf_state,
    u.s.entry_ext_gwy, pf_state_compare_ext_gwy)

struct pfi_if {
	char				 pfif_name[IFNAMSIZ];
	uint64_t			 pfif_packets[2][2][2];
	uint64_t			 pfif_bytes[2][2][2];
	uint64_t			 pfif_addcnt;
	uint64_t			 pfif_delcnt;
	long				 pfif_tzero;
	int				 pfif_states;
	int				 pfif_rules;
	int				 pfif_flags;
};

TAILQ_HEAD(pfi_grouphead, pfi_kif);
TAILQ_HEAD(pfi_statehead, pfi_kif);
RB_HEAD(pfi_ifhead, pfi_kif);
struct pfi_kif {
	struct pfi_if			 pfik_if;
	RB_ENTRY(pfi_kif)		 pfik_tree;
	struct pf_state_tree_lan_ext	 pfik_lan_ext;
	struct pf_state_tree_ext_gwy	 pfik_ext_gwy;
	struct pfi_grouphead		 pfik_grouphead;
	TAILQ_ENTRY(pfi_kif)		 pfik_instances;
	TAILQ_ENTRY(pfi_kif)		 pfik_w_states;
	struct hook_desc_head		*pfik_ah_head;
	void				*pfik_ah_cookie;
	struct pfi_kif			*pfik_parent;
	struct ifnet			*pfik_ifp;
	int				 pfik_states;
	int				 pfik_rules;
#if defined(__NetBSD__) || defined(__QNXNTO__)
	struct hook_desc_head		 pfik_ifaddrhooks;
#endif
};
#define pfik_name	pfik_if.pfif_name
#define pfik_packets	pfik_if.pfif_packets
#define pfik_bytes	pfik_if.pfif_bytes
#define pfik_tzero	pfik_if.pfif_tzero
#define pfik_flags	pfik_if.pfif_flags
#define pfik_addcnt	pfik_if.pfif_addcnt
#define pfik_delcnt	pfik_if.pfif_delcnt
#define pfik_states	pfik_if.pfif_states
#define pfik_rules	pfik_if.pfif_rules

#define PFI_IFLAG_GROUP		0x0001	/* group of interfaces */
#define PFI_IFLAG_INSTANCE	0x0002	/* single instance */
#define PFI_IFLAG_CLONABLE	0x0010	/* clonable group */
#define PFI_IFLAG_DYNAMIC	0x0020	/* dynamic group */
#define PFI_IFLAG_ATTACHED	0x0040	/* interface attached */
#define PFI_IFLAG_SKIP		0x0100	/* skip filtering on interface */
#define PFI_IFLAG_SETABLE_MASK	0x0100	/* setable via DIOC{SET,CLR}IFFLAG */

struct pf_pdesc {
	uint64_t	 tot_len;	/* Make Mickey money */
	union {
		struct tcphdr		*tcp;
		struct udphdr		*udp;
		struct icmp		*icmp;
#ifdef INET6
		struct icmp6_hdr	*icmp6;
#endif /* INET6 */
		void			*any;
	} hdr;
	struct pf_addr	 baddr;		/* address before translation */
	struct pf_addr	 naddr;		/* address after translation */
	struct pf_rule	*nat_rule;	/* nat/rdr rule applied to packet */
	struct pf_addr	*src;
	struct pf_addr	*dst;
	struct ether_header
			*eh;
	uint16_t	*ip_sum;
	uint32_t	 p_len;		/* total length of payload */
	uint16_t	 flags;		/* Let SCRUB trigger behavior in
					 * state code. Easier than tags */
#define PFDESC_TCP_NORM	0x0001		/* TCP shall be statefully scrubbed */
#define PFDESC_IP_REAS	0x0002		/* IP frags would've been reassembled */
	sa_family_t	 af;
	uint8_t		 proto;
	uint8_t		 tos;
};

/* flags for RDR options */
#define PF_DPORT_RANGE	0x01		/* Dest port uses range */
#define PF_RPORT_RANGE	0x02		/* RDR'ed port uses range */

/* Reasons code for passing/dropping a packet */
#define PFRES_MATCH	0		/* Explicit match of a rule */
#define PFRES_BADOFF	1		/* Bad offset for pull_hdr */
#define PFRES_FRAG	2		/* Dropping following fragment */
#define PFRES_SHORT	3		/* Dropping short packet */
#define PFRES_NORM	4		/* Dropping by normalizer */
#define PFRES_MEMORY	5		/* Dropped due to lacking mem */
#define PFRES_TS	6		/* Bad TCP Timestamp (RFC1323) */
#define PFRES_CONGEST	7		/* Congestion (of ipintrq) */
#define PFRES_IPOPTIONS 8		/* IP option */
#define PFRES_PROTCKSUM 9		/* Protocol checksum invalid */
#define PFRES_BADSTATE	10		/* State mismatch */
#define PFRES_STATEINS	11		/* State insertion failure */
#define PFRES_MAXSTATES	12		/* State limit */
#define PFRES_SRCLIMIT	13		/* Source node/conn limit */
#define PFRES_SYNPROXY	14		/* SYN proxy */
#define PFRES_MAX	15		/* total+1 */

#define PFRES_NAMES { \
	"match", \
	"bad-offset", \
	"fragment", \
	"short", \
	"normalize", \
	"memory", \
	"bad-timestamp", \
	"congestion", \
	"ip-option", \
	"proto-cksum", \
	"state-mismatch", \
	"state-insert", \
	"state-limit", \
	"src-limit", \
	"synproxy", \
	NULL \
}

/* Counters for other things we want to keep track of */
#define LCNT_STATES		0	/* states */
#define LCNT_SRCSTATES		1	/* max-src-states */
#define LCNT_SRCNODES		2	/* max-src-nodes */
#define LCNT_SRCCONN		3	/* max-src-conn */
#define LCNT_SRCCONNRATE	4	/* max-src-conn-rate */
#define LCNT_OVERLOAD_TABLE	5	/* entry added to overload table */
#define LCNT_OVERLOAD_FLUSH	6	/* state entries flushed */
#define LCNT_MAX		7	/* total+1 */

#define LCNT_NAMES { \
	"max states per rule", \
	"max-src-states", \
	"max-src-nodes", \
	"max-src-conn", \
	"max-src-conn-rate", \
	"overload table insertion", \
	"overload flush states", \
	NULL \
}

/* UDP state enumeration */
#define PFUDPS_NO_TRAFFIC	0
#define PFUDPS_SINGLE		1
#define PFUDPS_MULTIPLE		2

#define PFUDPS_NSTATES		3	/* number of state levels */

#define PFUDPS_NAMES { \
	"NO_TRAFFIC", \
	"SINGLE", \
	"MULTIPLE", \
	NULL \
}

/* Other protocol state enumeration */
#define PFOTHERS_NO_TRAFFIC	0
#define PFOTHERS_SINGLE		1
#define PFOTHERS_MULTIPLE	2

#define PFOTHERS_NSTATES	3	/* number of state levels */

#define PFOTHERS_NAMES { \
	"NO_TRAFFIC", \
	"SINGLE", \
	"MULTIPLE", \
	NULL \
}

#define FCNT_STATE_SEARCH	0
#define FCNT_STATE_INSERT	1
#define FCNT_STATE_REMOVALS	2
#define FCNT_MAX		3

#define SCNT_SRC_NODE_SEARCH	0
#define SCNT_SRC_NODE_INSERT	1
#define SCNT_SRC_NODE_REMOVALS	2
#define SCNT_MAX		3

#define ACTION_SET(a, x) \
	do { \
		if ((a) != NULL) \
			*(a) = (x); \
	} while (0)

#define REASON_SET(a, x) \
	do { \
		if ((a) != NULL) \
			*(a) = (x); \
		if (x < PFRES_MAX) \
			pf_status.counters[x]++; \
	} while (0)

struct pf_status {
	uint64_t	counters[PFRES_MAX];
	uint64_t	lcounters[LCNT_MAX];	/* limit counters */
	uint64_t	fcounters[FCNT_MAX];
	uint64_t	scounters[SCNT_MAX];
	uint64_t	pcounters[2][2][3];
	uint64_t	bcounters[2][2];
	uint64_t	stateid;
	uint32_t	running;
	uint32_t	states;
	uint32_t	src_nodes;
	uint32_t	since;
	uint32_t	debug;
	uint32_t	hostid;
	uint32_t	reass;
	char		ifname[IFNAMSIZ];
};

#define PF_REASS_ENABLED	0x01

struct cbq_opts {
	u_int		minburst;
	u_int		maxburst;
	u_int		pktsize;
	u_int		maxpktsize;
	u_int		ns_per_byte;
	u_int		maxidle;
	int		minidle;
	u_int		offtime;
	int		flags;
};

struct priq_opts {
	int		flags;
};

struct hfsc_opts {
	/* real-time service curve */
	u_int		rtsc_m1;	/* slope of the 1st segment in bps */
	u_int		rtsc_d;		/* the x-projection of m1 in msec */
	u_int		rtsc_m2;	/* slope of the 2nd segment in bps */
	/* link-sharing service curve */
	u_int		lssc_m1;
	u_int		lssc_d;
	u_int		lssc_m2;
	/* upper-limit service curve */
	u_int		ulsc_m1;
	u_int		ulsc_d;
	u_int		ulsc_m2;
	int		flags;
};

struct pf_altq {
	char			 ifname[IFNAMSIZ];

	void			*altq_disc;	/* discipline-specific state */
	TAILQ_ENTRY(pf_altq)	 entries;

	/* scheduler spec */
	uint8_t			 scheduler;	/* scheduler type */
	uint16_t		 tbrsize;	/* tokenbucket regulator size */
	uint32_t		 ifbandwidth;	/* interface bandwidth */

	/* queue spec */
	char			 qname[PF_QNAME_SIZE];	/* queue name */
	char			 parent[PF_QNAME_SIZE];	/* parent name */
	uint32_t		 parent_qid;	/* parent queue id */
	uint32_t		 bandwidth;	/* queue bandwidth */
	uint8_t			 priority;	/* priority */
	uint16_t		 qlimit;	/* queue size limit */
	uint16_t		 flags;		/* misc flags */
	union {
		struct cbq_opts		 cbq_opts;
		struct priq_opts	 priq_opts;
		struct hfsc_opts	 hfsc_opts;
	} pq_u;

	uint32_t		 qid;		/* return value */
};

struct pf_tag {
	uint16_t	tag;		/* tag id */
};

struct pf_tagname {
	TAILQ_ENTRY(pf_tagname)	entries;
	char			name[PF_TAG_NAME_SIZE];
	uint16_t		tag;
	int			ref;
};

#define PFFRAG_FRENT_HIWAT	5000	/* Number of fragment entries */
#define PFFRAG_FRAG_HIWAT	1000	/* Number of fragmented packets */
#define PFFRAG_FRCENT_HIWAT	50000	/* Number of fragment cache entries */
#define PFFRAG_FRCACHE_HIWAT	10000	/* Number of fragment descriptors */

/*
 * ioctl parameter structures
 */

struct pfioc_pooladdr {
	uint32_t		 action;
	uint32_t		 ticket;
	uint32_t		 nr;
	uint32_t		 r_num;
	uint8_t			 r_action;
	uint8_t			 r_last;
	uint8_t			 af;
	char			 anchor[MAXPATHLEN];
	struct pf_pooladdr	 addr;
};

struct pfioc_rule {
	uint32_t	 action;
	uint32_t	 ticket;
	uint32_t	 pool_ticket;
	uint32_t	 nr;
	char		 anchor[MAXPATHLEN];
	char		 anchor_call[MAXPATHLEN];
	struct pf_rule	 rule;
};

struct pfioc_natlook {
	struct pf_addr	 saddr;
	struct pf_addr	 daddr;
	struct pf_addr	 rsaddr;
	struct pf_addr	 rdaddr;
	uint16_t	 sport;
	uint16_t	 dport;
	uint16_t	 rsport;
	uint16_t	 rdport;
	sa_family_t	 af;
	uint8_t		 proto;
	uint8_t		 direction;
};

struct pfioc_state {
	uint32_t	 nr;
	struct pf_state	 state;
};

struct pfioc_state_kill {
	/* XXX returns the number of states killed in psk_af */
	sa_family_t		psk_af;
	int			psk_proto;
	struct pf_rule_addr	psk_src;
	struct pf_rule_addr	psk_dst;
	char			psk_ifname[IFNAMSIZ];
};

struct pfioc_states {
	int	ps_len;
	union {
		caddr_t		 psu_buf;
		struct pf_state	*psu_states;
	} ps_u;
#define ps_buf		ps_u.psu_buf
#define ps_states	ps_u.psu_states
};

struct pfioc_src_nodes {
	int	psn_len;
	union {
		caddr_t		 psu_buf;
		struct pf_src_node	*psu_src_nodes;
	} psn_u;
#define psn_buf		psn_u.psu_buf
#define psn_src_nodes	psn_u.psu_src_nodes
};

struct pfioc_if {
	char		 ifname[IFNAMSIZ];
};

struct pfioc_tm {
	int		 timeout;
	int		 seconds;
};

struct pfioc_limit {
	int		 index;
	unsigned	 limit;
};

struct pfioc_altq {
	uint32_t	 action;
	uint32_t	 ticket;
	uint32_t	 nr;
	struct pf_altq	 altq;
};

struct pfioc_qstats {
	uint32_t	 ticket;
	uint32_t	 nr;
	void		*buf;
	int		 nbytes;
	uint8_t		 scheduler;
};

struct pfioc_ruleset {
	uint32_t	 nr;
	char		 path[MAXPATHLEN];
	char		 name[PF_ANCHOR_NAME_SIZE];
};

#define PF_RULESET_ALTQ		(PF_RULESET_MAX)
#define PF_RULESET_TABLE	(PF_RULESET_MAX+1)
struct pfioc_trans {
	int		 size;	/* number of elements */
	int		 esize; /* size of each element in bytes */
	struct pfioc_trans_e {
		int		rs_num;
		char		anchor[MAXPATHLEN];
		uint32_t	ticket;
	}		*array;
};

#define PFR_FLAG_ATOMIC		0x00000001
#define PFR_FLAG_DUMMY		0x00000002
#define PFR_FLAG_FEEDBACK	0x00000004
#define PFR_FLAG_CLSTATS	0x00000008
#define PFR_FLAG_ADDRSTOO	0x00000010
#define PFR_FLAG_REPLACE	0x00000020
#define PFR_FLAG_ALLRSETS	0x00000040
#define PFR_FLAG_ALLMASK	0x0000007F
#ifdef _KERNEL
#define PFR_FLAG_USERIOCTL	0x10000000
#endif

struct pfioc_table {
	struct pfr_table	 pfrio_table;
	void			*pfrio_buffer;
	int			 pfrio_esize;
	int			 pfrio_size;
	int			 pfrio_size2;
	int			 pfrio_nadd;
	int			 pfrio_ndel;
	int			 pfrio_nchange;
	int			 pfrio_flags;
	uint32_t		 pfrio_ticket;
};
#define	pfrio_exists	pfrio_nadd
#define	pfrio_nzero	pfrio_nadd
#define	pfrio_nmatch	pfrio_nadd
#define pfrio_naddr	pfrio_size2
#define pfrio_setflag	pfrio_size2
#define pfrio_clrflag	pfrio_nadd


#define PFI_FLAG_GROUP		0x0001	/* gets groups of interfaces */
#define PFI_FLAG_INSTANCE	0x0002	/* gets single interfaces */
#define PFI_FLAG_ALLMASK	0x0003

struct pfioc_iface {
	char	 pfiio_name[IFNAMSIZ];
	void	*pfiio_buffer;
	int	 pfiio_esize;
	int	 pfiio_size;
	int	 pfiio_nzero;
	int	 pfiio_flags;
};


/*
 * ioctl operations
 */

#define DIOCSTART	_IO  ('D',  1)
#define DIOCSTOP	_IO  ('D',  2)
#define DIOCADDRULE	_IOWR('D',  4, struct pfioc_rule)
#define DIOCGETRULES	_IOWR('D',  6, struct pfioc_rule)
#define DIOCGETRULE	_IOWR('D',  7, struct pfioc_rule)
/* XXX cut 8 - 17 */
#define DIOCCLRSTATES	_IOWR('D', 18, struct pfioc_state_kill)
#define DIOCGETSTATE	_IOWR('D', 19, struct pfioc_state)
#define DIOCSETSTATUSIF _IOWR('D', 20, struct pfioc_if)
#define DIOCGETSTATUS	_IOWR('D', 21, struct pf_status)
#define DIOCCLRSTATUS	_IO  ('D', 22)
#define DIOCNATLOOK	_IOWR('D', 23, struct pfioc_natlook)
#define DIOCSETDEBUG	_IOWR('D', 24, uint32_t)
#define DIOCGETSTATES	_IOWR('D', 25, struct pfioc_states)
#define DIOCCHANGERULE	_IOWR('D', 26, struct pfioc_rule)
/* XXX cut 26 - 28 */
#define DIOCSETTIMEOUT	_IOWR('D', 29, struct pfioc_tm)
#define DIOCGETTIMEOUT	_IOWR('D', 30, struct pfioc_tm)
#define DIOCADDSTATE	_IOWR('D', 37, struct pfioc_state)
#define DIOCCLRRULECTRS	_IO  ('D', 38)
#define DIOCGETLIMIT	_IOWR('D', 39, struct pfioc_limit)
#define DIOCSETLIMIT	_IOWR('D', 40, struct pfioc_limit)
#define DIOCKILLSTATES	_IOWR('D', 41, struct pfioc_state_kill)
#define DIOCSTARTALTQ	_IO  ('D', 42)
#define DIOCSTOPALTQ	_IO  ('D', 43)
#define DIOCADDALTQ	_IOWR('D', 45, struct pfioc_altq)
#define DIOCGETALTQS	_IOWR('D', 47, struct pfioc_altq)
#define DIOCGETALTQ	_IOWR('D', 48, struct pfioc_altq)
#define DIOCCHANGEALTQ	_IOWR('D', 49, struct pfioc_altq)
#define DIOCGETQSTATS	_IOWR('D', 50, struct pfioc_qstats)
#define DIOCBEGINADDRS	_IOWR('D', 51, struct pfioc_pooladdr)
#define DIOCADDADDR	_IOWR('D', 52, struct pfioc_pooladdr)
#define DIOCGETADDRS	_IOWR('D', 53, struct pfioc_pooladdr)
#define DIOCGETADDR	_IOWR('D', 54, struct pfioc_pooladdr)
#define DIOCCHANGEADDR	_IOWR('D', 55, struct pfioc_pooladdr)
/* XXX cut 55 - 57 */
#define	DIOCGETRULESETS	_IOWR('D', 58, struct pfioc_ruleset)
#define	DIOCGETRULESET	_IOWR('D', 59, struct pfioc_ruleset)
#define	DIOCRCLRTABLES	_IOWR('D', 60, struct pfioc_table)
#define	DIOCRADDTABLES	_IOWR('D', 61, struct pfioc_table)
#define	DIOCRDELTABLES	_IOWR('D', 62, struct pfioc_table)
#define	DIOCRGETTABLES	_IOWR('D', 63, struct pfioc_table)
#define	DIOCRGETTSTATS	_IOWR('D', 64, struct pfioc_table)
#define DIOCRCLRTSTATS  _IOWR('D', 65, struct pfioc_table)
#define	DIOCRCLRADDRS	_IOWR('D', 66, struct pfioc_table)
#define	DIOCRADDADDRS	_IOWR('D', 67, struct pfioc_table)
#define	DIOCRDELADDRS	_IOWR('D', 68, struct pfioc_table)
#define	DIOCRSETADDRS	_IOWR('D', 69, struct pfioc_table)
#define	DIOCRGETADDRS	_IOWR('D', 70, struct pfioc_table)
#define	DIOCRGETASTATS	_IOWR('D', 71, struct pfioc_table)
#define DIOCRCLRASTATS  _IOWR('D', 72, struct pfioc_table)
#define	DIOCRTSTADDRS	_IOWR('D', 73, struct pfioc_table)
#define	DIOCRSETTFLAGS	_IOWR('D', 74, struct pfioc_table)
#define DIOCRINADEFINE	_IOWR('D', 77, struct pfioc_table)
#define DIOCOSFPFLUSH	_IO('D', 78)
#define DIOCOSFPADD	_IOWR('D', 79, struct pf_osfp_ioctl)
#define DIOCOSFPGET	_IOWR('D', 80, struct pf_osfp_ioctl)
#define DIOCXBEGIN      _IOWR('D', 81, struct pfioc_trans)
#define DIOCXCOMMIT     _IOWR('D', 82, struct pfioc_trans)
#define DIOCXROLLBACK   _IOWR('D', 83, struct pfioc_trans)
#define DIOCGETSRCNODES	_IOWR('D', 84, struct pfioc_src_nodes)
#define DIOCCLRSRCNODES	_IO('D', 85)
#define DIOCSETHOSTID	_IOWR('D', 86, uint32_t)
#define DIOCIGETIFACES	_IOWR('D', 87, struct pfioc_iface)
#define DIOCICLRISTATS  _IOWR('D', 88, struct pfioc_iface)
#define DIOCSETIFFLAG	_IOWR('D', 89, struct pfioc_iface)
#define DIOCCLRIFFLAG	_IOWR('D', 90, struct pfioc_iface)
#define DIOCSETREASS	_IOWR('D', 92, u_int32_t)

#ifdef _KERNEL
RB_HEAD(pf_src_tree, pf_src_node);
RB_PROTOTYPE(pf_src_tree, pf_src_node, entry, pf_src_compare);
extern struct pf_src_tree tree_src_tracking;

RB_HEAD(pf_state_tree_id, pf_state);
RB_PROTOTYPE(pf_state_tree_id, pf_state,
    entry_id, pf_state_compare_id);
extern struct pf_state_tree_id tree_id;
extern struct pf_state_queue state_updates;

extern struct pf_anchor_global		  pf_anchors;
extern struct pf_ruleset		  pf_main_ruleset;
TAILQ_HEAD(pf_poolqueue, pf_pool);
extern struct pf_poolqueue		  pf_pools[2];
TAILQ_HEAD(pf_altqqueue, pf_altq);
extern struct pf_altqqueue		  pf_altqs[2];
extern struct pf_palist			  pf_pabuf;
extern struct pfi_kif			**pfi_index2kif;

extern u_int32_t		 ticket_altqs_active;
extern u_int32_t		 ticket_altqs_inactive;
extern int			 altqs_inactive_open;
extern u_int32_t		 ticket_pabuf;
extern struct pf_altqqueue	*pf_altqs_active;
extern struct pf_altqqueue	*pf_altqs_inactive;
extern struct pf_poolqueue	*pf_pools_active;
extern struct pf_poolqueue	*pf_pools_inactive;
extern int			 pf_tbladdr_setup(struct pf_ruleset *,
				    struct pf_addr_wrap *);
extern void			 pf_tbladdr_remove(struct pf_addr_wrap *);
extern void			 pf_tbladdr_copyout(struct pf_addr_wrap *);
extern void			 pf_calc_skip_steps(struct pf_rulequeue *);
extern struct pool		 pf_src_tree_pl, pf_rule_pl;
extern struct pool		 pf_state_pl, pf_altq_pl, pf_pooladdr_pl;
extern struct pool		 pf_state_scrub_pl;
extern void			 pf_purge_timeout(void *);
#ifndef __QNXNTO__
extern void			 pf_purge_expired_src_nodes(void);
extern void			 pf_purge_expired_states(void);
#else
extern void			 pf_purge_kick(void);
extern int			 pf_purge_expired_src_nodes(void);
extern int			 pf_purge_expired_states(void);
#endif
extern void			 pf_purge_expired_state(struct pf_state *);
extern int			 pf_insert_state(struct pfi_kif *,
				    struct pf_state *);
extern int			 pf_insert_src_node(struct pf_src_node **,
				    struct pf_rule *, struct pf_addr *,
				    sa_family_t);
void				 pf_src_tree_remove_state(struct pf_state *);
extern struct pf_state		*pf_find_state_byid(struct pf_state *);
extern struct pf_state		*pf_find_state_all(struct pf_state *key,
				    u_int8_t tree, int *more);
extern void			 pf_print_state(struct pf_state *);
extern void			 pf_print_flags(u_int8_t);
extern struct pf_anchor		*pf_find_anchor(const char *);
extern struct pf_ruleset	*pf_find_ruleset(const char *);
extern struct pf_ruleset	*pf_find_or_create_ruleset(const char *);
extern void			 pf_remove_if_empty_ruleset(
				    struct pf_ruleset *);
extern u_int16_t		 pf_cksum_fixup(u_int16_t, u_int16_t, u_int16_t,
				    u_int8_t);

extern struct ifnet		*sync_ifp;
extern struct pf_rule		 pf_default_rule;
extern void			 pf_addrcpy(struct pf_addr *, struct pf_addr *,
				    u_int8_t);
void				 pf_rm_rule(struct pf_rulequeue *,
				    struct pf_rule *);

#ifdef INET
int	pf_test(int, struct ifnet *, struct mbuf **, struct ether_header *);
#endif /* INET */

#ifdef INET6
int	pf_test6(int, struct ifnet *, struct mbuf **, struct ether_header *);
void	pf_poolmask(struct pf_addr *, struct pf_addr*,
	    struct pf_addr *, struct pf_addr *, u_int8_t);
void	pf_addr_inc(struct pf_addr *, sa_family_t);
#endif /* INET6 */

void   *pf_pull_hdr(struct mbuf *, int, void *, int, u_short *, u_short *,
	    sa_family_t);
void	pf_change_a(void *, u_int16_t *, u_int32_t, u_int8_t);
int	pflog_packet(struct pfi_kif *, struct mbuf *, sa_family_t, u_int8_t,
	    u_int8_t, struct pf_rule *, struct pf_rule *, struct pf_ruleset *);
int	pf_match_addr(u_int8_t, struct pf_addr *, struct pf_addr *,
	    struct pf_addr *, sa_family_t);
int	pf_match(u_int8_t, u_int32_t, u_int32_t, u_int32_t);
int	pf_match_port(u_int8_t, u_int16_t, u_int16_t, u_int16_t);
int	pf_match_uid(u_int8_t, uid_t, uid_t, uid_t);
int	pf_match_gid(u_int8_t, gid_t, gid_t, gid_t);

#ifdef __OpenBSD__
int	pf_refragment6(struct mbuf **, struct m_tag *, int);
#endif
void	pf_normalize_init(void);
#ifdef _LKM
void	pf_normalize_destroy(void);
#endif
int	pf_normalize_ip(struct mbuf **, int, struct pfi_kif *, u_short *,
	    struct pf_pdesc *);
int	pf_normalize_ip6(struct mbuf **, int, struct pfi_kif *, u_short *,
	    struct pf_pdesc *);
int	pf_normalize_tcp(int, struct pfi_kif *, struct mbuf *, int, int, void *,
	    struct pf_pdesc *);
void	pf_normalize_tcp_cleanup(struct pf_state *);
int	pf_normalize_tcp_init(struct mbuf *, int, struct pf_pdesc *,
	    struct tcphdr *, struct pf_state_peer *, struct pf_state_peer *);
int	pf_normalize_tcp_stateful(struct mbuf *, int, struct pf_pdesc *,
	    u_short *, struct tcphdr *, struct pf_state *,
	    struct pf_state_peer *, struct pf_state_peer *, int *);
u_int32_t
	pf_state_expires(const struct pf_state *);
#ifndef __QNXNTO__
void	pf_purge_expired_fragments(void);
#else
int	pf_purge_expired_fragments(void);
#endif
#ifndef QNX_MFIB
int	pf_routable(struct pf_addr *addr, sa_family_t af);
int	pf_rtlabel_match(struct pf_addr *, sa_family_t, struct pf_addr_wrap *);
#else
int	pf_routable(struct pf_addr *addr, sa_family_t af, int);
int	pf_rtlabel_match(struct pf_addr *, sa_family_t, struct pf_addr_wrap *, int);
#endif
void	pfr_initialize(void);
#ifdef _LKM
void	pfr_destroy(void);
#endif
int	pfr_match_addr(struct pfr_ktable *, struct pf_addr *, sa_family_t);
void	pfr_update_stats(struct pfr_ktable *, struct pf_addr *, sa_family_t,
	    u_int64_t, int, int, int);
int	pfr_pool_get(struct pfr_ktable *, int *, struct pf_addr *,
	    struct pf_addr **, struct pf_addr **, sa_family_t);
void	pfr_dynaddr_update(struct pfr_ktable *, struct pfi_dynaddr *);
struct pfr_ktable *
	pfr_attach_table(struct pf_ruleset *, char *);
void	pfr_detach_table(struct pfr_ktable *);
int	pfr_clr_tables(struct pfr_table *, int *, int);
int	pfr_add_tables(struct pfr_table *, int, int *, int);
int	pfr_del_tables(struct pfr_table *, int, int *, int);
int	pfr_get_tables(struct pfr_table *, struct pfr_table *, int *, int);
int	pfr_get_tstats(struct pfr_table *, struct pfr_tstats *, int *, int);
int	pfr_clr_tstats(struct pfr_table *, int, int *, int);
int	pfr_set_tflags(struct pfr_table *, int, int, int, int *, int *, int);
int	pfr_clr_addrs(struct pfr_table *, int *, int);
int	pfr_insert_kentry(struct pfr_ktable *, struct pfr_addr *, long);
int	pfr_add_addrs(struct pfr_table *, struct pfr_addr *, int, int *,
	    int);
int	pfr_del_addrs(struct pfr_table *, struct pfr_addr *, int, int *,
	    int);
int	pfr_set_addrs(struct pfr_table *, struct pfr_addr *, int, int *,
	    int *, int *, int *, int);
int	pfr_get_addrs(struct pfr_table *, struct pfr_addr *, int *, int);
int	pfr_get_astats(struct pfr_table *, struct pfr_astats *, int *, int);
int	pfr_clr_astats(struct pfr_table *, struct pfr_addr *, int, int *,
	    int);
int	pfr_tst_addrs(struct pfr_table *, struct pfr_addr *, int, int *,
	    int);
int	pfr_ina_begin(struct pfr_table *, u_int32_t *, int *, int);
int	pfr_ina_rollback(struct pfr_table *, u_int32_t, int *, int);
int	pfr_ina_commit(struct pfr_table *, u_int32_t, int *, int *, int);
int	pfr_ina_define(struct pfr_table *, struct pfr_addr *, int, int *,
	    int *, u_int32_t, int);

void		 pfi_initialize(void);
#ifdef _LKM
void		 pfi_destroy(void);
#endif
void		 pfi_attach_clone(struct if_clone *);
void		 pfi_attach_ifnet(struct ifnet *);
void		 pfi_detach_ifnet(struct ifnet *);
struct pfi_kif	*pfi_lookup_create(const char *);
struct pfi_kif	*pfi_lookup_if(const char *);
int		 pfi_maybe_destroy(struct pfi_kif *);
struct pfi_kif	*pfi_attach_rule(const char *);
void		 pfi_detach_rule(struct pfi_kif *);
void		 pfi_attach_state(struct pfi_kif *);
void		 pfi_detach_state(struct pfi_kif *);
int		 pfi_dynaddr_setup(struct pf_addr_wrap *, sa_family_t);
void		 pfi_dynaddr_copyout(struct pf_addr_wrap *);
void		 pfi_dynaddr_remove(struct pf_addr_wrap *);
void		 pfi_fill_oldstatus(struct pf_status *);
int		 pfi_clr_istats(const char *, int *, int);
int		 pfi_get_ifaces(const char *, struct pfi_if *, int *, int);
int		 pfi_set_flags(const char *, int);
int		 pfi_clear_flags(const char *, int);
int		 pfi_match_addr(struct pfi_dynaddr *, struct pf_addr *,
		    sa_family_t);

extern struct pfi_statehead	pfi_statehead;

u_int16_t	pf_tagname2tag(char *);
void		pf_tag2tagname(u_int16_t, char *);
void		pf_tag_ref(u_int16_t);
void		pf_tag_unref(u_int16_t);
int		pf_tag_packet(struct mbuf *, struct pf_tag *, int);
int		pf_addr_compare(struct pf_addr *, struct pf_addr *, sa_family_t);
u_int32_t	pf_qname2qid(char *);
void		pf_qid2qname(u_int32_t, char *);
void		pf_qid_unref(u_int32_t);

extern struct pf_status	pf_status;
extern struct pool	pf_frent_pl, pf_frag_pl;

struct pf_pool_limit {
	void		*pp;
	unsigned	 limit;
};
extern struct pf_pool_limit	pf_pool_limits[PF_LIMIT_MAX];

#if defined(__NetBSD__) || defined(__QNXNTO__)
#ifndef QNX_MFIB
int pfil4_wrapper(void *, struct mbuf **, struct ifnet *, int);
int pfil6_wrapper(void *, struct mbuf **, struct ifnet *, int);
int pfil_ifnet_wrapper(void *, struct mbuf **, struct ifnet *, int);
int pfil_ifaddr_wrapper(void *, struct mbuf **, struct ifnet *, int);
#else
int pfil4_wrapper(void *, struct mbuf **, struct ifnet *, int, int);
int pfil6_wrapper(void *, struct mbuf **, struct ifnet *, int, int);
int pfil_ifnet_wrapper(void *, struct mbuf **, struct ifnet *, int, int);
int pfil_ifaddr_wrapper(void *, struct mbuf **, struct ifnet *, int, int);
int pf_set_fib_tag(struct mbuf *m, int fib);
int pf_get_fib_tag(struct mbuf *m);
#endif

#endif

#ifdef __QNXNTO__
int pf_open(struct lwp *, struct file **);
#endif

/*
 * misc compatibility stuffs
 */
#if !defined(PRIu32)
#define	PRIu32	"u"	/* XXX */
#endif
#if !defined(__OpenBSD__)
#if !defined(__NetBSD__) && !defined(__QNXNTO__)
#include <sys/kernel.h> /* mono_time */
static __inline void getmicrouptime(struct timeval *);
static __inline void
getmicrouptime(struct timeval *tvp)
{
	int s;

	s = splclock();
	*tvp = mono_time;
	splx(s);
}
#define	time_second	time.tv_sec
#endif /* !__NetBSD__ */
#define	m_copym2	m_dup
#define	pool_allocator_oldnointr	pool_allocator_nointr
#endif /* !__OpenBSD__ */
#endif /* _KERNEL */

/* The fingerprint functions can be linked into userland programs (tcpdump) */
int	pf_osfp_add(struct pf_osfp_ioctl *);
#ifdef _KERNEL
struct pf_osfp_enlist *
	pf_osfp_fingerprint(struct pf_pdesc *, struct mbuf *, int,
	    const struct tcphdr *);
#endif /* _KERNEL */
struct pf_osfp_enlist *
	pf_osfp_fingerprint_hdr(const struct ip *, const struct tcphdr *);
void	pf_osfp_flush(void);
int	pf_osfp_get(struct pf_osfp_ioctl *);
void	pf_osfp_initialize(void);
#ifdef _LKM
void	pf_osfp_destroy(void);
#endif
int	pf_osfp_match(struct pf_osfp_enlist *, pf_osfp_t);
struct pf_os_fingerprint *
	pf_osfp_validate(void);


#endif /* _NET_PFVAR_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/dist/pf/net/pfvar.h $ $Rev: 862127 $")
#endif
