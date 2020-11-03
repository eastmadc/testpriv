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

/*	$NetBSD: if_bridgevar.h,v 1.8 2005/12/10 23:21:38 elad Exp $	*/

/*
 * Copyright 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
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
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1999, 2000 Jason L. Wright (jason@thought.net)
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * OpenBSD: if_bridge.h,v 1.14 2001/03/22 03:48:29 jason Exp
 */

/*
 * Data structure and control definitions for bridge interfaces.
 */

#ifndef _NET_IF_BRIDGEVAR_H_
#define _NET_IF_BRIDGEVAR_H_

#include <sys/callout.h>
#include <sys/queue.h>
#if defined(__QNXNTO__) && defined(_KERNEL)
#include <tpass.h>
#endif

/*
 * Commands used in the SIOCSDRVSPEC ioctl.  Note the lookup of the
 * bridge interface itself is keyed off the ifdrv structure.
 */
#define	BRDGADD			0	/* add bridge member (ifbreq) */
#define	BRDGDEL			1	/* delete bridge member (ifbreq) */
#define	BRDGGIFFLGS		2	/* get member if flags (ifbreq) */
#define	BRDGSIFFLGS		3	/* set member if flags (ifbreq) */
#define	BRDGSCACHE		4	/* set cache size (ifbrparam) */
#define	BRDGGCACHE		5	/* get cache size (ifbrparam) */
#define	BRDGGIFS		6	/* get member list (ifbifconf) */
#define	BRDGRTS			7	/* get address list (ifbaconf) */
#define	BRDGSADDR		8	/* set static address (ifbareq) */
#define	BRDGSTO			9	/* set cache timeout (ifbrparam) */
#define	BRDGGTO			10	/* get cache timeout (ifbrparam) */
#define	BRDGDADDR		11	/* delete address (ifbareq) */
#define	BRDGFLUSH		12	/* flush address cache (ifbreq) */

#define	BRDGGPRI		13	/* get priority (ifbrparam) */
#define	BRDGSPRI		14	/* set priority (ifbrparam) */
#define	BRDGGHT			15	/* get hello time (ifbrparam) */
#define	BRDGSHT			16	/* set hello time (ifbrparam) */
#define	BRDGGFD			17	/* get forward delay (ifbrparam) */
#define	BRDGSFD			18	/* set forward delay (ifbrparam) */
#define	BRDGGMA			19	/* get max age (ifbrparam) */
#define	BRDGSMA			20	/* set max age (ifbrparam) */
#define	BRDGSIFPRIO		21	/* set if priority (ifbreq) */
#define BRDGSIFCOST		22	/* set if path cost (ifbreq) */
#define BRDGGFILT	        23	/* get filter flags (ifbrparam) */
#define BRDGSFILT	        24	/* set filter flags (ifbrparam) */

#if defined(__QNXNTO__) && defined(_KERNEL)
#if NBRIDGE > 0
extern struct ifqueue bridgeintrq;
#endif

#ifndef DIAGNOSTIC
#define	BRIDGE_SELF_CHECK(wtp, line)	/* nothing */
#else /* DIAGNOSTIC */
#define BRIDGE_SELF_CHECK(wtp, line_from)				\
do {									\
	if ((wtp)->intr_sighot == _ISIG_HOT && (wtp)->wt_critical == 0)	\
		panic("bridge: unexpected context: cur: %d  from: %d",	\
		    __LINE__, (line_from));				\
} while (/* CONSTCOND */ 0)
#endif /* DIAGNOSTIC */

#ifndef IONET_COMPAT_BRIDGE
#define BRIDGE_SELF_ENTER(wtp, line_from)	BRIDGE_SELF_CHECK((wtp), (line_from))
#define BRIDGE_SELF_EXIT(wtp)			/* nothing */
#else /* IONET_COMPAT_BRIDGE */
#define BRIDGE_SELF_ENTER(wtp, line_from)				\
do {									\
	NW_SIGHOLD_P((wtp));						\
	BRIDGE_SELF_CHECK((wtp), (line_from));				\
} while (/* CONSTCOND */ 0)
#define BRIDGE_SELF_EXIT(wtp)	NW_SIGUNHOLD_P((wtp))
#endif /* IONET_COMPAT_BRIDGE */

#endif /* __QNXNTO__ && _KERNEL */

/*
 * Generic bridge control request.
 */
struct ifbreq {
	char		ifbr_ifsname[IFNAMSIZ];	/* member if name */
	uint32_t	ifbr_ifsflags;		/* member if flags */
	uint8_t		ifbr_state;		/* member if STP state */
	uint8_t		ifbr_priority;		/* member if STP priority */
	uint8_t		ifbr_path_cost;		/* member if STP cost */
	uint8_t		ifbr_portno;		/* member if port number */
};

/* BRDGGIFFLAGS, BRDGSIFFLAGS */
#define	IFBIF_LEARNING		0x01	/* if can learn */
#define	IFBIF_DISCOVER		0x02	/* if sends packets w/ unknown dest. */
#define	IFBIF_STP		0x04	/* if participates in spanning tree */

#define	IFBIFBITS	"\020\1LEARNING\2DISCOVER\3STP"

/* BRDGFLUSH */
#define	IFBF_FLUSHDYN		0x00	/* flush learned addresses only */
#define	IFBF_FLUSHALL		0x01	/* flush all addresses */

/* BRDGSFILT */
#define IFBF_FILT_USEIPF	0x00000001 /* enable ipf on bridge */
#define IFBF_FILT_MASK		0x00000001 /* mask of valid values */

/* STP port states */
#define	BSTP_IFSTATE_DISABLED	0
#define	BSTP_IFSTATE_LISTENING	1
#define	BSTP_IFSTATE_LEARNING	2
#define	BSTP_IFSTATE_FORWARDING	3
#define	BSTP_IFSTATE_BLOCKING	4

/*
 * Interface list structure.
 */
struct ifbifconf {
	uint32_t	ifbic_len;	/* buffer size */
	union {
		caddr_t	ifbicu_buf;
		struct ifbreq *ifbicu_req;
	} ifbic_ifbicu;
#define	ifbic_buf	ifbic_ifbicu.ifbicu_buf
#define	ifbic_req	ifbic_ifbicu.ifbicu_req
};

/*
 * Bridge address request.
 */
struct ifbareq {
	char		ifba_ifsname[IFNAMSIZ];	/* member if name */
	unsigned long	ifba_expire;		/* address expire time */
	uint8_t		ifba_flags;		/* address flags */
	uint8_t		ifba_dst[ETHER_ADDR_LEN];/* destination address */
};

#define	IFBAF_TYPEMASK	0x03	/* address type mask */
#define	IFBAF_DYNAMIC	0x00	/* dynamically learned address */
#define	IFBAF_STATIC	0x01	/* static address */

#define	IFBAFBITS	"\020\1STATIC"

/*
 * Address list structure.
 */
struct ifbaconf {
	uint32_t	ifbac_len;	/* buffer size */
	union {
		caddr_t ifbacu_buf;
		struct ifbareq *ifbacu_req;
	} ifbac_ifbacu;
#define	ifbac_buf	ifbac_ifbacu.ifbacu_buf
#define	ifbac_req	ifbac_ifbacu.ifbacu_req
};

/*
 * Bridge parameter structure.
 */
struct ifbrparam {
	union {
		uint32_t ifbrpu_int32;
		uint16_t ifbrpu_int16;
		uint8_t ifbrpu_int8;
	} ifbrp_ifbrpu;
};
#define	ifbrp_csize	ifbrp_ifbrpu.ifbrpu_int32	/* cache size */
#define	ifbrp_ctime	ifbrp_ifbrpu.ifbrpu_int32	/* cache time (sec) */
#define	ifbrp_prio	ifbrp_ifbrpu.ifbrpu_int16	/* bridge priority */
#define	ifbrp_hellotime	ifbrp_ifbrpu.ifbrpu_int8	/* hello time (sec) */
#define	ifbrp_fwddelay	ifbrp_ifbrpu.ifbrpu_int8	/* fwd time (sec) */
#define	ifbrp_maxage	ifbrp_ifbrpu.ifbrpu_int8	/* max age (sec) */
#define	ifbrp_filter	ifbrp_ifbrpu.ifbrpu_int32	/* filtering flags */

#ifdef _KERNEL
#ifdef __QNXNTO__
struct bridge_threadinfo;
#endif
/*
 * Timekeeping structure used in spanning tree code.
 */
struct bridge_timer {
	uint16_t	active;
	uint16_t	value;
};

struct bstp_config_unit {
	uint64_t	cu_rootid;
	uint64_t	cu_bridge_id;
	uint32_t	cu_root_path_cost;
	uint16_t	cu_message_age;
	uint16_t	cu_max_age;
	uint16_t	cu_hello_time;
	uint16_t	cu_forward_delay;
	uint16_t	cu_port_id;
	uint8_t		cu_message_type;
	uint8_t		cu_topology_change_acknowledgment;
	uint8_t		cu_topology_change;
};

struct bstp_tcn_unit {
	uint8_t		tu_message_type;
};

/*
 * Bridge interface list entry.
 */
struct bridge_iflist {
#ifdef __QNXNTO__
	struct tpass_entry	bif_tpe;	/* As first member for tpass */
#endif
	LIST_ENTRY(bridge_iflist) bif_next;
	uint64_t		bif_designated_root;
	uint64_t		bif_designated_bridge;
	uint32_t		bif_path_cost;
	uint32_t		bif_designated_cost;
	struct bridge_timer	bif_hold_timer;
	struct bridge_timer	bif_message_age_timer;
	struct bridge_timer	bif_forward_delay_timer;
	uint16_t		bif_port_id;
	uint16_t		bif_designated_port;
	struct bstp_config_unit	bif_config_bpdu;
	uint8_t			bif_state;
	uint8_t			bif_topology_change_acknowledge;
	uint8_t			bif_config_pending;
	uint8_t			bif_change_detection_enabled;
	uint8_t			bif_priority;
	struct ifnet		*bif_ifp;	/* member if */
	uint32_t		bif_flags;	/* member if flags */
#ifdef __QNXNTO__
	struct bridge_iflist_thread {
		TPASS_LIST_DECLARE(, bridge_iflist)	bif_th_tplu;
#define bif_th_passlist bif_th_tplu.tpl_local
		LIST_ENTRY(bridge_iflist)	bif_th_list;
	} bif_thread[1];
#endif
};

#ifdef __QNXNTO__
#define BIF_MARK_OFFLIST(bifth)	\
        TPASS_MARK_OFFLIST(&(bifth)->bif_th_tplu.tpl_private)
#define BRT_MARK_OFFLIST(brtth) \
        TPASS_MARK_OFFLIST(&(brtth)->brt_th_tplu.tpl_private)
#endif

/*
 * Bridge route node.
 */
struct bridge_rtnode {
#ifdef __QNXNTO__
	struct tpass_entry	brt_tpe;	/* As first member for tpass */
#endif
	LIST_ENTRY(bridge_rtnode) brt_hash;	/* hash table linkage */
	LIST_ENTRY(bridge_rtnode) brt_list;	/* list linkage */
	struct ifnet		*brt_ifp;	/* destination if */
	unsigned long		brt_expire;	/* expiration time */
#ifdef __QNXNTO__
	int			brt_hash_index;
#endif
	uint8_t			brt_flags;	/* address flags */
	uint8_t			brt_addr[ETHER_ADDR_LEN];
#ifdef __QNXNTO__
	struct bridge_rtnode_thread {
		TPASS_LIST_DECLARE(, bridge_rtnode)	brt_th_tplu;
#define brt_th_passlist brt_th_tplu.tpl_local
		LIST_ENTRY(bridge_rtnode)	brt_th_hash;	/* per thread hash table linkage. */
		LIST_ENTRY(bridge_rtnode)	brt_th_list;	/* per thread list linkage. */
	} brt_thread[1];
#endif
};

/*
 * Software state for each bridge.
 */
#ifdef __QNXNTO__
TPASS_QUEUES_DECLARE(iflist_passq, bridge_iflist);
TPASS_QUEUES_DECLARE(rtnode_passq, bridge_rtnode);
#endif
struct bridge_softc {
	struct ifnet		sc_if;
	LIST_ENTRY(bridge_softc) sc_list;
	uint64_t		sc_designated_root;
	uint64_t		sc_bridge_id;
	struct bridge_iflist	*sc_root_port;
	uint32_t		sc_root_path_cost;
	uint16_t		sc_max_age;
	uint16_t		sc_hello_time;
	uint16_t		sc_forward_delay;
	uint16_t		sc_bridge_max_age;
	uint16_t		sc_bridge_hello_time;
	uint16_t		sc_bridge_forward_delay;
	uint16_t		sc_topology_change_time;
	uint16_t		sc_hold_time;
	uint16_t		sc_bridge_priority;
	uint8_t			sc_topology_change_detected;
	uint8_t			sc_topology_change;
	struct bridge_timer	sc_hello_timer;
	struct bridge_timer	sc_topology_change_timer;
	struct bridge_timer	sc_tcn_timer;
	uint32_t		sc_brtmax;	/* max # of addresses */
	uint32_t		sc_brtcnt;	/* cur. # of addresses */
	uint32_t		sc_brttimeout;	/* rt timeout in seconds */
	struct callout		sc_brcallout;	/* bridge callout */
	struct callout		sc_bstpcallout;	/* STP callout */
	LIST_HEAD(, bridge_iflist) sc_iflist;	/* master member interface list */
	LIST_HEAD(, bridge_rtnode) *sc_rthash;  /* master forwarding table */
	LIST_HEAD(, bridge_rtnode) sc_rtlist;	/* list version of above */
	uint32_t		sc_rthash_key;	/* key for hash */
	uint32_t		sc_filter_flags; /* ipf and flags */
#ifdef __QNXNTO__
	void			*sc_alloc;
	struct bridge_softc_thread {
		union iflist_passq	sc_th_iftpqu;
#define sc_th_iftpq sc_th_iftpqu.tpq_local
		union rtnode_passq	sc_th_rttpqu;
#define sc_th_rttpq sc_th_rttpqu.tpq_local

		LIST_HEAD(, bridge_iflist)	sc_th_iflist;	/* member interface list */
		LIST_HEAD(, bridge_rtnode)	*sc_th_rthash;	/* our forwarding table */
		LIST_HEAD(, bridge_rtnode)	sc_th_rtlist;	/* list version of above */
	} sc_thread[1]; /* More if multithreaded */
#endif
};

extern const uint8_t bstp_etheraddr[];

void	bridge_ifdetach(struct ifnet *);

int	bridge_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
struct mbuf *bridge_input(struct ifnet *, struct mbuf *);

void	bstp_initialization(struct bridge_softc *);
void	bstp_stop(struct bridge_softc *);
struct mbuf *bstp_input(struct ifnet *, struct mbuf *);

void	bridge_enqueue(struct bridge_softc *, struct ifnet *, struct mbuf *,
	    int);
#ifdef __QNXNTO__
int	bridge_pre_main_init(void);
void	bridge_pre_main_fini(void);
int	bridge_register(struct bridge_threadinfo **);
int	bridge_deregister(struct bridge_threadinfo *);
#ifndef VARIANT_uni
int	bridge_destroy(struct bridge_threadinfo *);
#endif
#endif

#endif /* _KERNEL */
#endif /* !_NET_IF_BRIDGEVAR_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_bridgevar.h $ $Rev: 884515 $")
#endif
