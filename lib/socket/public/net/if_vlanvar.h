/*	$NetBSD: if_vlanvar.h,v 1.6 2005/12/11 12:24:51 christos Exp $	*/

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from FreeBSD: if_vlan_var.h,v 1.3 1999/08/28 00:48:24 peter Exp
 */

#ifndef _NET_IF_VLANVAR_H_INCLUDED
#define	_NET_IF_VLANVAR_H_INCLUDED

#ifndef _STDINT_H_INCLUDED
#include <stdint.h>
#endif

#ifndef _NET_IF_ETHER_H_INCLUDED
#include <net/if_ether.h>
#endif

struct ether_vlan_header {
	uint8_t		evl_dhost[ETHER_ADDR_LEN];
	uint8_t		evl_shost[ETHER_ADDR_LEN];
	uint16_t	evl_encap_proto;
	uint16_t	evl_tag;
	uint16_t	evl_proto;
} __attribute__((__packed__));

#define	EVL_VLANOFTAG(tag)	((tag) & 4095)
#define	EVL_PRIOFTAG(tag)	(((tag) >> 13) & 7)

/* Configuration structure for SIOCSETVLAN and SIOCGETVLAN ioctls. */
struct vlanreq {
	char		vlr_parent[IFNAMSIZ];
	unsigned short	vlr_tag;
};

#define	SIOCSETVLAN	SIOCSIFGENERIC
#define	SIOCGETVLAN	SIOCGIFGENERIC

#ifdef _KERNEL
void	vlan_input(struct ifnet *, struct mbuf *);
void	vlan_ifdetach(struct ifnet *);
#endif	/* _KERNEL */

#ifdef __QNXNTO__
struct ifvlan {
	union {
		struct ethercom ifvu_ec;
	} ifv_u;
	struct ifnet *ifv_p;	/* parent interface of this vlan */
	struct ifv_linkmib {
		const struct vlan_multisw *ifvm_msw;
		int	ifvm_encaplen;	/* encapsulation length */
		int	ifvm_mtufudge;	/* MTU fudged by this much */
		int	ifvm_mintu;	/* min transmission unit */
		uint16_t ifvm_proto;	/* encapsulation ethertype */
		uint16_t ifvm_tag;	/* tag to apply on packets */
	} ifv_mib;
	LIST_HEAD(__vlan_mchead, vlan_mc_entry) ifv_mc_listhead;
	LIST_ENTRY(ifvlan) ifv_list;
	int ifv_flags;
	void *ifv_alloc; /* QNX specific parameter. */
};
#endif
#endif	/* !_NET_IF_VLANVAR_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/net/if_vlanvar.h $ $Rev: 852068 $")
#endif
