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



/*	$NetBSD: ip6_output.c,v 1.149 2012/06/25 15:28:40 christos Exp $	*/
/*	$KAME: ip6_output.c,v 1.172 2001/03/25 09:55:56 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)ip_output.c	8.3 (Berkeley) 1/21/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ip6_output.c,v 1.149 2012/06/25 15:28:40 christos Exp $");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#include "opt_pfil_hooks.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/route.h>
#ifdef PFIL_HOOKS
#include <net/pfil.h>
#endif

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in_offload.h>
#include <netinet/portalgo.h>
#include <netinet6/in6_offload.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#include <netipsec/key.h>
#include <netipsec/xform.h>
#endif

#include <net/net_osdep.h>

#if defined(__QNXNTO__) &&			\
    (defined(IPSEC) || defined(FAST_IPSEC)) &&	\
    defined(PFIL_HOOKS)
extern int pfil_ipsec;
#endif

#ifdef __QNXNTO__
#include <compat/sys/sockio.h> /* COMPAT_OIFREQ for SO_BINDTODEVICE */
#include <net/if_extra.h>
#include <net/if_vlanvar.h>
#include <net/if_types.h>
#endif

#ifdef PFIL_HOOKS
extern struct pfil_head inet6_pfil_hook;	/* XXX */
#endif

struct ip6_exthdrs {
	struct mbuf *ip6e_ip6;
	struct mbuf *ip6e_hbh;
	struct mbuf *ip6e_dest1;
	struct mbuf *ip6e_rthdr;
	struct mbuf *ip6e_dest2;
};

static int ip6_pcbopt(int, u_char *, int, struct ip6_pktopts **,
	kauth_cred_t, int);
static int ip6_getpcbopt(struct ip6_pktopts *, int, struct mbuf **);
static int ip6_setpktopt(int, u_char *, int, struct ip6_pktopts *, kauth_cred_t,
	int, int, int);
#ifndef __QNXNTO__
static int ip6_setmoptions(int, struct ip6_moptions **, struct mbuf *);
#else
#ifndef QNX_MFIB
static int ip6_setmoptions(int, struct ip6_moptions **, struct mbuf *, struct ifnet *);
#else
static int ip6_setmoptions(int, struct ip6_moptions **, struct mbuf *, struct ifnet *, int);
#endif
#endif
static int ip6_getmoptions(int, struct ip6_moptions *, struct mbuf **);
static int ip6_copyexthdr(struct mbuf **, caddr_t, int);
static int ip6_insertfraghdr(struct mbuf *, struct mbuf *, int,
	struct ip6_frag **);
static int ip6_insert_jumboopt(struct ip6_exthdrs *, u_int32_t);
static int ip6_splithdr(struct mbuf *, struct ip6_exthdrs *);
static int ip6_getpmtu(struct route_in6 *, struct route_in6 *,
	struct ifnet *, struct in6_addr *, u_long *, int *
#ifdef __QNXNTO__
	, struct ifnet *
#ifdef QNX_MFIB
	, int
#endif
#endif
	);
static int copypktopts(struct ip6_pktopts *, struct ip6_pktopts *, int);

#ifdef RFC2292
static int ip6_pcbopts(struct ip6_pktopts **, struct mbuf *,
	struct socket *);
#endif

#define	IN6_NEED_CHECKSUM(ifp, csum_flags) \
	(__predict_true(((ifp)->if_flags & IFF_LOOPBACK) == 0 || \
	(((csum_flags) & M_CSUM_UDPv6) != 0 && udp_do_loopback_cksum) || \
	(((csum_flags) & M_CSUM_TCPv6) != 0 && tcp_do_loopback_cksum)))

/*
 * IP6 output. The packet in mbuf chain m contains a skeletal IP6
 * header (with pri, len, nxt, hlim, src, dst).
 * This function may modify ver and hlim only.
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 *
 * type of "mtu": rt_rmx.rmx_mtu is u_long, ifnet.ifr_mtu is int, and
 * nd_ifinfo.linkmtu is u_int32_t.  so we use u_long to hold largest one,
 * which is rt_rmx.rmx_mtu.
 */
int
#ifndef __QNXNTO__
ip6_output
#else
(ip6_output)
#endif
    (
    struct mbuf *m0,
    struct ip6_pktopts *opt,
    struct route_in6 *ro,
    int flags,
    struct ip6_moptions *im6o,
    struct socket *so,
    struct ifnet **ifpp		/* XXX: just for statistics */
#ifdef __QNXNTO__
    , struct ifnet *bounddevice
    , struct ifnet *ipsechint
#ifdef QNX_MFIB
    , int fib
#endif
#endif
)
{
	struct ip6_hdr *ip6, *mhip6;
	struct ifnet *ifp, *origifp;
	struct mbuf *m = m0;
	int hlen, tlen, len, off;
	boolean_t tso;
	struct route_in6 ip6route;
	struct rtentry *rt = NULL;
	struct sockaddr_in6 *dst, src_sa, dst_sa;
	int error = 0;
	struct in6_ifaddr *ia = NULL;
	u_long mtu;
	int alwaysfrag, dontfrag;
	u_int32_t optlen = 0, plen = 0, unfragpartlen = 0;
	struct ip6_exthdrs exthdrs;
	struct in6_addr finaldst, src0, dst0;
	u_int32_t zone;
	struct route_in6 *ro_pmtu = NULL;
	int hdrsplit = 0;
	int needipsec = 0;
#ifdef IPSEC
	int needipsectun = 0;
	struct secpolicy *sp = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
#endif /* IPSEC */
#ifdef FAST_IPSEC
	struct secpolicy *sp = NULL;
	int s;
#endif
#ifdef __QNXNTO__
	u_char *nexthdrp;
	struct mbuf *mprev;
	struct ifvlan *ifv = NULL;
#endif

#ifdef  DIAGNOSTIC
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("ip6_output: no HDR");

	if ((m->m_pkthdr.csum_flags &
	    (M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_TSOv4)) != 0) {
		panic("ip6_output: IPv4 checksum offload flags: %d",
		    m->m_pkthdr.csum_flags);
	}

	if ((m->m_pkthdr.csum_flags & (M_CSUM_TCPv6|M_CSUM_UDPv6)) ==
	    (M_CSUM_TCPv6|M_CSUM_UDPv6)) {
		panic("ip6_output: conflicting checksum offload flags: %d",
		    m->m_pkthdr.csum_flags);
	}
#endif

	M_CSUM_DATA_IPv6_HL_SET(m->m_pkthdr.csum_data, sizeof(struct ip6_hdr));
	
#ifdef __QNXNTO__
	/* In Strong ES model, if the socket was bound once before 
	 * and its interface detached, it is now unroutable...
	 */
	if (ip_bindinterface &&
		bounddevice == NULL &&
		so != NULL && sotoin6pcb(so) != NULL && 
		(sotoin6pcb(so)->in6p_flags & IN6P_DEVPURGE) != 0) {
		error = EHOSTUNREACH;
		goto bad;
	}
#endif

#define MAKE_EXTHDR(hp, mp)						\
    do {								\
	if (hp) {							\
		struct ip6_ext *eh = (struct ip6_ext *)(hp);		\
		error = ip6_copyexthdr((mp), (caddr_t)(hp), 		\
		    ((eh)->ip6e_len + 1) << 3);				\
		if (error)						\
			goto freehdrs;					\
	}								\
    } while (/*CONSTCOND*/ 0)

	bzero(&exthdrs, sizeof(exthdrs));
	if (opt) {
		/* Hop-by-Hop options header */
		MAKE_EXTHDR(opt->ip6po_hbh, &exthdrs.ip6e_hbh);
		/* Destination options header(1st part) */
		MAKE_EXTHDR(opt->ip6po_dest1, &exthdrs.ip6e_dest1);
		/* Routing header */
		MAKE_EXTHDR(opt->ip6po_rthdr, &exthdrs.ip6e_rthdr);
		/* Destination options header(2nd part) */
		MAKE_EXTHDR(opt->ip6po_dest2, &exthdrs.ip6e_dest2);
	}

	/*
	 * Calculate the total length of the extension header chain.
	 * Keep the length of the unfragmentable part for fragmentation.
	 */
	optlen = 0;
	if (exthdrs.ip6e_hbh) optlen += exthdrs.ip6e_hbh->m_len;
	if (exthdrs.ip6e_dest1) optlen += exthdrs.ip6e_dest1->m_len;
	if (exthdrs.ip6e_rthdr) optlen += exthdrs.ip6e_rthdr->m_len;
	unfragpartlen = optlen + sizeof(struct ip6_hdr);
	/* NOTE: we don't add AH/ESP length here. do that later. */
	if (exthdrs.ip6e_dest2) optlen += exthdrs.ip6e_dest2->m_len;

#ifndef __QNXNTO__
	if (needipsec &&
	    (m->m_pkthdr.csum_flags & (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0) {
		in6_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~(M_CSUM_UDPv6|M_CSUM_TCPv6);
	}


	/*
	 * If we need IPsec, or there is at least one extension header,
	 * separate IP6 header from the payload.
	 */
	if ((needipsec || optlen) && !hdrsplit)
#else
	/*
	 * If there is at least one extension header,
	 * separate IP6 header from the payload.
	 */
	if (optlen && !hdrsplit)
#endif
		{
		if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
			m = NULL;
			goto freehdrs;
		}
		m = exthdrs.ip6e_ip6;
		hdrsplit++;
	}

	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	/* adjust mbuf packet header length */
	m->m_pkthdr.len += optlen;
	plen = m->m_pkthdr.len - sizeof(*ip6);

	/* If this is a jumbo payload, insert a jumbo payload option. */
	if (plen > IPV6_MAXPACKET) {
		if (!hdrsplit) {
			if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
				m = NULL;
				goto freehdrs;
			}
			m = exthdrs.ip6e_ip6;
			hdrsplit++;
		}
		/* adjust pointer */
		ip6 = mtod(m, struct ip6_hdr *);
		if ((error = ip6_insert_jumboopt(&exthdrs, plen)) != 0)
			goto freehdrs;
		optlen += 8; /* XXX JUMBOOPTLEN */
		ip6->ip6_plen = 0;
	} else
		ip6->ip6_plen = htons(plen);

	/*
	 * Concatenate headers and fill in next header fields.
	 * Here we have, on "m"
	 *	IPv6 payload
	 * and we insert headers accordingly.  Finally, we should be getting:
	 *	IPv6 hbh dest1 rthdr ah* [esp* dest2 payload]
	 *
	 * during the header composing process, "m" points to IPv6 header.
	 * "mprev" points to an extension header prior to esp.
	 */
	{
#ifndef __QNXNTO__
		u_char *nexthdrp = &ip6->ip6_nxt;
		struct mbuf *mprev = m;
#else
		nexthdrp = &ip6->ip6_nxt;
		mprev = m;
#endif
		/*
		 * we treat dest2 specially.  this makes IPsec processing
		 * much easier.  the goal here is to make mprev point the
		 * mbuf prior to dest2.
		 *
		 * result: IPv6 dest2 payload
		 * m and mprev will point to IPv6 header.
		 */
		if (exthdrs.ip6e_dest2) {
			if (!hdrsplit)
				panic("assumption failed: hdr not split");
			exthdrs.ip6e_dest2->m_next = m->m_next;
			m->m_next = exthdrs.ip6e_dest2;
			*mtod(exthdrs.ip6e_dest2, u_char *) = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_DSTOPTS;
		}

#define MAKE_CHAIN(m, mp, p, i)\
    do {\
	if (m) {\
		if (!hdrsplit) \
			panic("assumption failed: hdr not split"); \
		*mtod((m), u_char *) = *(p);\
		*(p) = (i);\
		p = mtod((m), u_char *);\
		(m)->m_next = (mp)->m_next;\
		(mp)->m_next = (m);\
		(mp) = (m);\
	}\
    } while (/*CONSTCOND*/ 0)
		/*
		 * result: IPv6 hbh dest1 rthdr dest2 payload
		 * m will point to IPv6 header.  mprev will point to the
		 * extension header prior to dest2 (rthdr in the above case).
		 */
		MAKE_CHAIN(exthdrs.ip6e_hbh, mprev, nexthdrp, IPPROTO_HOPOPTS);
		MAKE_CHAIN(exthdrs.ip6e_dest1, mprev, nexthdrp,
		    IPPROTO_DSTOPTS);
		MAKE_CHAIN(exthdrs.ip6e_rthdr, mprev, nexthdrp,
		    IPPROTO_ROUTING);

		M_CSUM_DATA_IPv6_HL_SET(m->m_pkthdr.csum_data,
		    sizeof(struct ip6_hdr) + optlen);

	}

	/*
	 * If there is a routing header, replace destination address field
	 * with the first hop of the routing header.
	 */
	if (exthdrs.ip6e_rthdr) {
		struct ip6_rthdr *rh;
		struct ip6_rthdr0 *rh0;
		struct in6_addr *addr;
		struct sockaddr_in6 sa;

		rh = (struct ip6_rthdr *)(mtod(exthdrs.ip6e_rthdr,
		    struct ip6_rthdr *));
		finaldst = ip6->ip6_dst;
		switch (rh->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			 rh0 = (struct ip6_rthdr0 *)rh;
			 addr = (struct in6_addr *)(rh0 + 1);

			 /*
			  * construct a sockaddr_in6 form of
			  * the first hop.
			  *
			  * XXX: we may not have enough
			  * information about its scope zone;
			  * there is no standard API to pass
			  * the information from the
			  * application.
			  */
			 bzero(&sa, sizeof(sa));
			 sa.sin6_family = AF_INET6;
			 sa.sin6_len = sizeof(sa);
			 sa.sin6_addr = addr[0];
			 if ((error = sa6_embedscope(&sa,
			     ip6_use_defzone)) != 0) {
				 goto bad;
			 }
			 ip6->ip6_dst = sa.sin6_addr;
			 (void)memmove(&addr[0], &addr[1],
			     sizeof(struct in6_addr) *
			     (rh0->ip6r0_segleft - 1));
			 addr[rh0->ip6r0_segleft - 1] = finaldst;
			 /* XXX */
			 in6_clearscope(addr + rh0->ip6r0_segleft - 1);
			 break;
		default:	/* is it possible? */
			 error = EINVAL;
			 goto bad;
		}
	}

	/* Source address validation */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
	    (flags & IPV6_UNSPECSRC) == 0) {
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}

	ip6stat.ip6s_localout++;

	/*
	 * Route packet.
	 */
	/* initialize cached route */
	if (ro == 0) {
		ro = &ip6route;
		bzero((caddr_t)ro, sizeof(*ro));
	}
	ro_pmtu = ro;
	if (opt && opt->ip6po_rthdr)
		ro = &opt->ip6po_route;
	dst = (struct sockaddr_in6 *)&ro->ro_dst;

 	/*
	 * if specified, try to fill in the traffic class field.
	 * do not override if a non-zero value is already set.
	 * we check the diffserv field and the ecn field separately.
	 */
	if (opt && opt->ip6po_tclass >= 0) {
		int mask = 0;

		if ((ip6->ip6_flow & htonl(0xfc << 20)) == 0)
			mask |= 0xfc;
		if ((ip6->ip6_flow & htonl(0x03 << 20)) == 0)
			mask |= 0x03;
		if (mask != 0)
			ip6->ip6_flow |= htonl((opt->ip6po_tclass & mask) << 20);
	}

	/* fill in or override the hop limit field, if necessary. */
	if (opt && opt->ip6po_hlim != -1)
		ip6->ip6_hlim = opt->ip6po_hlim & 0xff;
	else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (im6o != NULL)
			ip6->ip6_hlim = im6o->im6o_multicast_hlim;
		else
			ip6->ip6_hlim = ip6_defmcasthlim;
	}

#if defined(__QNXNTO__) && \
    (defined(IPSEC) || defined(FAST_IPSEC)) &&	\
    defined(PFIL_HOOKS)
	if (pfil_ipsec) {
		/* Do a route lookup to get the ifp */
		ip6 = mtod(m, struct ip6_hdr *);
		bzero(&dst_sa, sizeof(dst_sa));
		dst_sa.sin6_family = AF_INET6;
		dst_sa.sin6_len = sizeof(dst_sa);
		dst_sa.sin6_addr = ip6->ip6_dst;
		ifp = NULL;
		error = in6_selectroute(&dst_sa, opt, im6o, ro, &ifp,
#ifndef QNX_MFIB
					&rt, 0, bounddevice);
#else
					&rt, 0, bounddevice, fib);
#endif
		if (error || (ifp == NULL)) {
			goto bad;
		}
		if ((error = pfil_run_hooks(&inet6_pfil_hook, &m, ifp,
#ifndef QNX_MFIB
					    PFIL_OUT)) != 0)
#else
						PFIL_OUT, fib)) != 0)
#endif
						{
			goto done;
		}
		if (m == NULL) {
			goto done;
		}
	}
#endif

#ifdef IPSEC
if (QNXNTO_IPSEC_ENABLED) {
	if ((flags & IPV6_FORWARDING) != 0) {
		needipsec = 0;
		goto skip_ipsec2;
	}

	/* get a security policy for this packet */
	if (so == NULL)
		sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, 0, &error
#ifdef __QNXNTO__
				, ipsechint
#endif
				);
	else {
		if (IPSEC_PCB_SKIP_IPSEC(sotoinpcb_hdr(so)->inph_sp,
					 IPSEC_DIR_OUTBOUND)) {
			needipsec = 0;
			goto skip_ipsec2;
		}
		sp = ipsec6_getpolicybysock(m, IPSEC_DIR_OUTBOUND, so, &error
#ifdef __QNXNTO__
				, ipsechint
#endif
				);
	}

	if (sp == NULL) {
		ipsec6stat.out_inval++;
		goto done;
	}

	error = 0;

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
		/*
		 * This packet is just discarded.
		 */
		ipsec6stat.out_polvio++;
		goto done;

	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		/* no need to do IPsec. */
		needipsec = 0;
		goto skip_ipsec2;
		break;

	case IPSEC_POLICY_IPSEC:
		if (sp->req == NULL) {
			/* XXX should be panic ? */
			printf("ip6_output: No IPsec request specified.\n");
			error = EINVAL;
			goto done;
		}
		needipsec = 1;
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		printf("ip6_output: Invalid policy found. %d\n", sp->policy);
	}

	if ((m->m_pkthdr.csum_flags & (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0) {
		in6_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~(M_CSUM_UDPv6|M_CSUM_TCPv6);
	}

	if (!hdrsplit) {
		if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
			m = NULL;
			goto done;
		}
		m = exthdrs.ip6e_ip6;
		hdrsplit++;
	}
	/*
	 * pointers after IPsec headers are not valid any more.
	 * other pointers need a great care too.
	 * (IPsec routines should not mangle mbufs prior to AH/ESP)
	 */
	exthdrs.ip6e_dest2 = NULL;

	{
		struct ip6_rthdr *rh = NULL;
		int segleft_org = 0;
		struct ipsec_output_state state;

		if (exthdrs.ip6e_rthdr) {
			rh = mtod(exthdrs.ip6e_rthdr, struct ip6_rthdr *);
			segleft_org = rh->ip6r_segleft;
			rh->ip6r_segleft = 0;
		}

		bzero(&state, sizeof(state));
		state.m = m;
		error = ipsec6_output_trans(&state, nexthdrp, mprev, sp, flags,
		    &needipsectun
#ifdef QNX_MFIB
		    , fib
#endif
		);
		m = state.m;
		if (error) {
			/* mbuf is already reclaimed in ipsec6_output_trans. */
			m = NULL;
			switch (error) {
			case EHOSTUNREACH:
			case ENETUNREACH:
			case EMSGSIZE:
			case ENOBUFS:
			case ENOMEM:
				break;
			default:
				printf("ip6_output (ipsec): error code %d\n", error);
				/* FALLTHROUGH */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}
		if (exthdrs.ip6e_rthdr) {
			/* ah6_output doesn't modify mbuf chain */
			rh->ip6r_segleft = segleft_org;
		}
	}
	if (needipsectun) {
		struct ipsec_output_state state;

		/*
		 * All the extension headers will become inaccessible
		 * (since they can be encrypted).
		 * Don't panic, we need no more updates to extension headers
		 * on inner IPv6 packet (since they are now encapsulated).
		 *
		 * IPv6 [ESP|AH] IPv6 [extension headers] payload
		 */
		bzero(&exthdrs, sizeof(exthdrs));
		exthdrs.ip6e_ip6 = m;

		bzero(&state, sizeof(state));
		state.m = m;
		state.ro = (struct route *)ro;
		state.dst = (struct sockaddr *)dst;

		error = ipsec6_output_tunnel(&state, sp, flags);

		m = state.m;
		ro_pmtu = ro = (struct route_in6 *)state.ro;
		dst = (struct sockaddr_in6 *)state.dst;
		if (error) {
			/* mbuf is already reclaimed in ipsec6_output_tunnel. */
			m0 = m = NULL;
			m = NULL;
			switch (error) {
			case EHOSTUNREACH:
			case ENETUNREACH:
			case EMSGSIZE:
			case ENOBUFS:
			case ENOMEM:
				break;
			default:
				printf("ip6_output (ipsec): error code %d\n", error);
				/* FALLTHROUGH */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}

		exthdrs.ip6e_ip6 = m;
	}
}
skip_ipsec2:;
#endif /* IPSEC */
#ifdef FAST_IPSEC
if (QNXNTO_IPSEC_ENABLED) {
	/* Check the security policy (SP) for the packet */
    
	sp = ipsec6_check_policy(m,so,flags,&needipsec,&error
#ifdef __QNXNTO__
			, ipsechint
#endif
			);
	if (error != 0) {
		/*
		 * Hack: -EINVAL is used to signal that a packet
		 * should be silently discarded.  This is typically
		 * because we asked key management for an SA and
		 * it was delayed (e.g. kicked up to IKE).
		 */
		if (error == -EINVAL) 
			error = 0;
		goto bad;
	}

	if (needipsec) {
		if ((m->m_pkthdr.csum_flags &
		     (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0) {
			in6_delayed_cksum(m);
			m->m_pkthdr.csum_flags &= ~(M_CSUM_UDPv6|M_CSUM_TCPv6);
		}
		if (!hdrsplit) {
			if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
				m = NULL;
				goto bad;
			}
			m = exthdrs.ip6e_ip6;
			hdrsplit++;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		s = splsoftnet();
		error = ipsec6_process_packet(m,sp->req);

		/*
		 * Preserve KAME behaviour: ENOENT can be returned
		 * when an SA acquire is in progress.  Don't propagate
		 * this to user-level; it confuses applications.
		 * XXX this will go away when the SADB is redone.
		 */
		if (error == ENOENT)
			error = 0;
		splx(s);
		goto done;
    }
}
#endif /* FAST_IPSEC */    



	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	bzero(&dst_sa, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(dst_sa);
	dst_sa.sin6_addr = ip6->ip6_dst;
#ifndef __QNXNTO__
	if ((error = in6_selectroute(&dst_sa, opt, im6o, ro, &ifp, &rt, 0))
#else
#ifndef QNX_MFIB
	if ((error = in6_selectroute(&dst_sa, opt, im6o, ro, &ifp, &rt, 0, bounddevice))
#else
	if ((error = in6_selectroute(&dst_sa, opt, im6o, ro, &ifp, &rt, 0, bounddevice, fib))
#endif
#endif
	    != 0) {
		switch (error) {
		case EHOSTUNREACH:
			ip6stat.ip6s_noroute++;
			break;
		case EADDRNOTAVAIL:
		default:
			break; /* XXX statistics? */
		}
		if (ifp != NULL)
			in6_ifstat_inc(ifp, ifs6_out_discard);
		goto bad;
	}
	if (rt == NULL) {
		/*
		 * If in6_selectroute() does not return a route entry,
		 * dst may not have been updated.
		 */
		*dst = dst_sa;	/* XXX */
	}

	/*
	 * then rt (for unicast) and ifp must be non-NULL valid values.
	 */
	if ((flags & IPV6_FORWARDING) == 0) {
		/* XXX: the FORWARDING flag can be set for mrouting. */
		in6_ifstat_inc(ifp, ifs6_out_request);
	}
	if (rt != NULL) {
		ia = (struct in6_ifaddr *)(rt->rt_ifa);
		rt->rt_use++;
	}

	/*
	 * The outgoing interface must be in the zone of source and
	 * destination addresses.  We should use ia_ifp to support the
	 * case of sending packets to an address of our own.
	 */
	if (ia != NULL && ia->ia_ifp)
		origifp = ia->ia_ifp;
	else
		origifp = ifp;

	src0 = ip6->ip6_src;
	if (in6_setscope(&src0, origifp, &zone))
		goto badscope;
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&src_sa) || zone != src_sa.sin6_scope_id)
		goto badscope;

	dst0 = ip6->ip6_dst;
	if (in6_setscope(&dst0, origifp, &zone))
		goto badscope;
	/* re-initialize to be sure */
	bzero(&dst_sa, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(dst_sa);
	dst_sa.sin6_addr = ip6->ip6_dst;
	if (sa6_recoverscope(&dst_sa) || zone != dst_sa.sin6_scope_id)
		goto badscope;

	/* scope check is done. */
	goto routefound;

  badscope:
	ip6stat.ip6s_badscope++;
	in6_ifstat_inc(origifp, ifs6_out_discard);
	if (error == 0)
		error = EHOSTUNREACH; /* XXX */
	goto bad;

  routefound:
	if (rt && !IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (opt && opt->ip6po_nextroute.ro_rt) {
			/*
			 * The nexthop is explicitly specified by the
			 * application.  We assume the next hop is an IPv6
			 * address.
			 */
			dst = (struct sockaddr_in6 *)opt->ip6po_nexthop;
		} else if ((rt->rt_flags & RTF_GATEWAY))
			dst = (struct sockaddr_in6 *)rt->rt_gateway;
	}

	/*
	 * XXXXXX: original code follows:
	 */
	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
		m->m_flags &= ~(M_BCAST | M_MCAST);	/* just in case */
	else {
		struct	in6_multi *in6m;

		m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;

		in6_ifstat_inc(ifp, ifs6_out_mcast);

		/*
		 * Confirm that the outgoing interface supports multicast.
		 */
		if (!(ifp->if_flags & IFF_MULTICAST)) {
			ip6stat.ip6s_noroute++;
			in6_ifstat_inc(ifp, ifs6_out_discard);
			error = ENETUNREACH;
			goto bad;
		}

		IN6_LOOKUP_MULTI(ip6->ip6_dst, ifp, in6m);
		if (in6m != NULL &&
		   (im6o == NULL || im6o->im6o_multicast_loop)) {
			/*
			 * If we belong to the destination multicast group
			 * on the outgoing interface, and the caller did not
			 * forbid loopback, loop back a copy.
			 */
			ip6_mloopback(ifp, m, dst);
		} else {
			/*
			 * If we are acting as a multicast router, perform
			 * multicast forwarding as if the packet had just
			 * arrived on the interface to which we are about
			 * to send.  The multicast forwarding function
			 * recursively calls this function, using the
			 * IPV6_FORWARDING flag to prevent infinite recursion.
			 *
			 * Multicasts that are looped back by ip6_mloopback(),
			 * above, will be forwarded by the ip6_input() routine,
			 * if necessary.
			 */
			if (ip6_mrouter && (flags & IPV6_FORWARDING) == 0) {
				if (ip6_mforward(ip6, ifp, m) != 0) {
					m_freem(m);
					goto done;
				}
			}
		}
		/*
		 * Multicasts with a hoplimit of zero may be looped back,
		 * above, but must not be transmitted on a network.
		 * Also, multicasts addressed to the loopback interface
		 * are not sent -- the above call to ip6_mloopback() will
		 * loop back a copy if this host actually belongs to the
		 * destination group on the loopback interface.
		 */
		if (ip6->ip6_hlim == 0 || (ifp->if_flags & IFF_LOOPBACK) ||
		    IN6_IS_ADDR_MC_INTFACELOCAL(&ip6->ip6_dst)) {
			m_freem(m);
			goto done;
		}
	}

	/*
	 * Fill the outgoing inteface to tell the upper layer
	 * to increment per-interface statistics.
	 */
	if (ifpp)
		*ifpp = ifp;

	/* Determine path MTU. */
	if ((error = ip6_getpmtu(ro_pmtu, ro, ifp, &finaldst, &mtu,
#ifndef __QNXNTO__
	    &alwaysfrag)) != 0)
#else
#ifndef QNX_MFIB
	    &alwaysfrag, bounddevice)) != 0)
#else
		&alwaysfrag, bounddevice, fib)) != 0)
#endif
#endif
		goto bad;
#ifdef IPSEC
	if (needipsectun)
		mtu = IPV6_MMTU;
#endif

	/*
	 * The caller of this function may specify to use the minimum MTU
	 * in some cases.
	 * An advanced API option (IPV6_USE_MIN_MTU) can also override MTU
	 * setting.  The logic is a bit complicated; by default, unicast
	 * packets will follow path MTU while multicast packets will be sent at
	 * the minimum MTU.  If IP6PO_MINMTU_ALL is specified, all packets
	 * including unicast ones will be sent at the minimum MTU.  Multicast
	 * packets will always be sent at the minimum MTU unless
	 * IP6PO_MINMTU_DISABLE is explicitly specified.
	 * See RFC 3542 for more details.
	 */
	if (mtu > IPV6_MMTU) {
		if ((flags & IPV6_MINMTU))
			mtu = IPV6_MMTU;
		else if (opt && opt->ip6po_minmtu == IP6PO_MINMTU_ALL)
			mtu = IPV6_MMTU;
		else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
			 (opt == NULL ||
			  opt->ip6po_minmtu != IP6PO_MINMTU_DISABLE)) {
			mtu = IPV6_MMTU;
		}
	}

	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);

	/*
	 * If the outgoing packet contains a hop-by-hop options header,
	 * it must be examined and processed even by the source node.
	 * (RFC 2460, section 4.)
	 */
	if (ip6->ip6_nxt == IPV6_HOPOPTS) {
		u_int32_t dummy1; /* XXX unused */
		u_int32_t dummy2; /* XXX unused */
		int hoff = sizeof(struct ip6_hdr);

		if (ip6_hopopts_input(&dummy1, &dummy2, &m, &hoff)) {
			/* m was already freed at this point */
			error = EINVAL;/* better error? */
			goto done;
		}

		ip6 = mtod(m, struct ip6_hdr *);
	}

#ifdef PFIL_HOOKS
#if defined(__QNXNTO__) &&			\
    (defined(IPSEC) || defined(FAST_IPSEC))
	if (!pfil_ipsec) {
#endif
	/*
	 * Run through list of hooks for output packets.
	 */
#ifndef QNX_MFIB
	if ((error = pfil_run_hooks(&inet6_pfil_hook, &m, ifp, PFIL_OUT)) != 0)
#else
	if ((error = pfil_run_hooks(&inet6_pfil_hook, &m, ifp, PFIL_OUT, fib)) != 0)
#endif
		goto done;
	if (m == NULL)
		goto done;
#if defined(__QNXNTO__) &&			\
    (defined(IPSEC) || defined(FAST_IPSEC))
	}
#endif
	ip6 = mtod(m, struct ip6_hdr *);
#endif /* PFIL_HOOKS */
	/*
	 * Send the packet to the outgoing interface.
	 * If necessary, do IPv6 fragmentation before sending.
	 *
	 * the logic here is rather complex:
	 * 1: normal case (dontfrag == 0, alwaysfrag == 0)
	 * 1-a:	send as is if tlen <= path mtu
	 * 1-b:	fragment if tlen > path mtu
	 *
	 * 2: if user asks us not to fragment (dontfrag == 1)
	 * 2-a:	send as is if tlen <= interface mtu
	 * 2-b:	error if tlen > interface mtu
	 *
	 * 3: if we always need to attach fragment header (alwaysfrag == 1)
	 *	always fragment
	 *
	 * 4: if dontfrag == 1 && alwaysfrag == 1
	 *	error, as we cannot handle this conflicting request
	 */
	tlen = m->m_pkthdr.len;
	tso = (m->m_pkthdr.csum_flags & M_CSUM_TSOv6) != 0;
	if (opt && (opt->ip6po_flags & IP6PO_DONTFRAG))
		dontfrag = 1;
	else
		dontfrag = 0;

	if (dontfrag && alwaysfrag) {	/* case 4 */
		/* conflicting request - can't transmit */
		error = EMSGSIZE;
		goto bad;
	}
	if (dontfrag && (!tso && tlen > IN6_LINKMTU(ifp))) {	/* case 2-b */
		/*
		 * Even if the DONTFRAG option is specified, we cannot send the
		 * packet when the data length is larger than the MTU of the
		 * outgoing interface.
		 * Notify the error by sending IPV6_PATHMTU ancillary data as
		 * well as returning an error code (the latter is not described
		 * in the API spec.)
		 */
		u_int32_t mtu32;
		struct ip6ctlparam ip6cp;

		mtu32 = (u_int32_t)mtu;
		bzero(&ip6cp, sizeof(ip6cp));
		ip6cp.ip6c_cmdarg = (void *)&mtu32;
		pfctlinput2(PRC_MSGSIZE, (struct sockaddr *)&ro_pmtu->ro_dst,
		    (void *)&ip6cp);

		error = EMSGSIZE;
		goto bad;
	}

	/*
	 * transmit packet without fragmentation
	 */
	if (dontfrag || (!alwaysfrag && (tlen <= mtu || tso))) {
		/* case 1-a and 2-a */
		struct in6_ifaddr *ia6;
		int sw_csum;

		ip6 = mtod(m, struct ip6_hdr *);
		ia6 = in6_ifawithifp(ifp, &ip6->ip6_src);
		if (ia6) {
			/* Record statistics for this interface address. */
			ia6->ia_ifa.ifa_data.ifad_outbytes += m->m_pkthdr.len;
		}
#ifdef IPSEC
if (QNXNTO_IPSEC_ENABLED) {
		/* clean ipsec history once it goes out of the node */
		ipsec_delaux(m);
}
#endif

#ifndef __QNXNTO__
		sw_csum = m->m_pkthdr.csum_flags & ~ifp->if_csum_flags_tx;
#else
		sw_csum = m->m_pkthdr.csum_flags;
		if ((ifp->if_type == IFT_ETHER) &&
		    (ifp->if_hdrlen == sizeof(struct ether_vlan_header))) {
			ifv = ifp->if_softc;
		}
		if (ifp->if_bridge_tx == NULL &&
		    !(ifv && ifv->ifv_p && ifv->ifv_p->if_bridge_tx != NULL)) {
			sw_csum &= ~ifp->if_csum_flags_tx;
		}

#endif
		if ((sw_csum & (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0) {
			if (IN6_NEED_CHECKSUM(ifp,
			    sw_csum & (M_CSUM_UDPv6|M_CSUM_TCPv6))) {
				in6_delayed_cksum(m);
			}
			m->m_pkthdr.csum_flags &= ~(M_CSUM_UDPv6|M_CSUM_TCPv6);
		}

#ifndef __QNXNTO__
		if (__predict_true(!tso ||
		    (ifp->if_capenable & IFCAP_TSOv6) != 0))
#else
		if (__predict_true(!tso ||
		    (ifp->if_capenable_tx & IFCAP_TSOv6) != 0))
#endif
		    {
			error = nd6_output(ifp, origifp, m, dst, rt
#ifdef QNX_MFIB
					, fib
#endif
			);
		} else {
			error = ip6_tso_output(ifp, origifp, m, dst, rt
#ifdef QNX_MFIB
					, fib
#endif
			);
		}
		goto done;
	}

	if (tso) {
		error = EINVAL; /* XXX */
		goto bad;
	}

	/*
	 * try to fragment the packet.  case 1-b and 3
	 */
	if (mtu < IPV6_MMTU) {
		/* path MTU cannot be less than IPV6_MMTU */
		error = EMSGSIZE;
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		goto bad;
	} else if (ip6->ip6_plen == 0) {
		/* jumbo payload cannot be fragmented */
		error = EMSGSIZE;
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		goto bad;
	} else {
		struct mbuf **mnext, *m_frgpart;
		struct ip6_frag *ip6f;
		u_int32_t id = htonl(ip6_randomid());
		u_char nextproto;
#if 0				/* see below */
		struct ip6ctlparam ip6cp;
		u_int32_t mtu32;
#endif

		/*
		 * Too large for the destination or interface;
		 * fragment if possible.
		 * Must be able to put at least 8 bytes per fragment.
		 */
		hlen = unfragpartlen;
		if (mtu > IPV6_MAXPACKET)
			mtu = IPV6_MAXPACKET;

#if 0
		/*
		 * It is believed this code is a leftover from the
		 * development of the IPV6_RECVPATHMTU sockopt and
		 * associated work to implement RFC3542.
		 * It's not entirely clear what the intent of the API
		 * is at this point, so disable this code for now.
		 * The IPV6_RECVPATHMTU sockopt and/or IPV6_DONTFRAG
		 * will send notifications if the application requests.
		 */

		/* Notify a proper path MTU to applications. */
		mtu32 = (u_int32_t)mtu;
		bzero(&ip6cp, sizeof(ip6cp));
		ip6cp.ip6c_cmdarg = (void *)&mtu32;
		pfctlinput2(PRC_MSGSIZE, (struct sockaddr *)&ro_pmtu->ro_dst,
		    (void *)&ip6cp);
#endif

		len = (mtu - hlen - sizeof(struct ip6_frag)) & ~7;
		if (len < 8) {
			error = EMSGSIZE;
			in6_ifstat_inc(ifp, ifs6_out_fragfail);
			goto bad;
		}

		mnext = &m->m_nextpkt;

		/*
		 * Change the next header field of the last header in the
		 * unfragmentable part.
		 */
		if (exthdrs.ip6e_rthdr) {
			nextproto = *mtod(exthdrs.ip6e_rthdr, u_char *);
			*mtod(exthdrs.ip6e_rthdr, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_dest1) {
			nextproto = *mtod(exthdrs.ip6e_dest1, u_char *);
			*mtod(exthdrs.ip6e_dest1, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_hbh) {
			nextproto = *mtod(exthdrs.ip6e_hbh, u_char *);
			*mtod(exthdrs.ip6e_hbh, u_char *) = IPPROTO_FRAGMENT;
		} else {
			nextproto = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_FRAGMENT;
		}

		if ((m->m_pkthdr.csum_flags & (M_CSUM_UDPv6|M_CSUM_TCPv6))
		    != 0) {
			if (IN6_NEED_CHECKSUM(ifp,
			    m->m_pkthdr.csum_flags &
			    (M_CSUM_UDPv6|M_CSUM_TCPv6))) {
				in6_delayed_cksum(m);
			}
			m->m_pkthdr.csum_flags &= ~(M_CSUM_UDPv6|M_CSUM_TCPv6);
		}

		/*
		 * Loop through length of segment after first fragment,
		 * make new header and copy data of each part and link onto
		 * chain.
		 */
		m0 = m;
		for (off = hlen; off < tlen; off += len) {
			struct mbuf *mlast;

			MGETHDR(m, M_DONTWAIT, MT_HEADER);
			if (!m) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			m->m_pkthdr.rcvif = NULL;
			m->m_flags = m0->m_flags & M_COPYFLAGS;
			*mnext = m;
			mnext = &m->m_nextpkt;
			m->m_data += max_linkhdr;
			mhip6 = mtod(m, struct ip6_hdr *);
			*mhip6 = *ip6;
			m->m_len = sizeof(*mhip6);
			error = ip6_insertfraghdr(m0, m, hlen, &ip6f);
			if (error) {
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			ip6f->ip6f_offlg = htons((u_int16_t)((off - hlen) & ~7));
			if (off + len >= tlen)
				len = tlen - off;
			else
				ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
			mhip6->ip6_plen = htons((u_int16_t)(len + hlen +
			    sizeof(*ip6f) - sizeof(struct ip6_hdr)));
			if ((m_frgpart = m_copy(m0, off, len)) == 0) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			for (mlast = m; mlast->m_next; mlast = mlast->m_next)
				;
			mlast->m_next = m_frgpart;
			m->m_pkthdr.len = len + hlen + sizeof(*ip6f);
			m->m_pkthdr.rcvif = (struct ifnet *)0;
			ip6f->ip6f_reserved = 0;
			ip6f->ip6f_ident = id;
			ip6f->ip6f_nxt = nextproto;
			ip6stat.ip6s_ofragments++;
			in6_ifstat_inc(ifp, ifs6_out_fragcreat);
		}

		in6_ifstat_inc(ifp, ifs6_out_fragok);
	}

	/*
	 * Remove leading garbages.
	 */
sendorfree:
	m = m0->m_nextpkt;
	m0->m_nextpkt = 0;
	m_freem(m0);
	for (m0 = m; m; m = m0) {
		m0 = m->m_nextpkt;
		m->m_nextpkt = 0;
		if (error == 0) {
			struct in6_ifaddr *ia6;
			ip6 = mtod(m, struct ip6_hdr *);
			ia6 = in6_ifawithifp(ifp, &ip6->ip6_src);
			if (ia6) {
				/*
				 * Record statistics for this interface
				 * address.
				 */
				ia6->ia_ifa.ifa_data.ifad_outbytes +=
				    m->m_pkthdr.len;
			}
#ifdef IPSEC
if (QNXNTO_IPSEC_ENABLED) {
			/* clean ipsec history once it goes out of the node */
			ipsec_delaux(m);
}
#endif
			error = nd6_output(ifp, origifp, m, dst, rt
#ifdef QNX_MFIB
					, fib
#endif
			);
		} else
			m_freem(m);
	}

	if (error == 0)
		ip6stat.ip6s_fragmented++;

done:
	if (ro == &ip6route && ro->ro_rt) { /* brace necessary for RTFREE */
		RTFREE(ro->ro_rt);
	} else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
		RTFREE(ro_pmtu->ro_rt);
	}

#ifdef IPSEC
if (QNXNTO_IPSEC_ENABLED) {
	if (sp != NULL)
		key_freesp(sp);
}
#endif /* IPSEC */
#ifdef FAST_IPSEC
if (QNXNTO_IPSEC_ENABLED) {
	if (sp != NULL)
		KEY_FREESP(&sp);
}
#endif /* FAST_IPSEC */


	return (error);

freehdrs:
	m_freem(exthdrs.ip6e_hbh);	/* m_freem will check if mbuf is 0 */
	m_freem(exthdrs.ip6e_dest1);
	m_freem(exthdrs.ip6e_rthdr);
	m_freem(exthdrs.ip6e_dest2);
	/* FALLTHROUGH */
bad:
	m_freem(m);
	goto done;
}

static int
ip6_copyexthdr(mp, hdr, hlen)
	struct mbuf **mp;
	caddr_t hdr;
	int hlen;
{
	struct mbuf *m;

	if (hlen > MCLBYTES)
		return (ENOBUFS); /* XXX */

	MGET(m, M_DONTWAIT, MT_DATA);
	if (!m)
		return (ENOBUFS);

	if (hlen > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
	}
	m->m_len = hlen;
	if (hdr)
		bcopy(hdr, mtod(m, caddr_t), hlen);

	*mp = m;
	return (0);
}

/*
 * Process a delayed payload checksum calculation.
 */
void
in6_delayed_cksum(struct mbuf *m)
{
	uint16_t csum, offset;

	KASSERT((m->m_pkthdr.csum_flags & (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0);
	KASSERT((~m->m_pkthdr.csum_flags & (M_CSUM_UDPv6|M_CSUM_TCPv6)) != 0);
	KASSERT((m->m_pkthdr.csum_flags
	    & (M_CSUM_UDPv4|M_CSUM_TCPv4|M_CSUM_TSOv4)) == 0);

	offset = M_CSUM_DATA_IPv6_HL(m->m_pkthdr.csum_data);
	csum = in6_cksum(m, 0, offset, m->m_pkthdr.len - offset);
	if (csum == 0 && (m->m_pkthdr.csum_flags & M_CSUM_UDPv6) != 0) {
		csum = 0xffff;
	}

	offset += M_CSUM_DATA_IPv6_OFFSET(m->m_pkthdr.csum_data);
	if ((offset + sizeof(csum)) > m->m_len) {
		m_copyback(m, offset, sizeof(csum), &csum);
	} else {
		*(uint16_t *)(mtod(m, caddr_t) + offset) = csum;
	}
}

/*
 * Insert jumbo payload option.
 */
static int
ip6_insert_jumboopt(exthdrs, plen)
	struct ip6_exthdrs *exthdrs;
	u_int32_t plen;
{
	struct mbuf *mopt;
	u_int8_t *optbuf;
	u_int32_t v;

#define JUMBOOPTLEN	8	/* length of jumbo payload option and padding */

	/*
	 * If there is no hop-by-hop options header, allocate new one.
	 * If there is one but it doesn't have enough space to store the
	 * jumbo payload option, allocate a cluster to store the whole options.
	 * Otherwise, use it to store the options.
	 */
	if (exthdrs->ip6e_hbh == 0) {
		MGET(mopt, M_DONTWAIT, MT_DATA);
		if (mopt == 0)
			return (ENOBUFS);
		mopt->m_len = JUMBOOPTLEN;
		optbuf = mtod(mopt, u_int8_t *);
		optbuf[1] = 0;	/* = ((JUMBOOPTLEN) >> 3) - 1 */
		exthdrs->ip6e_hbh = mopt;
	} else {
		struct ip6_hbh *hbh;

		mopt = exthdrs->ip6e_hbh;
		if (M_TRAILINGSPACE(mopt) < JUMBOOPTLEN) {
			/*
			 * XXX assumption:
			 * - exthdrs->ip6e_hbh is not referenced from places
			 *   other than exthdrs.
			 * - exthdrs->ip6e_hbh is not an mbuf chain.
			 */
			int oldoptlen = mopt->m_len;
			struct mbuf *n;

			/*
			 * XXX: give up if the whole (new) hbh header does
			 * not fit even in an mbuf cluster.
			 */
			if (oldoptlen + JUMBOOPTLEN > MCLBYTES)
				return (ENOBUFS);

			/*
			 * As a consequence, we must always prepare a cluster
			 * at this point.
			 */
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_freem(n);
					n = NULL;
				}
			}
			if (!n)
				return (ENOBUFS);
			n->m_len = oldoptlen + JUMBOOPTLEN;
			bcopy(mtod(mopt, caddr_t), mtod(n, caddr_t),
			    oldoptlen);
			optbuf = mtod(n, u_int8_t *) + oldoptlen;
			m_freem(mopt);
			mopt = exthdrs->ip6e_hbh = n;
		} else {
			optbuf = mtod(mopt, u_int8_t *) + mopt->m_len;
			mopt->m_len += JUMBOOPTLEN;
		}
		optbuf[0] = IP6OPT_PADN;
		optbuf[1] = 0;

		/*
		 * Adjust the header length according to the pad and
		 * the jumbo payload option.
		 */
		hbh = mtod(mopt, struct ip6_hbh *);
		hbh->ip6h_len += (JUMBOOPTLEN >> 3);
	}

	/* fill in the option. */
	optbuf[2] = IP6OPT_JUMBO;
	optbuf[3] = 4;
	v = (u_int32_t)htonl(plen + JUMBOOPTLEN);
	bcopy(&v, &optbuf[4], sizeof(u_int32_t));

	/* finally, adjust the packet header length */
	exthdrs->ip6e_ip6->m_pkthdr.len += JUMBOOPTLEN;

	return (0);
#undef JUMBOOPTLEN
}

/*
 * Insert fragment header and copy unfragmentable header portions.
 */
static int
ip6_insertfraghdr(m0, m, hlen, frghdrp)
	struct mbuf *m0, *m;
	int hlen;
	struct ip6_frag **frghdrp;
{
	struct mbuf *n, *mlast;

	if (hlen > sizeof(struct ip6_hdr)) {
		n = m_copym(m0, sizeof(struct ip6_hdr),
		    hlen - sizeof(struct ip6_hdr), M_DONTWAIT);
		if (n == 0)
			return (ENOBUFS);
		m->m_next = n;
	} else
		n = m;

	/* Search for the last mbuf of unfragmentable part. */
	for (mlast = n; mlast->m_next; mlast = mlast->m_next)
		;

	if ((mlast->m_flags & M_EXT) == 0 &&
	    M_TRAILINGSPACE(mlast) >= sizeof(struct ip6_frag)) {
		/* use the trailing space of the last mbuf for the fragment hdr */
		*frghdrp = (struct ip6_frag *)(mtod(mlast, caddr_t) +
		    mlast->m_len);
		mlast->m_len += sizeof(struct ip6_frag);
		m->m_pkthdr.len += sizeof(struct ip6_frag);
	} else {
		/* allocate a new mbuf for the fragment header */
		struct mbuf *mfrg;

		MGET(mfrg, M_DONTWAIT, MT_DATA);
		if (mfrg == 0)
			return (ENOBUFS);
		mfrg->m_len = sizeof(struct ip6_frag);
		*frghdrp = mtod(mfrg, struct ip6_frag *);
		mlast->m_next = mfrg;
	}

	return (0);
}

static int
#ifndef __QNXNTO__
ip6_getpmtu(ro_pmtu, ro, ifp, dst, mtup, alwaysfragp)
#else
#ifndef QNX_MFIB
ip6_getpmtu(ro_pmtu, ro, ifp, dst, mtup, alwaysfragp, if_mask)
#else
ip6_getpmtu(ro_pmtu, ro, ifp, dst, mtup, alwaysfragp, if_mask, fib)
	int fib;
#endif
	struct ifnet *if_mask;
#endif
	struct route_in6 *ro_pmtu, *ro;
	struct ifnet *ifp;
	struct in6_addr *dst;
	u_long *mtup;
	int *alwaysfragp;
{
	u_int32_t mtu = 0;
	int alwaysfrag = 0;
	int error = 0;

	if (ro_pmtu != ro) {
		/* The first hop and the final destination may differ. */
		struct sockaddr_in6 *sa6_dst =
		    (struct sockaddr_in6 *)&ro_pmtu->ro_dst;
		if (ro_pmtu->ro_rt &&
		    ((ro_pmtu->ro_rt->rt_flags & RTF_UP) == 0 ||
		      !IN6_ARE_ADDR_EQUAL(&sa6_dst->sin6_addr, dst))) {
			RTFREE(ro_pmtu->ro_rt);
			ro_pmtu->ro_rt = (struct rtentry *)NULL;
		}
		if (ro_pmtu->ro_rt == NULL) {
			bzero(sa6_dst, sizeof(*sa6_dst)); /* for safety */
			sa6_dst->sin6_family = AF_INET6;
			sa6_dst->sin6_len = sizeof(struct sockaddr_in6);
			sa6_dst->sin6_addr = *dst;

#ifndef __QNXNTO__
			rtalloc((struct route *)ro_pmtu);
#else
#ifndef QNX_MFIB
			(rtalloc)((struct route *)ro_pmtu, if_mask);
#else
			(rtalloc)((struct route *)ro_pmtu, if_mask, fib);
#endif
#endif
		}
	}
	if (ro_pmtu->ro_rt) {
		u_int32_t ifmtu;

		if (ifp == NULL)
			ifp = ro_pmtu->ro_rt->rt_ifp;
		ifmtu = IN6_LINKMTU(ifp);
		mtu = ro_pmtu->ro_rt->rt_rmx.rmx_mtu;
		if (mtu == 0)
			mtu = ifmtu;
		else if (mtu < IPV6_MMTU) {
			/*
			 * RFC2460 section 5, last paragraph:
			 * if we record ICMPv6 too big message with
			 * mtu < IPV6_MMTU, transmit packets sized IPV6_MMTU
			 * or smaller, with fragment header attached.
			 * (fragment header is needed regardless from the
			 * packet size, for translators to identify packets)
			 */
			alwaysfrag = 1;
			mtu = IPV6_MMTU;
		} else if (mtu > ifmtu) {
			/*
			 * The MTU on the route is larger than the MTU on
			 * the interface!  This shouldn't happen, unless the
			 * MTU of the interface has been changed after the
			 * interface was brought up.  Change the MTU in the
			 * route to match the interface MTU (as long as the
			 * field isn't locked).
			 */
			mtu = ifmtu;
			if (!(ro_pmtu->ro_rt->rt_rmx.rmx_locks & RTV_MTU))
				ro_pmtu->ro_rt->rt_rmx.rmx_mtu = mtu;
		}
	} else if (ifp) {
		mtu = IN6_LINKMTU(ifp);
	} else
		error = EHOSTUNREACH; /* XXX */

	*mtup = mtu;
	if (alwaysfragp)
		*alwaysfragp = alwaysfrag;
	return (error);
}

/*
 * IP6 socket option processing.
 */
int
ip6_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **mp)
{
	int optdatalen, uproto;
	void *optdata;
	struct in6pcb *in6p = sotoin6pcb(so);
	struct mbuf *m = *mp;
	int error, optval;
	int optlen;

	optlen = m ? m->m_len : 0;
	error = optval = 0;
	uproto = (int)so->so_proto->pr_protocol;

#ifdef __QNXNTO__
	if (level == SOL_SOCKET && optname == SO_BINDTODEVICE) {
		/*
		 * Socket level option but the route is often
		 * cached in in6p_route so we handle it here.
		 */
		struct ifreq *ifreq;
		struct ifnet *ifp;
		
		if (op == PRCO_GETOPT) {
			char *ifname;
			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			MCLAIM(m, so->so_mowner);
			ifname = mtod(m, char *);
			if (in6p->in6p_bounddevice != NULL) {
				m->m_len = strlcpy(ifname, in6p->in6p_bounddevice->if_xname, IFNAMSIZ) + 1;
			}
			else {
				m->m_len = 0;
			}
			return 0;
		}

		if (m == NULL) {
			return EINVAL;
		}
		if (op != PRCO_SETOPT) {
			m_free(m);
			return EINVAL;
		}

		/* Note: a NULL terminated string is also a valid for Linux compat */
		if (
#ifdef COMPAT_OIFREQ
			m->m_len != sizeof(struct oifreq)
			&& m->m_len != sizeof(*ifreq)
#else
			m->m_len != sizeof(*ifreq)
#endif
			&& m->m_len > IFNAMSIZ) {
			m_free(m);
			return EINVAL;
		}

		ifreq = mtod(m, struct ifreq *);
		if (memchr(ifreq->ifr_name, '\0', sizeof ifreq->ifr_name) == NULL) {
			m_free(m);
			return EINVAL;
		}

		if (m->m_len == 0 || ifreq->ifr_name[0] == '\0') {
			so->so_options &= ~optname;
			ifp = in6p->in6p_bounddevice;
			in6p->in6p_bounddevice = NULL;
			if_keepalive_stop_inp(&in6p->in6p_head, ifp, 1);
		}
#ifndef QNX_MFIB
		else if ((ifp = ifunit(ifreq->ifr_name)) == NULL) {
#else
		else if ((ifp = ifunit(ifreq->ifr_name, ANY_FIB)) == NULL) {
#endif
			error = ENXIO;
		}
		else {
			so->so_options |= optname;
			in6p->in6p_bounddevice = ifp;
		}

		m_free(m);
		return error;
	}
#endif
	
	if (level == IPPROTO_IPV6) {
		switch (op) {
		case PRCO_SETOPT:
			switch (optname) {
#ifdef RFC2292
			case IPV6_2292PKTOPTIONS:
				/* m is freed in ip6_pcbopts */
				error = ip6_pcbopts(&in6p->in6p_outputopts,
				    m, so);
				break;
#endif

			/*
			 * Use of some Hop-by-Hop options or some
			 * Destination options, might require special
			 * privilege.  That is, normal applications
			 * (without special privilege) might be forbidden
			 * from setting certain options in outgoing packets,
			 * and might never see certain options in received
			 * packets. [RFC 2292 Section 6]
			 * KAME specific note:
			 *  KAME prevents non-privileged users from sending or
			 *  receiving ANY hbh/dst options in order to avoid
			 *  overhead of parsing options in the kernel.
			 */
			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
			case IPV6_RECVRTHDRDSTOPTS:
			error = kauth_authorize_generic(kauth_cred_get(),
			    KAUTH_GENERIC_ISSUSER, NULL);
			if (error)
				break;
				/* FALLTHROUGH */
			case IPV6_UNICAST_HOPS:
			case IPV6_HOPLIMIT:
			case IPV6_FAITH:

			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:
			case IPV6_RECVTCLASS:
			case IPV6_V6ONLY:
				if (optlen != sizeof(int)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);
				switch (optname) {

				case IPV6_UNICAST_HOPS:
					if (optval < -1 || optval >= 256)
						error = EINVAL;
					else {
						/* -1 = kernel default */
						in6p->in6p_hops = optval;
					}
					break;
#define OPTSET(bit) \
do { \
if (optval) \
	in6p->in6p_flags |= (bit); \
else \
	in6p->in6p_flags &= ~(bit); \
} while (/*CONSTCOND*/ 0)

#ifdef RFC2292
#define OPTSET2292(bit) 			\
do { 						\
in6p->in6p_flags |= IN6P_RFC2292; 	\
if (optval) 				\
	in6p->in6p_flags |= (bit); 	\
else 					\
	in6p->in6p_flags &= ~(bit); 	\
} while (/*CONSTCOND*/ 0)
#endif

#define OPTBIT(bit) (in6p->in6p_flags & (bit) ? 1 : 0)

				case IPV6_RECVPKTINFO:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_PKTINFO);
					break;

				case IPV6_HOPLIMIT:
				{
					struct ip6_pktopts **optp;

#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					optp = &in6p->in6p_outputopts;
					error = ip6_pcbopt(IPV6_HOPLIMIT,
							   (u_char *)&optval,
							   sizeof(optval),
							   optp,
							   kauth_cred_get(), uproto);
					break;
				}

				case IPV6_RECVHOPLIMIT:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVHOPOPTS:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_DSTOPTS);
					break;

				case IPV6_RECVRTHDRDSTOPTS:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_RTHDRDSTOPTS);
					break;

				case IPV6_RECVRTHDR:
#ifdef RFC2292
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_RTHDR);
					break;

				case IPV6_FAITH:
					OPTSET(IN6P_FAITH);
					break;

				case IPV6_RECVPATHMTU:
					/*
					 * We ignore this option for TCP
					 * sockets.
					 * (RFC3542 leaves this case
					 * unspecified.)
					 */
					if (uproto != IPPROTO_TCP)
						OPTSET(IN6P_MTU);
					break;

				case IPV6_V6ONLY:
					/*
					 * make setsockopt(IPV6_V6ONLY)
					 * available only prior to bind(2).
					 * see ipng mailing list, Jun 22 2001.
					 */
					if (in6p->in6p_lport ||
					    !IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr)) {
						error = EINVAL;
						break;
					}
#ifdef INET6_BINDV6ONLY
					if (!optval)
						error = EINVAL;
#else
					OPTSET(IN6P_IPV6_V6ONLY);
#endif
					break;
				case IPV6_RECVTCLASS:
#ifdef RFC2292
					/* cannot mix with RFC2292 XXX */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
#endif
					OPTSET(IN6P_TCLASS);
					break;

				}
				break;

			case IPV6_OTCLASS:
			{
				struct ip6_pktopts **optp;
				u_int8_t tclass;

				if (optlen != sizeof(tclass)) {
					error = EINVAL;
					break;
				}
				tclass = *mtod(m, u_int8_t *);
				optp = &in6p->in6p_outputopts;
				error = ip6_pcbopt(optname,
						   (u_char *)&tclass,
						   sizeof(tclass),
						   optp,
						   kauth_cred_get(), uproto);
				break;
			}

			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
#ifdef __QNXNTO__
			case IPV6_PREFER_TEMPADDR:
#endif
				if (optlen != sizeof(optval)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);
				{
					struct ip6_pktopts **optp;
					optp = &in6p->in6p_outputopts;
					error = ip6_pcbopt(optname,
							   (u_char *)&optval,
							   sizeof(optval),
							   optp,
							   kauth_cred_get(), uproto);
					break;
				}

#ifdef RFC2292
			case IPV6_2292PKTINFO:
			case IPV6_2292HOPLIMIT:
			case IPV6_2292HOPOPTS:
			case IPV6_2292DSTOPTS:
			case IPV6_2292RTHDR:
				/* RFC 2292 */
				if (optlen != sizeof(int)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);
				switch (optname) {
				case IPV6_2292PKTINFO:
					OPTSET2292(IN6P_PKTINFO);
					break;
				case IPV6_2292HOPLIMIT:
					OPTSET2292(IN6P_HOPLIMIT);
					break;
				case IPV6_2292HOPOPTS:
					/*
					 * Check super-user privilege.
					 * See comments for IPV6_RECVHOPOPTS.
					 */
					if (kauth_authorize_generic(kauth_cred_get(),
					    KAUTH_GENERIC_ISSUSER, NULL))
						return (EPERM);
					OPTSET2292(IN6P_HOPOPTS);
					break;
				case IPV6_2292DSTOPTS:
					if (kauth_authorize_generic(kauth_cred_get(),
					    KAUTH_GENERIC_ISSUSER, NULL))
					OPTSET2292(IN6P_DSTOPTS|IN6P_RTHDRDSTOPTS); /* XXX */
					break;
				case IPV6_2292RTHDR:
					OPTSET2292(IN6P_RTHDR);
					break;
				}
				break;
#endif
			case IPV6_PKTINFO:
			case IPV6_HOPOPTS:
			case IPV6_RTHDR:
			case IPV6_DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_NEXTHOP:
			{
				/* new advanced API (RFC3542) */
				u_char *optbuf;
				int optbuflen;
				struct ip6_pktopts **optp;

#ifdef RFC2292
				/* cannot mix with RFC2292 */
				if (OPTBIT(IN6P_RFC2292)) {
					error = EINVAL;
					break;
				}
#endif

				if (m && m->m_next) {
					error = EINVAL;	/* XXX */
					break;
				}
				if (m) {
					optbuf = mtod(m, u_char *);
					optbuflen = m->m_len;
				} else {
					optbuf = NULL;
					optbuflen = 0;
				}
				optp = &in6p->in6p_outputopts;
				error = ip6_pcbopt(optname,
						   optbuf, optbuflen,
						   optp, kauth_cred_get(), uproto);
				break;
			}
#undef OPTSET

			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_JOIN_GROUP:
			case IPV6_LEAVE_GROUP:
                                error = ip6_setmoptions(optname,
#ifndef __QNXNTO__
				    &in6p->in6p_moptions, m);
#else
#ifndef QNX_MFIB
				    &in6p->in6p_moptions, m, in6p->in6p_bounddevice);
#else
				    &in6p->in6p_moptions, m, in6p->in6p_bounddevice, so->so_fibnum);
#endif
#endif
				break;

			case IPV6_PORTRANGE:
				optval = *mtod(m, int *);

				switch (optval) {
				case IPV6_PORTRANGE_DEFAULT:
					in6p->in6p_flags &= ~(IN6P_LOWPORT);
					in6p->in6p_flags &= ~(IN6P_HIGHPORT);
					break;

				case IPV6_PORTRANGE_HIGH:
					in6p->in6p_flags &= ~(IN6P_LOWPORT);
					in6p->in6p_flags |= IN6P_HIGHPORT;
					break;

				case IPV6_PORTRANGE_LOW:
					in6p->in6p_flags &= ~(IN6P_HIGHPORT);
					in6p->in6p_flags |= IN6P_LOWPORT;
					break;

				default:
					error = EINVAL;
					break;
				}
				break;


#if defined(IPSEC) || defined(FAST_IPSEC)
#ifdef __QNXNTO__
			case IPV6_IPSEC_POLICY_COMPAT:
#endif
			case IPV6_IPSEC_POLICY:
			{
#ifdef __QNXNTO__
				error = ENOPROTOOPT; /* Set default error in case ipsec not enabled */
#endif
if (QNXNTO_IPSEC_ENABLED) {
				caddr_t req = NULL;
				size_t len = 0;
				if (m) {
					req = mtod(m, caddr_t);
					len = m->m_len;
				}
				error = ipsec6_set_policy(in6p, optname, req,
							  len, kauth_cred_get());
}
			}
				break;
#endif /* IPSEC */

			case IPV6_PORTALGO:
				optval = *mtod(m, int *);
				if (error)
					break;

				error = portalgo_algo_index_select(
				    (struct inpcb_hdr *)in6p, optval);
			default:
				error = ENOPROTOOPT;
				break;
			}
			if (m)
				(void)m_free(m);
			break;

		case PRCO_GETOPT:
			switch (optname) {
#ifdef RFC2292
			case IPV6_2292PKTOPTIONS:
				/*
				 * RFC3542 (effectively) deprecated the
				 * semantics of the 2292-style pktoptions.
				 * Since it was not reliable in nature (i.e.,
				 * applications had to expect the lack of some
				 * information after all), it would make sense
				 * to simplify this part by always returning
				 * empty data.
				 */
				*mp = m_get(M_WAIT, MT_SOOPTS);
				(*mp)->m_len = 0;
				break;
#endif

			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
			case IPV6_RECVRTHDRDSTOPTS:
			case IPV6_UNICAST_HOPS:
			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:

			case IPV6_FAITH:
			case IPV6_V6ONLY:
			case IPV6_PORTRANGE:
			case IPV6_RECVTCLASS:
				switch (optname) {

				case IPV6_RECVHOPOPTS:
					optval = OPTBIT(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
					optval = OPTBIT(IN6P_DSTOPTS);
					break;

				case IPV6_RECVRTHDRDSTOPTS:
					optval = OPTBIT(IN6P_RTHDRDSTOPTS);
					break;

				case IPV6_UNICAST_HOPS:
					optval = in6p->in6p_hops;
					break;

				case IPV6_RECVPKTINFO:
					optval = OPTBIT(IN6P_PKTINFO);
					break;

				case IPV6_RECVHOPLIMIT:
					optval = OPTBIT(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVRTHDR:
					optval = OPTBIT(IN6P_RTHDR);
					break;

				case IPV6_RECVPATHMTU:
					optval = OPTBIT(IN6P_MTU);
					break;

				case IPV6_FAITH:
					optval = OPTBIT(IN6P_FAITH);
					break;

				case IPV6_V6ONLY:
					optval = OPTBIT(IN6P_IPV6_V6ONLY);
					break;

				case IPV6_PORTRANGE:
				    {
					int flags;
					flags = in6p->in6p_flags;
					if (flags & IN6P_HIGHPORT)
						optval = IPV6_PORTRANGE_HIGH;
					else if (flags & IN6P_LOWPORT)
						optval = IPV6_PORTRANGE_LOW;
					else
						optval = 0;
					break;
				    }
				case IPV6_RECVTCLASS:
					optval = OPTBIT(IN6P_TCLASS);
					break;

				}
				if (error)
					break;
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(int);
				*mtod(m, int *) = optval;
				break;

			case IPV6_PATHMTU:
			    {
				u_long pmtu = 0;
				struct ip6_mtuinfo mtuinfo;
				struct route_in6 *ro = (struct route_in6 *)&in6p
->in6p_route;

				if (!(so->so_state & SS_ISCONNECTED))
					return (ENOTCONN);
				/*
				 * XXX: we dot not consider the case of source
				 * routing, or optional information to specify
				 * the outgoing interface.
				 */
				error = ip6_getpmtu(ro, NULL, NULL,
#ifndef __QNXNTO__
				    &in6p->in6p_faddr, &pmtu, NULL);
#else
#ifndef QNX_MFIB
				    &in6p->in6p_faddr, &pmtu, NULL, in6p->in6p_bounddevice);
#else
				    &in6p->in6p_faddr, &pmtu, NULL, in6p->in6p_bounddevice, so->so_fibnum);
#endif
#endif
				if (error)
					break;
				if (pmtu > IPV6_MAXPACKET)
					pmtu = IPV6_MAXPACKET;

				memset(&mtuinfo, 0, sizeof(mtuinfo));
				mtuinfo.ip6m_mtu = (u_int32_t)pmtu;
				optdata = (void *)&mtuinfo;
				optdatalen = sizeof(mtuinfo);
				if (optdatalen > MCLBYTES)
					return (EMSGSIZE); /* XXX */
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				if (optdatalen > MLEN)
					MCLGET(m, M_WAIT);
				m->m_len = optdatalen;
				memcpy(mtod(m, void *), optdata, optdatalen);
				break;
			    }

#ifdef RFC2292
			case IPV6_2292PKTINFO:
			case IPV6_2292HOPLIMIT:
			case IPV6_2292HOPOPTS:
			case IPV6_2292RTHDR:
			case IPV6_2292DSTOPTS:
				switch (optname) {
				case IPV6_2292PKTINFO:
					optval = OPTBIT(IN6P_PKTINFO);
					break;
				case IPV6_2292HOPLIMIT:
					optval = OPTBIT(IN6P_HOPLIMIT);
					break;
				case IPV6_2292HOPOPTS:
					optval = OPTBIT(IN6P_HOPOPTS);
					break;
				case IPV6_2292RTHDR:
					optval = OPTBIT(IN6P_RTHDR);
					break;
				case IPV6_2292DSTOPTS:
					optval = OPTBIT(IN6P_DSTOPTS|IN6P_RTHDRDSTOPTS);
					break;
				}
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(int);
				*mtod(m, int *) = optval;
				break;
#endif
			case IPV6_PKTINFO:
			case IPV6_HOPOPTS:
			case IPV6_RTHDR:
			case IPV6_DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_NEXTHOP:
			case IPV6_OTCLASS:
			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
#ifdef __QNXNTO__
			case IPV6_PREFER_TEMPADDR:
#endif
				error = ip6_getpcbopt(in6p->in6p_outputopts,
				    optname, mp);
				break;

			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_JOIN_GROUP:
			case IPV6_LEAVE_GROUP:
				error = ip6_getmoptions(optname,
				    in6p->in6p_moptions, mp);
				break;

#if defined(IPSEC) || defined(FAST_IPSEC)
#ifdef __QNXNTO__
			case IPV6_IPSEC_POLICY_COMPAT:
				/*
				 * The old version didn't have the
				 * GETSOCKOPT_EXTRA flag or'd in which
				 * is required below.
				 */
				error = ENOPROTOOPT;
				break;
#endif
			case IPV6_PORTALGO:
				optval = ((struct inpcb_hdr *)in6p)->inph_portalgo;
				*mtod(m, int *) = optval;
				break;
			case IPV6_IPSEC_POLICY:
			    {
#ifdef __QNXNTO__
				error = ENOPROTOOPT; /* Set default error in case ipsec not enabled */
#endif
if (QNXNTO_IPSEC_ENABLED) {
				caddr_t req = NULL;
				size_t len = 0;
				if (m) {
					req = mtod(m, caddr_t);
					len = m->m_len;
				}
				error = ipsec6_get_policy(in6p, req, len, mp);
}
				break;
			    }
#endif /* IPSEC */




			default:
				error = ENOPROTOOPT;
				break;
			}
			break;
		}
	} else {
		error = EINVAL;
		if (op == PRCO_SETOPT && *mp)
			(void)m_free(*mp);
	}
	return (error);
}

int
ip6_raw_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
	int error = 0, optval, optlen;
	const int icmp6off = offsetof(struct icmp6_hdr, icmp6_cksum);
	struct in6pcb *in6p = sotoin6pcb(so);
	struct mbuf *m = *mp;

	optlen = m ? m->m_len : 0;

	if (level != IPPROTO_IPV6) {
		if (op == PRCO_SETOPT && *mp)
			(void)m_free(*mp);
		return (EINVAL);
	}

	switch (optname) {
	case IPV6_CHECKSUM:
		/*
		 * For ICMPv6 sockets, no modification allowed for checksum
		 * offset, permit "no change" values to help existing apps.
		 *
		 * XXX RFC3542 says: "An attempt to set IPV6_CHECKSUM
		 * for an ICMPv6 socket will fail."  The current
		 * behavior does not meet RFC3542.
		 */
		switch (op) {
		case PRCO_SETOPT:
			if (optlen != sizeof(int)) {
				error = EINVAL;
				break;
			}
			optval = *mtod(m, int *);
			if ((optval % 2) != 0) {
				/* the API assumes even offset values */
				error = EINVAL;
			} else if (so->so_proto->pr_protocol ==
			    IPPROTO_ICMPV6) {
				if (optval != icmp6off)
					error = EINVAL;
			} else
				in6p->in6p_cksum = optval;
			break;

		case PRCO_GETOPT:
			if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
				optval = icmp6off;
			else
				optval = in6p->in6p_cksum;

			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			m->m_len = sizeof(int);
			*mtod(m, int *) = optval;
			break;

		default:
			error = EINVAL;
			break;
		}
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	if (op == PRCO_SETOPT && m)
		(void)m_free(m);

	return (error);
}

#ifdef RFC2292
/*
 * Set up IP6 options in pcb for insertion in output packets or
 * specifying behavior of outgoing packets.
 */
static int
ip6_pcbopts(struct ip6_pktopts **pktopt, struct mbuf *m, struct socket *so)
{
	struct ip6_pktopts *opt = *pktopt;
	int error = 0;

	/* turn off any old options. */
	if (opt) {
#ifdef DIAGNOSTIC
	    if (opt->ip6po_pktinfo || opt->ip6po_nexthop ||
		opt->ip6po_hbh || opt->ip6po_dest1 || opt->ip6po_dest2 ||
		opt->ip6po_rhinfo.ip6po_rhi_rthdr)
		    printf("ip6_pcbopts: all specified options are cleared.\n");
#endif
		ip6_clearpktopts(opt, -1);
	} else
		opt = malloc(sizeof(*opt), M_IP6OPT, M_WAITOK);
	*pktopt = NULL;

	if (!m || m->m_len == 0) {
		/*
		 * Only turning off any previous options, regardless of
		 * whether the opt is just created or given.
		 */
		free(opt, M_IP6OPT);
		return (0);
	}

	/*  set options specified by user. */
	error = ip6_setpktopts(m, opt, NULL, kauth_cred_get(),
	    so->so_proto->pr_protocol);
	if (error != 0) {
		ip6_clearpktopts(opt, -1); /* XXX: discard all options */
		free(opt, M_IP6OPT);
		return (error);
	}
	*pktopt = opt;
	return (0);
}
#endif

/*
 * initialize ip6_pktopts.  beware that there are non-zero default values in
 * the struct.
 */
void
ip6_initpktopts(struct ip6_pktopts *opt)
{

	memset(opt, 0, sizeof(*opt));
	opt->ip6po_hlim = -1;	/* -1 means default hop limit */
	opt->ip6po_tclass = -1;	/* -1 means default traffic class */
	opt->ip6po_minmtu = IP6PO_MINMTU_MCASTONLY;
#ifdef __QNXNTO__
	opt->ip6po_prefer_tempaddr = IP6PO_TEMPADDR_SYSTEM;
#endif
}

#define sin6tosa(sin6)	((struct sockaddr *)(sin6)) /* XXX */
static int
ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt,
    kauth_cred_t cred, int uproto)
{
	struct ip6_pktopts *opt;

	if (*pktopt == NULL) {
		*pktopt = malloc(sizeof(struct ip6_pktopts), M_IP6OPT,
		    M_WAITOK);
		ip6_initpktopts(*pktopt);
	}
	opt = *pktopt;

	return (ip6_setpktopt(optname, buf, len, opt, cred, 1, 0, uproto));
}

static int
ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct mbuf **mp)
{
	void *optdata = NULL;
	int optdatalen = 0;
	struct ip6_ext *ip6e;
	int error = 0;
	struct in6_pktinfo null_pktinfo;
	int deftclass = 0, on;
	int defminmtu = IP6PO_MINMTU_MCASTONLY;
#ifdef __QNXNTO__
	int defpreftemp = IP6PO_TEMPADDR_SYSTEM;
#endif
	struct mbuf *m;

	switch (optname) {
	case IPV6_PKTINFO:
		if (pktopt && pktopt->ip6po_pktinfo)
			optdata = (void *)pktopt->ip6po_pktinfo;
		else {
			/* XXX: we don't have to do this every time... */
			memset(&null_pktinfo, 0, sizeof(null_pktinfo));
			optdata = (void *)&null_pktinfo;
		}
		optdatalen = sizeof(struct in6_pktinfo);
		break;
	case IPV6_OTCLASS:
		/* XXX */
		return (EINVAL);
	case IPV6_TCLASS:
		if (pktopt && pktopt->ip6po_tclass >= 0)
			optdata = (void *)&pktopt->ip6po_tclass;
		else
			optdata = (void *)&deftclass;
		optdatalen = sizeof(int);
		break;
	case IPV6_HOPOPTS:
		if (pktopt && pktopt->ip6po_hbh) {
			optdata = (void *)pktopt->ip6po_hbh;
			ip6e = (struct ip6_ext *)pktopt->ip6po_hbh;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDR:
		if (pktopt && pktopt->ip6po_rthdr) {
			optdata = (void *)pktopt->ip6po_rthdr;
			ip6e = (struct ip6_ext *)pktopt->ip6po_rthdr;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDRDSTOPTS:
		if (pktopt && pktopt->ip6po_dest1) {
			optdata = (void *)pktopt->ip6po_dest1;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest1;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_DSTOPTS:
		if (pktopt && pktopt->ip6po_dest2) {
			optdata = (void *)pktopt->ip6po_dest2;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest2;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_NEXTHOP:
		if (pktopt && pktopt->ip6po_nexthop) {
			optdata = (void *)pktopt->ip6po_nexthop;
			optdatalen = pktopt->ip6po_nexthop->sa_len;
		}
		break;
	case IPV6_USE_MIN_MTU:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_minmtu;
		else
			optdata = (void *)&defminmtu;
		optdatalen = sizeof(int);
		break;
	case IPV6_DONTFRAG:
		if (pktopt && ((pktopt->ip6po_flags) & IP6PO_DONTFRAG))
			on = 1;
		else
			on = 0;
		optdata = (void *)&on;
		optdatalen = sizeof(on);
		break;
#ifdef __QNXNTO__
	case IPV6_PREFER_TEMPADDR:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_prefer_tempaddr;
		else
 			optdata = (void *)&defpreftemp;
 		optdatalen = sizeof(int);
 		break;
#endif
	default:		/* should not happen */
#ifdef DIAGNOSTIC
		panic("ip6_getpcbopt: unexpected option\n");
#endif
		return (ENOPROTOOPT);
	}

	if (optdatalen > MCLBYTES)
		return (EMSGSIZE); /* XXX */
	*mp = m = m_get(M_WAIT, MT_SOOPTS);
	if (optdatalen > MLEN)
		MCLGET(m, M_WAIT);
	m->m_len = optdatalen;
	if (optdatalen)
		memcpy(mtod(m, void *), optdata, optdatalen);

	return (error);
}

void
ip6_clearpktopts(struct ip6_pktopts *pktopt, int optname)
{
	if (optname == -1 || optname == IPV6_PKTINFO) {
		if (pktopt->ip6po_pktinfo)
			free(pktopt->ip6po_pktinfo, M_IP6OPT);
		pktopt->ip6po_pktinfo = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPLIMIT)
		pktopt->ip6po_hlim = -1;
	if (optname == -1 || optname == IPV6_TCLASS)
		pktopt->ip6po_tclass = -1;
	if (optname == -1 || optname == IPV6_NEXTHOP) {
		if (pktopt->ip6po_nextroute.ro_rt) {
			RTFREE(pktopt->ip6po_nextroute.ro_rt);
			pktopt->ip6po_nextroute.ro_rt = NULL;
		}
		if (pktopt->ip6po_nexthop)
			free(pktopt->ip6po_nexthop, M_IP6OPT);
		pktopt->ip6po_nexthop = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPOPTS) {
		if (pktopt->ip6po_hbh)
			free(pktopt->ip6po_hbh, M_IP6OPT);
		pktopt->ip6po_hbh = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDRDSTOPTS) {
		if (pktopt->ip6po_dest1)
			free(pktopt->ip6po_dest1, M_IP6OPT);
		pktopt->ip6po_dest1 = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDR) {
		if (pktopt->ip6po_rhinfo.ip6po_rhi_rthdr)
			free(pktopt->ip6po_rhinfo.ip6po_rhi_rthdr, M_IP6OPT);
		pktopt->ip6po_rhinfo.ip6po_rhi_rthdr = NULL;
		if (pktopt->ip6po_route.ro_rt) {
			RTFREE(pktopt->ip6po_route.ro_rt);
			pktopt->ip6po_route.ro_rt = NULL;
		}
	}
	if (optname == -1 || optname == IPV6_DSTOPTS) {
		if (pktopt->ip6po_dest2)
			free(pktopt->ip6po_dest2, M_IP6OPT);
		pktopt->ip6po_dest2 = NULL;
	}
}

#define PKTOPT_EXTHDRCPY(type) 					\
do {								\
	if (src->type) {					\
		int hlen = (((struct ip6_ext *)src->type)->ip6e_len + 1) << 3;\
		dst->type = malloc(hlen, M_IP6OPT, canwait);	\
		if (dst->type == NULL && canwait == M_NOWAIT)	\
			goto bad;				\
		memcpy(dst->type, src->type, hlen);		\
	}							\
} while (/*CONSTCOND*/ 0)

static int
copypktopts(struct ip6_pktopts *dst, struct ip6_pktopts *src, int canwait)
{
	dst->ip6po_hlim = src->ip6po_hlim;
	dst->ip6po_tclass = src->ip6po_tclass;
	dst->ip6po_flags = src->ip6po_flags;
#ifdef __QNXNTO__
	dst->ip6po_prefer_tempaddr = src->ip6po_prefer_tempaddr;
#endif
	if (src->ip6po_pktinfo) {
		dst->ip6po_pktinfo = malloc(sizeof(*dst->ip6po_pktinfo),
		    M_IP6OPT, canwait);
		if (dst->ip6po_pktinfo == NULL && canwait == M_NOWAIT)
			goto bad;
		*dst->ip6po_pktinfo = *src->ip6po_pktinfo;
	}
	if (src->ip6po_nexthop) {
		dst->ip6po_nexthop = malloc(src->ip6po_nexthop->sa_len,
		    M_IP6OPT, canwait);
		if (dst->ip6po_nexthop == NULL && canwait == M_NOWAIT)
			goto bad;
		memcpy(dst->ip6po_nexthop, src->ip6po_nexthop,
		    src->ip6po_nexthop->sa_len);
	}
	PKTOPT_EXTHDRCPY(ip6po_hbh);
	PKTOPT_EXTHDRCPY(ip6po_dest1);
	PKTOPT_EXTHDRCPY(ip6po_dest2);
	PKTOPT_EXTHDRCPY(ip6po_rthdr); /* not copy the cached route */
	return (0);

  bad:
	if (dst->ip6po_pktinfo) free(dst->ip6po_pktinfo, M_IP6OPT);
	if (dst->ip6po_nexthop) free(dst->ip6po_nexthop, M_IP6OPT);
	if (dst->ip6po_hbh) free(dst->ip6po_hbh, M_IP6OPT);
	if (dst->ip6po_dest1) free(dst->ip6po_dest1, M_IP6OPT);
	if (dst->ip6po_dest2) free(dst->ip6po_dest2, M_IP6OPT);
	if (dst->ip6po_rthdr) free(dst->ip6po_rthdr, M_IP6OPT);

	return (ENOBUFS);
}
#undef PKTOPT_EXTHDRCPY

struct ip6_pktopts *
ip6_copypktopts(struct ip6_pktopts *src, int canwait)
{
	int error;
	struct ip6_pktopts *dst;

	dst = malloc(sizeof(*dst), M_IP6OPT, canwait);
	if (dst == NULL && canwait == M_NOWAIT)
		return (NULL);
	ip6_initpktopts(dst);

	if ((error = copypktopts(dst, src, canwait)) != 0) {
		free(dst, M_IP6OPT);
		return (NULL);
	}

	return (dst);
}

void
ip6_freepcbopts(struct ip6_pktopts *pktopt)
{
	if (pktopt == NULL)
		return;

	ip6_clearpktopts(pktopt, -1);

	free(pktopt, M_IP6OPT);
}

/*
 * Set the IP6 multicast options in response to user setsockopt().
 */
static int
#ifndef __QNXNTO__
ip6_setmoptions(optname, im6op, m)
#else
#ifndef QNX_MFIB
ip6_setmoptions(optname, im6op, m, if_mask)
	struct ifnet* if_mask;
#else
ip6_setmoptions(optname, im6op, m, if_mask, fib)
	struct ifnet* if_mask;
	int fib;
#endif
#endif
	int optname;
	struct ip6_moptions **im6op;
	struct mbuf *m;
{
	int error = 0;
	u_int loop, ifindex;
	struct ipv6_mreq *mreq;
	struct ifnet *ifp;
	struct ip6_moptions *im6o = *im6op;
	struct route_in6 ro;
	struct in6_multi_mship *imm;
	struct lwp *l = curlwp;	/* XXX */

	if (im6o == NULL) {
		/*
		 * No multicast option buffer attached to the pcb;
		 * allocate one and initialize to default values.
		 */
		im6o = (struct ip6_moptions *)
			malloc(sizeof(*im6o), M_IPMOPTS, M_WAITOK);

		if (im6o == NULL)
			return (ENOBUFS);
		*im6op = im6o;
		im6o->im6o_multicast_ifp = NULL;
		im6o->im6o_multicast_hlim = ip6_defmcasthlim;
		im6o->im6o_multicast_loop = IPV6_DEFAULT_MULTICAST_LOOP;
		LIST_INIT(&im6o->im6o_memberships);
	}

	switch (optname) {

	case IPV6_MULTICAST_IF:
		/*
		 * Select the interface for outgoing multicast packets.
		 */
		if (m == NULL || m->m_len != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		bcopy(mtod(m, u_int *), &ifindex, sizeof(ifindex));
		if (ifindex != 0) {
			if (if_indexlim <= ifindex || !ifindex2ifnet[ifindex]) {
				error = ENXIO;	/* XXX EINVAL? */
				break;
			}
			ifp = ifindex2ifnet[ifindex];
			if ((ifp->if_flags & IFF_MULTICAST) == 0) {
				error = EADDRNOTAVAIL;
				break;
			}
		} else
			ifp = NULL;
		im6o->im6o_multicast_ifp = ifp;
		break;

	case IPV6_MULTICAST_HOPS:
	    {
		/*
		 * Set the IP6 hoplimit for outgoing multicast packets.
		 */
		int optval;
		if (m == NULL || m->m_len != sizeof(int)) {
			error = EINVAL;
			break;
		}
		bcopy(mtod(m, u_int *), &optval, sizeof(optval));
		if (optval < -1 || optval >= 256)
			error = EINVAL;
		else if (optval == -1)
			im6o->im6o_multicast_hlim = ip6_defmcasthlim;
		else
			im6o->im6o_multicast_hlim = optval;
		break;
	    }

	case IPV6_MULTICAST_LOOP:
		/*
		 * Set the loopback flag for outgoing multicast packets.
		 * Must be zero or one.
		 */
		if (m == NULL || m->m_len != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		bcopy(mtod(m, u_int *), &loop, sizeof(loop));
		if (loop > 1) {
			error = EINVAL;
			break;
		}
		im6o->im6o_multicast_loop = loop;
		break;

	case IPV6_JOIN_GROUP:
		/*
		 * Add a multicast group membership.
		 * Group must be a valid IP6 multicast address.
		 */
		if (m == NULL || m->m_len != sizeof(struct ipv6_mreq)) {
			error = EINVAL;
			break;
		}
		mreq = mtod(m, struct ipv6_mreq *);
		if (IN6_IS_ADDR_UNSPECIFIED(&mreq->ipv6mr_multiaddr)) {
			/*
			 * We use the unspecified address to specify to accept
			 * all multicast addresses. Only super user is allowed
			 * to do this.
			 */
			if (kauth_authorize_generic(l->l_cred,
			    KAUTH_GENERIC_ISSUSER, &l->l_acflag))
			{
				error = EACCES;
				break;
			}
		} else if (!IN6_IS_ADDR_MULTICAST(&mreq->ipv6mr_multiaddr)) {
			error = EINVAL;
			break;
		}

		/*
		 * If no interface was explicitly specified, choose an
		 * appropriate one according to the given multicast address.
		 */
		if (mreq->ipv6mr_interface == 0) {
			struct sockaddr_in6 *dst;

			/*
			 * Look up the routing table for the
			 * address, and choose the outgoing interface.
			 *   XXX: is it a good approach?
			 */
			ro.ro_rt = NULL;
			dst = (struct sockaddr_in6 *)&ro.ro_dst;
			bzero(dst, sizeof(*dst));
			dst->sin6_family = AF_INET6;
			dst->sin6_len = sizeof(*dst);
			dst->sin6_addr = mreq->ipv6mr_multiaddr;
#ifndef __QNXNTO__
			rtalloc((struct route *)&ro);
#else
#ifndef QNX_MFIB
			(rtalloc)((struct route *)&ro, if_mask);
#else
			(rtalloc)((struct route *)&ro, if_mask, fib);
#endif
#endif
			if (ro.ro_rt == NULL) {
				error = EADDRNOTAVAIL;
				break;
			}
			ifp = ro.ro_rt->rt_ifp;
			rtfree(ro.ro_rt);
		} else {
			/*
			 * If the interface is specified, validate it.
			 */
			if (if_indexlim <= mreq->ipv6mr_interface ||
			    !ifindex2ifnet[mreq->ipv6mr_interface]) {
				error = ENXIO;	/* XXX EINVAL? */
				break;
			}
			ifp = ifindex2ifnet[mreq->ipv6mr_interface];
		}

		/*
		 * See if we found an interface, and confirm that it
		 * supports multicast
		 */
		if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0) {
			error = EADDRNOTAVAIL;
			break;
		}

		if (in6_setscope(&mreq->ipv6mr_multiaddr, ifp, NULL)) {
			error = EADDRNOTAVAIL; /* XXX: should not happen */
			break;
		}

		/*
		 * See if the membership already exists.
		 */
		for (imm = im6o->im6o_memberships.lh_first;
		     imm != NULL; imm = imm->i6mm_chain.le_next)
			if (imm->i6mm_maddr->in6m_ifp == ifp &&
			    IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr,
			    &mreq->ipv6mr_multiaddr))
				break;
		if (imm != NULL) {
			error = EADDRINUSE;
			break;
		}
		/*
		 * Everything looks good; add a new record to the multicast
		 * address list for the given interface.
		 */
		imm = in6_joingroup(ifp, &mreq->ipv6mr_multiaddr, &error, 0);
		if (imm == NULL)
			break;
		LIST_INSERT_HEAD(&im6o->im6o_memberships, imm, i6mm_chain);
		break;

	case IPV6_LEAVE_GROUP:
		/*
		 * Drop a multicast group membership.
		 * Group must be a valid IP6 multicast address.
		 */
		if (m == NULL || m->m_len != sizeof(struct ipv6_mreq)) {
			error = EINVAL;
			break;
		}
		mreq = mtod(m, struct ipv6_mreq *);

		/*
		 * If an interface address was specified, get a pointer
		 * to its ifnet structure.
		 */
		if (mreq->ipv6mr_interface != 0) {
			if (if_indexlim <= mreq->ipv6mr_interface ||
			    !ifindex2ifnet[mreq->ipv6mr_interface]) {
				error = ENXIO;	/* XXX EINVAL? */
				break;
			}
			ifp = ifindex2ifnet[mreq->ipv6mr_interface];
		} else
			ifp = NULL;

		/* Fill in the scope zone ID */
		if (ifp) {
			if (in6_setscope(&mreq->ipv6mr_multiaddr, ifp, NULL)) {
				/* XXX: should not happen */
				error = EADDRNOTAVAIL;
				break;
			}
		} else if (mreq->ipv6mr_interface != 0) {
			/*
			 * XXX: This case would happens when the (positive)
			 * index is in the valid range, but the corresponding
			 * interface has been detached dynamically.  The above
			 * check probably avoids such case to happen here, but
			 * we check it explicitly for safety.
			 */
			error = EADDRNOTAVAIL;
			break;	    
		} else {	/* ipv6mr_interface == 0 */
			struct sockaddr_in6 sa6_mc;

			/*
			 * The API spec says as follows:
			 *  If the interface index is specified as 0, the
			 *  system may choose a multicast group membership to
			 *  drop by matching the multicast address only.
			 * On the other hand, we cannot disambiguate the scope
			 * zone unless an interface is provided.  Thus, we
			 * check if there's ambiguity with the default scope
			 * zone as the last resort.
			 */
			bzero(&sa6_mc, sizeof(sa6_mc));
			sa6_mc.sin6_family = AF_INET6;
			sa6_mc.sin6_len = sizeof(sa6_mc);
			sa6_mc.sin6_addr = mreq->ipv6mr_multiaddr;
			error = sa6_embedscope(&sa6_mc, ip6_use_defzone);
			if (error != 0)
				break;
			mreq->ipv6mr_multiaddr = sa6_mc.sin6_addr;
		}

		/*
		 * Find the membership in the membership list.
		 */
		for (imm = im6o->im6o_memberships.lh_first;
		     imm != NULL; imm = imm->i6mm_chain.le_next) {
			if ((ifp == NULL || imm->i6mm_maddr->in6m_ifp == ifp) &&
			    IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr,
			    &mreq->ipv6mr_multiaddr))
				break;
		}
		if (imm == NULL) {
			/* Unable to resolve interface */
			error = EADDRNOTAVAIL;
			break;
		}
		/*
		 * Give up the multicast address record to which the
		 * membership points.
		 */
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	/*
	 * If all options have default values, no need to keep the mbuf.
	 */
	if (im6o->im6o_multicast_ifp == NULL &&
	    im6o->im6o_multicast_hlim == ip6_defmcasthlim &&
	    im6o->im6o_multicast_loop == IPV6_DEFAULT_MULTICAST_LOOP &&
	    im6o->im6o_memberships.lh_first == NULL) {
		free(*im6op, M_IPMOPTS);
		*im6op = NULL;
	}

	return (error);
}

/*
 * Return the IP6 multicast options in response to user getsockopt().
 */
static int
ip6_getmoptions(optname, im6o, mp)
	int optname;
	struct ip6_moptions *im6o;
	struct mbuf **mp;
{
	u_int *hlim, *loop, *ifindex;

	*mp = m_get(M_WAIT, MT_SOOPTS);

	switch (optname) {

	case IPV6_MULTICAST_IF:
		ifindex = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL || im6o->im6o_multicast_ifp == NULL)
			*ifindex = 0;
		else
			*ifindex = im6o->im6o_multicast_ifp->if_index;
		return (0);

	case IPV6_MULTICAST_HOPS:
		hlim = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL)
			*hlim = ip6_defmcasthlim;
		else
			*hlim = im6o->im6o_multicast_hlim;
		return (0);

	case IPV6_MULTICAST_LOOP:
		loop = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL)
			*loop = ip6_defmcasthlim;
		else
			*loop = im6o->im6o_multicast_loop;
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

/*
 * Discard the IP6 multicast options.
 */
void
ip6_freemoptions(im6o)
	struct ip6_moptions *im6o;
{
	struct in6_multi_mship *imm;

	if (im6o == NULL)
		return;

	while ((imm = im6o->im6o_memberships.lh_first) != NULL) {
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
	}
	free(im6o, M_IPMOPTS);
}

/*
 * Set IPv6 outgoing packet options based on advanced API.
 */
int
ip6_setpktopts(struct mbuf *control, struct ip6_pktopts *opt, 
	struct ip6_pktopts *stickyopt, kauth_cred_t cred, int uproto)
{
	struct cmsghdr *cm = 0;

	if (control == NULL || opt == NULL)
		return (EINVAL);

	ip6_initpktopts(opt);
	if (stickyopt) {
		int error;

		/*
		 * If stickyopt is provided, make a local copy of the options
		 * for this particular packet, then override them by ancillary
		 * objects.
		 * XXX: copypktopts() does not copy the cached route to a next
		 * hop (if any).  This is not very good in terms of efficiency,
		 * but we can allow this since this option should be rarely
		 * used.
		 */
		if ((error = copypktopts(opt, stickyopt, M_NOWAIT)) != 0)
			return (error);
	}

	/*
	 * XXX: Currently, we assume all the optional information is stored
	 * in a single mbuf.
	 */
	if (control->m_next)
		return (EINVAL);

	for (; control->m_len; control->m_data += CMSG_ALIGN(cm->cmsg_len),
	    control->m_len -= CMSG_ALIGN(cm->cmsg_len)) {
		int error;

		if (control->m_len < CMSG_LEN(0))
			return (EINVAL);

		cm = mtod(control, struct cmsghdr *);
		if (cm->cmsg_len == 0 || cm->cmsg_len > control->m_len
			|| CMSG_ALIGN(cm->cmsg_len) > control->m_len)
			return (EINVAL);
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		error = ip6_setpktopt(cm->cmsg_type, CMSG_DATA(cm),
		    cm->cmsg_len - CMSG_LEN(0), opt, cred, 0, 1, uproto);
		if (error)
			return (error);
	}

	return (0);
}

/*
 * Set a particular packet option, as a sticky option or an ancillary data
 * item.  "len" can be 0 only when it's a sticky option.
 * We have 4 cases of combination of "sticky" and "cmsg":
 * "sticky=0, cmsg=0": impossible
 * "sticky=0, cmsg=1": RFC2292 or RFC3542 ancillary data
 * "sticky=1, cmsg=0": RFC3542 socket option
 * "sticky=1, cmsg=1": RFC2292 socket option
 */
static int
ip6_setpktopt(int optname, u_char *buf, int len, struct ip6_pktopts *opt,
    kauth_cred_t cred, int sticky, int cmsg, int uproto)
{
	int minmtupolicy;
	int error;
#ifdef __QNXNTO__
	int preftemp;
#endif

	if (!sticky && !cmsg) {
#ifdef DIAGNOSTIC
		printf("ip6_setpktopt: impossible case\n");
#endif
		return (EINVAL);
	}

	/*
	 * IPV6_2292xxx is for backward compatibility to RFC2292, and should
	 * not be specified in the context of RFC3542.  Conversely,
	 * RFC3542 types should not be specified in the context of RFC2292.
	 */
	if (!cmsg) {
		switch (optname) {
		case IPV6_2292PKTINFO:
		case IPV6_2292HOPLIMIT:
		case IPV6_2292NEXTHOP:
		case IPV6_2292HOPOPTS:
		case IPV6_2292DSTOPTS:
		case IPV6_2292RTHDR:
		case IPV6_2292PKTOPTIONS:
			return (ENOPROTOOPT);
		}
	}
	if (sticky && cmsg) {
		switch (optname) {
		case IPV6_PKTINFO:
		case IPV6_HOPLIMIT:
		case IPV6_NEXTHOP:
		case IPV6_HOPOPTS:
		case IPV6_DSTOPTS:
		case IPV6_RTHDRDSTOPTS:
		case IPV6_RTHDR:
		case IPV6_USE_MIN_MTU:
		case IPV6_DONTFRAG:
		case IPV6_OTCLASS:
		case IPV6_TCLASS:
#ifdef __QNXNTO__
		case IPV6_PREFER_TEMPADDR: /* XXX: not an RFC3542 option */
#endif
			return (ENOPROTOOPT);
		}
	}

	switch (optname) {
#ifdef RFC2292
	case IPV6_2292PKTINFO:
#endif
	case IPV6_PKTINFO:
	{
		struct ifnet *ifp = NULL;
		struct in6_pktinfo *pktinfo;

		if (len != sizeof(struct in6_pktinfo))
			return (EINVAL);

		pktinfo = (struct in6_pktinfo *)buf;

		/*
		 * An application can clear any sticky IPV6_PKTINFO option by
		 * doing a "regular" setsockopt with ipi6_addr being
		 * in6addr_any and ipi6_ifindex being zero.
		 * [RFC 3542, Section 6]
		 */
		if (optname == IPV6_PKTINFO && opt->ip6po_pktinfo &&
		    pktinfo->ipi6_ifindex == 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			ip6_clearpktopts(opt, optname);
			break;
		}

		if (uproto == IPPROTO_TCP && optname == IPV6_PKTINFO &&
		    sticky && !IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			return (EINVAL);
		}

		/* validate the interface index if specified. */
		if (pktinfo->ipi6_ifindex >= if_indexlim) {
			 return (ENXIO);
		}
		if (pktinfo->ipi6_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi6_ifindex];
			if (ifp == NULL)
				return (ENXIO);
		}

		/*
		 * We store the address anyway, and let in6_selectsrc()
		 * validate the specified address.  This is because ipi6_addr
		 * may not have enough information about its scope zone, and
		 * we may need additional information (such as outgoing
		 * interface or the scope zone of a destination address) to
		 * disambiguate the scope.
		 * XXX: the delay of the validation may confuse the
		 * application when it is used as a sticky option.
		 */
		if (opt->ip6po_pktinfo == NULL) {
			opt->ip6po_pktinfo = malloc(sizeof(*pktinfo),
			    M_IP6OPT, M_NOWAIT);
			if (opt->ip6po_pktinfo == NULL)
				return (ENOBUFS);
		}
		memcpy(opt->ip6po_pktinfo, pktinfo, sizeof(*pktinfo));
		break;
	}

#ifdef RFC2292
	case IPV6_2292HOPLIMIT:
#endif
	case IPV6_HOPLIMIT:
	{
		int *hlimp;

		/*
		 * RFC 3542 deprecated the usage of sticky IPV6_HOPLIMIT
		 * to simplify the ordering among hoplimit options.
		 */
		if (optname == IPV6_HOPLIMIT && sticky)
			return (ENOPROTOOPT);

		if (len != sizeof(int))
			return (EINVAL);
		hlimp = (int *)buf;
		if (*hlimp < -1 || *hlimp > 255)
			return (EINVAL);

		opt->ip6po_hlim = *hlimp;
		break;
	}

	case IPV6_OTCLASS:
		if (len != sizeof(u_int8_t))
			return (EINVAL);

		opt->ip6po_tclass = *(u_int8_t *)buf;
		break;

	case IPV6_TCLASS:
	{
		int tclass;

		if (len != sizeof(int))
			return (EINVAL);
		tclass = *(int *)buf;
		if (tclass < -1 || tclass > 255)
			return (EINVAL);

		opt->ip6po_tclass = tclass;
		break;
	}

#ifdef RFC2292
	case IPV6_2292NEXTHOP:
#endif
	case IPV6_NEXTHOP:
		error = kauth_authorize_generic(cred, KAUTH_GENERIC_ISSUSER, NULL);
		if (error)
			return (error);

		if (len == 0) {	/* just remove the option */
			ip6_clearpktopts(opt, IPV6_NEXTHOP);
			break;
		}

		/* check if cmsg_len is large enough for sa_len */
		if (len < sizeof(struct sockaddr) || len < *buf)
			return (EINVAL);

		switch (((struct sockaddr *)buf)->sa_family) {
		case AF_INET6:
		{
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)buf;

			if (sa6->sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);

			if (IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) ||
			    IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
				return (EINVAL);
			}
			if ((error = sa6_embedscope(sa6, ip6_use_defzone))
			    != 0) {
				return (error);
			}
			break;
		}
		case AF_LINK:	/* eventually be supported? */
		default:
			return (EAFNOSUPPORT);
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_NEXTHOP);
		opt->ip6po_nexthop = malloc(*buf, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_nexthop == NULL)
			return (ENOBUFS);
		memcpy(opt->ip6po_nexthop, buf, *buf);
		break;

#ifdef RFC2292
	case IPV6_2292HOPOPTS:
#endif
	case IPV6_HOPOPTS:
	{
		struct ip6_hbh *hbh;
		int hbhlen;

		/*
		 * XXX: We don't allow a non-privileged user to set ANY HbH
		 * options, since per-option restriction has too much
		 * overhead.
		 */
		error = kauth_authorize_generic(cred, KAUTH_GENERIC_ISSUSER, NULL);
		if (error)
			return (error);

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_HOPOPTS);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_hbh))
			return (EINVAL);
		hbh = (struct ip6_hbh *)buf;
		hbhlen = (hbh->ip6h_len + 1) << 3;
		if (len != hbhlen)
			return (EINVAL);

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_HOPOPTS);
		opt->ip6po_hbh = malloc(hbhlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_hbh == NULL)
			return (ENOBUFS);
		memcpy(opt->ip6po_hbh, hbh, hbhlen);

		break;
	}

#ifdef RFC2292
	case IPV6_2292DSTOPTS:
#endif
	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS:
	{
		struct ip6_dest *dest, **newdest = NULL;
		int destlen;

		/* XXX: see the comment for IPV6_HOPOPTS */
		error = kauth_authorize_generic(cred, KAUTH_GENERIC_ISSUSER, NULL);
		if (error)
			return (error);

		if (len == 0) {
			ip6_clearpktopts(opt, optname);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_dest))
			return (EINVAL);
		dest = (struct ip6_dest *)buf;
		destlen = (dest->ip6d_len + 1) << 3;
		if (len != destlen)
			return (EINVAL);
		/*
		 * Determine the position that the destination options header
		 * should be inserted; before or after the routing header.
		 */
		switch (optname) {
		case IPV6_2292DSTOPTS:
			/*
			 * The old advanced API is ambiguous on this point.
			 * Our approach is to determine the position based
			 * according to the existence of a routing header.
			 * Note, however, that this depends on the order of the
			 * extension headers in the ancillary data; the 1st
			 * part of the destination options header must appear
			 * before the routing header in the ancillary data,
			 * too.
			 * RFC3542 solved the ambiguity by introducing
			 * separate ancillary data or option types.
			 */
			if (opt->ip6po_rthdr == NULL)
				newdest = &opt->ip6po_dest1;
			else
				newdest = &opt->ip6po_dest2;
			break;
		case IPV6_RTHDRDSTOPTS:
			newdest = &opt->ip6po_dest1;
			break;
		case IPV6_DSTOPTS:
			newdest = &opt->ip6po_dest2;
			break;
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, optname);
		*newdest = malloc(destlen, M_IP6OPT, M_NOWAIT);
		if (*newdest == NULL)
			return (ENOBUFS);
		memcpy(*newdest, dest, destlen);

		break;
	}

#ifdef RFC2292
	case IPV6_2292RTHDR:
#endif
	case IPV6_RTHDR:
	{
		struct ip6_rthdr *rth;
		int rthlen;

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_RTHDR);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_rthdr))
			return (EINVAL);
		rth = (struct ip6_rthdr *)buf;
		rthlen = (rth->ip6r_len + 1) << 3;
		if (len != rthlen)
			return (EINVAL);
		switch (rth->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			if (rth->ip6r_len == 0)	/* must contain one addr */
				return (EINVAL);
			if (rth->ip6r_len % 2) /* length must be even */
				return (EINVAL);
			if (rth->ip6r_len / 2 != rth->ip6r_segleft)
				return (EINVAL);
			break;
		default:
			return (EINVAL);	/* not supported */
		}
		/* turn off the previous option */
		ip6_clearpktopts(opt, IPV6_RTHDR);
		opt->ip6po_rthdr = malloc(rthlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_rthdr == NULL)
			return (ENOBUFS);
		memcpy(opt->ip6po_rthdr, rth, rthlen);
		break;
	}

	case IPV6_USE_MIN_MTU:
		if (len != sizeof(int))
			return (EINVAL);
		minmtupolicy = *(int *)buf;
		if (minmtupolicy != IP6PO_MINMTU_MCASTONLY &&
		    minmtupolicy != IP6PO_MINMTU_DISABLE &&
		    minmtupolicy != IP6PO_MINMTU_ALL) {
			return (EINVAL);
		}
		opt->ip6po_minmtu = minmtupolicy;
		break;

	case IPV6_DONTFRAG:
		if (len != sizeof(int))
			return (EINVAL);

		if (uproto == IPPROTO_TCP || *(int *)buf == 0) {
			/*
			 * we ignore this option for TCP sockets.
			 * (RFC3542 leaves this case unspecified.)
			 */
			opt->ip6po_flags &= ~IP6PO_DONTFRAG;
		} else
			opt->ip6po_flags |= IP6PO_DONTFRAG;
		break;
		
#ifdef __QNXNTO__
	case IPV6_PREFER_TEMPADDR:
		if (len != sizeof(int))
			return (EINVAL);
		preftemp = *(int *)buf;
		if (preftemp != IP6PO_TEMPADDR_SYSTEM &&
			preftemp != IP6PO_TEMPADDR_NOTPREFER &&
			preftemp != IP6PO_TEMPADDR_PREFER) {
			return (EINVAL);
		}
		opt->ip6po_prefer_tempaddr = preftemp;
		break;
#endif

	default:
		return (ENOPROTOOPT);
	} /* end of switch */

	return (0);
}

/*
 * Routine called from ip6_output() to loop back a copy of an IP6 multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be lo0ifp -- easier than replicating that code here.
 */
void
ip6_mloopback(ifp, m, dst)
	struct ifnet *ifp;
	struct mbuf *m;
	struct sockaddr_in6 *dst;
{
	struct mbuf *copym;
	struct ip6_hdr *ip6;

	copym = m_copy(m, 0, M_COPYALL);
	if (copym == NULL)
		return;

	/*
	 * Make sure to deep-copy IPv6 header portion in case the data
	 * is in an mbuf cluster, so that we can safely override the IPv6
	 * header portion later.
	 */
	if ((copym->m_flags & M_EXT) != 0 ||
	    copym->m_len < sizeof(struct ip6_hdr)) {
		copym = m_pullup(copym, sizeof(struct ip6_hdr));
		if (copym == NULL)
			return;
	}

#ifdef DIAGNOSTIC
	if (copym->m_len < sizeof(*ip6)) {
		m_freem(copym);
		return;
	}
#endif

	ip6 = mtod(copym, struct ip6_hdr *);
	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);

	(void)looutput(ifp, copym, (struct sockaddr *)dst, NULL);
}

/*
 * Chop IPv6 header off from the payload.
 */
static int
ip6_splithdr(m, exthdrs)
	struct mbuf *m;
	struct ip6_exthdrs *exthdrs;
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;

	ip6 = mtod(m, struct ip6_hdr *);
	if (m->m_len > sizeof(*ip6)) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);
		if (mh == 0) {
			m_freem(m);
			return ENOBUFS;
		}
		M_MOVE_PKTHDR(mh, m);
		MH_ALIGN(mh, sizeof(*ip6));
		m->m_len -= sizeof(*ip6);
		m->m_data += sizeof(*ip6);
		mh->m_next = m;
		m = mh;
		m->m_len = sizeof(*ip6);
		bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
	}
	exthdrs->ip6e_ip6 = m;
	return 0;
}

/*
 * Compute IPv6 extension header length.
 */
int
ip6_optlen(in6p)
	struct in6pcb *in6p;
{
	int len;

	if (!in6p->in6p_outputopts)
		return 0;

	len = 0;
#define elen(x) \
    (((struct ip6_ext *)(x)) ? (((struct ip6_ext *)(x))->ip6e_len + 1) << 3 : 0)

	len += elen(in6p->in6p_outputopts->ip6po_hbh);
	len += elen(in6p->in6p_outputopts->ip6po_dest1);
	len += elen(in6p->in6p_outputopts->ip6po_rthdr);
	len += elen(in6p->in6p_outputopts->ip6po_dest2);
	return len;
#undef elen
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/ip6_output.c $ $Rev: 852068 $")
#endif
