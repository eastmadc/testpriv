/*	$NetBSD: ipsec_output.c,v 1.17.2.2 2007/10/31 12:39:30 liamjfoy Exp $	*/

/*-
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: /repoman/r/ncvs/src/sys/netipsec/ipsec_output.c,v 1.3.2.2 2003/03/28 20:32:53 sam Exp $
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ipsec_output.c,v 1.17.2.2 2007/10/31 12:39:30 liamjfoy Exp $");

/*
 * IPsec output processing.
 */
#include "opt_inet.h"
#ifdef __FreeBSD__
#include "opt_inet6.h"
#endif
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/ip_ecn.h>
#ifdef INET6
#  ifdef __FreeBSD__
#  include <netinet6/ip6_ecn.h>
#  endif
#endif

#include <netinet/ip6.h>
#ifdef INET6
#include <netinet6/ip6_var.h>
#endif
#include <netinet/in_pcb.h>
#ifdef INET6
#include <netinet/icmp6.h>
#endif
#ifdef IPSEC_NAT_T
#include <netinet/udp.h>
#endif
#include <netipsec/ipsec.h>
#include <netipsec/ipsec_var.h>
#ifdef INET6
#include <netipsec/ipsec6.h>
#endif
#include <netipsec/ah_var.h>
#include <netipsec/esp_var.h>
#include <netipsec/ipcomp_var.h>

#include <netipsec/xform.h>

#include <netipsec/key.h>
#include <netipsec/keydb.h>
#include <netipsec/key_debug.h>
#include <netipsec/ipsec_osdep.h>

#include <net/net_osdep.h>		/* ovbcopy() in ipsec6_encapsulate() */

int
ipsec_process_done(struct mbuf *m, struct ipsecrequest *isr)
{
	struct tdb_ident *tdbi;
	struct m_tag *mtag;
	struct secasvar *sav;
	struct secasindex *saidx;
	int error;
#ifdef IPSEC_NAT_T
#ifdef INET
	struct ip * ip;
#endif /* INET */
#ifdef INET6
	struct ip6_hdr * ip6;
#endif /* INET6 */
#ifndef __QNXNTO__
	struct mbuf * mo;
#else
	struct mbuf *mo = NULL;
#endif
	struct udphdr *udp = NULL;
	uint64_t * data = NULL;
	int hlen, roff;
#endif /* IPSEC_NAT_T */
#ifdef QNX_MFIB
	int tun_encap_fib= DEFAULT_FIB;
#endif

	IPSEC_SPLASSERT_SOFTNET("ipsec_process_done");

	IPSEC_ASSERT(m != NULL, ("ipsec_process_done: null mbuf"));
	IPSEC_ASSERT(isr != NULL, ("ipsec_process_done: null ISR"));
	sav = isr->sav;
	IPSEC_ASSERT(sav != NULL, ("ipsec_process_done: null SA"));
	IPSEC_ASSERT(sav->sah != NULL, ("ipsec_process_done: null SAH"));

	saidx = &sav->sah->saidx;

#ifdef IPSEC_NAT_T
	if(sav->natt_type != 0) {
#ifndef __QNXNTO__
		ip = mtod(m, struct ip *);
#endif
		
		hlen = sizeof(struct udphdr);
		if (sav->natt_type == UDP_ENCAP_ESPINUDP_NON_IKE)
			hlen += sizeof(uint64_t);
#ifndef __QNXNTO__
		mo = m_makespace(m, sizeof(struct ip), hlen, &roff);
#else
		if (saidx->dst.sa.sa_family == AF_INET) 
			mo = m_makespace(m, sizeof(struct ip), hlen, &roff);
		else if (saidx->dst.sa.sa_family == AF_INET6)
			mo = m_makespace(m, sizeof(struct ip6_hdr), hlen, &roff); 
		else
			DPRINTF(("ipsec_process_done : Unsupported sa_family"));
#endif
		if (mo == NULL) {
			DPRINTF(("ipsec_process_done : failed to inject"
				"%u byte UDP for SA %s/%08lx\n",
					hlen, ipsec_address(&saidx->dst),
					(u_long) ntohl (sav->spi)));
			error = ENOBUFS;
			goto bad;
		}
		
		udp = (struct udphdr*) (mtod(mo, char*) + roff);
		data = (uint64_t*) (udp + 1);

		if (sav->natt_type == UDP_ENCAP_ESPINUDP_NON_IKE)
			*data = 0; /* NON-IKE Marker */

		if (sav->natt_type == UDP_ENCAP_ESPINUDP_NON_IKE)
			udp->uh_sport = htons(UDP_ENCAP_ESPINUDP_PORT);
		else
			udp->uh_sport = key_portfromsaddr(&saidx->src);

		udp->uh_dport = key_portfromsaddr(&saidx->dst);
		udp->uh_sum = 0;
#ifndef __QNXNTO__
		udp->uh_ulen = htons(m->m_pkthdr.len - (ip->ip_hl << 2));
#else
		/* At this point it is AF_INET or AF_INET6 */
		if (saidx->dst.sa.sa_family == AF_INET) {
			ip = mtod(m, struct ip *);
			udp->uh_ulen = htons(m->m_pkthdr.len - (ip->ip_hl << 2));
		}
#ifdef INET6
		else {
			ip6 = mtod(m, struct ip6_hdr *);
			udp->uh_sum = in6_cksum_phdr(&ip6->ip6_src, &ip6->ip6_dst, 
					ip6->ip6_plen, htonl(IPPROTO_UDP));
			m->m_pkthdr.csum_flags = M_CSUM_UDPv6;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum); 
			udp->uh_ulen = htons(m->m_pkthdr.len - (sizeof(struct ip6_hdr)));
		} 
#endif
#endif
	}
#endif /* IPSEC_NAT_T */

	switch (saidx->dst.sa.sa_family) {
#ifdef INET
	case AF_INET:
		/* Fix the header length, for AH processing. */
		mtod(m, struct ip *)->ip_len = htons(m->m_pkthdr.len);
#ifdef IPSEC_NAT_T
		if (sav->natt_type != 0)
			ip->ip_p = IPPROTO_UDP;
#endif /* IPSEC_NAT_T */
		break;
#endif /* INET */
#ifdef INET6
	case AF_INET6:
		/* Fix the header length, for AH processing. */
		if (m->m_pkthdr.len < sizeof (struct ip6_hdr)) {
			error = ENXIO;
			goto bad;
		}
		if (m->m_pkthdr.len - sizeof (struct ip6_hdr) > IPV6_MAXPACKET) {
			/* No jumbogram support. */
			error = ENXIO;	/*?*/
			goto bad;
		}
		mtod(m, struct ip6_hdr *)->ip6_plen =
			htons(m->m_pkthdr.len - sizeof(struct ip6_hdr));
#ifdef IPSEC_NAT_T
#ifndef __QNXNTO__
		if (sav->natt_type != 0)
			ip6->ip6_nxt = IPPROTO_UDP;
#else
		if (sav->natt_type != 0) {
			udp->uh_sum = in6_cksum_phdr(&ip6->ip6_src, &ip6->ip6_dst, 
					ip6->ip6_plen, htonl(IPPROTO_UDP));
			m->m_pkthdr.csum_flags = M_CSUM_UDPv6;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum); 
			ip6->ip6_nxt = IPPROTO_UDP;
		}
#endif
#endif /* IPSEC_NAT_T */
		break;
#endif /* INET6 */
	default:
		DPRINTF(("ipsec_process_done: unknown protocol family %u\n",
		    saidx->dst.sa.sa_family));
		error = ENXIO;
		goto bad;
	}

	key_sa_recordxfer(sav, m);

	/*
	 * Add a record of what we've done or what needs to be done to the
	 * packet.
	 */
	mtag = m_tag_get(PACKET_TAG_IPSEC_OUT_DONE,
			sizeof(struct tdb_ident), M_NOWAIT);
	if (mtag == NULL) {
		DPRINTF(("ipsec_process_done: could not get packet tag\n"));
		error = ENOMEM;
		goto bad;
	}

	tdbi = (struct tdb_ident *)(mtag + 1);
	tdbi->dst = saidx->dst;
	tdbi->proto = saidx->proto;
	tdbi->spi = sav->spi;
	m_tag_prepend(m, mtag);

	/*
	 * If there's another (bundled) SA to apply, do so.
	 * Note that this puts a burden on the kernel stack size.
	 * If this is a problem we'll need to introduce a queue
	 * to set the packet on so we can unwind the stack before
	 * doing further processing.
	 */
	if (isr->next) {
		newipsecstat.ips_out_bundlesa++;
        switch ( saidx->dst.sa.sa_family ) {
#ifdef INET
        case AF_INET:
			if (mtod(m, struct ip *)->ip_p == IPPROTO_IPIP)
				return ipsec4_process_packet(m, isr->next, 0, 1);
			else
				return ipsec4_process_packet(m, isr->next, 0,0);
#endif /* INET */
#ifdef INET6
		case AF_INET6:
        	return ipsec6_process_packet(m,isr->next);
#endif /* INET6 */
		default :
			DPRINTF(("ipsec_process_done: unknown protocol family %u\n",
                               saidx->dst.sa.sa_family));
			error = ENXIO;
			goto bad;
        }
	}

	/*
	 * We're done with IPsec processing, transmit the packet using the
	 * appropriate network protocol (IP or IPv6). SPD lookup will be
	 * performed again there.
	 */
	switch (saidx->dst.sa.sa_family) {
#ifdef INET
	struct ip *ip;
#ifdef __QNXNTO__
	struct ifnet *ifp =  NULL;
#endif
	case AF_INET:
		ip = mtod(m, struct ip *);
#ifdef __FreeBSD__
		/* FreeBSD ip_output() expects ip_len, ip_off in host endian */
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_off = ntohs(ip->ip_off);
#endif /* __FreeBSD_ */
#ifndef QNX_MFIB
		return ip_output(m, NULL, NULL, IP_RAWOUTPUT,
		    (struct ip_moptions *)NULL, (struct socket *)NULL);
#else
		if (*sav->if_outer != '\0') {
			ifp = ifunit(sav->if_outer, ANY_FIB);
			tun_encap_fib = if_get_first_fib(ifp);
		} else {
			ifp = NULL;
		}
		return ip_output(m, tun_encap_fib, NULL, NULL, IP_RAWOUTPUT | IP_BINDTODEVICE,
			(struct ip_moptions *)NULL, (struct socket *)NULL, ifp);
#endif

#endif /* INET */
#ifdef INET6
	case AF_INET6:
		/*
		 * We don't need massage, IPv6 header fields are always in
		 * net endian.
		 */
		return ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL
#ifdef __QNXNTO__
		, NULL, NULL
#ifdef QNX_MFIB
		, DEFAULT_FIB
#endif
#endif
		);
#endif /* INET6 */
	}
	panic("ipsec_process_done");
bad:
	m_freem(m);
	KEY_FREESAV(&sav);
	return (error);
}

static struct ipsecrequest *
ipsec_nextisr(
	struct mbuf *m,
	struct ipsecrequest *isr,
	int af,
	struct secasindex *saidx,
	int *error
)
{
#define IPSEC_OSTAT(x,y,z) (isr->saidx.proto == IPPROTO_ESP ? (x)++ : \
			    isr->saidx.proto == IPPROTO_AH ? (y)++ : (z)++)
	struct secasvar *sav;

	IPSEC_SPLASSERT_SOFTNET("ipsec_nextisr");
	IPSEC_ASSERT(af == AF_INET || af == AF_INET6,
		("ipsec_nextisr: invalid address family %u", af));
again:
	/*
	 * Craft SA index to search for proper SA.  Note that
	 * we only fillin unspecified SA peers for transport
	 * mode; for tunnel mode they must already be filled in.
	 */
	*saidx = isr->saidx;
	if (isr->saidx.mode == IPSEC_MODE_TRANSPORT) {
		/* Fillin unspecified SA peers only for transport mode */
		if (af == AF_INET) {
			struct sockaddr_in *sin;
			struct ip *ip = mtod(m, struct ip *);

			if (saidx->src.sa.sa_len == 0) {
				sin = &saidx->src.sin;
				sin->sin_len = sizeof(*sin);
				sin->sin_family = AF_INET;
				sin->sin_port = IPSEC_PORT_ANY;
				sin->sin_addr = ip->ip_src;
			}
			if (saidx->dst.sa.sa_len == 0) {
				sin = &saidx->dst.sin;
				sin->sin_len = sizeof(*sin);
				sin->sin_family = AF_INET;
				sin->sin_port = IPSEC_PORT_ANY;
				sin->sin_addr = ip->ip_dst;
			}
		} else {
			struct sockaddr_in6 *sin6;
			struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

			if (saidx->src.sin6.sin6_len == 0) {
				sin6 = (struct sockaddr_in6 *)&saidx->src;
				sin6->sin6_len = sizeof(*sin6);
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = IPSEC_PORT_ANY;
				sin6->sin6_addr = ip6->ip6_src;
				if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
					/* fix scope id for comparing SPD */
					sin6->sin6_addr.s6_addr16[1] = 0;
					sin6->sin6_scope_id =
					    ntohs(ip6->ip6_src.s6_addr16[1]);
				}
			}
			if (saidx->dst.sin6.sin6_len == 0) {
				sin6 = (struct sockaddr_in6 *)&saidx->dst;
				sin6->sin6_len = sizeof(*sin6);
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = IPSEC_PORT_ANY;
				sin6->sin6_addr = ip6->ip6_dst;
				if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
					/* fix scope id for comparing SPD */
					sin6->sin6_addr.s6_addr16[1] = 0;
					sin6->sin6_scope_id =
					    ntohs(ip6->ip6_dst.s6_addr16[1]);
				}
			}
		}
	}

	/*
	 * Lookup SA and validate it.
	 */
	*error = key_checkrequest(isr, saidx);
	if (*error != 0) {
		/*
		 * IPsec processing is required, but no SA found.
		 * I assume that key_acquire() had been called
		 * to get/establish the SA. Here I discard
		 * this packet because it is responsibility for
		 * upper layer to retransmit the packet.
		 */
		newipsecstat.ips_out_nosa++;
		goto bad;
	}
	sav = isr->sav;
	if (sav == NULL) {		/* XXX valid return */
		IPSEC_ASSERT(ipsec_get_reqlevel(isr) == IPSEC_LEVEL_USE,
			("ipsec_nextisr: no SA found, but required; level %u",
			ipsec_get_reqlevel(isr)));
		isr = isr->next;
		if (isr == NULL) {
			/*XXXstatistic??*/
			*error = EINVAL;		/*XXX*/
			return isr;
		}
		goto again;
	}

	/*
	 * Check system global policy controls.
	 */
	if ((isr->saidx.proto == IPPROTO_ESP && !esp_enable) ||
	    (isr->saidx.proto == IPPROTO_AH && !ah_enable) ||
	    (isr->saidx.proto == IPPROTO_IPCOMP && !ipcomp_enable)) {
		DPRINTF(("ipsec_nextisr: IPsec outbound packet dropped due"
			" to policy (check your sysctls)\n"));
		IPSEC_OSTAT(espstat.esps_pdrops, ahstat.ahs_pdrops,
		    ipcompstat.ipcomps_pdrops);
		*error = EHOSTUNREACH;
		goto bad;
	}

	/*
	 * Sanity check the SA contents for the caller
	 * before they invoke the xform output method.
	 */
	if (sav->tdb_xform == NULL) {
		DPRINTF(("ipsec_nextisr: no transform for SA\n"));
		IPSEC_OSTAT(espstat.esps_noxform, ahstat.ahs_noxform,
		    ipcompstat.ipcomps_noxform);
		*error = EHOSTUNREACH;
		goto bad;
	}
	return isr;
bad:
	IPSEC_ASSERT(*error != 0, ("ipsec_nextisr: error return w/ no error code"));
	return NULL;
#undef IPSEC_OSTAT
}

#ifdef INET
/*
 * IPsec output logic for IPv4.
 */
int
ipsec4_process_packet(
    struct mbuf *m,
    struct ipsecrequest *isr,
    int flags,
    int tunalready
)
{
	struct secasindex saidx;
	struct secasvar *sav;
	struct ip *ip;
	int s, error, i, off;

	IPSEC_ASSERT(m != NULL, ("ipsec4_process_packet: null mbuf"));
	IPSEC_ASSERT(isr != NULL, ("ipsec4_process_packet: null isr"));

	s = splsoftnet();			/* insure SA contents don't change */

	isr = ipsec_nextisr(m, isr, AF_INET, &saidx, &error);
	if (isr == NULL)
		goto bad;

	sav = isr->sav;
	if (!tunalready) {
		union sockaddr_union *dst = &sav->sah->saidx.dst;
		int setdf;

		/*
		 * Collect IP_DF state from the outer header.
		 */
		if (dst->sa.sa_family == AF_INET) {
			if (m->m_len < sizeof (struct ip) &&
			    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
				error = ENOBUFS;
				goto bad;
			}
			ip = mtod(m, struct ip *);
			/* Honor system-wide control of how to handle IP_DF */
			switch (ip4_ipsec_dfbit) {
			case 0:			/* clear in outer header */
			case 1:			/* set in outer header */
				setdf = ip4_ipsec_dfbit;
				break;
			default:		/* propagate to outer header */
				setdf = ip->ip_off;
#ifndef __FreeBSD__
		/* On FreeBSD, ip_off and ip_len assumed in host endian. */
				setdf = ntohs(setdf);
#endif
				setdf = htons(setdf & IP_DF);
				break;
			}
		} else {
			ip = NULL;		/* keep compiler happy */
			setdf = 0;
		}
		/* Do the appropriate encapsulation, if necessary */
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL || /* Tunnel requ'd */
		    dst->sa.sa_family != AF_INET ||	    /* PF mismatch */
#if 0
		    (sav->flags & SADB_X_SAFLAGS_TUNNEL) || /* Tunnel requ'd */
		    sav->tdb_xform->xf_type == XF_IP4 ||    /* ditto */
#endif
		    (dst->sa.sa_family == AF_INET &&	    /* Proxy */
		     dst->sin.sin_addr.s_addr != INADDR_ANY &&
		     dst->sin.sin_addr.s_addr != ip->ip_dst.s_addr)) {
			struct mbuf *mp;

			/* Fix IPv4 header checksum and length */
			if (m->m_len < sizeof (struct ip) &&
			    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
				error = ENOBUFS;
				goto bad;
			}
			ip = mtod(m, struct ip *);
			ip->ip_len = htons(m->m_pkthdr.len);
			ip->ip_sum = 0;
#ifdef _IP_VHL
			if (ip->ip_vhl == IP_VHL_BORING)
				ip->ip_sum = in_cksum_hdr(ip);
			else
				ip->ip_sum = in_cksum(m,
					_IP_VHL_HL(ip->ip_vhl) << 2);
#else
			ip->ip_sum = in_cksum(m, ip->ip_hl << 2);
#endif

			/* Encapsulate the packet */
			error = ipip_output(m, isr, &mp, 0, 0);
			if (mp == NULL && !error) {
				/* Should never happen. */
				DPRINTF(("ipsec4_process_packet: ipip_output "
					"returns no mbuf and no error!"));
				error = EFAULT;
			}
			if (error) {
				if (mp) {
					/* XXX: Should never happen! */
					m_freem(mp);
				}
				m = NULL; /* ipip_output() already freed it */
				goto bad;
			}
			m = mp, mp = NULL;
			/*
			 * ipip_output clears IP_DF in the new header.  If
			 * we need to propagate IP_DF from the outer header,
			 * then we have to do it here.
			 *
			 * XXX shouldn't assume what ipip_output does.
			 */
			if (dst->sa.sa_family == AF_INET && setdf) {
				if (m->m_len < sizeof (struct ip) &&
				    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
					error = ENOBUFS;
					goto bad;
				}
				ip = mtod(m, struct ip *);
				ip->ip_off |= IP_OFF_CONVERT(IP_DF);
			}
		}
	}

	/*
	 * Dispatch to the appropriate IPsec transform logic.  The
	 * packet will be returned for transmission after crypto
	 * processing, etc. are completed.  For encapsulation we
	 * bypass this call because of the explicit call done above
	 * (necessary to deal with IP_DF handling for IPv4).
	 *
	 * NB: m & sav are ``passed to caller'' who's reponsible for
	 *     for reclaiming their resources.
	 */
	if (sav->tdb_xform->xf_type != XF_IP4) {
		union sockaddr_union *dst = &sav->sah->saidx.dst;
		if (dst->sa.sa_family == AF_INET) {
			ip = mtod(m, struct ip *);
			i = ip->ip_hl << 2;
			off = offsetof(struct ip, ip_p);
		} else {
			i = sizeof(struct ip6_hdr);
			off = offsetof(struct ip6_hdr, ip6_nxt);
		}
		error = (*sav->tdb_xform->xf_output)(m, isr, NULL, i, off);
	} else {
		error = ipsec_process_done(m, isr);
	}
	splx(s);
	return error;
bad:
	splx(s);
	if (m)
		m_freem(m);
	return error;
}
#endif

#ifdef INET6
static int
compute_ipsec_pos(struct mbuf *m, int *i, int *off)
{
	int nxt;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr*);
	struct ip6_ext ip6e;
	int dstopt = 0;

	*i = sizeof(struct ip6_hdr);
	*off = offsetof(struct ip6_hdr, ip6_nxt);
	nxt = ip6->ip6_nxt;

	/*
	 * chase mbuf chain to find the appropriate place to
	 * put AH/ESP/IPcomp header.
	 *  IPv6 hbh dest1 rthdr ah* [esp* dest2 payload]
	 */
	while (1) {
		switch (nxt) {
		case IPPROTO_AH:
		case IPPROTO_ESP:
		case IPPROTO_IPCOMP:
			/*
			* we should not skip security header added
			* beforehand.
			*/
			return 0;

		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
			if (*i + sizeof(ip6e) > m->m_pkthdr.len) {
				return EINVAL;
			}

			/*
			* if we see 2nd destination option header,
			* we should stop there.
			*/
			if (nxt == IPPROTO_DSTOPTS && dstopt)
				return 0;

			if (nxt == IPPROTO_DSTOPTS) {
				/*
				 * Seen 1st or 2nd destination option.
				 * next time we see one, it must be 2nd.
				 */
				dstopt = 1;
			} else if (nxt == IPPROTO_ROUTING) {
				/*
				 * If we see destination option next
				 * time, it must be dest2.
				 */
				dstopt = 2;
			}

			/* skip this header */
			m_copydata(m, *i, sizeof(ip6e), &ip6e);
			nxt = ip6e.ip6e_nxt;
			*off = *i + offsetof(struct ip6_ext, ip6e_nxt);
			*i += (ip6e.ip6e_len + 1) << 3;
			if (*i > m->m_pkthdr.len) {
					return EINVAL;
			}
			break;
		default:
			return 0;
		}
	}

	return 0;
}

static int
in6_sa_equal_addrwithscope(const struct sockaddr_in6 *sa, const struct in6_addr *ia)
{
	struct in6_addr ia2;

	memcpy(&ia2, &sa->sin6_addr, sizeof(ia2));
	if (IN6_IS_SCOPE_LINKLOCAL(&sa->sin6_addr))
		ia2.s6_addr16[1] = htons(sa->sin6_scope_id);

	return IN6_ARE_ADDR_EQUAL(ia, &ia2);
}

int
ipsec6_process_packet(
	struct mbuf *m,
 	struct ipsecrequest *isr
    )
{
	struct secasindex saidx;
	struct secasvar *sav;
	struct ip6_hdr *ip6;
	int s, error, i, off;
	union sockaddr_union *dst;

	IPSEC_ASSERT(m != NULL, ("ipsec6_process_packet: null mbuf"));
	IPSEC_ASSERT(isr != NULL, ("ipsec6_process_packet: null isr"));

	s = splsoftnet();   /* insure SA contents don't change */
	isr = ipsec_nextisr(m, isr, AF_INET6, &saidx, &error);
	if (isr == NULL) {
		// XXX Should we send a notification ?
		goto bad;
	}

	sav = isr->sav;
	dst = &sav->sah->saidx.dst;

	ip6 = mtod(m, struct ip6_hdr *); /* XXX */

	/* Do the appropriate encapsulation, if necessary */
	if (isr->saidx.mode == IPSEC_MODE_TUNNEL || /* Tunnel requ'd */
	    dst->sa.sa_family != AF_INET6 ||        /* PF mismatch */
	    ((dst->sa.sa_family == AF_INET6) &&
	     (!IN6_IS_ADDR_UNSPECIFIED(&dst->sin6.sin6_addr)) &&
	     (!in6_sa_equal_addrwithscope(&dst->sin6,
				  &ip6->ip6_dst)))) {
		struct mbuf *mp;

		/* Fix IPv6 header payload length. */
		if (m->m_len < sizeof(struct ip6_hdr))
			if ((m = m_pullup(m,sizeof(struct ip6_hdr))) == NULL)
				return ENOBUFS;

		if (m->m_pkthdr.len - sizeof(*ip6) > IPV6_MAXPACKET) {
			/* No jumbogram support. */
			m_freem(m);
			return ENXIO;   /*XXX*/
		}

		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(*ip6));

		/* Encapsulate the packet */
		error = ipip_output(m, isr, &mp, 0, 0);
		if (mp == NULL && !error) {
			/* Should never happen. */
			DPRINTF(("ipsec6_process_packet: ipip_output "
				 "returns no mbuf and no error!"));
			error = EFAULT;
		}

		if (error) {
			if (mp) {
				/* XXX: Should never happen! */
				m_freem(mp);
			}
			m = NULL; /* ipip_output() already freed it */
			goto bad;
		}

		m = mp;
		mp = NULL;
	}

	if (dst->sa.sa_family == AF_INET) {
		struct ip *ip;
		ip = mtod(m, struct ip *);
		i = ip->ip_hl << 2;
		off = offsetof(struct ip, ip_p);
	} else {	
		error = compute_ipsec_pos(m, &i, &off);
		if (error)
			goto bad;
	}
	error = (*sav->tdb_xform->xf_output)(m, isr, NULL, i, off);
	splx(s);
	return error;
bad:
	splx(s);
	if (m)
		m_freem(m);
	return error;
}
#endif /*INET6*/

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netipsec/ipsec_output.c $ $Rev: 881594 $")
#endif
