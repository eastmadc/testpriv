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



/*	$NetBSD: ip_gre.c,v 1.44 2006/11/16 22:54:14 dyoung Exp $ */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Heiko W.Rupp <hwr@pilhuhn.de>
 *
 * IPv6-over-GRE contributed by Gert Doering <gert@greenie.muc.de>
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
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
 * deencapsulate tunneled packets and send them on
 * output half is in net/if_gre.[ch]
 * This currently handles IPPROTO_GRE, IPPROTO_MOBILE
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ip_gre.c,v 1.44 2006/11/16 22:54:14 dyoung Exp $");

#include "gre.h"
#if NGRE > 0

#include "opt_inet.h"
#include "opt_atalk.h"
#include "bpfilter.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <net/bpf.h>
#include <net/ethertypes.h>
#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/raw_cb.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_gre.h>
#else
#error ip_gre input without IP?
#endif


#ifdef NETATALK
#include <netatalk/at.h>
#include <netatalk/at_var.h>
#include <netatalk/at_extern.h>
#endif

/* Needs IP headers. */
#include <net/if_gre.h>

#include <machine/stdarg.h>

#if 1
void gre_inet_ntoa(struct in_addr in); 	/* XXX */
#endif

struct gre_softc *gre_lookup(struct mbuf *, u_int8_t);

int gre_input2(struct mbuf *, int, u_char);

/*
 * De-encapsulate a packet and feed it back through ip input (this
 * routine is called whenever IP gets a packet with proto type
 * IPPROTO_GRE and a local destination address).
 * This really is simple
 */
void
gre_input(struct mbuf *m, ...)
{
	int off, ret, proto;
	va_list ap;

	va_start(ap, m);
	off = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	ret = gre_input2(m, off, proto);
	/*
	 * ret == 0 : packet not processed, meaning that
	 * no matching tunnel that is up is found.
	 * we inject it to raw ip socket to see if anyone picks it up.
	 */
	if (ret == 0)
		rip_input(m, off, proto);
}

/*
 * decapsulate.
 * Does the real work and is called from gre_input() (above)
 * returns 0 if packet is not yet processed
 * and 1 if it needs no further processing
 * proto is the protocol number of the "calling" foo_input()
 * routine.
 */
int
gre_input2(struct mbuf *m, int hlen, u_char proto)
{
	const struct greip *gip;
	struct gre_softc *sc;

	if ((sc = gre_lookup(m, proto)) == NULL) {
		/* No matching tunnel or tunnel is down. */
		return 0;
	}

	if (m->m_len < sizeof(*gip)) {
		m = m_pullup(m, sizeof(*gip));
		if (m == NULL)
			return ENOBUFS;
	}
	gip = mtod(m, const struct greip *);

	return gre_input3(sc, m, hlen, proto, &gip->gi_g);
}

/*
 * input routine for IPPRPOTO_MOBILE
 * This is a little bit different from the other modes, as the
 * encapsulating header was not prepended, but instead inserted
 * between IP header and payload
 */
void
gre_mobile_input(struct mbuf *m, ...)
{
	struct ip *ip;
	struct mobip_h *mip;
	struct ifqueue *ifq;
	struct gre_softc *sc;
#ifndef __QNXNTO__
	uint8_t *hdr;
#endif
	int hlen, s;
	va_list ap;
	int msiz;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	struct nw_stk_ctl *sctlp;

	wtp = WTP;
	sctlp = &stk_ctl;
#endif

	va_start(ap, m);
	hlen = va_arg(ap, int);
	va_end(ap);

	if ((sc = gre_lookup(m, IPPROTO_MOBILE)) == NULL) {
		/* No matching tunnel or tunnel is down. */
		m_freem(m);
		return;
	}

	if (M_UNWRITABLE(m, sizeof(*mip))) {
		m = m_pullup(m, sizeof(*mip));
		if (m == NULL)
			return;
	}
	ip = mtod(m, struct ip *);
	/* XXX what if there are IP options? */
	mip = mtod(m, struct mobip_h *);

	sc->sc_if.if_ipackets++;
	sc->sc_if.if_ibytes += m->m_pkthdr.len;

	if (ntohs(mip->mh.proto) & MOB_H_SBIT) {
		msiz = MOB_H_SIZ_L;
		mip->mi.ip_src.s_addr = mip->mh.osrc;
	} else
		msiz = MOB_H_SIZ_S;

	if (M_UNWRITABLE(m, hlen + msiz)) {
		m = m_pullup(m, hlen + msiz);
		if (m == NULL)
			return;
		ip = mtod(m, struct ip *);
		mip = mtod(m, struct mobip_h *);
	}

	mip->mi.ip_dst.s_addr = mip->mh.odst;
	mip->mi.ip_p = (ntohs(mip->mh.proto) >> 8);

	if (gre_in_cksum((u_int16_t *)&mip->mh, msiz) != 0) {
		m_freem(m);
		return;
	}

#ifndef __QNXNTO__
	hdr = mtod(m, uint8_t *);
	memmove(hdr + hlen, hdr + hlen + msiz, m->m_len - msiz - hlen);
#else
	/*
	 * Rather than potentially move a lot of bytes down,
	 * we'll move the ip header up.
	 */
	memmove(m->m_data + msiz, ip, hlen);
	m->m_data += msiz;
	ip = mtod(m, struct ip *);
#endif
	m->m_len -= msiz;
	ip->ip_len = htons(ntohs(ip->ip_len) - msiz);
	m->m_pkthdr.len -= msiz;

	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(m, hlen);

#if NBPFILTER > 0
	if (sc->sc_if.if_bpf != NULL)
		bpf_mtap_af(sc->sc_if.if_bpf, AF_INET, m);
#endif /*NBPFILTER > 0*/

	ifq = &ipintrq;
	s = splnet();       /* possible */
#ifndef __QNXNTO__
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		m_freem(m);
	} else
		IF_ENQUEUE(ifq, m);
#else
	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		m_freem(m);
	} else {
		IF_ENQUEUE(ifq, m);

		if (ifq->ifq_len == 1) {
			if (sctlp->pkt_rx_q == NULL) {
				sctlp->pkt_rx_q = ifq;
			}
			else {
				/* make this new one the tail */
				ifq->ifq_next = sctlp->pkt_rx_q;
				ifq->ifq_prev = sctlp->pkt_rx_q->ifq_prev;
				*sctlp->pkt_rx_q->ifq_prev = ifq;
				sctlp->pkt_rx_q->ifq_prev  = &ifq->ifq_next;
			}
		}
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}
#endif
	splx(s);
}

/*
 * Find the gre interface associated with our src/dst/proto set.
 */
struct gre_softc *
gre_lookup(struct mbuf *m, u_int8_t proto)
{
	const struct ip *ip = mtod(m, const struct ip *);
	struct gre_softc *sc;

	LIST_FOREACH(sc, &gre_softc_list, sc_list) {
		if (sc->g_dst.s_addr == ip->ip_src.s_addr &&
		    sc->g_src.s_addr == ip->ip_dst.s_addr &&
		    sc->sc_proto == proto &&
		    (sc->sc_if.if_flags & IFF_UP) != 0)
			return sc;
	}

	return NULL;
}

#endif /* if NGRE > 0 */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/ip_gre.c $ $Rev: 680336 $")
#endif
