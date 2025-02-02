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

/* $NetBSD: if_pppoe.c,v 1.76.2.1 2007/09/11 09:19:17 xtraeme Exp $ */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_pppoe.c,v 1.76.2.1 2007/09/11 09:19:17 xtraeme Exp $");

#include "pppoe.h"
#include "bpfilter.h"
#include "opt_pfil_hooks.h"
#include "opt_pppoe.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/ioctl.h>
#include <sys/kauth.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_ether.h>
#include <net/if_sppp.h>
#include <net/if_spppvar.h>
#include <net/if_pppoe.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#ifndef __QNXNTO__
#include <machine/intr.h>
#endif

#ifdef __QNXNTO__
#include <net/netbyte.h>
#endif

#undef PPPOE_DEBUG		/* XXX - remove this or make it an option */
/* #define PPPOE_DEBUG 1 */

struct pppoehdr {
	u_int8_t vertype;
	u_int8_t code;
	u_int16_t session;
	u_int16_t plen;
} __attribute__((__packed__));

struct pppoetag {
	u_int16_t tag;
	u_int16_t len;
} __attribute__((__packed__));

#define PPPOE_HEADERLEN	sizeof(struct pppoehdr)
#define	PPPOE_OVERHEAD	(PPPOE_HEADERLEN + 2)
#define	PPPOE_VERTYPE	0x11	/* VER=1, TYPE = 1 */

#define	PPPOE_TAG_EOL		0x0000		/* end of list */
#define	PPPOE_TAG_SNAME		0x0101		/* service name */
#define	PPPOE_TAG_ACNAME	0x0102		/* access concentrator name */
#define	PPPOE_TAG_HUNIQUE	0x0103		/* host unique */
#define	PPPOE_TAG_ACCOOKIE	0x0104		/* AC cookie */
#define	PPPOE_TAG_VENDOR	0x0105		/* vendor specific */
#define	PPPOE_TAG_RELAYSID	0x0110		/* relay session id */
#define	PPPOE_TAG_SNAME_ERR	0x0201		/* service name error */
#define	PPPOE_TAG_ACSYS_ERR	0x0202		/* AC system error */
#define	PPPOE_TAG_GENERIC_ERR	0x0203		/* gerneric error */

#define PPPOE_CODE_PADI		0x09		/* Active Discovery Initiation */
#define	PPPOE_CODE_PADO		0x07		/* Active Discovery Offer */
#define	PPPOE_CODE_PADR		0x19		/* Active Discovery Request */
#define	PPPOE_CODE_PADS		0x65		/* Active Discovery Session confirmation */
#define	PPPOE_CODE_PADT		0xA7		/* Active Discovery Terminate */

/* two byte PPP protocol discriminator, then IP data */
#define	PPPOE_MAXMTU	(ETHERMTU - PPPOE_OVERHEAD)

/* Add a 16 bit unsigned value to a buffer pointed to by PTR */
#define	PPPOE_ADD_16(PTR, VAL)			\
		*(PTR)++ = (VAL) / 256;		\
		*(PTR)++ = (VAL) % 256

/* Add a complete PPPoE header to the buffer pointed to by PTR */
#define PPPOE_ADD_HEADER(PTR, CODE, SESS, LEN)	\
		*(PTR)++ = PPPOE_VERTYPE;	\
		*(PTR)++ = (CODE);		\
		PPPOE_ADD_16(PTR, SESS);	\
		PPPOE_ADD_16(PTR, LEN)

#define	PPPOE_DISC_TIMEOUT	(hz*5)	/* base for quick timeout calculation */
#define	PPPOE_SLOW_RETRY	(hz*60)	/* persistent retry interval */
#define PPPOE_DISC_MAXPADI	4	/* retry PADI four times (quickly) */
#define	PPPOE_DISC_MAXPADR	2	/* retry PADR twice */

#ifdef PPPOE_SERVER
/* from if_spppsubr.c */
#define IFF_PASSIVE	IFF_LINK0	/* wait passively for connection */
#endif

struct pppoe_softc {
	struct sppp sc_sppp;		/* contains a struct ifnet as first element */
	LIST_ENTRY(pppoe_softc) sc_list;
	struct ifnet *sc_eth_if;	/* ethernet interface we are using */

	int sc_state;			/* discovery phase or session connected */
	struct ether_addr sc_dest;	/* hardware address of concentrator */
	u_int16_t sc_session;		/* PPPoE session id */

	char *sc_service_name;		/* if != NULL: requested name of service */
	char *sc_concentrator_name;	/* if != NULL: requested concentrator id */
	u_int8_t *sc_ac_cookie;		/* content of AC cookie we must echo back */
	size_t sc_ac_cookie_len;	/* length of cookie data */
#ifdef PPPOE_SERVER
	u_int8_t *sc_hunique;		/* content of host unique we must echo back */
	size_t sc_hunique_len;		/* length of host unique */
#endif
	struct callout sc_timeout;	/* timeout while not in session state */
	int sc_padi_retried;		/* number of PADI retries already done */
	int sc_padr_retried;		/* number of PADR retries already done */
};

/* incoming traffic will be queued here */
struct ifqueue ppoediscinq = { .ifq_maxlen = IFQ_MAXLEN };
struct ifqueue ppoeinq = { .ifq_maxlen = IFQ_MAXLEN };

#ifndef __QNXNTO__
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
void * pppoe_softintr = NULL;
static void pppoe_softintr_handler(void *);
#else
struct callout pppoe_softintr = CALLOUT_INITIALIZER;
void pppoe_softintr_handler(void *);
#endif
#endif

extern int sppp_ioctl(struct ifnet *, unsigned long, void *);

/* input routines */
#ifndef __QNXNTO__
static void pppoe_input(void);
#endif
static void pppoe_disc_input(void *);
static void pppoe_dispatch_disc_pkt(struct mbuf *, int);
static void pppoe_data_input(void *);

/* management routines */
void pppoeattach(int);
static int pppoe_connect(struct pppoe_softc *);
static int pppoe_disconnect(struct pppoe_softc *);
static void pppoe_abort_connect(struct pppoe_softc *);
static int pppoe_ioctl(struct ifnet *, unsigned long, caddr_t);
static void pppoe_tls(struct sppp *);
static void pppoe_tlf(struct sppp *);
static void pppoe_start(struct ifnet *);
static void pppoe_clear_softc(struct pppoe_softc *, const char *);

/* internal timeout handling */
static void pppoe_timeout(void *);

/* sending actual protocol controll packets */
static int pppoe_send_padi(struct pppoe_softc *);
static int pppoe_send_padr(struct pppoe_softc *);
#ifdef PPPOE_SERVER
static int pppoe_send_pado(struct pppoe_softc *);
static int pppoe_send_pads(struct pppoe_softc *);
#endif
static int pppoe_send_padt(struct ifnet *, u_int, const u_int8_t *);

/* raw output */
static int pppoe_output(struct pppoe_softc *, struct mbuf *);

/* internal helper functions */
static struct pppoe_softc * pppoe_find_softc_by_session(u_int, struct ifnet *);
static struct pppoe_softc * pppoe_find_softc_by_hunique(u_int8_t *, size_t, struct ifnet *);
static struct mbuf *pppoe_get_mbuf(size_t len);

#ifdef PFIL_HOOKS
#ifndef QNX_MFIB
static int pppoe_ifattach_hook(void *, struct mbuf **, struct ifnet *, int);
#else
static int pppoe_ifattach_hook(void *, struct mbuf **, struct ifnet *, int, int);
#endif
#endif

static LIST_HEAD(pppoe_softc_head, pppoe_softc) pppoe_softc_list;

static int	pppoe_clone_create(struct if_clone *, int);
static int	pppoe_clone_destroy(struct ifnet *);

static struct if_clone pppoe_cloner =
    IF_CLONE_INITIALIZER("pppoe", pppoe_clone_create, pppoe_clone_destroy);

/* ARGSUSED */
#ifdef __QNXNTO__
struct timeval boottime;
#endif
void
pppoeattach(int count)
{
	LIST_INIT(&pppoe_softc_list);
	if_clone_attach(&pppoe_cloner);

#ifndef __QNXNTO__
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	pppoe_softintr = softintr_establish(IPL_SOFTNET, pppoe_softintr_handler, NULL);
#endif
#else
	boottime.tv_sec = time(NULL);

	ppoediscinq.ifq_intr = pppoe_disc_input;
	ppoediscinq.ifq_next = &ppoediscinq;
	ppoediscinq.ifq_prev = &ppoediscinq.ifq_next;

	ppoeinq.ifq_intr = pppoe_data_input;
	ppoeinq.ifq_next = &ppoeinq;
	ppoeinq.ifq_prev = &ppoeinq.ifq_next;
#endif
}

static int
pppoe_clone_create(struct if_clone *ifc, int unit)
{
	struct pppoe_softc *sc;

	sc = malloc(sizeof(struct pppoe_softc), M_DEVBUF, M_WAITOK);
	memset(sc, 0, sizeof(struct pppoe_softc));

	snprintf(sc->sc_sppp.pp_if.if_xname, sizeof(sc->sc_sppp.pp_if.if_xname),
	    "pppoe%d", unit);
	sc->sc_sppp.pp_if.if_softc = sc;
	sc->sc_sppp.pp_if.if_mtu = PPPOE_MAXMTU;
	sc->sc_sppp.pp_if.if_flags = IFF_SIMPLEX|IFF_POINTOPOINT|IFF_MULTICAST;
	sc->sc_sppp.pp_if.if_type = IFT_PPP;
	sc->sc_sppp.pp_if.if_hdrlen = sizeof(struct ether_header) + PPPOE_HEADERLEN;
	sc->sc_sppp.pp_if.if_dlt = DLT_PPP_ETHER;
	sc->sc_sppp.pp_flags |= PP_KEEPALIVE |	/* use LCP keepalive */
				PP_NOFRAMING;	/* no serial encapsulation */
	sc->sc_sppp.pp_if.if_ioctl = pppoe_ioctl;
	IFQ_SET_MAXLEN(&sc->sc_sppp.pp_if.if_snd, IFQ_MAXLEN);
	IFQ_SET_READY(&sc->sc_sppp.pp_if.if_snd);

	/* changed to real address later */
	memcpy(&sc->sc_dest, etherbroadcastaddr, sizeof(sc->sc_dest));

	callout_init(&sc->sc_timeout);

	sc->sc_sppp.pp_if.if_start = pppoe_start;
	sc->sc_sppp.pp_tls = pppoe_tls;
	sc->sc_sppp.pp_tlf = pppoe_tlf;
	sc->sc_sppp.pp_framebytes = PPPOE_HEADERLEN;	/* framing added to ppp packets */

	if_attach(&sc->sc_sppp.pp_if);
	sppp_attach(&sc->sc_sppp.pp_if);

#if NBPFILTER > 0
	bpfattach(&sc->sc_sppp.pp_if, DLT_PPP_ETHER, 0);
#endif
#ifdef PFIL_HOOKS
	if (LIST_EMPTY(&pppoe_softc_list))
		pfil_add_hook(pppoe_ifattach_hook, NULL,
		    PFIL_IFNET|PFIL_WAITOK, &if_pfil);
#endif
	LIST_INSERT_HEAD(&pppoe_softc_list, sc, sc_list);
	return 0;
}

static int
pppoe_clone_destroy(struct ifnet *ifp)
{
	struct pppoe_softc * sc = ifp->if_softc;

	callout_stop(&sc->sc_timeout);
	LIST_REMOVE(sc, sc_list);
#ifdef PFIL_HOOKS
	if (LIST_EMPTY(&pppoe_softc_list))
		pfil_remove_hook(pppoe_ifattach_hook, NULL,
		    PFIL_IFNET|PFIL_WAITOK, &if_pfil);
#endif
#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	sppp_detach(&sc->sc_sppp.pp_if);
	if_detach(ifp);
	if (sc->sc_concentrator_name)
		free(sc->sc_concentrator_name, M_DEVBUF);
	if (sc->sc_service_name)
		free(sc->sc_service_name, M_DEVBUF);
	if (sc->sc_ac_cookie)
		free(sc->sc_ac_cookie, M_DEVBUF);
	free(sc, M_DEVBUF);

	return (0);
}

/*
 * Find the interface handling the specified session.
 * Note: O(number of sessions open), this is a client-side only, mean
 * and lean implementation, so number of open sessions typically should
 * be 1.
 */
static struct pppoe_softc *
pppoe_find_softc_by_session(u_int session, struct ifnet *rcvif)
{
	struct pppoe_softc *sc;

	if (session == 0)
		return NULL;

	LIST_FOREACH(sc, &pppoe_softc_list, sc_list) {
		if (sc->sc_state == PPPOE_STATE_SESSION
		    && sc->sc_session == session) {
			if (sc->sc_eth_if == rcvif)
				return sc;
			else
				return NULL;
		}
	}
	return NULL;
}

/* Check host unique token passed and return appropriate softc pointer,
 * or NULL if token is bogus. */
static struct pppoe_softc *
pppoe_find_softc_by_hunique(u_int8_t *token, size_t len, struct ifnet *rcvif)
{
	struct pppoe_softc *sc, *t;

	if (LIST_EMPTY(&pppoe_softc_list))
		return NULL;

	if (len != sizeof sc)
		return NULL;
	memcpy(&t, token, len);

	LIST_FOREACH(sc, &pppoe_softc_list, sc_list)
		if (sc == t) break;

	if (sc == NULL) {
#ifdef PPPOE_DEBUG
		printf("pppoe: alien host unique tag, no session found\n");
#endif
		return NULL;
	}

	/* should be safe to access *sc now */
	if (sc->sc_state < PPPOE_STATE_PADI_SENT || sc->sc_state >= PPPOE_STATE_SESSION) {
		printf("%s: host unique tag found, but it belongs to a connection in state %d\n",
			sc->sc_sppp.pp_if.if_xname, sc->sc_state);
		return NULL;
	}
	if (sc->sc_eth_if != rcvif) {
		printf("%s: wrong interface, not accepting host unique\n",
			sc->sc_sppp.pp_if.if_xname);
		return NULL;
	}
	return sc;
}

#ifndef __QNXNTO__
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
static void
pppoe_softintr_handler(void *dummy)
{
	/* called at splsoftnet() */
	pppoe_input();
}
#else
void
pppoe_softintr_handler(void *dummy)
{
	int s = splnet();
	pppoe_input();
	splx(s);
}
#endif

/* called at appropriate protection level */
static void
pppoe_input(void)
{
	struct mbuf *m;
	int s, disc_done, data_done;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
	struct nw_stk_ctl *sctlp = &stk_ctl;
#endif

	do {
		disc_done = 0;
		data_done = 0;
		for (;;) {
			s = splnet();
			NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			IF_DEQUEUE(&ppoediscinq, m);
			splx(s);
			if (m == NULL) break;
			disc_done = 1;
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			pppoe_disc_input(m);
		}

		for (;;) {
			s = splnet();
			IF_DEQUEUE(&ppoeinq, m);
			splx(s);
			if (m == NULL) break;
			data_done = 1;
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			pppoe_data_input(m);
			NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		}
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	} while (disc_done || data_done);
}
#endif

/* analyze and handle a single received packet while not in session state */
static void
pppoe_dispatch_disc_pkt(struct mbuf *m, int off)
{
	u_int16_t tag, len;
	u_int16_t session, plen;
	struct pppoe_softc *sc;
	const char *err_msg, *devname;
	char *error;
	u_int8_t *ac_cookie;
	size_t ac_cookie_len;
#ifdef PPPOE_SERVER
	u_int8_t *hunique;
	size_t hunique_len;
#endif
	struct pppoehdr *ph;
	struct pppoetag *pt;
	struct mbuf *n;
	int noff, err, errortag;
	struct ether_header *eh;

	devname = "pppoe";	/* as long as we don't know which instance */
	err_msg = NULL;
	errortag = 0;
	if (m->m_len < sizeof(*eh)) {
		m = m_pullup(m, sizeof(*eh));
		if (!m)
			goto done;
	}
	eh = mtod(m, struct ether_header *);
	off += sizeof(*eh);

	ac_cookie = NULL;
	ac_cookie_len = 0;
#ifdef PPPOE_SERVER
	hunique = NULL;
	hunique_len = 0;
#endif
	session = 0;
	if (m->m_pkthdr.len - off <= PPPOE_HEADERLEN) {
		printf("pppoe: packet too short: %d\n", m->m_pkthdr.len);
		goto done;
	}

	n = m_pulldown(m, off, sizeof(*ph), &noff);
	if (!n) {
		printf("pppoe: could not get PPPoE header\n");
		m = NULL;
		goto done;
	}
	ph = (struct pppoehdr *)(mtod(n, caddr_t) + noff);
	if (ph->vertype != PPPOE_VERTYPE) {
		printf("pppoe: unknown version/type packet: 0x%x\n",
		    ph->vertype);
		goto done;
	}
	session = ntohs(ph->session);
	plen = ntohs(ph->plen);
	off += sizeof(*ph);

	if (plen + off > m->m_pkthdr.len) {
		printf("pppoe: packet content does not fit: data available = %d, packet size = %u\n",
		    m->m_pkthdr.len - off, plen);
		goto done;
	}
	m_adj(m, off + plen - m->m_pkthdr.len);	/* ignore trailing garbage */
	tag = 0;
	len = 0;
	sc = NULL;
	while (off + sizeof(*pt) <= m->m_pkthdr.len) {
		n = m_pulldown(m, off, sizeof(*pt), &noff);
		if (!n) {
			printf("%s: parse error\n", devname);
			m = NULL;
			goto done;
		}
		pt = (struct pppoetag *)(mtod(n, caddr_t) + noff);
		tag = ntohs(pt->tag);
		len = ntohs(pt->len);
		if (off + len > m->m_pkthdr.len) {
			printf("pppoe: tag 0x%x len 0x%x is too long\n",
			    tag, len);
			goto done;
		}
		switch (tag) {
		case PPPOE_TAG_EOL:
			goto breakbreak;
		case PPPOE_TAG_SNAME:
			break;	/* ignored */
		case PPPOE_TAG_ACNAME:
			error = NULL;
			if (sc != NULL && len > 0) {
				error = malloc(len+1, M_TEMP, M_NOWAIT);
				if (error) {
					n = m_pulldown(m, off + sizeof(*pt),
					    len, &noff);
					if (n) {
						strncpy(error,
						    mtod(n, caddr_t) + noff,
						    len);
						error[len] = '\0';
					}
					printf("%s: connected to %s\n",
					    devname, error);
					free(error, M_TEMP);
				}
			}
			break;	/* ignored */
		case PPPOE_TAG_HUNIQUE:
			if (sc != NULL)
				break;
			n = m_pulldown(m, off + sizeof(*pt), len, &noff);
			if (!n) {
				m = NULL;
				err_msg = "TAG HUNIQUE ERROR";
				break;
			}
#ifdef PPPOE_SERVER
			hunique = mtod(n, caddr_t) + noff;
			hunique_len = len;
#endif
			sc = pppoe_find_softc_by_hunique(mtod(n, caddr_t) + noff,
			    len, m->m_pkthdr.rcvif);
			if (sc != NULL)
				devname = sc->sc_sppp.pp_if.if_xname;
			break;
		case PPPOE_TAG_ACCOOKIE:
			if (ac_cookie == NULL) {
				n = m_pulldown(m, off + sizeof(*pt), len,
				    &noff);
				if (!n) {
					err_msg = "TAG ACCOOKIE ERROR";
					m = NULL;
					break;
				}
				ac_cookie = mtod(n, caddr_t) + noff;
				ac_cookie_len = len;
			}
			break;
		case PPPOE_TAG_SNAME_ERR:
			err_msg = "SERVICE NAME ERROR";
			errortag = 1;
			break;
		case PPPOE_TAG_ACSYS_ERR:
			err_msg = "AC SYSTEM ERROR";
			errortag = 1;
			break;
		case PPPOE_TAG_GENERIC_ERR:
			err_msg = "GENERIC ERROR";
			errortag = 1;
			break;
		}
		if (err_msg) {
			error = NULL;
			if (errortag && len) {
				error = malloc(len+1, M_TEMP, M_NOWAIT);
				n = m_pulldown(m, off + sizeof(*pt), len,
				    &noff);
				if (n && error) {
					strncpy(error, 
					    mtod(n, caddr_t) + noff, len);
					error[len] = '\0';
				}
			}
			if (error) {
				printf("%s: %s: %s\n", devname,
				    err_msg, error);
				free(error, M_TEMP);
			} else
				printf("%s: %s\n", devname, err_msg);
			if (errortag)
				goto done;
		}
		off += sizeof(*pt) + len;
	}
breakbreak:;
	switch (ph->code) {
	case PPPOE_CODE_PADI:
#ifdef PPPOE_SERVER
		/*
		 * got service name, concentrator name, and/or host unique.
		 * ignore if we have no interfaces with IFF_PASSIVE|IFF_UP.
		 */
		if (LIST_EMPTY(&pppoe_softc_list))
			goto done;
		LIST_FOREACH(sc, &pppoe_softc_list, sc_list) {
			if (!(sc->sc_sppp.pp_if.if_flags & IFF_UP))
				continue;
			if (!(sc->sc_sppp.pp_if.if_flags & IFF_PASSIVE))
				continue;
			if (sc->sc_state == PPPOE_STATE_INITIAL)
				break;
		}
		if (sc == NULL) {
/*			printf("pppoe: free passive interface is not found\n");*/
			goto done;
		}
		if (hunique) {
			if (sc->sc_hunique)
				free(sc->sc_hunique, M_DEVBUF);
			sc->sc_hunique = malloc(hunique_len, M_DEVBUF,
			    M_DONTWAIT);
			if (sc->sc_hunique == NULL)
				goto done;
			sc->sc_hunique_len = hunique_len;
			memcpy(sc->sc_hunique, hunique, hunique_len);
		}
		memcpy(&sc->sc_dest, eh->ether_shost, sizeof sc->sc_dest);
		sc->sc_state = PPPOE_STATE_PADO_SENT;
		pppoe_send_pado(sc);
		break;
#endif /* PPPOE_SERVER */
	case PPPOE_CODE_PADR:
#ifdef PPPOE_SERVER
		/*
		 * get sc from ac_cookie if IFF_PASSIVE
		 */
		if (ac_cookie == NULL) {
			/* be quiet if there is not a single pppoe instance */
			printf("pppoe: received PADR but not includes ac_cookie\n");
			goto done;
		}
		sc = pppoe_find_softc_by_hunique(ac_cookie,
						 ac_cookie_len,
						 m->m_pkthdr.rcvif);
		if (sc == NULL) {
			/* be quiet if there is not a single pppoe instance */
			if (!LIST_EMPTY(&pppoe_softc_list))
				printf("pppoe: received PADR but could not find request for it\n");
			goto done;
		}
		if (sc->sc_state != PPPOE_STATE_PADO_SENT) {
			printf("%s: received unexpected PADR\n",
			    sc->sc_sppp.pp_if.if_xname);
			goto done;
		}
		if (hunique) {
			if (sc->sc_hunique)
				free(sc->sc_hunique, M_DEVBUF);
			sc->sc_hunique = malloc(hunique_len, M_DEVBUF,
			    M_DONTWAIT);
			if (sc->sc_hunique == NULL)
				goto done;
			sc->sc_hunique_len = hunique_len;
			memcpy(sc->sc_hunique, hunique, hunique_len);
		}
		pppoe_send_pads(sc);
		sc->sc_state = PPPOE_STATE_SESSION;
		sc->sc_sppp.pp_up(&sc->sc_sppp);
		break;
#else
		/* ignore, we are no access concentrator */
		goto done;
#endif /* PPPOE_SERVER */
	case PPPOE_CODE_PADO:
		if (sc == NULL) {
			/* be quiet if there is not a single pppoe instance */
			if (!LIST_EMPTY(&pppoe_softc_list))
				printf("pppoe: received PADO but could not find request for it\n");
			goto done;
		}
		if (sc->sc_state != PPPOE_STATE_PADI_SENT) {
			printf("%s: received unexpected PADO\n",
			    sc->sc_sppp.pp_if.if_xname);
			goto done;
		}
		if (ac_cookie) {
			if (sc->sc_ac_cookie)
				free(sc->sc_ac_cookie, M_DEVBUF);
			sc->sc_ac_cookie = malloc(ac_cookie_len, M_DEVBUF,
			    M_DONTWAIT);
			if (sc->sc_ac_cookie == NULL)
				goto done;
			sc->sc_ac_cookie_len = ac_cookie_len;
			memcpy(sc->sc_ac_cookie, ac_cookie, ac_cookie_len);
		}
		memcpy(&sc->sc_dest, eh->ether_shost, sizeof sc->sc_dest);
		callout_stop(&sc->sc_timeout);
		sc->sc_padr_retried = 0;
		sc->sc_state = PPPOE_STATE_PADR_SENT;
		if ((err = pppoe_send_padr(sc)) != 0) {
			if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
				printf("%s: failed to send PADR, "
				    "error=%d\n", sc->sc_sppp.pp_if.if_xname,
				    err);
		}
		callout_reset(&sc->sc_timeout,
		    PPPOE_DISC_TIMEOUT * (1 + sc->sc_padr_retried),
		    pppoe_timeout, sc);
		break;
	case PPPOE_CODE_PADS:
		if (sc == NULL)
			goto done;
		sc->sc_session = session;
		callout_stop(&sc->sc_timeout);
		if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
			printf("%s: session 0x%x connected\n",
			    sc->sc_sppp.pp_if.if_xname, session);
		sc->sc_state = PPPOE_STATE_SESSION;
		sc->sc_sppp.pp_up(&sc->sc_sppp);	/* notify upper layers */
		break;
	case PPPOE_CODE_PADT:
		if (sc == NULL)
			goto done;
		pppoe_clear_softc(sc, "received PADT");
		break;
	default:
		printf("%s: unknown code (0x%04x) session = 0x%04x\n",
		    sc? sc->sc_sppp.pp_if.if_xname : "pppoe",
		    ph->code, session);
		break;
	}

done:
	if (m)
		m_freem(m);
	return;
}

static void
pppoe_disc_input(void *arg)
{
	struct mbuf *m;

	m = arg;

	/* avoid error messages if there is not a single pppoe instance */
	if (!LIST_EMPTY(&pppoe_softc_list)) {
		KASSERT(m->m_flags & M_PKTHDR);
		pppoe_dispatch_disc_pkt(m, 0);
	} else
		m_freem(m);
}

static void
pppoe_data_input(void *arg)
{
	u_int16_t session, plen;
	struct pppoe_softc *sc;
	struct pppoehdr *ph;
#ifdef PPPOE_TERM_UNKNOWN_SESSIONS
	u_int8_t shost[ETHER_ADDR_LEN];
#endif
	struct mbuf *m;

	m = arg;

	KASSERT(m->m_flags & M_PKTHDR);

#ifdef PPPOE_TERM_UNKNOWN_SESSIONS
	memcpy(shost, mtod(m, struct ether_header*)->ether_shost, ETHER_ADDR_LEN);
#endif
	m_adj(m, sizeof(struct ether_header));
	if (m->m_pkthdr.len <= PPPOE_HEADERLEN) {
		printf("pppoe (data): dropping too short packet: %d bytes\n",
		    m->m_pkthdr.len);
		goto drop;
	}

	if (m->m_len < sizeof(*ph)) {
		m = m_pullup(m, sizeof(*ph));
		if (!m) {
			printf("pppoe: could not get PPPoE header\n");
			return;
		}
	}
	ph = mtod(m, struct pppoehdr *);

	if (ph->vertype != PPPOE_VERTYPE) {
		printf("pppoe (data): unknown version/type packet: 0x%x\n",
		    ph->vertype);
		goto drop;
	}
	if (ph->code != 0)
		goto drop;

	session = ntohs(ph->session);
	sc = pppoe_find_softc_by_session(session, m->m_pkthdr.rcvif);
	if (sc == NULL) {
#ifdef PPPOE_TERM_UNKNOWN_SESSIONS
		printf("pppoe: input for unknown session 0x%x, sending PADT\n",
		    session);
		pppoe_send_padt(m->m_pkthdr.rcvif, session, shost);
#endif
		goto drop;
	}

	plen = ntohs(ph->plen);

#if NBPFILTER > 0
	if(sc->sc_sppp.pp_if.if_bpf)
		bpf_mtap(sc->sc_sppp.pp_if.if_bpf, m);
#endif

	m_adj(m, PPPOE_HEADERLEN);

#ifdef PPPOE_DEBUG
	{
		struct mbuf *p;

		printf("%s: pkthdr.len=%d, pppoe.len=%d",
			sc->sc_sppp.pp_if.if_xname,
			m->m_pkthdr.len, plen);
		p = m;
		while (p) {
			printf(" l=%d", p->m_len);
			p = p->m_next;
		}
		printf("\n");
	}
#endif

	if (m->m_pkthdr.len < plen)
		goto drop;

	/* fix incoming interface pointer (not the raw ethernet interface anymore) */
	m->m_pkthdr.rcvif = &sc->sc_sppp.pp_if;

	/* pass packet up and account for it */
	sc->sc_sppp.pp_if.if_ipackets++;
	sppp_input(&sc->sc_sppp.pp_if, m);
	return;

drop:
	m_freem(m);
}

static int
pppoe_output(struct pppoe_softc *sc, struct mbuf *m)
{
	struct sockaddr dst;
	struct ether_header *eh;
	u_int16_t etype;

	if (sc->sc_eth_if == NULL) {
		m_freem(m);
		return EIO;
	}

	memset(&dst, 0, sizeof dst);
	dst.sa_family = AF_UNSPEC;
	eh = (struct ether_header*)&dst.sa_data;
	etype = sc->sc_state == PPPOE_STATE_SESSION ? ETHERTYPE_PPPOE : ETHERTYPE_PPPOEDISC;
	eh->ether_type = htons(etype);
	memcpy(&eh->ether_dhost, &sc->sc_dest, sizeof sc->sc_dest);

#ifdef PPPOE_DEBUG
	printf("%s (%x) state=%d, session=0x%x output -> %s, len=%d\n",
	    sc->sc_sppp.pp_if.if_xname, etype,
	    sc->sc_state, sc->sc_session,
	    ether_sprintf((const unsigned char *)&sc->sc_dest), m->m_pkthdr.len);
#endif

	m->m_flags &= ~(M_BCAST|M_MCAST);
	sc->sc_sppp.pp_if.if_opackets++;
	return sc->sc_eth_if->if_output(sc->sc_eth_if, m, &dst, NULL);
}

static int
pppoe_ioctl(struct ifnet *ifp, unsigned long cmd, caddr_t data)
{
	struct lwp *l = curlwp;	/* XXX */
	struct pppoe_softc *sc = (struct pppoe_softc*)ifp;
	int error = 0;

	switch (cmd) {
	case PPPOESETPARMS:
	{
		struct pppoediscparms *parms = (struct pppoediscparms*)data;
		if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_INTERFACE,
		    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp, (void *)cmd,
		    NULL) != 0)
			return (EPERM);
		if (parms->eth_ifname[0] != 0) {
			struct ifnet	*eth_if;

#ifndef QNX_MFIB
			eth_if = ifunit(parms->eth_ifname);
#else
			eth_if = ifunit(parms->eth_ifname, ANY_FIB); /* should fib be post-encap fib? */
#endif
			if (eth_if == NULL || eth_if->if_dlt != DLT_EN10MB) {
				sc->sc_eth_if = NULL;
				return ENXIO;
			}

			if (sc->sc_sppp.pp_if.if_mtu >
			    eth_if->if_mtu - PPPOE_OVERHEAD) {
				sc->sc_sppp.pp_if.if_mtu = eth_if->if_mtu -
				    PPPOE_OVERHEAD;
			}
			sc->sc_eth_if = eth_if;
		}
#ifdef __QNXNTO__
		parms->ac_name = parms->ac_name_len ? parms->qnx_acname : 0;
		parms->service_name = parms->service_name_len? parms->qnx_svname : 0;
#endif
		if (parms->ac_name != NULL) {
			size_t s;
			char *b = malloc(parms->ac_name_len + 1, M_DEVBUF,
			    M_WAITOK);
			if (b == NULL)
				return ENOMEM;
			error = copyinstr(parms->ac_name, b,
			    parms->ac_name_len+1, &s);
			if (error != 0) {
				free(b, M_DEVBUF);
				return error;
			}
			if (s != parms->ac_name_len+1) {
				free(b, M_DEVBUF);
				return EINVAL;
			}
			if (sc->sc_concentrator_name)
				free(sc->sc_concentrator_name, M_DEVBUF);
			sc->sc_concentrator_name = b;
		}
		if (parms->service_name != NULL) {
			size_t s;
			char *b = malloc(parms->service_name_len + 1, M_DEVBUF,
			    M_WAITOK);
			if (b == NULL)
				return ENOMEM;
			error = copyinstr(parms->service_name, b,
			    parms->service_name_len+1, &s);
			if (error != 0) {
				free(b, M_DEVBUF);
				return error;
			}
			if (s != parms->service_name_len+1) {
				free(b, M_DEVBUF);
				return EINVAL;
			}
			if (sc->sc_service_name)
				free(sc->sc_service_name, M_DEVBUF);
			sc->sc_service_name = b;
		}
		return 0;
	}
	break;
	case PPPOEGETPARMS:
	{
		struct pppoediscparms *parms = (struct pppoediscparms*)data;
		memset(parms, 0, sizeof *parms);
		if (sc->sc_eth_if)
			strncpy(parms->ifname, sc->sc_eth_if->if_xname, IFNAMSIZ);
		return 0;
	}
	break;
	case PPPOEGETSESSION:
	{
		struct pppoeconnectionstate *state = (struct pppoeconnectionstate*)data;
		state->state = sc->sc_state;
		state->session_id = sc->sc_session;
		state->padi_retry_no = sc->sc_padi_retried;
		state->padr_retry_no = sc->sc_padr_retried;
		return 0;
	}
	break;
	case SIOCSIFFLAGS:
	{
		struct ifreq *ifr = (struct ifreq*) data;
		/*
		 * Prevent running re-establishment timers overriding
		 * administrators choice.
		 */
		if ((ifr->ifr_flags & IFF_UP) == 0
		     && sc->sc_state >= PPPOE_STATE_PADI_SENT
		     && sc->sc_state < PPPOE_STATE_SESSION) {
			callout_stop(&sc->sc_timeout);
			sc->sc_state = PPPOE_STATE_INITIAL;
			sc->sc_padi_retried = 0;
			sc->sc_padr_retried = 0;
			memcpy(&sc->sc_dest, etherbroadcastaddr,
			    sizeof(sc->sc_dest));
		}
		return sppp_ioctl(ifp, cmd, data);
	}
	case SIOCSIFMTU:
	{
		struct ifreq *ifr = (struct ifreq *)data;

		if (ifr->ifr_mtu > (sc->sc_eth_if == NULL ?
		    PPPOE_MAXMTU : (sc->sc_eth_if->if_mtu - PPPOE_OVERHEAD))) {
			return EINVAL;
		}
		return sppp_ioctl(ifp, cmd, data);
	}
	default:
		return sppp_ioctl(ifp, cmd, data);
	}
	return 0;
}

/*
 * Allocate a mbuf/cluster with space to store the given data length
 * of payload, leaving space for prepending an ethernet header
 * in front.
 */
static struct mbuf *
pppoe_get_mbuf(size_t len)
{
	struct mbuf *m;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return NULL;
	if (len + sizeof(struct ether_header) > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			struct mbuf *n;
			MFREE(m, n);
			return 0;
		}
	}
	m->m_data += sizeof(struct ether_header);
	m->m_len = len;
	m->m_pkthdr.len = len;
	m->m_pkthdr.rcvif = NULL;

	return m;
}

static int
pppoe_send_padi(struct pppoe_softc *sc)
{
	struct mbuf *m0;
	int len, l1 = 0, l2 = 0; /* XXX: gcc */
	u_int8_t *p;

	if (sc->sc_state >PPPOE_STATE_PADI_SENT)
		panic("pppoe_send_padi in state %d", sc->sc_state);

	/* calculate length of frame (excluding ethernet header + pppoe header) */
	len = 2 + 2 + 2 + 2 + sizeof sc;	/* service name tag is required, host unique is send too */
	if (sc->sc_service_name != NULL) {
		l1 = strlen(sc->sc_service_name);
		len += l1;
	}
	if (sc->sc_concentrator_name != NULL) {
		l2 = strlen(sc->sc_concentrator_name);
		len += 2 + 2 + l2;
	}

	/* allocate a buffer */
	m0 = pppoe_get_mbuf(len + PPPOE_HEADERLEN);	/* header len + payload len */
	if (!m0)
		return ENOBUFS;

	/* fill in pkt */
	p = mtod(m0, u_int8_t *);
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADI, 0, len);
	PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
	if (sc->sc_service_name != NULL) {
		PPPOE_ADD_16(p, l1);
		memcpy(p, sc->sc_service_name, l1);
		p += l1;
	} else {
		PPPOE_ADD_16(p, 0);
	}
	if (sc->sc_concentrator_name != NULL) {
		PPPOE_ADD_16(p, PPPOE_TAG_ACNAME);
		PPPOE_ADD_16(p, l2);
		memcpy(p, sc->sc_concentrator_name, l2);
		p += l2;
	}
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sizeof(sc));
	memcpy(p, &sc, sizeof sc);

#ifdef PPPOE_DEBUG
	p += sizeof sc;
	if (p - mtod(m0, u_int8_t *) != len + PPPOE_HEADERLEN)
		panic("pppoe_send_padi: garbled output len, should be %ld, is %ld",
		    (long)(len + PPPOE_HEADERLEN), (long)(p - mtod(m0, u_int8_t *)));
#endif

	/* send pkt */
	return pppoe_output(sc, m0);
}

static void
pppoe_timeout(void *arg)
{
	int x, retry_wait, err;
	struct pppoe_softc *sc = (struct pppoe_softc*)arg;

#ifdef PPPOE_DEBUG
	printf("%s: timeout\n", sc->sc_sppp.pp_if.if_xname);
#endif

	switch (sc->sc_state) {
	case PPPOE_STATE_PADI_SENT:
		/*
		 * We have two basic ways of retrying:
		 *  - Quick retry mode: try a few times in short sequence
		 *  - Slow retry mode: we already had a connection successfully
		 *    established and will try infinitely (without user
		 *    intervention)
		 * We only enter slow retry mode if IFF_LINK1 (aka autodial)
		 * is not set.
		 */

		/* initialize for quick retry mode */
		retry_wait = PPPOE_DISC_TIMEOUT * (1 + sc->sc_padi_retried);

		x = splnet();
		sc->sc_padi_retried++;
		if (sc->sc_padi_retried >= PPPOE_DISC_MAXPADI) {
			if ((sc->sc_sppp.pp_if.if_flags & IFF_LINK1) == 0) {
				/* slow retry mode */
				retry_wait = PPPOE_SLOW_RETRY;
			} else {
				pppoe_abort_connect(sc);
				splx(x);
				return;
			}
		}
		if ((err = pppoe_send_padi(sc)) != 0) {
			sc->sc_padi_retried--;
			if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
				printf("%s: failed to transmit PADI, "
				    "error=%d\n",
				    sc->sc_sppp.pp_if.if_xname, err);
		}
		callout_reset(&sc->sc_timeout, retry_wait,
		    pppoe_timeout, sc);
		splx(x);
		break;

	case PPPOE_STATE_PADR_SENT:
		x = splnet();
		sc->sc_padr_retried++;
		if (sc->sc_padr_retried >= PPPOE_DISC_MAXPADR) {
			memcpy(&sc->sc_dest, etherbroadcastaddr,
			    sizeof(sc->sc_dest));
			sc->sc_state = PPPOE_STATE_PADI_SENT;
			sc->sc_padr_retried = 0;
			if ((err = pppoe_send_padi(sc)) != 0) {
				if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
					printf("%s: failed to send PADI"
					    ", error=%d\n",
					    sc->sc_sppp.pp_if.if_xname,
					    err);
			}
			callout_reset(&sc->sc_timeout,
			    PPPOE_DISC_TIMEOUT * (1 + sc->sc_padi_retried),
			    pppoe_timeout, sc);
			splx(x);
			return;
		}
		if ((err = pppoe_send_padr(sc)) != 0) {
			sc->sc_padr_retried--;
			if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
				printf("%s: failed to send PADR, "
				    "error=%d\n", sc->sc_sppp.pp_if.if_xname,
				    err);
		}
		callout_reset(&sc->sc_timeout,
		    PPPOE_DISC_TIMEOUT * (1 + sc->sc_padr_retried),
		    pppoe_timeout, sc);
		splx(x);
		break;
	case PPPOE_STATE_CLOSING:
		pppoe_disconnect(sc);
		break;
	default:
		return;	/* all done, work in peace */
	}
}

/* Start a connection (i.e. initiate discovery phase) */
static int
pppoe_connect(struct pppoe_softc *sc)
{
	int x, err;

	if (sc->sc_state != PPPOE_STATE_INITIAL)
		return EBUSY;

#ifdef PPPOE_SERVER
	/* wait PADI if IFF_PASSIVE */
	if ((sc->sc_sppp.pp_if.if_flags & IFF_PASSIVE))
		return 0;
#endif
	x = splnet();
	/* save state, in case we fail to send PADI */
	sc->sc_state = PPPOE_STATE_PADI_SENT;
	sc->sc_padr_retried = 0;
	err = pppoe_send_padi(sc);
	if (err != 0 && sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
		printf("%s: failed to send PADI, error=%d\n",
		    sc->sc_sppp.pp_if.if_xname, err);
	callout_reset(&sc->sc_timeout, PPPOE_DISC_TIMEOUT, pppoe_timeout, sc);
	splx(x);
	return err;
}

/* disconnect */
static int
pppoe_disconnect(struct pppoe_softc *sc)
{
	int err, x;

	x = splnet();

	if (sc->sc_state < PPPOE_STATE_SESSION)
		err = EBUSY;
	else {
		if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
			printf("%s: disconnecting\n",
			    sc->sc_sppp.pp_if.if_xname);
		err = pppoe_send_padt(sc->sc_eth_if, sc->sc_session, (const u_int8_t *)&sc->sc_dest);
	}

	/* cleanup softc */
	sc->sc_state = PPPOE_STATE_INITIAL;
	memcpy(&sc->sc_dest, etherbroadcastaddr, sizeof(sc->sc_dest));
	if (sc->sc_ac_cookie) {
		free(sc->sc_ac_cookie, M_DEVBUF);
		sc->sc_ac_cookie = NULL;
	}
	sc->sc_ac_cookie_len = 0;
#ifdef PPPOE_SERVER
	if (sc->sc_hunique) {
		free(sc->sc_hunique, M_DEVBUF);
		sc->sc_hunique = NULL;
	}
	sc->sc_hunique_len = 0;
#endif
	sc->sc_session = 0;

	/* notify upper layer */
	sc->sc_sppp.pp_down(&sc->sc_sppp);

	splx(x);

	return err;
}

/* Connection attempt aborted */
static void
pppoe_abort_connect(struct pppoe_softc *sc)
{
	printf("%s: could not establish connection\n",
		sc->sc_sppp.pp_if.if_xname);
	sc->sc_state = PPPOE_STATE_CLOSING;

	/* notify upper layer */
	sc->sc_sppp.pp_down(&sc->sc_sppp);

	/* clear connection state */
	memcpy(&sc->sc_dest, etherbroadcastaddr, sizeof(sc->sc_dest));
	sc->sc_state = PPPOE_STATE_INITIAL;
}

/* Send a PADR packet */
static int
pppoe_send_padr(struct pppoe_softc *sc)
{
	struct mbuf *m0;
	u_int8_t *p;
	size_t len, l1 = 0; /* XXX: gcc */

	if (sc->sc_state != PPPOE_STATE_PADR_SENT)
		return EIO;

	len = 2 + 2 + 2 + 2 + sizeof(sc);		/* service name, host unique */
	if (sc->sc_service_name != NULL) {		/* service name tag maybe empty */
		l1 = strlen(sc->sc_service_name);
		len += l1;
	}
	if (sc->sc_ac_cookie_len > 0)
		len += 2 + 2 + sc->sc_ac_cookie_len;	/* AC cookie */
	m0 = pppoe_get_mbuf(len + PPPOE_HEADERLEN);
	if (!m0)
		return ENOBUFS;
	p = mtod(m0, u_int8_t *);
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADR, 0, len);
	PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
	if (sc->sc_service_name != NULL) {
		PPPOE_ADD_16(p, l1);
		memcpy(p, sc->sc_service_name, l1);
		p += l1;
	} else {
		PPPOE_ADD_16(p, 0);
	}
	if (sc->sc_ac_cookie_len > 0) {
		PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
		PPPOE_ADD_16(p, sc->sc_ac_cookie_len);
		memcpy(p, sc->sc_ac_cookie, sc->sc_ac_cookie_len);
		p += sc->sc_ac_cookie_len;
	}
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sizeof(sc));
	memcpy(p, &sc, sizeof sc);

#ifdef PPPOE_DEBUG
	p += sizeof sc;
	if (p - mtod(m0, u_int8_t *) != len + PPPOE_HEADERLEN)
		panic("pppoe_send_padr: garbled output len, should be %ld, is %ld",
			(long)(len + PPPOE_HEADERLEN), (long)(p - mtod(m0, u_int8_t *)));
#endif

	return pppoe_output(sc, m0);
}

/* send a PADT packet */
static int
pppoe_send_padt(struct ifnet *outgoing_if, u_int session, const u_int8_t *dest)
{
	struct ether_header *eh;
	struct sockaddr dst;
	struct mbuf *m0;
	u_int8_t *p;

	m0 = pppoe_get_mbuf(PPPOE_HEADERLEN);
	if (!m0)
		return EIO;
	p = mtod(m0, u_int8_t *);
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADT, session, 0);

	memset(&dst, 0, sizeof dst);
	dst.sa_family = AF_UNSPEC;
	eh = (struct ether_header*)&dst.sa_data;
	eh->ether_type = htons(ETHERTYPE_PPPOEDISC);
	memcpy(&eh->ether_dhost, dest, ETHER_ADDR_LEN);

	m0->m_flags &= ~(M_BCAST|M_MCAST);
	return outgoing_if->if_output(outgoing_if, m0, &dst, NULL);
}

#ifdef PPPOE_SERVER
static int
pppoe_send_pado(struct pppoe_softc *sc)
{
	struct mbuf *m0;
	u_int8_t *p;
	size_t len;

	if (sc->sc_state != PPPOE_STATE_PADO_SENT)
		return EIO;

	/* calc length */
	len = 0;
	/* include ac_cookie */
	len += 2 + 2 + sizeof(sc);
	/* include hunique */
	len += 2 + 2 + sc->sc_hunique_len;
	m0 = pppoe_get_mbuf(len + PPPOE_HEADERLEN);
	if (!m0)
		return EIO;
	p = mtod(m0, u_int8_t *);
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADO, 0, len);
	PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
	PPPOE_ADD_16(p, sizeof(sc));
	memcpy(p, &sc, sizeof(sc));
	p += sizeof(sc);
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sc->sc_hunique_len);
	memcpy(p, sc->sc_hunique, sc->sc_hunique_len);
	return pppoe_output(sc, m0);
}

static int
pppoe_send_pads(struct pppoe_softc *sc)
{
	struct bintime bt;
	struct mbuf *m0;
	u_int8_t *p;
	size_t len, l1 = 0;	/* XXX: gcc */

	if (sc->sc_state != PPPOE_STATE_PADO_SENT)
		return EIO;

	getbinuptime(&bt);
	sc->sc_session = bt.sec % 0xff + 1;
	/* calc length */
	len = 0;
	/* include hunique */
	len += 2 + 2 + 2 + 2 + sc->sc_hunique_len;	/* service name, host unique*/
	if (sc->sc_service_name != NULL) {		/* service name tag maybe empty */
		l1 = strlen(sc->sc_service_name);
		len += l1;
	}
	m0 = pppoe_get_mbuf(len + PPPOE_HEADERLEN);
	if (!m0)
		return ENOBUFS;
	p = mtod(m0, u_int8_t *);
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADS, sc->sc_session, len);
	PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
	if (sc->sc_service_name != NULL) {
		PPPOE_ADD_16(p, l1);
		memcpy(p, sc->sc_service_name, l1);
		p += l1;
	} else {
		PPPOE_ADD_16(p, 0);
	}
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sc->sc_hunique_len);
	memcpy(p, sc->sc_hunique, sc->sc_hunique_len);
	return pppoe_output(sc, m0);
}
#endif

static void
pppoe_tls(struct sppp *sp)
{
	struct pppoe_softc *sc = (void *)sp;
	if (sc->sc_state != PPPOE_STATE_INITIAL)
		return;
	pppoe_connect(sc);
}

static void
pppoe_tlf(struct sppp *sp)
{
	struct pppoe_softc *sc = (void *)sp;
	if (sc->sc_state < PPPOE_STATE_SESSION)
		return;
	/*
	 * Do not call pppoe_disconnect here, the upper layer state
	 * machine gets confused by this. We must return from this
	 * function and defer disconnecting to the timeout handler.
	 */
	sc->sc_state = PPPOE_STATE_CLOSING;
	callout_reset(&sc->sc_timeout, hz/50, pppoe_timeout, sc);
}

static void
pppoe_start(struct ifnet *ifp)
{
	struct pppoe_softc *sc = (void *)ifp;
	struct mbuf *m;
	u_int8_t *p;
	size_t len;

	if (sppp_isempty(ifp))
		return;

	/* are we ready to process data yet? */
	if (sc->sc_state < PPPOE_STATE_SESSION) {
		sppp_flush(&sc->sc_sppp.pp_if);
		return;
	}

	while ((m = sppp_dequeue(ifp)) != NULL) {
		len = m->m_pkthdr.len;
		M_PREPEND(m, PPPOE_HEADERLEN, M_DONTWAIT);
		if (m == NULL) {
			ifp->if_oerrors++;
			continue;
		}
		p = mtod(m, u_int8_t *);
		PPPOE_ADD_HEADER(p, 0, sc->sc_session, len);

#if NBPFILTER > 0
		if(sc->sc_sppp.pp_if.if_bpf)
			bpf_mtap(sc->sc_sppp.pp_if.if_bpf, m);
#endif

		pppoe_output(sc, m);
	}
}


#ifdef PFIL_HOOKS
static int
pppoe_ifattach_hook(void *arg, struct mbuf **mp, struct ifnet *ifp,
#ifndef QNX_MFIB
    int dir)
#else
    int dir, int fib)
#endif
{
	struct pppoe_softc *sc;
	int s;

	if (mp != (struct mbuf **)PFIL_IFNET_DETACH)
		return 0;

	s = splnet();
	LIST_FOREACH(sc, &pppoe_softc_list, sc_list) {
		if (sc->sc_eth_if != ifp)
			continue;
		if (sc->sc_sppp.pp_if.if_flags & IFF_UP) {
			sc->sc_sppp.pp_if.if_flags &= ~(IFF_UP|IFF_RUNNING);
			printf("%s: ethernet interface detached, going down\n",
			    sc->sc_sppp.pp_if.if_xname);
		}
		sc->sc_eth_if = NULL;
		pppoe_clear_softc(sc, "ethernet interface detached");
	}
	splx(s);

	return 0;
}
#endif

static void
pppoe_clear_softc(struct pppoe_softc *sc, const char *message)
{
	/* stop timer */
	callout_stop(&sc->sc_timeout);
	if (sc->sc_sppp.pp_if.if_flags & IFF_DEBUG)
		printf("%s: session 0x%x terminated, %s\n",
		    sc->sc_sppp.pp_if.if_xname, sc->sc_session, message);

	/* fix our state */
	sc->sc_state = PPPOE_STATE_INITIAL;

	/* signal upper layer */
	sc->sc_sppp.pp_down(&sc->sc_sppp);

	/* clean up softc */
	memcpy(&sc->sc_dest, etherbroadcastaddr, sizeof(sc->sc_dest));
	if (sc->sc_ac_cookie) {
		free(sc->sc_ac_cookie, M_DEVBUF);
		sc->sc_ac_cookie = NULL;
	}
	sc->sc_ac_cookie_len = 0;
	sc->sc_session = 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_pppoe.c $ $Rev: 680336 $")
#endif
