/*	$NetBSD: if_agrvar_impl.h,v 1.4 2006/10/29 22:14:14 yamt Exp $	*/

/*-
 * Copyright (c)2005 YAMAMOTO Takashi,
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
 */

#ifndef _NET_AGR_IF_AGRVAR_IMPL_H_
#define	_NET_AGR_IF_AGRVAR_IMPL_H_

/*
 * implementaion details for agr(4) driver.  (contrast to if_agrvar.h)
 */

#include <sys/lock.h>
#include <sys/queue.h>

struct agr_port;
struct agr_softc;

struct agr_port {
	struct ifnet *port_agrifp;
	struct ifnet *port_ifp;
	TAILQ_ENTRY(agr_port) port_q;
	int (*port_ioctl)(struct ifnet *, u_long, caddr_t);
	void *port_iftprivate;
	int port_flags;
	u_int port_media;
	char port_origlladdr[0];
};
#define	AGRPORT_COLLECTING	0x00000001
#define	AGRPORT_DISTRIBUTING	0x00000002
#define	AGRPORT_PROMISC		0x00000004
#define	AGRPORT_LADDRCHANGED	0x00000008
#define	AGRPORT_ATTACHED	0x00000010
#define	AGRPORT_LARVAL		0x00000020
#define	AGRPORT_DETACHING	0x00000040

struct agr_iftype_ops {

	void (*iftop_tick)(struct agr_softc *);
	void (*iftop_porttick)(struct agr_softc *, struct agr_port *);
	void (*iftop_portstate)(struct agr_port *);

	/*
	 * iftop_ctor:
	 * - inherit setting (eg. L1 address) from the first port.
	 * - initialize if_output, if_input, if_dlt, etc.
	 *   (in the case of IFT_ETHER, ether_ifattach.
	 */

	int (*iftop_ctor)(struct agr_softc *, struct ifnet *);

	void (*iftop_dtor)(struct agr_softc *);

	/*
	 * iftop_portinit:
	 * propagate setting to a newly added port.
	 */

	int (*iftop_portinit)(struct agr_softc *, struct agr_port *);

	/*
	 * iftop_portfini:
	 * restore setting of a port being removed.
	 */
	int (*iftop_portfini)(struct agr_softc *, struct agr_port *);

	struct agr_port *(*iftop_select_tx_port)(struct agr_softc *,
	    struct mbuf *);
	uint32_t (*iftop_hashmbuf)(struct agr_softc *, struct mbuf *);

	int (*iftop_configmulti_port)(struct agr_softc *, struct agr_port *,
	    boolean_t);
	int (*iftop_configmulti_ifreq)(struct agr_softc *, struct ifreq *,
	    boolean_t);
};

struct agr_ifreq {
	char ifr_name[IFNAMSIZ];
	struct sockaddr_storage ifr_ss;
};

struct agr_softc {
	struct lock sc_ioctl_lock;
	struct simplelock sc_lock;
	struct callout sc_callout;
	int sc_nports;
	TAILQ_HEAD(, agr_port) sc_ports;
	const struct agr_iftype_ops *sc_iftop;
	uint32_t sc_rr_counter;	/* distributor algorithm specific */
	void *sc_iftprivate;
	struct ifnet sc_if; /* should be the last. see agr_alloc_softc(). */
};

#define	AGR_SC_FROM_PORT(port) \
	((struct agr_softc *)(port)->port_agrifp->if_softc)

#define	AGR_LOCK(sc)		agr_lock(sc)
#define	AGR_UNLOCK(sc, s)	agr_unlock((sc), (s))
#define	AGR_ASSERT_LOCKED(sc)	LOCK_ASSERT(simple_lock_held(&(sc)->sc_lock))

int agr_lock(struct agr_softc *);
void agr_unlock(struct agr_softc *, int);

void agr_ioctl_lock(struct agr_softc *);
void agr_ioctl_unlock(struct agr_softc *);

int agrport_ioctl(struct agr_port *, u_long, caddr_t);

struct agr_softc *agr_alloc_softc(void);
void agr_free_softc(struct agr_softc *);

int agr_xmit_frame(struct ifnet *, struct mbuf *); /* XXX */

#define	AGR_ROUNDROBIN(sc)	(((sc)->sc_if.if_flags & IFF_LINK0) != 0)

void agrtimer_init(struct agr_softc *);
void agrtimer_start(struct agr_softc *);
void agrtimer_stop(struct agr_softc *);

void agrport_monitor(struct agr_port *);

#endif /* !_NET_AGR_IF_AGRVAR_IMPL_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/agr/if_agrvar_impl.h $ $Rev: 680336 $")
#endif
