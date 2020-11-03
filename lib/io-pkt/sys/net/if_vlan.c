/*
 * $QNXtpLicenseC:
 * Copyright 2007, 2009, QNX Software Systems. All Rights Reserved.
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



/*	$NetBSD: if_vlan.c,v 1.52 2006/11/16 01:33:40 christos Exp $	*/

/*-
 * Copyright (c) 2000, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran, and by Jason R. Thorpe of Zembu Labs, Inc.
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
 * from FreeBSD: if_vlan.c,v 1.16 2000/03/26 15:21:40 charnier Exp
 * via OpenBSD: if_vlan.c,v 1.4 2000/05/15 19:15:00 chris Exp
 */

/*
 * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.  Might be
 * extended some day to also handle IEEE 802.1P priority tagging.  This is
 * sort of sneaky in the implementation, since we need to pretend to be
 * enough of an Ethernet implementation to make ARP work.  The way we do
 * this is by telling everyone that we are an Ethernet interface, and then
 * catch the packets that ether_output() left on our output queue when it
 * calls if_start(), rewrite them for use by the real outgoing interface,
 * and ask it to send them.
 *
 * TODO:
 *
 *	- Need some way to notify vlan interfaces when the parent
 *	  interface changes MTU.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_vlan.c,v 1.52 2006/11/16 01:33:40 christos Exp $");

#include "opt_inet.h"
#include "bpfilter.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_ether.h>
#include <net/if_vlanvar.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_inarp.h>
#endif

#ifdef __QNXNTO__
#include <nw_msg.h>
#include <sys/dcmd_misc.h>
#include <netdrvr/ptp.h>
#endif

struct vlan_mc_entry {
	LIST_ENTRY(vlan_mc_entry)	mc_entries;
	/*
	 * A key to identify this entry.  The mc_addr below can't be
	 * used since multiple sockaddr may mapped into the same
	 * ether_multi (e.g., AF_UNSPEC).
	 */
	union {
		struct ether_multi	*mcu_enm;
	} mc_u;
	struct sockaddr_storage		mc_addr;
};

#define	mc_enm		mc_u.mcu_enm

#ifndef __QNXNTO__
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
		u_int16_t ifvm_proto;	/* encapsulation ethertype */
		u_int16_t ifvm_tag;	/* tag to apply on packets */
	} ifv_mib;
	LIST_HEAD(__vlan_mchead, vlan_mc_entry) ifv_mc_listhead;
	LIST_ENTRY(ifvlan) ifv_list;
	int ifv_flags;
};
#else
	/* Moved QNX definition of ifvlan to if_vlanvar.h */
#endif

#define	IFVF_PROMISC	0x01		/* promiscuous mode enabled */

#define	ifv_ec		ifv_u.ifvu_ec

#define	ifv_if		ifv_ec.ec_if

#define	ifv_msw		ifv_mib.ifvm_msw
#define	ifv_encaplen	ifv_mib.ifvm_encaplen
#define	ifv_mtufudge	ifv_mib.ifvm_mtufudge
#define	ifv_mintu	ifv_mib.ifvm_mintu
#define	ifv_tag		ifv_mib.ifvm_tag

struct vlan_multisw {
	int	(*vmsw_addmulti)(struct ifvlan *, struct ifreq *);
	int	(*vmsw_delmulti)(struct ifvlan *, struct ifreq *);
	void	(*vmsw_purgemulti)(struct ifvlan *);
};

static int	vlan_ether_addmulti(struct ifvlan *, struct ifreq *);
static int	vlan_ether_delmulti(struct ifvlan *, struct ifreq *);
static void	vlan_ether_purgemulti(struct ifvlan *);

const struct vlan_multisw vlan_ether_multisw = {
	vlan_ether_addmulti,
	vlan_ether_delmulti,
	vlan_ether_purgemulti,
};

static int	vlan_clone_create(struct if_clone *, int);
static int	vlan_clone_destroy(struct ifnet *);
static int	vlan_config(struct ifvlan *, struct ifnet *);
static int	vlan_ioctl(struct ifnet *, u_long, caddr_t);
static void	vlan_start(struct ifnet *);
static void	vlan_unconfig(struct ifnet *);

void		vlanattach(int);

/* XXX This should be a hash table with the tag as the basis of the key. */
static LIST_HEAD(, ifvlan) ifv_list;

struct if_clone vlan_cloner =
    IF_CLONE_INITIALIZER("vlan", vlan_clone_create, vlan_clone_destroy);

#ifdef __QNXNTO__
/* Used to pad ethernet frames with < ETHER_MIN_LEN bytes */
static char vlan_zero_pad_buff[ETHER_MIN_LEN];
#else
/* Used to pad ethernet frames with < ETHER_MIN_LEN + ETHER_VLAN_ENCAP_LEN bytes */
static char vlan_zero_pad_buff[ETHER_MIN_LEN + ETHER_VLAN_ENCAP_LEN];
#endif

void
vlanattach(int n)
{

	LIST_INIT(&ifv_list);
	if_clone_attach(&vlan_cloner);
}

static void
vlan_reset_linkname(struct ifnet *ifp)
{

	/*
	 * We start out with a "802.1Q VLAN" type and zero-length
	 * addresses.  When we attach to a parent interface, we
	 * inherit its type, address length, address, and data link
	 * type.
	 */

	ifp->if_type = IFT_L2VLAN;
	ifp->if_addrlen = 0;
	ifp->if_dlt = DLT_NULL;
	if_alloc_sadl(ifp);
}

static int
vlan_clone_create(struct if_clone *ifc, int unit)
{
	struct ifvlan *ifv;
	struct ifnet *ifp;
	int s;
#ifdef __QNXNTO__
	void *head;
#endif

#ifndef __QNXNTO__
	ifv = malloc(sizeof(struct ifvlan), M_DEVBUF, M_WAITOK);
	memset(ifv, 0, sizeof(struct ifvlan));
	ifp = &ifv->ifv_if;
#else
	head = malloc(sizeof(struct ifvlan) + NET_CACHELINE_SIZE, M_DEVBUF, M_WAITOK);
	memset(head, 0, sizeof(struct ifvlan) + NET_CACHELINE_SIZE);
	ifv = NET_CACHELINE_ALIGN(head);
	ifp = &ifv->ifv_if;
	ifv->ifv_alloc = head;
#endif
	LIST_INIT(&ifv->ifv_mc_listhead);

	s = splnet();
	LIST_INSERT_HEAD(&ifv_list, ifv, ifv_list);
	splx(s);

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "%s%d", ifc->ifc_name,
	    unit);
	ifp->if_softc = ifv;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = vlan_start;
	ifp->if_ioctl = vlan_ioctl;
	IFQ_SET_READY(&ifp->if_snd);

	if_attach(ifp);
	vlan_reset_linkname(ifp);

	return (0);
}

static int
vlan_clone_destroy(struct ifnet *ifp)
{
	struct ifvlan *ifv = ifp->if_softc;
	int s;

	s = splnet();
	LIST_REMOVE(ifv, ifv_list);
	vlan_unconfig(ifp);
	splx(s);

	if_detach(ifp);
#ifndef __QNXNTO__
	free(ifv, M_DEVBUF);
#else
	free(ifv->ifv_alloc, M_DEVBUF);
#endif

	return (0);
}

/*
 * Configure a VLAN interface.  Must be called at splnet().
 */
static int
vlan_config(struct ifvlan *ifv, struct ifnet *p)
{
	struct ifnet *ifp = &ifv->ifv_if;
	int error;

	if (ifv->ifv_p != NULL)
		return (EBUSY);

	switch (p->if_type) {
	case IFT_ETHER:
	    {
		struct ethercom *ec = (void *) p;

		ifv->ifv_msw = &vlan_ether_multisw;
		ifv->ifv_encaplen = ETHER_VLAN_ENCAP_LEN;
		ifv->ifv_mintu = ETHERMIN;

		/*
		 * If the parent supports the VLAN_MTU capability,
		 * i.e. can Tx/Rx larger than ETHER_MAX_LEN frames,
		 * enable it.
		 */
		if (ec->ec_nvlans++ == 0 &&
		    (ec->ec_capabilities & ETHERCAP_VLAN_MTU) != 0) {
			/*
			 * Enable Tx/Rx of VLAN-sized frames.
			 */
			ec->ec_capenable |= ETHERCAP_VLAN_MTU;
			if (p->if_flags & IFF_UP) {
				struct ifreq ifr;

				ifr.ifr_flags = p->if_flags;
				error = (*p->if_ioctl)(p, SIOCSIFFLAGS,
				    (caddr_t) &ifr);
				if (error) {
					if (ec->ec_nvlans-- == 1)
						ec->ec_capenable &=
						    ~ETHERCAP_VLAN_MTU;
					return (error);
				}
			}
			ifv->ifv_mtufudge = 0;
		} else if ((ec->ec_capabilities & ETHERCAP_VLAN_MTU) == 0) {
			/*
			 * Fudge the MTU by the encapsulation size.  This
			 * makes us incompatible with strictly compliant
			 * 802.1Q implementations, but allows us to use
			 * the feature with other NetBSD implementations,
			 * which might still be useful.
			 */
			ifv->ifv_mtufudge = ifv->ifv_encaplen;
		}

		/*
		 * If the parent interface can do hardware-assisted
		 * VLAN encapsulation, then propagate its hardware-
		 * assisted checksumming flags.
		 */
		if (ec->ec_capabilities & ETHERCAP_VLAN_HWTAGGING) {
#ifndef __QNXNTO__
			ifp->if_capabilities = p->if_capabilities &
			    (IFCAP_CSUM_IPv4_Tx|IFCAP_CSUM_IPv4_Rx|
			     IFCAP_CSUM_TCPv4_Tx|IFCAP_CSUM_TCPv4_Rx|
			     IFCAP_CSUM_UDPv4_Tx|IFCAP_CSUM_UDPv4_Rx|
			     IFCAP_CSUM_TCPv6_Tx|IFCAP_CSUM_TCPv6_Rx|
			     IFCAP_CSUM_UDPv6_Tx|IFCAP_CSUM_UDPv6_Rx);
#else
			ifp->if_capabilities_rx = p->if_capabilities_rx &
			    (IFCAP_CSUM_IPv4|IFCAP_CSUM_TCPv4|
			     IFCAP_CSUM_UDPv4|IFCAP_CSUM_TCPv6|
			     IFCAP_CSUM_UDPv6);
			ifp->if_capabilities_tx = p->if_capabilities_tx &
			    (IFCAP_CSUM_IPv4|IFCAP_CSUM_TCPv4|
			     IFCAP_CSUM_UDPv4|IFCAP_CSUM_TCPv6|
			     IFCAP_CSUM_UDPv6);
#endif
		}

		/*
		 * We inherit the parent's Ethernet address.
		 */
		ether_ifattach(ifp, LLADDR(p->if_sadl));
#ifdef __QNXNTO__
		ipsec_input_set_globalif(ifp);
#endif
		ifp->if_hdrlen = sizeof(struct ether_vlan_header); /* XXX? */
		break;
	    }

	default:
#ifndef __QNXNTO__
		return (EPROTONOSUPPORT);
#else
		{
			const u_int8_t lla[6] = {0,0,0,0,0,1};
			ether_ifattach(ifp, lla);
			ipsec_input_set_globalif(ifp);
			ifp->if_hdrlen = 0;
			ifv->ifv_mtufudge = 0;
		}
		break;
#endif
	}

	ifv->ifv_p = p;
	ifv->ifv_if.if_mtu = p->if_mtu - ifv->ifv_mtufudge;
	ifv->ifv_if.if_flags = p->if_flags &
	    (IFF_UP | IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST);

	/*
	 * Inherit the if_type from the parent.  This allows us
	 * to participate in bridges of that type.
	 */
	ifv->ifv_if.if_type = p->if_type;
#ifdef __QNXNTO__
	if (p->if_type == IFT_PPP || p->if_type == IFT_TUNNEL)
		ifv->ifv_if.if_type = IFT_ETHER; /* Maintain the Ethernet illusion */
#endif

	return (0);
}

/*
 * Unconfigure a VLAN interface.  Must be called at splnet().
 */
static void
vlan_unconfig(struct ifnet *ifp)
{
	struct ifvlan *ifv = ifp->if_softc;

	if (ifv->ifv_p == NULL)
		return;

	/*
 	 * Since the interface is being unconfigured, we need to empty the
	 * list of multicast groups that we may have joined while we were
	 * alive and remove them from the parent's list also.
	 */
#ifdef __QNXNTO__
	if (ifv->ifv_p->if_type == IFT_ETHER)
#endif
	(*ifv->ifv_msw->vmsw_purgemulti)(ifv);

	/* Disconnect from parent. */
	switch (ifv->ifv_p->if_type) {
	case IFT_ETHER:
	    {
		struct ethercom *ec = (void *) ifv->ifv_p;

		if (ec->ec_nvlans-- == 1) {
			/*
			 * Disable Tx/Rx of VLAN-sized frames.
			 */
			ec->ec_capenable &= ~ETHERCAP_VLAN_MTU;
			if (ifv->ifv_p->if_flags & IFF_UP) {
				struct ifreq ifr;

				ifr.ifr_flags = ifv->ifv_p->if_flags;
				(void) (*ifv->ifv_p->if_ioctl)(ifv->ifv_p,
				    SIOCSIFFLAGS, (caddr_t) &ifr);
			}
		}

		ether_ifdetach(ifp);
		vlan_reset_linkname(ifp);
		break;
	    }
#ifdef __QNXNTO__
	default:
		ether_ifdetach(ifp);
		vlan_reset_linkname(ifp);
		break;
#else
#ifdef DIAGNOSTIC
	default:
		panic("vlan_unconfig: impossible");
#endif
#endif
	}

	ifv->ifv_p = NULL;
	ifv->ifv_if.if_mtu = 0;
	ifv->ifv_flags = 0;

#ifdef __QNXNTO__
	ipsec_input_clear_globalif(ifp);
#endif
	if_down(ifp);
	ifp->if_flags &= ~(IFF_UP|IFF_RUNNING);
#ifndef __QNXNTO__
	ifp->if_capabilities = 0;
#else
	ifp->if_capabilities_rx = 0;
	ifp->if_capabilities_tx = 0;
#endif
}

/*
 * Called when a parent interface is detaching; destroy any VLAN
 * configuration for the parent interface.
 */
void
vlan_ifdetach(struct ifnet *p)
{
	struct ifvlan *ifv;
	int s;

	s = splnet();

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	     ifv = LIST_NEXT(ifv, ifv_list)) {
		if (ifv->ifv_p == p)
			vlan_unconfig(&ifv->ifv_if);
	}

	splx(s);
}

static int
vlan_set_promisc(struct ifnet *ifp)
{
	struct ifvlan *ifv = ifp->if_softc;
	int error = 0;

	if ((ifp->if_flags & IFF_PROMISC) != 0) {
		if ((ifv->ifv_flags & IFVF_PROMISC) == 0) {
			error = ifpromisc(ifv->ifv_p, 1);
			if (error == 0)
				ifv->ifv_flags |= IFVF_PROMISC;
		}
	} else {
		if ((ifv->ifv_flags & IFVF_PROMISC) != 0) {
			error = ifpromisc(ifv->ifv_p, 0);
			if (error == 0)
				ifv->ifv_flags &= ~IFVF_PROMISC;
		}
	}

	return (error);
}


#ifdef __QNXNTO__
/* Handle DCMD_MISC_GETPTREMBED */
static int vlan_getptrembed(u_long cmd, caddr_t data) {
	int                          len = 0;
	caddr_t                      ptr;
	struct proc		    *p;
	resmgr_context_t	    *ctp;
	io_devctl_t                 *msg;
	struct __ioctl_getptrembed  *embedmsg;

        /* Need to parse from the top of msg to find the original cmd and its data */
	p = curproc;
	ctp = &p->p_ctxt;
	msg = (io_devctl_t *)ctp->msg;
	embedmsg =  (struct __ioctl_getptrembed *) _DEVCTL_DATA(msg->i);

	data = (caddr_t) (embedmsg + 1) + embedmsg->niov * sizeof(iov_t);
	cmd = embedmsg->dcmd;

	switch (cmd) {
	case SIOCGETVLAN:
	case SIOCSETVLAN:
	case SIOCGETVLANPRIO:
	case SIOCSETVLANPRIO:
		{
			struct ifreq *ifr = (struct ifreq *) data;
			ptr = ifr->ifr_data;
			len = sizeof(struct vlanreq);
			break;
		}
	default:
		/* No support for embeddeded pointers for other ioctl commands */
		return EOPNOTSUPP;
	}

	if (ptr == NULL)
		return EFAULT;

	return ioctl_getptrembed(msg, ptr, len, embedmsg->niov);
}
#endif

static int
vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct lwp *l = curlwp;	/* XXX */
	struct ifvlan *ifv = ifp->if_softc;
	struct ifaddr *ifa = (struct ifaddr *) data;
	struct ifreq *ifr = (struct ifreq *) data;
#ifdef __QNXNTO__
	struct ifdrv *ifd = (struct ifdrv *) data;
#endif
	struct ifnet *pr;
	struct vlanreq vlr;
	struct sockaddr *sa;
	int s, error = 0;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		if (ifv->ifv_p != NULL) {
			ifp->if_flags |= IFF_UP;

			switch (ifa->ifa_addr->sa_family) {
#ifdef INET
			case AF_INET:
#ifdef __QNXNTO__
				if (ifv->ifv_p->if_type == IFT_ETHER)
				arp_ifinit(ifp, ifa);
#endif
				break;
#endif
			default:
				break;
			}
		} else {
			error = EINVAL;
		}
		break;

	case SIOCGIFADDR:
		sa = (struct sockaddr *)&ifr->ifr_data;
		memcpy(sa->sa_data, LLADDR(ifp->if_sadl), ifp->if_addrlen);
		break;

	case SIOCSIFMTU:
		if (ifv->ifv_p != NULL) {
			if (ifr->ifr_mtu >
			     (ifv->ifv_p->if_mtu - ifv->ifv_mtufudge) ||
			    ifr->ifr_mtu <
			     (ifv->ifv_mintu - ifv->ifv_mtufudge))
				error = EINVAL;
			else
				ifp->if_mtu = ifr->ifr_mtu;
		} else
			error = EINVAL;
		break;

	case SIOCSETVLAN:
		if ((error = kauth_authorize_network(l->l_cred,
		    KAUTH_NETWORK_INTERFACE,
		    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp, (void *)cmd,
		    NULL)) != 0)
			break;
#ifndef __QNXNTO__
		if ((error = copyin(ifr->ifr_data, &vlr, sizeof(vlr))) != 0)
#else
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		if ((error = copyin(data + sizeof(*ifr), &vlr, sizeof(vlr))) != 0)
#endif
			break;
		if (vlr.vlr_parent[0] == '\0') {
			vlan_unconfig(ifp);
			break;
		}
		if (vlr.vlr_tag != EVL_VLANOFTAG(vlr.vlr_tag)) {
			error = EINVAL;		 /* check for valid tag */
			break;
		}
#ifndef QNX_MFIB
		if ((pr = ifunit(vlr.vlr_parent)) == 0) {
#else
		if ((pr = ifunit(vlr.vlr_parent, ANY_FIB)) == 0) {
#endif
			error = ENOENT;
			break;
		}
		if ((error = vlan_config(ifv, pr)) != 0)
			break;
		ifv->ifv_tag = vlr.vlr_tag;
		ifp->if_flags |= IFF_RUNNING;

		/* Update promiscuous mode, if necessary. */
		vlan_set_promisc(ifp);
		break;

	case SIOCGETVLAN:
		memset(&vlr, 0, sizeof(vlr));
		if (ifv->ifv_p != NULL) {
			snprintf(vlr.vlr_parent, sizeof(vlr.vlr_parent), "%s",
			    ifv->ifv_p->if_xname);
#ifndef __QNXNTO__
			vlr.vlr_tag = ifv->ifv_tag;
#else
			vlr.vlr_tag = EVL_VLANOFTAG(ifv->ifv_tag);
#endif
		}
                
#ifndef __QNXNTO__
		error = copyout(&vlr, ifr->ifr_data, sizeof(vlr));
#else
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		error = copyout(&vlr, data + sizeof(*ifr), sizeof(vlr));
#endif
		break;

#ifdef __QNXNTO__
	case SIOCSETVLANPRIO:
		if ((error = kauth_authorize_network(l->l_cred,
		    KAUTH_NETWORK_INTERFACE,
		    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp, (void *)cmd,
		    NULL)) != 0) {
			break;
		}
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		if ((error = copyin(data + sizeof(*ifr), &vlr, sizeof(vlr))) != 0) {
			break;
		}
		if (vlr.vlr_tag > 7) {
			error = EINVAL;	   /* check for valid priority */
			break;
		}
		ifv->ifv_tag = EVL_VLANOFTAG(ifv->ifv_tag) | vlr.vlr_tag << 13;
		break;

	case SIOCGETVLANPRIO:
		memset(&vlr, 0, sizeof(vlr));
		vlr.vlr_tag = EVL_PRIOFTAG(ifv->ifv_tag);
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		error = copyout(&vlr, data + sizeof(*ifr), sizeof(vlr));
		break;
#endif
	case SIOCSIFFLAGS:
		/*
		 * For promiscuous mode, we enable promiscuous mode on
		 * the parent if we need promiscuous on the VLAN interface.
		 */
		if (ifv->ifv_p != NULL)
			error = vlan_set_promisc(ifp);
		break;

	case SIOCADDMULTI:
#ifdef __QNXNTO__
		if (ifv->ifv_p != NULL && ifv->ifv_p->if_type != IFT_ETHER)
			error = EOPNOTSUPP;
		else
#endif
		error = (ifv->ifv_p != NULL) ?
		    (*ifv->ifv_msw->vmsw_addmulti)(ifv, ifr) : EINVAL;
		break;

	case SIOCDELMULTI:
#ifdef __QNXNTO__
		if (ifv->ifv_p != NULL && ifv->ifv_p->if_type != IFT_ETHER)
			error = EOPNOTSUPP;
		else
#endif
		error = (ifv->ifv_p != NULL) ?
		    (*ifv->ifv_msw->vmsw_delmulti)(ifv, ifr) : EINVAL;
		break;
#ifdef __QNXNTO__
	case DCMD_MISC_GETPTREMBED:
		error = vlan_getptrembed(cmd, data);
		break;
	case SIOCALIFADDR:
		{
		struct if_laddrreq *iflr = (struct if_laddrreq *)data;

		/* MAC will only be active on vlan, not on parent */

		iflr->flags &= ~IFLR_ACTIVE;

		/* Add MAC to the parent interface */

		error = (ifv->ifv_p != NULL) ?
			ifioctl_common(ifv->ifv_p, cmd, data) : ENODEV;
		break;
		}
	case SIOCDLIFADDR:
		/* Delete MAC from the parent interface */

		error = (ifv->ifv_p != NULL) ?
			ifioctl_common(ifv->ifv_p, cmd, data) : ENODEV;
		break;
	case SIOCSDRVSPEC:
	case SIOCGDRVSPEC:
		switch (ifd->ifd_cmd) {
		case PTP_GET_RX_TIMESTAMP:
		case PTP_GET_TX_TIMESTAMP:
		case PTP_GET_TIME:
		case PTP_SET_TIME:
		case PTP_SET_COMPENSATION:
		case PTP_GET_COMPENSATION:
			error = (ifv->ifv_p != NULL) ?
				(ifv->ifv_p->if_ioctl)(ifv->ifv_p, cmd, data) : ENODEV;
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
#endif
	default:
		error = EINVAL;
	}

	splx(s);

	return (error);
}

static int
vlan_ether_addmulti(struct ifvlan *ifv, struct ifreq *ifr)
{
	const struct sockaddr *sa = ifreq_getaddr(SIOCADDMULTI, ifr);
	struct vlan_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	if (sa->sa_len > sizeof(struct sockaddr_storage))
		return (EINVAL);

	error = ether_addmulti(sa, &ifv->ifv_ec);
	if (error != ENETRESET)
		return (error);

	/*
	 * This is new multicast address.  We have to tell parent
	 * about it.  Also, remember this multicast address so that
	 * we can delete them on unconfigure.
	 */
	MALLOC(mc, struct vlan_mc_entry *, sizeof(struct vlan_mc_entry),
	    M_DEVBUF, M_NOWAIT);
	if (mc == NULL) {
		error = ENOMEM;
		goto alloc_failed;
	}

	/*
	 * As ether_addmulti() returns ENETRESET, following two
	 * statement shouldn't fail.
	 */
	(void)ether_multiaddr(sa, addrlo, addrhi);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ec, mc->mc_enm);
	memcpy(&mc->mc_addr, sa, sa->sa_len);
	LIST_INSERT_HEAD(&ifv->ifv_mc_listhead, mc, mc_entries);

	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCADDMULTI,
	    (caddr_t)ifr);
	if (error != 0)
		goto ioctl_failed;
	return (error);

 ioctl_failed:
	LIST_REMOVE(mc, mc_entries);
	FREE(mc, M_DEVBUF);
 alloc_failed:
	(void)ether_delmulti(sa, &ifv->ifv_ec);
	return (error);
}

static int
vlan_ether_delmulti(struct ifvlan *ifv, struct ifreq *ifr)
{
	const struct sockaddr *sa = ifreq_getaddr(SIOCDELMULTI, ifr);
	struct ether_multi *enm;
	struct vlan_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	/*
	 * Find a key to lookup vlan_mc_entry.  We have to do this
	 * before calling ether_delmulti for obvious reason.
	 */
	if ((error = ether_multiaddr(sa, addrlo, addrhi)) != 0)
		return (error);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ec, enm);

	error = ether_delmulti(sa, &ifv->ifv_ec);
	if (error != ENETRESET)
		return (error);

	/* We no longer use this multicast address.  Tell parent so. */
	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCDELMULTI,
	    (caddr_t)ifr);
	if (error == 0) {
		/* And forget about this address. */
		for (mc = LIST_FIRST(&ifv->ifv_mc_listhead); mc != NULL;
		    mc = LIST_NEXT(mc, mc_entries)) {
			if (mc->mc_enm == enm) {
				LIST_REMOVE(mc, mc_entries);
				FREE(mc, M_DEVBUF);
				break;
			}
		}
		KASSERT(mc != NULL);
	} else
		(void)ether_addmulti(sa, &ifv->ifv_ec);
	return (error);
}

/*
 * Delete any multicast address we have asked to add from parent
 * interface.  Called when the vlan is being unconfigured.
 */
static void
vlan_ether_purgemulti(struct ifvlan *ifv)
{
	struct ifnet *ifp = ifv->ifv_p;		/* Parent. */
	struct vlan_mc_entry *mc;
	union {
		struct ifreq ifreq;
		struct {
			char ifr_name[IFNAMSIZ];
			struct sockaddr_storage ifr_ss;
		} ifreq_storage;
	} ifreq;
	struct ifreq *ifr = &ifreq.ifreq;

	memcpy(ifr->ifr_name, ifp->if_xname, IFNAMSIZ);
	while ((mc = LIST_FIRST(&ifv->ifv_mc_listhead)) != NULL) {
		ifreq_setaddr(SIOCDELMULTI, ifr,
		    (const struct sockaddr *)&mc->mc_addr);
		(void)(*ifp->if_ioctl)(ifp, SIOCDELMULTI, (caddr_t)ifr);
		LIST_REMOVE(mc, mc_entries);
		FREE(mc, M_DEVBUF);
	}
}

static void
vlan_start(struct ifnet *ifp)
{
	struct ifvlan *ifv = ifp->if_softc;
	struct ifnet *p = ifv->ifv_p;
	struct ethercom *ec = (void *) ifv->ifv_p;
	struct mbuf *m;
	int error;
#ifdef __QNXNTO__
	int first = 1;
	struct nw_work_thread *wtp = WTP;
#endif
	ALTQ_DECL(struct altq_pktattr pktattr;)

	ifp->if_flags |= IFF_OACTIVE;

	for (;;) {
#ifdef __QNXNTO__
		if (first == 0) /* Already locked on entry */
			NW_SIGLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
		first = 0;
#endif
		IFQ_DEQUEUE(&ifp->if_snd, m);
#ifdef __QNXNTO__
		NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
#endif
		if (m == NULL)
			break;

#ifdef ALTQ
		/*
		 * If ALTQ is enabled on the parent interface, do
		 * classification; the queueing discipline might
		 * not require classification, but might require
		 * the address family/header pointer in the pktattr.
		 */
		if (ALTQ_IS_ENABLED(&p->if_snd)) {
			switch (p->if_type) {
			case IFT_ETHER:
				altq_etherclassify(&p->if_snd, m, &pktattr);
				break;
#ifdef DIAGNOSTIC
			default:
				panic("vlan_start: impossible (altq)");
#endif
			}
		}
#endif /* ALTQ */

#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m);
#endif
		/*
		 * If the parent can insert the tag itself, just mark
		 * the tag in the mbuf header.
		 */
#ifdef __QNXNTO__
		if (p->if_type == IFT_ETHER) {
		u_int new_ifv_tag;
		struct m_tag *vlanprio_tag = m_tag_find(m, PACKET_TAG_VLANPRIO, NULL);
		if (vlanprio_tag) {
			u_int vlanprio = (u_int)(*(uint8_t *)(vlanprio_tag + 1)); /* tag must be between 0 - 7 */
			new_ifv_tag = EVL_VLANOFTAG(ifv->ifv_tag) | (vlanprio & 7) << 13;
		}
		/*
		 * XXX Bypass hardware tagging if the vlan's parent is part of a bridge
		 */
		if ((ec->ec_capabilities & ETHERCAP_VLAN_HWTAGGING) &&
			!ifv->ifv_p->if_bridge_tx) {
#else
		if (ec->ec_capabilities & ETHERCAP_VLAN_HWTAGGING) {
#endif
			struct m_tag *mtag;

			mtag = m_tag_get(PACKET_TAG_VLAN, sizeof(u_int),
			    M_NOWAIT);
			if (mtag == NULL) {
				ifp->if_oerrors++;
				m_freem(m);
				continue;
			}
			if (vlanprio_tag) 
				*(u_int *)(mtag + 1) = new_ifv_tag;
			else
				*(u_int *)(mtag + 1) = ifv->ifv_tag;
			m_tag_prepend(m, mtag);
		} else {
			/*
			 * insert the tag ourselves
			 */
			M_PREPEND(m, ifv->ifv_encaplen, M_DONTWAIT);
			if (m == NULL) {
				printf("%s: unable to prepend encap header",
				    ifv->ifv_p->if_xname);
				ifp->if_oerrors++;
				continue;
			}

			switch (p->if_type) {
			case IFT_ETHER:
			    {
				struct ether_vlan_header *evl;

				if (m->m_len < sizeof(struct ether_vlan_header))
					m = m_pullup(m,
					    sizeof(struct ether_vlan_header));
				if (m == NULL) {
					printf("%s: unable to pullup encap "
					    "header", ifv->ifv_p->if_xname);
					ifp->if_oerrors++;
					continue;
				}

				/*
				 * Transform the Ethernet header into an
				 * Ethernet header with 802.1Q encapsulation.
				 */
				memmove(mtod(m, caddr_t),
				    mtod(m, caddr_t) + ifv->ifv_encaplen,
				    sizeof(struct ether_header));
				evl = mtod(m, struct ether_vlan_header *);
				evl->evl_proto = evl->evl_encap_proto;
				evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
				if (vlanprio_tag)
					evl->evl_tag = htons(new_ifv_tag);
				else
					evl->evl_tag = htons(ifv->ifv_tag);

				/*
				 * To cater for VLAN-aware layer 2 ethernet
				 * switches which may need to strip the tag
				 * before forwarding the packet, make sure
				 * the packet+tag is at least 68 bytes long.
				 * This is necessary because our parent will
				 * only pad to 64 bytes (ETHER_MIN_LEN) and
				 * some switches will not pad by themselves
				 * after deleting a tag.
				 */
				if (m->m_pkthdr.len <
				    (ETHER_MIN_LEN + ETHER_VLAN_ENCAP_LEN)) {
					m_copyback(m, m->m_pkthdr.len,
					    (ETHER_MIN_LEN +
					     ETHER_VLAN_ENCAP_LEN) -
					     m->m_pkthdr.len,
					    vlan_zero_pad_buff);
				}
				break;
			    }

#ifdef DIAGNOSTIC
			default:
				panic("vlan_start: impossible");
#endif
			}
		}
#ifdef __QNXNTO__
		}

		if (ifv->ifv_p->if_bridge_tx && wtp->flags & WT_BRIDGE) {
			/*
			 * XXX Get to bridge output if the parent has a bridge.
			 */
			((struct ifnet*)ifv->ifv_p->if_bridge_tx)->if_output(ifv->ifv_p, m, NULL,
				NULL);
			ifp->if_opackets++;
			continue;
		}
#endif
		/*
		 * Send it, precisely as the parent's output routine
		 * would have.  We are already running at splnet.
		 */
#ifdef __QNXNTO__
		NW_SIGLOCK_P(&p->if_snd_ex, iopkt_selfp, wtp);

		if (p->if_start == NULL) {
			/*
			 *  XXX QNX IPSEC: needed to catch and drop traffic destined to an ipsec tunnel that does not get slurped and encrypted
			 *  when the underlying interface is software-only (ppp, tun etc) and does not set if_start()
			 */
			ifp->if_oerrors++;
			NW_SIGUNLOCK_P(&p->if_snd_ex, iopkt_selfp, wtp);
			m_freem(m);
			continue;
		}
#endif
		IFQ_ENQUEUE(&p->if_snd, m, &pktattr, error);
		if (error) {
			/* mbuf is already freed */
			ifp->if_oerrors++;
#ifdef __QNXNTO__
			NW_SIGUNLOCK_P(&p->if_snd_ex, iopkt_selfp, wtp);
#endif
			continue;
		}

		ifp->if_opackets++;
		if ((p->if_flags & (IFF_RUNNING|IFF_OACTIVE)) == IFF_RUNNING)
			(*p->if_start)(p);
#ifdef __QNXNTO__
		else
			NW_SIGUNLOCK_P(&p->if_snd_ex, iopkt_selfp, wtp);
#endif
	}

	ifp->if_flags &= ~IFF_OACTIVE;
}

/*
 * Given an Ethernet frame, find a valid vlan interface corresponding to the
 * given source interface and tag, then run the real packet through the
 * parent's input routine.
 */
void
vlan_input(struct ifnet *ifp, struct mbuf *m)
{
	struct ifvlan *ifv;
	u_int tag;
	struct m_tag *mtag;

	mtag = m_tag_find(m, PACKET_TAG_VLAN, NULL);
	if (mtag != NULL) {
		/* m contains a normal ethernet frame, the tag is in mtag */
		tag = EVL_VLANOFTAG(*(u_int *)(mtag + 1));
		m_tag_delete(m, mtag);
	} else {
		switch (ifp->if_type) {
		case IFT_ETHER:
		    {
			struct ether_vlan_header *evl;

			if (m->m_len < sizeof(struct ether_vlan_header) &&
			    (m = m_pullup(m,
			     sizeof(struct ether_vlan_header))) == NULL) {
				printf("%s: no memory for VLAN header, "
				    "dropping packet.\n", ifp->if_xname);
				return;
			}
			evl = mtod(m, struct ether_vlan_header *);
			KASSERT(ntohs(evl->evl_encap_proto) == ETHERTYPE_VLAN);

			tag = EVL_VLANOFTAG(ntohs(evl->evl_tag));

			/*
			 * Restore the original ethertype.  We'll remove
			 * the encapsulation after we've found the vlan
			 * interface corresponding to the tag.
			 */
			evl->evl_encap_proto = evl->evl_proto;
			break;
		    }

		default:
			tag = (u_int) -1;	/* XXX GCC */
#ifdef DIAGNOSTIC
			panic("vlan_input: impossible");
#endif
		}
	}

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	    ifv = LIST_NEXT(ifv, ifv_list))
		if (ifp == ifv->ifv_p && tag == EVL_VLANOFTAG(ifv->ifv_tag))
			break;

	if (ifv == NULL ||
	    (ifv->ifv_if.if_flags & (IFF_UP|IFF_RUNNING)) !=
	     (IFF_UP|IFF_RUNNING)) {
		m_freem(m);
		ifp->if_noproto++;
		return;
	}

	/*
	 * Now, remove the encapsulation header.  The original
	 * header has already been fixed up above.
	 */
	if (mtag == NULL) {
		memmove(mtod(m, caddr_t) + ifv->ifv_encaplen,
		    mtod(m, caddr_t), sizeof(struct ether_header));
		m_adj(m, ifv->ifv_encaplen);
	}

	m->m_pkthdr.rcvif = &ifv->ifv_if;
	ifv->ifv_if.if_ipackets++;

#if NBPFILTER > 0
	if (ifv->ifv_if.if_bpf)
		bpf_mtap(ifv->ifv_if.if_bpf, m);
#endif

	/* Pass it back through the parent's input routine. */
	(*ifp->if_input)(&ifv->ifv_if, m);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_vlan.c $ $Rev: 892983 $")
#endif
