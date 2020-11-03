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


/*	$NetBSD: if_bridge.c,v 1.46 2006/11/23 04:07:07 rpaulo Exp $	*/

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
 * OpenBSD: if_bridge.c,v 1.60 2001/06/15 03:38:33 itojun Exp
 */

/*
 * Network interface bridge support.
 *
 * TODO:
 *
 *	- Currently only supports Ethernet-like interfaces (Ethernet,
 *	  802.11, VLANs on Ethernet, etc.)  Figure out a nice way
 *	  to bridge other types of interfaces (FDDI-FDDI, and maybe
 *	  consider heterogenous bridges).
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_bridge.c,v 1.46 2006/11/23 04:07:07 rpaulo Exp $");

#include "opt_bridge_ipf.h"
#include "opt_inet.h"
#include "opt_pfil_hooks.h"
#include "bpfilter.h"

#ifdef __QNXNTO__
#include "opt_ionet_compat.h"
#include <malloc.h> /* The QNX one */
#include <sys/syslog.h>
#include <nw_thread.h>
#include <netinet/in.h>
#endif
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/kauth.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>

#include <net/if_ether.h>
#include <net/if_bridgevar.h>

#if defined(BRIDGE_IPF) && defined(PFIL_HOOKS)
/* Used for bridge_ip[6]_checkbasic */
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>

#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#endif /* BRIDGE_IPF && PFIL_HOOKS */

#if defined(__QNXNTO__) && defined(INET6)
#include <netinet6/nd6.h>
#endif

/*
 * Size of the route hash table.  Must be a power of two.
 */
#ifndef BRIDGE_RTHASH_SIZE
#define	BRIDGE_RTHASH_SIZE		1024
#endif

#define	BRIDGE_RTHASH_MASK		(BRIDGE_RTHASH_SIZE - 1)

#include "carp.h"
#if NCARP > 0
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_carp.h>
#endif

/*
 * Maximum number of addresses to cache.
 */
#ifndef BRIDGE_RTABLE_MAX
#define	BRIDGE_RTABLE_MAX		100
#endif

/*
 * Spanning tree defaults.
 */
#define	BSTP_DEFAULT_MAX_AGE		(20 * 256)
#define	BSTP_DEFAULT_HELLO_TIME		(2 * 256)
#define	BSTP_DEFAULT_FORWARD_DELAY	(15 * 256)
#define	BSTP_DEFAULT_HOLD_TIME		(1 * 256)
#define	BSTP_DEFAULT_BRIDGE_PRIORITY	0x8000
#define	BSTP_DEFAULT_PORT_PRIORITY	0x80
#define	BSTP_DEFAULT_PATH_COST		55

/*
 * Timeout (in seconds) for entries learned dynamically.
 */
#ifndef BRIDGE_RTABLE_TIMEOUT
#define	BRIDGE_RTABLE_TIMEOUT		(20 * 60)	/* same as ARP */
#endif

/*
 * Number of seconds between walks of the route list.
 */
#ifndef BRIDGE_RTABLE_PRUNE_PERIOD
#define	BRIDGE_RTABLE_PRUNE_PERIOD	(5 * 60)
#endif

#ifdef __QNXNTO__
#ifndef VARIANT_uni
struct tpass_reminfo brt_tpass_reminfo;
struct tpass_reminfo bif_tpass_reminfo;
static pthread_mutex_t bridge_ex;
static int bridge_initialized;

static void bridge_walk_destroy_qs(struct bridge_softc_thread *, int);

#endif
#endif /* __QNXNTO__ */
int	bridge_rtable_prune_period = BRIDGE_RTABLE_PRUNE_PERIOD;

static struct pool bridge_rtnode_pool;

void	bridgeattach(int);

static int	bridge_clone_create(struct if_clone *, int);
static int	bridge_clone_destroy(struct ifnet *);

static int	bridge_ioctl(struct ifnet *, u_long, caddr_t);
static int	bridge_init(struct ifnet *);
static void	bridge_stop(struct ifnet *, int);
static void	bridge_start(struct ifnet *);

static void	bridge_forward(struct bridge_softc *, struct mbuf *m);

static void	bridge_timer(void *);

static void	bridge_broadcast(struct bridge_softc *, struct ifnet *,
				 struct mbuf *);

static int	bridge_rtupdate(struct bridge_softc *, const uint8_t *,
				struct ifnet *, int, uint8_t);
static struct ifnet *bridge_rtlookup(struct bridge_softc *, const uint8_t *);
static void	bridge_rttrim(struct bridge_softc *);
static void	bridge_rtage(struct bridge_softc *);
static void	bridge_rtflush(struct bridge_softc *, int);
static int	bridge_rtdaddr(struct bridge_softc *, const uint8_t *);
static void	bridge_rtdelete(struct bridge_softc *, struct ifnet *ifp);

static int	bridge_rtable_init(struct bridge_softc *);
static void	bridge_rtable_fini(struct bridge_softc *);

static struct bridge_rtnode *bridge_rtnode_lookup(struct bridge_softc *,
						  const uint8_t *);
static int	bridge_rtnode_insert(struct bridge_softc *,
				     struct bridge_rtnode *);
static void	bridge_rtnode_destroy(struct bridge_softc *,
				      struct bridge_rtnode *);

static struct bridge_iflist *bridge_lookup_member(struct bridge_softc *,
						  const char *name);
#ifndef __QNXNTO__
static struct bridge_iflist *bridge_lookup_member_if(struct bridge_softc *,
						     struct ifnet *ifp);
#endif
static void	bridge_delete_member(struct bridge_softc *,
				     struct bridge_iflist *);

static int	bridge_ioctl_add(struct bridge_softc *, void *);
static int	bridge_ioctl_del(struct bridge_softc *, void *);
static int	bridge_ioctl_gifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_sifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_scache(struct bridge_softc *, void *);
static int	bridge_ioctl_gcache(struct bridge_softc *, void *);
static int	bridge_ioctl_gifs(struct bridge_softc *, void *);
static int	bridge_ioctl_rts(struct bridge_softc *, void *);
static int	bridge_ioctl_saddr(struct bridge_softc *, void *);
static int	bridge_ioctl_sto(struct bridge_softc *, void *);
static int	bridge_ioctl_gto(struct bridge_softc *, void *);
static int	bridge_ioctl_daddr(struct bridge_softc *, void *);
static int	bridge_ioctl_flush(struct bridge_softc *, void *);
static int	bridge_ioctl_gpri(struct bridge_softc *, void *);
static int	bridge_ioctl_spri(struct bridge_softc *, void *);
static int	bridge_ioctl_ght(struct bridge_softc *, void *);
static int	bridge_ioctl_sht(struct bridge_softc *, void *);
static int	bridge_ioctl_gfd(struct bridge_softc *, void *);
static int	bridge_ioctl_sfd(struct bridge_softc *, void *);
static int	bridge_ioctl_gma(struct bridge_softc *, void *);
static int	bridge_ioctl_sma(struct bridge_softc *, void *);
static int	bridge_ioctl_sifprio(struct bridge_softc *, void *);
static int	bridge_ioctl_sifcost(struct bridge_softc *, void *);
#if defined(BRIDGE_IPF) && defined(PFIL_HOOKS)
static int	bridge_ioctl_gfilt(struct bridge_softc *, void *);
static int	bridge_ioctl_sfilt(struct bridge_softc *, void *);
static int	bridge_ipf(void *, struct mbuf **, struct ifnet *, int);
static int	bridge_ip_checkbasic(struct mbuf **mp);
# ifdef INET6
static int	bridge_ip6_checkbasic(struct mbuf **mp);
# endif /* INET6 */
#endif /* BRIDGE_IPF && PFIL_HOOKS */

#ifdef __QNXNTO__
#ifndef DIAGNOSTIC
static void	bridge_rtupdate_self(struct bridge_softc *, const uint8_t *,
	struct ifnet *, int, uint8_t, struct nw_work_thread *wtp);
static struct ifnet *bridge_rtlookup_self(struct bridge_softc *, const uint8_t *,
	struct nw_work_thread *);
static struct bridge_rtnode *bridge_rtnode_lookup_self(struct bridge_softc *,
	    const uint8_t *, struct nw_work_thread *);
static int	bridge_rtnode_insert_self(struct bridge_softc *,
    struct bridge_rtnode *, struct nw_work_thread *);
static struct bridge_iflist *bridge_lookup_member_if_self(struct bridge_softc *,
	struct ifnet *, struct nw_work_thread *);
#else /* DIAGNOSTIC */
static void	_bridge_rtupdate_self(struct bridge_softc *, const uint8_t *,
	    struct ifnet *, int, uint8_t, struct nw_work_thread *wtp, int);
#define bridge_rtupdate_self(a, b, c, d, e, f)		\
	_bridge_rtupdate_self((a), (b), (c), (d), (e), (f), __LINE__)
static struct ifnet *_bridge_rtlookup_self(struct bridge_softc *, const uint8_t *,
	struct nw_work_thread *, int);
#define bridge_rtlookup_self(a, b, c)			\
	_bridge_rtlookup_self((a), (b), (c), __LINE__)
static struct bridge_rtnode *_bridge_rtnode_lookup_self(struct bridge_softc *,
	    const uint8_t *, struct nw_work_thread *, int);
#define bridge_rtnode_lookup_self(a, b, c)		\
	_bridge_rtnode_lookup_self((a), (b), (c), __LINE__)
static int	_bridge_rtnode_insert_self(struct bridge_softc *,
    struct bridge_rtnode *, struct nw_work_thread *, int);
#define bridge_rtnode_insert_self(a, b, c)		\
	_bridge_rtnode_insert_self((a), (b), (c), __LINE__)
static struct bridge_iflist *_bridge_lookup_member_if_self(struct bridge_softc *,
	    struct ifnet *, struct nw_work_thread *, int);
#define bridge_lookup_member_if_self(a, b, c)		\
	_bridge_lookup_member_if_self((a), (b), (c), __LINE__)
#endif /* DIAGNOSTIC */
#endif /* __QNXNTO__ */

struct bridge_control {
	int	(*bc_func)(struct bridge_softc *, void *);
	int	bc_argsize;
	int	bc_flags;
};

#define	BC_F_COPYIN		0x01	/* copy arguments in */
#define	BC_F_COPYOUT		0x02	/* copy arguments out */
#define	BC_F_SUSER		0x04	/* do super-user check */

static const struct bridge_control bridge_control_table[] = {
	{ bridge_ioctl_add,		sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_del,		sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gifflags,	sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_sifflags,	sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_scache,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gcache,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },

	{ bridge_ioctl_gifs,		sizeof(struct ifbifconf),
	  BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_rts,		sizeof(struct ifbaconf),
	  BC_F_COPYIN|BC_F_COPYOUT },

	{ bridge_ioctl_saddr,		sizeof(struct ifbareq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sto,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gto,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },

	{ bridge_ioctl_daddr,		sizeof(struct ifbareq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_flush,		sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gpri,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },
	{ bridge_ioctl_spri,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_ght,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },
	{ bridge_ioctl_sht,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gfd,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },
	{ bridge_ioctl_sfd,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gma,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },
	{ bridge_ioctl_sma,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifprio,		sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifcost,		sizeof(struct ifbreq),
	  BC_F_COPYIN|BC_F_SUSER },
#if defined(BRIDGE_IPF) && defined(PFIL_HOOKS)
	{ bridge_ioctl_gfilt,		sizeof(struct ifbrparam),
	  BC_F_COPYOUT },
	{ bridge_ioctl_sfilt,		sizeof(struct ifbrparam),
	  BC_F_COPYIN|BC_F_SUSER },
#endif /* BRIDGE_IPF && PFIL_HOOKS */
};
static const int bridge_control_table_size =
    sizeof(bridge_control_table) / sizeof(bridge_control_table[0]);

static LIST_HEAD(, bridge_softc) bridge_list;

static struct if_clone bridge_cloner =
    IF_CLONE_INITIALIZER("bridge", bridge_clone_create, bridge_clone_destroy);

#ifdef __QNXNTO__
struct bridge_threadinfo {
	int	brti_idx;	/* idx as first member!  See union in nw_work_thread */
	int	brti_inuse;
}
#ifndef VARIANT_uni
__attribute__((aligned (NET_CACHELINE_SIZE)))
#endif
;

struct bridge_threadinfo *bridge_threads;

struct ifqueue bridgeintrq;
void bridge_intr_input(void *);

int brt_pool_item_size;
int bif_malloc_item_size;

static void bif_thread_decref(struct tpass_entry *tpass, int self);
static void brt_thread_decref(struct tpass_entry *tpass, int self);

#ifndef VARIANT_uni
#ifndef DIAGNOSTIC
void bridge_refresh_private_self(struct bridge_softc *,
    struct nw_work_thread *);
#else
void _bridge_refresh_private_self(struct bridge_softc *,
    struct nw_work_thread *, int);
#define bridge_refresh_private_self(a, b)	\
	_bridge_refresh_private_self((a), (b), __LINE__)
#endif
#endif


struct rtupdate_args {
	struct bridge_softc	*rup_sc;
	int			rup_setflags;
	uint8_t			rup_flags;
	uint8_t			rup_ether_dhost[ETHER_ADDR_LEN];
};


#ifndef NDEBUG
static int
bridge_thread_isempty(struct bridge_threadinfo *brtip)
{
	int idx;
	struct bridge_softc *sc;
	struct bridge_softc_thread *bscth;

	/*
	 * Entries on the create Q are OK.
	 * Other stragglers means the previous
	 * thread didn't clean up on exit.
	 */

	idx = brtip->brti_idx;

	LIST_FOREACH(sc, &bridge_list, sc_list) {
		bscth = &sc->sc_thread[idx];

		if (!LIST_EMPTY(&bscth->sc_th_iftpq.tpq_destroy_q) ||
		    !LIST_EMPTY(&bscth->sc_th_rttpq.tpq_destroy_q) ||
		    !LIST_EMPTY(&bscth->sc_th_iflist) ||
		    !LIST_EMPTY(&bscth->sc_th_rtlist))
			return 0;
	}

	return 1;
}
#endif

/*
 * This is called before the first thread is
 * created so we need to use the standard malloc / free.
 */
int
bridge_pre_main_init(void)
{
	size_t			size;
	struct nw_stk_ctl	*sctlp;
	int			lim, i;

	sctlp = &stk_ctl;
	lim = sctlp->nthreads_flow_max;

	size = lim * sizeof(*bridge_threads);
	if ((bridge_threads = (malloc)(size)) == NULL)
		return ENOMEM;

	memset(bridge_threads, 0x00, size);
	for (i = 0; i < lim; i++)
		bridge_threads[i].brti_idx = i;

	return EOK;
}

void
bridge_pre_main_fini(void)
{
	(free)(bridge_threads);
}


/* May be called by start thread (no context) so watch logging / panic */
int
bridge_register(struct bridge_threadinfo **retp)
{
	struct nw_stk_ctl		*sctlp;
	int				i;
	struct bridge_threadinfo	*brtip;

	sctlp = &stk_ctl;

	if (!ISSTART && !ISSTACK)
		return EPERM;

	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		brtip = &bridge_threads[i];
		if (brtip->brti_inuse == 0) {
#ifndef NDEBUG
			if (bridge_thread_isempty(brtip) == 0)
			    log(LOG_WARNING, "bridge stragglers");
#endif
			brtip->brti_inuse = 1;
			*retp = brtip;
			return EOK;
		}
	}
	return EAGAIN;
}




/* May be called by start thread (no context) so watch logging / panic */
int
bridge_deregister(struct bridge_threadinfo *brtip)
{
	struct nw_stk_ctl		*sctlp;
	int				idx;

	if (!ISSTART && !ISSTACK)
		return EPERM;

	sctlp = &stk_ctl;

	idx = brtip->brti_idx;

	if ((unsigned)idx > sctlp->nthreads_flow_max ||
	    &bridge_threads[idx] != brtip || brtip->brti_inuse == 0)
		return EINVAL;

#ifndef VARIANT_uni
	if (bridge_initialized) {
		bridge_destroy(brtip);
	}
#endif

	brtip->brti_inuse = 0;

	return EOK;
}


#ifndef VARIANT_uni
int
bridge_destroy(struct bridge_threadinfo *brtip)
{
	int				idx;
	struct bridge_softc		*sc;
	struct bridge_softc_thread	*bscth;
	struct bridge_iflist		*bif;
	struct bridge_rtnode		*brt;
	struct nw_work_thread		*wtp;


	idx = brtip->brti_idx;

	wtp = WTP;
	NW_SIGLOCK_P(&bridge_ex, iopkt_selfp, wtp);

	LIST_FOREACH(sc, &bridge_list, sc_list) {
		bscth = &sc->sc_thread[idx];

		/*
		 * We're walking another thread's qs but it's going away
		 * and therefore shouldn't be looking at them.
		 */
		bridge_walk_destroy_qs(bscth, idx);

		/*
		 * We move them back to the create q to simulate
		 * the dying thread never having seen the request
		 * to seed its private cache.  This avoids having to
		 * remove / reseed the entries from every thread.
		 */
		while ((bif = LIST_FIRST(&bscth->sc_th_iflist)) != NULL) {
			bif_thread_decref(&bif->bif_tpe, idx);

			LIST_INSERT_HEAD(&bscth->sc_th_iftpq.tpq_create_q, bif,
			    bif_thread[idx].bif_th_passlist);
			bif->bif_tpe.tpe_nthreads_creating++;
			bscth->sc_th_iftpq.tpq_items_changing++;
		}

		while ((brt = LIST_FIRST(&bscth->sc_th_rtlist)) != NULL) {
			brt_thread_decref(&brt->brt_tpe, idx);

			LIST_INSERT_HEAD(&bscth->sc_th_rttpq.tpq_create_q, brt,
			    brt_thread[idx].brt_th_passlist);
			brt->brt_tpe.tpe_nthreads_creating++;
			bscth->sc_th_rttpq.tpq_items_changing++;
		}
	}

	NW_SIGUNLOCK_P(&bridge_ex, iopkt_selfp, wtp);
	return EOK;
}
#endif /* VARIANT_uni */

/*
 * The point of this is to always have the 
 * stack do the initial create / destroy so 
 * that its master list is in fact the master.
 * Plus there's some assumptions when items
 * are initially created that we are the stack
 * with the signal locked and we can thereby
 * stuff our per thread cache up front.  This
 * also lets the stack access its master lists
 * without any locks.
 */
void
#ifndef DIAGNOSTIC
bridge_rtupdate_self(struct bridge_softc *sc, const uint8_t *dst,
    struct ifnet *dst_if, int setflags, uint8_t flags, struct nw_work_thread *wtp)
#else
_bridge_rtupdate_self(struct bridge_softc *sc, const uint8_t *dst,
    struct ifnet *dst_if, int setflags, uint8_t flags, struct nw_work_thread *wtp,
    int line_from)
#endif
{
	struct nw_stk_ctl *sctlp = &stk_ctl;
	struct ifqueue *inq;
	struct mbuf *m;
	struct rtupdate_args *rtup;
	struct bridge_threadinfo *brtip;
	int self;
	struct bridge_rtnode *brt;

	brtip = wtp->wt_brctl;

	self = brtip->brti_idx;
	BRIDGE_SELF_ENTER(wtp, line_from);
	brt  = bridge_rtnode_lookup_self(sc, dst, wtp);
	/*
	 * The high runner is probably that it's found or we're
	 * maxed out so do this up front.  This probably introduces
	 * a small window where our private thread cache is out of
	 * sync with the master but we should have done a
	 * bridge_refresh_private_self() recently for all places where
	 * this func is called (shouldn't be wildly out).  The
	 * other downside is that if we continue with the update,
	 * there's another similar check in bridge_rtupdate().
	 */
	if ((sc->sc_brtcnt >= sc->sc_brtmax) ||
	    ((brt != NULL) && (brt->brt_ifp == dst_if) &&
	    (((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) &&
	    (brt->brt_expire > time_uptime)))) {
		BRIDGE_SELF_EXIT(wtp);
		return;
	}
	BRIDGE_SELF_EXIT(wtp);

	if ((m = m_gethdr_wtp(MT_DATA, M_DONTWAIT, wtp)) == NULL)
		return;

	m->m_pkthdr.rcvif = dst_if;
	rtup = mtod(m, struct rtupdate_args *);
	rtup->rup_sc = sc;
	rtup->rup_setflags = setflags;
	rtup->rup_flags = flags;
	memcpy(rtup->rup_ether_dhost, dst, ETHER_ADDR_LEN);

	/*
	 * queue the packet on bridgeintrq.  This
	 * in turn causes the stack to come in
	 * through bridge_intr_input() when it
	 * processes the packet which in turn
	 * calls bridge_rtupdate() (stack's non
	 * interrupt context version)
	 */

	inq = &bridgeintrq;

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		m_freem(m);
	} else {
		IF_ENQUEUE(inq, m);

		if (inq->ifq_len == 1) {
			if (sctlp->pkt_rx_q == NULL) {
				sctlp->pkt_rx_q = inq;
			}
			else {
				/* make this new one the tail */
				inq->ifq_next = sctlp->pkt_rx_q;
				inq->ifq_prev = sctlp->pkt_rx_q->ifq_prev;
				*sctlp->pkt_rx_q->ifq_prev = inq;
				sctlp->pkt_rx_q->ifq_prev  = &inq->ifq_next;
			}
		}
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}
	
}

static void
bif_thread_decref(struct tpass_entry *tpass, int idx)
{
	struct bridge_iflist *bif;

	bif = (struct bridge_iflist *)tpass;
	LIST_REMOVE(bif, bif_thread[idx].bif_th_list);
}

static void
brt_thread_decref(struct tpass_entry *tpass, int idx)
{
	struct bridge_rtnode *brt;

	brt = (struct bridge_rtnode *)tpass;
	LIST_REMOVE(brt, brt_thread[idx].brt_th_list);
	LIST_REMOVE(brt, brt_thread[idx].brt_th_hash);
}

void
bridge_intr_input(void *arg)
{
	struct rtupdate_args *rup;
	struct mbuf *m;

	m = arg;

	rup = mtod(m, struct rtupdate_args *);
	bridge_rtupdate(rup->rup_sc, rup->rup_ether_dhost, m->m_pkthdr.rcvif,
	    rup->rup_setflags, rup->rup_flags);
	m_freem(m);
}


static __inline void
bif_start_rem(struct bridge_iflist *bif, struct bridge_softc *sc, int self,
    struct nw_work_thread *wtp)
{
#ifndef VARIANT_uni
	struct bridge_iflist_thread *bifth;
	union iflist_passq return_q;

	tpass_start_rem(&bif->bif_tpe,
	    &sc->sc_thread[0].sc_th_iftpqu.tpq_private,
	    &return_q.tpq_private, self, &bif_tpass_reminfo);


	while ((bif = LIST_FIRST(&return_q.tpq_local.tpq_destroy_q)) != NULL) {
		bifth = &bif->bif_thread[self];

		LIST_FIRST(&return_q.tpq_local.tpq_destroy_q) =
		    LIST_NEXT(bifth, bif_th_passlist);
		BIF_MARK_OFFLIST(bifth);

		return_q.tpq_local.tpq_items_changing--;
		free(bif, M_DEVBUF);
	}
#else 
	NW_SIGHOLD_P(wtp);
	/*
	 * The work done by the bif_thread_decref() passed
	 * to tpass_start_rem() in non uni variant above.
	 */
	LIST_REMOVE(bif, bif_thread[self].bif_th_list);
	NW_SIGUNHOLD_P(wtp);

	free(bif, M_DEVBUF);
#endif
}

static __inline void
brt_start_rem(struct bridge_rtnode *brt, struct bridge_softc *sc, int self,
    struct nw_work_thread *wtp)
{
#ifndef VARIANT_uni
	struct bridge_rtnode_thread *brtth;
	union rtnode_passq return_q;

	tpass_start_rem(&brt->brt_tpe,
	    &sc->sc_thread[0].sc_th_rttpqu.tpq_private,
	    &return_q.tpq_private, self, &brt_tpass_reminfo);

	while ((brt = LIST_FIRST(&return_q.tpq_local.tpq_destroy_q)) != NULL) {
		brtth = &brt->brt_thread[self];

		LIST_FIRST(&return_q.tpq_local.tpq_destroy_q) =
		    LIST_NEXT(brtth, brt_th_passlist);
		BRT_MARK_OFFLIST(brtth);

		return_q.tpq_local.tpq_items_changing--;
		pool_put(&bridge_rtnode_pool, brt);
	}
#else
	NW_SIGHOLD_P(wtp);
	/*
	 * The work done by the brt_thread_decref() passed
	 * to tpass_start_rem() in non uni variant above.
	 */
	LIST_REMOVE(brt, brt_thread[self].brt_th_list);
	LIST_REMOVE(brt, brt_thread[self].brt_th_hash);
	NW_SIGUNHOLD_P(wtp);

	pool_put(&bridge_rtnode_pool, brt);
#endif
}

#endif /* __QNXNTO__ */
/*
 * bridgeattach:
 *
 *	Pseudo-device attach routine.
 */
void
bridgeattach(int n)
{

#ifndef __QNXNTO__
	pool_init(&bridge_rtnode_pool, sizeof(struct bridge_rtnode),
	    0, 0, 0, "brtpl", NULL);
#else
	struct bridge_rtnode *brt;
	struct bridge_iflist *bif;
	struct nw_stk_ctl *sctlp = &stk_ctl;

	brt_pool_item_size = offsetof(struct bridge_rtnode, brt_thread[0]) +
	    sctlp->nthreads_flow_max * sizeof(brt->brt_thread[0]);

	bif_malloc_item_size = offsetof(struct bridge_iflist, bif_thread[0]) +
	    sctlp->nthreads_flow_max * sizeof(bif->bif_thread[0]);


	/* PR_PROTECT so we can free from an interrupt context */
	pool_init(&bridge_rtnode_pool, brt_pool_item_size,
	    0, 0, PR_PROTECT, "brtpl", NULL);
#ifndef VARIANT_uni
	(*iopkt_selfp->ex_init)(&bridge_ex);

	brt_tpass_reminfo.tpr_tlist_first_offset =
	    offsetof(struct bridge_rtnode, brt_thread[0].brt_th_tplu.tpl_private);
	/* The tpass_list entries are in an array of struct bridge_rtnode_thread */
	brt_tpass_reminfo.tpr_tlist_next_offset =
	    sizeof(struct bridge_rtnode_thread);

	/* The tpass_qs entries are in an array of struct bridge_softc_thread */
	brt_tpass_reminfo.tpr_pq_next_offset =
	    sizeof(struct bridge_softc_thread);

	brt_tpass_reminfo.tpr_rem_self = brt_thread_decref;
	brt_tpass_reminfo.tpr_lim = stk_ctl.nthreads_flow_max;
	brt_tpass_reminfo.tpr_mtx = &bridge_ex;


	bif_tpass_reminfo.tpr_tlist_first_offset =
	    offsetof(struct bridge_iflist, bif_thread[0].bif_th_tplu.tpl_private);
	/* The tpass_list entries are in an array of struct bridge_iflist_thread */
	bif_tpass_reminfo.tpr_tlist_next_offset =
	    sizeof(struct bridge_iflist_thread);

	/* The tpass_qs entries are in an array of struct bridge_softc_thread */
	bif_tpass_reminfo.tpr_pq_next_offset =
	    sizeof(struct bridge_softc_thread);

	bif_tpass_reminfo.tpr_rem_self = bif_thread_decref;
	bif_tpass_reminfo.tpr_lim = stk_ctl.nthreads_flow_max;
	bif_tpass_reminfo.tpr_mtx = &bridge_ex;
#endif
	bridgeintrq.ifq_intr   = bridge_intr_input;
	bridgeintrq.ifq_next   = &bridgeintrq;
	bridgeintrq.ifq_prev   = &bridgeintrq.ifq_next;
	bridgeintrq.ifq_maxlen = IFQ_MAXLEN; /* XXX hard value */
	bridge_initialized = 1;
#endif

	LIST_INIT(&bridge_list);
	if_clone_attach(&bridge_cloner);
}

/*
 * bridge_clone_create:
 *
 *	Create a new bridge instance.
 */
static int
bridge_clone_create(struct if_clone *ifc, int unit)
{
	struct bridge_softc *sc;
	struct ifnet *ifp;
	int s;

#ifndef __QNXNTO__
	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK);
	memset(sc, 0, sizeof(*sc));
#else
	int			size_struct, size_all;
	struct nw_stk_ctl	*sctlp = &stk_ctl;
	void			*head;

	size_struct  =  offsetof(struct bridge_softc, sc_thread) + sctlp->nthreads_flow_max * sizeof(sc->sc_thread[0]);
	size_all     = size_struct + NET_CACHELINE_SIZE;
	head = malloc(size_all, M_DEVBUF, M_WAITOK);
	memset(head, 0, size_all);
	sc = NET_CACHELINE_ALIGN(head);
	sc->sc_alloc = head;
#endif
	ifp = &sc->sc_if;

	sc->sc_brtmax = BRIDGE_RTABLE_MAX;
	sc->sc_brttimeout = BRIDGE_RTABLE_TIMEOUT;
	sc->sc_bridge_max_age = BSTP_DEFAULT_MAX_AGE;
	sc->sc_bridge_hello_time = BSTP_DEFAULT_HELLO_TIME;
	sc->sc_bridge_forward_delay = BSTP_DEFAULT_FORWARD_DELAY;
	sc->sc_bridge_priority = BSTP_DEFAULT_BRIDGE_PRIORITY;
	sc->sc_hold_time = BSTP_DEFAULT_HOLD_TIME;
	sc->sc_filter_flags = 0;

	/* Initialize our routing table. */
	bridge_rtable_init(sc);

	callout_init(&sc->sc_brcallout);
	callout_init(&sc->sc_bstpcallout);

	LIST_INIT(&sc->sc_iflist);
#ifdef __QNXNTO__
	for (s = 0; s < sctlp->nthreads_flow_max; s++)
		LIST_INIT(&sc->sc_thread[s].sc_th_iflist);
#endif

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "%s%d", ifc->ifc_name,
	    unit);
	ifp->if_softc = sc;
	ifp->if_mtu = ETHERMTU;
	ifp->if_ioctl = bridge_ioctl;
	ifp->if_output = bridge_output;
	ifp->if_start = bridge_start;
	ifp->if_stop = bridge_stop;
	ifp->if_init = bridge_init;
	ifp->if_type = IFT_BRIDGE;
	ifp->if_addrlen = 0;
	ifp->if_dlt = DLT_EN10MB;
	ifp->if_hdrlen = ETHER_HDR_LEN;

	if_attach(ifp);

	if_alloc_sadl(ifp);

	s = splnet();
	LIST_INSERT_HEAD(&bridge_list, sc, sc_list);
	splx(s);

	return (0);
}

/*
 * bridge_clone_destroy:
 *
 *	Destroy a bridge instance.
 */
static int
bridge_clone_destroy(struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct bridge_iflist *bif;
	int s;
#ifdef __QNXNTO__
	struct nw_stk_ctl *sctlp = &stk_ctl;
	struct nw_work_thread *wtp = WTP;
	struct bridge_rtnode *brt;
	struct tpass_entry *tpass;
	int i;
	struct bridge_iflist_thread *bifth;
	struct bridge_rtnode_thread *brtth;
	struct bridge_softc_thread *bscth;
#ifndef VARIANT_uni
	struct mbuf *m, *prev, *next;
	struct rtupdate_args *rup;
#endif

	if (wtp->am_stack == 0)
		panic("bridge_clone_destroy: not stack.");
	if (wtp->intr_sighot != _ISIG_QUIESCED)
		panic("bridge_clone_destroy: unexpected context.");

#ifndef VARIANT_uni
	prev = NULL;
	for (m = bridgeintrq.ifq_head; m; m = next) {
		next = m->m_nextpkt;

		rup = mtod(m, struct rtupdate_args *);
		if (rup->rup_sc != sc) {
			prev = m;
			continue;
		}

		if (prev)
			prev->m_nextpkt = m->m_nextpkt;
		else
			bridgeintrq.ifq_head = m->m_nextpkt;
		if (bridgeintrq.ifq_tail == m)
			bridgeintrq.ifq_tail = prev;
		bridgeintrq.ifq_len--;

		m->m_nextpkt = NULL;
		m_freem(m);
		IF_DROP(&bridgeintrq);
	}
#endif
#endif

	s = splnet();

	bridge_stop(ifp, 1);

	while ((bif = LIST_FIRST(&sc->sc_iflist)) != NULL)
		bridge_delete_member(sc, bif);

	LIST_REMOVE(sc, sc_list);

	splx(s);

	if_detach(ifp);

	/* Tear down the routing table. */
	bridge_rtable_fini(sc);

#ifndef __QNXNTO__
	free(sc, M_DEVBUF);
#else
	/*
	 * The deletion of the member ifaces and the associated
	 * routes may have only started the process if there are
	 * still per thread references.  However, the head of
	 * the per thread lists (sc) is going away.  We are
	 * quiesced so we can clean everything up here.
	 */

	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		bscth = &sc->sc_thread[i];
#ifdef DIAGNOSTIC
		if (!LIST_EMPTY(&bscth->sc_th_rttpq.tpq_destroy_q) ||
		    !LIST_EMPTY(&bscth->sc_th_iftpq.tpq_destroy_q)) {
			panic("bridge_clone_destroy: clone not cleared\n");
		}
#endif
		while ((brt = LIST_FIRST(&bscth->sc_th_rttpq.tpq_destroy_q)) != NULL) {
			brtth = &brt->brt_thread[i];

			LIST_FIRST(&bscth->sc_th_rttpq.tpq_destroy_q) =
			    LIST_NEXT(brtth, brt_th_passlist);
			BRT_MARK_OFFLIST(brtth);

			bscth->sc_th_rttpq.tpq_items_changing--;

			tpass = &brt->brt_tpe;
			brt_thread_decref(tpass, i);
			
			if (--tpass->tpe_nthreads_destroying == 0)
				pool_put(&bridge_rtnode_pool, brt);
		}

		while ((bif = LIST_FIRST(&bscth->sc_th_iftpq.tpq_destroy_q)) != NULL) {
			bifth = &bif->bif_thread[i];

			LIST_FIRST(&bscth->sc_th_iftpq.tpq_destroy_q) =
			    LIST_NEXT(bifth, bif_th_passlist);
			BIF_MARK_OFFLIST(bifth);

			bscth->sc_th_iftpq.tpq_items_changing--;

			tpass = &bif->bif_tpe;
			bif_thread_decref(tpass, i);
			
			if (--tpass->tpe_nthreads_destroying == 0)
				free(bif, M_DEVBUF);
		}
	}

	free(sc->sc_alloc, M_DEVBUF);
#endif

	return (0);
}

/*
 * bridge_ioctl:
 *
 *	Handle a control request from the operator.
 */
static int
bridge_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct lwp *l = curlwp;	/* XXX */
	union {
		struct ifbreq ifbreq;
		struct ifbifconf ifbifconf;
		struct ifbareq ifbareq;
		struct ifbaconf ifbaconf;
		struct ifbrparam ifbrparam;
	}
#ifndef __QNXNTO__
	    args;
#else
	    *args;
	struct ifreq *ifr;
#endif
	struct ifdrv *ifd = (struct ifdrv *) data;
	const struct bridge_control *bc;
	int s, error = 0;

	s = splnet();

	switch (cmd) {
	case SIOCGDRVSPEC:
	case SIOCSDRVSPEC:
		if (ifd->ifd_cmd >= bridge_control_table_size) {
			error = EINVAL;
			break;
		}
		bc = &bridge_control_table[ifd->ifd_cmd];

		if (cmd == SIOCGDRVSPEC &&
		    (bc->bc_flags & BC_F_COPYOUT) == 0) {
			error = EINVAL;
			break;
		}
		else if (cmd == SIOCSDRVSPEC &&
		    (bc->bc_flags & BC_F_COPYOUT) != 0) {
			error = EINVAL;
			break;
		}

		if (bc->bc_flags & BC_F_SUSER) {
			error = kauth_authorize_generic(l->l_cred,
			    KAUTH_GENERIC_ISSUSER, &l->l_acflag);
			if (error)
				break;
		}

#ifndef __QNXNTO__
		if (ifd->ifd_len != bc->bc_argsize ||
		    ifd->ifd_len > sizeof(args)) {
			error = EINVAL;
			break;
		}

		memset(&args, 0, sizeof(args));
		if (bc->bc_flags & BC_F_COPYIN) {
			error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
			if (error)
				break;
		}

		error = (*bc->bc_func)(sc, &args);
		if (error)
			break;

		if (bc->bc_flags & BC_F_COPYOUT)
			error = copyout(&args, ifd->ifd_data, ifd->ifd_len);
#else
		if (ifd->ifd_len != bc->bc_argsize ||
		    ifd->ifd_len > sizeof(*args)) {
			error = EINVAL;
			break;
		}
		args = (void *)(ifd + 1);

		/* Paranoid? */
		if ((char *)args + ifd->ifd_len >= (char *)curproc->p_ctxt.msg + curproc->p_ctxt.msg_max_size) {
			error = EMSGSIZE;
			break;
		}

		error = (*bc->bc_func)(sc, args);
		if (error)
			break;

#endif

		break;

	case SIOCSIFFLAGS:
		if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) == IFF_RUNNING) {
			/*
			 * If interface is marked down and it is running,
			 * then stop and disable it.
			 */
			(*ifp->if_stop)(ifp, 1);
		} else if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) == IFF_UP) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			error = (*ifp->if_init)(ifp);
		}
		break;

#ifdef __QNXNTO__
	case SIOCGIFMTU:
		ifr = (struct ifreq *)data;
		ifr->ifr_mtu = ifp->if_mtu;
		break;

	case SIOCSIFMTU:
		ifr = (struct ifreq *)data;
		if (ifp->if_mtu == ifr->ifr_mtu)
			break;
		ifp->if_mtu = ifr->ifr_mtu;
		/*
		 * If the link MTU changed, do network layer specific procedure.
		 */
#ifdef INET6
		nd6_setmtu(ifp);
#endif
		break;
#endif
	default:
		error = ENOTTY;
		break;
	}

	splx(s);

	return (error);
}

/*
 * bridge_lookup_member:
 *
 *	Lookup a bridge member interface.  Must be called at splnet().
 */
static struct bridge_iflist *
bridge_lookup_member(struct bridge_softc *sc, const char *name)
{
	struct bridge_iflist *bif;
	struct ifnet *ifp;
#if defined(__QNXNTO__) && defined(DIAGNOSTIC)
	if (!ISSTACK)
		panic("bridge_lookup_member: not stack.");
#endif

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		ifp = bif->bif_ifp;
		if (strcmp(ifp->if_xname, name) == 0)
			return (bif);
	}

	return (NULL);
}

#ifndef __QNXNTO__
/*
 * bridge_lookup_member_if:
 *
 *	Lookup a bridge member interface by ifnet*.  Must be called at splnet().
 */
static struct bridge_iflist *
bridge_lookup_member_if(struct bridge_softc *sc, struct ifnet *member_ifp)
{
	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (bif->bif_ifp == member_ifp)
			return (bif);
	}

	return (NULL);
}

#else
struct bridge_iflist *
#ifndef DIAGNOSTIC
bridge_lookup_member_if_self(struct bridge_softc *sc, struct ifnet *member_ifp,
    struct nw_work_thread *wtp)
#else
_bridge_lookup_member_if_self(struct bridge_softc *sc, struct ifnet *member_ifp,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	struct bridge_iflist *bif;
	int self;

	self = *wtp->wt_bridx;

	BRIDGE_SELF_ENTER(wtp, line_from);
	LIST_FOREACH(bif, &sc->sc_thread[self].sc_th_iflist, bif_thread[self].bif_th_list) {
		if (bif->bif_ifp == member_ifp)
			break;
	}
	BRIDGE_SELF_EXIT(wtp);

	return bif;
}
#endif

/*
 * bridge_delete_member:
 *
 *	Delete the specified member interface.
 */
static void
bridge_delete_member(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	struct ifnet *ifs = bif->bif_ifp;
#ifdef __QNXNTO__
	int self;
	struct nw_work_thread *wtp;

	wtp = WTP;
	self = *wtp->wt_bridx;
#ifdef DIAGNOSTIC
	if (ISIRUPT_P(wtp))
		panic("bridge_delete_member: unexpected context.");

#endif
#endif

	switch (ifs->if_type) {
	case IFT_ETHER:
		/*
		 * Take the interface out of promiscuous mode.
		 */
		(void) ifpromisc(ifs, 0);
		break;
	default:
#ifdef DIAGNOSTIC
		panic("bridge_delete_member: impossible");
#endif
		break;
	}

#ifndef __QNXNTO__
	ifs->if_bridge = NULL;
#else
	ifs->if_bridge_rx = NULL;
	ifs->if_bridge_tx = NULL;
#endif
	LIST_REMOVE(bif, bif_next);

	bridge_rtdelete(sc, ifs);

#ifndef __QNXNTO__
	free(bif, M_DEVBUF);
#else
	bif_start_rem(bif, sc, self, wtp);
#endif

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);
}

static int
bridge_ioctl_add(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif = NULL;
	struct ifnet *ifs;
	int error = 0;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	pthread_t self;
	struct nw_stk_ctl *sctlp;
	struct bridge_softc_thread *bscth;
#ifndef VARIANT_uni
	int i;
#endif
	sctlp = &stk_ctl;

	wtp = WTP;
	self = *wtp->wt_bridx;
#endif

#ifndef QNX_MFIB
	ifs = ifunit(req->ifbr_ifsname);
#else
	ifs = ifunit(req->ifbr_ifsname, ANY_FIB);
#endif
	if (ifs == NULL)
		return (ENOENT);

	if (sc->sc_if.if_mtu != ifs->if_mtu)
		return (EINVAL);

#ifndef __QNXNTO__
	if (ifs->if_bridge == sc)
		return (EEXIST);

	if (ifs->if_bridge != NULL)
		return (EBUSY);

	bif = malloc(sizeof(*bif), M_DEVBUF, M_NOWAIT);
#else
#ifndef IONET_COMPAT_BRIDGE
	if (ifs->if_flag & IFF_SHIM)
		return (EOPNOTSUPP);
#endif
	if (ifs->if_bridge_tx == sc)
		return (EEXIST);

	if (ifs->if_bridge_tx != NULL)
		return (EBUSY);

	bif = malloc(bif_malloc_item_size, M_DEVBUF, M_NOWAIT);
	if (!bif)
		return (ENOMEM);
	memset(bif, 0x00, bif_malloc_item_size);
#endif
	if (bif == NULL)
		return (ENOMEM);

	switch (ifs->if_type) {
	case IFT_ETHER:
		/*
		 * Place the interface into promiscuous mode.
		 */
		error = ifpromisc(ifs, 1);
		if (error)
			goto out;
		break;
	default:
		error = EINVAL;
		goto out;
	}

	bif->bif_ifp = ifs;
	bif->bif_flags = IFBIF_LEARNING | IFBIF_DISCOVER;
	bif->bif_priority = BSTP_DEFAULT_PORT_PRIORITY;
	bif->bif_path_cost = BSTP_DEFAULT_PATH_COST;

#ifndef __QNXNTO__
	ifs->if_bridge = sc;
#else
	ifs->if_bridge_rx = sc;
	ifs->if_bridge_tx = sc;
#endif
	LIST_INSERT_HEAD(&sc->sc_iflist, bif, bif_next);

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);
	else
		bstp_stop(sc);

#ifdef __QNXNTO__
	NW_SIGHOLD_P(wtp);
#ifndef VARIANT_uni
	NW_EX_LK(&bridge_ex, iopkt_selfp);

	/* Poke each thread into seeding their private hash */
	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		if (i == self)
			continue;
		bscth = &sc->sc_thread[i];
		LIST_INSERT_HEAD(&bscth->sc_th_iftpq.tpq_create_q,
		    bif, bif_thread[i].bif_th_passlist);
		bif->bif_tpe.tpe_nthreads_creating++;
		bscth->sc_th_iftpq.tpq_items_changing++;
	}

	/* Clear out any pending self destroys before self insert */
	bscth = &sc->sc_thread[self];
	bridge_walk_destroy_qs(bscth, self);

	NW_EX_UNLK(&bridge_ex, iopkt_selfp);
#endif
	/*
	 * Stuff our own without mutex but with signal locked.
	 */

	bscth = &sc->sc_thread[self];
	LIST_INSERT_HEAD(&bscth->sc_th_iflist, bif, bif_thread[self].bif_th_list);

	NW_SIGUNHOLD_P(wtp);
#endif
 out:
	if (error) {
		if (bif != NULL)
			free(bif, M_DEVBUF);
	}
	return (error);
}

static int
bridge_ioctl_del(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bridge_delete_member(sc, bif);

	return (0);
}

static int
bridge_ioctl_gifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	req->ifbr_ifsflags = bif->bif_flags;
	req->ifbr_state = bif->bif_state;
	req->ifbr_priority = bif->bif_priority;
	req->ifbr_path_cost = bif->bif_path_cost;
	req->ifbr_portno = bif->bif_ifp->if_index & 0xff;

	return (0);
}

static int
bridge_ioctl_sifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	if (req->ifbr_ifsflags & IFBIF_STP) {
		switch (bif->bif_ifp->if_type) {
		case IFT_ETHER:
			/* These can do spanning tree. */
			break;

		default:
			/* Nothing else can. */
			return (EINVAL);
		}
	}

	bif->bif_flags = req->ifbr_ifsflags;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

static int
bridge_ioctl_scache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	sc->sc_brtmax = param->ifbrp_csize;
	bridge_rttrim(sc);

	return (0);
}

static int
bridge_ioctl_gcache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_csize = sc->sc_brtmax;

	return (0);
}

static int
bridge_ioctl_gifs(struct bridge_softc *sc, void *arg)
{
	struct ifbifconf *bifc = arg;
	struct bridge_iflist *bif;
	struct ifbreq breq;
	int count, len, error = 0;
#ifdef __QNXNTO__
	struct ifbreq *breq_dst;
#endif

	count = 0;
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next)
		count++;

	if (bifc->ifbic_len == 0) {
		bifc->ifbic_len = sizeof(breq) * count;
		return (0);
	}
#ifdef __QNXNTO__
	breq_dst = (struct ifbreq *)(bifc + 1);
#endif

	count = 0;
	len = bifc->ifbic_len;
	memset(&breq, 0, sizeof breq);
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (len < sizeof(breq))
			break;

		strlcpy(breq.ifbr_ifsname, bif->bif_ifp->if_xname,
		    sizeof(breq.ifbr_ifsname));
		breq.ifbr_ifsflags = bif->bif_flags;
		breq.ifbr_state = bif->bif_state;
		breq.ifbr_priority = bif->bif_priority;
		breq.ifbr_path_cost = bif->bif_path_cost;
		breq.ifbr_portno = bif->bif_ifp->if_index & 0xff;
#ifndef __QNXNTO__
		error = copyout(&breq, bifc->ifbic_req + count, sizeof(breq));
#else
		error = copyout(&breq, breq_dst + count, sizeof(breq));
#endif
		if (error)
			break;
		count++;
		len -= sizeof(breq);
	}

	bifc->ifbic_len = sizeof(breq) * count;
	return (error);
}

static int
bridge_ioctl_rts(struct bridge_softc *sc, void *arg)
{
	struct ifbaconf *bac = arg;
	struct bridge_rtnode *brt;
	struct ifbareq bareq;
	int count = 0, error = 0, len;
#ifdef __QNXNTO__
	struct ifbareq *bareq_dst;
#endif

	if (bac->ifbac_len == 0)
		return (0);

#ifdef __QNXNTO__
	bareq_dst = (struct ifbareq *)(bac + 1);
#endif
	len = bac->ifbac_len;
	LIST_FOREACH(brt, &sc->sc_rtlist, brt_list) {
		if (len < sizeof(bareq))
			goto out;
		memset(&bareq, 0, sizeof(bareq));
		strlcpy(bareq.ifba_ifsname, brt->brt_ifp->if_xname,
		    sizeof(bareq.ifba_ifsname));
		memcpy(bareq.ifba_dst, brt->brt_addr, sizeof(brt->brt_addr));
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			bareq.ifba_expire = brt->brt_expire - time_uptime;
		} else
			bareq.ifba_expire = 0;
		bareq.ifba_flags = brt->brt_flags;

#ifndef __QNXNTO__
		error = copyout(&bareq, bac->ifbac_req + count, sizeof(bareq));
#else
		error = copyout(&bareq, bareq_dst + count, sizeof(bareq));
#endif
		if (error)
			goto out;
		count++;
		len -= sizeof(bareq);
	}
 out:
	bac->ifbac_len = sizeof(bareq) * count;
	return (error);
}

static int
bridge_ioctl_saddr(struct bridge_softc *sc, void *arg)
{
	struct ifbareq *req = arg;
	struct bridge_iflist *bif;
	int error;

	bif = bridge_lookup_member(sc, req->ifba_ifsname);
	if (bif == NULL)
		return (ENOENT);

	error = bridge_rtupdate(sc, req->ifba_dst, bif->bif_ifp, 1,
	    req->ifba_flags);

	return (error);
}

static int
bridge_ioctl_sto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	sc->sc_brttimeout = param->ifbrp_ctime;

	return (0);
}

static int
bridge_ioctl_gto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_ctime = sc->sc_brttimeout;

	return (0);
}

static int
bridge_ioctl_daddr(struct bridge_softc *sc, void *arg)
{
	struct ifbareq *req = arg;

	return (bridge_rtdaddr(sc, req->ifba_dst));
}

static int
bridge_ioctl_flush(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;

	bridge_rtflush(sc, req->ifbr_ifsflags);

	return (0);
}

static int
bridge_ioctl_gpri(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_prio = sc->sc_bridge_priority;

	return (0);
}

static int
bridge_ioctl_spri(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	sc->sc_bridge_priority = param->ifbrp_prio;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

static int
bridge_ioctl_ght(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_hellotime = sc->sc_bridge_hello_time >> 8;

	return (0);
}

static int
bridge_ioctl_sht(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	if (param->ifbrp_hellotime == 0)
		return (EINVAL);
	sc->sc_bridge_hello_time = param->ifbrp_hellotime << 8;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

static int
bridge_ioctl_gfd(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_fwddelay = sc->sc_bridge_forward_delay >> 8;

	return (0);
}

static int
bridge_ioctl_sfd(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	if (param->ifbrp_fwddelay == 0)
		return (EINVAL);
	sc->sc_bridge_forward_delay = param->ifbrp_fwddelay << 8;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

static int
bridge_ioctl_gma(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_maxage = sc->sc_bridge_max_age >> 8;

	return (0);
}

static int
bridge_ioctl_sma(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	if (param->ifbrp_maxage == 0)
		return (EINVAL);
	sc->sc_bridge_max_age = param->ifbrp_maxage << 8;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

static int
bridge_ioctl_sifprio(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bif->bif_priority = req->ifbr_priority;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

#if defined(BRIDGE_IPF) && defined(PFIL_HOOKS)
static int
bridge_ioctl_gfilt(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_filter = sc->sc_filter_flags;

	return (0);
}

static int
bridge_ioctl_sfilt(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	uint32_t nflags, oflags;

	if (param->ifbrp_filter & ~IFBF_FILT_MASK)
		return (EINVAL);

	nflags = param->ifbrp_filter;
	oflags = sc->sc_filter_flags;

	if ((nflags & IFBF_FILT_USEIPF) && !(oflags & IFBF_FILT_USEIPF)) {
		pfil_add_hook((void *)bridge_ipf, NULL, PFIL_IN|PFIL_OUT,
			&sc->sc_if.if_pfil);
	}
	if (!(nflags & IFBF_FILT_USEIPF) && (oflags & IFBF_FILT_USEIPF)) {
		pfil_remove_hook((void *)bridge_ipf, NULL, PFIL_IN|PFIL_OUT,
			&sc->sc_if.if_pfil);
	}

	sc->sc_filter_flags = nflags;

	return (0);
}
#endif /* BRIDGE_IPF && PFIL_HOOKS */

static int
bridge_ioctl_sifcost(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bif->bif_path_cost = req->ifbr_path_cost;

	if (sc->sc_if.if_flags & IFF_RUNNING)
		bstp_initialization(sc);

	return (0);
}

/*
 * bridge_ifdetach:
 *
 *	Detach an interface from a bridge.  Called when a member
 *	interface is detaching.
 */
void
bridge_ifdetach(struct ifnet *ifp)
{
#ifndef __QNXNTO__
	struct bridge_softc *sc = ifp->if_bridge;
#else
	struct bridge_softc *sc = ifp->if_bridge_tx;
#endif
	struct ifbreq breq;

	memset(&breq, 0, sizeof(breq));
	snprintf(breq.ifbr_ifsname, sizeof(breq.ifbr_ifsname), ifp->if_xname);

	(void) bridge_ioctl_del(sc, &breq);
}

/*
 * bridge_init:
 *
 *	Initialize a bridge interface.
 */
static int
bridge_init(struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;

	if (ifp->if_flags & IFF_RUNNING)
		return (0);

	callout_reset(&sc->sc_brcallout, bridge_rtable_prune_period * hz,
	    bridge_timer, sc);

	ifp->if_flags |= IFF_RUNNING;
	bstp_initialization(sc);
	return (0);
}

/*
 * bridge_stop:
 *
 *	Stop the bridge interface.
 */
static void
bridge_stop(struct ifnet *ifp, int disable)
{
	struct bridge_softc *sc = ifp->if_softc;

	if ((ifp->if_flags & IFF_RUNNING) == 0)
		return;

	callout_stop(&sc->sc_brcallout);
	bstp_stop(sc);

	IF_PURGE(&ifp->if_snd);

	bridge_rtflush(sc, IFBF_FLUSHDYN);

	ifp->if_flags &= ~IFF_RUNNING;
}

/*
 * bridge_enqueue:
 *
 *	Enqueue a packet on a bridge member interface.
 *
 *	NOTE: must be called at splnet().
 */
void
bridge_enqueue(struct bridge_softc *sc, struct ifnet *dst_ifp, struct mbuf *m,
    int runfilt)
{
	ALTQ_DECL(struct altq_pktattr pktattr;)
	int len, error;
	short mflags;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	m->m_pkthdr.csum_flags = 0;

#ifdef PFIL_HOOKS
	if (runfilt) {
		if (pfil_run_hooks(&sc->sc_if.if_pfil, &m,
#ifndef QNX_MFIB
		    dst_ifp, PFIL_OUT) != 0) {
#else
			/* XX MFIB: use first fib on output if. Not certain that is correct */
		    dst_ifp, PFIL_OUT, if_get_first_fib(dst_ifp)) != 0) {
#endif
			if (m != NULL)
				m_freem(m);
			return;
		}
		if (m == NULL)
			return;
	}
#endif /* PFIL_HOOKS */

#ifdef ALTQ
	/*
	 * If ALTQ is enabled on the member interface, do
	 * classification; the queueing discipline might
	 * not require classification, but might require
	 * the address family/header pointer in the pktattr.
	 */
	if (ALTQ_IS_ENABLED(&dst_ifp->if_snd)) {
		/* XXX IFT_ETHER */
		altq_etherclassify(&dst_ifp->if_snd, m, &pktattr);
	}
#endif /* ALTQ */

	len = m->m_pkthdr.len;
	m->m_flags |= M_PROTO1;
	mflags = m->m_flags;
#ifndef __QNXNTO__
	IFQ_ENQUEUE(&dst_ifp->if_snd, m, &pktattr, error);
	if (error) {
		/* mbuf is already freed */
		sc->sc_if.if_oerrors++;
		return;
	}

	sc->sc_if.if_opackets++;
	sc->sc_if.if_obytes += len;

	dst_ifp->if_obytes += len;

	if (mflags & M_MCAST) {
		sc->sc_if.if_omcasts++;
		dst_ifp->if_omcasts++;
	}

	if ((dst_ifp->if_flags & IFF_OACTIVE) == 0)
		(*dst_ifp->if_start)(dst_ifp);
#else
	NW_SIGLOCK_P(&dst_ifp->if_snd_ex, iopkt_selfp, wtp);
	IFQ_ENQUEUE(&dst_ifp->if_snd, m, &pktattr, error);
	/*
	 * If error, mbuf is already freed
	 * but we still want to tickle the
	 * driver.
	 */
	if (error) {
		sc->sc_if.if_oerrors++;
	}
	else {
		sc->sc_if.if_opackets++;
		sc->sc_if.if_obytes += len;

		dst_ifp->if_obytes += len;
		if (mflags & M_MCAST) {
			sc->sc_if.if_omcasts++;
			dst_ifp->if_omcasts++;
		}
	}
	if ((dst_ifp->if_flags_tx & IFF_OACTIVE) == 0)
		(*dst_ifp->if_start)(dst_ifp); /* This must release the lock */
	else
		NW_SIGUNLOCK_P(&dst_ifp->if_snd_ex, iopkt_selfp, wtp);
#endif
}

/*
 * bridge_output:
 *
 *	Send output from a bridge member interface.  This
 *	performs the bridging function for locally originated
 *	packets.
 *
 *	The mbuf has the Ethernet header already attached.  We must
 *	enqueue or free the mbuf before returning.
 */
int
bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *sa,
    struct rtentry *rt)
{
	struct ether_header *eh;
	struct ifnet *dst_if;
	struct bridge_softc *sc;
	int s;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	int self, am_stack;
	struct nw_stk_ctl *sctlp;

	wtp = WTP;
	sctlp = &stk_ctl;

	/*
	 * Paranoid?
	 * I think the only way this could happen
	 * is if a packet got fastforwarded by a
	 * thread with no flow associated with it.
	 * In such a case it should have been caught
	 * by an earlier check for flow.
	 */
	if (wtp->wt_bridx == NULL) {
		nw_thread_log_noflow();
		m_freem(m);
		return 0;
	}

	self = *wtp->wt_bridx;
#endif

	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL)
			return (0);
	}

	eh = mtod(m, struct ether_header *);
#ifndef __QNXNTO__
	sc = ifp->if_bridge;
#else
	sc = ifp->if_bridge_tx;
	/*
	 * bridge_output() is a pain as it's called from both
	 * the interrupt and stack contexts regardless of state
	 * of IONET_COMPAT_BRIDGE.  This means care must be
	 * taken to stick to the stack's master list if we are
	 * in fact the stack: if we are the stack without
	 * IONET_COMPAT_BRIDGE, *_self won't hold off the
	 * signal.
	 */
	am_stack = ISSTACK_P(wtp);
#ifdef DIAGNOSTIC
	if (am_stack == 0 && wtp->intr_sighot == _ISIG_HOT)
		panic("bridge: unexpected output context");
#endif
#ifndef VARIANT_uni
	if (am_stack == 0 &&
	    (sc->sc_thread[self].sc_th_iftpq.tpq_items_changing ||
	    sc->sc_thread[self].sc_th_rttpq.tpq_items_changing))
		bridge_refresh_private_self(sc, wtp);
#endif
#endif

	s = splnet();

	/*
	 * If bridge is down, but the original output interface is up,
	 * go ahead and send out that interface.  Otherwise, the packet
	 * is dropped below.
	 */
	if ((sc->sc_if.if_flags & IFF_RUNNING) == 0) {
		dst_if = ifp;
		goto sendunicast;
	}

	/*
	 * If the packet is a multicast, or we don't know a better way to
	 * get there, send to all interfaces.
	 */
	if (ETHER_IS_MULTICAST(eh->ether_dhost))
		dst_if = NULL;
	else {
#ifndef __QNXNTO__
		dst_if = bridge_rtlookup(sc, eh->ether_dhost);
#else
		if (am_stack == 0)
			dst_if = bridge_rtlookup_self(sc, eh->ether_dhost, wtp);
		else
			dst_if = bridge_rtlookup(sc, eh->ether_dhost);
#endif
	}
	if (dst_if == NULL) {
		struct bridge_iflist *bif;
		struct mbuf *mc;
		int used = 0;

#ifndef __QNXNTO__
		LIST_FOREACH(bif, &sc->sc_iflist, bif_next)
#else
		struct bridge_iflist *bifnext;

		if (am_stack) {
			bif = LIST_FIRST(&sc->sc_iflist);
		}
		else {
			bif = LIST_FIRST(&sc->sc_thread[self].sc_th_iflist);
		}

		for (; bif != NULL; bif = bifnext)
#endif
		    {
#ifdef __QNXNTO__
			if (am_stack)
				bifnext = LIST_NEXT(bif, bif_next);
			else
				bifnext = LIST_NEXT(bif, bif_thread[self].bif_th_list);
#endif
			dst_if = bif->bif_ifp;
			if ((dst_if->if_flags & IFF_RUNNING) == 0)
				continue;

			/*
			 * If this is not the original output interface,
			 * and the interface is participating in spanning
			 * tree, make sure the port is in a state that
			 * allows forwarding.
			 */
			if (dst_if != ifp &&
			    (bif->bif_flags & IFBIF_STP) != 0) {
				switch (bif->bif_state) {
				case BSTP_IFSTATE_BLOCKING:
				case BSTP_IFSTATE_LISTENING:
				case BSTP_IFSTATE_DISABLED:
					continue;
				}
			}

			if (LIST_NEXT(bif, bif_next) == NULL) {
				used = 1;
				mc = m;
			} else {
				mc = m_copym(m, 0, M_COPYALL, M_NOWAIT);
				if (mc == NULL) {
					sc->sc_if.if_oerrors++;
					continue;
				}
			}

			bridge_enqueue(sc, dst_if, mc, 0);
		}
		if (used == 0)
			m_freem(m);
		splx(s);
		return (0);
	}

 sendunicast:
	/*
	 * XXX Spanning tree consideration here?
	 */

	if ((dst_if->if_flags & IFF_RUNNING) == 0) {
		m_freem(m);
		splx(s);
		return (0);
	}

	bridge_enqueue(sc, dst_if, m, 0);

	splx(s);
	return (0);
}

/*
 * bridge_start:
 *
 *	Start output on a bridge.
 *
 *	NOTE: This routine should never be called in this implementation.
 */
static void
bridge_start(struct ifnet *ifp)
{

	printf("%s: bridge_start() called\n", ifp->if_xname);
}

#if defined(__QNXNTO__) && !defined(VARIANT_uni)
static void
bridge_walk_destroy_qs(struct bridge_softc_thread *bscth, int idx)
{
	struct bridge_iflist		*bif;
	struct bridge_rtnode		*brt;
	struct bridge_iflist_thread	*bifth;
	struct bridge_rtnode_thread	*brtth;

	while ((bif = LIST_FIRST(&bscth->sc_th_iftpq.tpq_destroy_q)) != NULL) {
		bifth = &bif->bif_thread[idx];

		LIST_FIRST(&bscth->sc_th_iftpq.tpq_destroy_q) =
		    LIST_NEXT(bifth, bif_th_passlist);
		BIF_MARK_OFFLIST(bifth);

		bscth->sc_th_iftpq.tpq_items_changing--;

		bif_thread_decref(&bif->bif_tpe, idx);
		
		if (--bif->bif_tpe.tpe_nthreads_destroying == 0) {
			/* free() can be called in any context. */
			free(bif, M_DEVBUF);
		}
	}

	while ((brt = LIST_FIRST(&bscth->sc_th_rttpq.tpq_destroy_q)) != NULL) {
		brtth = &brt->brt_thread[idx];

		LIST_FIRST(&bscth->sc_th_rttpq.tpq_destroy_q) =
		    LIST_NEXT(brtth, brt_th_passlist);
		BRT_MARK_OFFLIST(brtth);

		bscth->sc_th_rttpq.tpq_items_changing--;

		brt_thread_decref(&brt->brt_tpe, idx);
		
		if (--brt->brt_tpe.tpe_nthreads_destroying == 0) {
			/*
			 * pool created with PR_PROTECT so
			 * ok to free in any context.
			 */
			pool_put(&bridge_rtnode_pool, brt);
		}
	}
}

void
#ifndef DIAGNOSTIC
bridge_refresh_private_self(struct bridge_softc *sc,
    struct nw_work_thread *wtp)
#else
_bridge_refresh_private_self(struct bridge_softc *sc,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	struct bridge_iflist		*bif;
	struct bridge_rtnode		*brt;
	struct bridge_softc_thread	*bscth;
	struct bridge_rtnode_thread	*brtth;
	struct bridge_iflist_thread	*bifth;
	int				self;
	LIST_HEAD(, bridge_rtnode)	local_rtlist = { NULL };


	self = *wtp->wt_bridx;

	BRIDGE_SELF_ENTER(wtp, line_from); /* Holds sig if necesary */

	NW_EX_LK(&bridge_ex, iopkt_selfp);

	bscth = &sc->sc_thread[self];
	bridge_walk_destroy_qs(bscth, self);


	while ((bif = LIST_FIRST(&bscth->sc_th_iftpq.tpq_create_q)) != NULL) {
		bifth = &bif->bif_thread[self];

		LIST_FIRST(&bscth->sc_th_iftpq.tpq_create_q) =
		    LIST_NEXT(bifth, bif_th_passlist);
		BIF_MARK_OFFLIST(bifth);

		bscth->sc_th_iftpq.tpq_items_changing--;
		bif->bif_tpe.tpe_nthreads_creating--;

		LIST_INSERT_HEAD(&bscth->sc_th_iflist, bif,
		    bif_thread[self].bif_th_list);
	}


	while ((brt = LIST_FIRST(&bscth->sc_th_rttpq.tpq_create_q)) != NULL) {
		brtth = &brt->brt_thread[self];

		LIST_FIRST(&bscth->sc_th_rttpq.tpq_create_q) =
		    LIST_NEXT(brtth, brt_th_passlist);
		BRT_MARK_OFFLIST(brtth);

		bscth->sc_th_rttpq.tpq_items_changing--;
		brt->brt_tpe.tpe_nthreads_creating--;

		/*
		 * Q using local brt_th_list member, not
		 * brt_th_passlist whose access must be
		 * inside the mutex.
		 */
		LIST_INSERT_HEAD(&local_rtlist, brt, brt_thread[self].brt_th_list);
	}

	NW_EX_UNLK(&bridge_ex, iopkt_selfp);
	BRIDGE_SELF_EXIT(wtp);

	while ((brt = LIST_FIRST(&local_rtlist)) != NULL) {
		LIST_FIRST(&local_rtlist) = LIST_NEXT(brt, brt_thread[self].brt_th_list);
		bridge_rtnode_insert_self(sc, brt, wtp);
	}

	return;
}
#endif

/*
 * bridge_forward:
 *
 *	The forwarding function of the bridge.
 */
static void
bridge_forward(struct bridge_softc *sc, struct mbuf *m)
{
	struct bridge_iflist *bif;
	struct ifnet *src_if, *dst_if;
	struct ether_header *eh;
#ifdef __QNXNTO__
	int self;
	struct nw_work_thread *wtp = WTP;

	self = *wtp->wt_bridx;
#endif

	src_if = m->m_pkthdr.rcvif;

	sc->sc_if.if_ipackets++;
	sc->sc_if.if_ibytes += m->m_pkthdr.len;

	/*
	 * Look up the bridge_iflist.
	 */
#ifndef __QNXNTO__
	bif = bridge_lookup_member_if(sc, src_if);
#else
	bif = bridge_lookup_member_if_self(sc, src_if, wtp);
#endif
	if (bif == NULL) {
		/* Interface is not a bridge member (anymore?) */
		m_freem(m);
		return;
	}

	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
		case BSTP_IFSTATE_BLOCKING:
		case BSTP_IFSTATE_LISTENING:
		case BSTP_IFSTATE_DISABLED:
			m_freem(m);
			return;
		}
	}

	eh = mtod(m, struct ether_header *);

	/*
	 * If the interface is learning, and the source
	 * address is valid and not multicast, record
	 * the address.
	 */
	if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
	    ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
	    (eh->ether_shost[0] == 0 &&
	     eh->ether_shost[1] == 0 &&
	     eh->ether_shost[2] == 0 &&
	     eh->ether_shost[3] == 0 &&
	     eh->ether_shost[4] == 0 &&
	     eh->ether_shost[5] == 0) == 0) {
#ifndef  __QNXNTO__
		(void) bridge_rtupdate(sc, eh->ether_shost,
		    src_if, 0, IFBAF_DYNAMIC);
#else
		bridge_rtupdate_self(sc, eh->ether_shost,
		    src_if, 0, IFBAF_DYNAMIC, wtp);
#endif
	}

	if ((bif->bif_flags & IFBIF_STP) != 0 &&
	    bif->bif_state == BSTP_IFSTATE_LEARNING) {
		m_freem(m);
		return;
	}

	/*
	 * At this point, the port either doesn't participate
	 * in spanning tree or it is in the forwarding state.
	 */

	/*
	 * If the packet is unicast, destined for someone on
	 * "this" side of the bridge, drop it.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST)) == 0) {
#ifndef __QNXNTO__
		dst_if = bridge_rtlookup(sc, eh->ether_dhost);
#else
		dst_if = bridge_rtlookup_self(sc, eh->ether_dhost, wtp);
#endif
		if (src_if == dst_if) {
			m_freem(m);
			return;
		}
	} else {
		/* ...forward it to all interfaces. */
		sc->sc_if.if_imcasts++;
		dst_if = NULL;
	}

#ifdef PFIL_HOOKS
	if (pfil_run_hooks(&sc->sc_if.if_pfil, &m,
#ifndef QNX_MFIB
	    m->m_pkthdr.rcvif, PFIL_IN) != 0) {
#else
	    m->m_pkthdr.rcvif, PFIL_IN, if_get_first_fib(m->m_pkthdr.rcvif)) != 0) {
#endif
		if (m != NULL)
			m_freem(m);
		return;
	}
	if (m == NULL)
		return;
#endif /* PFIL_HOOKS */

	if (dst_if == NULL) {
		bridge_broadcast(sc, src_if, m);
		return;
	}

	/*
	 * At this point, we're dealing with a unicast frame
	 * going to a different interface.
	 */
	if ((dst_if->if_flags & IFF_RUNNING) == 0) {
		m_freem(m);
		return;
	}
#ifndef __QNXNTO__
	bif = bridge_lookup_member_if(sc, dst_if);
#else
	bif = bridge_lookup_member_if_self(sc, dst_if, wtp);
#endif
	if (bif == NULL) {
		/* Not a member of the bridge (anymore?) */
		m_freem(m);
		return;
	}

	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
		case BSTP_IFSTATE_DISABLED:
		case BSTP_IFSTATE_BLOCKING:
			m_freem(m);
			return;
		}
	}

	bridge_enqueue(sc, dst_if, m, 1);
}

/*
 * bridge_input:
 *
 *	Receive input from a member interface.  Queue the packet for
 *	bridging if it is not for us.
 */
struct mbuf *
bridge_input(struct ifnet *ifp, struct mbuf *m)
{
#ifndef __QNXNTO__
	struct bridge_softc *sc = ifp->if_bridge;
#else
	struct bridge_softc *sc = ifp->if_bridge_rx;
#endif
	struct bridge_iflist *bif;
	struct ether_header *eh;
	struct mbuf *mc;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp;
	int self;
	struct nw_stk_ctl *sctlp;
	struct ifaddr *ifa;
#ifdef INET6
	struct sockaddr_in6 *ifsin6;
#endif

	sctlp = &stk_ctl;
	wtp = WTP;

	/*
	 * Paranoid?
	 * This is 802 specific which implies a thread
	 * that should have a flow.  This shouldn't be
	 * reached by a thread handling a ppp interface
	 * for example.
	 */
	if (wtp->wt_bridx == NULL) {
		nw_thread_log_noflow();
		return m;
	}

	self = *wtp->wt_bridx;

#ifndef VARIANT_uni
	if (sc->sc_thread[self].sc_th_iftpq.tpq_items_changing > 0 ||
	    sc->sc_thread[self].sc_th_rttpq.tpq_items_changing > 0)
		bridge_refresh_private_self(sc, wtp);
#endif
#endif

	if ((sc->sc_if.if_flags & IFF_RUNNING) == 0)
		return (m);

#ifndef __QNXNTO__
	bif = bridge_lookup_member_if(sc, ifp);
#else
	bif = bridge_lookup_member_if_self(sc, ifp, wtp);
#endif
	if (bif == NULL)
		return (m);

	eh = mtod(m, struct ether_header *);

	if (m->m_flags & (M_BCAST|M_MCAST)) {
		/* Tap off 802.1D packets; they do not get forwarded. */
		if (memcmp(eh->ether_dhost, bstp_etheraddr,
		    ETHER_ADDR_LEN) == 0) {
			m = bstp_input(ifp, m);
			if (m == NULL)
				return (NULL);
		}

		if (bif->bif_flags & IFBIF_STP) {
			switch (bif->bif_state) {
			case BSTP_IFSTATE_BLOCKING:
			case BSTP_IFSTATE_LISTENING:
			case BSTP_IFSTATE_DISABLED:
				return (m);
			}
		}

		/*
		 * Make a deep copy of the packet and enqueue the copy
		 * for bridge processing; return the original packet for
		 * local processing.
		 */
		mc = m_dup(m, 0, M_COPYALL, M_NOWAIT);
		if (mc == NULL)
			return (m);

		/* Perform the bridge forwarding function with the copy. */
		bridge_forward(sc, mc);

#ifdef __QNXNTO__
		/*
		 * Find the bridge member that has higher level
		 * protocols bound and send it in via that interface.
		 */
		LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
			IFADDR_FOREACH(ifa, bif->bif_ifp) {
				if (ifa->ifa_addr->sa_family == AF_INET) {
					m->m_pkthdr.rcvif = bif->bif_ifp;
					return m;
				}
#ifdef INET6
				if (ifa->ifa_addr->sa_family == AF_INET6) {
					ifsin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					if (!IN6_IS_ADDR_LINKLOCAL(&ifsin6->sin6_addr)) {
						m->m_pkthdr.rcvif = bif->bif_ifp;
						return m;
					}
				}
#endif
			}
		}
#endif

		/* Return the original packet for local processing. */
		return (m);
	}

	if (bif->bif_flags & IFBIF_STP) {
		switch (bif->bif_state) {
		case BSTP_IFSTATE_BLOCKING:
		case BSTP_IFSTATE_LISTENING:
		case BSTP_IFSTATE_DISABLED:
			return (m);
		}
	}

	/*
	 * Unicast.  Make sure it's not for us.
	 */
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		/* It is destined for us. */
		if (memcmp(LLADDR(bif->bif_ifp->if_sadl), eh->ether_dhost,
		    ETHER_ADDR_LEN) == 0
#if NCARP > 0
		    || (bif->bif_ifp->if_carp && carp_ourether(bif->bif_ifp->if_carp,
			eh, IFT_ETHER, 0) != NULL)
#endif /* NCARP > 0 */
		    ) {
			if (bif->bif_flags & IFBIF_LEARNING)
#ifndef __QNXNTO__
				(void) bridge_rtupdate(sc,
				    eh->ether_shost, ifp, 0, IFBAF_DYNAMIC);
#else
				bridge_rtupdate_self(sc, eh->ether_shost,
				    ifp, 0, IFBAF_DYNAMIC, wtp);
#endif
			m->m_pkthdr.rcvif = bif->bif_ifp;
			return (m);
		}

		/* We just received a packet that we sent out. */
		if (memcmp(LLADDR(bif->bif_ifp->if_sadl), eh->ether_shost,
		    ETHER_ADDR_LEN) == 0
#if NCARP > 0
		    || (bif->bif_ifp->if_carp && carp_ourether(bif->bif_ifp->if_carp,
			eh, IFT_ETHER, 1) != NULL)
#endif /* NCARP > 0 */
		    ) {
			m_freem(m);
			return (NULL);
		}
	}

	/* Perform the bridge forwarding function. */
	bridge_forward(sc, m);

	return (NULL);
}

/*
 * bridge_broadcast:
 *
 *	Send a frame to all interfaces that are members of
 *	the bridge, except for the one on which the packet
 *	arrived.
 */
static void
bridge_broadcast(struct bridge_softc *sc, struct ifnet *src_if,
    struct mbuf *m)
{
	struct bridge_iflist *bif;
	struct mbuf *mc;
	struct ifnet *dst_if;
	int used = 0;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		dst_if = bif->bif_ifp;
		if (dst_if == src_if)
			continue;

		if (bif->bif_flags & IFBIF_STP) {
			switch (bif->bif_state) {
			case BSTP_IFSTATE_BLOCKING:
			case BSTP_IFSTATE_DISABLED:
				continue;
			}
		}

		if ((bif->bif_flags & IFBIF_DISCOVER) == 0 &&
		    (m->m_flags & (M_BCAST|M_MCAST)) == 0)
			continue;

		if ((dst_if->if_flags & IFF_RUNNING) == 0)
			continue;

		if (LIST_NEXT(bif, bif_next) == NULL) {
			mc = m;
			used = 1;
		} else {
			mc = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
			if (mc == NULL) {
				sc->sc_if.if_oerrors++;
				continue;
			}
		}

		bridge_enqueue(sc, dst_if, mc, 1);
	}
	if (used == 0)
		m_freem(m);
}

/*
 * bridge_rtupdate:
 *
 *	Add a bridge routing entry.
 */
static int
bridge_rtupdate(struct bridge_softc *sc, const uint8_t *dst,
    struct ifnet *dst_if, int setflags, uint8_t flags)
{
	struct bridge_rtnode *brt;
	int error, s;

	/*
	 * A route for this destination might already exist.  If so,
	 * update it, otherwise create a new one.
	 */
	if ((brt = bridge_rtnode_lookup(sc, dst)) == NULL) {
		if (sc->sc_brtcnt >= sc->sc_brtmax)
			return (ENOSPC);

		/*
		 * Allocate a new bridge forwarding node, and
		 * initialize the expiration time and Ethernet
		 * address.
		 */
		s = splnet();
		brt = pool_get(&bridge_rtnode_pool, PR_NOWAIT);
		splx(s);
		if (brt == NULL)
			return (ENOMEM);

#ifndef __QNXNTO__
		memset(brt, 0, sizeof(*brt));
#else
		memset(brt, 0, brt_pool_item_size);
#endif
		brt->brt_expire = time_uptime + sc->sc_brttimeout;
		brt->brt_flags = IFBAF_DYNAMIC;
		memcpy(brt->brt_addr, dst, ETHER_ADDR_LEN);

		if ((error = bridge_rtnode_insert(sc, brt)) != 0) {
			s = splnet();
			pool_put(&bridge_rtnode_pool, brt);
			splx(s);
			return (error);
		}
	}

	brt->brt_ifp = dst_if;
	if (setflags) {
		brt->brt_flags = flags;
		if (flags & IFBAF_STATIC)
			brt->brt_expire = 0;
		else
			brt->brt_expire = time_uptime + sc->sc_brttimeout;
#ifdef __QNXNTO__ /* From if_bridge.c r1.97. */
	} else {
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC)
			brt->brt_expire = time_uptime + sc->sc_brttimeout;
#endif /* __QNXNTO__ */
	}

	return (0);
}

/*
 * bridge_rtlookup:
 *
 *	Lookup the destination interface for an address.
 */
static struct ifnet *
bridge_rtlookup(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;

	if ((brt = bridge_rtnode_lookup(sc, addr)) == NULL)
		return (NULL);

	return (brt->brt_ifp);
}

#ifdef __QNXNTO__
struct ifnet *
#ifndef DIAGNOSTIC
bridge_rtlookup_self(struct bridge_softc *sc, const uint8_t *addr,
    struct nw_work_thread *wtp)
#else
_bridge_rtlookup_self(struct bridge_softc *sc, const uint8_t *addr,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	struct bridge_rtnode *brt;
	struct ifnet *ifp;

	BRIDGE_SELF_ENTER(wtp, line_from);

	if ((brt = bridge_rtnode_lookup_self(sc, addr, wtp)) == NULL)
		ifp = NULL;
	else
		ifp = brt->brt_ifp;

	BRIDGE_SELF_EXIT(wtp);

	return ifp;
}
#endif

/*
 * bridge_rttrim:
 *
 *	Trim the routine table so that we have a number
 *	of routing entries less than or equal to the
 *	maximum number.
 */
static void
bridge_rttrim(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;

	/* Make sure we actually need to do this. */
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;

	/* Force an aging cycle; this might trim enough addresses. */
	bridge_rtage(sc);
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;

	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			bridge_rtnode_destroy(sc, brt);
			if (sc->sc_brtcnt <= sc->sc_brtmax)
				return;
		}
	}
}

/*
 * bridge_timer:
 *
 *	Aging timer for the bridge.
 */
static void
bridge_timer(void *arg)
{
	struct bridge_softc *sc = arg;
	int s;

	s = splnet();
	bridge_rtage(sc);
	splx(s);

	if (sc->sc_if.if_flags & IFF_RUNNING)
		callout_reset(&sc->sc_brcallout,
		    bridge_rtable_prune_period * hz, bridge_timer, sc);
}

/*
 * bridge_rtage:
 *
 *	Perform an aging cycle.
 */
static void
bridge_rtage(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;

	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			if (time_uptime >= brt->brt_expire)
				bridge_rtnode_destroy(sc, brt);
		}
	}
}

/*
 * bridge_rtflush:
 *
 *	Remove all dynamic addresses from the bridge.
 */
static void
bridge_rtflush(struct bridge_softc *sc, int full)
{
	struct bridge_rtnode *brt, *nbrt;

	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if (full || (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC)
			bridge_rtnode_destroy(sc, brt);
	}
}

/*
 * bridge_rtdaddr:
 *
 *	Remove an address from the table.
 */
static int
bridge_rtdaddr(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;

	if ((brt = bridge_rtnode_lookup(sc, addr)) == NULL)
		return (ENOENT);

	bridge_rtnode_destroy(sc, brt);
	return (0);
}

/*
 * bridge_rtdelete:
 *
 *	Delete routes to a speicifc member interface.
 */
static void
bridge_rtdelete(struct bridge_softc *sc, struct ifnet *ifp)
{
	struct bridge_rtnode *brt, *nbrt;

	for (brt = LIST_FIRST(&sc->sc_rtlist); brt != NULL; brt = nbrt) {
		nbrt = LIST_NEXT(brt, brt_list);
		if (brt->brt_ifp == ifp)
			bridge_rtnode_destroy(sc, brt);
	}
}

/*
 * bridge_rtable_init:
 *
 *	Initialize the route table for this bridge.
 */
static int
bridge_rtable_init(struct bridge_softc *sc)
{
	int i;
#ifdef __QNXNTO__
	int			j;
	char			*cp;
	int			size;
	struct nw_stk_ctl	*sctlp = &stk_ctl;
#endif

#ifndef __QNXNTO__
	sc->sc_rthash = malloc(sizeof(*sc->sc_rthash) * BRIDGE_RTHASH_SIZE,
	    M_DEVBUF, M_NOWAIT);
	if (sc->sc_rthash == NULL)
		return (ENOMEM);

#else /* __QNXNTO__ */
	size = sizeof(*sc->sc_rthash) * BRIDGE_RTHASH_SIZE;
	/* One for master (stack's) list and one for each thread */
	sc->sc_rthash = malloc(size * (sctlp->nthreads_flow_max + 1), M_DEVBUF, M_NOWAIT);
	if (sc->sc_rthash == NULL)
		return (ENOMEM);
	cp = (char *)sc->sc_rthash;
	cp += size;

	for (i = 0; i < sctlp->nthreads_flow_max; i++, cp += size) {
		sc->sc_thread[i].sc_th_rthash = (void *)cp;
		for (j = 0; j < BRIDGE_RTHASH_SIZE; j++)
			LIST_INIT(&sc->sc_thread[i].sc_th_rthash[j]);

		LIST_INIT(&sc->sc_thread[i].sc_th_rtlist);

	}
#endif /* __QNXNTO__ */
	for (i = 0; i < BRIDGE_RTHASH_SIZE; i++)
		LIST_INIT(&sc->sc_rthash[i]);

	sc->sc_rthash_key = arc4random();

	LIST_INIT(&sc->sc_rtlist);

	return (0);
}

/*
 * bridge_rtable_fini:
 *
 *	Deconstruct the route table for this bridge.
 */
static void
bridge_rtable_fini(struct bridge_softc *sc)
{

	free(sc->sc_rthash, M_DEVBUF);
}

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 */
#define	mix(a, b, c)							\
do {									\
	a -= b; a -= c; a ^= (c >> 13);					\
	b -= c; b -= a; b ^= (a << 8);					\
	c -= a; c -= b; c ^= (b >> 13);					\
	a -= b; a -= c; a ^= (c >> 12);					\
	b -= c; b -= a; b ^= (a << 16);					\
	c -= a; c -= b; c ^= (b >> 5);					\
	a -= b; a -= c; a ^= (c >> 3);					\
	b -= c; b -= a; b ^= (a << 10);					\
	c -= a; c -= b; c ^= (b >> 15);					\
} while (/*CONSTCOND*/0)

static inline uint32_t
bridge_rthash(struct bridge_softc *sc, const uint8_t *addr)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = sc->sc_rthash_key;

	b += addr[5] << 8;
	b += addr[4];
	a += addr[3] << 24;
	a += addr[2] << 16;
	a += addr[1] << 8;
	a += addr[0];

	mix(a, b, c);

	return (c & BRIDGE_RTHASH_MASK);
}

#undef mix

/*
 * bridge_rtnode_lookup:
 *
 *	Look up a bridge route node for the specified destination.
 */
static struct bridge_rtnode *
bridge_rtnode_lookup(struct bridge_softc *sc, const uint8_t *addr)
{
	struct bridge_rtnode *brt;
	uint32_t hash;
	int dir;

	hash = bridge_rthash(sc, addr);
	LIST_FOREACH(brt, &sc->sc_rthash[hash], brt_hash) {
		dir = memcmp(addr, brt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0)
			return (brt);
		if (dir > 0)
			return (NULL);
	}

	return (NULL);
}
#ifdef __QNXNTO__
struct bridge_rtnode *
#ifndef DIAGNOSTIC
bridge_rtnode_lookup_self(struct bridge_softc *sc, const uint8_t *addr,
    struct nw_work_thread *wtp)
#else
_bridge_rtnode_lookup_self(struct bridge_softc *sc, const uint8_t *addr,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	struct bridge_rtnode *brt;
	uint32_t hash;
	int dir, self;
	struct bridge_softc_thread *bscth;

	self = *wtp->wt_bridx;

	BRIDGE_SELF_ENTER(wtp, line_from);

	bscth = &sc->sc_thread[self];
	hash = bridge_rthash(sc, addr);
	LIST_FOREACH(brt, &bscth->sc_th_rthash[hash], brt_thread[self].brt_th_hash) {
		dir = memcmp(addr, brt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0)
			break;
		if (dir > 0) {
			brt = NULL;
			break;
		}
	}

	BRIDGE_SELF_EXIT(wtp);

	return brt;
}
#endif

/*
 * bridge_rtnode_insert:
 *
 *	Insert the specified bridge node into the route table.  We
 *	assume the entry is not already in the table.
 */
static int
bridge_rtnode_insert(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	struct bridge_rtnode *lbrt;
	uint32_t hash;
	int dir;
#ifdef __QNXNTO__
	struct nw_stk_ctl *sctlp;
	struct nw_work_thread *wtp;
	pthread_t self;
#ifndef VARIANT_uni
	int i;
	struct bridge_softc_thread *bscth;
#endif
#endif

	hash = bridge_rthash(sc, brt->brt_addr);

#ifdef __QNXNTO__
	brt->brt_hash_index = hash;
	sctlp = &stk_ctl;
	wtp = WTP;
	self = *wtp->wt_bridx;
#ifdef DIAGNOSTIC
	/*
	 * uni variant never gives up the stack, non uni should never
	 * call this from the interrupt context (uni may).
	 */
	if (wtp->am_stack == 0)
		panic("bridge_rtnode: unexpected context.");
#endif
#endif
	lbrt = LIST_FIRST(&sc->sc_rthash[hash]);
	if (lbrt == NULL) {
		LIST_INSERT_HEAD(&sc->sc_rthash[hash], brt, brt_hash);
		goto out;
	}

	do {
		dir = memcmp(brt->brt_addr, lbrt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0)
			return (EEXIST);
		if (dir > 0) {
			LIST_INSERT_BEFORE(lbrt, brt, brt_hash);
			goto out;
		}
		if (LIST_NEXT(lbrt, brt_hash) == NULL) {
			LIST_INSERT_AFTER(lbrt, brt, brt_hash);
			goto out;
		}
		lbrt = LIST_NEXT(lbrt, brt_hash);
	} while (lbrt != NULL);

#ifdef DIAGNOSTIC
	panic("bridge_rtnode_insert: impossible");
#endif

 out:
	LIST_INSERT_HEAD(&sc->sc_rtlist, brt, brt_list);
	sc->sc_brtcnt++;

#ifdef __QNXNTO__
	NW_SIGHOLD_P(wtp);
#ifndef VARIANT_uni
	NW_EX_LK(&bridge_ex, iopkt_selfp);

	/* Poke each thread into seeding their private hash */
	for (i = 0; i < sctlp->nthreads_flow_max; i++) {
		if (i == self)
			continue;
		bscth = &sc->sc_thread[i];
		LIST_INSERT_HEAD(&bscth->sc_th_rttpq.tpq_create_q,
		    brt, brt_thread[i].brt_th_passlist);
		brt->brt_tpe.tpe_nthreads_creating++;
		bscth->sc_th_rttpq.tpq_items_changing++;
	}

	/* Clear out any pending self destroys before self insert */
	bscth = &sc->sc_thread[self];
	bridge_walk_destroy_qs(bscth, self);

	NW_EX_UNLK(&bridge_ex, iopkt_selfp);
#endif
	/*
	 * Stuff our own without mutex but with signal locked.
	 */

	bridge_rtnode_insert_self(sc, brt, wtp);

	NW_SIGUNHOLD_P(wtp);
#endif
	return (0);
}

#ifdef __QNXNTO__
int
#ifndef DIAGNOSTIC
bridge_rtnode_insert_self(struct bridge_softc *sc, struct bridge_rtnode *brt,
    struct nw_work_thread *wtp)
#else
_bridge_rtnode_insert_self(struct bridge_softc *sc, struct bridge_rtnode *brt,
    struct nw_work_thread *wtp, int line_from)
#endif
{
	struct bridge_rtnode *lbrt;
	uint32_t hash;
	int dir, ret, self;
	struct bridge_softc_thread *bscth;

	ret = 0;
	self = *wtp->wt_bridx;
	
	BRIDGE_SELF_ENTER(wtp, line_from);
	hash = brt->brt_hash_index;
	bscth = &sc->sc_thread[self];

	lbrt = LIST_FIRST(&bscth->sc_th_rthash[hash]);
	if (lbrt == NULL) {
                LIST_INSERT_HEAD(&bscth->sc_th_rthash[hash], brt, brt_thread[self].brt_th_hash);
		goto out;
	}

	do {
		dir = memcmp(brt->brt_addr, lbrt->brt_addr, ETHER_ADDR_LEN);
		if (dir == 0) {
			panic("rtnode self cache out of sync");
		}
		if (dir > 0) {
			LIST_INSERT_BEFORE(lbrt, brt, brt_thread[self].brt_th_hash);
			goto out;
		}
		if (LIST_NEXT(lbrt, brt_thread[self].brt_th_hash) == NULL) {
			LIST_INSERT_AFTER(lbrt, brt, brt_thread[self].brt_th_hash);
			goto out;
		}
		lbrt = LIST_NEXT(lbrt, brt_thread[self].brt_th_hash);
	} while (lbrt != NULL);

#ifdef DIAGNOSTIC
	panic("bridge_rtnode_insert_self: impossible");
#endif

 out:
	LIST_INSERT_HEAD(&bscth->sc_th_rtlist, brt, brt_thread[self].brt_th_list);
	BRIDGE_SELF_EXIT(wtp);

	return (ret);
}
#endif

/*
 * bridge_rtnode_destroy:
 *
 *	Destroy a bridge rtnode.
 */
static void
bridge_rtnode_destroy(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	int s = splnet();

#ifdef __QNXNTO__
	int self;
	struct nw_work_thread *wtp;

	wtp = WTP;

	self = *wtp->wt_bridx;
#endif
	LIST_REMOVE(brt, brt_hash);

	LIST_REMOVE(brt, brt_list);
	sc->sc_brtcnt--;
#ifndef __QNXNTO__
	pool_put(&bridge_rtnode_pool, brt);
#else
#ifdef DIAGNOSTIC
	if (ISIRUPT_P(wtp))
		panic("bridge_rtnode_destroy: unexpected context.");
#endif
	brt_start_rem(brt, sc, self, wtp);
#endif

	splx(s);
}

#if defined(BRIDGE_IPF) && defined(PFIL_HOOKS)
extern struct pfil_head inet_pfil_hook;                 /* XXX */
extern struct pfil_head inet6_pfil_hook;                /* XXX */

/*
 * Send bridge packets through IPF if they are one of the types IPF can deal
 * with, or if they are ARP or REVARP.  (IPF will pass ARP and REVARP without
 * question.)
 */
static int
bridge_ipf(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir)
{
	int snap, error;
	struct ether_header *eh1, eh2;
	struct llc llc1;
	u_int16_t ether_type;

	snap = 0;
	error = -1;	/* Default error if not error == 0 */
	eh1 = mtod(*mp, struct ether_header *);
	ether_type = ntohs(eh1->ether_type);

	/*
	 * Check for SNAP/LLC.
	 */
        if (ether_type < ETHERMTU) {
                struct llc *llc2 = (struct llc *)(eh1 + 1);

                if ((*mp)->m_len >= ETHER_HDR_LEN + 8 &&
                    llc2->llc_dsap == LLC_SNAP_LSAP &&
                    llc2->llc_ssap == LLC_SNAP_LSAP &&
                    llc2->llc_control == LLC_UI) {
                	ether_type = htons(llc2->llc_un.type_snap.ether_type);
			snap = 1;
                }
        }

	/*
	 * If we're trying to filter bridge traffic, don't look at anything
	 * other than IP and ARP traffic.  If the filter doesn't understand
	 * IPv6, don't allow IPv6 through the bridge either.  This is lame
	 * since if we really wanted, say, an AppleTalk filter, we are hosed,
	 * but of course we don't have an AppleTalk filter to begin with.
	 * (Note that since IPF doesn't understand ARP it will pass *ALL*
	 * ARP traffic.)
	 */
	switch (ether_type) {
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			return 0; /* Automatically pass */
		case ETHERTYPE_IP:
# ifdef INET6
		case ETHERTYPE_IPV6:
# endif /* INET6 */
			break;
		default:
			goto bad;
	}

	/* Strip off the Ethernet header and keep a copy. */
	m_copydata(*mp, 0, ETHER_HDR_LEN, (caddr_t) &eh2);
	m_adj(*mp, ETHER_HDR_LEN);

	/* Strip off snap header, if present */
	if (snap) {
		m_copydata(*mp, 0, sizeof(struct llc), (caddr_t) &llc1);
		m_adj(*mp, sizeof(struct llc));
	}

	/*
	 * Check basic packet sanity and run IPF through pfil.
	 */
	switch (ether_type)
	{
	case ETHERTYPE_IP :
		error = (dir == PFIL_IN) ? bridge_ip_checkbasic(mp) : 0;
		if (error == 0)
			error = pfil_run_hooks(&inet_pfil_hook, mp, ifp, dir);
		break;
# ifdef INET6
	case ETHERTYPE_IPV6 :
		error = (dir == PFIL_IN) ? bridge_ip6_checkbasic(mp) : 0;
		if (error == 0)
			error = pfil_run_hooks(&inet6_pfil_hook, mp, ifp, dir);
		break;
# endif
	default :
		error = 0;
		break;
	}

	if (*mp == NULL)
		return error;
	if (error != 0)
		goto bad;

	error = -1;

	/*
	 * Finally, put everything back the way it was and return
	 */
	if (snap) {
		M_PREPEND(*mp, sizeof(struct llc), M_DONTWAIT);
		if (*mp == NULL)
			return error;
		bcopy(&llc1, mtod(*mp, caddr_t), sizeof(struct llc));
	}

	M_PREPEND(*mp, ETHER_HDR_LEN, M_DONTWAIT);
	if (*mp == NULL)
		return error;
	bcopy(&eh2, mtod(*mp, caddr_t), ETHER_HDR_LEN);

	return 0;

    bad:
	m_freem(*mp);
	*mp = NULL;
	return error;
}

/*
 * Perform basic checks on header size since
 * IPF assumes ip_input has already processed
 * it for it.  Cut-and-pasted from ip_input.c.
 * Given how simple the IPv6 version is,
 * does the IPv4 version really need to be
 * this complicated?
 *
 * XXX Should we update ipstat here, or not?
 * XXX Right now we update ipstat but not
 * XXX csum_counter.
 */
static int
bridge_ip_checkbasic(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ip *ip;
	int len, hlen;

	if (*mp == NULL)
		return -1;

	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		if ((m = m_copyup(m, sizeof(struct ip),
			(max_linkhdr + 3) & ~3)) == NULL) {
			/* XXXJRT new stat, please */
			ipstat.ips_toosmall++;
			goto bad;
		}
	} else if (__predict_false(m->m_len < sizeof (struct ip))) {
		if ((m = m_pullup(m, sizeof (struct ip))) == NULL) {
			ipstat.ips_toosmall++;
			goto bad;
		}
	}
	ip = mtod(m, struct ip *);
	if (ip == NULL) goto bad;

	if (ip->ip_v != IPVERSION) {
		ipstat.ips_badvers++;
		goto bad;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) { /* minimum header length */
		ipstat.ips_badhlen++;
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0) {
			ipstat.ips_badhlen++;
			goto bad;
		}
		ip = mtod(m, struct ip *);
		if (ip == NULL) goto bad;
	}

        switch (m->m_pkthdr.csum_flags &
                ((m->m_pkthdr.rcvif->if_csum_flags_rx & M_CSUM_IPv4) |
                 M_CSUM_IPv4_BAD)) {
        case M_CSUM_IPv4|M_CSUM_IPv4_BAD:
                /* INET_CSUM_COUNTER_INCR(&ip_hwcsum_bad); */
                goto bad;

        case M_CSUM_IPv4:
                /* Checksum was okay. */
                /* INET_CSUM_COUNTER_INCR(&ip_hwcsum_ok); */
                break;

        default:
                /* Must compute it ourselves. */
                /* INET_CSUM_COUNTER_INCR(&ip_swcsum); */
                if (in_cksum(m, hlen) != 0)
                        goto bad;
                break;
        }

        /* Retrieve the packet length. */
        len = ntohs(ip->ip_len);

        /*
         * Check for additional length bogosity
         */
        if (len < hlen) {
                ipstat.ips_badlen++;
                goto bad;
        }

        /*
         * Check that the amount of data in the buffers
         * is as at least much as the IP header would have us expect.
         * Drop packet if shorter than we expect.
         */
        if (m->m_pkthdr.len < len) {
                ipstat.ips_tooshort++;
                goto bad;
        }

	/* Checks out, proceed */
	*mp = m;
	return 0;

    bad:
	*mp = m;
	return -1;
}

# ifdef INET6
/*
 * Same as above, but for IPv6.
 * Cut-and-pasted from ip6_input.c.
 * XXX Should we update ip6stat, or not?
 */
static int
bridge_ip6_checkbasic(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;

        /*
         * If the IPv6 header is not aligned, slurp it up into a new
         * mbuf with space for link headers, in the event we forward
         * it.  Otherwise, if it is aligned, make sure the entire base
         * IPv6 header is in the first mbuf of the chain.
         */
        if (IP6_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
                struct ifnet *inifp = m->m_pkthdr.rcvif;
                if ((m = m_copyup(m, sizeof(struct ip6_hdr),
                                  (max_linkhdr + 3) & ~3)) == NULL) {
                        /* XXXJRT new stat, please */
                        ip6stat.ip6s_toosmall++;
                        in6_ifstat_inc(inifp, ifs6_in_hdrerr);
                        goto bad;
                }
        } else if (__predict_false(m->m_len < sizeof(struct ip6_hdr))) {
                struct ifnet *inifp = m->m_pkthdr.rcvif;
                if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == NULL) {
                        ip6stat.ip6s_toosmall++;
                        in6_ifstat_inc(inifp, ifs6_in_hdrerr);
                        goto bad;
                }
        }

        ip6 = mtod(m, struct ip6_hdr *);

        if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
                ip6stat.ip6s_badvers++;
                in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_hdrerr);
                goto bad;
        }

	/* Checks out, proceed */
	*mp = m;
	return 0;

    bad:
	*mp = m;
	return -1;
}
# endif /* INET6 */
#endif /* BRIDGE_IPF && PFIL_HOOKS */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_bridge.c $ $Rev: 887443 $")
#endif
