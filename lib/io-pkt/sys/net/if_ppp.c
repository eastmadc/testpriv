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

/*	$NetBSD: if_ppp.c,v 1.111 2006/11/16 01:33:40 christos Exp $	*/
/*	Id: if_ppp.c,v 1.6 1997/03/04 03:33:00 paulus Exp 	*/

/*
 * if_ppp.c - Point-to-Point Protocol (PPP) Asynchronous driver.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Based on:
 *	@(#)if_sl.c	7.6.1.2 (Berkeley) 2/15/89
 *
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Serial Line interface
 *
 * Rick Adams
 * Center for Seismic Studies
 * 1300 N 17th Street, Suite 1450
 * Arlington, Virginia 22209
 * (703)276-7900
 * rick@seismo.ARPA
 * seismo!rick
 *
 * Pounded on heavily by Chris Torek (chris@mimsy.umd.edu, umcp-cs!chris).
 * Converted to 4.3BSD Beta by Chris Torek.
 * Other changes made at Berkeley, based in part on code by Kirk Smith.
 *
 * Converted to 4.3BSD+ 386BSD by Brad Parker (brad@cayman.com)
 * Added VJ tcp header compression; more unified ioctls
 *
 * Extensively modified by Paul Mackerras (paulus@cs.anu.edu.au).
 * Cleaned up a lot of the mbuf-related code to fix bugs that
 * caused system crashes and packet corruption.  Changed pppstart
 * so that it doesn't just give up with a collision if the whole
 * packet doesn't fit in the output ring buffer.
 *
 * Added priority queueing for interactive IP packets, following
 * the model of if_sl.c, plus hooks for bpf.
 * Paul Mackerras (paulus@cs.anu.edu.au).
 */

/* from if_sl.c,v 1.11 84/10/04 12:54:47 rick Exp */
/* from NetBSD: if_ppp.c,v 1.15.2.2 1994/07/28 05:17:58 cgd Exp */

/*
 * XXX IMP ME HARDER
 *
 * This is an explanation of that comment.  This code used to use
 * splimp() to block both network and tty interrupts.  However,
 * that call is deprecated.  So, we have replaced the uses of
 * splimp() with splhigh() in order to applomplish what it needs
 * to accomplish, and added that happy little comment.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_ppp.c,v 1.111 2006/11/16 01:33:40 christos Exp $");

#include "ppp.h"

#include "opt_inet.h"
#include "opt_gateway.h"
#include "opt_ppp.h"

#ifdef INET
#define VJC
#endif
#define PPP_COMPRESS

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#ifdef PPP_FILTER
#include <net/bpf.h>
#endif

#ifndef __QNXNTO__
#include <machine/intr.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#ifdef INET
#include <netinet/ip.h>
#endif

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#if defined(PPP_FILTER) || NBPFILTER > 0
#include <net/slip.h>
#endif

#ifdef VJC
#include <net/slcompress.h>
#endif

#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#include <net/if_pppvar.h>
#include <machine/cpu.h>

#ifdef PPP_COMPRESS
#define PACKETPTR	struct mbuf *
#include <net/ppp-comp.h>
#endif

static int	pppsioctl(struct ifnet *, u_long, caddr_t);
static void	ppp_requeue(struct ppp_softc *);
static void	ppp_ccp(struct ppp_softc *, struct mbuf *m, int rcvd);
static void	ppp_ccp_closed(struct ppp_softc *);
static void	ppp_inproc(struct ppp_softc *, struct mbuf *);
static void	pppdumpm(struct mbuf *m0);
#ifdef QNX_MULTILINKPPP
static int  pppmp_scinit(struct ppp_softc *sc, int master);
static void pppmp_input(struct ppp_softc *, struct mbuf *);
#endif
#ifdef ALTQ
static void	ppp_ifstart(struct ifnet *ifp);
#endif

#ifndef __QNXNTO__
#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
void		pppnetisr(void);
#endif
static void	pppintr(void *);
#endif

/*
 * Some useful mbuf macros not in mbuf.h.
 */
#define M_IS_CLUSTER(m)	((m)->m_flags & M_EXT)

#define M_DATASTART(m)	\
	(M_IS_CLUSTER(m) ? (m)->m_ext.ext_buf : \
	    (m)->m_flags & M_PKTHDR ? (m)->m_pktdat : (m)->m_dat)

#define M_DATASIZE(m)	\
	(M_IS_CLUSTER(m) ? (m)->m_ext.ext_size : \
	    (m)->m_flags & M_PKTHDR ? MHLEN: MLEN)

/*
 * We define two link layer specific mbuf flags, to mark high-priority
 * packets for output, and received packets following lost/corrupted
 * packets.
 */
#define	M_HIGHPRI	M_LINK0	/* output packet for sc_fastq */
#define	M_ERRMARK	M_LINK1	/* rx packet following lost/corrupted pkt */

static int		ppp_clone_create(struct if_clone *, int);
static int		ppp_clone_destroy(struct ifnet *);

static struct ppp_softc *ppp_create(const char *, int);

static LIST_HEAD(, ppp_softc) ppp_softc_list;

struct if_clone ppp_cloner =
    IF_CLONE_INITIALIZER("ppp", ppp_clone_create, ppp_clone_destroy);

#ifndef __QNXNTO__
static struct simplelock ppp_list_mutex = SIMPLELOCK_INITIALIZER;
#else
pthread_rwlock_t ppp_list_mutex = PTHREAD_RWLOCK_INITIALIZER;
#endif

#ifdef PPP_COMPRESS
/*
 * List of compressors we know about.
 * We leave some space so maybe we can modload compressors.
 */

extern struct compressor ppp_bsd_compress;
extern struct compressor ppp_deflate, ppp_deflate_draft;
#ifdef __QNXNTO__
extern struct compressor ppp_mppe;
#endif

struct compressor *ppp_compressors[PPP_COMPRESSORS_MAX] = {
#if DO_BSD_COMPRESS && defined(PPP_BSDCOMP)
    &ppp_bsd_compress,
#endif
#if DO_DEFLATE && defined(PPP_DEFLATE)
    &ppp_deflate,
    &ppp_deflate_draft,
#endif
#if DO_MPPE && defined(PPP_MPPE)
	&ppp_mppe,
#endif
    NULL
};
#endif /* PPP_COMPRESS */

#ifdef __QNXNTO__
static int qnx_checkpdev(int punit) {
	struct ppp_softc *sci;

	LIST_FOREACH(sci, &ppp_softc_list, sc_iflist) {
		if(sci->qnxsc_punit == punit) 
			return -1; /* in use */
	}
	return 0; 
}

void qnx_ifattach(struct ppp_softc *sc) {
	int i;
	pppmgr_ctrl_t *pc = &pppmgrctrl;
	if(!sc)
		return;

	if_attach(&sc->sc_if);
	if_alloc_sadl(&sc->sc_if);

	sc->qnxsc_flags |= QNXSC_IFATTACHED;
	if(pthread_rwlock_init(&sc->qnxsc_mplock, 0) != EOK)
		printf("rwlock_init failed %d\n", errno);

	qnx_simple_rdlock(&ppp_list_mutex);
		for( i = 0 ;i <= pc->punitmax ;i++ ) 
		if(qnx_checkpdev(i) == 0) {
			sc->qnxsc_punit = i;
			if(i == pc->punitmax)
				pc->punitmax++;
			break;
		}
	simple_unlock(&ppp_list_mutex);
}

void qnx_ifdetach(struct ppp_softc *sc) {
	if(sc->qnxsc_punit == -1)
		return;
	sc->qnxsc_punit = -1;
	if_detach(&sc->sc_if);
}
#endif /* QNXNTO */

/*
 * Called from boot code to establish ppp interfaces.
 */
void
pppattach(void)
{
#ifndef __QNXNTO__
    extern struct linesw ppp_disc;

    if (ttyldisc_attach(&ppp_disc) != 0)
    	panic("pppattach");
#endif
    LIST_INIT(&ppp_softc_list);
    if_clone_attach(&ppp_cloner);
}

static struct ppp_softc *
ppp_create(const char *name, int unit)
{
    struct ppp_softc *sc, *sci, *scl = NULL;

    MALLOC(sc, struct ppp_softc *, sizeof(*sc), M_DEVBUF, M_WAIT|M_ZERO);

#ifdef __QNXNTO__
	sc->qnxsc_punit = -1; 
#endif
    simple_lock(&ppp_list_mutex);
    if (unit == -1) {
	int i = 0;
	LIST_FOREACH(sci, &ppp_softc_list, sc_iflist) {
	    scl = sci;
	    if (i < sci->sc_unit) {
		unit = i;
		break;
	    } else {
#ifdef DIAGNOSTIC
		KASSERT(i == sci->sc_unit);
#endif
		i++;
	    }
	}
	if (unit == -1)
	    unit = i;
    } else {
	LIST_FOREACH(sci, &ppp_softc_list, sc_iflist) {
	    scl = sci;
	    if (unit < sci->sc_unit)
		break;
	    else if (unit == sci->sc_unit) {
#ifdef __QNXNTO__
		pthread_rwlock_destroy(&sc->qnxsc_mplock);
#endif
		FREE(sc, M_DEVBUF);
		return NULL;
	    }
	}
    }

    if (sci != NULL)
	LIST_INSERT_BEFORE(sci, sc, sc_iflist);
    else if (scl != NULL)
	LIST_INSERT_AFTER(scl, sc, sc_iflist);
    else
	LIST_INSERT_HEAD(&ppp_softc_list, sc, sc_iflist);

    simple_unlock(&ppp_list_mutex);

    (void)snprintf(sc->sc_if.if_xname, sizeof(sc->sc_if.if_xname), "%s%d",
	name, sc->sc_unit = unit);
    callout_init(&sc->sc_timo_ch);
    sc->sc_if.if_softc = sc;
    sc->sc_if.if_mtu = PPP_MTU;
    sc->sc_if.if_flags = IFF_POINTOPOINT | IFF_MULTICAST;
    sc->sc_if.if_type = IFT_PPP;
    sc->sc_if.if_hdrlen = PPP_HDRLEN;
    sc->sc_if.if_dlt = DLT_NULL;
    sc->sc_if.if_ioctl = pppsioctl;
    sc->sc_if.if_output = pppoutput;
#ifdef ALTQ
    sc->sc_if.if_start = ppp_ifstart;
#endif
    IFQ_SET_MAXLEN(&sc->sc_if.if_snd, IFQ_MAXLEN);
    sc->sc_inq.ifq_maxlen = IFQ_MAXLEN;
    sc->sc_fastq.ifq_maxlen = IFQ_MAXLEN;
    sc->sc_rawq.ifq_maxlen = IFQ_MAXLEN;
    /* Ratio of 1:2 packets between the regular and the fast queue */
    sc->sc_maxfastq = 2;	
    IFQ_SET_READY(&sc->sc_if.if_snd);
#ifndef __QNXNTO__
    if_attach(&sc->sc_if);
    if_alloc_sadl(&sc->sc_if);
#endif
#if NBPFILTER > 0
    bpfattach(&sc->sc_if, DLT_NULL, 0);
#endif
    return sc;
}

static int
ppp_clone_create(struct if_clone *ifc, int unit)
{
    return ppp_create(ifc->ifc_name, unit) == NULL ? EEXIST : 0;
}

static int
ppp_clone_destroy(struct ifnet *ifp)
{
    struct ppp_softc *sc = (struct ppp_softc *)ifp->if_softc;

    if (sc->sc_devp != NULL)
	return EBUSY; /* Not removing it */

    simple_lock(&ppp_list_mutex);
    LIST_REMOVE(sc, sc_iflist);
    simple_unlock(&ppp_list_mutex);

#if NBPFILTER > 0
    bpfdetach(ifp);
#endif
#ifndef __QNXNTO__
    if_detach(ifp);
#else
    qnx_ifdetach(sc);
    pthread_rwlock_destroy(&sc->qnxsc_mplock);
#endif
    FREE(sc, M_DEVBUF);
    return 0;
}

/*
 * Allocate a ppp interface unit and initialize it.
 */
struct ppp_softc *
pppalloc(pid_t pid)
{
    struct ppp_softc *sc = NULL, *scf;
    int i;

    simple_lock(&ppp_list_mutex);
    for (scf = LIST_FIRST(&ppp_softc_list); scf != NULL;
	scf = LIST_NEXT(scf, sc_iflist)) {
	if (scf->sc_xfer == pid) {
	    scf->sc_xfer = 0;
	    simple_unlock(&ppp_list_mutex);
	    return scf;
	}
	if (scf->sc_devp == NULL && sc == NULL)
	    sc = scf;
    }
    simple_unlock(&ppp_list_mutex);

    if (sc == NULL)
	sc = ppp_create(ppp_cloner.ifc_name, -1);

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
    sc->sc_si = softintr_establish(IPL_SOFTNET, pppintr, sc);
    if (sc->sc_si == NULL) {
	printf("%s: unable to establish softintr\n", sc->sc_if.if_xname);
	return (NULL);
    }
#endif
    sc->sc_flags = 0;
    sc->sc_mru = PPP_MRU;
    sc->sc_relinq = NULL;
    (void)memset(&sc->sc_stats, 0, sizeof(sc->sc_stats));
#ifdef VJC
    MALLOC(sc->sc_comp, struct slcompress *, sizeof(struct slcompress),
	   M_DEVBUF, M_NOWAIT);
    if (sc->sc_comp)
	sl_compress_init(sc->sc_comp);
#endif
#ifdef PPP_COMPRESS
    sc->sc_xc_state = NULL;
    sc->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */
    for (i = 0; i < NUM_NP; ++i)
	sc->sc_npmode[i] = NPMODE_ERROR;
    sc->sc_npqueue = NULL;
    sc->sc_npqtail = &sc->sc_npqueue;
    sc->sc_last_sent = sc->sc_last_recv = time_second;
#ifdef __QNXNTO__
    callout_init(&sc->tx_callout); 
#endif
    return sc;
}

/*
 * Deallocate a ppp unit.  Must be called at splsoftnet or higher.
 */
#if defined(__QNXNTO__) && defined(QNX_MULTILINKPPP)
static int qnx_mpppdealloc(struct ppp_softc *sc);
#endif
void
pppdealloc(struct ppp_softc *sc)
{
    struct mbuf *m;

#ifdef __QNXNTO__
    struct pppmgr_ocb *ocb = sc->qnxsc_ocb;

    if(ocb) {
        if(ocb->reader_rcvid) {
            MsgError(ocb->reader_rcvid, EBADF);
            ocb->reader_rcvid = 0;
        }
        ocb->ocb_flag &= ~OCBFLAG_PPP_ATTACHED;
    }
#ifdef QNX_MULTILINKPPP
    if((sc->qnxsc_flags & (QNXSC_IFATTACHED | QNXSC_MPSLAVE)))
        if(qnx_mpppdealloc(sc) == -1)
            return;
#endif
#endif

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
    softintr_disestablish(sc->sc_si);
#endif
#ifdef __QNXNTO__
    callout_stop(&sc->tx_callout);
#endif
    if_down(&sc->sc_if);
    sc->sc_if.if_flags &= ~(IFF_UP|IFF_RUNNING);
    sc->sc_devp = NULL;
    sc->sc_xfer = 0;
    for (;;) {
	IF_DEQUEUE(&sc->sc_rawq, m);
	if (m == NULL)
	    break;
	m_freem(m);
    }
    for (;;) {
	IF_DEQUEUE(&sc->sc_inq, m);
	if (m == NULL)
	    break;
	m_freem(m);
    }
    for (;;) {
	IF_DEQUEUE(&sc->sc_fastq, m);
	if (m == NULL)
	    break;
	m_freem(m);
    }
    while ((m = sc->sc_npqueue) != NULL) {
	sc->sc_npqueue = m->m_nextpkt;
	m_freem(m);
    }
    if (sc->sc_togo != NULL) {
	m_freem(sc->sc_togo);
	sc->sc_togo = NULL;
    }
#ifdef PPP_COMPRESS
    ppp_ccp_closed(sc);
    sc->sc_xc_state = NULL;
    sc->sc_rc_state = NULL;
#endif /* PPP_COMPRESS */
#ifdef PPP_FILTER
    if (sc->sc_pass_filt_in.bf_insns != 0) {
	FREE(sc->sc_pass_filt_in.bf_insns, M_DEVBUF);
	sc->sc_pass_filt_in.bf_insns = 0;
	sc->sc_pass_filt_in.bf_len = 0;
    }
    if (sc->sc_pass_filt_out.bf_insns != 0) {
	FREE(sc->sc_pass_filt_out.bf_insns, M_DEVBUF);
	sc->sc_pass_filt_out.bf_insns = 0;
	sc->sc_pass_filt_out.bf_len = 0;
    }
    if (sc->sc_active_filt_in.bf_insns != 0) {
	FREE(sc->sc_active_filt_in.bf_insns, M_DEVBUF);
	sc->sc_active_filt_in.bf_insns = 0;
	sc->sc_active_filt_in.bf_len = 0;
    }
    if (sc->sc_active_filt_out.bf_insns != 0) {
	FREE(sc->sc_active_filt_out.bf_insns, M_DEVBUF);
	sc->sc_active_filt_out.bf_insns = 0;
	sc->sc_active_filt_out.bf_len = 0;
    }
#endif /* PPP_FILTER */
#ifdef VJC
    if (sc->sc_comp != 0) {
	FREE(sc->sc_comp, M_DEVBUF);
	sc->sc_comp = 0;
    }
#endif
    (void)ppp_clone_destroy(&sc->sc_if);
}

/*
 * Ioctl routine for generic ppp devices.
 */
int
pppioctl(struct ppp_softc *sc, u_long cmd, caddr_t data, int flag,
    struct lwp *l)
{
    int s, error, flags, mru, npx;
    u_int nb;
    struct ppp_option_data *odp;
    struct compressor **cp;
    struct npioctl *npi;
    time_t t;
#ifdef PPP_FILTER
    struct bpf_program *bp, *nbp;
    struct bpf_insn *newcode, *oldcode;
    int newcodelen;
#endif /* PPP_FILTER */
#ifdef	PPP_COMPRESS
    u_char ccp_option[CCP_MAX_OPTION_LENGTH];
#endif

    switch (cmd) {
    case PPPIOCSFLAGS:
    case PPPIOCSMRU:
    case PPPIOCSMAXCID:
    case PPPIOCSCOMPRESS:
    case PPPIOCSNPMODE:
	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_INTERFACE,
	    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, &sc->sc_if, (void *)cmd,
	    NULL) != 0)
		return (EPERM);
	break;
    case PPPIOCXFERUNIT:
	/* XXX: Why is this privileged?! */
	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_INTERFACE,
	    KAUTH_REQ_NETWORK_INTERFACE_GETPRIV, &sc->sc_if, (void *)cmd,
	    NULL) != 0)
		return (EPERM);
	break;
    default:
	break;
    }

    switch (cmd) {
    case FIONREAD:
	*(int *)data = sc->sc_inq.ifq_len;
	break;

    case PPPIOCGUNIT:
	*(int *)data = sc->sc_unit;
	break;

    case PPPIOCGFLAGS:
	*(u_int *)data = sc->sc_flags;
	break;

    case PPPIOCGRAWIN:
	{
	    struct ppp_rawin *rwin = (struct ppp_rawin *)data;
	    u_char c, q = 0;

	    for (c = sc->sc_rawin_start; c < sizeof(sc->sc_rawin.buf);)
		rwin->buf[q++] = sc->sc_rawin.buf[c++];

	    for (c = 0; c < sc->sc_rawin_start;)
		rwin->buf[q++] = sc->sc_rawin.buf[c++];

	    rwin->count = sc->sc_rawin.count;
	}
	break;

    case PPPIOCSFLAGS:
	flags = *(int *)data & SC_MASK;
	s = splsoftnet();
#ifdef PPP_COMPRESS
	if (sc->sc_flags & SC_CCP_OPEN && !(flags & SC_CCP_OPEN))
	    ppp_ccp_closed(sc);
#endif
#ifndef __QNXNTO__
	splhigh();	/* XXX IMP ME HARDER */
#endif
	sc->sc_flags = (sc->sc_flags & ~SC_MASK) | flags;
	splx(s);
	break;

    case PPPIOCSMRU:
	mru = *(int *)data;
	if (mru >= PPP_MINMRU && mru <= PPP_MAXMRU)
	    sc->sc_mru = mru;
	break;

    case PPPIOCGMRU:
	*(int *)data = sc->sc_mru;
	break;

#ifdef VJC
    case PPPIOCSMAXCID:
	if (sc->sc_comp) {
	    s = splsoftnet();
	    sl_compress_setup(sc->sc_comp, *(int *)data);
	    splx(s);
	}
	break;
#endif

    case PPPIOCXFERUNIT:
#ifndef __QNXNTO__
	sc->sc_xfer = l->l_proc->p_pid;
#else
	sc->sc_xfer = LWP_TO_PR(l)->p_ctxt.info.pid;
#endif
	break;

#ifdef PPP_COMPRESS
    case PPPIOCSCOMPRESS:
	odp = (struct ppp_option_data *) data;
	nb = odp->length;
	if (nb > sizeof(ccp_option))
	    nb = sizeof(ccp_option);
# ifndef __QNXNTO__
	if ((error = copyin(odp->ptr, ccp_option, nb)) != 0)
	    return (error);
# else
	/* in QNX, the passed in ccp_option, is followed odp */
	if ((error = copyin(odp + 1, ccp_option, nb)) != 0)
	    return (error);
# endif
	if (ccp_option[1] < 2)	/* preliminary check on the length byte */
	    return (EINVAL);
	for (cp = ppp_compressors; *cp != NULL; ++cp)
	    if ((*cp)->compress_proto == ccp_option[0]) {
		/*
		 * Found a handler for the protocol - try to allocate
		 * a compressor or decompressor.
		 */
		error = 0;
		if (odp->transmit) {
		    s = splsoftnet();
		    if (sc->sc_xc_state != NULL)
			(*sc->sc_xcomp->comp_free)(sc->sc_xc_state);
		    sc->sc_xcomp = *cp;
		    sc->sc_xc_state = (*cp)->comp_alloc(ccp_option, nb);
		    if (sc->sc_xc_state == NULL) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: comp_alloc failed\n",
				sc->sc_if.if_xname);
			error = ENOBUFS;
		    }
#ifndef __QNXNTO__
		    splhigh();	/* XXX IMP ME HARDER */
#endif
		    sc->sc_flags &= ~SC_COMP_RUN;
		    splx(s);
		} else {
		    s = splsoftnet();
		    if (sc->sc_rc_state != NULL)
			(*sc->sc_rcomp->decomp_free)(sc->sc_rc_state);
		    sc->sc_rcomp = *cp;
		    sc->sc_rc_state = (*cp)->decomp_alloc(ccp_option, nb);
		    if (sc->sc_rc_state == NULL) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: decomp_alloc failed\n",
				sc->sc_if.if_xname);
			error = ENOBUFS;
		    }
#ifndef __QNXNTO__
		    splhigh();	/* XXX IMP ME HARDER */
#endif
		    sc->sc_flags &= ~SC_DECOMP_RUN;
		    splx(s);
		}
		return (error);
	    }
	if (sc->sc_flags & SC_DEBUG)
	    printf("%s: no compressor for [%x %x %x], %x\n",
		sc->sc_if.if_xname, ccp_option[0], ccp_option[1],
		ccp_option[2], nb);
	return (EINVAL);	/* no handler found */
#endif /* PPP_COMPRESS */

    case PPPIOCGNPMODE:
    case PPPIOCSNPMODE:
	npi = (struct npioctl *) data;
	switch (npi->protocol) {
	case PPP_IP:
	    npx = NP_IP;
	    break;
	case PPP_IPV6:
	    npx = NP_IPV6;
	    break;
	default:
	    return EINVAL;
	}
	if (cmd == PPPIOCGNPMODE) {
	    npi->mode = sc->sc_npmode[npx];
	} else {
	    if (npi->mode != sc->sc_npmode[npx]) {
		s = splnet();
		sc->sc_npmode[npx] = npi->mode;
		if (npi->mode != NPMODE_QUEUE) {
		    ppp_requeue(sc);
		    ppp_restart(sc);
		}
		splx(s);
	    }
	}
	break;

    case PPPIOCGIDLE:
#ifndef __QNXNTO__
	s = splsoftnet();
#endif
	t = time_second;
	((struct ppp_idle *)data)->xmit_idle = t - sc->sc_last_sent;
	((struct ppp_idle *)data)->recv_idle = t - sc->sc_last_recv;
	splx(s);
	break;

#ifdef PPP_FILTER
    case PPPIOCSPASS:
    case PPPIOCSACTIVE:
	/* These are no longer supported. */
	return EOPNOTSUPP;

    case PPPIOCSIPASS:
    case PPPIOCSOPASS:
    case PPPIOCSIACTIVE:
    case PPPIOCSOACTIVE:
	nbp = (struct bpf_program *) data;
	if ((unsigned) nbp->bf_len > BPF_MAXINSNS)
	    return EINVAL;
	newcodelen = nbp->bf_len * sizeof(struct bpf_insn);
	if (newcodelen != 0) {
	    newcode = malloc(newcodelen, M_DEVBUF, M_WAITOK);
	    /* WAITOK -- malloc() never fails. */
	    if ((error = copyin((caddr_t)nbp->bf_insns, (caddr_t)newcode,
			       newcodelen)) != 0) {
		free(newcode, M_DEVBUF);
		return error;
	    }
	    if (!bpf_validate(newcode, nbp->bf_len)) {
		free(newcode, M_DEVBUF);
		return EINVAL;
	    }
	} else
	    newcode = 0;
	switch (cmd) {
	case PPPIOCSIPASS:
	    bp = &sc->sc_pass_filt_in;
	    break;

	case PPPIOCSOPASS:
	    bp = &sc->sc_pass_filt_out;
	    break;

	case PPPIOCSIACTIVE:
	    bp = &sc->sc_active_filt_in;
	    break;

	case PPPIOCSOACTIVE:
	    bp = &sc->sc_active_filt_out;
	    break;
	default:
	    free(newcode, M_DEVBUF);
	    return (EPASSTHROUGH);
	}
	oldcode = bp->bf_insns;
	s = splnet();
	bp->bf_len = nbp->bf_len;
	bp->bf_insns = newcode;
	splx(s);
	if (oldcode != 0)
	    free(oldcode, M_DEVBUF);
	break;
#endif /* PPP_FILTER */
#ifdef __QNXNTO__
	case PPPIOCSMTU:
	{
		int mtu;
		if ((mtu = *(int *)data) < PPP_MINMTU || mtu > PPP_MAXMTU)
			return EINVAL;
		sc->sc_if.if_mtu = mtu;
		qnxtty_txrawbuf(sc);
		break;
	}
    case PPPIOCGMTU:
	    *(int *)data = sc->sc_if.if_mtu;
		break;
		
    case PPPIOCGCHAN:
        *(int *)data = sc->sc_unit;
        break;

    case PPPIOCNEWUNIT:
        qnx_ifattach(sc);
        *(int *)data = sc->qnxsc_punit;
        break;

    case PPPIOCDETACH:
        qnxppp_ttydetach(sc, 0);
        break;
#ifdef QNX_MULTILINKPPP
    case PPPIOCSMRRU:
    sc->qnxsc_mpmrru = *(int32_t *)data;
    break;

        case PPPIOCGSTAT:
    *(int *)data = sc->qnxsc_flags;
    break;

    case PPPIOCCONNECT:
        return pppmp_scinit(sc, *(int32_t *)data);
#endif
#endif

    default:
	return (EPASSTHROUGH);
    }
    return (0);
}

/*
 * Process an ioctl request to the ppp network interface.
 */
static int
pppsioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
    struct lwp *l = curlwp;	/* XXX */
    struct ppp_softc *sc = ifp->if_softc;
    struct ifaddr *ifa = (struct ifaddr *)data;
    struct ifreq *ifr = (struct ifreq *)data;
    struct ppp_stats *psp;
#ifdef	PPP_COMPRESS
    struct ppp_comp_stats *pcp;
#endif
    int s = splnet(), error = 0;

    switch (cmd) {
    case SIOCSIFFLAGS:
	if ((ifp->if_flags & IFF_RUNNING) == 0)
	    ifp->if_flags &= ~IFF_UP;
	break;

    case SIOCSIFADDR:
	switch (ifa->ifa_addr->sa_family) {
#ifdef INET
	case AF_INET:
	    break;
#endif
#ifdef INET6
	case AF_INET6:
	    break;
#endif
	default:
	    error = EAFNOSUPPORT;
	    break;
	}
	break;

    case SIOCSIFDSTADDR:
	switch (ifa->ifa_addr->sa_family) {
#ifdef INET
	case AF_INET:
	    break;
#endif
#ifdef INET6
	case AF_INET6:
	    break;
#endif
	default:
	    error = EAFNOSUPPORT;
	    break;
	}
	break;

    case SIOCSIFMTU:
	if ((error = kauth_authorize_network(l->l_cred,
	    KAUTH_NETWORK_INTERFACE, KAUTH_REQ_NETWORK_INTERFACE_SETPRIV,
	    ifp, (void *)cmd, NULL) != 0))
	    break;
	sc->sc_if.if_mtu = ifr->ifr_mtu;
	break;

    case SIOCGIFMTU:
	ifr->ifr_mtu = sc->sc_if.if_mtu;
	break;

    case SIOCADDMULTI:
    case SIOCDELMULTI:
	if (ifr == 0) {
	    error = EAFNOSUPPORT;
	    break;
	}
	switch (ifreq_getaddr(cmd, ifr)->sa_family) {
#ifdef INET
	case AF_INET:
	    break;
#endif
#ifdef INET6
	case AF_INET6:
	    break;
#endif
	default:
	    error = EAFNOSUPPORT;
	    break;
	}
	break;

    case SIOCGPPPSTATS:
	psp = &((struct ifpppstatsreq *) data)->stats;
	memset(psp, 0, sizeof(*psp));
	psp->p = sc->sc_stats;
#if defined(VJC) && !defined(SL_NO_STATS)
	if (sc->sc_comp) {
	    psp->vj.vjs_packets = sc->sc_comp->sls_packets;
	    psp->vj.vjs_compressed = sc->sc_comp->sls_compressed;
	    psp->vj.vjs_searches = sc->sc_comp->sls_searches;
	    psp->vj.vjs_misses = sc->sc_comp->sls_misses;
	    psp->vj.vjs_uncompressedin = sc->sc_comp->sls_uncompressedin;
	    psp->vj.vjs_compressedin = sc->sc_comp->sls_compressedin;
	    psp->vj.vjs_errorin = sc->sc_comp->sls_errorin;
	    psp->vj.vjs_tossed = sc->sc_comp->sls_tossed;
	}
#endif /* VJC */
	break;

#ifdef PPP_COMPRESS
    case SIOCGPPPCSTATS:
	pcp = &((struct ifpppcstatsreq *) data)->stats;
	memset(pcp, 0, sizeof(*pcp));
	if (sc->sc_xc_state != NULL)
	    (*sc->sc_xcomp->comp_stat)(sc->sc_xc_state, &pcp->c);
	if (sc->sc_rc_state != NULL)
	    (*sc->sc_rcomp->decomp_stat)(sc->sc_rc_state, &pcp->d);
	break;
#endif /* PPP_COMPRESS */

    default:
	error = EINVAL;
    }
    splx(s);
    return (error);
}

/*
 * Queue a packet.  Start transmission if not active.
 * Packet is placed in Information field of PPP frame.
 */
int
pppoutput(struct ifnet *ifp, struct mbuf *m0, struct sockaddr *dst,
    struct rtentry *rtp)
{
    struct ppp_softc *sc = ifp->if_softc;
    int protocol, address, control;
    u_char *cp;
#ifndef __QNXNTO__
    int s, error;
#else
    int error;
#endif
#ifdef INET
    struct ip *ip;
#endif
    struct ifqueue *ifq;
    enum NPmode mode;
    int len;
    ALTQ_DECL(struct altq_pktattr pktattr;)

#ifndef __QNXNTO__
    if (sc->sc_devp == NULL || (ifp->if_flags & IFF_RUNNING) == 0
	|| ((ifp->if_flags & IFF_UP) == 0 && dst->sa_family != AF_UNSPEC)) {
	error = ENETDOWN;	/* sort of */
	goto bad;
    }
#else 
    if ((ifp->if_flags & IFF_RUNNING) == 0
	|| ((ifp->if_flags & IFF_UP) == 0 && dst->sa_family != AF_UNSPEC)) {
	error = ENETDOWN;	/* sort of */
	goto bad;
    }
    if (sc->sc_devp == NULL) {
		if( (sc->qnxsc_flags & QNXSC_KEEPALIVE) == 0 ) {
			error = ENETDOWN;	/* sort of */
			goto bad;
		}
    }
#endif

    IFQ_CLASSIFY(&ifp->if_snd, m0, dst->sa_family, &pktattr);

    /*
     * Compute PPP header.
     */
    m0->m_flags &= ~M_HIGHPRI;
    switch (dst->sa_family) {
#ifdef INET
    case AF_INET:
	address = PPP_ALLSTATIONS;
	control = PPP_UI;
	protocol = PPP_IP;
	mode = sc->sc_npmode[NP_IP];

	/*
	 * If this packet has the "low delay" bit set in the IP header,
	 * put it on the fastq instead.
	 */
	ip = mtod(m0, struct ip *);
	if (ip->ip_tos & IPTOS_LOWDELAY)
	    m0->m_flags |= M_HIGHPRI;
	break;
#endif
#ifdef INET6
    case AF_INET6:
	address = PPP_ALLSTATIONS;	/*XXX*/
	control = PPP_UI;		/*XXX*/
	protocol = PPP_IPV6;
	mode = sc->sc_npmode[NP_IPV6];

#if 0	/* XXX flowinfo/traffic class, maybe? */
	/*
	 * If this packet has the "low delay" bit set in the IP header,
	 * put it on the fastq instead.
	 */
	ip = mtod(m0, struct ip *);
	if (ip->ip_tos & IPTOS_LOWDELAY)
	    m0->m_flags |= M_HIGHPRI;
#endif
	break;
#endif
    case AF_UNSPEC:
	address = PPP_ADDRESS(dst->sa_data);
	control = PPP_CONTROL(dst->sa_data);
	protocol = PPP_PROTOCOL(dst->sa_data);
	mode = NPMODE_PASS;
	break;
    default:
	printf("%s: af%d not supported\n", ifp->if_xname, dst->sa_family);
	error = EAFNOSUPPORT;
	goto bad;
    }

    /*
     * Drop this packet, or return an error, if necessary.
     */
    if (mode == NPMODE_ERROR) {
	error = ENETDOWN;
	goto bad;
    }
    if (mode == NPMODE_DROP) {
	error = 0;
	goto bad;
    }

    /*
     * Add PPP header.
     */
    M_PREPEND(m0, PPP_HDRLEN, M_DONTWAIT);
    if (m0 == NULL) {
	error = ENOBUFS;
	goto bad;
    }

    cp = mtod(m0, u_char *);
    *cp++ = address;
    *cp++ = control;
    *cp++ = protocol >> 8;
    *cp++ = protocol & 0xff;

    len = m_length(m0);

    if (sc->sc_flags & SC_LOG_OUTPKT) {
	printf("%s output: ", ifp->if_xname);
	pppdumpm(m0);
    }

    if ((protocol & 0x8000) == 0) {
#ifdef PPP_FILTER
	/*
	 * Apply the pass and active filters to the packet,
	 * but only if it is a data packet.
	 */
	if (sc->sc_pass_filt_out.bf_insns != 0
	    && bpf_filter(sc->sc_pass_filt_out.bf_insns, (u_char *) m0,
			  len, 0) == 0) {
	    error = 0;		/* drop this packet */
	    goto bad;
	}

	/*
	 * Update the time we sent the most recent packet.
	 */
	if (sc->sc_active_filt_out.bf_insns == 0
	    || bpf_filter(sc->sc_active_filt_out.bf_insns, (u_char *) m0,
	    		  len, 0))
	    sc->sc_last_sent = time_second;
#else
	/*
	 * Update the time we sent the most recent packet.
	 */
	sc->sc_last_sent = time_second;
#endif /* PPP_FILTER */
    }

#if NBPFILTER > 0
    /*
     * See if bpf wants to look at the packet.
     */
    if (sc->sc_if.if_bpf)
	bpf_mtap(sc->sc_if.if_bpf, m0);
#endif

    /*
     * Put the packet on the appropriate queue.
     */
#ifndef __QNXNTO__
    s = splnet();
    if (mode == NPMODE_QUEUE) {
	/* XXX we should limit the number of packets on this queue */
	*sc->sc_npqtail = m0;
	m0->m_nextpkt = NULL;
	sc->sc_npqtail = &m0->m_nextpkt;
    } else {
	ifq = (m0->m_flags & M_HIGHPRI) ? &sc->sc_fastq : NULL;
	if ((error = ifq_enqueue2(&sc->sc_if, ifq, m0
		ALTQ_COMMA ALTQ_DECL(&pktattr))) != 0) {
	    splx(s);
	    sc->sc_if.if_oerrors++;
	    sc->sc_stats.ppp_oerrors++;
	    return (error);
	}
	ppp_restart(sc);
    }
    ifp->if_opackets++;
    ifp->if_obytes += len;

    splx(s);
    return (0);
#else /* QNX ENQUEUE OUTQ */
{
	struct nw_work_thread *wtp = WTP;

	NW_SIGLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
    if (mode == NPMODE_QUEUE) {
	/* XXX we should limit the number of packets on this queue */
		struct pppmgr_ocb *ocb = sc->qnxsc_ocb;

		if((sc->sc_npqtail == &sc->sc_npqueue) && !(ocb->ocb_flag & OCBFLAG_PPP_NPQUEUED))
			ocb->ocb_flag |= OCBFLAG_PPP_NPQUEUED;

		*sc->sc_npqtail = m0;
		m0->m_nextpkt = NULL;
		sc->sc_npqtail = &m0->m_nextpkt;
		ifp->if_opackets++;
		ifp->if_obytes += len;
#ifdef __QNXNTO__
		iofunc_notify_trigger(ocb->notify, 1, IOFUNC_NOTIFY_INPUT);
#endif
		NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
    } else { 
		if ((m0->m_flags & M_HIGHPRI)
#ifdef ALTQ
	    && ALTQ_IS_ENABLED(&sc->sc_if.if_snd) == 0
#endif
			) {
			ifq = &sc->sc_fastq;
			if (IF_QFULL(ifq) && dst->sa_family != AF_UNSPEC) {
				IF_DROP(ifq);
				NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
				error = ENOBUFS;
				goto bad;
			} else {
			IF_ENQUEUE(ifq, m0);
			error = 0;
			}
		} else 
			IFQ_ENQUEUE(&sc->sc_if.if_snd, m0, &pktattr, error);

		if (error) {
			sc->sc_if.if_oerrors++;
			sc->sc_stats.ppp_oerrors++;
			NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
			return (error);
		}
		ifp->if_opackets++;
		ifp->if_obytes += len;
		NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
		ppp_restart(sc);
	} 
	return (0);
}
#endif
bad:
    m_freem(m0);
    return (error);
}

/*
 * After a change in the NPmode for some NP, move packets from the
 * npqueue to the send queue or the fast queue as appropriate.
 * Should be called at splnet, since we muck with the queues.
 */
static void
ppp_requeue(struct ppp_softc *sc)
{
    struct mbuf *m, **mpp;
    struct ifqueue *ifq;
    enum NPmode mode;
    int error;

    for (mpp = &sc->sc_npqueue; (m = *mpp) != NULL; ) {
	switch (PPP_PROTOCOL(mtod(m, u_char *))) {
	case PPP_IP:
	    mode = sc->sc_npmode[NP_IP];
	    break;
	case PPP_IPV6:
	    mode = sc->sc_npmode[NP_IPV6];
	    break;
	default:
	    mode = NPMODE_PASS;
	}

	switch (mode) {
	case NPMODE_PASS:
	    /*
	     * This packet can now go on one of the queues to be sent.
	     */
	    *mpp = m->m_nextpkt;
	    m->m_nextpkt = NULL;
	    ifq = (m->m_flags & M_HIGHPRI) ? &sc->sc_fastq : NULL;
	    if ((error = ifq_enqueue2(&sc->sc_if, ifq, m ALTQ_COMMA
		ALTQ_DECL(NULL))) != 0) {
		sc->sc_if.if_oerrors++;
		sc->sc_stats.ppp_oerrors++;
	    }
	    break;

	case NPMODE_DROP:
	case NPMODE_ERROR:
	    *mpp = m->m_nextpkt;
	    m_freem(m);
	    break;

	case NPMODE_QUEUE:
	    mpp = &m->m_nextpkt;
	    break;
	}
    }
    sc->sc_npqtail = mpp;
}

/*
 * Transmitter has finished outputting some stuff;
 * remember to call sc->sc_start later at splsoftnet.
 */
void
ppp_restart(struct ppp_softc *sc)
{
#ifndef __QNXNTO__
    int s = splhigh();	/* XXX IMP ME HARDER */

    sc->sc_flags &= ~SC_TBUSY;
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
    softintr_schedule(sc->sc_si);
#else
    schednetisr(NETISR_PPP);
#endif
    splx(s);
#else /* QNXNTO */
extern void pppasyncstart(struct ppp_softc* sc);
    sc->sc_flags &= ~SC_TBUSY;
    pppasyncstart(sc);
#endif
}

/*
 * Get a packet to send.  This procedure is intended to be called at
 * splsoftnet, since it may involve time-consuming operations such as
 * applying VJ compression, packet compression, address/control and/or
 * protocol field compression to the packet.
 */
struct mbuf *
ppp_dequeue(struct ppp_softc *sc)
{
    struct mbuf *m, *mp;
    u_char *cp;
    int address, control, protocol;
    int s;

    /*
     * Grab a packet to send: first try the fast queue, then the
     * normal queue.
     */
    s = splnet();
    if (sc->sc_nfastq < sc->sc_maxfastq) {
	IF_DEQUEUE(&sc->sc_fastq, m);
	if (m != NULL)
	    sc->sc_nfastq++;
	else
	    IFQ_DEQUEUE(&sc->sc_if.if_snd, m);
    } else {
	sc->sc_nfastq = 0;
	IFQ_DEQUEUE(&sc->sc_if.if_snd, m);
	if (m == NULL) {
	    IF_DEQUEUE(&sc->sc_fastq, m);
	    if (m != NULL)
		sc->sc_nfastq++;
	}
    }
    splx(s);

    if (m == NULL)
	return NULL;

    ++sc->sc_stats.ppp_opackets;

    /*
     * Extract the ppp header of the new packet.
     * The ppp header will be in one mbuf.
     */
    cp = mtod(m, u_char *);
    address = PPP_ADDRESS(cp);
    control = PPP_CONTROL(cp);
    protocol = PPP_PROTOCOL(cp);

    switch (protocol) {
    case PPP_IP:
#ifdef VJC
	/*
	 * If the packet is a TCP/IP packet, see if we can compress it.
	 */
	if ((sc->sc_flags & SC_COMP_TCP) && sc->sc_comp != NULL) {
	    struct ip *ip;
	    int type;

	    mp = m;
	    ip = (struct ip *) (cp + PPP_HDRLEN);
	    if (mp->m_len <= PPP_HDRLEN) {
		mp = mp->m_next;
		if (mp == NULL)
		    break;
		ip = mtod(mp, struct ip *);
	    }
	    /* this code assumes the IP/TCP header is in one non-shared mbuf */
	    if (ip->ip_p == IPPROTO_TCP) {
		type = sl_compress_tcp(mp, ip, sc->sc_comp,
				       !(sc->sc_flags & SC_NO_TCP_CCID));
		switch (type) {
		case TYPE_UNCOMPRESSED_TCP:
		    protocol = PPP_VJC_UNCOMP;
		    break;
		case TYPE_COMPRESSED_TCP:
		    protocol = PPP_VJC_COMP;
		    cp = mtod(m, u_char *);
		    cp[0] = address;	/* header has moved */
		    cp[1] = control;
		    cp[2] = 0;
		    break;
		}
		cp[3] = protocol;	/* update protocol in PPP header */
	    }
	}
#endif	/* VJC */
	break;

#ifdef PPP_COMPRESS
    case PPP_CCP:
	ppp_ccp(sc, m, 0);
	break;
#endif	/* PPP_COMPRESS */
    }

#ifdef PPP_COMPRESS
    if (protocol != PPP_LCP && protocol != PPP_CCP
	&& sc->sc_xc_state && (sc->sc_flags & SC_COMP_RUN)) {
	struct mbuf *mcomp = NULL;
	int slen;

	slen = 0;
	for (mp = m; mp != NULL; mp = mp->m_next)
	    slen += mp->m_len;
	(*sc->sc_xcomp->compress)
	    (sc->sc_xc_state, &mcomp, m, slen, sc->sc_if.if_mtu + PPP_HDRLEN);
	if (mcomp != NULL) {
	    if (sc->sc_flags & SC_CCP_UP) {
		/* Send the compressed packet instead of the original. */
		m_freem(m);
		m = mcomp;
		cp = mtod(m, u_char *);
		protocol = cp[3];
	    } else {
		/* Can't transmit compressed packets until CCP is up. */
		m_freem(mcomp);
	    }
	}
    }
#endif	/* PPP_COMPRESS */

    /*
     * Compress the address/control and protocol, if possible.
     */
#ifndef QNX_MULTILINKPPP
    if (sc->sc_flags & SC_COMP_AC && address == PPP_ALLSTATIONS &&
	control == PPP_UI && protocol != PPP_ALLSTATIONS &&
	protocol != PPP_LCP)
#else
    if ( ( (sc->qnxsc_flags & QNXSC_MPPP) || (sc->sc_flags & SC_COMP_AC) ) && address == PPP_ALLSTATIONS &&
	control == PPP_UI && protocol != PPP_ALLSTATIONS &&
	protocol != PPP_LCP)
#endif
    {
	/* can compress address/control */
	m->m_data += 2;
	m->m_len -= 2;
    }
#ifndef QNX_MULTILINKPPP
    if (sc->sc_flags & SC_COMP_PROT && protocol < 0xFF)
#else
    if ( ( (sc->qnxsc_flags & QNXSC_MPPP) || (sc->sc_flags & SC_COMP_PROT) ) && protocol < 0xFF)
#endif
    {
	/* can compress protocol */
	if (mtod(m, u_char *) == cp) {
	    cp[2] = cp[1];	/* move address/control up */
	    cp[1] = cp[0];
	}
	++m->m_data;
	--m->m_len;
    }

    return m;
}

#ifndef __QNXNTO__
#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
void
pppnetisr(void)
{
	struct ppp_softc *sc;

	for (sc = LIST_FIRST(&ppp_softc_list); sc != NULL;
	    sc = LIST_NEXT(sc, sc_iflist))
		pppintr(sc);
}
#endif
/*
 * Software interrupt routine, called at splsoftnet.
 */
static void
pppintr(void *arg)
{
	struct ppp_softc *sc = arg;
#ifndef __QNXNTO__
	struct mbuf *m;
#endif
	int s;

	if (!(sc->sc_flags & SC_TBUSY)
	    && (IFQ_IS_EMPTY(&sc->sc_if.if_snd) == 0 || sc->sc_fastq.ifq_head
		|| sc->sc_outm)) {
		s = splhigh();	/* XXX IMP ME HARDER */
		sc->sc_flags |= SC_TBUSY;
		splx(s);
		(*sc->sc_start)(sc);
	}
#ifndef __QNXNTO__
	for (;;) {
		s = splnet();
		IF_DEQUEUE(&sc->sc_rawq, m);
		splx(s);
		if (m == NULL)
			break;
		ppp_inproc(sc, m);
	}
#endif
}
#endif
#ifdef PPP_COMPRESS
/*
 * Handle a CCP packet.  `rcvd' is 1 if the packet was received,
 * 0 if it is about to be transmitted.
 */
static void
ppp_ccp(struct ppp_softc *sc, struct mbuf *m, int rcvd)
{
    u_char *dp, *ep;
    struct mbuf *mp;
    int slen, s;

    /*
     * Get a pointer to the data after the PPP header.
     */
    if (m->m_len <= PPP_HDRLEN) {
	mp = m->m_next;
	if (mp == NULL)
	    return;
	dp = (mp != NULL)? mtod(mp, u_char *): NULL;
    } else {
	mp = m;
	dp = mtod(mp, u_char *) + PPP_HDRLEN;
    }

    ep = mtod(mp, u_char *) + mp->m_len;
    if (dp + CCP_HDRLEN > ep)
	return;
    slen = CCP_LENGTH(dp);
    if (dp + slen > ep) {
	if (sc->sc_flags & SC_DEBUG)
	    printf("if_ppp/ccp: not enough data in mbuf (%p+%x > %p+%x)\n",
		dp, slen, mtod(mp, u_char *), mp->m_len);
	return;
    }

    switch (CCP_CODE(dp)) {
    case CCP_CONFREQ:
    case CCP_TERMREQ:
    case CCP_TERMACK:
	/* CCP must be going down - disable compression */
	if (sc->sc_flags & SC_CCP_UP) {
	    s = splhigh();	/* XXX IMP ME HARDER */
	    sc->sc_flags &= ~(SC_CCP_UP | SC_COMP_RUN | SC_DECOMP_RUN);
	    splx(s);
	}
	break;

    case CCP_CONFACK:
	if (sc->sc_flags & SC_CCP_OPEN && !(sc->sc_flags & SC_CCP_UP)
	    && slen >= CCP_HDRLEN + CCP_OPT_MINLEN
	    && slen >= CCP_OPT_LENGTH(dp + CCP_HDRLEN) + CCP_HDRLEN) {
	    if (!rcvd) {
		/* we're agreeing to send compressed packets. */
		if (sc->sc_xc_state != NULL
		    && (*sc->sc_xcomp->comp_init)
			(sc->sc_xc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
			 sc->sc_unit, 0, sc->sc_flags & SC_DEBUG)) {
		    s = splhigh();	/* XXX IMP ME HARDER */
		    sc->sc_flags |= SC_COMP_RUN;
		    splx(s);
		}
	    } else {
		/* peer is agreeing to send compressed packets. */
		if (sc->sc_rc_state != NULL
		    && (*sc->sc_rcomp->decomp_init)
			(sc->sc_rc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
			 sc->sc_unit, 0, sc->sc_mru,
			 sc->sc_flags & SC_DEBUG)) {
		    s = splhigh();	/* XXX IMP ME HARDER */
		    sc->sc_flags |= SC_DECOMP_RUN;
		    sc->sc_flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
		    splx(s);
		}
	    }
	}
	break;

    case CCP_RESETACK:
	if (sc->sc_flags & SC_CCP_UP) {
	    if (!rcvd) {
		if (sc->sc_xc_state && (sc->sc_flags & SC_COMP_RUN))
		    (*sc->sc_xcomp->comp_reset)(sc->sc_xc_state);
	    } else {
		if (sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN)) {
		    (*sc->sc_rcomp->decomp_reset)(sc->sc_rc_state);
		    s = splhigh();	/* XXX IMP ME HARDER */
		    sc->sc_flags &= ~SC_DC_ERROR;
		    splx(s);
		}
	    }
	}
	break;
    }
}

/*
 * CCP is down; free (de)compressor state if necessary.
 */
static void
ppp_ccp_closed(struct ppp_softc *sc)
{
    if (sc->sc_xc_state) {
	(*sc->sc_xcomp->comp_free)(sc->sc_xc_state);
	sc->sc_xc_state = NULL;
    }
    if (sc->sc_rc_state) {
	(*sc->sc_rcomp->decomp_free)(sc->sc_rc_state);
	sc->sc_rc_state = NULL;
    }
}
#endif /* PPP_COMPRESS */

/*
 * PPP packet input routine.
 * The caller has checked and removed the FCS and has inserted
 * the address/control bytes and the protocol high byte if they
 * were omitted.
 */
void
ppppktin(struct ppp_softc *sc, struct mbuf *m, int lost)
{
#ifndef __QNXNTO__
    int s = splhigh();	/* XXX IMP ME HARDER */
#endif

    if (lost)
	m->m_flags |= M_ERRMARK;
#ifndef __QNXNTO__
    IF_ENQUEUE(&sc->sc_rawq, m);
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
    softintr_schedule(sc->sc_si);
#else
    schednetisr(NETISR_PPP);
#endif
    splx(s);
    pppintr(sc);
#else
    ppp_inproc(sc, m);
#endif
}

/*
 * Process a received PPP packet, doing decompression as necessary.
 * Should be called at splsoftnet.
 */
#define COMPTYPE(proto)	((proto) == PPP_VJC_COMP? TYPE_COMPRESSED_TCP: \
			 TYPE_UNCOMPRESSED_TCP)

static void
ppp_inproc(struct ppp_softc *sc, struct mbuf *m)
{
    struct ifnet *ifp = &sc->sc_if;
    struct ifqueue *inq;
    int s, ilen, proto, rv;
    u_char *cp, adrs, ctrl;
    struct mbuf *mp, *dmp = NULL;
#ifdef VJC
    int xlen;
    u_char *iphdr;
    u_int hlen;
#endif

#ifdef __QNXNTO__
    cp = mtod(m, u_char *);
    if((proto = PPP_PROTOCOL(cp))== PPP_MP) {
        pppmp_input(sc, m);
        return;
    }
#endif
    sc->sc_stats.ppp_ipackets++;

    if (sc->sc_flags & SC_LOG_INPKT) {
	ilen = 0;
	for (mp = m; mp != NULL; mp = mp->m_next)
	    ilen += mp->m_len;
	printf("%s: got %d bytes\n", ifp->if_xname, ilen);
	pppdumpm(m);
    }

    cp = mtod(m, u_char *);
    adrs = PPP_ADDRESS(cp);
    ctrl = PPP_CONTROL(cp);
    proto = PPP_PROTOCOL(cp);

    if (m->m_flags & M_ERRMARK) {
	m->m_flags &= ~M_ERRMARK;
	s = splhigh();	/* XXX IMP ME HARDER */
	sc->sc_flags |= SC_VJ_RESET;
	splx(s);
    }

#ifdef PPP_COMPRESS
    /*
     * Decompress this packet if necessary, update the receiver's
     * dictionary, or take appropriate action on a CCP packet.
     */
    if (proto == PPP_COMP && sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN)
	&& !(sc->sc_flags & SC_DC_ERROR) && !(sc->sc_flags & SC_DC_FERROR)) {
	/* decompress this packet */
	rv = (*sc->sc_rcomp->decompress)(sc->sc_rc_state, m, &dmp);
	if (rv == DECOMP_OK) {
	    m_freem(m);
	    if (dmp == NULL) {
		/* no error, but no decompressed packet produced */
		return;
	    }
	    m = dmp;
	    cp = mtod(m, u_char *);
	    proto = PPP_PROTOCOL(cp);

	} else {
	    /*
	     * An error has occurred in decompression.
	     * Pass the compressed packet up to pppd, which may take
	     * CCP down or issue a Reset-Req.
	     */
	    if (sc->sc_flags & SC_DEBUG)
		printf("%s: decompress failed %d\n", ifp->if_xname, rv);
	    s = splhigh();	/* XXX IMP ME HARDER */
	    sc->sc_flags |= SC_VJ_RESET;
	    if (rv == DECOMP_ERROR)
		sc->sc_flags |= SC_DC_ERROR;
	    else
		sc->sc_flags |= SC_DC_FERROR;
	    splx(s);
	}

    } else {
	if (sc->sc_rc_state && (sc->sc_flags & SC_DECOMP_RUN)) {
	    (*sc->sc_rcomp->incomp)(sc->sc_rc_state, m);
	}
	if (proto == PPP_CCP) {
	    ppp_ccp(sc, m, 1);
	}
    }
#endif

    ilen = 0;
    for (mp = m; mp != NULL; mp = mp->m_next)
	ilen += mp->m_len;

#ifdef VJC
    if (sc->sc_flags & SC_VJ_RESET) {
	/*
	 * If we've missed a packet, we must toss subsequent compressed
	 * packets which don't have an explicit connection ID.
	 */
	if (sc->sc_comp)
	    sl_uncompress_tcp(NULL, 0, TYPE_ERROR, sc->sc_comp);
	s = splhigh();	/* XXX IMP ME HARDER */
	sc->sc_flags &= ~SC_VJ_RESET;
	splx(s);
    }

    /*
     * See if we have a VJ-compressed packet to uncompress.
     */
    if (proto == PPP_VJC_COMP) {
	if ((sc->sc_flags & SC_REJ_COMP_TCP) || sc->sc_comp == 0)
	    goto bad;

	xlen = sl_uncompress_tcp_core(cp + PPP_HDRLEN, m->m_len - PPP_HDRLEN,
				      ilen - PPP_HDRLEN, TYPE_COMPRESSED_TCP,
				      sc->sc_comp, &iphdr, &hlen);

	if (xlen <= 0) {
	    if (sc->sc_flags & SC_DEBUG)
		printf("%s: VJ uncompress failed on type comp\n",
		    ifp->if_xname);
	    goto bad;
	}

	/* Copy the PPP and IP headers into a new mbuf. */
	MGETHDR(mp, M_DONTWAIT, MT_DATA);
	if (mp == NULL)
	    goto bad;
	mp->m_len = 0;
	mp->m_next = NULL;
	if (hlen + PPP_HDRLEN > MHLEN) {
	    MCLGET(mp, M_DONTWAIT);
	    if (M_TRAILINGSPACE(mp) < hlen + PPP_HDRLEN) {
		m_freem(mp);
		goto bad;	/* lose if big headers and no clusters */
	    }
	}
	cp = mtod(mp, u_char *);
	cp[0] = adrs;
	cp[1] = ctrl;
	cp[2] = 0;
	cp[3] = PPP_IP;
	proto = PPP_IP;
	bcopy(iphdr, cp + PPP_HDRLEN, hlen);
	mp->m_len = hlen + PPP_HDRLEN;

	/*
	 * Trim the PPP and VJ headers off the old mbuf
	 * and stick the new and old mbufs together.
	 */
	m->m_data += PPP_HDRLEN + xlen;
	m->m_len -= PPP_HDRLEN + xlen;
	if (m->m_len <= M_TRAILINGSPACE(mp)) {
	    bcopy(mtod(m, u_char *), mtod(mp, u_char *) + mp->m_len, m->m_len);
	    mp->m_len += m->m_len;
	    MFREE(m, mp->m_next);
	} else
	    mp->m_next = m;
	m = mp;
	ilen += hlen - xlen;

    } else if (proto == PPP_VJC_UNCOMP) {
	if ((sc->sc_flags & SC_REJ_COMP_TCP) || sc->sc_comp == 0)
	    goto bad;

	xlen = sl_uncompress_tcp_core(cp + PPP_HDRLEN, m->m_len - PPP_HDRLEN,
				      ilen - PPP_HDRLEN, TYPE_UNCOMPRESSED_TCP,
				      sc->sc_comp, &iphdr, &hlen);

	if (xlen < 0) {
	    if (sc->sc_flags & SC_DEBUG)
		printf("%s: VJ uncompress failed on type uncomp\n",
		    ifp->if_xname);
	    goto bad;
	}

	proto = PPP_IP;
	cp[3] = PPP_IP;
    }
#endif /* VJC */

    /*
     * If the packet will fit in a header mbuf, don't waste a
     * whole cluster on it.
     */
    if (ilen <= MHLEN && M_IS_CLUSTER(m)) {
	MGETHDR(mp, M_DONTWAIT, MT_DATA);
	if (mp != NULL) {
	    m_copydata(m, 0, ilen, mtod(mp, caddr_t));
	    m_freem(m);
	    m = mp;
	    m->m_len = ilen;
	}
    }
    m->m_pkthdr.len = ilen;
    m->m_pkthdr.rcvif = ifp;

    if ((proto & 0x8000) == 0) {
#ifdef PPP_FILTER
	/*
	 * See whether we want to pass this packet, and
	 * if it counts as link activity.
	 */
	if (sc->sc_pass_filt_in.bf_insns != 0
	    && bpf_filter(sc->sc_pass_filt_in.bf_insns, (u_char *) m,
			  ilen, 0) == 0) {
	    /* drop this packet */
	    m_freem(m);
	    return;
	}
	if (sc->sc_active_filt_in.bf_insns == 0
	    || bpf_filter(sc->sc_active_filt_in.bf_insns, (u_char *) m,
	    		  ilen, 0))
	    sc->sc_last_recv = time_second;
#else
	/*
	 * Record the time that we received this packet.
	 */
	sc->sc_last_recv = time_second;
#endif /* PPP_FILTER */
    }

#if NBPFILTER > 0
    /* See if bpf wants to look at the packet. */
    if (sc->sc_if.if_bpf)
	bpf_mtap(sc->sc_if.if_bpf, m);
#endif

    rv = 0;
    switch (proto) {
#ifdef INET
    case PPP_IP:
	/*
	 * IP packet - take off the ppp header and pass it up to IP.
	 */
	if ((ifp->if_flags & IFF_UP) == 0
	    || sc->sc_npmode[NP_IP] != NPMODE_PASS) {
	    /* interface is down - drop the packet. */
	    m_freem(m);
	    return;
	}
	m->m_pkthdr.len -= PPP_HDRLEN;
	m->m_data += PPP_HDRLEN;
	m->m_len -= PPP_HDRLEN;
#ifdef GATEWAY
	if (ipflow_fastforward(m))
		return;
#endif
	schednetisr(NETISR_IP);
	inq = &ipintrq;
	break;
#endif

#ifdef INET6
    case PPP_IPV6:
	/*
	 * IPv6 packet - take off the ppp header and pass it up to IPv6.
	 */
	if ((ifp->if_flags & IFF_UP) == 0
	    || sc->sc_npmode[NP_IPV6] != NPMODE_PASS) {
	    /* interface is down - drop the packet. */
	    m_freem(m);
	    return;
	}
	m->m_pkthdr.len -= PPP_HDRLEN;
	m->m_data += PPP_HDRLEN;
	m->m_len -= PPP_HDRLEN;
	schednetisr(NETISR_IPV6);
	inq = &ip6intrq;
	break;
#endif

    default:
	/*
	 * Some other protocol - place on input queue for read().
	 */
	inq = &sc->sc_inq;
	rv = 1;
	break;
    }

    /*
     * Put the packet on the appropriate input queue.
     */
#ifndef __QNXNTO__
    s = splnet();
    if (IF_QFULL(inq)) {
	IF_DROP(inq);
	splx(s);
	if (sc->sc_flags & SC_DEBUG)
	    printf("%s: input queue full\n", ifp->if_xname);
	ifp->if_iqdrops++;
	goto bad;
    }
    IF_ENQUEUE(inq, m);
    splx(s);
    ifp->if_ipackets++;
    ifp->if_ibytes += ilen;

    if (rv)
	(*sc->sc_ctlp)(sc);
#else
{
	/* QNX ENQUEUE INQ */
	struct nw_stk_ctl *sctlp = &stk_ctl;
	NW_EX_LK(&sctlp->pkt_ex, iopkt_selfp);
	if(rv) {
		int rcvid;
		struct pppmgr_ocb *ocb = sc->qnxsc_ocb;
		/* data for pppd */
		/* Check if a reader is read-blocking there */
		if((rcvid = ocb->reader_rcvid)) {
			struct mbuf *m2;
			int len = 0;

			NW_EX_UNLK(&sctlp->pkt_ex, iopkt_selfp);
			for (m2 = m; m2 != 0; m2 = m2->m_next) {
				MsgWrite(rcvid, mtod(m2, u_char *), m2->m_len, len);
				len += m2->m_len;
			}
			m_freem(m);
			MsgReply_r(rcvid, EOK, 0, 0);
			return;
		}
	}
	
	/* Put data onto approciate queue */
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		if (sc->sc_flags & SC_DEBUG)
			printf("%s: input queue full\n", ifp->if_xname);
		ifp->if_iqdrops++;
		NW_EX_UNLK(&sctlp->pkt_ex, iopkt_selfp);
		goto bad;
	} 

	IF_ENQUEUE(inq, m);
	if ( rv == 0 && inq->ifq_len == 1) {
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
	ifp->if_ipackets++;
	ifp->if_ibytes += ilen;
	if(rv) {
		struct pppmgr_ocb *ocb = sc->qnxsc_ocb; 
		iofunc_notify_trigger(ocb->notify, 1, IOFUNC_NOTIFY_INPUT);
	}

	/* Notify the stack thread.  Will unlock pkt_ex. */
	poke_stack_pkt_q();
}
#endif

    return;

 bad:
    m_freem(m);
    sc->sc_if.if_ierrors++;
    sc->sc_stats.ppp_ierrors++;
}

#define MAX_DUMP_BYTES	128

static void
pppdumpm(struct mbuf *m0)
{
    char buf[3*MAX_DUMP_BYTES+4];
    char *bp = buf;
    struct mbuf *m;

    for (m = m0; m; m = m->m_next) {
	int l = m->m_len;
	u_char *rptr = (u_char *)m->m_data;

	while (l--) {
	    if (bp > buf + sizeof(buf) - 4)
		goto done;
	    *bp++ = hexdigits[*rptr >> 4]; /* convert byte to ascii hex */
	    *bp++ = hexdigits[*rptr++ & 0xf];
	}

	if (m->m_next) {
	    if (bp > buf + sizeof(buf) - 3)
		goto done;
	    *bp++ = '|';
	} else
	    *bp++ = ' ';
    }
done:
    if (m)
	*bp++ = '>';
    *bp = 0;
    printf("%s\n", buf);
}

#ifdef ALTQ
/*
 * a wrapper to transmit a packet from if_start since ALTQ uses
 * if_start to send a packet.
 */
static void
ppp_ifstart(struct ifnet *ifp)
{
	struct ppp_softc *sc;
	struct nw_work_thread *wtp = WTP;

	sc = ifp->if_softc;

	/*PPP does not use locking in the pppasyncstart code ..if_start()
          will always lock the send. At this point, the packets have already
          been dequeued from the interface queue to a specific PPP queue. This
          is an event to continue transmission if halted by ALTQ. Unlock here 
          or the interface will block. 

          If fastforward is ever changed to include PPP interface support, 
          locking would have to be applied to the pppasyncstart function in
          which case the unlock would occur after the sc_start.
        */ 
	
        NW_SIGUNLOCK_P(&ifp->if_snd_ex, iopkt_selfp, wtp);
        (*sc->sc_start)(sc);

}
#endif

#if defined(__QNXNTO__) && defined(QNX_MULTILINKPPP)
/* pppmp_scinit:
 * init mp 
 */
int pppmp_scinit(struct ppp_softc *sc, int master) {
	struct ppp_softc *msc;
	int ret;

	/* check request validity */
	if(master < 0) 
		return EINVAL;

	qnx_simple_rdlock(&ppp_list_mutex);
	LIST_FOREACH(msc, &ppp_softc_list, sc_iflist) {
		    if(msc->qnxsc_punit == master)
				break;
	}
	simple_unlock(&ppp_list_mutex);
	
	if(!msc)
		return EINVAL;

	if((ret = pthread_rwlock_wrlock(&msc->qnxsc_mplock)) != EOK)
		return ret;

	if(msc == sc && sc->qnxsc_mpnxsc != NULL) {
		pthread_rwlock_unlock(&msc->qnxsc_mplock);
		return EALREADY;
	}
	sc->qnxsc_mpnxsc  = msc->qnxsc_mpnxsc;
	msc->qnxsc_mpnxsc = sc;
	if(msc != sc) {
		sc->qnxsc_mpnxchan = msc;
		sc->qnxsc_flags |= QNXSC_MPSLAVE;
		sc->qnxsc_flags |= QNXSC_MPPP;
		sc->qnxsc_mplastseq = msc->qnxsc_mprq->seq_min; 
		pthread_rwlock_unlock(&msc->qnxsc_mplock);
		return EOK;
	} 

	pthread_rwlock_unlock(&msc->qnxsc_mplock);


	if((sc->qnxsc_mprq = (void *)malloc(sizeof(mp_ressq_t), M_DEVBUF, M_WAITOK)) == NULL)
		return ENOMEM;
	memset((void *)sc->qnxsc_mprq, 0, sizeof(mp_ressq_t));

	pthread_mutex_init(&sc->qnxsc_mprq->rqlock, 0);
	sc->qnxsc_mprq->mpinq.ifq_maxlen = QNX_MPRQMAXLEN;

	sc->qnxsc_mpnxchan = msc->qnxsc_mpnxsc;
	sc->qnxsc_flags |= QNXSC_IFATTACHED;
	sc->qnxsc_flags |= QNXSC_MPPP;

	return EOK;
}

#define SEQ32_LT(a,b)     ((int32_t)((a)-(b)) < 0)
#define SEQ32_LE(a,b)     ((int32_t)((a)-(b)) <= 0)
#define SEQ32_GT(a,b)     ((int32_t)((a)-(b)) > 0)
#define SEQ32_GE(a,b)     ((int32_t)((a)-(b)) >= 0)

static uint32_t getseq(struct mbuf *m, int type);
static u_char getbets(struct mbuf *m);
static int  mpdiscard(struct ifqueue *inq, int type, uint32_t b4); 
static int  if_mpenqueue(struct ifqueue *inq, int type, struct mbuf *m); 
static void seqnextupdate(struct ppp_softc *msc, int type); 
static int  eframeupdate(struct ppp_softc *msc, int type); 
static void mptoppp(struct mbuf *m, int type); 
static void mpappend(struct mbuf **mhd, struct mbuf *m); 

/* return BE */
static u_char getbets(struct mbuf *m) {
	u_char *cp = mtod(m, u_char *);
	return cp[4] & 0xf0;
}

/* return seq */
static uint32_t getseq(struct mbuf *m, int type) {
	u_char *cp = mtod(m, u_char *) + 2;
	return type ? ( ((cp[2] & 0x0f) << 8 | cp[3]) & 0xfff ) : \
		( ((cp[3] << 16) | (cp[4] << 8) | cp[5]) & 0xffffff );
}

/* Discard mp packet with seq < b4 */
static int mpdiscard(struct ifqueue *inq, int type, uint32_t b4) {
	struct mbuf *m;
	uint32_t seq;

	while(IF_POLL(inq, m)) {
		seq = getseq(m, type); 
		if(SEQ32_LT(seq, b4)) {
			IF_DEQUEUE(inq, m);
			m_freem(m);
		} else
			return 0;
	}

	return 0;
}

/* enqueue mppkt */
static int if_mpenqueue(struct ifqueue *inq, int type, struct mbuf *m) {
	struct mbuf *m0, *m1;
	uint32_t seq0, seq;

	if(!m)
		return 0;
	seq = getseq(m, type);
	m0 = inq->ifq_head;
	m1 = 0;
	while(m0) {
		seq0 = getseq(m0, type);
		if(SEQ32_LT(seq, seq0)) 
			break;
		else 
			if(seq == seq0) /* something wrong */
				return -1;
		m1 = m0;
		m0 = m0->m_nextpkt;
	}

	if(m1) {
		m->m_nextpkt  = m1->m_nextpkt;
		m1->m_nextpkt = m;
		if(m->m_nextpkt == NULL)
			inq->ifq_tail = m;
	} else {
		m->m_nextpkt  = inq->ifq_head;
		inq->ifq_head = m;
		if(inq->ifq_tail == NULL) 
			inq->ifq_tail = m;
	}
	inq->ifq_len++;

	return 0;
}

/* update seq_next */
static void seqnextupdate(struct ppp_softc *msc, int type) {
	mp_ressq_t *mprq = msc->qnxsc_mprq;
	struct ifqueue *inq;
	struct mbuf *m0;
	uint32_t seq0;

	inq = &mprq->mpinq;

	 if((m0 = inq->ifq_head)) {
		 seq0 = getseq(m0, type); 
		 mprq->seq_next = seq0 + 1;
		 m0 = m0->m_nextpkt;
	 }

	 while(m0) {
		 seq0 = getseq(m0, type);
		 if(seq0 == mprq->seq_next)
			 mprq->seq_next++;
		 else
			 break;
		 m0 = m0->m_nextpkt;
	 }
}

#define EFRAME_UNKNOWN	0
#define EFRAME_KNOWN	1
#define EFRAME_ARRIVED	2
/* update seq_eframe */
static int eframeupdate(struct ppp_softc *msc, int type) {
	mp_ressq_t *mprq = msc->qnxsc_mprq;
	struct ifqueue *inq;
	struct mbuf *m0;
	u_char bets0;
	uint32_t seq0;

	inq = &mprq->mpinq;
	m0 = inq->ifq_head;

	while(m0) {
		bets0 = getbets(m0);
		seq0  = getseq(m0, type);
		if( (bets0 & 0x80 ) && SEQ32_LE(mprq->seq_next, seq0 - 1) ) {
			mprq->seq_eframe = seq0 - 1;
			return EFRAME_KNOWN;
		}
		if(bets0 & 0x40) {
			mprq->seq_eframe = seq0;
			return EFRAME_ARRIVED;
		}
		m0 = m0->m_nextpkt;
	}

	mprq->seq_eframe = mprq->seq_next;
	return EFRAME_UNKNOWN;
}

/* prepare the mppkt for ppp_inproc() */
static void mptoppp(struct mbuf *m, int type) {
	int offset;
	u_char bets;

	bets = getbets(m);
	offset = (type ? MPHDRLEN_SSN : MPHDRLEN) + 2;

	if(bets & 0x80) {
		u_char *cp;
		cp = mtod(m, u_char *) + offset;
	
		if( *cp != PPP_ALLSTATIONS) {
			u_char *ph, ppphdr[4];
			int back;
			ph  = ppphdr;
			*ph++ = PPP_ALLSTATIONS;
			*ph++ = PPP_UI;
			if( (*cp & 1) == 1) 
				*ph++ = 0;

			back = ph - ppphdr;
			memcpy(cp - back, ppphdr, back);
			offset -= back;
		}
	}

	m->m_data += offset;
	m->m_len  -= offset;

	return;
}
/* append m to the end of *mhd */
static void mpappend(struct mbuf **mhd, struct mbuf *m) {
	struct mbuf *m0;

	if(!(m0=*mhd)) {
		*mhd = m;
		return;
	}

	while(m0->m_next) 
		m0 = m0->m_next;

	m0->m_next = m;
	return;
}

/* pppmp_input(): 
 * It should be only called by ppp_inproc(). 
 * 1) check validity of m.
 * 2) If a ppp packet is available, assemble it and call into ppp_proc().
 * 3) free m if bad.
 */
static void pppmp_input(struct ppp_softc *sc, struct mbuf *m)
{
	struct ppp_softc *msc = 0, *sc0 = 0;
	mp_ressq_t *mprq;
	int type, eframe = EFRAME_UNKNOWN;
	struct ifqueue *inq;
	struct mbuf *m0, *m1;

	uint32_t seq, seq0, minseq;
	uint8_t  bets; 

	if(!sc)
	    goto errout;

	qnx_simple_rdlock(&ppp_list_mutex);
	LIST_FOREACH(sc0, &ppp_softc_list, sc_iflist) {
	    if(sc0 == sc)
		break;
	}
	if(!sc0 || !(msc = ((sc->qnxsc_flags & QNXSC_IFATTACHED) ? sc : sc->qnxsc_mpnxchan) )) 
	{
	    simple_unlock(&ppp_list_mutex);
	    goto errout;
	}
	sc0 = 0;
	LIST_FOREACH(sc0, &ppp_softc_list, sc_iflist) {
	    if(sc0 == msc)
		break;
	}
	if(!sc0) {
	    simple_unlock(&ppp_list_mutex);
	    goto errout;
	}
	if((sc->qnxsc_flags & QNXSC_MPPP) == 0) { 
	    simple_unlock(&ppp_list_mutex);
	    goto errout;
	}
	simple_unlock(&ppp_list_mutex);

	if(pthread_rwlock_rdlock(&msc->qnxsc_mplock) != EOK) {
		msc = 0;
		goto errout;
	}

	type = msc->qnxsc_flags & QNXSC_MPSHORTSEQX;
	mprq = msc->qnxsc_mprq;
	inq  = &mprq->mpinq;
	bets = getbets(m);
	seq  = getseq(m, type);

	/* check validity */ 
	if (SEQ32_LT(seq, mprq->seq_min) || SEQ32_LT(seq, sc->qnxsc_mplastseq)) {
		pthread_rwlock_unlock(&msc->qnxsc_mplock);
		goto errout;
	}

	sc->qnxsc_mplastseq = seq;

	/* update min seq in all */
	minseq = seq;
	sc0 = msc;
	do {
		if(!(sc0->qnxsc_flags & QNXSC_DYIED) && SEQ32_LT(sc0->qnxsc_mplastseq, minseq))
			minseq = sc0->qnxsc_mplastseq;
		sc0 = sc0->qnxsc_mpnxsc;
	} while(sc0 != msc);

	mprq->seq_min = minseq;

	pthread_rwlock_unlock(&msc->qnxsc_mplock);

	if(pthread_mutex_lock(&mprq->rqlock) != EOK) {
	    msc = 0;
	    goto errout;
	}

	if ((bets & 0xc0) == 0xc0  && seq == mprq->seq_next) {
		mptoppp(m, type);
		ppp_inproc(msc, m);
		if(IF_IS_EMPTY(inq)) {
			mprq->seq_next = mprq->seq_eframe = seq + 1;
			pthread_mutex_unlock(&mprq->rqlock);
			return;
		} 
		m = 0;
	} 
	
	/* enqueue m */
	if(m) {
		if(IF_QFULL(inq)) { /* XXX */
			mpdiscard(inq, type, mprq->seq_next);
			if(IF_QFULL(inq)) { 
				pthread_mutex_unlock(&mprq->rqlock);
				goto errout;
			}
		}
		if(if_mpenqueue(inq, type, m) == -1) {
			pthread_mutex_unlock(&mprq->rqlock);
			goto errout;
		}
	}

	/* update seq_next and eframe */
	if (seq == mprq->seq_next) 
		seqnextupdate(msc, type);
	if (m || seq == mprq->seq_eframe)  
		eframe = eframeupdate(msc, type);
	
	/* check if a ppp packet is available */
	while(1) {
		/* check if still a hole is there */
		if(SEQ32_LE(mprq->seq_next, mprq->seq_eframe)) {
			if(SEQ32_LT(mprq->seq_eframe, minseq)) {
				int nmpkts = 0;

				/* the hole can't be patched. discard. */
				 while(IF_POLL(inq, m0)) {
					 seq0 = getseq(m0, type);
					 if(SEQ32_GT(seq0, mprq->seq_eframe))
						 break;
					 IF_DEQUEUE(inq, m0);
					 m_freem(m0);
					 msc->sc_stats.ppp_ierrors++;
					 nmpkts++;
				 }

				 mprq->seq_next = mprq->seq_eframe + 1;

				 /* update seq_next and eframe */
				 seqnextupdate(msc, type);
				 eframe = eframeupdate(msc, type);
				 continue;
			}
			break;
		}

		if(eframe != EFRAME_ARRIVED)
			break;

		m1 = 0;
		while(IF_POLL(inq, m0)) {
			seq0 = getseq(m0, type);
			if(SEQ32_GT(seq0, mprq->seq_eframe))
				break;
			IF_DEQUEUE(inq, m0);
			mptoppp(m0, type);
			mpappend(&m1, m0);
		}
			
		if(!m1) 
			break;
		ppp_inproc(msc, m1);
	}

	pthread_mutex_unlock(&mprq->rqlock);
	return;

errout:
	m_freem(m);
	if(msc)
		msc->sc_stats.ppp_ierrors++;
	return;
}

/* qnx_mpppdealloc: 
 * dealloc mp 
 */
int qnx_mpppdealloc(struct ppp_softc *sc) {
	struct ppp_softc *msc, *sc0, *sc1;
	mp_ressq_t *mprq;
	struct ifqueue *inq;
	struct mbuf *m;

	msc = (sc->qnxsc_flags & QNXSC_IFATTACHED) ? sc : sc->qnxsc_mpnxchan;
	if(!msc || !(mprq = msc->qnxsc_mprq))
		return 1;

	if(pthread_rwlock_wrlock(&msc->qnxsc_mplock) != EOK)
		return 1;

	if(sc != msc) {
		/* one sub channel to go */
		sc1 = 0;
		sc0 = msc;

		if(sc->qnxsc_mpnxsc == msc && (msc->qnxsc_flags & QNXSC_DYIED) ) {
			/* the last one */
			sc->qnxsc_flags &= ~QNXSC_MPMASK;
			sc->qnxsc_flags |= QNXSC_DYIED;
			sc->qnxsc_mpnxsc  = sc;
			msc->qnxsc_mpnxsc = msc; 
			pppdealloc(sc);
			goto clean_master;
		}

		while(sc0) {
			sc1 = sc0; 
			sc0 = sc0->qnxsc_mpnxsc;
			if(sc0 == sc) {
				sc1->qnxsc_mpnxsc = sc0->qnxsc_mpnxsc;
				sc0->qnxsc_mpnxchan = NULL;
				if(msc->qnxsc_mpnxchan == sc0)
					msc->qnxsc_mpnxchan = sc1;
				break;
			}
		}
		sc->qnxsc_flags &= ~QNXSC_MPMASK;
		sc->qnxsc_flags |= QNXSC_DYIED;
		if(msc->qnxsc_mpnxsc == msc) {
			msc->qnxsc_flags &= ~QNXSC_KEEPALIVE;
		}
		pthread_rwlock_unlock(&msc->qnxsc_mplock);
		return 1;
	} else {
		/* master to go */
		msc->qnxsc_flags |= QNXSC_DYIED;

		sc0 = msc->qnxsc_mpnxsc;
		if(sc0 != msc) {
			/* sub-channel still there: simply quit */
			msc->qnxsc_flags |= QNXSC_KEEPALIVE;
			msc->qnxsc_flags |= QNXSC_MPPP; /* XXX wzhang: fine tuning */
			if(msc->qnxsc_mpnxchan == msc) {
				msc->qnxsc_mpnxchan = sc0;
			}
			pthread_rwlock_unlock(&msc->qnxsc_mplock);
			return -1; /* indicate to pppdealloc() to keep if_up */
		}
	}

	if(pthread_mutex_lock(&mprq->rqlock) != EOK) { /* XXX */
		pthread_rwlock_unlock(&msc->qnxsc_mplock);
		return 1;
	}

clean_master:
	inq = &mprq->mpinq;
	while(!(IF_IS_EMPTY(inq))) {
		IF_DEQUEUE(inq, m);
		m_freem(m);
	}

	pthread_mutex_destroy(&mprq->rqlock);
	free(mprq, M_DEVBUF);

	msc->qnxsc_mprq = NULL;
	msc->qnxsc_flags &= ~QNXSC_MPMASK;
	pthread_rwlock_unlock(&msc->qnxsc_mplock);

	return 1;
}
#endif /* QNX MULTILINK PPP */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_ppp.c $ $Rev: 822252 $")
#endif
