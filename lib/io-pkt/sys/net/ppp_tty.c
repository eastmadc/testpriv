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

/*	$NetBSD: ppp_tty.c,v 1.45 2006/11/16 01:33:40 christos Exp $	*/
/*	Id: ppp_tty.c,v 1.3 1996/07/01 01:04:11 paulus Exp 	*/

/*
 * ppp_tty.c - Point-to-Point Protocol (PPP) driver for asynchronous
 * 	       tty devices.
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
 * so that it doesn't just give up with a "collision" if the whole
 * packet doesn't fit in the output ring buffer.
 *
 * Added priority queueing for interactive IP packets, following
 * the model of if_sl.c, plus hooks for bpf.
 * Paul Mackerras (paulus@cs.anu.edu.au).
 */

/* from if_sl.c,v 1.11 84/10/04 12:54:47 rick Exp */
/* from NetBSD: if_ppp.c,v 1.15.2.2 1994/07/28 05:17:58 cgd Exp */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ppp_tty.c,v 1.45 2006/11/16 01:33:40 christos Exp $");

#include "ppp.h"

#include "opt_ppp.h"
#ifdef __QNXNTO__
#include "opt_sigev.h"
#endif
#define VJC
#define PPP_COMPRESS

#ifndef __QNXNTO__
#include <sys/param.h>
#else
#define RESMGR_HANDLE_T void
#define RESMGR_OCB_T    void
#include <nw_thread.h>
#include "nw_msg.h"
#include <quiesce.h>
#include <alloca.h>
#endif
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/dkstat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/tty.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_types.h>

#ifdef VJC
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/slcompress.h>
#endif

#include "bpfilter.h"
#if NBPFILTER > 0 || defined(PPP_FILTER)
#include <net/bpf.h>
#endif
#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#include <net/if_pppvar.h>

#ifdef __QNXNTO__
#include <sys/syslog.h>
#include "blockop.h"
#endif
static int	pppopen(dev_t dev, struct tty *tp);
static int	pppclose(struct tty *tp, int flag);
static int	pppread(struct tty *tp, struct uio *uio, int flag);
static int	pppwrite(struct tty *tp, struct uio *uio, int flag);
static int	ppptioctl(struct tty *tp, u_long cmd, caddr_t data, int flag,
			  struct lwp *);
static int	pppinput(int c, struct tty *tp);
static int      qnx_pppframeinput(unsigned char *rdbuf, int len, struct tty *tp, int);
static int	pppstart(struct tty *tp);

struct linesw ppp_disc = {	/* XXX should be static */
	.l_name = "ppp",
	.l_open = pppopen,
	.l_close = pppclose,
	.l_read = pppread,
	.l_write = pppwrite,
	.l_ioctl = ppptioctl,
	.l_rint = pppinput,
	.l_start = pppstart,
#ifndef __QNXNTO__
	.l_modem = ttymodem,
	.l_poll = ttpoll
#endif
};

static void	ppprcvframe(struct ppp_softc *sc, struct mbuf *m);
static u_int16_t pppfcs(u_int16_t fcs, u_char *cp, int len);
#ifndef __QNXNTO__
static void	pppsyncstart(struct ppp_softc *sc);
static void	pppasyncstart(struct ppp_softc *);
static void	pppasyncctlp(struct ppp_softc *);
#else
void	pppasyncstart(struct ppp_softc *);
#endif
static void	pppasyncrelinq(struct ppp_softc *);
#ifndef __QNXNTO__
static void	ppp_timeout(void *);
#endif
static void	pppgetm(struct ppp_softc *sc);
#ifndef __QNXNTO__
static void	pppdumpb(u_char *b, int l);
static void	ppplogchar(struct ppp_softc *, int);
#endif
static void	pppdumpframe(struct ppp_softc *sc, struct mbuf* m, int xmit);
#if defined(__QNXNTO__) && defined(QNX_MULTILINKPPP)
static void qnx_mpppasyncstart __P((struct ppp_softc *));
#endif

#ifdef __QNXNTO__
#include <sys/dispatch.h>
#include <devctl.h>

#define PROC_FROM_CTP(ctp)  \
    (struct proc *)((char *)(ctp) - offsetof(struct proc, p_ctxt))
#define PROC_INIT(p, ctp, ocb) do {       \
	    (p) = PROC_FROM_CTP((ctp));       \
	    (p)->p_cred = (ocb)->ocb_cred;    \
	    kauth_cred_hold((ocb)->ocb_cred); \
		(p)->p_lwp.l_cred = (ocb)->ocb_cred; \
		kauth_cred_hold((ocb)->ocb_cred); \
	    PR_TO_LWP((p))->l_fp = 0;         \
} while (/* CONSTCOND */ 0)

#define PROC_FINI(p) do { \
	kauth_cred_free((p)->p_cred); \
	kauth_cred_free((p)->p_lwp.l_cred); \
} while (/* CONSTCOND */ 0)

#define ppp_thread_quiesce wt_specialized.sival_int
#define PPP_FLAG_READCOND	0x00000001
#define PPP_FLAG_QUIESCE	0x00000002
#define PPP_FLAG_DIE		0x00000004

struct ppprcv_loop_args {
	int			prio;
	struct ppp_softc	*sc;
};

static int   qnxtty_rdthread_init    (void *);
static void  qnxtty_rdthread_callout (void *, int);
static void *qnxtty_rdthread_reader  (void *);
static int   qnxtty_rdthread_create  (struct ppp_softc *);
static int   qnxtty_rdthread_destroy (struct ppp_softc *);
static void  qnxtty_output           (struct tty *);

pppmgr_ctrl_t pppmgrctrl;

static int pppmgr_open		(resmgr_context_t *, io_open_t *, RESMGR_HANDLE_T *, void *);
static int pppmgr_read		(resmgr_context_t *, io_read_t *, RESMGR_OCB_T *);
static int pppmgr_write		(resmgr_context_t *, io_write_t *, RESMGR_OCB_T *);
static int pppmgr_close_ocb	(resmgr_context_t *, void *, RESMGR_OCB_T *);
static int pppmgr_stat		(resmgr_context_t *, io_stat_t *, RESMGR_OCB_T *);
static int pppmgr_notify	(resmgr_context_t *, io_notify_t *, RESMGR_OCB_T *);
static int pppmgr_devctl	(resmgr_context_t *, io_devctl_t *, RESMGR_OCB_T *);
static int pppmgr_unblock	(resmgr_context_t *, io_pulse_t *, RESMGR_OCB_T *);
static int pppmgr_chmod  	(resmgr_context_t *, io_chmod_t *, RESMGR_OCB_T *);
static int pppmgr_chown  	(resmgr_context_t *, io_chown_t *, RESMGR_OCB_T *);

int qnxppp_ttyattach (struct pppmgr_ocb *, struct ppp_attach *); 
int qnxppp_ttydetach (struct ppp_softc *, int); 

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
 * Does c need to be escaped?
 */
#define ESCAPE_P(c)	(sc->sc_asyncmap[(c) >> 5] & (1 << ((c) & 0x1F)))

#ifdef __QNXNTO__

/* PPP does not use locking in the pppasyncstart code (executed in the
 * stack context). At this point the packets have already been dequeued
 * from the interface queue to a specific PPP queue. This is to continue
 * transmission if the TTY output buffer was full. If fastforward is ever
 * changed to include PPP interface support, locking may have to be applied
 * to the pppasyncstart function or here, see also ppp_ifstart (if_ppp.c)
 */ 

static void
ppp_kick_tx(void *arg)
{
	struct ppp_softc *sc = arg;
	if (sc->sc_devp)
		(*sc->sc_start)(sc);
}

#endif

/*
 * Procedures for using an async tty interface for PPP.
 */

/* This is a NetBSD-1.0 or later kernel. */
#define CCOUNT(q)	((q)->c_cc)

#define PPP_LOWAT	100	/* Process more output when < LOWAT on queue */
#define	PPP_HIWAT	400	/* Don't start a new packet if HIWAT on que */

/*
 * Line specific open routine for async tty devices.
 * Attach the given tty to the first available ppp unit.
 * Called from device open routine or ttioctl.
 */
/* ARGSUSED */
static int
pppopen(dev_t dev, struct tty *tp)
{
    struct lwp *l = curlwp;		/* XXX */
    struct ppp_softc *sc;
    int error, s;

    if ((error = kauth_authorize_generic(l->l_cred, KAUTH_GENERIC_ISSUSER,
	&l->l_acflag)) != 0)
	return (error);

#ifndef __QNXNTO__
    s = spltty();

    if (tp->t_linesw == &ppp_disc) {
	sc = (struct ppp_softc *) tp->t_sc;
	if (sc != NULL && sc->sc_devp == (void *) tp) {
	    splx(s);
	    return (0);
	}
    }

    if ((sc = pppalloc(l->l_proc->p_pid)) == NULL) {
	splx(s);
	return ENXIO;
    }

    if (sc->sc_relinq)
	(*sc->sc_relinq)(sc);	/* get previous owner to relinquish the unit */

#else
    if (tp == NULL && (tp = ttymalloc()) == NULL)
	return ENOMEM;
    tp->t_linesw = &ppp_disc;
    sc = (struct ppp_softc *)dev;
    tp->t_sc = sc;
    tp->t_oproc = qnxtty_output;

    /* set the fd to be read block */
    qnxppp_scrawbuf(sc, 0);
    s = 0;
    if (ioctl(sc->qnxsc_pppfdrd, FIONBIO, &s) == -1) {
	#ifdef QNXPPPDEBUG
	log(LOG_DEBUG, "ioctl(FIONBIO) rd: %m");
	#endif
    }
    s = 1;
    if (ioctl(sc->qnxsc_pppfdwr, FIONBIO, &s) == -1) {
	#ifdef QNXPPPDEBUG
	log(LOG_DEBUG, "ioctl(FIONBIO) wr: %m");
	#endif
    }		
    /* determine if the manager servicing fd supports readcond() */
    if (readcond(sc->qnxsc_pppfdrd, NULL, 0, 0, 0, 0) != -1) {
	#ifdef QNXPPPDEBUG
	log(LOG_DEBUG, "readcond() ok");
	#endif
    }
	/* start the reader thread */
	s = qnxtty_rdthread_create(sc);
	if(s != EOK) {
    #ifdef QNXPPPDEBUG 
		log(LOG_DEBUG, "CREATE READER THREAD: %m");
    #endif
		return s;
	}

#endif /* __QNXNTO__ */
#if NBPFILTER > 0
    /* Switch DLT to PPP-over-serial. */
    bpf_change_type(&sc->sc_if, DLT_PPP_SERIAL, PPP_HDRLEN);
#endif

    sc->sc_ilen = 0;
#ifndef __QNXNTO__
    sc->sc_m = NULL;	/* Demand dialing has already intialized pointer 
			 * otherwise it is already NULL.
			 */
#endif
    memset(sc->sc_asyncmap, 0, sizeof(sc->sc_asyncmap));
    sc->sc_asyncmap[0] = 0xffffffff;
    sc->sc_asyncmap[3] = 0x60000000;
    sc->sc_rasyncmap = 0;
    sc->sc_devp = (void *) tp;
#ifdef __QNXNTO__
    /* Grow the t_outq buffer to hold one complete frame including max escaped
     * characters rather than the default 2048.
     */	
    if (qnxtty_txrawbuf(sc) != 0)
	return -1;
#endif
    sc->sc_start = pppasyncstart;
#ifndef __QNXNTO__
    sc->sc_ctlp = pppasyncctlp;
#endif
    sc->sc_relinq = pppasyncrelinq;
    sc->sc_outm = NULL;
    pppgetm(sc);
    sc->sc_if.if_flags |= IFF_RUNNING;
    sc->sc_if.if_baudrate = tp->t_ospeed;

    tp->t_sc = (caddr_t) sc;
    ttyflush(tp, FREAD | FWRITE);

#ifndef __QNXNTO__
    splx(s);
#else
	sc->qnxsc_flags &= ~QNXSC_DYIED;
#endif
    return (0);
}

/*
 * Line specific close routine, called from device close routine
 * and from ttioctl.
 * Detach the tty from the ppp unit.
 * Mimics part of ttyclose().
 */
static int
pppclose(struct tty *tp, int flag)
{
    struct ppp_softc *sc;
    int s;

    s = spltty();
    ttyflush(tp, FREAD|FWRITE);
#ifndef __QNXNTO__
    ttyldisc_release(tp->t_linesw);
    tp->t_linesw = ttyldisc_default();
#else
    tp->t_linesw = NULL;
#endif
    sc = (struct ppp_softc *) tp->t_sc;
    if (sc != NULL) {
#ifndef __QNXNTO__
	tp->t_sc = NULL;
#else
	qnx_ifdetach(sc);
#endif
	if (tp == (struct tty *) sc->sc_devp) {
#ifdef __QNXNTO__
	    tp->t_sc = NULL;
	    /* cancel the read thread first */
	    if (sc->sc_if.if_flags & IFF_RUNNING)
		qnxppp_ttydetach(sc, 1);
#endif
	    pppasyncrelinq(sc);
	    pppdealloc(sc);
	}
    }
    splx(s);
    return 0;
}

/*
 * Relinquish the interface unit to another device.
 */
static void
pppasyncrelinq(struct ppp_softc *sc)
{
    int s;

#if NBPFILTER > 0
    /* Change DLT to back none. */
    bpf_change_type(&sc->sc_if, DLT_NULL, 0);
#endif

    s = spltty();
    if (sc->sc_outm) {
	m_freem(sc->sc_outm);
	sc->sc_outm = NULL;
    }
    if (sc->sc_m) {
	m_freem(sc->sc_m);
	sc->sc_m = NULL;
    }
    if (sc->sc_flags & SC_TIMEOUT) {
	callout_stop(&sc->sc_timo_ch);
	sc->sc_flags &= ~SC_TIMEOUT;
    }
    splx(s);
}

/*
 * Line specific (tty) read routine.
 */
static int
pppread(struct tty *tp, struct uio *uio, int flag)
{
    struct ppp_softc *sc = (struct ppp_softc *)tp->t_sc;
    struct mbuf *m, *m0;
    int s;
    int error = 0;

    if (sc == NULL)
	return 0;
    /*
     * Loop waiting for input, checking that nothing disasterous
     * happens in the meantime.
     */
    s = spltty();
    for (;;) {
	if (tp != (struct tty *) sc->sc_devp ||
	    tp->t_linesw != &ppp_disc) {
	    splx(s);
	    return 0;
	}
	if (sc->sc_inq.ifq_head != NULL)
	    break;
	if ((tp->t_state & TS_CARR_ON) == 0 && (tp->t_cflag & CLOCAL) == 0
	    && (tp->t_state & TS_ISOPEN)) {
	    splx(s);
	    return 0;		/* end of file */
	}
#ifndef __QNXNTO__
	if (tp->t_state & TS_ASYNC || flag & IO_NDELAY) {
#else
	if (tp->t_state & TS_ASYNC ) {
#endif
	    splx(s);
	    return (EWOULDBLOCK);
	}
#ifndef __QNXNTO__ /* XXX */
	error = ttysleep(tp, (caddr_t)&tp->t_rawq, TTIPRI|PCATCH, ttyin, 0);
	if (error) {
	    splx(s);
	    return error;
	}
#endif
    }

#ifndef __QNXNTO__
    /* Pull place-holder byte out of canonical queue */
    getc(&tp->t_canq);
#endif

    /* Get the packet from the input queue */
    IF_DEQUEUE(&sc->sc_inq, m0);
    splx(s);

    for (m = m0; m && uio->uio_resid; m = m->m_next)
	if ((error = uiomove(mtod(m, u_char *), m->m_len, uio)) != 0)
	    break;
    m_freem(m0);
    return (error);
}

/*
 * Line specific (tty) write routine.
 */
static int
pppwrite(struct tty *tp, struct uio *uio, int flag)
{
    struct ppp_softc *sc = (struct ppp_softc *)tp->t_sc;
    struct mbuf *m, *m0;
    struct sockaddr dst;
    int len, error;

#ifndef __QNXNTO__
    if ((tp->t_state & TS_CARR_ON) == 0 && (tp->t_cflag & CLOCAL) == 0)
	return 0;		/* wrote 0 bytes */
#endif
    if (tp->t_linesw != &ppp_disc)
	return (EINVAL);
    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return EIO;
    if (uio->uio_resid > sc->sc_if.if_mtu + PPP_HDRLEN ||
	uio->uio_resid < PPP_HDRLEN)
	return (EMSGSIZE);

    MGETHDR(m0, M_WAIT, MT_DATA);
    if (m0 == NULL)
	return ENOBUFS;

    m0->m_len = 0;
    m0->m_pkthdr.len = uio->uio_resid;
    m0->m_pkthdr.rcvif = NULL;

    if (uio->uio_resid >= MCLBYTES / 2)
	MCLGET(m0, M_DONTWAIT);

    for (m = m0; uio->uio_resid;) {
	len = M_TRAILINGSPACE(m);
	if (len > uio->uio_resid)
	    len = uio->uio_resid;
#ifndef __QNXNTO__
	if ((error = uiomove(mtod(m, u_char *), len, uio)) != 0) {
	    m_freem(m0);
	    return (error);
	}
#else
	memcpy(mtod(m, u_char *), (char *)uio->uio_iov->iov_base + uio->uio_offset, len);
	uio->uio_offset += len;
	uio->uio_resid  -= len;
#endif
	m->m_len = len;

	if (uio->uio_resid == 0)
	    break;

	MGET(m->m_next, M_WAIT, MT_DATA);
	if (m->m_next == NULL) {
	    m_freem(m0);
	    return ENOBUFS;
	}
	m = m->m_next;
	m->m_len = 0;
    }
    dst.sa_family = AF_UNSPEC;
    bcopy(mtod(m0, u_char *), dst.sa_data, PPP_HDRLEN);
    m_adj(m0, PPP_HDRLEN);
#ifndef __QNXNTO__
    return ((*sc->sc_if.if_output)(&sc->sc_if, m0, &dst, (struct rtentry *)0));
#else
	len = sc->qnxsc_flags;
	{
		int rc;
		rc = sc->qnxsc_flags & QNXSC_MPPP;
		if(rc) 
			sc->qnxsc_flags &= ~QNXSC_MPPP;
		error = (*sc->sc_if.if_output)(&sc->sc_if, m0, &dst, (struct rtentry *)0);
		if(rc) 
			sc->qnxsc_flags |= QNXSC_MPPP;
		sc->qnxsc_flags = len;
	}
	return error;
#endif
}

/*
 * Line specific (tty) ioctl routine.
 * This discipline requires that tty device drivers call
 * the line specific l_ioctl routine from their ioctl routines.
 */
/* ARGSUSED */
static int
ppptioctl(struct tty *tp, u_long cmd, caddr_t data, int flag, struct lwp *l)
{
    struct ppp_softc *sc = (struct ppp_softc *) tp->t_sc;
    int error, s;

    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return (EPASSTHROUGH);

    error = 0;
    switch (cmd) {
    case TIOCRCVFRAME:
    	ppprcvframe(sc,*((struct mbuf **)data));
	break;

    case PPPIOCSASYNCMAP:
	if ((error = kauth_authorize_generic(l->l_cred,
 	  KAUTH_GENERIC_ISSUSER, &l->l_acflag)) != 0)
	    break;
	sc->sc_asyncmap[0] = *(u_int *)data;
	break;

    case PPPIOCGASYNCMAP:
	*(u_int *)data = sc->sc_asyncmap[0];
	break;

    case PPPIOCSRASYNCMAP:
	if ((error = kauth_authorize_generic(l->l_cred,
	  KAUTH_GENERIC_ISSUSER, &l->l_acflag)) != 0)
	    break;
	sc->sc_rasyncmap = *(u_int *)data;
	break;

    case PPPIOCGRASYNCMAP:
	*(u_int *)data = sc->sc_rasyncmap;
	break;

    case PPPIOCSXASYNCMAP:
	if ((error = kauth_authorize_generic(l->l_cred,
	  KAUTH_GENERIC_ISSUSER, &l->l_acflag)) != 0)
	    break;
	s = spltty();
	bcopy(data, sc->sc_asyncmap, sizeof(sc->sc_asyncmap));
	sc->sc_asyncmap[1] = 0;		    /* mustn't escape 0x20 - 0x3f */
	sc->sc_asyncmap[2] &= ~0x40000000;  /* mustn't escape 0x5e */
	sc->sc_asyncmap[3] |= 0x60000000;   /* must escape 0x7d, 0x7e */
	splx(s);
	break;

    case PPPIOCGXASYNCMAP:
	bcopy(sc->sc_asyncmap, data, sizeof(sc->sc_asyncmap));
	break;

    default:
	error = pppioctl(sc, cmd, data, flag, l);
	if (error == 0 && cmd == PPPIOCSMRU)
	    pppgetm(sc);
    }

    return error;
}

/* receive a complete ppp frame from device in synchronous
 * hdlc mode. caller gives up ownership of mbuf
 */
static void
ppprcvframe(struct ppp_softc *sc, struct mbuf *m)
{
	int len, s;
	struct mbuf *n;
	u_char hdr[4];
	int hlen,count;

	for (n=m,len=0;n != NULL;n = n->m_next)
		len += n->m_len;
	if (len==0) {
		m_freem(m);
		return;
	}

	/* extract PPP header from mbuf chain (1 to 4 bytes) */
	for (n=m,hlen=0;n!=NULL && hlen<sizeof(hdr);n=n->m_next) {
		count = (sizeof(hdr)-hlen) < n->m_len ?
				sizeof(hdr)-hlen : n->m_len;
		bcopy(mtod(n,u_char*),&hdr[hlen],count);
		hlen+=count;
	}

	s = spltty();

	/* if AFCF compressed then prepend AFCF */
	if (hdr[0] != PPP_ALLSTATIONS) {
		if (sc->sc_flags & SC_REJ_COMP_AC) {
			if (sc->sc_flags & SC_DEBUG)
				printf(
				    "%s: garbage received: 0x%x (need 0xFF)\n",
				    sc->sc_if.if_xname, hdr[0]);
				goto bail;
			}
		M_PREPEND(m,2,M_DONTWAIT);
		if (m==NULL) {
			splx(s);
			return;
		}
		hdr[3] = hdr[1];
		hdr[2] = hdr[0];
		hdr[0] = PPP_ALLSTATIONS;
		hdr[1] = PPP_UI;
		len += 2;
	}

	/* if protocol field compressed, add MSB of protocol field = 0 */
	if (hdr[2] & 1) {
		/* a compressed protocol */
		M_PREPEND(m,1,M_DONTWAIT);
		if (m==NULL) {
			splx(s);
			return;
		}
		hdr[3] = hdr[2];
		hdr[2] = 0;
		len++;
	}

	/* valid LSB of protocol field has bit0 set */
	if (!(hdr[3] & 1)) {
		if (sc->sc_flags & SC_DEBUG)
			printf("%s: bad protocol %x\n", sc->sc_if.if_xname,
				(hdr[2] << 8) + hdr[3]);
			goto bail;
	}

	/* packet beyond configured mru? */
	if (len > sc->sc_mru + PPP_HDRLEN) {
		if (sc->sc_flags & SC_DEBUG)
			printf("%s: packet too big\n", sc->sc_if.if_xname);
		goto bail;
	}

	/* add expanded 4 byte header to mbuf chain */
	for (n=m,hlen=0;n!=NULL && hlen<sizeof(hdr);n=n->m_next) {
		count = (sizeof(hdr)-hlen) < n->m_len ?
				sizeof(hdr)-hlen : n->m_len;
		bcopy(&hdr[hlen],mtod(n,u_char*),count);
		hlen+=count;
	}

	/* if_ppp.c requires the PPP header and IP header */
	/* to be contiguous */
	count = len < MHLEN ? len : MHLEN;
	if (m->m_len < count) {
		m = m_pullup(m,count);
		if (m==NULL)
			goto bail;
	}

	sc->sc_stats.ppp_ibytes += len;

	if (sc->sc_flags & SC_LOG_RAWIN)
		pppdumpframe(sc,m,0);

	ppppktin(sc, m, 0);
	splx(s);
	return;
bail:
	m_freem(m);
	splx(s);
}

/*
 * FCS lookup table as calculated by genfcstab.
 */
static const u_int16_t fcstab[256] = {
	0x0000,	0x1189,	0x2312,	0x329b,	0x4624,	0x57ad,	0x6536,	0x74bf,
	0x8c48,	0x9dc1,	0xaf5a,	0xbed3,	0xca6c,	0xdbe5,	0xe97e,	0xf8f7,
	0x1081,	0x0108,	0x3393,	0x221a,	0x56a5,	0x472c,	0x75b7,	0x643e,
	0x9cc9,	0x8d40,	0xbfdb,	0xae52,	0xdaed,	0xcb64,	0xf9ff,	0xe876,
	0x2102,	0x308b,	0x0210,	0x1399,	0x6726,	0x76af,	0x4434,	0x55bd,
	0xad4a,	0xbcc3,	0x8e58,	0x9fd1,	0xeb6e,	0xfae7,	0xc87c,	0xd9f5,
	0x3183,	0x200a,	0x1291,	0x0318,	0x77a7,	0x662e,	0x54b5,	0x453c,
	0xbdcb,	0xac42,	0x9ed9,	0x8f50,	0xfbef,	0xea66,	0xd8fd,	0xc974,
	0x4204,	0x538d,	0x6116,	0x709f,	0x0420,	0x15a9,	0x2732,	0x36bb,
	0xce4c,	0xdfc5,	0xed5e,	0xfcd7,	0x8868,	0x99e1,	0xab7a,	0xbaf3,
	0x5285,	0x430c,	0x7197,	0x601e,	0x14a1,	0x0528,	0x37b3,	0x263a,
	0xdecd,	0xcf44,	0xfddf,	0xec56,	0x98e9,	0x8960,	0xbbfb,	0xaa72,
	0x6306,	0x728f,	0x4014,	0x519d,	0x2522,	0x34ab,	0x0630,	0x17b9,
	0xef4e,	0xfec7,	0xcc5c,	0xddd5,	0xa96a,	0xb8e3,	0x8a78,	0x9bf1,
	0x7387,	0x620e,	0x5095,	0x411c,	0x35a3,	0x242a,	0x16b1,	0x0738,
	0xffcf,	0xee46,	0xdcdd,	0xcd54,	0xb9eb,	0xa862,	0x9af9,	0x8b70,
	0x8408,	0x9581,	0xa71a,	0xb693,	0xc22c,	0xd3a5,	0xe13e,	0xf0b7,
	0x0840,	0x19c9,	0x2b52,	0x3adb,	0x4e64,	0x5fed,	0x6d76,	0x7cff,
	0x9489,	0x8500,	0xb79b,	0xa612,	0xd2ad,	0xc324,	0xf1bf,	0xe036,
	0x18c1,	0x0948,	0x3bd3,	0x2a5a,	0x5ee5,	0x4f6c,	0x7df7,	0x6c7e,
	0xa50a,	0xb483,	0x8618,	0x9791,	0xe32e,	0xf2a7,	0xc03c,	0xd1b5,
	0x2942,	0x38cb,	0x0a50,	0x1bd9,	0x6f66,	0x7eef,	0x4c74,	0x5dfd,
	0xb58b,	0xa402,	0x9699,	0x8710,	0xf3af,	0xe226,	0xd0bd,	0xc134,
	0x39c3,	0x284a,	0x1ad1,	0x0b58,	0x7fe7,	0x6e6e,	0x5cf5,	0x4d7c,
	0xc60c,	0xd785,	0xe51e,	0xf497,	0x8028,	0x91a1,	0xa33a,	0xb2b3,
	0x4a44,	0x5bcd,	0x6956,	0x78df,	0x0c60,	0x1de9,	0x2f72,	0x3efb,
	0xd68d,	0xc704,	0xf59f,	0xe416,	0x90a9,	0x8120,	0xb3bb,	0xa232,
	0x5ac5,	0x4b4c,	0x79d7,	0x685e,	0x1ce1,	0x0d68,	0x3ff3,	0x2e7a,
	0xe70e,	0xf687,	0xc41c,	0xd595,	0xa12a,	0xb0a3,	0x8238,	0x93b1,
	0x6b46,	0x7acf,	0x4854,	0x59dd,	0x2d62,	0x3ceb,	0x0e70,	0x1ff9,
	0xf78f,	0xe606,	0xd49d,	0xc514,	0xb1ab,	0xa022,	0x92b9,	0x8330,
	0x7bc7,	0x6a4e,	0x58d5,	0x495c,	0x3de3,	0x2c6a,	0x1ef1,	0x0f78
};

/*
 * Calculate a new FCS given the current FCS and the new data.
 */
static u_int16_t
pppfcs(u_int16_t fcs, u_char *cp, int len)
{
    while (len--)
	fcs = PPP_FCS(fcs, *cp++);
    return (fcs);
}

/* This gets called at splsoftnet from pppasyncstart at various times
 * when there is data ready to be sent.
 */
#ifndef __QNXNTO__
static void
pppsyncstart(struct ppp_softc *sc)
{
	struct tty *tp = (struct tty *) sc->sc_devp;
	struct mbuf *m, *n;
	const struct cdevsw *cdev;
	int len;

	for(m = sc->sc_outm;;) {
		if (m == NULL) {
			m = ppp_dequeue(sc);	/* get new packet */
			if (m == NULL)
				break;		/* no more packets */
			if (sc->sc_flags & SC_DEBUG)
				pppdumpframe(sc,m,1);
		}
		for(n=m,len=0;n!=NULL;n=n->m_next)
			len += n->m_len;

		/* call device driver IOCTL to transmit a frame */
#ifndef __QNXNTO__
		cdev = cdevsw_lookup(tp->t_dev);
		if (cdev == NULL ||
		    (*cdev->d_ioctl)(tp->t_dev, TIOCXMTFRAME, (caddr_t)&m,
				     0, 0)) {
			/* busy or error, set as current packet */
			sc->sc_outm = m;
			break;
		}
#endif
		sc->sc_outm = m = NULL;
		sc->sc_stats.ppp_obytes += len;
	}
}
#endif

/*
 * This gets called at splsoftnet from if_ppp.c at various times
 * when there is data ready to be sent.
 */
#ifndef __QNXNTO__
static void
#else
void
#endif
pppasyncstart(struct ppp_softc *sc)
{
    struct tty *tp = (struct tty *) sc->sc_devp;
    struct mbuf *m;
    int len;
    u_char *start, *stop, *cp;
    int n, ndone, done, idle;
    struct mbuf *m2;
    int s;

#ifdef __QNXNTO__
   /* Entering tx function which will clear TX if_snd queue.
    * If TTY output buffer is still full, callout will be set again
    * in qnxtty_output() 
    */
    callout_stop(&sc->tx_callout);
#endif

#ifndef __QNXNTO__
    if (sc->sc_flags & SC_SYNC){
	pppsyncstart(sc);
	return;
    }
#else
#ifdef QNX_MULTILINKPPP
	if ((sc->qnxsc_flags & QNXSC_IFATTACHED) &&
	    (sc->qnxsc_flags & QNXSC_MPPP) ) {
	qnx_mpppasyncstart(sc);
	return;
	}
#endif
#endif
#ifdef __QNXNTO__
    if (tp == NULL)
	return;
#endif
    idle = 0;

cont_processing:

    while (CCOUNT(&tp->t_outq) < PPP_HIWAT) {
	/*
	 * See if we have an existing packet partly sent.
	 * If not, get a new packet and start sending it.
	 */
	m = sc->sc_outm;
	if (m == NULL) {
	    /*
	     * Get another packet to be sent.
	     */
	    m = ppp_dequeue(sc);
	    if (m == NULL) {
		idle = 1;
		break;
	    }

	    /*
	     * The extra PPP_FLAG will start up a new packet, and thus
	     * will flush any accumulated garbage.  We do this whenever
	     * the line may have been idle for some time.
	     */
	    if (CCOUNT(&tp->t_outq) == 0) {
		++sc->sc_stats.ppp_obytes;
		(void) putc(PPP_FLAG, &tp->t_outq);
	    }

	    /* Calculate the FCS for the first mbuf's worth. */
	    sc->sc_outfcs = pppfcs(PPP_INITFCS, mtod(m, u_char *), m->m_len);
	}

	for (;;) {
	    start = mtod(m, u_char *);
	    len = m->m_len;
	    stop = start + len;
	    while (len > 0) {
		/*
		 * Find out how many bytes in the string we can
		 * handle without doing something special.
		 */
		for (cp = start; cp < stop; cp++)
		    if (ESCAPE_P(*cp))
			break;
		n = cp - start;
		if (n) {
		    /* NetBSD (0.9 or later), 4.3-Reno or similar. */
		    ndone = n - b_to_q(start, n, &tp->t_outq);
		    len -= ndone;
		    start += ndone;
		    sc->sc_stats.ppp_obytes += ndone;

		    if (ndone < n)
			break;	/* packet doesn't fit */
		}
		/*
		 * If there are characters left in the mbuf,
		 * the first one must be special.
		 * Put it out in a different form.
		 */
		if (len) {
		    s = spltty();
		    if (putc(PPP_ESCAPE, &tp->t_outq)) {
			splx(s);
			break;
		    }
		    if (putc(*start ^ PPP_TRANS, &tp->t_outq)) {
			(void) unputc(&tp->t_outq);
			splx(s);
			break;
		    }
		    splx(s);
		    sc->sc_stats.ppp_obytes += 2;
		    start++;
		    len--;
		}
	    }

	    /*
	     * If we didn't empty this mbuf, remember where we're up to.
	     * If we emptied the last mbuf, try to add the FCS and closing
	     * flag, and if we can't, leave sc_outm pointing to m, but with
	     * m->m_len == 0, to remind us to output the FCS and flag later.
	     */
	    done = len == 0;
	    if (done && m->m_next == NULL) {
		u_char *p, *q;
		int c;
		u_char endseq[8];

		/*
		 * We may have to escape the bytes in the FCS.
		 */
		p = endseq;
		c = ~sc->sc_outfcs & 0xFF;
		if (ESCAPE_P(c)) {
		    *p++ = PPP_ESCAPE;
		    *p++ = c ^ PPP_TRANS;
		} else
		    *p++ = c;
		c = (~sc->sc_outfcs >> 8) & 0xFF;
		if (ESCAPE_P(c)) {
		    *p++ = PPP_ESCAPE;
		    *p++ = c ^ PPP_TRANS;
		} else
		    *p++ = c;
		*p++ = PPP_FLAG;

		/*
		 * Try to output the FCS and flag.  If the bytes
		 * don't all fit, back out.
		 */
		s = spltty();
		for (q = endseq; q < p; ++q)
		    if (putc(*q, &tp->t_outq)) {
			done = 0;
			for (; q > endseq; --q)
			    unputc(&tp->t_outq);
			break;
		    }
		splx(s);
		if (done)
		    sc->sc_stats.ppp_obytes += q - endseq;
	    }

	    if (!done) {
		/* remember where we got to */
		m->m_data = start;
		m->m_len = len;
		break;
	    }

	    /* Finished with this mbuf; free it and move on. */
	    MFREE(m, m2);
	    m = m2;
	    if (m == NULL) {
		/* Finished a packet */
		break;
	    }
	    sc->sc_outfcs = pppfcs(sc->sc_outfcs, mtod(m, u_char *), m->m_len);
	}

	/*
	 * If m == NULL, we have finished a packet.
	 * If m != NULL, we've either done as much work this time
	 * as we need to, or else we've filled up the output queue.
	 */
	sc->sc_outm = m;
	if (m)
	    break;
    }
#ifdef __QNXNTO__
    if (CCOUNT(&tp->t_outq) == 0)
        return; /* Nothing to do */
#endif
    /* Call pppstart to start output again if necessary. */

    s = spltty();
    pppstart(tp);

#ifndef __QNXNTO__
    /*
     * This timeout is needed for operation on a pseudo-tty,
     * because the pty code doesn't call pppstart after it has
     * drained the t_outq.
     */
    if (!idle && (sc->sc_flags & SC_TIMEOUT) == 0) {
	callout_reset(&sc->sc_timo_ch, 1, ppp_timeout, sc);
	sc->sc_flags |= SC_TIMEOUT;
    }
#endif

    splx(s);
#ifdef __QNXNTO__
    /* Clear the interface if_snd queue if packets accumulated */ 	
 
    if (CCOUNT(&tp->t_outq) == 0) {
	goto cont_processing;
    }	 
#endif
}

/*
 * This gets called when a received packet is placed on
 * the inq, at splsoftnet.
 */
#ifndef __QNXNTO__
static void
pppasyncctlp(struct ppp_softc *sc)
{
    struct tty *tp;
    int s;

    /* Put a placeholder byte in canq for ttselect()/ttnread(). */
    s = spltty();
    tp = (struct tty *) sc->sc_devp;
    putc(0, &tp->t_canq);
    ttwakeup(tp);
    splx(s);
}
#endif

/*
 * Start output on async tty interface.  If the transmit queue
 * has drained sufficiently, arrange for pppasyncstart to be
 * called later at splsoftnet.
 * Called at spltty or higher.
 */
static int
pppstart(struct tty *tp)
{
#ifndef __QNXNTO__
    struct ppp_softc *sc = (struct ppp_softc *) tp->t_sc;
#endif

    /*
     * If there is stuff in the output queue, send it now.
     * We are being called in lieu of ttstart and must do what it would.
     */
    if (tp->t_oproc != NULL)
	(*tp->t_oproc)(tp);

#ifndef __QNXNTO__ 
    /*
     * If the transmit queue has drained and the tty has not hung up
     * or been disconnected from the ppp unit, then tell if_ppp.c that
     * we need more output.
     */
    if ((CCOUNT(&tp->t_outq) >= PPP_LOWAT)
	&& ((sc == NULL) || (sc->sc_flags & SC_TIMEOUT)))
	return 0;
#ifdef ALTQ
    /*
     * if ALTQ is enabled, don't invoke NETISR_PPP.
     * pppintr() could loop without doing anything useful
     * under rate-limiting.
     */
    if (ALTQ_IS_ENABLED(&sc->sc_if.if_snd))
	return 0;
#endif
    if (!((tp->t_state & TS_CARR_ON) == 0 && (tp->t_cflag & CLOCAL) == 0)
	&& sc != NULL && tp == (struct tty *) sc->sc_devp) {
	ppp_restart(sc);
    }
#endif /* !__QNXNTO__ */

    return 0;
}

/*
 * Timeout routine - try to start some more output.
 */
#ifndef __QNXNTO__
static void
ppp_timeout(void *x)
{
    struct ppp_softc *sc = (struct ppp_softc *) x;
    struct tty *tp = (struct tty *) sc->sc_devp;
    int s;

    s = spltty();
    sc->sc_flags &= ~SC_TIMEOUT;
    pppstart(tp);
    splx(s);
}
#endif

/*
 * Allocate enough mbuf to handle current MRU.
 */
static void
pppgetm(struct ppp_softc *sc)
{
    struct mbuf *m, **mp;
    int len;

    mp = &sc->sc_m;
    for (len = sc->sc_mru + PPP_HDRLEN + PPP_FCSLEN; len > 0; ){
	if ((m = *mp) == NULL) {
	    m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
	    if (m == NULL)
		break;
	    *mp = m;
	}
	len -= M_DATASIZE(m);
	mp = &m->m_next;
    }
}

/*
 * tty interface receiver interrupt.
 */
static const unsigned paritytab[8] = {
    0x96696996, 0x69969669, 0x69969669, 0x96696996,
    0x69969669, 0x96696996, 0x96696996, 0x69969669
};

static int
pppinput(int c, struct tty *tp)
{
    unsigned char	uc;

    uc = c;
    return qnx_pppframeinput(&uc, 1, tp, 1);
}


static int
qnx_pppframeinput(unsigned char *rdbuf, int len, struct tty *tp,
    int preamble)
{

    struct ppp_softc *sc;
    struct mbuf *m;
    unsigned char c;
    int i;
    int ilen;

    sc = (struct ppp_softc *) tp->t_sc;
    if (sc == NULL || tp != (struct tty *) sc->sc_devp)
	return 0;

    c = *rdbuf;


    if (preamble) {
	    /*
	     * Handle software flow control of output.
	     */
	    if (tp->t_iflag & IXON) {
		if (c == tp->t_cc[VSTOP] && tp->t_cc[VSTOP] != _POSIX_VDISABLE) {
		    if ((tp->t_state & TS_TTSTOP) == 0) {
			tp->t_state |= TS_TTSTOP;
		    }
		    return 0;
		}
		if (c == tp->t_cc[VSTART] && tp->t_cc[VSTART] != _POSIX_VDISABLE) {
		    tp->t_state &= ~TS_TTSTOP;
		    if (tp->t_oproc != NULL)
			(*tp->t_oproc)(tp);
		    return 0;
		}
	    }
    }

    if (c & 0x80)
	sc->sc_flags |= SC_RCV_B7_1;
    else
	sc->sc_flags |= SC_RCV_B7_0;
    if (paritytab[c >> 5] & (1 << (c & 0x1F)))
	sc->sc_flags |= SC_RCV_ODDP;
    else
	sc->sc_flags |= SC_RCV_EVNP;

    for (i = 0; i < len; i++) {

	    c = rdbuf[i];
	    ++tk_nin;
	    ++sc->sc_stats.ppp_ibytes;

	    if (c == PPP_FLAG) {
		ilen = sc->sc_ilen;
		sc->sc_ilen = 0;

		/*
		 * If SC_ESCAPED is set, then we've seen the packet
		 * abort sequence "}~".
		 */
		if (sc->sc_flags & (SC_FLUSH | SC_ESCAPED)
		    || (ilen > 0 && sc->sc_fcs != PPP_GOODFCS)) {
		    sc->sc_flags |= SC_PKTLOST;	/* note the dropped packet */
		    if ((sc->sc_flags & (SC_FLUSH | SC_ESCAPED)) == 0){
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: bad fcs %x\n", sc->sc_if.if_xname,
				sc->sc_fcs);
			sc->sc_if.if_ierrors++;
			sc->sc_stats.ppp_ierrors++;
		    } else
			sc->sc_flags &= ~(SC_FLUSH | SC_ESCAPED);
		    continue;
		}
	
		if (ilen < PPP_HDRLEN + PPP_FCSLEN) {
		    if (ilen) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: too short (%d)\n", sc->sc_if.if_xname, ilen);
			sc->sc_if.if_ierrors++;
			sc->sc_stats.ppp_ierrors++;
			sc->sc_flags |= SC_PKTLOST;
		    }
		    continue;
		}
	
		/*
		 * Remove FCS trailer.  Somewhat painful...
		 */
		ilen -= 2;
		if (--sc->sc_mc->m_len == 0) {
		    for (m = sc->sc_m; m->m_next != sc->sc_mc; m = m->m_next)
			;
		    sc->sc_mc = m;
		}
		sc->sc_mc->m_len--;
	
		/* excise this mbuf chain */
		m = sc->sc_m;
		sc->sc_m = sc->sc_mc->m_next;
		sc->sc_mc->m_next = NULL;
	
		ppppktin(sc, m, sc->sc_flags & SC_PKTLOST);
		if (sc->sc_flags & SC_PKTLOST) {
		    sc->sc_flags &= ~SC_PKTLOST;
		}
	
		pppgetm(sc);
		continue;
	    }
	
	    if (sc->sc_flags & SC_FLUSH) {
		continue;
	    }	
	
	    if (c < 0x20 && (sc->sc_rasyncmap & (1 << c)))
		continue;
	
	    if (sc->sc_flags & SC_ESCAPED) {
		sc->sc_flags &= ~SC_ESCAPED;
		c ^= PPP_TRANS;
	    } else if (c == PPP_ESCAPE) {
		sc->sc_flags |= SC_ESCAPED;
		continue;
	    }
	
	    /*
	     * Initialize buffer on first octet received.
	     * First octet could be address or protocol (when compressing
	     * address/control).
	     * Second octet is control.
	     * Third octet is first or second (when compressing protocol)
	     * octet of protocol.
	     * Fourth octet is second octet of protocol.
	     */

	    /* Using this switch statement makes the code much more complicated but
	     * removes a number of unnecessary comparisons so improves performance. */
	    switch(sc->sc_ilen) {
		case 1:
		    if (c != PPP_UI) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: missing UI (0x3), got 0x%x\n",
				sc->sc_if.if_xname, c);
			goto flush;
		    }
		    break;
	        case 0:
			/* reset the first input mbuf */
			if (sc->sc_m == NULL) {
			    pppgetm(sc);
			    if (sc->sc_m == NULL) {
				if (sc->sc_flags & SC_DEBUG)
				    printf("%s: no input mbufs!\n", sc->sc_if.if_xname);
				goto flush;
			    }
			}
			m = sc->sc_m;
			m->m_len = 0;
			m->m_data = M_DATASTART(sc->sc_m);
			sc->sc_mc = m;
			sc->sc_mp = mtod(m, char *);
			sc->sc_fcs = PPP_INITFCS;
			if (c == PPP_ALLSTATIONS) {
				break;
			}
			if (sc->sc_flags & SC_REJ_COMP_AC) {
			    if (sc->sc_flags & SC_DEBUG)
		 		printf("%s: garbage received: 0x%x (need 0xFF)\n",
				    sc->sc_if.if_xname, c);
			    goto flush;
			}
			*sc->sc_mp++ = PPP_ALLSTATIONS;
			*sc->sc_mp++ = PPP_UI;
			sc->sc_ilen += 2;
			m->m_len += 2;
			/* Fall through to sc_ilen = 2 since sc_ilen has been updated. */
		case 2:

		    if ((c & 1) == 1) {
		    	/* a compressed protocol */
		    	*sc->sc_mp++ = 0;
		    	sc->sc_ilen++;
		    	sc->sc_mc->m_len++;
		        /* Although sc_ilen has been updated here, there's no need to fall
			    through into case 3 since we already know that (c & 1) != 0) */
		    }
		    break;   
		case 3:
		    if ((c & 1) == 0) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: bad protocol %x\n", sc->sc_if.if_xname,
				(sc->sc_mp[-1] << 8) + c);
			goto flush;
		    }
		    break;
		default:
		    break;
		    
	    }
	
	    /* packet beyond configured mru? */
	    if (++sc->sc_ilen > sc->sc_mru + PPP_HDRLEN + PPP_FCSLEN) {
		if (sc->sc_flags & SC_DEBUG)
		    printf("%s: packet too big\n", sc->sc_if.if_xname);
		goto flush;
	    }
	
	    /* is this mbuf full? */
	    m = sc->sc_mc;
	    if (M_TRAILINGSPACE(m) <= 0) {
		if (m->m_next == NULL) {
		    pppgetm(sc);
		    if (m->m_next == NULL) {
			if (sc->sc_flags & SC_DEBUG)
			    printf("%s: too few input mbufs!\n", sc->sc_if.if_xname);
			goto flush;
		    }
		}
		sc->sc_mc = m = m->m_next;
		m->m_len = 0;
		m->m_data = M_DATASTART(m);
		sc->sc_mp = mtod(m, char *);
	    }
	
	    ++m->m_len;
	    *sc->sc_mp++ = c;
	    sc->sc_fcs = PPP_FCS(sc->sc_fcs, c);
	    continue;
	
	 flush:
	    if (!(sc->sc_flags & SC_FLUSH)) {
		sc->sc_if.if_ierrors++;
		sc->sc_stats.ppp_ierrors++;
		sc->sc_flags |= SC_FLUSH;
	    }
    }	/* bottom of for() loop */
    return 0;
}



#define MAX_DUMP_BYTES	128

#ifndef __QNXNTO__
static void
ppplogchar(struct ppp_softc *sc, int c)
{
    if (c >= 0) {
	sc->sc_rawin.buf[sc->sc_rawin_start++] = c;
	if (sc->sc_rawin.count < sizeof(sc->sc_rawin.buf))
	    sc->sc_rawin.count++;
    }
    if (sc->sc_rawin_start >= sizeof(sc->sc_rawin.buf)
	|| (c < 0 && sc->sc_rawin_start > 0)) {
	if (sc->sc_flags & (SC_LOG_FLUSH|SC_LOG_RAWIN)) {
	    printf("%s input: ", sc->sc_if.if_xname);
	    pppdumpb(sc->sc_rawin.buf, sc->sc_rawin_start);
	}
	if (c < 0)
	    sc->sc_rawin.count = 0;
	sc->sc_rawin_start = 0;
    }
}

static void
pppdumpb(u_char *b, int l)
{
    char bf[3*MAX_DUMP_BYTES+4];
    char *bp = bf;

    while (l--) {
	if (bp >= bf + sizeof(bf) - 3) {
	    *bp++ = '>';
	    break;
	}
	*bp++ = hexdigits[*b >> 4]; /* convert byte to ascii hex */
	*bp++ = hexdigits[*b++ & 0xf];
	*bp++ = ' ';
    }

    *bp = 0;
    printf("%s\n", bf);
}
#endif

static void
pppdumpframe(struct ppp_softc *sc, struct mbuf *m, int xmit)
{
	int i,lcount,copycount,count;
	char lbuf[16];
	char *data;

	if (m == NULL)
		return;

	for(count=m->m_len,data=mtod(m,char*);m != NULL;) {
		/* build a line of output */
		for(lcount=0;lcount < sizeof(lbuf);lcount += copycount) {
			if (!count) {
				m = m->m_next;
				if (m == NULL)
					break;
				count = m->m_len;
				data  = mtod(m,char*);
			}
			copycount = (count > sizeof(lbuf)-lcount) ?
					sizeof(lbuf)-lcount : count;
			bcopy(data,&lbuf[lcount],copycount);
			data  += copycount;
			count -= copycount;
		}

		/* output line (hex 1st, then ascii) */
		printf("%s %s:", sc->sc_if.if_xname,
		    xmit ? "output" : "input ");
		for(i=0;i<lcount;i++)
			printf("%02x ",(u_char)lbuf[i]);
		for(;i<sizeof(lbuf);i++)
			printf("   ");
		for(i=0;i<lcount;i++)
			printf("%c",(lbuf[i] >= 040 &&
			    lbuf[i] <= 0176) ? lbuf[i] : '.');
		printf("\n");
	}
}

#ifdef __QNXNTO__ 
static resmgr_connect_funcs_t pppmgr_connect_funcs = {
	1,
	pppmgr_open
};

static iofunc_attr_t pppmgr_attr;

static resmgr_io_funcs_t pppmgr_io_funcs = {
	11,
	pppmgr_read,
	pppmgr_write,
	pppmgr_close_ocb,
	pppmgr_stat,
	pppmgr_notify,
	pppmgr_devctl,
	pppmgr_unblock,
	NULL,                /* pathconf */
	NULL,                /* lseek    */
	pppmgr_chmod,
	pppmgr_chown

};

void
pppmgr_resinit(void *pin, char* prefix, size_t prefix_len)
{
	pppmgr_ctrl_t *pc = &pppmgrctrl;
	struct nw_stk_ctl *sctlp = pin;
	char *pname;
	size_t len;
	static const char pppmgr_path[] = "/dev/socket/pppmgr";

	if (prefix == NULL || pin == NULL) /* XXX */
		return;

	len = prefix_len + sizeof(pppmgr_path);
	pname = alloca(len);
	if(pname == NULL)  
		return; 
	memcpy(pname, prefix, prefix_len); 
	pname[prefix_len] = 0;
	strlcat(pname, pppmgr_path, len);

	iofunc_attr_init(&pppmgr_attr, 0664, NULL, NULL);
	pc->pathid = resmgr_attach(sctlp->dpp, 0, pname, _FTYPE_ANY, 0,
	    &pppmgr_connect_funcs, NULL, &pppmgr_attr);
	if (pc->pathid == -1)
		return;

	memset(&pc->pppmgrstat, 0, sizeof(struct stat));
	pc->pppmgrstat.st_ino = 640;
	pc->pppmgrstat.st_mtime = pc->pppmgrstat.st_atime =
	    pc->pppmgrstat.st_ctime = time(0);
	pc->pppmgrstat.st_mode = _S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
	pc->pppmgrstat.st_nlink = 1;
	pppattach(); 

	return;
}

static int
pppmgr_open(resmgr_context_t *ctp, io_open_t * msg, RESMGR_HANDLE_T *handle, void *extra)
{
	struct pppmgr_ocb *ocb;
	struct proc     *p;
	int ret = EOK;

	if ((ret = msg_open_chk_access(ctp, msg, (iofunc_attr_t *)handle)) != EOK)
		return ret;

	if ((ocb = malloc (sizeof(*ocb), M_DEVBUF, M_WAITOK)) == NULL) {
		ret = errno;
#ifdef QNXPPPDEBUG
		printf("malloc failed\n");
#endif
		return _RESMGR_ERRNO(ret);
	}
	memset(ocb, 0, sizeof(*ocb));

	ocb->iofunc_ocb.ioflag = msg->connect.ioflag; 
	ocb->iofunc_ocb.attr   = (iofunc_attr_t *)handle;
	ocb->pid   = curproc->p_ctxt.info.pid;
	
	p = PROC_FROM_CTP(ctp);
	p->p_cred = ocb->ocb_cred = kauth_cred_alloc();
	PR_TO_LWP(p)->l_fp = NULL;

	if (msg->connect.ioflag & _IO_FLAG_WR) {
		struct tty *tp;
		if ((ocb->sc = pppalloc(ocb->pid)) == NULL) {
			kauth_cred_free(p->p_cred);
			free(ocb, M_DEVBUF);
			return ENOMEM;
		}
		if ((tp = ttymalloc()) == NULL) {
			kauth_cred_free(p->p_cred);
			free(ocb->sc, M_DEVBUF);
			free(ocb, M_DEVBUF);
			return ENOMEM;
		}

		ocb->ocb_flag = OCBFLAG_PPP_CREATED;
		ocb->sc->qnxsc_ocb = ocb;
		ocb->sc->sc_devp = tp;
		ocb->sc->sc_if.if_flags |= IFF_RUNNING;
		tp->t_sc = ocb->sc;
	}

	if (resmgr_open_bind(ctp, ocb, &pppmgr_io_funcs) < 0) {
		ret = errno;
#ifdef QNXPPPDEBUG
		printf(" resmgr_open_band failed %d \n", ret);
#endif
		kauth_cred_free(p->p_cred);
		free(ocb->sc, M_DEVBUF);
		free(ocb, M_DEVBUF);
	}
	return _RESMGR_ERRNO(ret);
}

static int
pppmgr_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = (struct pppmgr_ocb *)o;
	struct ppp_softc *sc;
	struct mbuf *m, *m2;
	int nbytes;
	int msgoff;
	struct proc *p;

	struct nw_work_thread *wtp = WTP;
	struct nw_stk_ctl *sctlp = &stk_ctl;

	if ((sc = ocb->sc) == NULL)
		return _RESMGR_ERRNO(ENOSYS);

	if ((nbytes = msg->i.nbytes) == 0)
		return _RESMGR_ERRNO(EOK);
#ifdef __QNXNTO__
	if (sc->qnxsc_flags & QNXSC_TTY_PEER_CLOSE) {

		/* The peer of the TTY closed its end of the link (ie DCD dropped) */
		_IO_SET_READ_NBYTES(ctp, 0);
		return _RESMGR_ERRNO(EOK);
	}
#endif

	PROC_INIT(p, ctp, ocb);

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);

	IF_DEQUEUE(&sc->sc_inq, m);
	if (m == NULL) {
		/* no data available */
		if (ocb->ocb_flag & OCBFLAG_PPP_NPQUEUED) {
			/* NPQUEUED */
			uint8_t ret = PPP_FLAG;
			ocb->ocb_flag &= ~OCBFLAG_PPP_NPQUEUED;
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			MsgReply(ctp->rcvid, 1, &ret, 1);
			PROC_FINI(p);
			return _RESMGR_NOREPLY;
		}
		if (ocb->iofunc_ocb.ioflag & O_NONBLOCK) {
			/* unblock reading */
			NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
			PROC_FINI(p);
			return _RESMGR_ERRNO(EWOULDBLOCK);
		}
		/* reply him when we have data */
		ocb->reader_rcvid = ctp->rcvid;
		ocb->reader_nbytes = msg->i.nbytes;
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		PROC_FINI(p);
		return _RESMGR_NOREPLY;
	}
	
	NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);

	msgoff = 0;
	for (;;) {
		resmgr_msgwrite(ctp, mtod(m, u_char *), m->m_len, msgoff);
		msgoff += m->m_len;
		MFREE(m, m2);
		m = m2;
		if(m == NULL) 
			break;
	}
	_IO_SET_READ_NBYTES(ctp, msgoff);
	PROC_FINI(p);
	return _RESMGR_ERRNO(EOK);
}

static int
pppmgr_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = (struct pppmgr_ocb *)o;
	struct ppp_softc *sc;
	int ret;
	int nbytes;
	struct uio uio;
	struct iovec iov;
	struct proc *p;

	if ((nbytes = msg->i.nbytes) == 0)
		return _RESMGR_ERRNO(EOK);
	if ((sc = ocb->sc) == NULL || sc->sc_devp == NULL) 
		return _RESMGR_ERRNO(ENXIO);

	if ((iov.iov_base = malloc(msg->i.nbytes, M_DEVBUF, M_WAITOK)) == NULL)
		return _RESMGR_ERRNO(ENOMEM);

	PROC_INIT(p, ctp, ocb);

	iov.iov_len = msg->i.nbytes;
	if (resmgr_msgread(ctp, iov.iov_base, iov.iov_len,
	    sizeof(struct _io_write)) == -1) {
		PROC_FINI(p);
		free(iov.iov_base, M_DEVBUF);
		return _RESMGR_ERRNO(errno);
	}

	memset(&uio, 0, sizeof(struct uio)); 
	uio.uio_resid = msg->i.nbytes;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;

	ret = pppwrite((struct tty *)ocb->sc->sc_devp, &uio, 0);

	free(iov.iov_base, M_DEVBUF);

	if (ret == EOK) 
		_IO_SET_WRITE_NBYTES(ctp, nbytes);
	PROC_FINI(p);
	return _RESMGR_ERRNO(ret);
}

int
qnxtty_rdthread_destroy(struct ppp_softc *sc)
{
	nw_pthread_reap(sc->qnxsc_readtid);
	return 1;
}

struct ppp_close_blockop {
	int qnxsc_pppfdrd;
	int qnxsc_pppfdrd2;
	int qnxsc_pppfdwr;
};

void qnxppp_tty_close_blockop(void *arg);

void qnxppp_tty_close_blockop(void *arg)
{
	struct ppp_close_blockop *pcb;
	pcb = arg;

	if(pcb->qnxsc_pppfdrd != -1)
		close(pcb->qnxsc_pppfdrd);
	if(pcb->qnxsc_pppfdrd2 != -1)
		close(pcb->qnxsc_pppfdrd2);
	if(pcb->qnxsc_pppfdwr != -1)
		close(pcb->qnxsc_pppfdwr);
}

int
qnxppp_ttydetach(struct ppp_softc *sc, int free_tp)
{
	struct pppmgr_ocb *ocb = (struct pppmgr_ocb *)sc->qnxsc_ocb;
	struct ppp_close_blockop pcb;
	struct bop_dispatch bop;

	if (sc->qnxsc_readtid != -1) {
		qnxtty_rdthread_destroy(sc); 
		sc->qnxsc_readtid = -1;
	}

	pcb.qnxsc_pppfdrd = sc->qnxsc_pppfdrd;
	pcb.qnxsc_pppfdrd2 = sc->qnxsc_pppfdrd2;
	pcb.qnxsc_pppfdwr = sc->qnxsc_pppfdwr;

	bop.bop_func = qnxppp_tty_close_blockop;
	bop.bop_arg = &pcb;
	bop.bop_prio = curproc->p_ctxt.info.priority;
	blockop_dispatch(&bop, NULL);
	
	sc->qnxsc_pppfdrd = -1;
	sc->qnxsc_pppfdrd2 = -1;
	sc->qnxsc_pppfdwr = -1;

	if (sc->qnxsc_rdbuf != 0) {
		free(sc->qnxsc_rdbuf, M_DEVBUF);
		sc->qnxsc_rdbuf    = 0;
		sc->qnxsc_rdbuflen = 0;
	}

	if (ocb != NULL) 
		ocb->ocb_flag &= ~OCBFLAG_PPP_ATTACHED;

	sc->qnxsc_flags |= QNXSC_DYIED;

/* If we are doing demand dialing, we don't want the TTY structure
 * freed, as we could be connecting again and pppoutput will check
 * to see if we have a valid tp pointer. PPPIOCDETACH is only called in
 * demand mode.
 */

	if (free_tp) {
		ttyfree(sc->sc_devp);
		sc->sc_devp = 0; 
	}

	sc->qnxsc_flags &= ~QNXSC_TTY_PEER_CLOSE;

	return 0;
}

static int
pppmgr_close_ocb(resmgr_context_t *ctp, void *reserved, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = (struct pppmgr_ocb *)o;
	struct ppp_softc *sc;
	struct proc     *p;

	PROC_INIT(p, ctp, ocb);

	if ((sc = ocb->sc) != NULL && sc->sc_devp != NULL) 
		pppclose((struct tty *)sc->sc_devp, 0);
	else if (sc != NULL)
		pppdealloc(sc);

	iofunc_notify_remove(NULL, ocb->notify);
	kauth_cred_free(ocb->ocb_cred);
	free(ocb, M_DEVBUF);

	PROC_FINI(p);

	return _RESMGR_ERRNO(EOK);
}

static int
pppmgr_unblock(resmgr_context_t *ctp, io_pulse_t *msg, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = o;
	struct ppp_softc *sc;

	if ((sc = ocb->sc) != NULL) {
		struct nw_work_thread *wtp = WTP;
		struct nw_stk_ctl *sctlp = &stk_ctl;
		NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		ocb->reader_rcvid = 0;
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}

	return EOK;
}

static int
pppmgr_chmod(resmgr_context_t *ctp, io_chmod_t *mod_p, RESMGR_OCB_T *ocb)
{
	int                  status = EOK;

	if((status = iofunc_chmod_default(ctp, mod_p, ocb)) == EOK) {
		/* for some reason, we have attributes/mod_t in pppmgr_attr and
		   pppmgrstat.st_mode, we need to make sure that they are in sync */
		pppmgrctrl.pppmgrstat.st_mode = pppmgr_attr.mode;
	}
	return status;
}

static int
pppmgr_chown(resmgr_context_t *ctp, io_chown_t *own_p, RESMGR_OCB_T *ocb)
{
	int                  status = EOK;

	if((status = iofunc_chown_default(ctp, own_p, ocb)) == EOK) {
		/* for some reason, we have attributes/mod_t in pppmgr_attr and
		   pppmgrstat.st_mode, we need to make sure that they are in sync */
		pppmgrctrl.pppmgrstat.st_uid = pppmgr_attr.uid;
		pppmgrctrl.pppmgrstat.st_gid = pppmgr_attr.gid;
	}
	   
	return status;
}

static int
pppmgr_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = o;
	char *data = _DEVCTL_DATA(msg->i);
	int rc;

	struct proc *p;

	PROC_INIT(p, ctp, ocb);

	switch (msg->i.dcmd) {
	case F_GETFL:
		*(int *)data = ocb->iofunc_ocb.ioflag;
		msg->i.nbytes = sizeof(int);
		break;
	case F_SETFL:
		ocb->iofunc_ocb.ioflag = *(int *)data;
		msg->i.nbytes = 0;
		break;
	case PPPIOCATTACH:
		if (ocb->ocb_flag & OCBFLAG_PPP_ATTACHED) {
			PROC_FINI(p);
			return _RESMGR_ERRNO(ENXIO);
		}
		rc = qnxppp_ttyattach(ocb, (struct ppp_attach *)data);
		PROC_FINI(p);
		return _RESMGR_ERRNO(rc);
	default:
		if (ocb->sc == NULL) {
			PROC_FINI(p);
			return _RESMGR_ERRNO(ENOSYS);
		}
		if(ocb->sc->sc_devp == NULL) {
			msg->o.ret_val = pppioctl(ocb->sc, msg->i.dcmd, data,
			    msg->i.nbytes, curlwp);
		}
		else {
			msg->o.ret_val =
			    ppptioctl((struct tty *)ocb->sc->sc_devp,
				msg->i.dcmd, data, msg->i.nbytes, curlwp);
		}
		break;
	}

	SETIOV(ctp->iov + 0, &msg->o, sizeof(msg->o));
	_RESMGR_STATUS(ctp, msg->o.ret_val);
	PROC_FINI(p);
	if (msg->i.nbytes) {
		SETIOV(ctp->iov + 1, data, msg->o.nbytes);
		return _RESMGR_NPARTS(2);
	} else {
		return _RESMGR_NPARTS(1);
	}
}

int
qnxppp_ttyattach(struct pppmgr_ocb *ocb, struct ppp_attach *pattach) {
	struct ppp_softc *sc;
	int rc;

	switch(pattach->type) {
	case PPPATTACH_TYPE_DUPFD:
		if((ocb->sc) == NULL && (ocb->sc = pppalloc(ocb->pid)) == NULL)
			return ENOMEM;
		sc = ocb->sc;
		sc->qnxsc_pppfdrd = ConnectAttach(pattach->i.dupfd.srvnd,
		    pattach->i.dupfd.srvpid, pattach->i.dupfd.srvchid,
		    0, _NTO_COF_CLOEXEC);
		if (sc->qnxsc_pppfdrd == -1) {
			pppdealloc(sc);
			return EIO;
		}
		sc->qnxsc_slpid = pattach->i.dupfd.srvpid;

		if (MsgSendnc(sc->qnxsc_pppfdrd, &pattach->i.dupfd.dup,
		    sizeof(io_dup_t), 0, 0) == -1) {
			rc = errno;
			ConnectDetach_r(sc->qnxsc_pppfdrd);
			pppdealloc(sc);
			return rc;
		}
		sc->qnxsc_pppfdwr = openfd(sc->qnxsc_pppfdrd, O_WRONLY);
		if (sc->qnxsc_pppfdwr == -1) {
			rc = errno;
			close(sc->qnxsc_pppfdrd);
			pppdealloc(sc);
			return rc;
		}
		ConnectFlags_r(0, sc->qnxsc_pppfdrd, FD_CLOEXEC, 0);
		ConnectFlags_r(0, sc->qnxsc_pppfdwr, FD_CLOEXEC, 0);
		
		rc = pppopen((int)sc, sc->sc_devp); 
		if (rc == 0)
			ocb->ocb_flag = OCBFLAG_PPP_CREATED | OCBFLAG_PPP_ATTACHED;
		return rc;
	default:
		return EINVAL;
	}
	return EOK;
};

static int
pppmgr_stat(resmgr_context_t *ctp, io_stat_t *msg, RESMGR_OCB_T *o)
{
	msg->o = pppmgrctrl.pppmgrstat;
	SETIOV(ctp->iov + 0, &msg->o, sizeof(msg->o));
	_RESMGR_STATUS(ctp, EOK);
	return _RESMGR_NPARTS(1);
}

static int
pppmgr_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *o)
{
	struct pppmgr_ocb *ocb = o;
	unsigned trig = _NOTIFY_COND_OUTPUT;
	int n, notifycnts[3] = {1, 1, 1};
	int ret;
	struct ppp_softc *sc;
	struct nw_work_thread *wtp = WTP;
	struct nw_stk_ctl *sctlp = &stk_ctl;

	struct proc *p;

	if ((sc = ocb->sc) == NULL)
		  return _RESMGR_ERRNO(ENXIO);

	PROC_INIT(p, ctp, ocb);

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (!IF_IS_EMPTY(&sc->sc_inq) || (sc->qnxsc_flags & QNXSC_TTY_PEER_CLOSE)) 
		  trig |= _NOTIFY_COND_INPUT;
	ret = iofunc_notify(ctp, msg, &ocb->notify[0], trig, notifycnts, &n);
	NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);

	PROC_FINI(p);

	return ret;
}

/* alloc rawbufs */
/* flag = 1, alloc rdbuf; 2, wtbuf; 0, all; */
int
qnxppp_scrawbuf(struct ppp_softc *sc, int flag)
{
	int i;
	if (flag == 0 || flag == 1) {
		i = (sc->sc_mru + PPP_EXTRALEN) * 2 + 2;
		if (sc->qnxsc_rdbuf && sc->qnxsc_rdbuflen != i) {
			free(sc->qnxsc_rdbuf, M_DEVBUF);
			sc->qnxsc_rdbuf = 0;
		}
		if (sc->qnxsc_rdbuf == NULL && 
		    (sc->qnxsc_rdbuf = malloc(i, M_DEVBUF, M_WAITOK)) == NULL)  {
			sc->qnxsc_rdbuflen = 0;
			return -1;
		}
		sc->qnxsc_rdbuflen = i;
	}
	return 0;
}

/* realloc tty TX buffer */

int
qnxtty_txrawbuf(struct ppp_softc *sc)
{
	int i;
	struct tty *tp = sc->sc_devp;

	if (tp) {
		i = (sc->sc_if.if_mtu + PPP_EXTRALEN) * 2 + 2;
		if (tp->t_outq.c_cn != i) {
			clfree(&tp->t_outq);
			if (clalloc(&tp->t_outq, i, 0) != 0) {
				log(LOG_ERR, "qnxtty_txrawbuf allocation failed\n");
				return -1;
			}
		}
	}
	return 0;
}

int
qnxtty_rdthread_init(void *arg)
{
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	struct ppprcv_loop_args	*rargs;
	int			intr_prio;

	pthread_setname_np(gettid(), "io-pkt ppp");

  	sctlp = &stk_ctl;
	wtp = WTP;
	rargs = arg;
	intr_prio = rargs->prio;

	wtp->intr_sighot = _ISIG_HOT;
	wtp->wt_zone_mbuf.max = mbuf_cache_max;
	wtp->wt_zone_packet.max = pkt_cache_max;
	wtp->quiesce_callout = qnxtty_rdthread_callout;
	wtp->quiesce_arg = rargs->sc;
	pthread_mutex_init(&rargs->sc->rdthread_mutex, NULL);
	pthread_cond_init(&rargs->sc->rdthread_cond, NULL);
	pthread_mutex_lock(&rargs->sc->rdthread_mutex);

	return EOK;
}

void
qnxtty_rdthread_callout(void *arg, int die)
{

	struct ppp_softc	*sc;

	sc = arg;

	sc->qnxsc_quiesce = QNXSC_QUIESCE_PENDING;
	sc->qnxsc_pppfdrd2 = -1;
	if (die) {
		sc->qnxsc_quiesce |= QNXSC_QUIESCE_DIE;
		sc->qnxsc_pppfdrd2 = -1;
	}
	else {
		sc->qnxsc_pppfdrd2 = dup(sc->qnxsc_pppfdrd);
		/* dup clears() CLOEXEC */
		ConnectFlags_r(0, sc->qnxsc_pppfdrd2, FD_CLOEXEC, 0);
	}

	close(sc->qnxsc_pppfdrd);
	pthread_mutex_lock(&sc->rdthread_mutex);
	pthread_cond_signal(&sc->rdthread_cond);
	pthread_mutex_unlock(&sc->rdthread_mutex);

	return;
}

void *
qnxtty_rdthread_reader(void *arg)
{
	int			readlen, die;
	struct ppp_softc	*sc;
	sc = arg;
	
	for (;;) {
		readlen = read(sc->qnxsc_pppfdrd, sc->qnxsc_rdbuf, sc->qnxsc_rdbuflen);

		if (readlen == 0) {
		        struct pppmgr_ocb *ocb = sc->qnxsc_ocb;

			sc->qnxsc_flags |= QNXSC_TTY_PEER_CLOSE;
			iofunc_notify_trigger(ocb->notify, 1, IOFUNC_NOTIFY_INPUT);
			/* Nothing left to do as peer has gone away. */
			
			for(;;) {
				pthread_cond_wait(&sc->rdthread_cond, &sc->rdthread_mutex);					
				sc->qnxsc_pppfdrd = sc->qnxsc_pppfdrd2;
				sc->qnxsc_pppfdrd2 = -1;
				if (sc->qnxsc_quiesce & QNXSC_QUIESCE_DIE) {
					die = 1;
					pthread_mutex_unlock(&sc->rdthread_mutex);
					pthread_mutex_destroy(&sc->rdthread_mutex);
					pthread_cond_destroy(&sc->rdthread_cond);
				}
				else
					die = 0;
				sc->qnxsc_quiesce = 0;
				quiesce_block(die);	
			}
			return 0; //not reached

		}

		if (readlen == -1) {
			if (sc->qnxsc_quiesce & QNXSC_QUIESCE_PENDING) {
				pthread_cond_wait(&sc->rdthread_cond, &sc->rdthread_mutex);
				sc->qnxsc_pppfdrd = sc->qnxsc_pppfdrd2;
				sc->qnxsc_pppfdrd2 = -1;
				if (sc->qnxsc_quiesce & QNXSC_QUIESCE_DIE) {
					die = 1;
					pthread_mutex_unlock(&sc->rdthread_mutex);
					pthread_mutex_destroy(&sc->rdthread_mutex);
					pthread_cond_destroy(&sc->rdthread_cond);
				}
				else
					die = 0;
				sc->qnxsc_quiesce = 0;
				quiesce_block(die);
			}
			else {
				/* Don't spin if read returns -1. QUIESCE_PENDING
				   should be set soon, or thread will be destroyed.
				*/
				delay(100);
			}
			continue;
		}
	
		qnx_pppframeinput((unsigned char *)sc->qnxsc_rdbuf, readlen, sc->sc_devp, 0);

	}

	return 0;
}

static int
qnxtty_rdthread_create(struct ppp_softc *sc)
{
	struct ppprcv_loop_args init_args;

	init_args.prio = getprio(0); /* XXX */
	init_args.sc = sc;

	return nw_pthread_create(&sc->qnxsc_readtid, 0, 
	    qnxtty_rdthread_reader, (void *)sc, WT_FLOW, 
	    qnxtty_rdthread_init, (void *)&init_args);
}

void
qnxtty_output(struct tty *tp)
{
	int ret;
	struct ppp_softc *sc = tp->t_sc;
	int len;

	while ((len = ndqb(&tp->t_outq, 0)) > 0) {
		ret = write(sc->qnxsc_pppfdwr, tp->t_outq.c_cf, len);
		if (ret == -1 && errno == EAGAIN)
			callout_msec(&sc->tx_callout, 100, ppp_kick_tx, tp->t_sc);
		if (ret <= 0)
			break;
		ndflush(&tp->t_outq, ret);
	}
	return;
}

#ifdef QNX_MULTILINKPPP
/* multilink ppp */
static int getframelen(struct mbuf *);
static int puthdr(struct ppp_softc *, u_char, u_char *); 
static int putthis(struct ppp_softc *, u_char *, int); 
static int putend(struct ppp_softc *); 

/* get frame length */
static int
getframelen(struct mbuf *m)
{
	int len = 0;
	while (m) {
		len += m->m_len;
		m = m->m_next;
	}
	return len;
}

/* populate mphdr */
static int
puthdr(struct ppp_softc *sc, u_char bets, u_char *mphdr)
{
	struct ppp_softc *msc;
	mp_ressq_t *mprq;
	struct tty *tp = (struct tty *)sc->sc_devp;
  	u_char *cp = mphdr + 2;

	msc = (sc->qnxsc_flags & QNXSC_IFATTACHED) ? sc : sc->qnxsc_mpnxchan;
	mprq = msc->qnxsc_mprq;

	++msc->sc_stats.ppp_obytes;
	(void)putc(PPP_FLAG, &tp->t_outq);
	/* mp hdr */
	if ((msc->sc_flags & QNXSC_MPSHORTSEQX)) {
		*cp++ = bets + ((mprq->tx_seq >> 8) & 0xf);
		*cp++ = mprq->tx_seq;
	} else {
		*cp++ = bets;
		*cp++ = mprq->tx_seq >> 16;
		*cp++ = mprq->tx_seq >> 8;
		*cp++ = mprq->tx_seq;
	}
	putthis(sc, mphdr, cp - mphdr);

	return cp - mphdr;
}

/* to tty */
static int
putthis(struct ppp_softc *sc, u_char* buf, int len)
{
	struct tty *tp = (struct tty *)sc->sc_devp; 
	struct ppp_softc *msc;
	u_char *start, *stop, *cp;
	int n, ndone;

	msc = (sc->qnxsc_flags & QNXSC_IFATTACHED) ? sc : sc->qnxsc_mpnxchan;
	start = buf;
	stop  = buf + len;
	while (len > 0) {
		/*
		 * Find out how many bytes in the string we can
		 * handle without doing something special.
		 */
		for (cp = start; cp < stop; cp++) {
			if (ESCAPE_P(*cp))
				break;
		}
		n = cp - start;
		if (n) {
			/* NetBSD (0.9 or later), 4.3-Reno or similar. */
			ndone = n - b_to_q(start, n, &tp->t_outq);
			len -= ndone;
			start += ndone;
			msc->sc_stats.ppp_obytes += ndone;

			if (ndone < n)
				break;	/* packet doesn't fit */
		}
		/*
		 * If there are characters left in the mbuf,
		 * the first one must be special.
		 * Put it out in a different form.
		 */
		if (len) {
			if (putc(PPP_ESCAPE, &tp->t_outq)) {
					break;
			}
			if (putc(*start ^ PPP_TRANS, &tp->t_outq)) {
				(void)unputc(&tp->t_outq);
				break;
			}
			msc->sc_stats.ppp_obytes += 2;
			start++;
			len--;
		}
	} 
	return len;
}

/* add end */
static int
putend(struct ppp_softc *sc)
{
	struct tty *tp = (struct tty *)sc->sc_devp; 
	struct ppp_softc *msc;
	u_char *p, *q;
	int c;
	u_char endseq[8];
	int done = 1; 

	msc = (sc->qnxsc_flags & QNXSC_IFATTACHED) ? sc : sc->qnxsc_mpnxchan;
	/*
	 * We may have to escape the bytes in the FCS.
	 */
	p = endseq;
	c = ~sc->sc_outfcs & 0xFF;
	if (ESCAPE_P(c)) {
		*p++ = PPP_ESCAPE;
		*p++ = c ^ PPP_TRANS;
	} else
		*p++ = c;
	c = (~sc->sc_outfcs >> 8) & 0xFF;
	if (ESCAPE_P(c)) {
		*p++ = PPP_ESCAPE;
		*p++ = c ^ PPP_TRANS;
	} else
		*p++ = c;
	*p++ = PPP_FLAG;

	/*
	 * Try to output the FCS and flag.  If the bytes
	 * don't all fit, back out.
	 */
	for (q = endseq; q < p; ++q)  {
		if (putc(*q, &tp->t_outq)) {
			done = 0; 
			for (; q > endseq; --q)
				unputc(&tp->t_outq);
			break;
		}
	}
	if (done)
		msc->sc_stats.ppp_obytes += q - endseq;
	return done;
}

/* qnx_mpppasyncstart():
 * 1) gets packet on the waiting list.
 * 2) frag it if needed.
 * 3) send frags.
 */
#define MLEAVE	1
#define MBREAK	2

static void
qnx_mpppasyncstart(struct ppp_softc *msc)
{
	mp_ressq_t *mprq = msc->qnxsc_mprq;
	struct ppp_softc *sc0;
	struct mbuf *m, *m2, *mnext;
	int len, lentt, mphdrlen, done, status = 0;
	u_char *start, bets, mphdr[MPHDRLEN];

	mphdrlen = (msc->qnxsc_flags & QNXSC_MPSHORTSEQX) ? MPHDRLEN_SSN : MPHDRLEN;

	m = msc->sc_outm;

	if (pthread_rwlock_rdlock(&msc->qnxsc_mplock) != EOK)
		return;
	if (m == NULL) {
nextp:
		m = ppp_dequeue(msc);
		if (m == NULL) { /* done */
			pthread_rwlock_unlock(&msc->qnxsc_mplock);
			return;
		}
		len = getframelen(m);
		bets = (len > (msc->qnxsc_mpnxchan->sc_if.if_mtu + mphdrlen)) ? 0x80:0xc0; 
	} else {
		sc0 = msc->qnxsc_mpnxchan;	
		bets = mprq->bets;
		goto ctn;
	}

	mphdr[0] = PPP_MP >> 8;
	mphdr[1] = PPP_MP;

	mnext = 0;
	for (sc0 = msc->qnxsc_mpnxchan;; sc0 = sc0->qnxsc_mpnxsc) {
		if (sc0->qnxsc_flags & QNXSC_DYIED) 
			continue;
		/* check if a break is needed */
		len = getframelen(m);
		if (len <= (sc0->sc_if.if_mtu + mphdrlen)) 
			bets |= 0x40;
		else {
			if (mnext)
				bets &= 0x7f; 
		}

		/* add mp header */
		mphdrlen = puthdr(sc0, bets, mphdr); 
   		sc0->sc_outfcs = pppfcs(PPP_INITFCS, mphdr, mphdrlen);
	   	sc0->sc_outfcs = pppfcs(sc0->sc_outfcs, mtod(m, u_char *), m->m_len);
		mprq->tx_seq++;

ctn:
		lentt  = 0;
		status = 0;
		mnext  = 0;
		for (;;) { 
			start = mtod(m, u_char *);
		   	len = m->m_len;

			lentt += len;
			len = putthis(sc0, start, len);
			done = len == 0;
			
			if (done) {
				/* check if to frag */
				if (m->m_next) {
					if ((lentt + m->m_next->m_len) > (sc0->sc_if.if_mtu + mphdrlen)) {
						mnext = m->m_next;
						m->m_next = NULL;
						status = MBREAK;
					}
				}

				/* check if the end */
				if (m->m_next == NULL) { 
					done = putend(sc0); /* XXX */ 
				}
			}

			if (!done) {
				/* remember where we got to */
				m->m_data += len;
				m->m_len  -= len; 
				if (mnext) /* XXX: */
					m->m_next = mnext;
				status = MLEAVE;
				break; 
			}

			/* Finished with this mbuf; free it and move on. */
			MFREE(m, m2);
			m = m2;
			if (m == NULL) 
				break; 
			sc0->sc_outfcs = pppfcs(sc0->sc_outfcs, mtod(m, u_char *), m->m_len);
		}

		pppstart((struct tty *)sc0->sc_devp);

		if (status == MLEAVE) {
			/* there is still data left, do next time */
			msc->sc_outm = m;
			msc->qnxsc_mpnxchan = sc0;
			mprq->bets = bets;
			pthread_rwlock_unlock(&msc->qnxsc_mplock);
			return;
		}

		if (status == MBREAK) {
			m_freem(m);
			m = mnext;
		} else {
			/* to get next packet to send */
			msc->qnxsc_mpnxchan = sc0->qnxsc_mpnxsc;
			goto nextp;
		}
	}

	pthread_rwlock_unlock(&msc->qnxsc_mplock);
	return;
}
#endif /* QNX_MULTILINKPPP */

#endif /* QNX ppp resmgr */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/ppp_tty.c $ $Rev: 822252 $")
#endif
