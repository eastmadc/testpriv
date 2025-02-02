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



/*	$NetBSD: uipc_socket2.c,v 1.85 2007/08/02 02:42:40 rmind Exp $	*/

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
 *	@(#)uipc_socket2.c	8.2 (Berkeley) 2/14/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uipc_socket2.c,v 1.85 2007/08/02 02:42:40 rmind Exp $");

#include "opt_mbuftrace.h"
#include "opt_sb_max.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#ifndef __QNXNTO__
#include <sys/file.h>
#else
#include <sys/file_bsd.h>
#include "siglock.h"
#endif
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/kauth.h>

#ifdef __QNXNTO__
extern int debug_net_so_fib_verbosity;
#endif

/*
 * Primitive routines for operating on sockets and socket buffers
 */

/* strings for sleep message: */
#ifndef __QNXNTO__
const char	netcon[] = "netcon";
const char	netcls[] = "netcls";
const char	netio[] = "netio";
const char	netlck[] = "netlck";
#else
const char	netcon[] = "Unetcon";
const char	netcls[] = "Unetcls";
const char	netio[] = "Unetio";
const char	netlck[] = "Unetlck";
#endif

u_long	sb_max = SB_MAX;	/* maximum socket buffer size */
static u_long sb_max_adj;	/* adjusted sb_max */

/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_q0 for connections in progress
 * and so_q for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_q0 by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_q, making it available to accept().
 *
 * If a socket is closed with sockets on either
 * so_q0 or so_q, these sockets are dropped.
 *
 * If higher level protocols are implemented in
 * the kernel, the wakeups done here will sometimes
 * cause software-interrupt process scheduling.
 */

void
soisconnecting(struct socket *so)
{

	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
}

void
soisconnected(struct socket *so)
{
	struct socket	*head;

	head = so->so_head;
	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;
	if (head && soqremque(so, 0)) {
		soqinsque(head, so, 1);
		sorwakeup(head);
		wakeup((void *)&head->so_timeo);
	} else {
		wakeup((void *)&so->so_timeo);
#ifndef __QNXNTO__
/* Posix (and NetBSD for that matter) says writable on completion */
		sorwakeup(so);
#endif
		sowwakeup(so);
	}
}

void
soisdisconnecting(struct socket *so)
{

	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= (SS_ISDISCONNECTING|SS_CANTRCVMORE|SS_CANTSENDMORE);
	wakeup((void *)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

void
soisdisconnected(struct socket *so)
{

	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE|SS_ISDISCONNECTED);
	wakeup((void *)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, SS_ISCONFIRMING, or SS_ISCONNECTED.
 */
struct socket *
sonewconn(struct socket *head, int connstatus)
{
	struct socket	*so;
	int		soqueue;

	soqueue = connstatus ? 1 : 0;
	if (head->so_qlen + head->so_q0len > 3 * head->so_qlimit / 2)
		return ((struct socket *)0);
	so = pool_get(&socket_pool, PR_NOWAIT);
	if (so == NULL)
		return (NULL);
	memset((void *)so, 0, sizeof(*so));
	so->so_type = head->so_type;
	so->so_options = head->so_options &~ SO_ACCEPTCONN;
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF;
	so->so_proto = head->so_proto;
	so->so_timeo = head->so_timeo;
	so->so_pgid = head->so_pgid;
	so->so_send = head->so_send;
	so->so_receive = head->so_receive;
#ifdef QNX_MFIB
	so->so_fibnum = head->so_fibnum;
	so->so_fiborigin = SO_FIB_SONEWCONN;
#ifndef NDEBUG
	if (debug_net_so_fib_verbosity > 1) {
		printf("Socket type '%d': so=%10d assigning to fib %4d as new conn from so=%10d\n",
				so->so_fiborigin, (int)so, so->so_fibnum, (int)head);
	}
#endif
#endif
#ifndef __QNXNTO__
	so->so_uidinfo = head->so_uidinfo;
#else

	so->so_uid = *head->so_uidinfo;
	so->so_uidinfo = &so->so_uid;
	so->so_snd.sb_lowat = 1024*16;
#endif
#ifdef MBUFTRACE
	so->so_mowner = head->so_mowner;
	so->so_rcv.sb_mowner = head->so_rcv.sb_mowner;
	so->so_snd.sb_mowner = head->so_snd.sb_mowner;
#endif
	(void) soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat);
	so->so_snd.sb_lowat = head->so_snd.sb_lowat;
	so->so_rcv.sb_lowat = head->so_rcv.sb_lowat;
	so->so_rcv.sb_timeo = head->so_rcv.sb_timeo;
	so->so_snd.sb_timeo = head->so_snd.sb_timeo;
	so->so_rcv.sb_flags |= head->so_rcv.sb_flags & SB_AUTOSIZE;
	so->so_snd.sb_flags |= head->so_snd.sb_flags & SB_AUTOSIZE;
	soqinsque(head, so, soqueue);
	if ((*so->so_proto->pr_usrreq)(so, PRU_ATTACH,
	    (struct mbuf *)0, (struct mbuf *)0, (struct mbuf *)0,
	    (struct lwp *)0)) {
		(void) soqremque(so, soqueue);
		pool_put(&socket_pool, so);
		return (NULL);
	}
	if (connstatus) {
		sorwakeup(head);
		wakeup((void *)&head->so_timeo);
		so->so_state |= connstatus;
	}
	return (so);
}

void
soqinsque(struct socket *head, struct socket *so, int q)
{

#ifdef DIAGNOSTIC
	if (so->so_onq != NULL)
		panic("soqinsque");
#endif

	so->so_head = head;
	if (q == 0) {
		head->so_q0len++;
		so->so_onq = &head->so_q0;
	} else {
		head->so_qlen++;
		so->so_onq = &head->so_q;
	}
	TAILQ_INSERT_TAIL(so->so_onq, so, so_qe);
}

int
soqremque(struct socket *so, int q)
{
	struct socket	*head;

	head = so->so_head;
	if (q == 0) {
		if (so->so_onq != &head->so_q0)
			return (0);
		head->so_q0len--;
	} else {
		if (so->so_onq != &head->so_q)
			return (0);
		head->so_qlen--;
	}
	TAILQ_REMOVE(so->so_onq, so, so_qe);
	so->so_onq = NULL;
	so->so_head = NULL;
	return (1);
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */

void
socantsendmore(struct socket *so)
{

	so->so_state |= SS_CANTSENDMORE;
	sowwakeup(so);
}

void
socantrcvmore(struct socket *so)
{

	so->so_state |= SS_CANTRCVMORE;
	sorwakeup(so);
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */
int
sbwait(struct sockbuf *sb)
{

	sb->sb_flags |= SB_WAIT;
	return (tsleep((void *)&sb->sb_cc,
	    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH, netio,
	    sb->sb_timeo));
}

/*
 * Lock a sockbuf already known to be locked;
 * return any error returned from sleep (EINTR).
 */
int
sb_lock(struct sockbuf *sb)
{
	int	error;

	while (sb->sb_flags & SB_LOCK) {
		sb->sb_flags |= SB_WANT;
		error = tsleep((void *)&sb->sb_flags,
		    (sb->sb_flags & SB_NOINTR) ?  PSOCK : PSOCK|PCATCH,
		    netlck, 0);
		if (error)
			return (error);
	}
	sb->sb_flags |= SB_LOCK;
	return (0);
}

/*
 * Wakeup processes waiting on a socket buffer.
 * Do asynchronous notification via SIGIO
 * if the socket buffer has the SB_ASYNC flag set.
 */
void
sowakeup(struct socket *so, struct sockbuf *sb, int code)
{
	selnotify(&sb->sb_sel, 0);
#ifndef __QNXNTO__
	sb->sb_flags &= ~SB_SEL;
#else
	int trig;
	/*
	 * To avoid changing sowakeup() interface,
	 * we do this magic here.
	 */

	/*
	 * NetBSD procs blocked on select() / poll()
	 * will re-check soreadable() / sowritable()
	 * when they wakeup.  Once we raise the event,
	 * the client is gone so we have to check
	 * beforehand to avoid false wakeups.
	 */
	trig = 0;
	/* SS_ISDISCONNECTING ? */
	if ((so->so_state & (SS_CANTRCVMORE|SS_CANTSENDMORE)) ==
	    ((SS_CANTRCVMORE|SS_CANTSENDMORE))) {
		trig |= _NOTIFY_CONDE_HUP; /* unmaskable */
	}
	if (sb == &so->so_rcv) {
		if (soreadable(so)) {
			trig |= IOFUNC_NOTIFY_INPUT;
			iofunc_notify_trigger(so->so_notify, 1, trig);
			sb->sb_flags &= ~SB_SEL;
		}
	}
	else {
		if (sowritable(so)) {
			trig |= IOFUNC_NOTIFY_OUTPUT;
			iofunc_notify_trigger(so->so_notify, 1, trig);
			sb->sb_flags &= ~SB_SEL;
		}

	}
	if (trig & _NOTIFY_CONDE_HUP) {
		/*
		 * We try to combine the hup with one of the other
		 * events above.  If those succeeded the client
		 * should already be unblocked.
		 */
		iofunc_notify_trigger(so->so_notify, 1, IOFUNC_NOTIFY_HUP);
	}

#endif
	if (sb->sb_flags & SB_WAIT) {
		sb->sb_flags &= ~SB_WAIT;
		wakeup((void *)&sb->sb_cc);
	}
	if (sb->sb_flags & SB_ASYNC) {
		int band;
		if (code == POLL_IN)
			band = POLLIN|POLLRDNORM;
		else
			band = POLLOUT|POLLWRNORM;
#ifndef __QNXNTO__
		fownsignal(so->so_pgid, SIGIO, code, band, so);
#else
		fownsignal(so->so_rcvid, SIGIO, code, band, so);
#endif
	}
	if (sb->sb_flags & SB_UPCALL)
		(*so->so_upcall)(so, so->so_upcallarg, M_DONTWAIT);
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and
 * one for receiving data.  Each buffer contains a queue of mbufs,
 * information about the number of mbufs and amount of data in the
 * queue, and other fields allowing poll() statements and notification
 * on data availability to be implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.
 * Each record is a list of mbufs chained together with the m_next
 * field.  Records are chained together with the m_nextpkt field. The upper
 * level routine soreceive() expects the following conventions to be
 * observed when placing information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's
 *    name, then a record containing that name must be present before
 *    any associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really
 *    just additional data associated with the message), and there are
 *    ``rights'' to be received, then a record containing this data
 *    should be present (mbuf's must be of type MT_CONTROL).
 * 3. If a name or rights record exists, then it must be followed by
 *    a data record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space
 * should be released by calling sbrelease() when the socket is destroyed.
 */

int
sb_max_set(u_long new_sbmax)
{
	int s;

	if (new_sbmax < (16 * 1024))
		return (EINVAL);

	s = splsoftnet();
	sb_max = new_sbmax;
	sb_max_adj = (u_quad_t)new_sbmax * MCLBYTES / (MSIZE + MCLBYTES);
	splx(s);

	return (0);
}

int
soreserve(struct socket *so, u_long sndcc, u_long rcvcc)
{
	/*
	 * there's at least one application (a configure script of screen)
	 * which expects a fifo is writable even if it has "some" bytes
	 * in its buffer.
	 * so we want to make sure (hiwat - lowat) >= (some bytes).
	 *
	 * PIPE_BUF here is an arbitrary value chosen as (some bytes) above.
	 * we expect it's large enough for such applications.
	 */
	u_long  lowat = MAX(sock_loan_thresh, MCLBYTES);
	u_long  hiwat = lowat + PIPE_BUF;

	if (sndcc < hiwat)
		sndcc = hiwat;
	if (sbreserve(&so->so_snd, sndcc, so) == 0)
		goto bad;
	if (sbreserve(&so->so_rcv, rcvcc, so) == 0)
		goto bad2;
	if (so->so_rcv.sb_lowat == 0)
		so->so_rcv.sb_lowat = 1;
	if (so->so_snd.sb_lowat == 0)
		so->so_snd.sb_lowat = lowat;
	if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat)
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
	return (0);
 bad2:
	sbrelease(&so->so_snd, so);
 bad:
	return (ENOBUFS);
}

/*
 * Allot mbufs to a sockbuf.
 * Attempt to scale mbmax so that mbcnt doesn't become limiting
 * if buffering efficiency is near the normal case.
 */
int
sbreserve(struct sockbuf *sb, u_long cc, struct socket *so)
{
#ifndef __QNXNTO__
	struct lwp *l = curlwp; /* XXX */
#else
	struct uidinfo ui;
#endif
	rlim_t maxcc;
	struct uidinfo *uidinfo;

	KDASSERT(sb_max_adj != 0);
	if (cc == 0 || cc > sb_max_adj)
		return (0);
#ifndef __QNXNTO__ /* XXX todo (QNX) */
	if (so) {
		if (l && kauth_cred_geteuid(l->l_cred) == so->so_uidinfo->ui_uid)
			maxcc = l->l_proc->p_rlimit[RLIMIT_SBSIZE].rlim_cur;
		else
			maxcc = RLIM_INFINITY;
		uidinfo = so->so_uidinfo;
	} else {
		uidinfo = uid_find(0);	/* XXX: nothing better */
		maxcc = RLIM_INFINITY;
	}
#else
	if (so) 
		uidinfo = so->so_uidinfo;
	else
		uidinfo = &ui;
	maxcc = RLIM_INFINITY;
#endif
	if (!chgsbsize(uidinfo, &sb->sb_hiwat, cc, maxcc))
		return 0;
	sb->sb_mbmax = min(cc * 2, sb_max);
	if (sb->sb_lowat > sb->sb_hiwat)
		sb->sb_lowat = sb->sb_hiwat;
	return (1);
}

/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
void
sbrelease(struct sockbuf *sb, struct socket *so)
{

	sbflush(sb);
	(void)chgsbsize(so->so_uidinfo, &sb->sb_hiwat, 0,
	    RLIM_INFINITY);
	sb->sb_mbmax = 0;
}

/*
 * Routines to add and remove
 * data from an mbuf queue.
 *
 * The routines sbappend() or sbappendrecord() are normally called to
 * append new mbufs to a socket buffer, after checking that adequate
 * space is available, comparing the function sbspace() with the amount
 * of data to be added.  sbappendrecord() differs from sbappend() in
 * that data supplied is treated as the beginning of a new record.
 * To place a sender's address, optional access rights, and data in a
 * socket receive buffer, sbappendaddr() should be used.  To place
 * access rights and data in a socket receive buffer, sbappendrights()
 * should be used.  In either case, the new data begins a new record.
 * Note that unlike sbappend() and sbappendrecord(), these routines check
 * for the caller that there will be enough space to store the data.
 * Each fails if there is not enough space, or if it cannot find mbufs
 * to store additional information in.
 *
 * Reliable protocols may use the socket send buffer to hold data
 * awaiting acknowledgement.  Data is normally copied from a socket
 * send buffer in a protocol with m_copy for output to a peer,
 * and then removing the data from the socket buffer with sbdrop()
 * or sbdroprecord() when the data is acknowledged by the peer.
 */

#ifdef SOCKBUF_DEBUG
void
sblastrecordchk(struct sockbuf *sb, const char *where)
{
	struct mbuf *m = sb->sb_mb;

	while (m && m->m_nextpkt)
		m = m->m_nextpkt;

	if (m != sb->sb_lastrecord) {
		printf("sblastrecordchk: sb_mb %p sb_lastrecord %p last %p\n",
		    sb->sb_mb, sb->sb_lastrecord, m);
		printf("packet chain:\n");
		for (m = sb->sb_mb; m != NULL; m = m->m_nextpkt)
			printf("\t%p\n", m);
		panic("sblastrecordchk from %s", where);
	}
}

void
sblastmbufchk(struct sockbuf *sb, const char *where)
{
	struct mbuf *m = sb->sb_mb;
	struct mbuf *n;

	while (m && m->m_nextpkt)
		m = m->m_nextpkt;

	while (m && m->m_next)
		m = m->m_next;

	if (m != sb->sb_mbtail) {
		printf("sblastmbufchk: sb_mb %p sb_mbtail %p last %p\n",
		    sb->sb_mb, sb->sb_mbtail, m);
		printf("packet tree:\n");
		for (m = sb->sb_mb; m != NULL; m = m->m_nextpkt) {
			printf("\t");
			for (n = m; n != NULL; n = n->m_next)
				printf("%p ", n);
			printf("\n");
		}
		panic("sblastmbufchk from %s", where);
	}
}
#endif /* SOCKBUF_DEBUG */

/*
 * Link a chain of records onto a socket buffer
 */
#define	SBLINKRECORDCHAIN(sb, m0, mlast)				\
do {									\
	if ((sb)->sb_lastrecord != NULL)				\
		(sb)->sb_lastrecord->m_nextpkt = (m0);			\
	else								\
		(sb)->sb_mb = (m0);					\
	(sb)->sb_lastrecord = (mlast);					\
} while (/*CONSTCOND*/0)


#define	SBLINKRECORD(sb, m0)						\
    SBLINKRECORDCHAIN(sb, m0, m0)

/*
 * Append mbuf chain m to the last record in the
 * socket buffer sb.  The additional space associated
 * the mbuf chain is recorded in sb.  Empty mbufs are
 * discarded and mbufs are compacted where possible.
 */
void
sbappend(struct sockbuf *sb, struct mbuf *m)
{
	struct mbuf	*n;

	if (m == 0)
		return;

#ifdef MBUFTRACE
	m_claimm(m, sb->sb_mowner);
#endif

	SBLASTRECORDCHK(sb, "sbappend 1");

	if ((n = sb->sb_lastrecord) != NULL) {
		/*
		 * XXX Would like to simply use sb_mbtail here, but
		 * XXX I need to verify that I won't miss an EOR that
		 * XXX way.
		 */
		do {
			if (n->m_flags & M_EOR) {
				sbappendrecord(sb, m); /* XXXXXX!!!! */
				return;
			}
		} while (n->m_next && (n = n->m_next));
	} else {
		/*
		 * If this is the first record in the socket buffer, it's
		 * also the last record.
		 */
		sb->sb_lastrecord = m;
	}
	sbcompress(sb, m, n);
	SBLASTRECORDCHK(sb, "sbappend 2");
}

/*
 * This version of sbappend() should only be used when the caller
 * absolutely knows that there will never be more than one record
 * in the socket buffer, that is, a stream protocol (such as TCP).
 */
void
sbappendstream(struct sockbuf *sb, struct mbuf *m)
{

	KDASSERT(m->m_nextpkt == NULL);
	KASSERT(sb->sb_mb == sb->sb_lastrecord);

	SBLASTMBUFCHK(sb, __func__);

#ifdef MBUFTRACE
	m_claimm(m, sb->sb_mowner);
#endif

	sbcompress(sb, m, sb->sb_mbtail);

	sb->sb_lastrecord = sb->sb_mb;
	SBLASTRECORDCHK(sb, __func__);
}

#ifdef SOCKBUF_DEBUG
void
sbcheck(struct sockbuf *sb)
{
	struct mbuf	*m;
	u_long		len, mbcnt;

	len = 0;
	mbcnt = 0;
	for (m = sb->sb_mb; m; m = m->m_next) {
		len += m->m_len;
		mbcnt += MSIZE;
		if (m->m_flags & M_EXT)
			mbcnt += m->m_ext.ext_size;
		if (m->m_nextpkt)
			panic("sbcheck nextpkt");
	}
	if (len != sb->sb_cc || mbcnt != sb->sb_mbcnt) {
		printf("cc %lu != %lu || mbcnt %lu != %lu\n", len, sb->sb_cc,
		    mbcnt, sb->sb_mbcnt);
		panic("sbcheck");
	}
}
#endif

/*
 * As above, except the mbuf chain
 * begins a new record.
 */
void
sbappendrecord(struct sockbuf *sb, struct mbuf *m0)
{
	struct mbuf	*m;

	if (m0 == 0)
		return;

#ifdef MBUFTRACE
	m_claimm(m0, sb->sb_mowner);
#endif
	/*
	 * Put the first mbuf on the queue.
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	SBLASTRECORDCHK(sb, "sbappendrecord 1");
	SBLINKRECORD(sb, m0);
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
	SBLASTRECORDCHK(sb, "sbappendrecord 2");
}

/*
 * As above except that OOB data
 * is inserted at the beginning of the sockbuf,
 * but after any other OOB data.
 */
void
sbinsertoob(struct sockbuf *sb, struct mbuf *m0)
{
	struct mbuf	*m, **mp;

	if (m0 == 0)
		return;

	SBLASTRECORDCHK(sb, "sbinsertoob 1");

	for (mp = &sb->sb_mb; (m = *mp) != NULL; mp = &((*mp)->m_nextpkt)) {
	    again:
		switch (m->m_type) {

		case MT_OOBDATA:
			continue;		/* WANT next train */

		case MT_CONTROL:
			if ((m = m->m_next) != NULL)
				goto again;	/* inspect THIS train further */
		}
		break;
	}
	/*
	 * Put the first mbuf on the queue.
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	m0->m_nextpkt = *mp;
	if (*mp == NULL) {
		/* m0 is actually the new tail */
		sb->sb_lastrecord = m0;
	}
	*mp = m0;
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
	SBLASTRECORDCHK(sb, "sbinsertoob 2");
}

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
int
sbappendaddr(struct sockbuf *sb, const struct sockaddr *asa, struct mbuf *m0,
	struct mbuf *control)
{
	struct mbuf	*m, *n, *nlast;
	int		space, len;

	space = asa->sa_len;

	if (m0 != NULL) {
		if ((m0->m_flags & M_PKTHDR) == 0)
			panic("sbappendaddr");
		space += m0->m_pkthdr.len;
#ifdef MBUFTRACE
		m_claimm(m0, sb->sb_mowner);
#endif
	}
	for (n = control; n; n = n->m_next) {
		space += n->m_len;
		MCLAIM(n, sb->sb_mowner);
		if (n->m_next == 0)	/* keep pointer to last control buf */
			break;
	}
	if (space > sbspace(sb))
		return (0);
	MGET(m, M_DONTWAIT, MT_SONAME);
	if (m == 0)
		return (0);
	MCLAIM(m, sb->sb_mowner);
	/*
	 * XXX avoid 'comparison always true' warning which isn't easily
	 * avoided.
	 */
	len = asa->sa_len;
	if (len > MLEN) {
		MEXTMALLOC(m, asa->sa_len, M_NOWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (0);
		}
	}
	m->m_len = asa->sa_len;
	memcpy(mtod(m, void *), asa, asa->sa_len);
	if (n)
		n->m_next = m0;		/* concatenate data to control */
	else
		control = m0;
	m->m_next = control;

	SBLASTRECORDCHK(sb, "sbappendaddr 1");

	for (n = m; n->m_next != NULL; n = n->m_next)
		sballoc(sb, n);
	sballoc(sb, n);
	nlast = n;
	SBLINKRECORD(sb, m);

	sb->sb_mbtail = nlast;
	SBLASTMBUFCHK(sb, "sbappendaddr");

	SBLASTRECORDCHK(sb, "sbappendaddr 2");

	return (1);
}

/*
 * Helper for sbappendchainaddr: prepend a struct sockaddr* to
 * an mbuf chain.
 */
static inline struct mbuf *
m_prepend_sockaddr(struct sockbuf *sb, struct mbuf *m0,
		   const struct sockaddr *asa)
{
	struct mbuf *m;
	const int salen = asa->sa_len;

	/* only the first in each chain need be a pkthdr */
	MGETHDR(m, M_DONTWAIT, MT_SONAME);
	if (m == 0)
		return (0);
	MCLAIM(m, sb->sb_mowner);
#ifdef notyet
	if (salen > MHLEN) {
		MEXTMALLOC(m, salen, M_NOWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (0);
		}
	}
#else
	KASSERT(salen <= MHLEN);
#endif
	m->m_len = salen;
	memcpy(mtod(m, void *), asa, salen);
	m->m_next = m0;
	m->m_pkthdr.len = salen + m0->m_pkthdr.len;

	return m;
}

int
sbappendaddrchain(struct sockbuf *sb, const struct sockaddr *asa,
		  struct mbuf *m0, int sbprio)
{
	int space;
	struct mbuf *m, *n, *n0, *nlast;
	int error;

	/*
	 * XXX sbprio reserved for encoding priority of this* request:
	 *  SB_PRIO_NONE --> honour normal sb limits
	 *  SB_PRIO_ONESHOT_OVERFLOW --> if socket has any space,
	 *	take whole chain. Intended for large requests
	 *      that should be delivered atomically (all, or none).
	 * SB_PRIO_OVERDRAFT -- allow a small (2*MLEN) overflow
	 *       over normal socket limits, for messages indicating
	 *       buffer overflow in earlier normal/lower-priority messages
	 * SB_PRIO_BESTEFFORT -->  ignore limits entirely.
	 *       Intended for  kernel-generated messages only.
	 *        Up to generator to avoid total mbuf resource exhaustion.
	 */
	(void)sbprio;

	if (m0 && (m0->m_flags & M_PKTHDR) == 0)
		panic("sbappendaddrchain");

	space = sbspace(sb);

#ifdef notyet
	/*
	 * Enforce SB_PRIO_* limits as described above.
	 */
#endif

	n0 = NULL;
	nlast = NULL;
	for (m = m0; m; m = m->m_nextpkt) {
		struct mbuf *np;

#ifdef MBUFTRACE
		m_claimm(m, sb->sb_mowner);
#endif

		/* Prepend sockaddr to this record (m) of input chain m0 */
	  	n = m_prepend_sockaddr(sb, m, asa);
		if (n == NULL) {
			error = ENOBUFS;
			goto bad;
		}

		/* Append record (asa+m) to end of new chain n0 */
		if (n0 == NULL) {
			n0 = n;
		} else {
			nlast->m_nextpkt = n;
		}
		/* Keep track of last record on new chain */
		nlast = n;

		for (np = n; np; np = np->m_next)
			sballoc(sb, np);
	}

	SBLASTRECORDCHK(sb, "sbappendaddrchain 1");

	/* Drop the entire chain of (asa+m) records onto the socket */
	SBLINKRECORDCHAIN(sb, n0, nlast);

	SBLASTRECORDCHK(sb, "sbappendaddrchain 2");

	for (m = nlast; m->m_next; m = m->m_next)
		;
	sb->sb_mbtail = m;
	SBLASTMBUFCHK(sb, "sbappendaddrchain");

	return (1);

bad:
	/*
	 * On error, free the prepended addreseses. For consistency
	 * with sbappendaddr(), leave it to our caller to free
	 * the input record chain passed to us as m0.
	 */
	while ((n = n0) != NULL) {
	  	struct mbuf *np;

		/* Undo the sballoc() of this record */
		for (np = n; np; np = np->m_next)
			sbfree(sb, np);

		n0 = n->m_nextpkt;	/* iterate at next prepended address */
		MFREE(n, np);		/* free prepended address (not data) */
	}
	return 0;
}


int
sbappendcontrol(struct sockbuf *sb, struct mbuf *m0, struct mbuf *control)
{
	struct mbuf	*m, *mlast, *n;
	int		space;

	space = 0;
	if (control == 0)
		panic("sbappendcontrol");
	for (m = control; ; m = m->m_next) {
		space += m->m_len;
		MCLAIM(m, sb->sb_mowner);
		if (m->m_next == 0)
			break;
	}
	n = m;			/* save pointer to last control buffer */
	for (m = m0; m; m = m->m_next) {
		MCLAIM(m, sb->sb_mowner);
		space += m->m_len;
	}
	if (space > sbspace(sb))
		return (0);
	n->m_next = m0;			/* concatenate data to control */

	SBLASTRECORDCHK(sb, "sbappendcontrol 1");

	for (m = control; m->m_next != NULL; m = m->m_next)
		sballoc(sb, m);
	sballoc(sb, m);
	mlast = m;
	SBLINKRECORD(sb, control);

	sb->sb_mbtail = mlast;
	SBLASTMBUFCHK(sb, "sbappendcontrol");

	SBLASTRECORDCHK(sb, "sbappendcontrol 2");

	return (1);
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
void
sbcompress(struct sockbuf *sb, struct mbuf *m, struct mbuf *n)
{
	int		eor;
	struct mbuf	*o;

	eor = 0;
	while (m) {
		eor |= m->m_flags & M_EOR;
		if (m->m_len == 0 &&
		    (eor == 0 ||
		     (((o = m->m_next) || (o = n)) &&
		      o->m_type == m->m_type))) {
			if (sb->sb_lastrecord == m)
				sb->sb_lastrecord = m->m_next;
			m = m_free(m);
			continue;
		}
		if (n && (n->m_flags & M_EOR) == 0 &&
		    /* M_TRAILINGSPACE() checks buffer writeability */
		    m->m_len <= MCLBYTES / 4 && /* XXX Don't copy too much */
		    m->m_len <= M_TRAILINGSPACE(n) &&
		    n->m_type == m->m_type) {
			memcpy(mtod(n, char *) + n->m_len, mtod(m, void *),
			    (unsigned)m->m_len);
			n->m_len += m->m_len;
			sb->sb_cc += m->m_len;
			m = m_free(m);
			continue;
		}
		if (n)
			n->m_next = m;
		else
			sb->sb_mb = m;
		sb->sb_mbtail = m;
		sballoc(sb, m);
		n = m;
		m->m_flags &= ~M_EOR;
		m = m->m_next;
		n->m_next = 0;
	}
	if (eor) {
		if (n)
			n->m_flags |= eor;
		else
			printf("semi-panic: sbcompress\n");
	}
	SBLASTMBUFCHK(sb, __func__);
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
void
sbflush(struct sockbuf *sb)
{

	KASSERT((sb->sb_flags & SB_LOCK) == 0);

	while (sb->sb_mbcnt)
		sbdrop(sb, (int)sb->sb_cc);

	KASSERT(sb->sb_cc == 0);
	KASSERT(sb->sb_mb == NULL);
	KASSERT(sb->sb_mbtail == NULL);
	KASSERT(sb->sb_lastrecord == NULL);
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop(struct sockbuf *sb, int len)
{
	struct mbuf	*m, *mn, *next;

	next = (m = sb->sb_mb) ? m->m_nextpkt : 0;
	while (len > 0) {
		if (m == 0) {
			if (next == 0)
				panic("sbdrop");
			m = next;
			next = m->m_nextpkt;
			continue;
		}
		if (m->m_len > len) {
			m->m_len -= len;
			m->m_data += len;
			sb->sb_cc -= len;
			break;
		}
		len -= m->m_len;
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	while (m && m->m_len == 0) {
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	if (m) {
		sb->sb_mb = m;
		m->m_nextpkt = next;
	} else
		sb->sb_mb = next;
	/*
	 * First part is an inline SB_EMPTY_FIXUP().  Second part
	 * makes sure sb_lastrecord is up-to-date if we dropped
	 * part of the last record.
	 */
	m = sb->sb_mb;
	if (m == NULL) {
		sb->sb_mbtail = NULL;
		sb->sb_lastrecord = NULL;
	} else if (m->m_nextpkt == NULL)
		sb->sb_lastrecord = m;
}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
void
sbdroprecord(struct sockbuf *sb)
{
	struct mbuf	*m, *mn;

	m = sb->sb_mb;
	if (m) {
		sb->sb_mb = m->m_nextpkt;
		do {
			sbfree(sb, m);
			MFREE(m, mn);
		} while ((m = mn) != NULL);
	}
	SB_EMPTY_FIXUP(sb);
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation on a socket buffer.
 */
struct mbuf *
sbcreatecontrol(void *p, int size, int type, int level)
{
	struct cmsghdr	*cp;
	struct mbuf	*m;

	if (CMSG_SPACE(size) > MCLBYTES) {
		printf("sbcreatecontrol: message too large %d\n", size);
		return NULL;
	}

	if ((m = m_get(M_DONTWAIT, MT_CONTROL)) == NULL)
		return ((struct mbuf *) NULL);
	if (CMSG_SPACE(size) > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return NULL;
		}
	}
	cp = mtod(m, struct cmsghdr *);
	memcpy(CMSG_DATA(cp), p, size);
	m->m_len = CMSG_SPACE(size);
	cp->cmsg_len = CMSG_LEN(size);
	cp->cmsg_level = level;
	cp->cmsg_type = type;
	return (m);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/uipc_socket2.c $ $Rev: 853157 $")
#endif
