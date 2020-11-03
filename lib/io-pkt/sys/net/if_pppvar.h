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

/*	$NetBSD: if_pppvar.h,v 1.23 2006/07/23 22:06:12 ad Exp $	*/
/*	Id: if_pppvar.h,v 1.3 1996/07/01 01:04:37 paulus Exp	 */

/*
 * if_pppvar.h - private structures and declarations for PPP.
 *
 * Copyright (c) 1989-2002 Paul Mackerras. All rights reserved.
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
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
 */

#ifndef _NET_IF_PPPVAR_H_
#define _NET_IF_PPPVAR_H_

#include <sys/callout.h>

/*
 * Supported network protocols.  These values are used for
 * indexing sc_npmode.
 */
#define NP_IP	0		/* Internet Protocol */
#define NP_IPV6	1		/* Internet Protocol version 6 */
#define NUM_NP	2		/* Number of NPs. */

#ifdef __QNXNTO__
/* multilink ppp support */
#define QNX_MPRQMAXLEN	128
typedef struct {
	pthread_mutex_t	rqlock;
	struct ifqueue	mpinq;		/* input mp queue */
	uint32_t	seq_next;	/* seq for next */
	uint32_t	seq_min;	/* seq base */
	uint32_t	seq_eframe;	/* possible ending frame */
	uint32_t	tx_seq;		/* tx seq */
	u_char		bets;		/* sc_outm's bets */
} mp_ressq_t;
#endif

/*
 * Structure describing each ppp unit.
 */
struct ppp_softc {
	struct	ifnet sc_if;		/* network-visible interface */
#ifdef __QNXNTO__
	int		qnxsc_punit;		/* pseudo device # */
	void	*qnxsc_ocb;			/* pointer to ocb */
	int		qnxsc_pppfdrd;		/* read fd to serial line manager */
	int		qnxsc_pppfdwr;		/* write fd to serial line manager */
	int		qnxsc_pppfdrd2;
	int		qnxsc_quiesce;
#define	QNXSC_QUIESCE_PENDING	0x1
#define	QNXSC_QUIESCE_DIE	0x2
	pthread_mutex_t	rdthread_mutex;
	pthread_cond_t  rdthread_cond;
	int		qnxsc_slpid;		/* pid of the serial line driver */	
	int		qnxsc_readtid;		/* read thread id */
	char	*qnxsc_rdbuf;		/* raw read buffer used by read thread */
	int		qnxsc_rdbuflen;		/* raw read buffer len */
	int		qnxsc_flags;		/* qnx special flags */

	/* multilink ppp support */
	pthread_rwlock_t  qnxsc_mplock;	/* mutex to protect mp channel */
	struct ppp_softc *qnxsc_mpnxsc;		/* pointer to next in bundle */ 
	struct ppp_softc *qnxsc_mpnxchan;	/* master or next channel to send sth on */
	int        qnxsc_mpmrru;	/* max reconst. receive unit */
	uint32_t   qnxsc_mplastseq;	/* last sequence rcvd on this channel */
	mp_ressq_t *qnxsc_mprq;		/* workplace */	
	struct callout tx_callout;	/* Restart TX if TTY can't keep up */
#endif
	int	sc_unit;		/* XXX unit number */
	u_int	sc_flags;		/* control/status bits; see if_ppp.h */
	void	*sc_devp;		/* pointer to device-dep structure */
	void	(*sc_start)(struct ppp_softc *);	/* start output proc */
	void	(*sc_ctlp)(struct ppp_softc *); /* rcvd control pkt */
	void	(*sc_relinq)(struct ppp_softc *); /* relinquish ifunit */
	struct	callout sc_timo_ch;	/* timeout callout */
	u_int16_t sc_mru;		/* max receive unit */
	pid_t	sc_xfer;		/* used in transferring unit */
	struct	ifqueue sc_rawq;	/* received packets */
	struct	ifqueue sc_inq;		/* queue of input packets for daemon */
	struct	ifqueue sc_fastq;	/* interactive output packet q */
	struct	mbuf *sc_togo;		/* output packet ready to go */
	struct	mbuf *sc_npqueue;	/* output packets not to be sent yet */
	struct	mbuf **sc_npqtail;	/* ptr to last next ptr in npqueue */
	struct	pppstat sc_stats;	/* count of bytes/pkts sent/rcvd */
	enum	NPmode sc_npmode[NUM_NP]; /* what to do with each NP */
	struct	compressor *sc_xcomp;	/* transmit compressor */
	void	*sc_xc_state;		/* transmit compressor state */
	struct	compressor *sc_rcomp;	/* receive decompressor */
	void	*sc_rc_state;		/* receive decompressor state */
	time_t	sc_last_sent;		/* time (secs) last NP pkt sent */
	time_t	sc_last_recv;		/* time (secs) last NP pkt rcvd */
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	void	*sc_si;			/* software interrupt handle */
#endif
#ifdef PPP_FILTER
	/* Filter for packets to pass. */
	struct	bpf_program sc_pass_filt_in;
	struct	bpf_program sc_pass_filt_out;

	/* Filter for "non-idle" packets. */
	struct	bpf_program sc_active_filt_in;
	struct	bpf_program sc_active_filt_out;
#endif /* PPP_FILTER */
#ifdef	VJC
	struct	slcompress *sc_comp; 	/* vjc control buffer */
#endif

	/* Device-dependent part for async lines. */
	ext_accm sc_asyncmap;		/* async control character map */
	u_int32_t sc_rasyncmap;		/* receive async control char map */
	struct	mbuf *sc_outm;		/* mbuf chain currently being output */
	struct	mbuf *sc_m;		/* pointer to input mbuf chain */
	struct	mbuf *sc_mc;		/* pointer to current input mbuf */
	char	*sc_mp;			/* ptr to next char in input mbuf */
	u_int16_t sc_ilen;		/* length of input packet so far */
	u_int16_t sc_fcs;		/* FCS so far (input) */
	u_int16_t sc_outfcs;		/* FCS so far for output packet */
	u_int16_t sc_maxfastq;		/* Maximum number of packets that
					 * can be received back-to-back in
					 * the high priority queue */
	u_int8_t sc_nfastq;		/* Number of packets received
					 * back-to-back in the high priority
					 * queue */
	u_char sc_rawin_start;		/* current char start */
	struct ppp_rawin sc_rawin;	/* chars as received */
	LIST_ENTRY(ppp_softc) sc_iflist;
};
#if defined(__QNXNTO__)
/* multilink ppp support */
#define QNXSC_MPPPLINK		0x00000001	/* this link is to do mppp */
#define QNXSC_MPPP		0x00000002	/* do multilink encapsulation */
#define QNXSC_MPSHORTSEQ	0x00000004	/* use short MP sequence numbers */
#define QNXSC_MPSHORTSEQX	0x00000008	/* trasmit short MP seq numbers */
#define QNXSC_MPMASK		0x0000000F	/* qnx flag mask for MP */
#define QNXSC_MPMAIN		0x00000010
#define QNXSC_MPSLAVE		0x00000020

#define QNXSC_RUNNING		0x00000100
#define QNXSC_DYIED		0x00000200
#define QNXSC_CHN_DESTROY	0x00000400
#define QNXSC_KEEPALIVE		0x00000800
#define QNXSC_TTY_PEER_CLOSE	0x00400000	

#define QNXSC_IFATTACHED	0x01000000	/* if attached */
#endif

#ifdef _KERNEL

struct	ppp_softc *pppalloc(pid_t);
void	pppdealloc(struct ppp_softc *);
int	pppioctl(struct ppp_softc *, u_long, caddr_t, int, struct lwp *);
void	ppp_restart(struct ppp_softc *);
void	ppppktin(struct ppp_softc *, struct mbuf *, int);
struct	mbuf *ppp_dequeue(struct ppp_softc *);
int	pppoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
#ifdef __QNXNTO__
/* pppmgr control */
typedef struct {
	int pathid;
	int punitmax;
	struct stat pppmgrstat;
} pppmgr_ctrl_t;

extern pppmgr_ctrl_t pppmgrctrl;

/* ppp list locker */
extern pthread_rwlock_t ppp_list_mutex;

#ifdef simple_lock
#undef simple_lock
#define simple_lock     pthread_rwlock_wrlock
#endif

#ifdef simple_unlock
#undef simple_unlock
#define simple_unlock   pthread_rwlock_unlock
#endif

#define qnx_simple_rdlock   pthread_rwlock_rdlock

void	qnx_ifattach(struct ppp_softc *); 
void	qnx_ifdetach(struct ppp_softc *);
#endif /* __QNXNTO__ */
#endif /* _KERNEL */

#endif /* !_NET_IF_PPPVAR_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_pppvar.h $ $Rev: 707355 $")
#endif
