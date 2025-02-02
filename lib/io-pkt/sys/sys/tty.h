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

/*	$NetBSD: tty.h,v 1.71 2006/06/03 18:18:26 christos Exp $	*/

/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)tty.h	8.7 (Berkeley) 1/9/95
 */

#ifndef _SYS_TTY_H_
#define _SYS_TTY_H_
#ifndef __QNXNTO__

#include <sys/termios.h>
#else
#include <sys/event.h>
#include <termios.h>
#endif
#include <sys/select.h>
#include <sys/selinfo.h>	/* For struct selinfo. */
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/callout.h>

#ifdef __QNXNTO__
#include <sys/ioctl.h> 
#include <sys/ttycom.h>
#endif

/*
 * Clists are actually ring buffers. The c_cc, c_cf, c_cl fields have
 * exactly the same behaviour as in true clists.
 * if c_cq is NULL, the ring buffer has no TTY_QUOTE functionality
 * (but, saves memory and CPU time)
 *
 * *DON'T* play with c_cs, c_ce, c_cq, or c_cl outside tty_subr.c!!!
 */
struct clist {
	int	c_cc;		/* count of characters in queue */
	int	c_cn;		/* total ring buffer length */
	u_char	*c_cf;		/* points to first character */
	u_char	*c_cl;		/* points to next open character */
	u_char	*c_cs;		/* start of ring buffer */
	u_char	*c_ce;		/* c_ce + c_len */
	u_char	*c_cq;		/* N bits/bytes long, see tty_subr.c */
};

/*
 * Per-tty structure.
 *
 * Should be split in two, into device and tty drivers.
 * Glue could be masks of what to echo and circular buffer
 * (low, high, timeout).
 */
struct tty {
	TAILQ_ENTRY(tty) tty_link;	/* Link in global tty list. */
#ifndef __QNXNTO__
	struct	simplelock t_slock;	/* mutex for all access to this tty */
#endif
	struct	clist t_rawq;		/* Device raw input queue. */
	long	t_rawcc;		/* Raw input queue statistics. */
	struct	clist t_canq;		/* Device canonical queue. */
	long	t_cancc;		/* Canonical queue statistics. */
	struct	clist t_outq;		/* Device output queue. */
	struct	callout t_rstrt_ch;	/* for delayed output start */
	long	t_outcc;		/* Output queue statistics. */
	struct	linesw *t_linesw;	/* Interface to device drivers. */
	dev_t	t_dev;			/* Device. */
	int	t_state;		/* Device and driver (TS*) state. */
	int	t_wopen;		/* Processes waiting for open. */
	int	t_flags;		/* Tty flags. */
	struct	pgrp *t_pgrp;		/* Foreground process group. */
	struct	session *t_session;	/* Enclosing session. */
#ifndef __QNXNTO__
	struct	selinfo t_rsel;		/* Tty read/oob select. */
	struct	selinfo t_wsel;		/* Tty write select. */
#endif
	struct	termios t_termios;	/* Termios state. */
	struct	winsize t_winsize;	/* Window size. */
					/* Start output. */
	void	(*t_oproc)(struct tty *);
					/* Set hardware state. */
	int	(*t_param)(struct tty *, struct termios *);
					/* Set hardware flow control. */
	int	(*t_hwiflow)(struct tty *, int);
	void	*t_sc;			/* XXX: net/if_sl.c:sl_softc. */
	short	t_column;		/* Tty output column. */
	short	t_rocount, t_rocol;	/* Tty. */
	short	t_hiwat;		/* High water mark. */
	short	t_lowat;		/* Low water mark. */
	short	t_gen;			/* Generation number. */
};

#define __TTY_ENABLE_SLOCK
#ifdef __TTY_ENABLE_SLOCK
#define TTY_LOCK(tp) simple_lock(&(tp)->t_slock)
#define TTY_UNLOCK(tp) simple_unlock(&(tp)->t_slock)
#else /* __TTY_ENABLE_SLOCK */
#define TTY_LOCK(tp)	/**/
#define TTY_UNLOCK(tp)	/**/
#endif /* __TTY_ENABLE_SLOCK */

#define	t_cc		t_termios.c_cc
#define	t_cflag		t_termios.c_cflag
#define	t_iflag		t_termios.c_iflag
#define	t_ispeed	t_termios.c_ispeed
#define	t_lflag		t_termios.c_lflag
#define	t_oflag		t_termios.c_oflag
#define	t_ospeed	t_termios.c_ospeed

#define	TTIPRI	25			/* Sleep priority for tty reads. */
#define	TTOPRI	26			/* Sleep priority for tty writes. */

#define	TTMASK	15
#define	OBUFSIZ	100
#define	TTYHOG	1024

#ifdef _KERNEL
#define	TTMAXHIWAT	roundup(2048, CBSIZE)
#define	TTMINHIWAT	roundup(100, CBSIZE)
#define	TTMAXLOWAT	256
#define	TTMINLOWAT	32
#endif /* _KERNEL */

/* These flags are kept in t_state. */
#define	TS_ASLEEP	0x00001		/* Process waiting for tty. */
#define	TS_ASYNC	0x00002		/* Tty in async I/O mode. */
#define	TS_BUSY		0x00004		/* Draining output. */
#define	TS_CARR_ON	0x00008		/* Carrier is present. */
#define	TS_DIALOUT	0x00010		/* Tty used for dialout. */
#define	TS_FLUSH	0x00020		/* Outq has been flushed during DMA. */
#define	TS_ISOPEN	0x00040		/* Open has completed. */
#define	TS_TBLOCK	0x00080		/* Further input blocked. */
#define	TS_TIMEOUT	0x00100		/* Wait for output char processing. */
#define	TS_TTSTOP	0x00200		/* Output paused. */
#define	TS_XCLUDE	0x00400		/* Tty requires exclusivity. */

/* State for intra-line fancy editing work. */
#define	TS_BKSL		0x00800		/* State for lowercase \ work. */
#define	TS_CNTTB	0x01000		/* Counting tab width, ignore FLUSHO. */
#define	TS_ERASE	0x02000		/* Within a \.../ for PRTRUB. */
#define	TS_LNCH		0x04000		/* Next character is literal. */
#define	TS_TYPEN	0x08000		/* Retyping suspended input (PENDIN). */
#define	TS_LOCAL	(TS_BKSL | TS_CNTTB | TS_ERASE | TS_LNCH | TS_TYPEN)

/* Character type information. */
#define	ORDINARY	0
#define	CONTROL		1
#define	BACKSPACE	2
#define	NEWLINE		3
#define	TAB		4
#define	VTAB		5
#define	RETURN		6

struct speedtab {
	int sp_speed;			/* Speed. */
	int sp_code;			/* Code. */
};

/* Modem control commands (driver). */
#define	DMSET		0
#define	DMBIS		1
#define	DMBIC		2
#define	DMGET		3

/* Flags on a character passed to ttyinput. */
#define	TTY_CHARMASK	0x000000ff	/* Character mask */
#define	TTY_QUOTE	0x00000100	/* Character quoted */
#define	TTY_ERRORMASK	0xff000000	/* Error mask */
#define	TTY_FE		0x01000000	/* Framing error or BREAK condition */
#define	TTY_PE		0x02000000	/* Parity error */

/* Is tp controlling terminal for p? */
#define	isctty(p, tp)							\
	((p)->p_session == (tp)->t_session && (p)->p_flag & P_CONTROLT)

/* Is p in background of tp? */
#define	isbackground(p, tp)						\
	(isctty((p), (tp)) && (p)->p_pgrp != (tp)->t_pgrp)

/*
 * ttylist_head is defined here so that user-land has access to it.
 */
TAILQ_HEAD(ttylist_head, tty);		/* the ttylist is a TAILQ */

#ifdef _KERNEL
#include <sys/mallocvar.h>

MALLOC_DECLARE(M_TTYS);

extern	int tty_count;			/* number of ttys in global ttylist */
extern	struct ttychars ttydefaults;

/* Symbolic sleep message strings. */
extern	 const char ttyin[], ttyout[], ttopen[], ttclos[], ttybg[], ttybuf[];

int	 b_to_q(const u_char *, int, struct clist *);
void	 catq(struct clist *, struct clist *);
void	 clist_init(void);
int	 getc(struct clist *);
void	 ndflush(struct clist *, int);
int	 ndqb(struct clist *, int);
u_char	*nextc(struct clist *, u_char *, int *);
int	 putc(int, struct clist *);
int	 q_to_b(struct clist *, u_char *, int);
int	 unputc(struct clist *);

int	 nullmodem(struct tty *, int);
int	 tputchar(int, int, struct tty *);
int	 ttioctl(struct tty *, u_long, caddr_t, int, struct lwp *);
int	 ttread(struct tty *, struct uio *, int);
void	 ttrstrt(void *);
int	 ttpoll(struct tty *, int, struct lwp *);
void	 ttsetwater(struct tty *);
int	 ttspeedtab(int, const struct speedtab *);
int	 ttstart(struct tty *);
void	 ttwakeup(struct tty *);
int	 ttwrite(struct tty *, struct uio *, int);
void	 ttychars(struct tty *);
int	 ttycheckoutq(struct tty *, int);
int	 ttyclose(struct tty *);
void	 ttyflush(struct tty *, int);
void	 ttyinfo(struct tty *, int);
int	 ttyinput(int, struct tty *);
int	 ttylclose(struct tty *, int);
int	 ttylopen(dev_t, struct tty *);
int	 ttykqfilter(dev_t, struct knote *);
int	 ttymodem(struct tty *, int);
int	 ttyopen(struct tty *, int, int);
int	 ttyoutput(int, struct tty *);
void	 ttypend(struct tty *);
void	 ttyretype(struct tty *);
void	 ttyrub(int, struct tty *);
int	 ttysleep(struct tty *, void *, int, const char *, int);
int	 ttywait(struct tty *);
int	 ttywflush(struct tty *);

void	 tty_attach(struct tty *);
void	 tty_detach(struct tty *);
struct tty
	*ttymalloc(void);
void	 ttyfree(struct tty *);
u_char	*firstc(struct clist *, int *);

int	clalloc(struct clist *, int, int);
void	clfree(struct clist *);

#if defined(_KERNEL_OPT)
#include "opt_compat_freebsd.h"
#include "opt_compat_sunos.h"
#include "opt_compat_svr4.h"
#include "opt_compat_43.h"
#include "opt_compat_osf1.h"
#endif

#if defined(COMPAT_43) || defined(COMPAT_SUNOS) || defined(COMPAT_SVR4) || \
    defined(COMPAT_FREEBSD) || defined(COMPAT_OSF1) || defined(LKM)
# define COMPAT_OLDTTY
int 	ttcompat(struct tty *, u_long, caddr_t, int, struct lwp *);
#endif

#endif /* _KERNEL */

#endif /* !_SYS_TTY_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/tty.h $ $Rev: 680336 $")
#endif
