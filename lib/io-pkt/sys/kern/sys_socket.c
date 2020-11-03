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



/*	$NetBSD: sys_socket.c,v 1.49 2006/11/01 10:17:59 yamt Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)sys_socket.c	8.3 (Berkeley) 2/14/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sys_socket.c,v 1.49 2006/11/01 10:17:59 yamt Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#ifndef __QNXNTO__
#include <sys/file.h>
#else
#include <sys/file_bsd.h>
#include "notify.h"
#endif
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/route.h>

#ifdef __QNXNTO__
#include <sys/dcmd_misc.h>
int soo_close1(struct file *, struct lwp *);

#ifndef NDEBUG
extern int debug_net_so_fib_verbosity;
int if_debug_ioctl(u_long pid, u_long cmd, caddr_t data, int error
#ifdef QNX_MFIB
			, int fib
#endif
			);
#endif /* NDEBUG */
#endif

struct	fileops socketops = {
	soo_read, soo_write, soo_ioctl, soo_fcntl, soo_poll,
	soo_stat, soo_close, soo_kqfilter
#ifdef __QNXNTO__
	, soo_close1
#endif
};

/* ARGSUSED */
int
soo_read(struct file *fp, off_t *offset, struct uio *uio, kauth_cred_t cred,
    int flags)
{
	struct socket *so = (struct socket *) fp->f_data;
	return ((*so->so_receive)(so, (struct mbuf **)0,
		uio, (struct mbuf **)0, (struct mbuf **)0, (int *)0));
}

/* ARGSUSED */
int
soo_write(struct file *fp, off_t *offset, struct uio *uio, kauth_cred_t cred,
    int flags)
{
	struct socket *so = (struct socket *) fp->f_data;
	return (*so->so_send)(so, (struct mbuf *)0,
		uio, (struct mbuf *)0, (struct mbuf *)0, 0, curlwp);
}

int
soo_ioctl(struct file *fp, u_long cmd, void *data, struct lwp *l)
{
	struct socket *so = (struct socket *)fp->f_data;
#ifndef __QNXNTO__
	struct proc *p = l->l_proc;
#else
	struct proc *p = LWP_TO_PR(l);
        u_long ecmd = 0;
#endif

#ifdef QNX_MFIB
    if (so->so_fiborigin==SO_FIB_INIT) {
    	so->so_fibnum = kauth_getfib4cred(l->l_cred);
    	so->so_fiborigin = SO_FIB_SOOIOCTL;
#ifndef NDEBUG
    	if (debug_net_so_fib_verbosity > 1) {
    		printf("Socket type '%d': pid=%10d/so=%10d/user=%10d assigning to fib %4d\n",
    				so->so_fiborigin, curproc->p_ctxt.info.pid, (int)so,
    				(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
    	}
#endif
    }
#ifndef NDEBUG
    else {
    	if (debug_net_so_fib_verbosity > 2) {
    		printf("soo_ioctl: fib already set to %4d\n", so->so_fibnum);
    	}
    }
#endif
#endif

	switch (cmd) {

	case FIONBIO:
		if (*(int *)data)
			so->so_state |= SS_NBIO;
		else
			so->so_state &= ~SS_NBIO;
		return (0);

	case FIOASYNC:
		if (*(int *)data) {
			so->so_state |= SS_ASYNC;
			so->so_rcv.sb_flags |= SB_ASYNC;
			so->so_snd.sb_flags |= SB_ASYNC;
		} else {
			so->so_state &= ~SS_ASYNC;
			so->so_rcv.sb_flags &= ~SB_ASYNC;
			so->so_snd.sb_flags &= ~SB_ASYNC;
		}
		return (0);

	case FIONREAD:
		*(int *)data = so->so_rcv.sb_cc;
		return (0);

	case FIONWRITE:
		*(int *)data = so->so_snd.sb_cc;
		return (0);

	case FIONSPACE:
		/*
		 * See the comment around sbspace()'s definition
		 * in sys/socketvar.h in face of counts about maximum
		 * to understand the following test. We detect overflow
		 * and return zero.
		 */
		if ((so->so_snd.sb_hiwat < so->so_snd.sb_cc)
		    || (so->so_snd.sb_mbmax < so->so_snd.sb_mbcnt))
			*(int *)data = 0;
		else
			*(int *)data = sbspace(&so->so_snd);
		return (0);

	case SIOCSPGRP:
	case FIOSETOWN:
	case TIOCSPGRP:
#ifndef __QNXNTO__
		return fsetown(p, &so->so_pgid, cmd, data);
#else
		return fsetown(p, &so->so_pgid, &so->so_rcvid, cmd, data);
#endif

	case SIOCGPGRP:
	case FIOGETOWN:
	case TIOCGPGRP:
		return fgetown(p, so->so_pgid, cmd, data);

	case SIOCATMARK:
		*(int *)data = (so->so_state&SS_RCVATMARK) != 0;
		return (0);
	}
	/*
	 * Interface/routing/protocol specific ioctls:
	 * interface and routing ioctls should have a
	 * different entry since a socket's unnecessary
	 */

#ifdef __QNXNTO__
        /* Figure out the embedded command */
	if (cmd == DCMD_MISC_GETPTREMBED) {
		struct __ioctl_getptrembed *embedmsg = NULL;
		embedmsg = (struct __ioctl_getptrembed *) data;
		ecmd = embedmsg->dcmd;
	}

	if (IOCGROUP(cmd) == 'i' || IOCGROUP(ecmd) == 'i')
#ifndef NDEBUG
		return if_debug_ioctl(curproc->p_ctxt.info.pid, cmd, data, (ifioctl(so, cmd, data, l)), so->so_fibnum);
#else
		return (ifioctl(so, cmd, data, l));
#endif
	if (IOCGROUP(cmd) == 'r' || IOCGROUP(ecmd) == 'r')
		return (rtioctl(cmd, data, l));
#else
	if (IOCGROUP(cmd) == 'i')
		return (ifioctl(so, cmd, data, l));
	if (IOCGROUP(cmd) == 'r')
		return (rtioctl(cmd, data, l));
#endif
	return ((*so->so_proto->pr_usrreq)(so, PRU_CONTROL,
	    (struct mbuf *)cmd, (struct mbuf *)data, (struct mbuf *)0, l));
}

int
soo_fcntl(struct file *fp, u_int cmd, void *data, struct lwp *l)
{
	if (cmd == F_SETFL)
		return (0);
	else
		return (EOPNOTSUPP);
}

#ifndef __QNXNTO__
int
soo_poll(struct file *fp, int events, struct lwp *l)
{
	struct socket *so = (struct socket *)fp->f_data;
	int revents = 0;
	int s = splsoftnet();

	if (events & (POLLIN | POLLRDNORM))
		if (soreadable(so))
			revents |= events & (POLLIN | POLLRDNORM);

	if (events & (POLLOUT | POLLWRNORM))
		if (sowritable(so))
			revents |= events & (POLLOUT | POLLWRNORM);

	if (events & (POLLPRI | POLLRDBAND))
		if (so->so_oobmark || (so->so_state & SS_RCVATMARK))
			revents |= events & (POLLPRI | POLLRDBAND);

	if (revents == 0) {
		if (events & (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)) {
			selrecord(l, &so->so_rcv.sb_sel);
			so->so_rcv.sb_flags |= SB_SEL;
		}

		if (events & (POLLOUT | POLLWRNORM)) {
			selrecord(l, &so->so_snd.sb_sel);
			so->so_snd.sb_flags |= SB_SEL;
		}
	}

	splx(s);
	return (revents);
}
#else /* __QNXNTO__ */
int
soo_poll(struct file *fp, int notused, struct lwp *l)
{
	struct proc		*p;
	struct socket		*so;
	io_notify_t		*msg;
	resmgr_context_t	*ctp;
	unsigned		trig, asked;
	int			ret, action, lim;

	p = LWP_TO_PR(l);
	ctp = &p->p_ctxt;
	msg = &ctp->msg->notify;
	so = (struct socket *)fp->f_data;

	trig = _NOTIFY_COND_EXTEN;
	lim = sizeof(so->so_notify) / sizeof(so->so_notify[0]);
	action = msg->i.action;
	asked = msg->i.flags;

	if (soreadable(so))
		trig |= _NOTIFY_COND_INPUT;

	if (sowritable(so))
		trig |= _NOTIFY_COND_OUTPUT;

	if (so->so_oobmark || (so->so_state & SS_RCVATMARK))
		trig |= _NOTIFY_COND_OBAND;

	if ((so->so_state & (SS_CANTRCVMORE|SS_CANTSENDMORE)) ==
	    ((SS_CANTRCVMORE|SS_CANTSENDMORE))) {
		trig |= _NOTIFY_CONDE_HUP;
	}
	ret = iofunc_notify(ctp, msg, &so->so_notify[0], trig, NULL, &lim);

	/*
	 * Could always set SB_SEL (iofunc_notify_trigger() will
	 * do nothing if no event queued) but seems worthwhile to
	 * shortcut here for the high runner case (select(), poll()
	 * -> POLLARM).
	 */

	switch (action) {
	case _NOTIFY_ACTION_POLLARM:
		asked = asked ^ msg->o.flags;
		/* asked is now those asked for but not satisfied. */
		/* FALLTHROUGH */

	case _NOTIFY_ACTION_TRANARM:
		if (ret == EBUSY)
			break;

		if (asked & _NOTIFY_COND_INPUT)
			so->so_rcv.sb_flags |= SB_SEL;

		if (asked & _NOTIFY_COND_OUTPUT)
			so->so_snd.sb_flags |= SB_SEL;

		break;

	case _NOTIFY_ACTION_POLL: //no event ever queued
		break;

	default:
		so->so_rcv.sb_flags |= SB_SEL;
		so->so_snd.sb_flags |= SB_SEL;
		break;
	}

	return ret;
}

int
soo_close1(struct file *fp, struct lwp *l)
{
	struct socket		*so;
	resmgr_context_t	*ctp;
	struct proc		*p;
	iofunc_notify_t		*nop;
	int			nop_lim;

	p = LWP_TO_PR(l);
	ctp = &p->p_ctxt;
	so = (struct socket *)fp->f_data;

	nop = so->so_notify;
	nop_lim = sizeof(so->so_notify) / sizeof(so->so_notify[0]);
	        

	(*notify_trigger_strictp)(ctp, nop, 1,
	    _NOTIFY_CONDE_HUP | IOFUNC_NOTIFY_INPUT);
	(*notify_trigger_strictp)(ctp, nop, 1,
	    _NOTIFY_CONDE_HUP | IOFUNC_NOTIFY_OUTPUT);
	(*notify_trigger_strictp)(ctp, nop, 1, IOFUNC_NOTIFY_HUP);
	        
	(*notify_remove_strictp)(ctp, nop, nop_lim);
	return 0;
}
#endif /* __QNXNTO__  */

int
soo_stat(struct file *fp, struct stat *ub, struct lwp *l)
{
	struct socket *so = (struct socket *)fp->f_data;

	memset((caddr_t)ub, 0, sizeof(*ub));
	ub->st_mode = S_IFSOCK;
#ifdef __QNXNTO__
	/*
	 * NULL 4th and 5th parameter means historical fstat() request,
	 * not one of our PRSENSEREQ_* requests.
	 */
#endif
	return ((*so->so_proto->pr_usrreq)(so, PRU_SENSE,
	    (struct mbuf *)ub, (struct mbuf *)0, (struct mbuf *)0, l));
}

/* ARGSUSED */
int
soo_close(struct file *fp, struct lwp *l)
{
	int error = 0;

	if (fp->f_data)
		error = soclose((struct socket *)fp->f_data);
	fp->f_data = 0;
	return (error);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/sys_socket.c $ $Rev: 691213 $")
#endif
