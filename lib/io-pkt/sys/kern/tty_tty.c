/*	$NetBSD: tty_tty.c,v 1.31 2006/11/01 10:17:59 yamt Exp $	*/

/*-
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
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
 *	@(#)tty_tty.c	8.2 (Berkeley) 9/23/93
 */

/*
 * Indirect driver for controlling tty.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: tty_tty.c,v 1.31 2006/11/01 10:17:59 yamt Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/kauth.h>

#define cttyvp(p) ((p)->p_flag & P_CONTROLT ? (p)->p_session->s_ttyvp : NULL)

/*ARGSUSED*/
static int
cttyopen(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct vnode *ttyvp = cttyvp(l->l_proc);
	int error;

	if (ttyvp == NULL)
		return (ENXIO);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY);
#ifdef PARANOID
	/*
	 * Since group is tty and mode is 620 on most terminal lines
	 * and since sessions protect terminals from processes outside
	 * your session, this check is probably no longer necessary.
	 * Since it inhibits setuid root programs that later switch
	 * to another user from accessing /dev/tty, we have decided
	 * to delete this test. (mckusick 5/93)
	 */
	error = VOP_ACCESS(ttyvp,
	  (flag&FREAD ? VREAD : 0) | (flag&FWRITE ? VWRITE : 0), l->l_cred, l);
	if (!error)
#endif /* PARANOID */
		error = VOP_OPEN(ttyvp, flag, NOCRED, l);
	VOP_UNLOCK(ttyvp, 0);
	return (error);
}

/*ARGSUSED*/
static int
cttyread(dev_t dev, struct uio *uio, int flag)
{
	struct vnode *ttyvp = cttyvp(curproc);
	int error;

	if (ttyvp == NULL)
		return (EIO);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_READ(ttyvp, uio, flag, NOCRED);
	VOP_UNLOCK(ttyvp, 0);
	return (error);
}

/*ARGSUSED*/
static int
cttywrite(dev_t dev, struct uio *uio, int flag)
{
	struct vnode *ttyvp = cttyvp(curproc);
	struct mount *mp;
	int error;

	if (ttyvp == NULL)
		return (EIO);
	mp = NULL;
	if (ttyvp->v_type != VCHR &&
	    (error = vn_start_write(ttyvp, &mp, V_WAIT | V_PCATCH)) != 0)
		return (error);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_WRITE(ttyvp, uio, flag, NOCRED);
	VOP_UNLOCK(ttyvp, 0);
	vn_finished_write(mp, 0);
	return (error);
}

/*ARGSUSED*/
static int
cttyioctl(dev_t dev, u_long cmd, caddr_t addr, int flag, struct lwp *l)
{
	struct vnode *ttyvp = cttyvp(l->l_proc);

	if (ttyvp == NULL)
		return (EIO);
	if (cmd == TIOCSCTTY)		/* XXX */
		return (EINVAL);
	if (cmd == TIOCNOTTY) {
		if (!SESS_LEADER(l->l_proc)) {
			l->l_proc->p_flag &= ~P_CONTROLT;
			return (0);
		} else
			return (EINVAL);
	}
	return (VOP_IOCTL(ttyvp, cmd, addr, flag, NOCRED, l));
}

/*ARGSUSED*/
static int
cttypoll(dev_t dev, int events, struct lwp *l)
{
	struct vnode *ttyvp = cttyvp(l->l_proc);

	if (ttyvp == NULL)
		return (seltrue(dev, events, l));
	return (VOP_POLL(ttyvp, events, l));
}

static int
cttykqfilter(dev_t dev, struct knote *kn)
{
	/* This is called from filt_fileattach() by the attaching process. */
	struct proc *p = curproc;
	struct vnode *ttyvp = cttyvp(p);

	if (ttyvp == NULL)
		return (1);
	return (VOP_KQFILTER(ttyvp, kn));
}

const struct cdevsw ctty_cdevsw = {
	cttyopen, nullclose, cttyread, cttywrite, cttyioctl,
	nullstop, notty, cttypoll, nommap, cttykqfilter, D_TTY
};

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/tty_tty.c $ $Rev: 680336 $")
#endif
