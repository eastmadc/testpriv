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


/*	$NetBSD: uipc_syscalls.c,v 1.155 2012/06/22 18:26:35 christos Exp $	*/

/*-
 * Copyright (c) 2008, 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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
 * Copyright (c) 1982, 1986, 1989, 1990, 1993
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
 *	@(#)uipc_syscalls.c	8.6 (Berkeley) 2/14/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uipc_syscalls.c,v 1.155 2012/06/22 18:26:35 christos Exp $");

#ifndef __QNXNTO__
#include "opt_ktrace.h"
#include "opt_pipe.h"
#else
#include "opt_sctp.h"
#include <siglock.h>
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#ifndef __QNXNTO__
#include <sys/file.h>
#else
#include <sys/file_bsd.h>
#include <nw_msg.h>
#endif
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/un.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/event.h>

#include <sys/mount.h>
#ifndef __QNXNTO__
#include <sys/sa.h>
#endif
#include <sys/syscallargs.h>

#ifdef QNX_MFIB
#include <sys/kauth.h>
#endif

#include <uvm/uvm_extern.h>
#ifdef __QNXNTO__
#define IOV_MAX 1024
#ifndef NDEBUG
extern int debug_net_so_fib_verbosity;
#endif
#endif

/*
 * System call interface to the socket abstraction.
 */
extern const struct fileops socketops;

int
sys___socket30(struct lwp *l, void *v, register_t *retval)
{
	struct sys___socket30_args /* {
		syscallarg(int)	domain;
		syscallarg(int)	type;
		syscallarg(int)	protocol;
	} */ *uap = v;

#ifndef __QNXNTO__
	struct filedesc	*fdp;
#endif
	struct socket	*so;
	struct file	*fp;
#ifndef __QNXNTO__
	int		fd, error;
#else
	int		error;
#endif

#ifndef __QNXNTO__
	fdp = l->l_proc->p_fd;
	/* falloc() will use the desciptor for us */
	if ((error = falloc(l, &fp, &fd)) != 0)
		return (error);
#else
	fp = l->l_fp;
	if ((error = falloc(l, &fp)) != 0)
		return (error);

	if ((error = nto_bindit(&LWP_TO_PR(l)->p_ctxt, fp)) != 0)
		goto err;
#endif
	fp->f_flag = FREAD|FWRITE;
	fp->f_type = DTYPE_SOCKET;
	fp->f_ops = &socketops;
	error = socreate(SCARG(uap, domain), &so, SCARG(uap, type),
			 SCARG(uap, protocol), l);
	if (error) {
#ifdef __QNXNTO__
		nto_unbind(&LWP_TO_PR(l)->p_ctxt);
 err:
#endif
		FILE_UNUSE(fp, l);
#ifndef __QNXNTO__
		fdremove(fdp, fd);
#endif
		ffree(fp);
	} else {
		fp->f_data = so;
		FILE_SET_MATURE(fp);
		FILE_UNUSE(fp, l);
#ifndef __QNXNTO__
		*retval = fd;
#else
		*retval = (uintptr_t)fp;
#endif
	}
	return (error);
}

/* ARGSUSED */
int
sys_bind(struct lwp *l, void *v, register_t *retval)
{
	struct sys_bind_args /* {
		syscallarg(int)				s;
		syscallarg(const struct sockaddr *)	name;
		syscallarg(unsigned int)		namelen;
	} */ *uap = v;
	struct mbuf	*nam;
	int		error;

	error = sockargs(&nam, SCARG(uap, name), SCARG(uap, namelen),
	    MT_SONAME);
	if (error)
		return error;

	return do_sys_bind(l, SCARG(uap, s), nam);
}

int
do_sys_bind(struct lwp *l, int s, struct mbuf *nam)
{
	struct file	*fp;
	int		error;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0) {
		m_freem(nam);
		return (error);
	}
	MCLAIM(nam, ((struct socket *)fp->f_data)->so_mowner);
	error = sobind(fp->f_data, nam, l);
	m_freem(nam);
	FILE_UNUSE(fp, l);
	return error;
}

/* ARGSUSED */
int
sys_listen(struct lwp *l, void *v, register_t *retval)
{
	struct sys_listen_args /* {
		syscallarg(int)	s;
		syscallarg(int)	backlog;
	} */ *uap = v;
	struct file	*fp;
	int		error;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, SCARG(uap, s), &fp)) != 0)
		return (error);
	error = solisten(fp->f_data, SCARG(uap, backlog), l);
	FILE_UNUSE(fp, l);
	return error;
}

int
do_sys_accept(struct lwp *l, int sock, struct mbuf **name, register_t *new_sock)
{
#ifndef __QNXNTO__
	struct filedesc	*fdp;
#endif
	struct file	*fp;
	struct mbuf	*nam;
#ifndef __QNXNTO__
	int		error, s, fd;
#else
	int		error, s;
	struct msg_open_info	*org_info;
#endif
	struct socket	*so;
	int		fflag;

#ifndef __QNXNTO__
	fdp = l->l_proc->p_fd;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(fdp, sock, &fp)) != 0)
		return (error);
#else
	if ((error = (getsock)(l, sock, &fp)) != 0)
		return (error);
	org_info = fp->f_path_info;
#endif
	s = splsoftnet();
	so = (struct socket *)fp->f_data;
	FILE_UNUSE(fp, l);
	if (!(so->so_proto->pr_flags & PR_LISTEN)) {
		splx(s);
		return (EOPNOTSUPP);
	}
	if ((so->so_options & SO_ACCEPTCONN) == 0) {
		splx(s);
		return (EINVAL);
	}
	if ((so->so_state & SS_NBIO) && so->so_qlen == 0) {
		splx(s);
		return (EWOULDBLOCK);
	}
	while (so->so_qlen == 0 && so->so_error == 0) {
		if (so->so_state & SS_CANTRCVMORE) {
			so->so_error = ECONNABORTED;
			break;
		}
		error = tsleep(&so->so_timeo, PSOCK | PCATCH,
		    netcon,
#ifndef __QNXNTO__
		    0
#else
		    /*
		     * Follow prior art and honour SO_RCVTIMO on accept.
		     * This also gets inherited across sonewconn().
		     */
		    so->so_rcv.sb_timeo
#endif
		    );
		if (error) {
			splx(s);
#ifdef __QNXNTO__
			if (error == EBADF) {
				/*
				 * This socket was duped and
				 * another client thread closed
				 * it while we were blocked.
				 * Usually SS_CANTRCVMORE would
				 * be set and we would break above
				 * but this doesn't happen until
				 * last close.
				 */
				error = 0;
				so->so_error = ECONNABORTED;
				break;
			}
#endif
			return (error);
		}
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		splx(s);
		return (error);
	}
	fflag = fp->f_flag;
	/* falloc() will use the descriptor for us */
#ifndef __QNXNTO__
	if ((error = falloc(l, &fp, &fd)) != 0) {
		splx(s);
		return (error);
	}
	*new_sock = fd;
#else
	if ((error = falloc(l, &fp)) != 0) {
		splx(s);
		return (error);
	}
	if ((error = nto_bindit(&LWP_TO_PR(l)->p_ctxt, fp)) != 0) {
		ffree(fp);
		splx(s);
		return (error);
	}
	*new_sock = (uintptr_t)fp;
#endif

	/* connection has been removed from the listen queue */
	KNOTE(&so->so_rcv.sb_sel.sel_klist, 0);

	{ struct socket *aso = TAILQ_FIRST(&so->so_q);
	  if (soqremque(aso, 1) == 0)
		panic("accept");
	  so = aso;
	}
	fp->f_type = DTYPE_SOCKET;
	fp->f_flag = fflag;
	fp->f_ops = &socketops;
	fp->f_data = so;
#ifdef __QNXNTO__
	fp->f_path_info = org_info;
#endif
	nam = m_get(M_WAIT, MT_SONAME);
	error = soaccept(so, nam);

	if (error) {
		/* an error occurred, free the file descriptor and mbuf */
		m_freem(nam);
#ifndef __QNXNTO__
		fdremove(fdp, fd);
#else
		nto_unbind(&LWP_TO_PR(l)->p_ctxt);
#endif
		closef(fp, l);
	} else {
		FILE_SET_MATURE(fp);
		FILE_UNUSE(fp, l);
		*name = nam;
	}
	splx(s);
	return (error);
}

int
sys_accept(struct lwp *l, void *v, register_t *retval)
{
	struct sys_accept_args /* {
		syscallarg(int)			s;
		syscallarg(struct sockaddr *)	name;
		syscallarg(unsigned int *)	anamelen;
	} */ *uap = v;
	int error;
	struct mbuf *name;

	error = do_sys_accept(l, SCARG(uap, s), &name, retval);
	if (error != 0)
		return error;

	error = copyout_sockname(SCARG(uap, name), SCARG(uap, anamelen),
	    MSG_LENUSRSPACE, name);
	if (name != NULL)
		m_free(name);
	if (error != 0) {
#ifdef __QNXNTO__
		nto_unbind(&LWP_TO_PR(l)->p_ctxt);
#endif
		fdrelease(l, *retval);
	}
	return error;
}

/* ARGSUSED */
int
sys_connect(struct lwp *l, void *v, register_t *retval)
{
	struct sys_connect_args /* {
		syscallarg(int)				s;
		syscallarg(const struct sockaddr *)	name;
		syscallarg(unsigned int)		namelen;
	} */ *uap = v;
	int		error;
	struct mbuf	*nam;

	error = sockargs(&nam, SCARG(uap, name), SCARG(uap, namelen),
	    MT_SONAME);
	if (error)
		return error;
	return do_sys_connect(l,  SCARG(uap, s), nam);
}

int
do_sys_connect(struct lwp *l, int s, struct mbuf *nam)
{
	struct file	*fp;
	struct socket	*so;
	int		error;
	int		interrupted = 0;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0) {
		m_freem(nam);
		return (error);
	}
	so = fp->f_data;
	MCLAIM(nam, so->so_mowner);
	if (so->so_state & SS_ISCONNECTING) {
		error = EALREADY;
		goto out;
	}
#ifdef QNX_MFIB
	if (so->so_fiborigin==SO_FIB_INIT) {
	    	so->so_fibnum = kauth_getfib4cred(l->l_cred);
	    	so->so_fiborigin = SO_FIB_SYSCONNECT;
#ifndef NDEBUG
	    	if (debug_net_so_fib_verbosity > 1) {
	    		printf("Socket type '%d': pid=%10d/so=%10d/user=%10d assigning to fib %4d\n",
	    				so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid ,(int)so,
	    				(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
	    	}
#endif
	}
#ifndef NDEBUG
	else {
    	if (debug_net_so_fib_verbosity > 2) {
    		printf("sys_connect: fib already set to %4d\n", so->so_fibnum);
    	}
    }
#endif
#endif
	error = soconnect(so, nam, l);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		error = EINPROGRESS;
		goto out;
	}
	s = splsoftnet();
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = tsleep(&so->so_timeo, PSOCK | PCATCH,
			       netcon, 0);
		if (error) {
			if (error == EINTR || error == ERESTART)
				interrupted = 1;
			break;
		}
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
#ifdef __QNXNTO__
	/* eg. socket was closed out from under connect() by another thread. */
	if (error == EBADF)
		error = ECONNABORTED;
#endif
	splx(s);
 bad:
	if (!interrupted)
		so->so_state &= ~SS_ISCONNECTING;
	if (error == ERESTART)
		error = EINTR;
 out:
	FILE_UNUSE(fp, l);
	m_freem(nam);
	return (error);
}

int
sys_socketpair(struct lwp *l, void *v, register_t *retval)
{
	struct sys_socketpair_args /* {
		syscallarg(int)		domain;
		syscallarg(int)		type;
		syscallarg(int)		protocol;
		syscallarg(int *)	rsv;
	} */ *uap = v;
#ifndef __QNXNTO__
	struct filedesc	*fdp;
#endif
	struct file	*fp1, *fp2;
	struct socket	*so1, *so2;
#ifndef __QNXNTO__
	int		fd, error, sv[2];
#else
	int		error;
	struct file	**sv;
#endif

#ifdef __QNXNTO__	
	sv = SCARG(uap, rsv);
	fp1 = sv[0];
	FILE_USE(fp1);

	fp2 = sv[1];
	FILE_USE(fp2);
	
	so1 = (struct socket *)fp1->f_data;
	
	so2 = (struct socket *)fp2->f_data;
	
	if ((error = soconnect2(so1, so2)) != 0)
		goto bad;
	if (SCARG(uap, type) == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		error = soconnect2(so2, so1);
	}
 bad:		
	FILE_UNUSE(fp2, l);
	FILE_UNUSE(fp1, l);
	return (error);
	
#else
	fdp = l->l_proc->p_fd;
	error = socreate(SCARG(uap, domain), &so1, SCARG(uap, type),
	    SCARG(uap, protocol), l);
	if (error)
		return (error);
	error = socreate(SCARG(uap, domain), &so2, SCARG(uap, type),
	    SCARG(uap, protocol), l);
	if (error)
		goto free1;
	/* falloc() will use the descriptor for us */
	if ((error = falloc(l, &fp1, &fd)) != 0)
		goto free2;
	sv[0] = fd;
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_type = DTYPE_SOCKET;
	fp1->f_ops = &socketops;
	fp1->f_data = so1;
	if ((error = falloc(l, &fp2, &fd)) != 0)
		goto free3;
	fp2->f_flag = FREAD|FWRITE;
	fp2->f_type = DTYPE_SOCKET;
	fp2->f_ops = &socketops;
	fp2->f_data = so2;
	sv[1] = fd;
	if ((error = soconnect2(so1, so2)) != 0)
		goto free4;
	if (SCARG(uap, type) == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		 if ((error = soconnect2(so2, so1)) != 0)
			goto free4;
	}
	error = copyout(sv, SCARG(uap, rsv), 2 * sizeof(int));
	FILE_SET_MATURE(fp1);
	FILE_SET_MATURE(fp2);
	FILE_UNUSE(fp1, l);
	FILE_UNUSE(fp2, l);
	return (error);
 free4:
	FILE_UNUSE(fp2, l);
	ffree(fp2);
	fdremove(fdp, sv[1]);
 free3:
	FILE_UNUSE(fp1, l);
	ffree(fp1);
	fdremove(fdp, sv[0]);
 free2:
	(void)soclose(so2);
 free1:
	(void)soclose(so1);
	return (error);
#endif
}

int
sys_sendto(struct lwp *l, void *v, register_t *retval)
{
	struct sys_sendto_args /* {
		syscallarg(int)				s;
		syscallarg(const void *)		buf;
		syscallarg(size_t)			len;
		syscallarg(int)				flags;
		syscallarg(const struct sockaddr *)	to;
		syscallarg(unsigned int)		tolen;
	} */ *uap = v;
	struct msghdr	msg;
	struct iovec	aiov;

	msg.msg_name = __UNCONST(SCARG(uap, to)); /* XXXUNCONST kills const */
	msg.msg_namelen = SCARG(uap, tolen);
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_flags = 0;
	aiov.iov_base = __UNCONST(SCARG(uap, buf)); /* XXXUNCONST kills const */
	aiov.iov_len = SCARG(uap, len);
	return do_sys_sendmsg(l, SCARG(uap, s), &msg, SCARG(uap, flags), retval);
}

int
sys_sendmsg(struct lwp *l, void *v, register_t *retval)
{
	struct sys_sendmsg_args /* {
		syscallarg(int)				s;
		syscallarg(const struct msghdr *)	msg;
		syscallarg(int)				flags;
	} */ *uap = v;
#ifndef __QNXNTO__
	struct msghdr	msg;
	int		error;

	error = copyin(SCARG(uap, msg), &msg, sizeof(msg));
	if (error)
		return (error);

	msg.msg_flags = MSG_IOVUSRSPACE;
	return do_sys_sendmsg(l, SCARG(uap, s), &msg, SCARG(uap, flags), retval);
#else
	/*
	 * mh and mh->iov both point to area allocated on caller's
	 * stack so we don't need to copyin either of them.
	 * If we were to do so we'd need the VM_NOCTXT flag.
	 *
	 * Caller has set mh->msg_flags = 0.
	 */
	return do_sys_sendmsg(l, SCARG(uap, s), SCARG(uap, msg),
	    SCARG(uap, flags), retval);
#endif
}

static int
do_sys_sendmsg_so(struct lwp *l, int s, struct socket *so, file_t *fp,
    struct msghdr *mp, int flags, register_t *retsize)
{

	struct iovec	*tiov;
#ifndef __QNXNTO__
	struct iovec	aiov[UIO_SMALLIOV], *iov = aiov;
#endif
	struct mbuf	*to, *control;
	struct uio	auio;
	size_t		len, iovsz;
	int		i, error;
#ifdef KTRACE
	struct iovec	*ktriov = NULL;
	int iovlen;

	ktrkuser("msghdr", mp, sizeof *mp);
#endif

	/* If the caller passed us stuff in mbufs, we must free them. */
	to = (mp->msg_flags & MSG_NAMEMBUF) ? mp->msg_name : NULL;
	control = (mp->msg_flags & MSG_CONTROLMBUF) ? mp->msg_control : NULL;
	iovsz = mp->msg_iovlen * sizeof(struct iovec);

#ifndef __QNXNTO__ /* MSG_IOVUSRSPACE never used */
	if (mp->msg_flags & MSG_IOVUSRSPACE) {
		if ((unsigned int)mp->msg_iovlen > UIO_SMALLIOV) {
			if ((unsigned int)mp->msg_iovlen > IOV_MAX) {
				error = EMSGSIZE;
				goto bad;
			}
			iov = malloc(iovsz, M_IOV, M_WAITOK);
		}
		if (mp->msg_iovlen != 0) {
			error = copyin(mp->msg_iov, iov, iovsz);
			if (error)
				goto bad;
		}
		mp->msg_iov = iov;
	}
#endif

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_rw = UIO_WRITE;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	KASSERT(l == curlwp);
	auio.uio_vmspace = &LWP_TO_PR(l)->p_vmspace;

	for (i = 0, tiov = mp->msg_iov; i < mp->msg_iovlen; i++, tiov++) {
		/*
		 * Writes return ssize_t because -1 is returned on error.
		 * Therefore, we must restrict the length to SSIZE_MAX to
		 * avoid garbage return values.
		 */
		auio.uio_resid += tiov->iov_len;
		if (tiov->iov_len > SSIZE_MAX || auio.uio_resid > SSIZE_MAX) {
			error = EINVAL;
			goto bad;
		}
	}

	if (mp->msg_name && to == NULL) {
		error = sockargs(&to, mp->msg_name, mp->msg_namelen,
		    MT_SONAME);
		if (error)
			goto bad;
	}

	if (mp->msg_control) {
		if (mp->msg_controllen < CMSG_ALIGN(sizeof(struct cmsghdr))) {
			error = EINVAL;
			goto bad;
		}
		if (control == NULL) {
			error = sockargs(&control, mp->msg_control,
			    mp->msg_controllen, MT_CONTROL);
			if (error)
				goto bad;
		}
	}

#ifdef KTRACE
	if (ktrpoint(KTR_GENIO)) {
		ktriov = malloc(iovsz, M_TEMP, M_WAITOK);
		memcpy(ktriov, auio.uio_iov, iovsz);
	}
#endif

	if (mp->msg_name)
		MCLAIM(to, so->so_mowner);
	if (mp->msg_control)
		MCLAIM(control, so->so_mowner);

#ifdef QNX_MFIB
	if (so->so_fiborigin==SO_FIB_INIT) {
		so->so_fibnum = kauth_getfib4cred(l->l_cred);
		so->so_fiborigin = SO_FIB_SENDIT;
#ifndef NDEBUG
		if (debug_net_so_fib_verbosity > 1) {
			printf("Socket type '%d': pid=%10d/so=%10d/user=%10d assigning to fib %4d\n",
			    so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid ,(int)so,
			    (int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
		}
#endif
	}
#ifndef NDEBUG
	else {
		if (debug_net_so_fib_verbosity > 2) {
			printf("sendit: fib already set to %4d\n", so->so_fibnum);
		}
	}
#endif
#endif
	len = auio.uio_resid;
	error = (*so->so_send)(so, to, &auio, NULL, control, flags, l);
	/* Protocol is responsible for freeing 'control' */
	control = NULL;

	if (error) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		if (error == EPIPE && (flags & MSG_NOSIGNAL) == 0) {
			psignal(LWP_TO_PR(l), SIGPIPE);
		}
	}
	if (error == 0)
		*retsize = len - auio.uio_resid;

bad:
#ifdef KTRACE
	if (ktriov != NULL) {
		ktrgeniov(s, UIO_WRITE, ktriov, *retsize, error);
		free(ktriov, M_TEMP);
	}
#endif

#ifndef __QNXNTO__
 	if (iov != aiov)
		free(iov, M_IOV);
#endif
	if (to)
		m_freem(to);
	if (control)
		m_freem(control);

	return (error);
}

int
do_sys_sendmsg(struct lwp *l, int s, struct msghdr *mp, int flags,
    register_t *retsize)
{
	int		error;
	struct socket	*so;
	file_t		*fp;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0)
		return error;
	so = (struct socket *)fp->f_data;
	error = do_sys_sendmsg_so(l, s, so, fp, mp, flags, retsize);
	FILE_UNUSE(fp, l);
	return error;
}

int
sys_recvfrom(struct lwp *l, void *v, register_t *retval)
{
	struct sys_recvfrom_args /* {
		syscallarg(int)			s;
		syscallarg(void *)		buf;
		syscallarg(size_t)		len;
		syscallarg(int)			flags;
		syscallarg(struct sockaddr *)	from;
		syscallarg(unsigned int *)	fromlenaddr;
	} */ *uap = v;
	struct msghdr	msg;
	struct iovec	aiov;
	int		error;
	struct mbuf	*from;

	msg.msg_name = NULL;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = SCARG(uap, buf);
	aiov.iov_len = SCARG(uap, len);
	msg.msg_control = NULL;
	msg.msg_flags = SCARG(uap, flags) & MSG_USERFLAGS;

	error = do_sys_recvmsg(l, SCARG(uap, s), &msg, &from, NULL, retval);
	if (error != 0)
		return error;

	error = copyout_sockname(SCARG(uap, from), SCARG(uap, fromlenaddr),
	    MSG_LENUSRSPACE, from);
	if (from != NULL)
		m_free(from);
	return error;
}

int
sys_recvmsg(struct lwp *l, void *v, register_t *retval)
{
	struct sys_recvmsg_args /* {
		syscallarg(int)			s;
		syscallarg(struct msghdr *)	msg;
		syscallarg(int)			flags;
	} */ *uap = v;
#ifndef __QNXNTO__
	struct msghdr	msg;
#else
#define msg (*SCARG(uap, msg))
#endif
	int		error;
	struct mbuf	*from, *control;

#ifndef __QNXNTO__
	error = copyin(SCARG(uap, msg), &msg, sizeof(msg));
	if (error)
		return (error);

	msg.msg_flags = (SCARG(uap, flags) & MSG_USERFLAGS) | MSG_IOVUSRSPACE;
#else
	msg.msg_flags = (SCARG(uap, flags) & (MSG_USERFLAGS | MSG_HDREXTEN));
#endif

	error = do_sys_recvmsg(l, SCARG(uap, s), &msg, &from,
	    msg.msg_control != NULL ? &control : NULL, retval);
	if (error != 0)
		return error;

	if (msg.msg_control != NULL)
		error = copyout_msg_control(l, &msg, control);

	if (error == 0)
		error = copyout_sockname(msg.msg_name, &msg.msg_namelen, 0,
			from);
	if (from != NULL)
		m_free(from);
#ifndef __QNXNTO__
	if (error == 0)
		error = copyout(&msg, SCARG(uap, msg), sizeof(msg));
#else
#undef msg
#endif

	return (error);
}

int
sys_sendmmsg(struct lwp *l, const struct sys_sendmmsg_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int)			s;
		syscallarg(struct mmsghdr *)	mmsg;
		syscallarg(unsigned int)	vlen;
		syscallarg(unsigned int)	flags;
	} */
	struct mmsghdr mmsg;
	struct socket *so;
	file_t *fp;
	struct msghdr *msg = &mmsg.msg_hdr;
	int error, s;
	unsigned int vlen, flags, dg;
#ifdef __QNXNTO__
	struct iovec iov;
	char *namep, *controlp;
	struct proc *p = LWP_TO_PR(l);
	unsigned offset_last;
	struct mbuf *nextdata, *m, **mp, *m_new;
#endif

	s = SCARG(uap, s);
	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0)
		return error;
	so = (struct socket *)fp->f_data;

	vlen = SCARG(uap, vlen);
	if (vlen > 1024)
		vlen = 1024;

#ifndef __QNXNTO__
	flags = (SCARG(uap, flags) & MSG_USERFLAGS) | MSG_IOVUSRSPACE;
#else
	flags = (SCARG(uap, flags) & (MSG_USERFLAGS | MSG_HDREXTEN));
	namep = (char *)(SCARG(uap, mmsg) + vlen);
#endif

	for (dg = 0; dg < vlen;) {
		error = copyin(SCARG(uap, mmsg) + dg, &mmsg, sizeof(mmsg));
		if (error)
			break;

		msg->msg_flags = flags;

#ifdef __QNXNTO__
		if (msg->msg_name != NULL) {
			msg->msg_name = namep;
		}
		else {
			msg->msg_namelen = 0;
		}
		controlp = namep + msg->msg_namelen;

		if (msg->msg_control != NULL) {
			msg->msg_control = controlp;
		}
		else {
			msg->msg_controllen = 0;
		}
		namep = controlp + msg->msg_controllen;
		iov.iov_base = 0;
		iov.iov_len = mmsg.msg_len;
		msg->msg_iov = &iov;
		msg->msg_iovlen = 1;
		offset_last = p->p_offset;
		nextdata = m_split(p->p_mbuf, mmsg.msg_len, M_DONTWAIT);
		if (nextdata == NULL) {
			error = ENOBUFS;
			break;
		}
		for (mp = &p->p_mbuf; (m = *mp) != NULL; mp = &m->m_next) {
			if (m->m_next == NULL)
				break;
		}
		if (m != NULL && (m->m_flags & M_EXT)) {
			m_new = NULL;
			if (((m->m_flags & M_PKTHDR) && m->m_len <= MHLEN) ||
			    ((m->m_flags & M_PKTHDR) == 0 && m->m_len <= MLEN)) {
				m_new = m_get(M_DONTWAIT, MT_DATA);
				if (m_new == NULL) {
					error = ENOBUFS;
					break;
				}
			}
			if (m_new != NULL) {
				if (m->m_flags & M_PKTHDR)
					M_COPY_PKTHDR(m_new, m);
				memcpy(m_new->m_data, m->m_data, m->m_len);
				m_new->m_len = m->m_len;
				*mp = m_new;
				m_free(m);
			}
		}
#endif

		error = do_sys_sendmsg_so(l, s, so, fp, msg, flags, retval);
		if (error)
			break;

#ifdef KTRACE
		ktrkuser("msghdr", msg, sizeof *msg);
#endif
#ifndef __QNXNTO__
		mmsg.msg_len = *retval;
		error = copyout(&mmsg, SCARG(uap, mmsg) + dg, sizeof(mmsg));
#else
		p->p_offset = offset_last + mmsg.msg_len;
		mmsg.msg_len = *retval;
		m_freem(p->p_mbuf);
		p->p_mbuf = nextdata;
		/*
		 * We don't want to copyout the mmsg.msg_hdr portion which
		 * has our updated msg_name, msg_iov, msg_control
		 * members pointing in our address space.
		 */
		error = copyout(&mmsg.msg_len,
		    &(SCARG(uap, mmsg) + dg)->msg_len, sizeof(mmsg.msg_len));
#endif
		if (error)
			break;
		dg++;

	}

	*retval = dg;
	if (error)
		so->so_error = error;

	FILE_UNUSE(fp, l);

	/*
	 * If we succeeded at least once, return 0, hopefully so->so_error
	 * will catch it next time.
	 */
	if (dg)
		return 0;
	return error;
}

/*
 * Adjust for a truncated SCM_RIGHTS control message.
 *  This means closing any file descriptors that aren't present
 *  in the returned buffer.
 *  m is the mbuf holding the (already externalized) SCM_RIGHTS message.
 */
static void
free_rights(struct mbuf *m, struct lwp *l)
{
	int nfd;
	int i;
#ifndef __QNXNTO__
	int *fdv;

	nfd = m->m_len < CMSG_SPACE(sizeof(int)) ? 0
	    : (m->m_len - CMSG_SPACE(sizeof(int))) / sizeof(int) + 1;
	fdv = (int *) CMSG_DATA(mtod(m,struct cmsghdr *));
	for (i = 0; i < nfd; i++)
		fdrelease(l, fdv[i]);
#else
	io_dup_t *dup;

	nfd = m->m_len < CMSG_SPACE(sizeof(io_dup_t)) ? 0
	    : (m->m_len - CMSG_SPACE(sizeof(io_dup_t))) / sizeof(io_dup_t) + 1;
	dup = (io_dup_t *)CMSG_DATA(mtod(m,struct cmsghdr *));
	for (i = 0; i < nfd; i++)
		unp_discard(&dup[i]);
#endif
}

void
free_control_mbuf(struct lwp *l, struct mbuf *control, struct mbuf *uncopied)
{
	struct mbuf *next;
	struct cmsghdr *cmsg;
	bool do_free_rights = false;

	while (control != NULL) {
		cmsg = mtod(control, struct cmsghdr *);
		if (control == uncopied)
			do_free_rights = true;
		if (do_free_rights && cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS)
			free_rights(control, l);
		next = control->m_next;
		m_free(control);
		control = next;
	}
}

/* Copy socket control/CMSG data to user buffer, frees the mbuf */
int
copyout_msg_control(struct lwp *l, struct msghdr *mp, struct mbuf *control)
{
	int i, len, error = 0;
	struct cmsghdr *cmsg;
	struct mbuf *m;
	char *q;
#ifdef __QNXNTO__
	int len_tot = 0;
#endif

	len = mp->msg_controllen;
	if (len <= 0 || control == 0) {
		mp->msg_controllen = 0;
		free_control_mbuf(l, control, control);
		return 0;
	}

	q = (char *)mp->msg_control;

	for (m = control; m != NULL; ) {
		cmsg = mtod(m, struct cmsghdr *);
		i = m->m_len;
#ifdef __QNXNTO__
		len_tot += i;
#endif
		if (len < i) {
			mp->msg_flags |= MSG_CTRUNC;
			if (cmsg->cmsg_level == SOL_SOCKET
			    && cmsg->cmsg_type == SCM_RIGHTS)
				/* Do not truncate me ... */
				break;
			i = len;
		}
		error = copyout(mtod(m, void *), q, i);
		if (error != 0) {
			/* We must free all the SCM_RIGHTS */
			m = control;
			break;
		}
		m = m->m_next;
		if (m)
			i = ALIGN(i);
		q += i;
		len -= i;
		if (len <= 0)
			break;
	}

#ifdef __QNXNTO__
	if (mp->msg_flags & MSG_HDREXTEN)
		((struct msghdr_exten *)mp)->controltot = len_tot;

	if (mp->msg_flags & MSG_PEEK) {
		/*
		 * This is the condtion in free_control_mbuf that
		 * prevents free_rights().
		 */
		m = NULL;
	}
#endif
	free_control_mbuf(l, control, m);

	mp->msg_controllen = q - (char *)mp->msg_control;
	return error;
}

static int
do_sys_recvmsg_so(struct lwp *l, int s, struct socket *so, struct msghdr *mp,
    struct mbuf **from, struct mbuf **control, register_t *retsize)
{
#ifndef __QNXNTO__
	struct iovec	aiov[UIO_SMALLIOV], *iov = aiov;
#endif
	struct iovec	*tiov;
	struct uio	auio;
	size_t		len, iovsz;
	int		i, error;
#ifdef KTRACE
	struct iovec	*ktriov;
#endif

	*from = NULL;
	if (control != NULL)
		*control = NULL;
#ifdef __QNXNTO__
	struct msghdr_exten	*mep;
	struct m_hdr		m_ctrl;

	if ((mp->msg_flags & MSG_HDREXTEN) && mp->msg_control) {
		mep = (struct msghdr_exten *)mp;
		m_ctrl.mh_data = (void *)&mep->controlseq;
		*control = (struct mbuf *)&m_ctrl;
	}
	else {
		mep = NULL;
	}

#endif
#ifdef KTRACE
	ktriov = NULL;
#endif

	iovsz = mp->msg_iovlen * sizeof(struct iovec);
#ifndef __QNXNTO__ /* MSG_IOVUSRSPACE never used */
	if (mp->msg_flags & MSG_IOVUSRSPACE) {
		if ((unsigned int)mp->msg_iovlen > UIO_SMALLIOV) {
			if ((unsigned int)mp->msg_iovlen > IOV_MAX) {
				error = EMSGSIZE;
				goto out;
			}
			iov = malloc(iovsz, M_IOV, M_WAITOK);
		}
		if (mp->msg_iovlen != 0) {
			error = copyin(mp->msg_iov, iov, iovsz);
			if (error)
				goto out;
		}
		auio.uio_iov = iov;
	} else
#endif
		auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_rw = UIO_READ;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	KASSERT(l == curlwp);
	auio.uio_vmspace = &LWP_TO_PR(l)->p_vmspace;

	tiov = auio.uio_iov;
	for (i = 0; i < mp->msg_iovlen; i++, tiov++) {
		/*
		 * Reads return ssize_t because -1 is returned on error.
		 * Therefore we must restrict the length to SSIZE_MAX to
		 * avoid garbage return values.
		 */
		auio.uio_resid += tiov->iov_len;
		if (tiov->iov_len > SSIZE_MAX || auio.uio_resid > SSIZE_MAX) {
			error = EINVAL;
			goto out;
		}
	}
#ifdef KTRACE
	if (KTRPOINT(l->l_proc, KTR_GENIO)) {
		ktriov = malloc(iovlen, M_TEMP, M_WAITOK);
		memcpy(ktriov, auio.uio_iov, iovsz);
	}
#endif

	len = auio.uio_resid;
#ifndef __QNXNTO__
	mp->msg_flags &= MSG_USERFLAGS;
#else
	mp->msg_flags &= (MSG_USERFLAGS | MSG_HDREXTEN);
#endif
	error = (*so->so_receive)(so, from, &auio, NULL, control,
	    &mp->msg_flags);
	len -= auio.uio_resid;
	*retsize = len;
	if (error != 0 && len != 0
	    && (error == ERESTART || error == EINTR || error == EWOULDBLOCK))
		/* Some data transferred */
		error = 0;
#ifdef KTRACE
	if (ktriov != NULL) {
		if (error == 0)
			ktrgenio(l, s, UIO_READ, ktriov, len, 0);
		free(ktriov, M_TEMP);
	}
#endif
	if (error != 0) {
		m_freem(*from);
		*from = NULL;
		if (control != NULL) {
			free_control_mbuf(l, *control, *control);
			*control = NULL;
		}
	}
 out:
#ifndef __QNXNTO__
	if (iov != aiov)
		free(iov, M_IOV);
#endif
	return (error);
}


int
do_sys_recvmsg(struct lwp *l, int s, struct msghdr *mp, struct mbuf **from,
    struct mbuf **control, register_t *retsize)
{
	int error;
	struct socket *so;
	struct file	*fp;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0)
		return (error);
	so = (struct socket *)fp->f_data;
	error = do_sys_recvmsg_so(l, s, so, mp, from, control, retsize);
	FILE_UNUSE(fp, l);
	return error;
}

int
sys_recvmmsg(struct lwp *l, const struct sys_recvmmsg_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int)			s;
		syscallarg(struct mmsghdr *)	mmsg;
		syscallarg(unsigned int)	vlen;
		syscallarg(unsigned int)	flags;
		syscallarg(struct timespec *)	timeout;
	} */
	struct mmsghdr mmsg;
	struct socket *so;
	struct msghdr *msg = &mmsg.msg_hdr;
	int error, s;
	struct mbuf *from, *control;
	struct timespec ts, now;
	unsigned int vlen, flags, dg;
	struct file	*fp;
#ifdef __QNXNTO__
	void *offset_cur, *name_saved, *ctrl_saved;
	struct iovec iov_tmp;
	unsigned offset_saved, msg_len_saved;
	int iovlen_saved;
	iov_t *iov_saved;
	struct proc *p;

	p = LWP_TO_PR(l);

	offset_cur = SCARG(uap, mmsg) + SCARG(uap, vlen);
#endif

	if (SCARG(uap, timeout)) {
		if ((error = copyin(SCARG(uap, timeout), &ts, sizeof(ts))) != 0)
			return error;
		getnanotime(&now);
		timespecadd(&now, &ts, &ts);
	}

	s = SCARG(uap, s);
	if ((error = getsock(LWP_TO_PR(l)->p_fd, s, &fp)) != 0)
		return (error);
	so = (struct socket *)fp->f_data;

	vlen = SCARG(uap, vlen);
	if (vlen > 1024)
		vlen = 1024;

	from = NULL;
	flags = (SCARG(uap, flags) & MSG_USERFLAGS) | MSG_IOVUSRSPACE;

	for (dg = 0; dg < vlen;) {
		error = copyin(SCARG(uap, mmsg) + dg, &mmsg, sizeof(mmsg));
		if (error)
			break;
#ifdef __QNXNTO__
		offset_saved = p->p_offset;
		msg_len_saved = mmsg.msg_len;
		name_saved = msg->msg_name;
		ctrl_saved = msg->msg_control;
		iovlen_saved = msg->msg_iovlen;
		iov_saved = msg->msg_iov;
		if (msg->msg_name != NULL) {
			msg->msg_name = offset_cur;
			offset_cur = (void *)
			    ((uintptr_t)offset_cur + msg->msg_namelen);
		}

		if (msg->msg_control != NULL) {
			msg->msg_control = offset_cur;
			offset_cur = (void *)
			    ((uintptr_t)offset_cur + msg->msg_controllen);
		}

		msg->msg_iovlen = 1;
		msg->msg_iov = &iov_tmp;
		iov_tmp.iov_base = NULL;
		iov_tmp.iov_len = mmsg.msg_len;
#endif

		msg->msg_flags = flags & ~MSG_WAITFORONE;

		if (from != NULL) {
			m_free(from);
			from = NULL;
		}

		error = do_sys_recvmsg_so(l, s, so, msg, &from,
		    msg->msg_control != NULL ? &control : NULL, retval);
		if (error) {
			if (error == EAGAIN && dg > 0)
				error = 0;
			break;
		}
#ifdef __QNXNTO__
		/* In do_sys_recvmsg_so() lower layers performed the
		 * following:
		 *   Update [n]iovp to subtract off what was just used:
		 *   p->p_read.iovp += *p->p_read.niovp
		 *   *p->p_read.niovp = initial - *p->p_read.niovp
		 */
#endif

		if (msg->msg_control != NULL)
			error = copyout_msg_control(l, msg, control);
		if (error)
			break;

		error = copyout_sockname(msg->msg_name, &msg->msg_namelen, 0,
		    from);
		if (error)
			break;

#ifdef KTRACE
		ktrkuser("msghdr", msg, sizeof *msg);
#endif
		mmsg.msg_len = *retval;

#ifdef __QNXNTO__
		if (mmsg.msg_len != msg_len_saved) {
			error = MsgWritev_r(p->p_ctxt.rcvid,
			    p->p_read.iovp, *p->p_read.niovp,
			    p->p_read.flush_offset);
			if (error < 0) {
				error = -error;
				break;
			}
			*p->p_read.niovp = 0;
			p->p_read.flush_offset = offset_saved + msg_len_saved;
			m_freem(*p->p_read.m_to_free);
			*p->p_read.m_to_free = NULL;
		}

		msg->msg_name = name_saved;
		msg->msg_control = ctrl_saved;
		msg->msg_iovlen = iovlen_saved;
		msg->msg_iov = iov_saved;
#endif
		error = copyout(&mmsg, SCARG(uap, mmsg) + dg, sizeof(mmsg));
		if (error)
			break;

		dg++;
		if (msg->msg_flags & MSG_OOB)
			break;

		if (SCARG(uap, timeout)) {
			getnanotime(&now);
			timespecsub(&now, &ts, &now);
			if (now.tv_sec > 0)
				break;
		}

		if (flags & MSG_WAITFORONE)
			flags |= MSG_DONTWAIT;

#ifdef __QNXNTO__
		p->p_offset = offset_saved + msg_len_saved;
#endif
	}

	if (from != NULL)
		m_free(from);

	*retval = dg;
	if (error)
		so->so_error = error;
#ifdef __QNXNTO__
	/* On return from sys_recvmmsg() adjust p->p_read.[n]iovp to their
	 * final totals
	 */
#endif

	FILE_UNUSE(fp, l);

	/*
	 * If we succeeded at least once, return 0, hopefully so->so_error
	 * will catch it next time.
	 */
	if (dg)
		return 0;

	return error;
}


/* ARGSUSED */
int
sys_shutdown(struct lwp *l, void *v, register_t *retval)
{
	struct sys_shutdown_args /* {
		syscallarg(int)	s;
		syscallarg(int)	how;
	} */ *uap = v;
	struct proc	*p;
	struct file	*fp;
	int		error;

#ifndef __QNXNTO__
	p = l->l_proc;
#else
	p = LWP_TO_PR(l);
#endif
	/* getsock() will use the descriptor for us */
	if ((error = getsock(p->p_fd, SCARG(uap, s), &fp)) != 0)
		return (error);
	error = soshutdown((struct socket *)fp->f_data, SCARG(uap, how));
	FILE_UNUSE(fp, l);
	return (error);
}

/* ARGSUSED */
int
sys_setsockopt(struct lwp *l, void *v, register_t *retval)
{
	struct sys_setsockopt_args /* {
		syscallarg(int)			s;
		syscallarg(int)			level;
		syscallarg(int)			name;
		syscallarg(const void *)	val;
		syscallarg(unsigned int)	valsize;
	} */ *uap = v;
	struct proc	*p;
	struct file	*fp;
	struct mbuf	*m;
	struct socket	*so;
	int		error;
	unsigned int	len;

#ifndef __QNXNTO__
	p = l->l_proc;
#else
	p = LWP_TO_PR(l);
#endif
	m = NULL;
	/* getsock() will use the descriptor for us */
	if ((error = getsock(p->p_fd, SCARG(uap, s), &fp)) != 0)
		return (error);
	so = (struct socket *)fp->f_data;
	len = SCARG(uap, valsize);
	if (len > MCLBYTES) {
		error = EINVAL;
		goto out;
	}
	if (SCARG(uap, val)) {
		m = getsombuf(so, MT_SOOPTS);
		if (len > MLEN)
			m_clget(m, M_WAIT);
		error = copyin(SCARG(uap, val), mtod(m, void *), len);
		if (error) {
			(void) m_free(m);
			goto out;
		}
		m->m_len = SCARG(uap, valsize);
	}
	error = sosetopt(so, SCARG(uap, level), SCARG(uap, name), m);
 out:
	FILE_UNUSE(fp, l);
	return (error);
}

/* ARGSUSED */
int
sys_getsockopt(struct lwp *l, void *v, register_t *retval)
{
	struct sys_getsockopt_args /* {
		syscallarg(int)			s;
		syscallarg(int)			level;
		syscallarg(int)			name;
		syscallarg(void *)		val;
		syscallarg(unsigned int *)	avalsize;
	} */ *uap = v;
	struct file	*fp;
	struct mbuf	*m;
	unsigned int	op, i, valsize;
	int		error;
#ifdef __QNXNTO__
	struct mbuf	*msav;
#endif

	m = NULL;
#ifndef __QNXNTO__
	/* getsock() will use the descriptor for us */
	if ((error = getsock(l->l_proc->p_fd, SCARG(uap, s), &fp)) != 0)
		return (error);
#else
	msav = NULL;
	/* getsock() will use the descriptor for us */
	if ((error = (getsock)(l, SCARG(uap, s), &fp)) != 0)
		return (error);

#endif
	if (SCARG(uap, val)) {
#ifdef __QNXNTO__
		/*
		 * we return valsize with the message status
		 * so we've already pulled it out of the context.
		 */
		LWP_TO_PR(l)->p_vmspace.vm_flags |= VM_NOCTXT;
#endif
		error = copyin((caddr_t)SCARG(uap, avalsize),
			       (caddr_t)&valsize, sizeof(valsize));
		if (error)
			goto out;
#ifdef __QNXNTO__
		if (valsize > MCLBYTES) {
			/*
			 * Restrict us down to a cluster size, thats
			 * all we can pass either way...
			 */
			valsize = MCLBYTES;
		}
		
		if (SCARG(uap, name) & GETSOCKOPT_EXTRA) {
			/*
			 * SCTP wants to get some information
			 * from the getopt call.. to lookup an
			 * association. The alternative is to
			 * add special in/out syscalls which seems
			 * a large waste :>
			 */
			if (valsize <= MLEN)
				msav = m_get(M_DONTWAIT, MT_SOOPTS);
			else
				msav = m_getcl(M_DONTWAIT, MT_SOOPTS, 0);
			if (msav == NULL) {
				error = ENOBUFS;
				goto out;
			}
			error = copyin(SCARG(uap, val), mtod(msav, caddr_t), valsize);
			if (error) {
				(void) m_free(msav);
				goto out;
			}
			msav->m_len = valsize;
			m = msav;
		}
#endif
	} else
		valsize = 0;
	if ((error = sogetopt((struct socket *)fp->f_data, SCARG(uap, level),
	    SCARG(uap, name), &m)) == 0 && SCARG(uap, val) && valsize &&
	    m != NULL) {
		op = 0;
		while (m && !error && op < valsize) {
			i = min(m->m_len, (valsize - op));
			error = copyout(mtod(m, void *), SCARG(uap, val), i);
			op += i;
			SCARG(uap, val) = ((uint8_t *)SCARG(uap, val)) + i;
#ifdef __QNXNTO__
			if (m == msav)
				msav = NULL;
#endif
			m = m_free(m);
		}
		valsize = op;
		if (error == 0)
#ifdef __QNXNTO__
			/* As above */
#endif
			LWP_TO_PR(l)->p_vmspace.vm_flags |= VM_NOCTXT;
			error = copyout(&valsize,
					SCARG(uap, avalsize), sizeof(valsize));
	}
	if (m != NULL) {
#ifdef __QNXNTO__
		if (m == msav)
			msav = NULL;
#endif
		(void) m_free(m);
	}

#ifdef __QNXNTO__
	/*
	 * Check to see if the caller used my mbuf or not.
	 * For example, SCTP will use mbuf if passed in whereas
	 * other protocols will ignore the passed mbuf and
	 * replace it with one they allocate.
	 */
	if (msav)
		(void) m_free(msav);
#endif
 out:
	FILE_UNUSE(fp, l);
	return (error);
}

#ifdef PIPE_SOCKETPAIR
/* ARGSUSED */
int
sys_pipe(struct lwp *l, void *v, register_t *retval)
{
	struct filedesc	*fdp;
	struct file	*rf, *wf;
	struct socket	*rso, *wso;
	int		fd, error;

	fdp = l->l_proc->p_fd;
	if ((error = socreate(AF_LOCAL, &rso, SOCK_STREAM, 0, l)) != 0)
		return (error);
	if ((error = socreate(AF_LOCAL, &wso, SOCK_STREAM, 0, l)) != 0)
		goto free1;
	/* remember this socket pair implements a pipe */
	wso->so_state |= SS_ISAPIPE;
	rso->so_state |= SS_ISAPIPE;
	/* falloc() will use the descriptor for us */
	if ((error = falloc(l, &rf, &fd)) != 0)
		goto free2;
	retval[0] = fd;
	rf->f_flag = FREAD;
	rf->f_type = DTYPE_SOCKET;
	rf->f_ops = &socketops;
	rf->f_data = rso;
	if ((error = falloc(l, &wf, &fd)) != 0)
		goto free3;
	wf->f_flag = FWRITE;
	wf->f_type = DTYPE_SOCKET;
	wf->f_ops = &socketops;
	wf->f_data = wso;
	retval[1] = fd;
	if ((error = unp_connect2(wso, rso, PRU_CONNECT2)) != 0)
		goto free4;
	FILE_SET_MATURE(rf);
	FILE_SET_MATURE(wf);
	FILE_UNUSE(rf, l);
	FILE_UNUSE(wf, l);
	return (0);
 free4:
	FILE_UNUSE(wf, l);
	ffree(wf);
	fdremove(fdp, retval[1]);
 free3:
	FILE_UNUSE(rf, l);
	ffree(rf);
	fdremove(fdp, retval[0]);
 free2:
	(void)soclose(wso);
 free1:
	(void)soclose(rso);
	return (error);
}
#endif /* PIPE_SOCKETPAIR */

/*
 * Get socket name.
 */
/* ARGSUSED */
int
do_sys_getsockname(struct lwp *l, int fd, int which, struct mbuf **nam)
{
	struct file	*fp;
	struct socket	*so;
	struct mbuf	*m;
	int		error;

	/* getsock() will use the descriptor for us */
	if ((error = getsock(LWP_TO_PR(l)->p_fd, fd, &fp)) != 0)
		return error;
	so = (struct socket *)fp->f_data;

	if (which == PRU_PEERADDR
	    && (so->so_state & (SS_ISCONNECTED | SS_ISCONFIRMING)) == 0) {
		error = ENOTCONN;
		goto bad;
	}

	m = m_getclr(M_WAIT, MT_SONAME);
	*nam = m;
	MCLAIM(m, so->so_mowner);
	error = (*so->so_proto->pr_usrreq)(so, which, (struct mbuf *)0,
	    m, (struct mbuf *)0, (struct lwp *)0);
	if (error != 0)
		m_free(m);
    bad:
	FILE_UNUSE(fp, l);
	return error;
}

int
copyout_sockname(struct sockaddr *asa, unsigned int *alen, int flags,
    struct mbuf *addr)
{
	int len;
	int error;

	if (asa == NULL)
		/* Assume application not interested */
		return 0;

	if (flags & MSG_LENUSRSPACE) {
		error = copyin(alen, &len, sizeof(len));
		if (error)
			return error;
	} else
		len = *alen;
	if (len < 0)
		return EINVAL;

	if (addr == NULL) {
		len = 0;
		error = 0;
	} else {
		if (len > addr->m_len)
			len = addr->m_len;
		/* Maybe this ought to copy a chain ? */
		error = copyout(mtod(addr, void *), asa, len);
	}

	if (error == 0) {
		if (flags & MSG_LENUSRSPACE)
			error = copyout(&len, alen, sizeof(len));
		else
			*alen = len;
	}

	return error;
}

/*
 * Get socket name.
 */
/* ARGSUSED */
int
sys_getsockname(struct lwp *l, void *v, register_t *retval)
{
	struct sys_getsockname_args /* {
		syscallarg(int)			fdes;
		syscallarg(struct sockaddr *)	asa;
		syscallarg(unsigned int *)	alen;
	} */ *uap = v;
	struct mbuf	*m;
	int		error;

	error = do_sys_getsockname(l, SCARG(uap, fdes), PRU_SOCKADDR, &m);
	if (error != 0)
		return error;

	error = copyout_sockname(SCARG(uap, asa), SCARG(uap, alen),
	    MSG_LENUSRSPACE, m);
	if (m != NULL)
		m_free(m);
	return error;
}

/*
 * Get name of peer for connected socket.
 */
/* ARGSUSED */
int
sys_getpeername(struct lwp *l, void *v, register_t *retval)
{
	struct sys_getpeername_args /* {
		syscallarg(int)			fdes;
		syscallarg(struct sockaddr *)	asa;
		syscallarg(unsigned int *)	alen;
	} */ *uap = v;
	struct mbuf	*m;
	int		error;

	error = do_sys_getsockname(l, SCARG(uap, fdes), PRU_PEERADDR, &m);
	if (error != 0)
		return error;

	error = copyout_sockname(SCARG(uap, asa), SCARG(uap, alen),
	    MSG_LENUSRSPACE, m);
	if (m != NULL)
		m_free(m);
	return error;
}

/*
 * XXX In a perfect world, we wouldn't pass around socket control
 * XXX arguments in mbufs, and this could go away.
 */
int
sockargs(struct mbuf **mp, const void *bf, size_t buflen, int type)
{
	struct sockaddr	*sa;
	struct mbuf	*m;
	int		error;

	/*
	 * We can't allow socket names > UCHAR_MAX in length, since that
	 * will overflow sa_len.  Control data more than a page size in
	 * length is just too much.
	 */
	if (buflen > (type == MT_SONAME ? UCHAR_MAX : PAGE_SIZE))
		return (EINVAL);

	/* Allocate an mbuf to hold the arguments. */
	m = m_get(M_WAIT, type);
	/* can't claim.  don't who to assign it to. */
	if (buflen > MLEN) {
		/*
		 * Won't fit into a regular mbuf, so we allocate just
		 * enough external storage to hold the argument.
		 */
		MEXTMALLOC(m, buflen, M_WAITOK);
	}
	m->m_len = buflen;
	error = copyin(bf, mtod(m, caddr_t), buflen);
	if (error) {
		(void) m_free(m);
		return (error);
	}
	*mp = m;
	if (type == MT_SONAME) {
		sa = mtod(m, struct sockaddr *);
#if BYTE_ORDER != BIG_ENDIAN
		/*
		 * 4.3BSD compat thing - need to stay, since bind(2),
		 * connect(2), sendto(2) were not versioned for COMPAT_43.
		 */
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = buflen;
	}
	return (0);
}

#ifndef __QNXNTO__
int
getsock(struct filedesc *fdp, int fdes, struct file **fpp)
{
	struct file	*fp;

	if ((fp = fd_getfile(fdp, fdes)) == NULL)
		return (EBADF);

	FILE_USE(fp);

	if (fp->f_type != DTYPE_SOCKET) {
		FILE_UNUSE(fp, NULL);
		return (ENOTSOCK);
	}
	*fpp = fp;
	return (0);
}
#else
int
(getsock)(struct lwp *l, int fdes, struct file **fpp)
{
	struct file	*fp;

	if ((fp = l->l_fp) == NULL)
		return EBADF;

	if (fp->f_type != DTYPE_SOCKET)
		return ENOTSOCK;

	FILE_USE(fp);
	*fpp = fp;
	return 0;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/uipc_syscalls.c $ $Rev: 872341 $")
#endif
