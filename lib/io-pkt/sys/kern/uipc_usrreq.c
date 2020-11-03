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


/*	$NetBSD: uipc_usrreq.c,v 1.94.2.1 2007/08/21 19:33:57 liamjfoy Exp $	*/

/*-
 * Copyright (c) 1998, 2000, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)uipc_usrreq.c	8.9 (Berkeley) 5/14/95
 */

/*
 * Copyright (c) 1997 Christopher G. Demetriou.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	@(#)uipc_usrreq.c	8.9 (Berkeley) 5/14/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uipc_usrreq.c,v 1.94.2.1 2007/08/21 19:33:57 liamjfoy Exp $");

#ifdef __QNXNTO__
#include "opt_pru_sense.h"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#ifndef __QNXNTO__
#include <sys/file.h>
#else
#include <sys/file_bsd.h>
#include <sys/procmsg.h>
#include <sys/dispatch.h>
#include <sys/nlist.h>
#include "blockop.h"
#endif
#include <sys/stat.h>
#include <sys/mbuf.h>
#include <sys/kauth.h>

#ifdef __QNXNTO__
MALLOC_DEFINE(M_VNODE, "vnodes", "Dynamically allocated vnodes"); /* Usually in kern/vfs_subr.c */

struct unpcbtable unbtable = { CIRCLEQ_HEAD_INITIALIZER(unbtable.unpt_queue) };
NLIST_EXPORT(unbtable, unbtable);

#undef errno

# define VOP_UNLOCK(l, d)

struct sun_ref {
	int			sr_ref;
	struct sockaddr_un	sr_sun;
};

struct st_blockop {
	char		path[104];  /* From sys/un.h sun_path[104] */
	struct stat	*st;
	int		error;
};

extern pthread_key_t *blockop_resmgr_keyp;
	
static LIST_HEAD(, vnode) vn_list_head;
static resmgr_connect_funcs_t uds_cfuncs = {0};
static resmgr_io_funcs_t      uds_iofuncs;

struct sockaddr_un * sref_alloc(int);
void sref_free(struct sockaddr_un *);

#define SUN_TO_SREF(sun) \
	((struct sun_ref *) ((char *)(sun) - offsetof(struct sun_ref, sr_sun)))

/* some helper functions */

static void
sched_blockop(void *arg)
{
	/* There is no function to call, just force the caller's
	 * execution to be serialized with the other blockops in
	 * the main thread.
	 */
}

static void
stat_blockop(void *arg)
{
	struct st_blockop	*stbl;
	struct timespec		ts;

	stbl = arg;
	ts.tv_sec = 10;
	ts.tv_nsec = 0;
	timer_timeout(CLOCK_REALTIME, _NTO_TIMEOUT_REPLY | _NTO_TIMEOUT_SEND,
	        NULL, &ts, NULL);
	if (stat(stbl->path, stbl->st) == -1)
		stbl->error = errno;
	else
		stbl->error = EOK;
}

static void
sanitize_path(struct sockaddr_un *sun, size_t *addrlenp, char **epp, char **spp)
{
	char	*cp;
	int	prev;
	size_t	pathlen;
	char	*sp, *ep;

	if (addrlenp != NULL) {
		pathlen = *addrlenp - offsetof(struct sockaddr_un, sun_path);

		/*
		 * Strip multiple '/'.
		 *
		 * At some point (if not already) the client
		 * side of bind() may have to do some _connect()
		 * magic similiar to mount so that creation
		 * of UDS relative to the client's CWD work
		 * correctly. If that's present this work will
		 * have already been done on the client side.
		 *
		 * As it is now relative paths in the client
		 * get created relative to our CWD which is /
		 * after procmgr_daemon() at startup.
		 */
		prev = 0;
		for (cp = sun->sun_path; cp < sun->sun_path + pathlen;) {
			if (*cp == '/') {
				if (prev) {
					memmove(cp, cp + 1,
					    pathlen - 1 - (cp - sun->sun_path));
					pathlen--;
					sun->sun_len--;
					(*addrlenp)--;
				}
				else {
					prev = 1;
					cp++;
				}
			}
			else {
				prev = 0;
				cp++;
			}
		}
	}

	if (epp != NULL && spp != NULL) {
		/* find first terminator. */

		for (ep = sun->sun_path; *ep != '\0'; ep++)
			continue;
		*epp = ep;

		/* find last '/' */
		for (sp = ep; sp >= sun->sun_path; sp--) {
			if (*sp == '/')
				break;
		}
		if (sp < sun->sun_path)
			*spp = NULL;
		else
			*spp = sp;
	}
}

/* Force the caller to serialize execution with other
 * blockop operations.
 */

static void 
do_sched(struct proc *p)
{
	struct bop_dispatch	bop;

	bop.bop_func = sched_blockop;
	bop.bop_arg = NULL;
	bop.bop_prio = p->p_ctxt.info.priority;

	blockop_dispatch(&bop, p);
}

static int
do_stat(struct proc *p, struct sockaddr_un *sun, char **spp, struct stat *st, unsigned pflag)
{
	char			*dirname, *sp;
	struct st_blockop	stbl;
	struct bop_dispatch	bop;

	sp = *spp;
	if (sp == NULL) {
		/*
		 * dirname is "." which in turn is "/"
		 * due to procmgr_daemon()
		 */
		dirname = ".";
	}
	else {
		*sp = '\0';
		dirname = sun->sun_path;
	}

	strlcpy(stbl.path, dirname, sizeof(stbl.path));
	stbl.st = st;
	if (sp != NULL) {
		*sp = '/';
		sp++;
	}
	else {
		sp = sun->sun_path;
	}
	/* sp is now the basename */
	*spp = sp;

	bop.bop_func = stat_blockop;
	bop.bop_arg = &stbl;
	bop.bop_prio = p->p_ctxt.info.priority;

	p->p_flags |= pflag;
	blockop_dispatch(&bop, p);
	p->p_flags &= ~pflag;

	return stbl.error;
}

static void
vrele(struct vnode *vp)
{
	if (vp->v_id == -1) {
		/* abstract for which unlink will never come */
		assert(vp->v_attr.nlink == 1);
		LIST_REMOVE(vp, v_list);
		vp->v_list.le_next = NULL;
		vp->v_list.le_prev = NULL;
		vp->v_attr.nlink--;
		sref_free(vp->v_addr);
		vp->v_addr = NULL;
		free(vp, M_VNODE);
	}
	else if (vp->v_attr.nlink == 0)  {
		resmgr_detach(vp->v_dpp, vp->v_id, _RESMGR_DETACH_ALL);
		free(vp, M_VNODE);
	}

	return;
}

/* 
 * resmgr unlink connect funcs -- a UDS pathname can only be removed
 * by unlink().
 */
static int
vnode_unlink(resmgr_context_t *ctp, io_unlink_t *msg, RESMGR_HANDLE_T *handle, void *reserved) 
{
	struct vnode		*vp, *vp1;
	char			*ep, *sp;
	struct stat		st;
	int			error;
	struct proc		*p;
	struct _client_info	cinfo;
	iofunc_attr_t		attr;

	p = curproc;

	LIST_FOREACH(vp, &vn_list_head, v_list) {
		if (ctp->id == vp->v_id) {
			/* Do we have perms to unlink the under parent dir */
			sanitize_path(vp->v_addr, NULL, &ep, &sp);
			if ((error = do_stat(p, vp->v_addr, &sp, &st, P_RESMGR_KEY)) != EOK)
				return error;
			
			if (!S_ISDIR(st.st_mode))
				return EINVAL;

			/* perms to delete under dirname */
			if ((error = ConnectClientInfo_r(p->p_ctxt.info.scoid,
			    &cinfo, NGROUPS_MAX)) != EOK) {
				return error;
			}
			memset(&attr, 0x00, sizeof(attr));
			attr.uid = st.st_uid;
			attr.gid = st.st_gid;
			attr.mode = st.st_mode;
			if ((error = iofunc_check_access(&p->p_ctxt, &attr,
			    S_IWRITE, &cinfo)) != EOK) {
				return error;
			}

			/* As do_stat will cause a co-routine switch,
			 * double check that we are still on the list. If
			 * we are not, another request for the same
			 * pathname has reached this point and started the
			 * unlink. Just return ENOENT. The vp is not yet
			 * freed as the do_sched will again swap the
			 * co-routine to process this context before
			 * the free.
			 */

			LIST_FOREACH(vp1, &vn_list_head, v_list) {
				if (vp1 == vp)
					break;	
			}
			if (vp1 == NULL) {
				return ENOENT;
			}	

			LIST_REMOVE(vp, v_list);
			vp->v_list.le_next = NULL;
			vp->v_list.le_prev = NULL;

			if (--vp->v_attr.nlink != 0)
				panic("vnode_unlink");

			sref_free(vp->v_addr);
			vp->v_addr = NULL;

			if (vp->v_socket == NULL) {
				/* The resmgr_detach_ctp will remove the pathname
				 * in this context so vp (vnode) cannot be open()
				 * or connect() to, before we tsleep in
				 * do_sched(). The do_sched() will use blockop
				 * to serialize execution in the
				 * blockop so that the vp and be safely freed
				 * when we return from the tsleep. This is due
				 * to pseudo threading that could introduce
				 * race conditions in the do_stat() above if
				 * multiple unlinks on the same pathname occur.
				 */
				resmgr_detach(vp->v_dpp, vp->v_id, _RESMGR_DETACH_ALL);
				do_sched(p);
				free(vp, M_VNODE);
			}
			else {
				resmgr_detach(vp->v_dpp, vp->v_id, _RESMGR_DETACH_PATHNAME);
				/*
				 * _RESMGR_DETACH_ALL is still needed to release the link
				 * structure in the resmgr layer.  Done above in vrele()
				 * when the underlying socket itself is closed.
				 */
			}
			
			return EOK;
		}
	}
	return ENOENT;
}

static int
vnode_create(struct sockaddr_un *sun, struct proc *p, struct vnode **vpp,
    struct _client_info *info, iofunc_attr_t *dattr)
{
	struct vnode *vp;
	struct sun_ref *sref;
	proc_umask_t msg;

	if ((vp = malloc(sizeof(*vp), M_VNODE, M_WAITOK)) == NULL)
		return ENOMEM;

	memset(vp, 0, sizeof(*vp));

	if (sun->sun_path[0] == '\0') {
		/* abstract */
		vp->v_attr.nlink = 1;
		vp->v_id = -1;
	} else {
		msg.i.type = _PROC_UMASK;
		msg.i.subtype = _PROC_UMASK_GET;
		msg.i.umask = 0;
		msg.i.pid = p->p_ctxt.info.pid;

		if (MsgSendnc(PROCMGR_COID, &msg.i, sizeof(msg.i), &msg.o,
		    sizeof(msg.o)) == -1) {
			msg.o.umask = 0;
		}

		/*
		 * Following sets link count (attr.nlink) to 1 and link connect
		 * func callout to NULL.  Therefore the link count should only
		 * ever be 1 or 0.
		 */
		iofunc_attr_init(&vp->v_attr, S_IFSOCK | (0666 & ~msg.o.umask),
		    dattr, info);
		vp->v_dpp = p->p_ctxt.dpp;
		if (uds_cfuncs.nfuncs == 0) {
			iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &uds_cfuncs,
			    _RESMGR_IO_NFUNCS, &uds_iofuncs);
			uds_cfuncs.unlink = vnode_unlink;
		}
		if ((vp->v_id = resmgr_attach(vp->v_dpp, 0, sun->sun_path,
		    _FTYPE_SOCKET, 0, &uds_cfuncs, &uds_iofuncs,
		    &vp->v_attr)) == -1) {
			free(vp, M_VNODE);
			return *__get_errno_ptr();
		}
	}
	sref = SUN_TO_SREF(sun);
	sref->sr_ref++; /* vp now has a reference to sun */
	vp->v_addr = sun;
	LIST_INSERT_HEAD(&vn_list_head, vp, v_list);

	*vpp = vp;
	return EOK;
}

static struct
vnode *vnode_lookup(struct sockaddr_un *sun) {
	struct vnode *vp;
	
	LIST_FOREACH(vp, &vn_list_head, v_list) {
		if (vp->v_id == -1) {
			/*
			 * abstract.
			 *
			 * Note:
			 * We can't do this in all cases since
			 * sometimes bind is called with an addr where
			 * sun_len is greater than strlen(sun_path)
			 * (extra stuff that should be ignored in
			 * the non-abstract case).
			 */
			if (sun->sun_len == vp->v_addr->sun_len &&
			    memcmp(vp->v_addr, sun, sun->sun_len) == 0)
				break;
		}
		else if (strcmp(vp->v_addr->sun_path, sun->sun_path) == 0) {
			break;
		}
	}

	return vp;
}

#endif

/*
 * Unix communications domain.
 *
 * TODO:
 *	SEQPACKET, RDM
 *	rethink name space problems
 *	need a proper out-of-band
 */
const struct sockaddr_un sun_noname = {
	.sun_len = sizeof(sun_noname),
	.sun_family = AF_LOCAL,
};
ino_t	unp_ino;			/* prototype for fake inode numbers */

struct mbuf *unp_addsockcred(struct lwp *, struct mbuf *);

int
unp_output(struct mbuf *m, struct mbuf *control, struct unpcb *unp,
	struct lwp *l)
{
	struct socket *so2;
	const struct sockaddr_un *sun;

	so2 = unp->unp_conn->unp_socket;
	if (unp->unp_addr)
		sun = unp->unp_addr;
	else
		sun = &sun_noname;
	if (unp->unp_conn->unp_flags & UNP_WANTCRED)
		control = unp_addsockcred(l, control);
	if (sbappendaddr(&so2->so_rcv, (const struct sockaddr *)sun, m,
	    control) == 0) {
		unp_dispose(control);
		m_freem(control);
		m_freem(m);
		so2->so_rcv.sb_overflowed++;
		return (ENOBUFS);
	} else {
		sorwakeup(so2);
		return (0);
	}
}

void
unp_setsockaddr(struct unpcb *unp, struct mbuf *nam)
{
	const struct sockaddr_un *sun;

	if (unp->unp_addr)
		sun = unp->unp_addr;
	else
		sun = &sun_noname;
	nam->m_len = sun->sun_len;
	if (nam->m_len > MLEN)
		MEXTMALLOC(nam, nam->m_len, M_WAITOK);
	memcpy(mtod(nam, caddr_t), sun, (size_t)nam->m_len);
}

void
unp_setpeeraddr(struct unpcb *unp, struct mbuf *nam)
{
	const struct sockaddr_un *sun;

	if (unp->unp_conn && unp->unp_conn->unp_addr)
		sun = unp->unp_conn->unp_addr;
	else
		sun = &sun_noname;
	nam->m_len = sun->sun_len;
	if (nam->m_len > MLEN)
		MEXTMALLOC(nam, nam->m_len, M_WAITOK);
	memcpy(mtod(nam, caddr_t), sun, (size_t)nam->m_len);
}

/*ARGSUSED*/
int
uipc_usrreq(struct socket *so, int req, struct mbuf *m, struct mbuf *nam,
	struct mbuf *control, struct lwp *l)
{
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;
	struct proc *p;
	u_int newhiwat;
	int error = 0;

	if (req == PRU_CONTROL)
		return (EOPNOTSUPP);

#ifdef DIAGNOSTIC
	if (req != PRU_SEND && req != PRU_SENDOOB && control)
		panic("uipc_usrreq: unexpected control mbuf");
#endif
#ifndef __QNXNTO__
	p = l ? l->l_proc : NULL;
#else
	p = l ? LWP_TO_PR(l) : NULL;
#endif
	if (unp == 0 && req != PRU_ATTACH) {
		error = EINVAL;
		goto release;
	}

	switch (req) {

	case PRU_ATTACH:
		if (unp != 0) {
			error = EISCONN;
			break;
		}
		error = unp_attach(so);
		break;

	case PRU_DETACH:
		unp_detach(unp);
		break;

	case PRU_BIND:
		KASSERT(l != NULL);
		error = unp_bind(unp, nam, l);
		break;

	case PRU_LISTEN:
		if (unp->unp_vnode == 0)
			error = EINVAL;
		break;

	case PRU_CONNECT:
		KASSERT(l != NULL);
		error = unp_connect(so, nam, l);
		break;

	case PRU_CONNECT2:
		error = unp_connect2(so, (struct socket *)nam, PRU_CONNECT2);
		break;

	case PRU_DISCONNECT:
		unp_disconnect(unp);
		break;

	case PRU_ACCEPT:
		unp_setpeeraddr(unp, nam);
		/*
		 * Mark the initiating STREAM socket as connected *ONLY*
		 * after it's been accepted.  This prevents a client from
		 * overrunning a server and receiving ECONNREFUSED.
		 */
		if (unp->unp_conn != NULL &&
		    (unp->unp_conn->unp_socket->so_state & SS_ISCONNECTING))
			soisconnected(unp->unp_conn->unp_socket);
		break;

	case PRU_SHUTDOWN:
		socantsendmore(so);
		unp_shutdown(unp);
		break;

	case PRU_RCVD:
		switch (so->so_type) {

		case SOCK_DGRAM:
			panic("uipc 1");
			/*NOTREACHED*/

		case SOCK_STREAM:
#define	rcv (&so->so_rcv)
#define snd (&so2->so_snd)
			if (unp->unp_conn == 0)
				break;
			so2 = unp->unp_conn->unp_socket;
			/*
			 * Adjust backpressure on sender
			 * and wakeup any waiting to write.
			 */
			snd->sb_mbmax += unp->unp_mbcnt - rcv->sb_mbcnt;
			unp->unp_mbcnt = rcv->sb_mbcnt;
			newhiwat = snd->sb_hiwat + unp->unp_cc - rcv->sb_cc;
			(void)chgsbsize(so2->so_uidinfo,
			    &snd->sb_hiwat, newhiwat, RLIM_INFINITY);
			unp->unp_cc = rcv->sb_cc;
			sowwakeup(so2);
#undef snd
#undef rcv
			break;

		default:
			panic("uipc 2");
		}
		break;

	case PRU_SEND:
		/*
		 * Note: unp_internalize() rejects any control message
		 * other than SCM_RIGHTS, and only allows one.  This
		 * has the side-effect of preventing a caller from
		 * forging SCM_CREDS.
		 */
		if (control) {
			KASSERT(l != NULL);
			if ((error = unp_internalize(control, l)) != 0)
				goto die;
		}
		switch (so->so_type) {

		case SOCK_DGRAM: {
			if (nam) {
				if ((so->so_state & SS_ISCONNECTED) != 0) {
					error = EISCONN;
					goto die;
				}
				KASSERT(l != NULL);
				error = unp_connect(so, nam, l);
				if (error) {
				die:
					unp_dispose(control);
					m_freem(control);
					m_freem(m);
					break;
				}
			} else {
				if ((so->so_state & SS_ISCONNECTED) == 0) {
					error = ENOTCONN;
					goto die;
				}
			}
			KASSERT(p != NULL);
			error = unp_output(m, control, unp, l);
			if (nam)
				unp_disconnect(unp);
			break;
		}

		case SOCK_STREAM:
#define	rcv (&so2->so_rcv)
#define	snd (&so->so_snd)
			if (unp->unp_conn == NULL) {
				error = ENOTCONN;
				break;
			}
			so2 = unp->unp_conn->unp_socket;
			if (unp->unp_conn->unp_flags & UNP_WANTCRED) {
				/*
				 * Credentials are passed only once on
				 * SOCK_STREAM.
				 */
				unp->unp_conn->unp_flags &= ~UNP_WANTCRED;
				control = unp_addsockcred(l, control);
			}
			/*
			 * Send to paired receive port, and then reduce
			 * send buffer hiwater marks to maintain backpressure.
			 * Wake up readers.
			 */
			if (control) {
				if (sbappendcontrol(rcv, m, control) == 0) {
					unp_dispose(control);
					m_freem(control);
				}
			} else
				sbappend(rcv, m);
			snd->sb_mbmax -=
			    rcv->sb_mbcnt - unp->unp_conn->unp_mbcnt;
			unp->unp_conn->unp_mbcnt = rcv->sb_mbcnt;
			newhiwat = snd->sb_hiwat -
			    (rcv->sb_cc - unp->unp_conn->unp_cc);
			(void)chgsbsize(so->so_uidinfo,
			    &snd->sb_hiwat, newhiwat, RLIM_INFINITY);
			unp->unp_conn->unp_cc = rcv->sb_cc;
			sorwakeup(so2);
#undef snd
#undef rcv
			break;

		default:
			panic("uipc 4");
		}
		break;

	case PRU_ABORT:
		unp_drop(unp, ECONNABORTED);

		KASSERT(so->so_head == NULL);
#ifdef DIAGNOSTIC
		if (so->so_pcb == 0)
			panic("uipc 5: drop killed pcb");
#endif
		unp_detach(unp);
#ifdef __QNXNTO__
		sofree(so);
#endif
		break;

	case PRU_SENSE:
#ifdef __QNXNTO__
		/*
		 * Non NULL nam parameter means true protocol
		 * specific info is being requested rather than
		 * the generic fstat().
		 */
		if (nam != NULL) {
#ifndef OPT_PRU_SENSE_EXTEN
			return EOPNOTSUPP;
#else
			struct proto_sensereq *prs;
			char *dst;

			prs = (struct proto_sensereq *)nam;

			switch (prs->prs_how) {
			case PRSENSEREQ_STRING:
				dst = (char *)m;

				error = uipc_format(so, so->so_proto->pr_type, dst, &prs->prs_maxlen);
				if (error)
					return error;
				break;

			default:
				return EOPNOTSUPP;
			}

			return 0;
#endif
		}
#endif
		((struct stat *) m)->st_blksize = so->so_snd.sb_hiwat;
		if (so->so_type == SOCK_STREAM && unp->unp_conn != 0) {
			so2 = unp->unp_conn->unp_socket;
			((struct stat *) m)->st_blksize += so2->so_rcv.sb_cc;
		}
		((struct stat *) m)->st_dev = NODEV;
		if (unp->unp_ino == 0)
			unp->unp_ino = unp_ino++;
#ifndef __QNXNTO__
		((struct stat *) m)->st_atimespec =
		    ((struct stat *) m)->st_mtimespec =
		    ((struct stat *) m)->st_ctimespec = unp->unp_ctime;
#else
		((struct stat *) m)->st_atime =
		    ((struct stat *) m)->st_mtime =
		    ((struct stat *) m)->st_ctime = unp->unp_ctime.tv_sec;
#endif
		((struct stat *) m)->st_ino = unp->unp_ino;
		return (0);

	case PRU_RCVOOB:
		error = EOPNOTSUPP;
		break;

	case PRU_SENDOOB:
		m_freem(control);
		m_freem(m);
		error = EOPNOTSUPP;
		break;

	case PRU_SOCKADDR:
		unp_setsockaddr(unp, nam);
		break;

	case PRU_PEERADDR:
		unp_setpeeraddr(unp, nam);
		break;

	default:
		panic("piusrreq");
	}

release:
	return (error);
}

/*
 * Unix domain socket option processing.
 */
int
uipc_ctloutput(int op, struct socket *so, int level, int optname,
	struct mbuf **mp)
{
	struct unpcb *unp = sotounpcb(so);
	struct mbuf *m = *mp;
	int optval = 0, error = 0;

	if (level != 0) {
		error = EINVAL;
		if (op == PRCO_SETOPT && m)
			(void) m_free(m);
	} else switch (op) {

	case PRCO_SETOPT:
		switch (optname) {
		case LOCAL_CREDS:
		case LOCAL_CONNWAIT:
			if (m == NULL || m->m_len != sizeof(int))
				error = EINVAL;
			else {
				optval = *mtod(m, int *);
				switch (optname) {
#define	OPTSET(bit) \
	if (optval) \
		unp->unp_flags |= (bit); \
	else \
		unp->unp_flags &= ~(bit);

				case LOCAL_CREDS:
					OPTSET(UNP_WANTCRED);
					break;
				case LOCAL_CONNWAIT:
					OPTSET(UNP_CONNWAIT);
					break;
				}
			}
			break;
#undef OPTSET

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m)
			(void) m_free(m);
		break;

	case PRCO_GETOPT:
		switch (optname) {
		case LOCAL_PEEREID:
			if (unp->unp_flags & UNP_EIDSVALID) {
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(struct unpcbid);
				*mtod(m, struct unpcbid *) = unp->unp_connid;
			} else {
				error = EINVAL;
			}
			break;
		case LOCAL_CREDS:
			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			m->m_len = sizeof(int);
			switch (optname) {

#define	OPTBIT(bit)	(unp->unp_flags & (bit) ? 1 : 0)

			case LOCAL_CREDS:
				optval = OPTBIT(UNP_WANTCRED);
				break;
			}
			*mtod(m, int *) = optval;
			break;
#undef OPTBIT

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	return (error);
}

/*
 * Both send and receive buffers are allocated PIPSIZ bytes of buffering
 * for stream sockets, although the total for sender and receiver is
 * actually only PIPSIZ.
 * Datagram sockets really use the sendspace as the maximum datagram size,
 * and don't really want to reserve the sendspace.  Their recvspace should
 * be large enough for at least one max-size datagram plus address.
 */
#ifndef __QNXNTO__
#define	PIPSIZ	4096
#else
 #ifndef PIPE_BUF
  #define PIPE_BUF 5120
 #endif
 #define PIPSIZ PIPE_BUF
#endif
u_long	unpst_sendspace = PIPSIZ;
u_long	unpst_recvspace = PIPSIZ;
u_long	unpdg_sendspace = 2*1024;	/* really max datagram size */
u_long	unpdg_recvspace = 4*1024;

int	unp_rights;			/* file descriptors in flight */

int
unp_attach(struct socket *so)
{
	struct unpcb *unp;
	int error;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		switch (so->so_type) {

		case SOCK_STREAM:
			error = soreserve(so, unpst_sendspace, unpst_recvspace);
			break;

		case SOCK_DGRAM:
			error = soreserve(so, unpdg_sendspace, unpdg_recvspace);
			break;

		default:
			panic("unp_attach");
		}
		if (error)
			return (error);
	}
	unp = malloc(sizeof(*unp), M_PCB, M_NOWAIT);
	if (unp == NULL)
		return (ENOBUFS);
	memset((caddr_t)unp, 0, sizeof(*unp));
	unp->unp_socket = so;
	so->so_pcb = unp;
#ifdef __QNXNTO__
	CIRCLEQ_INSERT_HEAD(&unbtable.unpt_queue, unp, unp_queue);
#endif
	nanotime(&unp->unp_ctime);
	return (0);
}

void
unp_detach(struct unpcb *unp)
{

#ifdef __QNXNTO__
	CIRCLEQ_REMOVE(&unbtable.unpt_queue, unp, unp_queue);
#endif
	if (unp->unp_vnode) {
		unp->unp_vnode->v_socket = 0;
		vrele(unp->unp_vnode);
		unp->unp_vnode = 0;
	}
	if (unp->unp_conn)
		unp_disconnect(unp);
	while (unp->unp_refs)
		unp_drop(unp->unp_refs, ECONNRESET);
	soisdisconnected(unp->unp_socket);
	unp->unp_socket->so_pcb = 0;
	if (unp->unp_addr)
#ifndef __QNXNTO__
		free(unp->unp_addr, M_SONAME);
#else
		sref_free(unp->unp_addr);
#endif
	if (unp_rights) {
		/*
		 * Normally the receive buffer is flushed later,
		 * in sofree, but if our receive buffer holds references
		 * to descriptors that are now garbage, we will dispose
		 * of those descriptor references after the garbage collector
		 * gets them (resulting in a "panic: closef: count < 0").
		 */
		sorflush(unp->unp_socket);
		free(unp, M_PCB);
#ifndef __QNXNTO__
		unp_gc();
#endif
	} else
		free(unp, M_PCB);
}

int
unp_bind(struct unpcb *unp, struct mbuf *nam, struct lwp *l)
{
	struct sockaddr_un *sun;
	struct vnode *vp;
#ifndef __QNXNTO__
	struct mount *mp;
	struct vattr vattr;
#endif	
	size_t addrlen;
	struct proc *p;
	int error;
#ifndef __QNXNTO__
	struct nameidata nd;
#else
	struct stat		st;
	char			*ep, *sp;
	iofunc_attr_t		attr;
	struct _client_info	cinfo;
#endif	

	if (unp->unp_vnode != 0)
		return (EINVAL);

#ifndef __QNXNTO__
	p = l->l_proc;
#else
	p = LWP_TO_PR(l);
#endif
	/*
	 * Allocate the new sockaddr.  We have to allocate one
	 * extra byte so that we can ensure that the pathname
	 * is nul-terminated.
	 */
	addrlen = nam->m_len + 1;
#ifndef __QNXNTO__
	sun = malloc(addrlen, M_SONAME, M_WAITOK);
#else
	sun = mtod(nam, struct sockaddr_un *);
	/* Sanity */
	if (sun->sun_len != nam->m_len)
		return EINVAL;
	sun = sref_alloc(addrlen);
#endif
	m_copydata(nam, 0, nam->m_len, (caddr_t)sun);
	*(((char *)sun) + nam->m_len) = '\0';

#ifdef __QNXNTO__
	error = EINVAL;
	if (sun->sun_len <= offsetof(struct sockaddr_un, sun_path) ||
	    (error = ConnectClientInfo_r(p->p_ctxt.info.scoid, &cinfo,
	    NGROUPS_MAX)) != EOK) {
		goto bad;
	}

	if (sun->sun_path[0] != '\0') {
		/* Not abstract */
		sanitize_path(sun, &addrlen, &ep, &sp);
		if (ep == sun->sun_path) {
			/* "/"  which we don't support */
			error = ENOENT;
			goto bad;
		}
	}
	else {
		/* 'abstract' UDS */
		goto vcreate;
	}

	if ((error = do_stat(p, sun, &sp, &st, 0)) != EOK)
		goto bad;

	if (!S_ISDIR(st.st_mode) || sp == ep) {
		error = EADDRINUSE;
		goto bad;
	}

	/* perms to create under dirname */
	memset(&attr, 0x00, sizeof(attr));
	attr.uid = st.st_uid;
	attr.gid = st.st_gid;
	attr.mode = st.st_mode;
	if ((error = iofunc_check_access(&p->p_ctxt, &attr, S_IWRITE,
	    &cinfo)) != EOK) {
		goto bad;
	}


	sp = ep;
	error = do_stat(p, sun, &sp, &st, 0);
	*ep = '\0';

	/*
	 * We could allow existing sockets to be overlaid
	 * as long as it's not one of our own which could
	 * be caught by a vnode_lookup() as a particular
	 * instance could be targeted with SOCK=/foo and
	 * connect(); however an unlink() couldn't be
	 * targeted so we don't overlay.
	 */

#if 0
	if (error != EOK && error != ENOENT)
		goto bad;

	if (error == EOK && !S_ISSOCK(st.st_mode)) {
		error = EADDRINUSE;
		goto bad;
	}

	/* Make sure it's not one of our own */
	if (vnode_lookup(sun->sun_path) != NULL) {
		error = EADDRINUSE;
		goto bad;
	}
#else
	if (error == EOK) {
		error = EADDRINUSE;
		goto bad;
	}
	else if	(error != ENOENT) {
		goto bad;
	}
#endif

vcreate:
	/* OK, let's create it */
	error = vnode_create(sun, p, &vp, &cinfo, &attr);
	if (error)
		goto bad;
#else	
restart:
	NDINIT(&nd, CREATE, FOLLOW | LOCKPARENT, UIO_SYSSPACE,
	    sun->sun_path, l);

/* SHOULD BE ABLE TO ADOPT EXISTING AND wakeup() ALA FIFO's */
	if ((error = namei(&nd)) != 0)
		goto bad;
	vp = nd.ni_vp;
	if (vp != NULL || vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		if (vp != NULL) {
			error = EADDRINUSE;
			goto bad;
		}
		error = vn_start_write(NULL, &mp,
		    V_WAIT | V_SLEEPONLY | V_PCATCH);
		if (error)
			goto bad;
		goto restart;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VSOCK;
	vattr.va_mode = ACCESSPERMS & ~(p->p_cwdi->cwdi_cmask);
	VOP_LEASE(nd.ni_dvp, l, l->l_cred, LEASE_WRITE);
	error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	vn_finished_write(mp, 0);
	if (error)
		goto bad;
	vp = nd.ni_vp;
#endif
	vp->v_socket = unp->unp_socket;
	unp->unp_vnode = vp;
	unp->unp_addrlen = addrlen;
	unp->unp_addr = sun;

 	unp->unp_connid.unp_pid = cinfo.pid;
	unp->unp_connid.unp_euid = cinfo.cred.euid;
	unp->unp_connid.unp_egid = cinfo.cred.egid;
	unp->unp_flags |= UNP_EIDSBIND;
	VOP_UNLOCK(vp, 0);
	return (0);

 bad:
#ifndef __QNXNTO__
	free(sun, M_SONAME);
#else
	sref_free(sun);
#endif
	return (error);
}

int
unp_connect(struct socket *so, struct mbuf *nam, struct lwp *l)
{
	struct sockaddr_un *sun;
	struct vnode *vp;
	struct socket *so2, *so3;
	struct unpcb *unp, *unp2, *unp3;
	size_t addrlen;
	int error;
#ifndef __QNXNTO__
	struct nameidata nd;
#else
	struct _client_info info;
	struct proc *p;

	p = LWP_TO_PR(l);
#endif

	/*
	 * Allocate a temporary sockaddr.  We have to allocate one extra
	 * byte so that we can ensure that the pathname is nul-terminated.
	 * When we establish the connection, we copy the other PCB's
	 * sockaddr to our own.
	 */
	addrlen = nam->m_len + 1;
#ifdef __QNXNTO__
	/* The following one's temporary so sref_[alloc/free] aren't needed */
#endif
	sun = malloc(addrlen, M_SONAME, M_WAITOK);
	m_copydata(nam, 0, nam->m_len, (caddr_t)sun);
	*(((char *)sun) + nam->m_len) = '\0';

#ifdef __QNXNTO__
	if (nam->m_len <= offsetof(struct sockaddr_un, sun_path)) {
		error = EINVAL;
		goto bad2;
	}
	else if (sun->sun_path[0] != '\0') {
		/* Not abstract */
		sanitize_path(sun, &addrlen, NULL, NULL);
	}


	if ((vp = vnode_lookup(sun)) == NULL) {
		error = ENOENT;
		goto bad2;
	}

	if ((error = ConnectClientInfo_r(p->p_ctxt.info.scoid, &info, NGROUPS_MAX)) != 0)
		goto bad2;
	
	if (vp->v_id == -1) {
		/* abstract.  No perm checking.  Better use getpeereid() */
	} else if ((error = iofunc_check_access(&p->p_ctxt, &vp->v_attr,
	    S_IWRITE, &info)) != 0) {
		goto bad2;
	}
	
#else	
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, sun->sun_path, l);

	if ((error = namei(&nd)) != 0)
		goto bad2;
	vp = nd.ni_vp;
	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		goto bad;
	}
	if ((error = VOP_ACCESS(vp, VWRITE, l->l_cred, l)) != 0)
		goto bad;
#endif
	so2 = vp->v_socket;
	if (so2 == 0) {
		error = ECONNREFUSED;
		goto bad;
	}
	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		goto bad;
	}
	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		if ((so2->so_options & SO_ACCEPTCONN) == 0 ||
		    (so3 = sonewconn(so2, 0)) == 0) {
			error = ECONNREFUSED;
			goto bad;
		}
		unp = sotounpcb(so);
		unp2 = sotounpcb(so2);
		unp3 = sotounpcb(so3);
		if (unp2->unp_addr) {
#ifndef __QNXNTO__
			unp3->unp_addr = malloc(unp2->unp_addrlen,
			    M_SONAME, M_WAITOK);
#else
			unp3->unp_addr = sref_alloc(unp2->unp_addrlen);
#endif
			memcpy(unp3->unp_addr, unp2->unp_addr,
			    unp2->unp_addrlen);
			unp3->unp_addrlen = unp2->unp_addrlen;
		}
		unp3->unp_flags = unp2->unp_flags;

		unp3->unp_connid.unp_pid = info.pid;
		unp3->unp_connid.unp_euid = info.cred.euid; /* kauth_cred_geteuid(l->l_cred); */
		unp3->unp_connid.unp_egid = info.cred.egid; /* kauth_cred_getegid(l->l_cred); */
		unp3->unp_flags |= UNP_EIDSVALID;
		so2 = so3;
		if (unp2->unp_flags & UNP_EIDSBIND) {
			unp->unp_connid = unp2->unp_connid;
			unp->unp_flags |= UNP_EIDSVALID;
		}
	}
	error = unp_connect2(so, so2, PRU_CONNECT);
 bad:
#ifndef __QNXNTO__
	vput(vp);
#endif
 bad2:
	free(sun, M_SONAME);
	return (error);
}

int
unp_connect2(struct socket *so, struct socket *so2, int req)
{
	struct unpcb *unp = sotounpcb(so);
	struct unpcb *unp2;

	if (so2->so_type != so->so_type)
		return (EPROTOTYPE);
	unp2 = sotounpcb(so2);
	unp->unp_conn = unp2;
	switch (so->so_type) {

	case SOCK_DGRAM:
		unp->unp_nextref = unp2->unp_refs;
		unp2->unp_refs = unp;
		soisconnected(so);
		break;

	case SOCK_STREAM:
		unp2->unp_conn = unp;
		if (req == PRU_CONNECT &&
		    ((unp->unp_flags | unp2->unp_flags) & UNP_CONNWAIT))
			soisconnecting(so);
		else
			soisconnected(so);
		soisconnected(so2);
		break;

	default:
		panic("unp_connect2");
	}
	return (0);
}

void
unp_disconnect(struct unpcb *unp)
{
	struct unpcb *unp2 = unp->unp_conn;

	if (unp2 == 0)
		return;
	unp->unp_conn = 0;
	switch (unp->unp_socket->so_type) {

	case SOCK_DGRAM:
		if (unp2->unp_refs == unp)
			unp2->unp_refs = unp->unp_nextref;
		else {
			unp2 = unp2->unp_refs;
			for (;;) {
				if (unp2 == 0)
					panic("unp_disconnect");
				if (unp2->unp_nextref == unp)
					break;
				unp2 = unp2->unp_nextref;
			}
			unp2->unp_nextref = unp->unp_nextref;
		}
		unp->unp_nextref = 0;
		unp->unp_socket->so_state &= ~SS_ISCONNECTED;
		break;

	case SOCK_STREAM:
		soisdisconnected(unp->unp_socket);
		unp2->unp_conn = 0;
		soisdisconnected(unp2->unp_socket);
		break;
	}
}

#ifdef notdef
unp_abort(struct unpcb *unp)
{
	unp_detach(unp);
}
#endif

void
unp_shutdown(struct unpcb *unp)
{
	struct socket *so;

	if (unp->unp_socket->so_type == SOCK_STREAM && unp->unp_conn &&
	    (so = unp->unp_conn->unp_socket))
		socantrcvmore(so);
}

void
unp_drop(struct unpcb *unp, int errno)
{
	struct socket *so = unp->unp_socket;

	so->so_error = errno;
	unp_disconnect(unp);
	if (so->so_head) {
		so->so_pcb = 0;
		sofree(so);
		if (unp->unp_addr)
#ifndef __QNXNTO__
			free(unp->unp_addr, M_SONAME);
#else
			sref_free(unp->unp_addr);
#endif
		free(unp, M_PCB);
	}
}

#ifdef notdef
unp_drain(void)
{

}
#endif

#ifndef __QNXNTO__
int
unp_externalize(struct mbuf *rights, struct lwp *l)
{
	struct cmsghdr *cm = mtod(rights, struct cmsghdr *);
	struct proc *p = l->l_proc;
	int i, *fdp;
	struct file **rp;
	struct file *fp;
	int nfds, error = 0;

	nfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm))) /
	    sizeof(struct file *);
	rp = (struct file **)CMSG_DATA(cm);

	fdp = malloc(nfds * sizeof(int), M_TEMP, M_WAITOK);

	/* Make sure the recipient should be able to see the descriptors.. */
	if (p->p_cwdi->cwdi_rdir != NULL) {
		rp = (struct file **)CMSG_DATA(cm);
		for (i = 0; i < nfds; i++) {
			fp = *rp++;
			/*
			 * If we are in a chroot'ed directory, and
			 * someone wants to pass us a directory, make
			 * sure it's inside the subtree we're allowed
			 * to access.
			 */
			if (fp->f_type == DTYPE_VNODE) {
				struct vnode *vp = (struct vnode *)fp->f_data;
				if ((vp->v_type == VDIR) &&
				    !vn_isunder(vp, p->p_cwdi->cwdi_rdir, l)) {
					error = EPERM;
					break;
				}
			}
		}
	}

 restart:
	rp = (struct file **)CMSG_DATA(cm);
	if (error != 0) {
		for (i = 0; i < nfds; i++) {
			fp = *rp;
			/*
			 * zero the pointer before calling unp_discard,
			 * since it may end up in unp_gc()..
			 */
			*rp++ = 0;
			unp_discard(fp);
		}
		goto out;
	}

	/*
	 * First loop -- allocate file descriptor table slots for the
	 * new descriptors.
	 */
	for (i = 0; i < nfds; i++) {
		fp = *rp++;
		if ((error = fdalloc(p, 0, &fdp[i])) != 0) {
			/*
			 * Back out what we've done so far.
			 */
			for (--i; i >= 0; i--)
				fdremove(p->p_fd, fdp[i]);

			if (error == ENOSPC) {
				fdexpand(p);
				error = 0;
			} else {
				/*
				 * This is the error that has historically
				 * been returned, and some callers may
				 * expect it.
				 */
				error = EMSGSIZE;
			}
			goto restart;
		}

		/*
		 * Make the slot reference the descriptor so that
		 * fdalloc() works properly.. We finalize it all
		 * in the loop below.
		 */
		p->p_fd->fd_ofiles[fdp[i]] = fp;
	}

	/*
	 * Now that adding them has succeeded, update all of the
	 * descriptor passing state.
	 */
	rp = (struct file **)CMSG_DATA(cm);
	for (i = 0; i < nfds; i++) {
		fp = *rp++;
		fp->f_msgcount--;
		unp_rights--;
	}

	/*
	 * Copy temporary array to message and adjust length, in case of
	 * transition from large struct file pointers to ints.
	 */
	memcpy(CMSG_DATA(cm), fdp, nfds * sizeof(int));
	cm->cmsg_len = CMSG_LEN(nfds * sizeof(int));
	rights->m_len = CMSG_SPACE(nfds * sizeof(int));
 out:
	free(fdp, M_TEMP);
	return (error);
}
#else

int
unp_externalize(struct mbuf *rights, struct lwp *l, int flags)
{
	pid_t			savepid;
	iov_t			iov;
	struct cmsghdr		*cm;
	int			nfds, i, newfd, error, savefd;
	io_dup_t		*dup;
	struct proc		*p;

	p = LWP_TO_PR(l);
	error = 0;

	cm = mtod(rights, struct cmsghdr *);
	nfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm))) / sizeof(io_dup_t);

	dup = (io_dup_t *)CMSG_DATA(cm);
	for (i = 0; i < nfds; i++) {
		if (flags & DOM_EXTEN) {
			/*
			 * We're handling a request from a newer
			 * libsocket so set up the dup message
			 * to operate on our internally dup'd
			 * fd.
			 */
			newfd = dup->i.info.priority;
			savepid = dup->i.info.pid;
			savefd = dup->i.info.priority;
			if (ConnectServerInfo_r(getpid(), newfd,
			    &dup->i.info) != newfd) {
				error = EBADF;
				break;
			}
			/* Overload the thread id to carry sender's pid (us) */
			dup->i.info.tid = getpid();
			dup->i.info.pid = savepid;
		}
		savepid = dup->i.info.pid;
		dup->i.info.pid = dup->i.info.tid;

		SETIOV(&iov, dup, offsetof(io_dup_t, i.key));
		if (flags & DOM_EXTEN) {
			MsgKeyData(p->p_ctxt.rcvid, _NTO_KEYDATA_CALCULATE,
			    0, &dup->i.key, &iov, 1);
		}
		else {
			/*
			 * The old recvmsg sent the dup after the 
			 * peek at which point we've done the
			 * unp_discard() and set the fd to -1
			 */
			dup->i.info.priority = -1;
			MsgKeyData(p->p_ctxt.rcvid, _NTO_KEYDATA_CALCULATE,
			    0, &dup->i.key, &iov, 1);
			dup->i.info.priority = savefd;
		}

		if ((flags & DOM_PEEK) == 0) {
			unp_discard(dup);
		}

		dup->i.info.pid = savepid;
		dup++;
	}

	if (error != 0 && (flags & DOM_PEEK) == 0) {
		dup = (io_dup_t *)CMSG_DATA(cm);
		for (i = 0; i < nfds; i++) {
			unp_discard(dup);
			dup++;
		}
	}


	return error;
}
#endif

#ifndef __QNXNTO__
int
unp_internalize(struct mbuf *control, struct lwp *l)
{
	struct proc *p = l->l_proc;
	struct filedesc *fdescp = p->p_fd;
	struct cmsghdr *newcm, *cm = mtod(control, struct cmsghdr *);
	struct file **rp, **files;
	struct file *fp;
	int i, fd, *fdp;
	int nfds;
	u_int neededspace;

	/* Sanity check the control message header */
	if (cm->cmsg_type != SCM_RIGHTS || cm->cmsg_level != SOL_SOCKET ||
	    cm->cmsg_len != control->m_len)
		return (EINVAL);

	/* Verify that the file descriptors are valid */
	nfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm))) / sizeof(int);
	fdp = (int *)CMSG_DATA(cm);
	for (i = 0; i < nfds; i++) {
		fd = *fdp++;
		if ((fp = fd_getfile(fdescp, fd)) == NULL)
			return (EBADF);
		simple_unlock(&fp->f_slock);
	}

	/* Make sure we have room for the struct file pointers */
	neededspace = CMSG_SPACE(nfds * sizeof(struct file *)) -
	    control->m_len;
	if (neededspace > M_TRAILINGSPACE(control)) {

		/* allocate new space and copy header into it */
		newcm = malloc(
		    CMSG_SPACE(nfds * sizeof(struct file *)),
		    M_MBUF, M_WAITOK);
		if (newcm == NULL)
			return (E2BIG);
		memcpy(newcm, cm, sizeof(struct cmsghdr));
		files = (struct file **)CMSG_DATA(newcm);
	} else {
		/* we can convert in-place */
		newcm = NULL;
		files = (struct file **)CMSG_DATA(cm);
	}

	/*
	 * Transform the file descriptors into struct file pointers, in
	 * reverse order so that if pointers are bigger than ints, the
	 * int won't get until we're done.
	 */
	fdp = (int *)CMSG_DATA(cm) + nfds;
	rp = files + nfds;
	for (i = 0; i < nfds; i++) {
		fp = fdescp->fd_ofiles[*--fdp];
		simple_lock(&fp->f_slock);
#ifdef DIAGNOSTIC
		if (fp->f_iflags & FIF_WANTCLOSE)
			panic("unp_internalize: file already closed");
#endif
		*--rp = fp;
		fp->f_count++;
		fp->f_msgcount++;
		simple_unlock(&fp->f_slock);
		unp_rights++;
	}

	if (newcm) {
		if (control->m_flags & M_EXT)
			MEXTREMOVE(control);
		MEXTADD(control, newcm,
		    CMSG_SPACE(nfds * sizeof(struct file *)),
		    M_MBUF, NULL, NULL);
		cm = newcm;
	}

	/* adjust message & mbuf to note amount of space actually used. */
	cm->cmsg_len = CMSG_LEN(nfds * sizeof(struct file *));
	control->m_len = CMSG_SPACE(nfds * sizeof(struct file *));
	return (0);
}

#else

static void
clearfds(io_dup_t *dup, int num)
{
	int			i;

	for (i = 0; i < num; i++) {
		close(dup->i.info.priority);
		dup->i.info.priority = -1;
		unp_rights--;
		dup--;
	}
}

struct dup_arg {
	pid_t		pid;
	int		nfds;
	int		*fdp;
	io_dup_t	*rp;
	int		ret;
};

static void thread_wakeup (void *arg)
{
	wakeup(arg);
}

static void* dup_thread (void *arg)
{
	struct _server_info	info;
	char			namebuf[32];
	pid_t			savepid;
	struct dup_arg		*da;
	int			*fdp;
	io_dup_t		*rp, *rp_save;
	int			i, newfd;

	da = arg;
	fdp = da->fdp;
	rp = da->rp;
	rp_save = rp;

	snprintf(namebuf, sizeof(namebuf), "FD Dup %d", da->pid);
	pthread_setname_np(gettid(), namebuf);

	for (i = 0; i < da->nfds; i++) {
		newfd = ConnectServerInfo_r(da->pid, *fdp, &info);
		if (newfd != *fdp) {
			da->ret = EBADF;
			clearfds(rp_save, i);
			stk_context_callback_2(thread_wakeup, arg, NULL);
			return NULL;
		}

		rp->i.info.nd = info.nd;
		rp->i.info.pid = info.pid;
		rp->i.info.chid = info.chid;
		rp->i.info.scoid = info.scoid;
		rp->i.info.coid = info.coid;
		rp->i.type = _IO_DUP;
		rp->i.combine_len = sizeof(rp->i);

		if ((newfd = ConnectAttach(rp->i.info.nd, rp->i.info.pid,
					   rp->i.info.chid, 0,
					   _NTO_COF_NOEVENT)) == -1) {
			da->ret = EBADF;
			clearfds(rp_save, i);
			stk_context_callback_2(thread_wakeup, arg, NULL);
			return NULL;
		}

		savepid = rp->i.info.pid;
		rp->i.info.pid = da->pid;

		if (MsgSendnc_r(newfd, &rp->i, sizeof(rp->i), NULL, 0) < 0) {
			ConnectDetach_r(newfd);
			da->ret = EBADF;
			clearfds(rp_save, i);
			stk_context_callback_2(thread_wakeup, arg, NULL);
			return NULL;
		}

		rp->i.info.priority = newfd;
		unp_rights++;

		/* Overload the thread id to carry sender's pid */
		rp->i.info.tid = da->pid;
		rp->i.info.pid = savepid;

		/*
		 * We've done our internal dup at this point,
		 * but we've set up the "to be passed out" dup
		 * message to operate on the sender's fd for
		 * compatibility with older libsockets.  We'll
		 * override this to operate on our internally
		 * dup'd instance in unp_externalize() if it's
		 * called as a result of a newer recvmsg().
		 */

		rp--;
		fdp--;
	}
	da->ret = EOK;
	stk_context_callback_2(thread_wakeup, arg, NULL);
	return NULL;
}

int
unp_internalize(struct mbuf *control, struct lwp *l)
{
	struct cmsghdr		*newcm, *cm;
	struct proc		*p = LWP_TO_PR(l);
	io_dup_t		*dupes;
	size_t			size;
	int			nfds;
	u_int			neededspace;
	struct dup_arg		da;
	pthread_t		tid;

	p = LWP_TO_PR(l);
	cm = mtod(control, struct cmsghdr *);

	/* Sanity check the control message header */
	if (cm->cmsg_type != SCM_RIGHTS || cm->cmsg_level != SOL_SOCKET ||
	    cm->cmsg_len > control->m_len ||
	    cm->cmsg_len < CMSG_ALIGN(sizeof(*cm)))
		return (EINVAL);

	/* Verify that the file descriptors are valid */
	nfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm))) / sizeof(int);

	/* the only test we can do, is do a ConnectServerInfo() on each fd, 
	 * we will do that later anyway, so skip this test here.
	 */

	/* Make sure we have room for the io_dup structures */
	neededspace = CMSG_SPACE(nfds * sizeof(io_dup_t)) -
	    control->m_len;
	if (neededspace > M_TRAILINGSPACE(control)) {
		/* allocate new space and copy header into it */
		size = CMSG_SPACE(nfds * sizeof(io_dup_t));
		newcm = MEXTMALLOC_ALLOC(size, M_MBUF, M_NOWAIT);
		if (newcm == NULL)
			return (E2BIG);
		memcpy(newcm, cm, sizeof(struct cmsghdr));
		dupes = (io_dup_t *)CMSG_DATA(newcm);		
	} else {
		/* we can convert in-place */
		newcm = NULL;
		dupes = (io_dup_t *)CMSG_DATA(cm);
	}

	/*
	 * Transform the file descriptors into io_dup_ts, in
	 * reverse order since io_dup_ts are bigger than ints
	 * (the int won't get clobered until we're done).
	 */
	da.pid = p->p_ctxt.info.pid;
	da.nfds = nfds;
	da.fdp = ((int *)CMSG_DATA(cm)) + nfds - 1;
	da.rp = dupes + nfds - 1;

	if (pthread_create(&tid, NULL, dup_thread, &da) != EOK) {
	    if (newcm != NULL) {
		free(newcm, M_MBUF);
	    }
	    return EBADF;
	}
	ltsleep(&da, 0, "FD Dup", 0, NULL);
	pthread_join(tid, NULL);
	if (da.ret != EOK) {
	    if (newcm != NULL) {
		free(newcm, M_MBUF);
	    }
	    return EBADF;
	}

	if (newcm) {
		if (control->m_flags & M_EXT)
			mextremove(control);
		MEXTADD(control, newcm,
		    CMSG_SPACE(nfds * sizeof(io_dup_t)),
		    M_MBUF, NULL, NULL, MEXTMALLOC_REFCNTP(newcm, size));
		cm = newcm;
	}

	/* adjust message & mbuf to note amount of space actually used. */
	cm->cmsg_len = CMSG_LEN(nfds * sizeof(io_dup_t));
	control->m_len = CMSG_SPACE(nfds * sizeof(io_dup_t));
	
	return (0);
}
#endif

struct mbuf *
unp_addsockcred(struct lwp *l, struct mbuf *control)
{
	struct cmsghdr *cmp;
	struct sockcred *sc;
	struct mbuf *m, *n;
	int len, space, i;

#if defined(__QNXNTO__)	
	struct _client_info cinfo;
	struct proc *p;

	p = LWP_TO_PR(l);

	if (ConnectClientInfo_r(p->p_ctxt.info.scoid, &cinfo, NGROUPS_MAX) != 0)
		return control;

	len = CMSG_LEN(SOCKCREDSIZE(cinfo.cred.ngroups));
	space = CMSG_SPACE(SOCKCREDSIZE(cinfo.cred.ngroups));
#else
	len = CMSG_LEN(SOCKCREDSIZE(kauth_cred_ngroups(l->l_cred)));
	space = CMSG_SPACE(SOCKCREDSIZE(kauth_cred_ngroups(l->l_cred)));
#endif

	m = m_get(M_WAIT, MT_CONTROL);
	if (space > MLEN) {
		if (space > MCLBYTES)
			MEXTMALLOC(m, space, M_WAITOK);
		else
			m_clget(m, M_WAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (control);
		}
	}

	m->m_len = space;
	m->m_next = NULL;
	cmp = mtod(m, struct cmsghdr *);
	sc = (struct sockcred *)CMSG_DATA(cmp);
	cmp->cmsg_len = len;
	cmp->cmsg_level = SOL_SOCKET;
	cmp->cmsg_type = SCM_CREDS;
#ifndef __QNXNTO__
	sc->sc_uid = kauth_cred_getuid(l->l_cred);
	sc->sc_euid = kauth_cred_geteuid(l->l_cred);
	sc->sc_gid = kauth_cred_getgid(l->l_cred);
	sc->sc_egid = kauth_cred_getegid(l->l_cred);
	sc->sc_ngroups = kauth_cred_ngroups(l->l_cred);
	for (i = 0; i < sc->sc_ngroups; i++)
		sc->sc_groups[i] = kauth_cred_group(l->l_cred, i);
#else
	sc->sc_uid = cinfo.cred.ruid;
	sc->sc_euid = cinfo.cred.euid;
	sc->sc_gid = cinfo.cred.rgid;
	sc->sc_egid = cinfo.cred.egid;
	sc->sc_ngroups = cinfo.cred.ngroups;
	for (i = 0; i < sc->sc_ngroups; i++)
		sc->sc_groups[i] = cinfo.cred.grouplist[i];
#endif

	/*
	 * If a control message already exists, append us to the end.
	 */
	if (control != NULL) {
		for (n = control; n->m_next != NULL; n = n->m_next)
			;
		n->m_next = m;
	} else
		control = m;

	return (control);
}

int	unp_defer, unp_gcing;
extern	struct domain unixdomain;

/*
 * Comment added long after the fact explaining what's going on here.
 * Do a mark-sweep GC of file descriptors on the system, to free up
 * any which are caught in flight to an about-to-be-closed socket.
 *
 * Traditional mark-sweep gc's start at the "root", and mark
 * everything reachable from the root (which, in our case would be the
 * process table).  The mark bits are cleared during the sweep.
 *
 * XXX For some inexplicable reason (perhaps because the file
 * descriptor tables used to live in the u area which could be swapped
 * out and thus hard to reach), we do multiple scans over the set of
 * descriptors, using use *two* mark bits per object (DEFER and MARK).
 * Whenever we find a descriptor which references other descriptors,
 * the ones it references are marked with both bits, and we iterate
 * over the whole file table until there are no more DEFER bits set.
 * We also make an extra pass *before* the GC to clear the mark bits,
 * which could have been cleared at almost no cost during the previous
 * sweep.
 *
 * XXX MP: this needs to run with locks such that no other thread of
 * control can create or destroy references to file descriptors. it
 * may be necessary to defer the GC until later (when the locking
 * situation is more hospitable); it may be necessary to push this
 * into a separate thread.
 */
#ifndef __QNXNTO__
void
unp_gc(void)
{
	struct file *fp, *nextfp;
	struct socket *so, *so1;
	struct file **extra_ref, **fpp;
	int nunref, i;

	if (unp_gcing)
		return;
	unp_gcing = 1;
	unp_defer = 0;

	/* Clear mark bits */
	LIST_FOREACH(fp, &filehead, f_list)
		fp->f_flag &= ~(FMARK|FDEFER);

	/*
	 * Iterate over the set of descriptors, marking ones believed
	 * (based on refcount) to be referenced from a process, and
	 * marking for rescan descriptors which are queued on a socket.
	 */
	do {
		LIST_FOREACH(fp, &filehead, f_list) {
			if (fp->f_flag & FDEFER) {
				fp->f_flag &= ~FDEFER;
				unp_defer--;
#ifdef DIAGNOSTIC
				if (fp->f_count == 0)
					panic("unp_gc: deferred unreferenced socket");
#endif
			} else {
				if (fp->f_count == 0)
					continue;
				if (fp->f_flag & FMARK)
					continue;
				if (fp->f_count == fp->f_msgcount)
					continue;
			}
			fp->f_flag |= FMARK;

			if (fp->f_type != DTYPE_SOCKET ||
			    (so = (struct socket *)fp->f_data) == 0)
				continue;
			if (so->so_proto->pr_domain != &unixdomain ||
			    (so->so_proto->pr_flags&PR_RIGHTS) == 0)
				continue;
#ifdef notdef
			if (so->so_rcv.sb_flags & SB_LOCK) {
				/*
				 * This is problematical; it's not clear
				 * we need to wait for the sockbuf to be
				 * unlocked (on a uniprocessor, at least),
				 * and it's also not clear what to do
				 * if sbwait returns an error due to receipt
				 * of a signal.  If sbwait does return
				 * an error, we'll go into an infinite
				 * loop.  Delete all of this for now.
				 */
				(void) sbwait(&so->so_rcv);
				goto restart;
			}
#endif
			unp_scan(so->so_rcv.sb_mb, unp_mark, 0);
			/*
			 * mark descriptors referenced from sockets queued on the accept queue as well.
			 */
			if (so->so_options & SO_ACCEPTCONN) {
				TAILQ_FOREACH(so1, &so->so_q0, so_qe) {
					unp_scan(so1->so_rcv.sb_mb, unp_mark, 0);
				}
				TAILQ_FOREACH(so1, &so->so_q, so_qe) {
					unp_scan(so1->so_rcv.sb_mb, unp_mark, 0);
				}
			}

		}
	} while (unp_defer);
	/*
	 * Sweep pass.  Find unmarked descriptors, and free them.
	 *
	 * We grab an extra reference to each of the file table entries
	 * that are not otherwise accessible and then free the rights
	 * that are stored in messages on them.
	 *
	 * The bug in the original code is a little tricky, so I'll describe
	 * what's wrong with it here.
	 *
	 * It is incorrect to simply unp_discard each entry for f_msgcount
	 * times -- consider the case of sockets A and B that contain
	 * references to each other.  On a last close of some other socket,
	 * we trigger a gc since the number of outstanding rights (unp_rights)
	 * is non-zero.  If during the sweep phase the gc code un_discards,
	 * we end up doing a (full) closef on the descriptor.  A closef on A
	 * results in the following chain.  Closef calls soo_close, which
	 * calls soclose.   Soclose calls first (through the switch
	 * uipc_usrreq) unp_detach, which re-invokes unp_gc.  Unp_gc simply
	 * returns because the previous instance had set unp_gcing, and
	 * we return all the way back to soclose, which marks the socket
	 * with SS_NOFDREF, and then calls sofree.  Sofree calls sorflush
	 * to free up the rights that are queued in messages on the socket A,
	 * i.e., the reference on B.  The sorflush calls via the dom_dispose
	 * switch unp_dispose, which unp_scans with unp_discard.  This second
	 * instance of unp_discard just calls closef on B.
	 *
	 * Well, a similar chain occurs on B, resulting in a sorflush on B,
	 * which results in another closef on A.  Unfortunately, A is already
	 * being closed, and the descriptor has already been marked with
	 * SS_NOFDREF, and soclose panics at this point.
	 *
	 * Here, we first take an extra reference to each inaccessible
	 * descriptor.  Then, if the inaccessible descriptor is a
	 * socket, we call sorflush in case it is a Unix domain
	 * socket.  After we destroy all the rights carried in
	 * messages, we do a last closef to get rid of our extra
	 * reference.  This is the last close, and the unp_detach etc
	 * will shut down the socket.
	 *
	 * 91/09/19, bsy@cs.cmu.edu
	 */
	extra_ref = malloc(nfiles * sizeof(struct file *), M_FILE, M_WAITOK);
	for (nunref = 0, fp = LIST_FIRST(&filehead), fpp = extra_ref; fp != 0;
	    fp = nextfp) {
		nextfp = LIST_NEXT(fp, f_list);
		simple_lock(&fp->f_slock);
		if (fp->f_count != 0 &&
		    fp->f_count == fp->f_msgcount && !(fp->f_flag & FMARK)) {
			*fpp++ = fp;
			nunref++;
			fp->f_count++;
		}
		simple_unlock(&fp->f_slock);
	}
	for (i = nunref, fpp = extra_ref; --i >= 0; ++fpp) {
		fp = *fpp;
		simple_lock(&fp->f_slock);
		FILE_USE(fp);
		if (fp->f_type == DTYPE_SOCKET)
			sorflush((struct socket *)fp->f_data);
		FILE_UNUSE(fp, NULL);
	}
	for (i = nunref, fpp = extra_ref; --i >= 0; ++fpp) {
		fp = *fpp;
		simple_lock(&fp->f_slock);
		FILE_USE(fp);
		(void) closef(fp, (struct lwp *)0);
	}
	free((caddr_t)extra_ref, M_FILE);
	unp_gcing = 0;
}
#endif

void
unp_dispose(struct mbuf *m)
{

	if (m)
		unp_scan(m, unp_discard, 1);
}

#ifndef __QNXNTO__
void
unp_scan(struct mbuf *m0, void (*op)(struct file *), int discard)
{
	struct mbuf *m;
	struct file **rp;
	struct cmsghdr *cm;
	int i;
	int qfds;

	while (m0) {
		for (m = m0; m; m = m->m_next) {
			if (m->m_type == MT_CONTROL &&
			    m->m_len >= sizeof(*cm)) {
				cm = mtod(m, struct cmsghdr *);
				if (cm->cmsg_level != SOL_SOCKET ||
				    cm->cmsg_type != SCM_RIGHTS)
					continue;
				qfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm)))
				    / sizeof(struct file *);
				rp = (struct file **)CMSG_DATA(cm);
				for (i = 0; i < qfds; i++) {
					struct file *fp = *rp;
					if (discard)
						*rp = 0;
					(*op)(fp);
					rp++;
				}
				break;		/* XXX, but saves time */
			}
		}
		m0 = m0->m_nextpkt;
	}
}

void
unp_mark(struct file *fp)
{
	if (fp == NULL)
		return;

	if (fp->f_flag & FMARK)
		return;

	/* If we're already deferred, don't screw up the defer count */
	if (fp->f_flag & FDEFER)
		return;

	/*
	 * Minimize the number of deferrals...  Sockets are the only
	 * type of descriptor which can hold references to another
	 * descriptor, so just mark other descriptors, and defer
	 * unmarked sockets for the next pass.
	 */
	if (fp->f_type == DTYPE_SOCKET) {
		unp_defer++;
		if (fp->f_count == 0)
			panic("unp_mark: queued unref");
		fp->f_flag |= FDEFER;
	} else {
		fp->f_flag |= FMARK;
	}
	return;
}

void
unp_discard(struct file *fp)
{
	if (fp == NULL)
		return;
	simple_lock(&fp->f_slock);
	fp->f_usecount++;	/* i.e. FILE_USE(fp) sans locking */
	fp->f_msgcount--;
	simple_unlock(&fp->f_slock);
	unp_rights--;
	(void) closef(fp, (struct lwp *)0);
}
#else
void
unp_scan(struct mbuf *m0, void (*op)(io_dup_t *), int discard)
{
	struct mbuf *m;
	io_dup_t *dup;
	struct cmsghdr *cm;
	int i;
	int qfds;

	while (m0) {
		for (m = m0; m; m = m->m_next) {
			if (m->m_type == MT_CONTROL &&
			    m->m_len >= sizeof(*cm)) {
				cm = mtod(m, struct cmsghdr *);
				if (cm->cmsg_level != SOL_SOCKET ||
				    cm->cmsg_type != SCM_RIGHTS)
					continue;
				qfds = (cm->cmsg_len - CMSG_ALIGN(sizeof(*cm)))
				    / sizeof(io_dup_t);
				dup = (io_dup_t *)CMSG_DATA(cm);
				for (i = 0; i < qfds; i++) {
					(*op)(dup);
					dup++;
				}
				break;		/* XXX, but saves time */
			}
		}
		m0 = m0->m_nextpkt;
	}
}

static void* close_thread (void *arg)
{
	char			namebuf[32];
	int fd;

	fd = *(int*)arg;

	snprintf(namebuf, sizeof(namebuf), "FD Close %d", fd);
	pthread_setname_np(gettid(), namebuf);

	close(fd);
	stk_context_callback_2(thread_wakeup, arg, NULL);
	return NULL;
}

void
unp_discard(io_dup_t *dup)
{
	pthread_t	tid;
	int		newfd;

	if (dup == NULL || (newfd = dup->i.info.priority) == -1)
		return;

	pthread_create(&tid, NULL, close_thread, &newfd);
	ltsleep(&newfd, 0, "FD Close", 0, NULL);
	pthread_join(tid, NULL);

	dup->i.info.priority = -1;
	unp_rights--;
}

struct sockaddr_un *
sref_alloc(int len)
{
	struct sun_ref *sref;

	sref = malloc(offsetof(struct sun_ref, sr_sun) + len,
	    M_SONAME, M_WAITOK);
	sref->sr_ref = 1;

	return &sref->sr_sun;
}

void
sref_free(struct sockaddr_un *sun)
{
	struct sun_ref *sref;

	sref = SUN_TO_SREF(sun);

	/*
	 * Ref count should be 1 or 2 on entry: only
	 * unp and / or vnode should have reference.
	 */
	sref->sr_ref--;

	if ((unsigned)sref->sr_ref > 1)
		panic("sref_free");

	if (sref->sr_ref == 0)
		free(sref, M_SONAME);
}

int
uipc_format(struct socket *so, int type, char *buf, int *maxlen)
{
	struct unpcb *unp;
	struct sockaddr_un *sun;
	int pathlen, ret;
	char *path;
	char types[SOCK_RAW + 1] = {'S', 'D', 'R', '?'};
	char tc;

	tc = types[min(SOCK_RAW, type - 1)];

	if ((unp = sotounpcb(so)) == NULL || (sun = unp->unp_addr) == NULL ||
	    (pathlen = sun->sun_len - (sizeof(*sun) - sizeof(sun->sun_path))) <= 0) {
		path = "";
		pathlen = 0;
	}
	else {
		path = sun->sun_path;
	}
		
	if ((ret = snprintf(buf, *maxlen, "UDS %c %s", tc, path)) == -1)
		return *__get_errno_ptr();

	if (ret < *maxlen) {
		/* include terminating '\0' */
		ret++;
	}
	else {
		ret = *maxlen;
		buf[ret - 1] = '\0';
	}

	*maxlen = ret;

	return 0;
}

int
uipc_path(struct socket *so, char *dst, int lim)
{
	struct unpcb *unp;
	struct sockaddr_un *sun;
	int pathlen;

	if ((unp = sotounpcb(so)) == NULL || (sun = unp->unp_addr) == NULL ||
	    (pathlen = sun->sun_len - (sizeof(*sun) - sizeof(sun->sun_path))) <= 0) {
		return -1;
	}

	/* pathlen doesn't include \0 */
	pathlen = min(pathlen, lim - 1);

	strncpy(dst, sun->sun_path, min(lim, pathlen));
	dst[pathlen] = '\0';
	return pathlen + 1;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/uipc_usrreq.c $ $Rev: 892448 $")
#endif
