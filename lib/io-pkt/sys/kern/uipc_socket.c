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


/*	$NetBSD: uipc_socket.c,v 1.129.2.1 2007/05/13 21:23:47 pavel Exp $	*/

/*-
 * Copyright (c) 2002, 2007, 2008, 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of Wasabi Systems, Inc, and by Andrew Doran.
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
 * Copyright (c) 2004 The FreeBSD Foundation
 * Copyright (c) 2004 Robert Watson
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
 *	@(#)uipc_socket.c	8.6 (Berkeley) 5/2/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uipc_socket.c,v 1.129.2.1 2007/05/13 21:23:47 pavel Exp $");

#include "opt_sock_counters.h"
#include "opt_sosend_loan.h"
#include "opt_mbuftrace.h"
#ifndef __QNXNTO__
#include "opt_somaxkva.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#ifndef __QNXNTO__
#include <sys/file.h>
#else
#include <sys/file_bsd.h>
#include "siglock.h"
#endif
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/pool.h>
#include <sys/event.h>
#include <sys/poll.h>
#include <sys/kauth.h>

#ifndef __QNXNTO__
#include <uvm/uvm.h>
#endif

#ifdef QNX_MFIB
#include <net/route.h>
#endif

#ifdef __QNXNTO__
#ifndef NDEBUG
extern int debug_net_so_fib_verbosity;
#endif
int so_txprio_enabled = 0;
#endif

POOL_INIT(socket_pool, sizeof(struct socket), 0, 0, 0, "sockpl", NULL);

MALLOC_DEFINE(M_SOOPTS, "soopts", "socket options");
MALLOC_DEFINE(M_SONAME, "soname", "socket name");

extern int	somaxconn;			/* patchable (XXX sysctl) */
int		somaxconn = SOMAXCONN;

#ifdef SOSEND_COUNTERS
#include <sys/device.h>

static struct evcnt sosend_loan_big = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "sosend", "loan big");
static struct evcnt sosend_copy_big = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "sosend", "copy big");
static struct evcnt sosend_copy_small = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "sosend", "copy small");
static struct evcnt sosend_kvalimit = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
    NULL, "sosend", "kva limit");

#define	SOSEND_COUNTER_INCR(ev)		(ev)->ev_count++

EVCNT_ATTACH_STATIC(sosend_loan_big);
EVCNT_ATTACH_STATIC(sosend_copy_big);
EVCNT_ATTACH_STATIC(sosend_copy_small);
EVCNT_ATTACH_STATIC(sosend_kvalimit);
#else

#define	SOSEND_COUNTER_INCR(ev)		/* nothing */

#endif /* SOSEND_COUNTERS */

#ifndef __QNXNTO__
static struct callback_entry sokva_reclaimerentry;

#ifdef SOSEND_NO_LOAN
int sock_loan_thresh = -1;
#else
int sock_loan_thresh = 4096;
#endif
#else
int sock_loan_thresh = -1;
#endif

#ifndef __QNXNTO__
static struct simplelock so_pendfree_slock = SIMPLELOCK_INITIALIZER;
static struct mbuf *so_pendfree;

#ifndef SOMAXKVA
#define	SOMAXKVA (16 * 1024 * 1024)
#endif
int somaxkva = SOMAXKVA;
static int socurkva;
static int sokvawaiters;

#define	SOCK_LOAN_CHUNK		65536

static size_t sodopendfree(void);
static size_t sodopendfreel(void);

static vsize_t
sokvareserve(struct socket *so, vsize_t len)
{
	int s;
	int error;

	s = splvm();
	simple_lock(&so_pendfree_slock);
	while (socurkva + len > somaxkva) {
		size_t freed;

		/*
		 * try to do pendfree.
		 */

		freed = sodopendfreel();

		/*
		 * if some kva was freed, try again.
		 */

		if (freed)
			continue;

		SOSEND_COUNTER_INCR(&sosend_kvalimit);
		sokvawaiters++;
		error = ltsleep(&socurkva, PVM | PCATCH, "sokva", 0,
		    &so_pendfree_slock);
		sokvawaiters--;
		if (error) {
			len = 0;
			break;
		}
	}
	socurkva += len;
	simple_unlock(&so_pendfree_slock);
	splx(s);
	return len;
}

static void
sokvaunreserve(vsize_t len)
{
	int s;

	s = splvm();
	simple_lock(&so_pendfree_slock);
	socurkva -= len;
	if (sokvawaiters)
		wakeup(&socurkva);
	simple_unlock(&so_pendfree_slock);
	splx(s);
}

/*
 * sokvaalloc: allocate kva for loan.
 */

vaddr_t
sokvaalloc(vsize_t len, struct socket *so)
{
	vaddr_t lva;

	/*
	 * reserve kva.
	 */

	if (sokvareserve(so, len) == 0)
		return 0;

	/*
	 * allocate kva.
	 */

	lva = uvm_km_alloc(kernel_map, len, 0, UVM_KMF_VAONLY | UVM_KMF_WAITVA);
	if (lva == 0) {
		sokvaunreserve(len);
		return (0);
	}

	return lva;
}

/*
 * sokvafree: free kva for loan.
 */

void
sokvafree(vaddr_t sva, vsize_t len)
{

	/*
	 * free kva.
	 */

	uvm_km_free(kernel_map, sva, len, UVM_KMF_VAONLY);

	/*
	 * unreserve kva.
	 */

	sokvaunreserve(len);
}

static void
sodoloanfree(struct vm_page **pgs, caddr_t buf, size_t size)
{
	vaddr_t va, sva, eva;
	vsize_t len;
	paddr_t pa;
	int i, npgs;

	eva = round_page((vaddr_t) buf + size);
	sva = trunc_page((vaddr_t) buf);
	len = eva - sva;
	npgs = len >> PAGE_SHIFT;

	if (__predict_false(pgs == NULL)) {
		pgs = alloca(npgs * sizeof(*pgs));

		for (i = 0, va = sva; va < eva; i++, va += PAGE_SIZE) {
			if (pmap_extract(pmap_kernel(), va, &pa) == FALSE)
				panic("sodoloanfree: va 0x%lx not mapped", va);
			pgs[i] = PHYS_TO_VM_PAGE(pa);
		}
	}

	pmap_kremove(sva, len);
	pmap_update(pmap_kernel());
	uvm_unloan(pgs, npgs, UVM_LOAN_TOPAGE);
	sokvafree(sva, len);
}

static size_t
sodopendfree()
{
	int s;
	size_t rv;

	s = splvm();
	simple_lock(&so_pendfree_slock);
	rv = sodopendfreel();
	simple_unlock(&so_pendfree_slock);
	splx(s);

	return rv;
}

/*
 * sodopendfreel: free mbufs on "pendfree" list.
 * unlock and relock so_pendfree_slock when freeing mbufs.
 *
 * => called with so_pendfree_slock held.
 * => called at splvm.
 */

static size_t
sodopendfreel()
{
	size_t rv = 0;

	LOCK_ASSERT(simple_lock_held(&so_pendfree_slock));

	for (;;) {
		struct mbuf *m;
		struct mbuf *next;

		m = so_pendfree;
		if (m == NULL)
			break;
		so_pendfree = NULL;
		simple_unlock(&so_pendfree_slock);
		/* XXX splx */

		for (; m != NULL; m = next) {
			next = m->m_next;

			rv += m->m_ext.ext_size;
			sodoloanfree((m->m_flags & M_EXT_PAGES) ?
			    m->m_ext.ext_pgs : NULL, m->m_ext.ext_buf,
			    m->m_ext.ext_size);
			pool_cache_put(&mbpool_cache, m);
		}

		/* XXX splvm */
		simple_lock(&so_pendfree_slock);
	}

	return (rv);
}

void
soloanfree(struct mbuf *m, caddr_t buf, size_t size, void *arg)
{
	int s;

	if (m == NULL) {

		/*
		 * called from MEXTREMOVE.
		 */

		sodoloanfree(NULL, buf, size);
		return;
	}

	/*
	 * postpone freeing mbuf.
	 *
	 * we can't do it in interrupt context
	 * because we need to put kva back to kernel_map.
	 */

	s = splvm();
	simple_lock(&so_pendfree_slock);
	m->m_next = so_pendfree;
	so_pendfree = m;
	if (sokvawaiters)
		wakeup(&socurkva);
	simple_unlock(&so_pendfree_slock);
	splx(s);
}

static long
sosend_loan(struct socket *so, struct uio *uio, struct mbuf *m, long space)
{
	struct iovec *iov = uio->uio_iov;
	vaddr_t sva, eva;
	vsize_t len;
	vaddr_t lva, va;
	int npgs, i, error;

	if (VMSPACE_IS_KERNEL_P(uio->uio_vmspace))
		return (0);

	if (iov->iov_len < (size_t) space)
		space = iov->iov_len;
	if (space > SOCK_LOAN_CHUNK)
		space = SOCK_LOAN_CHUNK;

	eva = round_page((vaddr_t) iov->iov_base + space);
	sva = trunc_page((vaddr_t) iov->iov_base);
	len = eva - sva;
	npgs = len >> PAGE_SHIFT;

	/* XXX KDASSERT */
	KASSERT(npgs <= M_EXT_MAXPAGES);

	lva = sokvaalloc(len, so);
	if (lva == 0)
		return 0;

	error = uvm_loan(&uio->uio_vmspace->vm_map, sva, len,
	    m->m_ext.ext_pgs, UVM_LOAN_TOPAGE);
	if (error) {
		sokvafree(lva, len);
		return (0);
	}

	for (i = 0, va = lva; i < npgs; i++, va += PAGE_SIZE)
		pmap_kenter_pa(va, VM_PAGE_TO_PHYS(m->m_ext.ext_pgs[i]),
		    VM_PROT_READ, 0);
	pmap_update(pmap_kernel());

	lva += (vaddr_t) iov->iov_base & PAGE_MASK;

	MEXTADD(m, (void *) lva, space, M_MBUF, soloanfree, so);
	m->m_flags |= M_EXT_PAGES | M_EXT_ROMAP;

	uio->uio_resid -= space;
	/* uio_offset not updated, not set/used for write(2) */
	uio->uio_iov->iov_base = (char *)uio->uio_iov->iov_base + space;
	uio->uio_iov->iov_len -= space;
	if (uio->uio_iov->iov_len == 0) {
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}

	return (space);
}
#endif

struct mbuf *
getsombuf(struct socket *so, int type)
{
	struct mbuf *m;

	m = m_get(M_WAIT, type);
	MCLAIM(m, so->so_mowner);
	return m;
}

#ifndef __QNXNTO__
static int
sokva_reclaim_callback(struct callback_entry *ce, void *obj, void *arg)
{

	KASSERT(ce == &sokva_reclaimerentry);
	KASSERT(obj == NULL);

	sodopendfree();
	if (!vm_map_starved_p(kernel_map)) {
		return CALLBACK_CHAIN_ABORT;
	}
	return CALLBACK_CHAIN_CONTINUE;
}
#endif /* !__QNXNTO__ */

void
soinit(void)
{

	/* Set the initial adjusted socket buffer size. */
	if (sb_max_set(sb_max))
		panic("bad initial sb_max value: %lu", sb_max);

#ifndef __QNXNTO__
	callback_register(&vm_map_to_kernel(kernel_map)->vmk_reclaim_callback,
	    &sokva_reclaimerentry, NULL, sokva_reclaim_callback);
#endif
}

/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */
/*ARGSUSED*/
int
socreate(int dom, struct socket **aso, int type, int proto, struct lwp *l)
{
	const struct protosw	*prp;
	struct socket	*so;
	uid_t		uid;
#ifdef __QNXNTO__
	gid_t		gid;
#endif
	int		error, s;

	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_SOCKET,
	    KAUTH_REQ_NETWORK_SOCKET_OPEN, (void *)(u_long)dom,
	    (void *)(u_long)type, (void *)(u_long)proto) != 0)
		return (EPERM);

	if (proto)
		prp = pffindproto(dom, proto, type);
	else
		prp = pffindtype(dom, type);
	if (prp == 0) {
		/* no support for domain */
		if (pffinddomain(dom) == 0)
			return (EAFNOSUPPORT);
		/* no support for socket type */
		if (proto == 0 && type != 0)
			return (EPROTOTYPE);
		return (EPROTONOSUPPORT);
	}
	if (prp->pr_usrreq == 0)
		return (EPROTONOSUPPORT);
	if (prp->pr_type != type)
		return (EPROTOTYPE);
	s = splsoftnet();
	so = pool_get(&socket_pool, PR_WAITOK);
	memset((caddr_t)so, 0, sizeof(*so));
	TAILQ_INIT(&so->so_q0);
	TAILQ_INIT(&so->so_q);
	so->so_type = type;
	so->so_proto = prp;
	so->so_send = sosend;
	so->so_receive = soreceive;
#ifdef MBUFTRACE
	so->so_rcv.sb_mowner = &prp->pr_domain->dom_mowner;
	so->so_snd.sb_mowner = &prp->pr_domain->dom_mowner;
	so->so_mowner = &prp->pr_domain->dom_mowner;
#endif
	if (l != NULL) {
		uid = kauth_cred_geteuid(l->l_cred);
#ifdef __QNXNTO__
		gid = kauth_cred_getegid(l->l_cred);
#endif
	} else {
		uid = 0;
#ifdef __QNXNTO__
		gid = 0;
#endif
	}
#ifndef __QNXNTO__
	so->so_uidinfo = uid_find(uid);
#else
	so->so_uid.ui_uid = uid;
	so->so_uid.ui_sbsize = 0;
	so->so_uidinfo = &so->so_uid;

	so->so_gid	= gid;
#ifdef QNX_MFIB
    if (so->so_fiborigin==SO_FIB_INIT) {
    	so->so_fibnum = kauth_getfib4cred(l->l_cred);
    	so->so_fiborigin = SO_FIB_SOCREATE;
#ifndef NDEBUG
    	if (debug_net_so_fib_verbosity > 1) {
    		printf("Socket type '%d': pid=%10d/so=%10d/user=%10d assigning to fib %4d\n",
    				so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
    				(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
    	}
#endif
    }
#ifndef NDEBUG
    else {
    	if (debug_net_so_fib_verbosity > 2) {
    		printf("socreat: fib already set to %4d\n", so->so_fibnum);
    	}
    }
#endif
#endif
	so->so_txprio = SO_TXPRIO_DEFAULT;
	so->so_vlanprio = SO_VLANPRIO_UNDEF;
#endif
	error = (*prp->pr_usrreq)(so, PRU_ATTACH, (struct mbuf *)0,
	    (struct mbuf *)(long)proto, (struct mbuf *)0, l);
	if (error) {
		so->so_state |= SS_NOFDREF;
		sofree(so);
		splx(s);
		return (error);
	}
	splx(s);
	*aso = so;
	return (0);
}

int
sobind(struct socket *so, struct mbuf *nam, struct lwp *l)
{
	int	s, error;

	s = splsoftnet();
	error = (*so->so_proto->pr_usrreq)(so, PRU_BIND, (struct mbuf *)0,
	    nam, (struct mbuf *)0, l);
	splx(s);
	return (error);
}

int
solisten(struct socket *so, int backlog, struct lwp *l)
{
	int	s, error;
#ifdef __QNXNTO__
#if 0  /* This should all go in the SCTP PRU_LISTEN handling code. */
	short oldopt, oldqlimit;
#endif
#endif

	s = splsoftnet();
#ifdef __QNXNTO__
#if 0 /* This should all go in the SCTP PRU_LISTEN handling code. */
	oldopt = so->so_options;
	oldqlimit = so->so_qlimit;
	
	if (TAILQ_EMPTY(&so->so_q))
		so->so_options |= SO_ACCEPTCONN;
	if (backlog < 0)
		backlog = 0;
	so->so_qlimit = min(backlog, somaxconn);
	/* SCTP needs to look at and tweak both
	 * the inbound backlog paramter AND the
	 * so_options (UDP model both connect's and
	 * gets inbound connections .. implicitly).
	 */
#endif
	error = (*so->so_proto->pr_usrreq)(so, PRU_LISTEN, (struct mbuf *)0,
	    (struct mbuf *)0, (struct mbuf *)0, l);
#endif
	if (error) {
#ifdef __QNXNTO__
#if 0 /* This should all go in the SCTP PRU_LISTEN handling code. */
		so->so_options = oldopt;
		so->so_qlimit = oldqlimit;
#endif
#endif
		splx(s);
		return (error);
	}
	if (TAILQ_EMPTY(&so->so_q))
		so->so_options |= SO_ACCEPTCONN;
	if (backlog < 0)
		backlog = 0;
	so->so_qlimit = min(backlog, somaxconn);
	splx(s);
	return (0);
}

void
sofree(struct socket *so)
{
#ifdef __QNXNTO__
	struct sockbuf	*sb;
	struct knote	*kn;
	struct file	*fp;
	int		i;
#endif

	if (so->so_pcb || (so->so_state & SS_NOFDREF) == 0)
		return;
	if (so->so_head) {
		/*
		 * We must not decommission a socket that's on the accept(2)
		 * queue.  If we do, then accept(2) may hang after select(2)
		 * indicated that the listening socket was ready.
		 */
		if (!soqremque(so, 0))
			return;
	}
	if (so->so_rcv.sb_hiwat)
		(void)chgsbsize(so->so_uidinfo, &so->so_rcv.sb_hiwat, 0,
		    RLIM_INFINITY);
	if (so->so_snd.sb_hiwat)
		(void)chgsbsize(so->so_uidinfo, &so->so_snd.sb_hiwat, 0,
		    RLIM_INFINITY);
	sbrelease(&so->so_snd, so);
	sorflush(so);
#ifdef __QNXNTO__
	/*
	 * NULL ctp below means remove them all (this is lastclose).
	 */
	iofunc_notify_remove(NULL, so->so_notify);

	/*
	 * We can't block in closef() waiting for 
	 * fp->usecount to drain so we have to
	 * clean this up here.
	 */
	for (i = 0, sb = &so->so_snd; i < 2; i++, sb = &so->so_rcv) {
		while ((kn = SLIST_FIRST(&sb->sb_sel.sel_klist)) != NULL) {
			SLIST_FIRST(&sb->sb_sel.sel_klist) = SLIST_NEXT(kn, kn_selnext);
			fp = kn->kn_fp;
#ifndef NDEBUG
			if (fp->f_data != so)
				panic("sofree: knotes knackered");
#endif
			knote_free(kn);
		}
	}
#endif
	pool_put(&socket_pool, so);
}

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
int
soclose(struct socket *so)
{
	struct socket	*so2;
	int		s, error;

	error = 0;
	s = splsoftnet();		/* conservative */
	if (so->so_options & SO_ACCEPTCONN) {
		while ((so2 = TAILQ_FIRST(&so->so_q0)) != 0) {
			(void) soqremque(so2, 0);
			(void) soabort(so2);
		}
		while ((so2 = TAILQ_FIRST(&so->so_q)) != 0) {
			(void) soqremque(so2, 1);
			(void) soabort(so2);
		}
	}
	if (so->so_pcb == 0)
		goto discard;
	if (so->so_state & SS_ISCONNECTED) {
		if ((so->so_state & SS_ISDISCONNECTING) == 0) {
			error = sodisconnect(so);
			if (error)
				goto drop;
		}
		if (so->so_options & SO_LINGER) {
			if ((so->so_state & SS_ISDISCONNECTING) &&
			    (so->so_state & SS_NBIO))
				goto drop;
			while (so->so_state & SS_ISCONNECTED) {
				error = tsleep((caddr_t)&so->so_timeo,
					       PSOCK | PCATCH, netcls,
					       so->so_linger * hz);
				if (error)
					break;
			}
		}
	}
 drop:
	if (so->so_pcb) {
		int error2 = (*so->so_proto->pr_usrreq)(so, PRU_DETACH,
		    (struct mbuf *)0, (struct mbuf *)0, (struct mbuf *)0,
		    (struct lwp *)0);
		if (error == 0)
			error = error2;
	}
 discard:
	if (so->so_state & SS_NOFDREF)
		panic("soclose: NOFDREF");
	so->so_state |= SS_NOFDREF;
	sofree(so);
	splx(s);
	return (error);
}

/*
 * Must be called at splsoftnet...
 */
int
soabort(struct socket *so)
{
	int error;

	KASSERT(so->so_head == NULL);
	error = (*so->so_proto->pr_usrreq)(so, PRU_ABORT, (struct mbuf *)0,
	    (struct mbuf *)0, (struct mbuf *)0, (struct lwp *)0);
	if (error) {
		sofree(so);
	}
	return error;
}

int
soaccept(struct socket *so, struct mbuf *nam)
{
	int	s, error;

	error = 0;
	s = splsoftnet();
	if ((so->so_state & SS_NOFDREF) == 0)
		panic("soaccept: !NOFDREF");
	so->so_state &= ~SS_NOFDREF;
	if ((so->so_state & SS_ISDISCONNECTED) == 0 ||
	    (so->so_proto->pr_flags & PR_ABRTACPTDIS) == 0)
		error = (*so->so_proto->pr_usrreq)(so, PRU_ACCEPT,
		    (struct mbuf *)0, nam, (struct mbuf *)0, (struct lwp *)0);
	else
		error = ECONNABORTED;

	splx(s);
	return (error);
}

int
soconnect(struct socket *so, struct mbuf *nam, struct lwp *l)
{
	int		s, error;

	if (so->so_options & SO_ACCEPTCONN)
		return (EOPNOTSUPP);
	s = splsoftnet();
	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.
	 * This allows user to disconnect by connecting to, e.g.,
	 * a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnect(so))))
		error = EISCONN;
	else
		error = (*so->so_proto->pr_usrreq)(so, PRU_CONNECT,
		    (struct mbuf *)0, nam, (struct mbuf *)0, l);
	splx(s);
	return (error);
}

int
soconnect2(struct socket *so1, struct socket *so2)
{
	int	s, error;

	s = splsoftnet();
	error = (*so1->so_proto->pr_usrreq)(so1, PRU_CONNECT2,
	    (struct mbuf *)0, (struct mbuf *)so2, (struct mbuf *)0,
	    (struct lwp *)0);
	splx(s);
	return (error);
}

int
sodisconnect(struct socket *so)
{
	int	s, error;

	s = splsoftnet();
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto bad;
	}
	if (so->so_state & SS_ISDISCONNECTING) {
		error = EALREADY;
		goto bad;
	}
	error = (*so->so_proto->pr_usrreq)(so, PRU_DISCONNECT,
	    (struct mbuf *)0, (struct mbuf *)0, (struct mbuf *)0,
	    (struct lwp *)0);
 bad:
	splx(s);
#ifndef __QNXNTO__
	sodopendfree();
#endif
	return (error);
}

#ifdef __QNXNTO__
/*
 * At 2k clusters, means can MsgReadv / MsgWritev 64k at at time.  Should
 * be plenty with size of send buffer at 28k at time of writing,
 * see TCP_SENDSPACE in netinet/tcp_usrreq.c.  Also watch
 * so_snd.sb_lowat.  Set to 16k at time of writing so we can
 * MsgRead 16k at a time (8 clusters).
 */
#define SET_MAX 32

static int
uiomove_fast(int *set_num, iov_t *set, int *set_start_off, char *buf, int len,
    struct uio *uio, struct lwp *l)
{
	struct proc *p = LWP_TO_PR(l);
	int ret;
	uintptr_t up;

	if(*set_num == SET_MAX) {
		if ((ret = MsgReadv_r(p->p_ctxt.rcvid, set, *set_num, *set_start_off)) < 0)
			return -ret;

		*set_num = 0;
	}

	if(*set_num == 0)
		*set_start_off = p->p_offset;

	SETIOV(&set[*set_num], buf, len);
	(*set_num)++;

	p->p_offset += len;
	up = (unsigned)uio->uio_iov->iov_base;
	up += len;
	uio->uio_iov->iov_base = (void *)up;
	uio->uio_iov->iov_len  -= len;
	uio->uio_resid         -= len;
	uio->uio_offset        += len;

	return 0;
}
#endif

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_NOWAIT : M_WAITOK)
/*
 * Send on a socket.
 * If send must go all at once and message is larger than
 * send buffering, then hard error.
 * Lock against other senders.
 * If must go all at once and not enough room now, then
 * inform user that this would block and do nothing.
 * Otherwise, if nonblocking, send as much as possible.
 * The data to be sent is described by "uio" if nonzero,
 * otherwise by the mbuf chain "top" (which must be null
 * if uio is not).  Data provided in mbuf chain must be small
 * enough to send all at once.
 *
 * Returns nonzero on error, timeout or signal; callers
 * must check for short counts if EINTR/ERESTART are returned.
 * Data and control buffers are freed on return.
 */
int
sosend(struct socket *so, struct mbuf *addr, struct uio *uio, struct mbuf *top,
	struct mbuf *control, int flags, struct lwp *l)
{
	struct mbuf	**mp, *m;
	struct proc	*p;
	long		space, len, resid, clen, mlen;
	int		error, s, dontroute, atomic;
#ifdef __QNXNTO__
	iov_t		set[SET_MAX];
	int		set_num;
	int		set_start_off;
	int		last_preload, iglowat;
	uintptr_t	up;

	set_num = 0;
	set_start_off = 0;
#endif
#ifndef __QNXNTO__
	p = l->l_proc;
	sodopendfree();
#else
	p = LWP_TO_PR(l);

	if (p->p_mbuf != NULL) {
#if !defined(NDEBUG) || defined(DIAGNOSTIC)
		if ((p->p_mbuf->m_flags & M_PKTHDR) == 0) {
			panic("sosend p_mbuf no pkthdr");
		}
#endif
		/*
		 * We recalculate this to what we actually send here.
		 * Other layers (tun) use the passed in value.
		 */
		p->p_mbuf->m_pkthdr.len = 0;
	}
#endif

	clen = 0;
	atomic = sosendallatonce(so) || top;
	if (uio)
		resid = uio->uio_resid;
	else
		resid = top->m_pkthdr.len;
	/*
	 * In theory resid should be unsigned.
	 * However, space must be signed, as it might be less than 0
	 * if we over-committed, and we must use a signed comparison
	 * of space and resid.  On the other hand, a negative resid
	 * causes us to loop sending 0-length segments to the protocol.
	 */
	if (resid < 0) {
		error = EINVAL;
		goto out;
	}
	dontroute =
	    (flags & MSG_DONTROUTE) && (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	if (p)
		p->p_stats->p_ru.ru_msgsnd++;
	if (control)
		clen = control->m_len;
#define	snderr(errno)	{ error = errno; splx(s); goto release; }

 restart:
#ifdef __QNXNTO__
	iglowat = so->so_state & SS_IGLOWAT;
	so->so_state &= ~SS_IGLOWAT;
#endif
	if ((error = sblock(&so->so_snd, SBLOCKWAIT(flags))) != 0)
		goto out;
	do {
		s = splsoftnet();
		if (so->so_state & SS_CANTSENDMORE)
			snderr(EPIPE);
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			splx(s);
			goto release;
		}
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
				if ((so->so_state & SS_ISCONFIRMING) == 0 &&
				    !(resid == 0 && clen != 0))
					snderr(ENOTCONN);
			} else if (addr == 0)
				snderr(EDESTADDRREQ);
		}
		space = sbspace(&so->so_snd);
		if (flags & MSG_OOB)
			space += 1024;
		if ((atomic && resid > so->so_snd.sb_hiwat) ||
		    clen > so->so_snd.sb_hiwat)
			snderr(EMSGSIZE);
		if (space < resid + clen &&
		    (atomic || (space < so->so_snd.sb_lowat
#ifdef __QNXNTO__
		    && (iglowat == 0 || space == 0)
#endif
		    ) || space < clen )) {
			if (so->so_state & SS_NBIO)
				snderr(EWOULDBLOCK);
			sbunlock(&so->so_snd);
			error = sbwait(&so->so_snd);
			splx(s);
			if (error) {
#ifdef __QNXNTO__
				/*
				 * Check if this socket was duped
				 * and another client thread closed
				 * it while we were blocked.
				 * Usually SS_CANTSENDMORE would
				 * be set and we would EPIPE after
				 * the restart label above but this
				 * doesn't happen until last close.
				 */
				if (error == EBADF)
					error = EPIPE;
#endif
				goto out;
			}
			goto restart;
		}
		splx(s);
		mp = &top;
		space -= clen;
		do {
#ifdef __QNXNTO__
			set_num = 0;
			iglowat = 0;
#endif
			if (uio == NULL) {
				/*
				 * Data is prepackaged in "top".
				 */
				resid = 0;
				if (flags & MSG_EOR)
					top->m_flags |= M_EOR;
#ifdef __QNXNTO__
				goto moved;
#endif
			} else do {
#ifdef __QNXNTO__
				last_preload = 0;
				if ((m = p->p_mbuf) != NULL) {
					if ((p->p_mbuf = m->m_next) == NULL)
						last_preload = 1;
					m->m_next = NULL;
					len = m->m_len;
#ifndef NDEBUG
					if(len > resid)
						panic("sosend: resid < 0");
					if (top == NULL && (m->m_flags & M_PKTHDR) == 0)
						panic("sosend: non pkt");
#endif
					up = (unsigned)uio->uio_iov->iov_base;
					up += len;
					uio->uio_iov->iov_base = (void *)up;
					uio->uio_iov->iov_len  -= len;
					uio->uio_resid         -= len;
					uio->uio_offset        += len;
					p->p_offset += len;
					space -= len;
					error = 0;
					MCLAIM(m, so->so_snd.sb_mowner);
					goto have_data;
				}
#endif
				if (top == 0) {
					m = m_gethdr(M_WAIT, MT_DATA);
					mlen = MHLEN;
					m->m_pkthdr.len = 0;
					m->m_pkthdr.rcvif = (struct ifnet *)0;
				} else {
					m = m_get(M_WAIT, MT_DATA);
					mlen = MLEN;
				}
				MCLAIM(m, so->so_snd.sb_mowner);
#ifndef __QNXNTO__
				if (sock_loan_thresh >= 0 &&
				    uio->uio_iov->iov_len >= sock_loan_thresh &&
				    space >= sock_loan_thresh &&
				    (len = sosend_loan(so, uio, m,
						       space)) != 0) {
					SOSEND_COUNTER_INCR(&sosend_loan_big);
					space -= len;
					goto have_data;
				}
#endif
				if (resid >= MINCLSIZE && space >= MCLBYTES) {
					SOSEND_COUNTER_INCR(&sosend_copy_big);
					m_clget(m, M_WAIT);
					if ((m->m_flags & M_EXT) == 0)
						goto nopages;
					mlen = MCLBYTES;
					if (atomic && top == 0) {
						len = lmin(MCLBYTES - max_hdr,
						    resid);
						m->m_data += max_hdr;
					} else
						len = lmin(MCLBYTES, resid);
					space -= len;
				} else {
 nopages:
					SOSEND_COUNTER_INCR(&sosend_copy_small);
					len = lmin(lmin(mlen, resid), space);
					space -= len;
					/*
					 * For datagram protocols, leave room
					 * for protocol headers in first mbuf.
					 */
					if (atomic && top == 0 && len < mlen)
						MH_ALIGN(m, len);
				}
#ifndef __QNXNTO__
				error = uiomove(mtod(m, caddr_t), (int)len,
				    uio);
#else
				error = uiomove_fast(&set_num, set, &set_start_off, mtod(m, caddr_t), (int)len, uio, l);
#endif
 have_data:
				resid = uio->uio_resid;
				m->m_len = len;
				*mp = m;
				top->m_pkthdr.len += len;
				if (error)
					goto release;
				mp = &m->m_next;
				if (resid <= 0) {
					if (flags & MSG_EOR)
						top->m_flags |= M_EOR;
					break;
				}
			} while (space > 0 &&
#ifndef __QNXNTO__
			    atomic
#else
			    (last_preload == 0 || set_num < SET_MAX || atomic) /* Don't degenerate to kercall per PRU_SEND */
#endif
			    );
#ifdef __QNXNTO__
			if (set_num && (error = MsgReadv_r(p->p_ctxt.rcvid, set, set_num, set_start_off)) < 0) {
				error = -error;
				goto release;
			}

 moved:
#define ADD_PACKET_TAG(m, type, val)					\
do {									\
	struct m_tag *mtag =						\
	    m_tag_get(type, sizeof(uint8_t), M_NOWAIT);	\
	if (mtag != NULL) {						\
	    *(uint8_t *)(mtag + 1) = val;				\
	    m_tag_prepend(m, mtag);					\
	}								\
} while (0)
			if (so_txprio_enabled)
				ADD_PACKET_TAG(top, PACKET_TAG_TXQ, so->so_txprio);
			if (so->so_vlanprio != SO_VLANPRIO_UNDEF)
				ADD_PACKET_TAG(top, PACKET_TAG_VLANPRIO, so->so_vlanprio);
#endif
			
			s = splsoftnet();

			if (so->so_state & SS_CANTSENDMORE)
				snderr(EPIPE);

			if (dontroute)
				so->so_options |= SO_DONTROUTE;
			if (resid > 0)
				so->so_state |= SS_MORETOCOME;
			error = (*so->so_proto->pr_usrreq)(so,
			    (flags & MSG_OOB) ? PRU_SENDOOB : PRU_SEND,
			    top, addr, control, curlwp);	/* XXX */
			if (dontroute)
				so->so_options &= ~SO_DONTROUTE;
			if (resid > 0)
				so->so_state &= ~SS_MORETOCOME;
			splx(s);

			clen = 0;
			control = 0;
			top = 0;
			mp = &top;
#ifdef __QNXNTO__
			if (uio != NULL && (m = p->p_mbuf) != NULL &&
			    (m->m_flags & M_PKTHDR) == 0) {
#ifndef NDEBUG
				if (((m->m_flags & (M_EXT | M_CLUSTER)) != (M_EXT | M_CLUSTER)) &&
				    (m->m_data < m->m_pktdat || m->m_data >= m->m_pktdat + MHLEN)) {
					panic("sosend: can't transform to pkt hdr");
				}
#endif
				m->m_flags |= M_PKTHDR;
				m->m_pkthdr.len        = 0;
				m->m_pkthdr.rcvif      = NULL;
				m->m_pkthdr.csum_data  = 0;
				m->m_pkthdr.csum_flags = 0;
				SLIST_INIT(&m->m_pkthdr.tags);
			}
#endif
			if (error)
				goto release;
		} while (resid && space > 0);
	} while (resid);

 release:
	sbunlock(&so->so_snd);
 out:
	if (top)
		m_freem(top);
	if (control)
		m_freem(control);
	return (error);
}

/*
 * Following replacement or removal of the first mbuf on the first
 * mbuf chain of a socket buffer, push necessary state changes back
 * into the socket buffer so that other consumers see the values
 * consistently.  'nextrecord' is the callers locally stored value of
 * the original value of sb->sb_mb->m_nextpkt which must be restored
 * when the lead mbuf changes.  NOTE: 'nextrecord' may be NULL.
 */
static void
sbsync(struct sockbuf *sb, struct mbuf *nextrecord)
{

	/*
	 * First, update for the new value of nextrecord.  If necessary,
	 * make it the first record.
	 */
	if (sb->sb_mb != NULL)
		sb->sb_mb->m_nextpkt = nextrecord;
	else
		sb->sb_mb = nextrecord;

        /*
         * Now update any dependent socket buffer fields to reflect
         * the new state.  This is an inline of SB_EMPTY_FIXUP, with
         * the addition of a second clause that takes care of the
         * case where sb_mb has been updated, but remains the last
         * record.
         */
        if (sb->sb_mb == NULL) {
                sb->sb_mbtail = NULL;
                sb->sb_lastrecord = NULL;
        } else if (sb->sb_mb->m_nextpkt == NULL)
                sb->sb_lastrecord = sb->sb_mb;
}

/*
 * Implement receive operations on a socket.
 * We depend on the way that records are added to the sockbuf
 * by sbappend*.  In particular, each record (mbufs linked through m_next)
 * must begin with an address if the protocol so specifies,
 * followed by an optional mbuf or mbufs containing ancillary data,
 * and then zero or more mbufs of data.
 * In order to avoid blocking network interrupts for the entire time here,
 * we splx() while doing the actual copy to user space.
 * Although the sockbuf is locked, new data may still be appended,
 * and thus we must maintain consistency of the sockbuf during that time.
 *
 * The caller may receive the data as a single mbuf chain by supplying
 * an mbuf **mp0 for use in returning the chain.  The uio is then used
 * only for the count in uio_resid.
 */
#ifdef __QNXNTO__
/*
 * There's two situations unique to us where data taken off the
 * socket buffer may not actually make it to userland:
 * - Messaging passing fault.
 * - close() on fd by another thread.
 *
 * Both should be obvious to client via errno.  The first is obviously
 * an error.  There may be an argument for the second that the data
 * should stay around in case the fd was duped but is it obvious
 * to one fd whether the read on the other didn't actually succeed?
 *
 * Notice that in the case of a message pass error we don't early out
 * but save it until the end.  This makes the logic to keep atomic
 * records in order simpler.
 */
#define NTO_RECV_SET(p, iovp, niovp, m, moff, len, uio)		\
do {								\
	SETIOV((iovp), mtod((m), caddr_t) + (moff), (len));	\
	(iovp)++;						\
	(*(niovp))++;						\
	(uio)->uio_resid -= (len);				\
	(uio)->uio_offset += (len);				\
	(p)->p_offset += (len);					\
} while (0 /*CONSTCOND*/)

#define NTO_RECV_FLUSHEM(p, uio, iovp, niovp,				\
    m_outp, flush_on_wait, flush_on_exit, msg_error)			\
do {									\
	if ((msg_error) == 0) {						\
		(msg_error) = MsgWritev_r((p)->p_ctxt.rcvid,		\
		     (p)->p_read.iovp, *(niovp), (p)->p_read.flush_offset);	\
		if ((msg_error) < 0)					\
			(msg_error) = -(msg_error);			\
		else							\
			(msg_error) = 0;				\
	}								\
	*(niovp) = 0;							\
	(iovp) = (p)->p_read.iovp;					\
	m_freem(*(p)->p_read.m_to_free);				\
	*(p)->p_read.m_to_free = NULL;					\
	(m_outp) = (p)->p_read.m_to_free;				\
	(p)->p_read.flush_offset = (p)->p_offset;			\
	/* niov = 0 so no chance we point in recv buf */		\
	(flush_on_wait) = 0;						\
	/* So originator doesn't reply at offset 0 */			\
	(flush_on_exit) = 1;						\
} while (0 /*CONSTCOND*/)
#endif
int
soreceive(struct socket *so, struct mbuf **paddr, struct uio *uio,
	struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	struct lwp *l = curlwp;
	struct mbuf	*m, **mp;
	int		flags, len, error, s, offset, moff, type, orig_resid;
	const struct protosw	*pr;
	struct mbuf	*nextrecord;
	int		mbuf_removed = 0;
	const struct domain *dom;
#ifdef __QNXNTO__
	/*
	 * We assume p->read.iovp, p->read->niovp are always valid on entry.
	 * p->read.m_to_free is NULL on entry.  ie we're always called
	 * from tcpip_read in msg.c.
	 */
	int		*niovp, niov_max, msg_error;
	int		flush_on_wait, flush_on_exit;
	iov_t		*iovp;
	struct mbuf	**m_outp;
	struct		proc *p;
	unsigned	*controlseqp;
	int		dom_flags;

	p = LWP_TO_PR(l);
#endif

	pr = so->so_proto;
	dom = pr->pr_domain;
	mp = mp0;
	type = 0;
	orig_resid = uio->uio_resid;
#ifdef __QNXNTO__
	iovp            = p->p_read.iovp;
	niovp           = p->p_read.niovp;
	niov_max        = p->p_read.niov_max;
	iovp		+= *niovp;
	flush_on_wait   = 0;
	flush_on_exit   = 0;
	msg_error       = 0;
	m_outp		= p->p_read.m_to_free;
	while (*m_outp != NULL)
		m_outp = &(*m_outp)->m_next;


	if (paddr)
		*paddr = 0;

	if (flagsp)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;

	if ((flags & MSG_HDREXTEN) != 0 && controlp != NULL) {
		controlseqp = mtod(*controlp, unsigned *);
		dom_flags = DOM_EXTEN;
	} else {
		controlseqp = NULL;
		dom_flags = 0;
	}

	if (controlp)
		*controlp = 0;
#else
	if (paddr)
		*paddr = 0;
	if (controlp)
		*controlp = 0;
	if (flagsp)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;

	if ((flags & MSG_DONTWAIT) == 0)
		sodopendfree();
#endif

	if (flags & MSG_OOB) {
		m = m_get(M_WAIT, MT_DATA);
		error = (*pr->pr_usrreq)(so, PRU_RCVOOB, m,
		    (struct mbuf *)(long)(flags & MSG_PEEK),
		    (struct mbuf *)0, l);
		if (error)
			goto bad;
		do {
			error = uiomove(mtod(m, caddr_t),
			    (int) min(uio->uio_resid, m->m_len), uio);
			m = m_free(m);
		} while (uio->uio_resid && error == 0 && m);
 bad:
		if (m)
			m_freem(m);
		return (error);
	}
	if (mp)
		*mp = (struct mbuf *)0;
	if (so->so_state & SS_ISCONFIRMING && uio->uio_resid)
		(*pr->pr_usrreq)(so, PRU_RCVD, (struct mbuf *)0,
		    (struct mbuf *)0, (struct mbuf *)0, l);

 restart:
	if ((error = sblock(&so->so_rcv, SBLOCKWAIT(flags))) != 0)
		return (error);
	s = splsoftnet();

	m = so->so_rcv.sb_mb;
	/*
	 * If we have less data than requested, block awaiting more
	 * (subject to any timeout) if:
	 *   1. the current count is less than the low water mark,
	 *   2. MSG_WAITALL is set, and it is possible to do the entire
	 *	receive operation at once if we block (resid <= hiwat), or
	 *   3. MSG_DONTWAIT is not set.
	 * If MSG_WAITALL is set but resid is larger than the receive buffer,
	 * we have to do the receive in sections, and thus risk returning
	 * a short count if a timeout or signal occurs after we start.
	 */
#ifdef __QNXNTO__
/*
 * Since we often try to combine the ack with the window update
 * unlike NetBSD proper, we need to do tcp MSG_WAITALL in sections
 * so we can periodically call tcp_output() as the window moves.
 * Should be ok since user should still check return even with MSG_WAITALL.
 * CHECKME, this probably means MSG_WAITALL and MSG_PEEK are incompatible?
 */
#define EXCLUDE_WAITALL (pr->pr_flags & PR_WAITALL_RCVD)
#else
#define EXCLUDE_WAITALL (0)
#endif
	if (m == 0 || (((flags & MSG_DONTWAIT) == 0 &&
	    so->so_rcv.sb_cc < uio->uio_resid) &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && EXCLUDE_WAITALL == 0 && uio->uio_resid <= so->so_rcv.sb_hiwat)) &&
	    m->m_nextpkt == 0 && (pr->pr_flags & PR_ATOMIC) == 0)) {
#ifdef DIAGNOSTIC
		if (m == 0 && so->so_rcv.sb_cc)
			panic("receive 1");
#endif
		if (so->so_error) {
			if (m)
				goto dontblock;
			error = so->so_error;
			if ((flags & MSG_PEEK) == 0)
				so->so_error = 0;
			goto release;
		}
		if (so->so_state & SS_CANTRCVMORE) {
			if (m)
				goto dontblock;
			else
				goto release;
		}
		for (; m; m = m->m_next)
			if (m->m_type == MT_OOBDATA  || (m->m_flags & M_EOR)) {
				m = so->so_rcv.sb_mb;
				goto dontblock;
			}
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
		    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
			error = ENOTCONN;
			goto release;
		}
		if (uio->uio_resid == 0)
			goto release;
		if ((so->so_state & SS_NBIO) || (flags & MSG_DONTWAIT)) {
			error = EWOULDBLOCK;
			goto release;
		}
		SBLASTRECORDCHK(&so->so_rcv, "soreceive sbwait 1");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive sbwait 1");
		sbunlock(&so->so_rcv);
#ifdef __QNXNTO__
		/*
		 * Don't need to check flush_on_wait here as 
		 * the only point we jump to restart after
		 * potentially setting up iovs is if
		 * uio_resid == orig_resid (0 length iovs?).
		 */
#endif
		error = sbwait(&so->so_rcv);
		splx(s);
		if (error) {
#ifdef __QNXNTO__
			if (error == EBADF) {
				/*
				 * This socket was duped and
				 * another client thread closed
				 * it while we were blocked.
				 * Usually SS_CANTRCVMORE would be
				 * set and this test would be done
				 * above but this doesn't happen
				 * until last close.
				 */

				error = 0;

				if (m) {
					/* Make sure we don't sbwait() below */
					flags &= ~MSG_WAITALL;
					goto dontblock;
				}
				else {
					goto release;
				}
			}
#endif
			return (error);
		}
		goto restart;
	}
 dontblock:
	/*
	 * On entry here, m points to the first record of the socket buffer.
	 * From this point onward, we maintain 'nextrecord' as a cache of the
	 * pointer to the next record in the socket buffer.  We must keep the
	 * various socket buffer pointers and local stack versions of the
	 * pointers in sync, pushing out modifications before dropping the
	 * IPL, and re-reading them when picking it up.
	 *
	 * Otherwise, we will race with the network stack appending new data
	 * or records onto the socket buffer by using inconsistent/stale
	 * versions of the field, possibly resulting in socket buffer
	 * corruption.
	 *
	 * By holding the high-level sblock(), we prevent simultaneous
	 * readers from pulling off the front of the socket buffer.
	 */
	if (l)
#ifndef __QNXNTO__
		l->l_proc->p_stats->p_ru.ru_msgrcv++;
#else
		p->p_stats->p_ru.ru_msgrcv++;
#endif
	KASSERT(m == so->so_rcv.sb_mb);
	SBLASTRECORDCHK(&so->so_rcv, "soreceive 1");
	SBLASTMBUFCHK(&so->so_rcv, "soreceive 1");
	nextrecord = m->m_nextpkt;
#ifdef __QNXNTO__
	/*
	 * Only check controlseqp the first time through.
	 * This makes sure the head of the control data
	 * is what they expect.  If we happen to sbwait
	 * and more control data comes in they may get
	 * more than they expect but this could happen
	 * normally if the new control data came in before
	 * the actual recvmsg().  We also haven't moved
	 * any data (addr, control or normal) the first
	 * time through so this avoids windows where normal
	 * data could be lost on a EILSEQ.
	 */
	if (controlseqp != NULL) {
		if (*controlseqp == 0) {
			if (so->so_controlseq == 0) {
				/*
				 * 0 is special in userland.
				 * Don't pass it back.
				 */
				so->so_controlseq++;
			}
			*controlseqp = so->so_controlseq;
		}
		else if (*controlseqp != so->so_controlseq) {
			error = EILSEQ;
			goto release;
		}
		controlseqp = NULL;
	}
#endif
	if (pr->pr_flags & PR_ADDR) {
#ifdef DIAGNOSTIC
		if (m->m_type != MT_SONAME)
			panic("receive 1a");
#endif
		orig_resid = 0;
		if (flags & MSG_PEEK) {
			if (paddr)
				*paddr = m_copy(m, 0, m->m_len);
			m = m->m_next;
		} else {
			sbfree(&so->so_rcv, m);
			mbuf_removed = 1;
			if (paddr) {
				*paddr = m;
				so->so_rcv.sb_mb = m->m_next;
				m->m_next = 0;
				m = so->so_rcv.sb_mb;
			} else {
				MFREE(m, so->so_rcv.sb_mb);
				m = so->so_rcv.sb_mb;
			}
			sbsync(&so->so_rcv, nextrecord);
		}
	}
#ifdef __QNXNTO__
	if (pr->pr_flags & PR_ADDR_OPT) {
		/*
		 * For SCTP we may be getting a 
		 * whole message OR a partial delivery.
		 */
		if (m->m_type == MT_SONAME) {
			orig_resid = 0;
			if (flags & MSG_PEEK) {
				if (paddr)
				  *paddr = m_copy(m, 0, m->m_len);
				m = m->m_next;
			} else {
				sbfree(&so->so_rcv, m);
				if (paddr) {
					*paddr = m;
					so->so_rcv.sb_mb = m->m_next;
					m->m_next = 0;
					m = so->so_rcv.sb_mb;
				} else {
					MFREE(m, so->so_rcv.sb_mb);
					m = so->so_rcv.sb_mb;
				}
				sbsync(&so->so_rcv, nextrecord);
			}
		}
	}
#endif

	/*
	 * Process one or more MT_CONTROL mbufs present before any data mbufs
	 * in the first mbuf chain on the socket buffer.  If MSG_PEEK, we
	 * just copy the data; if !MSG_PEEK, we call into the protocol to
	 * perform externalization (or freeing if controlp == NULL).
	 */
	if (m != NULL && m->m_type == MT_CONTROL) {
		struct mbuf *cm = NULL, *cmn;
		struct mbuf **cme = &cm;

		do {
			if (flags & MSG_PEEK) {
#ifndef __QNXNTO__
				if (controlp != NULL) {
					*controlp = m_copy(m, 0, m->m_len);
					controlp = &(*controlp)->m_next;
#else
				if (cme != NULL) {
					*cme = m_copy(m, 0, m->m_len);
					cme = &(*cme)->m_next;
#endif
				}
				m = m->m_next;
			} else {
				sbfree(&so->so_rcv, m);
				so->so_rcv.sb_mb = m->m_next;
				m->m_next = NULL;
				*cme = m;
				cme = &(*cme)->m_next;
				m = so->so_rcv.sb_mb;
#ifdef __QNXNTO__
				/* mbuf removed via non peek so bump sequence */
				so->so_controlseq++;
#endif
			}
		} while (m != NULL && m->m_type == MT_CONTROL);
		if ((flags & MSG_PEEK) == 0)
			sbsync(&so->so_rcv, nextrecord);
		for (; cm != NULL; cm = cmn) {
			cmn = cm->m_next;
			cm->m_next = NULL;
			type = mtod(cm, struct cmsghdr *)->cmsg_type;
			if (controlp != NULL) {
				if (dom->dom_externalize != NULL &&
				    type == SCM_RIGHTS) {
					splx(s);
#ifndef __QNXNTO__
					error = (*dom->dom_externalize)(cm, l);
#else
					if (flags & MSG_PEEK) {
						error = (*dom->dom_externalize)
							(cm, l,
							 dom_flags | DOM_PEEK);
					} else {
						error = (*dom->dom_externalize)
							(cm, l,
							 dom_flags);
					}
#endif
					s = splsoftnet();
				}
				*controlp = cm;
				while (*controlp != NULL)
					controlp = &(*controlp)->m_next;
			} else {
				/*
				 * Dispose of any SCM_RIGHTS message that went
				 * through the read path rather than recv.
				 */
				if (dom->dom_dispose != NULL &&
				    type == SCM_RIGHTS) {
					splx(s);
					(*dom->dom_dispose)(cm);
					s = splsoftnet();
				}
				m_freem(cm);
			}
		}
		if (m != NULL)
			nextrecord = so->so_rcv.sb_mb->m_nextpkt;
		else
			nextrecord = so->so_rcv.sb_mb;
		orig_resid = 0;
	}

	/* If m is non-NULL, we have some data to read. */
	if (m != NULL) {
		type = m->m_type;
		if (type == MT_OOBDATA)
			flags |= MSG_OOB;
	}
	SBLASTRECORDCHK(&so->so_rcv, "soreceive 2");
	SBLASTMBUFCHK(&so->so_rcv, "soreceive 2");

	moff = 0;
	offset = 0;
	while (m && uio->uio_resid > 0 && error == 0) {
		if (m->m_type == MT_OOBDATA) {
			if (type != MT_OOBDATA)
				break;
		} else if (type == MT_OOBDATA)
			break;
#ifdef DIAGNOSTIC
		else if (m->m_type != MT_DATA && m->m_type != MT_HEADER)
			panic("receive 3");
#endif
		so->so_state &= ~SS_RCVATMARK;
		len = uio->uio_resid;
		if (so->so_oobmark && len > so->so_oobmark - offset)
			len = so->so_oobmark - offset;
		if (len > m->m_len - moff)
			len = m->m_len - moff;
		/*
		 * If mp is set, just pass back the mbufs.
		 * Otherwise copy them out via the uio, then free.
		 * Sockbuf must be consistent here (points to current mbuf,
		 * it points to next record) when we drop priority;
		 * we must note any additions to the sockbuf when we
		 * block interrupts again.
		 */
		if (mp == 0) {
			SBLASTRECORDCHK(&so->so_rcv, "soreceive uiomove");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive uiomove");
			splx(s);
#ifndef __QNXNTO__
			error = uiomove(mtod(m, caddr_t) + moff, (int)len, uio);
			s = splsoftnet();
			if (error) {
				/*
				 * If any part of the record has been removed
				 * (such as the MT_SONAME mbuf, which will
				 * happen when PR_ADDR, and thus also
				 * PR_ATOMIC, is set), then drop the entire
				 * record to maintain the atomicity of the
				 * receive operation.
				 *
				 * This avoids a later panic("receive 1a")
				 * when compiled with DIAGNOSTIC.
				 */
				if (m && mbuf_removed
				    && (pr->pr_flags & PR_ATOMIC))
					(void) sbdroprecord(&so->so_rcv);

				goto release;
			}
#else
#if 0
			if (do_move) {
				memcpy(); /* Can't fail */
				uio->resid -= len;
				uio->uio_offset += len;
			}
#endif
#endif
		} else
			uio->uio_resid -= len;
		if (len == m->m_len - moff) {
			if (m->m_flags & M_EOR)
				flags |= MSG_EOR;
#ifdef __QNXNTO__
			if (m->m_flags & M_NOTIFICATION)
				flags |= MSG_NOTIFICATION;
#endif
			if (flags & MSG_PEEK) {
#ifdef __QNXNTO__
#if 0
				if (do_move == 0) {
#endif
					NTO_RECV_SET(p, iovp, niovp, m, moff,
					    len, uio);
					/*
					 * This is still in the recv buffer so
					 * we have to mark for flush in case we
					 * sbwait() below.  This is because we
					 * don't have exclusive access to this
					 * mbuf via our m_outp list.  Who does
					 * PEEK and WAITALL anyway?
					 */
					if (*niovp == niov_max)
						NTO_RECV_FLUSHEM(p, uio,
						    iovp, niovp,
						    m_outp, flush_on_wait,
						    flush_on_exit, msg_error);
					else
						flush_on_wait = 1;
#if 0
				}
#endif
#endif
				m = m->m_next;
				moff = 0;
			} else {
				nextrecord = m->m_nextpkt;
				sbfree(&so->so_rcv, m);
				if (mp) {
					*mp = m;
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = (struct mbuf *)0;
				} else {
#ifndef __QNXNTO__
					MFREE(m, so->so_rcv.sb_mb);
#else
#if 0
					if (do_move == 1) {
						MFREE(m, so->so_rcv.sb_mb);
					} else {
#endif
						so->so_rcv.sb_mb = m->m_next;
						m->m_next = NULL;
						*m_outp = m;
						m_outp = &m->m_next;
						NTO_RECV_SET(p, iovp, niovp, m, moff,
						    len, uio);
						if (*niovp == niov_max)
							NTO_RECV_FLUSHEM(p, uio,
							    iovp, niovp,
							    m_outp, flush_on_wait,
							    flush_on_exit, msg_error);
#if 0
					}
#endif
#endif
					m = so->so_rcv.sb_mb;
				}
				/*
				 * If m != NULL, we also know that
				 * so->so_rcv.sb_mb != NULL.
				 */
				KASSERT(so->so_rcv.sb_mb == m);
				if (m) {
					m->m_nextpkt = nextrecord;
					if (nextrecord == NULL)
						so->so_rcv.sb_lastrecord = m;
				} else {
					so->so_rcv.sb_mb = nextrecord;
					SB_EMPTY_FIXUP(&so->so_rcv);
				}
				SBLASTRECORDCHK(&so->so_rcv, "soreceive 3");
				SBLASTMBUFCHK(&so->so_rcv, "soreceive 3");
			}
		} else {
			if (flags & MSG_PEEK)
#ifdef __QNXNTO__
			    {
#if 0
				if (do_move == 0) {
#endif
					NTO_RECV_SET(p, iovp, niovp, m, moff,
					    len, uio);
					if (*niovp == niov_max)
						NTO_RECV_FLUSHEM(p, uio,
						    iovp, niovp,
						    m_outp, flush_on_wait,
						    flush_on_exit, msg_error);
					else
						flush_on_wait = 1;
#if 0
				}
#endif
#endif
				moff += len;
#ifdef __QNXNTO__
			}
#endif
			else {
				if (mp)
#ifndef __QNXNTO__
					*mp = m_copym(m, 0, len, M_WAIT);
#else
					*mp = m_copym(m, moff, len, M_WAIT);
				
				else /* if (do_move == 0) */ {
					/*
					 * We know we won't sbwait() below as m != NULL
					 * (resid must be 0 here).
					 */
					NTO_RECV_SET(p, iovp, niovp, m, moff,
					    len, uio);
					if (*niovp == niov_max)
						NTO_RECV_FLUSHEM(p, uio,
						    iovp, niovp,
						    m_outp, flush_on_wait,
						    flush_on_exit, msg_error);
				}
#endif
				m->m_data += len;
				m->m_len -= len;
				so->so_rcv.sb_cc -= len;
			}
		}
		if (so->so_oobmark) {
			if ((flags & MSG_PEEK) == 0) {
				so->so_oobmark -= len;
				if (so->so_oobmark == 0) {
					so->so_state |= SS_RCVATMARK;
					break;
				}
			} else {
				offset += len;
				if (offset == so->so_oobmark)
					break;
			}
		}
		if (flags & MSG_EOR)
			break;
		/*
		 * If the MSG_WAITALL flag is set (for non-atomic socket),
		 * we must not quit until "uio->uio_resid == 0" or an error
		 * termination.  If a signal/timeout occurs, return
		 * with a short count but without error.
		 * Keep sockbuf locked against other readers.
		 */
		while (flags & MSG_WAITALL && m == 0 && uio->uio_resid > 0 &&
		    !sosendallatonce(so) && !nextrecord) {
			if (so->so_error || so->so_state & SS_CANTRCVMORE)
				break;
			/*
			 * If we are peeking and the socket receive buffer is
			 * full, stop since we can't get more data to peek at.
			 */
			if ((flags & MSG_PEEK) && sbspace(&so->so_rcv) <= 0)
				break;
			/*
			 * If we've drained the socket buffer, tell the
			 * protocol in case it needs to do something to
			 * get it filled again.
			 */
			if ((pr->pr_flags & PR_WANTRCVD) && so->so_pcb)
				(*pr->pr_usrreq)(so, PRU_RCVD,
				    (struct mbuf *)0,
				    (struct mbuf *)(long)flags,
				    (struct mbuf *)0, l);
			SBLASTRECORDCHK(&so->so_rcv, "soreceive sbwait 2");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive sbwait 2");
#ifdef __QNXNTO__
			if (flush_on_wait)
				NTO_RECV_FLUSHEM(p, uio,
				    iovp, niovp,
				    m_outp, flush_on_wait,
				    flush_on_exit, msg_error);
#endif
			error = sbwait(&so->so_rcv);
			if (error) {
				sbunlock(&so->so_rcv);
				splx(s);
#ifdef __QNXNTO__
				if (error == EBADF) {
					/*
					 * This socket was duped and
					 * another client thread closed
					 * it while we were blocked.
					 * Usually SS_CANTRCVMORE would
					 * be set and we would break from
					 * this while loop above but this
					 * doesn't happen until last close.
					 */
					error = 0;
					break;
				}
#endif
				return (0);
			}
			if ((m = so->so_rcv.sb_mb) != NULL)
				nextrecord = m->m_nextpkt;
		}
	}

	if (m && pr->pr_flags & PR_ATOMIC) {
		flags |= MSG_TRUNC;
		if ((flags & MSG_PEEK) == 0)
			(void) sbdroprecord(&so->so_rcv);
	}
	if ((flags & MSG_PEEK) == 0) {
		if (m == 0) {
			/*
			 * First part is an inline SB_EMPTY_FIXUP().  Second
			 * part makes sure sb_lastrecord is up-to-date if
			 * there is still data in the socket buffer.
			 */
			so->so_rcv.sb_mb = nextrecord;
			if (so->so_rcv.sb_mb == NULL) {
				so->so_rcv.sb_mbtail = NULL;
				so->so_rcv.sb_lastrecord = NULL;
			} else if (nextrecord->m_nextpkt == NULL)
				so->so_rcv.sb_lastrecord = nextrecord;
		}
		SBLASTRECORDCHK(&so->so_rcv, "soreceive 4");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive 4");
		if (pr->pr_flags & PR_WANTRCVD && so->so_pcb)
			(*pr->pr_usrreq)(so, PRU_RCVD, (struct mbuf *)0,
			    (struct mbuf *)(long)flags, (struct mbuf *)0, l);
	}
	if (orig_resid == uio->uio_resid && orig_resid &&
	    (flags & MSG_EOR) == 0 && (so->so_state & SS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv);
		splx(s);
		goto restart;
	}

	if (flagsp)
		*flagsp |= flags;
 release:
	sbunlock(&so->so_rcv);
	splx(s);
#ifdef __QNXNTO__
	if (flush_on_exit) {
		NTO_RECV_FLUSHEM(p, uio,
		    iovp, niovp,
		    m_outp, flush_on_wait,
		    flush_on_exit, msg_error);
		if (msg_error)
			error = msg_error;
	}
#endif
	return (error);
}

int
soshutdown(struct socket *so, int how)
{
	const struct protosw	*pr;

	pr = so->so_proto;
	if (!(how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR))
		return (EINVAL);

#ifdef __QNXNTO__
	if((so->so_type == SOCK_STREAM) && ((so->so_state & SS_ISCONNECTED) == 0))
		return(ENOTCONN);	
#endif
	if (how == SHUT_RD || how == SHUT_RDWR)
		sorflush(so);
	if (how == SHUT_WR || how == SHUT_RDWR)
		return (*pr->pr_usrreq)(so, PRU_SHUTDOWN, (struct mbuf *)0,
		    (struct mbuf *)0, (struct mbuf *)0, (struct lwp *)0);
	return (0);
}

void
sorflush(struct socket *so)
{
	struct sockbuf	*sb, asb;
	const struct protosw	*pr;
	int		s;

	sb = &so->so_rcv;
	pr = so->so_proto;
	sb->sb_flags |= SB_NOINTR;
	(void) sblock(sb, M_WAITOK);
	s = splnet();
	socantrcvmore(so);
	sbunlock(sb);
	asb = *sb;
	/*
	 * Clear most of the sockbuf structure, but leave some of the
	 * fields valid.
	 */
	memset(&sb->sb_startzero, 0,
	    sizeof(*sb) - offsetof(struct sockbuf, sb_startzero));
	splx(s);
	if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose)
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);
	sbrelease(&asb, so);
}

int
sosetopt(struct socket *so, int level, int optname, struct mbuf *m0)
{
	int		error;
	struct mbuf	*m;

	error = 0;
	m = m0;
	if (level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput)
			return ((*so->so_proto->pr_ctloutput)
				  (PRCO_SETOPT, so, level, optname, &m0));
		error = ENOPROTOOPT;
	} else {
		switch (optname) {

		case SO_LINGER:
			if (m == NULL || m->m_len != sizeof(struct linger)) {
				error = EINVAL;
				goto bad;
			}
			if (mtod(m, struct linger *)->l_linger < 0 ||
			    mtod(m, struct linger *)->l_linger > (INT_MAX / hz)) {
				error = EDOM;
				goto bad;
			}
			so->so_linger = mtod(m, struct linger *)->l_linger;
			/* fall thru... */

		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_USELOOPBACK:
		case SO_BROADCAST:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_OOBINLINE:
		case SO_TIMESTAMP:
			if (m == NULL || m->m_len < sizeof(int)) {
				error = EINVAL;
				goto bad;
			}
			if (*mtod(m, int *))
				so->so_options |= optname;
			else
				so->so_options &= ~optname;
			break;

		case SO_SNDBUF:
		case SO_RCVBUF:
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
		    {
			int optval;

			if (m == NULL || m->m_len < sizeof(int)) {
				error = EINVAL;
				goto bad;
			}

			/*
			 * Values < 1 make no sense for any of these
			 * options, so disallow them.
			 */
			optval = *mtod(m, int *);
			if (optval < 1) {
				error = EINVAL;
				goto bad;
			}

			switch (optname) {

			case SO_SNDBUF:
			case SO_RCVBUF:
				if (sbreserve(optname == SO_SNDBUF ?
				    &so->so_snd : &so->so_rcv,
				    (u_long) optval, so) == 0) {
					error = ENOBUFS;
					goto bad;
				}
				break;

			/*
			 * Make sure the low-water is never greater than
			 * the high-water.
			 */
			case SO_SNDLOWAT:
#ifdef __QNXNTO__
				/*
				 * On tcp sockets, this option is usually specified
				 * before the connection where we recalculate it (see
				 * tcp_check_sndbuf()).  Our algorithm is probably better
				 * anyway.  If they really need this, can re-override
				 * after the connection is up.
				 */
#endif
				so->so_snd.sb_lowat =
				    (optval > so->so_snd.sb_hiwat) ?
				    so->so_snd.sb_hiwat : optval;
				break;
			case SO_RCVLOWAT:
				so->so_rcv.sb_lowat =
				    (optval > so->so_rcv.sb_hiwat) ?
				    so->so_rcv.sb_hiwat : optval;
				break;
			}
			break;
		    }

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
		    {
			struct timeval *tv;
			int val;
#ifdef __QNXNTO__
			int64_t val_long;
#endif

			if (m == NULL || m->m_len < sizeof(*tv)) {
				error = EINVAL;
				goto bad;
			}
			tv = mtod(m, struct timeval *);
#ifndef __QNXNTO__
			if (tv->tv_sec > (INT_MAX - tv->tv_usec / tick) / hz) {
				error = EDOM;
				goto bad;
			}
			val = tv->tv_sec * hz + tv->tv_usec / tick;
			if (val == 0 && tv->tv_usec != 0)
				val = 1;
#else
			/*
			 * Couple of issues.  People (Posix) get excited when timeouts happen too
			 * early.  Too late is OK.  The NetBSD scheme is to round down to nearest
			 * tick, but there's still the issue of starting the operation in the middle
			 * of a tick (round down twice).  We comprimise by rounding up here, but
			 * rounding back down when reporting.  This means the requested value is
			 * probably greater than what getsockopt(.., SO_*TIMEO) returns (like NetBSD)
			 * but at least getsockopt() returns a guaranteed minimum.  Also hz is an
			 * approximation so use NTO_mHZ to get closer.
			 */
			if (tv->tv_sec > (INT_MAX - tv->tv_usec / (1000000000 / NTO_mHZ)) / (NTO_mHZ / 1000)) {
				error = EDOM;
				goto bad;
			}
			val_long = tv->tv_sec * (NTO_mHZ / 1000 ) + tv->tv_usec / (1000000000 / NTO_mHZ);
			if (val_long == 0 && tv->tv_usec != 0)
				val_long = 1;
			else if (val_long + 2 > INT_MAX) {
				error = EDOM;
				goto bad;
			}
				
			val = val_long;
			if (val != 0)
				val += 2;
#endif

			switch (optname) {

			case SO_SNDTIMEO:
				so->so_snd.sb_timeo = val;
				break;
			case SO_RCVTIMEO:
				so->so_rcv.sb_timeo = val;
				break;
			}
			break;
		    }
#ifdef __QNXNTO__
		/*
		 * Socket level option but the route is often
		 * cached in inp_route so handle it at proto.
		 */
		case SO_BINDTODEVICE:
			if (so->so_proto && so->so_proto->pr_ctloutput)
				return ((*so->so_proto->pr_ctloutput)
				    (PRCO_SETOPT, so, level, optname, &m0));
			error = ENOPROTOOPT;
			break;
#ifdef QNX_MFIB
		/*
		 * Used to modify which fib the socket is intended to be addressing. User sockets are fib-scoped based on their
		 * group IDs.
		 *
		 */
		case SO_SETFIB: {
			int optval;
			int orig_fib;

			if (m == NULL || m->m_len < sizeof(int)) {
				error = EINVAL;
				goto bad;
			}

			/*
			 * Values < 0 or > FIBS_MAX make no sense for this
			 * option, so disallow them.
			 */
			optval = *mtod(m, int *);
			if (optval < 0 || optval >= FIBS_MAX) {
				error = EINVAL;
				goto bad;
			}
			/* verify specified fib is allowed for this user */
			if ((kauth_authorize_generic(curlwp->l_cred, KAUTH_GENERIC_ISSUSER, NULL) != 0) &&
					(kauth_chkfib4cred(curlwp->l_cred, optval) != 0)) {
#ifndef NDEBUG
				if (debug_net_so_fib_verbosity > 0) {
					printf("Socket type '%d': pid=%10d/user=%10d/s=%10d SO_SETFIB failed (EPERM) from fib %4d to fib %4d\n",
							so->so_fiborigin, curproc->p_ctxt.info.pid,
							(int)kauth_cred_geteuid(curlwp->l_cred), (int)so,
							so->so_fibnum, optval);
				}
#endif
				error = EPERM;
				goto bad;
			}

			orig_fib = so->so_fibnum;
			so->so_fibnum = optval;
			so->so_fiborigin=SO_FIB_SETFIB;
#ifndef NDEBUG
			if (debug_net_so_fib_verbosity > 1) {
				printf("Socket type '%d': pid=%10d/user=%10d/s=%10d SO_SETFIB from fib %4d to fib %4d\n",
						so->so_fiborigin, curproc->p_ctxt.info.pid,
						(int)kauth_cred_geteuid(curlwp->l_cred),(int)so,
						orig_fib, so->so_fibnum);
			}
#endif
			break;
		}
#endif
		case SO_TXPRIO: {
			uint8_t	optval;
			if (m == NULL || m->m_len != sizeof(uint8_t)) {
				error = EINVAL;
				goto bad;
			}
			if (!so_txprio_enabled) {
				error = EOPNOTSUPP;
				goto bad;
			}
			optval = *mtod(m, uint8_t *);
			if (optval < SO_TXPRIO_MIN || optval > SO_TXPRIO_MAX) {
				error = EINVAL;
				goto bad;
			}
			so->so_txprio = optval;
			break;
		}
		case SO_VLANPRIO: {
			uint8_t optval;
			if (m == NULL || m->m_len != sizeof(uint8_t)) {
				error = EINVAL;
				goto bad;
			}
			optval = *mtod(m, uint8_t *);
			if (optval < SO_VLANPRIO_MIN || optval > SO_VLANPRIO_MAX) {
				error = EINVAL;
				goto bad;
			}
			so->so_vlanprio = optval;
			break;
		}
#endif

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto && so->so_proto->pr_ctloutput) {
			(void) ((*so->so_proto->pr_ctloutput)
				  (PRCO_SETOPT, so, level, optname, &m0));
			m = NULL;	/* freed by protocol */
		}
	}
 bad:
	if (m)
		(void) m_free(m);
	return (error);
}

int
sogetopt(struct socket *so, int level, int optname, struct mbuf **mp)
{
	struct mbuf	*m;

	if (level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			return ((*so->so_proto->pr_ctloutput)
				  (PRCO_GETOPT, so, level, optname, mp));
		} else
			return (ENOPROTOOPT);
#ifdef __QNXNTO__
		/*
		 * Socket level option but the route is often
		 * cached in inp_route so handle it at proto.
		 */
	} else if (optname == SO_BINDTODEVICE) {
		if (so->so_proto && so->so_proto->pr_ctloutput)
			return ((*so->so_proto->pr_ctloutput)
				    (PRCO_GETOPT, so, level, optname, mp));
		return ENOPROTOOPT;
#endif
	} else {
		m = m_get(M_WAIT, MT_SOOPTS);
		m->m_len = sizeof(int);

		switch (optname) {

		case SO_LINGER:
			m->m_len = sizeof(struct linger);
			mtod(m, struct linger *)->l_onoff =
				so->so_options & SO_LINGER;
			mtod(m, struct linger *)->l_linger = so->so_linger;
			break;

		case SO_USELOOPBACK:
		case SO_DONTROUTE:
		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_BROADCAST:
		case SO_OOBINLINE:
		case SO_TIMESTAMP:
			*mtod(m, int *) = so->so_options & optname;
			break;

		case SO_TYPE:
			*mtod(m, int *) = so->so_type;
			break;

		case SO_ERROR:
			*mtod(m, int *) = so->so_error;
			so->so_error = 0;
			break;

		case SO_SNDBUF:
			*mtod(m, int *) = so->so_snd.sb_hiwat;
			break;

		case SO_RCVBUF:
			*mtod(m, int *) = so->so_rcv.sb_hiwat;
			break;

		case SO_SNDLOWAT:
			*mtod(m, int *) = so->so_snd.sb_lowat;
			break;

		case SO_RCVLOWAT:
			*mtod(m, int *) = so->so_rcv.sb_lowat;
			break;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
		    {
			uint64_t val = (optname == SO_SNDTIMEO ?
			     so->so_snd.sb_timeo : so->so_rcv.sb_timeo);

			m->m_len = sizeof(struct timeval);
#ifndef __QNXNTO__
			mtod(m, struct timeval *)->tv_sec = val / hz;
			mtod(m, struct timeval *)->tv_usec =
			    (val % hz) * tick;
#else
			/* See comment when val set above */
			val = imax(val - 2, 0);

			mtod(m, struct timeval *)->tv_sec = (val * 1000) / NTO_mHZ;
			mtod(m, struct timeval *)->tv_usec =
			    ((val * 1000) % NTO_mHZ) * 1000000 / NTO_mHZ;
#endif
			break;
		    }

		case SO_OVERFLOWED:
			*mtod(m, int *) = so->so_rcv.sb_overflowed;
			break;
#ifdef __QNXNTO__
		case SO_TXPRIO:
			if (!so_txprio_enabled) {
				(void)m_free(m);
				return (EOPNOTSUPP);
			}
			m->m_len = sizeof(uint8_t);
			*mtod(m, uint8_t *) = so->so_txprio;
			break;
		case SO_VLANPRIO:
			m->m_len = sizeof(uint8_t);
			*mtod(m, uint8_t *) = so->so_vlanprio;
			break;
#endif
		default:
			(void)m_free(m);
			return (ENOPROTOOPT);
		}
		*mp = m;
		return (0);
	}
}

void
sohasoutofband(struct socket *so)
{
#ifndef __QNXNTO__
	fownsignal(so->so_pgid, SIGURG, POLL_PRI, POLLPRI|POLLRDBAND, so);
	selwakeup(&so->so_rcv.sb_sel);
#else
	fownsignal(so->so_rcvid, SIGURG, POLL_PRI, POLLPRI|POLLRDBAND, so);
	iofunc_notify_trigger(so->so_notify, 1, IOFUNC_NOTIFY_OBAND);
#endif
}

static void
filt_sordetach(struct knote *kn)
{
	struct socket	*so;

	so = (struct socket *)kn->kn_fp->f_data;
	SLIST_REMOVE(&so->so_rcv.sb_sel.sel_klist, kn, knote, kn_selnext);
	if (SLIST_EMPTY(&so->so_rcv.sb_sel.sel_klist))
		so->so_rcv.sb_flags &= ~SB_KNOTE;
}

/*ARGSUSED*/
static int
filt_soread(struct knote *kn, long hint)
{
	struct socket	*so;

	so = (struct socket *)kn->kn_fp->f_data;
	kn->kn_data = so->so_rcv.sb_cc;
	if (so->so_state & SS_CANTRCVMORE) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		return (1);
	}
	if (so->so_error)	/* temporary udp error */
		return (1);
	if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= kn->kn_sdata);
	return (kn->kn_data >= so->so_rcv.sb_lowat);
}

static void
filt_sowdetach(struct knote *kn)
{
	struct socket	*so;

	so = (struct socket *)kn->kn_fp->f_data;
	SLIST_REMOVE(&so->so_snd.sb_sel.sel_klist, kn, knote, kn_selnext);
	if (SLIST_EMPTY(&so->so_snd.sb_sel.sel_klist))
		so->so_snd.sb_flags &= ~SB_KNOTE;
}

/*ARGSUSED*/
static int
filt_sowrite(struct knote *kn, long hint)
{
	struct socket	*so;

	so = (struct socket *)kn->kn_fp->f_data;
	kn->kn_data = sbspace(&so->so_snd);
	if (so->so_state & SS_CANTSENDMORE) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		return (1);
	}
	if (so->so_error)	/* temporary udp error */
		return (1);
	if (((so->so_state & SS_ISCONNECTED) == 0) &&
	    (so->so_proto->pr_flags & PR_CONNREQUIRED))
		return (0);
	if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= kn->kn_sdata);
	return (kn->kn_data >= so->so_snd.sb_lowat);
}

/*ARGSUSED*/
static int
filt_solisten(struct knote *kn, long hint)
{
	struct socket	*so;

	so = (struct socket *)kn->kn_fp->f_data;

	/*
	 * Set kn_data to number of incoming connections, not
	 * counting partial (incomplete) connections.
	 */
	kn->kn_data = so->so_qlen;
	return (kn->kn_data > 0);
}

static const struct filterops solisten_filtops =
	{ 1, NULL, filt_sordetach, filt_solisten };
static const struct filterops soread_filtops =
	{ 1, NULL, filt_sordetach, filt_soread };
static const struct filterops sowrite_filtops =
	{ 1, NULL, filt_sowdetach, filt_sowrite };

int
soo_kqfilter(struct file *fp, struct knote *kn)
{
	struct socket	*so;
	struct sockbuf	*sb;

	so = (struct socket *)kn->kn_fp->f_data;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (so->so_options & SO_ACCEPTCONN)
			kn->kn_fop = &solisten_filtops;
		else
			kn->kn_fop = &soread_filtops;
		sb = &so->so_rcv;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &sowrite_filtops;
		sb = &so->so_snd;
		break;
	default:
		return (1);
	}
	SLIST_INSERT_HEAD(&sb->sb_sel.sel_klist, kn, kn_selnext);
	sb->sb_flags |= SB_KNOTE;
	return (0);
}

#include <sys/sysctl.h>

#ifndef __QNXNTO__
static int sysctl_kern_somaxkva(SYSCTLFN_PROTO);

/*
 * sysctl helper routine for kern.somaxkva.  ensures that the given
 * value is not too small.
 * (XXX should we maybe make sure it's not too large as well?)
 */
static int
sysctl_kern_somaxkva(SYSCTLFN_ARGS)
{
	int error, new_somaxkva;
	struct sysctlnode node;
	int s;

	new_somaxkva = somaxkva;
	node = *rnode;
	node.sysctl_data = &new_somaxkva;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	if (new_somaxkva < (16 * 1024 * 1024)) /* sanity */
		return (EINVAL);

	s = splvm();
	simple_lock(&so_pendfree_slock);
	somaxkva = new_somaxkva;
	wakeup(&socurkva);
	simple_unlock(&so_pendfree_slock);
	splx(s);

	return (error);
}

SYSCTL_SETUP(sysctl_kern_somaxkva_setup, "sysctl kern.somaxkva setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "kern", NULL,
		       NULL, 0, NULL, 0,
		       CTL_KERN, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "somaxkva",
		       SYSCTL_DESCR("Maximum amount of kernel memory to be "
				    "used for socket buffers"),
		       sysctl_kern_somaxkva, 0, NULL, 0,
		       CTL_KERN, KERN_SOMAXKVA, CTL_EOL);
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/uipc_socket.c $ $Rev: 872079 $")
#endif
