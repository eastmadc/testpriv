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

/*	$NetBSD: kern_sysctl.c,v 1.206 2006/11/01 10:17:58 yamt Exp $	*/

/*-
 * Copyright (c) 2003 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Brown.
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
 *      This product includes software developed by the NetBSD
 *      Foundation, Inc. and its contributors.
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

/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
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
 *	@(#)kern_sysctl.c	8.9 (Berkeley) 5/20/95
 */

/*
 * sysctl system call.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: kern_sysctl.c,v 1.206 2006/11/01 10:17:58 yamt Exp $");

#include "opt_defcorename.h"
#include "opt_ktrace.h"
#ifndef __QNXNTO__
#include "ksyms.h"
#endif

#include <sys/param.h>
#define __COMPAT_SYSCTL
#include <sys/sysctl.h>
#include <sys/systm.h>
#ifndef __QNXNTO__
#include <sys/buf.h>
#include <sys/ksyms.h>
#endif
#include <sys/malloc.h>
#ifndef __QNXNTO__
#include <sys/mount.h>
#include <sys/sa.h>
#endif
#include <sys/syscallargs.h>
#include <sys/kauth.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <machine/stdarg.h>

#define	MAXDESCLEN	1024
MALLOC_DEFINE(M_SYSCTLNODE, "sysctlnode", "sysctl node structures");
MALLOC_DEFINE(M_SYSCTLDATA, "sysctldata", "misc sysctl data");

#ifndef __QNXNTO__
static int sysctl_mmap(SYSCTLFN_PROTO);
#endif
static int sysctl_alloc(struct sysctlnode *, int);
static int sysctl_realloc(struct sysctlnode *);

static int sysctl_cvt_in(struct lwp *, int *, const void *, size_t,
			 struct sysctlnode *);
static int sysctl_cvt_out(struct lwp *, int, const struct sysctlnode *,
			  void *, size_t, size_t *);

static int sysctl_log_add(struct sysctllog **, const struct sysctlnode *);
static int sysctl_log_realloc(struct sysctllog *);

struct sysctllog {
	const struct sysctlnode *log_root;
	int *log_num;
	int log_size, log_left;
};

/*
 * the "root" of the new sysctl tree
 */
struct sysctlnode sysctl_root = {
	.sysctl_flags = SYSCTL_VERSION|
	    CTLFLAG_ROOT|CTLFLAG_READWRITE|
	    CTLTYPE_NODE,
	.sysctl_num = 0,
	/*
	 * XXX once all ports are on gcc3, we can get rid of this
	 * ugliness and simply make it into
	 *
	 *	.sysctl_size = sizeof(struct sysctlnode),
	 */
	sysc_init_field(_sysctl_size, sizeof(struct sysctlnode)),
	.sysctl_name = "(root)",
};

/*
 * link set of functions that add nodes at boot time (see also
 * sysctl_buildtree())
 */
__link_set_decl(sysctl_funcs, sysctl_setup_func);
#ifndef __QNXNTO__

/*
 * The `sysctl_lock' is intended to serialize access to the sysctl
 * tree.  Given that it is now (a) dynamic, and (b) most consumers of
 * sysctl are going to be copying data out, the old `sysctl_memlock'
 * has been `upgraded' to simply guard the whole tree.
 *
 * The two new data here are to keep track of the locked chunk of
 * memory, if there is one, so that it can be released more easily
 * from anywhere.
 */
struct lock sysctl_treelock;
caddr_t sysctl_memaddr;
size_t sysctl_memsize;

/*
 * Attributes stored in the kernel.
 */
#endif /* !__QNXNTO__ */
char hostname[MAXHOSTNAMELEN];
int hostnamelen;

#ifndef __QNXNTO__
char domainname[MAXHOSTNAMELEN];
int domainnamelen;

long hostid;
#endif /* !__QNXNTO__ */

#ifndef __QNXNTO__
#ifndef DEFCORENAME
#define	DEFCORENAME	"%n.core"
#endif
char defcorename[MAXPATHLEN] = DEFCORENAME;

#endif /* !__QNXXNTO__ */
/*
 * ********************************************************************
 * Section 0: Some simple glue
 * ********************************************************************
 * By wrapping copyin(), copyout(), and copyinstr() like this, we can
 * stop caring about who's calling us and simplify some code a bunch.
 * ********************************************************************
 */
static inline int
sysctl_copyin(struct lwp *l, const void *uaddr, void *kaddr, size_t len)
{
	int error;

	if (l != NULL) {
		error = copyin(uaddr, kaddr, len);
#ifdef KTRACE
		if (!error && KTRPOINT(l->l_proc, KTR_MIB)) {
			struct iovec iov;

			iov.iov_base = (void *)(vaddr_t)uaddr;
			iov.iov_len = len;
			ktrgenio(l, -1, UIO_WRITE, &iov, len, error);
		}
#endif

	} else {
#ifndef __QNXNTO__
		error = kcopy(uaddr, kaddr, len);
#else
		memcpy(kaddr, uaddr, len);
		error = 0;
#endif
	}

	return error;
}

static inline int
sysctl_copyout(struct lwp *l, const void *kaddr, void *uaddr, size_t len)
{
	int error;

	if (l != NULL) {
		error = copyout(kaddr, uaddr, len);
#ifdef KTRACE
		if (!error && KTRPOINT(l->l_proc, KTR_MIB)) {
			struct iovec iov;

			iov.iov_base = (void *)(vaddr_t)uaddr;
			iov.iov_len = len;
			ktrgenio(l, -1, UIO_READ, &iov, len, error);
		}
#endif
	} else {
#ifndef __QNXNTO__
		error = kcopy(kaddr, uaddr, len);
#else
		memcpy(uaddr, kaddr, len);
		return 0;
#endif
	}
	
	return error;
}

static inline int
sysctl_copyinstr(struct lwp *l, const void *uaddr, void *kaddr,
		 size_t len, size_t *done)
{
	int error;

	if (l != NULL) {
		error = copyinstr(uaddr, kaddr, len, done);
#ifdef KTRACE
		if (!error && KTRPOINT(l->l_proc, KTR_MIB)) {
			struct iovec iov;

			iov.iov_base = (void *)(vaddr_t)uaddr;
			iov.iov_len = len;
			ktrgenio(l, -1, UIO_WRITE, &iov, len, error);
		}
#endif
	} else {
#ifndef __QNXNTO__
		error = copystr(uaddr, kaddr, len, done);
#else
		panic("sysctl_copyinstr");
#endif
	}

	return error;
}

/*
 * ********************************************************************
 * Initialize sysctl subsystem.
 * ********************************************************************
 */
void
sysctl_init(void)
{
	sysctl_setup_func * const *sysctl_setup, f;

#ifndef __QNXNTO__
	lockinit(&sysctl_treelock, PRIBIO|PCATCH, "sysctl", 0, 0);
#endif

	/*
	 * dynamic mib numbers start here
	 */
	sysctl_root.sysctl_num = CREATE_BASE;

        __link_set_foreach(sysctl_setup, sysctl_funcs) {
		/*
		 * XXX - why do i have to coerce the pointers like this?
		 */
		f = (void*)*sysctl_setup;
		(*f)(NULL);
	}

	/*
	 * setting this means no more permanent nodes can be added,
	 * trees that claim to be readonly at the root now are, and if
	 * the main tree is readonly, *everything* is.
	 */
	sysctl_root.sysctl_flags |= CTLFLAG_PERMANENT;

}

/*
 * ********************************************************************
 * The main native sysctl system call itself.
 * ********************************************************************
 */
int
sys___sysctl(struct lwp *l, void *v, register_t *retval)
{
	struct sys___sysctl_args /* {
		syscallarg(const int *) name;
		syscallarg(u_int) namelen;
		syscallarg(void *) old;
		syscallarg(size_t *) oldlenp;
		syscallarg(const void *) new;
		syscallarg(size_t) newlen;
	} */ *uap = v;
	int error, nerror, name[CTL_MAXNAME];
	size_t oldlen, savelen, *oldlenp;

	/*
	 * get oldlen
	 */
	oldlen = 0;
	oldlenp = SCARG(uap, oldlenp);
	if (oldlenp != NULL) {
#ifdef __QNXNTO__
		/*
		 * We return our oldlen in the status of
		 * the reply so we can't copy it out below.
		 * We could copy it in here if we pointed it
		 * in the msg context but we still couldn't
		 * copy it out as we set VM_OUTFORCE.
		 */
		curproc->p_vmspace.vm_flags |= VM_NOCTXT;
#endif
		error = copyin(oldlenp, &oldlen, sizeof(oldlen));
		if (error)
			return (error);
	}
	savelen = oldlen;

	/*
	 * top-level sysctl names may or may not be non-terminal, but
	 * we don't care
	 */
	if (SCARG(uap, namelen) > CTL_MAXNAME || SCARG(uap, namelen) < 1)
		return (EINVAL);
	error = copyin(SCARG(uap, name), &name,
		       SCARG(uap, namelen) * sizeof(int));
	if (error)
		return (error);

#ifdef KTRACE
	if (KTRPOINT(l->l_proc, KTR_MIB)) 
		ktrmib(l, name, SCARG(uap, namelen));
#endif
	/*
	 * wire old so that copyout() is less likely to fail?
	 */
#ifndef __QNXNTO__
	error = sysctl_lock(l, SCARG(uap, old), savelen);
	if (error)
		return (error);
#endif

	/*
	 * do sysctl work (NULL means main built-in default tree)
	 */
	error = sysctl_dispatch(&name[0], SCARG(uap, namelen),
				SCARG(uap, old), &oldlen,
				SCARG(uap, new), SCARG(uap, newlen),
				&name[0], l, NULL);

	/*
	 * release the sysctl lock
	 */
#ifndef __QNXNTO__
	sysctl_unlock(l);
#endif

	/*
	 * set caller's oldlen to new value even in the face of an
	 * error (if this gets an error and they didn't have one, they
	 * get this one)
	 */
	if (oldlenp) {
#ifdef __QNXNTO__
		/* As above */
		curproc->p_vmspace.vm_flags |= VM_NOCTXT;
#endif
		nerror = copyout(&oldlen, oldlenp, sizeof(oldlen));
		if (error == 0)
			error = nerror;
	}

	/*
	 * if the only problem is that we weren't given enough space,
	 * that's an ENOMEM error
	 */
	if (error == 0 && SCARG(uap, old) != NULL && savelen < oldlen)
		error = ENOMEM;

	return (error);
}

#ifndef __QNXNTO__
/*
 * ********************************************************************
 * Section 1: How the tree is used
 * ********************************************************************
 * Implementations of sysctl for emulations should typically need only
 * these three functions in this order: lock the tree, dispatch
 * request into it, unlock the tree.
 * ********************************************************************
 */
int
sysctl_lock(struct lwp *l, void *oldp, size_t savelen)
{
	int error = 0;

	error = lockmgr(&sysctl_treelock, LK_EXCLUSIVE, NULL);
	if (error)
		return (error);

	if (l != NULL && oldp != NULL && savelen) {

		/*
		 * be lazy - memory is locked for short time only, so
		 * just do a basic check against system limit
		 */

		if (uvmexp.wired + atop(savelen) > uvmexp.wiredmax) {
			lockmgr(&sysctl_treelock, LK_RELEASE, NULL);
			return (ENOMEM);
		}
		error = uvm_vslock(l->l_proc->p_vmspace, oldp, savelen,
				   VM_PROT_WRITE);
		if (error) {
			(void) lockmgr(&sysctl_treelock, LK_RELEASE, NULL);
			return (error);
		}
		sysctl_memaddr = oldp;
		sysctl_memsize = savelen;
	}

	return (0);
}
#endif

/*
 * ********************************************************************
 * the main sysctl dispatch routine.  scans the given tree and picks a
 * function to call based on what it finds.
 * ********************************************************************
 */
int
sysctl_dispatch(SYSCTLFN_ARGS)
{
	int error;
	sysctlfn fn;
	int ni;

	if (rnode && SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_dispatch: rnode %p wrong version\n", rnode);
		error = EINVAL;
		goto out;
	}

	fn = NULL;
	error = sysctl_locate(l, name, namelen, &rnode, &ni);

	if (rnode->sysctl_func != NULL) {
		/*
		 * the node we ended up at has a function, so call it.  it can
		 * hand off to query or create if it wants to.
		 */
		fn = rnode->sysctl_func;
	} else if (error == 0) {
		/*
		 * we found the node they were looking for, so do a lookup.
		 */
		fn = (sysctlfn)sysctl_lookup; /* XXX may write to rnode */
	} else if (error == ENOENT && (ni + 1) == namelen && name[ni] < 0) {
		/*
		 * prospective parent node found, but the terminal node was
		 * not.  generic operations associate with the parent.
		 */
		switch (name[ni]) {
		case CTL_QUERY:
			fn = sysctl_query;
			break;
		case CTL_CREATE:
#if NKSYMS > 0
		case CTL_CREATESYM:
#endif /* NKSYMS > 0 */
			fn = (sysctlfn)sysctl_create; /* we own the rnode */
			break;
		case CTL_DESTROY:
			fn = (sysctlfn)sysctl_destroy; /* we own the rnode */
			break;
#ifndef __QNXNTO__
		case CTL_MMAP:
			fn = (sysctlfn)sysctl_mmap; /* we own the rnode */
			break;
#endif
		case CTL_DESCRIBE:
			fn = sysctl_describe;
			break;
		default:
			error = EOPNOTSUPP;
			break;
		}
	}

	/*
	 * after all of that, maybe we found someone who knows how to
	 * get us what we want?
	 */
	if (fn != NULL)
		error = (*fn)(name + ni, namelen - ni, oldp, oldlenp,
			      newp, newlen, name, l, rnode);
	else if (error == 0)
		error = EOPNOTSUPP;

out:
	return (error);
}

#ifndef __QNXNTO__
/*
 * ********************************************************************
 * Releases the tree lock.  Note that if uvm_vslock() was called when
 * the lock was taken, we release that memory now.  By keeping track
 * of where and how much by ourselves, the lock can be released much
 * more easily from anywhere.
 * ********************************************************************
 */
void
sysctl_unlock(struct lwp *l)
{

	if (l != NULL && sysctl_memsize != 0) {
		uvm_vsunlock(l->l_proc->p_vmspace, sysctl_memaddr,
			     sysctl_memsize);
		sysctl_memsize = 0;
	}

	(void) lockmgr(&sysctl_treelock, LK_RELEASE, NULL);
}
#endif

/*
 * ********************************************************************
 * Section 2: The main tree interfaces
 * ********************************************************************
 * This is how sysctl_dispatch() does its work, and you can too, by
 * calling these routines from helpers (though typically only
 * sysctl_lookup() will be used).  The tree MUST BE LOCKED when these
 * are called.
 * ********************************************************************
 */

/*
 * sysctl_locate -- Finds the node matching the given mib under the
 * given tree (via rv).  If no tree is given, we fall back to the
 * native tree.  The current process (via l) is used for access
 * control on the tree (some nodes may be traversable only by root) and
 * on return, nip will show how many numbers in the mib were consumed.
 */
int
sysctl_locate(struct lwp *l, const int *name, u_int namelen,
	      const struct sysctlnode **rnode, int *nip)
{
	const struct sysctlnode *node, *pnode;
	int tn, si, ni, error, alias;

	/*
	 * basic checks and setup
	 */
	if (*rnode == NULL)
		*rnode = &sysctl_root;
	if (nip)
		*nip = 0;
	if (namelen == 0)
		return (0);

	/*
	 * search starts from "root"
	 */
	pnode = *rnode;
	if (SYSCTL_VERS(pnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_locate: pnode %p wrong version\n", pnode);
		return (EINVAL);
	}
	node = pnode->sysctl_child;
	error = 0;

	/*
	 * scan for node to which new node should be attached
	 */
	for (ni = 0; ni < namelen; ni++) {
		/*
		 * walked off bottom of tree
		 */
		if (node == NULL) {
			if (SYSCTL_TYPE(pnode->sysctl_flags) == CTLTYPE_NODE)
				error = ENOENT;
			else
				error = ENOTDIR;
			break;
		}
		/*
		 * can anyone traverse this node or only root?
		 */
		if (l != NULL && (pnode->sysctl_flags & CTLFLAG_PRIVATE) &&
		    (error = kauth_authorize_system(l->l_cred,
		    KAUTH_SYSTEM_SYSCTL, KAUTH_REQ_SYSTEM_SYSCTL_PRVT,
		    NULL, NULL, NULL)) != 0)
			return (error);
		/*
		 * find a child node with the right number
		 */
		tn = name[ni];
		alias = 0;

		si = 0;
		/*
		 * Note: ANYNUMBER only matches positive integers.
		 * Since ANYNUMBER is only permitted on single-node
		 * sub-trees (eg proc), check before the loop and skip
		 * it if we can.
		 */
		if ((node[si].sysctl_flags & CTLFLAG_ANYNUMBER) && (tn >= 0))
			goto foundit;
		for (; si < pnode->sysctl_clen; si++) {
			if (node[si].sysctl_num == tn) {
				if (node[si].sysctl_flags & CTLFLAG_ALIAS) {
					if (alias++ == 4)
						break;
					else {
						tn = node[si].sysctl_alias;
						si = -1;
					}
				} else
					goto foundit;
			}
		}
		/*
		 * if we ran off the end, it obviously doesn't exist
		 */
		error = ENOENT;
		break;

		/*
		 * so far so good, move on down the line
		 */
	  foundit:
		pnode = &node[si];
		if (SYSCTL_TYPE(pnode->sysctl_flags) == CTLTYPE_NODE)
			node = node[si].sysctl_child;
		else
			node = NULL;
	}

	*rnode = pnode;
	if (nip)
		*nip = ni;

	return (error);
}

/*
 * sysctl_query -- The auto-discovery engine.  Copies out the structs
 * describing nodes under the given node and handles overlay trees.
 */
int
sysctl_query(SYSCTLFN_ARGS)
{
	int error, ni, elim, v;
	size_t out, left, t;
	const struct sysctlnode *enode, *onode;
	struct sysctlnode qnode;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_query: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	if (SYSCTL_TYPE(rnode->sysctl_flags) != CTLTYPE_NODE)
		return (ENOTDIR);
	if (namelen != 1 || name[0] != CTL_QUERY)
		return (EINVAL);

	error = 0;
	out = 0;
	left = *oldlenp;
	elim = 0;
	enode = NULL;

	/*
	 * translate the given request to a current node
	 */
	error = sysctl_cvt_in(l, &v, newp, newlen, &qnode);
	if (error)
		return (error);

	/*
	 * if the request specifies a version, check it
	 */
	if (qnode.sysctl_ver != 0) {
		enode = rnode;
		if (qnode.sysctl_ver != enode->sysctl_ver &&
		    qnode.sysctl_ver != sysctl_rootof(enode)->sysctl_ver)
			return (EINVAL);
	}

#ifndef __QNXNTO__
	/*
	 * process has overlay tree
	 */
	if (l && l->l_proc->p_emul->e_sysctlovly) {
		enode = l->l_proc->p_emul->e_sysctlovly;
		elim = (name - oname);
		error = sysctl_locate(l, oname, elim, &enode, NULL);
		if (error == 0) {
			/* ah, found parent in overlay */
			elim = enode->sysctl_clen;
			enode = enode->sysctl_child;
		} else {
			error = 0;
			elim = 0;
			enode = NULL;
		}
	}
#endif

	for (ni = 0; ni < rnode->sysctl_clen; ni++) {
		onode = &rnode->sysctl_child[ni];
		if (enode && enode->sysctl_num == onode->sysctl_num) {
			if (SYSCTL_TYPE(enode->sysctl_flags) != CTLTYPE_NODE)
				onode = enode;
			if (--elim > 0)
				enode++;
			else
				enode = NULL;
		}
		error = sysctl_cvt_out(l, v, onode, oldp, left, &t);
		if (error)
			return (error);
		if (oldp != NULL)
			oldp = (char*)oldp + t;
		out += t;
		left -= MIN(left, t);
	}

	/*
	 * overlay trees *MUST* be entirely consumed
	 */
	KASSERT(enode == NULL);

	*oldlenp = out;

	return (error);
}

/*
 * sysctl_create -- Adds a node (the description of which is taken
 * from newp) to the tree, returning a copy of it in the space pointed
 * to by oldp.  In the event that the requested slot is already taken
 * (either by name or by number), the offending node is returned
 * instead.  Yes, this is complex, but we want to make sure everything
 * is proper.
 */
#ifdef SYSCTL_DEBUG_CREATE
int _sysctl_create(SYSCTLFN_ARGS);
int
_sysctl_create(SYSCTLFN_ARGS)
#else
int
sysctl_create(SYSCTLFN_ARGS)
#endif
{
	struct sysctlnode nnode, *node, *pnode;
	int error, ni, at, nm, type, sz, flags, anum, v;
	void *own;

	error = 0;
	own = NULL;
	anum = -1;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_create: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	if (namelen != 1 || (name[namelen - 1] != CTL_CREATE
#if NKSYMS > 0
			     && name[namelen - 1] != CTL_CREATESYM
#endif /* NKSYMS > 0 */
			     ))
		return (EINVAL);

	/*
	 * processes can only add nodes at securelevel 0, must be
	 * root, and can't add nodes to a parent that's not writeable
	 */
	if (l != NULL) {
#ifndef SYSCTL_DISALLOW_CREATE
		error = kauth_authorize_system(l->l_cred, KAUTH_SYSTEM_SYSCTL,
		    KAUTH_REQ_SYSTEM_SYSCTL_ADD, NULL, NULL, NULL);
		if (error)
			return (error);
		if (!(rnode->sysctl_flags & CTLFLAG_READWRITE))
#endif /* SYSCTL_DISALLOW_CREATE */
			return (EPERM);
	}

	/*
	 * nothing can add a node if:
	 * we've finished initial set up and
	 * the tree itself is not writeable or
	 * the entire sysctl system is not writeable
	 */
	if ((sysctl_root.sysctl_flags & CTLFLAG_PERMANENT) &&
	    (!(sysctl_rootof(rnode)->sysctl_flags & CTLFLAG_READWRITE) ||
	     !(sysctl_root.sysctl_flags & CTLFLAG_READWRITE)))
		return (EPERM);

	/*
	 * it must be a "node", not a "int" or something
	 */
	if (SYSCTL_TYPE(rnode->sysctl_flags) != CTLTYPE_NODE)
		return (ENOTDIR);
	if (rnode->sysctl_flags & CTLFLAG_ALIAS) {
		printf("sysctl_create: attempt to add node to aliased "
		       "node %p\n", rnode);
		return (EINVAL);
	}
	pnode = __UNCONST(rnode); /* we are adding children to this node */

	if (newp == NULL)
		return (EINVAL);
	error = sysctl_cvt_in(l, &v, newp, newlen, &nnode);
	if (error)
		return (error);

	/*
	 * nodes passed in don't *have* parents
	 */
	if (nnode.sysctl_parent != NULL)
		return (EINVAL);

	/*
	 * if we are indeed adding it, it should be a "good" name and
	 * number
	 */
	nm = nnode.sysctl_num;
#if NKSYMS > 0
	if (nm == CTL_CREATESYM)
		nm = CTL_CREATE;
#endif /* NKSYMS > 0 */
	if (nm < 0 && nm != CTL_CREATE)
		return (EINVAL);
	sz = 0;

	/*
	 * the name can't start with a digit
	 */
	if (nnode.sysctl_name[sz] >= '0' &&
	    nnode.sysctl_name[sz] <= '9')
		return (EINVAL);

	/*
	 * the name must be only alphanumerics or - or _, longer than
	 * 0 bytes and less that SYSCTL_NAMELEN
	 */
	while (sz < SYSCTL_NAMELEN && nnode.sysctl_name[sz] != '\0') {
		if ((nnode.sysctl_name[sz] >= '0' &&
		     nnode.sysctl_name[sz] <= '9') ||
		    (nnode.sysctl_name[sz] >= 'A' &&
		     nnode.sysctl_name[sz] <= 'Z') ||
		    (nnode.sysctl_name[sz] >= 'a' &&
		     nnode.sysctl_name[sz] <= 'z') ||
		    nnode.sysctl_name[sz] == '-' ||
		    nnode.sysctl_name[sz] == '_')
			sz++;
		else
			return (EINVAL);
	}
	if (sz == 0 || sz == SYSCTL_NAMELEN)
		return (EINVAL);

	/*
	 * various checks revolve around size vs type, etc
	 */
	type = SYSCTL_TYPE(nnode.sysctl_flags);
	flags = SYSCTL_FLAGS(nnode.sysctl_flags);
	sz = nnode.sysctl_size;

	/*
	 * find out if there's a collision, and if so, let the caller
	 * know what they collided with
	 */
	node = pnode->sysctl_child;
	at = 0;
	if (node) {
		if ((flags | node->sysctl_flags) & CTLFLAG_ANYNUMBER)
			/* No siblings for a CTLFLAG_ANYNUMBER node */
			return EINVAL;
		for (ni = 0; ni < pnode->sysctl_clen; ni++) {
			if (nm == node[ni].sysctl_num ||
			    strcmp(nnode.sysctl_name, node[ni].sysctl_name) == 0) {
				/*
				 * ignore error here, since we
				 * are already fixed on EEXIST
				 */
				(void)sysctl_cvt_out(l, v, &node[ni], oldp,
						     *oldlenp, oldlenp);
				return (EEXIST);
			}
			if (nm > node[ni].sysctl_num)
				at++;
		}
	}

	/*
	 * use sysctl_ver to add to the tree iff it hasn't changed
	 */
	if (nnode.sysctl_ver != 0) {
		/*
		 * a specified value must match either the parent
		 * node's version or the root node's version
		 */
		if (nnode.sysctl_ver != sysctl_rootof(rnode)->sysctl_ver &&
		    nnode.sysctl_ver != rnode->sysctl_ver) {
			return (EINVAL);
		}
	}

	/*
	 * only the kernel can assign functions to entries
	 */
	if (l != NULL && nnode.sysctl_func != NULL)
		return (EPERM);

	/*
	 * only the kernel can create permanent entries, and only then
	 * before the kernel is finished setting itself up
	 */
	if (l != NULL && (flags & ~SYSCTL_USERFLAGS))
		return (EPERM);
	if ((flags & CTLFLAG_PERMANENT) &
	    (sysctl_root.sysctl_flags & CTLFLAG_PERMANENT))
		return (EPERM);
	if ((flags & (CTLFLAG_OWNDATA | CTLFLAG_IMMEDIATE)) ==
	    (CTLFLAG_OWNDATA | CTLFLAG_IMMEDIATE))
		return (EINVAL);
	if ((flags & CTLFLAG_IMMEDIATE) &&
	    type != CTLTYPE_INT && type != CTLTYPE_QUAD)
		return (EINVAL);

	/*
	 * check size, or set it if unset and we can figure it out.
	 * kernel created nodes are allowed to have a function instead
	 * of a size (or a data pointer).
	 */
	switch (type) {
	case CTLTYPE_NODE:
		/*
		 * only *i* can assert the size of a node
		 */
		if (flags & CTLFLAG_ALIAS) {
			anum = nnode.sysctl_alias;
			if (anum < 0)
				return (EINVAL);
			nnode.sysctl_alias = 0;
		}
		if (sz != 0 || nnode.sysctl_data != NULL)
			return (EINVAL);
		if (nnode.sysctl_csize != 0 ||
		    nnode.sysctl_clen != 0 ||
		    nnode.sysctl_child != 0)
			return (EINVAL);
		if (flags & CTLFLAG_OWNDATA)
			return (EINVAL);
		sz = sizeof(struct sysctlnode);
		break;
	case CTLTYPE_INT:
		/*
		 * since an int is an int, if the size is not given or
		 * is wrong, we can "int-uit" it.
		 */
		if (sz != 0 && sz != sizeof(int))
			return (EINVAL);
		sz = sizeof(int);
		break;
	case CTLTYPE_STRING:
		/*
		 * strings are a little more tricky
		 */
		if (sz == 0) {
			if (l == NULL) {
				if (nnode.sysctl_func == NULL) {
					if (nnode.sysctl_data == NULL)
						return (EINVAL);
					else
						sz = strlen(nnode.sysctl_data) +
						    1;
				}
			} else if (nnode.sysctl_data == NULL &&
				 flags & CTLFLAG_OWNDATA) {
				return (EINVAL);
			} else {
				char *vp, *e;
				size_t s;

				/*
				 * we want a rough idea of what the
				 * size is now
				 */
				vp = malloc(PAGE_SIZE, M_SYSCTLDATA,
					     M_WAITOK|M_CANFAIL);
				if (vp == NULL)
					return (ENOMEM);
				e = nnode.sysctl_data;
				do {
					error = copyinstr(e, vp, PAGE_SIZE, &s);
					if (error) {
						if (error != ENAMETOOLONG) {
							free(vp, M_SYSCTLDATA);
							return (error);
						}
						e += PAGE_SIZE;
						if ((e - 32 * PAGE_SIZE) >
						    (char*)nnode.sysctl_data) {
							free(vp, M_SYSCTLDATA);
							return (ERANGE);
						}
					}
				} while (error != 0);
				sz = s + (e - (char*)nnode.sysctl_data);
				free(vp, M_SYSCTLDATA);
			}
		}
		break;
	case CTLTYPE_QUAD:
		if (sz != 0 && sz != sizeof(u_quad_t))
			return (EINVAL);
		sz = sizeof(u_quad_t);
		break;
	case CTLTYPE_STRUCT:
		if (sz == 0) {
			if (l != NULL || nnode.sysctl_func == NULL)
				return (EINVAL);
			if (flags & CTLFLAG_OWNDATA)
				return (EINVAL);
		}
		break;
	default:
		return (EINVAL);
	}

	/*
	 * at this point, if sz is zero, we *must* have a
	 * function to go with it and we can't own it.
	 */

	/*
	 *  l  ptr own
	 *  0   0   0  -> EINVAL (if no func)
	 *  0   0   1  -> own
	 *  0   1   0  -> kptr
	 *  0   1   1  -> kptr
	 *  1   0   0  -> EINVAL
	 *  1   0   1  -> own
	 *  1   1   0  -> kptr, no own (fault on lookup)
	 *  1   1   1  -> uptr, own
	 */
	if (type != CTLTYPE_NODE) {
		if (sz != 0) {
			if (flags & CTLFLAG_OWNDATA) {
				own = malloc(sz, M_SYSCTLDATA,
					     M_WAITOK|M_CANFAIL);
				if (own == NULL)
					return ENOMEM;
				if (nnode.sysctl_data == NULL)
					memset(own, 0, sz);
				else {
					error = sysctl_copyin(l,
					    nnode.sysctl_data, own, sz);
					if (error != 0) {
						free(own, M_SYSCTLDATA);
						return (error);
					}
				}
			} else if ((nnode.sysctl_data != NULL) &&
				 !(flags & CTLFLAG_IMMEDIATE)) {
#if NKSYMS > 0
				if (name[namelen - 1] == CTL_CREATESYM) {
					char symname[128]; /* XXX enough? */
					u_long symaddr;
					size_t symlen;

					error = sysctl_copyinstr(l,
					    nnode.sysctl_data, symname,
					    sizeof(symname), &symlen);
					if (error)
						return (error);
					error = ksyms_getval(NULL, symname,
					    &symaddr, KSYMS_EXTERN);
					if (error)
						return (error); /* EINVAL? */
					nnode.sysctl_data = (void*)symaddr;
				}
#endif /* NKSYMS > 0 */
				/*
				 * Ideally, we'd like to verify here
				 * that this address is acceptable,
				 * but...
				 *
				 * - it might be valid now, only to
				 *   become invalid later
				 *
				 * - it might be invalid only for the
				 *   moment and valid later
				 *
				 * - or something else.
				 *
				 * Since we can't get a good answer,
				 * we'll just accept the address as
				 * given, and fault on individual
				 * lookups.
				 */
			}
		} else if (nnode.sysctl_func == NULL)
			return (EINVAL);
	}

	/*
	 * a process can't assign a function to a node, and the kernel
	 * can't create a node that has no function or data.
	 * (XXX somewhat redundant check)
	 */
	if (l != NULL || nnode.sysctl_func == NULL) {
		if (type != CTLTYPE_NODE &&
		    nnode.sysctl_data == NULL &&
		    !(flags & CTLFLAG_IMMEDIATE) &&
		    own == NULL)
			return (EINVAL);
	}

#ifdef SYSCTL_DISALLOW_KWRITE
	/*
	 * a process can't create a writable node unless it refers to
	 * new data.
	 */
	if (l != NULL && own == NULL && type != CTLTYPE_NODE &&
	    (flags & CTLFLAG_READWRITE) != CTLFLAG_READONLY &&
	    !(flags & CTLFLAG_IMMEDIATE))
		return (EPERM);
#endif /* SYSCTL_DISALLOW_KWRITE */

	/*
	 * make sure there's somewhere to put the new stuff.
	 */
	if (pnode->sysctl_child == NULL) {
		if (flags & CTLFLAG_ANYNUMBER)
			error = sysctl_alloc(pnode, 1);
		else
			error = sysctl_alloc(pnode, 0);
		if (error) {
			if (own != NULL)
				free(own, M_SYSCTLDATA);
			return (error);
		}
	}
	node = pnode->sysctl_child;

	/*
	 * no collisions, so pick a good dynamic number if we need to.
	 */
	if (nm == CTL_CREATE) {
		nm = ++sysctl_root.sysctl_num;
		for (ni = 0; ni < pnode->sysctl_clen; ni++) {
			if (nm == node[ni].sysctl_num) {
				nm++;
				ni = -1;
			} else if (nm > node[ni].sysctl_num)
				at = ni + 1;
		}
	}

	/*
	 * oops...ran out of space
	 */
	if (pnode->sysctl_clen == pnode->sysctl_csize) {
		error = sysctl_realloc(pnode);
		if (error) {
			if (own != NULL)
				free(own, M_SYSCTLDATA);
			return (error);
		}
		node = pnode->sysctl_child;
	}

	/*
	 * insert new node data
	 */
	if (at < pnode->sysctl_clen) {
		int t;

		/*
		 * move the nodes that should come after the new one
		 */
		memmove(&node[at + 1], &node[at],
			(pnode->sysctl_clen - at) * sizeof(struct sysctlnode));
		memset(&node[at], 0, sizeof(struct sysctlnode));
		node[at].sysctl_parent = pnode;
		/*
		 * and...reparent any children of any moved nodes
		 */
		for (ni = at; ni <= pnode->sysctl_clen; ni++)
			if (node[ni].sysctl_child != NULL)
				for (t = 0; t < node[ni].sysctl_csize; t++)
					node[ni].sysctl_child[t].sysctl_parent =
						&node[ni];
	}
	node = &node[at];
	pnode->sysctl_clen++;

	strlcpy(node->sysctl_name, nnode.sysctl_name,
		sizeof(node->sysctl_name));
	node->sysctl_num = nm;
	node->sysctl_size = sz;
	node->sysctl_flags = SYSCTL_VERSION|type|flags; /* XXX other trees */
	node->sysctl_csize = 0;
	node->sysctl_clen = 0;
	if (own) {
		node->sysctl_data = own;
		node->sysctl_flags |= CTLFLAG_OWNDATA;
	} else if (flags & CTLFLAG_ALIAS) {
		node->sysctl_alias = anum;
	} else if (flags & CTLFLAG_IMMEDIATE) {
		switch (type) {
		case CTLTYPE_INT:
			node->sysctl_idata = nnode.sysctl_idata;
			break;
		case CTLTYPE_QUAD:
			node->sysctl_qdata = nnode.sysctl_qdata;
			break;
		}
	} else {
		node->sysctl_data = nnode.sysctl_data;
		node->sysctl_flags &= ~CTLFLAG_OWNDATA;
	}
        node->sysctl_func = nnode.sysctl_func;
        node->sysctl_child = NULL;
	/* node->sysctl_parent should already be done */

	/*
	 * update "version" on path to "root"
	 */
	for (; rnode->sysctl_parent != NULL; rnode = rnode->sysctl_parent)
		;
	pnode = node;
	for (nm = rnode->sysctl_ver + 1; pnode != NULL;
	     pnode = pnode->sysctl_parent)
		pnode->sysctl_ver = nm;

	/* If this fails, the node is already added - the user won't know! */
	error = sysctl_cvt_out(l, v, node, oldp, *oldlenp, oldlenp);

	return (error);
}

/*
 * ********************************************************************
 * A wrapper around sysctl_create() that prints the thing we're trying
 * to add.
 * ********************************************************************
 */
#ifdef SYSCTL_DEBUG_CREATE
int
sysctl_create(SYSCTLFN_ARGS)
{
	const struct sysctlnode *node;
	int k, rc, ni, nl = namelen + (name - oname);

	node = newp;

	printf("namelen %d (", nl);
	for (ni = 0; ni < nl - 1; ni++)
		printf(" %d", oname[ni]);
	printf(" %d )\t[%s]\tflags %08x (%08x %d %zu)\n",
	       k = node->sysctl_num,
	       node->sysctl_name,
	       node->sysctl_flags,
	       SYSCTL_FLAGS(node->sysctl_flags),
	       SYSCTL_TYPE(node->sysctl_flags),
	       node->sysctl_size);

	node = rnode;
	rc = _sysctl_create(SYSCTLFN_CALL(rnode));

	printf("sysctl_create(");
	for (ni = 0; ni < nl - 1; ni++)
		printf(" %d", oname[ni]);
	printf(" %d ) returned %d\n", k, rc);

	return (rc);
}
#endif /* SYSCTL_DEBUG_CREATE */

/*
 * sysctl_destroy -- Removes a node (as described by newp) from the
 * given tree, returning (if successful) a copy of the dead node in
 * oldp.  Since we're removing stuff, there's not much to check.
 */
int
sysctl_destroy(SYSCTLFN_ARGS)
{
	struct sysctlnode *node, *pnode, onode, nnode;
	int ni, error, v;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_destroy: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	error = 0;

	if (namelen != 1 || name[namelen - 1] != CTL_DESTROY)
		return (EINVAL);

	/*
	 * processes can only destroy nodes at securelevel 0, must be
	 * root, and can't remove nodes from a parent that's not
	 * writeable
	 */
	if (l != NULL) {
#ifndef SYSCTL_DISALLOW_CREATE
		error = kauth_authorize_system(l->l_cred, KAUTH_SYSTEM_SYSCTL,
		    KAUTH_REQ_SYSTEM_SYSCTL_DELETE, NULL, NULL, NULL);
		if (error)
			return (error);
		if (!(rnode->sysctl_flags & CTLFLAG_READWRITE))
#endif /* SYSCTL_DISALLOW_CREATE */
			return (EPERM);
	}

	/*
	 * nothing can remove a node if:
	 * the node is permanent (checked later) or
	 * the tree itself is not writeable or
	 * the entire sysctl system is not writeable
	 *
	 * note that we ignore whether setup is complete or not,
	 * because these rules always apply.
	 */
	if (!(sysctl_rootof(rnode)->sysctl_flags & CTLFLAG_READWRITE) ||
	    !(sysctl_root.sysctl_flags & CTLFLAG_READWRITE))
		return (EPERM);

	if (newp == NULL)
		return (EINVAL);
	error = sysctl_cvt_in(l, &v, newp, newlen, &nnode);
	if (error)
		return (error);
	memset(&onode, 0, sizeof(struct sysctlnode));

	node = rnode->sysctl_child;
	for (ni = 0; ni < rnode->sysctl_clen; ni++) {
		if (nnode.sysctl_num == node[ni].sysctl_num) {
			/*
			 * if name specified, must match
			 */
			if (nnode.sysctl_name[0] != '\0' &&
			    strcmp(nnode.sysctl_name, node[ni].sysctl_name))
				continue;
			/*
			 * if version specified, must match
			 */
			if (nnode.sysctl_ver != 0 &&
			    nnode.sysctl_ver != node[ni].sysctl_ver)
				continue;
			/*
			 * this must be the one
			 */
			break;
		}
	}
	if (ni == rnode->sysctl_clen)
		return (ENOENT);
	node = &node[ni];
	pnode = node->sysctl_parent;

	/*
	 * if the kernel says permanent, it is, so there.  nyah.
	 */
	if (SYSCTL_FLAGS(node->sysctl_flags) & CTLFLAG_PERMANENT)
		return (EPERM);

	/*
	 * can't delete non-empty nodes
	 */
	if (SYSCTL_TYPE(node->sysctl_flags) == CTLTYPE_NODE &&
	    node->sysctl_clen != 0)
		return (ENOTEMPTY);

	/*
	 * if the node "owns" data, release it now
	 */
	if (node->sysctl_flags & CTLFLAG_OWNDATA) {
		if (node->sysctl_data != NULL)
			free(node->sysctl_data, M_SYSCTLDATA);
		node->sysctl_data = NULL;
	}
	if (node->sysctl_flags & CTLFLAG_OWNDESC) {
		if (node->sysctl_desc != NULL)
			/*XXXUNCONST*/
			free(__UNCONST(node->sysctl_desc), M_SYSCTLDATA);
		node->sysctl_desc = NULL;
	}

	/*
	 * if the node to be removed is not the last one on the list,
	 * move the remaining nodes up, and reparent any grandchildren
	 */
	onode = *node;
	if (ni < pnode->sysctl_clen - 1) {
		int t;

		memmove(&pnode->sysctl_child[ni], &pnode->sysctl_child[ni + 1],
			(pnode->sysctl_clen - ni - 1) *
			sizeof(struct sysctlnode));
		for (; ni < pnode->sysctl_clen - 1; ni++)
			if (SYSCTL_TYPE(pnode->sysctl_child[ni].sysctl_flags) ==
			    CTLTYPE_NODE)
				for (t = 0;
				     t < pnode->sysctl_child[ni].sysctl_clen;
				     t++)
					pnode->sysctl_child[ni].sysctl_child[t].
						sysctl_parent =
						&pnode->sysctl_child[ni];
		ni = pnode->sysctl_clen - 1;
		node = &pnode->sysctl_child[ni];
	}

	/*
	 * reset the space we just vacated
	 */
	memset(node, 0, sizeof(struct sysctlnode));
	node->sysctl_parent = pnode;
	pnode->sysctl_clen--;

	/*
	 * if this parent just lost its last child, nuke the creche
	 */
	if (pnode->sysctl_clen == 0) {
		free(pnode->sysctl_child, M_SYSCTLNODE);
		pnode->sysctl_csize = 0;
		pnode->sysctl_child = NULL;
	}

	/*
	 * update "version" on path to "root"
	 */
        for (; rnode->sysctl_parent != NULL; rnode = rnode->sysctl_parent)
                ;
	for (ni = rnode->sysctl_ver + 1; pnode != NULL;
	     pnode = pnode->sysctl_parent)
		pnode->sysctl_ver = ni;

	error = sysctl_cvt_out(l, v, &onode, oldp, *oldlenp, oldlenp);

	return (error);
}

/*
 * sysctl_lookup -- Handles copyin/copyout of new and old values.
 * Partial reads are globally allowed.  Only root can write to things
 * unless the node says otherwise.
 */
int
sysctl_lookup(SYSCTLFN_ARGS)
{
	int error, rw;
	size_t sz, len;
	void *d;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_lookup: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	error = 0;

	/*
	 * you can't "look up" a node.  you can "query" it, but you
	 * can't "look it up".
	 */
	if (SYSCTL_TYPE(rnode->sysctl_flags) == CTLTYPE_NODE || namelen != 0)
		return (EINVAL);

	/*
	 * some nodes are private, so only root can look into them.
	 */
	if (l != NULL && (rnode->sysctl_flags & CTLFLAG_PRIVATE) &&
	    (error = kauth_authorize_system(l->l_cred, KAUTH_SYSTEM_SYSCTL,
	    KAUTH_REQ_SYSTEM_SYSCTL_PRVT, NULL, NULL, NULL)) != 0)
		return (error);

	/*
	 * if a node wants to be writable according to different rules
	 * other than "only root can write to stuff unless a flag is
	 * set", then it needs its own function which should have been
	 * called and not us.
	 */
	if (l != NULL && newp != NULL &&
	    !(rnode->sysctl_flags & CTLFLAG_ANYWRITE) &&
	    (error = kauth_authorize_generic(l->l_cred,
	    KAUTH_GENERIC_ISSUSER, &l->l_acflag)) != 0)
		return (error);

	/*
	 * is this node supposedly writable?
	 */
	rw = (rnode->sysctl_flags & CTLFLAG_READWRITE) ? 1 : 0;

	/*
	 * it appears not to be writable at this time, so if someone
	 * tried to write to it, we must tell them to go away
	 */
	if (!rw && newp != NULL)
		return (EPERM);

	/*
	 * step one, copy out the stuff we have presently
	 */
	if (rnode->sysctl_flags & CTLFLAG_IMMEDIATE) {
		/*
		 * note that we discard const here because we are
		 * modifying the contents of the node (which is okay
		 * because it's ours)
		 */
		switch (SYSCTL_TYPE(rnode->sysctl_flags)) {
		case CTLTYPE_INT:
			d = __UNCONST(&rnode->sysctl_idata);
			break;
		case CTLTYPE_QUAD:
			d = __UNCONST(&rnode->sysctl_qdata);
			break;
		default:
			return (EINVAL);
		}
	} else
		d = rnode->sysctl_data;
	if (SYSCTL_TYPE(rnode->sysctl_flags) == CTLTYPE_STRING)
		sz = strlen(d) + 1; /* XXX@@@ possible fault here */
	else
		sz = rnode->sysctl_size;
	if (oldp != NULL)
		error = sysctl_copyout(l, d, oldp, MIN(sz, *oldlenp));
	if (error)
		return (error);
	*oldlenp = sz;

	/*
	 * are we done?
	 */
	if (newp == NULL || newlen == 0)
		return (0);

	/*
	 * hmm...not done.  must now "copy in" new value.  re-adjust
	 * sz to maximum value (strings are "weird").
	 */
	sz = rnode->sysctl_size;
	switch (SYSCTL_TYPE(rnode->sysctl_flags)) {
	case CTLTYPE_INT:
	case CTLTYPE_QUAD:
	case CTLTYPE_STRUCT:
		/*
		 * these data must be *exactly* the same size coming
		 * in.
		 */
		if (newlen != sz)
			return (EINVAL);
		error = sysctl_copyin(l, newp, d, sz);
		break;
	case CTLTYPE_STRING: {
		/*
		 * strings, on the other hand, can be shorter, and we
		 * let userland be sloppy about the trailing nul.
		 */
		char *newbuf;

		/*
		 * too much new string?
		 */
		if (newlen > sz)
			return (EINVAL);

		/*
		 * temporary copy of new inbound string
		 */
		len = MIN(sz, newlen);
		newbuf = malloc(len, M_SYSCTLDATA, M_WAITOK|M_CANFAIL);
		if (newbuf == NULL)
			return (ENOMEM);
		error = sysctl_copyin(l, newp, newbuf, len);
		if (error) {
			free(newbuf, M_SYSCTLDATA);
			return (error);
		}

		/*
		 * did they null terminate it, or do we have space
		 * left to do it ourselves?
		 */
		if (newbuf[len - 1] != '\0' && len == sz) {
			free(newbuf, M_SYSCTLDATA);
			return (EINVAL);
		}

		/*
		 * looks good, so pop it into place and zero the rest.
		 */
		if (len > 0)
			memcpy(d, newbuf, len);
		if (sz != len)
			memset((char*)d + len, 0, sz - len);
		free(newbuf, M_SYSCTLDATA);
		break;
	}
	default:
		return (EINVAL);
	}

	return (error);
}

#ifndef __QNXNTO__
/*
 * sysctl_mmap -- Dispatches sysctl mmap requests to those nodes that
 * purport to handle it.  This interface isn't fully fleshed out yet,
 * unfortunately.
 */
static int
sysctl_mmap(SYSCTLFN_ARGS)
{
	const struct sysctlnode *node;
	struct sysctlnode nnode;
	int error;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_mmap: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	/*
	 * let's just pretend that didn't happen, m'kay?
	 */
	if (l == NULL)
		return (EPERM);

	/*
	 * is this a sysctlnode description of an mmap request?
	 */
	if (newp == NULL || newlen != sizeof(struct sysctlnode))
		return (EINVAL);
	error = sysctl_copyin(l, newp, &nnode, sizeof(nnode));
	if (error)
		return (error);

	/*
	 * does the node they asked for exist?
	 */
	if (namelen != 1)
		return (EOPNOTSUPP);
	node = rnode;
        error = sysctl_locate(l, &nnode.sysctl_num, 1, &node, NULL);
	if (error)
		return (error);

	/*
	 * does this node that we have found purport to handle mmap?
	 */
	if (node->sysctl_func == NULL ||
	    !(node->sysctl_flags & CTLFLAG_MMAP))
		return (EOPNOTSUPP);

	/*
	 * well...okay, they asked for it.
	 */
	return ((*node->sysctl_func)(SYSCTLFN_CALL(node)));
}
#endif

int
sysctl_describe(SYSCTLFN_ARGS)
{
	struct sysctldesc *d;
	void *bf;
	size_t sz, left, tot;
	int i, error, v = -1;
	struct sysctlnode *node;
	struct sysctlnode dnode;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_query: rnode %p wrong version\n", rnode);
		return (EINVAL);
	}

	if (SYSCTL_TYPE(rnode->sysctl_flags) != CTLTYPE_NODE)
		return (ENOTDIR);
	if (namelen != 1 || name[0] != CTL_DESCRIBE)
		return (EINVAL);

	/*
	 * get ready...
	 */
	error = 0;
	d = bf = malloc(MAXDESCLEN, M_TEMP, M_WAITOK|M_CANFAIL);
	if (bf == NULL)
		return ENOMEM;
	tot = 0;
	node = rnode->sysctl_child;
	left = *oldlenp;

	/*
	 * no request -> all descriptions at this level
	 * request with desc unset -> just this node
	 * request with desc set -> set descr for this node
	 */
	if (newp != NULL) {
		error = sysctl_cvt_in(l, &v, newp, newlen, &dnode);
		if (error)
			goto out;
		if (dnode.sysctl_desc != NULL) {
			/*
			 * processes cannot set descriptions above
			 * securelevel 0.  and must be root.  blah
			 * blah blah.  a couple more checks are made
			 * once we find the node we want.
			 */
			if (l != NULL) {
#ifndef SYSCTL_DISALLOW_CREATE
				error = kauth_authorize_system(l->l_cred,
				    KAUTH_SYSTEM_SYSCTL,
				    KAUTH_REQ_SYSTEM_SYSCTL_DESC, NULL,
				    NULL, NULL);
				if (error)
					goto out;
#else /* SYSCTL_DISALLOW_CREATE */
				error = EPERM;
				goto out;
#endif /* SYSCTL_DISALLOW_CREATE */
			}

			/*
			 * find node and try to set the description on it
			 */
			for (i = 0; i < rnode->sysctl_clen; i++)
				if (node[i].sysctl_num == dnode.sysctl_num)
					break;
			if (i == rnode->sysctl_clen) {
				error = ENOENT;
				goto out;
			}
			node = &node[i];

			/*
			 * did the caller specify a node version?
			 */
			if (dnode.sysctl_ver != 0 &&
			    dnode.sysctl_ver != node->sysctl_ver) {
				error = EINVAL;
				goto out;
			}

			/*
			 * okay...some rules:
			 * (1) if setup is done and the tree is
			 *     read-only or the whole system is
			 *     read-only
			 * (2) no one can set a description on a
			 *     permanent node (it must be set when
			 *     using createv)
			 * (3) processes cannot *change* a description
			 * (4) processes *can*, however, set a
			 *     description on a read-only node so that
			 *     one can be created and then described
			 *     in two steps
			 * anything else come to mind?
			 */
			if ((sysctl_root.sysctl_flags & CTLFLAG_PERMANENT) &&
			    (!(sysctl_rootof(node)->sysctl_flags &
			       CTLFLAG_READWRITE) ||
			     !(sysctl_root.sysctl_flags & CTLFLAG_READWRITE))) {
				error = EPERM;
				goto out;
			}
			if (node->sysctl_flags & CTLFLAG_PERMANENT) {
				error = EPERM;
				goto out;
			}
			if (l != NULL && node->sysctl_desc != NULL) {
				error = EPERM;
				goto out;
			}

			/*
			 * right, let's go ahead.  the first step is
			 * making the description into something the
			 * node can "own", if need be.
			 */
			if (l != NULL ||
			    dnode.sysctl_flags & CTLFLAG_OWNDESC) {
				char *nd, *k;

				k = malloc(MAXDESCLEN, M_TEMP,
				    M_WAITOK|M_CANFAIL);
				if (k == NULL) {
					error = ENOMEM;
					goto out;
				}
				error = sysctl_copyinstr(l, dnode.sysctl_desc,
							 k, MAXDESCLEN, &sz);
				if (error) {
					free(k, M_TEMP);
					goto out;
				}
				nd = malloc(sz, M_SYSCTLDATA,
					    M_WAITOK|M_CANFAIL);
				if (nd == NULL) {
					free(k, M_TEMP);
					error = ENOMEM;
					goto out;
				}
				memcpy(nd, k, sz);
				dnode.sysctl_flags |= CTLFLAG_OWNDESC;
				dnode.sysctl_desc = nd;
				free(k, M_TEMP);
			}

			/*
			 * now "release" the old description and
			 * attach the new one.  ta-da.
			 */
			if ((node->sysctl_flags & CTLFLAG_OWNDESC) &&
			    node->sysctl_desc != NULL)
				/*XXXUNCONST*/
				free(__UNCONST(node->sysctl_desc), M_SYSCTLDATA);
			node->sysctl_desc = dnode.sysctl_desc;
			node->sysctl_flags |=
				(dnode.sysctl_flags & CTLFLAG_OWNDESC);

			/*
			 * now we "fall out" and into the loop which
			 * will copy the new description back out for
			 * those interested parties
			 */
		}
	}

	/*
	 * scan for one description or just retrieve all descriptions
	 */
	for (i = 0; i < rnode->sysctl_clen; i++) {
		/*
		 * did they ask for the description of only one node?
		 */
		if (v != -1 && node[i].sysctl_num != dnode.sysctl_num)
			continue;

		/*
		 * don't describe "private" nodes to non-suser users
		 */
		if ((node[i].sysctl_flags & CTLFLAG_PRIVATE) && (l != NULL) &&
		    !(kauth_authorize_system(l->l_cred, KAUTH_SYSTEM_SYSCTL,
		    KAUTH_REQ_SYSTEM_SYSCTL_PRVT, NULL, NULL, NULL)))
			continue;

		/*
		 * is this description "valid"?
		 */
		memset(bf, 0, MAXDESCLEN);
		if (node[i].sysctl_desc == NULL)
			sz = 1;
		else if (copystr(node[i].sysctl_desc, &d->descr_str[0],
				 MAXDESCLEN - sizeof(*d), &sz) != 0) {
			/*
			 * erase possible partial description
			 */
			memset(bf, 0, MAXDESCLEN);
			sz = 1;
		}

		/*
		 * we've got it, stuff it into the caller's buffer
		 */
		d->descr_num = node[i].sysctl_num;
		d->descr_ver = node[i].sysctl_ver;
		d->descr_len = sz; /* includes trailing nul */
		sz = (caddr_t)NEXT_DESCR(d) - (caddr_t)d;
		if (oldp != NULL && left >= sz) {
			error = sysctl_copyout(l, d, oldp, sz);
			if (error)
				goto out;
			left -= sz;
			oldp = (void *)__sysc_desc_adv(oldp, d->descr_len);
		}
		tot += sz;

		/*
		 * if we get this far with v not "unset", they asked
		 * for a specific node and we found it
		 */
		if (v != -1)
			break;
	}

	/*
	 * did we find it after all?
	 */
	if (v != -1 && tot == 0)
		error = ENOENT;
	else
		*oldlenp = tot;

out:
	free(bf, M_TEMP);
	return (error);
}

/*
 * ********************************************************************
 * Section 3: Create and destroy from inside the kernel
 * ********************************************************************
 * sysctl_createv() and sysctl_destroyv() are simpler-to-use
 * interfaces for the kernel to fling new entries into the mib and rip
 * them out later.  In the case of sysctl_createv(), the returned copy
 * of the node (see sysctl_create()) will be translated back into a
 * pointer to the actual node.
 *
 * Note that sysctl_createv() will return 0 if the create request
 * matches an existing node (ala mkdir -p), and that sysctl_destroyv()
 * will return 0 if the node to be destroyed already does not exist
 * (aka rm -f) or if it is a parent of other nodes.
 *
 * This allows two (or more) different subsystems to assert sub-tree
 * existence before populating their own nodes, and to remove their
 * own nodes without orphaning the others when they are done.
 * ********************************************************************
 */
int
sysctl_createv(struct sysctllog **log, int cflags,
	       const struct sysctlnode **rnode, const struct sysctlnode **cnode,
	       int flags, int type, const char *namep, const char *descr,
	       sysctlfn func, u_quad_t qv, void *newp, size_t newlen,
	       ...)
{
	va_list ap;
	int error, ni, namelen, name[CTL_MAXNAME];
	const struct sysctlnode *root, *pnode;
	struct sysctlnode nnode, onode, *dnode;
	size_t sz;

	/*
	 * where are we putting this?
	 */
	if (rnode != NULL && *rnode == NULL) {
		printf("sysctl_createv: rnode NULL\n");
		return (EINVAL);
	}
	root = rnode ? *rnode : NULL;
	if (cnode != NULL)
		*cnode = NULL;
	if (cflags != 0)
		return (EINVAL);

	/*
	 * what is it?
	 */
	flags = SYSCTL_VERSION|SYSCTL_TYPE(type)|SYSCTL_FLAGS(flags);
	if (log != NULL)
		flags &= ~CTLFLAG_PERMANENT;

	/*
	 * where do we put it?
	 */
	va_start(ap, newlen);
	namelen = 0;
	ni = -1;
	do {
		if (++ni == CTL_MAXNAME)
			return (ENAMETOOLONG);
		name[ni] = va_arg(ap, int);
		/*
		 * sorry, this is not supported from here
		 */
		if (name[ni] == CTL_CREATESYM)
			return (EINVAL);
	} while (name[ni] != CTL_EOL && name[ni] != CTL_CREATE);
	namelen = ni + (name[ni] == CTL_CREATE ? 1 : 0);
	va_end(ap);

	/*
	 * what's it called
	 */
	if (strlcpy(nnode.sysctl_name, namep, sizeof(nnode.sysctl_name)) >=
	    sizeof(nnode.sysctl_name))
		return (ENAMETOOLONG);

	/*
	 * cons up the description of the new node
	 */
	nnode.sysctl_num = name[namelen - 1];
	name[namelen - 1] = CTL_CREATE;
	nnode.sysctl_size = newlen;
	nnode.sysctl_flags = flags;
	if (type == CTLTYPE_NODE) {
		nnode.sysctl_csize = 0;
		nnode.sysctl_clen = 0;
		nnode.sysctl_child = NULL;
		if (flags & CTLFLAG_ALIAS)
			nnode.sysctl_alias = qv;
	} else if (flags & CTLFLAG_IMMEDIATE) {
		switch (type) {
		case CTLTYPE_INT:
			nnode.sysctl_idata = qv;
			break;
		case CTLTYPE_QUAD:
			nnode.sysctl_qdata = qv;
			break;
		default:
			return (EINVAL);
		}
	} else {
		nnode.sysctl_data = newp;
	}
	nnode.sysctl_func = func;
	nnode.sysctl_parent = NULL;
	nnode.sysctl_ver = 0;

	/*
	 * initialize lock state -- we need locks if the main tree has
	 * been marked as complete, but since we could be called from
	 * either there, or from a device driver (say, at device
	 * insertion), or from an lkm (at lkm load time, say), we
	 * don't really want to "wait"...
	 */
#ifndef __QNXNTO__
	error = sysctl_lock(NULL, NULL, 0);
	if (error)
		return (error);
#endif

	/*
	 * locate the prospective parent of the new node, and if we
	 * find it, add the new node.
	 */
	sz = sizeof(onode);
	pnode = root;
	error = sysctl_locate(NULL, &name[0], namelen - 1, &pnode, &ni);
	if (error) {
		printf("sysctl_createv: sysctl_locate(%s) returned %d\n",
		       nnode.sysctl_name, error);
#ifndef __QNXNTO__
		sysctl_unlock(NULL);
#endif
		return (error);
	}
	error = sysctl_create(&name[ni], namelen - ni, &onode, &sz,
			      &nnode, sizeof(nnode), &name[0], NULL,
			      pnode);

	/*
	 * unfortunately the node we wanted to create is already
	 * there.  if the node that's already there is a reasonable
	 * facsimile of the node we wanted to create, just pretend
	 * (for the caller's benefit) that we managed to create the
	 * node they wanted.
	 */
	if (error == EEXIST) {
		/* name is the same as requested... */
		if (strcmp(nnode.sysctl_name, onode.sysctl_name) == 0 &&
		    /* they want the same function... */
		    nnode.sysctl_func == onode.sysctl_func &&
		    /* number is the same as requested, or... */
		    (nnode.sysctl_num == onode.sysctl_num ||
		     /* they didn't pick a number... */
		     nnode.sysctl_num == CTL_CREATE)) {
			/*
			 * collision here from trying to create
			 * something that already existed; let's give
			 * our customers a hand and tell them they got
			 * what they wanted.
			 */
#ifdef SYSCTL_DEBUG_CREATE
			printf("cleared\n");
#endif /* SYSCTL_DEBUG_CREATE */
			error = 0;
		}
	}

	if (error == 0 &&
	    (cnode != NULL || log != NULL || descr != NULL)) {
		/*
		 * sysctl_create() gave us back a copy of the node,
		 * but we need to know where it actually is...
		 */
		pnode = root;
		error = sysctl_locate(NULL, &name[0], namelen - 1, &pnode, &ni);

		/*
		 * manual scan of last layer so that aliased nodes
		 * aren't followed.
		 */
		if (error == 0) {
			for (ni = 0; ni < pnode->sysctl_clen; ni++)
				if (pnode->sysctl_child[ni].sysctl_num ==
				    onode.sysctl_num)
					break;
			if (ni < pnode->sysctl_clen)
				pnode = &pnode->sysctl_child[ni];
			else
				error = ENOENT;
		}

		/*
		 * not expecting an error here, but...
		 */
		if (error == 0) {
			if (log != NULL)
				sysctl_log_add(log, pnode);
			if (cnode != NULL)
				*cnode = pnode;
			if (descr != NULL) {
				/*
				 * allow first caller to *set* a
				 * description actually to set it
				 * 
				 * discard const here so we can attach
				 * the description
				 */
				dnode = __UNCONST(pnode);
				if (pnode->sysctl_desc != NULL)
					/* skip it...we've got one */;
				else if (flags & CTLFLAG_OWNDESC) {
					size_t l = strlen(descr) + 1;
					char *d = malloc(l, M_SYSCTLDATA,
							 M_WAITOK|M_CANFAIL);
					if (d != NULL) {
						memcpy(d, descr, l);
						dnode->sysctl_desc = d;
						dnode->sysctl_flags |=
						    CTLFLAG_OWNDESC;
					}
				} else
					dnode->sysctl_desc = descr;
			}
		} else {
			printf("sysctl_create succeeded but node not found?!\n");
			/*
			 *  confusing, but the create said it
			 * succeeded, so...
			 */
			error = 0;
		}
	}

	/*
	 * now it should be safe to release the lock state.  note that
	 * the pointer to the newly created node being passed back may
	 * not be "good" for very long.
	 */
#ifndef __QNXNTO__
	sysctl_unlock(NULL);
#endif

	if (error != 0) {
		printf("sysctl_createv: sysctl_create(%s) returned %d\n",
		       nnode.sysctl_name, error);
#if 0
		if (error != ENOENT)
			sysctl_dump(&onode);
#endif
	}

	return (error);
}

int
sysctl_destroyv(struct sysctlnode *rnode, ...)
{
	va_list ap;
	int error, name[CTL_MAXNAME], namelen, ni;
	const struct sysctlnode *pnode, *node;
	struct sysctlnode dnode, *onode;
	size_t sz;

	va_start(ap, rnode);
	namelen = 0;
	ni = 0;
	do {
		if (ni == CTL_MAXNAME)
			return (ENAMETOOLONG);
		name[ni] = va_arg(ap, int);
	} while (name[ni++] != CTL_EOL);
	namelen = ni - 1;
	va_end(ap);

	/*
	 * i can't imagine why we'd be destroying a node when the tree
	 * wasn't complete, but who knows?
	 */
#ifndef __QNXNTO__
	error = sysctl_lock(NULL, NULL, 0);
	if (error)
		return (error);
#endif

	/*
	 * where is it?
	 */
	node = rnode;
	error = sysctl_locate(NULL, &name[0], namelen - 1, &node, &ni);
	if (error) {
		/* they want it gone and it's not there, so... */
#ifndef __QNXNTO__
		sysctl_unlock(NULL);
#endif
		return (error == ENOENT ? 0 : error);
	}

	/*
	 * set up the deletion
	 */
	pnode = node;
	node = &dnode;
	memset(&dnode, 0, sizeof(dnode));
	dnode.sysctl_flags = SYSCTL_VERSION;
	dnode.sysctl_num = name[namelen - 1];

	/*
	 * we found it, now let's nuke it
	 */
	name[namelen - 1] = CTL_DESTROY;
	sz = 0;
	error = sysctl_destroy(&name[namelen - 1], 1, NULL, &sz,
			       node, sizeof(*node), &name[0], NULL,
			       pnode);
	if (error == ENOTEMPTY) {
		/*
		 * think of trying to delete "foo" when "foo.bar"
		 * (which someone else put there) is still in
		 * existence
		 */
		error = 0;

		/*
		 * dunno who put the description there, but if this
		 * node can ever be removed, we need to make sure the
		 * string doesn't go out of context.  that means we
		 * need to find the node that's still there (don't use
		 * sysctl_locate() because that follows aliasing).
		 */
		node = pnode->sysctl_child;
		for (ni = 0; ni < pnode->sysctl_clen; ni++)
			if (node[ni].sysctl_num == dnode.sysctl_num)
				break;
		node = (ni < pnode->sysctl_clen) ? &node[ni] : NULL;

		/*
		 * if we found it, and this node has a description,
		 * and this node can be released, and it doesn't
		 * already own its own description...sigh.  :)
		 */
		if (node != NULL && node->sysctl_desc != NULL &&
		    !(node->sysctl_flags & CTLFLAG_PERMANENT) &&
		    !(node->sysctl_flags & CTLFLAG_OWNDESC)) {
			char *d;

			sz = strlen(node->sysctl_desc) + 1;
			d = malloc(sz, M_SYSCTLDATA, M_WAITOK|M_CANFAIL);
			if (d != NULL) {
				/*
				 * discard const so that we can
				 * re-attach the description
				 */
				memcpy(d, node->sysctl_desc, sz);
				onode = __UNCONST(node);
				onode->sysctl_desc = d;
				onode->sysctl_flags |= CTLFLAG_OWNDESC;
			} else {
				/*
				 * XXX drop the description?  be
				 * afraid?  don't care?
				 */
			}
		}
	}

#ifndef __QNXNTO__
        sysctl_unlock(NULL);
#endif

	return (error);
}
#ifndef __QNXNTO__

#if 0
/*
 * ********************************************************************
 * the dump routine.  i haven't yet decided how (if at all) i'll call
 * this from userland when it's in the kernel.
 * ********************************************************************
 */
static const char *
sf(int f)
{
	static char s[256];
	char *c;

	s[0] = '\0';
	c = "";

#define print_flag(_f, _s, _c, _q, _x) \
	if (((_f) & (__CONCAT(CTLFLAG_,_x))) == (__CONCAT(CTLFLAG_,_q))) { \
		strlcat((_s), (_c), sizeof(_s)); \
		strlcat((_s), __STRING(_q), sizeof(_s)); \
		(_c) = ","; \
		(_f) &= ~__CONCAT(CTLFLAG_,_x); \
	}

	print_flag(f, s, c, READONLY,  READWRITE);
	print_flag(f, s, c, READWRITE, READWRITE);
	print_flag(f, s, c, ANYWRITE,  ANYWRITE);
	print_flag(f, s, c, PRIVATE,   PRIVATE);
	print_flag(f, s, c, PERMANENT, PERMANENT);
	print_flag(f, s, c, OWNDATA,   OWNDATA);
	print_flag(f, s, c, IMMEDIATE, IMMEDIATE);
	print_flag(f, s, c, HEX,       HEX);
	print_flag(f, s, c, ROOT,      ROOT);
	print_flag(f, s, c, ANYNUMBER, ANYNUMBER);
	print_flag(f, s, c, HIDDEN,    HIDDEN);
	print_flag(f, s, c, ALIAS,     ALIAS);
#undef print_flag

	if (f) {
		char foo[9];
		snprintf(foo, sizeof(foo), "%x", f);
		strlcat(s, c, sizeof(s));
		strlcat(s, foo, sizeof(s));
	}

	return (s);
}

static const char *
st(int t)
{

	switch (t) {
	case CTLTYPE_NODE:
		return "NODE";
	case CTLTYPE_INT:
		return "INT";
	case CTLTYPE_STRING:
		return "STRING";
	case CTLTYPE_QUAD:
		return "QUAD";
	case CTLTYPE_STRUCT:
		return "STRUCT";
	}

	return "???";
}

void
sysctl_dump(const struct sysctlnode *d)
{
	static char nmib[64], smib[256];
	static int indent;
	struct sysctlnode *n;
	char *np, *sp, tmp[20];
	int i;

	if (d == NULL)
		return;

	np = &nmib[strlen(nmib)];
	sp = &smib[strlen(smib)];

	if (!(d->sysctl_flags & CTLFLAG_ROOT)) {
		snprintf(tmp, sizeof(tmp), "%d", d->sysctl_num);
		strcat(nmib, ".");
		strcat(smib, ".");
		strcat(nmib, tmp);
		strcat(smib, d->sysctl_name);
		printf("%s -> %s (%d)\n", &nmib[1], &smib[1],
		       SYSCTL_TYPE(d->sysctl_flags));
	}

	if (1) {
		printf("%*s%p:\tsysctl_name  [%s]\n", indent, "",
		       d, d->sysctl_name);
		printf("%*s\t\tsysctl_num    %d\n",   indent, "",
		       d->sysctl_num);
		printf("%*s\t\tsysctl_flags  %x (flags=%x<%s> type=%d<%s> "
		       "size=%zu)\n",
		       indent, "", d->sysctl_flags,
		       SYSCTL_FLAGS(d->sysctl_flags),
		       sf(SYSCTL_FLAGS(d->sysctl_flags)),
		       SYSCTL_TYPE(d->sysctl_flags),
		       st(SYSCTL_TYPE(d->sysctl_flags)),
		       d->sysctl_size);
		if (SYSCTL_TYPE(d->sysctl_flags) == CTLTYPE_NODE) {
			printf("%*s\t\tsysctl_csize  %d\n",   indent, "",
			       d->sysctl_csize);
			printf("%*s\t\tsysctl_clen   %d\n",   indent, "",
			       d->sysctl_clen);
			printf("%*s\t\tsysctl_child  %p\n",   indent, "",
			       d->sysctl_child);
		} else
			printf("%*s\t\tsysctl_data   %p\n",   indent, "",
			       d->sysctl_data);
		printf("%*s\t\tsysctl_func   %p\n",   indent, "",
		       d->sysctl_func);
		printf("%*s\t\tsysctl_parent %p\n",   indent, "",
		       d->sysctl_parent);
		printf("%*s\t\tsysctl_ver    %d\n",   indent, "",
		       d->sysctl_ver);
	}

	if (SYSCTL_TYPE(d->sysctl_flags) == CTLTYPE_NODE) {
		indent += 8;
		n = d->sysctl_child;
		for (i = 0; i < d->sysctl_clen; i++) {
			sysctl_dump(&n[i]);
		}
		indent -= 8;
	}

	np[0] = '\0';
	sp[0] = '\0';
}
#endif /* 0 */

/*
 * ********************************************************************
 * Deletes an entire n-ary tree.  Not recommended unless you know why
 * you're doing it.  Personally, I don't know why you'd even think
 * about it.
 * ********************************************************************
 */
void
sysctl_free(struct sysctlnode *rnode)
{
	struct sysctlnode *node, *pnode;

	if (rnode == NULL)
		rnode = &sysctl_root;

	if (SYSCTL_VERS(rnode->sysctl_flags) != SYSCTL_VERSION) {
		printf("sysctl_free: rnode %p wrong version\n", rnode);
		return;
	}

	pnode = rnode;

	node = pnode->sysctl_child;
	do {
		while (node != NULL && pnode->sysctl_csize > 0) {
			while (node <
			       &pnode->sysctl_child[pnode->sysctl_clen] &&
			       (SYSCTL_TYPE(node->sysctl_flags) !=
				CTLTYPE_NODE ||
				node->sysctl_csize == 0)) {
				if (SYSCTL_FLAGS(node->sysctl_flags) &
				    CTLFLAG_OWNDATA) {
					if (node->sysctl_data != NULL) {
						free(node->sysctl_data,
						     M_SYSCTLDATA);
						node->sysctl_data = NULL;
					}
				}
				if (SYSCTL_FLAGS(node->sysctl_flags) &
				    CTLFLAG_OWNDESC) {
					if (node->sysctl_desc != NULL) {
						/*XXXUNCONST*/
						free(__UNCONST(node->sysctl_desc),
						     M_SYSCTLDATA);
						node->sysctl_desc = NULL;
					}
				}
				node++;
			}
			if (node < &pnode->sysctl_child[pnode->sysctl_clen]) {
				pnode = node;
				node = node->sysctl_child;
			} else
				break;
		}
		if (pnode->sysctl_child != NULL)
			free(pnode->sysctl_child, M_SYSCTLNODE);
		pnode->sysctl_clen = 0;
		pnode->sysctl_csize = 0;
		pnode->sysctl_child = NULL;
		node = pnode;
		pnode = node->sysctl_parent;
	} while (pnode != NULL && node != rnode);
}
#endif /* !__QNXNTO__ */

int
sysctl_log_add(struct sysctllog **logp, const struct sysctlnode *node)
{
	int name[CTL_MAXNAME], namelen, i;
	const struct sysctlnode *pnode;
	struct sysctllog *log;

	if (node->sysctl_flags & CTLFLAG_PERMANENT)
		return (0);

	if (logp == NULL)
		return (0);

	if (*logp == NULL) {
		log = malloc(sizeof(struct sysctllog),
		       M_SYSCTLDATA, M_WAITOK|M_CANFAIL);
		if (log == NULL) {
			/* XXX print error message? */
			return (-1);
		}
		log->log_num = malloc(16 * sizeof(int),
		       M_SYSCTLDATA, M_WAITOK|M_CANFAIL);
		if (log->log_num == NULL) {
			/* XXX print error message? */
			free(log, M_SYSCTLDATA);
			return (-1);
		}
		memset(log->log_num, 0, 16 * sizeof(int));
		log->log_root = NULL;
		log->log_size = 16;
		log->log_left = 16;
		*logp = log;
	} else
		log = *logp;

	/*
	 * check that the root is proper.  it's okay to record the
	 * address of the root of a tree.  it's the only thing that's
	 * guaranteed not to shift around as nodes come and go.
	 */
	if (log->log_root == NULL)
		log->log_root = sysctl_rootof(node);
	else if (log->log_root != sysctl_rootof(node)) {
		printf("sysctl: log %p root mismatch (%p)\n",
		       log->log_root, sysctl_rootof(node));
		return (-1);
	}

	/*
	 * we will copy out name in reverse order
	 */
	for (pnode = node, namelen = 0;
	     pnode != NULL && !(pnode->sysctl_flags & CTLFLAG_ROOT);
	     pnode = pnode->sysctl_parent)
		name[namelen++] = pnode->sysctl_num;

	/*
	 * do we have space?
	 */
	if (log->log_left < (namelen + 3))
		sysctl_log_realloc(log);
	if (log->log_left < (namelen + 3))
		return (-1);

	/*
	 * stuff name in, then namelen, then node type, and finally,
	 * the version for non-node nodes.
	 */
	for (i = 0; i < namelen; i++)
		log->log_num[--log->log_left] = name[i];
	log->log_num[--log->log_left] = namelen;
	log->log_num[--log->log_left] = SYSCTL_TYPE(node->sysctl_flags);
	if (log->log_num[log->log_left] != CTLTYPE_NODE)
		log->log_num[--log->log_left] = node->sysctl_ver;
	else
		log->log_num[--log->log_left] = 0;

	return (0);
}

void
sysctl_teardown(struct sysctllog **logp)
{
	const struct sysctlnode *rnode;
	struct sysctlnode node;
	struct sysctllog *log;
	uint namelen;
	int *name, t, v, error, ni;
	size_t sz;

	if (logp == NULL || *logp == NULL)
		return;
	log = *logp;

#ifndef __QNXNTO__
	error = sysctl_lock(NULL, NULL, 0);
	if (error)
		return;
#endif

	memset(&node, 0, sizeof(node));

	while (log->log_left < log->log_size) {
		KASSERT((log->log_left + 3 < log->log_size) &&
			(log->log_left + log->log_num[log->log_left + 2] <=
			 log->log_size));
		v = log->log_num[log->log_left++];
		t = log->log_num[log->log_left++];
		namelen = log->log_num[log->log_left++];
		name = &log->log_num[log->log_left];

		node.sysctl_num = name[namelen - 1];
		node.sysctl_flags = SYSCTL_VERSION|t;
		node.sysctl_ver = v;

		rnode = log->log_root;
		error = sysctl_locate(NULL, &name[0], namelen, &rnode, &ni);
		if (error == 0) {
			name[namelen - 1] = CTL_DESTROY;
			rnode = rnode->sysctl_parent;
			sz = 0;
			(void)sysctl_destroy(&name[namelen - 1], 1, NULL,
					     &sz, &node, sizeof(node),
					     &name[0], NULL, rnode);
		}

		log->log_left += namelen;
	}

	KASSERT(log->log_size == log->log_left);
	free(log->log_num, M_SYSCTLDATA);
	free(log, M_SYSCTLDATA);
	*logp = NULL;

#ifndef __QNXNTO__
	sysctl_unlock(NULL);
#endif
}
#ifndef __QNXNTO__

/*
 * ********************************************************************
 * old_sysctl -- A routine to bridge old-style internal calls to the
 * new infrastructure.
 * ********************************************************************
 */
int
old_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
	   void *newp, size_t newlen, struct lwp *l)
{
	int error;
	size_t oldlen = 0;
	size_t savelen;

	if (oldlenp) {
		oldlen = *oldlenp;
	}
	savelen = oldlen;

	error = sysctl_lock(l, oldp, savelen);
	if (error)
		return (error);
	error = sysctl_dispatch(name, namelen, oldp, &oldlen,
				newp, newlen, name, l, NULL);
	sysctl_unlock(l);
	if (error == 0 && oldp != NULL && savelen < oldlen)
		error = ENOMEM;

	if (oldlenp) {
		*oldlenp = oldlen;
	}

	return (error);
}

/*
 * ********************************************************************
 * Section 4: Generic helper routines
 * ********************************************************************
 * "helper" routines that can do more finely grained access control,
 * construct structures from disparate information, create the
 * appearance of more nodes and sub-trees, etc.  for example, if
 * CTL_PROC wanted a helper function, it could respond to a CTL_QUERY
 * with a dynamically created list of nodes that represented the
 * currently running processes at that instant.
 * ********************************************************************
 */

/*
 * first, a few generic helpers that provide:
 *
 * sysctl_needfunc()		a readonly interface that emits a warning
 * sysctl_notavail()		returns EOPNOTSUPP (generic error)
 * sysctl_null()		an empty return buffer with no error
 */
int
sysctl_needfunc(SYSCTLFN_ARGS)
{
	int error;

	printf("!!SYSCTL_NEEDFUNC!!\n");

	if (newp != NULL || namelen != 0)
		return (EOPNOTSUPP);

	error = 0;
	if (oldp != NULL)
		error = sysctl_copyout(l, rnode->sysctl_data, oldp,
				       MIN(rnode->sysctl_size, *oldlenp));
	*oldlenp = rnode->sysctl_size;

	return (error);
}

int
sysctl_notavail(SYSCTLFN_ARGS)
{

	if (namelen == 1 && name[0] == CTL_QUERY)
		return (sysctl_query(SYSCTLFN_CALL(rnode)));

	return (EOPNOTSUPP);
}

int
sysctl_null(SYSCTLFN_ARGS)
{

	*oldlenp = 0;

	return (0);
}
#endif

/*
 * ********************************************************************
 * Section 5: The machinery that makes it all go
 * ********************************************************************
 * Memory "manglement" routines.  Not much to this, eh?
 * ********************************************************************
 */
static int
sysctl_alloc(struct sysctlnode *p, int x)
{
	int i;
	struct sysctlnode *n;

	assert(p->sysctl_child == NULL);

	if (x == 1)
		n = malloc(sizeof(struct sysctlnode),
		       M_SYSCTLNODE, M_WAITOK|M_CANFAIL);
	else
		n = malloc(SYSCTL_DEFSIZE * sizeof(struct sysctlnode),
		       M_SYSCTLNODE, M_WAITOK|M_CANFAIL);
	if (n == NULL)
		return (ENOMEM);

	if (x == 1) {
		memset(n, 0, sizeof(struct sysctlnode));
		p->sysctl_csize = 1;
	} else {
		memset(n, 0, SYSCTL_DEFSIZE * sizeof(struct sysctlnode));
		p->sysctl_csize = SYSCTL_DEFSIZE;
	}
	p->sysctl_clen = 0;

	for (i = 0; i < p->sysctl_csize; i++)
		n[i].sysctl_parent = p;

	p->sysctl_child = n;
	return (0);
}

static int
sysctl_realloc(struct sysctlnode *p)
{
	int i, j;
	struct sysctlnode *n;

	assert(p->sysctl_csize == p->sysctl_clen);

	/*
	 * how many do we have...how many should we make?
	 */
	i = p->sysctl_clen;
	n = malloc(2 * i * sizeof(struct sysctlnode), M_SYSCTLNODE,
		   M_WAITOK|M_CANFAIL);
	if (n == NULL)
		return (ENOMEM);

	/*
	 * move old children over...initialize new children
	 */
	memcpy(n, p->sysctl_child, i * sizeof(struct sysctlnode));
	memset(&n[i], 0, i * sizeof(struct sysctlnode));
	p->sysctl_csize = 2 * i;

	/*
	 * reattach moved (and new) children to parent; if a moved
	 * child node has children, reattach the parent pointers of
	 * grandchildren
	 */
        for (i = 0; i < p->sysctl_csize; i++) {
                n[i].sysctl_parent = p;
		if (n[i].sysctl_child != NULL) {
			for (j = 0; j < n[i].sysctl_csize; j++)
				n[i].sysctl_child[j].sysctl_parent = &n[i];
		}
	}

	/*
	 * get out with the old and in with the new
	 */
	free(p->sysctl_child, M_SYSCTLNODE);
	p->sysctl_child = n;

	return (0);
}

static int
sysctl_log_realloc(struct sysctllog *log)
{
	int *n, s, d;

	s = log->log_size * 2;
	d = log->log_size;

	n = malloc(s * sizeof(int), M_SYSCTLDATA, M_WAITOK|M_CANFAIL);
	if (n == NULL)
		return (-1);

	memset(n, 0, s * sizeof(int));
	memcpy(&n[d], log->log_num, d * sizeof(int));
	free(log->log_num, M_SYSCTLDATA);
	log->log_num = n;
	if (d)
		log->log_left += d;
	else
		log->log_left = s;
	log->log_size = s;

	return (0);
}

/*
 * ********************************************************************
 * Section 6: Conversion between API versions wrt the sysctlnode
 * ********************************************************************
 */
static int
sysctl_cvt_in(struct lwp *l, int *vp, const void *i, size_t sz,
	      struct sysctlnode *node)
{
	int error, flags;

	if (i == NULL || sz < sizeof(flags))
		return (EINVAL);

	error = sysctl_copyin(l, i, &flags, sizeof(flags));
	if (error)
		return (error);

#if (SYSCTL_VERSION != SYSCTL_VERS_1)
#error sysctl_cvt_in: no support for SYSCTL_VERSION
#endif /*  (SYSCTL_VERSION != SYSCTL_VERS_1) */

	if (sz == sizeof(*node) &&
	    SYSCTL_VERS(flags) == SYSCTL_VERSION) {
		error = sysctl_copyin(l, i, node, sizeof(*node));
		if (error)
			return (error);
		*vp = SYSCTL_VERSION;
		return (0);
	}

	return (EINVAL);
}

static int
sysctl_cvt_out(struct lwp *l, int v, const struct sysctlnode *i,
	       void *ovp, size_t left, size_t *szp)
{
	size_t sz = sizeof(*i);
	const void *src = i;
	int error;

	switch (v) {
	case SYSCTL_VERS_0:
		return (EINVAL);

#if (SYSCTL_VERSION != SYSCTL_VERS_1)
#error sysctl_cvt_out: no support for SYSCTL_VERSION
#endif /*  (SYSCTL_VERSION != SYSCTL_VERS_1) */

	case SYSCTL_VERSION:
		/* nothing more to do here */
		break;
	}

	if (ovp != NULL && left >= sz) {
		error = sysctl_copyout(l, src, ovp, sz);
		if (error)
			return (error);
	}

	if (szp != NULL)
		*szp = sz;

	return (0);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/kern_sysctl.c $ $Rev: 895114 $")
#endif
