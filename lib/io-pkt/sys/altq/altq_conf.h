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

/*	$NetBSD: altq_conf.h,v 1.9 2006/10/12 19:59:08 peter Exp $	*/
/*	$KAME: altq_conf.h,v 1.10 2005/04/13 03:44:24 suz Exp $	*/

/*
 * Copyright (C) 1998-2002
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _ALTQ_ALTQ_CONF_H_
#define	_ALTQ_ALTQ_CONF_H_
#ifdef ALTQ3_COMPAT

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>

#ifdef __QNXNTO__
#include <sys/iofunc.h>
#endif

#if (__FreeBSD_version > 300000)
#define	ALTQ_KLD
#endif

#ifdef ALTQ_KLD
#include <sys/module.h>
#endif

#ifndef dev_decl
#ifdef __STDC__
#define	dev_decl(n,t)	d_ ## t ## _t n ## t
#else
#define	dev_decl(n,t)	d_/**/t/**/_t n/**/t
#endif
#endif

#if defined(__NetBSD__) || defined(__QNXNTO__)
typedef int d_open_t(dev_t, int, int, struct lwp *);
typedef int d_close_t(dev_t, int, int, struct lwp *);
typedef int d_ioctl_t(dev_t, u_long, caddr_t, int, struct lwp *);
#endif /* __NetBSD__ */

#if defined(__QNXNTO__)
int altq_copyout(const void *src, void *dst, size_t len);
#endif

#if defined(__OpenBSD__)
typedef int d_open_t(dev_t, int, int, struct proc *);
typedef int d_close_t(dev_t, int, int, struct proc *);
typedef int d_ioctl_t(dev_t, u_long, caddr_t, int, struct proc *);

#define	noopen	(dev_type_open((*))) enodev
#define	noclose	(dev_type_close((*))) enodev
#define	noioctl	(dev_type_ioctl((*))) enodev

int altqopen(dev_t, int, int, struct proc *);
int altqclose(dev_t, int, int, struct proc *);
int altqioctl(dev_t, u_long, caddr_t, int, struct proc *);
#endif

/*
 * altq queueing discipline switch structure
 */
struct altqsw {
	const char	*d_name;
	d_open_t	*d_open;
	d_close_t	*d_close;
	d_ioctl_t	*d_ioctl;
#ifdef __QNXNTO__
	iofunc_attr_t	attr;
	int		nopens; /* number of concurrent opens */
#endif
#ifdef __FreeBSD__
	dev_t		 dev;	/* make_dev result for later destroy_dev */
#endif
};

#define	altqdev_decl(n) \
	dev_decl(n,open); dev_decl(n,close); dev_decl(n,ioctl)

#ifdef ALTQ_KLD

struct altq_module_data {
	int	type;		/* discipline type */
	int	ref;		/* reference count */
	struct	altqsw *altqsw; /* discipline functions */
};

#define	ALTQ_MODULE(name, type, devsw)					\
static struct altq_module_data name##_moddata = { type, 0, devsw };	\
									\
moduledata_t name##_mod = {						\
    #name,								\
    altq_module_handler,						\
    &name##_moddata							\
};									\
DECLARE_MODULE(name, name##_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE+96)

void altq_module_incref(int);
void altq_module_declref(int);
int altq_module_handler(module_t, int, void *);

#endif /* ALTQ_KLD */

#endif /* _KERNEL */
#endif /* ALTQ3_COMPAT */
#endif /* _ALTQ_ALTQ_CONF_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/altq/altq_conf.h $ $Rev: 680336 $")
#endif
