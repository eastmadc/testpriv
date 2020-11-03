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

/*	$NetBSD: pf_lkm.c,v 1.3 2005/12/11 12:24:49 christos Exp $	*/

/*
 *  Copyright (c) 2004 The NetBSD Foundation, Inc.
 *  All rights reserved.
 *
 *  This code is derived from software contributed to the NetBSD Foundation
 *  by Peter Postma and Joel Wilsson.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this software
 *     must display the following acknowledgement:
 *         This product includes software developed by the NetBSD
 *         Foundation, Inc. and its contributors.
 *  4. Neither the name of The NetBSD Foundation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 *  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 *  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: pf_lkm.c,v 1.3 2005/12/11 12:24:49 christos Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#ifndef __QNXNTO__
#include <sys/lkm.h>
#else
#include <stdlib.h>	
#include <sys/proc.h>
#include "nw_datastruct.h"
#include "nw_msg.h"
#include <devctl.h>
#include <fcntl.h>
#include <sys/callout.h>
#include <sys/dispatch.h>
#include <sys/resmgr.h>
#include <sys/malloc.h>
#include <alloca.h>
#endif

#include <net/if.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#ifdef __QNXNTO__
#include <net/pfvar.h>

#else
int		pf_lkmentry(struct lkm_table *, int, int);
static int	pf_lkmload(struct lkm_table *, int);
static int	pf_lkmunload(struct lkm_table *, int);
#endif

extern void	pfattach(int);
extern void	pfdetach(void);
extern void	pflogattach(int);
extern void	pflogdetach(void);
#ifdef __QNXNTO__
extern int pfioctl(dev_t, u_long, caddr_t, int, struct lwp *);
extern char *__prefix;
#endif

extern const struct cdevsw pf_cdevsw;

#ifndef __QNXNTO__
MOD_DEV("pf", "pf", NULL, -1, &pf_cdevsw, -1);

int
pf_lkmentry(struct lkm_table *lkmtp, int cmd, int ver)
{
	LKM_DISPATCH(lkmtp, cmd, ver, pf_lkmload, pf_lkmunload, lkm_nofunc);
}

static int
pf_lkmload(struct lkm_table *lkmtp, int cmd)
{
	if (lkmexists(lkmtp))
		return (EEXIST);

	pfattach(1);
	pflogattach(1);

	return (0);
}

static int
pf_lkmunload(struct lkm_table *lkmtp, int cmd)
{
	pfdetach();
	pflogdetach();

	return (0);
}
#else
#define PROC_FROM_CTP(ctp)      \
	(struct proc *)((char *)(ctp) - offsetof(struct proc, p_ctxt))


static int pfres_open(resmgr_context_t *, io_open_t *,
    struct msg_open_info *, struct file **);

static int loaded;

static struct msg_open_info pf_info = {
	{0}, 0, 0, PATH_TYPE_LSM, pfres_open
};

static int pf_entry(void *, struct _iopkt_self *, char *);

struct _iopkt_lsm_entry IOPKT_LSM_ENTRY_SYM(pf) =
  IOPKT_LSM_ENTRY_SYM_INIT(pf_entry);

static int
pf_entry(void *dll_hdl, struct _iopkt_self *iopkt, char *options)
{
	struct nw_stk_ctl *sctlp;
	char *pf_path;
	int len;

	sctlp = &stk_ctl;

#if 0
	resmgr_attr_t	attr;

	/* Make sure it's not already loaded */
	if (pf_dpp != NULL)
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.nparts_max = 2;
	iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &pf_connectfuncs, _RESMGR_IO_NFUNCS, &pf_iofuncs);
	iofunc_attr_init(&pf_ioattr, 0600 | S_IFCHR, 0, 0);

	pf_connectfuncs.open	= pfres_open;
	pf_iofuncs.close_ocb	= pfres_close;
	pf_iofuncs.devctl	= pfres_devctl;
	
	/* Add check for SOCK prefix */
	if ((pf_pathid = resmgr_attach(dpp, &attr, "/dev/pf", _FTYPE_ANY, 0, &pf_connectfuncs, &pf_iofuncs, NULL)) == -1)
	{
		return -1;
	}

	pf_dpp = dpp;


	pfattach(1);
	pflogattach(1);
	
	return 0;
#endif

	/* Make sure it's not already loaded */
	if (loaded)
		return EALREADY;

	/* Check for SOCK prefix */
	if (__prefix)
		len = strlen(__prefix) + strlen("/dev/pf") + 1;
	else
		len = strlen("/dev/pf") + 1;

	if ((pf_path = alloca(len)) == NULL )
	{
		errno=ENOMEM;
		return -1;
	}

	if (__prefix) {
		strcpy(pf_path, __prefix);
		strcat(pf_path, "/dev/pf");
	}
	else
		strcpy(pf_path, "/dev/pf");

	iofunc_attr_init(&pf_info.attr, S_IFNAM | 0660, 0, 0);
	if ((pf_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, pf_path, _FTYPE_ANY, 0, &tcpip_connect_funcs,
	    NULL, &pf_info.attr)) == -1) {
		return errno;
	}
	pfattach(1);
	pflogattach(1);
	loaded = 1;
	return 0;
}

static int
pfres_open(resmgr_context_t *ctp, io_open_t *msg,
    struct msg_open_info *mop, struct file **fp)
{
	struct proc	*p;
	int		ret;

	p = PROC_FROM_CTP(ctp);

	if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) != EOK)
		return ret;

	return pf_open(PR_TO_LWP(p), fp);
}
#endif  /* __QNXNTO__ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lkm/net/pf/pf_lkm.c $ $Rev: 729877 $")
#endif
