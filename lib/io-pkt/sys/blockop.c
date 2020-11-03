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

#include <sys/proc.h>
#include <blockop.h>
#include <nw_sig.h>
#include <process.h>
#include <signal.h>
#include <dlfcn.h>
#include <siglock.h>

pthread_key_t	*blockop_resmgr_keyp;

void
blockop_init(void)
{
	void	*hdl;

	if ((hdl = dlopen(NULL, RTLD_WORLD)) == NULL)
		return;

	blockop_resmgr_keyp = dlsym(hdl, "_resmgr_thread_key");

	dlclose(hdl); /* Null op when dlopen(NULL) but... */
}

int
blockop_dispatch(struct bop_dispatch *bop, struct proc *p)
{
	union sigval sival;
	sival.sival_ptr = bop;
	int ret;
	void *resp;
	struct nw_work_thread *wtp = WTP;

	if (!ISSTACK_P(wtp) || (wtp->intr_sighot == 0 && stk_ctl.quiesce_count == 0))
	  panic(__func__);

	if (bop->bop_prio <= 0)
	  panic("blockop_dispatch: Invalid pulse priority");

	sigqueue(getpid(), NW_SIG_BLOCKOP, sival);
	if (p != NULL && (p->p_flags & P_RESMGR_KEY) && blockop_resmgr_keyp != NULL)
		resp = pthread_getspecific(*blockop_resmgr_keyp);
	ret = tsleep((caddr_t)bop, 0, "blockop", 0);
	if (p != NULL && (p->p_flags & P_RESMGR_KEY) && blockop_resmgr_keyp != NULL)
		pthread_setspecific(*blockop_resmgr_keyp, resp);
	return ret;
}

void
blockop_wakeup(void *arg)
{
	struct bop_dispatch	*bop;
	struct nw_work_thread	*wtp = WTP;

	if (!ISSTACK_P(wtp) || (wtp->intr_sighot == 0 && stk_ctl.quiesce_count == 0))
	  panic(__func__);

	bop = arg;

	wakeup(bop);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/blockop.c $ $Rev: 832191 $")
#endif
