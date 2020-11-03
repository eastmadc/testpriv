/*
 * $QNXLicenseC:
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






#include "opt_ionet_compat.h"

#include <ionet_compat.h>
#include <sys/syslog.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <stdlib.h>
#include <string.h>
#include <device_qnx.h>


#define PROC_FROM_CTP(ctp)	\
	(struct proc *)((char *)(ctp) - offsetof(struct proc, p_ctxt))

/* The name of the stack. i.e. "io-net" or "io-net2" */
char ionet_instance[30] = "io-net";


/*
 * It would be nice if this were in the the shim's shim_ionet_msg.c
 * but dev_detach() may dlclose() the shim so we have to start here.
 */
int
ionet_umount(resmgr_context_t *ctp, io_mount_t *msg, RESMGR_HANDLE_T *handle,
    io_mount_extra_t *extra)
{
	struct device   *dev;
	struct proc	*p;
	int		error;

	/* Only support umount.  Mount is handled in stack proper */
	if (!(extra->flags & _MOUNT_UNMOUNT))
		return ENOSYS;

	p = PROC_FROM_CTP(ctp);

	p->p_cred = kauth_cred_alloc();

	p->p_lwp.l_cred = p->p_cred;
	kauth_cred_hold(p->p_cred);

	dev = handle;
	error = dev_detach(dev, 0);

	kauth_cred_free(p->p_lwp.l_cred);
	kauth_cred_free(p->p_cred);

	return error;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/ionet_compat.c $ $Rev: 680336 $")
#endif
