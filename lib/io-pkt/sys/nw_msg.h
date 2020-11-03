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

#ifndef _NW_MSG_H_INCLUDED
#define _NW_MSG_H_INCLUDED

#ifdef _KERNEL_OPT
#include "opt_msg.h"
#endif

#include <sys/resmgr.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>


#ifdef OCB_LOCAL_CACHE
#define OCB_CACHE_COID_MAX 20

struct ocb_cache {
	int nd;
	pid_t pid;
	void *ocbs[OCB_CACHE_COID_MAX];
};

extern struct ocb_cache *ocb_cache;
extern int ocb_cache_scoid_max;
void * ocb_local_cache_find(struct _msg_info *);
#endif

extern void _resmgr_handler(resmgr_context_t *ctp);

extern int msg_init(void);

extern resmgr_io_funcs_t nw_io_funcs;
extern resmgr_connect_funcs_t tcpip_connect_funcs;
extern resmgr_connect_funcs_t mount_cfuncs;

struct file;
struct proc;

enum msg_open_type {
	PATH_TYPE_SOCKET,
	PATH_TYPE_CRYPTO,
	PATH_TYPE_BPF,
	PATH_TYPE_PF,
	PATH_TYPE_LSM,
	PATH_TYPE_SRT,
	PATH_TYPE_TUN,
	PATH_TYPE_TAP,
};

struct msg_open_info {
	iofunc_attr_t	attr;		/* first member! */
	int		path_id;
	int		domain;
	int		path_type;	/* msg_open_type enum above */
	int		(*open)(resmgr_context_t *, io_open_t *,
	    		    struct msg_open_info *, struct file **);
	int		index;
	int		zero;
};

extern int nto_bindit(resmgr_context_t *, void *);
extern int nto_unbind(resmgr_context_t *);
extern int msg_open_chk_access(resmgr_context_t *, io_open_t *, iofunc_attr_t *);

extern int ioctl_getoneptrembed(io_devctl_t *msg, caddr_t embed_ptr, int embed_len, int index);
extern int ioctl_getptrembed(io_devctl_t *msg, caddr_t embed_ptr, int embed_len, int niov);

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_msg.h $ $Rev: 680336 $")
#endif
