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

#ifndef _NW_RESMGR_H_INCLUDED
#define _NW_RESMGR_H_INCLUDED

#include <sys/resmgr.h>

/*
 * XXX taken from lib/c/inc/resmgr.h
 *     any place using this is being slightly naughty.
 */
struct binding {
	void				*ocb;           /* user allocated data handle (per open) */
	const resmgr_io_funcs_t		*funcs;         /* functions from the link structure */
	int				id;             /* numeric id of the link structure */
	unsigned			count;          /* reference count on this structure */
};

extern resmgr_io_funcs_t nw_io_funcs;

/* The funcs we resmgr_open_bind() which take a struct file */
#define RESMGR_BINDING_FILE_FUNCS (&nw_io_funcs)

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_resmgr.h $ $Rev: 680336 $")
#endif
