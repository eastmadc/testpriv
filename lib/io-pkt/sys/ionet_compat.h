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

#ifndef _IONET_COMPAT_H_INCLUDED
#define _IONET_COMPAT_H_INCLUDED

#include <sys/resmgr.h>
#include <sys/iofunc.h>


#define IONET_SHIM_NAME 	"devnp-shim.so"

extern char ionet_instance[30];
extern int ionet_init_instance(char *, char *);
extern int ionet_umount(resmgr_context_t *, io_mount_t *,
    RESMGR_HANDLE_T *, io_mount_extra_t *);

extern int ionet_enmap;

#endif /* ! _IONET_COMPAT_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/ionet_compat.h $ $Rev: 680336 $")
#endif
