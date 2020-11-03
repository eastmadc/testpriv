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



#ifndef _NOTIFY_H_INCLUDED
#define _NOTIFY_H_INCLUDED

#ifndef __RESMGR_H_INCLUDED
#include <sys/resmgr.h>
#endif

#ifndef __IOFUNC_H_INCLUDED
#include <sys/iofunc.h>
#endif

extern void (*notify_trigger_strictp)(resmgr_context_t *, iofunc_notify_t *, int, int);
extern void (*notify_remove_strictp)(resmgr_context_t *, iofunc_notify_t *, int);
extern void notify_init(void);

#endif /* !_NOTIFY_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/notify.h $ $Rev: 680336 $")
#endif
