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





#ifndef _QNX_H_
#define _QNX_H_

/*
 * There's nothing we want from <strings.h>.
 * In particular we don't want it to define bcopy -> memmove.
 * We want bcopy -> memcpy from "sys/systm.h".  Catch any
 * potential occurances of the former.
 */
#define _STRINGS_H_INCLUDED


/* Set up a BSD like environment */
#include <sys/cdefs_bsd.h>
#include <sys/param_bsd.h>


/* instead of bringing in the NetBSD sys/uvm stuff */
extern int pagesize;		/* init_main.c */
extern int pagesize_large;	/* init_main.c (QNX specific) */
#define PAGE_SIZE pagesize

#endif /* !_QNX_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/qnx.h $ $Rev: 680336 $")
#endif
