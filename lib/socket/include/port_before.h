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

#ifndef __QNXNTO__
#include "namespace.h"
#endif
#include <sys/cdefs.h>
#include <inttypes.h>

#define ISC_FORMAT_PRINTF(a,b) __attribute__((__format__(__printf__,a,b)))
#define ISC_SOCKLEN_T	socklen_t
#define DE_CONST(c,v)	v = ((c) ? \
	strchr((const void *)(c), *(const char *)(const void *)(c)) : NULL)
#ifndef lint
#define UNUSED(a)	(void)&a
#else
#define UNUSED(a)	a = a
#endif


#ifndef MIN
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#endif

typedef uint8_t		u_int8_t;
typedef uint16_t	u_int16_t;
typedef uint32_t	u_int32_t;

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/include/port_before.h $ $Rev: 680336 $")
#endif
