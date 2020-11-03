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

#ifndef _AUTOCONNECT_H_INCLUDED
#define _AUTOCONNECT_H_INCLUDED

#include <stdlib.h>

extern int __try_auto_connect;

static inline int do_autocon(void);

static inline int
do_autocon(void)
{
	int	ret, saved_errno;

	ret = 0;
	if (__try_auto_connect == 1) {
		saved_errno = errno;
	       	if (getenv("AUTOCONNECT") != NULL)
			ret = 1;
		errno = saved_errno;
	}

	__try_auto_connect = 0;
	return ret;
}
	
int autoconnect(void);
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/autoconnect.h $ $Rev: 729877 $")
#endif
