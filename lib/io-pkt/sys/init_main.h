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

#ifndef _INIT_MAIN_H_INCLUDED
#define _INIT_MAIN_H_INCLUDED

#include <receive.h>

int nw_max_prio;

MALLOC_DECLARE(M_INIT);

int pre_main_init(void);
void pre_main_fini(void);

int main_init(char *, int, char **);
void main_fini(int, int, const char *);

void load_drivers(void *);


#endif /* !_INIT_MAIN_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/init_main.h $ $Rev: 768535 $")
#endif
