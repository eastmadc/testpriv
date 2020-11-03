/*
 * $QNXLicenseC:
 * Copyright 2008, QNX Software Systems. All Rights Reserved.
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

#ifndef _ALIGNBYTES_H_INCLUDED
#define _ALIGNBYTES_H_INCLUDED

#if defined(__X86__) || defined(__MIPS__) || defined(__SH__)
#define ALIGNBYTES		(sizeof(int) - 1)
#elif defined(__PPC__)
#define ALIGNBYTES		(sizeof(long long) - 1)
#elif defined(__ARM__)
#if defined(VARIANT_v7)
#define ALIGNBYTES		(sizeof(long long) - 1)
#else
#define ALIGNBYTES		(sizeof(int) - 1)
#endif
#else
#error ALIGNBYTES not defined for cpu
#endif

#define ALIGN(p)                (((unsigned int)(p) + ALIGNBYTES) &~ ALIGNBYTES)

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/alignbytes.h $ $Rev: 822252 $")
#endif
