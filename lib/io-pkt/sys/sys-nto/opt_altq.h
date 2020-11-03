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





#include "opt_altq_enabled.h"

#ifdef ALTQ
#define ALTQ_AFMAP        1
#define ALTQ_BLUE         1
#define ALTQ_CBQ          1
#define ALTQ_CDNR         1
#define ALTQ_DEBUG        1
#define ALTQ_FIFOQ        1
#define ALTQ_FLOWVALVE    1
#define ALTQ_HFSC         1
#define ALTQ_IPSEC        1
#define ALTQ_LOCALQ       1
#define ALTQ_PRIQ         1
#define ALTQ_RED          1
#define ALTQ_RIO          1
#define ALTQ_WFQ          1

/* #define ADJUST_CUTOFF     1 */
/* #define BLUE_STATS        1 */
/* #define BORROW_OFFTIME    1 */
/* #define CBQ_TRACE         1 */
/* #define FIFOQ_STATS       1 */
/* #define FV_STATS          1 */
/* #define HFSC_PKTLOG       1 */
/* #define RED_RANDOM_LOOP   1 */
/* #define RED_STATS         1 */
/* #define RIO_STATS         1 */
/* #define WFQ_DEBUG         1 */
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys-nto/opt_altq.h $ $Rev: 680336 $")
#endif
