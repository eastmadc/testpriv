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


#include "asm.h"
#include "asmoff.def"

#if defined(__BIGENDIAN__) && !defined(__ARMEB__)
#define __ARMEB__ /* gcc 3'ism */
#endif

/* 
 * void _sched_arm_asm(jump_buf, void *) 
 *
 * Entry:
 * 	r0	jump_buf
 *	r1	void *
 *
 */

ENTRY(_sched_arm_asm)
	mov r2, r0
	ldmia r2, {r4-r11,sp}
	mov r0, r1
	mov lr, #0
	ldr pc, [r2, #0x24]

#ifdef __QNXNTO__
#ifdef __USESRCVERSION
.section .ident, "SM",%progbits,1;
.asciz "$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/target/arm/sched_arm.S $ $Rev: 701486 $";
.previous
#endif
#endif 
