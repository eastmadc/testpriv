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

/*	$NetBSD: pim6.h,v 1.5 2005/12/10 23:39:56 elad Exp $	*/
/*	$KAME: pim6.h,v 1.3 2000/03/25 07:23:58 sumikawa Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET6_PIM6_H_
#define _NETINET6_PIM6_H_

/*
 * Protocol Independent Multicast (PIM) definitions
 *
 * Written by Ahmed Helmy, SGI, July 1996
 *
 * MULTICAST
 */

/*
 * PIM packet header
 */
#ifdef __QNXNTO__
#ifndef __PARAM_H_INCLUDED
#include <sys/param.h> /* For BYTE_ORDER defines */
#endif
#endif

#define PIM_VERSION	2
struct pim {
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
	u_char	pim_type:4, /* the PIM message type, currently they are:
			     * Hello, Register, Register-Stop, Join/Prune,
			     * Bootstrap, Assert, Graft (PIM-DM only),
			     * Graft-Ack (PIM-DM only), C-RP-Adv
			     */
		pim_ver:4;  /* PIM version number; 2 for PIMv2 */
#else
	u_char	pim_ver:4,	/* PIM version */
		pim_type:4;	/* PIM type    */
#endif
	u_char  pim_rsv;	/* Reserved */
	u_short	pim_cksum;	/* IP style check sum */
};

#define PIM_MINLEN	8		/* The header min. length is 8    */
#define PIM6_REG_MINLEN	(PIM_MINLEN+40)	/* Register message + inner IP6 header */

/*
 * Message types
 */
#define PIM_REGISTER	1	/* PIM Register type is 1 */

/* second bit in reg_head is the null bit */
#define PIM_NULL_REGISTER 0x40000000

#endif /* !_NETINET6_PIM6_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/pim6.h $ $Rev: 680336 $")
#endif
