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

/* $NetBSD: if_pppoe.h,v 1.8 2005/12/10 23:21:38 elad Exp $ */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NET_IF_PPPOE_H_
#define _NET_IF_PPPOE_H_

struct pppoediscparms {
	char	ifname[IFNAMSIZ];	/* pppoe interface name */
	char	eth_ifname[IFNAMSIZ];	/* external ethernet interface name */
	const char *ac_name;		/* access concentrator name (or NULL) */
	size_t	ac_name_len;		/* on write: length of buffer for ac_name */
	const char *service_name;	/* service name (or NULL) */
	size_t	service_name_len;	/* on write: length of buffer for service name */
#ifdef __QNXNTO__
	char	qnx_acname[256];
	char	qnx_svname[256];
#endif
};

#define	PPPOESETPARMS	_IOW('i', 110, struct pppoediscparms)
#define	PPPOEGETPARMS	_IOWR('i', 111, struct pppoediscparms)

#define PPPOE_STATE_INITIAL	0
#define PPPOE_STATE_PADI_SENT	1
#define	PPPOE_STATE_PADR_SENT	2
#define	PPPOE_STATE_SESSION	3
#define	PPPOE_STATE_CLOSING	4
/* passive */
#define	PPPOE_STATE_PADO_SENT	1

struct pppoeconnectionstate {
	char	ifname[IFNAMSIZ];	/* pppoe interface name */
	u_int	state;			/* one of the PPPOE_STATE_ states above */
	u_int	session_id;		/* if state == PPPOE_STATE_SESSION */
	u_int	padi_retry_no;		/* number of retries already sent */
	u_int	padr_retry_no;
};

#define PPPOEGETSESSION	_IOWR('i', 112, struct pppoeconnectionstate)

#ifdef _KERNEL

extern struct ifqueue ppoediscinq;
extern struct ifqueue ppoeinq;

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
extern void * pppoe_softintr;			/* softinterrupt cookie */
#else
extern struct callout pppoe_softintr;		/* callout (poor mans softint) */
extern void pppoe_softintr_handler(void*);	/* handler function */
#endif

#endif /* _KERNEL */
#endif /* !_NET_IF_PPPOE_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_pppoe.h $ $Rev: 680336 $")
#endif
