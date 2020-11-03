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

/*	$NetBSD: getservbyport.c,v 1.11 2005/04/18 19:39:45 kleink Exp $	*/

/*-
 * Copyright (c) 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
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

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: getservbyport.c,v 1.11 2005/04/18 19:39:45 kleink Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#ifndef __QNXNTO__
#include "reentrant.h"
#else
#include <pthread.h>
#include <errno.h>
#endif

#include <netdb.h>

#include "servent.h"

#ifdef __weak_alias
__weak_alias(getservbyport,_getservbyport)
#endif

#ifndef __QNXNTO__
#ifdef _REENTRANT
extern mutex_t _servent_mutex;
#endif
#else
extern pthread_mutex_t _servent_mutex;
#endif
extern struct servent_data _servent_data;

struct servent *
getservbyport(int port, const char *proto)
{
	struct servent *s;

#ifndef __QNXNTO__
	mutex_lock(&_servent_mutex);
	s = getservbyport_r(port, proto, &_servent_data.serv, &_servent_data);
	mutex_unlock(&_servent_mutex);
#else
	int ret;

	if ((ret = pthread_mutex_lock(&_servent_mutex)) != EOK) {
		/*
		 * This func isn't advertised as setting errno
		 * but give some indication...
		 */
		errno = ret;
		return NULL;
	}
	s = getservbyport_r(port, proto, &_servent_data.serv, &_servent_data);
	pthread_mutex_unlock(&_servent_mutex);
#endif
	return (s);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/getservbyport.c $ $Rev: 680336 $")
#endif
