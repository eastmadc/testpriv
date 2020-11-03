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



/*	$NetBSD: getprotobyname_r.c,v 1.3 2005/04/18 19:39:45 kleink Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)getprotoname.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: getprotobyname_r.c,v 1.3 2005/04/18 19:39:45 kleink Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"

#include <assert.h>
#ifdef __QNXNTO__
#define _DIAGASSERT(x) ((void)0)
#endif
#include <netdb.h>
#include <string.h>
#ifdef __QNXNTO__
#include <unistd.h>
#endif

#include "protoent.h"

#ifdef __weak_alias
__weak_alias(getprotobyname_r,_getprotobyname_r)
#endif

#ifdef __QNXNTO__
extern struct protoent __builtin_protos[];
#endif

struct protoent *
getprotobyname_r(const char *name, struct protoent *pr,
    struct protoent_data *pd)
{
	struct protoent *p;
	char **cp;

	_DIAGASSERT(name != NULL);

#ifdef __QNXNTO__
	if (access(_PATH_PROTOCOLS, R_OK) != 0) {
		int i;
		for (i = 0; __builtin_protos[i].p_name != NULL; i++) {
			if (strcmp(__builtin_protos[i].p_name, name) == 0)
				return &__builtin_protos[i];
		}
		return 0;
	} 
#endif
	setprotoent_r(pd->stayopen, pd);
	while ((p = getprotoent_r(pr, pd)) != NULL) {
		if (strcmp(p->p_name, name) == 0)
			break;
		for (cp = p->p_aliases; *cp != NULL; cp++)
			if (strcmp(*cp, name) == 0)
				goto found;
	}
found:
	if (!pd->stayopen)
		if (pd->fp != NULL) {
			(void)fclose(pd->fp);
			pd->fp = NULL;
		}
	return p;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/getprotobyname_r.c $ $Rev: 680336 $")
#endif
