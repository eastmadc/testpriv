/*	$NetBSD: sethostent.c,v 1.14.10.1 2007/05/17 21:25:17 jdc Exp $	*/

/*
 * Copyright (c) 1985, 1993
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
static char sccsid[] = "@(#)sethostent.c	8.1 (Berkeley) 6/4/93";
static char rcsid[] = "Id: sethostent.c,v 8.5 1996/09/28 06:51:07 vixie Exp ";
#else
__RCSID("$NetBSD: sethostent.c,v 1.14.10.1 2007/05/17 21:25:17 jdc Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>

#ifdef __weak_alias
__weak_alias(sethostent,_sethostent)
__weak_alias(endhostent,_endhostent)
#endif

void	_endhtent __P((void));
#ifndef _REENTRANT
void	res_close __P((void));
#endif
void	_sethtent __P((int));

void
/*ARGSUSED*/
sethostent(stayopen)
	int stayopen;
{
#ifndef _REENTRANT
	if ((_res.options & RES_INIT) == 0 && res_init() == -1)
		return;
	if (stayopen)
		_res.options |= RES_STAYOPEN | RES_USEVC;
#endif
	_sethtent(stayopen);
}

void
endhostent()
{
#ifndef _REENTRANT
	_res.options &= ~(RES_STAYOPEN | RES_USEVC);
	res_close();
#endif
	_endhtent();
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/sethostent.c $ $Rev: 680336 $")
#endif
