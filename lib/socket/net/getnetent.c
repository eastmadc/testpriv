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

/*	$NetBSD: getnetent.c,v 1.16.10.1 2007/05/17 21:25:16 jdc Exp $	*/

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
 *
 * Portions Copyright (c) 1993 Carlos Leandro and Rui Salgueiro
 *    Dep. Matematica Universidade de Coimbra, Portugal, Europe
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * from getnetent.c   1.1 (Coimbra) 93/06/02
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)getnetent.c	8.1 (Berkeley) 6/4/93";
static char rcsid[] = "Id: getnetent.c,v 8.4 1997/06/01 20:34:37 vixie Exp ";
#else
__RCSID("$NetBSD: getnetent.c,v 1.16.10.1 2007/05/17 21:25:16 jdc Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#if (!defined(__QNXNTO__) && defined(_LIBC)) ||	\
    (defined(__QNXNTO__) && defined(_LIBSOCKET))
#include "namespace.h"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#ifdef __weak_alias
__weak_alias(endnetent,_endnetent)
__weak_alias(getnetent,_getnetent)
__weak_alias(setnetent,_setnetent)
#endif

#define	MAXALIASES	35

static FILE *netf;
static char line[BUFSIZ+1];
static struct netent net;
static char *net_aliases[MAXALIASES];
int _net_stayopen;

static void __setnetent __P((int));
static void __endnetent __P((void));

void
setnetent(stayopen)
	int stayopen;
{

	sethostent(stayopen);
	__setnetent(stayopen);
}

void
endnetent()
{

	endhostent();
	__endnetent();
}

static void
__setnetent(f)
	int f;
{

	if (netf == NULL)
		netf = fopen(_PATH_NETWORKS, "r" );
	else
		rewind(netf);
	_net_stayopen |= f;
}

static void
__endnetent()
{

	if (netf) {
		fclose(netf);
		netf = NULL;
	}
	_net_stayopen = 0;
}

struct netent *
getnetent()
{
	char *p;
	register char *cp, **q;

	if (netf == NULL && (netf = fopen(_PATH_NETWORKS, "r" )) == NULL)
		return (NULL);
#if (defined(__sparc__) && defined(_LP64)) ||		\
    defined(__alpha__) ||				\
    (defined(__i386__) && defined(_LP64)) ||		\
    (defined(__sh__) && defined(_LP64))
	net.__n_pad0 = 0;
#endif
again:
	p = fgets(line, sizeof line, netf);
	if (p == NULL)
		return (NULL);
	if (*p == '#')
		goto again;
	cp = strpbrk(p, "#\n");
	if (cp == NULL)
		goto again;
	*cp = '\0';
	net.n_name = p;
	cp = strpbrk(p, " \t");
	if (cp == NULL)
		goto again;
	*cp++ = '\0';
	while (*cp == ' ' || *cp == '\t')
		cp++;
	p = strpbrk(cp, " \t");
	if (p != NULL)
		*p++ = '\0';
	net.n_net = inet_network(cp);
	net.n_addrtype = AF_INET;
	q = net.n_aliases = net_aliases;
	if (p != NULL) {
		cp = p;
		while (cp && *cp) {
			if (*cp == ' ' || *cp == '\t') {
				cp++;
				continue;
			}
			if (q < &net_aliases[MAXALIASES - 1])
				*q++ = cp;
			cp = strpbrk(cp, " \t");
			if (cp != NULL)
				*cp++ = '\0';
		}
	}
	*q = NULL;
	return (&net);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/getnetent.c $ $Rev: 680336 $")
#endif
