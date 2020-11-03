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

/*	$NetBSD: inet_neta.c,v 1.1 2004/05/20 23:13:02 christos Exp $	*/

/*
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static const char rcsid[] = "Id: inet_neta.c,v 8.2 1996/08/08 06:54:44 vixie Exp ";
#else
__RCSID("$NetBSD: inet_neta.c,v 1.1 2004/05/20 23:13:02 christos Exp $");
#endif
#endif

#include "namespace.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef __QNXNTO__
#include <nbutil.h>
#define _DIAGASSERT(x) /* nothing */
#endif

#ifdef __weak_alias
__weak_alias(inet_neta,_inet_neta)
#endif

/*
 * char *
 * inet_neta(src, dst, size)
 *	format a u_long network number into presentation format.
 * return:
 *	pointer to dst, or NULL if an error occurred (check errno).
 * note:
 *	format of ``src'' is as for inet_network().
 * author:
 *	Paul Vixie (ISC), July 1996
 */
char *
inet_neta(src, dst, size)
	u_long src;
	char *dst;
	size_t size;
{
	char *odst = dst;
	char *ep;
	int advance;

	_DIAGASSERT(dst != NULL);

	if (src == 0x00000000) {
		if (size < sizeof "0.0.0.0")
			goto emsgsize;
		strlcpy(dst, "0.0.0.0", size);
		return dst;
	}
	ep = dst + size;
	if (ep <= dst)
		goto emsgsize;
	while (src & 0xffffffff) {
		u_char b = (u_char)((src & 0xff000000) >> 24);

		src <<= 8;
		if (b || src) {
			advance = snprintf(dst, (size_t)(ep - dst), "%u", b);
			if (advance <= 0 || advance >= ep - dst)
				goto emsgsize;
			dst += advance;
			if (src != 0L) {
				if (dst + 1 >= ep)
					goto emsgsize;
				*dst++ = '.';
				*dst = '\0';
			}
		}
	}
	return (odst);

 emsgsize:
	errno = EMSGSIZE;
	return (NULL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/inet/inet_neta.c $ $Rev: 680336 $")
#endif
