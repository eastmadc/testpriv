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

/*	$NetBSD: linkaddr.c,v 1.14 2005/11/29 03:11:59 christos Exp $	*/

/*-
 * Copyright (c) 1990, 1993
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
static char sccsid[] = "@(#)linkaddr.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: linkaddr.c,v 1.14 2005/11/29 03:11:59 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>

#include <assert.h>
#ifdef __QNXNTO__
#include <stdlib.h> // for min()
#define _DIAGASSERT(x) ((void)0)
#endif
#include <string.h>

/* States*/
#define NAMING	0
#define GOTONE	1
#define GOTTWO	2
#define RESET	3
/* Inputs */
#define	DIGIT	(4*0)
#define	END	(4*1)
#define DELIM	(4*2)
#define LETTER	(4*3)

void
link_addr(addr, sdl)
	register const char *addr;
	register struct sockaddr_dl *sdl;
{
	register char *cp = sdl->sdl_data;
	char *cplim = sdl->sdl_len + (char *)(void *)sdl;
	register int byte = 0, state = NAMING;
	register int newaddr = 0;	/* pacify gcc */

	_DIAGASSERT(addr != NULL);
	_DIAGASSERT(sdl != NULL);

	(void)memset(&sdl->sdl_family, 0, (size_t)sdl->sdl_len - 1);
	sdl->sdl_family = AF_LINK;
	do {
		state &= ~LETTER;
		if ((*addr >= '0') && (*addr <= '9')) {
			newaddr = *addr - '0';
		} else if ((*addr >= 'a') && (*addr <= 'f')) {
			newaddr = *addr - 'a' + 10;
		} else if ((*addr >= 'A') && (*addr <= 'F')) {
			newaddr = *addr - 'A' + 10;
		} else if (*addr == 0) {
			state |= END;
		} else if (state == NAMING &&
			   (((*addr >= 'A') && (*addr <= 'Z')) ||
			   ((*addr >= 'a') && (*addr <= 'z'))))
			state |= LETTER;
		else
			state |= DELIM;
		addr++;
		switch (state /* | INPUT */) {
		case NAMING | DIGIT:
		case NAMING | LETTER:
			*cp++ = addr[-1];
			continue;
		case NAMING | DELIM:
			state = RESET;
			sdl->sdl_nlen = cp - sdl->sdl_data;
			continue;
		case GOTTWO | DIGIT:
			*cp++ = byte;
			/* FALLTHROUGH */
		case RESET | DIGIT:
			state = GOTONE;
			byte = newaddr;
			continue;
		case GOTONE | DIGIT:
			state = GOTTWO;
			byte = newaddr + (byte << 4);
			continue;
		default: /* | DELIM */
			state = RESET;
			*cp++ = byte;
			byte = 0;
			continue;
		case GOTONE | END:
		case GOTTWO | END:
			*cp++ = byte;
			/* FALLTHROUGH */
		case RESET | END:
			break;
		}
		break;
	} while (cp < cplim); 
	sdl->sdl_alen = cp - LLADDR(sdl);
	newaddr = cp - (char *)(void *)sdl;
	if ((size_t) newaddr > sizeof(*sdl))
		sdl->sdl_len = newaddr;
	return;
}

static const char hexlist[16] = "0123456789abcdef";

char *
link_ntoa(sdl)
	register const struct sockaddr_dl *sdl;
{
	static char obuf[64];
	register char *out = obuf;
	register size_t i;
	const u_char *in = (const u_char *)CLLADDR(sdl);
	const u_char *inlim = in + sdl->sdl_alen;
	int firsttime = 1;
#ifdef __QNXNTO__
	size_t bytes;
	const size_t max_bytes = sizeof(obuf) - 1;
	const char * const last_byte = &obuf[sizeof(obuf) - 1];
#endif

	_DIAGASSERT(sdl != NULL);

#ifdef __QNXNTO__

	if (sdl->sdl_nlen) {
		bytes = min(max_bytes, (size_t)sdl->sdl_nlen);
		(void)memcpy(obuf, sdl->sdl_data, bytes);
		out += bytes;
		if ((sdl->sdl_alen) && (out < last_byte)) {
			*out++ = ':';
		}
	}
	while (in < inlim) {
		if (firsttime) {
			firsttime = 0;
		} else {
			if (out < last_byte) {
				*out++ = '.';
			} else {
				break;
			}
		}
		i = *in++;
		if ((i > 0xf)) {
			if (out < last_byte) {
				*out++ = hexlist[i>>4];
			} else {
				break;
			}

			if (out < last_byte) {
				*out++ = hexlist[i & 0xf];
			} else {
				break;
			}
		} else {
			if (out < last_byte) {
				*out++ = hexlist[i];
			} else {
				break;
			}
		}
	}
#else
	if (sdl->sdl_nlen) {
		(void)memcpy(obuf, sdl->sdl_data, (size_t)sdl->sdl_nlen);
		out += sdl->sdl_nlen;
		if (sdl->sdl_alen)
			*out++ = ':';
	}
	while (in < inlim) {
		if (firsttime)
			firsttime = 0;
		else
			*out++ = '.';
		i = *in++;
		if (i > 0xf) {
			out[1] = hexlist[i & 0xf];
			i >>= 4;
			out[0] = hexlist[i];
			out += 2;
		} else
			*out++ = hexlist[i];
	}
#endif
	*out = 0;
	return (obuf);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/linkaddr.c $ $Rev: 816347 $")
#endif
