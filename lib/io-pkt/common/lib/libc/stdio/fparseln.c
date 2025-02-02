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

/*	$NetBSD: fparseln.c,v 1.5 2004/06/20 22:20:15 jmc Exp $	*/

/*
 * Copyright (c) 1997 Christos Zoulas.  All rights reserved.
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
 *	This product includes software developed by Christos Zoulas.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef __QNXNTO__
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: fparseln.c,v 1.5 2004/06/20 22:20:15 jmc Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef __QNXNTO__
#define _DIAGASSERT(x) ((void)0)
#include <nbutil.h>

/* Weak aliases are enabled for libsocket but this isn't exported */
#undef __weak_alias
#endif

#ifdef __weak_alias
__weak_alias(fparseln,_fparseln)
#endif

#if ! HAVE_FPARSELN

#ifndef __QNXNTO__
#ifndef HAVE_NBTOOL_CONFIG_H
#include "reentrant.h"
#include "local.h"
#else
#define FLOCKFILE(fp)
#define FUNLOCKFILE(fp)
#endif
#else /* __QNXNTO__ */
#define FLOCKFILE(fp) flockfile((fp))
#define FUNLOCKFILE(fp) funlockfile((fp))
#endif /* __QNXNTO__ */

#if (defined(_REENTRANT) && !HAVE_NBTOOL_CONFIG_H)
#define __fgetln(f, l) __fgetstr(f, l, '\n')
#else
#define __fgetln(f, l) fgetln(f, l)
#endif

static int isescaped(const char *, const char *, int);

/* isescaped():
 *	Return true if the character in *p that belongs to a string
 *	that starts in *sp, is escaped by the escape character esc.
 */
static int
isescaped(const char *sp, const char *p, int esc)
{
	const char     *cp;
	size_t		ne;

	_DIAGASSERT(sp != NULL);
	_DIAGASSERT(p != NULL);

	/* No escape character */
	if (esc == '\0')
		return 1;

	/* Count the number of escape characters that precede ours */
	for (ne = 0, cp = p; --cp >= sp && *cp == esc; ne++)
		continue;

	/* Return true if odd number of escape characters */
	return (ne & 1) != 0;
}


/* fparseln():
 *	Read a line from a file parsing continuations ending in \
 *	and eliminating trailing newlines, or comments starting with
 *	the comment char.
 */
char *
fparseln(FILE *fp, size_t *size, size_t *lineno, const char str[3], int flags)
{
	static const char dstr[3] = { '\\', '\\', '#' };

	size_t	s, len;
	char   *buf;
	char   *ptr, *cp;
	int	cnt;
	char	esc, con, nl, com;
#ifdef __QNXNTO__
	char	*fgbuf;
	size_t	fgbufsize;

	fgbuf = NULL;
	fgbufsize = 0;
#endif

	_DIAGASSERT(fp != NULL);

	len = 0;
	buf = NULL;
	cnt = 1;

	if (str == NULL)
		str = dstr;

	esc = str[0];
	con = str[1];
	com = str[2];
	/*
	 * XXX: it would be cool to be able to specify the newline character,
	 * but unfortunately, fgetln does not let us
	 */
	nl  = '\n';

	FLOCKFILE(fp);

	while (cnt) {
		cnt = 0;

		if (lineno)
			(*lineno)++;

#ifndef __QNXNTO__
		if ((ptr = __fgetln(fp, &s)) == NULL)
			break;
#else
		if ((ptr = fgetln_r(fp, &s, &fgbuf, &fgbufsize)) == NULL)
			break;
#endif

		if (s && com) {		/* Check and eliminate comments */
			for (cp = ptr; cp < ptr + s; cp++)
				if (*cp == com && !isescaped(ptr, cp, esc)) {
					s = cp - ptr;
					cnt = s == 0 && buf == NULL;
					break;
				}
		}

		if (s && nl) { 		/* Check and eliminate newlines */
			cp = &ptr[s - 1];

			if (*cp == nl)
				s--;	/* forget newline */
		}

		if (s && con) {		/* Check and eliminate continuations */
			cp = &ptr[s - 1];

			if (*cp == con && !isescaped(ptr, cp, esc)) {
				s--;	/* forget escape */
				cnt = 1;
			}
		}

		if (s == 0 && buf != NULL)
			continue;

		if ((cp = realloc(buf, len + s + 1)) == NULL) {
			FUNLOCKFILE(fp);
			free(buf);
#ifdef __QNXNTO__
			free(fgbuf);
#endif
			return NULL;
		}
		buf = cp;

		(void) memcpy(buf + len, ptr, s);
		len += s;
		buf[len] = '\0';
	}

	FUNLOCKFILE(fp);
#ifdef __QNXNTO__
	free(fgbuf);
	fgbuf = NULL;
	fgbufsize = 0;
#endif

	if ((flags & FPARSELN_UNESCALL) != 0 && esc && buf != NULL &&
	    strchr(buf, esc) != NULL) {
		ptr = cp = buf;
		while (cp[0] != '\0') {
			int skipesc;

			while (cp[0] != '\0' && cp[0] != esc)
				*ptr++ = *cp++;
			if (cp[0] == '\0' || cp[1] == '\0')
				break;

			skipesc = 0;
			if (cp[1] == com)
				skipesc += (flags & FPARSELN_UNESCCOMM);
			if (cp[1] == con)
				skipesc += (flags & FPARSELN_UNESCCONT);
			if (cp[1] == esc)
				skipesc += (flags & FPARSELN_UNESCESC);
			if (cp[1] != com && cp[1] != con && cp[1] != esc)
				skipesc = (flags & FPARSELN_UNESCREST);

			if (skipesc)
				cp++;
			else
				*ptr++ = *cp++;
			*ptr++ = *cp++;
		}
		*ptr = '\0';
		len = strlen(buf);
	}

	if (size)
		*size = len;
	return buf;
}

#ifdef TEST

int main(int, char **);

int
main(int argc, char **argv)
{
	char   *ptr;
	size_t	size, line;

	line = 0;
	while ((ptr = fparseln(stdin, &size, &line, NULL,
	    FPARSELN_UNESCALL)) != NULL)
		printf("line %d (%d) |%s|\n", line, size, ptr);
	return 0;
}

/*

# This is a test
line 1
line 2 \
line 3 # Comment
line 4 \# Not comment \\\\

# And a comment \
line 5 \\\
line 6

*/

#endif /* TEST */
#endif	/* ! HAVE_FPARSELN */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/common/lib/libc/stdio/fparseln.c $ $Rev: 680336 $")
#endif
