/*
 * Copyright (c) 1996,1999 by Internet Software Consortium.
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
#ifdef notdef
static const char rcsid[] = "Id: inet_net_ntop.c,v 1.1.2.1 2002/08/02 02:17:21 marka Exp ";
#else
__RCSID("$NetBSD: inet_net_ntop.c,v 1.1 2004/05/20 23:13:02 christos Exp $");
#endif
#endif

#include "port_before.h"

#include "namespace.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "port_after.h"

#ifdef __weak_alias
__weak_alias(inet_net_ntop,_inet_net_ntop)
#endif

#ifdef SPRINTF_CHAR
# define SPRINTF(x) strlen(sprintf/**/x)
#else
# define SPRINTF(x) sprintf x
#endif

static char *	inet_net_ntop_ipv4 __P((const u_char *src, int bits,
					char *dst, size_t size));
static char *	inet_net_ntop_ipv6 __P((const u_char *src, int bits,
					char *dst, size_t size));

/*
 * char *
 * inet_net_ntop(af, src, bits, dst, size)
 *	convert network number from network to presentation format.
 *	generates CIDR style result always.
 * return:
 *	pointer to dst, or NULL if an error occurred (check errno).
 * author:
 *	Paul Vixie (ISC), July 1996
 */
char *
inet_net_ntop(af, src, bits, dst, size)
	int af;
	const void *src;
	int bits;
	char *dst;
	size_t size;
{
	switch (af) {
	case AF_INET:
		return (inet_net_ntop_ipv4(src, bits, dst, size));
	case AF_INET6:
		return (inet_net_ntop_ipv6(src, bits, dst, size));
	default:
		errno = EAFNOSUPPORT;
		return (NULL);
	}
}

/*
 * static char *
 * inet_net_ntop_ipv4(src, bits, dst, size)
 *	convert IPv4 network number from network to presentation format.
 *	generates CIDR style result always.
 * return:
 *	pointer to dst, or NULL if an error occurred (check errno).
 * note:
 *	network byte order assumed.  this means 192.5.5.240/28 has
 *	0b11110000 in its fourth octet.
 * author:
 *	Paul Vixie (ISC), July 1996
 */
static char *
inet_net_ntop_ipv4(src, bits, dst, size)
	const u_char *src;
	int bits;
	char *dst;
	size_t size;
{
	char *odst = dst;
	char *t;
	u_int m;
	int b;

	if (bits < 0 || bits > 32) {
		errno = EINVAL;
		return (NULL);
	}

	if (bits == 0) {
		if (size < sizeof "0")
			goto emsgsize;
		*dst++ = '0';
		size--;
		*dst = '\0';
	}

	/* Format whole octets. */
	for (b = bits / 8; b > 0; b--) {
		if (size <= sizeof "255.")
			goto emsgsize;
		t = dst;
		dst += SPRINTF((dst, "%u", *src++));
		if (b > 1) {
			*dst++ = '.';
			*dst = '\0';
		}
		size -= (size_t)(dst - t);
	}

	/* Format partial octet. */
	b = bits % 8;
	if (b > 0) {
		if (size <= sizeof ".255")
			goto emsgsize;
		t = dst;
		if (dst != odst)
			*dst++ = '.';
		m = ((1 << b) - 1) << (8 - b);
		dst += SPRINTF((dst, "%u", *src & m));
		size -= (size_t)(dst - t);
	}

	/* Format CIDR /width. */
	if (size <= sizeof "/32")
		goto emsgsize;
	dst += SPRINTF((dst, "/%u", bits));
	return (odst);

 emsgsize:
	errno = EMSGSIZE;
	return (NULL);
}

/*
 * static char *
 * inet_net_ntop_ipv6(src, bits, fakebits, dst, size)
 *	convert IPv6 network number from network to presentation format.
 *	generates CIDR style result always. Picks the shortest representation
 *	unless the IP is really IPv4.
 *	always prints specified number of bits (bits).
 * return:
 *	pointer to dst, or NULL if an error occurred (check errno).
 * note:
 *	network byte order assumed.  this means 192.5.5.240/28 has
 *	0x11110000 in its fourth octet.
 * author:
 *	Vadim Kogan (UCB), June 2001
 *  Original version (IPv4) by Paul Vixie (ISC), July 1996
 */

static char *
inet_net_ntop_ipv6(const u_char *src, int bits, char *dst, size_t size) {
	u_int	m;
	int	b;
	size_t	p;
	int	zero_s, zero_l, tmp_zero_s, tmp_zero_l;
	int	i;
	int	is_ipv4 = 0;
	unsigned char inbuf[16];
	char outbuf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255/128")];
	char	*cp;
	int	words;
	u_char	*s;

	if (bits < 0 || bits > 128) {
		errno = EINVAL;
		return (NULL);
	}

	cp = outbuf;

	if (bits == 0) {
		*cp++ = ':';
		*cp++ = ':';
		*cp = '\0';
	} else {
		/* Copy src to private buffer.  Zero host part. */	
		p = (bits + 7) / 8;
		memcpy(inbuf, src, p);
		memset(inbuf + p, 0, 16 - p);
		b = bits % 8;
		if (b != 0) {
			m = ~0 << (8 - b);
			inbuf[p-1] &= m;
		}

		s = inbuf;

		/* how many words need to be displayed in output */
		words = (bits + 15) / 16;
		if (words == 1)
			words = 2;
		
		/* Find the longest substring of zero's */
		zero_s = zero_l = tmp_zero_s = tmp_zero_l = 0;
		for (i = 0; i < (words * 2); i += 2) {
			if ((s[i] | s[i+1]) == 0) {
				if (tmp_zero_l == 0)
					tmp_zero_s = i / 2;
				tmp_zero_l++;
			} else {
				if (tmp_zero_l && zero_l < tmp_zero_l) {
					zero_s = tmp_zero_s;
					zero_l = tmp_zero_l;
					tmp_zero_l = 0;
				}
			}
		}

		if (tmp_zero_l && zero_l < tmp_zero_l) {
			zero_s = tmp_zero_s;
			zero_l = tmp_zero_l;
		}

		if (zero_l != words && zero_s == 0 && ((zero_l == 6) ||
		    ((zero_l == 5 && s[10] == 0xff && s[11] == 0xff) ||
		    ((zero_l == 7 && s[14] != 0 && s[15] != 1)))))
			is_ipv4 = 1;

		/* Format whole words. */
		for (p = 0; p < words; p++) {
			if (zero_l != 0 && p >= zero_s && p < zero_s + zero_l) {
				/* Time to skip some zeros */
				if (p == zero_s)
					*cp++ = ':';
				if (p == words - 1)
					*cp++ = ':';
				s++;
				s++;
				continue;
			}

			if (is_ipv4 && p > 5 ) {
				*cp++ = (p == 6) ? ':' : '.';
				cp += SPRINTF((cp, "%u", *s++));
				/* we can potentially drop the last octet */
				if (p != 7 || bits > 120) {
					*cp++ = '.';
					cp += SPRINTF((cp, "%u", *s++));
				}
			} else {
				if (cp != outbuf)
					*cp++ = ':';
				cp += SPRINTF((cp, "%x", *s * 256 + s[1]));
				s += 2;
			}
		}
	}
	/* Format CIDR /width. */
	(void)SPRINTF((cp, "/%u", bits));
	if (strlen(outbuf) + 1 > size)
		goto emsgsize;
	strcpy(dst, outbuf);
	
	return (dst);

emsgsize:
	errno = EMSGSIZE;
	return (NULL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/inet/inet_net_ntop.c $ $Rev: 680336 $")
#endif
