/*	$NetBSD: __res_send.c,v 1.4 2005/09/13 01:44:10 christos Exp $	*/

/*
 * written by matthew green, 22/04/97.
 * public domain.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: __res_send.c,v 1.4 2005/09/13 01:44:10 christos Exp $");
#endif

#if defined(__indr_reference)
__indr_reference(__res_send, res_send)
#else

#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>

/* XXX THIS IS A MESS!  SEE <resolv.h> XXX */

#undef res_send
int	res_send(const u_char *, int, u_char *, int);

int
res_send(const u_char *buf, int buflen, u_char *ans, int anssiz)
{

	return __res_send(buf, buflen, ans, anssiz);
}

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/__res_send.c $ $Rev: 680336 $")
#endif
