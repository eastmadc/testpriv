#ifdef __QNXNTO__
#ifndef IFIPSEC_H
#define IFIPSEC_H
#define	NIFIPSEC	1
/*
 * NetBSD's config utility usually builds ioconf.c and puts
 * the prototype there following their pseudo-device rules.
 */
void ifipsecattach(int);
#endif
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys-nto/ifipsec.h $ $Rev: 680336 $")
#endif
