/*	$NetBSD: altqconf.h,v 1.4 2002/09/22 20:09:15 jdolecek Exp $	*/

#ifdef _KERNEL

#if defined(_KERNEL_OPT)
#include "opt_altq_enabled.h"
#endif

#include <sys/conf.h>

#ifdef ALTQ
#define	NALTQ	1
#else
#define	NALTQ	0
#endif

#endif /* _KERNEL */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/altq/altqconf.h $ $Rev: 680336 $")
#endif
