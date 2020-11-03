/*
 * $QNXLicenseC:
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






#ifndef __NLIST_H_INCLUDED
#define __NLIST_H_INCLUDED

#include <nlist.h>
#include <sys/cdefs_bsd.h>

struct nlist_export {
	const char		*ne_name;
	int			ne_size;
	const void		*ne_addr;
	struct nlist_export	*ne_next;
};


/*
 * Ones known at link time just need to use
 * NLIST_EXPORT().  Anything dynamically loaded
 * needs to call nlist_add() themselves for any
 * symbols they want exported.  We don't currently
 * unload anything so don't need a nlist_remove().
 */


#define NLIST_DEFINE(name, obj)				\
static struct nlist_export NL_##name[1] = {		\
	{						\
		(#name),				\
		sizeof((obj)),				\
		&(obj),					\
		0					\
	}						\
}							\

/*
 * The first arg is what nlist() does the strcmp against.
 * It's usually the name of the obj but not always.
 */
#define NLIST_EXPORT(name, obj)				\
NLIST_DEFINE(name, obj);				\
__link_set_add_rodata(nlist_exports, NL_##name)

#define NLIST_EXPORT_IPSEC(name, obj)			\
NLIST_DEFINE(name, obj);				\
__link_set_add_rodata(nlist_exports_ipsec, NL_##name)

extern void nlist_init(void);
extern void nlist_add(struct nlist_export *);
extern int nlist_old(struct nlist_old *nl, int num);

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/nlist.h $ $Rev: 680336 $")
#endif
