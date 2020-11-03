/*	$NetBSD: res_private.h,v 1.3 2009/10/24 17:24:01 christos Exp $	*/

#ifndef res_private_h
#define res_private_h

#ifdef __QNXNTO__
#include "res_init_pps.h"
#include <stdio.h>
#define RES_INFINITE_CACHE_TIME ((uint64_t)-1)
#endif

struct __res_state_ext {
	union res_sockaddr_union nsaddrs[MAXNS];
	struct sort_list {
		int     af;
		union {
			struct in_addr  ina;
			struct in6_addr in6a;
		} addr, mask;
	} sort_list[MAXRESOLVSORT];
	char nsuffix[64];
	char nsuffix2[64];
#ifndef __QNXNTO__
	struct timespec res_conf_time;
	int kq, resfd;
#else
	struct timespec res_conf_time;
	uint64_t max_cache_time_in_nsec; /* 0 means do not cache (although (options & RES_INIT) == 0 in the same circumstances, RES_INFINITE_CACHE_TIME means never expire the cache (infinite) */
	char * conf_domain; /*%< the last read value for _CS_DOMAIN -- used for caching */
	char * conf_resolv; /*%< the last read value for _CS_RESOLVE -- used for caching */
	struct pps_context *pps_ctx;
#endif
};

extern int res_ourserver_p(const res_state, const struct sockaddr *);
#ifdef __QNXNTO__
#define RES_VINIT_PREINIT	1
#define RES_VINIT_PPSRELOAD	2
#endif
extern int __res_vinit(res_state, int);

#endif

/*! \file */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/res_private.h $ $Rev: 724903 $")
#endif
