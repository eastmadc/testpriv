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

#include <sys/cache.h>  /* QNX one */

extern struct cache_ctrl qnx_cachectl;

/*
 * On some architectures (ppc) a flush also
 * invalidates the cache whereas a store makes
 * physical memory consistent with the cache
 * without the invalidate.
 */

#ifdef __PPC__

static inline void
dcbst(uint32_t line_size, void *vaddr, int len)
{
	uintptr_t	cur, end;
	
	cur = (uintptr_t)vaddr;
	end = (cur + len + line_size - 1) & ~(line_size - 1);
	cur &= ~(line_size - 1);

	for (; cur < end; cur += line_size) {
		vaddr = (void *)cur;
		__asm__ __volatile__("dcbst 0,%0;" :: "r"(vaddr));
	}
}

static inline void
dcbi(uint32_t line_size, void *vaddr, int len)
{
	uintptr_t	cur, end;
	
	cur = (uintptr_t)vaddr;
	end = (cur + len + line_size - 1) & ~(line_size - 1);
	cur &= ~(line_size - 1);

	for (; cur < end; cur += line_size) {
		vaddr = (void *)cur;
		__asm__ __volatile__("dcbi 0,%0;" :: "r"(vaddr));
	}
}

static inline void
dcbf(uint32_t line_size, void *vaddr, int len)
{
	uintptr_t	cur, end;
	
	cur = (uintptr_t)vaddr;
	end = (cur + len + line_size - 1) & ~(line_size - 1);
	cur &= ~(line_size - 1);

	for (; cur < end; cur += line_size) {
		vaddr = (void *)cur;
		__asm__ __volatile__("dcbf 0,%0;" :: "r"(vaddr));
	}
}

#define NW_CACHE_STORE(__cinfo, __vaddr, __paddr, __len)	\
	dcbst((__cinfo)->cache_line_size, (__vaddr), (__len))

#define NW_CACHE_FLUSH(__cinfo, __vaddr, __paddr, __len)	\
	dcbf((__cinfo)->cache_line_size, (__vaddr), (__len))

#define NW_CACHE_INVAL(__cinfo, __vaddr, __paddr, __len)	\
	dcbi((__cinfo)->cache_line_size, (__vaddr), (__len))

#define NW_CACHE_SYNC() __asm__ __volatile__("sync;")

#else

/* The defaults. Store is same as flush */
#define NW_CACHE_STORE(__cinfo, __vaddr, __paddr, __len)	\
	CACHE_FLUSH((__cinfo), (__vaddr), (__paddr), (__len))

#define NW_CACHE_FLUSH(__cinfo, __vaddr, __paddr, __len)	\
	CACHE_FLUSH((__cinfo), (__vaddr), (__paddr), (__len))

#define NW_CACHE_INVAL(__cinfo, __vaddr, __paddr, __len)	\
	CACHE_INVAL((__cinfo), (__vaddr), (__paddr), (__len))

#define NW_CACHE_SYNC() ((void)0) /* Nothing: the above do syncs if necessary */

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_cache.h $ $Rev: 680336 $")
#endif
