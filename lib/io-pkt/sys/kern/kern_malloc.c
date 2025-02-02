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



/*	$NetBSD: kern_malloc.c,v 1.105 2006/11/01 10:17:58 yamt Exp $	*/

/*
 * Copyright (c) 1987, 1991, 1993
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
 *
 *	@(#)kern_malloc.c	8.4 (Berkeley) 5/20/95
 */

/*
 * Copyright (c) 1996 Christopher G. Demetriou.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *
 *	@(#)kern_malloc.c	8.4 (Berkeley) 5/20/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: kern_malloc.c,v 1.105 2006/11/01 10:17:58 yamt Exp $");

#include "opt_lockdebug.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#if !defined(__QNXNTO__) || !defined(SIMPLE_MALLOC_BSD)

#include <uvm/uvm_extern.h>

static struct vm_map_kernel kmem_map_store;
struct vm_map *kmem_map = NULL;

#include "opt_kmempages.h"

#ifdef NKMEMCLUSTERS
#error NKMEMCLUSTERS is obsolete; remove it from your kernel config file and use NKMEMPAGES instead or let the kernel auto-size
#endif

/*
 * Default number of pages in kmem_map.  We attempt to calculate this
 * at run-time, but allow it to be either patched or set in the kernel
 * config file.
 */
#ifndef NKMEMPAGES
#define	NKMEMPAGES	0
#endif
int	nkmempages = NKMEMPAGES;

/*
 * Defaults for lower- and upper-bounds for the kmem_map page count.
 * Can be overridden by kernel config options.
 */
#ifndef	NKMEMPAGES_MIN
#define	NKMEMPAGES_MIN	NKMEMPAGES_MIN_DEFAULT
#endif

#ifndef NKMEMPAGES_MAX
#define	NKMEMPAGES_MAX	NKMEMPAGES_MAX_DEFAULT
#endif

#include "opt_kmemstats.h"
#include "opt_malloclog.h"
#include "opt_malloc_debug.h"

#define	MINALLOCSIZE	(1 << MINBUCKET)
#define	BUCKETINDX(size) \
	((size) <= (MINALLOCSIZE * 128) \
		? (size) <= (MINALLOCSIZE * 8) \
			? (size) <= (MINALLOCSIZE * 2) \
				? (size) <= (MINALLOCSIZE * 1) \
					? (MINBUCKET + 0) \
					: (MINBUCKET + 1) \
				: (size) <= (MINALLOCSIZE * 4) \
					? (MINBUCKET + 2) \
					: (MINBUCKET + 3) \
			: (size) <= (MINALLOCSIZE* 32) \
				? (size) <= (MINALLOCSIZE * 16) \
					? (MINBUCKET + 4) \
					: (MINBUCKET + 5) \
				: (size) <= (MINALLOCSIZE * 64) \
					? (MINBUCKET + 6) \
					: (MINBUCKET + 7) \
		: (size) <= (MINALLOCSIZE * 2048) \
			? (size) <= (MINALLOCSIZE * 512) \
				? (size) <= (MINALLOCSIZE * 256) \
					? (MINBUCKET + 8) \
					: (MINBUCKET + 9) \
				: (size) <= (MINALLOCSIZE * 1024) \
					? (MINBUCKET + 10) \
					: (MINBUCKET + 11) \
			: (size) <= (MINALLOCSIZE * 8192) \
				? (size) <= (MINALLOCSIZE * 4096) \
					? (MINBUCKET + 12) \
					: (MINBUCKET + 13) \
				: (size) <= (MINALLOCSIZE * 16384) \
					? (MINBUCKET + 14) \
					: (MINBUCKET + 15))

/*
 * Array of descriptors that describe the contents of each page
 */
struct kmemusage {
	short ku_indx;		/* bucket index */
	union {
		u_short freecnt;/* for small allocations, free pieces in page */
		u_short pagecnt;/* for large allocations, pages alloced */
	} ku_un;
};
#define	ku_freecnt ku_un.freecnt
#define	ku_pagecnt ku_un.pagecnt

struct kmembuckets kmembuckets[MINBUCKET + 16];
struct kmemusage *kmemusage;
char *kmembase, *kmemlimit;

/*
 * Turn virtual addresses into kmem map indicies
 */
#define	btokup(addr)	(&kmemusage[((caddr_t)(addr) - kmembase) >> PGSHIFT])

struct malloc_type *kmemstatistics;

#ifdef MALLOCLOG
#ifndef MALLOCLOGSIZE
#define	MALLOCLOGSIZE	100000
#endif

struct malloclog {
	void *addr;
	long size;
	struct malloc_type *type;
	int action;
	const char *file;
	long line;
} malloclog[MALLOCLOGSIZE];

long	malloclogptr;

static void
domlog(void *a, long size, struct malloc_type *type, int action,
    const char *file, long line)
{

	malloclog[malloclogptr].addr = a;
	malloclog[malloclogptr].size = size;
	malloclog[malloclogptr].type = type;
	malloclog[malloclogptr].action = action;
	malloclog[malloclogptr].file = file;
	malloclog[malloclogptr].line = line;
	malloclogptr++;
	if (malloclogptr >= MALLOCLOGSIZE)
		malloclogptr = 0;
}

static void
hitmlog(void *a)
{
	struct malloclog *lp;
	long l;

#define	PRT do { \
	lp = &malloclog[l]; \
	if (lp->addr == a && lp->action) { \
		printf("malloc log entry %ld:\n", l); \
		printf("\taddr = %p\n", lp->addr); \
		printf("\tsize = %ld\n", lp->size); \
		printf("\ttype = %s\n", lp->type->ks_shortdesc); \
		printf("\taction = %s\n", lp->action == 1 ? "alloc" : "free"); \
		printf("\tfile = %s\n", lp->file); \
		printf("\tline = %ld\n", lp->line); \
	} \
} while (/* CONSTCOND */0)

	for (l = malloclogptr; l < MALLOCLOGSIZE; l++)
		PRT;

	for (l = 0; l < malloclogptr; l++)
		PRT;
#undef PRT
}
#endif /* MALLOCLOG */

#ifdef DIAGNOSTIC
/*
 * This structure provides a set of masks to catch unaligned frees.
 */
const long addrmask[] = { 0,
	0x00000001, 0x00000003, 0x00000007, 0x0000000f,
	0x0000001f, 0x0000003f, 0x0000007f, 0x000000ff,
	0x000001ff, 0x000003ff, 0x000007ff, 0x00000fff,
	0x00001fff, 0x00003fff, 0x00007fff, 0x0000ffff,
};

/*
 * The WEIRD_ADDR is used as known text to copy into free objects so
 * that modifications after frees can be detected.
 */
#define	WEIRD_ADDR	((uint32_t) 0xdeadbeef)
#ifdef DEBUG
#define	MAX_COPY	PAGE_SIZE
#else
#define	MAX_COPY	32
#endif

/*
 * Normally the freelist structure is used only to hold the list pointer
 * for free objects.  However, when running with diagnostics, the first
 * 8/16 bytes of the structure is unused except for diagnostic information,
 * and the free list pointer is at offset 8/16 in the structure.  Since the
 * first 8 bytes is the portion of the structure most often modified, this
 * helps to detect memory reuse problems and avoid free list corruption.
 */
struct freelist {
	uint32_t spare0;
#ifdef _LP64
	uint32_t spare1;		/* explicit padding */
#endif
	struct malloc_type *type;
	caddr_t	next;
};
#else /* !DIAGNOSTIC */
struct freelist {
	caddr_t	next;
};
#endif /* DIAGNOSTIC */

#endif /* __QNXNTO__ && SIMPLE_MALLOC_BSD */
/*
 * The following are standard, built-in malloc types and are not
 * specific to any subsystem.
 */
MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_DMAMAP, "DMA map", "bus_dma(9) structures");
MALLOC_DEFINE(M_FREE, "free", "should be on free list");
MALLOC_DEFINE(M_PCB, "pcb", "protocol control block");
MALLOC_DEFINE(M_SOFTINTR, "softintr", "Softinterrupt structures");
MALLOC_DEFINE(M_TEMP, "temp", "misc. temporary data buffers");

/* XXX These should all be elsewhere. */
MALLOC_DEFINE(M_RTABLE, "routetbl", "routing tables");
MALLOC_DEFINE(M_FTABLE, "fragtbl", "fragment reassembly header");
MALLOC_DEFINE(M_UFSMNT, "UFS mount", "UFS mount structure");
MALLOC_DEFINE(M_NETADDR, "Export Host", "Export host address structure");
MALLOC_DEFINE(M_IPMOPTS, "ip_moptions", "internet multicast options");
MALLOC_DEFINE(M_IPMADDR, "in_multi", "internet multicast address");
MALLOC_DEFINE(M_MRTABLE, "mrt", "multicast routing tables");
MALLOC_DEFINE(M_BWMETER, "bwmeter", "multicast upcall bw meters");
MALLOC_DEFINE(M_1394DATA, "1394data", "IEEE 1394 data buffers");

#if !defined(__QNXNTO__) || !defined(SIMPLE_MALLOC_BSD)
struct simplelock malloc_slock = SIMPLELOCK_INITIALIZER;

/*
 * Allocate a block of memory
 */
#ifdef MALLOCLOG
void *
_malloc(unsigned long size, struct malloc_type *ksp, int flags,
    const char *file, long line)
#else
void *
malloc(unsigned long size, struct malloc_type *ksp, int flags)
#endif /* MALLOCLOG */
{
	struct kmembuckets *kbp;
	struct kmemusage *kup;
	struct freelist *freep;
	long indx, npg, allocsize;
	int s;
	caddr_t va, cp, savedlist;
#ifdef DIAGNOSTIC
	uint32_t *end, *lp;
	int copysize;
#endif

#ifdef LOCKDEBUG
	if ((flags & M_NOWAIT) == 0)
		ASSERT_SLEEPABLE(NULL, "malloc");
#endif
#ifdef MALLOC_DEBUG
	if (debug_malloc(size, ksp, flags, (void *) &va))
		return ((void *) va);
#endif
	indx = BUCKETINDX(size);
	kbp = &kmembuckets[indx];
	s = splvm();
	simple_lock(&malloc_slock);
#ifdef KMEMSTATS
	while (ksp->ks_memuse >= ksp->ks_limit) {
		if (flags & M_NOWAIT) {
			simple_unlock(&malloc_slock);
			splx(s);
			return ((void *) NULL);
		}
		if (ksp->ks_limblocks < 65535)
			ksp->ks_limblocks++;
		ltsleep((caddr_t)ksp, PSWP+2, ksp->ks_shortdesc, 0,
			&malloc_slock);
	}
	ksp->ks_size |= 1 << indx;
#endif
#ifdef DIAGNOSTIC
	copysize = 1 << indx < MAX_COPY ? 1 << indx : MAX_COPY;
#endif
	if (kbp->kb_next == NULL) {
		kbp->kb_last = NULL;
		if (size > MAXALLOCSAVE)
			allocsize = round_page(size);
		else
			allocsize = 1 << indx;
		npg = btoc(allocsize);
		simple_unlock(&malloc_slock);
		va = (caddr_t) uvm_km_alloc(kmem_map,
		    (vsize_t)ctob(npg), 0,
		    ((flags & M_NOWAIT) ? UVM_KMF_NOWAIT : 0) |
		    ((flags & M_CANFAIL) ? UVM_KMF_CANFAIL : 0) |
		    UVM_KMF_WIRED);
		if (__predict_false(va == NULL)) {
			/*
			 * Kmem_malloc() can return NULL, even if it can
			 * wait, if there is no map space available, because
			 * it can't fix that problem.  Neither can we,
			 * right now.  (We should release pages which
			 * are completely free and which are in kmembuckets
			 * with too many free elements.)
			 */
			if ((flags & (M_NOWAIT|M_CANFAIL)) == 0)
				panic("malloc: out of space in kmem_map");
			splx(s);
			return (NULL);
		}
		simple_lock(&malloc_slock);
#ifdef KMEMSTATS
		kbp->kb_total += kbp->kb_elmpercl;
#endif
		kup = btokup(va);
		kup->ku_indx = indx;
		if (allocsize > MAXALLOCSAVE) {
			if (npg > 65535)
				panic("malloc: allocation too large");
			kup->ku_pagecnt = npg;
#ifdef KMEMSTATS
			ksp->ks_memuse += allocsize;
#endif
			goto out;
		}
#ifdef KMEMSTATS
		kup->ku_freecnt = kbp->kb_elmpercl;
		kbp->kb_totalfree += kbp->kb_elmpercl;
#endif
		/*
		 * Just in case we blocked while allocating memory,
		 * and someone else also allocated memory for this
		 * kmembucket, don't assume the list is still empty.
		 */
		savedlist = kbp->kb_next;
		kbp->kb_next = cp = va + (npg << PAGE_SHIFT) - allocsize;
		for (;;) {
			freep = (struct freelist *)cp;
#ifdef DIAGNOSTIC
			/*
			 * Copy in known text to detect modification
			 * after freeing.
			 */
			end = (uint32_t *)&cp[copysize];
			for (lp = (uint32_t *)cp; lp < end; lp++)
				*lp = WEIRD_ADDR;
			freep->type = M_FREE;
#endif /* DIAGNOSTIC */
			if (cp <= va)
				break;
			cp -= allocsize;
			freep->next = cp;
		}
		freep->next = savedlist;
		if (kbp->kb_last == NULL)
			kbp->kb_last = (caddr_t)freep;
	}
	va = kbp->kb_next;
	kbp->kb_next = ((struct freelist *)va)->next;
#ifdef DIAGNOSTIC
	freep = (struct freelist *)va;
	/* XXX potential to get garbage pointer here. */
	if (kbp->kb_next) {
		int rv;
		vaddr_t addr = (vaddr_t)kbp->kb_next;

		vm_map_lock(kmem_map);
		rv = uvm_map_checkprot(kmem_map, addr,
		    addr + sizeof(struct freelist), VM_PROT_WRITE);
		vm_map_unlock(kmem_map);

		if (__predict_false(rv == 0)) {
			printf("Data modified on freelist: "
			    "word %ld of object %p size %ld previous type %s "
			    "(invalid addr %p)\n",
			    (long)((int32_t *)&kbp->kb_next - (int32_t *)kbp),
			    va, size, "foo", kbp->kb_next);
#ifdef MALLOCLOG
			hitmlog(va);
#endif
			kbp->kb_next = NULL;
		}
	}

	/* Fill the fields that we've used with WEIRD_ADDR */
#ifdef _LP64
	freep->type = (struct malloc_type *)
	    (WEIRD_ADDR | (((u_long) WEIRD_ADDR) << 32));
#else
	freep->type = (struct malloc_type *) WEIRD_ADDR;
#endif
	end = (uint32_t *)&freep->next +
	    (sizeof(freep->next) / sizeof(int32_t));
	for (lp = (uint32_t *)&freep->next; lp < end; lp++)
		*lp = WEIRD_ADDR;

	/* and check that the data hasn't been modified. */
	end = (uint32_t *)&va[copysize];
	for (lp = (uint32_t *)va; lp < end; lp++) {
		if (__predict_true(*lp == WEIRD_ADDR))
			continue;
		printf("Data modified on freelist: "
		    "word %ld of object %p size %ld previous type %s "
		    "(0x%x != 0x%x)\n",
		    (long)(lp - (uint32_t *)va), va, size,
		    "bar", *lp, WEIRD_ADDR);
#ifdef MALLOCLOG
		hitmlog(va);
#endif
		break;
	}

	freep->spare0 = 0;
#endif /* DIAGNOSTIC */
#ifdef KMEMSTATS
	kup = btokup(va);
	if (kup->ku_indx != indx)
		panic("malloc: wrong bucket");
	if (kup->ku_freecnt == 0)
		panic("malloc: lost data");
	kup->ku_freecnt--;
	kbp->kb_totalfree--;
	ksp->ks_memuse += 1 << indx;
out:
	kbp->kb_calls++;
	ksp->ks_inuse++;
	ksp->ks_calls++;
	if (ksp->ks_memuse > ksp->ks_maxused)
		ksp->ks_maxused = ksp->ks_memuse;
#else
out:
#endif
#ifdef MALLOCLOG
	domlog(va, size, ksp, 1, file, line);
#endif
	simple_unlock(&malloc_slock);
	splx(s);
	if ((flags & M_ZERO) != 0)
		memset(va, 0, size);
	return ((void *) va);
}

/*
 * Free a block of memory allocated by malloc.
 */
#ifdef MALLOCLOG
void
_free(void *addr, struct malloc_type *ksp, const char *file, long line)
#else
void
free(void *addr, struct malloc_type *ksp)
#endif /* MALLOCLOG */
{
	struct kmembuckets *kbp;
	struct kmemusage *kup;
	struct freelist *freep;
	long size;
	int s;
#ifdef DIAGNOSTIC
	caddr_t cp;
	int32_t *end, *lp;
	long alloc, copysize;
#endif

#ifdef MALLOC_DEBUG
	if (debug_free(addr, ksp))
		return;
#endif

#ifdef DIAGNOSTIC
	/*
	 * Ensure that we're free'ing something that we could
	 * have allocated in the first place.  That is, check
	 * to see that the address is within kmem_map.
	 */
	if (__predict_false((vaddr_t)addr < vm_map_min(kmem_map) ||
	    (vaddr_t)addr >= vm_map_max(kmem_map)))
		panic("free: addr %p not within kmem_map", addr);
#endif

	kup = btokup(addr);
	size = 1 << kup->ku_indx;
	kbp = &kmembuckets[kup->ku_indx];
	s = splvm();
	simple_lock(&malloc_slock);
#ifdef MALLOCLOG
	domlog(addr, 0, ksp, 2, file, line);
#endif
#ifdef DIAGNOSTIC
	/*
	 * Check for returns of data that do not point to the
	 * beginning of the allocation.
	 */
	if (size > PAGE_SIZE)
		alloc = addrmask[BUCKETINDX(PAGE_SIZE)];
	else
		alloc = addrmask[kup->ku_indx];
	if (((u_long)addr & alloc) != 0)
		panic("free: unaligned addr %p, size %ld, type %s, mask %ld",
		    addr, size, ksp->ks_shortdesc, alloc);
#endif /* DIAGNOSTIC */
	if (size > MAXALLOCSAVE) {
		uvm_km_free(kmem_map, (vaddr_t)addr, ctob(kup->ku_pagecnt),
		    UVM_KMF_WIRED);
#ifdef KMEMSTATS
		size = kup->ku_pagecnt << PGSHIFT;
		ksp->ks_memuse -= size;
		kup->ku_indx = 0;
		kup->ku_pagecnt = 0;
		if (ksp->ks_memuse + size >= ksp->ks_limit &&
		    ksp->ks_memuse < ksp->ks_limit)
			wakeup((caddr_t)ksp);
#ifdef DIAGNOSTIC
		if (ksp->ks_inuse == 0)
			panic("free 1: inuse 0, probable double free");
#endif
		ksp->ks_inuse--;
		kbp->kb_total -= 1;
#endif
		simple_unlock(&malloc_slock);
		splx(s);
		return;
	}
	freep = (struct freelist *)addr;
#ifdef DIAGNOSTIC
	/*
	 * Check for multiple frees. Use a quick check to see if
	 * it looks free before laboriously searching the freelist.
	 */
	if (__predict_false(freep->spare0 == WEIRD_ADDR)) {
		for (cp = kbp->kb_next; cp;
		    cp = ((struct freelist *)cp)->next) {
			if (addr != cp)
				continue;
			printf("multiply freed item %p\n", addr);
#ifdef MALLOCLOG
			hitmlog(addr);
#endif
			panic("free: duplicated free");
		}
	}
#ifdef LOCKDEBUG
	/*
	 * Check if we're freeing a locked simple lock.
	 */
	simple_lock_freecheck(addr, (char *)addr + size);
#endif
	/*
	 * Copy in known text to detect modification after freeing
	 * and to make it look free. Also, save the type being freed
	 * so we can list likely culprit if modification is detected
	 * when the object is reallocated.
	 */
	copysize = size < MAX_COPY ? size : MAX_COPY;
	end = (int32_t *)&((caddr_t)addr)[copysize];
	for (lp = (int32_t *)addr; lp < end; lp++)
		*lp = WEIRD_ADDR;
	freep->type = ksp;
#endif /* DIAGNOSTIC */
#ifdef KMEMSTATS
	kup->ku_freecnt++;
	if (kup->ku_freecnt >= kbp->kb_elmpercl) {
		if (kup->ku_freecnt > kbp->kb_elmpercl)
			panic("free: multiple frees");
		else if (kbp->kb_totalfree > kbp->kb_highwat)
			kbp->kb_couldfree++;
	}
	kbp->kb_totalfree++;
	ksp->ks_memuse -= size;
	if (ksp->ks_memuse + size >= ksp->ks_limit &&
	    ksp->ks_memuse < ksp->ks_limit)
		wakeup((caddr_t)ksp);
#ifdef DIAGNOSTIC
	if (ksp->ks_inuse == 0)
		panic("free 2: inuse 0, probable double free");
#endif
	ksp->ks_inuse--;
#endif
	if (kbp->kb_next == NULL)
		kbp->kb_next = addr;
	else
		((struct freelist *)kbp->kb_last)->next = addr;
	freep->next = NULL;
	kbp->kb_last = addr;
	simple_unlock(&malloc_slock);
	splx(s);
}

/*
 * Change the size of a block of memory.
 */
void *
realloc(void *curaddr, unsigned long newsize, struct malloc_type *ksp,
    int flags)
{
	struct kmemusage *kup;
	unsigned long cursize;
	void *newaddr;
#ifdef DIAGNOSTIC
	long alloc;
#endif

	/*
	 * realloc() with a NULL pointer is the same as malloc().
	 */
	if (curaddr == NULL)
		return (malloc(newsize, ksp, flags));

	/*
	 * realloc() with zero size is the same as free().
	 */
	if (newsize == 0) {
		free(curaddr, ksp);
		return (NULL);
	}

#ifdef LOCKDEBUG
	if ((flags & M_NOWAIT) == 0)
		ASSERT_SLEEPABLE(NULL, "realloc");
#endif

	/*
	 * Find out how large the old allocation was (and do some
	 * sanity checking).
	 */
	kup = btokup(curaddr);
	cursize = 1 << kup->ku_indx;

#ifdef DIAGNOSTIC
	/*
	 * Check for returns of data that do not point to the
	 * beginning of the allocation.
	 */
	if (cursize > PAGE_SIZE)
		alloc = addrmask[BUCKETINDX(PAGE_SIZE)];
	else
		alloc = addrmask[kup->ku_indx];
	if (((u_long)curaddr & alloc) != 0)
		panic("realloc: "
		    "unaligned addr %p, size %ld, type %s, mask %ld\n",
		    curaddr, cursize, ksp->ks_shortdesc, alloc);
#endif /* DIAGNOSTIC */

	if (cursize > MAXALLOCSAVE)
		cursize = ctob(kup->ku_pagecnt);

	/*
	 * If we already actually have as much as they want, we're done.
	 */
	if (newsize <= cursize)
		return (curaddr);

	/*
	 * Can't satisfy the allocation with the existing block.
	 * Allocate a new one and copy the data.
	 */
	newaddr = malloc(newsize, ksp, flags);
	if (__predict_false(newaddr == NULL)) {
		/*
		 * malloc() failed, because flags included M_NOWAIT.
		 * Return NULL to indicate that failure.  The old
		 * pointer is still valid.
		 */
		return (NULL);
	}
	memcpy(newaddr, curaddr, cursize);

	/*
	 * We were successful: free the old allocation and return
	 * the new one.
	 */
	free(curaddr, ksp);
	return (newaddr);
}

/*
 * Roundup size to the actual allocation size.
 */
unsigned long
malloc_roundup(unsigned long size)
{

	if (size > MAXALLOCSAVE)
		return (roundup(size, PAGE_SIZE));
	else
		return (1 << BUCKETINDX(size));
}

/*
 * Add a malloc type to the system.
 */
void
malloc_type_attach(struct malloc_type *type)
{

	if (nkmempages == 0)
		panic("malloc_type_attach: nkmempages == 0");

	if (type->ks_magic != M_MAGIC)
		panic("malloc_type_attach: bad magic");

#ifdef DIAGNOSTIC
	{
		struct malloc_type *ksp;
		for (ksp = kmemstatistics; ksp != NULL; ksp = ksp->ks_next) {
			if (ksp == type)
				panic("malloc_type_attach: already on list");
		}
	}
#endif

#ifdef KMEMSTATS
	if (type->ks_limit == 0)
		type->ks_limit = ((u_long)nkmempages << PAGE_SHIFT) * 6U / 10U;
#else
	type->ks_limit = 0;
#endif

	type->ks_next = kmemstatistics;
	kmemstatistics = type;
}

/*
 * Remove a malloc type from the system..
 */
void
malloc_type_detach(struct malloc_type *type)
{
	struct malloc_type *ksp;

#ifdef DIAGNOSTIC
	if (type->ks_magic != M_MAGIC)
		panic("malloc_type_detach: bad magic");
#endif

	if (type == kmemstatistics)
		kmemstatistics = type->ks_next;
	else {
		for (ksp = kmemstatistics; ksp->ks_next != NULL;
		     ksp = ksp->ks_next) {
			if (ksp->ks_next == type) {
				ksp->ks_next = type->ks_next;
				break;
			}
		}
#ifdef DIAGNOSTIC
		if (ksp->ks_next == NULL)
			panic("malloc_type_detach: not on list");
#endif
	}
	type->ks_next = NULL;
}

/*
 * Set the limit on a malloc type.
 */
void
malloc_type_setlimit(struct malloc_type *type, u_long limit)
{
#ifdef KMEMSTATS
	int s;

	s = splvm();
	type->ks_limit = limit;
	splx(s);
#endif
}

/*
 * Compute the number of pages that kmem_map will map, that is,
 * the size of the kernel malloc arena.
 */
void
kmeminit_nkmempages(void)
{
	int npages;

	if (nkmempages != 0) {
		/*
		 * It's already been set (by us being here before, or
		 * by patching or kernel config options), bail out now.
		 */
		return;
	}

	npages = physmem;

	if (npages > NKMEMPAGES_MAX)
		npages = NKMEMPAGES_MAX;

	if (npages < NKMEMPAGES_MIN)
		npages = NKMEMPAGES_MIN;

	nkmempages = npages;
}

/*
 * Initialize the kernel memory allocator
 */
void
kmeminit(void)
{
	__link_set_decl(malloc_types, struct malloc_type);
	struct malloc_type * const *ksp;
	vaddr_t kmb, kml;
#ifdef KMEMSTATS
	long indx;
#endif

#if	((MAXALLOCSAVE & (MAXALLOCSAVE - 1)) != 0)
		ERROR!_kmeminit:_MAXALLOCSAVE_not_power_of_2
#endif
#if	(MAXALLOCSAVE > MINALLOCSIZE * 32768)
		ERROR!_kmeminit:_MAXALLOCSAVE_too_big
#endif
#if	(MAXALLOCSAVE < NBPG)
		ERROR!_kmeminit:_MAXALLOCSAVE_too_small
#endif

	if (sizeof(struct freelist) > (1 << MINBUCKET))
		panic("minbucket too small/struct freelist too big");

	/*
	 * Compute the number of kmem_map pages, if we have not
	 * done so already.
	 */
	kmeminit_nkmempages();

	kmemusage = (struct kmemusage *) uvm_km_alloc(kernel_map,
	    (vsize_t)(nkmempages * sizeof(struct kmemusage)), 0,
	    UVM_KMF_WIRED|UVM_KMF_ZERO);
	kmb = 0;
	kmem_map = uvm_km_suballoc(kernel_map, &kmb,
	    &kml, ((vsize_t)nkmempages << PAGE_SHIFT),
	    VM_MAP_INTRSAFE, FALSE, &kmem_map_store);
	uvm_km_vacache_init(kmem_map, "kvakmem", 0);
	kmembase = (char *)kmb;
	kmemlimit = (char *)kml;
#ifdef KMEMSTATS
	for (indx = 0; indx < MINBUCKET + 16; indx++) {
		if (1 << indx >= PAGE_SIZE)
			kmembuckets[indx].kb_elmpercl = 1;
		else
			kmembuckets[indx].kb_elmpercl = PAGE_SIZE / (1 << indx);
		kmembuckets[indx].kb_highwat =
			5 * kmembuckets[indx].kb_elmpercl;
	}
#endif

	/* Attach all of the statically-linked malloc types. */
	__link_set_foreach(ksp, malloc_types)
		malloc_type_attach(*ksp);

#ifdef MALLOC_DEBUG
	debug_malloc_init();
#endif
}

#ifdef DDB
#include <ddb/db_output.h>

/*
 * Dump kmem statistics from ddb.
 *
 * usage: call dump_kmemstats
 */
void	dump_kmemstats(void);

void
dump_kmemstats(void)
{
#ifdef KMEMSTATS
	struct malloc_type *ksp;

	for (ksp = kmemstatistics; ksp != NULL; ksp = ksp->ks_next) {
		if (ksp->ks_memuse == 0)
			continue;
		db_printf("%s%.*s %ld\n", ksp->ks_shortdesc,
		    (int)(20 - strlen(ksp->ks_shortdesc)),
		    "                    ",
		    ksp->ks_memuse);
	}
#else
	db_printf("Kmem stats are not being collected.\n");
#endif /* KMEMSTATS */
}
#endif /* DDB */


#if 0
/*
 * Diagnostic messages about "Data modified on
 * freelist" indicate a memory corruption, but
 * they do not help tracking it down.
 * This function can be called at various places
 * to sanity check malloc's freelist and discover
 * where does the corruption take place.
 */
int
freelist_sanitycheck(void) {
	int i,j;
	struct kmembuckets *kbp;
	struct freelist *freep;
	int rv = 0;

	for (i = MINBUCKET; i <= MINBUCKET + 15; i++) {
		kbp = &kmembuckets[i];
		freep = (struct freelist *)kbp->kb_next;
		j = 0;
		while(freep) {
			vm_map_lock(kmem_map);
			rv = uvm_map_checkprot(kmem_map, (vaddr_t)freep,
			    (vaddr_t)freep + sizeof(struct freelist),
			    VM_PROT_WRITE);
			vm_map_unlock(kmem_map);

			if ((rv == 0) || (*(int *)freep != WEIRD_ADDR)) {
				printf("bucket %i, chunck %d at %p modified\n",
				    i, j, freep);
				return 1;
			}
			freep = (struct freelist *)freep->next;
			j++;
		}
	}

	return 0;
}
#endif
#else /* __QNXNTO__ && SIMPLE_MALLOC_BSD */

/*
 * Until we can get full malloc_bsd() going above
 * which uses the kmembucket stuff
 */
#include <sys/param_bsd.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/systm.h>

#undef malloc
#undef realloc
#undef free
#undef _MALLOC_H_INCLUDED
#include <malloc.h> /* The QNX one */

#ifndef NDEBUG
struct malcheck {
	uint32_t ksp;
	uint32_t size;
};
#define MALLOC_BSD_ALIGN	8 /* power of 2 */
#define MALLOC_BSD_ROUND(sz)	(((sz) + MALLOC_BSD_ALIGN - 1) & ~(MALLOC_BSD_ALIGN - 1))

static void *
addr_verify(void *addr, struct malloc_type *ksp, const char *func)
{
	ssize_t			size_start;
	struct malcheck		*mcp1, *mcp2;
	void			*va;

	if (addr == NULL)
		return NULL;

	size_start = MALLOC_BSD_ROUND(sizeof(struct malcheck));
	va = (void *)((uintptr_t)addr - size_start);

	mcp1 = (struct malcheck *)((uintptr_t)addr - sizeof(*mcp1));
	if (UNALIGNED_RET32(&mcp1->ksp) != (uint32_t)ksp)
		panic("addr_verify: %s: check1", func);

	mcp2 = (struct malcheck *)((uintptr_t)addr + mcp1->size);
	if (UNALIGNED_RET32(&mcp1->ksp) != UNALIGNED_RET32(&mcp2->ksp) ||
	    UNALIGNED_RET32(&mcp1->size) != UNALIGNED_RET32(&mcp2->size))
		panic("addr_verify: %s: check2", func);

	UNALIGNED_PUT32(&mcp1->ksp, 0);
	UNALIGNED_PUT32(&mcp1->size, 0);
	UNALIGNED_PUT32(&mcp2->ksp, 0);
	UNALIGNED_PUT32(&mcp2->size, 0);

	return va;
}
#endif

static int mem_wait;

/*
 * Allocate a block of memory.
 * 
 * Note malloc() / free() proper are mutexed so
 * also use these as a SIGLOCK wrappers.  Allows
 * malloc_bsd() / free_bsd() to be used in an
 * interrupt context.
 *
 * malloc(0) returns non NULL.
 */
void *
malloc_bsd(unsigned long size, struct malloc_type *ksp, int flags)
{
	return realloc_bsd(NULL, size, ksp, flags);
}


void *
realloc_bsd(void *addr, unsigned long size, struct malloc_type *ksp, int flags)
{
	void			*va;
	struct nw_work_thread	*wtp;
#if !defined(NDEBUG)
	ssize_t			size_start;
	struct malcheck		*mcp;
#endif

	wtp = WTP;

#ifndef NDEBUG
	if ((flags & M_NOWAIT) == 0 &&
	    wtp->intr_sighot == _ISIG_COLD && wtp->wt_intr_pending == 0) {
		panic("realloc: can't wait from interrupt context");
	}

	addr = addr_verify(addr, ksp, __FUNCTION__);

	size_start = MALLOC_BSD_ROUND(sizeof(struct malcheck));
#endif

	for (;;) {
#if !defined(NDEBUG)
		/* 2 slop words up front; 1 slop word at back */
		NW_SIGHOLD_P(wtp);
		va = realloc(addr, size_start + size + sizeof(struct malcheck));
		NW_SIGUNHOLD_P(wtp);

		if (va != NULL) {
			va = (void *)((uintptr_t)va + size_start);

			mcp = (struct malcheck *)((uintptr_t)va - sizeof(*mcp));
			UNALIGNED_PUT32(&mcp->ksp, (uint32_t)ksp);
			UNALIGNED_PUT32(&mcp->size, size);


			mcp = (struct malcheck *)((uintptr_t)va + size);
			UNALIGNED_PUT32(&mcp->ksp, (uint32_t)ksp);
			UNALIGNED_PUT32(&mcp->size, size);

			break;
		}
#else
		NW_SIGHOLD_P(wtp);
		va = realloc(addr, size);
		NW_SIGUNHOLD_P(wtp);

		if (va != NULL)
			break;
#endif
		if (!(flags & M_WAITOK)) {
			mbstat.m_drops++;
			break;
		}

		mbstat.m_wait++;
		/* FIXME trace */
		tsleep(&mem_wait, PSWP + 2, ksp->ks_shortdesc, 0);

		/* Reset in case tsleep() swapped us out */
		wtp = WTP;
	}

	if ((flags & M_ZERO) != 0)
		memset(va, 0, size);

	return va;
}
/*
 * Free a block of memory allocated by malloc.
 */

void
free_bsd(void *addr, struct malloc_type *ksp)
{
	struct nw_work_thread	*wtp;

#if !defined(NDEBUG)
	addr = addr_verify(addr, ksp, __FUNCTION__);
#endif
	wtp = WTP;
	NW_SIGHOLD_P(wtp);
	free(addr);
	NW_SIGUNHOLD_P(wtp);
//	wakeup((caddr_t)&mem_wait);
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/kern_malloc.c $ $Rev: 775442 $")
#endif
