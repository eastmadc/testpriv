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


/*	$NetBSD: subr_pool.c,v 1.124 2006/11/01 10:17:58 yamt Exp $	*/

/*-
 * Copyright (c) 1997, 1999, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Paul Kranenburg; by Jason R. Thorpe of the Numerical Aerospace
 * Simulation Facility, NASA Ames Research Center.
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
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: subr_pool.c,v 1.124 2006/11/01 10:17:58 yamt Exp $");

#include "opt_pool.h"
#include "opt_poollog.h"
#include "opt_lockdebug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/pool.h>
#include <sys/syslog.h>

#ifndef __QNXNTO__
#include <uvm/uvm.h>
#else
#include <sys/mman.h>
#include <sys/sched.h>
#include "nw_datastruct.h"
#include "siglock.h"
#endif /* __QNXNTO__ */


#ifndef __QNXNTO__
#define POOL_LOCK(pp, exp, wtp)	simple_lock(exp)
#define POOL_UNLOCK(pp, exp, wtp)	simple_unlock(exp)
#else /* __QNXNTO__ */
extern struct pool_allocator pool_allocator_bigpage; /* instantiated below */
static int force_bigpage;
#define POOL_LOCK(pp, exp, wtp)					\
do {								\
	if ((pp)->pr_roflags & PR_PROTECT)			\
		NW_SIGLOCK_P((exp), iopkt_selfp, (wtp));	\
} while (/*CONSTCOND*/ 0)

#define POOL_UNLOCK(pp, exp, wtp)				\
do {								\
	if ((pp)->pr_roflags & PR_PROTECT)			\
		NW_SIGUNLOCK_P((exp), iopkt_selfp, (wtp));	\
} while (/*CONSTCOND*/ 0)


/*
 * We currently have two phpools: one that locks and one 
 * that doesn't.  The cluster pool is unique in that that 
 * it locks and wants some extra room per cluster to hold 
 * a reference count.  This extra data is generally small
 * so we always tag it on the locking phpool even though
 * it's unused some of the time.
 *
 * XXX breaks division between pool and mbuf layer.
 */
#include <sys/mbuf.h>
/*
 * cluster pool always uses large pages.
 *    NOTE: some (most?) times pagesize_large == pagesize.
 */
#define PHEXTRA_SIZE (pagesize_large / mclbytes * sizeof(unsigned))

#endif

/*
 * Pool resource management utility.
 *
 * Memory is allocated in pages which are split into pieces according to
 * the pool item size. Each page is kept on one of three lists in the
 * pool structure: `pr_emptypages', `pr_fullpages' and `pr_partpages',
 * for empty, full and partially-full pages respectively. The individual
 * pool items are on a linked list headed by `ph_itemlist' in each page
 * header. The memory for building the page list is either taken from
 * the allocated pages themselves (for small pool items) or taken from
 * an internal pool of page headers (`phpool').
 */

/* List of all pools */
LIST_HEAD(,pool) pool_head = LIST_HEAD_INITIALIZER(pool_head);

/* Private pool for page header structures */
#ifndef __QNXNTO__
#define	PHPOOL_MAX	8
#else
#define	PHPOOL_MAX	1
#endif
static struct pool phpool[PHPOOL_MAX];
#ifndef __QNXNTO__
#define	PHPOOL_FREELIST_NELEM(idx)	(((idx) == 0) ? 0 : (1 << (idx)))
#else
#define	PHPOOL_FREELIST_NELEM(idx)	(0)
static struct pool phpool_extra_lock;
#endif

#ifdef POOL_SUBPAGE
/* Pool of subpages for use by normal pools. */
static struct pool psppool;
#endif

#ifndef __QNXNTO__
static SLIST_HEAD(, pool_allocator) pa_deferinitq =
    SLIST_HEAD_INITIALIZER(pa_deferinitq);

static void *pool_page_alloc_meta(struct pool *, int);
static void pool_page_free_meta(struct pool *, void *);

/* allocator for pool metadata */
static struct pool_allocator pool_allocator_meta = {
	pool_page_alloc_meta, pool_page_free_meta,
	.pa_backingmapptr = &kmem_map,
};
#endif

/* # of seconds to retain page after last use */
int pool_inactive_time = 10;

/* Next candidate for drainage (see pool_drain()) */
static struct pool	*drainpp;

#ifndef __QNXNTO__
/* This spin lock protects both pool_head and drainpp. */
struct simplelock pool_head_slock = SIMPLELOCK_INITIALIZER;
#else
/*
 * pool_init() pool_destroy() and pool_drain() only called
 * while we are 'the stack'.
 */
#endif

typedef uint8_t pool_item_freelist_t;

#ifndef __QNXNTO__
struct pool_item_header {
	/* Page headers */
	LIST_ENTRY(pool_item_header)
				ph_pagelist;	/* pool page list */
	SPLAY_ENTRY(pool_item_header)
				ph_node;	/* Off-page page headers */
	caddr_t			ph_page;	/* this page's address */
	struct timeval		ph_time;	/* last referenced */
	union {
		/* !PR_NOTOUCH */
		struct {
			LIST_HEAD(, pool_item)
				phu_itemlist;	/* chunk list for this page */
		} phu_normal;
		/* PR_NOTOUCH */
		struct {
			uint16_t
				phu_off;	/* start offset in page */
			pool_item_freelist_t
				phu_firstfree;	/* first free item */
			/*
			 * XXX it might be better to use
			 * a simple bitmap and ffs(3)
			 */
		} phu_notouch;
	} ph_u;
	uint16_t		ph_nmissing;	/* # of chunks in use */
};
#define	ph_itemlist	ph_u.phu_normal.phu_itemlist
#define	ph_off		ph_u.phu_notouch.phu_off
#define	ph_firstfree	ph_u.phu_notouch.phu_firstfree
#else

struct pool_item_header {
	/* Page headers */
	LIST_ENTRY(pool_item_header)
				ph_pagelist;	/* pool page list */
	LIST_HEAD(,pool_item)	ph_itemlist;	/* chunk list for this page */
	SPLAY_ENTRY(pool_item_header)
				ph_node;	/* Off-page page headers */
	unsigned int		ph_nmissing;	/* # of chunks in use */
	struct timeval		ph_time;	/* last referenced */
	/* page address (ph_page above) is in exported ph_pg */
#define ph_page ph_pg.pg_page
#define PG_TO_PIH(pg) ((struct pool_item_header *)((char *)pg - offsetof(struct pool_item_header, ph_pg)))
	struct			pool_cache_group *ph_pcgroup; /* back pointer to pool_cache_group */
	struct			pool *ph_pool;	/* Back pointer to pool */
	struct page_extra	ph_pg;

};
#endif

struct pool_item {
#ifdef DIAGNOSTIC
	u_int pi_magic;
#endif
#define	PI_MAGIC 0xdeadbeefU
	/* Other entries use only this list entry */
	LIST_ENTRY(pool_item)	pi_list;
};

#define	POOL_NEEDS_CATCHUP(pp)						\
	((pp)->pr_nitems < (pp)->pr_minitems)

/*
 * Pool cache management.
 *
 * Pool caches provide a way for constructed objects to be cached by the
 * pool subsystem.  This can lead to performance improvements by avoiding
 * needless object construction/destruction; it is deferred until absolutely
 * necessary.
 *
 * Caches are grouped into cache groups.  Each cache group references
 * up to 16 constructed objects.  When a cache allocates an object
 * from the pool, it calls the object's constructor and places it into
 * a cache group.  When a cache group frees an object back to the pool,
 * it first calls the object's destructor.  This allows the object to
 * persist in constructed form while freed to the cache.
 *
 * Multiple caches may exist for each pool.  This allows a single
 * object type to have multiple constructed forms.  The pool references
 * each cache, so that when a pool is drained by the pagedaemon, it can
 * drain each individual cache as well.  Each time a cache is drained,
 * the most idle cache group is freed to the pool in its entirety.
 *
 * Pool caches are layed on top of pools.  By layering them, we can avoid
 * the complexity of cache management for pools which would not benefit
 * from it.
 */

/* The cache group pool. */
static struct pool pcgpool;

static void	pool_cache_reclaim(struct pool_cache *, struct pool_pagelist *,
				   struct pool_cache_grouplist *);
static void	pcg_grouplist_free(struct pool_cache_grouplist *);

static int	pool_catchup(struct pool *);
static void	pool_prime_page(struct pool *, caddr_t,
		    struct pool_item_header *);
static void	pool_update_curpage(struct pool *);

static int	pool_grow(struct pool *, int);
static void	*pool_allocator_alloc(struct pool *, int);
static void	pool_allocator_free(struct pool *, void *);

#ifndef __QNXNTO__
static void pool_print_pagelist(struct pool *, struct pool_pagelist *,
	void (*)(const char *, ...));
static void pool_print1(struct pool *, const char *,
	void (*)(const char *, ...));
#else
static void pool_print_pagelist(struct pool *, struct pool_pagelist *,
	int (*)(const char *, ...));
static void pool_print1(struct pool *, const char *,
	int (*)(const char *, ...));
#endif

static int pool_chk_page(struct pool *, const char *,
			 struct pool_item_header *);

/*
 * Pool log entry. An array of these is allocated in pool_init().
 */
struct pool_log {
	const char	*pl_file;
	long		pl_line;
	int		pl_action;
#define	PRLOG_GET	1
#define	PRLOG_PUT	2
	void		*pl_addr;
};

#ifdef __QNXNTO__
void
pool_subsystem_birth(void *arg)
{
	int	bigpage_strict;

	bigpage_strict = *(int *)arg;

	if (bigpage_strict)
		force_bigpage = PR_BIGPAGE;
}
#endif

#ifdef POOL_DIAGNOSTIC
/* Number of entries in pool log buffers */
#ifndef POOL_LOGSIZE
#define	POOL_LOGSIZE	10
#endif

int pool_logsize = POOL_LOGSIZE;

static inline void
pr_log(struct pool *pp, void *v, int action, const char *file, long line)
{
	int n = pp->pr_curlogentry;
	struct pool_log *pl;

	if ((pp->pr_roflags & PR_LOGGING) == 0)
		return;

	/*
	 * Fill in the current entry. Wrap around and overwrite
	 * the oldest entry if necessary.
	 */
	pl = &pp->pr_log[n];
	pl->pl_file = file;
	pl->pl_line = line;
	pl->pl_action = action;
	pl->pl_addr = v;
	if (++n >= pp->pr_logsize)
		n = 0;
	pp->pr_curlogentry = n;
}

static void
pr_printlog(struct pool *pp, struct pool_item *pi,
    void (*pr)(const char *, ...))
{
	int i = pp->pr_logsize;
	int n = pp->pr_curlogentry;

	if ((pp->pr_roflags & PR_LOGGING) == 0)
		return;

	/*
	 * Print all entries in this pool's log.
	 */
	while (i-- > 0) {
		struct pool_log *pl = &pp->pr_log[n];
		if (pl->pl_action != 0) {
			if (pi == NULL || pi == pl->pl_addr) {
				(*pr)("\tlog entry %d:\n", i);
				(*pr)("\t\taction = %s, addr = %p\n",
				    pl->pl_action == PRLOG_GET ? "get" : "put",
				    pl->pl_addr);
				(*pr)("\t\tfile: %s at line %lu\n",
				    pl->pl_file, pl->pl_line);
			}
		}
		if (++n >= pp->pr_logsize)
			n = 0;
	}
}

static inline void
pr_enter(struct pool *pp, const char *file, long line)
{

	if (__predict_false(pp->pr_entered_file != NULL)) {
		printf("pool %s: reentrancy at file %s line %ld\n",
		    pp->pr_wchan, file, line);
		printf("         previous entry at file %s line %ld\n",
		    pp->pr_entered_file, pp->pr_entered_line);
		panic("pr_enter");
	}

	pp->pr_entered_file = file;
	pp->pr_entered_line = line;
}

static inline void
pr_leave(struct pool *pp)
{

	if (__predict_false(pp->pr_entered_file == NULL)) {
		printf("pool %s not entered?\n", pp->pr_wchan);
		panic("pr_leave");
	}

	pp->pr_entered_file = NULL;
	pp->pr_entered_line = 0;
}

static inline void
pr_enter_check(struct pool *pp, void (*pr)(const char *, ...))
{

	if (pp->pr_entered_file != NULL)
		(*pr)("\n\tcurrently entered from file %s line %ld\n",
		    pp->pr_entered_file, pp->pr_entered_line);
}
#else
#define	pr_log(pp, v, action, file, line)
#define	pr_printlog(pp, pi, pr)
#define	pr_enter(pp, file, line)
#define	pr_leave(pp)
#define	pr_enter_check(pp, pr)
#endif /* POOL_DIAGNOSTIC */

#ifndef __QNXNTO__
static inline int
pr_item_notouch_index(const struct pool *pp, const struct pool_item_header *ph,
    const void *v)
{
	const char *cp = v;
	int idx;

	KASSERT(pp->pr_roflags & PR_NOTOUCH);
	idx = (cp - ph->ph_page - ph->ph_off) / pp->pr_size;
	KASSERT(idx < pp->pr_itemsperpage);
	return idx;
}

#define	PR_FREELIST_ALIGN(p) \
	roundup((uintptr_t)(p), sizeof(pool_item_freelist_t))
#define	PR_FREELIST(ph)	((pool_item_freelist_t *)PR_FREELIST_ALIGN((ph) + 1))
#define	PR_INDEX_USED	((pool_item_freelist_t)-1)
#define	PR_INDEX_EOL	((pool_item_freelist_t)-2)

static inline void
pr_item_notouch_put(const struct pool *pp, struct pool_item_header *ph,
    void *obj)
{
	int idx = pr_item_notouch_index(pp, ph, obj);
	pool_item_freelist_t *freelist = PR_FREELIST(ph);

	KASSERT(freelist[idx] == PR_INDEX_USED);
	freelist[idx] = ph->ph_firstfree;
	ph->ph_firstfree = idx;
}

static inline void *
pr_item_notouch_get(const struct pool *pp, struct pool_item_header *ph)
{
	int idx = ph->ph_firstfree;
	pool_item_freelist_t *freelist = PR_FREELIST(ph);

	KASSERT(freelist[idx] != PR_INDEX_USED);
	ph->ph_firstfree = freelist[idx];
	freelist[idx] = PR_INDEX_USED;

	return ph->ph_page + ph->ph_off + idx * pp->pr_size;
}
#endif

static inline int
phtree_compare(struct pool_item_header *a, struct pool_item_header *b)
{

	/*
	 * we consider pool_item_header with smaller ph_page bigger.
	 * (this unnatural ordering is for the benefit of pr_find_pagehead.)
	 */

	if (a->ph_page < b->ph_page)
		return (1);
	else if (a->ph_page > b->ph_page)
		return (-1);
	else
		return (0);
}

SPLAY_PROTOTYPE(phtree, pool_item_header, ph_node, phtree_compare);
SPLAY_GENERATE(phtree, pool_item_header, ph_node, phtree_compare);

/*
 * Return the pool page header based on item address.
 */
static inline struct pool_item_header *
pr_find_pagehead(struct pool *pp, void *v)
{
	struct pool_item_header *ph, tmp;

	if ((pp->pr_roflags & PR_NOALIGN) != 0) {
		tmp.ph_page = (caddr_t)(uintptr_t)v;
		ph = SPLAY_FIND(phtree, &pp->pr_phtree, &tmp);
		if (ph == NULL) {
			ph = SPLAY_ROOT(&pp->pr_phtree);
			if (ph != NULL && phtree_compare(&tmp, ph) >= 0) {
				ph = SPLAY_NEXT(phtree, &pp->pr_phtree, ph);
			}
			KASSERT(ph == NULL || phtree_compare(&tmp, ph) < 0);
		}
	} else {
		caddr_t page =
		    (caddr_t)((uintptr_t)v & pp->pr_alloc->pa_pagemask);

		if ((pp->pr_roflags & PR_PHINPAGE) != 0) {
			ph = (void *)(page + pp->pr_phoffset);
		} else {
			tmp.ph_page = page;
			ph = SPLAY_FIND(phtree, &pp->pr_phtree, &tmp);
		}
	}

	KASSERT(ph == NULL || ((pp->pr_roflags & PR_PHINPAGE) != 0) ||
	    (ph->ph_page <= (char *)v &&
	    (char *)v < ph->ph_page + pp->pr_alloc->pa_pagesz));
	return ph;
}

static void
pr_pagelist_free(struct pool *pp, struct pool_pagelist *pq)
{
	struct pool_item_header *ph;
	int s;

	while ((ph = LIST_FIRST(pq)) != NULL) {
		LIST_REMOVE(ph, ph_pagelist);
		pool_allocator_free(pp, ph->ph_page);
		if ((pp->pr_roflags & PR_PHINPAGE) == 0) {
			s = splvm();
			pool_put(pp->pr_phpool, ph);
			splx(s);
		}
	}
}

/*
 * Remove a page from the pool.
 */
static inline void
pr_rmpage(struct pool *pp, struct pool_item_header *ph,
     struct pool_pagelist *pq)
{

	LOCK_ASSERT(simple_lock_held(&pp->pr_slock));

	/*
	 * If the page was idle, decrement the idle page count.
	 */
	if (ph->ph_nmissing == 0) {
#ifdef DIAGNOSTIC
		if (pp->pr_nidle == 0)
			panic("pr_rmpage: nidle inconsistent");
		if (pp->pr_nitems < pp->pr_itemsperpage)
			panic("pr_rmpage: nitems inconsistent");
#endif
		pp->pr_nidle--;
	}

	pp->pr_nitems -= pp->pr_itemsperpage;

	/*
	 * Unlink the page from the pool and queue it for release.
	 */
	LIST_REMOVE(ph, ph_pagelist);
	if ((pp->pr_roflags & PR_PHINPAGE) == 0)
		SPLAY_REMOVE(phtree, &pp->pr_phtree, ph);
	LIST_INSERT_HEAD(pq, ph, ph_pagelist);

	pp->pr_npages--;
	pp->pr_npagefree++;

	pool_update_curpage(pp);
}

static boolean_t
pa_starved_p(struct pool_allocator *pa)
{

#ifndef __QNXNTO__
	if (pa->pa_backingmap != NULL) {
		return vm_map_starved_p(pa->pa_backingmap);
	}
#endif
	return FALSE;
}

#ifndef __QNXNTO__
static int
pool_reclaim_callback(struct callback_entry *ce, void *obj, void *arg)
{
	struct pool *pp = obj;
	struct pool_allocator *pa = pp->pr_alloc;

	KASSERT(&pp->pr_reclaimerentry == ce);
	pool_reclaim(pp);
	if (!pa_starved_p(pa)) {
		return CALLBACK_CHAIN_ABORT;
	}
	return CALLBACK_CHAIN_CONTINUE;
}

static void
pool_reclaim_register(struct pool *pp)
{
	struct vm_map *map = pp->pr_alloc->pa_backingmap;
	int s;

	if (map == NULL) {
		return;
	}

	s = splvm(); /* not necessary for INTRSAFE maps, but don't care. */
	callback_register(&vm_map_to_kernel(map)->vmk_reclaim_callback,
	    &pp->pr_reclaimerentry, pp, pool_reclaim_callback);
	splx(s);
}

static void
pool_reclaim_unregister(struct pool *pp)
{
	struct vm_map *map = pp->pr_alloc->pa_backingmap;
	int s;

	if (map == NULL) {
		return;
	}

	s = splvm(); /* not necessary for INTRSAFE maps, but don't care. */
	callback_unregister(&vm_map_to_kernel(map)->vmk_reclaim_callback,
	    &pp->pr_reclaimerentry);
	splx(s);
}

static void
pa_reclaim_register(struct pool_allocator *pa)
{
	struct vm_map *map = *pa->pa_backingmapptr;
	struct pool *pp;

	KASSERT(pa->pa_backingmap == NULL);
	if (map == NULL) {
		SLIST_INSERT_HEAD(&pa_deferinitq, pa, pa_q);
		return;
	}
	pa->pa_backingmap = map;
	TAILQ_FOREACH(pp, &pa->pa_list, pr_alloc_list) {
		pool_reclaim_register(pp);
	}
}
#endif

/*
 * Initialize all the pools listed in the "pools" link set.
 */
void
pool_subsystem_init(void)
{
#ifndef __QNXNTO__
	struct pool_allocator *pa;
#endif
	__link_set_decl(pools, struct link_pool_init);
	struct link_pool_init * const *pi;

	__link_set_foreach(pi, pools)
		pool_init((*pi)->pp, (*pi)->size, (*pi)->align,
		    (*pi)->align_offset, (*pi)->flags, (*pi)->wchan,
		    (*pi)->palloc);
#ifndef __QNXNTO__
	while ((pa = SLIST_FIRST(&pa_deferinitq)) != NULL) {
		KASSERT(pa->pa_backingmapptr != NULL);
		KASSERT(*pa->pa_backingmapptr != NULL);
		SLIST_REMOVE_HEAD(&pa_deferinitq, pa_q);
		pa_reclaim_register(pa);
	}
#endif
}

/*
 * Initialize the given pool resource structure.
 *
 * We export this routine to allow other kernel parts to declare
 * static pools that must be initialized before malloc() is available.
 */
void
pool_init(struct pool *pp, size_t size, u_int align, u_int ioff, int flags,
    const char *wchan, struct pool_allocator *palloc)
#ifdef __QNXNTO__
{
	return pool_init_extra(pp, size, align, ioff, flags, wchan, palloc, 0, NOFD);
}
void
pool_init_extra(struct pool *pp, size_t size, u_int align, u_int ioff, int flags,
    const char *wchan, struct pool_allocator *palloc, size_t extra_size, int typed_mem_fd)
#endif
{
#ifdef DEBUG
	struct pool *pp1;
#endif
	size_t trysize, phsize;
	int off, slack, s;
#ifdef __QNXNTO__
	if (!ISSTACK)
		panic("pool_init: not stack");

	if (extra_size != 0)
		flags |= PR_EXTRA;

	flags |= force_bigpage;

	pp->pr_typed_mem_fd = typed_mem_fd;
#endif

	KASSERT((1UL << (CHAR_BIT * sizeof(pool_item_freelist_t))) - 2 >=
	    PHPOOL_FREELIST_NELEM(PHPOOL_MAX - 1));

#ifdef DEBUG
	/*
	 * Check that the pool hasn't already been initialised and
	 * added to the list of all pools.
	 */
	LIST_FOREACH(pp1, &pool_head, pr_poollist) {
		if (pp == pp1)
			panic("pool_init: pool %s already initialised",
			    wchan);
	}
#endif

#ifdef POOL_DIAGNOSTIC
	/*
	 * Always log if POOL_DIAGNOSTIC is defined.
	 */
	if (pool_logsize != 0)
		flags |= PR_LOGGING;
#endif

	if (palloc == NULL)
		palloc = &pool_allocator_kmem;
#ifdef __QNXNTO__
	if (flags & PR_BIGPAGE) {
		/* Make sure it's initialized  */
		pool_allocator_bigpage.pa_pagesz = pagesize_large;
		if (pagesize_large != pagesize)
			palloc = &pool_allocator_bigpage;
	}
#endif
#ifdef POOL_SUBPAGE
	if (size > palloc->pa_pagesz) {
		if (palloc == &pool_allocator_kmem)
			palloc = &pool_allocator_kmem_fullpage;
		else if (palloc == &pool_allocator_nointr)
			palloc = &pool_allocator_nointr_fullpage;
	}		
#endif /* POOL_SUBPAGE */
	if ((palloc->pa_flags & PA_INITIALIZED) == 0) {
		if (palloc->pa_pagesz == 0)
			palloc->pa_pagesz = PAGE_SIZE;

		TAILQ_INIT(&palloc->pa_list);

		simple_lock_init(&palloc->pa_slock);
		palloc->pa_pagemask = ~(palloc->pa_pagesz - 1);
		palloc->pa_pageshift = ffs(palloc->pa_pagesz) - 1;
#ifndef __QNXNTO__
		if (palloc->pa_backingmapptr != NULL) {
			pa_reclaim_register(palloc);
		}
#endif
		palloc->pa_flags |= PA_INITIALIZED;
	}

	if (align == 0)
		align = ALIGN(1);

	if ((flags & PR_NOTOUCH) == 0 && size < sizeof(struct pool_item))
		size = sizeof(struct pool_item);

	size = roundup(size, align);
#ifdef DIAGNOSTIC
	if (size > palloc->pa_pagesz)
		panic("pool_init: pool item size (%zu) too large", size);
#endif

	/*
	 * Initialize the pool structure.
	 */
	LIST_INIT(&pp->pr_emptypages);
	LIST_INIT(&pp->pr_fullpages);
	LIST_INIT(&pp->pr_partpages);
	LIST_INIT(&pp->pr_cachelist);
	pp->pr_curpage = NULL;
	pp->pr_npages = 0;
	pp->pr_minitems = 0;
	pp->pr_minpages = 0;
	pp->pr_maxpages = UINT_MAX;
	pp->pr_roflags = flags;
	pp->pr_flags = 0;
	pp->pr_size = size;
	pp->pr_align = align;
	pp->pr_wchan = wchan;
	pp->pr_alloc = palloc;
	pp->pr_nitems = 0;
	pp->pr_nout = 0;
	pp->pr_hardlimit = UINT_MAX;
	pp->pr_hardlimit_warning = NULL;
	pp->pr_hardlimit_ratecap.tv_sec = 0;
	pp->pr_hardlimit_ratecap.tv_usec = 0;
	pp->pr_hardlimit_warning_last.tv_sec = 0;
	pp->pr_hardlimit_warning_last.tv_usec = 0;
	pp->pr_drain_hook = NULL;
	pp->pr_drain_hook_arg = NULL;

	/*
	 * Decide whether to put the page header off page to avoid
	 * wasting too large a part of the page or too big item.
	 * Off-page page headers go on a hash table, so we can match
	 * a returned item with its header based on the page address.
	 * We use 1/16 of the page size and about 8 times of the item
	 * size as the threshold (XXX: tune)
	 *
	 * However, we'll put the header into the page if we can put
	 * it without wasting any items.
	 *
	 * Silently enforce `0 <= ioff < align'.
	 */
	pp->pr_itemoffset = ioff %= align;
	/* See the comment below about reserved bytes. */
	trysize = palloc->pa_pagesz - ((align - ioff) % align);
	phsize = ALIGN(sizeof(struct pool_item_header));
	if (pp->pr_roflags & PR_PHINPAGE ||
	    ((pp->pr_roflags & (PR_NOTOUCH | PR_NOALIGN)) == 0 &&
#ifdef __QNXNTO__
	    (pp->pr_roflags & PR_EXTRA) == 0 &&
#endif
	    (pp->pr_size < MIN(palloc->pa_pagesz / 16, phsize << 3) ||
	    trysize / pp->pr_size == (trysize - phsize) / pp->pr_size))) {
		/* Use the end of the page for the page header */
		pp->pr_roflags |= PR_PHINPAGE;
		pp->pr_phoffset = off = palloc->pa_pagesz - phsize;
	} else {
		/* The page header will be taken from our page header pool */
		pp->pr_phoffset = 0;
		off = palloc->pa_pagesz;
		SPLAY_INIT(&pp->pr_phtree);
	}

	/*
	 * Alignment is to take place at `ioff' within the item. This means
	 * we must reserve up to `align - 1' bytes on the page to allow
	 * appropriate positioning of each item.
	 */
	pp->pr_itemsperpage = (off - ((align - ioff) % align)) / pp->pr_size;
	KASSERT(pp->pr_itemsperpage != 0);
	if ((pp->pr_roflags & PR_NOTOUCH)) {
#ifndef __QNXNTO__
		int idx;

		for (idx = 0; pp->pr_itemsperpage > PHPOOL_FREELIST_NELEM(idx);
		    idx++) {
			/* nothing */
		}
		if (idx >= PHPOOL_MAX) {
			/*
			 * if you see this panic, consider to tweak
			 * PHPOOL_MAX and PHPOOL_FREELIST_NELEM.
			 */
			panic("%s: too large itemsperpage(%d) for PR_NOTOUCH",
			    pp->pr_wchan, pp->pr_itemsperpage);
		}
		pp->pr_phpool = &phpool[idx];
#else
		panic("pool_init: PR_NOTOUCH");
#endif
	} else if ((pp->pr_roflags & PR_PHINPAGE) == 0) {
		pp->pr_phpool = &phpool[0];
	}
#if defined(DIAGNOSTIC)
	else {
		pp->pr_phpool = NULL;
	}
#endif

	/*
	 * Use the slack between the chunks and the page header
	 * for "cache coloring".
	 */
	slack = off - pp->pr_itemsperpage * pp->pr_size;
	pp->pr_maxcolor = (slack / align) * align;
	pp->pr_curcolor = 0;

	pp->pr_nget = 0;
	pp->pr_nfail = 0;
	pp->pr_nput = 0;
	pp->pr_npagealloc = 0;
	pp->pr_npagefree = 0;
	pp->pr_hiwat = 0;
	pp->pr_nidle = 0;

#ifdef POOL_DIAGNOSTIC
	if (flags & PR_LOGGING) {
		if (kmem_map == NULL ||
		    (pp->pr_log = malloc(pool_logsize * sizeof(struct pool_log),
		     M_TEMP, M_NOWAIT)) == NULL)
			pp->pr_roflags &= ~PR_LOGGING;
		pp->pr_curlogentry = 0;
		pp->pr_logsize = pool_logsize;
	}
#endif

	pp->pr_entered_file = NULL;
	pp->pr_entered_line = 0;

#ifndef __QNXNTO__
	simple_lock_init(&pp->pr_slock);
#else
	if (flags & PR_PROTECT) {
		if (stk_ctl.iopkt->ex_init(&pp->pr_slock))
			panic("pool_init: ex_init");
	}
#endif

	/*
	 * Initialize private page header pool and cache magazine pool if we
	 * haven't done so yet.
	 * XXX LOCKING.
	 */
	if (phpool[0].pr_size == 0) {
#ifndef __QNXNTO__
		int idx;
		for (idx = 0; idx < PHPOOL_MAX; idx++) {
			static char phpool_names[PHPOOL_MAX][6+1+6+1];
			int nelem;
			size_t sz;

			nelem = PHPOOL_FREELIST_NELEM(idx);
			snprintf(phpool_names[idx], sizeof(phpool_names[idx]),
			    "phpool-%d", nelem);
			sz = sizeof(struct pool_item_header);
			if (nelem) {
				sz = PR_FREELIST_ALIGN(sz)
				    + nelem * sizeof(pool_item_freelist_t);
			}
			pool_init(&phpool[idx], sz, 0, 0, 0,
			    phpool_names[idx], &pool_allocator_meta);
		}
#else
		pool_init(&phpool[0], sizeof(struct pool_item_header), 0, 0,
		    0, "phpool-0", NULL);
#endif
#ifdef POOL_SUBPAGE
#ifndef __QNXNTO__
		pool_init(&psppool, POOL_SUBPAGE, POOL_SUBPAGE, 0,
		    PR_RECURSIVE, "psppool", &pool_allocator_meta);
#else
#error POOL_SUBPAGE needs work
#endif
#endif
#ifndef __QNXNTO__
		pool_init(&pcgpool, sizeof(struct pool_cache_group), 0, 0,
		    0, "pcgpool", &pool_allocator_meta);
#else
		pool_init(&pcgpool, sizeof(struct pool_cache_group), 0, 0,
		    PR_PROTECT | PR_PG_ARG, "pcgpool", NULL);
		pool_init(&phpool_extra_lock,
		    sizeof(struct pool_item_header) + PHEXTRA_SIZE,
		    0, 0, PR_PROTECT | PR_PG_ARG | PR_PHINPAGE, "phpool_extra_protect", NULL);
#endif
	}

#ifdef __QNXNTO__
	if ((pp->pr_roflags & PR_EXTRA) &&
	    (extra_size * pp->pr_itemsperpage != PHEXTRA_SIZE
	     || (pp->pr_roflags & PR_PHINPAGE))) {
		/*
		 * We multiplex the locking phpool but only
		 * expect one extra size (only mclpool usage).
		 * If this changes we'll have to initialize
		 * separate phpools.
		 */
		panic("unexpected pool extra");
	}

	if (pp->pr_roflags & PR_PHINPAGE)
		pp->pr_phpool = NULL;
	else {
		if ((pp->pr_roflags & (PR_PROTECT | PR_EXTRA)) == 0)
			pp->pr_phpool = &phpool[0];
		else
			pp->pr_phpool = &phpool_extra_lock;
	}
#endif
	/* Insert into the list of all pools. */
	simple_lock(&pool_head_slock);
	LIST_INSERT_HEAD(&pool_head, pp, pr_poollist);
	simple_unlock(&pool_head_slock);

	/* Insert this into the list of pools using this allocator. */
	s = splvm();
	simple_lock(&palloc->pa_slock);
	TAILQ_INSERT_TAIL(&palloc->pa_list, pp, pr_alloc_list);
	simple_unlock(&palloc->pa_slock);
	splx(s);
#ifndef __QNXNTO__
	pool_reclaim_register(pp);
#endif
}

/*
 * De-commision a pool resource.
 */
void
pool_destroy(struct pool *pp)
{
	struct pool_pagelist pq;
	struct pool_item_header *ph;
	int s;
#ifdef __QNXNTO__
	if (!ISSTACK)
		panic("pool_destroy: not stack");
#endif

	/* Remove from global pool list */
	simple_lock(&pool_head_slock);
	LIST_REMOVE(pp, pr_poollist);
	if (drainpp == pp)
		drainpp = NULL;
	simple_unlock(&pool_head_slock);

	/* Remove this pool from its allocator's list of pools. */
#ifndef __QNXNTO__
	pool_reclaim_unregister(pp);
#endif
	s = splvm();
	simple_lock(&pp->pr_alloc->pa_slock);
	TAILQ_REMOVE(&pp->pr_alloc->pa_list, pp, pr_alloc_list);
	simple_unlock(&pp->pr_alloc->pa_slock);
	splx(s);

	s = splvm();
	simple_lock(&pp->pr_slock);

	KASSERT(LIST_EMPTY(&pp->pr_cachelist));

#ifdef DIAGNOSTIC
	if (pp->pr_nout != 0) {
		pr_printlog(pp, NULL, printf);
		panic("pool_destroy: pool busy: still out: %u",
		    pp->pr_nout);
	}
#endif

	KASSERT(LIST_EMPTY(&pp->pr_fullpages));
	KASSERT(LIST_EMPTY(&pp->pr_partpages));

	/* Remove all pages */
	LIST_INIT(&pq);
	while ((ph = LIST_FIRST(&pp->pr_emptypages)) != NULL)
		pr_rmpage(pp, ph, &pq);

	simple_unlock(&pp->pr_slock);
	splx(s);

	pr_pagelist_free(pp, &pq);

#ifdef POOL_DIAGNOSTIC
	if ((pp->pr_roflags & PR_LOGGING) != 0)
		free(pp->pr_log, M_TEMP);
#endif
#ifdef __QNXNTO__
	if ((pp->pr_roflags & PR_PROTECT))
		stk_ctl.iopkt->ex_destroy(&pp->pr_slock);
#endif
}

void
pool_set_drain_hook(struct pool *pp, void (*fn)(void *, int), void *arg)
{

	/* XXX no locking -- must be used just after pool_init() */
#ifdef DIAGNOSTIC
	if (pp->pr_drain_hook != NULL)
		panic("pool_set_drain_hook(%s): already set", pp->pr_wchan);
#endif
	pp->pr_drain_hook = fn;
	pp->pr_drain_hook_arg = arg;
}

static struct pool_item_header *
pool_alloc_item_header(struct pool *pp, caddr_t storage, int flags)
{
	struct pool_item_header *ph;
	int s;

	LOCK_ASSERT(simple_lock_held(&pp->pr_slock) == 0);

	if ((pp->pr_roflags & PR_PHINPAGE) != 0)
		ph = (struct pool_item_header *) (storage + pp->pr_phoffset);
	else {
		s = splvm();
		ph = pool_get(pp->pr_phpool, flags);
		splx(s);
#ifdef __QNXNTO__
		/*
		 * If extra data is present, set the pointer and
		 * zero it out.
		 */
		if (pp->pr_roflags & PR_EXTRA) {
			s = pp->pr_phpool->pr_size - sizeof(*ph);
			ph->ph_pg.pg_extra = (void *)(ph + 1);
			memset(ph->ph_pg.pg_extra, 0x00, s);
		}
		else
			ph->ph_pg.pg_extra = NULL;
#endif
	}

	return (ph);
}

/*
 * Grab an item from the pool; must be called at appropriate spl level
 */
void *
#ifdef POOL_DIAGNOSTIC
#ifndef __QNXNTO__
_pool_get(struct pool *pp, int flags, const char *file, long line)
#else
_pool_get_header(struct pool *pp, int flags, struct page_extra **pg_in, const char *file, long line)
#endif
#else
#ifndef __QNXNTO__
pool_get(struct pool *pp, int flags)
#else
/*
 * pool_get requests for mbuf and cluster pools can be either M_WAIT
 * or M_NOWAIT translated to P_WAITOK flag at the pool level. ltsleep
 * can only be done if we are STACK context and not proc0. An alternative
 * of delay() cannot be done as we can block the stack context if proc0.
 * If M_WAIT is to be used, it cannot be in proc0. It is best to avoid
 * the M_WAIT concept and check for NULL in case of low memory conditions
 * as it is very difficult to determine if you fall under the valid
 * conditions. If M_WAIT is used outside of these conditions you will be
 * returned NULL if no memory is available.
 */

pool_get_header(struct pool *pp, int flags, struct page_extra **pg_in)
#endif
#endif
{
	struct pool_item *pi;
	struct pool_item_header *ph;
	void *v;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;

	KASSERT((pg_in == NULL && (pp->pr_roflags & PR_PG_ARG) == 0) ||
	    (pg_in != NULL && (pp->pr_roflags & PR_PG_ARG)));
#endif

#ifndef __QNXNTO__
#ifdef DIAGNOSTIC
	if (__predict_false(pp->pr_itemsperpage == 0))
		panic("pool_get: pool %p: pr_itemsperpage is zero, "
		    "pool not initialized?", pp);
	if (__predict_false(curlwp == NULL && doing_shutdown == 0 &&
			    (flags & PR_WAITOK) != 0))
		panic("pool_get: %s: must have NOWAIT", pp->pr_wchan);

#endif /* DIAGNOSTIC */
#ifdef LOCKDEBUG
	if (flags & PR_WAITOK)
		ASSERT_SLEEPABLE(NULL, "pool_get(PR_WAITOK)");
	SCHED_ASSERT_UNLOCKED();
#endif
#endif /* !__QNXNTO__ */

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	pr_enter(pp, file, line);

 startover:
	/*
	 * Check to see if we've reached the hard limit.  If we have,
	 * and we can wait, then wait until an item has been returned to
	 * the pool.
	 */
#ifdef DIAGNOSTIC
	if (__predict_false(pp->pr_nout > pp->pr_hardlimit)) {
		pr_leave(pp);
		POOL_UNLOCK(pp, &pp->pr_slock, wtp);
		panic("pool_get: %s: crossed hard limit", pp->pr_wchan);
	}
#endif
	if (__predict_false(pp->pr_nout == pp->pr_hardlimit)) {
		if (pp->pr_drain_hook != NULL) {
			/*
			 * Since the drain hook is going to free things
			 * back to the pool, unlock, call the hook, re-lock,
			 * and check the hardlimit condition again.
			 */
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			(*pp->pr_drain_hook)(pp->pr_drain_hook_arg, flags);
			POOL_LOCK(pp, &pp->pr_slock, wtp);
			pr_enter(pp, file, line);
			if (pp->pr_nout < pp->pr_hardlimit)
				goto startover;
		}
#ifndef __QNXNTO__
		if ((flags & PR_WAITOK) && !(flags & PR_LIMITFAIL)) {
#else
		/* It is unclear how PR_LIMITFAIL was intended to work.
		 * There is no counter associated with PR_LIMITFAIL, and
		 * if there was a limit, io-pkt would just fault as the
		 * code is not expecting an M_WAIT buffer allocation to
		 * return NULL.
		 * Some objects are allocated with both PR_WAITOK and
		 * PR_LIMITFAIL, this would just mean we do not wait forever
		 * and fault.
		 */
		if ((flags & PR_WAITOK) && ISSTACK && (curproc != stk_ctl.proc0)) {
#endif
			/*
			 * XXX: A warning isn't logged in this case.  Should
			 * it be?
			 */
			pp->pr_flags |= PR_WANTED;
			pr_leave(pp);
#ifndef __QNXNTO__
			ltsleep(pp, PSWP, pp->pr_wchan, 0, &pp->pr_slock);
#else
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			ltsleep(pp, PSWP, pp->pr_wchan, 0, NULL);
			wtp = WTP; /* reset after sleep */
			POOL_LOCK(pp, &pp->pr_slock, wtp);
#endif
			pr_enter(pp, file, line);
			goto startover;
		}

		/*
		 * Log a message that the hard limit has been hit.
		 */
		if (pp->pr_hardlimit_warning != NULL &&
		    ratecheck(&pp->pr_hardlimit_warning_last,
			      &pp->pr_hardlimit_ratecap))
			log(LOG_ERR, "%s\n", pp->pr_hardlimit_warning);

		pp->pr_nfail++;

		pr_leave(pp);
		POOL_UNLOCK(pp, &pp->pr_slock, wtp);
		return (NULL);
	}

	/*
	 * The convention we use is that if `curpage' is not NULL, then
	 * it points at a non-empty bucket. In particular, `curpage'
	 * never points at a page header which has PR_PHINPAGE set and
	 * has no items in its bucket.
	 */
	if ((ph = pp->pr_curpage) == NULL) {
		int error;

#ifdef DIAGNOSTIC
		if (pp->pr_nitems != 0) {
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			printf("pool_get: %s: curpage NULL, nitems %u\n",
			    pp->pr_wchan, pp->pr_nitems);
			panic("pool_get: nitems inconsistent");
		}
#endif

		/*
		 * Call the back-end page allocator for more memory.
		 * Release the pool lock, as the back-end page allocator
		 * may block.
		 */
		pr_leave(pp);
		error = pool_grow(pp, flags);
		pr_enter(pp, file, line);
		if (error != 0) {
			/*
			 * We were unable to allocate a page or item
			 * header, but we released the lock during
			 * allocation, so perhaps items were freed
			 * back to the pool.  Check for this case.
			 */
			if (pp->pr_curpage != NULL)
				goto startover;
#ifdef __QNXNTO__
			/* Flow through and return NULL if our conditions
			 * are not met.
			 */
			if ((flags & PR_WAITOK) && ISSTACK && (curproc != stk_ctl.proc0)) {
				/* PR_WANTED gives an indication to the
				 * pool cache layer that the pool layer
				 * wants its buffers back.
				 */
				pp->pr_flags |= PR_WANTED;
				pr_leave(pp);
				POOL_UNLOCK(pp, &pp->pr_slock, wtp);
				/* Timeout here for wakeup or system
				 * memory at 100 msec polling */
				ltsleep(pp, PSWP, pp->pr_wchan, (100 * hz) / 1000, NULL);
				wtp = WTP; /* reset after sleep */
				POOL_LOCK(pp, &pp->pr_slock, wtp);
				pr_enter(pp, file, line);

				goto startover;
			}
#endif
			pp->pr_nfail++;
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			return (NULL);
		}

		/* Start the allocation process over. */
		goto startover;
	}
#ifndef __QNXNTO__
	if (pp->pr_roflags & PR_NOTOUCH) {
#ifdef DIAGNOSTIC
		if (__predict_false(ph->ph_nmissing == pp->pr_itemsperpage)) {
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			panic("pool_get: %s: page empty", pp->pr_wchan);
		}
#endif
		v = pr_item_notouch_get(pp, ph);
#ifdef POOL_DIAGNOSTIC
		pr_log(pp, v, PRLOG_GET, file, line);
#endif
	} else {
#endif
		v = pi = LIST_FIRST(&ph->ph_itemlist);
		if (__predict_false(v == NULL)) {
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			panic("pool_get: %s: page empty", pp->pr_wchan);
		}
#ifdef DIAGNOSTIC
		if (__predict_false(pp->pr_nitems == 0)) {
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			printf("pool_get: %s: items on itemlist, nitems %u\n",
			    pp->pr_wchan, pp->pr_nitems);
			panic("pool_get: nitems inconsistent");
		}
#endif

#ifdef POOL_DIAGNOSTIC
		pr_log(pp, v, PRLOG_GET, file, line);
#endif

#ifdef DIAGNOSTIC
		if (__predict_false(pi->pi_magic != PI_MAGIC)) {
			pr_printlog(pp, pi, printf);
			panic("pool_get(%s): free list modified: "
			    "magic=%x; page %p; item addr %p\n",
			    pp->pr_wchan, pi->pi_magic, ph->ph_page, pi);
		}
#endif

		/*
		 * Remove from item list.
		 */
		LIST_REMOVE(pi, pi_list);
#ifndef __QNXNTO__
	}
#endif
	pp->pr_nitems--;
	pp->pr_nout++;
	if (ph->ph_nmissing == 0) {
#ifdef DIAGNOSTIC
		if (__predict_false(pp->pr_nidle == 0))
			panic("pool_get: nidle inconsistent");
#endif
		pp->pr_nidle--;

		/*
		 * This page was previously empty.  Move it to the list of
		 * partially-full pages.  This page is already curpage.
		 */
		LIST_REMOVE(ph, ph_pagelist);
		LIST_INSERT_HEAD(&pp->pr_partpages, ph, ph_pagelist);
	}
	ph->ph_nmissing++;
#ifdef __QNXNTO__
	if (pg_in != NULL)
		*pg_in = &ph->ph_pg;
#endif
	if (ph->ph_nmissing == pp->pr_itemsperpage) {
#ifdef DIAGNOSTIC
		if (__predict_false((pp->pr_roflags & PR_NOTOUCH) == 0 &&
		    !LIST_EMPTY(&ph->ph_itemlist))) {
			pr_leave(pp);
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			panic("pool_get: %s: nmissing inconsistent",
			    pp->pr_wchan);
		}
#endif
		/*
		 * This page is now full.  Move it to the full list
		 * and select a new current page.
		 */
		LIST_REMOVE(ph, ph_pagelist);
		LIST_INSERT_HEAD(&pp->pr_fullpages, ph, ph_pagelist);
		pool_update_curpage(pp);
	}

	pp->pr_nget++;
	pr_leave(pp);

	/*
	 * If we have a low water mark and we are now below that low
	 * water mark, add more items to the pool.
	 */
	if (POOL_NEEDS_CATCHUP(pp) && pool_catchup(pp) != 0) {
		/*
		 * XXX: Should we log a warning?  Should we set up a timeout
		 * to try again in a second or so?  The latter could break
		 * a caller's assumptions about interrupt protection, etc.
		 */
	}

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
	return (v);
}

/* Stack context callback function for wakeup of pseudo threads
 * waiting on available memory.
 */

#ifdef __QNXNTO__
static void pool_wakeup (void *arg)
{
	wakeup(arg);
}
#endif


/*
 * Internal version of pool_put().  Pool is already locked/entered.
 */
static void
#ifndef __QNXNTO__
pool_do_put(struct pool *pp, void *v, struct pool_pagelist *pq)
#else
pool_do_put(struct pool *pp, void *v, struct pool_pagelist *pq, struct page_extra *pg_in)
#endif
{
	struct pool_item *pi = v;
	struct pool_item_header *ph;

	LOCK_ASSERT(simple_lock_held(&pp->pr_slock));
	SCHED_ASSERT_UNLOCKED();

#ifdef DIAGNOSTIC
	if (__predict_false(pp->pr_nout == 0)) {
		printf("pool %s: putting with none out\n",
		    pp->pr_wchan);
		panic("pool_put");
	}
#endif

#ifdef __QNXNTO__
	KASSERT((pg_in == NULL && (pp->pr_roflags & PR_PG_ARG) == 0) ||
	    (pg_in != NULL && (pp->pr_roflags & PR_PG_ARG)));
	if (pg_in != NULL) {
		ph = PG_TO_PIH(pg_in);
		pp = ph->ph_pool;
	}
	else {
#endif
	if (__predict_false((ph = pr_find_pagehead(pp, v)) == NULL)) {
		pr_printlog(pp, NULL, printf);
		panic("pool_put: %s: page header missing", pp->pr_wchan);
	}
#ifdef __QNXNTO__
	}
#endif

#ifdef LOCKDEBUG
	/*
	 * Check if we're freeing a locked simple lock.
	 */
	simple_lock_freecheck((caddr_t)pi, ((caddr_t)pi) + pp->pr_size);
#endif

	/*
	 * Return to item list.
	 */
#ifndef __QNXNTO__
	if (pp->pr_roflags & PR_NOTOUCH) {
		pr_item_notouch_put(pp, ph, v);
	} else {
#endif
#ifdef DIAGNOSTIC
		pi->pi_magic = PI_MAGIC;
#endif
#ifdef DEBUG
		{
			int i, *ip = v;

			for (i = 0; i < pp->pr_size / sizeof(int); i++) {
				*ip++ = PI_MAGIC;
			}
		}
#endif

		LIST_INSERT_HEAD(&ph->ph_itemlist, pi, pi_list);
#ifndef __QNXNTO__
	}
#endif
	KDASSERT(ph->ph_nmissing != 0);
	ph->ph_nmissing--;
	pp->pr_nput++;
	pp->pr_nitems++;
	pp->pr_nout--;

	/* Cancel "pool empty" condition if it exists */
	if (pp->pr_curpage == NULL)
		pp->pr_curpage = ph;

#ifndef __QNXNTO__
	if (pp->pr_flags & PR_WANTED) {
		pp->pr_flags &= ~PR_WANTED;
		if (ph->ph_nmissing == 0)
			pp->pr_nidle++;
		wakeup((caddr_t)pp);
		return;
	}
#else
	if (pp->pr_flags & PR_WANTED) {
		struct nw_work_thread	*wtp = WTP;

		if(!ISIRUPT_P(wtp)) {
			pp->pr_flags &= ~PR_WANTED;
			if (ph->ph_nmissing == 0)
				pp->pr_nidle++;
			POOL_UNLOCK(pp, &pp->pr_slock, wtp);
			if (ISSTACK) {
				wakeup((caddr_t)pp);
			} else {
				/* Pool definitions are usually static
				 * structures and should always be present.
				 * If not, we cannot wait on it (PR_WANTED).
				 */
				stk_context_callback_2(pool_wakeup, pp, NULL);
			}
			POOL_LOCK(pp, &pp->pr_slock, wtp);
			return;
		}
	}
#endif

	/*
	 * If this page is now empty, do one of two things:
	 *
	 *	(1) If we have more pages than the page high water mark,
	 *	    free the page back to the system.  ONLY CONSIDER
	 *	    FREEING BACK A PAGE IF WE HAVE MORE THAN OUR MINIMUM PAGE
	 *	    CLAIM.
	 *
	 *	(2) Otherwise, move the page to the empty page list.
	 *
	 * Either way, select a new current page (so we use a partially-full
	 * page if one is available).
	 */
	if (ph->ph_nmissing == 0) {
		pp->pr_nidle++;
		if (pp->pr_npages > pp->pr_minpages &&
		    (pp->pr_npages > pp->pr_maxpages ||
		     pa_starved_p(pp->pr_alloc))) {
			pr_rmpage(pp, ph, pq);
		} else {
			LIST_REMOVE(ph, ph_pagelist);
			LIST_INSERT_HEAD(&pp->pr_emptypages, ph, ph_pagelist);

			/*
			 * Update the timestamp on the page.  A page must
			 * be idle for some period of time before it can
			 * be reclaimed by the pagedaemon.  This minimizes
			 * ping-pong'ing for memory.
			 */
			getmicrotime(&ph->ph_time);
		}
		pool_update_curpage(pp);
	}

	/*
	 * If the page was previously completely full, move it to the
	 * partially-full list and make it the current page.  The next
	 * allocation will get the item from this page, instead of
	 * further fragmenting the pool.
	 */
	else if (ph->ph_nmissing == (pp->pr_itemsperpage - 1)) {
		LIST_REMOVE(ph, ph_pagelist);
		LIST_INSERT_HEAD(&pp->pr_partpages, ph, ph_pagelist);
		pp->pr_curpage = ph;
	}
}

/*
 * Return resource to the pool; must be called at appropriate spl level
 */
#ifdef POOL_DIAGNOSTIC
#ifndef __QNXNTO__
void
_pool_put(struct pool *pp, void *v, const char *file, long line)
{
	struct pool_pagelist pq;

	LIST_INIT(&pq);

	simple_lock(&pp->pr_slock);
	pr_enter(pp, file, line);

	pr_log(pp, v, PRLOG_PUT, file, line);

	pool_do_put(pp, v, &pq);

	pr_leave(pp);
	simple_unlock(&pp->pr_slock);

	pr_pagelist_free(pp, &pq);
}
#else
void
_pool_put_header(struct pool *pp, void *v, struct page_extra *pg_in, const char *file, long line)
{
	struct pool_pagelist pq;
	struct nw_work_thread	*wtp;
	wtp = WTP;

	KASSERT((pg_in == NULL && (pp->pr_roflags & PR_PG_ARG) == 0) ||
	    (pg_in != NULL && (pp->pr_roflags & PR_PG_ARG)));

	LIST_INIT(&pq);

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	pr_enter(pp, file, line);

	pr_log(pp, v, PRLOG_PUT, file, line);

	pool_do_put(pp, v, &pq, pg_in);

	pr_leave(pp);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);

	if (! LIST_EMPTY(&pq))
		pr_pagelist_free(pp, &pq);
}
#endif
#undef pool_put
#endif /* POOL_DIAGNOSTIC */

#ifndef __QNXNTO__
void
pool_put(struct pool *pp, void *v)
{
	struct pool_pagelist pq;

	LIST_INIT(&pq);

	simple_lock(&pp->pr_slock);
	pool_do_put(pp, v, &pq);
	simple_unlock(&pp->pr_slock);

	pr_pagelist_free(pp, &pq);
}
#else
void
pool_put_header(struct pool *pp, void *v, struct page_extra *pg_in)
{
	struct nw_work_thread	*wtp;
	struct pool_pagelist pq;

	KASSERT((pg_in == NULL && (pp->pr_roflags & PR_PG_ARG) == 0) ||
	    (pg_in != NULL && (pp->pr_roflags & PR_PG_ARG)));

	LIST_INIT(&pq);

	wtp = WTP;

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	pool_do_put(pp, v, &pq, pg_in);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);

	if (! LIST_EMPTY(&pq))
		pr_pagelist_free(pp, &pq);
}
#endif

#ifdef POOL_DIAGNOSTIC
#define		pool_put(h, v)	_pool_put((h), (v), __FILE__, __LINE__)
#endif

/*
 * pool_grow: grow a pool by a page.
 *
 * => called with pool locked.
 * => unlock and relock the pool.
 * => return with pool locked.
 */

static int
pool_grow(struct pool *pp, int flags)
{
	struct pool_item_header *ph = NULL;
	char *cp;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
	cp = pool_allocator_alloc(pp, flags);
	if (__predict_true(cp != NULL)) {
		ph = pool_alloc_item_header(pp, cp, flags);
	}
	if (__predict_false(cp == NULL || ph == NULL)) {
		if (cp != NULL) {
			pool_allocator_free(pp, cp);
		}
		POOL_LOCK(pp, &pp->pr_slock,  wtp);
		return ENOMEM;
	}

	POOL_LOCK(pp, &pp->pr_slock,  wtp);
	pool_prime_page(pp, cp, ph);
	pp->pr_npagealloc++;
	return 0;
}

/*
 * Add N items to the pool.
 */
int
pool_prime(struct pool *pp, int n)
{
	int newpages;
	int error = 0;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	POOL_LOCK(pp, &pp->pr_slock,  wtp);

	newpages = roundup(n, pp->pr_itemsperpage) / pp->pr_itemsperpage;

	while (newpages-- > 0) {
		error = pool_grow(pp, PR_NOWAIT);
		if (error) {
			break;
		}
		pp->pr_minpages++;
	}

	if (pp->pr_minpages >= pp->pr_maxpages)
		pp->pr_maxpages = pp->pr_minpages + 1;	/* XXX */

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
	return error;
}

/*
 * Add a page worth of items to the pool.
 *
 * Note, we must be called with the pool descriptor LOCKED.
 */
static void
pool_prime_page(struct pool *pp, caddr_t storage, struct pool_item_header *ph)
{
	struct pool_item *pi;
	caddr_t cp = storage;
	unsigned int align = pp->pr_align;
	unsigned int ioff = pp->pr_itemoffset;
	int n;

	LOCK_ASSERT(simple_lock_held(&pp->pr_slock));

#ifdef DIAGNOSTIC
	if ((pp->pr_roflags & PR_NOALIGN) == 0 &&
	    ((uintptr_t)cp & (pp->pr_alloc->pa_pagesz - 1)) != 0)
		panic("pool_prime_page: %s: unaligned page", pp->pr_wchan);
#endif

	/*
	 * Insert page header.
	 */
	LIST_INSERT_HEAD(&pp->pr_emptypages, ph, ph_pagelist);
	LIST_INIT(&ph->ph_itemlist);
	ph->ph_page = storage;
	ph->ph_nmissing = 0;
#ifdef __QNXNTO__
	if ((pp->pr_roflags & PR_PHYS) != 0) {
		if (pp->pr_typed_mem_fd == NOFD) {
			mem_offset64(storage, NOFD, 1, &ph->ph_pg.pg_phys, 0);
		}
		else {
			posix_mem_offset64(storage, pp->pr_alloc->pa_pagesz, &ph->ph_pg.pg_phys,
			    NULL, NULL);
		}
	}
	ph->ph_pool = pp;
#endif
	getmicrotime(&ph->ph_time);
	if ((pp->pr_roflags & PR_PHINPAGE) == 0)
		SPLAY_INSERT(phtree, &pp->pr_phtree, ph);

	pp->pr_nidle++;

	/*
	 * Color this page.
	 */
	cp = (caddr_t)(cp + pp->pr_curcolor);
	if ((pp->pr_curcolor += align) > pp->pr_maxcolor)
		pp->pr_curcolor = 0;

	/*
	 * Adjust storage to apply aligment to `pr_itemoffset' in each item.
	 */
	if (ioff != 0)
		cp = (caddr_t)(cp + (align - ioff));

	/*
	 * Insert remaining chunks on the bucket list.
	 */
	n = pp->pr_itemsperpage;
	pp->pr_nitems += n;

#ifndef __QNXNTO__
	if (pp->pr_roflags & PR_NOTOUCH) {
		pool_item_freelist_t *freelist = PR_FREELIST(ph);
		int i;

		ph->ph_off = cp - storage;
		ph->ph_firstfree = 0;
		for (i = 0; i < n - 1; i++)
			freelist[i] = i + 1;
		freelist[n - 1] = PR_INDEX_EOL;
	} else {
#endif
		while (n--) {
			pi = (struct pool_item *)cp;

			KASSERT(((((vaddr_t)pi) + ioff) & (align - 1)) == 0);

			/* Insert on page list */
			LIST_INSERT_HEAD(&ph->ph_itemlist, pi, pi_list);
#ifdef DIAGNOSTIC
			pi->pi_magic = PI_MAGIC;
#endif
			cp = (caddr_t)(cp + pp->pr_size);
		}
#ifndef __QNXNTO__
	}
#endif

	/*
	 * If the pool was depleted, point at the new page.
	 */
	if (pp->pr_curpage == NULL)
		pp->pr_curpage = ph;

	if (++pp->pr_npages > pp->pr_hiwat)
		pp->pr_hiwat = pp->pr_npages;
}

/*
 * Used by pool_get() when nitems drops below the low water mark.  This
 * is used to catch up pr_nitems with the low water mark.
 *
 * Note 1, we never wait for memory here, we let the caller decide what to do.
 *
 * Note 2, we must be called with the pool already locked, and we return
 * with it locked.
 */
static int
pool_catchup(struct pool *pp)
{
	int error = 0;

	while (POOL_NEEDS_CATCHUP(pp)) {
		error = pool_grow(pp, PR_NOWAIT);
		if (error) {
			break;
		}
	}
	return error;
}

static void
pool_update_curpage(struct pool *pp)
{

	pp->pr_curpage = LIST_FIRST(&pp->pr_partpages);
	if (pp->pr_curpage == NULL) {
		pp->pr_curpage = LIST_FIRST(&pp->pr_emptypages);
	}
}

void
pool_setlowat(struct pool *pp, int n)
{

#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	POOL_LOCK(pp, &pp->pr_slock, wtp);

	pp->pr_minitems = n;
	pp->pr_minpages = (n == 0)
		? 0
		: roundup(n, pp->pr_itemsperpage) / pp->pr_itemsperpage;

	/* Make sure we're caught up with the newly-set low water mark. */
	if (POOL_NEEDS_CATCHUP(pp) && pool_catchup(pp) != 0) {
		/*
		 * XXX: Should we log a warning?  Should we set up a timeout
		 * to try again in a second or so?  The latter could break
		 * a caller's assumptions about interrupt protection, etc.
		 */
	}

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
}

void
pool_sethiwat(struct pool *pp, int n)
{
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	POOL_LOCK(pp, &pp->pr_slock, wtp);

	pp->pr_maxpages = (n == 0)
		? 0
		: roundup(n, pp->pr_itemsperpage) / pp->pr_itemsperpage;

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
}

void
pool_sethardlimit(struct pool *pp, int n, const char *warnmess, int ratecap)
{

#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif
	POOL_LOCK(pp, &pp->pr_slock, wtp);

	pp->pr_hardlimit = n;
	pp->pr_hardlimit_warning = warnmess;
	pp->pr_hardlimit_ratecap.tv_sec = ratecap;
	pp->pr_hardlimit_warning_last.tv_sec = 0;
	pp->pr_hardlimit_warning_last.tv_usec = 0;

	/*
	 * In-line version of pool_sethiwat(), because we don't want to
	 * release the lock.
	 */
	pp->pr_maxpages = (n == 0)
		? 0
		: roundup(n, pp->pr_itemsperpage) / pp->pr_itemsperpage;

	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
}

/*
 * Release all complete pages that have not been used recently.
 */
int
#ifdef POOL_DIAGNOSTIC
_pool_reclaim(struct pool *pp, const char *file, long line)
#else
pool_reclaim(struct pool *pp)
#endif
{
	struct pool_item_header *ph, *phnext;
	struct pool_cache *pc;
	struct pool_pagelist pq;
	struct pool_cache_grouplist pcgl;
	struct timeval curtime, diff;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	if (pp->pr_drain_hook != NULL) {
		/*
		 * The drain hook must be called with the pool unlocked.
		 */
		(*pp->pr_drain_hook)(pp->pr_drain_hook_arg, PR_NOWAIT);
	}

#ifndef __QNXNTO__
	if (simple_lock_try(&pp->pr_slock) == 0)
		return (0);
#else
	POOL_LOCK(pp, &pp->pr_slock, wtp);
#endif
	pr_enter(pp, file, line);

	LIST_INIT(&pq);
	LIST_INIT(&pcgl);

	/*
	 * Reclaim items from the pool's caches.
	 */
	LIST_FOREACH(pc, &pp->pr_cachelist, pc_poollist)
		pool_cache_reclaim(pc, &pq, &pcgl);

	getmicrotime(&curtime);

	for (ph = LIST_FIRST(&pp->pr_emptypages); ph != NULL; ph = phnext) {
		phnext = LIST_NEXT(ph, ph_pagelist);

		/* Check our minimum page claim */
		if (pp->pr_npages <= pp->pr_minpages)
			break;

		KASSERT(ph->ph_nmissing == 0);
		timersub(&curtime, &ph->ph_time, &diff);
		if (diff.tv_sec < pool_inactive_time
		    && !pa_starved_p(pp->pr_alloc))
			continue;

		/*
		 * If freeing this page would put us below
		 * the low water mark, stop now.
		 */
		if ((pp->pr_nitems - pp->pr_itemsperpage) <
		    pp->pr_minitems)
			break;

		pr_rmpage(pp, ph, &pq);
	}

	pr_leave(pp);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
	if (LIST_EMPTY(&pq) && LIST_EMPTY(&pcgl))
		return 0;

	pr_pagelist_free(pp, &pq);
	pcg_grouplist_free(&pcgl);
	return (1);
}

/*
 * Drain pools, one at a time.
 *
 * Note, we must never be called from an interrupt context.
 */
void
pool_drain(void *arg)
{
	struct pool *pp;
	int s;

#ifdef __QNXNTO__
	/*
	 * Must be stack since simple_lock()
	 * below is a no-op
	 */

	if (!ISSTACK)
		panic("pool_drain: not stack");
#endif

	pp = NULL;
	s = splvm();
	simple_lock(&pool_head_slock);
	if (drainpp == NULL) {
		drainpp = LIST_FIRST(&pool_head);
	}
	if (drainpp) {
		pp = drainpp;
		drainpp = LIST_NEXT(pp, pr_poollist);
	}
	simple_unlock(&pool_head_slock);
	if (pp)
		pool_reclaim(pp);
	splx(s);
}

/*
 * Diagnostic helpers.
 */
void
pool_print(struct pool *pp, const char *modif)
{
#ifndef __QNXNTO__
	int s;

	s = splvm();
	if (simple_lock_try(&pp->pr_slock) == 0) {
		printf("pool %s is locked; try again later\n",
		    pp->pr_wchan);
		splx(s);
		return;
	}
	pool_print1(pp, modif, printf);
	simple_unlock(&pp->pr_slock);
	splx(s);
#else
	struct nw_work_thread *wtp = WTP;

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	pool_print1(pp, modif, printf);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
#endif
}

void
#ifndef __QNXNTO__
pool_printall(const char *modif, void (*pr)(const char *, ...))
#else
pool_printall(const char *modif, int (*pr)(const char *, ...))
#endif
{
	struct pool *pp;

#ifndef __QNXNTO__
	if (simple_lock_try(&pool_head_slock) == 0) {
		(*pr)("WARNING: pool_head_slock is locked\n");
	} else {
		simple_unlock(&pool_head_slock);
	}
#endif


	LIST_FOREACH(pp, &pool_head, pr_poollist) {
		pool_printit(pp, modif, pr);
	}
}

void
#ifndef __QNXNTO__
pool_printit(struct pool *pp, const char *modif, void (*pr)(const char *, ...))
#else
pool_printit(struct pool *pp, const char *modif, int (*pr)(const char *, ...))
#endif
{
#ifndef __QNXNTO__
	int didlock = 0;
#else
	struct nw_work_thread *wtp = WTP;
#endif

	if (pp == NULL) {
		(*pr)("Must specify a pool to print.\n");
		return;
	}

	/*
	 * Called from DDB; interrupts should be blocked, and all
	 * other processors should be paused.  We can skip locking
	 * the pool in this case.
	 *
	 * We do a simple_lock_try() just to print the lock
	 * status, however.
	 */

#ifndef __QNXNTO__
	if (simple_lock_try(&pp->pr_slock) == 0)
		(*pr)("WARNING: pool %s is locked\n", pp->pr_wchan);
	else
		simple_unlock(&pp->pr_slock);

	pool_print1(pp, modif, pr);
#else
	POOL_LOCK(pp, &pp->pr_slock, wtp);
	pool_print1(pp, modif, pr);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
#endif
}

static void
#ifndef __QNXNTO__
pool_print_pagelist(struct pool *pp, struct pool_pagelist *pl,
    void (*pr)(const char *, ...))
#else
pool_print_pagelist(struct pool *pp, struct pool_pagelist *pl,
    int (*pr)(const char *, ...))
#endif
{
	struct pool_item_header *ph;
#ifdef DIAGNOSTIC
	struct pool_item *pi;
#endif

	LIST_FOREACH(ph, pl, ph_pagelist) {
		(*pr)("\t\tpage %p, nmissing %d, time %lu,%lu\n",
		    ph->ph_page, ph->ph_nmissing,
		    (u_long)ph->ph_time.tv_sec,
		    (u_long)ph->ph_time.tv_usec);
#ifdef DIAGNOSTIC
		if (!(pp->pr_roflags & PR_NOTOUCH)) {
			LIST_FOREACH(pi, &ph->ph_itemlist, pi_list) {
				if (pi->pi_magic != PI_MAGIC) {
					(*pr)("\t\t\titem %p, magic 0x%x\n",
					    pi, pi->pi_magic);
				}
			}
		}
#endif
	}
}

static void
#ifndef __QNXNTO__
pool_print1(struct pool *pp, const char *modif, void (*pr)(const char *, ...))
#else
pool_print1(struct pool *pp, const char *modif, int (*pr)(const char *, ...))
#endif
{
	struct pool_item_header *ph;
	struct pool_cache *pc;
	struct pool_cache_group *pcg;
	int i, print_log = 0, print_pagelist = 0, print_cache = 0;
	char c;

	while ((c = *modif++) != '\0') {
		if (c == 'l')
			print_log = 1;
		if (c == 'p')
			print_pagelist = 1;
		if (c == 'c')
			print_cache = 1;
	}

	(*pr)("POOL %s: size %u, align %u, ioff %u, roflags 0x%08x\n",
	    pp->pr_wchan, pp->pr_size, pp->pr_align, pp->pr_itemoffset,
	    pp->pr_roflags);
	(*pr)("\talloc %p\n", pp->pr_alloc);
	(*pr)("\tminitems %u, minpages %u, maxpages %u, npages %u\n",
	    pp->pr_minitems, pp->pr_minpages, pp->pr_maxpages, pp->pr_npages);
	(*pr)("\titemsperpage %u, nitems %u, nout %u, hardlimit %u\n",
	    pp->pr_itemsperpage, pp->pr_nitems, pp->pr_nout, pp->pr_hardlimit);

	(*pr)("\n\tnget %lu, nfail %lu, nput %lu\n",
	    pp->pr_nget, pp->pr_nfail, pp->pr_nput);
	(*pr)("\tnpagealloc %lu, npagefree %lu, hiwat %u, nidle %lu\n",
	    pp->pr_npagealloc, pp->pr_npagefree, pp->pr_hiwat, pp->pr_nidle);

	if (print_pagelist == 0)
		goto skip_pagelist;

	if ((ph = LIST_FIRST(&pp->pr_emptypages)) != NULL)
		(*pr)("\n\tempty page list:\n");
	pool_print_pagelist(pp, &pp->pr_emptypages, pr);
	if ((ph = LIST_FIRST(&pp->pr_fullpages)) != NULL)
		(*pr)("\n\tfull page list:\n");
	pool_print_pagelist(pp, &pp->pr_fullpages, pr);
	if ((ph = LIST_FIRST(&pp->pr_partpages)) != NULL)
		(*pr)("\n\tpartial-page list:\n");
	pool_print_pagelist(pp, &pp->pr_partpages, pr);

	if (pp->pr_curpage == NULL)
		(*pr)("\tno current page\n");
	else
		(*pr)("\tcurpage %p\n", pp->pr_curpage->ph_page);

 skip_pagelist:
	if (print_log == 0)
		goto skip_log;

	(*pr)("\n");
	if ((pp->pr_roflags & PR_LOGGING) == 0)
		(*pr)("\tno log\n");
	else {
		pr_printlog(pp, NULL, pr);
	}

 skip_log:
	if (print_cache == 0)
		goto skip_cache;

#ifndef __QNXNTO__
#define PR_GROUPLIST(pcg)						\
	(*pr)("\t\tgroup %p: avail %d\n", pcg, pcg->pcg_avail);		\
	for (i = 0; i < PCG_NOBJECTS; i++) {				\
		if (pcg->pcg_objects[i].pcgo_pa !=			\
		    POOL_PADDR_INVALID) {				\
			(*pr)("\t\t\t%p, 0x%llx\n",			\
			    pcg->pcg_objects[i].pcgo_va,		\
			    (unsigned long long)			\
			    pcg->pcg_objects[i].pcgo_pa);		\
		} else {						\
			(*pr)("\t\t\t%p\n",				\
			    pcg->pcg_objects[i].pcgo_va);		\
		}							\
	}
#else
#define PR_GROUPLIST(pcg)						\
	(*pr)("\t\tgroup %p: avail %d\n", pcg, pcg->pcg_avail);		\
	for (i = 0; i < PCG_NOBJECTS; i++) {				\
			(*pr)("\t\t\t%p\n",				\
			    pcg->pcg_objects[i].pcgo_va);		\
	}
#endif

	LIST_FOREACH(pc, &pp->pr_cachelist, pc_poollist) {
		(*pr)("\tcache %p\n", pc);
		(*pr)("\t    hits %lu misses %lu ngroups %lu nitems %lu\n",
		    pc->pc_hits, pc->pc_misses, pc->pc_ngroups, pc->pc_nitems);
		(*pr)("\t    full groups:\n");
		LIST_FOREACH(pcg, &pc->pc_fullgroups, pcg_list) {
			PR_GROUPLIST(pcg);
		}
		(*pr)("\t    partial groups:\n");
		LIST_FOREACH(pcg, &pc->pc_partgroups, pcg_list) {
			PR_GROUPLIST(pcg);
		}
		(*pr)("\t    empty groups:\n");
		LIST_FOREACH(pcg, &pc->pc_emptygroups, pcg_list) {
			PR_GROUPLIST(pcg);
		}
	}
#undef PR_GROUPLIST

 skip_cache:
	pr_enter_check(pp, pr);
}

static int
pool_chk_page(struct pool *pp, const char *label, struct pool_item_header *ph)
{
	struct pool_item *pi;
	caddr_t page;
	int n;

	if ((pp->pr_roflags & PR_NOALIGN) == 0) {
		page = (caddr_t)((uintptr_t)ph & pp->pr_alloc->pa_pagemask);
		if (page != ph->ph_page &&
		    (pp->pr_roflags & PR_PHINPAGE) != 0) {
			if (label != NULL)
				printf("%s: ", label);
			printf("pool(%p:%s): page inconsistency: page %p;"
			       " at page head addr %p (p %p)\n", pp,
				pp->pr_wchan, ph->ph_page,
				ph, page);
			return 1;
		}
	}

	if ((pp->pr_roflags & PR_NOTOUCH) != 0)
		return 0;

	for (pi = LIST_FIRST(&ph->ph_itemlist), n = 0;
	     pi != NULL;
	     pi = LIST_NEXT(pi,pi_list), n++) {

#ifdef DIAGNOSTIC
		if (pi->pi_magic != PI_MAGIC) {
			if (label != NULL)
				printf("%s: ", label);
			printf("pool(%s): free list modified: magic=%x;"
			       " page %p; item ordinal %d; addr %p\n",
				pp->pr_wchan, pi->pi_magic, ph->ph_page,
				n, pi);
			panic("pool");
		}
#endif
		if ((pp->pr_roflags & PR_NOALIGN) != 0) {
			continue;
		}
		page = (caddr_t)((uintptr_t)pi & pp->pr_alloc->pa_pagemask);
		if (page == ph->ph_page)
			continue;

		if (label != NULL)
			printf("%s: ", label);
		printf("pool(%p:%s): page inconsistency: page %p;"
		       " item ordinal %d; addr %p (p %p)\n", pp,
			pp->pr_wchan, ph->ph_page,
			n, pi, page);
		return 1;
	}
	return 0;
}


int
pool_chk(struct pool *pp, const char *label)
{
	struct pool_item_header *ph;
	int r = 0;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	LIST_FOREACH(ph, &pp->pr_emptypages, ph_pagelist) {
		r = pool_chk_page(pp, label, ph);
		if (r) {
			goto out;
		}
	}
	LIST_FOREACH(ph, &pp->pr_fullpages, ph_pagelist) {
		r = pool_chk_page(pp, label, ph);
		if (r) {
			goto out;
		}
	}
	LIST_FOREACH(ph, &pp->pr_partpages, ph_pagelist) {
		r = pool_chk_page(pp, label, ph);
		if (r) {
			goto out;
		}
	}

out:
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
	return (r);
}

/*
 * pool_cache_init:
 *
 *	Initialize a pool cache.
 *
 *	NOTE: If the pool must be protected from interrupts, we expect
 *	to be called at the appropriate interrupt priority level.
 */
void
pool_cache_init(struct pool_cache *pc, struct pool *pp,
    int (*ctor)(void *, void *, int),
    void (*dtor)(void *, void *),
    void *arg)
{
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	LIST_INIT(&pc->pc_emptygroups);
	LIST_INIT(&pc->pc_fullgroups);
	LIST_INIT(&pc->pc_partgroups);
#ifndef __QNXNTO__
	simple_lock_init(&pc->pc_slock);

#else
	if (iopkt_selfp->ex_init(&pc->pc_slock)) {
		panic("pool_cache_init: ex_init");
	}
	if (((pp)->pr_roflags & PR_PROTECT) == 0) {
		log(LOG_WARNING, "pool_cache_init: redundant locking?\n");
	}
#endif
	pc->pc_pool = pp;

	pc->pc_ctor = ctor;
	pc->pc_dtor = dtor;
	pc->pc_arg  = arg;

	pc->pc_hits   = 0;
	pc->pc_misses = 0;

	pc->pc_ngroups = 0;

	pc->pc_nitems = 0;

	POOL_LOCK(pp, &pp->pr_slock, wtp);
	LIST_INSERT_HEAD(&pp->pr_cachelist, pc, pc_poollist);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);
}

/*
 * pool_cache_destroy:
 *
 *	Destroy a pool cache.
 */
void
pool_cache_destroy(struct pool_cache *pc)
{
	struct pool *pp = pc->pc_pool;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	/* First, invalidate the entire cache. */
	pool_cache_invalidate(pc);

	/* ...and remove it from the pool's cache list. */
	POOL_LOCK(pp, &pp->pr_slock, wtp);
	LIST_REMOVE(pc, pc_poollist);
	POOL_UNLOCK(pp, &pp->pr_slock, wtp);

#ifdef __QNXNTO__
	stk_ctl.iopkt->ex_destroy(&pc->pc_slock);
#endif
}

static inline void *
#ifndef __QNXNTO__
pcg_get(struct pool_cache_group *pcg, paddr_t *pap)
#else
pcg_get(struct pool_cache_group *pcg)
#endif
{
	void *object;
	u_int idx;

	KASSERT(pcg->pcg_avail <= PCG_NOBJECTS);
	KASSERT(pcg->pcg_avail != 0);
	idx = --pcg->pcg_avail;

	KASSERT(pcg->pcg_objects[idx].pcgo_va != NULL);
	object = pcg->pcg_objects[idx].pcgo_va;
#ifndef __QNXNTO__
	if (pap != NULL)
		*pap = pcg->pcg_objects[idx].pcgo_pa;
#endif
	pcg->pcg_objects[idx].pcgo_va = NULL;

	return (object);
}

static inline void
#ifndef __QNXNTO__
pcg_put(struct pool_cache_group *pcg, void *object, paddr_t pa)
#else
pcg_put(struct pool_cache_group *pcg, void *object)
#endif
{
	u_int idx;

	KASSERT(pcg->pcg_avail < PCG_NOBJECTS);
	idx = pcg->pcg_avail++;

	KASSERT(pcg->pcg_objects[idx].pcgo_va == NULL);
	pcg->pcg_objects[idx].pcgo_va = object;
#ifndef __QNXNTO__
	pcg->pcg_objects[idx].pcgo_pa = pa;
#endif
}

static void
pcg_grouplist_free(struct pool_cache_grouplist *pcgl)
{
	struct pool_cache_group *pcg;
	int s;

	s = splvm();
	while ((pcg = LIST_FIRST(pcgl)) != NULL) {
		LIST_REMOVE(pcg, pcg_list);
		pool_put(&pcgpool, pcg);
	}
	splx(s);
}

/*
 * pool_cache_get{,_paddr}:
 *
 *	Get an object from a pool cache (optionally returning
 *	the physical address of the object).
 */
void *
#ifndef __QNXNTO__
pool_cache_get_paddr(struct pool_cache *pc, int flags, paddr_t *pap)
#else
pool_cache_get_header(struct pool_cache *pc, int flags, struct page_extra **pg_in, struct nw_work_thread **wtpp)
#endif
{
	struct pool_cache_group *pcg;
	void *object;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;

	KASSERT((pg_in == NULL && (pc->pc_pool->pr_roflags & PR_PG_ARG) == 0) ||
	    (pg_in != NULL && (pc->pc_pool->pr_roflags & PR_PG_ARG)));
#endif

#ifdef LOCKDEBUG
	if (flags & PR_WAITOK)
		ASSERT_SLEEPABLE(NULL, "pool_cache_get(PR_WAITOK)");
#endif

#ifndef __QNXNTO__
	simple_lock(&pc->pc_slock);

	pcg = LIST_FIRST(&pc->pc_partgroups);
	if (pcg == NULL) {
		pcg = LIST_FIRST(&pc->pc_fullgroups);
		if (pcg != NULL) {
			LIST_REMOVE(pcg, pcg_list);
			LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);
		}
	}
	if (pcg == NULL) {

		/*
		 * No groups with any available objects.  Allocate
		 * a new object, construct it, and return it to
		 * the caller.  We will allocate a group, if necessary,
		 * when the object is freed back to the cache.
		 */
		pc->pc_misses++;
		simple_unlock(&pc->pc_slock);
		object = pool_get(pc->pc_pool, flags);
		if (object != NULL && pc->pc_ctor != NULL) {
			if ((*pc->pc_ctor)(pc->pc_arg, object, flags) != 0) {
				pool_put(pc->pc_pool, object);
				return (NULL);
			}
		}
		if (object != NULL && pap != NULL) {
#ifdef POOL_VTOPHYS
			*pap = POOL_VTOPHYS(object);
#else
			*pap = POOL_PADDR_INVALID;
#endif
		}
		return (object);
	}

#else
	/*
	 * We expect the signal to be held at the time of the call, therefore
	 * only NW_EX_LK is required rather than the expected NW_SIGLOCK_P.
	 */
#ifdef DIAGNOSTIC
	if (wtp->wt_critical == 0)
		panic("pool_cache_get_header");
#endif
	NW_EX_LK(&pc->pc_slock, iopkt_selfp);
	pcg = LIST_FIRST(&pc->pc_partgroups);
	if (pcg == NULL) {
		pcg = LIST_FIRST(&pc->pc_fullgroups);
		if (pcg != NULL) {
			LIST_REMOVE(pcg, pcg_list);
			LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);
		}
	}
	if (pcg == NULL) {
		/*
		 * No groups with any available objects.  Allocate
		 * a new object, construct it, and return it to
		 * the caller.  We will allocate a group, if necessary,
		 * when the object is freed back to the cache.
		 */
		pc->pc_misses++;

		NW_SIGUNLOCK_P(&pc->pc_slock, iopkt_selfp, wtp);

		object = pool_get_header(pc->pc_pool, flags, pg_in);
		/*
		 * Need to reset and return out wtp in case
		 * we blocked and migrated threads.
		 */
		wtp = WTP;
		*wtpp = wtp;
		if (object != NULL && pc->pc_ctor != NULL) {
			if ((*pc->pc_ctor)(pc->pc_arg, object, flags) != 0) {
				pool_put_header(pc->pc_pool, object, *pg_in);
				return (NULL);
			}
		}
		return (object);
	}
#endif
	pc->pc_hits++;
	pc->pc_nitems--;
#ifndef __QNXNTO__
	object = pcg_get(pcg, pap);

	if (pcg->pcg_avail == 0) {
		LIST_REMOVE(pcg, pcg_list);
		LIST_INSERT_HEAD(&pc->pc_emptygroups, pcg, pcg_list);
	}
	simple_unlock(&pc->pc_slock);
#else
	object = pcg_get(pcg);
	*pg_in = *((struct page_extra **)object);

	if (pcg->pcg_avail == 0) {
		LIST_REMOVE(pcg, pcg_list);
		LIST_INSERT_HEAD(&pc->pc_emptygroups, pcg, pcg_list);
	}

	NW_SIGUNLOCK_P(&pc->pc_slock, iopkt_selfp, wtp);
#endif

	return (object);
}

/*
 * pool_cache_put{,_paddr}:
 *
 *	Put an object back to the pool cache (optionally caching the
 *	physical address of the object).
 */
void
#ifndef __QNXNTO__
pool_cache_put_paddr(struct pool_cache *pc, void *object, paddr_t pa)
#else
pool_cache_put_header(struct pool_cache *pc, void *object, struct page_extra *pg_in,
    struct nw_work_thread *wtp)
#endif
{
	struct pool_cache_group *pcg;
	int s;
#ifndef __QNXNTO__

	if (__predict_false((pc->pc_pool->pr_flags & PR_WANTED) != 0)) {
		goto destruct;
	}

	simple_lock(&pc->pc_slock);

	pcg = LIST_FIRST(&pc->pc_partgroups);
	if (pcg == NULL) {
		pcg = LIST_FIRST(&pc->pc_emptygroups);
		if (pcg != NULL) {
			LIST_REMOVE(pcg, pcg_list);
			LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);
		}
	}
	if (pcg == NULL) {

		/*
		 * No empty groups to free the object to.  Attempt to
		 * allocate one.
		 */
		simple_unlock(&pc->pc_slock);
		s = splvm();
		pcg = pool_get(&pcgpool, PR_NOWAIT);
		splx(s);
		if (pcg == NULL) {
destruct:

			/*
			 * Unable to allocate a cache group; destruct the object
			 * and free it back to the pool.
			 */
			pool_cache_destruct_object(pc, object);
			return;
		}
		memset(pcg, 0, sizeof(*pcg));
		simple_lock(&pc->pc_slock);
		pc->pc_ngroups++;
		LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);
	}

#else
        struct page_extra *pcg_page;
        struct pool_item_header *ph_in = PG_TO_PIH(pg_in);

        if (__predict_false((pc->pc_pool->pr_flags & PR_WANTED) != 0)) {
                /* NW_SIGHOLD_P set at the mbuf allocation level */
                NW_SIGUNHOLD_P(wtp);
                goto destruct;
        }

	/*
	 * We expect the signal to be held at the time of the call, therefore
	 * only NW_EX_LK is required rather than the expected NW_SIGLOCK_P.
	 */
#ifdef DIAGNOSTIC
	if (wtp->wt_critical == 0)
		panic("pool_cache_put_header");
#endif
	NW_EX_LK(&pc->pc_slock, iopkt_selfp);

	pcg = LIST_FIRST(&pc->pc_partgroups);
	if (pcg == NULL) {
		pcg = LIST_FIRST(&pc->pc_emptygroups);
		if (pcg != NULL) {
			LIST_REMOVE(pcg, pcg_list);
			LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);
		}
	}
	if (pcg == NULL) {
		/*
		 * No empty groups to free the object to.  Attempt to
		 * allocate one.
		 */
		NW_SIGUNLOCK_P(&pc->pc_slock, iopkt_selfp, wtp);

		s = splvm();
		/* NOWAIT so we know our wtp is always consistent */
		pcg = pool_get_header(&pcgpool, PR_NOWAIT, &pcg_page);
		splx(s);
		if (pcg == NULL) {
destruct:
			/*
			 * Unable to allocate a cache group; destruct the object
			 * and free it back to the pool.
			 */
			pool_cache_destruct_object_header(pc, object, ph_in);
			return;
		}

		memset(pcg, 0, sizeof(*pcg));

		pcg->pcg_pool_hd = PG_TO_PIH(pcg_page);

		NW_SIGLOCK_P(&pc->pc_slock, iopkt_selfp, wtp);

		pc->pc_ngroups++;
		LIST_INSERT_HEAD(&pc->pc_partgroups, pcg, pcg_list);

	}
#endif
	pc->pc_nitems++;
#ifndef __QNXNTO__
	pcg_put(pcg, object, pa);

	if (pcg->pcg_avail == PCG_NOBJECTS) {
		LIST_REMOVE(pcg, pcg_list);
		LIST_INSERT_HEAD(&pc->pc_fullgroups, pcg, pcg_list);
	}
	simple_unlock(&pc->pc_slock);
#else
	*((struct page_extra **)object) = pg_in;
	pcg_put(pcg, object);

	if (pcg->pcg_avail == PCG_NOBJECTS) {
		LIST_REMOVE(pcg, pcg_list);
		LIST_INSERT_HEAD(&pc->pc_fullgroups, pcg, pcg_list);
	}

	NW_SIGUNLOCK_P(&pc->pc_slock, iopkt_selfp, wtp);
#endif
}

/*
 * pool_cache_destruct_object:
 *
 *	Force destruction of an object and its release back into
 *	the pool.
 */
void
#ifndef __QNXNTO__
pool_cache_destruct_object(struct pool_cache *pc, void *object)
#else
pool_cache_destruct_object_header(struct pool_cache *pc, void *object, struct pool_item_header *ph_in)
#endif
{

	if (pc->pc_dtor != NULL)
		(*pc->pc_dtor)(pc->pc_arg, object);
#ifndef __QNXNTO__
	pool_put(pc->pc_pool, object);
#else
	pool_put_header(pc->pc_pool, object, &ph_in->ph_pg);
#endif
}

static void
pool_do_cache_invalidate_grouplist(struct pool_cache_grouplist *pcgsl,
    struct pool_cache *pc, struct pool_pagelist *pq,
    struct pool_cache_grouplist *pcgdl)
{
	struct pool_cache_group *pcg, *npcg;
	void *object;

	for (pcg = LIST_FIRST(pcgsl); pcg != NULL; pcg = npcg) {
		npcg = LIST_NEXT(pcg, pcg_list);
		while (pcg->pcg_avail != 0) {
			pc->pc_nitems--;
#ifndef __QNXNTO__
			object = pcg_get(pcg, NULL);
#else
			object = pcg_get(pcg);
#endif
			if (pc->pc_dtor != NULL)
				(*pc->pc_dtor)(pc->pc_arg, object);
#ifndef __QNXNTO__
			pool_do_put(pc->pc_pool, object, pq);
#else
			pool_do_put(pc->pc_pool, object, pq, NULL);
#endif
		}
		pc->pc_ngroups--;
		LIST_REMOVE(pcg, pcg_list);
		LIST_INSERT_HEAD(pcgdl, pcg, pcg_list);
	}
}

static void
pool_do_cache_invalidate(struct pool_cache *pc, struct pool_pagelist *pq,
    struct pool_cache_grouplist *pcgl)
{

	LOCK_ASSERT(simple_lock_held(&pc->pc_slock));
	LOCK_ASSERT(simple_lock_held(&pc->pc_pool->pr_slock));

	pool_do_cache_invalidate_grouplist(&pc->pc_fullgroups, pc, pq, pcgl);
	pool_do_cache_invalidate_grouplist(&pc->pc_partgroups, pc, pq, pcgl);

	KASSERT(LIST_EMPTY(&pc->pc_partgroups));
	KASSERT(LIST_EMPTY(&pc->pc_fullgroups));
	KASSERT(pc->pc_nitems == 0);
}

/*
 * pool_cache_invalidate:
 *
 *	Invalidate a pool cache (destruct and release all of the
 *	cached objects).
 */
void
pool_cache_invalidate(struct pool_cache *pc)
{
	struct pool_pagelist pq;
	struct pool_cache_grouplist pcgl;
#ifdef __QNXNTO__
	struct nw_work_thread *wtp = WTP;
#endif

	LIST_INIT(&pq);
	LIST_INIT(&pcgl);

	POOL_LOCK(pc->pc_pool, &pc->pc_slock, wtp);
	POOL_LOCK(pc->pc_pool, &pc->pc_pool->pr_slock, wtp);

	pool_do_cache_invalidate(pc, &pq, &pcgl);

	POOL_UNLOCK(pc->pc_pool, &pc->pc_pool->pr_slock, wtp);
	POOL_UNLOCK(pc->pc_pool, &pc->pc_slock, wtp);

	pr_pagelist_free(pc->pc_pool, &pq);
	pcg_grouplist_free(&pcgl);
}

/*
 * pool_cache_reclaim:
 *
 *	Reclaim a pool cache for pool_reclaim().
 */
static void
pool_cache_reclaim(struct pool_cache *pc, struct pool_pagelist *pq,
    struct pool_cache_grouplist *pcgl)
{

	/*
	 * We're locking in the wrong order (normally pool_cache -> pool,
	 * but the pool is already locked when we get here), so we have
	 * to use trylock.  If we can't lock the pool_cache, it's not really
	 * a big deal here.
	 */
#ifndef __QNXNTO__
	if (simple_lock_try(&pc->pc_slock) == 0)
		return;
#else
#ifdef DIAGNOSTIC
	struct nw_work_thread *wtp = WTP;

	/* Make sure signal is held off */
	if (wtp->wt_critical == 0)
		panic("pool_cache_reclaim");
#endif
	if (NW_EX_TRYLK(&pc->pc_slock) != EOK)
		return;
#endif

	pool_do_cache_invalidate(pc, pq, pcgl);

#ifndef __QNXNTO__
	simple_unlock(&pc->pc_slock);
#else
	NW_EX_TRYUNLK(&pc->pc_slock);
#endif
}

/*
 * Pool backend allocators.
 *
 * Each pool has a backend allocator that handles allocation, deallocation,
 * and any additional draining that might be needed.
 *
 * We provide two standard allocators:
 *
 *	pool_allocator_kmem - the default when no allocator is specified
 *
 *	pool_allocator_nointr - used for pools that will not be accessed
 *	in interrupt context.
 */
void	*pool_page_alloc(struct pool *, int);
void	pool_page_free(struct pool *, void *);

#ifdef POOL_SUBPAGE
struct pool_allocator pool_allocator_kmem_fullpage = {
	pool_page_alloc, pool_page_free, 0,
	.pa_backingmapptr = &kmem_map,
};
#else
struct pool_allocator pool_allocator_kmem = {
	pool_page_alloc, pool_page_free, 0,
};
#ifdef __QNXNTO__
struct pool_allocator pool_allocator_bigpage = {
	pool_page_alloc, pool_page_free, 0,
};
#endif
#endif

#ifndef __QNXNTO__
void	*pool_page_alloc_nointr(struct pool *, int);
void	pool_page_free_nointr(struct pool *, void *);

#ifdef POOL_SUBPAGE
struct pool_allocator pool_allocator_nointr_fullpage = {
	pool_page_alloc_nointr, pool_page_free_nointr, 0,
	.pa_backingmapptr = &kernel_map,
};
#else
struct pool_allocator pool_allocator_nointr = {
	pool_page_alloc_nointr, pool_page_free_nointr, 0,
	.pa_backingmapptr = &kernel_map,
};
#endif
#endif

#ifdef POOL_SUBPAGE
void	*pool_subpage_alloc(struct pool *, int);
void	pool_subpage_free(struct pool *, void *);

struct pool_allocator pool_allocator_kmem = {
	pool_subpage_alloc, pool_subpage_free, POOL_SUBPAGE,
	.pa_backingmapptr = &kmem_map,
};

#ifndef __QNXNTO__
void	*pool_subpage_alloc_nointr(struct pool *, int);
void	pool_subpage_free_nointr(struct pool *, void *);

struct pool_allocator pool_allocator_nointr = {
	pool_subpage_alloc, pool_subpage_free, POOL_SUBPAGE,
	.pa_backingmapptr = &kmem_map,
};
#endif
#endif /* POOL_SUBPAGE */

static void *
pool_allocator_alloc(struct pool *pp, int flags)
{
	struct pool_allocator *pa = pp->pr_alloc;
	void *res;

	LOCK_ASSERT(!simple_lock_held(&pp->pr_slock));

	res = (*pa->pa_alloc)(pp, flags);
	if (res == NULL && (flags & PR_WAITOK) == 0) {
		/*
		 * We only run the drain hook here if PR_NOWAIT.
		 * In other cases, the hook will be run in
		 * pool_reclaim().
		 */
		if (pp->pr_drain_hook != NULL) {
			(*pp->pr_drain_hook)(pp->pr_drain_hook_arg, flags);
			res = (*pa->pa_alloc)(pp, flags);
		}
	}
	return res;
}

static void
pool_allocator_free(struct pool *pp, void *v)
{
	struct pool_allocator *pa = pp->pr_alloc;

	LOCK_ASSERT(!simple_lock_held(&pp->pr_slock));

	(*pa->pa_free)(pp, v);
}

#ifndef __QNXNTO__
void *
pool_page_alloc(struct pool *pp, int flags)
{
	boolean_t waitok = (flags & PR_WAITOK) ? TRUE : FALSE;

	return ((void *) uvm_km_alloc_poolpage_cache(kmem_map, waitok));
}

void
pool_page_free(struct pool *pp, void *v)
{

	uvm_km_free_poolpage_cache(kmem_map, (vaddr_t) v);
}
#else
/*
 * Default page allocator.
 */
void *
pool_page_alloc(struct pool *pp, int flags)
{
	void			*p;
	int			prot_flags, map_flags;
	size_t			size;
	struct pool_allocator	*pa;
	size_t			size_extra;
	char			*cp;

	pa = pp->pr_alloc;
	/*
	 * We've set it up so that pr_roflags has PR_NOCACHE set
	 * depending on whether or not architecture requires it.
	 */
	prot_flags = PROT_READ | PROT_WRITE;
	if (pp->pr_roflags & PR_NOCACHE)
		prot_flags |= PROT_NOCACHE;

	if (pp->pr_typed_mem_fd == NOFD) {
		map_flags = MAP_PRIVATE | MAP_ANON;
		if (pp->pr_roflags & PR_PHYS)
			map_flags |= MAP_PHYS /*| MAP_NOX64K*/;
	}
	else {
		map_flags = MAP_SHARED;
		/*
		 * We specified POSIX_TYPED_MEM_ALLOCATE_CONTIG to
		 * posix_typed_mem_open() therefore MAP_PHYS isn't
		 * needed.
		 */
	}

	size = pa->pa_pagesz;

	KASSERT(!(size == pagesize_large &&
	    (pp->pr_roflags & PR_BIGPAGE) == 0));

	/*
	 * If they've asked for or are being forced to
	 * a big page but they don't store and pass back
	 * the pg_in arg, we have to ensure things are
	 * aligned to a big page so the pa_pagemask arg
	 * is in fact meaningful when referenced.
	 *
	 * The effect of this is that PR_BIGPAGE should
	 * probably only be used with PR_PG_ARG but deal
	 * with all cases.
	 */
	if ((pp->pr_roflags & (PR_BIGPAGE | PR_PG_ARG)) == PR_BIGPAGE) {
		size_extra = size - pagesize;;
		size += size_extra;
	}
	else {
		size_extra = 0;
	}

	if ((p = mmap(NULL, size, prot_flags, map_flags, pp->pr_typed_mem_fd,
	    0)) == MAP_FAILED) {
		return NULL;
	}


	if (size_extra != 0) {
		int	size_pre;

		cp = p;

		if ((size_pre = (uintptr_t)p & ~pa->pa_pagemask)) {
			size_pre = pa->pa_pagesz - size_pre;
			cp += size_pre;
			munmap(p, size_pre);
			p = cp;
			size_extra -= size_pre;
		}
		if (size_extra)
			munmap(cp + pa->pa_pagesz, size_extra);
	}

	return p;
}

void
pool_page_free(struct pool *pp, void *v)
{
        munmap(v, pp->pr_alloc->pa_pagesz);
}
#endif

#ifndef __QNXNTO__
static void *
pool_page_alloc_meta(struct pool *pp, int flags)
{
	boolean_t waitok = (flags & PR_WAITOK) ? TRUE : FALSE;

	return ((void *) uvm_km_alloc_poolpage(kmem_map, waitok));
}

static void
pool_page_free_meta(struct pool *pp, void *v)
{

	uvm_km_free_poolpage(kmem_map, (vaddr_t) v);
}
#endif

#ifdef POOL_SUBPAGE
/* Sub-page allocator, for machines with large hardware pages. */
void *
pool_subpage_alloc(struct pool *pp, int flags)
{
	void *v;
	int s;
	s = splvm();
	v = pool_get(&psppool, flags);
	splx(s);
	return v;
}

void
pool_subpage_free(struct pool *pp, void *v)
{
	int s;
	s = splvm();
	pool_put(&psppool, v);
	splx(s);
}

#ifndef __QNXNTO__
/* We don't provide a real nointr allocator.  Maybe later. */
void *
pool_subpage_alloc_nointr(struct pool *pp, int flags)
{

	return (pool_subpage_alloc(pp, flags));
}

void
pool_subpage_free_nointr(struct pool *pp, void *v)
{

	pool_subpage_free(pp, v);
}
#endif
#endif /* POOL_SUBPAGE */
#ifndef __QNXNTO__
void *
pool_page_alloc_nointr(struct pool *pp, int flags)
{
	boolean_t waitok = (flags & PR_WAITOK) ? TRUE : FALSE;

	return ((void *) uvm_km_alloc_poolpage_cache(kernel_map, waitok));
}

void
pool_page_free_nointr(struct pool *pp, void *v)
{

	uvm_km_free_poolpage_cache(kernel_map, (vaddr_t) v);
}
#endif



#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/kern/subr_pool.c $ $Rev: 882930 $")
#endif
