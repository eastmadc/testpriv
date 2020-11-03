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

/*	$NetBSD: bus.h,v 1.11 2006/02/16 20:17:15 perry Exp $	*/

/*-
 * Copyright (c) 1996, 1997, 1998, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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

/*
 * Copyright (c) 1996 Charles M. Hannum.  All rights reserved.
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
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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

#ifndef _X86_BUS_H_
#define _X86_BUS_H_

#ifndef __QNXNTO__
#include <machine/pio.h>
#else
#include <hw/inout.h>
#include <sys/syspage.h>
#include <stdint.h>
#endif

#ifdef BUS_SPACE_DEBUG
#include <sys/systm.h> /* for printf() prototype */
/*
 * Macros for sanity-checking the aligned-ness of pointers passed to
 * bus space ops.  These are not strictly necessary on the x86, but
 * could lead to performance improvements, and help catch problems
 * with drivers that would creep up on other architectures.
 */
#define	__BUS_SPACE_ALIGNED_ADDRESS(p, t)				\
	((((u_long)(p)) & (sizeof(t)-1)) == 0)

#define	__BUS_SPACE_ADDRESS_SANITY(p, t, d)				\
({									\
	if (__BUS_SPACE_ALIGNED_ADDRESS((p), t) == 0) {			\
		printf("%s 0x%lx not aligned to %d bytes %s:%d\n",	\
		    d, (u_long)(p), sizeof(t), __FILE__, __LINE__);	\
	}								\
	(void) 0;							\
})

#define BUS_SPACE_ALIGNED_POINTER(p, t) __BUS_SPACE_ALIGNED_ADDRESS(p, t)
#else
#define	__BUS_SPACE_ADDRESS_SANITY(p,t,d)	(void) 0
#define BUS_SPACE_ALIGNED_POINTER(p, t) ALIGNED_POINTER(p, t)
#endif /* BUS_SPACE_DEBUG */

#define	BUS_SPACE_IO	0x00000001	/* space is i/o space */
#define BUS_SPACE_MEM	0x00000002	/* space is mem space */
#ifdef __QNXNTO__
/* little endian flag, else BE */
#define BUS_SPACE_LE	0x00000004
#endif

#define __BUS_SPACE_HAS_STREAM_METHODS 1

/*
 * Bus address and size types
 */
#ifndef __QNXNTO__
typedef u_long bus_addr_t;
typedef u_long bus_size_t;
#else
typedef uint64_t bus_addr_t;
typedef size_t bus_size_t;
#endif

/*
 * Access methods for bus resources and address space.
 */
typedef	int bus_space_tag_t;
typedef	uintptr_t bus_space_handle_t;

/*
 *	int bus_space_map(bus_space_tag_t t, bus_addr_t addr,
 *	    bus_size_t size, int flags, bus_space_handle_t *bshp);
 *
 * Map a region of bus space.
 */

#define	BUS_SPACE_MAP_CACHEABLE		0x01
#define	BUS_SPACE_MAP_LINEAR		0x02
#define	BUS_SPACE_MAP_PREFETCHABLE	0x04

int bus_space_map(bus_space_tag_t t, bus_addr_t addr,
		bus_size_t size, int flags, bus_space_handle_t *bshp);



/*
 *	int bus_space_unmap(bus_space_tag_t t,
 *	    bus_space_handle_t bsh, bus_size_t size);
 *
 * Unmap a region of bus space.
 */
int bus_space_unmap(bus_space_tag_t tag, bus_space_handle_t handle, 
			bus_size_t size);

/*
 *	void *bus_space_vaddr(bus_space_tag_t, bus_space_handle_t);
 *
 * Get the kernel virtual address for the mapped bus space.
 * Only allowed for regions mapped with BUS_SPACE_MAP_LINEAR.
 *  (XXX not enforced)
 */
#define bus_space_vaddr(t, h) \
	(((t) & ~BUS_SPACE_LE) == BUS_SPACE_MEM ? (void *)(h) : (void *)0)


/*
 *	u_intN_t bus_space_read_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset);
 *
 * Read a 1, 2, 4, or 8 byte quantity from bus space
 * described by tag/handle/offset.
 */

uint8_t  bus_space_read_1(bus_space_tag_t, bus_space_handle_t, bus_size_t);
uint16_t bus_space_read_2(bus_space_tag_t, bus_space_handle_t, bus_size_t);
uint32_t bus_space_read_4(bus_space_tag_t, bus_space_handle_t, bus_size_t);

uint8_t  bus_space_read_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t);
uint16_t bus_space_read_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t);
uint32_t bus_space_read_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t);



#if 0	/* Cause a link error for bus_space_read_8 */
#define	bus_space_read_8(t, h, o)	!!! bus_space_read_8 unimplemented !!!
#define	bus_space_read_stream_8(t, h, o)	\
		!!! bus_space_read_stream_8 unimplemented !!!
#endif

/*
 *	void bus_space_read_multi_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t *addr, size_t count);
 *
 * Read `count' 1, 2, 4, or 8 byte quantities from bus space
 * described by tag/handle/offset and copy into buffer provided.
 */

void bus_space_read_multi_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_read_multi_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_read_multi_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);

void bus_space_read_multi_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_read_multi_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_read_multi_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);

#if 0	/* Cause a link error for bus_space_read_multi_8 */
#define	bus_space_read_multi_8	!!! bus_space_read_multi_8 unimplemented !!!
#define	bus_space_read_multi_stream_8	\
		!!! bus_space_read_multi_stream_8 unimplemented !!!
#endif

/*
 *	void bus_space_read_region_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t *addr, size_t count);
 *
 * Read `count' 1, 2, 4, or 8 byte quantities from bus space
 * described by tag/handle and starting at `offset' and copy into
 * buffer provided.
 */

void bus_space_read_region_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_read_region_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_read_region_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);

void bus_space_read_region_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_read_region_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_read_region_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);


#if 0	/* Cause a link error for bus_space_read_region_8 */
#define	bus_space_read_region_8	!!! bus_space_read_region_8 unimplemented !!!
#define	bus_space_read_region_stream_8	\
		!!! bus_space_read_region_stream_8 unimplemented !!!
#endif

/*
 *	void bus_space_write_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    u_intN_t value);
 *
 * Write the 1, 2, 4, or 8 byte value `value' to bus space
 * described by tag/handle/offset.
 */

void bus_space_write_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t);
void bus_space_write_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t);
void bus_space_write_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t);


void bus_space_write_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t);
void bus_space_write_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t);
void bus_space_write_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t);

#if 0	/* Cause a link error for bus_space_write_8 */
#define	bus_space_write_8	!!! bus_space_write_8 not implemented !!!
#define	bus_space_write_stream_8	\
		!!! bus_space_write_stream_8 not implemented !!!
#endif

/*
 *	void bus_space_write_multi_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    const u_intN_t *addr, size_t count);
 *
 * Write `count' 1, 2, 4, or 8 byte quantities from the buffer
 * provided to bus space described by tag/handle/offset.
 */

void bus_space_write_multi_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_write_multi_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_write_multi_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);

void bus_space_write_multi_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t *, size_t);
void bus_space_write_multi_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t *, size_t);
void bus_space_write_multi_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t *, size_t);


#if 0	/* Cause a link error for bus_space_write_multi_8 */
#define	bus_space_write_multi_8(t, h, o, ptr, cnt)			\
			!!! bus_space_write_multi_8 unimplemented !!!
#define	bus_space_write_multi_stream_8(t, h, o, ptr, cnt)		\
			!!! bus_space_write_multi_stream_8 unimplemented !!!
#endif

/*
 *	void bus_space_write_region_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    const u_intN_t *addr, size_t count);
 *
 * Write `count' 1, 2, 4, or 8 byte quantities from the buffer provided
 * to bus space described by tag/handle starting at `offset'.
 */

void bus_space_write_region_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint8_t *, size_t);
void bus_space_write_region_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint16_t *, size_t);
void bus_space_write_region_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint32_t *, size_t);

void bus_space_write_region_stream_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint8_t *, size_t);
void bus_space_write_region_stream_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint16_t *, size_t);
void bus_space_write_region_stream_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, const uint32_t *, size_t);


#if 0	/* Cause a link error for bus_space_write_region_8 */
#define	bus_space_write_region_8					\
			!!! bus_space_write_region_8 unimplemented !!!
#define	bus_space_write_region_stream_8				\
			!!! bus_space_write_region_stream_8 unimplemented !!!
#endif

/*
 *	void bus_space_set_multi_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset, u_intN_t val,
 *	    size_t count);
 *
 * Write the 1, 2, 4, or 8 byte value `val' to bus space described
 * by tag/handle/offset `count' times.
 */

void bus_space_set_multi_1 (bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t, size_t);
void bus_space_set_multi_2 (bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t, size_t);
void bus_space_set_multi_4 (bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t, size_t);


#if 0	/* Cause a link error for bus_space_set_multi_8 */
#define	bus_space_set_multi_8 !!! bus_space_set_multi_8 unimplemented !!!
#endif

/*
 *	void bus_space_set_region_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset, u_intN_t val,
 *	    size_t count);
 *
 * Write `count' 1, 2, 4, or 8 byte value `val' to bus space described
 * by tag/handle starting at `offset'.
 */


void bus_space_set_region_1(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint8_t val, size_t);
void bus_space_set_region_2(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint16_t val, size_t);
void bus_space_set_region_4(bus_space_tag_t, bus_space_handle_t, bus_size_t, uint32_t val, size_t);


#if 0	/* Cause a link error for bus_space_set_region_8 */
#define	bus_space_set_region_8	!!! bus_space_set_region_8 unimplemented !!!
#endif

/*
 *	void bus_space_copy_region_N(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh1, bus_size_t off1,
 *	    bus_space_handle_t bsh2, bus_size_t off2,
 *	    size_t count);
 *
 * Copy `count' 1, 2, 4, or 8 byte values from bus space starting
 * at tag/bsh1/off1 to bus space starting at tag/bsh2/off2.
 */

void bus_space_copy_region_1 (bus_space_tag_t, bus_space_handle_t, bus_size_t, bus_space_handle_t, bus_size_t, size_t);
void bus_space_copy_region_2 (bus_space_tag_t, bus_space_handle_t, bus_size_t, bus_space_handle_t, bus_size_t, size_t);
void bus_space_copy_region_4 (bus_space_tag_t, bus_space_handle_t, bus_size_t, bus_space_handle_t, bus_size_t, size_t);


#if 0	/* Cause a link error for bus_space_copy_8 */
#define	bus_space_copy_region_8	!!! bus_space_copy_region_8 unimplemented !!!
#endif


/*
 * Bus read/write barrier methods.
 *
 *	void bus_space_barrier(bus_space_tag_t tag,
 *	    bus_space_handle_t bsh, bus_size_t offset,
 *	    bus_size_t len, int flags);
 *
 * Note: the x86 does not currently require barriers, but we must
 * provide the flags to MI code.
 */
#define	bus_space_barrier(t, h, o, l, f)	\
	((void)((void)(t), (void)(h), (void)(o), (void)(l), (void)(f)))
#define	BUS_SPACE_BARRIER_READ	0x01		/* force read barrier */
#define	BUS_SPACE_BARRIER_WRITE	0x02		/* force write barrier */


/*
 * Flags used in various bus DMA methods.
 */
#define	BUS_DMA_WAITOK		0x000	/* safe to sleep (pseudo-flag) */
#define	BUS_DMA_NOWAIT		0x001	/* not safe to sleep */
#define	BUS_DMA_ALLOCNOW	0x002	/* perform resource allocation now */
#define	BUS_DMA_COHERENT	0x004	/* hint: map memory DMA coherent */
#define	BUS_DMA_STREAMING	0x008	/* hint: sequential, unidirectional */
#define	BUS_DMA_BUS1		0x010	/* placeholders for bus functions... */
#define	BUS_DMA_BUS2		0x020
#define	BUS_DMA_BUS3		0x040
#define	BUS_DMA_BUS4		0x080
#define	BUS_DMA_READ		0x100	/* mapping is device -> memory only */
#define	BUS_DMA_WRITE		0x200	/* mapping is memory -> device only */
#define	BUS_DMA_NOCACHE		0x400	/* hint: map non-cached memory */

/* Forwards needed by prototypes below. */
struct mbuf;
struct uio;

/*
 * Operations performed by bus_dmamap_sync().
 */
#define	BUS_DMASYNC_PREREAD	0x01	/* pre-read synchronization */
#define	BUS_DMASYNC_POSTREAD	0x02	/* post-read synchronization */
#define	BUS_DMASYNC_PREWRITE	0x04	/* pre-write synchronization */
#define	BUS_DMASYNC_POSTWRITE	0x08	/* post-write synchronization */

#ifndef __QNXNTO__
typedef void *bus_dma_tag_t;
#else
typedef uint64_t bus_dma_tag_t;
#endif
/*
 *	bus_dma_segment_t
 *
 *	Describes a single contiguous DMA transaction.  Values
 *	are suitable for programming into DMA registers.
 */
struct bus_dma_segment {
#ifdef __QNXNTO__
	void		*ds_alloc;
	size_t		ds_alloc_size;
	bus_size_t	ds_align;
	void		*ds_vaddr;
#endif
	bus_addr_t	ds_addr;	/* DMA address */
	bus_size_t	ds_len;		/* length of transfer */
};
typedef struct bus_dma_segment	bus_dma_segment_t;

typedef struct bus_dmamap {
	int         dm_total_segs;
	bus_size_t  dm_maxsegsz;
	bus_size_t  dm_mapsize;
	int         dm_nsegs;
	struct bus_dma_segment dm_segs[1];
} * bus_dmamap_t;

/*
 *	bus_dma_tag_t
 *
 *	A machine-dependent opaque type describing the implementation of
 *	DMA for a given bus.
 */

#ifndef __QNXNTO__
struct x86_bus_dma_tag {
	/*
	 * The `bounce threshold' is checked while we are loading
	 * the DMA map.  If the physical address of the segment
	 * exceeds the threshold, an error will be returned.  The
	 * caller can then take whatever action is necessary to
	 * bounce the transfer.  If this value is 0, it will be
	 * ignored.
	 */
	bus_addr_t _bounce_thresh;
	bus_addr_t _bounce_alloc_lo;
	bus_addr_t _bounce_alloc_hi;
	int	(*_may_bounce)(bus_dma_tag_t, bus_dmamap_t, int, int *);

	/*
	 * DMA mapping methods.
	 */
	int	(*_dmamap_create)(bus_dma_tag_t, bus_size_t, int,
		    bus_size_t, bus_size_t, int, bus_dmamap_t *);
	void	(*_dmamap_destroy)(bus_dma_tag_t, bus_dmamap_t);
	int	(*_dmamap_load)(bus_dma_tag_t, bus_dmamap_t, void *,
		    bus_size_t, struct proc *, int);
	int	(*_dmamap_load_mbuf)(bus_dma_tag_t, bus_dmamap_t,
		    struct mbuf *, int);
	int	(*_dmamap_load_uio)(bus_dma_tag_t, bus_dmamap_t,
		    struct uio *, int);
	int	(*_dmamap_load_raw)(bus_dma_tag_t, bus_dmamap_t,
		    bus_dma_segment_t *, int, bus_size_t, int);
	void	(*_dmamap_unload)(bus_dma_tag_t, bus_dmamap_t);
	void	(*_dmamap_sync)(bus_dma_tag_t, bus_dmamap_t,
		    bus_addr_t, bus_size_t, int);

	/*
	 * DMA memory utility functions.
	 */
	int	(*_dmamem_alloc)(bus_dma_tag_t, bus_size_t, bus_size_t,
		    bus_size_t, bus_dma_segment_t *, int, int *, int);
	void	(*_dmamem_free)(bus_dma_tag_t, bus_dma_segment_t *, int);
	int	(*_dmamem_map)(bus_dma_tag_t, bus_dma_segment_t *,
		    int, size_t, caddr_t *, int);
	void	(*_dmamem_unmap)(bus_dma_tag_t, caddr_t, size_t);
	paddr_t	(*_dmamem_mmap)(bus_dma_tag_t, bus_dma_segment_t *,
		    int, off_t, int, int);
};

static __inline void bus_dmamap_sync(bus_dma_tag_t, bus_dmamap_t,
    bus_addr_t, bus_size_t, int) __attribute__((__unused__));

#define	bus_dmamap_create(t, s, n, m, b, f, p)			\
	(*(t)->_dmamap_create)((t), (s), (n), (m), (b), (f), (p))
#define	bus_dmamap_destroy(t, p)				\
	(*(t)->_dmamap_destroy)((t), (p))
#define	bus_dmamap_load(t, m, b, s, p, f)			\
	(*(t)->_dmamap_load)((t), (m), (b), (s), (p), (f))
#define	bus_dmamap_load_mbuf(t, m, b, f)			\
	(*(t)->_dmamap_load_mbuf)((t), (m), (b), (f))
#define	bus_dmamap_load_uio(t, m, u, f)				\
	(*(t)->_dmamap_load_uio)((t), (m), (u), (f))
#define	bus_dmamap_load_raw(t, m, sg, n, s, f)			\
	(*(t)->_dmamap_load_raw)((t), (m), (sg), (n), (s), (f))
#define	bus_dmamap_unload(t, p)					\
	(*(t)->_dmamap_unload)((t), (p))
static __inline void
bus_dmamap_sync(bus_dma_tag_t t, bus_dmamap_t p, bus_addr_t o, bus_size_t l,
    int ops)
{
	if (ops & BUS_DMASYNC_POSTREAD)
		x86_lfence();
	if (t->_dmamap_sync)
		(*t->_dmamap_sync)(t, p, o, l, ops);
}

#define	bus_dmamem_alloc(t, s, a, b, sg, n, r, f)		\
	(*(t)->_dmamem_alloc)((t), (s), (a), (b), (sg), (n), (r), (f))
#define	bus_dmamem_free(t, sg, n)				\
	(*(t)->_dmamem_free)((t), (sg), (n))
#define	bus_dmamem_map(t, sg, n, s, k, f)			\
	(*(t)->_dmamem_map)((t), (sg), (n), (s), (k), (f))
#define	bus_dmamem_unmap(t, k, s)				\
	(*(t)->_dmamem_unmap)((t), (k), (s))
#define	bus_dmamem_mmap(t, sg, n, o, p, f)			\
	(*(t)->_dmamem_mmap)((t), (sg), (n), (o), (p), (f))
#else
void bus_space_init(void);
int	bus_dmamap_create(bus_dma_tag_t, bus_size_t, int, bus_size_t,
	    bus_size_t, int, bus_dmamap_t *);
void	bus_dmamap_destroy(bus_dma_tag_t, bus_dmamap_t);
int	bus_dmamap_load(bus_dma_tag_t, bus_dmamap_t, void *,
	    bus_size_t, struct proc *, int);
int	bus_dmamap_load_mbuf(bus_dma_tag_t, bus_dmamap_t,
	    struct mbuf *, int);
int	bus_dmamap_load_uio(bus_dma_tag_t, bus_dmamap_t, struct uio *, int);
void	bus_dmamap_unload(bus_dma_tag_t, bus_dmamap_t);
/*
 * We store the vaddr in the dma_segment as well so
 * restrict offset to uintptr_t size.
 */
void	bus_dmamap_sync(bus_dma_tag_t, bus_dmamap_t, uintptr_t,
	    bus_size_t, int);

int	bus_dmamem_alloc(bus_dma_tag_t, bus_size_t, bus_size_t, bus_size_t,
	    bus_dma_segment_t *, int, int *, int);
void	bus_dmamem_free(bus_dma_tag_t tag, bus_dma_segment_t *segs,
	    int nsegs);
int	bus_dmamem_map(bus_dma_tag_t, bus_dma_segment_t *,
	    int, size_t, caddr_t *, int);
void	bus_dmamem_unmap(bus_dma_tag_t tag, caddr_t kva,
	    size_t size);
#endif

/*
 *	bus_dmamap_t
 *
 *	Describes a DMA mapping.
 */
struct x86_bus_dmamap {
	/*
	 * PRIVATE MEMBERS: not for use by machine-independent code.
	 */
	bus_size_t	_dm_size;	/* largest DMA transfer mappable */
	int		_dm_segcnt;	/* number of segs this map can map */
	bus_size_t	_dm_maxmaxsegsz; /* fixed largest possible segment */
	bus_size_t	_dm_boundary;	/* don't cross this */
	bus_addr_t	_dm_bounce_thresh; /* bounce threshold; see tag */
	int		_dm_flags;	/* misc. flags */

	void		*_dm_cookie;	/* cookie for bus-specific functions */

	/*
	 * PUBLIC MEMBERS: these are used by machine-independent code.
	 */
	bus_size_t	dm_maxsegsz;	/* largest possible segment */
	bus_size_t	dm_mapsize;	/* size of the mapping */
	int		dm_nsegs;	/* # valid segments in mapping */
	bus_dma_segment_t dm_segs[1];	/* segments; variable length */
};

#endif /* _X86_BUS_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/machine/bus.h $ $Rev: 680336 $")
#endif
