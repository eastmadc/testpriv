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

/*      $NetBSD: bus_machdep.c,v 1.15 2002/04/10 10:09:31 haya Exp $    */

/*-
  * Copyright (c) 1996, 1997, 1998 The NetBSD Foundation, Inc.
  * All rights reserved.
  *
  * This code is derived from software contributed to The NetBSD Foundation
  * by Charles M. Hannum and by Jason R. Thorpe of the Numerical Aerospace
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
  *      This product includes software developed by the NetBSD
  *      Foundation, Inc. and its contributors.
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
 
#include <sys/mman.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#define _STDDEF_H_INCLUDED
#include <hw/pci.h>
#include <machine/bus.h>
#include <hw/inout.h>
#include <nw_cache.h>
#include <uvm/uvm_extern.h>

static bus_size_t round_pow2(bus_size_t);


int bus_dmamap_load_buffer(bus_dma_tag_t t, bus_dmamap_t map, 
	void *buf, bus_size_t buflen, 
	struct proc *p, int flags, paddr_t *lastaddrp,
	int *segp, int first);

int bus_dmamem_alloc_range(bus_dma_tag_t t, bus_size_t size, 
	bus_size_t alignment, bus_size_t boundary,
	bus_dma_segment_t *segs,	int nsegs, int *rsegs,
	int flags, paddr_t low, paddr_t high);

void
bus_space_init(void)
{
}

int
bus_space_map(bus_space_tag_t t, bus_addr_t addr, bus_size_t size,
    int flags, bus_space_handle_t *bshp)
{
	*bshp = (bus_space_handle_t)mmap_device_memory(0, size,
	    PROT_READ | PROT_WRITE | PROT_NOCACHE, MAP_SHARED, addr);

	if (*bshp == (bus_space_handle_t)MAP_FAILED)
		return -1;

	return 0;
}

int
bus_space_unmap(bus_space_tag_t t, bus_space_handle_t bshp, bus_size_t size)
{
#if 0
	munmap(bshp, size);
#else
	/*
	 * Will be unmapped (and freed) in bus_dmamem_free()
	 * which gets passed alloc size which may be greater
	 * than size passed here if it was requested to be
	 * aligned to > PAGE_SIZE.
	 */
#endif
	return 0;
}

/*
 * Common function for DMA map creation.  May be called by bus-specific
 * DMA map creation functions.
 */
int bus_dmamap_create(t, size, nsegments, maxsegsz, boundary, flags, dmamp)
	bus_dma_tag_t t;
	bus_size_t size;
	int nsegments;
	bus_size_t maxsegsz;
	bus_size_t boundary;
	int flags;
	bus_dmamap_t *dmamp;
{
	bus_dmamap_t map;
	void *mapstore;
	size_t mapsize;

	/*
	 * Allocate and initialize the DMA map.  The end of the map
	 * is a variable-sized array of segments, so we allocate enough
	 * room for them in one shot.
	 *
	 * Note we don't preserve the WAITOK or NOWAIT flags.  Preservation
	 * of ALLOCNOW notifies others that we've reserved these resources,
	 * and they are not to be freed.
	 *
	 * The bus_dmamap_t includes one bus_dma_segment_t, hence
	 * the (nsegments - 1).
	 */
	mapsize = sizeof(struct bus_dmamap) +
	    (sizeof(struct bus_dma_segment) * (nsegments - 1));
//	mapstore = mmap_device_memory(0, mapsize, PROT_READ|PROT_WRITE, MAP_ANON, 0);
//	if (mapstore == MAP_FAILED)
//		return (ENOMEM);
	mapstore = malloc(mapsize, M_DEVBUF, M_NOWAIT);
	if (mapstore == NULL)
	  return (ENOMEM);
	
   	map = (bus_dmamap_t)mapstore;
	memset(map, 0, mapsize);
	map->dm_total_segs = nsegments;
	map->dm_maxsegsz = maxsegsz;
	*dmamp = map;
	return (0);
}

/*
 * Common function for DMA map destruction.  May be called by bus-specific
 * DMA map destruction functions.
 */
void bus_dmamap_destroy(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	//munmap(map, sizeof(*map));
	free(map, M_DEVBUF);
}


/*
 * Common function for loading a DMA map with a linear buffer.  May
 * be called by bus-specific DMA map load functions.
 */
int bus_dmamap_load(t, map, buf, buflen, p, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
{
	paddr_t lastaddr;
	int seg, error;

	/*
	 * Make sure that on error condition we return "no valid mappings".
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;

	seg = 0;
	error = bus_dmamap_load_buffer(t, map, buf, buflen, p, flags,
	    &lastaddr, &seg, 1);
	if (error == 0) {
		map->dm_mapsize = buflen;
		map->dm_nsegs = seg + 1;
	}
	return (error);
}

/*
 * Like _bus_dmamap_load(), but for mbufs.
 */
int bus_dmamap_load_mbuf(t, map, m0, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct mbuf *m0;
	int flags;
{
	int seg, error, len, len_todo;
	struct mbuf *m;
	uint64_t bmstr = t;
	off64_t paddr;
	void *vaddr;
	
	/*
	 * Make sure that on error condition we return "no valid mappings."
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;

#ifdef DIAGNOSTIC
	if ((m0->m_flags & M_PKTHDR) == 0)
		panic("_bus_dmamap_load_mbuf: no packet header");
#endif

	seg = 0;
	error = 0;
	for (m = m0; m != NULL; m = m->m_next) {
		/* Some drivers don't like 0 length segments */
		if ((len_todo = m->m_len) == 0)
			continue;

		/* We have a short path to caculate the paddr */
		paddr = mbuf_phys(m);
		vaddr = mtod(m, void *);
again:
		if (seg >= map->dm_total_segs) {
			error = EFBIG;
			break;
		}
		len = min(len_todo, map->dm_maxsegsz);
		map->dm_segs[seg].ds_vaddr = vaddr;
		map->dm_segs[seg].ds_addr = paddr + bmstr;
		map->dm_segs[seg].ds_len = len;
		seg++;
		if ((len_todo -= len) > 0) {
			vaddr = (void *)((uintptr_t)vaddr + len);
			paddr += len;
			goto again;
		}
	}

	if (error == 0) {
		map->dm_mapsize = m0->m_pkthdr.len;
		map->dm_nsegs = seg;
	}

	return (error);
}

/*
 * Like _bus_dmamap_load(), but for uios.
 */
int
bus_dmamap_load_uio(bus_dma_tag_t t, bus_dmamap_t map, struct uio *uio,
    int flags)
{
	paddr_t lastaddr;
	int seg, i, error, first;
	bus_size_t minlen, resid;
	struct proc *p = NULL;
	struct iovec *iov;
	caddr_t addr;

	/*
	 * Make sure that on error condition we return "no valid mappings."
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;

	resid = uio->uio_resid;
	iov = uio->uio_iov;

	if (uio->uio_vmspace != NULL &&
	    uio->uio_vmspace->vm_flags == VM_USERSPACE) {
		p = uio->uio_vmspace->vm_proc;
#ifdef DIAGNOSTIC
		if (p == NULL)
			panic("_bus_dmamap_load_uio: USERSPACE but no proc");
#endif
	}

	first = 1;
	seg = 0;
	error = 0;
	for (i = 0; i < uio->uio_iovcnt && resid != 0 && error == 0; i++) {
		/*
		 * Now at the first iovec to load.  Load each iovec
		 * until we have exhausted the residual count.
		 */
		minlen = resid < iov[i].iov_len ? resid : iov[i].iov_len;
		addr = (caddr_t)iov[i].iov_base;

		error = bus_dmamap_load_buffer(t, map, addr, minlen,
		    p, flags, &lastaddr, &seg, first);
		first = 0;

		resid -= minlen;
	}

	if (error == 0) {
		map->dm_mapsize = uio->uio_resid;
		map->dm_nsegs = seg + 1;
	}

	return (error);
}

/*
 * Common function for unloading a DMA map.  May be called by
 * bus-specific DMA map unload functions.
 */
void
bus_dmamap_unload(bus_dma_tag_t t, bus_dmamap_t map)
{
	/*
	 * No resources to free; just mark the mappings as
	 * invalid.
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
}

/*
 * Common function for DMA map synchronization.  May be called
 * by bus-specific DMA map synchronization functions.
 */
void
bus_dmamap_sync(bus_dma_tag_t t, bus_dmamap_t map, uintptr_t offset,
    bus_size_t len, int ops)
{
#ifdef __X86__
	return;
#else
	uint64_t		bmstr;
	const bus_dma_segment_t	*ds;
	bus_size_t		seglen;
	bus_addr_t		paddr;
	void			*vaddr;

	/*
	 * If one is a nop but not the other, we may end
	 * up doing both.  We log this on cache_init().
	 */
	if ((qnx_cachectl.flags & __CACHE_FLUSH_NOP) &&
	    (qnx_cachectl.flags & __CACHE_INVAL_NOP)) {
		/*
		 * XXX what if there's a separate store that
		 *     isn't a nop?
		 */
		return;
	}

	bmstr = t;
	ds = map->dm_segs;

	if ((ops & (BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE)) != 0 &&
	    (ops & (BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE)) != 0)
		panic("bus_dmamap_sync");

	/* Skip leading amount */
	while (offset >= ds->ds_len) {
		offset -= ds->ds_len;
		ds++;
	}

	for (; len > 0; ds++) {
		seglen = ds->ds_len - offset;
		paddr = ds->ds_addr + offset;
		vaddr = (void *)((uintptr_t)ds->ds_vaddr + offset);

		offset = 0;

		if (seglen == 0)
			continue;

		paddr -= bmstr; /* convert bus to phys */

		if (seglen > len)
			seglen = len;
		len -= seglen;

		/* XXX do we really need to invalidate pre and post? */
		if (ops & (BUS_DMASYNC_POSTREAD | BUS_DMASYNC_PREREAD))
			NW_CACHE_INVAL(&qnx_cachectl, vaddr, paddr, seglen);

		if (ops & BUS_DMASYNC_PREWRITE)
			NW_CACHE_STORE(&qnx_cachectl, vaddr, paddr, seglen);

		/* Nothing for post write */
	}

	NW_CACHE_SYNC();
#endif
}

/*
 * Common function for DMA-safe memory allocation.  May be called
 * by bus-specific DMA memory allocation functions.
 */
int bus_dmamem_alloc(t, size, alignment, boundary, segs, nsegs, rsegs, flags)
	bus_dma_tag_t t;
	bus_size_t size, alignment, boundary;
	bus_dma_segment_t *segs;
	int nsegs;
	int *rsegs;
	int flags;
{
	return (bus_dmamem_alloc_range(t, size, alignment, boundary,
	    segs, nsegs, rsegs, flags, 0, 0));
}

/*
 * Common function for freeing DMA-safe memory.  May be called by
 * bus-specific DMA memory free functions.
 */
void bus_dmamem_free(t, segs, nsegs)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs;
{
	int curseg;

	for (curseg = 0; curseg < nsegs; curseg++) {
		munmap((void *)segs[curseg].ds_alloc, segs[curseg].ds_alloc_size);
	}
}

/*
 * Common function for mapping DMA-safe memory.  May be called by
 * bus-specific DMA memory map functions.
 */
int bus_dmamem_map(t, segs, nsegs, size, kvap, flags)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs;
	size_t size;
	caddr_t *kvap;
	int flags;
{
	void *va;

#ifndef __QNXNTO__
	bus_addr_t addr;
	int curseg;
	
	size = round_page(size);
	va = uvm_km_valloc(kernel_map, size);

	if (va == 0)
		return (ENOMEM);
	
	for (curseg = 0; curseg < nsegs; curseg++) {
		for (addr = segs[curseg].ds_addr;
		    addr < (segs[curseg].ds_addr + segs[curseg].ds_len);
		    addr += PAGE_SIZE, va += PAGE_SIZE, size -= PAGE_SIZE) {
			if (size == 0)
				panic("_bus_dmamem_map: size botch");
			pmap_enter(pmap_kernel(), va, addr,
			    VM_PROT_READ | VM_PROT_WRITE,
			    PMAP_WIRED | VM_PROT_READ | VM_PROT_WRITE);
		}
	}
	pmap_update(pmap_kernel());
#else
	int		prot;
	/* pad bytes required to meet requested alignment */
	int		pad, pad_max;
	off64_t		pa;
	uint64_t	bmstr;
	bus_size_t	align;
	
	bmstr = t;
	prot = PROT_READ | PROT_WRITE;
#ifndef __X86__ /* XXX need to be more sophisticated here */
	if (flags & (BUS_DMA_COHERENT | BUS_DMA_NOCACHE))
		prot |= PROT_NOCACHE;
#endif
	align = segs[0].ds_align;
	align = round_pow2(align);
	align = max(align, PAGE_SIZE);

	pad_max = align - PAGE_SIZE;

	va = mmap(0, size + pad_max, prot, MAP_ANON | MAP_PHYS, NOFD, 0);
	if (va == MAP_FAILED)
		return (ENOMEM);
	segs[0].ds_alloc = va;
	segs[0].ds_alloc_size = size + pad_max;
	if (mem_offset64(va, NOFD, size, &pa, 0) == -1) {
		munmap(va, size);
		return errno;
	}

	/* Align the physical addr, not the virtual. */
	if (pa & (align - 1)) {
		pad = align - (pa & (align - 1));
		if (pad > pad_max)
			panic("bus_dmamem_map");
		pa += pad;
		va = (void *)((uintptr_t)va + pad);
	}
	if (pa & (align - 1))
		panic("bus_dmamem_map");

	segs[0].ds_vaddr = va;
	segs[0].ds_addr = pa + bmstr;
	segs[0].ds_len = size;
	*kvap = (caddr_t)va;
#endif
	return (0);
}

/*
 * Common function for unmapping DMA-safe memory.  May be called by
 * bus-specific DMA memory unmapping functions.
 */
void bus_dmamem_unmap(t, kva, size)
	bus_dma_tag_t t;
	caddr_t kva;
	size_t size;
{

#ifdef DIAGNOSTIC
	if ((u_long)kva & PGOFSET)
		panic("_bus_dmamem_unmap");
#endif
	
#ifndef __QNXNTO__
	size = round_page(size);

	uvm_km_free(kernel_map, (vaddr_t)kva, size);
#else
	munmap(kva, size);
#endif
}

#if 0
/*
 * Common functin for mmap(2)'ing DMA-safe memory.  May be called by
 * bus-specific DMA mmap(2)'ing functions.
 */
paddr_t bus_dmamem_mmap(t, segs, nsegs, off, prot, flags)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs;
	off_t off;
	int prot, flags;
{
	int i;

	for (i = 0; i < nsegs; i++) {
#ifdef DIAGNOSTIC
		if (off & PGOFSET)
			panic("_bus_dmamem_mmap: offset unaligned");
		if (segs[i].ds_addr & PGOFSET)
			panic("_bus_dmamem_mmap: segment unaligned");
		if (segs[i].ds_len & PGOFSET)
			panic("_bus_dmamem_mmap: segment size not multiple"
			    " of page size");
#endif
		if (off >= segs[i].ds_len) {
			off -= segs[i].ds_len;
			continue;
		}

#ifndef __QNXNTO__
		return (i386_btop((caddr_t)segs[i].ds_addr + off));
#else
		{
#if 0
			unsigned offset;

			mem_offset((void *)(segs[i].ds_addr + off), NOFD, segs[i].ds_len, &offset, 0);
			return offset;
#else
			return segs[i].ds_addr - bmstr + off;	/* phys */
			/* or */
			return segs[i].ds_vaddr + off;		/* virt */
#endif
		}
#endif
	}

	/* Page not found. */
	return (-1);
}
#endif

/**********************************************************************
 * DMA utility functions
 **********************************************************************/

/*
 * Utility function to load a linear buffer.  lastaddrp holds state
 * between invocations (for multiple-buffer loads).  segp contains
 * the starting segment on entrace, and the ending segment on exit.
 * first indicates if this is the first invocation of this function.
 */
int bus_dmamap_load_buffer(t, map, buf, buflen, p, flags, lastaddrp, segp, first)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
	paddr_t *lastaddrp;
	int *segp;
	int first;
{
	int seg;

#ifndef __QNXNTO__
	bus_size_t sgsize;
	bus_addr_t curaddr, lastaddr, baddr, bmask;
	pmap_t pmap;
	
	for (seg = *segp; buflen > 0 ; ) {
		/*
		 * Get the physical address for this segment.
		 */
		(void) pmap_extract(pmap, vaddr, &curaddr);

		/*
		 * If we're beyond the bounce threshold, notify
		 * the caller.
		 */
		if (map->_dm_bounce_thresh != 0 &&
		    curaddr >= map->_dm_bounce_thresh)
			return (EINVAL);

		/*
		 * Compute the segment size, and adjust counts.
		 */
		sgsize = PAGE_SIZE - ((u_long)vaddr & PGOFSET);
		if (buflen < sgsize)
			sgsize = buflen;

		/*
		 * Make sure we don't cross any boundaries.
		 */
		if (map->_dm_boundary > 0) {
			baddr = (curaddr + map->_dm_boundary) & bmask;
			if (sgsize > (baddr - curaddr))
				sgsize = (baddr - curaddr);
		}

		/*
		 * Insert chunk into a segment, coalescing with
		 * previous segment if possible.
		 */
		if (first) {
			map->dm_segs[seg].ds_addr = curaddr;
			map->dm_segs[seg].ds_len = sgsize;
			first = 0;
		} else {
			if (curaddr == lastaddr &&
			    (map->dm_segs[seg].ds_len + sgsize) <=
			     map->_dm_maxsegsz &&
			    (map->_dm_boundary == 0 ||
			     (map->dm_segs[seg].ds_addr & bmask) ==
			     (curaddr & bmask)))
				map->dm_segs[seg].ds_len += sgsize;
			else {
				if (++seg >= map->_dm_segcnt)
					break;
				map->dm_segs[seg].ds_addr = curaddr;
				map->dm_segs[seg].ds_len = sgsize;
			}
		}

		lastaddr = curaddr + sgsize;
		vaddr += sgsize;
		buflen -= sgsize;
	}

	*segp = seg;
	*lastaddrp = lastaddr;

	/*
	 * Did we fit?
	 */
	if (buflen != 0)
		return (EFBIG);		/* XXX better return value here? */
#else
	off64_t		curaddr;
	uint64_t	bmstr;

	bmstr = t;

	if (mem_offset64(buf, NOFD, buflen, &curaddr, 0) == -1)
		return errno;
	
	seg = *segp;
	map->dm_segs[seg].ds_vaddr = buf;
	map->dm_segs[seg].ds_addr = curaddr + bmstr;
	map->dm_segs[seg].ds_len = buflen;
#endif
	return (0);
}

/*
 * Allocate physical memory from the given physical address range.
 * Called by DMA-safe memory allocation methods.
 */
int bus_dmamem_alloc_range(t, size, alignment, boundary, segs, nsegs, rsegs,
    flags, low, high)
	bus_dma_tag_t t;
	bus_size_t size, alignment, boundary;
	bus_dma_segment_t *segs;
	int nsegs;
	int *rsegs;
	int flags;
	paddr_t low;
	paddr_t high;
{
#ifdef __QNXNTO__
	int curseg;
	curseg = 0;
	segs[0].ds_align = alignment;
#else
	paddr_t curaddr, lastaddr;
	struct vm_page *m;
	int curseg, error;
	struct pglist mlist;

	/* Always round the size. */
	size = round_page(size);

	/*
	 * Compute the location, size, and number of segments actually
	 * returned by the VM code.
	 */
	m = mlist.tqh_first;
	curseg = 0;
	lastaddr = segs[curseg].ds_addr = VM_PAGE_TO_PHYS(m);
	segs[curseg].ds_len = PAGE_SIZE;
	m = m->pageq.tqe_next;

	for (; m != NULL; m = m->pageq.tqe_next) {
		curaddr = VM_PAGE_TO_PHYS(m);
#ifdef DIAGNOSTIC
		if (curaddr < low || curaddr >= high) {
			printf("vm_page_alloc_memory returned non-sensical"
			    " address 0x%lx\n", curaddr);
			panic("_bus_dmamem_alloc_range");
		}
#endif
		if (curaddr == (lastaddr + PAGE_SIZE))
			segs[curseg].ds_len += PAGE_SIZE;
		else {
			curseg++;
			segs[curseg].ds_addr = curaddr;
			segs[curseg].ds_len = PAGE_SIZE;
		}
		lastaddr = curaddr;
	}
#endif

	*rsegs = curseg + 1;
	return (0);
}

/*
 * Only X86 has separate in* / out* instructions for io
 * space access.  On all other platforms, they map to
 * *(volatile u_int8_t *)((h) + (o)) operations but they
 * include the proper eieio() instructions so we use them
 * explicitly.  The reason for this is because on all
 * platforms except X86, mmap_device_io() does a mmap() to
 * our address space similar to mmap_device_mem().
 *
 */

uint8_t
bus_space_read_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		return in8(h + o);
	else
		return *(volatile uint8_t *)(h + o);
#else
	return in8(h + o);
#endif
}

uint16_t
bus_space_read_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE) {
		if (t & BUS_SPACE_IO)
			return inle16(h + o);
		else
			return ENDIAN_LE16(*(volatile uint16_t *)(h + o));
	}
	else {
		if (t & BUS_SPACE_IO)
			return inbe16(h + o);
		else
			return ENDIAN_BE16(*(volatile uint16_t *)(h + o));
	}
#else
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE)
		return inle16(h + o);
	else
		return inbe16(h + o);

#endif
	
}


uint32_t
bus_space_read_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE) {
		if (t & BUS_SPACE_IO)
			return inle32(h + o);
		else
			return ENDIAN_LE32(*(volatile uint32_t *)(h + o));
	}
	else {
		if (t & BUS_SPACE_IO)
			return inbe32(h + o);
		else
			return ENDIAN_BE32(*(volatile uint32_t *)(h + o));
	}
#else
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE)
		return inle32(h + o);
	else
		return inbe32(h + o);

#endif
	
}


void
bus_space_write_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t v)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		out8(h + o, v);
	else
		*(volatile uint8_t *)(h + o) = v;
#else
	out8(h + o, v);
#endif
}

void
bus_space_write_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t v)
{
#ifdef __X86__
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE) {
		if (t & BUS_SPACE_IO)
			outle16(h + o, v);
		else
			*(volatile uint16_t *)(h + o) = ENDIAN_LE16(v);
	}
	else {
		if (t & BUS_SPACE_IO)
			outbe16(h + o, v);
		else
			*(volatile uint16_t *)(h + o) = ENDIAN_BE16(v);
	}
#else
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE)
		outle16(h + o, v);
	else
		outbe16(h + o, v);

#endif
	
}


void
bus_space_write_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t v)
{
#ifdef __X86__
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE) {
		if (t & BUS_SPACE_IO)
			outle32(h + o, v);
		else
			*(volatile uint32_t *)(h + o) = ENDIAN_LE32(v);
	}
	else {
		if (t & BUS_SPACE_IO)
			outbe32(h + o, v);
		else
			*(volatile uint32_t *)(h + o) = ENDIAN_BE32(v);
	}
#else
	/* endianess of the bus itself */
	if (t & BUS_SPACE_LE)
		outle32(h + o, v);
	else
		outbe32(h + o, v);

#endif
	
}






/* As above using native endianess */



uint8_t
bus_space_read_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		return in8(h + o);
	else
		return *(volatile uint8_t *)(h + o);
#else
	return in8(h + o);
#endif
}

uint16_t
bus_space_read_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		return in16(h + o);
	else
		return *(volatile uint16_t *)(h + o);
#else
	return in16(h + o);

#endif
	
}


uint32_t
bus_space_read_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		return in32(h + o);
	else
		return *(volatile uint32_t *)(h + o);
#else
	return in32(h + o);

#endif
	
}


void
bus_space_write_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t v)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		out8(h + o, v);
	else
		*(volatile uint8_t *)(h + o) = v;
#else
	out8(h + o, v);
#endif
}

void
bus_space_write_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t v)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		out16(h + o, v);
	else
		*(volatile uint16_t *)(h + o) = v;
#else
	out16(h + o, v);

#endif
	
}

void
bus_space_write_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t v)
{
#ifdef __X86__
	if (t & BUS_SPACE_IO)
		out32(h + o, v);
	else
		*(volatile uint32_t *)(h + o) = v;
#else
	out32(h + o, v);

#endif
	
}

/* As above, but multiple read/writes of the same offset */

void
bus_space_read_multi_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_1(t, h, o);
        }
}

void
bus_space_read_multi_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_2(t, h, o);
        }
}

void
bus_space_read_multi_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_4(t, h, o);
        }
}

void
bus_space_write_multi_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_1(t, h, o, *ptr++);
        }
}

void
bus_space_write_multi_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_2(t, h, o, *ptr++);
        }
}

void
bus_space_write_multi_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_4(t, h, o, *ptr++);
        }
}

void
bus_space_read_multi_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_stream_1(t, h, o);
        }
}

void
bus_space_read_multi_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_stream_2(t, h, o);
        }
}

void
bus_space_read_multi_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t *ptr, size_t count)
{
        while (count--) {
                *ptr++ = bus_space_read_stream_4(t, h, o);
        }
}

void
bus_space_write_multi_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint8_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_stream_1(t, h, o, *ptr++);
        }
}

void
bus_space_write_multi_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint16_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_stream_2(t, h, o, *ptr++);
        }
}

void
bus_space_write_multi_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o, uint32_t *ptr, size_t count)
{
        while (count--) {
                bus_space_write_stream_4(t, h, o, *ptr++);
        }
}




/* Multiple operations while incrementing offset */
void
bus_space_read_region_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint8_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_1(t, h, o);
		o++;
	}
}

void
bus_space_read_region_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint16_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_2(t, h, o);
		o+=2;
	}
}

void
bus_space_read_region_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint32_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_4(t, h, o);
		o+=4;
	}
}


void
bus_space_read_region_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint8_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_stream_1(t, h, o);
		o++;
	}
}

void
bus_space_read_region_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint16_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_stream_2(t, h, o);
		o+=2;
	}
}

void
bus_space_read_region_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    uint32_t *ptr, size_t count)
{
	while (count--) {
		*ptr++ = bus_space_read_stream_4(t, h, o);
		o+=4;
	}
}

void
bus_space_write_region_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint8_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_1(t, h, o, *ptr);
		ptr++;
		o++;
	}
}

void
bus_space_write_region_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint16_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_2(t, h, o, *ptr);
		ptr++;
		o+=2;
	}
}

void
bus_space_write_region_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint32_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_4(t, h, o, *ptr);
		ptr++;
		o+=4;
	}
}

void
bus_space_write_region_stream_1(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint8_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_stream_1(t, h, o, *ptr);
		ptr++;
		o++;
	}
}

void
bus_space_write_region_stream_2(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint16_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_stream_2(t, h, o, *ptr);
		ptr++;
		o+=2;
	}
}

void
bus_space_write_region_stream_4(bus_space_tag_t t, bus_space_handle_t h, bus_size_t o,
    const uint32_t *ptr, size_t count)
{
	while (count--) {
		bus_space_write_stream_4(t, h, o, *ptr);
		ptr++;
		o+=4;
	}
}


/* Round down to power of 2 */
static bus_size_t
round_pow2(bus_size_t val)
{
	bus_size_t msk;

	for (msk = ~(bus_size_t)0 ^ (~(bus_size_t)0 >> 1); msk != 0 ; msk >>= 1) {
		if (val & msk) {
			val &= ~(msk - 1);
			break;
		}
	}
	return val;

}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/qnx_bus.c $ $Rev: 680336 $")
#endif
