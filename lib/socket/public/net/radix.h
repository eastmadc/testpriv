/*	$NetBSD: radix.h,v 1.17 2006/10/22 20:55:09 christos Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1993
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
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 */

#ifndef _NET_RADIX_H_INCLUDED
#define _NET_RADIX_H_INCLUDED

#ifndef __PLATFORM_H_INCLUDED
#include <sys/platform.h>
#endif

#ifndef __TYPES_H_INCLUDED
#include <sys/types.h>
#endif

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct	radix_mask *rn_mklist;	/* list of masks contained in subtree */
	struct	radix_node *rn_p;	/* parent */
	short	rn_b;			/* bit offset; -1-index(netmask) */
	char	rn_bmask;		/* node: mask for bit test*/
	u_char	rn_flags;		/* enumerated next */
#define RNF_NORMAL	1		/* leaf contains normal route */
#define RNF_ROOT	2		/* leaf is root leaf for tree */
#define RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			const char *rn_Key;	/* object of search */
			const char *rn_Mask;	/* netmask, if present */
			struct	radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {			/* node only data: */
			int	rn_Off;		/* where to start compare */
			struct	radix_node *rn_L;/* progeny */
			struct	radix_node *rn_R;/* progeny */
		} rn_node;
	} rn_u;
#ifdef RN_DEBUG
	int rn_info;
	struct radix_node *rn_twin;
	struct radix_node *rn_ybro;
#endif
};

#define rn_dupedkey rn_u.rn_leaf.rn_Dupedkey
#define rn_key rn_u.rn_leaf.rn_Key
#define rn_mask rn_u.rn_leaf.rn_Mask
#define rn_off rn_u.rn_node.rn_Off
#define rn_l rn_u.rn_node.rn_L
#define rn_r rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	short	rm_b;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rn_bmask */
	u_char	rm_flags;		/* cf. rn_flags */
	struct	radix_mask *rm_mklist;	/* more masks to try */
	union	{
		const char *rmu_mask;		/* the mask */
		struct	radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	int	rm_refs;		/* # of references to this struct */
};

#define rm_mask rm_rmu.rmu_mask
#define rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

#define MKGet(m) {\
	if (rn_mkfreelist) {\
		m = rn_mkfreelist; \
		rn_mkfreelist = (m)->rm_mklist; \
	} else \
		R_Malloc(m, struct radix_mask *, sizeof (*(m))); }\

#define MKFree(m) { (m)->rm_mklist = rn_mkfreelist; rn_mkfreelist = (m);}

struct radix_node_head {
	struct	radix_node *rnh_treetop;
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
#ifdef QNX_MFIB
	int rnh_fib;
#endif
	struct	radix_node *(*rnh_addaddr)	/* add based on sockaddr */
		(const void *v, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		(const void *v, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_deladdr)	/* remove based on sockaddr */
#ifdef RADIX_MPATH
		(const void *v, const void *mask, struct radix_node_head *head,
				struct radix_node *rn);
#else
		(const void *v, const void *mask, struct radix_node_head *head);
#endif
	struct	radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		(const void *v, const void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		(const void *v, struct radix_node_head *head, void *hint);
	struct	radix_node *(*rnh_lookup)	/* locate based on sockaddr */
		(const void *v, const void *mask, struct radix_node_head *head, void *hint);
	struct	radix_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		(const void *v, struct radix_node_head *head);
#ifndef QNX_MFIB
	int	(*rnh_walktree)			/* traverse tree */
		(struct radix_node_head *,
		     int (*)(struct radix_node *, void *), void *);
#else
	int	(*rnh_walktree)			/* traverse tree */
		(struct radix_node_head *,
		     int (*)(struct radix_node *, void *, int), void *);
#endif
	int	(*rnh_match_hint)	/* locate based on packet hdr */
		(struct radix_node *t, void *hint);
	struct	radix_node rnh_nodes[3];	/* empty tree for common case */
	/* RADIX_MPATH support. Unused unless RADIX_MPATH is defined  */
	int     rnh_multipath;                  /* multipath? */
};


#ifdef _KERNEL
extern struct radix_mask *rn_mkfreelist;

#define Bcmp(a, b, n) ((n) == 0 ? 0 : memcmp((a), (b), (n)))
#define Bcopy(a, b, n) memmove((b), (a), (n))
#define Bzero(p, n) memset((p), 0, (n));
#define R_Malloc(p, t, n) (p = (t) malloc((size_t)(n), M_RTABLE, M_NOWAIT))
#define Free(p) free(p, M_RTABLE);
#endif /*_KERNEL*/

__BEGIN_DECLS

void	 rn_init(void);
int	 rn_inithead(void **, int);
int	 rn_inithead0(struct radix_node_head *, int);
int	 rn_refines(const void *, const void *);
int	 rn_walktree(struct radix_node_head *,
#ifndef QNX_MFIB
			  int (*)(struct radix_node *, void *), void *);
#else
			  int (*)(struct radix_node *, void *, int), void *);
#endif
struct radix_node
	 *rn_addmask(const void *, int, int),
	 *rn_addroute(const void *, const void *, struct radix_node_head *,
			struct radix_node [2]),
#ifdef RADIX_MPATH
	 *rn_delete(const void *, const void *, struct radix_node_head *, struct radix_node *rn),
#else
	 *rn_delete(const void *, const void *, struct radix_node_head *),
#endif
	 *rn_insert(const void *, struct radix_node_head *, int *,
			struct radix_node [2]),
	 *rn_lookup(const void *, const void *, struct radix_node_head *, void *hint),
	 *rn_match(const void *, struct radix_node_head *, void *hint),
	 *rn_newpair(const void *, int, struct radix_node[2]),
	 *rn_search(const void *, struct radix_node *),
	 *rn_search_m(const void *, struct radix_node *, const void *);
__END_DECLS

#endif /* !_NET_RADIX_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/net/radix.h $ $Rev: 680336 $")
#endif
