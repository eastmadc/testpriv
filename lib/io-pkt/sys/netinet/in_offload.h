/*	$NetBSD: in_offload.h,v 1.4 2006/11/25 18:41:36 yamt Exp $	*/

/*-
 * Copyright (c)2005, 2006 YAMAMOTO Takashi,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET_IN_OFFLOAD_H_
#define	_NETINET_IN_OFFLOAD_H_

/*
 * subroutines to do software-only equivalent of h/w offloading.
 */

int tcp4_segment(struct mbuf *, int (*)(void *, struct mbuf *), void *);
int ip_tso_output(struct ifnet *, struct mbuf *, struct sockaddr *,
    struct rtentry *);

/*
 * offloading related sysctl variables.
 *
 * they are here because it violates protocol layering in unusual way.
 * ie. while they are TCP/UDP sysctls, they are used by IP layer.
 */

extern int tcp_do_loopback_cksum; /* do TCP checksum on loopback? */
extern int udp_do_loopback_cksum; /* do UDP checksum on loopback? */

#define	IN_NEED_CHECKSUM(ifp, csum_flags) \
	(__predict_true(((ifp)->if_flags & IFF_LOOPBACK) == 0 || \
	(((csum_flags) & M_CSUM_UDPv4) != 0 && udp_do_loopback_cksum) || \
	(((csum_flags) & M_CSUM_TCPv4) != 0 && tcp_do_loopback_cksum) || \
	(((csum_flags) & M_CSUM_IPv4) != 0 && ip_do_loopback_cksum)))

#endif /* !_NETINET_IN_OFFLOAD_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/in_offload.h $ $Rev: 764208 $")
#endif
