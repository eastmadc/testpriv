/*	$NetBSD: tcp.h,v 1.25 2006/10/09 16:27:07 rpaulo Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_TCP_H_INCLUDED
#define _NETINET_TCP_H_INCLUDED

#ifndef __PLATFORM_H_INCLUDED
#include <sys/platform.h>
#endif

#ifdef __EXT_BSD

typedef _Uint32t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 * Updated by RFC 3168, September, 2001.
 */
struct tcphdr {
	_Uint16t th_sport;		/* source port */
	_Uint16t th_dport;		/* destination port */
	tcp_seq	  th_seq;		/* sequence number */
	tcp_seq	  th_ack;		/* acknowledgement number */
#if defined(__LITTLEENDIAN__)
	/*LINTED non-portable bitfields*/
	_Uint8t  th_x2:4,		/* (unused) */
		  th_off:4;		/* data offset */
#elif defined(__BIGENDIAN__)
	/*LINTED non-portable bitfields*/
	_Uint8t  th_off:4,		/* data offset */
		  th_x2:4;		/* (unused) */
#else
#error endian not defined
#endif
	_Uint8t  th_flags;
#define	TH_FIN	  0x01
#define	TH_SYN	  0x02
#define	TH_RST	  0x04
#define	TH_PUSH	  0x08
#define	TH_ACK	  0x10
#define	TH_URG	  0x20
#define	TH_ECE	  0x40
#define	TH_CWR	  0x80
	_Uint16t th_win;			/* window */
	_Uint16t th_sum;			/* checksum */
	_Uint16t th_urp;			/* urgent pointer */
} __attribute__((__packed__));

#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define	   TCPOLEN_MAXSEG		4
#define	TCPOPT_WINDOW		3
#define	   TCPOLEN_WINDOW		3
#define	TCPOPT_SACK_PERMITTED	4		/* Experimental */
#define	   TCPOLEN_SACK_PERMITTED	2
#define	TCPOPT_SACK		5		/* Experimental */
#define	TCPOPT_TIMESTAMP	8
#define	   TCPOLEN_TIMESTAMP		10
#define	   TCPOLEN_TSTAMP_APPA		(TCPOLEN_TIMESTAMP+2) /* appendix A */

#define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

#define	TCPOPT_SIGNATURE	19		/* Keyed MD5: RFC 2385 */
#define	   TCPOLEN_SIGNATURE		18
#define    TCPOLEN_SIGLEN		(TCPOLEN_SIGNATURE+2) /* padding */

#define MAX_TCPOPTLEN	40	/* max # bytes that go in options */

/*
 * Default maximum segment size for TCP.
 * This is defined by RFC 1112 Sec 4.2.2.6.
 */
#define	TCP_MSS		536

#define	TCP_MAXWIN	65535	/* largest value for (unscaled) window */

#define	TCP_MAX_WINSHIFT	14	/* maximum window shift */

#define	TCP_MAXBURST	4	/* maximum segments in a burst */

#endif /* __EXT_BSD */

/*
 * User-settable options (used with setsockopt).
 */
#define	TCP_NODELAY	0x01	/* don't delay send to coalesce packets */
#ifdef __EXT_BSD
#define	TCP_MAXSEG	0x02	/* set maximum segment size */
#endif
#ifdef __EXT_QNX
#define	TCP_KEEPALIVE	0x04	/* seconds between keepalive probes */
#endif
#ifdef __EXT_QNX
#define TCP_RTO		0x20
#define TCP_RTO_LIMIT	0x40
#define TCP_RTO_FINAL	0x80
#endif
/* Bits 0x04, 0x08 reserved for FreeBSD compatibility: TCP_NOPUSH, TCP_NOOPT */
#ifdef __EXT_BSD
#define TCP_MD5SIG	0x10	/* use MD5 digests (RFC2385) */
#define	TCP_CONGCTL	0x20	/* selected congestion control */
#endif
#endif /* !_NETINET_TCP_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/netinet/tcp.h $ $Rev: 778302 $")
#endif
