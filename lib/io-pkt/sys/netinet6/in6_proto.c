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

/*	$NetBSD: in6_proto.c,v 1.93 2011/09/24 17:22:14 christos Exp $	*/
/*	$KAME: in6_proto.c,v 1.66 2000/10/10 15:35:47 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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
 *	@(#)in_proto.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: in6_proto.c,v 1.93 2011/09/24 17:22:14 christos Exp $");

#include "opt_inet.h"
#include "opt_ipsec.h"
#include "opt_iso.h"

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/radix.h>

#if defined(RADIX_MPATH)
#include <net/radix_mpath.h>
#endif

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_pcb.h>

#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>

#include <netinet6/udp6.h>
#include <netinet6/udp6_var.h>

#include <netinet6/pim6_var.h>

#include <netinet6/nd6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#ifdef IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#include <netipsec/key.h>
#endif /* FAST_IPSEC */


#include "carp.h"
#if NCARP > 0
#include <netinet/ip_carp.h>
#endif

#include "etherip.h"
#if NETHERIP > 1
#include <netinet6/ip6_etherip.h>
#endif

#include <netinet6/ip6protosw.h>

#include <net/net_osdep.h>

#ifndef offsetof		/* XXX */
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

/*
 * TCP/IP protocol family: IP6, ICMP6, UDP, TCP.
 */

DOMAIN_DEFINE(inet6domain);	/* forward declare and add to link set */

const struct ip6protosw inet6sw[] = {
{ 0,		&inet6domain,	IPPROTO_IPV6,	0,
  0,		0,		0,		0,
  0,
  ip6_init,	0,		frag6_slowtimo,	frag6_drain,
},
{
#ifndef __QNXNTO__
  SOCK_DGRAM,	&inet6domain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR|PR_PURGEIF,
#else
  SOCK_DGRAM,	&inet6domain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR|PR_PURGEIF|PR_SENSE_EXTEN,
#endif
  udp6_input,	0,		udp6_ctlinput,	udp6_ctloutput,
  udp6_usrreq,	udp6_init,
  0,		0,		0,
},
{
#ifndef __QNXNTO__
  SOCK_STREAM,	&inet6domain,	IPPROTO_TCP,	PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN|PR_ABRTACPTDIS|PR_PURGEIF,
#else
  SOCK_STREAM,	&inet6domain,	IPPROTO_TCP,	PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN|PR_ABRTACPTDIS|PR_PURGEIF|PR_WAITALL_RCVD|PR_SENSE_EXTEN,
#endif
  tcp6_input,	0,		tcp6_ctlinput,	tcp_ctloutput,
  tcp_usrreq,
#ifdef INET	/* don't call initialization and timeout routines twice */
  0,		0,		0,		0,
#else
  tcp_init,	0,		tcp_slowtimo,	tcp_drain,
#endif
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_RAW,	PR_ATOMIC|PR_ADDR|PR_PURGEIF,
  rip6_input,	rip6_output,	rip6_ctlinput,	rip6_ctloutput,
  rip6_usrreq,
  0,		0,		0,		0,
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_ICMPV6,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  icmp6_input,	rip6_output,	rip6_ctlinput,	rip6_ctloutput,
  rip6_usrreq,
  icmp6_init,	0,		0,		0,
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_DSTOPTS,PR_ATOMIC|PR_ADDR,
  dest6_input,	0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_ROUTING,PR_ATOMIC|PR_ADDR,
  route6_input,	0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
{ SOCK_RAW,	&inet6domain,	IPPROTO_FRAGMENT,PR_ATOMIC|PR_ADDR,
  frag6_input,	0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
#ifdef IPSEC
{ SOCK_RAW,	&inet6domain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ah6_input,	0,	 	ah6_ctlinput,	0,
  0,
  0,		0,		0,		0,
},
#ifdef IPSEC_ESP
{ SOCK_RAW,	&inet6domain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  esp6_input,	0,	 	esp6_ctlinput,	0,
  0,
  0,		0,		0,		0,
},
#endif
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipcomp6_input, 0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
#endif /* IPSEC */
#ifdef FAST_IPSEC
{ SOCK_RAW,    &inet6domain,   IPPROTO_AH,     PR_ATOMIC|PR_ADDR,
  ipsec6_common_input, 0,              ah6_ctlinput,   0,
  0,
  0,           0,              0,              0,      
},
{ SOCK_RAW,    &inet6domain,   IPPROTO_ESP,    PR_ATOMIC|PR_ADDR,
  ipsec6_common_input,    0,           esp6_ctlinput,  0,
  0,
  0,           0,              0,              0,              
},
{ SOCK_RAW,    &inet6domain,   IPPROTO_IPCOMP, PR_ATOMIC|PR_ADDR,
  ipsec6_common_input,    0,           0,              0,
  0,
  0,           0,              0,              0,              
},
#endif /* FAST_IPSEC */
#ifdef INET
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPV4,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap6_input,	rip6_output, 	encap6_ctlinput, rip6_ctloutput,
  rip6_usrreq,
  encap_init,	0,		0,		0,
},
#endif
{ SOCK_RAW,	&inet6domain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap6_input, rip6_output,	encap6_ctlinput, rip6_ctloutput,
  rip6_usrreq,
  encap_init,	0,		0,		0,
},
#if NETHERIP > 1
{ SOCK_RAW,	&inet6domain,	IPPROTO_ETHERIP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  ip6_etherip_input,	rip6_output,	rip6_ctlinput,	rip6_ctloutput,
  rip6_usrreq,
  0,		0,		0,		0,
},
#endif
#if NCARP > 0
{ SOCK_RAW,	&inet6domain,	IPPROTO_CARP,	PR_ATOMIC|PR_ADDR,
  carp6_proto_input,	rip6_output,	0,		rip6_ctloutput,
  rip6_usrreq,
  0,		0,		0,		0,
},
#endif /* NCARP */
#ifdef ISO
{ SOCK_RAW,	&inet6domain,	IPPROTO_EON,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap6_input,	rip6_output,	encap6_ctlinput, rip6_ctloutput,
  rip6_usrreq,	/*XXX*/
  encap_init,	0,		0,		0,
},
#endif
{ SOCK_RAW,     &inet6domain,	IPPROTO_PIM,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  pim6_input,	rip6_output,	0,              rip6_ctloutput,
  rip6_usrreq,
  0,            0,              0,              0,
},
/* raw wildcard */
{ SOCK_RAW,	&inet6domain,	0,		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  rip6_input,	rip6_output,	0,		rip6_ctloutput,
  rip6_usrreq,
  rip6_init,	0,		0,		0,
},
};

static const struct sockaddr_in6 in6_any = {
	  .sin6_len = sizeof(in6_any)
	, .sin6_family = AF_INET6
	, .sin6_port = 0
	, .sin6_flowinfo = 0
	, .sin6_addr = IN6ADDR_ANY_INIT
	, .sin6_scope_id = 0
};

#ifdef __QNXNTO__
/* see lib/io-pkt/sys/netinet/in_proto.c */
#if defined(RADIX_MPATH)
int rn_mpath_inithead_inet(void **head, int off);
#else
int rn_inithead_inet(void **head, int off);
#endif
#endif

struct domain inet6domain = {
	.dom_family = AF_INET6, .dom_name = "internet6",
	.dom_init = NULL, .dom_externalize = NULL, .dom_dispose = NULL,
	.dom_protosw = (const struct protosw *)inet6sw,
	.dom_protoswNPROTOSW = (const struct protosw *)&inet6sw[sizeof(inet6sw)/sizeof(inet6sw[0])],
#if defined(RADIX_MPATH)
#ifndef __QNXNTO__
	.dom_rtattach = rn_mpath_inithead,
#else
	.dom_rtattach = rn_mpath_inithead_inet,
#endif
#else
#ifndef __QNXNTO__
	.dom_rtattach = rn_inithead,
#else
	.dom_rtattach = rn_inithead_inet,
#endif
#endif
	.dom_rtoffset = offsetof(struct sockaddr_in6, sin6_addr) << 3,
	.dom_maxrtkey = sizeof(struct sockaddr_in6),
	.dom_ifattach = in6_domifattach, .dom_ifdetach = in6_domifdetach,
	.dom_ifqueues = { &ip6intrq, NULL },
	.dom_link = { NULL },
	.dom_mowner = MOWNER_INIT("",""),
	.dom_sa_cmpofs = offsetof(struct sockaddr_in6, sin6_addr),
	.dom_sa_cmplen = sizeof(struct in6_addr),
	.dom_sa_any = (const struct sockaddr *)&in6_any,
	.dom_rtcache = LIST_HEAD_INITIALIZER(inet6domain.dom_rtcache)
};

/*
 * Internet configuration info
 */
#ifndef	IPV6FORWARDING
#ifdef GATEWAY6
#define	IPV6FORWARDING	1	/* forward IP6 packets not for us */
#else
#define	IPV6FORWARDING	0	/* don't forward IP6 packets not for us */
#endif /* GATEWAY6 */
#endif /* !IPV6FORWARDING */

int	ip6_forwarding = IPV6FORWARDING;	/* act as router? */
#ifdef QNX_MFIB
int	ip6_forwarding_mfibmask = 0;	/* act as router in these fibs */
#endif
int	ip6_sendredirects = 1;
int	ip6_defhlim = IPV6_DEFHLIM;
int	ip6_defmcasthlim = IPV6_DEFAULT_MULTICAST_HOPS;
int	ip6_accept_rtadv = 0;	/* "IPV6FORWARDING ? 0 : 1" is dangerous */
int	ip6_maxfragpackets = 200;
int	ip6_maxfrags = 200;
int	ip6_log_interval = 5;
int	ip6_hdrnestlimit = 50;	/* appropriate? */
int	ip6_dad_count = 1;	/* DupAddrDetectionTransmits */
int	ip6_auto_flowlabel = 1;
int	ip6_use_deprecated = 1;	/* allow deprecated addr (RFC2462 5.5.4) */
int	ip6_rr_prune = 5;	/* router renumbering prefix
				 * walk list every 5 sec. */
int	ip6_mcast_pmtu = 0;	/* enable pMTU discovery for multicast? */
int	ip6_v6only = 1;

int	ip6_keepfaith = 0;
time_t	ip6_log_time = (time_t)0L;

/* icmp6 */
/*
 * BSDI4 defines these variables in in_proto.c...
 * XXX: what if we don't define INET? Should we define pmtu6_expire
 * or so? (jinmei@kame.net 19990310)
 */
int pmtu_expire = 60*10;

/* raw IP6 parameters */
/*
 * Nominal space allocated to a raw ip socket.
 */
#define	RIPV6SNDQ	8192
#define	RIPV6RCVQ	8192

u_long	rip6_sendspace = RIPV6SNDQ;
u_long	rip6_recvspace = RIPV6RCVQ;

/* ICMPV6 parameters */
int	icmp6_rediraccept = 1;		/* accept and process redirects */
int	icmp6_redirtimeout = 10 * 60;	/* 10 minutes */
int	icmp6errppslim = 100;		/* 100pps */
#ifndef __QNXNTO__
int	icmp6_nodeinfo = 1;		/* enable/disable NI response */
#else
int	icmp6_nodeinfo = 0;		/* enable/disable NI response */
#endif

/* UDP on IP6 parameters */
int	udp6_sendspace = 9216;		/* really max datagram size */
int	udp6_recvspace = 40 * (1024 + sizeof(struct sockaddr_in6));
					/* 40 1K datagrams */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/in6_proto.c $ $Rev: 839788 $")
#endif
