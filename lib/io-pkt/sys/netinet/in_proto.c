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

/*	$NetBSD: in_proto.c,v 1.79 2006/11/23 04:07:07 rpaulo Exp $	*/

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
 *	@(#)in_proto.c	8.2 (Berkeley) 2/9/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: in_proto.c,v 1.79 2006/11/23 04:07:07 rpaulo Exp $");

#include "opt_mrouting.h"
#include "opt_eon.h"			/* ISO CLNL over IP */
#include "opt_iso.h"			/* ISO TP tunneled over IP */
#include "opt_inet.h"
#include "opt_ipsec.h"
#ifdef __QNXNTO__
//#include "opt_sctp.h"
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
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
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_ifattach.h>
#include <netinet/in_pcb.h>
#include <netinet/in_proto.h>

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet/ip6.h>
#endif

#include <netinet/igmp_var.h>
#ifdef PIM
#include <netinet/pim_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_encap.h>

/*
 * TCP/IP protocol family: IP, ICMP, UDP, TCP.
 */

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
#include <netipsec/key.h>
#endif	/* FAST_IPSEC */

#ifdef TPIP
#include <netiso/tp_param.h>
#include <netiso/tp_var.h>
#endif /* TPIP */

#ifdef EON
#include <netiso/eonvar.h>
#endif /* EON */

#include "gre.h"
#if NGRE > 0
#include <netinet/ip_gre.h>
#endif

#if defined(__QNXNTO__) && defined(SCTP)
#include <netinet/sctp_pcb.h>
#include <netinet/sctp.h>
#include <netinet/sctp_var.h>
#endif /* SCTP */

#include "carp.h"
#if NCARP > 0
#include <netinet/ip_carp.h>
#endif

#include "etherip.h"
#if NETHERIP > 0
#include <netinet/ip_etherip.h>
#endif

DOMAIN_DEFINE(inetdomain);	/* forward declare and add to link set */

#ifndef __QNXNTO__
const struct protosw inetsw[] = {
#else	
const struct protosw inetsw_default[] = {
#endif
{ 0,		&inetdomain,	0,		0,
  0,		ip_output,	0,		0,
  0,
  ip_init,	0,		ip_slowtimo,	ip_drain,
},
{
#ifndef __QNXNTO__
  SOCK_DGRAM,	&inetdomain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR|PR_PURGEIF,
#else
  SOCK_DGRAM,	&inetdomain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR|PR_PURGEIF|PR_SENSE_EXTEN,
#endif
  udp_input,	0,		udp_ctlinput,	udp_ctloutput,
  udp_usrreq,
  udp_init,	0,		0,		0,
},
{
#ifndef __QNXNTO__
  SOCK_STREAM,	&inetdomain,	IPPROTO_TCP,	PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN|PR_ABRTACPTDIS|PR_PURGEIF,
#else
  SOCK_STREAM,	&inetdomain,	IPPROTO_TCP,	PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN|PR_ABRTACPTDIS|PR_PURGEIF|PR_WAITALL_RCVD|PR_SENSE_EXTEN,
#endif
  tcp_input,	0,		tcp_ctlinput,	tcp_ctloutput,
  tcp_usrreq,
  tcp_init,	0,		tcp_slowtimo,	tcp_drain,
},
/*
 * SCTP place holder to let later loaded lsm-sctp.so init it
 * 
 * Order is very important here, we add the good one in
 * in this postion so it maps to the right ip_protox[]
 * postion for SCTP. Don't move the one above below
 * this one or IPv6/4 compatability will break
 *
 */
{    
	0, &inetdomain, 0
},
{
	0, &inetdomain, 0
},
{
	0, &inetdomain, 0
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_RAW,	PR_ATOMIC|PR_ADDR|PR_PURGEIF,
  rip_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  0,		0,		0,		0,
},
{
#ifndef __QNXNTO__
  SOCK_RAW,	&inetdomain,	IPPROTO_ICMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
#else
  SOCK_RAW,	&inetdomain,	IPPROTO_ICMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR|PR_SENSE_EXTEN,
#endif
  icmp_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  icmp_init,	0,		0,		0,
},
#ifdef IPSEC
{ SOCK_RAW,	&inetdomain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ah4_input,	0,	 	ah4_ctlinput,	0,
  0,
  0,		0,		0,		0,
},
#ifdef IPSEC_ESP
{ SOCK_RAW,	&inetdomain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  esp4_input,
  0,	 	esp4_ctlinput,	0,
  0,
  0,		0,		0,		0,
},
#endif
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipcomp4_input,
  0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
#endif /* IPSEC */
#ifdef FAST_IPSEC
{ SOCK_RAW,	&inetdomain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ipsec4_common_input,	0,	 	ah4_ctlinput,	0,
  0, 0,		0,		0,		0,
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  ipsec4_common_input,    0,	 	esp4_ctlinput,	0,
  0,
  0,		0,		0,		0,
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipsec4_common_input,    0,	 	0,		0,
  0,
  0,		0,		0,		0,
},
#endif /* FAST_IPSEC */
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV4,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	rip_output, 	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,	/*XXX*/
  encap_init,	0,		0,		0,
},
#ifdef INET6
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	rip_output, 	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,	/*XXX*/
  encap_init,	0,		0,		0,
},
#endif /* INET6 */
#if NETHERIP > 0
{ SOCK_RAW,	&inetdomain,	IPPROTO_ETHERIP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  ip_etherip_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  0,		0,		0,		0,
},
#endif
#if NCARP > 0
{ SOCK_RAW,	&inetdomain,	IPPROTO_CARP,	PR_ATOMIC|PR_ADDR,
  carp_proto_input,	rip_output,	0,		rip_ctloutput,
  rip_usrreq,
  0,		0,		0,		0,
},
#endif
#if NGRE > 0
{ SOCK_RAW,	&inetdomain,	IPPROTO_GRE,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  gre_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  0,		0,		0,		0,
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_MOBILE,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  gre_mobile_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  0,		0,		0,		0,
},
#endif /* NGRE > 0 */
{ SOCK_RAW,	&inetdomain,	IPPROTO_IGMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  igmp_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  NULL,		igmp_fasttimo,	igmp_slowtimo,	0,
},
#ifdef PIM
{ SOCK_RAW,	&inetdomain,	IPPROTO_PIM,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  pim_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  NULL,		0,		0,		0,
},
#endif /* PIM */
#ifdef TPIP
{ SOCK_SEQPACKET,&inetdomain,	IPPROTO_TP,	PR_CONNREQUIRED|PR_WANTRCVD|PR_LISTEN|PR_LASTHDR|PR_ABRTACPTDIS,
  tpip_input,	0,		tpip_ctlinput,	tp_ctloutput,
  tp_usrreq,
  tp_init,	0,		tp_slowtimo,	tp_drain,
},
#endif /* TPIP */
#ifdef ISO
/* EON (ISO CLNL over IP) */
#ifdef EON
{ SOCK_RAW,	&inetdomain,	IPPROTO_EON,	PR_LASTHDR,
  eoninput,	0,		eonctlinput,	0,
  0,
  eonprotoinit,	0,		0,		0,
},
#else
{ SOCK_RAW,	&inetdomain,	IPPROTO_EON,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,	/*XXX*/
  encap_init,	0,		0,		0,
},
#endif /* EON */
#endif /* ISO */
/* raw wildcard */
{
#ifndef __QNXNTO__
  SOCK_RAW,	&inetdomain,	0,		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
#else
  SOCK_RAW,	&inetdomain,	0,		PR_ATOMIC|PR_ADDR|PR_LASTHDR|PR_SENSE_EXTEN,
#endif
  rip_input,	rip_output,	rip_ctlinput,	rip_ctloutput,
  rip_usrreq,
  rip_init,	0,		0,		0,
},
};

#ifdef __QNXNTO__
static int
rnh_match_hint_inet(struct radix_node *t, void *hint)
{
	struct rtentry *rt;

	rt = (struct rtentry *)t;

	if (rt->rt_ifp == (struct ifnet *)hint)
		return 1;

	return 0;
}
#if defined(RADIX_MPATH)
int rn_mpath_inithead_inet(void **head, int off);

int
rn_mpath_inithead_inet(void **head, int off)
{
	int ret;
	struct radix_node_head *rnh;

	if ((ret = rn_mpath_inithead(head, off)) == 0)
		return 0;

	rnh = *head;
	rnh->rnh_match_hint = rnh_match_hint_inet;
	return ret;

}
#else
int rn_inithead_inet(void **head, int off);

int
rn_inithead_inet(void **head, int off)
{
	int ret;
	struct radix_node_head *rnh;

	if ((ret = rn_inithead(head, off)) == 0)
		return 0;

	rnh = *head;
	rnh->rnh_match_hint = rnh_match_hint_inet;
	return ret;

}
#endif //!defined(RADIX_MPATH)
#endif

#ifdef __QNXNTO__
struct protosw *inetsw = (struct protosw *)inetsw_default;
#endif
extern struct ifqueue ipintrq;

const struct sockaddr_in in_any = {
	  .sin_len = sizeof(struct sockaddr_in)
	, .sin_family = AF_INET
	, .sin_port = 0
	, .sin_addr = {.s_addr = 0 /* INADDR_ANY */}
};

struct domain inetdomain = {
	.dom_family = PF_INET, .dom_name = "internet", .dom_init = NULL,
	.dom_externalize = NULL, .dom_dispose = NULL,
#ifndef __QNXNTO__
	.dom_protosw = inetsw,
	.dom_protoswNPROTOSW = &inetsw[__arraycount(inetsw)],
	.dom_rtattach = rn_inithead,
#else
	.dom_protosw = inetsw_default,
	.dom_protoswNPROTOSW = &inetsw_default[__arraycount(inetsw_default)],
#if defined(RADIX_MPATH)
 	.dom_rtattach = rn_mpath_inithead_inet,
#else  // radix_mpath
 	.dom_rtattach = rn_inithead_inet,
#endif // radix_mpath
#endif // !__QNXNTO__
	.dom_rtoffset = 32, .dom_maxrtkey = sizeof(struct sockaddr_in),
#ifdef IPSELSRC
	.dom_ifattach = in_domifattach,
	.dom_ifdetach = in_domifdetach,
#else
	.dom_ifattach = NULL,
	.dom_ifdetach = NULL,
#endif
	.dom_ifqueues = { &ipintrq, NULL },
	.dom_link = { NULL },
	.dom_mowner = MOWNER_INIT("",""),
	.dom_sa_cmpofs = offsetof(struct sockaddr_in, sin_addr),
	.dom_sa_cmplen = sizeof(struct in_addr),
	.dom_sa_any = (const struct sockaddr *)&in_any,
	.dom_sockaddr_const_addr = sockaddr_in_const_addr,
	.dom_sockaddr_addr = sockaddr_in_addr,
	.dom_rtcache = LIST_HEAD_INITIALIZER(inetdomain.dom_rtcache)
};

u_char	ip_protox[IPPROTO_MAX];

int icmperrppslim = 100;			/* 100pps */

static void
sockaddr_in_addrlen(const struct sockaddr *sa, socklen_t *slenp)
{
	socklen_t slen;

	if (slenp == NULL)
		return;

	slen = sockaddr_getlen(sa);
	*slenp = (socklen_t)MIN(sizeof(struct in_addr),
	    slen - MIN(slen, offsetof(struct sockaddr_in, sin_addr)));
}

const void *
sockaddr_in_const_addr(const struct sockaddr *sa, socklen_t *slenp)
{
	const struct sockaddr_in *sin;

	sockaddr_in_addrlen(sa, slenp);
	sin = (const struct sockaddr_in *)sa;
	return &sin->sin_addr;
}

void *
sockaddr_in_addr(struct sockaddr *sa, socklen_t *slenp)
{
	struct sockaddr_in *sin;

	sockaddr_in_addrlen(sa, slenp);
	sin = (struct sockaddr_in *)sa;
	return &sin->sin_addr;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/in_proto.c $ $Rev: 680336 $")
#endif
