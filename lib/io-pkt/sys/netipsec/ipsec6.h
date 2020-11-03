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

/*	$NetBSD: ipsec6.h,v 1.4.24.1 2007/05/24 19:13:13 pavel Exp $	*/
/*	$FreeBSD: src/sys/netipsec/ipsec6.h,v 1.1.4.1 2003/01/24 05:11:35 sam Exp $	*/
/*	$KAME: ipsec.h,v 1.44 2001/03/23 08:08:47 itojun Exp $	*/

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
 * IPsec controller part.
 */

#ifndef _NETIPSEC_IPSEC6_H_
#define _NETIPSEC_IPSEC6_H_

#include <net/pfkeyv2.h>
#include <netipsec/keydb.h>
#if defined(__NetBSD__) || defined(__QNXNTO__)
#include <netinet6/in6_pcb.h>
#endif

#ifdef _KERNEL
extern int ip6_esp_trans_deflev;
extern int ip6_esp_net_deflev;
extern int ip6_ah_trans_deflev;
extern int ip6_ah_net_deflev;
extern int ip6_ipsec_ecn;
extern int ip6_esp_randpad;
extern struct secpolicy ip6_def_policy;

struct inpcb;
struct in6pcb;

/* KAME compatibility shims */
#define	ipsec6_getpolicybyaddr	ipsec_getpolicybyaddr
#define	ipsec6_getpolicybysock	ipsec_getpolicybysock
#define	ipsec6stat		newipsecstat
#define	out_inval		ips_out_inval
#define	in_polvio		ips_in_polvio
#define	out_polvio		ips_out_polvio
#define	key_freesp(_x)		KEY_FREESP(&_x)

extern int ipsec6_delete_pcbpolicy __P((struct in6pcb *));
extern int ipsec6_set_policy __P((struct in6pcb *inp, int optname,
	caddr_t request, size_t len, kauth_cred_t));
extern int ipsec6_get_policy
	__P((struct in6pcb *inp, caddr_t request, size_t len, struct mbuf **mp));
extern struct secpolicy *ipsec6_checkpolicy __P((struct mbuf *, u_int, 
    u_int, int *, struct in6pcb *
#ifdef __QNXNTO__
    , struct ifnet *
#endif
	));
struct secpolicy * ipsec6_check_policy(struct mbuf *, 
				const struct socket *, int, int*,int*
#ifdef __QNXNTO__
				, struct ifnet *
#endif
				);
extern int ipsec6_in_reject __P((struct mbuf *, struct in6pcb *));
/*
 * KAME ipsec6_in_reject_so(struct mbuf*, struct so)  compatibility shim
 */
#define ipsec6_in_reject_so(m, _so) \
  ipsec6_in_reject(m, ((_so) == NULL? NULL : sotoin6pcb(_so)))

struct tcp6cb;

extern size_t ipsec6_hdrsiz __P((struct mbuf *, u_int, struct in6pcb *));
extern size_t ipsec6_hdrsiz_tcp __P((struct tcpcb*));

struct ip6_hdr;
extern const char *ipsec6_logpacketstr __P((struct ip6_hdr *, u_int32_t));

#if defined(__NetBSD__) || defined(__QNXNTO__)
/* NetBSD protosw ctlin entrypoint */
extern void esp6_ctlinput __P((int, struct sockaddr *, void *));
extern void ah6_ctlinput __P((int, struct sockaddr *, void *));
#endif /* __NetBSD__  || __QNXNTO__ */

struct m_tag;
extern int ipsec6_common_input(struct mbuf **mp, int *offp, int proto);
extern int ipsec6_common_input_cb(struct mbuf *m, struct secasvar *sav,
			int skip, int protoff, struct m_tag *mt);
extern void esp6_ctlinput(int, struct sockaddr *, void *);

struct ipsec_output_state;

int ipsec6_process_packet __P((struct mbuf*,struct ipsecrequest *)); 
#endif /*_KERNEL*/

#endif /* !_NETIPSEC_IPSEC6_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netipsec/ipsec6.h $ $Rev: 749676 $")
#endif
