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

/*	$NetBSD: raw_ip6.c,v 1.78.8.1 2007/05/24 19:13:15 pavel Exp $	*/
/*	$KAME: raw_ip6.c,v 1.82 2001/07/23 18:57:56 jinmei Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)raw_ip.c	8.2 (Berkeley) 1/4/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: raw_ip6.c,v 1.78.8.1 2007/05/24 19:13:15 pavel Exp $");

#include "opt_ipsec.h"

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>
#include <netinet6/raw_ip6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec_var.h> /* XXX ipsecstat namespace */
#include <netipsec/ipsec6.h>
#endif

#include <machine/stdarg.h>

#include "faith.h"
#if defined(NFAITH) && 0 < NFAITH
#include <net/if_faith.h>
#endif

extern struct inpcbtable rawcbtable;
struct	inpcbtable raw6cbtable;
#define ifatoia6(ifa)	((struct in6_ifaddr *)(ifa))

/*
 * Raw interface to IP6 protocol.
 */

struct rip6stat rip6stat;
#ifdef __QNXNTO__
NLIST_EXPORT(rip6stat, rip6stat);
extern int ip_checkinterface;
#endif

/*
 * Initialize raw connection block queue.
 */
void
rip6_init()
{

	in6_pcbinit(&raw6cbtable, 1, 1);
}

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
int
rip6_input(mp, offp, proto)
	struct	mbuf **mp;
	int	*offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct inpcb_hdr *inph;
	struct in6pcb *in6p;
	struct in6pcb *last = NULL;
	struct sockaddr_in6 rip6src;
	struct mbuf *opts = NULL;

	rip6stat.rip6s_ipackets++;

#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6->ip6_dst)) {
		/* send icmp6 host unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}
#endif

	/* Be proactive about malicious use of IPv4 mapped address */
	if (IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)) {
		/* XXX stat */
		m_freem(m);
		return IPPROTO_DONE;
	}

	bzero(&rip6src, sizeof(rip6src));
	rip6src.sin6_len = sizeof(struct sockaddr_in6);
	rip6src.sin6_family = AF_INET6;
	rip6src.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&rip6src) != 0) {
		/* XXX: should be impossible. */
		m_freem(m);
		return IPPROTO_DONE;
	}

	CIRCLEQ_FOREACH(inph, &raw6cbtable.inpt_queue, inph_queue) {
		in6p = (struct in6pcb *)inph;
		if (in6p->in6p_af != AF_INET6)
			continue;
		if ((in6p->in6p_bounddevice != NULL &&
			m->m_pkthdr.rcvif != in6p->in6p_bounddevice) ||
		    (in6p->in6p_bounddevice == NULL &&
		    (in6p->in6p_flags & IN6P_DEVPURGE) != 0)) {
			continue;
		}
#ifdef QNX_MFIB
		if (in6p->in6p_socket != NULL && (if_get_fib_enabled(m->m_pkthdr.rcvif, in6p->in6p_socket->so_fibnum)))
			continue;
#endif
		if (in6p->in6p_ip6.ip6_nxt &&
		    in6p->in6p_ip6.ip6_nxt != proto)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (in6p->in6p_cksum != -1) {
			rip6stat.rip6s_isum++;
			if (in6_cksum(m, proto, *offp,
			    m->m_pkthdr.len - *offp)) {
				rip6stat.rip6s_badsum++;
				continue;
			}
		}
		if (last) {
			struct	mbuf *n;

#ifdef IPSEC
			/*
			 * Check AH/ESP integrity.
			 */
			if (QNXNTO_IPSEC_ENABLED && ipsec6_in_reject(m, last)) {
				ipsec6stat.in_polvio++;
				/* do not inject data into pcb */
			} else
#endif /* IPSEC */
#ifdef FAST_IPSEC
			/*
			 * Check AH/ESP integrity
			 */
			if (!QNXNTO_IPSEC_ENABLED || !ipsec6_in_reject(m,last)) 
#endif /* FAST_IPSEC */
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (last->in6p_flags & IN6P_CONTROLOPTS)
					ip6_savecontrol(last, &opts, ip6, n);
				/* strip intermediate headers */
				m_adj(n, *offp);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
				    (struct sockaddr *)&rip6src, n, opts) == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts)
						m_freem(opts);
					rip6stat.rip6s_fullsock++;
				} else
					sorwakeup(last->in6p_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (QNXNTO_IPSEC_ENABLED && last && ipsec6_in_reject(m, last)) {
		m_freem(m);
		ipsec6stat.in_polvio++;
		ip6stat.ip6s_delivered--;
		/* do not inject data into pcb */
	} else
#endif /* IPSEC */
#ifdef FAST_IPSEC
	if (QNXNTO_IPSEC_ENABLED && last && ipsec6_in_reject(m, last)) {
		m_freem(m);
		/*
		 * XXX ipsec6_in_reject update stat if there is an error
		 * so we just need to update stats by hand in the case of last is
		 * NULL
		 */
		if (!last)
			ipsec6stat.in_polvio++;
			ip6stat.ip6s_delivered--;
			/* do not inject data into pcb */
		} else
#endif /* FAST_IPSEC */
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS)
			ip6_savecontrol(last, &opts, ip6, m);
		/* strip intermediate headers */
		m_adj(m, *offp);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
		    (struct sockaddr *)&rip6src, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
			rip6stat.rip6s_fullsock++;
		} else
			sorwakeup(last->in6p_socket);
	} else {
		rip6stat.rip6s_nosock++;
		if (m->m_flags & M_MCAST)
			rip6stat.rip6s_nosockmcast++;
		if (proto == IPPROTO_NONE)
			m_freem(m);
		else {
			const int prvnxt = ip6_get_prevhdr(m, *offp);
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_protounknown);
			icmp6_error(m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_NEXTHEADER,
#ifndef QNX_MFIB
			    prvnxt);
#else
			    prvnxt, if_get_first_fib(m->m_pkthdr.rcvif));
#endif
		}
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}

void
rip6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	struct ip6_hdr *ip6;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	void *cmdarg;
	void (*notify) __P((struct in6pcb *, int)) = in6_rtchange;
	int nxt;
#ifdef __QNXNTO__
	struct ifnet *rcvif;
#endif

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd))
		notify = in6_rtchange, d = NULL;
	else if (cmd == PRC_HOSTDEAD)
		d = NULL;
	else if (cmd == PRC_MSGSIZE)
		; /* special code is present, see below */
	else if (inet6ctlerrmap[cmd] == 0)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		ip6 = ip6cp->ip6c_ip6;
		cmdarg = ip6cp->ip6c_cmdarg;
		sa6_src = ip6cp->ip6c_src;
		nxt = ip6cp->ip6c_nxt;
#ifdef __QNXNTO__
		if (ip6cp->ip6c_m) {
			rcvif = ip6cp->ip6c_m->m_pkthdr.rcvif;
		} else {
			rcvif = NULL;
		}
#endif
	} else {
		ip6 = NULL;
		cmdarg = NULL;
		sa6_src = &sa6_any;
		nxt = -1;
	}

	if (ip6 && cmd == PRC_MSGSIZE) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
		int valid = 0;
		struct in6pcb *in6p;

		/*
		 * Check to see if we have a valid raw IPv6 socket
		 * corresponding to the address in the ICMPv6 message
		 * payload, and the protocol (ip6_nxt) meets the socket.
		 * XXX chase extension headers, or pass final nxt value
		 * from icmp6_notify_error()
		 */
		in6p = NULL;
		in6p = in6_pcblookup_connect(&raw6cbtable, &sa6->sin6_addr, 0,
#ifndef __QNXNTO__
		    (const struct in6_addr *)&sa6_src->sin6_addr, 0, 0);
#else
		    (const struct in6_addr *)&sa6_src->sin6_addr, 0, 0, ip_checkinterface ? rcvif : NULL);
#endif
#if 0
		if (!in6p) {
			/*
			 * As the use of sendto(2) is fairly popular,
			 * we may want to allow non-connected pcb too.
			 * But it could be too weak against attacks...
			 * We should at least check if the local
			 * address (= s) is really ours.
			 */
			in6p = in6_pcblookup_bind(&raw6cbtable,
#ifndef __QNXNTO__
			    &sa6->sin6_addr, 0, 0);
#else
			    &sa6->sin6_addr, 0, 0, ip_checkinterface ? rcvif : NULL);
#endif
		}
#endif

		if (in6p && in6p->in6p_ip6.ip6_nxt &&
		    in6p->in6p_ip6.ip6_nxt == nxt)
			valid++;

		/*
		 * Depending on the value of "valid" and routing table
		 * size (mtudisc_{hi,lo}wat), we will:
		 * - recalculate the new MTU and create the
		 *   corresponding routing entry, or
		 * - ignore the MTU change notification.
		 */
		icmp6_mtudisc_update((struct ip6ctlparam *)d, valid);

		/*
		 * regardless of if we called icmp6_mtudisc_update(),
		 * we need to call in6_pcbnotify(), to notify path MTU
		 * change to the userland (RFC3542), because some
		 * unconnected sockets may share the same destination
		 * and want to know the path MTU.
		 */
	}

	(void) in6_pcbnotify(&raw6cbtable, sa, 0,
	    (const struct sockaddr *)sa6_src, 0, cmd, cmdarg, notify);
}

/*
 * Generate IPv6 header and pass packet to ip6_output.
 * Tack on options user may have setup with control call.
 */
int
#if __STDC__
rip6_output(struct mbuf *m, ...)
#else
rip6_output(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	struct socket *so;
	struct sockaddr_in6 *dstsock;
	struct mbuf *control;
	struct in6_addr *dst;
	struct ip6_hdr *ip6;
	struct in6pcb *in6p;
	u_int	plen = m->m_pkthdr.len;
	int error = 0;
	struct ip6_pktopts opt, *optp = NULL;
	struct ifnet *oifp = NULL;
	int type, code;		/* for ICMPv6 output statistics only */
	int scope_ambiguous = 0;
	struct in6_addr *in6a;
	va_list ap;

	va_start(ap, m);
	so = va_arg(ap, struct socket *);
	dstsock = va_arg(ap, struct sockaddr_in6 *);
	control = va_arg(ap, struct mbuf *);
	va_end(ap);

#ifdef QNX_MFIB
	int fib;
	if (so)
		fib = so->so_fibnum;
	else
		panic("rip6_output: couldn't select a fib");
#endif

	in6p = sotoin6pcb(so);

	dst = &dstsock->sin6_addr;
	if (control) {
		if ((error = ip6_setpktopts(control, &opt,
		    in6p->in6p_outputopts,
		    kauth_cred_get(), so->so_proto->pr_protocol)) != 0) {
			goto bad;
		}
		optp = &opt;
	} else
		optp = in6p->in6p_outputopts;

	/*
	 * Check and convert scope zone ID into internal form.
	 * XXX: we may still need to determine the zone later.
	 */
	if (!(so->so_state & SS_ISCONNECTED)) {
		if (dstsock->sin6_scope_id == 0 && !ip6_use_defzone)
			scope_ambiguous = 1;
		if ((error = sa6_embedscope(dstsock, ip6_use_defzone)) != 0)
			goto bad;
	}

	/*
	 * For an ICMPv6 packet, we should know its type and code
	 * to update statistics.
	 */
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icmp6;
		if (m->m_len < sizeof(struct icmp6_hdr) &&
		    (m = m_pullup(m, sizeof(struct icmp6_hdr))) == NULL) {
			error = ENOBUFS;
			goto bad;
		}
		icmp6 = mtod(m, struct icmp6_hdr *);
		type = icmp6->icmp6_type;
		code = icmp6->icmp6_code;
	} else {
		type = 0;
		code = 0;
	}

	M_PREPEND(m, sizeof(*ip6), M_DONTWAIT);
	if (!m) {
		error = ENOBUFS;
		goto bad;
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/*
	 * Next header might not be ICMP6 but use its pseudo header anyway.
	 */
	ip6->ip6_dst = *dst;

	/*
	 * Source address selection.
	 */
#ifndef __QNXNTO__
	if ((in6a = in6_selectsrc(dstsock, optp, in6p->in6p_moptions,
	    &in6p->in6p_route, &in6p->in6p_laddr, &oifp, &error)) == 0) {
#else
#ifndef QNX_MFIB
	if ((in6a = in6_selectsrc(dstsock, optp, in6p->in6p_moptions,
	    &in6p->in6p_route, &in6p->in6p_laddr, &oifp, &error, in6p->in6p_bounddevice)) == 0) {
#else
	if ((in6a = in6_selectsrc(dstsock, optp, in6p->in6p_moptions,
	    &in6p->in6p_route, &in6p->in6p_laddr, &oifp, &error, in6p->in6p_bounddevice, fib)) == 0) {
#endif
#endif
		if (error == 0)
			error = EADDRNOTAVAIL;
		goto bad;
	}
	ip6->ip6_src = *in6a;

	if (oifp && scope_ambiguous) {
		/*
		 * Application should provide a proper zone ID or the use of
		 * default zone IDs should be enabled.  Unfortunately, some
		 * applications do not behave as it should, so we need a
		 * workaround.  Even if an appropriate ID is not determined
		 * (when it's required), if we can determine the outgoing
		 * interface. determine the zone ID based on the interface.
		 */
		error = in6_setscope(&dstsock->sin6_addr, oifp, NULL);
		if (error != 0)
			goto bad;
	}
	ip6->ip6_dst = dstsock->sin6_addr;

	/* fill in the rest of the IPv6 header fields */
	ip6->ip6_flow = in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK;
	ip6->ip6_vfc  &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc  |= IPV6_VERSION;
	/* ip6_plen will be filled in ip6_output, so not fill it here. */
	ip6->ip6_nxt   = in6p->in6p_ip6.ip6_nxt;
	ip6->ip6_hlim = in6_selecthlim(in6p, oifp);

	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6 ||
	    in6p->in6p_cksum != -1) {
		const uint8_t nxt = ip6->ip6_nxt;
		int off;
		u_int16_t sum;

		/* compute checksum */
		if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
			off = offsetof(struct icmp6_hdr, icmp6_cksum);
		else
			off = in6p->in6p_cksum;
		if (plen < off + 1) {
			error = EINVAL;
			goto bad;
		}
		off += sizeof(struct ip6_hdr);

		sum = 0;
		m = m_copyback_cow(m, off, sizeof(sum), (caddr_t)&sum,
		    M_DONTWAIT);
		if (m == NULL) {
			error = ENOBUFS;
			goto bad;
		}
		sum = in6_cksum(m, nxt, sizeof(*ip6), plen);
		m = m_copyback_cow(m, off, sizeof(sum), (caddr_t)&sum,
		    M_DONTWAIT);
		if (m == NULL) {
			error = ENOBUFS;
			goto bad;
		}
	}

	error = ip6_output(m, optp, &in6p->in6p_route, 0,
		in6p->in6p_moptions, so, &oifp
#ifdef __QNXNTO__
		, in6p->in6p_bounddevice, NULL
#ifdef QNX_MFIB
		, fib
#endif
#endif
		);
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		if (oifp)
			icmp6_ifoutstat_inc(oifp, type, code);
		icmp6stat.icp6s_outhist[type]++;
	} else
		rip6stat.rip6s_opackets++;

	goto freectl;

 bad:
	if (m)
		m_freem(m);

 freectl:
	if (control) {
		ip6_clearpktopts(&opt, -1);
		m_freem(control);
	}
	return (error);
}

/*
 * Raw IPv6 socket option processing.
 */
int
rip6_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
	int error = 0;

	switch (level) {
#ifdef __QNXNTO__
	/*
	 * Socket level option but the route is often
	 * cached in in6p_route so handle it at IP.
	 */
	case SOL_SOCKET:
		if (optname == SO_BINDTODEVICE) {
			return ip6_ctloutput(op, so, level, optname, mp);
		}
		else if (op == PRCO_SETOPT && *mp)
			m_free(*mp);
		return EINVAL;
#endif
	case IPPROTO_IPV6:
		switch (optname) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			if (op == PRCO_SETOPT) {
				error = ip6_mrouter_set(optname, so, *mp);
				if (*mp)
					(void)m_free(*mp);
			} else if (op == PRCO_GETOPT)
				error = ip6_mrouter_get(optname, so, mp);
			else
				error = EINVAL;
			return (error);
		case IPV6_CHECKSUM:
			return (ip6_raw_ctloutput(op, so, level, optname, mp));
		default:
			return (ip6_ctloutput(op, so, level, optname, mp));
		}

	case IPPROTO_ICMPV6:
		/*
		 * XXX: is it better to call icmp6_ctloutput() directly
		 * from protosw?
		 */
		return (icmp6_ctloutput(op, so, level, optname, mp));

	default:
		if (op == PRCO_SETOPT && *mp)
			m_free(*mp);
		return EINVAL;
	}
}

extern	u_long rip6_sendspace;
extern	u_long rip6_recvspace;

int
rip6_usrreq(struct socket *so, int req, struct mbuf *m, 
	struct mbuf *nam, struct mbuf *control, struct lwp *l)
{
	struct in6pcb *in6p = sotoin6pcb(so);
	int s;
	int error = 0;

	if (req == PRU_CONTROL)
		return in6_control(so, (u_long)m, (void *)nam,
		    (struct ifnet *)control, l);

	if (req == PRU_PURGEIF) {
		in6_pcbpurgeif0(&raw6cbtable, (struct ifnet *)control);
		in6_purgeif((struct ifnet *)control);
		in6_pcbpurgeif(&raw6cbtable, (struct ifnet *)control);
		return 0;
	}

	switch (req) {
	case PRU_ATTACH:
		error = kauth_authorize_network(l->l_cred,
		    KAUTH_NETWORK_SOCKET, KAUTH_REQ_NETWORK_SOCKET_RAWSOCK,
		    NULL, NULL, NULL);
		if (in6p != NULL)
			panic("rip6_attach");
		if (error) {
			break;
		}
		s = splsoftnet();
		error = soreserve(so, rip6_sendspace, rip6_recvspace);
		if (error != 0) {
			splx(s);
			break;
		}
		if ((error = in6_pcballoc(so, &raw6cbtable)) != 0) {
			splx(s);
			break;
		}
		splx(s);
		in6p = sotoin6pcb(so);
		in6p->in6p_ip6.ip6_nxt = (long)nam;
		in6p->in6p_cksum = -1;

		MALLOC(in6p->in6p_icmp6filt, struct icmp6_filter *,
		    sizeof(struct icmp6_filter), M_PCB, M_NOWAIT);
		if (in6p->in6p_icmp6filt == NULL) {
			in6_pcbdetach(in6p);
			error = ENOMEM;
			break;
		}
		ICMP6_FILTER_SETPASSALL(in6p->in6p_icmp6filt);
		break;

	case PRU_DISCONNECT:
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			error = ENOTCONN;
			break;
		}
#ifdef __QNXNTO__
		if (in6p->in6p_socket && (in6p->in6p_socket->so_options & SO_BINDTODEVICE) == 0)
			in6p->in6p_bounddevice = NULL;
#endif
		in6p->in6p_faddr = in6addr_any;
		so->so_state &= ~SS_ISCONNECTED;	/* XXX */
		break;

	case PRU_ABORT:
		soisdisconnected(so);
		/* Fallthrough */
	case PRU_DETACH:
		if (in6p == 0)
			panic("rip6_detach");
		if (so == ip6_mrouter)
			ip6_mrouter_done();
		/* xxx: RSVP */
		if (in6p->in6p_icmp6filt) {
			FREE(in6p->in6p_icmp6filt, M_PCB);
			in6p->in6p_icmp6filt = NULL;
		}
		in6_pcbdetach(in6p);
		break;

	case PRU_BIND:
	    {
		struct sockaddr_in6 *addr = mtod(nam, struct sockaddr_in6 *);
		struct ifaddr *ia = NULL;

		if (nam->m_len != sizeof(*addr)) {
			error = EINVAL;
			break;
		}
		if ((ifnet.tqh_first == 0) || (addr->sin6_family != AF_INET6)) {
			error = EADDRNOTAVAIL;
			break;
		}
		if ((error = sa6_embedscope(addr, ip6_use_defzone)) != 0)
			break;

		/*
		 * we don't support mapped address here, it would confuse
		 * users so reject it
		 */
		if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
			error = EADDRNOTAVAIL;
			break;
		}
		if (!IN6_IS_ADDR_UNSPECIFIED(&addr->sin6_addr) &&
#ifndef __QNXNTO__
		    (ia = ifa_ifwithaddr((struct sockaddr *)addr)) == 0) {
#else
		    (ia = (ifa_ifwithaddr)((struct sockaddr *)addr, in6p->in6p_bounddevice
#ifdef QNX_MFIB
		    		, so->so_fibnum
#endif
		    		)) == 0) {
#endif
			error = EADDRNOTAVAIL;
			break;
		}
		if (ia && ((struct in6_ifaddr *)ia)->ia6_flags &
		    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|
		     IN6_IFF_DETACHED|IN6_IFF_DEPRECATED)) {
			error = EADDRNOTAVAIL;
			break;
		}
		in6p->in6p_laddr = addr->sin6_addr;
		break;
	    }

	case PRU_CONNECT:
	{
		struct sockaddr_in6 *addr = mtod(nam, struct sockaddr_in6 *);
		struct in6_addr *in6a = NULL;
		struct ifnet *ifp = NULL;
		int scope_ambiguous = 0;

		if (nam->m_len != sizeof(*addr)) {
			error = EINVAL;
			break;
		}
		if (ifnet.tqh_first == 0)
		{
			error = EADDRNOTAVAIL;
			break;
		}
		if (addr->sin6_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}

		/*
		 * Application should provide a proper zone ID or the use of
		 * default zone IDs should be enabled.  Unfortunately, some
		 * applications do not behave as it should, so we need a
		 * workaround.  Even if an appropriate ID is not determined,
		 * we'll see if we can determine the outgoing interface.  If we
		 * can, determine the zone ID based on the interface below.
		 */
		if (addr->sin6_scope_id == 0 && !ip6_use_defzone)
			scope_ambiguous = 1;
		if ((error = sa6_embedscope(addr, ip6_use_defzone)) != 0)
			return(error);

		/* Source address selection. XXX: need pcblookup? */
#ifndef __QNXNTO__
		in6a = in6_selectsrc(addr, in6p->in6p_outputopts,
		    in6p->in6p_moptions, &in6p->in6p_route,
		    &in6p->in6p_laddr, &ifp, &error);
#else
#ifndef QNX_MFIB
		in6a = in6_selectsrc(addr, in6p->in6p_outputopts,
		    in6p->in6p_moptions, &in6p->in6p_route,
		    &in6p->in6p_laddr, &ifp, &error, in6p->in6p_bounddevice);
#else
		in6a = in6_selectsrc(addr, in6p->in6p_outputopts,
		    in6p->in6p_moptions, &in6p->in6p_route,
		    &in6p->in6p_laddr, &ifp, &error, in6p->in6p_bounddevice, so->so_fibnum);
#endif
#endif
		if (in6a == NULL) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			break;
		}
		/* XXX: see above */
		if (ifp && scope_ambiguous &&
		    (error = in6_setscope(&addr->sin6_addr, ifp, NULL)) != 0) {
			break;
		}
#ifdef __QNXNTO__
		if (ip_bindinterface) {
			if (ifp != NULL) {
				in6p->in6p_bounddevice = ifp;
			} else {
				/* 
				 * If we're required to be bound, but there's no
				 * interface, abort connection.
				 */
				error = EADDRNOTAVAIL;
				break;
			}
		}
#endif
		in6p->in6p_laddr = *in6a;
		in6p->in6p_faddr = addr->sin6_addr;
		soisconnected(so);
		break;
	}

	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	/*
	 * Mark the connection as being incapable of futther input.
	 */
	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;
	/*
	 * Ship a packet out. The appropriate raw output
	 * routine handles any messaging necessary.
	 */
	case PRU_SEND:
	{
		struct sockaddr_in6 tmp;
		struct sockaddr_in6 *dst;

		/* always copy sockaddr to avoid overwrites */
		if (so->so_state & SS_ISCONNECTED) {
			if (nam) {
				error = EISCONN;
				break;
			}
			/* XXX */
			bzero(&tmp, sizeof(tmp));
			tmp.sin6_family = AF_INET6;
			tmp.sin6_len = sizeof(struct sockaddr_in6);
			bcopy(&in6p->in6p_faddr, &tmp.sin6_addr,
			    sizeof(struct in6_addr));
			dst = &tmp;
		} else {
			if (nam == NULL) {
				error = ENOTCONN;
				break;
			}
			if (nam->m_len != sizeof(tmp)) {
				error = EINVAL;
				break;
			}

			tmp = *mtod(nam, struct sockaddr_in6 *);
			dst = &tmp;

			if (dst->sin6_family != AF_INET6) {
				error = EAFNOSUPPORT;
				break;
			}
		}
		error = rip6_output(m, so, dst, control);
		m = NULL;
		break;
	}

	case PRU_SENSE:
		/*
		 * stat: don't bother with a blocksize
		 */
		return (0);
	/*
	 * Not supported.
	 */
	case PRU_RCVOOB:
	case PRU_RCVD:
	case PRU_LISTEN:
	case PRU_ACCEPT:
	case PRU_SENDOOB:
		error = EOPNOTSUPP;
		break;

	case PRU_SOCKADDR:
		in6_setsockaddr(in6p, nam);
		break;

	case PRU_PEERADDR:
		in6_setpeeraddr(in6p, nam);
		break;

	default:
		panic("rip6_usrreq");
	}
	if (m != NULL)
		m_freem(m);
	return (error);
}

SYSCTL_SETUP(sysctl_net_inet6_raw6_setup, "sysctl net.inet6.raw6 subtree setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "inet6", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET6, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "raw6",
		       SYSCTL_DESCR("Raw IPv6 settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET6, IPPROTO_RAW, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "pcblist",
		       SYSCTL_DESCR("Raw IPv6 control block list"),
		       sysctl_inpcblist, 0, &raw6cbtable, 0,
		       CTL_NET, PF_INET6, IPPROTO_RAW,
		       CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("Raw IPv6 statistics"),
		       NULL, 0, &rip6stat, sizeof(rip6stat),
		       CTL_NET, PF_INET6, IPPROTO_RAW, RAW6CTL_STATS,
		       CTL_EOL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/raw_ip6.c $ $Rev: 881150 $")
#endif
