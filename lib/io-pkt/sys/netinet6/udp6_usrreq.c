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



/*	$NetBSD: udp6_usrreq.c,v 1.90 2011/09/24 17:22:14 christos Exp $	*/
/*	$KAME: udp6_usrreq.c,v 1.86 2001/05/27 17:33:00 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)udp_var.h	8.1 (Berkeley) 6/10/93
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: udp6_usrreq.c,v 1.90 2011/09/24 17:22:14 christos Exp $");

#include "opt_inet.h"
#ifdef __QNXNTO__
#include "opt_inet.h"
#include "opt_ipsec.h"
#include "opt_pru_sense.h"
#endif

#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/nlist.h>
#endif
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/proc.h>
#ifdef __QNXNTO__
#include <sys/domain.h>
#endif
#include <sys/syslog.h>
#include <sys/domain.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/udp6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet/in_offload.h>

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_faith.h>
#endif

#ifdef __QNXNTO__
#undef errno
#ifdef OPT_PRU_SENSE_EXTEN
static const char *udp_prefix = "UDP";
#endif
#endif

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */

extern struct inpcbtable udbtable;
struct	udp6stat udp6stat;
#ifdef __QNXNTO__
NLIST_EXPORT(udp6stat, udp6stat);
#endif

static	void udp6_notify __P((struct in6pcb *, int));

void
udp6_init()
{
	/* initialization done in udp_input() due to initialization order */
}

/*
 * Notify a udp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
static	void
udp6_notify(in6p, errno)
	struct in6pcb *in6p;
	int errno;
{
	in6p->in6p_socket->so_error = errno;
	sorwakeup(in6p->in6p_socket);
	sowwakeup(in6p->in6p_socket);
}

void
udp6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	struct udphdr uh;
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
	struct mbuf *m;
	int off;
	void *cmdarg;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	void (*notify)(struct in6pcb *, int) = udp6_notify;
	struct udp_portonly {
		u_int16_t uh_sport;
		u_int16_t uh_dport;
	} *uhp;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd))
		notify = in6_rtchange, d = NULL;
	else if (cmd == PRC_HOSTDEAD)
		d = NULL;
	else if (cmd == PRC_MSGSIZE) {
		/* special code is present, see below */
		notify = in6_rtchange;
	}
	else if (inet6ctlerrmap[cmd] == 0)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		cmdarg = ip6cp->ip6c_cmdarg;
		sa6_src = ip6cp->ip6c_src;
	} else {
		m = NULL;
		ip6 = NULL;
		cmdarg = NULL;
		sa6_src = &sa6_any;
		off = 0;
	}

	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */

		/* check if we can safely examine src and dst ports */
		if (m->m_pkthdr.len < off + sizeof(*uhp)) {
			if (cmd == PRC_MSGSIZE)
				icmp6_mtudisc_update((struct ip6ctlparam *)d, 0);
			return;
		}

		memset(&uh, 0, sizeof(uh));
		m_copydata(m, off, sizeof(*uhp), (caddr_t)&uh);

		if (cmd == PRC_MSGSIZE) {
			int valid = 0;

			/*
			 * Check to see if we have a valid UDP socket
			 * corresponding to the address in the ICMPv6 message
			 * payload.
			 */
			if (in6_pcblookup_connect(&udbtable, &sa6->sin6_addr,
			    uh.uh_dport, (const struct in6_addr *)&sa6_src->sin6_addr,
#ifndef __QNXNTO__
			    uh.uh_sport, 0))
#else
			    uh.uh_sport, 0, m->m_pkthdr.rcvif))
#endif
				valid++;
#if 0
			/*
			 * As the use of sendto(2) is fairly popular,
			 * we may want to allow non-connected pcb too.
			 * But it could be too weak against attacks...
			 * We should at least check if the local address (= s)
			 * is really ours.
			 */
			else if (in6_pcblookup_bind(&udbtable, &sa6->sin6_addr,
			    uh.uh_dport, 0))
				valid++;
#endif

			/*
			 * Depending on the value of "valid" and routing table
			 * size (mtudisc_{hi,lo}wat), we will:
			 * - recalculate the new MTU and create the
			 *   corresponding routing entry, or
			 * - ignore the MTU change notification.
			 */
			icmp6_mtudisc_update((struct ip6ctlparam *)d, valid);

			/*
			 * regardless of if we called
			 * icmp6_mtudisc_update(), we need to call
			 * in6_pcbnotify(), to notify path MTU change
			 * to the userland (RFC3542), because some
			 * unconnected sockets may share the same
			 * destination and want to know the path MTU.
			 */
		}

		(void) in6_pcbnotify(&udbtable, sa, uh.uh_dport,
		    (const struct sockaddr *)sa6_src, uh.uh_sport, cmd, cmdarg,
		    notify);
	} else {
		(void) in6_pcbnotify(&udbtable, sa, 0,
		    (const struct sockaddr *)sa6_src, 0, cmd, cmdarg, notify);
	}
	return;
}

#ifdef __QNXNTO__

int
udp6_ctloutput(int op, struct socket *so, int level, int optname,
	struct mbuf **mp)
{
	int s;
	int error = 0;
	struct mbuf *m;
	struct in6pcb *in6p;
	int family;

	family = so->so_proto->pr_domain->dom_family;

	s = splsoftnet();
	switch (family) {
#ifdef INET
	case PF_INET:
		if (level != IPPROTO_UDP) {
			error = ip_ctloutput(op, so, level, optname, mp);
			goto end;
		}
		break;
#endif
#ifdef INET6
	case PF_INET6:
		if (level != IPPROTO_UDP) {
			error = ip6_ctloutput(op, so, level, optname, mp);
			goto end;
		}
		break;
#endif
	default:
		error = EAFNOSUPPORT;
		goto end;
	}

	switch(op) {
	case PRCO_SETOPT:
		m = *mp;
		in6p = sotoin6pcb(so);

		switch (optname) {
		case UDP_ENCAP:
			if (m == NULL || m->m_len < sizeof (int)) {
				error = EINVAL;
				break;
			}
		
			switch(*mtod(m, int *)) {
#ifdef IPSEC_NAT_T
			case 0:
				in6p->in6p_flags &= ~INP_ESPINUDP_ALL;
				break;

			case UDP_ENCAP_ESPINUDP:
				in6p->in6p_flags &= ~INP_ESPINUDP_ALL;
				in6p->in6p_flags |= INP_ESPINUDP;
				break;

			case UDP_ENCAP_ESPINUDP_NON_IKE:
				in6p->in6p_flags &= ~INP_ESPINUDP_ALL;
				in6p->in6p_flags |= INP_ESPINUDP_NON_IKE;
				break;
#endif
			default:
				error = EINVAL;
				break;
			}
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m != NULL) {
			m_free(m);
		}
		break;

	default:
		error = EINVAL;
		break;
	}

end:
	splx(s);
	return error;
}	

#endif		

extern	int udp6_sendspace;
extern	int udp6_recvspace;

int
udp6_usrreq(so, req, m, addr6, control, l)
	struct socket *so;
	int req;
	struct mbuf *m, *addr6, *control;
	struct lwp *l;
{
	struct	in6pcb *in6p = sotoin6pcb(so);
	int	error = 0;
	int	s;

	/*
	 * MAPPED_ADDR implementation info:
	 *  Mapped addr support for PRU_CONTROL is not necessary.
	 *  Because typical user of PRU_CONTROL is such as ifconfig,
	 *  and they don't associate any addr to their socket.  Then
	 *  socket family is only hint about the PRU_CONTROL'ed address
	 *  family, especially when getting addrs from kernel.
	 *  So AF_INET socket need to be used to control AF_INET addrs,
	 *  and AF_INET6 socket for AF_INET6 addrs.
	 */
	if (req == PRU_CONTROL)
		return (in6_control(so, (u_long)m, (caddr_t)addr6,
				   (struct ifnet *)control, l));

	if (req == PRU_PURGEIF) {
		in6_pcbpurgeif0(&udbtable, (struct ifnet *)control);
		in6_purgeif((struct ifnet *)control);
		in6_pcbpurgeif(&udbtable, (struct ifnet *)control);
		return (0);
	}

#ifndef __QNXNTO__
	if (in6p == NULL && req != PRU_ATTACH) {
#else
	if (in6p == NULL && req != PRU_ATTACH && req != PRU_SENSE)
#endif
	{
		error = EINVAL;
		goto release;
	}

	switch (req) {
	case PRU_ATTACH:
		/*
		 * MAPPED_ADDR implementation spec:
		 *  Always attach for IPv6,
		 *  and only when necessary for IPv4.
		 */
		if (in6p != NULL) {
			error = EINVAL;
			break;
		}
		s = splsoftnet();
		error = in6_pcballoc(so, &udbtable);
		splx(s);
		if (error)
			break;
		error = soreserve(so, udp6_sendspace, udp6_recvspace);
		if (error)
			break;
		in6p = sotoin6pcb(so);
		in6p->in6p_cksum = -1;	/* just to be sure */
		break;

	case PRU_DETACH:
		in6_pcbdetach(in6p);
		break;

	case PRU_BIND:
		s = splsoftnet();
		error = in6_pcbbind(in6p, addr6, l);
		splx(s);
		break;

	case PRU_LISTEN:
		error = EOPNOTSUPP;
		break;

	case PRU_CONNECT:
#ifdef __QNXNTO__
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr))
			so->so_state |= SS_IMPLICIT;
#endif
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			error = EISCONN;
			break;
		}
		s = splsoftnet();
		error = in6_pcbconnect(in6p, addr6, l);
		splx(s);
		if (error == 0)
			soisconnected(so);
		break;

	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	case PRU_ACCEPT:
		error = EOPNOTSUPP;
		break;

	case PRU_DISCONNECT:
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			error = ENOTCONN;
			break;
		}
		s = splsoftnet();
		in6_pcbdisconnect(in6p);
		memset((void *)&in6p->in6p_laddr, 0, sizeof(in6p->in6p_laddr));
		splx(s);
		so->so_state &= ~SS_ISCONNECTED;		/* XXX */
		in6_pcbstate(in6p, IN6P_BOUND);		/* XXX */
		break;

	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;

	case PRU_SEND:
		return (udp6_output(in6p, m, addr6, control, l));

	case PRU_ABORT:
		soisdisconnected(so);
		in6_pcbdetach(in6p);
		break;

	case PRU_SOCKADDR:
		in6_setsockaddr(in6p, addr6);
		break;

	case PRU_PEERADDR:
		in6_setpeeraddr(in6p, addr6);
		break;

	case PRU_SENSE:
#ifdef __QNXNTO__
		/*
		 * Non NULL 4th parameter means true protocol
		 * specific info is being requested rather than
		 * the generic fstat().
		 */
		if (addr6 != NULL) {
#ifndef OPT_PRU_SENSE_EXTEN
			return EOPNOTSUPP;
#else
			char *dst;
			struct proto_sensereq *prs;

			prs = (struct proto_sensereq *)addr6;

			switch (prs->prs_how) {
			case PRSENSEREQ_STRING:
				dst = (char *)m;

				error = in6_pcbformat(in6p, udp_prefix, NULL, 1, dst, &prs->prs_maxlen);
				if (error)
					return error;
				break;

			default:
				return EOPNOTSUPP;
			}

			return 0;
#endif
		}
#endif
		/*
		 * stat: don't bother with a blocksize
		 */
		return (0);

	case PRU_SENDOOB:
	case PRU_FASTTIMO:
	case PRU_SLOWTIMO:
	case PRU_PROTORCV:
	case PRU_PROTOSEND:
		error = EOPNOTSUPP;
		break;

	case PRU_RCVD:
	case PRU_RCVOOB:
		return (EOPNOTSUPP);	/* do not free mbuf's */

	default:
		panic("udp6_usrreq");
	}

release:
	if (control)
		m_freem(control);
	if (m)
		m_freem(m);
	return (error);
}

SYSCTL_SETUP(sysctl_net_inet6_udp6_setup, "sysctl net.inet6.udp6 subtree setup")
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
		       CTLTYPE_NODE, "udp6",
		       SYSCTL_DESCR("UDPv6 related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_INET6, IPPROTO_UDP, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "sendspace",
		       SYSCTL_DESCR("Default UDP send buffer size"),
		       NULL, 0, &udp6_sendspace, 0,
		       CTL_NET, PF_INET6, IPPROTO_UDP, UDP6CTL_SENDSPACE,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "recvspace",
		       SYSCTL_DESCR("Default UDP receive buffer size"),
		       NULL, 0, &udp6_recvspace, 0,
		       CTL_NET, PF_INET6, IPPROTO_UDP, UDP6CTL_RECVSPACE,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "do_loopback_cksum",
		       SYSCTL_DESCR("Perform UDP checksum on loopback"),
		       NULL, 0, &udp_do_loopback_cksum, 0,
		       CTL_NET, PF_INET6, IPPROTO_UDP, UDP6CTL_LOOPBACKCKSUM,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "pcblist",
		       SYSCTL_DESCR("UDP protocol control block list"),
		       sysctl_inpcblist, 0, &udbtable, 0,
		       CTL_NET, PF_INET6, IPPROTO_UDP, CTL_CREATE,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("UDPv6 statistics"),
		       NULL, 0, &udp6stat, sizeof(udp6stat),
		       CTL_NET, PF_INET6, IPPROTO_UDP, UDP6CTL_STATS,
		       CTL_EOL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/udp6_usrreq.c $ $Rev: 711842 $")
#endif
