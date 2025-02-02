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



/*	$NetBSD: tcp_usrreq.c,v 1.138 2007/11/04 11:04:27 rmind Exp $	*/

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

/*-
 * Copyright (c) 1997, 1998, 2005, 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe and Kevin M. Lahey of the Numerical Aerospace Simulation
 * Facility, NASA Ames Research Center.
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
 * This code is derived from software contributed to The NetBSD Foundation
 * by Rui Paulo.
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
 * Copyright (c) 1982, 1986, 1988, 1993, 1995
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
 *	@(#)tcp_usrreq.c	8.5 (Berkeley) 6/21/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: tcp_usrreq.c,v 1.138 2007/11/04 11:04:27 rmind Exp $");

#include "opt_inet.h"
#include "opt_ipsec.h"
#include "opt_tcp_debug.h"
#include "opt_mbuftrace.h"
#ifdef __QNXNTO__
#include "opt_pru_sense.h"
#endif
#include "rnd.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/domain.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/in_offload.h>

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#endif

#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_congctl.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>
#ifdef __QNXNTO__
#include <netinet/if_tcp_conf.h>
#include <net/if_extra.h>
#endif

#include "opt_tcp_space.h"

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if defined(__QNXNTO__)
static int      tcp_maxidle_sysctl_handler(SYSCTLFN_PROTO);
#if defined(OPT_PRU_SENSE_EXTEN)
static const char *tcp_prefix = "TCP";
#endif
#endif

/*
 * TCP protocol interface to socket abstraction.
 */

/*
 * Process a TCP user request for TCP tb.  If this is a send request
 * then m is the mbuf chain of send data.  If this is a timer expiration
 * (called from the software clock routine), then timertype tells which timer.
 */
/*ARGSUSED*/
int
tcp_usrreq(struct socket *so, int req,
    struct mbuf *m, struct mbuf *nam, struct mbuf *control, struct lwp *l)
{
	struct inpcb *inp;
#ifdef INET6
	struct in6pcb *in6p;
#endif
	struct tcpcb *tp = NULL;
	int s;
	int error = 0;
#ifdef TCP_DEBUG
	int ostate = 0;
#endif
	int family;	/* family of the socket */

	family = so->so_proto->pr_domain->dom_family;

	if (req == PRU_CONTROL) {
		switch (family) {
#ifdef INET
		case PF_INET:
			return (in_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, l));
#endif
#ifdef INET6
		case PF_INET6:
			return (in6_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, l));
#endif
		default:
			return EAFNOSUPPORT;
		}
	}

	s = splsoftnet();

	if (req == PRU_PURGEIF) {
		switch (family) {
#ifdef INET
		case PF_INET:
			in_pcbpurgeif0(&tcbtable, (struct ifnet *)control);
			in_purgeif((struct ifnet *)control);
			in_pcbpurgeif(&tcbtable, (struct ifnet *)control);
			break;
#endif
#ifdef INET6
		case PF_INET6:
			in6_pcbpurgeif0(&tcbtable, (struct ifnet *)control);
			in6_purgeif((struct ifnet *)control);
			in6_pcbpurgeif(&tcbtable, (struct ifnet *)control);
			break;
#endif
		default:
			splx(s);
			return (EAFNOSUPPORT);
		}
		splx(s);
		return (0);
	}

	switch (family) {
#ifdef INET
	case PF_INET:
		inp = sotoinpcb(so);
#ifdef INET6
		in6p = NULL;
#endif
		break;
#endif
#ifdef INET6
	case PF_INET6:
		inp = NULL;
		in6p = sotoin6pcb(so);
		break;
#endif
	default:
		splx(s);
		return EAFNOSUPPORT;
	}

#ifdef DIAGNOSTIC
#ifdef INET6
	if (inp && in6p)
		panic("tcp_usrreq: both inp and in6p set to non-NULL");
#endif
	if (req != PRU_SEND && req != PRU_SENDOOB && control)
		panic("tcp_usrreq: unexpected control mbuf");
#endif
	/*
	 * When a TCP is attached to a socket, then there will be
	 * a (struct inpcb) pointed at by the socket, and this
	 * structure will point at a subsidary (struct tcpcb).
	 */
#ifndef INET6
#ifndef __QNXNTO__
	if (inp == 0 && req != PRU_ATTACH)
#else
	/*
	 * This avoids at least the following window:
	 *  - shutdown(s, SHUT_WR)  (send our FIN)
	 *  -    their FIN arrives  (tcp_input() calls tcp_close())
	 *  - fstat(s, &stat)       (fails due to EINVAL below)
	 */
	if (inp == 0 && req != PRU_ATTACH && req != PRU_SENSE)
#endif
#else
#ifndef __QNXNTO__
	if ((inp == 0 && in6p == 0) && req != PRU_ATTACH)
#else
	if ((inp == 0 && in6p == 0) && req != PRU_ATTACH && req != PRU_SENSE)
#endif
#endif
	{
		error = EINVAL;
		goto release;
	}
#ifdef INET
	if (inp) {
		tp = intotcpcb(inp);
		/* WHAT IF TP IS 0? */
#ifdef KPROF
		tcp_acounts[tp->t_state][req]++;
#endif
#ifdef TCP_DEBUG
		ostate = tp->t_state;
#endif
	}
#endif
#ifdef INET6
	if (in6p) {
		tp = in6totcpcb(in6p);
		/* WHAT IF TP IS 0? */
#ifdef KPROF
		tcp_acounts[tp->t_state][req]++;
#endif
#ifdef TCP_DEBUG
		ostate = tp->t_state;
#endif
	}
#endif

	switch (req) {

	/*
	 * TCP attaches to socket via PRU_ATTACH, reserving space,
	 * and an internet control block.
	 */
	case PRU_ATTACH:
#ifndef INET6
		if (inp != 0)
#else
		if (inp != 0 || in6p != 0)
#endif
		{
			error = EISCONN;
			break;
		}
		error = tcp_attach(so);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Attach failed\n");
#else
				printf("Socket Attach failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
		if (error)
			break;
		if ((so->so_options & SO_LINGER) && so->so_linger == 0)
			so->so_linger = TCP_LINGERTIME;
		tp = sototcpcb(so);
		break;

	/*
	 * PRU_DETACH detaches the TCP protocol from the socket.
	 */
	case PRU_DETACH:
		tp = tcp_disconnect(tp);
		break;

	/*
	 * Give the socket an address.
	 */
	case PRU_BIND:
		switch (family) {
#ifdef INET
		case PF_INET:
			error = in_pcbbind(inp, nam, l);
			break;
#endif
#ifdef INET6
		case PF_INET6:
			error = in6_pcbbind(in6p, nam, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Bind failed\n");
#else
				printf("Socket Bind failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
			if (!error) {
				/* mapped addr case */
				if (IN6_IS_ADDR_V4MAPPED(&in6p->in6p_laddr))
					tp->t_family = AF_INET;
				else
					tp->t_family = AF_INET6;
			}
			break;
#endif
		}
		break;

	/*
	 * Prepare to accept connections.
	 */
	case PRU_LISTEN:
#ifdef INET
		if (inp && inp->inp_lport == 0) {
			error = in_pcbbind(inp, NULL, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Listen failed\n");
#else
				printf("Socket Listen failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
			if (error)
				break;
		}
#endif
#ifdef INET6
		if (in6p && in6p->in6p_lport == 0) {
			error = in6_pcbbind(in6p, NULL, l);
			if (error)
				break;
		}
#endif
		tp->t_state = TCPS_LISTEN;
		break;

	/*
	 * Initiate connection to peer.
	 * Create a template for use in transmissions on this connection.
	 * Enter SYN_SENT state, and mark socket as connecting.
	 * Start keep-alive timer, and seed output sequence space.
	 * Send initial segment on connection.
	 */
	case PRU_CONNECT:
#ifdef INET
		if (inp) {
			if (inp->inp_lport == 0) {
				error = in_pcbbind(inp, NULL, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Connect 1 failed\n");
#else
				printf("Socket Connect 1 failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
				if (error)
					break;
			}
#ifdef __QNXNTO__
			if (in_nullhost(inp->inp_laddr))
				so->so_state |= SS_IMPLICIT;
#endif
			error = in_pcbconnect(inp, nam, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Connect 2 failed\n");
#else
				printf("Socket Connect 2 failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
		}
#endif
#ifdef INET6
		if (in6p) {
			if (in6p->in6p_lport == 0) {
				error = in6_pcbbind(in6p, NULL, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Connect 3 failed\n");
#else
				printf("Socket Connect 3 failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
				if (error)
					break;
			}
			error = in6_pcbconnect(in6p, nam, l);
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket Connect 4 failed\n");
#else
				printf("Socket Connect 4 failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
			if (!error) {
				/* mapped addr case */
				if (IN6_IS_ADDR_V4MAPPED(&in6p->in6p_faddr))
					tp->t_family = AF_INET;
				else
					tp->t_family = AF_INET6;
			}
		}
#endif
		if (error)
			break;
		tp->t_template = tcp_template(tp);
		if (tp->t_template == 0) {
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("Socket template alloc failed\n");
#else
				printf("Socket template alloc failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif

#ifdef INET
			if (inp)
				in_pcbdisconnect(inp);
#endif
#ifdef INET6
			if (in6p)
				in6_pcbdisconnect(in6p);
#endif
			error = ENOBUFS;
			break;
		}
		/*
		 * Compute window scaling to request.
		 * XXX: This should be moved to tcp_output().
		 */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
		    (TCP_MAXWIN << tp->request_r_scale) < sb_max)
			tp->request_r_scale++;
		soisconnecting(so);
		tcpstat.tcps_connattempt++;
		tp->t_state = TCPS_SYN_SENT;
		TCP_TIMER_ARM(tp, TCPT_KEEP, TCPTV_KEEP_INIT);
		tp->iss = tcp_new_iss(tp, 0);
		tcp_sendseqinit(tp);
		error = tcp_output(tp);
#ifdef __QNXNTO__
#ifdef INET
		if (inp && error == EHOSTUNREACH) {
			in_pcbdisconnect(inp);
			if ((so->so_state & SS_IMPLICIT) != 0) {
				inp->inp_laddr.s_addr = 0;
				in_pcbstate(inp, INP_BOUND);
			}
		}
#endif
#ifdef INET6
                if (in6p && error == EHOSTUNREACH) {
                        /*do nothing yet: FIXME for INET6 */
                }
#endif
#endif /* __QNXNTO__ */
		break;

	/*
	 * Create a TCP connection between two sockets.
	 */
	case PRU_CONNECT2:
		error = EOPNOTSUPP;
#ifndef NDEBUG
			if (error) {
#ifndef QNX_MFIB
				printf("PRU_CONNECT2 failed\n");
#else
				printf("PRU_CONNECT2 failed '%d': pid=%10d/so=%10d/user=%10d on fib %4d\n",
						so->so_fiborigin, LWP_TO_PR(l)->p_ctxt.info.pid, (int)so,
						(int)kauth_cred_geteuid(l->l_cred), so->so_fibnum);
#endif
			}
#endif
		break;

	/*
	 * Initiate disconnect from peer.
	 * If connection never passed embryonic stage, just drop;
	 * else if don't need to let data drain, then can just drop anyways,
	 * else have to begin TCP shutdown process: mark socket disconnecting,
	 * drain unread data, state switch to reflect user close, and
	 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
	 * when peer sends FIN and acks ours.
	 *
	 * SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC TCPCB.
	 */
	case PRU_DISCONNECT:
		tp = tcp_disconnect(tp);
		break;

	/*
	 * Accept a connection.  Essentially all the work is
	 * done at higher levels; just return the address
	 * of the peer, storing through addr.
	 */
	case PRU_ACCEPT:
#ifdef INET
		if (inp)
			in_setpeeraddr(inp, nam);
#endif
#ifdef INET6
		if (in6p)
			in6_setpeeraddr(in6p, nam);
#endif
		break;

	/*
	 * Mark the connection as being incapable of further output.
	 */
	case PRU_SHUTDOWN:
		socantsendmore(so);
		tp = tcp_usrclosed(tp);
		if (tp)
			error = tcp_output(tp);
		break;

	/*
	 * After a receive, possibly send window update to peer.
	 */
	case PRU_RCVD:
		/*
		 * soreceive() calls this function when a user receives
		 * ancillary data on a listening socket. We don't call
		 * tcp_output in such a case, since there is no header
		 * template for a listening socket and hence the kernel
		 * will panic.
		 */
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) != 0)
			(void) tcp_output(tp);
		break;

	/*
	 * Do a send by putting data in output queue and updating urgent
	 * marker if URG set.  Possibly send more data.
	 */
	case PRU_SEND:
		if (control && control->m_len) {
			m_freem(control);
			m_freem(m);
			error = EINVAL;
			break;
		}
		sbappendstream(&so->so_snd, m);
		error = tcp_output(tp);
		break;

	/*
	 * Abort the TCP.
	 */
	case PRU_ABORT:
		tp = tcp_drop(tp, ECONNABORTED);
		break;

	case PRU_SENSE:
#ifdef __QNXNTO__
		/*
		 * Non NULL nam parameter means true protocol
		 * specific info is being requested rather than
		 * the generic fstat().
		 */
		if (nam != NULL) {
#ifndef OPT_PRU_SENSE_EXTEN
			return EOPNOTSUPP;
#else
			const char *suffix;
			char *dst;
			struct proto_sensereq *prs;

			prs = (struct proto_sensereq *)nam;

			switch (prs->prs_how) {
			case PRSENSEREQ_STRING:
				dst = (char *)m;

				if (tp)
					suffix = tcpstates[tp->t_state];
				else
					suffix = tcpstates[TCPS_CLOSED];

				switch (family) {
				case AF_INET:
					error = in_pcbformat(inp, tcp_prefix, suffix, 1, dst, &prs->prs_maxlen);
					if (error)
						return error;
					break;
#ifdef INET6
				case AF_INET6:
					error = in6_pcbformat(in6p, tcp_prefix, suffix, 1, dst, &prs->prs_maxlen);
					if (error)
						return error;
					break;
#endif
				default:
					return EAFNOSUPPORT;
				}

				break;
			default:
				return EOPNOTSUPP;
			}

			return 0;
#endif
		}
#endif /* __QNXNTO__ */
		/*
		 * stat: don't bother with a blocksize.
		 */
		splx(s);
		return (0);

	case PRU_RCVOOB:
		if (control && control->m_len) {
			m_freem(control);
			m_freem(m);
			error = EINVAL;
			break;
		}
		if ((so->so_oobmark == 0 &&
		    (so->so_state & SS_RCVATMARK) == 0) ||
		    so->so_options & SO_OOBINLINE ||
		    tp->t_oobflags & TCPOOB_HADDATA) {
			error = EINVAL;
			break;
		}
		if ((tp->t_oobflags & TCPOOB_HAVEDATA) == 0) {
			error = EWOULDBLOCK;
			break;
		}
		m->m_len = 1;
		*mtod(m, char *) = tp->t_iobc;
		if (((long)nam & MSG_PEEK) == 0)
			tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
		break;

	case PRU_SENDOOB:
		if (sbspace(&so->so_snd) < -512) {
			m_freem(m);
			error = ENOBUFS;
			break;
		}
		/*
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section.
		 * Otherwise, snd_up should be one lower.
		 */
		sbappendstream(&so->so_snd, m);
		tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
		tp->t_force = 1;
		error = tcp_output(tp);
		tp->t_force = 0;
		break;

	case PRU_SOCKADDR:
#ifdef INET
		if (inp)
			in_setsockaddr(inp, nam);
#endif
#ifdef INET6
		if (in6p)
			in6_setsockaddr(in6p, nam);
#endif
		break;

	case PRU_PEERADDR:
#ifdef INET
		if (inp)
			in_setpeeraddr(inp, nam);
#endif
#ifdef INET6
		if (in6p)
			in6_setpeeraddr(in6p, nam);
#endif
		break;

	default:
		panic("tcp_usrreq");
	}
#ifdef TCP_DEBUG
	if (tp && (so->so_options & SO_DEBUG))
		tcp_trace(TA_USER, ostate, tp, NULL, req);
#endif

release:
	splx(s);
	return (error);
}

int
tcp_ctloutput(int op, struct socket *so, int level, int optname,
    struct mbuf **mp)
{
	int error = 0, s;
	struct inpcb *inp;
#ifdef INET6
	struct in6pcb *in6p;
#endif
	struct tcpcb *tp;
	struct mbuf *m;
	int i;
	int family;	/* family of the socket */

	family = so->so_proto->pr_domain->dom_family;

	s = splsoftnet();
	switch (family) {
#ifdef INET
	case PF_INET:
		inp = sotoinpcb(so);
#ifdef INET6
		in6p = NULL;
#endif
		break;
#endif
#ifdef INET6
	case PF_INET6:
		inp = NULL;
		in6p = sotoin6pcb(so);
		break;
#endif
	default:
		splx(s);
		panic("%s: af %d", __func__, family);
	}
#ifndef INET6
	if (inp == NULL)
#else
	if (inp == NULL && in6p == NULL)
#endif
	{
		splx(s);
		if (op == PRCO_SETOPT && *mp)
			(void) m_free(*mp);
		return (ECONNRESET);
	}
#ifdef __QNXNTO__
	if (inp)
		tp = intotcpcb(inp);
#ifdef INET6
	else if (in6p)
		tp = in6totcpcb(in6p);
#endif
	else
		tp = NULL;
#endif
	if (level != IPPROTO_TCP) {
#ifdef __QNXNTO__
		if (optname == SO_SNDBUF)
			tcp_check_sndbuf(so, tp);

		/*
		 * We don't start this timer if SO_KEEPALIVE isn't
		 * set.  If it has changed we need to start it.
		 */
		if (optname == SO_KEEPALIVE && tp != NULL)
			tcp_timer_keep_est(tp);

#endif
		switch (family) {
#ifdef INET
		case PF_INET:
			error = ip_ctloutput(op, so, level, optname, mp);
			break;
#endif
#ifdef INET6
		case PF_INET6:
			error = ip6_ctloutput(op, so, level, optname, mp);
			break;
#endif
		}
		splx(s);
		return (error);
	}
#ifndef __QNXNTO__
	if (inp)
		tp = intotcpcb(inp);
#ifdef INET6
	else if (in6p)
		tp = in6totcpcb(in6p);
#endif
	else
		tp = NULL;
#else
	/* We moved this up */
#endif


	switch (op) {

	case PRCO_SETOPT:
		m = *mp;
		switch (optname) {

#ifdef TCP_SIGNATURE
		case TCP_MD5SIG:
			if (m == NULL || m->m_len < sizeof (int))
				error = EINVAL;
			if (error)
				break;
			if (*mtod(m, int *) > 0)
				tp->t_flags |= TF_SIGNATURE;
			else
				tp->t_flags &= ~TF_SIGNATURE;
			break;
#endif /* TCP_SIGNATURE */

		case TCP_NODELAY:
			if (m == NULL || m->m_len < sizeof (int))
				error = EINVAL;
			else if (*mtod(m, int *))
				tp->t_flags |= TF_NODELAY;
			else
				tp->t_flags &= ~TF_NODELAY;
			break;

		case TCP_MAXSEG:
			if (m && (i = *mtod(m, int *)) > 0 &&
			    i <= tp->t_peermss)
				tp->t_peermss = i;  /* limit on send size */
			else
				error = EINVAL;
			break;
#ifdef notyet
		case TCP_CONGCTL:
			if (m == NULL)
				error = EINVAL;
			error = tcp_congctl_select(tp, mtod(m, char *));
#endif
			break;

#ifdef __QNXNTO__
		case TCP_KEEPALIVE:
			if (m == NULL || m->m_len < sizeof(int)) {
				error = EINVAL;
			}
			else {
				tp->t_keepidle = (*mtod(m, int *)) * PR_SLOWHZ;
				tcp_timer_keep_est(tp);
			}
			break;
		case TCP_RTO:
		case TCP_RTO_LIMIT:
		case TCP_RTO_FINAL:
			if (m == NULL || m->m_len < sizeof(unsigned)) {
				error = EINVAL;
				break;
			}

			switch (optname) {
			case TCP_RTO:
				tp->t_rtfixed =
				    (*mtod(m, unsigned *)) * PR_SLOWHZ;
				break;

			case TCP_RTO_LIMIT:
				tp->t_rtlim = (*mtod(m, unsigned *));
				break;

			case TCP_RTO_FINAL:
				tp->t_rtfinal =
				    (*mtod(m, unsigned *)) * PR_SLOWHZ;
				break;
			}
			break;
#endif

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m)
			(void) m_free(m);
		break;

	case PRCO_GETOPT:
		*mp = m = m_get(M_WAIT, MT_SOOPTS);
		m->m_len = sizeof(int);
		MCLAIM(m, so->so_mowner);

		switch (optname) {
#ifdef TCP_SIGNATURE
		case TCP_MD5SIG:
			*mtod(m, int *) = (tp->t_flags & TF_SIGNATURE) ? 1 : 0;
			break;
#endif
		case TCP_NODELAY:
			*mtod(m, int *) = tp->t_flags & TF_NODELAY;
			break;
		case TCP_MAXSEG:
			*mtod(m, int *) = tp->t_peermss;
			break;
#ifdef __QNXNTO__
		case TCP_KEEPALIVE:
			*mtod(m, int *) = tp->t_keepidle / PR_SLOWHZ;
			break;

		case TCP_RTO:
			*mtod(m, unsigned *) = tp->t_rtfixed / PR_SLOWHZ;
			break;

		case TCP_RTO_LIMIT:
			*mtod(m, unsigned *) = tp->t_rtlim;
			break;

		case TCP_RTO_FINAL:
			*mtod(m, unsigned *) = tp->t_rtfinal / PR_SLOWHZ;
			break;
#endif
#ifdef notyet
		case TCP_CONGCTL:
			break;
#endif
		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	splx(s);
	return (error);
}

#ifndef TCP_SENDSPACE
#ifndef __QNXNTO__
#define	TCP_SENDSPACE	1024*32
#else
/*
 * To cut down on message passes, want lowat to be large;
 * however for tcp protocol, hiwat - lowat (what we
 * always try to keep on hand) should probably
 * be at least 4*mss.  mss isn't known until
 * we receive it from peer.  NetBSD default is
 * hiwat - lowat = 16k - 2k = 14k.  The most common
 * mss from peer is approx 1.5k so we choose a hiwat
 * of 22k.  Therefor:
 * lowat = 22k - 4*1.5K = 16k. (much larger than 2k of NetBSD).
 * We do the actual override of the default lowat of 2k when
 * we receive the peer's mss in netinet/tcp_subr.c.
 */

#define TCP_SENDSPACE   1024*22
#endif
#endif
int	tcp_sendspace = TCP_SENDSPACE;
#ifndef TCP_RECVSPACE
#define	TCP_RECVSPACE	1024*32
#endif
int	tcp_recvspace = TCP_RECVSPACE;

/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
int
tcp_attach(struct socket *so)
{
	struct tcpcb *tp;
	struct inpcb *inp;
#ifdef INET6
	struct in6pcb *in6p;
#endif
	int error;
	int family;	/* family of the socket */

	family = so->so_proto->pr_domain->dom_family;

#ifdef MBUFTRACE
	so->so_mowner = &tcp_mowner;
	so->so_rcv.sb_mowner = &tcp_rx_mowner;
	so->so_snd.sb_mowner = &tcp_tx_mowner;
#endif
	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, tcp_sendspace, tcp_recvspace);
		if (error)
			return (error);
	}

	so->so_rcv.sb_flags |= SB_AUTOSIZE;
	so->so_snd.sb_flags |= SB_AUTOSIZE;

	switch (family) {
#ifdef INET
	case PF_INET:
		error = in_pcballoc(so, &tcbtable);
		if (error)
			return (error);
		inp = sotoinpcb(so);
#ifdef INET6
		in6p = NULL;
#endif
		break;
#endif
#ifdef INET6
	case PF_INET6:
		error = in6_pcballoc(so, &tcbtable);
		if (error)
			return (error);
		inp = NULL;
		in6p = sotoin6pcb(so);
		break;
#endif
	default:
		return EAFNOSUPPORT;
	}
	if (inp)
		tp = tcp_newtcpcb(family, (void *)inp);
#ifdef INET6
	else if (in6p)
		tp = tcp_newtcpcb(family, (void *)in6p);
#endif
	else
		tp = NULL;

	if (tp == 0) {
		int nofd = so->so_state & SS_NOFDREF;	/* XXX */

		so->so_state &= ~SS_NOFDREF;	/* don't free the socket yet */
#ifdef INET
		if (inp)
			in_pcbdetach(inp);
#endif
#ifdef INET6
		if (in6p)
			in6_pcbdetach(in6p);
#endif
		so->so_state |= nofd;
		return (ENOBUFS);
	}
	tp->t_state = TCPS_CLOSED;
	return (0);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
struct tcpcb *
tcp_disconnect(struct tcpcb *tp)
{
	struct socket *so;

	if (tp->t_inpcb)
		so = tp->t_inpcb->inp_socket;
#ifdef INET6
	else if (tp->t_in6pcb)
		so = tp->t_in6pcb->in6p_socket;
#endif
	else
		so = NULL;

	if (TCPS_HAVEESTABLISHED(tp->t_state) == 0)
		tp = tcp_close(tp);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		tp = tcp_drop(tp, 0);
	else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		tp = tcp_usrclosed(tp);
		if (tp)
			(void) tcp_output(tp);
	}
	return (tp);
#ifdef __QNXNTO__
	/* inp_bounddevice MUST be left alone otherwise future tcp_output() while draining doesn't work.
	 * It's not harmful since TCP can't connect() again after disconnect...
	 */
#endif
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
struct tcpcb *
tcp_usrclosed(struct tcpcb *tp)
{

	switch (tp->t_state) {

	case TCPS_CLOSED:
	case TCPS_LISTEN:
	case TCPS_SYN_SENT:
		tp->t_state = TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_RECEIVED:
	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2) {
		struct socket *so;
		if (tp->t_inpcb)
			so = tp->t_inpcb->inp_socket;
#ifdef INET6
		else if (tp->t_in6pcb)
			so = tp->t_in6pcb->in6p_socket;
#endif
		else
			so = NULL;
		if (so)
			soisdisconnected(so);
		/*
		 * If we are in FIN_WAIT_2, we arrived here because the
		 * application did a shutdown of the send side.  Like the
		 * case of a transition from FIN_WAIT_1 to FIN_WAIT_2 after
		 * a full close, we start a timer to make sure sockets are
		 * not left in FIN_WAIT_2 forever.
		 */
		if ((tp->t_state == TCPS_FIN_WAIT_2) && (tcp_maxidle > 0))
			TCP_TIMER_ARM(tp, TCPT_2MSL, tcp_maxidle);
	}
	return (tp);
}

/*
 * sysctl helper routine for net.inet.ip.mssdflt.  it can't be less
 * than 32.
 */
static int
sysctl_net_inet_tcp_mssdflt(SYSCTLFN_ARGS)
{
	int error, mssdflt;
	struct sysctlnode node;

	mssdflt = tcp_mssdflt;
	node = *rnode;
	node.sysctl_data = &mssdflt;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	if (mssdflt < 32)
		return (EINVAL);
	tcp_mssdflt = mssdflt;

#ifdef __QNXNTO__
	tcp_tcpcb_template();
#endif
	return (0);
}

/*
 * sysctl helper routine for setting port related values under
 * net.inet.ip and net.inet6.ip6.  does basic range checking and does
 * additional checks for each type.  this code has placed in
 * tcp_input.c since INET and INET6 both use the same tcp code.
 *
 * this helper is not static so that both inet and inet6 can use it.
 */
int
sysctl_net_inet_ip_ports(SYSCTLFN_ARGS)
{
	int error, tmp;
	int apmin, apmax;
#ifndef IPNOPRIVPORTS
	int lpmin, lpmax;
#endif /* IPNOPRIVPORTS */
	struct sysctlnode node;

	if (namelen != 0)
		return (EINVAL);

	switch (name[-3]) {
#ifdef INET
	    case PF_INET:
		apmin = anonportmin;
		apmax = anonportmax;
#ifndef IPNOPRIVPORTS
		lpmin = lowportmin;
		lpmax = lowportmax;
#endif /* IPNOPRIVPORTS */
		break;
#endif /* INET */
#ifdef INET6
	    case PF_INET6:
		apmin = ip6_anonportmin;
		apmax = ip6_anonportmax;
#ifndef IPNOPRIVPORTS
		lpmin = ip6_lowportmin;
		lpmax = ip6_lowportmax;
#endif /* IPNOPRIVPORTS */
		break;
#endif /* INET6 */
	    default:
		return (EINVAL);
	}

	/*
	 * insert temporary copy into node, perform lookup on
	 * temporary, then restore pointer
	 */
	node = *rnode;
	tmp = *(int*)rnode->sysctl_data;
	node.sysctl_data = &tmp;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	/*
	 * simple port range check
	 */
	if (tmp < 0 || tmp > 65535)
		return (EINVAL);

	/*
	 * per-node range checks
	 */
	switch (rnode->sysctl_num) {
	case IPCTL_ANONPORTMIN:
	case IPV6CTL_ANONPORTMIN:
		if (tmp >= apmax)
			return (EINVAL);
#ifndef IPNOPRIVPORTS
		if (tmp < IPPORT_RESERVED)
                        return (EINVAL);
#endif /* IPNOPRIVPORTS */
		break;

	case IPCTL_ANONPORTMAX:
	case IPV6CTL_ANONPORTMAX:
                if (apmin >= tmp)
			return (EINVAL);
#ifndef IPNOPRIVPORTS
		if (tmp < IPPORT_RESERVED)
                        return (EINVAL);
#endif /* IPNOPRIVPORTS */
		break;

#ifndef IPNOPRIVPORTS
	case IPCTL_LOWPORTMIN:
	case IPV6CTL_LOWPORTMIN:
		if (tmp >= lpmax ||
		    tmp > IPPORT_RESERVEDMAX ||
		    tmp < IPPORT_RESERVEDMIN)
			return (EINVAL);
		break;

	case IPCTL_LOWPORTMAX:
	case IPV6CTL_LOWPORTMAX:
		if (lpmin >= tmp ||
		    tmp > IPPORT_RESERVEDMAX ||
		    tmp < IPPORT_RESERVEDMIN)
			return (EINVAL);
		break;
#endif /* IPNOPRIVPORTS */

	default:
		return (EINVAL);
	}

	*(int*)rnode->sysctl_data = tmp;

	return (0);
}

/*
 * sysctl helper routine for the net.inet.tcp.ident and
 * net.inet6.tcp6.ident nodes.  contains backwards compat code for the
 * old way of looking up the ident information for ipv4 which involves
 * stuffing the port/addr pairs into the mib lookup.
 */
static int
sysctl_net_inet_tcp_ident(SYSCTLFN_ARGS)
{
#ifdef INET
	struct inpcb *inb;
	struct sockaddr_in *si4[2];
#endif /* INET */
#ifdef INET6
	struct in6pcb *in6b;
	struct sockaddr_in6 *si6[2];
#endif /* INET6 */
	struct sockaddr_storage sa[2];
	struct socket *sockp;
	size_t sz;
	uid_t uid;
	int error, pf;

	if (namelen != 4 && namelen != 0)
		return (EINVAL);
	if (name[-2] != IPPROTO_TCP)
		return (EINVAL);
	pf = name[-3];

	/* old style lookup, ipv4 only */
	if (namelen == 4) {
#ifdef INET
		struct in_addr laddr, raddr;
		u_int lport, rport;

		if (pf != PF_INET)
			return EPROTONOSUPPORT;
		raddr.s_addr = (uint32_t)name[0];
		rport = (u_int)name[1];
		laddr.s_addr = (uint32_t)name[2];
		lport = (u_int)name[3];
		inb = in_pcblookup_connect(&tcbtable, raddr, rport,
					   laddr, lport);
		if (inb == NULL || (sockp = inb->inp_socket) == NULL)
			return (ESRCH);
		uid = sockp->so_uidinfo->ui_uid;
		if (oldp) {
			sz = MIN(sizeof(uid), *oldlenp);
			error = copyout(&uid, oldp, sz);
			if (error)
				return (error);
		}
		*oldlenp = sizeof(uid);
		return (0);
#else /* INET */
		return EINVAL;
#endif /* INET */
	}

	if (newp == NULL || newlen != sizeof(sa))
		return EINVAL;
	error = copyin(newp, &sa, newlen);
	if (error)
		return error;

	/*
	 * requested families must match
	 */
	if (pf != sa[0].ss_family || sa[0].ss_family != sa[1].ss_family)
		return EINVAL;

	switch (pf) {
#ifdef INET
	    case PF_INET:
		si4[0] = (struct sockaddr_in*)&sa[0];
		si4[1] = (struct sockaddr_in*)&sa[1];
		if (si4[0]->sin_len != sizeof(*si4[0]) ||
		    si4[0]->sin_len != si4[1]->sin_len)
			return (EINVAL);
		inb = in_pcblookup_connect(&tcbtable,
		    si4[0]->sin_addr, si4[0]->sin_port,
		    si4[1]->sin_addr, si4[1]->sin_port);
		if (inb == NULL || (sockp = inb->inp_socket) == NULL)
			return (ESRCH);
		break;
#endif /* INET */
#ifdef INET6
	    case PF_INET6:
		si6[0] = (struct sockaddr_in6*)&sa[0];
		si6[1] = (struct sockaddr_in6*)&sa[1];
		if (si6[0]->sin6_len != sizeof(*si6[0]) ||
		    si6[0]->sin6_len != si6[1]->sin6_len)
			return EINVAL;
		in6b = in6_pcblookup_connect(&tcbtable,
		    &si6[0]->sin6_addr, si6[0]->sin6_port,
		    &si6[1]->sin6_addr, si6[1]->sin6_port, 0
#ifdef __QNXNTO__
		    , in6b->in6p_bounddevice
#endif
		    );
		if (in6b == NULL || (sockp = in6b->in6p_socket) == NULL)
			return (ESRCH);
		break;
#endif /* INET6 */
	    default:
		return (EPROTONOSUPPORT);
	}
	*oldlenp = sizeof(uid);

	uid = sockp->so_uidinfo->ui_uid;
	if (oldp) {
		sz = MIN(sizeof(uid), *oldlenp);
		error = copyout(&uid, oldp, sz);
		if (error)
			return (error);
	}
	*oldlenp = sizeof(uid);

	return (0);
}

/*
 * sysctl helper for the inet and inet6 pcblists.  handles tcp/udp and
 * inet/inet6, as well as raw pcbs for each.  specifically not
 * declared static so that raw sockets and udp/udp6 can use it as
 * well.
 */
int
sysctl_inpcblist(SYSCTLFN_ARGS)
{
#ifdef INET
	struct sockaddr_in *in;
	const struct inpcb *inp;
#endif
#ifdef INET6
	struct sockaddr_in6 *in6;
	const struct in6pcb *in6p;
#endif
	/*
	 * sysctl_data is const, but CIRCLEQ_FOREACH can't use a const
	 * struct inpcbtable pointer, so we have to discard const.  :-/
	 */
	struct inpcbtable *pcbtbl = __UNCONST(rnode->sysctl_data);
	const struct inpcb_hdr *inph;
	struct tcpcb *tp;
	struct kinfo_pcb pcb;
	char *dp;
	u_int op, arg;
	size_t len, needed, elem_size, out_size;
	int error, elem_count, pf, proto, pf2;
#ifdef __QNXNTO__
	size_t elem_size_old = offsetof(struct kinfo_pcb, ki_fibnum);
#endif

	if (namelen != 4)
		return (EINVAL);

	if (oldp != NULL) {
		    len = *oldlenp;
		    elem_size = name[2];
		    elem_count = name[3];
		    if (elem_size != sizeof(pcb)
#ifdef __QNXNTO__
			&& elem_size != elem_size_old
#endif
			)
			    return EINVAL;
	} else {
		    len = 0;
		    elem_count = INT_MAX;
		    elem_size = sizeof(pcb);
	}
	error = 0;
	dp = oldp;
	op = name[0];
	arg = name[1];
	out_size = elem_size;
	needed = 0;

	if (namelen == 1 && name[0] == CTL_QUERY)
		return (sysctl_query(SYSCTLFN_CALL(rnode)));

	if (name - oname != 4)
		return (EINVAL);

	pf = oname[1];
	proto = oname[2];
	pf2 = (oldp != NULL) ? pf : 0;

	CIRCLEQ_FOREACH(inph, &pcbtbl->inpt_queue, inph_queue) {
#ifdef INET
		inp = (const struct inpcb *)inph;
#endif
#ifdef INET6
		in6p = (const struct in6pcb *)inph;
#endif

		if (inph->inph_af != pf)
			continue;

		if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_SOCKET,
		    KAUTH_REQ_NETWORK_SOCKET_CANSEE, inph->inph_socket, NULL,
		    NULL) != 0)
			continue;

		memset(&pcb, 0, sizeof(pcb));

		pcb.ki_family = pf;
		pcb.ki_type = proto;

		switch (pf2) {
		case 0:
			/* just probing for size */
			break;
#ifdef INET
		case PF_INET:
			pcb.ki_family = inp->inp_socket->so_proto->
			    pr_domain->dom_family;
			pcb.ki_type = inp->inp_socket->so_proto->
			    pr_type;
			pcb.ki_protocol = inp->inp_socket->so_proto->
			    pr_protocol;
			pcb.ki_pflags = inp->inp_flags;

			pcb.ki_sostate = inp->inp_socket->so_state;
			pcb.ki_prstate = inp->inp_state;
			if (proto == IPPROTO_TCP) {
				tp = intotcpcb(inp);
				pcb.ki_tstate = tp->t_state;
				pcb.ki_tflags = tp->t_flags;
			}

			pcb.ki_pcbaddr = PTRTOUINT64(inp);
			pcb.ki_ppcbaddr = PTRTOUINT64(inp->inp_ppcb);
			pcb.ki_sockaddr = PTRTOUINT64(inp->inp_socket);

			pcb.ki_rcvq = inp->inp_socket->so_rcv.sb_cc;
			pcb.ki_sndq = inp->inp_socket->so_snd.sb_cc;

			in = satosin(&pcb.ki_src);
			in->sin_len = sizeof(*in);
			in->sin_family = pf;
			in->sin_port = inp->inp_lport;
			in->sin_addr = inp->inp_laddr;
			if (pcb.ki_prstate >= INP_CONNECTED) {
				in = satosin(&pcb.ki_dst);
				in->sin_len = sizeof(*in);
				in->sin_family = pf;
				in->sin_port = inp->inp_fport;
				in->sin_addr = inp->inp_faddr;
			}
#ifdef __QNXNTO__
			/* old struct kinfo_pcb didn't have following members */
			if (elem_size == elem_size_old)
				break;
			pcb.ki_bound_ifindex = -1;
			if (inp->inp_bounddevice != NULL)
				pcb.ki_bound_ifindex = inp->inp_bounddevice->if_index;
			pcb.ki_fibnum = -1;
#ifdef QNX_MFIB

			if (inp->inp_socket != NULL)
				pcb.ki_fibnum = inp->inp_socket->so_fibnum;
#endif
#endif
			break;
#endif
#ifdef INET6
		case PF_INET6:
			pcb.ki_family = in6p->in6p_socket->so_proto->
			    pr_domain->dom_family;
			pcb.ki_type = in6p->in6p_socket->so_proto->pr_type;
			pcb.ki_protocol = in6p->in6p_socket->so_proto->
			    pr_protocol;
			pcb.ki_pflags = in6p->in6p_flags;

			pcb.ki_sostate = in6p->in6p_socket->so_state;
			pcb.ki_prstate = in6p->in6p_state;
			if (proto == IPPROTO_TCP) {
				tp = in6totcpcb(in6p);
				pcb.ki_tstate = tp->t_state;
				pcb.ki_tflags = tp->t_flags;
			}

			pcb.ki_pcbaddr = PTRTOUINT64(in6p);
			pcb.ki_ppcbaddr = PTRTOUINT64(in6p->in6p_ppcb);
			pcb.ki_sockaddr = PTRTOUINT64(in6p->in6p_socket);

			pcb.ki_rcvq = in6p->in6p_socket->so_rcv.sb_cc;
			pcb.ki_sndq = in6p->in6p_socket->so_snd.sb_cc;

			in6 = satosin6(&pcb.ki_src);
			in6->sin6_len = sizeof(*in6);
			in6->sin6_family = pf;
			in6->sin6_port = in6p->in6p_lport;
			in6->sin6_flowinfo = in6p->in6p_flowinfo;
			in6->sin6_addr = in6p->in6p_laddr;
			in6->sin6_scope_id = 0; /* XXX? */

			if (pcb.ki_prstate >= IN6P_CONNECTED) {
				in6 = satosin6(&pcb.ki_dst);
				in6->sin6_len = sizeof(*in6);
				in6->sin6_family = pf;
				in6->sin6_port = in6p->in6p_fport;
				in6->sin6_flowinfo = in6p->in6p_flowinfo;
				in6->sin6_addr = in6p->in6p_faddr;
				in6->sin6_scope_id = 0; /* XXX? */
			}
#ifdef __QNXNTO__
			/* old struct kinfo_pcb didn't have following members */
			if (elem_size == elem_size_old)
				break;
			pcb.ki_bound_ifindex = -1;
			if (in6p->in6p_bounddevice != NULL)
				pcb.ki_bound_ifindex = in6p->in6p_bounddevice->if_index;
			pcb.ki_fibnum = -1;
#ifdef QNX_MFIB
			if (in6p->in6p_socket != NULL)
				pcb.ki_fibnum = in6p->in6p_socket->so_fibnum;
#endif
#endif
			break;
#endif
		}

		if (len >= elem_size && elem_count > 0) {
			error = copyout(&pcb, dp, out_size);
			if (error)
				return (error);
			dp += elem_size;
			len -= elem_size;
		}
		if (elem_count > 0) {
			needed += elem_size;
			if (elem_count != INT_MAX)
				elem_count--;
		}
	}

	*oldlenp = needed;
	if (oldp == NULL)
		*oldlenp += PCB_SLOP * sizeof(struct kinfo_pcb);

	return (error);
}

static int
sysctl_tcp_congctl(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	int error, r;
	char newname[TCPCC_MAXLEN];

	strlcpy(newname, tcp_congctl_global_name, sizeof(newname) - 1);

	node = *rnode;
	node.sysctl_data = newname;
	node.sysctl_size = sizeof(newname);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error ||
	    newp == NULL ||
	    strncmp(newname, tcp_congctl_global_name, sizeof(newname)) == 0)
		return error;

	if ((r = tcp_congctl_select(NULL, newname)))
		return r;

	return error;
}

#ifdef __QNXNTO__
extern int tcp_rttdflt;
/*
 * sysctl helper routine for anything that changes tcpcb_template
 */
static int
sysctl_net_inet_tcp_tcpcbtemplate(SYSCTLFN_ARGS)
{
	int error;

	error = sysctl_lookup(SYSCTLFN_CALL(rnode));
	if (error || newp == NULL)
		return (error);

	tcp_tcpcb_template();

	return (0);
}
#endif

/*
 * this (second stage) setup routine is a replacement for tcp_sysctl()
 * (which is currently used for ipv4 and ipv6)
 */
static void
sysctl_net_inet_tcp_setup2(struct sysctllog **clog, int pf, const char *pfname,
			   const char *tcpname)
{
	const struct sysctlnode *sack_node;
	const struct sysctlnode *abc_node;
	const struct sysctlnode *ecn_node;
	const struct sysctlnode *congctl_node;
#ifdef TCP_DEBUG
	extern struct tcp_debug tcp_debug[TCP_NDEBUG];
	extern int tcp_debx;
#endif
#ifdef __QNXNTO__
	const struct sysctlnode *rnode;
#endif

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, pfname, NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, CTL_EOL);
#ifndef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, tcpname,
		       SYSCTL_DESCR("TCP related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_EOL);
#else
	sysctl_createv(clog, 0, NULL, &rnode,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, tcpname,
		       SYSCTL_DESCR("TCP related settings"),
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_EOL);
	sysctl_createv(clog, 0, &rnode, &rnode,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "ifconf",
		       SYSCTL_DESCR("TCP interface specific settings"),
		       NULL, 0, NULL, 0,
		       CTL_CREATE, CTL_EOL);
	if (pf == PF_INET)
		if4_tcp_conf_node = rnode->sysctl_num;
	else if (pf == PF_INET6)
		if6_tcp_conf_node = rnode->sysctl_num;
#endif

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rfc1323",
		       SYSCTL_DESCR("Enable RFC1323 TCP extensions"),
#ifndef __QNXNTO__
		       NULL, 0, &tcp_do_rfc1323, 0,
#else
		       sysctl_net_inet_tcp_tcpcbtemplate, 0, &tcp_do_rfc1323, 0,
#endif
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_RFC1323, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "sendspace",
		       SYSCTL_DESCR("Default TCP send buffer size"),
		       NULL, 0, &tcp_sendspace, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SENDSPACE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "recvspace",
		       SYSCTL_DESCR("Default TCP receive buffer size"),
		       NULL, 0, &tcp_recvspace, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_RECVSPACE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mssdflt",
		       SYSCTL_DESCR("Default maximum segment size"),
		       sysctl_net_inet_tcp_mssdflt, 0, &tcp_mssdflt, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_MSSDFLT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "syn_cache_limit",
		       SYSCTL_DESCR("Maximum number of entries in the TCP "
				    "compressed state engine"),
		       NULL, 0, &tcp_syn_cache_limit, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SYN_CACHE_LIMIT,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "syn_bucket_limit",
		       SYSCTL_DESCR("Maximum number of entries per hash "
				    "bucket in the TCP compressed state "
				    "engine"),
		       NULL, 0, &tcp_syn_bucket_limit, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SYN_BUCKET_LIMIT,
		       CTL_EOL);
#if 0 /* obsoleted */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "syn_cache_interval",
		       SYSCTL_DESCR("TCP compressed state engine's timer interval"),
		       NULL, 0, &tcp_syn_cache_interval, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SYN_CACHE_INTER,
		       CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "init_win",
		       SYSCTL_DESCR("Initial TCP congestion window"),
		       NULL, 0, &tcp_init_win, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_INIT_WIN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "mss_ifmtu",
		       SYSCTL_DESCR("Use interface MTU for calculating MSS"),
		       NULL, 0, &tcp_mss_ifmtu, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_MSS_IFMTU, CTL_EOL);
	sysctl_createv(clog, 0, NULL, &sack_node,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "sack",
		       SYSCTL_DESCR("RFC2018 Selective ACKnowledgement tunables"),
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SACK, CTL_EOL);

	/* Congctl subtree */
	sysctl_createv(clog, 0, NULL, &congctl_node,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "congctl",
		       SYSCTL_DESCR("TCP Congestion Control"),
	    	       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &congctl_node, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRING, "available",
		       SYSCTL_DESCR("Available Congestion Control Mechanisms"),
		       NULL, 0, &tcp_congctl_avail, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &congctl_node, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_STRING, "selected",
		       SYSCTL_DESCR("Selected Congestion Control Mechanism"),
		       sysctl_tcp_congctl, 0, NULL, TCPCC_MAXLEN,
		       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "win_scale",
		       SYSCTL_DESCR("Use RFC1323 window scale options"),
#ifndef __QNXNTO__
		       NULL, 0, &tcp_do_win_scale, 0,
#else
		       sysctl_net_inet_tcp_tcpcbtemplate, 0, &tcp_do_win_scale, 0,
#endif
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_WSCALE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "timestamps",
		       SYSCTL_DESCR("Use RFC1323 time stamp options"),
#ifndef __QNXNTO__
		       NULL, 0, &tcp_do_timestamps, 0,
#else
		       sysctl_net_inet_tcp_tcpcbtemplate, 0, &tcp_do_timestamps, 0,
#endif
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_TSTAMP, CTL_EOL);
#ifdef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "timestamps_monotonic",
		       SYSCTL_DESCR("Use monotonic RFC1323 time stamp options"),
		       NULL, 0, &tcp_timestamp_monotonic, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_TSTAMP_MONO, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "compat_42",
		       SYSCTL_DESCR("Enable workarounds for 4.2BSD TCP bugs"),
		       NULL, 0, &tcp_compat_42, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_COMPAT_42, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "cwm",
		       SYSCTL_DESCR("Hughes/Touch/Heidemann Congestion Window "
				    "Monitoring"),
		       NULL, 0, &tcp_cwm, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_CWM, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "cwm_burstsize",
		       SYSCTL_DESCR("Congestion Window Monitoring allowed "
				    "burst count in packets"),
		       NULL, 0, &tcp_cwm_burstsize, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_CWM_BURSTSIZE,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "ack_on_push",
		       SYSCTL_DESCR("Immediately return ACK when PSH is "
				    "received"),
		       NULL, 0, &tcp_ack_on_push, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_ACK_ON_PUSH, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "keepidle",
		       SYSCTL_DESCR("Allowed connection idle ticks before a "
				    "keepalive probe is sent"),
		       NULL, 0, &tcp_keepidle, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_KEEPIDLE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "keepintvl",
		       SYSCTL_DESCR("Ticks before next keepalive probe is sent"),
		       tcp_maxidle_sysctl_handler, 0, &tcp_keepintvl, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_KEEPINTVL, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "keepcnt",
		       SYSCTL_DESCR("Number of keepalive probes to send"),
		       tcp_maxidle_sysctl_handler, 0, &tcp_keepcnt, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_KEEPCNT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_IMMEDIATE,
		       CTLTYPE_INT, "slowhz",
		       SYSCTL_DESCR("Keepalive ticks per second"),
		       NULL, PR_SLOWHZ, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SLOWHZ, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "log_refused",
		       SYSCTL_DESCR("Log refused TCP connections"),
		       NULL, 0, &tcp_log_refused, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_LOG_REFUSED, CTL_EOL);
#if 0 /* obsoleted */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rstratelimit", NULL,
		       NULL, 0, &tcp_rst_ratelim, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_RSTRATELIMIT, CTL_EOL);
#endif
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rstppslimit",
		       SYSCTL_DESCR("Maximum number of RST packets to send "
				    "per second"),
		       NULL, 0, &tcp_rst_ppslim, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_RSTPPSLIMIT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "delack_ticks",
		       SYSCTL_DESCR("Number of ticks to delay sending an ACK"),
		       NULL, 0, &tcp_delack_ticks, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_DELACK_TICKS, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "init_win_local",
		       SYSCTL_DESCR("Initial TCP window size (in segments)"),
		       NULL, 0, &tcp_init_win_local, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_INIT_WIN_LOCAL,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_STRUCT, "ident",
		       SYSCTL_DESCR("RFC1413 Identification Protocol lookups"),
		       sysctl_net_inet_tcp_ident, 0, NULL, sizeof(uid_t),
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_IDENT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "do_loopback_cksum",
		       SYSCTL_DESCR("Perform TCP checksum on loopback"),
		       NULL, 0, &tcp_do_loopback_cksum, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_LOOPBACKCKSUM,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "pcblist",
		       SYSCTL_DESCR("TCP protocol control block list"),
		       sysctl_inpcblist, 0, &tcbtable, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE,
		       CTL_EOL);
	/* TCP socket buffers auto-sizing nodes */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "recvbuf_auto",
		       SYSCTL_DESCR("Enable automatic receive "
		           "buffer sizing (experimental)"),
		       NULL, 0, &tcp_do_autorcvbuf, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "recvbuf_inc",
		       SYSCTL_DESCR("Incrementor step size of "
		           "automatic receive buffer"),
		       NULL, 0, &tcp_autorcvbuf_inc, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "recvbuf_max",
		       SYSCTL_DESCR("Max size of automatic receive buffer"),
		       NULL, 0, &tcp_autorcvbuf_max, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "sendbuf_auto",
		       SYSCTL_DESCR("Enable automatic send "
		           "buffer sizing (experimental)"),
		       NULL, 0, &tcp_do_autosndbuf, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "sendbuf_inc",
		       SYSCTL_DESCR("Incrementor step size of "
		           "automatic send buffer"),
		       NULL, 0, &tcp_autosndbuf_inc, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "sendbuf_max",
		       SYSCTL_DESCR("Max size of automatic send buffer"),
		       NULL, 0, &tcp_autosndbuf_max, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);

	/* ECN subtree */
	sysctl_createv(clog, 0, NULL, &ecn_node,
	    	       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "ecn",
	    	       SYSCTL_DESCR("RFC3168 Explicit Congestion Notification"),
	    	       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &ecn_node, NULL,
	    	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "enable",
		       SYSCTL_DESCR("Enable TCP Explicit Congestion "
			   "Notification"),
	    	       NULL, 0, &tcp_do_ecn, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &ecn_node, NULL,
	    	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxretries",
		       SYSCTL_DESCR("Number of times to retry ECN setup "
			       "before disabling ECN on the connection"),
	    	       NULL, 0, &tcp_ecn_maxretries, 0, CTL_CREATE, CTL_EOL);

	/* SACK gets it's own little subtree. */
	sysctl_createv(clog, 0, NULL, &sack_node,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "enable",
		       SYSCTL_DESCR("Enable RFC2018 Selective ACKnowledgement"),
		       NULL, 0, &tcp_do_sack, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SACK, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, &sack_node,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "maxholes",
		       SYSCTL_DESCR("Maximum number of TCP SACK holes allowed per connection"),
		       NULL, 0, &tcp_sack_tp_maxholes, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SACK, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, &sack_node,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "globalmaxholes",
		       SYSCTL_DESCR("Global maximum number of TCP SACK holes"),
		       NULL, 0, &tcp_sack_globalmaxholes, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SACK, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, &sack_node,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_INT, "globalholes",
		       SYSCTL_DESCR("Global number of TCP SACK holes"),
		       NULL, 0, &tcp_sack_globalholes, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_SACK, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "stats",
		       SYSCTL_DESCR("TCP statistics"),
		       NULL, 0, &tcpstat, sizeof(tcpstat),
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_STATS,
		       CTL_EOL);
#ifdef TCP_DEBUG
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "debug",
		       SYSCTL_DESCR("TCP sockets debug information"),
		       NULL, 0, &tcp_debug, sizeof(tcp_debug),
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_DEBUG,
		       CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_INT, "debx",
		       SYSCTL_DESCR("Number of TCP debug sockets messages"),
		       NULL, 0, &tcp_debx, sizeof(tcp_debx),
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_DEBX,
		       CTL_EOL);
#endif
#if NRND > 0
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "iss_hash",
		       SYSCTL_DESCR("Enable RFC 1948 ISS by cryptographic "
				    "hash computation"),
		       NULL, 0, &tcp_do_rfc1948, sizeof(tcp_do_rfc1948),
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE,
		       CTL_EOL);
#endif

	/* ABC subtree */

	sysctl_createv(clog, 0, NULL, &abc_node,
		       CTLFLAG_PERMANENT, CTLTYPE_NODE, "abc",
		       SYSCTL_DESCR("RFC3465 Appropriate Byte Counting (ABC)"),
		       NULL, 0, NULL, 0,
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &abc_node, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "enable",
		       SYSCTL_DESCR("Enable RFC3465 Appropriate Byte Counting"),
		       NULL, 0, &tcp_do_abc, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &abc_node, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "aggressive",
		       SYSCTL_DESCR("1: L=2*SMSS 0: L=1*SMSS"),
		       NULL, 0, &tcp_abc_aggressive, 0, CTL_CREATE, CTL_EOL);
#ifdef __QNXNTO__
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rttdflt",
		       SYSCTL_DESCR("Set default RTT estimate"),
		       sysctl_net_inet_tcp_tcpcbtemplate, 0, &tcp_rttdflt, sizeof(tcp_rttdflt),
		       CTL_NET, pf, IPPROTO_TCP, CTL_CREATE, CTL_EOL);


	/* Our custom net.inet.tcp.<foo> under qnx.net.inet.tcp.<foo> */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "qnx", NULL,
		       NULL, 0, NULL, 0,
		       CTL_QNX, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_QNX, CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, pfname, NULL,
		       NULL, 0, NULL, 0,
		       CTL_QNX, CTL_NET, pf, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, tcpname,
		       SYSCTL_DESCR("TCP related settings"),
		       NULL, 0, NULL, 0,
		       CTL_QNX, CTL_NET, pf, IPPROTO_TCP, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "hiwat_adjust",
		       SYSCTL_DESCR("Base sb_hiwat on peer mss"),
		       NULL, 0, &tcp_hiwat_adjust, 0,
		       CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_HIWAT_ADJUST, CTL_EOL);
	/*
	 * Control io-net delack behavior
	 */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "qnx_delack",
		       SYSCTL_DESCR("Enable QNX delack behavior"),
		       NULL, 0, &tcp_do_legacy_qnx_delack, 0,
		       CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_QNX_DELACK, CTL_EOL);

	/*
	 * Compat net.inet.tcp.hiwat_adjust, should use
	 * qnx.net.inet.tcp.hiwat_adjust above.
	 */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "hiwat_adjust",
		       SYSCTL_DESCR("Base sb_hiwat on peer mss"),
		       NULL, 0, &tcp_hiwat_adjust, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_HIWAT_ADJUST, CTL_EOL);
	/* rto */
	sysctl_createv(clog, 0, NULL, NULL,
	    	   CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "rto",
			   SYSCTL_DESCR("Retransmission timeout value"),
			   NULL, 0, &tcp_rto, 0,
			   CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_RTO, CTL_EOL);
	/* rto_limit */
	sysctl_createv(clog, 0, NULL, NULL,
			   CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
			   CTLTYPE_INT, "rto_limit",
			   SYSCTL_DESCR("Retransmission timeout counter"),
			   NULL, 0, &tcp_rto_limit, 0,
			   CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_RTO_LIMIT, CTL_EOL);
	/* rto_final_timeout */
	sysctl_createv(clog, 0, NULL, NULL,
			   CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
			   CTLTYPE_INT, "rto_final_timeout",
			   SYSCTL_DESCR("Retransmission timeout for final packet"),
			   NULL, 0, &tcp_rto_final_timeout, 0,
			   CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_RTO_FINAL_TIMEOUT, CTL_EOL);

	/* Change TCP FACK recovery to be based on IP_MAXPACKET rather
	 * than segmentsize (MSS) for interfaces which support TCP segmentation
	 * offload. This is actually a function of the peer implementing TSO,
	 * but there is no TCP negotiation parameter for this. This is meant
	 * for >= Gbit speeds assuming all hosts on the subnet are applying
	 * TSO. This would be applied against TCP connections to remote
	 * hosts as well. In this case it would be viewed that FACK recovery
	 * is disabled.
	 */
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "fack_tso_adjust",
		       SYSCTL_DESCR("Forward ACK recovery adjustment for TSO"),
		       NULL, 0, (pf == AF_INET) ? &tcp_fack_tso_adjust4 :
		       &tcp_fack_tso_adjust6, 0,
		       CTL_QNX, CTL_NET, pf, IPPROTO_TCP, TCPCTL_QNX_FACK_TSO,
		       CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "drop_synfin",
		       SYSCTL_DESCR("Drop SYN packets if FIN is also set"),
		       NULL, 0, &tcp_drop_synfin, 0,
		       CTL_NET, pf, IPPROTO_TCP, TCPCTL_DROP_SYNFIN, CTL_EOL);

#endif
}

/*
 * Sysctl for tcp variables.
 */
#ifdef INET
SYSCTL_SETUP(sysctl_net_inet_tcp_setup, "sysctl net.inet.tcp subtree setup")
{

	sysctl_net_inet_tcp_setup2(clog, PF_INET, "inet", "tcp");
}
#endif /* INET */

#ifdef INET6
SYSCTL_SETUP(sysctl_net_inet6_tcp6_setup, "sysctl net.inet6.tcp6 subtree setup")
{

	sysctl_net_inet_tcp_setup2(clog, PF_INET6, "inet6", "tcp6");
}
#endif /* INET6 */

#ifdef __QNXNTO__
static int
tcp_maxidle_sysctl_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	int error, newval;


	node = *rnode;
	newval = node.sysctl_data == &tcp_keepintvl ?
	    tcp_keepintvl : tcp_keepcnt;
	node.sysctl_data = &newval;

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	/* Where this either points to tcp_keepintvl or tcp_keepcnt */
	*(int*)rnode->sysctl_data = newval;
	/* One of the dependencies of tcp_maxidle has changed, recompute */
	tcp_maxidle = tcp_keepintvl * tcp_keepcnt;
	return EOK;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/tcp_usrreq.c $ $Rev: 912385 $")
#endif
