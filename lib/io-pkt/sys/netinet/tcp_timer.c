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



/*	$NetBSD: tcp_timer.c,v 1.85 2011/04/20 13:35:52 gdt Exp $	*/

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
 * Copyright (c) 1997, 1998, 2001, 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe and Kevin M. Lahey of the Numerical Aerospace Simulation
 * Facility, NASA Ames Research Center.
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
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
 *	@(#)tcp_timer.c	8.2 (Berkeley) 5/24/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: tcp_timer.c,v 1.85 2011/04/20 13:35:52 gdt Exp $");

#include "opt_inet.h"
#include "opt_tcp_debug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#endif

#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_congctl.h>
#include <netinet/tcpip.h>
#ifdef TCP_DEBUG
#include <netinet/tcp_debug.h>
#endif
#ifdef __QNXNTO__
#include <net/if_extra.h>
#endif

/*
 * Various tunable timer parameters.  These are initialized in tcp_init(),
 * unless they are patched.
 */
int	tcp_keepidle = 0;
int	tcp_keepintvl = 0;
int	tcp_keepcnt = 0;		/* max idle probes */
int	tcp_maxpersistidle = 0;		/* max idle time in persist */
int	tcp_maxidle;			/* computed in tcp_slowtimo() */

/*
 * Time to delay the ACK.  This is initialized in tcp_init(), unless
 * its patched.
 */
int	tcp_delack_ticks = 0;

void	tcp_timer_rexmt(void *);
void	tcp_timer_persist(void *);
void	tcp_timer_keep(void *);
void	tcp_timer_2msl(void *);
#ifdef __QNXNTO__ 
void	tcp_timer_rtolim(void *);
void	tcp_timer_rtofinal(void *);

void tcp_timer_rexmt_doit(void *, int);

int	tcp_rto;
int	tcp_rto_lim;
int	tcp_rto_final;
#endif

const tcp_timer_func_t tcp_timer_funcs[TCPT_NTIMERS] = {
	tcp_timer_rexmt,
	tcp_timer_persist,
	tcp_timer_keep,
	tcp_timer_2msl,
};

#ifdef __QNXNTO__

void
tcp_timer_rtofinal(void *arg)
{
	struct tcpcb	*tp;

	tp = arg;

	/* Let tcp_timer_rexmt_doit() drop the socket */
	tp->t_rxtshift = TCP_MAXRXTSHIFT;
	tcp_timer_rexmt_doit(tp, 0);
}

void
tcp_timer_rtolim(void *arg)
{
	struct tcpcb	*tp;
	int		lim;

	tp = arg;

	/*
	 * Apply final timeout after rtolim.  Can't use
	 * t_rtfinal independently of t_rtlim: this is
	 * as per design doc.
	 *
	 * lim may need to be calculated using last timeout
	 * so do so before tcp_timer_rexmt_doit fiddles with
	 * t_rxtshift.
	 */

	if ((lim = tp->t_rtfinal) == 0) {
		/*
		 * t_rtfinal not specified so use last timeout
		 * first calculate how much time was spent on retransmits so far
		 * at least one retransmit has happened so far, i.e. t_rxshift >=1
		 */
		int x = 0;
		for ( ;  x < tp->t_rxtshift; x++ ){
			lim += tcp_backoff[ x ];
		}

		lim = tp->t_rtfixed * ( tp->t_rtlim - lim );
		if ( lim == 0 ) {
			/*
			 * last retransmit is done exactly at final time
			 * use the last backoff 'bracket' value
			 */
			lim = tp->t_rtfixed * tcp_backoff[ tp->t_rxtshift - 1 ];
		}
	}

	/* Send out the final packet */
	tcp_timer_rexmt_doit(tp, 1);

	/* Make sure no retransmit packets go out after this one */
	callout_stop_new(&tp->t_timer[TCPT_REXMT]);

	/*
	 * Set timeout to acually drop the socket using lim from above.
	 * Note we reuse t_timer_rtolim callout slot but specify a different
	 * func.  This means simply cancelling t_timer_rtolim when a packet
	 * comes in in either state handles all cases.
	 */
	callout_reset_new(&tp->t_timer_rtolim, lim * (hz / PR_SLOWHZ),
		 tcp_timer_rtofinal, tp, _CALLOUT_CLK_DEFAULT, 0 );

}

void
tcp_rexmit_fixed(struct tcpcb *tp, int nticks, int first)
{
	if ( ( tp->t_rtlim == 0 ) || ( tp->t_rtfixed == 0 ) || ( first == 0 ) ) {
		/*
		 * No RTO limit or value is set or
		 * First unfixed timeout or exponential backoff
		 */
		TCP_TIMER_ARM_ORG(tp, TCPT_REXMT, nticks);
	}
	else if ( first ) {
		callout_reset_new(&tp->t_timer_rtolim, (tp->t_rtfixed * tp->t_rtlim) *
			(hz / PR_SLOWHZ), tcp_timer_rtolim, tp, _CALLOUT_CLK_DEFAULT, 0 );
		/*avoid sending twice the final packet*/
		if ( tp->t_rtlim > 1 ){
			/* Ignore nticks and start at rtfixed */
			TCP_TIMER_ARM_ORG(tp, TCPT_REXMT, tp->t_rtfixed);
		}
	}
}
#endif

/*
 * Timer state initialization, called from tcp_init().
 */
void
tcp_timer_init(void)
{

	if (tcp_keepidle == 0)
		tcp_keepidle = TCPTV_KEEP_IDLE;

	if (tcp_keepintvl == 0)
		tcp_keepintvl = TCPTV_KEEPINTVL;

	if (tcp_keepcnt == 0)
		tcp_keepcnt = TCPTV_KEEPCNT;

	if (tcp_maxpersistidle == 0)
		tcp_maxpersistidle = TCPTV_KEEP_IDLE;

	if (tcp_delack_ticks == 0)
		tcp_delack_ticks = TCP_DELACK_TICKS;
#ifdef __QNXNTO__
	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;
#endif
}

/*
 * Return how many timers are currently being invoked.
 */
int
tcp_timers_invoking(struct tcpcb *tp)
{
	int i;
	int count = 0;

	for (i = 0; i < TCPT_NTIMERS; i++)
		if (callout_invoking_new(&tp->t_timer[i]))
			count++;
	if (callout_invoking(&tp->t_delack_ch))
		count++;

	return count;
}

/*
 * Callout to process delayed ACKs for a TCPCB.
 */
void
tcp_delack(void *arg)
{
	struct tcpcb *tp = arg;
	int s;

	/*
	 * If tcp_output() wasn't able to transmit the ACK
	 * for whatever reason, it will restart the delayed
	 * ACK callout.
	 */

	s = splsoftnet();
	callout_ack(&tp->t_delack_ch);
	if (tcp_isdead(tp)) {
		splx(s);
		return;
	}

	tp->t_flags |= TF_ACKNOW;
	(void) tcp_output(tp);
	splx(s);
}

#ifdef __QNXNTO__
int
tcp_slowticks(int *ticks_last)
{
	/* tcp_slowtimo() is driven off pfslowtime() */
	return pfslowtimo_ticks(ticks_last);
}

void
tcp_now_snap(void)
{
	static int ticks_last;

	tcp_now += tcp_slowticks(&ticks_last);
}
#endif
/*
 * Tcp protocol timeout routine called every 500 ms.
 * Updates the timers in all active tcb's and
 * causes finite state machine actions if timers expire.
 */
#ifndef __QNXNTO__
void
#else
int
#endif
tcp_slowtimo(void)
{
#ifndef __QNXNTO__
	int s;

	s = splsoftnet();
	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;
	tcp_iss_seq += TCP_ISSINCR;			/* increment iss */
	tcp_now++;					/* for timestamps */
	splx(s);
#else
	/*
	 * tcp_maxidle is incremented in sysctl handler for
	 * tcp_keepcnt / tcp_keepintvl.
	 */

	/* We increment tcp_iss_seq prior to use */

	/* we tcp_now_snap() prior to use */
	return 0; /* nothing to do here, move along */
#endif
}

/*
 * Cancel all timers for TCP tp.
 */
void
tcp_canceltimers(struct tcpcb *tp)
{
	int i;

#ifdef __QNXNTO__
	if_keepalive_stop(tp, NULL, 0);
#endif
	for (i = 0; i < TCPT_NTIMERS; i++)
		TCP_TIMER_DISARM(tp, i);
}

const int	tcp_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64 };

const int	tcp_totbackoff = 511;	/* sum of tcp_backoff[] */

/*
 * TCP timer processing.
 */

void
tcp_timer_rexmt(void *arg)
{
#ifdef __QNXNTO__
	tcp_timer_rexmt_doit(arg, 0);
}

void
tcp_timer_rexmt_doit(void *arg, int final)
{
#endif
	struct tcpcb *tp = arg;
	uint32_t rto;
	int s;
#ifdef TCP_DEBUG
	struct socket *so = NULL;
	short ostate;
#endif
#ifdef QNX_MFIB
	int fib = DEFAULT_FIB;
	/* only one of t_inpcb or t_in6pcb will be set */
#ifdef INET
	if (tp->t_inpcb)
		fib = tp->t_inpcb->inp_socket->so_fibnum;
#endif
#ifdef INET6
	if (tp->t_in6pcb)
		fib = tp->t_in6pcb->in6p_socket->so_fibnum;
#endif
#endif

	s = splsoftnet();
	callout_ack_new(&tp->t_timer[TCPT_REXMT]);
	if (tcp_isdead(tp)) {
		splx(s);
		return;
	}

	if ((tp->t_flags & TF_PMTUD_PEND) && tp->t_inpcb &&
	    SEQ_GEQ(tp->t_pmtud_th_seq, tp->snd_una) &&
	    SEQ_LT(tp->t_pmtud_th_seq, (int)(tp->snd_una + tp->t_ourmss))) {
		extern struct sockaddr_in icmpsrc;
		struct icmp icmp;

		tp->t_flags &= ~TF_PMTUD_PEND;

		/* XXX create fake icmp message with relevant entries */
		icmp.icmp_nextmtu = tp->t_pmtud_nextmtu;
		icmp.icmp_ip.ip_len = tp->t_pmtud_ip_len;
		icmp.icmp_ip.ip_hl = tp->t_pmtud_ip_hl;
		icmpsrc.sin_addr = tp->t_inpcb->inp_faddr;
#ifndef QNX_MFIB
		icmp_mtudisc(&icmp, icmpsrc.sin_addr);
#else
		icmp_mtudisc(&icmp, icmpsrc.sin_addr, fib);
#endif

		/*
		 * Notify all connections to the same peer about
		 * new mss and trigger retransmit.
		 */
		in_pcbnotifyall(&tcbtable, icmpsrc.sin_addr, EMSGSIZE,
		    tcp_mtudisc);
 		splx(s);
 		return;
 	}
#ifdef TCP_DEBUG
#ifdef INET
	if (tp->t_inpcb)
		so = tp->t_inpcb->inp_socket;
#endif
#ifdef INET6
	if (tp->t_in6pcb)
		so = tp->t_in6pcb->in6p_socket;
#endif
	ostate = tp->t_state;
#endif /* TCP_DEBUG */

	/*
	 * Clear the SACK scoreboard, reset FACK estimate.
	 */
	tcp_free_sackholes(tp);
	tp->snd_fack = tp->snd_una;

	/*
	 * Retransmission timer went off.  Message has not
	 * been acked within retransmit interval.  Back off
	 * to a longer retransmit interval and retransmit one segment.
	 */

	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
#ifndef __QNXNTO__
	/*
		* If the rtolim timer is set, it will handle the
		* final timeout.
		*/
		if (!final && !TCP_TIMER_ISARMED(tp, TCPT_RTOLIM)) {
#endif
		tcpstat.tcps_timeoutdrop++;
		tp = tcp_drop(tp, tp->t_softerror ?
		    tp->t_softerror : ETIMEDOUT);
		goto out;
#ifndef __QNXNTO__
		}
#endif
	}
	tcpstat.tcps_rexmttimeo++;
	rto = TCP_REXMTVAL(tp);
	if (rto < tp->t_rttmin)
		rto = tp->t_rttmin;
	TCPT_RANGESET(tp->t_rxtcur, rto * tcp_backoff[tp->t_rxtshift],
	    tp->t_rttmin, TCPTV_REXMTMAX);
#ifndef __QNXNTO__
	TCP_TIMER_ARM(tp, TCPT_REXMT, tp->t_rxtcur);
#else
	/*
	* If called from tcp_timer_rtolim() (TCPT_RTOLIM timer),
	* just send the final packet and don't rearm.
	*/
	if (!final) {
		/*
		* Can only use TCP_TIMER_ARM(, TCPT_REXMT, )
		* on the first setting as it always passes
		* the third arg to tcp_rexmit_fixed as 1.
		*/
		if (( tp->t_rtlim != 0 ) && ( tp->t_rtfixed != 0) ) {
			int rexmit_next;

			TCPT_RANGESET(rexmit_next,
				tp->t_rtfixed * tcp_backoff[tp->t_rxtshift],
				tp->t_rtfixed, TCPTV_REXMTMAX);
			tcp_rexmit_fixed(tp, rexmit_next, 0);
		}
		else
			tcp_rexmit_fixed(tp, tp->t_rxtcur, 0);
	}

#endif

	/*
	 * If we are losing and we are trying path MTU discovery,
	 * try turning it off.  This will avoid black holes in
	 * the network which suppress or fail to send "packet
	 * too big" ICMP messages.  We should ideally do
	 * lots more sophisticated searching to find the right
	 * value here...
	 */
	if (tp->t_mtudisc && tp->t_rxtshift > TCP_MAXRXTSHIFT / 6) {
		tcpstat.tcps_pmtublackhole++;

#ifdef INET
		/* try turning PMTUD off */
		if (tp->t_inpcb)
			tp->t_mtudisc = 0;
#endif
#ifdef INET6
		/* try using IPv6 minimum MTU */
		if (tp->t_in6pcb)
			tp->t_mtudisc = 0;
#endif

		/* XXX: more sophisticated Black hole recovery code? */
	}

	/*
	 * If losing, let the lower level know and try for
	 * a better route.  Also, if we backed off this far,
	 * our srtt estimate is probably bogus.  Clobber it
	 * so we'll take the next rtt measurement as our srtt;
	 * move the current srtt into rttvar to keep the current
	 * retransmit times until then.
	 */
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
#ifdef INET
		if (tp->t_inpcb)
			in_losing(tp->t_inpcb);
#endif
#ifdef INET6
		if (tp->t_in6pcb)
			in6_losing(tp->t_in6pcb);
#endif
		/*
		 * This operation is not described in RFC2988.  The
		 * point is to keep srtt+4*rttvar constant, so we
		 * should shift right 2 bits to divide by 4, and then
		 * shift right one bit because the storage
		 * representation of rttvar is 1/16s vs 1/32s for
		 * srtt.
		 */
		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	tp->snd_nxt = tp->snd_una;
	tp->snd_high = tp->snd_max;
	/*
	 * If timing a segment in this window, stop the timer.
	 */
	tp->t_rtttime = 0;
	/*
	 * Remember if we are retransmitting a SYN, because if
	 * we do, set the initial congestion window must be set
	 * to 1 segment.
	 */
	if (tp->t_state == TCPS_SYN_SENT)
		tp->t_flags |= TF_SYN_REXMT;

	/*
	 * Adjust congestion control parameters.
	 */
	tp->t_congctl->slow_retransmit(tp);

	(void) tcp_output(tp);

 out:
#ifdef TCP_DEBUG
	if (tp && so->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, NULL,
		    PRU_SLOWTIMO | (TCPT_REXMT << 8));
#endif
	splx(s);
}

void
tcp_timer_persist(void *arg)
{
	struct tcpcb *tp = arg;
	uint32_t rto;
	int s;
#ifdef TCP_DEBUG
	struct socket *so = NULL;
	short ostate;
#endif

	s = splsoftnet();
	callout_ack_new(&tp->t_timer[TCPT_PERSIST]);
	if (tcp_isdead(tp)) {
		splx(s);
		return;
	}

#ifdef TCP_DEBUG
#ifdef INET
	if (tp->t_inpcb)
		so = tp->t_inpcb->inp_socket;
#endif
#ifdef INET6
	if (tp->t_in6pcb)
		so = tp->t_in6pcb->in6p_socket;
#endif

	ostate = tp->t_state;
#endif /* TCP_DEBUG */

	/*
	 * Persistance timer into zero window.
	 * Force a byte to be output, if possible.
	 */

	/*
	 * Hack: if the peer is dead/unreachable, we do not
	 * time out if the window is closed.  After a full
	 * backoff, drop the connection if the idle time
	 * (no responses to probes) reaches the maximum
	 * backoff that we would use if retransmitting.
	 */
	rto = TCP_REXMTVAL(tp);
	if (rto < tp->t_rttmin)
		rto = tp->t_rttmin;
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
	    ((tcp_now - tp->t_rcvtime) >= tcp_maxpersistidle ||
	    (tcp_now - tp->t_rcvtime) >= rto * tcp_totbackoff)) {
		tcpstat.tcps_persistdrops++;
		tp = tcp_drop(tp, ETIMEDOUT);
		goto out;
	}
	tcpstat.tcps_persisttimeo++;
	tcp_setpersist(tp);
	tp->t_force = 1;
	(void) tcp_output(tp);
	tp->t_force = 0;

 out:
#ifdef TCP_DEBUG
	if (tp && so->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, NULL,
		    PRU_SLOWTIMO | (TCPT_PERSIST << 8));
#endif
	splx(s);
}

void
tcp_timer_keep(void *arg)
{
	struct tcpcb *tp = arg;
	struct socket *so = NULL;	/* Quell compiler warning */
	int s;
#ifdef TCP_DEBUG
	short ostate;
#endif

	s = splsoftnet();
	callout_ack_new(&tp->t_timer[TCPT_KEEP]);
	if (tcp_isdead(tp)) {
		splx(s);
		return;
	}

#ifdef TCP_DEBUG
	ostate = tp->t_state;
#endif /* TCP_DEBUG */

	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */

	tcpstat.tcps_keeptimeo++;
	if (TCPS_HAVEESTABLISHED(tp->t_state) == 0)
		goto dropit;
#ifdef INET
	if (tp->t_inpcb)
		so = tp->t_inpcb->inp_socket;
#endif
#ifdef INET6
	if (tp->t_in6pcb)
		so = tp->t_in6pcb->in6p_socket;
#endif
	KASSERT(so != NULL);
	if (so->so_options & SO_KEEPALIVE &&
	    tp->t_state <= TCPS_CLOSE_WAIT) {
	    	if ((tcp_maxidle > 0) &&
		    ((tcp_now - tp->t_rcvtime) >=
#ifndef __QNXNTO__
		     tcp_keepidle + tcp_maxidle
#else
		     tp->t_keepidle + tcp_maxidle
#endif
		    ))
			goto dropit;
		/*
		 * Send a packet designed to force a response
		 * if the peer is up and reachable:
		 * either an ACK if the connection is still alive,
		 * or an RST if the peer has closed the connection
		 * due to timeout or reboot.
		 * Using sequence number tp->snd_una-1
		 * causes the transmitted zero-length segment
		 * to lie outside the receive window;
		 * by the protocol spec, this requires the
		 * correspondent TCP to respond.
		 */
		tcpstat.tcps_keepprobe++;
		if (tcp_compat_42) {
			/*
			 * The keepalive packet must have nonzero
			 * length to get a 4.2 host to respond.
			 */
			(void)tcp_respond(tp, tp->t_template,
			    (struct mbuf *)NULL, NULL, tp->rcv_nxt - 1,
#ifndef QNX_MFIB
			    tp->snd_una - 1, 0);
#else
				tp->snd_una - 1, 0, so->so_fibnum);
#endif
		} else {
			(void)tcp_respond(tp, tp->t_template,
			    (struct mbuf *)NULL, NULL, tp->rcv_nxt,
#ifndef QNX_MFIB
			    tp->snd_una - 1, 0);
#else
				tp->snd_una - 1, 0, so->so_fibnum);
#endif
		}
		TCP_TIMER_ARM(tp, TCPT_KEEP, tcp_keepintvl);
	} else
#ifndef __QNXNTO__
		TCP_TIMER_ARM(tp, TCPT_KEEP, tcp_keepidle);
#else
		tcp_timer_keep_est(tp);
#endif

#ifdef TCP_DEBUG
	if (tp && so->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, NULL,
		    PRU_SLOWTIMO | (TCPT_KEEP << 8));
#endif
	splx(s);
	return;

 dropit:
	tcpstat.tcps_keepdrops++;
	(void) tcp_drop(tp, ETIMEDOUT);
	splx(s);
}

#ifdef __QNXNTO__
void tcp_timer_keep_est(struct tcpcb *tp)
{
	struct socket	*so;

	if (!TCPS_HAVEESTABLISHED(tp->t_state))
		return;

	so = NULL;

	if (tp->t_inpcb) {
		so = tp->t_inpcb->inp_socket;
	}
#ifdef INET6
	else if (tp->t_in6pcb) {
		so = tp->t_in6pcb->in6p_socket;
	}
#endif
	if (so != NULL && (so->so_options & SO_KEEPALIVE) == 0) {
		/*
		 * Once established, the func associated
		 * with this timer (tcp_timer_keep()) does
		 * nothing once but re-arm if SO_KEEPALIVE
		 * is not also set so don't bother arming it.
		 *
		 * Disarm the initial TCPTV_KEEP_INIT
		 * interval used to timeout the initial
		 * TCPS_SYN_[SENT|RECEIVED] state.
		 */
		TCP_TIMER_DISARM(tp, TCPT_KEEP);
		if_keepalive_stop(tp, NULL, 0);
	}
	else {
		/*
		 * Checks if there's a bound device with a per
		 * interface timeout, otherwise, uses tp->t_keepidle
		 */
		if_keepalive_start(tp);
	}


}
#endif

void
tcp_timer_2msl(void *arg)
{
	struct tcpcb *tp = arg;
	int s;
#ifdef TCP_DEBUG
	struct socket *so = NULL;
	short ostate;
#endif

	s = splsoftnet();
	callout_ack_new(&tp->t_timer[TCPT_2MSL]);
	if (tcp_isdead(tp)) {
		splx(s);
		return;
	}

	/*
	 * 2 MSL timeout went off, clear the SACK scoreboard, reset
	 * the FACK estimate.
	 */
	tcp_free_sackholes(tp);
	tp->snd_fack = tp->snd_una;

#ifdef TCP_DEBUG
#ifdef INET
	if (tp->t_inpcb)
		so = tp->t_inpcb->inp_socket;
#endif
#ifdef INET6
	if (tp->t_in6pcb)
		so = tp->t_in6pcb->in6p_socket;
#endif

	ostate = tp->t_state;
#endif /* TCP_DEBUG */

	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT, delete connection
	 * control block.  Otherwise, check again in a bit.
	 */
	if (tp->t_state != TCPS_TIME_WAIT &&
	    ((tcp_maxidle == 0) || ((tcp_now - tp->t_rcvtime) <= tcp_maxidle)))
		TCP_TIMER_ARM(tp, TCPT_2MSL, tcp_keepintvl);
	else
		tp = tcp_close(tp);

#ifdef TCP_DEBUG
	if (tp && so->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, NULL,
		    PRU_SLOWTIMO | (TCPT_2MSL << 8));
#endif
	splx(s);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/tcp_timer.c $ $Rev: 784808 $")
#endif
