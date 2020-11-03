
#ifndef CALLOUT_NEW
#define CALLOUT_NEW
#endif
#include "opt_inet.h"

#include <net/if_extra.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <netinet/in_pcb.h>
#ifdef INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/tcp_var.h>

static void if_extra_keepalive_callout(void *);
static inline void getboundifp(struct tcpcb *, struct ifnet **);




struct if_extra {
#ifdef INET6
	int			dad_count;
#endif
	enum callout_clock_type	gtimer;
	int			tp_keepidle;
	callout_t		tp_callout;
	TAILQ_HEAD(, tcpcb)	tp_keepidle_queue;
};

void
if_extra_setgtimer(struct ifnet *ifp, enum callout_clock_type type)
{
	struct if_extra	*ife;

	if ((ife = ifp->if_extra) != NULL) {
		ife->gtimer = type;
		log(LOG_INFO, "%s set gtimer %d", ifp->if_xname, type);
	}
}

enum callout_clock_type
if_extra_tp_getgtimer(struct tcpcb *tp)
{
	struct ifnet *ifp;
	struct if_extra	*ife;

	getboundifp(tp, &ifp);

	if (ifp == NULL || (ife = ifp->if_extra) == NULL)
		return _CALLOUT_CLK_DEFAULT;

	return ife->gtimer;
}


int *
if_keepalive_ptr(struct ifnet *ifp)
{
	struct if_extra	*ife;

	if (ifp == NULL || (ife = ifp->if_extra) == NULL)
		return NULL;

	return &ife->tp_keepidle;
}

int *
if_dad_count_ptr(struct ifnet *ifp)
{
#ifdef INET6
	struct if_extra	*ife;

	if (ifp == NULL || (ife = ifp->if_extra) == NULL)
		return NULL;

	return &ife->dad_count;
#else
	return NULL;
#endif
}

void
if_extra_init(struct ifnet *ifp)
{
	struct if_extra	*ife;

	if ((ife = malloc(sizeof(*ifp->if_extra), M_DEVBUF,
	    M_NOWAIT|M_ZERO)) != NULL) {
		TAILQ_INIT(&ife->tp_keepidle_queue);
		callout_init_new(&ife->tp_callout, CALLOUT_RANGE_EARLY);
#ifdef INET6
		/* Use global (traditional) dad_count, not this per iface val */
		ife->dad_count = DAD_COUNT_GLOBAL;
#endif
	}
	ifp->if_extra = ife;
}

#ifdef NDEBUG
#define VERIFY_TP(tp, ifp) (void)0
#else
#define VERIFY_TP(tp, ifp) do {		\
	struct ifnet *ifp2;		\
					\
	getboundifp(tp, &ifp2);		\
	if (ifp2 != ifp)		\
		panic("VERIFY_TP");	\
} while (0)
#endif


void
if_extra_destroy(struct ifnet *ifp)
{
	struct if_extra	*ife;
	struct tcpcb	*tp;

	if (ifp == NULL || (ife = ifp->if_extra) == NULL)
		return;

	/*
	 * 0 this out before calling if_keepalive_stop() below
	 * so that this interface timeout doesn't get restarted.
	 */
	ife->tp_keepidle = 0;

	while ((tp = TAILQ_FIRST(&ife->tp_keepidle_queue)) != NULL) {
		VERIFY_TP(tp, ifp);
		if_keepalive_stop(tp, ifp, 1);
	}
	callout_stop_new(&ife->tp_callout);

	ifp->if_extra = NULL;

	free(ife, M_DEVBUF);
}

static void
if_extra_keepalive_callout(void *arg)
{
	struct if_extra	*ife;
	struct tcpcb	*tp, *tp_next;
	int		tticks;

	ife = arg;

	tp_next = TAILQ_FIRST(&ife->tp_keepidle_queue);
	while ((tp = tp_next) != NULL) {
		tp_next = TAILQ_NEXT(tp, t_bound_keep);
		TAILQ_REMOVE(&ife->tp_keepidle_queue, tp, t_bound_keep);
		memset(&tp->t_bound_keep, 0x00, sizeof(tp->t_bound_keep));

		/* Call tcp_timer(tp) */
		tp->t_keepidle = ife->tp_keepidle; /* In case ife->tp_keepidl was changed */
		callout_runnow(&tp->t_timer[TCPT_KEEP], (tp));
	}

	if (!TAILQ_EMPTY(&ife->tp_keepidle_queue)) {
		tticks = ife->tp_keepidle * (hz / PR_SLOWHZ);
		/* We allow a range of 1/8th early */
		callout_reset_new(&ife->tp_callout, tticks,
		    if_extra_keepalive_callout, ife, ife->gtimer, tticks>>3);
	}
}

#define TP_ON_IFLIST(tp) ((tp)->t_bound_keep.tqe_prev != NULL)


void
if_keepalive_start(struct tcpcb *tp)
{
	int		kick, tticks;
	struct if_extra	*ife;
	struct ifnet    *ifp;

	getboundifp(tp, &ifp);

	if (ifp == NULL || (ife = ifp->if_extra) == NULL ||
	    ife->tp_keepidle == 0) {
		int tticks;

		/*
		 * What was traditionally done, except group timer
		 * may be used if enabled.
		 */

		/* we allow 1/8th range if using gtimers */
		tticks = tp->t_keepidle * hz / PR_SLOWHZ;

		callout_schedule_new(&tp->t_timer[TCPT_KEEP], tticks,
		    if_extra_tp_getgtimer(tp) , tticks >> 3);
				            
		return;
	}

	/*
	 * In case initial keepidle period expired and it's
	 * in tcp_keepintvl * tcp_keepcnt phase.
	 */
	callout_stop_new(&tp->t_timer[TCPT_KEEP]);

	if (!TP_ON_IFLIST(tp)) {
		if (TAILQ_EMPTY(&ife->tp_keepidle_queue))
			kick = 1;
		else
			kick = 0;

		/*
		 * We insert on HEAD in case we're being called
		 * from tcp_keep() as a result of if_extra_keepalive_callout()
		 * walking this list (head to tail).  We don't want it
		 * to hit this entry twice.
		 */
		TAILQ_INSERT_HEAD(&ife->tp_keepidle_queue, tp, t_bound_keep);
		tp->t_keepidle_orig = tp->t_keepidle;
		tp->t_keepidle = ife->tp_keepidle;
		if (kick) {
			tticks = ife->tp_keepidle * (hz / PR_SLOWHZ);
			/* We allow a range of 1/8th early */
			callout_reset_new(&ife->tp_callout, tticks,
			    if_extra_keepalive_callout, ife, ife->gtimer,
			    tticks>>3);
		}
	}
	else {
		/* Already on list.  Nothing to do */
	}
}

void
if_keepalive_stop(struct tcpcb *tp, struct ifnet *ifp, int restart)
{
	struct if_extra	*ife;

	if (!TP_ON_IFLIST(tp))
		return;

	if (ifp == NULL)
		getboundifp(tp, &ifp);

	if (ifp == NULL || (ife = ifp->if_extra) == NULL) {
		/*
		 * Shouldn't happen as check above means we think
		 * we're on this list
		 */
		panic("if_keepalive_stop");
		return;
	}

	TAILQ_REMOVE(&ife->tp_keepidle_queue, tp, t_bound_keep);
	memset(&tp->t_bound_keep, 0x00, sizeof(tp->t_bound_keep));
	tp->t_keepidle = tp->t_keepidle_orig;
	if (restart)
		tcp_timer_keep_est(tp); /* restart traditional timer */
}

void
if_keepalive_stop_inp(struct inpcb_hdr *inph, struct ifnet *ifp, int restart)
{
	struct inpcb		*inp;
#ifdef INET6
	struct in6pcb		*in6p;
#endif
	const struct socket	*so;
	struct tcpcb		*tp;

	switch (inph->inph_af) {
	case PF_INET:
		inp = (struct inpcb *)inph;
		so = inp->inp_socket;

		if (so != NULL && so->so_proto != NULL &&
		    so->so_proto->pr_protocol == IPPROTO_TCP &&
		    (tp = intotcpcb(inp)) != NULL) {
			if_keepalive_stop(tp, ifp, restart);
		}
		break;
#ifdef INET6
	case PF_INET6:
		in6p = (struct in6pcb *)inph;
		so = in6p->in6p_socket;

		if (so != NULL && so->so_proto != NULL &&
		    so->so_proto->pr_protocol == IPPROTO_TCP &&
		    (tp = in6totcpcb(in6p)) != NULL) {
			if_keepalive_stop(tp, ifp, restart);
		}
		break;
#endif
	default:
		break;
	}
}

static inline void
getboundifp(struct tcpcb *tp, struct ifnet **ifpp)
{
	*ifpp = NULL;

	if (tp->t_inpcb) {
		*ifpp = tp->t_inpcb->inp_bounddevice;
	}
#ifdef INET6 
	else if (tp->t_in6pcb) {
		*ifpp = tp->t_in6pcb->in6p_bounddevice;
	}
#endif
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_extra.c $ $Rev: 835196 $")
#endif
