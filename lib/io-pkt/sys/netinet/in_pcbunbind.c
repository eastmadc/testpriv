
#include "opt_inet.h"

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <netinet/in_pcb_hdr.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6.h>

#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>

extern struct inpcbtable rawcbtable;
#ifdef INET6
extern struct inpcbtable raw6cbtable;
#endif

static int inpcblist_unbindif_tbl(struct ifnet *, struct sockaddr *,
    struct inpcbtable *);

int
inpcblist_unbindif(struct ifnet *ifp, struct sockaddr *paddr)
{
	if (!ip_bindinterface)
		return 0;
	inpcblist_unbindif_tbl(ifp, paddr, &tcbtable);
	inpcblist_unbindif_tbl(ifp, paddr, &udbtable);
	inpcblist_unbindif_tbl(ifp, paddr, &rawcbtable);
#ifdef INET6
	inpcblist_unbindif_tbl(ifp, paddr, &raw6cbtable);
#endif
	return 0;
}

static int
inpcblist_unbindif_tbl(struct ifnet *ifp, struct sockaddr *paddr, struct inpcbtable *pcbtbl)
{
#ifdef INET
	struct sockaddr_in *in;
	struct inpcb *inp;
#endif
#ifdef INET6
	struct sockaddr_in6 *in6;
	struct in6pcb *in6p;
#endif
	const struct socket *so;
	struct inpcb_hdr *inph, *inph_next;
	struct tcpcb *tp;

	/*
	 * We can't use CIRCLEQ_FOREACH since inp may be freed
	 * in middle of loop: eg. by tcp_drop().  Therefore
	 * we have to find next member at top of loop.
	 */
	if (CIRCLEQ_EMPTY(&pcbtbl->inpt_queue))
		return 0;

	for (inph = CIRCLEQ_FIRST(&pcbtbl->inpt_queue); inph != NULL; inph = inph_next) {
		inph_next = CIRCLEQ_LOOP_NEXT(&pcbtbl->inpt_queue, inph,
		    inph_queue);
		if (inph_next == CIRCLEQ_FIRST(&pcbtbl->inpt_queue))
			inph_next = NULL;

		switch (inph->inph_af) {
#ifdef INET
		case PF_INET:
			if (paddr->sa_family != PF_INET)
				break;
			inp = (struct inpcb *)inph;
			in = satosin(paddr);
			so = inp->inp_socket;

			if (inp->inp_bounddevice == ifp &&
			    in_hosteq(in->sin_addr, inp->inp_laddr)) {
				in_unbindif(inp);
				if (so != NULL && so->so_proto != NULL &&
				    so->so_proto->pr_protocol == IPPROTO_TCP &&
				    (tp = intotcpcb(inp)) != NULL) {
					tcp_drop(tp, ECONNABORTED);
				}
			}

			break;
#endif
#ifdef INET6
		case PF_INET6:
			in6p = (struct in6pcb *)inph;
			so = in6p->in6p_socket;
			if (in6p->in6p_bounddevice != ifp)
				break;

			if (IN6_IS_ADDR_V4MAPPED(&in6p->in6p_laddr) &&
			    paddr->sa_family == PF_INET) {
				struct in_addr iad;
				iad.s_addr = in6p->in6p_laddr.s6_addr32[3];
				in = satosin(paddr);
				if (!in_hosteq(in->sin_addr, iad))
					break;
			}
			else if (paddr->sa_family != PF_INET6)
				break;
			else {
				in6 = satosin6(paddr);
				if (!IN6_ARE_ADDR_EQUAL(&in6->sin6_addr, &in6p->in6p_laddr))
					break;
			}
			in6_unbindif(in6p);
			if (so != NULL && so->so_proto != NULL &&
			    so->so_proto->pr_protocol == IPPROTO_TCP &&
			    (tp = in6totcpcb(in6p)) != NULL) {
				tcp_drop(tp, ECONNABORTED);
			}

			break;
#endif
		default:
			break;
		}

	}

	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/in_pcbunbind.c $ $Rev: 757178 $")
#endif
