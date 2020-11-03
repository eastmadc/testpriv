#include <sys/callout.h>

struct tcpcb;
struct inpcb_hdr;

void if_extra_setgtimer(struct ifnet *, enum callout_clock_type);
enum callout_clock_type if_extra_tp_getgtimer(struct tcpcb *);

void if_extra_init(struct ifnet *);
void if_extra_destroy(struct ifnet *);

int * if_keepalive_ptr(struct ifnet *);

void if_keepalive_start(struct tcpcb *);
void if_keepalive_stop(struct tcpcb *, struct ifnet *, int);

int * if_dad_count_ptr(struct ifnet *);

void if_keepalive_stop_inp(struct inpcb_hdr *, struct ifnet *, int);

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_extra.h $ $Rev: 835196 $")
#endif
