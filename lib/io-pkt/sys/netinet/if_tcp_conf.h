#ifdef _KERNEL
#include <net/if.h>

int if4_tcp_conf_node;
int if6_tcp_conf_node;

void if_tcp_ifconf_add(struct ifnet *ifp);
void if_tcp_ifconf_remove(struct ifnet *ifp);
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/if_tcp_conf.h $ $Rev: 680336 $")
#endif
