#ifdef _KERNEL
#include <net/if.h>

extern int if_ip6_conf_node;

void if_ip6_ifconf_add(struct ifnet *ifp);
void if_ip6_ifconf_remove(struct ifnet *ifp);
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/ip6_ifconf.h $ $Rev: 680336 $")
#endif
