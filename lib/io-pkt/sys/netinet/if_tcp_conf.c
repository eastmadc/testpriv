#include <stdlib.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/if_tcp_conf.h>
#include <netinet/tcp_var.h>
#include <net/if_extra.h>

int if4_tcp_conf_node;
int if6_tcp_conf_node;



/*
 * Called during if_attach.  This gives us a chance to set up interface
 * specific sysctl settings.
 */
void if_tcp_ifconf_add(struct ifnet *ifp)
{
	int *if_keep;

	if (ifp->if_type == IFT_LOOP) {
	    /*
	     * Multiple "lo0" across different FIBs cause sysctl issues
	     * and TCP keepalives are useless on loopback interfaces
	     */
	    return;
	}

	if ((if_keep = if_keepalive_ptr(ifp)) == NULL)
		return;

	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READONLY,
				   CTLTYPE_NODE, ifp->if_xname,
				   SYSCTL_DESCR("interface specific settings"),
				   NULL, 0, NULL, 0,
				   CTL_NET, PF_INET, IPPROTO_TCP, if4_tcp_conf_node, ifp->if_index, CTL_EOL);

	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READWRITE,
				   CTLTYPE_INT, "if_keep",
				   SYSCTL_DESCR("interface specific keepalive value"),
				   NULL, 0, if_keep, 0,
				   CTL_NET, PF_INET, IPPROTO_TCP, if4_tcp_conf_node, ifp->if_index, TCPCTL_IF_KEEP, CTL_EOL);

#ifdef INET6
	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READONLY,
				   CTLTYPE_NODE, ifp->if_xname,
				   SYSCTL_DESCR("interface specific settings"),
				   NULL, 0, NULL, 0,
				   CTL_NET, PF_INET6, IPPROTO_TCP, if6_tcp_conf_node, ifp->if_index, CTL_EOL);

	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READWRITE,
				   CTLTYPE_INT, "if_keep",
				   SYSCTL_DESCR("interface specific keepalive value"),
				   NULL, 0, if_keep, 0,
				   CTL_NET, PF_INET6, IPPROTO_TCP, if6_tcp_conf_node, ifp->if_index, TCPCTL_IF_KEEP, CTL_EOL);
#endif
}

/*
 * Called during if_detach.  This allows us to remove any interface specific
 * sysctl settings.
 */
void if_tcp_ifconf_remove(struct ifnet *ifp)
{
	if (ifp->if_type == IFT_LOOP) {
	    return;
	}

	sysctl_destroyv(NULL, CTL_NET, PF_INET, IPPROTO_TCP, if4_tcp_conf_node, ifp->if_index, TCPCTL_IF_KEEP, CTL_EOL);
	sysctl_destroyv(NULL, CTL_NET, PF_INET, IPPROTO_TCP, if4_tcp_conf_node, ifp->if_index, CTL_EOL);

	sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_TCP, if6_tcp_conf_node, ifp->if_index, TCPCTL_IF_KEEP, CTL_EOL);
	sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_TCP, if6_tcp_conf_node, ifp->if_index, CTL_EOL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/if_tcp_conf.c $ $Rev: 724903 $")
#endif
