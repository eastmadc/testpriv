#include <stdlib.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <netinet6/ip6_ifconf.h>
#include <net/if_extra.h>

int if_ip6_conf_node;

/*
 *  accept_rtadv is being stored as a flag, so a helper function is needed
 *  with sysctl.  Within the sysctl tree the value of this flag will be set to
 *  0 or 1, but we need to translate that over to a bit flag for our own use.
 */
static int
ip6_accept_rtadv_sysctl_handler(SYSCTLFN_ARGS)
{
	int error, t, orig;
	struct sysctlnode node;

	node = *rnode;
	/* grab a snapshot of the set flags */
	orig = *(int*)node.sysctl_data;
	/* as far as sysctl is concerned we only deal with 1 or 0, so convert over
	 * for them
	 */
	t    = (orig & IFF_ACCEPTRTADV)?1:0;
	node.sysctl_data = &t;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	/* boundary checks */
	if (t < 0 || t > 1)
		return (EINVAL);

	/* clear or set the flag */
	*(int*)rnode->sysctl_data = (orig & ~IFF_ACCEPTRTADV) | (t == 1?IFF_ACCEPTRTADV:0);
	return (0);
}

/*
 *  ip6forwarding is being stored as a flag, so a helper function is needed
 *  with sysctl.  Within the sysctl tree the value of this flag will be set to
 *  0 or 1, but we need to translate that over to a bit flag for our own use.
 */
static int
ip6_forwarding_sysctl_handler(SYSCTLFN_ARGS)
{
	int error, t, orig;
	struct sysctlnode node;

	node = *rnode;
	/* grab a snapshot of the set flags */
	orig = *(int*)node.sysctl_data;
	/* as far as sysctl is concerned we only deal with 1 or 0, so convert over
	 * for them
	 */
	t    = (orig & IFF_IP6FORWARDING)?1:0;
	node.sysctl_data = &t;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return (error);

	/* boundary checks */
	if (t < 0 || t > 1)
		return (EINVAL);

	/* clear or set the flag */
	*(int*)rnode->sysctl_data = (orig & ~IFF_IP6FORWARDING) | (t == 1?IFF_IP6FORWARDING:0);
	return (0);
}

/*
 * Called during if_attach.  This gives us a chance to set up interface
 * specific sysctl settings.
 */
void if_ip6_ifconf_add(struct ifnet *ifp)
{
	int *dad_count;

	/* some interfaces are not IPv6 capable */
	switch (ifp->if_type) {
		case IFT_BRIDGE:
		case IFT_LOOP:
#ifdef IFT_PFLOG
		case IFT_PFLOG:
#endif
#ifdef IFT_PFSYNC
		case IFT_PFSYNC:
#endif
			return;
	}

	dad_count = if_dad_count_ptr(ifp);

	/*
	 *  Ignoring errors, not much we can do about them.
	 */
	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READONLY,
				   CTLTYPE_NODE, ifp->if_xname,
				   SYSCTL_DESCR("interface specific settings"),
				   NULL, 0, NULL, 0,
				   CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, CTL_EOL);

	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READWRITE,
				   CTLTYPE_INT, "accept_rtadv",
				   SYSCTL_DESCR("Accept router advertisements"),
				   ip6_accept_rtadv_sysctl_handler, 0, &ifp->if_flags, 0,
				   CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_ACCEPT_RTADV, CTL_EOL);
				   
	sysctl_createv(NULL, 0, NULL, NULL,
				   CTLFLAG_READWRITE,
				   CTLTYPE_INT, "forwarding",
				   SYSCTL_DESCR("Allow IPv6 forwarding"),
				   ip6_forwarding_sysctl_handler, 0, &ifp->if_flags, 0,
				   CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_FORWARDING, CTL_EOL);
	if (dad_count != NULL) {
		sysctl_createv(NULL, 0, NULL, NULL,
		    CTLFLAG_READWRITE,
		    CTLTYPE_INT, "dad_count",
		    SYSCTL_DESCR("Duplicate address detection count"),
		    NULL, 0, dad_count, 0,
		    CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_DAD_DISABLE, CTL_EOL);
	}
}

/*
 * Called during if_detach.  This allows us to remove any interface specific
 * sysctl settings.
 */
void if_ip6_ifconf_remove(struct ifnet *ifp)
{
	int *dad_count;

	/* some interfaces are not IPv6 capable */
	switch (ifp->if_type) {
		case IFT_BRIDGE:
		case IFT_LOOP:
#ifdef IFT_PFLOG
		case IFT_PFLOG:
#endif
#ifdef IFT_PFSYNC
		case IFT_PFSYNC:
#endif
			return;
	}

	/*
	 *  Ignoring errors, not much we can do about them.
	 */
	dad_count = if_dad_count_ptr(ifp);
	if (dad_count != NULL) {
		sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_DAD_DISABLE, CTL_EOL);
	}
	sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_ACCEPT_RTADV, CTL_EOL);
	sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, IPV6CTL_FORWARDING, CTL_EOL);
	sysctl_destroyv(NULL, CTL_NET, PF_INET6, IPPROTO_IPV6, if_ip6_conf_node, ifp->if_index, CTL_EOL);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet6/ip6_ifconf.c $ $Rev: 835196 $")
#endif
