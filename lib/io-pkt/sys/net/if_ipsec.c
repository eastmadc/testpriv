/*
 * $QNXtpLicenseC:
 * Copyright 2011, QNX Software Systems. All Rights Reserved.
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

#include "opt_inet.h"
#include "bpfilter.h"
#ifdef INET6
#include "opt_inet6.h"
#endif
#include "opt_ipsec.h"

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_ipsec.h>
#ifdef INET
#include <netinet/ip_var.h>
#include <netinet/ip.h>
#include <netipsec/ipsec_var.h>
#include <netinet/ip6.h>
#endif
#ifdef INET6
#include <netinet6/ip6_var.h>
/*#include <netinet6/ipsec.h>*/
#endif
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <net/netisr.h>
#include <sys/kauth.h>
#if NBPFILTER > 0
#include <sys/time.h>
#include <net/bpf.h>
#endif

#define	IFIPSEC_DEBUGGING		1
#define IFIPSEC_ALLOW_BYPASS	1

#define IFIPSEC_PRINTF( fmt, ... )											\
	printf( "[%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__ )

#if IFIPSEC_DEBUGGING
#define IFIPSEC_DEBUG( threshold, fmt, ... )	\
	do {										\
		if( ifipsec_debug > threshold ) {		\
			IFIPSEC_PRINTF( fmt, __VA_ARGS__ );	\
		}										\
	} while( 0 )
#else
#define IFIPSEC_DEBUG( fmt, ... )
#endif

static const int IPSEC_MTU = 1400;		/* default value, allows for 100 bytes of overhead */

struct ifipsec {
	struct ifnet *ifi_ifp;			/* may be NULL if interface is destroyed, but refcnt != 0 */
	struct ifnet *ifi_ifp_alloc;
	void *ifi_alloc;			/* used to free structure */
	int	ifi_flags;
	struct ifnet *ifi_outer;			/* the outer/public interface, may be NULL */
	int	 ifi_refcnt;			/* reference counter */
	struct ifi_linkmib {
		int ifim_encaplen;		/* encapsulation length */
		int ifim_mtufudge;		/* fudge MTU by this much */
	} ifi_mib;
	LIST_ENTRY( ifipsec ) ifi_list;
};
#define ifi_mtufudge	ifi_mib.ifim_mtufudge

static void	ifipsec_free(struct ifipsec *);
struct ifipsec*	ifipsec_alloc(struct ifnet *);
struct ifnet * ifipsec_is_valid(struct ifipsec *);


static int	ipsec_clone_create( struct if_clone *ifp, int unit );
static int	ipsec_clone_destroy( struct ifnet *ifp );
static int	ipsec_output( struct ifnet *ip, struct mbuf *m, struct sockaddr *sa, struct rtentry *rt );
static int	ipsec_ioctl( struct ifnet *ifp, u_long cmd, caddr_t data );
static int	ipsec_config( struct ifipsec *ifi, struct ifnet *p );
static void	ipsec_unconfig( struct ifnet *ifp );
void		ipsec_ifdetach( struct ifnet *outer );
void		ifipsecattach( int n );

static LIST_HEAD( , ifipsec ) ifi_list;

static int	ipsec_node;					/* used to create ipsecX sysctl nodes */
static int	ifipsec_debug = 0;			/* if true, enable global IPsec interface debugging */
#if IFIPSEC_ALLOW_BYPASS
static int	ipsec_allow_bypass = 0;		/* if true, we can pass packets in the raw, without IPsec */
#endif

struct if_clone ipsec_cloner =
	IF_CLONE_INITIALIZER( "ipsec", ipsec_clone_create, ipsec_clone_destroy );

void
ifipsecattach( int n )
{
	LIST_INIT( &ifi_list );
	if_clone_attach( &ipsec_cloner );
}

/*
 * ipsec_clone_create
 */
static int
ipsec_clone_create( struct if_clone *ifc, int unit )
{
	struct ifipsec *ifi;
	struct ifnet *ifp;
	void *head;
	int s;
	
	/*
	 * Keep the struct ifipsec and struct ifnet separate so that we can
	 * free the latter whenever the stack requires it, but can keep the
	 * former around to avoid dangling pointers in mid-crypto.
	 */
	head = malloc( sizeof( *ifi ) + NET_CACHELINE_SIZE, M_DEVBUF, M_WAITOK );
	if (head == NULL)
		panic( "%s:%d: head == NULL...", __FILE__, __LINE__);

	memset( head, 0, sizeof( *ifi ) + NET_CACHELINE_SIZE );
	ifi = NET_CACHELINE_ALIGN( head );
	ifi->ifi_alloc = head;
	
	head = malloc( sizeof( *ifp ) + NET_CACHELINE_SIZE, M_DEVBUF, M_WAITOK );
	if (head == NULL)
		panic( "%s:%d: head == NULL...", __FILE__, __LINE__);
	memset( head, 0, sizeof( *ifp ) + NET_CACHELINE_SIZE );
	ifp = NET_CACHELINE_ALIGN( head );
	ifi->ifi_ifp_alloc = head;
	ifi->ifi_ifp = ifp;
	
	ifi->ifi_refcnt = 1;	/* reference from ifp->if_softc */
	s = splnet();
	LIST_INSERT_HEAD( &ifi_list, ifi, ifi_list );
	splx( s );
	
	snprintf( ifp->if_xname, sizeof( ifp->if_xname ), "%s%d", ifc->ifc_name, unit );
	ifp->if_softc = ifi;
	ifp->if_flags = IFF_SIMPLEX|IFF_POINTOPOINT;	/* XXX do we need other flags here? */
	ifp->if_output = ipsec_output;
	ifp->if_input = ipsec_input;
	ifp->if_ioctl = ipsec_ioctl;
	IFQ_SET_READY( &ifp->if_snd );
	
	if_attach( ifp );
	ifp->if_type = IFT_TUNNEL;
	ifp->if_addrlen = 0;
	ifp->if_dlt = DLT_NULL;
	if_alloc_sadl( ifp );
#if NBPFILTER > 0
	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));
#endif
	IFIPSEC_DEBUG( 1, "Created '%s'", ifp->if_xname );

	return 0;
}

/*
 * ipsec_clone_destroy
 */
static int
ipsec_clone_destroy( struct ifnet *ifp )
{
	struct ifipsec *ifi = ifp->if_softc;
	int s;
	
	IFIPSEC_DEBUG( 1, "Destroying '%s'", ifp->if_xname );
	
	s = splnet();
	ipsec_unconfig( ifp );
	ifi->ifi_ifp = NULL;
#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	splx( s );
	
	if_detach( ifp );

	ifipsec_free( ifi );
	
	return 0;
}

/*
 * ipsec_config
 */
static int
ipsec_config( struct ifipsec *ifi, struct ifnet *p )
{
	struct ifnet *ifp = ifi->ifi_ifp;
	
	if( ifi->ifi_outer != NULL ) {
		return EBUSY;
	}
	
	ifi->ifi_outer = p;
	ifp->if_flags |= ( IFF_UP | IFF_RUNNING );
	ifp->if_mtu = p->if_mtu - ifi->ifi_mtufudge;
	
	return 0;
}

/*
 * ipsec_unconfig
 */
static void
ipsec_unconfig( struct ifnet *ifp )
{
	struct ifipsec *ifi = ifp->if_softc;
	
	if (ifi == NULL) {
		return;
	}

	if( ifi->ifi_outer == NULL ) {
		return;
	}

	ifi->ifi_outer = NULL;
	if (ifi->ifi_ifp != NULL) {
		ifi->ifi_ifp->if_mtu = 0;
	}
	ifi->ifi_flags = 0;
	
	if_down( ifp );
	ifp->if_flags &= ~( IFF_UP | IFF_RUNNING );
	ifp->if_capabilities_rx = 0;
	ifp->if_capabilities_tx = 0;
}

/*
 * ipsec_ifdetach
 *
 * XXX is this required?
 */
void
ipsec_ifdetach( struct ifnet *outer )
{
	struct ifipsec *ifi;
	int s;
	
	s = splnet();
	for( ifi = LIST_FIRST( &ifi_list ); ifi != NULL; ifi = LIST_NEXT( ifi, ifi_list ) ) {
		if( ifi->ifi_outer == outer ) {
			ipsec_unconfig( ifi->ifi_ifp );
		}
	}
	splx( s );
}

/*
 * ipsec_ioctl
 */
static int
ipsec_ioctl( struct ifnet *ifp, u_long cmd, caddr_t data )
{
	struct lwp *l = curlwp;
	struct ifipsec *ifi = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifipsecreq ipsecr;
	struct ifnet *pr;
	int error = 0;
	int s;
	
	s = splnet();

	switch( cmd ) {
		case SIOCSETIFIPSEC: /* overloaded */

			if( ( error = kauth_authorize_network( l->l_cred,
				KAUTH_NETWORK_INTERFACE,
				KAUTH_REQ_NETWORK_INTERFACE_SETPRIV,
			    ifp,
			    (void *)cmd,
				NULL ) ) != 0
			) {
				break;
			}
			curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
			if( ( error = copyin( data + sizeof( *ifr ), &ipsecr, sizeof( ipsecr ) ) ) != 0 ) {
				break;
			}
			if( ipsecr.ipsecr_parent[0] == '\0' ) {
				ipsec_unconfig( ifp );
				break;
			}

			if ((pr = ifunit(ipsecr.ipsecr_parent
#ifdef QNX_MFIB
			    , ANY_FIB
#endif
			    )) == 0 ) {
				error = ENOENT;
				break;
			}
			if( ( error = ipsec_config( ifi, pr ) ) != 0 ) {
				break;
			}
			ifp->if_flags |= IFF_RUNNING;
			break;
		
		case SIOCGETIFIPSEC: /* overloaded */
			memset( &ipsecr, 0, sizeof( ipsecr ) );
			if( ifi->ifi_outer != NULL ) {
				strlcpy(ipsecr.ipsecr_parent,ifi->ifi_outer->if_xname, sizeof(ipsecr.ipsecr_parent));
			}
					
			curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
			error = copyout( &ipsecr, data + sizeof( *ifr ), sizeof( ipsecr ) );
			break;
		case SIOCSIFMTU:
			if (ifi->ifi_ifp != NULL) {
				if (ifr->ifr_mtu >
				     (ifi->ifi_ifp->if_mtu - ifi->ifi_mtufudge))
					error = EINVAL;
				else
					ifp->if_mtu = ifr->ifr_mtu;
			} else
				error = EINVAL;
			break;
		case SIOCSIFADDR:
			/* XXX: ipsec i/f catch this case so we don't return EINVAL. */
			break;
		default:
			IFIPSEC_DEBUG( 1, "unhandled ioctl %ld", cmd );
			error = EINVAL;
			break;
	}
	
	splx( s );
	return error;
}
/*
 * ipsec_output
 */
static int
ipsec_output( struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst, struct rtentry *rt )
{
	struct ifipsec *ifi = ifp->if_softc;
	int error;
	int mlen;
	
	if( ( ifp->if_flags & ( IFF_UP | IFF_RUNNING ) ) != ( IFF_UP | IFF_RUNNING ) ) {
		m_free( m );
		error = ENETDOWN;
		goto end;
	}

	IFIPSEC_DEBUG(2 ,"ipsec_output: Entered ipsec_output ifi->outer = %s ifp = %s",ifi->ifi_outer->if_xname, ifp->if_xname);
	mlen = m->m_pkthdr.len;
#if NBPFILTER >0
	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, dst->sa_family, m);
#endif

	switch( dst->sa_family ) {
#ifdef INET
		case AF_INET:
			IFIPSEC_DEBUG(2 ,"ipsec_output:calling ip_output %s fib = %d", ifp->if_xname, if_get_first_fib(ifi->ifi_outer) );
			error = ip_output( m,
#ifdef QNX_MFIB
			    if_get_first_fib(ifi->ifi_outer), /* Use first outer fib */
#endif
			    /* struct mbuf *opt */ NULL,
			    /* struct route *ro */ NULL,
		            /* int flags */ IP_RAWOUTPUT | IP_BINDTODEVICE | IP_IPSECINNERIF,
		            /* struct ip_moptions *imo */ NULL,
			    /* int *p_mtu */ NULL,
			    /* struct ifnet *bounddevice */ ifi->ifi_outer,
			    /* Stops a continuous loop back to ip_output if no sp matches. */
			    /* struct ifnet *ipsechint */ ifp
			);
			IFIPSEC_DEBUG(2 ,"ipsec_output: done ip_output %s", ifp->if_xname );
			break;
#endif

#ifdef INET6
		case AF_INET6:
			error = ip6_output( m,
				/* struct ip6_pktopts *opt */ NULL,
				/* struct route_in6 *ro */ NULL,
				/* int flags */ 0,
				/* struct ip6_moptions *im6o */ NULL,
				/* struct socket *so */ NULL,
				/* struct ifnet **ifpp */ NULL,
				/* struct ifnet *bounddevice */ ifi->ifi_outer,
				/* struct ifnet *ipsechint */ ifp
#ifdef QNX_MFIB
				, if_get_first_fib(ifi->ifi_outer) /* Use first outer fib */
#endif
			);
			break;
#endif
		
		default:
			m_free( m );
			error = EAFNOSUPPORT;
			goto end;
	}
	
end:
	/* 'm' must be freed before getting here */
	switch( error ) {
		case 0:
			ifp->if_opackets += 1;
			ifp->if_obytes += mlen;
			break;

		case ENOENT:
			/* see ip_output.c:878..886 */
			error = 0;
			/* FALLTHROUGH */

		default:
			ifp->if_oerrors += 1;
			break;
	}
	return error;
}
/*
 * ipsec_input
 */
void
ipsec_input(struct ifnet *ifp, struct mbuf *m)
{
	int mlen;
	struct ip *ip = NULL;
	u_int32_t af = AF_INET;
	mlen = m->m_pkthdr.len;

	IFIPSEC_DEBUG(2 , "ipsec_input: changing rcvif from %s to %s\n",
		m->m_pkthdr.rcvif->if_xname, ifp->if_xname);

	m->m_pkthdr.rcvif = ifp;
	/*
	 * If the IP header is not aligned, slurp it up into a new
	 * mbuf with space for link headers, in the event we forward
	 * it.  Otherwise, if it is aligned, make sure the entire
	 * base IP header is in the first mbuf of the chain.
	 */
	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		if ((m = m_copyup(m, sizeof(struct ip),
				  (max_linkhdr + 3) & ~3)) == NULL) {
			ifp->if_iqdrops +=1;
			return;
		}
	} else if (__predict_false(m->m_len < sizeof (struct ip))) {
		if ((m = m_pullup(m, sizeof (struct ip))) == NULL) {
			ifp->if_iqdrops +=1;
			return;
		}
	}
	ip = mtod(m, struct ip *);
	if (ip->ip_v == IPVERSION) {
		af = AF_INET;
	} else if (ip->ip_v == IPV6_VERSION) {
		af = AF_INET6;
	} else {
		ifp->if_iqdrops +=1;
		return;
	}

#if NBPFILTER > 0
	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, af,m);
#endif
	ifp->if_ipackets += 1;
	ifp->if_ibytes += mlen;

	/*
	 * Re-dispatch via software interrupt for IPv4,
	 * return and let ipsec_callback handle for IPv6
	 */
	if (af == AF_INET)
		schednetisr(NETISR_IP);
	/* XXX: ipsec i/f For ipv6 let IPsec callback handle sending the packet up.*/

}

/*
 * Add a reference to the interface's internal structure.
 */
struct ifipsec*
ifipsec_alloc(struct ifnet *ifp)
{
	struct ifipsec *ifi = ifp->if_softc;
	int s;
	
	s = splnet();
	ifi->ifi_refcnt += 1;
	splx( s );
	IFIPSEC_DEBUG( 1, "Incremented '%s' reference count to %d", ifp->if_xname, ifi->ifi_refcnt );
	
	return ifi;
}

/*
 * Check to see if the IPsec interface reference is still valid.
 */
struct ifnet *
ifipsec_is_valid( struct ifipsec *ifi )
{
	int s;
	struct ifnet *ifp;
	
	/* XXX - ipsec i/f: is this spinlock required? */
	s = splnet();
	ifp = ifi->ifi_ifp;
	splx( s );
	
	return ifp;
}

/*
 * Remove the reference to the internal structure.
 */
static void
ifipsec_free( struct ifipsec *ifi )
{
	int s;

	if( ifi != NULL ) {
		ifi->ifi_refcnt -= 1;
		if(ifi->ifi_refcnt < 0) {
			/* warning warning, danger danger! */
			panic( "%s:%d: %p->ifi_refcnt=%d < 0!", __FILE__, __LINE__, ifi, ifi->ifi_refcnt );
		} else if (ifi->ifi_refcnt == 0) {
			/* no more references, free it */
			s = splnet();
			LIST_REMOVE( ifi, ifi_list );
			splx( s );
			if( ifi->ifi_ifp != NULL ) {
				panic( "%s:%d: %p->ifi_ifp=%p != NULL!", __FILE__, __LINE__, ifi, ifi->ifi_ifp );
			}
			free( ifi->ifi_ifp_alloc, M_DEVBUF );
			ifi->ifi_ifp_alloc = NULL;
		}
	}
}

/*
 * Configure the sysctl entries for this module.
 */
SYSCTL_SETUP( sysctl_ifipsec_setup, "sysctl net.link.ifipsec subtree setup" )
{
	const struct sysctlnode *node;
	int error = 0;
	
	if( ( error = sysctl_createv( clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "net", NULL,
	    NULL, 0, NULL, 0,
	    CTL_NET, CTL_EOL ) ) != 0 )
	{
		return;
	}

	if( ( error = sysctl_createv( clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "link", NULL,
	    NULL, 0, NULL, 0,
	    CTL_NET, AF_LINK, CTL_EOL ) ) != 0 )
	{
		return;
	}

	if( ( error = sysctl_createv( clog, 0, NULL, &node,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "ifipsec", NULL,
	    NULL, 0, NULL, 0,
	    CTL_NET, AF_LINK, CTL_CREATE, CTL_EOL ) ) != 0 )
	{
		return;
	}
	
	ipsec_node = ( node != NULL ) ? node->sysctl_num : 0;	/* XXX required??? */

	if( ( error = sysctl_createv( clog, 0, NULL, &node,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "debug",
		SYSCTL_DESCR( "Enable debug logging for all IPsec interfaces" ),
	    NULL, 0, &ifipsec_debug, 0,
	    CTL_NET, AF_LINK, IPSECCTL_DEBUG, CTL_EOL ) ) != 0 )
	{
		return;
	}
#if IFIPSEC_ALLOW_BYPASS
	if( ( error = sysctl_createv( clog, 0, NULL, &node,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "allow_bypass",
		SYSCTL_DESCR( "Allow IPsec interfaces to pass traffic with policy BYPASS or NONE" ),
	    NULL, 0, &ipsec_allow_bypass, 0,
	    CTL_NET, AF_LINK, IPSECCTL_BYPASS, CTL_EOL ) ) != 0 )
	{
		return;
	}
#endif
}


#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_ipsec.c $ $Rev: 724903 $")
#endif
