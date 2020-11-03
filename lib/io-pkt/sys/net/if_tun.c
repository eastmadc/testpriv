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

/*	$NetBSD: if_tun.c,v 1.113 2010/04/05 07:22:24 joerg Exp $	*/

/*
 * Copyright (c) 1988, Julian Onions <jpo@cs.nott.ac.uk>
 * Nottingham University 1987.
 *
 * This source may be freely distributed, however I would be interested
 * in any changes that are made.
 *
 * This driver takes packets off the IP i/f and hands them up to a
 * user process to have its wicked way with. This driver has its
 * roots in a similar driver written by Phil Cockcroft (formerly) at
 * UCL. This driver is based much more on read/write/poll mode of
 * operation though.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_tun.c,v 1.113 2010/04/05 07:22:24 joerg Exp $");

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/buf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/signalvar.h>
#include <sys/conf.h>
#include <sys/kauth.h>
#ifndef __QNXNTO__
#include <sys/simplelock.h>
#include <sys/cpu.h>
#else
#include <sys/file_bsd.h>
#include <sys/filedesc.h>
#include <nw_msg.h>
#include <sys/resmgr.h>
#include <notify.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>


#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_inarp.h>
#endif


#include "bpfilter.h"
#if NBPFILTER > 0
#include <sys/time.h>
#include <net/bpf.h>
#endif

#include <net/if_tun.h>

#ifdef __QNXNTO__
extern char *__prefix;
extern int __num_tun_control_interface;
#endif

#define TUNDEBUG	if (tundebug) printf
int	tundebug = 0;

extern int ifqmaxlen;
void	tunattach(int);

static LIST_HEAD(, tun_softc) tun_softc_list;
static LIST_HEAD(, tun_softc) tunz_softc_list;
#ifndef __QNXNTO__
static struct simplelock tun_softc_lock;
#endif

static int	tun_ioctl(struct ifnet *, u_long, caddr_t);
static int	tun_output(struct ifnet *, struct mbuf *,
			struct sockaddr *, struct rtentry *rt);
static int	tun_clone_create(struct if_clone *, int);
static int	tun_clone_destroy(struct ifnet *);

static struct if_clone tun_cloner =
    IF_CLONE_INITIALIZER("tun", tun_clone_create, tun_clone_destroy);

static void tunattach0(struct tun_softc *);
static void tuninit(struct tun_softc *);
static void tun_i_softintr(void *);
#ifdef ALTQ
static void tun_o_softintr(void *);
static void tunstart(struct ifnet *);
#endif
static struct tun_softc *tun_find_unit(dev_t);
static struct tun_softc *tun_find_zunit(int);

#ifndef __QNXNTO__
static dev_type_open(tunopen);
static dev_type_close(tunclose);
static dev_type_read(tunread);
static dev_type_write(tunwrite);
static dev_type_ioctl(tunioctl);
static dev_type_poll(tunpoll);
static dev_type_kqfilter(tunkqfilter);

const struct cdevsw tun_cdevsw = {
	tunopen, tunclose, tunread, tunwrite, tunioctl,
	nostop, notty, tunpoll, nommap, tunkqfilter, D_OTHER,
};
#else
static int	tunread(struct file *, off_t *, struct uio *, kauth_cred_t,
    int);
static int	tunwrite(struct file *, off_t *, struct uio *, kauth_cred_t,
    int);
static int	tunioctl(struct file *, u_long, void *, struct lwp *);
static int	tunpoll(struct file *, int, struct lwp *);
static int	tunclose(struct file *, struct lwp *);
static int	tunkqfilter(struct file *, struct knote *);
static int	tunclose1(struct file *, struct lwp *);

static const struct fileops tun_fileops = {
	tunread,
	tunwrite,
	tunioctl,
	fnullop_fcntl,
	tunpoll,
#ifndef __QNXNTO__
	fbadop_stat,
#else
	fnullop_stat,
#endif
	tunclose,
	tunkqfilter,
	tunclose1,
};
#endif

void
tunattach(int unused)
{

	simple_lock_init(&tun_softc_lock);
	LIST_INIT(&tun_softc_list);
	LIST_INIT(&tunz_softc_list);
	if_clone_attach(&tun_cloner);
}

/*
 * Find driver instance from dev_t.
 * Call at splnet().
 * Returns with tp locked (if found).
 */
static struct tun_softc *
tun_find_unit(dev_t dev)
{
	struct tun_softc *tp;
	int unit = minor(dev);

	simple_lock(&tun_softc_lock);
	LIST_FOREACH(tp, &tun_softc_list, tun_list)
		if (unit == tp->tun_unit)
			break;
	if (tp)
		simple_lock(&tp->tun_lock);
	simple_unlock(&tun_softc_lock);

	return (tp);
}

/*
 * Find zombie driver instance by unit number.
 * Call at splnet().
 * Remove tp from list and return it unlocked (if found).
 */
static struct tun_softc *
tun_find_zunit(int unit)
{
	struct tun_softc *tp;

	simple_lock(&tun_softc_lock);
	LIST_FOREACH(tp, &tunz_softc_list, tun_list)
		if (unit == tp->tun_unit)
			break;
	if (tp)
		LIST_REMOVE(tp, tun_list);
	simple_unlock(&tun_softc_lock);
#ifdef DIAGNOSTIC
	if (tp != NULL && (tp->tun_flags & (TUN_INITED|TUN_OPEN)) != TUN_OPEN)
		printf("tun%d: inconsistent flags: %x\n", unit, tp->tun_flags);
#endif

	return (tp);
}

static int
tun_clone_create(struct if_clone *ifc, int unit)
{
	struct tun_softc *tp;
#ifdef __QNXNTO__
	char ifnam_buf[PATH_MAX];
	struct nw_stk_ctl *sctlp = &stk_ctl;
#endif
	if ((tp = tun_find_zunit(unit)) == NULL) {
		/* Allocate a new instance */
		tp = malloc(sizeof(*tp), M_DEVBUF, M_WAITOK|M_ZERO);

		tp->tun_unit = unit;
		simple_lock_init(&tp->tun_lock);
#ifndef __QNXNTO__
		selinit(&tp->tun_rsel);
		selinit(&tp->tun_wsel);
#endif
	} else {
		/* Revive tunnel instance; clear ifp part */
		(void)memset(&tp->tun_if, 0, sizeof(struct ifnet));
	}

	if_initname(&tp->tun_if, ifc->ifc_name, unit);
	tunattach0(tp);
	tp->tun_flags |= TUN_INITED;
#ifndef __QNXNTO__
	tp->tun_osih = softint_establish(SOFTINT_CLOCK, tun_o_softintr, tp);
	tp->tun_isih = softint_establish(SOFTINT_CLOCK, tun_i_softintr, tp);
#endif

	simple_lock(&tun_softc_lock);
	LIST_INSERT_HEAD(&tun_softc_list, tp, tun_list);
	simple_unlock(&tun_softc_lock);

#ifdef __QNXNTO__
	if (unit >= __num_tun_control_interface) {
		iofunc_attr_init(&tp->tun_info.attr, S_IFCHR | 0600, 0, NULL);
		tp->tun_info.index = unit;
		tp->tun_info.domain = 0;
		tp->tun_info.path_type = PATH_TYPE_TUN;
		tp->dpp = sctlp->dpp;
		if (__prefix)
			snprintf(ifnam_buf, sizeof(ifnam_buf), "%s%s%s", __prefix, "/dev/", tp->tun_if.if_xname);
		else
			snprintf(ifnam_buf, sizeof(ifnam_buf), "%s%s","/dev/", tp->tun_if.if_xname);
		if ((tp->tun_info.path_id = resmgr_attach(tp->dpp, 0, ifnam_buf, _FTYPE_ANY, 0, &tcpip_connect_funcs, NULL, &tp->tun_info.attr)) == -1) {
			tun_clone_destroy(&tp->tun_if);
			return 0;
		}
	}
	else
		tp->tun_info.path_id = -1;
#endif
	return (0);
}

static void
tunattach0(struct tun_softc *tp)
{
	struct ifnet *ifp;

	ifp = &tp->tun_if;
	ifp->if_softc = tp;
	ifp->if_mtu = TUNMTU;
	ifp->if_ioctl = tun_ioctl;
	ifp->if_output = tun_output;
#ifdef ALTQ
	ifp->if_start = tunstart;
#endif
	ifp->if_flags = IFF_POINTOPOINT;
	ifp->if_type = IFT_TUNNEL;
	ifp->if_snd.ifq_maxlen = ifqmaxlen;
	ifp->if_collisions = 0;
	ifp->if_ierrors = 0;
	ifp->if_oerrors = 0;
	ifp->if_ipackets = 0;
	ifp->if_opackets = 0;
	ifp->if_ibytes   = 0;
	ifp->if_obytes   = 0;
	ifp->if_dlt = DLT_NULL;
	IFQ_SET_READY(&ifp->if_snd);
	if_attach(ifp);
	if_alloc_sadl(ifp);
#if NBPFILTER > 0
	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));
#endif
}

static int
tun_clone_destroy(struct ifnet *ifp)
{
	struct tun_softc *tp = (void *)ifp;
	int s, zombie = 0;

	s = splnet();
	simple_lock(&tun_softc_lock);
	simple_lock(&tp->tun_lock);
	LIST_REMOVE(tp, tun_list);
	if (tp->tun_flags & TUN_OPEN) {
		/* Hang on to storage until last close */
		zombie = 1;
		tp->tun_flags &= ~TUN_INITED;
		LIST_INSERT_HEAD(&tunz_softc_list, tp, tun_list);
	}
	simple_unlock(&tun_softc_lock);

	IF_PURGE(&ifp->if_snd);
	ifp->if_flags &= ~IFF_RUNNING;

	if (tp->tun_flags & TUN_RWAIT) {
		tp->tun_flags &= ~TUN_RWAIT;
		wakeup((void *)tp);
	}
	selnotify(&tp->tun_rsel, 0);
#ifdef __QNXNTO__
	iofunc_notify_trigger(tp->tun_notify, 1, IOFUNC_NOTIFY_INPUT);
#endif

	simple_unlock(&tp->tun_lock);
	splx(s);

	if (tp->tun_flags & TUN_ASYNC && tp->tun_pgid)
		fownsignal(tp->tun_pgid, SIGIO, POLL_HUP, 0, NULL);

#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	if_detach(ifp);

#ifdef __QNXNTO__
	if (tp->tun_info.path_id != -1)
		resmgr_detach(tp->dpp, tp->tun_info.path_id, _RESMGR_DETACH_ALL);
#endif
	if (!zombie)
		free(tp, M_DEVBUF);

	return (0);
}

/*
 * tunnel open - must be superuser & the device must be
 * configured in
 */
#ifndef __QNXNTO__
static int
tunopen(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct ifnet	*ifp;
	struct tun_softc *tp;
	int	s, error;

	if ((error = kauth_authorize_generic(l->l_cred, KAUTH_GENERIC_ISSUSER,
	    &l->l_acflag)) != 0)
		return (error);

	s = splnet();
	tp = tun_find_unit(dev);

	if (tp == NULL) {
		(void)tun_clone_create(&tun_cloner, minor(dev));
		tp = tun_find_unit(dev);
		if (tp == NULL) {
			error = ENXIO;
			goto out_nolock;
		}
	}

	if (tp->tun_flags & TUN_OPEN) {
		error = EBUSY;
		goto out;
	}

	ifp = &tp->tun_if;
	tp->tun_flags |= TUN_OPEN;
	TUNDEBUG("%s: open\n", ifp->if_xname);
out:
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (error);
}
#else
int
tunopen(struct lwp *l, struct msg_open_info *mop, struct file **retval)
{
	int			error;
	struct proc		*p;
	struct file		*fp;
	struct ifnet		*ifp;
	struct tun_softc	*tp;
	int			dev;
	unsigned		ioflag;

	dev = mop->index;

	p = LWP_TO_PR(l);

	ioflag = p->p_ctxt.msg->connect.ioflag;

	/*
	 * We don't check KAUTH_GENERIC_ISSUSER like NetBSD, rather
	 * we assume they know what they're doing WRT chmod / chown.
	 */

	/* falloc() will use the descriptor for us. */
	if ((error = falloc(l, &fp)) != 0)
		return error;

	if ((error = nto_bindit(&p->p_ctxt, fp)) != 0)
		goto err1;

	if ((ioflag & (_IO_FLAG_RD | _IO_FLAG_WR)) == 0) {
		tp = NULL;
		goto filedone;
	}

	tp = tun_find_unit(dev);

	if (tp == NULL) {
		(void)tun_clone_create(&tun_cloner, minor(dev));
		tp = tun_find_unit(dev);
		if (tp == NULL) {
			error = ENXIO;
			goto err2;
		}
	}

	if (tp->tun_flags & TUN_OPEN) {
		error = EBUSY;
		goto err2;
	}

	ifp = &tp->tun_if;
	tp->tun_flags |= TUN_OPEN;
	TUNDEBUG("%s: open\n", ifp->if_xname);

filedone:
	/* Since _IO_FLAG_RD == FREAD && _IO_FLAG_WR == FWRITE */
	fp->f_flag = ioflag;

	fp->f_ops = &tun_fileops;
	fp->f_data = (caddr_t)tp;

	fp->f_type = DTYPE_MISC;
	FILE_SET_MATURE(fp);
	FILE_UNUSE(fp, p);
	*retval = fp;

	return EOK;
err2:
	nto_unbind(&p->p_ctxt);
err1:
	FILE_UNUSE(fp, p);
	ffree(fp);
	return error;
}
#endif

/*
 * tunclose - close the device - mark i/f down & delete
 * routing info
 */
#ifndef __QNXNTO__
int
tunclose(dev_t dev, int flag, int mode,
    struct lwp *l)
#else
static int
tunclose(struct file *fp, struct lwp * l)
#endif
{
	int	s;
	struct tun_softc *tp;
	struct ifnet	*ifp;
#ifdef __QNXNTO__
	dev_t	dev;
	struct tun_softc *tp0;

	dev = fp->f_path_info->index;

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}
#endif

	s = splnet();
	if ((tp = tun_find_zunit(minor(dev))) != NULL) {
		/* interface was "destroyed" before the close */
		free(tp, M_DEVBUF);
		goto out_nolock;
	}

	if ((tp = tun_find_unit(dev)) == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	    )
		goto out_nolock;

	ifp = &tp->tun_if;

	tp->tun_flags &= ~TUN_OPEN;

	/*
	 * junk all pending output
	 */
	IFQ_PURGE(&ifp->if_snd);

	if (ifp->if_flags & IFF_UP) {
		if_down(ifp);
		if (ifp->if_flags & IFF_RUNNING) {
			/* find internet addresses and delete routes */
			struct ifaddr *ifa;
			IFADDR_FOREACH(ifa, ifp) {
#if defined(INET) || defined(INET6)
				if (ifa->ifa_addr->sa_family == AF_INET ||
				    ifa->ifa_addr->sa_family == AF_INET6) {
#ifndef QNX_MFIB
					rtinit(ifa, (int)RTM_DELETE,
					       tp->tun_flags & TUN_DSTADDR
							? RTF_HOST
							: 0);
#else

					int fib=-1;
					while ((fib=if_get_next_fib(ifp, fib)) < FIBS_MAX) {
						rtinit(ifa, (int)RTM_DELETE,
						    tp->tun_flags & TUN_DSTADDR
						    ? RTF_HOST
						    : 0, fib);
					}
#endif
				}
#endif
			}
		}
	}
	tp->tun_pgid = 0;
	selnotify(&tp->tun_rsel, 0);

	TUNDEBUG ("%s: closed\n", ifp->if_xname);
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (0);
}

/*
 * Call at splnet().
 */
static void
tuninit(struct tun_softc *tp)
{
	struct ifnet	*ifp = &tp->tun_if;
	struct ifaddr	*ifa;

	TUNDEBUG("%s: tuninit\n", ifp->if_xname);

	simple_lock(&tp->tun_lock);
	ifp->if_flags |= IFF_UP | IFF_RUNNING;

	tp->tun_flags &= ~(TUN_IASET|TUN_DSTADDR);
	IFADDR_FOREACH(ifa, ifp) {
#ifdef INET
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin;

			sin = satosin(ifa->ifa_addr);
			if (sin && sin->sin_addr.s_addr)
				tp->tun_flags |= TUN_IASET;

			if (ifp->if_flags & IFF_POINTOPOINT) {
				sin = satosin(ifa->ifa_dstaddr);
				if (sin && sin->sin_addr.s_addr)
					tp->tun_flags |= TUN_DSTADDR;
			}
		}
#endif
#ifdef INET6
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin;

			sin = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (!IN6_IS_ADDR_UNSPECIFIED(&sin->sin6_addr))
				tp->tun_flags |= TUN_IASET;

			if (ifp->if_flags & IFF_POINTOPOINT) {
				sin = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
				if (sin &&
				    !IN6_IS_ADDR_UNSPECIFIED(&sin->sin6_addr))
					tp->tun_flags |= TUN_DSTADDR;
			} else
				tp->tun_flags &= ~TUN_DSTADDR;
		}
#endif /* INET6 */
	}

	simple_unlock(&tp->tun_lock);
	return;
}

/*
 * Process an ioctl request.
 */
static int
tun_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int		error = 0, s;
	struct tun_softc *tp = (struct tun_softc *)(ifp->if_softc);
	struct ifreq *ifr = (struct ifreq *) data;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		tuninit(tp);
		TUNDEBUG("%s: address set\n", ifp->if_xname);
		break;
	case SIOCSIFDSTADDR:
		tuninit(tp);
		TUNDEBUG("%s: destination address set\n", ifp->if_xname);
		break;
	case SIOCSIFBRDADDR:
		TUNDEBUG("%s: broadcast address set\n", ifp->if_xname);
		break;
	case SIOCSIFMTU:
		if (ifr->ifr_mtu > TUNMTU || ifr->ifr_mtu < 576) {
			error = EINVAL;
			break;
		}
		TUNDEBUG("%s: interface mtu set\n", ifp->if_xname);
		ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == NULL) {
	        	error = EAFNOSUPPORT;           /* XXX */
			break;
		}
		switch (ifreq_getaddr(cmd, ifr)->sa_family) {
#ifdef INET
		case AF_INET:
			break;
#endif
#ifdef INET6
		case AF_INET6:
			break;
#endif
		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;
	case SIOCSIFFLAGS:
		break;
	default:
		error = EINVAL;
	}

	splx(s);
	return (error);
}

/*
 * tun_output - queue packets from higher level ready to put out.
 */
static int
tun_output(struct ifnet *ifp, struct mbuf *m0, struct sockaddr *dst,
    struct rtentry *rt)
{
	struct tun_softc *tp = ifp->if_softc;
	int		s;
	int		error;
#if defined(INET) || defined(INET6)
	int		mlen;
	uint32_t	*af;
#endif
	ALTQ_DECL(struct altq_pktattr pktattr;)

	s = splnet();
	simple_lock(&tp->tun_lock);
	TUNDEBUG ("%s: tun_output\n", ifp->if_xname);

	if ((tp->tun_flags & TUN_READY) != TUN_READY) {
		TUNDEBUG ("%s: not ready 0%o\n", ifp->if_xname,
			  tp->tun_flags);
		m_freem (m0);
		error = EHOSTDOWN;
		goto out;
	}

	/*
	 * if the queueing discipline needs packet classification,
	 * do it before prepending link headers.
	 */
	IFQ_CLASSIFY(&ifp->if_snd, m0, dst->sa_family, &pktattr);

	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, dst->sa_family, m0);

	switch(dst->sa_family) {
#ifdef INET6
	case AF_INET6:
#endif
#ifdef INET
	case AF_INET:
#endif
#if defined(INET) || defined(INET6)
		if (tp->tun_flags & TUN_PREPADDR) {
			/* Simple link-layer header */
			M_PREPEND(m0, dst->sa_len, M_DONTWAIT);
			if (m0 == NULL) {
				IF_DROP(&ifp->if_snd);
				error = ENOBUFS;
				goto out;
			}
			bcopy(dst, mtod(m0, char *), dst->sa_len);
		}

		if (tp->tun_flags & TUN_IFHEAD) {
			/* Prepend the address family */
			M_PREPEND(m0, sizeof(*af), M_DONTWAIT);
			if (m0 == NULL) {
				IF_DROP(&ifp->if_snd);
				error = ENOBUFS;
				goto out;
			}
			af = mtod(m0,uint32_t *);
			*af = htonl(dst->sa_family);
		} else {
#ifdef INET     
			if (dst->sa_family != AF_INET)
#endif
			{
				m_freem(m0);
				error = EAFNOSUPPORT;
				goto out;
			}
		}
		/* FALLTHROUGH */
	case AF_UNSPEC:
#ifdef __QNXNTO__
		/* If bulk mode, prepend size */
		if (tp->tun_flags & TUN_BLK) {
			mlen = m0->m_pkthdr.len;
			M_PREPEND(m0, sizeof(mlen), M_DONTWAIT);
			if (m0 == NULL) {
				IF_DROP(&ifp->if_snd);
				error = ENOBUFS;
				goto out;
			}
			*mtod(m0, int *) = mlen;
		}
#endif
		IFQ_ENQUEUE(&ifp->if_snd, m0, &pktattr, error);
		if (error) {
			ifp->if_collisions++;
			error = EAFNOSUPPORT;
			goto out;
		}
		mlen = m0->m_pkthdr.len;
		ifp->if_opackets++;
		ifp->if_obytes += mlen;
		break;
#endif
	default:
		m_freem(m0);
		error = EAFNOSUPPORT;
		goto out;
	}

	if (tp->tun_flags & TUN_RWAIT) {
		tp->tun_flags &= ~TUN_RWAIT;
		wakeup((void *)tp);
	}
	if (tp->tun_flags & TUN_ASYNC && tp->tun_pgid)
#ifndef __QNXNTO__
		softint_schedule(tp->tun_isih);
#else
		/* Just call it */
		tun_i_softintr(tp);
#endif

	selnotify(&tp->tun_rsel, 0);
#ifdef __QNXNTO__
	iofunc_notify_trigger(tp->tun_notify, 1, IOFUNC_NOTIFY_INPUT);
#endif
out:
	simple_unlock(&tp->tun_lock);
	splx(s);
	return (0);
}

static void
tun_i_softintr(void *cookie)
{
	struct tun_softc *tp = cookie;

	if (tp->tun_flags & TUN_ASYNC && tp->tun_pgid)
#ifndef __QNXNTO__
		fownsignal(tp->tun_pgid, SIGIO, POLL_IN, POLLIN|POLLRDNORM,
		    NULL);
#else
		fownsignal(tp->tun_rcvid, SIGIO, POLL_IN, POLLIN|POLLRDNORM,
		    NULL);
#endif
}

#ifdef ALTQ
static void
tun_o_softintr(void *cookie)
{
	struct tun_softc *tp = cookie;

	if (tp->tun_flags & TUN_ASYNC && tp->tun_pgid)
#ifndef __QNXNTO__
		fownsignal(tp->tun_pgid, SIGIO, POLL_OUT, POLLOUT|POLLWRNORM,
		    NULL);
#else
		fownsignal(tp->tun_rcvid, SIGIO, POLL_OUT, POLLOUT|POLLWRNORM,
		    NULL);
#endif
}
#endif

/*
 * the cdevsw interface is now pretty minimal.
 */
#ifndef __QNXNTO__
int
tunioctl(dev_t dev, u_long cmd, void *data, int flag, struct lwp *l)
#else
static int
tunioctl(struct file *fp, u_long cmd, void *data, struct lwp *l)
#endif
{
	struct tun_softc *tp;
	int s, error = 0;
#ifdef __QNXNTO__
	int dev;
	struct proc *p;
	struct tun_softc *tp0;

	dev = fp->f_path_info->index;
	p = LWP_TO_PR(l);

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}
#endif

	s = splnet();
	tp = tun_find_unit(dev);

	/* interface was "destroyed" already */
	if (tp == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	    ) {
		error = ENXIO;
		goto out_nolock;
	}

	switch (cmd) {
	case TUNSDEBUG:
		tundebug = *(int *)data;
		break;

	case TUNGDEBUG:
		*(int *)data = tundebug;
		break;

	case TUNSIFMODE:
		switch (*(int *)data & (IFF_POINTOPOINT|IFF_BROADCAST)) {
		case IFF_POINTOPOINT:
		case IFF_BROADCAST:
			if (tp->tun_if.if_flags & IFF_UP) {
				error = EBUSY;
				goto out;
			}
			tp->tun_if.if_flags &=
				~(IFF_BROADCAST|IFF_POINTOPOINT|IFF_MULTICAST);
			tp->tun_if.if_flags |= *(int *)data;
			break;
		default:
			error = EINVAL;
			goto out;
		}
		break;

	case TUNSLMODE:
		if (*(int *)data) {
			tp->tun_flags |= TUN_PREPADDR;
			tp->tun_flags &= ~TUN_IFHEAD;
		} else
			tp->tun_flags &= ~TUN_PREPADDR;
		break;

	case TUNSIFHEAD:
		if (*(int *)data) {
			tp->tun_flags |= TUN_IFHEAD;
			tp->tun_flags &= ~TUN_PREPADDR;
		} else
			tp->tun_flags &= ~TUN_IFHEAD;
		break;

	case TUNGIFHEAD:
		*(int *)data = (tp->tun_flags & TUN_IFHEAD);
		break;

	case FIONBIO:
		if (*(int *)data)
			tp->tun_flags |= TUN_NBIO;
		else
			tp->tun_flags &= ~TUN_NBIO;
		break;

	case FIOASYNC:
		if (*(int *)data)
			tp->tun_flags |= TUN_ASYNC;
		else
			tp->tun_flags &= ~TUN_ASYNC;
		break;

	case FIONREAD:
		if (tp->tun_if.if_snd.ifq_head)
			*(int *)data = tp->tun_if.if_snd.ifq_head->m_pkthdr.len;
		else
			*(int *)data = 0;
		break;
#ifdef __QNXNTO__
	case TUNSBLK:
		if (*(int *)data)
			tp->tun_flags |= TUN_BLK;
		else
			tp->tun_flags &= ~TUN_BLK;
		break;
#endif
	case TIOCSPGRP:
	case FIOSETOWN:
#ifndef __QNXNTO__
		error = fsetown(&tp->tun_pgid, cmd, data);
#else
		error = fsetown(p, &tp->tun_pgid, &tp->tun_rcvid, cmd, data);
#endif
		break;

	case TIOCGPGRP:
	case FIOGETOWN:
#ifndef __QNXNTO__
		error = fgetown(tp->tun_pgid, cmd, data);
#else
		error = fgetown(p, tp->tun_pgid, cmd, data);
#endif
		break;

	default:
		error = ENOTTY;
	}

out:
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (error);
}

#ifdef __QNXNTO__
static inline void
tun_siov(struct proc *p, struct uio *uio, void *v, size_t sz)
{
	SETIOV(&p->p_read.iovp[*p->p_read.niovp], v, sz);
	(*p->p_read.niovp)++;
	uio->uio_resid -= sz;
	uio->uio_offset += sz;
	p->p_offset += sz;
}
#endif
/*
 * The cdevsw read interface - reads a packet at a time, or at
 * least as much of a packet as can be read.
 */
#ifndef __QNXNTO__
int
tunread(dev_t dev, struct uio *uio, int ioflag)
#else
static int
tunread(struct file *fp, off_t *offp, struct uio *uio, kauth_cred_t cred, int flags)
#endif
{
	struct tun_softc *tp;
	struct ifnet	*ifp;
	struct mbuf	*m, *m0;
	int		error = 0, len, s, index;
#ifdef __QNXNTO__
	int		pktcnt;
	int		dev;
	struct tun_softc *tp0;
	struct proc	*p;
	int		delsave;

	p = curproc;

	dev = fp->f_path_info->index;

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}
#endif

	s = splnet();
	tp = tun_find_unit(dev);

	/* interface was "destroyed" already */
	if (tp == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	    ) {
		error = ENXIO;
		goto out_nolock;
	}

	index = tp->tun_if.if_index;
	ifp = &tp->tun_if;

	TUNDEBUG ("%s: read\n", ifp->if_xname);
	if ((tp->tun_flags & TUN_READY) != TUN_READY) {
		TUNDEBUG ("%s: not ready 0%o\n", ifp->if_xname, tp->tun_flags);
		error = EHOSTDOWN;
		goto out;
	}

	tp->tun_flags &= ~TUN_RWAIT;

#ifdef __QNXNTO__
	pktcnt = 0;
blkagain:
	if (pktcnt > 0 && (uio->uio_resid < ifp->if_mtu + sizeof(int) ||
	    IFQ_IS_EMPTY(&ifp->if_snd))) {
		goto out_nolock;
	}
#endif
	do {
		IFQ_DEQUEUE(&ifp->if_snd, m0);
		if (m0 == 0) {
			if (tp->tun_flags & TUN_NBIO) {
				error = EWOULDBLOCK;
				goto out;
			}
			tp->tun_flags |= TUN_RWAIT;
#ifndef __QNXNTO__
			if ((error = ltsleep((void *)tp, PZERO|PCATCH|PNORELOCK,
					"tunread", 0, &tp->tun_lock)) != 0) {
#else
			if ((error = ltsleep((void *)tp, PZERO|PCATCH|PNORELOCK,
					"Utunread", 0, &tp->tun_lock)) != 0) {
#endif
				goto out_nolock;
			} else {
				/*
				 * Maybe the interface was destroyed while
				 * we were sleeping, so let's ensure that
				 * we're looking at the same (valid) tun
				 * interface before looping.
				 */
				tp = tun_find_unit(dev);
				if (tp == NULL) {
					error = ENXIO;
					goto out_nolock;
				}
				if (tp->tun_if.if_index != index) {
					error = ENXIO;
					goto out;
				}
			}
		}
	} while (m0 == 0);

	simple_unlock(&tp->tun_lock);
	splx(s);

#ifdef __QNXNTO__
	pktcnt++;
#endif
	/* Copy the mbuf chain */
	while (m0 && uio->uio_resid > 0 && error == 0) {
		len = min(uio->uio_resid, m0->m_len);
#ifndef __QNXNTO__
		if (len != 0)
			error = uiomove(mtod(m0, void *), len, uio);
		MFREE(m0, m);
#else
		delsave = 0;
		if (len != 0) {
			if (*p->p_read.niovp < p->p_read.niov_max) {
				tun_siov(p, uio, mtod(m0, void *), len);
				delsave = 1;
			}
			else
				error = uiomove(mtod(m0, void *), len, uio);
		}
		if (delsave == 0) {
			MFREE(m0, m);
		}
		else {
			m = m0->m_next;
			m0->m_next = *p->p_read.m_to_free;
			*p->p_read.m_to_free = m0;

		}
#endif
		m0 = m;
	}

	if (m0) {
		TUNDEBUG("Dropping mbuf\n");
		m_freem(m0);
	}
	if (error)
		ifp->if_ierrors++;
#ifdef __QNXNTO__
	else if (tp->tun_flags & TUN_BLK)
		goto blkagain;
#endif
	return (error);

out:
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (error);
}

/*
 * the cdevsw write interface - an atomic write is a packet - or else!
 */
#ifndef __QNXNTO__
int
tunwrite(dev_t dev, struct uio *uio, int ioflag)
#else
static int
tunwrite(struct file *fp, off_t *offp, struct uio *uio,
    kauth_cred_t cred, int flags)
#endif
{
	struct tun_softc *tp;
	struct ifnet	*ifp;
	struct mbuf	*top, **mp, *m;
	struct ifqueue	*ifq;
	struct sockaddr	dst;
	int		isr, error = 0, s, tlen, mlen;
	uint32_t	family;
#ifdef __QNXNTO__
	int		dev, oldresid, pktlen;
	struct tun_softc *tp0;
	struct proc	*p;

	p = curproc;

	dev = fp->f_path_info->index;

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}
#endif

	s = splnet();
	tp = tun_find_unit(dev);

	/* interface was "destroyed" already */
	if (tp == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	) {
		error = ENXIO;
		goto out_nolock;
	}

#ifdef __QNXNTO__
	oldresid = uio->uio_resid;
	pktlen = 0;
	uio->uio_vmspace->vm_flags |= VM_USERMBUF;
blkagain:
#endif
	/* Unlock until we've got the data */
	simple_unlock(&tp->tun_lock);
	splx(s);

	ifp = &tp->tun_if;

	TUNDEBUG("%s: tunwrite\n", ifp->if_xname);

#ifdef __QNXNTO__
	if (tp->tun_flags & TUN_BLK) {
		oldresid -= pktlen;
		uio->uio_resid = oldresid;
		if (uio->uio_resid <= 0)
			goto out0;
		/* Copyin packet len */
		error = uiomove(&pktlen, sizeof(int), uio);

		if (error)
			goto out0;
		oldresid = uio->uio_resid;
		uio->uio_resid = pktlen;
	}
#endif
	if (tp->tun_flags & TUN_PREPADDR) {
		if (uio->uio_resid < sizeof(dst)) {
			error = EIO;
			goto out0;
		}
		error = uiomove((void *)&dst, sizeof(dst), uio);
		if (dst.sa_len > sizeof(dst)) {
			/* Duh.. */
			char discard;
			int n = dst.sa_len - sizeof(dst);
			while (n--)
				if ((error = uiomove(&discard, 1, uio)) != 0) {
					goto out0;
				}
		}
	} else if (tp->tun_flags & TUN_IFHEAD) {
		if (uio->uio_resid < sizeof(family)){
			error = EIO;
			goto out0;
		}
		error = uiomove((void *)&family, sizeof(family), uio);
		dst.sa_family = ntohl(family);
	} else {
#ifdef INET
		dst.sa_family = AF_INET;
#endif
	}

	if (uio->uio_resid > ifp->if_mtu) {
		TUNDEBUG("%s: len=%lu!\n", ifp->if_xname,
		    (unsigned long)uio->uio_resid);
		error = EIO;
		goto out0;
	}

	switch (dst.sa_family) {
#ifdef INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		ifq = &ip6intrq;
		isr = NETISR_IPV6;
		break;
#endif
	default:
		error = EAFNOSUPPORT;
		goto out0;
	}

	tlen = uio->uio_resid;

	/* get a header mbuf */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL) {
		error = ENOBUFS;
		goto out0;
	}
	mlen = MHLEN;

	top = NULL;
	mp = &top;

#ifdef __QNXNTO__
	/*
	 * Ensure that at least the header mbuf is assigned.  If there is data
	 * to be written, the length will be updated in the loop below.
	 */
	top = m;
	m->m_len = 0;

	if (p->p_mbuf != NULL) {
		top = p->p_mbuf;
		p->p_mbuf = NULL;
		if (top->m_pkthdr.len > uio->uio_resid) {
			p->p_mbuf = m_split(top, uio->uio_resid, M_DONTWAIT);
			if (p->p_mbuf == NULL) {
				error = ENOBUFS;
				/* top (assigned to p->p_mbuf above) freed below */
			}
			else {
				p->p_offset += uio->uio_resid;
				uio->uio_offset += uio->uio_resid;
				uio->uio_resid = 0;
			}
			m_free(m);
		}
		else {
			p->p_offset += top->m_pkthdr.len;
			uio->uio_offset += top->m_pkthdr.len;
			uio->uio_resid -= top->m_pkthdr.len;
			if (uio->uio_resid == 0)
				m_free(m);
			else {
				m->m_flags &= ~M_PKTHDR;
				for (; *mp != NULL; mp = &(*mp)->m_next)
					continue;
			}
		}
	}
#endif

	while (error == 0 && uio->uio_resid > 0) {
#ifdef __QNXNTO__
		if (uio->uio_resid > mlen) {
			MCLGET(m, M_DONTWAIT);
			if (m->m_flags & M_EXT)
				mlen = m->m_ext.ext_size;
		}
#endif
		m->m_len = min(mlen, uio->uio_resid);
		error = uiomove(mtod(m, void *), m->m_len, uio);
		*mp = m;
		mp = &m->m_next;
		if (error == 0 && uio->uio_resid > 0) {
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m == NULL) {
				error = ENOBUFS;
				break;
			}
			mlen = MLEN;
		}
	}
	if (error) {
		if (top != NULL)
			m_freem (top);
		ifp->if_ierrors++;
		goto out0;
	}

	top->m_pkthdr.len = tlen;
	top->m_pkthdr.rcvif = ifp;

	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, dst.sa_family, top);

	s = splnet();
	simple_lock(&tp->tun_lock);
	if ((tp->tun_flags & TUN_INITED) == 0) {
		/* Interface was destroyed */
		error = ENXIO;
		goto out;
	}
#ifndef __QNXNTO__
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		ifp->if_collisions++;
		m_freem(top);
		error = ENOBUFS;
		goto out;
	}

	IF_ENQUEUE(ifq, top);
	ifp->if_ipackets++;
	ifp->if_ibytes += tlen;
#else
	{
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;

	sctlp = &stk_ctl;
	wtp = WTP;

	NW_SIGLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		ifp->if_collisions++;
		NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
		m_freem(top);
		error = ENOBUFS;
		goto out;
	}

	IF_ENQUEUE(ifq, top);
	ifp->if_ipackets++;
	ifp->if_ibytes += tlen;

	if (ifq->ifq_len == 1) {
		if (sctlp->pkt_rx_q == NULL) {
			sctlp->pkt_rx_q = ifq;
		}
		else {
			/* make this new one the tail */
			ifq->ifq_next = sctlp->pkt_rx_q;
			ifq->ifq_prev = sctlp->pkt_rx_q->ifq_prev;
			*sctlp->pkt_rx_q->ifq_prev = ifq;
			sctlp->pkt_rx_q->ifq_prev  = &ifq->ifq_next;
		}
	}
	NW_SIGUNLOCK_P(&sctlp->pkt_ex, iopkt_selfp, wtp);
	}
	if (tp->tun_flags & TUN_BLK)
		goto blkagain;
	uio->uio_vmspace->vm_flags &= ~VM_USERMBUF;
#endif
	schednetisr(isr);
out:
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
out0:
	return (error);
}

#ifdef ALTQ
/*
 * Start packet transmission on the interface.
 * when the interface queue is rate-limited by ALTQ or TBR,
 * if_start is needed to drain packets from the queue in order
 * to notify readers when outgoing packets become ready.
 *
 * Should be called at splnet.
 */
static void
tunstart(struct ifnet *ifp)
{
	struct tun_softc *tp = ifp->if_softc;

	if (!ALTQ_IS_ENABLED(&ifp->if_snd) && !TBR_IS_ENABLED(&ifp->if_snd))
		return;

	simple_lock(&tp->tun_lock);
	if (!IF_IS_EMPTY(&ifp->if_snd)) {
		if (tp->tun_flags & TUN_RWAIT) {
			tp->tun_flags &= ~TUN_RWAIT;
			wakeup((void *)tp);
		}
		if (tp->tun_flags & TUN_ASYNC && tp->tun_pgid)
#ifndef __QNXNTO__
			softint_schedule(tp->tun_osih);
#else
			/* Just call it */
			tun_o_softintr(tp);
#endif

		selnotify(&tp->tun_rsel, 0);
	}
	simple_unlock(&tp->tun_lock);
}
#endif /* ALTQ */
/*
 * tunpoll - the poll interface, this is only useful on reads
 * really. The write detect always returns true, write never blocks
 * anyway, it either accepts the packet or drops it.
 */
#ifndef __QNXNTO__
int
tunpoll(dev_t dev, int events, struct lwp *l)
{
	struct tun_softc *tp;
	struct ifnet	*ifp;
	int		s, revents = 0;

	s = splnet();
	tp = tun_find_unit(dev);

	/* interface was "destroyed" already */
	if (tp == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	    )
		goto out_nolock;

	ifp = &tp->tun_if;

	TUNDEBUG("%s: tunpoll\n", ifp->if_xname);

	if (events & (POLLIN | POLLRDNORM)) {
		if (!IFQ_IS_EMPTY(&ifp->if_snd)) {
			TUNDEBUG("%s: tunpoll q=%d\n", ifp->if_xname,
			    ifp->if_snd.ifq_len);
			revents |= events & (POLLIN | POLLRDNORM);
		} else {
			TUNDEBUG("%s: tunpoll waiting\n", ifp->if_xname);
			selrecord(l, &tp->tun_rsel);
		}
	}

	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (revents);
}
#else
static int
tunpoll(struct file *fp, int events, struct lwp *l)
{
	struct tun_softc	*tp, *tp0;
	struct ifnet		*ifp;
	unsigned		trig;
	int			s, dev;
	io_notify_t		*msg;
	resmgr_context_t	*ctp;
	struct proc		*p;

	dev = fp->f_path_info->index;

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}

	p = LWP_TO_PR(l);
	ctp = &p->p_ctxt;
	msg = &ctp->msg->notify;

	trig = 0;

	s = splnet();
	tp = tun_find_unit(dev);

	/* interface was "destroyed" already or driver
	 * instance did not match descriptor data */
	if (tp == NULL || tp != tp0) {
		return 0;
	}

	/* As in NetBSD, assume it safe to write */
	trig |= _NOTIFY_COND_OUTPUT;

	ifp = &tp->tun_if;

	TUNDEBUG("%s: tunpoll\n", ifp->if_xname);

	if (!IFQ_IS_EMPTY(&ifp->if_snd)) {
		TUNDEBUG("%s: tunpoll q=%d\n", ifp->if_xname,
		    ifp->if_snd.ifq_len);
		trig |= _NOTIFY_COND_INPUT;
	}


	simple_unlock(&tp->tun_lock);
	return iofunc_notify(ctp, msg, &tp->tun_notify[0], trig, NULL, NULL);
}

static int
tunclose1(struct file *fp, struct lwp *l)
{
	struct tun_softc	*tp;
	resmgr_context_t        *ctp;
	struct proc             *p;
	iofunc_notify_t         *nop;
	int                     nop_lim;

	p = LWP_TO_PR(l);
	ctp = &p->p_ctxt;
	tp = (struct tun_softc *)fp->f_data;

	if (tp == NULL)
		return 0;

	nop = tp->tun_notify;
	nop_lim = sizeof(tp->tun_notify) / sizeof(tp->tun_notify[0]);

	(*notify_trigger_strictp)(ctp, nop, 1, IOFUNC_NOTIFY_INPUT);
	(*notify_trigger_strictp)(ctp, nop, 1, IOFUNC_NOTIFY_OUTPUT);

	(*notify_remove_strictp)(ctp, nop, nop_lim);
	return 0;
}

#endif

static void
filt_tunrdetach(struct knote *kn)
{
	struct tun_softc *tp = kn->kn_hook;
	int s;

	s = splnet();
	SLIST_REMOVE(&tp->tun_rsel.sel_klist, kn, knote, kn_selnext);
	splx(s);
}

static int
filt_tunread(struct knote *kn, long hint)
{
	struct tun_softc *tp = kn->kn_hook;
	struct ifnet *ifp = &tp->tun_if;
	struct mbuf *m;
	int s;

	s = splnet();
	IF_POLL(&ifp->if_snd, m);
	if (m == NULL) {
		splx(s);
		return (0);
	}

	for (kn->kn_data = 0; m != NULL; m = m->m_next)
		kn->kn_data += m->m_len;

	splx(s);
	return (1);
}

static const struct filterops tunread_filtops =
	{ 1, NULL, filt_tunrdetach, filt_tunread };

static const struct filterops tun_seltrue_filtops =
	{ 1, NULL, filt_tunrdetach, filt_seltrue };

#ifndef __QNXNTO__
int
tunkqfilter(dev_t dev, struct knote *kn)
#else
static int
tunkqfilter(struct file *fp, struct knote *kn)
#endif
{
	struct tun_softc *tp;
	struct klist *klist;
	int rv = 0, s;
#ifdef __QNXNTO__
	int dev;
	struct tun_softc *tp0;

	dev = fp->f_path_info->index;

	if ((tp0 = fp->f_data) == NULL) {
		/* Something weird's going on */
		return ENXIO;
	}
#endif

	s = splnet();
	tp = tun_find_unit(dev);
	if (tp == NULL
#ifdef __QNXNTO__
	    || tp != tp0
#endif
	    )
		goto out_nolock;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &tp->tun_rsel.sel_klist;
		kn->kn_fop = &tunread_filtops;
		break;

	case EVFILT_WRITE:
		klist = &tp->tun_rsel.sel_klist;
		kn->kn_fop = &tun_seltrue_filtops;
		break;

	default:
		rv = EINVAL;
		goto out;
	}

	kn->kn_hook = tp;

	SLIST_INSERT_HEAD(klist, kn, kn_selnext);

out:
	simple_unlock(&tp->tun_lock);
out_nolock:
	splx(s);
	return (rv);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_tun.c $ $Rev: 853157 $")
#endif
