/*
 * $QNXLicenseC:
 * Copyright 2007, 2009, QNX Software Systems. All Rights Reserved.
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



 

#include "opt_msg.h"
#include "opt_ionet_compat.h"
#include "nw_dl.h"
#include "nw_msg.h"
#include "nw_datastruct.h"
#include "opt_pru_sense.h"
#include "opt_ipsec.h"
#include "bpfilter.h"
#include "pf.h"
#include "srt.h"
#include "tun.h"
#include "tap.h"

#include <sys/dcmd_ip.h>
#include <sys/iomsg.h>
#include <sys/iomgr.h>
#include <sys/iofunc.h>
#include <sys/resmgr.h>
#include <sys/mbuf.h>
#include <sys/netmgr.h>
#include <sys/proc.h>
#include <sys/sockmsg.h>
#include <sys/syscallargs.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/dispatch.h>
#include <sys/dcmd_all.h>
#include <sys/dcmd_ip.h>
#include <sys/dcmd_blk.h>
#include <sys/dcmd_misc.h>
#include <sys/ucred.h>
#include <sys/systm.h>
#include <sys/file_bsd.h>
#include <sys/uio_bsd.h>
#include <sys/selinfo.h>
#include <sys/eventvar.h>
#include <sys/socketvar.h>
#include <sys/kauth.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in_pcb.h>
#ifdef INET6
#include <netinet6/in6_pcb.h>
#endif
#include <sys/ioctl.h>
#include <sys/signalvar.h>
#include <sys/filedesc.h>
#include <nlist.h>
#include <sys/nlist.h>
#include <errno.h>
#include <device_qnx.h>
#include "notify.h"
#include "delta.h"
#include "receive.h"
#ifdef IONET_COMPAT
#include "ionet_compat.h"
#endif
#ifdef FAST_IPSEC
#include "opencrypto/cryptodev.h"
#endif
#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#if NPF > 0
#include <net/pfvar.h>
#endif
#if NSRT > 0
#include <net/if_srt.h>
#endif
#if NTUN > 0
#include <net/if_tun.h>
#endif
#if NTAP > 0
#include <net/if_tap.h>
#endif
#include <ioctl_long.h>
#include <alloca.h>


#define PROC_FROM_CTP(ctp)	\
	(struct proc *)((char *)(ctp) - offsetof(struct proc, p_ctxt))

#define PROC_SETUP(p, ctp, fp, ocb) do {	\
	(fp) = (ocb);				\
	(p)->p_cred = (fp)->f_cred;		\
	kauth_cred_hold((fp)->f_cred);		\
	(p)->p_lwp.l_cred = (fp)->f_cred;	\
	kauth_cred_hold((fp)->f_cred);		\
	PR_TO_LWP((p))->l_fp = (fp);		\
} while (/* CONSTCOND */ 0)

#define PROC_RESTORE(p, fp, ocb) do {		\
	(fp) = (ocb);				\
	(p)->p_cred = (fp)->f_cred;		\
	(p)->p_lwp.l_cred = (fp)->f_cred;	\
	PR_TO_LWP((p))->l_fp = (fp);		\
} while (/* CONSTCOND */ 0)

#define PROC_INIT(p, ctp, fp, ocb) do {		\
	(p) = PROC_FROM_CTP((ctp));		\
	PROC_SETUP((p), (ctp), (fp), (ocb));	\
} while (/* CONSTCOND */ 0)

#define PROC_FINI(p) do {			\
	kauth_cred_free((p)->p_cred);		\
	kauth_cred_free((p)->p_lwp.l_cred);	\
} while (/* CONSTCOND */ 0)



int af_stat(resmgr_context_t *ctp, io_stat_t *msg, RESMGR_OCB_T *ocb);

static resmgr_io_funcs_t keep_stat_happy=
{
	4,
	NULL,               /* read */
	NULL,               /* write */
	NULL,               /* lastclose */
	af_stat     /* stat */
};



int tcpip_open(resmgr_context_t *ctp, io_open_t *msg, RESMGR_HANDLE_T *handle, void *extra);

int tcpip_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb);
int tcpip_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb);
int tcpip_stat(resmgr_context_t *ctp, io_stat_t *msg, RESMGR_OCB_T *ocb);
int tcpip_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *ocb);
int tcpip_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb);
int tcpip_unblock(resmgr_context_t *ctp, io_pulse_t *msg, RESMGR_OCB_T *ocb);
int tcpip_lseek(resmgr_context_t *ctp, io_lseek_t *msg, RESMGR_OCB_T *ocb);
int tcpip_openfd(resmgr_context_t *ctp, io_openfd_t *msg, RESMGR_OCB_T *ocb);
int tcpip_fdinfo(resmgr_context_t *ctp, io_fdinfo_t *msg, RESMGR_OCB_T *ocb);
int tcpip_msg (resmgr_context_t *ctp, io_msg_t *msg, RESMGR_OCB_T *ocb);
int tcpip_dup(resmgr_context_t *ctp, io_dup_t *msg, RESMGR_OCB_T *ocb);
int tcpip_close (resmgr_context_t *ctp, io_close_t *msg, RESMGR_OCB_T *ocb);
int tcpip_chmod (resmgr_context_t *ctp, io_chmod_t *msg, RESMGR_OCB_T *ocb);
int tcpip_chown (resmgr_context_t *ctp, io_chown_t *msg, RESMGR_OCB_T *ocb);

static int tcpip_fop(resmgr_context_t *ctp, resmgr_iomsgs_t *msg, RESMGR_OCB_T *ocb);



static const unsigned char pad_data[UCHAR_MAX]; /* Max size of struct sockaddr */


resmgr_connect_funcs_t tcpip_connect_funcs = {
	1,
	tcpip_open,
};

resmgr_io_funcs_t nw_io_funcs = {
	22,
	tcpip_read,
	tcpip_write,
	NULL,                 /* close_ocb (lastclose) */
	tcpip_stat,
	tcpip_notify,
	tcpip_devctl,
	tcpip_unblock,
	NULL,                 /* pathconf */
	tcpip_lseek,
	tcpip_chmod,
	tcpip_chown,
	NULL,                 /* utime */
	tcpip_openfd,
	tcpip_fdinfo,
	NULL,                 /* lock */
	NULL,                 /* space */
	NULL,                 /* shutdown */
	NULL,                 /* mmap */
	tcpip_msg,
	NULL,                 /* umount */
	tcpip_dup,
	tcpip_close
};

#ifdef OCB_LOCAL_CACHE
static void
fp_local_cache(struct _msg_info *info, struct file *fp)
{
	int scoid;

	scoid = info->scoid & ~_NTO_SIDE_CHANNEL;
	/* Unsigned comparisons to catch negative values */
	if ((unsigned)scoid < ocb_cache_scoid_max &&
	    (unsigned)info->coid < OCB_CACHE_COID_MAX) {
		if (ocb_cache[scoid].nd  != info->nd ||
		    ocb_cache[scoid].pid != info->pid) {
			memset(ocb_cache[scoid].ocbs, 0x00, sizeof(ocb_cache[scoid].ocbs));
		}
		ocb_cache[scoid].nd  = info->nd;
		ocb_cache[scoid].pid = info->pid;
		ocb_cache[scoid].ocbs[info->coid] = fp;
	}
}
#endif

/*
 * Any open on /dev/socket/X will use this;
 * mainly for proper st_dev, st_inode reporting.
 */
int
af_stat(resmgr_context_t *ctp, io_stat_t *msg, RESMGR_OCB_T *ocb)
{
	struct msg_open_info *mop = (struct msg_open_info *)ocb;

	iofunc_time_update(&mop->attr);
	iofunc_stat(ctp, &mop->attr, &msg->o);
	/* Only space for one iov in ctp */
	return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
}

int 
tcpip_open(resmgr_context_t *ctp, io_open_t *msg, RESMGR_HANDLE_T *handle, void *extra)
{
	int				ret;
	struct file			*fp;
	struct msg_open_info		*mop;
	struct proc			*p;
	struct nw_stk_ctl		*sctlp;
	io_socket_extra_t		*extrap;
	struct sys___socket30_args	uap;

	sctlp = &stk_ctl;
	p = PROC_FROM_CTP(ctp);
	mop = (struct msg_open_info *)handle;

	if (p->p_mbuf != NULL) {
		 /*
		  * Open that's not the first part of a combine.  Someone
		  * must be trying to purposefully break things.
		  */
		return EINVAL;
	}

	p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
	p->p_mbuf->m_next = NULL;
	sctlp->recv_start++;
	sctlp->recv_avail--;

	p->p_cred = kauth_cred_alloc();

	p->p_lwp.l_cred = p->p_cred;
	kauth_cred_hold(p->p_cred);

	PR_TO_LWP(p)->l_fp = NULL;

	if (mop->path_id != ctp->id) {
		ret = EBADF;
		goto err;
	}

	if (mop->path_id == -1) {
		ret = ENOENT;
		goto err;
	}

	fp = NULL;
	ret = ENOSYS;

	switch (mop->path_type) {
	case PATH_TYPE_SOCKET:
		extrap = extra;

		if (msg->connect.file_type == _FTYPE_ANY) {
			/* open("/dev/socket/X",  ); */
			if (resmgr_open_bind(ctp, mop, &keep_stat_happy) == -1)
				ret = errno;
			else {
				mop->attr.flags |=
				    IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
				ret = EOK;
			}
		} 
		else if (msg->connect.file_type != _FTYPE_SOCKET ||
		    msg->connect.extra_type != _IO_CONNECT_EXTRA_SOCKET ||
		    msg->connect.extra_len != sizeof *extrap || !extrap) {
			ret = ENOSYS;
		}
		else {
			SCARG(&uap, domain) = mop->domain;
			SCARG(&uap, type) = extrap->type;
			SCARG(&uap, protocol) = extrap->protocol;
			ret = sys___socket30(PR_TO_LWP(p), &uap, (uintptr_t *)&fp);
		}
		break;

	case PATH_TYPE_CRYPTO:
#ifdef FAST_IPSEC
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = cryptodev_open(PR_TO_LWP(p), &fp);
#endif
		break;

	case PATH_TYPE_BPF:
#if NBPFILTER > 0
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = bpf_open(PR_TO_LWP(p), &fp);
#endif
		break;

	case PATH_TYPE_PF:
#if 0
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = pf_open(PR_TO_LWP(p), &fp);
#endif
		break;

	case PATH_TYPE_SRT:
#if NSRT > 0
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = srt_open(PR_TO_LWP(p), mop, &fp);
#endif
		break;

	case PATH_TYPE_TUN:
#if NTUN > 0
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = tunopen(PR_TO_LWP(p), mop, &fp);
#endif
		break;

	case PATH_TYPE_TAP:
#if NTAP > 0
		if ((ret = msg_open_chk_access(ctp, msg, &mop->attr)) == EOK)
			ret = tapopen(PR_TO_LWP(p), mop, &fp);
#endif
		break;

	case PATH_TYPE_LSM:
		if (mop->open == NULL) {
			ret = ENOSYS;
			break;
		}

		ret = (*mop->open)(ctp, msg, mop, &fp);
		break;

	default:
		break;
	}	

	_RESMGR_STATUS(ctp, 0); /* Ignored by resmgr layer if ret != EOK */
	if (ret == EOK && fp != NULL) {
#ifdef OCB_LOCAL_CACHE
		fp_local_cache(&ctp->info, fp);
#endif
		fp->f_path_info = mop;
		fp->f_timeflags |= IOFUNC_ATTR_ATIME | IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
	}

err:
	kauth_cred_free(p->p_lwp.l_cred);
	kauth_cred_free(p->p_cred);
	return ret;
}


int
msg_open_chk_access(resmgr_context_t *ctp, io_open_t *msg,
    iofunc_attr_t *attr)
{
	struct _client_info	info;
	mode_t			check;
	int			ret;

	check = 0;

	ret = ConnectClientInfo_r(ctp->info.scoid, &info, NGROUPS_MAX);
	if (ret != EOK)
		return ret;

	if (msg->connect.ioflag & _IO_FLAG_RD)
		check |= S_IREAD;
	if (msg->connect.ioflag & _IO_FLAG_WR)
		check |= S_IWRITE;

	/*
	 * Only check permissions if reading or writing. An
	 * open without read or write still needs to pass so
	 * that stat() calls work.
	 */
	if (check)
		ret = iofunc_check_access(ctp, attr, check, &info);

	return ret;
}

int
tcpip_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
	int			ret, nbytes, retval;
	int			addrlen_saved, controlen_saved;
	struct file		*fp;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	struct mbuf		*m_to_free;
	iov_t			*rep_iov, *work_iov;
	unsigned		work_num, xtype;
	struct lwp		*l;
	
	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;

	l = PR_TO_LWP(p);

	work_iov = alloca(sctlp->reply_max * sizeof(iov_t));

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}

	p->p_read.m_to_free = &m_to_free;
	p->p_read.niovp = &work_num;
	work_num = 0;

	nbytes = 0;
	m_to_free = NULL;
	rep_iov = NULL;

	xtype = msg->i.xtype & _IO_XTYPE_MASK;
	switch (xtype) {
	case _IO_XTYPE_NONE:
	{
		struct sys_read_args uap;

		SCARG(&uap, fd)    = -1;
		SCARG(&uap, buf)   = NULL;
		SCARG(&uap, nbyte) = msg->i.nbytes;

		p->p_offset = 0;
		p->p_read.flush_offset = p->p_offset;

		p->p_read.iovp = work_iov;
		p->p_read.niov_max = sctlp->reply_max;
		ret = sys_read(l, &uap, &nbytes);

		rep_iov = work_iov;

		break;
	}

	case _IO_XTYPE_TCPIP:
	{
		struct sys_recvfrom_args	uap;
		io_sock_recvfrom_t		*recvp;
		socklen_t			*fromlenp;

		recvp = (io_sock_recvfrom_t *)msg;

		SCARG(&uap, s)     = -1;
		SCARG(&uap, flags) = recvp->i.flags;
		addrlen_saved = recvp->i.addrlen;
		SCARG(&uap, buf) = 0;
		SCARG(&uap, len) = recvp->i.read.nbytes;

		/*
		 * recvp->[io].addrlen should have been socklen_t (uint32_t)
		 * instead of a uint16_t.  Here we make space for SCARG(&uap,
		 * fromlenaddr) = fromlenp at the top of the message and shift
		 * the recvp->o down by the same amount.  Doing this puts this
		 * from address in the message context which makes copyin work
		 * without VM_NOCTXT flag.
		 *
		 * However, doing this makes the calculation of the offset in
		 * copy[in|out] for Msg[Read|Write] off if something doesn't
		 * fit in the context.
		 *
		 * However, we're copying out a sockaddr whose max size is
		 * UCHAR_MAX so this should never happen.  To be safe though we
		 * truncate passed in fromlen up front here so the MsgWrite()
		 * case in copyout() can never be hit.  It may be further
		 * truncated in copyout_sockname() to the size of the addr.
		 */

		fromlenp = (socklen_t *)recvp;
		SCARG(&uap, fromlenaddr) = fromlenp;
		recvp = (io_sock_recvfrom_t *)(fromlenp + 1);
		if ((*fromlenp = addrlen_saved) != 0) {
			char *from;

			from = (char *)(&recvp->o + 1);
			SCARG(&uap, from) = (struct sockaddr *)from;
			*fromlenp = min(*fromlenp,
		  	  ctp->msg_max_size - (from - (char *)ctp->msg));
		} else {
			SCARG(&uap, from) = NULL;
		}

		/*
		 * The original offset of the data in the message buffer from
		 * the client.  This is what's consulted by soreceive, not
		 * the copyin/out of the args.
		 */
		p->p_offset = sizeof recvp->o + addrlen_saved;
		p->p_read.flush_offset = p->p_offset;

		p->p_read.iovp = work_iov + 2;
		p->p_read.niov_max = sctlp->reply_max - 2;

		if ((ret = sys_recvfrom(l, &uap, &retval)) != EOK)
			break;

		recvp->o.addrlen = *fromlenp;
		nbytes = retval;

		if (*fromlenp == addrlen_saved) {
			/* High runner */
			SETIOV(work_iov + 1, recvp,  sizeof recvp->o + addrlen_saved);
			work_num++;
			rep_iov = work_iov + 1;
		}
		else if ((addrlen_saved - *fromlenp) <= sizeof pad_data) {
			/* Max size of struct sockaddr is UCHAR_MAX */
			SETIOV(work_iov, recvp,  sizeof recvp->o + *fromlenp);
			SETIOV(work_iov + 1, (void *)pad_data, addrlen_saved - *fromlenp);
			work_num += 2;
			rep_iov = work_iov;
		}
		else {
			/* They've done something really weird */
			MsgWritev(ctp->rcvid, work_iov + 2, work_num, sizeof recvp->o + addrlen_saved);
			SETIOV(work_iov, recvp,  sizeof recvp->o + *fromlenp);
			work_num = 1;
			rep_iov = work_iov;
		}
		break;
	}

	case _IO_XTYPE_TCPIP_MSG:
	case _IO_XTYPE_TCPIP_MSG2:
	{
		struct sys_recvmsg_args	uap;
		struct msghdr		*mhp;
		struct msghdr_exten	mh;
		struct iovec		iov;
		io_sock_recvmsg_t	*recvp;
		io_sock_recvmsg2_t	*recv2p;
		int			msgsize, msgoff;

		mhp = &mh.mhdr;
		SCARG(&uap, msg) = mhp;
		SCARG(&uap, s) = -1;

		if (xtype == _IO_XTYPE_TCPIP_MSG) {
			recvp = (io_sock_recvmsg_t *)msg;
			recv2p = NULL;

			addrlen_saved = recvp->i.addrlen;
			controlen_saved = recvp->i.controllen;

			SCARG(&uap, flags) = recvp->i.flags;
			SCARG(&uap, flags) &= ~MSG_HDREXTEN;
			mhp->msg_namelen = recvp->i.addrlen;
			mhp->msg_name = recvp->i.addrlen ?
			    (char *)(&recvp->o + 1) : (caddr_t) 0;
			mhp->msg_controllen = recvp->i.controllen;
			mhp->msg_control = recvp->i.controllen ?
			    (char *)(&recvp->o + 1) + recvp->i.addrlen : NULL;

			p->p_offset = sizeof(recvp->o) + recvp->i.addrlen +
			    recvp->i.controllen;
		}
		else {
			recv2p = (io_sock_recvmsg2_t *)msg;
			recvp = NULL;

			addrlen_saved = recv2p->i.addrlen;
			controlen_saved = recv2p->i.controllen;

			SCARG(&uap, flags) = recv2p->i.flags;
			SCARG(&uap, flags) |= MSG_HDREXTEN;
			mhp->msg_namelen = recv2p->i.addrlen;
			mhp->msg_name = recv2p->i.addrlen ?
			    (char *)(&recv2p->o + 1) : NULL;
			mhp->msg_controllen = recv2p->i.controllen;
			mhp->msg_control = recv2p->i.controllen ?
			    (char *)(&recv2p->o + 1) + recv2p->i.addrlen : NULL;
			mh.controltot = 0;
			mh.controlseq = recv2p->i.controlseq;

			p->p_offset = sizeof(recv2p->o) + recv2p->i.addrlen +
			    recv2p->i.controllen;
		}
		p->p_read.flush_offset = p->p_offset;
		mhp->msg_iovlen = 1;
		mhp->msg_iov = &iov;
		iov.iov_base = 0;   // m->name + m->namelen + m->controllen;
		iov.iov_len = msg->i.nbytes;

		p->p_read.iovp = work_iov + 1;
		p->p_read.niov_max = sctlp->reply_max - 1;

		if ((ret = sys_recvmsg(l, &uap, &retval)) != EOK)
			break;

		nbytes = retval;

		if (xtype == _IO_XTYPE_TCPIP_MSG) {
			recvp->o.flags = mhp->msg_flags;
			recvp->o.addrlen = mhp->msg_namelen;
			recvp->o.controllen = mhp->msg_controllen;

			SETIOV(work_iov, msg, sizeof(recvp->o) +
			    recvp->o.addrlen + recvp->o.controllen);
			if (recvp->o.addrlen == addrlen_saved &&
			    recvp->o.controllen == controlen_saved &&
			    GETIOVLEN(work_iov) <= ctp->msg_max_size - ctp->offset) {
				work_num++;
				rep_iov = work_iov;
			}
			else {
				msgoff = sizeof(recvp->o) + addrlen_saved;
				if (msgoff < ctp->msg_max_size - ctp->offset) {
					/*
					 * All or part of control data is in context.
					 * If part was outside, that portion would
					 * have already been handled by MsgWrite in
					 * copyout().
					 */
					msgsize = min(recvp->o.controllen,
					    ctp->msg_max_size - ctp->offset - msgoff);
					MsgWrite(ctp->rcvid, mhp->msg_control,
					    msgsize, msgoff);
				} else {
					/*
					 * All of control data was outside of context
					 * and would have already been handled by
					 * MsgWrite in copyout().
					 */
				}
				MsgWritev(ctp->rcvid, work_iov + 1, work_num,
				    msgoff + controlen_saved);

				msgsize = min(sizeof(recvp->o) + recvp->o.addrlen,
				    ctp->msg_max_size - ctp->offset);
				SETIOV(work_iov, msg, msgsize);
				work_num = 1;
				rep_iov = work_iov;
			}
		}
		else {
			recv2p->o.flags = mhp->msg_flags;
			recv2p->o.flags &= ~MSG_HDREXTEN;
			recv2p->o.addrlen = mhp->msg_namelen;
			recv2p->o.controllen = mhp->msg_controllen;
			recv2p->o.controltot = mh.controltot;
			recv2p->o.controlseq = mh.controlseq;

			SETIOV(work_iov, msg, sizeof(recv2p->o) +
			    recv2p->o.addrlen + recv2p->o.controllen);
			if (recv2p->o.addrlen == addrlen_saved &&
			    recv2p->o.controllen == controlen_saved &&
			    GETIOVLEN(work_iov) <= ctp->msg_max_size - ctp->offset) {
				work_num++;
				rep_iov = work_iov;
			}
			else {
				msgoff = sizeof(recv2p->o) + addrlen_saved;
				if (msgoff < ctp->msg_max_size - ctp->offset) {
					/*
					 * All or part of control data is in context.
					 * If part was outside, that portion would
					 * have already been handled by MsgWrite in
					 * copyout().
					 */
					msgsize = min(recv2p->o.controllen,
					    ctp->msg_max_size - ctp->offset - msgoff);
					MsgWrite(ctp->rcvid, mhp->msg_control,
					    msgsize, msgoff);
				} else {
					/*
					 * All of control data was outside of context
					 * and would have already been handled by
					 * MsgWrite in copyout().
					 */
				}
				MsgWritev(ctp->rcvid, work_iov + 1, work_num,
				    msgoff + controlen_saved);

				msgsize = min(sizeof(recv2p->o) + recv2p->o.addrlen,
				    ctp->msg_max_size - ctp->offset);
				SETIOV(work_iov, msg, msgsize);
				work_num = 1;
				rep_iov = work_iov;
			}
		}
		break;
	}
	case _IO_XTYPE_TCPIP_MMSG:
	{
		io_sock_recvmmsg_t		*recvp;
		struct sys_recvmmsg_args	uap;
		unsigned			off, off_org, sz;

		recvp = (io_sock_recvmmsg_t *)msg;

		addrlen_saved = recvp->i.addrlen_tot;
		controlen_saved = recvp->i.controllen_tot;

		SCARG(&uap, s) = -1;
		SCARG(&uap, mmsg)  = (struct mmsghdr *)(&recvp->i + 1);
		SCARG(&uap, vlen)  = recvp->i.vlen;
		SCARG(&uap, flags) = recvp->i.flags;
		if (recvp->i.flags & MSG_NOTIMEO) {
			SCARG(&uap, timeout) = NULL;
		} else {
			SCARG(&uap, timeout) = &recvp->i.to;
		}

		off_org = sizeof(recvp->i) +
		    recvp->i.vlen * sizeof(struct mmsghdr) +
		    addrlen_saved + controlen_saved;

		p->p_offset = off_org;
		p->p_read.flush_offset = p->p_offset;

		p->p_read.iovp = work_iov + 1;
		p->p_read.niov_max = sctlp->reply_max - 1;

		/*
		 * Where address / control data will go, but there may
		 * be gaps if we fill in less than their passed in
		 * msg_namelen / msg_controllen so zero this out.
		 */
		off = sizeof(*recvp) + recvp->i.vlen * sizeof(struct mmsghdr);
		if (off < ctp->msg_max_size - ctp->offset) {
			sz = (ctp->msg_max_size - ctp->offset) - off;
			memset((char *)recvp + off, 0x00, sz);
		}
		if ((ret = sys_recvmmsg(l, &uap, &retval)) != EOK)
			break;

		nbytes = retval;

		if (work_num && (p->p_read.flush_offset != off_org ||
		    off_org > ctp->msg_max_size - ctp->offset)) {
			MsgWritev(ctp->rcvid, work_iov + 1, work_num, p->p_read.flush_offset);
			SETIOV(work_iov, recvp, ctp->msg_max_size - ctp->offset);
			work_num = 1;
		} else {
			SETIOV(work_iov, recvp, off_org);
			work_num++;
		}
		rep_iov = work_iov;

		break;
	}

	case _IO_XTYPE_OFFSET:
		ret = ESPIPE;
		break;

	default:
		ret = ENOSYS;
		break;
	}

	/*
	 * We can't let the resmgr layer do the reply for us as 
	 * we build up our own iov list and don't reply from our 
	 * context.  This should be OK WRT combine message
	 * processing as a read can't really be in the middle of 
	 * a combine message due to the variable length of the 
	 * reply (any return other than EOK ends combine message 
	 * processing in the resmgr layer).
	 */

	if (ret != EOK) {
		MsgError(ctp->rcvid, ret);
	}
	else {
		fp->f_timeflags |= IOFUNC_ATTR_ATIME;
		MsgReplyv(ctp->rcvid, nbytes, rep_iov, work_num);
	}

	m_freem(m_to_free);

	/* Set these to known state */
	p->p_read.m_to_free = NULL;
	p->p_read.niovp     = NULL;
	p->p_read.iovp      = NULL;

	PROC_FINI(p);

	return _RESMGR_NOREPLY;
}

int
tcpip_chmod(resmgr_context_t *ctp, io_chmod_t *msg, RESMGR_OCB_T *ocb)
{
	return tcpip_fop(ctp, (resmgr_iomsgs_t *)msg, ocb);
}

int
tcpip_chown(resmgr_context_t *ctp, io_chown_t *msg, RESMGR_OCB_T *ocb)
{
	return tcpip_fop(ctp, (resmgr_iomsgs_t *)msg, ocb);
}

static int
tcpip_fop(resmgr_context_t *ctp, resmgr_iomsgs_t *msg, RESMGR_OCB_T *ocb)
{
	struct file		*fp;
	struct msg_open_info	*mop;
	iofunc_ocb_t		iocb;
	int			ret;

	/*
	 * PROC_[INIT|FINI]() not needed here since no stack code
	 * is called and we don't block.
	 */
	fp = ocb;

	/*
	 * Posix says:
	 * - fchmod on a socket is undefined
	 * - fchown on a socket gets EINVAL.
	 * Follow BSD and fail both.
	 */
	if (fp->f_type == DTYPE_SOCKET)
		return EINVAL;
	mop = fp->f_path_info;

	memset(&iocb, 0x00, sizeof(iocb));
	/* Knowing that iofunc_[chown|chmod] only look at these flags in ocb */
	iocb.ioflag = fp->f_flag;

	switch (msg->type) {
	case _IO_CHOWN:
		ret = iofunc_chown(ctp, &msg->chown, &iocb, &mop->attr);
		break;

	case _IO_CHMOD:
		ret = iofunc_chmod(ctp, &msg->chmod, &iocb, &mop->attr);
		break;

	default:
		ret = ENOSYS;
		break;
	}

	return ret;
}

int
tcpip_write (resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb)
{
	int			ret, nbytes, retval, replen;
	struct file		*fp;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	struct mbuf		*m_last;
	int			last_index, n_done, hdrlen, addrlen, ctrlen;
	char			*src, *dst, *ext_saved;
	struct page_extra	*pg_saved;
	struct nw_work_thread	*wtp;
#ifdef FAKE_UP_WRITES
	int			do_reply;

	do_reply = ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_TCPIP_DBUG);
#endif

	TASK_TIME_STOP(TASK_TIME_RESMGR);

	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;
	nbytes = retval = replen = 0;

	if (p->p_mbuf != NULL) {
		/*
		 * Part of combine message.
		 *
		 * Two issues:
		 *
		 * We take a variable number of iovs off of
		 * sctlp->recv_mbuf the calculations for which
		 * assume we're the first message.
		 *
		 * Not worth trying to remove the assumption
		 * above as any manipulations of sctlp->recv_mbuf
		 * must be done before we block via ltsleep().
		 * We don't know what messages may have come
		 * previously and therefore may have already
		 * slept.
		 */
		PROC_FINI(p);
		return EOPNOTSUPP;
	}

	switch (msg->i.xtype & _IO_XTYPE_MASK) {
	case _IO_XTYPE_NONE:
	{
		struct sys_write_args uap;

		nbytes = msg->i.nbytes;

		SCARG(&uap, fd)    = -1;
		SCARG(&uap, buf)   = NULL;
		SCARG(&uap, nbyte) = nbytes;

		p->p_offset = sizeof (msg->i);

		if (nbytes <= ctp->msg_max_size - sizeof(msg->i) || sctlp->recv_avail <= 1) {
			last_index = 0;
			n_done     = 0;
			hdrlen     = 28;
		}
		else {
			last_index = min(1 + ((nbytes - (ctp->msg_max_size - sizeof(msg->i))) / MCLBYTES), sctlp->recv_avail - 1);
			n_done     = (ctp->msg_max_size - sizeof(msg->i)) + ((last_index - 1) * MCLBYTES);
			hdrlen     = 0;
		}

		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		m_last = sctlp->recv_mbuf[sctlp->recv_start + last_index];
		m_last->m_next = NULL;

		p->p_mbuf->m_len  -= sizeof(msg->i);
		p->p_mbuf->m_data += sizeof(msg->i);

		m_last->m_len = min(nbytes - n_done, m_last->m_len);
		p->p_mbuf->m_pkthdr.len = n_done + m_last->m_len;

		/*
		 * If the last in the chain will fit into a non cluster,
		 * release the cluster and move it down.
		 *
		 * Note on pathological case:
		 * If this is the first mbuf in this chain (last_index == 0),
		 * sbcompress() may copy this a second time if it notices
		 * this will fit into last mbuf in the send buffer chain.
		 * In short, small writes stink.
		 */

		/*
		 * We always test against MHLEN and copy to m_last->m_pktdat
		 * in case sosend() wants to turn this into a pkt header (if
		 * it isn't already).
		 */
		if (m_last->m_len + hdrlen <= MHLEN) {
			dst = m_last->m_pktdat + hdrlen;
#ifndef NDEBUG
			if (last_index == 0 && (m_last->m_flags & M_PKTHDR) == 0)
					panic("tcpip_write");
#endif
			ext_saved = m_last->m_ext.ext_buf;
			pg_saved  = m_last->m_ext.ext_page;
			memcpy(dst, m_last->m_data, m_last->m_len);
			m_last->m_data = dst;
			/*
			 * XXX NTO Don't really like this as it subverts 
			 *         the per thread zone cache.
			 */
			wtp = WTP;
			NW_SIGHOLD_P(wtp);
			pool_cache_put_header(&mclpool_cache, ext_saved, pg_saved, wtp);
			m_last->m_flags &= ~M_EXTCOPYFLAGS;
		}

		sctlp->recv_avail -= last_index + 1;
		sctlp->recv_start += last_index + 1;

		ret = sys_write(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case _IO_XTYPE_TCPIP:
#if defined(FAKE_UP_WRITES) || (defined(USE_PULSE) && defined(TRACK_DELTAS))
	case _IO_XTYPE_TCPIP_DBUG:
#endif
	{
		io_sock_sendto_t *sendp = (io_sock_sendto_t *)msg;
		struct sys_sendto_args uap;

		/*
		 * The only reason this check is still needed is
		 * the assignment below of p->p_mbuf to the first
		 * cluster received into:
		 *   p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start]
		 *
		 * copyin() was enhanced since this check was initially
		 * added to MsgRead if past ctp->msg_max_size (the first
		 * mbuf the message was received into).
		 */
		if (sendp->i.addrlen + sizeof(sendp->i) >= ctp->msg_max_size - ctp->offset) {
			ret = EMSGSIZE;
			break;
		}

		nbytes = sendp->i.write.nbytes;

		SCARG(&uap, s)     = -1;
		SCARG(&uap, flags) = sendp->i.flags;
		SCARG(&uap, tolen) = sendp->i.addrlen;
		SCARG(&uap, to)    = sendp->i.addrlen ? (struct sockaddr *)((char *)&sendp->i + sizeof sendp->i) : NULL;
		SCARG(&uap, buf)   = 0;
		SCARG(&uap, len)   = nbytes;
		p->p_offset = sizeof sendp->i + sendp->i.addrlen;
#if defined(FAKE_UP_WRITES) || (defined(USE_PULSE) && defined(TRACK_DELTAS))
		if ((msg->i.xtype & _IO_XTYPE_MASK) == _IO_XTYPE_TCPIP_DBUG) {
			/* sendp->i.addrlen was used to store offset past 64 bit ClockCycles counter */
			SCARG(&uap, flags) = 0;
			SCARG(&uap, tolen) = 0;
			SCARG(&uap, to)    = NULL;
		}
#endif

		if (nbytes <= (n_done = ctp->msg_max_size - (sizeof(sendp->i) + sendp->i.addrlen)) ||
		    sctlp->recv_avail <= 1) {
			last_index = 0;
			n_done     = 0;
			hdrlen     = max(sizeof(*sendp), 28);
			addrlen    = sendp->i.addrlen;
		}
		else {
			last_index = min(1 + ((nbytes - n_done) / MCLBYTES), sctlp->recv_avail - 1);
			n_done    += (last_index - 1) * MCLBYTES;
			hdrlen     = 0;
			addrlen    = 0;
		}


		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		m_last = sctlp->recv_mbuf[sctlp->recv_start + last_index];
		m_last->m_next = NULL;

		p->p_mbuf->m_len  -= sizeof(sendp->i) + sendp->i.addrlen;
		p->p_mbuf->m_data += sizeof(sendp->i) + sendp->i.addrlen;

		m_last->m_len = min(nbytes - n_done, m_last->m_len);

		if (m_last->m_len + hdrlen + addrlen <= MHLEN) {
			dst = m_last->m_pktdat + hdrlen;
			if (last_index == 0) {
#ifndef NDEBUG
				if (!(m_last->m_flags & M_PKTHDR))
					panic("tcpip_write");
#endif
				src = (char *)&sendp->i + sizeof sendp->i;
				if (SCARG(&uap, to))
					SCARG(&uap, to) = (struct sockaddr *)dst; /* reset */;
				ctp->msg = (resmgr_iomsgs_t *)(dst - sizeof(*sendp));
				ctp->msg_max_size = MHLEN - ((char *)ctp->msg - m_last->m_pktdat);
			}
			else {
				src = m_last->m_data;
			}
			ext_saved = m_last->m_ext.ext_buf;
			pg_saved  = m_last->m_ext.ext_page;
			memcpy(dst, src, m_last->m_len + addrlen);
			m_last->m_data = dst + addrlen;
			wtp = WTP;
			NW_SIGHOLD_P(wtp);
			pool_cache_put_header(&mclpool_cache, ext_saved, pg_saved, wtp);
			m_last->m_flags &= ~M_EXTCOPYFLAGS;
		}

		sctlp->recv_avail -= last_index + 1;
		sctlp->recv_start += last_index + 1;


		ret = sys_sendto(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case _IO_XTYPE_TCPIP_MSG:
	{
		io_sock_sendmsg_t *sendp = (io_sock_sendmsg_t *)msg;
		struct sys_sendmsg_args uap;
		struct msghdr mh;
		struct iovec iov;

		/*
		 * As above.  This check could probably be
		 * remove with a little thought.
		 */
		if (sendp->i.addrlen + sendp->i.controllen + sizeof sendp->i >= ctp->msg_max_size - ctp->offset) {
			ret = EMSGSIZE;
			break;
		}

		nbytes = sendp->i.write.nbytes;

		SCARG(&uap, s)     = -1;
		SCARG(&uap, flags) = sendp->i.flags;
		SCARG(&uap, msg)   = &mh;
		mh.msg_namelen = sendp->i.addrlen;
		mh.msg_name = sendp->i.addrlen ? (char *)&sendp->i + sizeof sendp->i : (void *) 0;
		mh.msg_controllen = sendp->i.controllen;
		mh.msg_control = sendp->i.controllen ? (char *)&sendp->i + sizeof sendp->i + sendp->i.addrlen : NULL;
		mh.msg_iovlen = 1;
		mh.msg_iov = &iov;
		mh.msg_flags = 0;
		iov.iov_base = 0;   // m->name + m->namelen + m->controllen;
		iov.iov_len = sendp->i.write.nbytes;
		p->p_offset = sizeof sendp->i + sendp->i.addrlen + sendp->i.controllen;

		if (nbytes <= (n_done = ctp->msg_max_size - (sizeof(sendp->i) + sendp->i.addrlen + sendp->i.controllen)) ||
		    sctlp->recv_avail <= 1) {
			last_index = 0;
			n_done     = 0;
			hdrlen     = max(sizeof(*sendp), 28);
			addrlen    = sendp->i.addrlen;
			ctrlen     = sendp->i.controllen;
		}
		else {
			last_index = min(1 + ((nbytes - n_done) / MCLBYTES), sctlp->recv_avail - 1);
			n_done    +=  (last_index - 1) * MCLBYTES;
			hdrlen     = 0;
			addrlen    = 0;
			ctrlen     = 0;
		}


		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		m_last = sctlp->recv_mbuf[sctlp->recv_start + last_index];
		m_last->m_next = NULL;

		p->p_mbuf->m_len  -= sizeof(sendp->i) + sendp->i.addrlen + sendp->i.controllen;
		p->p_mbuf->m_data += sizeof(sendp->i) + sendp->i.addrlen + sendp->i.controllen;

		m_last->m_len = min(nbytes - n_done, m_last->m_len);

		if (m_last->m_len + hdrlen + addrlen + ctrlen <= MHLEN) {
			dst = m_last->m_pktdat + hdrlen;
			if (last_index == 0) {
#ifndef NDEBUG
				if (!(m_last->m_flags & M_PKTHDR))
					panic("tcpip_write");
#endif
				src = (char *)&sendp->i + sizeof sendp->i;
				if (mh.msg_name)
					mh.msg_name = dst; /* Reset */
				if (mh.msg_control)
					mh.msg_control = dst + addrlen; /* Reset */
				ctp->msg = (resmgr_iomsgs_t *)(dst - sizeof(*sendp));
				ctp->msg_max_size = MHLEN - ((char *)ctp->msg - m_last->m_pktdat);
			}
			else {
				src = m_last->m_data;
			}
			ext_saved = m_last->m_ext.ext_buf;
			pg_saved  = m_last->m_ext.ext_page;
			memcpy(dst, src, m_last->m_len + addrlen + ctrlen);
			m_last->m_data = dst + addrlen + ctrlen;
			wtp = WTP;
			NW_SIGHOLD_P(wtp);
			pool_cache_put_header(&mclpool_cache, ext_saved, pg_saved, wtp);
			m_last->m_flags &= ~M_EXTCOPYFLAGS;
		}
		src = NULL;

		sctlp->recv_avail -= last_index + 1;
		sctlp->recv_start += last_index + 1;


		ret = sys_sendmsg(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case _IO_XTYPE_TCPIP_MMSG:
	{
		io_sock_sendmmsg_t		*sendp;
		struct sys_sendmmsg_args	uap;
		struct mbuf			*m_control, *m_tmp;

		sendp = (io_sock_sendmmsg_t *)msg;

		SCARG(&uap, s)     = -1;
		SCARG(&uap, flags) = sendp->i.flags;
		SCARG(&uap, vlen)  = sendp->i.vlen;
		SCARG(&uap, mmsg)  = (struct mmsghdr *)(&sendp->i + 1);

		if (ctp->info.msglen <= ctp->msg_max_size) {
			last_index = 0;
		} else {
			last_index = (ctp->info.msglen - ctp->msg_max_size) / MCLBYTES;
			if ((ctp->info.msglen - ctp->msg_max_size) % MCLBYTES)
				last_index++;
			last_index = min(last_index, sctlp->recv_avail - 1);
		}


		if ((unsigned)msg->i.nbytes > ctp->info.srcmsglen) {
			ret = EINVAL;
			break;
		}

		p->p_offset = ctp->info.srcmsglen - msg->i.nbytes;
		if (p->p_offset < sizeof(*sendp)) {
			ret = EINVAL;
			break;
		}

		m_control = sctlp->recv_mbuf[sctlp->recv_start];
		m_last = sctlp->recv_mbuf[sctlp->recv_start + last_index];
		m_last->m_next = NULL;

		p->p_mbuf = m_split(m_control, p->p_offset, M_DONTWAIT);
		if (p->p_mbuf == NULL) {
			ret = ENOBUFS;
			break;
		}
#if 1 /* Is this needed ? */
		m_tmp = m_split(p->p_mbuf, msg->i.nbytes, M_DONTWAIT);
		if (m_tmp == NULL) {
			ret = ENOBUFS;
			break;
		}
		m_freem(m_tmp);
#endif

		sctlp->recv_avail -= last_index + 1;
		sctlp->recv_start += last_index + 1;

		ret = sys_sendmmsg(PR_TO_LWP(p), &uap, &retval);
		 /* Actually number of mmsg sent (retval <= vlen) */
		replen = retval * sizeof(struct mmsghdr) + sizeof(sendp->o);
		/*
		 * More mmsghdr than this would be handled by
		 * MsgWrite() in copyout()
		 * */
		replen = min(replen, ctp->msg_max_size);
		m_freem(m_control);
		memset(&sendp->o, 0x00, sizeof(sendp->o));
		break;
	}

	case _IO_XTYPE_OFFSET:
		ret = ESPIPE;
		break;

	default:
		ret = ENOSYS;
		break;
	}


#ifdef FAKE_UP_WRITES
	if (do_reply == 0) {
		PROC_FINI(p);
		return _RESMGR_NOREPLY;
	}
#endif
	
	if (ret == EOK) {
		fp->f_timeflags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
		_RESMGR_STATUS(ctp, retval);
		if (replen) {
			ret = _RESMGR_PTR(ctp, msg, replen);
		}
	}

	PROC_FINI(p);

	return ret;
}

int
tcpip_stat(resmgr_context_t *ctp, io_stat_t *msg, RESMGR_OCB_T *ocb)
{
	struct file			*fp;
	struct proc			*p;
	struct nw_stk_ctl		*sctlp;
	int				ret;
	struct msg_open_info		*mop;
	dev_t				dev;
	ino_t				ino_low, ino_hi;
	time_t				clock;
	struct sys___fstat30_args	uap;
	
	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}

	/*
	 * Get dev / ino from proc since it's actually handling
	 * /dev/socket/.  This avoids possible dev ino duplication
	 * but means all AF_INET (for example) sockets have same
	 * dev / ino (same as if did stat(/dev/socket/2).  Same
	 * behaviour as pipe.
	 */

	mop = fp->f_path_info;
	iofunc_stat(ctp, &mop->attr, &msg->o);

	/* Save */
	dev = msg->o.st_dev;
	ino_low = msg->o.st_ino;
	ino_hi = msg->o.st_ino_hi;

	SCARG(&uap, fd) = -1;
	SCARG(&uap, sb) = &msg->o;

	if ((ret = sys___fstat30(PR_TO_LWP(p), &uap, NULL)) != EOK) {
		PROC_FINI(p);
		return ret;
	}

	/* Restore */
	msg->o.st_dev = dev;
	msg->o.st_ino = ino_low;
	msg->o.st_ino_hi = ino_hi;

	if (fp->f_timeflags) {
		clock = time(NULL);

		if(fp->f_timeflags & IOFUNC_ATTR_MTIME)
			fp->f_mtime = clock;
		if(fp->f_timeflags & IOFUNC_ATTR_ATIME)
			fp->f_atime = clock;
		if(fp->f_timeflags & IOFUNC_ATTR_CTIME)
			fp->f_ctime = clock;

		fp->f_timeflags = 0;
	}

	msg->o.st_atime = fp->f_atime;
	msg->o.st_ctime = fp->f_ctime;
	msg->o.st_mtime = fp->f_mtime;

	PROC_FINI(p);

	_RESMGR_STATUS(ctp, 0);
	/* Only space for one iov in ctp */
	return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o));
}

int (* sys_sctp_peeloff)(struct proc *p, void *v, register_t *retval) = NULL;

int
tcpip_openfd(resmgr_context_t *ctp, io_openfd_t *msg, RESMGR_OCB_T *ocb)
{
	union {
		struct sys_accept_args accept; /* CHECKME: 4.3 COMPAT */
		struct sys___socket30_args socket;
		struct sys_socketpair_args socketpair;
		struct sctp_peeloff_args peeloff;
	} uap;
	int			retval, ret;
	struct file		*fp, *fp2;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	struct socket		*so;
	
	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}

	switch (msg->i.xtype) {
	case _IO_OPENFD_ACCEPT: {
		socklen_t *namelen;
		struct sockaddr *name;

		SCARG(&uap.accept, s) = -1;
		namelen = (socklen_t *)msg;
		name = (struct sockaddr *)(namelen + 1);
		*namelen = ctp->msg_max_size - ((char *)name - (char *)ctp->msg);
		SCARG(&uap.accept, anamelen) = namelen;;
		SCARG(&uap.accept, name)     = name;

		ret = sys_accept(PR_TO_LWP(p), &uap.accept, (uintptr_t *)&fp2);
		if (ret == EOK) {
#ifdef OCB_LOCAL_CACHE
			fp_local_cache(&ctp->info, fp2);
#endif
			_RESMGR_STATUS(ctp, *namelen);
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, name, *namelen);
		}
		break;
	}

#ifdef QNXNTO_KQUEUE_notyet
#if 0
	/*
	 * Enable this and remove option below once _IO_OPENFD_KQUEUE gets
	 * disseminated (6.3.2 and later).
	 */
	case _IO_OPENFD_KQUEUE:
#else
	case (_IO_OPENFD_PIPE + 1):
#endif
		ret = sys_kqueue(PR_TO_LWP(p), NULL, &fp2);
		if (ret == EOK) {
#ifdef OCB_LOCAL_CACHE
			fp_local_cache(&ctp->info, fp2);
#endif
			/*
			 * XXX
			 * inheriting the info from the seed.  
			 * This doesn't really make sense as
			 * there's no path associated with a
			 * kqueue but we should have something 
			 * here for stat handling.
			 */
			fp2->f_path_info = fp->f_path_info;
			_RESMGR_STATUS(ctp, 0);
		}
		break;
#endif

	case _IO_OPENFD_SCTP_PEELOFF:
		if (sys_sctp_peeloff == NULL) {
			ret = EOPNOTSUPP;
			break;
		}
		SCARG(&uap.peeloff, sd) = -1;
		SCARG(&uap.peeloff, name) = (caddr_t)&msg->i.key;

		ret = sys_sctp_peeloff(p, &uap.peeloff, &retval);
		/* Following ignored by resmgr layer if ret != EOK */
		_RESMGR_STATUS(ctp, 0);
		break;

	case _IO_OPENFD_PIPE:
	case _IO_OPENFD_NONE:
		kauth_cred_free(p->p_cred);
		p->p_cred = kauth_cred_alloc();

		if (fp->f_type != DTYPE_SOCKET || !(so = (struct socket *)fp->f_data) || !so->so_proto ||
		    !so->so_proto->pr_domain
#if 0
		    || so->so_proto->pr_domain->dom_family != AF_INET
#endif
		    ) {
			ret = ENOSYS;
			break;
		}
		SCARG(&uap.socket, domain)   = so->so_proto->pr_domain->dom_family;
		SCARG(&uap.socket, type)     = so->so_type;
		SCARG(&uap.socket, protocol) = so->so_proto->pr_protocol;
		ret = sys___socket30(PR_TO_LWP(p), &uap.socket, (uintptr_t *)&fp2);
		if (ret != EOK)
			break;

		fp2->f_path_info = fp->f_path_info;
		fp2->f_timeflags |= IOFUNC_ATTR_ATIME | IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
		if (msg->i.xtype == _IO_OPENFD_PIPE) {
			struct file *spair[2];
				
			spair[0] = fp;
			spair[1] = fp2;
				
			SCARG(&uap.socketpair, domain)   = so->so_proto->pr_domain->dom_family;
			SCARG(&uap.socketpair, type)     = so->so_type;
			SCARG(&uap.socketpair, protocol) = so->so_proto->pr_protocol;
			SCARG(&uap.socketpair, rsv)      = spair;
			ret = sys_socketpair(PR_TO_LWP(p), &uap.socketpair, &retval);
			if (ret != EOK) {
				/* Undo sys_socket() on fp2 */
				_resmgr_unbind(&ctp->info);
				soclose((struct socket *)fp2->f_data);
				ffree(fp2);
				break;
			}
		}
		/* Following ignored by resmgr layer if ret != EOK */
		_RESMGR_STATUS(ctp, 0);
		break;

	default:
		ret = ENOSYS;
		break;
	}

	PROC_FINI(p);

	return ret;
}
		
int
tcpip_close(resmgr_context_t *ctp, io_close_t *msg, RESMGR_OCB_T *ocb)
{	
	int			ret;
	struct file		*fp;
	struct proc		*p;
	struct sys_close_args	uap;
#ifdef OCB_LOCAL_CACHE
	int			scoid;
#endif
	RESMGR_OCB_T *restore_ocb = NULL;
	
	/*
	 * Doesn't manipulate sctlp->recv_mbuf et al since
	 * may be called as result of low res disconnect
	 * pulse.
	 */

	if (ctp->rcvid != -1) {
		p = PROC_FROM_CTP(ctp);
	}
	else {
		/* Cleaning out all fds on resmgr_detach() and can't map proc from ctp */
		p = curproc;
		restore_ocb = PR_TO_LWP((p))->l_fp;
	}
	PROC_SETUP(p, ctp, fp, ocb);

	SCARG(&uap, fd) = -1;

	ret = sys_close(PR_TO_LWP(p), &uap, NULL); /* Checks for EBADF */

#ifdef OCB_LOCAL_CACHE
	/*
	 * As with the resmgr layer, we always remove regardless
	 * of the value of ret.
	 */

	/* Unsigned comparisons to catch negative values */
	scoid = ctp->info.scoid & ~_NTO_SIDE_CHANNEL;
	if ((unsigned)scoid < ocb_cache_scoid_max &&
	    (unsigned)ctp->info.coid < OCB_CACHE_COID_MAX) {
		ocb_cache[scoid].ocbs[ctp->info.coid] = NULL;
	}
#endif
	/*
	 * If we happen to have been called as a result
	 * of a dup failing inside the resmgr layer,
	 * our return code is ignored and the
	 * resmgr layer will do the Reply.  Any
	 * reply done here in such a case will fail
	 * as the resmgr layer will have zeroed out
	 * the rcvid.  As such we simply let the
	 * resmgr layer always handle the Reply.
	 */

	PROC_FINI(p);

	if (restore_ocb)
		PROC_RESTORE(p, fp, restore_ocb);

	_RESMGR_STATUS(ctp, 0);

	return ret;
}


/* Utilities to deal with pointers embedded in ioctl() commands
 * copyin/out() have been modified to return EMORE in this condition at which point
 * libc's ioctl() will send an DCMD_MISC_GETPTREMBED message. These utilities
 * fill in a pointer which the module has identified as embedded in the original
 * message.
 */

/* Write embed_ptr and embed_len into iovec[index] of DCMD_MISC_GETPTREMBED message
 */
int ioctl_getoneptrembed(io_devctl_t *msg, caddr_t embed_ptr, int embed_len, int index) {
	int              offset = sizeof(io_devctl_t) + sizeof(struct __ioctl_getptrembed);
 	struct proc	*p;
	int              ret;
	iov_t            embediov;
	resmgr_context_t *ctp;

	/* Write in request for embedded pointer */
  	p = curproc;
	ctp = &p->p_ctxt;
	embediov.iov_base = embed_ptr;
	embediov.iov_len = embed_len;
	ret = copyout(&embediov, (uint8_t *)ctp->msg + offset + index*sizeof(embediov), sizeof(embediov));

	return ret;
}

/* Write embed_ptr and embed_len into iovec of DCMD_MISC_GETPTREMBED message
 * and zero out the rest of the niov entries in the iovec.
 */
int ioctl_getptrembed(io_devctl_t *msg, caddr_t embed_ptr, int embed_len, int niov) {
	int              offset = sizeof(io_devctl_t) + sizeof(struct __ioctl_getptrembed);
	struct proc	*p;
	iov_t            embediov;
	int              ret;
	int              i;
	resmgr_context_t *ctp;

	/* Write in request for embedded pointer */
	p = curproc;
	ctp = &p->p_ctxt;
	embediov.iov_base = embed_ptr;
	embediov.iov_len = embed_len;
	ret = copyout(&embediov, (uint8_t *)ctp->msg + offset, sizeof(embediov));
	if (ret)
		return ret;

	embediov.iov_base = NULL;
	embediov.iov_len = 0;
	for (i = 1; i < niov; i++) {
		ret = copyout(&embediov, (uint8_t *)ctp->msg + offset + i*sizeof(embediov), sizeof(embediov));
		if (ret)
			return ret;
	}

	return ret;
}


int
tcpip_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb)
{
	int			ret, retval, replen, *intp;
	struct file		*fp;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	struct lwp		*l;

	PROC_INIT(p, ctp, fp, ocb);
	l = PR_TO_LWP(p);

	sctlp = &stk_ctl;

	ret = retval = replen = 0;

	p->p_offset = 0;

#ifdef FAST_IPSEC
	/* Special case the devcrypto code to limit its impact */
	if (fp->f_type == DTYPE_CRYPTO) {
		int		niov, n_done;
		struct mbuf	*m_last;
		iov_t		work_iov[32], *wiovp;
		
		if (p->p_mbuf != NULL) {
			/* As tcpip_write() */
			PROC_FINI(p);
			return EOPNOTSUPP;
		}

		/*
		 * Calculate how many mbufs were consumed, as well as the amount of
		 * data in the last mbuf.
		 */
		if (ctp->info.msglen <= ctp->msg_max_size - ctp->offset ||
		    (msg->i.dcmd & DEVDIR_TO) == 0) {
			/* Got the whole message in one mbuf */
			niov = 1;
			n_done = 0;
		} else {
			/*
			 * Get the number of iovs rounded up
			 * (x +(y-1))/y  adding the denominator -1 to the numerator causes integer div to round up
			 */
			niov = min((ctp->info.msglen - (ctp->msg_max_size - ctp->offset) + (MCLBYTES - 1)) / MCLBYTES, sctlp->recv_avail);
			/* number of bytes excluding an incomplete trailing buffer */
			n_done = (niov - 1) * MCLBYTES + (ctp->msg_max_size - ctp->offset);
			/* add in the first buffer. The one sized (ctp->msg_max_size - ctp->offset) */
			niov++;
		}

		if (niov <= sizeof(work_iov) / sizeof(work_iov[0])) {
			wiovp = work_iov;
		} else if ((wiovp = malloc(niov * sizeof(*wiovp), M_TEMP, M_NOWAIT)) == NULL) {
			PROC_FINI(p);
			return ENOMEM;
		}
		memcpy(wiovp, sctlp->recv_iov + sctlp->recv_start, niov * sizeof(*wiovp));

		m_last = sctlp->recv_mbuf[sctlp->recv_start + niov - 1];
		m_last->m_next = NULL;

		p->p_read.iovp = wiovp;

		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_len  -= sizeof(msg->i);
		p->p_mbuf->m_data += sizeof(msg->i);
		p->p_mbuf->m_pkthdr.len = ctp->info.msglen - sizeof(msg->i);

		p->p_read.niovp = &niov;

		m_last->m_len = min(ctp->info.msglen - n_done, m_last->m_len);

		sctlp->recv_avail -= niov;
		sctlp->recv_start += niov;

		FILE_USE(fp);
		ret = fp->f_ops->fo_ioctl(fp, msg->i.dcmd, _DEVCTL_DATA(msg->i), l);
		FILE_UNUSE(fp, p);

		if (ret != EOK)
			MsgError(ctp->rcvid, ret);
		else if ((msg->i.dcmd & DEVDIR_FROM) == 0) {
			msg->o.ret_val = 0;
			MsgReply(ctp->rcvid, 0, msg, sizeof(msg->o));
		} else {
			msg->o.ret_val = 0;
			replen = sizeof msg->o + msg->o.nbytes;

			/* Limit the size of the last iov */
			if (niov == 1 || replen < (ctp->msg_max_size - ctp->offset) || p->p_offset) {
				niov = 1;
				/* If p_offset is set then copyout has already MsgWritten all data beyond
				 * the first iov (msg context) and only what copyout put in the context needs 
				 * to be written.
				 */
				p->p_read.iovp[0].iov_len = max(replen, p->p_offset);
			} else
				p->p_read.iovp[niov - 1].iov_len = (replen - (ctp->msg_max_size - ctp->offset)) % MCLBYTES;

			MsgReplyv(ctp->rcvid, 0, p->p_read.iovp, niov);
		}

		PROC_FINI(p);

		if (wiovp != work_iov)
			free(wiovp, M_TEMP);

		return _RESMGR_NOREPLY;
	}
#endif

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}


	switch (msg->i.dcmd) {
	case DCMD_IP_SDESTADDR:
	{
		struct sys_connect_args uap;

		SCARG(&uap, s)       = -1;
		SCARG(&uap, namelen) = msg->i.nbytes;
		SCARG(&uap, name)    = msg->i.nbytes ? (struct sockaddr *)((char *)msg + sizeof msg->i)  : (void *) 0;
		ret = sys_connect(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case DCMD_IP_SSRCADDR:
	{
		struct sys_bind_args uap;

		SCARG(&uap, s)       = -1;
		SCARG(&uap, namelen) = msg->i.nbytes;
		SCARG(&uap, name)    = msg->i.nbytes ? (struct sockaddr *)((char *)msg + sizeof msg->i) : NULL;
		ret = sys_bind(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case DCMD_IP_GDESTADDR:
	{
		struct sys_getpeername_args uap;

		SCARG(&uap, fdes) = -1;
		SCARG(&uap, alen) = &msg->i.nbytes;
		SCARG(&uap, asa)  = msg->i.nbytes ? (struct sockaddr *)((char *)&msg->o + sizeof msg->o) : NULL;
		if ((ret = sys_getpeername(PR_TO_LWP(p), &uap, &retval)) == EOK) {
			msg->o.ret_val = msg->i.nbytes;
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + msg->i.nbytes);
		}
		break;
	}

	case DCMD_IP_GSRCADDR:
	{
		struct sys_getsockname_args uap;

		SCARG(&uap, fdes) = -1;
		SCARG(&uap, alen) = &msg->i.nbytes;
		SCARG(&uap, asa)  = msg->i.nbytes ? (struct sockaddr *)((char *)msg + sizeof msg->o) : NULL;
		if ((ret = sys_getsockname(PR_TO_LWP(p), &uap, &retval)) == EOK) {
			msg->o.ret_val = msg->i.nbytes;
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + msg->i.nbytes);
		}
		break;
	}

	case DCMD_IP_LISTEN:
	{
		struct sys_listen_args uap;

		intp = _DEVCTL_DATA(msg->i);

		SCARG(&uap, s)       = -1;
		SCARG(&uap, backlog) = *intp;
		ret = sys_listen(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case DCMD_ALL_SETFLAGS:
	{
		/*
		 * Kernel from which this is derived likes to use F* variants.
		 * This is equivalent to.
		#define STATUS_FLAGS (O_APPEND|O_ASYNC|O_SYNC|O_NONBLOCK)
		 */
#define STATUS_FLAGS (FAPPEND|FASYNC|FFSYNC|FNONBLOCK)

		int tmp;

		intp = _DEVCTL_DATA(msg->i);

		fp->f_flag &= ~STATUS_FLAGS;
		fp->f_flag |= (FFLAGS(*intp) & STATUS_FLAGS);
		tmp = fp->f_flag & O_NONBLOCK;
#undef STATUS_FLAGS 
		do {
			FILE_USE(fp);
			ret = fp->f_ops->fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, l);
			FILE_UNUSE(fp, p);
// #if 0
			/* Enable this if O_ASYNC is added */
			if (ret != EOK) 
				break;
			tmp = fp->f_flag & O_ASYNC;
			FILE_USE(fp);
			ret = fp->f_ops->fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, l);
			FILE_UNUSE(fp, p);
			if (ret == EOK) 
				break;
			fp->f_flag &= ~FNONBLOCK;
			tmp = 0;
			FILE_USE(fp);
			(void) fp->f_ops->fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, l);
			FILE_UNUSE(fp, p);
// #endif
		} while (0);
		break;
	}

	case DCMD_ALL_GETFLAGS:
		intp = _DEVCTL_DATA(msg->o);

		*intp = OFLAGS(fp->f_flag);
		/* Only space for one iov in ctp */
		ret = _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + sizeof(*intp));
		break;

	case DCMD_IP_SHUTDOWN:
	{
		struct sys_shutdown_args uap;
		int *how = _DEVCTL_DATA(msg->i);

		SCARG(&uap, s) = -1;
		SCARG(&uap, how) = *how;
		ret = sys_shutdown(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case DCMD_FSYS_STATVFS: {
		struct statvfs *vfs;
		int size;

		vfs = (struct statvfs *)(&msg->o + 1);
		size = (char *)(vfs + 1) - (char *)ctp->msg;

		if (size > ctp->msg_max_size) {
			ret = EMSGSIZE;
			break;
		}

		memset(vfs, 0x00, sizeof(*vfs));
		vfs->f_fsid = IOPKT_VERSION;
		strlcpy(vfs->f_basetype, IOPKT_STRING, sizeof vfs->f_basetype);

		/* Only space for one iov in ctp */
		ret = _RESMGR_PTR(ctp, &msg->o, size);
		break;
	}

	case DCMD_ALL_SETOWN:
		/*
		 * We pass in what they're requesting via _DEVCTL_DATA.
		 * This gets validated in the mix against p->p_ctxt.info.
		 * Other required fields also puled from p->p_ctxt.info.
		 */
		FILE_USE(fp);
	  	ret = fp->f_ops->fo_ioctl(fp, SIOCSPGRP, _DEVCTL_DATA(msg->i), l);
		FILE_UNUSE(fp, p);
		break;

	case DCMD_ALL_GETOWN:
		intp = _DEVCTL_DATA(msg->o);

		FILE_USE(fp);
	  	ret = fp->f_ops->fo_ioctl(fp, SIOCGPGRP, intp, l);
		FILE_UNUSE(fp, p);

		if (ret == EOK) {
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, &msg->o,
			    sizeof(msg->o) + sizeof(*intp));
		}
		break;

	case DCMD_IP_FDINFO:
	{
#ifdef OPT_PRU_SENSE_EXTEN
		char *dst;
		struct socket *so;
		struct proto_sensereq prs;

		if (fp->f_type != DTYPE_SOCKET) {
			ret = EOPNOTSUPP;
			break;
		}

		so = (struct socket *) fp->f_data;

		if ((so->so_proto->pr_flags & PR_SENSE_EXTEN) == 0) {
			ret = EOPNOTSUPP;
			break;
		}

		if ((replen = ctp->msg_max_size - ctp->offset - sizeof msg->o) <= 0) {
			ret = EMSGSIZE;
			break;
		}

		replen = min(replen, msg->i.nbytes);
		/* Replen is now pathmax */
		dst = (char *)(_DEVCTL_DATA(msg->i));
		dst[0] = '\0';

		prs.prs_how = PRSENSEREQ_STRING;
		prs.prs_maxlen = replen;

		/*
		 * A PRU_SENSE with NULL 4th and 5th params is the historical fstat()
		 * request.  Unfortunately, there's not much useful socket info that
		 * will map into a struct stat.  We're looking for per proto data
		 * which is context (per socket family / type / proto) sensitive so
		 * the proto will fill in dst accordingly.  It's up to the caller to
		 * interpret based on context.
		 */
		ret = so->so_proto->pr_usrreq(so, PRU_SENSE, (struct mbuf *)dst,
		    (struct mbuf *)&prs, NULL, l);

		if (ret == EOK) {
			replen = prs.prs_maxlen + sizeof(msg->o);
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, &msg->o, replen);
		}

		break;
#else
		ret = EOPNOTSUPP;
		break;
#endif
	}
	default: /* Assume it's an ioctl of some sort. */ {
		void	*dp, *lp;
		size_t	dsize, lsize, curtot;
		int	cmd;

		cmd = msg->i.dcmd;

		dp = _DEVCTL_DATA(msg->i);
		dsize = IOCPARM_LEN((unsigned)msg->i.dcmd);
		lp = NULL;

		if (msg->i.dcmd == SIOCGIFCONF || msg->i.dcmd == NOSIOCGIFCONF) {
			/* libc sets this to the whole thing */
			msg->i.nbytes = dsize;
		}

#ifdef NOTYET /* breaks certain wireless drivers that don't copy[in|out]() */
		if (msg->i.nbytes != dsize) {
			ret = EINVAL;
			break;
		}
#endif

		curtot = ctp->offset + sizeof msg->i + msg->i.nbytes;

		/*
		 * If the initial part is too big for the context
		 * and we haven't special cased it, fail.
		 */
		if (curtot > ctp->msg_max_size) {
		    	dp = ioctl_long_alloc(dp, msg->i.dcmd, &lsize);
		    	if (dp == NULL) {
				ret = EMSGSIZE;
				break;
			}
			if (lsize != dsize) {
				ioctl_long_free(dp);
				ret = EINVAL;
				break;
			}
			lp = dp;
		}

		if (cmd & IOC_IN) {
			/*
			 * Will be == ctp->info.srcmsglen for most but
			 * will be < ctp->info.srcmsglen for embedded ioctls
			 */
			if (curtot > ctp->info.srcmsglen) {
				ret = EINVAL;
				break;
			}
		}
		else if (cmd & IOC_OUT) {
			/* IOC_OUT only, not (IOC_IN | IOC_OUT) */

			/*
			 * Paranoia: this should all get filled in by the
			 * fo_ioctl callout below.
			 */
			memset(dp, 0x00, dsize);
		}

		FILE_USE(fp);
		ret = fp->f_ops->fo_ioctl(fp, cmd, dp, l);
		FILE_UNUSE(fp, p);

		if (ret == EOK) {
			if ((cmd & IOC_OUT) == 0) {
				replen = sizeof(msg->o);
			}
			else if (lp != NULL) {
				if ((ret = MsgWrite_r(p->p_ctxt.rcvid, lp,
				    lsize, sizeof(msg->i))) < 0) {
					ret = -ret;
				}
				else {
					ret = EOK;
					replen = sizeof(msg->o);
				}
			}
			else {
				/*
				 * check p_offset in case copyout()
				 * put some more data in our context.
				 */
				replen = max(p->p_offset,
				    sizeof(msg->o) + msg->i.nbytes);
				/*
				 * If copyout needed more than our
				 * context, it will have called
				 * MsgWrite() on the remainder.
				 */
				replen = min(replen, ctp->msg_max_size - ctp->offset);
			}
			msg->o.ret_val = 0;
			if (ret == EOK) {
				/* Only space for one iov in ctp */
				ret = _RESMGR_PTR(ctp, &msg->o, replen);
			}
		}

		if (lp != NULL)
			ioctl_long_free(lp);

		break;
	}
	}

	PROC_FINI(p);

	_RESMGR_STATUS(ctp, 0);

	return ret;
}

int
tcpip_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *ocb)
{
	int		ret;
	struct file	*fp;
	struct proc	*p;

	PROC_INIT(p, ctp, fp, ocb);
	
	/*
	 * Don't manipulate sctlp->recv_start et al since
	 * this doesn't block and therefore doesn't need
	 * to save state.
	 */

	if (fp->f_ops != NULL && fp->f_ops->fo_poll != NULL) {
		ret = (*fp->f_ops->fo_poll)(fp, 0, PR_TO_LWP(p));
	}
	else {
		ret = EOPNOTSUPP;
	}

	PROC_FINI(p);
	return ret;
}

int
tcpip_dup(resmgr_context_t *ctp, io_dup_t *msg, RESMGR_OCB_T *ocb)
{
	struct file *fp;
	
	/*
	 * This doesn't block so we don't need to manipulate
	 * sctlp->recv_start to save state.
	 */
	fp = ocb;

	fp->f_count++;
#ifdef OCB_LOCAL_CACHE
	fp_local_cache(&ctp->info, fp);
#endif

	return EOK; /* resmgr will re-bind the same ocb */
}

int
tcpip_fdinfo(resmgr_context_t *ctp, io_fdinfo_t *msg, RESMGR_OCB_T *ocb)
{
	struct file		*fp;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;
	int			len, pathmax, lim, ret;
	char			*path, *suffix;
	struct msg_open_info	*mop;
	unsigned		flags;
	
	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}

	flags = msg->i.flags;

	switch (fp->f_type) {
	case DTYPE_SOCKET:
		mop = fp->f_path_info;

		if ((pathmax = ctp->msg_max_size - ctp->offset - sizeof msg->o) < 0) {
			ret = EMSGSIZE;
			break;
		}
		pathmax = min(pathmax, msg->i.path_len);
		lim = pathmax;
		path = (char *)(&msg->o + 1);

		memset(&msg->o, 0x00, sizeof msg->o);
		msg->o.info.mode = mop->attr.mode;
		msg->o.info.ioflag = O_RDWR + 1;

		/* Check if the request comes from a remote machine. */
		if (ND_NODE_CMP(ctp->info.srcnd, ND_LOCAL_NODE)) {
			flags &= ~_FDINFO_FLAG_LOCALPATH;
		}

		if ((len = resmgr_pathname(ctp->id, flags, path, pathmax)) == -1) {
			ret = errno;
			break;
		}

		pathmax = min(len, pathmax);

		if (mop->domain == AF_LOCAL && pathmax >= sizeof("/dev/socket/1")) {
			suffix = path + pathmax - sizeof("/dev/socket/1");
			if (strcmp(suffix, "/dev/socket/1") == 0 &&
			    (len = uipc_path((struct socket *)fp->f_data, suffix, lim - (suffix - path))) != -1) {
				pathmax = suffix - path + len;
			}
		}

		path[lim - 1] = '\0';
		    
		_RESMGR_STATUS(ctp, pathmax);
		/* Only space for one iov in ctp */
		ret = _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + pathmax);
		break;

	default:
		/* Probably a kqueue. */
		ret = ENOSYS;
		break;
	}


	PROC_FINI(p);

	return ret;
}


int
tcpip_msg(resmgr_context_t *ctp, io_msg_t *msg, RESMGR_OCB_T *ocb)
{
	int			ret, retval, replen, nbytes;
	struct file		*fp;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;

	if (msg->i.mgrid != _IOMGR_TCPIP)
		return ENOSYS;

	PROC_INIT(p, ctp, fp, ocb);

	sctlp = &stk_ctl;

	if (p->p_mbuf == NULL) {
		p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
		p->p_mbuf->m_next = NULL;
		sctlp->recv_start++;
		sctlp->recv_avail--;
	}

	nbytes = 0;

	switch (msg->i.subtype) {
#ifdef QNXNTO_KQUEUE_notyet
	case _IO_SOCK_KEVENT:
	{
		struct sys_kevent_args uap;
		io_sock_kevent_t *kev_msg = (io_sock_kevent_t *)msg;

		SCARG(&uap, fd)         = -1;
		/*
		 * We always set this changelist pointer up
		 * regardless of nchanges so sys_kevent() knows
		 * where the workbuf is.  This shouldn't change.
		 */
		SCARG(&uap, changelist) = (struct kevent *)(&kev_msg->i + 1);
		SCARG(&uap, nchanges)   = kev_msg->i.nchange;
		SCARG(&uap, eventlist)  = (struct kevent *)(&kev_msg->i + 1);
		SCARG(&uap, nevents)    = kev_msg->i.nevent;
		if (kev_msg->i.timeout) {
			/* ts is valid */
			SCARG(&uap, timeout) = &kev_msg->i.ts;
		}
		else {
			SCARG(&uap, timeout) = NULL;
			/* ts is not valid */
		}
		if ((ret = sys_kevent(PR_TO_LWP(p), &uap, &retval)) == EOK) {
			/* Set up our reply */
			msg = (void *)SCARG(&uap, eventlist);
			if ((retval & KEVENT_COPIED_OUT) == 0) {
				nbytes = retval;
				/* Only space for one iov in ctp */
				ret = _RESMGR_PTR(ctp, msg,
				    retval * sizeof(struct kevent));
			}
			else {
				nbytes = retval & ~KEVENT_COPIED_OUT;
			}
		}
		break;
	}
#endif

	case _IO_SOCK_SOPT:
	case _IO_SOCK_SOPT2:
	{
		struct sys_setsockopt_args uap;

		if (msg->i.subtype == _IO_SOCK_SOPT2) {
			io_sock_sopt2_t *sopt_msg = (io_sock_sopt2_t *)msg;

			SCARG(&uap, s)       = -1;
			SCARG(&uap, level)   = sopt_msg->i.level;
			SCARG(&uap, name)    = sopt_msg->i.optname;
			SCARG(&uap, valsize) = sopt_msg->i.optlen;
			SCARG(&uap, val)     = sopt_msg->i.optlen ? (char *)&sopt_msg->i + sizeof sopt_msg->i : NULL;
		}
		else {
			io_sock_sopt_t *sopt_msg = (io_sock_sopt_t *)msg;

			SCARG(&uap, s)       = -1;
			SCARG(&uap, level)   = sopt_msg->i.level;
			SCARG(&uap, name)    = sopt_msg->i.optname;
			SCARG(&uap, valsize) = sopt_msg->i.optlen;
			SCARG(&uap, val)     = sopt_msg->i.optlen ? (char *)&sopt_msg->i + sizeof sopt_msg->i : NULL;
		}
		ret = sys_setsockopt(PR_TO_LWP(p), &uap, &retval);
		break;
	}

	case _IO_SOCK_GOPT:
	case _IO_SOCK_GOPT2:
	{
		struct sys_getsockopt_args uap;

		if (msg->i.subtype == _IO_SOCK_GOPT2) {
			io_sock_gopt2_t *gopt_msg = (io_sock_gopt2_t *)msg;

			SCARG(&uap, s)     = -1;
			SCARG(&uap, level) = gopt_msg->i.level;
			SCARG(&uap, name)  = gopt_msg->i.optname;

			replen = gopt_msg->i.optlen;

#if 0
/* Not worth the approx extra 20 bytes? */
			if (gopt_msg->i.optname & GETSOCKOPT_EXTRA)
#endif
			/* In case GETSOCKOPT_EXTRA is set and it also reads from here */
			msg = (io_msg_t *)(gopt_msg + 1);

			replen = min(replen, ctp->msg_max_size - ((char *)msg - (char *)ctp->msg));

			SCARG(&uap, val)   = msg;
		}
		else {
			io_sock_gopt_t *gopt_msg = (io_sock_gopt_t *)msg;

			SCARG(&uap, s)     = -1;
			SCARG(&uap, level) = gopt_msg->i.level;
			SCARG(&uap, name)  = gopt_msg->i.optname;
			SCARG(&uap, val)   = gopt_msg;
			replen = 1024;
		}
		SCARG(&uap, avalsize) = &replen;
		if ((ret = sys_getsockopt(PR_TO_LWP(p), &uap, &retval)) == EOK) {
			nbytes = replen;
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, msg, replen);
		}
		break;
	}

	case _IO_SOCK_NLIST:
	{
		io_sock_nlist_t *nlist_msg = (io_sock_nlist_t *)msg;

		int num;

		/*
		 * Current implementation doesn't pass in number and we can't
		 * rely on info.srcmsglen because we haven't set _NTO_CHF_SENDER_LEN.
		 * This means if it doesn't fit in the context, we never MsgRead()
		 * in the rest.
		 */

		/*
		 * Recall, the first iov in the receive context is continuous
		 * for msg_max_size: the whole thing can be larger across many iovs.
		 */
		num = (min(ctp->info.msglen, ctp->msg_max_size) - sizeof nlist_msg->i) / sizeof(struct nlist_old);

		ret = nlist_old((struct nlist_old *)((char *)nlist_msg + sizeof nlist_msg->i), num);
		if (ret == EOK) {
			replen = ctp->info.msglen - sizeof nlist_msg->i;
			msg = (io_msg_t *)((char *)msg + sizeof nlist_msg->i);
			nbytes = 0;
			/* Only space for one iov in ctp */
			ret = _RESMGR_PTR(ctp, msg, replen);
		}
		break;
	}

	case _IO_SOCK_SYSCTL:
	case _IO_SOCK_SYSCTL2:
	{
		struct sys___sysctl_args a;
		int *name;
		unsigned oldlen, namelen, newlen;

		if (msg->i.subtype == _IO_SOCK_SYSCTL) {
			io_sock_sysctl_t  *sysctl_msg = (io_sock_sysctl_t *)msg;

			oldlen  = sysctl_msg->i.oldlen;
			newlen  = sysctl_msg->i.newlen;
			namelen = sysctl_msg->i.namelen;
			name     = (int *)(&sysctl_msg->i + 1);
		}
		else {
			io_sock_sysctl2_t  *sysctl_msg = (io_sock_sysctl2_t *)msg;

			oldlen  = sysctl_msg->i.oldlen;
			newlen  = sysctl_msg->i.newlen;
			namelen = sysctl_msg->i.namelen;
			name     = (int *)(&sysctl_msg->i + 1);

		}

		SCARG(&a, oldlenp) = &oldlen;
		/*
		 * Can't copyout() over our receive context
		 * then copyin() from it.
		 */
		p->p_vmspace.vm_flags |= VM_OUTFORCE;
		SCARG(&a, old) = oldlen ? msg : NULL;

		SCARG(&a, name)    = name;
		SCARG(&a, namelen) = namelen;


		SCARG(&a, new)     = newlen ? name + namelen : NULL;
		SCARG(&a, newlen)  = newlen;

		if ((ret = sys___sysctl(PR_TO_LWP(p), &a, 0)) != EOK) {
			break;
		}

		nbytes = oldlen;
		break;
	}

	default:
		ret = ENOSYS;
		break;
	}

	PROC_FINI(p);

	/* Following ignored by resmgr layer if ret != EOK */
	_RESMGR_STATUS(ctp, nbytes);

	return ret;
}

int
tcpip_unblock(resmgr_context_t *ctp, io_pulse_t *msg, RESMGR_OCB_T *ocb)
{
	struct file *fp;

	fp = ocb;

	/*
	 * This one currently is not started at proc.c:startproc().
	 * It doesn't sleep so doesn't need a full PROC_INIT().
	 *
	 * Also, don't manipulate sctlp->recv_mbuf et al since may be
	 * called as result of low res pulse.
	 */

	unblock(&stk_ctl, fp, ctp->rcvid, EINTR);

	return _RESMGR_NOREPLY;		
}

int
tcpip_lseek(resmgr_context_t *ctp, io_lseek_t *msg, RESMGR_OCB_T *ocb)
{
	return ESPIPE;
}

int
nto_bindit(resmgr_context_t *ctp, void *ocb)
{
	if (resmgr_open_bind(ctp, ocb, &nw_io_funcs) == -1)
		return errno;

	return EOK;
}

int
nto_unbind(struct _resmgr_context *ctp)
{
	if (_resmgr_unbind(&ctp->info) == -1)
		return errno;

	return EOK;
}


static int
lsm_mount(resmgr_context_t *ctp, io_mount_t *msg, RESMGR_HANDLE_T *handle, io_mount_extra_t *extra)
{
	struct _client_info	*cinfo;
	int			ret;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;

	p = PROC_FROM_CTP(ctp);
	sctlp = &stk_ctl;

	/* First check if it is ours. If not move on. */

	if (
#ifdef IONET_COMPAT
	    (strcmp(extra->extra.srv.type, ionet_instance) != 0) &&
#endif
	    (strcmp(extra->extra.srv.type, iopkt_instance) != 0) &&
	    (strcmp(extra->extra.srv.type, "tcpip") != 0)) {
		return ENOENT;
	}

	if (p->p_mbuf != NULL) {
		 /*
		  * Connect msg that's not the first part of a combine.
		  * Someone must be trying to purposefully break things.
		  */
		return EINVAL;
	}

	/*
	 * We may block as nw_dlopen() is a blockop so
	 * save our stack context.
	 */
	p->p_mbuf = sctlp->recv_mbuf[sctlp->recv_start];
	p->p_mbuf->m_next = NULL;
	sctlp->recv_start++;
	sctlp->recv_avail--;

	/* Don't support _MOUNT_UNMOUNT or anything else */
	if ((extra->flags & _MFLAG_OCB) == 0)
		return ENOSYS;

	/* 0 for flags (last param) as we're not interested in groups here */
	if ((ret = iofunc_client_info_ext(ctp, 0, &cinfo, 0)) != 0)
		return ret;

	/* only root allow to mount */
	if (cinfo->cred.euid != 0) {
		iofunc_client_info_ext_free(&cinfo);
		return EACCES;
	}
	iofunc_client_info_ext_free(&cinfo);

	ret = EOK;

	if ((extra->flags & _MOUNT_UNMOUNT) != 0) {
		ret = ENOSYS;
	}

	p->p_flags |= P_RESMGR_KEY;
	ret = nw_dlload_module(0, extra->extra.srv.special,
	    extra->extra.srv.data, p);
	p->p_flags &= ~P_RESMGR_KEY;

	return ret;
}

resmgr_connect_funcs_t mount_cfuncs=
{
	8,
	0,   /* open */
	0,   /* unlink */
	0,   /* rename */
	0,   /* mknod */
	0,   /* readlink */
	0,   /* link */
	0,   /* unblock */
	lsm_mount
};

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/msg.c $ $Rev: 902838 $")
#endif
