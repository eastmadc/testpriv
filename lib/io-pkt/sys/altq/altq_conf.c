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

/*	$NetBSD: altq_conf.c,v 1.18 2006/10/20 21:55:56 elad Exp $	*/
/*	$KAME: altq_conf.c,v 1.24 2005/04/13 03:44:24 suz Exp $	*/

/*
 * Copyright (C) 1997-2003
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: altq_conf.c,v 1.18 2006/10/20 21:55:56 elad Exp $");

#ifdef _KERNEL_OPT
#ifdef __QNXNTO__
#include "opt_altq_enabled.h"
#endif
#include "opt_altq.h"
#include "opt_inet.h"
#endif

/*
 * altq device interface.
 */
#include <sys/param.h>
#ifdef __QNXNTO__
#include <sys/malloc.h>
#include <sys/netmgr.h>
#endif
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kauth.h>

#include <net/if.h>

#ifdef __QNXNTO__
#include <sys/iofunc.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <stdlib.h>
#include <fcntl.h>
#include <devctl.h>
#include <string.h>
#include <dirent.h>
#endif

#include <altq/altq.h>
#include <altq/altqconf.h>
#include <altq/altq_conf.h>

#ifdef ALTQ3_COMPAT

#ifdef ALTQ_CBQ
altqdev_decl(cbq);
#endif
#ifdef ALTQ_WFQ
altqdev_decl(wfq);
#endif
#ifdef ALTQ_AFMAP
altqdev_decl(afm);
#endif
#ifdef ALTQ_FIFOQ
altqdev_decl(fifoq);
#endif
#ifdef ALTQ_RED
altqdev_decl(red);
#endif
#ifdef ALTQ_RIO
altqdev_decl(rio);
#endif
#ifdef ALTQ_LOCALQ
altqdev_decl(localq);
#endif
#ifdef ALTQ_HFSC
altqdev_decl(hfsc);
#endif
#ifdef ALTQ_CDNR
altqdev_decl(cdnr);
#endif
#ifdef ALTQ_BLUE
altqdev_decl(blue);
#endif
#ifdef ALTQ_PRIQ
altqdev_decl(priq);
#endif
#ifdef ALTQ_JOBS
altqdev_decl(jobs);
#endif

#if defined(__QNXNTO__)
#define enodev NULL
#ifdef nopoll
#undef nopoll
#endif
#define nopoll NULL
dev_type_open(altqopen);
dev_type_close(altqclose);
dev_type_ioctl(altqioctl);
#endif
/*
 * altq minor device (discipline) table
 */
static struct altqsw altqsw[] = {				/* minor */
#ifndef __QNXNTO__
	{"altq", noopen,	noclose,	noioctl},  /* 0 (reserved) */
#else
	{"altq",	altqopen,		altqclose,	altqioctl},  /* 0 (reserved) */
#endif
#ifdef ALTQ_CBQ
	{"cbq",	cbqopen,	cbqclose,	cbqioctl},	/* 1 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 1 */
#endif
#ifdef ALTQ_WFQ
	{"wfq",	wfqopen,	wfqclose,	wfqioctl},	/* 2 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 2 */
#endif
#ifdef ALTQ_AFMAP
	{"afm",	afmopen,	afmclose,	afmioctl},	/* 3 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 3 */
#endif
#ifdef ALTQ_FIFOQ
	{"fifoq", fifoqopen,	fifoqclose,	fifoqioctl},	/* 4 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 4 */
#endif
#ifdef ALTQ_RED
	{"red", redopen,	redclose,	redioctl},	/* 5 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 5 */
#endif
#ifdef ALTQ_RIO
	{"rio", rioopen,	rioclose,	rioioctl},	/* 6 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 6 */
#endif
#ifdef ALTQ_LOCALQ
	{"localq",localqopen,	localqclose,	localqioctl}, /* 7 (local use) */
#else
	{"noq",	noopen,		noclose,	noioctl},  /* 7 (local use) */
#endif
#ifdef ALTQ_HFSC
	{"hfsc",hfscopen,	hfscclose,	hfscioctl},	/* 8 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 8 */
#endif
#ifdef ALTQ_CDNR
	{"cdnr",cdnropen,	cdnrclose,	cdnrioctl},	/* 9 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 9 */
#endif
#ifdef ALTQ_BLUE
	{"blue",blueopen,	blueclose,	blueioctl},	/* 10 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 10 */
#endif
#ifdef ALTQ_PRIQ
	{"priq",priqopen,	priqclose,	priqioctl},	/* 11 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 11 */
#endif
#ifdef ALTQ_JOBS
	{"jobs",jobsopen,	jobsclose,	jobsioctl},	/* 12 */
#else
	{"noq", noopen,		noclose,	noioctl},	/* 12 */
#endif
};

/*
 * altq major device support
 */
int	naltqsw = sizeof (altqsw) / sizeof (altqsw[0]);

dev_type_open(altqopen);
dev_type_close(altqclose);
dev_type_ioctl(altqioctl);

#ifdef __QNXNTO__
static void altq_drvinit (void);
#endif

const struct cdevsw altq_cdevsw = {
	altqopen, altqclose, noread, nowrite, altqioctl,
	nostop, notty, nopoll, nommap, nokqfilter, D_OTHER,
};

#ifdef __QNXNTO__

#ifndef ROUNDUP
#define ROUNDUP(x,y)	((((x)+(y)-1)/(y))*(y))
#endif

pthread_once_t	altq_control = PTHREAD_ONCE_INIT;
iofunc_attr_t	*parent_attr = NULL;
static struct proc p;

int altq_copyin(const void *src, void *dst, size_t len);

int
altq_copyout(const void *src, void *dst, size_t len)
{
	char buf[100], *bptr;
	int err;
        int fd;

        if (ND_NODE_CMP(curproc->p_ctxt.info.nd, ND_LOCAL_NODE) == 0)
		err = 0;
	else
		err = netmgr_ndtostr(ND2S_DIR_SHOW, curproc->p_ctxt.info.nd, buf, sizeof(buf));

	if (err == -1)
		return errno;

        strncpy(buf + err, "/proc", sizeof(buf) - err);
	bptr = buf + strlen(buf);
	*bptr++ = '/';
        itoa(curproc->p_ctxt.info.pid, bptr, 10);
	bptr = buf + strlen(buf);
	strcat(buf, "/as");

	if ((fd = open(buf, O_RDWR))== -1) {
		return -1;
	}

	if (lseek(fd, (off_t)dst, SEEK_SET) == -1 || write(fd, src, len) == -1)
	{
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int
altq_copyin(const void *src, void *dst, size_t len)
{
	char buf[100], *bptr;
	int err;
        int fd;

        if (ND_NODE_CMP(curproc->p_ctxt.info.nd, ND_LOCAL_NODE) == 0)
		err = 0;
	else
		err = netmgr_ndtostr(ND2S_DIR_SHOW, curproc->p_ctxt.info.nd, buf, sizeof(buf));

	if (err == -1)
		return errno;

        strncpy(buf + err, "/proc", sizeof(buf) - err);
	bptr = buf + strlen(buf);
	*bptr++ = '/';
        itoa(curproc->p_ctxt.info.pid, bptr, 10);
	bptr = buf + strlen(buf);
	strcat(buf, "/as");

	if ((fd = open(buf, O_RDONLY))== -1)
		return -1;

	if (lseek(fd, (off_t)src, SEEK_SET) == -1 || read(fd, dst, len) == -1)
	{
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int
altq_io_open (resmgr_context_t *ctp, io_open_t *msg, RESMGR_HANDLE_T *handle, void *extra)
{
	int 		i, error = EOK;
	iofunc_attr_t 	*attr;
	
	parent_attr = handle;
	pthread_once(&altq_control, altq_drvinit);
	
	attr = NULL;
	i = -1;
	if (! msg->connect.path[0] )
	{
		attr = (iofunc_attr_t *)handle;
	} else
	{
		for (i = 0; i < naltqsw; i++ )
			if (!strcmp( msg->connect.path, altqsw[i].d_name ))
			{
				attr = &altqsw[i].attr;
				if (altqsw[i].d_open == noopen)
					return ENOTSUP;
				if (altqsw[i].nopens == 0) {
					error =	altqsw[i].d_open(0, 0, 0, PR_TO_LWP(&p));
					if (error) return error;
				}
				break;
			}
	}
	if (attr != NULL)
	{
		attr->inode = i;
		error = iofunc_open_default(ctp, msg, attr, extra );
		if (error == EOK && i != -1)
			altqsw[i].nopens++;
		else if ( error != EOK && i != -1) 
			altqsw[i].d_close(0, 0, 0, PR_TO_LWP(&p));
		return error;
	}
	else
	{	
		return ENOENT;
	}
}


static int
altq_io_read (resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb_t)
{
	iofunc_ocb_t 	*ocb;
	int             sts;

	ocb = ocb_t;

	if ( (sts = iofunc_read_verify(ctp, msg, ocb, NULL)) != EOK ) {
		printf( "ird: %d %s\n", sts, strerror( errno ) );
		return sts;
	}
	if ( (msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE )
		return (ENOSYS); /* no special xtypes supported */

	if ( S_ISDIR(ocb->attr->mode) ) {
		/* multiple dirents */
		struct dirent *d;
		int dsize, flen;
		void *buf;
		int nbytes = 0;

		if (ocb->offset == naltqsw )
		{
			MsgReply( ctp->rcvid, 0, NULL, 0 );
			return _RESMGR_NOREPLY;
		}
		if (ocb->offset > naltqsw )
		{
			return EINVAL;
		}
		MALLOC(buf, void *, msg->i.nbytes, M_TEMP, M_WAITOK);
		if(!buf )
			return ENOMEM;
		d = buf;
		while( ocb->offset < naltqsw  )
		{
			if ( altqsw[ocb->offset].d_open == noopen) {
				ocb->offset++;
				continue;
			}
			flen = strlen( altqsw[ocb->offset].d_name );
			dsize = ROUNDUP( 4, (sizeof(*d) + flen +1 -4 ));
			if ( nbytes + dsize > msg->i.nbytes )
			{
				/* out of space in read buffer */
				MsgReply( ctp->rcvid, nbytes, buf, nbytes );
				FREE(buf, M_TEMP);
				ocb->attr->flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
				return _RESMGR_NOREPLY;
			}
			d->d_ino = altqsw[ocb->offset].attr.inode;
			d->d_offset = ocb->offset;
			d->d_reclen = dsize;
			d->d_namelen = flen;
			strcpy( d->d_name, altqsw[ocb->offset].d_name );
			d = (struct dirent *)((char *)d + dsize);
			ocb->offset++;
			nbytes += dsize;  
		}
		MsgReply( ctp->rcvid, nbytes, buf, nbytes );
		FREE(buf, M_TEMP);
	} else {
		return ENOSYS;
	}
	if ( msg->i.nbytes > 0 )
		ocb->attr->flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;

	return( _RESMGR_NOREPLY );
}

static int
altq_io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, iofunc_ocb_t *ocb) 
{
	int status, nbytes, index;
	void *dptr;

	/* Let common code handle DCMD_ALL_* cases. */
	if ((status = iofunc_devctl_default(ctp, msg, ocb)) != _RESMGR_DEFAULT) {
		return(status);
	}

	index = ocb->attr->inode;
	if (index >= naltqsw)
		return ENOENT;

	status = nbytes = 0;
	dptr = _DEVCTL_DATA(msg->i);

	status = altqsw[index].d_ioctl(0, msg->i.dcmd, dptr, 0, curlwp);

	if (status == EOK) {
		if (msg->i.dcmd & IOC_OUT) {
			nbytes = IOCPARM_LEN(msg->i.dcmd);
		}
	}
	/* Clear return message */
	memset(&msg->o, 0, sizeof(msg->o));
	msg->o.ret_val = status;
	msg->o.nbytes = nbytes;

	return(_RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + nbytes));
}


static int
altq_io_close(resmgr_context_t *ctp, void *reserved, iofunc_ocb_t *ocb)
{
	int index;

//	iofunc_attr_t   *dattr = ((iofunc_ocb_t)ocb)->attr;

	index = ocb->attr->inode;
	if (index >= naltqsw)
		return ENOENT;

	if (altqsw[index].nopens == 1) {
		altqsw[index].d_close(0, 0, 0, PR_TO_LWP(&p));
	}

	if (altqsw[index].nopens > 0)
		altqsw[index].nopens--;

	return (iofunc_close_ocb_default(ctp, reserved, ocb));
}


resmgr_connect_funcs_t altq_cfuncs=
{
	8,
	altq_io_open,   /* open */
	0,   		/* unlink */
	0,   		/* rename */
	0,   		/* mknod */
	0,   		/* readlink */
	0,   		/* link */
	0,   		/* unblock */
	0,   		/* mount */
};

resmgr_io_funcs_t altq_iofuncs = {
	26,
	altq_io_read,
	NULL,                             /* write      */
	(void *)altq_io_close,
	(void *)iofunc_stat_default,
	NULL,                             /* notify     */
	(void *)altq_io_devctl,
	(void *)iofunc_unblock_default,
	(void *)iofunc_pathconf_default,
	(void *)iofunc_lseek_default,
	(void *)iofunc_chmod_default,
	(void *)iofunc_chown_default,
	(void *)iofunc_utime_default,
	(void *)iofunc_openfd_default,
	(void *)iofunc_fdinfo_default,
	(void *)iofunc_lock_default,
	NULL,                             /* space      */
	NULL,                             /* shutdown   */
	NULL,                             /* mmap       */
	NULL,                             /* msg        */
	NULL,                             /* reserved   */
	NULL,                             /* dup        */
	NULL,                             /* close_dup  */
	NULL,                             /* lock_ocb   */
	NULL,                             /* unlock_ocb */
	NULL,                             /* sync       */
	NULL                              /* power      */
};
#endif

int
altqopen(dev_t dev, int flag, int fmt, struct lwp *l)
{
	int unit = minor(dev);

	if (unit == 0)
		return (0);
	if (unit < naltqsw)
		return (*altqsw[unit].d_open)(dev, flag, fmt, l);

	return ENXIO;
}

int
altqclose(dev_t dev, int flag, int fmt, struct lwp *l)
{
	int unit = minor(dev);

	if (unit == 0)
		return (0);
	if (unit < naltqsw)
		return (*altqsw[unit].d_close)(dev, flag, fmt, l);

	return ENXIO;
}

int
altqioctl(dev_t dev, ioctlcmd_t cmd, caddr_t addr, int flag, struct lwp *l)
{
	int unit = minor(dev);

	if (unit == 0) {
		struct ifnet *ifp;
		struct altqreq *typereq;
		struct tbrreq *tbrreq;
		int error;

		switch (cmd) {
		case ALTQGTYPE:
		case ALTQTBRGET:
			break;
		default:
#if (__FreeBSD_version > 400000)
			if ((error = suser(p)) != 0)
				return (error);
#else
			if ((error = kauth_authorize_network(l->l_cred,
			    KAUTH_NETWORK_ALTQ, KAUTH_REQ_NETWORK_ALTQ_CONF,
			    NULL, NULL, NULL)) != 0)
				return (error);
#endif
			break;
		}

		switch (cmd) {
		case ALTQGTYPE:
			typereq = (struct altqreq *)addr;
#ifndef QNX_MFIB
			if ((ifp = ifunit(typereq->ifname)) == NULL)
#else
			if ((ifp = ifunit(typereq->ifname, ANY_FIB)) == NULL)
#endif
				return (EINVAL);
			typereq->arg = (u_long)ifp->if_snd.altq_type;
			return (0);
		case ALTQTBRSET:
			tbrreq = (struct tbrreq *)addr;
#ifndef QNX_MFIB
			if ((ifp = ifunit(tbrreq->ifname)) == NULL)
#else
			if ((ifp = ifunit(tbrreq->ifname, ANY_FIB)) == NULL)
#endif
				return (EINVAL);
			return tbr_set(&ifp->if_snd, &tbrreq->tb_prof);
		case ALTQTBRGET:
			tbrreq = (struct tbrreq *)addr;
#ifndef QNX_MFIB
			if ((ifp = ifunit(tbrreq->ifname)) == NULL)
#else
			if ((ifp = ifunit(tbrreq->ifname, ANY_FIB)) == NULL)
#endif
				return (EINVAL);
			return tbr_get(&ifp->if_snd, &tbrreq->tb_prof);
		default:
			return (EINVAL);
		}
	}
	if (unit < naltqsw)
		return (*altqsw[unit].d_ioctl)(dev, cmd, addr, flag, l);

	return ENXIO;
}

#ifdef __FreeBSD__
static int altq_devsw_installed = 0;
#endif

#ifdef __FreeBSD__
static void
altq_drvinit(void *unused)
{
	int unit;

#if 0
	mtx_init(&altq_mtx, "altq global lock", MTX_DEF);
#endif
	altq_devsw_installed = 1;
	printf("altq: attached. Major number assigned automatically.\n");

	/* create minor devices */
	for (unit = 0; unit < naltqsw; unit++) {
		if (unit == 0 || altqsw[unit].d_open != NULL)
			altqsw[unit].dev = make_dev(&altq_cdevsw, unit,
			    UID_ROOT, GID_WHEEL, 0644, "altq/%s",
			    altqsw[unit].d_name);
	}
}

SYSINIT(altqdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,altq_drvinit,NULL)

#endif /* FreeBSD */

#ifdef __QNXNTO__
static void altq_drvinit (void)
{
	int i;

	for (i = 0; i < naltqsw; i++ ) {
		iofunc_attr_init (&altqsw[i].attr, S_IFCHR | 0444, parent_attr, NULL);
	}
}
#endif /* __QNXNTO__ */

#ifdef ALTQ_KLD
/*
 * KLD support
 */
static int altq_module_register(struct altq_module_data *);
static int altq_module_deregister(struct altq_module_data *);

static struct altq_module_data *altq_modules[ALTQT_MAX];
#if __FreeBSD_version < 502103
static struct altqsw noqdisc = {"noq", noopen, noclose, noioctl};
#else
static struct altqsw noqdisc = {"noq"};
#endif

void altq_module_incref(int type)
{
	if (type < 0 || type >= ALTQT_MAX || altq_modules[type] == NULL)
		return;

	altq_modules[type]->ref++;
}

void altq_module_declref(int type)
{
	if (type < 0 || type >= ALTQT_MAX || altq_modules[type] == NULL)
		return;

	altq_modules[type]->ref--;
}

static int
altq_module_register(struct altq_module_data *mdata)
{
	int type = mdata->type;

	if (type < 0 || type >= ALTQT_MAX)
		return (EINVAL);
#if (__FreeBSD_version < 502103)
	if (altqsw[type].d_open != noopen)
#else
	if (altqsw[type].d_open != NULL)
#endif
		return (EBUSY);
	altqsw[type] = *mdata->altqsw;	/* set discipline functions */
	altq_modules[type] = mdata;	/* save module data pointer */
#if (__FreeBSD_version < 502103)
	make_dev(&altq_cdevsw, type, UID_ROOT, GID_WHEEL, 0644,
		 "altq/%s", altqsw[type].d_name);
#else
	altqsw[type].dev = make_dev(&altq_cdevsw, type, UID_ROOT, GID_WHEEL,
	    0644, "altq/%s", altqsw[type].d_name);
#endif
	return (0);
}

static int
altq_module_deregister(struct altq_module_data *mdata)
{
	int type = mdata->type;

	if (type < 0 || type >= ALTQT_MAX)
		return (EINVAL);
	if (mdata != altq_modules[type])
		return (EINVAL);
	if (altq_modules[type]->ref > 0)
		return (EBUSY);
#if (__FreeBSD_version < 502103)
	destroy_dev(makedev(CDEV_MAJOR, type));
#else
	destroy_dev(altqsw[type].dev);
#endif
	altqsw[type] = noqdisc;
	altq_modules[type] = NULL;
	return (0);
}

int
altq_module_handler(module_t mod, int cmd, void *arg)
{
	struct altq_module_data *data = (struct altq_module_data *)arg;
	int	error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = altq_module_register(data);
		break;

	case MOD_UNLOAD:
		error = altq_module_deregister(data);
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

#endif  /* ALTQ_KLD */
#endif /* ALTQ3_COMPAT */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/altq/altq_conf.c $ $Rev: 822252 $")
#endif
