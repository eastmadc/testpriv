#ifndef _IF_SRT_H_1b91f8f1_
#define _IF_SRT_H_1b91f8f1_

/* $NetBSD: if_srt.h,v 1.3 2009/12/09 00:44:26 dyoung Exp $ */

/* This file is in the public domain. */

#include <net/if.h> /* XXX for IFNAMSIZ */
#include <netinet/in.h> /* for in_addr/in6_addr */

struct srt_rt {
	unsigned int inx;
	int af;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} srcmatch;
	unsigned int srcmask;
	union {
		struct ifnet *dstifp;
		char dstifn[IFNAMSIZ];
	} u;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr sa;
	} dst;
};

/* Gets the number of slots in the rts array */
#define SRT_GETNRT _IOR('e',0,unsigned int)

/* Gets an rt entry, given the slot number in the inx field */
#define SRT_GETRT  _IOWR('e',1,struct srt_rt)

/* Sets an rt entry; inx must be either in the array or one past it */
#define SRT_SETRT  _IOW('e',2,struct srt_rt)

/* Delete an rt entry by index; shifts the rest down */
#define SRT_DELRT  _IOW('e',3,unsigned int)

/* Set flag bits */
#define SRT_SFLAGS _IOW('e',4,unsigned int)

/* Get flag bits */
#define SRT_GFLAGS _IOR('e',5,unsigned int)

/* Atomically replace flag bits */
#define SRT_SGFLAGS _IOWR('e',6,unsigned int)

/* Do debugging tasks (not documented here - see the source) */
#define SRT_DEBUG _IOW('e',7,void *)

/* Flag bits for SRT_*FLAGS */
#define SSF_MTULOCK 0x00000001 /* don't auto-update MTU */
/* Some flags are global; some are per-unit. */
#define SSF_GLOBAL (0)

#ifdef __QNXNTO__
int      srt_open(struct lwp *, struct msg_open_info *, struct file **);
#endif

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/net/if_srt.h $ $Rev: 680336 $")
#endif
