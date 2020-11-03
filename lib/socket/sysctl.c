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



#include "namespace.h"
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/sockmsg.h>
#include <sys/socket.h>

#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>

#include <stdlib.h>

#ifdef __weak_alias
__weak_alias(sysctl,_sysctl)
__weak_alias(sysctlfd,_sysctlfd)
#endif

#define SKIP_SET_FIB -1
int
sysctl_fib(const int *name, unsigned namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen, int socksetfib)
{
	return sysctlfd_fib(name, namelen, oldp, oldlenp, newp, newlen, -1, socksetfib);
}

int
sysctl(const int *name, unsigned namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	return sysctlfd_fib(name, namelen, oldp, oldlenp, newp, newlen, -1, SKIP_SET_FIB);

}

int
sysctlfd(const int *name, unsigned namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen, int fd_seed)
{
	return sysctlfd_fib(name, namelen, oldp, oldlenp, newp, newlen, fd_seed, -1);
}

int
sysctlfd_fib(const int *name, unsigned namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen, int fd_seed, int socksetfib)
{
	union {
		io_sock_sysctl_t  a;
		io_sock_sysctl2_t b;
	} sys;
	io_sock_sysctl2_t *sysp;
	iov_t siov[3], riov[1];
	int fd, ret;

	if (name[0] == CTL_USER) {
		if (newp != NULL) {
			errno = EPERM;
			return (-1);
		}
		if (namelen != 2) {
			errno = EINVAL;
			return (-1);
		}
		errno = EINVAL;
		return (-1);
	}

	/*
	 * To query the amount of data required to store the to be
	 * requested information, oldp should be NULL. The stack does
	 * the query operation if oldlenp is 0. Since this many not
	 * be initialized in the program lets do it here.
	 */	

	if ((oldp == NULL) && oldlenp)
		*oldlenp = 0;	

	if ((fd = fd_seed) < 0 && (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;

	if (socksetfib != -1) {
		int err = errno;
		setsockopt(fd, SOL_SOCKET, SO_SETFIB, (void *) &socksetfib, sizeof(socksetfib));
		errno = err;
	}

	sysp = &sys.b;

	sysp->i.msg.type        = _IO_MSG;
	sysp->i.msg.combine_len = sizeof *sysp + namelen * sizeof (int);
	sysp->i.msg.mgrid       = _IOMGR_TCPIP;
	sysp->i.msg.subtype     = _IO_SOCK_SYSCTL2;

	sysp->i.namelen = namelen;
	sysp->i.oldlen  = oldlenp ? *oldlenp: 0;
	sysp->i.newlen  = newlen;

	SETIOV(siov, &sysp->i, sizeof sysp->i);
	SETIOV(siov+1, (void *)name, namelen * sizeof(*name));
	SETIOV(siov+2, (void *)newp, newlen);

	SETIOV(riov, oldp, sysp->i.oldlen);

	if ((ret = MsgSendv(fd, siov, 3, riov, oldp ? 1 : 0)) == -1 &&
	    errno == ENOSYS) {
		/* Try falling back on old one */
		io_sock_sysctl_t *sysp;

		sysp = &sys.a;

		sysp->i.msg.subtype = _IO_SOCK_SYSCTL;

		sysp->i.namelen = namelen;
		sysp->i.oldlen  = oldlenp ? *oldlenp: 0;
		sysp->i.newlen  = newlen;

		SETIOV(siov, &sysp->i, sizeof sysp->i);

		ret = MsgSendv(fd, siov, 3, riov, oldp ? 1 : 0);
	}

	if (fd_seed < 0)
		close(fd);

	if (ret == -1)
		return -1;

	if (oldlenp)
		*oldlenp = ret;

	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/sysctl.c $ $Rev: 729877 $")
#endif
