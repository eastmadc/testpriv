/*
 * $QNXLicenseC:
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




#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dcmd_ip.h>
#include <sys/netmgr.h>
#include <sys/sockmsg.h>
#include <unistd.h>

int
listen (int s, int backlog)
{
	return _devctl(s, DCMD_IP_LISTEN, &backlog, sizeof backlog, _DEVCTL_FLAG_NORETVAL);
}

int
accept (int s, struct sockaddr *addr, socklen_t *addrlen)
{
	/* This is basically _sopenfd specifying a return buffer for dst address */
	int                  fd2, fd3;
	int                  ret;
	union {
		io_openfd_t		open;
		io_dup_t		dup;
	} msg;
	struct _server_info  info;

	if(s == -1 || ConnectServerInfo(0, s, &info) != s) {
		errno = EBADF;
		return -1;
	}

	/*
	 * MsgSend() will block until the connection comes in and the the resmgr functions are not bound
	 * until after it does. Do this blocking call on a side channel initially so it doesn't get
	 * dup()'d in a fork() / posix_spawn() etc. Any attempt to dup() an fd will EBADF until the resmgr
	 * binding is setup.
	 */
	if((fd2 = ConnectAttach(info.nd, info.pid, info.chid, _NTO_SIDE_CHANNEL, _NTO_COF_CLOEXEC)) == -1) {
		return -1;
	}

	memset(&msg.open.i, 0x00, sizeof msg.open.i);
	msg.open.i.type = _IO_OPENFD;
	msg.open.i.combine_len = sizeof msg.open.i;
	msg.open.i.ioflag = 0;
	msg.open.i.sflag = 0;
	msg.open.i.xtype = _IO_OPENFD_ACCEPT;
	msg.open.i.info.nd = netmgr_remote_nd(info.nd, ND_LOCAL_NODE);
	msg.open.i.info.pid = getpid();
	msg.open.i.info.chid = info.chid;
	msg.open.i.info.scoid = info.scoid;
	msg.open.i.info.coid = s;

	if((ret = MsgSend(fd2, &msg.open.i, sizeof msg.open.i, addr, addr && addrlen ? *addrlen : 0)) == -1) {
		if(errno == EFAULT) {
			/* Error was on our side (supplied a bad buffer). */
			close (fd2);
		}
		else {
			if(errno == ENOSYS)
				errno = ENOTSOCK;
			ConnectDetach(fd2);
		}
		return -1;
	}

	if (addr && addrlen)
		*addrlen = min (ret, *addrlen);

	/* All setup so dup the side channel across to a real fd */
	if((fd3 = ConnectAttach_r(info.nd, info.pid, info.chid, 0, _NTO_COF_CLOEXEC)) < 0) {
		close(fd2);
		errno = -fd3;
		return -1;
	}

	memset(&msg.dup.i, 0x00, sizeof msg.dup.i);
	msg.dup.i.type = _IO_DUP;
	msg.dup.i.combine_len = sizeof msg.dup;
	msg.dup.i.info.nd = netmgr_remote_nd(info.nd, ND_LOCAL_NODE);
	msg.dup.i.info.pid = getpid();
	msg.dup.i.info.chid = info.chid;
	msg.dup.i.info.scoid = info.scoid;
	msg.dup.i.info.coid = fd2;
	if ((ret = MsgSendnc_r(fd3, &msg.dup.i, sizeof msg.dup.i, 0, 0)) < 0) {
		close(fd2);
		ConnectDetach_r(fd3);
		errno = -ret;
		return -1;
	}

	close(fd2);
	ConnectFlags_r(0, fd3, FD_CLOEXEC, 0);

	return fd3;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/accept.c $ $Rev: 844028 $")
#endif
