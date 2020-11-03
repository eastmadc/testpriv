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




#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockmsg.h>
#include <errno.h>
#include <unistd.h>


ssize_t
recv(int s, void *buf, size_t len, int flags)
{
	return recvfrom(s, buf, len, flags, NULL, 0);
}

int
recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	io_sock_recvfrom_t msg;
	iov_t iov_i[1];
	iov_t iov_o[3];
	int ret;

	msg.i.read.type        = _IO_READ;
	msg.i.read.combine_len = sizeof msg.i;
	msg.i.read.nbytes      = len;
	msg.i.read.xtype       = _IO_XTYPE_TCPIP;
	msg.i.read.zero        = 0;

	msg.i.flags            = flags;
	msg.i.addrlen          = (fromlen && from) ? *fromlen : 0;

	SETIOV(iov_i, &msg.i, sizeof msg.i);

	SETIOV(iov_o, &msg.o, sizeof msg.o);
	SETIOV(iov_o+1, from, msg.i.addrlen);
	SETIOV(iov_o+2, buf, len);

	if((ret = MsgSendv(fd, iov_i, 1, iov_o, 3)) == -1) {
		if(errno == ENOSYS)
			errno = ENOTSOCK;
		return -1;
	}

	if(fromlen)
		*fromlen = msg.o.addrlen;

	return ret;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/recv.c $ $Rev: 729877 $")
#endif
