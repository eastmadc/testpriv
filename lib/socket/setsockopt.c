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
#include <unistd.h>
#include <sys/iomsg.h>
#include <sys/iomgr.h>
#include <sys/sockmsg.h>
#include <sys/socket.h>

int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	union {
		io_sock_sopt_t so;
		io_sock_sopt2_t so2;
	} msg;
	iov_t wiov[2];
	int ret;

	if(!optval) {
		errno = EINVAL;
		return -1;
	}

	msg.so2.i.msg.type        = _IO_MSG;
	msg.so2.i.msg.combine_len = sizeof msg.so2.i + optlen;
	msg.so2.i.msg.mgrid       = _IOMGR_TCPIP;
	msg.so2.i.msg.subtype     = _IO_SOCK_SOPT2;
	msg.so2.i.level           = level;
	msg.so2.i.optname         = optname;
	msg.so2.i.optlen          = optlen;
	msg.so2.i.zero            = 0;

	SETIOV(wiov, &msg.so2.i, sizeof msg.so2.i);
	SETIOV(wiov+1, (void *)optval, optlen);

	if((ret = MsgSendv(s, wiov, 2, NULL, 0)) == -1 && errno == ENOSYS)
	{
		msg.so.i.msg.type        = _IO_MSG;
		msg.so.i.msg.combine_len = sizeof msg.so.i + optlen;
		msg.so.i.msg.mgrid       = _IOMGR_TCPIP;
		msg.so.i.msg.subtype     = _IO_SOCK_SOPT;
		msg.so.i.level           = level;
		msg.so.i.optname         = optname;
		msg.so.i.optlen          = optlen;

		SETIOV(wiov, &msg.so.i, sizeof msg.so.i);
		SETIOV(wiov+1, (void *)optval, optlen);

		if((ret = MsgSendv(s, wiov, 2, NULL, 0)) == -1 && errno == ENOSYS)
		  errno = ENOTSOCK;
	}
	return ret;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/setsockopt.c $ $Rev: 729877 $")
#endif
