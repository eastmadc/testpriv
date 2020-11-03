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
#include "autoconnect.h"


ssize_t
send(int s, const void * const msg, size_t len, int flags)
{
	return sendto(s, msg, len, flags, NULL, (socklen_t)0);
}

ssize_t
sendto(int fd, const void *buf, const size_t len, const int flags,
    const struct sockaddr *to, const socklen_t tolen)
{
	int			ret, err, retry;
	io_sock_sendto_t	msg;
	iov_t			iov_i[3];

	msg.i.write.type        = _IO_WRITE;
	msg.i.write.combine_len = sizeof msg.i;
	msg.i.write.nbytes      = len;
	msg.i.write.xtype       = _IO_XTYPE_TCPIP;
	msg.i.write.zero        = 0;

	msg.i.flags             = flags;
	msg.i.addrlen           = to ? tolen : 0;

	SETIOV(iov_i, &msg.i, sizeof msg.i);
	SETIOV(iov_i+1, (void *)to, msg.i.addrlen);
	SETIOV(iov_i+2, (void *)buf, len);


	retry = 1;
again:
	ret =  MsgSendv (fd, iov_i, 3, NULL, 0);

	if (ret == -1) {
		err = errno;
		if (err == ENOSYS) {
			errno = ENOTSOCK;
		}
		else if ((err == EHOSTUNREACH || err == EADDRNOTAVAIL) &&
		    retry != 0 && do_autocon() != 0) {
			ret = autoconnect();        
			if (ret == 0) {
				retry = 0;
				goto again;
			}
			else if (ret > 0) {
				/* script failed with non zero exit status. */
				errno = err; 
				ret = -1;
			}
			else {
				/* autoconnect failed internally. Return error. */
			}
		}
	}

	return ret;	
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/send.c $ $Rev: 729877 $")
#endif
