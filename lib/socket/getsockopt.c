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
#include <netinet/in.h>

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	union {
		io_sock_gopt_t	go;
		io_sock_gopt2_t go2;
	} msg;
	int ret, niov;
	iov_t siov[2];

	if (optval == NULL || optlen == NULL) {
		errno = EINVAL;
		return -1;
	}

	msg.go2.i.msg.type        = _IO_MSG;
	msg.go2.i.msg.combine_len = sizeof msg.go2.i;
	msg.go2.i.msg.mgrid       = _IOMGR_TCPIP;
	msg.go2.i.msg.subtype     = _IO_SOCK_GOPT2;
	msg.go2.i.level           = level;
	msg.go2.i.optname         = optname;
	msg.go2.i.optlen          = *optlen;
	msg.go2.i.zero            = 0;
	
	SETIOV(&siov[0], &msg.go2.i, sizeof(msg.go2.i));
	niov = 1;

	/*
	 * Some options (eg some SCTP) like to look at the
	 * old data before passing new data out (ugh).
	 */
	if (optname & GETSOCKOPT_EXTRA) {
		SETIOV(&siov[1], optval, *optlen);
		niov = 2;
	}

	if ((ret = MsgSendvs(s, siov, niov, optval, *optlen)) == -1) {
		/*
		 * Old io_sock_gopt_t had uint16_t optname
		 * and therefor also didn't support GETSOCKOPT_EXTRA.
		 */
		if (errno != ENOSYS || optname > USHRT_MAX)
			return -1;

		msg.go.i.msg.type        = _IO_MSG;
		msg.go.i.msg.combine_len = sizeof msg.go.i;
		msg.go.i.msg.mgrid       = _IOMGR_TCPIP;
		msg.go.i.msg.subtype     = _IO_SOCK_GOPT;
		msg.go.i.level           = level;
		msg.go.i.optname         = optname;
			
		if ((ret = MsgSend(s, &msg.go.i, sizeof(msg.go.i), optval, *optlen)) == -1) {
			if (errno == ENOSYS)
				errno = ENOTSOCK;
			return -1;
		}
	}

	*optlen = ret;
	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/getsockopt.c $ $Rev: 729877 $")
#endif
