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
#include <fcntl.h>
#include <share.h>
#include <sys/iomsg.h>
#include <sys/ftype.h>
#include <sys/sockmsg.h>
#include <sys/socket.h>

int socketpair(int domain, int type, int protocol, int filedes[2])
{

	filedes[0] = socket(domain, type, protocol);

	if(filedes[0] != -1) {
		filedes[1] = _sopenfd(filedes[0], O_RDWR, SH_DENYNO, _IO_OPENFD_PIPE);
		if (filedes[1] != -1) {
			return 0;
		}
		close(filedes[0]);
	} else if (errno == ENOENT) {
		errno = EAFNOSUPPORT;
	}
	return -1;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/socketpair.c $ $Rev: 729877 $")
#endif
