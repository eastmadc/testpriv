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
#include <devctl.h>
#include <stdlib.h>
#include <sys/dcmd_ip.h>
#include <sys/socket.h>

int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret;

	if((ret = _devctl(s, DCMD_IP_GDESTADDR, name, *namelen, 0)) == -1) {
		if(errno == ENOSYS)
			errno = ENOTSOCK;
		return -1; 
	}

	*namelen = min (*namelen, ret);
	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/getpeername.c $ $Rev: 729877 $")
#endif
