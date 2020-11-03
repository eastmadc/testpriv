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




#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <share.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/iomsg.h>
#include <sys/socket.h>
#include <sys/sockmsg.h>

/* 
The type and protocol map to 8 bytes of extra data in the connect message
The domain of the socket maps directly to a file name.
eg:
	PF_INET -> /dev/socket/2
*/
int socket(int domain, int type, int protocol)
{
	static char const * const _socket_prefix= SOCKET_PREFIX ;
	char const *e; 
	char *f;
	int len, err;
	io_socket_extra_t extra;

	extra.type=type;
	extra.protocol=protocol;

	err = errno;

	if ( (e=getenv("SOCK")) == NULL )
		e = _socket_prefix + sizeof (SOCKET_PREFIX) -1; //e = ""

	errno = err;

	len = strlen(e) + sizeof (SOCKET_PREFIX);

	if ( (f=alloca(len + 8*sizeof(int))) == NULL )
	{
		errno=ENOMEM;
		return -1;
	}

	strcpy (f, e);
	strcat (f, _socket_prefix);
	snprintf(f+len-1, 8*sizeof(int) + 1, "%d", domain);

	if((len = _connect(0, f, 0, 0, SH_COMPAT, _IO_CONNECT_OPEN, 0, 0,
	 _FTYPE_SOCKET, _IO_CONNECT_EXTRA_SOCKET, sizeof(extra), &extra,
	 0, 0, 0)) == -1) {
		if (errno == ENOENT || errno == ENOSYS) {
			errno = EAFNOSUPPORT; /* POSIX.  NetBSD-1-5 returns EPROTONOSUPPORT */
		}
	} else {
		/*
		 * Fib before iface in case iface is only in desired fib,
		 * not current one.
		 */
		if ((e=getenv("SOCK_SO_SETFIB")) != NULL) {
			/*
			 * If this fails, continue anyway, preserving 'errno' as per
			 * http://pubs.opengroup.org/onlinepubs/009695399/functions/errno.html
			 */
			char *ep = NULL;
			long int which_fib = -1;
			which_fib = strtoul(e, &ep, 10);
			if (*ep == '\0') {
				err = errno;
				setsockopt(len, SOL_SOCKET, SO_SETFIB, (void *) &which_fib, sizeof(which_fib));
				errno = err;
			}
		}
		if ((e=getenv("SOCK_SO_BINDTODEVICE")) != NULL) {
			/*
			 * If this fails, continue anyway, preserving 'errno' as per
			 * http://pubs.opengroup.org/onlinepubs/009695399/functions/errno.html
			 */
			err = errno;
			setsockopt(len, SOL_SOCKET, SO_BINDTODEVICE, e, strlen(e) +1);
			errno = err;
		}
	}

	return len;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/socket.c $ $Rev: 729877 $")
#endif
