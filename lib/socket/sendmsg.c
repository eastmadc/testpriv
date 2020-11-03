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
#include <assert.h>
#include <devctl.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/iomsg.h>
#include <sys/sockmsg.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "autoconnect.h"

static int send_iov(int fd, iov_t *iov, int start,
    struct mmsghdr *mm, unsigned vlen);

int
sendmmsg(int fd, struct mmsghdr *mm, unsigned int vlen, unsigned int flags)
{
	io_sock_sendmmsg_t	msg;
	int			niov, i, ret;
	iov_t			*iov_i;

	msg.i.write.type        = _IO_WRITE;
	msg.i.write.combine_len = sizeof msg.i;
	msg.i.write.nbytes      = 0;
	msg.i.write.xtype       = _IO_XTYPE_TCPIP_MMSG;
	msg.i.write.zero        = 0;

	msg.i.vlen              = vlen;
	msg.i.flags             = flags;

	/* The two SETIOV below in this function */
	niov = 2;

	/* each struct msghdr can have address and control data */
	niov += 2 * vlen;

	for (i = 0; i < vlen; i++) {
		niov += mm[i].msg_hdr.msg_iovlen;
	}

	if ((iov_i = malloc(niov * sizeof(*iov_i))) == NULL)
		return -1;

	SETIOV(iov_i + 0, &msg, sizeof(msg));
	SETIOV(iov_i + 1, mm, vlen * sizeof(*mm));

	ret = send_iov(fd, iov_i, 2, mm, vlen);
	free(iov_i);
	return ret;
}

int
sendmsg(int fd, const struct msghdr *m, int flags)
{
	io_sock_sendmsg_t	msg;
	iov_t			*iov_i;
	
	if ((iov_i = alloca((m->msg_iovlen+3) * sizeof (iov_t))) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	msg.i.write.type        = _IO_WRITE;
	msg.i.write.combine_len = sizeof msg.i;
	msg.i.write.nbytes      = 0;
	msg.i.write.xtype       = _IO_XTYPE_TCPIP_MSG;
	msg.i.write.zero        = 0;

	msg.i.flags             = flags;
	msg.i.addrlen           = m->msg_name    ? m->msg_namelen    : 0;
	msg.i.controllen        = m->msg_control ? m->msg_controllen : 0;

	SETIOV(iov_i, &msg.i, sizeof msg.i);

	return send_iov(fd, iov_i, 1, (struct mmsghdr *)m, 1);
}


static int
send_iov(int fd, iov_t *iov_i, int start, struct mmsghdr *mm, unsigned vlen)
{
	iov_t		*p, *q, *d;
	int		i, j, err, retry, nbytes_cur;
	struct msghdr	*m;
	struct _io_write *msg;
	size_t		sz;

	msg = (struct _io_write *)(iov_i->iov_base);

	p = iov_i + start;
	d = p + 2 * vlen;

	for (j = 0; j < vlen; j++, mm++) {
		m = &mm->msg_hdr;

		sz = m->msg_name != NULL ? m->msg_namelen : 0;
		SETIOV(p, m->msg_name, sz);
		p++;

		sz = m->msg_control != NULL ? m->msg_controllen : 0;
		SETIOV(p, m->msg_control, sz);
		p++;

		q = m->msg_iov;

		nbytes_cur = 0;
		for (i = m->msg_iovlen; i; i--) {
			*d = *q;
			nbytes_cur += GETIOVLEN(q);
			d++;
			q++;
		}

		msg->nbytes += nbytes_cur;
		if (msg->xtype == _IO_XTYPE_TCPIP_MMSG)
			mm->msg_len = nbytes_cur;
	}

	retry = 1;
again:
	if ((i = MsgSendv(fd, iov_i, d - iov_i, iov_i, start)) == -1) {
		if (errno == ENOSYS) {
			errno = ENOTSOCK;
		}
		else if ((errno == EHOSTUNREACH || errno == EADDRNOTAVAIL) &&
		    retry != 0 && do_autocon() != 0) {
			err = errno;
			i = autoconnect();
			if (i == 0) {
				retry = 0;
				goto again;
			}
			else if (i > 0) {
				/* script failed with non zero exit status. */
				errno = err;
				i = -1;					  
			}
			else {
				/* autoconnect failed internally. Return error. */
			}
		}
	}	

	return i;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/sendmsg.c $ $Rev: 812397 $")
#endif
