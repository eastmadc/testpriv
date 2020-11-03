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
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/iomsg.h>
#include <sys/socket.h>
#include <sys/sockmsg.h>
#include <unistd.h>
#include <string.h>

static int recvmsg_old(int fd, struct msghdr *m, int flags);
static void clearfds(void *, int);
static void clearbufs(iov_t **, char **, int);

int
recvmmsg(int s, struct mmsghdr *mm, unsigned int vlen, unsigned int flags,
    struct timespec *to)
{
	io_sock_recvmmsg_t	msgi;
	struct msghdr		*mh;
	int			i, j, k, ret, rc, niov, donow;
	iov_t			*iovp, *iova, *iovd; /* p, address, data */

	iovp = NULL;
	ret = 0;
	donow = 0;
again:
	mm += donow;
	vlen -= donow;

	msgi.i.read.type = _IO_READ;
	msgi.i.read.combine_len = sizeof msgi.i;
	msgi.i.read.nbytes = 0;
	msgi.i.read.xtype = _IO_XTYPE_TCPIP_MMSG;
	msgi.i.read.zero = 0;
	msgi.i.addrlen_tot = 0;
	msgi.i.controllen_tot = 0;

	msgi.i.vlen = vlen;
	if (to == NULL) {
		flags |= MSG_NOTIMEO;
		msgi.i.to.tv_sec = 0;
		msgi.i.to.tv_nsec = 0;
	} else {
		msgi.i.to = *to;
	}
	msgi.i.flags = flags;

	niov = 2;
	/*
	 * Currently we only support returning of address, not control data.
	 * If we ever start supporting control data as well, the '1' below
	 * will have to change to a '2'.
	 */
	niov += 1 * vlen;

	for (i = 0; i < vlen; i++) {
		mh = &mm[i].msg_hdr;
		niov += mh->msg_iovlen;
		if (mh->msg_control != NULL && mh->msg_controllen) {
			break;
		}
	}
	donow = i;

	if ((iova = realloc(iovp, niov * sizeof(*iovp))) == NULL) {
		goto fail;
	}
	iovp = iova;

	rc = 0;
	if (donow > 0) {
		SETIOV(iova, &msgi, sizeof(msgi));
		iova++;
		SETIOV(iova, mm, i * sizeof(*mm));
		iova++;
		/*
		 * Again, if we ever support control, the '1' below will
		 * have to change to a '2'.
		 */
		iovd = iova + 1 * vlen;
		for (j = 0; j < i; j++) {
			mh = &mm[j].msg_hdr;
			mm[j].msg_len = 0;
			if (mh->msg_name != NULL) {
				SETIOV(iova, mh->msg_name, mh->msg_namelen);
				msgi.i.addrlen_tot += mh->msg_namelen;
			} else {
				SETIOV(iova, NULL, 0);
			}
			iova++;
			for (k = 0; k < mh->msg_iovlen; k++) {
				*iovd = mh->msg_iov[k];
				mm[j].msg_len += GETIOVLEN(iovd);
				msgi.i.read.nbytes += GETIOVLEN(iovd);
				iovd++;
			}
		}
		if ((rc = MsgSendv(s, iovp, 2, iovp, niov)) == -1) {
			goto fail;
		}
		ret += rc;
	}

	/* XXX check timeout? */
	/* Did we find control data and not early out */
	if (donow < vlen && rc == donow) {
		unsigned int flags2;
		/*
		 * Note: timeout is only consulted in "kernel" once per
		 * completed mm operation. ie. it won't time out a particular
		 * blocking op (that's what SO_RCVTIMEO is for).  Therefore
		 * we don't have to propagate it to this single recvmsg
		 * call.
		 */
		flags2 = flags & ~MSG_WAITFORONE;
		if (flags & MSG_WAITFORONE) {
			if (donow > 0)
				flags2 |= MSG_DONTWAIT;
			flags |= MSG_DONTWAIT;
		}
		if ((rc = recvmsg(s, &mm[i].msg_hdr, flags2)) == -1)
			goto fail;

		mm[i].msg_len = rc;
		ret++;
		if (++donow < vlen)
			goto again;
	}

	free(iovp);
	return ret;
fail:
	free(iovp);
	return -1;
}

/* 
 * To support the UDS receiving fd, we do 2 reads if msg_control is
 * non-zero. The first read to get control message, and if it's a
 * SCM_RIGHTS, then we expand the control message buffer and the
 * 2nd read will got whole control message, and the user message;
 * otherwise, 2nd read only reading user message.
 */
int
recvmsg(int fd, struct msghdr *m, int flags)
{
	io_sock_recvmsg2_t	msgi, msgo;
	iov_t			iov_i[1], iov_o_work[12];
	iov_t			*iov_o, *p, *q;
	int			i, *fdp, rcvlen, todo, avail, nfds, newfd;
	int			oflags, olen, done, cur;
	struct cmsghdr		*cm, *cm_dst;
	char			*tmpbuf;
	io_dup_t		*dupmsg;
	pid_t			senderpid;


	if (m->msg_iovlen + 4 > sizeof(iov_o_work) / sizeof(iov_o_work[0])) {
		if ((iov_o = malloc(m->msg_iovlen + 4)) == NULL) {
			return -1;
		}
	} else {
		iov_o = iov_o_work;
	}

AGAIN:
	cm = NULL;
	tmpbuf = NULL;
	oflags = 0;
	olen = 0;

	msgi.i.read.type = _IO_READ;
	msgi.i.read.combine_len = sizeof msgi.i;
	msgi.i.read.nbytes = 0;
	msgi.i.read.xtype = _IO_XTYPE_TCPIP_MSG2;
	msgi.i.read.zero = 0;

	msgi.i.flags = flags;
	msgi.i.addrlen = m->msg_name ? m->msg_namelen : 0;
	msgi.i.controllen = m->msg_control ? m->msg_controllen : 0;
	msgi.i.controlseq = 0;

	SETIOV(iov_i, &msgi.i, sizeof msgi.i);

	p = iov_o;

	SETIOV(p, &msgo.o, sizeof msgo.o);
	p++;
	if (msgi.i.addrlen > 0) {
		SETIOV(p, m->msg_name, msgi.i.addrlen);
		p++;
	}
	if (msgi.i.controllen > 0) {
		SETIOV(p, m->msg_control, msgi.i.controllen);
		p++;
	}

	done = 0;
	todo = 0;
	if (msgi.i.controllen) {
		char  usrdat;

		SETIOV(p, &usrdat, sizeof(usrdat));
		p++;
		msgi.i.flags |= MSG_PEEK;
		msgi.i.read.nbytes = sizeof(usrdat);
		
		if (MsgSendv(fd, iov_i, 1, iov_o, p - iov_o) == -1) {
			clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
			if (errno == ENOSYS) {
				/* recvmsg_old() will ENOTSOCK if it gets ENOSYS */
				return recvmsg_old(fd, m, flags) /* ENOTSOCK */;
			}
			return -1;
		}

		msgi.i.controlseq = msgo.o.controlseq;
		msgi.i.controllen = msgo.o.controltot;
		if ((tmpbuf = malloc(msgo.o.controltot)) == NULL) {
			clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
			return -1;
		}
		SETIOV(p - 2, tmpbuf, msgo.o.controltot);

		if ((msgo.o.flags & MSG_CTRUNC) == 0) {
			memcpy(tmpbuf, m->msg_control, msgo.o.controllen);
		}
		else if (MsgSendv(fd, iov_i, 1, iov_o, p - iov_o) == -1) {
			if (errno == EILSEQ) {
				free(tmpbuf);
				tmpbuf = NULL;
				goto AGAIN;
			}
			clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
			return -1;
		}
		
		todo = msgo.o.controltot;
		avail = m->msg_controllen;

		cm = (struct cmsghdr *)tmpbuf;
		cm_dst = m->msg_control;

		for (;;) {
			cur = min(avail, todo);
			if (todo < sizeof(*cm)) {
				memcpy(cm_dst, cm, cur);
				todo -= cur;
				avail -= cur;
				done += cur;
				break;
			}


			if (cm->cmsg_level != SOL_SOCKET ||
			    cm->cmsg_type != SCM_RIGHTS) {
				cur = min(cur,
				    CMSG_SPACE(cm->cmsg_len - __CMSG_ALIGN(sizeof(*cm))));
				memcpy(cm_dst, cm, cur);
				todo -= cur;
				avail -= cur;
				done += cur;
				if (avail <= 0 || todo <= 0) {
					break;
				}
				cm = (struct cmsghdr *)((char *)cm + cur);
				cm_dst = (struct cmsghdr *)
				    ((char *)cm_dst + cur);
				continue;
				    
			}

			cur = min(cur, __CMSG_ALIGN(sizeof(*cm)));
			memcpy(cm_dst, cm, cur);
			todo -= cur;
			avail -= cur;
			done += cur;
			cm_dst->cmsg_len = sizeof(*cm_dst);
			if (avail <= 0 || todo <= 0) {
				break;
			}
			cm_dst->cmsg_len = __CMSG_ALIGN(sizeof(*cm_dst));

			nfds = min(todo, (cm->cmsg_len - __CMSG_ALIGN(sizeof(*cm)))) /
			    sizeof(io_dup_t);

			fdp = (int *)CMSG_DATA(cm_dst);
			dupmsg = (io_dup_t *)CMSG_DATA(cm);
			for (i = 0; i < nfds; i++) {
				if (avail < sizeof(int)) {
					break;
				}

				if (todo < sizeof(io_dup_t)) {
					/* something's out of sync on sender */
					todo = 0;
					break;
				}
				senderpid = dupmsg->i.info.tid;

				if ((newfd = ConnectAttach(dupmsg->i.info.nd,
				    dupmsg->i.info.pid,
				    dupmsg->i.info.chid, 0, 0)) == -1) {
					clearfds(m->msg_control, done);
					clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
					return -1;
				}
				
				dupmsg->i.info.pid = senderpid;
				if (MsgSendnc(newfd, &dupmsg->i,
				    sizeof(*dupmsg), 0, 0) == -1) {
					ConnectDetach_r(newfd);
					clearfds(m->msg_control, done);
					clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
					return -1;
				}
				
				*fdp++ = newfd;
				dupmsg++;
				todo -= sizeof(io_dup_t);
				avail -= sizeof(int);
				done += sizeof(int);
				cm_dst->cmsg_len += sizeof(int);
			}
			if (i != nfds)
				break;

			cur = __CMSG_ALIGN(cm->cmsg_len) - cm->cmsg_len;
			if (todo < cur) {
				todo = 0;
				break;
			}
			todo -= cur;
			cur = cm->cmsg_len + cur;
			cm = (struct cmsghdr *)((char *)cm + cur);

			cur = __CMSG_ALIGN(cm_dst->cmsg_len) - cm_dst->cmsg_len;
			if (avail < cur) {
				break;
			}
			avail -= cur;
			cur = cm_dst->cmsg_len + cur;
			cm_dst = (struct cmsghdr *)((char *)cm_dst + cur);

		}
		/* restore original flags */
		msgi.i.flags = flags;
		msgi.i.read.nbytes = 0;
		p--;
	}
	
	q = m->msg_iov;

	for (i = m->msg_iovlen; i; i--) {
		*p = *q;
		msgi.i.read.nbytes += GETIOVLEN(q);
		p++;
		q++;
	}

	if ((rcvlen = MsgSendv(fd, iov_i, 1, iov_o, (p - iov_o))) == -1) {
		if (errno == EILSEQ) {
			free(tmpbuf);
			tmpbuf = NULL;
			goto AGAIN;
		}
		clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);
		if (errno == ENOSYS) {
			/* recvmsg_old() will ENOTSOCK if it gets ENOSYS */
			return recvmsg_old(fd, m, flags) /* ENOTSOCK */;
		}
		return -1;
	}

	m->msg_flags = msgo.o.flags;
	if (todo > 0) {
		/* Might already be set */
		m->msg_flags |= MSG_CTRUNC;
	}

	if (m->msg_name)
		m->msg_namelen = msgo.o.addrlen;
	m->msg_controllen = done;

	clearbufs(&iov_o, &tmpbuf, iov_o != iov_o_work);

	return rcvlen;
}

static void
clearbufs(iov_t **iov, char **tmp, int do_iov)
{
	if (do_iov) {
		free(*iov);
		*iov = NULL;
	}
	free(*tmp);
	*tmp = NULL;
}

static void
clearfds(void *buf, int size)
{
	int		nfds, *fdp, i;
	struct cmsghdr	*cm;

	cm = buf;
	for (;;) {
		if (size <= CMSG_LEN(sizeof(int))) {
			return;
		}
		if (cm->cmsg_level == SOL_SOCKET &&
		    cm->cmsg_type == SCM_RIGHTS) {
			nfds = (cm->cmsg_len -
			    __CMSG_ALIGN(sizeof(struct cmsghdr))) / sizeof(int);
			fdp = (int *)CMSG_DATA(cm);
			for (i = 0; i < nfds; i++) {
				close(*fdp);
				fdp++;
			}
		}
		cm = (struct cmsghdr *)((char *)cm +
		    __CMSG_ALIGN(cm->cmsg_len));
		size -= __CMSG_ALIGN(cm->cmsg_len);
	}
}


static int
recvmsg_old(int fd, struct msghdr *m, int flags)
{
	io_sock_recvmsg_t msgi, msgo;
	iov_t iov_i[1];
	iov_t *iov_o, *p, *q;
	int i, j, *fdp, rcvlen, recvfd = 0;
	struct cmsghdr *cmptr = NULL;
	char           *tmpbuf = NULL;
	
	if ((iov_o = alloca((m->msg_iovlen+4) * sizeof(iov_t))) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	msgi.i.read.type        = _IO_READ;
	msgi.i.read.combine_len = sizeof msgi.i;
	msgi.i.read.nbytes      = 0;
	msgi.i.read.xtype       = _IO_XTYPE_TCPIP_MSG;
	msgi.i.read.zero        = 0;

	msgi.i.flags            = flags;
	msgi.i.addrlen          = m->msg_name    ? m->msg_namelen    : 0;
	msgi.i.controllen       = m->msg_control ? m->msg_controllen : 0;

	SETIOV (iov_i, &msgi.i, sizeof msgi.i);

	p = iov_o;

	SETIOV (p, &msgo.o, sizeof msgo.o);
	p++;
	if (m->msg_name) {
		SETIOV (p, m->msg_name, msgi.i.addrlen);
		p++;
	}
	if (m->msg_control) {
		SETIOV (p, m->msg_control, msgi.i.controllen);
		p++;
	}

	if (msgi.i.controllen) {
		iov_t *psave = p;
		char  usrdat;

		SETIOV(p, &usrdat, sizeof(usrdat));
		p++;
		msgi.i.flags |= MSG_PEEK;
		msgi.i.read.nbytes = sizeof(usrdat);
		
		if (MsgSendv(fd, iov_i, 1, iov_o, p - iov_o) == -1) {
			if(errno == ENOSYS)
				errno = ENOTSOCK;
			return -1;
		}

		if (msgo.o.controllen > sizeof(*cmptr) &&
		    (cmptr = CMSG_FIRSTHDR(m)) && cmptr->cmsg_level == SOL_SOCKET && 
		    cmptr->cmsg_type == SCM_RIGHTS) {
			recvfd = 1;
			if (msgo.o.controllen < cmptr->cmsg_len) {
				if ((tmpbuf = malloc(cmptr->cmsg_len - sizeof(*cmptr))) == NULL)
					return -1;
				msgi.i.controllen = cmptr->cmsg_len;
				p = psave - 1;
				SETIOV(p, m->msg_control, sizeof(*cmptr));
				p++;
				SETIOV(p, tmpbuf, cmptr->cmsg_len - sizeof(*cmptr));
				p++;
			}
		} else {
			/* 
			 * Either there is no control message or  we got a control 
			 * message but it's not SCM_RIGHTS, so reset p to receive 
			 * the data
			 */
			p = psave;
		}
		
		/* restore orignal flags */
		msgi.i.flags = flags;
		msgi.i.read.nbytes = 0;
	}
	
	q=m->msg_iov;

	for (i=m->msg_iovlen; i; i--) {
		*p = *q;
		msgi.i.read.nbytes += GETIOVLEN(q);
		p++;
		q++;
	}

	if ((rcvlen = MsgSendv(fd, iov_i, 1, iov_o, (p - iov_o))) == -1) {
		if(errno == ENOSYS)
			errno = ENOTSOCK;
		return -1;
	}

	m->msg_flags = msgo.o.flags;

	if (m->msg_name)
		m->msg_namelen = msgo.o.addrlen;

	if (m->msg_control)
		m->msg_controllen = msgo.o.controllen;

	if (recvfd) {
		/* now cmptr point to the control message
		 * Fixme: Do we need to use CMSG_NXTHDR to loop it? If so,
		 *        we also need to loop while we try to enlarge 
		 *        control buffer.
		 */
		io_dup_t *dupmsg;
		int		 newfd, nfds;
		pid_t	 senderpid;
	
		nfds = cmptr->cmsg_len / sizeof(io_dup_t);
		fdp = (int *)CMSG_DATA(cmptr);
		dupmsg = tmpbuf ? (io_dup_t *)tmpbuf : (io_dup_t *)CMSG_DATA(cmptr);
		cmptr->cmsg_len = sizeof(*cmptr);
		
		for (i=0; i<nfds; i++) {
			senderpid = dupmsg->i.info.tid;

			if ((newfd = ConnectAttach(dupmsg->i.info.nd,
			    dupmsg->i.info.pid,
			    dupmsg->i.info.chid, 0, 0)) == -1) {
				goto bad;
			}
			
			dupmsg->i.info.pid = senderpid;
			if(MsgSendnc(newfd, &dupmsg->i, sizeof(*dupmsg), 0, 0) == -1)
				goto bad;
			
			*fdp = newfd;
			fdp++;
			dupmsg++;
			cmptr->cmsg_len += sizeof(int);
		}
		m->msg_controllen = cmptr->cmsg_len;
		if (tmpbuf)
			free(tmpbuf);
	}
	return rcvlen;
	
bad:
	fdp = (int *)CMSG_DATA(cmptr);
	for (j = 0; j < i; j++, fdp++)
		ConnectDetach_r(*fdp);
	if (tmpbuf)
		free(tmpbuf);
	return -1;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/recvmsg.c $ $Rev: 812397 $")
#endif
