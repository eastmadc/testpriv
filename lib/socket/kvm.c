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




#include <sys/socket.h>
#include <sys/sockmsg.h>
#include <sys/netmgr.h>
#include <sys/iomgr.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#define _KERNEL	/* For nlist_old */
#include <nlist.h>
#undef _KERNEL
#include <kvm.h>

struct __kvm {
	int		fd;
	const char	*errstr;
	char		errbuf[_POSIX2_LINE_MAX];
};

static kvm_t *
kvm_getfd(int oflag)
{
	static char const * const	proc = "/proc/";
	static char const * const	as   = "/as";

	int				worklen, fd;
	char				*workp, *node;
	struct _server_info		sinfo;


	struct	__kvm			*kv;

	switch (oflag) {
	case O_RDONLY:
	case O_WRONLY:
	case O_RDWR:
		break;

	default:
		errno = EINVAL;
		return NULL;
	}

	worklen = strlen(proc) + (8*sizeof(int)) + strlen(as) + 1;
	if ((fd = socket(AF_INET, SOCK_RAW, 0)) == -1)
		return NULL;

	if (ConnectServerInfo(getpid(), fd, &sinfo) != fd) {
		close(fd);
		errno = ESRCH;
		return NULL;
	}

	if (sinfo.flags & _NTO_MI_ENDIAN_DIFF) {
		close(fd);
		errno = EOPNOTSUPP;
		return NULL;
	}

	close(fd);


	node = NULL;
	if (ND_NODE_CMP(sinfo.nd, ND_LOCAL_NODE) != 0) {
		int	len1, len2;

		len2 = -1;
		if ((len1 = netmgr_ndtostr(ND2S_DIR_SHOW | ND2S_NAME_SHOW,
		    sinfo.nd, NULL, 0)) == -1 ||
		    (node = malloc(len1 + worklen)) == NULL ||
		    (len2 = netmgr_ndtostr(ND2S_DIR_SHOW | ND2S_NAME_SHOW,
		    sinfo.nd, node, len1)) != len1) {
			free(node); /* may be NULL */
			if (len2 != -1) {
				/* Something weird happened */
				errno = EINVAL;
			}
			return NULL;
		}
		/* netmgr_ndtostr includes trailing '\0' */
		if (--len1 <= 0) {
			free(node);
			errno = EINVAL;
			return NULL;
		}

		workp = node + len1;
	}
	else {
		if ((node = malloc(worklen)) == NULL)
			return NULL;
		workp = node;
	}

	if (snprintf(workp, worklen, "%s%d%s", proc, sinfo.pid, as) >=
	    worklen) {
		free(node);
		errno = EINVAL;
		return NULL;
	}

	fd = open(node, oflag);
	free(node);
	if (fd == -1)
		return NULL;

	if ((kv = calloc(1, sizeof(*kv))) == NULL) {
		close(fd);
		return NULL;
	}

	kv->fd = fd;

	return kv;
}

static void
kvm_puterr(kvm_t *kv, int err)
{
	snprintf(kv->errbuf, _POSIX2_LINE_MAX, "%s", strerror(errno));
	if (kv->errstr != NULL) {
		/* from kvm_open() */
		fprintf(stderr, "%s: %s\n", kv->errstr, strerror(err));
	}
}

char *
kvm_geterr(kvm_t *kv)
{
    return kv->errbuf;
}


kvm_t *
kvm_openfiles(const char *execfile, const char *memfile, const char *swapfile,
    int oflags, char *errbuf)
{
	kvm_t	*kv;

	/*
	 * we ignore execfile, memfile, swapfile.  The stack
	 * pointed to by SOCK is always used.
	 */

	if ((kv = kvm_getfd(oflags)) == NULL && errbuf != NULL) {
		snprintf(errbuf, _POSIX2_LINE_MAX, "%s", strerror(errno));
	}
	return kv;
}

kvm_t *
kvm_open(const char *execfile, const char *memfile, const char *swapfile,
    int oflags, const char *errstr)
{
	kvm_t	*kv;

	if (execfile != NULL || memfile != NULL) {
		if (errstr != NULL) {
			errno = EINVAL;
			perror(errstr);
		}
	}

	if ((kv = kvm_getfd(oflags)) == NULL) {
		if (errstr != NULL) {
			perror(errstr);
		}
	}
	kv->errstr = errstr;
	return kv;
}

int
kvm_nlist(kvm_t *kv, struct nlist *nl)
{
	iov_t iov[2];
	io_sock_nlist_t msg;
	int n, fd, unfound, old;

	struct nlist_old nold[2];

	old = 0; /* Assume we are talking to a new stack */
	unfound = 0;

	memset(&nold[1], 0x00, sizeof(nold[1]));

	if ((fd = socket (AF_INET, SOCK_RAW, 0)) == -1) {
		kvm_puterr(kv, errno);
		return -1;
	}

	for (n = 0; nl[n].n_name != NULL && *nl[n].n_name != '\0'; n++) {
		/*
		 * The stack didn't always set the following
		 * two to 0 if it didn't find the symbol.
		 */
		nl[n].n_type = 0;
		nl[n].n_value = 0;

		if (!old) {
			old = 1;
		}
		if (old) {
			strlcpy(nold[0].n_name, nl[n].n_name, sizeof(nold[0].n_name));
			nold[0].n_value = nl[n].n_value;
			nold[0].n_type = nl[n].n_type;


			msg.i.msg.type        = _IO_MSG;
			msg.i.msg.combine_len = sizeof msg.i;
			msg.i.msg.mgrid       = _IOMGR_TCPIP;
			msg.i.msg.subtype     = _IO_SOCK_NLIST;

			SETIOV(iov, &msg.i, sizeof msg.i);
			SETIOV(iov+1, nold, sizeof(nold));


			if (MsgSendv(fd, iov, 2, iov+1, 1) == -1) {
				close (fd);
				kvm_puterr(kv, errno);
				return -1;
			}

			nl[n].n_value = nold[0].n_value;
			nl[n].n_type = nold[0].n_type;
		}

		if (nl[n].n_value == 0)
			unfound++;
	}


	if (n == 0) {
		close (fd);
		kvm_puterr(kv, EINVAL);
		return -1;
	}


	return unfound;
}


ssize_t
kvm_read(kvm_t *kv, u_long off, void *data, size_t length)
{
	int	len, r;

	if (lseek(kv->fd, off, SEEK_SET) == -1) {
		kvm_puterr(kv, errno);
		return -1;
	}

	len = length;
	while (len) {
		if ((r = read(kv->fd, data, len)) == -1) {
			kvm_puterr(kv, errno);
			return -1;
		}
                if (r == 0) { /*EOF?? An odd occurance but can happen when offset = 0 */
			errno = EINVAL; /* bad offset*/
			kvm_puterr(kv, errno);
			return -1;
		}
		len -= r;
		data = (void *)((uintptr_t)data + r);
	}
	return length;
}


ssize_t
kvm_write(kvm_t *kv, u_long off, const void *data, size_t length)
{
     	int	len, r;

	if (lseek(kv->fd, off, SEEK_SET) == -1) {
		kvm_puterr(kv, errno);
		return -1;
	}
	
	len = length;
	while (len) {
		if ((r = write(kv->fd, data, len)) == -1) {
			kvm_puterr(kv, errno);
			return -1;
		}
                if (r == 0) { /*Should not happen, but keep us from looping */
			errno = EINVAL; /* bad offset? */
			kvm_puterr(kv, errno);
			return -1;
		}
		len -= r;
		data = (void *)((uintptr_t)data + r);
	}
	return length;

}


int
kvm_close(kvm_t *kv)
{
	int ret;

	if ((ret = close(kv->fd)) == -1) {
		kvm_puterr(kv, errno);
	} else {
		free(kv);
	}
	return ret;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/kvm.c $ $Rev: 729877 $")
#endif
