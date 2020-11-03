/*
 * $QNXtpLicenseC:
 * Copyright 2007, 2009, QNX Software Systems. All Rights Reserved.
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

/*	$NetBSD: cryptodev.c,v 1.25 2006/11/16 01:33:51 christos Exp $ */
/*	$FreeBSD: src/sys/opencrypto/cryptodev.c,v 1.4.2.4 2003/06/03 00:09:02 sam Exp $	*/
/*	$OpenBSD: cryptodev.c,v 1.53 2002/07/10 22:21:30 mickey Exp $	*/

/*
 * Copyright (c) 2001 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: cryptodev.c,v 1.25 2006/11/16 01:33:51 christos Exp $");

#ifdef __QNXNTO__
#include "nw_datastruct.h"
#include "nw_msg.h"
#include "siglock.h"
#include <sys/file_bsd.h>
#include <sys/uio_bsd.h>
#include <sys/iofunc.h>
#include <devctl.h>
#include <sys/dcmd_misc.h>
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/errno.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/kauth.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/xform.h>

#ifdef __NetBSD__
  #define splcrypto splnet
#endif
#ifdef CRYPTO_DEBUG
#define DPRINTF(a) uprintf a
#else
#define DPRINTF(a)
#endif

#ifdef __QNXNTO__
#define splcrypto splnet
#define CRIO_IOV_MAX  ((1 << 18) /* 256K */ / MCLBYTES + 1)

// int altq_copyin(const void *src, void *dst, size_t len);
// int altq_copyout(const void *src, void *dst, size_t len);
#endif

struct csession {
	TAILQ_ENTRY(csession) next;
	u_int64_t	sid;
	u_int32_t	ses;

	u_int32_t	cipher;
	struct enc_xform *txform;
	u_int32_t	mac;
	struct auth_hash *thash;

	caddr_t		key;
	int		keylen;
	u_char		tmp_iv[EALG_MAX_BLOCK_LEN];

	caddr_t		mackey;
	int		mackeylen;
	u_char		tmp_mac[CRYPTO_MAX_MAC_LEN];

#ifndef __QNXNTO__
	struct iovec	iovec[IOV_MAX];
	struct uio	uio;
	int		error;
#else
	struct mbuf    *mbuf;
	void *		crp;
	int		error;
	iov_t		work_iov[1];	/* variable size */
#endif
};

struct fcrypt {
	TAILQ_HEAD(csessionlist, csession) csessions;
	int		sesn;
};


#ifndef __QNXNTO__
/* Declaration of master device (fd-cloning/ctxt-allocating) entrypoints */
static int	cryptoopen(dev_t dev, int flag, int mode, struct lwp *l);
static int	cryptoread(dev_t dev, struct uio *uio, int ioflag);
static int	cryptowrite(dev_t dev, struct uio *uio, int ioflag);
static int	cryptoioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct lwp *l);
static int	cryptoselect(dev_t dev, int rw, struct lwp *l);
#endif

/* Declaration of cloned-device (per-ctxt) entrypoints */
static int	cryptof_read(struct file *, off_t *, struct uio *, kauth_cred_t, int);
static int	cryptof_write(struct file *, off_t *, struct uio *, kauth_cred_t, int);
static int	cryptof_ioctl(struct file *, u_long, void*, struct lwp *l);
static int	cryptof_close(struct file *, struct lwp *);

static const struct fileops cryptofops = {
    cryptof_read,
    cryptof_write,
    cryptof_ioctl,
    fnullop_fcntl,
    fnullop_poll,
#ifndef __QNXNTO__
    fbadop_stat,
#else
    fnullop_stat,
#endif
    cryptof_close,
    fnullop_kqfilter
};

static struct	csession *csefind(struct fcrypt *, u_int);
static int	csedelete(struct fcrypt *, struct csession *);
static struct	csession *cseadd(struct fcrypt *, struct csession *);
static struct	csession *csecreate(struct fcrypt *, u_int64_t, caddr_t, u_int64_t,
    caddr_t, u_int64_t, u_int32_t, u_int32_t, struct enc_xform *,
    struct auth_hash *);
static int	csefree(struct csession *);

static int	cryptodev_op(struct csession *, struct crypt_op *, struct lwp *);
static int	cryptodev_key(struct crypt_kop *);
int	cryptodev_dokey(struct crypt_kop *kop, struct crparam kvp[]);

static int	cryptodev_cb(void *);
static int	cryptodevkey_cb(void *);

#ifdef __QNXNTO__
int
cryptodev_open(struct lwp *l, struct file **retval)
{
	struct proc	*p;
	struct fcrypt 	*fcr;
	struct file	*fp;
	int		error;

	p = LWP_TO_PR(l);
	if ((error = falloc(l, &fp)) != 0)
		return (error);

	if ((error = nto_bindit(&p->p_ctxt, fp)) != 0)
		goto err;

	MALLOC(fcr, struct fcrypt *,
	    sizeof(struct fcrypt), M_XDATA, M_WAITOK);
	TAILQ_INIT(&fcr->csessions);
	fcr->sesn = 0;

	if (p->p_ctxt.msg->connect.ioflag & _IO_FLAG_RD) 
		fp->f_flag |= FREAD;

	if (p->p_ctxt.msg->connect.ioflag & _IO_FLAG_WR) 
		fp->f_flag |= FWRITE;

	fp->f_type = DTYPE_CRYPTO;
	fp->f_ops = &cryptofops;
	if (error) {
		nto_unbind(&p->p_ctxt);
 err:
		FILE_UNUSE(fp, p);
		ffree(fp);
	} else {
		fp->f_data = (caddr_t) fcr;
		FILE_SET_MATURE(fp);
		FILE_UNUSE(fp, p);
		*retval = fp;
	}
	return (error);
}
#endif

/*
 * sysctl-able control variables for /dev/crypto now defined in crypto.c:
 * crypto_usercrypto, crypto_userasmcrypto, crypto_devallowsoft.
 */

/* ARGSUSED */
int
cryptof_read(struct file *fp, off_t *poff,
    struct uio *uio, kauth_cred_t cred, int flags)
{
	return (EIO);
}

/* ARGSUSED */
int
cryptof_write(struct file *fp, off_t *poff,
    struct uio *uio, kauth_cred_t cred, int flags)
{
	return (EIO);
}

#ifdef __QNXNTO__
/* Handle DCMD_MISC_GETPTREMBED */
static int crypto_getptrembed(u_long cmd, caddr_t data) {
	int                          ret, i;
	struct proc		    *p;
	resmgr_context_t	    *ctp;
	io_devctl_t                 *msg;
	struct __ioctl_getptrembed  *embedmsg;

	if (cmd != DCMD_MISC_GETPTREMBED) {
		return EINVAL;
	}

	/* Need to parse from the top of msg to find the original cmd and its data */
	p = curproc;
	ctp = &p->p_ctxt;
	msg = (io_devctl_t *)ctp->msg;
	embedmsg =  (struct __ioctl_getptrembed *) _DEVCTL_DATA(msg->i);

	data = (caddr_t) (embedmsg + 1) + embedmsg->niov * sizeof(iov_t);
	cmd = embedmsg->dcmd;

	switch (cmd) {
	case CIOCGSESSION:
		{
			struct session_op *sop = (struct session_op *)data;
			if (embedmsg->niov < 2)
				return EINVAL;
			ret = ioctl_getoneptrembed(msg, sop->key, sop->keylen, 0);
			if (ret > 0)
				return ret;
			ret = ioctl_getoneptrembed(msg, sop->mackey, sop->mackeylen, 1);
			if (ret > 0)
				return ret;
			for (i = 2; i < embedmsg->niov; i++) {
				ret = ioctl_getoneptrembed(msg, NULL, 0, i);
				if (ret > 0)
					return ret;
			}
			/*                         ret = _RESMGR_PTR(&p->p_ctxt, &msg->o, sizeof(msg->o)); */
			ret = EOK;
			break;
		}
	/* Note CIOCKEY taken care of in libc's ioctl() */
	default:
		/* No support for embeddeded pointers for other ioctl commands */
		ret = EOPNOTSUPP;
		break;
	}

	return ret;
}

static void crypto_sess_update(struct session_op *sop) {
	switch (sop->cipher) {
	case 0:
		break;
#ifdef __QNXNTO__
	case CRYPTO_AES_CTR:
	case CRYPTO_AES_CTR_HW:
	case CRYPTO_AES_CBC_HW:
#endif
	case CRYPTO_AES_CBC:
		sop->ses |= UINT64_C(0x0010000000000000);  /* IV 16 bytes */
		break;
	case CRYPTO_NULL_CBC:
		sop->ses |= UINT64_C(0x0004000000000000);  /* IV 4 bytes */
		break;
	case CRYPTO_ARC4:
		sop->ses |= UINT64_C(0x0001000000000000);  /* IV 1 bytes */
		break;
	case CRYPTO_DES_CBC:
	case CRYPTO_3DES_CBC:
	case CRYPTO_BLF_CBC:
	case CRYPTO_CAST_CBC:
	case CRYPTO_SKIPJACK_CBC:
	default:
		sop->ses |= UINT64_C(0x0008000000000000);   /* IV 8 bytes */
		break;
	}
	
	switch (sop->mac) {
	case 0:
		break;
	case CRYPTO_MD5:
		sop->ses |= UINT64_C(0x0000001000000000);   /* 16 bytes */
		break;
	case CRYPTO_SHA1:
		sop->ses |= UINT64_C(0x0000001400000000);   /* 20 bytes */
		break;
#ifdef __QNXNTO__
	case CRYPTO_SHA2_224:
		sop->ses |= UINT64_C(0x0000001C00000000);   /* 28 bytes */
		break;
	case CRYPTO_SHA2_256:
		sop->ses |= UINT64_C(0x0000002000000000);   /* 32 bytes */
		break;
	case CRYPTO_SHA2_384:
		sop->ses |= UINT64_C(0x0000003000000000);   /* 48 bytes */
		break;
	case CRYPTO_SHA2_512:
		sop->ses |= UINT64_C(0x0000004000000000);   /* 64 bytes */
		break;
#endif
	case CRYPTO_NULL_HMAC:
	case CRYPTO_MD5_HMAC:
	case CRYPTO_SHA1_HMAC:
	case CRYPTO_SHA2_HMAC:
	case CRYPTO_RIPEMD160_HMAC:
	default:
		sop->ses |= UINT64_C(0x0000000C00000000);   /* 12 bytes */
		break;
	}
}
#endif

/* ARGSUSED */
int
cryptof_ioctl(struct file *fp, u_long cmd, void* data, struct lwp *l)
{
	struct cryptoini cria, crie;
	struct fcrypt *fcr = (struct fcrypt *)fp->f_data;
	struct csession *cse;
	struct session_op *sop;
	struct crypt_op *cop;
	struct enc_xform *txform = NULL;
	struct auth_hash *thash = NULL;
	u_int64_t sid;
	u_int32_t ses;
	int error = 0;
#ifdef __QNXNTO__
	struct proc	*p;

	p = LWP_TO_PR(l);
#endif

	switch (cmd) {
	case CIOCGSESSION:
		sop = (struct session_op *)data;
#ifdef __QNXNTO__
		p->p_ctxt.msg->devctl.i.nbytes = sizeof(*sop);
#endif
		switch (sop->cipher) {
		case 0:
			break;
		case CRYPTO_DES_CBC:
			txform = &enc_xform_des;
			break;
		case CRYPTO_3DES_CBC:
			txform = &enc_xform_3des;
			break;
		case CRYPTO_BLF_CBC:
			txform = &enc_xform_blf;
			break;
		case CRYPTO_CAST_CBC:
			txform = &enc_xform_cast5;
			break;
		case CRYPTO_SKIPJACK_CBC:
			txform = &enc_xform_skipjack;
			break;
		case CRYPTO_AES_CBC:
			txform = &enc_xform_rijndael128;
			break;
#ifdef __QNXNTO__
		case CRYPTO_AES_CBC_HW:
			txform = &enc_xform_aes_cbc_hw;
			break;
		case CRYPTO_AES_CTR_HW:
			txform = &enc_xform_aes_ctr_hw;
			break;
		case CRYPTO_AES_CTR:
			txform = &enc_xform_aes_ctr;
			break;
#endif
		case CRYPTO_NULL_CBC:
			txform = &enc_xform_null;
			break;
		case CRYPTO_ARC4:
			txform = &enc_xform_arc4;
			break;
		default:
			DPRINTF(("Invalid cipher %d\n", sop->cipher));
			return (EINVAL);
		}

		switch (sop->mac) {
		case 0:
			break;
#ifndef __QNXNTO__
		case CRYPTO_MD5_HMAC:
			thash = &auth_hash_hmac_md5_96;
			break;
		case CRYPTO_SHA1_HMAC:
			thash = &auth_hash_hmac_sha1_96;
			break;
#else
		case CRYPTO_MD5_HMAC:
			thash = &auth_hash_hmac_md5;
			break;
		case CRYPTO_SHA1_HMAC:
			thash = &auth_hash_hmac_sha1;
			break;
		case CRYPTO_MD5_HMAC_96:
			thash = &auth_hash_hmac_md5_96;
			break;
		case CRYPTO_SHA1_HMAC_96:
			thash = &auth_hash_hmac_sha1_96;
			break;
#endif
		case CRYPTO_SHA2_HMAC:
			if (sop->mackeylen == auth_hash_hmac_sha2_256.keysize)
				thash = &auth_hash_hmac_sha2_256;
			else if (sop->mackeylen == auth_hash_hmac_sha2_384.keysize)
				thash = &auth_hash_hmac_sha2_384;
			else if (sop->mackeylen == auth_hash_hmac_sha2_512.keysize)
				thash = &auth_hash_hmac_sha2_512;
			else {
				DPRINTF(("Invalid mackeylen %d\n",
				    sop->mackeylen));
				return (EINVAL);
			}
			break;
		case CRYPTO_RIPEMD160_HMAC:
			thash = &auth_hash_hmac_ripemd_160_96;
			break;
		case CRYPTO_MD5:
			thash = &auth_hash_md5;
			break;
		case CRYPTO_SHA1:
			thash = &auth_hash_sha1;
			break;
#ifdef __QNXNTO__
		case CRYPTO_SHA2_224:
			thash = &auth_hash_sha2_224;
			break;
		case CRYPTO_SHA2_256:
			thash = &auth_hash_sha2_256;
			break;
		case CRYPTO_SHA2_384:
			thash = &auth_hash_sha2_384;
			break;
		case CRYPTO_SHA2_512:
			thash = &auth_hash_sha2_512;
			break;
		case CRYPTO_AES_XCBC_MAC:
			thash = &auth_hash_aes_xcbc_mac;
			break;
#endif
		case CRYPTO_NULL_HMAC:
			thash = &auth_hash_null;
			break;
		default:
			DPRINTF(("Invalid mac %d\n", sop->mac));
			return (EINVAL);
		}

		bzero(&crie, sizeof(crie));
		bzero(&cria, sizeof(cria));

		if (txform) {
			crie.cri_alg = txform->type;
			crie.cri_klen = sop->keylen * 8;
			if (sop->keylen > txform->maxkey ||
			    sop->keylen < txform->minkey) {
				DPRINTF(("keylen %d not in [%d,%d]\n",
				    sop->keylen, txform->minkey,
				    txform->maxkey));
				error = EINVAL;
				goto bail;
			}

			crie.cri_key = malloc(crie.cri_klen / 8, M_XDATA,
			    M_WAITOK);
#ifndef __QNXNTO__
			if ((error = copyin(sop->key, crie.cri_key,
			    crie.cri_klen / 8)))
				goto bail;
#else
			curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
			if ((error = copyin(sop + 1, crie.cri_key,
			    crie.cri_klen / 8)))
				goto bail;
#endif
			if (thash)
				crie.cri_next = &cria;
		}

		if (thash) {
			cria.cri_alg = thash->type;
			cria.cri_klen = sop->mackeylen * 8;
			if (sop->mackeylen != thash->keysize) {
				DPRINTF(("mackeylen %d != keysize %d\n",
				    sop->mackeylen, thash->keysize));
				error = EINVAL;
				goto bail;
			}

			if (cria.cri_klen) {
				cria.cri_key = malloc(cria.cri_klen / 8,
				    M_XDATA, M_WAITOK);
#ifndef __QNXNTO__
				if ((error = copyin(sop->mackey, cria.cri_key,
				    cria.cri_klen / 8)))
					goto bail;
#else
				curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
				if ((error = copyin((caddr_t *)(sop + 1) + crie.cri_klen / 8, cria.cri_key,
				    cria.cri_klen / 8)))
					goto bail;
#endif
			}
		}

		error = crypto_newsession(&sid, (txform ? &crie : &cria),
			    crypto_devallowsoft);
		if (error) {
		  	DPRINTF(("SIOCSESSION violates kernel parameters %d\n",
			    error));
			goto bail;
		}

		cse = csecreate(fcr, sid, crie.cri_key, crie.cri_klen,
		    cria.cri_key, cria.cri_klen, sop->cipher, sop->mac, txform,
		    thash);

		if (cse == NULL) {
			DPRINTF(("csecreate failed\n"));
			crypto_freesession(sid);
			error = EINVAL;
			goto bail;
		}
		sop->ses = cse->ses;
#ifdef __QNXNTO__
		/* Embed the IV/MAC length in session id */
		crypto_sess_update(sop);
#endif

bail:
		if (error) {
			if (crie.cri_key)
				FREE(crie.cri_key, M_XDATA);
			if (cria.cri_key)
				FREE(cria.cri_key, M_XDATA);
		}
		break;
	case CIOCFSESSION:
		ses = *(u_int32_t *)data;
		cse = csefind(fcr, ses);
		if (cse == NULL)
			return (EINVAL);
		csedelete(fcr, cse);
		error = csefree(cse);
		break;
	case CIOCCRYPT: {
		cop = (struct crypt_op *)data;
#ifdef __QNXNTO__
		/* Note CIOCCRYPT is special cased in libc */

		p->p_mbuf->m_len -= sizeof(*cop);
		p->p_mbuf->m_pkthdr.len -= sizeof(*cop);
		p->p_mbuf->m_data += sizeof(*cop);
#endif
		cse = csefind(fcr, cop->ses);
		if (cse == NULL) {
			DPRINTF(("csefind failed\n"));
			return (EINVAL);
		}
		error = cryptodev_op(cse, cop, l);
		break;
        }
	case CIOCKEY:
#ifdef __QNXNTO__
		/* Note CIOCKEY is special cased in libc */
#endif
		error = cryptodev_key((struct crypt_kop *)data);
		break;
	case CIOCASYMFEAT:
		error = crypto_getfeat((int *)data);
		break;
#ifdef __QNXNTO__
	case DCMD_MISC_GETPTREMBED:
		error = crypto_getptrembed(cmd, data);
		break;
#endif
	default:
		DPRINTF(("invalid ioctl cmd %ld\n", cmd));
		error = EINVAL;
	}
	return (error);
}

static int
cryptodev_op(struct csession *cse, struct crypt_op *cop, struct lwp *l)
{
	struct cryptop *crp = NULL;
	struct cryptodesc *crde = NULL, *crda = NULL;
	int i, error, s;
#ifdef __QNXNTO__
	int		need, canfree, niov;
	struct mbuf	*m, *m_prev;
	struct proc	*p;

	canfree = TRUE;
	p = LWP_TO_PR(l);
#endif

	if (cop->len > 256*1024-4)
		return (E2BIG);

	if (cse->txform) {
#ifndef __QNXNTO__
		if (cop->len == 0 || (cop->len % cse->txform->blocksize) != 0)
			return (EINVAL);
#else
		if (cop->len == 0 )
			return (EINVAL);
#endif
	}

#ifndef __QNXNTO__
	bzero(&cse->uio, sizeof(cse->uio));
	cse->uio.uio_iovcnt = 1;
	cse->uio.uio_resid = 0;
	cse->uio.uio_rw = UIO_WRITE;
	cse->uio.uio_iov = cse->iovec;
	UIO_SETUP_SYSSPACE(&cse->uio);
	bzero(&cse->iovec, sizeof(cse->iovec));
	cse->uio.uio_iov[0].iov_len = cop->len;
	cse->uio.uio_iov[0].iov_base = malloc(cop->len, M_XDATA, M_WAITOK);
	for (i = 0; i < cse->uio.uio_iovcnt; i++)
		cse->uio.uio_resid += cse->uio.uio_iov[0].iov_len;
#else
	/*
	 * Setup the reply iov.  On entry, p->p_read.iovp points into
	 * the main recv iov (sctlp->recv_iov).  Therefore, we need to
	 * copy this this over before any tsleep so the the main recv
	 * loop doesn't overwrite it.
	 */
	if (*p->p_read.niovp > CRIO_IOV_MAX)
		return EMSGSIZE;

	memcpy(cse->work_iov, p->p_read.iovp, sizeof(iov_t) * *p->p_read.niovp);
	p->p_read.iovp = cse->work_iov;

	/*
	 * It's possible that the hardware is still operating a on this session
	 * (in cases where the app had set an unblock timer). If a process
	 * needs to unblock before the hardware is done, we let the callback
	 * (cryptodev_cb) do the cleanup, but the callback may not have gone
	 * off yet (in the above mentioned case) so we sleep until it does.
	 */
	if (cse->crp != NULL) {
		error = tsleep(cse->crp, PSOCK, "crydev", 0);
		if (error != EOK)
			return error;

		/* Now we need to cleanup the previous session. The callback
		 * does the cleanup when nobody is waiting for the result, but
		 * since we waited (tsleep above) it assumed that whoever is
		 * waiting does the cleanup.
		 */
		m_freem((struct mbuf *)((struct cryptop *)cse->crp)->crp_buf);
		crypto_freereq(cse->crp);
		cse->crp = NULL;
	}

	/*
	 * We have the data in an mbuf chain, but we might not have all the
	 * data. Allocate extra mbufs.
	 */
	need = cop->len;
	if (cop->iv != NULL)
		need += cse->txform->blocksize;
	if (cop->mac != NULL)
		need += cse->thash->authsize;

	if (p->p_mbuf->m_pkthdr.len < need) {
		need = need - p->p_mbuf->m_pkthdr.len;

		niov = need >> MCLSHIFT;
		if (need & (MCLBYTES -1))
			niov++;		/* Add one for remainder */

		if (niov + *p->p_read.niovp > CRIO_IOV_MAX)
			return EMSGSIZE;

		for (i = niov, m_prev = NULL; i > 0; i--) {
			m = m_getcl(M_DONTWAIT, MT_DATA, 0);
			if (m != NULL) {
				m->m_len = MCLBYTES;
				SETIOV(&p->p_read.iovp[i - 1 + *p->p_read.niovp], m->m_data, MCLBYTES);
				m->m_next = m_prev;
				m_prev = m;
			} else {
				m_freem(m_prev);
				return ENOMEM;
			}
		}

		/*
		 * Make a single mbuf chain, but first trim length (if needed)
		 * from last mbuf in new chain.
		 */
		m_adj(m, (need & (MCLBYTES - 1)) - MCLBYTES);
                m_cat(p->p_mbuf, m);

		/* Get remaining data */
		i = MsgReadv_r(p->p_ctxt.rcvid, p->p_read.iovp + *p->p_read.niovp, niov, p->p_ctxt.info.msglen);
		if (i < 0)
			/* allocated mbufs will be freed with p->p_mbuf */
			return -i;

		if (i != need)
			return EINVAL;

		*p->p_read.niovp += niov;
		p->p_mbuf->m_pkthdr.len += need;

	}

#endif

	crp = crypto_getreq((cse->txform != NULL) + (cse->thash != NULL));
	if (crp == NULL) {
		error = ENOMEM;
		goto bail;
	}

	if (cse->thash) {
		crda = crp->crp_desc;
		if (cse->txform)
			crde = crda->crd_next;
	} else {
		if (cse->txform)
			crde = crp->crp_desc;
		else {
			error = EINVAL;
			goto bail;
		}
	}

#ifndef __QNXNTO__
	if ((error = copyin(cop->src, cse->uio.uio_iov[0].iov_base, cop->len)))
		goto bail;
#endif

#ifdef __QNXNTO__
	p->p_ctxt.msg->devctl.i.nbytes = sizeof(*cop);
#endif

	if (crda) {
		crda->crd_skip = 0;
		crda->crd_len = cop->len;
#ifndef __QNXNTO__
		crda->crd_inject = 0;	/* ??? */
#else
		crda->crd_inject = -cse->thash->authsize;
#endif

		crda->crd_alg = cse->mac;
		crda->crd_key = cse->mackey;
		crda->crd_klen = cse->mackeylen * 8;
#ifdef __QNXNTO__
		p->p_ctxt.msg->devctl.i.nbytes += cse->thash->authsize;
#endif
	}

	if (crde) {
		if (cop->op == COP_ENCRYPT)
			crde->crd_flags |= CRD_F_ENCRYPT;
		else
			crde->crd_flags &= ~CRD_F_ENCRYPT;
		crde->crd_len = cop->len;
		crde->crd_inject = 0;

		crde->crd_alg = cse->cipher;
		crde->crd_key = cse->key;
		crde->crd_klen = cse->keylen * 8;
#ifdef __QNXNTO__
		p->p_ctxt.msg->devctl.i.nbytes += cop->len;
#endif
	}

	crp->crp_ilen = cop->len;
#ifndef __QNXNTO__
	crp->crp_flags = CRYPTO_F_IOV | CRYPTO_F_CBIMM
		       | (cop->flags & COP_F_BATCH);
	crp->crp_buf = (caddr_t)&cse->uio;
#else
	crp->crp_flags = CRYPTO_F_IMBUF | CRYPTO_F_CBIMM
		       | (cop->flags & COP_F_BATCH);
	crp->crp_buf = (caddr_t)p->p_mbuf;
#endif
	crp->crp_callback = (int (*) (struct cryptop *)) cryptodev_cb;
	crp->crp_sid = cse->sid;
	crp->crp_opaque = (void *)cse;

	if (cop->iv) {
		if (crde == NULL) {
			error = EINVAL;
			goto bail;
		}
		if (cse->cipher == CRYPTO_ARC4) { /* XXX use flag? */
			error = EINVAL;
			goto bail;
		}
#ifndef __QNXNTO__
		if ((error = copyin(cop->iv, cse->tmp_iv, cse->txform->blocksize)))
			goto bail;
#else
		memcpy(cse->tmp_iv, p->p_mbuf->m_data, cse->txform->blocksize);
		p->p_mbuf->m_pkthdr.len -= cse->txform->blocksize;
		p->p_mbuf->m_len -= cse->txform->blocksize;
		p->p_mbuf->m_data += cse->txform->blocksize;
		p->p_ctxt.msg->devctl.i.nbytes += cse->txform->blocksize;
#endif
		bcopy(cse->tmp_iv, crde->crd_iv, cse->txform->blocksize);
		crde->crd_flags |= CRD_F_IV_EXPLICIT | CRD_F_IV_PRESENT;
		crde->crd_skip = 0;
	} else if (crde) {
		if (cse->cipher == CRYPTO_ARC4) { /* XXX use flag? */
			crde->crd_skip = 0;
		} else {
			crde->crd_flags |= CRD_F_IV_PRESENT;
			crde->crd_skip = cse->txform->blocksize;
			crde->crd_len -= cse->txform->blocksize;
		}
	}

	if (cop->mac) {
		if (crda == NULL) {
			error = EINVAL;
			goto bail;
		}
		crp->crp_mac=cse->tmp_mac;
#ifdef __QNXNTO__
		p->p_mbuf->m_pkthdr.len -= cse->thash->authsize;
		p->p_mbuf->m_len -= cse->thash->authsize;
		p->p_mbuf->m_data += cse->thash->authsize;
#endif
	}

#ifdef __QNXNTO__
	cse->crp = crp;
#endif
	s = splcrypto();	/* NB: only needed with CRYPTO_F_CBIMM */
	error = crypto_dispatch(crp);
	if (error == 0 && (crp->crp_flags & CRYPTO_F_DONE) == 0) {
		error = tsleep(crp, PSOCK, "crydev", 0);
#ifdef __QNXNTO__
		if (error != EOK) {
			canfree = FALSE;
			p->p_mbuf = NULL;
		}
#endif
	}
	splx(s);
	if (error) {
		goto bail;
	}

	if (crp->crp_etype != 0) {
		error = crp->crp_etype;
		goto bail;
	}

	if (cse->error) {
		error = cse->error;
		goto bail;
	}

#ifndef __QNXNTO__
	if (cop->dst &&
	    (error = copyout(cse->uio.uio_iov[0].iov_base, cop->dst, cop->len)))
		goto bail;

	if (cop->mac &&
	    (error = copyout(crp->crp_mac, cop->mac, cse->thash->authsize)))
		goto bail;
#else
	// we don't need a copy here since it is copies into the iov buffer in the driver.
#endif

bail:
#ifndef __QNXNTO__
	if (crp)
		crypto_freereq(crp);
	if (cse->uio.uio_iov[0].iov_base)
		free(cse->uio.uio_iov[0].iov_base, M_XDATA);
#else
	if (crp && canfree) {
		if(cse->crp != NULL) {
		    crypto_freereq(crp);
		    cse->crp = NULL;
		}
	}
#endif
#ifndef __QNXNTO__
	if (cse->uio.uio_iov[0].iov_base && canfree)
		free(cse->uio.uio_iov[0].iov_base, M_XDATA);
#endif

	return (error);
}

static int
cryptodev_cb(void *op)
{
	struct cryptop *crp = (struct cryptop *) op;
	struct csession *cse = (struct csession *)crp->crp_opaque;

	cse->error = crp->crp_etype;
	if (crp->crp_etype == EAGAIN)
		return crypto_dispatch(crp);
#ifndef __QNXNTO__
	wakeup_one(crp);
#else
	if (wakeup(crp) == 0) {
		m_freem((struct mbuf *)crp->crp_buf);
		if(cse->crp != NULL) {
		    crypto_freereq(crp);
		    cse->crp = NULL;
		}
	}
#endif
	return (0);
}

static int
cryptodevkey_cb(void *op)
{
	struct cryptkop *krp = (struct cryptkop *) op;

#ifndef __QNXNTO__
	wakeup_one(krp);
#else
	wakeup(krp);
#endif
	return (0);
}

static int
cryptodev_key(struct crypt_kop *kop)
{
	struct cryptkop *krp = NULL;
	int error = EINVAL;
	int in, out, size, i;
#ifdef __QNXNTO__
	int size_so_far = 0;
#endif

	if (kop->crk_iparams + kop->crk_oparams > CRK_MAXPARAM) {
		return (EFBIG);
	}

	in = kop->crk_iparams;
	out = kop->crk_oparams;
	switch (kop->crk_op) {
	case CRK_MOD_EXP:
		if (in == 3 && out == 1)
			break;
		return (EINVAL);
	case CRK_MOD_EXP_CRT:
		if (in == 6 && out == 1)
			break;
		return (EINVAL);
	case CRK_DSA_SIGN:
		if (in == 5 && out == 2)
			break;
		return (EINVAL);
	case CRK_DSA_VERIFY:
		if (in == 7 && out == 0)
			break;
		return (EINVAL);
	case CRK_DH_COMPUTE_KEY:
		if (in == 3 && out == 1)
			break;
		return (EINVAL);
	default:
		return (EINVAL);
	}

	krp = (struct cryptkop *)malloc(sizeof *krp, M_XDATA, M_WAITOK);
	if (!krp)
		return (ENOMEM);
	bzero(krp, sizeof *krp);
	krp->krp_op = kop->crk_op;
	krp->krp_status = kop->crk_status;
	krp->krp_iparams = kop->crk_iparams;
	krp->krp_oparams = kop->crk_oparams;
	krp->krp_status = 0;
	krp->krp_callback = (int (*) (struct cryptkop *)) cryptodevkey_cb;

	for (i = 0; i < CRK_MAXPARAM; i++)
		krp->krp_param[i].crp_nbits = kop->crk_param[i].crp_nbits;
	for (i = 0; i < krp->krp_iparams + krp->krp_oparams; i++) {
		size = (krp->krp_param[i].crp_nbits + 7) / 8;
		if (size == 0)
			continue;
		krp->krp_param[i].crp_p = malloc(size, M_XDATA, M_WAITOK);
		if (i >= krp->krp_iparams)
			continue;
#ifndef __QNXNTO__
		error = copyin(kop->crk_param[i].crp_p, krp->krp_param[i].crp_p, size);
#else
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		error = copyin((caddr_t)(kop+1) + size_so_far,
		    krp->krp_param[i].crp_p, 
		    size);
//		error = MsgRead(p->p_ctxt.rcvid, krp->krp_param[i].crp_p, size,
//		    sizeof(io_devctl_t) + sizeof(struct crypt_kop) + size_so_far);
		size_so_far += size;
//		if (error < 0)
//			error = errno;
//		error = altq_copyin(kop->crk_param[i].crp_p, krp->krp_param[i].crp_p, size);
#endif
		if (error)
			goto fail;
	}

	error = crypto_kdispatch(krp);
	if (error == 0)
		error = tsleep(krp, PSOCK, "crydev", 0);
	if (error)
		goto fail;

	if (krp->krp_status != 0) {
		error = krp->krp_status;
		goto fail;
	}

	for (i = krp->krp_iparams; i < krp->krp_iparams + krp->krp_oparams; i++) {
		size = (krp->krp_param[i].crp_nbits + 7) / 8;
		if (size == 0)
			continue;
#ifndef __QNXNTO__
		error = copyout(krp->krp_param[i].crp_p, kop->crk_param[i].crp_p, size);
#else
		curproc->p_vmspace.vm_flags |= VM_MSGLENCHECK;
		error = copyout(krp->krp_param[i].crp_p, (caddr_t)(kop+1) + size_so_far, size);
//		error = MsgWrite(p->p_ctxt.rcvid, krp->krp_param[i].crp_p, size,
//		    sizeof(io_devctl_t) + sizeof(struct crypt_kop) + size_so_far);
		size_so_far += size;
//		if (error < 0)
//			error = errno;
//		error = altq_copyout(krp->krp_param[i].crp_p, kop->crk_param[i].crp_p, size);
#endif
		if (error)
			goto fail;
	}

fail:
	if (krp) {
		kop->crk_status = krp->krp_status;
		for (i = 0; i < CRK_MAXPARAM; i++) {
			if (krp->krp_param[i].crp_p)
				FREE(krp->krp_param[i].crp_p, M_XDATA);
		}
		free(krp, M_XDATA);
	}
	return (error);
}

/* ARGSUSED */
static int
cryptof_close(struct file *fp, struct lwp *l)
{
	struct fcrypt *fcr = (struct fcrypt *)fp->f_data;
	struct csession *cse;

	while ((cse = TAILQ_FIRST(&fcr->csessions))) {
		TAILQ_REMOVE(&fcr->csessions, cse, next);
		(void)csefree(cse);
	}
	FREE(fcr, M_XDATA);

	/* close() stolen from sys/kern/kern_ktrace.c */

	fp->f_data = NULL;
#if 0
	FILE_UNUSE(fp, l);	/* release file */
	fdrelease(l, fd); 	/* release fd table slot */
#endif

	return 0;
}

static struct csession *
csefind(struct fcrypt *fcr, u_int ses)
{
	struct csession *cse;

	TAILQ_FOREACH(cse, &fcr->csessions, next)
		if (cse->ses == ses)
			return (cse);
	return (NULL);
}

static int
csedelete(struct fcrypt *fcr, struct csession *cse_del)
{
	struct csession *cse;

	TAILQ_FOREACH(cse, &fcr->csessions, next) {
		if (cse == cse_del) {
			TAILQ_REMOVE(&fcr->csessions, cse, next);
			return (1);
		}
	}
	return (0);
}

static struct csession *
cseadd(struct fcrypt *fcr, struct csession *cse)
{
	TAILQ_INSERT_TAIL(&fcr->csessions, cse, next);
	cse->ses = fcr->sesn++;
	return (cse);
}

static struct csession *
csecreate(struct fcrypt *fcr, u_int64_t sid, caddr_t key, u_int64_t keylen,
    caddr_t mackey, u_int64_t mackeylen, u_int32_t cipher, u_int32_t mac,
    struct enc_xform *txform, struct auth_hash *thash)
{
	struct csession *cse;
#ifndef __QNXNTO__

	MALLOC(cse, struct csession *, sizeof(struct csession),
	    M_XDATA, M_NOWAIT);
	if (cse == NULL)
		return NULL;
#else
	size_t size;

	size = offsetof(struct csession, work_iov) +
	    CRIO_IOV_MAX * sizeof(cse->work_iov[0]);
	MALLOC(cse, struct csession *, size,
	    M_XDATA, M_NOWAIT);
	if (cse == NULL)
		return NULL;
	memset(cse, 0x00, size);
#endif
	cse->key = key;
	cse->keylen = keylen/8;
	cse->mackey = mackey;
	cse->mackeylen = mackeylen/8;
	cse->sid = sid;
	cse->cipher = cipher;
	cse->mac = mac;
	cse->txform = txform;
	cse->thash = thash;
	cseadd(fcr, cse);
	return (cse);
}

static int
csefree(struct csession *cse)
{
	int error;

	error = crypto_freesession(cse->sid);
	if (cse->key)
		FREE(cse->key, M_XDATA);
	if (cse->mackey)
		FREE(cse->mackey, M_XDATA);
	FREE(cse, M_XDATA);
	return (error);
}

#ifndef __QNXNTO__
static int
cryptoopen(dev_t dev, int flag, int mode,
    struct lwp *l)
{
	if (crypto_usercrypto == 0)
		return (ENXIO);
	return (0);
}

static int
cryptoread(dev_t dev, struct uio *uio, int ioflag)
{
	return (EIO);
}

static int
cryptowrite(dev_t dev, struct uio *uio, int ioflag)
{
	return (EIO);
}

static int
cryptoioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
    struct lwp *l)
{
	struct file *f;
	struct fcrypt *fcr;
	int fd, error;

	switch (cmd) {
	case CRIOGET:
		MALLOC(fcr, struct fcrypt *,
		    sizeof(struct fcrypt), M_XDATA, M_WAITOK);
		TAILQ_INIT(&fcr->csessions);
		fcr->sesn = 0;

		error = falloc(l, &f, &fd);
		if (error) {
			FREE(fcr, M_XDATA);
			return (error);
		}
		f->f_flag = FREAD | FWRITE;
		f->f_type = DTYPE_CRYPTO;
		f->f_ops = &cryptofops;
		f->f_data = (caddr_t) fcr;
		*(u_int32_t *)data = fd;
		FILE_SET_MATURE(f);
		FILE_UNUSE(f, l);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

int
cryptoselect(dev_t dev, int rw, struct lwp *l)
{
	return (0);
}

/*static*/
struct cdevsw crypto_cdevsw = {
	/* open */	cryptoopen,
	/* close */	nullclose,
	/* read */	cryptoread,
	/* write */	cryptowrite,
	/* ioctl */	cryptoioctl,
	/* ttstop?*/	nostop,
	/* ??*/		notty,
	/* poll */	cryptoselect /*nopoll*/,
	/* mmap */	nommap,
	/* kqfilter */	nokqfilter,
	/* type */	D_OTHER,
};
#endif /* !__QNXNTO__ */

#if defined(__NetBSD__) || defined(__QNXNTO__)
/*
 * Pseudo-device initialization routine for /dev/crypto
 */
void	cryptoattach(int);

void
cryptoattach(int num)
{

	/* nothing to do */
}
#endif /* __NetBSD__ */



#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/opencrypto/cryptodev.c $ $Rev: 776559 $")
#endif
