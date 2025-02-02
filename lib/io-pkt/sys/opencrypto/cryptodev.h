/*
 * $QNXtpLicenseC:
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

/*	$NetBSD: cryptodev.h,v 1.7 2005/11/25 16:16:46 thorpej Exp $ */
/*	$FreeBSD: src/sys/opencrypto/cryptodev.h,v 1.2.2.6 2003/07/02 17:04:50 sam Exp $	*/
/*	$OpenBSD: cryptodev.h,v 1.33 2002/07/17 23:52:39 art Exp $	*/

/*
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
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

#ifndef _CRYPTO_CRYPTODEV_H_INCLUDED
#define _CRYPTO_CRYPTODEV_H_INCLUDED

#ifndef __QNXNTO__
#include <sys/ioccom.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#include <time.h>
#endif

/* Some initial values */
#define CRYPTO_DRIVERS_INITIAL	4
#define CRYPTO_SW_SESSIONS	32

/* THIS COMES FROM FREEBSD, NETBSD had not defined HASH_MAX_LEN */
#ifdef __QNXNTO__
/* Hash values */
#define NULL_HASH_LEN           16
#define MD5_HASH_LEN            16
#define SHA1_HASH_LEN           20
#define RIPEMD160_HASH_LEN      20
#define SHA2_256_HASH_LEN       32
#define SHA2_384_HASH_LEN       48
#define SHA2_512_HASH_LEN       64
#define MD5_KPDK_HASH_LEN       16
#define SHA1_KPDK_HASH_LEN      20
/* Maximum hash algorithm result length */
#define HASH_MAX_LEN            SHA2_512_HASH_LEN /* Keep this updated */
#endif

/* HMAC values */
#define HMAC_BLOCK_LEN		64
#define HMAC_IPAD_VAL		0x36
#define HMAC_OPAD_VAL		0x5C

/* Encryption algorithm block sizes */
#define DES_BLOCK_LEN		8
#define DES3_BLOCK_LEN		8
#define BLOWFISH_BLOCK_LEN	8
#define SKIPJACK_BLOCK_LEN	8
#define CAST128_BLOCK_LEN	8
#define RIJNDAEL128_BLOCK_LEN	16
#define EALG_MAX_BLOCK_LEN	16 /* Keep this updated */

/* Maximum hash algorithm result length */
#define AALG_MAX_RESULT_LEN	64 /* Keep this updated */

#define	CRYPTO_ALGORITHM_MIN			1
#define CRYPTO_DES_CBC				1
#define CRYPTO_3DES_CBC				2
#define CRYPTO_BLF_CBC				3
#define CRYPTO_CAST_CBC				4
#define CRYPTO_SKIPJACK_CBC			5
#define CRYPTO_MD5_HMAC				6
#define CRYPTO_SHA1_HMAC			7
#define CRYPTO_RIPEMD160_HMAC			8
#define CRYPTO_MD5_KPDK				9
#define CRYPTO_SHA1_KPDK			10
#define CRYPTO_RIJNDAEL128_CBC			11 /* 128 bit blocksize */
#define CRYPTO_AES_CBC				11 /* 128 bit blocksize -- the same as above */
#define CRYPTO_ARC4				12
#define CRYPTO_MD5				13
#define CRYPTO_SHA1				14
#define CRYPTO_SHA2_256_HMAC			15
#define CRYPTO_SHA2_HMAC			CRYPTO_SHA2_256_HMAC /* for compatibility */
#define CRYPTO_NULL_HMAC			16
#define CRYPTO_NULL_CBC				17
#define CRYPTO_DEFLATE_COMP			18 /* Deflate compression algorithm */
/* updated */
/*	$NetBSD: cryptodev.h,v 1.24 2011/05/26 21:50:03 drochner Exp $ */
#define CRYPTO_MD5_HMAC_96			19
#define CRYPTO_SHA1_HMAC_96			20
#define CRYPTO_RIPEMD160_HMAC_96		21
#define CRYPTO_GZIP_COMP			22 /* gzip compression algorithm */
#define CRYPTO_DEFLATE_COMP_NOGROW		23 /* Deflate, fail if not compressible */
#define CRYPTO_SHA2_384_HMAC			24
#define CRYPTO_SHA2_512_HMAC			25
#define CRYPTO_CAMELLIA_CBC			26
#define CRYPTO_AES_CTR				27
#define CRYPTO_AES_XCBC_MAC			28 /* backwards compatibility */
#define CRYPTO_AES_XCBC_MAC_96			28
#define CRYPTO_AES_GCM_16			29
#define CRYPTO_AES_128_GMAC			30
#define CRYPTO_AES_192_GMAC			31
#define CRYPTO_AES_256_GMAC			32
#define CRYPTO_AES_GMAC				33
/* specific to OMAP5*/
#define CRYPTO_SHA2_224				34
#define CRYPTO_SHA2_256				35
#define CRYPTO_SHA2_384				36
#define CRYPTO_SHA2_512				37
#define CRYPTO_SHA2_224_HMAC			38
/* specific to ti crypto */
#define CRYPTO_AES_CBC_HW			39 /* 128 bit blocksize -- the same as above */
#define CRYPTO_AES_CTR_HW			40 /* 128 bit blocksize -- the same as above */
#define CRYPTO_SHA1_HW				41
#define CRYPTO_SHA2_256_HW			42
#define CRYPTO_SHA2_384_HW			43
#define CRYPTO_SHA2_512_HW			44
#define CRYPTO_MD5_HMAC_HW			45
#define CRYPTO_SHA1_HMAC_HW			46
#define CRYPTO_SHA2_HMAC_HW			47
#define CRYPTO_MD5_HW				48
/* End of List */
#define CRYPTO_ALGORITHM_MAX			49 /* Keep updated - see below */

/* Algorithm flags */
#define	CRYPTO_ALG_FLAG_SUPPORTED		0x01 /* Algorithm is supported */
#define	CRYPTO_ALG_FLAG_RNG_ENABLE		0x02 /* Has HW RNG for DH/DSA */
#define	CRYPTO_ALG_FLAG_DSA_SHA			0x04 /* Can do SHA on msg */

#define CRYPTO_FLAG_ECB				0x0000
#define CRYPTO_FLAG_CBC				0x0001
#define CRYPTO_FLAG_CFB				0x0002
#define CRYPTO_FLAG_OFB				0x0003
#define CRYPTO_FLAG_CTR				0x0004
#define CRYPTO_FLAG_HMAC			0x0010
#define CRYPTO_FLAG_MASK			0x00FF

struct session_op {
	uint32_t	cipher;		/* ie. CRYPTO_DES_CBC */
	uint32_t	mac;		/* ie. CRYPTO_MD5_HMAC */

	uint32_t	keylen;		/* cipher key */
	caddr_t		key;
#ifndef __QNXNTO__
	int		mackeylen;	/* mac key */
#else
	uint32_t	mackeylen;
#endif
	caddr_t		mackey;

  	uint64_t	ses;		/* returns: session # */
};

struct crypt_op {
	uint64_t	ses;
	uint16_t	op;		/* i.e. COP_ENCRYPT */
#define COP_ENCRYPT	1
#define COP_DECRYPT	2
	uint16_t	flags;
#define	COP_F_BATCH 	0x0008		/* Dispatch as quickly as possible */
	uint32_t	len;
	caddr_t		src, dst;	/* become iov[] inside kernel */
	caddr_t		mac;		/* must be big enough for chosen MAC */
	caddr_t		iv;
};

#ifndef __QNXNTO__
#define CRYPTO_MAX_MAC_LEN	20
#else
#define CRYPTO_MAX_MAC_LEN	HASH_MAX_LEN	
#endif

/* bignum parameter, in packed bytes, ... */
struct crparam {
	caddr_t		crp_p;
	u_int		crp_nbits;
};

#define CRK_MAXPARAM	8

struct crypt_kop {
	u_int		crk_op;		/* ie. CRK_MOD_EXP or other */
	u_int		crk_status;	/* return status */
	u_short		crk_iparams;	/* # of input parameters */
	u_short		crk_oparams;	/* # of output parameters */
	u_int		crk_pad1;
	struct crparam	crk_param[CRK_MAXPARAM];
};
#define	CRK_ALGORITM_MIN	0
#define CRK_MOD_EXP		0
#define CRK_MOD_EXP_CRT		1
#define CRK_DSA_SIGN		2
#define CRK_DSA_VERIFY		3
#define CRK_DH_COMPUTE_KEY	4
#define CRK_ALGORITHM_MAX	4 /* Keep updated - see below */

#define CRF_MOD_EXP		(1 << CRK_MOD_EXP)
#define CRF_MOD_EXP_CRT		(1 << CRK_MOD_EXP_CRT)
#define CRF_DSA_SIGN		(1 << CRK_DSA_SIGN)
#define CRF_DSA_VERIFY		(1 << CRK_DSA_VERIFY)
#define CRF_DH_COMPUTE_KEY	(1 << CRK_DH_COMPUTE_KEY)

/*
 * done against open of /dev/crypto, to get a cloned descriptor.
 * Please use F_SETFD against the cloned descriptor.
 */
#define	CRIOGET		_IOWR('c', 100, uint32_t)

/* the following are done against the cloned descriptor */
#define	CIOCGSESSION	_IOWR('c', 101, struct session_op)
#define	CIOCFSESSION	_IOW('c', 102, uint32_t)
#define CIOCCRYPT	_IOWR('c', 103, struct crypt_op)
#define CIOCKEY		_IOWR('c', 104, struct crypt_kop)

#define CIOCASYMFEAT	_IOR('c', 105, uint32_t)

struct cryptotstat {
	struct timespec	acc;		/* total accumulated time */
	struct timespec	min;		/* max time */
	struct timespec	max;		/* max time */
	uint32_t	count;		/* number of observations */
};

struct cryptostats {
	uint32_t	cs_ops;		/* symmetric crypto ops submitted */
	uint32_t	cs_errs;	/* symmetric crypto ops that failed */
	uint32_t	cs_kops;	/* asymetric/key ops submitted */
	uint32_t	cs_kerrs;	/* asymetric/key ops that failed */
	uint32_t	cs_intrs;	/* crypto swi thread activations */
	uint32_t	cs_rets;	/* crypto return thread activations */
	uint32_t	cs_blocks;	/* symmetric op driver block */
	uint32_t	cs_kblocks;	/* symmetric op driver block */
	/*
	 * When CRYPTO_TIMING is defined at compile time and the
	 * sysctl debug.crypto is set to 1, the crypto system will
	 * accumulate statistics about how long it takes to process
	 * crypto requests at various points during processing.
	 */
	struct cryptotstat cs_invoke;	/* crypto_dipsatch -> crypto_invoke */
	struct cryptotstat cs_done;	/* crypto_invoke -> crypto_done */
	struct cryptotstat cs_cb;	/* crypto_done -> callback */
	struct cryptotstat cs_finis;	/* callback -> callback return */
};

#ifdef _KERNEL
/* Standard initialization structure beginning */
struct cryptoini {
	int		cri_alg;	/* Algorithm to use */
	int		cri_klen;	/* Key length, in bits */
	int		cri_rnd;	/* Algorithm rounds, where relevant */
	caddr_t		cri_key;	/* key to use */
	u_int8_t	cri_iv[EALG_MAX_BLOCK_LEN];	/* IV to use */
	struct cryptoini *cri_next;
};

/* Describe boundaries of a single crypto operation */
struct cryptodesc {
	int		crd_skip;	/* How many bytes to ignore from start */
	int		crd_len;	/* How many bytes to process */
	int		crd_inject;	/* Where to inject results, if applicable */
	int		crd_flags;

#define	CRD_F_ENCRYPT		0x01	/* Set when doing encryption */
#define	CRD_F_IV_PRESENT	0x02	/* When encrypting, IV is already in
					   place, so don't copy. */
#define	CRD_F_IV_EXPLICIT	0x04	/* IV explicitly provided */
#define	CRD_F_DSA_SHA_NEEDED	0x08	/* Compute SHA-1 of buffer for DSA */
#define CRD_F_COMP		0x0f    /* Set when doing compression */

	struct cryptoini	CRD_INI; /* Initialization/context data */
#define crd_iv		CRD_INI.cri_iv
#define crd_key		CRD_INI.cri_key
#define crd_rnd		CRD_INI.cri_rnd
#define crd_alg		CRD_INI.cri_alg
#define crd_klen	CRD_INI.cri_klen

	struct cryptodesc *crd_next;
};

/* Structure describing complete operation */
struct cryptop {
	TAILQ_ENTRY(cryptop) crp_next;
#ifdef __QNXNTO__
	struct cryptop	*crp_inext;
	int		crp_onqueue;
#endif

	u_int64_t	crp_sid;	/* Session ID */
	int		crp_ilen;	/* Input data total length */
	int		crp_olen;	/* Result total length */

	int		crp_etype;	/*
					 * Error type (zero means no error).
					 * All error codes except EAGAIN
					 * indicate possible data corruption (as in,
					 * the data have been touched). On all
					 * errors, the crp_sid may have changed
					 * (reset to a new one), so the caller
					 * should always check and use the new
					 * value on future requests.
					 */
	int		crp_flags;

#define CRYPTO_F_IMBUF		0x0001	/* Input/output are mbuf chains */
#define CRYPTO_F_IOV		0x0002	/* Input/output are uio */
#define CRYPTO_F_REL		0x0004	/* Must return data in same place */
#define	CRYPTO_F_BATCH		0x0008	/* Batch op if possible possible */
#define	CRYPTO_F_CBIMM		0x0010	/* Do callback immediately */
#define	CRYPTO_F_DONE		0x0020	/* Operation completed */
#define	CRYPTO_F_CBIFSYNC	0x0040	/* Do CBIMM if op is synchronous */

	caddr_t		crp_buf;	/* Data to be processed */
	caddr_t		crp_opaque;	/* Opaque pointer, passed along */
	struct cryptodesc *crp_desc;	/* Linked list of processing descriptors */

	int (*crp_callback)(struct cryptop *); /* Callback function */

	caddr_t		crp_mac;
	struct timespec	crp_tstamp;	/* performance time stamp */
};

#define CRYPTO_BUF_CONTIG	0x0
#define CRYPTO_BUF_IOV		0x1
#define CRYPTO_BUF_MBUF		0x2

#define CRYPTO_OP_DECRYPT	0x0
#define CRYPTO_OP_ENCRYPT	0x1

/*
 * Hints passed to process methods.
 */
#define	CRYPTO_HINT_MORE	0x1	/* more ops coming shortly */

struct cryptkop {
	TAILQ_ENTRY(cryptkop) krp_next;

	u_int		krp_op;		/* ie. CRK_MOD_EXP or other */
	u_int		krp_status;	/* return status */
	u_short		krp_iparams;	/* # of input parameters */
	u_short		krp_oparams;	/* # of output parameters */
	u_int32_t	krp_hid;
	struct crparam	krp_param[CRK_MAXPARAM];	/* kvm */
	int		(*krp_callback)(struct cryptkop *);
};

/* Crypto capabilities structure */
struct cryptocap {
	u_int32_t	cc_sessions;

	/*
	 * Largest possible operator length (in bits) for each type of
	 * encryption algorithm.
	 */
	u_int16_t	cc_max_op_len[CRYPTO_ALGORITHM_MAX + 1];

	u_int8_t	cc_alg[CRYPTO_ALGORITHM_MAX + 1];

	u_int8_t	cc_kalg[CRK_ALGORITHM_MAX + 1];

	u_int8_t	cc_flags;
	u_int8_t	cc_qblocked;		/* symmetric q blocked */
	u_int8_t	cc_kqblocked;		/* asymmetric q blocked */
#define CRYPTOCAP_F_CLEANUP	0x01		/* needs resource cleanup */
#define CRYPTOCAP_F_SOFTWARE	0x02		/* software implementation */
#define CRYPTOCAP_F_SYNC	0x04		/* operates synchronously */

	void		*cc_arg;		/* callback argument */
	int		(*cc_newsession)(void*, u_int32_t*, struct cryptoini*);
	int		(*cc_process) (void*, struct cryptop *, int);
	int		(*cc_freesession) (void*, u_int64_t);
	void		*cc_karg;		/* callback argument */
	int		(*cc_kprocess) (void*, struct cryptkop *, int);
};

/*
 * Session ids are 64 bits.  The lower 32 bits contain a "local id" which
 * is a driver-private session identifier.  The upper 32 bits contain a
 * "hardware id" used by the core crypto code to identify the driver and
 * a copy of the driver's capabilities that can be used by client code to
 * optimize operation.
 */
#define	CRYPTO_SESID2HID(_sid)	(((_sid) >> 32) & 0xffffff)
#define	CRYPTO_SESID2CAPS(_sid)	(((_sid) >> 56) & 0xff)
#define	CRYPTO_SESID2LID(_sid)	(((u_int32_t) (_sid)) & 0xffffffff)

MALLOC_DECLARE(M_CRYPTO_DATA);

extern	int crypto_newsession(u_int64_t *sid, struct cryptoini *cri, int hard);
extern	int crypto_freesession(u_int64_t sid);
extern	int32_t crypto_get_driverid(u_int32_t flags);
extern	int crypto_register(u_int32_t driverid, int alg, u_int16_t maxoplen,
	    u_int32_t flags,
	    int (*newses)(void*, u_int32_t*, struct cryptoini*),
	    int (*freeses)(void*, u_int64_t),
	    int (*process)(void*, struct cryptop *, int),
	    void *arg);
extern	int crypto_kregister(u_int32_t, int, u_int32_t,
	    int (*)(void*, struct cryptkop *, int),
	    void *arg);
extern	int crypto_unregister(u_int32_t driverid, int alg);
extern	int crypto_unregister_all(u_int32_t driverid);
extern	int crypto_dispatch(struct cryptop *crp);
extern	int crypto_kdispatch(struct cryptkop *);
#define	CRYPTO_SYMQ	0x1
#define	CRYPTO_ASYMQ	0x2
extern	int crypto_unblock(u_int32_t, int);
extern	void crypto_done(struct cryptop *crp);
extern	void crypto_kdone(struct cryptkop *);
extern	int crypto_getfeat(int *);

void	cuio_copydata(struct uio *, int, int, caddr_t);
void	cuio_copyback(struct uio *, int, int, caddr_t);
int	cuio_apply(struct uio *, int, int,
	    int (*f)(caddr_t, caddr_t, unsigned int), caddr_t);

extern	void crypto_freereq(struct cryptop *crp);
extern	struct cryptop *crypto_getreq(int num);

extern int cryptodev_open(struct lwp *l, struct file **retval);

extern	int crypto_usercrypto;		/* userland may do crypto requests */
extern	int crypto_userasymcrypto;	/* userland may do asym crypto reqs */
extern	int crypto_devallowsoft;	/* only use hardware crypto */


/*
 * initialize the crypto framework subsystem (not the pseudo-device).
 * This must be called very early in boot, so the framework is ready
 * to handle registration requests when crpto hardware is autoconfigured.
 * (This declaration doesnt really belong here but there's no header
 * for the raw framework.)
 */
void	crypto_init(void);

/*
 * Crypto-related utility routines used mainly by drivers.
 *
 * XXX these don't really belong here; but for now they're
 *     kept apart from the rest of the system.
 */
struct mbuf;
struct	mbuf	*m_getptr(struct mbuf *, int, int *);

struct uio;
extern	void cuio_copydata(struct uio* uio, int off, int len, caddr_t cp);
extern	void cuio_copyback(struct uio* uio, int off, int len, caddr_t cp);
#ifdef __FreeBSD__
extern struct iovec *cuio_getptr(struct uio *uio, int loc, int *off);
#else
extern int	cuio_getptr(struct uio *, int loc, int *off);
#endif

#ifdef __FreeBSD__	/* Standalone m_apply()/m_getptr() */
extern  int m_apply(struct mbuf *m, int off, int len,
                    int (*f)(caddr_t, caddr_t, unsigned int), caddr_t fstate);
extern  struct mbuf * m_getptr(struct mbuf *m, int loc, int *off);
#endif	/* Standalone m_apply()/m_getptr() */

#endif /* _KERNEL */
#endif /* _CRYPTO_CRYPTODEV_H_INCLUDED */



#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/opencrypto/cryptodev.h $ $Rev: 776559 $")
#endif
