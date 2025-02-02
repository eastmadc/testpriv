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

/*	$NetBSD: xform.c,v 1.15 2005/11/25 16:16:46 thorpej Exp $ */
/*	$FreeBSD: src/sys/opencrypto/xform.c,v 1.1.2.1 2002/11/21 23:34:23 sam Exp $	*/
/*	$OpenBSD: xform.c,v 1.19 2002/08/16 22:47:25 dhartmei Exp $	*/

/*
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr) and
 * Niels Provos (provos@physnet.uni-hamburg.de).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece,
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Additional features in 1999 by Angelos D. Keromytis.
 *
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 by John Ioannidis,
 * Angelos D. Keromytis and Niels Provos.
 *
 * Copyright (C) 2001, Angelos D. Keromytis.
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software.
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: xform.c,v 1.15 2005/11/25 16:16:46 thorpej Exp $");

#include <sys/param.h>
#include <sys/malloc.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/xform.h>

MALLOC_DEFINE(M_XDATA, "xform", "xform data buffers");

const u_int8_t hmac_ipad_buffer[64] = {
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

const u_int8_t hmac_opad_buffer[64] = {
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};

/* Encryption instances */
struct enc_xform enc_xform_null = {
	CRYPTO_NULL_CBC, "NULL",
	/* NB: blocksize of 4 is to generate a properly aligned ESP header */
	4, 0, 256 /* 2048 bits, max key */
};

struct enc_xform enc_xform_des = {
	CRYPTO_DES_CBC, "DES",
	8, 8, 8
};

struct enc_xform enc_xform_3des = {
	CRYPTO_3DES_CBC, "3DES",
	8, 24, 24
};

struct enc_xform enc_xform_blf = {
	CRYPTO_BLF_CBC, "Blowfish",
	8, 5, 56 /* 448 bits, max key */
};

struct enc_xform enc_xform_cast5 = {
	CRYPTO_CAST_CBC, "CAST-128",
	8, 5, 16
};

struct enc_xform enc_xform_skipjack = {
	CRYPTO_SKIPJACK_CBC, "Skipjack",
	8, 10, 10
};

struct enc_xform enc_xform_rijndael128 = {
	CRYPTO_RIJNDAEL128_CBC, "Rijndael-128/AES",
	16, 8, 32
};

struct enc_xform enc_xform_arc4 = {
	CRYPTO_ARC4, "ARC4",
	1, 1, 32
};

struct enc_xform enc_xform_aes_ctr = {
	CRYPTO_AES_CTR, "AES-CTR",
	16, 16, 32
};

struct enc_xform enc_xform_aes_cbc_hw = {
	CRYPTO_AES_CBC_HW, "AES-CBC-HW",
	16, 8, 32
};

struct enc_xform enc_xform_aes_ctr_hw = {
	CRYPTO_AES_CTR_HW, "AES-CTR-HW",
	16, 16, 32
};


/* Authentication instances */
struct auth_hash auth_hash_null = {
	CRYPTO_NULL_HMAC, "NULL-HMAC",
	0, 0, 12, sizeof(int)			/* NB: context isn't used */
};

struct auth_hash auth_hash_hmac_md5 = {
	CRYPTO_MD5_HMAC, "HMAC-MD5",
	16, 16, 16, 64
};

struct auth_hash auth_hash_hmac_sha1 = {
	CRYPTO_SHA1_HMAC, "HMAC-SHA1",
	20, 20, 20, 64
};

struct auth_hash auth_hash_hmac_md5_96 = {
	CRYPTO_MD5_HMAC, "HMAC-MD5",
	16, 16, 12, sizeof(MD5_CTX)
};

struct auth_hash auth_hash_hmac_sha1_96 = {
	CRYPTO_SHA1_HMAC, "HMAC-SHA1",
	20, 20, 12, sizeof(SHA1_CTX)
};

struct auth_hash auth_hash_hmac_ripemd_160_96 = {
	CRYPTO_RIPEMD160_HMAC, "HMAC-RIPEMD-160",
	20, 20, 12, sizeof(RMD160_CTX)
};

struct auth_hash auth_hash_key_md5 = {
	CRYPTO_MD5_KPDK, "Keyed MD5",
	0, 16, 16, sizeof(MD5_CTX)
};

struct auth_hash auth_hash_key_sha1 = {
	CRYPTO_SHA1_KPDK, "Keyed SHA1",
	0, 20, 20, sizeof(SHA1_CTX)
};

struct auth_hash auth_hash_md5 = {
	CRYPTO_MD5, "MD5",
	0, 16, 16, sizeof(MD5_CTX)
};

struct auth_hash auth_hash_sha1 = {
	CRYPTO_SHA1, "SHA1",
	0, 20, 20, sizeof(SHA1_CTX)
};


struct auth_hash auth_hash_sha2_224 = {
	CRYPTO_SHA2_224, "SHA2 224",
	0, 28, 28, sizeof(SHA256_CTX)
};

struct auth_hash auth_hash_sha2_256 = {
	CRYPTO_SHA2_256, "SHA2 256",
	0, 32, 32, sizeof(SHA256_CTX)
};

struct auth_hash auth_hash_sha2_384 = {
	CRYPTO_SHA2_384, "SHA2 384",
	0, 48, 48, sizeof(SHA384_CTX)
};

struct auth_hash auth_hash_sha2_512 = {
	CRYPTO_SHA2_512, "SHA2 512",
	0, 64, 64, sizeof(SHA512_CTX)
};

struct auth_hash auth_hash_hmac_sha2_256 = {
	CRYPTO_SHA2_HMAC, "HMAC-SHA2",
	32, 32, 12, sizeof(SHA256_CTX)
};

struct auth_hash auth_hash_hmac_sha2_384 = {
	CRYPTO_SHA2_HMAC, "HMAC-SHA2-384",
	48, 48, 12, sizeof(SHA384_CTX)
};

struct auth_hash auth_hash_hmac_sha2_512 = {
	CRYPTO_SHA2_HMAC, "HMAC-SHA2-512",
	64, 64, 12, sizeof(SHA512_CTX)
};

#ifdef __QNXNTO__
struct auth_hash auth_hash_aes_xcbc_mac = {
	CRYPTO_AES_XCBC_MAC, "AES-XCBC-MAC",
	16, 16, 12, sizeof(AESXCBCMAC_CTX)
};	
#endif

/* Compression instance */
struct comp_algo comp_algo_deflate = {
	CRYPTO_DEFLATE_COMP, "Deflate",
	90
};



#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/opencrypto/xform.c $ $Rev: 776559 $")
#endif
