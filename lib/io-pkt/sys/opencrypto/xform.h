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

/*	$NetBSD: xform.h,v 1.8 2006/10/27 21:20:48 christos Exp $ */
/*	$FreeBSD: src/sys/opencrypto/xform.h,v 1.1.2.1 2002/11/21 23:34:23 sam Exp $	*/
/*	$OpenBSD: xform.h,v 1.10 2002/04/22 23:10:09 deraadt Exp $	*/

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
 */

#ifndef _CRYPTO_XFORM_H_
#define _CRYPTO_XFORM_H_

#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <sys/rmd160.h>
#ifdef __QNXNTO__
#include <sys/aesxcbcmac.h>
#endif

/* Declarations */
struct auth_hash {
	int type;
	const char *name;
	u_int16_t keysize;
	u_int16_t hashsize;
	u_int16_t authsize;
	u_int16_t ctxsize;
};

/* Provide array-limit for clients (e.g., netipsec) */
#define	AH_ALEN_MAX	20	/* max authenticator hash length */

struct enc_xform {
	int type;
	const char *name;
	u_int16_t blocksize;
	u_int16_t minkey, maxkey;
};

struct comp_algo {
	int type;
	const char *name;
	size_t minlen;
};

extern const u_int8_t hmac_ipad_buffer[64];
extern const u_int8_t hmac_opad_buffer[64];

extern struct enc_xform enc_xform_null;
extern struct enc_xform enc_xform_des;
extern struct enc_xform enc_xform_3des;
extern struct enc_xform enc_xform_blf;
extern struct enc_xform enc_xform_cast5;
extern struct enc_xform enc_xform_skipjack;
extern struct enc_xform enc_xform_rijndael128;
extern struct enc_xform enc_xform_arc4;
#ifdef __QNXNTO__
extern struct enc_xform enc_xform_aes_ctr;
extern struct enc_xform enc_xform_aes_cbc_hw;
extern struct enc_xform enc_xform_aes_ctr_hw;
#endif

extern struct auth_hash auth_hash_null;
extern struct auth_hash auth_hash_md5;
extern struct auth_hash auth_hash_sha1;
extern struct auth_hash auth_hash_key_md5;
extern struct auth_hash auth_hash_key_sha1;
#ifdef __QNXNTO__
extern struct auth_hash auth_hash_sha2_224;
extern struct auth_hash auth_hash_sha2_256;
extern struct auth_hash auth_hash_sha2_384;
extern struct auth_hash auth_hash_sha2_512;
extern struct auth_hash auth_hash_hmac_md5;
extern struct auth_hash auth_hash_hmac_sha1;
#endif
extern struct auth_hash auth_hash_hmac_md5_96;
extern struct auth_hash auth_hash_hmac_sha1_96;
extern struct auth_hash auth_hash_hmac_ripemd_160_96;
extern struct auth_hash auth_hash_hmac_sha2_256;
extern struct auth_hash auth_hash_hmac_sha2_384;
extern struct auth_hash auth_hash_hmac_sha2_512;
#ifdef __QNXNTO__
extern struct auth_hash auth_hash_aes_xcbc_mac;
#endif

extern struct comp_algo comp_algo_deflate;

#ifdef _KERNEL
#include <sys/malloc.h>
MALLOC_DECLARE(M_XDATA);
#endif
#endif /* _CRYPTO_XFORM_H_ */



#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/opencrypto/xform.h $ $Rev: 776559 $")
#endif
