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


/*	$NetBSD: ah_aesxcbcmac.h,v 1.2 2005/12/10 23:39:56 elad Exp $	*/
/*	$KAME: ah_aesxcbcmac.h,v 1.2 2003/07/20 00:29:37 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998 and 2003 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET6_AH_AESXCBCMAC_H_
#define _NETINET6_AH_AESXCBCMAC_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <inttypes.h>
#include <crypto/rijndael/rijndael.h>

#define AES_BLOCKSIZE			16
#define AESXCBCMAC_DIGEST_LENGTH 	16

/* AES_XCBC_MAC context */ 
typedef struct AESXCBCMACContext {
	uint8_t		e[AES_BLOCKSIZE];
	uint8_t		buf[AES_BLOCKSIZE];
	size_t 		buflen;
	uint32_t	r_k1s[(RIJNDAEL_MAXNR+1)*4];
	uint32_t	r_k2s[(RIJNDAEL_MAXNR+1)*4];
	uint32_t	r_k3s[(RIJNDAEL_MAXNR+1)*4];
	int		r_nr; /* key-length-dependent number of rounds */
	uint8_t		k2[AES_BLOCKSIZE];
	uint8_t 	k3[AES_BLOCKSIZE]; 
} AESXCBCMAC_CTX;

__BEGIN_DECLS
int ah_aes_xcbc_mac_init(AESXCBCMAC_CTX *, const uint8_t*, int);
void ah_aes_xcbc_mac_loop(AESXCBCMAC_CTX *, const unsigned char *, u_int16_t);
void ah_aes_xcbc_mac_result(unsigned char[AESXCBCMAC_DIGEST_LENGTH], AESXCBCMAC_CTX *);
__END_DECLS

#endif /* !_NETINET6_AH_AESXCBCMAC_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/aesxcbcmac.h $ $Rev: 680336 $")
#endif
