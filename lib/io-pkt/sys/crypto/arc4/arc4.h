/*	$NetBSD: arc4.h,v 1.4 2005/12/11 12:20:48 christos Exp $	*/

/*
 * ARC4 implementation
 *	A Stream Cipher Encryption Algorithm "Arcfour"
 *	<draft-kaukonen-cipher-arcfour-03.txt>
 */

/*        This code illustrates a sample implementation
 *                 of the Arcfour algorithm
 *         Copyright (c) April 29, 1997 Kalle Kaukonen.
 *                    All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that this copyright
 * notice and disclaimer are retained.
 *
 * THIS SOFTWARE IS PROVIDED BY KALLE KAUKONEN AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL KALLE
 * KAUKONEN OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _CRYPTO_ARC4_H_
#define	_CRYPTO_ARC4_H_

int arc4_ctxlen(void);
void arc4_setkey(void *, const u_char *, unsigned int);
void arc4_encrypt(void *, u_char *, const u_char *, int);
void arc4_decrypt(void *, u_char *, const u_char *, int);

#endif /* _CRYPTO_ARC4_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/crypto/arc4/arc4.h $ $Rev: 680336 $")
#endif
