/*	$NetBSD: keydb.h,v 1.26 2005/12/11 00:02:28 elad Exp $	*/
/*	$KAME: keydb.h,v 1.23 2003/09/07 05:25:20 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#ifndef _NETKEY_KEYDB_H_INCLUDED
#define _NETKEY_KEYDB_H_INCLUDED

#ifdef _KERNEL

#if defined(_KERNEL_OPT)
#include "opt_ipsec.h"
#endif

#ifndef __MALLOCVAR_H_INCLUDED
#include <sys/mallocvar.h>
#endif

#ifndef _NETKEY_KEY_VAR_H_INCLUDED
#include <netkey/key_var.h>
#endif

#ifndef __QUEUE_H_INCLUDED
#include <sys/queue.h>
#endif

#ifndef _NETINET_IN_H_INCLUDED
#include <netinet/in.h>
#endif

MALLOC_DECLARE(M_SECA);

/* Security Assocciation Index */
/* NOTE: Ensure to be same address family */
struct secasindex {
	struct sockaddr_storage src;	/* srouce address for SA */
	struct sockaddr_storage dst;	/* destination address for SA */
	uint16_t proto;			/* IPPROTO_ESP or IPPROTO_AH */
	uint8_t mode;			/* mode of protocol, see ipsec.h */
	uint16_t reqid;			/* reqid id who owned this SA */
					/* see IPSEC_MANUAL_REQID_MAX. */
};

/* Security Association Data Base */
struct secashead {
	LIST_ENTRY(secashead) chain;

	struct secasindex saidx;

	struct sadb_ident *idents;	/* source identity */
	struct sadb_ident *identd;	/* destination identity */
					/* XXX I don't know how to use them. */

	uint8_t state;			/* MATURE or DEAD. */
	LIST_HEAD(_satree, secasvar) savtree[SADB_SASTATE_MAX+1];
					/* SA chain */
					/* The first of this list is newer SA */

	union {
		struct route sau_route;
		struct route_in6 sau_route6;
	} sa_u;
#define sa_route sa_u.sau_route
};

/* Security Association */
struct secasvar {
	TAILQ_ENTRY(secasvar) tailq;
	LIST_ENTRY(secasvar) chain;
	LIST_ENTRY(secasvar) spihash;

	int refcnt;			/* reference count */
	uint8_t state;			/* Status of this Association */

	uint8_t alg_auth;		/* Authentication Algorithm Identifier*/
	uint8_t alg_enc;		/* Cipher Algorithm Identifier */
	uint32_t spi;			/* SPI Value, network byte order */
	uint32_t flags;			/* holder for SADB_KEY_FLAGS */

	struct sadb_key *key_auth;	/* Key for Authentication */
	struct sadb_key *key_enc;	/* Key for Encryption */
	caddr_t iv;			/* Initilization Vector */
	u_int ivlen;			/* length of IV */
	void *sched;			/* intermediate encryption key */
	size_t schedlen;

	struct secreplay *replay;	/* replay prevention */
	long created;			/* for lifetime */

	struct sadb_lifetime *lft_c;	/* CURRENT lifetime, it's constant. */
	struct sadb_lifetime *lft_h;	/* HARD lifetime */
	struct sadb_lifetime *lft_s;	/* SOFT lifetime */

	uint64_t seq;			/* sequence number */
	pid_t pid;			/* message's pid */

	struct secashead *sah;		/* back pointer to the secashead */

	uint32_t id;			/* SA id */
	/* Nat-Traversal state */
#ifdef IPSEC_NAT_T
	uint16_t	natt_type;
	uint16_t	esp_frag;
#endif
};

/* replay prevention */
struct secreplay {
	uint64_t count;
	u_int wsize;		/* window size, i.g. 4 bytes */
	uint64_t seq;		/* used by sender */
	uint64_t lastseq;	/* used by receiver */
	uint8_t *bitmap;	/* used by receiver */
	int overflow;		/* what round does the counter take. */
};

/* socket table due to send PF_KEY messages. */
struct secreg {
	LIST_ENTRY(secreg) chain;

	struct socket *so;
};

#ifndef IPSEC_NONBLOCK_ACQUIRE
/* acquiring list table. */
struct secacq {
	LIST_ENTRY(secacq) chain;

	struct secasindex saidx;

	uint32_t seq;		/* sequence number */
	long created;		/* for lifetime */
	int count;		/* for lifetime */
};
#endif

/* Sensitivity Level Specification */
/* nothing */

#define SADB_KILL_INTERVAL	600	/* six seconds */

struct key_cb {
	int key_count;
	int any_count;
};

/* secpolicy */
struct secpolicy;
struct secpolicyindex;
extern struct secpolicy *keydb_newsecpolicy __P((void));
extern uint32_t keydb_newspid __P((void));
extern void keydb_delsecpolicy __P((struct secpolicy *));
extern int keydb_setsecpolicyindex
	__P((struct secpolicy *, struct secpolicyindex *));
/* secashead */
extern struct secashead *keydb_newsecashead __P((void));
extern void keydb_delsecashead __P((struct secashead *));
/* secasvar */
extern struct secasvar *keydb_newsecasvar __P((void));
extern void keydb_delsecasvar __P((struct secasvar *));
/* secreplay */
extern struct secreplay *keydb_newsecreplay __P((size_t));
extern void keydb_delsecreplay __P((struct secreplay *));
/* secreg */
extern struct secreg *keydb_newsecreg __P((void));
extern void keydb_delsecreg __P((struct secreg *));

#endif /* _KERNEL */


#endif /* !_NETKEY_KEYDB_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/public/netkey/keydb.h $ $Rev: 680336 $")
#endif
