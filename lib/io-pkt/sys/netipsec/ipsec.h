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

/*	$NetBSD: ipsec.h,v 1.17 2006/11/16 01:33:49 christos Exp $	*/
/*	$FreeBSD: /usr/local/www/cvsroot/FreeBSD/src/sys/netipsec/ipsec.h,v 1.2.4.2 2004/02/14 22:23:23 bms Exp $	*/
/*	$KAME: ipsec.h,v 1.53 2001/11/20 08:32:38 itojun Exp $	*/

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

/*
 * IPsec controller part.
 */

#ifndef _NETIPSEC_IPSEC_H_INCLUDED
#define _NETIPSEC_IPSEC_H_INCLUDED

#if defined(_KERNEL) && !defined(_LKM) && !defined(KLD_MODULE)
#include "opt_inet.h"
#include "opt_ipsec.h"
#endif

#include <net/pfkeyv2.h>
#ifdef _KERNEL
#include <netipsec/ipsec_osdep.h>
#endif
#include <netipsec/keydb.h>

#ifndef _INTTYPES_H_INCLUDED
#include <inttypes.h>
#endif
#ifndef _TYPES_H_INCLUDED
#include <sys/types.h>
#endif

#ifdef _KERNEL
#ifdef __QNXNTO__
extern int qnxnto_ipsec_enabled;
#endif

/*
 * Security Policy Index
 * Ensure that both address families in the "src" and "dst" are same.
 * When the value of the ul_proto is ICMPv6, the port field in "src"
 * specifies ICMPv6 type, and the port field in "dst" specifies ICMPv6 code.
 */
struct secpolicyindex {
	uint8_t dir;			/* direction of packet flow, see blow */
	union sockaddr_union src;	/* IP src address for SP */
	union sockaddr_union dst;	/* IP dst address for SP */
	uint8_t prefs;			/* prefix length in bits for src */
	uint8_t prefd;			/* prefix length in bits for dst */
	uint16_t ul_proto;		/* upper layer Protocol */
#ifdef notyet
	uid_t uids;
	uid_t uidd;
	gid_t gids;
	gid_t gidd;
#endif
};

/* Security Policy Data Base */
struct secpolicy {
	LIST_ENTRY(secpolicy) chain;

	u_int refcnt;			/* reference count */
	struct secpolicyindex spidx;	/* selector */
	uint32_t id;			/* It's unique number on the system. */
	u_int state;			/* 0: dead, others: alive */
#define IPSEC_SPSTATE_DEAD	0
#define IPSEC_SPSTATE_ALIVE	1

	u_int policy;		/* DISCARD, NONE or IPSEC, see keyv2.h */
	struct ipsecrequest *req;
				/* pointer to the ipsec request tree, */
				/* if policy == IPSEC else this value == NULL.*/

	/*
	 * lifetime handler.
	 * the policy can be used without limitiation if both lifetime and
	 * validtime are zero.
	 * "lifetime" is passed by sadb_lifetime.sadb_lifetime_addtime.
	 * "validtime" is passed by sadb_lifetime.sadb_lifetime_usetime.
	 */
	long created;		/* time created the policy */
	long lastused;		/* updated every when kernel sends a packet */
	long lifetime;		/* duration of the lifetime of this policy */
	long validtime;		/* duration this policy is valid without use */
#ifdef __QNXNTO__
	char if_inner[ IFNAMSIZ ];
	char if_outer[ IFNAMSIZ ];
	struct ifnet *ifn_inner;
	struct ifnet *ifn_outer;
#endif
};

/* Request for IPsec */
struct ipsecrequest {
	struct ipsecrequest *next;
				/* pointer to next structure */
				/* If NULL, it means the end of chain. */
	struct secasindex saidx;/* hint for search proper SA */
				/* if __ss_len == 0 then no address specified.*/
	u_int level;		/* IPsec level defined below. */

	struct secasvar *sav;	/* place holder of SA for use */
	struct secpolicy *sp;	/* back pointer to SP */
};

/* security policy in PCB */
struct inpcbpolicy {
	struct secpolicy *sp_in;
	struct secpolicy *sp_out;
	int priv;			/* privileged socket ? */

#if defined(__NetBSD__) || defined(__QNXNTO__)
	/* cached policy */
	struct {
		struct secpolicy *cachesp;
		struct secpolicyindex cacheidx;
		int cachehint;		/* processing requirement hint: */
#define	IPSEC_PCBHINT_MAYBE	0	/* IPsec processing maybe required */
#define	IPSEC_PCBHINT_YES	1	/* IPsec processing is required */
#define	IPSEC_PCBHINT_NO	2	/* IPsec processing not required */
		u_int cachegen;		/* spdgen when cache filled */
	} sp_cache[3];			/* XXX 3 == IPSEC_DIR_MAX */
	int sp_cacheflags;
#define	IPSEC_PCBSP_CONNECTED	1
#endif /* __NetBSD__ || __QNXNTO__ */
};

#if defined(__NetBSD__) || defined(__QNXNTO__)
#define	IPSEC_PCB_SKIP_IPSEC(inpp, dir)					\
	((inpp)->sp_cache[(dir)].cachehint == IPSEC_PCBHINT_NO &&	\
	 (inpp)->sp_cache[(dir)].cachegen == ipsec_spdgen)
#endif /* __NetBSD__ || __QNXNTO__ */

/* SP acquiring list table. */
struct secspacq {
	LIST_ENTRY(secspacq) chain;

	struct secpolicyindex spidx;

	long created;		/* for lifetime */
	int count;		/* for lifetime */
	/* XXX: here is mbuf place holder to be sent ? */
};
#endif /* _KERNEL */

/* according to IANA assignment, port 0x0000 and proto 0xff are reserved. */
#define IPSEC_PORT_ANY		0
#define IPSEC_ULPROTO_ANY	255
#define IPSEC_PROTO_ANY		255

/* mode of security protocol */
/* NOTE: DON'T use IPSEC_MODE_ANY at SPD.  It's only use in SAD */
#define	IPSEC_MODE_ANY		0	/* i.e. wildcard. */
#define	IPSEC_MODE_TRANSPORT	1
#define	IPSEC_MODE_TUNNEL	2
#define	IPSEC_MODE_TCPMD5	3	/* TCP MD5 mode */

/*
 * Direction of security policy.
 * NOTE: Since INVALID is used just as flag.
 * The other are used for loop counter too.
 */
#define IPSEC_DIR_ANY		0
#define IPSEC_DIR_INBOUND	1
#define IPSEC_DIR_OUTBOUND	2
#define IPSEC_DIR_MAX		3
#define IPSEC_DIR_INVALID	4

/* Policy level */
/*
 * IPSEC, ENTRUST and BYPASS are allowed for setsockopt() in PCB,
 * DISCARD, IPSEC and NONE are allowed for setkey() in SPD.
 * DISCARD and NONE are allowed for system default.
 */
#define IPSEC_POLICY_DISCARD	0	/* discarding packet */
#define IPSEC_POLICY_NONE	1	/* through IPsec engine */
#define IPSEC_POLICY_IPSEC	2	/* do IPsec */
#define IPSEC_POLICY_ENTRUST	3	/* consulting SPD if present. */
#define IPSEC_POLICY_BYPASS	4	/* only for privileged socket. */

/* Security protocol level */
#define	IPSEC_LEVEL_DEFAULT	0	/* reference to system default */
#define	IPSEC_LEVEL_USE		1	/* use SA if present. */
#define	IPSEC_LEVEL_REQUIRE	2	/* require SA. */
#define	IPSEC_LEVEL_UNIQUE	3	/* unique SA. */

#define IPSEC_MANUAL_REQID_MAX	0x3fff
				/*
				 * if security policy level == unique, this id
				 * indicate to a relative SA for use, else is
				 * zero.
				 * 1 - 0x3fff are reserved for manual keying.
				 * 0 are reserved for above reason.  Others is
				 * for kernel use.
				 * Note that this id doesn't identify SA
				 * by only itself.
				 */
#define IPSEC_REPLAYWSIZE  32

#ifdef _KERNEL
struct ipsec_output_state {
	struct mbuf *m;
	struct route *ro;
	struct sockaddr *dst;
};

struct ipsec_history {
	int ih_proto;
	uint32_t ih_spi;
};

extern int ipsec_debug;
#ifdef IPSEC_DEBUG
extern int ipsec_replay;
extern int ipsec_integrity;
#endif

extern struct newipsecstat newipsecstat;
extern struct secpolicy ip4_def_policy;
extern int ip4_esp_trans_deflev;
extern int ip4_esp_net_deflev;
extern int ip4_ah_trans_deflev;
extern int ip4_ah_net_deflev;
extern int ip4_ah_cleartos;
extern int ip4_ah_offsetmask;
extern int ip4_ipsec_dfbit;
extern int ip4_ipsec_ecn;
extern int ip4_esp_randpad;
extern int crypto_support;

#define ipseclog(x)	do { if (ipsec_debug) log x; } while (0)
/* for openbsd compatibility */
#define	DPRINTF(x)	do { if (ipsec_debug) printf x; } while (0)

#if defined(__NetBSD__) || defined(__QNXNTO__)
extern void ipsec_pcbconn __P((struct inpcbpolicy *));
extern void ipsec_pcbdisconn __P((struct inpcbpolicy *));
extern void ipsec_invalpcbcacheall __P((void));

extern u_int ipsec_spdgen;
#endif /* __NetBSD__  || __QNXNTO__ */

struct tdb_ident;
#ifndef __QNXNTO__
extern struct secpolicy *ipsec_getpolicy __P((struct tdb_ident*, u_int));
struct inpcb;
extern struct secpolicy *ipsec4_checkpolicy __P((struct mbuf *, u_int, u_int,
	int *, struct inpcb *));
extern struct secpolicy * ipsec_getpolicybyaddr(struct mbuf *, u_int,
	int, int *);
#else
extern struct secpolicy *ipsec_getpolicy __P((struct tdb_ident*, u_int, struct ifnet *));
struct inpcb;
extern struct secpolicy *ipsec4_checkpolicy __P((struct mbuf *, u_int, u_int,
	int *, struct inpcb *, struct ifnet *));
extern struct secpolicy * ipsec_getpolicybyaddr(struct mbuf *, u_int,
	int, int *, struct ifnet *);
#endif


static __inline struct secpolicy*
ipsec4_getpolicybysock(
    struct mbuf *m,
    u_int dir,
    const struct socket *so,
    int *err
)
{
  panic("ipsec4_getpolicybysock");
#ifdef __QNXNTO__
  return NULL;  /* Appease compiler. */
#endif
}

static __inline int
ipsec_copy_pcbpolicy(
    struct inpcbpolicy *old,
    struct inpcbpolicy *new
)
{
  /*XXX do nothing */
  return (0);
}

struct inpcb;
#define	ipsec_init_pcbpolicy ipsec_init_policy
extern int ipsec_init_policy __P((struct socket *so, struct inpcbpolicy **));
extern int ipsec_copy_policy
	__P((struct inpcbpolicy *, struct inpcbpolicy *));
extern u_int ipsec_get_reqlevel __P((struct ipsecrequest *));
extern int ipsec_in_reject __P((struct secpolicy *, struct mbuf *));

extern int ipsec4_set_policy __P((struct inpcb *inp, int optname,
	caddr_t request, size_t len, kauth_cred_t));
extern int ipsec4_get_policy __P((struct inpcb *inpcb, caddr_t request,
	size_t len, struct mbuf **mp));
extern int ipsec4_delete_pcbpolicy __P((struct inpcb *));
extern int ipsec4_in_reject __P((struct mbuf *, struct inpcb *));
/*
 * KAME ipsec4_in_reject_so(struct mbuf*, struct so)  compatibility shim
 */
#define ipsec4_in_reject_so(m, _so) \
  ipsec4_in_reject(m, ((_so) == NULL? NULL : sotoinpcb(_so)))


struct secas;
struct tcpcb;
extern int ipsec_chkreplay __P((uint32_t, struct secasvar *));
extern int ipsec_updatereplay __P((uint32_t, struct secasvar *));

extern size_t ipsec4_hdrsiz __P((struct mbuf *, u_int, struct inpcb *));
#ifdef __FreeBSD__
extern size_t ipsec_hdrsiz_tcp __P((struct tcpcb *));
#else
extern size_t ipsec4_hdrsiz_tcp __P((struct tcpcb *));
#define ipsec4_getpolicybyaddr ipsec_getpolicybyaddr
#endif

union sockaddr_union;
extern const char *ipsec_address(union sockaddr_union* sa);
extern const char *ipsec_logsastr __P((struct secasvar *));

extern void ipsec_dumpmbuf __P((struct mbuf *));

/* NetBSD protosw ctlin entrypoint */
extern void *esp4_ctlinput __P((int, struct sockaddr *, void *));
extern void *ah4_ctlinput __P((int, struct sockaddr *, void *));

struct m_tag;
extern void ipsec4_common_input(struct mbuf *m, ...);
extern int ipsec4_common_input_cb(struct mbuf *m, struct secasvar *sav,
			int skip, int protoff, struct m_tag *mt);
extern int ipsec4_process_packet __P((struct mbuf *, struct ipsecrequest *,
			int, int));
extern int ipsec_process_done __P((struct mbuf *, struct ipsecrequest *));
#define ipsec_indone(m)	\
	(m_tag_find((m), PACKET_TAG_IPSEC_IN_DONE, NULL) != NULL)

extern struct mbuf *ipsec_copypkt __P((struct mbuf *));

extern	void m_checkalignment(const char* where, struct mbuf *m0,
		int off, int len);
extern	struct mbuf *m_clone(struct mbuf *m0);
extern	struct mbuf *m_makespace(struct mbuf *m0, int skip, int hlen, int *off);
extern	caddr_t m_pad(struct mbuf *m, int n);
extern	int m_striphdr(struct mbuf *m, int skip, int hlen);

/* Per-socket caching of IPsec output policy */
static __inline
int ipsec_clear_socket_cache(struct mbuf *m)
{
  return 0;
}


#endif /* _KERNEL */

#ifndef _KERNEL
extern caddr_t ipsec_set_policy __P((char *, int));
extern int ipsec_get_policylen __P((caddr_t));
extern char *ipsec_dump_policy __P((caddr_t, char *));

extern const char *ipsec_strerror __P((void));
#endif /* !_KERNEL */

#ifdef _KERNEL
/* External declarations of per-file init functions */
INITFN void ah_attach(void);
INITFN void esp_attach(void);
INITFN void ipcomp_attach(void);
INITFN void ipe4_attach(void);
INITFN void ipe4_attach(void);
INITFN void tcpsignature_attach(void);

INITFN void ipsec_attach(void);
#endif /* _KERNEL */
#endif /* !_NETIPSEC_IPSEC_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netipsec/ipsec.h $ $Rev: 749676 $")
#endif
