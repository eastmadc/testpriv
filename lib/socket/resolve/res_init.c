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



/*	$NetBSD: res_init.c,v 1.22 2009/10/24 17:24:01 christos Exp $	*/

/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#ifdef notdef
static const char sccsid[] = "@(#)res_init.c	8.1 (Berkeley) 6/7/93";
static const char rcsid[] = "Id: res_init.c,v 1.26 2008/12/11 09:59:00 marka Exp";
#else
__RCSID("$NetBSD: res_init.c,v 1.22 2009/10/24 17:24:01 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "port_before.h"

#include "namespace.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifndef __QNXNTO__
#include <sys/event.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef __QNXNTO__
#include <errno.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <limits.h>
#endif

#define HAVE_MD5
#include <md5.h>

#ifndef HAVE_MD5
# include "../dst/md5.h"
#else
# ifdef SOLARIS2
#  include <sys/md5.h>
# endif
#endif
#ifndef _MD5_H_
# define _MD5_H_ 1	/*%< make sure we do not include rsaref md5.h file */
#endif

#include "port_after.h"

#if 0
#ifdef __weak_alias
__weak_alias(res_ninit,_res_ninit)
__weak_alias(res_randomid,__res_randomid)
__weak_alias(res_nclose,_res_nclose)
__weak_alias(res_ndestroy,_res_ndestroy)
__weak_alias(res_get_nibblesuffix,__res_get_nibblesuffix)
__weak_alias(res_get_nibblesuffix2,__res_get_nibblesuffix2)
__weak_alias(res_getservers,__res_getservers)
__weak_alias(res_setservers,__res_setservers)
#endif
#endif


/* ensure that sockaddr_in6 and IN6ADDR_ANY_INIT are declared / defined */
#include <resolv.h>

#include "res_private.h"

#define RESOLVSORT
/*% Options.  Should all be left alone. */
#ifndef DEBUG
#define DEBUG
#endif

/* Uncomment if you want additional logging */
/* #define DEBUG_LOGGING */

#ifdef SOLARIS2
#include <sys/systeminfo.h>
#endif

static void res_setoptions __P((res_state, const char *, const char *));

#ifdef RESOLVSORT
static const char sort_mask[] = "/&";
#define ISSORTMASK(ch) (strchr(sort_mask, ch) != NULL)
static u_int32_t net_mask __P((struct in_addr));
#endif

#if !defined(isascii)	/*%< XXX - could be a function */
# define isascii(c) (!(c & 0200))
#endif

#ifndef __QNXNTO__
static struct timespec __res_conf_time;
static const struct timespec ts = { 0, 0 };
#else
/* CODE DUPLICATION WARNING: This code is a duplicate of code in
 * libcares (ares_init.c) */
static char *
getconf(int token)
{
	size_t len;
	char *buf;
	char *cp;

	if((len=confstr(token,NULL,0))==0) {
		return strdup("");
	}

	if((buf=malloc(len))==NULL)
		return(NULL);
	if(confstr(token,buf,len)==0){
		*buf = '\0';
	}

	cp=buf;
	while(*cp!=NULL){
		if(*cp=='_')
		*cp=' ';
		cp++;
	}

	return(buf);
}

static char *
next_string(char *buf, size_t bufsiz, char **data)
{
	char *retval= *data;
	char *end;
	int len;

	if ((end = strchr(retval, '\n')) != NULL)
		len= min(end - retval + 1, bufsiz - 1);
	else
		len= min(strlen(retval), bufsiz - 1);
	strncpy(buf, retval, len);
	buf[len]= 0;
       *data += len;
	return buf;
}

/* CODE DUPLICATION WARNING: This code is a duplicate of code in
 * libcares (ares_init.c) */
/*
 * Some simple JSON-parsing functions that can also handle raw PPS strings and
 * regular non-PPS strings.
 */
typedef enum {
	pps_notfound,
	pps_string,
	pps_found,
	pps_json_again,
	pps_json_done
} pps_state;

static char*
next_string_prefix(char *buf, size_t bufsiz, char **data, const char *prefix)
{
	int len = 0;

	if (**data == '\0')
		return NULL;

	if ( prefix != NULL ) {
		len = strlcpy( buf, prefix, bufsiz );
		if ( len >= bufsiz ) {
			/* the buffer wasn't long enough */
			return NULL;
		}
	}
	(void)next_string(buf + len, bufsiz - len, data);
	return buf;
}

static char*
next_string_ex(char *buf, size_t bufsiz, char **data, pps_state *state, const char *pps_prefix)
{
	static const char _pps_json_token[] = "json";

	char *endquote, *ret;

	if ( state == NULL ) {
		return NULL;
	}
	ret = NULL;
	switch ( *state ) {
		case pps_notfound:
			ret = next_string_prefix(buf, bufsiz, data, NULL);
			break;

		case pps_found:
			*data = strchr( *data, ':' );
			if ( *data == NULL ) {
				break;
			}
			*data += 1;
			if ( strncmp( _pps_json_token, *data, sizeof( _pps_json_token ) - 1 ) == 0 ) {
				*data += sizeof( _pps_json_token ) - 1;
				if ( **data != ':' ) {
					break;
				}
				*data += 1;
				*data += strspn( *data, " \t" );
				if ( **data != '[' ) {
					break;
				}
				*data += 1;
				*state = pps_json_again;
			} else if ( **data == ':' ) {
				*data += 1;
				*state = pps_string;
				/* interspersing a switch and an if statement looks horrible,
				 * but is perfectly valid C syntax.
				 */
		case pps_string:
				ret = next_string_prefix(buf, bufsiz, data, pps_prefix);
				break;
			} else {
				break;
			}
			/* fallthrough */

		case pps_json_again:
			*data += strspn( *data, " \t" );
			switch ( **data ) {
				case '"':
					break;

				case ']':
					*state = pps_json_done;
					return NULL;

				case ',':
					*data += 1;
					*data += strspn( *data, " \t" );
					if ( **data != '"' ) {
						return NULL;
					}
					break;

				default:
					return NULL;
			}

			*data += 1;
			if ((endquote = strchr(*data, '"')) != NULL) {
				*endquote = '\n';
			}
			ret = next_string_prefix(buf, bufsiz, data, pps_prefix);
			if (endquote != NULL) {
				*endquote = '"';
			}
			break;

		default:
			break;
	}

	return ret;
}

static FILE *
openfile(const char *namebase, const char *mode)
{
	int len;
	char *name;
	FILE *fp;
	char nodename[MAXHOSTNAMELEN];

	if (namebase == NULL)
		return 0;

	len = strlen(namebase) + sizeof(nodename) + 2;
	if ((name = alloca(len)) == NULL) {
		 /*
		  * we could try just namebase,
		  * but then failures would be odd
		  */
		return 0;
	}
	gethostname(nodename, sizeof(nodename));
	snprintf(name, len, "%s.%s", namebase, nodename);
	/* Try host specific version first */
	if ((fp = fopen(name, mode)) != NULL)
		return fp;
	/* default */
	return fopen(namebase, mode);
}

/* CODE DUPLICATION WARNING: This code is a duplicate of code in
 * libcares (ares_init.c) */
/* returns 1 if the values differ, 0 otherwise */
static int
res_conf_str_used_and_differs(const char * previous_value, int token)
{
	if (previous_value == NULL) {
		/* We never used the previous value, so we must be loading via
		 * another technique, so indicate that it does NOT differ.
		 */
		return 0;
	}

	char * current_value = getconf(token);
	if (NULL == current_value) {
		/* We could not get a value, or we ran into a memory issue of
		 * some sort, as such, report that the it does NOT differ.
		 */
		return 0;
	}

	int res = (strcmp(previous_value, current_value) == 0) ? 0 : 1;

#ifdef DEBUG_LOGGING
	slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
		  "res_conf_str_used_and_differs: res=%d previous_value=%s, current_value=%s",
		  (int)res,
		  (const char *)((previous_value) ? previous_value : "<null>"),
		  (const char *)current_value);
#endif

	free(current_value);

	return res;
}

#endif

#ifdef __QNXNTO__
static int
ppsr_validate(struct pps_context *pps_ctx, unsigned int got, int debug)
{
	if (IFPPS_GET_FLAG(&pps_ctx->ppsr[ PPS_READER_TYPE_NAMESERVERS ], IFPPS_FLAG_VALID)) {
		return 1;
	}

	return 0;
}

static void
ppsr_fib_set(struct pps_reader *ppsr, char *val)
{
	char *p, *ep;
	int fib;

	ppsr->val.ival = 0;

	if ((p = strrchr(val, ':')) != NULL) {
		p++;
		fib = strtoul(p, &ep, 0);
		if (*ep == '\0' || *ep == '\n') {
			ppsr->val.ival = fib;
			IFPPS_SET_FLAG(ppsr, IFPPS_FLAG_VALID);
		}
	}
}

static void
ppsr_ip6ok_set(struct pps_reader *ppsr, char *val)
{
	if (strncmp(val, "ip6_ok::yes", sizeof("ip6_ok::yes") - 1) == 0) {
		ppsr->val.ival = 1;
	}
	else {
		ppsr->val.ival = 0;
	}
	IFPPS_SET_FLAG(ppsr, IFPPS_FLAG_VALID);
}

static int
ppsr_check_init(res_state statp, int forceload)
{
	struct pps_context *pps_ctx;

	if (statp->_u._ext.ext == NULL)
		return ENOMEM;

	pps_ctx = statp->_u._ext.ext->pps_ctx;

	if (pps_ctx == NULL) {
		pps_ctx = calloc(1, sizeof(*pps_ctx));
		if (pps_ctx == NULL) {
#ifdef DEBUG
			if( statp->options & RES_DEBUG ) {
				printf("ppsr_init: couldn't allocate %d bytes for PPS reader config\n",
					sizeof(*pps_ctx)
				);
			}
#endif
			return ENOMEM;
		}

		/* readifpps() assumes no duplicate keys */
		pps_ctx->ppsr[ PPS_READER_TYPE_SEARCHDOMAINS ].key = "searchdomains";
		pps_ctx->ppsr[ PPS_READER_TYPE_NAMESERVERS ].key = "nameservers";
		pps_ctx->ppsr[ PPS_READER_TYPE_IP4_OK ].key = "ip4_ok";
		pps_ctx->ppsr[ PPS_READER_TYPE_IP6_OK ].key = "ip6_ok";
		pps_ctx->ppsr[ PPS_READER_TYPE_IP6_OK ].setival = ppsr_ip6ok_set;
		pps_ctx->ppsr[ PPS_READER_TYPE_FIB ].key = "fib";
		pps_ctx->ppsr[ PPS_READER_TYPE_FIB ].setival = ppsr_fib_set;
		statp->_u._ext.ext->pps_ctx = pps_ctx;
		return 0;
	}
	else if (forceload) {
		return 0;
	}
	else if ((statp->pps_root != NULL && (pps_ctx->net_pps_root == NULL ||
	    strcmp(statp->pps_root, pps_ctx->net_pps_root))) ||
	    (statp->iface != NULL && (pps_ctx->sock_so_bindtodevice == NULL ||
	    strcmp(statp->iface, pps_ctx->sock_so_bindtodevice)))) {
		return 0;
	}

	return EEXIST;
}
#endif

/*
 * Resolver state default settings.
 */

/*%
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_ANY and the default domain name comes from the gethostname().
 *
 * An interrim version of this code (BIND 4.9, pre-4.4BSD) used 127.0.0.1
 * rather than INADDR_ANY ("0.0.0.0") as the default name server address
 * since it was noted that INADDR_ANY actually meant ``the first interface
 * you "ifconfig"'d at boot time'' and if this was a SLIP or PPP interface,
 * it had to be "up" in order for you to reach your own name server.  It
 * was later decided that since the recommended practice is to always 
 * install local static routes through 127.0.0.1 for all your network
 * interfaces, that we could solve this problem without a code change.
 *
 * The configuration file should always be used, since it is the only way
 * to specify a default domain.  If you are running a server on your local
 * machine, you should say "nameserver 0.0.0.0" or "nameserver 127.0.0.1"
 * in the configuration file.
 *
 * Return 0 if completes successfully, -1 on error
 */
int
res_ninit(res_state statp) {
#ifndef __QNXNTO__
	return (__res_vinit(statp, 0));
#else
	return (__res_vinit(statp, RES_VINIT_PPSRELOAD));
#endif
}

/*% This function has to be reachable by res_data.c but not publically. */
int
__res_vinit(res_state statp, int preinit) {
	register FILE *fp;
	register char *cp, **pp;
	register int n;
	char buf[BUFSIZ];
	int nserv = 0;    /*%< number of nameserver records read from file */
	int haveenv = 0;
	int havesearch = 0;
#ifdef RESOLVSORT
	int nsort = 0;
	char *net;
#endif
	int dots;
	union res_sockaddr_union u[2];
	int maxns = MAXNS;

	RES_SET_H_ERRNO(statp, 0);

#ifdef __QNXNTO__
	char *resenv;
	char *resenvtemp = NULL;
	char *cptemp = NULL;
	int nocache = 0;
	pps_state state;
	struct pps_reader *ppsr = NULL;
	struct pps_context *pps_ctx;
	int flags;

	/* preinit is actually flags on QNX */

	flags = preinit;
	preinit = preinit & RES_VINIT_PREINIT;

	/* save the PPS context across res_ndestroy() */
	if (statp->_u._ext.ext != NULL) {
		pps_ctx = statp->_u._ext.ext->pps_ctx;
		statp->_u._ext.ext->pps_ctx = NULL;
	} else {
		pps_ctx = NULL;
	}
#endif
	if ((statp->options & RES_INIT) != 0U)
		res_ndestroy(statp);

	if (!preinit) {
		statp->retrans = RES_TIMEOUT;
		statp->retry = RES_DFLRETRY;
		statp->options = RES_DEFAULT;
	}
	statp->_rnd = malloc(16);
	res_rndinit(statp);
	statp->id = res_nrandomid(statp);

	memset(u, 0, sizeof(u));
#ifdef USELOOPBACK
	u[nserv].sin.sin_addr = inet_makeaddr(IN_LOOPBACKNET, 1);
#else
	u[nserv].sin.sin_addr.s_addr = INADDR_ANY;
#endif
	u[nserv].sin.sin_family = AF_INET;
	u[nserv].sin.sin_port = htons(NAMESERVER_PORT);
#ifdef HAVE_SA_LEN
	u[nserv].sin.sin_len = sizeof(struct sockaddr_in);
#endif
	nserv++;
#ifdef HAS_INET6_STRUCTS
#ifdef USELOOPBACK
	u[nserv].sin6.sin6_addr = in6addr_loopback;
#else
	u[nserv].sin6.sin6_addr = in6addr_any;
#endif
	u[nserv].sin6.sin6_family = AF_INET6;
	u[nserv].sin6.sin6_port = htons(NAMESERVER_PORT);
#ifdef HAVE_SA_LEN
	u[nserv].sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	nserv++;
#endif
	statp->nscount = 0;
	statp->ndots = 1;
	statp->pfcode = 0;
	statp->_vcsock = -1;
	statp->_flags = 0;
	statp->qhook = NULL;
	statp->rhook = NULL;
	statp->_u._ext.nscount = 0;
	statp->_u._ext.ext = malloc(sizeof(*statp->_u._ext.ext));
	if (statp->_u._ext.ext != NULL) {
	        memset(statp->_u._ext.ext, 0, sizeof(*statp->_u._ext.ext));
		statp->_u._ext.ext->nsaddrs[0].sin = statp->nsaddr;
		strcpy(statp->_u._ext.ext->nsuffix, "ip6.arpa");
		strcpy(statp->_u._ext.ext->nsuffix2, "ip6.int");
#ifdef __QNXNTO__
		/* NOTE: if res_conf_time is ever adjusted to use the time a file is written, the clock
		 * source may need to be changed to accommodate how file system times are derived
		 */
		clock_gettime(CLOCK_MONOTONIC, &(statp->_u._ext.ext->res_conf_time));
/*		statp->_u._ext.ext->max_cache_time_in_nsec = RES_INFINITE_CACHE_TIME; -- default to be reverted to later */
		statp->_u._ext.ext->max_cache_time_in_nsec = (uint64_t)1000 * (uint64_t)1000 * (uint64_t)1000; /* default for PlayBook: 1000 milliseconds */
		statp->_u._ext.ext->conf_domain = NULL;
		statp->_u._ext.ext->conf_resolv = NULL;
		statp->_u._ext.ext->pps_ctx = pps_ctx;	/* preserved */
#endif
	} else {
		/*
		 * Historically res_init() rarely, if at all, failed.
		 * Examples and applications exist which do not check
		 * our return code.  Furthermore several applications
		 * simply call us to get the systems domainname.  So
		 * rather then immediately fail here we store the
		 * failure, which is returned later, in h_errno.  And
		 * prevent the collection of 'nameserver' information
		 * by setting maxns to 0.  Thus applications that fail
		 * to check our return code wont be able to make
		 * queries anyhow.
		 */
		RES_SET_H_ERRNO(statp, NETDB_INTERNAL);
		maxns = 0;
	}
#ifdef RESOLVSORT
	statp->nsort = 0;
#endif

#ifdef __QNXNTO__
	/* do this first so we can set the RES_DEBUG flag */
	if ((cp = getenv("RES_OPTIONS")) != NULL)
		res_setoptions(statp, cp, "env");
#endif

	res_setservers(statp, u, nserv);

#ifdef	SOLARIS2
	/*
	 * The old libresolv derived the defaultdomain from NIS/NIS+.
	 * We want to keep this behaviour
	 */
	{
		char buf[sizeof(statp->defdname)], *cp;
		int ret;

		if ((ret = sysinfo(SI_SRPC_DOMAIN, buf, sizeof(buf))) > 0 &&
			(unsigned int)ret <= sizeof(buf)) {
			if (buf[0] == '+')
				buf[0] = '.';
			cp = strchr(buf, '.');
			cp = (cp == NULL) ? buf : (cp + 1);
			(void)strlcpy(statp->defdname, cp,
			    sizeof(statp->defdname));
		}
	}
#endif	/* SOLARIS2 */

#ifndef __QNXNTO__
	/* Allow user to override the local domain definition */
	if ((cp = getenv("LOCALDOMAIN")) != NULL) {
		(void)strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		haveenv++;

		/*
		 * Set search list to be blank-separated strings
		 * from rest of env value.  Permits users of LOCALDOMAIN
		 * to still have a search list, and anyone to set the
		 * one that they want to use as an individual (even more
		 * important now that the rfc1535 stuff restricts searches)
		 */
		cp = statp->defdname;
		pp = statp->dnsrch;
		*pp++ = cp;
		for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++) {
			if (*cp == '\n')	/*%< silly backwards compat */
				break;
			else if (*cp == ' ' || *cp == '\t') {
				*cp = 0;
				n = 1;
			} else if (n) {
				*pp++ = cp;
				n = 0;
				havesearch = 1;
			}
		}
		/* null terminate last domain if there are excess */
		while (*cp != '\0' && *cp != ' ' && *cp != '\t' && *cp != '\n')
			cp++;
		*cp = '\0';
		*pp++ = 0;
	}
#else
	/* Allow user to override the local domain definition */
	cp = getenv("LOCALDOMAIN");
	resenv = getenv("RESCONF");
	if ((cp == NULL) || (resenv == NULL)) {
		/*
		 * If either of $LOCALDOMAIN or $RESCONF is not set, we may need to
		 * get properties from our PPS objects.  In that case, load them here,
		 * if they weren't already provided as a parameter.
		 */
		switch (ppsr_check_init(statp, flags & RES_VINIT_PPSRELOAD)) {
			case 0:
				/* if we make it here, we need to set pps_ctx */
				pps_ctx = statp->_u._ext.ext->pps_ctx;
				if (reloadifpps(statp, ppsr_validate, statp->options & RES_DEBUG) < 0) {
					/* error */
					state = pps_notfound;
					break;
				}
				/* fallthrough */

			case EEXIST:
				/* if we make it here, pps_ctx was already set */
				ppsr = pps_ctx->ppsr;
				state = pps_found;
				break;

			default:
				/*
				 * If we make it here, pps_ctx couldn't be created,
				 * so we'll try to fall back onto the other methods
				 * of acquiring a resolver configuration.
				 */
				state = pps_notfound;
				break;
		}
	} else if (pps_ctx != NULL) {
		/* we're not going to be using PPS, so destroy the context */
		destroyifpps(pps_ctx, statp->options & RES_DEBUG);
		free(statp->_u._ext.ext->pps_ctx);
		statp->_u._ext.ext->pps_ctx = NULL;
		pps_ctx = NULL;
	}
	if (cp != NULL) {
		state = pps_notfound;
	} else if (state == pps_found) {
		char *tempcp;
		/*
		 * If we have PPS data, it's okay to not have search domains,
		 * but then we don't want to pick them up from confstr either.
		 */
		if (IFPPS_GET_FLAG(&ppsr[ PPS_READER_TYPE_SEARCHDOMAINS ], IFPPS_FLAG_VALID)) {
			tempcp = ppsr[ PPS_READER_TYPE_SEARCHDOMAINS ].val.cval;
			if (next_string_ex(statp->defdname, sizeof(statp->defdname) - 1, &tempcp, &state, NULL) != NULL) {
				haveenv++;
			}
			cp = tempcp;
		}
	} else if ((cp = cptemp = getconf(_CS_DOMAIN)) != NULL) {
		if (*cp == '\0') {
			cp = NULL;
		}
	}
	/* keep a copy of the last value we retrieved */
	if (statp->_u._ext.ext != NULL) {
		if (NULL != statp->_u._ext.ext->conf_domain) {
			free(statp->_u._ext.ext->conf_domain);
		}
		statp->_u._ext.ext->conf_domain = cptemp;
	}
	if (cp != NULL) {
		if (state == pps_notfound) {
			(void)strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
			statp->defdname[sizeof(statp->defdname) - 1] = '\0';
			haveenv++;
		}
		/*
		 * Set search list to be blank-separated strings
		 * from rest of env value.  Permits users of LOCALDOMAIN
		 * to still have a search list, and anyone to set the
		 * one that they want to use as an individual (even more
		 * important now that the rfc1535 stuff restricts searches)
		 */
		cp = statp->defdname;
		pp = statp->dnsrch;
		*pp++ = cp;
		for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++) {
			if (*cp == '\n')	/*%< silly backwards compat */
				break;
			else if (*cp == ' ' || *cp == '\t') {
				*cp = 0;
				n = 1;
			} else if (n) {
				*pp++ = cp;
				n = 0;
				havesearch = 1;
			}
		}
		/* null terminate last domain if there are excess */
		while (*cp != '\0' && *cp != ' ' && *cp != '\t' && *cp != '\n')
			cp++;
		*cp = '\0';
		*pp++ = 0;
	}
#endif

#define	MATCH(line, name) \
	(!strncmp(line, name, sizeof(name) - 1) && \
	(line[sizeof(name) - 1] == ' ' || \
	 line[sizeof(name) - 1] == '\t'))

	nserv = 0;
#ifdef __QNXNTO__
	state = pps_notfound;
	if (resenv == NULL && ppsr != NULL) {
		if (IFPPS_GET_FLAG(&ppsr[ PPS_READER_TYPE_NAMESERVERS ], IFPPS_FLAG_VALID)) {
			resenv = ppsr[PPS_READER_TYPE_NAMESERVERS].val.cval;
			state = pps_found;
		}
	}
	fp = NULL;
	if ((resenv != NULL) ||
	    ((resenv = resenvtemp = getconf(_CS_RESOLVE)) != NULL && *resenv != '\0') ||
	    (fp = openfile(_PATH_RESCONF, "r")) != NULL)
#else
	if ((fp = fopen(_PATH_RESCONF, "r")) != NULL)
	    /* read the config file */
#endif
	{
#ifndef __QNXNTO__
	    while (fgets(buf, sizeof(buf), fp) != NULL)
#else
	    while (fp ? fgets(buf, sizeof(buf), fp) != NULL :
			next_string_ex(buf, sizeof(buf), &resenv, &state, "nameserver ") != 0)
#endif
	    {
		/* skip comments */
		if (*buf == ';' || *buf == '#')
			continue;
		/* read default domain name */
		if (MATCH(buf, "domain")) {
		    if (haveenv)	/*%< skip if have from environ */
			    continue;
		    cp = buf + sizeof("domain") - 1;
		    while (*cp == ' ' || *cp == '\t')
			    cp++;
		    if ((*cp == '\0') || (*cp == '\n'))
			    continue;
		    strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		    statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		    if ((cp = strpbrk(statp->defdname, " \t\n")) != NULL)
			    *cp = '\0';
		    havesearch = 0;
		    continue;
		}
#ifdef __QNXNTO__

		/* Docs will call the parameter "nocache on" as MATCH expects
		   the keyword to have a space or tab after. Parameter must
                   be specified with at least "nocache ".

		   maxns is set above. If maxns is zero, there is no
		   data to cache RES_INIT will not be set.
		 */

		if ((maxns != 0) && MATCH(buf, "nocache")) {
		    nocache = 1;
		    statp->_u._ext.ext->max_cache_time_in_nsec = RES_INFINITE_CACHE_TIME;
		    continue;
		}

		/* Read the maximum time (in milliseconds) to cache resolver configuration */
		/* maxns is set above. If zero, there is no data to cache and
		   RES_INIT will not be set
		 */

		if ((maxns != 0) && MATCH(buf, "maxcachetime")) {
			cp = buf + sizeof("maxcachetime") - 1;
		    while (*cp == ' ' || *cp == '\t')
			    cp++;
		    if ((*cp == '\0') || (*cp == '\n'))
			    continue;
		    char * endptr = NULL;
		    unsigned long v = strtoul(cp, &endptr, 0);
		    if (!(((endptr == cp) && (0 == v)) ||
		          ((ULONG_MAX == v) && (ERANGE == errno)))) {
		    	/* save after converting from milliseconds to nanoseconds */
		    	statp->_u._ext.ext->max_cache_time_in_nsec = (uint64_t)v * (uint64_t)1000 * (uint64_t)1000;
#ifdef DEBUG_LOGGING
		    	slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
		    	      "__res_vinit: maxcachetime=%lu milliseconds",
		    	      (unsigned long)v);
#endif
		    }
			continue;
		}
#endif
		/* set search list */
		if (MATCH(buf, "search")) {
		    if (haveenv)	/*%< skip if have from environ */
			    continue;
		    cp = buf + sizeof("search") - 1;
		    while (*cp == ' ' || *cp == '\t')
			    cp++;
		    if ((*cp == '\0') || (*cp == '\n'))
			    continue;
		    strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		    statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		    if ((cp = strchr(statp->defdname, '\n')) != NULL)
			    *cp = '\0';
		    /*
		     * Set search list to be blank-separated strings
		     * on rest of line.
		     */
		    cp = statp->defdname;
		    pp = statp->dnsrch;
		    *pp++ = cp;
		    for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++) {
			    if (*cp == ' ' || *cp == '\t') {
				    *cp = 0;
				    n = 1;
			    } else if (n) {
				    *pp++ = cp;
				    n = 0;
			    }
		    }
		    /* null terminate last domain if there are excess */
		    while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			    cp++;
		    *cp = '\0';
		    *pp++ = 0;
		    havesearch = 1;
		    continue;
		}
		/* read nameservers to query */
		if (MATCH(buf, "nameserver") && nserv < maxns) {
		    struct addrinfo hints, *ai;
		    char sbuf[NI_MAXSERV];
		    const size_t minsiz =
		        sizeof(statp->_u._ext.ext->nsaddrs[0]);

		    cp = buf + sizeof("nameserver") - 1;
		    while (*cp == ' ' || *cp == '\t')
			cp++;
		    cp[strcspn(cp, ";# \t\n")] = '\0';
		    if ((*cp != '\0') && (*cp != '\n')) {
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
			hints.ai_flags = AI_NUMERICHOST;
			sprintf(sbuf, "%u", NAMESERVER_PORT);
			if (getaddrinfo(cp, sbuf, &hints, &ai) == 0 &&
			    ai->ai_addrlen <= minsiz) {
			    if (statp->_u._ext.ext != NULL) {
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
				    ai->ai_addr, ai->ai_addrlen);
			    }
			    if (ai->ai_addrlen <=
			        sizeof(statp->nsaddr_list[nserv])) {
				memcpy(&statp->nsaddr_list[nserv],
				    ai->ai_addr, ai->ai_addrlen);
			    } else
				statp->nsaddr_list[nserv].sin_family = 0;
			    freeaddrinfo(ai);
			    nserv++;
			}
		    }
		    continue;
		}
#ifdef RESOLVSORT
		if (MATCH(buf, "sortlist")) {
		    struct in_addr a;

		    cp = buf + sizeof("sortlist") - 1;
		    while (nsort < MAXRESOLVSORT) {
			while (*cp == ' ' || *cp == '\t')
			    cp++;
			if (*cp == '\0' || *cp == '\n' || *cp == ';')
			    break;
			net = cp;
			while (*cp && !ISSORTMASK(*cp) && *cp != ';' &&
			       isascii(*cp) && !isspace((unsigned char)*cp))
				cp++;
			n = *cp;
			*cp = 0;
			if (inet_aton(net, &a)) {
			    statp->sort_list[nsort].addr = a;
			    if (ISSORTMASK(n)) {
				*cp++ = n;
				net = cp;
				while (*cp && *cp != ';' &&
					isascii(*cp) &&
					!isspace((unsigned char)*cp))
				    cp++;
				n = *cp;
				*cp = 0;
				if (inet_aton(net, &a)) {
				    statp->sort_list[nsort].mask = a.s_addr;
				} else {
				    statp->sort_list[nsort].mask = 
					net_mask(statp->sort_list[nsort].addr);
				}
			    } else {
				statp->sort_list[nsort].mask = 
				    net_mask(statp->sort_list[nsort].addr);
			    }
			    nsort++;
			}
			*cp = n;
		    }
		    continue;
		}
#endif
		if (MATCH(buf, "options")) {
		    res_setoptions(statp, buf + sizeof("options") - 1, "conf");
		    continue;
		}
	    }
	    if (nserv > 0) 
		statp->nscount = nserv;
#ifdef RESOLVSORT
	    statp->nsort = nsort;
#endif
#ifndef __QNXNTO__
	    statp->_u._ext.ext->resfd = dup(fileno(fp));
#endif
	    (void) fclose(fp);
#ifndef __QNXNTO__
	    if (fstat(statp->_u._ext.ext->resfd, &st) != -1)
		    __res_conf_time = statp->_u._ext.ext->res_conf_time =
			st.st_mtimespec;
	    statp->_u._ext.ext->kq = kqueue();
	    (void)fcntl(statp->_u._ext.ext->kq, F_SETFD, FD_CLOEXEC);
	    (void)fcntl(statp->_u._ext.ext->resfd, F_SETFD, FD_CLOEXEC);
	    EV_SET(&kc, statp->_u._ext.ext->resfd, EVFILT_VNODE,
		EV_ADD|EV_ENABLE|EV_CLEAR, NOTE_DELETE|NOTE_WRITE| NOTE_EXTEND|
		NOTE_ATTRIB|NOTE_LINK|NOTE_RENAME|NOTE_REVOKE, 0, 0);
	    (void)kevent(statp->_u._ext.ext->kq, &kc, 1, NULL, 0, &ts);
#endif
	} else {
#ifndef __QNXNTO__
	    statp->_u._ext.ext->kq = -1;
	    statp->_u._ext.ext->resfd = -1;
#endif
	}
/*
 * Last chance to get a nameserver.  This should not normally
 * be necessary
 */
#ifdef NO_RESOLV_CONF
	if(nserv == 0)
		nserv = get_nameservers(statp);
#endif

	if (statp->defdname[0] == 0 &&
	    gethostname(buf, sizeof(statp->defdname) - 1) == 0 &&
	    (cp = strchr(buf, '.')) != NULL)
		strcpy(statp->defdname, cp + 1);

	/* find components of local domain that might be searched */
	if (havesearch == 0) {
		pp = statp->dnsrch;
		*pp++ = statp->defdname;
		*pp = NULL;

		dots = 0;
		for (cp = statp->defdname; *cp; cp++)
			dots += (*cp == '.');

		cp = statp->defdname;
		while (pp < statp->dnsrch + MAXDFLSRCH) {
			if (dots < LOCALDOMAINPARTS)
				break;
			cp = strchr(cp, '.') + 1;    /*%< we know there is one */
			*pp++ = cp;
			dots--;
		}
		*pp = NULL;
#ifdef DEBUG
		if (statp->options & RES_DEBUG) {
			printf(";; res_init()... default dnsrch list:\n");
			for (pp = statp->dnsrch; *pp; pp++)
				printf(";;\t%s\n", *pp);
			printf(";;\t..END..\n");
		}
#endif
	}

#ifndef __QNXNTO__
	if ((cp = getenv("RES_OPTIONS")) != NULL)
		res_setoptions(statp, cp, "env");
#endif
#ifdef __QNXNTO__
	/* If maxns == 0 ENOMEM load again at next opportunity */
	if (nocache == 0 && maxns != 0)
#endif
	statp->options |= RES_INIT;
#ifdef __QNXNTO__
	if (statp->_u._ext.ext != NULL) {
		if (NULL != statp->_u._ext.ext->conf_resolv) {
			free(statp->_u._ext.ext->conf_resolv);
		}
		statp->_u._ext.ext->conf_resolv = resenvtemp;
	}
#endif
	return (statp->res_h_errno);
}

#ifndef __QNXNTO__
int
res_check(res_state statp, struct timespec *mtime)
{
	/*
	 * If the times are equal, then we check if there
	 * was a kevent related to resolv.conf and reload.
	 * If the times are not equal, then we don't bother
	 * to check the kevent, because another thread already
	 * did, loaded and changed the time.
	 */
	if (timespeccmp(&statp->_u._ext.ext->res_conf_time,
	    &__res_conf_time, ==)) {
		struct kevent ke;
		if (statp->_u._ext.ext->kq == -1)
			goto out;

		switch (kevent(statp->_u._ext.ext->kq, NULL, 0, &ke, 1, &ts)) {
		case 0:
		case -1:
out:
			if (mtime)
				*mtime = __res_conf_time;
			return 0;
		default:
			break;
		}
	}
	(void)__res_vinit(statp, 0);
	if (mtime)
		*mtime = __res_conf_time;
	return 1;
}
#else

/* returns 1 if the resolver information was reloaded,
 * returns 0 if the file wasn't reloaded */
int
res_check(res_state statp, struct timespec *mtime)
{
	if (NULL == statp) {
		if (mtime) {
			memset(mtime, 0, sizeof(*mtime));
		}
		return 0;
	}

	/* If ext is NULL an error occured the previous time, reload */

	if (NULL == statp->_u._ext.ext)
		goto reload;

	/* copy this now, rather than doing it for each return branch */
	if (mtime) {
		*mtime = statp->_u._ext.ext->res_conf_time;
	}

	/* if caching is disabled (this is the default), we never reload after we
	 * have loaded the first time regardless of what's changed
	 */
	uint64_t max_cache_time_in_nsec = statp->_u._ext.ext->max_cache_time_in_nsec;
	if (max_cache_time_in_nsec == RES_INFINITE_CACHE_TIME) {
#ifdef DEBUG_LOGGING
		slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
			  "res_check: caching disabled -- max_cache_time_in_nsec=RES_INFINITE_CACHE_TIME");
#endif
		return 0;
	}

	/* if we haven't exceeded the timeout, no need to reload */
	if (max_cache_time_in_nsec > 0) {
		struct timespec ts;
		/* NOTE: if res_conf_time is ever adjusted to use the time a file is written, the clock
		 * source may need to be changed to accommodate how file system times are derived
		 */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t now = timespec2nsec(&ts);
		uint64_t then = timespec2nsec(&(statp->_u._ext.ext->res_conf_time));
		if (now - then < max_cache_time_in_nsec) {
#ifdef DEBUG_LOGGING
			slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
				  "res_check: not yet exceeded cache interval time (now={tv_sec=%lu,tv_nsec=%lu},"
				  " then={tv_sec=%lu,tv_nsec=%lu}, max_cache_time_in_nsec=%lu)",
				  (unsigned long)ts.tv_sec,
				  (unsigned long)ts.tv_nsec,
				  (unsigned long)statp->_u._ext.ext->res_conf_time.tv_sec,
				  (unsigned long)statp->_u._ext.ext->res_conf_time.tv_nsec,
				  (unsigned long)max_cache_time_in_nsec);
#endif
			return 0;
		}
	}

	/*
	 * Check if we need to reload due to PPS property changes.
	 */
	switch (reloadifpps(statp, ppsr_validate, statp->options & RES_DEBUG)) {
		case 0:
			/* nothing changed, nothing to do */
#ifdef DEBUG_LOGGING
			slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
				  "res_check: no changes found in PPS configuration");
#endif
			return 0;

		case -1:
			/*
			 * Error: failed to load any PPS configurations.  Try other sources.
			 */
#ifdef DEBUG_LOGGING
			slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
				  "res_check: failed to read any PPS configuration");
#endif
			break;

		default:
			/* one or more PPS properties have changed, need to reload */
			goto reload;
	}

	/* check to see if the confSTR values of interest were used and have changed
	 * NOTE: we will actually end up reloading the confSTR values in __res_init(), but
	 * we haven't tried to optimize passing them to __res_vinit() so as to keep the
	 * diff smaller against the public version of this library, given the fact that
	 * they won't change that often, we consider this an acceptable impact in the
	 * reload scenario */
	if ((0 == res_conf_str_used_and_differs(statp->_u._ext.ext->conf_domain, _CS_DOMAIN)) &&
	    (0 == res_conf_str_used_and_differs(statp->_u._ext.ext->conf_resolv, _CS_RESOLVE))) {
#ifdef DEBUG_LOGGING
		slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
			  "res_check: values for CS_DOMAIN and CS_RESOLVE have not changed");
#endif
		return 0;
	}

reload:
	/* we have now decided that we need to reload, so do so */
	slogf(_SLOG_SETCODE(_SLOGC_TEST, 0), _SLOG_DEBUG1,
		  "res_check: reloading DNS resolver configuration");
	/* 0 flags here since we don't want to reloadifpps as it was just done above */
	(void)__res_vinit(statp, 0);

	if (mtime) {
		*mtime = statp->_u._ext.ext->res_conf_time;
	}
	return 1;
}
#endif

static void
res_setoptions(res_state statp, const char *options, const char *source)
{
	const char *cp = options;
	int i;
	struct __res_state_ext *ext = statp->_u._ext.ext;

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_setoptions(\"%s\", \"%s\")...\n",
		       options, source);
#endif
	while (*cp) {
		/* skip leading and inner runs of spaces */
		while (*cp == ' ' || *cp == '\t')
			cp++;
		/* search for and process individual options */
		if (!strncmp(cp, "ndots:", sizeof("ndots:") - 1)) {
			i = atoi(cp + sizeof("ndots:") - 1);
			if (i <= RES_MAXNDOTS)
				statp->ndots = i;
			else
				statp->ndots = RES_MAXNDOTS;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\tndots=%d\n", statp->ndots);
#endif
		} else if (!strncmp(cp, "timeout:", sizeof("timeout:") - 1)) {
			i = atoi(cp + sizeof("timeout:") - 1);
			if (i <= RES_MAXRETRANS)
				statp->retrans = i;
			else
				statp->retrans = RES_MAXRETRANS;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\ttimeout=%d\n", statp->retrans);
#endif
#ifdef	SOLARIS2
		} else if (!strncmp(cp, "retrans:", sizeof("retrans:") - 1)) {
			/*
		 	 * For backward compatibility, 'retrans' is
		 	 * supported as an alias for 'timeout', though
		 	 * without an imposed maximum.
		 	 */
			statp->retrans = atoi(cp + sizeof("retrans:") - 1);
		} else if (!strncmp(cp, "retry:", sizeof("retry:") - 1)){
			/*
			 * For backward compatibility, 'retry' is
			 * supported as an alias for 'attempts', though
			 * without an imposed maximum.
			 */
			statp->retry = atoi(cp + sizeof("retry:") - 1);
#endif	/* SOLARIS2 */
		} else if (!strncmp(cp, "attempts:", sizeof("attempts:") - 1)){
			i = atoi(cp + sizeof("attempts:") - 1);
			if (i <= RES_MAXRETRY)
				statp->retry = i;
			else
				statp->retry = RES_MAXRETRY;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\tattempts=%d\n", statp->retry);
#endif
		} else if (!strncmp(cp, "debug", sizeof("debug") - 1)) {
#ifdef DEBUG
			if (!(statp->options & RES_DEBUG)) {
				printf(";; res_setoptions(\"%s\", \"%s\")..\n",
				       options, source);
				statp->options |= RES_DEBUG;
			}
			printf(";;\tdebug\n");
#endif
		} else if (!strncmp(cp, "no_tld_query",
				    sizeof("no_tld_query") - 1) ||
			   !strncmp(cp, "no-tld-query",
				    sizeof("no-tld-query") - 1)) {
			statp->options |= RES_NOTLDQUERY;
		} else if (!strncmp(cp, "inet6", sizeof("inet6") - 1)) {
			statp->options |= RES_USE_INET6;
		} else if (!strncmp(cp, "rotate", sizeof("rotate") - 1)) {
			statp->options |= RES_ROTATE;
		} else if (!strncmp(cp, "no-check-names",
				    sizeof("no-check-names") - 1)) {
			statp->options |= RES_NOCHECKNAME;
		}
#ifdef RES_USE_EDNS0
		else if (!strncmp(cp, "edns0", sizeof("edns0") - 1)) {
			statp->options |= RES_USE_EDNS0;
		}
#endif
		else if (!strncmp(cp, "dname", sizeof("dname") - 1)) {
			statp->options |= RES_USE_DNAME;
		}
		else if (!strncmp(cp, "nibble:", sizeof("nibble:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix) - 1);
			strncpy(ext->nsuffix, cp, (size_t)i);
			ext->nsuffix[i] = '\0';
		}
		else if (!strncmp(cp, "nibble2:", sizeof("nibble2:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble2:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix2) - 1);
			strncpy(ext->nsuffix2, cp, (size_t)i);
			ext->nsuffix2[i] = '\0';
		}
		else if (!strncmp(cp, "v6revmode:", sizeof("v6revmode:") - 1)) {
			cp += sizeof("v6revmode:") - 1;
			/* "nibble" and "bitstring" used to be valid */
			if (!strncmp(cp, "single", sizeof("single") - 1)) {
				statp->options |= RES_NO_NIBBLE2;
			} else if (!strncmp(cp, "both", sizeof("both") - 1)) {
				statp->options &=
					 ~RES_NO_NIBBLE2;
			}
		}
		else {
			/* XXX - print a warning here? */
		}
   skip:
		/* skip to next run of spaces */
		while (*cp && *cp != ' ' && *cp != '\t')
			cp++;
	}
}

#ifdef RESOLVSORT
/* XXX - should really support CIDR which means explicit masks always. */
static u_int32_t
net_mask(in)		/*!< XXX - should really use system's version of this  */
	struct in_addr in;
{
	register u_int32_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return (htonl(IN_CLASSA_NET));
	else if (IN_CLASSB(i))
		return (htonl(IN_CLASSB_NET));
	return (htonl(IN_CLASSC_NET));
}
#endif

static u_char srnd[16];

void
res_rndinit(res_state statp)
{
	struct timeval now;
	u_int32_t u32;
	u_int16_t u16;
	u_char *rnd = statp->_rnd == NULL ? srnd : statp->_rnd;

	gettimeofday(&now, NULL);
	u32 = (u_int32_t)now.tv_sec;
	memcpy(rnd, &u32, 4);
	u32 = now.tv_usec;
	memcpy(rnd + 4, &u32, 4);
	u32 += (u_int32_t)now.tv_sec;
	memcpy(rnd + 8, &u32, 4);
	u16 = getpid();
	memcpy(rnd + 12, &u16, 2);
}

u_int
res_nrandomid(res_state statp) {
	struct timeval now;
	u_int16_t u16;
	MD5_CTX ctx;
	u_char *rnd = statp->_rnd == NULL ? srnd : statp->_rnd;

	gettimeofday(&now, NULL);
	u16 = (u_int16_t) (now.tv_sec ^ now.tv_usec);
	memcpy(rnd + 14, &u16, 2);
#ifndef HAVE_MD5
	MD5_Init(&ctx);
	MD5_Update(&ctx, rnd, 16);
	MD5_Final(rnd, &ctx);
#else
	MD5Init(&ctx);
	MD5Update(&ctx, rnd, 16);
	MD5Final(rnd, &ctx);
#endif
	memcpy(&u16, rnd + 14, 2);
	return ((u_int) u16);
}

/*%
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void
res_nclose(res_state statp) {
	int ns;

	if (statp->_vcsock >= 0) { 
		(void) close(statp->_vcsock);
		statp->_vcsock = -1;
		statp->_flags &= ~(RES_F_VC | RES_F_CONN);
	}
	for (ns = 0; ns < statp->_u._ext.nscount; ns++) {
		if (statp->_u._ext.nssocks[ns] != -1) {
			(void) close(statp->_u._ext.nssocks[ns]);
			statp->_u._ext.nssocks[ns] = -1;
		}
	}
}

void
res_ndestroy(res_state statp) {
	res_nclose(statp);
	if (statp->_u._ext.ext != NULL) {
#ifndef __QNXNTO__
		if (statp->_u._ext.ext->kq != -1)
			(void)close(statp->_u._ext.ext->kq);
		if (statp->_u._ext.ext->resfd != -1)
			(void)close(statp->_u._ext.ext->resfd);
#else
		if (statp->_u._ext.ext->conf_domain)
			free(statp->_u._ext.ext->conf_domain);
		statp->_u._ext.ext->conf_domain = NULL;
		if (statp->_u._ext.ext->conf_resolv)
			free(statp->_u._ext.ext->conf_resolv);
		statp->_u._ext.ext->conf_resolv = NULL;
		if (statp->_u._ext.ext->pps_ctx) {
			destroyifpps(statp->_u._ext.ext->pps_ctx, statp->options & RES_DEBUG);
			free(statp->_u._ext.ext->pps_ctx);
		}
		statp->_u._ext.ext->pps_ctx = NULL;
#endif
		free(statp->_u._ext.ext);
		statp->_u._ext.ext = NULL;
	}
	if (statp->_rnd != NULL) {
		free(statp->_rnd);
		statp->_rnd = NULL;
	}
	statp->options &= ~RES_INIT;
}

const char *
res_get_nibblesuffix(res_state statp) {
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix);
	return ("ip6.arpa");
}

const char *
res_get_nibblesuffix2(res_state statp) {
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix2);
	return ("ip6.int");
}

void
res_setservers(res_state statp, const union res_sockaddr_union *set, int cnt) {
	int i, nserv;
	size_t size;

	/* close open servers */
	res_nclose(statp);

	/* cause rtt times to be forgotten */
	statp->_u._ext.nscount = 0;

	nserv = 0;
	for (i = 0; i < cnt && nserv < MAXNS; i++) {
		switch (set->sin.sin_family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;

#ifdef HAS_INET6_STRUCTS
		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin6, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin6, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;
#endif

		default:
			break;
		}
		set++;
	}
	statp->nscount = nserv;
	
}

int
res_getservers(res_state statp, union res_sockaddr_union *set, int cnt) {
	int i;
	size_t size;
	u_int16_t family;

	for (i = 0; i < statp->nscount && i < cnt; i++) {
		if (statp->_u._ext.ext)
			family = statp->_u._ext.ext->nsaddrs[i].sin.sin_family;
		else 
			family = statp->nsaddr_list[i].sin_family;

		switch (family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&set->sin,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin, &statp->nsaddr_list[i],
				       size);
			break;

#ifdef HAS_INET6_STRUCTS
		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&set->sin6,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin6, &statp->nsaddr_list[i],
				       size);
			break;
#endif

		default:
			set->sin.sin_family = 0;
			break;
		}
		set++;
	}
	return (statp->nscount);
}

/*! \file */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/res_init.c $ $Rev: 799811 $")
#endif
