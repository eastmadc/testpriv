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



/*	$NetBSD: getservbyname_r.c,v 1.5 2006/07/28 15:14:45 christos Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)getservbyname.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: getservbyname_r.c,v 1.5 2006/07/28 15:14:45 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <assert.h>
#ifdef __QNXNTO__
#define _DIAGASSERT(x) ((void)0)
#endif
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#ifndef __QNXNTO__
#include <db.h>
#else
#include <unistd.h>
#endif

#include "servent.h"

#ifdef __weak_alias
__weak_alias(getservbyname_r,_getservbyname_r)
#endif

#ifdef __QNXNTO__
char *__noaliases_for_netdb= 0;
static struct servent builtin_services[]=
{  /* ports are in network order */
#ifdef __BIGENDIAN__
   { "ftp", &__noaliases_for_netdb, 0x0015, "tcp"},
   { "telnet", &__noaliases_for_netdb, 0x0017, "tcp" },
   { "smtp", &__noaliases_for_netdb, 0x0019, "tcp" },
   { "domain", &__noaliases_for_netdb, 0x0035, "tcp" },
   { "nntp", &__noaliases_for_netdb, 0x0077, "tcp"},
   { "netbios-ns", &__noaliases_for_netdb, 0x0089, "udp"},
   { "netbios-ssn", &__noaliases_for_netdb, 0x008b, "tcp"},
   { "sunrpc", &__noaliases_for_netdb, 0x006f, "udp"},
   { "sunrpc", &__noaliases_for_netdb, 0x006f, "tcp"},
   { "nfsd", &__noaliases_for_netdb, 0x0801, "udp"},
   { "nfsd", &__noaliases_for_netdb, 0x0801, "tcp"}
#else
   { "ftp", &__noaliases_for_netdb, 0x1500, "tcp"},
   { "telnet", &__noaliases_for_netdb, 0x1700, "tcp" },
   { "smtp", &__noaliases_for_netdb, 0x1900, "tcp" },
   { "domain", &__noaliases_for_netdb, 0x3500, "tcp" },
   { "nntp", &__noaliases_for_netdb, 0x7700, "tcp"},
   { "netbios-ns", &__noaliases_for_netdb, 0x8900, "udp"},
   { "netbios-ssn", &__noaliases_for_netdb, 0x8b00, "tcp"},
   { "sunrpc", &__noaliases_for_netdb, 0x6f00, "udp"},
   { "sunrpc", &__noaliases_for_netdb, 0x6f00, "tcp"},
   { "nfsd", &__noaliases_for_netdb, 0x0108, "udp"},
   { "nfsd", &__noaliases_for_netdb, 0x0108, "tcp"}
#endif
};
#endif

static struct servent *
_servent_getbyname(struct servent_data *sd, struct servent *sp,
    const char *name, const char *proto)
{
#ifndef __QNXNTO__
	if (sd->flags & _SV_DB) {
		char buf[BUFSIZ];
		DBT key, data;
		DB *db = sd->db;
		key.data = buf;

		if (proto == NULL)
			key.size = snprintf(buf, sizeof(buf), "\376%s", name);
		else
			key.size = snprintf(buf, sizeof(buf), "\376%s/%s",
			    name, proto);
		key.size++;
			
		if ((*db->get)(db, &key, &data, 0) != 0)
			return NULL;

		if ((*db->get)(db, &data, &key, 0) != 0)
			return NULL;

		if (sd->line)
			free(sd->line);

		sd->line = strdup(key.data);
		return _servent_parseline(sd, sp);
	} else
#endif
	    {
		while (_servent_getline(sd) != -1) {
			char **cp;
			if (_servent_parseline(sd, sp) == NULL)
				continue;

			if (strcmp(name, sp->s_name) == 0)
				goto gotname;

			for (cp = sp->s_aliases; *cp; cp++)
				if (strcmp(name, *cp) == 0)
					goto gotname;
			continue;
gotname:
			if (proto == NULL || strcmp(sp->s_proto, proto) == 0)
				return sp;
		}
		return NULL;
	}
}

struct servent *
getservbyname_r(const char *name, const char *proto, struct servent *sp,
    struct servent_data *sd)
{
	_DIAGASSERT(name != NULL);
	/* proto may be NULL */

#ifdef __QNXNTO__
	if (access(_PATH_SERVICES, R_OK) != 0) {
		int i;
		for (i = 0;
		    i < sizeof builtin_services / sizeof builtin_services[0];
		    i++) {
			if (strcmp(name, builtin_services[i].s_name) == 0 &&
				(!proto || (strcmp(proto, builtin_services[i].s_proto) == 0)))
			return &builtin_services[i];
		}
		return NULL;
	} 
#endif
	setservent_r(sd->flags & _SV_STAYOPEN, sd);
	sp = _servent_getbyname(sd, sp, name, proto);
	if (!(sd->flags & _SV_STAYOPEN))
		_servent_close(sd);
	return sp;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/net/getservbyname_r.c $ $Rev: 680336 $")
#endif
