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

/*	$NetBSD: res_state.c,v 1.6 2008/04/28 20:23:02 martin Exp $	*/

/*-
 * Copyright (c) 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: res_state.c,v 1.6 2008/04/28 20:23:02 martin Exp $");
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>

#ifndef __QNXNTO__
#include "pthread.h"
#include "pthread_int.h"
#else
#include <pthread.h>

static struct __res_state _nres
# if defined(__BIND_RES_TEXT)
	= { .retrans = RES_TIMEOUT, }	/*%< Motorola, et al. */
# endif
	;

static pthread_once_t res_once_ctl = PTHREAD_ONCE_INIT;
static pthread_key_t res_key;
static int res_key_created;

static void res_key_create(void);
static void res_key_destruct(void *);
static res_state __res_get_specific(void);
#endif

#ifndef __QNXNTO__
static SLIST_HEAD(, _res_st) res_list = LIST_HEAD_INITIALIZER(&res_list);

struct _res_st {
	/* __res_put_state() assumes st_res is the first member. */
	struct __res_state	st_res;

	SLIST_ENTRY(_res_st)	st_list;
};

static pthread_mutex_t res_mtx = PTHREAD_MUTEX_INITIALIZER;
#endif

res_state __res_state(void);
res_state __res_get_state(void);
void __res_put_state(res_state);

#ifdef RES_STATE_DEBUG
static void
res_state_debug(const char *msg, void *p)
{
	char buf[512];
	pthread_t self = pthread_self();
	int len = snprintf(buf, sizeof(buf), "%p: %s %p\n", self, msg, p);

	(void)write(STDOUT_FILENO, buf, (size_t)len);
}
#else
#define res_state_debug(a, b)
#endif

#ifdef __QNXNTO__
/* forward declaration */
int res_check(res_state statp, struct timespec *mtime);

static void
res_key_create(void)
{
	if (pthread_key_create(&res_key, res_key_destruct) == 0)
		res_key_created = 1;
}

static void
res_key_destruct(void *arg)
{
	res_state statp = arg;
	if( statp ) {
		res_ndestroy(statp);
	}
	free(arg);
	pthread_setspecific(res_key, NULL);
}

res_state
__res_get_specific(void)
{
	res_state	statp;


	if (pthread_self() == 1) {
		_nres.options |= RES_EXTENDED;
		return &_nres;
	}

	if (pthread_once(&res_once_ctl, res_key_create) != 0 ||
	    !res_key_created) {
		return NULL;
	}

	if ((statp = pthread_getspecific(res_key)) != NULL)
		return statp;

	if ((statp = calloc(1, sizeof(*statp))) == NULL)
		return NULL;

#if defined(__BIND_RES_TEXT)
	statp->retrans = RES_TIMEOUT;	/* Motorola, et al. */
#endif
	statp->options |= RES_EXTENDED;

	if (pthread_setspecific(res_key, statp) != 0) {
		free(statp);
		return NULL;
	}

	return statp;

}
#endif

res_state
__res_get_state(void)
{
	res_state res;
#ifndef __QNXNTO__
	struct _res_st *st;
	pthread_mutex_lock(&res_mtx);
	st = SLIST_FIRST(&res_list);
	if (st != NULL) {
		SLIST_REMOVE_HEAD(&res_list, st_list);
		pthread_mutex_unlock(&res_mtx);
		res = &st->st_res;
		res_state_debug("checkout from list", st);
	} else {
		pthread_mutex_unlock(&res_mtx);
		st = malloc(sizeof(*st));
		if (st == NULL) {
			h_errno = NETDB_INTERNAL;
			return NULL;
		}
		res = &st->st_res;
		res->options = 0;
		res_state_debug("alloc new", res);
	}
#else
	if ((res = __res_get_specific()) == NULL) {
		h_errno = NETDB_INTERNAL;
		return NULL;
	}
#endif
	if ((res->options & RES_INIT) == 0) {
		if (res_ninit(res) == -1) {
			h_errno = NETDB_INTERNAL;
#ifndef __QNXNTO__
			free(st);
#endif
			return NULL;
		}
	}
	return res;
}

void
/*ARGSUSED*/
__res_put_state(res_state res)
{
#ifndef __QNXNTO__
	struct _res_st *st = (struct _res_st *)(void *)res;

	res_state_debug("free", res);
	pthread_mutex_lock(&res_mtx);
	SLIST_INSERT_HEAD(&res_list, st, st_list);
	pthread_mutex_unlock(&res_mtx);
#else
	return;
#endif
}

/*
 * This is aliased via a macro to _res; don't allow multi-threaded programs
 * to use it.
 */
res_state
__res_state(void)
{
#ifndef __QNXNTO__
	static const char res[] = "_res is not supported for multi-threaded"
	    " programs.\n";
	(void)write(STDERR_FILENO, res, sizeof(res) - 1);
	abort();
	return NULL;
#else
	res_state	statp;

	if ((statp = __res_get_specific()) != NULL)
		return statp;

	return &_nres;	/* XXX */
#endif
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/res_state.c $ $Rev: 680336 $")
#endif
