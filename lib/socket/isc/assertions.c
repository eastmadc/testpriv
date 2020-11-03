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

/*	$NetBSD: assertions.c,v 1.2.10.2 2007/05/17 21:25:14 jdc Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1997,1999 by Internet Software Consortium.
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
#if !defined(LINT) && !defined(CODECENTER) && !defined(lint)
#ifdef notdef
static const char rcsid[] = "Id: assertions.c,v 1.2.18.1 2005/04/27 05:01:05 sra Exp";
#else
#ifndef __QNXNTO__
__RCSID("$NetBSD: assertions.c,v 1.2.10.2 2007/05/17 21:25:14 jdc Exp $");
#endif
#endif
#endif

#include "port_before.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>

#include "port_after.h"

/*
 * Forward.
 */

static void default_assertion_failed(const char *, int, assertion_type,
				     const char *, int);

/*
 * Public.
 */

assertion_failure_callback __assertion_failed = default_assertion_failed;

void
set_assertion_failure_callback(assertion_failure_callback f) {
	if (f == NULL)
		__assertion_failed = default_assertion_failed;
	else
		__assertion_failed = f;
}

const char *
assertion_type_to_text(assertion_type type) {
	const char *result;

	switch (type) {
	case assert_require:
		result = "REQUIRE";
		break;
	case assert_ensure:
		result = "ENSURE";
		break;
	case assert_insist:
		result = "INSIST";
		break;
	case assert_invariant:
		result = "INVARIANT";
		break;
	default:
		result = NULL;
	}
	return (result);
}

/*
 * Private.
 */

static void
default_assertion_failed(const char *file, int line, assertion_type type,
			 const char *cond, int print_errno)
{
	fprintf(stderr, "%s:%d: %s(%s)%s%s failed.\n",
		file, line, assertion_type_to_text(type), cond,
		(print_errno) ? ": " : "",
		(print_errno) ? strerror(errno) : "");
	abort();
	/* NOTREACHED */
}

/*! \file */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/isc/assertions.c $ $Rev: 680336 $")
#endif
