/*
 * $QNXtpLicenseC:
 * Copyright 2011, QNX Software Systems. All Rights Reserved.
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

#ifndef res_init_pps_h
#define res_init_pps_h


#include <stdio.h>

typedef enum {
    PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE,
    PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_STATUS_PUBLIC,
    PPS_SOURCE_TYPE_DEFAULT_PPS_PATH_AND_SOCK_SO_BINDTODEVICE,
    PPS_SOURCE_TYPE_COUNT,   /* used for building arrays, not a real source! */
    PPS_SOURCE_TYPE_NOT_USED /* sentinel indicating no pps source used */
} pps_source_type;

typedef enum {
    PPS_SOURCE_STATUS_NOT_FOUND,
    PPS_SOURCE_STATUS_BAD_DATA,
    PPS_SOURCE_STATUS_NOMEM,
    PPS_SOURCE_STATUS_IN_USE
} pps_source_status;

struct pps_source {
    FILE*               fp;
    pps_source_status   status;
    time_t              mtime;
};

typedef enum {
    PPS_READER_TYPE_SEARCHDOMAINS,
    PPS_READER_TYPE_NAMESERVERS,
    PPS_READER_TYPE_IP4_OK,
    PPS_READER_TYPE_IP6_OK,
    PPS_READER_TYPE_FIB,
    PPS_READER_TYPE_COUNT
} pps_reader_type;

struct pps_reader {
    const char*     key;
    union {
        char*           cval;
        int             ival;
    } val;
    void (*setival)(struct pps_reader *, char *);
    unsigned int    flags;
};

struct pps_context {
	char *net_pps_root;
	char *sock_so_bindtodevice;
	struct pps_source pps[ PPS_SOURCE_TYPE_COUNT ];
	struct pps_reader ppsr[ PPS_READER_TYPE_COUNT ];
};

typedef int (*reloadifpps_validate)( struct pps_context* pps_ctx, unsigned int got, int debug );

int reloadifpps(res_state res, reloadifpps_validate validate /* may be NULL */, int debug );
void destroyifpps( struct pps_context* pps_ctx, int debug );
int pps_ip6_ok(res_state);

typedef enum {
	IFPPS_FLAG_VALID,
	IFPPS_FLAG_COUNT /* not a valid flag! */
} IFPPS_FLAG;

#define IFPPS_GET_FLAG( ppsr, f )	( (ppsr)->flags & ( 1 << (f) ) )
#define IFPPS_SET_FLAG( ppsr, f )	( (ppsr)->flags |= ( 1 << (f) ) )
#define IFPPS_CLEAR_FLAG( ppsr, f )	( (ppsr)->flags &= ~( 1 << (f) ) )


#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/res_init_pps.h $ $Rev: 680336 $")
#endif
