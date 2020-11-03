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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <resolv.h>
#include <sys/stat.h>
#include "res_init_pps.h"
#include "res_private.h"


#ifndef DEBUG
#define DEBUG
#endif

int
pps_ip6_ok(res_state statp)
{
	struct pps_context *pps_ctx;
	struct pps_reader *ppsr;

	if (statp->_u._ext.ext == NULL ||
	    statp->_u._ext.ext->pps_ctx == NULL) {
		/* unknown */
		return -1;
	}

	pps_ctx = statp->_u._ext.ext->pps_ctx;
	/* pps_ctx may be null so check before deref of ppsr */
	ppsr = &pps_ctx->ppsr[PPS_READER_TYPE_IP6_OK];


	if (IFPPS_GET_FLAG(ppsr, IFPPS_FLAG_VALID) == 0) {
		/* unknown */
		return -1;
	}

	return ppsr->val.ival;
}

static int readifpps( struct pps_context* pps_ctx, FILE* pps, int debug )
{
	char *buf;
	unsigned int i;
	struct pps_reader *r;
	int got, done, new;

	buf = malloc( LINE_MAX );
	if( buf == NULL ) {
#ifdef DEBUG
		if( debug ) {
			printf( "readifpps: failed to allocate initial %d-byte buffer\n", LINE_MAX );
		}
		return 0;
#endif
	}

	done = 0;
	got = 0;
	while (!done && fgets(buf, LINE_MAX, pps) != NULL) {
		for( i = 0; i < PPS_READER_TYPE_COUNT; ++i ) {
			r = &pps_ctx->ppsr[ i ];
			if (r->key == NULL ||
			    strncmp(r->key, buf, strlen(r->key)) != 0) {
				continue;
			}
#ifdef DEBUG
			if( debug ) {
				printf( "readifpps: match reader[%d].key='%s': '%s'\n", i, r->key, buf );
			}
#endif
			new = 0;
			if (r->setival != NULL) {
				(*r->setival)(r, buf);
				new = 1;
			}
			else {
				if (r->val.cval != NULL && strcmp(r->val.cval, buf) == 0) {
					/* strings match, no need to do anything */
				} else {
					free(r->val.cval);
					if ((r->val.cval = strdup(buf)) == NULL) {
#ifdef DEBUG
						if (debug) {
							printf("readifpps: failed to allocate cval\n");
						}
#endif
						done = 1;
						break;
					}
					new = 1;
				}
				IFPPS_SET_FLAG(r, IFPPS_FLAG_VALID);
			}
			got += new;
			break; /* No duplicate keys. See ppsr_check_init() */
		}
	}
	rewind(pps);

	free(buf);
	buf = NULL;

	return got;
}

static void fclosepps( struct pps_context *pps_ctx, pps_source_type source )
{
	FILE *f;

	f = pps_ctx->pps[ source ].fp;
	if( f ) {
		fclose( f );
		pps_ctx->pps[ source ].fp = NULL;
	}
}

/*
 * Determine which PPS object to open, open it, and read its contents.  If the
 * contents are accepted by a supplied validation function, we're done; else
 * try the next source.
 *
 * Rather than stat()ing the individual components, this function just
 * blindly builds a pathname and tries to fopen() it.  In the best case, we
 * only require one path traversal, and the worst-case is no worse than if
 * we'd stat()ed for the path and the interface.
 *
 * State 5 "TRY_BOTH": try $NET_PPS_ROOT/interfaces/$SOCK_SO_BINDTODEVICE
 * State 4 "TRY_NET_PPS_ROOT": try $NET_PPS_ROOT/public_status
 * State 3 "TRY_SOCK_SO_BINDTODEVICE": try /pps/services/networking/interfaces/$SOCK_SO_BINDTODEVICE
 * State 2 "TRY_ONLY_NET_PPS_ROOT": same as State 4, but exit on failure
 * State 0 "NOTHING_FOUND": unable to find a valid PPS object
 *
 * Note that /pps/services/networking/status_public isn't tested, since this
 * falls back to using confstr().
 *
 * State machine:
 *                  START
 *                    |
 *           [ $NET && $SOCK? ] Yes---> ( 5 ) OK--> DONE
 *                    | No                | fail     ^
 *                    V                   V          |
 *   ( 2 ) <--Yes [ $NET? ]             ( 4 ) OK-----+
 *     | *            | No                |          |
 *     |              V                   V          |
 *     |          [ $SOCK? ] Yes------> ( 3 ) OK-----+
 *     |              | No                |          |
 *     |              |                   V          |
 *     |              +---------------> ( 0 ) *------+
 *     |                                  ^
 *     +----------------------------------+
 *                    *means we take this path pass or fail.
 *
 * Returns the number of PPS properties that were reloaded, 0 if none were (i.e.
 * nothing had changed), or -1 if no valid PPS objects could be found/opened.
 */
int
reloadifpps(res_state statp, reloadifpps_validate validate, int debug)
{
	/*
	 * Note that the numbering of these states is critical to the correct
	 * operation of the state machine.  Do not change these unless you
	 * are absolutely sure of what you are doing.
	 */
	typedef enum {
		STATE_TRY_BOTH						= 5,
		STATE_TRY_NET_PPS_ROOT				= 4,
		STATE_TRY_SOCK_SO_BINDTODEVICE		= 3,
		STATE_TRY_ONLY_NET_PPS_ROOT			= 2,
		STATE_TRY_ONLY_NET_PPS_ROOT_FAILED	= 1,
		STATE_NOTHING_FOUND					= 0
	} STATE;

	const char *ifac;
	const char *path;
	pps_source_type source;
	char *filename = NULL;
	int check_path = 1;
	int got = 0;
	int n = 0;
	struct pps_source *pps;
	STATE nextstate;
	STATE state;
	struct stat st;
	struct pps_context* pps_ctx;

	if (statp->_u._ext.ext == NULL ||
	    statp->_u._ext.ext->pps_ctx == NULL)
		/* there's nothing for us to do */
		return -1;

	pps_ctx = statp->_u._ext.ext->pps_ctx;

	if ((ifac = statp->iface) == NULL)
		ifac = getenv( "SOCK_SO_BINDTODEVICE" );
	if ((path = statp->pps_root) == NULL)
		path = getenv( "NET_PPS_ROOT" );

	if (path == NULL)
		path = "/pps/services/networking";

#ifdef DEBUG
	if( debug ) {
		printf( "reloadifpps: $NET_PPS_ROOT='%s', $SOCK_SO_BINDTODEVICE='%s'\n",
				path != NULL ? path : "<NOT SET>",
				ifac != NULL ? ifac : "<NOT SET>"
		);
	}
#endif

	if( pps_ctx->net_pps_root != NULL ) {
		if( path == NULL || strcmp( pps_ctx->net_pps_root, path ) != 0 ) {
			/* $NET_PPS_ROOT has changed */
#ifdef DEBUG
			if( debug ) {
				printf( ";; $NET_PPS_ROOT mismatch, invalidating dependencies\n" );
			}
#endif
			fclosepps( pps_ctx, PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE );
			fclosepps( pps_ctx, PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_STATUS_PUBLIC );
			free( pps_ctx->net_pps_root );
			if( path != NULL ) {
				pps_ctx->net_pps_root = strdup( path );
			} else {
				pps_ctx->net_pps_root = NULL;
			}
		}
	} else if( path != NULL ) {
		pps_ctx->net_pps_root = strdup( path );
	}
	if( pps_ctx->sock_so_bindtodevice != NULL ) {
		if( ifac == NULL || strcmp( pps_ctx->sock_so_bindtodevice, ifac ) != 0 ) {
			/* $SOCK_SO_BINDTODEVICE has changed */
#ifdef DEBUG
			if( debug ) {
				printf( ";; $SOCK_SO_BINDTODEVICE mismatch, invalidating dependencies\n" );
			}
#endif
			fclosepps( pps_ctx, PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE );
			fclosepps( pps_ctx, PPS_SOURCE_TYPE_DEFAULT_PPS_PATH_AND_SOCK_SO_BINDTODEVICE );
			free( pps_ctx->sock_so_bindtodevice );
			if( ifac != NULL ) {
				pps_ctx->sock_so_bindtodevice = strdup( ifac );
			} else {
				pps_ctx->sock_so_bindtodevice = NULL;
			}
		}
	} else if( ifac != NULL ) {
		pps_ctx->sock_so_bindtodevice = strdup( ifac );
	}

	if( path == NULL && ifac == NULL ) {
		/* there's nothing for us to do */
		return -1;
	} else if( path == NULL ) {
		nextstate = STATE_TRY_SOCK_SO_BINDTODEVICE;
	} else if( ifac == NULL ) {
		nextstate = STATE_TRY_ONLY_NET_PPS_ROOT;
	} else {
		nextstate = STATE_TRY_BOTH;
	}
	do {
		/* state machine handles PPS source priorities */
		state = nextstate;
		switch( state ) {
			case STATE_TRY_BOTH:
				source = PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE;
				nextstate = STATE_TRY_NET_PPS_ROOT;
				break;

			case STATE_TRY_ONLY_NET_PPS_ROOT:
				nextstate = STATE_TRY_ONLY_NET_PPS_ROOT_FAILED;
				/* fallthrough */
			case STATE_TRY_NET_PPS_ROOT:
				nextstate -= 1;
				source = PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_STATUS_PUBLIC;
				break;

			case STATE_TRY_SOCK_SO_BINDTODEVICE:
				nextstate = STATE_NOTHING_FOUND;
				source = PPS_SOURCE_TYPE_DEFAULT_PPS_PATH_AND_SOCK_SO_BINDTODEVICE;
				break;

			default:
				/* should never get here */
#ifdef DEBUG
				if( debug ) {
					printf( ";; state=%d INVALID STATE\n", state );
				}
#endif
				/* fallthrough */
			case STATE_NOTHING_FOUND:
				got = -1; /* failed to (re)load PPS */
				goto done;
		}

#ifdef DEBUG
		if( debug ) {
			const char const* sources[ PPS_SOURCE_TYPE_COUNT ] = {
					"$NET_PPS_ROOT/interfaces/$SOCK_SO_BINDTODEVICE",
					"$NET_PPS_ROOT/status_public",
					"/pps/services/networking/interfaces/$SOCK_SO_BINDTODEVICE"
			};
			printf( ";; state=%d, nextstate=%d, source=%s\n",
					state,
					nextstate,
					sources[ source ]
			);
		}
#endif

		pps = &pps_ctx->pps[ source ];
		if( pps->fp == NULL ) {
			if( filename == NULL ) {
				filename = malloc( PATH_MAX );
			}
			if( filename == NULL ) {
#ifdef DEBUG
				if( debug ) {
					printf( ";;\tNOMEM (%d bytes) for filename buffer\n", PATH_MAX );
				}
#endif
				pps->status = PPS_SOURCE_STATUS_NOMEM;
				got = -1;
				goto done;
			}

			/* make sure user-supplied path is '/'-terminated */
			if( check_path == 1 ) {
				switch( source ) {
					case PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE:
					case PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_STATUS_PUBLIC:
						n = strlcpy( filename, path, PATH_MAX );
						if( n >= PATH_MAX ) {
#ifdef DEBUG
							if( debug ) {
								printf( ";; PPS pathname length=%d > PATH_MAX=%d, aborting\n",
									n,
									PATH_MAX
								);
							}
#endif
							got = -1;
							goto done;
						}
						if( *( filename + n - 1 ) != '/' ) {
							*( filename + n ) = '/';
							n += 1;
						}
						check_path = 0;
						break;

					default:
						break;
				}
			}

			switch( source ) {
				case PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_SOCK_SO_BINDTODEVICE:
					if( snprintf( filename + n, PATH_MAX - n, "%s%s", "interfaces/", ifac ) > PATH_MAX - n ) {
						got = -1;
						goto done;
					}
					break;

				case PPS_SOURCE_TYPE_NET_PPS_ROOT_AND_STATUS_PUBLIC:
					if( snprintf( filename + n, PATH_MAX - n, "%s", "status_public" ) > PATH_MAX - n ) {
						got = -1;
						goto done;
					}
					break;

				case PPS_SOURCE_TYPE_DEFAULT_PPS_PATH_AND_SOCK_SO_BINDTODEVICE:
					if( snprintf( filename, PATH_MAX, "%s%s", "/pps/services/networking/interfaces/", ifac ) > PATH_MAX ) {
						got = -1;
						goto done;
					}
					break;

				default:
					/* should never get here */
#ifdef DEBUG
					if( debug ) {
						printf( ";; INVALID source=%d, aborting\n", source );
					}
#endif
					got = -1;
					goto done;
			}

			pps->fp = fopen( filename, "r" );
			pps->status = PPS_SOURCE_STATUS_IN_USE;
			pps->mtime = 0;
		}
		if( pps->fp == NULL ) {
#ifdef DEBUG
			if( debug ) {
				printf( ";;\tNOT FOUND '%s'\n", filename );
			}
#endif
			pps->status = PPS_SOURCE_STATUS_NOT_FOUND;
		} else {
			if( fstat( fileno( pps->fp ), &st ) != 0 ) {
				st.st_mtime = 1; /* insignificant non-zero value */
			}
			/*
			 * If we get here with a PPS stream that was previously flagged
			 * as 'PPS_SOURCE_STATUS_BAD_DATA' (or 'PPS_SOURCE_STATUS_NOMEM')
			 * this is our chance to change that state; but only if the
			 * mtime of the stream has changed--otherwise we already know
			 * its properties haven't changed, and we can move on to the
			 * next candidate PPS object.
			 */
			if( st.st_mtime != pps->mtime ) {
				/* a reload is required */
				pps->mtime = st.st_mtime;
				got = readifpps( pps_ctx, pps->fp, debug );
				if( validate == NULL || (*validate)( pps_ctx, got, debug ) > 0 ) {
					/* success */
					pps->status = PPS_SOURCE_STATUS_IN_USE;
#ifdef DEBUG
					if( debug ) {
						printf( ";;\tSUCCESS (got %d new values)\n", got );
					}
#endif
					goto done;
				} else {
#ifdef DEBUG
					if( debug ) {
						printf( ";;\tBAD DATA\n" );
					}
#endif
					pps->status = PPS_SOURCE_STATUS_BAD_DATA;
				}
			} else if( pps->status == PPS_SOURCE_STATUS_IN_USE ) {
#ifdef DEBUG
				if( debug ) {
					printf( ";;\tSUCCESS (no changes)\n" );
				}
#endif
			}
		}
		/*
		 * We only break out of this loop on two conditions:
		 * 1. when pps->state == PPS_SOURCE_STATUS_IN_USE, which means the
		 *    current pps->fp returned usable data; or
		 * 2. when we hit search state 0.
		 */
	} while( pps->status != PPS_SOURCE_STATUS_IN_USE );

done:
	free( filename );
	filename = NULL;

	return got;
}

void destroyifpps( struct pps_context* pps_ctx, int debug )
{
	struct pps_source *pps;
	struct pps_reader *ppsr;
	int i;

	if( pps_ctx == NULL ) {
		return;
	}

	/* free the env vars we used to build the PPS object pathname */
	free( pps_ctx->net_pps_root );
	pps_ctx->net_pps_root = NULL;
	free( pps_ctx->sock_so_bindtodevice );
	pps_ctx->sock_so_bindtodevice = NULL;

	/* free the raw strings we retrieved from the PPS object */
	for( i = 0; i < PPS_READER_TYPE_COUNT; ++i ) {
		ppsr = &pps_ctx->ppsr[i];
		if (ppsr->setival == NULL) {
			free(ppsr->val.cval );
			ppsr->val.cval = NULL;
		}
		IFPPS_CLEAR_FLAG(ppsr, IFPPS_FLAG_VALID);
	}

	/* close any open PPS objects */
	for( i = 0; i < PPS_SOURCE_TYPE_COUNT; ++i ) {
		pps = &pps_ctx->pps[ i ];
		if( pps->fp ) {
			fclose( pps->fp );
			pps->fp = NULL;
		}
	}
}


/*! \file */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/resolve/res_init_pps.c $ $Rev: 799811 $")
#endif
