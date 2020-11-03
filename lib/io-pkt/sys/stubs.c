/*
 * $QNXLicenseC:
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




#include "opt_pru_sense.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/slog.h>
#include <sys/param_bsd.h>
#include <sys/slogcodes.h>
#include <sys/syspage.h>
#include <sys/mman.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/nlist.h>
#include "nw_defs.h"
#include "sys/acct.h"
#include "sys/proc.h"
#include "sys/domain.h"
#include "sys/time_bsd.h"
#include "sys/ucred.h"
#include "sys/syslog.h"
#include "sys/rnd.h"
#include <sys/reboot.h>

#ifdef OPT_PRU_SENSE_EXTEN
/* Need tcpstates[].  Maybe not the best place to instantiate but... */
#ifndef TCP_DEBUG
#define TCPSTATES
#endif
#include <netinet/tcp_fsm.h>
#endif


int boothowto;

 /*
  * since HZ is _sysconf(3) in nto, these guys will be assigned
  * in init_main.c
  */
int     hz;
int     tick;
int     maxproc = NPROC;
int     desiredvnodes = NVNODE;
int     maxfiles = INT_MAX;
int     ncallout = 16 + NPROC;  /* size of callwheel (rounded to ^2) */
int     fscale = FSCALE;        /* kernel uses `FSCALE', user uses `fscale' */
/*
 *  * Various mbuf-related parameters.  These can also be changed at run-time
 *  * with sysctl.
 *  */
int     nmbclusters = NMBCLUSTERS;

#ifndef MBLOWAT
#define MBLOWAT         16
#endif
int     mblowat = MBLOWAT;

#ifndef MCLLOWAT
#define MCLLOWAT        8
#endif
int     mcllowat = MCLLOWAT;
/*
 * Actual network mbuf sizes (read-only), for netstat.
 */
const   int msize = MSIZE;
int mclshift = MCLSHIFT_NTOMIN;		/* The default, minimum size */
int mclbytes = (1 << MCLSHIFT_NTOMIN);	/* The default, minimum size */
#ifdef __QNXNTO__
NLIST_EXPORT(msize, msize);
NLIST_EXPORT(mclbytes, mclbytes);
#endif

#ifdef NO_UNIX_DOMAIN
/*
 * since we don't bring in kern/uipc_proto.c
 */
struct domain unixdomain;
#endif

static int last_level;

static int nw_vslogf_lock(int, const char *, va_list);
static void vlog_ext(int, int, const char *, va_list);


static int
nw_vslogf_lock(int level, const char *fmt, va_list ap)
{
	struct nw_work_thread *wtp;
	int ret;
	va_list ap_new;

	wtp = WTP;
	/*
	 * vslogf() calls slogsend() which has a mutex so we have
	 * to wrap this as a critical section so as not to handle
	 * interrupts it locked.
	 */
	va_copy(ap_new, ap);
	NW_SIGHOLD_P(wtp);
	ret = vslogf(_SLOG_SETCODE(_SLOGC_TCPIP, 0), level, fmt, ap_new);
	NW_SIGUNHOLD_P(wtp);
	va_end(ap_new);

	if (ret == -1)
		return errno;

	return 0;
}


void
panic(const char *fmt, ...)
{
	va_list ap;
	int level;

	level = _SLOG_CRITICAL;

	va_start(ap, fmt);
	nw_vslogf_lock(level, fmt, ap);
	va_end(ap);

	raise(SIGABRT);
}

void
log(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog_ext(0, level, fmt, ap);
	va_end(ap);
}

void
log_cons(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog_ext(1, level, fmt, ap);
	va_end(ap);
}

void
vlog(int level, const char *fmt, va_list ap)
{
	va_list ap_new;

	va_copy(ap_new, ap);
	vlog_ext(0, level, fmt, ap);
	va_end(ap_new);
}

static void
vlog_ext(int cons, int level, const char *fmt, va_list ap)
{
	va_list ap_new;

	last_level = level; /* XXX not thread safe */

	/*
	 * Convert syslog level to similar slog level.
	 * slog has 2 debug, syslog has an extra LOG_ALERT.
	 */
	if(level > 1)
		level--;

	if (cons != 0)
		level |= _SLOG_TEXTBIT;

	va_copy(ap_new, ap);
	nw_vslogf_lock(level, fmt, ap_new);
	va_end(ap_new);
}

void
addlog(const char * fmt, ...)
{
	va_list ap;

	/* Our addlog doesn't.  Rather it creates a new entry. */
	va_start(ap, fmt);
	vlog_ext(0, last_level, fmt, ap);
	va_end(ap);
}


/* We can't SIGLOCK at startup as our thread contexts aren't set up */
void
log_init(int level, const char *fmt, ...)
{
	va_list ap;

	if(level > 1)
		level--;

	level |= _SLOG_TEXTBIT;

	va_start(ap, fmt);
	vslogf(_SLOG_SETCODE(_SLOGC_TCPIP, 0), level, fmt, ap);
	va_end(ap);
}

int
printf(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	/*
	 * 6.3 libc compat.
	 *
	 * dlopen() used to call printf() w/ DL_DEBUG.
	 * We may be doing dlopen as a blockop from
	 * thread 1.  Thread 1 never handles interrupts 
	 * so don't need a context to keep track of 
	 * pre-emption.
	 */
	if (pthread_self() == 1) {
		/* The non-overidden one */
		ret = vfprintf(stdout, fmt, ap);
	}
	else {
		ret = vprintf(fmt, ap);
	}
	va_end(ap);

	return ret;
}

int
vprintf(const char *fmt, va_list ap)
{
	static char		linebuf[128];
	static int		last_idx;
	char 			*p;
	int			len, avail, flush, flush_asis, done;
	va_list			ap_new;
	struct nw_work_thread	*wtp;

	wtp = WTP;
	flush_asis = flush = done = 0;

	/*
	 * We don't enforce exclusive access to the
	 * static buffer so if not the stack, just log
	 * what we have.
	 */
	if (!ISSTACK_P(wtp))
		flush_asis = 1;
	else do {
		p = linebuf + last_idx;
		avail = sizeof(linebuf) - last_idx;
		va_copy(ap_new, ap);
		len = vsnprintf(p, avail, fmt, ap_new);
		va_end(ap_new);

		if (len >= avail) {
			if (avail == sizeof(linebuf)) {
				/* It'll never fit */
				flush_asis = 1;
				break;
			}

			/* Flush what we have and retry */
			linebuf[last_idx] = '\0';
			flush = 1;
		}
		else if (len > 0) {
			last_idx += len;
			if (linebuf[last_idx - 1] == '\n') {
				last_idx--;
				linebuf[last_idx] = '\0';
				flush = 1;
			}
			done = 1;
		}
		else
			break;

		if (flush) {
			NW_SIGHOLD_P(wtp);
			slogb(_SLOG_SETCODE(_SLOGC_TCPIP, 0),
			    _SLOG_INFO | _SLOG_TEXTBIT, linebuf, last_idx + 1);
			NW_SIGUNHOLD_P(wtp);

			last_idx = 0;
			flush = 0;
		}
	} while (!done);

	if (flush_asis) {
		va_copy(ap_new, ap);
		len = nw_vslogf_lock(_SLOG_INFO, fmt, ap_new);
		va_end(ap_new);
	}
	return len;
}

void
aprint_normal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static void
aprint_error_internal(const char *prefix, const char *fmt, va_list ap)
{
	if (prefix != NULL)
		printf("%s: ", prefix);

	vprintf(fmt, ap);
}

void
aprint_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	aprint_error_internal(NULL, fmt, ap);
	va_end(ap);
}

void
aprint_naive(const char *fmt, ...)
{
	va_list ap;

	if ((boothowto & (AB_QUIET|AB_SILENT|AB_VERBOSE)) == AB_QUIET) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

void
aprint_verbose(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	aprint_error_internal(NULL, fmt, ap);
	va_end(ap);
}

void
aprint_verbose_dev(device_t dv, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	aprint_error_internal(device_xname(dv), fmt, ap);
	va_end(ap);
}

void
aprint_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void
aprint_error_dev(device_t dv, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	aprint_error_internal(device_xname(dv), fmt, ap);
	va_end(ap);
}

int
__cmsg_alignbytes(void)
{
	/*
	 * NetBSD returns ALIGNBYTES which is processor dependent (arch/X/include/param.h).
	 */

	return ALIGNBYTES;    /* defined in lib/io-pkt/sys/alignbytes.h */
}



#include "rnd.h"

#if NRND > 0
static int rnd_fd = -1;

u_int32_t
rnd_extract_data(void *p, u_int32_t len, u_int32_t flag)
{
	int align, left = len;
	long i, *dst = p;
	char *s, *d;

	if (rnd_fd != -1) {
		if ((i = read(rnd_fd, p, len)) == -1) {
			close(rnd_fd);
			rnd_fd = -1;
			i = 0;
			log(LOG_WARNING, "Falling back on pseudo random generator: errno: %d", errno);
		}
		else if ((left = left - i) == 0) {
			return len;
		}
		dst = (long *)((char *)dst + i);
	}

	if ((align = ((int)dst & (sizeof(long) - 1))) != 0) {
		s = (char *)&i;
		d = (char *)dst;

		align = sizeof(long) - align;
		
		i = random();
		for (;;) {
			*d++ = *s++;
			if (--left == 0 || --align == 0)
				break;
		}
		dst = (long *)d;
	}

	while (left >= sizeof(long)) {
		*dst++ = random();
		left -= sizeof(long);
	}

	if (left) {
		s = (char *)&i;
		d = (char *)dst;
		
		i = random();
		while (left--)
			*d++ = *s++;
	}
	return len;
}
#endif

int
rnd_seed_fd(void)
{
	if((rnd_fd = open("/dev/random", O_RDONLY)) == -1)
		log(LOG_WARNING, "Unable to initialize random generator: errno: %d", errno);

	return rnd_fd;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/stubs.c $ $Rev: 822252 $")
#endif
