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



/* interface options */
#include "loop.h"
#include "ppp.h"
#include "opt_ppp.h"
#include "pppoe.h"
#include "tun.h"
#include "tap.h"
#include "gre.h"
#include "gif.h"
#include "vlan.h"
#include "bridge.h"
#include "opt_inet.h"
#include "opt_pfil_hooks.h"
#include "opt_ipsec.h"
#include "opt_oob.h"
#include "bpfilter.h"
#include "pf.h"
#include "srt.h"
#include "opt_ionet_compat.h"
#if defined( IPSEC ) || defined( FAST_IPSEC )
#include "ifipsec.h"
#endif


/*
 * Following makes the inline versions _not_ be
 * brought in from libkern.h and avoids a mismatch
 * warning.
 */

#define RESMGR_HANDLE_T void
#define RESMGR_OCB_T    void
#include <sys/param_bsd.h>
#include <sys/mbuf.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/syslog.h> /* BSD one */
#include <netinet/ip_var.h>
#include <net/if_ether.h>
#include <net/if_bridgevar.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/if_inarp.h>
#include <string.h>
#define _MALLOC_H_INCLUDED
#include <stdlib.h>
#include <sys/rnd.h>

#include <secmodel/secmodel.h>
#include <sys/kernel.h>
#include <sys/procmgr.h>
#include <sys/netmgr.h>
#include <sys/systm.h>
#include <sys/dispatch.h>
#include <sys/file_bsd.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/domain.h>
#include <sys/sched.h>
#include <netinet/in_var.h>
#include <alloca.h>
#include <nlist.h>
#include <sys/nlist.h>
#include <sys/evcnt.h>
#include <sys/kauth.h>
#include <dlfcn.h>
#define _STDDEF_H_INCLUDED
#include <hw/pci.h> /* QNX one */
#include <sys/cache.h> /* QNX one */
#if defined(IPSEC)
#include <netinet6/ipsec.h>
#endif
#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <opencrypto/cryptodev.h>
#endif
#if NBPFILTER > 0
#include <net/bpf.h>
#include <net/bpfdesc.h>
#endif
#if NPPP > 0
#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#endif
#ifdef IONET_COMPAT
#include <ionet_compat.h>
#endif

#include "nw_msg.h"
#include "nw_pci.h"
#include "nw_dl.h"
#include "nw_thread.h"
#include "quiesce.h"
#include "init_main.h"
#include "receive.h"
#include "notify.h"
#include "blockop.h"

MALLOC_DEFINE(M_INIT, "minit", "initialization structures");
const char hexdigits[] = "0123456789abcdef";

char *percent_s_null = "(null)";

extern char _connect_malloc; /* see _connect_ctrl.c */
extern char *__progname;

static void loopconfig(void);
static unsigned round_pow2(unsigned);
static void init_load(char *, char *, char *, char *, int);


static resmgr_connect_funcs_t autoconnect_cfuncs;
static resmgr_io_funcs_t autoconnect_iofuncs;
static resmgr_connect_funcs_t config_cfuncs;
static resmgr_io_funcs_t config_iofuncs;
#ifdef ALTQ_RESMGR
extern resmgr_connect_funcs_t altq_cfuncs;
extern resmgr_io_funcs_t altq_iofuncs;
#endif


extern dispatch_t *_dispatch_create(int chid, unsigned flags);


union attached_paths {
	char families [sizeof "/dev/socket/" + 8 * sizeof(int)]; /* For itoa */
	char autoconnect [sizeof "/dev/socket/autoconnect"];
	char config [sizeof "/dev/socket/config"];
};

/*
 * Anything that resmgr_attach()'s to tcpip_connect_funcs (comes in 
 * via af_open()) needs to set (struct msg_open_info *)->path_type.
 */
static struct msg_open_info inet_info = {
	{0}, 0, AF_INET, PATH_TYPE_SOCKET
};
static struct msg_open_info route_info = {
	{0}, 0, AF_ROUTE, PATH_TYPE_SOCKET
};
#ifndef NO_UNIX_DOMAIN
static struct msg_open_info unix_info = {
	{0}, 0, AF_UNIX, PATH_TYPE_SOCKET
};
#endif
#ifdef INET6
static struct msg_open_info inet6_info = {
	{0}, 0, AF_INET6, PATH_TYPE_SOCKET
};
#endif
#if defined(IPSEC) || defined(FAST_IPSEC)
static struct msg_open_info key_info = {
	{0}, 0, PF_KEY, PATH_TYPE_SOCKET
};
#endif
#ifdef FAST_IPSEC
static struct msg_open_info cryptodev_info = {
	{0}, 0, 0, PATH_TYPE_CRYPTO
};
#endif
#if NBPFILTER > 0
static struct msg_open_info bpf_info = {
	{0}, 0, 0, PATH_TYPE_BPF
};
static struct msg_open_info bpf_info2 = {
	{0}, 0, 0, PATH_TYPE_BPF
};
#endif

#if 0
static struct msg_open_info pf_info = {
	{0}, 0, 0, PATH_TYPE_PF
};
#endif
#if NSRT > 0
static struct msg_open_info srt_info = {
	{0}, 0, 0, PATH_TYPE_SRT
};
#endif
#if NTUN > 0
static struct msg_open_info *tun_info;
#endif
#if NTAP > 0
/* Cloning Device */
static struct msg_open_info tap_info = {{0}, -1, 0, PATH_TYPE_TAP}; 
#endif
static struct msg_open_info autoconnect_info;
static struct msg_open_info config_info;
static struct msg_open_info mount_info;
#ifdef ALTQ_RESMGR
static struct msg_open_info altq_info;
#endif

/*
 * Any option using containing the substring 'tcpip'
 * is invalid as it would be eaten as part of io-net2
 * compatibility.
 */
static char *tcpip_opts[] = {
	"recv_ctxt",
	"somaxconn",
	"threads_min",
	"threads",      /* This one same as following.  Left for compatibility */
	"threads_max",
	"threads_incr",
	"prefix",
	"stacksize",
	"forward",
	"fastforward",
	"timer_pulse_prio",
	"rx_pulse_prio",
	"rx_prio",
	"random",
	"cache",
	"reuseport_unicast",
	"mbuf_cache",
	"pkt_cache",
	"pkt_typed_mem",
	"pagesize",
	"bigpage_strict",
	"mclbytes",
#ifdef OOB_THREAD_HIGH
	"oob_prio_high",
#endif
#ifdef OOB_THREAD_LOW
	"oob_prio_low",
#endif
#ifdef INET6
	"forward6",
#endif
#if defined(IPSEC) || defined(FAST_IPSEC)
	"ipsec",
	"nocryptodev",
#ifdef PFIL_HOOKS
	"pfil_ipsec",
#endif
#endif
	"confstr_monitor",
#ifdef ALTQ_RESMGR
	"altq",
#endif
#ifdef FAKE_UP_WRITES
	"fake_src_cached",
	"nfake",
#endif
	"enmap",
	"timertol",
	"min_fperms",
	"rgroup_allowed",
	"tickstop_min",
	"tickstop_max",
#ifdef QNX_MFIB
	"mfib_enable",
	"mfib_gid_map",
#endif
	"so_txprio_enable",
	"stackguard",
	"gtimerlib",
#ifdef NTAP
	"num_tap_interface",
#endif
#ifdef NTUN
	"num_tun_control_interface",
#endif
	"bigstack",
	"strict_ts",
	"mtag_cache",
	"reply_ctxt",
	NULL
};

enum {
	OPT_RECV_CTXT,
	OPT_SOMAXCONN,
	OPT_THREADS_MIN,
	OPT_THREADS,
	OPT_THREADS_MAX,
	OPT_THREADS_INCR,
	OPT_PREFIX,
	OPT_STACKSIZE,
	OPT_FORWARD,
	OPT_FASTFORWARD,
	OPT_TIMER_PULSE_PRIO,
	OPT_RX_PULSE_PRIO, /* compat, see OPT_RX_PRIO */
	OPT_RX_PRIO,
	OPT_RANDOM,
	OPT_CACHE,
	OPT_REUSEPORT_UNICAST,
	OPT_MBUF_CACHE,
	OPT_PKT_CACHE,
	OPT_PKT_TYPED_MEM,
	OPT_PAGESIZE,
	OPT_BIGPAGE_STRICT,
	OPT_MCLBYTES,
#ifdef OOB_THREAD_HIGH
	OPT_OOB_PRIO_HIGH,
#endif
#ifdef OOB_THREAD_LOW
	OPT_OOB_PRIO_LOW,
#endif
#ifdef INET6
	OPT_FORWARD6,
#endif
#if defined(IPSEC) || defined(FAST_IPSEC)
	OPT_IPSEC,
	OPT_NOCRYPTODEV,
#ifdef PFIL_HOOKS
	OPT_PFIL_IPSEC,
#endif
#endif
	OPT_CONFSTR_MONITOR,
#ifdef ALTQ_RESMGR
	OPT_ALTQ,
#endif
#ifdef FAKE_UP_WRITES
	FAKE_SRC_CACHED,
	NFAKE,
#endif
	OPT_ENMAP,
	OPT_TIMERTOL,
	OPT_MIN_FPERMS,
	OPT_RGROUP_ALLOWED,
	OPT_TICKSTOP_MIN,
	OPT_TICKSTOP_MAX,
#ifdef QNX_MFIB
	OPT_MFIB_ENABLE,
	OPT_MFIB_GID_MAP,
#endif
	OPT_SOPRIO_ENABLE,
	OPT_STACKGUARD,
	OPT_GTIMERLIB,
#ifdef NTAP
	OPT_NUM_TAP_INTERFACE,
#endif
#ifdef NTUN
	OPT_NUM_TUN_CONTROL_INTERFACE,
#endif
	OPT_BIGSTACK,
	OPT_STRICT_TS,
	OPT_MTAG_CACHE,
	OPT_REPLY_CTXT,
	NUM_OPTS
};

unsigned int admin_group;
int pagesize, pagesize_large;
int nw_max_prio;
int pkt_typed_mem_fd;
struct cache_ctrl qnx_cachectl;
extern int somaxconn;		/* kern/uipc_socket.c */
extern int tickstop_min;	/* kern/kern_timeout.c */
extern int tickstop_max;
int reuseport_unicast = 0;
char *__prefix = NULL;
#if (defined(IPSEC) || defined(FAST_IPSEC)) && defined(PFIL_HOOKS)
int pfil_ipsec = 0;
#endif

#ifdef NTAP
int __num_tap_interface = 5;
#endif
#ifdef NTUN
int __num_tun_control_interface = 4;
#endif
#ifdef FAST_IPSEC
int __cryptodev = 1;
#endif

#ifdef FAKE_UP_WRITES
/* Following two in "delta.h" */
int nfake;
void *fake_cpy_buf;
#endif

int nw_pci_hdl = -1;

static int fperm = 0666;

/* Reserve for ip / udp headers on write */

/*
 * We need 28 bytes for proto headers (20 ip + 8 udp).
 * sizeof(io_write_t) == 16 (sendto() and sendmsg() headers >= sizeof(io_write_t))
 * therefor we need 28 - 16 = 12 filler bytes.
 */
#define NTO_HDR_LEN 12

/* Default to ClockCycles() timestamping for BPF */
uint32_t ts_fail = 0;

void
main_fini(int how, int err, const char *errmsg)
{
	struct nw_stk_ctl *sctlp;
	int i;

	sctlp = &stk_ctl;

	/* Fall through all the below */
	switch (how) {
	case -1:
	case 30:
#ifdef NTAP
                if(tap_info.path_id != -1)
                        resmgr_detach(sctlp->dpp, tap_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 29:
#if NTUN > 0
		for (i = 0; i < __num_tun_control_interface; i++) {
			if (tun_info[i].path_id == -1)
				continue;
			resmgr_detach(sctlp->dpp, tun_info[i].path_id, _RESMGR_DETACH_ALL);
		}
		free(tun_info, M_INIT);
#endif
#if NSRT > 0
		resmgr_detach(sctlp->dpp, srt_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 28:
#if NPF > 0
#ifndef __QNXNTO__
		resmgr_detach(sctlp->dpp, pf_info.path_id, _RESMGR_DETACH_ALL);
#endif
#endif

	case 27:
		interrupt_fini();
	case 26:
		quiesce_fini();
	case 25:
#if NBPFILTER > 0
		resmgr_detach(sctlp->dpp, bpf_info2.path_id, _RESMGR_DETACH_ALL);
	case 24:
		resmgr_detach(sctlp->dpp, bpf_info.path_id, _RESMGR_DETACH_ALL);
	case 23:
		/* Nothing needs to be done, bpf_init() failed */
	case 22:
#endif
#ifdef FAST_IPSEC
		if (__cryptodev) {
			resmgr_detach(sctlp->dpp, cryptodev_info.path_id, _RESMGR_DETACH_ALL);
		}
#endif
	case 21:
#ifdef ALTQ_RESMGR
		resmgr_detach(sctlp->dpp, altq_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 20:
#ifdef FAKE_UP_WRITES
		munmap(fake_cpy_buf, MCLBYTES);
#endif
	case 19:

		resmgr_detach(sctlp->dpp, mount_info.path_id, _RESMGR_DETACH_ALL);
	case 17:
		resmgr_detach(sctlp->dpp, config_info.path_id, _RESMGR_DETACH_ALL);
	case 16:
		resmgr_detach(sctlp->dpp, autoconnect_info.path_id, _RESMGR_DETACH_ALL);
	case 15:
#if defined(IPSEC) || defined(FAST_IPSEC)
		if (qnxnto_ipsec_enabled)
			resmgr_detach(sctlp->dpp, key_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 14:
#ifdef INET6
		resmgr_detach(sctlp->dpp, inet6_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 13:
#ifndef NO_UNIX_DOMAIN
		resmgr_detach(sctlp->dpp, unix_info.path_id, _RESMGR_DETACH_ALL);
#endif
	case 12:
		resmgr_detach(sctlp->dpp, route_info.path_id, _RESMGR_DETACH_ALL);
	case 11:
		resmgr_detach(sctlp->dpp, inet_info.path_id, _RESMGR_DETACH_ALL);
	case 10:
		clock_intr_destroy(sctlp);
	case 9:
		free(sctlp->recv_iov, M_INIT);
	case 8:
		free(sctlp->recv_mbuf, M_INIT);
	case 7:
		dispatch_destroy(sctlp->dpp);
		/* The above destroys the channel */
		sctlp->chid = -1;
		pci_detach(nw_pci_hdl);
	case 6:
		ConnectDetach(sctlp->coid);
	case 5:
		if (sctlp->chid != -1)
			ChannelDestroy(sctlp->chid);
	case 4:
		iopkt_selfp->ex_destroy(&sctlp->pkt_ex);
	case 3:
		iopkt_selfp->ex_destroy(&sctlp->stack_ex);
	case 2:
		cache_fini(&qnx_cachectl);
	case 1:
		free(sctlp->proc_prio.prio_prios, M_INIT);
	case 0:
		if (errmsg != NULL && err != EOK) {
			log(LOG_ERR, "%s: init_main: %s: %s",
			    __progname, errmsg , strerror(err));
		}
		else if (errmsg != NULL) {
			log(LOG_ERR, "%s: init_main: %s",
			    __progname, errmsg);
		}
		else if (err != EOK) {
			log(LOG_ERR, "%s: init_main: %s",
			    __progname, strerror(err));
		}
	default:
		break;
	}
}


/* FIXME_nto check error codes of init routines and backout */
int
main_init(char *options, int argc, char **argv)
{
	resmgr_attr_t		resmgr_attr;
	char			*workpath, *prefix, *sockendp;
	int			use_random, do_cache;
	size_t			workpath_len, prefix_len, sockend_len;
	int			confstr_monitor, pool_bigpage_strict;
	int			ret, oldsize;
	size_t			size;
	struct nw_stk_ctl	*sctlp;
	struct nw_work_thread	*wtp;
	void			*hdl;
	char			**percentsp;
#ifdef ALTQ_RESMGR
	int			altq = 0;
#endif

#ifdef FAKE_UP_WRITES
	int			fake_nocache_flag = PROT_NOCACHE;
	nfake = 3;
#endif

#if (defined(IPSEC) || defined(FAST_IPSEC)) && defined(QNXNTO_IPSEC_ALWAYS_ON)
	qnxnto_ipsec_enabled = 1;
#endif

	prefix = NULL;
	workpath_len = sizeof(union attached_paths);
	prefix_len = 0;
	use_random = 0;
	confstr_monitor = 0;
	do_cache = 1;
	pool_bigpage_strict = 0;
	pkt_typed_mem_fd = NOFD;
#ifdef IONET_COMPAT
	ionet_enmap = 1;
#endif

	/*
	 * Make sure fd to slogger is set up.  This avoids
	 * open("/dev/slog", ..) at random times.
	 */
	log(LOG_INFO, "tcpip starting");

	/*
	 * Print something pretty rather than faulting
	 * in stdio when NULL is passed to %s.  See
	 * lib/c/stdio/xputfld.c
	 */
	if ((hdl = dlopen(NULL, RTLD_WORLD)) != NULL) {
		if ((percentsp = dlsym(hdl, "output_for_percent_s_NULL")) != NULL)
			*percentsp = percent_s_null;
		dlclose(hdl);
	}

	if ((pagesize = sysconf(_SC_PAGESIZE)) == -1) {
		ret = errno;
		main_fini(0, ret, "_SC_PAGESIZE");
		return ret;
	}

	pagesize_large = 128 * 1024;

	sctlp = &stk_ctl;
	wtp = WTP;

	/* This is the first thread through */
	sctlp->stack_inuse = 1;
	wtp->am_stack = 1;

	/*
	 * See _connect_ctrl.c.  Setting this prevents alloca()
	 * if we also have a small stack (which we do).
	 */
	_connect_malloc = 1;

	/* Some defaults */
	sctlp->nprocs_min     = 15;
	sctlp->nprocs_max     = 200;
	sctlp->nprocs_incr    = 25;
	/* The default recv_max (recv_ctxt option) is based on the
	 * current default iperf3 buffer size for the TCP benchmark (128K) plus
	 * some overhead.
	 * The default reply_max (reply_ctxt) is based on the same buffer
	 * size. The reply_ctxt is based on parts rather than size.
	 * If this is a benchmark we would be able to reply with 90 clusters.
	 * At default size (2048) cluster with 1500MTU packet, this would be
	 * a bit more than 128K.
	 */
	sctlp->recv_max       = (132 * 1024);
	sctlp->reply_max      = 90;

	sctlp->stacksize      = 4096;
	sctlp->bigstack_size  = (128 * 1024);
	sctlp->rx_prio        = NW_INTR_PRIO;
#ifndef USE_TIMER_INTR
	sctlp->timer_pulse_prio = NW_INTR_PRIO;
#endif

	sctlp->fastforward = 1;
	sctlp->stackguard  = 0;

#ifdef OOB_THREAD_HIGH
	oob_ctl_high.prio = NW_DEF_OOB_PRIO_HIGH;
#endif
#ifdef OOB_THREAD_LOW
	oob_ctl_low.prio = NW_DEF_OOB_PRIO_LOW;
#endif

	nw_max_prio = sched_get_priority_max(SCHED_FIFO);
	nw_max_prio = max(nw_max_prio, sched_get_priority_max(SCHED_RR));
	nw_max_prio = max(nw_max_prio, sched_get_priority_max(SCHED_OTHER));

	while (options && *options != '\0') {
		char		*value, *prev;
		int		opt, ival;
		unsigned long	val;
		struct nlist_old	nl[2];
		char		*restore;

		restore = strchr(options, ',');
			
		opt = getsubopt(&options, tcpip_opts, &value);

		switch (opt) {
		case OPT_RECV_CTXT:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 4 * 1024);
			ival = imin(ival, 512 * 1024);
			ival &= ~(2048 - 1);
			sctlp->recv_max = ival;
			break;
		case OPT_REPLY_CTXT:
			if (value == NULL)
				break;
			/* Specified as num of packet buffers. These
			 * buffers may be combined for short packets. */
			ival = strtol(value, NULL, 0);
			ival = imax(ival, 32);
			ival = imin(ival, 512);
			sctlp->reply_max = ival;
			break;
		case OPT_SOMAXCONN:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			somaxconn = imax(SOMAXCONN, ival);
			break;

		case OPT_THREADS_MIN:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			sctlp->nprocs_min = imax(4, ival);
			sctlp->nprocs_min = imin(sctlp->nprocs_min, sctlp->nprocs_max);
			break;

		case OPT_THREADS:    /* Left around for compatibility */
		case OPT_THREADS_MAX:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			sctlp->nprocs_max = imax(4, ival);
			sctlp->nprocs_max = imax(sctlp->nprocs_max, sctlp->nprocs_min);
			break;

		case OPT_THREADS_INCR:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			sctlp->nprocs_incr = imax(4, ival);
			break;

		case OPT_PREFIX:
			if (value == NULL)
				break;

			prefix = value;
			/* Save len before ',' which getsubopt may() have removed is restored */
			prefix_len = strlen(prefix);

			/* Save prefix for DLLs mounted later and their resource managers. */
			if ((__prefix = strdup(prefix)) == NULL) {
				ret = errno;
				main_fini(0, ret, "strdup prefix");
				return ret;
			}
			break;

		case OPT_STACKSIZE:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			sctlp->stacksize = imax(sctlp->stacksize, ival);
			break;

		case OPT_FORWARD:
			ipforwarding = 1;
			break;

		case OPT_FASTFORWARD:
			if (value != NULL) {
				sctlp->fastforward = strtol(value, NULL, 0);
				if (sctlp->fastforward != 0) {
					sctlp->fastforward = 1;
					ipforwarding = 1;
				}
			}
			else {
				/*
				 * Assume they're turning it on
				 * and therefore set ipforwarding
				 * (compatible to old behaviour)
				 */
				ipforwarding = 1;
			}
			break;

#ifndef USER_TIMER_INTR
		case OPT_TIMER_PULSE_PRIO:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 1);
			ival = imin(ival, nw_max_prio);
			sctlp->timer_pulse_prio = ival;
			break;
#endif

		case OPT_RX_PULSE_PRIO: /* Compat */
		case OPT_RX_PRIO:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 1);
			ival = imin(ival, nw_max_prio);
			sctlp->rx_prio = ival;
			break;

		case OPT_RANDOM:
			use_random = 1;
			break;

		case OPT_CACHE:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			do_cache = ival;
			break;

		case OPT_REUSEPORT_UNICAST:
			reuseport_unicast = 1;
			break;

		case OPT_MBUF_CACHE:
		case OPT_PKT_CACHE:
		case OPT_MTAG_CACHE:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 0);
			if (opt == OPT_MBUF_CACHE)
				mbuf_cache_max = ival;
			else if (opt == OPT_MTAG_CACHE)
				mtag_cache_max = ival;
			else
				pkt_cache_max = ival;
			break;

		case OPT_PKT_TYPED_MEM:
			if (value == NULL)
				break;
			if ((pkt_typed_mem_fd =  posix_typed_mem_open(value, O_RDWR,
			    POSIX_TYPED_MEM_ALLOCATE_CONTIG)) == -1) {
				log(LOG_INFO, "unable to open pkt typed memory %s: %d", value, errno);
				pkt_typed_mem_fd = NOFD;
			}
			break;

		case OPT_PAGESIZE:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, pagesize);
			ival = imin(ival, 16 * 1024 * 1024);
			pagesize_large = round_pow2(ival);
			break;

		case OPT_BIGPAGE_STRICT:
			if (value == NULL) {
				pool_bigpage_strict = 1;
				break;
			}

			pool_bigpage_strict = strtol(value, NULL, 0);
			break;

		case OPT_MCLBYTES:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, (1 << MCLSHIFT_NTOMIN));
			ival = imin(ival, 16 * 1024);
			mclbytes = round_pow2(ival);
			break;

#ifdef OOB_THREAD_HIGH
		case OPT_OOB_PRIO_HIGH:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 1);
			ival = imin(ival, nw_max_prio);
			oob_ctl_high.prio = ival;
			break;
#endif

#ifdef OOB_THREAD_LOW
		case OPT_OOB_PRIO_LOW:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			ival = imax(ival, 1);
			ival = imin(ival, nw_max_prio);
			oob_ctl_low.prio = ival;
			break;
#endif

#ifdef INET6
		case OPT_FORWARD6:
			ip6_forwarding = 1;
			break;
#endif

#if defined(IPSEC) || defined(FAST_IPSEC)
		case OPT_IPSEC:
			qnxnto_ipsec_enabled = 1;
			break;

#ifdef FAST_IPSEC
		case OPT_NOCRYPTODEV:
			__cryptodev = 0;
			break;
#endif
#ifdef PFIL_HOOKS
		case OPT_PFIL_IPSEC:
			pfil_ipsec = 1;
			break;
#endif
#endif			
#ifdef ALTQ_RESMGR
		case OPT_ALTQ:
			altq = 1;
			break;
#endif

		case OPT_CONFSTR_MONITOR:
			confstr_monitor = 1;
			break;

#ifdef FAKE_UP_WRITES
		case FAKE_SRC_CACHED:
			fake_nocache_flag = 0;
			break;

		case NFAKE:
			if (value == NULL)
				break;

			nfake = strtol(value, NULL, 0);
			nfake = max(nfake, 0);
			nfake = min(nfake, 100);
			break;
#endif
		case OPT_ENMAP:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
#ifdef IONET_COMPAT
			ionet_enmap = ival;
#else
			if (ival) {
				log(LOG_INFO, "tcpip: no io-net compat.  "
				    "Ignoring \"%s\" option.", tcpip_opts[OPT_ENMAP]);
			}
#endif
			break;

		case OPT_TIMERTOL:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			if (ival < 0 || ival > 1000) {
				log(LOG_INFO, "tcpip: \"%s\" option: "
				    "%d %s.  Ignoring",
				    tcpip_opts[OPT_TIMERTOL], ival, ival < 0 ? "< 0" : "> 1000");
			}
			else {
				sctlp->timertol = ival;
			}
			break;
#ifdef NTAP
		case OPT_NUM_TAP_INTERFACE:
			__num_tap_interface = strtol(value, NULL, 0);
			break;
#endif
#ifdef NTUN
		case OPT_NUM_TUN_CONTROL_INTERFACE:
			__num_tun_control_interface = strtol(value, NULL, 0);
			break;
#endif
		case OPT_RGROUP_ALLOWED:
			log(LOG_INFO,
			    "tcpip: option %s: allowing root-group access", 
			/*
			 * Allow root-group access to root-only networking capabilities.
			 *
			 * When this option is defined, processes that are spawned as members of
			 * the root group (nto) are also allowed access to services that are
			 * restricted to root-only normally.
			 */
			tcpip_opts[OPT_RGROUP_ALLOWED]);
			if (value == NULL) {
				admin_group = 0;
			} else {
				admin_group = strtoul(value, NULL, 0);
			}
			secmodel_init(TCPIP_SUSER_RGROUP_ALLOW);
			break;

		case OPT_TICKSTOP_MIN:
		case OPT_TICKSTOP_MAX:
			if (value == NULL)
				break;

			ival = strtol(value, NULL, 0);
			if (opt == OPT_TICKSTOP_MIN)
				tickstop_min = ival;
			else
				tickstop_max = ival;
			break;
#ifdef QNX_MFIB
		case OPT_MFIB_ENABLE:
			log(LOG_INFO,
			    "tcpip: option %s: multi-fib enabled",
			    tcpip_opts[OPT_MFIB_ENABLE]);
			kauth_set_mfib_state(1);
			break;
		case OPT_MFIB_GID_MAP: {

			int fib = 0, gid = 0;
			char *equal = NULL, *semic = NULL;

			if (value == NULL)
				break;

			if (strchr(value, '=') == NULL) {
				for (;;) {
					if ((semic = strchr(value, ';')) != NULL)
						*semic = '\0';

					ival = strtol(value, NULL, 0);
					if (kauth_set_mfib_gid_map(ival, fib) == 0) {
						log(LOG_INFO,
						"tcpip: option %s: multi-fib gid %d mapped to fib #%d",
						tcpip_opts[OPT_MFIB_GID_MAP],
						ival, fib);
					} else {
						log(LOG_INFO,
						"tcpip: option %s: multi-fib failed to map gid %d",
						tcpip_opts[OPT_MFIB_GID_MAP],
						ival);
					}
					if (semic == NULL)
						break;
					fib++;
					*semic = ';';
					value = semic + 1;
				}
			} else {
				/* We/re expecting a semicolon-separated list of GID_FIB like: */
				/* 750_0;751_1;1000_15*/
				for (;;) {
					if ((equal = strchr(value, '=')) == NULL)
						break;

					if ((semic = strchr(value, ';')) != NULL) {
						*semic = '\0';
					}

					*equal = '\0';
					gid = strtol(value, NULL, 0);
					fib = strtol(equal+1, NULL, 0);
					*equal= '=';


					if (kauth_set_mfib_gid_map(gid, fib) == 0) {
						log(LOG_INFO,
						"tcpip: option %s: multi-fib gid %d mapped to fib #%d",
						tcpip_opts[OPT_MFIB_GID_MAP], gid, fib);
					} else {
						log(LOG_INFO,
						"tcpip: option %s: multi-fib failed to map gid %d to fib #%d",
						tcpip_opts[OPT_MFIB_GID_MAP], gid, fib);
					}


					if (semic == NULL)
						break;

					*semic = ';';
					value = semic +  1;
				}
			}
			break;
		}
#endif
		case OPT_SOPRIO_ENABLE:
			log(LOG_INFO,
				"tcpip: option %s: SO_TXPRIO support enabled",
				tcpip_opts[OPT_SOPRIO_ENABLE]);
			so_txprio_enabled = 1;
			break;
                case OPT_STACKGUARD:
                    sctlp->stackguard = 1;
                    break;

		case OPT_GTIMERLIB:
			if (value != NULL)
				gtimerlib = strdup(value);
			break;

		case OPT_BIGSTACK:
			if (value == NULL) {
				log(LOG_INFO, "tcpip: bigstack size "
				    "default %d", sctlp->bigstack_size);
			} else {
				sctlp->bigstack_size = strtol(value, NULL, 0);
			}
			break;

		case OPT_STRICT_TS:
			ts_fail = 1;
			break;

		case -1:
			/* If here, getsubopt() didn't find a token */

			/* 
			 * For some reason getsubopt sets value to start
			 * of this opt when no token found.
			 */
			prev = value;
			if (prev == NULL)
				break;

			value = strchr(prev, '=');
			if (value != NULL)
				value++;
				
			/* If no value is specified, we assume they mean "set". */
			if (value)
				val = strtol(value, 0, 0);
			else
				val = 1;
				
			strncpy(nl[0].n_name, prev, sizeof nl[0].n_name);
			nl[0].n_type = 0;
			nl[1].n_name[0] = 0;
			nlist_old(nl, 1);
				
			switch (nl[0].n_type) {
			case sizeof(char):
				*((char *)nl[0].n_value) = val;
				break;

			case sizeof(short):
				*((short *)nl[0].n_value) = val;
				break;

			case sizeof(long):
				*((long *)nl[0].n_value) = val;
				break;

			case 0:
			default:
				log(LOG_INFO, "tcpip: unrecognized option: \"%s\"\n", prev);
				break;

			}
			break;

		default:
			break; //should never happen
		}

		if (restore != NULL)
			*restore = ',';
	}

	if (tickstop_min < 0 || tickstop_max < 0 ||
	    tickstop_max < tickstop_min) {
		log(LOG_INFO, "tcpip: invalid tickstop combination (ignored)");
		tickstop_min = tickstop_max = 0;
	}

	if (sctlp->stackguard) {
	    pagesize = sysconf(_SC_PAGESIZE);
	    if ((sctlp->stacksize % pagesize) != 0) {
	        oldsize = sctlp->stacksize;
		sctlp->stacksize = ((oldsize / pagesize) + 1) * pagesize;
		log(LOG_INFO, "tcpip: stackguard enabled and configured stacksize %d was not a multiple of pagesize %d, increasing stacksize to %d\n",
		    oldsize, pagesize, sctlp->stacksize);
	    }
	}

	mclbytes = imin(mclbytes, pagesize_large);
	mclshift = ffs(mclbytes) - 1;

	size = (nw_max_prio+1) * sizeof(*sctlp->proc_prio.prio_prios);
	if ((sctlp->proc_prio.prio_prios = malloc(size, M_INIT, M_NOWAIT)) == NULL)
		return ENOMEM;

	memset(sctlp->proc_prio.prio_prios, 0x00, size);

	sctlp->do_cache       = do_cache;

	if (cache_init(0, &qnx_cachectl, NULL) == -1) {
		ret = errno;
		main_fini(1, ret, "cache_init");
		return ret;
	}

	/*
	 * If only one is a nop, we may end up doing both.  Don't
	 * think this currently happens but log it in case it
	 * changes.
	 */
	if (((qnx_cachectl.flags & __CACHE_FLUSH_NOP) != 0 &&
	    (qnx_cachectl.flags & __CACHE_INVAL_NOP) == 0) ||
	    ((qnx_cachectl.flags & __CACHE_FLUSH_NOP) == 0 &&
	    (qnx_cachectl.flags & __CACHE_INVAL_NOP) != 0)) {
		log(LOG_WARNING, "cache nops mismatch");
	}

	if ((ret = iopkt_selfp->ex_init(&sctlp->stack_ex)) != EOK) {
		main_fini(2, ret, "ex_init");
		return ret;
	}

	if ((ret = iopkt_selfp->ex_init(&sctlp->pkt_ex)) != EOK) {
		main_fini(3, ret, "ex_init");
		return ret;
	}

	if ((sctlp->chid = ChannelCreate(_NTO_CHF_UNBLOCK | _NTO_CHF_DISCONNECT)) == -1) {
		ret = errno;
		main_fini(4, ret, "ChannelCreate");
		return ret;
	}

	if ((sctlp->coid = ConnectAttach(ND_LOCAL_NODE, 0, sctlp->chid, _NTO_SIDE_CHANNEL, 0)) == -1) {
		ret = errno;
		main_fini(5, ret, "ConnectAttach");
		return ret;
	}

	if ((sctlp->dpp = _dispatch_create(sctlp->chid, 0)) == NULL) {
		ret = errno;
		main_fini(6, ret, "_dispatch_create");
		return ret;
	}

	if ((nw_pci_hdl = pci_attach(0)) == -1) {
		/*
		 * Soft error, probably won't be able to start
		 * any drivers though.
		 */
		log(LOG_WARNING, "Unable to attach to pci server: %s", strerror(errno));
	}

	if (use_random == 0)
		log(LOG_WARNING, "Using pseudo random generator.  See \"random\" option");
	else
		rnd_seed_fd();
	
	/* defined in stubs.c, orignal from conf/param.c */
	
	/* See comment for HZ in qnx.h */
	hz = NTO_HZ;
	tick = 1000000 / hz;

	tickstop_min *= hz;
	if (tickstop_min == 0) {
		/*
		 * Default is twice the default period.
		 *
		 * This is ignored unless tickstop_max is specified.
		 */

		/* TIMER_PULSE_PERIOD is in nsec */
		tickstop_min = (uint64_t)2*TIMER_PULSE_PERIOD*hz / 1000000000;
	}
	tickstop_max *= hz;

	sctlp->recv_max  = max(sctlp->recv_max, MCLBYTES);

	if (sctlp->recv_max & (MCLBYTES -1)) {
		sctlp->recv_max += MCLBYTES;
		sctlp->recv_max &= ~(MCLBYTES -1);
	}

	/* Convert to clusters */
	sctlp->recv_max = sctlp->recv_max / MCLBYTES + 1; /* +1 for room for headers, addrlen, ctrlen */

	if (sctlp->stacksize & (NW_STK_ALIGN - 1)) {
		sctlp->stacksize += NW_STK_ALIGN;
		sctlp->stacksize &= ~(NW_STK_ALIGN - 1);
	}

	if (sctlp->bigstack_size != 0) {
		if (sctlp->bigstack_size > sctlp->stacksize) {
			if (sctlp->bigstack_size & (NW_STK_ALIGN - 1)) {
				sctlp->bigstack_size += NW_STK_ALIGN;
				sctlp->bigstack_size &= ~(NW_STK_ALIGN - 1);
			}
		} else {
			log(LOG_INFO, "tcpip: bigstack size %d <= stacksize %d, ignoring",
			    sctlp->bigstack_size, sctlp->stacksize);
			sctlp->bigstack_size = 0;
		}
	}

	/*
	 * + 1 because it makes the logic for insertion into the array cleaner.
	 * m_next of last member always points to NULL since last + 1 slot should
	 * always be 0.
	 */
	size = (sctlp->recv_max + 1) * sizeof *sctlp->recv_mbuf;
	if ((sctlp->recv_mbuf = malloc(size, M_INIT, M_NOWAIT)) == NULL) {
		main_fini(7, ENOMEM, NULL);
		return ENOMEM;
	}
	memset(sctlp->recv_mbuf, 0x00, size);

	size = sctlp->recv_max * sizeof *sctlp->recv_iov;
	if ((sctlp->recv_iov = malloc(size, M_INIT, M_NOWAIT)) == NULL) {
		main_fini(8, ENOMEM, NULL);
		return ENOMEM;
	}
	memset(sctlp->recv_iov, 0x00, size);

	/* now some nto stuff */
	nlist_init();
	init_time();
	notify_init();

#ifndef USE_TIMER_INTR
	SIGEV_PULSE_INIT(&sctlp->timer_ev, sctlp->coid,
			 sctlp->timer_pulse_prio, NW_DEF_PULSE_CODE_TIMER, 0);
#endif
	if ((ret = clock_intr_init(sctlp)) != EOK) {
		main_fini(9, ret, "clock_intr_init");
		return ret;
	}

	/* always NULL terminates. ret includes NULL */
	ret = confstr(_CS_HOSTNAME, hostname,  sizeof(hostname));
	/* strlen(hostname) */
	hostnamelen = min(ret, sizeof(hostname)) - 1;
	
	/* 
	 * Register our paths.
	 */
	iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &autoconnect_cfuncs,
	    _RESMGR_IO_NFUNCS, &autoconnect_iofuncs);

	iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &config_cfuncs,
	    _RESMGR_IO_NFUNCS, &config_iofuncs);

	iofunc_attr_init(&inet_info.attr, S_IFSOCK | 0666, 0, 0);
	iofunc_attr_init(&route_info.attr, S_IFSOCK | 0666, 0, 0);
#ifndef NO_UNIX_DOMAIN
	iofunc_attr_init(&unix_info.attr, S_IFSOCK | 0666, 0, 0);
#endif
#ifdef INET6
	iofunc_attr_init(&inet6_info.attr, S_IFSOCK | 0666, 0, 0);
#endif
#if defined(IPSEC) || defined(FAST_IPSEC)
	iofunc_attr_init(&key_info.attr, S_IFSOCK | 0666, 0, 0);
#endif
	iofunc_attr_init(&autoconnect_info.attr, S_IFNAM | fperm, 0, 0);
	iofunc_attr_init(&config_info.attr, S_IFNAM | fperm, 0, 0);

	if (prefix != NULL)
		workpath_len += prefix_len;

	if ((workpath = alloca(workpath_len)) == NULL) {
		main_fini(10, ENOMEM, NULL);
		return ENOMEM;
	}

	memset(workpath, 0x00, workpath_len);
	if (prefix != NULL)
		strlcpy(workpath, prefix, workpath_len);

	prefix = workpath;
	workpath += prefix_len;
	workpath_len -= prefix_len;
	sockendp = workpath + strlcpy(workpath, "/dev/socket/", workpath_len);
	sockend_len = workpath_len - (sockendp - workpath);

	memset(&resmgr_attr, 0, sizeof resmgr_attr);
	resmgr_attr.nparts_max = 1;
	resmgr_attr.msg_max_size = MLEN; /* The min if out of resources. We vary the real value */

	itoa(AF_INET, sockendp, 10);
	if ((inet_info.path_id = resmgr_attach(sctlp->dpp,
	    &resmgr_attr, prefix, _FTYPE_SOCKET, _RESMGR_FLAG_SELF,
	    &tcpip_connect_funcs, NULL, &inet_info)) == -1) {
		ret = errno;
		main_fini(10, ret, "resmgr_attach");
		return ret;
	}

	itoa(AF_ROUTE, sockendp, 10);
	if ((route_info.path_id = resmgr_attach(sctlp->dpp,
	    &resmgr_attr,prefix, _FTYPE_SOCKET, _RESMGR_FLAG_SELF,
	    &tcpip_connect_funcs, NULL, &route_info)) == -1) {
		ret = errno;
		main_fini(11, ret, "resmgr_attach");
		return ret;
	}

#ifndef NO_UNIX_DOMAIN
	itoa(AF_UNIX, sockendp, 10);
	if ((unix_info.path_id = resmgr_attach(sctlp->dpp,
	    &resmgr_attr, prefix, _FTYPE_SOCKET, _RESMGR_FLAG_SELF,
	    &tcpip_connect_funcs, NULL, &unix_info)) == -1) {
		ret = errno;
		main_fini(12, ret, "resmgr_attach");
		return ret;
	}
#endif
	
#ifdef INET6
	itoa(AF_INET6, sockendp, 10);
	if ((inet6_info.path_id = resmgr_attach(sctlp->dpp,
	    &resmgr_attr, prefix, _FTYPE_SOCKET, _RESMGR_FLAG_SELF,
	    &tcpip_connect_funcs, NULL, &inet6_info)) == -1) {
		ret = errno;
		main_fini(13, ret, "resmgr_attach");
		return ret;
	}
#endif

#if defined(IPSEC) || defined(FAST_IPSEC)
	if (qnxnto_ipsec_enabled) {
		itoa(PF_KEY, sockendp, 10);
		if ((key_info.path_id = resmgr_attach(sctlp->dpp,
		    &resmgr_attr, prefix, _FTYPE_SOCKET, _RESMGR_FLAG_SELF,
		    &tcpip_connect_funcs, NULL, &key_info)) == -1) {
			ret = errno;
			main_fini(14, ret, "resmgr_attach");
			return ret;
		}
	}
#endif

	strlcpy(sockendp, "autoconnect", sockend_len);
	if ((autoconnect_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &autoconnect_cfuncs,
	    &autoconnect_iofuncs, &autoconnect_info.attr)) == -1) {
		ret = errno;
		main_fini(15, ret, "resmgr_attach");
		return ret;
	}

	strlcpy(sockendp, "config", sockend_len);
	if ((config_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &config_cfuncs,
	    &config_iofuncs, &config_info.attr)) == -1) {
		ret = errno;
		main_fini(16, ret, "resmgr_attach");
		return ret;
	}

	/* Handle mount requests */
	if ((mount_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, NULL, _FTYPE_MOUNT,
	    _RESMGR_FLAG_FTYPEONLY|_RESMGR_FLAG_DIR, &mount_cfuncs,
	    NULL, NULL)) == -1) {
		ret = errno;
		main_fini(18, ret, "resmgr_attach");
		return ret;
	}

#ifdef FAKE_UP_WRITES
	/* We always use the same source so it has to be at least MCLBYTES in size */
	if ((fake_cpy_buf = mmap(0, MCLBYTES, PROT_READ | PROT_WRITE | fake_nocache_flag,
	    MAP_PRIVATE | MAP_ANON, NOFD, 0)) == MAP_FAILED) {
		ret = errno;
		main_fini(19, ret, "mmap fake_cpy_buf");
		return ret;
	}
#endif

#ifdef ALTQ_RESMGR
	if (altq != 0) {
		/* Needs the SOCK prefix without the /dev/socket */
		strlcpy(workpath, workpath_len, "/dev/altq");
		iofunc_attr_init(&altq_info.attr, S_IFDIR | 0666, 0, 0);
		if ((altq_info.path_id = resmgr_attach(sctlp->dpp,
		    NULL, prefix, _FTYPE_ANY, _RESMGR_FLAG_DIR, &altq_cfuncs,
		    &altq_iofuncs, &altq_info.attr)) == -1) {
			ret = errno;
			main_fini(20, ret, "resmgr_attach");
			return ret;
		}
	}
#endif
#ifdef FAST_IPSEC
	/* Initializes the opencrypto framework */
	crypto_init();

	if (__cryptodev) {
		/* Needs the SOCK prefix without the /dev/socket */
		strlcpy(workpath, "/dev/crypto", workpath_len);
		iofunc_attr_init(&cryptodev_info.attr, S_IFNAM | fperm, 0, 0);
		if ((cryptodev_info.path_id = resmgr_attach(sctlp->dpp, NULL, prefix,
		    _FTYPE_ANY, 0, &tcpip_connect_funcs, NULL,
		    &cryptodev_info)) == -1) {
			ret = errno;
			main_fini(21, ret, "resmgr_attach");
			return ret;
		}
	}
#endif

#if NBPFILTER > 0
	ret = bpf_init();
	if (ret != EOK) {
		main_fini(22, ret, "bpf_init");
		return ret;
	}

	/* Needs the SOCK prefix without the /dev/socket */
	strlcpy(workpath, "/dev/bpf", workpath_len);
	iofunc_attr_init(&bpf_info.attr, S_IFCHR | 0600, 0, 0);
	if ((bpf_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs,
	    NULL, &bpf_info.attr)) == -1) {
		ret = errno;
		main_fini(23, ret, "resmgr_attach");
		return ret;
	}

	/* Create a /dev/bpf0 entry, alongside the /dev/bpf entry */
	strlcpy(workpath, "/dev/bpf0", workpath_len);
	iofunc_attr_init(&bpf_info2.attr, S_IFCHR | 0600, 0, 0);
	if ((bpf_info2.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs,
	    NULL, &bpf_info2.attr)) == -1) {
		ret = errno;
		main_fini(24, ret, "resmgr_attach");
		return ret;
	}
#endif
	if ((ret = quiesce_init()) != EOK) {
		main_fini(25, ret, "quiesce_init");
		return ret;
	}

	if ((ret = interrupt_init()) != EOK) {
		main_fini(26, ret, "interrupt_init");
		return ret;
	}

	blockop_init();
	/* NTO specific pool init */
	pool_subsystem_birth(&pool_bigpage_strict);

	pool_subsystem_init();
	slpq_init();

	callout_startup();

	mbinit();
	soinit();
	evcnt_init();
	sysctl_init();
	kauth_init();
	secmodel_start(); /* default model */

	msg_init();

	arpinit();

	init_procs(sctlp, 500);

	/* Bring up (attach) interfaces, see ioconf.c in BSD */
#if NLOOP > 0
	loopattach(1);
#endif
#if NPPP > 0
	pppmgr_resinit((void *)sctlp, prefix, prefix_len);
#endif
#if NPPPOE > 0
	{
	extern void pppoeattach(int);
	pppoeattach(NPPPOE);
	}
#endif
#ifdef FAST_IPSEC
	{
	extern void cryptoattach(int);
	extern void swcryptoattach(int);
	cryptoattach(1);
	swcryptoattach(1);
	}
#endif
#if NGRE > 0
	greattach(1);
#endif
#if NGIF > 0
	gifattach(1);
#endif
#if NVLAN > 0
	vlanattach(1);
#endif
#if NIFIPSEC > 0
    ifipsecattach(1);
#endif
#if NBRIDGE > 0
	bridgeattach(1);
#endif

#ifdef  FAST_IPSEC
	/* Attach network crypto subsystem */
	ipsec_attach();
#endif
	/* These two after all interfaces attached */
	ifinit();
	domaininit();
	if_attachdomain();

	/*
	 * Set this now before we (stack thread) start
	 * which opens allprocs up to realloc.
	 */
	sctlp->proc0 = &sctlp->allprocs[0].procs[0];

	/* Bring up localhost */
	loopconfig();

#if NPF > 0
#ifndef __QNXNTO__ 
	pfattach();

	/* Needs the SOCK prefix without the /dev/socket */
	strlcpy(workpath, workpath_len, "/dev/pf");
	iofunc_attr_init(&pf_info.attr, S_IFNAM | 0006, 0, 0);
	if ((pf_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs,
	    NULL, &pf_info.attr)) == -1) {
		ret = errno;
		main_fini(27, ret, "resmgr_attach");
		return ret;
	}

#endif
#endif

#if NSRT > 0
	srtattach();

	strlcpy(workpath, workpath_len, "/dev/srt0");
	iofunc_attr_init(&srt_info.attr, S_IFCHR | 0600, 0, 0);
	srt_info.index = 0; /* 0 == srt0 */
	if ((srt_info.path_id = resmgr_attach(sctlp->dpp,
	    NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs,
	    NULL, &srt_info.attr)) == -1) {
		ret = errno;
		main_fini(28, ret, "resmgr_attach");
		return ret;
	}
#endif

#if NTUN > 0
	{
		int i;
		tunattach(0); /*Arg is not used*/
		tun_info = malloc(sizeof(struct msg_open_info) * __num_tun_control_interface, M_INIT, M_NOWAIT);
		if (tun_info == NULL) {
			ret = errno;
			main_fini(27, ret, "malloc tun interface");
			return ret;
		}
		for (i = 0; i < __num_tun_control_interface; i++) {
			strlcpy(workpath, "/dev/tun", workpath_len);
			itoa(i, prefix + strlen(prefix), 10);
			iofunc_attr_init(&tun_info[i].attr, S_IFCHR | 0600, 0, 0);
			tun_info[i].index = i;
			tun_info[i].domain = 0;
			tun_info[i].path_type = PATH_TYPE_TUN;
			if ((tun_info[i].path_id = resmgr_attach(sctlp->dpp, NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs, NULL, &tun_info[i].attr)) == -1) {
				ret = errno;
				main_fini(29, ret, "resmgr_attach");
				return ret;
			}
		}
	}
#endif

#if NTAP > 0
	{
		tapattach(__num_tap_interface);

		strlcpy(workpath, "/dev/tap", workpath_len);
		iofunc_attr_init(&tap_info.attr, S_IFCHR | 0600, 0, 0);
		tap_info.index = -1;
		if ((tap_info.path_id = resmgr_attach(sctlp->dpp,
		    NULL, prefix, _FTYPE_ANY, 0, &tcpip_connect_funcs,
		    NULL, &tap_info.attr)) == -1) {
			ret = errno;
			main_fini(30, ret, "resmgr_attach");
			return ret;
		}
	}
#endif

	if (confstr_monitor) {
		struct sigevent ev;

		SIGEV_PULSE_INIT(&ev, sctlp->coid, NW_DEF_CONFSTR_PRIO, NW_DEF_PULSE_CODE_PROGMGR_EVENT, 0);
		procmgr_event_notify_add(PROCMGR_EVENT_CONFSTR, &ev);
	}

	/*
	 * PPC uses the p_jmp_arg field below in sched(). This field is set in
	 * pcreat(), but the "original" proc doesn't call pcreat().
	 */
#ifdef __PPC__
	sctlp->proc0->p_jmp_arg = &stk_ctl;
#endif

	return 0;
}

static void
loopconfig(void)
{
	struct ifnet		*ifp;
	struct ifaliasreq	ifra;
	struct sockaddr_in	*in;
	struct lwp		*l;

	l = curlwp;
#ifndef QNX_MFIB
	ifp = lo0ifp;
#else
	int fib;
	for (fib=0; fib<FIBS_MAX; fib++) {
		ifp = lo0ifp[fib];

#endif
	memset(&ifra, 0, sizeof ifra);
	strcpy(ifra.ifra_name, ifp->if_xname);

	in = (void *)&ifra.ifra_addr;
	in->sin_len = sizeof(*in);
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = htonl(0x7f000001);

	proc0_getprivs(l);

	in_control(0, SIOCDIFADDR, (void *)&ifra, ifp, curlwp);
	in_control(0, SIOCAIFADDR, (void *)&ifra, ifp, curlwp);
#ifdef INET6
	in6_if_up(ifp);
#endif
	proc0_remprivs(l);
#ifdef QNX_MFIB
	}
#endif
	return;
}



void
load_drivers (void *arg)
{
	int			opt, verbose;
	char			*mod_opts;
	struct _iopkt_self	*iopkt;
	struct nw_stk_ctl	*sctlp;
	struct rcv_loop_args	*rargs;

	iopkt = iopkt_selfp;
	sctlp = &stk_ctl;
	rargs = arg;
	if (rargs == NULL) {
		kthread_exit(0);
	}

	verbose = 0;

	/* pull out -v first */
	while (optind < rargs->main_argc) {
		if ((opt = getopt(rargs->main_argc,
		    rargs->main_argv, "v")) == -1) {
			optind++;
			continue;
		}
		switch (opt) {
		case 'v':
			verbose++;
			break;
		}
	}
	optind = 1; /* reset */

	while (optind < rargs->main_argc) {
		if ((opt = getopt(rargs->main_argc,
		    rargs->main_argv, "d:p:")) == -1) {
			optind++;
			continue;
		}

		if (optind >= rargs->main_argc ||
		    rargs->main_argv[optind] == NULL ||
		    *rargs->main_argv[optind] == '-')
			mod_opts = NULL;
		else
			mod_opts = rargs->main_argv[optind];

		switch (opt) {
		case 'd':

			init_load("devnp-", optarg, ".so", mod_opts, verbose);
			break;

		case 'p':
			if (strstr(optarg, "tcpip") != NULL)
				break; /* builtin */

			init_load("lsm-", optarg, ".so", mod_opts, verbose);
			break;

		default:
			break;
		}
	}
	kthread_exit(0);
}

static void
init_load(char *prefix, char *arg, char *suffix, char *opts, int verbose)
{
	char	*mp;

	mp = arg;

	if (arg[0] != '/') {
		if ((mp = malloc(strlen(prefix) + strlen(arg) +
		    strlen(suffix) + 1, M_TEMP, M_NOWAIT)) == NULL) {
			log(LOG_ERR, "Unable to load %s: no mem", arg);
			return;
		}
		strcpy(mp, prefix);
		strcat(mp, arg);
		strcat(mp, suffix);
	}

	nw_dlload_module(verbose, mp, opts, NULL);
	if (mp != arg)
		free(mp, M_TEMP);

	return;
}


int
pre_main_init(void)
{
	int ret;

	if ((ret = interrupt_pre_main_init()) != EOK)
		return ret;

	if ((ret = ipflow_pre_main_init()) != EOK)
		goto BAD1;

#if NBRIDGE > 0
	if ((ret = bridge_pre_main_init()) != EOK)
		goto BAD2;
#endif

	return EOK;

#if NBRIDGE > 0
BAD2:
	ipflow_pre_main_fini();
#endif
BAD1:
	interrupt_pre_main_fini();

	return ret;
}

void
pre_main_fini(void)
{
#if NBRIDGE > 0
	bridge_pre_main_fini();
#endif
	ipflow_pre_main_fini();
	interrupt_pre_main_fini();
}


/* Round down to power of 2 */
static unsigned
round_pow2(unsigned val)
{
	unsigned msk;

	for (msk = ~0u ^ (~0u >> 1); msk != 0 ; msk >>= 1) {
		if (val & msk) {
			val &= ~(msk - 1);
			break;
		}
	}
	return val;

}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/init_main.c $ $Rev: 902838 $")
#endif
