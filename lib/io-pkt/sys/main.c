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





#include "opt_oob.h"
#include "opt_ionet_compat.h"
#include "opt_sigev.h"

#include <malloc.h> /* The QNX one */
#include <sys/io-pkt.h>
#include <sys/procmgr.h>
#include <sys/syspage.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include "sys/syslog.h"

#include "nw_intr.h"
#include "nw_datastruct.h"
#include "nw_thread.h"
#include "receive.h"
#include "init_main.h"
#include "blockop.h"
#ifdef IONET_COMPAT
#include "ionet_compat.h"
#endif

#if defined(VARIANT_uni) && (defined(OOB_THREAD_LOW) || defined(OOB_THREAD_HIGH))
#error VARIANT_uni and OOB_THREAD are incompatible.
#endif

#if !defined(OPT_SIGEV_PULSE) && !defined(OPT_SIGEV_SIGNAL_TID)
#error one or more event notification mechanisms must be enabled.
#endif

#define IO_PKT_MAIN_THREAD_PRIO 21

extern char *__progname;
static const char *main_options = {
#if 0
	/*
	 * Tradional io-net args which are either not applicable
	 * or not yet simulated / supported.  Use with care.
	 */
	"a"	/* disable automount of converters */
	"m"	/* allow multicast ops on /dev/io-net/en* */
	"s"	/* 'static' configuration */
	"c:"	/* Cache enable / disable */
#endif
	"p:P:d:t:vSD"
#ifdef IONET_COMPAT
	"i:"
#endif
#if defined(OPT_SIGEV_PULSE) && defined(OPT_SIGEV_SIGNAL_TID)
	"e"	/* If both are supported, signal is default, -e toggles */
#endif
};
static char *proto_opts;

struct nw_stk_ctl stk_ctl;
#ifdef OOB_THREAD_LOW
struct nw_oob_ctl oob_ctl_low;
#endif
#ifdef OOB_THREAD_HIGH
struct nw_oob_ctl oob_ctl_high;
#endif
struct _iopkt_self *iopkt_selfp;

static void cache_validate(void);


int init_work_threads(int main_init, int num);
static void cleanup(struct nw_stk_ctl *, int full_cleanup);
static int init_instance(char *, char *, char *, size_t);
static void segv_handler(int);
static void do_exit(struct nw_stk_ctl *, int);



static struct rcv_loop_args rcv_loop_args;

char iopkt_instance[30] = "io-pkt";


static void
do_exit(struct nw_stk_ctl *sctlp, int how)
{
	int exit_status;

	exit_status = EXIT_FAILURE;

	switch (how) {
	case -1:
		exit_status = EXIT_SUCCESS;
	case 4:
		pre_main_fini();
	case 3:
		pthread_key_delete(sctlp->work_thread_key);
	case 2:
		nw_thread_fini();
	case 1:
		free(iopkt_selfp);
	case 0:
	default:
		exit(exit_status);
	}

}


int
main(int argc, char **argv)
{
	int			opt, ret, i, irupt_max;
	struct nw_stk_ctl	*sctlp;
	sigset_t		signals;
	struct sigaction	act;
	siginfo_t		sinfo;
	struct sched_param	sparam;
	size_t			size;
	void *			(*rfunc)(void *);
	int			handle_segv = 1;
	int io_pkt_main_thread_prio = IO_PKT_MAIN_THREAD_PRIO;

	pthread_setname_np(gettid(), "io-pkt main");

	/*
	 * If they're both defined, default is signal (comes last).
	 * -e will toggle back to pulse.
	 */
#ifdef OPT_SIGEV_PULSE
	rcv_loop_args.sigev_type = SIGEV_PULSE;
#endif
#ifdef OPT_SIGEV_SIGNAL_TID
	rcv_loop_args.sigev_type = SIGEV_SIGNAL_TID;
#endif

	sctlp = &stk_ctl;

	/*
	 * We want the stack to load drivers
	 * after its initialization succeeds.
	 */
	rcv_loop_args.main_argc = argc;
	rcv_loop_args.main_argv = argv;
	rcv_loop_args.main_options = main_options;

	cache_validate();

	if (ThreadCtl(_NTO_TCTL_IO, NULL) == -1) {
		log_init(LOG_ERR, "%s: ThreadCtl: %s", __progname, strerror(errno));
		return 1;
	}

	procmgr_daemon(EXIT_SUCCESS, PROCMGR_DAEMON_NODEVNULL);

#ifdef VARIANT_uni
	if (_syspage_ptr->num_cpu > 1) {
		/*
		 * Can't just fall back to single threaded because we
		 * also InterruptDisable() in uni mode rather than
		 * InterruptLock().
		 */
		log_init(LOG_ERR, "VARIANT mismatch: trying to run uniprocessor stack on SMP machine.");
		return 1;
	}
#endif
	sctlp->nthreads_core_max = _syspage_ptr->num_cpu;

	while (optind < argc) {
		if ((opt = getopt(argc, argv, main_options)) == -1) {
			optind++;
			continue;
		}

		switch (opt) {
		case 'p':
			if (strstr(optarg, "tcpip") != NULL) {
				if (optind < argc &&
				    argv[optind] != NULL &&
				    argv[optind][0] != '-') {
					/* skip '*tcpip*' and take next arg */
					proto_opts = argv[optind];
				}
				else {
					/* Just ignore it */
				}
			}
			break;

		case 'P':
			io_pkt_main_thread_prio = atoi(optarg);
			if (io_pkt_main_thread_prio < sched_get_priority_min(SCHED_RR) || io_pkt_main_thread_prio > sched_get_priority_max(SCHED_RR)) {
				log_init(LOG_ERR, "%s: ignoring invalid value %d for option -P", __progname, io_pkt_main_thread_prio);
				io_pkt_main_thread_prio = IO_PKT_MAIN_THREAD_PRIO;
			}
			break;

		case 't':
			sctlp->nthreads_core_max = strtoul(optarg, NULL, 0);
			sctlp->nthreads_core_max = min(sctlp->nthreads_core_max, NW_DEF_THREADS_MAX);
			sctlp->nthreads_core_max = max(sctlp->nthreads_core_max, 1);
			rcv_loop_args.preseed_threads = 1;
			break;

		case 'i':
#ifdef IONET_COMPAT
			if (init_instance(optarg, __progname,
			    ionet_instance + strlen(ionet_instance),
			    sizeof(ionet_instance) - strlen(ionet_instance)) != EOK)
				return 1; /* Stop initialization */
#endif
			if (init_instance(optarg, __progname,
			    iopkt_instance + strlen(iopkt_instance),
			    sizeof(iopkt_instance) - strlen(iopkt_instance)) != EOK)
				return 1; /* Stop initialization */
			break;

#if defined(OPT_SIGEV_PULSE) && defined(OPT_SIGEV_SIGNAL_TID)
		case 'e':
			rcv_loop_args.sigev_type = SIGEV_PULSE;
			break;
#endif

		case 'S':
			handle_segv = 0;
			break;
		case 'D': /* Dedicated stack context thread */
			sctlp->dedicated_stack_context = 1;
			break;
		default:
			break;
		}
	}

	if (SchedGet(0, 0, &sparam) == -1) {
		log_init(LOG_ERR, "%s: SchedGet: %s", __progname, strerror(errno));
		return 1;
	}

	sparam.sched_priority = io_pkt_main_thread_prio;
	if (SchedSet(0, 0, SCHED_NOCHANGE, &sparam) == -1) {
		log_init(LOG_ERR, "%s: SchedSet: %s", __progname, strerror(errno));
		return 1;
	}

#ifdef VARIANT_uni
	if (sctlp->nthreads_core_max > 1) {
		log_init(LOG_WARNING, "Falling back to single thread due to uni variant.");
		sctlp->nthreads_core_max = 1;
	}
#endif

	/*
	 * Allow space for high / low prio OOB threads
	 * to be created later if desired.
	 */
#ifdef OOB_THREAD_HIGH
	sctlp->nthreads_oob_max++;
#endif
#ifdef OOB_THREAD_LOW
	sctlp->nthreads_oob_max++;
#endif

	/* XXX need a command line option */
	sctlp->nthreads_flow_max = sctlp->nthreads_core_max;

	irupt_max = sctlp->nthreads_core_max + sctlp->nthreads_oob_max;
	size = offsetof(struct _iopkt_self, inter_threads[0]) +
	    irupt_max * sizeof(iopkt_selfp->inter_threads[0]);

	if ((iopkt_selfp = malloc(size)) == NULL) {
		log_init(LOG_ERR, "%s: Unable to alloc ctrl struct: %s", __progname, strerror(errno));
		return ENOMEM;
	}

	memset(iopkt_selfp, 0x00, size);

	for (i = 0; i < irupt_max; i++)
		iopkt_selfp->inter_threads[i].inter_tail = &iopkt_selfp->inter_threads[i].inter_head;

	sctlp->iopkt = iopkt_selfp;

	/* reset */
	optind = 1;
	/* Any errs were displayed on first pass */
	opterr = 0;

	/* Initialize or mutex operation callouts */
	if ((ret = nw_thread_init()) != EOK) {
		log_init(LOG_ERR, "%s: nw_thread_init: %s", __progname, strerror(errno));
		do_exit(sctlp, 1);
	}


	if ((ret = pthread_key_create(&sctlp->work_thread_key, NULL)) != EOK) {
		log_init(LOG_ERR, "%s: pthread_key_create: %s",
		    __progname, strerror(ret));
		do_exit(sctlp, 2);
	}

	sigfillset(&signals);
	sigdelset(&signals, SIGSEGV);
	sigdelset(&signals, SIGABRT);
	pthread_sigmask(SIG_BLOCK, &signals, NULL);
	if (handle_segv) {
		signal(SIGSEGV, segv_handler);
	}

	if ((ret = pre_main_init()) != EOK) {
		log_init(LOG_ERR, "%s: pre_main_init: %s",
		    __progname, strerror(ret));
		do_exit(sctlp, 3);
	}

	sigemptyset(&signals);

	act.sa_mask = signals;
#ifdef OPT_SIGEV_SIGNAL_TID
	act.sa_sigaction = interrupt_sig_handler;
	act.sa_flags = SA_NODEFER;  /* Don't have kernel mask off the signal */
	if (sigaction(NW_INTR_SIG, &act, NULL) == -1) {
		log_init(LOG_ERR, "%s: sigaction: %s",
		    __progname, strerror(errno));
		do_exit(sctlp, 4);
	}
#endif

	act.sa_handler = SIG_DFL;
	act.sa_flags = SA_SIGINFO; /* Make it queued */
	if (sigaction(NW_SIG_BLOCKOP, &act, NULL) == -1) {
		log_init(LOG_ERR, "%s: sigaction: %s",
		    __progname, strerror(errno));
		do_exit(sctlp, 4);
	}

	/*
	 * Always OK to do uniprocessor receive if nthreads_core == 1,
	 * even if VARIANT_smp or OOB_THREAD_*.
	 */
	if (sctlp->nthreads_core_max == 1) {
		rfunc = receive_loop_uni;
		if (sctlp->dedicated_stack_context) {
			log_init(LOG_WARNING,
				"Cannot have dedicated stack context core with only 1 core or thread : (-D option, -t option)\n");
			sctlp->dedicated_stack_context = 0;
		}
	}
#ifndef VARIANT_uni
	else {
		rfunc = receive_loop_multi;
	}
#endif

	ret = 0;
	rcv_loop_args.proto_opts = proto_opts;
	if ((ret = nw_pthread_create(NULL, NULL, rfunc, &rcv_loop_args,
	    WT_COREFLAGS, receive_loop_init, &rcv_loop_args)) != EOK) {
		log_init(LOG_ERR, "%s: pthread_create: %s",
		    __progname, strerror(ret));

		do_exit(sctlp, 4);
	}

	sigemptyset(&signals);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, NW_SIG_BLOCKOP);

	for (;;) {
		SignalWaitinfo(&signals, &sinfo);

		switch (sinfo.si_signo) {
		case SIGTERM:
			cleanup(sctlp, 1);
			do_exit(sctlp, -1); /* doesn't return */
			break;

		case NW_SIG_BLOCKOP: {
			struct bop_dispatch *bop;

			if (sinfo.si_pid != getpid())
			       continue;  /* Nice try. */
			bop = sinfo.si_value.sival_ptr;
			(*bop->bop_func)(bop->bop_arg);
			bop->bop_cb.func = blockop_wakeup;
			bop->bop_cb.arg = bop;
			MsgSendPulse(sctlp->coid, bop->bop_prio,
			    NW_DEF_PULSE_CODE_CALLBACK, (intptr_t)&bop->bop_cb);
			break;	
		}

		default:
			break;
		}
	}

}

pthread_t cleanup_stack_tid = -1;
int in_cleanup = 0;

static void
cleanup(struct nw_stk_ctl *sctlp, int full_cleanup)
{
	struct timespec		shutdown_time;
	int			ret;

	/*
	 * We don't know if the thread we created above
	 * is the thread that is the stack when our pulse
	 * is handled.
	 */
	pthread_sleepon_lock();
	if (in_cleanup) {
		/*
		 * If we're already in cleanup then we got hit with a SIGSEGV while processing a SIGTERM or
		 * the other way around. Either way we'll sleepon forever if the earlier cleanup already went through
		 * here. Therefore just return.
		 */
		log_init(LOG_WARNING, "Double signals detected! Already in cleanup.");
		pthread_sleepon_unlock();
		return;
	}
	in_cleanup = 1;
	MsgSendPulse(sctlp->coid, NW_DEF_PRIO_CLEANUP, NW_DEF_PULSE_CODE_DODIE,
		     (int)&cleanup_stack_tid);
	pthread_sleepon_wait(&cleanup_stack_tid);
	pthread_sleepon_unlock();
	
	if (clock_gettime(CLOCK_MONOTONIC, &shutdown_time) != -1) {
	    /* 
	     * If we can get clock time then do a timed join allowing 15 seconds 
	     * for the shutdown procs to complete. 
	     */
	    shutdown_time.tv_sec+= 15;
	    if ((ret = pthread_timedjoin_monotonic(cleanup_stack_tid, NULL, &shutdown_time)) != 0) {
		log_init(LOG_WARNING, "%s: timedjoin: %s", __progname,
			 strerror(ret));
	    }
	} else if (full_cleanup) {
	    /*
	     * In the full (shutdown) clean up case wait forever for the stack 
	     * thread to complete to guarantee orderly shutdown.
	     */
	    (void) pthread_join(cleanup_stack_tid, NULL);
	}
}


static void
cache_validate(void)
{
	struct cacheattr_entry	*cache_base;
	struct cacheattr_entry	*cache;
	int			cache_idx;

	cache_base = SYSPAGE_ENTRY(cacheattr);
	for (cache_idx = SYSPAGE_ENTRY(cpuinfo)->data_cache;
	    cache_idx != CACHE_LIST_END;
	    cache_idx = cache->next) {

		cache = &cache_base[cache_idx];

		if (cache->line_size > NET_CACHELINE_SIZE)
			log_init(LOG_WARNING, "NET_CACHELINE_SIZE suboptimal");
	}

	return;
}


/* Imitate the io-net API */
static int
init_instance(char *optarg, char*__progname, char *buf, size_t bufsize)
{
	char *ep;
	unsigned long instance;

	instance = 0;
	ep = NULL;
	instance = strtoul(optarg, &ep, 10);
	if (ep == NULL || *ep != '\0' || instance == ULONG_MAX) {
		log_init(LOG_ERR, "%s: Invalid instance number: %s\n",
		    __progname, strerror(errno));
		return EINVAL;
	}

	if (instance == 0) {
		/* map -i0 -> "io-pkt" */
		return EOK;
	}

	if (snprintf(buf, bufsize, "%lu", instance) >= bufsize)
		return EINVAL; 

	return EOK;
}

void
segv_handler(int signo)
{

	if (nw_thread_istracked()) {
		/*
		 * For now do the minimum amount of work in an attempt
		 * to not alter the state of the system at the time of
		 * the segv too much.
		 *
		 * As long as the shutdown callouts don't do too much,
		 * it should be able to call them from any tracked
		 * thread in an emergency, even if not 'the stack'.
		 *
		 * Note we don't know the state of this thread at the
		 * time of the segv (held mutexes etc..).  Because of
		 * this any attempt at trying to acquire / switch to
		 * the stack context probably has about as much chance
		 * of success as simply calling the shutdownhooks
		 * here.
		 */
		doshutdownhooks();
	}
	else {
		/*
		 * Perform a best-effort cleanup - ask the stack thread
		 * to call doshutdownhooks() and if possible wait for up
		 * to 15 seconds for it to complete. 
		 */
		cleanup(&stk_ctl, 0);
	}
	raise(SIGABRT);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/main.c $ $Rev: 902838 $")
#endif
