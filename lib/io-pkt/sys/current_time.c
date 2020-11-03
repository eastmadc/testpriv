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





#include <sys/syspage.h>
#include <sys/neutrino.h>
#include <sys/time.h>
#include <sys/time_bsd.h>
#include <sys/param_bsd.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <errno.h>
#include <pthread.h>

static pthread_once_t mtime_once = PTHREAD_ONCE_INIT;
static uint64_t cycles_per_us;
extern uint32_t ts_fail;
static uint64_t offset;
static uint64_t last_umono;
static uint64_t last_cycles;

static struct qtime_entry *qtp;

volatile struct timeval mono_time;  /* <sys/kernel.h> */
volatile struct timeval TIME;       /* <sys/kernel.h> */

void
init_time(void)
{
	qtp = SYSPAGE_ENTRY(qtime);
}

uint64_t
currtime_nto(int tod)
{
	uint64_t	nsec_mono, nsec_tod, adjust;


	for (;;) {
		/*
		 * Loop until we get two time values the same in case an
		 * interrupt comes in while we're reading the value.
		 */
#ifdef QTIME_FLAG_CHECK_STABLE
		if (qtp->flags & QTIME_FLAG_CHECK_STABLE) {
			do {
				nsec_mono = qtp->nsec;
				adjust = qtp->nsec_tod_adjust;
			} while (nsec_mono != qtp->nsec_stable);
		} else
#endif
			/*
			 * after a suitable period of time, we can probably remove
			 * this code and just assume that we're using a procnto
			 * that sets the nsec_stable field 2008/08/18
			 */
			do {
				nsec_mono = qtp->nsec;
				adjust = qtp->nsec_tod_adjust;
			} while (nsec_mono != qtp->nsec ||
			    adjust != qtp->nsec_tod_adjust);

		if (qtp->nsec_inc != 0 && nsec_mono != (-(uint64_t)1))
			break;

		/*
		 * If nsec field is -1, power managment has kicked in.
		 * If nsec_inc field is 0, there is no ticker
		 */
		nsec_mono = 0;
		adjust = 0;
		if (ClockTime_r(CLOCK_MONOTONIC, 0, &nsec_mono) != EOK ||
		    qtp->nsec_inc == -0) {
			break;
		}
	}

	nsec_tod = nsec_mono + adjust;

	/* Approximate these while we're here */
	mono_time.tv_sec  = nsecreal_ti(nsec_mono);
	mono_time.tv_usec = (nsec_mono & 0x3fffffff) >> 10;

	TIME.tv_sec  = nsecreal_ti(nsec_tod);
	TIME.tv_usec = (nsec_tod & 0x3fffffff) >> 10;

	if (tod)
		return (nsec_tod);

	return (nsec_mono);
}

static void
mtime(int get, int up, struct timeval *tv)
{
	static uint64_t		mtlast;
	static struct timeval	mt_tv;
	uint64_t		cur, curtick;

	/*
	 * See comments in <sys/timevar.h>. 'get' variants
	 * are allowed to return a less precise result.
	 */

	cur = currtime_nto(!up);
	curtick = cur & ~((1 << NTO_TSHIFT) -1);

	if (1 /* get */) {
		/*
		 * Try to only do the 64 bit division every tick.
		 * Makes microtime() not so micro...
		 */
		if (mtlast != curtick) {
			mtlast = curtick;
			mt_tv.tv_sec  = mtlast / 1000000000;
			mt_tv.tv_usec = (mtlast % 1000000000) / 1000;
		}
	}
	else {
		mtlast = curtick;
		mt_tv.tv_sec  = cur / 1000000000;
		mt_tv.tv_usec = (cur % 1000000000) / 1000;
	}
	tv->tv_sec  = mt_tv.tv_sec;
	tv->tv_usec = mt_tv.tv_usec;
}


void
microtime(struct timeval *tv)
{
	mtime(0, 0, tv);
}

void
getmicrotime(struct timeval *tv)
{
	mtime(1, 0, tv);
}

void
getmicrouptime(struct timeval *tv)
{
	mtime(1, 1, tv);
}


void
nanotime(struct timespec *ts)
{
	struct timeval tv;

	mtime(0, 0, &tv);
	TIMEVAL_TO_TIMESPEC(&tv, ts);
}

static void
mtime_init (void)
{
	uint64_t ucycles, utick;

	cycles_per_us = SYSPAGE_ENTRY(qtime)->cycles_per_sec / 1000000;
	if (cycles_per_us == 0) {
		log(LOG_ERR, "ClockCycles() too slow for accurate "
		    "timekeeping");
		ts_fail = 1;
	} else {
		last_umono = currtime_nto(0) / 1000;
		utick = currtime_nto(1) / 1000;
		last_cycles = ClockCycles();
		ucycles = last_cycles / cycles_per_us;
		offset = utick - ucycles;
	}

}

void
getnanotime(struct timespec *ts)
{
	struct timeval tv;

	mtime(1, 0, &tv);
	TIMEVAL_TO_TIMESPEC(&tv, ts);
}

/*
 * Attempt to use ClockCycles() for microsecond accurate timestamp.
 * If it fails then fall back to system tick accuracy, which is still
 * better than io-pkt tick.
 */
void
microtime_accurate (struct timeval *tv)
{
    uint64_t cycles;
    uint64_t ucycles;
    uint64_t ucycles_tod;
    uint64_t utick;
    uint64_t umono;
    uint64_t new_cycles_per_us;
    uint64_t cycles_diff;

    pthread_once(&mtime_once, mtime_init);

    utick = currtime_nto(1) / 1000;
    if (ts_fail) {
	tv->tv_sec = utick / 1000000;
	tv->tv_usec = utick - (tv->tv_sec * 1000000);
	return;
    }

    cycles = ClockCycles();
    ucycles = cycles / cycles_per_us;
    ucycles_tod = ucycles + offset;

    /* If off by more than 1 second then recalibrate */
    if (((ucycles_tod > utick) && ((ucycles_tod - utick) > 1000000)) ||
        ((ucycles_tod < utick) && ((utick - ucycles_tod) > 1000000))) {
	/*
	 * TSC calibration on x86 is done by a quick and dirty method in
	 * startup and may not be accurate enough for us. We can use our
	 * updates here to refine the value.
	 */
	umono = currtime_nto(0) / 1000;
	if ((cycles > last_cycles) && (umono > (last_umono + 1000000))) {
	    /* Nothing has rolled over and last update was over 1 sec ago */
	    new_cycles_per_us = (cycles - last_cycles) / (umono - last_umono);
	    last_umono = umono;
	    last_cycles = cycles;

	    if (new_cycles_per_us != cycles_per_us) {
		if (cycles_per_us > new_cycles_per_us) {
		    cycles_diff = cycles_per_us - new_cycles_per_us;
		} else {
		    cycles_diff = new_cycles_per_us - cycles_per_us;
		}

		if ((cycles_per_us / cycles_diff) > 10) {
		    /* Within 10% of old value, update it. */
		    cycles_per_us = new_cycles_per_us;
		    ucycles = cycles / cycles_per_us;
		} else {
		    log(LOG_ERR, "ClockCycles() too unreliable for "
			"accurate timekeeping");
		    ts_fail = 1;
		    tv->tv_sec = utick / 1000000;
		    tv->tv_usec = utick - (tv->tv_sec * 1000000);
		    return;
		}
	    }
	} else if ((cycles < last_cycles) || (last_umono < umono)) {
	    /* Rollover */
	    last_umono = umono;
	    last_cycles = cycles;
	}

	/* Calculate new offset and time */
	offset = utick - ucycles;
	ucycles_tod = ucycles + offset;
    }

    tv->tv_sec = ucycles_tod / 1000000;
    tv->tv_usec = ucycles_tod - (tv->tv_sec * 1000000);
    return;
}

/*
 * See sys/kernel.h for nsec and 2<<30 significance.
 * 
 * 10^9 / 2^30 ~= 477 / 512
 *
 * 512 == 2^9
 */
#define TI_SMALL_SHIFT	9
#define TI_SMALL_MULT	477

/*
 * Our time_t is unsigned so
 * no sign extension on shifting.
 */
time_t
tireal_ti_small(time_t ti)
{
	time_t tmp;

	/*
	 * Watch for overflow.
	 *
	 * If it's greater than this many seconds
	 * it's probably more or less permanent.
	 */
	if (ti > (time_t)-1 >> TI_SMALL_SHIFT)
		return ti;

	tmp = ti * TI_SMALL_MULT;
	ti = tmp >> TI_SMALL_SHIFT;
	/*
	 * Try to make worst case division rounding error
	 * half a second.  Helps conformance tests.
	 */
	if ((tmp & ((1<<TI_SMALL_SHIFT) - 1)) >= 1 << (TI_SMALL_SHIFT - 1))
		ti++;

	return ti;
}

time_t
ti_tireal_small(time_t ti)
{
	/* Watch for overflow */
	if (ti > (time_t)-1 >> TI_SMALL_SHIFT)
		return ti;

	return ((ti << TI_SMALL_SHIFT) / TI_SMALL_MULT);
}
#undef TI_SMALL_SHIFT
#undef TI_SMALL_MULT

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/current_time.c $ $Rev: 839392 $")
#endif
