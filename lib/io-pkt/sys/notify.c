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




#include <notify.h>
#include <dlfcn.h>
/*
 * If and when it's ever acceptable to not run against an old libc
 * that doesn't have the iofunc_notify_*_strict() routines, this
 * can all be removed and anywhere the following two _strictp pointers
 * are used, call the functions directly.
 */
void (*notify_trigger_strictp)(resmgr_context_t *, iofunc_notify_t *, int, int);
void (*notify_remove_strictp)(resmgr_context_t *, iofunc_notify_t *, int);


#ifndef VARIANT_a
static void
notify_trigger_null(resmgr_context_t *ctp, iofunc_notify_t *nop, int cnt, int index)
{
	return;
}

static void
notify_remove_null(resmgr_context_t *ctp, iofunc_notify_t *nop, int lim)
{
	return;
}
#endif


void
notify_init(void)
{
#ifndef VARIANT_a
	void *hdl;

	if ((hdl = dlopen(NULL, RTLD_WORLD)) == NULL ||
	    (notify_trigger_strictp = dlsym(hdl,
	    "iofunc_notify_trigger_strict")) == NULL ||
	    (notify_remove_strictp = dlsym(hdl,
	    "iofunc_notify_remove_strict")) == NULL) {
		notify_trigger_strictp = notify_trigger_null;
		notify_remove_strictp = notify_remove_null;
	}

	if (hdl != NULL)
		dlclose(hdl); /* Null op when dlopen(NULL) but... */
#else
	/*
	 * The final link of what this is bound into may
	 * not be static but if it is, we can't call dlopen()
	 * above.  If it is dynamic and they run against an
	 * old libc, the _strict symbols may not resolve and
	 * these may have to be flipped to the null variants.
	 */
	notify_trigger_strictp = iofunc_notify_trigger_strict;
	notify_remove_strictp = iofunc_notify_remove_strict;
#endif

	return;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/notify.c $ $Rev: 680336 $")
#endif
