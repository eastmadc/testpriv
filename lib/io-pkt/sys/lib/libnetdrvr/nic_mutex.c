/*
 * $QNXLicenseC:
 * Copyright 2015, QNX Software Systems. All Rights Reserved.
 *
 * You must obtain a written license from and pay applicable
 * license fees to QNX Software Systems before you may reproduce,
 * modify or distribute this software, or any work that includes
 * all or part of this software.   Free development licenses are
 * available for evaluation and non-commercial purposes.  For more
 * information visit http://licensing.qnx.com or email
 * licensing@qnx.com.
 *
 * This file may contain contributions from others.  Please review
 * this entire file for other proprietary rights or license notices,
 * as well as the QNX Development Suite License Guide at
 * http://licensing.qnx.com/license-guide/ for other information.
 * $
 */

#include <netdrvr/nic_mutex.h>
#include <netdrvr/nicsupport.h>
#include <sync.h>

#define _KERNEL
#include <sys/proc.h>
#include <sys/param_bsd.h>
#include <nw_thread.h>
#include <siglock.h>

static inline void
nic_mutex_check_context(const char *function) {
    if(curproc == stk_ctl.proc0) {
        panic("%s() called from proc0!", function);
    }
    if(nw_thread_istracked() == NULL) {
        panic("%s() called from untracked thread!", function);
    }
    if(ISIRUPT) {
        panic("%s() called from interrupt context!", function);
    }
}

#define NIC_MUTEX_CHECK_CONTEXT() nic_mutex_check_context(__FUNCTION__)

void
nic_mutex_lock(nic_mutex_t *mutex) {
    while(nic_mutex_trylock(mutex) != true) {
        /* Wait until the mutex is unlocked */
        (void)ltsleep(mutex, PWAIT, NULL, 0, NULL);
    }
}

bool
nic_mutex_trylock(nic_mutex_t *mutex) {
    bool result = false;

    NIC_MUTEX_CHECK_CONTEXT();

    switch(*mutex) {
        case NIC_MUTEX_UNLOCKED_VALUE:
            /* The mutex is unlocked, lock it */
            *mutex = NIC_MUTEX_LOCKED_VALUE;
            result = true;
            break;
        case NIC_MUTEX_LOCKED_VALUE:
            /* The mutex is already locked */
            result = false;
            break;
        default:
            panic("%s(): nic_mutex_t@%p has unexpected value: %X", __FUNCTION__, mutex, *mutex);
            break;
    }

    return result;
}

void
nic_mutex_unlock(nic_mutex_t *mutex) {
    NIC_MUTEX_CHECK_CONTEXT();

    /* try to unlock by setting mutex to NIC_MUTEX_UNLOCKED_VALUE */
    switch(*mutex) {
        case NIC_MUTEX_UNLOCKED_VALUE:
            panic("%s(): nic_mutex_t@%p is already unlocked", __FUNCTION__, mutex);
            break;
        case NIC_MUTEX_LOCKED_VALUE:
            /* The mutex is locked, unlock it */
            *mutex = NIC_MUTEX_UNLOCKED_VALUE;
            /* Wakeup threads waiting in nic_mutex_lock */
            NW_SIGHOLD;
            wakeup(mutex);
            NW_SIGUNHOLD;
            break;
        default:
            panic("%s(): nic_mutex_t@%p has unexpected value: %X", __FUNCTION__, mutex, *mutex);
            break;
    }
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/nic_mutex.c $ $Rev: 800192 $")
#endif
