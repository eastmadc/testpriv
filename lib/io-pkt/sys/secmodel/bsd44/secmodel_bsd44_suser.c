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

/* $NetBSD: secmodel_bsd44_suser.c,v 1.17.2.4 2007/02/09 22:26:07 tron Exp $ */
/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Elad Efrat.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file contains kauth(9) listeners needed to implement the traditional
 * NetBSD superuser access restrictions.
 *
 * There are two main resources a request can be issued to: user-owned and
 * system owned. For the first, traditional Unix access checks are done, as
 * well as superuser checks. If needed, the request context is examined before
 * a decision is made. For the latter, usually only superuser checks are done
 * as normal users are not allowed to access system resources.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: secmodel_bsd44_suser.c,v 1.17.2.4 2007/02/09 22:26:07 tron Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kauth.h>

#include <sys/acct.h>
#ifndef __QNXNTO__
#include <sys/ktrace.h>
#endif
#include <sys/mount.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/tty.h>
#include <net/route.h>

#ifndef __QNXNTO__
#include <miscfs/procfs/procfs.h>
#endif

#include <secmodel/bsd44/suser.h>

#ifdef __QNXNTO__
#include <secmodel/secmodel.h>

extern unsigned int admin_group;
int allow_root_group = 0;

void
secmodel_bsd44_suser_init(int option)
{
    switch (option) {
    case TCPIP_SUSER_RGROUP_ALLOW:
	allow_root_group = 1;
	break;

    case SECMODEL_INIT_OPTZ:
    default:
	/*shouldn't get here*/
	break;
    }
}

static boolean_t is_root_group_allowed(kauth_cred_t cred) {
	return (allow_root_group && (kauth_cred_getegid(cred) == admin_group));
}


#endif


void
secmodel_bsd44_suser_start(void)
{
	kauth_listen_scope(KAUTH_SCOPE_GENERIC,
	    secmodel_bsd44_suser_generic_cb, NULL);
	kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
	    secmodel_bsd44_suser_system_cb, NULL);
#ifndef __QNXNTO__
	kauth_listen_scope(KAUTH_SCOPE_PROCESS,
	    secmodel_bsd44_suser_process_cb, NULL);
#endif
	kauth_listen_scope(KAUTH_SCOPE_NETWORK,
	    secmodel_bsd44_suser_network_cb, NULL);
#ifndef __QNXNTO__
	kauth_listen_scope(KAUTH_SCOPE_MACHDEP,
	    secmodel_bsd44_suser_machdep_cb, NULL);
	kauth_listen_scope(KAUTH_SCOPE_DEVICE,
	    secmodel_bsd44_suser_device_cb, NULL);
#endif
}

/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: Generic
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_generic_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	boolean_t isroot;
	int result;

	isroot = (kauth_cred_geteuid(cred) == 0);
#ifdef __QNXNTO__
	/* permit networking services to run as non-root, check for effective group = 0 */
	isroot |= is_root_group_allowed(cred);
#endif
	result = KAUTH_RESULT_DENY;

	switch (action) {
	case KAUTH_GENERIC_ISSUSER:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_GENERIC_CANSEE:     
#ifndef __QNXNTO__
		if (!secmodel_bsd44_curtain)
			result = KAUTH_RESULT_ALLOW;
		else if (isroot || kauth_cred_uidmatch(cred, arg0))
#else
		/*
		 * CANSEE and kauth_cred_uidmatch() would
		 * need work as we always get credinfo on
		 * curproc.  And don't really save it with
		 * the fp (two scoids can map to the same fp
		 * (ocb)).  Plus we don't currently enable
		 * the sysctl to enable
		 * secmodel_bsd44_curtain.
		 */
#endif
			result = KAUTH_RESULT_ALLOW;

		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}

/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: System
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_system_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	boolean_t isroot;
	int result;
	enum kauth_system_req req;

	isroot = (kauth_cred_geteuid(cred) == 0);
#ifdef __QNXNTO__
	/* permit networking services to run as non-root, check for effective group = 0 */
	isroot |= is_root_group_allowed(cred);
#endif
	result = KAUTH_RESULT_DENY;
	req = (enum kauth_system_req)arg0;

	switch (action) {
	case KAUTH_SYSTEM_TIME:
		switch (req) {
		case KAUTH_REQ_SYSTEM_TIME_ADJTIME:
		case KAUTH_REQ_SYSTEM_TIME_NTPADJTIME:
		case KAUTH_REQ_SYSTEM_TIME_SYSTEM:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;

		default:
			result = KAUTH_RESULT_DEFER;
			break;
		}
		break;

	case KAUTH_SYSTEM_SYSCTL:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_SYSTEM_SWAPCTL:
	case KAUTH_SYSTEM_ACCOUNTING:
	case KAUTH_SYSTEM_REBOOT:
	case KAUTH_SYSTEM_CHROOT:
	case KAUTH_SYSTEM_FILEHANDLE:
	case KAUTH_SYSTEM_MKNOD:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}

#ifndef __QNXNTO__
/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: Process
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_process_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	struct proc *p;
	boolean_t isroot;
	int result;

	isroot = (kauth_cred_geteuid(cred) == 0);
	result = KAUTH_RESULT_DENY;
	p = arg0;

	switch (action) {
	case KAUTH_PROCESS_CANSIGNAL: {
		int signum;

		signum = (int)(unsigned long)arg1;

		if (isroot || kauth_cred_uidmatch(cred, p->p_cred) ||
		    (signum == SIGCONT && (curproc->p_session == p->p_session)))
			result = KAUTH_RESULT_ALLOW;
		break;
		}

	case KAUTH_PROCESS_CANSEE:
		if (!secmodel_bsd44_curtain)
			result = KAUTH_RESULT_ALLOW;
		else if (isroot || kauth_cred_uidmatch(cred, p->p_cred))
			result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_PROCESS_CANKTRACE:
		if (isroot) {
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		if ((p->p_traceflag & KTRFAC_ROOT) || (p->p_flag & P_SUGID)) {
			result = KAUTH_RESULT_DENY;
			break;
		}

		if (kauth_cred_geteuid(cred) == kauth_cred_getuid(p->p_cred) &&
		    kauth_cred_getuid(cred) == kauth_cred_getsvuid(p->p_cred) &&
		    kauth_cred_getgid(cred) == kauth_cred_getgid(p->p_cred) &&
		    kauth_cred_getgid(cred) == kauth_cred_getsvgid(p->p_cred)) {
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		result = KAUTH_RESULT_DENY;
		break;

	case KAUTH_PROCESS_CANPROCFS: {
		enum kauth_process_req req = (enum kauth_process_req)arg2;
		struct pfsnode *pfs = arg1;

		if (isroot) {
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		if (req == KAUTH_REQ_PROCESS_CANPROCFS_CTL) {
			result = KAUTH_RESULT_DENY;
			break;
		}

		switch (pfs->pfs_type) {
		case PFSregs:
		case PFSfpregs:
		case PFSmem:
			if (kauth_cred_getuid(cred) !=
			    kauth_cred_getuid(p->p_cred) ||
			    ISSET(p->p_flag, P_SUGID)) {
				result = KAUTH_RESULT_DENY;
				break;
			}
			/*FALLTHROUGH*/
		default:
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		break;
		}

	case KAUTH_PROCESS_CANPTRACE:
	case KAUTH_PROCESS_CANSYSTRACE:
		if (isroot) {
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		if (kauth_cred_getuid(cred) != kauth_cred_getuid(p->p_cred) ||
		    ISSET(p->p_flag, P_SUGID)) {
			result = KAUTH_RESULT_DENY;
			break;
		}

		result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_PROCESS_NICE:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		else if ((u_long)arg1 >= p->p_nice)
			result = KAUTH_RESULT_ALLOW; 
		break;

	case KAUTH_PROCESS_RLIMIT:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		else {
			struct rlimit *new_rlimit;
			u_long which;

			new_rlimit = arg1;
			which = (u_long)arg2;

			if (new_rlimit->rlim_max <=
			    p->p_rlimit[which].rlim_max)
				result = KAUTH_RESULT_ALLOW;
		}
		break;

	case KAUTH_PROCESS_SETID:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}
#endif

/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: Network
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_network_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2,
    void *arg3)
{
	boolean_t isroot;
	int result;
	enum kauth_network_req req;

	isroot = (kauth_cred_geteuid(cred) == 0);

#ifdef __QNXNTO__
	/* permit networking services to run as non-root, check for effective group = 0 */
	isroot |= is_root_group_allowed(cred);
#endif

	result = KAUTH_RESULT_DENY;
	req = (enum kauth_network_req)arg0;

	switch (action) {
	case KAUTH_NETWORK_ALTQ:
		switch (req) {
		case KAUTH_REQ_NETWORK_ALTQ_AFMAP:
		case KAUTH_REQ_NETWORK_ALTQ_BLUE:
		case KAUTH_REQ_NETWORK_ALTQ_CBQ:
		case KAUTH_REQ_NETWORK_ALTQ_CDNR:
		case KAUTH_REQ_NETWORK_ALTQ_CONF:
		case KAUTH_REQ_NETWORK_ALTQ_FIFOQ:
		case KAUTH_REQ_NETWORK_ALTQ_HFSC:
		case KAUTH_REQ_NETWORK_ALTQ_JOBS:
		case KAUTH_REQ_NETWORK_ALTQ_PRIQ:
		case KAUTH_REQ_NETWORK_ALTQ_RED:
		case KAUTH_REQ_NETWORK_ALTQ_RIO:
		case KAUTH_REQ_NETWORK_ALTQ_WFQ:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;

		default:
			result = KAUTH_RESULT_DEFER;
			break;
		}

		break;

	case KAUTH_NETWORK_BIND:
		switch (req) {
		case KAUTH_REQ_NETWORK_BIND_PRIVPORT:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;
		default:
			result = KAUTH_RESULT_ALLOW;
			break;
		}
		break;

	case KAUTH_NETWORK_INTERFACE:
		switch (req) {
		case KAUTH_REQ_NETWORK_INTERFACE_GET:
		case KAUTH_REQ_NETWORK_INTERFACE_SET:
			result = KAUTH_RESULT_ALLOW;
			break;

		case KAUTH_REQ_NETWORK_INTERFACE_GETPRIV:
		case KAUTH_REQ_NETWORK_INTERFACE_SETPRIV:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;

		default:
			result = KAUTH_RESULT_DEFER;
			break;
		}
		break;

	case KAUTH_NETWORK_ROUTE:
		switch (((struct rt_msghdr *)arg1)->rtm_type) {
		case RTM_GET:
			result = KAUTH_RESULT_ALLOW;
			break;

		default:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;
		}
		break;

	case KAUTH_NETWORK_SOCKET:
		switch (req) {
		case KAUTH_REQ_NETWORK_SOCKET_OPEN:
			if ((u_long)arg1 == PF_ROUTE || (u_long)arg1 == PF_BLUETOOTH)
				result = KAUTH_RESULT_ALLOW;
			else if ((u_long)arg2 == SOCK_RAW) {
				if (isroot)
					result = KAUTH_RESULT_ALLOW;
			} else
				result = KAUTH_RESULT_ALLOW;
			break;

		case KAUTH_REQ_NETWORK_SOCKET_RAWSOCK:
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
			break;

		case KAUTH_REQ_NETWORK_SOCKET_CANSEE:
#ifndef __QNXNTO__
			if (secmodel_bsd44_curtain) {
				uid_t so_uid;

				so_uid =
				    ((struct socket *)arg1)->so_uidinfo->ui_uid;
				if (isroot ||
				    kauth_cred_geteuid(cred) == so_uid)
					result = KAUTH_RESULT_ALLOW;
			} else
#else
			/* See comment in secmodel_bsd44_suser_generic_cb() */
#endif
				result = KAUTH_RESULT_ALLOW;
			break;

		default:
			result = KAUTH_RESULT_ALLOW;
			break;
		}

		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}

#ifndef __QNXNTO__
/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: Machdep
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_machdep_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2,
    void *arg3)
{
        boolean_t isroot;
        int result;

        isroot = (kauth_cred_geteuid(cred) == 0);
        result = KAUTH_RESULT_DENY;

        switch (action) {
	case KAUTH_MACHDEP_IOPERM_GET:
	case KAUTH_MACHDEP_LDT_GET:
	case KAUTH_MACHDEP_LDT_SET:
	case KAUTH_MACHDEP_MTRR_GET:
		result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_MACHDEP_IOPERM_SET:
	case KAUTH_MACHDEP_IOPL:
	case KAUTH_MACHDEP_MTRR_SET:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	case KAUTH_MACHDEP_UNMANAGEDMEM:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;
		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}

/*
 * kauth(9) listener
 *
 * Security model: Traditional NetBSD
 * Scope: Device
 * Responsibility: Superuser access
 */
int
secmodel_bsd44_suser_device_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2,
    void *arg3)
{
	struct tty *tty;
        boolean_t isroot;
        int result;

        isroot = (kauth_cred_geteuid(cred) == 0);
        result = KAUTH_RESULT_DENY;

	switch (action) {
	case KAUTH_DEVICE_TTY_OPEN:
		tty = arg0;

		if (!(tty->t_state & TS_ISOPEN))
			result = KAUTH_RESULT_ALLOW;
		else if (tty->t_state & TS_XCLUDE) {
			if (isroot)
				result = KAUTH_RESULT_ALLOW;
		} else
			result = KAUTH_RESULT_ALLOW;

		break;

	case KAUTH_DEVICE_TTY_PRIVSET:
		if (isroot)
			result = KAUTH_RESULT_ALLOW;

		break;

	default:
		result = KAUTH_RESULT_DEFER;
		break;
	}

	return (result);
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/secmodel/bsd44/secmodel_bsd44_suser.c $ $Rev: 834253 $")
#endif
