/* $NetBSD: kauth.h,v 1.24.2.4 2007/01/21 19:12:10 bouyer Exp $ */

/*-
 * Copyright (c) 2005, 2006 Elad Efrat <elad@NetBSD.org>  
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
 * This is based on Apple TN2127, available online at
 * http://developer.apple.com/technotes/tn2005/tn2127.html
 */

#ifndef _SYS_KAUTH_H_
#define	_SYS_KAUTH_H_

struct uucred;
struct ucred;
struct pcred;
struct proc;
struct tty;
struct vnode;

/* Types. */
typedef struct kauth_scope     *kauth_scope_t;
typedef struct kauth_listener  *kauth_listener_t;
typedef uint32_t		kauth_action_t;
typedef int (*kauth_scope_callback_t)(kauth_cred_t, kauth_action_t,
				      void *, void *, void *, void *, void *);

/*
 * Possible return values for a listener.
 */
#define	KAUTH_RESULT_ALLOW	0	/* allow access */
#define	KAUTH_RESULT_DENY	1	/* deny access */
#define	KAUTH_RESULT_DEFER	2	/* let others decide */

/*
 * Scopes.
 */
#define	KAUTH_SCOPE_GENERIC	"org.netbsd.kauth.generic"
#define	KAUTH_SCOPE_SYSTEM	"org.netbsd.kauth.system"
#define	KAUTH_SCOPE_PROCESS	"org.netbsd.kauth.process"
#define	KAUTH_SCOPE_NETWORK	"org.netbsd.kauth.network"
#define	KAUTH_SCOPE_MACHDEP	"org.netbsd.kauth.machdep"
#define	KAUTH_SCOPE_DEVICE	"org.netbsd.kauth.device"

/*
 * Generic scope - actions.
 */
enum {
	KAUTH_GENERIC_CANSEE=1,
	KAUTH_GENERIC_ISSUSER
};

/*
 * System scope - actions.
 */
enum {
	KAUTH_SYSTEM_ACCOUNTING=1,
	KAUTH_SYSTEM_CHROOT,
	KAUTH_SYSTEM_DEBUG,
	KAUTH_SYSTEM_FILEHANDLE,
	KAUTH_SYSTEM_LKM,
	KAUTH_SYSTEM_MKNOD,
	KAUTH_SYSTEM_REBOOT,
	KAUTH_SYSTEM_SETIDCORE,
	KAUTH_SYSTEM_SWAPCTL,
	KAUTH_SYSTEM_SYSCTL,
	KAUTH_SYSTEM_TIME
};

/*
 * System scope - sub-actions.
 */
enum kauth_system_req {
	KAUTH_REQ_SYSTEM_CHROOT_CHROOT=1,
	KAUTH_REQ_SYSTEM_CHROOT_FCHROOT,
	KAUTH_REQ_SYSTEM_DEBUG_IPKDB,
	KAUTH_REQ_SYSTEM_SYSCTL_ADD,
	KAUTH_REQ_SYSTEM_SYSCTL_DELETE,
	KAUTH_REQ_SYSTEM_SYSCTL_DESC,
	KAUTH_REQ_SYSTEM_SYSCTL_PRVT,
	KAUTH_REQ_SYSTEM_TIME_ADJTIME,
	KAUTH_REQ_SYSTEM_TIME_BACKWARDS,
	KAUTH_REQ_SYSTEM_TIME_NTPADJTIME,
	KAUTH_REQ_SYSTEM_TIME_RTCOFFSET,
	KAUTH_REQ_SYSTEM_TIME_SYSTEM
};	

/*
 * Process scope - actions.
 */
enum {
	KAUTH_PROCESS_CANKTRACE=1,
	KAUTH_PROCESS_CANPROCFS,
	KAUTH_PROCESS_CANPTRACE,
	KAUTH_PROCESS_CANSEE,
	KAUTH_PROCESS_CANSIGNAL,
	KAUTH_PROCESS_CANSYSTRACE,
	KAUTH_PROCESS_CORENAME,
	KAUTH_PROCESS_NICE,
	KAUTH_PROCESS_RLIMIT,
	KAUTH_PROCESS_SETID
};

/*
 * Process scope - sub-actions.
 */
enum kauth_process_req {
	KAUTH_REQ_PROCESS_CANPROCFS_CTL=1,
	KAUTH_REQ_PROCESS_CANPROCFS_READ,
	KAUTH_REQ_PROCESS_CANPROCFS_RW,
	KAUTH_REQ_PROCESS_CANPROCFS_WRITE
};

/*
 * Network scope - actions.
 */
enum {
	KAUTH_NETWORK_ALTQ=1,
	KAUTH_NETWORK_BIND,
	KAUTH_NETWORK_FIREWALL,
	KAUTH_NETWORK_INTERFACE,
	KAUTH_NETWORK_FORWSRCRT,
	KAUTH_NETWORK_ROUTE,
	KAUTH_NETWORK_SOCKET
};

/*
 * Network scope - sub-actions.
 */
enum kauth_network_req {
	KAUTH_REQ_NETWORK_ALTQ_AFMAP=1,
	KAUTH_REQ_NETWORK_ALTQ_BLUE,
	KAUTH_REQ_NETWORK_ALTQ_CBQ,
	KAUTH_REQ_NETWORK_ALTQ_CDNR,
	KAUTH_REQ_NETWORK_ALTQ_CONF,
	KAUTH_REQ_NETWORK_ALTQ_FIFOQ,
	KAUTH_REQ_NETWORK_ALTQ_HFSC,
	KAUTH_REQ_NETWORK_ALTQ_JOBS,
	KAUTH_REQ_NETWORK_ALTQ_PRIQ,
	KAUTH_REQ_NETWORK_ALTQ_RED,
	KAUTH_REQ_NETWORK_ALTQ_RIO,
	KAUTH_REQ_NETWORK_ALTQ_WFQ,
	KAUTH_REQ_NETWORK_BIND_PORT,
	KAUTH_REQ_NETWORK_BIND_PRIVPORT,
	KAUTH_REQ_NETWORK_FIREWALL_FW,
	KAUTH_REQ_NETWORK_FIREWALL_NAT,
	KAUTH_REQ_NETWORK_INTERFACE_GET,
	KAUTH_REQ_NETWORK_INTERFACE_GETPRIV,
	KAUTH_REQ_NETWORK_INTERFACE_SET,
	KAUTH_REQ_NETWORK_INTERFACE_SETPRIV,
	KAUTH_REQ_NETWORK_SOCKET_OPEN,
	KAUTH_REQ_NETWORK_SOCKET_RAWSOCK,
	KAUTH_REQ_NETWORK_SOCKET_CANSEE
};

/*
 * Machdep scope - actions.
 */
enum {
	KAUTH_MACHDEP_IOPERM_GET=1,
	KAUTH_MACHDEP_IOPERM_SET,
	KAUTH_MACHDEP_IOPL,
	KAUTH_MACHDEP_LDT_GET,
	KAUTH_MACHDEP_LDT_SET,
	KAUTH_MACHDEP_MTRR_GET,
	KAUTH_MACHDEP_MTRR_SET,
	KAUTH_MACHDEP_UNMANAGEDMEM
};

/*
 * Device scope - actions.
 */
enum {
	KAUTH_DEVICE_TTY_OPEN=1,
	KAUTH_DEVICE_TTY_PRIVSET,
	KAUTH_DEVICE_RAWIO_SPEC,
	KAUTH_DEVICE_RAWIO_PASSTHRU
};

/*
 * Device scope - sub-actions.
 */
enum kauth_device_req {
	KAUTH_REQ_DEVICE_RAWIO_SPEC_READ=1,
	KAUTH_REQ_DEVICE_RAWIO_SPEC_WRITE,
	KAUTH_REQ_DEVICE_RAWIO_SPEC_RW,
};

/*
 * Device scope, passthru request - identifiers.
 */
#define	KAUTH_REQ_DEVICE_RAWIO_PASSTHRU_READ		0x00000001
#define	KAUTH_REQ_DEVICE_RAWIO_PASSTHRU_WRITE		0x00000002
#define	KAUTH_REQ_DEVICE_RAWIO_PASSTHRU_READCONF	0x00000004
#define	KAUTH_REQ_DEVICE_RAWIO_PASSTHRU_WRITECONF	0x00000008
#define	KAUTH_REQ_DEVICE_RAWIO_PASSTHRU_ALL		0x0000000F

#define NOCRED ((kauth_cred_t)-1)	/* no credential available */
#define FSCRED ((kauth_cred_t)-2)	/* filesystem credential */

/* Macro to help passing arguments to authorization wrappers. */
#define	KAUTH_ARG(arg)	((void *)(unsigned long)(arg))

/*
 * Prototypes.
 */
void kauth_init(void);
kauth_scope_t kauth_register_scope(const char *, kauth_scope_callback_t, void *);
void kauth_deregister_scope(kauth_scope_t);
kauth_listener_t kauth_listen_scope(const char *, kauth_scope_callback_t, void *);
void kauth_unlisten_scope(kauth_listener_t);
int kauth_authorize_action(kauth_scope_t, kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *);

/* Authorization wrappers. */
#ifdef __QNXNTO__
int kauth_authorize_generic_by_ids(int, int, int, int, kauth_action_t, void *);
#endif
int kauth_authorize_generic(kauth_cred_t, kauth_action_t, void *);
int kauth_authorize_system(kauth_cred_t, kauth_action_t, enum kauth_system_req,
    void *, void *, void *);
int kauth_authorize_process(kauth_cred_t, kauth_action_t, struct proc *,
    void *, void *, void *);
int kauth_authorize_network(kauth_cred_t, kauth_action_t,
    enum kauth_network_req, void *, void *, void *);
int kauth_authorize_machdep(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *);
int kauth_authorize_device(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *);
int kauth_authorize_device_tty(kauth_cred_t, kauth_action_t, struct tty *);
int kauth_authorize_device_spec(kauth_cred_t, enum kauth_device_req,
    struct vnode *);
int kauth_authorize_device_passthru(kauth_cred_t, dev_t, u_long, void *);

/* Kauth credentials management routines. */
kauth_cred_t kauth_cred_alloc(void);
void kauth_cred_free(kauth_cred_t);
void kauth_cred_clone(kauth_cred_t, kauth_cred_t);
kauth_cred_t kauth_cred_dup(kauth_cred_t);
kauth_cred_t kauth_cred_copy(kauth_cred_t);

uid_t kauth_cred_getuid(kauth_cred_t);
uid_t kauth_cred_geteuid(kauth_cred_t);
uid_t kauth_cred_getsvuid(kauth_cred_t);
gid_t kauth_cred_getgid(kauth_cred_t);
gid_t kauth_cred_getegid(kauth_cred_t);
gid_t kauth_cred_getsvgid(kauth_cred_t);
int kauth_cred_ismember_gid(kauth_cred_t, gid_t, int *);
u_int kauth_cred_ngroups(kauth_cred_t);
gid_t kauth_cred_group(kauth_cred_t, u_int);

void kauth_cred_setuid(kauth_cred_t, uid_t);
void kauth_cred_seteuid(kauth_cred_t, uid_t);
void kauth_cred_setsvuid(kauth_cred_t, uid_t);
void kauth_cred_setgid(kauth_cred_t, gid_t);
void kauth_cred_setegid(kauth_cred_t, gid_t);
void kauth_cred_setsvgid(kauth_cred_t, gid_t);

void kauth_cred_hold(kauth_cred_t);
u_int kauth_cred_getrefcnt(kauth_cred_t);

int kauth_cred_setgroups(kauth_cred_t, gid_t *, size_t, uid_t);
int kauth_cred_getgroups(kauth_cred_t, gid_t *, size_t);

int kauth_cred_uidmatch(kauth_cred_t, kauth_cred_t);
void kauth_uucred_to_cred(kauth_cred_t, const struct uucred *);
void kauth_cred_to_uucred(struct uucred *, const kauth_cred_t);
int kauth_cred_uucmp(kauth_cred_t, const struct uucred *);
void kauth_cred_toucred(kauth_cred_t, struct ucred *);
void kauth_cred_topcred(kauth_cred_t, struct pcred *);

kauth_cred_t kauth_cred_get(void);
#ifdef __QNXNTO__
#ifdef QNX_MFIB
void kauth_set_mfib_state(int state);
int kauth_set_mfib_gid_map(int gid, int fib);
int kauth_getfib4cred(kauth_cred_t cred);
int kauth_chkfib4cred(kauth_cred_t cred, int fib);
#endif
#endif

#endif	/* !_SYS_KAUTH_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/sys/kauth.h $ $Rev: 680336 $")
#endif
