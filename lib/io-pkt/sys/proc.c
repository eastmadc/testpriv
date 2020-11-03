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





#include "qnx.h"
#include "nw_datastruct.h"
#include "nw_defs.h"
#include "nw_resmgr.h"
#include "nw_msg.h"
#include "nw_tls.h"
#include "delta.h"
#include <sys/param_bsd.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <sys/file_bsd.h>
#include <sys/mman.h>
#include <sys/systm.h>
#include <sys/sched.h>
#include <sys/ucred.h>
#include <sys/resourcevar.h>
#include <sys/mbuf.h>
#include <sys/kthread.h>

MALLOC_DECLARE(M_PROCALLOC);
MALLOC_DEFINE(M_PROCALLOC, "pralloc", "Proc alloc");

MALLOC_DEFINE(M_PROC, "proc", "Proc structures");

struct lwp *curlwp;

#ifdef MSG_EVENT_COUNTERS
#include <sys/device.h>

struct evcnt msg_ev = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
	NULL, "msg ev", "msg");
struct evcnt msg_ev_local = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
	NULL, "msg ev", "msg local");
#ifdef OCB_LOCAL_CACHE
struct evcnt msg_ev_local_ocb = EVCNT_INITIALIZER(EVCNT_TYPE_MISC,
	NULL, "msg ev", "msg local ocb");
#endif
#define MSG_EVENT_INCR(ev) (ev)->ev_count++
#else
#define MSG_EVENT_INCR(ev) ((void)0)
#endif


#ifdef OCB_LOCAL_CACHE

#include <sys/syspage.h>

struct ocb_cache *ocb_cache;

int ocb_cache_scoid_max;
#endif

struct lwp *proc_pull(struct prio *pmain);


#define ctx_save(p) _setjmp((p)->p_regs)
#ifdef __PPC__
#ifndef __QNXNTO__
static __inline__ void ctx_load(struct proc *p) __attribute__((__noreturn__));
#endif
static __inline__ void ctx_load(struct proc *p)
{
	/*
	 * This is similar to longjmp() but we
	 * multiplex the use of r3 as both return
	 * value and function arg.  We also branch
	 * off ctr instead of lr and make sure lr
	 * is zeroed out to keep the back traces
	 * pretty (make startproc() really look like
	 * the start of the trace).
	 */
	void *tmp;
	__asm__ __volatile__ (
		" li %0, 0;"
		" mtlr %0;"
		" lwz %0, 0(%1);"
		" lmw %%r14, 8(%1);"
		" mtctr %0;"
		" lwz %%r1, 4(%1);"
		" lwz %0, 80(%1);"
		" mtcrf 0x38, %0;"
		/*
		 * If jumping back to ctx_save() in resched(), r3 is the
		 * return value and anything non 0 will suffice.  If jumping
		 * to startproc(), r3 is the function argument.
		 */
		" mr %%r3, %2;"
		" bctr;"
			:"=r&"(tmp): "b"(p->p_regs), "r"(p->p_jmp_arg));

	/* Not reached */

	/* placate gcc */
	for (;;)
		continue;
}
#else
#define ctx_load(p) _longjmp((p)->p_regs, 1)
#endif


int
msg_init(void)
{
#ifdef MSG_EVENT_COUNTERS
	evcnt_attach_static(&msg_ev);
	evcnt_attach_static(&msg_ev_local);
#ifdef OCB_LOCAL_CACHE
	evcnt_attach_static(&msg_ev_local_ocb);
#endif
#endif

#ifdef OCB_LOCAL_CACHE
	if ((ocb_cache = mmap(0, SYSPAGE_ENTRY(system_private)->pagesize, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, NOFD, 0)) != MAP_FAILED) {
		ocb_cache_scoid_max = SYSPAGE_ENTRY(system_private)->pagesize / sizeof(struct ocb_cache);
	}
	
#endif
	return 0;
}

int
proc0_getprivs(struct lwp *l)
{
	struct proc	*p;

	p = LWP_TO_PR(l);
	if (p != stk_ctl.proc0 || l->l_cred != NULL || p->p_cred != NULL)
		return EINVAL;

	l->l_cred = p->p_cred = NOCRED;
	return 0;
}

int
proc0_remprivs(struct lwp *l)
{
	struct proc	*p;

	p = LWP_TO_PR(l);
	if (p != stk_ctl.proc0)
		return EINVAL;

	l->l_cred = p->p_cred = NULL;
	return 0;
}

int
add_procs(struct nw_stk_ctl *sctlp, int nprocs, int nstacks)
{
	struct proc_alloc *curprocs;
	int index, i, stacks_size;
	char *stacks;

#define PROC_ALLOC_INCR 4
	if (sctlp->proc_alloc_used == sctlp->proc_alloc_tot) {
		if ((curprocs = malloc((sctlp->proc_alloc_tot + PROC_ALLOC_INCR) * sizeof(*curprocs),
		    M_PROCALLOC, M_NOWAIT)) == NULL) {
			return ENOMEM;
		}

		memcpy(curprocs, sctlp->allprocs, sctlp->proc_alloc_used * sizeof(*sctlp->allprocs));
		memset(&curprocs[sctlp->proc_alloc_used], 0x00, PROC_ALLOC_INCR * sizeof(*curprocs));

		free(sctlp->allprocs, M_PROCALLOC);

		sctlp->allprocs = curprocs;
		sctlp->proc_alloc_tot += PROC_ALLOC_INCR;
	}
	else {
		curprocs = sctlp->allprocs;
	}
#undef PROC_ALLOC_INCR

	index = sctlp->proc_alloc_used;
	curprocs[index].stacks = NULL;

	if ((curprocs[index].procs = malloc(nprocs * sizeof(struct proc), M_PROC, M_NOWAIT)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	memset(curprocs[index].procs, 0x00, nprocs * sizeof(struct proc));

	if (sctlp->stackguard) {
	    pagesize = sysconf(_SC_PAGESIZE);
	    stacks_size = (nstacks * sctlp->stacksize) +
	      ((nstacks + 1) * pagesize);
	} else {
	    stacks_size = nstacks * sctlp->stacksize;
	}
	stacks = mmap(0, stacks_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_STACK, NOFD, 0);
	if (stacks == MAP_FAILED) {
		free(curprocs[index].procs, M_PROC);
		curprocs[index].procs  = NULL;
		errno = ENOMEM;
		return -1;
	}

	if (sctlp->stackguard) {
	    mprotect(stacks, pagesize, PROT_NONE);
	    stacks += pagesize;
	}
	curprocs[index].stacks = stacks;

	sctlp->nprocs_cur_max += nprocs - nstacks;

	for (i = nprocs - nstacks; i < nprocs; i++) {
		*((int *)stacks) = PROC_STACK_TEST_PAT;

		curprocs[index].procs[i].p_stats    = &sctlp->pstats;
		curprocs[index].procs[i].p_stkbase  = stacks;
		curprocs[index].procs[i].p_limit    = &sctlp->plimit;
		curprocs[index].procs[i].p_ctxt.dpp = sctlp->dpp;
		curprocs[index].procs[i].p_thread   = sctlp->nprocs_cur_max + i;
		curprocs[index].procs[i].p_vmspace.vm_proc =
		    &curprocs[index].procs[i];

		curprocs[index].procs[i].p_lwp.l_forw = PR_TO_LWP(sctlp->freeprocs);
		sctlp->freeprocs = &curprocs[index].procs[i];
		stacks += sctlp->stacksize;
		if (sctlp->stackguard) {
		    mprotect(stacks, pagesize, PROT_NONE);
		    stacks += pagesize;
		}
	}

	sctlp->nprocs_cur_max += nstacks;

	sctlp->proc_alloc_used++;

	return 0;
}

/* CHECKME_NTO can we move this into init_main.c and make it static? */
int
init_procs(struct nw_stk_ctl *sctlp, int nfd)
{
	struct plimit *plm = &sctlp->plimit;
	int error;
#if 0
	/*
	* This prevents array from ever being expanded;
	* however, reallocation in fdalloc() should be OK.
	*/
	plm.pl_rlimit[RLIMIT_NOFILE].rlim_cur = nfd;
	plm.pl_rlimit[RLIMIT_NOFILE].rlim_max = nfd;
#else
	/*
	 * Let the kernel enforce the limits.
	 */
	nfd = max(nfd >> 1, 250);
	plm->pl_rlimit[RLIMIT_NOFILE].rlim_cur = INT_MAX;
	plm->pl_rlimit[RLIMIT_NOFILE].rlim_max = INT_MAX;
#endif

	plm->pl_rlimit[RLIMIT_NPROC].rlim_cur = INT_MAX;
	plm->pl_rlimit[RLIMIT_NPROC].rlim_max = INT_MAX;

	plm->p_lflags = 0;
	plm->p_refcnt = 1;

	/*
	 * nstacks = (proc_min - 1) because first proc is us.  We are always READY
	 * and have a real stack (we're using it right now).
	 */
	error = add_procs(sctlp, sctlp->nprocs_min, sctlp->nprocs_min - 1);
	if (error)
		return error;


	curlwp                 = PR_TO_LWP(&sctlp->allprocs[0].procs[0]); /* First one (not on sctlp->freeprocs list) */
	curlwp->l_rval         = EOK;
	curlwp->l_prio.prio    = 0;
	curlwp->l_stat         = LREADY;
	curproc->p_stats       = &sctlp->pstats;
	curproc->p_stkbase     = NULL;
	curproc->p_limit       = &sctlp->plimit;
	curproc->p_ctxt.dpp    = sctlp->dpp;
	curproc->p_thread      = 0;               /* curproc - sctlp->allprocs */

	sctlp->nprocs_used = 1;
    
	return 0;
}

int
resched(struct proc *p)
{
	struct lwp	*l;

	l = PR_TO_LWP(p);

	l->l_rval = EOK;

	if (ctx_save(p))
		return l->l_rval;

	sched();
	return 0; /* not reached */
}


void
resched_force(struct proc *p, int new_prio)
{
	struct nw_stk_ctl	*sctlp;
	int			old_prio;
	struct lwp		*l;

	sctlp = &stk_ctl;
	l = PR_TO_LWP(p);

	if (sctlp->proc_prio.prio_all.tail != NULL) {
		old_prio = l->l_prio.prio; /* Save */
		l->l_prio.prio = new_prio;
		l->l_stat = LREADY;
		proc_put(l);
		resched(p);
		l->l_prio.prio = old_prio; /* Restore */
	}

	return;
}


struct lwp *
proc_pull(struct prio *prio)
{
	struct prio_ent	*p;
	struct lwp	*l;

	if ((p = prio->prio_all.tail) == NULL)
		return NULL;

	*prio->prio_all.tail->prv = NULL;

	if (prio->prio_all.head == NULL) {
		prio->prio_all.tail = NULL;
		prio->prio_prios[p->prio].head = NULL;
		prio->prio_prios[p->prio].tail = NULL;
	}
	else {
		prio->prio_all.tail = (struct prio_ent *)
		    ((char *)prio->prio_all.tail->prv - offsetof(struct prio_ent, nxt));
		if (prio->prio_all.tail->prio != p->prio) {
			prio->prio_prios[p->prio].head = NULL;
			prio->prio_prios[p->prio].tail = NULL;
		}
		else {
			prio->prio_prios[p->prio].tail = prio->prio_all.tail;
		}
	}
	p->nxt = NULL;
	p->prv = NULL;

	l = (struct lwp *)((char *)p - offsetof(struct lwp, l_prio));

	return l;
}

#if defined (__ARM__)
#ifndef __QNXNTO__
extern void _sched_arm_asm(_CSTD jmp_buf __env, void * __val) __attribute__ ((__noreturn__));
#else
extern void _sched_arm_asm(_CSTD jmp_buf __env, void * __val);
#endif
#endif

void
sched(void)
{
	struct lwp		*l;
	struct proc		*p;
	struct nw_stk_ctl	*sctlp;

	sctlp = &stk_ctl;

	if (sctlp->pkt_rx_q) {
		/*
		 * Back to main thread.  Force it
		 * back to top of loop.
		 */
		p = sctlp->proc0;
		l = PR_TO_LWP(p);
		l->l_rval = NW_DEF_SOFTCLOCK_PKT_LIM;
	}
	else if ((l = proc_pull(&sctlp->proc_prio)) != NULL) {
		p = LWP_TO_PR(l);
	}
	else {
		/* Back to main thread */
		p = sctlp->proc0;
		l = PR_TO_LWP(p);
	}

	curlwp = l;  /* reset */

	/*
	 * The following will restore __tls()->__stackaddr
	 * if p == proc0
	 */
	LIBC_TLS()->NW_TLS_STACKADDR = p->p_stkbase;

#if defined(__SH__)
	if (l->l_stat == LREADY_START) {
		l->l_stat = LRUNNING;

		__asm__ __volatile__ (
			"mov.l @(0,%0),r0;"
			"mov.l @(4,%0),r15;"
			"lds	r0,pr;"
			"rts;"
			/* pcreat() stored function arg here (jmp_arg) */
			"mov.l @(8,%0),r4;"
			:
			: "r"((p)->p_regs)
		);
	}
#elif defined(__MIPS__)
	if (l->l_stat == LREADY_START) {
		void *tmp1 = p->p_jmp_arg;

		l->l_stat = LRUNNING;
		p->p_jmp_arg = 0;

		__asm__ __volatile__ (
		".set noreorder		;"	
		"move $4,%1		;"
		"move $5,%0		;"
		"lw $6,0($5)		;" //jump target
		"li $31,0		;" //RA (no return)
		"lw $29,4($5)		;" //SP
		"lw $16,8($5)		;" //S0
		"lw $17,12($5)		;" //S1
		"lw $18,16($5)		;" //S2
		"lw $19,20($5)		;" //S3
		"lw $20,24($5)		;" //S4
		"lw $21,28($5)		;" //S5
		"lw $22,32($5)		;" //S6
		"lw $23,36($5)		;" //S7
		"jr $6			;"
		" lw $30,40($5)		;" //S8
		"  nop			;"
		".set reorder		;"	
		: : "r"(p->p_regs), "r"(tmp1)
	);
	}
#elif defined(__ARM__)
	if (l->l_stat == LREADY_START) {
		void    *tmp  = p->p_jmp_arg;

		p->p_jmp_arg = 0;
		l->l_stat = LRUNNING;

		_sched_arm_asm(p->p_regs, tmp);

	}
#elif defined(__X86__) || defined(__PPC__)
	/* Nothing to do */
#else
	#error Not configured for CPU
#endif

	l->l_stat = LRUNNING;
	ctx_load(p);
}

void
pcreat_setbigstack(struct proc *p)
{
	void			*stk;
	struct nw_stk_ctl	*sctlp;

	sctlp = &stk_ctl;

	stk = mmap(0, sctlp->bigstack_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_STACK | MAP_LAZY, NOFD, 0);
	if (stk == MAP_FAILED) {
		panic("Unable to allocate a bigstack");
	}

	p->p_flags |= P_BIGSTACK;
	p->p_stksaved = p->p_stkbase;

	*(unsigned*)((uintptr_t)stk + P_BIGSTACK_EXTRA) = PROC_STACK_TEST_PAT;

	/* pcreat() sets sp = p->p_stkbase + sctlp->stacksize */
	p->p_stkbase = (void*)((uintptr_t)stk + sctlp->bigstack_size -
	    sctlp->stacksize);
}

int
pcreat(struct proc *p, void (*entry)(void *), void *arg)
{
	uintptr_t		sp;
	struct nw_stk_ctl	*sctlp = &stk_ctl;
	struct lwp		*l = PR_TO_LWP(p);

	sctlp->nprocs_used++;

	l->l_prio.prio  = p->p_ctxt.info.priority; //For proc_put().

#ifndef NDEBUG
	/* Some assumptions are made for PPC in which arg can't be NULL */
	assert(arg != NULL);
#endif

	sp = (uintptr_t)p->p_stkbase + sctlp->stacksize;

#ifdef __GNUC__
# if defined(__X86__)
/* These jmpbuf offsets taken from libc/ansi/x86/_jmp.S */
#  define REG_IP 0x20
#  define REG_SP 0x2c
	sp -= sizeof(arg);                 /* Store argument to entry() */
	*(struct nw_stk_ctl **)sp = arg;

	sp -= sizeof(void (**)(void));       /* NULL out return adress */
	*(void (**)(void))sp = NULL;

	*(void **)((char *)p->p_regs + REG_IP) = entry;
	*(void **)((char *)p->p_regs + REG_SP) = (void *)sp;

# elif defined(__PPC__)
#  define REG_IP 0x00
#  define REG_SP 0x04
	/* Leave at least this much space for PPC function call */
	sp -= 3 * sizeof(uint64_t);

	p->p_jmp_arg = arg;

	*(void **)((char *)p->p_regs + REG_IP) = entry;
	*(void **)((char *)p->p_regs + REG_SP) = (void *)sp;

# elif defined(__SH__)
#  define REG_PR 0x00 /* Program return */
#  define REG_SP 0x04
/*
 * We don't initialize all the regs the first time
 * through (they're just floating).  We grab the
 * slot in p_regs that usually stores r8 to temporarily
 * store the jmp arg rather than adding another member
 * to struct proc as on some archs.
 */
#  define REG_R8 0x08
	sp -= sizeof(uint64_t);

	*(void **)((char *)p->p_regs + REG_PR) = entry;
	*(void **)((char *)p->p_regs + REG_SP) = (void *)sp;
	*(void **)((char *)p->p_regs + REG_R8) = arg;

# elif defined(__MIPS__)
#  define REG_IP 0x00
#  define REG_SP 0x04
/* These jmpbuf offsets taken from libc/ansi/mips/_jmp.S
 *      ----------------
 *      |       PC      |    jmp_buf[0]
 *      -----------------
 *      |       SP      |           [1]
 *      -----------------
 *      |       S0      |           [2]
 *      -----------------
 *      |       S1      |           [3]
 *      -----------------
 *      |       S2      |           [4]
 *      -----------------
 *      |       ...     |           ...
 *      -----------------
 *      |       S8      |           [10]
 *      -----------------
 */

	sp -= sizeof(uint64_t);

	p->p_jmp_arg = arg;
	*(void **)((char *)p->p_regs + REG_IP) = entry;
	*(void **)((char *)p->p_regs + REG_SP) = (void *)sp;

# elif defined(__ARM__)
/*  jmp_buf offsets taken from lib/c/ansi/arm/_jmp.S */
# 	define  REG_IP  0x24
# 	define  REG_SP  0x20

	sp -= sizeof(uint64_t);

	p->p_jmp_arg = arg;
	*(void **)((char *)p->p_regs + REG_IP) = entry;
	*(void **)((char *)p->p_regs + REG_SP) = (void *)sp;
# else
#  error Not configued for CPU
# endif
#else
# error Not configured for compiler
#endif

#undef REG_SP
#undef REG_IP

#ifndef NDEBUG
	if ((uintptr_t)sp & (NW_STK_ALIGN - 1))
		panic("stack not aligned");
#endif

	/*
	 * Initialize the remainder of the child's process environment.
	 * When the child has been set up, place on appropriate
	 * ready queue. 
	 */
	l->l_rval = 0;
#if MAXPRIO > 1
	p->p_pri = 1;
#endif
	l->l_stat = LREADY_START;
	proc_put(l);
	return p->p_thread;
}

#if 0
void
release_context(struct mbuf *m)
{
	nto_t_message_context_t *pm;
	struct nw_stk_ctl *sctlp;

	if(!(m->m_flags & M_EXT) || !(m->m_ext.ext_flags & M_EXT_FROM_US))
		panic("release_context");

	pm = m->m_ext.ext_arg;
	sctlp = m->m_ext.ext_types.extt_p;

	if(pm->u.ref_cnt-- != 2)
		_pool_put_header(sctlp->ctp_pool, pm, __FILE__, __LINE__, pm->ph);
}
#endif

/*
 * The main proc is at prio 0 and is at the tail of that Q.
 * Therefore, the one context (sctlp_ctxt) is still vaid (hasn't
 * been overwritten with another message yet at the main proc
 * hasn't been scheduled yet).
 */
void
startproc(void *arg)
{
	struct proc		*p;
	struct binding		*binding;
	void			*ocb;
	unsigned		type;
	resmgr_context_t	*ctp;
	int			scoid, ret;
	struct			_msg_info *info;
	int			(**funcp)(resmgr_context_t *ctp, io_read_t *msg,
	    			    void *ocb);
	struct			nw_stk_ctl *sctlp;

	sctlp = arg;

	p = LWP_TO_PR(curlwp);
	MSG_EVENT_INCR(&msg_ev);

	p->p_mbuf = NULL;
	p->p_cred = NULL;
//	p->p_flag = 0;
	p->p_vmspace.vm_flags = VM_USERSPACE;

	/* If here, we know it's not a pulse */
	ctp = &p->p_ctxt;
	type = p->p_curmsg = ctp->msg->type;
	switch (type) {
	/*
	 * All the ones with no special handling in
	 * the resmgr layer can go here.  This saves
	 * the double lock / unlock calls to _resmgr_handle()
	 * plus atomic_add() / atomic_sub() on the binding
	 * count.  We can do all this because we know only
	 * one thread is ever here at any point in time.
	 * 
	 * XXX This may break cross endian QNET support
	 *     if it's ever added to resmgr layer.
	 */
	case _IO_READ:
	case _IO_WRITE:
	case _IO_STAT:
	case _IO_DEVCTL:
	case _IO_LSEEK:
	case _IO_FDINFO:
	case _IO_MSG:
		info = &ctp->info;
		scoid = info->scoid & ~_NTO_SIDE_CHANNEL;

		MSG_EVENT_INCR(&msg_ev_local);

		if (info->flags & _NTO_MI_ENDIAN_DIFF) {
			MsgError(ctp->rcvid, EENDIAN);
			break;
		}
#ifdef OCB_LOCAL_CACHE
		else if ((ocb = ocb_local_cache_find(info)) != NULL) {
			MSG_EVENT_INCR(&msg_ev_local_ocb);
		}
#endif
		else if ((binding = _resmgr_handle(info, 0, _RESMGR_HANDLE_FIND)) == (void *)-1) {
			MsgError(ctp->rcvid, EBADF);
			break;
		}
		else {
			if (binding->funcs != RESMGR_BINDING_FILE_FUNCS) {
				_resmgr_handler(ctp);
				break;
			}
			ocb = binding->ocb;
		}

		type -= _IO_READ;
		funcp = &nw_io_funcs.read + type;
		ret = (**funcp)(ctp, &ctp->msg->read, ocb);

		switch (ret) {
		case _RESMGR_NOREPLY:
			break;

		case _RESMGR_DEFAULT:
			ret = ENOSYS;
			/* Fall through */

		default:
			if (ret <= 0) {
				MsgReplyv(ctp->rcvid, ctp->status,
				    ctp->iov + 0, -ret);
			}
			else {
				MsgError(ctp->rcvid, ret);
			}
		}

		break;

	default:
		if (type == _IO_NOTIFY) {
			/*
			 * There's a calculation in _resmgr_notify_handler() that
			 * determines the number of struct pollfd available in the
			 * ctp->msg buffer based on info.msglen; however, in our
			 * case we've done the initial MsgReceive across multiple
			 * iovs.  We've already limited ctp->msg_max_size to the
			 * first iov for other messages.
			 */
			ctp->info.msglen =
			    min(ctp->info.msglen, ctp->msg_max_size);
		}
		TASK_TIME_START(TASK_TIME_RESMGR);
		_resmgr_handler(ctp);
		break;
	}

	kthread_exit(0);
}


/* Returns 1 if moving from empty */
int
proc_put(struct lwp *l)
{
	int			pri_min, pri_max, i, prio;
	struct prio_ends	*priq;
	struct prio		*pmain;
	struct prio_ent		*pent;

	pmain = &stk_ctl.proc_prio;
	pent = &l->l_prio;
	priq = pmain->prio_prios;
	prio = pent->prio;

	if (pmain->prio_all.head == NULL) {
		priq[prio].head = pent;
		priq[prio].tail = pent;

		pmain->prio_all.head = pent;
		pmain->prio_all.tail = pent;
		pent->nxt = NULL;
		pent->prv = &pmain->prio_all.head;

		return 1;
	}

	if (priq[prio].head != NULL) {
		/* Easy case */

		/*
		 * We put it at the head of this priority's Q because
		 * numerically higher priorities are logically higher
		 * (sched() takes from the tail, not head).
		 */
		i = prio;
	}
	else {
		priq[prio].tail = pent;

		/*
		 * Now insert.
		 * We need put it either:
		 *  - before head of next higer (numerically) priority with entries.
		 *  - after  tail of next lower (numerically) priority with entries.
		 */
			
		pri_min = pmain->prio_all.head->prio;
		pri_max = pmain->prio_all.tail->prio;

		if (pri_max - prio > prio - pri_min) {
			/* start at us, move toward head */
			for (i = imax(prio - 1, pmain->prio_all.head->prio); ; i--) {
				if (priq[i].head != NULL)
					break;
			}
		}
		else {
			/* start at us, move toward tail */
			for (i = min(prio + 1, pmain->prio_all.tail->prio); ;i++) {
				if (priq[i].head != NULL)
					break;
			}
		}

		if (i < prio) {
			priq[prio].head = pent;

			pent->nxt = priq[i].tail->nxt;
			if (pent->nxt != NULL)
				pent->nxt->prv = &pent->nxt;
			else
				pmain->prio_all.tail = pent;
			pent->prv = &priq[i].tail->nxt;
			priq[i].tail->nxt = pent;

			return 0;
		}
	}

	pent->nxt            = priq[i].head;
	pent->prv            = priq[i].head->prv;
	priq[i].head->prv = &pent->nxt;
	*pent->prv           = pent;

	priq[prio].head = pent;

	return 0;
}
#if 0
void
gsignal(int rcvid, int sig)
{
    struct sigevent   e;

    e.sigev_notify= SIGEV_SIGNAL_CODE;
    e.sigev_signo= sig;
    e.sigev_code = SI_USER;
    e.sigev_value.sival_int = 0;

    MsgDeliverEvent(rcvid, &e);
	return;
}
#endif

void
psignal(struct proc *p, int sig)
{
	struct sigevent   e;

	e.sigev_notify= SIGEV_SIGNAL_CODE;
	e.sigev_signo= sig;
	e.sigev_code = SI_USER;
	e.sigev_value.sival_int = 0;

	MsgDeliverEvent(p->p_ctxt.rcvid, &e);

	return;
}


#ifdef OCB_LOCAL_CACHE
void *
ocb_local_cache_find(struct _msg_info *info)
{
	int scoid;
	void *ocb;

	/*
	 * Look at local cache conservatively so caller
	 * can fall back to _resmgr_handle() if any
	 * condition is not met.  even so, the binding
	 * should usually be found if the scoid / coid
	 * pair are in the cache range.
	 *
	 * unsigned comparisons to catch negative values.
	 */
	scoid = info->scoid & ~_NTO_SIDE_CHANNEL;

	if ((unsigned)scoid < ocb_cache_scoid_max &&
	    (unsigned)info->coid < OCB_CACHE_COID_MAX &&
	    ocb_cache[scoid].nd == info->nd &&
	    ocb_cache[scoid].pid == info->pid) {
		ocb = ocb_cache[scoid].ocbs[info->coid]; /* May be NULL */

	}
	else {
		ocb = NULL;
	}

	return ocb;
}
#endif


#if 0
/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void
wakeup(void *ident)
{
	struct slpque *qp;
	struct proc *p, **q;
	int s;

	s = splhigh();			/* XXXSMP: SCHED_LOCK(s) */

	qp = SLPQUE(ident);
 restart:
	for (q = &qp->sq_head; (p = *q) != NULL; ) {
#ifdef DIAGNOSTIC
		if (p->p_back || (p->p_stat != SSLEEP && p->p_stat != SSTOP))
			panic("wakeup");
#endif
		if (p->p_wchan == ident) {
			p->p_wchan = 0;
			*q = p->p_forw;
			if (qp->sq_tailp == &p->p_forw)
				qp->sq_tailp = q;
			if (p->p_stat == SSLEEP) {
				awaken(p);
				goto restart;
			}
		} else
			q = &p->p_forw;
	}
	splx(s);			/* XXXSMP: SCHED_UNLOCK(s) */
}
#endif

#ifdef QTEST

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <malloc.h>

#define NUM_PRIOS 64

typedef struct ent ent_t;
struct ent {
	ent_t *next;
	ent_t **prev;
	int prio;
};

typedef struct queue queue_t;
struct queue {
	ent_t *head;
	ent_t *tail;
};


static void
mkready(ent_t *entp, int prio, queue_t *qs, ent_t **ehead, ent_t **etail)
{
	int pri_min, pri_max;
	int  i;

	entp->prio = prio;

	if(!*ehead)
	{
		qs[prio].head = entp;
		qs[prio].tail = entp;

		*ehead = entp;
		*etail = entp;
		entp->next = NULL;
		entp->prev = ehead;

		return;
	}

	if(qs[prio].head)
	{
		/* Easy case */

		/*
		 * We put it at the head of this priority's Q because
		 * numerically higher prioritys are logically higher
		 * (sched() takes from the tail).
		 */
		i = prio;
	}
	else
	{
		qs[prio].tail = entp;

		/*
		 * Now insert.
		 * We need put it either:
		 *  - before head of next higer (numerically) priority with entries.
		 *  - after  tail of next lower (numerically) priority with entries.
		 */
			
		pri_min = (*ehead)->prio;
		pri_max = (*etail)->prio;

		if(pri_max - prio > prio - pri_min)
		{
			/* start at us, move toward head */
			for(i = imax(prio - 1, (*ehead)->prio); ; i--)
			{
				if(qs[i].head)
				{
					break;
				}
			}
		}
		else
		{
			/* start at us, move toward tail */
			for(i = min(prio + 1, (*etail)->prio); ;i++)
			{
				if(qs[i].head)
				{
					break;
				}
			}
		}

		if(i < prio)
		{
			if(entp->next = qs[i].tail->next)
				entp->next->prev = &entp->next;
			else
				*etail = entp;
			entp->prev = &qs[i].tail->next;
			qs[i].tail->next = entp;

			return;
		}
	}

	entp->next       = qs[i].head;
	entp->prev       = qs[i].head->prev;
	qs[i].head->prev = &entp->next;
	*entp->prev      = entp;

	qs[prio].head = entp;
}

int
main(void)
{
	ent_t *ehead = NULL, *etail = NULL;
	queue_t qs[NUM_PRIOS];

	ent_t *free_ent = NULL, *entp = NULL;
	int i, add, prio, rem;
	int j = 0, k = 0, sub = 4;


	memset(qs, 0x00, sizeof qs);

	for(i = 0; i<1000; i++)
	{
		if(!(entp = calloc(1, sizeof *entp)))
		{
			fprintf(stderr, "no mem\n");
			return 1;
		}

		entp->next = free_ent;
		free_ent = entp;
	}

	for(;;)
	{
		add = (random() >> 8) % (12 - sub);
		rem = (random() >> 8) % sub;

		prio = random() % NUM_PRIOS;

		if(add)
		{
			if(!(entp = free_ent))
			{
				add = 0;
				sub = 8;
				if(!(k++ % 100))
					printf("full\n");
			}
			else
			{
				free_ent = free_ent->next;
				entp->next = NULL;
				mkready(entp, prio, qs, &ehead, &etail);
			}
		}

		if(rem && etail)
		{
			entp = etail;
			*etail->prev = NULL;
			if(ehead == NULL)
			{
				etail = NULL;
				qs[entp->prio].head = NULL;
				qs[entp->prio].tail = NULL;
				sub = 4;
				if(!(j++ % 100))
				{
					printf("empty\n");
				}
			}
			else
			{
				etail = (ent_t *)((char *)etail->prev - offsetof(ent_t, next));
				if(etail->prio != entp->prio)
				{
					qs[entp->prio].head = NULL;
					qs[entp->prio].tail = NULL;
				}
				else
				{
					qs[entp->prio].tail = etail;
				}
			}
			entp->next = free_ent;
			free_ent = entp;
		}


		for(i = 0, entp = ehead; entp; entp = entp->next)
		{
			if(entp->prio < i)
			{
				fprintf(stderr, "bad sort\n");
				return 1;
			}
			i = entp->prio;
		}

	}

	return 0;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/proc.c $ $Rev: 768971 $")
#endif
