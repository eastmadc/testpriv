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





#ifndef __NW_CPU_MISC_H_INCLUDED
#error Do not include this file directly.  Include sys/nw_cpu_misc.h.
#endif

#ifndef _ARM_NW_CPU_MISC_H_INCLUDED
#define _ARM_NW_CPU_MISC_H_INCLUDED

#ifndef NDEBUG
#include "nw_tls.h"
#include "nw_sync.h"
#endif

/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */
#ifndef __atomic_fool_gcc
struct __gcc_fool { int __fool[100]; };
#define __atomic_fool_gcc(__x) (*(volatile struct __gcc_fool *)__x)
#endif


/* Save our current stack, move to our interrupt stack */
#define CPU_STACK_INTERRUPT(wtp)				\
	__asm__ __volatile__ (					\
		"str sp, %0;"					\
		"mov sp, %1;"					\
		: "=m" (__atomic_fool_gcc(&(wtp)->saved_sp))	\
		: "r" ((wtp)->intr_stack_tos)			\
		: "sp", "memory");				\


/* Restore our saved stack */
#define CPU_STACK_RESTORE(wtp)			\
	__asm__ __volatile__ (			\
		"mov sp, %0;"			\
		:				\
		: "r" ((wtp)->saved_sp)		\
		: "sp");


/* As above but we don't need to save our current stack */
#define CPU_STACK_INTERRUPT_NOSAVE(wtp)		\
	__asm__ __volatile__ (			\
		"mov sp, %0;"			\
		:				\
		: "r" ((wtp)->intr_stack_tos)	\
		: "sp");


/* interrupt_non_critical() needs current stack saved on ARM */
#define CPU_STACK_INTERRUPT_NON_CRITICAL(wtp) CPU_STACK_INTERRUPT((wtp))

 
#define CPU_RCV_LOOP_CTXT_STORE(wtp)				\
	{							\
	unsigned tmp;						\
	__asm__ __volatile__ (					\
		"mrs %0, cpsr;"					\
		"str %0, [%1, #64];"				\
		"adr %0, 1f;"					\
		"str %0, [%1, #60];"				\
		"stmia %1, {r0-r14};"				\
		"1:;"						\
		: "=r&" (tmp)					\
		: "r" (&(wtp)->rx_loop_ctxt.rx_loop_ctxt)	\
		: "memory"					\
	);							\
	}


#define CPU_RCV_LOOP_CTXT_RESTORE(wtp)	(wtp)->jp = &(wtp)->rx_loop_ctxt.rx_loop_ctxt

static __inline void cpu_sigcontext_validate(struct sigstack_entry *, mcontext_t *);

/* From ker/arm/kercpu.h */
#define REGSTATUS(reg)		((reg)->gpr[ARM_REG_R0])
#define REGIP(reg)		((reg)->gpr[ARM_REG_PC])

#define KER_ENTRY_SIZE		4	/* size of kernel entry opcode */
#define KERERR_SKIPAHEAD	4	/* increment IP by this much on error */


static __inline void
cpu_sigcontext_validate(struct sigstack_entry *ss, mcontext_t *jp)
{
#ifndef NDEBUG
	if (ss->mutex != NULL && (jp->cpu.gpr[ARM_REG_SP] & 1))
		panic("arm cpu_sigcontext_validate: critical section around kercall?");
#endif

	if (ss->mutex != NULL) {
		if (REGSTATUS(&jp->cpu) != EOK)
			REGIP(&jp->cpu) -= KER_ENTRY_SIZE + KERERR_SKIPAHEAD;
		else
			REGIP(&jp->cpu) -= KER_ENTRY_SIZE;

#ifndef NDEBUG
		if (ss->mutex->NW_SYNC_OWNER == __tls()->NW_TLS_OWNER ||
		    *(uint32_t *)REGIP(&jp->cpu) != 0xef000000) {   /* 'swi' instruction */
			panic("arm cpu_sigcontext_validate: Unexpected contested mutex context");
		}
#endif

		/* Reset the kercall. */
		jp->cpu.gpr[ARM_REG_R12] = __KER_SYNC_MUTEX_LOCK;

		/* Reset the kercall arg */
		jp->cpu.gpr[ARM_REG_R0] = (uint32_t)ss->mutex;
	}
	else if ((jp->cpu.gpr[ARM_REG_SP] & 1) != 0) {
		uintptr_t	start;
		uintptr_t	end;
		uintptr_t	pc;

		/* Derived from ker/arm/cpu_misc.c */
		/* critical section */

		start = jp->cpu.gpr[ARM_REG_IP];
		end   = jp->cpu.gpr[ARM_REG_LR];
		pc    = jp->cpu.gpr[ARM_REG_PC];

		if (pc >= start && pc < end && end - start < 20)
			jp->cpu.gpr[ARM_REG_PC] = start;
	}
}
#endif /* !_ARM_NW_CPU_MISC_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/target/arm/nw_cpu_misc.h $ $Rev: 680336 $")
#endif
