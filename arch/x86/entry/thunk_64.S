/*
 * Save registers before calling assembly functions. This avoids
 * disturbance of register allocation in some inline assembly constructs.
 * Copyright 2001,2002 by Andi Kleen, SuSE Labs.
 * Added trace_hardirqs callers - Copyright 2007 Steven Rostedt, Red Hat, Inc.
 * Subject to the GNU public license, v.2. No warranty of any kind.
 */
#include <linux/linkage.h>
#include "calling.h"
#include <asm/asm.h>
#include <asm/export.h>
#include <asm/alternative-asm.h>

	/* rdi:	arg1 ... normal C conventions. rax is saved/restored. */
	.macro THUNK name, func, put_ret_addr_in_rdi=0
	.globl \name
	.type \name, @function
\name:
	pushq %rbp
	movq %rsp, %rbp

	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %rax
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11

	.if \put_ret_addr_in_rdi
	/* 8(%rbp) is return addr on stack */
	movq 8(%rbp), %rdi
	.endif

	pax_direct_call \func

	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rax
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
	popq %rbp
	pax_ret \name
	_ASM_NOKPROBE(\name)
	.endm

#ifdef CONFIG_TRACE_IRQFLAGS
	THUNK trace_hardirqs_on_thunk,trace_hardirqs_on_caller,1
	THUNK trace_hardirqs_off_thunk,trace_hardirqs_off_caller,1
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	THUNK lockdep_sys_exit_thunk,lockdep_sys_exit
#endif

#ifdef CONFIG_PREEMPT
	THUNK ___preempt_schedule, preempt_schedule
	THUNK ___preempt_schedule_notrace, preempt_schedule_notrace
	EXPORT_SYMBOL(___preempt_schedule)
	EXPORT_SYMBOL(___preempt_schedule_notrace)
#endif
