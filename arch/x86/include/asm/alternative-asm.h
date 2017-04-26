#ifndef _ASM_X86_ALTERNATIVE_ASM_H
#define _ASM_X86_ALTERNATIVE_ASM_H

#ifdef __ASSEMBLY__

#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/irq_vectors.h>

#ifdef CONFIG_SMP
	.macro LOCK_PREFIX
672:	lock
	.pushsection .smp_locks,"a"
	.balign 4
	.long 672b - .
	.popsection
	.endm
#else
	.macro LOCK_PREFIX
	.endm
#endif

.macro pax_force_retaddr_bts rip=0
#ifdef KERNEXEC_PLUGIN
	btsq $63,\rip(%rsp)
#endif
.endm

#if defined(CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_BTS) && defined(CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR)
#error PAX: the KERNEXEC BTS and OR methods must not be enabled at once
#endif

.macro pax_force_retaddr rip=0
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_BTS
	btsq $63,\rip(%rsp)
#endif
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	orq %r12,\rip(%rsp)
#endif
.endm

.macro pax_force_fptr ptr
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_BTS
	btsq $63,\ptr
#endif
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	orq %r12,\ptr
#endif
.endm

.macro pax_set_fptr_mask
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movabs $0x8000000000000000,%r12
#endif
.endm

#ifdef CONFIG_PAX_RAP
.macro rap_call target hash="" sym=""

	jmp 2001f
	.ifb \hash
	__ASM_RAP_RET_HASH(__rap_hash_ret_\target)
	.else
	__ASM_RAP_RET_HASH(__rap_hash_ret_\hash)
	.endif
	.skip 8-(2002f-2001f),0xcc

	.ifnb \sym
	.globl \sym
\sym :
	.endif

2001:	call \target
2002:
.endm

.macro rap_retloc caller
	__ASM_RAP_RET_HASH(__rap_hash_ret_\caller)
	.skip 8-(2002f-2001f),0xcc
2001:	call \caller
2002:
.endm

.macro rap_ret func
	ret
.endm
#endif

.macro pax_direct_call_global target sym
#ifdef CONFIG_PAX_RAP
	rap_call \target, , \sym
#else
	.globl \sym
\sym :
	call \target
#endif
.endm

.macro pax_indirect_call target extra
#ifdef CONFIG_PAX_RAP
	rap_call "*\target" hash=\extra
#else
	call *\target
#endif
.endm

.macro pax_direct_call target
#ifdef CONFIG_PAX_RAP
	rap_call \target
#else
	call \target
#endif
.endm

.macro pax_retloc caller
#ifdef CONFIG_PAX_RAP
	rap_retloc \caller
#else
#endif
.endm

.macro pax_ret func
	pax_force_retaddr
#ifdef CONFIG_PAX_RAP
	rap_ret \func
#else
	ret
#endif
.endm

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro altinstruction_entry orig alt feature orig_len alt_len pad_len
	.long \orig - .
	.long \alt - .
	.word \feature
	.byte \orig_len
	.byte \alt_len
	.byte \pad_len
.endm

/*
 * Define an alternative between two instructions. If @feature is
 * present, early code in apply_alternatives() replaces @oldinstr with
 * @newinstr. ".skip" directive takes care of proper instruction padding
 * in case @newinstr is longer than @oldinstr.
 */
.macro ALTERNATIVE oldinstr, newinstr, feature
140:
	\oldinstr
141:
	.skip -(((144f-143f)-(141b-140b)) > 0) * ((144f-143f)-(141b-140b)),0x90
142:

	.pushsection .altinstructions,"a"
	altinstruction_entry 140b,143f,\feature,142b-140b,144f-143f,142b-141b
	.popsection

	.pushsection .altinstr_replacement,"a"
143:
	\newinstr
144:
	.popsection
.endm

#define old_len			141b-140b
#define new_len1		144f-143f
#define new_len2		145f-144f

/*
 * max without conditionals. Idea adapted from:
 * http://graphics.stanford.edu/~seander/bithacks.html#IntegerMinOrMax
 */
#define alt_max_short(a, b)	((a) ^ (((a) ^ (b)) & -(-((a) < (b)))))


/*
 * Same as ALTERNATIVE macro above but for two alternatives. If CPU
 * has @feature1, it replaces @oldinstr with @newinstr1. If CPU has
 * @feature2, it replaces @oldinstr with @feature2.
 */
.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
140:
	\oldinstr
141:
	.skip -((alt_max_short(new_len1, new_len2) - (old_len)) > 0) * \
		(alt_max_short(new_len1, new_len2) - (old_len)),0x90
142:

	.pushsection .altinstructions,"a"
	altinstruction_entry 140b,143f,\feature1,142b-140b,144f-143f,142b-141b
	altinstruction_entry 140b,144f,\feature2,142b-140b,145f-144f,142b-141b
	.popsection

	.pushsection .altinstr_replacement,"a"
143:
	\newinstr1
144:
	\newinstr2
145:
	.popsection
.endm

.macro __PAX_REFCOUNT section, counter
#ifdef CONFIG_PAX_REFCOUNT
	jo 111f
	.pushsection .text.\section
111:	lea \counter,%_ASM_CX
	int $X86_REFCOUNT_VECTOR
222:
	.popsection
333:
	_ASM_EXTABLE(222b, 333b)
#endif
.endm

.macro PAX_REFCOUNT64_OVERFLOW counter
	__PAX_REFCOUNT refcount64_overflow, \counter
.endm

.macro PAX_REFCOUNT64_UNDERFLOW counter
	__PAX_REFCOUNT refcount64_underflow, \counter
.endm
#endif  /*  __ASSEMBLY__  */

#endif /* _ASM_X86_ALTERNATIVE_ASM_H */
