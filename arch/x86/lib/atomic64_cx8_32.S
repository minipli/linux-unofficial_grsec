/*
 * atomic64_t for 586+
 *
 * Copyright © 2010  Luca Barbieri
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/linkage.h>
#include <asm/irq_vectors.h>
#include <asm/alternative-asm.h>

.macro read64 reg
	movl %ebx, %eax
	movl %ecx, %edx
/* we need LOCK_PREFIX since otherwise cmpxchg8b always does the write */
	LOCK_PREFIX
	cmpxchg8b (\reg)
.endm

ENTRY(atomic64_read_cx8)
	read64 %ecx
	pax_ret atomic64_read
ENDPROC(atomic64_read_cx8)

ENTRY(atomic64_read_unchecked_cx8)
	read64 %ecx
	pax_ret atomic64_read_unchecked
ENDPROC(atomic64_read_unchecked_cx8)

ENTRY(atomic64_set_cx8)
1:
/* we don't need LOCK_PREFIX since aligned 64-bit writes
 * are atomic on 586 and newer */
	cmpxchg8b (%esi)
	jne 1b

	pax_ret atomic64_set
ENDPROC(atomic64_set_cx8)

ENTRY(atomic64_set_unchecked_cx8)
1:
/* we don't need LOCK_PREFIX since aligned 64-bit writes
 * are atomic on 586 and newer */
	cmpxchg8b (%esi)
	jne 1b

	pax_ret atomic64_set_unchecked
ENDPROC(atomic64_set_unchecked_cx8)

ENTRY(atomic64_xchg_cx8)
1:
	LOCK_PREFIX
	cmpxchg8b (%esi)
	jne 1b

	pax_ret atomic64_xchg
ENDPROC(atomic64_xchg_cx8)

.macro addsub_return func ins insc unchecked=""
ENTRY(atomic64_\func\()_return\unchecked\()_cx8)
	pushl %ebp
	pushl %ebx
	pushl %esi
	pushl %edi

	movl %eax, %esi
	movl %edx, %edi
	movl %ecx, %ebp

	read64 %ecx
1:
	movl %eax, %ebx
	movl %edx, %ecx
	\ins\()l %esi, %ebx
	\insc\()l %edi, %ecx

.ifb \unchecked
.if \func == add
	PAX_REFCOUNT64_OVERFLOW (%ebp)
.else
	PAX_REFCOUNT64_UNDERFLOW (%ebp)
.endif
.endif

	LOCK_PREFIX
	cmpxchg8b (%ebp)
	jne 1b
	movl %ebx, %eax
	movl %ecx, %edx

	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	pax_ret atomic64_\func\()_return\unchecked
ENDPROC(atomic64_\func\()_return\unchecked\()_cx8)
.endm

addsub_return add add adc
addsub_return sub sub sbb
addsub_return add add adc _unchecked
addsub_return sub sub sbb _unchecked

.macro incdec_return func ins insc unchecked=""
ENTRY(atomic64_\func\()_return\unchecked\()_cx8)
	pushl %ebx

	read64 %esi
1:
	movl %eax, %ebx
	movl %edx, %ecx
	\ins\()l $1, %ebx
	\insc\()l $0, %ecx

.ifb \unchecked
.if \func == inc
	PAX_REFCOUNT64_OVERFLOW (%esi)
.else
	PAX_REFCOUNT64_UNDERFLOW (%esi)
.endif
.endif

	LOCK_PREFIX
	cmpxchg8b (%esi)
	jne 1b
	movl %ebx, %eax
	movl %ecx, %edx

	popl %ebx
	pax_ret atomic64_\func\()_return\unchecked
ENDPROC(atomic64_\func\()_return\unchecked\()_cx8)
.endm

incdec_return inc add adc
incdec_return dec sub sbb
incdec_return inc add adc _unchecked
incdec_return dec sub sbb _unchecked

ENTRY(atomic64_dec_if_positive_cx8)
	pushl %ebx

	read64 %esi
1:
	movl %eax, %ebx
	movl %edx, %ecx
	subl $1, %ebx
	sbb $0, %ecx

	PAX_REFCOUNT64_UNDERFLOW (%esi)

	js 2f
	LOCK_PREFIX
	cmpxchg8b (%esi)
	jne 1b

2:
	movl %ebx, %eax
	movl %ecx, %edx
	popl %ebx
	pax_ret atomic64_dec_if_positive
ENDPROC(atomic64_dec_if_positive_cx8)

ENTRY(atomic64_add_unless_cx8)
	pushl %ebp
	pushl %ebx
/* these just push these two parameters on the stack */
	pushl %edi
	pushl %ecx

	movl %eax, %ebp
	movl %edx, %edi

	read64 %esi
1:
	cmpl %eax, 0(%esp)
	je 4f
2:
	movl %eax, %ebx
	movl %edx, %ecx
	addl %ebp, %ebx
	adcl %edi, %ecx

	PAX_REFCOUNT64_OVERFLOW (%esi)

	LOCK_PREFIX
	cmpxchg8b (%esi)
	jne 1b

	movl $1, %eax
3:
	addl $8, %esp
	popl %ebx
	popl %ebp
	pax_ret atomic64_add_unless
4:
	cmpl %edx, 4(%esp)
	jne 2b
	xorl %eax, %eax
	jmp 3b
ENDPROC(atomic64_add_unless_cx8)

ENTRY(atomic64_inc_not_zero_cx8)
	pushl %ebx

	read64 %esi
1:
	movl %eax, %ecx
	orl %edx, %ecx
	jz 3f
	movl %eax, %ebx
	xorl %ecx, %ecx
	addl $1, %ebx
	adcl %edx, %ecx

	PAX_REFCOUNT64_OVERFLOW (%esi)

	LOCK_PREFIX
	cmpxchg8b (%esi)
	jne 1b

	movl $1, %eax
3:
	popl %ebx
	pax_ret atomic64_inc_not_zero
ENDPROC(atomic64_inc_not_zero_cx8)
