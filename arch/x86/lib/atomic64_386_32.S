/*
 * atomic64_t for 386/486
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

/* if you want SMP support, implement these with real spinlocks */
.macro LOCK reg
	pushfl
	cli
.endm

.macro UNLOCK reg
	popfl
.endm

#define BEGIN(op) \
.macro endp; \
ENDPROC(atomic64_##op##_386); \
.purgem endp; \
.endm; \
ENTRY(atomic64_##op##_386); \
	LOCK v;

#define ENDP endp

#define RET(op) \
	UNLOCK v; \
	pax_ret atomic64_##op##_386

#define RET_ENDP(op) \
	RET(op); \
	ENDP

#define v %ecx
BEGIN(read)
	movl  (v), %eax
	movl 4(v), %edx
RET_ENDP(read)
BEGIN(read_unchecked)
	movl  (v), %eax
	movl 4(v), %edx
RET_ENDP(read_unchecked)
#undef v

#define v %esi
BEGIN(set)
	movl %ebx,  (v)
	movl %ecx, 4(v)
RET_ENDP(set)
BEGIN(set_unchecked)
	movl %ebx,  (v)
	movl %ecx, 4(v)
RET_ENDP(set_unchecked)
#undef v

#define v  %esi
BEGIN(xchg)
	movl  (v), %eax
	movl 4(v), %edx
	movl %ebx,  (v)
	movl %ecx, 4(v)
RET_ENDP(xchg)
#undef v

#define v %ecx
BEGIN(add)
	addl %eax,  (v)
	adcl %edx, 4(v)

	PAX_REFCOUNT64_OVERFLOW (v)
RET_ENDP(add)
BEGIN(add_unchecked)
	addl %eax,  (v)
	adcl %edx, 4(v)
RET_ENDP(add_unchecked)
#undef v

#define v %ecx
BEGIN(add_return)
	addl  (v), %eax
	adcl 4(v), %edx

	movl %eax,  (v)
	movl %edx, 4(v)

	PAX_REFCOUNT64_OVERFLOW (v)
RET_ENDP(add_return)
BEGIN(add_return_unchecked)
	addl  (v), %eax
	adcl 4(v), %edx
	movl %eax,  (v)
	movl %edx, 4(v)
RET_ENDP(add_return_unchecked)
#undef v

#define v %ecx
BEGIN(sub)
	subl %eax,  (v)
	sbbl %edx, 4(v)

	PAX_REFCOUNT64_UNDERFLOW (v)
RET_ENDP(sub)
BEGIN(sub_unchecked)
	subl %eax,  (v)
	sbbl %edx, 4(v)
RET_ENDP(sub_unchecked)
#undef v

#define v %ecx
BEGIN(sub_return)
	negl %edx
	negl %eax
	sbbl $0, %edx
	addl  (v), %eax
	adcl 4(v), %edx

	movl %eax,  (v)
	movl %edx, 4(v)

	PAX_REFCOUNT64_UNDERFLOW (v)
RET_ENDP(sub_return)
BEGIN(sub_return_unchecked)
	negl %edx
	negl %eax
	sbbl $0, %edx
	addl  (v), %eax
	adcl 4(v), %edx
	movl %eax,  (v)
	movl %edx, 4(v)
RET_ENDP(sub_return_unchecked)
#undef v

#define v %esi
BEGIN(inc)
	addl $1,  (v)
	adcl $0, 4(v)

	PAX_REFCOUNT64_OVERFLOW (v)
RET_ENDP(inc)
BEGIN(inc_unchecked)
	addl $1,  (v)
	adcl $0, 4(v)
RET_ENDP(inc_unchecked)
#undef v

#define v %esi
BEGIN(inc_return)
	movl  (v), %eax
	movl 4(v), %edx
	addl $1, %eax
	adcl $0, %edx

	movl %eax,  (v)
	movl %edx, 4(v)

	PAX_REFCOUNT64_OVERFLOW (v)
RET_ENDP(inc_return)
BEGIN(inc_return_unchecked)
	movl  (v), %eax
	movl 4(v), %edx
	addl $1, %eax
	adcl $0, %edx
	movl %eax,  (v)
	movl %edx, 4(v)
RET_ENDP(inc_return_unchecked)
#undef v

#define v %esi
BEGIN(dec)
	subl $1,  (v)
	sbbl $0, 4(v)

	PAX_REFCOUNT64_UNDERFLOW (v)
RET_ENDP(dec)
BEGIN(dec_unchecked)
	subl $1,  (v)
	sbbl $0, 4(v)
RET_ENDP(dec_unchecked)
#undef v

#define v %esi
BEGIN(dec_return)
	movl  (v), %eax
	movl 4(v), %edx
	subl $1, %eax
	sbbl $0, %edx

	movl %eax,  (v)
	movl %edx, 4(v)

	PAX_REFCOUNT64_UNDERFLOW (v)
RET_ENDP(dec_return)
BEGIN(dec_return_unchecked)
	movl  (v), %eax
	movl 4(v), %edx
	subl $1, %eax
	sbbl $0, %edx
	movl %eax,  (v)
	movl %edx, 4(v)
RET_ENDP(dec_return_unchecked)
#undef v

#define v %esi
BEGIN(add_unless)
	addl %eax, %ecx
	adcl %edx, %edi
	addl  (v), %eax
	adcl 4(v), %edx

	PAX_REFCOUNT64_OVERFLOW (v)

	cmpl %eax, %ecx
	je 3f
1:
	movl %eax,  (v)
	movl %edx, 4(v)
	movl $1, %eax
2:
	RET(add_unless)
3:
	cmpl %edx, %edi
	jne 1b
	xorl %eax, %eax
	jmp 2b
ENDP
#undef v

#define v %esi
BEGIN(inc_not_zero)
	movl  (v), %eax
	movl 4(v), %edx
	testl %eax, %eax
	je 3f
1:
	addl $1, %eax
	adcl $0, %edx

	PAX_REFCOUNT64_OVERFLOW (v)

	movl %eax,  (v)
	movl %edx, 4(v)
	movl $1, %eax
2:
	RET(inc_not_zero)
3:
	testl %edx, %edx
	jne 1b
	jmp 2b
ENDP
#undef v

#define v %esi
BEGIN(dec_if_positive)
	movl  (v), %eax
	movl 4(v), %edx
	subl $1, %eax
	sbbl $0, %edx

	PAX_REFCOUNT64_UNDERFLOW (v)

	js 1f
	movl %eax,  (v)
	movl %edx, 4(v)
1:
RET_ENDP(dec_if_positive)
#undef v
