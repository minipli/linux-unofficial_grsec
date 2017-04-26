/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 *
 * But use these as seldom as possible since they are much more slower
 * than regular operations.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1996, 97, 99, 2000, 03, 04, 06 by Ralf Baechle
 */
#ifndef _ASM_ATOMIC_H
#define _ASM_ATOMIC_H

#include <linux/irqflags.h>
#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/compiler.h>
#include <asm/cpu-features.h>
#include <asm/cmpxchg.h>
#include <asm/war.h>

#ifdef CONFIG_GENERIC_ATOMIC64
#include <asm-generic/atomic64.h>
#endif

#define ATOMIC_INIT(i)	  { (i) }

#ifdef CONFIG_64BIT
#define _ASM_EXTABLE(from, to)		\
"	.section __ex_table,\"a\"\n"	\
"	.dword	" #from ", " #to"\n"	\
"	.previous\n"
#else
#define _ASM_EXTABLE(from, to)		\
"	.section __ex_table,\"a\"\n"	\
"	.word	" #from ", " #to"\n"	\
"	.previous\n"
#endif

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v)
{
	return READ_ONCE(v->counter);
}

static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return READ_ONCE(v->counter);
}

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}

static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}

#ifdef CONFIG_PAX_REFCOUNT
#define __OVERFLOW_POST				\
	"	b	4f		\n"	\
	"	.set	noreorder	\n"	\
	"3:	b	5f		\n"	\
	"	move	%0, %1		\n"	\
	"	.set	reorder		\n"
#define __OVERFLOW_EXTABLE	\
	"3:\n"			\
	_ASM_EXTABLE(2b, 3b)
#else
#define __OVERFLOW_POST
#define __OVERFLOW_EXTABLE
#endif

#define __ATOMIC_OP(op, suffix, asm_op, extable)			      \
static inline void atomic_##op##suffix(int i, atomic##suffix##_t * v)	      \
{									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		int temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	mips3					\n"   \
		"1:	ll	%0, %1		# atomic_" #op #suffix "\n"   \
		"2:	" #asm_op " %0, %2				\n"   \
		"	sc	%0, %1					\n"   \
		"	beqzl	%0, 1b					\n"   \
		extable							      \
		"	.set	mips0					\n"   \
		: "=&r" (temp), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		int temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	"MIPS_ISA_LEVEL"			\n"   \
		"1:	ll	%0, %1		# atomic_" #op #suffix "\n"   \
		"2:	" #asm_op " %0, %2				\n"   \
		"	sc	%0, %1					\n"   \
		"	beqz	%0, 1b					\n"   \
			extable						      \
		"	.set	mips0					\n"   \
		: "=&r" (temp), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		__asm__ __volatile__(					      \
		"2:	" #asm_op " %0, %1				\n"   \
		extable							      \
		: "+r" (v->counter) : "Ir" (i));			      \
		raw_local_irq_restore(flags);				      \
	}								      \
}

#define ATOMIC_OP(op, asm_op) __ATOMIC_OP(op, _unchecked, asm_op##u, )	      \
			      __ATOMIC_OP(op, , asm_op, __OVERFLOW_EXTABLE)

#define __ATOMIC_OP_RETURN(op, suffix, asm_op, post_op, extable)	      \
static inline int atomic_##op##_return##suffix##_relaxed(int i, atomic##suffix##_t * v) \
{									      \
	int result;							      \
									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		int temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	mips3					\n"   \
		"1:	ll	%1, %2	# atomic_" #op "_return" #suffix"\n"  \
		"2:	" #asm_op " %0, %1, %3				\n"   \
		"	sc	%0, %2					\n"   \
		"	beqzl	%0, 1b					\n"   \
		post_op							      \
		extable							      \
		"4:	" #asm_op " %0, %1, %3				\n"   \
		"5:							\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "+" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		int temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	"MIPS_ISA_LEVEL"			\n"   \
		"1:	ll	%1, %2	# atomic_" #op "_return" #suffix "\n" \
		"2:	" #asm_op " %0, %1, %3				\n"   \
		"	sc	%0, %2					\n"   \
		post_op							      \
		extable							      \
		"4:	" #asm_op " %0, %1, %3				\n"   \
		"5:							\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "+" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i));						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		__asm__ __volatile__(					      \
		"	lw	%0, %1					\n"   \
		"2:	" #asm_op " %0, %1, %2				\n"   \
		"	sw	%0, %1					\n"   \
		"3:							\n"   \
		extable							      \
		: "=&r" (result), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
		raw_local_irq_restore(flags);				      \
	}								      \
									      \
	return result;							      \
}

#define ATOMIC_OP_RETURN(op, asm_op) __ATOMIC_OP_RETURN(op, _unchecked, asm_op##u, , )	\
				     __ATOMIC_OP_RETURN(op, , asm_op, __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define ATOMIC_FETCH_OP(op, c_op, asm_op)				      \
static __inline__ int atomic_fetch_##op##_relaxed(int i, atomic_t * v)	      \
{									      \
	int result;							      \
									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		int temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	arch=r4000				\n"   \
		"1:	ll	%1, %2		# atomic_fetch_" #op "	\n"   \
		"	" #asm_op " %0, %1, %3				\n"   \
		"	sc	%0, %2					\n"   \
		"	beqzl	%0, 1b					\n"   \
		"	move	%0, %1					\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "+" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		int temp;						      \
									      \
		do {							      \
			__asm__ __volatile__(				      \
			"	.set	"MIPS_ISA_LEVEL"		\n"   \
			"	ll	%1, %2	# atomic_fetch_" #op "	\n"   \
			"	" #asm_op " %0, %1, %3			\n"   \
			"	sc	%0, %2				\n"   \
			"	.set	mips0				\n"   \
			: "=&r" (result), "=&r" (temp),			      \
			  "+" GCC_OFF_SMALL_ASM() (v->counter)		      \
			: "Ir" (i));					      \
		} while (unlikely(!result));				      \
									      \
		result = temp;						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		result = v->counter;					      \
		v->counter c_op i;					      \
		raw_local_irq_restore(flags);				      \
	}								      \
									      \
	return result;							      \
}

#define ATOMIC_OPS(op, asm_op)					      \
	ATOMIC_OP(op, asm_op)					      \
	ATOMIC_OP_RETURN(op, asm_op)				      \
	ATOMIC_FETCH_OP(op, asm_op)

ATOMIC_OPS(add, addu)
ATOMIC_OPS(sub, subu)

#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed
#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed

#undef ATOMIC_OPS
#define ATOMIC_OPS(op, asm_op)					      \
	ATOMIC_OP(op, asm_op)					      \
	ATOMIC_FETCH_OP(op, asm_op)

ATOMIC_OPS(and, and)
ATOMIC_OPS(or, or)
ATOMIC_OPS(xor, xor)

#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef __ATOMIC_OP_RETURN
#undef ATOMIC_OP
#undef __ATOMIC_OP

/*
 * atomic_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ int atomic_sub_if_positive(int i, atomic_t *v)
{
	int result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		int temp;

		__asm__ __volatile__(
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp),
		  "+" GCC_OFF_SMALL_ASM() (v->counter)
		: "Ir" (i), GCC_OFF_SMALL_ASM() (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		int temp;

		__asm__ __volatile__(
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"1:	ll	%1, %2		# atomic_sub_if_positive\n"
		"	subu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	sc	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 subu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp),
		  "+" GCC_OFF_SMALL_ASM() (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old,
					   int new)
{
	return cmpxchg(&(v->counter), old, new);
}

static inline int atomic_xchg(atomic_t *v, int new)
{
	return xchg(&v->counter, new);
}

static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&(v->counter), new);
}

/**
 * __atomic_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static __inline__ int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

#define atomic_dec_return(v) atomic_sub_return(1, (v))
#define atomic_inc_return(v) atomic_add_return(1, (v))
static __inline__ int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
}

/*
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic_sub_and_test(i, v) (atomic_sub_return((i), (v)) == 0)

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
static __inline__ int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v) == 0;
}

/*
 * atomic_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic_dec_and_test(v) (atomic_sub_return(1, (v)) == 0)

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 */
#define atomic_dec_if_positive(v)	atomic_sub_if_positive(1, v)

/*
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
#define atomic_inc(v) atomic_add(1, (v))
static __inline__ void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}

/*
 * atomic_dec - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic_dec(v) atomic_sub(1, (v))
static __inline__ void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}

/*
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic_add_negative(i, v) (atomic_add_return(i, (v)) < 0)

#ifdef CONFIG_64BIT

#define ATOMIC64_INIT(i)    { (i) }

/*
 * atomic64_read - read atomic variable
 * @v: pointer of type atomic64_t
 *
 */
static inline long atomic64_read(const atomic64_t *v)
{
	return READ_ONCE(v->counter);
}

static inline long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	return READ_ONCE(v->counter);
}

/*
 * atomic64_set - set atomic variable
 * @v: pointer of type atomic64_t
 * @i: required value
 */
static inline void atomic64_set(atomic64_t *v, long i)
{
	WRITE_ONCE(v->counter, i);
}

static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	WRITE_ONCE(v->counter, i);
}

#define __ATOMIC64_OP(op, suffix, asm_op, extable)			      \
static inline void atomic64_##op##suffix(long i, atomic64##suffix##_t * v)    \
{									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		long temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	"MIPS_ISA_LEVEL"			\n"   \
		"1:	lld	%0, %1		# atomic64_" #op #suffix "\n" \
		"2:	" #asm_op " %0, %2				\n"   \
		"	scd	%0, %1					\n"   \
		"	beqzl	%0, 1b					\n"   \
		extable							      \
		"	.set	mips0					\n"   \
		: "=&r" (temp), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		long temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	"MIPS_ISA_LEVEL"			\n"   \
		"1:	lld	%0, %1		# atomic64_" #op #suffix "\n" \
		"2:	" #asm_op " %0, %2				\n"   \
		"	scd	%0, %1					\n"   \
		"	beqz	%0, 1b					\n"   \
			extable						      \
		"	.set	mips0					\n"   \
		: "=&r" (temp), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		__asm__ __volatile__(					      \
		"2:	" #asm_op " %0, %1				\n"   \
		extable							      \
		: "+" GCC_OFF_SMALL_ASM() (v->counter) : "Ir" (i));	      \
		raw_local_irq_restore(flags);				      \
	}								      \
}

#define ATOMIC64_OP(op, asm_op) __ATOMIC64_OP(op, _unchecked, asm_op##u, )    \
				__ATOMIC64_OP(op, , asm_op, __OVERFLOW_EXTABLE)

#define __ATOMIC64_OP_RETURN(op, suffix, asm_op, post_op, extable)	      \
static inline long atomic64_##op##_return##suffix##_relaxed(long i, atomic64##suffix##_t * v)\
{									      \
	long result;							      \
									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		long temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	mips3					\n"   \
		"1:	lld	%1, %2		# atomic64_" #op "_return\n"  \
		"2:	" #asm_op " %0, %1, %3				\n"   \
		"	scd	%0, %2					\n"   \
		"	beqzl	%0, 1b					\n"   \
		post_op							      \
		extable							      \
		"4:	" #asm_op " %0, %1, %3				\n"   \
		"5:							\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "+" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		long temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	"MIPS_ISA_LEVEL"			\n"   \
		"1:	lld	%1, %2	# atomic64_" #op "_return" #suffix "\n"\
		"2:	" #asm_op " %0, %1, %3				\n"   \
		"	scd	%0, %2					\n"   \
		"	beqz	%0, 1b					\n"   \
		post_op							      \
		extable							      \
		"4:	" #asm_op " %0, %1, %3				\n"   \
		"5:							\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "=" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i), GCC_OFF_SMALL_ASM() (v->counter)		      \
		: "memory");						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		__asm__ __volatile__(					      \
		"	ld	%0, %1					\n"   \
		"2:	" #asm_op " %0, %1, %2				\n"   \
		"	sd	%0, %1					\n"   \
		"3:							\n"   \
		extable							      \
		: "=&r" (result), "+" GCC_OFF_SMALL_ASM() (v->counter)	      \
		: "Ir" (i));						      \
		raw_local_irq_restore(flags);				      \
	}								      \
									      \
	return result;							      \
}

#define ATOMIC64_OP_RETURN(op, asm_op) __ATOMIC64_OP_RETURN(op, _unchecked, asm_op##u, , )	\
				       __ATOMIC64_OP_RETURN(op, , asm_op, __OVERFLOW_POST, __OVERFLOW_EXTABLE)

#define ATOMIC64_FETCH_OP(op, c_op, asm_op)				      \
static __inline__ long atomic64_fetch_##op##_relaxed(long i, atomic64_t * v)  \
{									      \
	long result;							      \
									      \
	if (kernel_uses_llsc && R10000_LLSC_WAR) {			      \
		long temp;						      \
									      \
		__asm__ __volatile__(					      \
		"	.set	arch=r4000				\n"   \
		"1:	lld	%1, %2		# atomic64_fetch_" #op "\n"   \
		"	" #asm_op " %0, %1, %3				\n"   \
		"	scd	%0, %2					\n"   \
		"	beqzl	%0, 1b					\n"   \
		"	move	%0, %1					\n"   \
		"	.set	mips0					\n"   \
		: "=&r" (result), "=&r" (temp),				      \
		  "+" GCC_OFF_SMALL_ASM() (v->counter)			      \
		: "Ir" (i));						      \
	} else if (kernel_uses_llsc) {					      \
		long temp;						      \
									      \
		do {							      \
			__asm__ __volatile__(				      \
			"	.set	"MIPS_ISA_LEVEL"		\n"   \
			"	lld	%1, %2	# atomic64_fetch_" #op "\n"   \
			"	" #asm_op " %0, %1, %3			\n"   \
			"	scd	%0, %2				\n"   \
			"	.set	mips0				\n"   \
			: "=&r" (result), "=&r" (temp),			      \
			  "=" GCC_OFF_SMALL_ASM() (v->counter)		      \
			: "Ir" (i), GCC_OFF_SMALL_ASM() (v->counter)	      \
			: "memory");					      \
		} while (unlikely(!result));				      \
									      \
		result = temp;						      \
	} else {							      \
		unsigned long flags;					      \
									      \
		raw_local_irq_save(flags);				      \
		result = v->counter;					      \
		v->counter c_op i;					      \
		raw_local_irq_restore(flags);				      \
	}								      \
									      \
	return result;							      \
}

#define ATOMIC64_OPS(op, asm_op)					      \
	ATOMIC64_OP(op, asm_op)					      \
	ATOMIC64_OP_RETURN(op, asm_op)				      \
	ATOMIC64_FETCH_OP(op, asm_op)

ATOMIC64_OPS(add, daddu)
ATOMIC64_OPS(sub, dsubu)

#define atomic64_add_return_relaxed	atomic64_add_return_relaxed
#define atomic64_sub_return_relaxed	atomic64_sub_return_relaxed
#define atomic64_fetch_add_relaxed	atomic64_fetch_add_relaxed
#define atomic64_fetch_sub_relaxed	atomic64_fetch_sub_relaxed

#undef ATOMIC64_OPS
#define ATOMIC64_OPS(op, asm_op)					      \
	ATOMIC64_OP(op, asm_op)					      \
	ATOMIC64_FETCH_OP(op, asm_op)

ATOMIC64_OPS(and, and)
ATOMIC64_OPS(or, or)
ATOMIC64_OPS(xor, xor)

#define atomic64_fetch_and_relaxed	atomic64_fetch_and_relaxed
#define atomic64_fetch_or_relaxed	atomic64_fetch_or_relaxed
#define atomic64_fetch_xor_relaxed	atomic64_fetch_xor_relaxed

#undef ATOMIC64_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef __ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef __ATOMIC64_OP
#undef __OVERFLOW_EXTABLE
#undef __OVERFLOW_POST

/*
 * atomic64_sub_if_positive - conditionally subtract integer from atomic
 *                            variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ long atomic64_sub_if_positive(long i, atomic64_t *v)
{
	long result;

	smp_mb__before_llsc();

	if (kernel_uses_llsc && R10000_LLSC_WAR) {
		long temp;

		__asm__ __volatile__(
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqzl	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp),
		  "=" GCC_OFF_SMALL_ASM() (v->counter)
		: "Ir" (i), GCC_OFF_SMALL_ASM() (v->counter)
		: "memory");
	} else if (kernel_uses_llsc) {
		long temp;

		__asm__ __volatile__(
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"1:	lld	%1, %2		# atomic64_sub_if_positive\n"
		"	dsubu	%0, %1, %3				\n"
		"	bltz	%0, 1f					\n"
		"	scd	%0, %2					\n"
		"	.set	noreorder				\n"
		"	beqz	%0, 1b					\n"
		"	 dsubu	%0, %1, %3				\n"
		"	.set	reorder					\n"
		"1:							\n"
		"	.set	mips0					\n"
		: "=&r" (result), "=&r" (temp),
		  "+" GCC_OFF_SMALL_ASM() (v->counter)
		: "Ir" (i));
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		result = v->counter;
		result -= i;
		if (result >= 0)
			v->counter = result;
		raw_local_irq_restore(flags);
	}

	smp_llsc_mb();

	return result;
}

static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return cmpxchg(&v->counter, old, new);
}

static inline long atomic64_cmpxchg_unchecked(atomic64_unchecked_t *v, long old,
					      long new)
{
	return cmpxchg(&(v->counter), old, new);
}

static inline long atomic64_xchg(atomic64_t *v, long new)
{
	return xchg(&v->counter, new);
}

static inline long atomic64_xchg_unchecked(atomic64_unchecked_t *v, long new)
{
	return xchg(&(v->counter), new);
}

/**
 * atomic64_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns true iff @v was not @u.
 */
static __inline__ int atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic64_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

#define atomic64_dec_return(v) atomic64_sub_return(1, (v))
#define atomic64_inc_return(v) atomic64_add_return(1, (v))
#define atomic64_inc_return_unchecked(v) atomic64_add_return_unchecked(1, (v))

/*
 * atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_sub_and_test(i, v) (atomic64_sub_return((i), (v)) == 0)

/*
 * atomic64_inc_and_test - increment and test
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)
#define atomic64_inc_and_test_unchecked(v) atomic64_add_return_unchecked(1, (v)) == 0)

/*
 * atomic64_dec_and_test - decrement by 1 and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
#define atomic64_dec_and_test(v) (atomic64_sub_return(1, (v)) == 0)

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic64_t
 */
#define atomic64_dec_if_positive(v)	atomic64_sub_if_positive(1, v)

/*
 * atomic64_inc - increment atomic variable
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1.
 */
#define atomic64_inc(v) atomic64_add(1, (v))
#define atomic64_inc_unchecked(v) atomic64_add_unchecked(1, (v))

/*
 * atomic64_dec - decrement and test
 * @v: pointer of type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
#define atomic64_dec(v) atomic64_sub(1, (v))
#define atomic64_dec_unchecked(v) atomic64_sub_unchecked(1, (v))

/*
 * atomic64_add_negative - add and test if negative
 * @v: pointer of type atomic64_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
#define atomic64_add_negative(i, v) (atomic64_add_return(i, (v)) < 0)

#endif /* CONFIG_64BIT */

#endif /* _ASM_ATOMIC_H */
