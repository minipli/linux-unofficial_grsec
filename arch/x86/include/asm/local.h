#ifndef _ASM_X86_LOCAL_H
#define _ASM_X86_LOCAL_H

#include <linux/percpu.h>

#include <linux/atomic.h>
#include <asm/asm.h>

typedef struct {
	atomic_long_t a;
} local_t;

typedef struct {
	atomic_long_unchecked_t a;
} local_unchecked_t;

#define LOCAL_INIT(i)	{ ATOMIC_LONG_INIT(i) }

#define local_read(l)	atomic_long_read(&(l)->a)
#define local_read_unchecked(l)	atomic_long_read_unchecked(&(l)->a)
#define local_set(l, i)	atomic_long_set(&(l)->a, (i))
#define local_set_unchecked(l, i)	atomic_long_set_unchecked(&(l)->a, (i))

static inline void local_inc(local_t *l)
{
	asm volatile(_ASM_INC "%0\n\t"
		     PAX_REFCOUNT_OVERFLOW(BITS_PER_LONG/8)
		     : [counter] "+m" (l->a.counter)
		     : : "cc", "cx");
}

static inline void local_inc_unchecked(local_unchecked_t *l)
{
	asm volatile(_ASM_INC "%0\n"
		     : "+m" (l->a.counter));
}

static inline void local_dec(local_t *l)
{
	asm volatile(_ASM_DEC "%0\n\t"
		     PAX_REFCOUNT_UNDERFLOW(BITS_PER_LONG/8)
		     : [counter] "+m" (l->a.counter)
		     : : "cc", "cx");
}

static inline void local_dec_unchecked(local_unchecked_t *l)
{
	asm volatile(_ASM_DEC "%0\n"
		     : "+m" (l->a.counter));
}

static inline void local_add(long i, local_t *l)
{
	asm volatile(_ASM_ADD "%1,%0\n\t"
		     PAX_REFCOUNT_OVERFLOW(BITS_PER_LONG/8)
		     : [counter] "+m" (l->a.counter)
		     : "ir" (i)
		     : "cc", "cx");
}

static inline void local_add_unchecked(long i, local_unchecked_t *l)
{
	asm volatile(_ASM_ADD "%1,%0\n"
		     : "+m" (l->a.counter)
		     : "ir" (i));
}

static inline void local_sub(long i, local_t *l)
{
	asm volatile(_ASM_SUB "%1,%0\n\t"
		     PAX_REFCOUNT_UNDERFLOW(BITS_PER_LONG/8)
		     : [counter] "+m" (l->a.counter)
		     : "ir" (i)
		     : "cc", "cx");
}

static inline void local_sub_unchecked(long i, local_unchecked_t *l)
{
	asm volatile(_ASM_SUB "%1,%0\n"
		     : "+m" (l->a.counter)
		     : "ir" (i));
}

/**
 * local_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @l: pointer to type local_t
 *
 * Atomically subtracts @i from @l and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline bool local_sub_and_test(long i, local_t *l)
{
	GEN_BINARY_RMWcc(_ASM_SUB, l->a.counter, -BITS_PER_LONG/8, "er", i, "%0", e);
}

/**
 * local_dec_and_test - decrement and test
 * @l: pointer to type local_t
 *
 * Atomically decrements @l by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline bool local_dec_and_test(local_t *l)
{
	GEN_UNARY_RMWcc(_ASM_DEC, l->a.counter, -BITS_PER_LONG/8, "%0", e);
}

/**
 * local_inc_and_test - increment and test
 * @l: pointer to type local_t
 *
 * Atomically increments @l by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static inline bool local_inc_and_test(local_t *l)
{
	GEN_UNARY_RMWcc(_ASM_INC, l->a.counter, BITS_PER_LONG/8, "%0", e);
}

/**
 * local_add_negative - add and test if negative
 * @i: integer value to add
 * @l: pointer to type local_t
 *
 * Atomically adds @i to @l and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
static inline bool local_add_negative(long i, local_t *l)
{
	GEN_BINARY_RMWcc(_ASM_ADD, l->a.counter, BITS_PER_LONG/8, "er", i, "%0", s);
}

/**
 * local_add_return - add and return
 * @i: integer value to add
 * @l: pointer to type local_t
 *
 * Atomically adds @i to @l and returns @i + @l
 */
static inline long local_add_return(long i, local_t *l)
{
	long __i = i;
	asm volatile(_ASM_XADD "%0, %1\n\t"
		     PAX_REFCOUNT_OVERFLOW(BITS_PER_LONG/8)
		     : "+r" (i), [counter] "+m" (l->a.counter)
		     : : "memory", "cc", "cx");
	return i + __i;
}

/**
 * local_add_return_unchecked - add and return
 * @i: integer value to add
 * @l: pointer to type local_unchecked_t
 *
 * Atomically adds @i to @l and returns @i + @l
 */
static inline long local_add_return_unchecked(long i, local_unchecked_t *l)
{
	long __i = i;
	asm volatile(_ASM_XADD "%0, %1;"
		     : "+r" (i), "+m" (l->a.counter)
		     : : "memory");
	return i + __i;
}

static inline long local_sub_return(long i, local_t *l)
{
	return local_add_return(-i, l);
}

#define local_inc_return(l)  (local_add_return(1, l))
#define local_dec_return(l)  (local_sub_return(1, l))

#define local_cmpxchg(l, o, n) \
	(cmpxchg_local(&((l)->a.counter), (o), (n)))
#define local_cmpxchg_unchecked(l, o, n) \
	(cmpxchg_local(&((l)->a.counter), (o), (n)))
/* Always has a lock prefix */
#define local_xchg(l, n) (xchg(&((l)->a.counter), (n)))

/**
 * local_add_unless - add unless the number is a given value
 * @l: pointer of type local_t
 * @a: the amount to add to l...
 * @u: ...unless l is equal to u.
 *
 * Atomically adds @a to @l, so long as it was not @u.
 * Returns non-zero if @l was not @u, and zero otherwise.
 */
#define local_add_unless(l, a, u)				\
({								\
	long c, old;						\
	c = local_read((l));					\
	for (;;) {						\
		if (unlikely(c == (u)))				\
			break;					\
		old = local_cmpxchg((l), c, c + (a));		\
		if (likely(old == c))				\
			break;					\
		c = old;					\
	}							\
	c != (u);						\
})
#define local_inc_not_zero(l) local_add_unless((l), 1, 0)

/* On x86_32, these are no better than the atomic variants.
 * On x86-64 these are better than the atomic variants on SMP kernels
 * because they dont use a lock prefix.
 */
#define __local_inc(l)		local_inc(l)
#define __local_dec(l)		local_dec(l)
#define __local_add(i, l)	local_add((i), (l))
#define __local_sub(i, l)	local_sub((i), (l))

#endif /* _ASM_X86_LOCAL_H */
