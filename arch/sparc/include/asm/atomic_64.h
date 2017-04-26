/* atomic.h: Thankfully the V9 is at least reasonable for this
 *           stuff.
 *
 * Copyright (C) 1996, 1997, 2000, 2012 David S. Miller (davem@redhat.com)
 */

#ifndef __ARCH_SPARC64_ATOMIC__
#define __ARCH_SPARC64_ATOMIC__

#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/barrier.h>

#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define atomic_read(v)		READ_ONCE((v)->counter)
static inline int atomic_read_unchecked(const atomic_unchecked_t *v)
{
	return READ_ONCE(v->counter);
}
#define atomic64_read(v)	READ_ONCE((v)->counter)
static inline long atomic64_read_unchecked(const atomic64_unchecked_t *v)
{
	return READ_ONCE(v->counter);
}

#define atomic_set(v, i)	WRITE_ONCE(((v)->counter), (i))
static inline void atomic_set_unchecked(atomic_unchecked_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}
#define atomic64_set(v, i)	WRITE_ONCE(((v)->counter), (i))
static inline void atomic64_set_unchecked(atomic64_unchecked_t *v, long i)
{
	WRITE_ONCE(v->counter, i);
}

#define __ATOMIC_OP(op, suffix)						\
void atomic_##op##suffix(int, atomic##suffix##_t *);			\
void atomic64_##op##suffix(long, atomic64##suffix##_t *);

#define ATOMIC_OP(op) __ATOMIC_OP(op, ) __ATOMIC_OP(op, _unchecked)

#define __ATOMIC_OP_RETURN(op, suffix)					\
int atomic_##op##_return##suffix(int, atomic##suffix##_t *);		\
long atomic64_##op##_return##suffix(long, atomic64##suffix##_t *);

#define ATOMIC_OP_RETURN(op) __ATOMIC_OP_RETURN(op, ) __ATOMIC_OP_RETURN(op, _unchecked)

#define ATOMIC_FETCH_OP(op)						\
int atomic_fetch_##op(int, atomic_t *);					\
long atomic64_fetch_##op(long, atomic64_t *);

#define ATOMIC_OPS(op) ATOMIC_OP(op) ATOMIC_OP_RETURN(op) ATOMIC_FETCH_OP(op)

ATOMIC_OPS(add)
ATOMIC_OPS(sub)

#undef ATOMIC_OPS
#define ATOMIC_OPS(op) ATOMIC_OP(op) ATOMIC_FETCH_OP(op)

ATOMIC_OPS(and)
ATOMIC_OPS(or)
ATOMIC_OPS(xor)

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef __ATOMIC_OP_RETURN
#undef ATOMIC_OP
#undef __ATOMIC_OP

#define atomic_dec_return(v)   atomic_sub_return(1, v)
#define atomic64_dec_return(v) atomic64_sub_return(1, v)

#define atomic_inc_return(v)   atomic_add_return(1, v)
static inline int atomic_inc_return_unchecked(atomic_unchecked_t *v)
{
	return atomic_add_return_unchecked(1, v);
}
#define atomic64_inc_return(v) atomic64_add_return(1, v)
static inline long atomic64_inc_return_unchecked(atomic64_unchecked_t *v)
{
	return atomic64_add_return_unchecked(1, v);
}

/*
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
static inline int atomic_inc_and_test_unchecked(atomic_unchecked_t *v)
{
	return atomic_inc_return_unchecked(v) == 0;
}
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)

#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)
#define atomic64_sub_and_test(i, v) (atomic64_sub_return(i, v) == 0)

#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)
#define atomic64_dec_and_test(v) (atomic64_sub_return(1, v) == 0)

#define atomic_inc(v) atomic_add(1, v)
static inline void atomic_inc_unchecked(atomic_unchecked_t *v)
{
	atomic_add_unchecked(1, v);
}
#define atomic64_inc(v) atomic64_add(1, v)
static inline void atomic64_inc_unchecked(atomic64_unchecked_t *v)
{
	atomic64_add_unchecked(1, v);
}

#define atomic_dec(v) atomic_sub(1, v)
static inline void atomic_dec_unchecked(atomic_unchecked_t *v)
{
	atomic_sub_unchecked(1, v);
}
#define atomic64_dec(v) atomic64_sub(1, v)
static inline void atomic64_dec_unchecked(atomic64_unchecked_t *v)
{
	atomic64_sub_unchecked(1, v);
}

#define atomic_add_negative(i, v) (atomic_add_return(i, v) < 0)
#define atomic64_add_negative(i, v) (atomic64_add_return(i, v) < 0)

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
static inline int atomic_cmpxchg_unchecked(atomic_unchecked_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))
static inline int atomic_xchg_unchecked(atomic_unchecked_t *v, int new)
{
	return xchg(&v->counter, new);
}

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old, new;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addcc %2, %0, %0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "tvs %%icc, 6\n"
#endif

			     : "=r" (new)
			     : "0" (c), "ir" (a)
			     : "cc");

		old = atomic_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c;
}

#define atomic64_cmpxchg(v, o, n) \
	((__typeof__((v)->counter))cmpxchg(&((v)->counter), (o), (n)))
static inline long atomic64_cmpxchg_unchecked(atomic64_unchecked_t *v, long old,
					      long new)
{
	return cmpxchg(&(v->counter), old, new);
}

#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))
static inline long atomic64_xchg_unchecked(atomic64_unchecked_t *v, long new)
{
	return xchg(&v->counter, new);
}

static inline long atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old, new;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == u))
			break;

		asm volatile("addcc %2, %0, %0\n"

#ifdef CONFIG_PAX_REFCOUNT
			     "tvs %%xcc, 6\n"
#endif

			     : "=r" (new)
			     : "0" (c), "ir" (a)
			     : "cc");

		old = atomic64_cmpxchg(v, c, new);
		if (likely(old == c))
			break;
		c = old;
	}
	return c != u;
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

long atomic64_dec_if_positive(atomic64_t *v);

#endif /* !(__ARCH_SPARC64_ATOMIC__) */
