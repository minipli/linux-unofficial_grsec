/* atomic.S: These things are too big to do inline.
 *
 * Copyright (C) 1999, 2007 2012 David S. Miller (davem@davemloft.net)
 */

#include <linux/linkage.h>
#include <asm/asi.h>
#include <asm/backoff.h>
#include <asm/export.h>

	.text

	/* Three versions of the atomic routines, one that
	 * does not return a value and does not perform
	 * memory barriers, and a two which return
	 * a value, the new and old value resp. and does the
	 * barriers.
	 */

#ifdef CONFIG_PAX_REFCOUNT
#define __REFCOUNT_OP(op) op##cc
#define __OVERFLOW_IOP tvs	%icc, 6;
#define __OVERFLOW_XOP tvs	%xcc, 6;
#else
#define __REFCOUNT_OP(op) op
#define __OVERFLOW_IOP
#define __OVERFLOW_XOP
#endif

#define __ATOMIC_OP(op, suffix, asm_op, post_op)			\
ENTRY(atomic_##op##suffix) /* %o0 = increment, %o1 = atomic_ptr */	\
	BACKOFF_SETUP(%o2);						\
1:	lduw	[%o1], %g1;						\
	asm_op	%g1, %o0, %g7;						\
	post_op								\
	cas	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%icc, BACKOFF_LABEL(2f, 1b);				\
	 nop;								\
	retl;								\
	 nop;								\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic_##op##suffix);						\
EXPORT_SYMBOL(atomic_##op##suffix);

#define ATOMIC_OP(op) __ATOMIC_OP(op, , op, ) \
		      __ATOMIC_OP(op, _unchecked, __REFCOUNT_OP(op), __OVERFLOW_IOP)

#define __ATOMIC_OP_RETURN(op, suffix, asm_op, post_op)			\
ENTRY(atomic_##op##_return##suffix) /* %o0 = increment, %o1 = atomic_ptr */\
	BACKOFF_SETUP(%o2);						\
1:	lduw	[%o1], %g1;						\
	asm_op	%g1, %o0, %g7;						\
	post_op								\
	cas	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%icc, BACKOFF_LABEL(2f, 1b);				\
	 op	%g1, %o0, %g1;						\
	retl;								\
	 sra	%g1, 0, %o0;						\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic_##op##_return##suffix);					\
EXPORT_SYMBOL(atomic_##op##_return##suffix)

#define ATOMIC_OP_RETURN(op) __ATOMIC_OP_RETURN(op, , op, ) \
			     __ATOMIC_OP_RETURN(op, _unchecked, __REFCOUNT_OP(op), __OVERFLOW_IOP)

#define ATOMIC_FETCH_OP(op)						\
ENTRY(atomic_fetch_##op) /* %o0 = increment, %o1 = atomic_ptr */	\
	BACKOFF_SETUP(%o2);						\
1:	lduw	[%o1], %g1;						\
	op	%g1, %o0, %g7;						\
	cas	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%icc, BACKOFF_LABEL(2f, 1b);				\
	 nop;								\
	retl;								\
	 sra	%g1, 0, %o0;						\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic_fetch_##op);						\
EXPORT_SYMBOL(atomic_fetch_##op);

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

#define __ATOMIC64_OP(op, suffix, asm_op, post_op)			\
ENTRY(atomic64_##op##suffix) /* %o0 = increment, %o1 = atomic_ptr */	\
	BACKOFF_SETUP(%o2);						\
1:	ldx	[%o1], %g1;						\
	asm_op	%g1, %o0, %g7;						\
	post_op								\
	casx	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b);				\
	 nop;								\
	retl;								\
	 nop;								\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic64_##op##suffix);						\
EXPORT_SYMBOL(atomic64_##op##suffix);

#define ATOMIC64_OP(op) __ATOMIC64_OP(op, , op, ) \
			__ATOMIC64_OP(op, _unchecked, __REFCOUNT_OP(op), __OVERFLOW_XOP)

#define __ATOMIC64_OP_RETURN(op, suffix, asm_op, post_op)		\
ENTRY(atomic64_##op##_return##suffix) /* %o0 = increment, %o1 = atomic_ptr */\
	BACKOFF_SETUP(%o2);						\
1:	ldx	[%o1], %g1;						\
	asm_op	%g1, %o0, %g7;						\
	post_op								\
	casx	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b);				\
	 nop;								\
	retl;								\
	 op	%g1, %o0, %o0;						\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic64_##op##_return##suffix);				\
EXPORT_SYMBOL(atomic64_##op##_return##suffix);

#define ATOMIC64_OP_RETURN(op) __ATOMIC64_OP_RETURN(op, , op, ) \
			       __ATOMIC64_OP_RETURN(op, _unchecked, __REFCOUNT_OP(op), __OVERFLOW_XOP)

#define ATOMIC64_FETCH_OP(op)						\
ENTRY(atomic64_fetch_##op) /* %o0 = increment, %o1 = atomic_ptr */	\
	BACKOFF_SETUP(%o2);						\
1:	ldx	[%o1], %g1;						\
	op	%g1, %o0, %g7;						\
	casx	[%o1], %g1, %g7;					\
	cmp	%g1, %g7;						\
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b);				\
	 nop;								\
	retl;								\
	 mov	%g1, %o0;						\
2:	BACKOFF_SPIN(%o2, %o3, 1b);					\
ENDPROC(atomic64_fetch_##op);						\
EXPORT_SYMBOL(atomic64_fetch_##op);

#define ATOMIC64_OPS(op) ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)

ATOMIC64_OPS(add)
ATOMIC64_OPS(sub)

#undef ATOMIC64_OPS
#define ATOMIC64_OPS(op) ATOMIC64_OP(op) ATOMIC64_FETCH_OP(op)

ATOMIC64_OPS(and)
ATOMIC64_OPS(or)
ATOMIC64_OPS(xor)

#undef ATOMIC64_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef __ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef __ATOMIC64_OP
#undef __OVERFLOW_XOP
#undef __OVERFLOW_IOP
#undef __REFCOUNT_OP

ENTRY(atomic64_dec_if_positive) /* %o0 = atomic_ptr */
	BACKOFF_SETUP(%o2)
1:	ldx	[%o0], %g1
	brlez,pn %g1, 3f
	 sub	%g1, 1, %g7
	casx	[%o0], %g1, %g7
	cmp	%g1, %g7
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 nop
3:	retl
	 sub	%g1, 1, %o0
2:	BACKOFF_SPIN(%o2, %o3, 1b)
ENDPROC(atomic64_dec_if_positive)
EXPORT_SYMBOL(atomic64_dec_if_positive)
