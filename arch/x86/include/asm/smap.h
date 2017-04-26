/*
 * Supervisor Mode Access Prevention support
 *
 * Copyright (C) 2012 Intel Corporation
 * Author: H. Peter Anvin <hpa@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _ASM_X86_SMAP_H
#define _ASM_X86_SMAP_H

#include <linux/stringify.h>
#include <asm/nops.h>
#include <asm/cpufeatures.h>

/* "Raw" instruction opcodes */
#define __ASM_CLAC	.byte 0x0f,0x01,0xca
#define __ASM_STAC	.byte 0x0f,0x01,0xcb

#ifdef __ASSEMBLY__

#include <asm/alternative-asm.h>

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define ASM_PAX_OPEN_USERLAND					\
	ALTERNATIVE "", "pax_direct_call __pax_open_userland", X86_FEATURE_STRONGUDEREF

#define ASM_PAX_CLOSE_USERLAND					\
	ALTERNATIVE "", "pax_direct_call __pax_close_userland", X86_FEATURE_STRONGUDEREF

#else
#define ASM_PAX_OPEN_USERLAND
#define ASM_PAX_CLOSE_USERLAND
#endif

#ifdef CONFIG_X86_SMAP

#define ASM_CLAC \
	ALTERNATIVE "", __stringify(__ASM_CLAC), X86_FEATURE_SMAP

#define ASM_STAC \
	ALTERNATIVE "", __stringify(__ASM_STAC), X86_FEATURE_SMAP

#else /* CONFIG_X86_SMAP */

#define ASM_CLAC
#define ASM_STAC

#endif /* CONFIG_X86_SMAP */

#define ASM_USER_ACCESS_BEGIN	ASM_PAX_OPEN_USERLAND; ASM_STAC
#define ASM_USER_ACCESS_END	ASM_CLAC; ASM_PAX_CLOSE_USERLAND

#else /* __ASSEMBLY__ */

#include <asm/alternative.h>

#define __HAVE_ARCH_PAX_OPEN_USERLAND
#define __HAVE_ARCH_PAX_CLOSE_USERLAND

extern void __pax_open_userland(void);
static __always_inline unsigned long pax_open_userland(void)
{

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	asm volatile(ALTERNATIVE("", PAX_DIRECT_CALL("%P[open]"), X86_FEATURE_STRONGUDEREF)
		:
		: [open] "i" (__pax_open_userland)
		: "memory", "rax");
#endif

	return 0;
}

extern void __pax_close_userland(void);
static __always_inline unsigned long pax_close_userland(void)
{

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
	asm volatile(ALTERNATIVE("", PAX_DIRECT_CALL("%P[close]"), X86_FEATURE_STRONGUDEREF)
		:
		: [close] "i" (__pax_close_userland)
		: "memory", "rax");
#endif

	return 0;
}

#ifdef CONFIG_X86_SMAP

static __always_inline void clac(void)
{
	/* Note: a barrier is implicit in alternative() */
	alternative("", __stringify(__ASM_CLAC), X86_FEATURE_SMAP);
}

static __always_inline void stac(void)
{
	/* Note: a barrier is implicit in alternative() */
	alternative("", __stringify(__ASM_STAC), X86_FEATURE_SMAP);
}

/* These macros can be used in asm() statements */
#define ASM_CLAC \
	ALTERNATIVE("", __stringify(__ASM_CLAC), X86_FEATURE_SMAP)
#define ASM_STAC \
	ALTERNATIVE("", __stringify(__ASM_STAC), X86_FEATURE_SMAP)

#else /* CONFIG_X86_SMAP */

static inline void clac(void) { }
static inline void stac(void) { }

#define ASM_CLAC
#define ASM_STAC

#endif /* CONFIG_X86_SMAP */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_SMAP_H */
