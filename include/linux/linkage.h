#ifndef _LINUX_LINKAGE_H
#define _LINUX_LINKAGE_H

#include <linux/compiler.h>
#include <linux/stringify.h>
#include <linux/export.h>
#include <asm/linkage.h>
#include <asm/bitsperlong.h>

/* Some toolchains use other characters (e.g. '`') to mark new line in macro */
#ifndef ASM_NL
#define ASM_NL		 ;
#endif

#ifdef __cplusplus
#define CPP_ASMLINKAGE extern "C"
#else
#define CPP_ASMLINKAGE
#endif

#ifndef asmlinkage
#define asmlinkage CPP_ASMLINKAGE
#endif

#ifndef cond_syscall
# ifdef CONFIG_PAX_RAP
#  define rap_cond_syscall(x)				\
	".weak " VMLINUX_SYMBOL_STR(rap_##x) "\n\t"	\
	".set  " VMLINUX_SYMBOL_STR(rap_##x) ","	\
		 VMLINUX_SYMBOL_STR(rap_sys_ni_syscall) "\n\t"
# else
#  define rap_cond_syscall(x)
# endif
#define cond_syscall(x)	asm(				\
	rap_cond_syscall(x)				\
	".weak " VMLINUX_SYMBOL_STR(x) "\n\t"		\
	".set  " VMLINUX_SYMBOL_STR(x) ","		\
		 VMLINUX_SYMBOL_STR(sys_ni_syscall))
#endif

#ifndef SYSCALL_ALIAS
#define SYSCALL_ALIAS(alias, name) asm(			\
	".globl " VMLINUX_SYMBOL_STR(alias) "\n\t"	\
	".set   " VMLINUX_SYMBOL_STR(alias) ","		\
		  VMLINUX_SYMBOL_STR(name))
#endif

#define __page_aligned_data	__section(.data..page_aligned) __aligned(PAGE_SIZE)
#define __page_aligned_rodata	__read_only __aligned(PAGE_SIZE)
#define __page_aligned_bss	__section(.bss..page_aligned) __aligned(PAGE_SIZE)

/*
 * For assembly routines.
 *
 * Note when using these that you must specify the appropriate
 * alignment directives yourself
 */
#define __PAGE_ALIGNED_DATA	.section ".data..page_aligned", "aw"
#define __PAGE_ALIGNED_BSS	.section ".bss..page_aligned", "aw"

/*
 * This is used by architectures to keep arguments on the stack
 * untouched by the compiler by keeping them live until the end.
 * The argument stack may be owned by the assembly-language
 * caller, not the callee, and gcc doesn't always understand
 * that.
 *
 * We have the return value, and a maximum of six arguments.
 *
 * This should always be followed by a "return ret" for the
 * protection to work (ie no more work that the compiler might
 * end up needing stack temporaries for).
 */
/* Assembly files may be compiled with -traditional .. */
#ifndef __ASSEMBLY__
#ifndef asmlinkage_protect
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
#endif
#endif

#ifndef __ALIGN
#define __ALIGN		.align 4,0x90
#define __ALIGN_STR	".align 4,0x90"
#endif

#ifdef CONFIG_PAX_RAP
# if BITS_PER_LONG == 64
#  define __ASM_RAP_HASH(hash) .quad 0, hash
#  define __ASM_RAP_RET_HASH(hash) .quad hash
# elif BITS_PER_LONG == 32
#  define __ASM_RAP_HASH(hash) .long 0, hash
#  define __ASM_RAP_RET_HASH(hash) .long hash
# else
#  error incompatible BITS_PER_LONG
# endif
#endif

#ifdef __ASSEMBLY__

#ifndef LINKER_SCRIPT
#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR

#ifndef ENTRY
#define __ENTRY(name, rap_hash) \
	.globl name ASM_NL \
	ALIGN ASM_NL \
	rap_hash \
	name:

#define ENTRY(name) __ENTRY(name,)

#endif

#endif /* LINKER_SCRIPT */

#ifndef WEAK
#define __WEAK(name, rap_hash) \
	.weak name ASM_NL \
	rap_hash \
	name:

#define WEAK(name) __WEAK(name, )
#endif

#ifdef CONFIG_PAX_RAP
# define RAP_ENTRY(name) __ENTRY(name, __ASM_RAP_HASH(__rap_hash_call_##name) ASM_NL)
# define RAP_WEAK(name) __WEAK(name, __ASM_RAP_HASH(__rap_hash_call_##name) ASM_NL)
#else
# define RAP_ENTRY(name) ENTRY(name)
# define RAP_WEAK(name) WEAK(name)
#endif

#ifndef END
#define END(name) \
	.size name, .-name
#endif

/* If symbol 'name' is treated as a subroutine (gets called, and returns)
 * then please use ENDPROC to mark 'name' as STT_FUNC for the benefit of
 * static analysis tools such as stack depth analyzer.
 */
#ifndef ENDPROC
#define ENDPROC(name) \
	.type name, @function ASM_NL \
	END(name)
#endif

#endif

#endif
