	.text
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/smap.h>

# Copyright 2003, 2008 Pavel Machek <pavel@suse.cz>, distribute under GPLv2

	.code32
	ALIGN

ENTRY(wakeup_pmode_return)
wakeup_pmode_return:
	movw	$__KERNEL_DS, %ax
	movw	%ax, %ss
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ds
	movw	%ax, %es

	# reload the gdt, as we need the full 32 bit address
	lidt	saved_idt
	lldt	saved_ldt
	ljmp	$(__KERNEL_CS), $1f
1:
	movl	%cr3, %eax
	movl	%eax, %cr3
	wbinvd

	# and restore the stack ... but you need gdt for this to work
	movl	saved_context_esp, %esp

	cmpl	$0x12345678, saved_magic
	jne	bogus_magic

	# jump to place where we left off
	jmp	*(saved_eip)

bogus_magic:
	jmp	bogus_magic



save_registers:
	sidt	saved_idt
	sldt	saved_ldt
	str	saved_tss

	leal	4(%esp), %eax
	movl	%eax, saved_context_esp
	movl	%ebx, saved_context_ebx
	movl	%ebp, saved_context_ebp
	movl	%esi, saved_context_esi
	movl	%edi, saved_context_edi
	pushfl
	popl	saved_context_eflags

	movl	$ret_point, saved_eip
	pax_ret save_registers


restore_registers:
	movl	saved_context_ebp, %ebp
	movl	saved_context_ebx, %ebx
	movl	saved_context_esi, %esi
	movl	saved_context_edi, %edi
	pushl	saved_context_eflags
	popfl
	ASM_CLAC
	pax_ret restore_registers

ENTRY(do_suspend_lowlevel)
	pax_direct_call save_processor_state
	pax_direct_call save_registers
	pushl	$3
	pax_direct_call x86_acpi_enter_sleep_state
	addl	$4, %esp

#	In case of S3 failure, we'll emerge here.  Jump
# 	to ret_point to recover
	jmp	ret_point
	.p2align 4,,7
ret_point:
	pax_direct_call restore_registers
	pax_direct_call restore_processor_state
	pax_ret do_suspend_lowlevel

.data
ALIGN
ENTRY(saved_magic)	.long	0
ENTRY(saved_eip)	.long	0

# saved registers
saved_idt:	.long	0,0
saved_ldt:	.long	0
saved_tss:	.long	0

