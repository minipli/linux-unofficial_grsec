/*
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Enhanced CPU detection and feature setting code by Mike Jagdis
 *  and Martin Mares, November 1997.
 */

.text
#include <linux/threads.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/pgtable_types.h>
#include <asm/cache.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
#include <asm/setup.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include <asm/cpufeatures.h>
#include <asm/percpu.h>
#include <asm/nops.h>
#include <asm/bootparam.h>
#include <asm/export.h>
#include <asm/alternative-asm.h>

/* Physical address */
#define pa(X) ((X) - __PAGE_OFFSET)

#ifdef CONFIG_PAX_KERNEXEC
#define ta(X) (X)
#else
#define ta(X) ((X) - __PAGE_OFFSET)
#endif

/*
 * References to members of the new_cpu_data structure.
 */

#define X86		new_cpu_data+CPUINFO_x86
#define X86_VENDOR	new_cpu_data+CPUINFO_x86_vendor
#define X86_MODEL	new_cpu_data+CPUINFO_x86_model
#define X86_MASK	new_cpu_data+CPUINFO_x86_mask
#define X86_HARD_MATH	new_cpu_data+CPUINFO_hard_math
#define X86_CPUID	new_cpu_data+CPUINFO_cpuid_level
#define X86_CAPABILITY	new_cpu_data+CPUINFO_x86_capability
#define X86_VENDOR_ID	new_cpu_data+CPUINFO_x86_vendor_id

/*
 * This is how much memory in addition to the memory covered up to
 * and including _end we need mapped initially.
 * We need:
 *     (KERNEL_IMAGE_SIZE/4096) / 1024 pages (worst case, non PAE)
 *     (KERNEL_IMAGE_SIZE/4096) / 512 + 4 pages (worst case for PAE)
 *
 * Modulo rounding, each megabyte assigned here requires a kilobyte of
 * memory, which is currently unreclaimed.
 *
 * This should be a multiple of a page.
 *
 * KERNEL_IMAGE_SIZE should be greater than pa(_end)
 * and small than max_low_pfn, otherwise will waste some page table entries
 */

#define PAGE_TABLE_SIZE(pages) ((pages) / PTRS_PER_PTE)

/*
 * Number of possible pages in the lowmem region.
 *
 * We shift 2 by 31 instead of 1 by 32 to the left in order to avoid a
 * gas warning about overflowing shift count when gas has been compiled
 * with only a host target support using a 32-bit type for internal
 * representation.
 */
LOWMEM_PAGES = (((2<<31) - __PAGE_OFFSET) >> PAGE_SHIFT)

/* Enough space to fit pagetables for the low memory linear map */
MAPPING_BEYOND_END = PAGE_TABLE_SIZE(LOWMEM_PAGES) << PAGE_SHIFT

/*
 * Worst-case size of the kernel mapping we need to make:
 * a relocatable kernel can live anywhere in lowmem, so we need to be able
 * to map all of lowmem.
 */
KERNEL_PAGES = LOWMEM_PAGES

INIT_MAP_SIZE = PAGE_TABLE_SIZE(KERNEL_PAGES) * PAGE_SIZE
RESERVE_BRK(pagetables, INIT_MAP_SIZE)

/*
 * Real beginning of normal "text" segment
 */
ENTRY(stext)
ENTRY(_stext)

/*
 * 32-bit kernel entrypoint; only used by the boot CPU.  On entry,
 * %esi points to the real-mode code as a 32-bit pointer.
 * CS and DS must be 4 GB flat segments, but we don't depend on
 * any particular GDT layout, because we load our own as soon as we
 * can.
 */
__HEAD

#ifdef CONFIG_PAX_KERNEXEC
	jmp startup_32
/* PaX: fill first page in .text with int3 to catch NULL derefs in kernel mode */
.fill PAGE_SIZE-5,1,0xcc
#endif

ENTRY(startup_32)
	movl pa(initial_stack),%ecx
	
	/* test KEEP_SEGMENTS flag to see if the bootloader is asking
		us to not reload segments */
	testb $KEEP_SEGMENTS, BP_loadflags(%esi)
	jnz 2f

/*
 * Set segments to known values.
 */
	lgdt pa(boot_gdt_descr)
	movl $(__BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
	movl %eax,%ss
2:
	leal -__PAGE_OFFSET(%ecx),%esp

#ifdef CONFIG_SMP
	movl $pa(cpu_gdt_table),%edi
	movl $__per_cpu_load,%eax
	movw %ax,GDT_ENTRY_PERCPU * 8 + 2(%edi)
	rorl $16,%eax
	movb %al,GDT_ENTRY_PERCPU * 8 + 4(%edi)
	movb %ah,GDT_ENTRY_PERCPU * 8 + 7(%edi)
	movl $__per_cpu_end - 1,%eax
	subl $__per_cpu_start,%eax
	cmpl $0x100000,%eax
	jb 1f
	shrl $PAGE_SHIFT,%eax
	orb $0x80,GDT_ENTRY_PERCPU * 8 + 6(%edi)
1:
	movw %ax,GDT_ENTRY_PERCPU * 8 + 0(%edi)
	shrl $16,%eax
	orb %al,GDT_ENTRY_PERCPU * 8 + 6(%edi)
#endif

#ifdef CONFIG_PAX_MEMORY_UDEREF
	movl $NR_CPUS,%ecx
	movl $pa(cpu_gdt_table),%edi
1:
	movl $((((__PAGE_OFFSET-1) & 0xf0000000) >> 12) | 0x00c09700),GDT_ENTRY_KERNEL_DS * 8 + 4(%edi)
	movl $((((__PAGE_OFFSET-1) & 0xf0000000) >> 12) | 0x00c0fb00),GDT_ENTRY_DEFAULT_USER_CS * 8 + 4(%edi)
	movl $((((__PAGE_OFFSET-1) & 0xf0000000) >> 12) | 0x00c0f300),GDT_ENTRY_DEFAULT_USER_DS * 8 + 4(%edi)
	addl $PAGE_SIZE_asm,%edi
	loop 1b
#endif

#ifdef CONFIG_PAX_KERNEXEC
	movl $pa(boot_gdt),%edi
	movl $__LOAD_PHYSICAL_ADDR,%eax
	movw %ax,GDT_ENTRY_BOOT_CS * 8 + 2(%edi)
	rorl $16,%eax
	movb %al,GDT_ENTRY_BOOT_CS * 8 + 4(%edi)
	movb %ah,GDT_ENTRY_BOOT_CS * 8 + 7(%edi)
	rorl $16,%eax

	ljmp $(__BOOT_CS),$1f
1:

	movl $NR_CPUS,%ecx
	movl $pa(cpu_gdt_table),%edi
	addl $__PAGE_OFFSET,%eax
1:
	movb $0xc0,GDT_ENTRY_KERNEL_CS * 8 + 6(%edi)
	movb $0xc0,GDT_ENTRY_KERNEXEC_KERNEL_CS * 8 + 6(%edi)
	movw %ax,GDT_ENTRY_KERNEL_CS * 8 + 2(%edi)
	movw %ax,GDT_ENTRY_KERNEXEC_KERNEL_CS * 8 + 2(%edi)
	rorl $16,%eax
	movb %al,GDT_ENTRY_KERNEL_CS * 8 + 4(%edi)
	movb %al,GDT_ENTRY_KERNEXEC_KERNEL_CS * 8 + 4(%edi)
	movb %ah,GDT_ENTRY_KERNEL_CS * 8 + 7(%edi)
	movb %ah,GDT_ENTRY_KERNEXEC_KERNEL_CS * 8 + 7(%edi)
	rorl $16,%eax
	addl $PAGE_SIZE_asm,%edi
	loop 1b
#endif

/*
 * Clear BSS first so that there are no surprises...
 */
	cld
	xorl %eax,%eax
	movl $pa(__bss_start),%edi
	movl $pa(__bss_stop),%ecx
	subl %edi,%ecx
	shrl $2,%ecx
	rep ; stosl
/*
 * Copy bootup parameters out of the way.
 * Note: %esi still has the pointer to the real-mode data.
 * With the kexec as boot loader, parameter segment might be loaded beyond
 * kernel image and might not even be addressable by early boot page tables.
 * (kexec on panic case). Hence copy out the parameters before initializing
 * page tables.
 */
	movl $pa(boot_params),%edi
	movl $(PARAM_SIZE/4),%ecx
	cld
	rep
	movsl
	movl pa(boot_params) + NEW_CL_POINTER,%esi
	andl %esi,%esi
	jz 1f			# No command line
	movl $pa(boot_command_line),%edi
	movl $(COMMAND_LINE_SIZE/4),%ecx
	rep
	movsl
1:

#ifdef CONFIG_OLPC
	/* save OFW's pgdir table for later use when calling into OFW */
	movl %cr3, %eax
	movl %eax, pa(olpc_ofw_pgd)
#endif

#ifdef CONFIG_MICROCODE
	/* Early load ucode on BSP. */
	pax_direct_call load_ucode_bsp
#endif

/*
 * Initialize page tables.  This creates a PDE and a set of page
 * tables, which are located immediately beyond __brk_base.  The variable
 * _brk_end is set up to point to the first "safe" location.
 * Mappings are created both at virtual address 0 (identity mapping)
 * and PAGE_OFFSET for up to _end.
 */
#ifdef CONFIG_X86_PAE

	/*
	 * In PAE mode initial_page_table is statically defined to contain
	 * enough entries to cover the VMSPLIT option (that is the top 1, 2 or 3
	 * entries). The identity mapping is handled by pointing two PGD entries
	 * to the first kernel PMD.
	 *
	 * Note the upper half of each PMD or PTE are always zero at this stage.
	 */

#define KPMDS (((-__PAGE_OFFSET) >> 30) & 3) /* Number of kernel PMDs */

	xorl %ebx,%ebx				/* %ebx is kept at zero */

	movl $pa(__brk_base), %edi
	movl $pa(initial_pg_pmd), %edx
	movl $PTE_IDENT_ATTR, %eax
10:
	leal PDE_IDENT_ATTR(%edi),%ecx		/* Create PMD entry */
	movl %ecx,(%edx)			/* Store PMD entry */
						/* Upper half already zero */
	addl $8,%edx
	movl $512,%ecx
11:
	stosl
	xchgl %eax,%ebx
	stosl
	xchgl %eax,%ebx
	addl $0x1000,%eax
	loop 11b

	/*
	 * End condition: we must map up to the end + MAPPING_BEYOND_END.
	 */
	movl $pa(_end) + MAPPING_BEYOND_END + PTE_IDENT_ATTR, %ebp
	cmpl %ebp,%eax
	jb 10b
1:
	addl $__PAGE_OFFSET, %edi
	movl %edi, pa(_brk_end)
	shrl $12, %eax
	movl %eax, pa(max_pfn_mapped)

	/* Do early initialization of the fixmap area */
#ifdef CONFIG_COMPAT_VDSO
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR+_PAGE_USER,pa(initial_pg_pmd+0x1000*KPMDS-8)
#else
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR,pa(initial_pg_pmd+0x1000*KPMDS-8)
#endif
#else	/* Not PAE */

page_pde_offset = (__PAGE_OFFSET >> 20);

	movl $pa(__brk_base), %edi
	movl $pa(initial_page_table), %edx
	movl $PTE_IDENT_ATTR, %eax
10:
	leal PDE_IDENT_ATTR(%edi),%ecx		/* Create PDE entry */
	movl %ecx,(%edx)			/* Store identity PDE entry */
	movl %ecx,page_pde_offset(%edx)		/* Store kernel PDE entry */
	addl $4,%edx
	movl $1024, %ecx
11:
	stosl
	addl $0x1000,%eax
	loop 11b
	/*
	 * End condition: we must map up to the end + MAPPING_BEYOND_END.
	 */
	movl $pa(_end) + MAPPING_BEYOND_END + PTE_IDENT_ATTR, %ebp
	cmpl %ebp,%eax
	jb 10b
	addl $__PAGE_OFFSET, %edi
	movl %edi, pa(_brk_end)
	shrl $12, %eax
	movl %eax, pa(max_pfn_mapped)

	/* Do early initialization of the fixmap area */
#ifdef CONFIG_COMPAT_VDSO
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR+_PAGE_USER,pa(initial_page_table+0xffc)
#else
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR,pa(initial_page_table+0xffc)
#endif
#endif

#ifdef CONFIG_PARAVIRT
	/* This is can only trip for a broken bootloader... */
	cmpw $0x207, pa(boot_params + BP_version)
	jb default_entry

	/* Paravirt-compatible boot parameters.  Look to see what architecture
		we're booting under. */
	movl pa(boot_params + BP_hardware_subarch), %eax
	cmpl $num_subarch_entries, %eax
	jae bad_subarch

	jmp *pa(subarch_entries)(,%eax,4)

bad_subarch:
WEAK(lguest_entry)
WEAK(xen_entry)
	/* Unknown implementation; there's really
	   nothing we can do at this point. */
	ud2a

	__INITDATA

subarch_entries:
	.long ta(default_entry)		/* normal x86/PC */
	.long ta(lguest_entry)		/* lguest hypervisor */
	.long ta(xen_entry)		/* Xen hypervisor */
	.long ta(default_entry)		/* Moorestown MID */
num_subarch_entries = (. - subarch_entries) / 4
.previous
#else
	jmp default_entry
#endif /* CONFIG_PARAVIRT */

#ifdef CONFIG_HOTPLUG_CPU
/*
 * Boot CPU0 entry point. It's called from play_dead(). Everything has been set
 * up already except stack. We just set up stack here. Then call
 * start_secondary().
 */
ENTRY(start_cpu0)
	movl initial_stack, %ecx
	movl %ecx, %esp
	jmp  *(initial_code)
ENDPROC(start_cpu0)
#endif

/*
 * Non-boot CPU entry point; entered from trampoline.S
 * We can't lgdt here, because lgdt itself uses a data segment, but
 * we know the trampoline has already loaded the boot_gdt for us.
 *
 * If cpu hotplug is not supported then this code can go in init section
 * which will be freed later
 */
ENTRY(startup_32_smp)
	cld
	movl $(__BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
	movl pa(initial_stack),%ecx
	movl %eax,%ss
	leal -__PAGE_OFFSET(%ecx),%esp

#ifdef CONFIG_MICROCODE
	/* Early load ucode on AP. */
	pax_direct_call load_ucode_ap
#endif

default_entry:
#define CR0_STATE	(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | \
			 X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | \
			 X86_CR0_PG)
	movl $(CR0_STATE & ~X86_CR0_PG),%eax
	movl %eax,%cr0

/*
 * We want to start out with EFLAGS unambiguously cleared. Some BIOSes leave
 * bits like NT set. This would confuse the debugger if this code is traced. So
 * initialize them properly now before switching to protected mode. That means
 * DF in particular (even though we have cleared it earlier after copying the
 * command line) because GCC expects it.
 */
	pushl $0
	popfl

/*
 * New page tables may be in 4Mbyte page mode and may be using the global pages.
 *
 * NOTE! If we are on a 486 we may have no cr4 at all! Specifically, cr4 exists
 * if and only if CPUID exists and has flags other than the FPU flag set.
 */
	movl $-1,pa(X86_CPUID)		# preset CPUID level
	movl $X86_EFLAGS_ID,%ecx
	pushl %ecx
	popfl				# set EFLAGS=ID
	pushfl
	popl %eax			# get EFLAGS
	testl $X86_EFLAGS_ID,%eax	# did EFLAGS.ID remained set?
	jz enable_paging		# hw disallowed setting of ID bit
					# which means no CPUID and no CR4

	xorl %eax,%eax
	cpuid
	movl %eax,pa(X86_CPUID)		# save largest std CPUID function

	movl $1,%eax
	cpuid
	andl $~1,%edx			# Ignore CPUID.FPU
	jz enable_paging		# No flags or only CPUID.FPU = no CR4

	movl pa(mmu_cr4_features),%eax
	movl %eax,%cr4

#ifdef CONFIG_X86_PAE
	testb $X86_CR4_PAE, %al		# check if PAE is enabled
	jz enable_paging

	/* Check if extended functions are implemented */
	movl $0x80000000, %eax
	cpuid
	/* Value must be in the range 0x80000001 to 0x8000ffff */
	subl $0x80000001, %eax
	cmpl $(0x8000ffff-0x80000001), %eax
	ja enable_paging

	/* Clear bogus XD_DISABLE bits */
	call verify_cpu

	mov $0x80000001, %eax
	cpuid
	/* Execute Disable bit supported? */
	btl $(X86_FEATURE_NX & 31), %edx
	jnc enable_paging

	/* Setup EFER (Extended Feature Enable Register) */
	movl $MSR_EFER, %ecx
	rdmsr

	btsl $_EFER_NX, %eax
	/* Make changes effective */
	wrmsr

	btsl $_PAGE_BIT_NX-32,pa(__supported_pte_mask+4)
#endif

enable_paging:

/*
 * Enable paging
 */
	movl $pa(initial_page_table), %eax
	movl %eax,%cr3		/* set the page table pointer.. */
	movl $CR0_STATE,%eax
	movl %eax,%cr0		/* ..and set paging (PG) bit */
	ljmp $__BOOT_CS,$1f	/* Clear prefetch and normalize %eip */
1:
	/* Shift the stack pointer to a virtual address */
	addl $__PAGE_OFFSET, %esp

/*
 * start system 32-bit setup. We need to re-do some of the things done
 * in 16-bit mode for the "real" operations.
 */
	movl setup_once_ref,%eax
	andl %eax,%eax
	jz 1f				# Did we do this already?
	call *%eax
1:

/*
 * Check if it is 486
 */
	movb $4,X86			# at least 486
	cmpl $-1,X86_CPUID
	je is486

	/* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	cpuid
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	orl %eax,%eax			# do we have processor info as well?
	je is486

	movl $1,%eax		# Use the CPUID instruction to get CPU type
	cpuid
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

is486:
	movl $0x50022,%ecx	# set AM, WP, NE and MP
	movl %cr0,%eax
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl %ecx,%eax
	movl %eax,%cr0

	lgdt early_gdt_descr
	lidt idt_descr
	ljmp $(__KERNEL_CS),$1f
1:	movl $(__KERNEL_DS),%eax	# reload all the segment registers
	movl %eax,%ss			# after changing gdt.

#	movl $(__KERNEL_DS),%eax	# DS/ES contains default KERNEL segment
	movl %eax,%ds
	movl %eax,%es

	movl $(__KERNEL_PERCPU), %eax
	movl %eax,%fs			# set this cpu's percpu

#ifdef CONFIG_CC_STACKPROTECTOR
	movl $(__KERNEL_STACK_CANARY),%eax
#elif defined(CONFIG_PAX_MEMORY_UDEREF)
	movl $(__USER_DS),%eax
#else
	xorl %eax,%eax
#endif
	movl %eax,%gs

	xorl %eax,%eax			# Clear LDT
	lldt %ax

	pushl $0		# fake return address for unwinder
	jmp *(initial_code)

#include "verify_cpu.S"

/*
 *  setup_once
 *
 *  The setup work we only want to run on the BSP.
 *
 *  Warning: %esi is live across this function.
 */
__INIT
setup_once:
	/*
	 * Set up a idt with 256 interrupt gates that push zero if there
	 * is no error code and then jump to early_idt_handler_common.
	 * It doesn't actually load the idt - that needs to be done on
	 * each CPU. Interrupts are enabled elsewhere, when we can be
	 * relatively sure everything is ok.
	 */

	movl $idt_table,%edi
	movl $early_idt_handler_array,%eax
	movl $NUM_EXCEPTION_VECTORS,%ecx
1:
	movl %eax,(%edi)
	movl %eax,4(%edi)
	/* interrupt gate, dpl=0, present */
	movl $(0x8E000000 + __KERNEL_CS),2(%edi)
	addl $EARLY_IDT_HANDLER_SIZE,%eax
	addl $8,%edi
	loop 1b

	movl $256 - NUM_EXCEPTION_VECTORS,%ecx
	movl $ignore_int,%edx
	movl $(__KERNEL_CS << 16),%eax
	movw %dx,%ax		/* selector = 0x0010 = cs */
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */
2:
	movl %eax,(%edi)
	movl %edx,4(%edi)
	addl $8,%edi
	loop 2b

#ifdef CONFIG_CC_STACKPROTECTOR
	/*
	 * Configure the stack canary. The linker can't handle this by
	 * relocation.  Manually set base address in stack canary
	 * segment descriptor.
	 */
	movl $cpu_gdt_table,%eax
	movl $stack_canary,%ecx
#ifdef CONFIG_SMP
	addl $__per_cpu_load,%ecx
#endif
	movw %cx, 8 * GDT_ENTRY_STACK_CANARY + 2(%eax)
	shrl $16, %ecx
	movb %cl, 8 * GDT_ENTRY_STACK_CANARY + 4(%eax)
	movb %ch, 8 * GDT_ENTRY_STACK_CANARY + 7(%eax)
#endif

	andl $0,setup_once_ref	/* Once is enough, thanks */
	ret

ENTRY(early_idt_handler_array)
	# 36(%esp) %eflags
	# 32(%esp) %cs
	# 28(%esp) %eip
	# 24(%rsp) error code
	i = 0
	.rept NUM_EXCEPTION_VECTORS
	.ifeq (EXCEPTION_ERRCODE_MASK >> i) & 1
	pushl $0		# Dummy error code, to make stack frame uniform
	.endif
	pushl $i		# 20(%esp) Vector number
	jmp early_idt_handler_common
	i = i + 1
	.fill early_idt_handler_array + i*EARLY_IDT_HANDLER_SIZE - ., 1, 0xcc
	.endr
ENDPROC(early_idt_handler_array)
	
early_idt_handler_common:
	/*
	 * The stack is the hardware frame, an error code or zero, and the
	 * vector number.
	 */
	cld

	incl %ss:early_recursion_flag

	/* The vector number is in pt_regs->gs */

	cld
	pushl	%fs		/* pt_regs->fs */
	movw	$0, 2(%esp)	/* clear high bits (some CPUs leave garbage) */
	pushl	%es		/* pt_regs->es */
	movw	$0, 2(%esp)	/* clear high bits (some CPUs leave garbage) */
	pushl	%ds		/* pt_regs->ds */
	movw	$0, 2(%esp)	/* clear high bits (some CPUs leave garbage) */
	pushl	%eax		/* pt_regs->ax */
	pushl	%ebp		/* pt_regs->bp */
	pushl	%edi		/* pt_regs->di */
	pushl	%esi		/* pt_regs->si */
	pushl	%edx		/* pt_regs->dx */
	pushl	%ecx		/* pt_regs->cx */
	pushl	%ebx		/* pt_regs->bx */

	/* Fix up DS and ES */
	movl	$(__KERNEL_DS), %ecx
	movl	%ecx, %ds
	movl	%ecx, %es

	/* Load the vector number into EDX */
	movl	PT_GS(%esp), %edx

	/* Load GS into pt_regs->gs and clear high bits */
	movw	%gs, PT_GS(%esp)
	movw	$0, PT_GS+2(%esp)

	movl	%esp, %eax	/* args are pt_regs (EAX), trapnr (EDX) */
	pax_direct_call early_fixup_exception

	popl	%ebx		/* pt_regs->bx */
	popl	%ecx		/* pt_regs->cx */
	popl	%edx		/* pt_regs->dx */
	popl	%esi		/* pt_regs->si */
	popl	%edi		/* pt_regs->di */
	popl	%ebp		/* pt_regs->bp */
	popl	%eax		/* pt_regs->ax */
	popl	%ds		/* pt_regs->ds */
	popl	%es		/* pt_regs->es */
	popl	%fs		/* pt_regs->fs */
	popl	%gs		/* pt_regs->gs */
	decl	%ss:early_recursion_flag
	addl	$4, %esp	/* pop pt_regs->orig_ax */
	iret
ENDPROC(early_idt_handler_common)

/* This is the default interrupt "handler" :-) */
	ALIGN
ignore_int:
#ifdef CONFIG_PRINTK
	cmpl $2,%ss:early_recursion_flag
	je hlt_loop
	incl %ss:early_recursion_flag
	cld
	pushl %eax
	pushl %ecx
	pushl %edx
	pushl %es
	pushl %ds
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	pushl 16(%esp)
	pushl 24(%esp)
	pushl 32(%esp)
	pushl 40(%esp)
	pushl $int_msg
	pax_direct_call printk

	pax_direct_call dump_stack

	addl $(5*4),%esp
	popl %ds
	popl %es
	popl %edx
	popl %ecx
	popl %eax
#endif
	iret

hlt_loop:
	hlt
	jmp hlt_loop
ENDPROC(ignore_int)
__INITDATA
	.align 4
GLOBAL(early_recursion_flag)
	.long 0

__REFDATA
	.align 4
ENTRY(initial_code)
	.long i386_start_kernel
ENTRY(setup_once_ref)
	.long setup_once

__READ_ONLY
	.balign	PAGE_SIZE
#ifdef CONFIG_X86_PAE
initial_pg_pmd:
	.fill 1024*KPMDS,4,0
#else
.globl initial_page_table
initial_page_table:
	.fill 1024,4,0
#endif
initial_pg_fixmap:
	.fill 1024,4,0
.globl empty_zero_page
empty_zero_page:
	.fill 4096,1,0
.globl swapper_pg_dir
swapper_pg_dir:
#ifdef CONFIG_X86_PAE
	.fill PTRS_PER_PGD,8,0
#else
	.fill PTRS_PER_PGD,4,0
#endif
EXPORT_SYMBOL(empty_zero_page)

/*
 * This starts the data section.
 */
#ifdef CONFIG_X86_PAE
__READ_ONLY
	.balign	PAGE_SIZE
ENTRY(initial_page_table)
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0	/* low identity map */
# if KPMDS == 3
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x1000),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x2000),0
# elif KPMDS == 2
	.long	0,0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x1000),0
# elif KPMDS == 1
	.long	0,0
	.long	0,0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
# else
#  error "Kernel PMDs should be 1, 2 or 3"
# endif
	.balign PAGE_SIZE		/* needs to be page-sized too */

# ifdef CONFIG_PAX_PER_CPU_PGD
ENTRY(cpu_pgd)
	.rept 2*NR_CPUS
	.fill	PTRS_PER_PGD,8,0
	.endr
EXPORT_SYMBOL(cpu_pgd)
# endif

#endif

.data
.balign 4
ENTRY(initial_stack)
	.long init_thread_union+THREAD_SIZE-8

__INITRODATA
int_msg:
	.asciz "Unknown interrupt or fault at: %p %p %p\n"

#include "../../x86/xen/xen-head.S"

/*
 * The IDT and GDT 'descriptors' are a strange 48-bit object
 * only used by the lidt and lgdt instructions. They are not
 * like usual segment descriptors - they consist of a 16-bit
 * segment size, and 32-bit linear address value:
 */

__READ_ONLY
.globl boot_gdt_descr
.globl idt_descr

	ALIGN
# early boot GDT descriptor (must use 1:1 address mapping)
	.word 0				# 32 bit align gdt_desc.address
boot_gdt_descr:
	.word __BOOT_DS+7
	.long pa(boot_gdt)

	.word 0				# 32-bit align idt_desc.address
idt_descr:
	.word IDT_ENTRIES*8-1		# idt contains 256 entries
	.long idt_table

# boot GDT descriptor (later on used by CPU#0):
	.word 0				# 32 bit align gdt_desc.address
ENTRY(early_gdt_descr)
	.word GDT_ENTRIES*8-1
	.long cpu_gdt_table		/* Overwritten for secondary CPUs */

/*
 * The boot_gdt must mirror the equivalent in setup.S and is
 * used only for booting.
 */
	.align L1_CACHE_BYTES
ENTRY(boot_gdt)
	.fill GDT_ENTRY_BOOT_CS,8,0
	.quad 0x00cf9b000000ffff	/* kernel 4GB code at 0x00000000 */
	.quad 0x00cf93000000ffff	/* kernel 4GB data at 0x00000000 */

	.align PAGE_SIZE_asm
ENTRY(cpu_gdt_table)
	.rept NR_CPUS
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* 0x0b reserved */
	.quad 0x0000000000000000	/* 0x13 reserved */
	.quad 0x0000000000000000	/* 0x1b reserved */

#ifdef CONFIG_PAX_KERNEXEC
	.quad 0x00cf9b000000ffff	/* 0x20 alternate kernel 4GB code at 0x00000000 */
#else
	.quad 0x0000000000000000	/* 0x20 unused */
#endif

	.quad 0x0000000000000000	/* 0x28 unused */
	.quad 0x0000000000000000	/* 0x33 TLS entry 1 */
	.quad 0x0000000000000000	/* 0x3b TLS entry 2 */
	.quad 0x0000000000000000	/* 0x43 TLS entry 3 */
	.quad 0x0000000000000000	/* 0x4b reserved */
	.quad 0x0000000000000000	/* 0x53 reserved */
	.quad 0x0000000000000000	/* 0x5b reserved */

	.quad 0x00cf9b000000ffff	/* 0x60 kernel 4GB code at 0x00000000 */
	.quad 0x00cf93000000ffff	/* 0x68 kernel 4GB data at 0x00000000 */
	.quad 0x00cffb000000ffff	/* 0x73 user 4GB code at 0x00000000 */
	.quad 0x00cff3000000ffff	/* 0x7b user 4GB data at 0x00000000 */

	.quad 0x0000000000000000	/* 0x80 TSS descriptor */
	.quad 0x0000000000000000	/* 0x88 LDT descriptor */

	/*
	 * Segments used for calling PnP BIOS have byte granularity.
	 * The code segments and data segments have fixed 64k limits,
	 * the transfer segment sizes are set at run time.
	 */
	.quad 0x00409b000000ffff	/* 0x90 32-bit code */
	.quad 0x00009b000000ffff	/* 0x98 16-bit code */
	.quad 0x000093000000ffff	/* 0xa0 16-bit data */
	.quad 0x0000930000000000	/* 0xa8 16-bit data */
	.quad 0x0000930000000000	/* 0xb0 16-bit data */

	/*
	 * The APM segments have byte granularity and their bases
	 * are set at run time.  All have 64k limits.
	 */
	.quad 0x00409b000000ffff	/* 0xb8 APM CS    code */
	.quad 0x00009b000000ffff	/* 0xc0 APM CS 16 code (16 bit) */
	.quad 0x004093000000ffff	/* 0xc8 APM DS    data */

	.quad 0x00c093000000ffff	/* 0xd0 - ESPFIX SS */
	.quad 0x0040930000000000	/* 0xd8 - PERCPU */
	.quad 0x0040910000000017	/* 0xe0 - STACK_CANARY */
	.quad 0x0000000000000000	/* 0xe8 - PCIBIOS_CS */
	.quad 0x0000000000000000	/* 0xf0 - PCIBIOS_DS */
	.quad 0x0000000000000000	/* 0xf8 - GDT entry 31: double-fault TSS */

	/* Be sure this is zeroed to avoid false validations in Xen */
	.fill PAGE_SIZE_asm - GDT_SIZE,1,0
	.endr

EXPORT_SYMBOL_GPL(cpu_gdt_table)
