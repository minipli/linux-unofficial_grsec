/*
 * ld script for the x86 kernel
 *
 * Historic 32-bit version written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *
 * Modernisation, unification and other changes and fixes:
 *   Copyright (C) 2007-2009  Sam Ravnborg <sam@ravnborg.org>
 *
 *
 * Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */

#ifdef CONFIG_X86_32
#define LOAD_OFFSET __PAGE_OFFSET
#else
#define LOAD_OFFSET __START_KERNEL_map
#endif

#include <asm-generic/vmlinux.lds.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/page_types.h>
#include <asm/cache.h>
#include <asm/boot.h>
#include <asm/segment.h>

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_KERNEXEC)
#define __KERNEL_TEXT_OFFSET	(LOAD_OFFSET + ____LOAD_PHYSICAL_ADDR)
#else
#define __KERNEL_TEXT_OFFSET	0
#endif

#undef i386     /* in case the preprocessor is a 32bit one */

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#ifdef CONFIG_X86_32
OUTPUT_ARCH(i386)
ENTRY(phys_startup_32)
jiffies = jiffies_64;
#else
OUTPUT_ARCH(i386:x86-64)
ENTRY(phys_startup_64)
jiffies_64 = jiffies;
#endif

#if defined(CONFIG_X86_64)
/*
 * On 64-bit, align RODATA to 2MB so we retain large page mappings for
 * boundaries spanning kernel text, rodata and data sections.
 *
 * However, kernel identity mappings will have different RWX permissions
 * to the pages mapping to text and to the pages padding (which are freed) the
 * text section. Hence kernel identity mappings will be broken to smaller
 * pages. For 64-bit, kernel text and kernel identity mappings are different,
 * so we can enable protection checks as well as retain 2MB large page
 * mappings for kernel text.
 */
#define X64_ALIGN_RODATA_BEGIN	. = ALIGN(HPAGE_SIZE);

#define X64_ALIGN_RODATA_END					\
		. = ALIGN(HPAGE_SIZE);				\
		__end_rodata_hpage_align = .;

#else

#define X64_ALIGN_RODATA_BEGIN
#define X64_ALIGN_RODATA_END

#endif

PHDRS {
	text PT_LOAD FLAGS(5);          /* R_E */
#ifdef CONFIG_X86_32
	module PT_LOAD FLAGS(5);        /* R_E */
#endif
#ifdef CONFIG_XEN
	rodata PT_LOAD FLAGS(5);        /* R_E */
#else
	rodata PT_LOAD FLAGS(4);        /* R__ */
#endif
	data PT_LOAD FLAGS(6);          /* RW_ */
	init.begin PT_LOAD FLAGS(6);    /* RW_ */
#ifdef CONFIG_SMP
	percpu PT_LOAD FLAGS(6);        /* RW_ */
#endif
	text.init PT_LOAD FLAGS(5);     /* R_E */
	text.exit PT_LOAD FLAGS(5);     /* R_E */
	init PT_LOAD FLAGS(6);          /* RW_ */
	note PT_NOTE FLAGS(0);          /* ___ */
}

SECTIONS
{
#ifdef CONFIG_X86_32
	. = LOAD_OFFSET + ____LOAD_PHYSICAL_ADDR;
#else
	. = __START_KERNEL;
#endif

	/* Text and read-only data */
	.text (. - __KERNEL_TEXT_OFFSET): AT(ADDR(.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
		/* bootstrapping code */
#ifdef CONFIG_X86_32
		phys_startup_32 = ABSOLUTE(startup_32 - LOAD_OFFSET + __KERNEL_TEXT_OFFSET);
		__LOAD_PHYSICAL_ADDR = . - LOAD_OFFSET + __KERNEL_TEXT_OFFSET;
#else
		phys_startup_64 = ABSOLUTE(startup_64 - LOAD_OFFSET + __KERNEL_TEXT_OFFSET);
		__LOAD_PHYSICAL_ADDR = ABSOLUTE(. - LOAD_OFFSET + __KERNEL_TEXT_OFFSET);
#endif
		_text = .;
		HEAD_TEXT
		. = ALIGN(8);
		_stext = .;
		TEXT_TEXT
		SCHED_TEXT
		CPUIDLE_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		ENTRY_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT
		*(.fixup)
		*(.gnu.warning)
	} :text = 0x9090

	. += __KERNEL_TEXT_OFFSET;

#ifdef CONFIG_X86_32
	. = ALIGN(PAGE_SIZE);
	.module.text : AT(ADDR(.module.text) - LOAD_OFFSET) {

#ifdef CONFIG_PAX_KERNEXEC
		MODULES_EXEC_VADDR = .;
		BYTE(0)
		. += (CONFIG_PAX_KERNEXEC_MODULE_TEXT * 1024 * 1024);
		. = ALIGN(HPAGE_SIZE) - 1;
		MODULES_EXEC_END = .;
#endif

	} :module
#endif

	.text.end : AT(ADDR(.text.end) - LOAD_OFFSET) {
		/* End of text section */
		BYTE(0)
		_etext = . - __KERNEL_TEXT_OFFSET;
	}

	. = ALIGN(PAGE_SIZE);
	NOTES :rodata :note

	EXCEPTION_TABLE(16) :rodata

	/* .text should occupy whole number of pages */
	. = ALIGN(PAGE_SIZE);
	X64_ALIGN_RODATA_BEGIN
	RO_DATA(PAGE_SIZE)
	X64_ALIGN_RODATA_END

	/* Data */
	.data : AT(ADDR(.data) - LOAD_OFFSET) {

#ifdef CONFIG_PAX_KERNEXEC
		. = ALIGN(HPAGE_SIZE);
#else
		. = ALIGN(PAGE_SIZE);
#endif

		/* Start of data section */
		_sdata = .;

		/* init_task */
		INIT_TASK_DATA(THREAD_SIZE)

		NOSAVE_DATA

		PAGE_ALIGNED_DATA(PAGE_SIZE)

		CACHELINE_ALIGNED_DATA(L1_CACHE_BYTES)

		DATA_DATA
		CONSTRUCTORS

		/* rarely changed data like cpu maps */
		READ_MOSTLY_DATA(INTERNODE_CACHE_BYTES)

		/* End of data section */
		_edata = .;
	} :data


	. = ALIGN(PAGE_SIZE);
	__vvar_page = .;

	.vvar : AT(ADDR(.vvar) - LOAD_OFFSET) {
		/* work around gold bug 13023 */
		__vvar_beginning_hack = .;

		/* Place all vvars at the offsets in asm/vvar.h. */
#define EMIT_VVAR(name, offset) 			\
		. = __vvar_beginning_hack + offset;	\
		*(.vvar_ ## name)
#define __VVAR_KERNEL_LDS
#include <asm/vvar.h>
#undef __VVAR_KERNEL_LDS
#undef EMIT_VVAR

		/*
		 * Pad the rest of the page with zeros.  Otherwise the loader
		 * can leave garbage here.
		 */
		. = __vvar_beginning_hack + PAGE_SIZE;
	} :data

       . = ALIGN(__vvar_page + PAGE_SIZE, PAGE_SIZE);

	/* Init code and data - will be freed after init */
	.init.begin : AT(ADDR(.init.begin) - LOAD_OFFSET) {
		BYTE(0)

#ifdef CONFIG_PAX_KERNEXEC
		. = ALIGN(HPAGE_SIZE);
#else
		. = ALIGN(PAGE_SIZE);
#endif

		__init_begin = .; /* paired with __init_end */
	} :init.begin

#ifdef CONFIG_SMP
	/*
	 * percpu offsets are zero-based on SMP.  PERCPU_VADDR() changes the
	 * output PHDR, so the next output section - .init.text - should
	 * start another segment - init.
	 */
	PERCPU_VADDR(INTERNODE_CACHE_BYTES, 0, :percpu)
	ASSERT(SIZEOF(.data..percpu) < CONFIG_PHYSICAL_START,
	       "per-CPU data too large - increase CONFIG_PHYSICAL_START")
#endif

	. = ALIGN(PAGE_SIZE);
	init_begin = .;
	.init.text (. - __KERNEL_TEXT_OFFSET): AT(init_begin - LOAD_OFFSET) {
		VMLINUX_SYMBOL(_sinittext) = .;
		INIT_TEXT
		. = ALIGN(PAGE_SIZE);
	} :text.init

	/*
	 * Section for code used exclusively before alternatives are run. All
	 * references to such code must be patched out by alternatives, normally
	 * by using X86_FEATURE_ALWAYS CPU feature bit.
	 *
	 * See static_cpu_has() for an example.
	 */
	.altinstr_aux : AT(ADDR(.altinstr_aux) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
		*(.altinstr_aux)
	}

	/*
	 * .exit.text is discard at runtime, not link time, to deal with
	 *  references from .altinstructions and .eh_frame
	 */
	.exit.text : AT(ADDR(.exit.text) - LOAD_OFFSET + __KERNEL_TEXT_OFFSET) {
		EXIT_TEXT
		VMLINUX_SYMBOL(_einittext) = .;

#ifdef CONFIG_PAX_KERNEXEC
		. = ALIGN(HPAGE_SIZE);
#else
		. = ALIGN(16);
#endif

	} :text.exit
	. = init_begin + SIZEOF(.init.text) + SIZEOF(.altinstr_aux) + SIZEOF(.exit.text);

	. = ALIGN(PAGE_SIZE);
	INIT_DATA_SECTION(16) :init

	.x86_cpu_dev.init : AT(ADDR(.x86_cpu_dev.init) - LOAD_OFFSET) {
		__x86_cpu_dev_start = .;
		*(.x86_cpu_dev.init)
		__x86_cpu_dev_end = .;
	}

#ifdef CONFIG_X86_INTEL_MID
	.x86_intel_mid_dev.init : AT(ADDR(.x86_intel_mid_dev.init) - \
								LOAD_OFFSET) {
		__x86_intel_mid_dev_start = .;
		*(.x86_intel_mid_dev.init)
		__x86_intel_mid_dev_end = .;
	}
#endif

	/*
	 * start address and size of operations which during runtime
	 * can be patched with virtualization friendly instructions or
	 * baremetal native ones. Think page table operations.
	 * Details in paravirt_types.h
	 */
	. = ALIGN(8);
	.parainstructions : AT(ADDR(.parainstructions) - LOAD_OFFSET) {
		__parainstructions = .;
		*(.parainstructions)
		__parainstructions_end = .;
	}

	/*
	 * struct alt_inst entries. From the header (alternative.h):
	 * "Alternative instructions for different CPU types or capabilities"
	 * Think locking instructions on spinlocks.
	 */
	. = ALIGN(8);
	.altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}

	/*
	 * And here are the replacement instructions. The linker sticks
	 * them as binary blobs. The .altinstructions has enough data to
	 * get the address and the length of them to patch the kernel safely.
	 */
	.altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
		*(.altinstr_replacement)
	}

	/*
	 * struct iommu_table_entry entries are injected in this section.
	 * It is an array of IOMMUs which during run time gets sorted depending
	 * on its dependency order. After rootfs_initcall is complete
	 * this section can be safely removed.
	 */
	.iommu_table : AT(ADDR(.iommu_table) - LOAD_OFFSET) {
		__iommu_table = .;
		*(.iommu_table)
		__iommu_table_end = .;
	}

	. = ALIGN(8);
	.apicdrivers : AT(ADDR(.apicdrivers) - LOAD_OFFSET) {
		__apicdrivers = .;
		*(.apicdrivers);
		__apicdrivers_end = .;
	}

	. = ALIGN(8);

	.exit.data : AT(ADDR(.exit.data) - LOAD_OFFSET) {
		EXIT_DATA
	}

#ifndef CONFIG_SMP
	PERCPU_SECTION(INTERNODE_CACHE_BYTES)
#endif

	. = ALIGN(PAGE_SIZE);

	/* freed after init ends here */
	.init.end : AT(ADDR(.init.end) - LOAD_OFFSET) {
		__init_end = .;
	}

	/*
	 * smp_locks might be freed after init
	 * start/end must be page aligned
	 */
	. = ALIGN(PAGE_SIZE);
	.smp_locks : AT(ADDR(.smp_locks) - LOAD_OFFSET) {
		__smp_locks = .;
		*(.smp_locks)
		__smp_locks_end = .;
		. = ALIGN(PAGE_SIZE);
	}

	/* BSS */
	. = ALIGN(PAGE_SIZE);
	.bss : AT(ADDR(.bss) - LOAD_OFFSET) {
		__bss_start = .;
		*(.bss..page_aligned)
		*(.bss)
		. = ALIGN(PAGE_SIZE);
		__bss_stop = .;
	}

	. = ALIGN(PAGE_SIZE);
	.brk : AT(ADDR(.brk) - LOAD_OFFSET) {
		__brk_base = .;
		. += 64 * 1024;		/* 64k alignment slop space */
		*(.brk_reservation)	/* areas brk users have reserved */
		. = ALIGN(HPAGE_SIZE);
		__brk_limit = .;
	}

	. = ALIGN(PAGE_SIZE);		/* keep VO_INIT_SIZE page aligned */
	_end = .;

        STABS_DEBUG
        DWARF_DEBUG

	/* Sections to be discarded */
	DISCARDS
	/DISCARD/ : {
		*(.eh_frame)
		*(__func_stack_frame_non_standard)
	}
}


#ifdef CONFIG_X86_32
/*
 * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
 */
. = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
	   "kernel image bigger than KERNEL_IMAGE_SIZE");
#else
/*
 * Per-cpu symbols which need to be offset from __per_cpu_load
 * for the boot processor.
 */
#define INIT_PER_CPU(x) init_per_cpu__##x = x + __per_cpu_load
INIT_PER_CPU(irq_stack_union);

/*
 * Build-time check on the image size:
 */
. = ASSERT((_end - _text - __KERNEL_TEXT_OFFSET <= KERNEL_IMAGE_SIZE),
	   "kernel image bigger than KERNEL_IMAGE_SIZE");

#ifdef CONFIG_SMP
. = ASSERT((irq_stack_union == 0),
           "irq_stack_union is not at start of per-cpu area");
#endif

#endif /* CONFIG_X86_32 */

#ifdef CONFIG_KEXEC_CORE
#include <asm/kexec.h>

. = ASSERT(kexec_control_code_size <= KEXEC_CONTROL_CODE_MAX_SIZE,
           "kexec control code size is too big");
#endif

