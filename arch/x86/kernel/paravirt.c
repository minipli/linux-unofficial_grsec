/*  Paravirtualization interfaces
    Copyright (C) 2006 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    2007 - x86_64 support added by Glauber de Oliveira Costa, Red Hat Inc
*/

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/efi.h>
#include <linux/bcd.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>

#include <asm/bug.h>
#include <asm/paravirt.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/time.h>
#include <asm/pgalloc.h>
#include <asm/irq.h>
#include <asm/delay.h>
#include <asm/fixmap.h>
#include <asm/apic.h>
#include <asm/tlbflush.h>
#include <asm/timer.h>
#include <asm/special_insns.h>

/*
 * nop stub, which must not clobber anything *including the stack* to
 * avoid confusing the entry prologues.
 */
extern void _paravirt_nop(void);
asm (".pushsection .entry.text, \"ax\"\n"
     ".global _paravirt_nop\n"
     "_paravirt_nop:\n\t"
     "ret\n\t"
     ".size _paravirt_nop, . - _paravirt_nop\n\t"
     ".type _paravirt_nop, @function\n\t"
     ".popsection");

/* identity function, which can be inlined */
u32 notrace _paravirt_ident_32(u32 x)
{
	return x;
}

u64 notrace _paravirt_ident_64(u64 x)
{
	return x;
}
#if defined(CONFIG_X86_32) && defined(CONFIG_X86_PAE)
PV_CALLEE_SAVE_REGS_THUNK(_paravirt_ident_64);
#endif

void __init default_banner(void)
{
	printk(KERN_INFO "Booting paravirtualized kernel on %s\n",
	       pv_info.name);
}

/* Undefined instruction for dealing with missing ops pointers. */
static const unsigned char ud2a[] = { 0x0f, 0x0b };

struct longbranch {
	unsigned char opcode;
	u32 delta;
} __attribute__((packed));

struct shortbranch {
	unsigned char opcode;
	signed char delta;
};

unsigned paravirt_patch_call(void *insnbuf,
			     const void *target, u16 tgt_clobbers,
			     unsigned long addr, u16 site_clobbers,
			     unsigned len)
{
	struct longbranch *b = insnbuf;
#ifdef CONFIG_PAX_RAP
	struct shortbranch *hashb = insnbuf;
#endif
	unsigned long delta = (unsigned long)target - (addr+5);

	if (tgt_clobbers & ~site_clobbers)
		return len;	/* target would clobber too much for this site */
	if (len < 5)
		return len;	/* call too long for patch site */

#ifdef CONFIG_PAX_RAP
	if (hashb->opcode != 0xeb)
		return len;
	hashb->delta = len - sizeof(*b) - sizeof(*hashb);
	b = insnbuf + len - sizeof(*b);
	delta = (unsigned long)target - (addr + len);
#endif

	b->opcode = 0xe8; /* call */
	b->delta = delta;
	BUILD_BUG_ON(sizeof(*b) != 5);

#ifdef CONFIG_PAX_RAP
	return len;
#else
	return 5;
#endif
}

unsigned paravirt_patch_jmp(void *insnbuf, const void *target,
			    unsigned long addr, unsigned len)
{
	struct longbranch *b = insnbuf;
	unsigned long delta = (unsigned long)target - (addr+5);

	if (len < 5)
		return len;	/* call too long for patch site */

	b->opcode = 0xe9;	/* jmp */
	b->delta = delta;

	return 5;
}

/* Neat trick to map patch type back to the call within the
 * corresponding structure. */
static void *get_call_destination(u8 type)
{
	struct paravirt_patch_template tmpl = {
		.pv_init_ops = pv_init_ops,
		.pv_time_ops = pv_time_ops,
		.pv_cpu_ops = pv_cpu_ops,
		.pv_irq_ops = pv_irq_ops,
		.pv_mmu_ops = pv_mmu_ops,
#ifdef CONFIG_PARAVIRT_SPINLOCKS
		.pv_lock_ops = pv_lock_ops,
#endif
	};
	return *((void **)&tmpl + type);
}

#if (defined(CONFIG_X86_32) && defined(CONFIG_X86_PAE)) || defined(CONFIG_PAX_RAP)
#if CONFIG_PGTABLE_LEVELS >= 3
PV_CALLEE_SAVE_REGS_THUNK(native_pmd_val);
PV_CALLEE_SAVE_REGS_THUNK(native_make_pmd);
#if CONFIG_PGTABLE_LEVELS == 4
PV_CALLEE_SAVE_REGS_THUNK(native_pud_val);
PV_CALLEE_SAVE_REGS_THUNK(native_make_pud);
#endif
#endif
PV_CALLEE_SAVE_REGS_THUNK(native_pte_val);
PV_CALLEE_SAVE_REGS_THUNK(native_pgd_val);
PV_CALLEE_SAVE_REGS_THUNK(native_make_pte);
PV_CALLEE_SAVE_REGS_THUNK(native_make_pgd);

const struct pv_mmu_ops rap_pv_mmu_ops __initconst = {
#if CONFIG_PGTABLE_LEVELS >= 3
	.pmd_val = (union paravirt_callee_save) { .pmd_val = native_pmd_val },
	.make_pmd = (union paravirt_callee_save) { .make_pmd = native_make_pmd },

#if CONFIG_PGTABLE_LEVELS == 4
	.pud_val = (union paravirt_callee_save) { .pud_val = native_pud_val },
	.make_pud = (union paravirt_callee_save) { .make_pud = native_make_pud },
#endif
#endif /* CONFIG_PGTABLE_LEVELS >= 3 */
	.pte_val = (union paravirt_callee_save) { .pte_val = native_pte_val },
	.pgd_val = (union paravirt_callee_save) { .pgd_val = native_pgd_val },

	.make_pte = (union paravirt_callee_save) { .make_pte = native_make_pte },
	.make_pgd = (union paravirt_callee_save) { .make_pgd = native_make_pgd },
};
#endif

unsigned paravirt_patch_default(u8 type, u16 clobbers, void *insnbuf,
				unsigned long addr, unsigned len)
{
	void *opfunc = get_call_destination(type);
	unsigned ret;

	if (opfunc == NULL)
		/* If there's no function, patch it with a ud2a (BUG) */
		ret = paravirt_patch_insns(insnbuf, len, (const char *)ktva_ktla((unsigned long)ud2a), ud2a+sizeof(ud2a));
	else if (opfunc == (void *)_paravirt_nop)
		ret = 0;

	/* identity functions just return their single argument */
#ifdef CONFIG_PAX_RAP
	else if (
#if CONFIG_PGTABLE_LEVELS >= 3
		 opfunc == (void *)__raw_callee_save_native_pmd_val ||
		 opfunc == (void *)__raw_callee_save_native_make_pmd ||
#if CONFIG_PGTABLE_LEVELS == 4
		 opfunc == (void *)__raw_callee_save_native_pud_val ||
		 opfunc == (void *)__raw_callee_save_native_make_pud ||
#endif
#endif
		 opfunc == (void *)__raw_callee_save_native_pte_val ||
		 opfunc == (void *)__raw_callee_save_native_pgd_val ||
		 opfunc == (void *)__raw_callee_save_native_make_pte ||
		 opfunc == (void *)__raw_callee_save_native_make_pgd)
#else
	else if (
#if CONFIG_PGTABLE_LEVELS >= 3
		 opfunc == (void *)native_pmd_val ||
		 opfunc == (void *)native_make_pmd ||
#if CONFIG_PGTABLE_LEVELS == 4
		 opfunc == (void *)native_pud_val ||
		 opfunc == (void *)native_make_pud ||
#endif
#endif
		 opfunc == (void *)native_pte_val ||
		 opfunc == (void *)native_pgd_val ||
		 opfunc == (void *)native_make_pte ||
		 opfunc == (void *)native_make_pgd)
#endif
#ifdef CONFIG_X86_32
#ifdef CONFIG_X86_PAE
		ret = paravirt_patch_ident_64(insnbuf, len);
#else
		ret = paravirt_patch_ident_32(insnbuf, len);
#endif
#else
		ret = paravirt_patch_ident_64(insnbuf, len);
#endif

	else if (type == PARAVIRT_PATCH(pv_cpu_ops.iret) ||
		 type == PARAVIRT_PATCH(pv_cpu_ops.usergs_sysret64))
		/* If operation requires a jmp, then jmp */
		ret = paravirt_patch_jmp(insnbuf, opfunc, addr, len);
	else
		/* Otherwise call the function; assume target could
		   clobber any caller-save reg */
		ret = paravirt_patch_call(insnbuf, opfunc, CLBR_ANY,
					  addr, clobbers, len);

	return ret;
}

unsigned paravirt_patch_insns(void *insnbuf, unsigned len,
			      const char *start, const char *end)
{
	unsigned insn_len = end - start;

	if (insn_len > len || start == NULL)
		insn_len = len;
	else
		memcpy(insnbuf, (const char *)ktla_ktva((unsigned long)start), insn_len);

	return insn_len;
}

static void native_flush_tlb(void)
{
	__native_flush_tlb();
}

/*
 * Global pages have to be flushed a bit differently. Not a real
 * performance problem because this does not happen often.
 */
static void native_flush_tlb_global(void)
{
	__native_flush_tlb_global();
}

static void native_flush_tlb_single(unsigned long addr)
{
	__native_flush_tlb_single(addr);
}

struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;

static u64 native_steal_clock(int cpu)
{
	return 0;
}

/* These are in entry.S */
extern void native_iret(void);
extern void native_usergs_sysret64(void);

static struct resource reserve_ioports = {
	.start = 0,
	.end = IO_SPACE_LIMIT,
	.name = "paravirt-ioport",
	.flags = IORESOURCE_IO | IORESOURCE_BUSY,
};

/*
 * Reserve the whole legacy IO space to prevent any legacy drivers
 * from wasting time probing for their hardware.  This is a fairly
 * brute-force approach to disabling all non-virtual drivers.
 *
 * Note that this must be called very early to have any effect.
 */
int paravirt_disable_iospace(void)
{
	return request_resource(&ioport_resource, &reserve_ioports);
}

static DEFINE_PER_CPU(enum paravirt_lazy_mode, paravirt_lazy_mode) = PARAVIRT_LAZY_NONE;

static inline void enter_lazy(enum paravirt_lazy_mode mode)
{
	BUG_ON(this_cpu_read(paravirt_lazy_mode) != PARAVIRT_LAZY_NONE);

	this_cpu_write(paravirt_lazy_mode, mode);
}

static void leave_lazy(enum paravirt_lazy_mode mode)
{
	BUG_ON(this_cpu_read(paravirt_lazy_mode) != mode);

	this_cpu_write(paravirt_lazy_mode, PARAVIRT_LAZY_NONE);
}

void paravirt_enter_lazy_mmu(void)
{
	enter_lazy(PARAVIRT_LAZY_MMU);
}

void paravirt_leave_lazy_mmu(void)
{
	leave_lazy(PARAVIRT_LAZY_MMU);
}

void paravirt_flush_lazy_mmu(void)
{
	preempt_disable();

	if (paravirt_get_lazy_mode() == PARAVIRT_LAZY_MMU) {
		arch_leave_lazy_mmu_mode();
		arch_enter_lazy_mmu_mode();
	}

	preempt_enable();
}

void paravirt_start_context_switch(struct task_struct *prev)
{
	BUG_ON(preemptible());

	if (this_cpu_read(paravirt_lazy_mode) == PARAVIRT_LAZY_MMU) {
		arch_leave_lazy_mmu_mode();
		set_ti_thread_flag(task_thread_info(prev), TIF_LAZY_MMU_UPDATES);
	}
	enter_lazy(PARAVIRT_LAZY_CPU);
}

void paravirt_end_context_switch(struct task_struct *next)
{
	BUG_ON(preemptible());

	leave_lazy(PARAVIRT_LAZY_CPU);

	if (test_and_clear_ti_thread_flag(task_thread_info(next), TIF_LAZY_MMU_UPDATES))
		arch_enter_lazy_mmu_mode();
}

enum paravirt_lazy_mode paravirt_get_lazy_mode(void)
{
	if (in_interrupt())
		return PARAVIRT_LAZY_NONE;

	return this_cpu_read(paravirt_lazy_mode);
}

struct pv_info pv_info __read_only = {
	.name = "bare hardware",
	.kernel_rpl = 0,
	.shared_kernel_pmd = 1,	/* Only used when CONFIG_X86_PAE is set */

#ifdef CONFIG_X86_64
	.extra_user_64bit_cs = __USER_CS,
#endif
};

struct pv_init_ops pv_init_ops __read_only = {
	.patch = native_patch,
};

struct pv_time_ops pv_time_ops __read_only = {
	.sched_clock = native_sched_clock,
	.steal_clock = native_steal_clock,
};


#ifdef CONFIG_PAX_RAP
PV_CALLEE_SAVE_REGS_THUNK(native_save_fl);
PV_CALLEE_SAVE_REGS_THUNK(native_restore_fl);
PV_CALLEE_SAVE_REGS_THUNK(native_irq_disable);
PV_CALLEE_SAVE_REGS_THUNK(native_irq_enable);

const struct pv_irq_ops rap_pv_irq_ops __initconst = {
	.save_fl = (union paravirt_callee_save) { .save_fl = native_save_fl },
	.restore_fl = (union paravirt_callee_save) { .restore_fl = native_restore_fl },
	.irq_disable = (union paravirt_callee_save) { .irq_disable = native_irq_disable },
	.irq_enable = (union paravirt_callee_save) { .irq_enable = native_irq_enable },
};
#endif

__visible struct pv_irq_ops pv_irq_ops __read_only = {
	.save_fl = __PV_IS_CALLEE_SAVE(save_fl, native_save_fl),
	.restore_fl = __PV_IS_CALLEE_SAVE(restore_fl, native_restore_fl),
	.irq_disable = __PV_IS_CALLEE_SAVE(irq_disable, native_irq_disable),
	.irq_enable = __PV_IS_CALLEE_SAVE(irq_enable, native_irq_enable),
	.safe_halt = native_safe_halt,
	.halt = native_halt,
#ifdef CONFIG_X86_64
	.adjust_exception_frame = paravirt_nop,
#endif
};

static void native_alloc_ldt(struct desc_struct *ldt, unsigned entries)
{
}

static void native_free_ldt(struct desc_struct *ldt, unsigned entries)
{
}

static void native_start_context_switch(struct task_struct *prev)
{
}

static void native_end_context_switch(struct task_struct *next)
{
}

__visible struct pv_cpu_ops pv_cpu_ops __read_only = {
	.cpuid = native_cpuid,
	.get_debugreg = native_get_debugreg,
	.set_debugreg = native_set_debugreg,
	.clts = native_clts,
	.read_cr0 = native_read_cr0,
	.write_cr0 = native_write_cr0,
	.read_cr4 = native_read_cr4,
	.write_cr4 = native_write_cr4,
#ifdef CONFIG_X86_64
	.read_cr8 = native_read_cr8,
	.write_cr8 = native_write_cr8,
#endif
	.wbinvd = native_wbinvd,
	.read_msr = native_read_msr,
	.write_msr = native_write_msr,
	.read_msr_safe = native_read_msr_safe,
	.write_msr_safe = native_write_msr_safe,
	.read_pmc = native_read_pmc,
	.load_tr_desc = native_load_tr_desc,
	.set_ldt = native_set_ldt,
	.load_gdt = native_load_gdt,
	.load_idt = native_load_idt,
	.store_idt = native_store_idt,
	.store_tr = native_store_tr,
	.load_tls = native_load_tls,
#ifdef CONFIG_X86_64
	.load_gs_index = native_load_gs_index,
#endif
	.write_ldt_entry = native_write_ldt_entry,
	.write_gdt_entry = native_write_gdt_entry,
	.write_idt_entry = native_write_idt_entry,

	.alloc_ldt = native_alloc_ldt,
	.free_ldt = native_free_ldt,

	.load_sp0 = native_load_sp0,

#ifdef CONFIG_X86_64
	.usergs_sysret64 = native_usergs_sysret64,
#endif
	.iret = native_iret,
	.swapgs = native_swapgs,

	.set_iopl_mask = native_set_iopl_mask,
	.io_delay = native_io_delay,

	.start_context_switch = native_start_context_switch,
	.end_context_switch = native_end_context_switch,
};

/* At this point, native_get/set_debugreg has real function entries */
NOKPROBE_SYMBOL(native_get_debugreg);
NOKPROBE_SYMBOL(native_set_debugreg);
NOKPROBE_SYMBOL(native_load_idt);

#ifdef CONFIG_X86_32
#ifdef CONFIG_X86_PAE
/* 64-bit pagetable entries */
#define PTE_IDENT(field, op)	PV_CALLEE_SAVE(field, op)
#else
/* 32-bit pagetable entries */
#define PTE_IDENT(field, op)	__PV_IS_CALLEE_SAVE(field, op)
#endif
#else
/* 64-bit pagetable entries */
#define PTE_IDENT(field, op)	__PV_IS_CALLEE_SAVE(field, op)
#endif

static void native_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
}

static void native_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
}

static void native_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
}

static void native_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
}

static void native_release_pte(unsigned long pfn)
{
}

static void native_release_pmd(unsigned long pfn)
{
}

static void native_release_pud(unsigned long pfn)
{
}

static void native_pte_update(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
}

static void native_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm)
{
}

static void native_exit_mmap(struct mm_struct *mm)
{
}

static void native_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
}

struct pv_mmu_ops pv_mmu_ops __ro_after_init = {

	.read_cr2 = native_read_cr2,
	.write_cr2 = native_write_cr2,
	.read_cr3 = native_read_cr3,
	.write_cr3 = native_write_cr3,

	.flush_tlb_user = native_flush_tlb,
	.flush_tlb_kernel = native_flush_tlb_global,
	.flush_tlb_single = native_flush_tlb_single,
	.flush_tlb_others = native_flush_tlb_others,

	.pgd_alloc = __paravirt_pgd_alloc,
	.pgd_free = native_pgd_free,

	.alloc_pte = native_alloc_pte,
	.alloc_pmd = native_alloc_pmd,
	.alloc_pud = native_alloc_pud,
	.release_pte = native_release_pte,
	.release_pmd = native_release_pmd,
	.release_pud = native_release_pud,

	.set_pte = native_set_pte,
	.set_pte_at = native_set_pte_at,
	.set_pmd = native_set_pmd,
	.set_pmd_at = native_set_pmd_at,
	.pte_update = native_pte_update,

	.ptep_modify_prot_start = __ptep_modify_prot_start,
	.ptep_modify_prot_commit = __ptep_modify_prot_commit,

#if CONFIG_PGTABLE_LEVELS >= 3
#ifdef CONFIG_X86_PAE
	.set_pte_atomic = native_set_pte_atomic,
	.pte_clear = native_pte_clear,
	.pmd_clear = native_pmd_clear,
#endif
	.set_pud = native_set_pud,

	.pmd_val = PTE_IDENT(pmd_val, native_pmd_val),
	.make_pmd = PTE_IDENT(make_pmd, native_make_pmd),

#if CONFIG_PGTABLE_LEVELS == 4
	.pud_val = PTE_IDENT(pud_val, native_pud_val),
	.make_pud = PTE_IDENT(make_pud, native_make_pud),

	.set_pgd = native_set_pgd,
	.set_pgd_batched = native_set_pgd_batched,
#endif
#endif /* CONFIG_PGTABLE_LEVELS >= 3 */

	.pte_val = PTE_IDENT(pte_val, native_pte_val),
	.pgd_val = PTE_IDENT(pgd_val, native_pgd_val),

	.make_pte = PTE_IDENT(make_pte, native_make_pte),
	.make_pgd = PTE_IDENT(make_pgd, native_make_pgd),

	.dup_mmap = native_dup_mmap,
	.exit_mmap = native_exit_mmap,
	.activate_mm = native_activate_mm,

	.lazy_mode = {
		.enter = paravirt_nop,
		.leave = paravirt_nop,
		.flush = paravirt_nop,
	},

	.set_fixmap = native_set_fixmap,

#ifdef CONFIG_PAX_KERNEXEC
	.pax_open_kernel = native_pax_open_kernel,
	.pax_close_kernel = native_pax_close_kernel,
#endif

};

EXPORT_SYMBOL_GPL(pv_time_ops);
EXPORT_SYMBOL    (pv_cpu_ops);
EXPORT_SYMBOL    (pv_mmu_ops);
EXPORT_SYMBOL_GPL(pv_info);
EXPORT_SYMBOL    (pv_irq_ops);
