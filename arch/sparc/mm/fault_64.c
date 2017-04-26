/*
 * arch/sparc64/mm/fault.c: Page fault handlers for the 64-bit Sparc.
 *
 * Copyright (C) 1996, 2008 David S. Miller (davem@davemloft.net)
 * Copyright (C) 1997, 1999 Jakub Jelinek (jj@ultra.linux.cz)
 */

#include <asm/head.h>

#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/extable.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/percpu.h>
#include <linux/context_tracking.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/compiler.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/openprom.h>
#include <asm/oplib.h>
#include <asm/asi.h>
#include <asm/lsu.h>
#include <asm/sections.h>
#include <asm/mmu_context.h>
#include <asm/setup.h>

int show_unhandled_signals = 1;

static inline __kprobes int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (kprobes_built_in() && !user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 0))
			ret = 1;
		preempt_enable();
	}
	return ret;
}

static void __kprobes unhandled_fault(unsigned long address,
				      struct task_struct *tsk,
				      struct pt_regs *regs)
{
	if ((unsigned long) address < PAGE_SIZE) {
		printk(KERN_ALERT "Unable to handle kernel NULL "
		       "pointer dereference\n");
	} else {
		printk(KERN_ALERT "Unable to handle kernel paging request "
		       "at virtual address %016lx\n", (unsigned long)address);
	}
	printk(KERN_ALERT "tsk->{mm,active_mm}->context = %016lx\n",
	       (tsk->mm ?
		CTX_HWBITS(tsk->mm->context) :
		CTX_HWBITS(tsk->active_mm->context)));
	printk(KERN_ALERT "tsk->{mm,active_mm}->pgd = %016lx\n",
	       (tsk->mm ? (unsigned long) tsk->mm->pgd :
		          (unsigned long) tsk->active_mm->pgd));
	die_if_kernel("Oops", regs);
}

static void __kprobes bad_kernel_pc(struct pt_regs *regs, unsigned long vaddr)
{
	printk(KERN_CRIT "OOPS: Bogus kernel PC [%016lx] in fault handler\n",
	       regs->tpc);
	printk(KERN_CRIT "OOPS: RPC [%016lx]\n", regs->u_regs[15]);
	printk("OOPS: RPC <%pA>\n", (void *) regs->u_regs[15]);
	printk(KERN_CRIT "OOPS: Fault was to vaddr[%lx]\n", vaddr);
	dump_stack();
	unhandled_fault(regs->tpc, current, regs);
}

/*
 * We now make sure that mmap_sem is held in all paths that call 
 * this. Additionally, to prevent kswapd from ripping ptes from
 * under us, raise interrupts around the time that we look at the
 * pte, kswapd will have to wait to get his smp ipi response from
 * us. vmtruncate likewise. This saves us having to get pte lock.
 */
static unsigned int get_user_insn(unsigned long tpc)
{
	pgd_t *pgdp = pgd_offset(current->mm, tpc);
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep, pte;
	unsigned long pa;
	u32 insn = 0;

	if (pgd_none(*pgdp) || unlikely(pgd_bad(*pgdp)))
		goto out;
	pudp = pud_offset(pgdp, tpc);
	if (pud_none(*pudp) || unlikely(pud_bad(*pudp)))
		goto out;

	/* This disables preemption for us as well. */
	local_irq_disable();

	pmdp = pmd_offset(pudp, tpc);
	if (pmd_none(*pmdp) || unlikely(pmd_bad(*pmdp)))
		goto out_irq_enable;

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	if (is_hugetlb_pmd(*pmdp)) {
		pa  = pmd_pfn(*pmdp) << PAGE_SHIFT;
		pa += tpc & ~HPAGE_MASK;

		/* Use phys bypass so we don't pollute dtlb/dcache. */
		__asm__ __volatile__("lduwa [%1] %2, %0"
				     : "=r" (insn)
				     : "r" (pa), "i" (ASI_PHYS_USE_EC));
	} else
#endif
	{
		ptep = pte_offset_map(pmdp, tpc);
		pte = *ptep;
		if (pte_present(pte)) {
			pa  = (pte_pfn(pte) << PAGE_SHIFT);
			pa += (tpc & ~PAGE_MASK);

			/* Use phys bypass so we don't pollute dtlb/dcache. */
			__asm__ __volatile__("lduwa [%1] %2, %0"
					     : "=r" (insn)
					     : "r" (pa), "i" (ASI_PHYS_USE_EC));
		}
		pte_unmap(ptep);
	}
out_irq_enable:
	local_irq_enable();
out:
	return insn;
}

static inline void
show_signal_msg(struct pt_regs *regs, int sig, int code,
		unsigned long address, struct task_struct *tsk)
{
	if (!unhandled_signal(tsk, sig))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %p (rpc %p) sp %p error %x",
	       task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
	       tsk->comm, task_pid_nr(tsk), address,
	       (void *)regs->tpc, (void *)regs->u_regs[UREG_I7],
	       (void *)regs->u_regs[UREG_FP], code);

	print_vma_addr(KERN_CONT " in ", regs->tpc);

	printk(KERN_CONT "\n");
}

static void do_fault_siginfo(int code, int sig, struct pt_regs *regs,
			     unsigned long fault_addr, unsigned int insn,
			     int fault_code)
{
	unsigned long addr;
	siginfo_t info;

	info.si_code = code;
	info.si_signo = sig;
	info.si_errno = 0;
	if (fault_code & FAULT_CODE_ITLB) {
		addr = regs->tpc;
	} else {
		/* If we were able to probe the faulting instruction, use it
		 * to compute a precise fault address.  Otherwise use the fault
		 * time provided address which may only have page granularity.
		 */
		if (insn)
			addr = compute_effective_address(regs, insn, 0);
		else
			addr = fault_addr;
	}
	info.si_addr = (void __user *) addr;
	info.si_trapno = 0;

	if (unlikely(show_unhandled_signals))
		show_signal_msg(regs, sig, code, addr, current);

	force_sig_info(sig, &info, current);
}

static unsigned int get_fault_insn(struct pt_regs *regs, unsigned int insn)
{
	if (!insn) {
		if (!regs->tpc || (regs->tpc & 0x3))
			return 0;
		if (regs->tstate & TSTATE_PRIV) {
			insn = *(unsigned int *) regs->tpc;
		} else {
			insn = get_user_insn(regs->tpc);
		}
	}
	return insn;
}

static void __kprobes do_kernel_fault(struct pt_regs *regs, int si_code,
				      int fault_code, unsigned int insn,
				      unsigned long address)
{
	unsigned char asi = ASI_P;
 
	if ((!insn) && (regs->tstate & TSTATE_PRIV))
		goto cannot_handle;

	/* If user insn could be read (thus insn is zero), that
	 * is fine.  We will just gun down the process with a signal
	 * in that case.
	 */

	if (!(fault_code & (FAULT_CODE_WRITE|FAULT_CODE_ITLB)) &&
	    (insn & 0xc0800000) == 0xc0800000) {
		if (insn & 0x2000)
			asi = (regs->tstate >> 24);
		else
			asi = (insn >> 5);
		if ((asi & 0xf2) == 0x82) {
			if (insn & 0x1000000) {
				handle_ldf_stq(insn, regs);
			} else {
				/* This was a non-faulting load. Just clear the
				 * destination register(s) and continue with the next
				 * instruction. -jj
				 */
				handle_ld_nf(insn, regs);
			}
			return;
		}
	}
		
	/* Is this in ex_table? */
	if (regs->tstate & TSTATE_PRIV) {
		const struct exception_table_entry *entry;

		entry = search_exception_tables(regs->tpc);
		if (entry) {
			regs->tpc = entry->fixup;
			regs->tnpc = regs->tpc + 4;
			return;
		}
	} else {
		/* The si_code was set to make clear whether
		 * this was a SEGV_MAPERR or SEGV_ACCERR fault.
		 */
		do_fault_siginfo(si_code, SIGSEGV, regs, address, insn, fault_code);
		return;
	}

cannot_handle:
	unhandled_fault (address, current, regs);
}

static void noinline __kprobes bogus_32bit_fault_tpc(struct pt_regs *regs)
{
	static int times;

	if (times++ < 10)
		printk(KERN_ERR "FAULT[%s:%d]: 32-bit process reports "
		       "64-bit TPC [%lx]\n",
		       current->comm, current->pid,
		       regs->tpc);
	show_regs(regs);
}

#ifdef CONFIG_PAX_PAGEEXEC
#ifdef CONFIG_PAX_DLRESOLVE
static void pax_emuplt_close(struct vm_area_struct *vma)
{
	vma->vm_mm->call_dl_resolve = 0UL;
}

static int pax_emuplt_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned int *kaddr;

	vmf->page = alloc_page(GFP_HIGHUSER);
	if (!vmf->page)
		return VM_FAULT_OOM;

	kaddr = kmap(vmf->page);
	memset(kaddr, 0, PAGE_SIZE);
	kaddr[0] = 0x9DE3BFA8U; /* save */
	flush_dcache_page(vmf->page);
	kunmap(vmf->page);
	return VM_FAULT_MAJOR;
}

static const struct vm_operations_struct pax_vm_ops = {
	.close = pax_emuplt_close,
	.fault = pax_emuplt_fault
};

static int pax_insert_vma(struct vm_area_struct *vma, unsigned long addr)
{
	int ret;

	INIT_LIST_HEAD(&vma->anon_vma_chain);
	vma->vm_mm = current->mm;
	vma->vm_start = addr;
	vma->vm_end = addr + PAGE_SIZE;
	vma->vm_flags = VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_ops = &pax_vm_ops;

	ret = insert_vm_struct(current->mm, vma);
	if (ret)
		return ret;

	++current->mm->total_vm;
	return 0;
}
#endif

/*
 * PaX: decide what to do with offenders (regs->tpc = fault address)
 *
 * returns 1 when task should be killed
 *         2 when patched PLT trampoline was detected
 *         3 when unpatched PLT trampoline was detected
 */
static int pax_handle_fetch_fault(struct pt_regs *regs)
{

#ifdef CONFIG_PAX_EMUPLT
	int err;

	do { /* PaX: patched PLT emulation #1 */
		unsigned int sethi1, sethi2, jmpl;

		err = get_user(sethi1, (unsigned int *)regs->tpc);
		err |= get_user(sethi2, (unsigned int *)(regs->tpc+4));
		err |= get_user(jmpl, (unsigned int *)(regs->tpc+8));

		if (err)
			break;

		if ((sethi1 & 0xFFC00000U) == 0x03000000U &&
		    (sethi2 & 0xFFC00000U) == 0x03000000U &&
		    (jmpl & 0xFFFFE000U) == 0x81C06000U)
		{
			unsigned long addr;

			regs->u_regs[UREG_G1] = (sethi2 & 0x003FFFFFU) << 10;
			addr = regs->u_regs[UREG_G1];
			addr += (((jmpl | 0xFFFFFFFFFFFFE000UL) ^ 0x00001000UL) + 0x00001000UL);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #2 */
		unsigned int ba;

		err = get_user(ba, (unsigned int *)regs->tpc);

		if (err)
			break;

		if ((ba & 0xFFC00000U) == 0x30800000U || (ba & 0xFFF80000U) == 0x30480000U) {
			unsigned long addr;

			if ((ba & 0xFFC00000U) == 0x30800000U)
				addr = regs->tpc + ((((ba | 0xFFFFFFFFFFC00000UL) ^ 0x00200000UL) + 0x00200000UL) << 2);
			else
				addr = regs->tpc + ((((ba | 0xFFFFFFFFFFF80000UL) ^ 0x00040000UL) + 0x00040000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #3 */
		unsigned int sethi, bajmpl, nop;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(bajmpl, (unsigned int *)(regs->tpc+4));
		err |= get_user(nop, (unsigned int *)(regs->tpc+8));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    ((bajmpl & 0xFFFFE000U) == 0x81C06000U || (bajmpl & 0xFFF80000U) == 0x30480000U) &&
		    nop == 0x01000000U)
		{
			unsigned long addr;

			addr = (sethi & 0x003FFFFFU) << 10;
			regs->u_regs[UREG_G1] = addr;
			if ((bajmpl & 0xFFFFE000U) == 0x81C06000U)
				addr += (((bajmpl | 0xFFFFFFFFFFFFE000UL) ^ 0x00001000UL) + 0x00001000UL);
			else
				addr = regs->tpc + ((((bajmpl | 0xFFFFFFFFFFF80000UL) ^ 0x00040000UL) + 0x00040000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #4 */
		unsigned int sethi, mov1, call, mov2;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(mov1, (unsigned int *)(regs->tpc+4));
		err |= get_user(call, (unsigned int *)(regs->tpc+8));
		err |= get_user(mov2, (unsigned int *)(regs->tpc+12));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    mov1 == 0x8210000FU &&
		    (call & 0xC0000000U) == 0x40000000U &&
		    mov2 == 0x9E100001U)
		{
			unsigned long addr;

			regs->u_regs[UREG_G1] = regs->u_regs[UREG_RETPC];
			addr = regs->tpc + 4 + ((((call | 0xFFFFFFFFC0000000UL) ^ 0x20000000UL) + 0x20000000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #5 */
		unsigned int sethi, sethi1, sethi2, or1, or2, sllx, jmpl, nop;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(sethi1, (unsigned int *)(regs->tpc+4));
		err |= get_user(sethi2, (unsigned int *)(regs->tpc+8));
		err |= get_user(or1, (unsigned int *)(regs->tpc+12));
		err |= get_user(or2, (unsigned int *)(regs->tpc+16));
		err |= get_user(sllx, (unsigned int *)(regs->tpc+20));
		err |= get_user(jmpl, (unsigned int *)(regs->tpc+24));
		err |= get_user(nop, (unsigned int *)(regs->tpc+28));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    (sethi1 & 0xFFC00000U) == 0x03000000U &&
		    (sethi2 & 0xFFC00000U) == 0x0B000000U &&
		    (or1 & 0xFFFFE000U) == 0x82106000U &&
		    (or2 & 0xFFFFE000U) == 0x8A116000U &&
		    sllx == 0x83287020U &&
		    jmpl == 0x81C04005U &&
		    nop == 0x01000000U)
		{
			unsigned long addr;

			regs->u_regs[UREG_G1] = ((sethi1 & 0x003FFFFFU) << 10) | (or1 & 0x000003FFU);
			regs->u_regs[UREG_G1] <<= 32;
			regs->u_regs[UREG_G5] = ((sethi2 & 0x003FFFFFU) << 10) | (or2 & 0x000003FFU);
			addr = regs->u_regs[UREG_G1] + regs->u_regs[UREG_G5];
			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #6 */
		unsigned int sethi, sethi1, sethi2, sllx, or,  jmpl, nop;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(sethi1, (unsigned int *)(regs->tpc+4));
		err |= get_user(sethi2, (unsigned int *)(regs->tpc+8));
		err |= get_user(sllx, (unsigned int *)(regs->tpc+12));
		err |= get_user(or, (unsigned int *)(regs->tpc+16));
		err |= get_user(jmpl, (unsigned int *)(regs->tpc+20));
		err |= get_user(nop, (unsigned int *)(regs->tpc+24));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    (sethi1 & 0xFFC00000U) == 0x03000000U &&
		    (sethi2 & 0xFFC00000U) == 0x0B000000U &&
		    sllx == 0x83287020U &&
		    (or & 0xFFFFE000U) == 0x8A116000U &&
		    jmpl == 0x81C04005U &&
		    nop == 0x01000000U)
		{
			unsigned long addr;

			regs->u_regs[UREG_G1] = (sethi1 & 0x003FFFFFU) << 10;
			regs->u_regs[UREG_G1] <<= 32;
			regs->u_regs[UREG_G5] = ((sethi2 & 0x003FFFFFU) << 10) | (or & 0x3FFU);
			addr = regs->u_regs[UREG_G1] + regs->u_regs[UREG_G5];
			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: unpatched PLT emulation step 1 */
		unsigned int sethi, ba, nop;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(ba, (unsigned int *)(regs->tpc+4));
		err |= get_user(nop, (unsigned int *)(regs->tpc+8));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    ((ba & 0xFFC00000U) == 0x30800000U || (ba & 0xFFF80000U) == 0x30680000U) &&
		    nop == 0x01000000U)
		{
			unsigned long addr;
			unsigned int save, call;
			unsigned int sethi1, sethi2, or1, or2, sllx, add, jmpl;

			if ((ba & 0xFFC00000U) == 0x30800000U)
				addr = regs->tpc + 4 + ((((ba | 0xFFFFFFFFFFC00000UL) ^ 0x00200000UL) + 0x00200000UL) << 2);
			else
				addr = regs->tpc + 4 + ((((ba | 0xFFFFFFFFFFF80000UL) ^ 0x00040000UL) + 0x00040000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			err = get_user(save, (unsigned int *)addr);
			err |= get_user(call, (unsigned int *)(addr+4));
			err |= get_user(nop, (unsigned int *)(addr+8));
			if (err)
				break;

#ifdef CONFIG_PAX_DLRESOLVE
			if (save == 0x9DE3BFA8U &&
			    (call & 0xC0000000U) == 0x40000000U &&
			    nop == 0x01000000U)
			{
				struct vm_area_struct *vma;
				unsigned long call_dl_resolve;

				down_read(&current->mm->mmap_sem);
				call_dl_resolve = current->mm->call_dl_resolve;
				up_read(&current->mm->mmap_sem);
				if (likely(call_dl_resolve))
					goto emulate;

				vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);

				down_write(&current->mm->mmap_sem);
				if (current->mm->call_dl_resolve) {
					call_dl_resolve = current->mm->call_dl_resolve;
					up_write(&current->mm->mmap_sem);
					if (vma)
						kmem_cache_free(vm_area_cachep, vma);
					goto emulate;
				}

				call_dl_resolve = get_unmapped_area(NULL, 0UL, PAGE_SIZE, 0UL, MAP_PRIVATE);
				if (!vma || (call_dl_resolve & ~PAGE_MASK)) {
					up_write(&current->mm->mmap_sem);
					if (vma)
						kmem_cache_free(vm_area_cachep, vma);
					return 1;
				}

				if (pax_insert_vma(vma, call_dl_resolve)) {
					up_write(&current->mm->mmap_sem);
					kmem_cache_free(vm_area_cachep, vma);
					return 1;
				}

				current->mm->call_dl_resolve = call_dl_resolve;
				up_write(&current->mm->mmap_sem);

emulate:
				regs->u_regs[UREG_G1] = (sethi & 0x003FFFFFU) << 10;
				regs->tpc = call_dl_resolve;
				regs->tnpc = addr+4;
				return 3;
			}
#endif

			/* PaX: glibc 2.4+ generates sethi/jmpl instead of save/call */
			if ((save & 0xFFC00000U) == 0x05000000U &&
			    (call & 0xFFFFE000U) == 0x85C0A000U &&
			    nop == 0x01000000U)
			{
				regs->u_regs[UREG_G1] = (sethi & 0x003FFFFFU) << 10;
				regs->u_regs[UREG_G2] = addr + 4;
				addr = (save & 0x003FFFFFU) << 10;
				addr += (((call | 0xFFFFFFFFFFFFE000UL) ^ 0x00001000UL) + 0x00001000UL);

				if (test_thread_flag(TIF_32BIT))
					addr &= 0xFFFFFFFFUL;

				regs->tpc = addr;
				regs->tnpc = addr+4;
				return 3;
			}

			/* PaX: 64-bit PLT stub */
			err = get_user(sethi1, (unsigned int *)addr);
			err |= get_user(sethi2, (unsigned int *)(addr+4));
			err |= get_user(or1, (unsigned int *)(addr+8));
			err |= get_user(or2, (unsigned int *)(addr+12));
			err |= get_user(sllx, (unsigned int *)(addr+16));
			err |= get_user(add, (unsigned int *)(addr+20));
			err |= get_user(jmpl, (unsigned int *)(addr+24));
			err |= get_user(nop, (unsigned int *)(addr+28));
			if (err)
				break;

			if ((sethi1 & 0xFFC00000U) == 0x09000000U &&
			    (sethi2 & 0xFFC00000U) == 0x0B000000U &&
			    (or1 & 0xFFFFE000U) == 0x88112000U &&
			    (or2 & 0xFFFFE000U) == 0x8A116000U &&
			    sllx == 0x89293020U &&
			    add == 0x8A010005U &&
			    jmpl == 0x89C14000U &&
			    nop == 0x01000000U)
			{
				regs->u_regs[UREG_G1] = (sethi & 0x003FFFFFU) << 10;
				regs->u_regs[UREG_G4] = ((sethi1 & 0x003FFFFFU) << 10) | (or1 & 0x000003FFU);
				regs->u_regs[UREG_G4] <<= 32;
				regs->u_regs[UREG_G5] = ((sethi2 & 0x003FFFFFU) << 10) | (or2 & 0x000003FFU);
				regs->u_regs[UREG_G5] += regs->u_regs[UREG_G4];
				regs->u_regs[UREG_G4] = addr + 24;
				addr = regs->u_regs[UREG_G5];
				regs->tpc = addr;
				regs->tnpc = addr+4;
				return 3;
			}
		}
	} while (0);

#ifdef CONFIG_PAX_DLRESOLVE
	do { /* PaX: unpatched PLT emulation step 2 */
		unsigned int save, call, nop;

		err = get_user(save, (unsigned int *)(regs->tpc-4));
		err |= get_user(call, (unsigned int *)regs->tpc);
		err |= get_user(nop, (unsigned int *)(regs->tpc+4));
		if (err)
			break;

		if (save == 0x9DE3BFA8U &&
		    (call & 0xC0000000U) == 0x40000000U &&
		    nop == 0x01000000U)
		{
			unsigned long dl_resolve = regs->tpc + ((((call | 0xFFFFFFFFC0000000UL) ^ 0x20000000UL) + 0x20000000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				dl_resolve &= 0xFFFFFFFFUL;

			regs->u_regs[UREG_RETPC] = regs->tpc;
			regs->tpc = dl_resolve;
			regs->tnpc = dl_resolve+4;
			return 3;
		}
	} while (0);
#endif

	do { /* PaX: patched PLT emulation #7, must be AFTER the unpatched PLT emulation */
		unsigned int sethi, ba, nop;

		err = get_user(sethi, (unsigned int *)regs->tpc);
		err |= get_user(ba, (unsigned int *)(regs->tpc+4));
		err |= get_user(nop, (unsigned int *)(regs->tpc+8));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    (ba & 0xFFF00000U) == 0x30600000U &&
		    nop == 0x01000000U)
		{
			unsigned long addr;

			addr = (sethi & 0x003FFFFFU) << 10;
			regs->u_regs[UREG_G1] = addr;
			addr = regs->tpc + ((((ba | 0xFFFFFFFFFFF80000UL) ^ 0x00040000UL) + 0x00040000UL) << 2);

			if (test_thread_flag(TIF_32BIT))
				addr &= 0xFFFFFFFFUL;

			regs->tpc = addr;
			regs->tnpc = addr+4;
			return 2;
		}
	} while (0);

#endif

	return 1;
}

void pax_report_insns(struct pt_regs *regs, void *pc, void *sp)
{
	unsigned long i;

	printk(KERN_ERR "PAX: bytes at PC: ");
	for (i = 0; i < 8; i++) {
		unsigned int c;
		if (get_user(c, (unsigned int *)pc+i))
			printk(KERN_CONT "???????? ");
		else
			printk(KERN_CONT "%08x ", c);
	}
	printk("\n");
}
#endif

asmlinkage void __kprobes do_sparc64_fault(struct pt_regs *regs)
{
	enum ctx_state prev_state = exception_enter();
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned int insn = 0;
	int si_code, fault_code, fault;
	unsigned long address, mm_rss;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	fault_code = get_thread_fault_code();

	if (notify_page_fault(regs))
		goto exit_exception;

	si_code = SEGV_MAPERR;
	address = current_thread_info()->fault_address;

	if ((fault_code & FAULT_CODE_ITLB) &&
	    (fault_code & FAULT_CODE_DTLB))
		BUG();

	if (test_thread_flag(TIF_32BIT)) {
		if (!(regs->tstate & TSTATE_PRIV)) {
			if (unlikely((regs->tpc >> 32) != 0)) {
				bogus_32bit_fault_tpc(regs);
				goto intr_or_no_mm;
			}
		}
		if (unlikely((address >> 32) != 0))
			goto intr_or_no_mm;
	}

	if (regs->tstate & TSTATE_PRIV) {
		unsigned long tpc = regs->tpc;

		/* Sanity check the PC. */
		if ((tpc >= KERNBASE && tpc < (unsigned long) __init_end) ||
		    (tpc >= MODULES_VADDR && tpc < MODULES_END)) {
			/* Valid, no problems... */
		} else {
			bad_kernel_pc(regs, address);
			goto exit_exception;
		}
	} else
		flags |= FAULT_FLAG_USER;

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (faulthandler_disabled() || !mm)
		goto intr_or_no_mm;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (!down_read_trylock(&mm->mmap_sem)) {
		if ((regs->tstate & TSTATE_PRIV) &&
		    !search_exception_tables(regs->tpc)) {
			insn = get_fault_insn(regs, insn);
			goto handle_kernel_fault;
		}

retry:
		down_read(&mm->mmap_sem);
	}

	if (fault_code & FAULT_CODE_BAD_RA)
		goto do_sigbus;

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;

#ifdef CONFIG_PAX_PAGEEXEC
	/* PaX: detect ITLB misses on non-exec pages */
	if ((mm->pax_flags & MF_PAX_PAGEEXEC) && vma->vm_start <= address &&
	    !(vma->vm_flags & VM_EXEC) && (fault_code & FAULT_CODE_ITLB))
	{
		if (address != regs->tpc)
			goto good_area;

		up_read(&mm->mmap_sem);
		switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUPLT
		case 2:
		case 3:
			return;
#endif

		}
		pax_report_fault(regs, (void *)regs->tpc, (void *)(regs->u_regs[UREG_FP] + STACK_BIAS));
		do_group_exit(SIGKILL);
	}
#endif

	/* Pure DTLB misses do not tell us whether the fault causing
	 * load/store/atomic was a write or not, it only says that there
	 * was no match.  So in such a case we (carefully) read the
	 * instruction to try and figure this out.  It's an optimization
	 * so it's ok if we can't do this.
	 *
	 * Special hack, window spill/fill knows the exact fault type.
	 */
	if (((fault_code &
	      (FAULT_CODE_DTLB | FAULT_CODE_WRITE | FAULT_CODE_WINFIXUP)) == FAULT_CODE_DTLB) &&
	    (vma->vm_flags & VM_WRITE) != 0) {
		insn = get_fault_insn(regs, 0);
		if (!insn)
			goto continue_fault;
		/* All loads, stores and atomics have bits 30 and 31 both set
		 * in the instruction.  Bit 21 is set in all stores, but we
		 * have to avoid prefetches which also have bit 21 set.
		 */
		if ((insn & 0xc0200000) == 0xc0200000 &&
		    (insn & 0x01780000) != 0x01680000) {
			/* Don't bother updating thread struct value,
			 * because update_mmu_cache only cares which tlb
			 * the access came from.
			 */
			fault_code |= FAULT_CODE_WRITE;
		}
	}
continue_fault:

	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (!(fault_code & FAULT_CODE_WRITE)) {
		/* Non-faulting loads shouldn't expand stack. */
		insn = get_fault_insn(regs, insn);
		if ((insn & 0xc0800000) == 0xc0800000) {
			unsigned char asi;

			if (insn & 0x2000)
				asi = (regs->tstate >> 24);
			else
				asi = (insn >> 5);
			if ((asi & 0xf2) == 0x82)
				goto bad_area;
		}
	}
	if (expand_stack(vma, address))
		goto bad_area;
	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
	si_code = SEGV_ACCERR;

	/* If we took a ITLB miss on a non-executable page, catch
	 * that here.
	 */
	if ((fault_code & FAULT_CODE_ITLB) && !(vma->vm_flags & VM_EXEC)) {
		WARN(address != regs->tpc,
		     "address (%lx) != regs->tpc (%lx)\n", address, regs->tpc);
		WARN_ON(regs->tstate & TSTATE_PRIV);
		goto bad_area;
	}

	if (fault_code & FAULT_CODE_WRITE) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;

		/* Spitfire has an icache which does not snoop
		 * processor stores.  Later processors do...
		 */
		if (tlb_type == spitfire &&
		    (vma->vm_flags & VM_EXEC) != 0 &&
		    vma->vm_file != NULL)
			set_thread_fault_code(fault_code |
					      FAULT_CODE_BLKCOMMIT);

		flags |= FAULT_FLAG_WRITE;
	} else {
		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
			goto bad_area;
	}

	fault = handle_mm_fault(vma, address, flags);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		goto exit_exception;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			current->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ,
				      1, regs, address);
		} else {
			current->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN,
				      1, regs, address);
		}
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;

			/* No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */

			goto retry;
		}
	}
	up_read(&mm->mmap_sem);

	mm_rss = get_mm_rss(mm);
#if defined(CONFIG_TRANSPARENT_HUGEPAGE)
	mm_rss -= (mm->context.thp_pte_count * (HPAGE_SIZE / PAGE_SIZE));
#endif
	if (unlikely(mm_rss >
		     mm->context.tsb_block[MM_TSB_BASE].tsb_rss_limit))
		tsb_grow(mm, MM_TSB_BASE, mm_rss);
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	mm_rss = mm->context.hugetlb_pte_count + mm->context.thp_pte_count;
	mm_rss *= REAL_HPAGE_PER_HPAGE;
	if (unlikely(mm_rss >
		     mm->context.tsb_block[MM_TSB_HUGE].tsb_rss_limit)) {
		if (mm->context.tsb_block[MM_TSB_HUGE].tsb)
			tsb_grow(mm, MM_TSB_HUGE, mm_rss);
		else
			hugetlb_setup(regs);

	}
#endif
exit_exception:
	exception_exit(prev_state);
	return;

	/*
	 * Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
bad_area:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);

handle_kernel_fault:
	do_kernel_fault(regs, si_code, fault_code, insn, address);
	goto exit_exception;

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);
	if (!(regs->tstate & TSTATE_PRIV)) {
		pagefault_out_of_memory();
		goto exit_exception;
	}
	goto handle_kernel_fault;

intr_or_no_mm:
	insn = get_fault_insn(regs, 0);
	goto handle_kernel_fault;

do_sigbus:
	insn = get_fault_insn(regs, insn);
	up_read(&mm->mmap_sem);

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	do_fault_siginfo(BUS_ADRERR, SIGBUS, regs, address, insn, fault_code);

	/* Kernel mode? Handle exceptions or die */
	if (regs->tstate & TSTATE_PRIV)
		goto handle_kernel_fault;
}
