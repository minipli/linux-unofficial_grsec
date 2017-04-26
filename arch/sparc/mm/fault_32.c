/*
 * fault.c:  Page fault handlers for the Sparc.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 * Copyright (C) 1996 Eddie C. Dost (ecd@skynet.be)
 * Copyright (C) 1997 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 */

#include <asm/head.h>

#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/threads.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/perf_event.h>
#include <linux/interrupt.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/compiler.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/openprom.h>
#include <asm/oplib.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/traps.h>

#include "mm_32.h"

int show_unhandled_signals = 1;

static void __noreturn unhandled_fault(unsigned long address,
				       struct task_struct *tsk,
				       struct pt_regs *regs)
{
	if ((unsigned long) address < PAGE_SIZE) {
		printk(KERN_ALERT
		    "Unable to handle kernel NULL pointer dereference\n");
	} else {
		printk(KERN_ALERT "Unable to handle kernel paging request at virtual address %08lx\n",
		       address);
	}
	printk(KERN_ALERT "tsk->{mm,active_mm}->context = %08lx\n",
		(tsk->mm ? tsk->mm->context : tsk->active_mm->context));
	printk(KERN_ALERT "tsk->{mm,active_mm}->pgd = %08lx\n",
		(tsk->mm ? (unsigned long) tsk->mm->pgd :
			(unsigned long) tsk->active_mm->pgd));
	die_if_kernel("Oops", regs);
}

asmlinkage int lookup_fault(unsigned long pc, unsigned long ret_pc,
			    unsigned long address)
{
	struct pt_regs regs;
	unsigned long g2;
	unsigned int insn;
	int i;

	i = search_extables_range(ret_pc, &g2);
	switch (i) {
	case 3:
		/* load & store will be handled by fixup */
		return 3;

	case 1:
		/* store will be handled by fixup, load will bump out */
		/* for _to_ macros */
		insn = *((unsigned int *) pc);
		if ((insn >> 21) & 1)
			return 1;
		break;

	case 2:
		/* load will be handled by fixup, store will bump out */
		/* for _from_ macros */
		insn = *((unsigned int *) pc);
		if (!((insn >> 21) & 1) || ((insn>>19)&0x3f) == 15)
			return 2;
		break;

	default:
		break;
	}

	memset(&regs, 0, sizeof(regs));
	regs.pc = pc;
	regs.npc = pc + 4;
	__asm__ __volatile__(
		"rd %%psr, %0\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n" : "=r" (regs.psr));
	unhandled_fault(address, current, &regs);

	/* Not reached */
	return 0;
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
	       (void *)regs->pc, (void *)regs->u_regs[UREG_I7],
	       (void *)regs->u_regs[UREG_FP], code);

	print_vma_addr(KERN_CONT " in ", regs->pc);

	printk(KERN_CONT "\n");
}

static void __do_fault_siginfo(int code, int sig, struct pt_regs *regs,
			       unsigned long addr)
{
	siginfo_t info;

	info.si_signo = sig;
	info.si_code = code;
	info.si_errno = 0;
	info.si_addr = (void __user *) addr;
	info.si_trapno = 0;

	if (unlikely(show_unhandled_signals))
		show_signal_msg(regs, sig, info.si_code,
				addr, current);

	force_sig_info (sig, &info, current);
}

static unsigned long compute_si_addr(struct pt_regs *regs, int text_fault)
{
	unsigned int insn;

	if (text_fault)
		return regs->pc;

	if (regs->psr & PSR_PS)
		insn = *(unsigned int *) regs->pc;
	else
		__get_user(insn, (unsigned int *) regs->pc);

	return safe_compute_effective_address(regs, insn);
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
 * PaX: decide what to do with offenders (regs->pc = fault address)
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

		err = get_user(sethi1, (unsigned int *)regs->pc);
		err |= get_user(sethi2, (unsigned int *)(regs->pc+4));
		err |= get_user(jmpl, (unsigned int *)(regs->pc+8));

		if (err)
			break;

		if ((sethi1 & 0xFFC00000U) == 0x03000000U &&
		    (sethi2 & 0xFFC00000U) == 0x03000000U &&
		    (jmpl & 0xFFFFE000U) == 0x81C06000U)
		{
			unsigned int addr;

			regs->u_regs[UREG_G1] = (sethi2 & 0x003FFFFFU) << 10;
			addr = regs->u_regs[UREG_G1];
			addr += (((jmpl | 0xFFFFE000U) ^ 0x00001000U) + 0x00001000U);
			regs->pc = addr;
			regs->npc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #2 */
		unsigned int ba;

		err = get_user(ba, (unsigned int *)regs->pc);

		if (err)
			break;

		if ((ba & 0xFFC00000U) == 0x30800000U || (ba & 0xFFF80000U) == 0x30480000U) {
			unsigned int addr;

			if ((ba & 0xFFC00000U) == 0x30800000U)
				addr = regs->pc + ((((ba | 0xFFC00000U) ^ 0x00200000U) + 0x00200000U) << 2);
			else
				addr = regs->pc + ((((ba | 0xFFF80000U) ^ 0x00040000U) + 0x00040000U) << 2);
			regs->pc = addr;
			regs->npc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #3 */
		unsigned int sethi, bajmpl, nop;

		err = get_user(sethi, (unsigned int *)regs->pc);
		err |= get_user(bajmpl, (unsigned int *)(regs->pc+4));
		err |= get_user(nop, (unsigned int *)(regs->pc+8));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    ((bajmpl & 0xFFFFE000U) == 0x81C06000U || (bajmpl & 0xFFF80000U) == 0x30480000U) &&
		    nop == 0x01000000U)
		{
			unsigned int addr;

			addr = (sethi & 0x003FFFFFU) << 10;
			regs->u_regs[UREG_G1] = addr;
			if ((bajmpl & 0xFFFFE000U) == 0x81C06000U)
				addr += (((bajmpl | 0xFFFFE000U) ^ 0x00001000U) + 0x00001000U);
			else
				addr = regs->pc + ((((bajmpl | 0xFFF80000U) ^ 0x00040000U) + 0x00040000U) << 2);
			regs->pc = addr;
			regs->npc = addr+4;
			return 2;
		}
	} while (0);

	do { /* PaX: unpatched PLT emulation step 1 */
		unsigned int sethi, ba, nop;

		err = get_user(sethi, (unsigned int *)regs->pc);
		err |= get_user(ba, (unsigned int *)(regs->pc+4));
		err |= get_user(nop, (unsigned int *)(regs->pc+8));

		if (err)
			break;

		if ((sethi & 0xFFC00000U) == 0x03000000U &&
		    ((ba & 0xFFC00000U) == 0x30800000U || (ba & 0xFFF80000U) == 0x30680000U) &&
		    nop == 0x01000000U)
		{
			unsigned int addr, save, call;

			if ((ba & 0xFFC00000U) == 0x30800000U)
				addr = regs->pc + 4 + ((((ba | 0xFFC00000U) ^ 0x00200000U) + 0x00200000U) << 2);
			else
				addr = regs->pc + 4 + ((((ba | 0xFFF80000U) ^ 0x00040000U) + 0x00040000U) << 2);

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
				regs->pc = call_dl_resolve;
				regs->npc = addr+4;
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
				addr += (((call | 0xFFFFE000U) ^ 0x00001000U) + 0x00001000U);
				regs->pc = addr;
				regs->npc = addr+4;
				return 3;
			}
		}
	} while (0);

	do { /* PaX: unpatched PLT emulation step 2 */
		unsigned int save, call, nop;

		err = get_user(save, (unsigned int *)(regs->pc-4));
		err |= get_user(call, (unsigned int *)regs->pc);
		err |= get_user(nop, (unsigned int *)(regs->pc+4));
		if (err)
			break;

		if (save == 0x9DE3BFA8U &&
		    (call & 0xC0000000U) == 0x40000000U &&
		    nop == 0x01000000U)
		{
			unsigned int dl_resolve = regs->pc + ((((call | 0xC0000000U) ^ 0x20000000U) + 0x20000000U) << 2);

			regs->u_regs[UREG_RETPC] = regs->pc;
			regs->pc = dl_resolve;
			regs->npc = dl_resolve+4;
			return 3;
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

static noinline void do_fault_siginfo(int code, int sig, struct pt_regs *regs,
				      int text_fault)
{
	unsigned long addr = compute_si_addr(regs, text_fault);

	__do_fault_siginfo(code, sig, regs, addr);
}

asmlinkage void do_sparc_fault(struct pt_regs *regs, int text_fault, int write,
			       unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	unsigned int fixup;
	unsigned long g2;
	int from_user = !(regs->psr & PSR_PS);
	int fault, code;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	if (text_fault)
		address = regs->pc;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
	code = SEGV_MAPERR;
	if (address >= TASK_SIZE)
		goto vmalloc_fault;

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (pagefault_disabled() || !mm)
		goto no_context;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

retry:
	down_read(&mm->mmap_sem);

	if (!from_user && address >= PAGE_OFFSET)
		goto bad_area;

	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;
	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
	code = SEGV_ACCERR;
	if (write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	} else {

#ifdef CONFIG_PAX_PAGEEXEC
		if ((mm->pax_flags & MF_PAX_PAGEEXEC) && text_fault && !(vma->vm_flags & VM_EXEC)) {
			up_read(&mm->mmap_sem);
			switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUPLT
			case 2:
			case 3:
				return;
#endif

			}
			pax_report_fault(regs, (void *)regs->pc, (void *)regs->u_regs[UREG_FP]);
			do_group_exit(SIGKILL);
		}
#endif

		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
			goto bad_area;
	}

	if (from_user)
		flags |= FAULT_FLAG_USER;
	if (write)
		flags |= FAULT_FLAG_WRITE;

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, address, flags);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return;

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
	return;

	/*
	 * Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	/* User mode accesses just cause a SIGSEGV */
	if (from_user) {
		do_fault_siginfo(code, SIGSEGV, regs, text_fault);
		return;
	}

	/* Is this in ex_table? */
no_context:
	g2 = regs->u_regs[UREG_G2];
	if (!from_user) {
		fixup = search_extables_range(regs->pc, &g2);
		/* Values below 10 are reserved for other things */
		if (fixup > 10) {
			extern const unsigned int __memset_start[];
			extern const unsigned int __memset_end[];
			extern const unsigned int __csum_partial_copy_start[];
			extern const unsigned int __csum_partial_copy_end[];

#ifdef DEBUG_EXCEPTIONS
			printk("Exception: PC<%08lx> faddr<%08lx>\n",
			       regs->pc, address);
			printk("EX_TABLE: insn<%08lx> fixup<%08x> g2<%08lx>\n",
				regs->pc, fixup, g2);
#endif
			if ((regs->pc >= (unsigned long)__memset_start &&
			     regs->pc < (unsigned long)__memset_end) ||
			    (regs->pc >= (unsigned long)__csum_partial_copy_start &&
			     regs->pc < (unsigned long)__csum_partial_copy_end)) {
				regs->u_regs[UREG_I4] = address;
				regs->u_regs[UREG_I5] = regs->pc;
			}
			regs->u_regs[UREG_G2] = g2;
			regs->pc = fixup;
			regs->npc = regs->pc + 4;
			return;
		}
	}

	unhandled_fault(address, tsk, regs);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (from_user) {
		pagefault_out_of_memory();
		return;
	}
	goto no_context;

do_sigbus:
	up_read(&mm->mmap_sem);
	do_fault_siginfo(BUS_ADRERR, SIGBUS, regs, text_fault);
	if (!from_user)
		goto no_context;

vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 */
		int offset = pgd_index(address);
		pgd_t *pgd, *pgd_k;
		pmd_t *pmd, *pmd_k;

		pgd = tsk->active_mm->pgd + offset;
		pgd_k = init_mm.pgd + offset;

		if (!pgd_present(*pgd)) {
			if (!pgd_present(*pgd_k))
				goto bad_area_nosemaphore;
			pgd_val(*pgd) = pgd_val(*pgd_k);
			return;
		}

		pmd = pmd_offset(pgd, address);
		pmd_k = pmd_offset(pgd_k, address);

		if (pmd_present(*pmd) || !pmd_present(*pmd_k))
			goto bad_area_nosemaphore;

		*pmd = *pmd_k;
		return;
	}
}

/* This always deals with user addresses. */
static void force_user_fault(unsigned long address, int write)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	unsigned int flags = FAULT_FLAG_USER;
	int code;

	code = SEGV_MAPERR;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;
good_area:
	code = SEGV_ACCERR;
	if (write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	} else {
		if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
			goto bad_area;
	}
	switch (handle_mm_fault(vma, address, flags)) {
	case VM_FAULT_SIGBUS:
	case VM_FAULT_OOM:
		goto do_sigbus;
	}
	up_read(&mm->mmap_sem);
	return;
bad_area:
	up_read(&mm->mmap_sem);
	__do_fault_siginfo(code, SIGSEGV, tsk->thread.kregs, address);
	return;

do_sigbus:
	up_read(&mm->mmap_sem);
	__do_fault_siginfo(BUS_ADRERR, SIGBUS, tsk->thread.kregs, address);
}

static void check_stack_aligned(unsigned long sp)
{
	if (sp & 0x7UL)
		force_sig(SIGILL, current);
}

void window_overflow_fault(void)
{
	unsigned long sp;

	sp = current_thread_info()->rwbuf_stkptrs[0];
	if (((sp + 0x38) & PAGE_MASK) != (sp & PAGE_MASK))
		force_user_fault(sp + 0x38, 1);
	force_user_fault(sp, 1);

	check_stack_aligned(sp);
}

void window_underflow_fault(unsigned long sp)
{
	if (((sp + 0x38) & PAGE_MASK) != (sp & PAGE_MASK))
		force_user_fault(sp + 0x38, 0);
	force_user_fault(sp, 0);

	check_stack_aligned(sp);
}

void window_ret_fault(struct pt_regs *regs)
{
	unsigned long sp;

	sp = regs->u_regs[UREG_FP];
	if (((sp + 0x38) & PAGE_MASK) != (sp & PAGE_MASK))
		force_user_fault(sp + 0x38, 0);
	force_user_fault(sp, 0);

	check_stack_aligned(sp);
}
