/*
 *  linux/arch/alpha/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/io.h>

#define __EXTERN_INLINE inline
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#undef  __EXTERN_INLINE

#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/uaccess.h>

extern void die_if_kernel(char *,struct pt_regs *,long, unsigned long *);


/*
 * Force a new ASN for a task.
 */

#ifndef CONFIG_SMP
unsigned long last_asn = ASN_FIRST_VERSION;
#endif

void
__load_new_mm_context(struct mm_struct *next_mm)
{
	unsigned long mmc;
	struct pcb_struct *pcb;

	mmc = __get_new_mm_context(next_mm, smp_processor_id());
	next_mm->context[smp_processor_id()] = mmc;

	pcb = &current_thread_info()->pcb;
	pcb->asn = mmc & HARDWARE_ASN_MASK;
	pcb->ptbr = ((unsigned long) next_mm->pgd - IDENT_ADDR) >> PAGE_SHIFT;

	__reload_thread(pcb);
}

#ifdef CONFIG_PAX_PAGEEXEC
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
		unsigned int ldah, ldq, jmp;

		err = get_user(ldah, (unsigned int *)regs->pc);
		err |= get_user(ldq, (unsigned int *)(regs->pc+4));
		err |= get_user(jmp, (unsigned int *)(regs->pc+8));

		if (err)
			break;

		if ((ldah & 0xFFFF0000U) == 0x277B0000U &&
		    (ldq & 0xFFFF0000U) == 0xA77B0000U &&
		    jmp == 0x6BFB0000U)
		{
			unsigned long r27, addr;
			unsigned long addrh = (ldah | 0xFFFFFFFFFFFF0000UL) << 16;
			unsigned long addrl = ldq | 0xFFFFFFFFFFFF0000UL;

			addr = regs->r27 + ((addrh ^ 0x80000000UL) + 0x80000000UL) + ((addrl ^ 0x8000UL) + 0x8000UL);
			err = get_user(r27, (unsigned long *)addr);
			if (err)
				break;

			regs->r27 = r27;
			regs->pc = r27;
			return 2;
		}
	} while (0);

	do { /* PaX: patched PLT emulation #2 */
		unsigned int ldah, lda, br;

		err = get_user(ldah, (unsigned int *)regs->pc);
		err |= get_user(lda, (unsigned int *)(regs->pc+4));
		err |= get_user(br, (unsigned int *)(regs->pc+8));

		if (err)
			break;

		if ((ldah & 0xFFFF0000U) == 0x277B0000U &&
		    (lda & 0xFFFF0000U) == 0xA77B0000U &&
		    (br & 0xFFE00000U) == 0xC3E00000U)
		{
			unsigned long addr = br | 0xFFFFFFFFFFE00000UL;
			unsigned long addrh = (ldah | 0xFFFFFFFFFFFF0000UL) << 16;
			unsigned long addrl = lda | 0xFFFFFFFFFFFF0000UL;

			regs->r27 += ((addrh ^ 0x80000000UL) + 0x80000000UL) + ((addrl ^ 0x8000UL) + 0x8000UL);
			regs->pc += 12 + (((addr ^ 0x00100000UL) + 0x00100000UL) << 2);
			return 2;
		}
	} while (0);

	do { /* PaX: unpatched PLT emulation */
		unsigned int br;

		err = get_user(br, (unsigned int *)regs->pc);

		if (!err && (br & 0xFFE00000U) == 0xC3800000U) {
			unsigned int br2, ldq, nop, jmp;
			unsigned long addr = br | 0xFFFFFFFFFFE00000UL, resolver;

			addr = regs->pc + 4 + (((addr ^ 0x00100000UL) + 0x00100000UL) << 2);
			err = get_user(br2, (unsigned int *)addr);
			err |= get_user(ldq, (unsigned int *)(addr+4));
			err |= get_user(nop, (unsigned int *)(addr+8));
			err |= get_user(jmp, (unsigned int *)(addr+12));
			err |= get_user(resolver, (unsigned long *)(addr+16));

			if (err)
				break;

			if (br2 == 0xC3600000U &&
			    ldq == 0xA77B000CU &&
			    nop == 0x47FF041FU &&
			    jmp == 0x6B7B0000U)
			{
				regs->r28 = regs->pc+4;
				regs->r27 = addr+16;
				regs->pc = resolver;
				return 3;
			}
		}
	} while (0);
#endif

	return 1;
}

void pax_report_insns(struct pt_regs *regs, void *pc, void *sp)
{
	unsigned long i;

	printk(KERN_ERR "PAX: bytes at PC: ");
	for (i = 0; i < 5; i++) {
		unsigned int c;
		if (get_user(c, (unsigned int *)pc+i))
			printk(KERN_CONT "???????? ");
		else
			printk(KERN_CONT "%08x ", c);
	}
	printk("\n");
}
#endif

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to handle_mm_fault().
 *
 * mmcsr:
 *	0 = translation not valid
 *	1 = access violation
 *	2 = fault-on-read
 *	3 = fault-on-execute
 *	4 = fault-on-write
 *
 * cause:
 *	-1 = instruction fetch
 *	0 = load
 *	1 = store
 *
 * Registers $9 through $15 are saved in a block just prior to `regs' and
 * are saved and restored around the call to allow exception code to
 * modify them.
 */

/* Macro for exception fixup code to access integer registers.  */
#define dpf_reg(r)							\
	(((unsigned long *)regs)[(r) <= 8 ? (r) : (r) <= 15 ? (r)-16 :	\
				 (r) <= 18 ? (r)+8 : (r)-10])

asmlinkage void
do_page_fault(unsigned long address, unsigned long mmcsr,
	      long cause, struct pt_regs *regs)
{
	struct vm_area_struct * vma;
	struct mm_struct *mm = current->mm;
	const struct exception_table_entry *fixup;
	int fault, si_code = SEGV_MAPERR;
	siginfo_t info;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	/* As of EV6, a load into $31/$f31 is a prefetch, and never faults
	   (or is suppressed by the PALcode).  Support that for older CPUs
	   by ignoring such an instruction.  */
	if (cause == 0) {
		unsigned int insn;
		__get_user(insn, (unsigned int __user *)regs->pc);
		if ((insn >> 21 & 0x1f) == 0x1f &&
		    /* ldq ldl ldt lds ldg ldf ldwu ldbu */
		    (1ul << (insn >> 26) & 0x30f00001400ul)) {
			regs->pc += 4;
			return;
		}
	}

	/* If we're in an interrupt context, or have no user context,
	   we must not take the fault.  */
	if (!mm || faulthandler_disabled())
		goto no_context;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
	if (address >= TASK_SIZE)
		goto vmalloc_fault;
#endif
	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;
retry:
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

	/* Ok, we have a good vm_area for this memory access, so
	   we can handle it.  */
 good_area:
	si_code = SEGV_ACCERR;
	if (cause < 0) {
		if (!(vma->vm_flags & VM_EXEC)) {

#ifdef CONFIG_PAX_PAGEEXEC
			if (!(mm->pax_flags & MF_PAX_PAGEEXEC) || address != regs->pc)
				goto bad_area;

			up_read(&mm->mmap_sem);
			switch (pax_handle_fetch_fault(regs)) {

#ifdef CONFIG_PAX_EMUPLT
			case 2:
			case 3:
				return;
#endif

			}
			pax_report_fault(regs, (void *)regs->pc, (void *)rdusp());
			do_group_exit(SIGKILL);
#else
			goto bad_area;
#endif

		}
	} else if (!cause) {
		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
			goto bad_area;
	} else {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	}

	/* If for any reason at all we couldn't handle the fault,
	   make sure we exit gracefully rather than endlessly redo
	   the fault.  */
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
		if (fault & VM_FAULT_MAJOR)
			current->maj_flt++;
		else
			current->min_flt++;
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;

			 /* No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */

			goto retry;
		}
	}

	up_read(&mm->mmap_sem);

	return;

	/* Something tried to access memory that isn't in our memory map.
	   Fix it, but check if it's kernel or user first.  */
 bad_area:
	up_read(&mm->mmap_sem);

	if (user_mode(regs))
		goto do_sigsegv;

 no_context:
	/* Are we prepared to handle this fault as an exception?  */
	if ((fixup = search_exception_tables(regs->pc)) != 0) {
		unsigned long newpc;
		newpc = fixup_exception(dpf_reg, fixup, regs->pc);
		regs->pc = newpc;
		return;
	}

	/* Oops. The kernel tried to access some bad page. We'll have to
	   terminate things with extreme prejudice.  */
	printk(KERN_ALERT "Unable to handle kernel paging request at "
	       "virtual address %016lx\n", address);
	die_if_kernel("Oops", regs, cause, (unsigned long*)regs - 16);
	do_exit(SIGKILL);

	/* We ran out of memory, or some other thing happened to us that
	   made us unable to handle the page fault gracefully.  */
 out_of_memory:
	up_read(&mm->mmap_sem);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

 do_sigbus:
	up_read(&mm->mmap_sem);
	/* Send a sigbus, regardless of whether we were in kernel
	   or user mode.  */
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void __user *) address;
	force_sig_info(SIGBUS, &info, current);
	if (!user_mode(regs))
		goto no_context;
	return;

 do_sigsegv:
	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code = si_code;
	info.si_addr = (void __user *) address;
	force_sig_info(SIGSEGV, &info, current);
	return;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
 vmalloc_fault:
	if (user_mode(regs))
		goto do_sigsegv;
	else {
		/* Synchronize this task's top level page-table
		   with the "reference" page table from init.  */
		long index = pgd_index(address);
		pgd_t *pgd, *pgd_k;

		pgd = current->active_mm->pgd + index;
		pgd_k = swapper_pg_dir + index;
		if (!pgd_present(*pgd) && pgd_present(*pgd_k)) {
			pgd_val(*pgd) = pgd_val(*pgd_k);
			return;
		}
		goto no_context;
	}
#endif
}
