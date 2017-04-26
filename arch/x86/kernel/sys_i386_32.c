/*
 * This file contains various random system calls that
 * have a non-standard calling sequence on the Linux/i386
 * platform.
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/ipc.h>
#include <linux/elf.h>

#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/syscalls.h>

int i386_mmap_check(unsigned long addr, unsigned long len, unsigned long flags)
{
	unsigned long pax_task_size = TASK_SIZE;

#ifdef CONFIG_PAX_SEGMEXEC
	if (current->mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	if (flags & MAP_FIXED)
		if (len > pax_task_size || addr > pax_task_size - len)
			return -EINVAL;

	return 0;
}

/*
 * Align a virtual address to avoid aliasing in the I$ on AMD F15h.
 */
static unsigned long get_align_mask(void)
{
	if (va_align.flags < 0 || !(va_align.flags & ALIGN_VA_32))
		return 0;

	if (!(current->flags & PF_RANDOMIZE))
		return 0;

	return va_align.mask;
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long pax_task_size = TASK_SIZE;
	struct vm_unmapped_area_info info;
	unsigned long offset = gr_rand_threadstack_offset(mm, filp, flags);

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	pax_task_size -= PAGE_SIZE;

	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	if (addr) {
		addr = PAGE_ALIGN(addr);
		if (pax_task_size - len >= addr) {
			vma = find_vma(mm, addr);
			if (check_heap_stack_gap(vma, addr, len, offset))
				return addr;
		}
	}

	info.flags = 0;
	info.length = len;
	info.align_mask = filp ? get_align_mask() : 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	info.threadstack_offset = offset;

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE)) {
		info.low_limit = 0x00110000UL;
		info.high_limit = mm->start_code;

#ifdef CONFIG_PAX_RANDMMAP
		if (mm->pax_flags & MF_PAX_RANDMMAP)
			info.low_limit += mm->delta_mmap & 0x03FFF000UL;
#endif

		if (info.low_limit < info.high_limit) {
			addr = vm_unmapped_area(&info);
			if (!IS_ERR_VALUE(addr))
				return addr;
		}
	} else
#endif

	info.low_limit = mm->mmap_base;
	info.high_limit = pax_task_size;

	return vm_unmapped_area(&info);
}

unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr0,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0, pax_task_size = TASK_SIZE;
	struct vm_unmapped_area_info info;
	unsigned long offset = gr_rand_threadstack_offset(mm, filp, flags);

#ifdef CONFIG_PAX_SEGMEXEC
	if (mm->pax_flags & MF_PAX_SEGMEXEC)
		pax_task_size = SEGMEXEC_TASK_SIZE;
#endif

	pax_task_size -= PAGE_SIZE;

	/* requested length too big for entire address space */
	if (len > pax_task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

#ifdef CONFIG_PAX_PAGEEXEC
	if (!(__supported_pte_mask & _PAGE_NX) && (mm->pax_flags & MF_PAX_PAGEEXEC) && (flags & MAP_EXECUTABLE))
		goto bottomup;
#endif

#ifdef CONFIG_PAX_RANDMMAP
	if (!(mm->pax_flags & MF_PAX_RANDMMAP))
#endif

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		if (pax_task_size - len >= addr) {
			vma = find_vma(mm, addr);
			if (check_heap_stack_gap(vma, addr, len, offset))
				return addr;
		}
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = mm->mmap_base;
	info.align_mask = filp ? get_align_mask() : 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	info.threadstack_offset = offset;

	addr = vm_unmapped_area(&info);
	if (!(addr & ~PAGE_MASK))
		return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
}
