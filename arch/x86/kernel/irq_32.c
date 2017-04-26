/*
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the lowest level x86-specific interrupt
 * entry, irq-stacks and irq statistics code. All the remaining
 * irq logic is done by the generic kernel/irq/ code and
 * by the x86-specific irq controller code. (e.g. i8259.c and
 * io_apic.c.)
 */

#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>
#include <linux/mm.h>

#include <asm/apic.h>

#ifdef CONFIG_DEBUG_STACKOVERFLOW

extern void gr_handle_kernel_exploit(void);

int sysctl_panic_on_stackoverflow __read_mostly;

/* Debugging check for stack overflow: is there less than 1KB free? */
static int check_stack_overflow(void)
{
	long sp;

	__asm__ __volatile__("andl %%esp,%0" :
			     "=r" (sp) : "0" (THREAD_SIZE - 1));

	return sp < STACK_WARN;
}

static asmlinkage void print_stack_overflow(void)
{
	printk(KERN_WARNING "low stack detected by irq handler\n");
	dump_stack();
	gr_handle_kernel_exploit();
	if (sysctl_panic_on_stackoverflow)
		panic("low stack detected by irq handler - check messages\n");
}

#else
static inline int check_stack_overflow(void) { return 0; }
static asmlinkage void print_stack_overflow(void) { }
#endif

DEFINE_PER_CPU(struct irq_stack *, hardirq_stack);
DEFINE_PER_CPU(struct irq_stack *, softirq_stack);

static void call_on_stack(void (asmlinkage *func)(void), void *stack)
{
	asm volatile("xchgl	%%ebx,%%esp	\n"
		     PAX_INDIRECT_CALL("*%%edi", "__do_softirq") "\n"
		     "movl	%%ebx,%%esp	\n"
		     : "=b" (stack)
		     : "0" (stack),
		       "D"(func)
		     : "memory", "cc", "edx", "ecx", "eax");
}

static inline void *current_stack(void)
{
	return (void *)(current_stack_pointer() & ~(THREAD_SIZE - 1));
}

static inline int execute_on_irq_stack(int overflow, struct irq_desc *desc)
{
	struct irq_stack *irqstk;
	u32 *isp, *prev_esp, arg1;

	irqstk = __this_cpu_read(hardirq_stack);

	/*
	 * this is where we switch to the IRQ stack. However, if we are
	 * already using the IRQ stack (because we interrupted a hardirq
	 * handler) we can't do that and just have to keep using the
	 * current stack (which is the irq stack already after all)
	 */
	if (unlikely((void *)current_stack_pointer - (void *)irqstk < THREAD_SIZE))
		return 0;

	isp = (u32 *) ((char *)irqstk + sizeof(*irqstk) - 8);

	/* Save the next esp at the bottom of the stack */
	prev_esp = (u32 *)irqstk;
	*prev_esp = current_stack_pointer();

#ifdef CONFIG_PAX_MEMORY_UDEREF
	__set_fs(MAKE_MM_SEG(0));
#endif

	if (unlikely(overflow))
		call_on_stack(print_stack_overflow, isp);

	asm volatile("xchgl	%%ebx,%%esp	\n"
		     PAX_INDIRECT_CALL("*%%edi", "handle_bad_irq") "\n"
		     "movl	%%ebx,%%esp	\n"
		     : "=a" (arg1), "=b" (isp)
		     :  "0" (desc),   "1" (isp),
			"D" (desc->handle_irq)
		     : "memory", "cc", "ecx");

#ifdef CONFIG_PAX_MEMORY_UDEREF
	__set_fs(current->thread.addr_limit);
#endif

	return 1;
}

/*
 * allocate per-cpu stacks for hardirq and for softirq processing
 */
void irq_ctx_init(int cpu)
{
	if (per_cpu(hardirq_stack, cpu))
		return;

	per_cpu(hardirq_stack, cpu) = page_address(alloc_pages_node(cpu_to_node(cpu), THREADINFO_GFP, THREAD_SIZE_ORDER));
	per_cpu(softirq_stack, cpu) = page_address(alloc_pages_node(cpu_to_node(cpu), THREADINFO_GFP, THREAD_SIZE_ORDER));
}

void do_softirq_own_stack(void)
{
	struct irq_stack *irqstk;
	u32 *isp, *prev_esp;

	irqstk = __this_cpu_read(softirq_stack);

	/* build the stack frame on the softirq stack */
	isp = (u32 *) ((char *)irqstk + sizeof(*irqstk));

	/* Push the previous esp onto the stack */
	prev_esp = (u32 *)irqstk;
	*prev_esp = current_stack_pointer();

#ifdef CONFIG_PAX_MEMORY_UDEREF
	__set_fs(MAKE_MM_SEG(0));
#endif

	call_on_stack(__do_softirq, isp);

#ifdef CONFIG_PAX_MEMORY_UDEREF
	__set_fs(current->thread.addr_limit);
#endif

}

bool handle_irq(struct irq_desc *desc, struct pt_regs *regs)
{
	int overflow = check_stack_overflow();

	if (IS_ERR_OR_NULL(desc))
		return false;

	if (user_mode(regs) || !execute_on_irq_stack(overflow, desc)) {
		if (unlikely(overflow))
			print_stack_overflow();
		generic_handle_irq_desc(desc);
	}

	return true;
}
