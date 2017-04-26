#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/grinternal.h>

void gr_handle_msr_write(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_MSRWRITE_MSG);
	return;
}
EXPORT_SYMBOL_GPL(gr_handle_msr_write);

void
gr_handle_ioperm(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_IOPERM_MSG);
	return;
}

void
gr_handle_iopl(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_IOPL_MSG);
	return;
}

void
gr_handle_mem_readwrite(u64 from, u64 to)
{
	gr_log_two_u64(GR_DONT_AUDIT, GR_MEM_READWRITE_MSG, from, to);
	return;
}

void
gr_handle_vm86(void)
{
	gr_log_noargs(GR_DONT_AUDIT, GR_VM86_MSG);
	return;
}

void
gr_log_badprocpid(const char *entry)
{
	gr_log_str(GR_DONT_AUDIT, GR_BADPROCPID_MSG, entry);
	return;
}
