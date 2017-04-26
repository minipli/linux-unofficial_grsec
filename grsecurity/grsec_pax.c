#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/grinternal.h>
#include <linux/grsecurity.h>

void
gr_log_textrel(struct vm_area_struct * vma, bool is_textrel_rw)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_textrel_ulong_ulong(GR_DONT_AUDIT, GR_TEXTREL_AUDIT_MSG,
			is_textrel_rw ? "executable to writable" : "writable to executable",
			vma->vm_file, vma->vm_start, vma->vm_pgoff);
#endif
	return;
}

void gr_log_ptgnustack(struct file *file)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_rwxmap(GR_DONT_AUDIT, GR_PTGNUSTACK_MSG, file);
#endif
	return;
}

void
gr_log_rwxmmap(struct file *file)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_rwxmap(GR_DONT_AUDIT, GR_RWXMMAP_MSG, file);
#endif
	return;
}

void
gr_log_rwxmprotect(struct vm_area_struct *vma)
{
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	if (grsec_enable_log_rwxmaps)
		gr_log_rwxmap_vma(GR_DONT_AUDIT, GR_RWXMPROTECT_MSG, vma);
#endif
	return;
}
