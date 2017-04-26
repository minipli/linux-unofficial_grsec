#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/grinternal.h>
#include <linux/security.h>

void
gr_audit_ptrace(struct task_struct *task)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_PTRACE
	if (grsec_enable_audit_ptrace)
		gr_log_ptrace(GR_DO_AUDIT, GR_PTRACE_AUDIT_MSG, task);
#endif
	return;
}

int
gr_ptrace_readexec(struct file *file, int unsafe_flags)
{
#ifdef CONFIG_GRKERNSEC_PTRACE_READEXEC
	const struct dentry *dentry = file->f_path.dentry;
	const struct vfsmount *mnt = file->f_path.mnt;

	if (grsec_enable_ptrace_readexec && (unsafe_flags & LSM_UNSAFE_PTRACE) && 
	    (inode_permission(d_backing_inode(dentry), MAY_READ) || !gr_acl_handle_open(dentry, mnt, MAY_READ))) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_PTRACE_READEXEC_MSG, dentry, mnt);
		return -EACCES;
	}
#endif
	return 0;
}
