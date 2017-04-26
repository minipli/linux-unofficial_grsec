#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

void
gr_log_chdir(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_AUDIT_CHDIR
	if ((grsec_enable_chdir && grsec_enable_group &&
	     in_group_p(grsec_audit_gid)) || (grsec_enable_chdir &&
					      !grsec_enable_group)) {
		gr_log_fs_generic(GR_DO_AUDIT, GR_CHDIR_AUDIT_MSG, dentry, mnt);
	}
#endif
	return;
}
