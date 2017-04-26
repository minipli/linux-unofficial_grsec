#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/grinternal.h>

int gr_get_symlinkown_enabled(void)
{
#ifdef CONFIG_GRKERNSEC_SYMLINKOWN
	if (grsec_enable_symlinkown && in_group_p(grsec_symlinkown_gid))
		return 1;
#endif
	return 0;
}

int gr_handle_symlink_owner(const struct path *link, const struct inode *target)
{
#ifdef CONFIG_GRKERNSEC_SYMLINKOWN
	const struct inode *link_inode = d_backing_inode(link->dentry);

	if (target && !uid_eq(link_inode->i_uid, target->i_uid)) {
		gr_log_fs_int2(GR_DONT_AUDIT, GR_SYMLINKOWNER_MSG, link->dentry, link->mnt, GR_GLOBAL_UID(link_inode->i_uid), GR_GLOBAL_UID(target->i_uid));
		return 1;
	}
#endif
	return 0;
}

int
gr_handle_follow_link(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_LINK
	struct inode *inode = d_backing_inode(dentry);
	struct inode *parent = d_backing_inode(dentry->d_parent);
	const struct cred *cred = current_cred();

	if (grsec_enable_link && d_is_symlink(dentry) &&
	    (parent->i_mode & S_ISVTX) && !uid_eq(parent->i_uid, inode->i_uid) &&
	    (parent->i_mode & S_IWOTH) && !uid_eq(cred->fsuid, inode->i_uid)) {
		gr_log_fs_int2(GR_DONT_AUDIT, GR_SYMLINK_MSG, dentry, mnt, GR_GLOBAL_UID(inode->i_uid), GR_GLOBAL_GID(inode->i_gid));
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_hardlink(const struct dentry *dentry,
		   const struct vfsmount *mnt,
		   const struct filename *to)
{
#ifdef CONFIG_GRKERNSEC_LINK
	struct inode *inode = d_backing_inode(dentry);
	const struct cred *cred = current_cred();

	if (grsec_enable_link && !uid_eq(cred->fsuid, inode->i_uid) &&
	    (!d_is_reg(dentry) || is_privileged_binary(dentry) || 
	     (inode_permission(inode, MAY_READ | MAY_WRITE))) &&
	    !capable(CAP_FOWNER) && gr_is_global_nonroot(cred->uid)) {
		gr_log_fs_int2_str(GR_DONT_AUDIT, GR_HARDLINK_MSG, dentry, mnt, GR_GLOBAL_UID(inode->i_uid), GR_GLOBAL_GID(inode->i_gid), to->name);
		return -EPERM;
	}
#endif
	return 0;
}
