#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/grinternal.h>

int
gr_handle_fifo(const struct dentry *dentry, const struct vfsmount *mnt,
	       const struct dentry *dir, const int flag, const int acc_mode)
{
#ifdef CONFIG_GRKERNSEC_FIFO
	const struct cred *cred = current_cred();
	struct inode *inode = d_backing_inode(dentry);
	struct inode *dir_inode = d_backing_inode(dir);

	if (grsec_enable_fifo && S_ISFIFO(inode->i_mode) &&
	    !(flag & O_EXCL) && (dir_inode->i_mode & S_ISVTX) &&
	    !uid_eq(inode->i_uid, dir_inode->i_uid) &&
	    !uid_eq(cred->fsuid, inode->i_uid)) {
		if (!inode_permission(inode, acc_mode))
			gr_log_fs_int2(GR_DONT_AUDIT, GR_FIFO_MSG, dentry, mnt, GR_GLOBAL_UID(inode->i_uid), GR_GLOBAL_GID(inode->i_gid));
		return -EACCES;
	}
#endif
	return 0;
}
