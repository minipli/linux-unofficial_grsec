#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/gracl.h>

umode_t
gr_acl_umask(void)
{
	if (unlikely(!gr_acl_is_enabled()))
		return 0;

	return current->role->umask;
}

__u32
gr_acl_handle_hidden_file(const struct dentry * dentry,
			  const struct vfsmount * mnt)
{
	__u32 mode;

	if (unlikely(d_is_negative(dentry)))
		return GR_FIND;

	mode =
	    gr_search_file(dentry, GR_FIND | GR_AUDIT_FIND | GR_SUPPRESS, mnt);

	if (unlikely(mode & GR_FIND && mode & GR_AUDIT_FIND)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, GR_HIDDEN_ACL_MSG, dentry, mnt);
		return mode;
	} else if (unlikely(!(mode & GR_FIND) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, GR_HIDDEN_ACL_MSG, dentry, mnt);
		return 0;
	} else if (unlikely(!(mode & GR_FIND)))
		return 0;

	return GR_FIND;
}

__u32
gr_acl_handle_open(const struct dentry * dentry, const struct vfsmount * mnt,
		   int acc_mode)
{
	__u32 reqmode = GR_FIND;
	__u32 mode;

	if (unlikely(d_is_negative(dentry)))
		return reqmode;

	if (acc_mode & MAY_APPEND)
		reqmode |= GR_APPEND;
	else if (acc_mode & MAY_WRITE)
		reqmode |= GR_WRITE;
	if ((acc_mode & MAY_READ) && !d_is_dir(dentry))
		reqmode |= GR_READ;

	mode =
	    gr_search_file(dentry, reqmode | to_gr_audit(reqmode) | GR_SUPPRESS,
			   mnt);

	if (unlikely(((mode & reqmode) == reqmode) && mode & GR_AUDITS)) {
		gr_log_fs_rbac_mode2(GR_DO_AUDIT, GR_OPEN_ACL_MSG, dentry, mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : reqmode &
			       GR_APPEND ? " appending" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & GR_SUPPRESS)))
	{
		gr_log_fs_rbac_mode2(GR_DONT_AUDIT, GR_OPEN_ACL_MSG, dentry, mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : reqmode &
			       GR_APPEND ? " appending" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

__u32
gr_acl_handle_creat(const struct dentry * dentry,
		    const struct dentry * p_dentry,
		    const struct vfsmount * p_mnt, int open_flags, int acc_mode,
		    const int imode)
{
	__u32 reqmode = GR_WRITE | GR_CREATE;
	__u32 mode;

	if (acc_mode & MAY_APPEND)
		reqmode |= GR_APPEND;
	// if a directory was required or the directory already exists, then
	// don't count this open as a read
	if ((acc_mode & MAY_READ) &&
	    !((open_flags & O_DIRECTORY) || d_is_dir(dentry)))
		reqmode |= GR_READ;
	if ((open_flags & O_CREAT) &&
	    ((imode & S_ISUID) || ((imode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))
		reqmode |= GR_SETID;

	mode =
	    gr_check_create(dentry, p_dentry, p_mnt,
			    reqmode | to_gr_audit(reqmode) | GR_SUPPRESS);

	if (unlikely(((mode & reqmode) == reqmode) && mode & GR_AUDITS)) {
		gr_log_fs_rbac_mode2(GR_DO_AUDIT, GR_CREATE_ACL_MSG, dentry, p_mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : reqmode &
			       GR_APPEND ? " appending" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & GR_SUPPRESS)))
	{
		gr_log_fs_rbac_mode2(GR_DONT_AUDIT, GR_CREATE_ACL_MSG, dentry, p_mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : reqmode &
			       GR_APPEND ? " appending" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

__u32
gr_acl_handle_access(const struct dentry * dentry, const struct vfsmount * mnt,
		     const int fmode)
{
	__u32 mode, reqmode = GR_FIND;

	if ((fmode & S_IXOTH) && !d_is_dir(dentry))
		reqmode |= GR_EXEC;
	if (fmode & S_IWOTH)
		reqmode |= GR_WRITE;
	if (fmode & S_IROTH)
		reqmode |= GR_READ;

	mode =
	    gr_search_file(dentry, reqmode | to_gr_audit(reqmode) | GR_SUPPRESS,
			   mnt);

	if (unlikely(((mode & reqmode) == reqmode) && mode & GR_AUDITS)) {
		gr_log_fs_rbac_mode3(GR_DO_AUDIT, GR_ACCESS_ACL_MSG, dentry, mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : "",
			       reqmode & GR_EXEC ? " executing" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & GR_SUPPRESS)))
	{
		gr_log_fs_rbac_mode3(GR_DONT_AUDIT, GR_ACCESS_ACL_MSG, dentry, mnt,
			       reqmode & GR_READ ? " reading" : "",
			       reqmode & GR_WRITE ? " writing" : "",
			       reqmode & GR_EXEC ? " executing" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

static __u32 generic_fs_handler(const struct dentry *dentry, const struct vfsmount *mnt, __u32 reqmode, const char *fmt)
{
	__u32 mode;

	mode = gr_search_file(dentry, reqmode | to_gr_audit(reqmode) | GR_SUPPRESS, mnt);

	if (unlikely(((mode & (reqmode)) == (reqmode)) && mode & GR_AUDITS)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, fmt, dentry, mnt);
		return mode;
	} else if (unlikely((mode & (reqmode)) != (reqmode) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, fmt, dentry, mnt);
		return 0;
	} else if (unlikely((mode & (reqmode)) != (reqmode)))
		return 0;

	return (reqmode);
}

__u32
gr_acl_handle_rmdir(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE | GR_DELETE , GR_RMDIR_ACL_MSG);
}

__u32
gr_acl_handle_unlink(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE | GR_DELETE , GR_UNLINK_ACL_MSG);
}

__u32
gr_acl_handle_truncate(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE, GR_TRUNCATE_ACL_MSG);
}

__u32
gr_acl_handle_utime(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE, GR_ATIME_ACL_MSG);
}

__u32
gr_acl_handle_chmod(const struct dentry *dentry, const struct vfsmount *mnt,
		     umode_t *modeptr)
{
	umode_t mode;
	struct inode *inode = d_backing_inode(dentry);

	*modeptr &= ~gr_acl_umask();
	mode = *modeptr;

	if (unlikely(inode && S_ISSOCK(inode->i_mode)))
		return 1;

	if (unlikely(!d_is_dir(dentry) &&
		     ((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))) {
		return generic_fs_handler(dentry, mnt, GR_WRITE | GR_SETID,
				   GR_CHMOD_ACL_MSG);
	} else {
		return generic_fs_handler(dentry, mnt, GR_WRITE, GR_CHMOD_ACL_MSG);
	}
}

__u32
gr_acl_handle_chown(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE, GR_CHOWN_ACL_MSG);
}

__u32
gr_acl_handle_setxattr(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE, GR_SETXATTR_ACL_MSG);
}

__u32
gr_acl_handle_removexattr(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_WRITE, GR_REMOVEXATTR_ACL_MSG);
}

__u32
gr_acl_handle_execve(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_EXEC, GR_EXEC_ACL_MSG);
}

__u32
gr_acl_handle_unix(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, GR_READ | GR_WRITE,
			   GR_UNIXCONNECT_ACL_MSG);
}

/* hardlinks require at minimum create and link permission,
   any additional privilege required is based on the
   privilege of the file being linked to
*/
__u32
gr_acl_handle_link(const struct dentry * new_dentry,
		   const struct dentry * parent_dentry,
		   const struct vfsmount * parent_mnt,
		   const struct dentry * old_dentry,
		   const struct vfsmount * old_mnt, const struct filename *to)
{
	__u32 mode;
	__u32 needmode = GR_CREATE | GR_LINK;
	__u32 needaudit = GR_AUDIT_CREATE | GR_AUDIT_LINK;

	mode =
	    gr_check_link(new_dentry, parent_dentry, parent_mnt, old_dentry,
			  old_mnt);

	if (unlikely(((mode & needmode) == needmode) && (mode & needaudit))) {
		gr_log_fs_rbac_str(GR_DO_AUDIT, GR_LINK_ACL_MSG, old_dentry, old_mnt, to->name);
		return mode;
	} else if (unlikely(((mode & needmode) != needmode) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_str(GR_DONT_AUDIT, GR_LINK_ACL_MSG, old_dentry, old_mnt, to->name);
		return 0;
	} else if (unlikely((mode & needmode) != needmode))
		return 0;

	return 1;
}

__u32
gr_acl_handle_symlink(const struct dentry * new_dentry,
		      const struct dentry * parent_dentry,
		      const struct vfsmount * parent_mnt, const struct filename *from)
{
	__u32 needmode = GR_WRITE | GR_CREATE;
	__u32 mode;

	mode =
	    gr_check_create(new_dentry, parent_dentry, parent_mnt,
			    GR_CREATE | GR_AUDIT_CREATE |
			    GR_WRITE | GR_AUDIT_WRITE | GR_SUPPRESS);

	if (unlikely(mode & GR_WRITE && mode & GR_AUDITS)) {
		gr_log_fs_str_rbac(GR_DO_AUDIT, GR_SYMLINK_ACL_MSG, from->name, new_dentry, parent_mnt);
		return mode;
	} else if (unlikely(((mode & needmode) != needmode) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_str_rbac(GR_DONT_AUDIT, GR_SYMLINK_ACL_MSG, from->name, new_dentry, parent_mnt);
		return 0;
	} else if (unlikely((mode & needmode) != needmode))
		return 0;

	return (GR_WRITE | GR_CREATE);
}

static __u32 generic_fs_create_handler(const struct dentry *new_dentry, const struct dentry *parent_dentry, const struct vfsmount *parent_mnt, __u32 reqmode, const char *fmt)
{
	__u32 mode;

	mode = gr_check_create(new_dentry, parent_dentry, parent_mnt, reqmode | to_gr_audit(reqmode) | GR_SUPPRESS);

	if (unlikely(((mode & (reqmode)) == (reqmode)) && mode & GR_AUDITS)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, fmt, new_dentry, parent_mnt);
		return mode;
	} else if (unlikely((mode & (reqmode)) != (reqmode) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, fmt, new_dentry, parent_mnt);
		return 0;
	} else if (unlikely((mode & (reqmode)) != (reqmode)))
		return 0;

	return (reqmode);
}

__u32
gr_acl_handle_mknod(const struct dentry * new_dentry,
		    const struct dentry * parent_dentry,
		    const struct vfsmount * parent_mnt,
		    const int mode)
{
	__u32 reqmode = GR_WRITE | GR_CREATE;
	if (unlikely((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))
		reqmode |= GR_SETID;

	return generic_fs_create_handler(new_dentry, parent_dentry, parent_mnt,
				  reqmode, GR_MKNOD_ACL_MSG);
}

__u32
gr_acl_handle_mkdir(const struct dentry *new_dentry,
		    const struct dentry *parent_dentry,
		    const struct vfsmount *parent_mnt)
{
	return generic_fs_create_handler(new_dentry, parent_dentry, parent_mnt,
				  GR_WRITE | GR_CREATE, GR_MKDIR_ACL_MSG);
}

#define RENAME_CHECK_SUCCESS(old, new) \
	(((old & (GR_WRITE | GR_READ)) == (GR_WRITE | GR_READ)) && \
	 ((new & (GR_WRITE | GR_READ)) == (GR_WRITE | GR_READ)))

int
gr_acl_handle_rename(struct dentry *new_dentry,
		     struct dentry *parent_dentry,
		     const struct vfsmount *parent_mnt,
		     struct dentry *old_dentry,
		     struct inode *old_parent_inode,
		     struct vfsmount *old_mnt, const struct filename *newname, unsigned int flags)
{
	__u32 comp1, comp2;
	int error = 0;

	if (unlikely(!gr_acl_is_enabled()))
		return 0;

	if (flags & RENAME_EXCHANGE) {
		comp1 = gr_search_file(new_dentry, GR_READ | GR_WRITE |
				       GR_AUDIT_READ | GR_AUDIT_WRITE |
				       GR_SUPPRESS, parent_mnt);
		comp2 =
		    gr_search_file(old_dentry,
				   GR_READ | GR_WRITE | GR_AUDIT_READ |
				   GR_AUDIT_WRITE | GR_SUPPRESS, old_mnt);
	} else if (d_is_negative(new_dentry)) {
		comp1 = gr_check_create(new_dentry, parent_dentry, parent_mnt,
					GR_READ | GR_WRITE | GR_CREATE | GR_AUDIT_READ |
					GR_AUDIT_WRITE | GR_AUDIT_CREATE | GR_SUPPRESS);
		comp2 = gr_search_file(old_dentry, GR_READ | GR_WRITE |
				       GR_DELETE | GR_AUDIT_DELETE |
				       GR_AUDIT_READ | GR_AUDIT_WRITE |
				       GR_SUPPRESS, old_mnt);
	} else {
		comp1 = gr_search_file(new_dentry, GR_READ | GR_WRITE |
				       GR_CREATE | GR_DELETE |
				       GR_AUDIT_CREATE | GR_AUDIT_DELETE |
				       GR_AUDIT_READ | GR_AUDIT_WRITE |
				       GR_SUPPRESS, parent_mnt);
		comp2 =
		    gr_search_file(old_dentry,
				   GR_READ | GR_WRITE | GR_AUDIT_READ |
				   GR_DELETE | GR_AUDIT_DELETE |
				   GR_AUDIT_WRITE | GR_SUPPRESS, old_mnt);
	}

	if (RENAME_CHECK_SUCCESS(comp1, comp2) &&
	    ((comp1 & GR_AUDITS) || (comp2 & GR_AUDITS)))
		gr_log_fs_rbac_str(GR_DO_AUDIT, GR_RENAME_ACL_MSG, old_dentry, old_mnt, newname->name);
	else if (!RENAME_CHECK_SUCCESS(comp1, comp2) && !(comp1 & GR_SUPPRESS)
		 && !(comp2 & GR_SUPPRESS)) {
		gr_log_fs_rbac_str(GR_DONT_AUDIT, GR_RENAME_ACL_MSG, old_dentry, old_mnt, newname->name);
		error = -EACCES;
	} else if (unlikely(!RENAME_CHECK_SUCCESS(comp1, comp2)))
		error = -EACCES;

	return error;
}

void
gr_acl_handle_exit(void)
{
	u16 id;
	char *rolename;

	if (unlikely(current->acl_sp_role && gr_acl_is_enabled() &&
	    !(current->role->roletype & GR_ROLE_PERSIST))) {
		id = current->acl_role_id;
		rolename = current->role->rolename;
		gr_set_acls(1);
		gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_SPROLEL_ACL_MSG, rolename, id);
	}

	gr_put_exec_file(current);
	return;
}

int
gr_acl_handle_procpidmem(const struct task_struct *task)
{
	if (unlikely(!gr_acl_is_enabled()))
		return 0;

	if (task != current && (task->acl->mode & GR_PROTPROCFD) &&
	    !(current->acl->mode & GR_POVERRIDE) &&
	    !(current->role->roletype & GR_ROLE_GOD))
		return -EACCES;

	return 0;
}
