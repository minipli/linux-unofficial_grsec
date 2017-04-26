#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/namei.h>
#include "../fs/mount.h"
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

#ifdef CONFIG_GRKERNSEC_CHROOT_INITRD
int gr_init_ran;
#endif

void gr_inc_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
	struct dentry *tmpd = dentry;

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);

	while (tmpd != mnt->mnt_root) {
		atomic_inc(&tmpd->chroot_refcnt);
		tmpd = tmpd->d_parent;
	}
	atomic_inc(&tmpd->chroot_refcnt);

	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);
#endif
}

void gr_dec_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
	struct dentry *tmpd = dentry;

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);

	while (tmpd != mnt->mnt_root) {
		atomic_dec(&tmpd->chroot_refcnt);
		tmpd = tmpd->d_parent;
	}
	atomic_dec(&tmpd->chroot_refcnt);

	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);
#endif
}

#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
static struct dentry *get_closest_chroot(struct dentry *dentry)
{
	write_seqlock(&rename_lock);
	do {
		if (atomic_read(&dentry->chroot_refcnt)) {
			write_sequnlock(&rename_lock);
			return dentry;
		}
		dentry = dentry->d_parent;
	} while (!IS_ROOT(dentry));
	write_sequnlock(&rename_lock);
	return NULL;
}
#endif

int gr_bad_chroot_rename(struct dentry *olddentry, struct vfsmount *oldmnt,
			 struct dentry *newdentry, struct vfsmount *newmnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
	struct dentry *chroot;

	if (unlikely(!grsec_enable_chroot_rename))
		return 0;

	if (likely(!proc_is_chrooted(current) && gr_is_global_root(current_uid())))
		return 0;

	chroot = get_closest_chroot(olddentry);

	if (chroot == NULL)
		return 0;

	if (is_subdir(newdentry, chroot))
		return 0;

	gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_RENAME_MSG, olddentry, oldmnt);

	return 1;
#else
	return 0;
#endif
}

void gr_set_chroot_entries(struct task_struct *task, const struct path *path)
{
#ifdef CONFIG_GRKERNSEC
	if (task_pid_nr(task) > 1 && path->dentry != init_task.fs->root.dentry &&
	    		     path->dentry != task->nsproxy->mnt_ns->root->mnt.mnt_root
#ifdef CONFIG_GRKERNSEC_CHROOT_INITRD
			     && gr_init_ran
#endif
	   )
		task->gr_is_chrooted = 1;
	else {
#ifdef CONFIG_GRKERNSEC_CHROOT_INITRD
		if (task_pid_nr(task) == 1 && !gr_init_ran)
			gr_init_ran = 1;
#endif
		task->gr_is_chrooted = 0;
	}

	task->gr_chroot_dentry = path->dentry;
#endif
	return;
}

void gr_clear_chroot_entries(struct task_struct *task)
{
#ifdef CONFIG_GRKERNSEC
	task->gr_is_chrooted = 0;
	task->gr_chroot_dentry = NULL;
#endif
	return;
}	

int
gr_handle_chroot_unix(const pid_t pid)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	struct task_struct *p;

	if (unlikely(!grsec_enable_chroot_unix))
		return 1;

	if (likely(!proc_is_chrooted(current)))
		return 1;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	p = find_task_by_vpid_unrestricted(pid);
	if (unlikely(p && !have_same_root(current, p))) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		gr_log_noargs(GR_DONT_AUDIT, GR_UNIX_CHROOT_MSG);
		return 0;
	}
	read_unlock(&tasklist_lock);
	rcu_read_unlock();
#endif
	return 1;
}

int
gr_handle_chroot_nice(void)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	if (grsec_enable_chroot_nice && proc_is_chrooted(current)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_NICE_CHROOT_MSG);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_setpriority(struct task_struct *p, const int niceval)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	if (grsec_enable_chroot_nice && (niceval < task_nice(p))
			&& proc_is_chrooted(current)) {
		gr_log_str_int(GR_DONT_AUDIT, GR_PRIORITY_CHROOT_MSG, p->comm, task_pid_nr(p));
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_chroot_fowner(struct pid *pid, enum pid_type type)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	struct task_struct *p;
	int ret = 0;
	if (!grsec_enable_chroot_findtask || !proc_is_chrooted(current) || !pid)
		return ret;

	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, p) {
		if (!have_same_root(current, p)) {
			ret = 1;
			goto out;
		}
	} while_each_pid_task(pid, type, p);
out:
	read_unlock(&tasklist_lock);
	return ret;
#endif
	return 0;
}

int
gr_pid_is_chrooted(struct task_struct *p)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	if (!grsec_enable_chroot_findtask || !proc_is_chrooted(current) || p == NULL)
		return 0;

	if ((p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)) ||
	    !have_same_root(current, p)) {
		return 1;
	}
#endif
	return 0;
}

EXPORT_SYMBOL_GPL(gr_pid_is_chrooted);

#if defined(CONFIG_GRKERNSEC_CHROOT_DOUBLE) || defined(CONFIG_GRKERNSEC_CHROOT_FCHDIR)
int gr_is_outside_chroot(const struct dentry *u_dentry, const struct vfsmount *u_mnt)
{
	struct path path, currentroot;
	int ret = 0;

	path.dentry = (struct dentry *)u_dentry;
	path.mnt = (struct vfsmount *)u_mnt;
	get_fs_root(current->fs, &currentroot);
	if (path_is_under(&path, &currentroot))
		ret = 1;
	path_put(&currentroot);

	return ret;
}
#endif

int
gr_chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	if (!grsec_enable_chroot_fchdir)
		return 1;

	if (!proc_is_chrooted(current))
		return 1;
	else if (!gr_is_outside_chroot(u_dentry, u_mnt)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_FCHDIR_MSG, u_dentry, u_mnt);
		return 0;
	}
#endif
	return 1;
}

int
gr_chroot_pathat(int dfd, struct dentry *u_dentry, struct vfsmount *u_mnt, unsigned flags)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	struct fd f;
	struct path fd_path;
	struct path file_path;

	if (!grsec_enable_chroot_fchdir)
		return 0;

	if (!proc_is_chrooted(current) || dfd == -1 || dfd == AT_FDCWD)
		return 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	f = fdget_raw(dfd);
	if (!f.file)
		return 0;

	fd_path = f.file->f_path;
	path_get(&fd_path);
	fdput(f);

	file_path.dentry = u_dentry;
	file_path.mnt = u_mnt;

	if (!gr_is_outside_chroot(u_dentry, u_mnt) && !path_is_under(&file_path, &fd_path)) {
		path_put(&fd_path);
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_PATHAT_MSG, u_dentry, u_mnt);
		return -ENOENT;
	}
	path_put(&fd_path);
#endif
	return 0;
}

int
gr_chroot_fhandle(void)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	if (!grsec_enable_chroot_fchdir)
		return 1;

	if (!proc_is_chrooted(current))
		return 1;
	else {
		gr_log_noargs(GR_DONT_AUDIT, GR_CHROOT_FHANDLE_MSG);
		return 0;
	}
#endif
	return 1;
}

int
gr_chroot_shmat(const pid_t shm_cprid, const pid_t shm_lapid,
		const u64 shm_createtime)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	struct task_struct *p;

	if (unlikely(!grsec_enable_chroot_shmat))
		return 1;

	if (likely(!proc_is_chrooted(current)))
		return 1;

	rcu_read_lock();
	read_lock(&tasklist_lock);

	if ((p = find_task_by_vpid_unrestricted(shm_cprid))) {
		if (time_before_eq64(p->start_time, shm_createtime)) {
			if (have_same_root(current, p)) {
				goto allow;
			} else {
				read_unlock(&tasklist_lock);
				rcu_read_unlock();
				gr_log_noargs(GR_DONT_AUDIT, GR_SHMAT_CHROOT_MSG);
				return 0;
			}
		}
		/* creator exited, pid reuse, fall through to next check */
	}
	if ((p = find_task_by_vpid_unrestricted(shm_lapid))) {
		if (unlikely(!have_same_root(current, p))) {
			read_unlock(&tasklist_lock);
			rcu_read_unlock();
			gr_log_noargs(GR_DONT_AUDIT, GR_SHMAT_CHROOT_MSG);
			return 0;
		}
	}

allow:
	read_unlock(&tasklist_lock);
	rcu_read_unlock();
#endif
	return 1;
}

void
gr_log_chroot_exec(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	if (grsec_enable_chroot_execlog && proc_is_chrooted(current))
		gr_log_fs_generic(GR_DO_AUDIT, GR_EXEC_CHROOT_MSG, dentry, mnt);
#endif
	return;
}

int
gr_handle_chroot_mknod(const struct dentry *dentry,
		       const struct vfsmount *mnt, const int mode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	if (grsec_enable_chroot_mknod && !S_ISFIFO(mode) && !S_ISREG(mode) && 
	    proc_is_chrooted(current)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_MKNOD_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_mount(const struct dentry *dentry,
		       const struct vfsmount *mnt, const char *dev_name)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	if (grsec_enable_chroot_mount && proc_is_chrooted(current)) {
		gr_log_str_fs(GR_DONT_AUDIT, GR_MOUNT_CHROOT_MSG, dev_name ? dev_name : "none", dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_pivot(void)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	if (grsec_enable_chroot_pivot && proc_is_chrooted(current)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_PIVOT_CHROOT_MSG);
		return -EPERM;
	}
#endif
	return 0;
}

int
gr_handle_chroot_chroot(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	if (grsec_enable_chroot_double && proc_is_chrooted(current) &&
	    !gr_is_outside_chroot(dentry, mnt)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHROOT_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}

extern const char *captab_log[];
extern int captab_log_entries;

int
gr_task_chroot_is_capable(const struct task_struct *task, const struct cred *cred, const int cap)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (grsec_enable_chroot_caps && proc_is_chrooted(task)) {
		kernel_cap_t chroot_caps = GR_CHROOT_CAPS;
		if (cap_raised(chroot_caps, cap)) {
			if (cap_raised(cred->cap_effective, cap) && cap < captab_log_entries) {
				gr_log_cap(GR_DONT_AUDIT, GR_CAP_CHROOT_MSG, task, captab_log[cap]);
			}
			return 0;
		}
	}
#endif
	return 1;
}

int
gr_chroot_is_capable(const int cap)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	return gr_task_chroot_is_capable(current, current_cred(), cap);
#endif
	return 1;
}

int
gr_task_chroot_is_capable_nolog(const struct task_struct *task, const int cap)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (grsec_enable_chroot_caps && proc_is_chrooted(task)) {
		kernel_cap_t chroot_caps = GR_CHROOT_CAPS;
		if (cap_raised(chroot_caps, cap)) {
			return 0;
		}
	}
#endif
	return 1;
}

int
gr_chroot_is_capable_nolog(const int cap)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	return gr_task_chroot_is_capable_nolog(current, cap);
#endif
	return 1;
}

int
gr_handle_chroot_sysctl(const int op)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	if (grsec_enable_chroot_sysctl && (op & MAY_WRITE) &&
	    proc_is_chrooted(current))
		return -EACCES;
#endif
	return 0;
}

void
gr_handle_chroot_chdir(const struct path *path)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	if (grsec_enable_chroot_chdir)
		set_fs_pwd(current->fs, path);
#endif
	return;
}

int
gr_handle_chroot_chmod(const struct dentry *dentry,
		       const struct vfsmount *mnt, const int mode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	/* allow chmod +s on directories, but not files */
	if (grsec_enable_chroot_chmod && !d_is_dir(dentry) &&
	    ((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))) &&
	    proc_is_chrooted(current)) {
		gr_log_fs_generic(GR_DONT_AUDIT, GR_CHMOD_CHROOT_MSG, dentry, mnt);
		return -EPERM;
	}
#endif
	return 0;
}
