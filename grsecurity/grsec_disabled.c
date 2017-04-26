#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>

#ifdef CONFIG_PAX_HAVE_ACL_FLAGS
void
pax_set_initial_flags(struct linux_binprm *bprm)
{
	return;
}
#endif

#ifdef CONFIG_SYSCTL
__u32
gr_handle_sysctl(const struct ctl_table * table, const int op)
{
	return 0;
}
#endif

#ifdef CONFIG_TASKSTATS
int gr_is_taskstats_denied(int pid)
{
	return 0;
}
#endif

int
gr_acl_is_enabled(void)
{
	return 0;
}

int
gr_learn_cap(const struct task_struct *task, const struct cred *cred, const int cap, bool log)
{
	return 0;
}

void
gr_handle_proc_create(const struct dentry *dentry, const struct inode *inode) 
{
	return;
}

int
gr_handle_rawio(const struct inode *inode)
{
	return 0;
}

void
gr_acl_handle_psacct(struct task_struct *task, const long code)
{
	return;
}

int
gr_handle_ptrace(struct task_struct *task, const long request)
{
	return 0;
}

int
gr_handle_proc_ptrace(struct task_struct *task)
{
	return 0;
}

int
gr_set_acls(const int type)
{
	return 0;
}

int
gr_check_hidden_task(const struct task_struct *tsk)
{
	return 0;
}

int
gr_check_protected_task(const struct task_struct *task)
{
	return 0;
}

int
gr_check_protected_task_fowner(struct pid *pid, enum pid_type type)
{
	return 0;
}

void
gr_copy_label(struct task_struct *tsk)
{
	return;
}

void
gr_set_pax_flags(struct task_struct *task)
{
	return;
}

int
gr_set_proc_label(const struct dentry *dentry, const struct vfsmount *mnt,
		  const int unsafe_share)
{
	return 0;
}

void
gr_handle_delete(const u64 ino, const dev_t dev)
{
	return;
}

void
gr_handle_create(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return;
}

void
gr_handle_crash(struct task_struct *task, const int sig)
{
	return;
}

int
gr_check_crash_exec(const struct file *filp)
{
	return 0;
}

int
gr_check_crash_uid(const kuid_t uid)
{
	return 0;
}

void
gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
		 struct dentry *old_dentry,
		 struct dentry *new_dentry,
		 struct vfsmount *mnt, const __u8 replace, unsigned int flags)
{
	return;
}

int
gr_search_socket(const int family, const int type, const int protocol)
{
	return 1;
}

int
gr_search_connectbind(const int mode, const struct socket *sock,
		      const struct sockaddr_in *addr)
{
	return 0;
}

void
gr_handle_alertkill(struct task_struct *task)
{
	return;
}

__u32
gr_acl_handle_execve(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_hidden_file(const struct dentry * dentry,
			  const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_open(const struct dentry * dentry, const struct vfsmount * mnt,
		   int acc_mode)
{
	return 1;
}

__u32
gr_acl_handle_rmdir(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_unlink(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

int
gr_acl_handle_mmap(const struct file *file, const unsigned long prot,
		   unsigned int *vm_flags)
{
	return 1;
}

__u32
gr_acl_handle_truncate(const struct dentry * dentry,
		       const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_utime(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_access(const struct dentry * dentry,
		     const struct vfsmount * mnt, const int fmode)
{
	return 1;
}

__u32
gr_acl_handle_chmod(const struct dentry * dentry, const struct vfsmount * mnt,
		    umode_t *mode)
{
	return 1;
}

__u32
gr_acl_handle_chown(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_setxattr(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_removexattr(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

void
grsecurity_init(void)
{
	return;
}

umode_t gr_acl_umask(void)
{
	return 0;
}

__u32
gr_acl_handle_mknod(const struct dentry * new_dentry,
		    const struct dentry * parent_dentry,
		    const struct vfsmount * parent_mnt,
		    const int mode)
{
	return 1;
}

__u32
gr_acl_handle_mkdir(const struct dentry * new_dentry,
		    const struct dentry * parent_dentry,
		    const struct vfsmount * parent_mnt)
{
	return 1;
}

__u32
gr_acl_handle_symlink(const struct dentry * new_dentry,
		      const struct dentry * parent_dentry,
		      const struct vfsmount * parent_mnt, const struct filename *from)
{
	return 1;
}

__u32
gr_acl_handle_link(const struct dentry * new_dentry,
		   const struct dentry * parent_dentry,
		   const struct vfsmount * parent_mnt,
		   const struct dentry * old_dentry,
		   const struct vfsmount * old_mnt, const struct filename *to)
{
	return 1;
}

int
gr_acl_handle_rename(const struct dentry *new_dentry,
		     const struct dentry *parent_dentry,
		     const struct vfsmount *parent_mnt,
		     const struct dentry *old_dentry,
		     const struct inode *old_parent_inode,
		     const struct vfsmount *old_mnt, const struct filename *newname,
		     unsigned int flags)
{
	return 0;
}

int
gr_acl_handle_filldir(const struct file *file, const char *name,
		      const int namelen, const u64 ino)
{
	return 1;
}

int
gr_handle_shmat(const pid_t shm_cprid, const pid_t shm_lapid,
		const u64 shm_createtime, const kuid_t cuid, const int shmid)
{
	return 1;
}

int
gr_search_bind(const struct socket *sock, const struct sockaddr_in *addr)
{
	return 0;
}

int
gr_search_accept(const struct socket *sock)
{
	return 0;
}

int
gr_search_listen(const struct socket *sock)
{
	return 0;
}

int
gr_search_connect(const struct socket *sock, const struct sockaddr_in *addr)
{
	return 0;
}

__u32
gr_acl_handle_unix(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return 1;
}

__u32
gr_acl_handle_creat(const struct dentry * dentry,
		    const struct dentry * p_dentry,
		    const struct vfsmount * p_mnt, int open_flags, int acc_mode,
		    const int imode)
{
	return 1;
}

void
gr_acl_handle_exit(void)
{
	return;
}

int
gr_acl_handle_mprotect(const struct file *file, const unsigned long prot)
{
	return 1;
}

void
gr_set_role_label(const kuid_t uid, const kgid_t gid)
{
	return;
}

int
gr_acl_handle_procpidmem(const struct task_struct *task)
{
	return 0;
}

int
gr_search_udp_recvmsg(struct sock *sk, const struct sk_buff *skb)
{
	return 0;
}

int
gr_search_udp_sendmsg(struct sock *sk, struct sockaddr_in *addr)
{
	return 0;
}

int
gr_check_user_change(kuid_t real, kuid_t effective, kuid_t fs)
{
	return 0;
}

int
gr_check_group_change(kgid_t real, kgid_t effective, kgid_t fs)
{
	return 0;
}

int gr_acl_enable_at_secure(void)
{
	return 0;
}

dev_t gr_get_dev_from_dentry(struct dentry *dentry)
{
	return d_backing_inode(dentry)->i_sb->s_dev;
}

u64 gr_get_ino_from_dentry(struct dentry *dentry)
{
	return d_backing_inode(dentry)->i_ino;
}

void gr_put_exec_file(struct task_struct *task)
{
	return;
}

#ifdef CONFIG_SECURITY
EXPORT_SYMBOL_GPL(gr_check_user_change);
EXPORT_SYMBOL_GPL(gr_check_group_change);
#endif
