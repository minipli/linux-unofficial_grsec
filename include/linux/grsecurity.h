#ifndef GR_SECURITY_H
#define GR_SECURITY_H
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/binfmts.h>
#include <linux/tty.h>
#include <linux/gracl.h>

/* notify of brain-dead configs */
#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_GRKERNSEC_KMEM)
#error "CONFIG_DEBUG_FS being enabled is a security risk when CONFIG_GRKERNSEC_KMEM is enabled"
#endif
#if defined(CONFIG_PROC_PAGE_MONITOR) && defined(CONFIG_GRKERNSEC)
#error "CONFIG_PROC_PAGE_MONITOR is a security risk"
#endif
#if defined(CONFIG_GRKERNSEC_PROC_USER) && defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
#error "CONFIG_GRKERNSEC_PROC_USER and CONFIG_GRKERNSEC_PROC_USERGROUP cannot both be enabled."
#endif
#if defined(CONFIG_GRKERNSEC_PROC) && !defined(CONFIG_GRKERNSEC_PROC_USER) && !defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
#error "CONFIG_GRKERNSEC_PROC enabled, but neither CONFIG_GRKERNSEC_PROC_USER nor CONFIG_GRKERNSEC_PROC_USERGROUP enabled"
#endif
#if defined(CONFIG_PAX_NOEXEC) && !defined(CONFIG_PAX_PAGEEXEC) && !defined(CONFIG_PAX_SEGMEXEC) && !defined(CONFIG_PAX_KERNEXEC)
#error "CONFIG_PAX_NOEXEC enabled, but PAGEEXEC, SEGMEXEC, and KERNEXEC are disabled."
#endif
#if defined(CONFIG_PAX_ASLR) && !defined(CONFIG_PAX_RANDKSTACK) && !defined(CONFIG_PAX_RANDUSTACK) && !defined(CONFIG_PAX_RANDMMAP)
#error "CONFIG_PAX_ASLR enabled, but RANDKSTACK, RANDUSTACK, and RANDMMAP are disabled."
#endif
#if defined(CONFIG_PAX) && !defined(CONFIG_PAX_NOEXEC) && !defined(CONFIG_PAX_ASLR)
#error "CONFIG_PAX enabled, but no PaX options are enabled."
#endif

int gr_handle_new_usb(void);

void gr_handle_brute_attach(int dumpable);
void gr_handle_brute_check(void);
void gr_handle_kernel_exploit(void);

char gr_roletype_to_char(void);

int gr_proc_is_restricted(void);

int gr_acl_enable_at_secure(void);

int gr_check_user_change(kuid_t real, kuid_t effective, kuid_t fs);
int gr_check_group_change(kgid_t real, kgid_t effective, kgid_t fs);

int gr_learn_cap(const struct task_struct *task, const struct cred *cred, const int cap, bool log);

void gr_del_task_from_ip_table(struct task_struct *p);

int gr_pid_is_chrooted(struct task_struct *p);
int gr_handle_chroot_fowner(struct pid *pid, enum pid_type type);
int gr_handle_chroot_nice(void);
int gr_handle_chroot_sysctl(const int op);
int gr_handle_chroot_setpriority(struct task_struct *p,
					const int niceval);
int gr_chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt);
int gr_chroot_pathat(int dfd, struct dentry *u_dentry, struct vfsmount *u_mnt, unsigned flags);
int gr_chroot_fhandle(void);
int gr_handle_chroot_chroot(const struct dentry *dentry,
				   const struct vfsmount *mnt);
void gr_handle_chroot_chdir(const struct path *path);
int gr_handle_chroot_chmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int gr_handle_chroot_mknod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int gr_handle_chroot_mount(const struct dentry *dentry,
				  const struct vfsmount *mnt,
				  const char *dev_name);
int gr_handle_chroot_pivot(void);
int gr_handle_chroot_unix(const pid_t pid);

int gr_handle_rawio(const struct inode *inode);

void gr_handle_ioperm(void);
void gr_handle_iopl(void);
void gr_handle_msr_write(void);

umode_t gr_acl_umask(void);

int gr_tpe_allow(const struct file *file);

void gr_set_chroot_entries(struct task_struct *task, const struct path *path);
void gr_clear_chroot_entries(struct task_struct *task);

void gr_log_forkfail(const int retval);
void gr_log_timechange(void);
void gr_log_signal(const int sig, const void *addr, const struct task_struct *t);
void gr_log_chdir(const struct dentry *dentry,
			 const struct vfsmount *mnt);
void gr_log_chroot_exec(const struct dentry *dentry,
			       const struct vfsmount *mnt);
void gr_log_remount(const char *devname, const int retval);
void gr_log_unmount(const char *devname, const int retval);
void gr_log_mount(const char *from, struct path *to, const int retval);
void gr_log_textrel(struct vm_area_struct *vma, bool is_textrel_rw);
void gr_log_ptgnustack(struct file *file);
void gr_log_rwxmmap(struct file *file);
void gr_log_rwxmprotect(struct vm_area_struct *vma);

int gr_handle_follow_link(const struct dentry *dentry,
				 const struct vfsmount *mnt);
int gr_handle_fifo(const struct dentry *dentry,
			  const struct vfsmount *mnt,
			  const struct dentry *dir, const int flag,
			  const int acc_mode);
int gr_handle_hardlink(const struct dentry *dentry,
			      const struct vfsmount *mnt,
			      const struct filename *to);

int gr_is_capable(const int cap);
int gr_is_capable_nolog(const int cap);
int gr_task_is_capable(const struct task_struct *task, const struct cred *cred, const int cap);
int gr_task_is_capable_nolog(const struct task_struct *task, const struct cred *cred, const int cap);

void gr_copy_label(struct task_struct *tsk);
void gr_handle_crash(struct task_struct *task, const int sig);
int gr_handle_signal(const struct task_struct *p, const int sig);
int gr_check_crash_uid(const kuid_t uid);
int gr_check_protected_task(const struct task_struct *task);
int gr_check_protected_task_fowner(struct pid *pid, enum pid_type type);
int gr_acl_handle_mmap(const struct file *file,
			      const unsigned long prot);
int gr_acl_handle_mprotect(const struct file *file,
				  const unsigned long prot);
int gr_check_hidden_task(const struct task_struct *tsk);
__u32 gr_acl_handle_truncate(const struct dentry *dentry,
				    const struct vfsmount *mnt);
__u32 gr_acl_handle_utime(const struct dentry *dentry,
				 const struct vfsmount *mnt);
__u32 gr_acl_handle_access(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int fmode);
__u32 gr_acl_handle_chmod(const struct dentry *dentry,
				 const struct vfsmount *mnt, umode_t *mode);
__u32 gr_acl_handle_chown(const struct dentry *dentry,
				 const struct vfsmount *mnt);
__u32 gr_acl_handle_setxattr(const struct dentry *dentry,
				 const struct vfsmount *mnt);
__u32 gr_acl_handle_removexattr(const struct dentry *dentry,
				 const struct vfsmount *mnt);
int gr_handle_ptrace(struct task_struct *task, const long request);
int gr_handle_proc_ptrace(struct task_struct *task);
__u32 gr_acl_handle_execve(const struct dentry *dentry,
				  const struct vfsmount *mnt);
int gr_check_crash_exec(const struct file *filp);
int gr_acl_is_enabled(void);
void gr_set_role_label(struct task_struct *task, const kuid_t uid,
			      const kgid_t gid);
int gr_set_proc_label(const struct dentry *dentry,
			const struct vfsmount *mnt,
			const int unsafe_flags);
__u32 gr_acl_handle_hidden_file(const struct dentry *dentry,
				const struct vfsmount *mnt);
__u32 gr_acl_handle_open(const struct dentry *dentry,
				const struct vfsmount *mnt, int acc_mode);
__u32 gr_acl_handle_creat(const struct dentry *dentry,
				 const struct dentry *p_dentry,
				 const struct vfsmount *p_mnt,
				 int open_flags, int acc_mode, const int imode);
void gr_handle_create(const struct dentry *dentry,
			     const struct vfsmount *mnt);
void gr_handle_proc_create(const struct dentry *dentry,
			   const struct inode *inode);
__u32 gr_acl_handle_mknod(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt,
				 const int mode);
__u32 gr_acl_handle_mkdir(const struct dentry *new_dentry,
				 const struct dentry *parent_dentry,
				 const struct vfsmount *parent_mnt);
__u32 gr_acl_handle_rmdir(const struct dentry *dentry,
				 const struct vfsmount *mnt);
void gr_handle_delete(const u64 ino, const dev_t dev);
__u32 gr_acl_handle_unlink(const struct dentry *dentry,
				  const struct vfsmount *mnt);
__u32 gr_acl_handle_symlink(const struct dentry *new_dentry,
				   const struct dentry *parent_dentry,
				   const struct vfsmount *parent_mnt,
				   const struct filename *from);
__u32 gr_acl_handle_link(const struct dentry *new_dentry,
				const struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				const struct dentry *old_dentry,
				const struct vfsmount *old_mnt, const struct filename *to);
int gr_handle_symlink_owner(const struct path *link, const struct inode *target);
int gr_acl_handle_rename(struct dentry *new_dentry,
				struct dentry *parent_dentry,
				const struct vfsmount *parent_mnt,
				struct dentry *old_dentry,
				struct inode *old_parent_inode,
				struct vfsmount *old_mnt, const struct filename *newname, unsigned int flags);
void gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
				struct dentry *old_dentry,
				struct dentry *new_dentry,
				struct vfsmount *mnt, const __u8 replace, unsigned int flags);
__u32 gr_check_link(const struct dentry *new_dentry,
			   const struct dentry *parent_dentry,
			   const struct vfsmount *parent_mnt,
			   const struct dentry *old_dentry,
			   const struct vfsmount *old_mnt);
int gr_acl_handle_filldir(const struct file *file, const char *name,
				 const unsigned int namelen, const u64 ino);

__u32 gr_acl_handle_unix(const struct dentry *dentry,
				const struct vfsmount *mnt);
void gr_acl_handle_exit(void);
void gr_acl_handle_psacct(struct task_struct *task, const long code);
int gr_acl_handle_procpidmem(const struct task_struct *task);
int gr_handle_rofs_mount(struct dentry *dentry, struct vfsmount *mnt, int mnt_flags);
int gr_handle_rofs_blockwrite(struct dentry *dentry, struct vfsmount *mnt, int acc_mode);
void gr_audit_ptrace(struct task_struct *task);
dev_t gr_get_dev_from_dentry(struct dentry *dentry);
u64 gr_get_ino_from_dentry(struct dentry *dentry);
void gr_put_exec_file(struct task_struct *task);

int gr_get_symlinkown_enabled(void);

int gr_ptrace_readexec(struct file *file, int unsafe_flags);

int gr_handle_tiocsti(struct tty_struct *tty);

void gr_inc_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt);
void gr_dec_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt);
int gr_bad_chroot_rename(struct dentry *olddentry, struct vfsmount *oldmnt,
			 struct dentry *newdentry, struct vfsmount *newmnt);

#ifdef CONFIG_GRKERNSEC_RESLOG
extern void gr_log_resource(const struct task_struct *task, const int res,
				   const unsigned long wanted, const int gt);
#else
static inline void gr_log_resource(const struct task_struct *task, const int res,
				   const unsigned long wanted, const int gt)
{
}
#endif

#ifdef CONFIG_GRKERNSEC
void task_grsec_rbac(struct seq_file *m, struct task_struct *p);
void gr_handle_vm86(void);
void gr_handle_mem_readwrite(u64 from, u64 to);

void gr_log_badprocpid(const char *entry);

extern int grsec_enable_dmesg;
extern int grsec_disable_privio;

#ifdef CONFIG_GRKERNSEC_PROC_USERGROUP
extern kgid_t grsec_proc_gid;
#endif

#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
extern int grsec_enable_chroot_findtask;
#endif
#ifdef CONFIG_GRKERNSEC_SETXID
extern int grsec_enable_setxid;
#endif
#endif

#endif
