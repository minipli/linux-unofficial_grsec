#ifndef __GRINTERNAL_H
#define __GRINTERNAL_H

#ifdef CONFIG_GRKERNSEC

#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/gracl.h>
#include <linux/grdefs.h>
#include <linux/grmsg.h>

void gr_add_learn_entry(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
__u32 gr_search_file(const struct dentry *dentry, const __u32 mode,
			    const struct vfsmount *mnt);
__u32 gr_check_create(const struct dentry *new_dentry,
			     const struct dentry *parent,
			     const struct vfsmount *mnt, const __u32 mode);
int gr_check_protected_task(const struct task_struct *task);
__u32 to_gr_audit(const __u32 reqmode);
int gr_set_acls(const int type);
int gr_acl_is_enabled(void);
char gr_roletype_to_char(void);

void gr_handle_alertkill(struct task_struct *task);
char *gr_to_filename(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *gr_to_filename1(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *gr_to_filename2(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *gr_to_filename3(const struct dentry *dentry,
			    const struct vfsmount *mnt);

extern int grsec_enable_ptrace_readexec;
extern int grsec_enable_harden_ptrace;
extern int grsec_enable_link;
extern int grsec_enable_fifo;
extern int grsec_enable_execve;
extern int grsec_enable_shm;
extern int grsec_enable_execlog;
extern int grsec_enable_signal;
extern int grsec_enable_audit_ptrace;
extern int grsec_enable_forkfail;
extern int grsec_enable_time;
extern int grsec_enable_rofs;
extern int grsec_deny_new_usb;
extern int grsec_enable_chroot_shmat;
extern int grsec_enable_chroot_mount;
extern int grsec_enable_chroot_double;
extern int grsec_enable_chroot_pivot;
extern int grsec_enable_chroot_chdir;
extern int grsec_enable_chroot_chmod;
extern int grsec_enable_chroot_mknod;
extern int grsec_enable_chroot_fchdir;
extern int grsec_enable_chroot_nice;
extern int grsec_enable_chroot_execlog;
extern int grsec_enable_chroot_caps;
extern int grsec_enable_chroot_rename;
extern int grsec_enable_chroot_sysctl;
extern int grsec_enable_chroot_unix;
extern int grsec_enable_symlinkown;
extern kgid_t grsec_symlinkown_gid;
extern int grsec_enable_tpe;
extern kgid_t grsec_tpe_gid;
extern int grsec_enable_tpe_all;
extern int grsec_enable_tpe_invert;
extern int grsec_enable_socket_all;
extern kgid_t grsec_socket_all_gid;
extern int grsec_enable_socket_client;
extern kgid_t grsec_socket_client_gid;
extern int grsec_enable_socket_server;
extern kgid_t grsec_socket_server_gid;
extern kgid_t grsec_audit_gid;
extern int grsec_enable_group;
extern int grsec_enable_log_rwxmaps;
extern int grsec_enable_mount;
extern int grsec_enable_chdir;
extern int grsec_resource_logging;
extern int grsec_enable_blackhole;
extern int grsec_lastack_retries;
extern int grsec_enable_brute;
extern int grsec_enable_harden_ipc;
extern int grsec_enable_harden_tty;
extern int grsec_lock;

extern spinlock_t grsec_alert_lock;
extern unsigned long grsec_alert_wtime;
extern unsigned long grsec_alert_fyet;

extern spinlock_t grsec_audit_lock;

extern rwlock_t grsec_exec_file_lock;

#define gr_task_fullpath(tsk) ((tsk)->exec_file ? \
			gr_to_filename2((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define gr_parent_task_fullpath(tsk) ((tsk)->real_parent->exec_file ? \
			gr_to_filename3((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define gr_task_fullpath0(tsk) ((tsk)->exec_file ? \
			gr_to_filename((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define gr_parent_task_fullpath0(tsk) ((tsk)->real_parent->exec_file ? \
			gr_to_filename1((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define proc_is_chrooted(tsk_a)  ((tsk_a)->gr_is_chrooted)

#define have_same_root(tsk_a,tsk_b) ((tsk_a)->gr_chroot_dentry == (tsk_b)->gr_chroot_dentry)

static inline bool gr_is_same_file(const struct file *file1, const struct file *file2)
{
	if (file1 && file2) {
		const struct inode *inode1 = file1->f_path.dentry->d_inode;
		const struct inode *inode2 = file2->f_path.dentry->d_inode;
		if (inode1->i_ino == inode2->i_ino && inode1->i_sb->s_dev == inode2->i_sb->s_dev)
			return true;
	}

	return false;
}

#define GR_CHROOT_CAPS {{ \
	CAP_TO_MASK(CAP_LINUX_IMMUTABLE) | CAP_TO_MASK(CAP_NET_ADMIN) | \
	CAP_TO_MASK(CAP_SYS_MODULE) | CAP_TO_MASK(CAP_SYS_RAWIO) | \
	CAP_TO_MASK(CAP_SYS_PACCT) | CAP_TO_MASK(CAP_SYS_ADMIN) | \
	CAP_TO_MASK(CAP_SYS_BOOT) | CAP_TO_MASK(CAP_SYS_TIME) | \
	CAP_TO_MASK(CAP_NET_RAW) | CAP_TO_MASK(CAP_SYS_TTY_CONFIG) | \
	CAP_TO_MASK(CAP_IPC_OWNER) | CAP_TO_MASK(CAP_SETFCAP), \
	CAP_TO_MASK(CAP_SYSLOG) | CAP_TO_MASK(CAP_MAC_ADMIN) }}

#define security_learn(normal_msg,args...) \
({ \
	read_lock(&grsec_exec_file_lock); \
	gr_add_learn_entry(normal_msg "\n", ## args); \
	read_unlock(&grsec_exec_file_lock); \
})

enum {
	GR_DO_AUDIT,
	GR_DONT_AUDIT,
	/* used for non-audit messages that we shouldn't kill the task on */
	GR_DONT_AUDIT_GOOD
};

enum {
	GR_TTYSNIFF,
	GR_RBAC,
	GR_RBAC_STR,
	GR_STR_RBAC,
	GR_RBAC_MODE2,
	GR_RBAC_MODE3,
	GR_FILENAME,
	GR_SYSCTL_HIDDEN,
	GR_NOARGS,
	GR_ONE_INT,
	GR_ONE_INT_TWO_STR,
	GR_ONE_STR,
	GR_STR_INT,
	GR_TWO_STR_INT,
	GR_TWO_INT,
	GR_TWO_U64,
	GR_THREE_INT,
	GR_FIVE_INT_TWO_STR,
	GR_TWO_STR,
	GR_THREE_STR,
	GR_FOUR_STR,
	GR_STR_FILENAME,
	GR_FILENAME_STR,
	GR_FILENAME_TWO_INT,
	GR_FILENAME_TWO_INT_STR,
	GR_TEXTREL,
	GR_PTRACE,
	GR_RESOURCE,
	GR_CAP,
	GR_SIG,
	GR_SIG2,
	GR_CRASH1,
	GR_CRASH2,
	GR_PSACCT,
	GR_RWXMAP,
	GR_RWXMAPVMA
};

#define gr_log_hidden_sysctl(audit, msg, str) gr_log_varargs(audit, msg, GR_SYSCTL_HIDDEN, str)
#define gr_log_ttysniff(audit, msg, task) gr_log_varargs(audit, msg, GR_TTYSNIFF, task)
#define gr_log_fs_rbac_generic(audit, msg, dentry, mnt) gr_log_varargs(audit, msg, GR_RBAC, dentry, mnt)
#define gr_log_fs_rbac_str(audit, msg, dentry, mnt, str) gr_log_varargs(audit, msg, GR_RBAC_STR, dentry, mnt, str)
#define gr_log_fs_str_rbac(audit, msg, str, dentry, mnt) gr_log_varargs(audit, msg, GR_STR_RBAC, str, dentry, mnt)
#define gr_log_fs_rbac_mode2(audit, msg, dentry, mnt, str1, str2) gr_log_varargs(audit, msg, GR_RBAC_MODE2, dentry, mnt, str1, str2)
#define gr_log_fs_rbac_mode3(audit, msg, dentry, mnt, str1, str2, str3) gr_log_varargs(audit, msg, GR_RBAC_MODE3, dentry, mnt, str1, str2, str3)
#define gr_log_fs_generic(audit, msg, dentry, mnt) gr_log_varargs(audit, msg, GR_FILENAME, dentry, mnt)
#define gr_log_noargs(audit, msg) gr_log_varargs(audit, msg, GR_NOARGS)
#define gr_log_int(audit, msg, num) gr_log_varargs(audit, msg, GR_ONE_INT, num)
#define gr_log_int_str2(audit, msg, num, str1, str2) gr_log_varargs(audit, msg, GR_ONE_INT_TWO_STR, num, str1, str2)
#define gr_log_str(audit, msg, str) gr_log_varargs(audit, msg, GR_ONE_STR, str)
#define gr_log_str_int(audit, msg, str, num) gr_log_varargs(audit, msg, GR_STR_INT, str, num)
#define gr_log_int_int(audit, msg, num1, num2) gr_log_varargs(audit, msg, GR_TWO_INT, num1, num2)
#define gr_log_two_u64(audit, msg, num1, num2) gr_log_varargs(audit, msg, GR_TWO_U64, num1, num2)
#define gr_log_int3(audit, msg, num1, num2, num3) gr_log_varargs(audit, msg, GR_THREE_INT, num1, num2, num3)
#define gr_log_int5_str2(audit, msg, num1, num2, str1, str2) gr_log_varargs(audit, msg, GR_FIVE_INT_TWO_STR, num1, num2, str1, str2)
#define gr_log_str_str(audit, msg, str1, str2) gr_log_varargs(audit, msg, GR_TWO_STR, str1, str2)
#define gr_log_str2_int(audit, msg, str1, str2, num) gr_log_varargs(audit, msg, GR_TWO_STR_INT, str1, str2, num)
#define gr_log_str3(audit, msg, str1, str2, str3) gr_log_varargs(audit, msg, GR_THREE_STR, str1, str2, str3)
#define gr_log_str4(audit, msg, str1, str2, str3, str4) gr_log_varargs(audit, msg, GR_FOUR_STR, str1, str2, str3, str4)
#define gr_log_str_fs(audit, msg, str, dentry, mnt) gr_log_varargs(audit, msg, GR_STR_FILENAME, str, dentry, mnt)
#define gr_log_fs_str(audit, msg, dentry, mnt, str) gr_log_varargs(audit, msg, GR_FILENAME_STR, dentry, mnt, str)
#define gr_log_fs_int2(audit, msg, dentry, mnt, num1, num2) gr_log_varargs(audit, msg, GR_FILENAME_TWO_INT, dentry, mnt, num1, num2)
#define gr_log_fs_int2_str(audit, msg, dentry, mnt, num1, num2, str) gr_log_varargs(audit, msg, GR_FILENAME_TWO_INT_STR, dentry, mnt, num1, num2, str)
#define gr_log_textrel_ulong_ulong(audit, msg, str, file, ulong1, ulong2) gr_log_varargs(audit, msg, GR_TEXTREL, str, file, ulong1, ulong2)
#define gr_log_ptrace(audit, msg, task) gr_log_varargs(audit, msg, GR_PTRACE, task)
#define gr_log_res_ulong2_str(audit, msg, task, ulong1, str, ulong2) gr_log_varargs(audit, msg, GR_RESOURCE, task, ulong1, str, ulong2)
#define gr_log_cap(audit, msg, task, str) gr_log_varargs(audit, msg, GR_CAP, task, str)
#define gr_log_sig_addr(audit, msg, str, addr) gr_log_varargs(audit, msg, GR_SIG, str, addr)
#define gr_log_sig_task(audit, msg, task, num) gr_log_varargs(audit, msg, GR_SIG2, task, num)
#define gr_log_crash1(audit, msg, task, ulong) gr_log_varargs(audit, msg, GR_CRASH1, task, ulong)
#define gr_log_crash2(audit, msg, task, ulong1) gr_log_varargs(audit, msg, GR_CRASH2, task, ulong1)
#define gr_log_procacct(audit, msg, task, num1, num2, num3, num4, num5, num6, num7, num8, num9) gr_log_varargs(audit, msg, GR_PSACCT, task, num1, num2, num3, num4, num5, num6, num7, num8, num9)
#define gr_log_rwxmap(audit, msg, str) gr_log_varargs(audit, msg, GR_RWXMAP, str)
#define gr_log_rwxmap_vma(audit, msg, str) gr_log_varargs(audit, msg, GR_RWXMAPVMA, str)

void gr_log_varargs(int audit, const char *msg, int argtypes, ...);

#endif

#endif
