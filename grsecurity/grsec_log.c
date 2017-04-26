#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/grinternal.h>

#ifdef CONFIG_TREE_PREEMPT_RCU
#define DISABLE_PREEMPT() preempt_disable()
#define ENABLE_PREEMPT() preempt_enable()
#else
#define DISABLE_PREEMPT()
#define ENABLE_PREEMPT()
#endif

#define BEGIN_LOCKS(x) \
	DISABLE_PREEMPT(); \
	rcu_read_lock(); \
	read_lock(&tasklist_lock); \
	read_lock(&grsec_exec_file_lock); \
	if (x != GR_DO_AUDIT) \
		spin_lock(&grsec_alert_lock); \
	else \
		spin_lock(&grsec_audit_lock)

#define END_LOCKS(x) \
	if (x != GR_DO_AUDIT) \
		spin_unlock(&grsec_alert_lock); \
	else \
		spin_unlock(&grsec_audit_lock); \
	read_unlock(&grsec_exec_file_lock); \
	read_unlock(&tasklist_lock); \
	rcu_read_unlock(); \
	ENABLE_PREEMPT(); \
	if (x == GR_DONT_AUDIT) \
		gr_handle_alertkill(current)

enum {
	FLOODING,
	NO_FLOODING
};

extern char *gr_alert_log_fmt;
extern char *gr_audit_log_fmt;
extern char *gr_alert_log_buf;
extern char *gr_audit_log_buf;

static int gr_log_start(int audit)
{
	char *loglevel = (audit == GR_DO_AUDIT) ? KERN_INFO : KERN_ALERT;
	char *fmt = (audit == GR_DO_AUDIT) ? gr_audit_log_fmt : gr_alert_log_fmt;
	char *buf = (audit == GR_DO_AUDIT) ? gr_audit_log_buf : gr_alert_log_buf;
#if (CONFIG_GRKERNSEC_FLOODTIME > 0 && CONFIG_GRKERNSEC_FLOODBURST > 0)
	unsigned long curr_secs = get_seconds();

	if (audit == GR_DO_AUDIT)
		goto set_fmt;

	if (!grsec_alert_wtime || time_after(curr_secs, grsec_alert_wtime + CONFIG_GRKERNSEC_FLOODTIME)) {
		grsec_alert_wtime = curr_secs;
		grsec_alert_fyet = 0;
	} else if (time_before_eq(curr_secs, grsec_alert_wtime + CONFIG_GRKERNSEC_FLOODTIME)
		    && (grsec_alert_fyet < CONFIG_GRKERNSEC_FLOODBURST)) {
		grsec_alert_fyet++;
	} else if (grsec_alert_fyet == CONFIG_GRKERNSEC_FLOODBURST) {
		grsec_alert_wtime = curr_secs;
		grsec_alert_fyet++;
		printk(KERN_ALERT "grsec: more alerts, logging disabled for %d seconds\n", CONFIG_GRKERNSEC_FLOODTIME);
		return FLOODING;
	}
	else return FLOODING;

set_fmt:
#endif
	memset(buf, 0, PAGE_SIZE);
	if (current->signal->curr_ip && gr_acl_is_enabled()) {
		sprintf(fmt, "%s%s", loglevel, "grsec: From %pI4: (%.64s:%c:%.950s) ");
		snprintf(buf, PAGE_SIZE - 1, fmt, &current->signal->curr_ip, current->role->rolename, gr_roletype_to_char(), current->acl->filename);
	} else if (current->signal->curr_ip) {
		sprintf(fmt, "%s%s", loglevel, "grsec: From %pI4: ");
		snprintf(buf, PAGE_SIZE - 1, fmt, &current->signal->curr_ip);
	} else if (gr_acl_is_enabled()) {
		sprintf(fmt, "%s%s", loglevel, "grsec: (%.64s:%c:%.950s) ");
		snprintf(buf, PAGE_SIZE - 1, fmt, current->role->rolename, gr_roletype_to_char(), current->acl->filename);
	} else {
		sprintf(fmt, "%s%s", loglevel, "grsec: ");
		strcpy(buf, fmt);
	}

	return NO_FLOODING;
}

static void gr_log_middle(int audit, const char *msg, va_list ap)
	__attribute__ ((format (printf, 2, 0)));

static void gr_log_middle(int audit, const char *msg, va_list ap)
{
	char *buf = (audit == GR_DO_AUDIT) ? gr_audit_log_buf : gr_alert_log_buf;
	unsigned int len = strlen(buf);

	vsnprintf(buf + len, PAGE_SIZE - len - 1, msg, ap);

	return;
}

static void gr_log_middle_varargs(int audit, const char *msg, ...)
	__attribute__ ((format (printf, 2, 3)));

static void gr_log_middle_varargs(int audit, const char *msg, ...)
{
	char *buf = (audit == GR_DO_AUDIT) ? gr_audit_log_buf : gr_alert_log_buf;
	unsigned int len = strlen(buf);
	va_list ap;

	va_start(ap, msg);
	vsnprintf(buf + len, PAGE_SIZE - len - 1, msg, ap);
	va_end(ap);

	return;
}

static void gr_log_end(int audit, int append_default)
{
	char *buf = (audit == GR_DO_AUDIT) ? gr_audit_log_buf : gr_alert_log_buf;
	if (append_default) {
		struct task_struct *task = current;
		struct task_struct *parent = task->real_parent;
		const struct cred *cred = __task_cred(task);
		const struct cred *pcred = __task_cred(parent);
		unsigned int len = strlen(buf);

		snprintf(buf + len, PAGE_SIZE - len - 1, DEFAULTSECMSG, gr_task_fullpath(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath(task), parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid));
	}

	printk("%s\n", buf);

	return;
}

void gr_log_varargs(int audit, const char *msg, int argtypes, ...)
{
	int logtype;
	char *result = (audit == GR_DO_AUDIT) ? "successful" : "denied";
	char *str1 = NULL, *str2 = NULL, *str3 = NULL;
	void *voidptr = NULL;
	int num1 = 0, num2 = 0;
	unsigned long ulong1 = 0, ulong2 = 0;
	struct dentry *dentry = NULL;
	struct vfsmount *mnt = NULL;
	struct file *file = NULL;
	struct task_struct *task = NULL;
	struct vm_area_struct *vma = NULL;
	const struct cred *cred, *pcred;
	va_list ap;

	BEGIN_LOCKS(audit);
	logtype = gr_log_start(audit);
	if (logtype == FLOODING) {
		END_LOCKS(audit);
		return;
	}
	va_start(ap, argtypes);
	switch (argtypes) {
	case GR_TTYSNIFF:
		task = va_arg(ap, struct task_struct *);
		gr_log_middle_varargs(audit, msg, &task->signal->curr_ip, gr_task_fullpath0(task), task->comm, task_pid_nr(task), gr_parent_task_fullpath0(task), task->real_parent->comm, task_pid_nr(task->real_parent));
		break;
	case GR_SYSCTL_HIDDEN:
		str1 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, result, str1);
		break;
	case GR_RBAC:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		gr_log_middle_varargs(audit, msg, result, gr_to_filename(dentry, mnt));
		break;
	case GR_RBAC_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, result, gr_to_filename(dentry, mnt), str1);
		break;
	case GR_STR_RBAC:
		str1 = va_arg(ap, char *);
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		gr_log_middle_varargs(audit, msg, result, str1, gr_to_filename(dentry, mnt));
		break;
	case GR_RBAC_MODE2:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		str2 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, result, gr_to_filename(dentry, mnt), str1, str2);
		break;
	case GR_RBAC_MODE3:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		str2 = va_arg(ap, char *);
		str3 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, result, gr_to_filename(dentry, mnt), str1, str2, str3);
		break;
	case GR_FILENAME:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		gr_log_middle_varargs(audit, msg, gr_to_filename(dentry, mnt));
		break;
	case GR_STR_FILENAME:
		str1 = va_arg(ap, char *);
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		gr_log_middle_varargs(audit, msg, str1, gr_to_filename(dentry, mnt));
		break;
	case GR_FILENAME_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, gr_to_filename(dentry, mnt), str1);
		break;
	case GR_FILENAME_TWO_INT:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		num1 = va_arg(ap, int);
		num2 = va_arg(ap, int);
		gr_log_middle_varargs(audit, msg, gr_to_filename(dentry, mnt), num1, num2);
		break;
	case GR_FILENAME_TWO_INT_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		num1 = va_arg(ap, int);
		num2 = va_arg(ap, int);
		str1 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, gr_to_filename(dentry, mnt), num1, num2, str1);
		break;
	case GR_TEXTREL:
		str1 = va_arg(ap, char *);
		file = va_arg(ap, struct file *);
		ulong1 = va_arg(ap, unsigned long);
		ulong2 = va_arg(ap, unsigned long);
		gr_log_middle_varargs(audit, msg, str1, file ? gr_to_filename(file->f_path.dentry, file->f_path.mnt) : "<anonymous mapping>", ulong1, ulong2);
		break;
	case GR_PTRACE:
		task = va_arg(ap, struct task_struct *);
		gr_log_middle_varargs(audit, msg, task->exec_file ? gr_to_filename(task->exec_file->f_path.dentry, task->exec_file->f_path.mnt) : "(none)", task->comm, task_pid_nr(task));
		break;
	case GR_RESOURCE:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		str1 = va_arg(ap, char *);
		ulong2 = va_arg(ap, unsigned long);
		gr_log_middle_varargs(audit, msg, ulong1, str1, ulong2, gr_task_fullpath(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid));
		break;
	case GR_CAP:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		str1 = va_arg(ap, char *);
		gr_log_middle_varargs(audit, msg, str1, gr_task_fullpath(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid));
		break;
	case GR_SIG:
		str1 = va_arg(ap, char *);
		voidptr = va_arg(ap, void *);
		gr_log_middle_varargs(audit, msg, str1, voidptr);
		break;
	case GR_SIG2:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		num1 = va_arg(ap, int);
		gr_log_middle_varargs(audit, msg, num1, gr_task_fullpath0(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath0(task), task->real_parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid));
		break;
	case GR_CRASH1:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		gr_log_middle_varargs(audit, msg, gr_task_fullpath(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid), GR_GLOBAL_UID(cred->uid), ulong1);
		break;
	case GR_CRASH2:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		gr_log_middle_varargs(audit, msg, gr_task_fullpath(task), task->comm, task_pid_nr(task), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), gr_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid), ulong1);
		break;
	case GR_RWXMAP:
		file = va_arg(ap, struct file *);
		gr_log_middle_varargs(audit, msg, file ? gr_to_filename(file->f_path.dentry, file->f_path.mnt) : "<anonymous mapping>");
		break;
	case GR_RWXMAPVMA:
		vma = va_arg(ap, struct vm_area_struct *);
		if (vma->vm_file)
			str1 = gr_to_filename(vma->vm_file->f_path.dentry, vma->vm_file->f_path.mnt);
		else if (vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP))
			str1 = "<stack>";
		else if (vma->vm_start <= current->mm->brk &&
			 vma->vm_end >= current->mm->start_brk)
			str1 = "<heap>";
		else
			str1 = "<anonymous mapping>";
		gr_log_middle_varargs(audit, msg, str1);
		break;
	case GR_PSACCT:
		{
			unsigned int wday, cday;
			__u8 whr, chr;
			__u8 wmin, cmin;
			__u8 wsec, csec;

			task = va_arg(ap, struct task_struct *);
			wday = va_arg(ap, unsigned int);
			cday = va_arg(ap, unsigned int);
			whr = va_arg(ap, int);
			chr = va_arg(ap, int);
			wmin = va_arg(ap, int);
			cmin = va_arg(ap, int);
			wsec = va_arg(ap, int);
			csec = va_arg(ap, int);
			ulong1 = va_arg(ap, unsigned long);
			cred = __task_cred(task);
			pcred = __task_cred(task->real_parent);

			gr_log_middle_varargs(audit, msg, gr_task_fullpath(task), task->comm, task_pid_nr(task), &task->signal->curr_ip, tty_name(task->signal->tty), GR_GLOBAL_UID(cred->uid), GR_GLOBAL_UID(cred->euid), GR_GLOBAL_GID(cred->gid), GR_GLOBAL_GID(cred->egid), wday, whr, wmin, wsec, cday, chr, cmin, csec, (task->flags & PF_SIGNALED) ? "killed by signal" : "exited", ulong1, gr_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), &task->real_parent->signal->curr_ip, tty_name(task->real_parent->signal->tty), GR_GLOBAL_UID(pcred->uid), GR_GLOBAL_UID(pcred->euid), GR_GLOBAL_GID(pcred->gid), GR_GLOBAL_GID(pcred->egid));
		}
		break;
	default:
		gr_log_middle(audit, msg, ap);
	}
	va_end(ap);
	// these don't need DEFAULTSECARGS printed on the end
	if (argtypes == GR_CRASH1 || argtypes == GR_CRASH2)
		gr_log_end(audit, 0);
	else
		gr_log_end(audit, 1);
	END_LOCKS(audit);
}
