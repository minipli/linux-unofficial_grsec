#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

int
gr_handle_sysctl_mod(const char *dirname, const char *name, const int op)
{
#ifdef CONFIG_GRKERNSEC_SYSCTL
	if (dirname == NULL || name == NULL)
		return 0;
	if (!strcmp(dirname, "grsecurity") && grsec_lock && (op & MAY_WRITE)) {
		gr_log_str(GR_DONT_AUDIT, GR_SYSCTL_MSG, name);
		return -EACCES;
	}
#endif
	return 0;
}

#if defined(CONFIG_GRKERNSEC_ROFS) || defined(CONFIG_GRKERNSEC_DENYUSB)
static int __maybe_unused __read_only one = 1;
#endif

#if defined(CONFIG_GRKERNSEC_SYSCTL) || defined(CONFIG_GRKERNSEC_ROFS) || \
	defined(CONFIG_GRKERNSEC_DENYUSB)
struct ctl_table grsecurity_table[] = {
#ifdef CONFIG_GRKERNSEC_SYSCTL
#ifdef CONFIG_GRKERNSEC_SYSCTL_DISTRO
#ifdef CONFIG_GRKERNSEC_IO
	{
		.procname	= "disable_priv_io",
		.data		= &grsec_disable_privio,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#endif
#ifdef CONFIG_GRKERNSEC_LINK
	{
		.procname	= "linking_restrictions",
		.data		= &grsec_enable_link,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SYMLINKOWN
	{
		.procname	= "enforce_symlinksifowner",
		.data		= &grsec_enable_symlinkown,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "symlinkown_gid",
		.data		= &grsec_symlinkown_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_BRUTE
	{
		.procname	= "deter_bruteforce",
		.data		= &grsec_enable_brute,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FIFO
	{
		.procname	= "fifo_restrictions",
		.data		= &grsec_enable_fifo,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_PTRACE_READEXEC
	{
		.procname	= "ptrace_readexec",
		.data		= &grsec_enable_ptrace_readexec,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SETXID
	{
		.procname	= "consistent_setxid",
		.data		= &grsec_enable_setxid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_BLACKHOLE
	{
		.procname	= "ip_blackhole",
		.data		= &grsec_enable_blackhole,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "lastack_retries",
		.data		= &grsec_lastack_retries,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_EXECLOG
	{
		.procname	= "exec_logging",
		.data		= &grsec_enable_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_RWXMAP_LOG
	{
		.procname	= "rwxmap_logging",
		.data		= &grsec_enable_log_rwxmaps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SIGNAL
	{
		.procname	= "signal_logging",
		.data		= &grsec_enable_signal,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_FORKFAIL
	{
		.procname	= "forkfail_logging",
		.data		= &grsec_enable_forkfail,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TIME
	{
		.procname	= "timechange_logging",
		.data		= &grsec_enable_time,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	{
		.procname	= "chroot_deny_shmat",
		.data		= &grsec_enable_chroot_shmat,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	{
		.procname	= "chroot_deny_unix",
		.data		= &grsec_enable_chroot_unix,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	{
		.procname	= "chroot_deny_mount",
		.data		= &grsec_enable_chroot_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	{
		.procname	= "chroot_deny_fchdir",
		.data		= &grsec_enable_chroot_fchdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	{
		.procname	= "chroot_deny_chroot",
		.data		= &grsec_enable_chroot_double,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	{
		.procname	= "chroot_deny_pivot",
		.data		= &grsec_enable_chroot_pivot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	{
		.procname	= "chroot_enforce_chdir",
		.data		= &grsec_enable_chroot_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	{
		.procname	= "chroot_deny_chmod",
		.data		= &grsec_enable_chroot_chmod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	{
		.procname	= "chroot_deny_mknod",
		.data		= &grsec_enable_chroot_mknod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	{
		.procname	= "chroot_restrict_nice",
		.data		= &grsec_enable_chroot_nice,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_EXECLOG
	{
		.procname	= "chroot_execlog",
		.data		= &grsec_enable_chroot_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	{
		.procname	= "chroot_caps",
		.data		= &grsec_enable_chroot_caps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
	{
		.procname	= "chroot_deny_bad_rename",
		.data		= &grsec_enable_chroot_rename,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	{
		.procname	= "chroot_deny_sysctl",
		.data		= &grsec_enable_chroot_sysctl,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE
	{
		.procname	= "tpe",
		.data		= &grsec_enable_tpe,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "tpe_gid",
		.data		= &grsec_tpe_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE_INVERT
	{
		.procname	= "tpe_invert",
		.data		= &grsec_enable_tpe_invert,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_TPE_ALL
	{
		.procname	= "tpe_restrict_all",
		.data		= &grsec_enable_tpe_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_ALL
	{
		.procname	= "socket_all",
		.data		= &grsec_enable_socket_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_all_gid",
		.data		= &grsec_socket_all_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_CLIENT
	{
		.procname	= "socket_client",
		.data		= &grsec_enable_socket_client,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_client_gid",
		.data		= &grsec_socket_client_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	{
		.procname	= "socket_server",
		.data		= &grsec_enable_socket_server,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_server_gid",
		.data		= &grsec_socket_server_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_GROUP
	{
		.procname	= "audit_group",
		.data		= &grsec_enable_group,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "audit_gid",
		.data		= &grsec_audit_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_CHDIR
	{
		.procname	= "audit_chdir",
		.data		= &grsec_enable_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_MOUNT
	{
		.procname	= "audit_mount",
		.data		= &grsec_enable_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_DMESG
	{
		.procname	= "dmesg",
		.data		= &grsec_enable_dmesg,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	{
		.procname	= "chroot_findtask",
		.data		= &grsec_enable_chroot_findtask,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_RESLOG
	{
		.procname	= "resource_logging",
		.data		= &grsec_resource_logging,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_AUDIT_PTRACE
	{
		.procname	= "audit_ptrace",
		.data		= &grsec_enable_audit_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	{
		.procname	= "harden_ptrace",
		.data		= &grsec_enable_harden_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_HARDEN_IPC
	{
		.procname	= "harden_ipc",
		.data		= &grsec_enable_harden_ipc,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_HARDEN_TTY
	{
		.procname	= "harden_tty",
		.data		= &grsec_enable_harden_tty,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
	{
		.procname	= "grsec_lock",
		.data		= &grsec_lock,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_ROFS
	{
		.procname	= "romount_protect",
		.data		= &grsec_enable_rofs,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax_secure,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
#if defined(CONFIG_GRKERNSEC_DENYUSB) && !defined(CONFIG_GRKERNSEC_DENYUSB_FORCE)
	{
		.procname	= "deny_new_usb",
		.data		= &grsec_deny_new_usb,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
	{ }
};
#endif
