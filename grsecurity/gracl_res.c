#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/gracl.h>
#include <linux/grinternal.h>

static const char *restab_log[] = {
	[RLIMIT_CPU] = "RLIMIT_CPU",
	[RLIMIT_FSIZE] = "RLIMIT_FSIZE",
	[RLIMIT_DATA] = "RLIMIT_DATA",
	[RLIMIT_STACK] = "RLIMIT_STACK",
	[RLIMIT_CORE] = "RLIMIT_CORE",
	[RLIMIT_RSS] = "RLIMIT_RSS",
	[RLIMIT_NPROC] = "RLIMIT_NPROC",
	[RLIMIT_NOFILE] = "RLIMIT_NOFILE",
	[RLIMIT_MEMLOCK] = "RLIMIT_MEMLOCK",
	[RLIMIT_AS] = "RLIMIT_AS",
	[RLIMIT_LOCKS] = "RLIMIT_LOCKS",
	[RLIMIT_SIGPENDING] = "RLIMIT_SIGPENDING",
	[RLIMIT_MSGQUEUE] = "RLIMIT_MSGQUEUE",
	[RLIMIT_NICE] = "RLIMIT_NICE",
	[RLIMIT_RTPRIO] = "RLIMIT_RTPRIO",
	[RLIMIT_RTTIME] = "RLIMIT_RTTIME",
	[GR_CRASH_RES] = "RLIMIT_CRASH"
};

void
gr_log_resource(const struct task_struct *task,
		const int res, const unsigned long wanted, const int gt)
{
	const struct cred *cred;
	unsigned long rlim;

	if (!gr_acl_is_enabled() && !grsec_resource_logging)
		return;

	// not yet supported resource
	if (unlikely(!restab_log[res]))
		return;

	/*
	 * not really security relevant, too much userland code shared
	 * from pulseaudio that blindly attempts to violate limits in a loop,
	 * resulting in log spam
	 */
	if (res == RLIMIT_NICE)
		return;

	if (res == RLIMIT_CPU || res == RLIMIT_RTTIME)
		rlim = task_rlimit_max(task, res);
	else
		rlim = task_rlimit(task, res);

	if (likely((rlim == RLIM_INFINITY) || (gt && wanted <= rlim) || (!gt && wanted < rlim)))
		return;

	rcu_read_lock();
	cred = __task_cred(task);

	if (res == RLIMIT_NPROC && 
	    (cap_raised(cred->cap_effective, CAP_SYS_ADMIN) || 
	     cap_raised(cred->cap_effective, CAP_SYS_RESOURCE)))
		goto out_rcu_unlock;
	else if (res == RLIMIT_MEMLOCK &&
		 cap_raised(cred->cap_effective, CAP_IPC_LOCK))
		goto out_rcu_unlock;
	rcu_read_unlock();

	gr_log_res_ulong2_str(GR_DONT_AUDIT, GR_RESOURCE_MSG, task, wanted, restab_log[res], rlim);

	return;
out_rcu_unlock:
	rcu_read_unlock();
	return;
}
