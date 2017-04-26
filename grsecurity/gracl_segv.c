#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/mman.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/gracl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#if defined(CONFIG_BTRFS_FS) || defined(CONFIG_BTRFS_FS_MODULE)
#include <linux/magic.h>
#include <linux/pagemap.h>
#include "../fs/btrfs/async-thread.h"
#include "../fs/btrfs/ctree.h"
#include "../fs/btrfs/btrfs_inode.h"
#endif

static struct crash_uid *uid_set;
static unsigned short uid_used;
static DEFINE_SPINLOCK(gr_uid_lock);
extern rwlock_t gr_inode_lock;
extern struct acl_subject_label *
	lookup_acl_subj_label(const u64 inode, const dev_t dev,
			      const struct acl_role_label *role);

int
gr_init_uidset(void)
{
	uid_set =
	    kmalloc(GR_UIDTABLE_MAX * sizeof (struct crash_uid), GFP_KERNEL);
	uid_used = 0;

	return uid_set ? 1 : 0;
}

void
gr_free_uidset(void)
{
	if (uid_set) {
		struct crash_uid *tmpset;
		spin_lock(&gr_uid_lock);
		tmpset = uid_set;
		uid_set = NULL;
		uid_used = 0;
		spin_unlock(&gr_uid_lock);
		if (tmpset)
			kfree(tmpset);
	}

	return;
}

int
gr_find_uid(const uid_t uid)
{
	struct crash_uid *tmp = uid_set;
	uid_t buid;
	int low = 0, high = uid_used - 1, mid;

	while (high >= low) {
		mid = (low + high) >> 1;
		buid = tmp[mid].uid;
		if (buid == uid)
			return mid;
		if (buid > uid)
			high = mid - 1;
		if (buid < uid)
			low = mid + 1;
	}

	return -1;
}

static void
gr_insertsort(void)
{
	unsigned short i, j;
	struct crash_uid index;

	for (i = 1; i < uid_used; i++) {
		index = uid_set[i];
		j = i;
		while ((j > 0) && uid_set[j - 1].uid > index.uid) {
			uid_set[j] = uid_set[j - 1];
			j--;
		}
		uid_set[j] = index;
	}

	return;
}

static void
gr_insert_uid(const kuid_t kuid, const unsigned long expires)
{
	int loc;
	uid_t uid = GR_GLOBAL_UID(kuid);

	if (uid_used == GR_UIDTABLE_MAX)
		return;

	loc = gr_find_uid(uid);

	if (loc >= 0) {
		uid_set[loc].expires = expires;
		return;
	}

	uid_set[uid_used].uid = uid;
	uid_set[uid_used].expires = expires;
	uid_used++;

	gr_insertsort();

	return;
}

void
gr_remove_uid(const unsigned short loc)
{
	unsigned short i;

	for (i = loc + 1; i < uid_used; i++)
		uid_set[i - 1] = uid_set[i];

	uid_used--;

	return;
}

int gr_find_and_remove_uid(uid_t uid)
{
	int loc;

	spin_lock(&gr_uid_lock);
	loc = gr_find_uid(uid);
	if (loc >= 0)
		gr_remove_uid(loc);
	spin_unlock(&gr_uid_lock);

	return loc >= 0 ? 1 : 0;
}

int
gr_check_crash_uid(const kuid_t kuid)
{
	int loc;
	int ret = 0;
	uid_t uid;

	if (unlikely(!gr_acl_is_enabled()))
		return 0;

	uid = GR_GLOBAL_UID(kuid);

	spin_lock(&gr_uid_lock);
	loc = gr_find_uid(uid);

	if (loc < 0)
		goto out_unlock;

	if (time_before_eq(uid_set[loc].expires, get_seconds()))
		gr_remove_uid(loc);
	else
		ret = 1;

out_unlock:
	spin_unlock(&gr_uid_lock);
	return ret;
}

extern int gr_fake_force_sig(int sig, struct task_struct *t);

void
gr_handle_crash(struct task_struct *task, const int sig)
{
	struct acl_subject_label *curr;
	struct task_struct *tsk, *tsk2;
	const struct cred *cred;
	const struct cred *cred2;

	if (sig != SIGSEGV && sig != SIGKILL && sig != SIGBUS && sig != SIGILL)
		return;

	if (unlikely(!gr_acl_is_enabled()))
		return;

	curr = task->acl;

	if (!(curr->resmask & (1U << GR_CRASH_RES)))
		return;

	if (time_before_eq(curr->expires, get_seconds())) {
		curr->expires = 0;
		curr->crashes = 0;
	}

	curr->crashes++;

	if (!curr->expires)
		curr->expires = get_seconds() + curr->res[GR_CRASH_RES].rlim_max;

	if ((curr->crashes >= curr->res[GR_CRASH_RES].rlim_cur) &&
	    time_after(curr->expires, get_seconds())) {
		int is_priv = is_privileged_binary(task->mm->exe_file->f_path.dentry);

		rcu_read_lock();
		cred = __task_cred(task);
		if (gr_is_global_nonroot(cred->uid) && is_priv) {
			gr_log_crash1(GR_DONT_AUDIT, GR_SEGVSTART_ACL_MSG, task, curr->res[GR_CRASH_RES].rlim_max);
			spin_lock(&gr_uid_lock);
			gr_insert_uid(cred->uid, curr->expires);
			spin_unlock(&gr_uid_lock);
			curr->expires = 0;
			curr->crashes = 0;
			read_lock(&tasklist_lock);
			do_each_thread(tsk2, tsk) {
				cred2 = __task_cred(tsk);
				if (tsk != task && uid_eq(cred2->uid, cred->uid))
					gr_fake_force_sig(SIGKILL, tsk);
			} while_each_thread(tsk2, tsk);
			read_unlock(&tasklist_lock);
		} else {
			gr_log_crash2(GR_DONT_AUDIT, GR_SEGVNOSUID_ACL_MSG, task, curr->res[GR_CRASH_RES].rlim_max);
			read_lock(&tasklist_lock);
			read_lock(&grsec_exec_file_lock);
			do_each_thread(tsk2, tsk) {
				if (likely(tsk != task)) {
					// if this thread has the same subject as the one that triggered
					// RES_CRASH and it's the same binary, kill it
					if (tsk->acl == task->acl && gr_is_same_file(tsk->exec_file, task->exec_file))
						gr_fake_force_sig(SIGKILL, tsk);
				}
			} while_each_thread(tsk2, tsk);
			read_unlock(&grsec_exec_file_lock);
			read_unlock(&tasklist_lock);
		}
		rcu_read_unlock();
	}

	return;
}

int
gr_check_crash_exec(const struct file *filp)
{
	struct acl_subject_label *curr;
	struct dentry *dentry;

	if (unlikely(!gr_acl_is_enabled()))
		return 0;

	read_lock(&gr_inode_lock);
	dentry = filp->f_path.dentry;
	curr = lookup_acl_subj_label(gr_get_ino_from_dentry(dentry), gr_get_dev_from_dentry(dentry),
				     current->role);
	read_unlock(&gr_inode_lock);

	if (!curr || !(curr->resmask & (1U << GR_CRASH_RES)) ||
	    (!curr->crashes && !curr->expires))
		return 0;

	if ((curr->crashes >= curr->res[GR_CRASH_RES].rlim_cur) &&
	    time_after(curr->expires, get_seconds()))
		return 1;
	else if (time_before_eq(curr->expires, get_seconds())) {
		curr->crashes = 0;
		curr->expires = 0;
	}

	return 0;
}

void
gr_handle_alertkill(struct task_struct *task)
{
	struct acl_subject_label *curracl;
	__u32 curr_ip;
	struct task_struct *p, *p2;

	if (unlikely(!gr_acl_is_enabled()))
		return;

	curracl = task->acl;
	curr_ip = task->signal->curr_ip;

	if ((curracl->mode & GR_KILLIPPROC) && curr_ip) {
		read_lock(&tasklist_lock);
		do_each_thread(p2, p) {
			if (p->signal->curr_ip == curr_ip)
				gr_fake_force_sig(SIGKILL, p);
		} while_each_thread(p2, p);
		read_unlock(&tasklist_lock);
	} else if (curracl->mode & GR_KILLPROC)
		gr_fake_force_sig(SIGKILL, task);

	return;
}
