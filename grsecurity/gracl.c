#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/sysctl.h>
#include <linux/netdevice.h>
#include <linux/ptrace.h>
#include <linux/gracl.h>
#include <linux/gralloc.h>
#include <linux/security.h>
#include <linux/grinternal.h>
#include <linux/pid_namespace.h>
#include <linux/stop_machine.h>
#include <linux/fdtable.h>
#include <linux/percpu.h>
#include <linux/hugetlb.h>
#include <linux/posix-timers.h>
#include <linux/prefetch.h>
#if defined(CONFIG_BTRFS_FS) || defined(CONFIG_BTRFS_FS_MODULE)
#include <linux/magic.h>
#include <linux/pagemap.h>
#include "../fs/btrfs/async-thread.h"
#include "../fs/btrfs/ctree.h"
#include "../fs/btrfs/btrfs_inode.h"
#endif
#include "../fs/mount.h"

#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/mman.h>

#define FOR_EACH_ROLE_START(role) \
	role = running_polstate.role_list; \
	while (role) {

#define FOR_EACH_ROLE_END(role) \
		role = role->prev; \
	}

extern struct path gr_real_root;

static struct gr_policy_state running_polstate;
struct gr_policy_state *polstate = &running_polstate;
extern struct gr_alloc_state *current_alloc_state;

extern char *gr_shared_page[4];
DEFINE_RWLOCK(gr_inode_lock);

static unsigned int gr_status __read_only = GR_STATUS_INIT;

#ifdef CONFIG_NET
extern struct vfsmount *sock_mnt;
#endif

extern struct vfsmount *pipe_mnt;
extern struct vfsmount *shm_mnt;

#ifdef CONFIG_HUGETLBFS
extern struct vfsmount *hugetlbfs_vfsmount[HUGE_MAX_HSTATE];
#endif

extern u16 acl_sp_role_value;
extern struct acl_object_label *fakefs_obj_rw;
extern struct acl_object_label *fakefs_obj_rwx;

int gr_acl_is_enabled(void)
{
	return (gr_status & GR_READY);
}

void gr_enable_rbac_system(void)
{
	pax_open_kernel();
	gr_status |= GR_READY;
	pax_close_kernel();
}

int gr_rbac_disable(void *unused)
{
	pax_open_kernel();
	gr_status &= ~GR_READY;
	pax_close_kernel();

	return 0;
}

static inline dev_t __get_dev(const struct dentry *dentry)
{
	struct dentry *ldentry = d_backing_dentry((struct dentry *)dentry);

#if defined(CONFIG_BTRFS_FS) || defined(CONFIG_BTRFS_FS_MODULE)
	if (ldentry->d_sb->s_magic == BTRFS_SUPER_MAGIC)
		return BTRFS_I(d_inode(ldentry))->root->anon_dev;
	else
#endif
		return d_inode(ldentry)->i_sb->s_dev;
}

static inline u64 __get_ino(const struct dentry *dentry)
{
	struct dentry *ldentry = d_backing_dentry((struct dentry *)dentry);

#if defined(CONFIG_BTRFS_FS) || defined(CONFIG_BTRFS_FS_MODULE)
	if (ldentry->d_sb->s_magic == BTRFS_SUPER_MAGIC)
		return btrfs_ino(d_inode(dentry));
	else
#endif
		return d_inode(ldentry)->i_ino;
}

dev_t gr_get_dev_from_dentry(struct dentry *dentry)
{
	return __get_dev(dentry);
}

u64 gr_get_ino_from_dentry(struct dentry *dentry)
{
	return __get_ino(dentry);
}

static char gr_task_roletype_to_char(struct task_struct *task)
{
	switch (task->role->roletype &
		(GR_ROLE_DEFAULT | GR_ROLE_USER | GR_ROLE_GROUP |
		 GR_ROLE_SPECIAL)) {
	case GR_ROLE_DEFAULT:
		return 'D';
	case GR_ROLE_USER:
		return 'U';
	case GR_ROLE_GROUP:
		return 'G';
	case GR_ROLE_SPECIAL:
		return 'S';
	}

	return 'X';
}

char gr_roletype_to_char(void)
{
	return gr_task_roletype_to_char(current);
}

int
gr_acl_tpe_check(void)
{
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
	if (current->role->roletype & GR_ROLE_TPE)
		return 1;
	else
		return 0;
}

int
gr_handle_rawio(const struct inode *inode)
{
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	if (inode && (S_ISBLK(inode->i_mode) || (S_ISCHR(inode->i_mode) && imajor(inode) == RAW_MAJOR)) &&
	    grsec_enable_chroot_caps && proc_is_chrooted(current) &&
	    !capable(CAP_SYS_RAWIO))
		return 1;
#endif
	return 0;
}

int
gr_streq(const char *a, const char *b, const unsigned int lena, const unsigned int lenb)
{
	if (likely(lena != lenb))
		return 0;

	return !memcmp(a, b, lena);
}

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	return prepend(buffer, buflen, (const char *)name->name, name->len);
}

static int prepend_path(const struct path *path, struct path *root,
			char **buffer, int *buflen)
{
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	struct mount *mnt = real_mount(vfsmnt);
	bool slash = false;
	int error = 0;

	while (dentry != root->dentry || vfsmnt != root->mnt) {
		struct dentry * parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (!mnt_has_parent(mnt)) {
				goto out;
			}
			dentry = mnt->mnt_mountpoint;
			mnt = mnt->mnt_parent;
			vfsmnt = &mnt->mnt;
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		spin_lock(&dentry->d_lock);
		error = prepend_name(buffer, buflen, &dentry->d_name);
		spin_unlock(&dentry->d_lock);
		if (!error)
			error = prepend(buffer, buflen, "/", 1);
		if (error)
			break;

		slash = true;
		dentry = parent;
	}

out:
	if (!error && !slash)
		error = prepend(buffer, buflen, "/", 1);

	return error;
}

/* this must be called with mount_lock and rename_lock held */

static char *__our_d_path(const struct path *path, struct path *root,
			char *buf, int buflen)
{
	char *res = buf + buflen;
	int error;

	prepend(&res, &buflen, "\0", 1);
	error = prepend_path(path, root, &res, &buflen);
	if (error)
		return ERR_PTR(error);

	return res;
}

static char *
gen_full_path(struct path *path, struct path *root, char *buf, int buflen)
{
	char *retval;

	retval = __our_d_path(path, root, buf, buflen);
	if (unlikely(IS_ERR(retval)))
		retval = strcpy(buf, "<path too long>");
	else if (unlikely(retval[1] == '/' && retval[2] == '\0'))
		retval[1] = '\0';

	return retval;
}

static char *
__d_real_path(const struct dentry *dentry, const struct vfsmount *vfsmnt,
		char *buf, int buflen)
{
	struct path path;
	char *res;

	path.dentry = (struct dentry *)dentry;
	path.mnt = (struct vfsmount *)vfsmnt;

	/* we can use gr_real_root.dentry, gr_real_root.mnt, because this is only called
	   by the RBAC system */
	res = gen_full_path(&path, &gr_real_root, buf, buflen);

	return res;
}

static char *
d_real_path(const struct dentry *dentry, const struct vfsmount *vfsmnt,
	    char *buf, int buflen)
{
	char *res;
	struct path path;
	struct path root;
	struct task_struct *reaper = init_pid_ns.child_reaper;

	path.dentry = (struct dentry *)dentry;
	path.mnt = (struct vfsmount *)vfsmnt;

	/* we can't use gr_real_root.dentry, gr_real_root.mnt, because they belong only to the RBAC system */
	get_fs_root(reaper->fs, &root);

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);
	res = gen_full_path(&path, &root, buf, buflen);
	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);

	path_put(&root);
	return res;
}

char *
gr_to_filename_rbac(const struct dentry *dentry, const struct vfsmount *mnt)
{
	char *ret;
	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);
	ret = __d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0],smp_processor_id()),
			     PAGE_SIZE);
	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);
	return ret;
}

static char *
gr_to_proc_filename_rbac(const struct dentry *dentry, const struct vfsmount *mnt)
{
	char *ret;
	char *buf;
	int buflen;

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);
	buf = per_cpu_ptr(gr_shared_page[0], smp_processor_id());
	ret = __d_real_path(dentry, mnt, buf, PAGE_SIZE - 6);
	buflen = (int)(ret - buf);
	if (buflen >= 5)
		prepend(&ret, &buflen, "/proc", 5);
	else
		ret = strcpy(buf, "<path too long>");
	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);
	return ret;
}

char *
gr_to_filename_nolock(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return __d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0],smp_processor_id()),
			     PAGE_SIZE);
}

char *
gr_to_filename(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename1(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[1], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename2(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[2], smp_processor_id()),
			   PAGE_SIZE);
}

char *
gr_to_filename3(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[3], smp_processor_id()),
			   PAGE_SIZE);
}

__u32
to_gr_audit(const __u32 reqmode)
{
	/* masks off auditable permission flags, then shifts them to create
	   auditing flags, and adds the special case of append auditing if
	   we're requesting write */
	return (((reqmode & ~GR_AUDITS) << 10) | ((reqmode & GR_WRITE) ? GR_AUDIT_APPEND : 0));
}

struct acl_role_label *
__lookup_acl_role_label(const struct gr_policy_state *state, const struct task_struct *task, const uid_t uid,
		      const gid_t gid)
{
	unsigned int index = gr_rhash(uid, GR_ROLE_USER, state->acl_role_set.r_size);
	struct acl_role_label *match;
	struct role_allowed_ip *ipp;
	unsigned int x;
	u32 curr_ip = task->signal->saved_ip;

	match = state->acl_role_set.r_hash[index];

	while (match) {
		if ((match->roletype & (GR_ROLE_DOMAIN | GR_ROLE_USER)) == (GR_ROLE_DOMAIN | GR_ROLE_USER)) {
			for (x = 0; x < match->domain_child_num; x++) {
				if (match->domain_children[x] == uid)
					goto found;
			}
		} else if (match->uidgid == uid && match->roletype & GR_ROLE_USER)
			break;
		match = match->next;
	}
found:
	if (match == NULL) {
	      try_group:
		index = gr_rhash(gid, GR_ROLE_GROUP, state->acl_role_set.r_size);
		match = state->acl_role_set.r_hash[index];

		while (match) {
			if ((match->roletype & (GR_ROLE_DOMAIN | GR_ROLE_GROUP)) == (GR_ROLE_DOMAIN | GR_ROLE_GROUP)) {
				for (x = 0; x < match->domain_child_num; x++) {
					if (match->domain_children[x] == gid)
						goto found2;
				}
			} else if (match->uidgid == gid && match->roletype & GR_ROLE_GROUP)
				break;
			match = match->next;
		}
found2:
		if (match == NULL)
			match = state->default_role;
		if (match->allowed_ips == NULL)
			return match;
		else {
			for (ipp = match->allowed_ips; ipp; ipp = ipp->next) {
				if (likely
				    ((ntohl(curr_ip) & ipp->netmask) ==
				     (ntohl(ipp->addr) & ipp->netmask)))
					return match;
			}
			match = state->default_role;
		}
	} else if (match->allowed_ips == NULL) {
		return match;
	} else {
		for (ipp = match->allowed_ips; ipp; ipp = ipp->next) {
			if (likely
			    ((ntohl(curr_ip) & ipp->netmask) ==
			     (ntohl(ipp->addr) & ipp->netmask)))
				return match;
		}
		goto try_group;
	}

	return match;
}

static struct acl_role_label *
lookup_acl_role_label(const struct task_struct *task, const uid_t uid,
		      const gid_t gid)
{
	return __lookup_acl_role_label(&running_polstate, task, uid, gid);
}

struct acl_subject_label *
lookup_acl_subj_label(const u64 ino, const dev_t dev,
		      const struct acl_role_label *role)
{
	unsigned int index = gr_fhash(ino, dev, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

struct acl_subject_label *
lookup_acl_subj_label_deleted(const u64 ino, const dev_t dev,
			  const struct acl_role_label *role)
{
	unsigned int index = gr_fhash(ino, dev, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       !(match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && (match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

static struct acl_object_label *
lookup_acl_obj_label(const u64 ino, const dev_t dev,
		     const struct acl_subject_label *subj)
{
	unsigned int index = gr_fhash(ino, dev, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

static struct acl_object_label *
lookup_acl_obj_label_create(const u64 ino, const dev_t dev,
		     const struct acl_subject_label *subj)
{
	unsigned int index = gr_fhash(ino, dev, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       !(match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && (match->mode & GR_DELETED))
		return match;

	match = subj->obj_hash[index];

	while (match && (match->inode != ino || match->device != dev ||
	       (match->mode & GR_DELETED))) {
		match = match->next;
	}

	if (match && !(match->mode & GR_DELETED))
		return match;
	else
		return NULL;
}

struct name_entry *
__lookup_name_entry(const struct gr_policy_state *state, const char *name)
{
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(NULL, (const unsigned char *)name, len);
	unsigned int index = key % state->name_set.n_size;
	struct name_entry *match;

	match = state->name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len)))
		match = match->next;

	return match;
}

static struct name_entry *
lookup_name_entry(const char *name)
{
	return __lookup_name_entry(&running_polstate, name);
}

static struct name_entry *
lookup_name_entry_create(const char *name)
{
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(NULL, (const unsigned char *)name, len);
	unsigned int index = key % running_polstate.name_set.n_size;
	struct name_entry *match;

	match = running_polstate.name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len) ||
			 !match->deleted))
		match = match->next;

	if (match && match->deleted)
		return match;

	match = running_polstate.name_set.n_hash[index];

	while (match && (match->key != key || !gr_streq(match->name, name, match->len, len) ||
			 match->deleted))
		match = match->next;

	if (match && !match->deleted)
		return match;
	else
		return NULL;
}

static struct inodev_entry *
lookup_inodev_entry(const u64 ino, const dev_t dev)
{
	unsigned int index = gr_fhash(ino, dev, running_polstate.inodev_set.i_size);
	struct inodev_entry *match;

	match = running_polstate.inodev_set.i_hash[index];

	while (match && (match->nentry->inode != ino || match->nentry->device != dev))
		match = match->next;

	return match;
}

void
__insert_inodev_entry(const struct gr_policy_state *state, struct inodev_entry *entry)
{
	unsigned int index = gr_fhash(entry->nentry->inode, entry->nentry->device,
				    state->inodev_set.i_size);
	struct inodev_entry **curr;

	entry->prev = NULL;

	curr = &state->inodev_set.i_hash[index];
	if (*curr != NULL)
		(*curr)->prev = entry;
	
	entry->next = *curr;
	*curr = entry;

	return;
}

static void
insert_inodev_entry(struct inodev_entry *entry)
{
	__insert_inodev_entry(&running_polstate, entry);
}

void
insert_acl_obj_label(struct acl_object_label *obj,
		     struct acl_subject_label *subj)
{
	unsigned int index =
	    gr_fhash(obj->inode, obj->device, subj->obj_hash_size);
	struct acl_object_label **curr;

	obj->prev = NULL;

	curr = &subj->obj_hash[index];
	if (*curr != NULL)
		(*curr)->prev = obj;

	obj->next = *curr;
	*curr = obj;

	return;
}

void
insert_acl_subj_label(struct acl_subject_label *obj,
		      struct acl_role_label *role)
{
	unsigned int index = gr_fhash(obj->inode, obj->device, role->subj_hash_size);
	struct acl_subject_label **curr;

	obj->prev = NULL;

	curr = &role->subj_hash[index];
	if (*curr != NULL)
		(*curr)->prev = obj;

	obj->next = *curr;
	*curr = obj;

	return;
}

/* derived from glibc fnmatch() 0: match, 1: no match*/

static int
glob_match(const char *p, const char *n)
{
	char c;

	while ((c = *p++) != '\0') {
	switch (c) {
		case '?':
			if (*n == '\0')
				return 1;
			else if (*n == '/')
				return 1;
			break;
		case '\\':
			if (*n != c)
				return 1;
			break;
		case '*':
			for (c = *p++; c == '?' || c == '*'; c = *p++) {
				if (*n == '/')
					return 1;
				else if (c == '?') {
					if (*n == '\0')
						return 1;
					else
						++n;
				}
			}
			if (c == '\0') {
				return 0;
			} else {
				const char *endp;

				if ((endp = strchr(n, '/')) == NULL)
					endp = n + strlen(n);

				if (c == '[') {
					for (--p; n < endp; ++n)
						if (!glob_match(p, n))
							return 0;
				} else if (c == '/') {
					while (*n != '\0' && *n != '/')
						++n;
					if (*n == '/' && !glob_match(p, n + 1))
						return 0;
				} else {
					for (--p; n < endp; ++n)
						if (*n == c && !glob_match(p, n))
							return 0;
				}

				return 1;
			}
		case '[':
			{
			int not;
			char cold;

			if (*n == '\0' || *n == '/')
				return 1;

			not = (*p == '!' || *p == '^');
			if (not)
				++p;

			c = *p++;
			for (;;) {
				unsigned char fn = (unsigned char)*n;

				if (c == '\0')
					return 1;
				else {
					if (c == fn)
						goto matched;
					cold = c;
					c = *p++;

					if (c == '-' && *p != ']') {
						unsigned char cend = *p++;

						if (cend == '\0')
							return 1;

						if (cold <= fn && fn <= cend)
							goto matched;

						c = *p++;
					}
				}

				if (c == ']')
					break;
			}
			if (!not)
				return 1;
			break;
		matched:
			while (c != ']') {
				if (c == '\0')
					return 1;

				c = *p++;
			}
			if (not)
				return 1;
		}
		break;
	default:
		if (c != *n)
			return 1;
	}

	++n;
	}

	if (*n == '\0')
		return 0;

	if (*n == '/')
		return 0;

	return 1;
}

static struct acl_object_label *
chk_glob_label(struct acl_object_label *globbed,
	const struct dentry *dentry, const struct vfsmount *mnt, char **path)
{
	struct acl_object_label *tmp;

	if (*path == NULL)
		*path = gr_to_filename_nolock(dentry, mnt);

	tmp = globbed;

	while (tmp) {
		if (!glob_match(tmp->filename, *path))
			return tmp;
		tmp = tmp->next;
	}

	return NULL;
}

static struct acl_object_label *
__full_lookup(const struct dentry *orig_dentry, const struct vfsmount *orig_mnt,
	    const u64 curr_ino, const dev_t curr_dev,
	    const struct acl_subject_label *subj, char **path, const int checkglob)
{
	struct acl_subject_label *tmpsubj;
	struct acl_object_label *retval;
	struct acl_object_label *retval2;

	tmpsubj = (struct acl_subject_label *) subj;
	read_lock(&gr_inode_lock);
	do {
		retval = lookup_acl_obj_label(curr_ino, curr_dev, tmpsubj);
		if (retval) {
			if (checkglob && retval->globbed) {
				retval2 = chk_glob_label(retval->globbed, orig_dentry, orig_mnt, path);
				if (retval2)
					retval = retval2;
			}
			break;
		}
	} while ((tmpsubj = tmpsubj->parent_subject));
	read_unlock(&gr_inode_lock);

	return retval;
}

static struct acl_object_label *
full_lookup(const struct dentry *orig_dentry, const struct vfsmount *orig_mnt,
	    struct dentry *curr_dentry,
	    const struct acl_subject_label *subj, char **path, const int checkglob)
{
	int newglob = checkglob;
	u64 inode;
	dev_t device;

	/* if we aren't checking a subdirectory of the original path yet, don't do glob checking
	   as we don't want a / * rule to match instead of the / object
	   don't do this for create lookups that call this function though, since they're looking up
	   on the parent and thus need globbing checks on all paths
	*/
	if (orig_dentry == curr_dentry && newglob != GR_CREATE_GLOB)
		newglob = GR_NO_GLOB;

	spin_lock(&curr_dentry->d_lock);
	inode = __get_ino(curr_dentry);
	device = __get_dev(curr_dentry);
	spin_unlock(&curr_dentry->d_lock);

	return __full_lookup(orig_dentry, orig_mnt, inode, device, subj, path, newglob);
}

#ifdef CONFIG_HUGETLBFS
static inline bool
is_hugetlbfs_mnt(const struct vfsmount *mnt)
{
	int i;
	for (i = 0; i < HUGE_MAX_HSTATE; i++) {
		if (unlikely(hugetlbfs_vfsmount[i] == mnt))
			return true;
	}

	return false;
}
#endif

static struct acl_object_label *
__chk_obj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj, char *path, const int checkglob)
{
	struct dentry *dentry = (struct dentry *) l_dentry;
	struct vfsmount *mnt = (struct vfsmount *) l_mnt;
	struct inode * inode = d_backing_inode(dentry);
	struct mount *real_mnt = real_mount(mnt);
	struct acl_object_label *retval;
	struct dentry *parent;

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);

	if (unlikely((mnt == shm_mnt && inode->i_nlink == 0) || mnt == pipe_mnt ||
#ifdef CONFIG_NET
	    mnt == sock_mnt ||
#endif
#ifdef CONFIG_HUGETLBFS
	    (is_hugetlbfs_mnt(mnt) && inode->i_nlink == 0) ||
#endif
		/* ignore Eric Biederman */
	    IS_PRIVATE(inode))) {
		retval = (subj->mode & GR_SHMEXEC) ? fakefs_obj_rwx : fakefs_obj_rw;
		goto out;
	}

	for (;;) {
		if (dentry == gr_real_root.dentry && mnt == gr_real_root.mnt)
			break;

		if (dentry == mnt->mnt_root || IS_ROOT(dentry)) {
			if (!mnt_has_parent(real_mnt))
				break;

			retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);
			if (retval != NULL)
				goto out;

			dentry = real_mnt->mnt_mountpoint;
			real_mnt = real_mnt->mnt_parent;
			mnt = &real_mnt->mnt;
			continue;
		}

		parent = dentry->d_parent;
		retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);
		if (retval != NULL)
			goto out;

		dentry = parent;
	}

	retval = full_lookup(l_dentry, l_mnt, dentry, subj, &path, checkglob);

	/* gr_real_root is pinned so we don't have to hold a reference */
	if (retval == NULL)
		retval = full_lookup(l_dentry, l_mnt, gr_real_root.dentry, subj, &path, checkglob);
out:
	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);

	BUG_ON(retval == NULL);

	return retval;
}

static struct acl_object_label *
chk_obj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj)
{
	char *path = NULL;
	return __chk_obj_label(l_dentry, l_mnt, subj, path, GR_REG_GLOB);
}

static struct acl_object_label *
chk_obj_label_noglob(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	      const struct acl_subject_label *subj)
{
	char *path = NULL;
	return __chk_obj_label(l_dentry, l_mnt, subj, path, GR_NO_GLOB);
}

static struct acl_object_label *
chk_obj_create_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
		     const struct acl_subject_label *subj, char *path)
{
	return __chk_obj_label(l_dentry, l_mnt, subj, path, GR_CREATE_GLOB);
}

struct acl_subject_label *
chk_subj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt,
	       const struct acl_role_label *role)
{
	struct dentry *dentry = (struct dentry *) l_dentry;
	struct vfsmount *mnt = (struct vfsmount *) l_mnt;
	struct mount *real_mnt = real_mount(mnt);
	struct acl_subject_label *retval;
	struct dentry *parent;

	read_seqlock_excl(&mount_lock);
	write_seqlock(&rename_lock);

	for (;;) {
		if (dentry == gr_real_root.dentry && mnt == gr_real_root.mnt)
			break;
		if (dentry == mnt->mnt_root || IS_ROOT(dentry)) {
			if (!mnt_has_parent(real_mnt))
				break;

			spin_lock(&dentry->d_lock);
			read_lock(&gr_inode_lock);
			retval =
				lookup_acl_subj_label(__get_ino(dentry),
						__get_dev(dentry), role);
			read_unlock(&gr_inode_lock);
			spin_unlock(&dentry->d_lock);
			if (retval != NULL)
				goto out;

			dentry = real_mnt->mnt_mountpoint;
			real_mnt = real_mnt->mnt_parent;
			mnt = &real_mnt->mnt;
			continue;
		}

		spin_lock(&dentry->d_lock);
		read_lock(&gr_inode_lock);
		retval = lookup_acl_subj_label(__get_ino(dentry),
					  __get_dev(dentry), role);
		read_unlock(&gr_inode_lock);
		parent = dentry->d_parent;
		spin_unlock(&dentry->d_lock);

		if (retval != NULL)
			goto out;

		dentry = parent;
	}

	spin_lock(&dentry->d_lock);
	read_lock(&gr_inode_lock);
	retval = lookup_acl_subj_label(__get_ino(dentry),
				  __get_dev(dentry), role);
	read_unlock(&gr_inode_lock);
	spin_unlock(&dentry->d_lock);

	if (unlikely(retval == NULL)) {
		/* gr_real_root is pinned, we don't need to hold a reference */
		read_lock(&gr_inode_lock);
		retval = lookup_acl_subj_label(__get_ino(gr_real_root.dentry),
					  __get_dev(gr_real_root.dentry), role);
		read_unlock(&gr_inode_lock);
	}
out:
	write_sequnlock(&rename_lock);
	read_sequnlock_excl(&mount_lock);

	BUG_ON(retval == NULL);

	return retval;
}

void
assign_special_role(const char *rolename)
{
	struct acl_object_label *obj;
	struct acl_role_label *r;
	struct acl_role_label *assigned = NULL;
	struct task_struct *tsk;
	struct file *filp;

	FOR_EACH_ROLE_START(r)
		if (!strcmp(rolename, r->rolename) &&
		    (r->roletype & GR_ROLE_SPECIAL)) {
			assigned = r;
			break;
		}
	FOR_EACH_ROLE_END(r)

	if (!assigned)
		return;

	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);

	tsk = current->real_parent;
	if (tsk == NULL)
		goto out_unlock;

	filp = tsk->exec_file;
	if (filp == NULL)
		goto out_unlock;

	tsk->is_writable = 0;
	tsk->inherited = 0;

	tsk->acl_sp_role = 1;
	tsk->acl_role_id = ++acl_sp_role_value;
	tsk->role = assigned;
	tsk->acl = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt, tsk->role);

	/* ignore additional mmap checks for processes that are writable
	   by the default ACL */
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, running_polstate.default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		tsk->is_writable = 1;
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, tsk->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		tsk->is_writable = 1;

#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
	printk(KERN_ALERT "Assigning special role:%s subject:%s to process (%s:%d)\n", tsk->role->rolename,
			tsk->acl->filename, tsk->comm, task_pid_nr(tsk));
#endif

out_unlock:
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
	return;
}


static void
gr_log_learn(const struct dentry *dentry, const struct vfsmount *mnt, const __u32 mode)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename, task->role->roletype,
		       GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid), task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       1UL, 1UL, gr_to_filename(dentry, mnt), (unsigned long) mode, &task->signal->saved_ip);

	return;
}

static void
gr_log_learn_uid_change(const kuid_t real, const kuid_t effective, const kuid_t fs)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_ID_LEARN_MSG, task->role->rolename, task->role->roletype,
		       GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid), task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       'u', GR_GLOBAL_UID(real), GR_GLOBAL_UID(effective), GR_GLOBAL_UID(fs), &task->signal->saved_ip);

	return;
}

static void
gr_log_learn_gid_change(const kgid_t real, const kgid_t effective, const kgid_t fs)
{
	struct task_struct *task = current;
	const struct cred *cred = current_cred();

	security_learn(GR_ID_LEARN_MSG, task->role->rolename, task->role->roletype,
		       GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid), task->exec_file ? gr_to_filename1(task->exec_file->f_path.dentry,
		       task->exec_file->f_path.mnt) : task->acl->filename, task->acl->filename,
		       'g', GR_GLOBAL_GID(real), GR_GLOBAL_GID(effective), GR_GLOBAL_GID(fs), &task->signal->saved_ip);

	return;
}

static void
gr_set_proc_res(struct task_struct *task)
{
	struct acl_subject_label *proc;
	unsigned short i;

	proc = task->acl;

	if (proc->mode & (GR_LEARN | GR_INHERITLEARN))
		return;

	for (i = 0; i < RLIM_NLIMITS; i++) {
		unsigned long rlim_cur, rlim_max;

		if (!(proc->resmask & (1U << i)))
			continue;

		rlim_cur = proc->res[i].rlim_cur;
		rlim_max = proc->res[i].rlim_max;

		if (i == RLIMIT_NOFILE) {
			unsigned long saved_sysctl_nr_open = sysctl_nr_open;
			if (rlim_cur > saved_sysctl_nr_open)
				rlim_cur = saved_sysctl_nr_open;
			if (rlim_max > saved_sysctl_nr_open)
				rlim_max = saved_sysctl_nr_open;
		}

		task->signal->rlim[i].rlim_cur = rlim_cur;
		task->signal->rlim[i].rlim_max = rlim_max;

		if (i == RLIMIT_CPU)
			update_rlimit_cpu(task, rlim_cur);
	}

	return;
}

/* both of the below must be called with
	rcu_read_lock();
	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
   except in the case of gr_set_role_label() (for __gr_get_subject_for_task)
*/

struct acl_subject_label *__gr_get_subject_for_task(const struct gr_policy_state *state, struct task_struct *task, const char *filename, int fallback)
{
	char *tmpname;
	struct acl_subject_label *tmpsubj;
	struct file *filp;
	struct name_entry *nmatch;

	filp = task->exec_file;
	if (filp == NULL)
		return NULL;

	/* the following is to apply the correct subject
	   on binaries running when the RBAC system
	   is enabled, when the binaries have been
	   replaced or deleted since their execution
	   -----
	   when the RBAC system starts, the inode/dev
	   from exec_file will be one the RBAC system
	   is unaware of.  It only knows the inode/dev
	   of the present file on disk, or the absence
	   of it.
	*/

	if (filename)
		nmatch = __lookup_name_entry(state, filename);
	else {
		preempt_disable();
		tmpname = gr_to_filename_rbac(filp->f_path.dentry, filp->f_path.mnt);

		nmatch = __lookup_name_entry(state, tmpname);
		preempt_enable();
	}
	tmpsubj = NULL;
	if (nmatch) {
		if (nmatch->deleted)
			tmpsubj = lookup_acl_subj_label_deleted(nmatch->inode, nmatch->device, task->role);
		else
			tmpsubj = lookup_acl_subj_label(nmatch->inode, nmatch->device, task->role);
	}
	/* this also works for the reload case -- if we don't match a potentially inherited subject
	   then we fall back to a normal lookup based on the binary's ino/dev
	*/
	if (tmpsubj == NULL && fallback)
		tmpsubj = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt, task->role);

	return tmpsubj;
}

static struct acl_subject_label *gr_get_subject_for_task(struct task_struct *task, const char *filename, int fallback)
{
	return __gr_get_subject_for_task(&running_polstate, task, filename, fallback);
}

void __gr_apply_subject_to_task(const struct gr_policy_state *state, struct task_struct *task, struct acl_subject_label *subj)
{
	struct acl_object_label *obj;
	struct file *filp;

	filp = task->exec_file;

	task->acl = subj;
	task->is_writable = 0;
	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, state->default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, task->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;

	gr_set_proc_res(task);

#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
	printk(KERN_ALERT "gr_set_acls for (%s:%d): role:%s, subject:%s\n", task->comm, task_pid_nr(task), task->role->rolename, task->acl->filename);
#endif
}

static void gr_apply_subject_to_task(struct task_struct *task, struct acl_subject_label *subj)
{
	__gr_apply_subject_to_task(&running_polstate, task, subj);
}

__u32
gr_search_file(const struct dentry * dentry, const __u32 mode,
	       const struct vfsmount * mnt)
{
	__u32 retval = mode;
	struct acl_subject_label *curracl;
	struct acl_object_label *currobj;

	if (unlikely(!(gr_status & GR_READY)))
		return (mode & ~GR_AUDITS);

	curracl = current->acl;

	currobj = chk_obj_label(dentry, mnt, curracl);
	retval = currobj->mode & mode;

	/* if we're opening a specified transfer file for writing
	   (e.g. /dev/initctl), then transfer our role to init
	*/
	if (unlikely(currobj->mode & GR_INIT_TRANSFER && retval & GR_WRITE &&
		     current->role->roletype & GR_ROLE_PERSIST)) {
		struct task_struct *task = init_pid_ns.child_reaper;

		if (task->role != current->role) {
			struct acl_subject_label *subj;

			task->acl_sp_role = 0;
			task->acl_role_id = current->acl_role_id;
			task->role = current->role;
			rcu_read_lock();
			read_lock(&grsec_exec_file_lock);
			subj = gr_get_subject_for_task(task, NULL, 1);
			gr_apply_subject_to_task(task, subj);
			read_unlock(&grsec_exec_file_lock);
			rcu_read_unlock();
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_INIT_TRANSFER_MSG);
		}
	}

	if (unlikely
	    ((curracl->mode & (GR_LEARN | GR_INHERITLEARN)) && !(mode & GR_NOPTRACE)
	     && (retval != (mode & ~(GR_AUDITS | GR_SUPPRESS))))) {
		__u32 new_mode = mode;

		new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

		retval = new_mode;

		if (new_mode & GR_EXEC && curracl->mode & GR_INHERITLEARN)
			new_mode |= GR_INHERIT;

		if (!(mode & GR_NOLEARN))
			gr_log_learn(dentry, mnt, new_mode);
	}

	return retval;
}

struct acl_object_label *gr_get_create_object(const struct dentry *new_dentry,
					      const struct dentry *parent,
					      const struct vfsmount *mnt)
{
	struct name_entry *match;
	struct acl_object_label *matchpo;
	struct acl_subject_label *curracl;
	char *path;

	if (unlikely(!(gr_status & GR_READY)))
		return NULL;

	preempt_disable();
	path = gr_to_filename_rbac(new_dentry, mnt);
	match = lookup_name_entry_create(path);

	curracl = current->acl;

	if (match) {
		read_lock(&gr_inode_lock);
		matchpo = lookup_acl_obj_label_create(match->inode, match->device, curracl);
		read_unlock(&gr_inode_lock);

		if (matchpo) {
			preempt_enable();
			return matchpo;
		}
	}

	// lookup parent

	matchpo = chk_obj_create_label(parent, mnt, curracl, path);

	preempt_enable();
	return matchpo;
}

__u32
gr_check_create(const struct dentry * new_dentry, const struct dentry * parent,
		const struct vfsmount * mnt, const __u32 mode)
{
	struct acl_object_label *matchpo;
	__u32 retval;

	if (unlikely(!(gr_status & GR_READY)))
		return (mode & ~GR_AUDITS);

	matchpo = gr_get_create_object(new_dentry, parent, mnt);

	retval = matchpo->mode & mode;

	if ((retval != (mode & ~(GR_AUDITS | GR_SUPPRESS)))
	    && (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))) {
		__u32 new_mode = mode;

		new_mode &= ~(GR_AUDITS | GR_SUPPRESS);

		gr_log_learn(new_dentry, mnt, new_mode);
		return new_mode;
	}

	return retval;
}

__u32
gr_check_link(const struct dentry * new_dentry,
	      const struct dentry * parent_dentry,
	      const struct vfsmount * parent_mnt,
	      const struct dentry * old_dentry, const struct vfsmount * old_mnt)
{
	struct acl_object_label *obj;
	__u32 oldmode, newmode;
	__u32 needmode;
	__u32 checkmodes = GR_FIND | GR_APPEND | GR_WRITE | GR_EXEC | GR_SETID | GR_READ |
			   GR_DELETE | GR_INHERIT;

	if (unlikely(!(gr_status & GR_READY)))
		return (GR_CREATE | GR_LINK);

	obj = chk_obj_label(old_dentry, old_mnt, current->acl);
	oldmode = obj->mode;

	obj = gr_get_create_object(new_dentry, parent_dentry, parent_mnt);
	newmode = obj->mode;

	needmode = newmode & checkmodes;

	// old name for hardlink must have at least the permissions of the new name
	if ((oldmode & needmode) != needmode)
		goto bad;

	// if old name had restrictions/auditing, make sure the new name does as well
	needmode = oldmode & (GR_NOPTRACE | GR_PTRACERD | GR_INHERIT | GR_AUDITS);

	// don't allow hardlinking of suid/sgid/fcapped files without permission
	if (is_privileged_binary(old_dentry))
		needmode |= GR_SETID;

	if ((newmode & needmode) != needmode)
		goto bad;

	// enforce minimum permissions
	if ((newmode & (GR_CREATE | GR_LINK)) == (GR_CREATE | GR_LINK))
		return newmode;
bad:
	needmode = oldmode;
	if (is_privileged_binary(old_dentry))
		needmode |= GR_SETID;
	
	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN)) {
		gr_log_learn(old_dentry, old_mnt, needmode | GR_CREATE | GR_LINK);
		return (GR_CREATE | GR_LINK);
	} else if (newmode & GR_SUPPRESS)
		return GR_SUPPRESS;
	else
		return 0;
}

int
gr_check_hidden_task(const struct task_struct *task)
{
	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (!(task->acl->mode & GR_PROCFIND) && !(current->acl->mode & GR_VIEW))
		return 1;

	return 0;
}

int
gr_check_protected_task(const struct task_struct *task)
{
	if (unlikely(!(gr_status & GR_READY) || !task))
		return 0;

	if ((task->acl->mode & GR_PROTECTED) && !(current->acl->mode & GR_KILL) &&
	    task->acl != current->acl)
		return 1;

	return 0;
}

int
gr_check_protected_task_fowner(struct pid *pid, enum pid_type type)
{
	struct task_struct *p;
	int ret = 0;

	if (unlikely(!(gr_status & GR_READY) || !pid))
		return ret;

	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, p) {
		if ((p->acl->mode & GR_PROTECTED) && !(current->acl->mode & GR_KILL) &&
		    p->acl != current->acl) {
			ret = 1;
			goto out;
		}
	} while_each_pid_task(pid, type, p);
out:
	read_unlock(&tasklist_lock);

	return ret;
}

void
gr_copy_label(struct task_struct *tsk)
{
	struct task_struct *p = current;

	tsk->inherited = p->inherited;
	tsk->acl_sp_role = 0;
	tsk->acl_role_id = p->acl_role_id;
	tsk->acl = p->acl;
	tsk->role = p->role;
	tsk->signal->used_accept = 0;
	tsk->signal->curr_ip = p->signal->curr_ip;
	tsk->signal->saved_ip = p->signal->saved_ip;
	if (p->exec_file)
		get_file(p->exec_file);
	tsk->exec_file = p->exec_file;
	tsk->is_writable = p->is_writable;
	if (unlikely(p->signal->used_accept)) {
		p->signal->curr_ip = 0;
		p->signal->saved_ip = 0;
	}

	return;
}

extern int gr_process_kernel_setuid_ban(struct user_struct *user);

int
gr_check_user_change(kuid_t real, kuid_t effective, kuid_t fs)
{
	unsigned int i;
	__u16 num;
	uid_t *uidlist;
	uid_t curuid;
	int realok = 0;
	int effectiveok = 0;
	int fsok = 0;
	uid_t globalreal, globaleffective, globalfs;

#if defined(CONFIG_GRKERNSEC_KERN_LOCKOUT)
	struct user_struct *user;

	if (!uid_valid(real))
		goto skipit;

	/* find user based on global namespace */

	globalreal = GR_GLOBAL_UID(real);

	user = find_user(make_kuid(&init_user_ns, globalreal));
	if (user == NULL)
		goto skipit;

	if (gr_process_kernel_setuid_ban(user)) {
		/* for find_user */
		free_uid(user);
		return 1;
	}

	/* for find_user */
	free_uid(user);

skipit:
#endif

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		gr_log_learn_uid_change(real, effective, fs);

	num = current->acl->user_trans_num;
	uidlist = current->acl->user_transitions;

	if (uidlist == NULL)
		return 0;

	if (!uid_valid(real)) {
		realok = 1;
		globalreal = (uid_t)-1;		
	} else {
		globalreal = GR_GLOBAL_UID(real);		
	}
	if (!uid_valid(effective)) {
		effectiveok = 1;
		globaleffective = (uid_t)-1;
	} else {
		globaleffective = GR_GLOBAL_UID(effective);
	}
	if (!uid_valid(fs)) {
		fsok = 1;
		globalfs = (uid_t)-1;
	} else {
		globalfs = GR_GLOBAL_UID(fs);
	}

	if (current->acl->user_trans_type & GR_ID_ALLOW) {
		for (i = 0; i < num; i++) {
			curuid = uidlist[i];
			if (globalreal == curuid)
				realok = 1;
			if (globaleffective == curuid)
				effectiveok = 1;
			if (globalfs == curuid)
				fsok = 1;
		}
	} else if (current->acl->user_trans_type & GR_ID_DENY) {
		for (i = 0; i < num; i++) {
			curuid = uidlist[i];
			if (globalreal == curuid)
				break;
			if (globaleffective == curuid)
				break;
			if (globalfs == curuid)
				break;
		}
		/* not in deny list */
		if (i == num) {
			realok = 1;
			effectiveok = 1;
			fsok = 1;
		}
	}

	if (realok && effectiveok && fsok)
		return 0;
	else {
		gr_log_int(GR_DONT_AUDIT, GR_USRCHANGE_ACL_MSG, realok ? (effectiveok ? (fsok ? 0 : globalfs) : globaleffective) : globalreal);
		return 1;
	}
}

int
gr_check_group_change(kgid_t real, kgid_t effective, kgid_t fs)
{
	unsigned int i;
	__u16 num;
	gid_t *gidlist;
	gid_t curgid;
	int realok = 0;
	int effectiveok = 0;
	int fsok = 0;
	gid_t globalreal, globaleffective, globalfs;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		gr_log_learn_gid_change(real, effective, fs);

	num = current->acl->group_trans_num;
	gidlist = current->acl->group_transitions;

	if (gidlist == NULL)
		return 0;

	if (!gid_valid(real)) {
		realok = 1;
		globalreal = (gid_t)-1;		
	} else {
		globalreal = GR_GLOBAL_GID(real);
	}
	if (!gid_valid(effective)) {
		effectiveok = 1;
		globaleffective = (gid_t)-1;		
	} else {
		globaleffective = GR_GLOBAL_GID(effective);
	}
	if (!gid_valid(fs)) {
		fsok = 1;
		globalfs = (gid_t)-1;		
	} else {
		globalfs = GR_GLOBAL_GID(fs);
	}

	if (current->acl->group_trans_type & GR_ID_ALLOW) {
		for (i = 0; i < num; i++) {
			curgid = gidlist[i];
			if (globalreal == curgid)
				realok = 1;
			if (globaleffective == curgid)
				effectiveok = 1;
			if (globalfs == curgid)
				fsok = 1;
		}
	} else if (current->acl->group_trans_type & GR_ID_DENY) {
		for (i = 0; i < num; i++) {
			curgid = gidlist[i];
			if (globalreal == curgid)
				break;
			if (globaleffective == curgid)
				break;
			if (globalfs == curgid)
				break;
		}
		/* not in deny list */
		if (i == num) {
			realok = 1;
			effectiveok = 1;
			fsok = 1;
		}
	}

	if (realok && effectiveok && fsok)
		return 0;
	else {
		gr_log_int(GR_DONT_AUDIT, GR_GRPCHANGE_ACL_MSG, realok ? (effectiveok ? (fsok ? 0 : globalfs) : globaleffective) : globalreal);
		return 1;
	}
}

extern int gr_acl_is_capable(const int cap);

void
gr_set_role_label(struct task_struct *task, const kuid_t kuid, const kgid_t kgid)
{
	struct acl_role_label *role = task->role;
	struct acl_role_label *origrole = role;
	struct acl_subject_label *subj = NULL;
	struct acl_object_label *obj;
	struct file *filp;
	uid_t uid;
	gid_t gid;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	uid = GR_GLOBAL_UID(kuid);
	gid = GR_GLOBAL_GID(kgid);

	filp = task->exec_file;

	/* kernel process, we'll give them the kernel role */
	if (unlikely(!filp)) {
		task->role = running_polstate.kernel_role;
		task->acl = running_polstate.kernel_role->root_label;
		return;
	} else if (!task->role || !(task->role->roletype & GR_ROLE_SPECIAL)) {
		/* save the current ip at time of role lookup so that the proper
		   IP will be learned for role_allowed_ip */
		task->signal->saved_ip = task->signal->curr_ip;
		role = lookup_acl_role_label(task, uid, gid);
	}

	/* don't change the role if we're not a privileged process */
	if (role && task->role != role &&
	    (((role->roletype & GR_ROLE_USER) && !gr_acl_is_capable(CAP_SETUID)) ||
	     ((role->roletype & GR_ROLE_GROUP) && !gr_acl_is_capable(CAP_SETGID))))
		return;

	task->role = role;

	if (task->inherited) {
		/* if we reached our subject through inheritance, then first see
		   if there's a subject of the same name in the new role that has
		   an object that would result in the same inherited subject
		*/
		subj = gr_get_subject_for_task(task, task->acl->filename, 0);
		if (subj) {
			obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, subj);
			if (!(obj->mode & GR_INHERIT))
				subj = NULL;
		}
		
	}
	if (subj == NULL) {
		/* otherwise:
		   perform subject lookup in possibly new role
		   we can use this result below in the case where role == task->role
		*/
		subj = chk_subj_label(filp->f_path.dentry, filp->f_path.mnt, role);
	}

	/* if we changed uid/gid, but result in the same role
	   and are using inheritance, don't lose the inherited subject
	   if current subject is other than what normal lookup
	   would result in, we arrived via inheritance, don't
	   lose subject
	*/
	if (role != origrole || (!(task->acl->mode & GR_INHERITLEARN) &&
				   (subj == task->acl)))
		task->acl = subj;

	/* leave task->inherited unaffected */

	task->is_writable = 0;

	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, running_polstate.default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;
	obj = chk_obj_label(filp->f_path.dentry, filp->f_path.mnt, task->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;

#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
	printk(KERN_ALERT "Set role label for (%s:%d): role:%s, subject:%s\n", task->comm, task_pid_nr(task), task->role->rolename, task->acl->filename);
#endif

	gr_set_proc_res(task);

	return;
}

int
gr_set_proc_label(const struct dentry *dentry, const struct vfsmount *mnt,
		  const int unsafe_flags)
{
	struct task_struct *task = current;
	struct acl_subject_label *newacl;
	struct acl_object_label *obj;
	__u32 retmode;

	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	newacl = chk_subj_label(dentry, mnt, task->role);

	/* special handling for if we did an strace -f -p <pid> from an admin role, where pid then
	   did an exec
	*/
	rcu_read_lock();
	read_lock(&tasklist_lock);
	if (task->ptrace && task->parent && ((task->parent->role->roletype & GR_ROLE_GOD) ||
	    (task->parent->acl->mode & GR_POVERRIDE))) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		goto skip_check;
	}
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	if (unsafe_flags && !(task->acl->mode & GR_POVERRIDE) && (task->acl != newacl) &&
	     !(task->role->roletype & GR_ROLE_GOD) &&
	     !gr_search_file(dentry, GR_PTRACERD, mnt) &&
	     !(task->acl->mode & (GR_LEARN | GR_INHERITLEARN))) {
		if (unsafe_flags & LSM_UNSAFE_SHARE)
			gr_log_fs_generic(GR_DONT_AUDIT, GR_UNSAFESHARE_EXEC_ACL_MSG, dentry, mnt);
		else if (unsafe_flags & (LSM_UNSAFE_PTRACE_CAP | LSM_UNSAFE_PTRACE))
			gr_log_fs_generic(GR_DONT_AUDIT, GR_PTRACE_EXEC_ACL_MSG, dentry, mnt);
		else
			gr_log_fs_generic(GR_DONT_AUDIT, GR_NNP_EXEC_ACL_MSG, dentry, mnt);
		return -EACCES;
	}

skip_check:

	obj = chk_obj_label(dentry, mnt, task->acl);
	retmode = obj->mode & (GR_INHERIT | GR_AUDIT_INHERIT);

	if (!(task->acl->mode & GR_INHERITLEARN) &&
	    ((newacl->mode & GR_LEARN) || !(retmode & GR_INHERIT))) {
		if (obj->nested)
			task->acl = obj->nested;
		else
			task->acl = newacl;
		task->inherited = 0;
	} else {
		task->inherited = 1;
		if (retmode & GR_INHERIT && retmode & GR_AUDIT_INHERIT)
			gr_log_str_fs(GR_DO_AUDIT, GR_INHERIT_ACL_MSG, task->acl->filename, dentry, mnt);
	}

	task->is_writable = 0;

	/* ignore additional mmap checks for processes that are writable 
	   by the default ACL */
	obj = chk_obj_label(dentry, mnt, running_polstate.default_role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;
	obj = chk_obj_label(dentry, mnt, task->role->root_label);
	if (unlikely(obj->mode & GR_WRITE))
		task->is_writable = 1;

	gr_set_proc_res(task);

#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
	printk(KERN_ALERT "Set subject label for (%s:%d): role:%s, subject:%s\n", task->comm, task_pid_nr(task), task->role->rolename, task->acl->filename);
#endif
	return 0;
}

/* always called with valid inodev ptr */
static void
do_handle_delete(struct inodev_entry *inodev, const u64 ino, const dev_t dev)
{
	struct acl_object_label *matchpo;
	struct acl_subject_label *matchps;
	struct acl_subject_label *subj;
	struct acl_role_label *role;
	unsigned int x;

	FOR_EACH_ROLE_START(role)
		FOR_EACH_SUBJECT_START(role, subj, x)
			if ((matchpo = lookup_acl_obj_label(ino, dev, subj)) != NULL)
				matchpo->mode |= GR_DELETED;
		FOR_EACH_SUBJECT_END(subj,x)
		FOR_EACH_NESTED_SUBJECT_START(role, subj)
			/* nested subjects aren't in the role's subj_hash table */
			if ((matchpo = lookup_acl_obj_label(ino, dev, subj)) != NULL)
				matchpo->mode |= GR_DELETED;
		FOR_EACH_NESTED_SUBJECT_END(subj)
		if ((matchps = lookup_acl_subj_label(ino, dev, role)) != NULL)
			matchps->mode |= GR_DELETED;
	FOR_EACH_ROLE_END(role)

	inodev->nentry->deleted = 1;

	return;
}

void
gr_handle_delete(const u64 ino, const dev_t dev)
{
	struct inodev_entry *inodev;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	write_lock(&gr_inode_lock);
	inodev = lookup_inodev_entry(ino, dev);
	if (inodev != NULL)
		do_handle_delete(inodev, ino, dev);
	write_unlock(&gr_inode_lock);

	return;
}

static void
update_acl_obj_label(const u64 oldinode, const dev_t olddevice,
		     const u64 newinode, const dev_t newdevice,
		     struct acl_subject_label *subj)
{
	unsigned int index = gr_fhash(oldinode, olddevice, subj->obj_hash_size);
	struct acl_object_label *match;

	match = subj->obj_hash[index];

	while (match && (match->inode != oldinode ||
	       match->device != olddevice ||
	       !(match->mode & GR_DELETED)))
		match = match->next;

	if (match && (match->inode == oldinode)
	    && (match->device == olddevice)
	    && (match->mode & GR_DELETED)) {
		if (match->prev == NULL) {
			subj->obj_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->inode = newinode;
		match->device = newdevice;
		match->mode &= ~GR_DELETED;

		insert_acl_obj_label(match, subj);
	}

	return;
}

static void
update_acl_subj_label(const u64 oldinode, const dev_t olddevice,
		      const u64 newinode, const dev_t newdevice,
		      struct acl_role_label *role)
{
	unsigned int index = gr_fhash(oldinode, olddevice, role->subj_hash_size);
	struct acl_subject_label *match;

	match = role->subj_hash[index];

	while (match && (match->inode != oldinode ||
	       match->device != olddevice ||
	       !(match->mode & GR_DELETED)))
		match = match->next;

	if (match && (match->inode == oldinode)
	    && (match->device == olddevice)
	    && (match->mode & GR_DELETED)) {
		if (match->prev == NULL) {
			role->subj_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->inode = newinode;
		match->device = newdevice;
		match->mode &= ~GR_DELETED;

		insert_acl_subj_label(match, role);
	}

	return;
}

static void
update_inodev_entry(const u64 oldinode, const dev_t olddevice,
		    const u64 newinode, const dev_t newdevice)
{
	unsigned int index = gr_fhash(oldinode, olddevice, running_polstate.inodev_set.i_size);
	struct inodev_entry *match;

	match = running_polstate.inodev_set.i_hash[index];

	while (match && (match->nentry->inode != oldinode ||
	       match->nentry->device != olddevice || !match->nentry->deleted))
		match = match->next;

	if (match && (match->nentry->inode == oldinode)
	    && (match->nentry->device == olddevice) &&
	    match->nentry->deleted) {
		if (match->prev == NULL) {
			running_polstate.inodev_set.i_hash[index] = match->next;
			if (match->next != NULL)
				match->next->prev = NULL;
		} else {
			match->prev->next = match->next;
			if (match->next != NULL)
				match->next->prev = match->prev;
		}
		match->prev = NULL;
		match->next = NULL;
		match->nentry->inode = newinode;
		match->nentry->device = newdevice;
		match->nentry->deleted = 0;

		insert_inodev_entry(match);
	}

	return;
}

static void
__do_handle_create(const struct name_entry *matchn, u64 ino, dev_t dev)
{
	struct acl_subject_label *subj;
	struct acl_role_label *role;
	unsigned int x;

	FOR_EACH_ROLE_START(role)
		update_acl_subj_label(matchn->inode, matchn->device, ino, dev, role);

		FOR_EACH_NESTED_SUBJECT_START(role, subj)
			if ((subj->inode == ino) && (subj->device == dev)) {
				subj->inode = ino;
				subj->device = dev;
			}
			/* nested subjects aren't in the role's subj_hash table */
			update_acl_obj_label(matchn->inode, matchn->device,
					     ino, dev, subj);
		FOR_EACH_NESTED_SUBJECT_END(subj)
		FOR_EACH_SUBJECT_START(role, subj, x)
			update_acl_obj_label(matchn->inode, matchn->device,
					     ino, dev, subj);
		FOR_EACH_SUBJECT_END(subj,x)
	FOR_EACH_ROLE_END(role)

	update_inodev_entry(matchn->inode, matchn->device, ino, dev);

	return;
}

static void
do_handle_create(const struct name_entry *matchn, const struct dentry *dentry,
		 const struct vfsmount *mnt)
{
	u64 ino = __get_ino(dentry);
	dev_t dev = __get_dev(dentry);

	__do_handle_create(matchn, ino, dev);	

	return;
}

void
gr_handle_create(const struct dentry *dentry, const struct vfsmount *mnt)
{
	struct name_entry *matchn;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	preempt_disable();
	matchn = lookup_name_entry(gr_to_filename_rbac(dentry, mnt));

	if (unlikely((unsigned long)matchn)) {
		write_lock(&gr_inode_lock);
		do_handle_create(matchn, dentry, mnt);
		write_unlock(&gr_inode_lock);
	}
	preempt_enable();

	return;
}

void
gr_handle_proc_create(const struct dentry *dentry, const struct inode *inode)
{
	struct name_entry *matchn;

	if (unlikely(!(gr_status & GR_READY)))
		return;

	preempt_disable();
	matchn = lookup_name_entry(gr_to_proc_filename_rbac(dentry, init_pid_ns.proc_mnt));

	if (unlikely((unsigned long)matchn)) {
		write_lock(&gr_inode_lock);
		__do_handle_create(matchn, inode->i_ino, inode->i_sb->s_dev);
		write_unlock(&gr_inode_lock);
	}
	preempt_enable();

	return;
}

void
gr_handle_rename(struct inode *old_dir, struct inode *new_dir,
		 struct dentry *old_dentry,
		 struct dentry *new_dentry,
		 struct vfsmount *mnt, const __u8 replace, unsigned int flags)
{
	struct name_entry *matchn;
	struct name_entry *matchn2 = NULL;
	struct inodev_entry *inodev;
	struct inode *inode = d_backing_inode(new_dentry);
	struct inode *old_inode = d_backing_inode(old_dentry);
	u64 old_ino = __get_ino(old_dentry);
	dev_t old_dev = __get_dev(old_dentry);
	unsigned int exchange = flags & RENAME_EXCHANGE;

	/* vfs_rename swaps the name and parent link for old_dentry and
	   new_dentry
	   at this point, old_dentry has the new name, parent link, and inode
	   for the renamed file
	   if a file is being replaced by a rename, new_dentry has the inode
	   and name for the replaced file
	*/

	if (unlikely(!(gr_status & GR_READY)))
		return;

	preempt_disable();
	matchn = lookup_name_entry(gr_to_filename_rbac(old_dentry, mnt));

	/* exchange cases:
	   a filename exists for the source, but not dest
		do a recreate on source
	   a filename exists for the dest, but not source
		do a recreate on dest
	   a filename exists for both source and dest
		delete source and dest, then create source and dest
	   a filename exists for neither source nor dest
		no updates needed

	   the name entry lookups get us the old inode/dev associated with
	   each name, so do the deletes first (if possible) so that when
	   we do the create, we pick up on the right entries
	*/

	if (exchange)
		matchn2 = lookup_name_entry(gr_to_filename_rbac(new_dentry, mnt));

	/* we wouldn't have to check d_inode if it weren't for
	   NFS silly-renaming
	 */

	write_lock(&gr_inode_lock);
	if (unlikely((replace || exchange) && inode)) {
		u64 new_ino = __get_ino(new_dentry);
		dev_t new_dev = __get_dev(new_dentry);

		inodev = lookup_inodev_entry(new_ino, new_dev);
		if (inodev != NULL && ((inode->i_nlink <= 1) || d_is_dir(new_dentry)))
			do_handle_delete(inodev, new_ino, new_dev);
	}

	inodev = lookup_inodev_entry(old_ino, old_dev);
	if (inodev != NULL && ((old_inode->i_nlink <= 1) || d_is_dir(old_dentry)))
		do_handle_delete(inodev, old_ino, old_dev);

	if (unlikely(matchn != NULL))
		do_handle_create(matchn, old_dentry, mnt);

	if (unlikely(matchn2 != NULL))
		do_handle_create(matchn2, new_dentry, mnt);

	write_unlock(&gr_inode_lock);
	preempt_enable();

	return;
}

#if defined(CONFIG_GRKERNSEC_RESLOG) || !defined(CONFIG_GRKERNSEC_NO_RBAC)
static const unsigned long res_learn_bumps[GR_NLIMITS] = {
	[RLIMIT_CPU] = GR_RLIM_CPU_BUMP,
	[RLIMIT_FSIZE] = GR_RLIM_FSIZE_BUMP,
	[RLIMIT_DATA] = GR_RLIM_DATA_BUMP,
	[RLIMIT_STACK] = GR_RLIM_STACK_BUMP,
	[RLIMIT_CORE] = GR_RLIM_CORE_BUMP,
	[RLIMIT_RSS] = GR_RLIM_RSS_BUMP,
	[RLIMIT_NPROC] = GR_RLIM_NPROC_BUMP,
	[RLIMIT_NOFILE] = GR_RLIM_NOFILE_BUMP,
	[RLIMIT_MEMLOCK] = GR_RLIM_MEMLOCK_BUMP,
	[RLIMIT_AS] = GR_RLIM_AS_BUMP,
	[RLIMIT_LOCKS] = GR_RLIM_LOCKS_BUMP,
	[RLIMIT_SIGPENDING] = GR_RLIM_SIGPENDING_BUMP,
	[RLIMIT_MSGQUEUE] = GR_RLIM_MSGQUEUE_BUMP,
	[RLIMIT_NICE] = GR_RLIM_NICE_BUMP,
	[RLIMIT_RTPRIO] = GR_RLIM_RTPRIO_BUMP,
	[RLIMIT_RTTIME] = GR_RLIM_RTTIME_BUMP
};

void
gr_learn_resource(const struct task_struct *task,
		  const int res, const unsigned long wanted, const int gt)
{
	struct acl_subject_label *acl;
	const struct cred *cred;

	if (unlikely((gr_status & GR_READY) &&
		     task->acl && (task->acl->mode & (GR_LEARN | GR_INHERITLEARN))))
		goto skip_reslog;

	gr_log_resource(task, res, wanted, gt);
skip_reslog:

	if (unlikely(!(gr_status & GR_READY) || !wanted || res >= GR_NLIMITS))
		return;

	acl = task->acl;

	if (likely(!acl || !(acl->mode & (GR_LEARN | GR_INHERITLEARN)) ||
		   !(acl->resmask & (1U << (unsigned short) res))))
		return;

	if (wanted >= acl->res[res].rlim_cur) {
		unsigned long res_add;

		res_add = wanted + res_learn_bumps[res];

		acl->res[res].rlim_cur = res_add;

		if (wanted > acl->res[res].rlim_max)
			acl->res[res].rlim_max = res_add;

		/* only log the subject filename, since resource logging is supported for
		   single-subject learning only */
		rcu_read_lock();
		cred = __task_cred(task);
		security_learn(GR_LEARN_AUDIT_MSG, task->role->rolename,
			       task->role->roletype, GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid), acl->filename,
			       acl->filename, acl->res[res].rlim_cur, acl->res[res].rlim_max,
			       "", (unsigned long) res, &task->signal->saved_ip);
		rcu_read_unlock();
	}

	return;
}
EXPORT_SYMBOL_GPL(gr_learn_resource);
#endif

#if defined(CONFIG_PAX_HAVE_ACL_FLAGS) && (defined(CONFIG_PAX_NOEXEC) || defined(CONFIG_PAX_ASLR))
void
pax_set_initial_flags(struct linux_binprm *bprm)
{
	struct task_struct *task = current;
        struct acl_subject_label *proc;
	unsigned long flags;

        if (unlikely(!(gr_status & GR_READY)))
                return;

	flags = pax_get_flags(task);

        proc = task->acl;

	if (proc->pax_flags & GR_PAX_DISABLE_PAGEEXEC)
		flags &= ~MF_PAX_PAGEEXEC;
	if (proc->pax_flags & GR_PAX_DISABLE_SEGMEXEC)
		flags &= ~MF_PAX_SEGMEXEC;
	if (proc->pax_flags & GR_PAX_DISABLE_RANDMMAP)
		flags &= ~MF_PAX_RANDMMAP;
	if (proc->pax_flags & GR_PAX_DISABLE_EMUTRAMP)
		flags &= ~MF_PAX_EMUTRAMP;
	if (proc->pax_flags & GR_PAX_DISABLE_MPROTECT)
		flags &= ~MF_PAX_MPROTECT;

	if (proc->pax_flags & GR_PAX_ENABLE_PAGEEXEC)
		flags |= MF_PAX_PAGEEXEC;
	if (proc->pax_flags & GR_PAX_ENABLE_SEGMEXEC)
		flags |= MF_PAX_SEGMEXEC;
	if (proc->pax_flags & GR_PAX_ENABLE_RANDMMAP)
		flags |= MF_PAX_RANDMMAP;
	if (proc->pax_flags & GR_PAX_ENABLE_EMUTRAMP)
		flags |= MF_PAX_EMUTRAMP;
	if (proc->pax_flags & GR_PAX_ENABLE_MPROTECT)
		flags |= MF_PAX_MPROTECT;

	pax_set_flags(task, flags);

        return;
}
#endif

int
gr_handle_proc_ptrace(struct task_struct *task)
{
	struct file *filp;
	struct task_struct *tmp = task;
	struct task_struct *curtemp = current;
	__u32 retmode;

#ifndef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
#endif

	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	filp = task->exec_file;

	while (task_pid_nr(tmp) > 0) {
		if (tmp == curtemp)
			break;
		tmp = tmp->real_parent;
	}

	if (!filp || (task_pid_nr(tmp) == 0 && ((grsec_enable_harden_ptrace && gr_is_global_nonroot(current_uid()) && !(gr_status & GR_READY)) ||
				((gr_status & GR_READY)	&& !(current->acl->mode & GR_RELAXPTRACE))))) {
		read_unlock(&grsec_exec_file_lock);
		read_unlock(&tasklist_lock);
		return 1;
	}

#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (!(gr_status & GR_READY)) {
		read_unlock(&grsec_exec_file_lock);
		read_unlock(&tasklist_lock);
		return 0;
	}
#endif

	retmode = gr_search_file(filp->f_path.dentry, GR_NOPTRACE, filp->f_path.mnt);
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);

	if (retmode & GR_NOPTRACE)
		return 1;

	if (!(current->acl->mode & GR_POVERRIDE) && !(current->role->roletype & GR_ROLE_GOD)
	    && (current->acl != task->acl || (current->acl != current->role->root_label
	    && task_pid_nr(current) != task_pid_nr(task))))
		return 1;

	return 0;
}

void task_grsec_rbac(struct seq_file *m, struct task_struct *p)
{
	if (unlikely(!(gr_status & GR_READY)))
		return;

	if (!(current->role->roletype & GR_ROLE_GOD))
		return;

	seq_printf(m, "RBAC:\t%.64s:%c:%.950s\n",
			p->role->rolename, gr_task_roletype_to_char(p),
			p->acl->filename);
}

int
gr_handle_ptrace(struct task_struct *task, const long request)
{
	struct task_struct *tmp = task;
	struct task_struct *curtemp = current;
	__u32 retmode;

#ifndef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (unlikely(!(gr_status & GR_READY)))
		return 0;
#endif
	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		read_lock(&tasklist_lock);
		while (task_pid_nr(tmp) > 0) {
			if (tmp == curtemp)
				break;
			tmp = tmp->real_parent;
		}

		if (task_pid_nr(tmp) == 0 && ((grsec_enable_harden_ptrace && gr_is_global_nonroot(current_uid()) && !(gr_status & GR_READY)) ||
					((gr_status & GR_READY)	&& !(current->acl->mode & GR_RELAXPTRACE)))) {
			read_unlock(&tasklist_lock);
			gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
			return 1;
		}
		read_unlock(&tasklist_lock);
	}

#ifdef CONFIG_GRKERNSEC_HARDEN_PTRACE
	if (!(gr_status & GR_READY))
		return 0;
#endif

	read_lock(&grsec_exec_file_lock);
	if (unlikely(!task->exec_file)) {
		read_unlock(&grsec_exec_file_lock);
		return 0;
	}

	retmode = gr_search_file(task->exec_file->f_path.dentry, GR_PTRACERD | GR_NOPTRACE, task->exec_file->f_path.mnt);
	read_unlock(&grsec_exec_file_lock);

	if (retmode & GR_NOPTRACE) {
		gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
		return 1;
	}
		
	if (retmode & GR_PTRACERD) {
		switch (request) {
		case PTRACE_SEIZE:
		case PTRACE_POKETEXT:
		case PTRACE_POKEDATA:
		case PTRACE_POKEUSR:
#if !defined(CONFIG_PPC32) && !defined(CONFIG_PPC64) && !defined(CONFIG_PARISC) && !defined(CONFIG_ALPHA) && !defined(CONFIG_IA64) && !defined(CONFIG_ARM64)
		case PTRACE_SETREGS:
		case PTRACE_SETFPREGS:
#endif
#ifdef CONFIG_COMPAT
#ifdef CONFIG_ARM64
		case COMPAT_PTRACE_SETREGS:
		case COMPAT_PTRACE_SETVFPREGS:
#ifdef CONFIG_HAVE_HW_BREAKPOINT
		case COMPAT_PTRACE_SETHBPREGS:
#endif
#endif
#endif
#ifdef CONFIG_X86
		case PTRACE_SETFPXREGS:
#endif
#ifdef CONFIG_ALTIVEC
		case PTRACE_SETVRREGS:
#endif
#ifdef CONFIG_ARM
		case PTRACE_SET_SYSCALL:
		case PTRACE_SETVFPREGS:
#ifdef CONFIG_HAVE_HW_BREAKPOINT
		case PTRACE_SETHBPREGS:
#endif
#endif
			return 1;
		default:
			return 0;
		}
	} else if (!(current->acl->mode & GR_POVERRIDE) &&
		   !(current->role->roletype & GR_ROLE_GOD) &&
		   (current->acl != task->acl)) {
		gr_log_ptrace(GR_DONT_AUDIT, GR_PTRACE_ACL_MSG, task);
		return 1;
	}

	return 0;
}

static int is_writable_mmap(const struct file *filp)
{
	struct task_struct *task = current;
	struct acl_object_label *obj, *obj2;
	struct dentry *dentry = filp->f_path.dentry;
	struct vfsmount *mnt = filp->f_path.mnt;
	struct inode *inode = d_backing_inode(dentry);

	if (gr_status & GR_READY && !(task->acl->mode & GR_OVERRIDE) &&
	    !task->is_writable && d_is_reg(dentry) && (mnt != shm_mnt || (inode->i_nlink > 0))) {
		obj = chk_obj_label(dentry, mnt, running_polstate.default_role->root_label);
		obj2 = chk_obj_label(dentry, mnt, task->role->root_label);
		if (unlikely((obj->mode & GR_WRITE) || (obj2->mode & GR_WRITE))) {
			gr_log_fs_generic(GR_DONT_AUDIT, GR_WRITLIB_ACL_MSG, dentry, mnt);
			return 1;
		}
	}
	return 0;
}

int
gr_acl_handle_mmap(const struct file *file, const unsigned long prot)
{
	__u32 mode;

	if (unlikely(!file || !(prot & PROT_EXEC)))
		return 1;

	if (is_writable_mmap(file))
		return 0;

	mode =
	    gr_search_file(file->f_path.dentry,
			   GR_EXEC | GR_AUDIT_EXEC | GR_SUPPRESS,
			   file->f_path.mnt);

	if (!gr_tpe_allow(file))
		return 0;

	if (unlikely(!(mode & GR_EXEC) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, GR_MMAP_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	} else if (unlikely(!(mode & GR_EXEC))) {
		return 0;
	} else if (unlikely(mode & GR_EXEC && mode & GR_AUDIT_EXEC)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, GR_MMAP_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 1;
	}

	return 1;
}

int
gr_acl_handle_mprotect(const struct file *file, const unsigned long prot)
{
	__u32 mode;

	if (unlikely(!file || !(prot & PROT_EXEC)))
		return 1;

	if (is_writable_mmap(file))
		return 0;

	mode =
	    gr_search_file(file->f_path.dentry,
			   GR_EXEC | GR_AUDIT_EXEC | GR_SUPPRESS,
			   file->f_path.mnt);

	if (!gr_tpe_allow(file))
		return 0;

	if (unlikely(!(mode & GR_EXEC) && !(mode & GR_SUPPRESS))) {
		gr_log_fs_rbac_generic(GR_DONT_AUDIT, GR_MPROTECT_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 0;
	} else if (unlikely(!(mode & GR_EXEC))) {
		return 0;
	} else if (unlikely(mode & GR_EXEC && mode & GR_AUDIT_EXEC)) {
		gr_log_fs_rbac_generic(GR_DO_AUDIT, GR_MPROTECT_ACL_MSG, file->f_path.dentry, file->f_path.mnt);
		return 1;
	}

	return 1;
}

void
gr_acl_handle_psacct(struct task_struct *task, const long code)
{
	unsigned long runtime, cputime;
	cputime_t utime, stime;
	unsigned int wday, cday;
	__u8 whr, chr;
	__u8 wmin, cmin;
	__u8 wsec, csec;
	struct timespec curtime, starttime;

	if (unlikely(!(gr_status & GR_READY) || !task->acl ||
		     !(task->acl->mode & GR_PROCACCT)))
		return;
	
	curtime = ns_to_timespec(ktime_get_ns());
	starttime = ns_to_timespec(task->start_time);
	runtime = curtime.tv_sec - starttime.tv_sec;
	wday = runtime / (60 * 60 * 24);
	runtime -= wday * (60 * 60 * 24);
	whr = runtime / (60 * 60);
	runtime -= whr * (60 * 60);
	wmin = runtime / 60;
	runtime -= wmin * 60;
	wsec = runtime;

	task_cputime(task, &utime, &stime);
	cputime = cputime_to_secs(utime + stime);
	cday = cputime / (60 * 60 * 24);
	cputime -= cday * (60 * 60 * 24);
	chr = cputime / (60 * 60);
	cputime -= chr * (60 * 60);
	cmin = cputime / 60;
	cputime -= cmin * 60;
	csec = cputime;

	gr_log_procacct(GR_DO_AUDIT, GR_ACL_PROCACCT_MSG, task, wday, whr, wmin, wsec, cday, chr, cmin, csec, code);

	return;
}

#ifdef CONFIG_TASKSTATS
int gr_is_taskstats_denied(int pid)
{
	struct task_struct *task;
#if defined(CONFIG_GRKERNSEC_PROC_USER) || defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
	const struct cred *cred;
#endif
	int ret = 0;

	/* restrict taskstats viewing to un-chrooted root users
	   who have the 'view' subject flag if the RBAC system is enabled
	*/

	rcu_read_lock();
	read_lock(&tasklist_lock);
	task = find_task_by_vpid(pid);
	if (task) {
#ifdef CONFIG_GRKERNSEC_CHROOT
		if (proc_is_chrooted(task))
			ret = -EACCES;
#endif
#if defined(CONFIG_GRKERNSEC_PROC_USER) || defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
		cred = __task_cred(task);
#ifdef CONFIG_GRKERNSEC_PROC_USER
		if (gr_is_global_nonroot(cred->uid))
			ret = -EACCES;
#elif defined(CONFIG_GRKERNSEC_PROC_USERGROUP)
		if (gr_is_global_nonroot(cred->uid) && !groups_search(cred->group_info, grsec_proc_gid))
			ret = -EACCES;
#endif
#endif
		if (gr_status & GR_READY) {
			if (!(task->acl->mode & GR_VIEW))
				ret = -EACCES;
		}
	} else
		ret = -ENOENT;

	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	return ret;
}
#endif

/* AUXV entries are filled via a descendant of search_binary_handler
   after we've already applied the subject for the target
*/
int gr_acl_enable_at_secure(void)
{
	if (unlikely(!(gr_status & GR_READY)))
		return 0;

	if (current->acl->mode & GR_ATSECURE)
		return 1;

	return 0;
}
	
int gr_acl_handle_filldir(const struct file *file, const char *name, const unsigned int namelen, const u64 ino)
{
	struct task_struct *task = current;
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct acl_object_label *obj, *tmp;
	struct acl_subject_label *subj;
	unsigned int bufsize;
	int is_not_root;
	char *path;
	dev_t dev = __get_dev(dentry);

	if (unlikely(!(gr_status & GR_READY)))
		return 1;

	if (task->acl->mode & (GR_LEARN | GR_INHERITLEARN))
		return 1;

	/* ignore Eric Biederman */
	if (IS_PRIVATE(d_backing_inode(dentry)))
		return 1;

	subj = task->acl;
	read_lock(&gr_inode_lock);
	do {
		obj = lookup_acl_obj_label(ino, dev, subj);
		if (obj != NULL) {
			read_unlock(&gr_inode_lock);
			return (obj->mode & GR_FIND) ? 1 : 0;
		}
	} while ((subj = subj->parent_subject));
	read_unlock(&gr_inode_lock);
	
	/* this is purely an optimization since we're looking for an object
	   for the directory we're doing a readdir on
	   if it's possible for any globbed object to match the entry we're
	   filling into the directory, then the object we find here will be
	   an anchor point with attached globbed objects
	*/
	obj = chk_obj_label_noglob(dentry, mnt, task->acl);
	if (obj->globbed == NULL)
		return (obj->mode & GR_FIND) ? 1 : 0;

	is_not_root = ((obj->filename[0] == '/') &&
		   (obj->filename[1] == '\0')) ? 0 : 1;
	bufsize = PAGE_SIZE - namelen - is_not_root;

	/* check bufsize > PAGE_SIZE || bufsize == 0 */
	if (unlikely((bufsize - 1) > (PAGE_SIZE - 1)))
		return 1;

	preempt_disable();
	path = d_real_path(dentry, mnt, per_cpu_ptr(gr_shared_page[0], smp_processor_id()),
			   bufsize);

	bufsize = strlen(path);

	/* if base is "/", don't append an additional slash */
	if (is_not_root)
		*(path + bufsize) = '/';
	memcpy(path + bufsize + is_not_root, name, namelen);
	*(path + bufsize + namelen + is_not_root) = '\0';

	tmp = obj->globbed;
	while (tmp) {
		if (!glob_match(tmp->filename, path)) {
			preempt_enable();
			return (tmp->mode & GR_FIND) ? 1 : 0;
		}
		tmp = tmp->next;
	}
	preempt_enable();
	return (obj->mode & GR_FIND) ? 1 : 0;
}

void gr_put_exec_file(struct task_struct *task)
{
	struct file *filp;  

	write_lock(&grsec_exec_file_lock);
	filp = task->exec_file;   
	task->exec_file = NULL;
	write_unlock(&grsec_exec_file_lock);

	if (filp)
		fput(filp);

	return;
}


#ifdef CONFIG_NETFILTER_XT_MATCH_GRADM_MODULE
EXPORT_SYMBOL_GPL(gr_acl_is_enabled);
#endif
#ifdef CONFIG_SECURITY
EXPORT_SYMBOL_GPL(gr_check_user_change);
EXPORT_SYMBOL_GPL(gr_check_group_change);
#endif

