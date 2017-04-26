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
#include "../fs/mount.h"

#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/mman.h>

extern struct gr_policy_state *polstate;

#define FOR_EACH_ROLE_START(role) \
	role = polstate->role_list; \
	while (role) {

#define FOR_EACH_ROLE_END(role) \
		role = role->prev; \
	}

struct path gr_real_root;

extern struct gr_alloc_state *current_alloc_state;

u16 acl_sp_role_value;

static DEFINE_MUTEX(gr_dev_mutex);

extern int chkpw(struct gr_arg *entry, unsigned char *salt, unsigned char *sum);
extern void gr_clear_learn_entries(void);

struct gr_arg *gr_usermode __read_only;
unsigned char *gr_system_salt __read_only;
unsigned char *gr_system_sum __read_only;

static unsigned int gr_auth_attempts = 0;
static unsigned long gr_auth_expires = 0UL;

struct acl_object_label *fakefs_obj_rw;
struct acl_object_label *fakefs_obj_rwx;

extern int gr_init_uidset(void);
extern void gr_free_uidset(void);
extern int gr_find_and_remove_uid(uid_t uid);

extern struct acl_subject_label *__gr_get_subject_for_task(const struct gr_policy_state *state, struct task_struct *task, const char *filename, int fallback);
extern void __gr_apply_subject_to_task(const struct gr_policy_state *state, struct task_struct *task, struct acl_subject_label *subj);
extern int gr_streq(const char *a, const char *b, const unsigned int lena, const unsigned int lenb);
extern void __insert_inodev_entry(const struct gr_policy_state *state, struct inodev_entry *entry);
extern struct acl_role_label *__lookup_acl_role_label(const struct gr_policy_state *state, const struct task_struct *task, const uid_t uid, const gid_t gid);
extern void insert_acl_obj_label(struct acl_object_label *obj, struct acl_subject_label *subj);
extern void insert_acl_subj_label(struct acl_subject_label *obj, struct acl_role_label *role);
extern struct name_entry * __lookup_name_entry(const struct gr_policy_state *state, const char *name);
extern char *gr_to_filename_rbac(const struct dentry *dentry, const struct vfsmount *mnt);
extern struct acl_subject_label *lookup_acl_subj_label(const u64 ino, const dev_t dev, const struct acl_role_label *role);
extern struct acl_subject_label *lookup_acl_subj_label_deleted(const u64 ino, const dev_t dev, const struct acl_role_label *role);
extern void assign_special_role(const char *rolename);
extern struct acl_subject_label *chk_subj_label(const struct dentry *l_dentry, const struct vfsmount *l_mnt, const struct acl_role_label *role);
extern int gr_rbac_disable(void *unused);
extern void gr_enable_rbac_system(void);

static int copy_acl_object_label_normal(struct acl_object_label *obj, const struct acl_object_label *userp)
{
	if (copy_from_user(obj, userp, sizeof(struct acl_object_label)))
		return -EFAULT;

	return 0;
}

static int copy_acl_ip_label_normal(struct acl_ip_label *ip, const struct acl_ip_label *userp)
{
	if (copy_from_user(ip, userp, sizeof(struct acl_ip_label)))
		return -EFAULT;

	return 0;
}

static int copy_acl_subject_label_normal(struct acl_subject_label *subj, const struct acl_subject_label *userp)
{
	if (copy_from_user(subj, userp, sizeof(struct acl_subject_label)))
		return -EFAULT;

	return 0;
}

static int copy_acl_role_label_normal(struct acl_role_label *role, const struct acl_role_label *userp)
{
	if (copy_from_user(role, userp, sizeof(struct acl_role_label)))
		return -EFAULT;

	return 0;
}

static int copy_role_allowed_ip_normal(struct role_allowed_ip *roleip, const struct role_allowed_ip *userp)
{
	if (copy_from_user(roleip, userp, sizeof(struct role_allowed_ip)))
		return -EFAULT;

	return 0;
}

static int copy_sprole_pw_normal(struct sprole_pw *pw, unsigned long idx, const struct sprole_pw *userp)
{
	if (copy_from_user(pw, userp + idx, sizeof(struct sprole_pw)))
		return -EFAULT;

	return 0;
}

static int copy_gr_hash_struct_normal(struct gr_hash_struct *hash, const struct gr_hash_struct *userp)
{
	if (copy_from_user(hash, userp, sizeof(struct gr_hash_struct)))
		return -EFAULT;

	return 0;
}

static int copy_role_transition_normal(struct role_transition *trans, const struct role_transition *userp)
{
	if (copy_from_user(trans, userp, sizeof(struct role_transition)))
		return -EFAULT;

	return 0;
}

int copy_pointer_from_array_normal(void *ptr, unsigned long idx, const void *userp)
{
	if (copy_from_user(ptr, userp + (idx * sizeof(void *)), sizeof(void *)))
		return -EFAULT;

	return 0;
}

static int copy_gr_arg_wrapper_normal(const char __user *buf, struct gr_arg_wrapper *uwrap)
{
	if (copy_from_user(uwrap, buf, sizeof (struct gr_arg_wrapper)))
		return -EFAULT;

	if ((uwrap->version != GRSECURITY_VERSION) ||
	    (uwrap->size != sizeof(struct gr_arg)))
		return -EINVAL;

	return 0;
}

static int copy_gr_arg_normal(const struct gr_arg __user *buf, struct gr_arg *arg)
{
	if (copy_from_user(arg, buf, sizeof (struct gr_arg)))
		return -EFAULT;

	return 0;
}

static size_t get_gr_arg_wrapper_size_normal(void)
{
	return sizeof(struct gr_arg_wrapper);
}

#ifdef CONFIG_COMPAT
extern int copy_gr_arg_wrapper_compat(const char *buf, struct gr_arg_wrapper *uwrap);
extern int copy_gr_arg_compat(const struct gr_arg __user *buf, struct gr_arg *arg);
extern int copy_acl_object_label_compat(struct acl_object_label *obj, const struct acl_object_label *userp);
extern int copy_acl_subject_label_compat(struct acl_subject_label *subj, const struct acl_subject_label *userp);
extern int copy_acl_role_label_compat(struct acl_role_label *role, const struct acl_role_label *userp);
extern int copy_role_allowed_ip_compat(struct role_allowed_ip *roleip, const struct role_allowed_ip *userp);
extern int copy_role_transition_compat(struct role_transition *trans, const struct role_transition *userp);
extern int copy_gr_hash_struct_compat(struct gr_hash_struct *hash, const struct gr_hash_struct *userp);
extern int copy_pointer_from_array_compat(void *ptr, unsigned long idx, const void *userp);
extern int copy_acl_ip_label_compat(struct acl_ip_label *ip, const struct acl_ip_label *userp);
extern int copy_sprole_pw_compat(struct sprole_pw *pw, unsigned long idx, const struct sprole_pw *userp);
extern size_t get_gr_arg_wrapper_size_compat(void);

int (* copy_gr_arg_wrapper)(const char *buf, struct gr_arg_wrapper *uwrap) __read_only;
int (* copy_gr_arg)(const struct gr_arg *buf, struct gr_arg *arg) __read_only;
int (* copy_acl_object_label)(struct acl_object_label *obj, const struct acl_object_label *userp) __read_only;
int (* copy_acl_subject_label)(struct acl_subject_label *subj, const struct acl_subject_label *userp) __read_only;
int (* copy_acl_role_label)(struct acl_role_label *role, const struct acl_role_label *userp) __read_only;
int (* copy_acl_ip_label)(struct acl_ip_label *ip, const struct acl_ip_label *userp) __read_only;
int (* copy_pointer_from_array)(void *ptr, unsigned long idx, const void *userp) __read_only;
int (* copy_sprole_pw)(struct sprole_pw *pw, unsigned long idx, const struct sprole_pw *userp) __read_only;
int (* copy_gr_hash_struct)(struct gr_hash_struct *hash, const struct gr_hash_struct *userp) __read_only;
int (* copy_role_transition)(struct role_transition *trans, const struct role_transition *userp) __read_only;
int (* copy_role_allowed_ip)(struct role_allowed_ip *roleip, const struct role_allowed_ip *userp) __read_only;
size_t (* get_gr_arg_wrapper_size)(void) __read_only;

#else
#define copy_gr_arg_wrapper copy_gr_arg_wrapper_normal
#define copy_gr_arg copy_gr_arg_normal
#define copy_gr_hash_struct copy_gr_hash_struct_normal
#define copy_acl_object_label copy_acl_object_label_normal
#define copy_acl_subject_label copy_acl_subject_label_normal
#define copy_acl_role_label copy_acl_role_label_normal
#define copy_acl_ip_label copy_acl_ip_label_normal
#define copy_pointer_from_array copy_pointer_from_array_normal
#define copy_sprole_pw copy_sprole_pw_normal
#define copy_role_transition copy_role_transition_normal
#define copy_role_allowed_ip copy_role_allowed_ip_normal
#define get_gr_arg_wrapper_size get_gr_arg_wrapper_size_normal
#endif

static struct acl_subject_label *
lookup_subject_map(const struct acl_subject_label *userp)
{
	unsigned int index = gr_shash(userp, polstate->subj_map_set.s_size);
	struct subject_map *match;

	match = polstate->subj_map_set.s_hash[index];

	while (match && match->user != userp)
		match = match->next;

	if (match != NULL)
		return match->kernel;
	else
		return NULL;
}

static void
insert_subj_map_entry(struct subject_map *subjmap)
{
	unsigned int index = gr_shash(subjmap->user, polstate->subj_map_set.s_size);
	struct subject_map **curr;

	subjmap->prev = NULL;

	curr = &polstate->subj_map_set.s_hash[index];
	if (*curr != NULL)
		(*curr)->prev = subjmap;

	subjmap->next = *curr;
	*curr = subjmap;

	return;
}

static void
__insert_acl_role_label(struct acl_role_label *role, uid_t uidgid)
{
	unsigned int index =
	    gr_rhash(uidgid, role->roletype & (GR_ROLE_USER | GR_ROLE_GROUP), polstate->acl_role_set.r_size);
	struct acl_role_label **curr;
	struct acl_role_label *tmp, *tmp2;

	curr = &polstate->acl_role_set.r_hash[index];

	/* simple case, slot is empty, just set it to our role */
	if (*curr == NULL) {
		*curr = role;
	} else {
		/* example:
		   1 -> 2 -> 3 (adding 2 -> 3 to here)
		   2 -> 3
		*/
		/* first check to see if we can already be reached via this slot */
		tmp = *curr;
		while (tmp && tmp != role)
			tmp = tmp->next;
		if (tmp == role) {
			/* we don't need to add ourselves to this slot's chain */
			return;
		}
		/* we need to add ourselves to this chain, two cases */
		if (role->next == NULL) {
			/* simple case, append the current chain to our role */
			role->next = *curr;
			*curr = role;
		} else {
			/* 1 -> 2 -> 3 -> 4
			   2 -> 3 -> 4
			   3 -> 4 (adding 1 -> 2 -> 3 -> 4 to here)
			*/			   
			/* trickier case: walk our role's chain until we find
			   the role for the start of the current slot's chain */
			tmp = role;
			tmp2 = *curr;
			while (tmp->next && tmp->next != tmp2)
				tmp = tmp->next;
			if (tmp->next == tmp2) {
				/* from example above, we found 3, so just
				   replace this slot's chain with ours */
				*curr = role;
			} else {
				/* we didn't find a subset of our role's chain
				   in the current slot's chain, so append their
				   chain to ours, and set us as the first role in
				   the slot's chain

				   we could fold this case with the case above,
				   but making it explicit for clarity
				*/
				tmp->next = tmp2;
				*curr = role;
			}
		}
	}

	return;
}

static void
insert_acl_role_label(struct acl_role_label *role)
{
	int i;

	if (polstate->role_list == NULL) {
		polstate->role_list = role;
		role->prev = NULL;
	} else {
		role->prev = polstate->role_list;
		polstate->role_list = role;
	}
	
	/* used for hash chains */
	role->next = NULL;

	if (role->roletype & GR_ROLE_DOMAIN) {
		for (i = 0; i < role->domain_child_num; i++)
			__insert_acl_role_label(role, role->domain_children[i]);
	} else
		__insert_acl_role_label(role, role->uidgid);
}
					
static int
insert_name_entry(char *name, const u64 inode, const dev_t device, __u8 deleted)
{
	struct name_entry **curr, *nentry;
	struct inodev_entry *ientry;
	unsigned int len = strlen(name);
	unsigned int key = full_name_hash(NULL, (const unsigned char *)name, len);
	unsigned int index = key % polstate->name_set.n_size;

	curr = &polstate->name_set.n_hash[index];

	while (*curr && ((*curr)->key != key || !gr_streq((*curr)->name, name, (*curr)->len, len)))
		curr = &((*curr)->next);

	if (*curr != NULL)
		return 1;

	nentry = acl_alloc(sizeof (struct name_entry));
	if (nentry == NULL)
		return 0;
	ientry = acl_alloc(sizeof (struct inodev_entry));
	if (ientry == NULL)
		return 0;
	ientry->nentry = nentry;

	nentry->key = key;
	nentry->name = name;
	nentry->inode = inode;
	nentry->device = device;
	nentry->len = len;
	nentry->deleted = deleted;

	nentry->prev = NULL;
	curr = &polstate->name_set.n_hash[index];
	if (*curr != NULL)
		(*curr)->prev = nentry;
	nentry->next = *curr;
	*curr = nentry;

	/* insert us into the table searchable by inode/dev */
	__insert_inodev_entry(polstate, ientry);

	return 1;
}

/* allocating chained hash tables, so optimal size is where lambda ~ 1 */

static void *
create_table(__u32 * len, int elementsize)
{
	unsigned int table_sizes[] = {
		7, 13, 31, 61, 127, 251, 509, 1021, 2039, 4093, 8191, 16381,
		32749, 65521, 131071, 262139, 524287, 1048573, 2097143,
		4194301, 8388593, 16777213, 33554393, 67108859
	};
	void *newtable = NULL;
	unsigned int pwr = 0;

	while ((pwr < ((sizeof (table_sizes) / sizeof (table_sizes[0])) - 1)) &&
	       table_sizes[pwr] <= *len)
		pwr++;

	if (table_sizes[pwr] <= *len || (table_sizes[pwr] > ULONG_MAX / elementsize))
		return newtable;

	if ((table_sizes[pwr] * elementsize) <= PAGE_SIZE)
		newtable =
		    kmalloc(table_sizes[pwr] * elementsize, GFP_KERNEL);
	else
		newtable = vmalloc(table_sizes[pwr] * elementsize);

	*len = table_sizes[pwr];

	return newtable;
}

static int
init_variables(const struct gr_arg *arg, bool reload)
{
	struct task_struct *reaper = init_pid_ns.child_reaper;
	unsigned int stacksize;

	polstate->subj_map_set.s_size = arg->role_db.num_subjects;
	polstate->acl_role_set.r_size = arg->role_db.num_roles + arg->role_db.num_domain_children;
	polstate->name_set.n_size = arg->role_db.num_objects;
	polstate->inodev_set.i_size = arg->role_db.num_objects;

	if (!polstate->subj_map_set.s_size || !polstate->acl_role_set.r_size ||
	    !polstate->name_set.n_size || !polstate->inodev_set.i_size)
		return 1;

	if (!reload) {
		if (!gr_init_uidset())
			return 1;
	}

	/* set up the stack that holds allocation info */

	stacksize = arg->role_db.num_pointers + 5;

	if (!acl_alloc_stack_init(stacksize))
		return 1;

	if (!reload) {
		/* grab reference for the real root dentry and vfsmount */
		get_fs_root(reaper->fs, &gr_real_root);
	
#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
	printk(KERN_ALERT "Obtained real root device=%d, inode=%lu\n", gr_get_dev_from_dentry(gr_real_root.dentry), gr_get_ino_from_dentry(gr_real_root.dentry));
#endif

		fakefs_obj_rw = kzalloc(sizeof(struct acl_object_label), GFP_KERNEL);
		if (fakefs_obj_rw == NULL)
			return 1;
		fakefs_obj_rw->mode = GR_FIND | GR_READ | GR_WRITE;
	
		fakefs_obj_rwx = kzalloc(sizeof(struct acl_object_label), GFP_KERNEL);
		if (fakefs_obj_rwx == NULL)
			return 1;
		fakefs_obj_rwx->mode = GR_FIND | GR_READ | GR_WRITE | GR_EXEC;
	}

	polstate->subj_map_set.s_hash =
	    (struct subject_map **) create_table(&polstate->subj_map_set.s_size, sizeof(void *));
	polstate->acl_role_set.r_hash =
	    (struct acl_role_label **) create_table(&polstate->acl_role_set.r_size, sizeof(void *));
	polstate->name_set.n_hash = (struct name_entry **) create_table(&polstate->name_set.n_size, sizeof(void *));
	polstate->inodev_set.i_hash =
	    (struct inodev_entry **) create_table(&polstate->inodev_set.i_size, sizeof(void *));

	if (!polstate->subj_map_set.s_hash || !polstate->acl_role_set.r_hash ||
	    !polstate->name_set.n_hash || !polstate->inodev_set.i_hash)
		return 1;

	memset(polstate->subj_map_set.s_hash, 0,
	       sizeof(struct subject_map *) * polstate->subj_map_set.s_size);
	memset(polstate->acl_role_set.r_hash, 0,
	       sizeof (struct acl_role_label *) * polstate->acl_role_set.r_size);
	memset(polstate->name_set.n_hash, 0,
	       sizeof (struct name_entry *) * polstate->name_set.n_size);
	memset(polstate->inodev_set.i_hash, 0,
	       sizeof (struct inodev_entry *) * polstate->inodev_set.i_size);

	return 0;
}

/* free information not needed after startup
   currently contains user->kernel pointer mappings for subjects
*/

static void
free_init_variables(void)
{
	__u32 i;

	if (polstate->subj_map_set.s_hash) {
		for (i = 0; i < polstate->subj_map_set.s_size; i++) {
			if (polstate->subj_map_set.s_hash[i]) {
				kfree(polstate->subj_map_set.s_hash[i]);
				polstate->subj_map_set.s_hash[i] = NULL;
			}
		}

		if ((polstate->subj_map_set.s_size * sizeof (struct subject_map *)) <=
		    PAGE_SIZE)
			kfree(polstate->subj_map_set.s_hash);
		else
			vfree(polstate->subj_map_set.s_hash);
	}

	return;
}

static void
free_variables(bool reload)
{
	struct acl_subject_label *s;
	struct acl_role_label *r;
	struct task_struct *task, *task2;
	unsigned int x;

	if (!reload) {
		gr_clear_learn_entries();

		read_lock(&tasklist_lock);
		do_each_thread(task2, task) {
			task->acl_sp_role = 0;
			task->acl_role_id = 0;
			task->inherited = 0;
			task->acl = NULL;
			task->role = NULL;
		} while_each_thread(task2, task);
		read_unlock(&tasklist_lock);

		kfree(fakefs_obj_rw);
		fakefs_obj_rw = NULL;
		kfree(fakefs_obj_rwx);
		fakefs_obj_rwx = NULL;

		/* release the reference to the real root dentry and vfsmount */
		path_put(&gr_real_root);
		memset(&gr_real_root, 0, sizeof(gr_real_root));
	}

	/* free all object hash tables */

	FOR_EACH_ROLE_START(r)
		if (r->subj_hash == NULL)
			goto next_role;
		FOR_EACH_SUBJECT_START(r, s, x)
			if (s->obj_hash == NULL)
				break;
			if ((s->obj_hash_size * sizeof (struct acl_object_label *)) <= PAGE_SIZE)
				kfree(s->obj_hash);
			else
				vfree(s->obj_hash);
		FOR_EACH_SUBJECT_END(s, x)
		FOR_EACH_NESTED_SUBJECT_START(r, s)
			if (s->obj_hash == NULL)
				break;
			if ((s->obj_hash_size * sizeof (struct acl_object_label *)) <= PAGE_SIZE)
				kfree(s->obj_hash);
			else
				vfree(s->obj_hash);
		FOR_EACH_NESTED_SUBJECT_END(s)
		if ((r->subj_hash_size * sizeof (struct acl_subject_label *)) <= PAGE_SIZE)
			kfree(r->subj_hash);
		else
			vfree(r->subj_hash);
		r->subj_hash = NULL;
next_role:
	FOR_EACH_ROLE_END(r)

	acl_free_all();

	if (polstate->acl_role_set.r_hash) {
		if ((polstate->acl_role_set.r_size * sizeof (struct acl_role_label *)) <=
		    PAGE_SIZE)
			kfree(polstate->acl_role_set.r_hash);
		else
			vfree(polstate->acl_role_set.r_hash);
	}
	if (polstate->name_set.n_hash) {
		if ((polstate->name_set.n_size * sizeof (struct name_entry *)) <=
		    PAGE_SIZE)
			kfree(polstate->name_set.n_hash);
		else
			vfree(polstate->name_set.n_hash);
	}

	if (polstate->inodev_set.i_hash) {
		if ((polstate->inodev_set.i_size * sizeof (struct inodev_entry *)) <=
		    PAGE_SIZE)
			kfree(polstate->inodev_set.i_hash);
		else
			vfree(polstate->inodev_set.i_hash);
	}

	if (!reload)
		gr_free_uidset();

	memset(&polstate->name_set, 0, sizeof (struct name_db));
	memset(&polstate->inodev_set, 0, sizeof (struct inodev_db));
	memset(&polstate->acl_role_set, 0, sizeof (struct acl_role_db));
	memset(&polstate->subj_map_set, 0, sizeof (struct acl_subj_map_db));

	polstate->default_role = NULL;
	polstate->kernel_role = NULL;
	polstate->role_list = NULL;

	return;
}

static struct acl_subject_label *
do_copy_user_subj(struct acl_subject_label *userp, struct acl_role_label *role, int *already_copied);

static int alloc_and_copy_string(char **name, unsigned int maxlen)
{
	unsigned int len = strnlen_user(*name, maxlen);
	char *tmp;

	if (!len || len >= maxlen)
		return -EINVAL;

	if ((tmp = (char *) acl_alloc(len)) == NULL)
		return -ENOMEM;

	if (copy_from_user(tmp, *name, len))
		return -EFAULT;

	tmp[len-1] = '\0';
	*name = tmp;

	return 0;
}

static int
copy_user_glob(struct acl_object_label *obj)
{
	struct acl_object_label *g_tmp, **guser;
	int error;

	if (obj->globbed == NULL)
		return 0;

	guser = &obj->globbed;
	while (*guser) {
		g_tmp = (struct acl_object_label *)
			acl_alloc(sizeof (struct acl_object_label));
		if (g_tmp == NULL)
			return -ENOMEM;

		if (copy_acl_object_label(g_tmp, *guser))
			return -EFAULT;

		error = alloc_and_copy_string(&g_tmp->filename, PATH_MAX);
		if (error)
			return error;

		*guser = g_tmp;
		guser = &(g_tmp->next);
	}

	return 0;
}

static int
copy_user_objs(struct acl_object_label *userp, struct acl_subject_label *subj,
	       struct acl_role_label *role)
{
	struct acl_object_label *o_tmp;
	int ret;

	while (userp) {
		if ((o_tmp = (struct acl_object_label *)
		     acl_alloc(sizeof (struct acl_object_label))) == NULL)
			return -ENOMEM;

		if (copy_acl_object_label(o_tmp, userp))
			return -EFAULT;

		userp = o_tmp->prev;

		ret = alloc_and_copy_string(&o_tmp->filename, PATH_MAX);
		if (ret)
			return ret;

		insert_acl_obj_label(o_tmp, subj);
		if (!insert_name_entry(o_tmp->filename, o_tmp->inode,
				       o_tmp->device, (o_tmp->mode & GR_DELETED) ? 1 : 0))
			return -ENOMEM;

		ret = copy_user_glob(o_tmp);
		if (ret)
			return ret;

		if (o_tmp->nested) {
			int already_copied;

			o_tmp->nested = do_copy_user_subj(o_tmp->nested, role, &already_copied);
			if (IS_ERR(o_tmp->nested))
				return PTR_ERR(o_tmp->nested);

			/* insert into nested subject list if we haven't copied this one yet
			   to prevent duplicate entries */
			if (!already_copied) {
				o_tmp->nested->next = role->hash->first;
				role->hash->first = o_tmp->nested;
			}
		}
	}

	return 0;
}

static __u32
count_user_subjs(struct acl_subject_label *userp)
{
	struct acl_subject_label s_tmp;
	__u32 num = 0;

	while (userp) {
		if (copy_acl_subject_label(&s_tmp, userp))
			break;

		userp = s_tmp.prev;
	}

	return num;
}

static int
copy_user_allowedips(struct acl_role_label *rolep)
{
	struct role_allowed_ip *ruserip, *rtmp = NULL, *rlast;

	ruserip = rolep->allowed_ips;

	while (ruserip) {
		rlast = rtmp;

		if ((rtmp = (struct role_allowed_ip *)
		     acl_alloc(sizeof (struct role_allowed_ip))) == NULL)
			return -ENOMEM;

		if (copy_role_allowed_ip(rtmp, ruserip))
			return -EFAULT;

		ruserip = rtmp->prev;

		if (!rlast) {
			rtmp->prev = NULL;
			rolep->allowed_ips = rtmp;
		} else {
			rlast->next = rtmp;
			rtmp->prev = rlast;
		}

		if (!ruserip)
			rtmp->next = NULL;
	}

	return 0;
}

static int
copy_user_transitions(struct acl_role_label *rolep)
{
	struct role_transition *rusertp, *rtmp = NULL, *rlast;
	int error;

	rusertp = rolep->transitions;

	while (rusertp) {
		rlast = rtmp;

		if ((rtmp = (struct role_transition *)
		     acl_alloc(sizeof (struct role_transition))) == NULL)
			return -ENOMEM;

		if (copy_role_transition(rtmp, rusertp))
			return -EFAULT;

		rusertp = rtmp->prev;

		error = alloc_and_copy_string(&rtmp->rolename, GR_SPROLE_LEN);
		if (error)
			return error;

		if (!rlast) {
			rtmp->prev = NULL;
			rolep->transitions = rtmp;
		} else {
			rlast->next = rtmp;
			rtmp->prev = rlast;
		}

		if (!rusertp)
			rtmp->next = NULL;
	}

	return 0;
}

static __u32 count_user_objs(const struct acl_object_label __user *userp)
{
	struct acl_object_label o_tmp;
	__u32 num = 0;

	while (userp) {
		if (copy_acl_object_label(&o_tmp, userp))
			break;

		userp = o_tmp.prev;
		num++;
	}

	return num;
}

static struct acl_subject_label *
do_copy_user_subj(struct acl_subject_label *userp, struct acl_role_label *role, int *already_copied)
{
	struct acl_subject_label *s_tmp = NULL, *s_tmp2;
	__u32 num_objs;
	struct acl_ip_label **i_tmp, *i_utmp2;
	struct gr_hash_struct ghash;
	struct subject_map *subjmap;
	unsigned int i_num;
	int err;

	if (already_copied != NULL)
		*already_copied = 0;

	s_tmp = lookup_subject_map(userp);

	/* we've already copied this subject into the kernel, just return
	   the reference to it, and don't copy it over again
	*/
	if (s_tmp) {
		if (already_copied != NULL)
			*already_copied = 1;
		return(s_tmp);
	}

	if ((s_tmp = (struct acl_subject_label *)
	    acl_alloc(sizeof (struct acl_subject_label))) == NULL)
		return ERR_PTR(-ENOMEM);

	subjmap = (struct subject_map *)kmalloc(sizeof (struct subject_map), GFP_KERNEL);
	if (subjmap == NULL)
		return ERR_PTR(-ENOMEM);

	subjmap->user = userp;
	subjmap->kernel = s_tmp;
	insert_subj_map_entry(subjmap);

	if (copy_acl_subject_label(s_tmp, userp))
		return ERR_PTR(-EFAULT);

	err = alloc_and_copy_string(&s_tmp->filename, PATH_MAX);
	if (err)
		return ERR_PTR(err);

	if (!strcmp(s_tmp->filename, "/"))
		role->root_label = s_tmp;

	if (copy_gr_hash_struct(&ghash, s_tmp->hash))
		return ERR_PTR(-EFAULT);

	/* copy user and group transition tables */

	if (s_tmp->user_trans_num) {
		uid_t *uidlist;

		uidlist = (uid_t *)acl_alloc_num(s_tmp->user_trans_num, sizeof(uid_t));
		if (uidlist == NULL)
			return ERR_PTR(-ENOMEM);
		if (copy_from_user(uidlist, s_tmp->user_transitions, s_tmp->user_trans_num * sizeof(uid_t)))
			return ERR_PTR(-EFAULT);

		s_tmp->user_transitions = uidlist;
	}

	if (s_tmp->group_trans_num) {
		gid_t *gidlist;

		gidlist = (gid_t *)acl_alloc_num(s_tmp->group_trans_num, sizeof(gid_t));
		if (gidlist == NULL)
			return ERR_PTR(-ENOMEM);
		if (copy_from_user(gidlist, s_tmp->group_transitions, s_tmp->group_trans_num * sizeof(gid_t)))
			return ERR_PTR(-EFAULT);

		s_tmp->group_transitions = gidlist;
	}

	/* set up object hash table */
	num_objs = count_user_objs(ghash.first);

	s_tmp->obj_hash_size = num_objs;
	s_tmp->obj_hash =
	    (struct acl_object_label **)
	    create_table(&(s_tmp->obj_hash_size), sizeof(void *));

	if (!s_tmp->obj_hash)
		return ERR_PTR(-ENOMEM);

	memset(s_tmp->obj_hash, 0,
	       s_tmp->obj_hash_size *
	       sizeof (struct acl_object_label *));

	/* add in objects */
	err = copy_user_objs(ghash.first, s_tmp, role);

	if (err)
		return ERR_PTR(err);

	/* set pointer for parent subject */
	if (s_tmp->parent_subject) {
		s_tmp2 = do_copy_user_subj(s_tmp->parent_subject, role, NULL);

		if (IS_ERR(s_tmp2))
			return s_tmp2;

		s_tmp->parent_subject = s_tmp2;
	}

	/* add in ip acls */

	if (!s_tmp->ip_num) {
		s_tmp->ips = NULL;
		goto insert;
	}

	i_tmp =
	    (struct acl_ip_label **) acl_alloc_num(s_tmp->ip_num,
					       sizeof (struct acl_ip_label *));

	if (!i_tmp)
		return ERR_PTR(-ENOMEM);

	for (i_num = 0; i_num < s_tmp->ip_num; i_num++) {
		*(i_tmp + i_num) =
		    (struct acl_ip_label *)
		    acl_alloc(sizeof (struct acl_ip_label));
		if (!*(i_tmp + i_num))
			return ERR_PTR(-ENOMEM);

		if (copy_pointer_from_array(&i_utmp2, i_num, s_tmp->ips))
			return ERR_PTR(-EFAULT);

		if (copy_acl_ip_label(*(i_tmp + i_num), i_utmp2))
			return ERR_PTR(-EFAULT);
		
		if ((*(i_tmp + i_num))->iface == NULL)
			continue;

		err = alloc_and_copy_string(&(*(i_tmp + i_num))->iface, IFNAMSIZ);
		if (err)
			return ERR_PTR(err);
	}

	s_tmp->ips = i_tmp;

insert:
	if (!insert_name_entry(s_tmp->filename, s_tmp->inode,
			       s_tmp->device, (s_tmp->mode & GR_DELETED) ? 1 : 0))
		return ERR_PTR(-ENOMEM);

	return s_tmp;
}

static int
copy_user_subjs(struct acl_subject_label *userp, struct acl_role_label *role)
{
	struct acl_subject_label s_pre;
	struct acl_subject_label * ret;
	int err;

	while (userp) {
		if (copy_acl_subject_label(&s_pre, userp))
			return -EFAULT;
		
		ret = do_copy_user_subj(userp, role, NULL);

		err = PTR_ERR(ret);
		if (IS_ERR(ret))
			return err;

		insert_acl_subj_label(ret, role);

		userp = s_pre.prev;
	}

	return 0;
}

static int
copy_user_acl(struct gr_arg *arg)
{
	struct acl_role_label *r_tmp = NULL, **r_utmp, *r_utmp2;
	struct acl_subject_label *subj_list;
	struct sprole_pw *sptmp;
	struct gr_hash_struct *ghash;
	uid_t *domainlist;
	unsigned int r_num;
	int err = 0;
	__u16 i;
	__u32 num_subjs;

	/* we need a default and kernel role */
	if (arg->role_db.num_roles < 2)
		return -EINVAL;

	/* copy special role authentication info from userspace */

	polstate->num_sprole_pws = arg->num_sprole_pws;
	polstate->acl_special_roles = (struct sprole_pw **) acl_alloc_num(polstate->num_sprole_pws, sizeof(struct sprole_pw *));

	if (!polstate->acl_special_roles && polstate->num_sprole_pws)
		return -ENOMEM;

	for (i = 0; i < polstate->num_sprole_pws; i++) {
		sptmp = (struct sprole_pw *) acl_alloc(sizeof(struct sprole_pw));
		if (!sptmp)
			return -ENOMEM;
		if (copy_sprole_pw(sptmp, i, arg->sprole_pws))
			return -EFAULT;

		err = alloc_and_copy_string((char **)&sptmp->rolename, GR_SPROLE_LEN);
		if (err)
			return err;

#ifdef CONFIG_GRKERNSEC_RBAC_DEBUG
		printk(KERN_ALERT "Copying special role %s\n", sptmp->rolename);
#endif

		polstate->acl_special_roles[i] = sptmp;
	}

	r_utmp = (struct acl_role_label **) arg->role_db.r_table;

	for (r_num = 0; r_num < arg->role_db.num_roles; r_num++) {
		r_tmp = acl_alloc(sizeof (struct acl_role_label));

		if (!r_tmp)
			return -ENOMEM;

		if (copy_pointer_from_array(&r_utmp2, r_num, r_utmp))
			return -EFAULT;

		if (copy_acl_role_label(r_tmp, r_utmp2))
			return -EFAULT;

		err = alloc_and_copy_string(&r_tmp->rolename, GR_SPROLE_LEN);
		if (err)
			return err;

		if (!strcmp(r_tmp->rolename, "default")
		    && (r_tmp->roletype & GR_ROLE_DEFAULT)) {
			polstate->default_role = r_tmp;
		} else if (!strcmp(r_tmp->rolename, ":::kernel:::")) {
			polstate->kernel_role = r_tmp;
		}

		if ((ghash = (struct gr_hash_struct *) acl_alloc(sizeof(struct gr_hash_struct))) == NULL)
			return -ENOMEM;

		if (copy_gr_hash_struct(ghash, r_tmp->hash))
			return -EFAULT;

		r_tmp->hash = ghash;

		num_subjs = count_user_subjs(r_tmp->hash->first);

		r_tmp->subj_hash_size = num_subjs;
		r_tmp->subj_hash =
		    (struct acl_subject_label **)
		    create_table(&(r_tmp->subj_hash_size), sizeof(void *));

		if (!r_tmp->subj_hash)
			return -ENOMEM;

		err = copy_user_allowedips(r_tmp);
		if (err)
			return err;

		/* copy domain info */
		if (r_tmp->domain_children != NULL) {
			domainlist = acl_alloc_num(r_tmp->domain_child_num, sizeof(uid_t));
			if (domainlist == NULL)
				return -ENOMEM;

			if (copy_from_user(domainlist, r_tmp->domain_children, r_tmp->domain_child_num * sizeof(uid_t)))
				return -EFAULT;

			r_tmp->domain_children = domainlist;
		}

		err = copy_user_transitions(r_tmp);
		if (err)
			return err;

		memset(r_tmp->subj_hash, 0,
		       r_tmp->subj_hash_size *
		       sizeof (struct acl_subject_label *));

		/* acquire the list of subjects, then NULL out
		   the list prior to parsing the subjects for this role,
		   as during this parsing the list is replaced with a list
		   of *nested* subjects for the role
		*/
		subj_list = r_tmp->hash->first;

		/* set nested subject list to null */
		r_tmp->hash->first = NULL;

		err = copy_user_subjs(subj_list, r_tmp);

		if (err)
			return err;

		insert_acl_role_label(r_tmp);
	}

	if (polstate->default_role == NULL || polstate->kernel_role == NULL)
		return -EINVAL;

	return err;
}

static int gracl_reload_apply_policies(void *reload)
{
	struct gr_reload_state *reload_state = (struct gr_reload_state *)reload;
	struct task_struct *task, *task2;
	struct acl_role_label *role, *rtmp;
	struct acl_subject_label *subj;
	const struct cred *cred;
	int role_applied;
	int ret = 0;

	memcpy(&reload_state->oldpolicy, reload_state->oldpolicy_ptr, sizeof(struct gr_policy_state));
	memcpy(&reload_state->oldalloc, reload_state->oldalloc_ptr, sizeof(struct gr_alloc_state));

	/* first make sure we'll be able to apply the new policy cleanly */
	do_each_thread(task2, task) {
		if (task->exec_file == NULL)
			continue;
		role_applied = 0;
		if (!reload_state->oldmode && task->role->roletype & GR_ROLE_SPECIAL) {
			/* preserve special roles */
			FOR_EACH_ROLE_START(role)
				if ((role->roletype & GR_ROLE_SPECIAL) && !strcmp(task->role->rolename, role->rolename)) {
					rtmp = task->role;
					task->role = role;
					role_applied = 1;
					break;
				}
			FOR_EACH_ROLE_END(role)
		}
		if (!role_applied) {
			cred = __task_cred(task);
			rtmp = task->role;
			task->role = __lookup_acl_role_label(polstate, task, GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid));
		}
		/* this handles non-nested inherited subjects, nested subjects will still
		   be dropped currently */
		subj = __gr_get_subject_for_task(polstate, task, task->acl->filename, 1);
		task->tmpacl = __gr_get_subject_for_task(polstate, task, NULL, 1);
		/* change the role back so that we've made no modifications to the policy */
		task->role = rtmp;

		if (subj == NULL || task->tmpacl == NULL) {
			ret = -EINVAL;
			goto out;
		}
	} while_each_thread(task2, task);

	/* now actually apply the policy */

	do_each_thread(task2, task) {
		if (task->exec_file) {
			role_applied = 0;
			if (!reload_state->oldmode && task->role->roletype & GR_ROLE_SPECIAL) {
				/* preserve special roles */
				FOR_EACH_ROLE_START(role)
					if ((role->roletype & GR_ROLE_SPECIAL) && !strcmp(task->role->rolename, role->rolename)) {
						task->role = role;
						role_applied = 1;
						break;
					}
				FOR_EACH_ROLE_END(role)
			}
			if (!role_applied) {
				cred = __task_cred(task);
				task->role = __lookup_acl_role_label(polstate, task, GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid));
			}
			/* this handles non-nested inherited subjects, nested subjects will still
			   be dropped currently */
			if (!reload_state->oldmode && task->inherited)
				subj = __gr_get_subject_for_task(polstate, task, task->acl->filename, 1);
			else {
				/* looked up and tagged to the task previously */
				subj = task->tmpacl;
			}
			/* subj will be non-null */
			__gr_apply_subject_to_task(polstate, task, subj);
			if (reload_state->oldmode) {
				task->acl_role_id = 0;
				task->acl_sp_role = 0;
				task->inherited = 0;
			}
		} else {
			// it's a kernel process
			task->role = polstate->kernel_role;
			task->acl = polstate->kernel_role->root_label;
#ifdef CONFIG_GRKERNSEC_ACL_HIDEKERN
			task->acl->mode &= ~GR_PROCFIND;
#endif
		}
	} while_each_thread(task2, task);

	memcpy(reload_state->oldpolicy_ptr, &reload_state->newpolicy, sizeof(struct gr_policy_state));
	memcpy(reload_state->oldalloc_ptr, &reload_state->newalloc, sizeof(struct gr_alloc_state));

out:

	return ret;
}

static int gracl_reload(struct gr_arg *args, unsigned char oldmode)
{
	struct gr_reload_state new_reload_state = { };
	int err;

	new_reload_state.oldpolicy_ptr = polstate;
	new_reload_state.oldalloc_ptr = current_alloc_state;
	new_reload_state.oldmode = oldmode;

	current_alloc_state = &new_reload_state.newalloc;
	polstate = &new_reload_state.newpolicy;

	/* everything relevant is now saved off, copy in the new policy */
	if (init_variables(args, true)) {
		gr_log_str(GR_DONT_AUDIT_GOOD, GR_INITF_ACL_MSG, GR_VERSION);
		err = -ENOMEM;
		goto error;
	}

	err = copy_user_acl(args);
	free_init_variables();
	if (err)
		goto error;
	/* the new policy is copied in, with the old policy available via saved_state
	   first go through applying roles, making sure to preserve special roles
	   then apply new subjects, making sure to preserve inherited and nested subjects,
	   though currently only inherited subjects will be preserved
	*/
	err = stop_machine(gracl_reload_apply_policies, &new_reload_state, NULL);
	if (err)
		goto error;

	/* we've now applied the new policy, so restore the old policy state to free it */
	polstate = &new_reload_state.oldpolicy;
	current_alloc_state = &new_reload_state.oldalloc;
	free_variables(true);

	/* oldpolicy/oldalloc_ptr point to the new policy/alloc states as they were copied
	   to running_polstate/current_alloc_state inside stop_machine
	*/
	err = 0;
	goto out;
error:
	/* on error of loading the new policy, we'll just keep the previous
	   policy set around
	*/
	free_variables(true);

	/* doesn't affect runtime, but maintains consistent state */
out:
	polstate = new_reload_state.oldpolicy_ptr;
	current_alloc_state = new_reload_state.oldalloc_ptr;

	return err;
}

static int
gracl_init(struct gr_arg *args)
{
	int error = 0;

	memcpy(gr_system_salt, args->salt, GR_SALT_LEN);
	memcpy(gr_system_sum, args->sum, GR_SHA_LEN);

	if (init_variables(args, false)) {
		gr_log_str(GR_DONT_AUDIT_GOOD, GR_INITF_ACL_MSG, GR_VERSION);
		error = -ENOMEM;
		goto out;
	}

	error = copy_user_acl(args);
	free_init_variables();
	if (error)
		goto out;

	error = gr_set_acls(0);
	if (error)
		goto out;

	gr_enable_rbac_system();

	return 0;

out:
	free_variables(false);
	return error;
}

static int
lookup_special_role_auth(__u16 mode, const char *rolename, unsigned char **salt,
			 unsigned char **sum)
{
	struct acl_role_label *r;
	struct role_allowed_ip *ipp;
	struct role_transition *trans;
	unsigned int i;
	int found = 0;
	u32 curr_ip = current->signal->curr_ip;

	current->signal->saved_ip = curr_ip;

	/* check transition table */

	for (trans = current->role->transitions; trans; trans = trans->next) {
		if (!strcmp(rolename, trans->rolename)) {
			found = 1;
			break;
		}
	}

	if (!found)
		return 0;

	/* handle special roles that do not require authentication
	   and check ip */

	FOR_EACH_ROLE_START(r)
		if (!strcmp(rolename, r->rolename) &&
		    (r->roletype & GR_ROLE_SPECIAL)) {
			found = 0;
			if (r->allowed_ips != NULL) {
				for (ipp = r->allowed_ips; ipp; ipp = ipp->next) {
					if ((ntohl(curr_ip) & ipp->netmask) ==
					     (ntohl(ipp->addr) & ipp->netmask))
						found = 1;
				}
			} else
				found = 2;
			if (!found)
				return 0;

			if (((mode == GR_SPROLE) && (r->roletype & GR_ROLE_NOPW)) ||
			    ((mode == GR_SPROLEPAM) && (r->roletype & GR_ROLE_PAM))) {
				*salt = NULL;
				*sum = NULL;
				return 1;
			}
		}
	FOR_EACH_ROLE_END(r)

	for (i = 0; i < polstate->num_sprole_pws; i++) {
		if (!strcmp(rolename, (const char *)polstate->acl_special_roles[i]->rolename)) {
			*salt = polstate->acl_special_roles[i]->salt;
			*sum = polstate->acl_special_roles[i]->sum;
			return 1;
		}
	}

	return 0;
}

int gr_check_secure_terminal(struct task_struct *task)
{
	struct task_struct *p, *p2, *p3;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *our_file = NULL, *file;
	struct inode *our_inode = NULL;
	int i;

	if (task->signal->tty == NULL)
		return 1;

	files = get_files_struct(task);
	if (files != NULL) {
		rcu_read_lock();
		fdt = files_fdtable(files);
		for (i=0; i < fdt->max_fds; i++) {
			file = fcheck_files(files, i);
			if (file && (our_file == NULL) && (file->private_data == task->signal->tty)) {
				get_file(file);
				our_file = file;
			}
		}
		rcu_read_unlock();
		put_files_struct(files);
	}

	if (our_file == NULL)
		return 1;

	our_inode = d_backing_inode(our_file->f_path.dentry);

	read_lock(&tasklist_lock);
	do_each_thread(p2, p) {
		files = get_files_struct(p);
		if (files == NULL ||
		    (p->signal && p->signal->tty == task->signal->tty)) {
			if (files != NULL)
				put_files_struct(files);
			continue;
		}
		rcu_read_lock();
		fdt = files_fdtable(files);
		for (i=0; i < fdt->max_fds; i++) {
			struct inode *inode = NULL;
			file = fcheck_files(files, i);
			if (file)
				inode = d_backing_inode(file->f_path.dentry);
			if (inode && S_ISCHR(inode->i_mode) && inode->i_rdev == our_inode->i_rdev) {
				p3 = task;
				while (task_pid_nr(p3) > 0) {
					if (p3 == p)
						break;
					p3 = p3->real_parent;
				}
				if (p3 == p)
					break;
				gr_log_ttysniff(GR_DONT_AUDIT_GOOD, GR_TTYSNIFF_ACL_MSG, p);
				gr_handle_alertkill(p);
				rcu_read_unlock();
				put_files_struct(files);
				read_unlock(&tasklist_lock);
				fput(our_file);
				return 0;
			}
		}
		rcu_read_unlock();
		put_files_struct(files);
	} while_each_thread(p2, p);
	read_unlock(&tasklist_lock);

	fput(our_file);
	return 1;
}

ssize_t
write_grsec_handler(struct file *file, const char __user * buf, size_t count, loff_t *ppos)
{
	struct gr_arg_wrapper uwrap;
	unsigned char *sprole_salt = NULL;
	unsigned char *sprole_sum = NULL;
	int error = 0;
	int error2 = 0;
	size_t req_count = 0;
	unsigned char oldmode = 0;

	mutex_lock(&gr_dev_mutex);

	if (gr_acl_is_enabled() && !(current->acl->mode & GR_KERNELAUTH)) {
		error = -EPERM;
		goto out;
	}

#ifdef CONFIG_COMPAT
	pax_open_kernel();
	if (in_compat_syscall()) {
		copy_gr_arg_wrapper = &copy_gr_arg_wrapper_compat;
		copy_gr_arg = &copy_gr_arg_compat;
		copy_acl_object_label = &copy_acl_object_label_compat;
		copy_acl_subject_label = &copy_acl_subject_label_compat;
		copy_acl_role_label = &copy_acl_role_label_compat;
		copy_acl_ip_label = &copy_acl_ip_label_compat;
		copy_role_allowed_ip = &copy_role_allowed_ip_compat;
		copy_role_transition = &copy_role_transition_compat;
		copy_sprole_pw = &copy_sprole_pw_compat;
		copy_gr_hash_struct = &copy_gr_hash_struct_compat;
		copy_pointer_from_array = &copy_pointer_from_array_compat;
		get_gr_arg_wrapper_size = &get_gr_arg_wrapper_size_compat;
	} else {
		copy_gr_arg_wrapper = &copy_gr_arg_wrapper_normal;
		copy_gr_arg = &copy_gr_arg_normal;
		copy_acl_object_label = &copy_acl_object_label_normal;
		copy_acl_subject_label = &copy_acl_subject_label_normal;
		copy_acl_role_label = &copy_acl_role_label_normal;
		copy_acl_ip_label = &copy_acl_ip_label_normal;
		copy_role_allowed_ip = &copy_role_allowed_ip_normal;
		copy_role_transition = &copy_role_transition_normal;
		copy_sprole_pw = &copy_sprole_pw_normal;
		copy_gr_hash_struct = &copy_gr_hash_struct_normal;
		copy_pointer_from_array = &copy_pointer_from_array_normal;
		get_gr_arg_wrapper_size = &get_gr_arg_wrapper_size_normal;
	}
	pax_close_kernel();
#endif

	req_count = get_gr_arg_wrapper_size();

	if (count != req_count) {
		gr_log_int_int(GR_DONT_AUDIT_GOOD, GR_DEV_ACL_MSG, (int)count, (int)req_count);
		error = -EINVAL;
		goto out;
	}

	
	if (gr_auth_expires && time_after_eq(get_seconds(), gr_auth_expires)) {
		gr_auth_expires = 0;
		gr_auth_attempts = 0;
	}

	error = copy_gr_arg_wrapper(buf, &uwrap);
	if (error)
		goto out;

	error = copy_gr_arg(uwrap.arg, gr_usermode);
	if (error)
		goto out;

	if (gr_usermode->mode != GR_SPROLE && gr_usermode->mode != GR_SPROLEPAM &&
	    gr_auth_attempts >= CONFIG_GRKERNSEC_ACL_MAXTRIES &&
	    time_after(gr_auth_expires, get_seconds())) {
		error = -EBUSY;
		goto out;
	}

	/* if non-root trying to do anything other than use a special role,
	   do not attempt authentication, do not count towards authentication
	   locking
	 */

	if (gr_usermode->mode != GR_SPROLE && gr_usermode->mode != GR_STATUS &&
	    gr_usermode->mode != GR_UNSPROLE && gr_usermode->mode != GR_SPROLEPAM &&
	    gr_is_global_nonroot(current_uid())) {
		error = -EPERM;
		goto out;
	}

	/* ensure pw and special role name are null terminated */

	gr_usermode->pw[GR_PW_LEN - 1] = '\0';
	gr_usermode->sp_role[GR_SPROLE_LEN - 1] = '\0';

	/* Okay. 
	 * We have our enough of the argument structure..(we have yet
	 * to copy_from_user the tables themselves) . Copy the tables
	 * only if we need them, i.e. for loading operations. */

	switch (gr_usermode->mode) {
	case GR_STATUS:
			if (gr_acl_is_enabled()) {
				error = 1;
				if (!gr_check_secure_terminal(current))
					error = 3;
			} else
				error = 2;
			goto out;
	case GR_SHUTDOWN:
		if (gr_acl_is_enabled() && !(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			stop_machine(gr_rbac_disable, NULL, NULL);
			free_variables(false);
			memset(gr_usermode, 0, sizeof(struct gr_arg));
			memset(gr_system_salt, 0, GR_SALT_LEN);
			memset(gr_system_sum, 0, GR_SHA_LEN);
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SHUTS_ACL_MSG);
		} else if (gr_acl_is_enabled()) {
			gr_log_noargs(GR_DONT_AUDIT, GR_SHUTF_ACL_MSG);
			error = -EPERM;
		} else {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SHUTI_ACL_MSG);
			error = -EAGAIN;
		}
		break;
	case GR_ENABLE:
		if (!gr_acl_is_enabled() && !(error2 = gracl_init(gr_usermode)))
			gr_log_str(GR_DONT_AUDIT_GOOD, GR_ENABLE_ACL_MSG, GR_VERSION);
		else {
			if (gr_acl_is_enabled())
				error = -EAGAIN;
			else
				error = error2;
			gr_log_str(GR_DONT_AUDIT, GR_ENABLEF_ACL_MSG, GR_VERSION);
		}
		break;
	case GR_OLDRELOAD:
		oldmode = 1;
	case GR_RELOAD:
		if (!gr_acl_is_enabled()) {
			gr_log_str(GR_DONT_AUDIT_GOOD, GR_RELOADI_ACL_MSG, GR_VERSION);
			error = -EAGAIN;
		} else if (!(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			error2 = gracl_reload(gr_usermode, oldmode);
			if (!error2)
				gr_log_str(GR_DONT_AUDIT_GOOD, GR_RELOAD_ACL_MSG, GR_VERSION);
			else {
				gr_log_str(GR_DONT_AUDIT, GR_RELOADF_ACL_MSG, GR_VERSION);
				error = error2;
			}
		} else {
			gr_log_str(GR_DONT_AUDIT, GR_RELOADF_ACL_MSG, GR_VERSION);
			error = -EPERM;
		}
		break;
	case GR_SEGVMOD:
		if (unlikely(!gr_acl_is_enabled())) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SEGVMODI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (!(chkpw(gr_usermode, gr_system_salt, gr_system_sum))) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SEGVMODS_ACL_MSG);
			if (gr_usermode->segv_device && gr_usermode->segv_inode) {
				struct acl_subject_label *segvacl;
				segvacl =
				    lookup_acl_subj_label(gr_usermode->segv_inode,
							  gr_usermode->segv_device,
							  current->role);
				if (segvacl) {
					segvacl->crashes = 0;
					segvacl->expires = 0;
				}
			} else
				gr_find_and_remove_uid(gr_usermode->segv_uid);
		} else {
			gr_log_noargs(GR_DONT_AUDIT, GR_SEGVMODF_ACL_MSG);
			error = -EPERM;
		}
		break;
	case GR_SPROLE:
	case GR_SPROLEPAM:
		if (unlikely(!gr_acl_is_enabled())) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_SPROLEI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (current->role->expires && time_after_eq(get_seconds(), current->role->expires)) {
			current->role->expires = 0;
			current->role->auth_attempts = 0;
		}

		if (current->role->auth_attempts >= CONFIG_GRKERNSEC_ACL_MAXTRIES &&
		    time_after(current->role->expires, get_seconds())) {
			error = -EBUSY;
			goto out;
		}

		if (lookup_special_role_auth
		    (gr_usermode->mode, (const char *)gr_usermode->sp_role, &sprole_salt, &sprole_sum)
		    && ((!sprole_salt && !sprole_sum)
			|| !(chkpw(gr_usermode, sprole_salt, sprole_sum)))) {
			char *p = "";
			assign_special_role((const char *)gr_usermode->sp_role);
			read_lock(&tasklist_lock);
			if (current->real_parent)
				p = current->real_parent->role->rolename;
			read_unlock(&tasklist_lock);
			gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_SPROLES_ACL_MSG,
					p, acl_sp_role_value);
		} else {
			gr_log_str(GR_DONT_AUDIT, GR_SPROLEF_ACL_MSG, gr_usermode->sp_role);
			error = -EPERM;
			if(!(current->role->auth_attempts++))
				current->role->expires = get_seconds() + CONFIG_GRKERNSEC_ACL_TIMEOUT;

			goto out;
		}
		break;
	case GR_UNSPROLE:
		if (unlikely(!gr_acl_is_enabled())) {
			gr_log_noargs(GR_DONT_AUDIT_GOOD, GR_UNSPROLEI_ACL_MSG);
			error = -EAGAIN;
			break;
		}

		if (current->role->roletype & GR_ROLE_SPECIAL) {
			char *p = "";
			int i = 0;

			read_lock(&tasklist_lock);
			if (current->real_parent) {
				p = current->real_parent->role->rolename;
				i = current->real_parent->acl_role_id;
			}
			read_unlock(&tasklist_lock);

			gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_UNSPROLES_ACL_MSG, p, i);
			gr_set_acls(1);
		} else {
			error = -EPERM;
			goto out;
		}
		break;
	default:
		gr_log_int(GR_DONT_AUDIT, GR_INVMODE_ACL_MSG, gr_usermode->mode);
		error = -EINVAL;
		break;
	}

	if (error != -EPERM)
		goto out;

	if(!(gr_auth_attempts++))
		gr_auth_expires = get_seconds() + CONFIG_GRKERNSEC_ACL_TIMEOUT;

      out:
	mutex_unlock(&gr_dev_mutex);

	if (!error)
		error = req_count;

	return error;
}

int
gr_set_acls(const int type)
{
	struct task_struct *task, *task2;
	struct acl_role_label *role = current->role;
	struct acl_subject_label *subj;
	__u16 acl_role_id = current->acl_role_id;
	const struct cred *cred;
	int ret;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	read_lock(&grsec_exec_file_lock);
	do_each_thread(task2, task) {
		/* check to see if we're called from the exit handler,
		   if so, only replace ACLs that have inherited the admin
		   ACL */

		if (type && (task->role != role ||
			     task->acl_role_id != acl_role_id))
			continue;

		task->acl_role_id = 0;
		task->acl_sp_role = 0;
		task->inherited = 0;

		if (task->exec_file) {
			cred = __task_cred(task);
			task->role = __lookup_acl_role_label(polstate, task, GR_GLOBAL_UID(cred->uid), GR_GLOBAL_GID(cred->gid));
			subj = __gr_get_subject_for_task(polstate, task, NULL, 1);
			if (subj == NULL) {
				ret = -EINVAL;
				read_unlock(&grsec_exec_file_lock);
				read_unlock(&tasklist_lock);
				rcu_read_unlock();
				gr_log_str_int(GR_DONT_AUDIT_GOOD, GR_DEFACL_MSG, task->comm, task_pid_nr(task));
				return ret;
			}
			__gr_apply_subject_to_task(polstate, task, subj);
		} else {
			// it's a kernel process
			task->role = polstate->kernel_role;
			task->acl = polstate->kernel_role->root_label;
#ifdef CONFIG_GRKERNSEC_ACL_HIDEKERN
			task->acl->mode &= ~GR_PROCFIND;
#endif
		}
	} while_each_thread(task2, task);
	read_unlock(&grsec_exec_file_lock);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	return 0;
}
