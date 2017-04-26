#include <linux/kernel.h>
#include <linux/gracl.h>
#include <linux/compat.h>
#include <linux/gracl_compat.h>

#include <asm/uaccess.h>

int copy_gr_arg_wrapper_compat(const char *buf, struct gr_arg_wrapper *uwrap)
{
	struct gr_arg_wrapper_compat uwrapcompat;

        if (copy_from_user(&uwrapcompat, buf, sizeof(uwrapcompat)))
                return -EFAULT;

        if ((uwrapcompat.version != GRSECURITY_VERSION) ||
	    (uwrapcompat.size != sizeof(struct gr_arg_compat)))  
                return -EINVAL;

	uwrap->arg = compat_ptr(uwrapcompat.arg);
	uwrap->version = uwrapcompat.version;
	uwrap->size = sizeof(struct gr_arg);

        return 0;
}

int copy_gr_arg_compat(const struct gr_arg __user *buf, struct gr_arg *arg)
{
	struct gr_arg_compat argcompat;

        if (copy_from_user(&argcompat, buf, sizeof(argcompat)))
                return -EFAULT;

	arg->role_db.r_table = compat_ptr(argcompat.role_db.r_table);
	arg->role_db.num_pointers = argcompat.role_db.num_pointers;
	arg->role_db.num_roles = argcompat.role_db.num_roles;
	arg->role_db.num_domain_children = argcompat.role_db.num_domain_children;
	arg->role_db.num_subjects = argcompat.role_db.num_subjects;
	arg->role_db.num_objects = argcompat.role_db.num_objects;

	memcpy(&arg->pw, &argcompat.pw, sizeof(arg->pw));
	memcpy(&arg->salt, &argcompat.salt, sizeof(arg->salt));
	memcpy(&arg->sum, &argcompat.sum, sizeof(arg->sum));
	memcpy(&arg->sp_role, &argcompat.sp_role, sizeof(arg->sp_role));
	arg->sprole_pws = compat_ptr(argcompat.sprole_pws);
	arg->segv_device = argcompat.segv_device;
	arg->segv_inode = argcompat.segv_inode;
	arg->segv_uid = argcompat.segv_uid;
	arg->num_sprole_pws = argcompat.num_sprole_pws;
	arg->mode = argcompat.mode;

	return 0;
}

int copy_acl_object_label_compat(struct acl_object_label *obj, const struct acl_object_label *userp)
{
	struct acl_object_label_compat objcompat;

	if (copy_from_user(&objcompat, userp, sizeof(objcompat)))
                return -EFAULT;

	obj->filename = compat_ptr(objcompat.filename);
	obj->inode = objcompat.inode;
	obj->device = objcompat.device;
	obj->mode = objcompat.mode;

	obj->nested = compat_ptr(objcompat.nested);
	obj->globbed = compat_ptr(objcompat.globbed);

	obj->prev = compat_ptr(objcompat.prev);
	obj->next = compat_ptr(objcompat.next);

	return 0;
}

int copy_acl_subject_label_compat(struct acl_subject_label *subj, const struct acl_subject_label *userp)
{
	unsigned int i;
	struct acl_subject_label_compat subjcompat;

	if (copy_from_user(&subjcompat, userp, sizeof(subjcompat)))
                return -EFAULT;

	subj->filename = compat_ptr(subjcompat.filename);
	subj->inode = subjcompat.inode;
	subj->device = subjcompat.device;
	subj->mode = subjcompat.mode;
	subj->cap_mask = subjcompat.cap_mask;
	subj->cap_lower = subjcompat.cap_lower;
	subj->cap_invert_audit = subjcompat.cap_invert_audit;

	for (i = 0; i < GR_NLIMITS; i++) {
		if (subjcompat.res[i].rlim_cur == COMPAT_RLIM_INFINITY)
			subj->res[i].rlim_cur = RLIM_INFINITY;
		else
			subj->res[i].rlim_cur = subjcompat.res[i].rlim_cur;
		if (subjcompat.res[i].rlim_max == COMPAT_RLIM_INFINITY)
			subj->res[i].rlim_max = RLIM_INFINITY;
		else
			subj->res[i].rlim_max = subjcompat.res[i].rlim_max;
	}
	subj->resmask = subjcompat.resmask;

	subj->user_trans_type = subjcompat.user_trans_type;
	subj->group_trans_type = subjcompat.group_trans_type;
	subj->user_transitions = compat_ptr(subjcompat.user_transitions);
	subj->group_transitions = compat_ptr(subjcompat.group_transitions);
	subj->user_trans_num = subjcompat.user_trans_num;
	subj->group_trans_num = subjcompat.group_trans_num;

	memcpy(&subj->sock_families, &subjcompat.sock_families, sizeof(subj->sock_families));
	memcpy(&subj->ip_proto, &subjcompat.ip_proto, sizeof(subj->ip_proto));
	subj->ip_type = subjcompat.ip_type;
	subj->ips = compat_ptr(subjcompat.ips);
	subj->ip_num = subjcompat.ip_num;
	subj->inaddr_any_override = subjcompat.inaddr_any_override;

	subj->crashes = subjcompat.crashes;
	subj->expires = subjcompat.expires;

	subj->parent_subject = compat_ptr(subjcompat.parent_subject);
	subj->hash = compat_ptr(subjcompat.hash);
	subj->prev = compat_ptr(subjcompat.prev);
	subj->next = compat_ptr(subjcompat.next);

	subj->obj_hash = compat_ptr(subjcompat.obj_hash);
	subj->obj_hash_size = subjcompat.obj_hash_size;
	subj->pax_flags = subjcompat.pax_flags;

	return 0;
}

int copy_acl_role_label_compat(struct acl_role_label *role, const struct acl_role_label *userp)
{
	struct acl_role_label_compat rolecompat;

	if (copy_from_user(&rolecompat, userp, sizeof(rolecompat)))
                return -EFAULT;

	role->rolename = compat_ptr(rolecompat.rolename);
	role->uidgid = rolecompat.uidgid;
	role->roletype = rolecompat.roletype;

	role->auth_attempts = rolecompat.auth_attempts;
	role->expires = rolecompat.expires;

	role->root_label = compat_ptr(rolecompat.root_label);
	role->hash = compat_ptr(rolecompat.hash);

	role->prev = compat_ptr(rolecompat.prev);
	role->next = compat_ptr(rolecompat.next);

	role->transitions = compat_ptr(rolecompat.transitions);
	role->allowed_ips = compat_ptr(rolecompat.allowed_ips);
	role->domain_children = compat_ptr(rolecompat.domain_children);
	role->domain_child_num = rolecompat.domain_child_num;

	role->umask = rolecompat.umask;

	role->subj_hash = compat_ptr(rolecompat.subj_hash);
	role->subj_hash_size = rolecompat.subj_hash_size;

	return 0;
}

int copy_role_allowed_ip_compat(struct role_allowed_ip *roleip, const struct role_allowed_ip *userp)
{
	struct role_allowed_ip_compat roleip_compat;

	if (copy_from_user(&roleip_compat, userp, sizeof(roleip_compat)))
                return -EFAULT;

	roleip->addr = roleip_compat.addr;
	roleip->netmask = roleip_compat.netmask;

	roleip->prev = compat_ptr(roleip_compat.prev);
	roleip->next = compat_ptr(roleip_compat.next);

	return 0;
}

int copy_role_transition_compat(struct role_transition *trans, const struct role_transition *userp)
{
	struct role_transition_compat trans_compat;

	if (copy_from_user(&trans_compat, userp, sizeof(trans_compat)))
                return -EFAULT;

	trans->rolename = compat_ptr(trans_compat.rolename);

	trans->prev = compat_ptr(trans_compat.prev);
	trans->next = compat_ptr(trans_compat.next);

	return 0;

}

int copy_gr_hash_struct_compat(struct gr_hash_struct *hash, const struct gr_hash_struct *userp)
{
	struct gr_hash_struct_compat hash_compat;

	if (copy_from_user(&hash_compat, userp, sizeof(hash_compat)))
                return -EFAULT;

	hash->table = compat_ptr(hash_compat.table);
	hash->nametable = compat_ptr(hash_compat.nametable);
	hash->first = compat_ptr(hash_compat.first);

	hash->table_size = hash_compat.table_size;
	hash->used_size = hash_compat.used_size;

	hash->type = hash_compat.type;

	return 0;
}

int copy_pointer_from_array_compat(void *ptr, unsigned long idx, const void *userp)
{
	compat_uptr_t ptrcompat;

	if (copy_from_user(&ptrcompat, userp + (idx * sizeof(ptrcompat)), sizeof(ptrcompat)))
                return -EFAULT;

	*(void **)ptr = compat_ptr(ptrcompat);

	return 0;
}

int copy_acl_ip_label_compat(struct acl_ip_label *ip, const struct acl_ip_label *userp)
{
	struct acl_ip_label_compat ip_compat;

	if (copy_from_user(&ip_compat, userp, sizeof(ip_compat)))
                return -EFAULT;

	ip->iface = compat_ptr(ip_compat.iface);
	ip->addr = ip_compat.addr;
	ip->netmask = ip_compat.netmask;
	ip->low = ip_compat.low;
	ip->high = ip_compat.high;
	ip->mode = ip_compat.mode;
	ip->type = ip_compat.type;

	memcpy(&ip->proto, &ip_compat.proto, sizeof(ip->proto));

	ip->prev = compat_ptr(ip_compat.prev);
	ip->next = compat_ptr(ip_compat.next);

	return 0;
}

int copy_sprole_pw_compat(struct sprole_pw *pw, unsigned long idx, const struct sprole_pw *userp)
{
	struct sprole_pw_compat pw_compat;

	if (copy_from_user(&pw_compat, (const void *)userp + (sizeof(pw_compat) * idx), sizeof(pw_compat)))
                return -EFAULT;

	pw->rolename = compat_ptr(pw_compat.rolename);
	memcpy(&pw->salt, pw_compat.salt, sizeof(pw->salt));
	memcpy(&pw->sum, pw_compat.sum, sizeof(pw->sum));

	return 0;
}

size_t get_gr_arg_wrapper_size_compat(void)
{
	return sizeof(struct gr_arg_wrapper_compat);
}

