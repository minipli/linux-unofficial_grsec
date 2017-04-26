#ifndef GR_ACL_COMPAT_H
#define GR_ACL_COMPAT_H

#include <linux/resource.h>
#include <asm/resource.h>

struct sprole_pw_compat {
	compat_uptr_t rolename;
	unsigned char salt[GR_SALT_LEN];
	unsigned char sum[GR_SHA_LEN];
};

struct gr_hash_struct_compat {
	compat_uptr_t table;
	compat_uptr_t nametable;
	compat_uptr_t first;
	__u32 table_size;
	__u32 used_size;
	int type;
};

struct acl_subject_label_compat {
	compat_uptr_t filename;
	compat_u64 inode;
	__u32 device;
	__u32 mode;
	kernel_cap_t cap_mask;
	kernel_cap_t cap_lower;
	kernel_cap_t cap_invert_audit;

	struct compat_rlimit res[GR_NLIMITS];
	__u32 resmask;

	__u8 user_trans_type;
	__u8 group_trans_type;
	compat_uptr_t user_transitions;
	compat_uptr_t group_transitions;
	__u16 user_trans_num;
	__u16 group_trans_num;

	__u32 sock_families[2];
	__u32 ip_proto[8];
	__u32 ip_type;
	compat_uptr_t ips;
	__u32 ip_num;
	__u32 inaddr_any_override;

	__u32 crashes;
	compat_ulong_t expires;

	compat_uptr_t parent_subject;
	compat_uptr_t hash;
	compat_uptr_t prev;
	compat_uptr_t next;

	compat_uptr_t obj_hash;
	__u32 obj_hash_size;
	__u16 pax_flags;
};

struct role_allowed_ip_compat {
	__u32 addr;
	__u32 netmask;

	compat_uptr_t prev;
	compat_uptr_t next;
};

struct role_transition_compat {
	compat_uptr_t rolename;

	compat_uptr_t prev;
	compat_uptr_t next;
};

struct acl_role_label_compat {
	compat_uptr_t rolename;
	uid_t uidgid;
	__u16 roletype;

	__u16 auth_attempts;
	compat_ulong_t expires;

	compat_uptr_t root_label;
	compat_uptr_t hash;

	compat_uptr_t prev;
	compat_uptr_t next;

	compat_uptr_t transitions;
	compat_uptr_t allowed_ips;
	compat_uptr_t domain_children;
	__u16 domain_child_num;

	umode_t umask;

	compat_uptr_t subj_hash;
	__u32 subj_hash_size;
};

struct user_acl_role_db_compat {
	compat_uptr_t r_table;
	__u32 num_pointers;
	__u32 num_roles;
	__u32 num_domain_children;
	__u32 num_subjects;
	__u32 num_objects;
};

struct acl_object_label_compat {
	compat_uptr_t filename;
	compat_u64 inode;
	__u32 device;
	__u32 mode;

	compat_uptr_t nested;
	compat_uptr_t globbed;

	compat_uptr_t prev;
	compat_uptr_t next;
};

struct acl_ip_label_compat {
	compat_uptr_t iface;
	__u32 addr;
	__u32 netmask;
	__u16 low, high;
	__u8 mode;
	__u32 type;
	__u32 proto[8];

	compat_uptr_t prev;
	compat_uptr_t next;
};

struct gr_arg_compat {
	struct user_acl_role_db_compat role_db;
	unsigned char pw[GR_PW_LEN];
	unsigned char salt[GR_SALT_LEN];
	unsigned char sum[GR_SHA_LEN];
	unsigned char sp_role[GR_SPROLE_LEN];
	compat_uptr_t sprole_pws;
	__u32 segv_device;
	compat_u64 segv_inode;
	uid_t segv_uid;
	__u16 num_sprole_pws;
	__u16 mode;
};

struct gr_arg_wrapper_compat {
	compat_uptr_t arg;
	__u32 version;
	__u32 size;
};

#endif
