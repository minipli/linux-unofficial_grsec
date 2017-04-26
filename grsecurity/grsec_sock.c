#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>
#include <linux/gracl.h>

extern int gr_search_udp_recvmsg(struct sock *sk, const struct sk_buff *skb);
extern int gr_search_udp_sendmsg(struct sock *sk, struct sockaddr_in *addr);

EXPORT_SYMBOL_GPL(gr_search_udp_recvmsg);
EXPORT_SYMBOL_GPL(gr_search_udp_sendmsg);

#ifdef CONFIG_UNIX_MODULE
EXPORT_SYMBOL_GPL(gr_acl_handle_unix);
EXPORT_SYMBOL_GPL(gr_acl_handle_mknod);
EXPORT_SYMBOL_GPL(gr_handle_chroot_unix);
EXPORT_SYMBOL_GPL(gr_handle_create);
#endif

#ifdef CONFIG_GRKERNSEC
#define gr_conn_table_size 32749
struct conn_table_entry {
	struct conn_table_entry *next;
	struct signal_struct *sig;
};

struct conn_table_entry *gr_conn_table[gr_conn_table_size];
DEFINE_SPINLOCK(gr_conn_table_lock);

extern const char * gr_socktype_to_name(unsigned char type);
extern const char * gr_proto_to_name(unsigned char proto);
extern const char * gr_sockfamily_to_name(unsigned char family);

static int 
conn_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, unsigned int size)
{
	return ((daddr + saddr + (sport << 8) + (dport << 16)) % size);
}

static int
conn_match(const struct signal_struct *sig, __u32 saddr, __u32 daddr, 
	   __u16 sport, __u16 dport)
{
	if (unlikely(sig->gr_saddr == saddr && sig->gr_daddr == daddr &&
		     sig->gr_sport == sport && sig->gr_dport == dport))
		return 1;
	else
		return 0;
}

static void gr_add_to_task_ip_table_nolock(struct signal_struct *sig, struct conn_table_entry *newent)
{
	struct conn_table_entry **match;
	unsigned int index;

	index = conn_hash(sig->gr_saddr, sig->gr_daddr, 
			  sig->gr_sport, sig->gr_dport, 
			  gr_conn_table_size);

	newent->sig = sig;
	
	match = &gr_conn_table[index];
	newent->next = *match;
	*match = newent;

	return;
}

static void gr_del_task_from_ip_table_nolock(struct signal_struct *sig)
{
	struct conn_table_entry *match, *last = NULL;
	unsigned int index;

	index = conn_hash(sig->gr_saddr, sig->gr_daddr, 
			  sig->gr_sport, sig->gr_dport, 
			  gr_conn_table_size);

	match = gr_conn_table[index];
	while (match && !conn_match(match->sig, 
		sig->gr_saddr, sig->gr_daddr, sig->gr_sport, 
		sig->gr_dport)) {
		last = match;
		match = match->next;
	}

	if (match) {
		if (last)
			last->next = match->next;
		else
			gr_conn_table[index] = NULL;
		kfree(match);
	}

	return;
}

static struct signal_struct * gr_lookup_task_ip_table(__u32 saddr, __u32 daddr,
					     __u16 sport, __u16 dport)
{
	struct conn_table_entry *match;
	unsigned int index;

	index = conn_hash(saddr, daddr, sport, dport, gr_conn_table_size);

	match = gr_conn_table[index];
	while (match && !conn_match(match->sig, saddr, daddr, sport, dport))
		match = match->next;

	if (match)
		return match->sig;
	else
		return NULL;
}

#endif

void gr_update_task_in_ip_table(const struct inet_sock *inet)
{
#ifdef CONFIG_GRKERNSEC
	struct signal_struct *sig = current->signal;
	struct conn_table_entry *newent;

	newent = kmalloc(sizeof(struct conn_table_entry), GFP_ATOMIC);
	if (newent == NULL)
		return;
	/* no bh lock needed since we are called with bh disabled */
	spin_lock(&gr_conn_table_lock);
	gr_del_task_from_ip_table_nolock(sig);
	sig->gr_saddr = inet->inet_rcv_saddr;
	sig->gr_daddr = inet->inet_daddr;
	sig->gr_sport = inet->inet_sport;
	sig->gr_dport = inet->inet_dport;
	gr_add_to_task_ip_table_nolock(sig, newent);
	spin_unlock(&gr_conn_table_lock);
#endif
	return;
}

void gr_del_task_from_ip_table(struct task_struct *task)
{
#ifdef CONFIG_GRKERNSEC
	spin_lock_bh(&gr_conn_table_lock);
	gr_del_task_from_ip_table_nolock(task->signal);
	spin_unlock_bh(&gr_conn_table_lock);
#endif
	return;
}

void
gr_attach_curr_ip(const struct sock *sk)
{
#ifdef CONFIG_GRKERNSEC
	struct signal_struct *p, *set;
	const struct inet_sock *inet = inet_sk(sk);	

	if (unlikely(sk->sk_protocol != IPPROTO_TCP))
		return;

	set = current->signal;

	spin_lock_bh(&gr_conn_table_lock);
	p = gr_lookup_task_ip_table(inet->inet_daddr, inet->inet_rcv_saddr,
				    inet->inet_dport, inet->inet_sport);
	if (unlikely(p != NULL)) {
		set->curr_ip = p->curr_ip;
		set->used_accept = 1;
		gr_del_task_from_ip_table_nolock(p);
		spin_unlock_bh(&gr_conn_table_lock);
		return;
	}
	spin_unlock_bh(&gr_conn_table_lock);

	set->curr_ip = inet->inet_daddr;
	set->used_accept = 1;
#endif
	return;
}

int
gr_handle_sock_all(const int family, const int type, const int protocol)
{
#ifdef CONFIG_GRKERNSEC_SOCKET_ALL
	if (grsec_enable_socket_all && in_group_p(grsec_socket_all_gid) &&
	    (family != AF_UNIX)) {
		if (family == AF_INET)
			gr_log_str3(GR_DONT_AUDIT, GR_SOCK_MSG, gr_sockfamily_to_name(family), gr_socktype_to_name(type), gr_proto_to_name(protocol));
		else
			gr_log_str2_int(GR_DONT_AUDIT, GR_SOCK_NOINET_MSG, gr_sockfamily_to_name(family), gr_socktype_to_name(type), protocol);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_sock_server(const struct sockaddr *sck)
{
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	if (grsec_enable_socket_server &&
	    in_group_p(grsec_socket_server_gid) &&
	    sck && (sck->sa_family != AF_UNIX) &&
	    (sck->sa_family != AF_LOCAL)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_BIND_MSG);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_sock_server_other(const struct sock *sck)
{
#ifdef CONFIG_GRKERNSEC_SOCKET_SERVER
	if (grsec_enable_socket_server &&
	    in_group_p(grsec_socket_server_gid) &&
	    sck && (sck->sk_family != AF_UNIX) &&
	    (sck->sk_family != AF_LOCAL)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_BIND_MSG);
		return -EACCES;
	}
#endif
	return 0;
}

int
gr_handle_sock_client(const struct sockaddr *sck)
{
#ifdef CONFIG_GRKERNSEC_SOCKET_CLIENT
	if (grsec_enable_socket_client && in_group_p(grsec_socket_client_gid) &&
	    sck && (sck->sa_family != AF_UNIX) &&
	    (sck->sa_family != AF_LOCAL)) {
		gr_log_noargs(GR_DONT_AUDIT, GR_CONNECT_MSG);
		return -EACCES;
	}
#endif
	return 0;
}
