#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/gracl.h>
#include <linux/grsecurity.h>
#include <linux/grinternal.h>

#define GR_BIND			0x01
#define GR_CONNECT		0x02
#define GR_INVERT		0x04
#define GR_BINDOVERRIDE		0x08
#define GR_CONNECTOVERRIDE	0x10
#define GR_SOCK_FAMILY		0x20

static const char * gr_protocols[IPPROTO_MAX] = {
	"ip", "icmp", "igmp", "ggp", "ipencap", "st", "tcp", "cbt",
	"egp", "igp", "bbn-rcc", "nvp", "pup", "argus", "emcon", "xnet",
	"chaos", "udp", "mux", "dcn", "hmp", "prm", "xns-idp", "trunk-1",
	"trunk-2", "leaf-1", "leaf-2", "rdp", "irtp", "iso-tp4", "netblt", "mfe-nsp",
	"merit-inp", "sep", "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++",
	"il", "ipv6", "sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre",
	"mhrp", "bna", "ipv6-crypt", "ipv6-auth", "i-nlsp", "swipe", "narp", "mobile",
	"tlsp", "skip", "ipv6-icmp", "ipv6-nonxt", "ipv6-opts", "unknown:61", "cftp", "unknown:63",
	"sat-expak", "kryptolan", "rvd", "ippc", "unknown:68", "sat-mon", "visa", "ipcv",
	"cpnx", "cphb", "wsn", "pvp", "br-sat-mon", "sun-nd", "wb-mon", "wb-expak", 
	"iso-ip", "vmtp", "secure-vmtp", "vines", "ttp", "nfsnet-igp", "dgp", "tcf", 
	"eigrp", "ospf", "sprite-rpc", "larp", "mtp", "ax.25", "ipip", "micp",
	"scc-sp", "etherip", "encap", "unknown:99", "gmtp", "ifmp", "pnni", "pim",
	"aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer", "ipx-in-ip",
	"vrrp", "pgm", "unknown:114", "l2tp", "ddx", "iatp", "stp", "srp",
	"uti", "smp", "sm", "ptp", "isis", "fire", "crtp", "crdup",
	"sscopmce", "iplt", "sps", "pipe", "sctp", "fc", "unkown:134", "unknown:135",
	"unknown:136", "unknown:137", "unknown:138", "unknown:139", "unknown:140", "unknown:141", "unknown:142", "unknown:143",
	"unknown:144", "unknown:145", "unknown:146", "unknown:147", "unknown:148", "unknown:149", "unknown:150", "unknown:151",
	"unknown:152", "unknown:153", "unknown:154", "unknown:155", "unknown:156", "unknown:157", "unknown:158", "unknown:159",
	"unknown:160", "unknown:161", "unknown:162", "unknown:163", "unknown:164", "unknown:165", "unknown:166", "unknown:167",
	"unknown:168", "unknown:169", "unknown:170", "unknown:171", "unknown:172", "unknown:173", "unknown:174", "unknown:175",
	"unknown:176", "unknown:177", "unknown:178", "unknown:179", "unknown:180", "unknown:181", "unknown:182", "unknown:183",
	"unknown:184", "unknown:185", "unknown:186", "unknown:187", "unknown:188", "unknown:189", "unknown:190", "unknown:191",
	"unknown:192", "unknown:193", "unknown:194", "unknown:195", "unknown:196", "unknown:197", "unknown:198", "unknown:199",
	"unknown:200", "unknown:201", "unknown:202", "unknown:203", "unknown:204", "unknown:205", "unknown:206", "unknown:207",
	"unknown:208", "unknown:209", "unknown:210", "unknown:211", "unknown:212", "unknown:213", "unknown:214", "unknown:215",
	"unknown:216", "unknown:217", "unknown:218", "unknown:219", "unknown:220", "unknown:221", "unknown:222", "unknown:223",
	"unknown:224", "unknown:225", "unknown:226", "unknown:227", "unknown:228", "unknown:229", "unknown:230", "unknown:231",
	"unknown:232", "unknown:233", "unknown:234", "unknown:235", "unknown:236", "unknown:237", "unknown:238", "unknown:239",
	"unknown:240", "unknown:241", "unknown:242", "unknown:243", "unknown:244", "unknown:245", "unknown:246", "unknown:247",
	"unknown:248", "unknown:249", "unknown:250", "unknown:251", "unknown:252", "unknown:253", "unknown:254", "unknown:255",
	};

static const char * gr_socktypes[SOCK_MAX] = {
	"unknown:0", "stream", "dgram", "raw", "rdm", "seqpacket", "unknown:6", 
	"unknown:7", "unknown:8", "unknown:9", "packet"
	};

static const char * gr_sockfamilies[AF_MAX] = {
	"unspec", "unix", "inet", "ax25", "ipx", "appletalk", "netrom", "bridge", "atmpvc", "x25",
	"inet6", "rose", "decnet", "netbeui", "security", "key", "netlink", "packet", "ash",
	"econet", "atmsvc", "rds", "sna", "irda", "ppox", "wanpipe", "llc", "ib", "mpls", "can",
	"tipc", "bluetooth", "iucv", "rxrpc", "isdn", "phonet", "ieee802154", "ciaf", "alg",
	"nfc", "vsock", "kcm", "qipcrtr"
	};

const char *
gr_proto_to_name(unsigned char proto)
{
	return gr_protocols[proto];
}

const char *
gr_socktype_to_name(unsigned char type)
{
	return gr_socktypes[type];
}

const char *
gr_sockfamily_to_name(unsigned char family)
{
	return gr_sockfamilies[family];
}

extern const struct net_proto_family __rcu *net_families[NPROTO] __read_mostly;

int
gr_search_socket(const int domain, const int type, const int protocol)
{
	struct acl_subject_label *curr;
	const struct cred *cred = current_cred();

	if (unlikely(!gr_acl_is_enabled()))
		goto exit;

	if ((domain < 0) || (type < 0) || (protocol < 0) ||
	    (domain >= AF_MAX) || (type >= SOCK_MAX) || (protocol >= IPPROTO_MAX))
		goto exit;	// let the kernel handle it

	curr = current->acl;

	if (curr->sock_families[domain / 32] & (1U << (domain % 32))) {
		/* the family is allowed, if this is PF_INET allow it only if
		   the extra sock type/protocol checks pass */
		if (domain == PF_INET)
			goto inet_check;
		goto exit;
	} else {
		if (curr->mode & (GR_LEARN | GR_INHERITLEARN)) {
			__u32 fakeip = 0;
			security_learn(GR_IP_LEARN_MSG, current->role->rolename,
				       current->role->roletype, GR_GLOBAL_UID(cred->uid),
				       GR_GLOBAL_GID(cred->gid), current->exec_file ?
				       gr_to_filename(current->exec_file->f_path.dentry,
				       current->exec_file->f_path.mnt) :
				       curr->filename, curr->filename,
				       &fakeip, domain, 0, 0, GR_SOCK_FAMILY,
				       &current->signal->saved_ip);
			goto exit;
		}
		goto exit_fail;
	}

inet_check:
	/* the rest of this checking is for IPv4 only */
	if (!curr->ips)
		goto exit;

	if ((curr->ip_type & (1U << type)) &&
	    (curr->ip_proto[protocol / 32] & (1U << (protocol % 32))))
		goto exit;

	if (curr->mode & (GR_LEARN | GR_INHERITLEARN)) {
		/* we don't place acls on raw sockets , and sometimes
		   dgram/ip sockets are opened for ioctl and not
		   bind/connect, so we'll fake a bind learn log */
		if (type == SOCK_RAW || type == SOCK_PACKET) {
			__u32 fakeip = 0;
			security_learn(GR_IP_LEARN_MSG, current->role->rolename,
				       current->role->roletype, GR_GLOBAL_UID(cred->uid),
				       GR_GLOBAL_GID(cred->gid), current->exec_file ?
				       gr_to_filename(current->exec_file->f_path.dentry,
				       current->exec_file->f_path.mnt) :
				       curr->filename, curr->filename,
				       &fakeip, 0, type,
				       protocol, GR_CONNECT, &current->signal->saved_ip);
		} else if ((type == SOCK_DGRAM) && (protocol == IPPROTO_IP)) {
			__u32 fakeip = 0;
			security_learn(GR_IP_LEARN_MSG, current->role->rolename,
				       current->role->roletype, GR_GLOBAL_UID(cred->uid),
				       GR_GLOBAL_GID(cred->gid), current->exec_file ?
				       gr_to_filename(current->exec_file->f_path.dentry,
				       current->exec_file->f_path.mnt) :
				       curr->filename, curr->filename,
				       &fakeip, 0, type,
				       protocol, GR_BIND, &current->signal->saved_ip);
		}
		/* we'll log when they use connect or bind */
		goto exit;
	}

exit_fail:
	if (domain == PF_INET)
		gr_log_str3(GR_DONT_AUDIT, GR_SOCK_MSG, gr_sockfamily_to_name(domain), 
			    gr_socktype_to_name(type), gr_proto_to_name(protocol));
	else if (rcu_access_pointer(net_families[domain]) != NULL)
		gr_log_str2_int(GR_DONT_AUDIT, GR_SOCK_NOINET_MSG, gr_sockfamily_to_name(domain), 
			    gr_socktype_to_name(type), protocol);

	return 0;
exit:
	return 1;
}

int check_ip_policy(struct acl_ip_label *ip, __u32 ip_addr, __u16 ip_port, __u8 protocol, const int mode, const int type, __u32 our_addr, __u32 our_netmask)
{
	if ((ip->mode & mode) &&
	    (ip_port >= ip->low) &&
	    (ip_port <= ip->high) &&
	    ((ntohl(ip_addr) & our_netmask) ==
	     (ntohl(our_addr) & our_netmask))
	    && (ip->proto[protocol / 32] & (1U << (protocol % 32)))
	    && (ip->type & (1U << type))) {
		if (ip->mode & GR_INVERT)
			return 2; // specifically denied
		else
			return 1; // allowed
	}

	return 0; // not specifically allowed, may continue parsing
}

static int
gr_search_connectbind(const int full_mode, struct sock *sk,
		      struct sockaddr_in *addr, const int type)
{
	char iface[IFNAMSIZ] = {0};
	struct acl_subject_label *curr;
	struct acl_ip_label *ip;
	struct inet_sock *isk;
	struct net_device *dev;
	struct in_device *idev;
	unsigned long i;
	int ret;
	int mode = full_mode & (GR_BIND | GR_CONNECT);
	__u32 ip_addr = 0;
	__u32 our_addr;
	__u32 our_netmask;
	char *p;
	__u16 ip_port = 0;
	const struct cred *cred = current_cred();

	if (unlikely(!gr_acl_is_enabled() || sk->sk_family != PF_INET))
		return 0;

	curr = current->acl;
	isk = inet_sk(sk);

	/* INADDR_ANY overriding for binds, inaddr_any_override is already in network order */
	if ((full_mode & GR_BINDOVERRIDE) && addr->sin_addr.s_addr == htonl(INADDR_ANY) && curr->inaddr_any_override != 0)
		addr->sin_addr.s_addr = curr->inaddr_any_override;
	if ((full_mode & GR_CONNECT) && isk->inet_saddr == htonl(INADDR_ANY) && curr->inaddr_any_override != 0) {
		struct sockaddr_in saddr;
		int err;

		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = curr->inaddr_any_override;
		saddr.sin_port = isk->inet_sport;

		err = security_socket_bind(sk->sk_socket, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
		if (err)
			return err;

		err = sk->sk_socket->ops->bind(sk->sk_socket, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
		if (err)
			return err;
	}

	if (!curr->ips)
		return 0;

	ip_addr = addr->sin_addr.s_addr;
	ip_port = ntohs(addr->sin_port);

	if (curr->mode & (GR_LEARN | GR_INHERITLEARN)) {
		security_learn(GR_IP_LEARN_MSG, current->role->rolename,
			       current->role->roletype, GR_GLOBAL_UID(cred->uid),
			       GR_GLOBAL_GID(cred->gid), current->exec_file ?
			       gr_to_filename(current->exec_file->f_path.dentry,
			       current->exec_file->f_path.mnt) :
			       curr->filename, curr->filename,
			       &ip_addr, ip_port, type,
			       sk->sk_protocol, mode, &current->signal->saved_ip);
		return 0;
	}

	for (i = 0; i < curr->ip_num; i++) {
		ip = *(curr->ips + i);
		if (ip->iface != NULL) {
			strncpy(iface, ip->iface, IFNAMSIZ - 1);
			p = strchr(iface, ':');
			if (p != NULL)
				*p = '\0';
			dev = dev_get_by_name(sock_net(sk), iface);
			if (dev == NULL)
				continue;
			idev = in_dev_get(dev);
			if (idev == NULL) {
				dev_put(dev);
				continue;
			}
			rcu_read_lock();
			for_ifa(idev) {
				if (!strcmp(ip->iface, ifa->ifa_label)) {
					our_addr = ifa->ifa_address;
					our_netmask = 0xffffffff;
					ret = check_ip_policy(ip, ip_addr, ip_port, sk->sk_protocol, mode, type, our_addr, our_netmask);
					if (ret == 1) {
						rcu_read_unlock();
						in_dev_put(idev);
						dev_put(dev);
						return 0;
					} else if (ret == 2) {
						rcu_read_unlock();
						in_dev_put(idev);
						dev_put(dev);
						goto denied;
					}
				}
			} endfor_ifa(idev);
			rcu_read_unlock();
			in_dev_put(idev);
			dev_put(dev);
		} else {
			our_addr = ip->addr;
			our_netmask = ip->netmask;
			ret = check_ip_policy(ip, ip_addr, ip_port, sk->sk_protocol, mode, type, our_addr, our_netmask);
			if (ret == 1)
				return 0;
			else if (ret == 2)
				goto denied;
		}
	}

denied:
	if (mode == GR_BIND)
		gr_log_int5_str2(GR_DONT_AUDIT, GR_BIND_ACL_MSG, &ip_addr, ip_port, gr_socktype_to_name(type), gr_proto_to_name(sk->sk_protocol));
	else if (mode == GR_CONNECT)
		gr_log_int5_str2(GR_DONT_AUDIT, GR_CONNECT_ACL_MSG, &ip_addr, ip_port, gr_socktype_to_name(type), gr_proto_to_name(sk->sk_protocol));

	return -EACCES;
}

int
gr_search_connect(struct socket *sock, struct sockaddr_in *addr)
{
	/* always allow disconnection of dgram sockets with connect */
	if (addr->sin_family == AF_UNSPEC)
		return 0;
	return gr_search_connectbind(GR_CONNECT | GR_CONNECTOVERRIDE, sock->sk, addr, sock->type);
}

int
gr_search_bind(struct socket *sock, struct sockaddr_in *addr)
{
	return gr_search_connectbind(GR_BIND | GR_BINDOVERRIDE, sock->sk, addr, sock->type);
}

int gr_search_listen(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sockaddr_in addr;

	addr.sin_addr.s_addr = inet_sk(sk)->inet_saddr;
	addr.sin_port = inet_sk(sk)->inet_sport;

	return gr_search_connectbind(GR_BIND | GR_CONNECTOVERRIDE, sock->sk, &addr, sock->type);
}

int gr_search_accept(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sockaddr_in addr;

	addr.sin_addr.s_addr = inet_sk(sk)->inet_saddr;
	addr.sin_port = inet_sk(sk)->inet_sport;

	return gr_search_connectbind(GR_BIND | GR_CONNECTOVERRIDE, sock->sk, &addr, sock->type);
}

int
gr_search_udp_sendmsg(struct sock *sk, struct sockaddr_in *addr)
{
	if (addr)
		return gr_search_connectbind(GR_CONNECT, sk, addr, SOCK_DGRAM);
	else {
		struct sockaddr_in sin;
		const struct inet_sock *inet = inet_sk(sk);

		sin.sin_addr.s_addr = inet->inet_daddr;
		sin.sin_port = inet->inet_dport;

		return gr_search_connectbind(GR_CONNECT | GR_CONNECTOVERRIDE, sk, &sin, SOCK_DGRAM);
	}
}

int
gr_search_udp_recvmsg(struct sock *sk, const struct sk_buff *skb)
{
	struct sockaddr_in sin;

	if (unlikely(skb->len < sizeof (struct udphdr)))
		return 0;	// skip this packet

	sin.sin_addr.s_addr = ip_hdr(skb)->saddr;
	sin.sin_port = udp_hdr(skb)->source;

	return gr_search_connectbind(GR_CONNECT | GR_CONNECTOVERRIDE, sk, &sin, SOCK_DGRAM);
}
