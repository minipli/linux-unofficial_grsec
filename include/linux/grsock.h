#ifndef __GRSOCK_H
#define __GRSOCK_H

extern void gr_attach_curr_ip(const struct sock *sk);
extern int gr_handle_sock_all(const int family, const int type,
			      const int protocol);
extern int gr_handle_sock_server(const struct sockaddr *sck);
extern int gr_handle_sock_server_other(const struct sock *sck);
extern int gr_handle_sock_client(const struct sockaddr *sck);
extern int gr_search_connect(struct socket * sock,
			     struct sockaddr_in * addr);
extern int gr_search_bind(struct socket * sock,
			  struct sockaddr_in * addr);
extern int gr_search_listen(struct socket * sock);
extern int gr_search_accept(struct socket * sock);
extern int gr_search_socket(const int domain, const int type,
			    const int protocol);

#endif
