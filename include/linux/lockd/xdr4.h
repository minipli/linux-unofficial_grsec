/*
 * linux/include/linux/lockd/xdr4.h
 *
 * XDR types for the NLM protocol
 *
 * Copyright (C) 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef LOCKD_XDR4_H
#define LOCKD_XDR4_H

#include <linux/fs.h>
#include <linux/nfs.h>
#include <linux/sunrpc/xdr.h>
#include <linux/lockd/xdr.h>

/* error codes new to NLMv4 */
#define	nlm4_deadlock		cpu_to_be32(NLM_DEADLCK)
#define	nlm4_rofs		cpu_to_be32(NLM_ROFS)
#define	nlm4_stale_fh		cpu_to_be32(NLM_STALE_FH)
#define	nlm4_fbig		cpu_to_be32(NLM_FBIG)
#define	nlm4_failed		cpu_to_be32(NLM_FAILED)



int	nlm4svc_decode_testargs(void *, __be32 *, void *);
int	nlm4svc_encode_testres(void *, __be32 *, void *);
int	nlm4svc_decode_lockargs(void *, __be32 *, void *);
int	nlm4svc_decode_cancargs(void *, __be32 *, void *);
int	nlm4svc_decode_unlockargs(void *, __be32 *, void *);
int	nlm4svc_encode_res(void *, __be32 *, void *);
int	nlm4svc_decode_res(void *, __be32 *, void *);
int	nlm4svc_encode_void(void *, __be32 *, void *);
int	nlm4svc_decode_void(void *, __be32 *, void *);
int	nlm4svc_decode_shareargs(void *, __be32 *, void *);
int	nlm4svc_encode_shareres(void *, __be32 *, void *);
int	nlm4svc_decode_notify(void *, __be32 *, void *);
int	nlm4svc_decode_reboot(void *, __be32 *, void *);
/*
int	nlmclt_encode_testargs(void *, u32 *, void *);
int	nlmclt_encode_lockargs(void *, u32 *, void *);
int	nlmclt_encode_cancargs(void *, u32 *, void *);
int	nlmclt_encode_unlockargs(void *, u32 *, void *);
 */
extern const struct rpc_version nlm_version4;

#endif /* LOCKD_XDR4_H */
