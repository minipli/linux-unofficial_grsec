/*
 *	gradm match for netfilter
 *	Copyright (c) Zbigniew Krzystolik, 2010
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either version
 *	2 or 3 as published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/grsecurity.h>
#include <linux/netfilter/xt_gradm.h>

static bool
gradm_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_gradm_mtinfo *info = par->matchinfo;
	bool retval = false;
	if (gr_acl_is_enabled())
		retval = true;
	return retval ^ info->invflags;
}

static struct xt_match gradm_mt_reg __read_mostly = {
		.name       = "gradm",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.match      = gradm_mt,
		.matchsize  = XT_ALIGN(sizeof(struct xt_gradm_mtinfo)),
		.me         = THIS_MODULE,
};

static int __init gradm_mt_init(void)
{
	return xt_register_match(&gradm_mt_reg);
}

static void __exit gradm_mt_exit(void)
{
	xt_unregister_match(&gradm_mt_reg);
}

module_init(gradm_mt_init);
module_exit(gradm_mt_exit);
MODULE_AUTHOR("Zbigniew Krzystolik <zbyniu@destrukcja.pl>");
MODULE_DESCRIPTION("Xtables: Grsecurity RBAC match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_gradm");
MODULE_ALIAS("ip6t_gradm");
