/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_NAT_H
#define __NET_TC_NAT_H

#include <linux/types.h>
#include <net/act_api.h>

struct tcf_nat {
	struct tc_action common;

	__be32 old_addr;
	__be32 new_addr;
	__be32 mask;
	u32 flags;
};

#define to_tcf_nat(a) ((struct tcf_nat *)a)

static inline bool is_tcf_nat(const struct tc_action *act)
{
#if defined(CONFIG_NET_CLS_ACT) && IS_ENABLED(CONFIG_NET_ACT_NAT)
	if (act->ops && act->ops->id == TCA_ID_NAT)
		return true;
#endif
	return false;
}

static inline __be32 tcf_nat_old_addr(const struct tc_action *a)
{
	return to_tcf_nat(a)->old_addr;
}

static inline __be32 tcf_nat_new_addr(const struct tc_action *a)
{
	return to_tcf_nat(a)->new_addr;
}

static inline __be32 tcf_nat_mask(const struct tc_action *a)
{
	return to_tcf_nat(a)->mask;
}

static inline u32 tcf_nat_flags(const struct tc_action *a)
{
	return to_tcf_nat(a)->flags;
}

#endif /* __NET_TC_NAT_H */
