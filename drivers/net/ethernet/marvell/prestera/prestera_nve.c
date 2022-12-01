// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_log.h"

static const struct rhashtable_params __prestera_l2tun_tep_ht_params = {
	.key_offset  = offsetof(struct prestera_l2tun_tep, key),
	.head_offset = offsetof(struct prestera_l2tun_tep, ht_node),
	.key_len     = sizeof(struct prestera_l2tun_tep_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_l2tun_tt_ht_params = {
	.key_offset  = offsetof(struct prestera_l2tun_tt, key),
	.head_offset = offsetof(struct prestera_l2tun_tt, ht_node),
	.key_len     = sizeof(struct prestera_l2tun_tt_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_l2tun_vp_hw_index_ht_params = {
	.key_offset  = offsetof(struct prestera_l2tun_vp, hw_tep_id),
	.head_offset = offsetof(struct prestera_l2tun_vp, hw_index_ht_node),
	.key_len     = sizeof(u32),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_l2tun_vp_ht_params = {
	.key_offset  = offsetof(struct prestera_l2tun_vp, key),
	.head_offset = offsetof(struct prestera_l2tun_vp, ht_node),
	.key_len     = sizeof(struct prestera_l2tun_vp_key),
	.automatic_shrinking = true,
};

struct prestera_l2tun_vp *
prestera_l2tun_vp_find(struct prestera_switch *sw,
		       struct prestera_l2tun_vp_key *key)
{
	struct prestera_l2tun_vp *o;

	o = rhashtable_lookup_fast(&sw->router->nve.l2tun_vp_ht, key,
				   __prestera_l2tun_vp_ht_params);

	return IS_ERR(o) ? NULL : o;
}

static void
__prestera_l2tun_vp_destroy(struct prestera_switch *sw,
			    struct prestera_l2tun_vp *o)
{
	/* Optional: Ensure that there are no more entries in FDB */
	WARN_ON(prestera_hw_fdb_flush_tep(sw, o->hw_tep_id,
					  PRESTERA_FDB_FLUSH_MODE_ALL));

	rhashtable_remove_fast(&sw->router->nve.l2tun_vp_hw_index_ht,
			       &o->hw_index_ht_node,
			       __prestera_l2tun_vp_hw_index_ht_params);
	rhashtable_remove_fast(&sw->router->nve.l2tun_vp_ht, &o->ht_node,
			       __prestera_l2tun_vp_ht_params);
	WARN_ON(prestera_hw_l2tun_tep_del(sw, o->hw_tep_id));
	kfree(o);
}

static struct prestera_l2tun_vp *
__prestera_l2tun_vp_create(struct prestera_switch *sw,
			   struct prestera_l2tun_vp_key *key)
{
	struct prestera_l2tun_vp *o;
	int err;

	o = kzalloc(sizeof(*o), GFP_KERNEL);
	if (!o)
		goto err_kzalloc;

	INIT_LIST_HEAD(&o->l2tun_tt_list);
	INIT_LIST_HEAD(&o->l2tun_tep_list);
	INIT_LIST_HEAD(&o->flood_domain_port_list);

	memcpy(&o->key, key, sizeof(*key));

	err = prestera_hw_l2tun_tep_create(sw, &o->hw_tep_id);
	if (err)
		goto err_hw_add;

	err = rhashtable_insert_fast(&sw->router->nve.l2tun_vp_ht,
				     &o->ht_node,
				     __prestera_l2tun_vp_ht_params);
	if (err)
		goto err_ht_insert;

	err = rhashtable_insert_fast(&sw->router->nve.l2tun_vp_hw_index_ht,
				     &o->hw_index_ht_node,
				     __prestera_l2tun_vp_hw_index_ht_params);
	if (err)
		goto err_hw_idx_ht_insert;

	return o;

err_hw_idx_ht_insert:
	rhashtable_remove_fast(&sw->router->nve.l2tun_vp_ht, &o->ht_node,
			       __prestera_l2tun_vp_ht_params);
err_ht_insert:
	WARN_ON(prestera_hw_l2tun_tep_del(sw, o->hw_tep_id));
err_hw_add:
	kfree(o);
err_kzalloc:
	return NULL;
}

struct prestera_l2tun_vp *
prestera_l2tun_vp_get(struct prestera_switch *sw,
		      struct prestera_l2tun_vp_key *key)
{
	struct prestera_l2tun_vp  *o;

	o = prestera_l2tun_vp_find(sw, key);
	if (o)
		return o;

	return __prestera_l2tun_vp_create(sw, key);
}

void prestera_l2tun_vp_put(struct prestera_switch *sw,
			   struct prestera_l2tun_vp *o)
{
	if (list_empty(&o->l2tun_tt_list) &&
	    list_empty(&o->l2tun_tep_list) &&
	    list_empty(&o->flood_domain_port_list))
		__prestera_l2tun_vp_destroy(sw, o);
}

struct prestera_l2tun_vp *
prestera_l2tun_vp_find_hw_index(struct prestera_switch *sw, u32 id)
{
	struct prestera_l2tun_vp *o;

	o = rhashtable_lookup_fast(&sw->router->nve.l2tun_vp_hw_index_ht, &id,
				   __prestera_l2tun_vp_hw_index_ht_params);

	return IS_ERR(o) ? NULL : o;
}

int prestera_l2tun_vp_util_fdb_set(struct prestera_switch *sw,
				   struct prestera_l2tun_vp_key *key,
				   u8 *mac, u16 vid, bool enable, bool dynamic)
{
	struct prestera_l2tun_vp *vp;
	int err;

	vp = prestera_l2tun_vp_find(sw, key);
	/* This is util. So no need to dynamically create vp. */
	if (!vp)
		return -ENOENT;

	if (enable)
		err = prestera_hw_fdb_tep_add(sw, vp->hw_tep_id,
					      mac, vid, dynamic);
	else
		err = prestera_hw_fdb_tep_del(sw, vp->hw_tep_id, mac, vid);

	return err;
}

struct prestera_l2tun_tep *
prestera_l2tun_tep_find(struct prestera_switch *sw,
			struct prestera_l2tun_tep_key *key)
{
	struct prestera_l2tun_tep *tep;

	tep = rhashtable_lookup_fast(&sw->router->nve.l2tun_tep_ht, key,
				     __prestera_l2tun_tep_ht_params);

	return IS_ERR(tep) ? NULL : tep;
}

void prestera_l2tun_tep_destroy(struct prestera_switch *sw,
				struct prestera_l2tun_tep *tep)
{
	WARN_ON(prestera_hw_l2tun_tep_clear(sw, tep->vp->hw_tep_id));

	rhashtable_remove_fast(&sw->router->nve.l2tun_tep_ht, &tep->ht_node,
			       __prestera_l2tun_tep_ht_params);
	list_del(&tep->nh_neigh_head);
	prestera_nh_neigh_put(sw, tep->n);
	list_del(&tep->l2tun_vp_head);
	prestera_l2tun_vp_put(sw, tep->vp);
	kfree(tep);
}

int prestera_l2tun_tep_set(struct prestera_switch *sw,
			   struct prestera_l2tun_tep *tep)
{
	int err;

	err = prestera_hw_l2tun_tep_set(sw, tep->vp->hw_tep_id, tep->n->info,
					tep->cfg.dip.u.ipv4,
					tep->cfg.sip.u.ipv4,
					tep->cfg.l4_dst, tep->cfg.l4_src,
					tep->cfg.vni, tep->cfg.source_id);
	if (err) {
		pr_err("prestera_hw_l2tun_tep_set failed");
		return err;
	}

	return 0;
}

struct prestera_l2tun_tep *
prestera_l2tun_tep_create(struct prestera_switch *sw,
			  struct prestera_l2tun_tep_key *key,
			  struct prestera_l2tun_tep_cfg *cfg,
			  struct prestera_nh_neigh_key *n_key)
{
	struct prestera_l2tun_tep *tep;
	int err;

	tep = kzalloc(sizeof(*tep), GFP_KERNEL);
	if (!tep)
		goto err_kzalloc;

	memcpy(&tep->key, key, sizeof(*key));
	memcpy(&tep->cfg, cfg, sizeof(*cfg));

	tep->n = prestera_nh_neigh_get(sw, n_key);
	if (!tep->n)
		goto err_nh_get;

	list_add(&tep->nh_neigh_head, &tep->n->l2tun_tep_list);

	tep->vp = prestera_l2tun_vp_get(sw, &key->vp_key);
	if (!tep->vp)
		goto err_vp_get;

	list_add(&tep->l2tun_vp_head, &tep->vp->l2tun_tep_list);

	err = prestera_l2tun_tep_set(sw, tep);
	if (err)
		goto err_tep_set;

	err = rhashtable_insert_fast(&sw->router->nve.l2tun_tep_ht,
				     &tep->ht_node,
				     __prestera_l2tun_tep_ht_params);
	if (err)
		goto err_ht_insert;

	return tep;

err_ht_insert:
	WARN_ON(prestera_hw_l2tun_tep_clear(sw, tep->vp->hw_tep_id));
err_tep_set:
	list_del(&tep->l2tun_vp_head);
	prestera_l2tun_vp_put(sw, tep->vp);
err_vp_get:
	list_del(&tep->nh_neigh_head);
	prestera_nh_neigh_put(sw, tep->n);
err_nh_get:
	kfree(tep);
err_kzalloc:
	return NULL;
}

struct prestera_l2tun_tt *
prestera_l2tun_tt_find(struct prestera_switch *sw,
		       struct prestera_l2tun_tt_key *key)
{
	struct prestera_l2tun_tt *tt;

	tt = rhashtable_lookup_fast(&sw->router->nve.l2tun_tt_ht, key,
				    __prestera_l2tun_tt_ht_params);

	return IS_ERR(tt) ? NULL : tt;
}

void prestera_l2tun_tt_destroy(struct prestera_switch *sw,
			       struct prestera_l2tun_tt *tt)
{
	WARN_ON(prestera_hw_l2tun_tt_del(sw, tt->hw_tt_id));

	rhashtable_remove_fast(&sw->router->nve.l2tun_tt_ht, &tt->ht_node,
			       __prestera_l2tun_tt_ht_params);
	if (tt->vp) {
		list_del(&tt->l2tun_vp_head);
		prestera_l2tun_vp_put(sw, tt->vp);
	}

	kfree(tt);
}

struct prestera_l2tun_tt *
prestera_l2tun_tt_create(struct prestera_switch *sw,
			 struct prestera_l2tun_tt_key *key, u16 pvid,
			 struct prestera_l2tun_vp_key *vp_key, u32 source_id)
{
	struct prestera_l2tun_tt *tt;
	int err;

	tt = kzalloc(sizeof(*tt), GFP_KERNEL);
	if (!tt)
		goto err_kzalloc;

	/* Sanitize key */
	if (!key->match_src_ip)
		memset(&key->src_ip, 0, sizeof(key->src_ip));

	memcpy(&tt->key, key, sizeof(*key));
	tt->pvid = pvid;
	tt->source_id = source_id;

	if (vp_key) {
		tt->vp = prestera_l2tun_vp_get(sw, vp_key);
		if (!tt->vp)
			goto err_vp_get;

		list_add(&tt->l2tun_vp_head, &tt->vp->l2tun_tt_list);
	}

	err = prestera_hw_l2tun_tt_create(sw, key->ip.u.ipv4,
					  key->match_src_ip, key->src_ip.u.ipv4,
					  key->port, key->vni,
					  tt->vp ? tt->vp->hw_tep_id : 0,
					  tt->pvid, tt->source_id,
					  &tt->hw_tt_id);
	if (err)
		goto err_hw_create;

	err = rhashtable_insert_fast(&sw->router->nve.l2tun_tt_ht,
				     &tt->ht_node,
				     __prestera_l2tun_tt_ht_params);
	if (err)
		goto err_ht_insert;

	return tt;

err_ht_insert:
	prestera_hw_l2tun_tt_del(sw, tt->hw_tt_id);
err_hw_create:
	if (tt->vp) {
		list_del(&tt->l2tun_vp_head);
		prestera_l2tun_vp_put(sw, tt->vp);
	}
err_vp_get:
	kfree(tt);
err_kzalloc:
	return NULL;
}

int prestera_l2tun_init(struct prestera_switch *sw)
{
	int err;

	err = rhashtable_init(&sw->router->nve.l2tun_vp_ht,
			      &__prestera_l2tun_vp_ht_params);
	if (err)
		goto err_l2tun_vp_ht;

	err = rhashtable_init(&sw->router->nve.l2tun_vp_hw_index_ht,
			      &__prestera_l2tun_vp_hw_index_ht_params);
	if (err)
		goto err_l2tun_vp_hw_index_ht;

	err = rhashtable_init(&sw->router->nve.l2tun_tep_ht,
			      &__prestera_l2tun_tep_ht_params);
	if (err)
		goto err_l2tun_tep_ht;

	err = rhashtable_init(&sw->router->nve.l2tun_tt_ht,
			      &__prestera_l2tun_tt_ht_params);
	if (err)
		goto err_l2tun_tt_ht;

	return 0;

err_l2tun_tt_ht:
	rhashtable_destroy(&sw->router->nve.l2tun_tep_ht);
err_l2tun_tep_ht:
	rhashtable_destroy(&sw->router->nve.l2tun_vp_hw_index_ht);
err_l2tun_vp_hw_index_ht:
	rhashtable_destroy(&sw->router->nve.l2tun_vp_ht);
err_l2tun_vp_ht:
	return err;
}

void prestera_l2tun_fini(struct prestera_switch *sw)
{
	/* TODO: clear all hw entries (walk ht) */

	rhashtable_destroy(&sw->router->nve.l2tun_tt_ht);
	rhashtable_destroy(&sw->router->nve.l2tun_tep_ht);
	rhashtable_destroy(&sw->router->nve.l2tun_vp_hw_index_ht);
	rhashtable_destroy(&sw->router->nve.l2tun_vp_ht);
}
