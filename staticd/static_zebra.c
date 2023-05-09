/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "srcdest_table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "hash.h"
#include "jhash.h"
#include "srv6.h"
#include "lib_errors.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"
#include "static_debug.h"
#include "static_srv6.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_NHT_DATA, "Static Nexthop tracking data");
PREDECL_HASH(static_nht_hash);

struct static_nht_data {
	struct static_nht_hash_item itm;

	struct prefix nh;
	safi_t safi;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t nh_num;
	bool registered;
};

static int static_nht_data_cmp(const struct static_nht_data *nhtd1,
			       const struct static_nht_data *nhtd2)
{
	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return numcmp(nhtd1->nh_vrf_id, nhtd2->nh_vrf_id);
	if (nhtd1->safi != nhtd2->safi)
		return numcmp(nhtd1->safi, nhtd2->safi);

	return prefix_cmp(&nhtd1->nh, &nhtd2->nh);
}

static unsigned int static_nht_data_hash(const struct static_nht_data *nhtd)
{
	unsigned int key = 0;

	key = prefix_hash_key(&nhtd->nh);
	return jhash_2words(nhtd->nh_vrf_id, nhtd->safi, key);
}

DECLARE_HASH(static_nht_hash, struct static_nht_data, itm, static_nht_data_cmp,
	     static_nht_data_hash);

static struct static_nht_hash_head static_nht_hash[1];

/* Zebra structure to hold current status. */
struct zclient *zclient;
uint32_t zebra_ecmp_count = MULTIPATH_NUM;

/* Interface addition message from zebra. */
static int static_ifp_create(struct interface *ifp)
{
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_destroy(struct interface *ifp)
{
	static_ifindex_update(ifp, false);
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int static_ifp_up(struct interface *ifp)
{
	/* Install any static reliant on this interface coming up */
	static_install_intf_nh(ifp);
	static_ifindex_update(ifp, true);

	/* TEMP WORKAROUND
	 * staticd tries to install a seg6local nexthop before receiving
	 * interface information and fails.
	 * This workaround, calls static_zebra_srv6_sid_update() to install
	 * SIDs after at least one interface is available
	 */
	struct static_srv6_sid *sid;
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid))
		static_zebra_srv6_sid_update(sid);

	return 0;
}

static int static_ifp_down(struct interface *ifp)
{
	static_ifindex_update(ifp, false);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	safi_t safi;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note, NULL,
				      &safi))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %pFX failed to install for table: %u",
			  __func__, &p, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn(
			"%s: Route %pFX over-ridden by better route for table: %u",
			__func__, &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVED:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_INSTALLED);
		zlog_warn("%s: Route %pFX failure to remove for table: %u",
			  __func__, &p, table_id);
		break;
	}

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	static_fixup_vrf_ids(vrf_info_lookup(VRF_DEFAULT));

	static_fixup_vrf_srv6_sids(vrf_info_lookup(VRF_DEFAULT));
}

/* API to check whether the configured nexthop address is
 * one of its local connected address or not.
 */
static bool
static_nexthop_is_local(vrf_id_t vrfid, struct prefix *addr, int family)
{
	if (family == AF_INET) {
		if (if_address_is_local(&addr->u.prefix4, AF_INET, vrfid))
			return true;
	} else if (family == AF_INET6) {
		if (if_address_is_local(&addr->u.prefix6, AF_INET6, vrfid))
			return true;
	}
	return false;
}
static int static_zebra_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct static_nht_data *nhtd, lookup;
	struct zapi_route nhr;
	struct prefix matched;
	afi_t afi = AFI_IP;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &matched, &nhr)) {
		zlog_err("Failure to decode nexthop update message");
		return 1;
	}

	if (matched.family == AF_INET6)
		afi = AFI_IP6;

	if (nhr.type == ZEBRA_ROUTE_CONNECT) {
		if (static_nexthop_is_local(vrf_id, &matched,
					    nhr.prefix.family))
			nhr.nexthop_num = 0;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = matched;
	lookup.nh_vrf_id = vrf_id;
	lookup.safi = nhr.safi;

	nhtd = static_nht_hash_find(static_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr.nexthop_num;

		static_nht_reset_start(&matched, afi, nhr.safi,
				       nhtd->nh_vrf_id);
		static_nht_update(NULL, &matched, nhr.nexthop_num, afi,
				  nhr.safi, nhtd->nh_vrf_id);
	} else
		zlog_err("No nhtd?");

	return 1;
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
	zebra_ecmp_count = cap->ecmp;
}

static struct static_nht_data *
static_nht_hash_getref(const struct static_nht_data *ref)
{
	struct static_nht_data *nhtd;

	nhtd = static_nht_hash_find(static_nht_hash, ref);
	if (!nhtd) {
		nhtd = XCALLOC(MTYPE_STATIC_NHT_DATA, sizeof(*nhtd));

		prefix_copy(&nhtd->nh, &ref->nh);
		nhtd->nh_vrf_id = ref->nh_vrf_id;
		nhtd->safi = ref->safi;

		static_nht_hash_add(static_nht_hash, nhtd);
	}

	nhtd->refcount++;
	return nhtd;
}

static bool static_nht_hash_decref(struct static_nht_data **nhtd_p)
{
	struct static_nht_data *nhtd = *nhtd_p;

	*nhtd_p = NULL;

	if (--nhtd->refcount > 0)
		return true;

	static_nht_hash_del(static_nht_hash, nhtd);
	XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
	return false;
}

static void static_nht_hash_clear(void)
{
	struct static_nht_data *nhtd;

	while ((nhtd = static_nht_hash_pop(static_nht_hash)))
		XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
}

static bool static_zebra_nht_get_prefix(const struct static_nexthop *nh,
					struct prefix *p)
{
	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		p->family = AF_UNSPEC;
		return false;

	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		p->u.prefix4 = nh->addr.ipv4;
		return true;

	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		p->u.prefix6 = nh->addr.ipv6;
		return true;
	}

	assertf(0, "BUG: someone forgot to add nexthop type %u", nh->type);
}

void static_zebra_nht_register(struct static_nexthop *nh, bool reg)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	struct static_route_info *si = static_route_info_from_rnode(rn);
	struct static_nht_data *nhtd, lookup = {};
	uint32_t cmd;

	if (!static_zebra_nht_get_prefix(nh, &lookup.nh))
		return;
	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.safi = si->safi;

	if (nh->nh_registered) {
		/* nh->nh_registered means we own a reference on the nhtd */
		nhtd = static_nht_hash_find(static_nht_hash, &lookup);

		assertf(nhtd, "BUG: NH %pFX registered but not in hashtable",
			&lookup.nh);
	} else if (reg) {
		nhtd = static_nht_hash_getref(&lookup);

		if (nhtd->refcount > 1)
			DEBUGD(&static_dbg_route,
			       "Reusing registered nexthop(%pFX) for %pRN %d",
			       &lookup.nh, rn, nhtd->nh_num);
	} else {
		/* !reg && !nh->nh_registered */
		zlog_warn("trying to unregister nexthop %pFX twice",
			  &lookup.nh);
		return;
	}

	nh->nh_registered = reg;

	if (reg) {
		if (nhtd->nh_num) {
			/* refresh with existing data */
			afi_t afi = prefix_afi(&lookup.nh);

			if (nh->state == STATIC_NOT_INSTALLED)
				nh->state = STATIC_START;
			static_nht_update(&rn->p, &nhtd->nh, nhtd->nh_num, afi,
					  si->safi, nh->nh_vrf_id);
			return;
		}

		if (nhtd->registered)
			/* have no data, but did send register */
			return;

		cmd = ZEBRA_NEXTHOP_REGISTER;
		DEBUGD(&static_dbg_route, "Registering nexthop(%pFX) for %pRN",
		       &lookup.nh, rn);
	} else {
		bool was_zebra_registered;

		was_zebra_registered = nhtd->registered;
		if (static_nht_hash_decref(&nhtd))
			/* still got references alive */
			return;

		/* NB: nhtd is now NULL. */
		if (!was_zebra_registered)
			return;

		cmd = ZEBRA_NEXTHOP_UNREGISTER;
		DEBUGD(&static_dbg_route,
		       "Unregistering nexthop(%pFX) for %pRN", &lookup.nh, rn);
	}

	if (zclient_send_rnh(zclient, cmd, &lookup.nh, si->safi, false, false,
			     nh->nh_vrf_id) == ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop %pFX for %pRN to zebra",
			  __func__, &lookup.nh, rn);
	else if (reg)
		nhtd->registered = true;
}

extern void static_zebra_route_add(struct static_path *pn, bool install)
{
	struct route_node *rn = pn->rn;
	struct static_route_info *si = rn->info;
	struct static_nexthop *nh;
	const struct prefix *p, *src_pp;
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	uint32_t nh_num = 0;

	p = src_pp = NULL;
	srcdest_rnode_prefixes(rn, &p, &src_pp);

	memset(&api, 0, sizeof(api));
	api.vrf_id = si->svrf->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_STATIC;
	api.safi = si->safi;
	memcpy(&api.prefix, p, sizeof(api.prefix));

	if (src_pp) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_pp, sizeof(api.src_prefix));
	}
	SET_FLAG(api.flags, ZEBRA_FLAG_RR_USE_DISTANCE);
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	if (pn->distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = pn->distance;
	}
	if (pn->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = pn->tag;
	}
	if (pn->table_id != 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = pn->table_id;
	}
	frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
		/* Don't overrun the nexthop array */
		if (nh_num == zebra_ecmp_count)
			break;

		api_nh = &api.nexthops[nh_num];
		if (nh->nh_vrf_id == VRF_UNKNOWN)
			continue;

		api_nh->vrf_id = nh->nh_vrf_id;
		if (nh->onlink)
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		if (nh->color != 0) {
			SET_FLAG(api.message, ZAPI_MESSAGE_SRTE);
			api_nh->srte_color = nh->color;
		}

		nh->state = STATIC_SENT_TO_ZEBRA;

		switch (nh->type) {
		case STATIC_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			break;
		case STATIC_IPV4_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = nh->ifindex;
			api_nh->gate = nh->addr;
			break;
		case STATIC_BLACKHOLE:
			api_nh->type = NEXTHOP_TYPE_BLACKHOLE;
			switch (nh->bh_type) {
			case STATIC_BLACKHOLE_DROP:
			case STATIC_BLACKHOLE_NULL:
				api_nh->bh_type = BLACKHOLE_NULL;
				break;
			case STATIC_BLACKHOLE_REJECT:
				api_nh->bh_type = BLACKHOLE_REJECT;
			}
			break;
		}

		if (nh->snh_label.num_labels) {
			int i;

			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
			api_nh->label_num = nh->snh_label.num_labels;
			for (i = 0; i < api_nh->label_num; i++)
				api_nh->labels[i] = nh->snh_label.label[i];
		}
		nh_num++;
	}

	api.nexthop_num = nh_num;

	/*
	 * If we have been given an install but nothing is valid
	 * go ahead and delete the route for double plus fun
	 */
	if (!nh_num && install)
		install = false;

	zclient_route_send(install ?
			   ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}

/*
 * Install an SRv6 SID in the zebra RIB.
 */
extern void static_zebra_srv6_sid_add(struct static_srv6_sid *sid)
{
	enum seg6local_action_t seg6local_action =
		ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct seg6local_context seg6local_ctx = {};
	struct srv6_sid_structure seg6local_structure = {};
	struct vrf *vrf;
	struct interface *ifp;
	ifindex_t oif = 0;
	int ret = 0;

	// /* By default, use the loopback interface as outgoing device */
	// ifp = if_lookup_by_name("lo", VRF_DEFAULT);
	// if (!ifp) {
	// 	return;
	// }

	/* convert `static_srv6_sid_behavior_t` to `seg6local_action_t` */
	switch (sid->behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_X:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_T:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_T;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DX2:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DX2;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DX6:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DX6;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DX4:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DX4;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_B6:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_B6;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_B6_ENCAP:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_BM:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_BM;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_S:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_S;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_AS:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_AS;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_AM:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_AM;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_BPF:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_BPF;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_END_DT46:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_UDT4;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_UDT6;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_UDT46;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_UN:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case STATIC_SRV6_SID_BEHAVIOR_UA:
		seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		break;
	}

	/* process SRv6 SID attributes */

	/* generate nexthop from the interface name, if configured */
	if (sid->attributes.ifname[0] != '\0') {
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp)
			return;

		oif = ifp->ifindex;
	}

	/* generate nexthop from the adjacency, if configured */
	if (!IPV6_ADDR_SAME(&sid->attributes.adj_v6, &in6addr_any))
		seg6local_ctx.nh6 = sid->attributes.adj_v6;

	/* generate table ID from the VRF name, if configured */
	if (sid->attributes.vrf_name[0] != '\0') {
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf || !CHECK_FLAG(vrf->status, VRF_ACTIVE))
			return;

		seg6local_ctx.table = vrf->data.l.table_id;
		oif = vrf->vrf_id;
	}

	/* By default, use the first non-loopback interface as outgoing device
	 */
	if (!oif) {
		for (int i = 0; i < 256; ++i) {
			ifp = if_lookup_by_index(i, VRF_DEFAULT);
			if (ifp && !strmatch(ifp->name, "lo"))
				break;
		}
		if (!ifp) {
			zlog_err("No valid interfaces found. Skipping SID %pI6",
				 &sid->addr);
			return;
		}
		oif = ifp->ifindex;
	}

	/* If SRv6 SID is a uSID, set flavor data structure */
	if (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UN ||
	    sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UA) {
		SET_SRV6_FLV_OP(seg6local_ctx.flv.flv_ops,
				ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		seg6local_ctx.flv.lcblock_len =
			ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCBLOCK_LEN;
		seg6local_ctx.flv.lcnode_func_len =
			ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN;
	}

	/* Prepare SRv6 SID structure. Currently we use the hardcoded default values */
	seg6local_structure.block_bits_length = ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCBLOCK_LEN;
	seg6local_structure.node_bits_length = ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN;
	seg6local_structure.function_bits_length = ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN;
	seg6local_structure.argument_bits_length = 0;

	/* install the SRv6 SID in the zebra RIB */
	ret = zclient_send_localsid(zclient, &sid->addr, oif, seg6local_action,
				    &seg6local_ctx, &seg6local_structure);
	if (ret == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "zclient_send_localsid() add failed: %s",
			 safe_strerror(errno));

	/* set SRV6_SID_SENT_TO_ZEBRA flag */
	SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

/*
 * Remove an SRv6 SID from the zebra RIB.
 */
extern void static_zebra_srv6_sid_del(struct static_srv6_sid *sid)
{
	struct vrf *vrf;
	ifindex_t oif = 0;
	int ret = 0;

	if (sid->attributes.vrf_name[0] != '\0') {
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf)
			return;

		oif = vrf->vrf_id;
	}

	/* remove the SRv6 SID from the zebra RIB */
	ret = zclient_send_localsid(zclient, &sid->addr, oif,
				    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, NULL, NULL);
	if (ret == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "zclient_send_localsid() delete failed: %s",
			 safe_strerror(errno));

	/* set SRV6_SID_SENT_TO_ZEBRA flag */
	UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

/*
 * This function can be used to update the zebra RIB after a SID's validity flag
 * changes. If the SID is valid and was not previously installed in the zebra
 * RIB, this function installs the SID in the zebra RIB. If the SID is invalid
 * and was previously installed in the zebra RIB, this function removes the SID
 * from the zebra RIB.
 */
extern void static_zebra_srv6_sid_update(struct static_srv6_sid *sid)
{
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID) &&
	    !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_add(sid);
	else if (!CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID) &&
		 CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_del(sid);
}

static zclient_handler *const static_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_NEXTHOP_UPDATE] = static_zebra_nexthop_update,
};

void static_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	if_zapi_callbacks(static_ifp_create, static_ifp_up,
			  static_ifp_down, static_ifp_destroy);

	zclient = zclient_new(master, &opt, static_handlers,
			      array_size(static_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	zclient->zebra_capabilities = static_zebra_capabilities;
	zclient->zebra_connected = zebra_connected;

	static_nht_hash_init(static_nht_hash);
}

/* static_zebra_stop used by tests/lib/test_grpc.cpp */
void static_zebra_stop(void)
{
	static_nht_hash_clear();
	static_nht_hash_fini(static_nht_hash);

	if (!zclient)
		return;
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}

void static_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_reg_requests(zclient, vrf->vrf_id);
}

void static_zebra_vrf_unregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_dereg_requests(zclient, vrf->vrf_id);
}
