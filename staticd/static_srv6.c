/*
 * STATICd - SRv6 code
 * Copyright (C) 2022 University of Rome Tor Vergata
 *               Carmine Scarpitta
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

#include "vrf.h"
#include "nexthop.h"

#include "static_routes.h"
#include "static_srv6.h"
#include "static_vrf.h"
#include "static_zebra.h"
#include "zclient.h"

extern struct zclient *zclient;

struct list *srv6_sids;

DEFINE_QOBJ_TYPE(static_srv6_sid);
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID Info");

const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END:
		return "End";
	case STATIC_SRV6_SID_BEHAVIOR_END_X:
		return "End.X";
	case STATIC_SRV6_SID_BEHAVIOR_END_T:
		return "End.T";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX2:
		return "End.DX2";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX6:
		return "End.DX6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX4:
		return "End.DX4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "End.DT6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "End.DT4";
	case STATIC_SRV6_SID_BEHAVIOR_END_B6:
		return "End.B6";
	case STATIC_SRV6_SID_BEHAVIOR_END_B6_ENCAP:
		return "End.B6.Encap";
	case STATIC_SRV6_SID_BEHAVIOR_END_BM:
		return "End.BM";
	case STATIC_SRV6_SID_BEHAVIOR_END_S:
		return "End.S";
	case STATIC_SRV6_SID_BEHAVIOR_END_AS:
		return "End.AS";
	case STATIC_SRV6_SID_BEHAVIOR_END_AM:
		return "End.AM";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

const char *
static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END:
		return "end";
	case STATIC_SRV6_SID_BEHAVIOR_END_X:
		return "end-x";
	case STATIC_SRV6_SID_BEHAVIOR_END_T:
		return "end-t";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX2:
		return "end-dx2";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX6:
		return "end-dx6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DX4:
		return "end-dx4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "end-dt6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "end-dt4";
	case STATIC_SRV6_SID_BEHAVIOR_END_B6:
		return "end-b6";
	case STATIC_SRV6_SID_BEHAVIOR_END_B6_ENCAP:
		return "end-b6-encap";
	case STATIC_SRV6_SID_BEHAVIOR_END_BM:
		return "end-bm";
	case STATIC_SRV6_SID_BEHAVIOR_END_S:
		return "end-s";
	case STATIC_SRV6_SID_BEHAVIOR_END_AS:
		return "end-as";
	case STATIC_SRV6_SID_BEHAVIOR_END_AM:
		return "end-am";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

int static_sr_config_write(struct vty *vty)
{
	struct listnode *node;
	struct static_srv6_sid *sid;

	vty_out(vty, "!\n");
	if (listcount(srv6_sids)) {
		vty_out(vty, "segment-routing\n");
		vty_out(vty, " srv6\n");
		vty_out(vty, "  explicit-sids\n");
		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
			vty_out(vty, "   sid %pI6 behavior %s\n", &sid->addr,
				static_srv6_sid_behavior2clistr(sid->behavior));
			if (sid->vrf_name[0] != '\0') {
				vty_out(vty, "    sharing-attributes\n");
				if (sid->vrf_name[0] != '\0')
					vty_out(vty, "     vrf-name %s\n",
						sid->vrf_name);
			}
			vty_out(vty, "     exit\n");
			vty_out(vty, "     !\n");
			vty_out(vty, "    exit\n");
			vty_out(vty, "    !\n");
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");
		vty_out(vty, " exit\n");
		vty_out(vty, " !\n");
		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

json_object *srv6_sid_json(const struct static_srv6_sid *sid)
{
	json_object *jo_root = NULL;
	json_object *jo_attributes = NULL;

	jo_root = json_object_new_object();

	/* set address */
	json_object_string_addf(jo_root, "address", "%pI6", &sid->addr);

	/* set behavior */
	json_object_string_add(jo_root, "behavior",
			       static_srv6_sid_behavior2str(sid->behavior));

	/* set SRv6 SID attributes */
	jo_attributes = json_object_new_object();
	json_object_object_add(jo_root, "attributes", jo_attributes);

	/* set VRF name */
	if (sid->vrf_name[0] != '\0')
		json_object_string_add(jo_attributes, "vrfName", sid->vrf_name);

	json_object_boolean_add(
		jo_root, "valid",
		CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID));

	return jo_root;
}

json_object *srv6_sid_detailed_json(const struct static_srv6_sid *sid)
{
	json_object *jo_root = NULL;
	json_object *jo_attributes = NULL;

	jo_root = json_object_new_object();

	/* set address */
	json_object_string_addf(jo_root, "address", "%pI6", &sid->addr);

	/* set behavior */
	json_object_string_add(jo_root, "behavior",
			       static_srv6_sid_behavior2str(sid->behavior));

	/* set SRv6 SID attributes */
	jo_attributes = json_object_new_object();
	json_object_object_add(jo_root, "attributes", jo_attributes);

	/* set VRF name */
	if (sid->vrf_name[0] != '\0')
		json_object_string_add(jo_attributes, "vrfName", sid->vrf_name);

	json_object_boolean_add(
		jo_root, "valid",
		CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID));

	return jo_root;
}

void mark_srv6_sid_as_valid(struct static_srv6_sid *sid, bool is_valid)
{
	if (is_valid)
		SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	else
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

	/* update the zebra RIB */
	static_zebra_srv6_sid_update(sid);
}

void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	if (!srv6_sids || !enable_svrf)
		return;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!strcmp(sid->vrf_name, enable_svrf->vrf->name))
			static_zebra_srv6_sid_update(sid);
	}
}

void static_cleanup_vrf_srv6_sids(struct static_vrf *disable_svrf)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	if (!srv6_sids || !disable_svrf)
		return;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!strcmp(sid->vrf_name, disable_svrf->vrf->name))
			static_zebra_srv6_sid_del(sid);
	}
}

struct static_srv6_sid *srv6_sid_alloc(struct in6_addr *addr,
				       enum static_srv6_sid_behavior_t behavior)
{
	struct static_srv6_sid *sid = NULL;

	sid = XCALLOC(MTYPE_STATIC_SRV6_SID, sizeof(struct static_srv6_sid));
	sid->addr = *addr;
	sid->behavior = behavior;

	QOBJ_REG(sid, static_srv6_sid);
	return sid;
}

void static_srv6_sid_add(struct static_srv6_sid *sid)
{
	listnode_add(srv6_sids, sid);
	static_zebra_srv6_sid_update(sid);
}

struct static_srv6_sid *static_srv6_sid_lookup(struct in6_addr *sid_addr)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid))
		if (sid_same(&sid->addr, sid_addr))
			return sid;
	return NULL;
}

// void static_srv6_sid_free(struct static_srv6_sid *sid)
// {
// 	static_zebra_srv6_sid_del(sid);
// 	XFREE(MTYPE_STATIC_SRV6_SID, sid);
// }

void static_srv6_sid_del(struct static_srv6_sid *sid)
{
	QOBJ_UNREG(sid);

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_del(sid);

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

void static_srv6_init(void)
{
	srv6_sids = list_new();
	srv6_sids->del = (void (*)(void *))static_srv6_sid_del;
}

void static_srv6_cleanup(void)
{
	list_delete(&srv6_sids);
}
