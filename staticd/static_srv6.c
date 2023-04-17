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
#include "zclient.h"

#include "static_routes.h"
#include "static_srv6.h"
#include "static_vrf.h"
#include "static_zebra.h"

/*
 * Definitions and external declarations.
 */
extern struct zclient *zclient;

/*
 * List of SRv6 SIDs.
 */
struct list *srv6_sids = NULL;

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID");

DEFINE_QOBJ_TYPE(static_srv6_sid);

/*
 * Convert SRv6 behavior to human-friendly string.
 */
const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "End.DT6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "End.DT4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT46:
		return "End.DT46";
	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
		return "uDT4";
	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
		return "uDT6";
	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
		return "uDT46";
	case STATIC_SRV6_SID_BEHAVIOR_UN:
		return "uN";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

/*
 * Convert SRv6 behavior to human-friendly string, used in CLI output.
 */
const char *
static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "end-dt6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "end-dt4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT46:
		return "end-dt46";
	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
		return "end-dt4-usid";
	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
		return "end-dt6-usid";
	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
		return "end-dt46-usid";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

/*
 * Print current Segment Routing configuration on VTY.
 */
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
			if (sid->attributes.vrf_name[0] != '\0') {
				vty_out(vty, "    sharing-attributes\n");
				if (sid->attributes.vrf_name[0] != '\0')
					vty_out(vty, "     vrf-name %s\n",
						sid->attributes.vrf_name);
				vty_out(vty, "    exit\n");
				vty_out(vty, "    !\n");
			}
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

/*
 * Return a JSON representation of an SRv6 SID.
 */
json_object *srv6_sid_json(const struct static_srv6_sid *sid)
{
	json_object *jo_root = NULL;
	json_object *jo_attributes = NULL;

	jo_root = json_object_new_object();

	/* set the SRv6 SID address */
	json_object_string_addf(jo_root, "address", "%pI6", &sid->addr);

	/* set the SRv6 SID behavior */
	json_object_string_add(jo_root, "behavior",
			       static_srv6_sid_behavior2str(sid->behavior));

	/* set the SRv6 SID attributes */
	jo_attributes = json_object_new_object();
	json_object_object_add(jo_root, "attributes", jo_attributes);

	/* set the VRF name, if configured */
	if (sid->attributes.vrf_name[0] != '\0')
		json_object_string_add(jo_attributes, "vrfName", sid->attributes.vrf_name);

	/* set a flag indicating whether the SRv6 SID is valid or not; a SID is
	 * valid if all the mandatory attributes have been configured */
	json_object_boolean_add(
		jo_root, "valid",
		CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID));

	return jo_root;
}

/*
 * Return a detailed JSON representation of an SRv6 SID.
 */
json_object *srv6_sid_detailed_json(const struct static_srv6_sid *sid)
{
	json_object *jo_root = NULL;
	json_object *jo_attributes = NULL;

	jo_root = json_object_new_object();

	/* set the SRv6 SID address */
	json_object_string_addf(jo_root, "address", "%pI6", &sid->addr);

	/* set the SRv6 SID behavior */
	json_object_string_add(jo_root, "behavior",
			       static_srv6_sid_behavior2str(sid->behavior));

	/* set the SRv6 SID attributes */
	jo_attributes = json_object_new_object();
	json_object_object_add(jo_root, "attributes", jo_attributes);

	/* set the VRF name, if configured */
	if (sid->attributes.vrf_name[0] != '\0')
		json_object_string_add(jo_attributes, "vrfName", sid->attributes.vrf_name);

	/* set a flag indicating whether the SRv6 SID is valid or not; a SID is
	 * valid if all the mandatory attributes have been configured */
	json_object_boolean_add(
		jo_root, "valid",
		CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID));

	return jo_root;
}

/*
 * Mark an SRv6 SID as "valid" or "invalid" and update the zebra RIB
 * accordingly. An SRv6 SID is considered "valid" when all the mandatory
 * attributes have been configured. On the contrary, a SID is "invalid" when one
 * or more mandatory attributes have not yet been configured.
 */
void mark_srv6_sid_as_valid(struct static_srv6_sid *sid, bool is_valid)
{
	/* set/unset SRV6_SID_VALID flag */
	if (is_valid)
		SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	else
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

	/* update the zebra RIB by adding/removing the SID depending on
	 * SRV6_SID_VALID */
	static_zebra_srv6_sid_update(sid);
}

/*
 * When a VRF is enabled in the kernel, go through all the static SRv6 SIDs in
 * the system that use this VRF (e.g., End.DT4 or End.DT6 SRv6 SIDs) and install
 * them in the zebra RIB.
 *
 * enable_svrf -> the VRF being enabled
 */
void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	if (!srv6_sids || !enable_svrf)
		return;

	/* iterate over the list of SRv6 SIDs and install the SIDs that use this
	 * VRF in the zebra RIB */
	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!strcmp(sid->attributes.vrf_name, enable_svrf->vrf->name))
			static_zebra_srv6_sid_update(sid);
	}
}

/*
 * When a VRF is disabled in the kernel, we call this function and it removes
 * all the static SRv6 SIDs using this VRF from the zebra RIB (e.g., End.DT4 or
 * End.DT6 SRv6 SIDs).
 *
 * disable_svrf - The VRF being disabled
 */
void static_cleanup_vrf_srv6_sids(struct static_vrf *disable_svrf)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	if (!srv6_sids || !disable_svrf)
		return;

	/* iterate over the list of SRv6 SIDs and remove the SIDs that use this
	 * VRF from the zebra RIB */
	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (!strcmp(sid->attributes.vrf_name, disable_svrf->vrf->name))
			static_zebra_srv6_sid_del(sid);
	}
}

/*
 * Allocate an SRv6 SID object and initialize the fields common to all the
 * behaviors (i.e., SID address and behavor).
 */
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

/*
 * Add an SRv6 SID to the list of SRv6 SIDs. Also, if the SID is valid (i.e.,
 * all the mandatory attributes have been configured), add the SID to the zebra
 * RIB.
 */
void static_srv6_sid_add(struct static_srv6_sid *sid)
{
	listnode_add(srv6_sids, sid);
	static_zebra_srv6_sid_update(sid);
}

/*
 * Look-up an SRv6 SID in the list of SRv6 SIDs.
 */
struct static_srv6_sid *static_srv6_sid_lookup(struct in6_addr *sid_addr)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid))
		if (sid_same(&sid->addr, sid_addr))
			return sid;
	return NULL;
}

/*
 * Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID.
 */
void static_srv6_sid_del(struct static_srv6_sid *sid)
{
	QOBJ_UNREG(sid);

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_del(sid);

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

/*
 * Initialize SRv6 data structures.
 */
void static_srv6_init(void)
{
	srv6_sids = list_new();
	srv6_sids->del = (void (*)(void *))static_srv6_sid_del;
}

/*
 * Clean up all the SRv6 data structures.
 */
void static_srv6_cleanup(void)
{
	list_delete(&srv6_sids);
}
