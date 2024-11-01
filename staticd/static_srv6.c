// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - Segment Routing over IPv6 (SRv6) code
 * Copyright (C) 2024 Carmine Scarpitta
 */
#include <zebra.h>

#include "vrf.h"
#include "nexthop.h"

#include "static_routes.h"
#include "static_srv6.h"
#include "static_vrf.h"
#include "static_zebra.h"

/*
 * List of SRv6 SIDs.
 */
struct list *srv6_locators = NULL;

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_LOCATOR, "Static SRv6 locator");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID");

DEFINE_QOBJ_TYPE(static_srv6_locator);

/*
 * Convert SRv6 behavior to human-friendly string.
 */
const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END:
		return "End";
	case STATIC_SRV6_SID_BEHAVIOR_END_X:
		return "End.X";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "End.DT6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "End.DT4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT46:
		return "End.DT46";
	case STATIC_SRV6_SID_BEHAVIOR_UN:
		return "uN";
	case STATIC_SRV6_SID_BEHAVIOR_UA:
		return "uA";
	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
		return "uDT6";
	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
		return "uDT4";
	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
		return "uDT46";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	}

	return "unspec";
}

// /*
//  * Convert SRv6 behavior to human-friendly string, used in CLI output.
//  */
// const char *
// static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t behavior)
// {
// 	switch (behavior) {
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
// 		return "udt6";
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
// 		return "udt4";
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
// 		return "udt46";
// 	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
// 		return "unspec";
// 	}
// }

// /*
//  * Print current Segment Routing configuration on VTY.
//  */
// int static_sr_config_write(struct vty *vty)
// {
// 	struct listnode *node;
// 	struct static_srv6_sid *sid;

// 	vty_out(vty, "!\n");
// 	if (listcount(srv6_sids)) {
// 		vty_out(vty, "segment-routing\n");
// 		vty_out(vty, " srv6\n");
// 		vty_out(vty, "  explicit-sids\n");
// 		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
// 			vty_out(vty, "   sid %pI6 behavior %s\n", &sid->addr,
// 				static_srv6_sid_behavior2clistr(sid->behavior));
// 			if (sid->attributes.vrf_name[0] != '\0') {
// 				vty_out(vty, "    sharing-attributes\n");
// 				if (sid->attributes.vrf_name[0] != '\0')
// 					vty_out(vty, "     vrf-name %s\n",
// 						sid->attributes.vrf_name);
// 			}
// 			vty_out(vty, "     exit\n");
// 			vty_out(vty, "     !\n");
// 			vty_out(vty, "    exit\n");
// 			vty_out(vty, "    !\n");
// 			vty_out(vty, "   exit\n");
// 			vty_out(vty, "   !\n");
// 		}
// 		vty_out(vty, "  exit\n");
// 		vty_out(vty, "  !\n");
// 		vty_out(vty, " exit\n");
// 		vty_out(vty, " !\n");
// 		vty_out(vty, "exit\n");
// 		vty_out(vty, "!\n");
// 	}
// 	return 0;
// }

/*
 * When a VRF is enabled in the kernel, go through all the static SRv6 SIDs in
 * the system that use this VRF (e.g., End.DT4 or End.DT6 SRv6 SIDs) and install
 * them in the zebra RIB.
 *
 * enable_svrf -> the VRF being enabled
 */
void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf)
{
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;
	struct listnode *node1, *node2;

	if (!srv6_locators || !enable_svrf)
		return;

	zlog_info("VRF %s enabled. Installing SIDs", enable_svrf->vrf->name);

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node1, locator)) {
		/* iterate over the list of SRv6 SIDs and install the SIDs that use this
		* VRF in the zebra RIB */
		zlog_info("Scanning locator %s", locator->name);
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node2, sid)) {
			zlog_info("Scanning SID %pI6, vrf %s", &sid->addr, sid->attributes.vrf_name);
			if (!strcmp(sid->attributes.vrf_name, enable_svrf->vrf->name))
				static_zebra_srv6_sid_install(sid);
		}
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
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;
	struct listnode *node1, *node2;

	if (!srv6_locators || !disable_svrf)
		return;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node1, locator)) {
		/* iterate over the list of SRv6 SIDs and remove the SIDs that use this
		* VRF from the zebra RIB */
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node2, sid)) {
			if (!strcmp(sid->attributes.vrf_name, disable_svrf->vrf->name))
				static_zebra_srv6_sid_uninstall(sid);
		}
	}
}

/*
 * Allocate an SRv6 SID object and initialize the fields common to all the
 * behaviors (i.e., SID address and behavor).
 */
struct static_srv6_sid *static_srv6_sid_alloc(struct in6_addr *addr)
{
	struct static_srv6_sid *sid = NULL;

	sid = XCALLOC(MTYPE_STATIC_SRV6_SID, sizeof(struct static_srv6_sid));
	sid->addr = *addr;

	// QOBJ_REG(sid, static_srv6_sid);
	return sid;
}

void static_srv6_sid_free(struct static_srv6_sid *sid)
{
	// QOBJ_UNREG(sid);

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

struct static_srv6_locator *static_srv6_locator_lookup(const char *name)
{
	struct static_srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

// /*
//  * Add an SRv6 SID to the list of SRv6 SIDs. Also, if the SID is valid (i.e.,
//  * all the mandatory attributes have been configured), add the SID to the zebra
//  * RIB.
//  */
// void static_srv6_sid_add(struct static_srv6_sid *sid)
// {
// 	listnode_add(srv6_sids, sid);
// 	static_zebra_srv6_sid_update(sid);
// }

/*
 * Look-up an SRv6 SID in the list of SRv6 SIDs.
 */
struct static_srv6_sid *static_srv6_sid_lookup(struct in6_addr *sid_addr)
{
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;
	struct listnode *node1, *node2;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node1, locator))
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node2, sid))
			if (sid_same(&sid->addr, sid_addr))
				return sid;

	return NULL;
}

struct static_srv6_locator *static_srv6_locator_alloc(const char *name)
{
	struct static_srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_STATIC_SRV6_LOCATOR, sizeof(struct static_srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));
	locator->srv6_sids = list_new();
	locator->srv6_sids->del = delete_static_srv6_sid;

	QOBJ_REG(locator, static_srv6_locator);
	return locator;
}

void static_srv6_locator_free(struct static_srv6_locator *locator)
{
	if (locator) {
		QOBJ_UNREG(locator);
		list_delete(&locator->srv6_sids);

		XFREE(MTYPE_STATIC_SRV6_LOCATOR, locator);
	}
}

void delete_static_srv6_locator(void *val)
{
	static_srv6_locator_free((struct static_srv6_locator *)val);
}

/*
 * Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID.
 */
void static_srv6_sid_del(struct static_srv6_sid *sid)
{
	// if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_release_srv6_sid(sid);
		static_zebra_srv6_sid_uninstall(sid);

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

void delete_static_srv6_sid(void *val)
{
	static_srv6_sid_free((struct static_srv6_sid *)val);
}

/*
 * Initialize SRv6 data structures.
 */
void static_srv6_init(void)
{
	srv6_locators = list_new();
	// srv6_sids->del = (void (*)(void *))static_srv6_sid_del;
}

/*
 * Clean up all the SRv6 data structures.
 */
void static_srv6_cleanup(void)
{
	list_delete(&srv6_locators);
}