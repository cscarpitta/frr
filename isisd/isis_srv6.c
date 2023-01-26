/*
 * This is an implementation of Segment Routing over IPv6 (SRv6) for IS-IS
 * as per draft-ietf-lsr-isis-srv6-extensions
 * https://datatracker.ietf.org/doc/html/draft-ietf-lsr-isis-srv6-extensions
 *
 * Copyright (C) 2022 University of Rome Tor Vergata
 *
 * Author: Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
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

#include "srv6.h"
#include "termtable.h"

#include "isisd/isisd.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_srv6.h"
#include "isisd/isis_zebra.h"

/* Local variables and functions */
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_SID, "ISIS SRv6 Segment ID");

/* Unset SRv6 locator */
int isis_srv6_locator_unset(struct isis_area *area)
{
	int ret;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct isis_srv6_sid *sid;

	if (strmatch(area->srv6db.config.srv6_locator_name, "")) {
		zlog_err("BUG: locator name not set (isis_srv6_locator_unset)");
		return -1;
	}

	/* Release chunk notification via ZAPI */
	ret = isis_zebra_srv6_manager_release_locator_chunk(
		area->srv6db.config.srv6_locator_name);
	if (ret < 0)
		return -1;

	/* Delete chunks */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_locator_chunks, node, nnode,
			       chunk)) {

		if (IS_DEBUG_SR)
			zlog_debug(
				"Deleting SRv6 Locator chunk (locator %s, prefix %pFX) from IS-IS area %s",
				area->srv6db.config.srv6_locator_name,
				&chunk->prefix, area->area_tag);

		if (IS_DEBUG_SR)
			zlog_debug(
				"Releasing chunk of locator %s for IS-IS area %s",
				area->srv6db.config.srv6_locator_name,
				area->area_tag);

		listnode_delete(area->srv6db.srv6_locator_chunks, chunk);
		srv6_locator_chunk_free(&chunk);
	}

	/* Delete SRv6 SIDs */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_sids, node, nnode, sid)) {

		if (IS_DEBUG_SR)
			zlog_debug(
				"Deleting SRv6 SID (locator %s, sid %pI6) from IS-IS area %s",
				area->srv6db.config.srv6_locator_name,
				&sid->value, area->area_tag);

		/* Uninstall the SRv6 SID from the forwarding plane through
		 * Zebra */
		isis_zebra_end_sid_uninstall(area, sid);

		listnode_delete(area->srv6db.srv6_sids, sid);
		XFREE(MTYPE_ISIS_SRV6_SID, sid);
	}

	/* Clear locator name */
	memset(area->srv6db.config.srv6_locator_name, 0,
	       sizeof(area->srv6db.config.srv6_locator_name));

	/* Regenerate LSPs to advertise that the locator does not exist anymore
	 */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

/**
 * Transpose SID.
 *
 * @param sid
 * @param label
 * @param offset
 * @param len
 */
static void transpose_sid(struct in6_addr *sid, uint32_t index, uint8_t offset,
			  uint8_t len)
{
	for (uint8_t idx = 0; idx < len; idx++) {
		uint8_t tidx = offset + idx;
		sid->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (index >> (len - 1 - idx) & 0x1)
			sid->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}
}

static bool sid_exist(struct isis_area *area, const struct in6_addr *sid)
{
	struct listnode *node;
	struct in6_addr *s;

	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, s))
		if (sid_same(s, sid))
			return true;
	return false;
}


/**
 * Allocate an SRv6 SID from an SRv6 locator.
 *
 */

/*
 * This function generates a new SID based on bgp->srv6_locator_chunks and
 * TODO:fix desc index. The locator and generated SID are stored in arguments
 * sid_locator and sid, respectively.
 *
 * if index != 0: try to allocate as index-mode
 * else: try to allocate as auto-mode
 */
struct isis_srv6_sid *
isis_srv6_sid_alloc(struct isis_area *area, uint32_t index,
	       struct srv6_locator_chunk *srv6_locator_chunk,
	       enum seg6local_action_t behavior)
{
	// int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	// struct listnode *node;
	// struct srv6_locator_chunk *chunk;
	// bool alloced = false;
	// int label = 0;
	// uint8_t offset = 0;
	// uint8_t func_len = 0, shift_len = 0;
	// uint32_t index_max = 0;

	struct isis_srv6_sid *sid = NULL;
	uint8_t offset = 0;
	uint8_t func_len = 0;
	uint32_t index_max;
	bool alloced = false;

	offset = srv6_locator_chunk->block_bits_length +
		 srv6_locator_chunk->node_bits_length;
	func_len = srv6_locator_chunk->function_bits_length;

	if (!area || !srv6_locator_chunk)
		return false;

	sid = XCALLOC(MTYPE_ISIS_SRV6_SID, sizeof(struct isis_srv6_sid));

	sid->value = srv6_locator_chunk->prefix.prefix;
	sid->behavior = behavior;
	sid->locator = srv6_locator_chunk;


	if (index != 0) {
		transpose_sid(&sid->value, index, offset, func_len);
		if (sid_exist(area, &sid->value)) {
			sr_debug("ISIS-SRv6 (%s): SID %pI6 already in use",
				 area->area_tag, sid);
			return NULL;
		}
	} else {
		index_max = (1 << srv6_locator_chunk->function_bits_length) - 1;
		for (uint32_t i = 1; i < index_max; i++) {
			transpose_sid(&sid->value, i, offset, func_len);
			if (sid_exist(area, &sid->value))
				continue;
			alloced = true;
			break;
		}
	}

	if (!alloced) {
		sr_debug("ISIS-SRv6 (%s): no SIDs available in locator",
			 area->area_tag);
		return NULL;
	}

	// transpose_sid(sid, index, offset, func_len);

	sr_debug("ISIS-SRv6 (%s): allocating new SID %pI6", area->area_tag,
		 sid);

	return sid;
}

void isis_srv6_sid_free(struct isis_srv6_sid **sid)
{
	XFREE(MTYPE_ISIS_SRV6_SID, *sid);
}

/**
 * Show Segment Routing over IPv6 (SRv6) Node.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_node(struct vty *vty, struct isis_area *area, int level)
{
	struct isis_lsp *lsp;
	struct ttable *tt;

	vty_out(vty, " IS-IS %s SRv6-Nodes:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(
		tt,
		"System ID|Algorithm|SRH Max SL|SRH Max End Pop|SRH Max H.encaps|SRH Max End D");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	frr_each (lspdb, &area->lspdb[level - 1], lsp) {
		struct isis_router_cap *cap;

		if (!lsp->tlvs)
			continue;
		cap = lsp->tlvs->router_cap;
		if (!cap)
			continue;

		ttable_add_row(
			tt, "%s|%s|%u|%u|%u|%u", sysid_print(lsp->hdr.lsp_id),
			cap->algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF",
			cap->srv6_msd.max_seg_left_msd,
			cap->srv6_msd.max_end_pop_msd,
			cap->srv6_msd.max_h_encaps_msd,
			cap->srv6_msd.max_end_d_msd);
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);
}

DEFUN(show_srv6_node, show_srv6_node_cmd,
      "show " PROTO_NAME " segment-routing srv6 node",
      SHOW_STR
      PROTO_HELP
      "Segment-Routing\n"
      "Segment-Routing over IPv6 (SRv6)\n"
      "SRv6 node\n")
{
	struct listnode *node, *inode;
	struct isis_area *area;
	struct isis *isis;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			vty_out(vty, "Area %s:\n",
				area->area_tag ? area->area_tag : "null");
			if (!area->srv6db.enabled) {
				vty_out(vty, " SRv6 is disabled\n");
				continue;
			}
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++)
				show_node(vty, area, level);
		}
	}

	return CMD_SUCCESS;
}

/**
 * IS-IS SRv6 initialization for given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_init(struct isis_area *area)
{
	struct isis_srv6_db *srv6db = &area->srv6db;

	sr_debug("ISIS-SRv6 (%s): Initialize Segment Routing SRv6 DB",
		 area->area_tag);

	/* Initialize SRv6 Data Base */
	memset(srv6db, 0, sizeof(*srv6db));

	/* Pull defaults from the YANG module */
	srv6db->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SRV6);

	srv6db->config.max_seg_left_msd = SRV6_MAX_SEG_LEFT;
	srv6db->config.max_end_pop_msd = SRV6_MAX_END_POP;
	srv6db->config.max_h_encaps_msd = SRV6_MAX_H_ENCAPS;
	srv6db->config.max_end_d_msd = SRV6_MAX_END_D;

	/* Initialize SRv6 Locator chunks list */
	srv6db->srv6_locator_chunks = list_new();
	srv6db->srv6_locator_chunks->del =
		(void (*)(void *))srv6_locator_chunk_free;

	/* Initialize SRv6 SIDs list */
	srv6db->srv6_sids = list_new();
	srv6db->srv6_sids->del = (void (*)(void *))isis_srv6_sid_free;

	area->srv6db.enabled = true; // TODO: temporary; to be moved
}

/**
 * Terminate IS-IS SRv6 for the given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_term(struct isis_area *area)
{
	struct isis_srv6_db *srv6db = &area->srv6db;

	sr_debug("ISIS-SRv6 (%s): Terminate SRv6", area->area_tag);

	/* Free SRv6 Locator chunks list */
	list_delete(&srv6db->srv6_locator_chunks);

	/* Free SRv6 SIDs list */
	list_delete(&srv6db->srv6_sids);
}

/**
 * IS-IS SRv6 global initialization.
 */
void isis_srv6_init(void)
{
	install_element(VIEW_NODE, &show_srv6_node_cmd);
}

/**
 * IS-IS SRv6 global terminate.
 */
void isis_srv6_term(void)
{
}
