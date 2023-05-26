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
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_route.h"
#include "isisd/isis_srv6.h"
#include "isisd/isis_zebra.h"

/* Local variables and functions */
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_SID, "ISIS SRv6 Segment ID");
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_INFO, "ISIS SRv6 information");

// static void srv6_endx_sid_update(struct srv6_adjacency *sra,
// 			      struct srv6_locator_chunk *chunk);
static void srv6_endx_sid_del(struct srv6_adjacency *sra);

/**
 * Fill in SRv6 SID Structure Sub-Sub-TLV with information from an SRv6 SID
 *
 * @param sid				    SRv6 SID configuration
 * @param structure_subsubtlv	SRv6 SID Structure Sub-Sub-TLV to be updated
 */
void isis_srv6_sid_structure2subsubtlv(
	const struct isis_srv6_sid *sid,
	struct isis_srv6_sid_structure_subsubtlv *structure_subsubtlv)
{
	/* Set Locator Block length */
	structure_subsubtlv->loc_block_len = sid->structure.loc_block_len;

	/* Set Locator Node length */
	structure_subsubtlv->loc_node_len = sid->structure.loc_node_len;

	/* Set Function length */
	structure_subsubtlv->func_len = sid->structure.func_len;

	/* Set Argument length */
	structure_subsubtlv->arg_len = sid->structure.arg_len;
}

/**
 * Fill in SRv6 End SID Sub-TLV with information from an SRv6 End SID.
 *
 * @param sid	      SRv6 End SID configuration
 * @param sid_subtlv  SRv6 End SID Sub-TLV to be updated
 */
void isis_srv6_end_sid2subtlv(const struct isis_srv6_sid *sid,
			      struct isis_srv6_end_sid_subtlv *sid_subtlv)
{
	/* Set SRv6 End SID flags */
	sid_subtlv->flags = sid->flags;

	/* Set SRv6 EndSID behavior */
	sid_subtlv->behavior = (CHECK_FLAG(sid->locator->flags, SRV6_LOCATOR_USID)) ? SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID : SRV6_ENDPOINT_BEHAVIOR_END;

	/* Set SRv6 End SID value */
	sid_subtlv->value = sid->value;
}

/**
 * Fill in SRv6 Locator TLV with information from an SRv6 locator.
 *
 * @param loc	     SRv6 Locator configuration
 * @param loc_tlv    SRv6 Locator TLV to be updated
 */
void isis_srv6_locator2tlv(const struct isis_srv6_locator *loc,
			   struct isis_srv6_locator_tlv *loc_tlv)
{
	/* Set SRv6 Locator metric */
	loc_tlv->metric = loc->metric;

	/* Set SRv6 Locator flags */
	loc_tlv->flags = loc->flags;

	/* Set SRv6 Locator algorithm */
	loc_tlv->algorithm = loc->algorithm;

	/* Set SRv6 Locator prefix */
	loc_tlv->prefix = loc->prefix;
}

/* Unset SRv6 locator */
int isis_srv6_locator_unset(struct isis_area *area)
{
	int ret;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct isis_srv6_sid *sid;
	struct srv6_adjacency *sra;

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

	/* Uninstall all local Adjacency-SIDs. */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

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
	struct isis_srv6_sid *s;

	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, s))
		if (sid_same(&s->value, sid))
			return true;
	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_endx_sids, node, s))
		if (sid_same(&s->value, sid))
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

	/* Fill SRv6 SID structure */
	sid->structure.loc_block_len = srv6_locator_chunk->block_bits_length;
	sid->structure.loc_node_len = srv6_locator_chunk->node_bits_length;
	sid->structure.func_len = srv6_locator_chunk->function_bits_length;
	sid->structure.arg_len = srv6_locator_chunk->argument_bits_length;


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
		 &sid->value);

	return sid;
}

void isis_srv6_sid_free(struct isis_srv6_sid **sid)
{
	XFREE(MTYPE_ISIS_SRV6_SID, *sid);
}

/**
 * Delete all backup SRv6 End.X SIDs.
 *
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
void isis_area_delete_backup_srv6_endx_sids(struct isis_area *area, int level)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode, sra))
		if (sra->type == ISIS_SRV6_LAN_BACKUP
		    && (sra->adj->level & level))
			srv6_endx_sid_del(sra);
}

/* --- SRv6 End.X SID management functions ------------------- */

/**
 * Add new local End.X SID.
 *
 * @param adj	   IS-IS Adjacency
 * @param backup   True to initialize backup Adjacency SID
 * @param nexthops List of backup nexthops (for backup End.X SIDs only)
 */
void srv6_endx_sid_add_single(struct isis_adjacency *adj, bool backup,
			   struct list *nexthops)
{
	struct isis_circuit *circuit = adj->circuit;
	struct isis_area *area = circuit->area;
	struct srv6_adjacency *sra;
	struct isis_srv6_endx_sid_subtlv *adj_sid;
	struct isis_srv6_lan_endx_sid_subtlv *ladj_sid;
	struct in6_addr nexthop = {};
	uint8_t flags = 0;
	struct isis_srv6_sid *sid;
	struct srv6_locator_chunk* chunk;

	if (!area || !area->srv6db.srv6_locator_chunks || list_isempty(area->srv6db.srv6_locator_chunks))
		return;

	sr_debug("ISIS-SRv6 (%s): Add %s End.X SID", area->area_tag,
		 backup ? "Backup" : "Primary");

	/* Determine nexthop IP address */
	if (!circuit->ipv6_router || !adj->ll_ipv6_count)
		return;
	
	chunk = (struct srv6_locator_chunk *)listgetdata(
		listhead(area->srv6db.srv6_locator_chunks));
	if (!chunk)
		return;

	nexthop = adj->ll_ipv6_addrs[0];

	/* Prepare SRv6 End.X as per RFC9352 section #8.1 */
	if (backup)
		SET_FLAG(flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG);

	/* Get a SID from the SRv6 locator for this Adjacency */
	sid = isis_srv6_sid_alloc(area, 0, chunk,
					ZEBRA_SEG6_LOCAL_ACTION_END_X);
	if (!sid)
		return;

	if (circuit->ext == NULL)
		circuit->ext = isis_alloc_ext_subtlvs();

	sra = XCALLOC(MTYPE_ISIS_SRV6_INFO, sizeof(*sra));
	sra->type = backup ? ISIS_SRV6_LAN_BACKUP : ISIS_SRV6_ADJ_NORMAL;
	sra->sid = sid;
	sra->nexthop = nexthop;

	// if (backup && nexthops) {
	// 	struct isis_vertex_adj *vadj;
	// 	struct listnode *node;

	// 	sra->backup_nexthops = list_new();
	// 	for (ALL_LIST_ELEMENTS_RO(nexthops, node, vadj)) {
	// 		struct isis_adjacency *adj = vadj->sadj->adj;
	// 		struct mpls_label_stack *label_stack;

	// 		label_stack = vadj->label_stack;
	// 		adjinfo2nexthop(family, sra->backup_nexthops, adj, NULL,
	// 				label_stack);
	// 	}
	// }

	switch (circuit->circ_type) {
	/* SRv6 LAN End.X SID for Broadcast interface section #8.2 */
	case CIRCUIT_T_BROADCAST:
		ladj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*ladj_sid));
		memcpy(ladj_sid->neighbor_id, adj->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->flags = flags;
		ladj_sid->algorithm = SR_ALGORITHM_SPF;
		ladj_sid->weight = 0;
		ladj_sid->behavior = CHECK_FLAG(chunk->flags, SRV6_LOCATOR_USID) ? SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID : SRV6_ENDPOINT_BEHAVIOR_END_X;
		ladj_sid->value = sid->value;
		ladj_sid->subsubtlvs = isis_alloc_subsubtlvs(ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);
		isis_subsubtlvs_set_srv6_sid_structure(ladj_sid->subsubtlvs, sid);
		isis_tlvs_add_srv6_lan_endx_sid(circuit->ext, ladj_sid);
		sra->u.lendx_sid = ladj_sid;
		break;
	/* SRv6 End.X SID for Point to Point interface section #8.1 */
	case CIRCUIT_T_P2P:
		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->flags = flags;
		adj_sid->algorithm = SR_ALGORITHM_SPF;
		adj_sid->weight = 0;
		adj_sid->behavior = CHECK_FLAG(chunk->flags, SRV6_LOCATOR_USID) ? SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID : SRV6_ENDPOINT_BEHAVIOR_END_X;
		adj_sid->value = sid->value;
		adj_sid->subsubtlvs = isis_alloc_subsubtlvs(ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);
		isis_subsubtlvs_set_srv6_sid_structure(adj_sid->subsubtlvs, sid);
		isis_tlvs_add_srv6_endx_sid(circuit->ext, adj_sid);
		sra->u.endx_sid = adj_sid;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	/* Add Adjacency-SID in SRDB */
	sra->adj = adj;
	listnode_add(area->srv6db.srv6_endx_sids, sra);
	listnode_add(adj->srv6_endx_sids, sra);

	isis_zebra_srv6_endx_sid_install(sra);
}

/**
 * Add Primary and Backup local SRv6 End.X SID.
 *
 * @param adj	  IS-IS Adjacency
 */
void srv6_endx_sid_add(struct isis_adjacency *adj)
{
	srv6_endx_sid_add_single(adj, false, NULL);
}

// /**
//  * Update local SRv6 End.X SID.
//  *
//  * @param sra	SRv6 Adjacency
//  * @param chunk	New SRv6 locator chunk
//  */
// static void srv6_endx_sid_update(struct srv6_adjacency *sra,
// 			      struct srv6_locator_chunk *chunk)
// {
// 	struct isis_circuit *circuit = sra->adj->circuit;
// 	struct isis_area *area = circuit->area;

// 	/* First remove the old SRv6 SID */
// 	isis_zebra_end_sid_uninstall(area, sra->sid);

// 	/* Got new SID in the new SRv6 locator chunk */
// 	sra->sid = isis_srv6_sid_alloc(area, 0, chunk,
// 					ZEBRA_SEG6_LOCAL_ACTION_END_X);
// 	if (!sra->sid)
// 		return;

// 	switch (circuit->circ_type) {
// 	case CIRCUIT_T_BROADCAST:
// 		sra->u.lendx_sid->value = sra->sid->value;
// 		break;
// 	case CIRCUIT_T_P2P:
// 		sra->u.endx_sid->value = sra->sid->value;
// 		break;
// 	default:
// 		flog_warn(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
// 			  __func__, circuit->circ_type);
// 		break;
// 	}

// 	/* Finally configure the new MPLS Label */
// 	isis_zebra_end_sid_install(area, sra->sid);
// }

/**
 * Delete local SRv6 End.X SID.
 *
 * @param sra	SRv6 Adjacency
 */
static void srv6_endx_sid_del(struct srv6_adjacency *sra)
{
	struct isis_circuit *circuit = sra->adj->circuit;
	struct isis_area *area = circuit->area;

	sr_debug("ISIS-SRv6 (%s): Delete SRv6 End.X SID", area->area_tag);

	isis_zebra_srv6_endx_sid_uninstall(sra);

	/* Release dynamic SRv6 SID and remove subTLVs */
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		isis_tlvs_del_srv6_lan_endx_sid(circuit->ext, sra->u.lendx_sid);
		break;
	case CIRCUIT_T_P2P:
		isis_tlvs_del_srv6_endx_sid(circuit->ext, sra->u.endx_sid);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	if (sra->type == ISIS_SRV6_LAN_BACKUP && sra->backup_nexthops) {
		sra->backup_nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&sra->backup_nexthops);
	}

	/* Remove Adjacency-SID from the SRDB */
	listnode_delete(area->srv6db.srv6_endx_sids, sra);
	listnode_delete(sra->adj->srv6_endx_sids, sra);
	XFREE(MTYPE_ISIS_SRV6_INFO, sra);
}

/**
 * Lookup SRv6 End.X SID by type.
 *
 * @param adj	  IS-IS Adjacency
 * @param type    SRv6 End.X SID type
 */
struct srv6_adjacency *isis_srv6_endx_sid_find(struct isis_adjacency *adj,
					  enum srv6_adj_type type)
{
	struct srv6_adjacency *sra;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj->srv6_endx_sids, node, sra))
		if (sra->type == type)
			return sra;

	return NULL;
}

/**
 * Remove all SRv6 End.X SIDs associated to an adjacency that is going down.
 *
 * @param adj	IS-IS Adjacency
 *
 * @return	0
 */
static int srv6_adj_state_change(struct isis_adjacency *adj)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srv6db.enabled)
		return 0;

	if (adj->adj_state == ISIS_ADJ_UP)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->adj_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

	return 0;
}

/**
 * When IS-IS Adjacency got one or more IPv6 addresses, add new
 * IPv6 address to corresponding SRv6 End.X SID accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int srv6_adj_ip_enabled(struct isis_adjacency *adj, int family,
			     bool global)
{
	if (!adj->circuit->area->srv6db.enabled || global || family != AF_INET6)
		return 0;

	srv6_endx_sid_add(adj);

	return 0;
}

/**
 * When IS-IS Adjacency doesn't have any IPv6 addresses anymore,
 * delete the corresponding SRv6 End.X SID(s) accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int srv6_adj_ip_disabled(struct isis_adjacency *adj, int family,
			      bool global)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srv6db.enabled || global || family != AF_INET6)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

	return 0;
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
			tt, "%pSY|%s|%u|%u|%u|%u", lsp->hdr.lsp_id,
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
	srv6db->srv6_endx_sids = list_new();

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
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	sr_debug("ISIS-SRv6 (%s): Terminate SRv6", area->area_tag);

	/* Uninstall all local SRv6 End.X SIDs */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

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

	/* Register hooks. */
	hook_register(isis_adj_state_change_hook, srv6_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, srv6_adj_ip_enabled);
	hook_register(isis_adj_ip_disabled_hook, srv6_adj_ip_disabled);
}

/**
 * IS-IS SRv6 global terminate.
 */
void isis_srv6_term(void)
{
	/* Unregister hooks. */
	hook_unregister(isis_adj_state_change_hook, srv6_adj_state_change);
	hook_unregister(isis_adj_ip_enabled_hook, srv6_adj_ip_enabled);
	hook_unregister(isis_adj_ip_disabled_hook, srv6_adj_ip_disabled);
}
