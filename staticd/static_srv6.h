/*
 * STATICd - SRv6 header
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
#ifndef __STATIC_SRV6_H__
#define __STATIC_SRV6_H__

#include "vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions for SRv6 behaviors used by STATIC.
 */
enum static_srv6_sid_behavior_t {
	STATIC_SRV6_SID_BEHAVIOR_UNSPEC = 0,
	/* node segment */
	STATIC_SRV6_SID_BEHAVIOR_END = 1,
	/* adjacency segment (IPv6 cross-connect) */
	STATIC_SRV6_SID_BEHAVIOR_END_X = 2,
	/* lookup of next seg NH in table */
	STATIC_SRV6_SID_BEHAVIOR_END_T = 3,
	/* decap and L2 cross-connect */
	STATIC_SRV6_SID_BEHAVIOR_END_DX2 = 4,
	/* decap and IPv6 cross-connect */
	STATIC_SRV6_SID_BEHAVIOR_END_DX6 = 5,
	/* decap and IPv4 cross-connect */
	STATIC_SRV6_SID_BEHAVIOR_END_DX4 = 6,
	/* decap and lookup of DA in v6 table */
	STATIC_SRV6_SID_BEHAVIOR_END_DT6 = 7,
	/* decap and lookup of DA in v4 table */
	STATIC_SRV6_SID_BEHAVIOR_END_DT4 = 8,
	/* binding segment with insertion */
	STATIC_SRV6_SID_BEHAVIOR_END_B6 = 9,
	/* binding segment with encapsulation */
	STATIC_SRV6_SID_BEHAVIOR_END_B6_ENCAP = 10,
	/* binding segment with MPLS encap */
	STATIC_SRV6_SID_BEHAVIOR_END_BM = 11,
	/* lookup last seg in table */
	STATIC_SRV6_SID_BEHAVIOR_END_S = 12,
	/* forward to SR-unaware VNF with static proxy */
	STATIC_SRV6_SID_BEHAVIOR_END_AS = 13,
	/* forward to SR-unaware VNF with masquerading */
	STATIC_SRV6_SID_BEHAVIOR_END_AM = 14,
	/* custom BPF action */
	STATIC_SRV6_SID_BEHAVIOR_END_BPF = 15,
	/* decap and lookup of DA in v4 or v6 table */
	STATIC_SRV6_SID_BEHAVIOR_END_DT46 = 16,
	/* decap and lookup of DA in v4 table (uSID) */
	STATIC_SRV6_SID_BEHAVIOR_UDT4 = 100,
	/* decap and lookup of DA in v6 table (uSID) */
	STATIC_SRV6_SID_BEHAVIOR_UDT6 = 101,
	/* decap and lookup of DA in v4 or v6 table (uSID) */
	STATIC_SRV6_SID_BEHAVIOR_UDT46 = 102,
	/* shift and lookup */
	STATIC_SRV6_SID_BEHAVIOR_UN = 103,
	/* shift and cross-connect */
	STATIC_SRV6_SID_BEHAVIOR_UA = 104,
};

/* Attributes for an SRv6 SID */
struct static_srv6_sid_attributes {
	/* VRF name */
	char vrf_name[VRF_NAMSIZ];
	/* Interface name */
	char ifname[IF_NAMESIZE];
	/* IPv6 adjacency */
	struct in6_addr adj_v6;
};

/* Static SRv6 SID */
struct static_srv6_sid {
	/* SRv6 SID address */
	struct in6_addr addr;
	/* behavior bound to the SRv6 SID */
	enum static_srv6_sid_behavior_t behavior;
	/* SID attributes */
	struct static_srv6_sid_attributes attributes;

	/* SRv6 SID flags */
	uint8_t flags;
/* this SRv6 SID is valid and can be installed in the zebra RIB */
#define STATIC_FLAG_SRV6_SID_VALID (1 << 0)
/* this SRv6 SID has been installed in the zebra RIB */
#define STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA (2 << 0)

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(static_srv6_sid);

/* List of SRv6 SIDs. */
extern struct list *srv6_sids;

/* Print current Segment Routing configuration on VTY. */
int static_sr_config_write(struct vty *vty);

/* Allocate an SRv6 SID object and initialize its fields, SID address and
 * behavor. */
extern struct static_srv6_sid *
srv6_sid_alloc(struct in6_addr *addr, enum static_srv6_sid_behavior_t behavior);
/* Add an SRv6 SID to the list of SRv6 SIDs. Also, if the SID is valid, add the
 * SID to the zebra RIB. */
extern void static_srv6_sid_add(struct static_srv6_sid *sid);
/* Look-up an SRv6 SID in the list of SRv6 SIDs. */
extern struct static_srv6_sid *
static_srv6_sid_lookup(struct in6_addr *sid_addr);
/* Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID. */
extern void static_srv6_sid_del(struct static_srv6_sid *sid);

/* Convert SRv6 behavior to human-friendly string. */
const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t action);
/* Convert SRv6 behavior to human-friendly string, used in CLI output. */
const char *
static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t action);

/* Return a JSON representation of an SRv6 SID. */
json_object *srv6_sid_json(const struct static_srv6_sid *sid);
/* Return a detailed JSON representation of an SRv6 SID. */
json_object *srv6_sid_detailed_json(const struct static_srv6_sid *sid);

/* Initialize SRv6 data structures. */
extern void static_srv6_init(void);
/* Clean up all the SRv6 data structures. */
extern void static_srv6_cleanup(void);

/* Mark an SRv6 SID as "valid" or "invalid" and update the zebra RIB
 * accordingly. An SRv6 SID is considered "valid" when all the mandatory
 * attributes have been set. On the contrary, a SID is "invalid" when one or
 * more mandatory attributes have not yet been configured. */
void mark_srv6_sid_as_valid(struct static_srv6_sid *sid, bool is_valid);

/* When a VRF is enabled by the kernel, go through all the static SRv6 SIDs in
 * the system that use this VRF (e.g., End.DT4 or End.DT6 SRv6 SIDs) and install
 * them in the zebra RIB. */
void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf);
/* When a VRF is shutdown by the kernel, we call this function and it removes
 * all static SRv6 SIDs using this VRF from the zebra RIB (e.g., End.DT4 or
 * End.DT6 SRv6 SIDs). */
void static_cleanup_vrf_srv6_sids(struct static_vrf *disable_svrf);

#ifdef __cplusplus
}
#endif

#endif /* __STATIC_SRV6_H__ */
