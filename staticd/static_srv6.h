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

#ifdef __cplusplus
extern "C" {
#endif

#include "vrf.h"


enum static_srv6_sid_behavior_t {
	STATIC_SRV6_SID_BEHAVIOR_UNSPEC = 0,
	STATIC_SRV6_SID_BEHAVIOR_END = 1,
	STATIC_SRV6_SID_BEHAVIOR_END_X = 2,
	STATIC_SRV6_SID_BEHAVIOR_END_T = 3,
	STATIC_SRV6_SID_BEHAVIOR_END_DX2 = 4,
	STATIC_SRV6_SID_BEHAVIOR_END_DX6 = 5,
	STATIC_SRV6_SID_BEHAVIOR_END_DX4 = 6,
	STATIC_SRV6_SID_BEHAVIOR_END_DT6 = 7,
	STATIC_SRV6_SID_BEHAVIOR_END_DT4 = 8,
	STATIC_SRV6_SID_BEHAVIOR_END_B6 = 9,
	STATIC_SRV6_SID_BEHAVIOR_END_B6_ENCAP = 10,
	STATIC_SRV6_SID_BEHAVIOR_END_BM = 11,
	STATIC_SRV6_SID_BEHAVIOR_END_S = 12,
	STATIC_SRV6_SID_BEHAVIOR_END_AS = 13,
	STATIC_SRV6_SID_BEHAVIOR_END_AM = 14,
	STATIC_SRV6_SID_BEHAVIOR_END_BPF = 15,
};

struct static_srv6_sid {
	struct in6_addr addr;
	enum static_srv6_sid_behavior_t behavior;
	char vrf_name[VRF_NAMSIZ];

	/* SRv6 SID flags */
	uint8_t flags;
/* This SRv6 SID is valid and can be installed in the zebra RIB. */
#define STATIC_FLAG_SRV6_SID_VALID     (1 << 0)
/* This SRv6 SID has been installed in the zebra RIB. */
#define STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA     (2 << 0)

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(static_srv6_sid);

extern struct list *srv6_sids;

int static_sr_config_write(struct vty *vty);

extern struct static_srv6_sid *
srv6_sid_alloc(struct in6_addr *addr, enum static_srv6_sid_behavior_t behavior);
extern void static_srv6_sid_add(struct static_srv6_sid *sid);
extern struct static_srv6_sid *
static_srv6_sid_lookup(struct in6_addr *sid_addr);
extern void static_srv6_sid_free(struct static_srv6_sid *sid);
extern void static_srv6_sid_del(struct static_srv6_sid *sid);

const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t action);

const char *
static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t action);

json_object *srv6_sid_json(const struct static_srv6_sid *sid);
json_object *srv6_sid_detailed_json(const struct static_srv6_sid *sid);

extern void static_srv6_init(void);
extern void static_srv6_cleanup(void);

void mark_srv6_sid_as_valid(struct static_srv6_sid *sid, bool is_valid);

void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf);
void static_cleanup_vrf_srv6_sids(struct static_vrf *disable_svrf);

#ifdef __cplusplus
}
#endif

#endif
