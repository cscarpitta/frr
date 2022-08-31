/*
 * Zebra connect library for staticd
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
 */
#ifndef __STATIC_ZEBRA_H__
#define __STATIC_ZEBRA_H__

#include "static_srv6.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct thread_master *master;

extern void static_zebra_nht_register(struct static_nexthop *nh, bool reg);

extern void static_zebra_route_add(struct static_path *pn, bool install);
extern void static_zebra_init(void);
/* static_zebra_stop used by tests/lib/test_grpc.cpp */
extern void static_zebra_stop(void);
extern void static_zebra_vrf_register(struct vrf *vrf);
extern void static_zebra_vrf_unregister(struct vrf *vrf);

/* Install an SRv6 SID in the zebra RIB. */
extern void static_zebra_srv6_sid_add(struct static_srv6_sid *sid);
/* Remove an SRv6 SID from the zebra RIB. */
extern void static_zebra_srv6_sid_del(struct static_srv6_sid *sid);
/* This function can be used to update the zebra RIB after a SID's validity flag
 * changes. If the SID is valid and was not previously installed in the zebra
 * RIB, this function installs the SID in the zebra RIB. If the SID is invalid
 * and was previously installed in the zebra RIB, this function removes the SID
 * from the zebra RIB. */
extern void static_zebra_srv6_sid_update(struct static_srv6_sid *sid);

#ifdef __cplusplus
}
#endif

#endif
