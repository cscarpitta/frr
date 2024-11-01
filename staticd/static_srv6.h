// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - Segment Routing over IPv6 (SRv6) header
 * Copyright (C) 2024 Carmine Scarpitta
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
	STATIC_SRV6_SID_BEHAVIOR_END = 1,
	STATIC_SRV6_SID_BEHAVIOR_END_X = 2,
	STATIC_SRV6_SID_BEHAVIOR_END_DT6 = 3,
	STATIC_SRV6_SID_BEHAVIOR_END_DT4 = 4,
	STATIC_SRV6_SID_BEHAVIOR_END_DT46 = 5,
	STATIC_SRV6_SID_BEHAVIOR_UN = 6,
	STATIC_SRV6_SID_BEHAVIOR_UA = 7,
	STATIC_SRV6_SID_BEHAVIOR_UDT6 = 8,
	STATIC_SRV6_SID_BEHAVIOR_UDT4 = 9,
	STATIC_SRV6_SID_BEHAVIOR_UDT46 = 10,

};

/* Attributes for an SRv6 SID */
struct static_srv6_sid_attributes {
	/* VRF name */
	char vrf_name[VRF_NAMSIZ];
	char ifname[IFNAMSIZ];
	struct in6_addr nh6;
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

	struct static_srv6_locator *locator;

	char opcode[256];

	// QOBJ_FIELDS;
};
// DECLARE_QOBJ_TYPE(static_srv6_sid);

struct static_srv6_locator {
	char name[SRV6_LOCNAME_SIZE];
	struct prefix_ipv6 prefix;

	/*
	 * Bit length of SRv6 locator described in
	 * draft-ietf-bess-srv6-services-05#section-3.2.1
	 */
	uint8_t block_bits_length;
	uint8_t node_bits_length;
	uint8_t function_bits_length;
	uint8_t argument_bits_length;

	uint8_t flags;
#define SRV6_LOCATOR_USID (1 << 0) /* The SRv6 Locator is a uSID Locator */
	
	struct list *srv6_sids;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(static_srv6_locator);

/* List of SRv6 SIDs. */
extern struct list *srv6_locators;
// extern struct list *srv6_sids;

// /* Print current Segment Routing configuration on VTY. */
// int static_sr_config_write(struct vty *vty);

/* Allocate an SRv6 SID object and initialize its fields, SID address and
 * behavor. */
extern struct static_srv6_sid *
static_srv6_sid_alloc(struct in6_addr *addr);
extern void
static_srv6_sid_free(struct static_srv6_sid *sid);
/* Add an SRv6 SID to the list of SRv6 SIDs. Also, if the SID is valid, add the
 * SID to the zebra RIB. */
// extern void static_srv6_sid_add(struct static_srv6_sid *sid);
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
// const char *
// static_srv6_sid_behavior2clistr(enum static_srv6_sid_behavior_t action);

/* Initialize SRv6 data structures. */
extern void static_srv6_init(void);
/* Clean up all the SRv6 data structures. */
extern void static_srv6_cleanup(void);

/* When a VRF is enabled by the kernel, go through all the static SRv6 SIDs in
 * the system that use this VRF (e.g., End.DT4 or End.DT6 SRv6 SIDs) and install
 * them in the zebra RIB. */
void static_fixup_vrf_srv6_sids(struct static_vrf *enable_svrf);
/* When a VRF is shutdown by the kernel, we call this function and it removes
 * all static SRv6 SIDs using this VRF from the zebra RIB (e.g., End.DT4 or
 * End.DT6 SRv6 SIDs). */
void static_cleanup_vrf_srv6_sids(struct static_vrf *disable_svrf);

struct static_srv6_locator *static_srv6_locator_alloc(const char *name);
void static_srv6_locator_free(struct static_srv6_locator *locator);
struct static_srv6_locator *static_srv6_locator_lookup(const char *name);

void delete_static_srv6_sid(void *val);
void delete_static_srv6_locator(void *val);

#ifdef __cplusplus
}
#endif

#endif /* __STATIC_SRV6_H__ */