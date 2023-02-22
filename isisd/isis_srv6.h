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

#ifndef _FRR_ISIS_SRV6_H
#define _FRR_ISIS_SRV6_H

/* Maximum SRv6 SID Depths supported by the router */
#define SRV6_MAX_SEG_LEFT 16
#define SRV6_MAX_END_POP 0
#define SRV6_MAX_H_ENCAPS 1
#define SRV6_MAX_END_D 2

/* SRv6 SID */
struct isis_srv6_sid {
	struct isis_srv6_sid *next;

	uint8_t flags;
	enum seg6local_action_t behavior;
	struct in6_addr value;
	struct srv6_locator_chunk *locator;
	struct isis_sid_structure structure;
};

/* Per-area IS-IS SRv6 Data Base (SRv6 DB) */
struct isis_srv6_db {
	/* Global Operational status of SRv6 */
	bool enabled;

	/* List of SRv6 Locator chunks */
	struct list *srv6_locator_chunks;

	/* List of SRv6 SIDs allocated by the IS-IS instance */
	struct list *srv6_sids;

	/* Area SRv6 configuration. */
	struct {
		/* Administrative status of SRv6 */
		bool enabled;

		/* Name of the SRv6 Locator */
		char srv6_locator_name[SRV6_LOCNAME_SIZE];

		/* Maximum Segments Left Depth supported by the router */
		uint8_t max_seg_left_msd;

		/* Maximum Maximum End Pop Depth supported by the router */
		uint8_t max_end_pop_msd;

		/* Maximum H.Encaps supported by the router */
		uint8_t max_h_encaps_msd;

		/* Maximum End D MSD supported by the router */
		uint8_t max_end_d_msd;
	} config;
};

struct isis_srv6_sid * srv6_sid_alloc(struct isis_area *area, uint32_t index,
			      struct srv6_locator_chunk *srv6_locator_chunk, enum seg6local_action_t behavior);
void srv6_sid_free(struct in6_addr **sid);

extern void isis_srv6_area_init(struct isis_area *area);
extern void isis_srv6_area_term(struct isis_area *area);

void isis_srv6_init(void);
void isis_srv6_term(void);

extern void isis_srv6_sid_free(struct isis_srv6_sid **sid);

#endif /* _FRR_ISIS_SRV6_H */
