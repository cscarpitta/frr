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

/* Per-area IS-IS SRv6 Data Base (SRV6DB). */
struct isis_srv6_db {

	/* Area SRv6 configuration. */
	struct {
		/* Administrative status of SRv6 */
		bool enabled;
	} config;
};

extern void isis_srv6_area_init(struct isis_area *area);
extern void isis_srv6_area_term(struct isis_area *area);

void isis_srv6_init(void);
void isis_srv6_term(void);

#endif /* _FRR_ISIS_SRV6_H */
