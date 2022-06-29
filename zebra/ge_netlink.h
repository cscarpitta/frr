/* Header file exported by ge_netlink.c to zebra.
 * Copyright (C) 2022  Carmine Scarpitta, University of Rome Tor Vergata
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_GE_NETLINK_H
#define _ZEBRA_GE_NETLINK_H

#ifdef HAVE_NETLINK

#include "zebra/zebra_dplane.h"


extern int genl_resolve_family(const char *family, struct zebra_dplane_ctx *ctx);
extern ssize_t netlink_sr_tunsrc_set_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   void *buf, size_t buflen);
extern ssize_t netlink_sr_tunsrc_set_msg_encoder(struct zebra_dplane_ctx *ctx,
                void *buf, size_t buflen);
struct nl_batch;
extern enum netlink_msg_status netlink_put_sr_tunsrc_set_msg(struct nl_batch *bth,
						   struct zebra_dplane_ctx *ctx);


#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_GE_NETLINK_H */