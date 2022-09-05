/*
 * Generic Netlink functions
 * Copyright (C) 2022  Carmine Scarpitta, University of Rome Tor Vergata
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

#ifdef HAVE_NETLINK

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H

#include <linux/genetlink.h>
#include <linux/seg6_genl.h>

#include "lib/ns.h"
#include "zebra/ge_netlink.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"


static int16_t genl_family = -1;

static int netlink_genl_parse_family(struct nlmsghdr *h,
					       ns_id_t ns_id, int startup)
{
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	int len = h->nlmsg_len;
	struct rtattr *attrs;

	if (h->nlmsg_type != GENL_ID_CTRL) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
			"nlmsg_type=0x%x\n", h->nlmsg_len, h->nlmsg_type);
		return -1;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		fprintf(stderr, "wrong controller message len %d\n", len);
		return -1;
	}

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		fprintf(stderr, "Unknown controller command %d\n", ghdr->cmd);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	netlink_parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
		fprintf(stderr, "Missing family id TLV\n");
		return -1;
	}

	genl_family = *(int16_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);

	return 0;
}

int genl_resolve_family(const char *family, struct zebra_dplane_ctx *ctx)
{
    struct zebra_ns *zns;

	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	zns = zebra_ns_lookup(dplane_ctx_get_ns_sock(ctx));

    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type = GENL_ID_CTRL;

 	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 0;

    if (!nl_attr_put(&req.n, sizeof(req), CTRL_ATTR_FAMILY_NAME,
                family, strlen(family) + 1))
        return 0;

    return ge_netlink_talk(netlink_genl_parse_family, &req.n, zns,
			    false);
}

#endif /* HAVE_NETLINK */