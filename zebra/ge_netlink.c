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


static int16_t seg6_genl_family = -1;

static int netlink_seg6_genl_parse_family(struct nlmsghdr *h, ns_id_t ns_id,
					  int startup)
{
	int len;
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	struct rtattr *attrs;

	if (h->nlmsg_type != GENL_ID_CTRL) {
		zlog_err(
			"Not a controller message, nlmsg_len=%d nlmsg_type=0x%x",
			h->nlmsg_len, h->nlmsg_type);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		zlog_err(
			"Message received from netlink is of a broken size %d %zu",
			h->nlmsg_len, (size_t)NLMSG_LENGTH(GENL_HDRLEN));
		return -1;
	}

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		zlog_err("Unknown controller command %d", ghdr->cmd);
		return -1;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	netlink_parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
		zlog_err("Missing family id TLV");
		return -1;
	}

	seg6_genl_family = *(int16_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);

	return 0;
}

int genl_resolve_family(const char *family, struct zebra_dplane_ctx *ctx)
{
	struct zebra_ns *zns;
	struct genl_request req;

	memset(&req, 0, sizeof(req));

	zns = zebra_ns_lookup(dplane_ctx_get_ns_sock(ctx));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = GENL_ID_CTRL;

	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.g.cmd = CTRL_CMD_GETFAMILY;
	req.g.version = 0;

	if (!nl_attr_put(&req.n, sizeof(req), CTRL_ATTR_FAMILY_NAME, family,
			 strlen(family) + 1))
		return 0;

	if (strmatch(family, "SEG6"))
		return ge_netlink_talk(netlink_seg6_genl_parse_family, &req.n,
				       zns, false);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Unsupported Generic Netlink family");

	return -1;
}

/*
 * sr tunsrc change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
ssize_t netlink_sr_tunsrc_set_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					 void *buf, size_t buflen)
{
	struct nlsock *nl;
	const struct in6_addr *tunsrc_addr;
	struct genl_request *req = buf;

	tunsrc_addr = dplane_ctx_get_sr_tunsrc_addr(ctx);

	if (buflen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	if (seg6_genl_family < 0)
		if (genl_resolve_family("SEG6", ctx)) {
			zlog_err("%s: generic netlink resolve family failed",
				 __func__);
			return -1;
		}

	req->n.nlmsg_type = seg6_genl_family;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->g.cmd = cmd;
	req->g.version = SEG6_GENL_VERSION;

	switch (cmd) {
	case SEG6_CMD_SET_TUNSRC:
		if (!nl_attr_put(&req->n, buflen, SEG6_ATTR_DST, tunsrc_addr,
				 sizeof(struct in6_addr)))
			return 0;
		break;
	default:
		zlog_err("%s: unsupported command (%u)", __func__, cmd);
		return -1;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

ssize_t netlink_sr_tunsrc_set_msg_encoder(struct zebra_dplane_ctx *ctx,
					  void *buf, size_t buflen)
{
	enum dplane_op_e op;
	int cmd = 0;

	op = dplane_ctx_get_op(ctx);

	/* Call to netlink layer based on type of operation */
	switch (op) {
	case DPLANE_OP_SR_TUNSRC_SET:
		/* Validate */
		if (dplane_ctx_get_sr_tunsrc_addr(ctx) == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"sr tunsrc set failed: SRv6 encap source address not set");
			return -1;
		}

		cmd = SEG6_CMD_SET_TUNSRC;

		break;
	default:
		/* Invalid op */
		zlog_err(
			"%s: context received for kernel sr tunsrc update with incorrect OP code (%u)",
			__func__, op);
		return -1;
	}

	return netlink_sr_tunsrc_set_msg_encode(cmd, ctx, buf, buflen);
}

enum netlink_msg_status
netlink_put_sr_tunsrc_set_msg(struct nl_batch *bth,
			      struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	struct zebra_ns *zns;
	struct genl_request req;

	op = dplane_ctx_get_op(ctx);
	assert(op == DPLANE_OP_SR_TUNSRC_SET);

	netlink_sr_tunsrc_set_msg_encoder(ctx, &req, sizeof(req));

	zns = zebra_ns_lookup(dplane_ctx_get_ns_sock(ctx));


	return ge_netlink_talk(netlink_talk_filter, &req.n, zns, false);
}

#endif /* HAVE_NETLINK */
