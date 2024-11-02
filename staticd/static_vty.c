// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vty code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "vrf.h"
#include "prefix.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"
#include "mgmt_be_client.h"
#include "mpls.h"
#include "northbound.h"
#include "libfrr.h"
#include "routing_nb.h"
#include "northbound_cli.h"
#include "frrdistance.h"

#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_debug.h"
#include "staticd/static_vty_clippy.c"
#include "static_nb.h"
#include "static_srv6.h"
#include "static_zebra.h"

#define STATICD_STR "Static route daemon\n"

/** All possible route parameters available in CLI. */
struct static_route_args {
	/** "no" command? */
	bool delete;
	/** Is VRF obtained from XPath? */
	bool xpath_vrf;

	bool onlink;
	afi_t afi;
	safi_t safi;

	const char *vrf;
	const char *nexthop_vrf;
	const char *prefix;
	const char *prefix_mask;
	const char *source;
	const char *gateway;
	const char *interface_name;
	const char *segs;
	const char *flag;
	const char *tag;
	const char *distance;
	const char *label;
	const char *table;
	const char *color;

	bool bfd;
	bool bfd_multi_hop;
	const char *bfd_source;
	const char *bfd_profile;
};

static int static_route_nb_run(struct vty *vty, struct static_route_args *args)
{
	int ret;
	struct prefix p, src;
	struct in_addr mask;
	enum static_nh_type type;
	const char *bh_type;
	char xpath_prefix[XPATH_MAXLEN];
	char xpath_nexthop[XPATH_MAXLEN];
	char xpath_mpls[XPATH_MAXLEN];
	char xpath_label[XPATH_MAXLEN];
	char xpath_segs[XPATH_MAXLEN];
	char xpath_seg[XPATH_MAXLEN];
	char ab_xpath[XPATH_MAXLEN];
	char buf_prefix[PREFIX_STRLEN];
	char buf_src_prefix[PREFIX_STRLEN] = {};
	char buf_nh_type[PREFIX_STRLEN] = {};
	char buf_tag[PREFIX_STRLEN];
	uint8_t label_stack_id = 0;
	uint8_t segs_stack_id = 0;
	char *orig_label = NULL, *orig_seg = NULL;
	const char *buf_gate_str;
	uint8_t distance = ZEBRA_STATIC_DISTANCE_DEFAULT;
	route_tag_t tag = 0;
	uint32_t table_id = 0;
	const struct lyd_node *dnode;
	const struct lyd_node *vrf_dnode;

	if (args->xpath_vrf) {
		vrf_dnode = yang_dnode_get(vty->candidate_config->dnode,
					   VTY_CURR_XPATH);
		if (vrf_dnode == NULL) {
			vty_out(vty,
				"%% Failed to get vrf dnode in candidate db\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		args->vrf = yang_dnode_get_string(vrf_dnode, "name");
	} else {
		if (args->vrf == NULL)
			args->vrf = VRF_DEFAULT_NAME;
	}
	if (args->nexthop_vrf == NULL)
		args->nexthop_vrf = args->vrf;

	if (args->interface_name &&
	    !strcasecmp(args->interface_name, "Null0")) {
		args->flag = "Null0";
		args->interface_name = NULL;
	}

	assert(!!str2prefix(args->prefix, &p));

	switch (args->afi) {
	case AFI_IP:
		/* Cisco like mask notation. */
		if (args->prefix_mask) {
			assert(inet_pton(AF_INET, args->prefix_mask, &mask) ==
			       1);
			p.prefixlen = ip_masklen(mask);
		}
		break;
	case AFI_IP6:
		/* srcdest routing */
		if (args->source)
			assert(!!str2prefix(args->source, &src));
		break;
	case AFI_L2VPN:
	case AFI_UNSPEC:
	case AFI_MAX:
		break;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);
	prefix2str(&p, buf_prefix, sizeof(buf_prefix));

	if (args->bfd && args->gateway == NULL) {
		vty_out(vty, "%% Route monitoring requires a gateway\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (args->source)
		prefix2str(&src, buf_src_prefix, sizeof(buf_src_prefix));
	if (args->gateway)
		buf_gate_str = args->gateway;
	else
		buf_gate_str = "";

	if (args->gateway == NULL && args->interface_name == NULL)
		type = STATIC_BLACKHOLE;
	else if (args->gateway && args->interface_name) {
		if (args->afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY_IFNAME;
		else
			type = STATIC_IPV6_GATEWAY_IFNAME;
	} else if (args->interface_name)
		type = STATIC_IFNAME;
	else {
		if (args->afi == AFI_IP)
			type = STATIC_IPV4_GATEWAY;
		else
			type = STATIC_IPV6_GATEWAY;
	}

	/* Administrative distance. */
	if (args->distance)
		distance = strtol(args->distance, NULL, 10);

	/* tag */
	if (args->tag)
		tag = strtoul(args->tag, NULL, 10);

	/* TableID */
	if (args->table)
		table_id = strtol(args->table, NULL, 10);

	static_get_nh_type(type, buf_nh_type, sizeof(buf_nh_type));
	if (!args->delete) {
		if (args->source)
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_SRC_NH_KEY_NO_DISTANCE_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 buf_src_prefix, table_id, buf_nh_type,
				 args->nexthop_vrf, buf_gate_str,
				 args->interface_name);
		else
			snprintf(ab_xpath, sizeof(ab_xpath),
				 FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 table_id, buf_nh_type, args->nexthop_vrf,
				 buf_gate_str, args->interface_name);

		/*
		 * If there's already the same nexthop but with a different
		 * distance, then remove it for the replacement.
		 */
		dnode = yang_dnode_get(vty->candidate_config->dnode, ab_xpath);
		if (dnode) {
			dnode = yang_get_subtree_with_no_sibling(dnode);
			assert(dnode);
			yang_dnode_get_path(dnode, ab_xpath, XPATH_MAXLEN);

			nb_cli_enqueue_change(vty, ab_xpath, NB_OP_DESTROY,
					      NULL);
		}

		/* route + path procesing */
		if (args->source)
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_S_ROUTE_SRC_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 buf_src_prefix, table_id, distance);
		else
			snprintf(xpath_prefix, sizeof(xpath_prefix),
				 FRR_STATIC_ROUTE_INFO_KEY_XPATH,
				 "frr-staticd:staticd", "staticd", args->vrf,
				 buf_prefix,
				 yang_afi_safi_value2identity(args->afi,
							      args->safi),
				 table_id, distance);

		nb_cli_enqueue_change(vty, xpath_prefix, NB_OP_CREATE, NULL);

		/* Tag processing */
		snprintf(buf_tag, sizeof(buf_tag), "%u", tag);
		strlcpy(ab_xpath, xpath_prefix, sizeof(ab_xpath));
		strlcat(ab_xpath, FRR_STATIC_ROUTE_PATH_TAG_XPATH,
			sizeof(ab_xpath));
		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_MODIFY, buf_tag);

		/* nexthop processing */

		snprintf(ab_xpath, sizeof(ab_xpath),
			 FRR_STATIC_ROUTE_NH_KEY_XPATH, buf_nh_type,
			 args->nexthop_vrf, buf_gate_str, args->interface_name);
		strlcpy(xpath_nexthop, xpath_prefix, sizeof(xpath_nexthop));
		strlcat(xpath_nexthop, ab_xpath, sizeof(xpath_nexthop));
		nb_cli_enqueue_change(vty, xpath_nexthop, NB_OP_CREATE, NULL);

		if (type == STATIC_BLACKHOLE) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_BH_XPATH,
				sizeof(ab_xpath));

			/* Route flags */
			if (args->flag) {
				switch (args->flag[0]) {
				case 'r':
					bh_type = "reject";
					break;
				case 'b':
					bh_type = "unspec";
					break;
				case 'N':
					bh_type = "null";
					break;
				default:
					bh_type = NULL;
					break;
				}
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, bh_type);
			} else {
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "null");
			}
		}
		if (type == STATIC_IPV4_GATEWAY_IFNAME
		    || type == STATIC_IPV6_GATEWAY_IFNAME) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_ONLINK_XPATH,
				sizeof(ab_xpath));

			if (args->onlink)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY, "false");
		}
		if (type == STATIC_IPV4_GATEWAY ||
		    type == STATIC_IPV6_GATEWAY ||
		    type == STATIC_IPV4_GATEWAY_IFNAME ||
		    type == STATIC_IPV6_GATEWAY_IFNAME) {
			strlcpy(ab_xpath, xpath_nexthop, sizeof(ab_xpath));
			strlcat(ab_xpath, FRR_STATIC_ROUTE_NH_COLOR_XPATH,
				sizeof(ab_xpath));
			if (args->color)
				nb_cli_enqueue_change(vty, ab_xpath,
						      NB_OP_MODIFY,
						      args->color);
		}
		if (args->label) {
			/* copy of label string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));

			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);

			orig_label = ostr = XSTRDUP(MTYPE_TMP, args->label);
			while ((nump = strsep(&ostr, "/")) != NULL) {
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_STATIC_ROUTE_NHLB_KEY_XPATH,
					 label_stack_id);
				strlcpy(xpath_label, xpath_mpls,
					sizeof(xpath_label));
				strlcat(xpath_label, ab_xpath,
					sizeof(xpath_label));
				nb_cli_enqueue_change(vty, xpath_label,
						      NB_OP_MODIFY, nump);
				label_stack_id++;
			}
		} else {
			strlcpy(xpath_mpls, xpath_nexthop, sizeof(xpath_mpls));
			strlcat(xpath_mpls, FRR_STATIC_ROUTE_NH_LABEL_XPATH,
				sizeof(xpath_mpls));
			nb_cli_enqueue_change(vty, xpath_mpls, NB_OP_DESTROY,
					      NULL);
		}
		if (args->segs) {
			/* copy of seg string (start) */
			char *ostr;
			/* pointer to next segment */
			char *nump;

			strlcpy(xpath_segs, xpath_nexthop, sizeof(xpath_segs));
			strlcat(xpath_segs, FRR_STATIC_ROUTE_NH_SRV6_SEGS_XPATH,
				sizeof(xpath_segs));

			nb_cli_enqueue_change(vty, xpath_segs, NB_OP_DESTROY,
					      NULL);

			orig_seg = ostr = XSTRDUP(MTYPE_TMP, args->segs);
			while ((nump = strsep(&ostr, "/")) != NULL) {
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_STATIC_ROUTE_NH_SRV6_KEY_SEG_XPATH,
					 segs_stack_id);
				strlcpy(xpath_seg, xpath_segs,
					sizeof(xpath_seg));
				strlcat(xpath_seg, ab_xpath, sizeof(xpath_seg));
				nb_cli_enqueue_change(vty, xpath_seg,
						      NB_OP_MODIFY, nump);
				segs_stack_id++;
			}
		} else {
			strlcpy(xpath_segs, xpath_nexthop, sizeof(xpath_segs));
			strlcat(xpath_segs, FRR_STATIC_ROUTE_NH_SRV6_SEGS_XPATH,
				sizeof(xpath_segs));
			nb_cli_enqueue_change(vty, xpath_segs, NB_OP_DESTROY,
					      NULL);
		}
		if (args->bfd) {
			char xpath_bfd[XPATH_MAXLEN];

			if (args->bfd_source) {
				strlcpy(xpath_bfd, xpath_nexthop,
					sizeof(xpath_bfd));
				strlcat(xpath_bfd,
					"/frr-staticd:bfd-monitoring/source",
					sizeof(xpath_bfd));
				nb_cli_enqueue_change(vty, xpath_bfd,
						      NB_OP_MODIFY,
						      args->bfd_source);
			}

			strlcpy(xpath_bfd, xpath_nexthop, sizeof(xpath_bfd));
			strlcat(xpath_bfd,
				"/frr-staticd:bfd-monitoring/multi-hop",
				sizeof(xpath_bfd));
			nb_cli_enqueue_change(vty, xpath_bfd, NB_OP_MODIFY,
					      args->bfd_multi_hop ? "true"
								  : "false");

			if (args->bfd_profile) {
				strlcpy(xpath_bfd, xpath_nexthop,
					sizeof(xpath_bfd));
				strlcat(xpath_bfd,
					"/frr-staticd:bfd-monitoring/profile",
					sizeof(xpath_bfd));
				nb_cli_enqueue_change(vty, xpath_bfd,
						      NB_OP_MODIFY,
						      args->bfd_profile);
			}
		}

		ret = nb_cli_apply_changes(vty, "%s", xpath_prefix);

		if (orig_label)
			XFREE(MTYPE_TMP, orig_label);
		if (orig_seg)
			XFREE(MTYPE_TMP, orig_seg);
	} else {
		if (args->source) {
			if (args->distance)
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_DEL_S_ROUTE_SRC_NH_KEY_XPATH,
					 "frr-staticd:staticd", "staticd",
					 args->vrf, buf_prefix,
					 yang_afi_safi_value2identity(
						 args->afi, args->safi),
					 buf_src_prefix, table_id, distance,
					 buf_nh_type, args->nexthop_vrf,
					 buf_gate_str, args->interface_name);
			else
				snprintf(
					ab_xpath, sizeof(ab_xpath),
					FRR_DEL_S_ROUTE_SRC_NH_KEY_NO_DISTANCE_XPATH,
					"frr-staticd:staticd", "staticd",
					args->vrf, buf_prefix,
					yang_afi_safi_value2identity(
						args->afi, args->safi),
					buf_src_prefix, table_id, buf_nh_type,
					args->nexthop_vrf, buf_gate_str,
					args->interface_name);
		} else {
			if (args->distance)
				snprintf(ab_xpath, sizeof(ab_xpath),
					 FRR_DEL_S_ROUTE_NH_KEY_XPATH,
					 "frr-staticd:staticd", "staticd",
					 args->vrf, buf_prefix,
					 yang_afi_safi_value2identity(
						 args->afi, args->safi),
					 table_id, distance, buf_nh_type,
					 args->nexthop_vrf, buf_gate_str,
					 args->interface_name);
			else
				snprintf(
					ab_xpath, sizeof(ab_xpath),
					FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH,
					"frr-staticd:staticd", "staticd",
					args->vrf, buf_prefix,
					yang_afi_safi_value2identity(
						args->afi, args->safi),
					table_id, buf_nh_type,
					args->nexthop_vrf, buf_gate_str,
					args->interface_name);
		}

		dnode = yang_dnode_get(vty->candidate_config->dnode, ab_xpath);
		if (!dnode) {
			vty_out(vty,
				"%% Refusing to remove a non-existent route\n");
			return CMD_SUCCESS;
		}

		dnode = yang_get_subtree_with_no_sibling(dnode);
		assert(dnode);
		yang_dnode_get_path(dnode, ab_xpath, XPATH_MAXLEN);

		nb_cli_enqueue_change(vty, ab_xpath, NB_OP_DESTROY, NULL);
		ret = nb_cli_apply_changes(vty, "%s", ab_xpath);
	}

	return ret;
}

/* Static unicast routes for multicast RPF lookup. */
DEFPY_YANG (ip_mroute_dist,
       ip_mroute_dist_cmd,
       "[no] ip mroute A.B.C.D/M$prefix <A.B.C.D$gate|INTERFACE$ifname> [{"
       "(1-255)$distance"
       "|bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}]"
       "}]",
       NO_STR
       IP_STR
       "Configure static unicast route into MRIB for multicast RPF lookup\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Nexthop address\n"
       "Nexthop interface name\n"
       "Distance\n"
       BFD_INTEGRATION_STR
       BFD_INTEGRATION_MULTI_HOP_STR
       BFD_INTEGRATION_SOURCE_STR
       BFD_INTEGRATION_SOURCEV4_STR
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_MULTICAST,
		.prefix = prefix_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.distance = distance_str,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_nb_run(vty, &args);
}

/* Static route configuration.  */
DEFPY_YANG(ip_route_blackhole,
      ip_route_blackhole_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask>                        \
	<reject|blackhole>$flag                                               \
	[{                                                                    \
	  tag (1-4294967295)                                                  \
	  |(1-255)$distance                                                   \
	  |vrf NAME                                                           \
	  |label WORD                                                         \
          |table (1-4294967295)                                               \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.vrf = vrf,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ip_route_blackhole_vrf,
      ip_route_blackhole_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask>                        \
	<reject|blackhole>$flag                                               \
	[{                                                                    \
	  tag (1-4294967295)                                                  \
	  |(1-255)$distance                                                   \
	  |label WORD                                                         \
	  |table (1-4294967295)                                               \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.xpath_vrf = true,
	};

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(args.prefix);

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ip_route_address_interface,
      ip_route_address_interface_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	<INTERFACE|Null0>$ifname                       \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |onlink$onlink                               \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}] \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ip_route_address_interface_vrf,
      ip_route_address_interface_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	A.B.C.D$gate                                   \
	<INTERFACE|Null0>$ifname                       \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |onlink$onlink                               \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}] \
	  }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.xpath_vrf = true,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ip_route,
      ip_route_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|<INTERFACE|Null0>$ifname>        \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}] \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ip_route_vrf,
      ip_route_vrf_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	<A.B.C.D$gate|<INTERFACE|Null0>$ifname>        \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}] \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "IP gateway address\n"
      "IP gateway interface name\n"
      "Null interface\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP,
		.safi = SAFI_UNICAST,
		.prefix = prefix,
		.prefix_mask = mask_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.xpath_vrf = true,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route_blackhole,
      ipv6_route_blackhole_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <reject|blackhole>$flag                          \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
            |table (1-4294967295)                          \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.vrf = vrf,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route_blackhole_vrf,
      ipv6_route_blackhole_vrf_cmd,
      "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <reject|blackhole>$flag                          \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
            |table (1-4294967295)                          \
          }]",
      NO_STR
      IPV6_STR
      "Establish static routes\n"
      "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
      "IPv6 source-dest route\n"
      "IPv6 source prefix\n"
      "Emit an ICMP unreachable when matched\n"
      "Silently discard pkts when matched\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this prefix\n"
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.flag = flag,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.xpath_vrf = true,
	};

	/*
	 * Coverity is complaining that prefix could
	 * be dereferenced, but we know that prefix will
	 * valid.  Add an assert to make it happy
	 */
	assert(args.prefix);

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route_address_interface, ipv6_route_address_interface_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          <INTERFACE|Null0>$ifname                         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |onlink$onlink                                 \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|profile BFDPROF$bfd_profile}] \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" VRF_CMD_HELP_STR MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR
	   "Treat the nexthop as directly attached to the interface\n"
	   "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_PROFILE_STR
				   BFD_PROFILE_NAME_STR "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route_address_interface_vrf,
	   ipv6_route_address_interface_vrf_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          X:X::X:X$gate                                    \
          <INTERFACE|Null0>$ifname                         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |onlink$onlink                                 \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|profile BFDPROF$bfd_profile}] \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR
	   "Treat the nexthop as directly attached to the interface\n"
	   "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_PROFILE_STR
				   BFD_PROFILE_NAME_STR "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.onlink = !!onlink,
		.xpath_vrf = true,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route, ipv6_route_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>         \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |vrf NAME                                      \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
            |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|profile BFDPROF$bfd_profile}] \
			|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" VRF_CMD_HELP_STR MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_PROFILE_STR
				   BFD_PROFILE_NAME_STR "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.vrf = vrf,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,

	};

	return static_route_nb_run(vty, &args);
}

DEFPY_YANG(ipv6_route_vrf, ipv6_route_vrf_cmd,
	   "[no] ipv6 route X:X::X:X/M$prefix [from X:X::X:X/M] \
          <X:X::X:X$gate|<INTERFACE|Null0>$ifname>                 \
          [{                                               \
            tag (1-4294967295)                             \
            |(1-255)$distance                              \
            |label WORD                                    \
	    |table (1-4294967295)                          \
            |nexthop-vrf NAME                              \
	    |color (1-4294967295)                          \
	    |bfd$bfd [{multi-hop$bfd_multi_hop|source X:X::X:X$bfd_source|profile BFDPROF$bfd_profile}] \
		|segments WORD 								   \
          }]",
	   NO_STR IPV6_STR
	   "Establish static routes\n"
	   "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
	   "IPv6 source-dest route\n"
	   "IPv6 source prefix\n"
	   "IPv6 gateway address\n"
	   "IPv6 gateway interface name\n"
	   "Null interface\n"
	   "Set tag for this route\n"
	   "Tag value\n"
	   "Distance value for this prefix\n" MPLS_LABEL_HELPSTR
	   "Table to configure\n"
	   "The table number to configure\n" VRF_CMD_HELP_STR "SR-TE color\n"
	   "The SR-TE color to configure\n" BFD_INTEGRATION_STR
		   BFD_INTEGRATION_MULTI_HOP_STR BFD_INTEGRATION_SOURCE_STR
			   BFD_INTEGRATION_SOURCEV4_STR BFD_PROFILE_STR
				   BFD_PROFILE_NAME_STR "Value of segs\n"
	   "Segs (SIDs)\n")
{
	struct static_route_args args = {
		.delete = !!no,
		.afi = AFI_IP6,
		.safi = SAFI_UNICAST,
		.prefix = prefix_str,
		.source = from_str,
		.gateway = gate_str,
		.interface_name = ifname,
		.tag = tag_str,
		.distance = distance_str,
		.label = label,
		.table = table_str,
		.color = color_str,
		.xpath_vrf = true,
		.nexthop_vrf = nexthop_vrf,
		.bfd = !!bfd,
		.bfd_multi_hop = !!bfd_multi_hop,
		.bfd_source = bfd_source_str,
		.bfd_profile = bfd_profile,
		.segs = segments,
	};

	return static_route_nb_run(vty, &args);
}

#ifdef INCLUDE_MGMTD_CMDDEFS_ONLY

static void static_cli_show(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "../vrf");
	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, "vrf %s\n", vrf);
}

static void static_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "../vrf");
	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, "exit-vrf\n");
}

struct mpls_label_iter {
	struct vty *vty;
	bool first;
};

static int mpls_label_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct mpls_label_iter *iter = arg;

	if (yang_dnode_exists(dnode, "label")) {
		if (iter->first)
			vty_out(iter->vty, " label %s",
				yang_dnode_get_string(dnode, "label"));
		else
			vty_out(iter->vty, "/%s",
				yang_dnode_get_string(dnode, "label"));
		iter->first = false;
	}

	return YANG_ITER_CONTINUE;
}

struct srv6_seg_iter {
	struct vty *vty;
	bool first;
};

static int srv6_seg_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct srv6_seg_iter *iter = arg;
	char buffer[INET6_ADDRSTRLEN];
	struct in6_addr cli_seg;

	if (yang_dnode_exists(dnode, "seg")) {
		if (iter->first) {
			yang_dnode_get_ipv6(&cli_seg, dnode, "seg");
			if (inet_ntop(AF_INET6, &cli_seg, buffer,
				      INET6_ADDRSTRLEN) == NULL) {
				return 1;
			}
			vty_out(iter->vty, " segments %s", buffer);
		} else {
			yang_dnode_get_ipv6(&cli_seg, dnode, "seg");
			if (inet_ntop(AF_INET6, &cli_seg, buffer,
				      INET6_ADDRSTRLEN) == NULL) {
				return 1;
			}
			vty_out(iter->vty, "/%s", buffer);
		}
		iter->first = false;
	}

	return YANG_ITER_CONTINUE;
}

static void nexthop_cli_show(struct vty *vty, const struct lyd_node *route,
			     const struct lyd_node *src,
			     const struct lyd_node *path,
			     const struct lyd_node *nexthop, bool show_defaults)
{
	const char *vrf;
	const char *afi_safi;
	afi_t afi;
	safi_t safi;
	enum static_nh_type nh_type;
	enum static_blackhole_type bh_type;
	uint32_t tag;
	uint8_t distance;
	struct mpls_label_iter iter;
	struct srv6_seg_iter seg_iter;
	const char *nexthop_vrf;
	uint32_t table_id;
	bool onlink;

	vrf = yang_dnode_get_string(route, "../../vrf");

	afi_safi = yang_dnode_get_string(route, "afi-safi");
	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (afi == AFI_IP)
		vty_out(vty, "%sip",
			strmatch(vrf, VRF_DEFAULT_NAME) ? "" : " ");
	else
		vty_out(vty, "%sipv6",
			strmatch(vrf, VRF_DEFAULT_NAME) ? "" : " ");

	if (safi == SAFI_UNICAST)
		vty_out(vty, " route");
	else
		vty_out(vty, " mroute");

	vty_out(vty, " %s", yang_dnode_get_string(route, "prefix"));

	if (src)
		vty_out(vty, " from %s",
			yang_dnode_get_string(src, "src-prefix"));

	nh_type = yang_dnode_get_enum(nexthop, "nh-type");
	switch (nh_type) {
	case STATIC_IFNAME:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "interface"));
		break;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "gateway"));
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "gateway"));
		vty_out(vty, " %s",
			yang_dnode_get_string(nexthop, "interface"));
		break;
	case STATIC_BLACKHOLE:
		bh_type = yang_dnode_get_enum(nexthop, "bh-type");
		switch (bh_type) {
		case STATIC_BLACKHOLE_DROP:
			vty_out(vty, " blackhole");
			break;
		case STATIC_BLACKHOLE_NULL:
			vty_out(vty, " Null0");
			break;
		case STATIC_BLACKHOLE_REJECT:
			vty_out(vty, " reject");
			break;
		}
		break;
	}

	if (yang_dnode_exists(path, "tag")) {
		tag = yang_dnode_get_uint32(path, "tag");
		if (tag != 0 || show_defaults)
			vty_out(vty, " tag %" PRIu32, tag);
	}

	distance = yang_dnode_get_uint8(path, "distance");
	if (distance != ZEBRA_STATIC_DISTANCE_DEFAULT || show_defaults)
		vty_out(vty, " %" PRIu8, distance);

	iter.vty = vty;
	iter.first = true;
	yang_dnode_iterate(mpls_label_iter_cb, &iter, nexthop,
			   "./mpls-label-stack/entry");

	seg_iter.vty = vty;
	seg_iter.first = true;
	yang_dnode_iterate(srv6_seg_iter_cb, &seg_iter, nexthop,
			   "./srv6-segs-stack/entry");

	nexthop_vrf = yang_dnode_get_string(nexthop, "vrf");
	if (strcmp(vrf, nexthop_vrf))
		vty_out(vty, " nexthop-vrf %s", nexthop_vrf);

	table_id = yang_dnode_get_uint32(path, "table-id");
	if (table_id || show_defaults)
		vty_out(vty, " table %" PRIu32, table_id);

	if (yang_dnode_exists(nexthop, "onlink")) {
		onlink = yang_dnode_get_bool(nexthop, "onlink");
		if (onlink)
			vty_out(vty, " onlink");
	}

	if (yang_dnode_exists(nexthop, "srte-color"))
		vty_out(vty, " color %s",
			yang_dnode_get_string(nexthop, "srte-color"));

	if (yang_dnode_exists(nexthop, "bfd-monitoring")) {
		const struct lyd_node *bfd_dnode =
			yang_dnode_get(nexthop, "bfd-monitoring");

		if (yang_dnode_get_bool(bfd_dnode, "multi-hop")) {
			vty_out(vty, " bfd multi-hop");

			if (yang_dnode_exists(bfd_dnode, "source"))
				vty_out(vty, " source %s",
					yang_dnode_get_string(bfd_dnode,
							      "./source"));
		} else
			vty_out(vty, " bfd");

		if (yang_dnode_exists(bfd_dnode, "profile"))
			vty_out(vty, " profile %s",
				yang_dnode_get_string(bfd_dnode, "profile"));
	}

	vty_out(vty, "\n");
}

static void static_nexthop_cli_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *path = yang_dnode_get_parent(dnode, "path-list");
	const struct lyd_node *route =
		yang_dnode_get_parent(path, "route-list");

	nexthop_cli_show(vty, route, NULL, path, dnode, show_defaults);
}

static void static_src_nexthop_cli_show(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *path = yang_dnode_get_parent(dnode, "path-list");
	const struct lyd_node *src = yang_dnode_get_parent(path, "src-list");
	const struct lyd_node *route = yang_dnode_get_parent(src, "route-list");

	nexthop_cli_show(vty, route, src, path, dnode, show_defaults);
}

static int static_nexthop_cli_cmp(const struct lyd_node *dnode1,
				  const struct lyd_node *dnode2)
{
	enum static_nh_type nh_type1, nh_type2;
	struct prefix prefix1, prefix2;
	const char *vrf1, *vrf2;
	int ret = 0;

	nh_type1 = yang_dnode_get_enum(dnode1, "nh-type");
	nh_type2 = yang_dnode_get_enum(dnode2, "nh-type");

	if (nh_type1 != nh_type2)
		return (int)nh_type1 - (int)nh_type2;

	switch (nh_type1) {
	case STATIC_IFNAME:
		ret = if_cmp_name_func(
			yang_dnode_get_string(dnode1, "interface"),
			yang_dnode_get_string(dnode2, "interface"));
		break;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		yang_dnode_get_prefix(&prefix1, dnode1, "gateway");
		yang_dnode_get_prefix(&prefix2, dnode2, "gateway");
		ret = prefix_cmp(&prefix1, &prefix2);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		yang_dnode_get_prefix(&prefix1, dnode1, "gateway");
		yang_dnode_get_prefix(&prefix2, dnode2, "gateway");
		ret = prefix_cmp(&prefix1, &prefix2);
		if (!ret)
			ret = if_cmp_name_func(
				yang_dnode_get_string(dnode1, "interface"),
				yang_dnode_get_string(dnode2, "interface"));
		break;
	case STATIC_BLACKHOLE:
		/* There's only one blackhole nexthop per route */
		ret = 0;
		break;
	}

	if (ret)
		return ret;

	vrf1 = yang_dnode_get_string(dnode1, "vrf");
	if (strmatch(vrf1, "default"))
		vrf1 = "";
	vrf2 = yang_dnode_get_string(dnode2, "vrf");
	if (strmatch(vrf2, "default"))
		vrf2 = "";

	return if_cmp_name_func(vrf1, vrf2);
}

static int static_route_list_cli_cmp(const struct lyd_node *dnode1,
				     const struct lyd_node *dnode2)
{
	const char *afi_safi1, *afi_safi2;
	afi_t afi1, afi2;
	safi_t safi1, safi2;
	struct prefix prefix1, prefix2;

	afi_safi1 = yang_dnode_get_string(dnode1, "afi-safi");
	yang_afi_safi_identity2value(afi_safi1, &afi1, &safi1);

	afi_safi2 = yang_dnode_get_string(dnode2, "afi-safi");
	yang_afi_safi_identity2value(afi_safi2, &afi2, &safi2);

	if (afi1 != afi2)
		return (int)afi1 - (int)afi2;

	if (safi1 != safi2)
		return (int)safi1 - (int)safi2;

	yang_dnode_get_prefix(&prefix1, dnode1, "prefix");
	yang_dnode_get_prefix(&prefix2, dnode2, "prefix");

	return prefix_cmp(&prefix1, &prefix2);
}

static int static_src_list_cli_cmp(const struct lyd_node *dnode1,
				   const struct lyd_node *dnode2)
{
	struct prefix prefix1, prefix2;

	yang_dnode_get_prefix(&prefix1, dnode1, "src-prefix");
	yang_dnode_get_prefix(&prefix2, dnode2, "src-prefix");

	return prefix_cmp(&prefix1, &prefix2);
}

static int static_path_list_cli_cmp(const struct lyd_node *dnode1,
				    const struct lyd_node *dnode2)
{
	uint32_t table_id1, table_id2;
	uint8_t distance1, distance2;

	table_id1 = yang_dnode_get_uint32(dnode1, "table-id");
	table_id2 = yang_dnode_get_uint32(dnode2, "table-id");

	if (table_id1 != table_id2)
		return (int)table_id1 - (int)table_id2;

	distance1 = yang_dnode_get_uint8(dnode1, "distance");
	distance2 = yang_dnode_get_uint8(dnode2, "distance");

	return (int)distance1 - (int)distance2;
}

const struct frr_yang_module_info frr_staticd_cli_info = {
	.name = "frr-staticd",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd",
			.cbs = {
				.cli_show = static_cli_show,
				.cli_show_end = static_cli_show_end,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list",
			.cbs = {
				.cli_cmp = static_route_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list",
			.cbs = {
				.cli_cmp = static_path_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.cli_show = static_nexthop_cli_show,
				.cli_cmp = static_nexthop_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list",
			.cbs = {
				.cli_cmp = static_src_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list",
			.cbs = {
				.cli_cmp = static_path_list_cli_cmp,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.cli_show = static_src_nexthop_cli_show,
				.cli_cmp = static_nexthop_cli_cmp,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

#else /* ifdef INCLUDE_MGMTD_CMDDEFS_ONLY */

DEFPY_YANG(debug_staticd, debug_staticd_cmd,
	   "[no] debug static [{events$events|route$route|bfd$bfd}]",
	   NO_STR DEBUG_STR STATICD_STR
	   "Debug events\n"
	   "Debug route\n"
	   "Debug bfd\n")
{
	/* If no specific category, change all */
	if (strmatch(argv[argc - 1]->text, "static"))
		static_debug_set(vty->node, !no, true, true, true);
	else
		static_debug_set(vty->node, !no, !!events, !!route, !!bfd);

	return CMD_SUCCESS;
}

DEFPY(staticd_show_bfd_routes, staticd_show_bfd_routes_cmd,
      "show bfd static route [json]$isjson",
      SHOW_STR
      BFD_INTEGRATION_STR
      STATICD_STR
      ROUTE_STR
      JSON_STR)
{
	static_bfd_show(vty, !!isjson);
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_static,
	    show_debugging_static_cmd,
	    "show debugging [static]",
	    SHOW_STR
	    DEBUG_STR
	    "Static Information\n")
{
	vty_out(vty, "Staticd debugging status\n");

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

DEFUN_NOSH (static_segment_routing, static_segment_routing_cmd,
      "segment-routing",
      "Segment Routing\n")
{
	// char xpath[XPATH_MAXLEN + 107];

	// snprintf(xpath, sizeof(xpath), "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing");

	// // vty_out(vty, "msg: %s\n", xpath);

	// VTY_PUSH_XPATH(SEGMENT_ROUTING_NODE, xpath);

	// return CMD_SUCCESS;

	vty->node = SEGMENT_ROUTING_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (static_srv6, static_srv6_cmd,
      "srv6",
      "Segment Routing SRv6\n")
{
	// char xpath[XPATH_MAXLEN + 107];

	// snprintf(xpath, sizeof(xpath), "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6");

	// // vty_out(vty, "msg: %s\n", xpath);

	// VTY_PUSH_XPATH(SRV6_NODE, xpath);

	// return CMD_SUCCESS;

	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (static_srv6_locators,
            static_srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	// char xpath[XPATH_MAXLEN + 107];

	// snprintf(xpath, sizeof(xpath), "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators");

	// // vty_out(vty, "msg: %s\n", xpath);

	// VTY_PUSH_XPATH(SRV6_LOCS_NODE, xpath);

	// return CMD_SUCCESS;


	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (static_srv6_locator,
            static_srv6_locator_cmd,
            "locator WORD",
            "Segment Routing SRv6 locator\n"
            "Specify locator-name\n")
{
	// int ret;
	// char xpath[XPATH_MAXLEN + 107];

	// // nb_cli_enqueue_change(vty, "./frr-staticd:staticd/segment-routing/", NB_OP_CREATE, NULL);
	// // nb_cli_enqueue_change(vty, "./frr-staticd:staticd/segment-routing/srv6", NB_OP_CREATE, NULL);
	// // nb_cli_enqueue_change(vty, "./frr-staticd:staticd/segment-routing/locators", NB_OP_CREATE, NULL);

	// snprintf(xpath, sizeof(xpath), "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='%s'][name='%s'][vrf='%s']/frr-staticd:staticd/segment-routing/srv6/locators/locator[name='%s']",
	// 	 "frr-staticd:staticd", "staticd", VRF_DEFAULT_NAME, argv[1]->arg);

	// // vty_out(vty, "msg: %s\n", xpath);

	// nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	// ret = nb_cli_apply_changes(vty, NULL);
	// if (ret == CMD_SUCCESS)
	// 	VTY_PUSH_XPATH(SRV6_LOC_NODE, xpath);

	// return ret;

	struct static_srv6_locator *locator = static_srv6_locator_lookup(argv[1]->arg);
	if (locator) {
		// vty->node = SRV6_LOC_NODE;
		VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
		return CMD_SUCCESS;
	}

	locator = static_srv6_locator_alloc(argv[1]->arg);
	if (!locator) {
		vty_out(vty, "%% Alloc failed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	listnode_add(srv6_locators, locator);

	if (static_zebra_srv6_manager_get_locator(argv[1]->arg) < 0) {
		vty_out(vty, "%% static_zebra_srv6_manager_get_locator failed\n");
		return CMD_WARNING;
	}

	VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
	// vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

DEFPY_YANG (no_static_srv6, no_static_srv6_cmd,
      "no srv6",
      NO_STR
      "Segment Routing SRv6\n")
{
	// char xpath[XPATH_MAXLEN + 37];

	// snprintf(xpath, sizeof(xpath), "%s/srv6",
	// 	 VTY_CURR_XPATH);

	// nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	// return nb_cli_apply_changes(vty, NULL);


	struct static_srv6_locator *locator;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(srv6_locators, node, nnode, locator)) {
		listnode_delete(srv6_locators, locator);
		static_srv6_locator_free(locator);
	}
	
	return CMD_SUCCESS;
}

DEFUN_NOSH (no_srv6_locator,
       no_srv6_locator_cmd,
       "no locator WORD",
       NO_STR
       "Segment Routing SRv6 locator\n"
       "Specify locator-name\n")
{
	// char xpath[XPATH_MAXLEN + 37];

	// snprintf(xpath, sizeof(xpath), "%s/locator[locator='%s']",
	// 	 VTY_CURR_XPATH, argv[1]->arg);

	// // vty_out(vty, "msg: %s\n", xpath);

	// nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	// return nb_cli_apply_changes(vty, NULL);

	struct static_srv6_locator *locator;

	locator = static_srv6_locator_lookup(argv[2]->arg);
	if (!locator) {
		vty_out(vty, "%% Can't find SRv6 locator\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	listnode_delete(srv6_locators, locator);
	static_srv6_locator_free(locator);
	
	return CMD_SUCCESS;
}

// static const char *seg6local_action2yang(uint32_t action)
// {
// 	switch (action) {
// 	case STATIC_SRV6_SID_BEHAVIOR_UN:
// 		return "un";
// 	case STATIC_SRV6_SID_BEHAVIOR_UA:
// 		return "ua";
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
// 		return "udt6";
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
// 		return "udt4";
// 	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
// 		return "udt46";
// 	}

// 	return "unspec";
// }


DEFUN(srv6_opcode, srv6_opcode_cmd,
      "opcode X:X::X:X [<uA interface IFNAME | uDT6 vrf VIEWVRFNAME | uDT4 vrf VIEWVRFNAME | uDT46 vrf VIEWVRFNAME>]",
	  "Configure SRv6 SID opcode\n"
      "Specify SRv6 SID opcode\n"
      "Apply the code to a uA SID\n"
      "Configure interface name\n"
      "Specify interface name\n"
      "Apply the code to an uDT6 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n"
      "Apply the code to an uDT4 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n"
      "Apply the code to an uDT46 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n")
{
	// vty_out(vty, "opcode 1\n");
	VTY_DECLVAR_CONTEXT(static_srv6_locator, locator);
	// vty_out(vty, "opcode 2\n");
	// struct static_srv6_locator *locator;
	// locator = static_srv6_locator_lookup(loc->name);
	// if (!locator) {
	// 	vty_out(vty, "Can't find locator");
	// 	return CMD_WARNING;
	// }
	enum static_srv6_sid_behavior_t behavior = STATIC_SRV6_SID_BEHAVIOR_UNSPEC;
	int idx = 0;
	const char *vrf_name = NULL;
	const char *ifn = NULL;
	char *prefix = NULL;
	int ret = 0;
	struct in6_addr ipv6prefix = { };
	struct in6_addr sid_value = {};
	struct static_srv6_sid *sid = NULL, *s = NULL;
	// char xpath[XPATH_MAXLEN + 37];
	// char xpath_behavior[XPATH_MAXLEN + 100];
	// char xpath_vrf_name[XPATH_MAXLEN + 100];
	// char xpath_ifname[XPATH_MAXLEN + 100];

	if (argv_find(argv, argc, "uN", &idx))
		behavior = STATIC_SRV6_SID_BEHAVIOR_UN;
	else if (argv_find(argv, argc, "uA", &idx)) {
		behavior = STATIC_SRV6_SID_BEHAVIOR_UA;
		ifn = argv[idx + 2]->arg;
	} else if (argv_find(argv, argc, "uDT6", &idx)) {
		behavior = STATIC_SRV6_SID_BEHAVIOR_UDT6;
		vrf_name = argv[idx + 2]->arg;
	} else if (argv_find(argv, argc, "uDT4", &idx)) {
		behavior = STATIC_SRV6_SID_BEHAVIOR_UDT4;
		vrf_name = argv[idx + 2]->arg;
	} else if (argv_find(argv, argc, "uDT46", &idx)) {
		behavior = STATIC_SRV6_SID_BEHAVIOR_UDT46;
		vrf_name = argv[idx + 2]->arg;
	}

	prefix = argv[1]->arg;
	// ret = str2prefix_ipv6(prefix, &ipv6prefix);
	// apply_mask_ipv6(&ipv6prefix);
	ret = inet_pton(AF_INET6, prefix, &ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	combine_sid(locator, &ipv6prefix, &sid_value);

	struct listnode *node;
	// struct static_srv6_sid *sid;
	for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node, s)) {
		if (IPV6_ADDR_SAME(&s->addr, &sid_value)) {
			vty_out(vty, "SID %pI6 already exists\n", &sid_value);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (behavior == STATIC_SRV6_SID_BEHAVIOR_UDT6 || behavior == STATIC_SRV6_SID_BEHAVIOR_UDT4 || behavior == STATIC_SRV6_SID_BEHAVIOR_UDT46) {
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node, s)) {
			if (behavior == s->behavior && strncmp(vrf_name, s->attributes.vrf_name, sizeof(s->attributes.vrf_name)) == 0) {
				vty_out(vty, "VRF %s already associated with SID %pI6\n",
					vrf_name, &sid_value);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	if (behavior == STATIC_SRV6_SID_BEHAVIOR_UA) {
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node, s)) {
			if (behavior == s->behavior && strncmp(ifn, s->attributes.ifname, sizeof(s->attributes.ifname)) == 0) {
				vty_out(vty, "Interface %s already associated with SID %pI6\n",
					ifn, &sid_value);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}


	// snprintf(xpath, sizeof(xpath), "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='%s'][name='%s'][vrf='%s']/frr-staticd:staticd/segment-routing/srv6/locators/locator[name='%s']",
	// 	 "frr-staticd:staticd", "staticd", VRF_DEFAULT_NAME, argv[1]->arg);

	// zlog_info("received prefix %s", prefix);
	// char buf_ipv6[256] = {};
	// inet_ntop(AF_INET6, &ipv6prefix, buf_ipv6,
	// 		  sizeof(buf_ipv6));
	// zlog_info("received buf_ipv6 %s", buf_ipv6);

	// snprintf(xpath, sizeof(xpath), "./local-sids/sid[sid='%s']", prefix);
	// snprintf(xpath_behavior, sizeof(xpath_behavior), "%s/behavior", xpath);
	// snprintf(xpath_vrf_name, sizeof(xpath_vrf_name), "%s/vrf-name", xpath);
	// snprintf(xpath_ifname, sizeof(xpath_ifname), "%s/ifname", xpath);

	// zlog_info("xpath %s", xpath);

	// nb_cli_enqueue_change(vty, xpath,
	// 				NB_OP_CREATE, buf_ipv6);

	// nb_cli_enqueue_change(vty, xpath_behavior,
	// 				NB_OP_MODIFY, seg6local_action2yang(behavior));

	// if (vrf_name)
	// 	nb_cli_enqueue_change(vty, xpath_vrf_name,
	// 					NB_OP_MODIFY, vrf_name);

	// if (ifn)
	// 	nb_cli_enqueue_change(vty, xpath_ifname,
	// 					NB_OP_MODIFY, ifn);

	// return nb_cli_apply_changes(vty, NULL);

	// for (ALL_LIST_ELEMENTS_RO(locator->sids, node, sid)) {
	// 	if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix)) {
	// 		vty_out(vty,
	// 			"Prefix %s is already exist,please delete it first. \n",
	// 			argv[1]->arg);
	// 		return CMD_WARNING;
	// 	}
	// }

	// sid = sid_lookup_by_vrf_action(locator, vrfName, sidaction);
	// if (sid) {
	// 	vty_out(vty,
	// 		"VRF %s is already exist,please delete it first. \n",
	// 		vrfName);
	// 	return CMD_WARNING;
	// }

	// /* if the SRv6 SID already exists and it is bound to the same behavior,
	//  * do nothing */
	// sid = static_srv6_sid_lookup(&ipv6prefix);
	// if (sid && sid->behavior == behavior) {
	// 	VTY_PUSH_CONTEXT(STATIC_SRV6_SID_NODE, sid);
	// 	return CMD_SUCCESS;
	// }

	// /* if the SRv6 already exists but it is bound to a different behavior,
	//  * return an error */
	// if (sid && sid->behavior != behavior) {
	// 	vty_out(vty,
	// 		"%% SRv6 SID %pI6 already bound to the behavior %s\n",
	// 		&sid->addr,
	// 		static_srv6_sid_behavior2str(sid->behavior));
	// 	return CMD_WARNING_CONFIG_FAILED;
	// }

	// /* the sid does not exist yet, let's create a new one */
	// /* alloc memory for the new SRv6 SID */
	// sid = srv6_sid_alloc(&addr, behavior);
	// if (!sid) {
	// 	vty_out(vty, "%% Alloc failed\n");
	// 	return CMD_WARNING_CONFIG_FAILED;
	// }

	// sid = srv6_locator_sid_alloc();
	// sid->behavior = behavior;

	// if (vrf_name != NULL)
	// 	strlcpy(sid->attributes.vrf_name, vrf_name, VRF_NAMSIZ);

	// sid->addr = ipv6prefix;
	// strncpy(sid->sidstr, prefix, PREFIX_STRLEN);

	// sid->ifname[0] = '\0';
	// // memcpy(&sid->nexthop, &nexthop, sizeof(struct in6_addr));
	// if (!zebra_srv6_local_sid_format_valid(locator, sid)) {
	// 	vty_out(vty, "%% Malformed locator sid opcode format\n");
	// 	srv6_locator_sid_free(sid);
	// 	return CMD_WARNING_CONFIG_FAILED;
	// }

	// listnode_add(srv6_sids, sid);
	// // zebra_srv6_local_sid_add(locator, sid);

	// // for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, client_node, client)) {
	// // 	zsend_srv6_manager_get_locator_sid_response(client, VRF_DEFAULT,
	// // 						    locator, sid);
	// // }

	// /* add the new SRv6 SID to the staticd SRv6 SIDs list and install it in
	//  * the zebra RIB */
	// /* SID is not guaranteed to be installed immediately in the zebra RIB */
	// /* if one or more mandatory attributes have not yet been configured, the
	//  * installation of the SID in the zebra rib is postponed until all the
	//  * attributes are configured */
	// static_srv6_sid_add(sid);

	sid = static_srv6_sid_alloc(&sid_value);
	if (!sid) {
		vty_out(vty,
			"%% Can't alloc SID\n");
		return CMD_WARNING;
	}

	sid->behavior = behavior;

	if (vrf_name)
		strncpy(sid->attributes.vrf_name, vrf_name, sizeof(sid->attributes.vrf_name));

	if (ifn)
		strncpy(sid->attributes.ifname, ifn, sizeof(sid->attributes.ifname));

	sid->locator = locator;

	strlcpy(sid->opcode, prefix, sizeof(sid->opcode));
	
	listnode_add(locator->srv6_sids, sid);
	static_zebra_request_srv6_sid(sid);

	return CMD_SUCCESS;
}

DEFUN(no_srv6_opcode, no_srv6_opcode_cmd,
      "no opcode X:X::X:X [<uA interface IFNAME | uDT6 vrf VIEWVRFNAME | uDT4 vrf VIEWVRFNAME | uDT46 vrf VIEWVRFNAME>]",
      NO_STR
	  "Configure SRv6 SID opcode\n"
      "Specify SRv6 SID opcode\n"
      "Apply the code to a uA SID\n"
      "Configure interface name\n"
      "Specify interface name\n"
      "Apply the code to an uDT6 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n"
      "Apply the code to an uDT4 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n"
      "Apply the code to an uDT46 SID\n"
      "Configure VRF name\n"
      "Specify VRF name\n")
{
	// char xpath[XPATH_MAXLEN + 37];
	// const struct lyd_node *dnode;

	// snprintf(xpath, sizeof(xpath), "./local-sids/sid[sid='%s']",
	// 	 argv[2]->arg);

	// dnode = yang_dnode_get(vty->candidate_config->dnode, "/frr-routing:routing/control-plane-protocols/control-plane-protocol");
	// if (!dnode) {
	// 	vty_out(vty,
	// 		"%% Refusing to remove a non-existent opcode\n");
	// 	return CMD_SUCCESS;
	// }

	// nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	// return nb_cli_apply_changes(vty, NULL);
	
	VTY_DECLVAR_CONTEXT(static_srv6_locator, locator);

	struct static_srv6_sid *sid;

	struct in6_addr ipv6prefix = {};
	char *prefix = argv[2]->arg;
	// ret = str2prefix_ipv6(prefix, &ipv6prefix);
	// apply_mask_ipv6(&ipv6prefix);
	int ret = inet_pton(AF_INET6, prefix, &ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	struct in6_addr sid_value = {};
	combine_sid(locator, &ipv6prefix, &sid_value);

	sid = static_srv6_sid_lookup(&sid_value);
	if (!sid) {
		vty_out(vty, "Can't find SID %s\n", prefix);
		return CMD_WARNING;
	}
	listnode_delete(locator->srv6_sids, sid);
	static_srv6_sid_del(sid);
	// static_srv6_sid_free(sid);

	return CMD_SUCCESS;
}

static int static_sr_config_write(struct vty *vty)
{
	struct listnode *node, *node2;
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;

	if (listcount(srv6_locators) == 0)
		return 0;

	vty_out(vty, "!\n");
	vty_out(vty, "segment-routing\n");
	vty_out(vty, " srv6\n");
	vty_out(vty, "  locators\n");
	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, locator)) {
		vty_out(vty, "   locator %s\n", locator->name);
		for (ALL_LIST_ELEMENTS_RO(locator->srv6_sids, node2, sid)) {
			if (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UA)
				vty_out(vty, "    opcode %s uA interface %s\n", sid->opcode, sid->attributes.ifname);
			if (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UDT4)
				vty_out(vty, "    opcode %s uDT4 vrf %s\n", sid->opcode, sid->attributes.vrf_name);
			if (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UDT6)
				vty_out(vty, "    opcode %s uDT6 vrf %s\n", sid->opcode, sid->attributes.vrf_name);
			if (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UDT46)
				vty_out(vty, "    opcode %s uDT46 vrf %s\n", sid->opcode, sid->attributes.vrf_name);
		}
		vty_out(vty, "   exit\n");
		vty_out(vty, "   !\n");
	}
	vty_out(vty, "  exit\n");
	vty_out(vty, "  !\n");
	vty_out(vty, " exit\n");
	vty_out(vty, " !\n");
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");

	return 0;
}

static struct cmd_node sr_node = {
	.name = "sr",
	.node = SEGMENT_ROUTING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-sr)# ",
	.config_write = static_sr_config_write,
};

static struct cmd_node srv6_node = {
	.name = "srv6",
	.node = SRV6_NODE,
	.parent_node = SEGMENT_ROUTING_NODE,
	.prompt = "%s(config-srv6)# ",
};

static struct cmd_node srv6_locs_node = {
	.name = "srv6-locators",
	.node = SRV6_LOCS_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-locators)# ",
};

static struct cmd_node srv6_loc_node = {
	.name = "srv6-locator",
	.node = SRV6_LOC_NODE,
	.parent_node = SRV6_LOCS_NODE,
	.prompt = "%s(config-srv6-locator)# "
};

#endif /* ifndef INCLUDE_MGMTD_CMDDEFS_ONLY */

void static_vty_init(void)
{
#ifndef INCLUDE_MGMTD_CMDDEFS_ONLY
	install_element(ENABLE_NODE, &debug_staticd_cmd);
	install_element(CONFIG_NODE, &debug_staticd_cmd);
	install_element(ENABLE_NODE, &show_debugging_static_cmd);
	install_element(ENABLE_NODE, &staticd_show_bfd_routes_cmd);

	/* Install nodes and its default commands */
	install_node(&sr_node);
	install_node(&srv6_node);
	install_node(&srv6_locs_node);
	install_node(&srv6_loc_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
	
	install_element(CONFIG_NODE, &static_segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &static_srv6_cmd);
	install_element(SEGMENT_ROUTING_NODE, &no_static_srv6_cmd);
	install_element(SRV6_NODE, &static_srv6_locators_cmd);
	install_element(SRV6_LOCS_NODE, &static_srv6_locator_cmd);
	install_element(SRV6_LOC_NODE, &srv6_opcode_cmd);
	install_element(SRV6_LOC_NODE, &no_srv6_opcode_cmd);

#else /* else INCLUDE_MGMTD_CMDDEFS_ONLY */
	install_element(CONFIG_NODE, &ip_mroute_dist_cmd);

	install_element(CONFIG_NODE, &ip_route_blackhole_cmd);
	install_element(VRF_NODE, &ip_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_address_interface_cmd);
	install_element(VRF_NODE, &ip_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ip_route_cmd);
	install_element(VRF_NODE, &ip_route_vrf_cmd);

	install_element(CONFIG_NODE, &ipv6_route_blackhole_cmd);
	install_element(VRF_NODE, &ipv6_route_blackhole_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_address_interface_cmd);
	install_element(VRF_NODE, &ipv6_route_address_interface_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_route_cmd);
	install_element(VRF_NODE, &ipv6_route_vrf_cmd);
#endif /* ifndef INCLUDE_MGMTD_CMDDEFS_ONLY */

#ifndef INCLUDE_MGMTD_CMDDEFS_ONLY
	mgmt_be_client_lib_vty_init();
#endif
}
