#!/usr/bin/env python

# Copyright (c) 2022, University of Rome Tor Vergata
# Authored by Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import re
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Define connections
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-r2", "r2-r1")


def setup_module(mod):
    """Sets up the pytest environment"""

    # Verify if kernel requirements are satisfied
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # Build the topology
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra and isis configuration files
    for rname, router in tgen.routers().items():
        router.load_config(TopoRouter.RD_ZEBRA,
                           os.path.join(CWD, '{}/zebra.conf'.format(rname)))
        router.load_config(TopoRouter.RD_ISIS,
                           os.path.join(CWD, '{}/isisd.conf'.format(rname)))

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    # Teardown the topology
    tgen = get_topogen()
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = functools.partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step1/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step1/show_ip_route.ref"
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step1/show_ipv6_route.ref"
        )


def test_srv6_locator_step1():
    logger.info("Test (step 1): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show segment-routing srv6 locator json", "step1/show_srv6_locator_table.ref"
         )


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


# def test_rib():
#     router_compare_json_output("r1", "show isis segment-routing srv6 node json")
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
#     check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10v4_rib.json")
#     check_rib("r1", "show ip route vrf vrf20 json", "r1/vrf20v4_rib.json")
#     check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10v4_rib.json")
#     check_rib("r2", "show ip route vrf vrf20 json", "r2/vrf20v4_rib.json")
#     check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
#     check_rib("ce2", "show ip route json", "ce2/ip_rib.json")
#     check_rib("ce3", "show ip route json", "ce3/ip_rib.json")
#     check_rib("ce4", "show ip route json", "ce4/ip_rib.json")
#     check_rib("ce5", "show ip route json", "ce5/ip_rib.json")
#     check_rib("ce6", "show ip route json", "ce6/ip_rib.json")

#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
#     check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10v6_rib.json")
#     check_rib("r1", "show ipv6 route vrf vrf20 json", "r1/vrf20v6_rib.json")
#     check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10v6_rib.json")
#     check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20v6_rib.json")
#     check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
#     check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
#     check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
#     check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
#     check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
#     check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


# def test_ping():
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping4("ce1", "192.168.3.2", True)
#     check_ping4("ce1", "192.168.4.2", False)
#     check_ping4("ce1", "192.168.5.2", False)
#     check_ping4("ce1", "192.168.6.2", False)
#     check_ping4("ce4", "192.168.1.2", False)
#     check_ping4("ce4", "192.168.2.2", False)
#     check_ping4("ce4", "192.168.3.2", False)
#     check_ping4("ce4", "192.168.5.2", True)
#     check_ping4("ce4", "192.168.6.2", True)

#     check_ping6("ce1", "2001:2::2", True)
#     check_ping6("ce1", "2001:3::2", True)
#     check_ping6("ce1", "2001:4::2", False)
#     check_ping6("ce1", "2001:5::2", False)
#     check_ping6("ce1", "2001:6::2", False)
#     check_ping6("ce4", "2001:1::2", False)
#     check_ping6("ce4", "2001:2::2", False)
#     check_ping6("ce4", "2001:3::2", False)
#     check_ping6("ce4", "2001:5::2", True)
#     check_ping6("ce4", "2001:6::2", True)


# def test_bgp_sid_vpn_export_disable():
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1 vrf vrf10
#           segment-routing srv6
#            no sid vpn per-vrf export
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_sid_vpn_export_disabled.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_sid_vpn_export_disabled.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_sid_vpn_export_disabled.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_sid_vpn_export_disabled.json")
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)


# def test_bgp_sid_vpn_export_reenable():
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1 vrf vrf10
#           segment-routing srv6
#            sid vpn per-vrf export auto
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_sid_vpn_export_reenabled.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_sid_vpn_export_reenabled.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_sid_vpn_export_reenabled.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_sid_vpn_export_reenabled.json")
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)


# def test_locator_delete():
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          segment-routing
#           srv6
#            locators
#             no locator loc1
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_deleted.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_deleted.json")
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)


# def test_locator_recreate():
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          segment-routing
#           srv6
#            locators
#             locator loc1
#              prefix 2001:db8:1:1::/64
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)


# def test_bgp_locator_unset():
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1
#           segment-routing srv6
#            no locator loc1
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_deleted.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_deleted.json")
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)


# def test_bgp_locator_reset():
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1
#           segment-routing srv6
#            locator loc1
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)


# def test_bgp_srv6_unset():
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1
#           no segment-routing srv6
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_deleted.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_deleted.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_deleted.json")
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)


# def test_bgp_srv6_reset():
#     check_ping4("ce1", "192.168.2.2", False)
#     check_ping6("ce1", "2001:2::2", False)
#     get_topogen().gears["r1"].vtysh_cmd(
#         """
#         configure terminal
#          router bgp 1
#           segment-routing srv6
#            locator loc1
#         """
#     )
#     check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
#     check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
#     check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
#     check_ping4("ce1", "192.168.2.2", True)
#     check_ping6("ce1", "2001:2::2", True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
