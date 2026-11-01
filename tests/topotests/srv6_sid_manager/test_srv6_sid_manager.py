#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by Carmine Scarpitta <cscarpit@cisco.com>
#

"""
test_srv6_sid_manager.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+             +---------+
         |         |                     |         |             |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |eth-dst2     |   DST2  |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |-------------+ 9.9.9.5 |
         |         |eth-rt5       eth-rt4|         |      eth-rt5|         |
         +---------+                     +---------+             +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.10.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         | 9.9.9.2 |
                         |         |
                         +---------+

"""

import functools
import ipaddress
import json
import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    create_interface_in_kernel,
)
from lib.checkping import check_ping

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.isisd,
    pytest.mark.sharpd,
    pytest.mark.staticd,
]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    tgen.add_router("rt4")
    tgen.add_router("rt5")
    tgen.add_router("rt6")
    tgen.add_router("dst")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")
    tgen.add_router("ce7")
    tgen.add_router("dst2")

    # Define connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-dst2")
    switch.add_link(tgen.gears["dst2"], nodeif="eth-rt5")

    tgen.add_link(tgen.gears["ce1"], tgen.gears["rt1"], "eth-rt1", "eth-ce1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["rt6"], "eth-rt6", "eth-ce2")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["rt1"], "eth-rt1", "eth-ce3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["rt6"], "eth-rt6", "eth-ce4")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["rt1"], "eth-rt1", "eth-ce5")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["rt6"], "eth-rt6", "eth-ce6")
    tgen.add_link(tgen.gears["ce7"], tgen.gears["rt5"], "eth-rt5", "eth-ce7")

    tgen.gears["rt1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt1"].run("ip link set vrf10 up")
    tgen.gears["rt1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt1"].run("ip link set vrf20 up")
    tgen.gears["rt1"].run("ip link set eth-ce1 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce3 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce5 master vrf20")

    tgen.gears["rt5"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt5"].run("ip link set vrf10 up")
    tgen.gears["rt5"].run("ip link set eth-dst2 master vrf10")
    tgen.gears["rt5"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt5"].run("ip link set vrf20 up")
    tgen.gears["rt5"].run("ip link set eth-ce7 master vrf20")

    tgen.gears["rt6"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt6"].run("ip link set vrf10 up")
    tgen.gears["rt6"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt6"].run("ip link set vrf20 up")
    tgen.gears["rt6"].run("ip link set eth-ce2 master vrf10")
    tgen.gears["rt6"].run("ip link set eth-ce4 master vrf20")
    tgen.gears["rt6"].run("ip link set eth-ce6 master vrf20")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
        netmask="128",
        create=True,
    )


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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        if rname == "rt1":
            router.load_config(TopoRouter.RD_STATIC)
        if os.path.exists("{}/sharpd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    # Teardown the topology
    tgen = get_topogen()
    tgen.stop_topology()


router_compare_json_output = functools.partial(
    topotest.router_compare_json_output, count=120, wait=0.5, CWD=CWD
)


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    success, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies():
    logger.info("Test: check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4():
    logger.info("Test: verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "show_ip_route.ref"
        )


def test_rib_ipv6():
    logger.info("Test: verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(rname, "show ipv6 route json", "show_ipv6_route.ref")


def test_srv6_locator():
    logger.info("Test: verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "show_srv6_locator_table.ref",
        )


def test_vpn_rib():
    check_rib("rt1", "show bgp ipv6 vpn json", "rt1/vpnv6_rib.ref")
    check_rib("rt6", "show bgp ipv6 vpn json", "rt6/vpnv6_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf10 json", "rt1/vrf10_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf20 json", "rt1/vrf20_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf10 json", "rt6/vrf10_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf20 json", "rt6/vrf20_rib.ref")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    logger.info("Test: verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup encap route on rt1, decap route on rt2
    # tgen.gears["rt1"].vtysh_cmd("sharp install seg6-routes fc00:0:9::1 nexthop-seg6 2001:db8:1::2 encap fc00:0:2:6:fe00:: 1")
    tgen.gears["rt1"].cmd(
        "ip -6 r a fc00:0:9::1/128 encap seg6 mode encap segs fc00:0:2:6:fe00:: via 2001:db8:1::2"
    )
    # tgen.gears["rt6"].vtysh_cmd("sharp install seg6local-routes fc00:0:f00d:: nexthop-seg6local eth-dst End_DT6 254 1")
    tgen.gears["rt6"].cmd("ip -6 r a fc00:0:9::1/128 via 2001:db8:10::2 vrf vrf10")
    tgen.gears["dst"].cmd("ip -6 r a 2001:db8:1::1/128 via 2001:db8:10::1")

    # Try to ping dst from rt1
    check_ping("rt1", "fc00:0:9::1", True, 10, 1)


def test_usid_lib_ranges():
    """Verify uSID LIB ranges reject a start greater than the end."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    output = router.vtysh_cmd(
        format_context + "local-id-block explicit start 201 end 200\n"
    )
    assert "Explicit LIB start (0xc9) cannot be greater than end (0xc8)" in output

    output = router.vtysh_cmd(
        format_context + "wide-local-id-block start 401 end 400\n"
    )
    assert "Wide LIB start (0x191) cannot be greater than end (0x190)" in output

    output = router.vtysh_cmd("write terminal")
    assert "local-id-block explicit start 0xc9 end 0xc8" not in output
    assert "wide-local-id-block start 0x191 end 0x190" not in output


def test_usid_lib_ranges_hex():
    """Verify uSID LIB ranges accept hexadecimal values and show them in hex."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    # Change the ranges and verify the values are reflected in the configuration.
    router.vtysh_cmd(
        format_context
        + "local-id-block start 0x123\n"
        + "local-id-block explicit start 0x201 end 0x2ff\n"
        + "wide-local-id-block start 0x301 end 0x3ff\n"
        + "wide-local-id-block explicit start 0x401\n"
    )

    output = router.vtysh_cmd("write terminal")
    assert "local-id-block start 0x123" in output
    assert "local-id-block explicit start 0x201 end 0x2ff" in output
    assert "wide-local-id-block start 0x301 end 0x3ff" in output
    assert "wide-local-id-block explicit start 0x401" in output

    # Restore the default ranges and verify the overrides are gone.
    router.vtysh_cmd(
        format_context
        + "no local-id-block\n"
        + "no local-id-block explicit\n"
        + "no wide-local-id-block\n"
        + "no wide-local-id-block explicit\n"
    )
    output = router.vtysh_cmd("write terminal")
    assert "local-id-block start 0x123" not in output
    assert "local-id-block explicit start 0x201 end 0x2ff" not in output
    assert "wide-local-id-block start 0x301 end 0x3ff" not in output
    assert "wide-local-id-block explicit start 0x401" not in output


def _dynamic_sids_from_range(router, sid_start, sid_end):
    """Check that BGP and IS-IS have dynamic SIDs from the requested range."""
    try:
        sids = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    except json.JSONDecodeError as error:
        return "show segment-routing srv6 sid json: {}".format(error)

    protocols = set()
    for sid, info in sids.items():
        if info.get("allocationMode") != "dynamic":
            continue

        sid_func = int.from_bytes(ipaddress.IPv6Address(sid).packed[6:8], "big")
        if not sid_start <= sid_func < sid_end:
            continue

        protocols.update(client["protocol"] for client in info.get("clients", []))

    missing = {"bgp", "isis"} - protocols
    if missing:
        return "No dynamic SID from range 0x{:x}-0x{:x} for {}".format(
            sid_start, sid_end - 1, ", ".join(sorted(missing))
        )

    return None


def _dynamic_sid_for_client(router, protocol, sid_start, sid_end):
    """Return a client's dynamic SID from the requested uSID LIB range."""
    sids = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    for sid, info in sids.items():
        if info.get("allocationMode") != "dynamic":
            continue

        sid_func = int.from_bytes(ipaddress.IPv6Address(sid).packed[6:8], "big")
        if not sid_start <= sid_func < sid_end:
            continue

        if any(client["protocol"] == protocol for client in info.get("clients", [])):
            return sid

    return None


def _check_srv6_sid_clients(router, sid, expected_clients, allocation_mode=None):
    """Check that the requested SRv6 SID is shared by the expected clients."""
    try:
        output = json.loads(
            router.vtysh_cmd("show segment-routing srv6 sid {} json".format(sid))
        )
    except json.JSONDecodeError as error:
        return "show segment-routing srv6 sid {} json: {}".format(sid, error)

    sid_info = output.get(sid)
    if not sid_info:
        return "SRv6 SID {} was not allocated".format(sid)

    if allocation_mode and sid_info.get("allocationMode") != allocation_mode:
        return "SRv6 SID {} has allocation mode {}, expected {}".format(
            sid, sid_info.get("allocationMode"), allocation_mode
        )

    clients = {client["protocol"] for client in sid_info.get("clients", [])}
    missing = set(expected_clients) - clients
    if missing:
        return "SRv6 SID {} is missing clients {}".format(
            sid, ", ".join(sorted(missing))
        )

    return None


def _check_srv6_vpn_routes(rt1, rt6, rt1_sid):
    """Check ingress and egress VPN routes on both PEs."""
    routes = (
        (rt6, "2001:1::/64", "bgp", rt1_sid),
        (rt1, "2001:1::/64", "connected", None),
        (rt1, "2001:2::/64", "bgp", "fc00:0:6:fe00::"),
        (rt6, "2001:2::/64", "connected", None),
    )

    for router, prefix, protocol, sid in routes:
        try:
            output = json.loads(
                router.vtysh_cmd("show ipv6 route vrf vrf10 json")
            )
        except json.JSONDecodeError as error:
            return "show ipv6 route vrf vrf10 json: {}".format(error)

        entries = output.get(prefix, [])
        entry = next((route for route in entries if route.get("selected")), None)
        if not entry:
            return "{} has no selected route for {}".format(router.name, prefix)
        if entry.get("protocol") != protocol:
            return "{} route for {} uses {}, expected {}".format(
                router.name, prefix, entry.get("protocol"), protocol
            )

        if sid:
            route_sids = {
                nexthop.get("seg6", {}).get("segs")
                for nexthop in entry.get("nexthops", [])
            }
            if sid not in route_sids:
                return "{} route for {} uses SID {}, expected {}".format(
                    router.name, prefix, route_sids, sid
                )

    for router, sid in ((rt1, rt1_sid), (rt6, "fc00:0:6:fe00::")):
        try:
            output = json.loads(router.vtysh_cmd("show ipv6 route json"))
        except json.JSONDecodeError as error:
            return "show ipv6 route json: {}".format(error)

        entries = [
            route
            for prefix, routes in output.items()
            if prefix.rsplit("/", 1)[0] == sid
            for route in routes
        ]
        entry = next((route for route in entries if route.get("selected")), None)
        if not entry:
            return "{} has no installed local SID route for {}".format(
                router.name, sid
            )

        local_sid = any(
            nexthop.get("interfaceName") == "vrf10"
            and nexthop.get("seg6local", {}).get("action") == "uDT6"
            for nexthop in entry.get("nexthops", [])
        )
        if not local_sid:
            return "{} local SID {} is not installed with uDT6 for vrf10".format(
                router.name, sid
            )

    return None


def _check_srv6_vpn_forwarding(rt1, rt6, rt1_sid):
    check_routes = functools.partial(_check_srv6_vpn_routes, rt1, rt6, rt1_sid)
    _, result = topotest.run_and_expect(check_routes, None, count=30, wait=1)
    assert result is None, result

    check_ping("ce2", "2001:1::2", True, 10, 1)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_dynamic_sid_range_and_static_sid_configuration():
    """Verify dynamic range allocation and staticd explicit SID configuration."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    start = 0xD000
    explicit_start = 0xFE00
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    # Verify the baseline routes and forwarding.
    _check_srv6_vpn_forwarding(router, tgen.gears["rt6"], "fc00:0:1:fe00::")

    # Change the dynamic range and verify BGP and IS-IS allocate from it.
    router.vtysh_cmd(format_context + "local-id-block start 0xd000\n")
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
no sid vpn export 65024
"""
    )
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
sid vpn export auto
"""
    )

    check_dynamic_sids = functools.partial(
        _dynamic_sids_from_range, router, start, explicit_start
    )
    _, result = topotest.run_and_expect(check_dynamic_sids, None, count=30, wait=1)
    assert result is None, result
    bgp_dynamic_sid = _dynamic_sid_for_client(router, "bgp", start, explicit_start)
    assert bgp_dynamic_sid, "BGP has no dynamic SID in the configured range"
    _check_srv6_vpn_forwarding(router, tgen.gears["rt6"], bgp_dynamic_sid)

    # Configure the same SIDs explicitly in staticd and verify BGP and IS-IS share them.
    router.vtysh_cmd(
        """configure terminal
segment-routing
srv6
static-sids
sid fc00:0:1:fe10::/64 locator loc1 behavior uDT6 vrf vrf10
sid fc00:0:1::/48 locator loc1 behavior uN
"""
    )

    for sid, clients, allocation_mode in (
        ("fc00:0:1:fe10::", {"static", "bgp"}, "explicit"),
        ("fc00:0:1::", {"static", "isis"}, "dynamic"),
    ):
        check_sid_clients = functools.partial(
            _check_srv6_sid_clients, router, sid, clients, allocation_mode
        )
        _, result = topotest.run_and_expect(
            check_sid_clients, None, count=30, wait=1
        )
        assert result is None, result
    _check_srv6_vpn_forwarding(router, tgen.gears["rt6"], "fc00:0:1:fe10::")

    # Restore BGP and range defaults and verify the test overrides are gone.
    router.vtysh_cmd(
        """configure terminal
segment-routing
srv6
static-sids
no sid fc00:0:1:fe10::/64
no sid fc00:0:1::/48
"""
    )
    router.vtysh_cmd(format_context + "no local-id-block\n")
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
no sid vpn export auto
"""
    )
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
sid vpn export 65024
"""
    )

    output = router.vtysh_cmd("write terminal")
    assert "local-id-block start 0xd000" not in output
    assert "sid vpn export auto" not in output
    assert "sid vpn export 65024" in output
    assert "sid fc00:0:1:fe10::/64" not in output
    assert "sid fc00:0:1::/48" not in output
    _check_srv6_vpn_forwarding(router, tgen.gears["rt6"], "fc00:0:1:fe00::")


def test_uncompressed_explicit_range_hex():
    """Verify the uncompressed explicit range accepts and shows hex values."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    format_context = """configure terminal
segment-routing
srv6
formats
format uncompressed-f4024
"""

    # Change the range and verify the value is reflected in the configuration.
    router.vtysh_cmd(format_context + "explicit start 0x1234\n")

    output = router.vtysh_cmd("write terminal")
    assert "explicit start 0x1234" in output

    # Restore the default range and verify the override is gone.
    router.vtysh_cmd(format_context + "no explicit\n")
    output = router.vtysh_cmd("write terminal")
    assert "explicit start 0x1234" not in output


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
