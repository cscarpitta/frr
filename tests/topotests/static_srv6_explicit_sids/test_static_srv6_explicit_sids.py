#!/usr/bin/env python

#
# test_static_srv6_explicit_sids.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by
# University of Rome Tor Vergata, Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
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

"""
test_static_srv6_explicit_sids.py:
Test for SRv6 explicit SIDs on staticd
"""

import os
import sys
import json
import pytest
import functools
import platform

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.topotest import version_cmp

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")

    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth3")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_srv6_sid(router, expected_sid_file):
    logger.info("checking static srv6 sid status")
    output = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    expected = open_json_file("{}/{}".format(CWD, expected_sid_file))
    return topotest.json_cmp(output, expected)


def check_srv6_sid(router, expected_file):
    func = functools.partial(_check_srv6_sid, router, expected_file)
    success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
    assert result is None, "Failed"


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
    success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"


def test_srv6_sids():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for SRv6 SIDs Configuration")
    check_srv6_sid(router, "expected_sids.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib.json")


def test_no_srv6():
    tgen = get_topogen()
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for SRv6 disable")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          no srv6
        """
    )
    check_srv6_sid(router, "expected_sids_no_srv6.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_no_srv6.json")


def test_srv6_sid_end_dt6_create():
    if version_cmp(platform.release(), "4.10") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 4.10)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test add SRv6 End.DT6 SID")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::1 behavior end-dt6
             sharing-attributes
              vrf-name vrf10
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt6_create.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt6_create.json")


def test_srv6_sid_end_dt6_vrf_unset():
    if version_cmp(platform.release(), "4.10") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 4.10)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test unset SRv6 End.DT6 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::1 behavior end-dt6
             sharing-attributes
              no vrf-name
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt6_vrf_unset.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt6_vrf_unset.json")


def test_srv6_sid_end_dt6_vrf_set():
    if version_cmp(platform.release(), "4.10") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 4.10)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test set SRv6 End.DT6 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::1 behavior end-dt6
             sharing-attributes
              vrf-name vrf10
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt6_vrf_set.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt6_vrf_set.json")


def test_srv6_sid_end_dt6_vrf_change():
    if version_cmp(platform.release(), "4.10") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 4.10)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test change SRv6 End.DT6 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::1 behavior end-dt6
             sharing-attributes
              vrf-name vrf20
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt6_vrf_change.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt6_vrf_change.json")


def test_srv6_sid_end_dt6_delete():
    if version_cmp(platform.release(), "4.10") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 4.10)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test remove SRv6 End.DT6 SID")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            no sid 2001:db8:1:1::1
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt6_delete.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt6_delete.json")


def test_srv6_sid_end_dt4_create():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test add SRv6 End.DT4 SID")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::2 behavior end-dt4
             sharing-attributes
              vrf-name vrf10
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt4_create.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt4_create.json")


def test_srv6_sid_end_dt4_vrf_unset():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test unset SRv6 End.DT4 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::2 behavior end-dt4
             sharing-attributes
              no vrf-name
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt4_vrf_unset.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt4_vrf_unset.json")


def test_srv6_sid_end_dt4_vrf_set():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test set SRv6 End.DT4 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::2 behavior end-dt4
             sharing-attributes
              vrf-name vrf10
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt4_vrf_set.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt4_vrf_set.json")


def test_srv6_sid_end_dt4_vrf_change():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test change SRv6 End.DT4 VRF")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            sid 2001:db8:1:1::2 behavior end-dt4
             sharing-attributes
              vrf-name vrf20
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt4_vrf_change.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt4_vrf_change.json")


def test_srv6_sid_end_dt4_delete():
    if version_cmp(platform.release(), "5.11") < 0:
        error_msg = (
            'This test will not run. (have kernel "{}", '
            "requires kernel >= 5.11)".format(platform.release())
        )
        pytest.skip(error_msg)

    tgen = get_topogen()
    router = tgen.gears["r1"]

    logger.info("Test remove SRv6 End.DT4 SID")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           explicit-sids
            no sid 2001:db8:1:1::2
        """
    )
    check_srv6_sid(router, "expected_sids_srv6_sid_end_dt4_delete.json")
    check_rib("r1", "show ipv6 route json", "r1/ipv6_rib_srv6_sid_end_dt4_delete.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
