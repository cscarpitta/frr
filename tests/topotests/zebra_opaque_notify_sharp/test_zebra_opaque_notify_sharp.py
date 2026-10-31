#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Verify Zebra does not send opaque messages to notification-only clients."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.sharpd]


def build_topo(tgen):
    """Build a single-router topology running Zebra and Sharp."""
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd"])

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _read_sharp_log(log_path):
    try:
        with open(log_path, encoding="utf-8") as log_file:
            return log_file.read()
    except FileNotFoundError:
        return ""


def test_notification_only_client_does_not_receive_sync():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_log = os.path.join(tgen.logdir, "r1", "sharpd.log")

    # Capture Sharp's opaque-message debug output for the assertions below.
    r1.vtysh_cmd(
        """
        configure terminal
        log file sharpd.log debug
        end
        """,
        daemon="sharpd",
    )

    # Subscribe to SYNC notifications without registering to receive SYNC
    # messages. Importing the TED sends an empty LINK_STATE_SYNC request.
    r1.vtysh_cmd("sharp send opaque notify reg type 1")

    # Register a separate opaque subtype as a marker so the test can wait
    # until Zebra has processed the preceding SYNC request.
    r1.vtysh_cmd("sharp send opaque reg sharp type 99")
    before = _read_sharp_log(sharp_log)

    r1.vtysh_cmd("sharp import-te")
    r1.vtysh_cmd("sharp send opaque type 99 1")

    marker = "sharp_opaque_handler: [0] received opaque type 99"

    def marker_received():
        return marker in _read_sharp_log(sharp_log)[len(before) :]

    _, result = topotest.run_and_expect(marker_received, True, count=20, wait=1)
    assert result is True, "Sharp did not receive the opaque marker message"

    received_sync = "sharp_opaque_handler: [0] received opaque type 1"
    new_log = _read_sharp_log(sharp_log)[len(before) :]
    assert received_sync not in new_log, (
        "Zebra delivered the empty LINK_STATE_SYNC request to Sharp's "
        "notification-only registration"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
