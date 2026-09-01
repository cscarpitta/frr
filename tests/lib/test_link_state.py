# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestLinkState(frrtest.TestMultiOut):
    program = "./test_link_state"


TestLinkState.onesimple("Link State edge lifetime test passed.")
