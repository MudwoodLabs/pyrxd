"""Two round-6 residuals: a durable handle that accepted garbage, and a probe skip too wide.

#502 item 7 — `PendingDeploy.deploy_tx_hash` was prefix-checked only, so `"0x"` and `"0xzz"`
round-tripped into the record whose whole purpose is to be the surviving reference to a funded
contract. A handle that stores garbage is worse than none: it reads as a record and points nowhere.

#502 item 3 — the H-reuse probe was skipped whenever the record carried a pending deploy, for
WHATEVER hashlock was passed. The evidence is "this swap already reserved THIS H"; it says nothing
about an unrelated one.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.locator import PendingDeploy, check_tx_hash, normalise_tx_hash
from pyrxd.security.errors import ValidationError

_ADDR = "0x" + "11" * 20
_GOOD = "0x" + "ab" * 32


class TestTheTxHashShape:
    @pytest.mark.parametrize(
        "bad",
        [
            "0x",  # the prefix alone — accepted before
            "0xzz",  # prefixed, not hex
            "0x" + "ab" * 31,  # one byte short
            "0x" + "ab" * 33,  # one byte long
            "0x" + "ab" * 32 + "0",  # 67 chars
            "",
        ],
    )
    def test_a_malformed_hash_cannot_reach_the_durable_record(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            PendingDeploy(address=_ADDR, deploy_tx_hash=bad)

    def test_a_real_hash_is_accepted(self) -> None:
        """The honest path. A guard that refuses valid work is a bug, and this one sits on the
        record that makes a crashed fund recoverable."""
        assert PendingDeploy(address=_ADDR, deploy_tx_hash=_GOOD).deploy_tx_hash == _GOOD

    def test_uppercase_hex_is_accepted(self) -> None:
        """Nodes return mixed case. Refusing it would reject a perfectly good handle."""
        assert PendingDeploy(address=_ADDR, deploy_tx_hash="0x" + "AB" * 32)

    def test_the_normaliser_still_prefixes_AND_now_validates(self) -> None:
        """`normalise_tx_hash` existed because the two writers disagreed about the prefix — and on
        a real chain that raised mid-fund, after the contract was deployed. It now also rejects a
        hash of the wrong shape, so both writers reach the same check."""
        assert normalise_tx_hash("ab" * 32) == _GOOD
        assert normalise_tx_hash(_GOOD) == _GOOD
        with pytest.raises(ValidationError):
            normalise_tx_hash("ab" * 31)

    def test_the_check_is_SHAPE_only_and_says_so(self) -> None:
        """It cannot confirm the hash created the address — that needs a chain read. Pinned so the
        docstring is not later read as a stronger guarantee than it is."""
        assert check_tx_hash(_GOOD) == _GOOD
        assert "Shape only" in (check_tx_hash.__doc__ or "")


class TestTheProbeSkipIsScopedToTheRecordsOwnH:
    def test_the_skip_requires_the_hashlock_to_MATCH(self) -> None:
        """The mechanism, read off the source: the skip is conditioned on the passed hashlock
        equalling the record's, not merely on a pending deploy existing.

        Driving this through `pre_btc_lock_check` needs a full coordinator with a seen-store, a
        funded covenant and a live record; the property that regressed is one boolean, so it is
        pinned where it lives.
        """
        import inspect

        from pyrxd.gravity.swap_coordinator import SwapCoordinator

        src = inspect.getsource(SwapCoordinator.pre_btc_lock_check)
        assert "resuming_this_h" in src
        assert "self.record.terms.hashlock" in src, "the skip is not compared against the record's own H"
        assert "if not resuming_this_h and self.seen_store.has_seen" in src

    def test_the_old_unscoped_form_is_gone(self) -> None:
        import inspect

        from pyrxd.gravity.swap_coordinator import SwapCoordinator

        src = inspect.getsource(SwapCoordinator.pre_btc_lock_check)
        assert "if not self.record.pending_counter_contract and self.seen_store.has_seen" not in src
