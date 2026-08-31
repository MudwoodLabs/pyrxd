"""Pricing a replacement so a node actually accepts it (#515, #504 item 1).

A resume that finds its own push still pending cannot rebuild and re-send: an identically-priced
transaction at a used nonce is rejected as `transaction already imported`, which is what the
crash-resume run measured. Replacing requires raising BOTH EIP-1559 fields by at least the node's
`txpool.pricebump` — 10% on geth and its peers.

The existing `basefee_headroom` knob cannot do this: it scales the basefee share and documents
itself as touching "never the tip", so a resend through it is not a replacement at any headroom.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.replacement import (
    DEFAULT_BUMP_PCT,
    MIN_REPLACEMENT_BUMP_PCT,
    bump_replacement_fees,
    clears_replacement_bump,
)
from pyrxd.security.errors import ValidationError

_PREV = {"maxFeePerGas": 2_000_000_000, "maxPriorityFeePerGas": 1_000_000_000}


class TestBothFieldsRise:
    def test_both_are_raised_not_just_the_cap(self) -> None:
        """The whole defect. Raising only `maxFeePerGas` — which is all `basefee_headroom` does —
        leaves the tip unchanged and the node rejects it as underpriced."""
        got = bump_replacement_fees(_PREV)
        assert got["maxFeePerGas"] > _PREV["maxFeePerGas"]
        assert got["maxPriorityFeePerGas"] > _PREV["maxPriorityFeePerGas"]

    def test_both_clear_the_node_threshold(self) -> None:
        got = bump_replacement_fees(_PREV)
        for field in _PREV:
            assert clears_replacement_bump(got[field], _PREV[field]), field

    def test_the_default_bump_is_above_the_floor(self) -> None:
        """Landing exactly on the boundary loses to integer truncation somewhere between here and
        the node's own comparison, so the applied bump sits above the required one."""
        assert DEFAULT_BUMP_PCT > MIN_REPLACEMENT_BUMP_PCT

    def test_a_bump_below_the_floor_is_refused(self) -> None:
        """Building a transaction that will certainly be rejected is worse than refusing to build
        it: the caller learns at the node, on a funding path, mid-resume."""
        with pytest.raises(ValidationError, match="below the"):
            bump_replacement_fees(_PREV, pct=5)

    def test_other_fields_are_carried_through(self) -> None:
        """The nonce especially. A replacement that loses its pin becomes an ADDITIONAL transfer."""
        prev = {**_PREV, "nonce": 7, "gas": 21_000}
        got = bump_replacement_fees(prev)
        assert got["nonce"] == 7 and got["gas"] == 21_000


class TestTheThresholdArithmetic:
    @pytest.mark.parametrize(
        ("new", "prev", "expected"),
        [
            (110, 100, True),  # exactly 10%
            (109, 100, False),  # a fraction under
            (111, 100, True),
            (100, 100, False),  # unchanged is not a replacement
            (99, 100, False),  # lower certainly is not
        ],
    )
    def test_the_boundary_is_inclusive_and_exact(self, new, prev, expected) -> None:
        """Pins `>=` rather than `>`, and does it over integers. Float arithmetic here is the one
        thing that turns a bump computed as sufficient into one the node rejects."""
        assert clears_replacement_bump(new, prev) is expected

    def test_rounding_goes_UP(self) -> None:
        """There is no partial credit for nearly clearing the threshold."""
        got = bump_replacement_fees({"maxFeePerGas": 101, "maxPriorityFeePerGas": 101}, pct=10)
        assert got["maxFeePerGas"] == 112  # ceil(101 * 1.10) == 112, not 111
        assert clears_replacement_bump(got["maxFeePerGas"], 101)


class TestItRefusesWhatItCannotPriceHonestly:
    @pytest.mark.parametrize("missing", ["maxFeePerGas", "maxPriorityFeePerGas"])
    def test_a_half_specified_previous_is_refused(self, missing: str) -> None:
        """Both fields must be read off the PENDING transaction. Filling one from a fresh estimate
        is how a replacement silently comes out below what is already pending."""
        prev = {k: v for k, v in _PREV.items() if k != missing}
        with pytest.raises(ValidationError, match=missing):
            bump_replacement_fees(prev)

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5, "100"])
    def test_a_non_positive_or_non_int_fee_is_refused(self, bad) -> None:
        with pytest.raises(ValidationError):
            bump_replacement_fees({**_PREV, "maxFeePerGas": bad})

    def test_an_inconsistent_previous_is_refused_rather_than_patched(self) -> None:
        """A tip above the cap is not a transaction a node accepted, so there is no valid
        replacement for it. Refusing says so instead of inventing one."""
        with pytest.raises(ValidationError, match="exceeds maxFeePerGas"):
            bump_replacement_fees({"maxFeePerGas": 100, "maxPriorityFeePerGas": 100_000})

    def test_it_does_not_read_a_network(self) -> None:
        """Pure arithmetic on purpose: choosing WHEN to replace, and whether it is safe, belongs to
        the caller — which on a funding path must also hold a durable nonce pin."""
        import inspect

        from pyrxd.eth_wallet import replacement

        src = inspect.getsource(replacement)
        for forbidden in ("await ", "async def", "requests", "web3"):
            assert forbidden not in src, f"the pricing helper reaches for {forbidden!r}"
