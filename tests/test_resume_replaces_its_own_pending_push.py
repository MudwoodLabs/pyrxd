"""A resume may replace its OWN still-pending push, and nothing else (#515, #504 item 1).

The in-flight guard refused whenever `pending > latest`, which is exactly the case a resume racing
its own push produces — so the nonce pin's replacement half was unreachable, and the measured
outcomes were `still in flight` (guard on) or `transaction already imported` (guard off).

The carve-out is narrow on purpose. When `latest` sits at the pinned nonce and `pending` is one
past it, there is exactly ONE transaction in flight and it occupies our own pinned slot. Re-sending
there cannot double-fund: only one transaction per nonce can mine, so the replacement either
supersedes the original or loses to it with `nonce too low`. The value moves once either way.
"""

from __future__ import annotations

import inspect

import pytest

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg, _fee_fields_of
from pyrxd.security.errors import NetworkError

_SRC = inspect.getsource(Erc20HtlcLeg._push_and_bind)


class TestTheCarveOutIsExact:
    def test_it_requires_latest_AT_the_pin_and_pending_one_past(self) -> None:
        """Both halves. `latest == pin` means our slot is unmined; `pending == pin + 1` means
        exactly one transaction is in flight. Either alone admits an unrelated transaction."""
        assert "latest_nonce == int(push_nonce)" in _SRC
        assert "pending_nonce == int(push_nonce) + 1" in _SRC

    def test_it_requires_BOTH_durable_handles(self) -> None:
        """The nonce identifies the slot, the hash identifies the transaction. Without the hash the
        rebuild would be identically priced and rejected as `already imported` — a worse outcome
        than the refusal, because it reads as a node fault."""
        assert "push_nonce is not None" in _SRC
        assert "push_tx_hash is not None" in _SRC

    def test_the_refusal_still_stands_for_everything_else(self) -> None:
        """The carve-out narrows the guard; it must not remove it. An unrelated in-flight
        transaction is still the case the guard was written for."""
        assert "and not _replaces_own_push" in _SRC
        assert "are still in flight" in _SRC

    def test_it_prices_against_the_PENDING_transaction_not_an_estimate(self) -> None:
        """When fees have fallen since the push, an estimate-based bump comes out BELOW what is
        pending and the node rejects it while this code believes it raised the price."""
        assert "get_transaction(str(push_tx_hash))" in _SRC
        assert "bump_replacement_fees(_fee_fields_of(pending_tx))" in _SRC

    def test_the_replacement_keeps_the_PIN(self) -> None:
        """A replacement that lost its nonce would be an ADDITIONAL transfer — the exact
        double-fund the guard exists to prevent, arrived at through the fix for it."""
        pin = _SRC.index('push_tx = {**push_tx, "nonce": int(push_nonce)}')
        bump = _SRC.index("bump_replacement_fees(")
        assert pin < bump, "the fee bump must build on the pinned tx, not replace it"


class TestTheFeeFieldsAreReadHonestly:
    def test_a_1559_transaction_yields_both_fields(self) -> None:
        got = _fee_fields_of({"maxFeePerGas": 200, "maxPriorityFeePerGas": 100, "nonce": 7})
        assert got == {"maxFeePerGas": 200, "maxPriorityFeePerGas": 100}

    @pytest.mark.parametrize("missing", ["maxFeePerGas", "maxPriorityFeePerGas"])
    def test_a_missing_field_is_refused_by_name(self, missing: str) -> None:
        tx = {"maxFeePerGas": 200, "maxPriorityFeePerGas": 100}
        del tx[missing]
        with pytest.raises(NetworkError, match=missing):
            _fee_fields_of(tx)

    def test_a_LEGACY_gasPrice_transaction_is_refused_not_guessed(self) -> None:
        """It has no tip to raise, so no valid 1559 replacement exists for it. Waiting is the
        honest answer; synthesising a tip would price against a field the node never saw."""
        with pytest.raises(NetworkError, match="EIP-1559|maxFee"):
            _fee_fields_of({"gasPrice": 1_000_000_000})

    def test_a_None_field_counts_as_missing(self) -> None:
        """Nodes return `None` for absent fields rather than omitting them, so a `in tx` test would
        pass and then `int(None)` would raise somewhere less legible."""
        with pytest.raises(NetworkError):
            _fee_fields_of({"maxFeePerGas": 200, "maxPriorityFeePerGas": None})
