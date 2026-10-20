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


# --------------------------------------------------------------------------- the branch, executed
#
# The tests above read the branch's SOURCE. #850 PR 3 made it reachable in production (the push hash
# now reaches the record), and the Mythos review of that PR was the first thing to EXECUTE it: it
# found that a replacement whose broadcast failed left the record naming a hash no node knows, and
# every later resume died on a bare `eth_getTransactionByHash failed`. These run the shipped
# `Erc20HtlcLeg.fund` against the fake chain the durability tests use.

import asyncio

from tests.test_deployed_contract_is_durable_before_funding import (
    _AMOUNT,
    _CLAIMANT,
    _FUND_TIMEOUT,
    _PENDING,
    _REFUNDEE,
    _real_verify_leg,
)

_ORIGINAL = "0x" + "11" * 32
_REPLACEMENT = "0x" + "22" * 32
_PIN = 41


def _resuming_leg(*, pending: int, latest: int, pool: dict, send_fails: bool = False):
    """The shipped token leg on a fake chain whose pool knows the hashes in *pool*, at nonces
    pending/latest, with a send that reports its hash through `on_signed` before it is sent (as the
    real `_sign_and_send` does) and then optionally fails."""
    order: list[str] = []
    leg = _real_verify_leg(on_chain={}, held=0, order=order, inflight=pending, settled=latest)

    async def get_transaction(h):
        if h in pool:
            return dict(pool[h])
        raise NetworkError(f"eth_getTransactionByHash failed: not found {h}")

    leg._rpc.get_transaction = get_transaction
    sent: list[dict] = []

    async def _sign_and_send(tx, *, preflight=True, private=False, on_signed=None):
        if on_signed is not None:
            await on_signed(_REPLACEMENT)
        if send_fails:
            raise NetworkError("replacement transaction underpriced")
        sent.append(dict(tx))
        order.append("tokens-pushed")
        return _REPLACEMENT

    leg._sign_and_send = _sign_and_send
    return leg, sent


def _resume(leg, push_tx_hash: str, recorded: list[tuple[int, str]] | None = None):
    recorded = [] if recorded is None else recorded

    async def on_push_hash(nonce: int, h: str) -> None:
        recorded.append((nonce, h))

    asyncio.run(
        leg.fund(
            hashlock=b"\x33" * 32,
            claimant=_CLAIMANT,
            refundee=_REFUNDEE,
            timeout=_FUND_TIMEOUT,
            amount_wei=_AMOUNT,
            resume_from=_PENDING,
            push_nonce=_PIN,
            push_tx_hash=push_tx_hash,
            on_push_hash=on_push_hash,
        )
    )
    return recorded


_STUCK = {_ORIGINAL: {"maxFeePerGas": 3, "maxPriorityFeePerGas": 1, "nonce": _PIN}}


class TestTheReplacementBranchExecuted:
    def test_a_resume_replaces_its_own_stuck_push_at_the_pin_with_both_fees_raised(self) -> None:
        """Honest path: one transaction in our slot, read back by its recorded hash."""
        leg, sent = _resuming_leg(pending=_PIN + 1, latest=_PIN, pool=_STUCK)
        recorded = _resume(leg, _ORIGINAL)
        assert len(sent) == 1 and sent[0]["nonce"] == _PIN
        assert sent[0]["maxFeePerGas"] > 3 and sent[0]["maxPriorityFeePerGas"] > 1
        assert recorded == [(_PIN, _REPLACEMENT)], "the replacement's hash was not recorded before its send"

    def test_after_a_failed_replacement_the_next_resume_refuses_and_says_why(self) -> None:
        """The Mythos M1 case. The first resume records the replacement's hash and its send fails;
        the original is still pending. The next resume cannot read the recorded hash back: it must
        refuse with the in-flight explanation, send nothing, and not surface a bare RPC failure."""
        leg, _ = _resuming_leg(pending=_PIN + 1, latest=_PIN, pool=_STUCK, send_fails=True)
        recorded: list[tuple[int, str]] = []
        with pytest.raises(NetworkError, match="underpriced"):
            _resume(leg, _ORIGINAL, recorded)
        assert recorded == [(_PIN, _REPLACEMENT)], "precondition: the record now names the failed replacement"
        leg, sent = _resuming_leg(pending=_PIN + 1, latest=_PIN, pool=_STUCK)
        with pytest.raises(NetworkError) as raised:
            _resume(leg, recorded[-1][1])  # what the record now holds
        msg = str(raised.value)
        assert "still occupies the pinned push nonce 41" in msg and _REPLACEMENT in msg, msg
        assert "Nothing was sent" in msg and "mine or drop" in msg, msg
        assert sent == []

    def test_an_unrelated_transaction_in_our_slot_is_refused_not_priced(self) -> None:
        """Our push was evicted and something else took the slot: the recorded hash is unknown."""
        leg, sent = _resuming_leg(pending=_PIN + 1, latest=_PIN, pool={})
        with pytest.raises(NetworkError, match="cannot be read back"):
            _resume(leg, _ORIGINAL)
        assert sent == []

    def test_once_the_slot_is_free_a_resume_sends_at_the_pin_again(self) -> None:
        """Honest path after the wedge clears: nothing in flight, so the stale recorded hash is not
        consulted and a plain send at the pinned nonce goes out."""
        leg, sent = _resuming_leg(pending=_PIN, latest=_PIN, pool={})
        _resume(leg, _REPLACEMENT)
        assert len(sent) == 1 and sent[0]["nonce"] == _PIN
