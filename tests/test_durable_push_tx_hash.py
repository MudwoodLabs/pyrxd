"""The push transaction's hash is durable BEFORE it is broadcast (#515, #504 item 1).

The nonce pin identifies the SLOT; the hash identifies the TRANSACTION. A resume that wants to
replace its own still-pending push must clear that transaction's fees by a margin, which means
reading them — and `eth_getTransactionByHash` needs the hash. `txpool_content` is non-standard and
absent from most public endpoints, so without a durable hash there is no way to price a
replacement at all. That missing read, not the arithmetic, is what blocked the carve-out.

Recordable before the broadcast because a signed transaction's hash is keccak of its own bytes.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.swap_state import SwapRecord, SwapState
from pyrxd.security.errors import ValidationError
from tests.test_swap_record_erc20_migration import _erc20_locator, _token_terms

_GOOD = "0x" + "ab" * 32


@pytest.fixture
def erc20_record() -> SwapRecord:
    """A record with a PENDING DEPLOY, because that is the only state a pending push exists in.

    The push fields are serialised inside `if self.pending_counter_contract:` — deliberately, so a
    BTC record stays byte-identical to the v1 wire form. A fixture with a push nonce and no pending
    contract is a state the system never produces, and a round-trip assertion against it tests
    nothing.
    """
    return SwapRecord(
        state=SwapState.NEGOTIATED,
        terms=_token_terms(),
        counterchain_locator=_erc20_locator(),
        pending_counter_contract="0x" + "77" * 20,
        pending_counter_deploy_tx="0x" + "de" * 32,
    )


def _with(record: SwapRecord, **kw) -> SwapRecord:
    import dataclasses

    return dataclasses.replace(record, **kw)


class TestTheRecordHoldsIt:
    def test_a_hash_and_its_nonce_round_trip(self, erc20_record: SwapRecord) -> None:
        rec = _with(erc20_record, pending_push_nonce=7, pending_push_tx_hash=_GOOD)
        back = SwapRecord.from_dict(rec.to_dict())
        assert back.pending_push_nonce == 7
        assert back.pending_push_tx_hash == _GOOD

    def test_absent_by_default_and_omitted_from_the_wire(self, erc20_record: SwapRecord) -> None:
        """A record with no pending push must serialise exactly as before, or an older reader sees
        a field it cannot interpret for a swap that has none."""
        assert erc20_record.pending_push_tx_hash is None
        assert "pending_push_tx_hash" not in erc20_record.to_dict()

    def test_a_record_with_NO_pending_deploy_never_grows_the_field(self) -> None:
        """The v1-wire-form guarantee. Push fields live inside the pending-deploy branch, so a BTC
        or fresh record stays byte-identical to what a pre-ETH binary wrote."""
        bare = SwapRecord(state=SwapState.NEGOTIATED, terms=_token_terms(), counterchain_locator=_erc20_locator())
        d = bare.to_dict()
        assert "pending_push_tx_hash" not in d and "pending_push_nonce" not in d

    def test_a_malformed_hash_is_refused(self, erc20_record: SwapRecord) -> None:
        """The same shape check the deploy handle uses. A durable reference that round-trips
        garbage reads as a record and points nowhere."""
        for bad in ("0x", "0xzz", "0x" + "ab" * 31, "ab" * 32):
            with pytest.raises(ValidationError):
                _with(erc20_record, pending_push_nonce=7, pending_push_tx_hash=bad)

    def test_a_hash_WITHOUT_its_nonce_is_refused(self, erc20_record: SwapRecord) -> None:
        """Both or neither. With only the hash a resume could neither replace the pending push nor
        rule out sending a second one at a different nonce — a handle it cannot act on."""
        with pytest.raises(ValidationError, match="without pending_push_nonce"):
            _with(erc20_record, pending_push_nonce=None, pending_push_tx_hash=_GOOD)

    def test_a_nonce_without_a_hash_is_still_fine(self, erc20_record: SwapRecord) -> None:
        """The honest path, and the pre-existing shape. Every record written before this field
        existed has a pin and no hash, and must still load."""
        rec = _with(erc20_record, pending_push_nonce=7)
        assert SwapRecord.from_dict(rec.to_dict()).pending_push_nonce == 7


class TestTheLegRecordsItBeforeSending:
    """Reachability: a field nothing writes is not a durable handle."""

    def test_the_push_threads_an_on_push_hash_hook(self) -> None:
        import inspect

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

        src = inspect.getsource(Erc20HtlcLeg._push_and_bind)
        assert "on_push_hash" in src
        # It must ride `on_signed`, which fires BETWEEN signing and sending — recording after the
        # broadcast would leave exactly the window the hash exists to close.
        assert "on_signed=" in src
        assert src.index("on_signed=") > src.index("on_push_hash"), "the hook is not wired to the send"

    def test_fund_exposes_it_to_callers(self) -> None:
        import inspect

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

        assert "on_push_hash" in inspect.signature(Erc20HtlcLeg.fund).parameters or "on_push_hash" in (
            inspect.getsource(Erc20HtlcLeg.fund)
        )
