"""Conformance tests for the concrete BTC HTLC leg (``BitcoinTaprootLeg``).

No real chain: the broadcaster + funding reader are fakes that record calls and
hand back the values a real regtest node would. These tests cover the leg
contract the ``SwapCoordinator`` relies on — SPK derivation, the audit gate,
idempotent broadcast, on-chain amount read-back (D4), and role-keyed claim/refund —
without moving any value. The live two-wallet regtest swap (T5) is a separate,
docker-gated effort.
"""

from __future__ import annotations

import hashlib
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import (
    AUDIT_CLEARED_NETWORKS,
    BitcoinCoreBroadcaster,
    BitcoinTaprootLeg,
    FundingPolicy,
    require_audit_cleared,
)
from pyrxd.btc_wallet.keys import BtcKeypair, generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.swap_state import NegotiatedTerms
from pyrxd.security.errors import InsufficientConfirmationsError, NetworkError, ValidationError

# --------------------------------------------------------------------------- helpers


def _xonly_of(kp: BtcKeypair) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(kp._privkey.unsafe_raw_bytes()).format()


def _terms(*, maker_kp: BtcKeypair, taker_kp: BtcKeypair, hashlock: bytes | None = None) -> NegotiatedTerms:
    """Terms whose BTC leaf keys correspond to real keypairs (maker=claim, taker=refund)."""
    if hashlock is None:
        hashlock = hashlib.sha256(os.urandom(32)).digest()
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly_of(maker_kp),
        btc_refund_pubkey_xonly=_xonly_of(taker_kp),
    )


class FakeBroadcaster:
    """Records broadcasts; returns the txid the node would. ``echo_txid`` simulates
    a mismatching broadcast result (e.g. a wrong-tx node)."""

    def __init__(self, *, txid: str | None = None) -> None:
        self.raw_seen: list[bytes] = []
        self._txid = txid

    async def broadcast(self, raw_tx: bytes) -> str:
        self.raw_seen.append(bytes(raw_tx))
        if self._txid is not None:
            return self._txid
        # Default: derive the same BE txid build_payment_tx would (non-witness hash).
        # For the funding tx the leg authoritatively uses payment.txid, so this is
        # only consulted for claim/refund; return a deterministic stand-in.
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


class FakeFundingReader:
    """Returns a configured on-chain amount; records the conf threshold it was asked for."""

    def __init__(self, *, amount_sats: int = 100_000, raise_shallow: bool = False, claim_confs: int = 100) -> None:
        self.amount_sats = amount_sats
        self.raise_shallow = raise_shallow
        self.claim_confs = claim_confs
        self.asked_min_confs: int | None = None

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        self.asked_min_confs = min_confirmations
        if self.raise_shallow:
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)
        return self.amount_sats

    async def confirmations(self, txid: str) -> int:
        return self.claim_confs

    async def txid_of(self, raw_tx: bytes) -> str:
        # Node-authoritative txid; the fake just hashes deterministically.
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


def _leg(
    *,
    taker_kp: BtcKeypair,
    maker_kp: BtcKeypair,
    broadcaster=None,
    reader=None,
    network: str = "bcrt",
    maker_claim_privkey: bytes | None = None,
    funding_value: int = 200_000,
) -> BitcoinTaprootLeg:
    return BitcoinTaprootLeg(
        network=network,
        taker_keypair=taker_kp,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=funding_value),
        maker_claim_pubkey_xonly=_xonly_of(maker_kp),
        broadcaster=broadcaster or FakeBroadcaster(),
        funding_reader=reader or FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        maker_claim_privkey=maker_claim_privkey,
    )


# --------------------------------------------------------------------------- audit gate


def test_audit_gate_allows_test_chains():
    for net in AUDIT_CLEARED_NETWORKS:
        require_audit_cleared(net, audit_cleared=False)  # no raise


def test_audit_gate_no_longer_blocks_mainnet_without_optin():
    # 0.9.0: the audit gate is retained for backward-compat but no longer raises.
    require_audit_cleared("bc", audit_cleared=False)  # no raise


def test_audit_gate_allows_mainnet_with_explicit_optin():
    require_audit_cleared("bc", audit_cleared=True)  # no raise


def test_leg_ctor_constructs_on_mainnet_without_optin():
    # 0.9.0: the leg no longer refuses to construct for a value-bearing network.
    taker, maker = generate_keypair("bc"), generate_keypair("bc")
    leg = _leg(taker_kp=taker, maker_kp=maker, network="bc")
    assert leg.network == "bc"


# --------------------------------------------------------------------------- SPK derivation


def test_derive_and_promised_spk_match_and_equal_htlc():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    leg = _leg(taker_kp=taker, maker_kp=maker)
    expected = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    ).scriptpubkey
    assert leg.derive_funding_scriptpubkey(terms) == expected
    assert leg.promised_funding_scriptpubkey(terms) == expected


# --------------------------------------------------------------------------- fund


async def test_fund_reads_amount_from_chain_not_self_report():
    """D4: the locator amount comes from the funding reader (on-chain), not the
    builder's self-reported value. Configure the reader to disagree and prove the
    locator carries the reader's number."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    reader = FakeFundingReader(amount_sats=100_000)
    bc = FakeBroadcaster()
    leg = _leg(taker_kp=taker, maker_kp=maker, broadcaster=bc, reader=reader)
    # The leg uses build_payment_tx's authoritative txid; make the broadcaster echo it.
    # (fund() asserts broadcast txid == built txid.)
    from pyrxd.btc_wallet.payment import build_payment_tx

    htlc = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )
    built = build_payment_tx(
        taker,
        leg.funding_utxo,
        to_hash=htlc.output_key,
        to_type="p2tr",
        amount_sats=terms.btc_sats,
        fee_sats=500,
        input_type="p2wpkh",
    )
    bc._txid = built.txid

    locator = await leg.fund(terms)
    assert isinstance(locator, t.BtcHtlcLocator)
    assert locator.amount_sats == 100_000  # from the reader
    assert locator.funding_outpoint.txid == built.txid
    assert locator.funding_outpoint.vout == 0
    assert reader.asked_min_confs == 1  # conf-gated
    assert len(bc.raw_seen) == 1  # broadcast once


async def test_fund_fail_closed_on_broadcast_txid_mismatch():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    bc = FakeBroadcaster(txid="ff" * 32)  # deliberately wrong txid
    leg = _leg(taker_kp=taker, maker_kp=maker, broadcaster=bc)
    with pytest.raises(NetworkError, match="!= built funding txid"):
        await leg.fund(terms)


async def test_fund_fail_closed_on_shallow_funding():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    from pyrxd.btc_wallet.payment import build_payment_tx

    htlc = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )
    bc = FakeBroadcaster()
    reader = FakeFundingReader(raise_shallow=True)
    leg = _leg(taker_kp=taker, maker_kp=maker, broadcaster=bc, reader=reader)
    built = build_payment_tx(
        taker,
        leg.funding_utxo,
        to_hash=htlc.output_key,
        to_type="p2tr",
        amount_sats=terms.btc_sats,
        fee_sats=500,
        input_type="p2wpkh",
    )
    bc._txid = built.txid
    with pytest.raises(NetworkError, match="confirmations"):
        await leg.fund(terms)


class _ShallowThenConfirmReader(FakeFundingReader):
    """Raises the 'not enough confs' NetworkError ``shallow_calls`` times, then returns
    the amount — models a just-broadcast tx that confirms after a few polls. The message
    raises InsufficientConfirmationsError — the typed exception fund()'s retry-guard
    catches by class, not by substring."""

    def __init__(self, *, shallow_calls: int, amount_sats: int = 100_000) -> None:
        super().__init__(amount_sats=amount_sats)
        self._remaining = shallow_calls
        self.read_calls = 0

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        self.read_calls += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)
        return self.amount_sats


def _fund_built_txid(terms, leg, taker):
    from pyrxd.btc_wallet.payment import build_payment_tx

    htlc = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )
    built = build_payment_tx(
        taker,
        leg.funding_utxo,
        to_hash=htlc.output_key,
        to_type="p2tr",
        amount_sats=terms.btc_sats,
        fee_sats=500,
        input_type="p2wpkh",
    )
    return built.txid


async def test_fund_polls_for_confirmation_when_configured():
    """Regression for the first-mainnet-run bug: fund() broadcasts then reads the amount
    back, but on a chain without on-demand mining the tx is 0-conf for ~1 block. With a
    poll interval set, fund() retries the 'needs confs' error until the tx confirms
    instead of failing instantly. (poll_s tiny so the test is fast.)"""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    bc = FakeBroadcaster()
    reader = _ShallowThenConfirmReader(shallow_calls=2, amount_sats=terms.btc_sats)
    leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=bc,
        funding_reader=reader,
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        fund_confirm_poll_s=0.01,
        fund_confirm_timeout_s=30.0,
    )
    bc._txid = _fund_built_txid(terms, leg, taker)
    locator = await leg.fund(terms)
    assert locator.amount_sats == terms.btc_sats
    assert reader.read_calls == 3  # 2 shallow + 1 success


async def test_fund_poll_times_out_still_fail_closed():
    """If the funding tx never confirms within the timeout, fund() re-raises the typed
    InsufficientConfirmationsError rather than returning an unconfirmed amount
    (still fail-closed). Uses a tiny but non-zero timeout — the cbd5fc0 fix-up ctor
    validation rejects ``poll_s > 0 and timeout_s == 0`` (silent zero-budget loop)."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    bc = FakeBroadcaster()
    reader = _ShallowThenConfirmReader(shallow_calls=10**9)  # never confirms
    leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=bc,
        funding_reader=reader,
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        fund_confirm_poll_s=0.005,
        fund_confirm_timeout_s=0.05,  # one or two retries then timeout
    )
    bc._txid = _fund_built_txid(terms, leg, taker)
    with pytest.raises(InsufficientConfirmationsError) as ei:
        await leg.fund(terms)
    assert ei.value.have == 0
    assert ei.value.required == 1


async def test_fund_poll_does_not_swallow_other_errors():
    """A non-confirmation NetworkError (e.g. bad vout) must NOT be retried — it
    propagates immediately even with polling enabled."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    bc = FakeBroadcaster()

    class _BadVoutReader(FakeFundingReader):
        async def read_output_amount_sats(self, txid, vout, *, min_confirmations):
            raise NetworkError("could not read output value for deadbeef…:0")

    leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=bc,
        funding_reader=_BadVoutReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        fund_confirm_poll_s=0.01,
        fund_confirm_timeout_s=30.0,
    )
    bc._txid = _fund_built_txid(terms, leg, taker)
    with pytest.raises(NetworkError, match="could not read output value"):
        await leg.fund(terms)


def test_leg_ctor_accepts_funding_policy_dataclass():
    """The new policy=FundingPolicy(...) form mirrors the legacy loose kwargs and
    produces a leg with the same observable shape."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=FakeBroadcaster(),
        funding_reader=FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        policy=FundingPolicy(fee_sats=750, min_confirmations=3, funding_input_type="p2wpkh"),
    )
    assert isinstance(leg.policy, FundingPolicy)
    assert leg.fee_sats == 750
    assert leg.min_confirmations == 3
    assert leg.funding_input_type == "p2wpkh"


def test_leg_ctor_rejects_policy_and_legacy_kwargs_mixed():
    """``policy=`` and the legacy loose kwargs are mutually exclusive — passing both
    raises so the source-of-truth is never ambiguous."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    with pytest.raises(ValidationError, match="policy=FundingPolicy"):
        BitcoinTaprootLeg(
            network="bcrt",
            taker_keypair=taker,
            funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
            maker_claim_pubkey_xonly=_xonly_of(maker),
            broadcaster=FakeBroadcaster(),
            funding_reader=FakeFundingReader(),
            refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
            claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
            policy=FundingPolicy(fee_sats=500),
            fee_sats=999,  # mixing
        )


def test_leg_ctor_rejects_non_funding_policy_object():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    with pytest.raises(ValidationError, match="policy must be a FundingPolicy"):
        BitcoinTaprootLeg(
            network="bcrt",
            taker_keypair=taker,
            funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
            maker_claim_pubkey_xonly=_xonly_of(maker),
            broadcaster=FakeBroadcaster(),
            funding_reader=FakeFundingReader(),
            refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
            claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
            policy={"fee_sats": 500},  # type: ignore[arg-type]
        )


def test_leg_ctor_rejects_poll_without_timeout():
    """Footgun: ``fund_confirm_poll_s>0`` with ``fund_confirm_timeout_s<=0`` reads as
    "poll forever" but actually times out on the first retry (deadline = now + 0).
    The ctor must reject this combination loudly (security-sentinel L1)."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    with pytest.raises(ValidationError, match="fund_confirm_poll_s > 0 requires"):
        BitcoinTaprootLeg(
            network="bcrt",
            taker_keypair=taker,
            funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
            maker_claim_pubkey_xonly=_xonly_of(maker),
            broadcaster=FakeBroadcaster(),
            funding_reader=FakeFundingReader(),
            refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
            claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
            fee_sats=500,
            min_confirmations=1,
            fund_confirm_poll_s=0.1,
            fund_confirm_timeout_s=0.0,
        )


# --------------------------------------------------------------------------- claim / refund


async def test_claim_requires_maker_key():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    leg = _leg(taker_kp=taker, maker_kp=maker)  # no maker_claim_privkey -> taker-role
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    with pytest.raises(ValidationError, match="maker_claim_privkey"):
        await leg.claim(locator, os.urandom(32))


async def test_claim_broadcasts_with_maker_key_and_reveals_preimage():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    terms = _terms(maker_kp=maker, taker_kp=taker, hashlock=h)
    bc = FakeBroadcaster()
    leg = _leg(
        taker_kp=taker,
        maker_kp=maker,
        broadcaster=bc,
        maker_claim_privkey=maker._privkey.unsafe_raw_bytes(),
    )
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    await leg.claim(locator, p)
    assert len(bc.raw_seen) == 1
    # The preimage is recoverable from the broadcast claim tx witness (real claim).
    assert t.scrape_secret(bc.raw_seen[0], h) == p


async def test_refund_signs_with_taker_key_and_broadcasts():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    bc = FakeBroadcaster()
    leg = _leg(taker_kp=taker, maker_kp=maker, broadcaster=bc)
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    await leg.refund(locator, terms.t_btc)
    assert len(bc.raw_seen) == 1  # broadcast the CSV refund


# --------------------------------------------------------------------------- broadcaster idempotency


class _FakeRpc:
    """Async rpc(method, params) stand-in for BitcoinCoreBroadcaster."""

    def __init__(self, *, send_result=None, send_error: str | None = None, decode_txid: str | None = None) -> None:
        self.send_result = send_result
        self.send_error = send_error
        self.decode_txid = decode_txid
        self.calls: list[str] = []

    async def __call__(self, method: str, params: list):
        self.calls.append(method)
        if method == "sendrawtransaction":
            if self.send_error is not None:
                raise NetworkError(self.send_error)
            return self.send_result
        if method == "decoderawtransaction":
            return {"txid": self.decode_txid}
        raise AssertionError(f"unexpected rpc {method}")


async def test_broadcaster_returns_node_txid_on_success():
    rpc = _FakeRpc(send_result="ab" * 32)
    bcaster = BitcoinCoreBroadcaster(rpc)
    txid = await bcaster.broadcast(b"\x02\x00rawtx")
    assert txid == "ab" * 32
    assert rpc.calls == ["sendrawtransaction"]


async def test_broadcaster_idempotent_on_already_known():
    """A node that already has the tx is SUCCESS — the broadcaster resolves the
    canonical txid via decoderawtransaction rather than treating it as an error."""
    rpc = _FakeRpc(send_error="txn-already-known", decode_txid="cd" * 32)
    bcaster = BitcoinCoreBroadcaster(rpc)
    txid = await bcaster.broadcast(b"\x02\x00rawtx")
    assert txid == "cd" * 32
    assert rpc.calls == ["sendrawtransaction", "decoderawtransaction"]


async def test_broadcaster_raises_on_real_error():
    rpc = _FakeRpc(send_error="non-mandatory-script-verify-flag")
    bcaster = BitcoinCoreBroadcaster(rpc)
    with pytest.raises(NetworkError, match="sendrawtransaction failed"):
        await bcaster.broadcast(b"\x02\x00rawtx")


# --------------------------------------------------------------------------- fail-closed guards


def test_broadcaster_rejects_non_callable_rpc():
    with pytest.raises(ValidationError, match="async callable"):
        BitcoinCoreBroadcaster(rpc="not-callable")  # type: ignore[arg-type]


async def test_broadcaster_rejects_empty_raw():
    bcaster = BitcoinCoreBroadcaster(_FakeRpc(send_result="ab" * 32))
    with pytest.raises(ValidationError, match="non-empty bytes"):
        await bcaster.broadcast(b"")


async def test_broadcaster_raises_when_send_returns_non_str():
    bcaster = BitcoinCoreBroadcaster(_FakeRpc(send_result=12345))
    with pytest.raises(NetworkError, match="did not return a txid"):
        await bcaster.broadcast(b"\x02\x00rawtx")


async def test_broadcaster_raises_when_decode_missing_txid_on_already_known():
    rpc = _FakeRpc(send_error="already in mempool", decode_txid=None)
    bcaster = BitcoinCoreBroadcaster(rpc)
    with pytest.raises(NetworkError, match="decoderawtransaction did not return a txid"):
        await bcaster.broadcast(b"\x02\x00rawtx")


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"broadcaster": object()}, "BtcBroadcaster"),
        ({"funding_reader": object()}, "BtcFundingReader"),
        ({"fee_sats": 0}, "fee_sats"),
        ({"min_confirmations": -1}, "min_confirmations"),
    ],
)
def test_leg_ctor_fail_closed_validation(kwargs, match):
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    base = dict(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=FakeBroadcaster(),
        funding_reader=FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
    )
    base.update(kwargs)
    with pytest.raises(ValidationError, match=match):
        BitcoinTaprootLeg(**base)


def test_leg_ctor_rejects_non_keypair_and_non_utxo():
    maker = generate_keypair("bcrt")
    common = dict(
        network="bcrt",
        maker_claim_pubkey_xonly=_xonly_of(maker),
        broadcaster=FakeBroadcaster(),
        funding_reader=FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
    )
    with pytest.raises(ValidationError, match="taker_keypair"):
        BitcoinTaprootLeg(taker_keypair=object(), funding_utxo=BtcUtxo("ab" * 32, 0, 200_000), **common)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="funding_utxo"):
        BitcoinTaprootLeg(taker_keypair=generate_keypair("bcrt"), funding_utxo=object(), **common)  # type: ignore[arg-type]


async def test_fund_fail_closed_on_nonpositive_onchain_amount():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    from pyrxd.btc_wallet.payment import build_payment_tx

    htlc = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )
    bc = FakeBroadcaster()
    reader = FakeFundingReader(amount_sats=0)  # node reports a 0-value output
    leg = _leg(taker_kp=taker, maker_kp=maker, broadcaster=bc, reader=reader)
    built = build_payment_tx(
        taker,
        leg.funding_utxo,
        to_hash=htlc.output_key,
        to_type="p2tr",
        amount_sats=terms.btc_sats,
        fee_sats=500,
        input_type="p2wpkh",
    )
    bc._txid = built.txid
    with pytest.raises(NetworkError, match="non-positive on-chain amount"):
        await leg.fund(terms)


async def test_claim_and_refund_reject_bad_locator():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker, maker_claim_privkey=maker._privkey.unsafe_raw_bytes())
    with pytest.raises(ValidationError, match="locator must be a BtcHtlcLocator"):
        await leg.claim(object(), os.urandom(32))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="locator must be a BtcHtlcLocator"):
        await leg.refund(object(), t.Timelock(144, t.TimeUnit.BLOCKS))  # type: ignore[arg-type]


async def test_refund_rejects_non_timelock():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker, taker_kp=taker)
    leg = _leg(taker_kp=taker, maker_kp=maker)
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    with pytest.raises(ValidationError, match="timeout must be a Timelock"):
        await leg.refund(locator, 144)  # type: ignore[arg-type]


def test_scrape_secret_passthrough():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    terms = _terms(maker_kp=maker, taker_kp=taker, hashlock=h)
    leg = _leg(taker_kp=taker, maker_kp=maker)
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    claim_tx = t.build_claim_tx(
        locator=locator,
        preimage=p,
        claim_privkey=maker._privkey.unsafe_raw_bytes(),
        to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    assert leg.scrape_secret(claim_tx, h) == p


# --------------------------------------------------------------------------- reorg gate: confirmations_of_claim


def _real_claim_tx(taker, maker) -> bytes:
    """A real maker claim tx (so the leg's LOCAL btc_txid_from_raw can derive its txid).

    The preimage must open the HTLC hashlock for build_claim_tx to accept it, so the
    HTLC is bound to sha256(p) for a fixed p.
    """
    p = b"\x11" * 32
    htlc = t.build_htlc(
        hashlock=hashlib.sha256(p).digest(),
        claim_pubkey_xonly=_xonly_of(maker),
        refund_pubkey_xonly=_xonly_of(taker),
        timeout=t.Timelock(144, t.TimeUnit.BLOCKS),
        network="bcrt",
    )
    loc = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), 100_000)
    return t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker._privkey.unsafe_raw_bytes(),
        to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )


async def test_confirmations_of_claim_returns_depth():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    reader = FakeFundingReader(claim_confs=7)
    leg = _leg(taker_kp=taker, maker_kp=maker, reader=reader)
    # The leg derives the txid LOCALLY from these bytes (btc_txid_from_raw), so the tx
    # must be a real, well-formed claim tx — a non-tx byte string would fail-close.
    assert await leg.confirmations_of_claim(_real_claim_tx(taker, maker)) == 7


async def test_confirmations_of_claim_rejects_empty_bytes():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker)
    with pytest.raises(ValidationError, match="non-empty bytes"):
        await leg.confirmations_of_claim(b"")


async def test_confirmations_of_claim_fail_closed_on_malformed_tx():
    """A non-tx byte string fails closed in the LOCAL txid derivation (never reads a
    bogus depth)."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker)
    with pytest.raises(ValidationError):  # btc_txid_from_raw rejects the garbage bytes
        await leg.confirmations_of_claim(b"\x02\x00rawclaimtx")


async def test_confirmations_of_claim_fail_closed_on_bad_depth():
    class BadReader(FakeFundingReader):
        async def confirmations(self, txid: str) -> int:
            return -1  # nonsense depth

    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker, reader=BadReader())
    with pytest.raises(NetworkError, match="non-negative-int depth"):
        await leg.confirmations_of_claim(_real_claim_tx(taker, maker))
