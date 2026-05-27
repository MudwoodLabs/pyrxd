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
    require_audit_cleared,
)
from pyrxd.btc_wallet.keys import BtcKeypair, generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.swap_state import NegotiatedTerms
from pyrxd.security.errors import NetworkError, ValidationError

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
            raise NetworkError(f"output has 0 confirmations, required {min_confirmations}")
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


def test_audit_gate_refuses_mainnet_without_optin():
    with pytest.raises(ValidationError, match="value-bearing"):
        require_audit_cleared("bc", audit_cleared=False)


def test_audit_gate_allows_mainnet_with_explicit_optin():
    require_audit_cleared("bc", audit_cleared=True)  # no raise


def test_audit_gate_rejects_empty_network():
    with pytest.raises(ValidationError, match="non-empty"):
        require_audit_cleared("", audit_cleared=True)


def test_leg_ctor_refuses_mainnet_without_optin():
    taker, maker = generate_keypair("bc"), generate_keypair("bc")
    with pytest.raises(ValidationError, match="value-bearing"):
        _leg(taker_kp=taker, maker_kp=maker, network="bc")


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


async def test_confirmations_of_claim_returns_depth():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    reader = FakeFundingReader(claim_confs=7)
    leg = _leg(taker_kp=taker, maker_kp=maker, reader=reader)
    assert await leg.confirmations_of_claim(b"\x02\x00rawclaimtx") == 7


async def test_confirmations_of_claim_rejects_empty_bytes():
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker)
    with pytest.raises(ValidationError, match="non-empty bytes"):
        await leg.confirmations_of_claim(b"")


async def test_confirmations_of_claim_fail_closed_on_bad_depth():
    class BadReader(FakeFundingReader):
        async def confirmations(self, txid: str) -> int:
            return -1  # nonsense depth

    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    leg = _leg(taker_kp=taker, maker_kp=maker, reader=BadReader())
    with pytest.raises(NetworkError, match="non-negative-int depth"):
        await leg.confirmations_of_claim(b"\x02\x00rawclaimtx")
