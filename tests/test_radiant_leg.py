"""Conformance tests for the concrete Radiant covenant leg (radiant_leg.py).

No real chain: the ElectrumX client + indexer are fakes that return what a real
regtest node/indexer would. These pin the leg contract the SwapCoordinator drives —
covenant SPK derivation bound to the terms' dest hashes, outpoint discovery by SPK
UTXO scan, conf-gated on-chain carrier value, the RXinDexer->ResolvedRef adapter
through the real verify_ref_authenticity gate, idempotent broadcast, the SeenStore,
and the audit gate. On-chain acceptance is the e2e regtest milestone (step 5).
"""

from __future__ import annotations

import hashlib
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft, build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import (
    RadiantChainIO,
    RadiantCovenantLeg,
    RxinDexerRefAdapter,
    SeenStore,
)
from pyrxd.gravity.ref_authenticity import verify_ref_authenticity
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20

_P = b"\xaa" * 32
_H = hashlib.sha256(_P).digest()
_TAKER_PKH = b"\x11" * 20
_MAKER_PKH = b"\x22" * 20
_REF_TXID = "ab" * 32


def _xonly() -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _rxd_terms(amount: int = 100_000, csv: int = 6) -> NegotiatedTerms:
    cov = build_htlc_covenant_rxd(
        amount=amount, taker_pkh=_TAKER_PKH, maker_pkh=_MAKER_PKH, hashlock=_H, refund_csv=csv
    )
    return NegotiatedTerms(
        hashlock=_H,
        btc_sats=100_000,
        radiant_amount=amount,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(csv, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _ft_terms(amount: int = 1000, csv: int = 6) -> NegotiatedTerms:
    cov = build_htlc_covenant_ft(
        genesis_txid=_REF_TXID,
        genesis_vout=0,
        amount=amount,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=csv,
    )
    return NegotiatedTerms(
        hashlock=_H,
        btc_sats=100_000,
        radiant_amount=amount,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(csv, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=GlyphRef(txid=_REF_TXID, vout=0).to_bytes(),
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


class FakeClient:
    """A fake ElectrumX client: configurable confs + UTXO set + broadcast result."""

    def __init__(
        self,
        *,
        confirmations: int = 3,
        utxo_value: int = 100_000,
        utxos: list | None = None,
        broadcast_error: str | None = None,
    ) -> None:
        self.confirmations_val = confirmations
        self.utxo_value = utxo_value
        self._utxos = utxos
        self.broadcast_error = broadcast_error
        self.broadcast_raw: list[bytes] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        self.broadcast_raw.append(bytes(raw_tx))
        if self.broadcast_error is not None:
            raise NetworkError(self.broadcast_error)
        return "ab" * 32

    async def get_transaction_verbose(self, txid):
        return {"confirmations": self.confirmations_val}

    async def get_utxos(self, script_hash):
        if self._utxos is not None:
            return self._utxos
        return [UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=self.utxo_value, height=100)]


class FakeIndexer:
    def __init__(self, token):
        self.token = token

    async def glyph_get_token(self, ref):
        return self.token


class FakeFeeSource:
    def next_fee_input(self) -> FeeInput:
        k = PrivateKey(bytes.fromhex("33" * 32))
        pkh = bytes(Hex20(k.public_key().hash160()))
        return FeeInput(
            txid="ef" * 32, vout=0, value=10_000_000, scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac", wif=k.wif()
        )


def _leg(*, client=None, fee_source=None, network="bcrt", min_confirmations=1):
    return RadiantCovenantLeg(
        network=network,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        chain_io=RadiantChainIO(client or FakeClient()),
        fee_source=fee_source or FakeFeeSource(),
        min_confirmations=min_confirmations,
    )


# --------------------------------------------------------------------------- SeenStore


def test_seen_store_roundtrip():
    s = SeenStore()
    h = b"\x01" * 32
    assert not s.has_seen(h)
    s.mark_seen(h)
    assert s.has_seen(h)
    assert not s.has_seen(b"\x02" * 32)


def test_seen_store_reserve_is_atomic_test_and_set():
    s = SeenStore()
    h = b"\x03" * 32
    assert s.reserve(h) is True  # freshly reserved
    assert s.reserve(h) is False  # already reserved => refused
    assert s.has_seen(h) is True
    assert s.durable is False  # the wired store is honestly non-durable


# --------------------------------------------------------------------------- audit gate


def test_leg_constructs_on_mainnet_without_optin():
    # 0.9.0: the audit gate is retained for backward-compat but no longer raises —
    # the leg constructs on a value-bearing network without the opt-in.
    leg = RadiantCovenantLeg(
        network="rxd",
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        chain_io=RadiantChainIO(FakeClient()),
        fee_source=FakeFeeSource(),
    )
    assert leg.network == "rxd"


# --------------------------------------------------------------------------- covenant SPK binding


async def test_expected_spk_matches_builder_and_binds_terms():
    terms = _rxd_terms()
    cov = build_htlc_covenant_rxd(
        amount=terms.radiant_amount,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=terms.t_rxd.value,
    )
    leg = _leg()
    assert await leg.expected_covenant_scriptpubkey(terms) == cov.funded_spk


async def test_expected_spk_ft_variant():
    terms = _ft_terms()
    leg = _leg()
    spk = await leg.expected_covenant_scriptpubkey(terms)
    assert spk.endswith(bytes.fromhex("dec0e9aa76e378e4a269e69d"))  # FT epilogue weld


async def test_spk_fail_closed_on_wrong_dest_hash():
    """If the leg's configured pkhs don't reproduce the terms' dest hashes, the leg
    is set up for the wrong party — fail closed before any spend."""
    terms = _rxd_terms()
    object.__setattr__(terms, "taker_dest_hash", b"\x00" * 32)  # corrupt the binding
    leg = _leg()
    with pytest.raises(ValidationError, match="taker_dest_hash"):
        await leg.expected_covenant_scriptpubkey(terms)


# --------------------------------------------------------------------------- outpoint discovery


async def test_covenant_outpoint_located_by_utxo_scan():
    terms = _rxd_terms(amount=100_000)
    leg = _leg(client=FakeClient(utxo_value=100_000))
    assert await leg.covenant_outpoint(terms) == "cd" * 32 + ":0"


async def test_covenant_outpoint_fail_closed_on_value_mismatch():
    terms = _rxd_terms(amount=100_000)
    leg = _leg(client=FakeClient(utxo_value=999))  # wrong carrier value
    with pytest.raises(NetworkError, match="matches the expected carrier value"):
        await leg.covenant_outpoint(terms)


async def test_covenant_outpoint_fail_closed_when_unfunded():
    terms = _rxd_terms()
    leg = _leg(client=FakeClient(utxos=[]))  # no UTXO yet
    with pytest.raises(NetworkError, match="no UTXO found"):
        await leg.covenant_outpoint(terms)


async def test_covenant_outpoint_ambiguous_utxo_fail_closed():
    terms = _rxd_terms(amount=100_000)
    dupes = [
        UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=100_000, height=100),
        UtxoRecord(tx_hash="ce" * 32, tx_pos=1, value=100_000, height=101),
    ]
    leg = _leg(client=FakeClient(utxos=dupes))
    with pytest.raises(NetworkError, match="ambiguous"):
        await leg.covenant_outpoint(terms)


async def test_find_covenant_utxo_registers_spk_for_registry_client():
    """Regression (mainnet autonomous-claim dust run, 2026-06-14): a registry-backed client
    (``SshTrRadiantClient``-style — ``get_utxos`` resolves a script_hash to its SPK via a
    ``register_spk`` registry to build its scantxoutset descriptor, so an UNREGISTERED
    covenant SPK scans EMPTY) returned no UTXO for a covenant the fresh per-swap claim leg
    never registered → ``find_covenant_utxo`` misread it as "not funded" and the autonomous
    executor declined "already spent" while the covenant sat unspent. ``find_covenant_utxo``
    must register the SPK it is about to scan (idempotent; no-op for registry-less clients)."""
    import hashlib

    spk = bytes.fromhex("76a914" + "11" * 20 + "88ac")

    class RegistryClient:
        """Resolves get_utxos ONLY for SPKs passed through register_spk (mirrors SshTr)."""

        def __init__(self) -> None:
            self._known: set[bytes] = set()

        def register_spk(self, s: bytes) -> None:
            self._known.add(hashlib.sha256(bytes(s)).digest()[::-1])

        async def broadcast(self, raw):  # pragma: no cover - unused here
            return "ab" * 32

        async def get_transaction_verbose(self, txid):  # pragma: no cover - unused here
            return {"confirmations": 10}

        async def get_utxos(self, script_hash):
            if bytes(script_hash) not in self._known:
                return []  # the bug's trigger: an unregistered SPK scans empty
            return [UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=1000, height=100)]

    io = RadiantChainIO(RegistryClient())
    # Pre-fix this raised NetworkError("no UTXO found ...") because the SPK was never
    # registered; post-fix find_covenant_utxo registers it first and locates the UTXO.
    outpoint, value, _height = await io.find_covenant_utxo(spk, expected_value=1000)
    assert outpoint == "cd" * 32 + ":0"
    assert value == 1000


async def test_covenant_unspent_incl_mempool_delegates_and_falls_back():
    """Mempool-AWARE covenant liveness (review HIGH): delegates to the client's optional
    ``txout_unspent_incl_mempool`` (gettxout include_mempool) when present — True=unspent,
    False=spent incl. mempool — and returns None when the client cannot answer, so a caller
    without the capability keeps its own idempotency guard."""

    class MempoolClient(FakeClient):
        def __init__(self, unspent: bool) -> None:
            super().__init__()
            self._unspent = unspent
            self.calls: list = []

        async def txout_unspent_incl_mempool(self, txid, vout):
            self.calls.append((txid, vout))
            return self._unspent

    c = MempoolClient(True)
    assert await RadiantChainIO(c).covenant_unspent_incl_mempool("ab" * 32 + ":0") is True
    assert c.calls == [("ab" * 32, 0)]  # outpoint split correctly
    # spent (confirmed OR in mempool) → False (the executor treats this as already-claimed).
    assert await RadiantChainIO(MempoolClient(False)).covenant_unspent_incl_mempool("cd" * 32 + ":1") is False
    # a client WITHOUT the capability → None (caller falls back to its SeenStore guard).
    assert await RadiantChainIO(FakeClient()).covenant_unspent_incl_mempool("ef" * 32 + ":0") is None
    # malformed outpoint fails closed.
    with pytest.raises(ValidationError, match="bad covenant outpoint"):
        await RadiantChainIO(MempoolClient(True)).covenant_unspent_incl_mempool("nocolon")


# --------------------------------------------------------------------------- claim / refund spends


async def test_claim_asset_builds_and_broadcasts():
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    leg = _leg(client=client)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    txid = await leg.claim_asset(rec, _P)
    assert txid == "ab" * 32
    assert len(client.broadcast_raw) == 1


async def test_refund_asset_builds_and_broadcasts():
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    leg = _leg(client=client)
    rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    txid = await leg.refund_asset(rec)
    assert txid == "ab" * 32
    assert len(client.broadcast_raw) == 1


async def test_spend_conf_gated():
    terms = _rxd_terms(amount=100_000)
    leg = _leg(client=FakeClient(utxo_value=100_000, confirmations=0), min_confirmations=1)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with pytest.raises(NetworkError, match="not yet spendable"):
        await leg.claim_asset(rec, _P)


async def test_spend_idempotent_on_already_known():
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3, broadcast_error="txn-already-known in mempool")
    leg = _leg(client=client)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    txid = await leg.claim_asset(rec, _P)
    # idempotent: returns the built tx's own txid (64-char hex), not an error.
    assert len(txid) == 64


async def test_spend_rejects_non_record():
    leg = _leg()
    with pytest.raises(ValidationError, match="record must be a SwapRecord"):
        await leg.claim_asset(object(), _P)
    with pytest.raises(ValidationError, match="record must be a SwapRecord"):
        await leg.refund_asset(object())


# --------------------------------------------------------------------------- RxinDexer ref adapter


async def test_ref_adapter_resolves_genuine_token():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_outpoint": f"{_REF_TXID}:0", "payload_hash": "99" * 32}), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved is not None
    assert resolved.genesis_outpoint == ref
    assert resolved.has_gly_marker is True
    assert resolved.payload_hash == bytes.fromhex("99" * 32)
    assert resolved.confirmations == 10


async def test_ref_adapter_accepted_by_gate():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_outpoint": f"{_REF_TXID}:0"}), io)
    await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)  # no raise


async def test_ref_adapter_unknown_token_rejected_by_gate():
    """R1: a self-crafted singleton that doesn't resolve -> None -> gate fail-closed."""
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient())
    adapter = RxinDexerRefAdapter(FakeIndexer(None), io)
    with pytest.raises(ValidationError, match="does not resolve to a minted asset"):
        await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)


async def test_ref_adapter_wrong_genesis_rejected_by_gate():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_outpoint": f"{'cd' * 32}:0"}), io)  # different genesis
    with pytest.raises(ValidationError, match="genesis outpoint does not equal"):
        await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)


async def test_ref_adapter_shallow_genesis_rejected_by_gate():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=2))  # < min
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_outpoint": f"{_REF_TXID}:0"}), io)
    with pytest.raises(ValidationError, match="confirmations"):
        await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)


async def test_ref_adapter_ref_txid_vout_fallback():
    """The adapter also accepts ref_txid + ref_vout when ref_outpoint is absent."""
    ref = GlyphRef(txid=_REF_TXID, vout=2).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_txid": _REF_TXID, "ref_vout": 2}), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved.genesis_outpoint == ref


async def test_ref_adapter_real_rxindexer_glyph_id_shape():
    """The REAL RXinDexer reports the genesis outpoint under ``glyph_id`` /
    ``txid`` + ``vout`` (NOT ``ref_outpoint`` / ``ref_txid``).

    Pinned to a live regtest RXinDexer capture (2026-06-01) of a genuinely
    minted NFT Glyph. The original adapter only read ``ref_outpoint`` /
    ``ref_txid``, so against the real indexer ``_genesis_outpoint`` fell through
    to the all-zero placeholder and the gate failed closed on EVERY real Glyph.
    The fake (which returns those legacy field names) never caught this; only an
    e2e against the real indexer did.
    """
    real_token = {  # verbatim glyph.get_token() shape from rxindexer-electrumx
        "glyph_id": f"{_REF_TXID}:0",
        "txid": _REF_TXID,
        "vout": 0,
        "value": 4_000_000,
        "envelope_source": "input:0",
        "version": 1,
        "is_reveal": True,
        "token_type": "NFT",
        "metadata": {"protocols": [2], "version": 1, "name": "X", "ticker": None, "decimals": 0},
    }
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer(real_token), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved is not None
    assert resolved.genesis_outpoint == ref  # was all-zero before the fix
    assert resolved.has_gly_marker is True
    # And the gate accepts it.
    await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)


async def test_ref_adapter_real_shape_txid_vout_without_glyph_id():
    """Fallback within the real-indexer shape: txid + vout when glyph_id absent."""
    ref = GlyphRef(txid=_REF_TXID, vout=3).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"txid": _REF_TXID, "vout": 3}), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved.genesis_outpoint == ref


async def test_ref_adapter_no_outpoint_field_fails_binding():
    """A token dict with no outpoint field -> placeholder genesis -> gate rejects."""
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"some_other_field": 1}), io)
    with pytest.raises(ValidationError, match="genesis outpoint does not equal"):
        await verify_ref_authenticity(adapter, ref, asset_variant="nft", min_confirmations=6)


async def test_ref_adapter_non_dict_token_raises():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient())
    adapter = RxinDexerRefAdapter(FakeIndexer(["not", "a", "dict"]), io)
    with pytest.raises(NetworkError, match="expected dict"):
        await adapter.resolve_ref(ref)


# --------------------------------------------------------------------------- chain-io / adapter validation


def test_chain_io_requires_client_methods():
    class Partial:
        async def broadcast(self, raw):  # missing get_transaction_verbose / get_utxos
            return "x"

    with pytest.raises(ValidationError, match="must provide"):
        RadiantChainIO(Partial())


def test_ref_adapter_requires_indexer_and_chain_io():
    io = RadiantChainIO(FakeClient())
    with pytest.raises(ValidationError, match="glyph_get_token"):
        RxinDexerRefAdapter(object(), io)
    with pytest.raises(ValidationError, match="chain_io must be a RadiantChainIO"):
        RxinDexerRefAdapter(FakeIndexer(None), object())


def test_leg_validates_chain_io_and_fee_source():
    with pytest.raises(ValidationError, match="chain_io must be a RadiantChainIO"):
        RadiantCovenantLeg(
            network="bcrt", taker_pkh=_TAKER_PKH, maker_pkh=_MAKER_PKH, chain_io=object(), fee_source=FakeFeeSource()
        )
    with pytest.raises(ValidationError, match="fee_source must implement"):
        RadiantCovenantLeg(
            network="bcrt",
            taker_pkh=_TAKER_PKH,
            maker_pkh=_MAKER_PKH,
            chain_io=RadiantChainIO(FakeClient()),
            fee_source=object(),
        )


def test_leg_validates_min_confirmations():
    with pytest.raises(ValidationError, match="min_confirmations must be a non-negative int"):
        RadiantCovenantLeg(
            network="bcrt",
            taker_pkh=_TAKER_PKH,
            maker_pkh=_MAKER_PKH,
            chain_io=RadiantChainIO(FakeClient()),
            fee_source=FakeFeeSource(),
            min_confirmations=-1,
        )


async def test_build_covenant_rejects_non_terms():
    leg = _leg()
    with pytest.raises(ValidationError, match="terms must be a NegotiatedTerms"):
        await leg.expected_covenant_scriptpubkey(object())


async def test_nft_variant_builds_and_binds():
    """The NFT variant path: covenant SPK built from terms, dest-hash bound."""
    from pyrxd.gravity.htlc_covenant import build_htlc_covenant_nft

    cov = build_htlc_covenant_nft(
        genesis_txid=_REF_TXID,
        genesis_vout=0,
        nft_carrier_value=1000,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=6,
    )
    terms = NegotiatedTerms(
        hashlock=_H,
        btc_sats=100_000,
        radiant_amount=1000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(6, t.TimeUnit.BLOCKS),
        asset_variant="nft",
        genesis_ref=GlyphRef(txid=_REF_TXID, vout=0).to_bytes(),
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )
    leg = _leg()
    assert await leg.expected_covenant_scriptpubkey(terms) == cov.funded_spk


async def test_spk_fail_closed_on_wrong_maker_dest_hash():
    terms = _rxd_terms()
    object.__setattr__(terms, "maker_dest_hash", b"\x00" * 32)
    leg = _leg()
    with pytest.raises(ValidationError, match="maker_dest_hash"):
        await leg.expected_covenant_scriptpubkey(terms)


async def test_chain_io_broadcast_rejects_empty_and_surfaces_errors():
    io = RadiantChainIO(FakeClient())
    with pytest.raises(ValidationError, match="non-empty bytes"):
        await io.broadcast(b"")
    io_err = RadiantChainIO(FakeClient(broadcast_error="mempool conflict"))
    with pytest.raises(NetworkError, match="radiant broadcast failed"):
        await io_err.broadcast(b"\x02\x00rawtx")


async def test_chain_io_verbose_must_be_dict():
    class BadClient(FakeClient):
        async def get_transaction_verbose(self, txid):
            return ["not", "a", "dict"]

    io = RadiantChainIO(BadClient())
    with pytest.raises(NetworkError, match="did not return a dict"):
        await io.confirmations("ab" * 32)


async def test_ref_adapter_payload_hash_as_bytes():
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer({"ref_outpoint": f"{_REF_TXID}:0", "payload_hash": b"\x99" * 32}), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved.payload_hash == b"\x99" * 32


@pytest.mark.parametrize(
    "token",
    [
        {"ref_outpoint": "nothex:0"},  # malformed txid in outpoint -> placeholder
        {"ref_outpoint": f"{_REF_TXID}:notint"},  # malformed vout -> placeholder
        {"ref_txid": "shorttxid", "ref_vout": 0},  # malformed fallback txid -> placeholder
        {"ref_outpoint": f"{_REF_TXID}:0", "payload_hash": "nothex"},  # bad payload hex -> b""
        {"ref_outpoint": f"{_REF_TXID}:0", "payload_hash": 12345},  # non-str/bytes payload -> b""
    ],
)
async def test_ref_adapter_tolerates_malformed_indexer_fields(token):
    """A hostile/buggy indexer returning malformed fields must not crash the adapter;
    a bad genesis falls to a placeholder (gate rejects), a bad payload falls to b""."""
    ref = GlyphRef(txid=_REF_TXID, vout=0).to_bytes()
    io = RadiantChainIO(FakeClient(confirmations=10))
    adapter = RxinDexerRefAdapter(FakeIndexer(token), io)
    resolved = await adapter.resolve_ref(ref)
    assert resolved is not None  # does not crash
    if "payload_hash" in token:
        assert resolved.payload_hash == b""  # malformed payload -> empty (no binding)
