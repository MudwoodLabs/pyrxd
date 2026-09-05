"""Conformance tests for the concrete Radiant covenant leg (radiant_leg.py).

No real chain: the ElectrumX client + indexer are fakes that return what a real
regtest node/indexer would. These pin the leg contract the SwapCoordinator drives —
covenant SPK derivation bound to the terms' dest hashes, outpoint discovery by SPK
UTXO scan, conf-gated on-chain carrier value, the RXinDexer->ResolvedRef adapter
through the real verify_ref_authenticity gate, idempotent broadcast, the SeenStore,
and the audit gate. On-chain acceptance is the e2e regtest milestone (step 5).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy
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
from pyrxd.security.errors import InsufficientFundsError, NetworkError, ValidationError
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
        # t_btc DERIVES from the covenant's own CSV. Under the inverted relation (#482) the
        # Radiant leg the maker LOCKS must outlast the leg it CLAIMS, and `csv` IS that
        # Radiant timelock — so a fixed 72 is unconstructible the moment csv drops below it,
        # which is the default here (6).
        t_btc=t.Timelock(max(1, csv // 2), t.TimeUnit.BLOCKS),
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
        # t_btc DERIVES from the covenant's own CSV. Under the inverted relation (#482) the
        # Radiant leg the maker LOCKS must outlast the leg it CLAIMS, and `csv` IS that
        # Radiant timelock — so a fixed 72 is unconstructible the moment csv drops below it,
        # which is the default here (6).
        t_btc=t.Timelock(max(1, csv // 2), t.TimeUnit.BLOCKS),
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


async def test_covenant_outpoint_selects_the_earliest_confirmed_of_several():
    """Was `..._ambiguous_utxo_fail_closed`, asserting a refusal.

    That refusal was the attack one step earlier than the one it appeared to prevent: this is the
    path that WRITES the outpoint later spends pin to, so anyone paying the covenant address before
    it ran stopped the pin from ever being recorded, and every subsequent spend went back to
    re-discovering — and refusing. Selecting the earliest-confirmed match is deterministic for both
    parties and picks the honest funding, which necessarily precedes any poison.
    """
    terms = _rxd_terms(amount=100_000)
    dupes = [
        UtxoRecord(tx_hash="ce" * 32, tx_pos=1, value=100_000, height=101),  # later — the poison
        UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=100_000, height=100),  # earlier — the real one
    ]
    leg = _leg(client=FakeClient(utxos=dupes))
    assert await leg.covenant_outpoint(terms) == "cd" * 32 + ":0"


async def test_covenant_outpoint_prefers_a_CONFIRMED_output_over_a_mempool_one():
    """Height 0 means unconfirmed. A mempool output must never displace a mined one, or an attacker
    could steer the selection for free by broadcasting rather than paying."""
    terms = _rxd_terms(amount=100_000)
    dupes = [
        UtxoRecord(tx_hash="ff" * 32, tx_pos=0, value=100_000, height=0),  # unconfirmed
        UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=100_000, height=900),  # mined, but later-looking
    ]
    leg = _leg(client=FakeClient(utxos=dupes))
    assert await leg.covenant_outpoint(terms) == "cd" * 32 + ":0"


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
    terms = _rxd_terms(amount=100_000)  # csv=6
    # Mature: the covenant UTXO is buried >= t_rxd (6) deep, so the CSV refund is final.
    client = FakeClient(utxo_value=100_000, confirmations=6)
    leg = _leg(client=client)
    rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    txid = await leg.refund_asset(rec)
    assert txid == "ab" * 32
    assert len(client.broadcast_raw) == 1


async def test_refund_asset_rejects_premature_csv():
    """P3 maturity self-check: a CSV refund one block short of t_rxd maturity must fail closed with a
    clear "needs N, has M" message and NOT broadcast — the leg refuses a non-final refund rather than
    relying on node rejection under deadline pressure."""
    terms = _rxd_terms(amount=100_000)  # csv=6 → mature at confirmations >= 6
    client = FakeClient(utxo_value=100_000, confirmations=5)
    leg = _leg(client=client)
    rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with pytest.raises(NetworkError, match="not yet mature: needs 6 confirmations, has 5"):
        await leg.refund_asset(rec)
    assert client.broadcast_raw == [], "no non-final refund may be broadcast before CSV maturity"


async def test_claim_asset_not_gated_by_csv_maturity():
    """The CLAIM branch has no CSV — claim_asset must remain spendable at shallow depth (only the
    reorg min_confirmations gate applies), unaffected by the refund-side maturity check."""
    terms = _rxd_terms(amount=100_000)  # csv=6
    client = FakeClient(utxo_value=100_000, confirmations=1)  # far below csv, but >= min_confirmations
    leg = _leg(client=client, min_confirmations=1)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    txid = await leg.claim_asset(rec, _P)
    assert txid == "ab" * 32


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
        t_btc=t.Timelock(3, t.TimeUnit.BLOCKS),
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


# --------------------------------------------------------------------------- deadline-aware fee gate (A1)
#
# Radiant has neither RBF nor CPFP, so an under-fee'd claim/refund cannot be repaired
# after broadcast — it squats on its own inputs until mempool expiry (8h). The leg is
# the single choke point every time-critical covenant spend passes through, so the
# pre-broadcast affordability gate lives there. See pyrxd.gravity.fee_policy.


class SizedFeeSource:
    """A fee source dispensing an exact photon value, counting how often it is drawn."""

    def __init__(self, value: int) -> None:
        self.value = value
        self.calls = 0

    def next_fee_input(self) -> FeeInput:
        self.calls += 1
        k = PrivateKey(bytes.fromhex("33" * 32))
        pkh = bytes(Hex20(k.public_key().hash160()))
        return FeeInput(
            txid="ef" * 32, vout=0, value=self.value, scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac", wif=k.wif()
        )


def test_leg_rejects_a_non_policy_fee_policy():
    with pytest.raises(ValidationError, match="fee_policy must be a DeadlineFeePolicy"):
        RadiantCovenantLeg(
            network="bcrt",
            taker_pkh=_TAKER_PKH,
            maker_pkh=_MAKER_PKH,
            chain_io=RadiantChainIO(FakeClient()),
            fee_source=FakeFeeSource(),
            fee_policy=object(),  # type: ignore[arg-type]
        )


def test_leg_defaults_to_the_effective_min_relay_rate():
    assert _leg().fee_policy is DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    assert _leg().fee_policy.relay_fee_per_kb == 10_000_000  # 0.10 RXD/kB


async def test_claim_broadcasts_and_warns_when_the_fee_clears_the_floor_but_not_the_target(caplog):
    """REGRESSION TEST for a fund-loss bug: the urgency premium must NOT gate broadcast.

    Two independent security passes (a review and a ~2.17M-case red-team sweep) found
    the same bug in the first cut of this feature: the premium was enforced as a HARD
    pre-broadcast gate, so a fee the node WOULD have accepted and mined was refused.
    Refusing changes nothing about the fee paid — the whole fee input is the miner fee
    on a single-output covenant either way — so the claim simply never went out, the
    maker's CSV refund branch opened, and the asset was LOST. Worse, the premium RISES
    as the deadline closes, so the old gate refused hardest exactly when claiming
    mattered most.

    Here csv=6 with 5 confirmations leaves 1 block to the deadline: multiplier
    1 + 2*(6-1)/6 = 8/3, so a ~266-byte claim targets ~7.1M photons while the node's
    real floor is ~2.66M. 3,000,000 photons is ABOVE the floor and BELOW the target.
    It must BROADCAST, and warn.
    """
    terms = _rxd_terms(amount=100_000, csv=6)
    client = FakeClient(utxo_value=100_000, confirmations=5)
    src = SizedFeeSource(3_000_000)  # over the node's floor, under the urgency target
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with caplog.at_level("WARNING"):
        assert await leg.claim_asset(rec, _P) == "ab" * 32
    assert len(client.broadcast_raw) == 1, "a fee the node accepts must go on-chain, deadline or not"
    # The fee really is under the urgency target — otherwise this test proves nothing.
    sent = len(client.broadcast_raw[0])
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(sent) <= 3_000_000
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.required_fee(sent, blocks_to_deadline=1) > 3_000_000
    # ...and the operator is told to fund a larger pool — a WARNING, not a refusal.
    assert any(
        r.levelname == "WARNING"
        and "below the " in r.getMessage()
        and "urgency target" in r.getMessage()
        and "blocks_to_deadline=1" in r.getMessage()
        for r in caplog.records
    )
    assert not any("REFUSING to broadcast" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("blocks_left", [0, 1, 2])
async def test_a_fee_over_the_floor_broadcasts_at_every_urgency(blocks_left, caplog):
    """The same regression, swept across the closest deadlines — where the premium peaks.

    ``taker_claim_asset_from_vulnerable`` exists to race this window; a gate that
    refuses at 0/1/2 blocks left would disarm exactly the spend it is meant to protect.
    """
    csv = 6
    terms = _rxd_terms(amount=100_000, csv=csv)
    # confirmations = csv - blocks_left, so `blocks_left` blocks remain before refund.
    client = FakeClient(utxo_value=100_000, confirmations=csv - blocks_left)
    leg = _leg(client=client, fee_source=SizedFeeSource(3_000_000))
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with caplog.at_level("WARNING"):
        assert await leg.claim_asset(rec, _P) == "ab" * 32
    assert len(client.broadcast_raw) == 1
    sent = len(client.broadcast_raw[0])
    # Under the target at every one of these distances — so each case is a real regression.
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.required_fee(sent, blocks_to_deadline=blocks_left) > 3_000_000
    assert any(r.levelname == "WARNING" and "urgency target" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("blocks_left", [0, 1, 2])
async def test_claim_below_the_node_floor_is_still_refused(blocks_left):
    """The guard must not have been WEAKENED, only re-aimed at the node's real floor.

    Below ``min_relay_fee`` the spend is unrelayable, and with no RBF and no CPFP it
    cannot be repaired — it squats on its own inputs until mempool expiry. Refusing is
    strictly better than that, and unlike the premium case it costs nothing: the node
    would not have accepted this transaction anyway. Swept across the tightest deadlines
    to show the floor binds regardless of urgency, exactly as the premium no longer does.
    """
    csv = 6
    terms = _rxd_terms(amount=100_000, csv=csv)
    client = FakeClient(utxo_value=100_000, confirmations=csv - blocks_left)
    src = SizedFeeSource(1_000_000)  # under the ~2.66M floor for a ~266-byte claim
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with pytest.raises(InsufficientFundsError) as ei:
        await leg.claim_asset(rec, _P)
    assert ei.value.available == 1_000_000
    # The shortfall is reported against the HARD floor, not the urgency target: that is
    # the number an operator has to clear to get this spend relayed at all. The claim is
    # ~266 bytes; band the assertion over 200..400 bytes so it does not pin an exact
    # signature length, but keep it tight enough to EXCLUDE the premium numbers
    # (>= 5.3M at these distances), which is what the old buggy gate reported here.
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(200) <= ei.value.required
    assert ei.value.required <= DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(400)
    assert client.broadcast_raw == [], "nothing may go on-chain when the gate refuses"
    # The message must carry WHY this is fatal rather than merely slow — an operator
    # reading the page has to know there is no bump path.
    assert "no RBF" in str(ei.value) and "no CPFP" in str(ei.value)


async def test_the_leg_pages_when_the_builder_did_not_already_refuse(caplog):
    """The leg's own ERROR page, exercised directly.

    Sub-floor fees are caught twice: ``build_htlc_claim_tx`` runs a deadline-UNAWARE
    floor check on the assembled bytes (``htlc_spend._assert_fee_clears_relay_floor``)
    before the leg's ``_assert_affordable`` ever sees them, and since the correction both
    gates test the identical condition (``fee < min_relay_fee``) against the identical
    bytes. So on the normal claim path the builder always raises first and the leg's
    page is defence-in-depth. Drive it directly so the paging text stays covered and
    keeps naming the deadline.
    """
    terms = _rxd_terms(amount=100_000, csv=6)
    client = FakeClient(utxo_value=100_000, confirmations=5)
    leg = _leg(client=client, fee_source=SizedFeeSource(10_000_000))
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    await leg.claim_asset(rec, _P)  # build a real, correctly-sized claim to measure
    sent = client.broadcast_raw[0]

    class _Tx:
        def serialize(self):
            return sent

    poor = dataclasses.replace(leg.fee_source.next_fee_input(), value=1_000)
    with caplog.at_level("ERROR"):
        with pytest.raises(InsufficientFundsError):
            leg._assert_affordable(_Tx(), poor, blocks_to_deadline=1, kind="claim")
    assert any(
        r.levelname == "ERROR"
        and "REFUSING to broadcast" in r.getMessage()
        and "blocks_to_deadline=1" in r.getMessage()
        for r in caplog.records
    )


async def test_the_same_fee_is_accepted_far_from_the_deadline():
    """Identical fee input, identical transaction — only the deadline differs.

    This is what makes the gate deadline-AWARE rather than just a higher flat floor.
    """
    terms = _rxd_terms(amount=100_000, csv=100)  # deadline far outside the 6-block horizon
    client = FakeClient(utxo_value=100_000, confirmations=3)
    src = SizedFeeSource(3_000_000)
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    assert await leg.claim_asset(rec, _P) == "ab" * 32
    assert len(client.broadcast_raw) == 1


async def test_claim_past_the_deadline_targets_the_maximum_premium_but_still_broadcasts(caplog):
    """Past the deadline the TARGET is the maximum premium — but it is still only a target.

    confirmations >= csv: the maker's refund branch is already open, so
    ``blocks_to_deadline`` clamps to 0 (never negative) and the multiplier to 3.0. This
    is the worst case for the old hard gate: the largest premium, on the claim with the
    least time left, where a refusal is closest to a guaranteed loss. The node's floor
    is still ~2.66M, so 7,000,000 photons relays fine and MUST go out.
    """
    terms = _rxd_terms(amount=100_000, csv=6)
    client = FakeClient(utxo_value=100_000, confirmations=99)
    src = SizedFeeSource(7_000_000)  # over the ~2.66M floor, under 3.0x of it (~7.98M)
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with caplog.at_level("WARNING"):
        assert await leg.claim_asset(rec, _P) == "ab" * 32
    assert len(client.broadcast_raw) == 1
    sent = len(client.broadcast_raw[0])
    # The premium clamps at 3.0x and never exceeds it, however far past the deadline.
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.required_fee(
        sent, blocks_to_deadline=0
    ) == DEFAULT_RADIANT_DEADLINE_FEE_POLICY.required_fee(sent, blocks_to_deadline=-99)
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.required_fee(sent, blocks_to_deadline=0) > 7_000_000
    assert any(
        r.levelname == "WARNING" and "urgency target" in r.getMessage() and "blocks_to_deadline=0" in r.getMessage()
        for r in caplog.records
    )


async def test_refund_uses_the_flat_floor_with_no_urgency_premium():
    """A matured CSV refund has no closing window — it stays valid indefinitely — so it
    pays the relay floor and no premium. The floor itself still binds."""
    terms = _rxd_terms(amount=100_000, csv=6)
    client = FakeClient(utxo_value=100_000, confirmations=6)
    rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    # 3M photons > the ~2.33M flat floor for a ~233-byte refund => accepted, even though
    # the covenant is exactly at its CSV deadline (which would be 3x on the claim path).
    ok_leg = _leg(client=client, fee_source=SizedFeeSource(3_000_000))
    assert await ok_leg.refund_asset(rec) == "ab" * 32
    # ...but a sub-floor fee is still refused.
    bad_client = FakeClient(utxo_value=100_000, confirmations=6)
    bad_leg = _leg(client=bad_client, fee_source=SizedFeeSource(1_000_000))
    with pytest.raises(InsufficientFundsError, match="no deadline"):
        await bad_leg.refund_asset(rec)
    assert bad_client.broadcast_raw == []


async def test_an_injected_policy_overrides_the_default_rate():
    # The node's effective_minrelaytxfee is policy, not protocol: a leg pointed at a
    # node advertising 0.01 RXD/kB is sized for that node, with no code change.
    terms = _rxd_terms(amount=100_000, csv=6)
    client = FakeClient(utxo_value=100_000, confirmations=5)
    leg = RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        chain_io=RadiantChainIO(client),
        fee_source=SizedFeeSource(3_000_000),
        # 0.01 RXD/kB is the LEGACY rate, below the protocol bound (now the EFFECTIVE
        # rate), so pointing at a node that really relays this low is an explicit act.
        fee_policy=DeadlineFeePolicy(relay_fee_per_kb=1_000_000, allow_below_protocol_floor=True),
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    assert await leg.claim_asset(rec, _P) == "ab" * 32


async def test_the_gate_measures_the_transaction_it_is_about_to_send():
    # The requirement must track the ACTUAL broadcast bytes. Build at a comfortable fee,
    # read the size off the wire bytes the leg sent, and check the arithmetic closes.
    terms = _rxd_terms(amount=100_000, csv=100)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    leg = _leg(client=client, fee_source=SizedFeeSource(10_000_000))
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    await leg.claim_asset(rec, _P)
    sent = client.broadcast_raw[0]
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(len(sent)) <= 10_000_000


# ------- audit B3: a REFUSED build must not charge the fee pool's cap ------------------------


def _capped_pool(*values: int):
    """A real :class:`CappedFeeWalletSource` over a freshly generated pool key.

    One key owns every pool UTXO (that is what a pool wallet is), so only the outpoints
    differ. The key is generated, never hand-written.
    """
    from pyrxd.gravity.capped_fee_source import CappedFeeWalletSource

    key = PrivateKey(os.urandom(32))
    spk = b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"
    pool = [FeeInput(txid=os.urandom(32).hex(), vout=0, value=v, scriptpubkey=spk, wif=key.wif()) for v in values]
    return CappedFeeWalletSource(pool, total_cap_photons=20_000_000)


async def test_a_refused_claim_does_not_charge_the_fee_cap():
    """The leg dispenses BEFORE it builds, and the build refuses below the relay floor.

    Nothing is broadcast and no fee is paid, so the operator's cumulative cap must be
    untouched. Before the fix the refused input stayed charged: seven such refusals burned
    3,500,000 of a 20,000,000 cap and the covering 20,000,000 input became unreachable.
    """
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    src = _capped_pool(500_000, 20_000_000)  # 500,000 is below the ~2.67M floor for a claim
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")

    with pytest.raises(InsufficientFundsError):
        await leg.claim_asset(rec, _P)

    assert client.broadcast_raw == [], "nothing went on-chain, so nothing may be charged"
    assert src.dispensed_photons == 0, "a refused build must not consume the cap"
    assert src.remaining_inputs == 1, "dispense-once still holds: the refused input is retired"


async def test_seven_refused_ticks_do_not_strand_the_covering_input_end_to_end():
    """The audit's measured drain, driven through the real leg.

    Pool = 7 x 500,000 + 1 x 20,000,000, cap = 20,000,000, exactly as measured. Seven
    refusals then a claim: pre-fix the eighth call raised ``FeePoolExhaustedError`` and the
    asset was left to the counterparty's CSV refund with a funded pool still sitting there.
    """
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    src = _capped_pool(*([500_000] * 7), 20_000_000)
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")

    for _ in range(7):
        with pytest.raises(InsufficientFundsError):
            await leg.claim_asset(rec, _P)
    assert client.broadcast_raw == []

    txid = await leg.claim_asset(rec, _P)  # the covering input is still reachable
    assert txid == "ab" * 32
    assert len(client.broadcast_raw) == 1
    assert src.dispensed_photons == 20_000_000  # only the input actually spent is charged


async def test_a_refused_refund_does_not_charge_the_fee_cap():
    """Same guarantee on the refund path (the maker's CSV escape hatch)."""
    terms = _rxd_terms(amount=100_000)  # csv=6
    client = FakeClient(utxo_value=100_000, confirmations=6)  # mature
    src = _capped_pool(500_000, 20_000_000)
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")

    with pytest.raises(InsufficientFundsError):
        await leg.refund_asset(rec)

    assert client.broadcast_raw == []
    assert src.dispensed_photons == 0


async def test_a_fee_source_without_release_unspent_still_works():
    """The release is duck-typed and OPTIONAL: a plain FeeUtxoSource must keep working."""
    terms = _rxd_terms(amount=100_000)
    client = FakeClient(utxo_value=100_000, confirmations=3)
    src = SizedFeeSource(1_000_000)  # no release_unspent
    leg = _leg(client=client, fee_source=src)
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
    with pytest.raises(InsufficientFundsError):
        await leg.claim_asset(rec, _P)
    assert client.broadcast_raw == []


class TestASecondPaymentToTheCovenantCannotBlockTheSpend:
    """The covenant scriptPubKey is a pure function of PUBLIC negotiated terms, so anyone can
    construct it and anyone can pay it.

    That made a discovery-time refusal into an attack: after revealing `p`, a maker sends a second
    ordinary output of exactly `radiant_amount` to the same address, `find_covenant_utxo` refuses
    with "ambiguous covenant UTXO set", and the taker's claim fails on every retry until `t_rxd`
    expires — while the autonomous executor classifies the refusal as a transient read fault and
    keeps retrying, looking healthy. The maker then CSV-refunds both outputs.

    Once the funded outpoint is known there is nothing to discover, so the spend pins to it.
    """

    @staticmethod
    def _two_utxos(value: int):
        return [
            UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=value, height=100),  # the real one
            UtxoRecord(tx_hash="99" * 32, tx_pos=0, value=value, height=140),  # the poison
        ]

    @pytest.mark.asyncio
    async def test_a_pinned_outpoint_is_selected_out_of_a_poisoned_set(self) -> None:
        client = FakeClient()
        client._utxos = self._two_utxos(100_000)
        io = RadiantChainIO(client)
        outpoint, value, _h = await io.find_covenant_utxo(
            b"\x00" * 25, expected_value=100_000, pin_outpoint="ab" * 32 + ":1"
        )
        assert outpoint == "ab" * 32 + ":1", "the poison output was selected, or the spend refused"
        assert value == 100_000

    @pytest.mark.asyncio
    async def test_WITHOUT_a_pin_the_EARLIEST_CONFIRMED_match_is_selected(self) -> None:
        """The discovery path must SELECT, not refuse — and this test previously asserted the
        opposite, on the reasoning that "nothing has been committed yet, so there is nothing for a
        refusal to deny". That was wrong: the pin's only WRITER comes through this path, so
        poisoning the address before the outpoint is recorded stopped the pin from ever being
        written, and every later spend ran unpinned. The refusal WAS the attack, one step earlier.

        The honest funding necessarily precedes any poison, so earliest-confirmed picks it — and it
        is deterministic across both parties, which "first returned" would not be.
        """
        client = FakeClient()
        client._utxos = self._two_utxos(100_000)
        io = RadiantChainIO(client)
        outpoint, value, height = await io.find_covenant_utxo(b"\x00" * 25, expected_value=100_000)
        assert outpoint == "ab" * 32 + ":1", "the later (poison) output was selected"
        assert value == 100_000 and height == 100

    @pytest.mark.asyncio
    async def test_a_pin_that_is_NOT_in_the_live_set_is_refused(self) -> None:
        """Pinning must not become a way to spend something that is gone: a recorded outpoint that
        has been spent or reorged out must fail closed, not fall back to whatever else is there."""
        client = FakeClient()
        client._utxos = self._two_utxos(100_000)
        io = RadiantChainIO(client)
        with pytest.raises(NetworkError, match="not in this scriptPubKey"):
            await io.find_covenant_utxo(b"\x00" * 25, expected_value=100_000, pin_outpoint="ee" * 32 + ":0")

    @pytest.mark.asyncio
    async def test_a_pinned_outpoint_still_has_to_match_the_expected_value(self) -> None:
        """The value filter runs BEFORE the pin, so a record pointing at a wrong-value output at
        the right address is still refused — the pin narrows, it does not waive."""
        client = FakeClient()
        client._utxos = [UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=42, height=100)]
        io = RadiantChainIO(client)
        with pytest.raises(NetworkError, match="expected carrier value"):
            await io.find_covenant_utxo(b"\x00" * 25, expected_value=100_000, pin_outpoint="ab" * 32 + ":1")


@pytest.mark.asyncio
async def test_the_SPEND_PATH_pins_the_recorded_outpoint_against_a_poisoned_set():
    """The production entry point for the pin.

    Selecting the right UTXO is useless if `_resolve_covenant` never passes the recorded outpoint
    down — the poisoning attack works through the SPEND path (`claim_asset` / `refund_asset`), not
    through a direct call to the scanner. This drives the real leg with a record that carries the
    outpoint and a UTXO set containing a second, identically-valued payment to the same address.
    """
    from pyrxd.gravity.swap_state import SwapRecord, SwapState

    terms = _rxd_terms(amount=100_000)
    real = UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=100_000, height=100)
    poison = UtxoRecord(tx_hash="99" * 32, tx_pos=0, value=100_000, height=140)
    leg = _leg(client=FakeClient(utxos=[real, poison]))
    record = SwapRecord(state=SwapState.BOTH_LOCKED, terms=terms).with_radiant_lock("ab" * 32 + ":1", "00" * 25)

    cov, outpoint, carrier, _confs = await leg._resolve_covenant(record)
    assert outpoint == "ab" * 32 + ":1", (
        "the spend path re-discovered by scan instead of using the recorded outpoint, so a second "
        "payment to the covenant address blocks it"
    )
    assert carrier == 100_000
    assert cov is not None


class TestAnUnreadableConfirmationDepthFailsClosed:
    """This guard replaced a bare `int(info.get("confirmations", 0) or 0)` after a real bug: a
    string coerced silently into a depth, and a JSON `Infinity` raised `OverflowError` — not a
    `NetworkError`, so it escaped every `except NetworkError` on a value-moving path as a bare
    traceback. It had no test until now, which is how the fail-closed direction could regress
    unnoticed.
    """

    @staticmethod
    def _io(raw):
        # Subclass the real fake so the client satisfies RadiantChainIO's full interface; only the
        # one method under test is overridden.
        class _C(FakeClient):
            async def get_transaction_verbose(self, _txid):
                return {"confirmations": raw}

        return RadiantChainIO(_C())

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "raw"),
        [
            ("JSON Infinity", float("inf")),
            ("negative infinity", float("-inf")),
            ("NaN", float("nan")),
            ("a non-numeric string", "deep"),
            ("a dict", {"depth": 3}),
        ],
    )
    async def test_an_unreadable_depth_raises_NetworkError(self, label: str, raw) -> None:
        """NetworkError specifically — the callers on the value-moving path catch that and nothing
        else, so any other exception type escapes as an unhandled traceback."""
        with pytest.raises(NetworkError, match="unreadable confirmation depth"):
            await self._io(raw).confirmations("ab" * 32)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("label", "raw", "want"), [("absent", None, 0), ("negative", -5, 0), ("zero", 0, 0)])
    async def test_a_falsy_or_negative_depth_reads_as_ZERO_not_as_deep(self, label: str, raw, want: int) -> None:
        """Fail-closed direction: unknown or nonsensical depth must read as UNCONFIRMED, never as
        buried. Reading it as deep is what lets a spend proceed against a covenant a reorg can
        still remove."""
        assert await self._io(raw).confirmations("ab" * 32) == want

    @pytest.mark.asyncio
    async def test_an_HONEST_depth_still_passes_through(self) -> None:
        """A guard that refuses valid work is a bug — an ordinary integer depth must survive."""
        assert await self._io(7).confirmations("ab" * 32) == 7

    @pytest.mark.asyncio
    async def test_a_NUMERIC_STRING_does_not_silently_coerce(self) -> None:
        """The original bug: `"999999"` became a depth of 999999 and a shallow covenant read as
        buried. Whether it is refused or read as 0, it must NOT come back as a large depth."""
        try:
            got = await self._io("999999").confirmations("ab" * 32)
        except NetworkError:
            return  # refused outright — also correct
        assert got == 0, f"a string depth coerced to {got}; a shallow covenant would read as buried"


def _nft_terms(carrier: int = 1000, csv: int = 6) -> NegotiatedTerms:
    """NFT terms. Note `radiant_amount == nft_carrier_value` here is CORRECT, not a fixture
    shortcut: for the NFT variant the field genuinely IS the carrier dust value, and identity is
    bound separately by the genesis ref welded into the scriptPubKey."""
    from pyrxd.gravity.htlc_covenant import build_htlc_covenant_nft

    cov = build_htlc_covenant_nft(
        genesis_txid=_REF_TXID,
        genesis_vout=0,
        nft_carrier_value=carrier,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=csv,
    )
    return NegotiatedTerms(
        hashlock=_H,
        btc_sats=100_000,
        radiant_amount=carrier,
        # t_btc DERIVES from the covenant's own CSV. Under the inverted relation (#482) the
        # Radiant leg the maker LOCKS must outlast the leg it CLAIMS, and `csv` IS that
        # Radiant timelock — so a fixed 72 is unconstructible the moment csv drops below it,
        # which is the default here (6).
        t_btc=t.Timelock(max(1, csv // 2), t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(csv, t.TimeUnit.BLOCKS),
        asset_variant="nft",
        genesis_ref=GlyphRef(txid=_REF_TXID, vout=0).to_bytes(),
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


class TestTheFundingGateIsExercisedPerAssetVariant:
    """`verify_maker_asset_funded` is the HZ-1 gate: the taker MUST NOT fund the counter leg until
    this confirms the maker's asset is really locked, at the agreed value, buried deep enough.

    It had NO per-variant coverage. Its only real-leg exercise hardcoded the RXD covenant, and the
    coordinator tests use a duck-typed fake that records the call without running it. That is how
    #505 — the FT gate comparing a carrier photon value against a token count — survived: no test
    ever drove this method with an FT.
    """

    @pytest.mark.asyncio
    async def test_rxd_accepts_a_correctly_funded_covenant(self) -> None:
        terms = _rxd_terms(amount=100_000)
        leg = _leg(client=FakeClient(utxo_value=100_000, confirmations=6))
        outpoint, value, confs = await leg.verify_maker_asset_funded(terms, min_confirmations=3)
        assert value == 100_000 and confs == 6 and outpoint

    @pytest.mark.asyncio
    async def test_rxd_refuses_a_wrongly_valued_covenant(self) -> None:
        terms = _rxd_terms(amount=100_000)
        leg = _leg(client=FakeClient(utxo_value=99_999, confirmations=6))
        with pytest.raises(NetworkError, match="expected carrier value"):
            await leg.verify_maker_asset_funded(terms, min_confirmations=3)

    @pytest.mark.asyncio
    async def test_rxd_refuses_a_covenant_that_is_too_shallow(self) -> None:
        """The depth half of the gate — a covenant a reorg can still remove must not clear it."""
        terms = _rxd_terms(amount=100_000)
        leg = _leg(client=FakeClient(utxo_value=100_000, confirmations=1))
        with pytest.raises(NetworkError):
            await leg.verify_maker_asset_funded(terms, min_confirmations=6)

    @pytest.mark.asyncio
    async def test_nft_accepts_a_covenant_funded_at_the_CARRIER_value(self) -> None:
        """For NFT, `radiant_amount` genuinely IS the carrier dust value, so comparing it against
        the UTXO's photon value is correct. Asserting that here is what makes the FT case below a
        real contrast rather than an untested assumption."""
        terms = _nft_terms(carrier=1000)
        leg = _leg(client=FakeClient(utxo_value=1000, confirmations=6))
        _outpoint, value, _confs = await leg.verify_maker_asset_funded(terms, min_confirmations=3)
        assert value == 1000

    @pytest.mark.asyncio
    async def test_ft_refuses_a_covenant_funded_BELOW_the_token_amount(self) -> None:
        """The scenario #505 called a defect, corrected against the chain.

        #505 asserted that 1000 tokens on 546 photons of dust is an honest funding the gate
        wrongly refuses. On Radiant that output cannot exist: an FT's quantity IS its output value,
        1 photon = 1 token unit (``docs/concepts/radiant-fts-are-on-chain.md``;
        ``OP_REFVALUESUM_OUTPUTS`` sums ref-bearing outputs' native nValue; ``FtUtxo`` raises on
        ``value != ft_amount`` because such a UTXO cannot exist on chain).

        So 546 photons IS 546 tokens — a covenant funded 454 short of the negotiated 1000, and
        refusing it is the gate working. This test replaces a strict xfail that encoded the
        colored-coin model Radiant does not use.
        """
        terms = _ft_terms(amount=1000)
        leg = _leg(client=FakeClient(utxo_value=546, confirmations=6))
        with pytest.raises((NetworkError, ValidationError)):
            await leg.verify_maker_asset_funded(terms, min_confirmations=3)

    @pytest.mark.asyncio
    async def test_ft_ACCEPTS_a_covenant_funded_with_the_token_amount(self) -> None:
        """The honest path, which works and always did: 1000 tokens funded as 1000 photons."""
        terms = _ft_terms(amount=1000)
        leg = _leg(client=FakeClient(utxo_value=1000, confirmations=6))
        _outpoint, value, _confs = await leg.verify_maker_asset_funded(terms, min_confirmations=3)
        assert value == 1000


class TestTheRefundPathIsReachedThroughTheLegPerAssetVariant:
    """`refund_asset` — the LEG, not the builder — is exercised for `rxd` only.

    #510 item 3 named two functions with no FT/NFT coverage anywhere: `build_htlc_refund_tx` and
    `radiant_leg.refund_asset`. The first was covered at the builder level in
    `tests/test_htlc_refund_ft_nft_coverage.py`, deliberately so. This is the second — the
    production entry point every caller (`mutual_refund`, `maybe_refund_asset_on_maker_stall`,
    the watchtower's refund page) actually reaches, and the path that recovers a stalled maker's
    asset.

    Between the caller and the builder sits `_resolve_covenant`, which rebuilds the covenant from
    `terms` per variant and pins the on-chain value against `terms.radiant_amount`; a variant
    that never runs through it has never had its recovery path executed, only its bytes checked.

    Both halves per variant, because the leg-level gate is the P3 CSV maturity self-check and a
    refusal test on its own cannot distinguish "refuses a premature refund" from "refuses this
    variant". The mature case proves each variant can still be recovered.
    """

    @staticmethod
    def _terms_and_carrier(variant: str):
        """Terms plus the photon value the covenant is funded with, csv 6 in every case.

        An FT's quantity IS its output value on Radiant (1 photon = 1 token unit), so 1000 tokens
        funds as 1000 photons; the NFT's is carrier dust. They differ from the RXD leg's 100_000
        deliberately — a shared value would hide a variant reading the wrong one.
        """
        if variant == "rxd":
            return _rxd_terms(amount=100_000), 100_000
        if variant == "ft":
            return _ft_terms(amount=1000), 1000
        return _nft_terms(carrier=1000), 1000

    @pytest.mark.parametrize("variant", ["rxd", "ft", "nft"])
    @pytest.mark.asyncio
    async def test_a_mature_covenant_is_refunded(self, variant: str) -> None:
        terms, carrier = self._terms_and_carrier(variant)
        # csv is 6, so 6 confirmations is exactly maturity.
        client = FakeClient(utxo_value=carrier, confirmations=6)
        leg = _leg(client=client)
        rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
        assert await leg.refund_asset(rec) == "ab" * 32
        assert len(client.broadcast_raw) == 1

    @pytest.mark.parametrize("variant", ["rxd", "ft", "nft"])
    @pytest.mark.asyncio
    async def test_a_premature_covenant_is_refused_and_nothing_is_broadcast(self, variant: str) -> None:
        terms, carrier = self._terms_and_carrier(variant)
        client = FakeClient(utxo_value=carrier, confirmations=5)  # one short of csv 6
        leg = _leg(client=client)
        rec = SwapRecord(state=SwapState.MAKER_STALLS, terms=terms, radiant_covenant_outpoint="cd" * 32 + ":0")
        with pytest.raises(NetworkError, match="not yet mature: needs 6 confirmations, has 5"):
            await leg.refund_asset(rec)
        assert client.broadcast_raw == [], "no non-final refund may be broadcast before CSV maturity"


class TestAnEvictedClaimCanBeRebroadcast:
    """A claim only beats the CSV refund by BEING in the mempool when maturity arrives — a
    non-BIP68-final refund is rejected from the mempool, so the maker cannot pre-broadcast. Radiant
    has no RBF and no CPFP and expires the mempool after about eight hours, so an evicted claim
    cannot be bumped back in; re-broadcasting is the only way.

    The coordinator broadcast and advanced straight to a completed state, so an eviction was
    invisible: the refund became valid at maturity, confirmed, and took both legs while the record
    said the swap had finished.
    """

    @staticmethod
    def _leg_with(unspent):
        class _C(FakeClient):
            async def get_utxos(self, script_hash):
                return [UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=100_000, height=100)]

            # The chain-io wrapper reads `txout_unspent_incl_mempool` off the CLIENT — overriding
            # the wrapper's own method name would stub the layer under test instead of feeding it.
            async def txout_unspent_incl_mempool(self, _txid, _vout):
                return unspent

        return _leg(client=_C(confirmations=10))

    def _record(self):
        from pyrxd.gravity.swap_state import SwapRecord, SwapState

        return SwapRecord(state=SwapState.SECRET_REVEALED, terms=_rxd_terms(amount=100_000)).with_radiant_lock(
            "ab" * 32 + ":1", "00" * 25
        )

    @pytest.mark.asyncio
    async def test_an_unspent_covenant_means_EVICTED_and_triggers_a_rebroadcast(self) -> None:
        leg = self._leg_with(True)
        sent: list = []

        async def _claim(record, preimage):
            sent.append(bytes(preimage))
            return "re" * 32

        leg.claim_asset = _claim
        assert await leg.rebroadcast_claim_if_evicted(self._record(), b"\x11" * 32) == "re" * 32
        assert sent == [b"\x11" * 32], "the claim was not re-broadcast despite the covenant being unspent"

    @pytest.mark.asyncio
    async def test_a_SPENT_covenant_does_nothing(self) -> None:
        """The claim is alive — in the mempool or mined. Re-broadcasting would be a pointless
        duplicate, and on a chain with no RBF a duplicate is its own risk."""
        leg = self._leg_with(False)
        sent: list = []
        leg.claim_asset = lambda *a, **k: sent.append(1)
        assert await leg.rebroadcast_claim_if_evicted(self._record(), b"\x11" * 32) is None
        assert sent == []

    @pytest.mark.asyncio
    async def test_an_ABSTAIN_does_NOT_rebroadcast(self) -> None:
        """An unknown answer is not an eviction. Treating None as "gone" would fire a duplicate
        broadcast every time a source was merely unreachable."""
        leg = self._leg_with(None)
        sent: list = []
        leg.claim_asset = lambda *a, **k: sent.append(1)
        assert await leg.rebroadcast_claim_if_evicted(self._record(), b"\x11" * 32) is None
        assert sent == []
