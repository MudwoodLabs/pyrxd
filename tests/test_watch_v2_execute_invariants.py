"""Assurance for the v2 autonomous BTC-refund path (``gravity.watch.executor`` + the ``decide()``
maturity gate + the reconciler seam). Pure/property/fuzz — NO node required; this is the cheapest
assurance for the headline safety properties (dormant-by-construction, capped, keyless, fail-closed).

The two hardening gaps the divergent panel surfaced are pinned here: SECONDS-unit ``t_btc`` is never
auto-acted, and the gate keys on the TYPED ``autonomous_btc_refund`` discriminator (an ETH swap that
emits the same ``taker_refund_btc`` display string must NOT arm the BTC executor).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import coincurve
import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import (
    Decision,
    ExecOutcome,
    Intent,
    Observations,
    PresignedRefund,
    Reconciler,
    RefundExecutor,
    decide,
    load_presigned_refund,
    make_refund_broadcaster,
)
from pyrxd.gravity.watch.executor import MAINNET_DUST_CEILING_SATS
from pyrxd.security.errors import ValidationError
from tests.test_watch_quorum import _policy

_H = hashlib.sha256(b"v2-refund").digest()
_REFUND_SPK = b"\x51\x20" + b"\x33" * 32  # the operator's pinned refund destination (P2TR-shaped)
_OTHER_SPK = b"\x51\x20" + b"\x44" * 32
_FUND_TXID = "ab" * 32
_COV = "cd" * 32 + ":0"


def _xonly(sk: coincurve.PrivateKey) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(sk.secret).format()


def _terms(*, btc_sats: int = 5_000, t_btc: t.Timelock | None = None) -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=_H,
        btc_sats=btc_sats,
        radiant_amount=1_000,
        t_btc=t_btc or t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x02" * 32,
        btc_refund_pubkey_xonly=b"\x03" * 32,
    )


def _swap(
    *,
    network: str = "bcrt",
    btc_sats: int = 5_000,
    t_btc_blocks: int = 144,
    fee_sats: int = 500,
    refund_spk: bytes = _REFUND_SPK,
    funding_txid: str = _FUND_TXID,
    funding_vout: int = 0,
    state: SwapState = SwapState.BTC_LOCKED,
) -> tuple[SwapRecord, PresignedRefund]:
    """Build a consistent (record, pre-signed refund blob) pair via the REAL builders, so the executor
    binds against a genuine refund tx (not a fixture stub)."""
    taker_sk = coincurve.PrivateKey(os.urandom(32))
    maker_sk = coincurve.PrivateKey(os.urandom(32))
    timeout = t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS)
    htlc = t.build_htlc(
        hashlock=_H,
        claim_pubkey_xonly=_xonly(maker_sk),
        refund_pubkey_xonly=_xonly(taker_sk),
        timeout=timeout,
        network=network,
    )
    loc = htlc.with_funding(t.BtcOutpoint(funding_txid, funding_vout), btc_sats)
    raw = t.build_refund_tx(
        locator=loc,
        refund_privkey=taker_sk.secret,
        timeout=timeout,
        to_scriptpubkey=refund_spk,
        fee_sats=fee_sats,
        aux_rand=os.urandom(32),
    )
    rec = SwapRecord(
        state=state,
        terms=_terms(btc_sats=btc_sats, t_btc=timeout),
        counterchain_locator=loc,
        radiant_covenant_outpoint=_COV,
    )
    return rec, PresignedRefund(raw_tx=raw, swap_id="swap1")


def _write(d: Path, blob: PresignedRefund) -> None:
    (d / f"{blob.swap_id}.refund.json").write_text(json.dumps(blob.to_dict()))


class _FakeBroadcaster:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        self.calls.append(bytes(raw_tx))
        return t.btc_txid_from_raw(raw_tx)


class _RaisingBroadcaster:
    async def broadcast(self, raw_tx: bytes) -> str:
        raise RuntimeError("node down")


def _armed(blobs_dir: Path, broadcaster, *, network="bcrt", cap=10_000, refund_spk=_REFUND_SPK, single=False):
    return RefundExecutor(
        broadcaster=broadcaster,
        blobs_dir=blobs_dir,
        network=network,
        cap_sats=cap,
        refund_spk=refund_spk,
        accept_single_source=single,
    )


def _refund_decision(*, low_corroboration=False) -> Decision:
    return Decision(
        Intent.PAGE_REFUND,
        reason="matured BTC refund due",
        recommended_action="taker_refund_btc",
        autonomous_btc_refund=True,
        low_corroboration=low_corroboration,
    )


# ───────────────────────────────────────── PresignedRefund + load ──


def test_presigned_refund_derives_fields_from_raw_tx():
    rec, blob = _swap()
    loc = rec.btc_locator
    assert blob.funding_prevout == loc.funding_outpoint.prevout_bytes()
    assert blob.input_nsequence == rec.terms.t_btc.to_nsequence()
    assert blob.output_spk == _REFUND_SPK
    assert blob.output_value_sats == loc.amount_sats - 500
    assert blob.txid == t.btc_txid_from_raw(blob.raw_tx)
    assert PresignedRefund.from_dict(blob.to_dict()).raw_tx == blob.raw_tx  # round-trip, no key/p stored


def test_presigned_refund_rejects_non_tx_bytes():
    with pytest.raises(ValidationError):
        PresignedRefund(raw_tx=b"\x00\x01\x02", swap_id="s")
    with pytest.raises(ValidationError):
        PresignedRefund(raw_tx=b"", swap_id="s")


def test_load_misfiled_blob_is_rejected(tmp_path):
    _, blob = _swap()
    (tmp_path / "wrongname.refund.json").write_text(json.dumps(blob.to_dict()))
    with pytest.raises(ValidationError):  # blob.swap_id 'swap1' != filename 'wrongname'
        load_presigned_refund(tmp_path, "wrongname")


def test_load_absent_blob_is_none(tmp_path):
    assert load_presigned_refund(tmp_path, "nope") is None


# ───────────────────────────────────── structural dormancy gate ──


@given(network=st.text(min_size=1, max_size=12))
def test_refund_broadcaster_live_over_whole_network_domain(network):
    # 0.9.0: the audit gate no longer blocks — make_refund_broadcaster returns the
    # injected live broadcaster for any network (the dust cap is enforced elsewhere
    # at construction, not by this seam).
    sink = _FakeBroadcaster()
    assert make_refund_broadcaster(network, audit_cleared=False, broadcaster=sink) is sink
    assert make_refund_broadcaster(network, audit_cleared=True, broadcaster=sink) is sink


def test_mainnet_broadcaster_is_live_without_optin():
    # 0.9.0: no longer dormant by construction — the audit gate is non-blocking.
    sink = _FakeBroadcaster()
    assert make_refund_broadcaster("bc", audit_cleared=False, broadcaster=sink) is sink


def test_mainnet_cap_is_dust_bound_at_construction():
    # On a value-bearing network a live broadcaster CANNOT be armed above the dust ceiling.
    with pytest.raises(ValidationError):
        _armed(Path("."), _FakeBroadcaster(), network="bc", cap=MAINNET_DUST_CEILING_SATS + 1)
    # at/below the ceiling is allowed (the deliberate dust clearance)
    _armed(Path("."), _FakeBroadcaster(), network="bc", cap=MAINNET_DUST_CEILING_SATS)
    # a cleared TEST chain has no dust ceiling (no real value)
    _armed(Path("."), _FakeBroadcaster(), network="bcrt", cap=10_000_000)


def test_dust_ceiling_tracks_funding_reader():
    # One definition of "dust" — kept in lockstep with the funding reader's single-source cap.
    assert MAINNET_DUST_CEILING_SATS == 10_000


def test_construction_guards():
    with pytest.raises(ValidationError):
        _armed(Path("."), _FakeBroadcaster(), cap=0)  # 'no cap' can never mean unlimited
    with pytest.raises(ValidationError):
        RefundExecutor(broadcaster=_FakeBroadcaster(), blobs_dir=".", network="bcrt", cap_sats=10_000, refund_spk=b"")


# ─────────────────────────────────────── executor: happy path ──


async def test_executor_broadcasts_when_all_binds_hold(tmp_path):
    rec, blob = _swap(network="bcrt", btc_sats=5_000, fee_sats=500)
    _write(tmp_path, blob)
    b = _FakeBroadcaster()
    out = await _armed(tmp_path, b).execute("swap1", rec, _refund_decision())
    assert out is ExecOutcome.BROADCAST
    assert b.calls == [blob.raw_tx]  # the EXACT pre-signed bytes, re-sent verbatim


async def test_executor_mainnet_dust_clearance_broadcasts(tmp_path):
    # A deliberate mainnet dust run: explicit opt-in, dust-bound cap, single-source accepted.
    rec, blob = _swap(network="bc", btc_sats=3_000, fee_sats=300)
    _write(tmp_path, blob)
    b = make_refund_broadcaster("bc", audit_cleared=True, broadcaster=_FakeBroadcaster())
    ex = RefundExecutor(
        broadcaster=b,
        blobs_dir=tmp_path,
        network="bc",
        cap_sats=5_000,
        refund_spk=_REFUND_SPK,
        accept_single_source=True,
    )
    out = await ex.execute("swap1", rec, _refund_decision(low_corroboration=True))
    assert out is ExecOutcome.BROADCAST


# ─────────────────────────────── executor: every decline path ──


_UNSET = object()


async def _declines(tmp_path, *, decision=None, write=True, **ex_kw):
    rec, blob = _swap(network="bcrt")
    if write:
        _write(tmp_path, blob)
    b = ex_kw.pop("broadcaster", _UNSET)
    if b is _UNSET:
        b = _FakeBroadcaster()  # default armed; pass broadcaster=None explicitly to test dormancy
    ex = _armed(tmp_path, b, **ex_kw)
    out = await ex.execute("swap1", rec, decision or _refund_decision())
    return out, b, rec, blob


async def test_decline_dormant_network(tmp_path):
    out, *_ = await _declines(tmp_path, broadcaster=None)  # None == dormant
    assert out is ExecOutcome.DECLINED


async def test_decline_low_corroboration_without_dust_clearance(tmp_path):
    out, b, *_ = await _declines(tmp_path, decision=_refund_decision(low_corroboration=True))
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_network_mismatch(tmp_path):
    out, b, *_ = await _declines(tmp_path, network="signet")  # record locator is 'bcrt'
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_missing_blob(tmp_path):
    out, b, *_ = await _declines(tmp_path, write=False)
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_output_spk_mismatch(tmp_path):
    out, b, *_ = await _declines(tmp_path, refund_spk=_OTHER_SPK)  # not the blob's pinned destination
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_over_cap(tmp_path):
    out, b, *_ = await _declines(tmp_path, cap=1_000)  # output 4_500 > cap
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_funding_outpoint_mismatch(tmp_path):
    # blob spends "ab"*32:0 but the record's locator is a DIFFERENT outpoint
    _, blob = _swap(network="bcrt", funding_txid="ab" * 32)
    rec, _ = _swap(network="bcrt", funding_txid="ef" * 32)
    _write(tmp_path, blob)
    b = _FakeBroadcaster()
    out = await _armed(tmp_path, b).execute("swap1", rec, _refund_decision())
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_decline_nsequence_mismatch(tmp_path):
    # blob signed for t_btc=144 but the record negotiated t_btc=200 → wrong CSV
    _, blob = _swap(network="bcrt", t_btc_blocks=144)
    rec, _ = _swap(network="bcrt", t_btc_blocks=200)
    _write(tmp_path, blob)
    b = _FakeBroadcaster()
    out = await _armed(tmp_path, b).execute("swap1", rec, _refund_decision())
    assert out is ExecOutcome.DECLINED and b.calls == []


async def test_eth_string_does_not_arm_btc_executor(tmp_path):
    # The ETH branch emits recommended_action="taker_refund_btc" but autonomous_btc_refund=False.
    # The executor keys on the TYPED discriminator → silent no-op, NOT a broadcast.
    rec, blob = _swap(network="bcrt")
    _write(tmp_path, blob)
    b = _FakeBroadcaster()
    d = Decision(Intent.PAGE_REFUND, reason="eth", recommended_action="taker_refund_btc", autonomous_btc_refund=False)
    out = await _armed(tmp_path, b).execute("swap1", rec, d)
    assert out is None and b.calls == []


# ───────────────────────── refund-first-only (no autonomous claim) ──


@pytest.mark.parametrize("intent", list(Intent))
async def test_refund_first_only_no_autonomous_claim(tmp_path, intent):
    # For EVERY non-PAGE_REFUND intent, autonomous_btc_refund is structurally False (Decision invariant),
    # so the executor is a no-op. Only PAGE_REFUND can carry the discriminator → claim can never auto-fire.
    d = Decision(intent, reason="x", autonomous_btc_refund=(intent is Intent.PAGE_REFUND))
    rec, blob = _swap(network="bcrt")
    _write(tmp_path, blob)
    b = _FakeBroadcaster()
    out = await _armed(tmp_path, b).execute("swap1", rec, d)
    if intent is Intent.PAGE_REFUND:
        assert out is ExecOutcome.BROADCAST
    else:
        assert out is None and b.calls == []


def test_autonomous_flag_only_valid_on_page_refund():
    with pytest.raises(ValidationError):
        Decision(Intent.PAGE_CLAIM, reason="x", autonomous_btc_refund=True)


# ─────────────────────────── decide(): maturity + seconds gates ──


def _obs(**kw):
    base = dict(maker_has_claimed_btc=False, now_rxd_height=500)
    base.update(kw)
    return Observations(**base)


def _btc_rec(state=SwapState.BTC_LOCKED, *, t_btc=None):
    return SwapRecord(
        state=state,
        terms=_terms(t_btc=t_btc),
        counterchain_locator=None,
        radiant_covenant_outpoint=None,
    )


def _decide(rec, obs):
    return decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=6)


def test_btc_locked_refunds_only_when_funding_matured():
    rec = _btc_rec()  # t_btc = 144 blocks
    assert _decide(rec, _obs(btc_funding_confirmations=None)).intent is Intent.WATCH
    assert _decide(rec, _obs(btc_funding_confirmations=100)).intent is Intent.WATCH
    d = _decide(rec, _obs(btc_funding_confirmations=144))
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc" and d.autonomous_btc_refund is True


def test_btc_locked_never_refunds_when_asset_is_locked():
    rec = _btc_rec()
    d = _decide(rec, _obs(btc_funding_confirmations=999, asset_locked_at_height=100))
    assert d.intent is Intent.WATCH  # maker DID lock → not refunding even though funding matured


def test_seconds_unit_t_btc_never_auto_refunds():
    rec = _btc_rec(t_btc=t.Timelock(1_000_000, t.TimeUnit.SECONDS))  # time-based CSV
    d = _decide(rec, _obs(btc_funding_confirmations=10_000))
    assert d.intent is Intent.WATCH and d.autonomous_btc_refund is False


def test_params_mismatch_autonomous_only_when_matured():
    rec = _btc_rec(state=SwapState.PARAMS_MISMATCH)
    immature = _decide(rec, _obs(btc_funding_confirmations=None))
    assert immature.intent is Intent.PAGE_REFUND and immature.autonomous_btc_refund is False  # page yes, auto no
    mature = _decide(rec, _obs(btc_funding_confirmations=200))
    assert mature.intent is Intent.PAGE_REFUND and mature.autonomous_btc_refund is True


# ─────────────────────────────────────────── keyless invariant ──


_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


def _swap_with_key(*, network="bcrt", btc_sats=5_000, fee_sats=500):
    """Like ``_swap`` but returns the refund private key + dest SPK so the online presign step can sign."""
    taker_sk = coincurve.PrivateKey(os.urandom(32))
    maker_sk = coincurve.PrivateKey(os.urandom(32))
    timeout = t.Timelock(144, t.TimeUnit.BLOCKS)
    htlc = t.build_htlc(
        hashlock=_H,
        claim_pubkey_xonly=_xonly(maker_sk),
        refund_pubkey_xonly=_xonly(taker_sk),
        timeout=timeout,
        network=network,
    )
    loc = htlc.with_funding(t.BtcOutpoint(_FUND_TXID, 0), btc_sats)
    rec = SwapRecord(
        state=SwapState.BTC_LOCKED,
        terms=_terms(btc_sats=btc_sats, t_btc=timeout),
        counterchain_locator=loc,
        radiant_covenant_outpoint=_COV,
    )
    return rec, taker_sk.secret


async def test_presign_step_arms_an_executor_acceptable_blob(tmp_path):
    # The online setup step rebuilds the refund from the PERSISTED record (locator round-trip), signs
    # once with the operator's key, and writes the sidecar the keyless tower later broadcasts.
    from presign_refund import presign_refund  # scripts/ sibling (key used here, NEVER in the tower)

    rec, refund_privkey = _swap_with_key(network="bcrt", btc_sats=5_000, fee_sats=500)
    (tmp_path / "swap1.json").write_text(json.dumps(rec.to_dict()))  # as the coordinator persists it
    dest = presign_refund(
        record_path=tmp_path / "swap1.json",
        refund_privkey=refund_privkey,
        to_scriptpubkey=_REFUND_SPK,
        fee_sats=500,
        out_dir=tmp_path,
    )
    assert dest.name == "swap1.refund.json"
    # the tower loads + accepts it (arming with the SAME pinned refund SPK) → BROADCAST
    b = _FakeBroadcaster()
    out = await _armed(tmp_path, b).execute("swap1", rec, _refund_decision())
    assert out is ExecOutcome.BROADCAST and len(b.calls) == 1


def test_spend_fields_parser_fail_closed_and_differential():
    # The new hardened parser must NEVER half-parse: it agrees with btc_txid_from_raw (both succeed on a
    # valid segwit refund, both raise on garbage), and rejects truncation / trailing bytes fail-closed.
    _, blob = _swap()
    raw = blob.raw_tx
    fields = t.btc_spend_fields_from_raw(raw)
    assert len(fields.input_prevouts) == 1 and len(fields.outputs) == 1
    assert t.btc_txid_from_raw(raw)  # the sibling hardened parser succeeds on the same bytes
    with pytest.raises(ValidationError):
        t.btc_spend_fields_from_raw(raw[:-1])  # truncated
    with pytest.raises(ValidationError):
        t.btc_spend_fields_from_raw(raw + b"\x00")  # trailing bytes after locktime
    for bad in (b"", b"\x00\x01\x02", b"\x02\x00\x00\x00"):  # garbage / version-only
        with pytest.raises(ValidationError):
            t.btc_spend_fields_from_raw(bad)
        with pytest.raises(ValidationError):
            t.btc_txid_from_raw(bad)  # differential: neither hardened parser ever half-parses


def test_records_store_ignores_refund_sidecars(tmp_path):
    # The default --refund-blobs-dir == --records-dir; the sidecar must NOT be parsed as a SwapRecord
    # (which would spam per-tick warnings / trip the all-unreadable "watching nothing" page).
    import asyncio

    from pyrxd.gravity.watch import JsonDirRecordStore

    _, blob = _swap()
    _write(tmp_path, blob)  # writes <swap1>.refund.json beside where records live
    active = asyncio.run(JsonDirRecordStore(tmp_path).list_active())
    assert active == []  # the refund sidecar is ignored, not a phantom/unreadable "record"


def test_funding_reader_is_network_aware():
    # The runner's BTC funding reader must follow --network: mainnet → 3 default 2-of-3 Esplora; signet →
    # the configured signet Esplora (NOT mainnet), quorum clamped to the single source. A mainnet reader
    # on a signet run would never find the funding (fail-closed WATCH), so this wiring is load-bearing.
    from watchtower_run import _build_funding_reader

    mainnet = _build_funding_reader("bc", ["https://mempool.space"], 2)
    assert mainnet._quorum == 2 and len(mainnet._readers) == 3

    signet = _build_funding_reader("signet", ["https://mempool.space/signet"], 2)
    assert len(signet._readers) == 1 and signet._quorum == 1  # clamped to the single signet source
    assert "signet/api" in signet._readers[0]._http._base_url  # signet Esplora API base, not mainnet


def test_executor_module_is_keyless():
    src = Path(__file__).resolve().parent.parent / "src" / "pyrxd" / "gravity" / "watch" / "executor.py"
    text = src.read_text()
    for forbidden in (
        "coincurve",
        "PrivateKey",
        "SwapCoordinator",
        "build_refund_tx",
        "build_claim_tx",
        "sign_schnorr",
    ):
        assert forbidden not in text, f"executor.py must be keyless — found {forbidden!r}"


# ─────────────────────────────────────────── reconciler seam ──


class _Store:
    def __init__(self, items):
        self._items = items

    async def list_active(self):
        return self._items


class _MatureObserver:
    """Returns a matured-funding observation → decide() yields PAGE_REFUND(autonomous) for a BTC_LOCKED swap."""

    async def observe(self, swap_id, record):
        return Observations(maker_has_claimed_btc=False, now_rxd_height=500, btc_funding_confirmations=999)


class _Alerter:
    def __init__(self):
        self.pages = []

    async def handle(self, swap_id, decision):
        self.pages.append((swap_id, decision.intent))


def _reconciler(executor, alerter):
    rec, _ = _swap(network="bcrt")
    return (
        Reconciler(
            store=_Store([("swap1", rec)]),
            observer=_MatureObserver(),
            alerter=alerter,
            policy=_policy(),
            safety_window_blocks=6,
            executor=executor,
        ),
        rec,
    )


async def test_reconciler_default_broadcasts_nothing_but_pages(tmp_path):
    alerter = _Alerter()
    r, _ = _reconciler(None, alerter)  # default → NullExecutor
    [res] = await r.tick()
    assert res.decision.intent is Intent.PAGE_REFUND and res.decision.autonomous_btc_refund is True
    assert res.executed is None  # NO autonomy by default
    assert alerter.pages == [("swap1", Intent.PAGE_REFUND)]  # but the operator IS paged


async def test_reconciler_armed_broadcasts_and_still_pages(tmp_path):
    _, blob = _swap(network="bcrt")
    _write(tmp_path, blob)
    alerter = _Alerter()
    r, _ = _reconciler(_armed(tmp_path, _FakeBroadcaster()), alerter)
    [res] = await r.tick()
    assert res.executed is ExecOutcome.BROADCAST
    assert alerter.pages == [("swap1", Intent.PAGE_REFUND)]  # alerter ALWAYS fires, even after a broadcast


async def test_reconciler_broadcast_failure_is_failed_and_still_pages(tmp_path):
    _, blob = _swap(network="bcrt")
    _write(tmp_path, blob)
    alerter = _Alerter()
    r, _ = _reconciler(_armed(tmp_path, _RaisingBroadcaster()), alerter)
    [res] = await r.tick()
    assert res.executed is ExecOutcome.FAILED  # broadcast raised → recorded, not swallowed
    assert alerter.pages == [("swap1", Intent.PAGE_REFUND)]  # and the operator is STILL paged
