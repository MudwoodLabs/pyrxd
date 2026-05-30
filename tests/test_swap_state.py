"""Exhaustive tests for the pure swap FSM + durable types (``gravity.swap_state``).

Covers:
* every state in the mermaid §Architecture diagram exists;
* every LEGAL transition is allowed and every ILLEGAL one rejected;
* no non-terminal state strands (every one has an exit);
* terminal states have no outgoing edges and ``advance`` refuses them;
* NegotiatedTerms / SwapRecord JSON round-trip; the secret p is never present.
"""

from __future__ import annotations

import hashlib
import itertools
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.swap_state import (
    TERMINAL_STATES,
    TRANSITIONS,
    NegotiatedTerms,
    SwapEvent,
    SwapRecord,
    SwapState,
    advance,
    allowed_targets,
    can_transition,
    is_terminal,
)
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms(*, variant: str = "ft", t_btc_blocks: int = 144, t_rxd_blocks: int = 72) -> NegotiatedTerms:
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    return NegotiatedTerms(
        hashlock=h,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant=variant,
        genesis_ref=b"\xaa" * 36 if variant in ("ft", "nft") else b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _locator() -> t.BtcHtlcLocator:
    htlc = t.build_htlc(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        claim_pubkey_xonly=_xonly(),
        refund_pubkey_xonly=_xonly(),
        timeout=t.Timelock(144, t.TimeUnit.BLOCKS),
    )
    return htlc.with_funding(t.BtcOutpoint("ab" * 32, 0), 100_000)


# ---------------------------------------------------------------------------
# State enumeration
# ---------------------------------------------------------------------------


def test_thirteen_states_present():
    expected = {
        "NEGOTIATED",
        "BTC_LOCKED",
        "BOTH_LOCKED",
        "SECRET_REVEALED",
        "COMPLETED",
        "MUTUAL_REFUND",
        "PARAMS_MISMATCH",
        "MAKER_STALLS",
        "ASSET_VULNERABLE",
        "ONE_SIDED_LOSS_TAKER",
        "ABORTED",
        "ASSET_REFUNDED_TAKER_ACTS",
    }
    actual = {s.name for s in SwapState}
    assert actual == expected
    # The mermaid diagram has 12 named states (the 13th node is the [*] pseudo-state).
    assert len(SwapState) == 12


def test_terminal_states():
    assert (
        frozenset(
            {
                SwapState.COMPLETED,
                SwapState.MUTUAL_REFUND,
                SwapState.ABORTED,
                SwapState.ASSET_REFUNDED_TAKER_ACTS,
                SwapState.ONE_SIDED_LOSS_TAKER,
            }
        )
        == TERMINAL_STATES
    )


# ---------------------------------------------------------------------------
# Transition table
# ---------------------------------------------------------------------------

# The complete legal edge set, hand-transcribed from the mermaid diagram, kept
# SEPARATE from the implementation's table so a typo in either is caught.
_LEGAL_EDGES = frozenset(
    {
        (SwapState.NEGOTIATED, SwapState.BTC_LOCKED),
        (SwapState.NEGOTIATED, SwapState.ABORTED),
        (SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED),
        (SwapState.BTC_LOCKED, SwapState.ABORTED),
        (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH),
        (SwapState.PARAMS_MISMATCH, SwapState.ABORTED),
        (SwapState.BOTH_LOCKED, SwapState.SECRET_REVEALED),
        (SwapState.BOTH_LOCKED, SwapState.MAKER_STALLS),
        (SwapState.BOTH_LOCKED, SwapState.MUTUAL_REFUND),
        (SwapState.MAKER_STALLS, SwapState.ASSET_REFUNDED_TAKER_ACTS),
        (SwapState.SECRET_REVEALED, SwapState.COMPLETED),
        (SwapState.SECRET_REVEALED, SwapState.ASSET_VULNERABLE),
        (SwapState.ASSET_VULNERABLE, SwapState.ONE_SIDED_LOSS_TAKER),
        (SwapState.ASSET_VULNERABLE, SwapState.COMPLETED),
    }
)


def test_transition_table_matches_diagram():
    assert TRANSITIONS == _LEGAL_EDGES


def test_transition_count():
    assert len(TRANSITIONS) == 14


def test_every_legal_transition_allowed():
    for src, dst in _LEGAL_EDGES:
        assert can_transition(src, dst), f"{src} -> {dst} should be allowed"


def test_every_illegal_transition_rejected():
    all_pairs = set(itertools.product(SwapState, SwapState))
    illegal = all_pairs - _LEGAL_EDGES
    for src, dst in illegal:
        assert not can_transition(src, dst), f"{src} -> {dst} should be rejected"


def test_no_non_terminal_state_strands():
    """Every non-terminal state must have at least one outgoing edge."""
    for state in SwapState:
        if state in TERMINAL_STATES:
            continue
        assert allowed_targets(state), f"{state} is non-terminal but has no exit (stranded)"


def test_terminal_states_have_no_exits():
    for state in TERMINAL_STATES:
        assert allowed_targets(state) == frozenset()
        assert is_terminal(state)


def test_advance_happy_path_chain():
    s = SwapState.NEGOTIATED
    s = advance(s, SwapEvent.TAKER_FUNDS_BTC)
    assert s is SwapState.BTC_LOCKED
    s = advance(s, SwapEvent.MAKER_LOCKS_ASSET)
    assert s is SwapState.BOTH_LOCKED
    s = advance(s, SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
    assert s is SwapState.SECRET_REVEALED
    s = advance(s, SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
    assert s is SwapState.COMPLETED
    assert is_terminal(s)


def test_advance_rejects_undefined_event_for_state():
    with pytest.raises(ValidationError):
        advance(SwapState.NEGOTIATED, SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)


def test_advance_refuses_terminal_state():
    with pytest.raises(ValidationError):
        advance(SwapState.COMPLETED, SwapEvent.TAKER_FUNDS_BTC)


def test_advance_every_event_maps_to_a_legal_edge():
    """Each defined (state,event)->target must itself be a legal diagram edge."""
    for state in SwapState:
        if state in TERMINAL_STATES:
            continue
        for event in SwapEvent:
            try:
                target = advance(state, event)
            except ValidationError:
                continue
            assert (state, target) in _LEGAL_EDGES


def test_can_transition_type_guard():
    with pytest.raises(ValidationError):
        can_transition("NEGOTIATED", SwapState.BTC_LOCKED)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# NegotiatedTerms
# ---------------------------------------------------------------------------


def test_terms_round_trip_json():
    terms = _terms()
    d = terms.to_dict()
    # JSON-clean (no bytes objects).
    import json

    s = json.dumps(d)
    back = NegotiatedTerms.from_dict(json.loads(s))
    assert back == terms


def test_terms_never_carries_preimage():
    terms = _terms()
    d = terms.to_dict()
    # No field named p / preimage / secret anywhere.
    flat = str(d).lower()
    assert "preimage" not in flat
    assert "secret" not in flat
    assert not any(k in ("p", "preimage", "secret") for k in d)


def test_terms_rejects_same_unit_bad_ordering():
    with pytest.raises(ValidationError):
        _terms(t_btc_blocks=72, t_rxd_blocks=72)  # t_btc <= t_rxd
    with pytest.raises(ValidationError):
        _terms(t_btc_blocks=50, t_rxd_blocks=72)


def test_terms_rejects_seconds_t_rxd_f002():
    # F-002: the Radiant HTLC covenant CSV operand has no SECONDS (BIP68 type-flag)
    # encoding path, so a SECONDS-tagged t_rxd would be used raw and desync the
    # on-chain refund window from every off-chain safety gate. Reject at construction.
    with pytest.raises(ValidationError, match="t_rxd must be a BLOCKS timelock"):
        NegotiatedTerms(
            hashlock=hashlib.sha256(b"x").digest(),
            btc_sats=100_000,
            radiant_amount=1_000,
            t_btc=t.Timelock(200_000, t.TimeUnit.SECONDS),
            t_rxd=t.Timelock(100_000, t.TimeUnit.SECONDS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=_xonly(),
            btc_refund_pubkey_xonly=_xonly(),
        )


def test_terms_rejects_short_hashlock():
    with pytest.raises(ValidationError):
        NegotiatedTerms(
            hashlock=b"\x00" * 31,
            btc_sats=1,
            radiant_amount=1,
            t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=_xonly(),
            btc_refund_pubkey_xonly=_xonly(),
        )


def test_terms_ft_requires_genesis_ref():
    with pytest.raises(ValidationError):
        _bad = NegotiatedTerms(
            hashlock=hashlib.sha256(b"x").digest(),
            btc_sats=1,
            radiant_amount=1,
            t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="ft",
            genesis_ref=b"",  # missing
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=_xonly(),
            btc_refund_pubkey_xonly=_xonly(),
        )


# ---------------------------------------------------------------------------
# SwapRecord
# ---------------------------------------------------------------------------


def test_record_round_trip_with_btc_lock():
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms())
    rec = rec.with_btc_lock(_locator()).with_state(SwapState.BTC_LOCKED)
    import json

    d = rec.to_dict()
    s = json.dumps(d)
    back = SwapRecord.from_dict(json.loads(s))
    assert back.state is SwapState.BTC_LOCKED
    assert back.terms == rec.terms
    # The full locator round-trips (the crash-recovery requirement).
    assert back.btc_locator is not None
    assert back.btc_locator.to_dict() == rec.btc_locator.to_dict()
    assert back.btc_locator.control_block_claim == rec.btc_locator.control_block_claim
    assert back.btc_locator.script_tree.merkle_root == rec.btc_locator.script_tree.merkle_root


def test_record_round_trip_with_radiant_lock():
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms())
    rec = (
        rec.with_btc_lock(_locator()).with_radiant_lock("cd" * 32 + ":1", "deadbeef").with_state(SwapState.BOTH_LOCKED)
    )
    import json

    back = SwapRecord.from_dict(json.loads(json.dumps(rec.to_dict())))
    assert back.radiant_covenant_outpoint == "cd" * 32 + ":1"
    assert back.radiant_covenant_spk_hex == "deadbeef"


def test_record_serialized_form_excludes_secret():
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms())
    d = rec.to_dict()
    flat = str(d).lower()
    assert "preimage" not in flat and "secret" not in flat
    assert "p" not in d  # no top-level secret field


def test_record_rejects_bad_spk_hex():
    with pytest.raises(ValidationError):
        SwapRecord(state=SwapState.BOTH_LOCKED, terms=_terms(), radiant_covenant_spk_hex="nothex!!")


# --------------------------------------------------------------------------- R3: ETH counter-leg terms

_ZERO = b"\x00" * 32


def _eth_terms(*, value_wei: int = 10**15) -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(7200, t.TimeUnit.SECONDS),  # ETH refund duration; skips same-unit guard
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_ZERO,
        btc_refund_pubkey_xonly=_ZERO,
        counter_chain="eth",
        value_amount=value_wei,
    )


def test_btc_terms_default_counter_chain_and_byte_identical_to_dict():
    terms = _terms(variant="rxd")
    assert terms.counter_chain == "btc"
    assert terms.value_amount == terms.btc_sats  # 0 sentinel -> btc_sats
    d = terms.to_dict()
    assert "counter_chain" not in d and "value_amount" not in d  # pre-ETH wire form unchanged
    assert NegotiatedTerms.from_dict(d) == terms


def test_eth_terms_construct_and_roundtrip():
    terms = _eth_terms(value_wei=10**15)
    assert terms.counter_chain == "eth"
    assert terms.value_amount == 10**15  # wei, independent of btc_sats
    d = terms.to_dict()
    assert d["counter_chain"] == "eth" and d["value_amount"] == 10**15
    assert NegotiatedTerms.from_dict(d) == terms


def test_eth_terms_reject_nonzero_btc_xonly():
    with pytest.raises(ValidationError, match="zero placeholder"):
        NegotiatedTerms(
            hashlock=hashlib.sha256(os.urandom(32)).digest(),
            btc_sats=100_000,
            radiant_amount=1_000,
            t_btc=t.Timelock(7200, t.TimeUnit.SECONDS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=b"\x03" * 32,  # a real key on an ETH swap
            btc_refund_pubkey_xonly=_ZERO,
            counter_chain="eth",
            value_amount=10**15,
        )


def test_legacy_terms_from_dict_defaults_to_btc():
    d = _terms(variant="ft").to_dict()
    assert "counter_chain" not in d  # legacy wire form (no ETH fields)
    terms = NegotiatedTerms.from_dict(d)
    assert terms.counter_chain == "btc"
    assert terms.value_amount == terms.btc_sats


def test_bad_counter_chain_rejected():
    with pytest.raises(ValidationError, match="counter_chain"):
        NegotiatedTerms(
            hashlock=hashlib.sha256(os.urandom(32)).digest(),
            btc_sats=1_000,
            radiant_amount=1,
            t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=_xonly(),
            btc_refund_pubkey_xonly=_xonly(),
            counter_chain="ltc",
        )


# --------------------------------------------------------------------------- R3b: SwapRecord locator


def _eth_locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "ab" * 20,
        deploy_tx_hash="0x" + "cd" * 32,
        hashlock="0x" + "ef" * 32,
        claimant="0x" + "11" * 20,
        refundee="0x" + "22" * 20,
        timeout=1779710245,
        amount_wei=10**15,
    )


def test_btc_record_to_dict_is_v1_byte_identical():
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms()).with_btc_lock(_locator())
    d = rec.to_dict()
    assert "btc_locator" in d  # v1 bare key
    assert "schema_version" not in d and "counterchain_locator" not in d
    assert SwapRecord.from_dict(d) == rec
    assert rec.btc_locator is not None and rec.counterchain_locator is rec.btc_locator


def test_eth_record_roundtrip_v2_tagged():
    terms = _eth_terms()
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms).with_counter_lock(_eth_locator())
    d = rec.to_dict()
    assert d["schema_version"] == 2
    assert d["counterchain_locator"]["chain"] == "eth"
    assert "btc_locator" not in d
    back = SwapRecord.from_dict(d)
    assert back == rec
    assert isinstance(back.counterchain_locator, EthHtlcLocator)
    assert back.btc_locator is None  # the BTC-only alias is None for an ETH locator


def test_legacy_v1_record_from_dict_reads_btc_locator():
    # a pre-ETH persisted record: bare btc_locator, no schema_version/counter_chain
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms()).with_btc_lock(_locator())
    v1 = rec.to_dict()
    assert set(v1).isdisjoint({"schema_version", "counterchain_locator"})
    back = SwapRecord.from_dict(v1)
    assert isinstance(back.counterchain_locator, type(_locator()))
    assert back.terms.counter_chain == "btc"


def test_record_rejects_locator_chain_mismatch():
    # a BTC locator on an ETH swap, and vice-versa, are fail-closed
    with pytest.raises(ValidationError, match="counter_chain == 'eth'"):
        SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms(), counterchain_locator=_eth_locator())
    with pytest.raises(ValidationError, match="counter_chain == 'btc'"):
        SwapRecord(state=SwapState.BTC_LOCKED, terms=_eth_terms(), counterchain_locator=_locator())


def test_eth_record_prefund_roundtrips_via_terms():
    # ETH swap before the counter-leg lock: no locator yet; ETH-ness preserved via terms
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms())
    d = rec.to_dict()
    assert "btc_locator" in d and d["btc_locator"] is None  # v1 form, no locator
    back = SwapRecord.from_dict(d)
    assert back.terms.counter_chain == "eth" and back.counterchain_locator is None


def test_eth_value_amount_zero_rejected_no_sats_coercion():
    # ETH value_amount is WEI; the 0=>btc_sats sentinel must NOT cross the sats↔wei boundary
    # (audit fail_closed). A forgotten wei value fails closed instead of silently funding at
    # the sats scale.
    with pytest.raises(ValidationError, match="explicitly set for an ETH swap"):
        _eth_terms(value_wei=0)
    # BTC keeps the 0 -> btc_sats sentinel (byte-equivalent).
    btc = _terms(variant="rxd")
    assert btc.value_amount == btc.btc_sats
