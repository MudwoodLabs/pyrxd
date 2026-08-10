"""Conformance-vector guard for the cross-chain HTLC swap-handshake wire format.

Re-derives every published vector in ``conformance/htlc-handshake-vectors.json`` from the
live builders, so the spec in ``docs/htlc-handshake-wire-format.md`` cannot silently rot
away from the code it documents.

HONESTY NOTE: pyrxd is the reference *producer* for this suite, so a passing run is a
REGRESSION LOCK (the bytes have not drifted), not independent validation. It says nothing
about whether the protocol is safe — the swap stack is UNAUDITED. What it does buy is that
a second implementation has a fixed, versioned target to differential-test against, and
that pyrxd cannot change the handshake bytes without either updating the published file or
turning this red.

The suite covers four things the spec makes normative:

1. the ``NegotiatedTerms`` JSON wire form round-trips byte-identically, and the optional
   ETH/credential keys are omitted exactly when they hold their BTC defaults;
2. the 32-byte preimage rule — the fixed length is what the ``OP_SIZE <0x20>
   OP_EQUALVERIFY`` prefix consensus-pins on both legs' claim branches;
3. the timelock-margin invariant ``t_btc - t_rxd >= margin``, including the cross-unit case
   that the cheap same-unit construction guard cannot see;
4. the two re-derived commitments a counterparty actually checks — the BTC P2TR funding
   scriptPubKey and the Radiant covenant scriptPubKey.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.htlc_covenant import (
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
    holder_hash,
)
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin
from pyrxd.gravity.swap_state import NegotiatedTerms
from pyrxd.security.errors import ValidationError

VECTORS_PATH = Path(__file__).resolve().parent.parent / "conformance" / "htlc-handshake-vectors.json"


def _load() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


_DOC = _load()
_TERMS = _DOC["terms_vectors"]
_HASHLOCKS = _DOC["hashlock_vectors"]
_MARGINS = _DOC["margin_vectors"]


def _ids(vectors: list[dict]) -> list[str]:
    return [v["id"] for v in vectors]


def _timelock(d: dict) -> bt.Timelock:
    return bt.Timelock(int(d["value"]), bt.TimeUnit(d["unit"]))


# ---------------------------------------------------------------------------
# Suite shape
# ---------------------------------------------------------------------------


def test_schema_marker():
    assert _DOC["schema"] == "radiant-htlc-handshake/1"


def test_suite_covers_every_asset_variant_and_both_counter_chains():
    """A handshake spec that only exercises the RXD/BTC happy path is not a spec."""
    variants = {v["terms"]["asset_variant"] for v in _TERMS}
    assert variants == {"rxd", "ft", "nft"}, f"missing asset-variant coverage: {variants}"
    chains = {v["terms"].get("counter_chain", "btc") for v in _TERMS}
    assert chains == {"btc", "eth"}, f"missing counter-chain coverage: {chains}"
    assert any("credential_ref" in v["terms"] for v in _TERMS), "no credential-gated vector"


def test_no_vector_carries_a_preimage_field():
    """The preimage p must never appear in a serialised handshake artifact.

    The published hashlock vectors carry a deliberately-synthetic ASCII preimage under
    ``preimage_ascii`` (it is test data, not a secret) — but no ``terms`` object may carry
    one under any name, which is the property the wire form actually guarantees.
    """
    for v in _TERMS:
        for key in v["terms"]:
            assert "preimage" not in key.lower(), f"{v['id']}: terms carries a preimage-shaped key {key!r}"
            assert not key.lower().endswith("_p"), f"{v['id']}: terms carries a preimage-shaped key {key!r}"


# ---------------------------------------------------------------------------
# 1. NegotiatedTerms wire form
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_terms_round_trip_byte_identical(vec: dict):
    """``from_dict`` then ``to_dict`` must reproduce the published JSON exactly.

    This is the interop contract: a second implementation that emits these bytes is read
    correctly by pyrxd, and vice versa.
    """
    terms = NegotiatedTerms.from_dict(vec["terms"])
    assert terms.to_dict() == vec["terms"], (
        f"handshake vector {vec['id']!r} no longer round-trips — regenerate the suite or fix the wire form"
    )


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_optional_keys_are_omitted_exactly_when_default(vec: dict):
    """The BTC wire form omits the ETH-additive keys; a reader MUST supply the defaults.

    A conforming implementation that requires all keys to be present would reject every
    honest BTC handshake, so the omission rule is normative rather than cosmetic.
    """
    d = vec["terms"]
    terms = NegotiatedTerms.from_dict(d)
    assert ("counter_chain" in d) is (terms.counter_chain != "btc")
    assert ("value_amount" in d) is (terms.value_amount != terms.btc_sats)
    assert ("eth_timeout_unix_s" in d) is (terms.eth_timeout_unix_s is not None)
    assert ("credential_ref" in d) is bool(terms.credential_ref)


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_t_rxd_is_always_blocks(vec: dict):
    """The Radiant covenant CSV has no SECONDS encoding, so t_rxd is BLOCKS-only."""
    assert vec["terms"]["t_rxd"]["unit"] == "blocks"


def test_from_dict_silently_ignores_unknown_keys():
    """Documented, deliberate, and load-bearing for anyone extending the format.

    ``from_dict`` reads named keys only: an unknown key is dropped without error and there
    is no version field on ``terms`` to trip on. A receiver therefore cannot detect that a
    sender meant something it does not understand — which is exactly why the spec makes the
    two re-derived commitments (BTC funding SPK, Radiant covenant SPK), not the envelope,
    the thing safety rests on. If this test ever starts failing because parsing became
    strict, that is an improvement: update the spec's "Extending the format" section.
    """
    d = dict(_TERMS[0]["terms"])
    d["a_key_from_a_future_version"] = "ignored"
    assert NegotiatedTerms.from_dict(d).to_dict() == _TERMS[0]["terms"]


# ---------------------------------------------------------------------------
# 2. Hashlock / preimage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", _HASHLOCKS, ids=_ids(_HASHLOCKS))
def test_hashlock_is_single_sha256_of_the_preimage(vec: dict):
    p = vec["preimage_ascii"].encode()
    assert len(p) == vec["preimage_len"]
    assert hashlib.sha256(p).hexdigest() == vec["hashlock_hex"]


@pytest.mark.parametrize("vec", _HASHLOCKS, ids=_ids(_HASHLOCKS))
def test_only_a_32_byte_preimage_conforms(vec: dict):
    """The length rule is the fixed preimage-length theft vector, stated normatively.

    A non-32-byte ``p`` whose SHA256 still equals ``H`` satisfies a naive hashlock check but
    is rejected by the on-chain ``OP_SIZE <0x20> OP_EQUALVERIFY`` prefix, and is skipped by
    the 32-byte-only witness scrape — so a counterparty that accepted one would be left
    unable to claim.
    """
    assert vec["conforming"] is (vec["preimage_len"] == 32)


def test_claim_leaf_pins_the_preimage_to_32_bytes():
    """OP_SIZE (0x82) then a minimal push of 0x20 then OP_EQUALVERIFY (0x88) — the pin."""
    h = bytes.fromhex(_HASHLOCKS[0]["hashlock_hex"])
    leaf = bt.claim_leaf_script(h, bytes.fromhex("33" * 32))
    assert leaf[:4] == bytes.fromhex("82012088"), leaf[:4].hex()


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_terms_hashlock_matches_the_published_preimage(vec: dict):
    p = _HASHLOCKS[0]["preimage_ascii"].encode()
    assert vec["terms"]["hashlock"] == hashlib.sha256(p).hexdigest()


# ---------------------------------------------------------------------------
# 3. Timelock margin
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", _MARGINS, ids=_ids(_MARGINS))
def test_margin_verdicts(vec: dict):
    """``assert_timelock_margin`` must accept/reject exactly as published.

    The invariant is ``t_btc - t_rxd >= margin`` with both legs normalised to blocks. The
    direction is counterintuitive and load-bearing: the party who locks FIRST (the taker,
    on the counter leg) holds the LONGER refund window, so the leg claimed second (Radiant)
    always matures first.
    """
    policy = MarginPolicy(
        margin=_timelock(vec["margin"]),
        block_interval_s=float(vec["block_interval_s"]),
        is_measured=False,
        accept_flat_burial=True,
    )
    t_btc, t_rxd = _timelock(vec["t_btc"]), _timelock(vec["t_rxd"])
    if vec["verdict"] == "accept":
        assert_timelock_margin(t_btc, t_rxd, policy)
    else:
        with pytest.raises(ValidationError):
            assert_timelock_margin(t_btc, t_rxd, policy)


def test_cross_unit_inversion_passes_construction_but_fails_the_margin_check():
    """The construction guard is NOT the safety check — the normalising one is.

    ``NegotiatedTerms.__post_init__`` only compares t_btc/t_rxd when they share a unit, so a
    SECONDS t_btc that is shorter than a BLOCKS t_rxd constructs happily. Only
    ``assert_timelock_margin`` catches it. A second implementation that ports the cheap
    guard and skips the normalising one will fund inverted swaps.
    """
    vec = next(v for v in _MARGINS if v["id"] == "margin-cross-unit-inversion")
    base = dict(_TERMS[0]["terms"])
    base["t_btc"] = vec["t_btc"]
    base["t_rxd"] = vec["t_rxd"]
    terms = NegotiatedTerms.from_dict(base)  # constructs — the guard does not fire
    policy = MarginPolicy(
        margin=_timelock(vec["margin"]),
        block_interval_s=float(vec["block_interval_s"]),
        is_measured=False,
        accept_flat_burial=True,
    )
    with pytest.raises(ValidationError, match="ordering violated"):
        assert_timelock_margin(terms.t_btc, terms.t_rxd, policy)


# ---------------------------------------------------------------------------
# 4. The re-derived commitments
# ---------------------------------------------------------------------------


def _covenant_for(terms: NegotiatedTerms, taker_pkh: bytes, maker_pkh: bytes):
    common = {
        "taker_pkh": taker_pkh,
        "maker_pkh": maker_pkh,
        "hashlock": terms.hashlock,
        "refund_csv": terms.t_rxd.value,
    }
    if terms.asset_variant == "rxd":
        return build_htlc_covenant_rxd(amount=terms.radiant_amount, **common)
    txid = terms.genesis_ref[:32][::-1].hex()
    vout = int.from_bytes(terms.genesis_ref[32:], "little")
    if terms.asset_variant == "ft":
        return build_htlc_covenant_ft(genesis_txid=txid, genesis_vout=vout, amount=terms.radiant_amount, **common)
    return build_htlc_covenant_nft(
        genesis_txid=txid, genesis_vout=vout, nft_carrier_value=terms.radiant_amount, **common
    )


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_radiant_covenant_spk_rederives_from_terms(vec: dict):
    """The asset-side commitment. Byte-equality here revalidates every negotiated Radiant
    parameter at once, because each is substituted into the covenant bytecode."""
    terms = NegotiatedTerms.from_dict(vec["terms"])
    dp = vec["derivation_params"]
    cov = _covenant_for(terms, bytes.fromhex(dp["taker_pkh_hex"]), bytes.fromhex(dp["maker_pkh_hex"]))
    assert cov.funded_spk.hex() == vec["covenant_scriptpubkey_hex"], (
        f"vector {vec['id']!r}: covenant SPK diverged from the published bytes"
    )


@pytest.mark.parametrize("vec", _TERMS, ids=_ids(_TERMS))
def test_dest_hashes_are_hash256_of_the_holder_scripts(vec: dict):
    """``taker_dest_hash`` / ``maker_dest_hash`` are hash256 of the HOLDER SCRIPT, not of a
    pkh — a second implementation that hashes the pkh produces an unspendable covenant."""
    terms = NegotiatedTerms.from_dict(vec["terms"])
    dp = vec["derivation_params"]
    kw = {"variant": terms.asset_variant, "genesis_ref": terms.genesis_ref}
    assert holder_hash(bytes.fromhex(dp["taker_pkh_hex"]), **kw) == terms.taker_dest_hash
    assert holder_hash(bytes.fromhex(dp["maker_pkh_hex"]), **kw) == terms.maker_dest_hash


_BTC_TERMS = [v for v in _TERMS if v["terms"].get("counter_chain", "btc") == "btc"]


@pytest.mark.parametrize("vec", _BTC_TERMS, ids=_ids(_BTC_TERMS))
def test_btc_funding_spk_rederives_from_terms(vec: dict):
    """The counter-leg commitment. The taker funds this address; the maker re-derives it
    and refuses to lock the asset unless the on-chain output pays exactly it."""
    terms = NegotiatedTerms.from_dict(vec["terms"])
    dp = vec["derivation_params"]
    htlc = bt.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network=dp["btc_network"],
    )
    assert htlc.scriptpubkey.hex() == dp["btc_funding_scriptpubkey_hex"]
    assert htlc.address == dp["btc_funding_address"]
    assert htlc.script_tree.claim_script.hex() == dp["btc_claim_leaf_script_hex"]
    assert htlc.script_tree.refund_script.hex() == dp["btc_refund_leaf_script_hex"]


def test_credential_gating_does_not_change_the_covenant_spk():
    """``credential_ref`` is OFF-CHAIN policy — it is absent from the bytecode.

    Without this, ``btc-rxd-credential-gated`` passes
    ``test_radiant_covenant_spk_rederives_from_terms`` for the wrong reason: the
    builder is simply never told about the credential, so of course the bytes match.
    Asserted here as the *expected* property, because the spec's §4 claim that a single
    SPK byte-comparison revalidates every negotiated Radiant parameter has exactly one
    exception, and this is it. An implementer who reads that claim as covering the
    credential gate has no gate at all: nothing on chain stops an uncredentialed party
    who learns ``p`` and can produce the pinned holder script from claiming.

    If this ever starts failing because the credential became covenant-bound, that is a
    security improvement — update ``docs/htlc-handshake-wire-format.md`` §4 with it.
    """
    gated = next(v for v in _TERMS if v["id"] == "btc-rxd-credential-gated")
    plain = next(v for v in _TERMS if v["id"] == "btc-rxd")

    assert gated["terms"]["credential_ref"], "the gated vector must actually carry a credential_ref"
    assert "credential_ref" not in plain["terms"]
    assert {k: v for k, v in gated["terms"].items() if k != "credential_ref"} == plain["terms"], (
        "the two vectors must differ ONLY by credential_ref for this comparison to mean anything"
    )
    assert gated["covenant_scriptpubkey_hex"] == plain["covenant_scriptpubkey_hex"], (
        "credential_ref unexpectedly entered the covenant bytecode"
    )
    assert gated["derivation_params"] == plain["derivation_params"]


def test_no_covenant_builder_accepts_a_credential_parameter():
    """The structural half of the claim above: there is no parameter to pass."""
    import inspect

    for builder in (build_htlc_covenant_rxd, build_htlc_covenant_ft, build_htlc_covenant_nft):
        params = set(inspect.signature(builder).parameters)
        assert not any("credential" in p for p in params), f"{builder.__name__} grew a credential parameter: {params}"


# ---------------------------------------------------------------------------
# 5. genesis_ref — what is enforced, and where
# ---------------------------------------------------------------------------


def _rxd_vector() -> dict:
    return next(v for v in _TERMS if v["id"] == "btc-rxd")


def test_ft_nft_empty_genesis_ref_rejected_at_construction():
    """``swap_state.py:339-341`` is a NON-EMPTINESS check — this is all it catches."""
    for variant in ("ft", "nft"):
        d = dict(_rxd_vector()["terms"])
        d["asset_variant"] = variant
        d["genesis_ref"] = ""
        with pytest.raises(ValidationError, match="non-empty genesis_ref"):
            NegotiatedTerms.from_dict(d)


def test_ft_wrong_length_genesis_ref_constructs_and_fails_later():
    """The 36-byte rule is enforced at ``htlc_covenant.py:194-195``, not at construction.

    Fail-closed, but DEFERRED: a reader must not infer ``len(genesis_ref) == 36`` from the
    fact that ``NegotiatedTerms`` accepted the document.
    """
    d = dict(_rxd_vector()["terms"])
    d["asset_variant"] = "ft"
    d["genesis_ref"] = "ab" * 7
    terms = NegotiatedTerms.from_dict(d)  # constructs — the emptiness guard does not fire
    assert len(terms.genesis_ref) == 7
    with pytest.raises(ValidationError, match="36-byte genesis_ref"):
        holder_hash(bytes(20), variant="ft", genesis_ref=terms.genesis_ref)


def test_rxd_genesis_ref_is_accepted_and_silently_ignored():
    """Nothing rejects a non-empty ``genesis_ref`` on an ``rxd`` swap.

    It round-trips through the wire form and changes nothing that is derived, so two
    ``rxd`` documents differing only here describe the same swap. Documented rather
    than fixed: rejecting it would be a wire-format break.
    """
    vec = _rxd_vector()
    d = dict(vec["terms"])
    d["genesis_ref"] = "ab" * 36
    terms = NegotiatedTerms.from_dict(d)

    assert terms.to_dict()["genesis_ref"] == "ab" * 36  # preserved, not normalised away
    assert holder_hash(bytes(20), variant="rxd", genesis_ref=terms.genesis_ref) == holder_hash(
        bytes(20), variant="rxd", genesis_ref=b""
    )

    dp = vec["derivation_params"]
    pkhs = (bytes.fromhex(dp["taker_pkh_hex"]), bytes.fromhex(dp["maker_pkh_hex"]))
    assert (
        _covenant_for(terms, *pkhs).funded_spk.hex()
        == _covenant_for(NegotiatedTerms.from_dict(vec["terms"]), *pkhs).funded_spk.hex()
        == vec["covenant_scriptpubkey_hex"]
    )


def test_btc_funding_spk_does_not_bind_the_asset_side():
    """A published fact a second implementer must not get wrong.

    The BTC P2TR taptree commits to H, both x-only keys and ``t_btc`` — and to NOTHING on
    the Radiant side. The rxd / ft / nft vectors differ in ``asset_variant``,
    ``genesis_ref``, ``radiant_amount`` and both dest hashes, yet derive the SAME funding
    address. Verifying the BTC leg therefore says nothing about which asset is being
    bought; only the covenant SPK check does.
    """
    spks = {
        v["derivation_params"]["btc_funding_scriptpubkey_hex"]
        for v in _BTC_TERMS
        if v["id"] in {"btc-rxd", "btc-ft", "btc-nft"}
    }
    covenants = {v["covenant_scriptpubkey_hex"] for v in _BTC_TERMS if v["id"] in {"btc-rxd", "btc-ft", "btc-nft"}}
    assert len(spks) == 1, "the BTC funding SPK unexpectedly varies with the asset side"
    assert len(covenants) == 3, "the covenant SPK must distinguish the three asset variants"
