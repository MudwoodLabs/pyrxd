"""Live-regtest validation of the deployed-covenant semantics the differential
model leaves skipped.

Resolves every "needs live-regtest" / "NOT modelled" question in
``tests/test_spv_covenant_differential_deployed.py`` against REAL Radiant consensus
via ``testmempoolaccept`` on an isolated ``radiant-core:v3.1.1`` regtest node — the
only way to pin behaviour that depends on the compiled script interpreter:

  * Group V  — value-field ``OP_8 OP_SPLIT OP_DROP OP_BIN2NUM`` on 5..8 significant
               bytes (Radiant CScriptNum element-size limit). Un-skips
               ``test_value_5_to_8_byte_bin2num_needs_regtest``.
  * Group NB — per-header nBits exponent ceiling: the covenant tolerates exp up to
               0x20 while Python's ``Nbits`` rejects > 0x1d. Un-skips
               ``test_header_nbits_exponent_ceiling_divergence_needs_regtest``.
  * Group M  — 20-level merkle walk + sentinel (0x02) NO-OP handling.
  * Group S  — baseline (S-1), multi-output finalize introspection arity (S-2), and
               the compile-time ``claimDeadline`` floor 1774427796 (S-3).

Direction labels (per the differential test):
  A = Python ACCEPTS / covenant REJECTS  -> taker strands BTC on the no-refund
      finalize path (the dangerous direction).
  B = covenant ACCEPTS / Python REJECTS  -> forged proof slips past review.

Every case asserts the plan's predicted verdict AND records the OBSERVED
``{allowed, reject_reason}`` to ``REGTEST_COVENANT_SEMANTICS_RESULTS.json`` as
measured evidence — a failing assertion is a real divergence to investigate, not a
guess. Plan: docs/brainstorms/gravity-ref-spike/REGTEST_VALIDATION_PLAN_2026-05-30.md.

Pre-grind the PoW chains ONCE with ``python tests/_regtest_grind_chains.py``
(parallel, ~5 min on a many-core box); this file reads the cached chains. Gating
(matches test_htlc_regtest_e2e.py):
``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``; skips (never fails) without
docker / the image. NEVER touches a mainnet node; no covenant spend is ever
broadcast — every verdict comes from ``testmempoolaccept``.

Run: ``RADIANT_REGTEST=1 pytest tests/test_spv_covenant_differential_regtest.py -m integration -s``
"""

from __future__ import annotations

import json
import os
import struct

import pytest

# Reuse the isolated-regtest harness wholesale (node fixture spins up + tears down
# a throwaway radiant-core:v3.1.1 container; accepts() == testmempoolaccept).
# Bare module names (NOT ``tests.X``): pytest's default prepend import mode puts the
# ``tests/`` dir on sys.path, and there is no ``tests/__init__.py``, so ``tests`` is not
# an importable package under ``pytest tests/ -o "addopts="`` (the coverage-overall step).
from test_htlc_regtest_e2e import _pay_to_spk, _RegtestNode, node  # noqa: F401  (node = fixture)

# Reuse the PROVEN, model-faithful BTC-tx builder + helpers + constants so the
# funding-tx shape exactly matches the covenant model the deployed test diffs against.
from test_spv_covenant_differential_deployed import (
    _SPK,
    MAKER20,
    SATS,
    _build,
    _output0_offset,
    _vi,
)

from pyrxd.gravity.codehash import compute_p2sh_code_hash, compute_p2sh_script_pubkey
from pyrxd.gravity.covenant import CovenantArtifact, build_gravity_offer
from pyrxd.gravity.transactions import build_finalize_tx, build_forfeit_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.spv.merkle import build_branch, compute_root
from pyrxd.spv.payment import P2WPKH
from pyrxd.spv.pow import hash256
from pyrxd.spv.proof import _BUILDER_TOKEN, CovenantParams, SpvProof, _read_varint

pytestmark = pytest.mark.integration

# Relaxed-target nBits exp 0x1d for the happy/V/M/S chains (Python's Nbits accepts
# <= 0x1d). NB substitutes exp 0x1e..0x21 directly into the covenant + headers.
_NBITS = b"\xff\xff\x7f\x1d"
_ANCHOR = b"\x99" * 32
_ANCHOR_HEIGHT = 800_000
_HEADER_SLOTS = 12  # MakerCovenantFlat12x20 ABI
_BRANCH_SLOTS = 20
_CLAIM_DEADLINE = 1_900_000_000  # year 2030; > the covenant's baked floor + now+24h
_DEADLINE_FLOOR = 1_774_427_796  # baked covenant constant (ASM token 1: 949ec369 LE)
_PHOTONS = 10_000_000  # 0.1 RXD locked in the MakerClaimed UTXO
_FEE_SATS = 30_000_000  # 0.3 RXD — covers the ~12 KB finalize at the regtest relayfee

_RESULTS_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "docs/brainstorms/gravity-ref-spike/REGTEST_COVENANT_SEMANTICS_RESULTS.json",
    )
)

_MAKER_KEY = PrivateKey(b"\x11" * 32)
_TAKER_KEY = PrivateKey(b"\x22" * 32)


# --------------------------------------------------------------------------- evidence


def _record(case: str, res: dict, *, direction: str, note: str) -> None:
    """Append the OBSERVED node verdict to the results JSON (read-modify-write so a
    partial run still persists what it measured)."""
    try:
        with open(_RESULTS_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[case] = {
        "allowed": res.get("allowed"),
        "reject_reason": res.get("reject-reason"),
        "direction": direction,
        "note": note,
    }
    with open(_RESULTS_PATH, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- chain cache


def _chain(value: int, nbits: bytes, n_levels: int):
    """Load a pre-ground chain cache for the payment tx (value -> txid). Raises with a
    clear message if the grinder has not been run."""
    raw = _build([b""], [(value, _SPK[P2WPKH](MAKER20))])
    txid_le = hash256(raw)
    path = f"/tmp/rgt_chain_{txid_le.hex()}_{nbits.hex()}_{n_levels}.json"
    if not os.path.exists(path):
        raise AssertionError(f"missing ground chain {path}; run `python tests/_regtest_grind_chains.py` first")
    with open(path) as f:
        return raw, txid_le, json.load(f)


def _proof(value: int = SATS, *, nbits: bytes = _NBITS, n_levels: int = 1, branch: bytes | None = None) -> SpvProof:
    """Construct an SpvProof DIRECTLY from a pre-ground cached chain, bypassing
    SpvProofBuilder's Python verification.

    build_finalize_tx only PACKS proof.headers/branch/raw_tx into the scriptSig (it
    re-verifies nothing), so a directly-built proof produces byte-identical finalize
    bytes to the verified path for the agreement cases — re-confirmed by S-1 — while
    also letting the exp>0x1d (NB) / negative-value (V-4ctrl) / corrupt-branch (M)
    cases produce finalize bytes the Python verifier would refuse to build.
    """
    raw, txid_le, cache = _chain(value, nbits, n_levels)
    headers = [bytes.fromhex(h) for h in cache["headers_hex"]]
    pos = cache["pos"]
    if branch is None:
        branch = build_branch(cache["merkle_be"], pos=pos)
    params = CovenantParams(
        btc_receive_hash=MAKER20,
        btc_receive_type=P2WPKH,
        btc_satoshis=SATS,
        chain_anchor=_ANCHOR,
        anchor_height=_ANCHOR_HEIGHT,
        merkle_depth=max(1, min(n_levels, 32)),
        expected_nbits=(nbits if nbits[3] <= 0x1D else None),  # None disables the pin (exp>0x1d)
    )
    return SpvProof(
        txid=txid_le[::-1].hex(),
        raw_tx=raw,
        headers=headers,
        branch=branch,
        pos=pos,
        output_offset=_output0_offset(raw),
        covenant_params=params,
        _token=_BUILDER_TOKEN,
    )


def _inline_proof(value: int, nbits: bytes) -> SpvProof:
    """Build a 12-header chain WITHOUT PoW grinding — for exp>0x20 (NB-2c) where the
    covenant rejects on the exponent-ceiling check BEFORE evaluating PoW, so nonce
    is irrelevant. (exp 0x21 also overflows the target reconstruction, so it cannot
    be ground.)"""
    raw = _build([b""], [(value, _SPK[P2WPKH](MAKER20))])
    txid_le = hash256(raw)
    sib_be = [((b"\xab" * 32)[::-1]).hex()]
    branch = build_branch(sib_be, pos=1)
    root_le = compute_root(txid_le[::-1].hex(), branch)
    headers, prev = [], _ANCHOR
    for i in range(_HEADER_SLOTS):
        root = root_le if i == 0 else b"\x77" * 32
        h = b"\x00\x00\x00\x20" + prev + root + b"\x00\x00\x00\x00" + nbits + b"\x00\x00\x00\x00"
        headers.append(h)
        prev = hash256(h)
    params = CovenantParams(
        btc_receive_hash=MAKER20,
        btc_receive_type=P2WPKH,
        btc_satoshis=SATS,
        chain_anchor=_ANCHOR,
        anchor_height=_ANCHOR_HEIGHT,
        merkle_depth=1,
        expected_nbits=None,
    )
    return SpvProof(
        txid=txid_le[::-1].hex(),
        raw_tx=raw,
        headers=headers,
        branch=branch,
        pos=1,
        output_offset=_output0_offset(raw),
        covenant_params=params,
        _token=_BUILDER_TOKEN,
    )


# --------------------------------------------------------------------------- offers


class _NbOffer:
    """Minimal offer-like object for NB cases (build_gravity_offer's _Nbits guard
    refuses exp>0x1d, so the covenant is built via the artifact directly)."""

    def __init__(self, claimed_redeem_hex, expected_code_hash_hex, photons_offered, claim_deadline):
        self.claimed_redeem_hex = claimed_redeem_hex
        self.expected_code_hash_hex = expected_code_hash_hex
        self.photons_offered = photons_offered
        self.claim_deadline = claim_deadline


def _make_offer(
    *,
    btc_satoshis: int = SATS,
    photons: int = _PHOTONS,
    claim_deadline: int = _CLAIM_DEADLINE,
    accept_short_deadline: bool = False,
):
    """Build a MakerCovenantFlat12x20 offer (regtest relaxed nBits)."""
    return build_gravity_offer(
        maker_pkh=_MAKER_KEY.public_key().hash160(),
        maker_pk=_MAKER_KEY.public_key().serialize(),
        taker_pk=_TAKER_KEY.public_key().serialize(),
        taker_radiant_pkh=_TAKER_KEY.public_key().hash160(),
        btc_receive_hash=MAKER20,
        btc_receive_type="p2wpkh",
        btc_satoshis=btc_satoshis,
        btc_chain_anchor=_ANCHOR,
        expected_nbits=_NBITS,
        anchor_height=_ANCHOR_HEIGHT,
        merkle_depth=1,
        claim_deadline=claim_deadline,
        photons_offered=photons,
        reject_low_difficulty=False,  # regtest ffff7f1d — opt out of the F-02 floor
        accept_short_deadline=accept_short_deadline,
    )


def _substitute_nbits_covenant(*, nbits: bytes, nbits_next: bytes | None = None, photons: int = _PHOTONS) -> _NbOffer:
    """Build a flat_12x20 covenant with an exp>0x1d nBits by calling the artifact
    substitute directly — bypassing build_gravity_offer's _Nbits guard. Replicates
    covenant.py's claimed_params assembly (covenant.py:505-541)."""
    nbits_next = nbits_next or nbits
    art = CovenantArtifact.load("maker_covenant_flat_12x20_sentinel_all")
    ctor = {p["name"] for p in art.constructor_params()}
    params = {
        "makerPkh": _MAKER_KEY.public_key().hash160().hex(),
        "btcReceiveHash": MAKER20.hex(),
        "btcSatoshis": SATS,
        "btcChainAnchor": _ANCHOR.hex(),
        "expectedNBits": nbits.hex(),
        "totalPhotonsInOutput": photons,
    }
    for name, value in {
        "takerRadiantPkh": _TAKER_KEY.public_key().hash160().hex(),
        "expectedNBitsNext": nbits_next.hex(),
        "claimDeadline": _CLAIM_DEADLINE,
        "btcReceiveType": 1,  # p2wpkh
    }.items():
        if name in ctor:
            params[name] = value
    redeem = art.substitute(params)
    return _NbOffer(redeem.hex(), compute_p2sh_code_hash(redeem).hex(), photons, _CLAIM_DEADLINE)


# --------------------------------------------------------------------------- deploy + run


def _deploy(rnode: _RegtestNode, offer, *, extra: int = 0) -> tuple[str, int, int]:
    """Fund the MakerClaimed P2SH UTXO. finalize() inspects only the spending tx +
    SPV data, not how the claimed UTXO was created, so paying the P2SH directly is a
    faithful shortcut. ``extra`` over-funds (S-2 needs room for output 1)."""
    claimed = bytes.fromhex(offer.claimed_redeem_hex)
    assert compute_p2sh_code_hash(claimed) == bytes.fromhex(offer.expected_code_hash_hex)
    carrier = offer.photons_offered + _FEE_SATS + extra
    txid = _pay_to_spk(rnode, compute_p2sh_script_pubkey(claimed), carrier)
    return txid, 0, carrier


def _finalize(offer, spv: SpvProof, txid: str, vout: int, photons: int, *, fee: int = _FEE_SATS) -> str:
    fin = build_finalize_tx(
        spv_proof=spv,
        claimed_redeem_hex=offer.claimed_redeem_hex,
        funding_txid=txid,
        funding_vout=vout,
        funding_photons=photons,
        to_address=_TAKER_KEY.address(),
        fee_sats=fee,
        minimum_output_photons=offer.photons_offered,
        header_slots=_HEADER_SLOTS,
        branch_slots=_BRANCH_SLOTS,
    )
    return fin.tx_hex


def _run(rnode: _RegtestNode, offer, spv: SpvProof) -> dict:
    """deploy -> finalize -> testmempoolaccept; returns the node result dict."""
    txid, vout, photons = _deploy(rnode, offer)
    return rnode.accepts(_finalize(offer, spv, txid, vout, photons))


# =========================================================================== S-1 baseline


def test_s1_happy_path_finalize_accepted(node: _RegtestNode):
    """S-1 (CRITICAL baseline): the canonical empty-scriptSig finalize is ACCEPTED by
    the deployed covenant on real regtest consensus. Every Direction-A reject elsewhere
    is only trustworthy once this passes."""
    offer = _make_offer()
    res = _run(node, offer, _proof(SATS))
    _record("S-1_baseline", res, direction="agreement", note="canonical empty-scriptSig P2WPKH finalize")
    assert res.get("allowed") is True, f"S-1 baseline REJECTED: {res.get('reject-reason')!r} | {res}"


# =========================================================================== Group V (value)

# (id, output-0 value, offer btcSatoshis threshold, expect_allowed, note)
_V_CASES = [
    ("V-1_5byte_2pow32", 4_294_967_296, SATS, True, "5 sig bytes (2^32); accept iff 64-bit numeric"),
    ("V-2a_maxmoney_3bythreshold", 2_100_000_000_000_000, SATS, True, "7-byte value (MAX_MONEY), 3-byte threshold"),
    ("V-2b_maxmoney_7bythreshold", 2_100_000_000_000_000, 2_000_000_000_000_000, True, "both operands 7-byte"),
    ("V-3a_7byte_3bythreshold", 2_000_000_000_000_000, SATS, True, "7-byte value, 3-byte threshold"),
    (
        "V-3b_7byte_7bythreshold",
        2_000_000_000_000_000,
        2_000_000_000_000_000,
        True,
        "value == 7-byte threshold (>= inclusive)",
    ),
    ("V-4_8byte_bit63clear", 0x7F00000000000000, SATS, True, "8 sig bytes, max positive int64"),
    ("V-4ctrl_bit63set", 0x8000000000000000, SATS, False, "bit-63 set => signed-negative decode < threshold (control)"),
    # Reject-twin pinning the FULL 7-byte threshold width: a 7-byte value just BELOW a
    # 7-byte threshold must REJECT. If the covenant truncated the threshold push, value
    # would be >= the truncated operand and wrongly accept — so this reject proves the
    # GREATERTHANOREQUAL runs on the full 7-byte threshold (complements V-2b/V-3b).
    (
        "V-5_7byte_below_threshold",
        1_999_999_999_999_999,
        2_000_000_000_000_000,
        False,
        "7-byte value < 7-byte threshold => reject",
    ),
]


@pytest.mark.parametrize("case,value,threshold,expect,note", _V_CASES, ids=[c[0] for c in _V_CASES])
def test_value_bin2num_significant_bytes(node: _RegtestNode, case, value, threshold, expect, note):
    """Group V: does the covenant's OP_BIN2NUM value read accept 5..8 significant
    bytes? Hypothesis (mainnet dMint uses 8-byte OP_8 SPLIT + GEQ): 64-bit numeric =>
    V-1/2/3/4 accept. If a positive case REJECTS, that is Direction-A taker fund-loss
    (a reachable high-value offer un-finalizable from birth)."""
    offer = _make_offer(btc_satoshis=threshold)
    res = _run(node, offer, _proof(value))
    direction = "control" if not expect else ("A?" if value <= 0x00FFFFFFFFFFFFFF else "parity")
    _record(case, res, direction=direction, note=note)
    assert res.get("allowed") is expect, f"{case} expected allowed={expect}: {res.get('reject-reason')!r} | {res}"


# =========================================================================== Group NB (nBits exp)

# (id, nBits LE, expect_allowed, note)
_NB_CASES = [
    ("NB-1_exp0x1e", b"\xff\xff\x7f\x1e", True, "exp 0x1e tolerated (Python Nbits rejects > 0x1d)"),
    ("NB-2a_exp0x1f", b"\xff\xff\x7f\x1f", True, "exp 0x1f tolerated"),
    ("NB-2b_exp0x20", b"\xff\xff\x7f\x20", True, "exp 0x20 = ceiling, tolerated"),
    ("NB-2c_exp0x21", b"\xff\xff\x7f\x21", False, "exp 0x21 > ceiling => OP_LESSTHANOREQUAL OP_VERIFY reject"),
]


@pytest.mark.parametrize("case,nbits,expect,note", _NB_CASES, ids=[c[0] for c in _NB_CASES])
def test_header_nbits_exponent_ceiling(node: _RegtestNode, case, nbits, expect, note):
    """Group NB: the covenant pins per-header nBits and bounds the exponent to
    [3, 0x20]. Python's Nbits rejects exp > 0x1d. So exp 0x1e..0x20 ACCEPTING on the
    covenant = confirmed Direction-B accept-band; exp 0x21 must REJECT (first mutual
    reject). Covenant built via artifact-substitution (build_gravity_offer refuses)."""
    offer = _substitute_nbits_covenant(nbits=nbits)
    spv = _inline_proof(SATS, nbits) if nbits[3] > 0x20 else _proof(SATS, nbits=nbits)
    res = _run(node, offer, spv)
    _record(case, res, direction=("B" if expect else "agreement"), note=note)
    assert res.get("allowed") is expect, f"{case} expected allowed={expect}: {res.get('reject-reason')!r} | {res}"


# =========================================================================== Group M (merkle)


def test_m1_short_branch_padded_to_20(node: _RegtestNode):
    """M-1: a real depth-1 branch padded to 20 with 0x02 sentinels (exactly what
    build_finalize_tx emits) is ACCEPTED — the 19 sentinels NO-OP."""
    offer = _make_offer()
    res = _run(node, offer, _proof(SATS, n_levels=1))  # build_finalize_tx auto-pads to 20
    _record("M-1_padded_depth1", res, direction="agreement", note="19 trailing 0x02 sentinels NO-OP")
    assert res.get("allowed") is True, f"M-1 REJECTED: {res.get('reject-reason')!r} | {res}"


def test_m1neg_corrupt_sentinel_direction_rejected(node: _RegtestNode):
    """M-1 negative control: replace one trailing pad slot's direction byte 0x02 ->
    0x00 so it is NO LONGER a NO-OP (does H(cur||zeros)) -> wrong root -> REJECT.
    Proves it is specifically 0x02 that NO-OPs."""
    offer = _make_offer()
    real = build_branch([((b"\xab" * 32)[::-1]).hex()], pos=1)  # the one real level (dir 0x01)
    corrupt = real + (b"\x02" + b"\x00" * 32) * 18 + (b"\x00" + b"\x00" * 32)  # last slot dir 0x00, not 0x02
    res = _run(node, offer, _proof(SATS, n_levels=1, branch=corrupt))
    _record("M-1neg_corrupt_sentinel", res, direction="agreement", note="0x00 pad dir mutates root -> reject")
    assert res.get("allowed") is False, f"M-1neg expected REJECT (root mismatch): {res}"


def test_m2_full_20_real_levels(node: _RegtestNode):
    """M-2: a genuine 20-level merkle branch (no padding) is ACCEPTED — confirms 20 is
    a real usable depth, not just a padding ceiling."""
    offer = _make_offer()
    res = _run(node, offer, _proof(SATS, n_levels=20))
    _record("M-2_full_20_levels", res, direction="agreement", note="20 genuine levels verify")
    assert res.get("allowed") is True, f"M-2 REJECTED: {res.get('reject-reason')!r} | {res}"


def test_m3_misplaced_sentinel_rejected(node: _RegtestNode):
    """M-3: inject a 0x02 sentinel into a REAL interior level of the 20-level branch
    (covenant NO-OPs it) -> the genuine sibling is skipped -> wrong root -> REJECT.
    Proves sentinels only safely NO-OP as trailing padding, never to forge inclusion."""
    offer = _make_offer()
    _raw, _txid, cache = _chain(SATS, _NBITS, 20)
    branch = bytearray(build_branch(cache["merkle_be"], pos=1))
    branch[0] = 0x02  # corrupt level-0 direction: real sibling now skipped
    res = _run(node, offer, _proof(SATS, n_levels=20, branch=bytes(branch)))
    _record("M-3_misplaced_sentinel", res, direction="agreement", note="0x02 on a real level skips sibling -> reject")
    assert res.get("allowed") is False, f"M-3 expected REJECT (root mismatch): {res}"


def test_m4_over_depth_rejected_at_construction():
    """M-4: a 21-real-level branch exceeds the covenant's 20 branch slots; the BUILDER
    refuses it at construction (transactions.py), so nothing is ever broadcast.

    This is a BUILDER-side guard, NOT an on-chain one: the covenant indexes 20 FIXED
    slot offsets and would silently ignore a 21st slot's trailing bytes (it never reads
    past slot 19). So the over-depth defense must live in the builder — which is exactly
    why this asserts the builder raises rather than asserting a node reject.

    Unlike the rest of the matrix this needs no node — so it must also need no /tmp chain
    cache (it runs un-skipped under ``coverage-overall``, which drops the integration
    filter but has no RADIANT_REGTEST/grind). Build a minimal proof inline: 12 dummy
    headers satisfy build_finalize_tx's header-count check, which runs BEFORE the branch-
    depth check that this test exercises."""
    over = (b"\x00" + b"\x11" * 32) * 21  # 21 levels
    raw = _build([b""], [(SATS, _SPK[P2WPKH](MAKER20))])
    spv = SpvProof(
        txid=hash256(raw)[::-1].hex(),
        raw_tx=raw,
        headers=[b"\x00" * 80] * _HEADER_SLOTS,  # dummy: count check passes before the depth check
        branch=over,
        pos=1,
        output_offset=_output0_offset(raw),
        covenant_params=CovenantParams(
            btc_receive_hash=MAKER20,
            btc_receive_type=P2WPKH,
            btc_satoshis=SATS,
            chain_anchor=_ANCHOR,
            anchor_height=_ANCHOR_HEIGHT,
            merkle_depth=1,
            expected_nbits=None,
        ),
        _token=_BUILDER_TOKEN,
    )
    with pytest.raises(ValidationError, match="exceeds covenant branch_slots"):
        build_finalize_tx(
            spv_proof=spv,
            claimed_redeem_hex=_make_offer().claimed_redeem_hex,
            funding_txid="11" * 32,
            funding_vout=0,
            funding_photons=_PHOTONS + _FEE_SATS,
            to_address=_TAKER_KEY.address(),
            fee_sats=_FEE_SATS,
            minimum_output_photons=_PHOTONS,
            header_slots=_HEADER_SLOTS,
            branch_slots=_BRANCH_SLOTS,
        )


# =========================================================================== Group S (structure/deadline)


def _split_finalize_outputs(raw: bytes, out0_value: int, out1_spk: bytes) -> bytes:
    """Rewrite a single-output finalize tx into two outputs: output0 keeps its SPK but
    value out0_value; output1 gets the remainder paid to out1_spk. Used for S-2 (the
    builder hardcodes one output)."""
    p = 4
    assert raw[p] == 0x01, "expected single input"
    p += 1 + 36
    sl, p = _read_varint(raw, p)
    p += sl + 4  # scriptSig + sequence
    prefix = raw[:p]
    n_out, q = _read_varint(raw, p)
    assert n_out == 1
    orig_value = int.from_bytes(raw[q : q + 8], "little")
    q += 8
    slen, q = _read_varint(raw, q)
    spk0 = raw[q : q + slen]
    q += slen
    locktime = raw[q : q + 4]
    body = (
        _vi(2)
        + struct.pack("<Q", out0_value)
        + _vi(len(spk0))
        + spk0
        + struct.pack("<Q", orig_value - out0_value)
        + _vi(len(out1_spk))
        + out1_spk
    )
    return prefix + body + locktime


def test_s2_multi_output_finalize_arity(node: _RegtestNode):
    """S-2: a 2-output finalize (output0 = correct taker payment >= floor; output1 =
    arbitrary). The covenant introspects output 0 only (no OP_*COUNT / NUMOUTPUTS), so
    it should ACCEPT. Negative control: output0 underfunded -> REJECT (proves output-0
    still binds; payment can't be routed to output1)."""
    offer = _make_offer()
    txid, vout, photons = _deploy(node, offer, extra=5_000_000)  # room for output 1 above dust
    raw = bytes.fromhex(_finalize(offer, _proof(SATS), txid, vout, photons))
    maker_spk = b"\x76\xa9\x14" + _MAKER_KEY.public_key().hash160() + b"\x88\xac"

    two = _split_finalize_outputs(raw, offer.photons_offered, maker_spk)  # output0 == floor
    res = node.accepts(two.hex())
    _record("S-2_multi_output", res, direction="B", note="index-0-only introspection; no arity guard")
    assert res.get("allowed") is True, f"S-2 expected ACCEPT (index-0-only): {res.get('reject-reason')!r} | {res}"

    two_bad = _split_finalize_outputs(raw, offer.photons_offered - 1, maker_spk)  # output0 below floor
    res_bad = node.accepts(two_bad.hex())
    _record(
        "S-2_multi_output_control",
        res_bad,
        direction="agreement",
        note="output0 < floor with 2 outputs => reject (proves output-0 binds; can't route to output1)",
    )
    assert res_bad.get("allowed") is False, f"S-2 control expected REJECT (output0 < floor): {res_bad}"


def test_s3_claim_deadline_floor(node: _RegtestNode):
    """S-3 (Direction-A): the covenant bakes a fixed claimDeadline floor 1774427796
    (token: $claimDeadline >= 0x69c39e94 VERIFY) checked on BOTH finalize and forfeit
    before any branch. A deadline below the floor bricks the covenant (taker can never
    finalize -> permanent stranding); Python's validate_claim_deadline has no such
    awareness. Pins: below-floor REJECT, exact-floor ACCEPT (>= inclusive)."""
    # LOW: claim_deadline = floor - 1  -> token-3 OP_VERIFY rejects (both paths).
    low = _make_offer(claim_deadline=_DEADLINE_FLOOR - 1, accept_short_deadline=True)
    res_low = _run(node, low, _proof(SATS))
    _record("S-3_below_floor", res_low, direction="A", note="deadline < 1774427796 bricks finalize")
    assert res_low.get("allowed") is False, f"S-3 below-floor expected REJECT: {res_low}"

    # HIGH: claim_deadline = floor exactly -> >= is inclusive -> ACCEPT.
    high = _make_offer(claim_deadline=_DEADLINE_FLOOR, accept_short_deadline=True)
    res_high = _run(node, high, _proof(SATS))
    _record("S-3_at_floor", res_high, direction="agreement", note="deadline == 1774427796 (>= inclusive) accepts")
    assert res_high.get("allowed") is True, (
        f"S-3 at-floor expected ACCEPT: {res_high.get('reject-reason')!r} | {res_high}"
    )


def test_s3_forfeit_after_deadline(node: _RegtestNode):
    """S-3 forfeit: once claimDeadline (== floor, in the past) is mature vs the node's
    median-time-past, the Maker's forfeit() reclaim is ACCEPTED (nLockTime CLTV +
    floor both satisfied)."""
    node.mine(6)  # advance MTP past the (already-past) deadline
    offer = _make_offer(claim_deadline=_DEADLINE_FLOOR, accept_short_deadline=True)
    txid, vout, photons = _deploy(node, offer)
    res = node.accepts(
        build_forfeit_tx(
            offer=offer,
            funding_txid=txid,
            funding_vout=vout,
            funding_photons=photons,
            maker_address=_MAKER_KEY.address(),
            fee_sats=_FEE_SATS,
        ).tx_hex
    )
    _record("S-3_forfeit", res, direction="agreement", note="forfeit reclaim after mature deadline")
    assert res.get("allowed") is True, f"S-3 forfeit expected ACCEPT: {res.get('reject-reason')!r} | {res}"
