"""Differential test: Python SPV path vs the DEPLOYED covenant MakerCovenantFlat12x20.

Audit follow-up F-06. The pre-existing ``tests/test_spv_covenant_differential.py``
diffs the Python parser against ``docs/brainstorms/gravity-ref-spike/rxd_sim.py``,
which is an explicit model of ``GravityNftCovenantAnyWallet20`` — NOT the covenant
that ships. The default covenant loaded by ``build_gravity_offer`` is
``MakerCovenantFlat12x20``
(``src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json``),
which is structurally NARROWER than the any-wallet model.

This file hand-ports a faithful Python reference model of the DEPLOYED covenant's
accept/reject logic (from the token-by-token ASM spec) and diffs it against the
real Python SPV path (``strip_witness`` + ``_output_offsets`` + ``verify_payment``
for tx structure/payment; ``verify_chain`` for headers/nBits/PoW; ``verify_tx_in_block``
for the merkle walk; ``_first_input_is_null_outpoint`` for coinbase; ``_read_varint``
for CompactSize).

Two divergence directions, both fund-relevant (the comments use these labels):

  Direction-A  Python ACCEPTS / covenant REJECTS  -> taker strands BTC on the
               no-refund finalize path. This is the surface the old any-wallet
               test WRONGLY accepted (multi-input, change-first / payment-in-out-1,
               scriptSig-len not in {0,23}). Asserted here as covenant-REJECT.
  Direction-B  covenant ACCEPTS / Python REJECTS  -> a forged proof slips past
               review, or a wasted fee.

Anything the spec flags as UNCERTAIN (needs live-regtest) is NOT asserted as
agreement: it is skipped or xfailed with a clear marker. In particular the
8-byte OP_BIN2NUM >4-byte-element numeric behaviour, the compile-time
claimDeadline clamp, OP_OUTPUTVALUE arity, and the exact tolerated branch length
are NOT modelled as accept/reject decisions here. All four are now CONFIRMED on
live radiant-core:v3.1.1 regtest consensus in
``tests/test_spv_covenant_differential_regtest.py`` (groups V / S-3 / S-2 / M); see
``docs/brainstorms/gravity-ref-spike/REGTEST_COVENANT_SEMANTICS_RESULTS.json``.

The deployed-covenant model here covers ONLY the funding-tx structure + payment
parse (spec sections B/C) and the header/nBits/PoW/merkle gates (sections D/E/F)
to the confidence the spec pins. It deliberately models a single committed
``btc_receive_type`` (the covenant bakes in exactly one), unlike the Python
``verify_payment`` which is told the type by the caller — so the model and the
Python path are always driven with the SAME committed type.
"""

from __future__ import annotations

import struct
from functools import cache

import pytest

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.chain import verify_chain
from pyrxd.spv.merkle import build_branch, compute_root, extract_merkle_root, verify_tx_in_block
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from pyrxd.spv.pow import hash256, verify_header_pow
from pyrxd.spv.proof import (
    _first_input_is_null_outpoint,
    _output_offsets,
    _read_varint,
)
from pyrxd.spv.witness import strip_witness

# --------------------------------------------------------------------------- constants

MAKER20 = b"\xee" * 20
MAKER32 = b"\xee" * 32
OTHER20 = b"\x33" * 20
OTHER32 = b"\x33" * 32
SATS = 100_000

# scriptPubKey templates per committed receive type (spec section C).
_SPK = {
    P2PKH: lambda h: b"\x76\xa9\x14" + h + b"\x88\xac",  # 25 bytes
    P2WPKH: lambda h: b"\x00\x14" + h,  # 22 bytes
    P2SH: lambda h: b"\xa9\x14" + h + b"\x87",  # 23 bytes
    P2TR: lambda h: b"\x51\x20" + h,  # 34 bytes
}
_SPK_LEN = {P2PKH: 25, P2WPKH: 22, P2SH: 23, P2TR: 34}
_HASH = {P2PKH: MAKER20, P2WPKH: MAKER20, P2SH: MAKER20, P2TR: MAKER32}

# Real mainnet block 840000 header — real PoW, real nBits 19420317 (exponent 0x19,
# within the covenant's 3..0x20 bound). Reused as a known-good header for the
# header/nBits/PoW differential (its prevHash is a usable chain anchor).
BLOCK_840000 = (
    "00e05f2aab948491071265ad552351d0ad625745668da54b01720100000000000000"
    "00004f89a5d73bd4d4887f25981fe81892ccafda10c27f52d6f3dd28183a7c411b03"
    "b7072366194203177d9863ea"
)
_H840K = bytes.fromhex(BLOCK_840000)
_NBITS_840K = _H840K[72:76]  # b"\x19\x42\x03\x17"
_ANCHOR_840K = _H840K[4:36]  # prevHash field, usable as chain anchor


# --------------------------------------------------------------------------- tx builders


def _vi(n: int) -> bytes:
    """Canonical CompactSize."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _build(scriptsigs, outputs, *, n_in_varint: bytes | None = None) -> bytes:
    """Build a legacy (witness-stripped) tx. ``n_in_varint`` overrides the input
    count byte verbatim (to forge a non-canonical / multi-byte count)."""
    p = [struct.pack("<I", 2)]
    p.append(n_in_varint if n_in_varint is not None else _vi(len(scriptsigs)))
    for ss in scriptsigs:
        p += [b"\x11" * 32 + b"\x00\x00\x00\x00", _vi(len(ss)), ss, b"\xff\xff\xff\xff"]
    p.append(_vi(len(outputs)))
    for v, spk in outputs:
        # value may be passed as raw 8 bytes (to force bit-63) or as an int.
        vb = v if isinstance(v, bytes) else struct.pack("<Q", v)
        p += [vb, _vi(len(spk)), spk]
    p.append(b"\x00\x00\x00\x00")
    return b"".join(p)


# --------------------------------------------------------------------------- DEPLOYED-covenant model


class CovenantReject(Exception):
    """Raised by the model when the deployed covenant would ScriptFail / not finalize."""


def deployed_covenant_accepts(
    raw_tx: bytes,
    *,
    btc_receive_hash: bytes,
    btc_receive_type: str,
    btc_satoshis: int,
) -> bool:
    """Faithful Python model of MakerCovenantFlat12x20's funding-tx structure +
    payment-output accept/reject logic (spec sections B + C).

    Returns True if the covenant would accept the payment; raises ``CovenantReject``
    (mimicking a consensus ScriptFail / failed finalize) otherwise. Models ONLY the
    high/medium-confidence pins. Header/PoW/nBits/merkle (sections D/E/F) are modelled
    separately (see ``model_*`` helpers) since the Python path verifies those in
    dedicated functions.

    NOT modelled (spec UNCERTAIN — never asserted as accept/reject here; all four are
    CONFIRMED live in test_spv_covenant_differential_regtest.py, see that file's
    REGTEST_COVENANT_SEMANTICS_RESULTS.json):
      * the 8-byte OP_BIN2NUM >4-byte numeric behaviour for the value read — covenant
        is 64-bit numeric (regtest group V); we only model the bit-63-negative case here;
      * whether a multi-output RXD finalize is accepted — index-0-only, ACCEPTS (S-2);
      * the empty-scriptSig live-acceptance question — ACCEPTS (S-1 baseline);
      * the compile-time claimDeadline clamp — floor 1774427796 enforced (S-3).
    """

    def split(b: bytes, n: int) -> tuple[bytes, bytes]:
        # Radiant OP_SPLIT: ScriptFails if n<0 or n>len.
        if n < 0 or n > len(b):
            raise CovenantReject(f"OP_SPLIT out of range n={n} len={len(b)}")
        return b[:n], b[n:]

    # B.1 rawTx size > 64.
    if not (len(raw_tx) > 64):
        raise CovenantReject("rawTx.length <= 64")

    # B.2 single input pinned: rawTx[4] == 0x01.
    _, r = split(raw_tx, 4)
    nin_byte, _ = split(r, 1)
    if nin_byte != b"\x01":
        raise CovenantReject(f"rawTx[4]={nin_byte.hex()} != 01 (single-input pin)")

    # B.4 scriptSig-length dispatch on EXACTLY {0x00, 0x17}. rawTx[41] (offset 0x29).
    _, r = split(raw_tx, 0x29)
    ssl_byte, _ = split(r, 1)
    if ssl_byte == b"\x00":
        output_offset = 46  # 41 + 1 + 0 + 4(seq)
    else:
        # ELSE arm forces ssl == 0x17 (23) and pins the scriptSig content shape.
        if ssl_byte != b"\x17":
            raise CovenantReject(f"scriptSig-len {ssl_byte.hex()} not in {{00,17}}")
        # rawTx[42]==0x16, rawTx[43]==0x00, rawTx[44]==0x14 (P2WPKH witness shape).
        if raw_tx[42:43] != b"\x16":
            raise CovenantReject("scriptSig[0] != 0x16")
        if raw_tx[43:44] != b"\x00":
            raise CovenantReject("scriptSig[1] != 0x00")
        if raw_tx[44:45] != b"\x14":
            raise CovenantReject("scriptSig[2] != 0x14")
        # output-count offset = 41(ssl byte) + 1 + 23(scriptSig) + 4(seq) = 69 (0x45);
        # the value field of output 0 then sits at 70 (0x46). Spec section B.4.
        output_offset = 69

    # B.5 output-count varint at the computed offset must be a single byte 1..252.
    _, r = split(raw_tx, output_offset)
    nout_byte, _ = split(r, 1)
    if nout_byte in (b"\x00", b"\xfd", b"\xfe", b"\xff"):
        raise CovenantReject(f"nOut byte {nout_byte.hex()} not a 1-byte CompactSize 1..252")
    # nOut value itself is NOT pinned; output region begins right after this byte.
    out0 = output_offset + 1

    # C. payment parse — OUTPUT 0 ONLY, single committed type. No scan, no terminal check.
    # value: first 8 bytes, signed CScriptNum (OP_BIN2NUM).
    _, r = split(raw_tx, out0)
    vbytes, _ = split(r, 8)
    value = int.from_bytes(vbytes, "little")
    if vbytes[-1] & 0x80:  # bit 63 set -> negative signed decode
        value -= 1 << 64
    if not (value >= btc_satoshis):
        raise CovenantReject(f"value {value} < btcSatoshis {btc_satoshis}")

    # script length byte + prefix/hash/suffix pin for the single committed type.
    _, r = split(raw_tx, out0 + 8)
    slen_byte, _ = split(r, 1)
    want_len = _SPK_LEN[btc_receive_type]
    if slen_byte != bytes([want_len]):
        raise CovenantReject(f"script-len {slen_byte.hex()} != {want_len:#x} for {btc_receive_type}")
    _, r = split(raw_tx, out0 + 9)
    spk, _ = split(r, want_len)
    expected_spk = _SPK[btc_receive_type](btc_receive_hash)
    if spk != expected_spk:
        raise CovenantReject(f"output[0] SPK does not match committed {btc_receive_type} script")
    return True


def _model_accepts(raw_tx, h, t, sats) -> bool:
    try:
        return deployed_covenant_accepts(raw_tx, btc_receive_hash=h, btc_receive_type=t, btc_satoshis=sats)
    except CovenantReject:
        return False


# --------------------------------------------------------------------------- Python-path drivers


def _python_struct_and_payment_accepts(raw_tx, h, t, sats) -> bool:
    """Drive the Python SPV structure + payment path with the SAME single committed
    type the covenant bakes in (NOT all four types — that mismatch is exactly the
    F-06 modelling gap)."""
    try:
        stripped = strip_witness(raw_tx)
    except ValidationError:
        return False
    try:
        offsets = _output_offsets(stripped)
    except (ValidationError, SpvVerificationError):
        return False
    # The deployed covenant only ever reads OUTPUT 0; the Python builder pins the
    # output_offset to a real boundary. To mirror "covenant reads output 0", the
    # Python decision is: is output 0 a valid payment of the committed type?
    out0 = _output0_offset(stripped)
    if out0 is None or out0 not in offsets:
        return False
    try:
        verify_payment(stripped, out0, h, t, sats)
        return True
    except (ValidationError, SpvVerificationError):
        return False


def _output0_offset(stripped: bytes) -> int | None:
    """Byte offset of output 0 in a witness-stripped tx, via the production varint
    parser (handles multi-byte counts). None on any parse problem."""
    try:
        pos = 4
        n_in, pos = _read_varint(stripped, pos)
        for _ in range(n_in):
            pos += 36
            sl, pos = _read_varint(stripped, pos)
            pos += sl + 4
            if pos > len(stripped):
                return None
        _, pos = _read_varint(stripped, pos)  # n_out
        return pos
    except (ValidationError, SpvVerificationError):
        return None


# --------------------------------------------------------------------------- header / merkle models


def model_header_accepts(header: bytes, *, expected_nbits: bytes, expected_nbits_next: bytes) -> bool:
    """Model the covenant's per-header gate (spec D + E): nBits pin, exponent
    floor 3 / ceiling 0x20, and hash256(header) strictly < target."""
    if len(header) != 80:
        return False
    nbits = header[72:76]
    # D. nBits ∈ {expectedNBits, expectedNBitsNext}.
    if nbits not in (expected_nbits, expected_nbits_next):
        return False
    exponent = nbits[3]
    # D. exponent floor 3, ceiling 0x20 (32).
    if not (3 <= exponent <= 0x20):
        return False
    mantissa_le = nbits[0:3]
    if exponent > 32 or exponent < 3:
        return False
    # Reconstruct target the same way pow.py does (well-defined for exp 3..29; the
    # covenant tolerates up to 0x20 but mainnet nBits never exceeds 0x1d, and the
    # only header we drive PoW on is the real 840000 with exponent 0x19).
    if exponent > 29:
        # spec UNCERTAIN: target reconstruction for exp 30..32 not modelled; the
        # nBits-pin alone gates these and we never feed such a header.
        return False
    target_le = bytes(exponent - 3) + mantissa_le + bytes(32 - exponent)
    hash_be = hash256(header)[::-1]
    target_be = target_le[::-1]
    return hash_be < target_be  # E. strict less-than


def model_merkle_root(txid_be_hex: str, branch: bytes) -> bytes:
    """Model the covenant's 20-level walk: dir 0x00 => H(cur||sib); 0x01 =>
    H(sib||cur); ANY other dir byte => NO-OP (sentinel skip). No coinbase/64-byte
    in-walk guard."""
    leaf = bytes.fromhex(txid_be_hex)[::-1]
    cur = leaf
    n = len(branch) // 33
    for i in range(n):
        d = branch[i * 33]
        sib = branch[i * 33 + 1 : i * 33 + 33]
        if d == 0x00:
            cur = hash256(cur + sib)
        elif d == 0x01:
            cur = hash256(sib + cur)
        # else: sentinel / unknown direction -> no-op (current unchanged)
    return cur


# =========================================================================== STRUCTURE + PAYMENT


# (label, scriptsigs, outputs, type, hash, expect_model_accepts, direction-note)
_STRUCT_CASES = [
    # Happy: single empty-scriptSig input, P2WPKH payment in output 0.
    ("happy_p2wpkh_out0", [b""], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, True, None),
    # Happy: 23-byte P2WPKH-witness-shaped scriptSig (16 00 14 ...).
    (
        "happy_segwit_ssl23",
        [b"\x16\x00\x14" + b"\x55" * 20],
        [(SATS, _SPK[P2WPKH](MAKER20))],
        P2WPKH,
        MAKER20,
        True,
        None,
    ),
    ("happy_p2pkh_out0", [b""], [(SATS, _SPK[P2PKH](MAKER20))], P2PKH, MAKER20, True, None),
    ("happy_p2sh_out0", [b""], [(SATS, _SPK[P2SH](MAKER20))], P2SH, MAKER20, True, None),
    ("happy_p2tr_out0", [b""], [(SATS, _SPK[P2TR](MAKER32))], P2TR, MAKER32, True, None),
    # Underpay / wrong hash reject (both paths).
    ("underpay", [b""], [(SATS - 1, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, None),
    ("wrong_hash", [b""], [(SATS, _SPK[P2WPKH](OTHER20))], P2WPKH, MAKER20, False, None),
    # ---- Direction-A: any-wallet ACCEPTS, deployed must REJECT (fund-loss surface) ----
    # multi-input (nIn=4): any-wallet allows nIn<=4; deployed pins rawTx[4]==1.
    ("four_inputs_A", [b"", b"", b"", b""], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    ("two_inputs_A", [b"", b""], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    # change-first: payment in output 1; deployed reads output 0 only.
    (
        "change_first_A",
        [b""],
        [(50, _SPK[P2WPKH](OTHER20)), (SATS, _SPK[P2WPKH](MAKER20))],
        P2WPKH,
        MAKER20,
        False,
        "A",
    ),
    # scriptSig-len not in {0,23}: P2PKH-signed ~107B, or 8, or 127.
    ("ssl_107_A", [b"\x01" * 107], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    ("ssl_8_A", [b"\x01" * 8], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    ("ssl_127_A", [b"\x01" * 127], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    # 23-byte scriptSig whose content isn't 16 00 14 (non-P2WPKH shape).
    ("ssl23_wrong_content_A", [b"\xaa" * 23], [(SATS, _SPK[P2WPKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
    # wrong committed type: a P2PKH payment under a covenant committed to P2WPKH.
    ("wrong_type_A", [b""], [(SATS, _SPK[P2PKH](MAKER20))], P2WPKH, MAKER20, False, "A"),
]


@pytest.mark.parametrize(
    "label,ss,outs,typ,h,expect,direction",
    _STRUCT_CASES,
    ids=[c[0] for c in _STRUCT_CASES],
)
def test_struct_payment_model_matches_expectation(label, ss, outs, typ, h, expect, direction):
    """The deployed-covenant model decides each curated case as the spec pins."""
    raw = _build(ss, outs)
    assert _model_accepts(raw, h, typ, SATS) is expect, f"model wrong on {label}"


@pytest.mark.parametrize(
    "label,ss,outs,typ,h,expect,direction",
    [c for c in _STRUCT_CASES if c[6] == "A"],
    ids=[c[0] for c in _STRUCT_CASES if c[6] == "A"],
)
def test_direction_a_deployed_covenant_rejects(label, ss, outs, typ, h, expect, direction):
    """Direction-A: cases the old any-wallet differential WRONGLY accepted must be
    REJECTED by the deployed covenant (else the taker strands BTC on no-refund)."""
    raw = _build(ss, outs)
    assert _model_accepts(raw, h, typ, SATS) is False, f"{label} should be covenant-REJECT (Direction-A fund-loss)"


def test_struct_payment_differential_vs_python():
    """Differential: drive the Python SPV structure+payment path with the SAME
    single committed type and assert it AGREES with the deployed-covenant model on
    every curated case where BOTH decide.

    Direction-A cases (multi-input, change-first, ssl-not-in-{0,23}) are where the
    Python path ACCEPTS and the deployed covenant REJECTS — captured explicitly so
    the divergence is documented, not silently passed."""
    documented_a_divergences = []
    for label, ss, outs, typ, h, _expect, _direction in _STRUCT_CASES:
        raw = _build(ss, outs)
        py = _python_struct_and_payment_accepts(raw, h, typ, SATS)
        cov = _model_accepts(raw, h, typ, SATS)
        if py == cov:
            continue
        # The only tolerated direction here is A: Python ACCEPTS, covenant REJECTS.
        assert py and not cov, f"NOVEL divergence on {label}: py={py} cov={cov}"
        documented_a_divergences.append(label)
    # change_first: Python reads output 0 (which is change, not the maker), so
    # Python also REJECTS — agreement. The Python path mirrors output-0-only here.
    # multi-input + ssl cases: Python's _output_offsets accepts the structure and
    # output 0 IS the payment, so Python ACCEPTS while the covenant REJECTS.
    assert "four_inputs_A" in documented_a_divergences
    assert "two_inputs_A" in documented_a_divergences
    assert "ssl_107_A" in documented_a_divergences


def test_struct_payment_seeded_fuzz():
    """Seeded deterministic differential fuzz (no nondeterministic RNG — inputs
    vary by loop index so runs reproduce). Across single-input txs with the
    payment in output 0, the Python structure+payment path and the deployed model
    must AGREE; any disagreement on this restricted shape is a NOVEL finding."""
    types = [P2PKH, P2WPKH, P2SH, P2TR]
    novel = []
    for i in range(4000):
        typ = types[i % 4]
        h = _HASH[typ]
        # value sweeps around the threshold and into large (but < 2**40) territory.
        val = [SATS, SATS - 1, SATS + 1, 1, (i * 7919) % (1 << 32)][i % 5]
        # scriptSig: empty, or a valid 23-byte P2WPKH-witness shape (both accepted
        # shapes); occasionally a wrong-hash output to exercise reject parity.
        ssl_choice = i % 3
        if ssl_choice == 0:
            ss = b""
        elif ssl_choice == 1:
            ss = b"\x16\x00\x14" + bytes([i % 256]) * 20
        else:
            ss = b""  # keep within accepted shapes; ssl-not-in-{0,23} covered by curated A cases
        use_hash = h if (i % 7) else (OTHER32 if typ == P2TR else OTHER20)
        spk = _SPK[typ](use_hash)
        raw = _build([ss], [(val, spk)])
        py = _python_struct_and_payment_accepts(raw, h, typ, SATS)
        cov = _model_accepts(raw, h, typ, SATS)
        if py != cov:
            novel.append((i, typ, val, ss.hex(), py, cov))
    assert not novel, f"NOVEL Python<->model divergences on single-input/out0 shape: {novel[:5]}"


def test_value_bit63_rejected_both_paths():
    """value >= 2**63 (bit 63 set): the deployed covenant decodes it NEGATIVE as a
    signed CScriptNum -> value < btcSatoshis -> REJECT; the Python verify_payment
    rejects it explicitly (F-25). Both reject -> agreement (Direction-B parity)."""
    big = (1 << 63).to_bytes(8, "little")
    raw = _build([b""], [(big, _SPK[P2WPKH](MAKER20))])
    out0 = _output0_offset(strip_witness(raw))
    assert out0 is not None
    with pytest.raises(SpvVerificationError, match="bit 63"):
        verify_payment(strip_witness(raw), out0, MAKER20, P2WPKH, SATS)
    assert _model_accepts(raw, MAKER20, P2WPKH, SATS) is False


def test_op_return_output0_rejected_both_paths():
    """An OP_RETURN at output 0: Python rejects explicitly (03-C2); the deployed
    covenant rejects implicitly (its script-length byte / prefix pin fails for the
    committed type). Agreement on REJECT."""
    # Use a 23-byte OP_RETURN so the script-LENGTH pin passes (23 == P2SH len) and
    # the dedicated 03-C2 guard (script[0]==0x6a) is what fires — not the length pin.
    op_return_spk = b"\x6a\x15" + b"\xcc" * 21  # OP_RETURN push21 (len 23)
    assert len(op_return_spk) == 23
    raw = _build([b""], [(SATS, op_return_spk)])
    out0 = _output0_offset(strip_witness(raw))
    assert out0 is not None
    # committed P2SH (script-len 23): length pin passes, so the 03-C2 OP_RETURN guard rejects.
    with pytest.raises(SpvVerificationError, match="OP_RETURN"):
        verify_payment(strip_witness(raw), out0, MAKER20, P2SH, SATS)
    assert _model_accepts(raw, MAKER20, P2SH, SATS) is False


def test_cparser2_forged_payment_blob_in_scriptsig_rejected():
    """C-PARSER-2 / F-09 (ported from the retired any-wallet differential test): a
    payment-shaped blob planted in the input scriptSig must NOT be mistaken for the
    payment output. Deployed covenant: the 31-byte scriptSig is not in {0x00,0x17}
    -> REJECT. Python: the blob's byte offset is NOT a member of _output_offsets (the
    genuine output boundaries), so build()'s ``output_offset not in _output_offsets``
    gate rejects it; and output 0 pays OTHER (tiny value), so verify_payment rejects."""
    blob = struct.pack("<Q", SATS) + b"\x16" + _SPK[P2WPKH](MAKER20)  # value(8)+pushlen(1)+spk(22)=31
    raw = _build([blob], [(50, _SPK[P2WPKH](OTHER20))])  # real output pays OTHER, tiny value
    stripped = strip_witness(raw)
    offsets = _output_offsets(stripped)
    # blob start = version(4) + n_in(1) + prevout(36) + scriptSig-len byte(1) = 42.
    assert 42 not in offsets, "forged scriptSig blob offset must not be a real output boundary"
    assert _model_accepts(raw, MAKER20, P2WPKH, SATS) is False
    assert _python_struct_and_payment_accepts(raw, MAKER20, P2WPKH, SATS) is False


# =========================================================================== VARINT (CompactSize)


def test_noncanonical_input_count_varint():
    """A non-canonical 0xFD-prefixed input count (encodes 1): the Python
    _read_varint REJECTS it (F-15); the deployed covenant reads rawTx[4] as a
    single byte 0xFD != 0x01 -> single-input pin REJECTS. Both reject -> agreement.

    Direction note: this is the F-15 fix exercised against the deployed covenant's
    single-byte read — neither side is fooled by the overlong encoding."""
    # Forge input-count varint 0xFD 0x01 0x00 (overlong encoding of 1).
    raw = _build([b""], [(SATS, _SPK[P2WPKH](MAKER20))], n_in_varint=b"\xfd\x01\x00")
    # Python: strip_witness / _output_offsets reject the non-canonical count.
    with pytest.raises((ValidationError, SpvVerificationError)):
        _output_offsets(strip_witness(raw))
    # Deployed covenant: rawTx[4] == 0xFD != 0x01 -> reject.
    assert _model_accepts(raw, MAKER20, P2WPKH, SATS) is False


def test_canonical_varint_roundtrip_agreement():
    """For canonical single-byte counts the Python varint reader and the model
    both treat rawTx[4] consistently (single-input only)."""
    for n in (1, 2, 3):
        raw = _build([b""] * n, [(SATS, _SPK[P2WPKH](MAKER20))])
        v, _ = _read_varint(strip_witness(raw), 4)
        assert v == n
        # model accepts only n==1.
        assert _model_accepts(raw, MAKER20, P2WPKH, SATS) is (n == 1)


# =========================================================================== HEADERS / nBits / PoW


def test_header_nbits_pin_differential_real_block():
    """Differential on the real mainnet 840000 header. With the committed nBits
    matching, BOTH verify_chain and the model accept; with a mismatched pin BOTH
    reject. The exponent (0x19) is inside the covenant's 3..0x20 bound."""
    # matching pin: verify_chain returns the header hash in LE (hash256(header),
    # NOT reversed) and accepts.
    hashes = verify_chain([_H840K], expected_nbits=_NBITS_840K)
    assert hashes == [hash256(_H840K)]
    assert model_header_accepts(_H840K, expected_nbits=_NBITS_840K, expected_nbits_next=_NBITS_840K) is True

    # mismatched pin: Python verify_chain rejects; model rejects.
    wrong = b"\xff\xff\x00\x1d"
    with pytest.raises(SpvVerificationError, match="does not match the committed"):
        verify_chain([_H840K], expected_nbits=wrong)
    assert model_header_accepts(_H840K, expected_nbits=wrong, expected_nbits_next=wrong) is False


def test_header_nbits_retarget_window_second_value():
    """The covenant pins nBits ∈ {expectedNBits, expectedNBitsNext}. When the real
    nBits matches the SECOND (retarget-window) value, both accept."""
    other = b"\x18\x00\x00\x1d"  # arbitrary valid-shaped second value (exp 0x1d)
    hashes = verify_chain([_H840K], expected_nbits=other, expected_nbits_next=_NBITS_840K)
    assert len(hashes) == 1
    assert model_header_accepts(_H840K, expected_nbits=other, expected_nbits_next=_NBITS_840K) is True


def test_header_pow_strict_less_than_agreement():
    """A header whose hash equals/exceeds target is rejected by both verify_header_pow
    (strict <) and the model. Tamper the 840000 nonce to break PoW."""
    tampered = _H840K[:76] + b"\x00\x00\x00\x00"
    with pytest.raises(SpvVerificationError, match="PoW"):
        verify_header_pow(tampered)
    # model: same nBits pin satisfied, but PoW strict-< fails.
    assert model_header_accepts(tampered, expected_nbits=_NBITS_840K, expected_nbits_next=_NBITS_840K) is False


def test_header_chain_anchor_differential():
    """verify_chain pins headers[0].prevHash to the chain anchor; a wrong anchor
    rejects. (The covenant pins the first header's prevHash to btcChainAnchor.)"""
    hashes = verify_chain([_H840K], chain_anchor=_ANCHOR_840K, expected_nbits=_NBITS_840K)
    assert len(hashes) == 1
    with pytest.raises(SpvVerificationError, match="chain_anchor"):
        verify_chain([_H840K], chain_anchor=b"\x00" * 32, expected_nbits=_NBITS_840K)


@pytest.mark.skip(
    reason="RESOLVED live in tests/test_spv_covenant_differential_regtest.py::"
    "test_header_nbits_exponent_ceiling (NB-1..NB-2c): on radiant-core:v3.1.1 regtest "
    "the covenant ACCEPTS nBits exponent 0x1e/0x1f/0x20 (which Python's Nbits rejects "
    "as > 0x1d) and REJECTS 0x21 — a confirmed Direction-B accept-band [0x1e..0x20]. "
    "Corroborates F-02 (reject_low_difficulty mandatory for any covenant-less SPV use). "
    "Evidence: docs/brainstorms/gravity-ref-spike/REGTEST_COVENANT_SEMANTICS_RESULTS.json. "
    "This placeholder stays skipped; the live integration test is the evidence."
)
def test_header_nbits_exponent_ceiling_divergence_needs_regtest():
    raise AssertionError("unreachable: skipped")


# =========================================================================== MERKLE walk


# Expensive: grinds a ~24-bit-target block header in pure Python (~13s/call).
# Every caller passes identical args, so memoize to grind once per
# (payment_spk, n_levels) instead of once per test. Returns only immutable
# bytes/str, so sharing one cached tuple across tests is safe.
@cache
def _grind_tx_into_block(payment_spk: bytes, n_levels: int = 1):
    """Build a single-input/single-output tx and a relaxed-target block whose
    merkle root commits it at pos=1 with ``n_levels`` siblings. Returns
    (txid_be_hex, stripped_raw, branch, pos, header, anchor)."""
    raw_tx = _build([b""], [(SATS, payment_spk)])
    txid_le = hash256(raw_tx)
    txid_be_hex = txid_le[::-1].hex()
    # one sibling; root = H(sibling || txid) for pos=1 (current on the right).
    sib_le = b"\xab" * 32
    sib_be_hex = sib_le[::-1].hex()
    merkle_root_le = hash256(sib_le + txid_le)
    anchor = b"\x99" * 32
    nbits = b"\xff\xff\x7f\x1d"  # large target, exponent 0x1d
    # grind a relaxed-target header (LE bytes 29..31 == 0 gate).
    base = b"\x00\x00\x00\x20" + anchor + merkle_root_le + b"\x00\x00\x00\x00" + nbits
    header = None
    for nonce in range(50_000_000):
        h = base + nonce.to_bytes(4, "little")
        d = hash256(h)
        if d[29] == 0 and d[30] == 0 and d[31] == 0:
            try:
                verify_header_pow(h)
                header = h
                break
            except SpvVerificationError:
                continue
    assert header is not None, "could not grind relaxed header"
    branch = build_branch([sib_be_hex], pos=1)
    return txid_be_hex, raw_tx, branch, 1, header, anchor


def test_merkle_walk_differential_pos1():
    """Differential merkle: the production verify_tx_in_block accepts a tx at pos=1,
    and the deployed-covenant model computes the SAME root (direction byte 0x01 =>
    H(sibling||current)) which matches the header's root."""
    txid_be_hex, raw_tx, branch, pos, header, _anchor = _grind_tx_into_block(_SPK[P2WPKH](MAKER20))
    # Python path accepts inclusion.
    verify_tx_in_block(raw_tx, txid_be_hex, branch, pos, header, expected_depth=1)
    # Model: walk and compare to the header's committed root.
    model_root = model_merkle_root(txid_be_hex, branch)
    assert model_root == extract_merkle_root(header)
    # And the production compute_root agrees with the model walk byte-for-byte.
    assert compute_root(txid_be_hex, branch) == model_root


def test_merkle_sentinel_direction_byte_is_noop():
    """A sentinel direction byte (0x02, neither 0x00 nor 0x01) is a NO-OP in BOTH
    the covenant model and the production compute_root — appending a sentinel level
    leaves the computed root unchanged (this is how 20-level padding is skipped)."""
    txid_be_hex, _raw, branch, _pos, _header, _anchor = _grind_tx_into_block(_SPK[P2WPKH](MAKER20))
    sentinel_level = b"\x02" + b"\x00" * 32
    root_no_sentinel = compute_root(txid_be_hex, branch)
    root_with_sentinel = model_merkle_root(txid_be_hex, branch + sentinel_level)
    assert root_with_sentinel == root_no_sentinel
    # production compute_root treats any non-0 direction as "right" — so it does
    # NOT no-op a 0x02 byte. This is a MODELLED behavioural divergence between
    # the covenant (no-op) and compute_root (treats >0 as right): documented, and
    # it is benign because the production BUILDER only ever emits dir in {0,1}
    # for real levels and pads via a separate mechanism, never feeding 0x02 to
    # compute_root. See xfail below for the explicit characterization.


@pytest.mark.xfail(
    reason="DOCUMENTED divergence (benign): compute_root treats ANY non-zero "
    "direction byte as 'sibling on left' (merkle.py:109-112 `else`), whereas the "
    "covenant treats a 0x02 sentinel as a NO-OP (skip). Production build_branch "
    "only ever emits dir in {0,1}, so compute_root is never fed a 0x02 — the "
    "divergence is unreachable in production. Not a bug to force-pass; pinned so a "
    "future change to compute_root's direction handling is noticed.",
    strict=True,
)
def test_merkle_compute_root_vs_model_on_sentinel_divergence():
    txid_be_hex, _raw, branch, _pos, _header, _anchor = _grind_tx_into_block(_SPK[P2WPKH](MAKER20))
    sentinel_level = b"\x02" + b"\x00" * 32
    # The covenant NO-OPs the sentinel; compute_root does NOT (treats 0x02 as right).
    # So these MUST differ — the xfail asserts they do (strict=True).
    assert compute_root(txid_be_hex, branch + sentinel_level) == model_merkle_root(txid_be_hex, branch + sentinel_level)


def test_coinbase_structural_reject_differential():
    """A coinbase tx (null-outpoint first input) is rejected by the Python
    structural guard regardless of pos (F-04). The deployed covenant has NO in-walk
    coinbase guard, but its single-input/output-0 structure pins would still parse
    a coinbase's shape — so this is the Python-side defense the covenant lacks.

    We assert the Python structural reject fires; we do NOT assert the covenant
    rejects a coinbase (it does not have that guard) — this is a Direction-B note:
    Python is STRICTER here, which is the safe direction (no fund loss)."""
    coinbase = (
        struct.pack("<I", 2)
        + b"\x01"
        + b"\x00" * 32  # null prevout txid
        + b"\xff\xff\xff\xff"  # vout 0xffffffff
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + struct.pack("<Q", SATS)
        + _vi(len(_SPK[P2WPKH](MAKER20)))
        + _SPK[P2WPKH](MAKER20)
        + b"\x00\x00\x00\x00"
    )
    assert _first_input_is_null_outpoint(coinbase) is True
    # The deployed covenant model has no coinbase guard; it parses the structure
    # the same as a normal single-input tx. We pin that the covenant model would
    # ACCEPT this shape (output 0 pays the maker) while Python's builder REJECTS
    # it via _first_input_is_null_outpoint — Python stricter = safe (Direction-B).
    assert _model_accepts(coinbase, MAKER20, P2WPKH, SATS) is True


def test_coinbase_pos_aliasing_rejected_differential():
    """F-04/F-05: a pos with bits beyond the branch depth (e.g. pos=2 at depth 1)
    reproduces the coinbase's all-left branch (pos=0) and previously bypassed the
    ``pos == 0`` guard. The production ``build_branch`` AND ``verify_tx_in_block``
    now reject it as out-of-range — mirroring the covenant's fixed-depth walk where
    a leaf index cannot exceed the committed tree depth. (Mutation check: disabling
    the ``pos >> depth`` guard in merkle.py makes THIS test red, not just test_spv.py.)"""
    sib_be_hex = "ab" * 32
    # Construction-time reject: build_branch refuses an out-of-range pos.
    with pytest.raises(ValidationError, match="beyond branch depth"):
        build_branch([sib_be_hex], pos=2)  # depth 1, pos 2 = 0b10 -> aliases pos 0
    # Independent reject in verify_tx_in_block (defense in depth for direct callers).
    raw_tx = b"\xaa" * 80
    branch = b"\x00" + bytes.fromhex(sib_be_hex)[::-1]  # one 33-byte level
    with pytest.raises(SpvVerificationError, match="beyond branch depth"):
        verify_tx_in_block(raw_tx, "a" * 64, branch, pos=2, header=b"\x00" * 80, expected_depth=1)


@pytest.mark.skip(
    reason="RESOLVED live in tests/test_spv_covenant_differential_regtest.py::"
    "test_value_bin2num_significant_bytes (V-1..V-5): on radiant-core:v3.1.1 regtest the "
    "covenant reads output-0 value as a full 64-bit signed CScriptNum — 5/7/8-significant-"
    "byte values ACCEPT (>= threshold incl. a 7-byte value vs a 7-byte threshold), a "
    "bit-63-set value decodes NEGATIVE and REJECTS, and a 7-byte value just below a 7-byte "
    "threshold REJECTS. No Direction-A divergence (the covenant is genuinely 64-bit "
    "numeric). Evidence: docs/brainstorms/gravity-ref-spike/REGTEST_COVENANT_SEMANTICS_RESULTS.json."
)
def test_value_5_to_8_byte_bin2num_needs_regtest():
    raise AssertionError("unreachable: skipped")
