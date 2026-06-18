"""Golden-vector + guard tests for the productized Radiant HTLC covenant builders.

The builders reproduce the EXACT holder scripts that were accepted on Radiant MAINNET
during the spike (recorded in ``docs/brainstorms/gravity-ref-spike/.live_swap_{nft,ft}.json``).
NOTE (v2): the OP_SIZE<0x20> preimage-length pin (security review: preimage-length asset
theft) intentionally SUPERSEDES the v1 mainnet covenant *scriptPubKey*, so the full SPK no
longer reproduces v1 byte-for-byte — the holder scripts (unchanged by the pin) still do, and
every claim branch now carries the 32-byte pin. v2 consensus validity is proven by the regtest
spend/reject test (live node).

The remaining tests pin the two static guards (bare-0xbd opcode walk + ref count)
and the fail-closed parameter validation — the covenant moves real value, so every
uncertain input must raise, never silently mis-bind.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from pyrxd.gravity.htlc_covenant import (
    FT_EPILOGUE,
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

_SPIKE = Path(__file__).resolve().parent.parent / "docs" / "brainstorms" / "gravity-ref-spike"


def _pkh(wif: str) -> bytes:
    return bytes(Hex20(PrivateKey(wif).public_key().hash160()))


def _load_vector(name: str) -> dict:
    path = _SPIKE / name
    if not path.exists():
        pytest.skip(f"mainnet golden vector {name} not present")
    return json.loads(path.read_text())


# --------------------------------------------------------------------------- golden vectors


def test_nft_covenant_v2_pins_preimage_length_holder_unchanged():
    """v2 preimage-length pin (security review: preimage-length asset theft). The OP_SIZE<0x20>
    check on the claim branch intentionally SUPERSEDES the v1 mainnet covenant SPK, so the full
    scriptPubKey no longer reproduces v1 byte-for-byte (the v1 swap stays recorded in
    .live_swap_nft.json as history; v2 consensus validity is proven by the regtest spend/reject
    test). The HOLDER scripts (P2PKH of the pkhs) are untouched by v2, so they still reproduce
    the mainnet-proven holders byte-for-byte."""
    v = _load_vector(".live_swap_nft.json")
    txid, vout = v["nft_genesis"].split(":")
    cov = build_htlc_covenant_nft(
        genesis_txid=txid,
        genesis_vout=int(vout),
        nft_carrier_value=v["nft_carrier"],
        taker_pkh=_pkh(v["nft_claim_taker_wif"]),
        maker_pkh=_pkh(v["nft_owner_wif"]),
        hashlock=bytes.fromhex(v["hashlock"]),
        refund_csv=v["btc_refund_csv_blocks"],
    )
    assert b"\x82\x01\x20\x88\xa8" in cov.funded_spk, (
        "claim branch must pin p to 32 bytes (OP_SIZE<0x20>OP_EQUALVERIFY OP_SHA256)"
    )
    assert cov.funded_spk.hex() != v["nft_covenant_spk_hex"], "v1 mainnet SPK is intentionally superseded by the pin"
    assert cov.taker_holder_script.hex() == v["nft_taker_holder_script"]  # holder unchanged (mainnet-proven)
    assert cov.variant == "nft"
    assert cov.genesis_ref  # non-empty


def test_ft_covenant_v2_pins_preimage_length_holder_unchanged():
    """v2 preimage-length pin (see the NFT test). v1 covenant SPK superseded; holder + the
    FT epilogue weld + the sole bare-0xbd at prologue_len are structurally preserved."""
    v = _load_vector(".live_swap_ft.json")
    txid, vout = v["ft_genesis"].split(":")
    cov = build_htlc_covenant_ft(
        genesis_txid=txid,
        genesis_vout=int(vout),
        amount=v["ft_source_carrier_rxd"],
        taker_pkh=_pkh(v["ft_claim_taker_wif"]),
        maker_pkh=_pkh(v["ft_owner_wif"]),
        hashlock=bytes.fromhex(v["hashlock"]),
        refund_csv=v["btc_refund_csv_blocks"],
    )
    assert b"\x82\x01\x20\x88\xa8" in cov.funded_spk, "claim branch must pin p to 32 bytes (OP_SIZE)"
    assert cov.funded_spk.hex() != v["ft_covenant_spk_hex"], "v1 mainnet SPK is intentionally superseded by the pin"
    assert cov.taker_holder_script.hex() == v["ft_taker_holder_script"]  # holder unchanged (mainnet-proven)
    # FT funded SPK ends with the epilogue weld; the sole bare-0xbd is at prologue_len.
    assert cov.funded_spk.endswith(FT_EPILOGUE)
    assert cov.funded_spk[cov.prologue_len] == 0xBD


def test_all_three_covenant_variants_pin_preimage_to_32_bytes():
    """Regression (security review: preimage-length asset theft): EVERY HTLC covenant variant's
    claim branch must consensus-pin p to exactly 32 bytes via OP_SIZE<0x20>OP_EQUALVERIFY
    immediately before the preimage OP_SHA256 (fragment 82 0120 88 a8), so a malicious maker
    cannot reveal a non-32-byte p' that the 32-byte-only scrape_secret silently skips. CI-safe
    (synthetic inputs, no private vectors). Full consensus rejection of a non-32-byte spend is
    proven by the regtest spend/reject test (live radiant-core node)."""
    h = hashlib.sha256(b"p" * 32).digest()
    tp, mp, gt = bytes(range(20)), bytes([0x22] * 20), "ab" * 32
    pin = b"\x82\x01\x20\x88\xa8"  # OP_SIZE  push(0x20)  OP_EQUALVERIFY  OP_SHA256
    covs = {
        "rxd": build_htlc_covenant_rxd(amount=1000, taker_pkh=tp, maker_pkh=mp, hashlock=h, refund_csv=48),
        "ft": build_htlc_covenant_ft(
            genesis_txid=gt, genesis_vout=0, amount=1000, taker_pkh=tp, maker_pkh=mp, hashlock=h, refund_csv=48
        ),
        "nft": build_htlc_covenant_nft(
            genesis_txid=gt,
            genesis_vout=0,
            nft_carrier_value=1000,
            taker_pkh=tp,
            maker_pkh=mp,
            hashlock=h,
            refund_csv=48,
        ),
    }
    for name, cov in covs.items():
        assert pin in cov.funded_spk, f"{name}: claim branch missing the 32-byte preimage pin (theft regression)"
        # the pin sits in the CLAIM branch, before that branch's hashlock check (OP_SHA256 <H>).
        assert cov.funded_spk.index(pin) < cov.funded_spk.index(h), f"{name}: pin not before the claim hashlock"


# --------------------------------------------------------------------------- RXD (no mainnet golden)


def _rxd_args(**over):
    base = dict(
        amount=1_000,
        taker_pkh=b"\x11" * 20,
        maker_pkh=b"\x22" * 20,
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        refund_csv=6,
    )
    base.update(over)
    return base


def test_rxd_builds_and_passes_guards():
    cov = build_htlc_covenant_rxd(**_rxd_args())
    assert isinstance(cov, HtlcCovenant)
    assert cov.variant == "rxd"
    assert cov.genesis_ref == b""  # native RXD carries no ref
    # 25-byte P2PKH holder, no ref/weld.
    assert cov.taker_holder_script == b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
    assert cov.expected_taker_hash == hashlib.sha256(hashlib.sha256(cov.taker_holder_script).digest()).digest()


def test_rxd_is_deterministic():
    args = _rxd_args(hashlock=b"\xab" * 32)
    assert build_htlc_covenant_rxd(**args).funded_spk == build_htlc_covenant_rxd(**args).funded_spk


# --------------------------------------------------------------------------- refundCsv MINIMALDATA


def test_refund_csv_minimal_push_for_small_ints():
    # 1..16 must be OP_N (single byte 0x51..0x60), NOT a length-prefixed push.
    from pyrxd.gravity.htlc_covenant import _minimal_num_push

    assert _minimal_num_push(1) == b"\x51"
    assert _minimal_num_push(6) == b"\x56"
    assert _minimal_num_push(16) == b"\x60"
    assert _minimal_num_push(0) == b"\x00"
    # 17+ falls back to a length-prefixed scriptnum push.
    assert _minimal_num_push(17) == b"\x01\x11"


# --------------------------------------------------------------------------- F-001: value-param MINIMALDATA


_FT_NFT_BASE = dict(
    genesis_txid="ab" * 32,
    genesis_vout=0,
    taker_pkh=b"\x11" * 20,
    maker_pkh=b"\x22" * 20,
    hashlock=b"\xaa" * 32,
    refund_csv=6,
)


@pytest.mark.parametrize("value", [1, 5, 16, 17, 1000])
def test_value_param_minimal_push_builds_for_all_variants_f001(value):
    """F-001 regression: an asset value in 1..16 must build (GUARD 3 accepts it),
    proving OP_N minimal encoding — NOT the non-minimal 1-byte data push that trips
    MANDATORY MINIMALDATA and bricks the covenant on BOTH the claim and refund
    branches. Pre-fix the value param used ``_push(_scriptnum(v))``, which for v in
    1..16 produced e.g. ``0105`` instead of ``OP_5``. Boundary 17 + 1000 confirm the
    >16 path is unchanged.
    """
    build_htlc_covenant_rxd(**_rxd_args(amount=value))
    build_htlc_covenant_ft(amount=value, **_FT_NFT_BASE)
    build_htlc_covenant_nft(nft_carrier_value=value, **_FT_NFT_BASE)


def test_value_param_emits_op_n_not_non_minimal_push_f001():
    """The funded SPK for a small value carries the OP_N opcode and NOT the bricking
    non-minimal 1-byte push form. Fixed (no-0x01-byte) hashlock/pkhs keep the byte
    search free of false positives."""
    cov = build_htlc_covenant_rxd(
        amount=5, taker_pkh=b"\x22" * 20, maker_pkh=b"\x33" * 20, hashlock=b"\xaa" * 32, refund_csv=6
    )
    assert b"\x55" in cov.funded_spk  # OP_5
    assert b"\x01\x05" not in cov.funded_spk  # the F-001 brick (push 1 byte 0x05)
    # >16 is byte-identical to the prior encoder (preserves mainnet golden vectors).
    from pyrxd.gravity.htlc_covenant import _push, _scriptnum

    cov17 = build_htlc_covenant_rxd(
        amount=17, taker_pkh=b"\x22" * 20, maker_pkh=b"\x33" * 20, hashlock=b"\xaa" * 32, refund_csv=6
    )
    assert _push(_scriptnum(17)) in cov17.funded_spk


def test_assert_minimal_pushes_guard_matches_checkminimalpush():
    """GUARD 3 mirrors Radiant-Core CheckMinimalPush: accept minimal forms, reject
    every non-minimal push class (the layer that would have caught F-001 at build
    time even if the encoder regressed)."""
    from pyrxd.gravity.htlc_covenant import _assert_minimal_pushes

    # minimal forms pass
    _assert_minimal_pushes(b"\x55", variant="t")  # OP_5
    _assert_minimal_pushes(b"\x60\x00", variant="t")  # OP_16, OP_0
    _assert_minimal_pushes(b"\x20" + b"\xaa" * 32, variant="t")  # 32-byte direct push
    _assert_minimal_pushes(b"\x01\x00", variant="t")  # 1-byte 0x00 IS minimal (data, not OP_0)
    _assert_minimal_pushes(b"\xd8" + b"\x05" * 36, variant="t")  # ref operand skipped, not parsed as pushes
    _assert_minimal_pushes(b"\x4c\x50" + b"\xbb" * 80, variant="t")  # PUSHDATA1 of 80 bytes (>75) is minimal

    # non-minimal classes raise
    for bad in (
        b"\x01\x05",  # 1-byte push of 5 -> must be OP_5
        b"\x01\x01",  # -> OP_1
        b"\x01\x10",  # -> OP_16
        b"\x01\x81",  # -> OP_1NEGATE
        b"\x4c\x02\xaa\xbb",  # PUSHDATA1 of 2 bytes (<=75 must be direct)
        b"\x4d\x10\x00" + b"\xaa" * 16,  # PUSHDATA2 of 16 bytes (<=255 must be PUSHDATA1)
    ):
        with pytest.raises(ValidationError, match="GUARD 3 FAIL"):
            _assert_minimal_pushes(bad, variant="t")


# --------------------------------------------------------------------------- parameter validation


@pytest.mark.parametrize(
    "over,match",
    [
        ({"hashlock": b"\x00" * 31}, "hashlock must be 32 bytes"),
        ({"refund_csv": 0}, "refund_csv must be a positive int"),
        ({"refund_csv": -1}, "refund_csv must be a positive int"),
        ({"amount": 0}, "amount must be a positive int"),
        ({"taker_pkh": b"\x11" * 19}, "20"),  # Hex20 length error
    ],
)
def test_rxd_param_validation_fail_closed(over, match):
    with pytest.raises(ValidationError, match=match):
        build_htlc_covenant_rxd(**_rxd_args(**over))


def test_refund_csv_must_fit_16_bits_f002():
    # F-002: refund_csv is the BIP68 relative-BLOCK count used both as the covenant
    # operand and the refund spend's nSequence (masked to 16 bits). > 0xFFFF would not
    # round-trip and would silently produce a different on-chain timelock — reject it.
    with pytest.raises(ValidationError, match="16 bits"):
        build_htlc_covenant_rxd(**_rxd_args(refund_csv=0x10000))
    # the 16-bit boundary itself is accepted.
    build_htlc_covenant_rxd(**_rxd_args(refund_csv=0xFFFF))


def test_nft_carrier_value_must_be_positive():
    with pytest.raises(ValidationError, match="nft_carrier_value must be a positive int"):
        build_htlc_covenant_nft(
            genesis_txid="ab" * 32,
            genesis_vout=0,
            nft_carrier_value=0,
            taker_pkh=b"\x11" * 20,
            maker_pkh=b"\x22" * 20,
            hashlock=b"\xaa" * 32,
            refund_csv=6,
        )


# --------------------------------------------------------------------------- static guards


def test_bd_opcode_walk_finds_ft_epilogue_weld_only():
    """A synthetic FT-shaped script: the bare 0xbd inside a push operand must NOT be
    counted; only the opcode-position weld counts."""
    from pyrxd.gravity.htlc_covenant import _opcode_bd_positions

    # A 1-byte push of 0xbd (operand, not opcode) then a bare 0xbd opcode.
    script = b"\x01\xbd" + b"\xbd"
    assert _opcode_bd_positions(script) == [2]  # only the bare opcode at index 2


def test_guard_rejects_ref_op_inside_pushdata_is_not_walked_as_op():
    """A 0xd8 (ref op) byte that appears INSIDE a data push is operand, not an op —
    the walker must skip the push operand, not treat embedded bytes as ref ops."""
    from pyrxd.gravity.htlc_covenant import _opcode_bd_positions

    # push 3 bytes containing 0xbd; then nothing. The 0xbd is operand → not counted.
    assert _opcode_bd_positions(b"\x03\xbd\xbd\xbd") == []


def test_ft_param_validation_fail_closed():
    base = dict(
        genesis_txid="ab" * 32,
        genesis_vout=0,
        amount=1000,
        taker_pkh=b"\x11" * 20,
        maker_pkh=b"\x22" * 20,
        hashlock=b"\xaa" * 32,
        refund_csv=6,
    )
    with pytest.raises(ValidationError, match="FT amount must be a positive int"):
        build_htlc_covenant_ft(**{**base, "amount": 0})
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        build_htlc_covenant_ft(**{**base, "hashlock": b"\x00" * 16})


def test_guard_error_paths_raise():
    """The two static guards must RAISE on a malformed funded SPK (defense-in-depth:
    a future artifact regression that moved the boundary or dropped the ref must
    fail closed, not silently mis-bind)."""
    from pyrxd.gravity.htlc_covenant import _guard_bd, _guard_refs

    with pytest.raises(ValidationError, match="GUARD 1 FAIL"):
        _guard_bd(b"\xbd\xbd", expected=[0], variant="nft")  # two bare 0xbd, expected one
    with pytest.raises(ValidationError, match="GUARD 2 FAIL"):
        _guard_refs(b"\x76\xa9", expected_ref=b"\xcc" * 36, variant="ft")  # no ref present


def test_opcode_walk_tolerates_truncated_pushes():
    """The opcode walker must not index past the end on a truncated PUSHDATA — it
    breaks out rather than raising (the guards then catch the structural problem)."""
    from pyrxd.gravity.htlc_covenant import _opcode_bd_positions

    assert _opcode_bd_positions(b"\x4c") == []  # PUSHDATA1 with no length byte
    assert _opcode_bd_positions(b"\x4d\x01") == []  # PUSHDATA2 with truncated length
    assert _opcode_bd_positions(b"\x4e\x01\x02\x03") == []  # PUSHDATA4 truncated


def test_artifact_loader_rejects_path_traversal():
    from pyrxd.gravity.htlc_covenant import _load_template

    with pytest.raises(ValidationError, match="outside the bundled artifacts"):
        _load_template("../../../etc/passwd")
    with pytest.raises(FileNotFoundError):
        _load_template("NoSuchHtlcArtifact")


def test_artifact_loader_rejects_missing_hex(tmp_path, monkeypatch):
    import pyrxd.gravity.htlc_covenant as mod

    monkeypatch.setattr(mod, "_ARTIFACTS_DIR", tmp_path)
    (tmp_path / "Broken.artifact.json").write_text(json.dumps({"asm": "..."}))  # no 'hex'
    with pytest.raises(ValidationError, match="no 'hex' string"):
        mod._load_template("Broken")


def test_opcode_walk_skips_valid_pushdata_operands():
    """Walk over valid PUSHDATA1/2/4 pushes (operand present) — the walker advances
    past the operand and finds a trailing bare 0xbd at the correct position."""
    from pyrxd.gravity.htlc_covenant import _opcode_bd_positions

    # PUSHDATA1: 0x4c <len=2> <2 bytes>, then bare 0xbd at index 4.
    assert _opcode_bd_positions(b"\x4c\x02\xaa\xbb\xbd") == [4]
    # PUSHDATA2: 0x4d <len=2 LE> <2 bytes>, then bare 0xbd at index 5.
    assert _opcode_bd_positions(b"\x4d\x02\x00\xaa\xbb\xbd") == [5]
    # PUSHDATA4: 0x4e <len=2 LE32> <2 bytes>, then bare 0xbd at index 7.
    assert _opcode_bd_positions(b"\x4e\x02\x00\x00\x00\xaa\xbb\xbd") == [7]


def test_substitute_rejects_unfilled_placeholder():
    from pyrxd.gravity.htlc_covenant import _substitute

    with pytest.raises(ValidationError, match="unfilled covenant placeholder"):
        _substitute("ab<missing>cd", {}, variant="rxd")


def test_minimal_num_push_rejects_negative():
    from pyrxd.gravity.htlc_covenant import _minimal_num_push

    with pytest.raises(ValidationError, match="refund_csv must be a non-negative int"):
        _minimal_num_push(-1)


def test_scriptnum_and_push_encoder_edges():
    from pyrxd.gravity.htlc_covenant import _push, _scriptnum

    assert _scriptnum(0) == b""
    assert _scriptnum(0x80) == b"\x80\x00"  # high bit set -> pad
    assert _scriptnum(-1) == b"\x81"  # negative sign bit
    assert _push(b"") == b"\x00"
    assert _push(b"\x01" * 100)[:2] == b"\x4c\x64"  # PUSHDATA1
    assert _push(b"\x01" * 300)[:3] == b"\x4d\x2c\x01"  # PUSHDATA2
    with pytest.raises(ValidationError, match="64 KB"):
        _push(b"\x00" * 0x10000)


def test_nft_and_ft_bind_exactly_the_genesis_ref():
    """GUARD 2: the only input ref the funded SPK carries is the genesis ref."""
    from pyrxd.glyph.script import count_input_refs
    from pyrxd.glyph.types import GlyphRef

    v = _load_vector(".live_swap_nft.json")
    txid, vout = v["nft_genesis"].split(":")
    cov = build_htlc_covenant_nft(
        genesis_txid=txid,
        genesis_vout=int(vout),
        nft_carrier_value=v["nft_carrier"],
        taker_pkh=_pkh(v["nft_claim_taker_wif"]),
        maker_pkh=_pkh(v["nft_owner_wif"]),
        hashlock=bytes.fromhex(v["hashlock"]),
        refund_csv=v["btc_refund_csv_blocks"],
    )
    ref = GlyphRef(txid=txid, vout=int(vout)).to_bytes()
    assert set(count_input_refs(cov.funded_spk).keys()) == {ref}
    assert cov.genesis_ref == ref
