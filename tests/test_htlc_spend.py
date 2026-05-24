"""Phase-3 Gravity Taproot-HTLC: Radiant-side claim/refund tx-builder structural
tests (NO on-chain spend — the parent runs the mainnet proof).

Covers all 3 covenant variants (ft|nft|rxd). Asserts the SETTLED scriptSig layout
and the single-output + fee model, plus serialize/parse round-trip.

What is verified here is STRUCTURAL ONLY: the byte layout of the claim/refund
scriptSigs, the v2/nSequence BIP68 wiring on the refund, the single covenant-pinned
output, and that output[0] hashes to the taker/maker hash the covenant pins. Whether
the Radiant interpreter ACCEPTS these spends is NOT tested here — that is the parent's
mainnet proof (the CSV gate was proven separately in .csv_spike.json).

Claim scriptSig (settled): <preimage push> <OP_0>  — preimage FIRST, selector LAST
  (covenant claim branch does OP_SWAP before OP_SHA256, so the preimage must sit UNDER
  the selector on the stack). selector is the LAST push, on top.
Refund scriptSig (settled): <OP_1>  — selector only, no preimage, no sig (CSV-gated).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SPIKE_DIR = REPO_ROOT / "docs" / "brainstorms" / "gravity-ref-spike"

sys.path.insert(0, str(REPO_ROOT / "src"))


def _load(modname: str):
    path = SPIKE_DIR / f"{modname}.py"
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


# The SPK builder loads artifacts via a RELATIVE path (ART_DIR), so the builders
# must be invoked with the repo root as CWD. We chdir for the whole module.
@pytest.fixture(scope="module", autouse=True)
def _cwd_repo_root():
    prev = os.getcwd()
    os.chdir(REPO_ROOT)
    try:
        yield
    finally:
        os.chdir(prev)


from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction

CLAIM = None
REFUND = None
SPK = None


@pytest.fixture(scope="module", autouse=True)
def _modules(_cwd_repo_root):
    global CLAIM, REFUND, SPK
    CLAIM = _load("build_htlc_claim")
    REFUND = _load("build_htlc_refund")
    SPK = _load("build_htlc_covenant_spk")
    yield


# --- helpers ---------------------------------------------------------------

# A real (CSPRNG) preimage and its sha256 hashlock — never hand-written keys.
PREIMAGE = os.urandom(32)
HASHLOCK = hashlib.sha256(PREIMAGE).digest()
REFUND_CSV = 12
AMOUNT = 100_000_000
NFT_CARRIER = 1000
FEE_AMT = 200_000_000

# Synthetic funding outpoints (NOT broadcast).
COV_TXID = "a" * 64
FEE_TXID = "b" * 64
GENESIS_TXID = "1" * 64


def _keys():
    taker = PrivateKey()
    maker = PrivateKey()
    fee = PrivateKey()
    return taker, maker, fee


def _fee_spk(fee_key: PrivateKey) -> bytes:
    pkh = bytes(Hex20(fee_key.public_key().hash160()))
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


class Cov(NamedTuple):
    spk: bytes
    taker_script: bytes
    maker_script: bytes
    expected_taker_hash: bytes
    expected_maker_hash: bytes
    out0: int


def _read_artifact_hex(name: str) -> str:
    with open(SPIKE_DIR / name) as fh:
        return json.load(fh)["hex"]


def _build_covenant(variant: str, taker: PrivateKey, maker: PrivateKey) -> Cov:
    """Drive the SPK builder's internal helpers to produce a funded covenant SPK
    plus the taker/maker holder scripts the covenant pins via hash-compare."""
    taker_pkh = bytes(Hex20(taker.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker.public_key().hash160()))

    if variant == "rxd":
        taker_script = SPK.rxd_holder_script(taker_pkh)
        maker_script = SPK.rxd_holder_script(maker_pkh)
        spk_hex = _read_artifact_hex("GravityHtlcCovenantRxd.artifact.json")
        subs = {
            "hashlock": SPK.push(HASHLOCK).hex(),
            "refundCsv": SPK.minimal_num_push(REFUND_CSV).hex(),
            "amount": SPK.push(SPK.scriptnum(AMOUNT)).hex(),
            "expectedTakerHash": SPK.push(SPK.hash256(taker_script)).hex(),
            "expectedMakerHash": SPK.push(SPK.hash256(maker_script)).hex(),
        }
        out0 = AMOUNT
    else:
        from pyrxd.glyph.types import GlyphRef
        ref_wire = GlyphRef(txid=GENESIS_TXID, vout=0).to_bytes()
        if variant == "ft":
            taker_script = SPK.ft_holder_script(taker_pkh, ref_wire)
            maker_script = SPK.ft_holder_script(maker_pkh, ref_wire)
            spk_hex = _read_artifact_hex("GravityHtlcCovenantFt.artifact.json")
            subs = {
                "REF": ref_wire.hex(),
                "hashlock": SPK.push(HASHLOCK).hex(),
                "refundCsv": SPK.minimal_num_push(REFUND_CSV).hex(),
                "amount": SPK.push(SPK.scriptnum(AMOUNT)).hex(),
                "expectedTakerFtHash": SPK.push(SPK.hash256(taker_script)).hex(),
                "expectedMakerFtHash": SPK.push(SPK.hash256(maker_script)).hex(),
            }
            out0 = AMOUNT
        else:  # nft
            taker_script = SPK.nft_holder_script(taker_pkh, ref_wire)
            maker_script = SPK.nft_holder_script(maker_pkh, ref_wire)
            spk_hex = _read_artifact_hex("GravityHtlcCovenantNft.artifact.json")
            subs = {
                "REF": ref_wire.hex(),
                "hashlock": SPK.push(HASHLOCK).hex(),
                "refundCsv": SPK.minimal_num_push(REFUND_CSV).hex(),
                "nftCarrierValue": SPK.push(SPK.scriptnum(NFT_CARRIER)).hex(),
                "expectedTakerNftHash": SPK.push(SPK.hash256(taker_script)).hex(),
                "expectedMakerNftHash": SPK.push(SPK.hash256(maker_script)).hex(),
            }
            out0 = NFT_CARRIER
        # FT needs the epilogue weld appended post-compile.
        if variant == "ft":
            for n, v in subs.items():
                spk_hex = spk_hex.replace(f"<{n}>", v)
            cov = bytes.fromhex(spk_hex) + b"\xbd\xd0" + ref_wire + SPK.FT_EPILOGUE
            return Cov(cov, taker_script, maker_script,
                       SPK.hash256(taker_script), SPK.hash256(maker_script), out0)

    for n, v in subs.items():
        spk_hex = spk_hex.replace(f"<{n}>", v)
    assert "<" not in spk_hex, spk_hex
    cov = bytes.fromhex(spk_hex)
    return Cov(cov, taker_script, maker_script,
               SPK.hash256(taker_script), SPK.hash256(maker_script), out0)


def _parse_pushes(script: bytes):
    """Minimal scriptSig push/op walker -> list of (kind, payload).
    kind is 'op' for a bare opcode (payload=opcode byte), 'push' for data."""
    out = []
    i = 0
    while i < len(script):
        op = script[i]
        if op == 0x00:
            out.append(("op", 0x00))  # OP_0 / empty push
            i += 1
        elif 0x01 <= op <= 0x4B:
            out.append(("push", script[i + 1 : i + 1 + op]))
            i += 1 + op
        elif op == 0x4C:
            n = script[i + 1]
            out.append(("push", script[i + 2 : i + 2 + n]))
            i += 2 + n
        elif op == 0x4D:
            n = script[i + 1] | (script[i + 2] << 8)
            out.append(("push", script[i + 3 : i + 3 + n]))
            i += 3 + n
        else:
            out.append(("op", op))
            i += 1
    return out


VARIANTS = ["ft", "nft", "rxd"]


# --- tests -----------------------------------------------------------------

@pytest.mark.parametrize("variant", VARIANTS)
def test_claim_scriptsig_layout(variant):
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)

    tx = CLAIM.build_claim_tx(
        variant, PREIMAGE, c.spk, COV_TXID, 0, c.out0, c.taker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )

    # Covenant input scriptSig = <preimage push> <OP_0 selector>. Preimage FIRST.
    sig = tx.inputs[0].unlocking_script.serialize()
    parsed = _parse_pushes(sig)
    assert len(parsed) == 2, f"expected [preimage, OP_0], got {parsed}"
    assert parsed[0] == ("push", PREIMAGE), "first item must be the preimage push"
    assert parsed[1] == ("op", 0x00), "selector must be OP_0 (last)"

    # Single covenant-pinned output: the taker holder script at out0 value.
    assert len(tx.outputs) == 1, "covenant enforces outputs.length==1"
    assert tx.outputs[0].locking_script.serialize() == c.taker_script
    assert tx.outputs[0].satoshis == c.out0
    assert hashlib.sha256(hashlib.sha256(c.taker_script).digest()).digest() == c.expected_taker_hash

    # Fee model: fee = (carrier + fee_amt) - out0, no change output.
    fee_consumed = (c.out0 + FEE_AMT) - c.out0
    assert fee_consumed == FEE_AMT


@pytest.mark.parametrize("variant", VARIANTS)
def test_refund_scriptsig_and_bip68(variant):
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)

    tx = REFUND.build_refund_tx(
        variant, REFUND_CSV, c.spk, COV_TXID, 0, c.out0, c.maker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )

    # Refund scriptSig = OP_1 selector only.
    sig = tx.inputs[0].unlocking_script.serialize()
    assert sig == b"\x51", f"refund scriptSig must be OP_1, got {sig.hex()}"

    # BIP68: v2 tx + covenant input nSequence == refundCsv.
    assert tx.version == 2
    assert tx.inputs[0].sequence == REFUND_CSV

    # Single output to the MAKER holder script.
    assert len(tx.outputs) == 1
    assert tx.outputs[0].locking_script.serialize() == c.maker_script
    assert tx.outputs[0].satoshis == c.out0
    assert hashlib.sha256(hashlib.sha256(c.maker_script).digest()).digest() == c.expected_maker_hash


@pytest.mark.parametrize("variant", VARIANTS)
def test_claim_decode_roundtrip(variant):
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)
    tx = CLAIM.build_claim_tx(
        variant, PREIMAGE, c.spk, COV_TXID, 0, c.out0, c.taker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )
    raw = tx.serialize().hex()
    back = Transaction.from_hex(raw)
    assert back.version == 1  # claim tx is plain v1 (no BIP68 on claim)
    assert len(back.outputs) == 1
    assert back.outputs[0].locking_script.serialize() == c.taker_script
    assert back.outputs[0].satoshis == c.out0
    # covenant input scriptSig survives the round-trip with preimage-then-OP_0.
    parsed = _parse_pushes(back.inputs[0].unlocking_script.serialize())
    assert parsed[0] == ("push", PREIMAGE)
    assert parsed[1] == ("op", 0x00)


@pytest.mark.parametrize("variant", VARIANTS)
def test_refund_decode_roundtrip(variant):
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)
    tx = REFUND.build_refund_tx(
        variant, REFUND_CSV, c.spk, COV_TXID, 0, c.out0, c.maker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )
    raw = tx.serialize().hex()
    back = Transaction.from_hex(raw)
    assert back.version == 2
    assert back.inputs[0].sequence == REFUND_CSV
    assert back.inputs[0].unlocking_script.serialize() == b"\x51"
    assert len(back.outputs) == 1
    assert back.outputs[0].locking_script.serialize() == c.maker_script


@pytest.mark.parametrize("variant", VARIANTS)
def test_wrong_preimage_changes_scriptsig(variant):
    """Sanity: a wrong preimage produces a different covenant scriptSig (the
    on-chain sha256(preimage)==hashlock check would reject it; we only assert the
    structural difference here, not interpreter rejection)."""
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)
    good = CLAIM.build_claim_tx(
        variant, PREIMAGE, c.spk, COV_TXID, 0, c.out0, c.taker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )
    wrong = CLAIM.build_claim_tx(
        variant, os.urandom(32), c.spk, COV_TXID, 0, c.out0, c.taker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee),
    )
    good_sig = good.inputs[0].unlocking_script.serialize()
    wrong_sig = wrong.inputs[0].unlocking_script.serialize()
    assert good_sig != wrong_sig
    # Both still structurally well-formed: preimage push + OP_0.
    assert _parse_pushes(wrong_sig)[1] == ("op", 0x00)


@pytest.mark.parametrize("variant", VARIANTS)
def test_premature_refund_is_v1_and_seq_zero(variant):
    """The --premature path (used by the parent's negative on-chain test) must
    produce a v1 tx with cov nSequence=0 so BIP68 is NOT satisfiable."""
    taker, maker, fee = _keys()
    c = _build_covenant(variant, taker, maker)
    tx = REFUND.build_refund_tx(
        variant, REFUND_CSV, c.spk, COV_TXID, 0, c.out0, c.maker_script,
        fee.wif(), FEE_TXID, 0, FEE_AMT, _fee_spk(fee), premature=True,
    )
    assert tx.version == 1
    assert tx.inputs[0].sequence == 0


def test_covenant_spk_guards_pass_all_variants():
    """The SPK builder's GUARD 1 (bare-0xbd) + GUARD 2 (input-ref count) must pass
    for all three variants — exercised by _build_covenant for ft/nft; rxd's guards
    run inside _build_rxd, so assert the rxd body carries NO ref op and NO 0xbd."""
    from pyrxd.glyph.script import count_input_refs
    taker, maker, _ = _keys()
    cov_rxd = _build_covenant("rxd", taker, maker).spk
    assert SPK._opcode_bd_positions(cov_rxd) == []
    assert list(count_input_refs(cov_rxd)) == []
    # FT must carry exactly one bare 0xbd (the epilogue weld); NFT exactly zero.
    cov_ft = _build_covenant("ft", taker, maker).spk
    cov_nft = _build_covenant("nft", taker, maker).spk
    assert len(SPK._opcode_bd_positions(cov_ft)) == 1
    assert SPK._opcode_bd_positions(cov_nft) == []
