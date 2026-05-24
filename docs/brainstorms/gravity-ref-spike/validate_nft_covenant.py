#!/usr/bin/env python3
"""Phase-1 NFT covenant static guard. Substitutes realistic values into
GravityNftCovenantAnyWallet20.artifact.json and asserts:
  - exactly ONE distinct input-ref (the genesis singleton),
  - it is parsed as OP_PUSHINPUTREFSINGLETON (0xd8),
  - parser-equivalence: count_input_refs == {genesis ref}.
The funded NFT UTXO IS the compiled script verbatim (no epilogue append).

NOTE: unlike FT, there is NO offset-0 positional anchor — the covenant emits the
claimDeadline S1 check before the singleton push, and consensus GetPushRefs is
position-agnostic, so the singleton is found wherever it sits. The guard is
"exactly one singleton ref," not "singleton at offset 0."
Run: python3 validate_nft_covenant.py
"""

import hashlib
import json
import sys

sys.path.insert(0, "src")
from pyrxd.glyph.script import count_input_refs, iter_input_refs  # noqa: E402

REF = "576999c71ab91a82f8339c6e1f5bbbbd0aa253fa63f065892e4c9cc26efe0dcc00000000"


def _nft(pkh: str) -> bytes:
    return b"\xd8" + bytes.fromhex(REF) + b"\x75\x76\xa9\x14" + bytes.fromhex(pkh) + b"\x88\xac"


def _h256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _sn(n: int) -> bytes:
    if n == 0:
        return b""
    o = bytearray()
    while n:
        o.append(n & 0xFF)
        n >>= 8
    if o[-1] & 0x80:
        o.append(0)
    return bytes(o)


def _push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + b
    if n <= 255:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


def main() -> None:
    art = json.load(open("docs/brainstorms/gravity-ref-spike/GravityNftCovenantAnyWallet20.artifact.json"))
    tmpl = art["hex"]
    subs = {
        "REF": REF,
        "btcReceiveHash": _push(bytes(20)).hex(),
        "btcSatoshis": _push(_sn(10000)).hex(),
        "btcChainAnchor": _push(bytes(32)).hex(),
        "expectedNBits": _push(bytes.fromhex("ffff7f1d")).hex(),
        "expectedNBitsNext": _push(bytes.fromhex("ffff7f1d")).hex(),
        "claimDeadline": _push(_sn(1900000000)).hex(),
        "nftCarrierValue": _push(_sn(1000)).hex(),
        "expectedTakerNftHash": _push(_h256(_nft("11" * 20))).hex(),
        "expectedMakerNftHash": _push(_h256(_nft("22" * 20))).hex(),
    }
    spk = tmpl
    for k, v in subs.items():
        spk = spk.replace(f"<{k}>", v)
    assert "<" not in spk, f"unfilled placeholder: {spk[spk.index('<') :][:30]}"
    full = bytes.fromhex(spk)  # NFT funded UTXO = compiled script verbatim

    refs = list(iter_input_refs(full))
    counts = count_input_refs(full)
    assert set(counts) == {bytes.fromhex(REF)}, f"expected exactly the genesis ref, got {counts}"
    assert refs and all(op == 0xD8 for op, _ in refs), (
        f"ref must be a singleton (0xd8), got {[hex(o) for o, _ in refs]}"
    )

    # AUDIT 2026-05-24 M-FUSE-2: opcode-level HARDENING assertions over the
    # compiled ASM. The ref-parse checks above do NOT verify the covenant
    # actually enforces conservation/destination — a trivially-weak `d8<ref>
    # OP_1` stub would pass them. Assert every hardening primitive is present in
    # the compiled bytecode so a drifted/unhardened covenant (M-FUSE-1) cannot
    # silently ship.
    asm = art["asm"]
    required_ops = {
        "singleton prologue": "OP_PUSHINPUTREFSINGLETON",
        "output-count clamp": "OP_TXOUTPUTCOUNT",
        "singleton conservation": "OP_REFOUTPUTCOUNT_OUTPUTS",
        "carrier-value pin": "OP_OUTPUTVALUE",
        "destination hash-compare": "OP_HASH256",
        "CLTV deadline": "OP_CHECKLOCKTIMEVERIFY",
        # C-PARSER-1 fix: the terminal pos == rawTx.length - 4 check.
        "parser terminal length check": "OP_SIZE",
    }
    for label, op in required_ops.items():
        assert op in asm, f"HARDENING MISSING: {label} ({op}) absent from compiled covenant"
    # Both expected-hash params must be referenced (taker finalize + maker forfeit).
    assert asm.count("OP_HASH256") >= 2, "expected >=2 OP_HASH256 (taker + maker hash-compares + merkle)"
    # C-PARSER-1: a signed-scriptLen guard must bound the output/input lengths.
    assert "OP_LESSTHANOREQUAL" in asm, "C-PARSER-1 sl/ssl <= 252 guard missing from compiled covenant"

    print(
        f"NFT covenant static guard PASS: {len(full)}-B script, exactly one singleton ref (0xd8), "
        f"no phantom; all hardening opcodes present (incl. C-PARSER-1 length guard + terminal check)."
    )


if __name__ == "__main__":
    main()
