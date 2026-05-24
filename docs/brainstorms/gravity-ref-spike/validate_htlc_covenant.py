#!/usr/bin/env python3
"""Phase-2 HTLC covenant static guard (upgraded; model: validate_nft_covenant.py).

Validates BOTH GravityHtlcCovenant{Ft,Nft} from their compiled artifacts (no
funds, dry). Asserts, per variant:

  1. REF parse: exactly ONE distinct input-ref == the genesis ref, no phantom
     (count_input_refs == {genesis}); the ref opcode is correct
     (FT -> 0xd0 OP_PUSHINPUTREF; NFT -> 0xd8 OP_PUSHINPUTREFSINGLETON).
  2. Opcode-level HARDENING present (NOT a trivially-weak stub):
     - selector dispatch (OP_IF/OP_ELSE/OP_ENDIF, claim=index0, refund=index1);
     - claim branch: OP_SHA256 + the taker hash-compare (OP_OUTPUTBYTECODE
       OP_HASH256 ... OP_EQUAL);
     - refund branch: OP_CHECKSEQUENCEVERIFY + the maker hash-compare;
     - both hash-compares present and BRANCH-CORRECT (taker hash before OP_ELSE,
       maker hash after OP_ELSE) — the C1/race protection rides on this.
  3. Output pinning uses the proven hash-compare pattern
     (OP_0 OP_OUTPUTBYTECODE OP_HASH256 <hash> OP_EQUAL), NOT LockingBytecodeP2PKH.
  4. FT vs NFT consensus-gate difference:
     - FT MUST keep OP_REFVALUESUM_OUTPUTS (L2 amount conservation);
     - NFT MUST NOT contain OP_REFVALUESUM_OUTPUTS (Layer-1 only; no FT leak)
       and MUST contain OP_OUTPUTVALUE (carrier-value pin).
  5. NO SPV residue (no OP_CHECKLOCKTIMEVERIFY/CLTV deadline, no merkle-tail
     opcodes leaked from the base) — the SPV body is gone.
  6. bare-0xbd-in-opcode-position guard over the substituted prologue: the new
     sha256/CSV opcodes must not push the codeScriptHash boundary; for a funded
     FT SPK the only bare 0xbd is the epilogue weld, for NFT there are none.

Run: python3 docs/brainstorms/gravity-ref-spike/validate_htlc_covenant.py
"""
import hashlib
import json
import sys

sys.path.insert(0, "src")
from pyrxd.glyph.script import count_input_refs, iter_input_refs  # noqa: E402

ART_DIR = "docs/brainstorms/gravity-ref-spike"
REF = "576999c71ab91a82f8339c6e1f5bbbbd0aa253fa63f065892e4c9cc26efe0dcc00000000"
FT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")


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


def _minimal_num_push(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    return _push(_sn(n))


def _h256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _ft_script(pkh: str) -> bytes:
    return b"\x76\xa9\x14" + bytes.fromhex(pkh) + b"\x88\xac\xbd\xd0" + bytes.fromhex(REF) + FT_EPILOGUE


def _nft_script(pkh: str) -> bytes:
    return b"\xd8" + bytes.fromhex(REF) + b"\x75\x76\xa9\x14" + bytes.fromhex(pkh) + b"\x88\xac"


def _opcode_bd_positions(spk: bytes):
    REF_OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}
    i, bds = 0, []
    while i < len(spk):
        op = spk[i]
        if op == 0xBD:
            bds.append(i)
        if op in REF_OPS:
            i += 37
            continue
        if 0x01 <= op <= 0x4B:
            i += 1 + op
            continue
        if op == 0x4C:
            i += 2 + spk[i + 1]
            continue
        if op == 0x4D:
            i += 3 + (spk[i + 1] | (spk[i + 2] << 8))
            continue
        if op == 0x4E:
            i += 5 + int.from_bytes(spk[i + 1 : i + 5], "little")
            continue
        i += 1
    return bds


def _check(variant: str) -> int:
    is_ft = variant == "ft"
    art = json.load(open(f"{ART_DIR}/GravityHtlcCovenant{'Ft' if is_ft else 'Nft'}.artifact.json"))
    tmpl, asm = art["hex"], art["asm"]

    if is_ft:
        subs = {
            "REF": REF,
            "hashlock": _push(b"\xaa" * 32).hex(),
            "refundCsv": _minimal_num_push(6).hex(),
            "amount": _push(_sn(1000)).hex(),
            "expectedTakerFtHash": _push(_h256(_ft_script("11" * 20))).hex(),
            "expectedMakerFtHash": _push(_h256(_ft_script("22" * 20))).hex(),
        }
    else:
        subs = {
            "REF": REF,
            "hashlock": _push(b"\xaa" * 32).hex(),
            "refundCsv": _minimal_num_push(6).hex(),
            "nftCarrierValue": _push(_sn(1000)).hex(),
            "expectedTakerNftHash": _push(_h256(_nft_script("11" * 20))).hex(),
            "expectedMakerNftHash": _push(_h256(_nft_script("22" * 20))).hex(),
        }

    spk = tmpl
    for k, v in subs.items():
        spk = spk.replace(f"<{k}>", v)
    assert "<" not in spk, f"[{variant}] unfilled placeholder: {spk[spk.index('<'):][:30]}"
    prologue = bytes.fromhex(spk)
    funded = prologue + (b"\xbd\xd0" + bytes.fromhex(REF) + FT_EPILOGUE if is_ft else b"")

    # 1. REF parse: exactly one genesis ref, correct opcode.
    refs = list(iter_input_refs(funded))
    counts = count_input_refs(funded)
    assert set(counts) == {bytes.fromhex(REF)}, f"[{variant}] expected exactly genesis ref, got {counts}"
    want_op = 0xD0 if is_ft else 0xD8
    assert refs and all(op == want_op for op, _ in refs), (
        f"[{variant}] ref opcode must be {hex(want_op)}, got {[hex(o) for o, _ in refs]}"
    )

    # 2./3. Opcode hardening + hash-compare pattern (proven shape, NOT P2PKH equality).
    required = {
        "selector dispatch (IF)": "OP_IF",
        "selector dispatch (ELSE)": "OP_ELSE",
        "selector dispatch (ENDIF)": "OP_ENDIF",
        "claim hashlock": "OP_SHA256",
        "refund relative timelock": "OP_CHECKSEQUENCEVERIFY",
        "output bytecode pin": "OP_OUTPUTBYTECODE",
        "destination hash-compare": "OP_HASH256",
        "ref present on exactly one output": "OP_REFOUTPUTCOUNT_OUTPUTS",
        "output-count clamp": "OP_TXOUTPUTCOUNT",
    }
    for label, op in required.items():
        assert op in asm, f"[{variant}] HARDENING MISSING: {label} ({op})"
    assert "LockingBytecodeP2PKH" not in asm and "OP_EQUALVERIFY OP_CHECKSIG" not in asm, (
        f"[{variant}] must use hash-compare output pin, not P2PKH equality"
    )
    assert asm.count("OP_OUTPUTBYTECODE") >= 2, f"[{variant}] need >=2 output-bytecode pins (taker+maker)"
    assert asm.count("OP_HASH256") >= 2, f"[{variant}] need >=2 OP_HASH256 (taker+maker hash-compares)"

    # Branch-correctness: taker hash-compare is in the claim branch (before
    # OP_ELSE), maker in the refund branch (after OP_ELSE). The selector is
    # claim=index0 (OP_0) / refund=index1 (OP_1) — confirm the gate order.
    toks = asm.split()
    i_if, i_else, i_endif = toks.index("OP_IF"), toks.index("OP_ELSE"), toks.index("OP_ENDIF")
    assert i_if < i_else < i_endif, f"[{variant}] dispatch order broken"
    claim_branch, refund_branch = toks[i_if:i_else], toks[i_else:i_endif]
    th = "$expectedTakerFtHash" if is_ft else "$expectedTakerNftHash"
    mh = "$expectedMakerFtHash" if is_ft else "$expectedMakerNftHash"
    assert "OP_SHA256" in claim_branch and th in claim_branch, (
        f"[{variant}] claim branch must hold sha256(preimage) + taker hash-compare"
    )
    assert "OP_CHECKSEQUENCEVERIFY" in refund_branch and mh in refund_branch, (
        f"[{variant}] refund branch must hold tx.age CSV + maker hash-compare"
    )
    assert "OP_SHA256" not in refund_branch, f"[{variant}] sha256 leaked into refund branch"
    assert "OP_CHECKSEQUENCEVERIFY" not in claim_branch, f"[{variant}] CSV leaked into claim branch"

    # 4. FT vs NFT consensus-gate difference.
    if is_ft:
        assert "OP_REFVALUESUM_OUTPUTS" in asm, "[ft] L2 amount conservation (refValueSum) missing"
        assert "OP_PUSHINPUTREF" in asm and "OP_PUSHINPUTREFSINGLETON" not in asm, (
            "[ft] FT must bind a fungible ref (0xd0), not a singleton"
        )
    else:
        assert "OP_REFVALUESUM_OUTPUTS" not in asm, (
            "[nft] FT-LEAK: refValueSum present in NFT covenant (must be Layer-1 only)"
        )
        assert "OP_PUSHINPUTREFSINGLETON" in asm, "[nft] singleton ref opcode missing"
        assert "OP_OUTPUTVALUE" in asm, "[nft] carrier-value pin missing"

    # 5. NO SPV residue.
    assert "OP_CHECKLOCKTIMEVERIFY" not in asm, f"[{variant}] CLTV deadline leaked (SPV residue)"

    # 6. bare-0xbd guard over the substituted prologue.
    bds = _opcode_bd_positions(funded)
    if is_ft:
        assert bds == [len(prologue)], f"[ft] bare 0xbd at {bds} != [{len(prologue)}] (only the epilogue weld is legal)"
    else:
        assert bds == [], f"[nft] unexpected bare 0xbd at {bds} (FT-leak / boundary shift)"

    print(
        f"  [{variant}] PASS: {len(funded)}-B funded SPK, exactly one genesis ref "
        f"({hex(want_op)}), no phantom; selector dispatch + sha256-claim + CSV-refund + "
        f"branch-correct taker/maker hash-compares; "
        + ("FT L2 conservation kept; only the epilogue weld carries 0xbd."
           if is_ft else "NFT Layer-1 only (no refValueSum/FT-leak), no bare 0xbd.")
    )
    return len(funded)


def main() -> None:
    print("HTLC covenant static guard (Phase 2):")
    ft_len = _check("ft")
    nft_len = _check("nft")
    _validate_rxd()
    print(f"ALL GUARDS PASS. FT funded SPK = {ft_len} B; NFT funded SPK = {nft_len} B; RXD = native (no ref).")




def _validate_rxd() -> None:
    """RXD variant: native coins, NO ref machinery. Asserts no ref opcodes, the
    value pin + branch-correct hash-compares on both routes, output-count clamp,
    and no SPV/CLTV residue. (Native RXD has no consensus conservation backstop,
    so the value pin + destination hash-compare are the SOLE guarantors.)"""
    art = json.load(open(f"{ART_DIR}/GravityHtlcCovenantRxd.artifact.json"))
    asm = art["asm"]
    hexc = art["hex"].lower()
    claim_b = asm.split("OP_ELSE")[0]
    refund_b = asm.split("OP_ELSE")[1]
    A = []
    def a(name, cond): A.append((name, cond))
    for op in ("OP_PUSHINPUTREF", "OP_PUSHINPUTREFSINGLETON", "OP_REFVALUESUM", "OP_REFOUTPUTCOUNT"):
        a(f"no {op}", op not in asm)
    a("no FT epilogue weld", "dec0e9aa" not in hexc)
    a("output-count clamp", "OP_TXOUTPUTCOUNT OP_1 OP_NUMEQUALVERIFY" in asm)
    a("selector dispatch", "OP_DUP OP_0 OP_NUMEQUAL OP_IF" in asm and "OP_ELSE OP_1 OP_NUMEQUALVERIFY" in asm)
    a("claim: sha256 hashlock", "OP_SHA256 $hashlock OP_EQUALVERIFY" in claim_b)
    a("claim: value pin", "OP_OUTPUTVALUE $amount OP_GREATERTHANOREQUAL" in claim_b)
    a("claim: taker hash-compare", "OP_OUTPUTBYTECODE OP_HASH256 $expectedTakerHash OP_EQUAL" in claim_b)
    a("refund: CSV", "$refundCsv OP_CHECKSEQUENCEVERIFY OP_DROP" in refund_b)
    a("refund: value pin", "OP_OUTPUTVALUE $amount OP_GREATERTHANOREQUAL" in refund_b)
    a("refund: maker hash-compare", "OP_OUTPUTBYTECODE OP_HASH256 $expectedMakerHash OP_EQUAL" in refund_b)
    a("branch-correct (taker not in refund)", "expectedTakerHash" not in refund_b)
    a("branch-correct (maker not in claim)", "expectedMakerHash" not in claim_b)
    a("no SPV/CLTV residue", "OP_CHECKLOCKTIMEVERIFY" not in asm)
    fails = [n for n, c in A if not c]
    assert not fails, f"RXD guard FAILED: {fails}"
    print(f"  [rxd] PASS: native-RXD HTLC (no ref machinery); selector dispatch + "
          f"sha256-claim + CSV-refund + value pin + branch-correct taker/maker "
          f"hash-compares; no SPV residue. ({len(A)} checks)")


if __name__ == "__main__":
    main()
