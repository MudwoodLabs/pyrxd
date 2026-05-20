#!/usr/bin/env python3
"""Spike step 3: substitute the FT-release covenant params and compute its
P2SH address + redeem script. REF = the minted FT's ref (txid:vout wire form)."""
import json
import sys

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.types import Hex20
from pyrxd.keys import PrivateKey

ARTIFACT = "docs/brainstorms/gravity-ref-spike/GravityFtReleaseSpike.artifact.json"

FT_REF_TXID = sys.argv[1]
FT_REF_VOUT = int(sys.argv[2])
AMOUNT = int(sys.argv[3])
TAKER_WIF = sys.argv[4]
MAKER_WIF = sys.argv[5]
DEADLINE = int(sys.argv[6])

ref = GlyphRef(txid=FT_REF_TXID, vout=FT_REF_VOUT)
ref_wire = ref.to_bytes()  # 36 bytes
taker_pkh = bytes(Hex20(PrivateKey(TAKER_WIF).public_key().hash160()))
maker_pkh = bytes(Hex20(PrivateKey(MAKER_WIF).public_key().hash160()))

art = json.load(open(ARTIFACT))
hex_template = art["hex"]

# The rxdc compiler emits each constructor param as a PUSH-LESS <NAME>
# placeholder (it expects the substituted value to ALREADY be a complete
# pushdata — see pyrxd/gravity/covenant.py:_encode_bytes_push). The earlier
# version of this script substituted RAW bytes, which spliced REF's internal
# 0xd8 byte into the script body where consensus parsed it as a phantom
# OP_PUSHINPUTREFSINGLETON -> rejected. So: push-wrap every DATA param.
#
# EXCEPTION: <REF> follows the literal 0xd0 (OP_PUSHINPUTREF) opcode, whose
# operand is 36 RAW bytes (NOT a pushdata). So <REF> alone is substituted raw;
# all other params are push-wrapped.
#
# The covenant no longer embeds the expected FT script as comparison bytes —
# it compares hash256(output.lockingBytecode) against precomputed hashes, so
# the ref's 0xd8-bearing bytes never appear raw in the covenant scriptPubKey.
def scriptnum(n: int) -> bytes:
    if n == 0: return b""
    neg = n < 0; n = abs(n); out = bytearray()
    while n: out.append(n & 0xFF); n >>= 8
    if out[-1] & 0x80: out.append(0x80 if neg else 0x00)
    elif neg: out[-1] |= 0x80
    return bytes(out)

def push(b: bytes) -> bytes:
    """Minimal data push (matches pyrxd/gravity/covenant.py:_encode_bytes_push)."""
    n = len(b)
    if n == 0: return b"\x00"          # OP_0
    if n <= 75: return bytes([n]) + b
    if n <= 255: return b"\x4c" + bytes([n]) + b
    if n <= 65535: return b"\x4d" + n.to_bytes(2, "little") + b
    raise ValueError(f"push: data too large ({n})")

def ft_locking_script(pkh: bytes) -> bytes:
    """Canonical 75-byte FT holder script for (pkh, REF) — mirror of
    pyrxd.glyph.script.build_ft_locking_script. The expected settlement output."""
    return b"\x76\xa9\x14" + pkh + b"\x88\xac\xbd\xd0" + ref_wire \
        + b"\xde\xc0\xe9\xaa\x76\xe3\x78\xe4\xa2\x69\xe6\x9d"

def hash256(b: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

expected_taker_ft_hash = hash256(ft_locking_script(taker_pkh))
expected_maker_ft_hash = hash256(ft_locking_script(maker_pkh))

# <REF> raw (OP_PUSHINPUTREF operand); everything else push-wrapped.
subs = {
    "REF": ref_wire.hex(),
    "AMOUNT": push(scriptnum(AMOUNT)).hex(),
    "EXPECTED_TAKER_FT_HASH": push(expected_taker_ft_hash).hex(),
    "MAKER_PKH": push(maker_pkh).hex(),
    "EXPECTED_MAKER_FT_HASH": push(expected_maker_ft_hash).hex(),
    "DEADLINE": push(scriptnum(DEADLINE)).hex(),
}

redeem_hex = hex_template
for name, val in subs.items():
    redeem_hex = redeem_hex.replace(f"<{name}>", val)

assert "<" not in redeem_hex, f"unfilled placeholder remains: {redeem_hex}"
covenant_spk = bytes.fromhex(redeem_hex)

# BARE deployment: the covenant scriptPubKey IS the substituted covenant
# bytecode. It leads with OP_PUSHINPUTREF <REF>, so the funded UTXO exposes
# the ref opcode (conservation satisfied). NO P2SH wrap — that would hide the
# ref behind a914<hash>87 and burn it.
assert covenant_spk[:1] == b"\xd0", "covenant must lead with OP_PUSHINPUTREF (0xd0)"

# Phantom-ref guard: walk the spk the way Radiant consensus (GetPushRefs) does
# and assert EXACTLY one ref (the FT ref) is found. This is the check that
# would have caught the original bug before broadcast.
def _walk_refs(spk: bytes) -> list[tuple[int, str]]:
    REF_OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}
    out, i = [], 0
    while i < len(spk):
        op = spk[i]
        if op in REF_OPS:
            out.append((i, spk[i + 1:i + 37].hex())); i += 37; continue
        if 0x01 <= op <= 0x4B: i += 1 + op; continue
        if op == 0x4C: i += 2 + spk[i + 1]; continue
        if op == 0x4D: i += 3 + (spk[i + 1] | (spk[i + 2] << 8)); continue
        if op == 0x4E: i += 5 + int.from_bytes(spk[i + 1:i + 5], "little"); continue
        i += 1
    return out

_refs = _walk_refs(covenant_spk)
assert len(_refs) == 1 and _refs[0][1] == ref_wire.hex(), \
    f"phantom-ref check FAILED: parser found {_refs}, expected exactly [(0, {ref_wire.hex()})]"

print(json.dumps({
    "covenant_spk_hex": covenant_spk.hex(),
    "covenant_spk_len": len(covenant_spk),
    "ref_wire_hex": ref_wire.hex(),
    "taker_pkh": taker_pkh.hex(),
    "maker_pkh": maker_pkh.hex(),
    "expected_taker_ft_hash": expected_taker_ft_hash.hex(),
    "expected_maker_ft_hash": expected_maker_ft_hash.hex(),
    "amount": AMOUNT,
    "deadline": DEADLINE,
}))
