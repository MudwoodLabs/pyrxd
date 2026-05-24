#!/usr/bin/env python3
"""Build the NFT-covenant funding scriptPubKey (the singleton-bearing UTXO whose
spend is gated by the full SPV + NFT covenant). UNLIKE FT there is NO epilogue
and NO prologue weld: the funded SPK IS the substituted covenant bytecode
verbatim — the singleton ref lives inside the body as `d8<REF>` (right after the
claimDeadline check), placed there by the compiled artifact.

Substitutes the NFT-covenant constructor params (push-wrapped per the rxdc ABI;
REF raw after the d8 opcode), then re-runs the two static guards (no stray
ref-opcode beyond the one genesis singleton; exactly one ref == genesis).

Deltas vs build_fused_ft_spk.py:
  - artifact = GravityNftCovenantAnyWallet20 (no `amount`; adds `nftCarrierValue`)
  - expected hashes are over the 63-byte NFT script (build_nft_locking_script),
    not the 75-byte FT holder script
  - NO FT epilogue / NO `bd d0 <ref>` weld appended — fused_nft = prologue
  - leading-opcode guard is "exactly one ref == genesis" (the singleton is NOT
    at offset 0; claimDeadline precedes it — consensus GetPushRefs is
    position-agnostic, proven in validate_nft_covenant.py)
"""
import hashlib
import json
import sys

from pyrxd.glyph.script import count_input_refs
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

ARTIFACT = "docs/brainstorms/gravity-ref-spike/GravityNftCovenantAnyWallet20.artifact.json"

GENESIS_TXID = sys.argv[1]
GENESIS_VOUT = int(sys.argv[2])
NFT_CARRIER_VALUE = int(sys.argv[3])
TAKER_WIF = sys.argv[4]
MAKER_WIF = sys.argv[5]
CLAIM_DEADLINE = int(sys.argv[6])
BTC_RECEIVE_HASH = sys.argv[7]      # 20-byte hex (p2wpkh hash) — per-offer derived in prod
BTC_SATOSHIS = int(sys.argv[8])
BTC_CHAIN_ANCHOR = sys.argv[9]      # 32-byte hex
EXPECTED_NBITS = sys.argv[10]       # 4-byte hex LE
EXPECTED_NBITS_NEXT = sys.argv[11]

ref = GlyphRef(txid=GENESIS_TXID, vout=GENESIS_VOUT)
ref_wire = ref.to_bytes()
taker_pkh = bytes(Hex20(PrivateKey(TAKER_WIF).public_key().hash160()))
maker_pkh = bytes(Hex20(PrivateKey(MAKER_WIF).public_key().hash160()))
hex_template = json.load(open(ARTIFACT))["hex"]


def scriptnum(n: int) -> bytes:
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + b
    if n <= 255:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


def nft_script(pkh: bytes) -> bytes:
    """Canonical 63-byte NFT singleton script for (pkh, REF) — mirror of
    pyrxd.glyph.script.build_nft_locking_script. The expected settlement output."""
    return b"\xd8" + ref_wire + b"\x75\x76\xa9\x14" + pkh + b"\x88\xac"


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


expected_taker_nft_hash = hash256(nft_script(taker_pkh))
expected_maker_nft_hash = hash256(nft_script(maker_pkh))

subs = {
    "REF": ref_wire.hex(),  # raw — follows the d8 opcode
    "btcReceiveHash": push(bytes.fromhex(BTC_RECEIVE_HASH)).hex(),
    "btcSatoshis": push(scriptnum(BTC_SATOSHIS)).hex(),
    "btcChainAnchor": push(bytes.fromhex(BTC_CHAIN_ANCHOR)).hex(),
    "expectedNBits": push(bytes.fromhex(EXPECTED_NBITS)).hex(),
    "expectedNBitsNext": push(bytes.fromhex(EXPECTED_NBITS_NEXT)).hex(),
    "claimDeadline": push(scriptnum(CLAIM_DEADLINE)).hex(),
    "nftCarrierValue": push(scriptnum(NFT_CARRIER_VALUE)).hex(),
    "expectedTakerNftHash": push(expected_taker_nft_hash).hex(),
    "expectedMakerNftHash": push(expected_maker_nft_hash).hex(),
}
spk_hex = hex_template
for name, val in subs.items():
    spk_hex = spk_hex.replace(f"<{name}>", val)
assert "<" not in spk_hex, f"unfilled placeholder: {spk_hex[spk_hex.index('<'):][:40]}"
fused_nft = bytes.fromhex(spk_hex)  # NO epilogue, NO weld — the covenant IS the SPK


# Static guard: exactly one ref == genesis singleton (no phantom). The
# singleton is NOT at offset 0 (claimDeadline check precedes it); the guard is
# position-agnostic, matching consensus GetPushRefs.
refs = count_input_refs(fused_nft)
assert set(refs) == {ref_wire}, f"GUARD FAIL: refs {[r.hex() for r in refs]} != {{{ref_wire.hex()}}}"

print(
    json.dumps(
        {
            "fused_nft_spk_hex": fused_nft.hex(),
            "len": len(fused_nft),
            "ref_wire_hex": ref_wire.hex(),
            "expected_taker_nft_hash": expected_taker_nft_hash.hex(),
            "expected_maker_nft_hash": expected_maker_nft_hash.hex(),
            "taker_pkh": taker_pkh.hex(),
            "maker_pkh": maker_pkh.hex(),
            "taker_nft_script": nft_script(taker_pkh).hex(),
            "maker_nft_script": nft_script(maker_pkh).hex(),
            "nft_carrier_value": NFT_CARRIER_VALUE,
            "claim_deadline": CLAIM_DEADLINE,
        }
    )
)
