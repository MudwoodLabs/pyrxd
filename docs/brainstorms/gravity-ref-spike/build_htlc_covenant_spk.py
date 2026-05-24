#!/usr/bin/env python3
"""Build a funded HTLC-covenant scriptPubKey (Phase 2), FT or NFT variant.

Model: build_fused_nft_spk.py / build_fused_ft_spk.py. Substitutes the HTLC
constructor params into the compiled artifact template, then re-runs the static
guards (exactly one genesis ref, no phantom; opcode-level bare-0xbd guard).

KEY HARD-REQUIREMENT differences from the SPV builders (from .csv_spike.json):
  - refundCsv MUST be MINIMAL-pushed (OP_N for 1..16) or MANDATORY MINIMALDATA
    bricks the covenant. See _minimal_num_push().
  - hashlock is a 32-byte sha256 image, push-wrapped (data param).
  - expected{Taker,Maker}Hash are hash256 over the proper holder script:
      FT  -> 75-byte FT holder script  (p2pkh + bd d0 <ref> dec0e9aa...)
      NFT -> 63-byte NFT singleton script (d8 <ref> 75 + p2pkh)
  - REF is raw (follows the d0/d8 opcode).

FT vs NFT (the consensus-gate difference):
  FT  funded SPK = <substituted covenant> bd d0 <ref> dec0e9aa76e378e4a269e69d
      (the FT epilogue weld is appended POST-COMPILE, same as build_fused_ft_spk.py;
       L2 codeScriptHashValueSum conservation lives in that epilogue).
  NFT funded SPK = the substituted covenant VERBATIM (no epilogue, no weld;
       the singleton ref d8<ref> is inside the compiled body).

RXD variant (Phase 3 addition — NO ref machinery):
  GravityHtlcCovenantRxd takes (hashlock, refundCsv, amount, expectedTakerHash,
  expectedMakerHash). The asset is native RXD, so there is NO genesis ref, NO
  d0/d8 prologue, NO FT epilogue weld. expected{Taker,Maker}Hash = hash256 of the
  25-byte P2PKH holder script (76a914<pkh>88ac). The funded SPK is the substituted
  compiled body VERBATIM. GUARD 1 (bare-0xbd) must find NONE (no ref ops at all);
  GUARD 2 (count_input_refs) must find NONE.

Usage:
  build_htlc_covenant_spk.py ft  <genesis_txid> <vout> <amount>          <taker_wif> <maker_wif> <hashlock_hex> <refund_csv>
  build_htlc_covenant_spk.py nft <genesis_txid> <vout> <nft_carrier_val> <taker_wif> <maker_wif> <hashlock_hex> <refund_csv>
  build_htlc_covenant_spk.py rxd <amount> <taker_wif> <maker_wif> <hashlock_hex> <refund_csv>
"""
import hashlib
import json
import sys

sys.path.insert(0, "src")
from pyrxd.glyph.script import count_input_refs  # noqa: E402
from pyrxd.glyph.types import GlyphRef  # noqa: E402
from pyrxd.keys import PrivateKey  # noqa: E402
from pyrxd.security.types import Hex20  # noqa: E402

FT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")
ART_DIR = "docs/brainstorms/gravity-ref-spike"


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


def minimal_num_push(n: int) -> bytes:
    """Minimal CScriptNum push (MANDATORY MINIMALDATA, .csv_spike.json finding):
    OP_1..OP_16 for 1..16, OP_0 for 0, else a length-prefixed scriptnum. A
    non-minimal push (e.g. 0x0102 for `2`) trips 'Data push larger than
    necessary' and bricks the covenant — refundCsv is a small int so this matters."""
    if n == 0:
        return b"\x00"  # OP_0
    if 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 (0x51) .. OP_16 (0x60)
    return push(scriptnum(n))


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _opcode_bd_positions(spk: bytes):
    """Walk the script as an opcode stream and return every position holding a
    bare 0xbd (OP_PUSHINPUTREFSINGLETON's sibling / FT codeScriptHash boundary
    opcode). For the FT funded SPK the ONLY legitimate bare 0xbd is the epilogue
    weld at offset len(prologue); for NFT there must be NONE. A 0xbd that lands
    in an opcode position inside the new sha256/CSV prologue would move the
    codeScriptHash boundary and silently break L2 conservation."""
    REF_OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}
    i = 0
    bds = []
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


def ft_holder_script(pkh: bytes, ref_wire: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac\xbd\xd0" + ref_wire + FT_EPILOGUE


def nft_holder_script(pkh: bytes, ref_wire: bytes) -> bytes:
    return b"\xd8" + ref_wire + b"\x75\x76\xa9\x14" + pkh + b"\x88\xac"


def rxd_holder_script(pkh: bytes) -> bytes:
    """The native-RXD holder script is a plain 25-byte P2PKH (no ref, no weld)."""
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def _build_rxd() -> None:
    """RXD variant: no ref/genesis args. argv: amount taker_wif maker_wif hashlock_hex refund_csv."""
    amount = int(sys.argv[2])
    taker_wif, maker_wif = sys.argv[3], sys.argv[4]
    hashlock = bytes.fromhex(sys.argv[5])
    refund_csv = int(sys.argv[6])
    assert len(hashlock) == 32, f"hashlock must be 32 bytes, got {len(hashlock)}"

    taker_pkh = bytes(Hex20(PrivateKey(taker_wif).public_key().hash160()))
    maker_pkh = bytes(Hex20(PrivateKey(maker_wif).public_key().hash160()))
    expected_taker = hash256(rxd_holder_script(taker_pkh))
    expected_maker = hash256(rxd_holder_script(maker_pkh))

    artifact = f"{ART_DIR}/GravityHtlcCovenantRxd.artifact.json"
    subs = {
        "hashlock": push(hashlock).hex(),
        "refundCsv": minimal_num_push(refund_csv).hex(),
        "amount": push(scriptnum(amount)).hex(),
        "expectedTakerHash": push(expected_taker).hex(),
        "expectedMakerHash": push(expected_maker).hex(),
    }
    spk_hex = json.load(open(artifact))["hex"]
    for name, val in subs.items():
        spk_hex = spk_hex.replace(f"<{name}>", val)
    assert "<" not in spk_hex, f"unfilled placeholder: {spk_hex[spk_hex.index('<'):][:40]}"
    fused = bytes.fromhex(spk_hex)

    # GUARD 1: native RXD has NO ref op and NO FT epilogue — there must be NO bare 0xbd.
    bds = _opcode_bd_positions(fused)
    assert bds == [], f"GUARD 1 FAIL (RXD): unexpected bare 0xbd at {bds}"
    # GUARD 2: there must be NO input refs at all (no genesis ref to bind).
    refs = count_input_refs(fused)
    assert list(refs) == [], f"GUARD 2 FAIL (RXD): unexpected refs {[r.hex() for r in refs]}"

    print(json.dumps({
        "variant": "rxd",
        "fused_spk_hex": fused.hex(),
        "len": len(fused),
        "prologue_len": len(fused),
        "hashlock_hex": hashlock.hex(),
        "refund_csv": refund_csv,
        "amount": amount,
        "expected_taker_hash": expected_taker.hex(),
        "expected_maker_hash": expected_maker.hex(),
        "taker_script": rxd_holder_script(taker_pkh).hex(),
        "maker_script": rxd_holder_script(maker_pkh).hex(),
        "taker_pkh": taker_pkh.hex(),
        "maker_pkh": maker_pkh.hex(),
    }))


def main() -> None:
    variant = sys.argv[1]
    if variant == "rxd":
        _build_rxd()
        return

    genesis_txid = sys.argv[2]
    genesis_vout = int(sys.argv[3])
    value_param = int(sys.argv[4])  # FT amount OR nft carrier value
    taker_wif, maker_wif = sys.argv[5], sys.argv[6]
    hashlock_hex = sys.argv[7]
    refund_csv = int(sys.argv[8])

    assert variant in ("ft", "nft"), "variant must be ft|nft|rxd"
    hashlock = bytes.fromhex(hashlock_hex)
    assert len(hashlock) == 32, f"hashlock must be 32 bytes, got {len(hashlock)}"

    ref = GlyphRef(txid=genesis_txid, vout=genesis_vout)
    ref_wire = ref.to_bytes()
    taker_pkh = bytes(Hex20(PrivateKey(taker_wif).public_key().hash160()))
    maker_pkh = bytes(Hex20(PrivateKey(maker_wif).public_key().hash160()))

    if variant == "ft":
        artifact = f"{ART_DIR}/GravityHtlcCovenantFt.artifact.json"
        expected_taker = hash256(ft_holder_script(taker_pkh, ref_wire))
        expected_maker = hash256(ft_holder_script(maker_pkh, ref_wire))
        taker_script = ft_holder_script(taker_pkh, ref_wire)
        maker_script = ft_holder_script(maker_pkh, ref_wire)
        subs = {
            "REF": ref_wire.hex(),
            "hashlock": push(hashlock).hex(),
            "refundCsv": minimal_num_push(refund_csv).hex(),
            "amount": push(scriptnum(value_param)).hex(),
            "expectedTakerFtHash": push(expected_taker).hex(),
            "expectedMakerFtHash": push(expected_maker).hex(),
        }
    else:
        artifact = f"{ART_DIR}/GravityHtlcCovenantNft.artifact.json"
        expected_taker = hash256(nft_holder_script(taker_pkh, ref_wire))
        expected_maker = hash256(nft_holder_script(maker_pkh, ref_wire))
        taker_script = nft_holder_script(taker_pkh, ref_wire)
        maker_script = nft_holder_script(maker_pkh, ref_wire)
        subs = {
            "REF": ref_wire.hex(),
            "hashlock": push(hashlock).hex(),
            "refundCsv": minimal_num_push(refund_csv).hex(),
            "nftCarrierValue": push(scriptnum(value_param)).hex(),
            "expectedTakerNftHash": push(expected_taker).hex(),
            "expectedMakerNftHash": push(expected_maker).hex(),
        }

    spk_hex = json.load(open(artifact))["hex"]
    for name, val in subs.items():
        spk_hex = spk_hex.replace(f"<{name}>", val)
    assert "<" not in spk_hex, f"unfilled placeholder: {spk_hex[spk_hex.index('<'):][:40]}"
    prologue = bytes.fromhex(spk_hex)

    if variant == "ft":
        fused = prologue + b"\xbd\xd0" + ref_wire + FT_EPILOGUE
        # GUARD 1: the only bare 0xbd is the epilogue weld at offset len(prologue).
        bds = _opcode_bd_positions(fused)
        assert bds == [len(prologue)], f"GUARD 1 FAIL (FT): bd positions {bds} != [{len(prologue)}]"
    else:
        fused = prologue  # NFT funded UTXO IS the compiled script verbatim.
        # GUARD 1: NFT has NO FT epilogue — there must be NO bare 0xbd at all.
        bds = _opcode_bd_positions(fused)
        assert bds == [], f"GUARD 1 FAIL (NFT): unexpected bare 0xbd at {bds} (FT-leak?)"

    # GUARD 2: exactly one ref == the genesis ref (no phantom).
    refs = count_input_refs(fused)
    assert set(refs) == {ref_wire}, f"GUARD 2 FAIL: refs {[r.hex() for r in refs]} != {{{ref_wire.hex()}}}"

    print(json.dumps({
        "variant": variant,
        "fused_spk_hex": fused.hex(),
        "len": len(fused),
        "prologue_len": len(prologue),
        "ref_wire_hex": ref_wire.hex(),
        "hashlock_hex": hashlock.hex(),
        "refund_csv": refund_csv,
        "expected_taker_hash": expected_taker.hex(),
        "expected_maker_hash": expected_maker.hex(),
        "taker_script": taker_script.hex(),
        "maker_script": maker_script.hex(),
        "taker_pkh": taker_pkh.hex(),
        "maker_pkh": maker_pkh.hex(),
    }))


if __name__ == "__main__":
    main()
