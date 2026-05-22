#!/usr/bin/env python3
"""Phase-4 any-wallet integration: transform the fused FT covenant
(GravityFtCovenant.rxd) so its BTC-payment verification accepts ANY
single-sig-segwit-input wallet tx (multi-input, change anywhere) instead of
the fixed single-input/fixed-offset shape. Reads the fused covenant on stdin,
writes the any-wallet covenant on stdout.

Two replacements (everything else verbatim — SPV header/Merkle, FT hardening,
hash-compare routes):
1. The fixed tx-layout block -> input-skip (per-input scriptSigLen varint,
   caps <=4) computing `pos` at the output-count, reading `nOut`.
2. The fixed-offset P2WPKH payment block -> output-scan (per-output scriptLen
   varint, caps <=4) setting `found`, then `require(found)`.

Safety: rawTx is Merkle-pinned (hash256(rawTx) leaf), so parsing it is
forgery-proof; the covenant computes every offset itself (no attacker offset
arg) — preserves audit-03-C2's intent. Caps are liveness limits.
"""
import sys

src = sys.stdin.read()

# --- Replacement 1: tx-layout block -> input-skip ---
OLD_LAYOUT_START = "            // --- Tx-structure constraint (forces known output offset) ---"
# the block runs through the outputCountByteVal != 0xff require.
old_layout_anchor_end = "            require(outputCountByteVal != 0xff);"
i0 = src.index(OLD_LAYOUT_START)
i1 = src.index(old_layout_anchor_end) + len(old_layout_anchor_end)
new_input_skip = """            // --- Any-wallet input skip (any-wallet design note 2026-05-20) ---
            // rawTx is Merkle-pinned (hash256(rawTx) leaf), so parsing it is
            // forgery-proof; we compute every offset ourselves (no attacker
            // offset arg). Caps: <=4 inputs / <=4 outputs (liveness, not safety).
            require(rawTx.length > 64);
            int nIn = int(rawTx.split(4)[1].split(1)[0]);
            require(nIn >= 1);
            require(nIn <= 4);
            int pos = 5;
            // Skip each input: 36 outpoint + scriptSigLen varint(1) + scriptSig + 4 seq.
            // Handles native-segwit/P2TR (scriptSig 0x00) and P2SH-P2WPKH (0x16..).
            int ssl1 = int(rawTx.split(pos + 36)[1].split(1)[0]);
            pos = pos + 36 + 1 + ssl1 + 4;
            if (nIn >= 2) { int ssl2 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl2 + 4; }
            if (nIn >= 3) { int ssl3 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl3 + 4; }
            if (nIn >= 4) { int ssl4 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl4 + 4; }
            // pos now -> output-count varint.
            int nOut = int(rawTx.split(pos)[1].split(1)[0]);
            require(nOut >= 1);
            require(nOut <= 4);
            pos = pos + 1;"""
src = src[:i0] + new_input_skip + src[i1:]

# --- Replacement 2: fixed-offset payment block -> output-scan ---
OLD_PAY = """            // --- BTC payment verification (P2WPKH) ---
            // P2WPKH: 31-byte output
            bytes output = rawTx.split(outputOffset)[1].split(31)[0];
            int value = int(output.split(8)[0]);
            require(value >= btcSatoshis);
            bytes scriptSection = output.split(8)[1];
            bytes prefix = scriptSection.split(3)[0];
            require(prefix == 0x160014);
            bytes hash = scriptSection.split(3)[1];
            require(hash == btcReceiveHash);"""
# Per-output 4-way match: P2WPKH(22) / P2PKH(25) / P2SH(23) / P2TR(34).
# Each output at byte `p`: value(8) + scriptLen varint(1) + script(scriptLen).
# btcReceiveHash is the maker's committed hash (20B for the first three,
# 32B for P2TR); only the shape matching the maker's address type + hash fires.
def _scan_one(vn: str, sln: str) -> str:
    return (
        f"            int {vn} = int(rawTx.split(pos)[1].split(8)[0]);\n"
        f"            int {sln} = int(rawTx.split(pos + 8)[1].split(1)[0]);\n"
        # P2WPKH: 0x0014 + 20B hash
        f"            if ({sln} == 22) {{ if (rawTx.split(pos + 9)[1].split(2)[0] == 0x0014) {{ if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) {{ if ({vn} >= btcSatoshis) {{ found = true; }} }} }} }}\n"
        # P2PKH: 0x76a914 + 20B hash + 0x88ac
        f"            if ({sln} == 25) {{ if (rawTx.split(pos + 9)[1].split(3)[0] == 0x76a914) {{ if (rawTx.split(pos + 12)[1].split(20)[0] == btcReceiveHash) {{ if (rawTx.split(pos + 32)[1].split(2)[0] == 0x88ac) {{ if ({vn} >= btcSatoshis) {{ found = true; }} }} }} }} }}\n"
        # P2SH: 0xa914 + 20B hash + 0x87
        f"            if ({sln} == 23) {{ if (rawTx.split(pos + 9)[1].split(2)[0] == 0xa914) {{ if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) {{ if (rawTx.split(pos + 31)[1].split(1)[0] == 0x87) {{ if ({vn} >= btcSatoshis) {{ found = true; }} }} }} }} }}\n"
        # P2TR: 0x5120 + 32B x-only key
        f"            if ({sln} == 34) {{ if (rawTx.split(pos + 9)[1].split(2)[0] == 0x5120) {{ if (rawTx.split(pos + 11)[1].split(32)[0] == btcReceiveHash) {{ if ({vn} >= btcSatoshis) {{ found = true; }} }} }} }}\n"
    )

NEW_SCAN = (
    "            // --- Any-wallet output scan: find the maker payment >= btcSatoshis ---\n"
    "            // Matches all 4 BTC output types (P2WPKH/P2PKH/P2SH/P2TR) at ANY\n"
    "            // output index (change anywhere). Each output: value(8) + scriptLen\n"
    "            // varint(1) + script(scriptLen). btcReceiveHash = maker's committed\n"
    "            // hash (20B for the first three, 32B for P2TR).\n"
    "            bool found = false;\n"
    + _scan_one("v1", "sl1")
    + "            pos = pos + 9 + sl1;\n"
    + "            if (nOut >= 2) {\n" + _scan_one("v2", "sl2") + "                pos = pos + 9 + sl2;\n            }\n"
    + "            if (nOut >= 3) {\n" + _scan_one("v3", "sl3") + "                pos = pos + 9 + sl3;\n            }\n"
    + "            if (nOut >= 4) {\n" + _scan_one("v4", "sl4") + "            }\n"
    + "            require(found);"
)
assert OLD_PAY in src, "fixed-offset payment block not found verbatim"
src = src.replace(OLD_PAY, NEW_SCAN, 1)

# Rename contract so the artifact is distinct.
src = src.replace("contract GravityFtCovenantFlat", "contract GravityFtCovenantAnyWalletFlat")

# Sanity: outputOffset must be fully gone.
assert "outputOffset" not in src, "outputOffset leaked — replacement incomplete"
assert "found" in src and "nOut" in src

sys.stdout.write(src)
