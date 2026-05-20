#!/usr/bin/env python3
"""Spike: build the premine FT deploy commit tx (step 1 of on-chain validation).

Builds the commit transaction's raw shape with pyrxd, leaving funding-input
signing to the node. Prints the raw commit tx hex for testmempoolaccept.

NOT a shipped builder — disposable spike harness (per the design doc's
"spike harness allowed before production builder" note).
"""
import json
import sys

from pyrxd.glyph.builder import GlyphBuilder, CommitParams
from pyrxd.glyph.types import GlyphMetadata
from pyrxd.security.types import Hex20
from pyrxd.keys import PrivateKey  # WIF -> key

# --- inputs (from the node) ---------------------------------------------------
WIF = sys.argv[1]
FUNDING_TXID = sys.argv[2]
FUNDING_VOUT = int(sys.argv[3])
FUNDING_AMOUNT = int(sys.argv[4])  # photons

key = PrivateKey(WIF)
pkh = Hex20(key.public_key().hash160())

# --- metadata: a tiny test FT -------------------------------------------------
meta = GlyphMetadata.for_dmint_ft(
    ticker="GRSPK",
    name="Gravity ref spike token",
    decimals=0,
    description="Disposable test FT for ref-bearing covenant validation.",
    image_url="https://example.org/grspk.png",
    image_sha256="aa" * 32,
)

builder = GlyphBuilder()
commit = builder.prepare_commit(
    CommitParams(
        metadata=meta,
        owner_pkh=pkh,
        change_pkh=pkh,
        funding_satoshis=FUNDING_AMOUNT,
    )
)

# commit output value: small, leaves room for reveal + fees.
# Premine supply chosen as 100000 units (= 100000 photons on the FT output).
SUPPLY = 100_000
# Reveal is ~475 bytes; Radiant's EFFECTIVE relay rate is 10_000 photons/byte
# (pyrxd MIN_FEE_RATE / ft.py:38), NOT the advertised 1_000/byte minrelaytxfee.
# So the reveal needs ~4.75M fee. commit_value = supply + generous fee headroom.
commit_value = SUPPLY + 8_000_000  # supply + ~8M reveal-fee headroom (10k/byte)
fee = commit.estimated_fee
change_value = FUNDING_AMOUNT - commit_value - fee

assert change_value > 546, f"change too small: {change_value}"

out = {
    "pkh": bytes(pkh).hex(),
    "commit_script_hex": commit.commit_script.hex(),
    "cbor_hex": commit.cbor_bytes.hex(),
    "payload_hash_hex": commit.payload_hash.hex(),
    "estimated_fee": fee,
    "commit_value": commit_value,
    "change_value": change_value,
    "supply": SUPPLY,
    "funding_txid": FUNDING_TXID,
    "funding_vout": FUNDING_VOUT,
}
print(json.dumps(out))
