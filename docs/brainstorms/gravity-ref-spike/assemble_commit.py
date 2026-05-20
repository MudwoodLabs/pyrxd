#!/usr/bin/env python3
"""Assemble the unsigned raw commit tx (hand-serialized, since output[0] is a
non-standard commit script createrawtransaction won't take). Prints unsigned
raw hex + the prevout info the node needs to sign."""
import json
import sys

j = json.loads(sys.argv[1])

def varint(n: int) -> bytes:
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def push_script(s: bytes) -> bytes:
    return varint(len(s)) + s

commit_script = bytes.fromhex(j["commit_script_hex"])
pkh = bytes.fromhex(j["pkh"])
change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"  # P2PKH to same key

# Unsigned tx: version(4) | vin count | [outpoint(36) + scriptSig(empty) + seq(4)] | vout count | outputs | locktime(4)
version = (2).to_bytes(4, "little")
txid_le = bytes.fromhex(j["funding_txid"])[::-1]
outpoint = txid_le + j["funding_vout"].to_bytes(4, "little")
vin = varint(1) + outpoint + push_script(b"") + (0xFFFFFFFF).to_bytes(4, "little")

out0 = j["commit_value"].to_bytes(8, "little") + push_script(commit_script)
out1 = j["change_value"].to_bytes(8, "little") + push_script(change_spk)
vout = varint(2) + out0 + out1

locktime = (0).to_bytes(4, "little")
unsigned = version + vin + vout + locktime

print(json.dumps({
    "unsigned_hex": unsigned.hex(),
    "prevout_spk": "76a914" + j["pkh"] + "88ac",
    "funding_txid": j["funding_txid"],
    "funding_vout": j["funding_vout"],
    "funding_amount_btc": j.get("funding_amount_btc"),
}))
