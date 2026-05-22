#!/usr/bin/env python3
"""Build a MULTI-INPUT (2-input) native-segwit BTC payment to the maker — the
shape the single-input covenant REJECTS but the any-wallet covenant accepts.
Spends two UTXOs at the funding wallet -> output[0] = payment to maker,
output[1] = change back to the funding wallet. BIP143 segwit-v0, both inputs
the same key (funding wallet). Prints signed tx hex + txid.

Args: <utxo0_txid> <utxo0_vout> <utxo0_value> <utxo1_txid> <utxo1_vout> <utxo1_value>
      <maker_hash20_hex> <amount_sats> <fee_sats>
Reads the funding WIF from .aw_taker_funding.json.
"""
import hashlib
import json
import struct
import sys

import base58
import coincurve

u0t, u0v, u0val = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
u1t, u1v, u1val = sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
MAKER = bytes.fromhex(sys.argv[7])
AMT = int(sys.argv[8])
FEE = int(sys.argv[9])

fund = json.load(open("docs/brainstorms/gravity-ref-spike/.aw_taker_funding.json"))
priv = base58.b58decode_check(fund["wif"])[1:33]
sk = coincurve.PrivateKey(priv)
pub = sk.public_key.format(compressed=True)
pkh = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
assert pkh.hex() == fund["pkh"], "funding key mismatch"


def h256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


VERSION = struct.pack("<I", 2)
LOCKTIME = struct.pack("<I", 0)
SEQ = b"\xff\xff\xff\xff"

ins = [(bytes.fromhex(u0t)[::-1], u0v, u0val), (bytes.fromhex(u1t)[::-1], u1v, u1val)]
outpoints = b"".join(txid + struct.pack("<I", v) for txid, v, _ in ins)
sequences = SEQ * len(ins)
hash_prevouts = h256(outpoints)
hash_sequence = h256(sequences)

change_val = u0val + u1val - AMT - FEE
assert change_val >= 0, f"insufficient: {u0val+u1val} < {AMT}+{FEE}"
pay_spk = b"\x00\x14" + MAKER
out0 = struct.pack("<Q", AMT) + bytes([len(pay_spk)]) + pay_spk
change_spk = b"\x00\x14" + pkh
DUST = 294
outs = out0
if change_val >= DUST:
    outs += struct.pack("<Q", change_val) + bytes([len(change_spk)]) + change_spk
    n_out = 2
else:
    n_out = 1  # change is dust -> fold into fee
hash_outputs = h256(outs)

script_code = b"\x76\xa9\x14" + pkh + b"\x88\xac"
sc = bytes([len(script_code)]) + script_code

witnesses = b""
vin = b""
for txid, v, val in ins:
    outpoint = txid + struct.pack("<I", v)
    preimage = (
        VERSION + hash_prevouts + hash_sequence + outpoint + sc + struct.pack("<Q", val) + SEQ + hash_outputs + LOCKTIME + struct.pack("<I", 1)
    )
    sig = sk.sign(h256(preimage), hasher=None) + b"\x01"
    witnesses += b"\x02" + bytes([len(sig)]) + sig + bytes([len(pub)]) + pub
    vin += outpoint + b"\x00" + SEQ  # empty scriptSig (native segwit)

raw = VERSION + b"\x00\x01" + bytes([len(ins)]) + vin + bytes([n_out]) + outs + witnesses + LOCKTIME
nonwit = VERSION + bytes([len(ins)]) + vin + bytes([n_out]) + outs + LOCKTIME
txid = h256(nonwit)[::-1].hex()
print(json.dumps({"tx_hex": raw.hex(), "txid": txid, "n_inputs": len(ins), "n_outputs": n_out, "change": change_val}))
