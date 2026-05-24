#!/usr/bin/env python3
"""Phase-2 GATE spike (HTLC plan): prove the Radiant `tx.age`/CSV relative-timelock
refund leg works on MAINNET.

Three sub-commands:
  spk        — print the bare CSV-covenant scriptPubKey (substitute refundCsv + ownerPkh)
  fund       — build a tx funding the covenant SPK from a deploy UTXO
  refund     — build a refund spend of the covenant UTXO with v2 + nSequence=refundCsv
               (--premature sets nSequence=0 / version=1 so BIP68 should NOT engage → reject)

Covenant (rxdc): `<refundCsv> OP_CHECKSEQUENCEVERIFY OP_DROP 76a914 <ownerPkh> ... OP_EQUAL`
hex template: <refundCsv>b2750376a914<ownerPkh>7e0288ac7e00cd87

BIP68 (verified consensus-enforced, validation.cpp ConnectBlock ~2012): the SPEND must
be nVersion>=2 AND its input nSequence must encode the relative lock (block count, with
the type-flag clear and disable-flag clear) for OP_CHECKSEQUENCEVERIFY to be satisfiable.
"""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

ARTIFACT = "/tmp/csv_min3.artifact.json"


def _scriptnum(n: int) -> bytes:
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
    """Minimal CScriptNum push (MANDATORY MINIMALDATA): OP_1..OP_16 for 1..16,
    OP_0 for 0, else a length-prefixed scriptnum. CSV operands are small ints."""
    if n == 0:
        return b"\x00"  # OP_0
    if 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 (0x51) .. OP_16 (0x60)
    return _push(_scriptnum(n))


def _hash256(b: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _owner_p2pkh(owner_pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + owner_pkh + b"\x88\xac"


def build_spk(refund_csv: int, owner_pkh: bytes) -> bytes:
    # Hash-compare pattern (matches the proven FT/NFT covenants): pin output[0] to
    # hash256(owner P2PKH script). _push the 32-byte hash (data param, push-wrapped).
    expected = _hash256(_owner_p2pkh(owner_pkh))
    tmpl = json.load(open(ARTIFACT))["hex"]
    spk = tmpl.replace("<refundCsv>", _minimal_num_push(refund_csv).hex())
    spk = spk.replace("<expectedOwnerHash>", _push(expected).hex())
    assert "<" not in spk, f"unfilled: {spk}"
    return bytes.fromhex(spk)


cmd = sys.argv[1]

if cmd == "spk":
    refund_csv = int(sys.argv[2])
    owner_pkh = bytes(Hex20(PrivateKey(sys.argv[3]).public_key().hash160()))
    spk = build_spk(refund_csv, owner_pkh)
    print(json.dumps({"spk_hex": spk.hex(), "len": len(spk), "owner_pkh": owner_pkh.hex()}))

elif cmd == "fund":
    # spike_csv_refund.py fund <deploy_wif> <spk_hex> <fee_txid> <fee_vout> <fee_amt> <fee_spk_hex> <carrier>
    deploy_wif, spk_hex, fee_txid = sys.argv[2], sys.argv[3], sys.argv[4]
    fee_vout, fee_amt = int(sys.argv[5]), int(sys.argv[6])
    fee_spk_hex, carrier = sys.argv[7], int(sys.argv[8])
    key = PrivateKey(deploy_wif)
    pub = key.public_key().serialize()
    pkh = bytes(Hex20(key.public_key().hash160()))

    def _unlock(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    src_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(fee_vout)]
    src_outs.append(TransactionOutput(Script(bytes.fromhex(fee_spk_hex)), fee_amt))
    src = Transaction(tx_inputs=[], tx_outputs=src_outs)
    src.txid = lambda: fee_txid  # type: ignore
    fin = TransactionInput(source_transaction=src, source_txid=fee_txid, source_output_index=fee_vout,
                           unlocking_script_template=to_unlock_script_template(_unlock, lambda: 110))
    fin.satoshis = fee_amt
    fin.locking_script = Script(bytes.fromhex(fee_spk_hex))
    FEE = 3_000_000
    change = fee_amt - carrier - FEE
    assert change > 546, f"change {change}"
    change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    tx = Transaction(tx_inputs=[fin], tx_outputs=[
        TransactionOutput(Script(bytes.fromhex(spk_hex)), carrier),
        TransactionOutput(Script(change_spk), change),
    ])
    tx.sign()
    raw = tx.serialize().hex()
    print(json.dumps({"hex": raw, "txid": tx.txid(), "covenant_vout": 0, "carrier": carrier, "size": len(raw) // 2}))

elif cmd == "refund":
    # spike_csv_refund.py refund <owner_wif> <spk_hex> <cov_txid> <cov_vout> <carrier> <refund_csv> <fee_txid> <fee_vout> <fee_amt> <fee_spk_hex> [--premature]
    owner_wif, spk_hex, cov_txid = sys.argv[2], sys.argv[3], sys.argv[4]
    cov_vout, carrier, refund_csv = int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])
    fee_txid, fee_vout, fee_amt, fee_spk_hex = sys.argv[8], int(sys.argv[9]), int(sys.argv[10]), sys.argv[11]
    premature = "--premature" in sys.argv

    owner = PrivateKey(owner_wif)
    owner_pkh = bytes(Hex20(owner.public_key().hash160()))
    fee_key = PrivateKey(fee_wif := owner_wif)  # same key funds the fee here for simplicity
    fee_pub = fee_key.public_key().serialize()
    cov_spk = bytes.fromhex(spk_hex)

    def _cov_unlock(tx, idx):
        # Multi-function covenant dispatches on a selector: refund() is function index 0,
        # so the scriptSig pushes OP_0. (A single-function covenant emits no dispatch and
        # an empty scriptSig leaves OP_DUP with an empty stack -> "stack size" failure —
        # the HTLC covenant MUST be multi-function claim/refund with a selector, matching
        # the proven FT/NFT covenants.)
        return Script(b"\x00")  # OP_0 selector = refund (function index 0)

    def _fee_unlock(tx, idx):
        inp = tx.inputs[idx]
        sig = fee_key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))

    # Each input gets its own synthetic source tx keyed to its real txid (cov and fee may
    # be different txids). A synthetic source with the spent output at its real index avoids
    # the "output index out of range" sighash error.
    def _src_with_output(txid: str, vout: int, spk: bytes, val: int) -> Transaction:
        outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
        outs.append(TransactionOutput(Script(spk), val))
        t = Transaction(tx_inputs=[], tx_outputs=outs)
        t.txid = lambda: txid  # type: ignore
        return t

    cov_src = _src_with_output(cov_txid, cov_vout, cov_spk, carrier)
    cov_in = TransactionInput(source_transaction=cov_src, source_txid=cov_txid, source_output_index=cov_vout,
                              unlocking_script_template=to_unlock_script_template(_cov_unlock, lambda: 4))
    cov_in.satoshis = carrier
    cov_in.locking_script = Script(cov_spk)
    # BIP68: nSequence encodes the relative lock (block count, type-flag=0). disable-flag (1<<31) clear.
    cov_in.sequence = 0 if premature else refund_csv

    fee_src = _src_with_output(fee_txid, fee_vout, bytes.fromhex(fee_spk_hex), fee_amt)
    fee_in = TransactionInput(source_transaction=fee_src, source_txid=fee_txid, source_output_index=fee_vout,
                              unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
    fee_in.satoshis = fee_amt
    fee_in.locking_script = Script(bytes.fromhex(fee_spk_hex))
    fee_in.sequence = 0xFFFFFFFF if premature else 0xFFFFFFFE  # fee input needn't carry the relative lock

    # output[0] must be the owner P2PKH (covenant checks this); send carrier there.
    owner_lock = b"\x76\xa9\x14" + owner_pkh + b"\x88\xac"
    # Refund tx ~268B; node effective 0.10 RXD/kB ceil -> ~2.68M min. 3M = headroom.
    FEE = 3_000_000
    out0_val = carrier
    fee_change = fee_amt - FEE
    assert fee_change > 546
    tx = Transaction(
        tx_inputs=[cov_in, fee_in],
        tx_outputs=[
            TransactionOutput(Script(owner_lock), out0_val),
            TransactionOutput(Script(b"\x76\xa9\x14" + owner_pkh + b"\x88\xac"), fee_change),
        ],
    )
    tx.version = 1 if premature else 2  # BIP68 needs v2
    tx.sign()
    raw = tx.serialize().hex()
    print(json.dumps({"hex": raw, "txid": tx.txid(), "version": tx.version,
                      "cov_sequence": cov_in.sequence, "premature": premature, "size": len(raw) // 2}))
