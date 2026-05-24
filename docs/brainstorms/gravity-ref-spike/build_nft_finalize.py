#!/usr/bin/env python3
"""Finalize the NFT swap: spend the NFT covenant UTXO via `finalize` (SPV proof)
-> standard 63-byte TAKER NFT output. scriptSig: <h1>..<h12> <branch padded to
20> <rawTx> OP_0. The fee comes from a separate plain-RXD input; output[0] is
the taker NFT (must hash to the covenant's expectedTakerNftHash). The covenant
also enforces outputs.length==1, refOutputCount(ref)==1, outputs[0].value ==
nftCarrierValue, and the singleton is conserved (carried from the covenant
input to the taker NFT output).
"""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

PROOF = json.load(open(sys.argv[1]))
COV_SPK_HEX = sys.argv[2]
COV_TXID = sys.argv[3]
COV_VOUT = int(sys.argv[4])
CARRIER_VALUE = int(sys.argv[5])
TAKER_NFT_SPK_HEX = sys.argv[6]
FEE_WIF = sys.argv[7]
FEE_TXID = sys.argv[8]
FEE_VOUT = int(sys.argv[9])
FEE_AMT = int(sys.argv[10])
FEE_SPK_HEX = sys.argv[11]
BRANCH_SLOTS = 20

fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
cov_spk = bytes.fromhex(COV_SPK_HEX)


def _push_data(b: bytes) -> bytes:
    n = len(b)
    if n < 0x4C:
        return bytes([n]) + b
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + b
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + b
    return b"\x4e" + n.to_bytes(4, "little") + b


def _finalize_scriptsig(tx, idx):
    headers = [bytes.fromhex(h) for h in PROOF["headers"]]
    branch = bytes.fromhex(PROOF["branch_hex"])
    real_depth = len(branch) // 33
    sentinel = bytes([0x02]) + b"\x00" * 32
    if real_depth < BRANCH_SLOTS:
        branch = branch + sentinel * (BRANCH_SLOTS - real_depth)
    raw_tx = bytes.fromhex(PROOF["raw_tx_hex"])
    parts = [_push_data(h) for h in headers]
    parts.append(_push_data(branch))
    parts.append(_push_data(raw_tx))
    parts.append(b"\x00")  # OP_0 selector = finalize
    return Script(b"".join(parts))


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(_push_data(sig + inp.sighash.to_bytes(1, "little")) + _push_data(fee_pub))


src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(cov_spk), CARRIER_VALUE)])
src.txid = lambda: COV_TXID  # type: ignore
cov_in = TransactionInput(source_transaction=src, source_txid=COV_TXID, source_output_index=COV_VOUT,
                          unlocking_script_template=to_unlock_script_template(_finalize_scriptsig, lambda: 3000))
cov_in.satoshis = CARRIER_VALUE
cov_in.locking_script = Script(cov_spk)

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

# The covenant enforces outputs.length == 1, so there is EXACTLY one output:
# the taker NFT (value == nftCarrierValue, carries the singleton). The entire
# fee input minus the carrier value is consumed as fee — so size the fee input
# appropriately upstream (no change output is permitted).
total_in = CARRIER_VALUE + FEE_AMT
fee_spent = total_in - CARRIER_VALUE
assert fee_spent >= 100_000_000, f"fee {fee_spent} below ~10k/byte for the big finalize tx"
tx = Transaction(
    tx_inputs=[cov_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(bytes.fromhex(TAKER_NFT_SPK_HEX)), CARRIER_VALUE),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"hex": raw, "txid": tx.txid(), "size": len(raw) // 2}))
