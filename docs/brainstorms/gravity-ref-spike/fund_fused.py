#!/usr/bin/env python3
"""Phase-4 funding: transfer the standard FT into the FUSED FT covenant
(GravityFtCovenant). FT input signed by FT_WIF, fee input by FEE_WIF (they
differ now — FT is at the taker key, fee RXD at the deploy key).

Outputs: [0] fused-covenant FT (value = FT amount; carries the ref)
         [1] plain-RXD change to the fee key
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

FT_WIF = sys.argv[1]
FEE_WIF = sys.argv[2]
FUSED_SPK_HEX = sys.argv[3]
FT_TXID = sys.argv[4]
FT_VOUT = int(sys.argv[5])
FT_SCRIPT_HEX = sys.argv[6]
FT_AMOUNT = int(sys.argv[7])
FEE_TXID = sys.argv[8]
FEE_VOUT = int(sys.argv[9])
FEE_AMT = int(sys.argv[10])
FEE_SPK_HEX = sys.argv[11]

ft_key = PrivateKey(FT_WIF)
ft_pub = ft_key.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
fee_pkh = bytes(Hex20(fee_key.public_key().hash160()))


def _ft_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = ft_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(ft_pub))


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


ft_src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(bytes.fromhex(FT_SCRIPT_HEX)), FT_AMOUNT)])
ft_src.txid = lambda: FT_TXID  # type: ignore
ft_in = TransactionInput(source_transaction=ft_src, source_txid=FT_TXID, source_output_index=FT_VOUT,
                         unlocking_script_template=to_unlock_script_template(_ft_unlock, lambda: 110))
ft_in.satoshis = FT_AMOUNT
ft_in.locking_script = Script(bytes.fromhex(FT_SCRIPT_HEX))

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

FEE = 104_000_000  # >10k/byte for the ~10.2KB M=20 funding tx
change_val = FEE_AMT - FEE
assert change_val > 546, f"change too small: {change_val}"
change_spk = b"\x76\xa9\x14" + fee_pkh + b"\x88\xac"

tx = Transaction(
    tx_inputs=[ft_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(bytes.fromhex(FUSED_SPK_HEX)), FT_AMOUNT),
        TransactionOutput(Script(change_spk), change_val),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"hex": raw, "txid": tx.txid(), "fused_vout": 0,
                  "change_vout": 1, "change_val": change_val, "size": len(raw) // 2}))
