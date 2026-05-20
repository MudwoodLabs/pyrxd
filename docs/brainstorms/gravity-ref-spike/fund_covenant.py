#!/usr/bin/env python3
"""Spike step 4: fund the covenant — transfer the minted FT into the BARE
covenant scriptPubKey. The FT input is signed by the deploy key (FT script is
P2PKH-prefixed). A second plain-RXD input covers the fee; change returns to the
deploy key. Output[0] = covenant spk (value=FT amount, carries the ref)."""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

DEPLOY_WIF = sys.argv[1]
cov = json.loads(sys.argv[2])
FT_TXID = sys.argv[3]
FT_VOUT = int(sys.argv[4])
FT_SCRIPT_HEX = sys.argv[5]   # the 75-byte FT locking script on the FT UTXO
FT_AMOUNT = int(sys.argv[6])  # 100000 (= photons on FT UTXO)
FEE_TXID = sys.argv[7]
FEE_VOUT = int(sys.argv[8])
FEE_AMT = int(sys.argv[9])
FEE_SPK_HEX = sys.argv[10]

key = PrivateKey(DEPLOY_WIF)
pubkey = key.public_key().serialize()
pkh = bytes(Hex20(key.public_key().hash160()))
covenant_spk = bytes.fromhex(cov["covenant_spk_hex"])

# --- FT input (P2PKH-style spend of the FT-prefixed script) ----------------
def _ft_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pubkey))

ft_src = Transaction(tx_inputs=[], tx_outputs=[
    TransactionOutput(Script(bytes.fromhex(FT_SCRIPT_HEX)), FT_AMOUNT)])
ft_src.txid = lambda: FT_TXID  # type: ignore
ft_in = TransactionInput(source_transaction=ft_src, source_txid=FT_TXID,
                         source_output_index=FT_VOUT,
                         unlocking_script_template=to_unlock_script_template(_ft_unlock, lambda: 110))
ft_in.satoshis = FT_AMOUNT
ft_in.locking_script = Script(bytes.fromhex(FT_SCRIPT_HEX))

# --- fee input (plain P2PKH owned by deploy key) ---------------------------
def _p2pkh_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pubkey))

# Shim must place the fee output at the real FEE_VOUT index (pad earlier vouts).
_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID,
                          source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_p2pkh_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

# --- outputs: covenant (FT_AMOUNT, carries ref) + change -------------------
# covenant output value MUST equal FT_AMOUNT (1 photon = 1 FT unit).
FEE = 8_000_000  # ~15.5k/byte for the ~514B tx; effective relay rate is 10k/byte
change_val = (FT_AMOUNT + FEE_AMT) - FT_AMOUNT - FEE
assert change_val > 546, f"change too small: {change_val}"
change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"

tx = Transaction(
    tx_inputs=[ft_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(covenant_spk), FT_AMOUNT),
        TransactionOutput(Script(change_spk), change_val),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"funding_hex": raw, "funding_txid": tx.txid(),
                  "covenant_vout": 0, "covenant_value": FT_AMOUNT, "change_val": change_val}))
