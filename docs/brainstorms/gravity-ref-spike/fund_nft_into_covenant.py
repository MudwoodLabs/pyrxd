#!/usr/bin/env python3
"""Fund the minted NFT into the NFT swap covenant. Spends the standard 63-byte
NFT UTXO (d8<ref>75 76a914<owner>88ac) at the owner key + a plain-RXD fee input,
and creates the covenant output whose SPK is the substituted NFT covenant
bytecode (which itself carries the singleton via its embedded d8<REF>).

The singleton ref is conserved: it appears on input (the NFT UTXO) and on
output[0] (the covenant SPK embeds d8<REF> for the same ref). Consensus
validatePushRefRule (outputs ⊆ inputs) is satisfied.

Outputs: [0] covenant SPK, value = NFT_CARRIER_VALUE (carries the singleton)
         [1] plain-RXD change to the fee key

NOTE: the NFT input is spent with an ordinary P2PKH unlock (sig+pubkey) — the
d8<ref>75 prologue is a no-op for auth, the trailing 76a914..88ac is the spend
condition. No extra push for the singleton.
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

NFT_WIF = sys.argv[1]            # owner of the minted NFT (deploy key)
FEE_WIF = sys.argv[2]
COVENANT_SPK_HEX = sys.argv[3]
NFT_TXID = sys.argv[4]
NFT_VOUT = int(sys.argv[5])
NFT_SCRIPT_HEX = sys.argv[6]     # the 63-byte NFT script being spent
NFT_VALUE = int(sys.argv[7])     # photons in the NFT UTXO
CARRIER_VALUE = int(sys.argv[8]) # photons to place in the covenant output
FEE_TXID = sys.argv[9]
FEE_VOUT = int(sys.argv[10])
FEE_AMT = int(sys.argv[11])
FEE_SPK_HEX = sys.argv[12]

nft_key = PrivateKey(NFT_WIF)
nft_pub = nft_key.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
fee_pkh = bytes(Hex20(fee_key.public_key().hash160()))


def _nft_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = nft_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(nft_pub))


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


nft_src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(bytes.fromhex(NFT_SCRIPT_HEX)), NFT_VALUE)])
nft_src.txid = lambda: NFT_TXID  # type: ignore
nft_in = TransactionInput(source_transaction=nft_src, source_txid=NFT_TXID, source_output_index=NFT_VOUT,
                          unlocking_script_template=to_unlock_script_template(_nft_unlock, lambda: 110))
nft_in.satoshis = NFT_VALUE
nft_in.locking_script = Script(bytes.fromhex(NFT_SCRIPT_HEX))

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

FEE = 8_000_000  # ~600B NFT-into-HTLC-covenant funding tx at 0.10 RXD/kB
# The NFT carrier value comes from the NFT input; the fee input covers FEE + change.
change_val = (NFT_VALUE + FEE_AMT) - CARRIER_VALUE - FEE
assert change_val > 546, f"change too small: {change_val}"
change_spk = b"\x76\xa9\x14" + fee_pkh + b"\x88\xac"

tx = Transaction(
    tx_inputs=[nft_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(bytes.fromhex(COVENANT_SPK_HEX)), CARRIER_VALUE),
        TransactionOutput(Script(change_spk), change_val),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"hex": raw, "txid": tx.txid(), "covenant_vout": 0,
                  "change_vout": 1, "change_val": change_val, "size": len(raw) // 2}))
