#!/usr/bin/env python3
"""Spike step 2: build the reveal tx that creates the premine FT output.
The FT output's outpoint becomes the permanent token ref.
Follows tests/test_dmint_deploy_integration.py's reveal pattern. Signs locally
(commit-script spend is a P2PKH-style <sig><pubkey>), prints raw reveal hex."""
import json
import sys

from pyrxd.glyph.builder import GlyphBuilder
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

WIF = sys.argv[1]
commit = json.loads(sys.argv[2])
COMMIT_TXID = sys.argv[3]

key = PrivateKey(WIF)
pubkey = key.public_key().serialize()
pkh = Hex20(key.public_key().hash160())

builder = GlyphBuilder()
reveal = builder.prepare_ft_deploy_reveal(
    commit_txid=COMMIT_TXID,
    commit_vout=0,
    commit_value=commit["commit_value"],
    cbor_bytes=bytes.fromhex(commit["cbor_hex"]),
    premine_pkh=pkh,
    premine_amount=commit["supply"],
)

scriptsig_suffix = reveal.scriptsig_suffix

def _reveal_unlock(tx, input_index):
    inp = tx.inputs[input_index]
    sig = key.sign(tx.preimage(input_index))
    sighash_byte = inp.sighash.to_bytes(1, "little")
    p2pkh_part = encode_pushdata(sig + sighash_byte) + encode_pushdata(pubkey)
    return Script(p2pkh_part + scriptsig_suffix)

def _reveal_est_len():
    return 107 + len(scriptsig_suffix)

# Reconstruct the commit output being spent (a shim source tx).
src = Transaction(tx_inputs=[], tx_outputs=[
    TransactionOutput(Script(bytes.fromhex(commit["commit_script_hex"])), commit["commit_value"]),
])
src.txid = lambda: COMMIT_TXID  # type: ignore[method-assign]

reveal_input = TransactionInput(
    source_transaction=src,
    source_txid=COMMIT_TXID,
    source_output_index=0,
    unlocking_script_template=to_unlock_script_template(_reveal_unlock, _reveal_est_len),
)
reveal_input.satoshis = commit["commit_value"]
reveal_input.locking_script = Script(bytes.fromhex(commit["commit_script_hex"]))

# vout[0] = the FT output (value == supply); the rest stays as fee headroom.
# Single FT output only (premine-only deploy, numContracts=0).
reveal_tx = Transaction(
    tx_inputs=[reveal_input],
    tx_outputs=[TransactionOutput(Script(reveal.locking_script), commit["supply"])],
)
reveal_tx.sign()

reveal_hex = reveal_tx.serialize().hex() if hasattr(reveal_tx, "serialize") else reveal_tx.raw().hex()
reveal_txid = reveal_tx.txid()

print(json.dumps({
    "reveal_hex": reveal_hex,
    "reveal_txid": reveal_txid,
    "ft_ref_txid": reveal_txid,   # the token ref = (reveal_txid, vout 0)
    "ft_ref_vout": 0,
    "ft_locking_script_hex": reveal.locking_script.hex(),
    "supply": commit["supply"],
    "pkh": bytes(pkh).hex(),
}))
