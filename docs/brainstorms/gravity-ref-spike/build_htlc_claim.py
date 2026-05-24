#!/usr/bin/env python3
"""Phase-3 HTLC CLAIM builder — spend a funded HTLC-covenant UTXO via claim(preimage).

Works for all 3 variants (ft|nft|rxd). The covenant SPK and the expected output
differ per variant, but the SPEND SHAPE is identical:
  - output[0] = the TAKER's holder script (75-B FT / 63-B NFT / 25-B P2PKH),
    value = FT amount / NFT carrier / RXD amount.
  - a separate plain-RXD fee input (own synthetic source tx) supplies the fee.
  - the covenant input's scriptSig = <preimage push> <OP_0 selector>.

SELECTOR/ARG ORDER (verified against the covenant asm + build_nft_finalize.py):
  The claim branch dispatch is `OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_SWAP OP_SHA256
  ...`. The selector is on TOP of the stack (OP_DUP/OP_NUMEQUAL inspect it), the
  preimage below it. After OP_IF, `OP_SWAP` puts the preimage on top for OP_SHA256.
  So the scriptSig pushes the PREIMAGE FIRST, then the OP_0 selector LAST — exactly
  like build_nft_finalize.py pushes <data...> then OP_0. (selector is the LAST push.)

SINGLE-OUTPUT + FEE MODEL (replicates build_nft_finalize.py byte-for-byte):
  Every HTLC covenant enforces `tx.outputs.length == 1`, so there is EXACTLY one
  output — the taker holder output. A change output would break the covenant.
  Therefore the fee = (covenant carrier + fee-input amount) - out0_value, i.e. the
  entire fee-input surplus is consumed as fee with NO change output. Size the fee
  input upstream so this surplus clears the per-kB min-relay fee.

  FT/RXD: out0_value == amount (covenant pins refValueSum/value to `amount`).
  NFT:    out0_value == nftCarrierValue (covenant pins outputs[0].value).

Usage:
  build_htlc_claim.py <variant> <preimage_hex> <cov_spk_hex> <cov_txid> <cov_vout>
      <out0_value> <taker_holder_spk_hex> <fee_wif> <fee_txid> <fee_vout> <fee_amt> <fee_spk_hex>
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "src")
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput


def _push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + b
    if n <= 255:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


def build_claim_tx(
    variant: str,
    preimage: bytes,
    cov_spk: bytes,
    cov_txid: str,
    cov_vout: int,
    out0_value: int,
    taker_holder_spk: bytes,
    fee_wif: str,
    fee_txid: str,
    fee_vout: int,
    fee_amt: int,
    fee_spk: bytes,
) -> Transaction:
    assert variant in ("ft", "nft", "rxd"), "variant must be ft|nft|rxd"
    fee_key = PrivateKey(fee_wif)
    fee_pub = fee_key.public_key().serialize()

    def _cov_unlock(tx, idx):
        # PREIMAGE first (lands UNDER the selector), then OP_0 selector LAST (on
        # top). The claim branch does OP_DUP/OP_NUMEQUAL on the selector then
        # OP_SWAP to bring the preimage up for OP_SHA256.
        return Script(_push(preimage) + b"\x00")

    def _fee_unlock(tx, idx):
        inp = tx.inputs[idx]
        sig = fee_key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))

    def _src_with_output(txid: str, vout: int, spk: bytes, val: int) -> Transaction:
        outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
        outs.append(TransactionOutput(Script(spk), val))
        t = Transaction(tx_inputs=[], tx_outputs=outs)
        t.txid = lambda: txid  # type: ignore
        return t

    cov_src = _src_with_output(cov_txid, cov_vout, cov_spk, out0_value)
    cov_in = TransactionInput(source_transaction=cov_src, source_txid=cov_txid, source_output_index=cov_vout,
                              unlocking_script_template=to_unlock_script_template(_cov_unlock, lambda: len(preimage) + 4))
    cov_in.satoshis = out0_value
    cov_in.locking_script = Script(cov_spk)

    fee_src = _src_with_output(fee_txid, fee_vout, fee_spk, fee_amt)
    fee_in = TransactionInput(source_transaction=fee_src, source_txid=fee_txid, source_output_index=fee_vout,
                              unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
    fee_in.satoshis = fee_amt
    fee_in.locking_script = Script(fee_spk)

    # SINGLE OUTPUT (covenant enforces outputs.length==1). The fee input surplus
    # is consumed entirely as fee; NO change output (would break the covenant).
    tx = Transaction(
        tx_inputs=[cov_in, fee_in],
        tx_outputs=[TransactionOutput(Script(taker_holder_spk), out0_value)],
    )
    tx.sign()
    return tx


def main() -> None:
    variant = sys.argv[1]
    preimage = bytes.fromhex(sys.argv[2])
    cov_spk = bytes.fromhex(sys.argv[3])
    cov_txid = sys.argv[4]
    cov_vout = int(sys.argv[5])
    out0_value = int(sys.argv[6])
    taker_holder_spk = bytes.fromhex(sys.argv[7])
    fee_wif = sys.argv[8]
    fee_txid = sys.argv[9]
    fee_vout = int(sys.argv[10])
    fee_amt = int(sys.argv[11])
    fee_spk = bytes.fromhex(sys.argv[12])

    tx = build_claim_tx(variant, preimage, cov_spk, cov_txid, cov_vout, out0_value,
                        taker_holder_spk, fee_wif, fee_txid, fee_vout, fee_amt, fee_spk)
    raw = tx.serialize().hex()
    print(json.dumps({"variant": variant, "hex": raw, "txid": tx.txid(), "size": len(raw) // 2}))


if __name__ == "__main__":
    main()
