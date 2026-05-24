#!/usr/bin/env python3
"""Phase-3 HTLC REFUND builder — spend a funded HTLC-covenant UTXO via refund().

Works for all 3 variants (ft|nft|rxd). refund() takes NO params and does NO sig
check — it is gated by the relative timelock (tx.age -> OP_CHECKSEQUENCEVERIFY).
BIP68 requires the SPEND tx be nVersion>=2 with the covenant input's nSequence =
refundCsv (block count, type-flag clear, disable-flag clear).

SELECTOR: refund() is function index 1; the dispatch is `OP_DUP OP_0 OP_NUMEQUAL
OP_IF ... OP_ELSE OP_1 OP_NUMEQUALVERIFY ...`. So the scriptSig is JUST the OP_1
selector (no preimage, no sig — exactly like build_forfeit.py's OP_1). The
selector is the sole stack item; OP_DUP/OP_NUMEQUAL fail the ==0 test, ELSE runs
OP_1 OP_NUMEQUALVERIFY which consumes it.

SINGLE-OUTPUT + FEE MODEL: identical to claim — the covenant enforces
`tx.outputs.length == 1`, so output[0] is the MAKER holder output and the fee
input surplus is consumed entirely as fee (NO change output). See build_htlc_claim.py.

  FT/RXD: out0_value == amount.   NFT: out0_value == nftCarrierValue.

Usage:
  build_htlc_refund.py <variant> <refund_csv> <cov_spk_hex> <cov_txid> <cov_vout>
      <out0_value> <maker_holder_spk_hex> <fee_wif> <fee_txid> <fee_vout> <fee_amt> <fee_spk_hex>
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


def build_refund_tx(
    variant: str,
    refund_csv: int,
    cov_spk: bytes,
    cov_txid: str,
    cov_vout: int,
    out0_value: int,
    maker_holder_spk: bytes,
    fee_wif: str,
    fee_txid: str,
    fee_vout: int,
    fee_amt: int,
    fee_spk: bytes,
    *,
    premature: bool = False,
) -> Transaction:
    assert variant in ("ft", "nft", "rxd"), "variant must be ft|nft|rxd"
    fee_key = PrivateKey(fee_wif)
    fee_pub = fee_key.public_key().serialize()

    def _cov_unlock(tx, idx):
        # refund() = function index 1 -> OP_1 selector only. No preimage, no sig.
        return Script(b"\x51")  # OP_1 selector (refund)

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
                              unlocking_script_template=to_unlock_script_template(_cov_unlock, lambda: 4))
    cov_in.satoshis = out0_value
    cov_in.locking_script = Script(cov_spk)
    # BIP68: nSequence encodes the relative lock (block count; type-flag=0, disable-flag=0).
    # --premature sets nSequence=0 so OP_CHECKSEQUENCEVERIFY should NOT be satisfiable.
    cov_in.sequence = 0 if premature else refund_csv

    fee_src = _src_with_output(fee_txid, fee_vout, fee_spk, fee_amt)
    fee_in = TransactionInput(source_transaction=fee_src, source_txid=fee_txid, source_output_index=fee_vout,
                              unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
    fee_in.satoshis = fee_amt
    fee_in.locking_script = Script(fee_spk)
    # The fee input need not carry the relative lock; keep it < max so it doesn't
    # disable nLockTime semantics, but its value is irrelevant to BIP68 on the cov input.
    fee_in.sequence = 0xFFFFFFFF if premature else 0xFFFFFFFE

    tx = Transaction(
        tx_inputs=[cov_in, fee_in],
        tx_outputs=[TransactionOutput(Script(maker_holder_spk), out0_value)],
    )
    tx.version = 1 if premature else 2  # BIP68 needs v2
    tx.sign()
    return tx


def main() -> None:
    variant = sys.argv[1]
    refund_csv = int(sys.argv[2])
    cov_spk = bytes.fromhex(sys.argv[3])
    cov_txid = sys.argv[4]
    cov_vout = int(sys.argv[5])
    out0_value = int(sys.argv[6])
    maker_holder_spk = bytes.fromhex(sys.argv[7])
    fee_wif = sys.argv[8]
    fee_txid = sys.argv[9]
    fee_vout = int(sys.argv[10])
    fee_amt = int(sys.argv[11])
    fee_spk = bytes.fromhex(sys.argv[12])
    premature = "--premature" in sys.argv

    tx = build_refund_tx(variant, refund_csv, cov_spk, cov_txid, cov_vout, out0_value,
                         maker_holder_spk, fee_wif, fee_txid, fee_vout, fee_amt, fee_spk,
                         premature=premature)
    raw = tx.serialize().hex()
    print(json.dumps({"variant": variant, "hex": raw, "txid": tx.txid(),
                      "version": tx.version, "cov_sequence": tx.inputs[0].sequence,
                      "premature": premature, "size": len(raw) // 2}))


if __name__ == "__main__":
    main()
