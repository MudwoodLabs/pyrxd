#!/usr/bin/env python3
"""Build the NFT-covenant negative-test transactions. Each MUST be rejected by
consensus (testmempoolaccept allowed=false). Spends the live NFT covenant UTXO
via the forfeit route (CLTV-gated, no SPV) with a deliberately-wrong output or
locktime. Conservation here is COVENANT-ONLY (consensus permits an NFT burn),
so these negatives are the load-bearing proof that the covenant body alone
guards the one-of-one.

Cases (selected by argv[1]):
  burn        -> output[0] is a plain P2PKH (no singleton) => refOutputCount(ref)==1 fails / burn
  clone       -> two outputs (both NFT-shaped)            => outputs.length==1 fails
  wrong_dest  -> output[0] = a THIRD-party NFT script      => hash256 != expectedMakerNftHash
  wrong_value -> output[0] = maker NFT but value 2000      => outputs[0].value != nftCarrierValue
  predeadline -> correct maker NFT but nLockTime < deadline => CLTV (tx.time>=claimDeadline) fails

Prints the signed hex.
"""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

CASE = sys.argv[1]
COV = json.load(open(sys.argv[2]))          # .nft_covenant2.json
COV_TXID = sys.argv[3]
COV_VOUT = int(sys.argv[4])
CARRIER = int(sys.argv[5])
FEE_WIF = sys.argv[6]
FEE_TXID = sys.argv[7]
FEE_VOUT = int(sys.argv[8])
FEE_AMT = int(sys.argv[9])
FEE_SPK_HEX = sys.argv[10]
NLOCKTIME = int(sys.argv[11])

cov_spk = bytes.fromhex(COV["fused_nft_spk_hex"])
maker_nft = bytes.fromhex(COV["maker_nft_script"])
taker_nft = bytes.fromhex(COV["taker_nft_script"])
ref_wire = bytes.fromhex(COV["ref_wire_hex"])
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
fee_pkh = bytes.fromhex(FEE_SPK_HEX)[3:23]

# A third-party NFT script (different pkh) for wrong_dest — still a valid NFT
# carrying the singleton, just to the wrong owner.
third_pkh = bytes.fromhex("00" * 20)
third_nft = b"\xd8" + ref_wire + b"\x75\x76\xa9\x14" + third_pkh + b"\x88\xac"
plain_p2pkh = b"\x76\xa9\x14" + bytes.fromhex("11" * 20) + b"\x88\xac"


def _forfeit_unlock(tx, idx):
    return Script(b"\x51")  # OP_1 selector (forfeit), no sig (CLTV-gated)


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(cov_spk), CARRIER)])
src.txid = lambda: COV_TXID  # type: ignore
cov_in = TransactionInput(source_transaction=src, source_txid=COV_TXID, source_output_index=COV_VOUT,
                          unlocking_script_template=to_unlock_script_template(_forfeit_unlock, lambda: 150))
cov_in.satoshis = CARRIER
cov_in.locking_script = Script(cov_spk)
cov_in.sequence = 0xFFFFFFFE

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))
fee_in.sequence = 0xFFFFFFFE

change_spk = b"\x76\xa9\x14" + fee_pkh + b"\x88\xac"
FEE = 120_000_000

if CASE == "burn":
    outs = [TransactionOutput(Script(plain_p2pkh), CARRIER)]
elif CASE == "clone":
    outs = [TransactionOutput(Script(maker_nft), CARRIER), TransactionOutput(Script(taker_nft), CARRIER)]
elif CASE == "wrong_dest":
    outs = [TransactionOutput(Script(third_nft), CARRIER)]
elif CASE == "wrong_value":
    outs = [TransactionOutput(Script(maker_nft), CARRIER + 1000)]
elif CASE == "predeadline":
    outs = [TransactionOutput(Script(maker_nft), CARRIER)]
else:
    raise SystemExit(f"unknown case {CASE}")

# Add a change output only for single-output cases would break outputs.length==1
# for the honest path; but these are NEGATIVE tests — for burn/wrong_dest/
# wrong_value/predeadline we keep exactly ONE covenant-side output (the fee
# goes entirely to fee, matching the honest finalize shape). For clone we
# already have two. No extra RXD change output (would itself trip length!=1).
tx = Transaction(tx_inputs=[cov_in, fee_in], tx_outputs=outs, locktime=NLOCKTIME)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"case": CASE, "hex": raw, "txid": tx.txid(), "nlocktime": NLOCKTIME, "size": len(raw) // 2}))
