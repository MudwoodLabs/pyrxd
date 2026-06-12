"""Differential consensus validation of soulbound covenants on a real regtest node.

Proves, against ``radiant-core:v3.1.1`` consensus (via ``testmempoolaccept``), that
BOTH soulbound covenant designs enforce the same security property:

* **recur-to-self**  (output[0] is a byte-identical clone)            -> ACCEPTED
* **transfer-to-other** (output[0] is a clone with a different owner) -> REJECTED
* **burn**            (no output carries the singleton ref)           -> ACCEPTED

…for:

1. the **pyrxd prototype** (:mod:`pyrxd.glyph.soulbound_covenant`, full-bytecode
   self-equality, branch auto-selected by ``OP_REFOUTPUTCOUNT_OUTPUTS``), and
2. the **deployed design** copied byte-for-byte from the live mainnet token
   "TheArtofSatoshi" (``OP_CODESCRIPTBYTECODE_*`` self-equality, explicit IF/ELSE
   selector).

This is the validation that upgrades the prototype's docstring claim from
"structural only" to "consensus-confirmed". It reuses the proven HTLC regtest
harness; it manages its own isolated node and moves no real value.

Run it:  RADIANT_REGTEST=1 pytest tests/test_soulbound_covenant_regtest.py -m integration -s
"""

from __future__ import annotations

import pytest

from pyrxd.constants import SIGHASH
from pyrxd.glyph.soulbound_covenant import (
    build_composable_soulbound_nft_covenant,
    build_soulbound_nft_covenant,
)
from pyrxd.glyph.soulbound_detect import classify_soulbound
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# Reuse the proven regtest harness (node fixture + tx helpers).
from tests.test_htlc_regtest_e2e import (  # noqa: F401  (node is a pytest fixture)
    _biggest_utxo,
    _fee_input,
    _p2pkh_unlock,
    _pay_to_spk,
    _src,
    node,
)

pytestmark = pytest.mark.integration

_CARRIER = 100_000


# --------------------------------------------------------------------------- covenant builders


def _deployed_soulbound_spk(ref_wire: bytes, pkh: bytes) -> bytes:
    """The live mainnet soulbound covenant, parameterized by ref + owner pkh.

    Byte-for-byte the structure of TheArtofSatoshi UTXO 4b25…:0:
    d8<ref> OP_SWAP OP_IF OP_DROP <owner> OP_0 OP_CODESCRIPTBYTECODE_OUTPUT
    OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO OP_EQUAL OP_ELSE
    OP_REFOUTPUTCOUNT_OUTPUTS OP_0 OP_NUMEQUAL OP_VERIFY <owner> OP_1 OP_ENDIF
    """
    owner = b"\x76\xa9\x14" + pkh + b"\x88\xad"  # DUP HASH160 <pkh> EQUALVERIFY CHECKSIGVERIFY
    return (
        b"\xd8"
        + ref_wire
        + b"\x7c\x63\x75"
        + owner
        + b"\x00\xea\xc0\xe9\x87"
        + b"\x67\xde\x00\x9c\x69"
        + owner
        + b"\x51\x68"
    )


def _selector_unlock(key: PrivateKey, selector: bytes):
    """Unlock for the deployed covenant: <sig> <pubkey> <selector>."""
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + selector)

    return to_unlock_script_template(_u, lambda: 112)


# --------------------------------------------------------------------------- spend helper


def _fee_txin(node) -> TransactionInput:
    fee = _fee_input(node)
    key = PrivateKey(fee.wif)
    ti = TransactionInput(
        source_transaction=_src(fee.txid, fee.vout, fee.scriptpubkey, fee.value),
        source_txid=fee.txid,
        source_output_index=fee.vout,
        unlocking_script_template=_p2pkh_unlock(key),
        sighash=SIGHASH.ALL_FORKID,
    )
    ti.satoshis = fee.value
    ti.locking_script = Script(fee.scriptpubkey)
    return ti


def _build_spend(node, cov_spk, cov_txid, owner_key, output0_spk, unlock_template) -> str:
    cov_in = TransactionInput(
        source_transaction=_src(cov_txid, 0, cov_spk, _CARRIER),
        source_txid=cov_txid,
        source_output_index=0,
        unlocking_script_template=unlock_template,
        sighash=SIGHASH.ALL_FORKID,
    )
    cov_in.satoshis = _CARRIER
    cov_in.locking_script = Script(cov_spk)
    tx = Transaction(
        tx_inputs=[cov_in, _fee_txin(node)],
        tx_outputs=[TransactionOutput(Script(output0_spk), _CARRIER)],
    )
    tx.sign()
    return tx.serialize().hex()


def _build_spend_multi(node, cov_spk, cov_txid, unlock_template, outputs) -> str:
    """Spend the covenant into an arbitrary list of (spk, value) outputs."""
    cov_in = TransactionInput(
        source_transaction=_src(cov_txid, 0, cov_spk, _CARRIER),
        source_txid=cov_txid,
        source_output_index=0,
        unlocking_script_template=unlock_template,
        sighash=SIGHASH.ALL_FORKID,
    )
    cov_in.satoshis = _CARRIER
    cov_in.locking_script = Script(cov_spk)
    tx = Transaction(
        tx_inputs=[cov_in, _fee_txin(node)],
        tx_outputs=[TransactionOutput(Script(spk), val) for spk, val in outputs],
    )
    tx.sign()
    return tx.serialize().hex()


def _fund_singleton(node, build_spk):
    """Mint a singleton into the covenant (R1 mechanism: spend the outpoint that
    equals the ref so it enters the input-ref set). Returns (cov_spk, cov_txid,
    owner_key)."""
    u = _biggest_utxo(node)
    ref = GlyphRef(txid=u["txid"], vout=u["vout"])
    owner_key = PrivateKey(str(node.cli("dumpprivkey", u["address"], wallet=True)))
    pkh = bytes(Hex20(owner_key.public_key().hash160()))
    cov_spk = build_spk(ref.to_bytes(), pkh)
    cov_txid = _pay_to_spk(node, cov_spk, _CARRIER, spend_outpoint=(u["txid"], u["vout"]))
    return cov_spk, cov_txid, owner_key, pkh


def _p2pkh(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def _other_pkh(_pkh: bytes) -> bytes:
    """A deterministic, different owner pkh (for the transfer-to-other case)."""
    return bytes(Hex20(PrivateKey(b"\x02" * 32).public_key().hash160()))


# --------------------------------------------------------------------------- the proofs


class TestSoulboundConsensus:
    def test_pyrxd_prototype_enforces_soulbinding(self, node):
        def build(ref, pkh):
            return build_soulbound_nft_covenant(GlyphRef.from_bytes(ref), pkh).funded_spk

        cov_spk, cov_txid, owner_key, pkh = _fund_singleton(node, build)
        assert classify_soulbound(cov_spk).is_consensus_soulbound

        # recur-to-self -> ACCEPTED   (unlock = <sig><pubkey>; branch auto from REFOUTPUTCOUNT)
        recur = _build_spend(node, cov_spk, cov_txid, owner_key, cov_spk, _p2pkh_unlock(owner_key))
        assert node.accepts(recur)["allowed"] is True, node.accepts(recur)

        # transfer-to-other -> REJECTED  (clone with the SAME ref but a different owner)
        other_spk = build(cov_spk[1:37], _other_pkh(pkh))
        xfer = _build_spend(node, cov_spk, cov_txid, owner_key, other_spk, _p2pkh_unlock(owner_key))
        assert node.accepts(xfer)["allowed"] is False, node.accepts(xfer)

        # burn -> ACCEPTED  (output[0] is a plain p2pkh, no ref carried)
        burn = _build_spend(node, cov_spk, cov_txid, owner_key, _p2pkh(pkh), _p2pkh_unlock(owner_key))
        assert node.accepts(burn)["allowed"] is True, node.accepts(burn)

    def test_deployed_design_enforces_soulbinding(self, node):
        cov_spk, cov_txid, owner_key, pkh = _fund_singleton(node, _deployed_soulbound_spk)
        assert classify_soulbound(cov_spk).is_consensus_soulbound

        recur_spk = _deployed_soulbound_spk(cov_spk[1:37], pkh)  # exact clone (same ref+owner)
        # recur -> ACCEPTED (IF branch, selector OP_1)
        recur = _build_spend(node, cov_spk, cov_txid, owner_key, recur_spk, _selector_unlock(owner_key, b"\x51"))
        assert node.accepts(recur)["allowed"] is True, node.accepts(recur)

        # transfer -> REJECTED (IF branch, different owner -> CODESCRIPTBYTECODE != )
        xfer_spk = _deployed_soulbound_spk(cov_spk[1:37], _other_pkh(pkh))
        xfer = _build_spend(node, cov_spk, cov_txid, owner_key, xfer_spk, _selector_unlock(owner_key, b"\x51"))
        assert node.accepts(xfer)["allowed"] is False, node.accepts(xfer)

        # burn -> ACCEPTED (ELSE branch, selector OP_0, no ref output)
        burn = _build_spend(node, cov_spk, cov_txid, owner_key, _p2pkh(pkh), _selector_unlock(owner_key, b"\x00"))
        assert node.accepts(burn)["allowed"] is True, node.accepts(burn)

    def test_composable_covenant_recurs_to_any_index(self, node):
        """The index-independent covenant: the credential can recur to output[1]
        while output[0] is something else (the property a swap claim needs, and
        the fixed-output[0] covenant cannot do). transfer still rejected, burn ok."""

        def build(ref, pkh):
            return build_composable_soulbound_nft_covenant(GlyphRef.from_bytes(ref), pkh).funded_spk

        cov_spk, cov_txid, owner_key, pkh = _fund_singleton(node, build)
        assert classify_soulbound(cov_spk).is_consensus_soulbound

        # recur to output[1], output[0] = an unrelated p2pkh -> ACCEPTED (composability)
        recur = _build_spend_multi(
            node,
            cov_spk,
            cov_txid,
            _p2pkh_unlock(owner_key),
            [(_p2pkh(pkh), 600), (cov_spk, _CARRIER)],
        )
        assert node.accepts(recur)["allowed"] is True, node.accepts(recur)

        # transfer (clone with a different owner, at output[1]) -> REJECTED
        other = build(cov_spk[1:37], _other_pkh(pkh))
        xfer = _build_spend_multi(
            node,
            cov_spk,
            cov_txid,
            _p2pkh_unlock(owner_key),
            [(_p2pkh(pkh), 600), (other, _CARRIER)],
        )
        assert node.accepts(xfer)["allowed"] is False, node.accepts(xfer)

        # burn -> ACCEPTED
        burn = _build_spend_multi(node, cov_spk, cov_txid, _p2pkh_unlock(owner_key), [(_p2pkh(pkh), _CARRIER)])
        assert node.accepts(burn)["allowed"] is True, node.accepts(burn)
