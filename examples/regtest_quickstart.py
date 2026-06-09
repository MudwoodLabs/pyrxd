#!/usr/bin/env python3
"""Mint your first Glyph NFT on a local regtest chain — zero config.

This is the companion script for the 5-minute quickstart
(``docs/tutorials/quickstart.md``). It assumes a regtest node is already
running::

    pyrxd regtest up

and then mints a Glyph NFT end-to-end against it: it pulls a funded UTXO from
the dev wallet, builds the two-phase commit/reveal with the pyrxd SDK
(:class:`pyrxd.glyph.GlyphBuilder`), broadcasts each tx through the node's RPC,
and mines a block to confirm. No ElectrumX, no mainnet, no real value.

    python examples/regtest_quickstart.py

The transaction-building here is the same proven logic as
``examples/glyph_mint_demo.py`` (which mints on mainnet via ElectrumX); only the
transport is swapped — UTXO lookup, broadcast, and confirmation all go through
``pyrxd regtest`` instead of a remote server.
"""

from __future__ import annotations

import os
import sys
import time

# Make pyrxd importable from the source tree when run in-place.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.devnet import DevnetError, RegtestNode
from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import CommitParams, RevealParams
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction, TransactionInput, TransactionOutput

MIN_FEE_RATE = 10_000  # photons/byte — regtest relay floor matches mainnet
REVEAL_BUDGET = 580 * MIN_FEE_RATE * 12 // 10 + 546
COMMIT_VALUE = REVEAL_BUDGET + 200_000  # commit output must cover the reveal cost
COMMIT_DUST = 276 * MIN_FEE_RATE


# --------------------------------------------------------------------- tx builders
# (identical to examples/glyph_mint_demo.py — pure SDK, no transport coupling)


def _glyph_reveal_unlock(private_key: PrivateKey, scriptsig_suffix: bytes):
    def sign(tx, input_index) -> Script:
        tx_input = tx.inputs[input_index]
        signature = private_key.sign(tx.preimage(input_index))
        pubkey = private_key.public_key().serialize()
        p2pkh_part = encode_pushdata(signature + tx_input.sighash.to_bytes(1, "little")) + encode_pushdata(pubkey)
        return Script(p2pkh_part + scriptsig_suffix)

    return to_unlock_script_template(sign, lambda: 107 + len(scriptsig_suffix))


def _build_commit_tx(utxo: dict, key: PrivateKey, commit_script: bytes, commit_value: int, address: str) -> Transaction:
    inp = TransactionInput(
        source_txid=utxo["tx_hash"],
        source_output_index=utxo["tx_pos"],
        unlocking_script_template=P2PKH().unlock(key),
    )
    inp.satoshis = utxo["value"]
    inp.locking_script = P2PKH().lock(address)
    src_out = TransactionOutput(P2PKH().lock(address), utxo["value"])

    class _SrcTx:
        def __init__(self, out, _tx_pos: int = utxo["tx_pos"]) -> None:
            self.outputs = {_tx_pos: out}

    inp.source_transaction = _SrcTx(src_out)
    if utxo["value"] < commit_value + COMMIT_DUST * 3:
        raise ValueError(f"funding UTXO too small: {utxo['value']} < {commit_value + COMMIT_DUST * 3}")

    tx = Transaction(
        tx_inputs=[inp],
        tx_outputs=[
            TransactionOutput(Script(commit_script), commit_value),
            TransactionOutput(P2PKH().lock(address), change=True),
        ],
    )
    tx.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))
    tx.sign()
    return tx


def _build_reveal_tx(
    commit_txid: str, commit_value: int, commit_script: bytes, suffix: bytes, nft_script: bytes, key: PrivateKey
) -> Transaction:
    src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(commit_script), commit_value)])
    src.txid = lambda: commit_txid  # type: ignore[method-assign]
    reveal_input = TransactionInput(
        source_transaction=src,
        source_output_index=0,
        unlocking_script_template=_glyph_reveal_unlock(key, suffix),
    )
    # Pass 1: measure the real signed size with a trial output value.
    trial = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(nft_script), max(546, commit_value // 2))],
    )
    trial.sign()
    fee = trial.byte_length() * (MIN_FEE_RATE + 500)
    nft_value = commit_value - fee
    if nft_value < 546:
        raise ValueError(f"commit value {commit_value} too small for reveal fee {fee}")
    # Pass 2: re-sign over the final output.
    reveal_input.unlocking_script = None
    tx = Transaction(tx_inputs=[reveal_input], tx_outputs=[TransactionOutput(Script(nft_script), nft_value)])
    tx.sign()
    return tx


# --------------------------------------------------------------------- main flow


def _funded_key(node: RegtestNode, need: int) -> tuple[PrivateKey, str, dict]:
    """Pull a funded UTXO + its key from the dev wallet."""
    unspent = node.cli("listunspent", "1", "9999999", wallet=True)
    if not isinstance(unspent, list):
        raise DevnetError("could not list regtest UTXOs")
    for u in unspent:
        value = round(u["amount"] * 1e8)
        if value >= need:
            wif = str(node.cli("dumpprivkey", u["address"], wallet=True))
            return PrivateKey(wif), u["address"], {"tx_hash": u["txid"], "tx_pos": u["vout"], "value": value}
    raise DevnetError(f"no UTXO with at least {need} photons — try `pyrxd regtest mine 10`")


def main() -> None:
    node = RegtestNode()
    if not node.is_running():
        print("regtest node is not running. Start it first:\n    pyrxd regtest up")
        sys.exit(1)

    key, address, utxo = _funded_key(node, COMMIT_VALUE + COMMIT_DUST * 3)
    pkh = Hex20(key.public_key().hash160())
    print(f"minting from {address}  (UTXO {utxo['tx_hash'][:12]}…:{utxo['tx_pos']}, {utxo['value']:,} photons)")

    builder = GlyphBuilder()
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="my-first-glyph",
        description="Minted on regtest via the pyrxd quickstart",
        token_type="quickstart",
        attrs={"minted_at": str(int(time.time()))},
    )
    commit = builder.prepare_commit(CommitParams(metadata=metadata, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=0))

    # --- commit ---
    commit_tx = _build_commit_tx(utxo, key, commit.commit_script, COMMIT_VALUE, address)
    commit_txid = node.cli("sendrawtransaction", commit_tx.serialize().hex())
    node.mine(1)
    commit_value = commit_tx.outputs[0].satoshis
    print(f"commit:  {commit_txid}  ({commit_value:,} photons, confirmed)")

    # --- reveal ---
    reveal = builder.prepare_reveal(
        RevealParams(
            commit_txid=str(commit_txid),
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=pkh,
            is_nft=True,
        )
    )
    reveal_tx = _build_reveal_tx(
        str(commit_txid), commit_value, commit.commit_script, reveal.scriptsig_suffix, reveal.locking_script, key
    )
    reveal_txid = node.cli("sendrawtransaction", reveal_tx.serialize().hex())
    node.mine(1)

    print(f"reveal:  {reveal_txid}  (NFT output {reveal_tx.outputs[0].satoshis:,} photons, confirmed)")
    print()
    print("NFT minted on regtest.")
    print(f"  genesis ref: {commit_txid}:0   <- this is the token's permanent identity")
    print(f"  owner:       {address}")
    print()
    print("inspect it on the node:")
    print("  pyrxd regtest info")
    print(
        f"  docker exec {RegtestNode.CONTAINER} radiant-cli -regtest -rpcuser={RegtestNode.RPC_USER} "
        f"-rpcpassword={RegtestNode.RPC_PASSWORD} getrawtransaction {reveal_txid} 1"
    )


if __name__ == "__main__":
    main()
