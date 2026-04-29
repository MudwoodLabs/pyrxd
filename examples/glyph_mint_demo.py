#!/usr/bin/env python3
"""Glyph NFT mainnet mint — commit/reveal two-phase integration test.

Mints a minimal NFT Glyph on Radiant mainnet using the pyrxd SDK.
Requires a funded WIF key with at least 5M photons.

Usage
-----
    GLYPH_WIF=<wif> python examples/glyph_mint_demo.py

    # Dry-run (builds txs but does not broadcast):
    DRY_RUN=1 GLYPH_WIF=<wif> python examples/glyph_mint_demo.py

Environment
-----------
    GLYPH_WIF     WIF private key for the minting wallet (required)
    DRY_RUN       Set to '0' to broadcast; any other value = dry-run (default)
    ELECTRUMX_URL WebSocket URL for ElectrumX (default: radiant4people mainnet)
    COMMIT_TXID   If set, skip commit and go straight to reveal (resume flow)
    COMMIT_VOUT   Output index of commit tx (default 0)
    COMMIT_VALUE  Photons in commit output (required if COMMIT_TXID is set)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import websockets

# Make sure pyrxd is importable from the source tree
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import CommitParams, RevealParams
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix
from pyrxd.hash import sha256
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.script.type import to_unlock_script_template
from pyrxd.transaction.transaction import Transaction, TransactionInput, TransactionOutput

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"
ELECTRUMX_URL: str = os.environ.get(
    "ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/"
)
GLYPH_WIF: str = os.environ.get("GLYPH_WIF", "")
RESUME_COMMIT_TXID: str = os.environ.get("COMMIT_TXID", "")
RESUME_COMMIT_VOUT: int = int(os.environ.get("COMMIT_VOUT", "0"))
RESUME_COMMIT_VALUE: int = int(os.environ.get("COMMIT_VALUE", "0"))

MIN_FEE_RATE = 10_000  # photons/byte
COMMIT_SIZE = 276       # estimated commit tx bytes
REVEAL_SIZE = 580       # conservative estimate: 250 base + 165 scriptsig suffix + padding
COMMIT_DUST = COMMIT_SIZE * MIN_FEE_RATE         # fee to broadcast commit
REVEAL_BUDGET = REVEAL_SIZE * MIN_FEE_RATE * 12 // 10 + 546  # reveal fee (20% headroom) + min NFT output
COMMIT_VALUE = REVEAL_BUDGET + 200_000            # commit output must cover reveal costs


# ---------------------------------------------------------------------------
# ElectrumX helpers (raw WebSocket — no SDK network layer needed here)
# ---------------------------------------------------------------------------


async def electrumx_call(method: str, params: list) -> object:
    async with websockets.connect(ELECTRUMX_URL) as ws:
        req = json.dumps({"id": 1, "method": method, "params": params})
        await ws.send(req)
        resp = json.loads(await ws.recv())
    if "error" in resp and resp["error"]:
        raise RuntimeError(f"ElectrumX error: {resp['error']}")
    return resp.get("result")


async def fetch_utxos(address: str) -> list:
    script = P2PKH().lock(address)
    script_bytes = script.serialize()
    script_hash = sha256(script_bytes).hex()
    reversed_hash = "".join(reversed([script_hash[i:i+2] for i in range(0, len(script_hash), 2)]))
    return await electrumx_call("blockchain.scripthash.listunspent", [reversed_hash])


async def broadcast(tx_hex: str) -> str:
    return await electrumx_call("blockchain.transaction.broadcast", [tx_hex])


async def fetch_raw_tx(txid: str) -> str:
    return await electrumx_call("blockchain.transaction.get", [txid])


# ---------------------------------------------------------------------------
# Custom unlocking template for Glyph reveal
# ---------------------------------------------------------------------------


def glyph_reveal_unlock(private_key: PrivateKey, scriptsig_suffix: bytes):
    """Return an UnlockingScriptTemplate that signs as P2PKH then appends Glyph suffix."""

    def sign(tx, input_index) -> Script:
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = private_key.sign(tx.preimage(input_index))
        pubkey: bytes = private_key.public_key().serialize()

        from pyrxd.script.type import encode_pushdata
        p2pkh_part = (
            encode_pushdata(signature + sighash.to_bytes(1, "little"))
            + encode_pushdata(pubkey)
        )
        return Script(p2pkh_part + scriptsig_suffix)

    def estimated_unlocking_byte_length() -> int:
        return 107 + len(scriptsig_suffix)

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


# ---------------------------------------------------------------------------
# Tx builders
# ---------------------------------------------------------------------------


def build_commit_tx(
    utxos: list,
    private_key: PrivateKey,
    commit_script_bytes: bytes,
    commit_value: int,
    address: str,
) -> Transaction:
    """Build (unsigned) commit transaction spending P2PKH UTXOs."""
    inputs = []
    total_in = 0
    for utxo in utxos:
        inp = TransactionInput(
            source_txid=utxo["tx_hash"],
            source_output_index=utxo["tx_pos"],
            unlocking_script_template=P2PKH().unlock(private_key),
        )
        # Set fields that fee() needs to compute change
        inp.satoshis = utxo["value"]
        inp.locking_script = P2PKH().lock(address)
        # fee() reads from source_transaction.outputs — wrap with a simple object
        src_out = TransactionOutput(P2PKH().lock(address), utxo["value"])

        class _SrcTx:
            def __init__(self, out): self.outputs = {utxo["tx_pos"]: out}

        inp.source_transaction = _SrcTx(src_out)
        inp.source_output_index = utxo["tx_pos"]
        inputs.append(inp)
        total_in += utxo["value"]
        if total_in >= commit_value + COMMIT_DUST * 3:
            break

    if total_in < commit_value:
        raise ValueError(f"Insufficient funds: {total_in} < {commit_value} needed")

    tx = Transaction(
        tx_inputs=inputs,
        tx_outputs=[
            # vout 0: commit output (custom script)
            TransactionOutput(Script(commit_script_bytes), commit_value),
            # vout 1: change back to sender
            TransactionOutput(P2PKH().lock(address), change=True),
        ],
    )
    from pyrxd.fee_models import SatoshisPerKilobyte
    tx.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))  # SatoshisPerKilobyte takes per-KB
    tx.sign()
    return tx


def build_reveal_tx(
    commit_txid: str,
    commit_vout: int,
    commit_value: int,
    commit_script_bytes: bytes,
    scriptsig_suffix: bytes,
    nft_locking_script_bytes: bytes,
    private_key: PrivateKey,
    address: str,
) -> Transaction:
    """Build reveal transaction spending the commit output."""
    src = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(Script(commit_script_bytes), commit_value)],
    )
    src.txid = lambda: commit_txid  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src,
        source_output_index=commit_vout,
        unlocking_script_template=glyph_reveal_unlock(private_key, scriptsig_suffix),
    )

    # Build with trial nft_value to measure actual byte length, then recompute fee.
    # Two-pass: first pass with placeholder value, second pass with correct fee.
    trial_nft = max(546, commit_value // 2)
    trial_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(nft_locking_script_bytes), trial_nft)],
    )
    trial_tx.sign()
    actual_size = trial_tx.byte_length()

    # Compute fee at 10,500 photons/byte (5% above minimum for relay headroom)
    fee = actual_size * (MIN_FEE_RATE + 500)
    nft_value = commit_value - fee
    if nft_value < 546:
        raise ValueError(
            f"Commit value ({commit_value}) too small to cover reveal fee ({fee} for {actual_size} bytes). "
            f"Need at least {fee + 546} photons in commit output."
        )

    # Reset the unlocking script so sign() re-signs over the final outputs (not trial outputs)
    reveal_input.unlocking_script = None

    tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(nft_locking_script_bytes), nft_value)],
    )
    tx.sign()
    return tx


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------


async def main() -> None:
    if not GLYPH_WIF:
        print("ERROR: Set GLYPH_WIF environment variable to your funded WIF key")
        sys.exit(1)

    private_key = PrivateKey(GLYPH_WIF)
    pub = private_key.public_key()
    address = pub.address()
    pkh_bytes = pub.hash160()

    print(f"Minting wallet: {address}")
    print(f"DRY_RUN: {DRY_RUN}")
    print()

    # Step 1: Build Glyph metadata
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="pyrxd-sdk-mint-test",
        description="First Glyph NFT minted via pyrxd — integration test",
        token_type="sdk-test",
        attrs={"sdk_version": "0.0.2", "minted_at": str(int(time.time()))},
    )
    print(f"NFT name: {metadata.name}")

    builder = GlyphBuilder()
    from pyrxd.security.types import Hex20
    from pyrxd.glyph.builder import CommitParams, RevealParams

    commit_result = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=Hex20(pkh_bytes),
            change_pkh=Hex20(pkh_bytes),
            funding_satoshis=0,  # placeholder — fee computed during build
        )
    )
    print(f"Commit payload hash: {commit_result.payload_hash.hex()}")
    print(f"CBOR bytes ({len(commit_result.cbor_bytes)}): {commit_result.cbor_bytes.hex()}")
    print(f"Commit script ({len(commit_result.commit_script)}): {commit_result.commit_script.hex()}")
    print()

    # Step 2: Commit transaction
    if RESUME_COMMIT_TXID:
        commit_txid = RESUME_COMMIT_TXID
        commit_vout = RESUME_COMMIT_VOUT
        commit_value = RESUME_COMMIT_VALUE
        print(f"Resuming from commit txid: {commit_txid}:{commit_vout} ({commit_value} photons)")
        # Try to load saved CBOR from a prior commit phase
        import json as _json
        from pyrxd.glyph.script import build_commit_locking_script, hash_payload
        try:
            with open("/tmp/glyph_mint_resume.json") as f:
                saved = _json.load(f)
            if saved.get("commit_txid") == commit_txid:
                saved_cbor = bytes.fromhex(saved["cbor_hex"])
                saved_hash = hash_payload(saved_cbor)
                saved_script = build_commit_locking_script(saved_hash, Hex20(pkh_bytes))
                from pyrxd.glyph.builder import CommitResult
                commit_result = CommitResult(
                    commit_script=saved_script,
                    cbor_bytes=saved_cbor,
                    payload_hash=saved_hash,
                    estimated_fee=commit_result.estimated_fee,
                )
                print(f"Loaded saved CBOR from /tmp/glyph_mint_resume.json")
                print(f"Commit script (from saved CBOR): {saved_script.hex()}")
        except FileNotFoundError:
            print("No saved CBOR found — using freshly computed CBOR (MUST match commit!)")
        except Exception as e:
            print(f"Warning: could not load saved CBOR: {e}")
    else:
        print("Fetching UTXOs...")
        utxos = await fetch_utxos(address)
        if not utxos:
            print("No UTXOs found! Fund the address and retry.")
            sys.exit(1)
        total = sum(u["value"] for u in utxos)
        print(f"Found {len(utxos)} UTXO(s), total: {total:,} photons")

        commit_value = COMMIT_VALUE
        commit_tx = build_commit_tx(
            utxos=utxos,
            private_key=private_key,
            commit_script_bytes=commit_result.commit_script,
            commit_value=commit_value,
            address=address,
        )
        commit_txid = commit_tx.txid()
        commit_vout = 0
        # Read back actual commit output value (fee may have adjusted change)
        commit_value = commit_tx.outputs[0].satoshis

        print(f"Commit tx: {commit_txid}")
        print(f"  size: {commit_tx.byte_length()} bytes")
        print(f"  fee: {commit_tx.get_fee():,} photons")
        print(f"  commit output: {commit_value:,} photons")
        print(f"  hex: {commit_tx.hex()[:80]}...")
        print()

        # Save CBOR bytes and resume info so the reveal step can use the same payload
        resume_info = {
            "commit_txid": commit_txid,
            "commit_vout": commit_vout,
            "commit_value": commit_value,
            "cbor_hex": commit_result.cbor_bytes.hex(),
        }
        with open("/tmp/glyph_mint_resume.json", "w") as f:
            import json as _json
            _json.dump(resume_info, f)
        print(f"Resume info saved to /tmp/glyph_mint_resume.json")

        if DRY_RUN:
            print("[DRY RUN] Commit tx not broadcast. Set DRY_RUN=0 to broadcast.")
            print(f"To resume reveal after broadcast:")
            print(f"  COMMIT_TXID={commit_txid} COMMIT_VOUT=0 COMMIT_VALUE={commit_value}")
            print(f"  Or: CBOR_HEX={commit_result.cbor_bytes.hex()}")
            return
        else:
            print("Broadcasting commit tx...")
            result = await broadcast(commit_tx.hex())
            print(f"Broadcast result: {result}")
            if result != commit_txid:
                print(f"WARNING: returned txid {result!r} != computed {commit_txid!r}")
            print(f"\nCommit tx broadcast: {commit_txid}")
            print("Waiting 90s for commit to confirm before reveal (Radiant ~2min block time)...")
            await asyncio.sleep(90)

    # Step 3: Build and broadcast reveal transaction
    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=commit_vout,
            commit_value=commit_value,
            cbor_bytes=commit_result.cbor_bytes,
            owner_pkh=Hex20(pkh_bytes),
            is_nft=True,
        )
    )

    reveal_tx = build_reveal_tx(
        commit_txid=commit_txid,
        commit_vout=commit_vout,
        commit_value=commit_value,
        commit_script_bytes=commit_result.commit_script,
        scriptsig_suffix=reveal_scripts.scriptsig_suffix,
        nft_locking_script_bytes=reveal_scripts.locking_script,
        private_key=private_key,
        address=address,
    )
    reveal_txid = reveal_tx.txid()

    print(f"Reveal tx: {reveal_txid}")
    print(f"  size: {reveal_tx.byte_length()} bytes")
    print(f"  fee: {reveal_tx.get_fee():,} photons")
    print(f"  NFT output: {reveal_tx.outputs[0].satoshis:,} photons")
    print(f"  locking script: {reveal_scripts.locking_script.hex()}")
    print(f"  hex: {reveal_tx.hex()[:80]}...")
    print()

    if DRY_RUN:
        print("[DRY RUN] Reveal tx not broadcast.")
        print(f"Reveal tx hex:\n{reveal_tx.hex()}")
        return

    print("Broadcasting reveal tx...")
    result = await broadcast(reveal_tx.hex())
    print(f"Broadcast result: {result}")
    print()
    print("=== Glyph NFT minted successfully! ===")
    print(f"  Commit txid: {commit_txid}")
    print(f"  Reveal txid: {reveal_txid}")
    print(f"  NFT ref:     {commit_txid}:{commit_vout}")
    print(f"  Owner:       {address}")


if __name__ == "__main__":
    asyncio.run(main())
