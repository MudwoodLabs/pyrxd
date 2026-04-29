#!/usr/bin/env python3
"""Deploy a plain-FT Glyph token with a full premine on Radiant mainnet.

This is the canonical "issue your own token" flow using pyrxd:

  1. Build GlyphMetadata with ``protocol=[GlyphProtocol.FT]``
  2. prepare_commit   → commit locking script + payload hash
  3. Broadcast commit tx (P2PKH inputs → commit output + change)
  4. prepare_ft_deploy_reveal → FT locking script + scriptSig suffix
  5. Broadcast reveal tx (commit output → FT output carrying full supply)

The reveal output's outpoint becomes the permanent token ref.  All issued
units land in the deployer's FT UTXO.  Radiant convention: 1 photon = 1 FT
unit, so ``PREMINE_AMOUNT`` is the integer supply.

Usage
-----
    GLYPH_WIF=<wif> python examples/ft_deploy_premine.py

    # Dry-run (builds txs but does not broadcast):
    DRY_RUN=1 GLYPH_WIF=<wif> python examples/ft_deploy_premine.py

    # Resume reveal phase after commit was broadcast:
    COMMIT_TXID=<txid> COMMIT_VOUT=0 COMMIT_VALUE=<photons> \\
      GLYPH_WIF=<wif> python examples/ft_deploy_premine.py

Environment
-----------
    GLYPH_WIF        WIF private key for the deploying wallet (required)
    DRY_RUN          Set to '0' to broadcast; any other value = dry-run (default)
    ELECTRUMX_URL    WebSocket URL for ElectrumX (default: radiant4people mainnet)
    COMMIT_TXID      If set, skip commit and go straight to reveal
    COMMIT_VOUT      Output index of commit tx (default 0)
    COMMIT_VALUE     Photons in commit output (required when COMMIT_TXID is set)
    TOKEN_NAME       Token name (default: MY-TOKEN)
    TOKEN_TICKER     Ticker symbol, max 16 chars (default: MTK)
    PREMINE_AMOUNT   Integer supply in FT units/photons (default: 1_000_000)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import websockets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import CommitParams
from pyrxd.hash import sha256
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
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
TOKEN_NAME: str = os.environ.get("TOKEN_NAME", "MY-TOKEN")
TOKEN_TICKER: str = os.environ.get("TOKEN_TICKER", "MTK")
PREMINE_AMOUNT: int = int(os.environ.get("PREMINE_AMOUNT", "1000000"))

MIN_FEE_RATE = 10_000       # photons/byte
COMMIT_SIZE = 276            # estimated commit tx bytes
REVEAL_SIZE = 610            # conservative: 250 base + 165 scriptsig + FT locking script
COMMIT_DUST = COMMIT_SIZE * MIN_FEE_RATE
REVEAL_BUDGET = REVEAL_SIZE * MIN_FEE_RATE * 12 // 10 + PREMINE_AMOUNT
COMMIT_VALUE_TARGET = REVEAL_BUDGET + 200_000   # commit output must cover reveal + premine

RESUME_FILE = "/tmp/ft_deploy_resume.json"


# ---------------------------------------------------------------------------
# ElectrumX helpers
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
    script_hash = sha256(script.serialize()).hex()
    rev_hash = "".join(reversed([script_hash[i:i+2] for i in range(0, len(script_hash), 2)]))
    return await electrumx_call("blockchain.scripthash.listunspent", [rev_hash])


async def broadcast(tx_hex: str) -> str:
    return await electrumx_call("blockchain.transaction.broadcast", [tx_hex])


# ---------------------------------------------------------------------------
# Unlocking template helpers
# ---------------------------------------------------------------------------


def p2pkh_unlock_template(private_key: PrivateKey):
    """Standard P2PKH unlock template (sign + pubkey push)."""
    def sign(tx, idx) -> Script:
        sig = private_key.sign(tx.preimage(idx))
        sighash = tx.inputs[idx].sighash
        pub = private_key.public_key().serialize()
        return Script(
            encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        )

    def estimated_len() -> int:
        return 107

    return to_unlock_script_template(sign, estimated_len)


def ft_reveal_unlock_template(private_key: PrivateKey, scriptsig_suffix: bytes):
    """Unlock template for the FT reveal input: P2PKH signature + Glyph suffix."""
    def sign(tx, idx) -> Script:
        sig = private_key.sign(tx.preimage(idx))
        sighash = tx.inputs[idx].sighash
        pub = private_key.public_key().serialize()
        p2pkh_part = (
            encode_pushdata(sig + sighash.to_bytes(1, "little"))
            + encode_pushdata(pub)
        )
        return Script(p2pkh_part + scriptsig_suffix)

    def estimated_len() -> int:
        return 107 + len(scriptsig_suffix)

    return to_unlock_script_template(sign, estimated_len)


# ---------------------------------------------------------------------------
# Transaction builders
# ---------------------------------------------------------------------------


def build_commit_tx(
    utxos: list,
    private_key: PrivateKey,
    commit_script: bytes,
    commit_value: int,
    address: str,
) -> Transaction:
    """Spend P2PKH UTXOs, place commit script at vout 0, change at vout 1."""
    from pyrxd.fee_models import SatoshisPerKilobyte

    inputs = []
    total_in = 0
    for utxo in utxos:
        src_out = TransactionOutput(P2PKH().lock(address), utxo["value"])

        class _SrcTx:
            def __init__(self, out, pos):
                self.outputs = {pos: out}

        inp = TransactionInput(
            source_txid=utxo["tx_hash"],
            source_output_index=utxo["tx_pos"],
            unlocking_script_template=p2pkh_unlock_template(private_key),
        )
        inp.satoshis = utxo["value"]
        inp.locking_script = P2PKH().lock(address)
        inp.source_transaction = _SrcTx(src_out, utxo["tx_pos"])
        inputs.append(inp)
        total_in += utxo["value"]
        if total_in >= commit_value + COMMIT_DUST * 3:
            break

    if total_in < commit_value:
        raise ValueError(f"Insufficient funds: have {total_in:,}, need {commit_value:,} photons")

    tx = Transaction(
        tx_inputs=inputs,
        tx_outputs=[
            TransactionOutput(Script(commit_script), commit_value),
            TransactionOutput(P2PKH().lock(address), change=True),
        ],
    )
    tx.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))
    tx.sign()
    return tx


def build_reveal_tx(
    commit_txid: str,
    commit_vout: int,
    commit_value: int,
    commit_script: bytes,
    scriptsig_suffix: bytes,
    ft_locking_script: bytes,
    premine_amount: int,
    private_key: PrivateKey,
) -> Transaction:
    """Spend commit output, produce FT output carrying full premine."""
    src = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(Script(commit_script), commit_value)],
    )
    src.txid = lambda: commit_txid  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src,
        source_output_index=commit_vout,
        unlocking_script_template=ft_reveal_unlock_template(private_key, scriptsig_suffix),
    )

    # Two-pass fee: trial tx → measure size → compute fee → set FT output value.
    # The FT locking script holds ``premine_amount`` photons (1 photon = 1 FT unit).
    # Whatever is left from commit_value after fee covers the FT output.
    trial_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(ft_locking_script), premine_amount)],
    )
    trial_tx.sign()
    actual_size = trial_tx.byte_length()

    fee = actual_size * (MIN_FEE_RATE + 500)
    leftover = commit_value - premine_amount - fee
    if leftover < 0:
        raise ValueError(
            f"Commit value ({commit_value:,}) too small: "
            f"premine ({premine_amount:,}) + fee ({fee:,}) = {premine_amount + fee:,}. "
            f"Increase COMMIT_VALUE_TARGET or reduce PREMINE_AMOUNT."
        )

    # Re-sign over final outputs (not the trial outputs used for size measurement).
    reveal_input.unlocking_script = None

    tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(ft_locking_script), premine_amount)],
    )
    tx.sign()
    return tx


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    if not GLYPH_WIF:
        print("ERROR: Set GLYPH_WIF to your funded WIF private key")
        sys.exit(1)

    private_key = PrivateKey(GLYPH_WIF)
    pub = private_key.public_key()
    address = pub.address()
    pkh = Hex20(pub.hash160())

    print(f"Deployer wallet: {address}")
    print(f"Token name:      {TOKEN_NAME}")
    print(f"Ticker:          {TOKEN_TICKER}")
    print(f"Premine supply:  {PREMINE_AMOUNT:,} FT units")
    print(f"DRY_RUN:         {DRY_RUN}")
    print()

    # Step 1: Build FT metadata (protocol=[FT])
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.FT],
        name=TOKEN_NAME,
        ticker=TOKEN_TICKER,
        description=f"{TOKEN_NAME} — issued via pyrxd ft_deploy_premine example",
        attrs={"issued_at": str(int(time.time())), "sdk": "pyrxd-0.2.0rc1"},
    )

    builder = GlyphBuilder()
    commit_result = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=pkh,
            change_pkh=pkh,
            funding_satoshis=0,
        )
    )
    print(f"Payload hash:  {commit_result.payload_hash.hex()}")
    print(f"CBOR ({len(commit_result.cbor_bytes)} bytes): {commit_result.cbor_bytes.hex()}")
    print()

    # Step 2: Commit phase
    if RESUME_COMMIT_TXID:
        commit_txid = RESUME_COMMIT_TXID
        commit_vout = RESUME_COMMIT_VOUT
        commit_value = RESUME_COMMIT_VALUE
        print(f"Resuming from commit {commit_txid}:{commit_vout} ({commit_value:,} photons)")
        # Try to reload CBOR from prior run so payload hash stays consistent.
        try:
            with open(RESUME_FILE) as f:
                saved = json.load(f)
            if saved.get("commit_txid") == commit_txid:
                from pyrxd.glyph.builder import CommitResult
                from pyrxd.glyph.script import build_commit_locking_script, hash_payload
                saved_cbor = bytes.fromhex(saved["cbor_hex"])
                saved_hash = hash_payload(saved_cbor)
                saved_script = build_commit_locking_script(saved_hash, pkh)
                commit_result = CommitResult(
                    commit_script=saved_script,
                    cbor_bytes=saved_cbor,
                    payload_hash=saved_hash,
                    estimated_fee=commit_result.estimated_fee,
                )
                print(f"Loaded saved CBOR from {RESUME_FILE}")
        except FileNotFoundError:
            print(f"No resume file found at {RESUME_FILE} — using fresh CBOR (MUST match commit tx)")
        except Exception as e:
            print(f"Warning: could not load resume file: {e}")
    else:
        print("Fetching UTXOs...")
        utxos = await fetch_utxos(address)
        if not utxos:
            print("No UTXOs found. Fund the address and retry.")
            sys.exit(1)
        total = sum(u["value"] for u in utxos)
        print(f"Found {len(utxos)} UTXO(s), total: {total:,} photons")

        commit_value = COMMIT_VALUE_TARGET
        commit_tx = build_commit_tx(
            utxos=utxos,
            private_key=private_key,
            commit_script=commit_result.commit_script,
            commit_value=commit_value,
            address=address,
        )
        commit_txid = commit_tx.txid()
        commit_vout = 0
        commit_value = commit_tx.outputs[0].satoshis

        print(f"Commit tx:     {commit_txid}")
        print(f"  size:        {commit_tx.byte_length()} bytes")
        print(f"  fee:         {commit_tx.get_fee():,} photons")
        print(f"  commit out:  {commit_value:,} photons")
        print()

        resume_info = {
            "commit_txid": commit_txid,
            "commit_vout": commit_vout,
            "commit_value": commit_value,
            "cbor_hex": commit_result.cbor_bytes.hex(),
        }
        with open(RESUME_FILE, "w") as f:
            json.dump(resume_info, f)
        print(f"Resume info saved to {RESUME_FILE}")

        if DRY_RUN:
            print("[DRY RUN] Commit tx not broadcast. Set DRY_RUN=0 to broadcast.")
            print(f"  Resume env: COMMIT_TXID={commit_txid} COMMIT_VOUT=0 COMMIT_VALUE={commit_value}")
            return
        else:
            print("Broadcasting commit tx...")
            result = await broadcast(commit_tx.hex())
            print(f"Broadcast result: {result}")
            print("Waiting 90s for commit to confirm before reveal...")
            await asyncio.sleep(90)

    # Step 3: Reveal phase — prepare_ft_deploy_reveal
    reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=commit_txid,
        commit_vout=commit_vout,
        commit_value=commit_value,
        cbor_bytes=commit_result.cbor_bytes,
        premine_pkh=pkh,
        premine_amount=PREMINE_AMOUNT,
    )

    reveal_tx = build_reveal_tx(
        commit_txid=commit_txid,
        commit_vout=commit_vout,
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        scriptsig_suffix=reveal_scripts.scriptsig_suffix,
        ft_locking_script=reveal_scripts.locking_script,
        premine_amount=reveal_scripts.premine_amount,
        private_key=private_key,
    )
    reveal_txid = reveal_tx.txid()

    print(f"Reveal tx:     {reveal_txid}")
    print(f"  size:        {reveal_tx.byte_length()} bytes")
    print(f"  fee:         {reveal_tx.get_fee():,} photons")
    print(f"  FT output:   {reveal_tx.outputs[0].satoshis:,} photons ({PREMINE_AMOUNT:,} FT units)")
    print(f"  FT locking:  {reveal_scripts.locking_script.hex()}")
    print(f"  Token ref:   {commit_txid}:{commit_vout}")
    print()

    if DRY_RUN:
        print("[DRY RUN] Reveal tx not broadcast.")
        print(f"Reveal tx hex:\n{reveal_tx.hex()}")
        return

    print("Broadcasting reveal tx...")
    result = await broadcast(reveal_tx.hex())
    print(f"Broadcast result: {result}")
    print()
    print("=== FT token deployed successfully! ===")
    print(f"  Token name:  {TOKEN_NAME} ({TOKEN_TICKER})")
    print(f"  Supply:      {PREMINE_AMOUNT:,} FT units")
    print(f"  Token ref:   {commit_txid}:{commit_vout}")
    print(f"  Reveal txid: {reveal_txid}")
    print(f"  Owner:       {address}")


if __name__ == "__main__":
    asyncio.run(main())
