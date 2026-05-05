#!/usr/bin/env python3
"""Transfer an existing Glyph FT token between addresses on Radiant mainnet.

This is the "send tokens you already own" flow. Unlike ``ft_deploy_premine.py``
(which mints a brand-new token), this script spends FT-bearing UTXOs the
sender already holds and produces a recipient FT output (plus FT change if
the transfer is partial).

Why this example exists
-----------------------
The unit test ``tests/test_ft_transfer.py`` synthesises FT UTXOs in-process
via ``build_ft_locking_script(...)``. That works to validate conservation
arithmetic and signing — but it bypasses the "is this UTXO actually an
on-chain FT UTXO holding the token I think it holds?" question entirely.
Adapting the test pattern to live data without that filter produces txs
the network rejects with::

    bad-txns-inputs-outputs-invalid-transaction-reference-operations
    (code 19)

…because Radiant's ref-conservation rule forbids materialising
``OP_PUSHINPUTREF`` outputs without an input that already carries the same
ref. Plain RXD UTXOs can't fund FT transfers — only the *FT UTXOs of the
specific token* can.

This example shows the correct filter: fetch the wallet's UTXOs, fetch each
source tx, classify the locking script, and only build ``FtUtxo`` records
for outputs that are actually FT scripts for the target token's ref.

Usage
-----
    SENDER_WIF=<wif> \\
    TOKEN_REF=<txid:vout> \\
    RECIPIENT_ADDR=<R…> \\
    AMOUNT=<units> \\
    python examples/ft_transfer_demo.py

    # Dry-run (builds + prints raw hex but does not broadcast):
    DRY_RUN=1 SENDER_WIF=… TOKEN_REF=… RECIPIENT_ADDR=… AMOUNT=… \\
      python examples/ft_transfer_demo.py

Environment
-----------
    SENDER_WIF       WIF private key holding the FT UTXOs (required)
    TOKEN_CONTRACT   72-char contract id as shown in Radiant explorers,
                     e.g. ``b45dc4...a2a800000004`` for RBG. Either this
                     OR ``TOKEN_REF`` is required.
    TOKEN_REF        Alternative form: ``<txid>:<vout>``, e.g.
                     ``b45dc4...a2a8:4``. Use whichever is more convenient.
    RECIPIENT_ADDR   Radiant address (R…) of the recipient (required)
    AMOUNT           FT units to send (required, integer)
    DRY_RUN          Default ``1``; set to ``0`` to actually broadcast
    ELECTRUMX_URL    WebSocket URL (default: radiant4people mainnet)
    FEE_RATE         photons/byte for the transfer (default: 10000)
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph.builder import FtTransferParams, FtUtxo, GlyphBuilder
from pyrxd.glyph.script import extract_ref_from_ft_script, is_ft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"
ELECTRUMX_URL: str = os.environ.get("ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/")
SENDER_WIF: str = os.environ.get("SENDER_WIF", "")
TOKEN_CONTRACT: str = os.environ.get("TOKEN_CONTRACT", "")
TOKEN_REF: str = os.environ.get("TOKEN_REF", "")
RECIPIENT_ADDR: str = os.environ.get("RECIPIENT_ADDR", "")
AMOUNT: int = int(os.environ.get("AMOUNT", "0"))
FEE_RATE: int = int(os.environ.get("FEE_RATE", "10000"))


# ---------------------------------------------------------------------------
# Address → PKH (Radiant base58check P2PKH)
# ---------------------------------------------------------------------------


_RADIANT_MAINNET_VERSION_BYTE = 0x00  # Radiant uses Bitcoin mainnet's P2PKH version


def address_to_pkh(address: str) -> Hex20:
    """Decode a Radiant P2PKH address to its 20-byte hash160.

    Validates base58check, payload length, and version byte. Mismatched
    version (e.g. a Bitcoin testnet or Litecoin address pasted by mistake)
    is rejected — silently accepting cross-network addresses would let a
    transfer go to an unspendable script.

    .. warning::

       Radiant mainnet P2PKH shares Bitcoin mainnet's ``0x00`` version byte.
       This check **cannot** distinguish a Bitcoin mainnet address from a
       Radiant one — both decode the same way. Confirm the address is a
       Radiant address out-of-band before broadcasting, or the transfer will
       go to an unspendable script.
    """
    from pyrxd.base58 import base58check_decode

    try:
        payload = base58check_decode(address)
    except Exception as exc:
        raise ValueError(f"invalid Radiant address: {address!r}") from exc
    if len(payload) != 21:
        raise ValueError(f"address must decode to 21 bytes (1 version + 20 hash); got {len(payload)}")
    if payload[0] != _RADIANT_MAINNET_VERSION_BYTE:
        raise ValueError(
            f"unsupported address version byte {payload[0]:#x}: "
            f"expected {_RADIANT_MAINNET_VERSION_BYTE:#x} (Radiant mainnet P2PKH)"
        )
    return Hex20(payload[1:])


# ---------------------------------------------------------------------------
# FT UTXO collection — the key step the unit test fixtures hide
# ---------------------------------------------------------------------------


async def collect_ft_utxos(
    client: ElectrumXClient,
    sender_address: str,
    token_ref: GlyphRef,
) -> list[FtUtxo]:
    """Find every FT UTXO at *sender_address* that holds the *token_ref* token.

    For each raw UTXO from electrumx ``listunspent``:

    1. Fetch the source transaction (electrumx doesn't include the locking
       script in ``listunspent``; we have to fetch it).
    2. Classify the output's locking script — only 75-byte FT scripts qualify.
    3. Decode the ref encoded inside the script and require an exact match to
       *token_ref*. Different tokens have different refs even though their
       script layout is identical.

    UTXOs that fail any check are silently skipped. The returned list contains
    only correctly-classified, ref-matching FT UTXOs ready for ``FtUtxoSet``.
    """
    raw_utxos = await client.get_utxos(script_hash_for_address(sender_address))
    ft_utxos: list[FtUtxo] = []

    for u in raw_utxos:
        try:
            raw = await client.get_transaction(Txid(u.tx_hash))
        except NetworkError:
            continue
        tx = Transaction.from_hex(bytes(raw))
        if tx is None or u.tx_pos >= len(tx.outputs):
            continue
        script = tx.outputs[u.tx_pos].locking_script.serialize()  # bytes
        if not is_ft_script(script.hex()):
            continue  # not an FT lock at all (probably plain P2PKH RXD)
        if extract_ref_from_ft_script(script) != token_ref:
            continue  # FT, but a different token
        ft_utxos.append(
            FtUtxo(
                txid=u.tx_hash,
                vout=u.tx_pos,
                value=u.value,
                ft_amount=u.value,  # 1 photon = 1 FT unit (consensus rule)
                ft_script=script,
            )
        )

    return ft_utxos


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _parse_token_ref(s: str) -> GlyphRef:
    if ":" not in s:
        raise ValueError(f"TOKEN_REF must be 'txid:vout', got {s!r}")
    txid_hex, vout_str = s.split(":", 1)
    return GlyphRef(txid=Txid(txid_hex), vout=int(vout_str))


def _resolve_token_ref() -> GlyphRef:
    """Resolve the token ref from either TOKEN_CONTRACT or TOKEN_REF.

    Both forms describe the same deploy outpoint; users supply whichever
    is more convenient. A 72-char contract id (as shown in explorers) is
    decoded via :meth:`GlyphRef.from_contract_hex`; a ``txid:vout`` string
    is parsed directly. Setting both is rejected to avoid silent mismatches.
    """
    if TOKEN_CONTRACT and TOKEN_REF:
        raise ValueError("set either TOKEN_CONTRACT or TOKEN_REF, not both")
    if TOKEN_CONTRACT:
        return GlyphRef.from_contract_hex(TOKEN_CONTRACT)
    if TOKEN_REF:
        return _parse_token_ref(TOKEN_REF)
    raise ValueError("set TOKEN_CONTRACT (72-char contract id) or TOKEN_REF (txid:vout)")


async def main() -> None:
    if not SENDER_WIF:
        print("ERROR: set SENDER_WIF to the WIF private key holding the FT UTXOs")
        sys.exit(1)
    if not (TOKEN_CONTRACT or TOKEN_REF):
        print("ERROR: set TOKEN_CONTRACT (72-char contract id) or TOKEN_REF (txid:vout)")
        sys.exit(1)
    if not RECIPIENT_ADDR:
        print("ERROR: set RECIPIENT_ADDR to the recipient's R… address")
        sys.exit(1)
    if AMOUNT <= 0:
        print("ERROR: set AMOUNT to a positive integer (FT units to send)")
        sys.exit(1)

    # Wrap the WIF decode so a malformed key doesn't surface a base58
    # ValueError whose traceback echoes the (almost-correct) WIF on stderr.
    try:
        sender_key = PrivateKey(SENDER_WIF)
    except Exception:
        print("ERROR: SENDER_WIF could not be decoded as a WIF private key", file=sys.stderr)
        sys.exit(1)
    sender_address = sender_key.public_key().address()
    try:
        recipient_pkh = address_to_pkh(RECIPIENT_ADDR)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        token_ref = _resolve_token_ref()
    except (ValueError, ValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Sender:      {sender_address}")
    print(f"Recipient:   {RECIPIENT_ADDR}")
    print(f"Token ref:   {token_ref.txid}:{token_ref.vout}")
    print(f"Amount:      {AMOUNT:,} FT units")
    print(f"Fee rate:    {FEE_RATE} photons/byte")
    print(f"DRY_RUN:     {DRY_RUN}")
    print()

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        print("Scanning for FT UTXOs...")
        ft_utxos = await collect_ft_utxos(client, sender_address, token_ref)
        if not ft_utxos:
            print(f"No FT UTXOs found at {sender_address} for ref {token_ref.txid}:{token_ref.vout}.")
            print()
            print("Things to check:")
            print(f"  - confirm with a Radiant explorer that {sender_address}")
            print(f"    actually holds the token at ref {token_ref.txid}:{token_ref.vout}")
            print("  - confirm TOKEN_REF is the token's *deploy* outpoint, not a transfer outpoint")
            print("  - confirm the wallet derivation matches the address holding the FTs")
            sys.exit(2)
        total_ft = sum(u.ft_amount for u in ft_utxos)
        print(f"Found {len(ft_utxos)} FT UTXO(s), total: {total_ft:,} FT units")
        if total_ft < AMOUNT:
            print(f"ERROR: insufficient FT balance — need {AMOUNT:,}, have {total_ft:,}")
            sys.exit(2)

        builder = GlyphBuilder()
        result = builder.build_ft_transfer_tx(
            FtTransferParams(
                ref=token_ref,
                utxos=ft_utxos,
                amount=AMOUNT,
                new_owner_pkh=recipient_pkh,
                private_key=sender_key,
                fee_rate=FEE_RATE,
            )
        )

        print()
        print(f"Transfer tx: {result.tx.txid()}")
        print(f"  size:      {result.tx.byte_length()} bytes")
        print(f"  fee:       {result.fee:,} photons")
        print(f"  inputs:    {len(result.tx.inputs)}")
        print(f"  outputs:   {len(result.tx.outputs)}")
        print(f"  to:        {RECIPIENT_ADDR} ({AMOUNT:,} FT units)")
        if result.change_ft_script is not None:
            # Recover selected inputs by matching tx.inputs back to the offered
            # ft_utxos pool by (txid, vout). Greedy-largest-first selection
            # means tx.inputs is a *subset* of ft_utxos, so total_ft - AMOUNT
            # would over-report the change.
            selected_keys = {(str(inp.source_txid), inp.source_output_index) for inp in result.tx.inputs}
            selected_ft_in = sum(u.ft_amount for u in ft_utxos if (u.txid, u.vout) in selected_keys)
            change_amount = selected_ft_in - AMOUNT
            print(f"  change:    {sender_address} ({change_amount:,} FT units)")
        print()

        if DRY_RUN:
            print("[DRY RUN] Transfer tx not broadcast. Set DRY_RUN=0 to broadcast.")
            print()
            print(f"Raw tx hex:\n{result.tx.hex()}")
            return

        print("Broadcasting transfer tx...")
        txid = await client.broadcast(result.tx.serialize())
        print(f"Broadcast result: {txid}")


if __name__ == "__main__":
    asyncio.run(main())
