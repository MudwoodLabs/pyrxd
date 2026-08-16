#!/usr/bin/env python3
"""Transfer an existing Glyph FT token between addresses on Radiant mainnet.

This is the "send tokens you already own" flow. Unlike ``ft_deploy_premine.py``
(which mints a brand-new token), this script spends FT-bearing UTXOs the sender
already holds and produces a recipient FT output (plus FT change if the transfer
is partial).

What this example is for now
----------------------------
It used to be 399 lines, because the only working transfer implementation lived
inside ``pyrxd.cli`` where nothing could import it, so this file re-implemented
the whole path: scan the address, fetch each source transaction, classify every
locking script, match the token ref, find a plain-RXD UTXO for the fee, then
assemble and sign. All of that is now :mod:`pyrxd.glyph.transfer`, reachable
through :class:`~pyrxd.glyph.client.GlyphClient`, so the example can show the
API instead of a re-implementation of it.

Two things this still has to teach, because the SDK cannot do them for you:

**1. The token cannot pay its own fee.** On Radiant an FT's quantity **is** its
output's photon value — 1 photon = 1 unit — so subtracting a fee from a token
output burns units and delivers the recipient less than was asked for. The fee
comes from a separate plain-RXD input. The sending address must hold a little
plain RXD as well as the token; ``transfer-nft`` sources a separate input for
the same reason.

**2. The transfer path wants a wallet, and a WIF is not one.**
:class:`~pyrxd.glyph.client.GlyphClient` is built for
:class:`~pyrxd.hd.wallet.HdWallet`, which knows about many derived addresses.
This example holds exactly one key, so it supplies the small adapter below —
about twenty lines covering the two methods the transfer path actually calls.
If you already have an ``HdWallet``, pass it directly and delete the adapter.

Verify what you sign
--------------------
The delivered quantity is read back off the built transaction rather than
trusted to equal ``AMOUNT`` because ``AMOUNT`` was asked for. That check is
cheap, and Radiant has neither RBF nor CPFP — a wrong quantity cannot be
recalled once broadcast.

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
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph.client import GlyphClient
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20, Txid

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
# One WIF, shaped like a wallet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AddressRecord:
    """The two fields ``pyrxd.glyph.transfer`` reads off a wallet's addresses."""

    address: str
    used: bool = True


class SingleKeyWallet:
    """The minimum wallet surface :mod:`pyrxd.glyph.transfer` needs, over one key.

    The transfer path calls exactly two things: ``addresses`` (to know which
    addresses to scan for token holdings) and ``collect_spendable(client)`` (to
    get ``(utxo, address, key)`` triples it can select inputs and fee funding
    from). A single-key holder can supply both in a few lines.

    ``used=True`` because there is one address and it is the one to scan. An
    ``HdWallet`` tracks that per derived address so a fresh wallet does not scan
    a thousand empty ones; here the question does not arise.

    This is deliberately NOT in the library. It is the right shape for an example
    and for a script, but a real single-key wallet also wants change handling and
    an address-reuse policy, and shipping a name like ``SingleKeyWallet`` invites
    callers to assume it has them.
    """

    def __init__(self, key: PrivateKey) -> None:
        self._key = key
        self.address: str = key.public_key().address()
        self.addresses: dict[str, _AddressRecord] = {"single": _AddressRecord(address=self.address)}

    async def collect_spendable(self, client: ElectrumXClient) -> list[tuple[object, str, PrivateKey]]:
        """Every UTXO at this key's address, as ``(utxo, address, key)`` triples.

        Token-bearing UTXOs are returned too — filtering is the transfer path's
        job, and it does it against each output's **on-chain** locking script
        rather than against anything asserted here. A funding UTXO is only ever
        chosen after being confirmed a bare 25-byte P2PKH, so this cannot cause
        a token to be spent as fee.
        """
        utxos = await client.get_utxos(script_hash_for_address(self.address))
        return [(u, self.address, self._key) for u in utxos]


# ---------------------------------------------------------------------------
# Token ref resolution
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


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

    wallet = SingleKeyWallet(sender_key)

    print(f"Sender:      {wallet.address}")
    print(f"Recipient:   {RECIPIENT_ADDR}")
    print(f"Token ref:   {token_ref.txid}:{token_ref.vout}")
    print(f"Amount:      {AMOUNT:,} FT units")
    print(f"Fee rate:    {FEE_RATE} photons/byte")
    print(f"DRY_RUN:     {DRY_RUN}")
    print()

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        glyph = GlyphClient(client, wallet, fee_rate=FEE_RATE)

        # Build and sign, but do NOT broadcast: `build_ft_transfer` stops at a
        # signed transaction so the caller can show it to a human first, which is
        # what the CLI does and what the checks below do here. `transfer_ft` is
        # the one-call version that also broadcasts.
        print("Selecting FT inputs and fee funding...")
        try:
            build = await glyph.build_ft_transfer(token_ref, AMOUNT, recipient_pkh)
        except InsufficientFundsError as exc:
            msg = str(exc)
            print(f"ERROR: {msg}", file=sys.stderr)
            print()
            if "plain-RXD" in msg:
                print("An FT output's value IS its unit count on Radiant, so the token cannot pay")
                print("its own fee without burning units. Send a little plain RXD to this address")
                print("and re-run.")
            else:
                print("Things to check:")
                print(f"  - confirm with a Radiant explorer that {wallet.address}")
                print(f"    actually holds the token at ref {token_ref.txid}:{token_ref.vout}")
                print("  - confirm the ref is the token's *deploy* outpoint, not a transfer outpoint")
            sys.exit(2)
        except ValidationError as exc:
            print(f"ERROR: could not build the transfer: {exc}", file=sys.stderr)
            sys.exit(2)

        raw = build.serialize()
        print()
        print(f"Transfer tx: {build.tx.txid()}")
        print(f"  size:      {len(raw)} bytes")
        print(f"  fee:       {build.fee:,} photons (from plain RXD, not the token)")
        print(f"  inputs:    {len(build.tx.inputs)}")
        print(f"  outputs:   {len(build.tx.outputs)}")
        print(f"  to:        {RECIPIENT_ADDR} ({AMOUNT:,} FT units)")
        print()

        # Read the delivered quantity back off the built transaction rather than
        # trusting that it equals AMOUNT because we asked for AMOUNT. Output [0]
        # is the recipient's; on Radiant its photon value IS the unit count.
        delivered = build.tx.outputs[0].satoshis
        if delivered != AMOUNT:
            print(f"REFUSING TO BROADCAST: recipient output is {delivered:,} units, not {AMOUNT:,}.")
            sys.exit(3)
        print(f"Verified:    recipient output carries exactly {delivered:,} units")
        print()

        if DRY_RUN:
            print("[DRY RUN] Transfer tx not broadcast. Set DRY_RUN=0 to broadcast.")
            print()
            print(f"Raw tx hex:\n{raw.hex()}")
            return

        print("Broadcasting transfer tx...")
        txid = await client.broadcast(raw)
        print(f"Broadcast result: {txid}")


if __name__ == "__main__":
    asyncio.run(main())
