"""Async helpers to fetch the transactions a swap references.

Kept separate from the pure :mod:`pyrxd.swap.partial` core so that
``import pyrxd.swap`` pulls in no network dependencies — the
``ElectrumXClient`` import is deferred into the functions that use it.

A maker uses :func:`fetch_transaction` to load the source tx of the UTXO
they want to give; a taker uses :func:`fetch_funding_input` to load each
of their own funding UTXOs. The maker's source tx travels inside the
:class:`~pyrxd.swap.types.SwapOffer`, so a taker never needs the network
to *verify* an offer — only to gather their own funding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..keys import PrivateKey
from ..security.errors import ValidationError
from ..security.types import Txid
from ..transaction.transaction import Transaction
from .partial import FundingInput

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient


async def fetch_transaction(client: ElectrumXClient, txid: str | Txid) -> Transaction:
    """Fetch and parse a transaction, verifying it actually hashes to *txid*.

    The server-honesty check (computed txid == requested txid) means a
    hostile or buggy server cannot substitute a different transaction.
    """
    wanted = Txid(str(txid))
    raw = await client.get_transaction(wanted)
    tx = Transaction.from_hex(bytes(raw))
    if tx is None:
        raise ValidationError(f"could not parse the transaction returned for {wanted}")
    if tx.txid() != str(wanted):
        raise ValidationError(f"server returned a transaction whose hash != requested txid ({wanted})")
    return tx


async def fetch_funding_input(
    client: ElectrumXClient,
    *,
    txid: str | Txid,
    vout: int,
    key: PrivateKey,
) -> FundingInput:
    """Resolve one of the taker's UTXOs into a :class:`FundingInput` for ``accept_offer``."""
    source_tx = await fetch_transaction(client, txid)
    if not 0 <= vout < len(source_tx.outputs):
        raise ValidationError(f"vout {vout} out of range for transaction {txid}")
    return FundingInput(source_tx=source_tx, vout=vout, key=key)
