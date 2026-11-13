"""Swap records with an ETH counter leg, for the ``pyrxd swap build-eth-refund`` tests (#818).

The record is what ``scripts/eth_swap_run.py`` writes beside its recovery file
(``<keys-out>.swaprec.json``, through :class:`~pyrxd.gravity.record_sink.JsonFileRecordSink`), so
the tests write it the same way.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pyrxd.btc_wallet import taproot as t
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_state import NegotiatedTerms, RecordRole, SwapRecord, SwapState


def eth_terms(hashlock: bytes, *, amount: int, timeout: int, token_address: str = "") -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(36, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=amount,
        eth_timeout_unix_s=timeout,
        token_address=token_address,
    )


def eth_record(
    locator: EthHtlcLocator,
    *,
    state: SwapState = SwapState.BOTH_LOCKED,
    role: RecordRole | None = RecordRole.TAKER,
    **fields: Any,
) -> SwapRecord:
    token = locator.token_address if isinstance(locator, Erc20HtlcLocator) else ""
    terms = eth_terms(locator.hashlock_bytes, amount=locator.amount_wei, timeout=locator.timeout, token_address=token)
    return SwapRecord(state=state, terms=terms, counterchain_locator=locator, role=role, **fields)


def write_record(swap_file: Path, record: SwapRecord) -> Path:
    """Persist *record* where the ETH runners do: ``<swap_file>.swaprec.json``."""
    path = Path(str(swap_file) + ".swaprec.json")
    asyncio.run(JsonFileRecordSink(path)(record))
    return path
