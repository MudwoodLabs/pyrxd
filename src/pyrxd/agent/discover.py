"""Watch-only UTXO discovery from an account xpub (CLI-side, no private key).

The agent vends the account ``xpub`` on unlock; this turns it into a spendable
UTXO set the way ``HdWallet.refresh``/``collect_spendable`` do — but key-free.
For each spendable output it also fetches the FULL source tx, because the agent
verifies every prevout against it (C1) before signing. Network I/O only; the
returned coords + source txs are exactly what :class:`WatchOnlyTxBuilder` needs.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..hd.bip32 import Xpub
from ..network.electrumx import ElectrumXClient, script_hash_for_address
from ..security.errors import ValidationError
from ..security.types import Txid
from .watch_only import WatchOnlyUtxo

#: BIP44 chains: 0 = external/receive, 1 = internal/change.
_EXTERNAL_CHAIN = 0
_INTERNAL_CHAIN = 1
_DEFAULT_GAP_LIMIT = 20


@dataclass(frozen=True)
class WatchOnlyScan:
    """Result of a watch-only scan: spendable UTXOs + the next unused change index."""

    utxos: list[WatchOnlyUtxo]
    next_change_index: int


async def collect_watch_only_utxos(
    account_xpub: Xpub, client: ElectrumXClient, *, gap_limit: int = _DEFAULT_GAP_LIMIT
) -> WatchOnlyScan:
    """Gap-limit scan both BIP44 chains from the public xpub and collect spendable UTXOs.

    ``get_history`` marks a derived address used; ``get_utxos`` enumerates its
    spendable outputs; ``get_transaction`` fetches each output's source tx (for the
    agent's C1 prevout check). Also reports the next unused internal index, so the
    caller can place change on a fresh change address. No private key is touched.
    """
    if not isinstance(account_xpub, Xpub):
        raise ValidationError("account_xpub must be an Xpub (watch-only discovery: no private key)")
    if not isinstance(gap_limit, int) or isinstance(gap_limit, bool) or gap_limit <= 0:
        raise ValidationError("gap_limit must be a positive int")

    utxos: list[WatchOnlyUtxo] = []
    next_change_index = 0
    for change in (_EXTERNAL_CHAIN, _INTERNAL_CHAIN):
        chain_xpub = account_xpub.ckd(change)
        consecutive_unused = 0
        index = 0
        while consecutive_unused < gap_limit:
            address = chain_xpub.ckd(index).address()
            script_hash = script_hash_for_address(address)
            if await client.get_history(script_hash):
                consecutive_unused = 0
                if change == _INTERNAL_CHAIN:
                    next_change_index = index + 1
                for utxo in await client.get_utxos(script_hash):
                    raw = await client.get_transaction(Txid(utxo.tx_hash))
                    utxos.append(
                        WatchOnlyUtxo(
                            txid=utxo.tx_hash,
                            vout=utxo.tx_pos,
                            value=utxo.value,
                            change=change,
                            index=index,
                            source_tx_hex=bytes(raw).hex(),
                        )
                    )
            else:
                consecutive_unused += 1
            index += 1
    return WatchOnlyScan(utxos=utxos, next_change_index=next_change_index)
