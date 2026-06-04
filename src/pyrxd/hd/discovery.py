"""Multi-path account discovery for BIP44 wallet recovery.

The Radiant ecosystem never agreed on a BIP44 ``coin_type``, so the same
mnemonic produces different addresses (and apparently-empty balances) across
wallets and across versions of the same wallet:

    coin_type 0    Photonic <= v2.x (legacy), Electron-Radiant, Chainbow
    coin_type 512  SLIP-0044 spec, Tangem, Photonic >= v3.0.0
    coin_type 236  pre-#14 pyrxd (BSV's coin type)

A user whose funds landed on one path but whose wallet derives another sees a
zero balance even though the explorer shows the coins on-chain. :func:`discover`
resolves this: given a mnemonic, it scans every ``(coin_type, account)`` pair
over both BIP44 chains with the standard gap-limit and reports which derived
addresses actually have on-chain history.

This is a strict superset of Photonic v3.0.1's ``probeCoinTypeFromHistory``
(which probes only coin types {0, 512} at two fixed leaves): here every
account and every gap-limit index on both the receive and change chains is
covered, across an extra coin type.

Design constraints (see docs/plans/2026-06-04-feat-hd-wallet-multipath-recovery-discovery-plan.md):
- **Read-only.** Discovery reports *where* the funds are; moving them is a
  separate, explicit :meth:`HdWallet.send_max` the caller invokes afterwards.
  Recovery never signs or broadcasts.
- **Offline derivation.** The mnemonic never crosses the wire — only derived
  addresses do (for the scripthash history/balance queries).
- **Fail loud.** A network error mid-scan propagates rather than being
  silently reported as "empty". For a recovery tool, a partial scan
  misreported as complete is the dangerous failure mode; :meth:`HdWallet.refresh`
  already re-raises on network failure (N5) and we do not swallow it here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..network.electrumx import ElectrumXClient, script_hash_for_address
from .wallet import HdWallet

# The candidate coin types, in ecosystem-prevalence order. Kept here as the
# single source of truth for "which paths does recovery try by default".
DEFAULT_COIN_TYPES: tuple[int, ...] = (0, 512, 236)

# Account indices to scan by default. Most wallets only ever use account 0;
# 0..2 covers the rare multi-account setup without exploding the round-trip count.
DEFAULT_ACCOUNTS: tuple[int, ...] = (0, 1, 2)

# Human-readable labels so a hit explains *which* wallet wrote that path.
_COIN_TYPE_LABELS: dict[int, str] = {
    0: "legacy (Photonic <= v2 / Electron-Radiant / Chainbow)",
    512: "SLIP-0044 (Tangem / Photonic >= v3.0.0 / pyrxd default)",
    236: "legacy BSV coin type (pre-#14 pyrxd)",
}


def coin_type_label(coin_type: int) -> str:
    """Return a human label for *coin_type*, or a generic note if unknown."""
    return _COIN_TYPE_LABELS.get(coin_type, f"coin type {coin_type} (unrecognised)")


@dataclass(frozen=True)
class DiscoveryHit:
    """One derived address that has on-chain history."""

    coin_type: int
    account: int
    change: int  # 0 = external/receive, 1 = internal/change
    index: int
    address: str
    confirmed: int  # photons
    unconfirmed: int  # photons

    @property
    def path(self) -> str:
        return f"m/44'/{self.coin_type}'/{self.account}'/{self.change}/{self.index}"

    @property
    def total(self) -> int:
        return self.confirmed + self.unconfirmed


@dataclass(frozen=True)
class DiscoveryReport:
    """Result of a multi-path scan."""

    hits: list[DiscoveryHit]
    scanned: list[tuple[int, int]]  # (coin_type, account) pairs actually scanned
    total_confirmed: int
    total_unconfirmed: int

    @property
    def found(self) -> bool:
        return bool(self.hits)

    @property
    def total(self) -> int:
        return self.total_confirmed + self.total_unconfirmed


async def discover(
    client: ElectrumXClient,
    mnemonic: str,
    *,
    passphrase: str = "",  # nosec B107 — BIP39 passphrase, not a hardcoded password
    coin_types: Sequence[int] = DEFAULT_COIN_TYPES,
    accounts: Sequence[int] = DEFAULT_ACCOUNTS,
) -> DiscoveryReport:
    """Scan ``coin_types x accounts`` for derived addresses with on-chain history.

    For each ``(coin_type, account)`` pair, builds the account wallet, runs the
    standard BIP44 gap-limit scan (gap 20, both chains) via
    :meth:`HdWallet.refresh`, and records every used address together with its
    confirmed/unconfirmed balance and full derivation path.

    *mnemonic* is used only to derive keys locally; it is never sent to the
    server. Only derived addresses (as scripthashes) reach the network.

    Raises whatever :meth:`HdWallet.refresh` / :meth:`ElectrumXClient.get_balance`
    raise on network failure — a partial scan is **not** silently reported as
    empty. The caller decides how to surface an aborted scan.

    Returns a :class:`DiscoveryReport`; ``report.found`` is ``False`` when no
    scanned path had any history (the caller should then suggest widening the
    ranges or supplying the funded address directly).
    """
    hits: list[DiscoveryHit] = []
    scanned: list[tuple[int, int]] = []
    total_confirmed = 0
    total_unconfirmed = 0

    for coin_type in coin_types:
        for account in accounts:
            wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase, account=account, coin_type=coin_type)
            await wallet.refresh(client)
            scanned.append((coin_type, account))

            for record in wallet.known_addresses():
                if not record.used:
                    continue
                raw_confirmed, raw_unconfirmed = await client.get_balance(script_hash_for_address(record.address))
                confirmed, unconfirmed = int(raw_confirmed), int(raw_unconfirmed)
                hits.append(
                    DiscoveryHit(
                        coin_type=coin_type,
                        account=account,
                        change=record.change,
                        index=record.index,
                        address=record.address,
                        confirmed=confirmed,
                        unconfirmed=unconfirmed,
                    )
                )
                total_confirmed += confirmed
                total_unconfirmed += unconfirmed

    # Surface the largest balances first; a used-but-empty address (history but
    # zero balance — funds already spent) still reveals the active path, so it
    # is retained but sorts last.
    hits.sort(key=lambda h: h.total, reverse=True)

    return DiscoveryReport(
        hits=hits,
        scanned=scanned,
        total_confirmed=total_confirmed,
        total_unconfirmed=total_unconfirmed,
    )
