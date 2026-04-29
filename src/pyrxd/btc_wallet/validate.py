"""Input validation helpers for Bitcoin wallet operations.

Ports the address/value guards from btc_wallet.js::getUtxos (post-audit hardening).
Rejects path traversal characters, query injection, and non-Bitcoin address shapes.

No assert in src/ — all invariants use explicit raises.
"""

from __future__ import annotations

import re

from pyrxd.security.errors import ValidationError

__all__ = ["validate_btc_address", "validate_satoshis"]

# Bitcoin address validation regexes (from btc_wallet.js)
# Base58Check: P2PKH (1...) or P2SH (3...) — charset excludes 0/O/I/l
_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{20,34}$")
# bech32/bech32m: bc1 prefix, lowercase, no 1/b/i/o
_BECH32_RE = re.compile(r"^bc1[02-9ac-hj-np-z]{20,87}$")


def validate_btc_address(address: str) -> None:
    """Validate a mainnet Bitcoin address.

    Rejects path traversal, query injection, and anything outside the two
    recognized mainnet address shapes (Base58Check P2PKH/P2SH and bech32/bech32m).

    Raises:
        ValidationError: if the address is not a recognized mainnet format.
    """
    if not isinstance(address, str):
        raise ValidationError("address must be a string")
    if not (_BASE58_RE.match(address) or _BECH32_RE.match(address)):
        raise ValidationError("address is not a recognized mainnet Bitcoin format")


def validate_satoshis(value: int, name: str = "value") -> None:
    """Validate a satoshi amount.

    Rules:
      - Must be a plain int (not bool, not float).
      - Must be > 0.
      - Must not exceed max BTC supply (21M BTC = 2.1e15 sats).

    Raises:
        ValidationError: on any violation.
    """
    if isinstance(value, bool):
        raise ValidationError(f"{name} must not be bool")
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if value <= 0:
        raise ValidationError(f"{name} must be > 0")
    if value > 2_100_000_000_000_000:
        raise ValidationError(f"{name} exceeds max BTC supply")
