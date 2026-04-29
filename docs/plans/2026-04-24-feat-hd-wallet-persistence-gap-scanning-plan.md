---
title: "feat: Persistent HD Wallet with BIP44 Gap Scanning"
type: feat
date: 2026-04-24
---

# feat: Persistent HD Wallet with BIP44 Gap Scanning

## Overview

Upgrade the SDK's HD wallet from a stateless derivation library into a persistent wallet with:

1. **Correct BIP44 coin type 236** for Radiant (currently defaults to 0/Bitcoin via `BIP44_DERIVATION_PATH = "m/44'/0'/0'"`)
2. **Gap-limit scanning** (BIP44 standard: 20 consecutive unused addresses → stop) using the now-available `get_history()` ElectrumX method
3. **Encrypted local persistence** — save/load derived addresses and UTXO cache to disk using the SDK's existing `AesCbc` or BIE1 ECIES encryption

This enables an offline-capable wallet that does not re-derive and re-scan from scratch on every startup.

## Problem Statement

The current HD wallet code:

- Derives keys correctly once you supply the right path — but `BIP44_DERIVATION_PATH = "m/44'/0'/0'"` hardwires coin type 0 (Bitcoin), not 236 (Radiant)
- Has no gap-limit scanning: no way to discover which derived addresses have been used on-chain
- Has no persistence: every session must re-derive all keys from the mnemonic
- `get_history()` does not exist in `ElectrumXClient` (needed for gap scanning and is being added in the GlyphScanner plan)

The result: a downstream app (any wallet UI, dApp) must either scan every address ever (slow) or trust the user to track their address index (error-prone).

## Proposed Solution

Add a `HdWallet` class in `src/pyrxd/hd/wallet.py` that:

1. Derives keys using the corrected BIP44 path `m/44'/236'/account'/change/index`
2. Runs gap-limit discovery against ElectrumX on first use (or explicit `refresh()` call)
3. Persists discovered address→index mappings and UTXO cache to an encrypted JSON file
4. On subsequent loads, restores state from disk and only scans new addresses beyond the known tip

Also fix `BIP44_DERIVATION_PATH` constant in `bip44.py` from `"m/44'/0'/0'"` to `"m/44'/236'/0'"`.

## Technical Approach

### BIP44 path correction

```python
# src/pyrxd/hd/bip44.py
BIP44_DERIVATION_PATH = "m/44'/236'/0'"   # was: "m/44'/0'/0'"
```

This is a **breaking change** for anyone using the old path. Flag in changelog.

### Gap-limit scan algorithm

```
For change=0 (external chain) and change=1 (internal/change chain):
  gap = 0
  index = 0
  while gap < GAP_LIMIT (20):
    path = f"m/44'/236'/{account}'/{change}/{index}"
    address = derive_address(xprv, path)
    history = await electrumx.get_history(script_hash_for_address(address))
    if history:
      gap = 0
      record address as used at index
    else:
      gap += 1
    index += 1
  # addresses up to (index - GAP_LIMIT) are the active set
```

### Encrypted persistence format

```json
{
  "version": 1,
  "account": 0,
  "coin_type": 236,
  "external_tip": 42,
  "internal_tip": 7,
  "addresses": {
    "0/0": {"address": "1...", "used": true},
    "0/1": {"address": "1...", "used": false}
  },
  "utxo_cache": {
    "1abc...": [{"txid": "...", "vout": 0, "value": 546, "height": 12345}]
  }
}
```

Encrypted with AES-CBC using a key derived from the mnemonic's seed (so the file is useless without the mnemonic). Alternatively, use a user-supplied passphrase.

```python
# Key derivation for file encryption
from pyrxd.hash import hash256
from pyrxd.aes_cbc import AesCbc

encryption_key = hash256(seed_bytes)[:32]  # 256-bit key from BIP39 seed
aes = AesCbc(encryption_key)
ciphertext = aes.encrypt(json_bytes)
```

### `HdWallet` API sketch

```python
# src/pyrxd/hd/wallet.py
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

GAP_LIMIT = 20

@dataclass
class AddressRecord:
    address: str
    path: str       # e.g. "m/44'/236'/0'/0/5"
    used: bool

@dataclass
class HdWallet:
    """Persistent BIP44 HD wallet with gap-limit scanning for Radiant (coin type 236)."""

    _xprv: object           # Xprv root key (not serialized)
    _seed: bytes            # for deriving encryption key
    account: int = 0
    external_tip: int = 0   # highest known external index
    internal_tip: int = 0
    addresses: dict[str, AddressRecord] = field(default_factory=dict)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> HdWallet: ...

    @classmethod
    def load(cls, path: Path, mnemonic: str, passphrase: str = "") -> HdWallet: ...

    def save(self, path: Path) -> None: ...

    async def refresh(self, client: ElectrumXClient) -> int:
        """Run gap-limit scan. Returns count of newly discovered used addresses."""
        ...

    def next_receive_address(self) -> str:
        """Return the next unused external address."""
        ...

    async def get_balance(self, client: ElectrumXClient) -> int:
        """Return total confirmed satoshis across all known addresses."""
        ...

    async def get_utxos(self, client: ElectrumXClient) -> List[UtxoRecord]:
        """Return all UTXOs across known addresses."""
        ...
```

### ElectrumX `get_history` (prerequisite)

This method is also needed by `GlyphScanner` and is planned there (Phase 1). Coordinate so it is added once and shared.

```python
# src/pyrxd/network/electrumx.py (already planned)
async def get_history(self, script_hash: "Hex32 | bytes | str") -> List[dict]:
    script_hash = _coerce_hex32(script_hash)
    return await self._call("blockchain.scripthash.get_history", [script_hash.hex()])
```

### Implementation Phases

#### Phase 1: BIP44 constant fix + `get_history` (week 1)

- Fix `BIP44_DERIVATION_PATH` in `bip44.py` to `"m/44'/236'/0'"`
- Confirm `get_history` is added (coordinate with GlyphScanner plan — both need it)
- Add tests verifying coin type 236 derivation produces correct addresses

#### Phase 2: Gap-limit scanner (week 1)

- Implement `HdWallet.refresh()` with gap-limit algorithm
- Test with mocked ElectrumX: empty wallet (stops at GAP_LIMIT), wallet with 5 used addresses, wallet with addresses used at index > GAP_LIMIT (extended scan)
- Test both external (change=0) and internal (change=1) chains

#### Phase 3: Encrypted persistence (week 2)

- Implement `HdWallet.save()` and `HdWallet.load()`
- Derive encryption key from BIP39 seed (deterministic, no stored passphrase)
- Test: round-trip save/load, tampered ciphertext raises `ValidationError`, wrong mnemonic produces garbage (decrypt fails gracefully)
- Test: `load()` on nonexistent path creates fresh wallet

#### Phase 4: Balance and UTXO aggregation (week 2)

- Implement `HdWallet.get_balance()` and `HdWallet.get_utxos()`
- These call `ElectrumXClient.get_utxos()` for each known address
- UTXO cache updated on refresh (not auto-refreshed on every call — caller must `refresh()` first)
- Test: summing across multiple addresses, empty wallet returns 0

## Alternative Approaches Considered

**Alternative: Store xpub only (no mnemonic required for load)**
Desirable for watch-only wallet. Deferred — full key wallet is the foundation; watch-only can be added as `HdWallet.from_xpub()` later without changing the persistence format.

**Alternative: SQLite instead of encrypted JSON**
More scalable for large address sets, but adds a dependency. JSON is sufficient for BIP44 gap-limit (max ~200 addresses per account under normal usage). Revisit if account counts grow.

**Alternative: Argon2 KDF for file encryption key**
More secure than `hash256(seed)` against offline attacks, but requires a new dependency. The BIP39 seed already has 128-256 bits of entropy; `hash256(seed)` is sufficient. Add note in docs that mnemonic security = file security.

**Alternative: Store encrypted mnemonic in file**
Rejected — the mnemonic should never be written to disk by the SDK. The caller holds it; the SDK derives the encryption key from the seed at load time.

## Acceptance Criteria

### Functional

- [ ] `HdWallet.from_mnemonic("word1 ... word12")` derives addresses on the `m/44'/236'/0'/0/n` path
- [ ] `refresh()` stops after 20 consecutive addresses with no history (GAP_LIMIT)
- [ ] `refresh()` extends scan correctly when a used address is found beyond the previous tip
- [ ] `save()` produces an encrypted file; `load()` restores exact same state
- [ ] `next_receive_address()` returns the first external address with `used=False`
- [ ] `get_balance()` sums UTxO values across all known used addresses
- [ ] Existing code using `bip44_derive_xprv_from_mnemonic()` still works (path change is additive, not breaking the function signature)

### Non-Functional

- [ ] No plaintext mnemonic or private key bytes written to disk
- [ ] `mypy --strict` passes on new module
- [ ] `pytest --cov-fail-under=85` still passes

### Quality Gates

- [ ] 40+ new tests in `tests/test_hd_wallet.py`
- [ ] Hypothesis property test: any 12-24 word mnemonic → stable address derivation (same mnemonic always yields same addresses)
- [ ] Document the breaking change to `BIP44_DERIVATION_PATH` in `CHANGELOG.md`

## Dependencies & Prerequisites

- `get_history()` in `ElectrumXClient` — add in GlyphScanner Phase 1 (or this phase if scanner is not started yet)
- `bip32_derive_xkeys_from_xkey` / `_derive_xkeys_from_xkey` at `bip44.py:42` ✅
- `bip44_derive_xprv_from_mnemonic()` — verify exists and returns `Xprv`
- `script_hash_for_address()` at `electrumx.py:84` ✅
- `AesCbc` at `aes_cbc.py` ✅
- `hash256` from `pyrxd.hash` ✅
- `UtxoRecord` dataclass in `electrumx.py` ✅

## Risk Analysis

**Risk: BIP44 path constant change is breaking**
Any downstream code that hardcodes the old path or calls `bip44_derive_xprv_from_mnemonic()` and expects Bitcoin-path addresses will silently derive different addresses.
Mitigation: Version bump, CHANGELOG entry, and keep the old function accepting an explicit `coin_type: int = 236` override param.

**Risk: Gap-limit scan is slow for large wallets**
20 addresses × 2 chains × ElectrumX round-trip latency = up to 40 sequential network calls.
Mitigation: Batch with `asyncio.gather()` — scan up to GAP_LIMIT addresses concurrently per chain. If found, extend and batch again.

**Risk: `AesCbc` encrypt/decrypt API**
The existing `AesCbc` class may use a different interface than expected (e.g., requires IV separately, or returns a different format).
Mitigation: Read `aes_cbc.py` before implementing; test encrypt/decrypt round-trip in isolation.

**Risk: Internal chain (change=1) addresses not scanned**
Many wallets ignore the internal chain for display but must scan it for balance.
Mitigation: `refresh()` scans both chains explicitly; tests cover both.

## Future Considerations

- **Watch-only wallet**: `HdWallet.from_xpub(xpub, ...)` — scan-only, no signing
- **Multi-account**: `HdWallet.account` is already a parameter; UI for switching accounts
- **Hardware wallet**: Replace `Xprv` key derivation with a `SignerProtocol` interface for Ledger/Trezor support
- **Glyph inventory integration**: After `GlyphScanner` exists, add `HdWallet.get_glyphs(client)` that calls `GlyphScanner.scan_address()` for each known address

## References

### Internal

- `src/pyrxd/hd/bip44.py` — `BIP44_DERIVATION_PATH`, `_derive_xkeys_from_xkey` at line 42
- `src/pyrxd/hd/bip44.py` — `bip44_derive_xprv_from_mnemonic()`
- `src/pyrxd/network/electrumx.py:84` — `script_hash_for_address()`
- `src/pyrxd/network/electrumx.py:275` — `get_utxos()` returning `List[UtxoRecord]`
- `src/pyrxd/aes_cbc.py` — AES-CBC encryption
- `src/pyrxd/wallet.py` — existing `Wallet` class (contrast: HdWallet is higher-level)
- `tests/test_property_based.py` — Hypothesis patterns for key derivation tests

### External

- BIP44 spec: coin type 236 for Radiant — https://github.com/satoshilabs/slips/blob/master/slip-0044.md
- BIP44 gap limit: 20 consecutive unused addresses = stop scanning
- ElectrumX: `blockchain.scripthash.get_history` returns `[{tx_hash: str, height: int}]`; unconfirmed txs have `height: 0` or negative
