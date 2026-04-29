---
title: "feat: GlyphScanner — Network-to-Inventory Pipeline"
type: feat
date: 2026-04-24
---

# feat: GlyphScanner — Network-to-Inventory Pipeline

## Overview

Wire together the existing `GlyphInspector` (pure tx parser), `ElectrumXClient` (network), and the `GlyphNft`/`GlyphFt` types (defined but never constructed) into a single `GlyphScanner` class that resolves a Radiant address to its full Glyph inventory, including metadata from reveal transactions.

This is the highest-priority enhancement because it is **pure wiring** — all the pieces exist, nothing new needs to be designed. The gap today: `GlyphInspector.find_glyphs()` returns `GlyphOutput` objects with `metadata=None`, and `GlyphNft`/`GlyphFt` are defined in `types.py:421-438` but never constructed anywhere in the SDK.

## Problem Statement

A downstream consumer (e.g., a wallet UI) needs to answer: *"What Glyphs does address X own?"* Today that requires:

1. Compute `script_hash_for_address(addr)` ✅ (exists at `electrumx.py:84`)
2. Call `get_utxos(script_hash)` ✅ (exists, returns `List[UtxoRecord]`)
3. Fetch each UTXO's raw transaction bytes ✗ (no `get_raw_tx` in ElectrumXClient)
4. Parse scripts to identify Glyph outputs ✅ (`GlyphInspector.find_glyphs()`)
5. Fetch origin transaction to extract metadata from reveal scriptSig ✗ (no helper)
6. Extract `owner_pkh` from the locking script ✗ (`extract_owner_pkh_from_nft_script` exists in `script.py` but not wired up in inspector)
7. Construct `GlyphNft` / `GlyphFt` ✗ (never called)

## Proposed Solution

Add a `GlyphScanner` class in a new file `src/pyrxd/glyph/scanner.py` that:

1. Accepts an `ElectrumXClient` (injected, not instantiated — testable)
2. Exposes `async def scan_address(address: str) -> List[GlyphNft | GlyphFt]`
3. Exposes `async def scan_script_hash(script_hash: Hex32) -> List[GlyphNft | GlyphFt]`
4. Internally fetches UTXOs → raw txs → parses scripts → fetches reveal txs for metadata → constructs typed objects

Also add `get_raw_tx(txid: str) -> bytes` and `get_history(script_hash: Hex32) -> List[dict]` to `ElectrumXClient` to support the scanner and HD gap scanning.

## Technical Approach

### Architecture

```
GlyphScanner
  ├── electrumx: ElectrumXClient   (injected)
  └── inspector: GlyphInspector    (instantiated internally, stateless)

scan_address(addr)
  → script_hash_for_address(addr)
  → get_utxos(script_hash)              # existing
  → [for each utxo] get_raw_tx(txid)   # new ElectrumX method
  → Transaction.from_hex(raw_hex)       # existing SDK tx parser
  → inspector.find_glyphs(outputs)      # existing
  → [for each GlyphOutput] get_raw_tx(ref.txid)  # origin tx for metadata
  → inspector.extract_reveal_metadata(origin_tx.inputs[0].script_sig)
  → extract_owner_pkh_from_nft/ft_script(output.script)
  → GlyphNft(ref, owner_pkh, metadata) or GlyphFt(ref, owner_pkh, amount, metadata)
```

### New ElectrumXClient methods

```python
# electrumx.py
async def get_raw_tx(self, txid: str) -> bytes:
    """Fetch raw transaction bytes by txid."""
    result = await self._call("blockchain.transaction.get", [txid, False])
    return bytes.fromhex(result)

async def get_history(self, script_hash: "Hex32 | bytes | str") -> List[dict]:
    """Return tx history for script_hash [{tx_hash, height}, ...]."""
    script_hash = _coerce_hex32(script_hash)
    return await self._call("blockchain.scripthash.get_history", [script_hash.hex()])
```

### GlyphScanner implementation sketch

```python
# src/pyrxd/glyph/scanner.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Union

from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.script import (
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
)
from pyrxd.glyph.types import GlyphFt, GlyphNft
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address
from pyrxd.transaction.transaction import Transaction

GlyphItem = Union[GlyphNft, GlyphFt]


class GlyphScanner:
    def __init__(self, client: ElectrumXClient) -> None:
        self._client = client
        self._inspector = GlyphInspector()

    async def scan_address(self, address: str) -> List[GlyphItem]:
        sh = script_hash_for_address(address)
        return await self.scan_script_hash(sh)

    async def scan_script_hash(self, script_hash) -> List[GlyphItem]:
        utxos = await self._client.get_utxos(script_hash)
        results: List[GlyphItem] = []
        for utxo in utxos:
            raw = await self._client.get_raw_tx(utxo.txid)
            tx = Transaction.from_hex(raw.hex())
            outputs = [(out.satoshis, bytes.fromhex(out.locking_script)) for out in tx.outputs]
            glyphs = self._inspector.find_glyphs(outputs)
            for g in glyphs:
                if g.vout != utxo.vout:
                    continue  # this UTXO doesn't match this glyph output
                metadata = None
                try:
                    origin_raw = await self._client.get_raw_tx(g.ref.txid)
                    origin_tx = Transaction.from_hex(origin_raw.hex())
                    scriptsig = bytes.fromhex(origin_tx.inputs[0].unlocking_script or "")
                    metadata = self._inspector.extract_reveal_metadata(scriptsig)
                except Exception:
                    pass
                script = g.script
                if g.glyph_type == "nft":
                    pkh = extract_owner_pkh_from_nft_script(script)
                    if pkh:
                        results.append(GlyphNft(ref=g.ref, owner_pkh=pkh, metadata=metadata))
                elif g.glyph_type == "ft":
                    pkh = extract_owner_pkh_from_ft_script(script)
                    if pkh:
                        results.append(GlyphFt(ref=g.ref, owner_pkh=pkh, amount=utxo.value, metadata=metadata))
        return results
```

### Public API export

Add to `src/pyrxd/__init__.py`:

```python
from pyrxd.glyph.scanner import GlyphScanner, GlyphItem
```

### Implementation Phases

#### Phase 1: ElectrumX method additions

- Add `get_raw_tx()` to `ElectrumXClient` (`network/electrumx.py`)
- Add `get_history()` to `ElectrumXClient` (`network/electrumx.py`)
- Add both to `BtcDataSource` ABC if appropriate
- Export from `__init__.py`

#### Phase 2: GlyphScanner core

- Create `src/pyrxd/glyph/scanner.py`
- Implement `GlyphScanner.scan_address()` and `scan_script_hash()`
- Verify `extract_owner_pkh_from_nft_script` / `extract_owner_pkh_from_ft_script` in `script.py` return `Hex20` or `None`
- Handle `metadata=None` gracefully (transfer, not reveal)
- Export from `src/pyrxd/glyph/__init__.py` and top-level `__init__.py`

#### Phase 3: Tests

- `tests/test_glyph_scanner.py` — fully mocked `ElectrumXClient`
- Cover: NFT scan, FT scan, mixed outputs, missing reveal tx (metadata=None), vout mismatch filtering, empty wallet, network error propagation
- Cover `get_raw_tx` and `get_history` unit tests in existing electrumx test file

## Alternative Approaches Considered

**Alternative: Return `GlyphOutput` list (current state)**
Rejected — caller still has to fetch reveal txs and construct types. The whole point is to remove that burden.

**Alternative: Batch-fetch all raw txs concurrently**
Desirable optimization but deferred — `asyncio.gather()` for all UTXO tx fetches can be added in a follow-up without API changes.

**Alternative: Add `get_history()` and scan by tx history instead of UTXOs**
More complete (catches spent NFTs) but adds complexity. UTxO-based scan is correct for "current inventory" queries. `get_history()` is still added as a lower-level primitive for HD gap scanning.

## Acceptance Criteria

### Functional

- [ ] `GlyphScanner.scan_address(addr)` returns `List[GlyphNft | GlyphFt]` for all Glyphs owned at that address
- [ ] Glyphs without a reveal scriptSig (transfers) return `metadata=None` without error
- [ ] `GlyphNft` and `GlyphFt` are correctly constructed with `ref`, `owner_pkh`, `amount` (FT only), and `metadata`
- [ ] `ElectrumXClient.get_raw_tx(txid)` returns `bytes`
- [ ] `ElectrumXClient.get_history(script_hash)` returns `List[dict]` with `tx_hash` and `height` keys
- [ ] `GlyphScanner` is exported from top-level `pyrxd.__init__`

### Non-Functional

- [ ] No network calls in unit tests (mock `ElectrumXClient`)
- [ ] Scanner does not instantiate or own an `ElectrumXClient` (injected dependency)
- [ ] All new code passes `mypy --strict`

### Quality Gates

- [ ] `pytest --cov-fail-under=85` still passes
- [ ] New test file covers all scanner branches
- [ ] No `_int_` substring in any test method/class names (conftest integration filter)

## Dependencies & Prerequisites

- `GlyphInspector.find_glyphs()` — exists at `inspector.py:37` ✅
- `GlyphInspector.extract_reveal_metadata()` — exists at `inspector.py:57` ✅
- `extract_owner_pkh_from_nft_script` / `_from_ft_script` — exists in `script.py` (verify return type is `Hex20 | None`)
- `GlyphNft`, `GlyphFt` — defined in `types.py:421-438` ✅
- `script_hash_for_address()` — exists at `electrumx.py:84` ✅
- `get_utxos()` — exists, returns `List[UtxoRecord]` ✅
- `Transaction.from_hex()` — verify it exists in transaction module

## Risk Analysis

**Risk: `Transaction.from_hex()` may not expose `inputs[0].unlocking_script` as hex str**
Mitigation: Read `transaction/transaction.py` before implementing; adjust attribute name if needed.

**Risk: `extract_owner_pkh_from_nft_script` may return raw bytes instead of `Hex20`**
Mitigation: Check return type; wrap with `.hex()` if needed.

**Risk: vout filtering logic** — a single tx may have multiple Glyph outputs; the scanner must match the UTXO's `vout` to the `GlyphOutput.vout`.
Mitigation: Already handled in implementation sketch above with `if g.vout != utxo.vout: continue`.

## References

### Internal

- `src/pyrxd/glyph/inspector.py:37` — `GlyphInspector.find_glyphs()`
- `src/pyrxd/glyph/inspector.py:57` — `GlyphInspector.extract_reveal_metadata()`
- `src/pyrxd/glyph/types.py:421-438` — `GlyphNft`, `GlyphFt` (defined, never constructed)
- `src/pyrxd/glyph/script.py` — `extract_owner_pkh_from_nft_script`, `extract_owner_pkh_from_ft_script`
- `src/pyrxd/network/electrumx.py:84` — `script_hash_for_address()`
- `src/pyrxd/network/electrumx.py:275` — `get_utxos()` returning `List[UtxoRecord]`

### External

- ElectrumX protocol: `blockchain.transaction.get` — returns raw hex, second param `verbose=False`
- ElectrumX protocol: `blockchain.scripthash.get_history` — returns `[{tx_hash, height}]`
