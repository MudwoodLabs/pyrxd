---
title: "feat: MUT / CONTAINER / WAVE Glyph builders"
type: feat
date: 2026-04-24
---

# feat: MUT / CONTAINER / WAVE Glyph builders

## Overview

Add `GlyphBuilder` methods for three Glyph protocol variants that are defined in the spec but not yet buildable by the SDK:

- **MUT (protocol 5)**: Mutable NFT — two-output reveal pattern; state prefix stores `payload_hash + OP_STATESEPARATOR` before the 102-byte covenant body
- **CONTAINER (protocol 7)**: Collection — NFT + child-linking via `OP_PUSHINPUTREF`
- **WAVE (protocol 11)**: On-chain naming — MUT + name semantics; protocol field is `[NFT(2), MUT(5), WAVE(11)]`

**Dependency order**: CONTAINER extends NFT (independent of MUT). MUT must exist before WAVE. Suggested implementation order: MUT → CONTAINER → WAVE.

## Problem Statement

`GlyphBuilder` (in `builder.py`) currently supports NFT commit/reveal and FT commit/reveal. The three new variants require:

- **MUT**: A reveal tx that produces TWO outputs — a 63-byte NFT singleton token + a 174-byte mutable contract UTXO. The mutable contract script is already buildable (`build_mutable_nft_script()` at `script.py:179`) but the two-output reveal transaction is not wired up. The reveal scriptSig (`build_mutable_scriptsig()`) is at `payload.py:227-282`.
- **CONTAINER**: An NFT reveal that adds a `OP_PUSHINPUTREF <child_ref>` prefix to the locking script, linking the container to its children.
- **WAVE**: Like MUT reveal but with `protocol=[2, 5, 11]` in the CBOR metadata and a `name` field.

The `MUTABLE_NFT_SCRIPT_RE` regex at `script.py:172-176` exists but is **not used** by `GlyphInspector` — detection of mutable Glyph transfers is also missing (tracked separately in the scanner plan, but the regex being unused is a signal that MUT was planned but not completed).

## Proposed Solution

### Phase 1: MUT Builder

Add `GlyphBuilder.prepare_mutable_reveal()` that returns a `MutableRevealResult` with two outputs (NFT token + mutable contract). The caller appends these to a funding transaction.

```python
# src/pyrxd/glyph/builder.py additions

@dataclass(frozen=True)
class MutableRevealParams:
    commit_txid: str        # txid of the commit tx
    commit_vout: int        # vout of the commit output
    commit_satoshis: int    # satoshis at commit output
    metadata: GlyphMetadata
    owner_address: str      # P2PKH address for NFT token output
    funding_utxos: list     # UTXOs to pay fees

@dataclass
class MutableRevealResult:
    tx_hex: str             # signed reveal tx hex
    ref: GlyphRef           # the Glyph reference (commit_txid:commit_vout)
    nft_output_index: int   # vout of the 63-byte NFT singleton (usually 0)
    contract_output_index: int  # vout of the 174-byte mutable contract (usually 1)
    payload_hash: bytes     # sha256d of CBOR payload (stored in contract state prefix)
```

Internally:
1. Build CBOR payload with `protocol=[2, 5]` (NFT + MUT)
2. Hash payload: `payload_hash = hash256(cbor_bytes)`
3. Build NFT locking script: `build_nft_script(ref, owner_pkh)`
4. Build mutable contract script: `build_mutable_nft_script(ref, payload_hash)` — 174 bytes
5. Build reveal scriptSig: `build_mutable_scriptsig(privkey, pubkey, cbor_bytes)` from `payload.py:227`
6. Assemble tx: 1 input (commit UTXO) + funding inputs + 2 outputs (NFT + contract)
7. Sign funding inputs with standard P2PKH sigs

### Phase 2: CONTAINER Builder

Add `GlyphBuilder.prepare_container_reveal()`:

- Like NFT reveal but locking script is `OP_PUSHINPUTREF <child_ref> <NFT_script_body>`
- `child_ref` can be `None` for an empty container (children linked later via mutation)
- Protocol field: `[2, 7]` (NFT + CONTAINER)

### Phase 3: WAVE Builder

Add `GlyphBuilder.prepare_wave_reveal()`:

- Like MUT reveal but protocol field is `[2, 5, 11]` (NFT + MUT + WAVE)
- Requires a `name: str` field in metadata (validated: printable ASCII, ≤ 255 chars)
- `name` stored in CBOR payload under key `"name"`

### MUT Inspector Update

Update `GlyphInspector.find_glyphs()` to detect mutable contract scripts using `MUTABLE_NFT_SCRIPT_RE`, and set `glyph_type="mut"` in the returned `GlyphOutput`. Also update `GlyphScanner` (once built) to handle the `"mut"` type.

## Technical Approach

### MUT script structure (from `script.py`)

```
174-byte mutable contract:
  [20 bytes: payload_hash[:20]]   ← state prefix
  [OP_STATESEPARATOR = 0xbe]      ← 1 byte
  [OP_PUSHINPUTREFSINGLETON]      ← 1 byte
  [36 bytes: ref.to_bytes()]      ← glyph ref
  [102 bytes: _MUTABLE_NFT_BODY]  ← covenant body
```

The `build_mutable_nft_script(mutable_ref, payload_hash)` function at `script.py:179` already handles this. The payload_hash passed in must be the hash256 of the CBOR payload.

### Reveal scriptSig (from `payload.py:227-282`)

`build_mutable_scriptsig(privkey, pubkey, cbor_payload)` already builds the full scriptSig including the `gly` marker. This is the existing function that just needs to be called by the builder.

### Two-output reveal tx assembly

```python
# Pseudo-structure of MUT reveal tx
inputs:
  [0]: commit UTXO (scriptSig = build_mutable_scriptsig(...))
  [1..n]: funding UTXOs (standard P2PKH sigs)
outputs:
  [0]: 546 sat  — NFT token: build_nft_script(ref, owner_pkh)      # 63 bytes
  [1]: 546 sat  — Mutable contract: build_mutable_nft_script(ref, payload_hash)  # 174 bytes
  [2]: change (optional)
```

### Implementation files

| File | Change |
|------|--------|
| `src/pyrxd/glyph/builder.py` | Add `prepare_mutable_reveal()`, `prepare_container_reveal()`, `prepare_wave_reveal()` and their param/result dataclasses |
| `src/pyrxd/glyph/inspector.py` | Add MUT detection in `find_glyphs()` using `MUTABLE_NFT_SCRIPT_RE` |
| `src/pyrxd/glyph/types.py` | Add `GlyphMut` dataclass (parallel to `GlyphNft`/`GlyphFt`) |
| `src/pyrxd/__init__.py` | Export new builder params, result types, `GlyphMut` |

### Implementation Phases

#### Phase 1: MUT Builder (week 1)

1. Add `MutableRevealParams`, `MutableRevealResult` dataclasses to `builder.py`
2. Implement `GlyphBuilder.prepare_mutable_reveal()`
3. Add `GlyphMut` to `types.py` (parallel to `GlyphNft`)
4. Update `GlyphInspector.find_glyphs()` to detect mutable scripts
5. Write `tests/test_mut_builder.py` — 20+ tests

#### Phase 2: CONTAINER Builder (week 1, can overlap with MUT)

1. Add `ContainerRevealParams`, `ContainerRevealResult` to `builder.py`
2. Implement `GlyphBuilder.prepare_container_reveal()`
3. Write `tests/test_container_builder.py` — 15+ tests

#### Phase 3: WAVE Builder (week 2, after MUT)

1. Add `WaveRevealParams`, `WaveRevealResult` to `builder.py`
2. Implement `GlyphBuilder.prepare_wave_reveal()` (delegates to MUT logic, adds name field)
3. Add name validation: printable ASCII, ≤ 255 chars
4. Write `tests/test_wave_builder.py` — 15+ tests

## Alternative Approaches Considered

**Alternative: Single `prepare_reveal(protocol: list[GlyphProtocol], ...)` method**
Rejected — different protocols have different required fields (MUT needs `payload_hash`, CONTAINER needs `child_ref`, WAVE needs `name`). Typed params per variant are safer and more discoverable.

**Alternative: Add WAVE before MUT**
Rejected — WAVE is a superset of MUT. Implementing MUT first means WAVE delegates to proven code.

**Alternative: Update `GlyphOutput.glyph_type` to use `GlyphProtocol` enum**
Desirable but breaking change — deferred. Current `glyph_type: str` is `"nft"` or `"ft"`; extending with `"mut"` as string is backward-compatible.

## Acceptance Criteria

### Functional — MUT

- [ ] `prepare_mutable_reveal()` returns a tx hex with exactly 2 Glyph outputs: 63-byte NFT + 174-byte mutable contract
- [ ] Mutable contract locking script matches `MUTABLE_NFT_SCRIPT_RE`
- [ ] `payload_hash` in the contract state prefix is `hash256(cbor_payload)`
- [ ] `GlyphInspector.find_glyphs()` detects mutable scripts and returns `glyph_type="mut"`

### Functional — CONTAINER

- [ ] `prepare_container_reveal()` produces a locking script with `OP_PUSHINPUTREF <child_ref>` prefix when `child_ref` is provided
- [ ] Works with `child_ref=None` for an empty container
- [ ] CBOR payload has `protocol=[2, 7]`

### Functional — WAVE

- [ ] `prepare_wave_reveal()` produces a mutable NFT with `protocol=[2, 5, 11]` in CBOR
- [ ] `name` field present in CBOR payload
- [ ] `ValidationError` raised for non-printable or >255-char names
- [ ] Reuses MUT two-output reveal structure

### Non-Functional

- [ ] All new code passes `mypy --strict`
- [ ] No network calls in tests
- [ ] `pytest --cov-fail-under=85` still passes

### Quality Gates

- [ ] 50+ new tests across the three builders
- [ ] Property-based test (Hypothesis) for name validation edge cases

## Dependencies & Prerequisites

- `build_mutable_nft_script()` at `script.py:179` ✅
- `build_mutable_scriptsig()` at `payload.py:227` ✅
- `MUTABLE_NFT_SCRIPT_RE` at `script.py:172` ✅
- `build_nft_script()` — verify exists in `script.py`
- `GlyphBuilder` base class in `builder.py` ✅
- `hash256` from `pyrxd.hash` ✅

## Risk Analysis

**Risk: Two-output tx fee calculation**
The mutable contract output is 174 bytes vs a typical 34-byte P2PKH output — fee models need updating to account for larger output scripts.
Mitigation: Use `len(locking_script)` in fee calculation rather than assuming fixed output sizes.

**Risk: `build_mutable_scriptsig` signature**
If it expects a `PrivateKey` object vs raw bytes, the builder interface must match.
Mitigation: Read `payload.py:227-282` before implementing.

**Risk: CONTAINER child-linking semantics**
The Glyph spec says children link to containers via `OP_PUSHINPUTREF`, but the exact position in the script needs verification against Photonic Wallet's output.
Mitigation: Cross-reference against existing `extract_ref_from_nft_script` to understand the expected structure.

## References

### Internal

- `src/pyrxd/glyph/script.py:141-165` — `_MUTABLE_NFT_BODY`
- `src/pyrxd/glyph/script.py:172-176` — `MUTABLE_NFT_SCRIPT_RE`
- `src/pyrxd/glyph/script.py:179-202` — `build_mutable_nft_script()`
- `src/pyrxd/glyph/payload.py:227-282` — `build_mutable_scriptsig()`
- `src/pyrxd/glyph/builder.py` — existing `GlyphBuilder` with NFT/FT support
- `src/pyrxd/glyph/types.py:421-438` — `GlyphNft`, `GlyphFt` (pattern for new `GlyphMut`)
- `tests/test_dmint_end_to_end.py` — pattern for builder test structure

### External

- Glyph protocol spec: protocol values 2=NFT, 4=DMINT, 5=MUT, 7=CONTAINER, 11=WAVE
- Photonic Wallet source: reference implementation for WAVE/CONTAINER script construction
