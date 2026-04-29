---
title: "GlyphScanner, MUT/CONTAINER/WAVE builders, and HdWallet implementation for rxd-python-sdk"
date: 2026-04-25
type: feature-implementation
component: rxd-python-sdk
tags: [glyph, scanner, hd-wallet, mut, container, wave, bip44, electrumx, bip39, aes-cbc, gap-limit]
symptoms:
  - no high-level API to scan an address or script hash and get typed GlyphNft/GlyphFt objects back
  - GlyphInspector and ElectrumXClient existed in isolation with no wiring between them
  - ElectrumXClient lacked get_history() needed for gap-limit scanning
  - GlyphBuilder had no methods for mutable, container, or WAVE glyph reveal transactions
  - GlyphInspector.find_glyphs() could not detect mutable scripts (MUTABLE_NFT_SCRIPT_RE defined but unwired)
  - no BIP44 HD wallet with correct Radiant coin type (236, not 0)
  - no encrypted wallet persistence across sessions
  - no aggregated get_balance() or get_utxos() across all derived addresses
  - BIP44_DERIVATION_PATH constant in constants.py used wrong coin type (0 = Bitcoin instead of 236 = Radiant)
status: solved
commit: 42af375
---

# GlyphScanner, MUT/CONTAINER/WAVE builders, and HdWallet SDK features

Three wiring features that connect independently correct SDK subsystems into coherent pipelines.
All verified: **1978 tests passing, 86.57% coverage** (threshold: 85%).

---

## Solution

### Feature 1 — GlyphScanner (address → Glyph inventory)

**File created:** `src/pyrxd/glyph/scanner.py`

A high-level async API that wires `GlyphInspector` (pure parser), `ElectrumXClient` (network), and
`GlyphNft`/`GlyphFt` typed result objects together. Callers pass an already-connected client; the
scanner does not own the connection lifecycle.

```python
async with ElectrumXClient(urls) as client:
    scanner = GlyphScanner(client)
    glyphs = await scanner.scan_address("1RadiantAddress...")   # List[GlyphNft | GlyphFt]
    # or by raw script hash:
    glyphs = await scanner.scan_script_hash(sh)
```

Internally `scan_script_hash`:
1. Fetches all UTXOs via `get_utxos()`
2. Fetches raw txs concurrently via `asyncio.gather` + `get_transaction()`
3. Runs `GlyphInspector.find_glyphs()` on each tx's outputs
4. Matches UTXO `tx_pos` to inspector result `vout`
5. Calls `_fetch_reveal_metadata(origin_txid)` to populate `metadata` (`None` for transfers)

Errors per-UTXO are caught and logged; partial results are returned rather than raising.

**Also added to `ElectrumXClient`** (`network/electrumx.py`):

```python
async def get_history(self, script_hash: "Hex32 | bytes | str") -> List[dict]:
    """Return [{"tx_hash": str, "height": int}, ...]; height 0/negative = unconfirmed."""
    script_hash = _coerce_hex32(script_hash)
    result = await self._call("blockchain.scripthash.get_history", [script_hash.hex()])
    ...
```

**21 new tests** in `tests/test_glyph_scanner.py`.

---

### Feature 2 — MUT / CONTAINER / WAVE Glyph builders

**File modified:** `src/pyrxd/glyph/builder.py` (new dataclasses + three new `GlyphBuilder` methods)

**`prepare_mutable_reveal()`** — MUT protocol (`GlyphProtocol.MUT = 5`).
Produces **two outputs**: 63-byte NFT singleton + 174-byte mutable contract UTXO.

```python
scripts = builder.prepare_mutable_reveal(commit_txid, commit_vout, cbor_bytes, owner_pkh)
# -> MutableRevealScripts(ref, nft_script, contract_script, scriptsig_suffix, payload_hash)
assert len(scripts.nft_script) == 63
assert len(scripts.contract_script) == 174
```

**`prepare_container_reveal()`** — CONTAINER protocol (`GlyphProtocol.CONTAINER = 7`).
NFT with optional `OP_PUSHINPUTREF <child_ref>` prefix (`0xd0`, not `0xd8`).

```python
scripts = builder.prepare_container_reveal(
    commit_txid, commit_vout, cbor_bytes, owner_pkh,
    child_ref=GlyphRef(txid=Txid("cc"*32), vout=1),   # optional
)
# -> ContainerRevealScripts(ref, locking_script, scriptsig_suffix, child_ref)
assert scripts.locking_script[0] == 0xD0   # OP_PUSHINPUTREF (non-singleton)
```

**`prepare_wave_reveal()`** — WAVE on-chain naming (`GlyphProtocol.WAVE = 11`).
Extends MUT; requires `name` to be non-empty printable ASCII ≤ 255 chars.

```python
scripts = builder.prepare_wave_reveal(
    commit_txid, commit_vout, cbor_bytes, owner_pkh, name="mytoken.rxd"
)
# -> MutableRevealScripts (same two-output shape as MUT)
```

**GlyphInspector** (`src/pyrxd/glyph/inspector.py`) updated to detect mutable scripts:

```python
elif MUTABLE_NFT_SCRIPT_RE.fullmatch(script_hex):
    parsed = parse_mutable_nft_script(script)
    if parsed is not None:
        ref, _ = parsed
        results.append(GlyphOutput(vout=vout, glyph_type="mut", ref=ref, ...))
```

**43 new tests** in `tests/test_mut_container_wave_builders.py`.

---

### Feature 3 — HdWallet (BIP44 gap scanning + encrypted persistence)

**File created:** `src/pyrxd/hd/wallet.py`
**File modified:** `src/pyrxd/constants.py` — BIP44 coin type fixed from 0 to 236.

```python
# Before (wrong):
BIP44_DERIVATION_PATH = "m/44'/0'/0'"    # Bitcoin coin type

# After (correct):
BIP44_DERIVATION_PATH = "m/44'/236'/0'"  # Radiant coin type (SLIP-0044)
```

Key API:

```python
# Create
wallet = HdWallet.from_mnemonic("word1 ... word12")

# Gap-limit scan (stops after 20 consecutive unused addresses per chain)
async with ElectrumXClient(urls) as client:
    new_count = await wallet.refresh(client)
    addr = wallet.next_receive_address()
    balance = await wallet.get_balance(client)     # sats across all used addresses
    utxos  = await wallet.get_utxos(client)        # UTxOs across all used addresses

# Encrypted persistence (AES-CBC; key = hash256(bip39_seed)[:32])
wallet.save(Path("wallet.dat"))
wallet = HdWallet.load(Path("wallet.dat"), mnemonic="word1 ... word12")
```

Gap scanning is done one address at a time (not batched) to maintain correct BIP44 gap-limit
semantics. Both the external chain (change=0) and internal chain (change=1) are scanned independently.

**37 new tests** in `tests/test_hd_wallet.py`.

---

## Common Pitfalls

### GlyphScanner

**Do not add a `get_raw_tx()` alias.** `get_transaction()` already returns `RawTx` (bytes).
Adding a parallel method creates two sources of truth.

**`script_hash_for_address` must be a module-level import, not a local import.**
If imported inside the function body, `unittest.mock.patch` cannot intercept it:

```python
# WRONG — patch won't work:
async def scan_address(self, address):
    from ..network.electrumx import script_hash_for_address   # local import
    sh = script_hash_for_address(address)

# CORRECT — patchable:
from ..network.electrumx import script_hash_for_address   # module level

async def scan_address(self, address):
    sh = script_hash_for_address(address)
```

Patch target: `pyrxd.glyph.scanner.script_hash_for_address` (where it's used, not where defined).

**Per-UTXO exception handling is required.** A bad UTXO should not crash the whole scan.

### MUT/CONTAINER/WAVE Builders

**MUT reveal is two outputs, not one.** The 174-byte mutable contract UTXO is separate from the 63-byte NFT token. Missing it silently loses state.

**CONTAINER uses `OP_PUSHINPUTREF (0xd0)`, not `OP_PUSHINPUTREFSINGLETON (0xd8)`.**
These opcodes differ by 8 and visually look identical. Wrong opcode = wrong singleton semantics.

**WAVE validation happens at `GlyphMetadata` construction, not at the builder.**
`GlyphMetadata.__post_init__` validates protocol combinations. `GlyphProtocol.WAVE` without
`GlyphProtocol.MUT` raises `ValidationError` during metadata construction — before any builder
call. Callers must be prepared for this.

**Never leave a detection primitive (regex, RE, pattern) unwired.** `MUTABLE_NFT_SCRIPT_RE` was
defined in `script.py` but never called. Dead detection code is a maintenance hazard; wire it
into the inspector/parser immediately or delete it.

### HdWallet

**BIP44 coin type for Radiant is 236, not 0.** Using `"m/44'/0'/0'"` silently produces a
completely different key tree from a different coin's address space. Verify against SLIP-0044:
https://github.com/satoshilabs/slips/blob/master/slip-0044.md (Radiant = 236).

**`bip32_derive_xkeys_from_xkey()` does not accept an integer `change` argument.**
Use `.ckd()` directly:

```python
# CORRECT:
child = xprv.ckd(change).ckd(index)
address = child.address()

# WRONG (AttributeError or silent no-op depending on version):
keys = bip32_derive_xkeys_from_xkey(xprv, index_start=0, index_end=5, change=0)
```

**Batching address derivation breaks BIP44 gap-limit semantics.**
Derive and check one address at a time. A batch of N addresses checked together means a used
address at position k within the batch retroactively invalidates gap tracking for 0..k-1.

**Wrong mnemonic → `InvalidPadding` → `ValidationError`.**
Do not catch `ValidationError` broadly in code that also handles decryption — the signal will
be swallowed. Treat decryption `ValidationError` as "wrong mnemonic or corrupted file."

**`seed_from_mnemonic()` requires `passphrase=` as a keyword argument.** Positional passing
binds to the wrong parameter.

---

## Best Practices

- **Audit existing client methods before adding new ones.** For RPC clients, the method you need often exists under a slightly different name. A quick `grep` or `dir()` saves a duplicate.
- **Validate protocol combinations at the data layer (`__post_init__`), not in the builder.** Errors surface earlier and every downstream consumer gets the same validation for free.
- **Cite SLIP-0044 in constants.** A comment next to `236` citing the registry entry makes the number traceable and prevents future regression.
- **Document the AES-CBC key derivation formula in the docstring.** `key = hash256(seed)[:32]` is non-obvious. Future implementers must not use `hash256(mnemonic.encode())` — incompatible ciphertext.
- **Document IV layout as a format commitment.** `file_bytes = iv + ciphertext` must be stable across versions. A stored wallet must be decryptable by future code.

---

## Test Patterns Worth Reusing

### Patch at the usage site, not the definition site

```python
with mock.patch("pyrxd.glyph.scanner.script_hash_for_address", return_value=b"..."):
    result = await scanner.scan_address("any-address")
```

### Per-UTXO fault injection

```python
async def failing_get_tx(txid):
    if txid == bad_txid:
        raise NetworkError("gone")
    return valid_raw

client.get_transaction = failing_get_tx
results = await scanner.scan_script_hash(sh)
assert len(results) == n_utxos - 1   # bad one skipped, rest returned
```

### Two-output assertion for MUT reveal

```python
scripts = builder.prepare_mutable_reveal(txid, 0, cbor_bytes, owner_pkh)
assert len(scripts.nft_script) == 63
assert len(scripts.contract_script) == 174
assert MUTABLE_NFT_SCRIPT_RE.fullmatch(scripts.contract_script.hex())
```

### Opcode identity assertion (catches silent swaps)

```python
scripts = builder.prepare_container_reveal(txid, 0, cbor_bytes, owner_pkh, child_ref=ref)
assert scripts.locking_script[0] == 0xD0    # OP_PUSHINPUTREF, not 0xD8 singleton
```

### Wrong-mnemonic decrypt raises, not silences

```python
wallet.save(path)
with pytest.raises(ValidationError):
    HdWallet.load(path, mnemonic=different_mnemonic)
```

### Gap-limit boundary: scan stops at correct index

```python
# Index 5 is used → scanner must reach index 25 (5 + GAP_LIMIT = 25)
wallet.addresses["0/5"] = AddressRecord(..., used=True)
await wallet.refresh(client)
assert "0/25" in wallet.addresses
```

---

## Related Documentation

- `docs/solutions/logic-errors/radiant-bip143-sighash-missing-field-and-stale-trial-signature.md` — BIP143 `hashOutputHashes` fix; relevant to any Glyph builder broadcast path
- `docs/solutions/logic-errors/hashoutputhashes-zero-refs-must-be-literal-zeros.md` — zero-refs `refsHash` fix; applies to all builder output scripts
- `docs/solutions/ceremonies/fhc-treasury-keygen.md` — BIP44 key generation; must be coordinated with coin-type-236 fix to avoid ceremony address drift
- `docs/plans/2026-04-24-feat-glyph-scanner-network-to-inventory-plan.md` — design for GlyphScanner and `get_history()` addition
- `docs/plans/2026-04-24-feat-glyph-mut-container-wave-builders-plan.md` — design for MUT/CONTAINER/WAVE builder methods
- `docs/plans/2026-04-24-feat-hd-wallet-persistence-gap-scanning-plan.md` — design for HdWallet gap scanning and persistence
