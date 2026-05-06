---
title: Dmint classifier missed V1 contracts on Radiant mainnet
problem_type: integration_issue
component: pyrxd.glyph.dmint
symptoms:
  - All 10 dmint contract outputs in RBG reveal tx classified as type=unknown
  - V2 parser raised "unrecognised opcode 0xbd" at byte 95
  - Only FT and NFT vouts classified; dmint contracts silently failed
  - Synthetic V2 fixtures passed but live mainnet inspection failed
severity: high
date_solved: 2026-05-06
prs: [36, 39, 41]
tags: [dmint, glyph, classifier, mainnet, parser, v1, regression]
related_files:
  - src/pyrxd/glyph/dmint.py
  - src/pyrxd/cli/glyph_cmds.py
  - tests/test_glyph.py
  - tests/cli/test_glyph_inspect_cmds.py
---

## Symptom

When inspecting the RBG token's reveal transaction (`c5c296ebff5869c6e2b208ce0cd04be479a9f10d33cf73608f0a5efc2d6b55b6`) on Radiant mainnet, the dmint inspector classified every dmint output as unrecognised:

```
vouts 0-9: type=unknown
vout 10:   type=ft
vouts 11-12: type=nft
vout 13:   type=p2pkh
```

The 10 dmint contract UTXOs at vouts 0-9 — the entire mining pool — were silently invisible. No exception, no warning, just `unknown`. The synthetic V2 unit tests all passed.

## Investigation

1. Pulled the reveal tx via the live mainnet client and dumped the raw output scripts for vouts 0-9.
2. Hand-decoded one script byte-by-byte against the V2 layout that `DmintState._from_v2_script` expected. Found only **6** state pushes before an `OP_STATESEPARATOR` (0xbd), not the 10 V2 pushes the parser was walking.
3. Counted the post-separator code section: **145 bytes**, byte-identical across all 10 outputs except a single byte at offset 19 inside the epilogue (`0xaa` = `OP_HASH256` = SHA256D).
4. Cross-referenced with `docs/dmint-research-mainnet.md` §2.2/§3, which already documents the V1 format (6 state items + fixed code template). The shipped parser was written against V2 only.
5. Audited `tests/test_glyph_dmint.py` — every fixture was a synthetic script generated from `build_dmint_state_script` (which is V2). No real-mainnet bytes were ever exercised against `from_script`, so the V1/V2 mismatch could not surface.

## Root Cause

Two layouts exist; the parser only knew V2:

|                | V1 (mainnet)                | V2 (HEAD spec)            |
|----------------|-----------------------------|---------------------------|
| State items    | 6                           | 10                        |
| Algo encoding  | byte inside code epilogue   | `_push_minimal` in state  |
| DAA mode       | none (always FIXED)         | state push + DAA bytecode |
| Code section   | 145-byte fixed template     | parameterised             |

`_from_v2_script` consumes pushes positionally. On a V1 script it reaches item 5 (V1's 8-byte target push), reads it as `algoId`/`daaMode`/`targetTime`, then expects `0x04` (push-4) for `lastTime` and finds `0xbd` (`OP_STATESEPARATOR`) instead — raising `ValidationError`. The caller swallowed that as "not a dmint contract."

The test suite missed it because every fixture round-tripped V2 builder output through the V2 parser. There were no captured-mainnet-bytes goldens, so a parser that worked on synthetic V2 but rejected every real V1 contract on chain looked perfectly green.

## Solution

Turn `from_script` into a dispatcher that tries V2 first, then falls back to V1, and finally raises a combined error naming both attempts ([`src/pyrxd/glyph/dmint.py`](../../../src/pyrxd/glyph/dmint.py) `from_script`):

```python
@classmethod
def from_script(cls, script_bytes: bytes) -> DmintState:
    try:
        return cls._from_v2_script(script_bytes)
    except ValidationError as v2_exc:
        try:
            return cls._from_v1_script(script_bytes)
        except ValidationError as v1_exc:
            raise ValidationError(
                f"DmintState.from_script: not a dMint contract (V2: {v2_exc}; V1: {v1_exc})"
            ) from None
```

`_from_v1_script` walks the 6 V1 state items (height, contractRef, tokenRef, maxHeight, reward, 8-byte target push), then validates the code section against a V1 epilogue fingerprint:

```python
algo = _match_v1_epilogue(script_bytes, pos)
if algo is None:
    raise ValidationError(f"...code epilogue at pos {pos} does not match V1 template")
```

The fingerprint is the 145-byte mainnet template with a single byte wildcarded. `_V1_EPILOGUE_PREFIX` covers the 19 bytes before the algo selector; `_V1_EPILOGUE_ALGO_OFFSET = 19` selects the wildcard byte; `_V1_EPILOGUE_SUFFIX` covers everything after (the FT-CSH builder, output validation, and tail). The middle byte is mapped via `_V1_ALGO_BYTE_TO_ENUM`: `0xaa→SHA256D`, `0xee→BLAKE3`, `0xef→K12`. Returning the parsed state with `is_v1=True`, `daa_mode=FIXED`, and `target_time=last_time=0` lets callers ignore V2-only fields safely. `build_dmint_mint_tx` refuses V1 inputs explicitly so V1 contracts can't be accidentally rebuilt with V2 covenant code.

## Verification

Re-ran the inspector against the RBG reveal tx. 13 of 14 outputs classified correctly: 10 dmint contracts (vouts 0-9), 1 FT (vout 10), 2 NFTs (vouts 11-12); vout 13 is plain P2PKH change. The parser surfaced the RBG token parameters directly from the on-chain V1 state:

- `max_height` = 6,750,000
- `reward` = 6,200 photons
- `algo` = SHA256D (epilogue byte `0xaa`)
- `daa_mode` = FIXED (V1 has no DAA bytecode)
- Total supply = 6,750,000 × 6,200 = **41,850,000,000 photons (41.85B)**

All 10 contract UTXOs returned identical state (modulo `height`), confirming the fingerprint discriminator is tight enough to accept real mainnet bytes and the dispatcher cleanly routes them to the V1 path.

## Related Documentation

**Past solutions (`docs/solutions/`)**

`docs/solutions/` exists with `design-decisions/` and `integration-issues/` subdirectories. **No prior solution covers dmint, the V1/V2 classifier, parser, or fixtures.** The closest tangential precedent is [`docs/solutions/integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md`](../integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md) — same family of risk (don't change a wire-format constant in isolation; values are baked into test fixtures).

**Spec docs that informed the fix**

- [`docs/dmint-research-mainnet.md`](../../dmint-research-mainnet.md) — V1 byte layout
  - §1 Discovery method (line 15) — node access, epilogue fingerprint `dec0e9aa76e378e4` (line 28)
  - §2.2 Byte-by-byte decode of UTXO #1 (line 94) — full V1 opcode walk
  - §3 Cross-comparison (line 155) — table noting "V2 state items: 3 … matches V1 preimage layout, not V2" (line 145)
  - §5 Open questions (line 259) — explicit "Cannot distinguish V1 vs V2 from the guide alone" (line 268), "Python builder needs both code paths and a switch" (lines 272-273)
- [`docs/dmint-research-photonic.md`](../../dmint-research-photonic.md) — V2 reference and V1/V2 classification
  - §2.1 State script V2, 10 items (line 48)
  - §10 Follow-up: V1 vs V2 classification + ship-which decision (line 584)
  - §10.2 V1 bytecode location and `V1_BYTECODE_PART_B` literal (lines 608-622)
- [`docs/dmint-followup.md`](../../dmint-followup.md) — PoW dMint future-work scope context

**PR chain (relevant context)**

- #34 `fix(cli): pass hex str to is_ft_script in transfer-ft path`
- #35 `feat(glyph): GlyphRef.from_contract_hex for explorer-style contract ids`
- #36 `feat(glyph): classify dMint contract outputs + commit scripts` *(initial classifier — V2-only — the bug)*
- #37 `feat(cli): pyrxd glyph inspect — classify any Glyph input offline`
- #38 `feat(cli): pyrxd glyph inspect --fetch — txid lookup via electrumx` *(surfaced the bug live)*
- #39 `fix(glyph): parse V1 dMint contracts (the actual mainnet format)` *(the fix)*
- #40 `fix(cli): support Python 3.10 via tomli fallback for tomllib`
- #41 `test(cli): lock inspect against a real RBG transfer fixture` *(regression fixture from real mainnet bytes)*

**Cross-references in pyrxd modules**

- [`src/pyrxd/glyph/script.py`](../../../src/pyrxd/glyph/script.py) `is_dmint_contract_script` — thin wrapper around `DmintState.from_script`; catches `ValidationError`, `struct.error`, `IndexError`. Inherits V1 support automatically via the dispatcher.
- [`src/pyrxd/glyph/inspector.py`](../../../src/pyrxd/glyph/inspector.py) `find_glyphs` — imports `DmintState` lazily (cycle avoidance), stores parsed state on `GlyphOutput.dmint_state`, calls `DmintState.from_script(script)` to classify.
- [`src/pyrxd/cli/glyph_cmds.py`](../../../src/pyrxd/cli/glyph_cmds.py) `_inspect_script` and `inspect` command — emits `{"type": "dmint", "version": "v1|v2", "contract_ref_outpoint", …}`.
- [`src/pyrxd/glyph/scanner.py`](../../../src/pyrxd/glyph/scanner.py) — **does not consume `DmintState`** (no references found); scanner does not currently classify dmint outputs in wallet display.

## Prevention

### The pattern to institutionalize

When adding any parser or classifier for an on-chain format, **capture real mainnet bytes as test fixtures alongside synthetic ones**. Synthetic-only fixtures lock the parser to *the spec it was written from*, not *the spec actually deployed*. The `DmintState.from_script` bug and the earlier FT-transfer Discord thread share one root cause: a test suite that round-trips its own builder and declares victory. The builder and parser agree because they were both written from the same document — neither has ever met a transaction the network actually mined.

The corrective rule: **a parser is not "tested" until it has correctly classified bytes that came off the chain.**

### Checklist: adding a new on-chain parser in pyrxd

- [ ] Synthetic builder + parser round-trip tests (table stakes; keeps the builder honest)
- [ ] At least one live-mainnet fixture captured from a real tx and committed to the test file
- [ ] Cite the source txid in a test class docstring or module-level constant so the provenance survives refactors
- [ ] If multiple deployment versions exist (V1 vs V2, legacy vs current), capture **one fixture per version**
- [ ] Test the dispatcher on inputs from both versions, plus an input that matches neither, to confirm the `unknown` path works
- [ ] Run the fixture through the full integration path — `find_glyphs`, CLI `glyph inspect` output — not only the leaf parser. Many bugs only surface once the bytes are walked end-to-end.

### Concrete test pattern

PR #41 set the template. Inline the captured bytes as `bytes.fromhex(...)` constants in the test file, with a comment block stating the source txid, the vout, and what the bytes represent. Two reference points already in the tree:

- `tests/test_glyph.py::TestV1DmintParser` — fixture-only form. The class docstring names the txid; the hex constant is named after the field it represents; assertions cover each parsed attribute.
- `tests/cli/test_glyph_inspect_cmds.py::TestInspectRealRbgTransfer` — integration form. Same fixture, but exercised through the CLI command so the user-visible output is locked in.

Keep both forms. The leaf-parser test pinpoints regressions; the integration test catches breakage in the layers between the parser and the user.

### Future improvement: `scripts/regen_onchain_fixtures.py`

A small helper that takes a list of `(txid, vout | "all")` pairs, fetches the raw script bytes via the existing RPC client, and emits paste-ready `bytes.fromhex(...)` literals plus the citation comment block. Don't build it yet — wait until the third time someone hand-copies hex from a block explorer. When that happens, the script removes the friction that currently discourages adding live fixtures.

### What this teaches about reading specs

`docs/dmint-research-mainnet.md` documented the V1 layout. `docs/dmint-research-photonic.md` documented V2. The parser was written from the photonic doc; mainnet runs V1. The lesson is not "read more docs" — both docs were read. The lesson is **pick the spec that matches deployed reality, not intended reality**.

Practical heuristic for pyrxd: before implementing a parser from a spec document, confirm with a block explorer or RPC query that at least one real transaction matches that spec's shape. If you can't find one, you are either parsing a future format (fine, but mark it experimental) or parsing a format that was never actually deployed (a trap). The captured-fixture rule enforces this automatically: you cannot complete the checklist for a format that has no on-chain instances.
