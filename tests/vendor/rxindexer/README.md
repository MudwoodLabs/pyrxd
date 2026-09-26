# Vendored RXinDexer sources

Verbatim, unmodified copies of the files under `electrumx/` here, from
[Radiant-Core/RXinDexer](https://github.com/Radiant-Core/RXinDexer) at the commit recorded in
`MANIFEST.json` (`ca8a6a4e77ef0ad3f24ec6f41cb0a73eb5f3651e`) — the same commit
`tests/fixtures/rxindexer_upstream_pin.json` pins. They are **test fixtures**: the test suite
imports them to run the indexer's own WAVE claim path. Nothing in `src/` imports them, and they
are not part of the installed package.

RXinDexer is derived from ElectrumX and distributed under the MIT License;
`LICENCE` is its licence file, copied verbatim from the same commit.

## Why these are here

A WAVE name is registered by the indexer, not by consensus. `src/pyrxd/glyph/wave_rules.py`
decides whether a payload registers a name (`wave_registered_label`), and so whether it owes the
registration fee, and how much (`wave_registration_price`). Both are pyrxd's transcriptions of
RXinDexer. The tests that graded them graded pyrxd with pyrxd: the CLI suite asked
`wave_registered_label` whether the reveal registered the name it paid for, and the library suite
compared against a second transcription written into the test file (0.25.0 pre-release panel,
reviewer D). A transcription checked against another transcription says nothing about the
indexer.

`tests/rxindexer_oracle.py` runs `WaveIndex.process_tx` from these files on pyrxd-built
transactions, and `tests/test_wave_fee_matches_the_pinned_indexer.py` holds pyrxd's fee decision,
price and treasury to what that code does.

## Which files, and why whole files

| File | Why |
|---|---|
| `electrumx/server/wave_index.py` | the claim path (`process_tx`), `validate_wave_name`, `wave_name_price`, the treasury default |
| `electrumx/lib/glyph.py` | the envelope parser the block processor runs before `process_tx` |
| `electrumx/lib/util.py`, `hash.py`, `script.py`, `enum.py` | what those two import (the claim path builds the owner key with `Script`) |
| `electrumx/__init__.py`, `lib/__init__.py`, `server/__init__.py` | the package as upstream lays it out |

Whole files, not extracted functions: the pin is a digest per FILE, so a whole file is the only
form whose bytes can be proved to be the pinned code. `test_wave_fee_matches_the_pinned_indexer.py`
checks every file against `MANIFEST.json`, checks the file set in both directions, and checks that
the two files the drift pin also covers (`wave_index.py`, `lib/glyph.py`) carry the pin's digests
at the pin's commit — so moving the pin without re-vendoring fails.

One step of the indexer's path is NOT vendored: which input's envelope the block processor hands
`process_tx` is chosen inside `GlyphIndex` (`electrumx/server/glyph_index.py`, lines 847-880),
which needs a whole index to run. `tests/rxindexer_oracle.py` transcribes those lines and says so.

## Refreshing

After `python scripts/check_photonic_drift.py --target rxindexer --update-pin` moves the pin,
fetch each file listed in `MANIFEST.json` at the new commit, byte for byte:

    gh api "repos/Radiant-Core/RXinDexer/contents/<path>?ref=<commit>" \
      -H "Accept: application/vnd.github.raw" > tests/vendor/rxindexer/<path>

then write the new commit and `sha256sum` digests into `MANIFEST.json`, re-read the transcribed
`glyph_index.py` lines against `tests/rxindexer_oracle.py`, and run the tests. Never edit a file
here to make a test pass: `ruff` and the pre-commit hooks are told to leave this directory alone
for that reason (`pyproject.toml`, `.pre-commit-config.yaml`).

Line citations in `docs/` of a file vendored here (`electrumx/server/wave_index.py`,
`electrumx/lib/glyph.py`, …) resolve to the copy here (`tests/test_doc_citations_resolve.py`), so
they are line numbers at the pinned commit.
