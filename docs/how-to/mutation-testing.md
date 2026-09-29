# Mutation testing the consensus-critical and value-moving modules

Mutation testing measures **test quality**, not just line coverage: it mutates the source (e.g. flips
`!= 80` to `< 80`, `i - 1` to `i + 1`) and checks whether the suite *catches* each change. A **killed**
mutant means a test failed (good); a **survived** mutant means the line runs but no assertion pins its
behavior — a potential gap.

## Running it

```bash
poetry install --with dev   # brings in cosmic-ray
poetry run task mutate                    # no argument: the default scope, spv
poetry run task mutate spv                # spv/ — the original gate, named explicitly
poetry run task mutate script             # script/ primitives
poetry run task mutate transaction        # transaction/ serialization, inputs, outputs
poetry run task mutate txpreimage         # the FORKID sighash preimage (2 shards in CI)
poetry run task mutate dmint              # glyph/dmint/builders.py — the covenant builders (2 shards in CI)
poetry run task mutate dmintchain         # glyph/dmint/chain.py — state re-derivation parse
poetry run task mutate dmintminer         # glyph/dmint/types.py + miner.py (3 shards in CI)

poetry run task mutate fee                # fee_sizing.py — the one fee-sizing rule
poetry run task mutate wallet             # wallet.py — the flat-key send/sweep builders
poetry run task mutate hdwallet           # hd/wallet.py — the BIP32/44 send/sweep builders
poetry run task mutate glyph              # glyph/ft.py + glyph/builder.py — token builders
poetry run task mutate mint               # glyph/mint.py + transfer.py + client.py — mint/move facade
poetry run task mutate glyphscript        # glyph/script.py + glyph/payload.py — envelope + locking scripts
poetry run task mutate verdicts           # authority/burn/relationship verdicts — the modules that answer "is this true"
poetry run task mutate mutchain           # the mutable-chain walk and its discovery from the chain
poetry run task mutate waveverdicts       # WAVE identity and HashMark anchor verdicts
poetry run task mutate btcleg            # the BTC HTLC leg — taproot refund/claim leafs, payment parse, key handling
poetry run task mutate covenants         # consensus-enforced covenant bytes — the Gravity covenant, soulbound
poetry run task mutate htlccovenant      # gravity/htlc_covenant.py — the HTLC covenant bytes (2 shards in CI)
poetry run task mutate radiantleg        # gravity/radiant_leg.py — the Radiant HTLC leg
poetry run task mutate rswpcovenant      # swap/rswp/covenant.py — the RSWP covenant bytes (2 shards in CI)
poetry run task mutate gravitycore       # gravity/transactions.py — the Gravity transaction builders (2 shards in CI)
poetry run task mutate gravitystate      # the Gravity swap state and trade
poetry run task mutate gravitymaker      # maker, fee policy, finality
poetry run task mutate gravitylegs       # reorg cost, the counter-chain legs, receive, ref authenticity, codehash
poetry run task mutate cryptoprim        # crypto primitives — AEAD, KEM, AES-CBC, curve
poetry run task mutate cryptokeys        # keys.py — signing and key handling
poetry run task mutate cryptosec         # secret handling — RNG, reveal, validated types, unit tags
poetry run task mutate cryptoutils       # utils.py — DER, address/WIF decode, script numbers (3 shards in CI)
poetry run task mutate cryptohash        # hash.py — incl. pure-Python RIPEMD160 and SHA-512/256 (6 shards in CI)
poetry run task mutate glyphverify       # creator signatures, credential binding, royalties
poetry run task mutate glyphscan         # glyph scanner and glyph types
poetry run task mutate glyphinspector    # glyph inspector, WAVE parsing, confusables
poetry run task mutate waverules         # WAVE name rules
poetry run task mutate inspectcore       # glyph/_inspect_core.py — the classification core (4 shards in CI)
poetry run task mutate glyphlock         # timelocked glyph content — reveal tx, encryption envelope, fee sizing
poetry run task mutate wire              # wire encodings and proofs — compactsize, merkle path, consensus walk, message
poetry run task mutate hashmark          # script/hashmark.py — the HashMark encoder/decoder
poetry run task mutate wiretx            # hashmark_tx.py + swap/rswp/wire.py
poetry run task mutate hdseed            # BIP39 mnemonics, BIP44 paths, and account discovery
poetry run task mutate feecore           # the fee models beneath fee_sizing
poetry run task mutate walletcore        # consensus constants and the partial/resolve swap halves
poetry run task mutate markcli           # cli/hashmark_cmds.py — what `pyrxd mark`/`verify` print
poetry run task mutate inspectcli        # cli/glyph_inspect.py — what `pyrxd glyph inspect` prints (4 shards in CI)
poetry run task mutate swap               # gravity/htlc_spend.py + swap/rswp/orders.py
poetry run task mutate coordinator        # gravity/swap_coordinator.py — the swap state machine
poetry run task mutate network            # network/ — remote-response parsing + failover
poetry run task mutate keys               # security/secrets + base58 + hd/bip32 + hd/descriptor + watch/cli_secrets
poetry run task mutate ethleg             # eth_wallet/ — the EVM counter leg (11 modules)
poetry run task mutate ethtimelock        # gravity/eth_rxd_timelock.py — cross-clock timelock arithmetic

poetry run task mutate consensus          # the original four groups, now seven after the timeout split
poetry run task mutate value              # the forty-three value-moving groups
poetry run task mutate all                # everything, sequentially (many hours)
```

The runnable list above is the complete set. `VALUE_GROUPS` in
[`scripts/mutation_test.sh`](../../scripts/mutation_test.sh) is the source of
truth for it, and `tests/test_mutation_groups_are_wired.py` fails if this page
falls behind it — which it did: `glyphscript`, `keys`, `ethleg` and
`ethtimelock` were all absent while this page said "eight". `glyphscript` was
the sharpest case: this page carries a whole "Baseline results — mint and
glyphscript" section for a group its own runnable list did not mention.

This runs [`scripts/mutation_test.sh`](../../scripts/mutation_test.sh). It mutates
`src/pyrxd/<scope>/<file>.py` **in place** (the editable install picks it up), runs a scope-targeted
fast test command per mutant, and restores via `git`. It is an **occasional gate, not part of
`task ci`** (slow). Don't run concurrent git ops on `src/pyrxd` while it runs — when other
sessions/worktrees are active, run the whole thing in a detached worktree.

Useful environment knobs:

- `MUTATION_SESSION_DIR=dir` — keep the cosmic-ray session `.sqlite` files for survivor triage
  (query them with `cr-report`, `cr-html`, or a `mutation_specs ⋈ work_results` join for diffs).
- `MUTATION_REPORT_DIR=dir` — where the per-group Markdown survivor lists land
  (default `.mutation-reports/`, gitignored).
- `MUTATION_MIN_KILL_PCT=N` — opt-in gate: exit non-zero below N% total kill rate.
- `MUTATION_SHARD=k` — run only shard `k` (1-based) of a group listed in `group_shards` in the
  script: every N-th mutant of each module, via `scripts/mutation_shard.py`. The weekly workflow
  sets it; a local run leaves it unset and gets the whole group. Refused for a group that is not
  sharded, so a job named for one slice cannot quietly run everything.
- `MUTATION_RESUME=1` — keep an existing session and pick up where it stopped. `cosmic-ray exec`
  only runs jobs with no result yet, so a group killed at 90% resumes instead of restarting. Use it
  with `MUTATION_SESSION_DIR` and **only when the module has not changed since the session was
  created** — the session's mutation specs were derived from the source at `init` time, so resuming
  across an edit would score two different versions of the file under one number.

### Before it mutates anything

Three preflight checks run first, each for a failure mode that otherwise produces a confident,
meaningless number:

1. **Target sources must be clean.** Cleanup is `git checkout -- <files>`; with uncommitted work in
   a target file that is data loss, and the "baseline" would not be the committed code.
2. **`import pyrxd` must resolve to this checkout.** A shared virtualenv whose editable install
   points at a different clone (a `.pth` naming another repo root) would have cosmic-ray mutate files
   the tests never import — every mutant "survives" and a healthy module scores ~0% killed.
3. **The group's clean suite must be green.** cosmic-ray reads a non-zero exit as *mutant killed*, so
   a red or uncollectable test list scores **100% killed on every module**. That is the most
   flattering number the tool can produce and it is entirely fiction.

The run also restores on `INT`/`TERM`/`HUP`, not just `EXIT`: bash skips an `EXIT` trap when killed by
an untrapped signal, and a run killed mid-sweep used to leave a mutated source file in the tree
looking exactly like a hand edit.

### Parallelism

cosmic-ray's `local` distributor is serial, and two groups **cannot** share one checkout — the mutation
is a real edit to `src/pyrxd`, so a second group's tests would import the first group's mutant and
mis-score it. To use more cores, give each group its own clone and run one group per clone:

```bash
git clone --local --no-hardlinks . /tmp/lane-$g && cd /tmp/lane-$g && task mutate $g
```

That is how the baseline below was measured.

> Scope exclusions, on purpose: `spv/proof.py` / `spv/witness.py` (covered by the fuzz harness, ~30×
> slower per mutant), `__init__.py` re-export shims, `script/unlocking_template.py` (17-line ABC), and
> `glyph/dmint/__init__.py`. The whole-file scope for `glyph/dmint/miner.py` includes the mining
> dispatch loops; their kills come mostly from the DAA/preimage tests, not the multiprocessing paths.
> In `network`, `rxindexer.py` and `chaintracker.py` ARE in scope but score low by design
> (`rxindexer.py` killed 10%) — they are thin passthroughs with no decision in them, so their
> survivors are expected rather than actionable.

### Why `network` is in scope

The other four scopes protect arithmetic a *node* would eventually reject. `network` protects the
one place where nothing else will: consensus does not defend an SPV client against a server that
answers truthfully but about the wrong thing. Whether a lying ElectrumX / Esplora / Bitcoin Core
endpoint can move value rests entirely on `_guards.py` (fail-closed coercions), the
request↔response bindings in `electrumx.py` and `bitcoin.py`, `confirm.py`'s depth gate,
`tls_pin.py` + `registry.py` (which server, on which chain, under which pin) and `failover.py`
(which of those may be relaxed on a retry).

Two files that are part of the same trust boundary sit outside the group because they are not under
`network/`: `swap/rswp/node_rpc.py` and `gravity/watch/adapters.py`. Both were hand-mutated in the
2026-08 sweep (see below); a future scope extension should fold them in.

## Scopes and test commands

Each scope uses a fast targeted test list (defined in `mutation_test.sh`) so a full file sweep stays
tractable — the per-mutant cost is the test command's wall time. `tests/test_mutation_hardening.py`
(the survivor-killing assertions) leads every list so `-x` exits cheapest on the pinned mutants; the
property/differential suites (`test_preimage_differential.py`, `test_dmint_vector_derivations.py`)
close the transaction/dmint lists as the wide net.

Two constraints shape the value-group lists specifically:

- **Files from the same sub-package stay contiguous.** Splitting `tests/cli/*` across the arg list
  makes pytest 9.1.1 stop applying `tests/cli/conftest.py` to the later ones — the `runner` fixture
  disappears and 32 tests ERROR. Because cosmic-ray scores a non-zero exit as *killed*, that reads as
  a perfect score. This is a property of the suite, not of the harness: it reproduces with a plain
  `pytest a b c` invocation. The lists broke this rule anyway (`glyphverify` and `walletcore` fatally,
  `wire` harmlessly), so `tests/test_mutation_groups_are_wired.py` now fails on any group that splits a
  directory holding a `conftest.py`, and `scripts/derive_mutation_test_lists.py` emits those runs
  contiguous and last.
- **Group by the tests that decide, not by directory.** `wallet.py` and `hd/wallet.py` started as one
  group and their decisive suites turned out to be nearly disjoint, so each file's mutants were paying
  for the other file's tests — a ~15s clean suite where each half needs ~8s. They are two groups now.
- **A slow test in the list is a slow test times the mutant count.** The clean-suite wall time is not
  a detail of the list; it decides whether the group can be run at all. Scoping `mint` found
  `test_glyph_mint_facade.py` at 30.8s — three tests each waiting out a 10s confirmation poll interval
  that nothing could shorten, because neither of `_reveal`'s two waits was passed an `interval_s`.
  Against 1,644 mutants that is the difference between **~11 hours and under an hour**, so the fix
  (`poll_interval_s`, exposed on `GlyphMinter`/`GlyphClient`) was a prerequisite for the group rather
  than a nicety. Before adding a group, time its list first: if it is far off the ~1-3s the others
  run in, find out why before writing the group.

### A third equivalent-mutant class: BitOr on OS flag constants

The catalogued equivalents are type annotations, error-message f-strings and
interpreter-detail rewrites. Add flag arithmetic.

`JsonFilePendingStore.save` opens with `os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_CLOEXEC`,
and `_fsync_dir` with `os.O_RDONLY | O_CLOEXEC`. Those constants are **pairwise disjoint**
bits, so `|`, `+` and `^` produce the identical value — every BitOr_Add and BitOr_BitXor
mutant on such a line is equivalent by construction.

`_fsync_dir` is the extreme case: `os.O_RDONLY` is **0**, so `0 op O_CLOEXEC` is 0 or
524288 (or -524288) for every operator cosmic-ray substitutes, and `os.open` on a directory
succeeds with all of them — the only casualty is close-on-exec, which has no observable
in-process effect. 12 of its 13 mutants survive and **none of them is killable**. The one
that dies does so because `/` yields a float and `os.open` rejects it.

Across the mint and glyphscript sweeps this class accounts for 22 survivors that would
otherwise read as untested durability code. Recognising it matters because the surrounding
code — atomic write, fsync, `0o600` — genuinely is fund-critical, so the temptation is to
write a test. There is nothing there to test.

### Verifying one mutant by hand — clear the bytecode cache

The loop for proving a new test actually kills something is: plant the defect, run the
suite, confirm RED, restore, confirm GREEN. Restoring with `cp` (or any write that keeps
the file the same size within the same second) can leave Python serving the **cached
bytecode of the mutant** — CPython invalidates a `.pyc` on mtime and size, and a
same-length edit defeats both.

It is not hypothetical: swapping `if n <= 75:` for `if n <= 74:` in `glyph/payload.py` and
restoring produced a "failure" on clean source that took several minutes to chase, because
the interpreter was still running the mutant. Same-length numeric and operator edits are
exactly the mutations cosmic-ray generates most.

So between plant and run, and again between restore and re-run:

```bash
find src -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
```

`scripts/mutation_test.sh` is not affected — it restores with `git checkout --`, and each
cosmic-ray mutant runs in a fresh subprocess against a freshly written file — but the
manual loop is, and a false SURVIVED reads as "my test is worthless" while a false KILLED
reads as "my test works". Both are worse than no measurement.

### And confirm the plant actually landed

The cache trap above is an edit that applied and was then served stale. The other way to get
a false SURVIVED is simpler and easier to miss: **the edit never applied at all.** A `sed`
pattern that does not match, an insertion anchored to the wrong line, an indentation
mismatch — each exits 0, changes nothing, and the suite then passes for the most boring
reason available. It reads exactly like a surviving mutant.

Observed in another project (2026-08): of five mutants recorded as SURVIVED in one
session, **three had never been applied**. The tests were fine; the measurement was fiction.

cosmic-ray cannot make this mistake — it rewrites the AST and writes the mutant file itself,
which is why `scripts/mutation_test.sh` needs no such check. The by-hand loop has no such
guarantee, so make the edit prove itself:

```bash
# before: capture the exact thing you intend to change
before=$(grep -c 'if n <= 75:' src/pyrxd/glyph/payload.py)
# ...plant the mutation...
after=$(grep -c 'if n <= 75:' src/pyrxd/glyph/payload.py)
[ "$before" -gt "$after" ] || { echo "MUTATION DID NOT APPLY — result is meaningless"; exit 1; }
```

`git diff --stat -- <file>` works just as well and is harder to get wrong. The rule is the
same either way: **a SURVIVED verdict is only evidence if you have proof the source changed.**
Check the restore too — a restore that silently fails leaves the mutant in your tree and
poisons every run after it.

## Baseline results — mint and glyphscript (2026-08)

Both groups were run twice. The first numbers are kept because the difference between
them is the point: **a kill rate measures the test list as much as the code.** Both lists
were first built by topic — files that looked related to the module — and both were wrong.
Rebuilding them from which test files actually reference each module's symbols moved
`glyph/payload.py` from 37% to 75%.

| Module | Mutants | Killed | Survived | annot | Logic | Effective |
|---|---|---|---|---|---|---|
| `glyph/mint.py` | 804 | 506 | 298 | 187 | 102 | **82%** |
| `glyph/transfer.py` | 582 | 398 | 184 | 55 | 124 | **76%** |
| `glyph/client.py` | 258 | 137 | 121 | 99 | 11 | **86%** |
| `glyph/script.py` | 703 | 625 | 78 | 22 | 55 | **92%** |
| `glyph/payload.py` | 572 | 429 | 143 | 0 | 143 | **75%** |

*Effective* is against killable mutants — survivors marked `annot` are BitOr rewrites of
type annotations, which cannot change behaviour under `from __future__ import annotations`.
The raw column understates `client.py` badly: 99 of its 121 survivors are that class.

What the two sweeps actually found, and what was done about it:

- **`ft_funding`'s fee estimate — 104 logic survivors on two lines.** The number deciding
  which plain-RXD UTXO can pay an FT transfer's fee, passed to `find_plain_rxd_utxo`, which
  skips anything below it. Every constant and operator was mutable with nothing noticing,
  including deleting the 2x headroom the docstring promises. Now 18, pinned by probing the
  acceptance threshold and bounding it against a real built transfer's fee.
- **The commit's per-kB conversion — 12 survivors on one line.** `SatoshisPerKilobyte(fee_rate
  * 1000)`. Note the asymmetry it sits in: `assert_pays_for_its_size` appears once in
  `mint.py`, on the reveal. The commit is built, fee'd, signed and broadcast with no size
  check. The tests assert the property the missing guard would have.
- **`_push_bytes` — 66 survivors on the CBOR push opcode selection.** Executed by every
  mint (a modest NFT's CBOR is 186 bytes) but never asserted, so the opcode and the
  little-endian length width were both free to change.
- **Compound shape guards in `script.py` — 25 survivors on four lines.** `if len(script) !=
  75 or script[25] != 0xBD or script[26] != 0xD0:` — mutating one clause survives because
  the others still reject the malformed inputs the suite uses. The module scored 92%
  *because* these were the part nothing reached.

Not everything surviving is worth a test. `_push_minimal_int` has survivors on branches that
look identical to `_push_bytes`'s, but its condition is on the byte-length of an encoded
integer: reaching `length >= 0x4C` needs n >= 2**608. Unreachable, not untested.

## Baseline results — spv (2026-06)

| Module | Mutants | Killed | Survived | Killed |
|---|---|---|---|---|
| `pow.py` | 143 | 120 | 23 | 84% |
| `merkle.py` | 354 | 288 | 66 | 81% |
| `chain.py` | 132 | 78 | 54 | 59% |
| `payment.py` | 268 | 219 | 49 | 82% |

## Baseline + hardening results — script/, transaction/, glyph/dmint/ (2026-07)

The 2026-07 run measured each file with the PRE-hardening test lists (baseline), then every surviving
mutant was re-checked individually — its stored diff applied to a clean worktree and the UPDATED test
command run — to measure the post-hardening score without a second multi-hour sweep. A full re-run of
one scope (`script`) spot-checked that the per-survivor method matches a fresh sweep.

| Module | Mutants | Baseline killed | After hardening | Still surviving | …of which annotation-equivalent |
|---|---|---|---|---|---|
| `transaction/transaction.py` | 509 | 285 (56%) | 360 (71%) | 149 | 99 |
| `transaction/transaction_input.py` | 104 | 44 (42%) | 47 (45%) | 57 | 55 |
| `transaction/transaction_output.py` | 53 | 16 (30%) | 19 (36%) | 34 | 33 |
| `transaction/transaction_preimage.py` | 675 | 322 (48%) | **622 (92%)** | 53 | 0 |
| `script/script.py` | 299 | 172 (58%) | 207 (69%) | 92 | 33 |
| `script/timelock.py` | 257 | 249 (97%) | 253 (98%) | 4 | 0 |
| `script/type.py` | 340 | 241 (71%) | 272 (80%) | 68 | 55 |
| `glyph/dmint/builders.py` | 2197 | 2024 (92%) | **2179 (99%)** | 18 | 0 |
| `glyph/dmint/chain.py` | 1251 | 803 (64%) | 930 (74%) | 321 | 28 |
| `glyph/dmint/types.py` | 364 | 232 (64%) | 326 (90%) | 38 | 0 |
| `glyph/dmint/miner.py` | 1909 | 1430 (75%) | 1453 (76%) | 456 | 39 |

The annotation-equivalent column is a conservative lower bound (surviving `BitOr`-family mutants
whose diff touches only a signature/annotation line). Excluding just that class, the
annotation-adjusted post-hardening scores are e.g. transaction.py 88%, transaction_input 96%,
type.py 95%, transaction_output 95% — the honest view of files whose raw score is dragged by
`str | bytes | Reader`-style signatures.

**Spot-check:** a full fresh sweep of the `script` scope at the same commit reported 92 / 4 / 68
survivors for script.py / timelock.py / type.py — identical, file for file, to the per-survivor
re-check's prediction.

## Baseline results — value-moving modules (2026-08)

First measurement of the new scope, at commit `3115028` (module sources identical to `724fe92`).
Every module below ran to completion; the kill rate is over mutants that actually executed.

| Group | Module | Mutants | Killed | Survived | Killed | …annotation-equivalent | Wall time |
|---|---|---|---|---|---|---|---|
| `fee` | `fee_sizing.py` | 362 | 322 | 40 | **89%** | 0 | 16 min |
| `wallet` | `wallet.py` | 295 | 176 | 119 | 59% | 0 | 26 min |
| `hdwallet` | `hd/wallet.py` | 1201 | 776 | 425 | 65% | 132 | 89 min |
| `glyph` | `glyph/ft.py` | 453 | 318 | 135 | 70% | 77 | 13 min |
| `glyph` | `glyph/builder.py` | 736 | 177 | 559 | **24%** | 88 | 24 min |
| `swap` | `gravity/htlc_spend.py` | 277 | 205 | 72 | 74% | 22 | 7 min |
| `swap` | `swap/rswp/orders.py` | 529 | 282 | 247 | 53% | 143 | 15 min |
| `coordinator` | `gravity/swap_coordinator.py` | 1657 | 1162 | 495 | 70% | 187 | 42 min |
| `network` | `network/bitcoin.py` | 1288 | 840 | 448 | 65% | 77 | 47 min |
| `network` | `network/electrumx.py` | 557 | 301 | 256 | 54% | 110 | 26 min |
| `network` | `network/failover.py` | 251 | 118 | 133 | 47% | 88 | 8 min |
| `network` | `network/confirm.py` | 171 | 132 | 39 | 77% | 22 | 16 min |
| `network` | `network/registry.py` | 100 | 67 | 33 | 67% | 22 | 3 min |
| `network` | `network/rxindexer.py` | 95 | 10 | 85 | **10%** | 55 | 1 min |
| `network` | `network/tls_pin.py` | 93 | 76 | 17 | 81% | 11 | 2 min |
| `network` | `network/_guards.py` | 85 | 70 | 15 | 82% | 11 | 2 min |
| `network` | `network/chaintracker.py` | 21 | 17 | 4 | 80% | 0 | <1 min |
| **total** | | **8171** | **5049** | **3122** | **61%** | **1045** | **5 h 36 m** |

Per group, which is the unit a runner executes:

| Group | Mutants | Killed | Wall time |
|---|---|---|---|
| `fee` | 362 | 89% | 16 min |
| `wallet` | 295 | 59% | 26 min |
| `hdwallet` | 1201 | 65% | 89 min |
| `glyph` | 1189 | 42% | 37 min |
| `swap` | 806 | 60% | 22 min |
| `coordinator` | 1657 | 70% | 42 min |
| `network` | 2661 | 61% | 104 min |

**5 h 36 m serially; 1 h 44 m as wall clock** when each group gets its own runner, which is the
shape the scheduled workflow uses. That difference is the whole argument for one job per group.

> **Wall times are upper bounds, not clean measurements.** They were taken on a 32-core workstation
> running six to eight of these groups concurrently *and* an unrelated parallel mutation workload —
> load average 12-16 throughout. A single group run on an idle machine will be faster; a 2-core CI
> runner will be slower. Treat them as "what a group costs when the box is busy", which is the number
> that decides whether anyone can afford to run it.

Three results stand out, and none is a scheduling artifact:

- **`glyph/builder.py` kills 24% of its mutants** — the lowest score in the scope, on the largest
  module in it. Line coverage from the offline suite is 66%, so a third of the file never executes
  here; the regtest end-to-end suites cover those paths and they do not run in this lane. The honest
  reading is that this module's *offline* tests are close to a smoke test.
- **`wallet.py` kills 59% with zero annotation-equivalent survivors.** Unlike the other low scorers it
  has no annotation noise inflating the count: those 119 survivors are all real assertions nobody
  wrote, in the module that builds ordinary sends.
- **`network/rxindexer.py` kills 10%**, but 55 of its 85 survivors are annotations — the module is
  small and heavily typed. Adjusted, it is 30 genuine survivors out of 40 non-annotation mutants,
  which is still the weakest ratio in `network/` and the one to look at first.

For contrast, the small guard modules score well: `_guards.py` 82%, `tls_pin.py` 81%,
`chaintracker.py` 80%, `confirm.py` 77%. Test quality here is not uniformly low — it is low
specifically where the module is large and its coverage comes from regtest rather than unit tests.

## Reading the score — survivors are not all bugs

A large share of survivors are **equivalent mutants** that *cannot* be killed because they don't change
behavior. In this codebase they cluster into:

- **Type annotations** — `bytes | None` → `bytes - None`. Harmless: `from __future__ import annotations`
  makes annotations strings, never evaluated. This is the single largest class in every file (e.g. 33 of
  transaction.py's survivors sit on two `str | bytes | Reader` signatures).
- **Error-message f-strings** — `f"…offset {i - 1}"` → `{i + 1}`. Only the *text* of an exception
  message; no test asserts exact wording, and it shouldn't.
- **Interpreter-detail equivalents** — `==` → `is` on small interned ints / single-char strings /
  enum members; `x & (1<<31)` → `x // (1<<31)` inside a range-checked 32-bit domain; `<` → `!=` on a
  monotonically increasing loop counter.
- **Equivalent-for-valid-inputs** — e.g. `to_ef`'s `source_txid` branch (both branches produce the same
  bytes when `source_txid == source_transaction.txid()`, which construction guarantees), or comparison
  rewrites that only diverge for inputs outside the documented domain (`change_distribution` strings
  other than `"equal"`/`"random"`).
- **Outcome-equivalent guards** — `from_hex` length checks where `!=` vs `<` cannot differ because
  `Reader.read_bytes` never over-returns, and any fall-through still ends in the same `None` via the
  surrounding `suppress(Exception)`.

So the raw kill-rate **understates** real assertion quality. The value of the run is finding the
*genuine* gaps — branches that execute with no behavioral test.

## What the 2026-07 run found and closed

Survivor triage produced `tests/test_mutation_hardening.py` — every test there names the mutant class
it kills. The genuine gaps were real and some were consensus-adjacent:

- **`Transaction.txid()` byte order had no test.** The `hash()[::-1]` reversal could be deleted and the
  suite stayed green. Now pinned against a stdlib-only double-SHA256 re-derivation.
- **The FORKID preimage module was killable almost at will** (56%+ survival at baseline): the ref-scanner
  push-skip arithmetic, SIGHASH branch selection, and field assembly had only fixed-vector coverage.
  The spec-derived differential (`tests/test_preimage_differential.py`, anchored to the radiantjs golden
  vectors) now catches these, plus direct pins for the truncated-pushref guards the (deliberately
  well-formed) differential generator can't reach.
- **Script chunk parsing asserted nothing about chunk data** — push-boundary (75 B), PUSHDATA1/2/4
  dispatch, `from_asm` token handling ("-1" vs "0", push-size cliffs, unknown opcodes), `find_and_delete`
  retention, `__eq__` vs ordering.
- **Validation guards lacked boundary-exact tests** — dMint deploy params (`__post_init__` rules),
  CSV/CLTV ranges and the disable-bit ordering, BEEF version magic, `parse_script_offsets` skip
  arithmetic, minimal-push sign-bit padding (`0x90` → `90 00`).
- **dMint state re-derivation guards** — the script-number parser pinned to the encoding spec from both
  sides (parse + encode), and surgical corruption of valid contracts at documented layout offsets.

## What the 2026-08 run found (open — not yet closed)

The full survivor lists are in [`../reference/mutation-survivors/`](../reference/mutation-survivors/index.md),
one file per group, with file:line and the exact source change. These are the entries whose *meaning* is
worth stating up front, because in each case the guard is load-bearing and its removal is invisible:

- **The relay-floor comparison has no equality test.** `fee_sizing.required_fee` line 284,
  `if fee_rate < relay_floor_photons_per_byte()`, survives being rewritten to `<=`, `!=` and `is not`.
  Those differ from `<` only when `fee_rate == floor` — the single most common production value, and
  the case that decides whether a caller's sub-floor rate is honoured verbatim or raised.
- **`fee_never_below_relay_floor`'s rate arithmetic is never decisive.** Line 336's
  `size_bytes * fee_rate` survives `-`, `//`, `%`, `>>` and `&`: every test of this function lands on
  the `min_relay_fee` side of the `max()`. This is the "no opt-out" API documented for callers whose
  fee rate crosses a trust boundary.
- **Two exported consensus constants are unpinned.** `WITNESS_SCALE_FACTOR = 4` (BIP141, used by
  `bitcoin_virtual_size` and re-exported through `gravity/fee_policy.py`) survives becoming 3 or 5;
  `RADIANT_MIN_RELAY_PHOTONS_PER_KB` survives ±1. No test states either value.
- **HTLC unlocking-script size estimates are unpinned.** In `gravity/htlc_spend.py`, `lambda: 110`
  (P2PKH fee input) survives 109 and 111, and `lambda: len(selector) + 80` (covenant input) survives
  every binary-operator rewrite including `-`. These estimates are what the fee is sized from before
  the real signature exists. Radiant has neither RBF nor CPFP, so an under-estimate is the documented
  failure: rejected for `min relay fee not met`, holding its inputs until mempool expiry — on a claim,
  against a deadline. The same file's line 149 appends the sighash flag with `to_bytes(1, "little")`
  and survives a width of 2, which would emit a scriptSig consensus rejects; nothing asserts the bytes.
- **The cross-chain timelock ordering guard is not boundary-tested.** In
  `swap_coordinator.assert_timelock_margin`, the ordering comparison survives rewriting, as does the
  margin comparison below it. The equal-timelock case is exactly the unsafe one.

  > **The 2026-08 run quoted the PRE-#482 source, and that quote is not repeated here.** At the time
  > this line read `if btc_blocks <= rxd_blocks` — the *wrong* direction, which #482 identified as a
  > deterministic maker-theft path and inverted. The current source reads
  > `if rxd_blocks <= btc_blocks`, and #567 replaced the margin comparison underneath it with a
  > wall-clock one (`maker_refund_opens_s < taker_refund_opens_s + margin_s`) because the two legs
  > count different chains' blocks. Re-run `task mutate coordinator` before triaging either against
  > today's tree; the same caveat is on
  > [`docs/reference/mutation-survivors/coordinator.md`](../reference/mutation-survivors/coordinator.md),
  > whose rows are a 2026-08-12 snapshot. An unmarked quote of the superseded ordering is how the
  > unsafe direction re-acquires authority, which is the whole reason #482 was a security release.
- **Validation loops can be made to iterate zero times.** `ZeroIterationForLoop` survives on
  `swap_coordinator`'s `__post_init__` and `taker_refund_window_open` parameter-validation loops —
  every guard inside them is unexercised. `accept_flat_burial: bool = False` also survives flipping to
  `True` at all three of its declarations, a safety-posture default nothing pins.
- **RSWP order/asset binding guards survive.** In `swap/rswp/orders.py`, the checks that the offered
  UTXO belongs to the order (`give_source_tx.txid() != order.offered_txid`) and that the advertised
  token id and contract type match what is actually offered (`order.token_id != _pushed_token_id(give)`,
  `order.offered_type != _contract_type_of(give)`) all survive operator rewrites, as does
  `change = total_in - fee`. `tx.sign(bypass=True)` survives flipping to `False` in three builders.

Nothing here is a demonstrated exploit, and several may prove equivalent on inspection. What the run
establishes is narrower and still worth having: **these lines can be changed without any test
objecting**, in modules that decide how much value moves and to whom.

## Known remaining survivors (deferred)

- `spv/merkle.py` — the `i * 33` branch-index arithmetic needs a **multi-level** proof fixture;
  `spv/pow.py` chunked compare needs mined boundary headers; `spv/payment.py` needs boundary-exact
  transactions (unchanged from 2026-06).
- `transaction.py` BEEF **bump-combine** branches (`to_beef` path_index dedup/merge) need
  MerklePath-carrying fixtures; BEEF/EF are BSV interchange formats, not Radiant consensus surfaces, so
  these are documented rather than chased.
- `glyph/dmint/chain.py` async ElectrumX discovery flows and `glyph/dmint/miner.py` mining-dispatch
  loops — operational (not byte-consensus) paths whose remaining survivors are timing/IO-shaped; the
  regtest e2e suites cover them end-to-end.
- `glyph/builder.py`'s uncovered third — the offline suite never executes it, so those survivors say
  "not tested offline", which is already known from the 66% line coverage. Closing them means either
  offline fixtures for the builder paths or accepting that the regtest suites own them; that is a
  scope decision, not a triage one.

## Where this runs

Three places, deliberately, and **not** on the per-push path:

| Where | What | Why |
|---|---|---|
| `task mutate <group>` | on demand, locally | the loop you use while writing killer tests |
| [`Mutation (scheduled)`](https://github.com/MudwoodLabs/pyrxd/blob/main/.github/workflows/mutation.yml) | weekly, one parallel job per group (or per shard) | keeps the survivor list current without anyone remembering to run it |
| pre-release | `task mutate value` over the groups touching what shipped | the release checklist's slot for "did the new tests actually assert anything" |

The per-push gate is `ci.yml`, whose required checks must stay fast enough that people do not learn
to route around them; the measured cost here is **5 h 36 m of compute**, 16-104 minutes per group on
a loaded 32-core box. That is not a per-push shape at any budget. The scheduled lane is modelled on the existing
`Fuzz (scheduled)` workflow — Tuesday cron so it does not collide with Monday's fuzz run, forks
excluded from the schedule, manual `workflow_dispatch` retained.

One job per group, `fail-fast: false`. Groups **cannot** share a runner: cosmic-ray edits
`src/pyrxd` in place, so a second group's tests would import the first group's mutant and mis-score
it. Separate runners give each group its own checkout for free and make the wall clock the slowest
group rather than the sum. The repo is public, so these are free-tier minutes rather than a draw on
the private Actions pool.

### Fitting a group in one job (330 minutes)

A job that hits `timeout-minutes: 330` is cancelled and produces no score. Two runs on 2026-09-29
measured which groups do not fit:

- **Run 36521398529**, a manual dispatch of six groups on `b81658c1`, lost four of the six:
  `wire`, `verdicts`, `glyphverify` and `inspectcli`.
- **Scheduled run 36558376548**, on `fa47d7f6`, ran all 29 groups and lost six: `dmint`,
  `cryptoprim`, `gravitycore`, `covenants`, `glyphverify` and `inspectcli`. `transaction`
  finished in 319 minutes and `verdicts` in 318, 11 and 12 minutes under the limit; `wire`
  finished in 263.

Each of these groups is now split by module, and any module too big for one job on its own is
**sharded**: `group_shards` in the script names it, `scripts/mutation_groups.py` emits one matrix
job per shard, and each job keeps every N-th mutant of the fresh session
(`scripts/mutation_shard.py`). A sharded group may hold several modules; each is split N ways.
Every split group keeps its parent's exact test command (tests, marker and timeout), so no module
is tested by less than before; `test_a_split_group_keeps_its_parents_exact_test_command` pins
that.

The same module does not take the same time in every run. On the 12 modules both runs reached,
run 36521398529 took 0.79-1.53× as long as run 36558376548 (1.53× on `script/hashmark`: 10,648 s
against 6,953 s). So the split below keeps every job under about 165 minutes, which stays under
330 even at 1.53× slower, rather than just under 330.

**The first split** (`wire`, `verdicts`, `glyphverify`, `inspectcli`), sized from run
36521398529. Minutes per job, from that run's per-module seconds where it reached the module
(**M**), and otherwise ESTIMATED (**E**) from a `cosmic-ray init` mutant count times a per-mutant
rate. Run 36558376548 later measured some of these on the old grouping; its figures are in the
last column.

| Job | Modules | Minutes | Basis | Run 36558376548 |
|---|---|---|---|---|
| `wire` | compactsize, merkle_path, script/consensus, script/message | ~118 | M, except message (E) | 80 M |
| `hashmark` | script/hashmark | 177 | M (1,084 mutants, 10,648 s) | 116 M |
| `wiretx` | hashmark_tx, swap/rswp/wire | ~103 | E: an earlier run's per-mutant rate × 1.7; on the four `wire` modules both runs reached, run 36521398529 was 1.4-1.8× slower per mutant | 67 M |
| `verdicts` | glyph/authority, burn, relationships | 149 | M | 114 M |
| `mutchain` | glyph/mutable_chain, mutable_chain_discovery | 152 | M | 118 M |
| `waveverdicts` | glyph/wave_identity, mark_anchor | ~103 | E: earlier per-mutant rate × 1.1; the five `verdicts` modules both runs reached were 1.10-1.12× slower | 85 M |
| `glyphverify` | glyph/creator, credential_binding, royalty | 124 | M | 149 M |
| `glyphscan` | glyph/scanner, types | ~164 | E: scanner at its measured 12.7 s/mutant (it grew from 237 to 375 mutants in #784); types at 13.7 s | scanner 76 M; types not reached |
| `glyphinspector` | glyph/inspector, wave, confusables | ~173 | inspector M; wave and confusables E at 13.7 s | inspector ran ≥ 105 without finishing |
| `waverules` | glyph/wave_rules | ~172 | E: 755 mutants at 13.7 s | not reached |
| `inspectcore` ×4 | glyph/_inspect_core | ~133 each | E: 2,334 mutants at 13.7 s, over 4 shards | not reached |
| `inspectcli` ×4 | cli/glyph_inspect | ~149 each | E: 1,428 mutants at 25 s, over 4 shards | whole module ran ≥ 330 without finishing (≥ 82 per shard) |

The 13.7 s/mutant for the `glyphverify` test list is a SAMPLE, not a sweep: 25 random
`_inspect_core` mutants averaged 18.9 s on a local box whose clean `glyphverify` suite took 29 s
against the runner's 21 s, so 18.9 × 21 / 29. It agrees with the 12-13 s the runner measured on
credential_binding, scanner and inspector. For `inspectcli`, 25 random mutants averaged 30.9 s
locally; the 15 that survived (and so ran the whole list) averaged 40.7 s against the runner's
33 s clean suite, so 30.9 × 33 / 40.7 ≈ 25 s. Neither sample hit the per-mutant timeout. If
every mutant survived and so ran the full clean suite, one `inspectcore` shard (584 mutants ×
21 s) would take ~204 minutes and one `inspectcli` shard (357 × 33 s) ~196. That is NOT an upper
bound: a mutant that hangs costs the group's cosmic-ray timeout (`group_timeout`: 60 s for
`inspectcore`, 90 s for `inspectcli`), not the clean-suite time, so the ceiling is about 584 ×
60 s ≈ 584 minutes and 357 × 90 s ≈ 536 minutes per shard. The estimates rest on the samples
never having hit that timeout. Run 36558376548 ran the glyph modules 1.19-1.26× slower than run
36521398529 did, which would put `glyphinspector` and `waverules` near 210 minutes.

**The second split** (`transaction`, `dmint`, `covenants`, `gravitycore`, `cryptoprim`), sized from
run 36558376548. **M** is measured seconds from that run (halved or thirded for a sharded module).
**S** is a 30-mutant local sample of the module (the same test command, seed 20260929), scaled to
the runner by a CONTROL module of the same group that the run did measure, and by the ratio of the
clean-suite times; the range is the two scalings, widened to include the group's mean seconds per
mutant. **E** is the module's `cosmic-ray init` count times the group's measured mean seconds per
mutant (low end) or the group's highest sampled rate (high end). Every count (local cosmic-ray
8.4.6) was checked against the run's logged counts on the modules it did reach, and matched exactly.

| Job | Modules | Minutes per job | Basis |
|---|---|---|---|
| `transaction` | transaction, transaction_input, transaction_output | 103 | M |
| `txpreimage` ×2 | transaction/transaction_preimage | 107 each | M (12,898 s) |
| `dmint` ×2 | glyph/dmint/builders | 110 each | M (13,165 s) |
| `dmintchain` | glyph/dmint/chain | 116-149 | S; the run had already spent ≥ 111 minutes on it when cancelled |
| `dmintminer` ×3 | glyph/dmint/types, miner | 115-160 each | miner S (3,001 mutants, 296-381 minutes alone), types E |
| `covenants` | gravity/covenant, glyph/soulbound_covenant | 122-125 | covenant M, soulbound E |
| `htlccovenant` ×2 | gravity/htlc_covenant | 106 each | M (12,693 s) |
| `radiantleg` | gravity/radiant_leg | 73-87 | S; ≥ 43 minutes spent on it when cancelled |
| `rswpcovenant` ×2 | swap/rswp/covenant | 62-97 each | S (1,273 mutants) |
| `gravitycore` ×2 | gravity/transactions | 102 each | M (12,218 s) |
| `gravitystate` | gravity/swap_state, trade | 124 | M |
| `gravitymaker` | gravity/maker, fee_policy, finality | 124-161 | maker S, the rest E |
| `gravitylegs` | gravity/reorg_cost, eth_leg, counter_chain_leg, receive, ref_authenticity, codehash | 114-164 | E |
| `cryptoprim` | crypto/aead, crypto/kem, aes_cbc, curve | 157 | M |
| `cryptokeys` | keys | 148 | M |
| `cryptosec` | security/rng, reveal, types, units | 63-109 | E (`units` has 0 mutants) |
| `cryptoutils` ×3 | utils | 144-149 each | S (1,845 mutants) |
| `cryptohash` ×6 | hash | 137-141 each | S (2,464 mutants) |

The group mean was wrong in three places, which is why the samples exist. `dmint/chain` had already
run about 6,636 s when the job was cancelled (its wall time less `builders`, the baseline, and the
~30 s of setup the finished jobs show), above the 5,091 s that the group's mean (3.86 s per mutant,
all of it from `builders`) predicts for the whole module. `dmint/miner` samples at 5.9-7.6 s per
mutant on the runner, not 3.86, which made two shards too few. `hash` samples at 20-21 s per mutant
against the group's 11.9, because 14 of its 30 sampled mutants survived and so ran the whole clean
suite; the mean alone would have given it four shards of ~123 minutes where the sample says
~205-212.

The first weekly run of the new split replaces every **E** and **S** above with a measurement; if
any job lands near the timeout, split or shard it further rather than raising the timeout.

### One module's score from its shards

Each shard job prints its own line per module and uploads its own sessions, as
`mutation-<group>-shard<k>of<n>`. A module's score is the SUM over its shards: add the `killed`
and the `mutants` columns across the n shard logs, then divide. The shards partition the module's
mutants exactly (`tests/test_mutation_shard.py`), so nothing is counted twice or missed. Do not
average the per-shard percentages: shards differ in size by up to one mutant, and a shard that
did not finish reports a rate over the mutants it ran, which averaging would weight like a full
one. `scripts/mutation_shard_scores.py` does the sum from the downloaded logs:

```bash
gh run download <run-id> --repo MudwoodLabs/pyrxd --pattern 'mutation-cryptohash-shard*' --dir shards
python scripts/mutation_shard_scores.py shards/*/mutation-*.log
```

It refuses a module that has an INCOMPLETE shard or is missing a shard, rather than report a
score over part of the module.

cosmic-ray runs one mutant at a time (the `local` distributor is serial), so each job uses one of
the runner's cores; the step prints `nproc` so the count is recorded rather than assumed.

### What each job uploads

Two artifacts per job, both under dot-directories and so both needing `include-hidden-files: true`
(upload-artifact skips hidden paths by default since v4.4, which is why every artifact before this
held only the log):

- `mutation-<job>-survivors` — the Markdown survivor list. **Required** when the sweep succeeded:
  the upload fails the job if it is missing. On a failed sweep it is uploaded if it exists.
- `mutation-<job>` — the log and the session `.sqlite` files, always, including after a timeout,
  so the mutants that did run can still be re-queried with `cr-report`.

The lane is **report-only** — no `MUTATION_MIN_KILL_PCT`. A third of the survivors in this scope are
equivalent mutants (1 045 of 3 122 are annotation-only by the conservative count), so a raw kill-rate
threshold would either sit below the real quality bar or fail the build on untriaged noise. Its
output is the uploaded survivor list; triage is the human step, and the tests it produces belong in
`tests/test_mutation_hardening.py`. Set a per-group threshold once that group's equivalent classes
have been triaged out — `fee` at 89% is the closest to ready.
