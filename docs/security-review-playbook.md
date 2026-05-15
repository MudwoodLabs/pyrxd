# Security review playbook

A working notebook of the techniques that found **real bugs** in
pyrxd's 0.5.0 and 0.5.1 release cycles — not a generic methodology.
Each section names the technique, the actual finding it produced, and
the cases where it applies vs. where it doesn't.

Use this when starting a review on pyrxd itself, or as a reference
when bootstrapping a review of a sibling project in the Radiant
ecosystem.

## Scope and limits

This document captures **what worked on pyrxd** between roughly
2026-04-29 (0.2.0) and 2026-05-14 (0.5.1). It is biased toward:

* Wire-format builders that emit bytes the rest of the ecosystem
  parses.
* Parsers that consume attacker-supplied input (block-explorer
  pastes, ElectrumX responses, hostile reveal scriptSigs).
* Library code shipped to PyPI under MIT/Apache — the audience is
  downstream SDK consumers, not end users.

It is **not** a comprehensive Radiant-ecosystem methodology. If your
target is a frontend wallet, an indexer, or pure tooling without
on-chain serialization, only a subset of the techniques here will
apply. The "When it applies / when it doesn't" subsection of each
case study calls that out.

## Per-repo intake checklist

Before picking which techniques to run on a new repo, answer five
questions. The Yes answers map to the case studies below.

| Question | If yes → | If no → |
|---|---|---|
| Does the repo emit bytes that another implementation has to parse (transactions, contracts, CBOR, BIP-32 paths)? | §1 golden-vector pinning | Skip §1 |
| Is there a canonical reference implementation in another language? | §2 cross-implementation byte-diff | Skip §2; §1 carries the load alone |
| Does the repo expose any parser to attacker-controlled input? | §3 trust-boundary fuzz contract | Skip §3 |
| Is the repo about to ship a release with non-trivial new surface? | §4 multi-reviewer panel | Optional |
| Is the repo public? | §5 mechanical leak-checking | Skip §5 (private repos still benefit but the urgency is lower) |

If you got at most one Yes, this playbook isn't the right tool —
spawn the `security-sentinel` reviewer alone via the `/security-panel`
skill (see `.claude/skills/security-panel.md`) and call it.

If you got three or more, run them in the order listed: §1 builds the
golden vectors §2 will diff against; §3 hardens the parser side; §4
fans the multi-reviewer panel out across the cleaned tree; §5 is the
mechanical guard that runs in CI from then on.

---

## §1 — Golden-vector pinning against mainnet

**What it does.** For every wire-format builder, capture real
on-chain bytes for a known-good transaction and assert
`build(...) == GOLDEN`.

**What it found.** Two critical bugs that 49 round-trip tests missed:

1. **M1 V1 dMint mint scriptSig push convention.** Pre-0.5.0,
   `build_mint_scriptsig` pushed `<inputHash> <outputHash> <nonce>
   <0x00>` (72 bytes total). The canonical mainnet convention is
   `<0x04 nonce(4)> <0x20 inputHash(32)> <0x20 outputHash(32)>
   <0x00>` — same length, different push order. The old shape
   produced mint transactions the covenant rejects 100% of the time.
   M1 had never successfully spent a mainnet contract until this
   bug was found by walking real bytes against the builder's output.
   Verified fixed at txid `c9fdcd34…e530`.
2. **V2 mint reward output emitted plain P2PKH at vout[1].** The
   covenant requires the same 75-byte FT-wrapped reward as V1
   (`build_dmint_v1_ft_output_script`). Caught pre-V2-mainnet-deploy
   when the audit panel walked the V2 builder against the V1 golden.
   Would have been a 100% rejection on every V2 mint.

**Why round-trip tests miss this.** `assert parse(build(x)) == x`
proves the builder and parser are self-consistent. Both can harbor
**coordinated bugs** invisible to every round-trip assertion —
they were authored from the same flawed mental model. Real-world
example here: the M1 builder *and* the M1 parser agreed on the wrong
push order. Mainnet didn't.

**Where pyrxd carries this.** Six golden-vector test classes pin
every wire-format builder pyrxd ships:

| Builder | Test class | Mainnet ref |
|---|---|---|
| `build_ft_locking_script` (75 B) | `TestFtLockingScriptMainnetGolden` | RBG transfer `ac7f1f70…0ae4` |
| `build_nft_locking_script` (63 B) | `TestNftLockingScriptMainnetGolden` | Glyph NFT `27390efa…be7e` |
| `build_commit_locking_script` (75 B, FT + NFT) | `TestCommitLockingScriptMainnetGolden` | GLYPH deploy `a443d9df…878b` |
| `decode_payload` + `build_reveal_scriptsig_suffix` (65 569 B w/ embedded PNG) | `TestCborPayloadMainnetGolden` | GLYPH reveal `b965b32d…9dd6` |
| `build_dmint_v1_contract_script` (241 B) | `TestV1GoldenVectorGlyphPattern` | GLYPH deploy reveal vout 0 |
| `build_mint_scriptsig` (72 B) + 4-output mint shape | `TestCovenantShape` | snk `146a4d68…f3c` + PXD `c9fdcd34…e530` |

**Mechanics — how to add one in roughly 20 minutes.**

1. Find a mainnet transaction known to use the format you're building.
   For Glyph/dMint, the [Radiant Glyph Guide][rgg]'s §17 has a
   table; otherwise `gh api repos/<org>/<repo>/contents/...` against a
   working implementation's test fixtures, or `getrawtransaction`
   against your full node.
2. Fetch the raw tx hex; extract the specific output (or scriptsig)
   bytes you want to pin. For payloads >a few kB, check them in as a
   binary fixture under `tests/fixtures/` (see `glyph_reveal_cbor.bin`
   for the canonical example).
3. Write one test class that asserts:
   - `build(...) == captured_bytes` (the core assertion)
   - The captured bytes pass your own classifier (round-trips with
     the parser side, but the *baseline* truth is the on-chain bytes,
     not the round-trip)
   - `extract_*(captured_bytes)` recovers the inputs (proves bytes
     and parser agree)

The test file in `tests/test_glyph_dmint.py::TestCommitLockingScriptMainnetGolden`
is a good template — 79 lines, three assertions, no dependencies
beyond the builder itself.

**When it applies.** Any function whose output is a byte string
another implementation must parse. Bonus when the on-chain consumers
are covenant-driven (Radiant covenants reject byte-shape mismatches
100% of the time — silent corruption is impossible, but so is
"works on testnet").

**When it doesn't.** Pure business logic, frontend rendering,
tooling without serialization, RPC client wrappers that round-trip
JSON unmodified. Don't manufacture golden vectors where there is no
canonical wire format to pin against.

**Anti-pattern to avoid.** Don't write goldens against your own
testnet broadcasts. The point is *independent ground truth* — bytes
emitted by a different implementation (Photonic, glyph-miner,
Photonic Wallet, etc.) on mainnet. A self-loop test pinning your own
output against your own output is just a slower round-trip test.

[rgg]: https://github.com/MudwoodLabs/radiant-glyph-guide

---

## §2 — Cross-implementation byte-diff

**What it does.** Diff your builder's output against the canonical
reference implementation, at the byte level, with the explicit rule:
"Photonic (or whatever the reference is) is the default; deviate
explicitly and document the reason when the reference is wrong."

**What it found.** The audit pattern that catches the bugs §1's
golden vectors only catch retrospectively (after they ship to
mainnet). Used during 0.4.0 → 0.5.0 to validate the V1 deploy and
V1 mint flows before the first mainnet broadcast.

The rule cuts both ways:
- The Photonic V1 mint scriptSig push order is what pyrxd had to
  match — pyrxd had it wrong, Photonic had it right.
- Photonic's `parseDmintScript` ships as V2-only in master — but
  the live ecosystem runs V1. pyrxd correctly deviated and
  documented `docs/dmint-research-photonic-deploy.md` §7 explaining
  why.

**Where pyrxd records the diff convention.** Two places, both
public-tracked:

- `docs/dmint-research-photonic-deploy.md` — per-decision table:
  Photonic file/line, what value Photonic emits, what pyrxd emits,
  and the reason for any divergence.
- `docs/dmint-research-photonic.md` — the same for the broader
  Photonic source-tree walk.

**Mechanics.** Read the reference implementation *with the goal of
emitting matching bytes* — not "understand the protocol." Capture
each builder call and decode call as a row in a divergence table:

| Photonic file:line | Photonic emits | pyrxd emits | Match? | Reason if not |
|---|---|---|---|---|
| `script.ts:152-213` (ftCommitScript) | `aa20<hash>88…` | `aa20<hash>88…` | ✓ | — |
| `script.ts:704-766` (dMintScript) | V2 9-state-item layout | V1 3-state-item layout | ✗ | Photonic master ships V2-only emit; live chain runs V1 |

The act of filling the table *is* the audit. Each "match" row is a
no-op confirmation; each "no match" row is either a real divergence
(documented) or a bug (fix and re-row).

**When it applies.** Protocols with a canonical reference
implementation in another language. For Radiant: Photonic Wallet
(Glyph/dMint/WAVE), glyph-miner (dMint mining), RXinDexer (indexer
classifiers). For other ecosystems: BIP-32 reference vectors, the
Bitcoin Core RPC reference, etc.

**When it doesn't.** Protocols with no second implementation, or
where the second implementation is *itself* a fork of yours. Then §1
golden vectors against on-chain bytes are the strongest baseline you
can write.

**The deferral rule.** Don't write a divergence row that says
"Photonic does X, we'll do Y because X is suboptimal" without
mainnet evidence. Either:

1. Find an on-chain transaction emitted by a *third* implementation
   that agrees with X — Photonic is right, you match.
2. Find an on-chain transaction emitted by a third implementation
   that agrees with Y — Photonic is wrong (or outdated), document
   and deviate.
3. Neither exists — the protocol surface isn't validated; **don't
   ship it**, mark experimental, defer to a future release where one
   side has been validated.

The V2 dMint reward bug was caught by exactly this rule: pyrxd's
V2 path matched Photonic's V2 emit, but no V2 contract has been
deployed to mainnet → no third-party validation possible → the V2
path is now quarantined behind `V2UnvalidatedWarning` (see §6 below
for how this connects to release hygiene).

---

## §3 — Trust-boundary fuzz contract

**What it does.** For every parser that consumes attacker-supplied
input, assert one specific contract:

> Return a structured value, or raise one specific exception type.
> Any other exception type is a bug — the parser leaking its
> internal failure mode past its trust boundary.

**What it found.** A `cbor2.CBORDecodeError` escaping `decode_payload`
that slipped past the inspect-tool's `except ValidationError`
handler. The inspect tool's browser flow crashed instead of cleanly
classifying the input as malformed. Fix was a one-line wrap inside
`decode_payload`; without the fuzz test, the bug would have only
been visible to a user who happened to paste exactly the wrong
bytes.

**Where pyrxd carries this.** `tests/test_fuzz_parsers.py` ships
eight Hypothesis targets, all asserting the same contract via the
shared `_fail_unexpected()` helper:

```python
def _fail_unexpected(target: str, exc: BaseException, raw: bytes | str) -> None:
    payload = raw.hex() if isinstance(raw, (bytes, bytearray)) else repr(raw)
    pytest.fail(
        f"{target} raised unexpected {type(exc).__name__}: {exc}\n"
        f"  input ({len(raw)}): {payload}"
    )
```

The eight targets:

1. `decode_payload` — CBOR decode boundary
2. `DmintState.from_script` — variable-length opcode walker
3. `GlyphInspector.extract_reveal_metadata` — push-data walker
4. `GlyphInspector.find_glyphs` — script classifier dispatch
5. `_inspect_script` — CLI/browser inspect dispatch
6. `_classify_input` — top-level inspect classifier
7. `GlyphRef.from_bytes` / `from_contract_hex` — fixed-shape ref
   decoders
8. Round-trip: `build_mutable_scriptsig` → push-data walker recovers
   the embedded CBOR (proves builder and parser agree on the
   structural contract, separate from the byte-shape contract §1
   covers)

Plus five atheris coverage-guided harnesses under
`scripts/fuzz_atheris/`, hitting the same surface with libFuzzer
mutation feedback.

**Mechanics — adding a fuzz target.**

1. Identify the parser function that consumes attacker input. "Where
   does untrusted bytes/text first cross into your code?" — that's
   the boundary.
2. Write one `@given(data=st.binary(...))` decorator + a try/except
   asserting the contract:

```python
@given(data=st.binary(min_size=0, max_size=1024))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_my_parser_only_validation_error(data):
    try:
        my_parser(data)
    except ValidationError:
        # expected: parser converted a malformed input cleanly
        pass
    except Exception as exc:
        _fail_unexpected("my_parser", exc, data)
```

3. Run at CI budget (~1.5 s for 400 examples). If it finds a
   counterexample, the failure message prints the offending bytes
   hex-encoded — paste it into a reproduction unit test before
   fixing the parser.

**When it applies.** Any parser at a trust boundary: HTTP request
handlers, RPC dispatchers, file-format readers, script walkers,
CBOR/JSON/protobuf decoders. Anywhere the input is "whatever the
attacker decided to send."

**When it doesn't.** Internal-only parsers consuming data your own
code wrote three lines earlier. The trust boundary is *external
input* — fuzzing your own serialization round-trip is a §1
golden-vector concern, not a §3 fuzz concern.

**Cost.** The Hypothesis suite runs in ~1.5 s at CI budget (400
examples per target). The atheris harnesses are overnight-run
material — invoke via `scripts/fuzz_overnight.sh` against an 8-core
box. Don't put atheris on the per-commit CI path.

**Anti-pattern.** A `try/except: pass` with no comment looks like a
broad swallow even when it's correct. Either add a comment naming
the expected contract (`# expected: parser converted a malformed
input cleanly`) or pin the exception type tightly. CodeQL's
`py/empty-except` rule will flag the comment-less form.

---

## §4 — Multi-reviewer panel

**What it does.** Spawn a fan-out of specialised reviewer subagents
in parallel against the same target (a PR, a branch's diff, or a
specific path). Each reviewer focuses on its own dimension —
security, architecture, simplicity, performance, etc. — and returns
a short report. You synthesize.

**What it found.** Almost everything in the 0.5.0 audit pass: the
V2 reward-shape bug (red-team chain-conformance reviewer),
unnecessary V2 surface that turned into the `V2UnvalidatedWarning`
quarantine (architecture-strategist), the broad-except leak that
turned into §3 (security-sentinel + pattern-recognition-specialist),
the missing FT golden vector (pattern-recognition-specialist).
0.5.0's CHANGELOG attributes findings to specific reviewers.

**The roster.** Eight slots, three are language-specific. For a
Python repo:

| Slot | Reviewer | What it catches |
|---|---|---|
| Security | `compound-engineering:review:security-sentinel` | Auth, input validation, secrets, OWASP top-10 patterns |
| Pattern recognition | `compound-engineering:review:pattern-recognition-specialist` | Anti-patterns, naming inconsistencies, duplication |
| Architecture | `compound-engineering:review:architecture-strategist` | Layering, coupling, abstraction boundaries |
| Simplicity | `compound-engineering:review:code-simplicity-reviewer` | YAGNI violations, premature abstraction |
| Performance | `compound-engineering:review:performance-oracle` | Algorithmic complexity, hot-path issues |
| Data integrity | `compound-engineering:review:data-integrity-guardian` | Migrations, transactions, persistent state |
| Language quality | `compound-engineering:review:kieran-python-reviewer` (or `kieran-typescript-reviewer`, `kieran-rails-reviewer`) | Idiomatic patterns, type safety, maintainability |
| Red team | `general-purpose` with a red-team prompt | Adversarial mindset; "what's the worst thing a hostile caller could do here?" |

There is **no dedicated red-team reviewer**; the eighth slot is a
`general-purpose` agent given a red-team-styled prompt. Lean
heavily on "what assumptions does this code make about its caller
that an attacker could violate?"

**Where pyrxd carries this.** As a Claude skill at
`.claude/skills/security-panel.md` (this PR adds it). Invoke with
`/security-panel`; it prompts for scope (current branch diff, a
specific path, or a PR number) then fans the eight reviewers out in
parallel.

**Mechanics.** The skill instructs the orchestrating Claude
instance to make **eight `Agent` tool calls in a single message** so
they run concurrently. Each agent gets a prompt scoped to its
dimension plus the same target description. The skill defines an
output schema — each reviewer returns under 400 words; the
orchestrator synthesizes findings into a single report with severity
buckets (critical / high / medium / low / info) and a "consensus
vs. one-reviewer-only" tag on each finding.

**When it applies.** Pre-release audits. Risky refactors. New
features touching wire formats or trust boundaries. Any change where
the cost of a bug is high and the diff is large enough that single-
reviewer fatigue is a real risk.

**When it doesn't.** Per-commit reviews on a routine PR — you'll
burn tokens for low marginal value. Documentation-only PRs (run
`every-style-editor` alone). Mechanical chores (linting, dep bumps,
CI config tweaks).

**Cost.** Each reviewer agent is a full Claude run with its own
context. Eight in parallel on a 2 000-line diff is roughly the
token cost of a heavy investigation. Budget accordingly.

**Anti-pattern: reviewer overload.** Running the full panel on
every PR trains the team to ignore reviewer findings ("noise"). Save
it for the moments where the signal-to-noise actually warrants it.

---

## §5 — Mechanical leak-checking

**What it does.** A `task ci` check that scans every tracked
markdown/RST file for two leak classes:

1. **Markdown link targets pointing into `.gitignore`d paths**
   (`[text](docs/design/foo.md)` when `docs/design/` is private).
   Such links break in every clone and leak the existence of
   private files via the link text.
2. **Absolute home-directory paths with a baked-in username**
   (`/home/<user>/...` or `/Users/<user>/...`) anywhere in doc
   body, link or prose or fenced code block. These leak the
   author's username and local layout. When they point into a
   sibling private project, they leak that project's existence
   too.

**What it found.** A single grep at the end of the 0.5.1 release
sprint surfaced **18 leaks across 6 tracked docs** that had been
public on `origin/main` for over a week:

- One `file://` markdown link directly into the author's private
  `~/.claude/` auto-memory directory.
- Two prose mentions of that private memory file's name.
- About fifteen `/home/<user>/apps/…` paths, several pointing into
  a private sibling-project group (leaking the existence of those
  private projects via the path name alone).
- A VPS IP and a full `ssh ericadmin@<ip> -- sudo docker exec ...`
  line — username + IP + the fact the VPS runs docker as sudo.

Every leak was old. None had been caught by review. None had been
caught by CI. The mechanical scan ran in 60 ms.

**Where pyrxd carries this.** `scripts/check-no-private-links.py`.
Two checks, both run on every invocation:

1. Link-target check — link is gitignored.
2. Home-path regex check — `/home/<user>/...` or
   `/Users/<user>/...` in any tracked doc.

Wired into `task ci` so the pre-push hook catches new leaks before
they reach `origin`. The hardened version was deliberately narrow:
it does **not** flag `~/...` (username-agnostic — the correct way
to document `~/.pyrxd/config.toml`), `/root/...` (no username),
or `/tmp/...` (scratch paths carry no user identity).

**Mechanics — porting to another repo.** The script is portable
as-is. Drop `scripts/check-no-private-links.py` into the target
repo, add it to `task ci` (or whatever the equivalent test
runner is), and add a `.gitignore` block for repo-specific private
paths (most repos want at least `.claude/`, `.worktrees/`,
`logs/`). Done.

**When it applies.** Every public repo. Even when the techniques in
§1–§4 don't fit (frontend-only, doc-only), this one always does.

**When it doesn't.** Truly-private internal repos where there's no
publication surface at all. Even then, the discipline pays off if
you ever consider opening the repo later.

**Anti-pattern.** Methodology theatre — adding a "Security
Checklist" markdown file that nobody reads is worse than nothing,
because it creates the appearance of coverage. The mechanical
check, in CI, is the only form that catches the next leak.

---

## What this playbook is NOT

Worth being explicit, because it's tempting to over-read the success
of one release cycle as a general methodology:

* **Not a substitute for a deep-review pass on a new repo.** The
  techniques here found bugs on a *familiar* codebase. The first
  pass on an unfamiliar repo should still be the multi-reviewer
  panel from §4, not the playbook in isolation.
* **Not a guarantee.** Six golden vectors caught two on-chain-
  rejection bugs. They would not have caught a covert ECDSA-nonce
  reuse, a timing side-channel, or a logic error in the wallet's
  coin-selection. Different attack classes need different lenses.
* **Not stable.** This document will go stale. Re-derive the
  techniques from the next release cycle's *actual* findings; don't
  preserve sections out of habit.

## Update protocol

Add a new case study when:

* A specific technique finds a real bug that the other techniques in
  this playbook would have missed.
* You ship a security fix and want the lesson to compound.

Remove or rewrite a case study when:

* It no longer reflects the actual workflow.
* The technique it documents is now mechanical (lives in `task ci`
  rather than in human review).
* A subsequent finding contradicts it.

The point is the case studies, not the index. Length is fine as long
as every section names a real finding.
