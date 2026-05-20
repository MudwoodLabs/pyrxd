# dMint Integration — Brainstorm

**Date:** 2026-05-07 (revised same day after V1-vs-V2 ecosystem check)
**Status:** Brainstorm (pre-plan)
**Owner:** eric

## What We're Building

Finish dMint support in pyrxd so the SDK can both **claim from existing
mainnet V1 dMint contracts** (e.g. RBG) and **deploy fresh V1 dMint
tokens that other ecosystem tooling can mine**. Today pyrxd
reads/classifies every live dMint shape but cannot mint against the
only contract version anyone has actually deployed, and its
`prepare_dmint_deploy` silently produces V2 contracts that no
ecosystem miner targets.

Framing: this is a **tool, not a wallet**. pyrxd ships protocol primitives
plus a slow-but-correct reference miner. UX, GPU mining, and operational
tooling are out of scope.

## Immediate Deploy Footgun

[`prepare_dmint_deploy`](../../src/pyrxd/glyph/builder.py#L291) ships
today with no version parameter — it always emits a **V2** contract via
`build_dmint_contract_script` (V2 hex template). Anyone running it
against mainnet right now would issue a non-standard token:

- **Zero live V2 contracts exist on mainnet.** All seven decoded
  contracts in [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md)
  are V1.
- **glyph-miner targets V1 only** (4-byte nonce, V1 OP_PICK indices in
  the locking script). It cannot mine a V2 deploy without code
  changes.
- **Photonic Wallet's CashScript source `powmint.rxd` is V1-only.** V2
  in Photonic exists only as hand-written hex.
- **Indexer behavior on V2 deploys is empirically unknown** — RXinDexer
  and Photonic explorer were both built when V1 was the only shape.

This shifts the milestone sequence: V1-deploy moves up; V2 work moves
out indefinitely.

## Why This Matters

`docs/dmint-followup.md` is **stale** — it describes pyrxd as having only
the premine path with PoW listed as future work. The actual code in
[`src/pyrxd/glyph/dmint.py`](../../src/pyrxd/glyph/dmint.py) (1,268 lines)
already contains:

- Full V2 contract script builder
- ASERT/LWMA/FIXED DAA bytecode emitters and off-chain mirrors
- V1 + V2 contract-state parser
- Solution verifier (sha256d)
- 3-tx deploy orchestration via [`prepare_dmint_deploy`](../../src/pyrxd/glyph/builder.py#L291)

What is **actually** missing:

1. **V1 mint builder.** [`build_dmint_mint_tx`](../../src/pyrxd/glyph/dmint.py#L1019)
   refuses V1 contracts at [L1091](../../src/pyrxd/glyph/dmint.py#L1091).
   All seven live mainnet contracts decoded in
   [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) are V1.
   So pyrxd can read them but not spend them.
2. **No nonce-grinding loop.** Only solution verification ships, not mining.
3. **No live-mint integration test.** Tests round-trip against synthetic
   UTXOs only — no proof a tx pyrxd builds actually clears the network.
4. **EPOCH and SCHEDULE DAA modes** raise `NotImplementedError` (low
   priority — not used by any observed contract).

## Why This Approach

**Approach 1 (revised): V1-mint, then V1-deploy, V2 deferred indefinitely.**

- M1: **V1 mint.** Unblocks RBG and every live mainnet contract.
- M2: **V1 deploy.** Lets users issue *new* dMint tokens in the format
  the rest of the ecosystem (glyph-miner, RXinDexer, Photonic explorer)
  understands. Also closes the deploy footgun above by giving
  `prepare_dmint_deploy` a `version` parameter that defaults to V1.
- M3 (deferred): V2 deploy + V2 miner. Only worth doing when someone
  actually wants V2's DAA features (ASERT/LWMA dynamic difficulty). No
  live demand observed.

The original sequence ("V1 mint, then V2 deploy proof") assumed V2 was
the modern format to standardize on. Field check disagreed: V2 is the
*unproven* path, not the *current* path.

Rejected: a single combined PR (worse review surface) and
V1-mint-only-with-everything-else-deferred (leaves the deploy footgun
in place).

## Key Decisions

1. **Tool, not wallet.** pyrxd exposes protocol primitives. No UI, no
   hardware-wallet hooks, no daemon.

2. **V1 mint, then V1 deploy. V2 deferred indefinitely.** Three
   milestones; M3 (V2) is "if/when someone needs DAA features," not a
   committed roadmap item.

3. **Python reference miner + external shim.** A slow Python `mine_solution`
   ships for correctness and CI. The preimage byte layout is documented
   precisely so external miners (e.g. `glyph-miner`) can plug in. We do
   **not** bundle a fast miner.

4. **Acceptance bar = synthetic mainnet first, real mainnet second.** For
   each milestone:
   - Synthetic stage: deploy/mint a low-difficulty contract pyrxd controls,
     broadcast on mainnet, verify confirmation. This is the CI/dev gate.
   - Real stage: at least one mint against a live third-party contract
     (e.g. RBG) confirmed on-chain before declaring the milestone shipped.

5. **`testmempoolaccept` is a smoke check, not the bar.** It catches
   structural errors but does not exercise covenant verification.

6. **`docs/dmint-followup.md` gets rewritten in Milestone 2** as a
   how-dMint-works document, not future-work. The current framing is
   actively misleading.

## Milestone 1 Scope (V1 mint)

**Lands:**
- V1 path in `build_dmint_mint_tx` (or a sibling V1 builder)
- V1 preimage layout (4-byte nonce, scriptSig is `[nonce, inputHash, outputHash, OP_0]` per
  [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) §4)
- `pyrxd.glyph.dmint.mine_solution(...)` — pure-Python, returns nonce
- The preimage byte layout lives in code with comments explaining the wire
  shape — sufficient for external miners to interoperate. Not a separate
  spec deliverable.
- Synthetic mainnet integration test (deploy a low-diff V1 contract, mine
  it, broadcast, confirm)
- One real mint against a live V1 contract, manually verified

**Out of scope for Milestone 1:**
- V2 deploy live-network proof (Milestone 2)
- Fast miner / GPU support (always — that's `glyph-miner`'s job)
- EPOCH and SCHEDULE DAA modes (no observed contract uses them)

## Milestone 2 Scope (V1 deploy)

**Lands:**
- V1 builders in `pyrxd.glyph.dmint`: `build_dmint_v1_state_script`,
  `build_dmint_v1_code_script` (V1 epilogue with algo byte), and a V1
  `prepare_dmint_deploy` path
- `prepare_dmint_deploy` gains a `version: Literal["v1", "v2"] = "v1"`
  parameter. **Default flips to V1** because every live ecosystem tool
  expects V1. V2 callers must opt in explicitly.
- Live mainnet deploy of a fresh V1 dMint token end-to-end
- First mint against that V1 token using the Milestone 1 miner loop
- Cross-tool verification: confirm glyph-miner can mine the token we
  deployed (this is the real interoperability gate, not a pyrxd-talking-
  to-pyrxd round-trip)
- Rewrite of `docs/dmint-followup.md` as how-it-works
- Example `examples/dmint_deploy_demo.py` (V1)

**Out of scope for Milestone 2:**
- V2 deploy proof (deferred to M3, "if/when").
- A V1-source CashScript path. Photonic uses CashScript for V1 source;
  pyrxd hand-builds V1 hex from the documented byte template — no need
  to introduce a CashScript compiler dependency.

## Milestone 3 Scope (V2 deploy + V2 miner) — deferred indefinitely

Only revisit when one of these is true:
- Someone (Photonic, an indexer maintainer, a token issuer) actually
  wants V2's dynamic-difficulty features (ASERT or LWMA)
- The first V2 contract appears on mainnet from any source
- pyrxd users start asking for it

Until then, V2 code in `dmint.py` stays as latent
correctness-tested-but-unused. Periodic check: does V2 still parse
correctly under any glyph-miner / Photonic update? (Already covered
by existing parser tests.)

## Decisions Folded In From Review

**Real V1 target = RBG.** Per
[`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) §2.3,
RBG's contract has `maxHeight=628,328` with observed heights clustered
around 90,078 as of 2026-04-22. At ~14% mined with hundreds of thousands
of mints to go, it is unambiguously still active for the foreseeable
future. No chain query needed to confirm.

## Open Questions

1. **Mining time budget for CI.** The right max-iterations cap and
   target-difficulty for the synthetic test will be calibrated empirically
   once the Python miner exists. Plan should include a calibration step,
   not a guessed number.

2. **Preimage-layout source of truth.** The V1 layout is inferred from
   live tx + locking script per `docs/dmint-research-mainnet.md` §5.
   Read Photonic's `mine.ts` to confirm before building, or treat the
   live-tx evidence as sufficient and let a real-mint broadcast be the
   tiebreaker?

3. **Synthetic-mainnet test in CI or manual?** A test that broadcasts to
   mainnet costs RXD. Default assumption: manual / on-demand, not per-PR.
   Plan should make this explicit.

4. **Followup-doc rewrite timing.** Land the rewrite with Milestone 2, or
   add an "out of date — see code" warning at the top of
   `docs/dmint-followup.md` immediately to stop misleading readers?

## References

- [`docs/dmint-followup.md`](../dmint-followup.md) — stale; to be rewritten
- [`docs/dmint-research-photonic.md`](../dmint-research-photonic.md) — Photonic Wallet TS reference
- [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) — live V1 contract decode + mint trace
- [`src/pyrxd/glyph/dmint.py`](../../src/pyrxd/glyph/dmint.py) — current implementation
- [`src/pyrxd/glyph/builder.py:291`](../../src/pyrxd/glyph/builder.py#L291) — `prepare_dmint_deploy`
- External: the `glyph-miner` project — fast miner reference (not pyrxd)
