# Gravity swap — red-team audit (2026-05-24)

Four parallel adversarial agents, each owning a surface, each required to prove
exploits (not theorize). Findings below were **independently re-verified by me**
against the production code and/or the Radiant-Core consensus source
(Radiant-Core `src/script/interpreter.cpp`,
`src/validation.h`) — provenance noted per finding. "Proven-in-analysis" means
the mechanism is confirmed against source/compiled opcodes but was NOT executed
against a live covenant UTXO (the settled-swap UTXOs are spent; a live
`testmempoolaccept` of a theft tx needs a fresh funded covenant).

## CRITICAL findings

### C-PARSER-1 — On-chain output-scan: signed `scriptLen` rewinds `pos`, matching a forged payment planted in a scriptSig → asset stolen, maker paid nothing
**Severity: CRITICAL. Verdict: mechanism CONFIRMED against Radiant-Core source; executed in simulation + production-Python; NOT yet live-`testmempoolaccept`'d.**

The any-wallet output scan reads each output's script-length byte and advances
`pos = pos + 9 + sl` with **no range/sign guard on `sl`**.
- `int(...)` compiles to `OP_BIN2NUM` (interpreter.cpp `case OP_BIN2NUM`,
  `CScriptNum::MinimallyEncode` — **signed** sign-magnitude LE). A single
  length byte ≥ 0x80 (a *legal* Bitcoin scriptPubKey length of 128–252)
  decodes **negative**.
- The advance opcodes in the compiled artifact are `2b OP_PICK OP_9 OP_ADD
  OP_ADD` (and `OP_2 OP_PICK OP_9 OP_ADD OP_OVER OP_ADD`) — confirmed by
  reading `GravityNftCovenantAnyWallet20.artifact.json` asm — with **no**
  `OP_GREATERTHAN`/range check between the `OP_BIN2NUM` and the `OP_ADD`.
- A negative `sl` rewinds `pos` to a *smaller positive* value. The subsequent
  `OP_SPLIT` (interpreter.cpp:1439-1444: fails only if `position < 0 ||
  position > data.size()`) **succeeds** at the rewound positive offset → the
  next output-scan reads attacker-controlled bytes from an **input scriptSig**,
  where the attacker planted a fake `value|0x16|0x0014|<maker_pkh>` blob. `found`
  becomes true; the covenant releases the asset though no output pays the maker.

The Merkle/PoW binding is intact (the bytes must be a real mined tx) but the
attacker mines their own tx and fully controls its bytes. **This is asset
theft at the consensus/covenant level.**

**DELIVERY-COST CORRECTION (verified 2026-05-24, refines the agent's
"~zero cost" claim):** triggering the negative `sl` requires a scriptLen byte
≥ 0x80 → an **output script of 128–252 bytes**. Standard Bitcoin relay policy
**rejects** such outputs (bare-multisig max ~105 B; OP_RETURN cap 83 B), so the
exploit tx will **not propagate through normal relay**. Delivery therefore
requires getting a **non-standard tx mined** (direct-to-miner / tx-acceleration
services — a real, purchasable capability, but not a free walk-up). Net: the
attack is REAL and must be fixed, but the practical bar is "attacker with
non-standard-tx mining access," not "any taker for free." The input-skip parser
shares the identical signed-varint bug (`pos += 36+1+ssl+4`), but a single
negative `ssl` underflows `pos` to negative → `OP_SPLIT` fails (interpreter.cpp:
1440), so the single-input path self-rejects; the **output-scan** is the live
vector. Verified: faithful simulator (`rxd_sim.py`, validated against the real
settled payment → found=True AND the exploit tx → found=True) + Radiant-Core
`OP_BIN2NUM` (signed `CScriptNum::MinimallyEncode`) + `OP_SPLIT` bounds.
**PROVEN-AT-CONSENSUS** (sim + source); a live mainnet broadcast was declined
because it needs non-standard-tx mining (user decision 2026-05-24).

**Fix:** after each `sl` read, `require(sl == 22 || sl == 23 || sl == 25 ||
sl == 34)` (only the 4 valid output types are ever matched anyway), AND after
`require(found)` add `require(pos == rawTx.length - 4)` (assert the walk
consumed exactly to the 4-byte locktime — forbids any rewind/overlap). Apply
the same `require(ssl >= 0)` (or type-bounded) guard to the input-skip.
Source: `fuse_anywallet.py:40-48` (input skip) + `:89-92` (output advance),
compiled `GravityNftCovenantAnyWallet20.rxd` scan block.

### C-PARSER-2 — Production `SpvProofBuilder.build()` trusts a caller-supplied `output_offset`; never confirms it is output-aligned
**Severity: CRITICAL (defense-in-depth layer). Verdict: CONFIRMED by code read + executed through production Python.**

`verify_payment(raw_tx, output_offset, ...)` (`src/pyrxd/spv/payment.py:43-128`)
validates only the *structure* at the given offset (value/len/prefix/hash,
lines 72-128). It never parses the tx's output list to confirm `output_offset`
is the start of a real output. The 02-F-11 boundary check (line 74) guards
buffer bounds only. A caller can point `output_offset` into a scriptSig holding
a planted P2WPKH-shaped blob and `build()` returns a "valid" SpvProof for a tx
that pays the maker nothing. Same root cause as C-PARSER-1 (payment location
never proven to be an output), in the off-chain/SDK layer.

**Fix:** `verify_payment`/`build()` must self-parse inputs+outputs and require
the offset to equal an enumerated output boundary — or drop the offset arg and
scan outputs with the (fixed) C-PARSER-1 logic.

### C-ECON-1 — The documented "per-offer-derived btcReceiveHash (H1)" replay defense does not exist in code
**Severity: CRITICAL. Verdict: CONFIRMED by code read (absence).**

Every design doc + memory cites "per-offer derived btcReceiveHash (H1 binding)"
as the cross-offer replay defense. **It is not implemented.**
`build_gravity_offer(... btc_receive_hash: bytes ...)`
(`src/pyrxd/gravity/covenant.py:308`) takes the hash as a raw caller arg and
substitutes it verbatim (`covenant.py:395`). No BIP32/child/offer-index
derivation exists anywhere in `src/pyrxd/gravity/` or `btc_wallet/` (grep:
empty). The spike builders carry the tell: `# ... per-offer derived in prod`
(`build_fused_nft_spk.py:38`) — "in prod" is aspirational.

**Impact:** a BTC payment cannot reference a Radiant offer (Bitcoin has no
knowledge of Radiant). The covenant binds the payment only by
`btcReceiveHash` + `btcSatoshis` + `btcChainAnchor`. If a maker reuses the same
receive address + amount across two offers with overlapping anchor windows,
**one BTC payment + one SPV proof finalizes BOTH** — a taker pays once, takes
two assets (or a payment is double-counted). Conditional on address reuse, but
nothing prevents/detects it, and the docs assert the opposite.

**Fix:** real per-offer derived receive address committed in the offer, OR an
`OP_RETURN` offer-tag the covenant parses. Until then, correct the docs/memory
to state replay is UNMITIGATED + add a guard rejecting a reused live
`btc_receive_hash`. **Memory `feedback_gravity_anchor_timing` / swap-order
notes that imply H1 is real must be corrected.**

### C-NFT-1 — REF authenticity is never verified: the covenant binds an OUTPOINT, not a genuine minted NFT
**Severity: CRITICAL (counterparty trust). Verdict: CONFIRMED against Radiant-Core validation.h.**

Consensus (`validation.h:1044-1049`) auto-inserts every input's prevout outpoint
into `inputSingletonRefSet`; `validatePushRefRule` only requires
output-refs ⊆ input-refs; `OP_PUSHINPUTREFSINGLETON` (interpreter.cpp) only
size-checks + pushes. So a `d8<REF>` covenant where `REF` = the outpoint of
**any** input the maker spends at funding satisfies all ref rules — the
singleton need not be a genuinely-minted NFT. `build_fused_nft_spk.py:44` takes
an arbitrary CLI outpoint; `fund_nft_into_covenant.py` takes `NFT_SCRIPT_HEX` as
a trusted arg and never checks it reveals a real `gly` commit.

**Impact:** a malicious maker advertises a real one-of-one, funds the covenant
with a *fake* singleton (any outpoint), finalize settles correctly to the taker
— who pays BTC and receives a `d8<ref>…` output no Glyph indexer recognizes as
the advertised asset. The "one-of-one" guarantee is structural, not semantic.

**Fix:** off-chain — the taker MUST verify, before paying BTC, that `REF`
resolves on a trusted indexer to the genuine reveal of the advertised NFT
(genesis txid:vout, payload hash, `gly` marker). Not a script fix; currently
undocumented. The covenant cannot self-verify mint provenance.

## HIGH

### H-ECON-2 — On-chain covenant has no minimum-deadline floor; the 24h guard is app-layer + bypassable
The deployed covenant enforces only a static past-date floor (`claimDeadline >=
~2026-04-24`, decoded LE constant `e5beea69`). The 24h check is only in Python
(`types.py:82`, `covenant.py:275`, bypassable via `accept_short_deadline`). A
maker can deploy a near-deadline offer; a taker who pays BTC then can't reach
the 12-confirmation SPV maturity (~2h typical, ~6h at observed 30-min BTC gaps)
before the maker forfeits → taker loses BTC, gets no NFT. **Fix:** tie the
forfeit floor to the verified BTC header timestamps (anchor + maturity margin),
not a hardcoded date.

### H-NFT/ECON — Post-deadline finalize/forfeit race (winner-take-all for an NFT)
finalize has no upper time bound; after the deadline both routes are
simultaneously spendable (the known S1 race). For an indivisible NFT this is
winner-take-all decided by miners/fees. **Fix:** add a finalize-side
`tx.time < claimDeadline` CLTV so the two routes are mutually exclusive;
document a "finalize by deadline − N hours" taker rule.

## MEDIUM (pipeline fragility)

### M-FUSE-1 — `fuse_nft_covenant.py` route replacements have no post-assert that they fired
The Delta-3 (finalize) / Delta-4 (forfeit) `src.replace()` calls
(`fuse_nft_covenant.py:66-83`) silently no-op if the upstream generator's
indent/names drift. The existing asserts (`:89-94`) check banned tokens + that
ctor param NAMES exist — both pass vacuously even if a route's hash-compare was
silently dropped. A drifted forfeit route → unhardened maker reclaim that still
compiles. Mirror gap in `fuse_ft_covenant.py:52-79`. **Fix:** assert the new
route strings are present AND old route shapes absent.

### M-FUSE-2 — `validate_nft_covenant.py` is ref-parse-only; does not verify any hardening opcode
The guard asserts only "exactly one genesis singleton ref, all 0xd8". A
trivially-weak `d8<ref> OP_1` covenant PASSES it. Combined with M-FUSE-1, a
drifted unhardened covenant passes every automated guard. **Fix:** add an
opcode-level assertion over the compiled artifact (CLTV, refOutputCount==1,
value pin, both hash-compares present + branch-correct).

## DEFENSES PROVEN (held under attack)

- The **shipped** `GravityNftCovenantAnyWallet20` artifact is correctly
  hardened: pushInputRefSingleton, outputs.length==1, refOutputCount==1, value
  pin, both hash-compares branch-correct, CLTV present (decoded asm). No FT leak
  (no refValueSum / codeScriptHashValueSum / FT epilogue / bd-d0 weld).
- Phantom-ref machinery sound: the funded SPK decodes to exactly one ref
  (genesis singleton, 0xd8, offset 12); push-wrapping makes data-as-opcode
  impossible (11 fuzzed param cases + length-invariance all clean).
- 64-byte Merkle-forgery guard, hash256(stripped)==txid leaf binding, PoW/nBits,
  chain anchor + link, coinbase guard (Python path), the 5 existing negatives
  (burn/clone/wrong_dest/wrong_value/predeadline) — all hold.
- Branch selector (OP_0/OP_1) has no third path / no else-less fall-through;
  finalize hash-compare is OP_EQUALVERIFY (fail-stop), stack-clean.

## Bottom line

The mechanism (lock → SPV-gated release → forfeit) is sound and the shipped
covenant is correctly hardened — but **the BTC-payment parser has a
consensus-confirmed theft bug (C-PARSER-1)**, the **off-chain proof builder has
the same root-cause hole (C-PARSER-2)**, the **advertised replay defense is
vaporware (C-ECON-1)**, and **REF authenticity is a counterparty-trust gap
(C-NFT-1)**. None were caught by the prior 5-negative suite. All four are
fixable; C-PARSER-1 is the one that lets a taker steal outright and must gate
any further on-chain use. This is exactly why the external-audit gate existed —
the demo working on-chain did NOT mean the parser was safe.

## Fixes applied (2026-05-24)

| Finding | Status | Where |
|---|---|---|
| C-PARSER-1 (signed scriptLen rewind) | **FIXED + recompiled** | `fuse_anywallet.py`: per-output `require(sl>=0 && sl<=252)`, per-input `require(ssl>=0 && ssl<=252)`, terminal `require(pos == rawTx.length-4)`. Recompiled `GravityNftCovenantAnyWallet20` (guards confirmed in ASM). Regression: real payment accepts, exploit rejects at sl<0, change-first accepts. |
| C-PARSER-2 (unvalidated output_offset) | **FIXED + tested** | `spv/proof.py`: `_output_offsets()` self-parses the tx; `build()` requires the offset to be a real output boundary. 3 regression tests in `test_gravity_red_team.py`; 167 SPV tests green. |
| C-ECON-1 (H1 not implemented / replay) | **MITIGATED + docs corrected** | `covenant.py build_gravity_offer`: `used_btc_receive_hashes` reuse guard + prominent warning. Design/plan docs corrected to state H1 was never implemented. Full per-offer derivation remains a design follow-up. |
| M-FUSE-1 (silent transform no-op) | **FIXED** | route-fired post-asserts in `fuse_nft_covenant.py` + `fuse_ft_covenant.py`. |
| M-FUSE-2 (vacuous validator) | **FIXED** | `validate_nft_covenant.py` now asserts all hardening opcodes (+ C-PARSER-1 guards) present in the compiled covenant. |

## Follow-ups REQUIRED before any production / mainnet-product claim

These are design / off-chain / governance items not closable by a covenant patch alone:

1. **C-NFT-1 (REF authenticity):** the taker's off-chain flow MUST verify, before
   paying BTC, that the covenant's `REF` resolves on a trusted indexer to the
   genuine reveal of the advertised NFT (genesis txid:vout, payload hash, `gly`
   marker). The covenant cannot self-verify mint provenance. Currently
   undocumented in the taker flow — add it.
2. **C-ECON-1 (full fix):** implement real per-offer derived BTC receive
   addresses (committed in the offer) or an `OP_RETURN` offer-tag the covenant
   parses, so a BTC payment is offer-specific. The reuse guard is only
   best-effort.
3. **H-ECON-2 (deadline floor):** replace the hardcoded past-date covenant floor
   with an anchor-relative floor (`claimDeadline >= anchor_block_time +
   maturity_margin`) using the header timestamps the covenant already verifies,
   so a taker who pays BTC always has time to reach the 12-confirmation SPV
   window before forfeit.
4. **H (finalize/forfeit race):** consider a finalize-side `tx.time <
   claimDeadline` so the two routes are mutually exclusive; document a
   "finalize by deadline − N hours" taker rule.
5. **External audit** of the (now-fixed) parser + SPV path remains the hard gate.
   This red-team is internal; an independent audit should re-confirm the fixes
   and look for what four agents + one reviewer still missed.
