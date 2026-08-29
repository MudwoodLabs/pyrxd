An ERC-20 counter leg, an installable `[eth]` extra, and a deploy receipt we should never have trusted.

## The `[eth]` extra never existed

`pip install 'pyrxd[eth]'` did not work, and had not since the ETH code landed. Five separate runtime errors told users to "install the eth extra" while `pyproject.toml` had **no `[project.optional-dependencies]` section at all**. pip warned *"does not provide the extra 'eth'"*, installed nothing, and the next import failed by instructing the user to do the thing that had just silently no-opped.

`web3` was declared only in the `test` dependency-group, so a library consumer had no supported path to the ETH stack at all. `eth-keys` and `eth-account` are now declared rather than inherited transitively from `web3`, and the aiohttp error no longer points at an extra — aiohttp is a required runtime dependency and was never optional.

This is the least interesting bug in the release and probably the one that cost real people the most time.

## A deploy receipt decided where the swap's ETH went

The native ETH leg took its HTLC contract address from `receipt["contractAddress"]`. `wait_receipt` is primary-endpoint-only by design, so **one RPC endpoint chose the address holding the entire counter leg**, and every downstream check still passed — the ETH really was at the address it named. Verifying the code there does not help either: an attacker deploys the same bytecode and holds the claim key.

A CREATE address is `keccak(rlp([sender, nonce]))[12:]`. Both inputs belong to the deployer, so this was never something to be *told*. `create_address()` derives it, cross-checks what the receipt reported, and refuses on any disagreement — no second endpoint, no trust.

**This defect is present in v0.20.0 and earlier.** Reaching it requires the primary endpoint to be malicious or compromised, which is the threat model the multi-source quorum layer exists for.

The same defect had already been found and fixed on the token leg. It was fixed **only where it had been demonstrated**, and the native leg — the one that has carried real value — kept it. A finding gives you coordinates; the fix belongs to the class.

## A transient RPC failure destroyed the preimage

`maker_claims_btc` zeroized `p` in a `finally`, on **every** exit — including failures where nothing had been broadcast, such as a chain-id assertion or a fee read. That destroyed the only copy of a still-secret preimage and left both parties waiting out their timelocks, over a blip a retry would have survived.

The legs now mark the submit boundary with `PreRevealAbort` — a promise about *where* a failure happened, not why — and the coordinator zeroizes on everything else. Past that boundary `p` may already be public, and a genuine freeze refusal means the swap cannot complete anyway. Pre-existing on the native leg; the ERC-20 leg's extra pre-reveal reads made it far likelier to fire.

## The token leg refused accounts their owners hold the keys to

`verify_funded` rejected any claimant or refundee carrying contract code, because a native ETH send *executes* the recipient's code and a recipient that reverts on receive would lock the funds. An **EIP-7702 delegated EOA** carries 23 bytes of code (`0xef0100` + delegate) and is an ordinary account the user holds the key to. Both anvil dev addresses carry one on mainnet today, so this is a live population, not a hypothetical.

The restriction is meaningless for the token leg, whose payout calls the **token** contract and never the recipient, so it opts out. The native default is unchanged, and its refusal message now names EIP-7702 when that is what it found, rather than claiming "not an EOA" about an address that is one.

A guard that refuses honest work is a defect, not a safe default.

## USDC: same protocol, different guarantee

RXD/Glyph ↔ USDC uses the same HTLC protocol as RXD ↔ ETH and **does not carry the same guarantee**. Native ETH is held by the EVM. USDC is held by a contract whose issuer can freeze addresses.

Measured on a mainnet fork against the real contract: freezing the **HTLC itself** makes `claim` *and* `refund` revert **permanently**, with no timeout to rescue the funds. Mitigations are per-swap contracts (a freeze loses one swap, not all), a pre-reveal blacklist gate inside `claim`, and a deliberately short funded window. **None of them is a fix.** The residual is accepted, documented, and must travel with any user-facing description of the corridor.

Funding is a push, not a pull: deploy, then a plain `transfer`. A payable constructor cannot pull a token, so no allowance is ever created — the approve race, the dangling allowance and the reset-to-zero dance all disappear together.

Token addresses are pinned per chain id from the issuer's own list and **never resolved by symbol**. Bridged `USDC.e` on Arbitrum and Optimism, Arbitrum's omnichain `USDT0`, and BNB Smart Chain's Binance-Peg `USDC` are refused by address, each named for what it is. The BSC one is also 18 decimals where Circle's USDC is 6 everywhere, so symbol resolution would be a wrong-issuer error and a 10^12 scale error at once.

`Erc20HtlcLeg` is a subclass, not a fork: **zero lines change in the native leg**, and `claim`, `refund`, `fetch_claim_artifacts`, `assert_claim_provenance`, `is_final` and `claim_finality_verdict` are inherited unchanged. Secret recovery needs no token-specific code at all.

## Unit conflations are type errors now

Two confirmed defects in this codebase had the same shape: two quantities that are both non-negative `int`, semantically incompatible, meeting in a field that could hold either. The mainnet shim stored a confirmation depth in `UtxoRecord.height`, which inverted the covenant lookup's earliest-confirmed anti-poisoning rule into a poison-*selecting* one.

`ChainHeight`, `Confirmations`, `PhotonValue`, `BlockSpan` and `Seconds` are `NewType` tags — zero runtime cost, no validation, no behaviour change — applied to the producers and the gates. A test suite runs mypy over fixtures reproducing each real defect and proves the checker rejects it, and that the corrected form still passes.

`task typecheck` also gates now. Its declared scope had been reporting 295 errors across 40 transitively-imported modules, so `task ci` was failing at that step rather than checking anything.

## A mechanism that manufactured its own evidence

A fourth pair was tagged the same way and it was wrong.

An issue reported that a Glyph FT's token count could be conflated with its carrier's photon value. `TokenUnits` and `PhotonValue` were made **incompatible** types on the strength of it. mypy then produced genuine-looking `arg-type` errors on **correct code**, and those errors were read as confirming the defect. A fix making FT swaps fail closed was written, tested and reviewed before anyone asked the plain question.

On Radiant, an FT's quantity **is** its output's photon value — 1 photon = 1 token unit, enforced by `OP_REFVALUESUM_OUTPUTS` summing each ref-bearing output's `nValue`. The distinction does not exist on the chain. The correct model was in-tree the whole time, in `glyph/ft.py`, citing the exact interpreter line, in a module nobody in that review thread opened.

The loop is the part worth keeping: the issue asserted it → a branch wrote the assertion into a docstring → the type work encoded it → mypy emitted real errors on correct code → reviewers cited the docstring and the errors as corroboration. Three reviewers agreeing meant three reviewers reading the same wrong sentence, one the review process had itself written.

`TokenUnits` is now a **subtype** of `PhotonValue`, so the intent survives while an FT amount flows into a photon slot, because it is one. **Before encoding a distinction in the type system, verify it against the layer that enforces it. A wrong invariant does not fail loudly — it gets enforced.**

No FT swap behaviour changed in this release. The gate was correct before and is correct now.

## Still true

The swap stack remains **unaudited**. An external audit is a hard gate before it is used with real value. The USDC corridor carries the issuer-freeze residual above on top of that, and it is not something an audit removes.
