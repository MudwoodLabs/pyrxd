This release fixes a signature-encoding defect that shipped in **every version since 0.2.0**, and changes one constructor's behaviour in a way that can break downstream callers. Read the second section if you build `GlyphRef` from your own data.

## `sign(k=...)` emitted DER a Radiant node cannot accept

`_sign_custom_k` carried a private second copy of the DER encoder that wrote `r` and `s` as fixed 32-byte integers with no `lstrip(b"\x00")`. DER forbids a leading zero byte that is not needed to keep the integer positive, so below 2²⁴⁷ — roughly 1 signature in 171 — the encoding is non-minimal. Radiant applies `SCRIPT_VERIFY_STRICTENC`, mandatory under FORKID, so such a signature is not merely unusual: **it cannot confirm**.

Measured against this project's own strict decoder: **14 of 2,000** signatures rejected before the fix, **0 of 2,000** after. Two independent re-measurements agree.

The rate understates it for the one production caller. `RPuzzle.unlock` pins `k`, which pins `r` — so for the affected fraction of puzzles, **every** unlock a released pyrxd builds is node-rejected, and retrying cannot help because nothing about the retry changes `r`. The `s` half varies with the transaction and is retryable; the `r` half is not.

**If you never call `sign(k=...)`, you were never affected.** `Transaction.sign()` — the CLI, the wallet, every glyph mint and commit/reveal, the swap legs — takes the libsecp256k1 path with RFC 6979 nonces, which produces minimal DER and normalises low-s itself. Exactly one line in `src/` passes a custom `k`, and nothing in `src/` calls `RPuzzle`.

The correct encoder was already imported into the same module. The fix deletes the duplicate rather than patching it.

## Breaking: `GlyphRef` refuses a txid its own type refuses

`GlyphRef.txid` is annotated `Txid`, which requires 64 **lowercase** hex characters — but a dataclass does not enforce an annotation at runtime, so a raw `str` skipped validation entirely.

The consequence was a silent identity fork, not a crash: an uppercase txid produced a ref whose `to_bytes()` is **byte-identical** to the lowercase one while `==` and `hash()` differ. Set membership and every `ref == other` check saw two different tokens where consensus sees one.

**Upgrading.** Nothing inside pyrxd changes. The break is for callers who build a `GlyphRef` from their own data — an indexer response, a stored record, user input — where a txid may arrive uppercase. `prepare_*_reveal`, `build_reveal_outputs` and `build_htlc_covenant_ft/nft` all take a `str` txid and now raise `ValidationError` where they previously succeeded. Lowercase at your boundary.

## Minting into a collection stripped the container's covenant

`prepare_container_child_reveal` rebuilt the container from a pubkey hash, so an authority-gated, mutable or soulbound container came back as a plain 63-byte NFT — same ref, covenant gone — in the one transaction whose purpose is to leave it untouched. Re-gating needs the issuer, so a holder could not undo it.

This was the third instance of one defect. The other two were fixed at the site, which is why this one stayed invisible; the class is now enumerated by an AST guard rather than patched a fourth time.

## A delegated authorship claim could be forged

`verify_relationship_claims` honoured caller-supplied delegate refs whenever *some* delegate burn existed, never checking that the burned base was the one those refs came from. A reveal burning an unrelated base returned `ok=True, basis=DELEGATED` — under a reason sentence asserting a fact the code had not established. A self-minted base costs nothing.

`glyph inspect --fetch` was correct only by accident, because it pools resolutions per transaction. An indexer caching them across transactions got a forgeable verdict. Refs are now bound to their originating base.

## Release path

Publishing previously ran no test between a tag and PyPI, and a tag can point at any commit. A `verify` job now refuses a commit that is not an ancestor of `main` and runs lint, typecheck and the suite before anything is built.

Also in this release: `verify_burn`'s verdict now states what it does **not** establish — it binds no transaction, and for a fungible token an `ok` verdict means the spent output's units are gone, not the supply. Delegate-bound commits are now visible on both the CLI and the browser inspect page.
