**pyrxd 0.25.0** — WAVE claims in the shape the indexer registers, the protocol's registration fee paid by default, and HashMark records published and checked from the command line.

**WAVE names built from a qualified name never registered.** `build_wave_metadata` put `alice.rxd` in `attrs.name`; RXinDexer registers from `attrs.name` and refuses the dot, so it skipped the claim without an error. The reveal confirmed, the fee was spent, the name never resolved. Claims now use Photonic's field set, and one label rule — 3–63 characters of `a-z 0-9 -`, domain `rxd` — is checked before the commit, not after it.

**Registering pays the WAVE fee by default:** 100 to 5 RXD by length, paid to the protocol treasury from a wallet input in the reveal itself. A mint interrupted after its commit saves a record first, and `pyrxd glyph resume-mint` finishes it.

**Some dMint contracts pyrxd deployed could never be minted.** The builders are fixed; for contracts already deployed that way, `claim-dmint` now says so instead of grinding.

**`pyrxd mark <file>` publishes a HashMark record:** the file is hashed on your machine and never goes on chain; the record holds its digest, your key's hash160, a signature over both and an optional label. `--dry-run` shows the record and sends nothing.

**`pyrxd verify <txid> --min-confirmations N`** checks one: who signed it, whether a file matches it, whether a WAVE name pointed at the key at the mark's block, and whether the block is buried deep enough. Also in the browser: https://mudwoodlabs.github.io/pyrxd/verify/

Upgrade note: WAVE labels, the reveal builders' fee output, `judge_name_at_mark`, `verify_attestation` and `PendingStore` change for callers; see the notes.

The swap and gravity stacks remain experimental and unaudited.

https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.25.0
