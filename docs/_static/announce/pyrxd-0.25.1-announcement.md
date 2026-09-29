**pyrxd 0.25.1** — HashMark records from the command line, plus fixes to wallet scanning and token listing.

**`pyrxd mark <file>`** publishes a HashMark record: the file's digest, your key's hash160 and a signature over both. The file stays on your machine. **`pyrxd verify <txid> --min-confirmations N`** checks one: who signed it, whether a file matches, and whether the block is buried deep enough. The 0.25.1 wheel itself is marked on mainnet in block 468521, check it in the browser: https://mudwoodlabs.github.io/pyrxd/verify/?input=aa66b04662aa5514ed7d0027ff3cbd608d73f3e2b92d4129d810eb576bc0c86e

**Fixed:**
• A wallet made with `pyrxd wallet new` could not spend until something had scanned it, and nothing saved that scan. Every spend path now scans first, and `balance`, `glyph list` and `utxos` do too.
• `glyph list` looked tokens up under the owner's plain script hash; Radiant's indexer files them under the token script with its refs zeroed. It now reads the right place, and takes each token's owner and amount from the transaction rather than the server's listing.
• `pyrxd address` no longer hands out an address that has been paid, and sends through pyrxd's ElectrumX client check the txid the server echoes back.
• The ETH swap leg's deadline check had an off-by-one and ignored the claim's inclusion time. The effect was a stalled swap that refunds, not a loss.

0.25.0 (also in this release line) builds WAVE claims in the shape the indexer registers and pays the registration fee by default.

Upgrade note: `balance`, `glyph list`, `utxos` and `address` exit 2 when an address can't be read, and a mismatched broadcast echo raises `BroadcastEchoMismatch`; see the notes.

The swap and gravity stacks remain experimental and unaudited.

https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.25.1
