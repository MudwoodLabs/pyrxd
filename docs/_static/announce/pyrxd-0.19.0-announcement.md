**pyrxd 0.19.0** — one object for minting and moving Glyph tokens, plus the fund-safety work that came out of reviewing it seven times.

**`GlyphClient`** composes minting and transfers behind one object. NFT transfers are importable for the first time: the old builder spends the singleton alone and takes the fee from its own value, so it refuses any carrier under ~2,330,546 photons — every ordinary dust-carrying NFT. The new path keeps the singleton intact and funds the fee separately.

**Broadcast txids are no longer taken on trust.** `broadcast` returns whatever the node says, and the reply was only format-checked — a lying server could drop a transaction, echo a real confirmed txid, and have the caller believe a transfer happened that did not. Every fund-moving path now derives the txid from the bytes it signed.

**A fee ceiling was unreachable on the only path that mattered.** Measured on a stored rate carrying a per-kB figure in a per-byte field: a reveal paid 2,600,000,000 photons (26 RXD) on a 260-byte transaction, no refusal, no warning.

**Two destinations were unpinned** — `transfer-nft`'s recipient, and `deploy-ft --treasury`, which receives the entire premined supply. A wrong-network address decodes into a valid-looking PKH and locks tokens to a script no local key can spend.

Reviewed by an 8-reviewer panel, then seven adversarial rounds. Every round found a defect introduced by the previous round's fixes, two of which moved funds. Every new test was verified by planting the defect, watching it fail, and restoring.

9,241 tests pass. CI also went from 39/34/8 minutes across the Python matrix to 8.3/7.8/6.7.

The swap and gravity stacks remain experimental and unaudited.

https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.19.0
