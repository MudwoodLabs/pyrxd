This release fixes two bugs that made core commands useless on mainnet: a wallet made with `pyrxd wallet new` could not spend what it was sent, and `pyrxd glyph list` found no tokens on a real server. It also fixes an off-by-one in the ETH swap leg's deadline check, `pyrxd address` handing out an address that had already been paid, and wallet sends that trusted the txid a server echoed back. **Some changes are visible to scripts.** Read the last section if you parse the exit code or `--json` output of `balance`, `glyph list`, `utxos`, `address` or `verify`, catch `NetworkError` around a broadcast, or call `collect_spendable` or `GlyphScanner`.

## A `pyrxd wallet new` wallet can spend (#759)

Spend commands, `utxos`, `balance` and `glyph list` read only the addresses a gap-limit scan had marked used. Only `wallet send` and `balance --refresh` ran that scan, and nothing saved it. A funded new wallet had nothing to spend: `pyrxd mark` told a wallet holding 100 RXD to "fund this wallet", and `balance` showed 0. Every one of these commands now runs the scan first. The scan is not saved, so the wallet file is unchanged. `glyph resume-mint` can also reveal a new wallet's interrupted commit.

This resolves the known issue in 0.25.0's notes: **`pyrxd mark` now works from a `wallet new` wallet.**

## `glyph list` finds tokens (#782)

`GlyphScanner` read the address's P2PKH script hash. A Radiant ElectrumX lists a token output under its script with every ref zeroed, not there, so `glyph list` found nothing on a real server. Measured on one mainnet address: 0 tokens before the fix, 246 after. `glyph list` now also takes a token's owner and an FT's amount from the transaction the server serves, not from the server's listing, and refuses a listing that transaction contradicts.

Still open: an address that has only ever received tokens, and no plain RXD, is not found by the scan (#787).

## Also in this release

- **ETH↔RXD swaps:** `assert_eth_deadline_is_claimable` accepted a deadline one second too close, and left out the 96 s the maker's claim guard needs to get its claim mined (#791). The effect was liveness, not loss: the swap could be funded, but the maker's claim was then refused before it was broadcast, so the preimage stayed secret and both legs refunded after their timeouts.
- **`pyrxd address`** no longer hands out an address that has been paid plain RXD (#781).
- **Broadcast echo:** `HdWallet.send`/`send_max` and `RxdWallet.send`/`send_max` returned whatever txid the server echoed. Every broadcast through a pyrxd client now checks the echo against the transaction it sent (#780).
- **`pyrxd mark`** shows non-ASCII blank characters in a label as `<U+XXXX>` in the confirmation (#747).
- **`pyrxd verify`** accepts `<txid>:<n>` and a contract id, and says what the named output is (#745).
- **`glyph inspect`** reads the 65-byte hash-lock commit seen under mainnet DAT reveals (#751).
- **The `/inspect/` and `/verify/` pages** no longer load Pyodide's end-of-life OpenSSL; the block hash is computed by a pure-Python SHA-512/256 (#757).
- **`--allow-overpay`** is deprecated on `mark`, `glyph transfer-nft` and `glyph timelock-reveal`, where it never had an effect. Scripts that pass it keep working (#793).

## Breaking changes

- **`balance`, `glyph list` and `utxos`** exit 2 when any address cannot be read, and print nothing in `--json` or `--quiet`. `utxos` used to list the partial view and exit 0.
- **`address`** now reads the chain, and exits 2 with no address if the scan fails. `--index N` still reads nothing.
- **Broadcast echo mismatch** raises `BroadcastEchoMismatch` (the failover client raised `NetworkError`), which `except NetworkError` does not catch. In the CLI it exits 1. It now stops `mint-nft`, `deploy-ft` and `deploy-dmint` rather than warning and continuing.
- **`verify <txid>:<n>`** and a contract id, which 0.25.0 refused with exit 1, now get the transaction's verdict. One naming an output the transaction does not have still exits 1, with no verdict in any output mode.
- **`GlyphScanner`** reads tokens at different script hashes, takes FT amounts from the transaction, and with `strict=True` raises `ServerInconsistencyError` or `NetworkError` where it used to leave an item out.
- **`HdWallet.collect_spendable`** is strict by default: a failed per-address read raises `NetworkError` instead of returning a short list.
- **`glyph inspect`** classifies the 65-byte commit as `commit-dat`, where it read `not-a-commit`. An outpoint's output index must be ASCII digits. `NetworkProfile` raises `ValidationError`, not `ValueError`, for a malformed IPv6 URL.

The full list is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
