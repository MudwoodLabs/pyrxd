# How to troubleshoot common errors

**Who this page is for:** you ran a `pyrxd` command (or called the library
directly) and got an error, or a symptom that looks like an error but isn't
one (a balance that's silently wrong). This page maps concrete error text
and symptoms to a cause and a one-line fix. It is not a full API or
exception reference — for that, read the cited source files directly.

Every entry below quotes a real string found in the pyrxd source at the time
of writing, with a file and line citation. Where a plausible-sounding error
doesn't actually exist in the code, this page says so rather than inventing
one — grep the source yourself if a string here looks stale; line numbers
drift as the codebase changes.

---

## How pyrxd reports errors

Every CLI-level failure is a `CliError` (a `click.ClickException` subclass)
with up to three parts — a one-line `message`, a `cause` (what went wrong,
sensitive values redacted), and a `fix` (a concrete next step). `format_message`
renders them as:

```
error: <message>
  cause: <cause>
  fix: <fix>
```

— [`src/pyrxd/cli/errors.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/errors.py)

The exit code tells you which family the error is from, before you even read
the text:

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | user error (bad input, missing file, insufficient funds) |
| `2` | network error (couldn't reach ElectrumX, broadcast rejected) |
| `3` | wallet decryption failed |
| `4` | unexpected error (a bug — should not happen; file an issue) |

Pass `--debug` to any command to also print the underlying Python traceback
(no captured local variables — just function names, line numbers, and source
lines, the same exposure as any uncaught exception).

Library code (used directly, outside the CLI) raises typed exceptions from
`pyrxd.security.errors` instead — `ValidationError`, `NetworkError`,
`KeyMaterialError`, and so on. The CLI wraps those into the three-line
`CliError` block above; the entries below give you both forms where they
differ.

---

## 1. Zero balance after restoring a wallet (no error at all)

**Symptom:** you restore a mnemonic, `pyrxd balance` shows `0`, but a block
explorer shows the address holding funds — except it's *not* the address
your wallet derived, because the funds landed on a different BIP44 path.

**Cause:** the Radiant ecosystem never agreed on a BIP44 `coin_type`, so the
same seed produces different addresses depending on which wallet derived it:

| coin_type | Used by |
|---|---|
| `0`   | Photonic ≤ v2.x (legacy), Electron-Radiant, Chainbow |
| `512` | SLIP-0044 spec, Tangem, Photonic ≥ v3.0.0 (pyrxd's default) |
| `236` | pre-#14 pyrxd (BSV's coin type) |

See the module docstring in
[`src/pyrxd/hd/discovery.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/discovery.py)
for the full explanation and `DEFAULT_COIN_TYPES = (0, 512, 236)`.

**Fix:** `pyrxd wallet recover --scan` — scans every coin-type/account
combination and reports which path actually holds funds. Full walkthrough,
including `wallet sweep` to move the funds once found:
[Recover funds across wallet paths](recover-funds-across-wallet-paths.md).

---

## 2. Wallet won't decrypt after upgrading pyrxd (non-ASCII passphrase)

**Symptom:** a wallet file created before **pyrxd 0.11.3** with a
**non-ASCII BIP39 passphrase** (accents, umlauts, CJK — anything beyond
plain ASCII) now fails to decrypt, even though you're certain the mnemonic
and passphrase are correct.

**What you actually see at the CLI:** every wallet-opening command (`balance`,
`utxos`, any `glyph` or `wallet` subcommand that decrypts the wallet file)
funnels a decrypt failure through the same generic block, exit code 3:

```
error: Could not decrypt wallet file
  cause: wrong mnemonic, wrong passphrase, or wallet file is corrupt
  fix: check the mnemonic and passphrase exactly, then try again
```

— `WalletDecryptError`'s default message
([`src/pyrxd/cli/errors.py:120-125`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/errors.py)).
**Verified:** the CLI's wallet loader deliberately discards the library's
more specific decrypt-failure message (which, called directly, includes an
NFKD hint pointing at this exact cause) and always re-raises this generic
text —
[`src/pyrxd/cli/prompts.py:166-174`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/prompts.py)
and
[`src/pyrxd/cli/wallet_cmds.py:192-200`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/wallet_cmds.py)
both do this on purpose (never echo the user's input back). So at the CLI,
this generic message is the *only* symptom you get — nothing on-screen
mentions NFKD or normalization.

**Cause:** BIP39 requires the mnemonic and passphrase to be NFKD-normalized
before they enter PBKDF2. pyrxd versions before 0.11.3 skipped that step, so
a non-ASCII passphrase could derive a different seed than the spec requires
— and the wallet file's AES-GCM key is derived from that seed, so a file
saved under the old seed only decrypts by reproducing it.

**Fix:** the escape hatch is `normalize=False`, reachable from
`HdWallet.load`, `load_or_create`, `from_mnemonic`, the `bip32_*`/`bip44_*`
derivation helpers, and `pyrxd.hd.discover` — but **not** exposed as a CLI
flag, so this recovery is library-only. Full recipe (how to tell if you're
affected, and how to sweep funds off the legacy seed permanently) is the
"Non-ASCII passphrases" section of
[Recover funds across wallet paths](recover-funds-across-wallet-paths.md).

---

## 3. "no single UTXO is large enough to fund the mint / deploy"

**Symptom, verbatim** (one of three, depending on command):

```
error: no single UTXO is large enough to fund the mint
error: no single UTXO is large enough to fund the deploy
error: no single UTXO is large enough to fund the dMint deploy
```

From `glyph mint-nft`
([`src/pyrxd/cli/glyph_cmds.py:297`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py)),
`glyph deploy-ft`
([`:551`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py)),
and `glyph deploy-dmint`
([`:1350`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py))
respectively. The `cause` line names the exact shortfall (`need ≥ N photons
in one UTXO; largest is M`).

**Cause:** the commit/deploy builder needs **one single UTXO** that covers
the commit value plus both the commit's own fee estimate and slack for the
reveal — it does not combine multiple smaller UTXOs for this step.

**Fix (all three, same text):** `consolidate UTXOs first, or fund the wallet
from a single source`.

---

## 4. "commit value cannot cover the reveal fee" (reveal too big to pay for itself)

**Symptom, verbatim** (from `glyph mint-nft` and `glyph deploy-ft`):

```
error: commit value cannot cover the reveal fee — refusing to broadcast the commit
  cause: commit value cannot fund the reveal: <N> photons available, <M> required
         (<carrier> carrier + <fee> reveal fee for a <size>-byte reveal carrying
         <cbor> bytes of CBOR at <rate> photons/byte) — short by <shortfall>
  fix: shrink the metadata (the reveal scriptSig carries the whole CBOR payload) or lower --fee-rate
```

— [`src/pyrxd/cli/glyph_cmds.py:239-258`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py)
wraps the library's `InsufficientFundsError` from
[`check_reveal_funding`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/fees.py)
(`src/pyrxd/glyph/fees.py:208-241`).

**Cause:** the reveal transaction's scriptSig carries the **entire CBOR
metadata payload**, so a large `metadata.json` (a long image URL, several
attributes) makes the reveal itself big — and therefore its own fee, which
is paid entirely out of the commit output. `check_reveal_funding` computes
the real fee (via the same `SatoshisPerKilobyte.compute_fee` the actual
transaction uses, so it can't drift) and refuses **before** the commit is
broadcast if the commit can't cover it. Without this guard, the failure
would happen after the commit was already on-chain, stranding it — see the
module docstring in `fees.py` for the history.

**Fix:** shrink the metadata (drop a long image URL, trim attributes), or
raise the effective fee-model headroom. **Note:** the `--fee-rate` mentioned
in the fix text is **not an actual flag** on `mint-nft` or `deploy-ft` —
verified: neither command declares a `--fee-rate` option
([`src/pyrxd/cli/glyph_cmds.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py)).
The real lever is the global fee rate, set via `fee_rate` in
`~/.pyrxd/config.toml` or the `PYRXD_FEE_RATE` environment variable (photons
per byte; default `10000`) — see
[`src/pyrxd/cli/config.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/config.py).
In practice, shrinking the metadata is the more useful fix, since fee rate
is a network-relay floor, not something you generally want lower.

**Scope:** this pre-broadcast guard runs for `glyph mint-nft` and `glyph
deploy-ft`. `glyph deploy-dmint` sizes its commit differently (multiple
contract ref-seeds, not a single reveal-fee-vs-carrier trade) and does not
call this same check.

---

## 5. Insufficient funds on `glyph claim-dmint`

Two distinct failures, both from `glyph claim-dmint`:

**a) No funding UTXO found at all** — verbatim:

```
error: could not find a plain-RXD funding UTXO for the mint
  cause: <InvalidFundingUtxoError text>
  fix: fund <miner_address> with >= <needed> photons of plain RXD, or pass --reward-address
```

— [`src/pyrxd/cli/glyph_cmds.py:1818-1825`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py).
`needed = contract.reward + 10_000_000 + 546` photons — the reward, a fee
buffer, and dust for the change output. This scans for a UTXO that is
**plain RXD only** (token-bearing UTXOs at the same address are excluded).

**b) A funding UTXO exists but is too small** — the library's
`PoolTooSmallError`, verbatim message shape:

```
funding_utxo (<value> photons) too small to cover reward (<reward>) + fee (<fee>):
change would be <change> photons, below 546 dust limit.
```

— [`src/pyrxd/glyph/dmint/miner.py:1241`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/miner.py)
and
[`:1475`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/miner.py)
(the V1 and V2 mining paths). The CLI reframes any `DmintError` from mining
as:

```
error: funding can't cover the mint reward + fee
  cause: <PoolTooSmallError text>
  fix: fund the reward address with more plain RXD, or lower --fee-rate
```

— [`src/pyrxd/cli/glyph_cmds.py:1737-1742`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py).
Same caveat as item 4: `claim-dmint` has no `--fee-rate` flag either
(verified) — the fix is really "fund more RXD," or lower the global fee rate
via config/env.

**Fix:** fund the reward/miner address (`--reward-address`, or the wallet
address with the largest UTXO by default) with more plain RXD.

---

## 6. The node rejected your broadcast

[Broadcast a transaction](broadcast-a-transaction.md) already documents the
four rejection symptoms you'll actually hit, in its "Handling broadcast
errors" section — `bad-txns-inputs-missingorspent`, `txn-mempool-conflict`,
`min relay fee not met`, `mandatory-script-verify-flag-failed` — read that
page for what each one means and how to recover. This section
covers **what pyrxd actually raises today**, which is more specific than
that page's "generic `NetworkError`, diagnose by on-chain symptom" framing.

**Current behavior (verified):** `ElectrumXClient` now classifies a node's
JSON-RPC error. If the error code is one of `{1, -25, -26, -27}` (the codes
ElectrumX/bitcoind use for "the node evaluated your tx and said no"), or the
sanitized reason matches a known reject-reason marker (`bad-txns-`,
`txn-mempool-conflict`, `min relay fee not met`,
`mandatory-script-verify-flag-failed`, `dust`, `non-final`, and others — see
`_POLICY_MESSAGE_MARKERS`), it raises the typed `PolicyRejection` instead of
a bare `NetworkError`:

```python
from pyrxd.security.errors import PolicyRejection, NetworkError

try:
    txid = await client.broadcast(raw_tx)
except PolicyRejection as exc:
    print(exc.code, exc.reason)   # e.g. -26, "bad-txns-inputs-missingorspent"
except NetworkError:
    ...  # a genuine transport fault (dropped socket, timeout, etc.)
```

— [`src/pyrxd/network/electrumx.py:83-175`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py).
`PolicyRejection` is a subclass of both `NetworkError` and `CovenantError`,
so existing `except NetworkError` handlers still catch it. The node's
rejection reason is sanitized (first line only, control characters
stripped, long tokens redacted, clipped to 200 chars) but **is** attached to
the exception via `.reason` — it is the one deliberate carve-out from
pyrxd's "never embed server text in an exception" rule, because discarding
it previously hid a real covenant-rejection bug for weeks. All four
rejections named in the broadcast-a-transaction.md table match a marker
above, so all four **are** distinguishable via `exc.reason` — you no longer
need to inspect the block explorer or turn on `DEBUG` logging to tell them
apart.

**Fix:** catch `PolicyRejection` specifically and branch on `.reason`; fall
back to the broadcast-a-transaction.md symptom table for what each reason
means.

---

## 7. Can't reach ElectrumX, or requests keep timing out

Three real strings from `ElectrumXClient`:

- `"Failed to connect to any ElectrumX server"` —
  [`src/pyrxd/network/electrumx.py:635`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py):
  every server in your URL list failed to connect. Check the URL(s), your
  network, and that the server is up.
- `"ElectrumX connection lost"` —
  [`:717`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py):
  the WebSocket dropped mid-session; all pending requests fail with this.
  Reconnect (a fresh `ElectrumXClient` / `async with` block).
- `"ElectrumX request timed out"` (or `"... (send)"`) —
  [`:766, :771`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py):
  a single RPC call exceeded its timeout. Retry, or pass a longer timeout if
  the server is just slow.

**A different shape you'll see during commit→reveal waits:** `glyph
mint-nft`, `deploy-ft`, and `deploy-dmint` all poll for the commit tx's
confirmation before broadcasting the reveal, via
`pyrxd.network.confirm.wait_for_confirmation`
([`src/pyrxd/network/confirm.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/confirm.py)).
This poller **swallows** any `NetworkError` from an individual poll and
keeps retrying — right after a broadcast, the tx is routinely not yet
visible to the server, and that's expected, not fatal. It remembers the
*last* such error and names it in the eventual timeout message, so a
persistently broken transport is still diagnosable instead of a bare "gave
up." At the CLI, a poll that never confirms surfaces as:

```
error: timed out waiting for confirmation
  cause: tx has <N> confirmations, required <M> (timeout (last poll error: <text>))
  fix: check the txid on a block explorer. Not confirmed: nothing is stranded — re-run the
       command. Confirmed: this CLI has no resume flag, so rebuild the reveal with the SDK …
```

— [`src/pyrxd/cli/glyph_cmds.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py),
exit code 2. **Fix:** check the commit txid on a block explorer.

- **It never confirmed.** Nothing was spent that you cannot re-spend. Re-run
  the command.
- **It confirmed.** There is no `--resume` flag and no `COMMIT_TXID`
  environment variable in this CLI — earlier versions of this page and of the
  error hint said otherwise, and were wrong. (`COMMIT_TXID` is read by the
  standalone `examples/*.py` demo scripts, which carry their own hard-coded
  metadata and cannot resume a CLI mint.) Recover through the SDK instead:

  ```python
  from pyrxd.glyph.builder import GlyphBuilder, RevealParams
  from pyrxd.glyph.payload import encode_payload

  cbor_bytes, _payload_hash = encode_payload(metadata)   # the SAME metadata file, unmodified
  scripts = GlyphBuilder().prepare_reveal(
      RevealParams(
          commit_txid=commit_txid,      # from the explorer
          commit_vout=0,
          commit_value=commit_value,    # the commit output's value
          cbor_bytes=cbor_bytes,
          owner_pkh=owner_pkh,          # the minting wallet's PKH
          is_nft=True,                  # False for an FT deploy
      )
  )
  ```

  Then build the reveal transaction spending `commit_txid:0` with
  `scripts.scriptsig_suffix` appended to a normal P2PKH unlock — see
  `examples/glyph_mint_demo.py` for the shape.

  **The metadata file must be byte-identical.** The commit output's script is
  `OP_HASH256 <payload_hash> OP_EQUALVERIFY …` before its P2PKH tail, so it can
  only ever be spent by a reveal that pushes CBOR hashing to that exact
  `payload_hash`. Re-encoding an edited metadata file produces a different hash
  and the output becomes unspendable — there is no owner-only escape path.

---

## 8. dMint v2 flags and premine

**`--daa-mode` requires `--v2`**, verbatim:

```
error: --daa-mode requires --v2 (V1 dMint is FIXED difficulty only)
```

— [`src/pyrxd/cli/glyph_cmds.py:1244`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py).
V1 dMint contracts are fixed-difficulty only; a difficulty-adjustment mode
(`fixed`/`asert`/`lwma`/`epoch`/`schedule`) only makes sense on a V2
contract. **Fix:** add `--v2` to `glyph deploy-dmint`, or drop `--daa-mode`.

**The historical V2 opt-out is now a non-blocking warning, not an error.**
Verified in
[`src/pyrxd/glyph/builder.py:453-480`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/builder.py):
calling `prepare_dmint_deploy` with `allow_v2_deploy=False` on
`DmintV2DeployParams` used to refuse; as of 0.9.0 (V2 consensus-proven on
regtest + mainnet, #219) it only emits a `UserWarning`:

```
prepare_dmint_deploy was called with allow_v2_deploy=False for a
DmintV2DeployParams; V2 deploy is no longer blocked (consensus-proven
on regtest + mainnet, #219) and proceeds anyway. Drop the
allow_v2_deploy=False argument to silence this warning.
```

This only matters if you're calling `GlyphBuilder.prepare_dmint_deploy`
directly with that argument — the CLI's `glyph deploy-dmint` doesn't expose
`allow_v2_deploy` and always deploys V2 when `--v2` is passed.

**Premine is deferred for both V1 and V2 dMint deploys.** Two
`ValidationError`s, both verbatim:

```
V1 deploy with premine is deferred work — see docs/dmint-research-photonic-deploy.md §7.2. Set premine_amount=None for now.
```
```
V2 deploy with premine is deferred work (mirrors V1). Set premine_amount=None for now.
```

— [`src/pyrxd/glyph/builder.py:376-381`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/builder.py)
and
[`:481-484`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/builder.py).
**Fix:** dMint tokens deploy with no premine today (`premine_amount=None`);
this is a permissionless-mining-only feature until premine support ships.

---

## 9. "My FT shows up as plain RXD" (no error — a real gap)

**Symptom:** you hold a Glyph FT (or NFT), but `pyrxd balance` counts its
value as ordinary RXD, and `pyrxd utxos` lists its UTXO like any other,
with no indication it's a token carrier.

**There is no error string for this** — it's an honest gap, not a bug that
raises anything. Verified: `balance_cmd` sums `client.get_balance(...)`
across every used address's raw scripthash
([`src/pyrxd/cli/query_cmds.py:97-145`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/query_cmds.py)),
and `utxos_cmd` lists whatever `wallet.collect_spendable(client)` returns
([`:148-196`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/query_cmds.py),
backed by
[`HdWallet.collect_spendable`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/wallet.py)
at `src/pyrxd/hd/wallet.py:938-970`). Neither path decodes the locking
script to check whether it's a Glyph FT/NFT envelope versus plain P2PKH —
both just report the UTXO's raw `value` field from ElectrumX. A Glyph
carrier's photon value (the 546-dust NFT carrier, or an FT's premined
supply amount) gets counted exactly like spendable RXD, which it is
**not** — spending it as a plain-RXD input burns the token.

**Fix:** `pyrxd glyph list --type ft` (or `--type nft`, or `--type all`) —
[`src/pyrxd/cli/glyph_cmds.py:1042-1053`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/glyph_cmds.py) —
scans wallet addresses and decodes the Glyph envelope, so token holdings
show up as tokens, separate from the plain-RXD balance. Use this whenever
you need to know what's actually spendable versus what's a token carrier.

---

## References

- [`src/pyrxd/cli/errors.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/cli/errors.py) — the `CliError` format and exit-code convention
- [`src/pyrxd/security/errors.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/security/errors.py) — the library's typed exception hierarchy
- [Recover funds across wallet paths](recover-funds-across-wallet-paths.md) — coin-type scanning and the non-ASCII passphrase / NFKD recovery recipe
- [Broadcast a transaction](broadcast-a-transaction.md) — the four common node-rejection symptoms
