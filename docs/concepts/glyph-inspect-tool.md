# Glyph inspect tool: structural match, not semantic correctness

**Why this page exists:** when you paste a Radiant txid, contract id,
outpoint, or raw script hex into something called an "inspector," the
natural assumption is that a green check mark means the bytes are
*correct* — that the FT will spend, the dMint contract will mint, the
NFT actually exists. The pyrxd inspect tool does **not** make that
claim. It is an offline structural-match classifier: it tells you
which on-chain *shape* a script or transaction matches, and every
output is qualified to make the trust boundary explicit. This page
explains what the tool does, what the qualifier rules out, and what
the two delivery variants (CLI and browser) actually run.

---

## What the tool does

You hand it one of four inputs:

| Input form     | Example                                                              | Needs network? |
|----------------|----------------------------------------------------------------------|----------------|
| Hex script     | `76a914aaaa…aaaa88ac`                                                | no             |
| Contract id    | `b45dc453…a2a800000000` (72 hex chars: 32-byte txid + 4-byte vout)   | no             |
| Outpoint       | `b45dc453…a2a8:0`                                                    | no (`--resolve` to fetch source tx) |
| Txid           | 64 hex chars                                                         | yes (`--fetch`) |

It runs the bytes through the structural classifier in
[`src/pyrxd/glyph/_inspect_core.py`](../../src/pyrxd/glyph/_inspect_core.py)
and returns one of the recognised shapes: `ft`, `nft`, `mut`, `dmint`,
`commit-ft`, `commit-nft`, `op_return`, `p2pkh`, or `unknown`. For a
fetched transaction it adds a tx-shape banner (e.g. "this is a V1 dMint
deploy commit", "this is a dMint claim at height 41/625000") and, when
`vin[0]` is a dMint mint claim, decodes the 4 canonical scriptSig
pushes.

Both variants share the same Python classifier — there is exactly one
implementation. The browser variant loads that same code into Pyodide
and runs it client-side.

---

## The two variants

### CLI: `pyrxd glyph inspect`

Implementation in
[`src/pyrxd/cli/glyph_cmds.py`](../../src/pyrxd/cli/glyph_cmds.py)
(the `inspect_cmd` Click command, with helpers re-imported from
`pyrxd.glyph._inspect_core` so the CLI module owns presentation only,
not classification logic).

```
$ pyrxd glyph inspect 76a914aaaa…aaaa88ac
$ pyrxd glyph inspect b45dc453…a2a8:0
$ pyrxd glyph inspect <txid> --fetch          # network call to ElectrumX
$ pyrxd glyph inspect <txid:vout> --resolve   # fetch source tx, classify that vout
```

The CLI is read-only by design: no broadcast, no wallet load, no
mnemonic prompt. Pass `--json` (or pipe stdout) for machine output;
the `--json` schema is documented in the command's docstring and is
stable across patch releases.

### Browser: Pyodide-hosted at `/inspect/`

The static page at
<https://mudwoodlabs.github.io/pyrxd/inspect/> loads the **same
Python code** into Pyodide and runs the entire classifier in-browser.
Source lives in the repo at `docs/inspect_static/inspect/` —
`index.html` is the page shell, `inspect.js` is the boot + DOM glue,
`glue.py` runs inside Pyodide and calls into `pyrxd.glyph.inspect`.

What runs server-side: nothing. GitHub Pages serves static bytes;
there is no application backend. ElectrumX is only contacted for the
`txid` auto-fetch path, and that connection is a direct WebSocket
from the browser to a single hard-coded server pinned in the page's
Content-Security-Policy `connect-src`.

No key material is ever loaded. No transactions are ever signed or
broadcast. The page is a diagnostic, not a wallet.

---

## The trust boundary

Structural match does not equal protocol-semantic correctness. Every
classified output is qualified to spell out what the pattern match
does *not* verify.

For example, the FT/NFT qualifier from the CLI's
[`_render_script_human`](../../src/pyrxd/cli/glyph_cmds.py):

> structural pattern match: bytes match the FT/NFT script template;
> does NOT verify the ref points to a valid Glyph contract

And for dMint contracts:

> structural pattern match; does NOT verify the contract_ref points
> to a valid mint chain or that the parameters match a deployed token

Concretely, things `inspect` will tell you and things it will NOT
tell you:

| The tool says…                                                              | …which means                                                                                                | …but it does NOT say                                                                                  |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `type=ft, ref=b45dc4…:0`                                                     | The 75-byte script matches the FT template, with the conservation fingerprint `dec0e9aa76e378e4a269e69d` at the tail. | That a transfer spending this UTXO will satisfy the FT covenant's input/output balance check at broadcast. |
| `type=dmint, version=v1, height=41/625000, reward=50000`                     | The 241-byte script matches the V1 dMint contract layout; those numbers were pushed onto the stack.         | That the parameters match the deployed token's CBOR metadata, that anyone has successfully mined from this contract, or that the contract is the head of its mint chain. |
| `type=commit-ft, payload_hash=…`                                             | The script matches the commit-ft hashlock template.                                                         | That a reveal tx exists or that the CBOR behind the hashlock decodes to anything valid.                 |
| Tx-shape banner: "V1 dMint deploy commit"                                    | The tx outputs match the commit shape: one commit-ft, one commit-nft, N P2PKH ref-seeds, change.            | That a successful reveal followed, that the deployer broadcast valid CBOR, or that any mining will happen. |
| Tx-shape banner: "dMint claim at height 41/625000"                           | `vin[0]` carries a 4-push scriptSig matching V1/V2 mint shape and the spent contract advanced its height.   | That the on-chain covenant *accepted* this spend — the covenant has runtime conditions (PoW, FT conservation, reward output shape) the byte-level classifier cannot evaluate without re-executing the script. |

The boundary is intentional. `inspect` reads bytes; it does not
execute scripts and it does not contact an indexer. If you need
"this UTXO is *really* the head of this mint chain" or "this FT
output will be accepted by the network when spent," that's a
different tool.

---

## Tx-shape banner

For a fetched transaction, the inspect tool emits a one-paragraph
banner describing what *kind* of transaction the user is looking at,
based on the per-output classification plus a few input-side
heuristics. The browser variant emits these in
[`docs/inspect_static/inspect/inspect.js`](../../docs/inspect_static/inspect/inspect.js).

Recognised shapes:

| Shape                          | Trigger                                                                                                                          |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| **FT deploy**                  | One `commit-ft` output paired with at least one FT or NFT singleton — the on-chain event that brings a fungible token into existence. |
| **NFT deploy**                 | A `commit-nft` output without a paired `commit-ft`.                                                                              |
| **V1 dMint deploy commit**     | One `commit-ft` + one `commit-nft` + ≥3 P2PKH ref-seed outputs. The mainnet Glyph Protocol deploy commit was 1+1+32+1 outputs.   |
| **V1 dMint deploy reveal**     | Two or more `dmint` contract outputs of the V1 shape, sharing one `token_ref`. Mainnet GLYPH had 32 parallel contracts in one reveal. |
| **dMint claim**                | A `dmint` output whose `contract_ref` matches the spent input and whose `height` is non-zero, paired with a V1/V2 mint scriptSig at `vin[0]`. |
| **Glyph burn**                 | A reveal whose CBOR metadata signals burn intent; the protocol does not transfer the burned ref forward.                          |
| **Mutable contract update**    | A `mut` output whose script template matches and whose `payload_hash` is the commitment to off-chain CBOR.                        |

Plain RXD sends and ordinary transfers render with no banner — the
absence of a banner is itself a signal that the transaction is not a
Glyph protocol event.

A note on V2: pyrxd's classifier recognises V2 dMint contract shapes
and the 8-byte-nonce V2 mint scriptSig, but **no V2 dMint contracts
exist on Radiant mainnet today**. Every live dMint deploy and claim
the tool has classified in the wild is V1. The V2 paths are exercised
only by synthetic tests; pre-mainnet-V2 the 0.5.0 audit caught a V2
reward-output bug (R1) that would have rejected every V2 mint at the
network layer (see the 0.5.0 CHANGELOG entry).

---

## V1 mint scriptSig decode

When `vin[0]` of a fetched transaction matches the dMint mint claim
shape, the inspect tool decodes the four canonical pushes:

| Push    | Field         | Width                                  |
|--------:|---------------|----------------------------------------|
| 1       | nonce (LE)    | **4 bytes = V1**, **8 bytes = V2**     |
| 2       | input hash    | 32 bytes — `SHA256d(funding_script)`   |
| 3       | output hash   | 32 bytes — `SHA256d(OP_RETURN_script)` |
| 4       | OP_0          | 1 byte                                 |

The version is distinguished by nonce width: a 4-byte nonce (V1) gives
a 72-byte scriptSig; an 8-byte nonce (V2) gives 76 bytes. The two
hashes are **literal `SHA256d` outputs**, not preimage halves — this
distinction is load-bearing because the M1 release shipped with the
preimage halves pushed instead of the SHA256d outputs, and every
on-chain mine was rejected by the covenant until the fix landed at
mainnet txid
`c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
(see the 0.5.0 CHANGELOG entry and the related solutions doc on the
M1 V1 mint scriptSig divergence).

The inspect tool surfaces all four pushes plus the inferred version
hint, so a reader can verify by eye that a mint claim's scriptSig
matches the convention.

---

## OP_RETURN data carriers

OP_RETURN outputs are classified explicitly with `type=op_return` and
the trailing data bytes are split out from the leading `0x6a` opcode
into a separate `data_hex` field. This is a cosmetic but useful
separation: a reader scanning a dMint claim sees that `vout[2]` is
the OP_RETURN message script the mint covenant hashes (and whose
`SHA256d` appears in the scriptSig at `vin[0]`), without having to
manually strip the opcode prefix.

The OP_RETURN classifier does not interpret the payload — it does
not assume CBOR, ASCII, protocol-tag prefixes, or anything else.
If a reader needs to know what the bytes mean, they decode them
out-of-band.

---

## Browser variant: install-time integrity

The browser inspector is served from GitHub Pages. The page bytes
themselves are trust-on-first-use from the user's perspective, but
everything the page *loads at runtime* is integrity-checked:

| Artifact                       | Source                          | Verification                                |
|--------------------------------|---------------------------------|---------------------------------------------|
| Pyodide loader (`pyodide.js`)  | jsdelivr CDN                    | Subresource Integrity (SHA-384) on the `<script>` tag |
| `pyrxd` wheel                  | same-origin (`/inspect/wheels/`) | SHA-256 verified against `manifest.json` before `micropip.install` |
| Vendored `cbor2==5.4.6` wheel  | same-origin (`/inspect/wheels/`) | SHA-256 verified against `manifest.json` before `micropip.install` |
| `glue.py` (Python bootstrap)   | same-origin                     | SHA-256 verified against `manifest.json` before evaluation |
| Pyodide runtime packages (`micropip`, `pycryptodome`) | jsdelivr CDN (Pyodide-managed) | served via Pyodide's own integrity-checked package index |

If any SHA-256 mismatches the manifest, the install aborts loudly
with an error citing the mismatch — the tool does not fall through to
"try without the integrity check." The verification code is in
[`docs/inspect_static/inspect/inspect.js`](../../docs/inspect_static/inspect/inspect.js)
(`fetchAndVerify`).

The page's Content-Security-Policy denies PyPI as a script source.
`micropip.install(..., deps=False)` is used for the pyrxd wheel so no
transitive PyPI metadata fetch happens during bootstrap. The cbor2
wheel is pinned to `5.4.6` because cbor2 6.x ships C-only and a
Pyodide install that depends on a PyPI fetch creates an off-origin
trust path the same-origin SHA-256 approach is designed to avoid.

The manifest itself is loaded same-origin and its fields are
validated before they're consumed: `manifest.wheel` and
`manifest.cbor2_wheel` must be bare basenames (no `/`, no `..`,
no URL-encoded separators), and every SHA-256 field must be exactly
64 lowercase hex characters. A poisoned manifest cannot redirect a
wheel install to a different origin or skip the integrity check by
supplying a malformed hash.

---

## Why share one classifier across CLI and browser

The CLI and browser variants both import from
[`pyrxd.glyph.inspect`](../../src/pyrxd/glyph/inspect.py) — the
public façade — which re-exports helpers from
`pyrxd.glyph._inspect_core`. That core module is deliberately pure:
no `click`, no `aiohttp`, no `websockets`, no `coincurve`,
no `Cryptodome.Cipher`. Importing it under Pyodide does not drag
heavy dependencies that don't exist in the WASM runtime. This
property is asserted by a test
(`tests/web/test_inspect_imports_pyodide_clean.py`).

The split means a change to the classifier is a change to *one* file
that both variants pick up. Bug-for-bug parity between CLI and
browser is structural, not a sync chore.

---

## Footguns the tool guards against

1. **"It's classified, so it must be correct."** Every classified
   output carries a structural-match qualifier. The CLI prints it in
   parentheses below the per-script body; the browser shows it as a
   `structural-note` paragraph. The qualifier is not optional and not
   suppressible — the trust boundary is part of the output, not
   metadata for the user to discover.

2. **"It looks like a V2 dMint contract on mainnet."** The
   classifier recognises V2 shapes for forward-compatibility, but no
   V2 dMint contract has been deployed on Radiant mainnet to date.
   The tx-shape banner for a V2 claim says so explicitly. If you
   paste a V2-shaped contract and see `version=v2` in the output,
   that is a synthetic input or a future deploy — it is not a
   mainnet token to date.

3. **Hostile manifests, poisoned wheels, and CDN compromise.** The
   browser variant treats every install artifact as untrusted bytes
   until verified. SHA-256 mismatch aborts loudly; basename
   validation rejects path traversal; SRI on the loader catches a
   jsdelivr compromise before WASM ever runs. The CSP forbids
   `script-src` from anywhere other than the page itself and the
   pinned jsdelivr origin.

4. **Spoofed token names in CBOR metadata.** Reveal-tx metadata
   strings are sanitised through `sanitize_display_string`
   (strips Unicode control / format / combining codepoints) and
   capped via `truncate_for_human`. Token names and tickers are run
   through the TR39 confusables skeleton check
   (`looks_confusable_with_latin`) — a Cyrillic-spoofed "USDC" is
   flagged with a warning banner before the user sees the rendered
   metadata.

5. **OP_RETURN ambiguity.** Data carriers are classified as
   `op_return` with the data split out, not silently grouped with
   "unknown" scripts. A reader looking at a dMint claim can see at a
   glance that the OP_RETURN at `vout[2]` is the message script
   whose hash appears in the scriptSig.

---

## Source-of-truth references

- **Classifier core.**
  [`src/pyrxd/glyph/_inspect_core.py`](../../src/pyrxd/glyph/_inspect_core.py)
  (private; pure-Python, no heavy deps)
- **Public façade.**
  [`src/pyrxd/glyph/inspect.py`](../../src/pyrxd/glyph/inspect.py)
- **CLI command.**
  [`src/pyrxd/cli/glyph_cmds.py`](../../src/pyrxd/cli/glyph_cmds.py)
  (the `inspect_cmd` Click command and renderers)
- **Browser host.**
  [`docs/inspect_static/inspect/index.html`](../../docs/inspect_static/inspect/index.html),
  [`docs/inspect_static/inspect/inspect.js`](../../docs/inspect_static/inspect/inspect.js),
  [`docs/inspect_static/inspect/glue.py`](../../docs/inspect_static/inspect/glue.py)
- **CHANGELOG entries.** 0.4.0 (Glyph inspect — CLI / browser) and
  0.5.0 (V1 mint scriptSig parsing, V1 deploy detection) in the
  repository's `CHANGELOG.md`.
- **Related concept.**
  [Radiant FTs are on-chain (not metadata-on-P2PKH)](radiant-fts-are-on-chain.md)
  — what the 75-byte FT shape the inspector matches actually means at
  the consensus layer.
