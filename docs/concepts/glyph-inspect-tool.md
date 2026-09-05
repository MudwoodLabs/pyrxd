# Glyph inspect tool: structural match, not semantic correctness

**Why this page exists:** when you paste a Radiant txid, contract id,
outpoint, or raw script hex into something called an "inspector," the
natural assumption is that a green check mark means the bytes are
*correct* — that the FT will spend, the dMint contract will mint, the
NFT actually exists. The pyrxd inspect tool does **not** make that
claim. It is a structural-match classifier: it tells you which
on-chain *shape* a script or transaction matches, and most shapes come
with a qualifier making the trust boundary explicit. This page explains
what the tool does, what the qualifier rules out, which shapes and
surfaces are missing one, and what the two delivery variants (CLI and
browser) actually run.

---

## What the tool does

You hand it one of four inputs:

| Input form     | Example                                                              | Needs network? |
|----------------|----------------------------------------------------------------------|----------------|
| Hex script     | `76a914aaaa…aaaa88ac`                                                | no             |
| Contract id    | `b45dc453…a2a800000000` (72 hex chars: 32-byte txid + 4-byte vout)   | no             |
| Outpoint       | `b45dc453…a2a8:0`                                                    | no (`--resolve` to fetch source tx) |
| Txid           | 64 hex chars                                                         | yes (`--fetch`) |

A 32-byte locking script is also 64 hex, and one real shape lands there: a CLTV
time-lock whose deadline is a wall-clock time (every Unix deadline from 1985 to
2038 encodes as a 4-byte push, giving a 32-byte script). Those are the
wall-clock HTLC refund legs, so 64 hex that parses as an **exact** CLTV/CSV
P2PKH template is read as a script rather than a txid. The preference is
deliberately narrow: it runs the production template parser, which pins the
P2PKH tail, the `OP_DROP`, the time-lock opcode and a minimal value push, so a
real txid cannot fall into it by accident.

It runs the bytes through the structural classifier in
[`src/pyrxd/glyph/_inspect_core.py`](../../src/pyrxd/glyph/_inspect_core.py)
and returns one of the recognised shapes. The page keeps a single list
of them, under "Two classifiers: script-level and envelope-level"
below. For a fetched transaction it also decodes the 4 canonical
scriptSig pushes when `vin[0]` is a dMint mint claim.

The tx-shape banner (e.g. "this is a V1 dMint deploy commit", "this is
a dMint claim at height 41/625000") is **browser-only**. It is computed
in `inspect.js` from the classified outputs plus the reveal metadata;
nothing in the Python classifier produces one, and
`pyrxd glyph inspect --fetch` prints no equivalent in either human or
`--json` mode.

Both variants share the same Python classifier — there is exactly one
implementation. The browser variant loads that same code into Pyodide
and runs it client-side.

---

## The two variants

### CLI: `pyrxd glyph inspect`

Implementation in
[`src/pyrxd/cli/glyph_inspect.py`](../../src/pyrxd/cli/glyph_inspect.py)
(the `inspect_cmd` Click command and its renderers, with helpers
re-imported from `pyrxd.glyph._inspect_core` so the CLI module owns
presentation only, not classification logic). `glyph_cmds.py` only
attaches it to the group — `glyph_group.add_command(inspect_cmd)` —
and re-exports the name.

```
$ pyrxd glyph inspect 76a914aaaa…aaaa88ac
$ pyrxd glyph inspect b45dc453…a2a8:0
$ pyrxd glyph inspect <txid> --fetch          # network call to ElectrumX
$ pyrxd glyph inspect <txid:vout> --resolve   # fetch source tx, classify that vout
$ pyrxd glyph inspect <op_return hex> --verify-wave   # names a verified HashMark signer owns
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

Structural match does not equal protocol-semantic correctness. Most
classified shapes carry a qualifier spelling out what the pattern match
does *not* verify — but not all of them, and not on every surface. The
exact coverage is in "Footguns the tool guards against" §1 below; read
it before relying on the qualifier's presence as a safety net.

For example, the FT/NFT qualifier from the CLI's
[`_render_script_human`](../../src/pyrxd/cli/glyph_inspect.py):

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
| Tx-shape banner: "V1 dMint deploy commit"                                    | The output *counts* match the commit shape: at least one commit-ft, at least one commit-nft, and at least three P2PKH outputs (change plus the ref-seeds). | That a successful reveal followed, that the deployer broadcast valid CBOR, or that any mining will happen. Nor that those P2PKH outputs really are 1-photon ref-seeds — the banner counts them, it never reads their values. |
| Tx-shape banner: "dMint claim at height 41/625000"                           | Some output classified as `dmint` and carries a non-zero `height`; the two numbers in the sentence are read off that one output. | That the on-chain covenant *accepted* this spend — the covenant has runtime conditions (PoW, FT conservation, reward output shape) the byte-level classifier cannot evaluate without re-executing the script. Nor that `vin[0]` spent *this* contract: the banner never compares `contract_ref` against the inputs, and the mint scriptSig at `vin[0]` only adds a trailing sentence when one happens to be present. |
| `type=soulbound-covenant, variant=fixed-index`                               | The bytes are an **exact** round-trip against pyrxd's soulbound covenant builder for the reported ref and owner. The only spends the lock permits are a byte-identical self-clone or a burn. | That the bound ref names a live Glyph singleton, that the singleton is actually held at this output, or that the covenant is free of defects — it is a pre-external-audit prototype. |
| `type=self-replicating-covenant`                                             | The script binds a singleton ref **and** contains a self-replication-or-burn structure.                     | That it is a soulbound token. Container and vault covenants self-replicate too, and these bytes match no covenant pyrxd builds. This tier is markers, not identification. |
| `type=p2pkh-csv, locktime_units=144, locktime_basis=blocks`                   | The script is `<144> OP_CHECKSEQUENCEVERIFY OP_DROP <P2PKH>`; the encoded relative delay is 144 blocks from this output's confirmation. | Whether the delay has elapsed — that needs this output's confirmation height, which a locking script does not carry. |
| `type=unknown, token_bearing=true`                                           | No classifier claims the shape, but the opcode-aware walk found OP_PUSHINPUTREF-family refs in it.          | What the script does. It says only that spending this UTXO as plain funding would destroy the token it carries. `token_bearing=null` means the script did not decode, so the *absence* of a ref was never proven either. |

The boundary is intentional. `inspect` reads bytes; it does not
execute scripts, and no *classification* is ever taken from a server —
no ref chain is walked, no contract is resolved, no type comes back
from an index.

That is not the same as "no network." Three paths do talk to an
ElectrumX server, which is an indexer: `--fetch` and `--resolve` issue
`blockchain.transaction.get` to obtain the raw transaction, and the
CLI's `--verify-wave` issues a lookup for the WAVE names a verified
HashMark signer owns. The browser variant does the same fetch over a
WebSocket to the single server pinned in the page's CSP `connect-src`.
The server hands over bytes; every verdict is then computed locally
from those bytes. If you need "this UTXO is *really* the head of this
mint chain" or "this FT output will be accepted by the network when
spent," that's a different tool.

---

## Two classifiers: script-level and envelope-level

`inspect` runs **two** independent classifiers, and confusing them
sends people hunting for byte patterns that cannot exist.

**Script-level** — reads a locking script and reports a `type`. This
is what you get from `pyrxd glyph inspect <hex>`, and what fills each
row of the `outputs[]` list on a fetched transaction. Every value
`_inspect_core` can emit:

`p2pkh`, `p2pkh-cltv`, `p2pkh-csv`, `p2sh`, `nft`, `ft`, `mut`,
`commit-nft`, `commit-ft`, `dmint`, `container-legacy`,
`delegate-token`, `delegate-burn`,
`soulbound-covenant`, `self-replicating-covenant`, `op_return`,
`op_return-msg`, `op_return-hashmark-v1`, `op_return-hashmark-v2`,
`unknown`.

Plus one that only ever appears in a fetched transaction's `outputs[]`
row, never from a pasted script: `error`, when classifying that one
output raised. The row keeps its `vout` and `satoshis`, and the `error`
field is the exception's class name and nothing more. The remaining
rows are unaffected, which is the point of the per-output `try`.

`delegate-token` and `delegate-burn` are the two halves of a delegate,
which is how a token's `in`/`by` claim can be authorised without the
minter holding the parent singleton. A `delegate-token` output is the
**same 63 bytes as `nft`**, differing only in the opcode (`0xd0`
`OP_PUSHINPUTREF` rather than `0xd8` `OP_PUSHINPUTREFSINGLETON`), so
anything classifying by length alone gets it wrong; it is token-bearing
either way, and spending one as ordinary funding destroys it. A
`delegate-burn` is the unspendable 42-byte marker a mint emits to prove
it consumed one.

Both name a **base** ref, not a container or author ref. The base is
where the authorisation actually lives, and the inspector cannot follow
it from the transaction in front of it — resolving a delegated claim
means fetching the base transaction, which `glyph inspect --fetch`
does and a pasted script cannot. A relationship that reads
`UNRESOLVED` alongside a `delegate_burns` entry means exactly that: the
lookup did not happen, **not** that the claim was forged.

The three `op_return-*` values are refinements of `op_return`, added
when the data carrier self-identifies (see "OP_RETURN data carriers"
below). Treat the prefix, not the exact string, as the stable part: a
consumer switching on `type == "op_return"` will miss them.

**Envelope-level** — reads the CBOR payload out of the reveal
transaction's scriptSig and reports the highest-specificity Glyph
protocol label under `metadata.classification`. It sees: `wave`,
`container`, `authority`, `timelock`, `encrypted`, `dmint`, `mut`,
`dat`, `ft`, `nft`, and `unknown` when the envelope claims no protocol
the classifier knows. This only appears on the fetched-transaction
forms (`--fetch`, and `--resolve` on an outpoint), because there is no
envelope to read without the reveal transaction.

The distinction that trips people:

- A **TIMELOCK token** and an **ENCRYPTED token** are envelope-level
  only. Their protocol flags live in the CBOR; their locking script is
  an ordinary NFT/MUT singleton. There is no script pattern to detect,
  so no amount of staring at the scriptPubKey will find one.
- `p2pkh-cltv` / `p2pkh-csv` are script-level, and are **unrelated** to
  the TIMELOCK protocol. They are plain BIP-65 / BIP-112 time-locked
  P2PKH outputs — in this codebase, most often an HTLC refund leg.
- A "soulbound" NFT can be either. `policy.transferable: false` in the
  envelope is **advisory** — a flag an honest wallet may choose to
  respect and any other wallet ignores. Only the script-level
  `soulbound-covenant` type reflects a restriction consensus enforces.
  A token can carry the metadata flag with a plain `nft` locking
  script, and that combination restricts nothing.

---

## Tx-shape banner

For a fetched transaction, the **browser** variant emits a
one-paragraph banner describing what *kind* of transaction the user is
looking at. It lives entirely in `_detectTxShape` in
[`docs/inspect_static/inspect/inspect.js`](../../docs/inspect_static/inspect/inspect.js);
the CLI has no equivalent, in human or `--json` mode.

Two things to hold onto before reading the table. First, `_detectTxShape`
returns on its **first** match, so the order below is the order it tries —
a transaction that would satisfy two rows gets the earlier one. Second,
apart from the reveal-metadata protocol markers, every trigger is a count
over the *classified output types* and nothing else: the function never
reads an output's value, never compares a `contract_ref` against the
inputs, and never looks at `vin[]` at all.

Recognised shapes, in evaluation order:

| # | Shape | Trigger |
|--:|-------|---------|
| 1 | **Glyph burn** | The reveal metadata's `protocol` list names BURN (`6`). |
| 2 | **CONTAINER** | `protocol` names CONTAINER (`7`). Collection envelope; the locking script is an ordinary NFT singleton. |
| 3 | **ENCRYPTED** | `protocol` names ENCRYPTED (`8`). |
| 4 | **TIMELOCK** | `protocol` names TIMELOCK (`9`). |
| 5 | **AUTHORITY** | `protocol` names AUTHORITY (`10`). |
| 6 | **WAVE** | `protocol` names WAVE (`11`). |
| 7 | **DAT** | `protocol` names DAT (`3`). |
| 8 | **V1 dMint deploy commit** | At least one `commit-ft` **and** at least one `commit-nft` **and** at least three `p2pkh` outputs. The mainnet Glyph Protocol deploy commit was 1+1+32+1 outputs; the banner reports `p2pkh count − 1` as the ref-seed count, assuming exactly one change output. |
| 9 | **Glyph FT deploy** | At least one `commit-ft` **and** at least one `commit-nft` (having failed the P2PKH count above). It does *not* look for FT or NFT outputs. |
| 10 | **commit-ft without commit-nft** | At least one `commit-ft` and no `commit-nft` — an older or unusual FT deploy. |
| 11 | **Glyph NFT deploy** | At least one `commit-nft` and no `commit-ft`. |
| 12 | **dMint deploy reveal** | The *first* `dmint` output has `height == 0`. The count of `dmint` outputs only chooses between the "N parallel contracts" and "a single contract" wording — it is not part of the trigger, no `token_ref` is compared across outputs, and V1 vs V2 is not distinguished here. |
| 13 | **dMint claim** | The first `dmint` output has a non-zero `height`. When `vin[0]` happens to carry a decodable mint scriptSig, a sentence naming its v1/v2 shape is appended; when it does not, the banner still fires. |
| 14 | **Mutable contract update** | At least one `mut` output. |

The metadata markers (1–7) are read off the reveal CBOR, which is
operator-supplied and enforced by nothing on chain. They say what a
token *declares itself to be*. Each list entry is matched both as the
number and as the enum name, because `str()` of a `GlyphProtocol`
member is `"6"` on Python 3.11+ and `"GlyphProtocol.BURN"` before it.

Note that the CONTAINER row is the marker only. `metadata.classification`
additionally treats a `type: "container"` string as a container
declaration — the form all four mainnet containers actually use — and
the banner does not.

No banner is emitted for a plain RXD send, an FT transfer, an NFT
singleton transfer, or any output mix that reaches the end of the
list. Absence of a banner therefore does **not** mean "not a Glyph
protocol event" — an ordinary FT or NFT transfer is a Glyph event and
gets none. It means only that the shape matched no rule above.

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

OP_RETURN outputs are classified explicitly, and the trailing data
bytes are split out from the leading `0x6a` opcode into a separate
`data_hex` field. This is a cosmetic but useful separation: a reader
scanning a dMint claim sees that `vout[2]` is the OP_RETURN message
script the mint covenant hashes (and whose `SHA256d` appears in the
scriptSig at `vin[0]`), without having to manually strip the opcode
prefix.

The baseline is `type=op_return` with `data_hex` and nothing more —
no CBOR is assumed, no encoding is guessed. But the classifier **does**
look for two self-identifying prefixes, and refines the type when it
finds one:

| Marker | Type becomes | What is decoded |
|--------|--------------|-----------------|
| Photonic `msg`: `OP_RETURN PUSH3 "msg" <push> <bytes>` | `op_return-msg` | The trailing push, decoded as UTF-8 into `message.text` (with `is_utf8` false and no text when it is not UTF-8). Sanitised for display at this boundary; `data_hex` still carries the raw bytes. |
| HashMark: `OP_RETURN PUSH8 "HASHMARK" …` | `op_return-hashmark-v1` / `-v2` | Version, algorithm, digest, optional label, and for v2 the committed signer hash160 and signature. |

For a well-formed HashMark the classifier goes one step further and
**verifies the v2 signature**: `verify_attestation` recovers the signing
key from the signature over the canonical statement and requires it to
hash to the signer committed in the record. The result lands in
`hashmark.attestation` as `valid`, `invalid_signature`, or
`not_attested`. Radiant mainnet's genesis hash is part of the signed
statement and a pasted script carries no chain context, so mainnet is
**assumed**, and the assumption is reported in the output rather than
hidden — the same bytes on another chain are a different statement.

Two consequences worth stating plainly:

- This is real cryptographic verification inside a tool otherwise
  described as byte-pattern matching. `attestation.outcome == "valid"`
  means a signature checked out. It still does not establish authorship,
  ownership, originality, or the truth of the marked file's contents —
  only that whoever holds that key made this statement about this digest
  no later than the confirming block.
- Anything that does not carry one of the two markers stays plain
  `op_return`, deliberately. A scanner meets thousands of other
  protocols' data outputs, and treating them as errors buries the real
  ones. If a reader needs to know what those bytes mean, they decode
  them out-of-band.

HashMark is a third-party format (MIT,
`github.com/cdonnachie/hashmark.rxd`); pyrxd implements the read side
only and never writes one.

The signature check is also why HashMark decoding is a **CLI-only**
capability today: it reaches for `coincurve`, which is not installed in
the browser's Pyodide runtime, so a HashMark OP_RETURN fails to classify
there. See "Why share one classifier across CLI and browser" below.

---

## Browser variant: install-time integrity

The browser inspector is served from GitHub Pages, and its install-time
checks are worth understanding precisely, because two of them are
narrower than they look.

| Artifact | Source | What is actually checked |
|----------|--------|--------------------------|
| Pyodide loader (`pyodide.js`) | jsdelivr CDN | Subresource Integrity (SHA-384) on the `<script>` tag in `index.html`. This is the **only** `integrity=` attribute on the page. |
| Everything else Pyodide loads — `pyodide.asm.js`, `pyodide.asm.wasm`, `python_stdlib.zip`, the lockfile, and the `micropip` / `pycryptodome` packages | jsdelivr CDN, under the `indexURL` passed to `loadPyodide` | **No SRI.** These are fetched by the loader script itself, after it runs. Whatever integrity Pyodide applies to its own packages is anchored in a lockfile that comes from the same `indexURL`, which this page does not pin. |
| `pyrxd` wheel | same-origin (`/inspect/wheels/`) | SHA-256 compared against `manifest.json` before `micropip.install`. |
| Vendored `cbor2==5.4.6` wheel | same-origin (`/inspect/wheels/`) | SHA-256 compared against `manifest.json` before `micropip.install`. Separately, the docs workflow verifies the upstream PyPI bytes at build time against a hash pinned **in the workflow file**, which is in git — that one anchor does sit outside the deploy. |
| `glue.py` (Python bootstrap) | same-origin | SHA-256 compared against `manifest.json` before evaluation. |
| `manifest.json` itself | same-origin | **Not hashed.** It is fetched with no integrity check, and every expected SHA-256 above is read out of it. |

If any SHA-256 mismatches the manifest, the install aborts loudly with
an error citing the mismatch — the tool does not fall through to "try
without the integrity check." The verification code is in
[`docs/inspect_static/inspect/inspect.js`](../../docs/inspect_static/inspect/inspect.js)
(`fetchAndVerify`).

### What the manifest check does and does not defend against

The manifest and the wheels are written by the same CI job and deployed
together, and the page reads the manifest from the same origin as the
bytes it describes. So the check is a **deploy-integrity** check —
"did these bytes come from the run that wrote this manifest?" — not a
supply-chain trust anchor.

It catches:

- a partial, stale or corrupted deploy: a wheel updated without its
  manifest (or the reverse), a truncated transfer, a stale cached wheel
  served alongside a fresh manifest;
- a manifest that tries to point an install somewhere else. `manifest.wheel`
  and `manifest.cbor2_wheel` must be bare basenames (no `/`, no `..`, no
  URL-encoded separators), so a poisoned manifest cannot redirect a wheel
  install off-origin or up a directory;
- a manifest that tries to *disable* a check by supplying a malformed
  digest: every SHA-256 field must be exactly 64 lowercase hex characters
  or boot fails, rather than the field being treated as "no hash".

It does **not** defend the deployed origin against itself. An attacker who
can rewrite the GitHub Pages deploy rewrites `manifest.json` in the same
act, and could equally rewrite `inspect.js` — which is also same-origin
and carries no hash — removing the check altogether. Closing that would
need a digest anchored somewhere the deploy cannot reach.

The page's Content-Security-Policy denies PyPI as a script source, and
`micropip.install(..., deps=False)` is used for the pyrxd wheel so no
transitive PyPI metadata fetch happens during bootstrap. The cbor2 wheel
is pinned to `5.4.6` because cbor2 6.x ships C-only and a Pyodide install
that depends on a PyPI fetch creates an off-origin trust path the
same-origin SHA-256 approach is designed to avoid.

---

## Why share one classifier across CLI and browser

The CLI and browser variants both import from
[`pyrxd.glyph.inspect`](../../src/pyrxd/glyph/inspect.py) — the
public façade — which re-exports helpers from
`pyrxd.glyph._inspect_core`. That core module's **import graph** is
deliberately pure: no `click`, no `aiohttp`, no `websockets`, no
`coincurve`, no `Cryptodome.Cipher`. Importing it under Pyodide does
not drag heavy dependencies that don't exist in the WASM runtime. That
property — and only that property — is asserted by a test
(`tests/web/test_inspect_imports_pyodide_clean.py`).

The split means a change to the classifier is a change to *one* file
that both variants pick up. Parity between CLI and browser is
structural for classification, not a sync chore.

Two caveats on how far that parity reaches, both verified against the
code rather than assumed:

- **The presentation layers are separate implementations.** The
  structural-match qualifiers, the tx-shape banner and the per-row
  fields are written twice — once in `_render_script_human` /
  `_render_txid_human` on the CLI side, once in `inspect.js` — and they
  do not cover the same set (see §1 below, and "Tx-shape banner"
  above). Only the classifier is shared.
- **The import graph is pure; one runtime path is not.** The test cited
  above proves that *importing* the façade pulls in no heavy dependency.
  It does not constrain what a classifier call reaches for later, and
  the HashMark branch does: `verify_attestation` imports
  `pyrxd.keys` — and so `coincurve` — inside the function body. Nothing
  installs `coincurve` under Pyodide, so in the browser a well-formed
  HashMark OP_RETURN does not classify: pasted on its own it comes back
  as an error, and inside a fetched transaction that one row degrades to
  `type=error` while the rest of the transaction renders normally. The
  CLI, which has `coincurve`, decodes and verifies it. This is a known
  gap, not a design intent.

---

## Footguns the tool guards against

1. **"It's classified, so it must be correct."** Most classified
   shapes carry a structural-match qualifier: the CLI prints it in
   parentheses below the per-script body, the browser shows it as a
   `structural-note` paragraph. Where it is emitted it is not optional
   and not suppressible.

   It is **not** emitted everywhere, and the gaps do not line up between
   the four rendering surfaces. Coverage as it stands:

   | Script `type` | CLI, pasted script | CLI, tx output row | Browser (either) |
   |---------------|--------------------|--------------------|------------------|
   | `ft`, `nft`, `mut`, `commit-ft`, `commit-nft`, `dmint`, `p2sh`, `p2pkh-cltv`, `p2pkh-csv` | qualifier | — | qualifier |
   | `container-legacy`, `soulbound-covenant`, `self-replicating-covenant` | the classifier's `note`, spelled out | one-line warning (`UNSPENDABLE`, `markers only — NOT proof of soulbound`) | the classifier's `note` |
   | `unknown` | "does not match any known Glyph or P2PKH layout" | token-bearing lines only | pasted script: a "doesn't match any known template" note; tx row: — |
   | `op_return` | — (the human renderer prints the head line and stops; not even `data_hex`) | — | qualifier |
   | `op_return-msg` | the decoded message, no qualifier | — | — |
   | `op_return-hashmark-v1` / `-v2` | the HashMark caveat, no qualifier | — | — (and see the `coincurve` gap above) |
   | `p2pkh` | — | — | — |
   | `error` | n/a | `(classifier error: …)` | the `error` field, no qualifier |

   Two mechanical causes are worth knowing, because they explain the
   shape of the table rather than each cell:

   - The browser's `_structuralQualifierNote` is a lookup on an
     **exact** type string over ten hand-written keys. The three
     `op_return-*` refinements therefore lose even the generic
     OP_RETURN qualifier that plain `op_return` gets, and `p2pkh`,
     `unknown` and `error` were never in the table.
   - The CLI's fetched-transaction renderer, `_render_txid_human`,
     emits no qualifier on any row, for any type. Since a pasted txid
     is how most people meet the tool, that is the surface where the
     trust boundary is least visible. Paste the individual script hex
     to get the qualified form.

   Read the qualifier as a bonus, not a guarantee: its absence says
   nothing about how much the classification proves.

2. **"It looks like a V2 dMint contract on mainnet."** The
   classifier recognises V2 shapes for forward-compatibility, but no
   V2 dMint contract has been deployed on Radiant mainnet to date.
   The browser's dMint-claim banner says so explicitly, though only
   when `vin[0]` carried a decodable mint scriptSig — the deploy-reveal
   banner carries no such note, and the CLI emits no banner at all. If
   you paste a V2-shaped contract and see `version=v2` in the output,
   that is a synthetic input or a future deploy — it is not a mainnet
   token to date.

3. **Hostile manifests, poisoned wheels, and CDN compromise.** The
   browser variant treats the wheels and `glue.py` as untrusted bytes
   until their SHA-256 matches the manifest: a mismatch aborts loudly,
   and basename validation rejects path traversal. The CSP forbids
   `script-src` from anywhere other than the page itself and the pinned
   jsdelivr origin.

   Be precise about the two limits, both spelled out under "Browser
   variant: install-time integrity" above. The SRI hash covers
   `pyodide.js` and nothing else — `pyodide.asm.wasm` and the rest of
   the runtime are fetched *by* that script, *after* it runs, from that
   same CDN path and with no `integrity` attribute — so it catches a
   tampered **loader**, not a jsdelivr compromise in general, and WASM
   does run from unverified bytes. And the manifest that supplies every SHA-256
   is itself fetched unverified from the deploy it is meant to police,
   which makes the wheel check a deploy-integrity check rather than a
   defence against a compromised deploy.

4. **Spoofed token names in CBOR metadata.** Reveal-tx metadata
   strings are sanitised through `sanitize_display_string`
   (strips Unicode control / format / combining codepoints) and
   capped via `truncate_for_human`. Token names and tickers are run
   through the TR39 confusables skeleton check
   (`looks_confusable_with_latin`) — a Cyrillic-spoofed "USDC" is
   flagged before the user sees the rendered metadata: the CLI prints
   a `*** WARNING ***` line ABOVE the field it applies to, and the
   browser page paints a warning band on the card.

   It reports **mimicry, not foreignness**. A wholly non-Latin name
   like `トークン` or `中文` is not flagged — a warning that fires on
   every legitimate Japanese token is the false positive that trains a
   reader to ignore the real one.

   This paragraph described the check as live while
   `looks_confusable_with_latin` had **no production caller** — a
   definition, a façade re-export and its tests. The CLI ran no
   confusables check at all and the browser used a weaker script-mixing
   heuristic. Wired 2026-09-03; both surfaces now read one verdict
   computed in `_inspect_core`.

5. **OP_RETURN ambiguity.** Data carriers are classified as
   `op_return` with the data split out, not silently grouped with
   "unknown" scripts. A reader looking at a dMint claim can see at a
   glance that the OP_RETURN at `vout[2]` is the message script
   whose hash appears in the scriptSig. Two self-identifying formats
   are decoded further and get their own types — see "OP_RETURN data
   carriers" above, including the signature verification that runs on a
   HashMark record and the shapes that do not reach it in the browser.

---

## Source-of-truth references

- **Classifier core.**
  [`src/pyrxd/glyph/_inspect_core.py`](../../src/pyrxd/glyph/_inspect_core.py)
  (private; pure-Python, no heavy deps at import time)
- **Public façade.**
  [`src/pyrxd/glyph/inspect.py`](../../src/pyrxd/glyph/inspect.py)
- **CLI command.**
  [`src/pyrxd/cli/glyph_inspect.py`](../../src/pyrxd/cli/glyph_inspect.py)
  — the `inspect_cmd` Click command, `_render_script_human`,
  `_render_txid_human` and the rest of the presentation layer.
- **CLI group wiring.**
  [`src/pyrxd/cli/glyph_cmds.py`](../../src/pyrxd/cli/glyph_cmds.py)
  — attaches the command to the `glyph` group and re-exports the name.
  It holds no inspect logic of its own.
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
