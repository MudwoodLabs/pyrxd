# Glyph token protocol — normative specification

This document specifies the Glyph token protocol on Radiant **as pyrxd implements
it**: the CBOR metadata envelope, the commit/reveal mint, reference (`ref`)
derivation, the locking-script templates for each token type, and the validation
rules a conforming implementation applies. It is written so that an independent
implementation in another language can produce byte-identical envelopes, scripts,
and refs.

Terms are defined in the [glossary](../concepts/glossary.md); this page does not
redefine them. For the narrative introduction to the same material see
[Understanding Glyph structures and terminology](../concepts/glyph-structures-and-terminology.md)
and [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md).

## 1. Status, scope, and how to read this

**Specification revision:** 2 — describes pyrxd **0.15.0** (unreleased)
(`pyproject.toml:9`).

Revision 2 rewrote §7.5 (CONTAINER) after putting its claims to a regtest node,
added the `in` / `by` envelope fields to §4.3, and retired §16.2. See §17.1.

**Source of truth.** Every normative statement below was derived from the pyrxd
source, and where possible from a test or conformance vector that pins the
behaviour. Each statement carries a citation of the form `path:line`. Where an
existing pyrxd document and the code disagreed, the code was taken as
authoritative and the disagreement is recorded in §16. Statements that could not
be verified against code, a test, or a chain artifact are labelled explicitly as
unverified — there are none presented as fact.

**Key words.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted
as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), and only when they appear in
all capitals.

**Two distinct authorities.** This specification separates:

- **Consensus rules** — enforced by Radiant nodes. Violating one produces an
  invalid transaction that no node will accept.
- **Protocol rules** — this specification's conventions. Violating one produces a
  transaction that confirms perfectly well but that other implementations will
  classify differently, or not at all.

Conflating the two is the single most common error in token-protocol
documentation, so every rule below says which kind it is. Where nothing enforces
a property, §9.4 and §11 say so plainly.

**Out of scope.** Radiant consensus itself, the ElectrumX/RXinDexer network
protocols, wallet key management, and the Gravity/RSWP swap stack. dMint contract
bytecode is summarised in §7.6 and specified by the machine-readable vectors in
`conformance/dmint-v2-contract-vectors.json`.

**Security posture.** The Glyph primitives described here are consensus-validated
on regtest and several are proven on Radiant mainnet, but the stack has not had an
external security audit. This specification documents behaviour; it is not a
safety endorsement.

## 2. Notation

- Hex strings are lowercase and represent bytes in transmission order.
- `<name:N>` denotes an `N`-byte field.
- **Display order** for a txid is the reversed (big-endian-looking) form printed
  by wallets and explorers. **Wire order** is the byte order used inside scripts
  and transaction serialisation. They are reverses of each other.
- `SHA256d(x)` means `SHA256(SHA256(x))`.
- Script byte values are given as opcodes; push-data is written as the literal
  push opcode followed by the payload.
- "photon" is the indivisible unit of RXD. An output's `satoshis` field is
  denominated in photons.

### 2.1 Radiant-specific opcodes used by this specification

Radiant extends the Bitcoin script opcode set. The values below are taken from
`src/pyrxd/constants.py:277-336`. These are **not** assumed knowledge; every
Glyph script template is built from them.

| Opcode | Byte | Behaviour |
|---|---|---|
| `OP_STATESEPARATOR` | `0xbd` | Marks the boundary between the *state script* (before) and the *code script* (after) of a locking script. Execution is unaffected; the split is what the `…_CODESCRIPT…` and `…_STATESCRIPT…` introspection opcodes read. At most one per script. |
| `OP_PUSHINPUTREF` | `0xd0` | Followed by a 36-byte ref operand. Pushes the ref onto the stack **and** requires that the same ref appear in some input of the spending transaction. Ref type NORMAL. |
| `OP_PUSHINPUTREFSINGLETON` | `0xd8` | As above, ref type SINGLETON: consensus additionally enforces uniqueness — no other unspent output may carry the same ref. |
| `OP_REQUIREINPUTREF` | `0xd1` | Asserts a ref is present in an input without pushing it. |
| `OP_REFTYPE_OUTPUT` | `0xda` | Pops a 36-byte ref; pushes `0` (absent), `1` (NORMAL), or `2` (SINGLETON) describing how that ref appears across the spending transaction's outputs. |
| `OP_REFOUTPUTCOUNT_OUTPUTS` | `0xde` | Pops a ref; pushes the number of outputs carrying it. |
| `OP_CODESCRIPTBYTECODE_UTXO` | `0xe9` | Pops an input index; pushes that input's code script (the bytes after `OP_STATESEPARATOR`). |
| `OP_CODESCRIPTHASHVALUESUM_UTXOS` | `0xe3` | Pops a code-script hash; pushes the summed photon value of all *inputs* whose code script hashes to it. |
| `OP_CODESCRIPTHASHVALUESUM_OUTPUTS` | `0xe4` | Same, over *outputs*. |
| `OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS` | `0xe6` | Pops a code-script hash; pushes the number of outputs whose code script hashes to it. |
| `OP_INPUTINDEX` | `0xc0` | Pushes the index of the input currently being evaluated. |
| `OP_OUTPOINTTXHASH` | `0xc8` | Pops an input index; pushes that input's outpoint txid in **wire order** (32 bytes). |
| `OP_OUTPOINTINDEX` | `0xc9` | Pops an input index; pushes that input's outpoint vout as a script number. |

The full opcode family (`0xd0`–`0xec`) is enumerated at
`src/pyrxd/constants.py:299-331`.

### 2.2 Ref-opcode scanning

A ref operand is 36 raw bytes following the opcode; it is **not** a push. An
implementation that needs to enumerate the refs in a script MUST walk the script
as an opcode stream — consuming each push opcode's payload — rather than scanning
for bytes in the ref-opcode range, because roughly half of random 20-byte
public-key hashes contain such a byte.

Exactly **five** opcodes are followed by a 36-byte operand, and the set is
**not** the contiguous `0xd0`–`0xd8` range:

| Opcode | Byte | Operand |
|---|---|---|
| `OP_PUSHINPUTREF` | `0xd0` | 36 bytes |
| `OP_REQUIREINPUTREF` | `0xd1` | 36 bytes |
| `OP_DISALLOWPUSHINPUTREF` | `0xd2` | 36 bytes |
| `OP_DISALLOWPUSHINPUTREFSIBLING` | `0xd3` | 36 bytes |
| `OP_REFHASHDATASUMMARY_UTXO` | `0xd4` | **none** |
| `OP_REFHASHVALUESUM_UTXOS` | `0xd5` | **none** |
| `OP_REFHASHDATASUMMARY_OUTPUT` | `0xd6` | **none** |
| `OP_REFHASHVALUESUM_OUTPUTS` | `0xd7` | **none** |
| `OP_PUSHINPUTREFSINGLETON` | `0xd8` | 36 bytes |

`0xd4`–`0xd7` are operand-less stack operations that happen to sit inside the
same byte range (`Radiant-Core/src/script/script.h:281-284`). Radiant's opcode
stepper `GetScriptOp` advances the program counter by 36 for the other five only
(`Radiant-Core/src/script/script.cpp:710-716`), and `CScript::GetPushRefs`
collects refs for that same five (`:586-590`). A walker that treats the range as
contiguous desynchronizes from consensus after any `0xd4`–`0xd7`: it either
rejects a valid script or — when the byte it resumes on happens to be a valid
single-byte opcode — silently resynchronizes, reporting a **phantom** ref and
dropping the real one. Implementations MUST use the five-opcode set.

pyrxd's walker is `iter_input_refs` (`src/pyrxd/glyph/script.py:454-509`) over
the constant `REF_OPCODES` (`:442`); the differential test against a port of the
consensus rule is `TestRefWalkerConsensusDifferential` in `tests/test_glyph.py`.
A script that ends mid-push or mid-ref-operand has ambiguous length;
implementations MUST refuse it rather than guess (`TruncatedScriptError`,
`src/pyrxd/glyph/script.py:445-451`).

## 3. Identifiers

### 3.1 `GlyphRef` — the 36-byte wire form

A ref is an outpoint encoded for embedding in a script:

```
<txid in wire order:32> || <vout as uint32 little-endian:4>     = 36 bytes
```

`src/pyrxd/glyph/types.py:43-54`. The txid bytes are the reverse of the display
form. `vout` MUST be in `[0, 2^32-1]` (`src/pyrxd/glyph/types.py:39-41`).

### 3.2 Contract id — the 72-hex display form

Wallets and explorers display a token's genesis ref as:

```
<txid in DISPLAY order:64 hex> || <vout as uint32 BIG-endian:8 hex>   = 72 hex chars
```

`src/pyrxd/glyph/types.py:56-95`. Both halves are in human-readable order, so the
trailing `00000004` reads as `4`. This form is **not** the wire form: the txid is
not reversed and the vout is big-endian. Confusing the two silently produces a
wrong-vout ref; `tests/test_glyph.py:299` pins that the two encodings differ.

## 4. The metadata envelope

### 4.1 Framing

The envelope is a CBOR map. In the reveal transaction it is carried in the
scriptSig of the input that spends the commit output, as two consecutive pushes
appended after the standard P2PKH unlock:

```
<sig> <pubkey> PUSH3 "gly" PUSH(n) <CBOR:n>
```

The 3-byte ASCII marker `gly` (`0x67 0x6c 0x79`) is **not** part of the CBOR
bytes and is **not** covered by the payload hash
(`src/pyrxd/glyph/payload.py:16, 22-24`).

The push opcode for the CBOR body MUST be selected by length
(`src/pyrxd/glyph/payload.py:210-220`; pinned across boundary lengths at
`tests/test_glyph_cbor_roundtrip.py:184-232`):

| CBOR length `n` | Push encoding |
|---|---|
| `n ≤ 75` | direct push: `n` |
| `76 ≤ n ≤ 255` | `0x4c` (`OP_PUSHDATA1`) `n:1` |
| `256 ≤ n ≤ 65535` | `0x4d` (`OP_PUSHDATA2`) `n:2` little-endian |
| `65536 ≤ n ≤ 262144` | `0x4e` (`OP_PUSHDATA4`) `n:4` little-endian |

`OP_PUSHDATA4` is not hypothetical: the mainnet Glyph Protocol reveal
`b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6` carries a
65,569-byte body and uses it (`tests/test_glyph.py:506-530`).

A parser MUST locate the envelope by walking the scriptSig's pushes and taking the
push immediately **after** a push equal to `gly`
(`src/pyrxd/glyph/inspector.py:280-319`). It MUST NOT assume the marker is at a
fixed offset, and it MUST support all four push opcodes — a walker that stops at
`0x4e` never reaches the marker on the mainnet token above.

The envelope MAY appear on an input other than input 0; pyrxd searches every
input (`src/pyrxd/glyph/inspector.py:149-162`).

### 4.2 The CBOR profile — a producer rule, not a validity rule

This is the most consequential detail in the envelope, and it is easy to get
backwards.

**Producer rule.** pyrxd encodes with `cbor2.dumps(payload, canonical=True)`
(`src/pyrxd/glyph/payload.py:35`) — RFC 8949 deterministic form: map keys sorted
length-first then bytewise, shortest-form integer and length encodings, shortest
unambiguous floats. Producers SHOULD use this form. It makes an envelope a pure
function of its logical content, independent of field-declaration order in the
source. `tests/test_golden_vectors.py:42-143` freezes the resulting bytes and
proves that reordering the constructor arguments does not change them.

**Consumer rule.** A decoder MUST NOT require canonical form. Verified against the
repository's own mainnet fixture: `tests/fixtures/glyph_reveal_cbor.bin` — the
65,569-byte envelope from the flagship mainnet Glyph Protocol reveal — is **not**
canonical on two counts:

- Its map header is `b9 0006` (a 16-bit length encoding of `map(6)`); canonical
  form requires the shortest header, `a6`.
- Its keys appear in producer insertion order `p, ticker, name, desc, by, main`;
  canonical order would be `p, by, desc, main, name, ticker`.

Re-encoding it canonically yields 65,565 bytes — four bytes shorter, and therefore
a different payload hash. Measured by decoding the fixture and comparing
`cbor2.dumps(cbor2.loads(raw), canonical=True)` against `raw`.

Three normative consequences follow:

1. An implementation MUST compute the payload hash over the **bytes received on
   chain**, never over a re-encoding of a decoded object. A verifier that decodes
   and re-encodes will reject every non-canonically-produced token, which today
   includes the reference mainnet deployment.
2. An implementation MUST NOT reject an envelope for being non-canonical.
3. Canonical encoding is a **pyrxd producer choice**, listed among the deliberate
   divergences from Photonic in §15.

### 4.3 Fields

All fields are OPTIONAL except `p`. Unknown fields MUST be ignored by a decoder
rather than treated as an error (see §16.1 for what pyrxd does with them today).
Field names, decoder types, and limits are from
`src/pyrxd/glyph/payload.py:92-189` and `src/pyrxd/glyph/types.py:381-429`.

| Key | CBOR type | Required | Max length | Meaning |
|---|---|---|---|---|
| `p` | array of uint | **yes** | — | Protocol markers (§8.1) |
| `v` | uint | no | — | Envelope version. Absent = V1; `2` = V2 |
| `name` | text | no | 64 | Display name |
| `ticker` | text | no | 16 | FT ticker symbol |
| `desc` | text | no | 1000 | Description |
| `type` | text | no | 64 | Free-form NFT type tag |
| `main` | map | no | — | Embedded media, `{"t": <mime>, "b": <bytes>}` |
| `attrs` | map | no | 64 entries | Free-form string attributes |
| `loc` | text | no | 512 | External URI (IPFS or other) |
| `loc_hash` | text | no | 128 | Integrity hash for `loc` |
| `decimals` | uint | no | `0..18` | Display precision only |
| `image` | text | no | 512 | HTTPS image URL |
| `image_ipfs` | text | no | 128 | IPFS CID |
| `image_sha256` | text | no | 64 | Lowercase hex SHA-256 of the image bytes |
| `dmint` | map | no | — | dMint configuration (§7.6.3) |
| `creator` | map | no | — | Creator identity + optional signature (§10) |
| `royalty` | map | no | — | Royalty hint (§11) |
| `policy` | map | no | — | Behaviour flags |
| `rights` | map | no | — | Licence and attribution |
| `created` | text | no | 64 | Creation timestamp |
| `commit_outpoint` | text | no | 128 | Self-declared commit outpoint |
| `in` | array of byte strings | no | — | Containers this token is a member of (§7.5) |
| `by` | array of byte strings | no | — | Author / issuer tokens |

Notes on individual fields:

- **`in` / `by`** each hold 36-byte refs in the **same wire form the locking
  script uses** — `txid` reversed, then `vout` little-endian — NOT the 72-char
  display form of §5. That is what lets a reader intersect a claimed ref against
  the refs it parsed out of the reveal's *output* scripts, which is the only
  check either field admits (§7.5, §9.4). Entries MAY be raw byte strings or
  wrapped in **CBOR tag 64**, like `main.b`; a decoder MUST accept both
  (`src/pyrxd/glyph/payload.py:81-121`). pyrxd emits raw byte strings.
  A decoder SHOULD drop a malformed entry rather than fail the whole envelope —
  this is advisory metadata on an attacker-controlled payload.

- **`main.b`** MAY be a raw byte string or a byte string wrapped in **CBOR tag 64**
  (uint8 array). Photonic emits tag 64; a decoder MUST unwrap it
  (`src/pyrxd/glyph/payload.py:115-122`). The mainnet fixture uses tag 64 for a
  65,430-byte PNG (verified by decoding the fixture).
- **`decimals`** is display metadata only. On chain, one photon is one FT unit;
  nothing scales by `decimals`. A decoder MUST reject a float or boolean here —
  CBOR floats truncate silently (`src/pyrxd/glyph/payload.py:79-89`).
- **`policy.transferable = false`** is an advisory soulbound marker. It is not
  enforced by any script pyrxd builds for an ordinary NFT; see §9.4.
- **`commit_outpoint`** is self-declared metadata. Nothing checks it against the
  transaction that actually created the token. The authoritative genesis ref is
  the one embedded in the locking script (§5).
- **`royalty.enforced`** means "wallets should honour this", never "the chain
  will". See §11.

### 4.4 Size limits

| Limit | Value | Source |
|---|---|---|
| CBOR body | 262,144 bytes (256 KiB) | `src/pyrxd/glyph/payload.py:51` |
| `attrs` entries | 64 | `src/pyrxd/glyph/payload.py:58` |
| `main.t` (MIME type) | 256 characters | `src/pyrxd/glyph/payload.py:67` |
| `main.b` (media) | bounded only by the CBOR body cap | — |

The 256 KiB body cap is a DoS bound chosen above the largest known real payload
(the 65,569-byte mainnet body); it is a pyrxd policy limit, not a consensus one.

**Reading is not writing.** The body cap is the only size bound applied on
decode. There is no separate `main.b` ceiling: media is whatever the enclosing
body can hold.

An earlier revision of this section said pyrxd "decodes media it would refuse to
construct" — which was correct — and it was then changed to match a 100,000-byte
cap in `GlyphMedia.__post_init__`. That cap was a write-side policy that fired
only on decode, because the decoder is the only code that constructs a
`GlyphMedia`; it refused real mainnet tokens (webp payloads of 153,650 / 178,608
/ 236,726 bytes, measured), and it made the 256 KiB body budget unreachable for
any media-bearing token. **The spec was right and the code was made authoritative
over it.** The cap is gone; this sentence is restored.

### 4.5 What a decoder MUST reject

`src/pyrxd/glyph/payload.py:92-189`:

- A body larger than 262,144 bytes.
- Bytes that are not decodable CBOR.
- A top-level value that is not a map.
- A map with no `p` key, or whose `p` is not an array.
- A `main.t` that is not a text string, or longer than 256 characters.

A decoder MUST NOT reject the whole payload for an unusable OPTIONAL field. A
text field that is the wrong type, or longer than its §4.3 cap, is **dropped**
(the decoder logs it and returns the empty string) so that the rest of the token
still decodes. Dropping preserves both properties the caps exist for — nothing is
coerced (`42` never becomes `"42"`), and nothing oversized reaches a caller —
while a rejection additionally discarded every other field. Measured on live
mainnet: 6 of 25 sampled payloads were rejected outright by the previous
behaviour, including Photonic-minted glyphs carrying `loc` as an integer.
- An `attrs` map with more than 64 entries.
- A `decimals` that is a float or boolean.

A decoder SHOULD NOT reject the whole envelope because one optional sub-object is
malformed. pyrxd logs and drops a malformed `creator`, `royalty`, `policy`, or
`rights` and keeps the rest (`src/pyrxd/glyph/payload.py:138-165`). A malformed
`dmint` object, by contrast, raises (`src/pyrxd/glyph/payload.py:131-136`) — an
asymmetry that is deliberate for a field indexers price tokens from, but it is an
asymmetry, and an interoperating implementation should know about it.

Any string field decoded from an envelope is attacker-controlled. An
implementation that renders these to a terminal or a UI MUST strip Unicode
categories `Cc`, `Cf`, `Cn`, `Co`, `Zl`, `Zp`, `Mn`, `Me` first — ANSI escapes,
bidi overrides, zero-width joiners, and combining marks are all reachable through
`name`, `desc`, `ticker`, and `attrs`
(`src/pyrxd/glyph/_inspect_core.py:69-111`).

### 4.6 The payload hash

```
payload_hash = SHA256d(cbor_bytes)          # 32 bytes
```

`src/pyrxd/glyph/script.py:189-191`. The `gly` marker is excluded. This is a
**double** SHA-256 — it matches `OP_HASH256`, which is what the commit script
executes.

## 5. Genesis ref derivation

**The rule.** A Glyph token's permanent identity — its genesis ref — is the
**outpoint of the commit output**, `commit_txid:commit_vout`. It is **not** the
reveal txid.

This is not a convention layered on top of the chain; it is what the commit
covenant enforces. Walking `build_commit_locking_script`
(`src/pyrxd/glyph/script.py:145-181`) with the reveal's scriptSig on the stack:

```
stack: [sig, pubkey, "gly", cbor]
c0                OP_INPUTINDEX                → i
c8                OP_OUTPOINTTXHASH  (pops i)  → this input's outpoint txid, wire order (32 B)
c0                OP_INPUTINDEX                → i
c9                OP_OUTPOINTINDEX   (pops i)  → this input's outpoint vout, as a number
54 80             OP_4 OP_NUM2BIN              → vout as 4-byte little-endian
7e                OP_CAT                       → txid_wire || vout_le  = the 36-byte ref
da                OP_REFTYPE_OUTPUT  (pops ref)→ 0 / 1 / 2
51 | 52           OP_1 (NORMAL) | OP_2 (SINGLETON)
9d                OP_NUMEQUALVERIFY
```

The input being evaluated is the one spending the commit output, so its outpoint
*is* the commit outpoint. The script therefore requires the reveal transaction to
produce an output carrying exactly that ref, at the required ref type. pyrxd
builds the matching locking script by constructing
`GlyphRef(commit_txid, commit_vout)` and embedding it
(`src/pyrxd/glyph/builder.py:251-258`), and reads it back with
`extract_ref_from_{nft,ft}_script` (`src/pyrxd/glyph/script.py:258-269`).

**Requirements.**

- An implementation MUST derive a token's identity from the ref embedded in its
  locking script, not from any transaction id.
- An implementation MUST NOT report the reveal txid as the token's ref. pyrxd's
  CLI did exactly this through 0.11.x and printed an identifier its own transfer
  commands could never resolve; corrected in 0.12.0 (commit `465bc4b`, PR #348)
  with round-trip tests at `tests/cli/test_glyph_cmds.py` asserting the reported
  ref equals the ref extracted from the reveal output, starts with the commit
  txid, and does not start with the reveal txid.
- The ref is invariant across transfers: a transfer re-emits the same 36 bytes
  (`tests/test_glyph_transfer.py:117-130`).

**Chain corroboration.** On the mainnet Glyph Protocol deploy, the reveal's 32
dMint contracts all carry `tokenRef = a443d9df…878b:0` and
`contractRef[i] = a443d9df…878b:(i+1)` — commit outpoints, in a reveal transaction
whose own txid is `b965b32d…9dd6`
([`docs/dmint-research-photonic-deploy.md`](../dmint-research-photonic-deploy.md), §3).

**Where the metadata lives.** Because the ref names the commit, fetching
`ref.txid` finds only the commit — whose inputs are plain funding spends and carry
no envelope. The envelope is in the transaction that **spends**
`ref.txid:ref.vout` (`src/pyrxd/glyph/scanner.py:222-258`). An implementation
resolving metadata from a ref MUST follow the spend, not the ref transaction.

## 6. The two-phase mint

### 6.1 Phase 1 — commit

The minter encodes the envelope, hashes it, and creates an output whose locking
script is the 75-byte commit script of §7.3. The CBOR bytes are **not** published
in this phase.

The commit output is a hashlock with **no owner-only escape path**: the only way
to spend it is a transaction whose scriptSig pushes bytes hashing to the committed
value. Losing the CBOR bytes between the two phases makes the output permanently
unspendable. An implementation MUST persist the exact CBOR bytes before
broadcasting the commit; re-deriving them from the logical metadata is not
sufficient in general, because metadata routinely carries timestamps
(`src/pyrxd/glyph/mint.py:19-56`).

The commit script's ref-type byte is derived from the envelope's `p` field, not
chosen independently: NFT (`2` present in `p`) produces the `OP_2`/SINGLETON
variant, anything else the `OP_1`/NORMAL variant
(`src/pyrxd/glyph/builder.py:209-215`).

### 6.2 Phase 2 — reveal

The reveal spends the commit output with

```
<sig> <pubkey> PUSH3 "gly" PUSH(n) <CBOR>
```

and produces at least one output carrying the ref `commit_txid:commit_vout` at the
required ref type. Ordering of the script's own checks, with the stack shown after
each step:

```
                                       [sig, pubkey, "gly", cbor]
aa   OP_HASH256                        [sig, pubkey, "gly", SHA256d(cbor)]
20 <payload_hash:32>                   [sig, pubkey, "gly", h, payload_hash]
88   OP_EQUALVERIFY                    [sig, pubkey, "gly"]
03 "gly"                               [sig, pubkey, "gly", "gly"]
88   OP_EQUALVERIFY                    [sig, pubkey]
… ref reconstruction + OP_REFTYPE_OUTPUT check (§5) …
76 a9 14 <pkh:20> 88 ac  P2PKH tail    [true]
```

So the reveal is bound to three things at once: the exact CBOR bytes, the literal
marker `gly`, and the existence of a correctly-typed output carrying the commit
outpoint as a ref. It is bound to the spender's key by the P2PKH tail.

### 6.3 Ordering constraints

- The commit MUST be broadcast before the reveal; the reveal spends it.
- The reveal's scriptSig MUST push `gly` before the CBOR body. The commit script
  consumes them in the order `cbor` then `"gly"` from the top of the stack, which
  is push order `"gly"` then `cbor`.
- Whether the commit must be **confirmed** before the reveal is broadcast is a
  protocol rule of *no* kind — it is neither consensus nor Glyph. The ref rule the
  commit covenant relies on is purely intra-transaction. pyrxd waits for
  confirmation for operational reasons (propagation, mempool eviction of an
  unconfirmed parent), and its own source says so explicitly
  (`src/pyrxd/glyph/mint.py:127-145`). Implementations SHOULD wait; they are not
  required to.
- The reveal's recipient MAY differ from the key that signs the reveal. pyrxd
  performs no authorisation check on recipient selection; mint-to-recipient is a
  supported flow (`src/pyrxd/glyph/builder.py:82-99`).

## 7. Locking-script templates

Every template below is pinned byte-for-byte against a mainnet transaction in the
test suite; the anchors are listed in §17.

### 7.1 NFT singleton — 63 bytes

```
d8 <ref:36>                OP_PUSHINPUTREFSINGLETON <ref>
75                         OP_DROP
76 a9 14 <owner_pkh:20>    OP_DUP OP_HASH160 PUSH20 <pkh>
88 ac                      OP_EQUALVERIFY OP_CHECKSIG
```

`src/pyrxd/glyph/script.py:127-132`. Total length MUST be 63 bytes; the builder
asserts it. Classifier regex: `^d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$`
(`src/pyrxd/glyph/script.py:113`).

The ref is pushed and immediately dropped — its only purpose is to invoke the
opcode's consensus effect. After the drop the remainder is an ordinary P2PKH, so a
standard `<sig> <pubkey>` scriptSig unlocks it. **There is no covenant logic in
this script**; see §9.3.

### 7.2 FT — 75 bytes

```
76 a9 14 <owner_pkh:20> 88 ac    P2PKH prologue                (25 bytes)
bd                               OP_STATESEPARATOR             (1 byte)
d0 <token_ref:36>                OP_PUSHINPUTREF <ref>         (37 bytes)
de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d   conservation epilogue    (12 bytes)
```

`src/pyrxd/glyph/script.py:135-142`; offset-by-offset assertions at
`tests/test_dmint_module.py:609-624`. Classifier regex at
`src/pyrxd/glyph/script.py:114`.

The token quantity carried by an FT output **is** the output's `satoshis` value:
one photon is one FT unit. There is no separate amount field.

The code script — everything after `OP_STATESEPARATOR` — is
`d0 <token_ref> de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d`. Its `SHA256d` is what the
conservation check keys on, so it is unique per token and identical across every
holding of that token. §9.2 walks the epilogue.

### 7.3 Commit — 75 bytes

```
aa                              OP_HASH256
20 <payload_hash:32>            PUSH32 <SHA256d(cbor)>
88                              OP_EQUALVERIFY
03 67 6c 79                     PUSH3 "gly"
88                              OP_EQUALVERIFY
c0 c8 c0 c9                     OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX
54 80 7e                        OP_4 OP_NUM2BIN OP_CAT
da                              OP_REFTYPE_OUTPUT
51 | 52                         OP_1 (NORMAL / FT) | OP_2 (SINGLETON / NFT)
9d                              OP_NUMEQUALVERIFY
76 a9 14 <owner_pkh:20> 88 ac   P2PKH tail
```

`src/pyrxd/glyph/script.py:145-181`. The FT and NFT variants are byte-identical
except for the ref-type opcode at **offset 48**: `0x51` for FT, `0x52` for NFT.
That single byte is pinned against both shapes appearing in one mainnet
transaction at `tests/test_glyph_dmint.py:227-240`.

An implementation MUST choose the ref-type byte to match the token type it is
minting. Emitting an FT-shaped reveal output against an NFT-shaped commit (or vice
versa) makes the reveal unspendable — the `OP_NUMEQUALVERIFY` fails.

### 7.4 Mutable NFT contract — 174 bytes

```
20 <payload_hash:32>       PUSH32 <SHA256d(cbor)>
75                         OP_DROP
bd                         OP_STATESEPARATOR
d8 <mutable_ref:36>        OP_PUSHINPUTREFSINGLETON <ref>
<body:102>                 fixed body
```

`src/pyrxd/glyph/script.py:340-364`. The 102-byte body is a fixed constant
(`src/pyrxd/glyph/script.py:306-330`) derived from Photonic Wallet's
`parseMutableScript` regex with the `gly` magic bytes substituted, and pinned at
`tests/test_glyph_v2.py:110-127`.

A MUT reveal produces **two** outputs: the 63-byte NFT singleton the owner holds,
and this 174-byte contract UTXO that holds the mutable state
(`src/pyrxd/glyph/builder.py:575-618`). Both carry the same ref.

The contract is spent with a scriptSig of the shape

```
PUSH3 "gly" PUSH <cbor> PUSH <op> <contract_output_index> <ref_hash_index> <ref_index> <token_output_index>
```

where `op` is `"mod"` (update the payload hash) or `"sl"` (seal — burn the
contract). Index integers use minimal push encoding
(`src/pyrxd/glyph/payload.py:246-302`).

This specification reproduces the body as a constant and does not restate a
stack-level derivation of it. Note that pyrxd's own size constant is **174**
bytes, while Photonic Wallet documents 175; pyrxd's value is the one that matches
the regex and the built script (`src/pyrxd/glyph/script.py:332-335`).

### 7.5 CONTAINER

A container's locking script is the **63-byte NFT singleton of §7.1, unchanged**
(`src/pyrxd/glyph/builder.py:673-737`). There is no container script shape.
Container-ness is the `7` marker in the envelope's `p` field, and it is invisible
on chain — exactly as in Photonic Wallet, which has a single `nftScript` and no
container variant (`packages/lib/src/script.ts`).

Membership points **child → parent** and lives in the *child's* envelope, in the
`in` field (§4.3). Nothing links a container to its members from the container
side.

#### 7.5.1 Why membership cannot be a script-level ref

This is a consensus property, not an implementation choice, and it constrains
every implementation equally.

`OP_PUSHINPUTREFSINGLETON` (`0xd8`) files its ref into **three** sets, not one —
`foundPushRefs`, `foundSingletonRefs`, and `foundDisallowedSiblingRefs`
(Radiant-Core `src/script/script.cpp:600-607`). The last one means: within a
single transaction, a ref pushed as a singleton by output *i* may not appear in
the push-ref set of **any** output *j ≠ i*
(`validateDisallowedSiblingsRefRule`, `src/validation.h:945-968`).

So a transaction that both (a) creates an output carrying `0xd0 <child_ref>` and
(b) keeps the child NFT alive as `0xd8 <child_ref>` is rejected with
`bad-txns-inputs-outputs-invalid-transaction-reference-operations`. And the
mirror image — a child whose script names a live container — fails for the same
reason. The only accepted form **consumes** the child's singleton, and because a
singleton ref re-enters `inputSingletonRefSet` only from an input's `0xd8` push
or an input outpoint (`src/validation.h:1046-1050`), a ref that has been consumed
into a `0xd0` push can never be minted as a singleton again. Naming a child in a
container's script therefore destroys that child, permanently.

The FT route is closed too: an FT input's own epilogue requires the ref's output
count to equal the FT code-script-hash output count (§9.2), and a container
output carrying the token ref breaks that equality — `OP_NUMEQUALVERIFY` fails.

All four behaviours are proven against a Radiant Core v3.1.1 regtest node in
`tests/test_container_regtest_e2e.py`; the reject reasons are quoted in §17.1.

#### 7.5.2 The removed 100-byte shape (pyrxd 0.9.0 – 0.14.0)

`prepare_container_reveal(child_ref=...)` used to emit:

```
d0 <child_ref:36>          OP_PUSHINPUTREF <child_ref>
d8 <ref:36> 75             the 63-byte NFT body of §7.1
76 a9 14 <pkh:20> 88 ac
```

An implementation that encounters one of these outputs on chain should know two
things about it:

1. **It cannot be spent by anyone.** `OP_PUSHINPUTREF` pushes the 36-byte ref and
   nothing drops it, so `OP_DUP OP_HASH160` runs over the ref rather than the
   pubkey and the `OP_EQUALVERIFY` against `<pkh>` fails for every possible
   scriptSig — the failing item is pushed by the *locking* script, so no unlock
   can influence it. Observed:
   `mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)`.
   (Contrast Photonic's `delegateTokenScript`, which is `OP_PUSHINPUTREF <ref>
   OP_DROP` + P2PKH — the `OP_DROP` is what pyrxd's prefix was missing. Repairing
   it makes the output spendable but does not rescue the design: §7.5.1 still
   applies, and the holder can drop the ref at any transfer.)
2. **Creating one destroyed a real NFT** (§7.5.1).

pyrxd 0.15.0 removed the parameter — passing it raises `ValidationError` — and
recognises the shape only to report it: `_inspect_script` returns
`type: "container-legacy"` with `spendable: false`,
`GlyphInspector.find_glyphs` returns a `container-legacy` entry with
`spendable=False`, `GlyphScanner` logs it and does not hand it back as a token,
and `build_nft_transfer_tx` refuses it by name
(`src/pyrxd/glyph/script.py:238-286`).

### 7.6 dMint contracts

#### 7.6.1 V1 — 241 bytes for typical parameters

State script (`src/pyrxd/glyph/dmint/builders.py:591-651`):

```
04 <height:4 LE>
d8 <contract_ref:36>
d0 <token_ref:36>
<max_height minimal push>
<reward minimal push>
08 <target:8 LE>
```

followed by the 145-byte code epilogue, which begins with `0xbd`
(`OP_STATESEPARATOR`) and is byte-identical across every V1 deployment except one
selector byte at epilogue offset 19: `0xaa` = SHA256d, `0xee` = BLAKE3,
`0xef` = K12 (`src/pyrxd/glyph/dmint/builders.py:548-585`).

`target` MUST be in `[1, 0x7fffffffffffffff]`. Script integers are signed, so a
value with the high bit set is negative on the stack and the on-chain comparison
misbehaves (`src/pyrxd/glyph/dmint/builders.py:634-639`).

The reward output a V1 mint pays is the 75-byte FT lock of §7.2, bound to
`token_ref` (`src/pyrxd/glyph/dmint/builders.py:683-711`). Producing a plain
P2PKH instead breaks the conservation check and the mint is rejected.

#### 7.6.2 V2 — 10-item state

```
<height minimal push>
d8 <contract_ref:36>
d0 <token_ref:36>
<max_height> <reward> <algo_id> <daa_mode> <target_time>     (minimal pushes)
04 <last_time:4 LE>
<target minimal push>
bd  OP_STATESEPARATOR
<code script>
```

`src/pyrxd/glyph/dmint/builders.py:475-522`. `height` and `target` use **minimal**
pushes: a fixed-width height push is rejected by Radiant's MINIMALDATA mempool
policy (`src/pyrxd/glyph/dmint/builders.py:484-489`). `last_time` stays a 4-byte
push because the covenant reconstructs it from `OP_TXLOCKTIME` with a fixed-width
`OP_NUM2BIN`.

The five difficulty-adjustment modes (`FIXED`, `EPOCH`, `ASERT`, `LWMA`,
`SCHEDULE`) each contribute a distinct bytecode block. The authoritative,
machine-readable definition is
[`conformance/dmint-v2-contract-vectors.json`](https://github.com/MudwoodLabs/pyrxd/blob/main/conformance/dmint-v2-contract-vectors.json):
six vectors covering all five modes, each giving `params` and the expected
`contract_script_hex`, re-derived and byte-compared on every CI run by
`tests/test_dmint_conformance_vectors.py`.

An honesty note carried over from that suite's own docstring
(`tests/test_dmint_conformance_vectors.py:6-12`): only the `v2-fixed-mainnet`
vector is anchored to an independent artifact (mainnet deploy
`95335028…bb16fb09` vout 0). The other five are pyrxd-produced regression locks,
not cross-implementation agreement, and MUST NOT be cited as such.

#### 7.6.3 The `dmint` envelope object

Field names mirror Photonic's `DmintPayload`
(`src/pyrxd/glyph/dmint/types.py:238-291`):

```
{ "algo": uint, "numContracts": uint, "maxHeight": uint, "reward": uint,
  "premine": uint, "diff": uint,
  "daa": { "mode": uint, "targetBlockTime": uint,
           "halfLife": uint?, "windowSize": uint? }? }
```

`daa` is omitted when the mode is `FIXED`. **Nothing on chain reconciles
`premine` against the photons a deploy actually emits.** pyrxd refuses a deploy
whose metadata advertises a premine it does not emit
(`src/pyrxd/glyph/builder.py:36-57`) — a deliberate addition, not shared with
Photonic, and therefore not something an implementation may rely on other
producers to have done.

### 7.7 Mint scriptSig (dMint claim)

A dMint mint spends a contract UTXO with exactly four pushes
(`src/pyrxd/glyph/inspector.py:164-216`):

```
<nonce:4 or 8> <input_hash:32> <output_hash:32> OP_0
```

- `nonce` — little-endian PoW nonce. 4 bytes = V1, 8 bytes = V2. This width is the
  only V1/V2 discriminator in the scriptSig.
- `input_hash` — `SHA256d(funding_input_locking_script)`.
- `output_hash` — `SHA256d(OP_RETURN script at vout[2])`.
- `OP_0` — the sentinel the covenant requires.

Total 72 bytes (V1) or 76 bytes (V2).

## 8. Token types

### 8.1 Protocol markers

`p` is an array of integers drawn from `src/pyrxd/glyph/types.py:18-29`:

| Value | Name | Meaning |
|---|---|---|
| 1 | `FT` | Fungible token |
| 2 | `NFT` | Non-fungible singleton |
| 3 | `DAT` | Data storage |
| 4 | `DMINT` | Proof-of-work distributed mint |
| 5 | `MUT` | Mutable metadata |
| 6 | `BURN` | Explicit burn |
| 7 | `CONTAINER` | Collection |
| 8 | `ENCRYPTED` | Encrypted content |
| 9 | `TIMELOCK` | Timelocked reveal |
| 10 | `AUTHORITY` | Issuer authority |
| 11 | `WAVE` | On-chain naming |

Producer-side combination rules enforced by pyrxd
(`src/pyrxd/glyph/types.py:344-365`):

- `p` MUST be non-empty and every value MUST be one of the above.
- `FT` and `NFT` are mutually exclusive.
- `DMINT` requires `FT`.
- `MUT`, `CONTAINER`, `ENCRYPTED`, `AUTHORITY` each require `NFT`.
- `TIMELOCK` requires `ENCRYPTED`.
- `WAVE` requires both `NFT` and `MUT`.

These are **protocol rules**, not consensus rules. A transaction carrying an
envelope that violates them confirms normally. A decoder MAY apply them as a
sanity check but MUST be prepared to encounter tokens that do not satisfy them —
pyrxd's own decoder does not re-check the combination rules on the decode path.

### 8.2 On-chain distinguishability

This is the part that matters for an indexer, and the honest summary is that the
envelope carries more type information than the chain does.

| Type | Distinguished on chain by | Classifier |
|---|---|---|
| FT | 75-byte script, `0xbd 0xd0` at offsets 25–26, FT epilogue at 63–75 | `is_ft_script` |
| NFT | 63-byte script starting `0xd8`, `0x75` at offset 37 | `is_nft_script` |
| dMint contract | parses as a V1 or V2 state+code layout | `DmintState.from_script` |
| MUT contract | 174-byte script, fixed 102-byte body | `MUTABLE_NFT_SCRIPT_RE` |
| commit (FT / NFT) | 75-byte script, `aa 20` prefix, byte 48 = `0x51` / `0x52` | `is_commit_{ft,nft}_script` |
| container-legacy (dead, pre-0.15.0) | 100-byte script, `0xd0`+36 then the 63-byte NFT body | `is_legacy_container_script` |
| CONTAINER | **not distinguishable** — byte-identical to an NFT by design (§7.5) | envelope only |
| DAT, BURN, ENCRYPTED, TIMELOCK, AUTHORITY, WAVE | **not distinguishable** — envelope markers only | envelope only |

`src/pyrxd/glyph/_inspect_core.py:210-322` is the dispatch order pyrxd uses, and
`src/pyrxd/glyph/_inspect_core.py:325-369` is the envelope-side classification,
which returns the highest-specificity marker present.

An implementation classifying a *token* (rather than an output) MUST read the
envelope. An implementation classifying an *output* can only report the script
shapes above.

## 9. Ref semantics — what is enforced, and what is not

### 9.1 Consensus: induction and singleton uniqueness

Every ref appearing in an output script MUST also appear in some input of the same
transaction. Radiant rejects a violation with
`bad-txns-inputs-outputs-invalid-transaction-reference-operations`. Refs cannot be
created from nothing — only carried forward
(`src/pyrxd/glyph/script.py:63-77`).

A `0xd8` SINGLETON ref additionally may not appear in more than one unspent
output.

Two consequences a specification must state plainly:

- **Consensus enforces uniqueness, not provenance.** A node auto-inserts every
  input's own prevout into the input ref set. A script carrying
  `d8 <arbitrary outpoint>` therefore satisfies every ref rule while referring to
  a plain wallet UTXO that was never a Glyph mint. A consensus-valid singleton ref
  need not be a genuinely minted token. Anyone accepting "the advertised asset"
  MUST resolve the ref off-chain against a trusted indexer — checking the genesis
  outpoint, a real `gly` envelope, the agreed payload hash, and a minimum genesis
  confirmation depth. This is documented with its live-node reproduction in
  [covenant building blocks](../concepts/covenant-building-blocks.md), §3.
- **Nothing requires a token to survive.** Burning is permitted at consensus
  level; zero carrying outputs is legal.

### 9.2 What the FT epilogue actually enforces

Executing the FT lock of §7.2 as the spending input's scriptPubKey, with
`<sig> <pubkey>` supplied:

```
… P2PKH …                                        [true]
bd   OP_STATESEPARATOR                           (no stack effect)
d0 <ref:36>  OP_PUSHINPUTREF                     [true, ref]
de   OP_REFOUTPUTCOUNT_OUTPUTS   (pops ref)      [true, n_ref]
c0   OP_INPUTINDEX                               [true, n_ref, i]
e9   OP_CODESCRIPTBYTECODE_UTXO  (pops i)        [true, n_ref, codescript]
aa   OP_HASH256                                  [true, n_ref, csh]
76   OP_DUP                                      [true, n_ref, csh, csh]
e3   OP_CODESCRIPTHASHVALUESUM_UTXOS  (pops)     [true, n_ref, csh, sum_in]
78   OP_OVER                                     [true, n_ref, csh, sum_in, csh]
e4   OP_CODESCRIPTHASHVALUESUM_OUTPUTS (pops)    [true, n_ref, csh, sum_in, sum_out]
a2   OP_GREATERTHANOREQUAL                       [true, n_ref, csh, sum_in >= sum_out]
69   OP_VERIFY                                   [true, n_ref, csh]
e6   OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS (pops) [true, n_ref, n_csh]
9d   OP_NUMEQUALVERIFY                           [true]
```

Two rules, and exactly two:

1. **`sum_in ≥ sum_out`.** The total photons on outputs bearing this token's code
   script may not exceed the total on the inputs. Inflation is impossible;
   **burning is permitted.** This is `≥`, not `=` — opcode `0xa2` is
   `OP_GREATERTHANOREQUAL` (`src/pyrxd/constants.py:244`).
2. **`n_ref == n_csh`.** The number of outputs carrying the token's ref equals the
   number of outputs whose code script hashes to the FT code script. This is what
   prevents the ref being smuggled into an output of any other shape — including
   an arbitrary covenant — while spending an FT.

Because the code script hash covers `d0 <token_ref> || <12-byte epilogue>`, it is
per-token: two different tokens never share a sum.

### 9.3 What the NFT script enforces

Nothing beyond §9.1. The 63-byte script is `OP_PUSHINPUTREFSINGLETON <ref>
OP_DROP` followed by a bare P2PKH. There is no value check, no output-count check,
and no continuation check. "Exactly one NFT output must exist" is **not** a
property of this script; it is something a covenant can impose, and pyrxd's
soulbound and HTLC covenants do
([covenant building blocks](../concepts/covenant-building-blocks.md), §1).

### 9.4 What is not enforced anywhere

An implementer building on this specification MUST NOT present any of the
following as guarantees:

| Property | Reality |
|---|---|
| Royalties | Advisory only. See §11. |
| `policy.transferable = false` (soulbound) | Advisory metadata. An ordinary NFT script has no transfer restriction. A consensus-enforced version requires a purpose-built covenant (`src/pyrxd/glyph/soulbound_covenant.py`). |
| Container membership | The child's `in` field is a claim. Nothing on chain binds a token to a container, nothing stops a token naming a container it never touched, and nothing stops the same claim being made by any number of tokens. The strongest available check is that the container's ref also appears among the refs of the child's reveal outputs — see §7.5. A script-level link is not an option: consensus forbids it (§7.5.1). |
| `dmint.premine` matching the emitted supply | Nothing on chain reconciles them. pyrxd checks at build time; other producers need not. |
| `commit_outpoint` in the envelope | Self-declared; nothing verifies it. |
| Ref provenance | Consensus never checks that a ref was ever a Glyph mint. §9.1. |
| Token supply after a burn | Burning is legal, so "total supply" is an upper bound, not an invariant. |
| Creator signature covering the on-chain bytes | It covers pyrxd's decoded field set, not the received bytes. §10.3. |

## 10. Creator signature (OPTIONAL)

### 10.1 Algorithm

`src/pyrxd/glyph/creator.py:29-98`:

1. Build the envelope map with `creator` set to
   `{"pubkey": <hex>, "sig": "", "algo": <algo>}` — `sig` empty, `algo` always
   present.
2. `commit_hash = SHA256d(cbor_bytes_of_that_map)`.
3. `message = SHA256("glyph-v2-creator:" || commit_hash)` — 32 bytes.
4. `sig = ECDSA(private_key, message)`, low-S, DER-encoded, no further hashing.
5. Store the DER hex in `creator.sig`.

`creator.pubkey` MUST be a 33-byte compressed secp256k1 public key, hex-encoded
with an `02` or `03` prefix (`src/pyrxd/glyph/types.py:141-149`).

### 10.2 The canonicalisation caveat

The signing encoder is `cbor2.dumps(d)` — **without** `canonical=True`
(`src/pyrxd/glyph/creator.py:43`), whereas the on-chain envelope is encoded with
`canonical=True` (`src/pyrxd/glyph/payload.py:35`). Verified: for a metadata
object with more than one field the two encodings differ, so the signed byte
string is not the canonical form of the signed map.

Consequences an interoperating implementation MUST know:

- To verify a pyrxd-produced creator signature, an implementation MUST reproduce
  the **insertion order** of pyrxd's `to_cbor_dict`
  (`src/pyrxd/glyph/types.py:381-429`), not a canonical ordering. Using a
  canonical encoder here produces a different message and the signature fails.
- Note also that this makes the signature dependent on source-code field order —
  the exact fragility `canonical=True` was introduced to eliminate on the envelope
  path (`src/pyrxd/glyph/payload.py:26-33`).
- The `creator` sub-map used for signing always contains all three keys, whereas
  the published `creator` omits `sig` when empty and `algo` when it equals the
  default (`src/pyrxd/glyph/types.py:151-157`). Signing and verification agree,
  but the signed map is not the published map.

### 10.3 What the signature covers

Verification reconstructs the signing input from a **decoded** metadata object
(`src/pyrxd/glyph/creator.py:124-126`). It therefore attests to the field set
pyrxd models, not to the bytes on chain. Measured behaviour:

- Adding an unknown top-level CBOR field to a signed payload does **not**
  invalidate the signature under pyrxd's verifier — the field is dropped on decode
  and never reaches the reconstructed signing input.
- A payload whose `main.b` uses CBOR tag 64 does not round-trip: re-encoding a
  decoded copy yields different bytes and a different payload hash (verified
  against `tests/fixtures/glyph_reveal_cbor.bin`).

An implementation MUST NOT describe a valid creator signature as "the creator
signed this token's on-chain metadata". It signed the modelled subset.

## 11. Royalties are advisory

A royalty on an ordinary Glyph transfer is a social convention. Nothing in Radiant
consensus, and nothing in any script this specification defines, requires a
royalty output to exist. The evidence, checked rather than assumed
(`src/pyrxd/glyph/royalty.py:1-45`):

- Transfer outputs are P2PKH-gated. The FT epilogue constrains *how much of the
  token* may exist on the output side (§9.2); it says nothing about where **value**
  goes, so it cannot require a payment to anyone. The NFT script constrains
  nothing at all (§9.3).
- No covenant that ships in pyrxd references a royalty.
- Photonic Wallet — the default reference implementation — reaches the same
  structural conclusion. In `packages/lib/src/royaltyCovenant.ts` the NFT at rest
  lives in the ordinary `nftScript`; enforcement exists only once a holder
  *voluntarily* lists the token into a sale covenant, and that file's own "Honest
  scope" note records that the covenant cannot stop a malicious seller crafting a
  non-compliant listing, nor a holder gifting the token out of band.

A royalty **can** be made binding on a *buyer*, by locking the token into a
covenant that releases it only against required outputs. It **cannot** be made
binding on a *holder* who simply transfers, because the holder chooses the
transaction. pyrxd does not ship a listing covenant.

Arithmetic, for implementations that choose to honour a royalty
(`src/pyrxd/glyph/royalty.py:114-197`):

```
due = max(minimum, floor(sale_price * bps / 10_000))
```

with `bps` in `[0, 10000]`. With `splits`, each recipient receives
`floor(due * split_bps / bps)` and the residue goes to the top-level `address`, so
`sum(payouts) == due` exactly. Payouts are plain 25-byte P2PKH outputs carrying no
ref — which is precisely what makes a royalty safe to attach to an FT transfer: a
ref-free output contributes nothing to any conservation sum, so the royalty comes
out of the transaction's RXD side, never out of the token side
(`src/pyrxd/glyph/royalty.py:200-209`).

`sale_price` is the consideration the seller receives. There is no royalty on a
gift; a flat per-move fee is expressed as `minimum` with `sale_price = 0`.

## 12. Conformance requirements

Consolidated. Each entry cites the section that justifies it.

### 12.1 Producers

- MUST encode the envelope as a CBOR map with a `p` array (§4.3).
- MUST push `gly` before the CBOR body in the reveal scriptSig, and MUST select the
  push opcode by the length table in §4.1.
- MUST commit `SHA256d(cbor_bytes)` — excluding the marker — into the commit script
  (§4.6, §7.3).
- MUST set the commit script's ref-type byte to `0x52` for an NFT and `0x51`
  otherwise (§7.3).
- MUST embed `GlyphRef(commit_txid, commit_vout)` in the reveal's locking script
  (§5).
- MUST persist the exact CBOR bytes before broadcasting the commit (§6.1).
- MUST NOT exceed the size limits of §4.4.
- SHOULD encode canonically per RFC 8949 (§4.2).
- SHOULD wait for the commit to confirm before revealing (§6.3).
- SHOULD apply the protocol-marker combination rules of §8.1.
- MAY mint to a recipient other than the reveal signer (§6.3).

### 12.2 Decoders and indexers

- MUST hash received bytes, never a re-encoding, when checking a payload against a
  commit (§4.2).
- MUST NOT reject an envelope for non-canonical encoding (§4.2).
- MUST reject the inputs listed in §4.5.
- MUST unwrap CBOR tag 64 around `main.b` (§4.3).
- MUST walk scriptSig pushes to find the `gly` marker, supporting all four push
  opcodes, and MUST NOT assume a fixed offset (§4.1).
- MUST treat the ref extracted from the locking script as the token identity, and
  MUST resolve metadata from the transaction that spends the ref outpoint (§5).
- MUST walk scripts as an opcode stream when enumerating refs (§2.2).
- MUST sanitise attacker-controlled strings before display (§4.5).
- MUST NOT present the properties in §9.4 as guarantees.
- SHOULD ignore unknown envelope fields rather than fail.
- SHOULD resolve ref provenance against a trusted indexer before accepting a
  token as the advertised asset (§9.1).

### 12.3 Wallets accepting or moving tokens

- MUST filter to correctly-shaped token UTXOs before building a transfer. Feeding a
  plain P2PKH UTXO into an FT transfer produces a transaction that violates
  induction and is rejected (`src/pyrxd/glyph/script.py:89-96`).
- MUST size FT outputs from the unit count, because an FT output's value *is* its
  unit count (§7.2).
- MUST NOT take a transfer fee out of a token output — that burns units. Fees come
  from separate plain-RXD inputs.
- SHOULD honour a declared royalty when the transfer is a sale (§11), and MUST NOT
  describe doing so as enforcement.

## 13. Versioning

**Envelope version (`v`).** Absent means V1; `2` means V2. V2 adds `dmint`,
`creator`, `royalty`, `policy`, `rights`, `created`, and `commit_outpoint`.
Indexers use `v` to select a parser. A V1 dMint deploy MUST NOT carry a `v` field;
pyrxd refuses one at build time (`src/pyrxd/glyph/builder.py:410-418`).

**dMint contract version.** V1 and V2 are distinguished structurally, not by a
version field: V1's sixth state item is a fixed 8-byte target push (`0x08` + 8
bytes), V2's is a minimal-push `algoId`
(`src/pyrxd/glyph/dmint/builders.py:606-620`). In a mint scriptSig the
discriminator is the nonce width, 4 vs 8 bytes (§7.7).

**Relation to the pyrxd version.** This specification revision describes pyrxd
0.15.0. pyrxd is 0.x: the API and on-chain formats are **not yet stable**. Under
[the versioning and deprecation policy](../versioning-and-deprecation-policy.md),
"the Glyph CBOR envelope" is named explicitly as a wire format whose change is
**breaking-class**, so:

- A change to the envelope, to a locking-script template, or to ref derivation is
  breaking-class and MUST be called out in the CHANGELOG.
- A minor bump (`0.N → 0.N+1`) MAY carry such a change pre-1.0.
- A patch bump carries only backward-compatible fixes.
- At 1.0, breaking-class changes will require a major bump.

**What compatibility is promised today.** Tokens already on chain are permanent;
nothing in a pyrxd release can change bytes that are already mined. What a release
may change is what pyrxd *builds*. The mainnet-anchored golden tests listed in §17
are the mechanism that makes such a change loud: any drift in the FT, NFT, commit,
mutable, or dMint templates fails CI against real chain bytes.

## 14. Worked example

Anchored to the Radiant Glyph Protocol ("GLYPH") deployment on Radiant mainnet at
block 228604, whose CBOR body is checked into this repository as
`tests/fixtures/glyph_reveal_cbor.bin`. Every value below was produced by running
pyrxd against that fixture; none is illustrative.

**Transactions.**

```
commit: a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b
reveal: b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6
```

**Step 1 — the envelope.** `tests/fixtures/glyph_reveal_cbor.bin`, 65,569 bytes.
Its first 12 bytes are

```
b90006617082010466746963
```

`b9 0006` is a `map(6)` header using a 16-bit length; `61 70` is the text key `p`;
`82 01 04` is the array `[1, 4]` — FT + DMINT. Decoded top-level keys, in the order
they appear on chain:

```
p, ticker, name, desc, by, main
```

`ticker = "GLYPH"`, `name = "Glyph Protocol"`, `main.t = "image/png"`, and `main.b`
is CBOR tag 64 wrapping 65,430 bytes beginning `89504e470d0a1a0a` — a PNG. There
is no `v` key, so this is a V1 envelope. Note both non-canonicalities from §4.2 in
one artifact: the non-minimal `b9 0006` header and the unsorted key order.

**Step 2 — the payload hash.**

```
SHA256d(fixture) = 68d8f755ac95f399b3ea9d54978ebe20d71bfce50a2a8bc2771621de7c1af2ca
```

For contrast, the single SHA-256 is
`d22e1a8472bcb00f9cfba2c024879d30c852e46149919be58c5d7e091361355b` — it is not the
committed value. The commit uses `OP_HASH256`, which is the double hash.

**Step 3 — the commit output.** Deploy commit vout 0, the FT commit, owner PKH
`7d6c507735322c6bac9398317a65b4597072f0a6` — 75 bytes:

```
aa2068d8f755ac95f399b3ea9d54978ebe20d71bfce50a2a8bc2771621de7c1af2ca8803676c7988c0
c8c0c954807eda519d76a9147d6c507735322c6bac9398317a65b4597072f0a688ac
```

The payload hash at offset 2 is exactly the value from step 2 — this is the
commit → reveal linkage. Byte 48 is `0x51` (`OP_1`, NORMAL): an FT commit.

The same transaction's vout 33 is the NFT commit for the companion token, byte-identical
except the payload hash and byte 48 = `0x52`:

```
aa20ab4fed5bedc8864371751d6b8e04d2ac32c1495c25807a97c8537969626fcdcc8803676c7988c0
c8c0c954807eda529d76a9147d6c507735322c6bac9398317a65b4597072f0a688ac
```

Both are pinned at `tests/test_glyph_dmint.py:171-240`.

**Step 4 — the reveal scriptSig framing.** After `<sig> <pubkey>`, at offset 108 of
the live scriptSig:

```
03 67 6c 79        PUSH3 "gly"
4e 21 00 01 00     OP_PUSHDATA4, length 0x00010021 = 65569
<65569 bytes>      the CBOR body
```

Reproduced by `build_reveal_scriptsig_suffix(fixture)`, which yields 65,578 bytes
beginning `03676c794e21000100`. Pinned at `tests/test_glyph.py:506-530`.

**Step 5 — ref derivation.** The commit's FT commit output is
`a443d9df…878b:0`, so the token's genesis ref is that outpoint. In wire form:

```
GlyphRef(txid="a443d9df…878b", vout=0).to_bytes()
  = 8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a4 00000000
```

The txid is reversed; the vout is little-endian. This is the `tokenRef` that
appears in all 32 dMint contracts of the reveal, and in every FT output of the
token thereafter. The companion NFT commit at vout 33 gives
`…:33` → `8b87c3c7…43a4 21000000`, which is the singleton ref in the reveal's
public-facing NFT output.

**Step 6 — the resulting locking scripts.** Reveal vout 32 is the public-facing NFT
singleton for the companion token, of the shape
`d8 <commit:33 wire> 75 76a914 <pkh> 88ac`
([`docs/dmint-research-photonic-deploy.md`](../dmint-research-photonic-deploy.md), §3
vout table). Constructing that shape with the deploy PKH used above gives the
63-byte script

```
d88b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a4210000007576a914
7d6c507735322c6bac9398317a65b4597072f0a688ac
```

The recipient PKH of the live vout 32 was not read from chain here, so treat the
final 25 bytes as constructed rather than observed; the first 38 are the ref
binding and are fixed by the commit outpoint.

The FT lock for any holding of the token is the 75-byte script

```
76a914<owner_pkh>88ac bd d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646
dfd943a400000000 dec0e9aa76e378e4a269e69d
```

Note the two encodings of the same outpoint side by side: `…43a4 21000000` (wire,
vout 33 little-endian) versus the contract id an explorer would print,
`a443d9df…878b` + `00000021`.

**Step 7 — the first dMint contract.** Reveal vout 0, 241 bytes, state portion:

```
04 00000000                              height = 0
d8 8b87c3c7…43a4 01000000                contractRef = commit:1
d0 8b87c3c7…43a4 00000000                tokenRef    = commit:0
03 689009                                max_height  = 625000
03 50c300                                reward      = 50000
08 74da40a70d74da00                      target      = 0x00da740da740da74
```

then the 145-byte code epilogue beginning `bd`. The full bytes are pinned at
`tests/test_dmint_v1_deploy.py:1126-1168`.

**Verifying this yourself.** Every value above is reproducible from the repository:

```python
import cbor2
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, decode_payload
from pyrxd.glyph.script import build_commit_locking_script, hash_payload
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.types import Hex20

raw = open("tests/fixtures/glyph_reveal_cbor.bin", "rb").read()
assert hash_payload(raw).hex() == (
    "68d8f755ac95f399b3ea9d54978ebe20d71bfce50a2a8bc2771621de7c1af2ca"
)
assert list(cbor2.loads(raw)) == ["p", "ticker", "name", "desc", "by", "main"]
assert cbor2.dumps(cbor2.loads(raw), canonical=True) != raw    # §4.2
assert build_reveal_scriptsig_suffix(raw)[:9].hex() == "03676c794e21000100"

owner = Hex20(bytes.fromhex("7d6c507735322c6bac9398317a65b4597072f0a6"))
commit = build_commit_locking_script(hash_payload(raw), owner, is_nft=False)
assert commit[48] == 0x51 and len(commit) == 75

ref = GlyphRef(txid="a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b", vout=0)
assert ref.to_bytes().hex().endswith("00000000")
```

## 15. Deliberate divergences from Photonic Wallet

Photonic Wallet is the reference TypeScript implementation and pyrxd's default
reference. It is not treated as infallible. Where pyrxd diverges, it does so
deliberately and for a stated reason; an interoperating implementation needs to
know which behaviour it will encounter.

| Area | Photonic | pyrxd | Reason |
|---|---|---|---|
| Envelope encoding | Producer-order CBOR (the mainnet fixture is non-canonical — §14) | RFC 8949 canonical | Determinism across source refactors and re-encoders (`src/pyrxd/glyph/payload.py:26-33`). Consumers on both sides must accept either (§4.2). |
| Royalty `minimum` with `splits` | Each split computed independently; `minimum` never consulted, so a royalty declaring `bps=100, minimum=50000` pays the minimum with one recipient and ignores it with two | Total computed once, then divided | Photonic's version can pay the creator less than the recorded terms (`src/pyrxd/glyph/royalty.py:56-68`). |
| Royalty residue | Flooring loss and any uncovered bps are dropped | Routed to the top-level address; `sum(payouts) == due` exactly | Same reason. |
| Royalty `enforced` flag | Returns *no* outputs when `enforced` is false — making an advisory royalty mean "never paid" | No branch on the flag; passing a royalty is the decision to pay it | The flag is display/policy metadata, not a payment switch (`src/pyrxd/glyph/royalty.py:70-74`). |
| `dmint.premine` consistency | No bounds or consistency checks at all | Deploy refused if the advertised premine ≠ the emitted premine | A mismatch is a permanently mis-reported supply and it is silent (`src/pyrxd/glyph/builder.py:36-57`). |
| Mutable NFT script size | Documented as 175 bytes | 174 bytes | 174 is what the regex and the built script actually are (`src/pyrxd/glyph/script.py:332-335`). |
| V2 dMint Part A | Older shape prefixed `51 75` (`OP_1 OP_DROP`) | Opens directly at `c0 c8`, matching the post-2026-05-26 canonical redesign | Byte-matched to the current canonical source and validated by golden vector (`src/pyrxd/glyph/dmint/builders.py:112-144`). |
| V2 EPOCH / LWMA difficulty adjustment | Pre-fix bytecode overflows int64 and bricks the contract at a boundary mint | Divide-first with a 2^48 clamp on both sides of the multiply; LWMA floors `timeDelta` at 0 | Upstream fix (Radiant-Core/Photonic-Wallet#2), which pyrxd byte-matches (`src/pyrxd/glyph/dmint/builders.py:291-311, 252-264`). The mainnet LWMA deploy `dea3beb9…` predates it and is deliberately **not** used as a golden anchor. |
| ASERT shift | `OP_LSHIFT`/`OP_RSHIFT`, which Radiant evaluates as big-endian bit-string shifts — wrong for the 8-byte little-endian target | Unrolled `OP_2MUL`/`OP_2DIV` steps with per-step overflow caps | The shift opcodes diverge from the miner's bigint arithmetic for any nonzero drift (`src/pyrxd/glyph/dmint/builders.py:158-167`). |
| WAVE name location | `attrs.name` | Accepts `attrs.name` (canonical) or a top-level `name` (legacy) | Legacy pyrxd tokens exist on chain; they are accepted but will not resolve against RXinDexer (`src/pyrxd/glyph/builder.py:686-734`). |

## 16. Underspecified and implementation-defined

Recorded rather than invented. An implementation that needs one of these settled
should treat the current pyrxd behaviour as observed fact, not as a rule.

### 16.1 Envelope round-tripping is lossy

`decode_payload` builds a fixed-field object, so any key it does not know is
dropped. Measured: an unknown top-level key does not survive a decode. Combined
with the tag-64 media asymmetry (§10.3), **decode-then-encode is not an identity**
and MUST NOT be used to verify a payload against a commit hash.

`in` and `by` were part of this loss until 0.15.0 — observable on the reference
mainnet token, whose `by` refs (CBOR tag 64-wrapped) had no representation in
pyrxd's metadata type. Both now decode
(`GlyphMetadata.container_refs` / `.author_refs`) and re-encode as raw byte
strings. That last asymmetry is deliberate and matches how pyrxd already handles
`main.b`: it decodes tag 64 and emits untagged, so a tag-64 producer's payload
still does not round-trip byte-for-byte.

### 16.2 Container membership carries no on-chain guarantee

Settled since 0.15.0, and recorded here because the shape of what is *not*
specified matters: a container is a plain NFT (§7.5), membership is the child's
`in` claim, and the only check available to a reader is the output-ref
intersection of §7.5. What remains genuinely unspecified is what a reader should
do with a token whose `in` names a container that has since been burned, and
whether a container may be a member of another container (nothing forbids it;
nothing implements it either).

### 16.3 A second, incompatible envelope shape for ENCRYPTED / TIMELOCK

`EncryptedContentStub.to_dict()` (`src/pyrxd/glyph/encrypted_content.py`) produces
`{p, type, name, main, crypto}` where `main` is
`{type, hash, enc, size, chunks, scheme}` — a completely different shape from the
`{t, b}` media map of §4.3 — and adds a top-level `crypto` object. **The
relationship between the two `main` shapes is still unspecified**, which is what
keeps this entry open.

What has changed since this entry was written is the reachability, in both
directions, and unevenly:

- **Encoding.** `GlyphMetadata` carries the shape in `encrypted_main` and `crypto`,
  and `to_cbor_dict()` emits both, so the canonical-encoding rule of §4.2 now does
  apply to it — `pyrxd.glyph.timelock.build_timelock_mint` produces such an
  envelope and `GlyphClient.mint_timelocked_nft` / `pyrxd glyph timelock-mint` mint
  it. The emitted dict is asserted equal to `EncryptedContentStub.to_dict()` and to
  Photonic's own block-mode vector in
  `tests/test_glyph_timelock_write_side_is_reachable.py`.
- **Decoding.** `decode_payload` reads `crypto.timelock` and nothing else from the
  `crypto` object; `main` in the encrypted shape still has no `t`/`b` keys, so it
  still decodes to `main = None`. This asymmetry is deliberate rather than an
  oversight — the per-recipient wraps in `crypto.recipients` are key material, and
  surfacing them through the inspect path is not something to do incidentally — but
  it does mean `decode(encode(x)) != x` for an encrypted envelope. A caller that
  needs the exact bytes a token arrived as reads `GlyphMetadata.source_cbor`.

### 16.4 Commit script ref-type byte is under-validated

`COMMIT_SCRIPT_RE` (`src/pyrxd/glyph/script.py:119`) matches any byte at the
ref-type position, not only `0x51`/`0x52`. A script with, say, `0x53` there
classifies as a commit but describes a ref type Radiant does not define. Behaviour
for such a script is undefined.

### 16.5 Carrier values

No consensus rule fixes the photon value of a commit, contract, or NFT carrier
output. Radiant-Core has no dust threshold — `GetDustThreshold` returns 1 and
`IsDust` is `nValue <= 0` — so any output worth at least one photon is standard
(`src/pyrxd/glyph/builder.py:930-942`, citing `src/policy/policy.cpp:19-25` at
`afdf57b1`). The 1-photon value on dMint contract outputs is pinned by the
**covenant** (`OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY`,
`src/pyrxd/glyph/dmint/builders.py:448`), not by the chain. The 546-photon floors
in pyrxd are wallet policy, not chain rules, and are labelled as such at
`src/pyrxd/glyph/ft.py:71`.

### 16.6 Envelope placement on multi-input reveals

The commit covenant only constrains the input that spends it. Whether an envelope
on some *other* input is meaningful is unspecified; pyrxd's scanner will find and
use it (`src/pyrxd/glyph/scanner.py:297-308`), which is lenient rather than
normative.

## 17. Provenance of the claims in this document

Every script template here is pinned byte-for-byte against a real mainnet
transaction in CI. The anchors:

| Artifact | Anchor transaction | Test |
|---|---|---|
| FT lock (75 B) | `ac7f1f70…0ae4` vout 0 (RBG transfer) | `tests/test_dmint_module.py:632+` |
| NFT lock (63 B) | `27390efa…be7e` vout 0 | `tests/test_glyph.py:129-198` |
| Commit script, both variants (75 B) | `a443d9df…878b` vouts 0 and 33 | `tests/test_glyph_dmint.py:171-240` |
| CBOR envelope + reveal framing (65,569 B) | `b965b32d…9dd6` vin 0 | `tests/test_glyph.py:435-530` |
| dMint V1 contract (241 B) | `b965b32d…9dd6` vout 0 | `tests/test_dmint_v1_deploy.py:1098-1214` |
| dMint V1 mint reward output (75 B) | `146a4d68…f3c` vout 1 | `tests/test_dmint_v1_mint.py:253-291` |
| dMint V2 contract, FIXED (380 B) | `95335028…bb16fb09` vout 0 | `tests/test_dmint_v2_mainnet_golden.py:23-68` |
| Mutable NFT body (102 B) | Photonic `parseMutableScript` reference | `tests/test_glyph_v2.py:110-127` |
| Container lock (63 B) + `in` envelope | frozen goldfile | `tests/test_golden_vectors.py`, `TestFrozenContainerVectors` |
| Canonical CBOR determinism | frozen goldfile | `tests/test_golden_vectors.py:42-143` |
| Envelope push framing across boundaries | property-based | `tests/test_glyph_cbor_roundtrip.py:184-232` |
| Genesis ref = commit outpoint | round-trip through the built reveal | `tests/cli/test_glyph_cmds.py`, `tests/test_glyph_mint_facade.py:212-216` |

Measurements stated in this document that are **not** covered by an existing test —
the non-canonicality of the mainnet fixture (§4.2, §14), the creator-signature
canonicalisation gap (§10.2), and the signature's indifference to unknown fields
(§10.3) — were produced by running pyrxd against the checked-in fixture and
builders while writing this specification. They are reproducible from the
snippets given, but they are not yet regression-locked in CI.

### 17.1 Consensus behaviour verified on a node

The CONTAINER claims of §7.5 are not derived from reading Radiant-Core; they were
put to a **Radiant Core v3.1.1 regtest node** and the reject reasons recorded.
`tests/test_container_regtest_e2e.py` (opt-in: `RADIANT_REGTEST=1 pytest -m
integration`) reproduces every row.

| Transaction | Result | Node's reason |
|---|---|---|
| Container + member reveal: spend the container UTXO, output `[child NFT, container re-created]` | **accepted** | — |
| Container transferred with `build_nft_transfer_tx` | **accepted** | — |
| Output carrying `0xd0 <child_ref>` **and** a sibling output re-creating the child as `0xd8 <child_ref>` | rejected | `bad-txns-inputs-outputs-invalid-transaction-reference-operations` |
| Same, with the child **not** re-created (the child NFT is consumed) | **accepted** — which is the hazard | — |
| Any spend of the resulting 100-byte output | rejected | `mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)` |
| Re-minting the consumed child as `0xd8 <child_ref>` from that output | rejected | `bad-txns-inputs-outputs-invalid-transaction-reference-operations` |
| Container naming an **FT** ref, with the FT kept alive in a sibling output | rejected | `mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation)` |
| A token claiming `in` for a container it never spent | **accepted** — membership is advisory (§9.4) | — |

## See also

- [Glossary](../concepts/glossary.md) — term definitions
- [Understanding Glyph structures and terminology](../concepts/glyph-structures-and-terminology.md)
- [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md)
- [Covenant building blocks](../concepts/covenant-building-blocks.md) — what covenants can and cannot enforce
- [V1 dMint deploys](../concepts/dmint-v1-deploy.md) and [V1 dMint mint mechanics](../concepts/v1-mint-mechanics.md)
- [Versioning and deprecation policy](../versioning-and-deprecation-policy.md)
- [`conformance/README.md`](https://github.com/MudwoodLabs/pyrxd/blob/main/conformance/README.md) — the machine-readable vector suites
