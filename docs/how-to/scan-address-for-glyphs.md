# How to scan an address for Glyphs

**Who this page is for:** anyone who has a Radiant address and wants the
list of Glyph tokens (NFTs and FTs) currently held at it. The recipe is
async, connects to ElectrumX once, and returns typed objects you can
filter and inspect in-process.

This page is a recipe. For *why* Radiant FTs are on-chain script bytes
rather than indexer-tracked balances, read
[Radiant FTs are on-chain (not metadata-on-P2PKH)](../concepts/radiant-fts-are-on-chain.md)
first — the scanner takes that model as given.

---

## TL;DR — three lines

```python
from pyrxd.glyph.scanner import GlyphScanner
from pyrxd.network.electrumx import ElectrumXClient

async with ElectrumXClient(["wss://your.electrumx.host:50004"]) as client:
    items = await GlyphScanner(client).scan_address(address)
```

`items` is a `list[GlyphNft | GlyphFt]`. Filter with `isinstance`.

---

## The full recipe

```python
import asyncio

from pyrxd.glyph.scanner import GlyphScanner
from pyrxd.glyph.types import GlyphFt, GlyphNft
from pyrxd.network.electrumx import ElectrumXClient


async def list_glyphs(address: str, server_url: str) -> None:
    async with ElectrumXClient([server_url]) as client:
        scanner = GlyphScanner(client)
        items = await scanner.scan_address(address)

    for item in items:
        if isinstance(item, GlyphNft):
            name = item.metadata.name if item.metadata else "(metadata unresolved)"
            print(f"NFT  ref={item.ref.txid}:{item.ref.vout}  name={name!r}")
        elif isinstance(item, GlyphFt):
            ticker = item.metadata.ticker if item.metadata else ""
            print(
                f"FT   ref={item.ref.txid}:{item.ref.vout}  "
                f"amount={item.amount}  ticker={ticker!r}"
            )


asyncio.run(list_glyphs(
    address="1YourRadiantAddressHere...",
    server_url="wss://your.electrumx.host:50004",
))
```

A few things to know:

- **One scanner per client.** `GlyphScanner` does not own the connection
  lifecycle. Use `ElectrumXClient` as an `async with` context manager and
  pass it in. The scanner reuses the open WebSocket for every fetch.
- **Concurrency is automatic.** Per-UTXO source-tx fetches and
  reveal-metadata resolutions are each batched through `asyncio.gather`,
  and each distinct `ref` is resolved once no matter how many UTXOs
  carry it. A 100-Glyph wallet pays a few round trips of latency, not
  200.
- **A failed reveal does not poison the result.** If the reveal for one
  Glyph cannot be fetched, that item still returns with
  `metadata=None`; the others come back with their metadata.
- **There is also `scan_script_hash(...)`** if you have already
  converted the address to a 32-byte script hash (e.g. for a non-P2PKH
  template).

---

## Interpreting the result

| Result entry | When | Notable fields |
| --- | --- | --- |
| `GlyphNft`   | UTXO's locking script is the canonical 63-byte NFT singleton shape | `ref`, `owner_pkh`, `metadata` (or `None`, see below) |
| `GlyphFt`    | UTXO's locking script is the canonical 75-byte FT shape | `ref`, `owner_pkh`, `amount` (photons), `metadata` (or `None`, see below) |

`ref` is a `GlyphRef(txid, vout)` — the outpoint that uniquely
identifies the token. Two `GlyphFt` entries with the same `ref` are the
same token (split across multiple UTXOs); `ref.txid` plus a colon plus
`ref.vout` is the form Radiant explorers display.

### Where the metadata comes from

`ref` is the token's **genesis outpoint, which is the commit outpoint** —
not the reveal txid. A mint is two transactions:

```text
commit tx                          reveal tx (spends commit vout)
┌───────────────────────────┐      ┌────────────────────────────────┐
│ in[0]: plain P2PKH funding│  ──▶ │ in[0] scriptSig:               │
│ out[v]: commit script     │      │   <sig> <pubkey> "gly" <CBOR>  │◀── metadata
└───────────────────────────┘      │ out[0]: NFT/FT lock            │
            ▲                      │   …ref = commit_txid:v         │
            └── ref points HERE    └────────────────────────────────┘
```

The CBOR metadata lives in the scriptSig of the input that **spends**
`ref.txid:ref.vout` — that is, in the reveal. The commit transaction
itself has no `gly` marker anywhere, so fetching `ref.txid` and reading
`input[0]` finds only a funding spend.

The scanner resolves the reveal for you. If the UTXO you hold came
straight out of the reveal, that tx *is* the reveal and no extra lookup
happens; otherwise the scanner asks the indexer for the history of the
commit output's script hash and picks the transaction whose input spends
the ref.

`metadata` is `None` only when that resolution fails — an indexer with no
history for the commit output, an unfetchable reveal, or a reveal whose
envelope pyrxd cannot decode. A plain transfer is *not* a reason for
`None`: transfers resolve the same metadata as freshly minted outputs,
one hop further back.

---

## Filter by Glyph type

The scanner returns `GlyphNft` and `GlyphFt` objects. Filter by class:

```python
nfts = [i for i in items if isinstance(i, GlyphNft)]
fts  = [i for i in items if isinstance(i, GlyphFt)]
```

Sum a token balance by ref:

```python
from collections import defaultdict

balances: dict[tuple[str, int], int] = defaultdict(int)
for i in items:
    if isinstance(i, GlyphFt):
        balances[(i.ref.txid, i.ref.vout)] += i.amount
```

If you also want to filter on FT vs. dMint-FT vs. WAVE vs. plain NFT,
read the `metadata.protocol` list:

```python
from pyrxd.glyph.types import GlyphProtocol

dmint_fts = [
    i for i in items
    if isinstance(i, GlyphFt)
    and i.metadata is not None
    and GlyphProtocol.DMINT in i.metadata.protocol
]
```

Items with `metadata=None` cannot be filtered this way — the protocol
list lives in the reveal CBOR, and the scanner could not reach it. To
chase one down by hand, remember that `item.ref` is the *commit*
outpoint: fetch `item.ref.txid`, hash its output script at
`item.ref.vout` into an ElectrumX script hash, and look through
`get_history(...)` for the transaction that spends that outpoint. That
is the reveal.

### One thing the scanner does *not* return

The classifier underneath the scanner also recognises **dMint
contract** outputs and **mutable-NFT (MUT)** outputs. The current
scanner only emits `GlyphNft` and `GlyphFt`, so dMint contract UTXOs
and MUT UTXOs held at the address are silently skipped. If you need
those, parse the UTXO scripts directly with `GlyphInspector` from
`pyrxd.glyph.inspector` — that's the same classifier the scanner uses
internally.

---

## Trust boundary: structural match, not consensus

The scanner classifies UTXOs the same way the `pyrxd glyph inspect`
CLI tool does — by **structural pattern match** on the locking-script
bytes. A 75-byte script ending with the canonical FT-CSH fingerprint is
reported as an FT; a 63-byte script matching the NFT singleton shape is
reported as an NFT. (A dedicated concept page on the inspect tool is in
flight; until it lands, the implementation in
[`src/pyrxd/glyph/inspector.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/glyph/inspector.py)
is the canonical reference.)

That tells you two things — and nothing more:

1. **The chain will treat this UTXO under Radiant's ref-conservation
   rules.** This is a consensus fact: the byte shape determines what
   `OP_PUSHINPUTREF` enforcement applies. The scanner is correct here.
2. **The output is structurally Glyph-shaped.** No claim is made about
   whether a particular off-chain protocol indexer (Photonic, an
   explorer, a marketplace) will accept this exact byte pattern as a
   valid token of the protocol version it implements.

The scanner does **not** simulate any indexer. A non-canonical CBOR
field, a protocol version the indexer doesn't recognise, a soft rule
about reveal-tx shape — none of those are checked. If you need
indexer-level agreement (e.g. "will Photonic Wallet display this token
the same way I see it?") you have to cross-check with that indexer
separately.

Same caveat applies as for `pyrxd glyph inspect`: pattern match, not
semantic correctness.

---

## References

- Scanner source:
  [`src/pyrxd/glyph/scanner.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/glyph/scanner.py)
- Classifier (used internally by the scanner):
  [`src/pyrxd/glyph/inspector.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/glyph/inspector.py)
- ElectrumX client:
  [`src/pyrxd/network/electrumx.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/network/electrumx.py)
- Result types:
  [`src/pyrxd/glyph/types.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/glyph/types.py)
- Scanner tests (canonical usage):
  [`tests/test_glyph_scanner.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/tests/test_glyph_scanner.py)
- Conceptual background: [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md)
- Same classifier from the CLI: the `pyrxd glyph inspect` tool (a
  dedicated concept page is in flight; meanwhile see
  [`src/pyrxd/glyph/inspector.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/glyph/inspector.py))
