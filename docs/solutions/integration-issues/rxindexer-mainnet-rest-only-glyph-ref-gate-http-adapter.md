---
title: Mainnet RXinDexer is REST-only — the ElectrumX-ws REF gate had no endpoint
problem_type: integration_issue
component: pyrxd.gravity / glyph REF authenticity gate
severity: high
date_solved: 2026-06-04
status: solved
symptoms:
  - The proven RxinDexerRefAdapter resolves a genesis ref via the ElectrumX-ws method glyph.get_token, which works on the glyph-enabled regtest electrumx but has NO endpoint on the mainnet RXinDexer deployment.
  - The mainnet RXinDexer on host tr (/srv/rxindexer) listens ONLY on the REST api (127.0.0.1:8000); the glyph electrumx-ws ports (50010/50011/50012) are not listening.
  - First REST attempts 404'd because I queried GET /tokens/{bare_txid} instead of the 72-hex wire ref.
  - The radiant MCP (radiant_get_token) returned "unknown method glyph.get_token_info" against a public vanilla Radiant electrumx that does not serve glyph methods.
  - pyrxd's ElectrumXClient is WebSocket-only and cannot connect to a raw-TCP/SSL electrumx port (e.g. :50012).
root_cause: >
  An indexer that exposes both an ElectrumX-ws interface and a FastAPI REST api can be deployed
  with only one of them running. The proven REF gate spoke ElectrumX-ws (the regtest path); the
  mainnet deployment runs the REST api only, so the gate had no live endpoint until a REST adapter
  was written. Compounding it: the REST lookup keys on the 72-hex wire ref, not a bare txid, and the
  URL key and the response identifier use different txid byte orders.
tags: [rxindexer, electrumx, rest-api, glyph, nft, ref-gate, ref-authenticity, byte-order, gravity, htlc, mainnet, deployment, eth-rxd-swap]
related_files:
  - scripts/_glyph_ref_http.py
  - scripts/eth_swap_run.py
  - src/pyrxd/gravity/radiant_leg.py
  - src/pyrxd/gravity/ref_authenticity.py
  - src/pyrxd/glyph/types.py
related_solutions:
  - ../design-decisions/spv-oracle-swap-is-not-atomic-use-htlc.md
  - ../design-decisions/spv-swap-deprecated-primitive-retained.md
---

# Mainnet RXinDexer is REST-only — the ElectrumX-ws REF gate had no endpoint

Resolving a Glyph (NFT) by its **genesis ref** is the load-bearing R1 forgery defense in the
ETH↔RXD HTLC swap: the covenant binds `reveal_txid:0`, and the swap coordinator's REF gate must
confirm that ref is a genuine on-chain `gly` reveal (not a self-consistent fake singleton) before
locking the asset. The proven gate spoke ElectrumX-ws. Taking the swap to **Radiant mainnet**
surfaced that the production indexer doesn't serve that interface.

## Symptom

- `RxinDexerRefAdapter` (`src/pyrxd/gravity/radiant_leg.py`) resolves a ref via the ElectrumX-ws
  method `glyph.get_token` over `wss://…`. This works against the regtest stack's glyph-enabled
  electrumx but there is **no such endpoint on mainnet**.
- The mainnet RXinDexer on host `tr` (`/srv/rxindexer`) runs **only** the indexer + REST api
  (`rxindexer-api` on `127.0.0.1:8000`). The glyph electrumx-ws SERVICES (50010 tcp / 50011 wss /
  50012 ssl) are **not listening**.
- A public vanilla Radiant electrumx (`electrumx.radiant4people.com:50012`, raw SSL) does **not**
  serve glyph methods (`radiant_get_token` → "unknown method glyph.get_token_info"), and pyrxd's
  `ElectrumXClient` is WebSocket-only so it can't even connect to a raw-TCP/SSL electrumx port.

Net effect: the REF gate that the whole swap's integrity depends on had no callable endpoint on the
chain where real value moves.

## Investigation (what didn't work, and why)

1. **Point the existing adapter at a public electrumx.** Failed two ways: the public server doesn't
   index glyphs (wrong method namespace), and pyrxd's `ElectrumXClient` needs a `wss://` port, not
   the raw-SSL `:50012`.
2. **Query the mainnet REST api with the bare txid** (`GET /tokens/{txid}`). Returned 404. The api
   keys a token on its **72-hex wire ref**, not a bare txid.
3. **Stand up / sync a glyph electrumx-ws on tr.** Rejected — a full electrumx sync is heavy and
   unnecessary once the REST resolution path was understood.

## Root cause

Two independent facts had to line up:

1. **Deployment shape.** RXinDexer ships both an ElectrumX-ws interface *and* a FastAPI REST api,
   but a given deployment may run only one. Mainnet `tr` runs the REST api only. (Verified live:
   `ss -tlnp` / the running services on `tr` show `:8000` bound to localhost; 50010/11/12 absent.)
2. **Lookup key + byte order.** The REST per-token route keys on the **72-hex wire ref**
   (`GlyphRef.to_bytes().hex()` = 36 bytes = txid + vout). And there is a **byte-order asymmetry**
   between the URL key and the returned identifier (see below).

## Solution

A small HTTP adapter, `scripts/_glyph_ref_http.py::SshTrHttpRefAdapter`, that implements the same
`RefAuthenticityIndexer` protocol (one async `resolve_ref`) and resolves the ref over the REST api
via `ssh tr curl`. It is wired into `scripts/eth_swap_run.py` as the **default** mainnet NFT REF
gate (used whenever `--rxd-indexer-ws` is omitted); the ElectrumX-ws adapter remains available for
the regtest path.

```python
async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
    ref = GlyphRef.from_bytes(bytes(genesis_ref))     # validates the 36-byte wire ref (raises -> fail-closed)
    query_ref = ref.txid + struct.pack("<I", ref.vout).hex()   # URL key: DISPLAY-order txid + LE vout
    token_id_expected = bytes(genesis_ref).hex()               # response id: INTERNAL-order txid + LE vout
    body, code = await self._api_get(f"/tokens/{query_ref}")   # ssh <host> curl http://127.0.0.1:8000/...
    if code == 404:
        return None                                  # unknown ref -> R1 forgery / not a real glyph -> fail closed
    if code != 200:
        raise NetworkError(...)                      # transient/5xx -> raise -> gate fails closed (does NOT pass)
    token = json.loads(body)
    if str(token.get("token_id", "")).lower() != token_id_expected.lower():
        return None                                  # id mismatch -> fail closed
    confs = await self._chain_io.confirmations(ref.txid)   # REST response carries no confs; read from chain
    return ResolvedRef(
        genesis_outpoint=bytes(genesis_ref),
        has_gly_marker=True,                         # a resolvable RXinDexer token IS a genuine gly reveal
        payload_hash=b"",                            # REST api doesn't expose the envelope hash; gate uses it only if expected set
        confirmations=confs,
    )
```

**The byte-order subtlety (the part that costs an hour if you guess).** `GlyphRef` keeps the txid in
**display** order in `.txid` and reverses it to **internal** order in `.to_bytes()`
(`src/pyrxd/glyph/types.py:45` — `bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)`):

- **URL key** (`/tokens/{ref}`): `ref.txid` (display order) + 4-byte little-endian vout, hex.
- **Response identifier** that you bind against: `bytes(genesis_ref).hex()` = **internal**-order
  (reversed) txid + LE vout = `GlyphRef.to_bytes().hex()`.

So the txid appears in *opposite* byte order in the request URL versus the value you compare in the
response. This was confirmed empirically, not assumed.

### Live verification (ground truth)

| Ref queried | Result |
| --- | --- |
| `ff5c20f6…:0` (genuine mainnet glyph) | `ResolvedRef(has_gly_marker=True, confirmations=3378, genesis_outpoint == ref)` |
| `3c0cf043…:0` (genuine mainnet glyph) | `ResolvedRef(confirmations=3914)` |
| `de…de:0` (fabricated ref) | HTTP 404 → `None` (gate fails closed — R1 forgery rejected) |

### Source-vs-deployment skew — a load-bearing caveat

The **live endpoint is authoritative**, and there is measurable skew between the deployed mainnet api
and the local RXinDexer source checkout (`~/apps/RXinDexer`):

- The deployed `/tokens/{ref}` route returns a JSON object whose **`token_id`** field equals the
  72-hex internal wire ref (this is what the live test bound against and what the adapter checks).
- The local source checkout instead shows a `GET /glyphs/{ref}` handler whose response uses a
  **`ref`** field formatted as display `txid_vout` (e.g. `abcd…_0`), with the `/tokens/{ref}/…`
  routes being the holders/supply/history siblings. That does **not** match the live `/tokens/{ref}`
  + `token_id` contract the adapter relies on — i.e. the checkout is a different version than what
  runs on `tr`.

This skew is *safe but brittle*: if the deployed api ever changes the field name or shape, the
adapter's `token.get("token_id")` check returns `None` and the gate **fails closed** (blocks the
swap; never passes a forgery). No fund-loss path, but a legitimate swap could be blocked until the
adapter is reconciled with the then-current api. **Trust the live endpoint over the checkout; pin the
adapter to the field the live api actually returns.**

## Prevention

- **When an indexer offers both ElectrumX-ws and REST, never assume both run.** Before wiring an
  adapter, check the *actual* listening services on the target host (`ss -tlnp`, `docker ps`,
  systemd units) — not the project README or a regtest compose file.
- **Read the indexer source for the exact lookup-key format** rather than guessing from URL
  conventions. Here the key is the 72-hex wire ref with a display-vs-internal txid byte-order
  asymmetry; a bare txid 404s.
- **Treat the live endpoint as the contract, the source checkout as a hint.** Version skew between a
  local checkout and a deployed service is normal; verify the response shape against the live api and
  pin the adapter to the field it actually returns.
- **Keep the security property fail-closed across the transport swap.** Both the ElectrumX-ws and the
  REST adapter must return `None` (or raise) on unknown ref / transient error so the REF gate refuses
  rather than passes. The R1 fake-singleton defense is only as good as its weakest transport.
- **Add a smoke check** that resolves a known-good mainnet ref and a fabricated ref before each
  real-value run — proves the live api shape still matches the adapter and that forgeries still 404.

## Status

Solved and live-verified (2026-06-04). `SshTrHttpRefAdapter` is the default mainnet NFT REF gate in
`scripts/eth_swap_run.py`; lint-clean; genuine mainnet glyphs resolve and a fabricated ref fails
closed. The supervised mainnet Glyph↔ETH run is gated only on the operator's ETH-side inputs.

## Related documentation

- [GlyphRef wire format and byte order](../../concepts/glyph-structures-and-terminology.md) — the
  display-vs-internal txid ordering this adapter has to get right.
- [Gravity cross-chain swap overview](../../concepts/gravity.md) — where the REF gate sits in the
  HTLC swap (Path B).
- [SPV-oracle swap is not atomic — use HTLC](../design-decisions/spv-oracle-swap-is-not-atomic-use-htlc.md)
  — why the swap is HTLC-based and the REF gate matters.
- [SPV swap deprecated, primitive retained](../design-decisions/spv-swap-deprecated-primitive-retained.md)
  — the retained one-way oracle/gate context.
