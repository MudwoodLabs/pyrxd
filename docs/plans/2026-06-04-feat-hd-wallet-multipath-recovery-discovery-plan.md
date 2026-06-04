---
title: HD wallet multi-path recovery / account-discovery for pyrxd
date: 2026-06-04
status: COMPLETE (P1–P5) on feat/hd-multipath-recovery-discovery — task ci green (3657 passed, 87.44% cov, mypy clean). Uncommitted; CLI + lib + how-to doc all in.
method: Source-grounded design. All file:line claims verified on fix/ghas-token-permissions against src/pyrxd/hd/wallet.py, src/pyrxd/cli/*, and upstream Radiant-Core/Photonic-Wallet master (packages/app/src/keys.ts probeCoinTypeFromHistory) @ 2026-06-04.
motivation: A community member's RXD is "stuck" in Chainbow — balance visible on the explorer but not in any wallet that restores the seed, because each wallet version derives a different address. Root cause is BIP44 coin-type / account fragmentation across the Radiant wallet ecosystem (Chainbow, Photonic, Electron, Samara, Tangem, pyrxd). pyrxd already has every primitive needed to resolve this; it just isn't exposed as a discovery operation.
---

# §0. Problem statement

A BIP39 seed does not define one address — it defines a tree. Which address a
wallet shows depends on its BIP44 path `m/44'/<coin_type>'/<account>'/<change>/<index>`.
The Radiant ecosystem never agreed on `coin_type`, so the same seed yields
different addresses (and apparently-empty balances) across wallets and across
versions of the *same* wallet:

| coin_type | Used by | Source |
|---|---|---|
| `0` | Photonic ≤ v2.x (legacy), Electron-Radiant, likely Chainbow | [hd/wallet.py:75-81](../../src/pyrxd/hd/wallet.py#L75-L81); Photonic `LEGACY_COIN_TYPE` |
| `512` | SLIP-0044 spec, Tangem, Photonic ≥ v3.0.0 | SLIP-0044 registry; Photonic `RADIANT_COIN_TYPE` |
| `236` | pre-#14 pyrxd (BSV coin type) | [hd/wallet.py:79-81](../../src/pyrxd/hd/wallet.py#L79-L81) |

**The symptom that motivated this:** "import seed on V2 → diff address; V3 on V2 →
diff address; nothing shows up; explorer says funds are there." That is exactly a
path mismatch, not a lost key.

**Prior art (the bar to beat):** upstream Photonic v3.0.1 added
`probeCoinTypeFromHistory` ([Radiant-Core/Photonic-Wallet] `packages/app/src/keys.ts`).
It is a recovery probe — but a **2×2** one: it tries coin types `{0, 512}` at
exactly two fixed leaves (`m/44'/ct'/0'/0/0` and `…/0/1`). It does **not** scan
address indices, accounts, or coin type `236`. This plan delivers the **strict
superset** as a reusable SDK primitive: coin types × accounts × gap-limit indices
on both chains, fully offline-derived.

# §1. Goals / non-goals

**Goals**
1. `HdWallet.discover(...)` — a **read-only** account-discovery API that, given a
   mnemonic, returns every `(coin_type, account, change, index, address, balance)`
   that has on-chain history.
2. `pyrxd wallet recover --scan` — CLI wrapping the above with human + `--json` output.
3. A derivation **cross-check test** proving pyrxd's BIP32 produces byte-identical
   addresses to `@scure/bip32` (Photonic/Chainbow stack) at the candidate paths.

**Non-goals (explicit)**
- **No sweeping / spending.** Discovery reports *where* the funds are. Moving them
  stays a separate, explicit `HdWallet.send_max` step the user invokes after seeing
  the report. This keeps recovery on the safe side of the signing/broadcast boundary.
- **No new network stack.** Reuse `ElectrumXClient` + the existing gap-limit
  `refresh` machinery.
- **No mnemonic persistence** beyond what the user already opts into; discovery is a
  transient, in-memory operation.

# §2. What already exists (verified — this is mostly wiring)

- `HdWallet.from_mnemonic(mnemonic, passphrase, account, coin_type)` — parameterized
  path; builds the account xprv at `m/44'/<coin_type>'/<account>'`
  ([hd/wallet.py:294-325](../../src/pyrxd/hd/wallet.py#L294-L325)).
- `HdWallet.refresh(client)` — BIP44 gap-limit scan of **both** external (change=0)
  and internal (change=1) chains, gap=20, re-raises network errors instead of
  silently marking addresses unused (N5) ([hd/wallet.py:605-665](../../src/pyrxd/hd/wallet.py#L605-L665)).
- `HdWallet.get_balance(client)` / `get_utxos(client)` — per-address aggregation
  ([hd/wallet.py:695-728](../../src/pyrxd/hd/wallet.py#L695-L728)).
- `AddressRecord{address, change, index, used}` — already records everything a hit
  needs except coin_type/account (carried by the wallet instance).
- CLI: `wallet_group` exists ([cli/wallet_cmds.py](../../src/pyrxd/cli/wallet_cmds.py));
  `CliContext.make_client()` builds an `ElectrumXClient([url])` from config/`--electrumx`
  (default `wss://electrumx.radiant4people.com:50022/`) ([cli/context.py:47-53](../../src/pyrxd/cli/context.py#L47-L53),
  [cli/config.py:39](../../src/pyrxd/cli/config.py#L39)).
- Cross-check fixtures already in tree: `scripts/gen-photonic-vectors`,
  `scripts/derive_photonic.js` (the `@scure/bip32` reference).

**Net:** the discovery loop is ~60–90 lines over existing methods. The real work is
the test gate, the CLI command, docs, and a security pass — i.e. the published-library bar.

# §3. Design

## 3.1 Library API — `HdWallet.discover`

A classmethod (it constructs one wallet per candidate, so it can't be an instance
method on a single pre-built wallet):

```python
@dataclass(frozen=True)
class DiscoveryHit:
    coin_type: int
    account: int
    change: int          # 0 = receive, 1 = change
    index: int
    address: str
    confirmed: int       # photons
    unconfirmed: int     # photons
    path: str            # "m/44'/<ct>'/<acct>'/<change>/<index>"

@dataclass(frozen=True)
class DiscoveryReport:
    hits: list[DiscoveryHit]
    scanned: list[tuple[int, int]]      # (coin_type, account) pairs actually scanned
    total_confirmed: int
    total_unconfirmed: int

@classmethod
async def discover(
    cls,
    client: ElectrumXClient,
    mnemonic: str,
    *,
    passphrase: str = "",
    coin_types: Sequence[int] = (0, 512, 236),
    accounts: Sequence[int] = (0, 1, 2),
    gap_limit: int = _GAP_LIMIT,        # 20, reuse the existing constant
) -> DiscoveryReport: ...
```

Behavior:
1. For each `(coin_type, account)` pair: `w = cls.from_mnemonic(mnemonic, passphrase,
   account=account, coin_type=coin_type)`; `await w.refresh(client)`.
2. For every `AddressRecord` with `used=True`, fetch per-address balance (reuse the
   `get_balance` fan-out, but retain the per-address split so each hit reports its own
   amount and path).
3. Aggregate into `DiscoveryReport`, sorted hits-first by descending confirmed balance.
4. **Offline derivation, network only for scripthash history/balance** — the mnemonic
   never crosses the wire; only derived addresses do.

Error policy: a network failure during one `(coin_type, account)` scan **propagates**
(consistent with `refresh`'s N5 fail-loud contract) — a silent "empty" here is the
exact failure mode that makes a funded wallet look lost. Caller (CLI) decides whether
to continue to the next candidate or abort; default = abort with a clear message,
since a partial scan reported as complete is dangerous.

## 3.2 CLI — `pyrxd wallet recover --scan`

```
pyrxd wallet recover --scan [--coin-types 0,512,236] [--accounts 0,1,2]
                            [--gap 20] [--passphrase]
```

- Reads the mnemonic via `prompt_mnemonic_input` (existing helper) — **never** a CLI
  arg or env var (shell history / process-list leak).
- Human output: a table of hits with full path + balance, then a one-line summary
  ("Found 1234567 photons at m/44'/0'/0'/0/0 (coin type 0 — Photonic legacy / Chainbow)").
- `--json`: emits `DiscoveryReport` as JSON for tooling.
- If zero hits: explicit "no on-chain history at any scanned path" + the next-step
  hint (widen `--coin-types`/`--accounts`, or supply the funded address).
- Annotate known coin types with their ecosystem label (0 → legacy/Photonic≤v2/Chainbow,
  512 → SLIP-44/Tangem/Photonic≥v3, 236 → old pyrxd) so the user understands the result.

## 3.3 Recovery → sweep handoff (documented, not automated)

The CLI report ends with the exact follow-up command to move funds once a hit is
found, e.g. `pyrxd wallet send-max --coin-type 0 --account 0 --to <addr>` (uses the
existing `send_max`). The plan does **not** build an auto-sweep. Rationale: keeps the
recovery path read-only; the user confirms the destination explicitly.

# §4. Test plan (the gate)

1. **Derivation cross-check (must-pass, blocks merge).** For a fixed test mnemonic,
   assert pyrxd's derived address at `m/44'/0'/0'/0/0`, `m/44'/512'/0'/0/0`,
   `m/44'/0'/0'/0/1` equals the `@scure/bip32` output from `scripts/derive_photonic.js`
   / `gen-photonic-vectors`. This proves we will recognize the *same* addresses these
   wallets generated. Without this, the tool is guessing.
2. **Discovery unit tests** against a fake/stub ElectrumX client: seed history at a
   known `(coin_type, account, change, index)` and assert `discover` finds exactly that
   hit, with the correct path string, on both the receive and change chains.
3. **Multi-hit + zero-hit** cases: funds split across two coin types → both reported;
   no history anywhere → empty report, no crash.
4. **Fail-loud**: a network error mid-scan raises (does not silently report empty).
5. **CLI**: `recover --scan` happy path + `--json` shape + zero-hit message, via the
   existing CLI test harness. Mnemonic read from prompt, never echoed.
6. **No-seed-leak**: assert the mnemonic does not appear in any emitted output / log /
   exception string (extends the existing `SecretBytes` discipline to the new surface).

# §5. Security review checklist

- Mnemonic: prompt-only input; held in `SecretBytes` where persisted; never logged,
  never in argv/env; zeroized where the existing code does.
- Output: addresses and balances only — no WIF/xprv in discovery output.
- Network: derived addresses only leave the host; assert no seed-derived secret is sent.
- Fail-loud on partial scans (see §3.1) — a swallowed network error misreporting "empty"
  is the headline risk for a *recovery* tool and must be tested.
- Read-only: no signing/broadcast in this feature; sweep stays a separate explicit op.

# §6. Phasing

- **P1 — lib core:** `DiscoveryHit`/`DiscoveryReport` + `HdWallet.discover`. Tests §4.2–4.4.
- **P2 — cross-check gate:** wire `derive_photonic.js` vectors into pytest (§4.1). This
  is the trust anchor; do it before the CLI so we never ship an unverified derivation.
- **P3 — CLI:** `wallet recover --scan` + human/JSON output + labels. Tests §4.5–4.6.
- **P4 — docs:** a `docs/how-to/recover-funds-across-wallet-paths.md` (public-safe,
  ecosystem-general — no private project references per repo norms) + README pointer.
- **P5 — CI green:** `task ci`, coverage gate, link check.

# §7. Decisions (RESOLVED 2026-06-04)

1. **Default scan breadth — DECIDED: `{0,512,236} × {0,1,2}`, gap 20.** Overridable via
   `coin_types` / `accounts` args. Note: `gap_limit` was **dropped** from the v1 signature —
   `HdWallet.refresh` hardcodes gap 20 (the BIP44 standard), and parameterizing a
   mainnet-proven method to expose a knob no caller needs yet is YAGNI. Add it only when a
   real need appears.
2. **Per-candidate network-error policy — DECIDED: abort loud.** `refresh`'s N5 fail-loud
   contract propagates; `discover` does not swallow it. A partial scan misreported as
   "empty" is the dangerous failure mode for a recovery tool. Tested
   (`test_network_error_propagates_not_swallowed`).
3. **Location — DECIDED: module-level `async def discover(...)` in `hd/discovery.py`.**
   Keeps `HdWallet` focused on a single account; `discover` constructs N wallets internally.

## Implementation status (P1 + P2 done)

- `src/pyrxd/hd/discovery.py` — `discover()` + `DiscoveryHit`/`DiscoveryReport` +
  `coin_type_label()`; exported from `pyrxd.hd`. 100% line+branch coverage.
- `tests/test_hd_discovery.py` — 11 tests (legacy-path find, change-chain, non-zero
  account, split-across-coin-types, zero-hit, scan coverage, custom ranges, fail-loud,
  no-seed-leak, labels). Reuses the Photonic-verified `EXPECTED_0` derivation anchor in
  `test_hd_wallet.py` (the §4.1 cross-check gate — already satisfied for coin type 0).
- mypy clean; ruff clean; 138 tests green (discovery + wallet).
- **Pending:** P3 `pyrxd wallet recover --scan` CLI, P4 how-to doc, P5 full `task ci`.

# §8. Effort estimate (honest)

- Throwaway script equivalent: ~1–2 hrs (already scoped in conversation).
- This, to pyrxd's published-library bar: **~half a day**, dominated by the cross-check
  vector gate (§4.1), CLI + tests, docs, and the security pass — not the discovery loop
  itself.

# §9. What this still cannot fix (limits to state in docs)

- A wallet using a **non-BIP44** scheme entirely → no path scan helps; only the funded
  address from the explorer does.
- A **wrong/incomplete seed** → unrecoverable by any tool.
- Coin types / accounts **outside the scanned ranges** → mitigated by overridable flags,
  but the default won't catch everything; the zero-hit message must say so.
