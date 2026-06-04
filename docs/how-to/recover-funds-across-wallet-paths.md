# How to recover funds when a wallet shows the wrong address

**Who this page is for:** anyone whose RXD is visible on a block explorer
but shows a **zero balance** in their wallet after restoring a seed phrase —
often after switching wallets (Photonic, Chainbow, Electron, Tangem) or
upgrading a wallet to a new version that changed its derivation path.

The coins are almost certainly **not lost**. A BIP39 seed does not define one
address — it defines a tree of addresses, and which one a wallet shows depends
on its **BIP44 derivation path**:

```
m / 44' / coin_type' / account' / change / index
```

The Radiant ecosystem never agreed on `coin_type`, so the same seed produces
different addresses across wallets and across versions of the *same* wallet:

| coin_type | Used by |
|---|---|
| `0`   | Photonic ≤ v2.x (legacy), Electron-Radiant, Chainbow |
| `512` | SLIP-0044 spec, Tangem, Photonic ≥ v3.0.0 |
| `236` | pre-#14 pyrxd (BSV's coin type) |

If your funds landed on one path but your wallet derives another, the balance
is invisible even though it is on-chain. This recipe scans all the likely paths
and tells you which one holds the money.

> **Read-only and offline-first.** Recovery derives keys locally and only ever
> sends *addresses* to the server — never your seed. It does not sign or
> broadcast anything. Once you know the path, you sweep the funds with a wallet
> that derives it, or a separate explicit send.

---

## TL;DR — the CLI

```console
$ pyrxd wallet recover --scan
Mnemonic (input hidden):
Found funds. Recover with the wallet that derives the matching path:

  12.34567 RXD  m/44'/0'/0'/0/0
      coin type 0 — legacy (Photonic <= v2 / Electron-Radiant / Chainbow)
      1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA

Total confirmed   12.34567 RXD
```

The mnemonic is read from a hidden prompt — never pass it as a command-line
argument (it would leak into your shell history and the process list).

Widen the search if nothing is found:

```console
$ pyrxd wallet recover --scan --coin-types 0,512,236 --accounts 0,1,2,3
```

`--json` emits a machine-readable report (`found`, `hits[]` with full `path`,
`address`, and balances) for tooling.

---

## The library API

```python
from pyrxd.hd import discover
from pyrxd.network.electrumx import ElectrumXClient

async with ElectrumXClient(["wss://your.electrumx.host:50022"]) as client:
    report = await discover(client, mnemonic)

if report.found:
    for hit in report.hits:
        print(hit.path, hit.address, hit.confirmed)  # photons
else:
    print("No history at any scanned path — widen coin_types/accounts.")
```

`discover` scans every `coin_type × account` pair over **both** BIP44 chains
(receive and change) with the standard gap limit, and returns a
`DiscoveryReport`:

- `report.found` — `True` if any scanned path had on-chain history.
- `report.hits` — `list[DiscoveryHit]`, each with `path`, `address`,
  `coin_type`, `account`, `change`, `index`, and `confirmed` / `unconfirmed`
  photon balances. Sorted largest-balance first.
- `report.total_confirmed` / `report.total_unconfirmed`.

Override the search ranges when needed:

```python
report = await discover(client, mnemonic, coin_types=(0, 512, 236), accounts=range(4))
```

### Defaults

| Argument | Default | Notes |
|---|---|---|
| `coin_types` | `(0, 512, 236)` | The three coin types seen in the ecosystem |
| `accounts` | `(0, 1, 2)` | Almost every wallet only uses account 0 |
| gap limit | `20` (fixed) | The BIP44 standard; both chains scanned |

---

## After you find the path

`discover` is **read-only** — it tells you *where* the funds are. To move them:

- Restore the seed in a wallet configured for the reported `coin_type`
  (for Photonic ≥ v3.0.1, the Recover screen auto-detects coin type 0 vs 512;
  tick "Use legacy derivation path" if it shows empty), **or**
- Sweep with pyrxd's own spend path once your wallet is built at that coin
  type (`HdWallet.from_mnemonic(mnemonic, coin_type=…)` then `send_max`).

---

## Failure modes

- **Scan reports "No on-chain history."** Widen `--coin-types` / `--accounts`.
  If still empty, confirm the funded address on a block explorer and check
  whether it matches *any* of the scanned paths — if not, the wallet may use a
  non-BIP44 scheme, and only that explorer address can guide manual recovery.
- **A network error mid-scan.** Recovery **fails loud** rather than reporting a
  false "empty" — a partial scan that looked complete is the dangerous failure
  mode for a recovery tool. Re-run against a reachable ElectrumX server
  (`--electrumx URL`).
- **Wrong or incomplete mnemonic.** No tool can recover from a bad seed; the
  command rejects an invalid mnemonic up front without echoing your input.

> **Never** type your seed phrase into a website, a "recovery service," or hand
> it to anyone offering to recover funds for you. Run recovery only in software
> you trust on your own device. A seed guarding real funds entered anywhere
> untrusted is how people get drained.
