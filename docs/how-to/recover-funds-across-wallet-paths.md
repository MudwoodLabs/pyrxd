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
- Sweep the path with pyrxd directly — the next section.

### Sweep a derived path with `pyrxd wallet sweep`

When the funds sit at a path no GUI wallet can reach (a non-zero account, or a
coin type your wallet won't derive), `wallet sweep` moves **everything** under
that path to an address you control:

```console
$ pyrxd wallet sweep --coin-type 0 --to 1YourSafeAddress
```

Pass the `--coin-type` (and `--account`, if non-zero) that `wallet recover
--scan` reported. The command sweeps every spendable UTXO under
`m/44'/<coin-type>'/<account>'` to `--to`, minus the fee. It is a **real signed
broadcast**, so it shows you the amount, fee, and destination and asks you to
confirm before anything goes out.

| Option | Default | Notes |
|---|---|---|
| `--coin-type` | *(required)* | The SLIP-0044 coin type the funds are on (e.g. `0` or `512`). |
| `--account` | `0` | The BIP44 account index the funds are on. |
| `--to` | *(required)* | Destination address you control. |
| `--fee-rate` | `10000` | Photons per **byte** (`fee = tx size in bytes x this`). The default sits exactly at Radiant's effective relay floor; a lower value is refused, because Radiant has no RBF and no CPFP so a sub-floor transaction cannot be fee-bumped. |

Send `--to` an address from a wallet you can actually use day-to-day — the point
of the sweep is to get the coins onto a reachable path.

---

## Non-ASCII passphrases: wallets created before pyrxd 0.12.0 (NFKD normalization)

**Who this section is for:** anyone who set a **BIP39 passphrase containing
non-ASCII characters** (accents, umlauts, CJK, anything beyond plain ASCII)
on a wallet created with **pyrxd earlier than 0.12.0**. If your passphrase is
plain ASCII — or you never set one — this section does not apply to you.

Everything above assumes the wallet derived the right *seed* and only the
*path* differs. This section covers the one case where the **seed itself** is
different. BIP39 requires the mnemonic and passphrase to be **NFKD-normalized**
before they enter PBKDF2. pyrxd versions before 0.12.0 skipped that step, so a
passphrase like `café` typed with a precomposed `U+00E9` derived a *different*
seed than the visually identical decomposed spelling — and a different seed
than any conformant BIP39 wallet derives from the same input. 0.12.0 fixed the
conformance bug; the old seed remains reproducible only through the explicit
`normalize=False` escape.

Check whether your passphrase is affected:

```python
import unicodedata
unicodedata.normalize("NFKD", passphrase) == passphrase
# True  -> not affected; normalize=False would change nothing for you
# False -> your pre-0.12.0 wallet sits on the unnormalized (legacy) seed
```

Two symptoms, one cause:

1. **Empty balance on restore.** Restoring the mnemonic + passphrase in a
   conformant wallet — or in pyrxd 0.12.0+ with its defaults — derives the
   conformant seed, which is *not* the seed your funds are on. Every path scan
   of that seed, including `pyrxd wallet recover --scan`, comes back empty at
   every coin type.
2. **The wallet file no longer decrypts.** `HdWallet.load` reports "Could not
   decrypt wallet file — wrong mnemonic, wrong passphrase, or ciphertext
   tampered" even though both are correct. The BIP39 seed doubles as the
   wallet file's AES-GCM encryption key, so a file saved from the legacy seed
   only decrypts by reproducing that legacy seed.

### Reach the legacy seed with `normalize=False`

Every mnemonic entry point accepts `normalize=False`, which reproduces the
pre-0.12.0 unnormalized seed. Scan the legacy seed's paths:

```python
from pyrxd.hd import discover

report = await discover(client, mnemonic, passphrase=passphrase, normalize=False)
```

Decrypt an existing wallet file that was saved under the legacy seed:

```python
from pathlib import Path
from pyrxd.hd import HdWallet

wallet = HdWallet.load(Path("wallet.dat"), mnemonic, passphrase, normalize=False)
```

The same keyword exists on `HdWallet.from_mnemonic` / `load_or_create`,
`seed_from_mnemonic`, and the `bip32_*` / `bip44_*` derivation helpers.
pyrxd never guesses the mode for you: a failed decrypt raises instead of
silently retrying with the other seed, so the legacy mode is only ever
entered explicitly.

### Move the funds off the legacy seed

The legacy seed is a dead end — **no other BIP39 implementation can ever
derive it**, so funds left there are one lost laptop away from being
unreachable. Sweep them to the conformant wallet (same mnemonic and
passphrase, default normalization):

```python
legacy = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase, normalize=False)
safe = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase)  # conformant default

await legacy.refresh(client)
await safe.refresh(client)
txid = await legacy.send_max(client, safe.next_receive_address())
```

Never create a new wallet with `normalize=False`. The flag exists solely so
funds stranded on the old seed can be moved off it.

---

## Failure modes

- **Scan reports "No on-chain history."** Widen `--coin-types` / `--accounts`.
  If you set a non-ASCII passphrase on a pre-0.12.0 pyrxd wallet, rescan the
  legacy seed with `normalize=False` (see the NFKD section above). If still
  empty, confirm the funded address on a block explorer and check
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
