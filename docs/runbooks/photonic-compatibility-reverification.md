# Photonic compatibility re-verification cadence

A quarterly procedure to confirm pyrxd's `coin_type=0` advice still
matches Photonic Wallet's published behaviour. Closes #20.

## Why this exists

pyrxd's `coin_type=0` test vector was end-to-end verified against
Photonic Wallet on **2026-05-03**, using the canonical BIP39
mnemonic `abandon abandon abandon abandon abandon abandon abandon
abandon abandon abandon abandon about`, against one Photonic build,
on one date.

Photonic publishes no versioned compatibility statement. If Photonic
ships a derivation-path change in a future release, pyrxd's
`coin_type=0` advice silently becomes wrong — and pyrxd has no
mechanism to detect the drift, by deliberate design (the preset
registry that would have made this a tracked vocabulary was rejected
as YAGNI in
[`docs/research/wallet-derivation-paths.md`](../research/wallet-derivation-paths.md)).

This runbook is the compensating control. It documents the
procedure and gives a stable home where each re-verification gets
appended.

## When to run

* **Quarterly**, starting 2026-08-03 (3 months from initial
  verification). Subsequent dates: 2026-11-03, 2027-02-03, 2027-05-03.
* **Whenever Photonic Wallet ships a major release** (check the
  [Photonic Wallet releases page](https://github.com/Radiant-Core/Photonic-Wallet/releases))
  even if quarterly is not yet due.
* **Before any pyrxd release that touches `HdWallet` derivation
  logic** — even if the prior re-verification was recent.

## Procedure

### 1. Install or update Photonic Wallet

From the [Photonic Wallet releases page](https://github.com/Radiant-Core/Photonic-Wallet/releases),
install the latest stable build for your platform. Record the
version number — you'll need it for the log entry below.

### 2. Restore the canonical test mnemonic

Open Photonic Wallet → **Restore wallet** → paste the canonical
BIP39 mnemonic:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Leave the passphrase blank.

### 3. Read the first receive address

Navigate to **Receive**. Photonic should display:

```
1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
```

This is the address derived from `m/44'/0'/0'/0/0` using the
canonical test mnemonic and `coin_type=0` (per Photonic's source at
`packages/app/src/keys.ts`).

### 4. Cross-check pyrxd against the same path

In a Python shell:

```python
from pyrxd.hd.wallet import HdWallet
w = HdWallet.from_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about",
    coin_type=0,
)
print(w.address(0, change=False))
# Expected: 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
```

### 5. Record the result

#### If both addresses match

Append a row to the **Verification log** below with the date,
Photonic version, your initials, and the result `✓ MATCH`. Commit
the change via a small docs PR (one-line addition).

#### If the addresses do not match

Stop. **Open a P0 issue** (`type: bug`, label `security`) titled
`pyrxd coin_type=0 advice has drifted from Photonic <version>`,
with body:

* pyrxd version checked
* Photonic version that produces the different address
* Both addresses (pyrxd's vs Photonic's), and the date both were
  observed
* A pointer to this runbook entry as the trigger

The fix is *not* to silently update pyrxd's vector — it's to
document that two valid addresses existed simultaneously, then
decide whether pyrxd ships a new compatibility default with a
migration note in the release CHANGELOG.

### 6. Optional: Electron-Radiant cross-check

Electron-Radiant is also documented as using `m/44'/0'/0'/0/0` but
was never end-to-end verified. If you have Electron-Radiant
installed, run the same restore + receive-address check. Record the
result as a separate log row tagged `(electron-radiant)`.

## Verification log

Append a new row after each re-verification. Most recent at top.

| Date | Photonic version | Verifier | Result | Notes |
|------|------------------|----------|--------|-------|
| 2026-05-03 | initial baseline | initial verification | ✓ MATCH | First end-to-end verification (the one this runbook is calibrated against). Recorded in #17 + `docs/research/wallet-derivation-paths.md`. |

## Open questions

These were flagged in #20 and are not blocking but are worth
revisiting if the cadence reveals friction:

* **Surface the verification date in pyrxd's CLI or README.** Today
  the date lives only in this runbook. A `pyrxd setup status` line
  or a README badge would let users see at a glance how stale the
  claim is. Deferred — implement if a user actually asks.
* **Automate via a GitHub Actions cron** that pings whoever's on the
  rotation. Current approach (this runbook + maintainer discipline)
  has no automated reminder. If the cadence slips twice in a row,
  add the cron.
