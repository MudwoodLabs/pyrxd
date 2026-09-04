# How to transfer a Glyph token after you mint it

**Who this page is for:** you minted a Glyph FT or NFT (see
[Mint a Glyph FT](../tutorials/mint-a-glyph-ft.md) /
[Mint a Glyph NFT](../tutorials/mint-a-glyph-nft.md)) and now want to send some
of it to someone else. Two CLI verbs cover both cases:

| You hold | Command | What moves |
|---|---|---|
| A fungible token (FT) | `pyrxd glyph transfer-ft` | `AMOUNT` units to one recipient, change back to you |
| A fungible token (FT), many recipients | `pyrxd glyph airdrop-ft` | one transaction paying N recipients, change back to you |
| A non-fungible token (NFT) | `pyrxd glyph transfer-nft` | the whole singleton to one recipient |

Both **sign and broadcast a real transaction** and ask you to confirm the
amount, recipient, and network first. A confirmed transfer is irreversible.

---

## The `REF` is the token, not the UTXO

The one thing that trips people up: `REF` is the token's **genesis ref** — the
`txid:vout` that identifies the token *class*, embedded in every output that
carries it. It is **not** the outpoint of the specific UTXO you happen to hold
right now. You pass the genesis ref once; pyrxd scans your wallet and finds
whichever UTXO(s) currently hold that token for you.

For an FT, the ref is the **commit outpoint from the deploy**, not the reveal
txid (a common mix-up — see
[Glyph structures and terminology](../concepts/glyph-structures-and-terminology.md)).
If you're not sure what your ref is, list your holdings:

```console
$ pyrxd glyph list --type ft
$ pyrxd glyph list --type nft
```

or decode any output you hold with the inspect tool — `ref_outpoint` in the
output is the value to pass:

```console
$ pyrxd glyph inspect <txid:vout> --resolve
```

---

## Transfer fungible tokens (FT)

```console
$ pyrxd glyph transfer-ft <REF> <AMOUNT> --to <ADDRESS>
```

- `REF` — the token's genesis ref as `txid:vout`.
- `AMOUNT` — units to send (must be > 0). One photon carries one FT unit.
- `--to` — the recipient's Radiant address (required).

pyrxd scans your used addresses for UTXOs of `REF`, greedily selects enough to
cover `AMOUNT`, and builds a **conservation-enforcing** transfer: the recipient
gets a new FT output for exactly `AMOUNT`, and any remainder comes back to you as
a change FT output. The Radiant FT consensus rule (token in == token out) is
preserved by construction — you cannot accidentally create or destroy units.

> **You need a little plain RXD.** An FT's quantity *is* its output value on
> Radiant (1 photon = 1 unit), so the fee cannot come out of a token output
> without shorting the recipient. The transfer sources it from a separate
> plain-RXD UTXO, the same way `transfer-nft` does. Without one it stops with
> *"no plain-RXD UTXO large enough to fund the fee"*.

```console
$ pyrxd glyph transfer-ft 9d3f…a1:1 250 --to 1Qq…recipient

  FT transfer
    ref:          9d3f…a1:1
    amount:       250 units
    recipient:    1Qq…recipient
    network:      mainnet

Broadcast this transfer? [y/N]: y

FT transfer broadcast: 4b1c…e7
```

> **One-address restriction (current).** The FT transfer signs all selected
> inputs with a single key. If your units are spread across multiple wallet
> addresses, the command stops with *"FT transfer across multiple wallet
> addresses isn't supported"* and asks you to consolidate first. Send the
> scattered pieces to one of your own addresses, then retry.

---

## Transfer a non-fungible token (NFT)

```console
$ pyrxd glyph transfer-nft <REF> --to <ADDRESS>
```

There's no amount — an NFT is a singleton, so the whole thing moves. pyrxd
finds the one UTXO holding `REF`, re-locks it to the recipient, and broadcasts.

```console
$ pyrxd glyph transfer-nft 7a0c…42:0 --to 1Rr…recipient

  NFT transfer
    ref:          7a0c…42:0
    recipient:    1Rr…recipient
    fee:          4,120,000 photons (412 B @ 10,000/B)
    network:      mainnet

Broadcast this transfer? [y/N]: y

NFT transfer broadcast: c88a…91
```

> **You need plain RXD to pay the fee, and it is not a token amount.** An NFT
> singleton carries only dust, so the transfer pulls the network fee from a
> separate plain-RXD UTXO in the same wallet. That UTXO has to be big enough on
> its own: at the default rate a transfer is roughly 380–410 bytes and Radiant's
> relay floor is 10,000 photons/byte, so the command needs a **single**
> non-token UTXO of about **0.038 RXD** — not "a small amount". Below that it
> stops before signing with *"no plain-RXD UTXO large enough to fund the NFT
> transfer fee"* and prints the exact number it needs.
>
> Change returns to you **when there is room for it**. If the funding UTXO only
> just covers the fee, there is no change output and the whole UTXO is paid to
> the miner; the confirmation block says so on the `fee:` line before you
> confirm. Fund with a comfortable margin if that matters to you.

---

## Send to many recipients at once (FT airdrop)

```console
$ pyrxd glyph airdrop-ft <REF> --to <ADDRESS>:<AMOUNT> --to <ADDRESS>:<AMOUNT>
$ pyrxd glyph airdrop-ft <REF> --recipients holders.csv
```

One transaction, not one per recipient. That matters more than it sounds: N
sequential transfers each spend the previous one's change, so if the run dies
partway you are left with a half-delivered list and no way to tell which half
from the token's ref alone. An airdrop lands whole or it does not land.

`--to` is repeatable and can be combined with `--recipients`. The file is either
a `.json` array of `{"address": …, "amount": …}` objects, or `address,amount`
CSV (blank lines and `#` comments ignored):

```
# holders.csv
1Alice…,250
1Bob…,100
1Carol…,50
```

```console
$ pyrxd glyph airdrop-ft 9d3f…a1:1 --recipients holders.csv

  FT airdrop
    ref:          9d3f…a1:1
    recipients:   3
    total:        400 units
    fee:          6,420,000 photons (from plain RXD, not the token)
    network:      mainnet

  Destinations
    vout 0: 250 units → 1Alice…
    vout 1: 100 units → 1Bob…
    vout 2: 50 units → 1Carol…

Broadcast this airdrop? [y/N]: y

FT airdrop broadcast: 71ba…0c
```

Output order follows your list, so `vout N` is recipient N — you can reconcile
who got what straight from the transaction.

> **You need plain RXD, and it is not optional.** On Radiant an FT's quantity
> *is* its output's value — 1 photon = 1 unit — so taking the fee out of a token
> output would deliver fewer units than you asked for. The airdrop sources the
> fee from a separate plain-RXD UTXO instead. Without one it stops with *"no
> plain-RXD UTXO large enough to fund the fee"* rather than quietly shorting a
> recipient. See [How much plain RXD an airdrop needs](#how-much-plain-rxd-an-airdrop-needs)
> below — it is a few tenths of an RXD, not a few thousandths, and it must sit
> on a **single** UTXO.

> **A repeated address is refused, not merged.** Two rows for the same address
> is usually a duplicated line in a holder export, and paying twice cannot be
> undone. Combine them into one row if the total really is intended.

---

## From Python

The CLI verbs are thin wrappers. `GlyphBuilder.build_ft_transfer_tx` and
`GlyphBuilder.build_ft_airdrop_tx` build the same transactions from the library,
and both take plain-RXD `funding` for the same reason the CLI needs it in your
wallet:

```python
from pyrxd.glyph.builder import FtAirdropParams, FtTransferParams, GlyphBuilder
from pyrxd.glyph.ft import AirdropFunding, AirdropRecipient

funding = [AirdropFunding(txid=fee_txid, vout=0, value=fee_value, private_key=fee_key)]

# One recipient.
transfer = GlyphBuilder().build_ft_transfer_tx(
    FtTransferParams(
        ref=ref, utxos=ft_utxos, amount=250,
        new_owner_pkh=recipient_pkh, private_key=key, funding=funding,
    )
)

# Many recipients, one transaction. Output order follows the list.
airdrop = GlyphBuilder().build_ft_airdrop_tx(
    FtAirdropParams(
        ref=ref, utxos=ft_utxos, private_key=key, funding=funding,
        recipients=[
            AirdropRecipient(pkh=alice_pkh, amount=250),
            AirdropRecipient(pkh=bob_pkh, amount=100),
        ],
    )
)
airdrop.recipient_scripts   # index-aligned with `recipients` and with tx.outputs
airdrop.fee                 # actual fee paid, in photons
```

`build_ft_transfer_tx` **is** a single-recipient `build_ft_airdrop_tx` — one
implementation, so the two cannot disagree about how many units anyone gets.
Reach for the airdrop form directly when you have several recipients, or when a
royalty is in play: `FtAirdropResult` reports the payouts and
`FtTransferResult` has no field for them.

Build your `FtUtxo` records with `ft_amount = value`. That is not a convention,
it is what an FT is: the builders refuse a mismatch rather than guess which of
the two numbers you meant. The filter that finds those UTXOs on chain is worked
through in [`examples/ft_transfer_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_transfer_demo.py).

---

## Royalties: honoured, not enforced

If a token's metadata declares a royalty, pyrxd can pay it — and you should know
exactly what that means. **Radiant does not enforce royalties.** An FT lock's
epilogue enforces *conservation* (how many units may exist on the output side);
it says nothing about where value goes. An NFT lock is a bare P2PKH behind a ref
push. Any wallet, pyrxd included, is free to build a transfer with no royalty
output at all, and the chain will accept it.

So: a royalty is a convention that a compliant wallet honours. pyrxd's FT
airdrop builder resolves it from the token's own `enforced` flag, and records
the decision in the result either way (a one-recipient airdrop is an ordinary
transfer):

```python
from pyrxd.glyph.ft import AirdropFunding, AirdropRecipient, FtUtxoSet

result = FtUtxoSet(ref=ref, utxos=utxos).build_airdrop_tx(
    [AirdropRecipient(pkh=recipient_pkh, amount=250)],
    key,
    funding=[AirdropFunding(txid=..., vout=0, value=..., private_key=fee_key)],
    royalty=token_royalty,      # the creator's recorded terms
    sale_price=1_000_000,       # photons the seller receives
    # pay_royalty=None (default) → pay iff token_royalty.enforced
    # pay_royalty=True           → pay an advisory royalty anyway
    # pay_royalty=False          → never pay
)
result.royalty_payouts          # who was paid, and how much
```

Two bounds worth knowing before you rely on this:

- **`enforced` is consulted, not ignored.** It is the creator's own statement
  about whether wallets should insist, and it defaults to `false`. Paying
  regardless would spend *your* funding photons on a payment the creator did not
  ask to be insisted on, so the default follows the flag and `pay_royalty=True`
  is the explicit opt-in for honouring an advisory royalty anyway.
- **A royalty can never exceed the sale price.** `minimum` is a free integer
  chosen by the token's creator with nothing on chain bounding it, and it is
  paid out of *your* funding inputs. It raises the payment toward the sale
  price; it cannot raise it past. A `minimum` on a transfer with no
  consideration (`sale_price=0`) therefore pays nothing.

`build_transfer_tx` takes no `royalty`: `FtTransferResult` has nowhere to report
who was paid, and paying without reporting would be worse than not offering the
option. Use the airdrop builder with one recipient — it is the same code path
and the same transaction. Same reason `build_nft_transfer_tx` takes none.

The royalty comes out of the RXD side as plain P2PKH outputs, never out of the
token, so it cannot change how many units anyone receives.

There is deliberately no `--royalty-address` CLI flag: terms typed in by the
person *paying* protect no creator. Reading a token's recorded terms off the
chain is the missing piece, and it is not built yet. See
[the design decision](../solutions/design-decisions/royalties-are-advisory-not-consensus-enforced.md)
for the full evidence, including what Photonic does.

To record a royalty on a token you are minting, add a `royalty` block to your
metadata file before `glyph mint-nft` / `glyph deploy-ft`:

```json
{
  "protocol": ["NFT"],
  "name": "My Token",
  "royalty": { "bps": 500, "address": "1Creator…" }
}
```

`bps` is basis points (500 = 5%). Optional: `minimum` (a photon floor, capped at
the sale price), `enforced` (whether compliant wallets should insist — pyrxd's
builders pay by default only when this is `true`; it still does **not** make the
chain enforce anything), and `splits` (a list of `{"address": …, "bps": …}`).

---

## Failure modes

- **`no FT holdings for <ref>` / `<NFT> is not held by this wallet`.** The
  wallet doesn't see the token at any used address. Run `pyrxd balance
  --refresh` to rescan, then retry. If it's still missing, the token is owned by
  a different wallet/address.
- **`insufficient FT balance: need N, have M`.** You're trying to send more
  units than you hold. Check with `pyrxd glyph list --type ft`.
- **`FT transfer across multiple wallet addresses isn't supported`.**
  Consolidate the units onto one address first (see the note above).
- **`no plain-RXD UTXO large enough to fund the NFT transfer fee`.** Add a little RXD to the
  wallet — the NFT itself can't pay its own fee.
- **`no plain-RXD UTXO large enough to fund the fee`.** Same cause, and an
  airdrop needs more of it — see the table below. The amount has to be on a
  *single* non-token UTXO. Consolidate some RXD, or split the list into smaller
  batches.
- **`recipient <address> appears more than once`.** A duplicated row in the
  holder list. Combine the two entries if the double payment is intended.

### How much plain RXD an airdrop needs

The funding check is a deliberately generous *pre-flight* bound, not the fee the
transaction ends up paying. It is computed in
[`src/pyrxd/glyph/transfer.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/transfer.py),
`ft_funding`:

```python
est_bytes = 84 * (n_outputs + 2) + 148 * (len(selected) + 1) + 50
needed    = est_bytes * fee_rate * 2
```

Three things that trip people up: the per-output byte cost is **doubled** for
headroom (Radiant has neither RBF nor CPFP, so a transaction that lands under
the relay floor cannot be repaired); there is a fixed overhead of two extra
output slots, the inputs, and 50 bytes of envelope on top of the per-recipient
term; and the whole amount must be available on one UTXO.

At the default fee rate of **10,000 photons/byte**
(`relay_floor_photons_per_byte()`), with the token held on a single FT UTXO:

| Recipients | `est_bytes` | Needed (photons) | Needed (RXD) |
| ---------: | ----------: | ---------------: | -----------: |
|          1 |         598 |       11,960,000 |     0.1196 |
|          2 |         682 |       13,640,000 |     0.1364 |
|          5 |         934 |       18,680,000 |     0.1868 |
|         10 |       1,354 |       27,080,000 |     0.2708 |
|         25 |       2,614 |       52,280,000 |     0.5228 |
|         50 |       4,714 |       94,280,000 |     0.9428 |
|        100 |       8,914 |      178,280,000 |     1.7828 |

Read off the shape rather than the rows: a **fixed ~0.1028 RXD** plus
**0.0168 RXD per recipient**. Each additional FT input the wallet has to select
adds a further 0.0296 RXD. Earlier revisions of this page said "roughly
0.0084 RXD per recipient" — that was the *undoubled* per-output byte cost with
the fixed overhead left out, and it under-states a one-recipient airdrop by
more than 14x.

> Numbers above are computed from the formula as written in `ft_funding`, at
> `fee_rate = 10000`, `len(selected) = 1`. They are the amount the guard
> **demands be present**, not a measurement of a broadcast transaction's fee —
> the real fee is smaller.
- **Couldn't reach ElectrumX.** The transfer needs the network to fetch source
  outputs and broadcast. Point at a reachable server with `--electrumx URL`.

---

## See also

- [Mint a Glyph FT](../tutorials/mint-a-glyph-ft.md) /
  [Mint a Glyph NFT](../tutorials/mint-a-glyph-nft.md) — where your `REF` comes
  from.
- [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md) — why FT
  conservation is a consensus rule, not a wallet convention.
- [Broadcast a transaction](broadcast-a-transaction.md) — what the rejection
  messages mean if a broadcast fails.
