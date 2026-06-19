# How to transfer a Glyph token after you mint it

**Who this page is for:** you minted a Glyph FT or NFT (see
[Mint a Glyph FT](../tutorials/mint-a-glyph-ft.md) /
[Mint a Glyph NFT](../tutorials/mint-a-glyph-nft.md)) and now want to send some
of it to someone else. Two CLI verbs cover both cases:

| You hold | Command | What moves |
|---|---|---|
| A fungible token (FT) | `pyrxd glyph transfer-ft` | `AMOUNT` units to one recipient, change back to you |
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
gets a new FT output for `AMOUNT`, and any remainder comes back to you as a
change FT output. The Radiant FT consensus rule (token in == token out) is
preserved by construction — you cannot accidentally create or destroy units.

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
    network:      mainnet

Broadcast this transfer? [y/N]: y

NFT transfer broadcast: c88a…91
```

> **You need a little plain RXD to pay the fee.** An NFT singleton carries only
> dust, so the transfer pulls the network fee from a separate plain-RXD UTXO in
> the same wallet. If the wallet has no spendable RXD, the command stops with
> *"no plain-RXD UTXO to fund the NFT transfer fee"* — fund the wallet with a
> small amount of RXD and retry. The fee change returns to you.

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
- **`no plain-RXD UTXO to fund the NFT transfer fee`.** Add a little RXD to the
  wallet — the NFT itself can't pay its own fee.
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
