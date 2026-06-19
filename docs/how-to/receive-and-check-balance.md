# How to receive funds and check your balance

**Who this page is for:** you have a wallet (`pyrxd wallet new` or
`pyrxd wallet recover`) and you want a receive address, then to confirm money
arrived. Everything on this page is **read-only** — no signing, no broadcast, no
mnemonic required for the balance and UTXO views.

```
pyrxd address   →  give it to the sender
pyrxd balance   →  did it arrive?
pyrxd utxos     →  what exactly do I hold?
```

---

## Get a receive address

```console
$ pyrxd address
1Abc…yourReceiveAddress
```

With no flags, `address` prints the **next unused external receive address** —
the right default for "where do I get paid." For deterministic lookups:

```console
$ pyrxd address --index 5            # external address at index 5
$ pyrxd address --index 5 --change   # the change-chain address at index 5
```

Hand the printed address to whoever is paying you. It's a public receive address
— safe to share.

---

## Check your balance

```console
$ pyrxd balance
Confirmed:    1.23456789 RXD
Unconfirmed:  0.00000000 RXD
```

`balance` sums confirmed and unconfirmed photons across the addresses the wallet
already knows about. If you just received to a **fresh** address the wallet
hasn't seen used yet, run a gap-limit scan first so it gets discovered:

```console
$ pyrxd balance --refresh
```

Use `--refresh` after receiving to a new address, or any time the balance looks
lower than the explorer shows. (If `--refresh` *still* shows zero while an
explorer shows funds, your coins are likely on a different derivation path —
see [Recover funds across wallet paths](recover-funds-across-wallet-paths.md).)

---

## See exactly what you hold

```console
$ pyrxd utxos
```

`utxos` is a read-only diagnostic listing every spendable output across your
used addresses. Two filters:

```console
$ pyrxd utxos --min-photons 10000   # hide dust below 10,000 photons
$ pyrxd utxos --addr 1Abc…           # only this address
```

This is the view to reach for when a send picks unexpected inputs, or when you
want to confirm a specific payment landed at a specific address.

---

## Receive without exposing the wallet: watch-only xpub

To let an external tool or service generate receive addresses for you **without
ever touching the seed**, export the account-level xpub:

```console
$ pyrxd wallet export-xpub
xpub6C…
```

The xpub at `m/44'/<coin_type>'/<account>'` derives receive addresses but
**carries no private keys** — safe to hand to a watch-only wallet or a merchant
integration. Anyone with it can watch and derive addresses; they cannot spend.

---

## See also

- [Your first Radiant transaction](../tutorials/your-first-radiant-transaction.md)
  — receive, check, then build and sign a send.
- [Recover funds across wallet paths](recover-funds-across-wallet-paths.md) —
  when the balance is zero but the explorer shows funds.
