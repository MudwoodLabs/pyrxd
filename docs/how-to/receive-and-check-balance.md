# How to receive funds and check your balance

**Who this page is for:** you have a wallet (`pyrxd wallet new` or
`pyrxd wallet recover`) and you want a receive address, then to confirm money
arrived. Everything on this page is **read-only** — no signing, no broadcast.
`balance` and `utxos` still ask for the mnemonic, to open the wallet file.

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
the right default for "where do I get paid." It scans the chain first, the same
scan `balance` runs, and prints the first receive address whose P2PKH script
hash has no history. That catches plain RXD: an address that was paid RXD, even
one later spent from, is not handed out again. It does not catch an address that
has only ever received a Glyph token. The indexer lists a token output under its
script hash with the refs zeroed, which the scan does not read, so such an
address can be handed out again
([#787](https://github.com/MudwoodLabs/pyrxd/issues/787)). The scan is not saved
to the wallet file. If an address cannot be read, `address` exits 2 and prints
no address, because it cannot show the one it would print is unused. `--change`
does the same on the change chain.

For deterministic lookups, which read nothing from the network:

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
Network    mainnet
Confirmed  123,456,789 photons (1.23456789 RXD)
Pending    0 photons (0.00000000 RXD)
```

`balance` scans the chain first: it walks the receive and change chains until 20
addresses in a row have no history, then sums confirmed and pending photons
across every address that has some. So a payment to any address inside that
window shows up, including on a wallet `pyrxd wallet new` just made. The
scan runs every time and is not saved to the wallet file. `--refresh`, which
used to turn the scan on, is still accepted and changes nothing.

If an address cannot be read, the balance is not reported as complete: the
command exits 2, and the human output shows what the other addresses hold with
an `INCOMPLETE` line naming the ones that failed (JSON and `--quiet` output
print nothing). Retry, or point `--electrumx` at another server.

If the balance shows zero while an explorer shows funds, your coins are likely
on a different derivation path — see
[Recover funds across wallet paths](recover-funds-across-wallet-paths.md).

---

## See exactly what you hold

```console
$ pyrxd utxos
```

`utxos` is a read-only diagnostic listing every spendable output across your
used addresses, after the same scan. An address it cannot read makes it exit 2
the same way `balance` does. Two filters:

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
**carries no private keys** — anyone with it can watch and derive addresses;
they cannot spend.

It is not, however, a casual thing to hand out. An xpub reveals *every*
address the wallet will ever derive, on both the receive and change chains,
and the fact that they belong together — a permanent disclosure of your whole
transaction history, past and future. Share it only with a party you would
trust with that; for a one-off payment, hand over a single address instead.

Add `--descriptor` to get an output script descriptor rather than a bare
xpub — script type, key origin, and derivation range in one string, which is
what other wallets actually want for a watch-only import:

```console
$ pyrxd wallet export-xpub --descriptor
...
  receive: pkh([73c5da0a/44h/512h/0h]xpub6BmWw…NZpB/0/*)
  change:  pkh([73c5da0a/44h/512h/0h]xpub6BmWw…NZpB/1/*)
```

See [Export a watch-only output-script
descriptor](export-a-watch-only-descriptor.md) for the full recipe, including
the `radiant-cli scantxoutset` example and the checksum incompatibility
between Radiant Core and Bitcoin Core.

---

## See also

- [Your first Radiant transaction](../tutorials/your-first-radiant-transaction.md)
  — receive, check, then build and sign a send.
- [Recover funds across wallet paths](recover-funds-across-wallet-paths.md) —
  when the balance is zero but the explorer shows funds.
