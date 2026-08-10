# Export a watch-only output-script descriptor

**Who this page is for:** anyone who wants another wallet, an indexer, or a
`radiant-cli` node to watch a pyrxd wallet's addresses without holding its
seed — and anyone who has already tried and been told `Invalid descriptor`.

An **output script descriptor** is a single string that says everything a
watching tool needs: the script type, the extended public key, which master
key it came from, at which derivation path, and which range to walk.

```text
pkh([73c5da0a/44h/512h/0h]xpub6BmWw…NZpB/0/*)
 │    │        │           │            └── walk /0/0, /0/1, /0/2, …
 │    │        │           └── the account-level xpub
 │    │        └── the BIP44 path that produced it
 │    └── the master key's fingerprint
 └── P2PKH — the only script type Radiant has
```

A bare xpub carries only the middle piece. The consumer then has to *guess*
the script type and has no way to tell which seed the key came from. The
descriptor removes both guesses.

## The one thing that will waste your afternoon

**Radiant Core rejects the checksummed descriptor form that Bitcoin Core
requires.**

Radiant Core forked from Bitcoin Core before the 0.18 release that introduced
descriptor checksums. Its `src/script/descriptor.cpp` has no checksum
machinery at all, so the trailing `#xxxxxxxx` is unparseable input rather than
an optional extra:

```console
$ radiant-cli scantxoutset start '["pkh([73c5da0a/44h/512h/0h]xpub6BmWw…/0/*)#w5v8ec5w"]'
error code: -5
error message:
Invalid descriptor 'pkh([73c5da0a/44h/512h/0h]xpub6BmWw…/0/*)#w5v8ec5w'
```

Drop the checksum and the same descriptor is accepted. That is why
`pyrxd wallet export-xpub --descriptor` emits **no checksum by default**. Add
`--checksum` only when the consumer is a Bitcoin-Core-lineage tool that
demands one — and expect Radiant Core to refuse that string.

## Export the descriptors

```console
$ pyrxd wallet export-xpub --descriptor

xpub at m/44'/512'/0':
  xpub6BmWwzAQXJ1dYPpnP3eQNN3XMCYD1Tvvy455NDJ6xDMAqAUfZHEzwZUWrCTgJw7Nr9PhpkZ9Kc7nNScnuanf7DB7PTEkL78kiaejmenNZpB

output script descriptors (master fingerprint 73c5da0a):
  receive: pkh([73c5da0a/44h/512h/0h]xpub6BmWw…NZpB/0/*)
  change:  pkh([73c5da0a/44h/512h/0h]xpub6BmWw…NZpB/1/*)
```

`--json` gives `descriptor_receive`, `descriptor_change`,
`master_fingerprint`, and `descriptor_origin_path` alongside the existing
`xpub` / `account` / `path` fields. `--quiet` prints the receive descriptor
alone, for piping.

### Import both, or under-report the balance

Two descriptors come out because a BIP44 wallet uses two chains: `/0/*` for
the addresses you hand out, `/1/*` for change returning from your own spends.
A watch-only import that takes only the receive descriptor will show a
balance that is missing every change output — which, after a few spends, is
most of the wallet. Import both.

### Hardened steps are written `h`, not `'`

Both notations parse. `h` is the default because a descriptor containing `'`
cannot be pasted inside a shell's single quotes without escaping, and that is
exactly how `radiant-cli` invocations get written. If a consumer insists on
apostrophes, rewriting `44h` as `44'` is a safe textual substitution — Radiant
Core accepts either.

## Scan the UTXO set with radiant-cli

`scantxoutset` is the descriptor consumer that ships with Radiant Core. It is
marked EXPERIMENTAL in its own help text, and it walks the **entire** UTXO set
on every call — expect it to take ten seconds or more and to load the node, so
do not put it in a polling loop.

```console
$ radiant-cli scantxoutset start '[{"desc":"pkh([73c5da0a/44h/512h/0h]xpub6BmWwzAQXJ1dYPpnP3eQNN3XMCYD1Tvvy455NDJ6xDMAqAUfZHEzwZUWrCTgJw7Nr9PhpkZ9Kc7nNScnuanf7DB7PTEkL78kiaejmenNZpB/0/*)","range":20}]'
{
  "success": true,
  "searched_items": 25950373,
  "unspents": [
  ],
  "total_amount": 0.00000000
}
```

(The xpub above is derived from the published BIP39 all-zero-entropy test
mnemonic — a world-known key that must never hold value. Substitute your own.)

`range` is the highest child index to derive, and it defaults to 1000. Set it
to at least your wallet's highest used index plus the gap limit (pyrxd uses
20), or the scan will silently miss funds past the end of the range. Run the
same command a second time with the `/1/*` descriptor for change.

### What Radiant Core does *not* have

Habits from Bitcoin Core that will not transfer:

| Bitcoin Core RPC   | On Radiant Core                                  |
| ------------------ | ------------------------------------------------ |
| `getdescriptorinfo` | Absent — no way to ask the node for a checksum. |
| `deriveaddresses`   | Absent — derive addresses client-side.          |
| `importdescriptors` | Absent — no descriptor wallet import.           |
| `scantxoutset`      | Present. The only descriptor consumer.           |

Supported descriptor functions are `pk`, `pkh`, `combo`, `multi`, `sh`,
`addr`, and `raw`. There is no `wpkh`, `wsh`, or `tr` — Radiant has no segwit
and no taproot, which is why pyrxd emits `pkh(...)`.

## Privacy: what you are actually handing over

The descriptor exports **no private key material**. Someone holding it can
derive your addresses and watch them; they cannot spend.

Note that this is a property of what pyrxd *emits*, not a property the format
enforces: Radiant Core's own `scantxoutset` help says a descriptor key may be
"an xpub/xprv", so the parser will happily accept a descriptor carrying a
private key and nothing downstream will complain. pyrxd's descriptor builders
refuse a non-xpub key outright for that reason. If you are hand-assembling a
descriptor, check the key starts with `xpub` before you send it anywhere.

But "cannot spend" is not "harmless." An xpub — and therefore a descriptor —
reveals *every address the wallet will ever derive, on both chains*, plus the
fact that those addresses belong together. That is a permanent, whole-history
disclosure, and it is a far larger one than handing someone a single receive
address. Give it only to a party you would let read your entire transaction
history, and prefer a single address for one-off payments.

Rotating away from a leaked xpub means moving the funds to a new seed. There
is no revoking it.

## Use it from Python

```python
from pyrxd.hd import HdWallet

wallet = HdWallet.load(path, mnemonic)
d = wallet.descriptors()
print(d.receive, d.change, d.master_fingerprint)

checked = wallet.descriptors(checksum=True)   # BIP380 suffix; Radiant Core rejects it
```

`pyrxd.hd.descriptor` also exposes `descriptor_checksum`, `append_checksum`,
and `verify_checksum` if you are handling descriptors from elsewhere.

### The fingerprint is the *master* fingerprint

`wallet.master_fingerprint()` returns `hash160(master pubkey)[:4]` — the
identifier of the key at `m`. It is deliberately **not**
`wallet.account_xpub().fingerprint`, which is the BIP32 *parent* fingerprint
stored inside the account key (the fingerprint of `m/44'/<coin>'`, one level
up). The two differ for any account below depth 1.

This distinction is easy to get wrong and hard to notice: a descriptor built
with the parent fingerprint still derives all the right addresses, so
balances look correct and nothing appears broken. It only fails later, when
some consumer tries to match the descriptor against a signing device or
against another descriptor from the same seed, and the origins do not line up.

---

## See also

- [Receive funds and check your balance](receive-and-check-balance.md) — the
  read-only wallet basics this page extends.
- [Recover funds across wallet paths](recover-funds-across-wallet-paths.md) —
  when the descriptor scans clean but you expected funds, the coin type is the
  usual culprit.
