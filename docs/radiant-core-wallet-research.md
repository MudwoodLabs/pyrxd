# Radiant Core wallet research — what does the node give us for free?

**Date:** 2026-04-30. **Status:** read-only investigation. Informs the [wallet-cli plan](wallet-cli-plan.md) decision.

## Question

Before building a pyrxd CLI / wallet facade, do Radiant Core's built-in wallet RPCs
already cover what users need? Specifically: can someone running a node use
`radiant-cli` to manage RXD and Glyph tokens without pyrxd?

## Method

Live queries against a self-hosted Radiant Core mainnet full node (version 200300, tip 424872 at time of probe). All queries were read-only RPC calls. No funds moved, no wallet state changed.

## Findings

### 1. Radiant Core has a complete Bitcoin-Core-style wallet

Standard wallet RPCs are present and working:

```
getbalance, getunconfirmedbalance, getwalletinfo
getnewaddress, getaddressinfo, listaddressgroupings
listunspent, listtransactions, listsinceblock
sendtoaddress, sendmany
signmessage, signrawtransactionwithwallet
walletcreatefundedpsbt, walletprocesspsbt
backupwallet, dumpwallet, importwallet, dumpprivkey, importprivkey
sethdseed, encryptwallet, walletpassphrase, walletpassphrasechange
addmultisigaddress, importmulti
```

The probed node has 180.48 RXD across 3,165 transactions in an HD-enabled, unencrypted wallet. Functionality at this layer is mature and well-tested (it's Bitcoin Core's wallet, lightly forked).

### 2. The wallet does NOT understand Glyph tokens

Three pieces of evidence:

**(a)** `listunspent` returns no Glyph metadata. The result schema includes `txid`, `vout`, `address`, `scriptPubKey`, `amount`, `confirmations`, `safe`, `solvable`, `spendable`. There's no `glyph_type`, no `token_ref`, no `ft_amount`. The wallet sees a Glyph UTXO as a generic output.

**(b)** Glyph scripts are decoded but classified `nonstandard`. Sample from the `a443d9df…878b` deploy commit (vout 0):

```json
{
  "n": 0,
  "scriptPubKey": {
    "asm": "OP_HASH256 68d8f755… OP_EQUALVERIFY 7957607 OP_EQUALVERIFY OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX 4 OP_NUM2BIN OP_CAT OP_REFTYPE_OUTPUT 1 OP_NUMEQUALVERIFY OP_DUP OP_HASH160 7d6c… OP_EQUALVERIFY OP_CHECKSIG",
    "type": "nonstandard"
  }
}
```

The decoder knows `OP_REFTYPE_OUTPUT` (Radiant added the opcode to the consensus layer), but the wallet's standardness check rejects the script. `sendtoaddress` won't auto-spend it; `solvable: false` would suppress it from `listunspent` defaults.

**(c)** No Glyph-aware RPCs exist beyond the swap index (covered below). No `getglyphs`, `gettokens`, `transferft`, `mintnft`. The full help output mentions "token" only inside the swap RPC group.

### 3. The swap index is a read-only indexer, not a builder

There are seven swap-related RPCs:

```
getopenorders "token_ref"            # open orders selling a token
getopenordersbywant "want_token_ref" # open orders buying a token
getswapcount "token_ref"
getswapcountbywant "want_token_ref"
getswaphistory "token_ref"
getswaphistorybywant "want_token_ref"
getswapindexinfo                     # is the index enabled? what's its tip?
```

All `get*`. No `createswap`, no `takeswap`, no `cancelswap`. The order-record schema is:

```json
{
  "version": n, "flags": n,
  "offered_type": n, "terms_type": n,
  "tokenid": "hex",
  "want_tokenid": "hex",
  "utxo": {"txid": "hex", "vout": n},
  "price_terms": "hex",
  "signature": "hex",
  "block_height": n
}
```

The presence of `signature` and `price_terms` strongly suggests a SIGHASH_SINGLE | ANYONECANPAY partial-tx swap pattern (same family as Bitcoin's "atomic-swap-with-PSBT"). The node *indexes* these orders when they appear on chain — it doesn't build them.

The probed node has the swap index disabled (`enabled: false`); enabling requires `-swapindex=1` in the node config and a reindex. This is a node-operator opt-in feature.

This is **on-chain RXD-internal token swap infrastructure**, distinct from pyrxd's Gravity protocol (which does **cross-chain BTC↔RXD** atomic swaps). They share the "atomic swap" name and SIGHASH-flag tricks but solve different problems.

### 4. Some node-operator-only features exist

```
generate, generatetoaddress, getblocktemplate, submitblock           # mining
finalizeblock, invalidateblock, parkblock, preciousblock              # chain control
addnode, disconnectnode, setban, getpeerinfo                          # P2P control
```

These are operator-of-this-machine commands. Not in pyrxd's scope, ever.

## Implications for pyrxd

### What we'd be re-implementing if we ship a CLI

Not much that's user-visible. RXD `send`, `balance`, `getnewaddress`, etc., have node-wallet equivalents that work fine if the user runs a node. A `pyrxd send` is a worse `radiant-cli sendtoaddress` for that user — it has to reimplement coin selection, fee estimation, signing, broadcasting, all already battle-tested in the node wallet.

### What we'd be adding that doesn't exist anywhere else

- **Glyph token operations.** Mint NFT, deploy FT, transfer FT preserving the on-chain ref, scan an address's Glyph holdings. None of this is in `radiant-cli`. Photonic Wallet (TypeScript) covers it; `pyrxd` is the Python equivalent.
- **No-node usability.** `radiant-cli` requires a synced full node — currently ~50 GB of mainnet history. ElectrumX-backed pyrxd works in seconds from a fresh `pip install`.
- **Cross-chain Gravity.** BTC↔RXD atomic swaps. Distinct from the node's swap index, which is RXD-internal.
- **App-developer ergonomics.** pyrxd is `import pyrxd` in a Python service. `radiant-cli` is a separate process you shell out to.

### What this means for "should we have a CLI?"

The original CLI plan was scoped around plain RXD ops (`send`, `balance`, `address`). Those use cases are largely covered by `radiant-cli` for users who run a node. The places where pyrxd uniquely matters are:

1. People who don't run a node (most app developers). They can't use `radiant-cli`.
2. Glyph token operations. The node wallet doesn't help; pyrxd's `glyph` builders do.
3. Production Python services that need to programmatically transact.

## Three options, re-evaluated

### Option A: Build the CLI as originally specced
The plain-RXD subcommands (`send`, `balance`, `address`) are mostly redundant with `radiant-cli` for node operators. The Glyph subcommands (`mint-nft`, `deploy-ft`, `transfer-ft`) are the genuine value-add.

### Option B: Build a Glyph-only CLI; skip the RXD subcommands
Make the CLI's positioning explicit: "use `radiant-cli` for plain RXD if you have a node; use `pyrxd` for everything Glyph." Smaller surface, clearer story.

### Option C: Skip the CLI; ship `HdWallet.send()` and call it done
Treat pyrxd as a Python-library-only product. Document `radiant-cli` as the recommended end-user CLI. Accept the pip-install-to-first-tx friction.

### Hybrid (probably the right answer)

The best mix is something like:
- **Always:** add `HdWallet.send()` and `HdWallet.send_max()`. Closes a real library-API gap. Small file edit. Independent of CLI decision.
- **Probably:** ship a small CLI with **only the Glyph + Gravity commands** plus a thin `pyrxd address` / `pyrxd balance` for new users who haven't installed a node yet. Frame it explicitly: "for plain RXD with a node, use `radiant-cli`."
- **Defer:** the full `pyrxd send` / `send-max` / `build-tx` / `broadcast` chain. They're nice-to-haves, but they duplicate the node wallet for users who have one and don't move the needle for users who don't (those users want Glyph features more).

This makes pyrxd's CLI a **specialty tool** for Glyph and Gravity, not a "yet another wallet" — clearer differentiation, less work, less maintenance burden.

## Questions for you to weigh in on

1. **Do you want the pyrxd CLI to compete with `radiant-cli` for plain RXD, or stay clear of that?** My recommendation: stay clear. Spend the engineering on what's unique.
2. **What do early users actually have?** If most have ElectrumX access but no node, broad CLI helps. If most run nodes, narrow Glyph-focused CLI is enough.
3. **Is there a documentation/onboarding benefit to a basic `pyrxd send`?** Maybe — a 5-minute "from `pip install` to first tx" demo is hard with no CLI. But that demo can also live in a script in `examples/`.

## Recommendation

Update the plan to be Glyph-and-Gravity-focused rather than full-wallet-replacing.

Concretely:
- **Cut 1:** Add `HdWallet.send()`. Ship a CLI with `pyrxd address`, `pyrxd balance`, `pyrxd glyph mint-nft`, `pyrxd glyph deploy-ft`, `pyrxd glyph transfer-ft`, `pyrxd glyph list`, `pyrxd wallet new`, `pyrxd wallet load`. Skip the `pyrxd send` / `send-max` / `build-tx` / `broadcast` set.
- **Cut 2:** Optionally add `pyrxd send` if the demo-friction case proves real. Add `pyrxd gravity *` for cross-chain atomic swaps once Gravity covenants are hardened.
- **README + docs:** be explicit. "Running a Radiant Core node? `radiant-cli` covers RXD ops. Want Glyph tokens or no-node usage? `pyrxd`."

This costs less to build, has a clear story, doesn't duplicate the node wallet, and focuses pyrxd's value where it actually exists.
