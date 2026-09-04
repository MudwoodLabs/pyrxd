# Use the public Radiant testnet

The [5-minute quickstart](../tutorials/quickstart.md) runs on **regtest** — a
private chain on your own machine. That is the recommended way to build and
iterate: it's deterministic, free, needs no peers, and you mine and fund blocks
yourself with `pyrxd regtest mine` / `pyrxd regtest fund`. Reach for the public
**testnet** only when you specifically need a *shared* network — testing against
other people's transactions, a wallet, or an indexer over real P2P/finality.

> **Reliability note (verified 2026-06-11).** Radiant's public testnet faucet is
> community-run and was returning a gateway error when this guide was written.
> Regtest has **no** external dependency and is the path that always works; treat
> testnet as best-effort. If the faucet below is down, ask in the official
> Radiant channels (linked from <https://radiantblockchain.org>) for the current
> testnet faucet — do not assume a specific URL is canonical.

## 1. Get a testnet-capable node binary

Testnet runs the same `radiantd` as mainnet, selected with `-testnet`. Download
the latest official release binary from
[Radiant-Core releases](https://github.com/Radiant-Core/Radiant-Core/releases)
(the `radiant-<version>-linux-x64.tar.gz` daemon bundle), or use the Radiant Core
GUI. Run it on testnet:

```console
$ radiantd -testnet -server -txindex=1 \
    -rpcuser=you -rpcpassword=change-me -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1
```

The `SCRIPT_SECURITY_UPGRADE` consensus rules added in v3.1.x — the per-script
opcode-cost budget, the K12 bound, and *consensus* enforcement of the per-script
peak stack-memory budget — are **already active on testnet from block 1**, so
testnet is the closest public mirror of post-upgrade mainnet behaviour, and a
good reason to validate covenant-heavy work here before mainnet.

Do not read that as "none of it applies to mainnet yet". Half of it already
does: `AcceptToMemoryPoolWorker` ORs `SCRIPT_VERIFY_MEMORY_BUDGET` into its
policy verify flags **unconditionally** (`src/validation.cpp:802-804` @
`v3.1.2`) — independently of `fRequireStandard` and of the activation height —
so **every mainnet node's mempool enforces the peak stack-memory budget today**
(`ScriptError::STACK_MEMORY`, `src/script/interpreter.cpp:2659-2665`). A script
that exceeds it is refused relay on mainnet now, while remaining
consensus-valid until the upgrade height. The opcode-cost budget is the half
that really is testnet-only for now: it is gated on `SCRIPT_SECURITY_UPGRADE`
alone (`src/validation.cpp:1782-1784`).

Both budgets' numeric values live in `consensus.h`, which is not among the
sources vendored at `tests/vendor/radiant_core/`, so this guide deliberately
quotes no figure for either — read them from the node you are running.

## 2. Point pyrxd at testnet

pyrxd's CLI config takes a `network` of `mainnet | testnet | regtest`
(`~/.pyrxd/config.toml`, see `pyrxd.cli.config`). Set `network = "testnet"` and
put your testnet node's RPC/ElectrumX endpoints under `[networks.testnet]`.

**This is required, not optional.** pyrxd ships no default testnet ElectrumX
server (none was confirmed to exist), and it will not fall back to the mainnet
one — a `--network testnet` run with no testnet endpoint configured refuses with
a message naming the exact TOML to add. That refusal replaced the older
behaviour, where the same command silently used the *mainnet* server while
reporting itself as testnet. Every endpoint is additionally checked against the
network's genesis hash on first use, so a wrong entry fails immediately instead
of at broadcast time.

```toml
network = "testnet"

[networks.testnet]
electrumx = "wss://your-testnet-electrumx:50022/"
```

Testnet addresses use the testnet version bytes, so a key reconstructed with
`PrivateKey(wif)` from a testnet wallet derives a testnet address — the same flow
as the quickstart, just on the shared chain.

## 3. Fund a testnet address

Testnet coins have no value and come from a faucet (you can't mine them on demand
the way `pyrxd regtest fund` does on your private chain). The community faucet has
been hosted at `faucet-testnet.radiant4people.com` (the mainnet sibling,
`faucet.radiant4people.com`, was live at the time of writing). Paste a testnet
address; if the faucet is unavailable, the official Radiant Discord is the place
to ask for testnet RXD or the current faucet endpoint.

Once funded, every other recipe — minting a Glyph, building a covenant, running a
swap leg — works the same as on regtest; only the network and the source of coins
change.

## When to use which

| | regtest (quickstart) | public testnet |
|---|---|---|
| Coins | `pyrxd regtest fund` (instant, unlimited) | community faucet (best-effort) |
| Blocks | you mine (`pyrxd regtest mine`) | shared, ~real timing |
| Peers / P2P | none (isolated) | real network |
| Determinism | total | none |
| Best for | building & iterating, CI, the quickstart | shared-network / wallet / indexer testing |

For almost all development, **stay on regtest**. Graduate to testnet only for the
shared-network behaviour regtest can't give you.
