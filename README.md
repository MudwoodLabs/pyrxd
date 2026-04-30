# pyrxd

Python SDK for the [Radiant (RXD) blockchain](https://radiantcore.org/).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docs](https://github.com/MudwoodLabs/pyrxd/actions/workflows/docs.yml/badge.svg)](https://mudwoodlabs.github.io/pyrxd/)

A typed, async-first SDK for building applications on Radiant. Includes
transaction construction, HD wallets, the Glyph token protocol (NFT, FT,
dMint), Gravity cross-chain atomic swaps, SPV verification, and an
ElectrumX network client.

## Status

**Pre-1.0 software.** APIs may change between minor versions before 1.0.
Cryptographic primitives have not been independently audited. See
[SECURITY.md](SECURITY.md) for security policy and disclosure.

**Working on mainnet today:**

- RXD send / send-max, balance and UTXO queries
- Glyph NFT mint (two-phase commit + reveal) and transfer — see `examples/glyph_mint_demo.py`
- Glyph FT premine deploy via `prepare_ft_deploy_reveal` — entire supply at vout[0]
- Glyph FT transfer via `FtUtxoSet.build_transfer_tx` (conservation-enforcing)
- BIP32/BIP39/BIP44 HD wallets with optional encrypted persistence (`HdWallet`)
- ElectrumX async client with reconnect, balance, UTXOs, history, broadcast

**Experimental:**

- Gravity cross-chain BTC↔RXD atomic swaps (`pyrxd.gravity`) — mainnet-proven
  for sentinel artifact paths; covenant variants still being hardened.
- dMint PoW-based distributed FT mint — premine-only deploys ship today; the
  full PoW mint covenant is documented in `docs/dmint-followup.md` as future
  work.

## Installation

```bash
pip install pyrxd
```

Requires Python 3.10 or newer.

## Quick start

### Generate a key and check a balance

```python
import asyncio
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address

async def main():
    priv = PrivateKey()  # no-arg constructor generates a fresh key
    addr = priv.public_key().address()
    print(f"address: {addr}")

    sh = script_hash_for_address(addr)
    async with ElectrumXClient(["wss://electrumx.radiant4people.com:50022/"]) as client:
        confirmed, unconfirmed = await client.get_balance(sh)
        print(f"balance: {confirmed:,} photons confirmed, {unconfirmed:,} unconfirmed")

asyncio.run(main())
```

### Send RXD

```python
from pyrxd.keys import PrivateKey
from pyrxd.transaction.transaction import Transaction, TransactionInput, TransactionOutput
from pyrxd.script.type import P2PKH

priv = PrivateKey("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ")
# ... build transaction with inputs and outputs ...
# See examples/ for full flows.
```

### Mint a Glyph NFT

```python
from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import CommitParams

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="My NFT",
    description="A demo non-fungible token.",
)
builder = GlyphBuilder()
commit = builder.prepare_commit(CommitParams(metadata=metadata, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=funding_amount))
# ... broadcast commit, then reveal ...
```

See [`examples/glyph_mint_demo.py`](examples/glyph_mint_demo.py) for a
complete end-to-end NFT mint, and [`examples/ft_deploy_premine.py`](examples/ft_deploy_premine.py)
for an FT premine deployment.

### Deploy a fungible token (premine)

```python
from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.FT],
    name="My Token",
    ticker="MTK",
    description="A premine fungible token.",
)
# Single commit + reveal mints the entire supply to one address.
# See examples/ft_deploy_premine.py for the full flow.
```

## Command line

`pip install pyrxd` also installs a `pyrxd` CLI. The command surface is
intentionally narrow — it covers wallet management and (in v0.3+)
Glyph token operations, the things that don't have a clean
equivalent in `radiant-cli` (the node wallet). For plain RXD
sendtoaddress on a node, prefer `radiant-cli`.

```bash
# Create a fresh HD wallet. The mnemonic is shown ONCE — write it down.
pyrxd wallet new

# Show the next unused receive address.
pyrxd address

# Check balance via ElectrumX.
pyrxd balance --refresh

# Look up a deterministic index without scanning.
pyrxd address --index 5

# Quiet mode for scripting.
pyrxd --quiet balance --refresh
```

`pyrxd <command> --help` prints the full reference for any subcommand.
JSON mode for scripting: pass `--json` (and `--yes` for any
broadcasting operation).

### Security: scripting `wallet new` with `--json --yes`

In `--json --yes` mode, `pyrxd wallet new` prints the mnemonic in
the JSON payload on stdout — that's the only way scripted automation
can capture a freshly-generated mnemonic. The user is responsible
for ensuring the consumer of stdout is itself secure:

- **Never run `pyrxd wallet new --json --yes | tee mnemonic.txt`** —
  that writes the mnemonic to disk unencrypted.
- **Never run it in a shell whose history is recorded with stdout** —
  most shells don't capture stdout in history, but some configurations
  and tools (`script`, terminal recorders, CI log collectors) do.
- **Don't run it in a container where stdout is logged to a shared
  log aggregator** — containerized stdout is captured by the
  orchestrator and ends up in centralized logging.

The interactive form (`pyrxd wallet new` without `--json`) shows the
mnemonic in a clearly-flagged box and waits for the user to press
Enter. Even then, terminal scrollback, tmux/screen buffers, and
screen-sharing can expose the mnemonic — do not run wallet
generation on a shared or recorded display.

## Production architecture

If you're building a web app that interacts with Radiant in production,
**do not put private keys in your web tier**. A web RCE in your app then
becomes a wallet compromise.

The recommended pattern:

1. Keep `pyrxd` as the cryptographic and protocol library — it's safe to
   import in any process that needs to *read* chain state.
2. Run a separate signing service (a small HTTP service that wraps
   `pyrxd`) on a different process, ideally a different host, with the
   private key loaded only there.
3. Have your web app talk to the signing service over an authenticated
   API (HMAC-signed requests, mutual TLS, or similar) for any operation
   that needs a signature.

This is the pattern used by major payment-rail SDKs (Stripe, Square,
AWS) and is the correct shape for any application handling real funds.

## Documentation

Hosted at **[mudwoodlabs.github.io/pyrxd](https://mudwoodlabs.github.io/pyrxd/)** (API
reference + tutorials + how-to guides + concepts).

Other resources in this repo:

- [`examples/`](examples/) — runnable end-to-end demos
- [`docs/dmint-followup.md`](docs/dmint-followup.md) — premine vs PoW dMint scope
- [`docs/dmint-research-photonic.md`](docs/dmint-research-photonic.md) — Photonic Wallet TS reference
- [`docs/dmint-research-mainnet.md`](docs/dmint-research-mainnet.md) — decoded live dMint contracts
- [`SECURITY.md`](SECURITY.md) — security policy and disclosure

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and how to send a PR. We use the [Developer Certificate of Origin](https://developercertificate.org/)
for contributor sign-off — no CLA paperwork.

By contributing, you agree your contributions are licensed under
Apache 2.0.

## Security

Report vulnerabilities privately to **security@mudwoodlabs.com**. See
[SECURITY.md](SECURITY.md) for the full policy and disclosure timeline.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 [Mudwood Labs](https://mudwoodlabs.com).
