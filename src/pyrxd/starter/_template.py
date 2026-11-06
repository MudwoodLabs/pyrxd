"""The files of the ``pyrxd new`` starter project, as text.

Kept as Python strings rather than package data so the template renders anywhere pyrxd
imports, including the browser build (Pyodide), with no file reads. Three tokens are
substituted by :func:`pyrxd.starter.render_project`:

``__PROJECT_NAME__``     the distribution name the user chose (``my-token-app``)
``__PACKAGE_NAME__``     its import name (``my_token_app``)
``__PYRXD_REQUIREMENT__`` the pyrxd requirement, derived from the running version

Paths may contain ``__PACKAGE_NAME__`` as well.
"""

from __future__ import annotations

PYPROJECT = """\
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "__PROJECT_NAME__"
version = "0.1.0"
description = "A Radiant app built on pyrxd."
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "__PYRXD_REQUIREMENT__",
]

[project.optional-dependencies]
test = [
    "pytest>=8",
]

[tool.hatch.build.targets.wheel]
packages = ["src/__PACKAGE_NAME__"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
"""

PACKAGE_INIT = '''\
"""__PROJECT_NAME__: a Radiant app built on pyrxd."""
'''

MINT = '''\
"""Mint a Glyph NFT. This is the file to change first.

``mint_nft`` does not care where the chain is: it takes a client (broadcast a transaction,
look one up) and a wallet (coins to spend, and the key for each). The test hands it a
throwaway local chain; ``main`` below hands it the one ``pyrxd regtest up`` started.
For mainnet you would pass an ``ElectrumXClient`` and an ``HdWallet`` instead.

Run it against a local chain::

    pyrxd regtest up
    python -m __PACKAGE_NAME__.mint
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore, MintResult


async def mint_nft(client: Any, wallet: Any, pending_dir: Path, *, name: str, description: str = "") -> MintResult:
    """Mint one NFT, paid for and owned by ``wallet``.

    A mint is two transactions: a commit, then a reveal that spends it. Between the two
    the minter saves its progress in ``pending_dir``, so a crash after the commit can be
    resumed instead of losing the coins locked in it. Keep that directory somewhere that
    lasts.
    """
    minter = GlyphMinter(client, wallet, JsonFilePendingStore(pending_dir))
    metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name, description=description)
    return await minter.mint_nft(metadata)


def main() -> None:
    from pyrxd.devnet import RegtestNode
    from pyrxd.testing import RegtestClient, RegtestWallet

    node = RegtestNode()
    if not node.is_running():
        sys.exit("no local chain is running. Start one with:\\n    pyrxd regtest up")
    wallet = RegtestWallet.funded(node, 1.0)
    result = asyncio.run(
        mint_nft(RegtestClient(node), wallet, Path(".pending-mints"), name="my first glyph")
    )
    print(f"minted an NFT owned by {wallet.address}")
    print(f"  token ref: {result.ref.txid}:{result.ref.vout}")
    print(f"  reveal tx: {result.reveal_txid}")


if __name__ == "__main__":
    main()
'''

CONFTEST = """\
# Loads pyrxd's regtest fixtures: regtest_node, regtest_client, regtest_wallet and
# regtest_wallet_factory. They start a throwaway Radiant node in docker for the test run
# and remove it afterwards.
pytest_plugins = ["pyrxd.testing.pytest_plugin"]
"""

TEST_MINT = '''\
"""Mint on a throwaway local chain and check the result on the node itself."""

from __future__ import annotations

import asyncio

from pyrxd.glyph.script import script_carries_ref

from __PACKAGE_NAME__.mint import mint_nft


def test_mint_nft_lands_on_chain(regtest_client, regtest_wallet, tmp_path):
    result = asyncio.run(mint_nft(regtest_client, regtest_wallet, tmp_path / "pending", name="test nft"))

    # Ask the node, not the minter: the reveal is mined...
    reveal = asyncio.run(regtest_client.get_transaction_verbose(result.reveal_txid))
    assert reveal["confirmations"] >= 1

    # ...one of its outputs holds the new token's ref (its permanent identity)...
    holders = [
        out for out in reveal["vout"]
        if script_carries_ref(bytes.fromhex(out["scriptPubKey"]["hex"]), result.ref.to_bytes())
    ]
    assert len(holders) == 1

    # ...and that output ends in a plain pay-to-public-key-hash to the wallet that minted it.
    owner_pkh = regtest_wallet.private_key.public_key().hash160()
    assert holders[0]["scriptPubKey"]["hex"].endswith("76a914" + owner_pkh.hex() + "88ac")
'''

CI = """\
name: tests

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: __CHECKOUT_ACTION__
      - uses: __SETUP_PYTHON_ACTION__
        with:
          python-version: "3.12"
      - name: Install
        run: pip install -e ".[test]"
      # Builds the Radiant node image from the official release binary (checksum-verified).
      # A few minutes the first time.
      - name: Build the regtest node image
        run: pyrxd regtest setup
      - name: Test against a local regtest chain
        run: pytest -q
"""

GITIGNORE = """\
__pycache__/
*.egg-info/
.venv/
.pytest_cache/
dist/
build/
# The minter's crash-recovery records. Keep them out of git, but do not delete one while
# a mint is unfinished: it holds what is needed to finish the reveal.
.pending-mints/
"""

README = """\
# __PROJECT_NAME__

A Radiant app built on [pyrxd](https://github.com/MudwoodLabs/pyrxd).

## Get going

You need Python 3.10+ and docker.

```bash
pip install -e ".[test]"
pyrxd regtest setup     # once: builds the local Radiant node image
pytest
```

The test starts a throwaway Radiant chain in docker, mints an NFT with
`src/__PACKAGE_NAME__/mint.py`, checks the result on the node, and removes the chain.

## Mint by hand

```bash
pyrxd regtest up        # a local chain that stays up
python -m __PACKAGE_NAME__.mint
pyrxd regtest down
```

## Where to go next

- Change `mint.py`: the metadata, a fungible token (`GlyphMinter.deploy_ft`), or a
  transfer. Keep the test passing as you go.
- The test fixtures (`regtest_client`, `regtest_wallet`, `regtest_wallet_factory`,
  `regtest_node`) come from `pyrxd.testing.pytest_plugin`.
- pyrxd docs: https://mudwoodlabs.github.io/pyrxd/

Everything here runs on regtest, a private chain whose coins are worthless. Moving to
mainnet means a real client and wallet, and real money: read the docs first.
"""

#: Relative path -> content. Order is the order files are written and listed.
FILES: dict[str, str] = {
    "pyproject.toml": PYPROJECT,
    "README.md": README,
    ".gitignore": GITIGNORE,
    ".github/workflows/ci.yml": CI,
    "src/__PACKAGE_NAME__/__init__.py": PACKAGE_INIT,
    "src/__PACKAGE_NAME__/mint.py": MINT,
    "tests/conftest.py": CONFTEST,
    "tests/test_mint.py": TEST_MINT,
}

#: The pinned GitHub Actions the generated workflow uses. Same pins as pyrxd's own
#: workflows; ``tests/test_starter_template.py`` fails if they drift apart.
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
SETUP_PYTHON_ACTION = "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0"
