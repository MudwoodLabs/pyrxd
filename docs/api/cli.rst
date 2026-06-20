pyrxd — command-line interface
==============================

Run ``pyrxd --help`` (and ``pyrxd <group> --help``) for the authoritative, version-accurate
usage. The command groups:

Wallet & queries
----------------

- ``pyrxd wallet`` — create / manage an encrypted HD wallet.
- ``pyrxd address`` / ``balance`` / ``utxos`` — query an address via ElectrumX.
- ``pyrxd agent`` — the sign-on-behalf signing daemon (see :doc:`agent`).

Glyph tokens
------------

- ``pyrxd glyph init-metadata`` — scaffold a metadata template.
- ``pyrxd glyph mint-nft`` / ``transfer-nft`` — mint and transfer a Glyph NFT.
- ``pyrxd glyph deploy-ft`` / ``transfer-ft`` — deploy (premine) and transfer a Glyph FT.
- ``pyrxd glyph deploy-dmint`` / ``claim-dmint`` — deploy a dMint contract and mine/claim from one.
- ``pyrxd glyph list`` — list the Glyph tokens a wallet holds.

Cross-chain swaps
-----------------

- ``pyrxd swap status --swap-file PATH`` — **read-only** inspection of a Gravity cross-chain swap
  from its recovery file: identity + timelock deadlines, and with ``--check-chain`` a read-only
  ElectrumX query of the RXD covenant that classifies the live situation (LOCKED / REFUND_OPEN /
  SETTLED / NOT_FUNDED) and prints the single safe next action. Never broadcasts.

Local dev chain
---------------

- ``pyrxd regtest setup`` / ``up`` / ``down`` — build + run a throwaway radiant-core regtest node.
- ``pyrxd setup`` — first-run environment setup.

For guided walkthroughs, see the :doc:`../tutorials/index` and :doc:`../how-to/index`.
