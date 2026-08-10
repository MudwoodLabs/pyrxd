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
- ``pyrxd glyph dmint-estimate`` — benchmark this machine's SHA256d rate and estimate
  time-to-mint (MEASURED rate, EXACT attempt distribution, PROJECTED ETA — kept apart).
- ``pyrxd glyph list`` — list the Glyph tokens a wallet holds.

Cross-chain swaps
-----------------

All four commands below are **strictly read-only — none of them broadcasts**. They print
facts and raw transaction hex; you inspect the result and broadcast it yourself, from your
own node, at a fee you chose. That is deliberate: Radiant has neither RBF nor CPFP, so a
time-critical claim or refund that fails to get mined cannot be bumped by any means, and a
human sizing the fee is the only remaining control.

- ``pyrxd swap status --swap-file PATH`` — inspection of a Gravity cross-chain swap from its
  recovery file: identity + timelock deadlines, and with ``--check-chain`` a read-only
  ElectrumX query of the RXD covenant that classifies the live situation (LOCKED /
  REFUND_OPEN / SETTLED / NOT_FUNDED) and prints the single safe next action. ``--check-chain``
  also reads the BTC/ETH counter-leg, so it can report that the counterparty's claim has
  revealed the preimage — the difference between "keep waiting" and "claim now", which the
  RXD covenant alone cannot show. With no counter-leg locator or endpoint configured it
  reports ``NOT_CHECKED`` with the reason rather than failing.
- ``pyrxd swap recover-preimage`` — scrape the preimage ``p`` from the counterparty's own
  on-chain claim and verify it. Provenance is mandatory: the fetched bytes must re-derive to
  the reported spender txid AND spend this swap's funding outpoint before anything is
  scraped, so a transaction that merely shares the hashlock is refused. ``--claim-tx-hex`` /
  ``--claim-tx-file`` run it fully offline, with the same requirement. It never reads the
  recovery file's own ``preimage_p_hex`` — on a maker's host that copy may still be a
  pre-reveal secret.
- ``pyrxd swap build-claim`` / ``build-refund`` — build the covenant spend and print its raw
  hex, alongside the decoded output and who it pays, the fee, the node's relay floor, the
  deadline-aware target, and the timing state. ``build-refund`` refuses an immature CSV
  unless you pass ``--allow-immature`` to pre-build it for broadcast at maturity.

Local dev chain
---------------

- ``pyrxd regtest setup`` / ``up`` / ``down`` — build + run a throwaway radiant-core regtest node.
- ``pyrxd setup`` — first-run environment setup.

For guided walkthroughs, see the :doc:`../tutorials/index` and :doc:`../how-to/index`.
