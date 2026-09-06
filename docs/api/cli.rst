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
- ``pyrxd glyph timelock-mint`` / ``timelock-reveal`` — seal content behind a timelock,
  and later publish the key that opens it. See below.

Timelocked content
------------------

A TIMELOCK Glyph is an NFT whose payload is encrypted off chain while the envelope carries
only ``sha256(key)``, an unlock point and an optional hint. The token itself is spendable and
transferable from the moment it is minted; the timelock gates *visibility*, not ownership.

.. warning::

   **Both of these commands do something that cannot be undone**, and they fail in opposite
   directions.

   ``timelock-mint`` writes the key, the ciphertext and the envelope bytes to files, and
   **nothing on chain carries any of them**. Lose the key or the ciphertext and the content is
   sealed forever — a mint cannot be re-run against the same token. Lose the envelope and a
   mint whose commit confirms while its reveal does not can never be completed: the commit
   output is a hashlock over those exact bytes, this CLI keeps no pending store, and an
   envelope built with ``--recipient`` cannot be reproduced from the same inputs (each wrap
   draws a fresh ephemeral key and nonce). All three output paths are required arguments for
   that reason, and all three files are written before the mint is broadcast.

   ``timelock-reveal`` publishes the key in an OP_RETURN. Once the transaction relays, anyone
   holding the ciphertext can decrypt it, permanently. There is no unreveal and no second
   reveal.

- ``pyrxd glyph timelock-mint --content FILE --name NAME --unlock-at N --cek-out PATH
  --ciphertext-out PATH --envelope-out PATH`` — encrypt ``FILE``, mint an NFT committing to
  the key, and save all three halves. ``--mode block`` (default) reads ``--unlock-at`` as a
  block height; ``--mode time``
  reads it as a unix timestamp. ``--recipient KID:HEX64`` wraps the key to an X25519 public
  key so that party can decrypt **immediately**, without waiting for the reveal; with no
  recipients the reveal is the only way in. The key file is written with mode ``0600``, and an
  existing output path is refused rather than overwritten.

- ``pyrxd glyph timelock-reveal REF --cek-file PATH`` — publish the key for the token at
  ``REF`` (its commit outpoint, the ref ``glyph list`` and ``glyph inspect`` report). The
  token's mint envelope is fetched **from the chain** and the key is checked against the
  commitment recorded there, so a key that does not belong to this token is refused before
  anything is signed — publishing the wrong one would spend the reveal and leave the payload
  unreadable for good. A reveal before the token's unlock point is refused unless
  ``--allow-early`` is passed, which the confirmation prompt then says in as many words.

  The prompt also shows the chain reading the unlock check was decided by — ``chain says:``,
  beside ``opens at:``. That number comes from the ElectrumX endpoint and **pyrxd does not
  verify it**: there is no proof-of-work check, no link to a header you already trust, and no
  second endpoint asked. An endpoint reporting a tip past the unlock point gets a permanent
  early reveal from a gate that believes itself satisfied, so the number is on screen for you
  to disagree with.

  ``--dry-run`` runs every check, builds and signs the transaction, prints the exact key that
  would become public and the raw transaction hex, and broadcasts nothing. Use it first.

  The key is taken from a file rather than an option: a 32-byte key typed on a command line
  lands in shell history. Hex or raw bytes are both accepted.

The read side needs no command of its own — ``pyrxd glyph inspect`` already reports a
timelocked token's unlock point and hint, and ``pyrxd.is_unlocked`` /
``pyrxd.get_unlock_remaining`` answer "can I read it yet" for a caller holding a chain view.

Cross-chain swaps
-----------------

.. warning::

   **This page does not list every** ``pyrxd swap`` **command, and some of the ones it
   omits DO broadcast and spend funds.** ``swap reserve``, ``post``, ``take``, ``cancel``
   and ``refund`` each prompt for confirmation and then broadcast; ``swap orders`` reads
   the on-chain book. Run ``pyrxd swap --help`` for the complete set — that is generated
   from the code and cannot drift.

   The read-only statement below is scoped to the four commands listed under it. It used
   to open this section unqualified, on a page the top-level ``--help`` calls "the full
   reference", which left a reader to conclude that ``pyrxd swap`` never broadcasts.

The four commands below are **strictly read-only — none of them broadcasts**. They print
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
