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
   mint whose commit confirms while its reveal does not can be completed only from a second
   copy of those bytes: the commit output is a hashlock over them, and an envelope built with
   ``--recipient`` cannot be reproduced from the same inputs (each wrap draws a fresh ephemeral
   key and nonce). The mint also saves a pending record beside the wallet file, which
   ``glyph resume-mint`` reveals from; the envelope file is the copy that does not depend on
   that directory. All three output paths are required arguments for
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
  ElectrumX query of the RXD covenant that classifies the live situation and prints the single
  safe next action. ``--check-chain`` also reads the BTC/ETH counter-leg, so it can report that
  the counterparty's claim has revealed the preimage — the difference between "keep waiting"
  and "claim now", which the RXD covenant alone cannot show. With no counter-leg locator or
  endpoint configured it reports ``NOT_CHECKED`` with the reason rather than failing.

  The covenant is ONE output, identified by provenance. Its script is a pure function of the
  swap's public terms, so anyone can pay it, and other outputs at the script are counted
  (``chain.ignored_outputs``) and otherwise ignored. The covenant is the outpoint the recovery file
  pins (``rxd_covenant_outpoint``, which the in-tree harnesses write once the covenant is pinned)
  or ``--covenant-outpoint TXID:VOUT``; without either, it is the earliest-confirmed payment to
  the script (of the amount the recovery file records — ``rxd_covenant_amount``, or for an ft
  file without it ``asset_ft_amount``; on Radiant 1 photon = 1 token unit, so that is the funded
  output's value for every variant), in
  the ordering the automated leg uses. Unlike the automated leg, which sees only live outputs, it
  looks through the script's history, so a covenant that was already spent is found even when a
  later payment of another value is still live — when the file records the amount
  (``rxd_covenant_amount``, or for ft ``asset_ft_amount``); with no amount recorded, that case
  reads ``COVENANT_UNIDENTIFIED`` (below). ``chain.covenant_outpoint`` and
  ``chain.covenant_identified_by`` say which output was taken and how. The situations:

  - ``NOT_FUNDED`` — the covenant is not on chain (one ElectrumX server's answer), or a pinned
    outpoint is not found and nothing else is live at the script (the reason says which).
  - ``COVENANT_UNIDENTIFIED`` — no output is named, because naming one would be a guess. The
    reason line says which of these applies; the remedy is ``--covenant-outpoint`` (or fixing the
    pin):

    - unpinned, the earliest output carrying the recorded amount (any output, when no amount is
      recorded) is SPENT while a later one is LIVE — either could be the swap's;
    - unpinned, outputs are live at the script but none carries the recorded amount;
    - unpinned, the history entries that would rule out an earlier, spent covenant could not be
      read, or there are more of them than the read fetches;
    - pinned, the outpoint is neither live nor in the script's history while other outputs are
      live (they are listed; nothing is assumed about them);
    - pinned, the outpoint does not pay the covenant script, or does not carry the recorded amount.
  - ``LOCKED`` — the covenant is live and only the taker's claim can be mined yet.
  - ``REFUND_OPEN`` — the covenant is live and deep enough that the maker's CSV refund is valid.
  For a spent covenant ``--check-chain`` also fetches the spending transaction and reads which
  branch took it — the taker's claim (``<p> OP_0``) or the maker's CSV refund (``OP_1``) — and
  reports it as ``chain.covenant_spend`` (``TAKER_CLAIM``, ``MAKER_REFUND`` or ``UNKNOWN``). A
  refund reported at a height below the covenant's funding height plus ``t_rxd`` cannot be mined,
  and is reported ``UNKNOWN``.

  Every verdict rests on one ElectrumX server and one counter-chain server. None of them says
  outright that nothing is left to claim or refund; the "both legs spent" ones ask for a second,
  independent source first.

  - ``SETTLED`` — both legs are spent and consistent: the taker claimed the covenant and the
    counter-leg was claimed with ``p`` (the swap completed), or the maker refunded the covenant
    and the counter-leg was refunded (aborted, both sides refunded). The counter-leg half is the
    word of the one server that answered, and the text names it.
  - ``MAKER_REFUNDED_AND_CLAIMED`` — the maker CSV-refunded the covenant AND the counter-leg was
    claimed with ``p``: the maker took both legs.
  - ``TAKER_CLAIMED_AND_REFUNDED`` — the taker claimed the covenant AND the counter-leg was
    refunded: the taker took both legs.
  - ``BOTH_SPENT_OUTCOME_UNKNOWN`` — both legs are spent, but the covenant's spending transaction
    could not be read, so who received the asset is not known. It is not a confirmed settlement.
  - ``COUNTER_LEG_LOCKED`` — the covenant is spent but the counter-leg is still locked. After a
    maker's refund the taker must refund its own counter-leg; a BTC HTLC's claim branch has no
    timelock, so until then a maker holding ``p`` can still sweep it. After a taker's claim the
    maker must claim the counter-leg with ``p`` before the taker's refund opens.
  - ``COUNTER_LEG_REFUND_UNCONFIRMED`` — the covenant is spent and the BTC counter-leg is spent by
    a refund the explorer reports NOT confirmed (``status.confirmed`` is not true). The HTLC's
    claim branch has no timelock, so until the refund confirms a claim with ``p`` can still
    replace it: after a taker's claim the maker is told to claim now; otherwise the taker is told
    to watch the refund until it confirms. A BTC refund the explorer reports confirmed is
    ``SPENT_NO_PREIMAGE``, one server's answer, and the text says so.
  - ``COVENANT_SPENT`` — the covenant is spent and the counter-leg was not checked, its read
    failed, or its state is ``UNKNOWN`` or (ETH) ``REFUND_REPORTED_UNCONFIRMED``. It does not mean
    the swap is over.

  The ETH counter-leg has no ``LOCKED`` state: a log can show that the HTLC contract was claimed
  (``Claimed``) or refunded (``Refunded``), never that it was not, and an empty log set is also
  what a pruned node or a log-range limit returns for a claimed contract. It is reported
  ``UNKNOWN``. A preimage in a ``Claimed`` log is
  recovered from the log itself, whether or not the RPC returns the claim transaction, because
  ``p`` is checked against the hashlock. A refund has nothing like that to check. One RPC's
  report of a refund — the ``Refunded`` log and whatever transaction it returns with it,
  including the raw transaction bytes — is that server's word, and pyrxd cannot prove it from
  that server, which can sign a ``refund()`` call with any key, never broadcast it, and name its
  hash in a fabricated log. It is therefore always reported
  ``REFUND_REPORTED_UNCONFIRMED`` (``SPENT_NO_PREIMAGE`` is never produced for ETH), it never
  produces a situation that says nothing is left to claim, and ``recover-preimage`` reports it
  as inconclusive. Check the contract on a second, independent RPC or an explorer before acting
  on a refund; ``--eth-rpc-url`` takes one URL, so pyrxd does not do that for you. The raw bytes
  (``eth_getRawTransactionByHash``) are still checked for consistency with the log: their
  keccak256 must equal the log's transaction hash, and ``Refunded`` logs naming two different
  transactions, or a transaction signed for another chain than the RPC's, are an ``ERROR``.

  Before reading anything, the ETH counter-leg read (``status`` and ``recover-preimage``) asks
  the RPC its chain (``eth_chainId``) and compares it to the ``eth_chain_id`` the recovery file
  records; an RPC on another chain is an ``ERROR`` naming both chain ids. A file that records no
  chain id is still read, and the output says the chain was not checked.

  Errors from a counter-leg endpoint are printed as the exception type, HTTP status and host —
  never the URL, which may carry an API key. Across the CLI, an endpoint named in an error, a
  ``fix:`` hint or a failover warning on stderr is shown as ``scheme://host:port`` only, and text
  an endpoint sends back has the URL's user name, password, query values, fragment and any path
  segment that looks like a credential removed (matched as whole tokens, case-insensitively and in
  percent-encoded form).

  pyrxd has no command that refunds a counter-leg, so where the taker may have to refund it the
  next action says which harness wrote the recovery file, when that leg's refund opens, and
  what in the file the refund needs. A two-host harness's ``--local-out`` secret file is not a recovery file
  ``status`` reads; it is refused with that harness's own ``--phase abort`` command.
- ``pyrxd swap recover-preimage`` — scrape the preimage ``p`` from the counterparty's own
  on-chain claim and verify it. Provenance is mandatory: the fetched bytes must re-derive to
  the reported spender txid AND spend this swap's funding outpoint before anything is
  scraped, so a transaction that merely shares the hashlock is refused. ``--claim-tx-hex`` /
  ``--claim-tx-file`` run it fully offline, with the same requirement. It never reads the
  recovery file's own ``preimage_p_hex`` — on a maker's host that copy may still be a
  pre-reveal secret. An outpoint spent by a transaction that reveals no ``p`` (a refund) is
  reported as such, not as "not revealed yet": no preimage will appear on it.
- ``pyrxd swap build-claim`` / ``build-refund`` — build the covenant spend and print its raw
  hex, alongside the decoded output and who it pays, the fee, the node's relay floor, the
  deadline-aware target, and the timing state. ``build-refund`` refuses an immature CSV
  unless you pass ``--allow-immature`` to pre-build it for broadcast at maturity. The covenant
  output is identified as ``status`` identifies it; other outputs at the covenant script are
  reported and left alone, and ``--covenant-outpoint TXID:VOUT`` names the covenant when the
  recovery file does not. A covenant that is already spent is refused as spent.

Local dev chain
---------------

- ``pyrxd regtest setup`` / ``up`` / ``down`` — build + run a throwaway radiant-core regtest node.
- ``pyrxd setup`` — first-run environment setup.

For guided walkthroughs, see the :doc:`../tutorials/index` and :doc:`../how-to/index`.
