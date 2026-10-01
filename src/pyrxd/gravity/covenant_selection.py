"""Which output paying a covenant scriptPubKey is THE covenant: the shared ordering.

A covenant scriptPubKey is a pure function of a swap's PUBLIC terms, so anyone can pay it, and a
scan of that script can return several outputs. Both readers order candidates by
:func:`earliest_confirmed_key`:

* the automated leg (:meth:`pyrxd.gravity.radiant_leg.RadiantChainIO.find_covenant_utxo`) sees only
  LIVE outputs of the agreed value (and selects the pinned outpoint once the record has one). Any
  live output it can select is spendable under the same covenant terms, so selecting it never
  moves value the terms do not describe;
* the read-only CLI (``pyrxd swap status`` / ``build-claim`` / ``build-refund``, through
  :func:`pyrxd.cli.swap_recovery.locate_covenant_funding`) also sees SPENT outputs, because it
  states whether the swap's covenant is live. Where the earliest candidate is spent and a later one
  is live, that statement would be a guess, so it names neither and asks for the outpoint.

It lives in its own dependency-free module because the CLI's cold-recovery path must not import
the leg module, which holds a broadcaster.
"""

from __future__ import annotations

__all__ = ["earliest_confirmed_key"]

#: Where an unconfirmed output sorts in :func:`earliest_confirmed_key`: after every mined one.
_UNCONFIRMED_SORTS_LAST = 1 << 62


def earliest_confirmed_key(height: int, txid: str, vout: int) -> tuple[int, str, int]:
    """Sort key for "which output paying the covenant script is the covenant": earliest-confirmed.

    The honest funding necessarily precedes any payment made because the script was funded.
    ``height`` is a BLOCK HEIGHT, never a confirmation count (the two sort in opposite directions):
    ``<= 0`` means unconfirmed, which sorts after every mined output, so a mempool output never
    displaces a mined one. Ties break on txid, then output index, so every reader derives the same
    answer whatever order a server lists outputs in.
    """
    return (height if height > 0 else _UNCONFIRMED_SORTS_LAST, txid, vout)
