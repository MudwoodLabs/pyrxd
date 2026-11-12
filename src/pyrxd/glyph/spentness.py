"""Ask two operators, not one, which of an owner's token outputs are unspent (#788).

:class:`~pyrxd.glyph.scanner.GlyphScanner` binds each listed token output to its own
transaction, so a server cannot invent a token, give it another owner or inflate its amount.
It cannot tell whether that output is still **unspent**: ``listunspent`` is the only source,
and a server that re-lists an output the wallet has already spent passes every other check.

This module asks the question of two sources of DIFFERENT OPERATORS
(:attr:`pyrxd.network.registry.Endpoint.source`), and neither one picks what is checked. The
script hashes each is asked about are derived here, from the owner's key
(:func:`~pyrxd.glyph.scanner.owned_token_script_hashes`), and each source's whole answer is
compared with the other's. So a source that re-lists a spent output (a decoy) and one that
leaves out an output it holds (a withholding) both show up as a disagreement, whichever of the
two sources lies, and whichever of them the inventory scan itself happened to read from.

What agreement is worth: two operators that both list an output as unspent are two operators'
word, not a proof. Two that collude, or that share one upstream node, can agree on a lie.
Nothing here proves an output unspent; that needs a node of one's own.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..security.types import Hex20
from .scanner import owned_token_script_hashes

#: ``(txid, vout)``, the txid lower-case hex in display order.
Outpoint = tuple[str, int]


def outpoint_of(txid: object, vout: int) -> Outpoint:
    """The comparable form of an outpoint: lower-case txid, int vout."""
    return (str(txid).lower(), int(vout))


async def listed_token_outpoints(client: Any, owner_pkhs: Iterable[Hex20]) -> frozenset[Outpoint]:
    """Every outpoint *client* lists as unspent under the token script hashes of *owner_pkhs*.

    The hashes are derived from the owners, never taken from a server. A failed read raises,
    as the client raises it: an answer that is missing a hash is not an empty one.
    """
    hashes = [h for pkh in dict.fromkeys(owner_pkhs) for h in owned_token_script_hashes(pkh)]
    listings = await asyncio.gather(*[client.get_utxos(h) for h in hashes])
    return frozenset(outpoint_of(u.tx_hash, u.tx_pos) for utxos in listings for u in utxos)


@dataclass(frozen=True)
class UnspentCrossCheck:
    """What two sources of different operators each list as unspent, for the same owners.

    ``labels`` names the two sources, in the order they were given. ``agreed`` is what both
    list. ``only_first`` and ``only_second`` are what one lists and the other does not: either
    a lie by one of them (a re-listed spent output, or a withheld unspent one) or a transaction
    one has seen and the other has not yet. This cannot tell those apart, so it never decides
    which side is right.
    """

    labels: tuple[str, str]
    agreed: frozenset[Outpoint]
    only_first: frozenset[Outpoint]
    only_second: frozenset[Outpoint]

    @property
    def disputed(self) -> frozenset[Outpoint]:
        """Every outpoint exactly one of the two sources lists."""
        return self.only_first | self.only_second


async def cross_check_unspent(
    first: Any,
    second: Any,
    owner_pkhs: Iterable[Hex20],
    *,
    labels: tuple[str, str],
) -> UnspentCrossCheck:
    """Ask *first* and *second* which of *owner_pkhs*' token outputs are unspent, and compare.

    The two clients must reach sources of different operators; that is the caller's to
    arrange (``pyrxd glyph list`` picks them by :attr:`~pyrxd.network.registry.Endpoint.source`).
    A failed read on either raises: a source that did not answer has not agreed.
    """
    owners = tuple(dict.fromkeys(owner_pkhs))
    a, b = await asyncio.gather(listed_token_outpoints(first, owners), listed_token_outpoints(second, owners))
    return UnspentCrossCheck(labels=labels, agreed=a & b, only_first=a - b, only_second=b - a)
