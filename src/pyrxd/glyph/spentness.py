"""Ask two operators, not one, which of an owner's token outputs are unspent (#788).

:class:`~pyrxd.glyph.scanner.GlyphScanner` binds each listed token output to its own
transaction, so a server cannot invent a token, give it another owner or inflate its amount.
It cannot tell whether that output is still **unspent**: ``listunspent`` is the only source,
and a server that re-lists an output the wallet has already spent passes every other check.

This module asks the question of two sources of DIFFERENT OPERATORS
(:attr:`pyrxd.network.registry.Endpoint.source`), and neither one picks what is checked. The
script hashes each is asked about are derived here, from the owner's key
(:func:`~pyrxd.glyph.scanner.owned_token_script_hashes`). Each operator's whole answer is
then compared, in BOTH directions, with the listing the inventory was read from
(:func:`judge_listing`): an outpoint the inventory shows that an operator does not list (a
re-listed spent output, a decoy) and an outpoint an operator lists that the inventory left out
(a withholding) are both disagreements. That holds whichever of the servers lies, including
when the inventory came from a server that is neither of the two.

What agreement is worth: two operators that both list an output as unspent are two operators'
word, not a proof. Two that collude, or that share one upstream node, can agree on a lie.
Nothing here proves an output unspent; that needs a node of one's own.

What this does not see: it compares listings for the owners it is given. A server that hides
a whole address while the wallet's addresses are being discovered keeps that address out of
the question, and nothing here notices.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..security.errors import NetworkError, TlsPinMismatchError, ValidationError
from ..security.types import Hex20
from .scanner import Outpoint, outpoint_of, owned_token_script_hashes

__all__ = [
    "ListingVerdict",
    "OperatorNotTrusted",
    "Outpoint",
    "UnspentCrossCheck",
    "cross_check_unspent",
    "judge_listing",
    "listed_token_outpoints",
    "outpoint_of",
]


class OperatorNotTrusted(NetworkError):
    """An operator answered in a way that is not "unreachable": a failed TLS pin, or another chain.

    Either means the client is not talking to the server it was configured for, so its silence
    must not be read as "could not be read, carry on". ``label`` names the operator.
    """

    def __init__(self, label: str, why: str) -> None:
        super().__init__(f"{label}: {why}")
        self.label = label
        self.why = why


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
    """What each of two operators listed as unspent for the same owners.

    ``answers`` maps each operator's label, in the order given, to its listing, or to ``None``
    when it could not be read (a network fault). Nothing here decides who is right.
    """

    answers: Mapping[str, frozenset[Outpoint] | None]

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(self.answers)

    @property
    def answered(self) -> dict[str, frozenset[Outpoint]]:
        return {label: listing for label, listing in self.answers.items() if listing is not None}

    @property
    def unreadable(self) -> tuple[str, ...]:
        return tuple(label for label, listing in self.answers.items() if listing is None)


async def cross_check_unspent(
    first: Any,
    second: Any,
    owner_pkhs: Iterable[Hex20],
    *,
    labels: tuple[str, str],
) -> UnspentCrossCheck:
    """Ask *first* and *second* which of *owner_pkhs*' token outputs are unspent.

    The two clients must reach sources of different operators; that is the caller's to
    arrange (``pyrxd glyph list`` picks them by :attr:`~pyrxd.network.registry.Endpoint.source`).
    Both are always asked, and each answer is kept on its own: one operator failing its reads
    does not throw away the other's answer.

    A network fault leaves that operator's answer ``None``. A failed TLS pin or a chain mismatch
    raises :class:`OperatorNotTrusted` naming it. Anything else is a bug and propagates.
    """
    if len(set(labels)) != 2:
        raise ValidationError("the two operators of a cross-check need two distinct labels")
    owners = tuple(dict.fromkeys(owner_pkhs))
    results = await asyncio.gather(
        listed_token_outpoints(first, owners), listed_token_outpoints(second, owners), return_exceptions=True
    )
    answers: dict[str, frozenset[Outpoint] | None] = {}
    for label, result in zip(labels, results):
        if isinstance(result, TlsPinMismatchError):
            raise OperatorNotTrusted(label, "its TLS certificate does not match the configured pin") from result
        if isinstance(result, ValidationError):
            raise OperatorNotTrusted(label, f"its answer was refused: {result}") from result
        if isinstance(result, NetworkError):
            answers[label] = None
        elif isinstance(result, BaseException):
            raise result
        else:
            answers[label] = result
    return UnspentCrossCheck(answers)


#: The party that served the inventory, in :attr:`ListingVerdict.disputes`.
INVENTORY = "the server this list was read from"


@dataclass(frozen=True)
class ListingVerdict:
    """The inventory's listing judged against the operators that answered.

    ``disputes`` maps each outpoint on which the parties disagree to ``(listed_by, not_listed_by)``:
    the parties, by label (the inventory is :data:`INVENTORY`), that do and do not list it as
    unspent. ``confirmed`` is true only when both operators answered and every party listed
    exactly the same outpoints.
    """

    disputes: Mapping[Outpoint, tuple[tuple[str, ...], tuple[str, ...]]]
    confirmed: bool
    unreadable: tuple[str, ...]


def judge_listing(inventory: frozenset[Outpoint], check: UnspentCrossCheck) -> ListingVerdict:
    """Compare what the inventory was read from with each operator that answered, both ways.

    *inventory* is every outpoint the inventory's server listed under the owners' token hashes
    (:attr:`pyrxd.glyph.scanner.GlyphHoldings.listed`), held or not, so a delegate token both
    sides list is not a disagreement. An outpoint is disputed when some party lists it and some
    other does not: one shown that an operator does not list, one an operator lists that the
    inventory left out, or one the two operators split on. An operator that could not be read
    is no party; with only one left, the inventory is still held to it.
    """
    parties: dict[str, frozenset[Outpoint]] = {INVENTORY: frozenset(inventory), **check.answered}
    every = frozenset().union(*parties.values())
    disputes: dict[Outpoint, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for outpoint in sorted(every):
        listed_by = tuple(p for p, listing in parties.items() if outpoint in listing)
        if len(listed_by) != len(parties):
            disputes[outpoint] = (listed_by, tuple(p for p in parties if p not in listed_by))
    return ListingVerdict(
        disputes=disputes,
        confirmed=not disputes and not check.unreadable and len(check.answered) == 2,
        unreadable=check.unreadable,
    )
