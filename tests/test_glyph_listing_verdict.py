"""``judge_listing`` (#788): when the two-operator listing check counts as confirmed.

``confirmed`` is documented as true only when both operators answered and every party listed
exactly the same outpoints. The ``glyph list`` tests reach it through the CLI, where a dispute is
refused before the status is shown, so a verdict that called a disputed listing confirmed went
unseen there. These pin the rule on the verdict itself, each refusal with its honest pair.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.scanner import outpoint_of
from pyrxd.glyph.spentness import INVENTORY, UnspentCrossCheck, judge_listing

A = outpoint_of("aa" * 32, 0)
B = outpoint_of("bb" * 32, 1)
LABELS = ("operator-1", "operator-2")


def _check(first, second) -> UnspentCrossCheck:
    return UnspentCrossCheck(dict(zip(LABELS, (first, second))))


def test_both_operators_listing_what_the_inventory_lists_is_confirmed() -> None:
    verdict = judge_listing(frozenset({A, B}), _check(frozenset({A, B}), frozenset({A, B})))
    assert verdict.confirmed is True
    assert dict(verdict.disputes) == {} and verdict.unreadable == ()


@pytest.mark.parametrize(
    ("inventory", "first", "second", "listed_by", "not_listed_by"),
    [
        # the inventory shows B, which neither operator lists (a re-listed spent output or a decoy)
        ({A, B}, {A}, {A}, (INVENTORY,), LABELS),
        # both operators list B, which the inventory left out (a withholding)
        ({A}, {A, B}, {A, B}, LABELS, (INVENTORY,)),
        # the two operators split on B
        ({A, B}, {A, B}, {A}, (INVENTORY, LABELS[0]), (LABELS[1],)),
    ],
    ids=["inventory-shows-more", "inventory-withholds", "operators-split"],
)
def test_a_listing_with_a_dispute_is_never_confirmed_though_both_answered(
    inventory, first, second, listed_by, not_listed_by
) -> None:
    verdict = judge_listing(frozenset(inventory), _check(frozenset(first), frozenset(second)))
    assert verdict.unreadable == ()
    assert dict(verdict.disputes) == {B: (listed_by, not_listed_by)}
    assert verdict.confirmed is False


def test_one_operator_unread_is_not_confirmed_even_when_the_other_agrees() -> None:
    verdict = judge_listing(frozenset({A}), _check(frozenset({A}), None))
    assert dict(verdict.disputes) == {}
    assert verdict.unreadable == (LABELS[1],)
    assert verdict.confirmed is False
