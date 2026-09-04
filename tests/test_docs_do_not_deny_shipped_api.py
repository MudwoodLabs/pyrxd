"""A doc that says a shipped class does not exist sends readers to hand-roll it.

`docs/how-to/build-a-cross-chain-swap.md` said "there is no `BitcoinTaprootLeg`
class yet" and told the reader to consume `pyrxd.btc_wallet.taproot` through a
duck-typed surface. The class exists, is exported, and is what the real-value
runners construct — `scripts/dust_swap_run.py` and `scripts/btc_swap_two_host.py`
both build one, and so does the proven regtest end-to-end.

That is a fund-moving surface, and a hand-rolled adapter that differs subtly from
the shipped leg is exactly the kind of thing that loses money. The same stale
sentence lived in `gravity/counter_chain_leg.py`'s scope note, which is where the
guide got it.

Only HALF of that note was stale, which is why it was corrected rather than
deleted: the coordinator really does still accept `btc_leg` structurally instead
of requiring that file's ABC. Saying the class is missing and saying the ABC is
not yet adopted are different claims, and only the second one was true.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: (symbol, module it must be importable from). Extend as other "does not exist
#: yet" claims are found; the point is that the doc scan below is driven by what
#: the code really exports.
_SHIPPED = [("BitcoinTaprootLeg", "pyrxd.btc_wallet")]


@pytest.mark.parametrize(("symbol", "module"), _SHIPPED)
def test_the_symbol_really_is_exported(symbol: str, module: str) -> None:
    """Non-vacuity, and the premise of the scan below: if this ever stops being
    true the doc claim becomes correct again and this file should be revisited."""
    mod = __import__(module, fromlist=[symbol])
    assert hasattr(mod, symbol), f"{module}.{symbol} is gone — the docs may now be right"


#: Spans that MENTION a phrase rather than ASSERTING it: a correction quoting the
#: wording it replaced. Stripped before scanning.
#:
#: This is not a nicety — it is the use/mention distinction, and a phrase scanner
#: cannot make it. Three separate guards written in one session were defeated by
#: exactly this: each correction quoted the old wrong sentence so a reader could
#: recognise it, and each scanner then matched the quotation and reported the
#: defect as still present. One of them was `git log -S`, which reported no fix at
#: all because the docstring re-added the string it counts.
#:
#: The alternative — banning historical quotes — throws away the most useful part
#: of a correction: telling someone who copied the old text what to re-check.
_MENTION = re.compile(
    r"(?:used to (?:say|read)|previously said|previously read|this page previously|"
    r"originally said)[^.]*?[.\n]"
    r"|[\u201c\u201d\"][^\"\u201c\u201d\n]{0,200}[\u201c\u201d\"]",
    re.IGNORECASE,
)


def _asserting_text(raw: str) -> str:
    """*raw* with quoted/historical spans removed, so only live claims remain."""
    return _MENTION.sub(" ", raw)


@pytest.mark.parametrize(("symbol", "module"), _SHIPPED)
def test_no_doc_or_docstring_says_it_does_not_exist(symbol: str, module: str) -> None:
    denials = []
    targets = list(_ROOT.glob("docs/**/*.md")) + list(_ROOT.glob("src/**/*.py"))
    for path in targets:
        if "brainstorms" in path.parts or "plans" in path.parts or "solutions" in path.parts:
            continue  # dated working notes and incident records describe the past on purpose
        text = path.read_text(encoding="utf-8", errors="replace")
        if symbol not in text:
            continue
        live = _asserting_text(text)
        for phrase in ("does not exist yet", "no `" + symbol + "`", "there is no " + symbol):
            if phrase in live:
                denials.append(f"{path.relative_to(_ROOT)}: {phrase!r}")
    assert not denials, (
        f"{symbol} is exported from {module} and constructed by the real-value swap runners, "
        f"but these say it does not exist — sending a reader to hand-roll an adapter on a "
        f"fund-moving surface:\n  " + "\n  ".join(denials)
    )


def test_the_mention_filter_keeps_ASSERTIONS_and_drops_QUOTATIONS() -> None:
    """Both directions. A filter that swallowed live assertions would make the scan
    above vacuous — the more dangerous failure, since it reads as a pass."""
    assert "does not exist yet" in _asserting_text("The class does not exist yet.")
    assert "does not exist yet" not in _asserting_text(
        'This note used to say "that class does not exist yet", which was wrong.'
    )
    assert "does not exist yet" not in _asserting_text(
        "It previously said \u201cthe class does not exist yet\u201d and sent readers elsewhere."
    )


def test_the_real_value_runners_really_do_construct_it() -> None:
    """The fact that makes the denial serious rather than pedantic."""
    users = [
        p.relative_to(_ROOT)
        for p in _ROOT.glob("scripts/*.py")
        if "BitcoinTaprootLeg(" in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert users, "no runner constructs BitcoinTaprootLeg — re-read before trusting this file"
