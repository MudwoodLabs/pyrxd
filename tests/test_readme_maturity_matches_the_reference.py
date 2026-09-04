"""The README must not claim more maturity than the reference table records.

`docs/reference/counter-chain-support.md` is the authority: it gives a proof level
per chain and asset, and states plainly that **not run** means "no run of any kind
has exercised it — not 'broken', unproven".

The README said the swap stack was "proven end-to-end … against BTC, ETH, and EVM
L2s (Base / Optimism / Arbitrum / Linea)" while that table marked **six** of those
rows *not run*. Measured independently: Optimism (10), Optimism Sepolia, Arbitrum
One, Arbitrum Sepolia, Linea and Linea Sepolia have ZERO occurrences in a chain-id
context anywhere in `tests/`.

The README is the widest-audience document this project has, and the one place a
maturity claim is most likely to be believed and least likely to be re-checked.

THE RATCHET GOES BOTH WAYS. If one of these chains ever gets a real run, the table
changes and this test fails — telling whoever did the run that the README can now
be strengthened. An overclaim and a stale underclaim are both drift.
"""

from __future__ import annotations

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_README = _ROOT / "README.md"
_TABLE = _ROOT / "docs/reference/counter-chain-support.md"

#: Chains named in the README's swap bullet whose proof level the table decides.
_L2_NAMES = ("Optimism", "Arbitrum", "Linea", "Base")


def _rows() -> list[tuple[str, str]]:
    """(chain name, proof-level cell) for every data row of the counter-chain table."""
    out = []
    for line in _TABLE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 3 and re.match(r"^[A-Za-z][A-Za-z0-9 ]+$", cells[0]):
            out.append((cells[0], cells[-1]))
    return out


def _unrun_chains() -> set[str]:
    return {name for name, level in _rows() if "not run" in level.lower()}


def test_the_table_parses_into_something_real() -> None:
    """Non-vacuity: an empty parse would make every assertion below pass."""
    rows = _rows()
    assert len(rows) > 8, f"only {len(rows)} chain rows parsed — has the table moved?"
    assert any("not run" in level.lower() for _n, level in rows), "no 'not run' rows found at all"


def test_the_README_does_not_call_an_UNRUN_chain_proven() -> None:
    """The exact overclaim that shipped."""
    readme = _README.read_text(encoding="utf-8")
    unrun = _unrun_chains()
    bad = []
    for para in readme.split("\n\n"):
        if "proven end-to-end" not in para:
            continue
        for name in _L2_NAMES:
            if any(name in u for u in unrun) and re.search(rf"proven end-to-end[^.]*{name}", para):
                bad.append(name)
    assert not bad, (
        f"the README calls the swap stack 'proven end-to-end' against {sorted(set(bad))}, which "
        f"docs/reference/counter-chain-support.md marks 'not run' — meaning no run of any kind has "
        f"exercised it. Either the table is stale (update it) or the README overclaims."
    )


def test_the_README_still_defers_to_the_table() -> None:
    """The claim is only safe because the authority is one click away and named."""
    readme = _README.read_text(encoding="utf-8")
    assert "counter-chain-support.md" in readme
    assert "unaudited" in readme.lower()


def test_the_unrun_set_is_what_the_README_says_it_is() -> None:
    """The both-ways ratchet. If a real run lands, this fails and points at the
    README rather than letting a now-understated claim sit there forever.

    EXACT row names, not substrings. The first version of this asserted
    `any("Optimism" in row ...)`, which "Optimism Sepolia" satisfies — so flipping
    the Optimism mainnet row to a real run changed nothing and the test passed for
    the wrong reason. Caught by planting that exact change.
    """
    unrun = _unrun_chains()
    for name in ("Optimism", "Arbitrum One", "Linea"):
        assert name in unrun, (
            f"{name!r} is no longer marked 'not run' in the counter-chain table. If it has had a "
            f"real run, the README's swap bullet can be strengthened — update both together. "
            f"(currently unrun: {sorted(unrun)})"
        )
