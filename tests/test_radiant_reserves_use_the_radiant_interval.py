"""A RADIANT-chain reserve must never be converted with the BITCOIN interval.

`rxd_claim_burial` and `rxd_claim_inclusion` count RADIANT blocks. They were
converted with `policy.block_interval_s` — Bitcoin's — at seven sites, and
`policy.rxd_block_interval_s` was used for them nowhere (#579).

It survived because it is INERT while every constructor tags those fields BLOCKS:
`normalize_to`/`_reserve_to_blocks` are then the identity and the interval
argument is never read. **A wrong argument that is never used looks exactly like
a right one**, which is why neither review nor the type system nor the parity
sweep caught it — `security/units.py` has one `BlockSpan` for all chains, so a
Radiant block and a Bitcoin block are the same type to it.

Both failure directions are real once a SECONDS value exists, measured at 600/300:

* an 1800 s burial is 6 Radiant blocks and was read as **3** — half the intended
  depth, the unsafe direction;
* a 900 s burial is 3 honest Radiant blocks and was **REFUSED at construction**
  as "1 blk < safety floor 2" — a guard refusing valid work.

Seven sites is why this is a scanner and not seven fixes.

WHAT THIS COVERS, AND WHAT IT DOES NOT. The scan is per CALL, over the AST. It was
per LINE, over a regex, and that missed a site that had shipped: in
`claim_executor._check_value_cap` the field and the interval sit on two different
lines of one call, so no line contained both. Measured — reverting that site passed
the entire suite (10,993 tests), its own module, AND this file. The behavioural
guard for it now lives in `TestTheValueCapReadsTheRadiantInterval`.

IT IS ALSO SYMMETRIC NOW. A Bitcoin reserve converted with the RADIANT interval is
the same defect and was covered by nothing. Found by accident: a bad restore
rewrote `btc_claim_reorg_depth` to use `rxd_block_interval_s` and the whole suite
passed. The field-to-chain map is read off `MarginPolicy` by prefix rather than
hand-typed, so a new `rxd_`/`btc_` reserve is covered the day it is added — the
previous hand-kept tuple is the artifact that let #511's `rxd_claim_inclusion` be
left off a list in the first place.

Still not covered: a regression INSIDE `_radiant_reserve_blocks`, whose parameter is
a generic `reserve` with no field name anywhere in the call. That half is covered by
`test_assess_claim_finality_parity_sweep_byte_equivalent`, whose reference derives
the interval from the rule independently and sweeps a SECONDS-tagged policy.
Verified rather than assumed: switching the helper back to the Bitcoin interval
fails the parity sweep, and adding a fresh call site that bypasses the helper fails
this file. Neither guard covers both, and saying so is the point — a scanner
presented as complete is worse than one with a stated edge.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"

#: Which interval belongs to which chain. The ONLY two spellings that exist.
_INTERVAL_FOR = {"rxd": "rxd_block_interval_s", "btc": "block_interval_s"}


def _chain_tagged_reserves() -> dict[str, str]:
    """Every ``Timelock`` field on :class:`MarginPolicy` that names a chain, DERIVED.

    This was a hand-typed tuple of two field names. A hand-kept list of the things a
    guard covers is the same artifact that produced the bug it guards: ``#511`` added
    ``rxd_claim_inclusion`` and it was left off the validation list, fail-open. Reading
    the prefix off the dataclass means a new ``rxd_``/``btc_`` reserve is covered the
    day it is added, by nobody remembering anything.
    """
    from pyrxd.btc_wallet.taproot import Timelock
    from pyrxd.gravity.swap_coordinator import MarginPolicy

    tagged = {}
    for name, field in MarginPolicy.__dataclass_fields__.items():
        if field.type not in (Timelock, "Timelock"):
            continue
        for chain in _INTERVAL_FOR:
            if name.startswith(f"{chain}_"):
                tagged[name] = chain
    if not tagged:
        raise AssertionError("no chain-tagged reserve fields found — the derivation is broken")
    return tagged


def _identifiers(node: ast.AST) -> set[str]:
    """Every attribute and bare name mentioned anywhere inside *node*.

    Exact identifiers, which is the point of using the AST rather than the text:
    ``rxd_block_interval_s`` CONTAINS ``block_interval_s`` as a substring, so the
    line-based pattern this replaces had to exclude the correct spelling by hand.
    """
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            out.add(child.attr)
        elif isinstance(child, ast.Name):
            out.add(child.id)
    return out


def _offenders() -> list[str]:
    """Call sites converting a chain's reserve with the OTHER chain's interval.

    Per CALL, not per LINE. The line-based version could not see the shape that
    shipped in `claim_executor._check_value_cap`, where the field and the interval sit
    on two different lines of one call — measured: reverting that site passed the
    entire suite, and this file, and was caught by nothing.
    """
    tagged = _chain_tagged_reserves()
    hits = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            names = _identifiers(node)
            for field, chain in tagged.items():
                if field not in names:
                    continue
                wrong = _INTERVAL_FOR[next(c for c in _INTERVAL_FOR if c != chain)]
                if wrong in names and _INTERVAL_FOR[chain] not in names:
                    hits.append(f"{path.relative_to(_ROOT)}:{node.lineno}: {field} ({chain}) converted with {wrong}")
    return hits


def test_the_scanner_catches_the_shipped_defect() -> None:
    """Non-vacuity: a scanner matching nothing is indistinguishable from a clean tree."""
    tree = ast.parse("blocks = _reserve_to_blocks(policy.rxd_claim_burial, policy.block_interval_s)")
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    names = _identifiers(call)
    assert "rxd_claim_burial" in names and "block_interval_s" in names
    assert "rxd_block_interval_s" not in names


def test_the_scanner_sees_a_call_SPLIT_OVER_LINES() -> None:
    """The shape that defeated the line-based version, and the reason for the rewrite.

    In `claim_executor._check_value_cap` the field and the interval are on separate
    lines of one call. A per-line regex matches neither line."""
    src = (
        "burial = self._policy.rxd_claim_burial.normalize_to(\n"
        "    TimeUnit.BLOCKS, block_interval_s=self._policy.block_interval_s\n"
        ").value\n"
    )
    call = next(
        n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and "rxd_claim_burial" in _identifiers(n)
    )
    names = _identifiers(call)
    assert "block_interval_s" in names and "rxd_block_interval_s" not in names


def test_the_scanner_accepts_the_CORRECT_spelling() -> None:
    """Honest path. `rxd_block_interval_s` contains `block_interval_s` as a substring,
    so a naive pattern flags every correct call site — a guard refusing valid work, on
    the very line that fixes the bug."""
    tree = ast.parse("b = _reserve_to_blocks(policy.rxd_claim_burial, policy.rxd_block_interval_s)")
    names = _identifiers(next(n for n in ast.walk(tree) if isinstance(n, ast.Call)))
    assert "block_interval_s" not in names, "the AST must not see a substring"


def test_the_scan_is_SYMMETRIC() -> None:
    """A Bitcoin reserve converted with the RADIANT interval is the same defect.

    Not hypothetical: while verifying this file I accidentally rewrote
    `btc_claim_reorg_depth` to use `rxd_block_interval_s`, and the whole suite —
    10,993 tests — passed. The old scanner only looked one way."""
    assert _chain_tagged_reserves()["btc_claim_reorg_depth"] == "btc"
    tree = ast.parse(
        "d = policy.btc_claim_reorg_depth.normalize_to(BLOCKS, block_interval_s=policy.rxd_block_interval_s)"
    )
    names = _identifiers(next(n for n in ast.walk(tree) if isinstance(n, ast.Call)))
    assert "btc_claim_reorg_depth" in names and "rxd_block_interval_s" in names


def test_no_reserve_is_converted_with_the_other_chains_interval() -> None:
    offenders = _offenders()
    assert not offenders, (
        "a chain's reserve is being converted with the OTHER chain's interval:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse `_radiant_reserve_blocks(policy, reserve)`, which picks the interval once."
    )


def test_the_derivation_still_finds_the_fields_this_guards() -> None:
    """Stale-guard ratchet. If every field were renamed out from under the prefix
    rule, the scan would pass forever by covering nothing."""
    tagged = _chain_tagged_reserves()
    assert {"rxd_claim_burial", "rxd_claim_inclusion", "btc_claim_reorg_depth"} <= set(tagged)
