"""Every shipped module is either mutation-tested or on a list that can only shrink.

`scripts/mutation_test.sh` names its modules by hand, group by group. Nothing derived that list
from the code, so a module joined the codebase mutation-tested only if someone remembered — and
the failure is silent in both directions: the suite passes, the weekly workflow is green, and the
module was never mutated.

THIS HAS ALREADY HAPPENED TWICE ON THIS REPO. `mutation_test.sh` itself records the first:
"`keys` was in NEITHER meta-group, so `task mutate all` silently skipped the module set that
[holds secrets, base58 and BIP32 derivation]". That was fixed by adding `keys` to VALUE_GROUPS —
the instance, not the class. It then recurred: `glyph/authority`, `glyph/burn`,
`glyph/relationships`, `glyph/mutable_chain`, `glyph/wave_identity` and `glyph/mark_anchor` were
all added by recent work and were in no group at all, including two modules whose entire job is to
answer "is this claim true".

WHAT KIND OF LIST THIS IS — read this before trusting it. `_NOT_YET_MUTATED` is NOT a set of
modules judged not to need mutation testing. It is a RATCHET: the honest state of the backlog on
the day it was written. Entries may be removed (by putting the module in a group) and must not be
added, so the number only falls. A new module has to be either in a group or a deliberate,
reviewed addition here — it cannot drift in unnoticed.

Whole packages are excluded by RULE rather than listed, because the rule is the reason:
`cli/` is Click wiring, `agent/` and `gravity/watch/` are daemons, `contrib/` is a sample miner.
Mutating command plumbing mostly produces equivalent mutants and swamps the signal.

THE PRIORITY, if someone is picking this up: the largest unmutated modules that carry covenant
bytes, signing, or value arithmetic are `btc_wallet/taproot` (1,466 lines — the BTC HTLC refund
and claim leafs), `gravity/radiant_leg`, `gravity/covenant`, `gravity/htlc_covenant` and
`swap/rswp/covenant`. Those are consensus-enforced, fund-moving, and irreversible when wrong,
which is the stated scope of the suite in its own opening line.
"""

from __future__ import annotations

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "pyrxd"
_SCRIPT = _ROOT / "scripts" / "mutation_test.sh"

#: Packages excluded by rule. The rule IS the reason, so there is nothing per-module to rot.
_OUT_OF_SCOPE_PREFIXES = (
    "cli/",  # Click command wiring: argument plumbing and output formatting
    "agent/",  # long-running daemon, exercised by its own integration tests
    "gravity/watch/",  # watchtower daemons, ditto
    "contrib/",  # sample miner shipped as an example, not a library surface
)
_OUT_OF_SCOPE_MODULES = {
    "__main__",  # `python -m pyrxd` entry point
    "devnet",  # local dev helper, never on a value path
    "utils",  # trivial helpers
}

#: The backlog, not an exemption list. See the module docstring. MAY SHRINK, MUST NOT GROW.
_NOT_YET_MUTATED = frozenset(
    {
        "eth_wallet/replacement",
        "glyph/_confusables",
        "glyph/inspect",
        "glyph/soulbound_detect",
        "gravity/capped_fee_source",
        "gravity/record_sink",
        "gravity/seen_store",
        "gravity/swap_order",
        "gravity/types",
        "script/unlocking_template",
        "spv/proof",
        "spv/witness",
        "swap/rswp/book",
        "swap/rswp/node_rpc",
        "swap/rswp/quoting",
        "swap/rswp/rxindexer_source",
        "swap/rswp/tracker",
        "swap/types",
    }
)


def _shipped_modules() -> set[str]:
    return {p.relative_to(_SRC).with_suffix("").as_posix() for p in _SRC.rglob("*.py") if p.name != "__init__.py"}


def _mutated_modules() -> set[str]:
    """Every module any group names, parsed from the script that actually runs them.

    NOT `if "/" in ...`. The module tables, the test tables, the per-group timeout table and the
    kill-threshold table all share the shape `name) echo "..." ;;`, so the parse has to tell them
    apart. Filtering on a slash looked like it did and silently dropped every group whose modules
    are all single-segment — `fee) echo "fee_sizing"` and `wallet) echo "wallet"` — reporting three
    covered modules as uncovered. An empty-result filter is not a finding until you know why it is
    empty, and this one was wrong in the direction that makes the backlog look worse than it is.
    """
    out: set[str] = set()
    for line in _SCRIPT.read_text(encoding="utf-8").split("\n"):
        m = re.match(r'\s*([a-z]+)\)\s+echo "([^"]*)" ;;', line)
        if not m:
            continue
        items = m.group(2).split()
        if not items or any(i.startswith("tests/") for i in items):
            continue
        if all(re.fullmatch(r"[\d.]+", i) for i in items):  # timeout / threshold tables
            continue
        out.update(items)
    return out


def _in_scope(module: str) -> bool:
    return not module.startswith(_OUT_OF_SCOPE_PREFIXES) and module not in _OUT_OF_SCOPE_MODULES


def test_no_module_joins_the_unmutated_backlog_silently() -> None:
    shipped = _shipped_modules()
    assert len(shipped) > 150, f"only {len(shipped)} modules found — the scan broke, not the code"
    mutated = _mutated_modules()
    assert len(mutated) > 30, f"only {len(mutated)} mutated modules parsed — the script format changed"

    uncovered = {m for m in shipped - mutated if _in_scope(m)}
    new = sorted(uncovered - _NOT_YET_MUTATED)
    assert not new, (
        f"these modules are in NO mutation group and not on the backlog: {new}. Put each in a "
        "group in scripts/mutation_test.sh (that is the fix), or — if it genuinely does not "
        "warrant mutation testing — add it to _OUT_OF_SCOPE_MODULES with the reason. Adding it to "
        "_NOT_YET_MUTATED is the last resort and makes the backlog longer, which is the direction "
        "it is not supposed to move."
    )


def test_the_backlog_only_shrinks() -> None:
    """The ratchet's other jaw: an entry that gained a group, or a module that was deleted, must
    leave — otherwise the list quietly shields a name that could regress later."""
    shipped = _shipped_modules()
    mutated = _mutated_modules()
    uncovered = {m for m in shipped - mutated if _in_scope(m)}
    stale = sorted(_NOT_YET_MUTATED - uncovered)
    assert not stale, (
        f"these are on the not-yet-mutated backlog but no longer belong there: {stale}. Either "
        "they are in a group now (good — delete the entry) or they were deleted/renamed. Leaving "
        "them makes the backlog read longer than it is."
    )


def test_the_documented_exclusion_is_still_true() -> None:
    """`spv/proof` and `spv/witness` are the ONLY modules the suite excludes with a stated reason —
    covered by the fuzz harness instead. Assert that harness still exists, so the reason cannot
    outlive the thing it points at."""
    script = _SCRIPT.read_text(encoding="utf-8")
    flat = " ".join(script.split())
    assert "intentionally excluded" in flat, "the documented exclusion rationale is gone"
    assert (_ROOT / "tests" / "test_fuzz_spv_parsers.py").exists(), (
        "mutation_test.sh excludes spv/proof and spv/witness because tests/test_fuzz_spv_parsers.py "
        "covers them; that file no longer exists, so the exclusion now protects nothing"
    )
