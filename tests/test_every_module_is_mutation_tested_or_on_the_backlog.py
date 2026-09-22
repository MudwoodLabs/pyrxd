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
#: module -> reason, not a bare set: a reason of "trivial" is a checkable CLAIM (see
#: `_oversized_trivial_reason` below), and a claim written as an inline `#` comment cannot be
#: read by any test. `utils` used to carry `# trivial helpers` here — PR #669 moved
#: `serialize_ecdsa_der`/`deserialize_ecdsa_der` (the consensus-strict DER parser every
#: signature now goes through), `decode_address`, `decode_wif`, `encode_script_num`/
#: `decode_script_num` and `encode_pushdata` into it, growing it to 794 lines, and the reason
#: went stale without anyone touching this line. It is now mutation-tested in the `cryptoprim`
#: group instead (scripts/mutation_test.sh) and has no entry here at all.
_OUT_OF_SCOPE_MODULES = {
    "__main__": "`python -m pyrxd` entry point",
    "devnet": "local dev helper, never on a value path",
    # A pure re-export of `security/json_guards`, which IS mutation-tested in the
    # `network` group. There is no behaviour here to mutate: five import bindings and
    # an `__all__`. The reason is not prose anyone has to keep believing —
    # `tests/web/test_mark_anchor_bridge.py::
    # TestTheAnchorIsReachableFromTheBrowser::test_the_old_location_re_exports_rather_
    # than_redefines` asserts each name is the SAME OBJECT as the one in the real
    # module, so the day this file grows a second definition that test fails and this
    # entry stops being true out loud.
    "network/_guards": "pure re-export of security/json_guards, which is mutated in the network group",
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


#: Below this line count, calling a module "trivial" is plausible on its face. The genuinely
#: trivial modules elsewhere in this repo sit far under it — script/unlocking_template.py is 17
#: lines, __main__.py is 8 — so 100 is a generous ceiling, not a tight one, and still catches
#: utils.py's actual size (794 lines, measured 2026-09-13) by a wide margin.
_TRIVIAL_LINE_LIMIT = 100


def _oversized_trivial_reason(module: str, reason: str) -> str | None:
    """Return a failure message if `reason` calls `module` trivial but its line count says
    otherwise, else None.

    A standalone function, not inlined in a test loop, so its correctness can be demonstrated
    directly (see `test_the_trivial_size_check_actually_fires` below) independent of whatever
    `_OUT_OF_SCOPE_MODULES` happens to hold today — a check whose only evidence is an empty loop
    over the current entries is indistinguishable from a check that can never fail.
    """
    if "trivial" not in reason.lower():
        return None
    path = _SRC / f"{module}.py"
    if not path.exists():
        return f"{module} is out of scope but src/pyrxd/{module}.py does not exist"
    lines = path.read_text(encoding="utf-8").count("\n") + 1
    if lines <= _TRIVIAL_LINE_LIMIT:
        return None
    return (
        f"{module} is exempted from mutation testing as trivial ({reason!r}) but is {lines} "
        f"lines — over the {_TRIVIAL_LINE_LIMIT}-line ceiling this repo's genuinely trivial "
        "modules sit well under (script/unlocking_template.py: 17 lines, __main__.py: 8 lines). "
        "Either the module shrank back down and the ceiling is fine, or the reason is stale and "
        "the module needs a real entry in scripts/mutation_test.sh."
    )


def test_a_trivial_exemption_reason_is_still_a_small_module() -> None:
    """The backlog ratchet (above) catches a module with NO stated reason. This catches the
    quieter version: a reason that WAS true and silently stopped being true, because nothing
    re-checks prose after it is written. `utils` carried exactly this — "trivial helpers" — for
    however long it took to grow from a handful of re-exports to 794 lines including the DER
    encoder every signature now goes through, and no test here would have said so."""
    bad = [
        msg for module, reason in _OUT_OF_SCOPE_MODULES.items() if (msg := _oversized_trivial_reason(module, reason))
    ]
    assert not bad, "\n".join(bad)


def test_the_trivial_size_check_actually_fires() -> None:
    """Non-vacuity for the test above: `_OUT_OF_SCOPE_MODULES` currently exempts nothing as
    'trivial' (the fix for this exact finding removed the one entry that did), so that test
    passes over zero iterations — output identical to a check that cannot fail at all. Call the
    same function directly against `utils.py`, a real file this repo ships, to prove it still
    catches an oversized 'trivial' claim rather than having quietly stopped checking anything."""
    utils_lines = (_SRC / "utils.py").read_text(encoding="utf-8").count("\n") + 1
    assert utils_lines > _TRIVIAL_LINE_LIMIT, (
        f"utils.py is now only {utils_lines} lines, at or under the {_TRIVIAL_LINE_LIMIT}-line "
        "ceiling — pick a different real, oversized module to prove this check fires"
    )
    msg = _oversized_trivial_reason("utils", "trivial helpers")
    assert msg is not None, "the trivial-size check no longer fires on a real oversized module"


def test_a_genuinely_trivial_module_is_not_refused() -> None:
    """The honest-path pair for the refusal above: a module that really is small must not be
    flagged just because its reason contains the word "trivial". `script/unlocking_template.py`
    is one of this repo's real, currently-exempt-by-rule trivial re-export files (17 lines,
    called "trivial re-exports" in scripts/mutation_test.sh's own comment) — the check must let
    an honest case like it through, or the ceiling would refuse legitimate exemptions and someone
    would end up raising `_TRIVIAL_LINE_LIMIT` to make the false alarm go away rather than fixing
    a real one."""
    path = _SRC / "script" / "unlocking_template.py"
    lines = path.read_text(encoding="utf-8").count("\n") + 1
    assert lines <= _TRIVIAL_LINE_LIMIT, (
        f"script/unlocking_template.py is now {lines} lines — pick a different genuinely small "
        "module to prove the honest path"
    )
    assert _oversized_trivial_reason("script/unlocking_template", "trivial re-exports") is None
