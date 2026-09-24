"""Opt-in e2e fixtures must satisfy the invariants production enforces — checked OFFLINE.

WHY THIS EXISTS. `XCHAIN_ETH_GLYPH_REAL` is scheduled nowhere, so nothing ran it for months. When
it was finally run it failed three times over, each on a guard that had landed since: the #482
timelock ordering, the cross-clock margin gate, and the mandatory ETH persist hook.

The expensive lesson is not "schedule the suite". Two of those three were failures of the FIXTURE,
and both are detectable with NO Docker, NO node and NO indexer: `NegotiatedTerms(t_rxd=60,
t_btc=100)` raises at construction. The suite never needed a node to reveal that it had rotted — it
needed anything at all to construct its terms, and nothing in CI ever did.

So this file runs in ordinary CI and asserts that the fixtures of the opt-in suites still satisfy
the guards production applies to them. It catches fixture drift the day it lands rather than the
next time somebody happens to stand up a Docker stack.

Scope, honestly: this pins the TIMELOCK RELATION, which is the invariant that has actually rotted
(three separate artifacts have now been caught carrying the pre-#482 ordering: the conformance
vectors in 0.22.0, the HZ-4 spec paragraph in #620, and these fixtures). It does not simulate the
suites; a fixture can satisfy this and still fail against a live node for other reasons.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.swap_state import NegotiatedTerms
from pyrxd.security.errors import ValidationError

_TESTS = Path(__file__).resolve().parent


def _opt_in_swap_suites() -> list[Path]:
    """Test files that are env-gated AND construct NegotiatedTerms.

    Derived, not listed. A new opt-in swap suite is covered the day it is added — the failure this
    file exists to prevent is precisely a suite nobody remembered to include.
    """
    out = []
    for f in sorted(_TESTS.glob("test_*.py")):
        if f.name == Path(__file__).name:
            continue
        src = f.read_text(errors="ignore")
        if "os.environ.get" in src and "pytest.skip" in src and "NegotiatedTerms(" in src:
            out.append(f)
    return out


def _timelock_blocks(node: ast.AST) -> int | None:
    """The literal block count in a `Timelock(<int>, ... BLOCKS)` call, if it is a plain literal."""
    if not (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", None)) == "Timelock"):
        return None
    if not node.args:
        return None
    first = node.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, int) else None


def _timelock_sites(scope: ast.AST) -> list[tuple[str, ast.AST, int]]:
    """Every place a `t_btc` / `t_rxd` Timelock is bound, in EITHER shape.

    Two shapes, and the second is why this is not just an assignment scan: three suites bind it as
    a local (`t_btc = Timelock(...)`) and a fourth passes it straight into the constructor
    (`NegotiatedTerms(..., t_btc=Timelock(...))`). The first version of this guard only walked
    assignments and gave that fourth suite a clean pass — the same hand-shaped-scope failure it
    was written to catch, committed inside the guard itself.
    """
    sites: list[tuple[str, ast.AST, int]] = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", getattr(node.targets[0], "attr", None))
            if name in ("t_btc", "t_rxd"):
                sites.append((name, node.value, node.lineno))
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("t_btc", "t_rxd"):
                    sites.append((kw.arg, kw.value, getattr(kw.value, "lineno", node.lineno)))
    return sites


def _scope_of_each_site(tree: ast.AST) -> dict[int, str]:
    """Innermost enclosing function for every line, so bindings in different tests never pair.

    Without this the scan compared ONE `t_rxd` against ONE `t_btc` per file. Pairing across
    unrelated test functions is meaningless, and — worse — the single-slot dict that produced it
    let a later correct pair MASK an earlier inverted one.
    """
    scope: dict[int, str] = {}

    def walk(node: ast.AST, name: str) -> None:
        for child in ast.iter_child_nodes(node):
            here = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else name
            if hasattr(child, "lineno"):
                scope[child.lineno] = here
            walk(child, here)

    walk(tree, "<module>")
    return scope


def _inverted_relations(path: Path) -> list[tuple[int, str]]:
    """Every binding that gives `t_btc` a value provably >= `t_rxd` — the pre-#482 ordering.

    EVERY pair, not the last one. The first version kept `literals[name]` in a single per-file
    slot and compared once at the end, so a file with an inverted pair followed by a correct pair
    came back CLEAN — measured: `t_rxd=60/t_btc=100` then `t_rxd=100/t_btc=60` returned []. Any
    honest test added below an inverted fixture silently certified it.

    Two detectable forms, both observed in this repo:
      * two int literals in the same scope, e.g. `t_rxd = Timelock(60)` / `t_btc = Timelock(100)`
      * an OFFSET off a shared base, `t_btc = Timelock(t_rxd_blocks + 40)` — inverted for EVERY
        value of the base, which a literal comparison alone would never catch.
    """
    tree = ast.parse(path.read_text(errors="ignore"))
    scope_of = _scope_of_each_site(tree)
    bad: set[tuple[int, str]] = set()
    by_scope: dict[str, list[tuple[str, int, int]]] = {}

    for name, value, lineno in _timelock_sites(tree):
        blocks = _timelock_blocks(value)
        if blocks is not None:
            by_scope.setdefault(scope_of.get(lineno, "<module>"), []).append((name, blocks, lineno))
            continue
        if name == "t_btc" and isinstance(value, ast.Call) and value.args:
            arg = value.args[0]
            if (
                isinstance(arg, ast.BinOp)
                and isinstance(arg.op, ast.Add)
                and isinstance(arg.right, ast.Constant)
                and isinstance(arg.right.value, int)
                and arg.right.value > 0
            ):
                base = getattr(arg.left, "id", "<expr>")
                bad.add((lineno, f"t_btc = Timelock({base} + {arg.right.value}) — exceeds t_rxd for every base"))

    # Within a scope, compare each `t_btc` against the NEAREST `t_rxd`, and flag every offender.
    for sites in by_scope.values():
        sites.sort(key=lambda s: s[2])
        rxds = [(v, ln) for n, v, ln in sites if n == "t_rxd"]
        for n, btc, btc_ln in sites:
            if n != "t_btc" or not rxds:
                continue
            rxd, _ = min(rxds, key=lambda r: abs(r[1] - btc_ln))
            if rxd <= btc:
                bad.add((btc_ln, f"t_rxd={rxd} <= t_btc={btc}"))
    return sorted(bad)


#: A file whose timelocks come from a production derivation cannot drift from the gate by
#: construction — there is no constant to go stale. That is the SAFE pattern, and it is also
#: invisible to a scan looking for literals, so the two have to be told apart.
#:
#: ONE PER COUNTER-CHAIN CLOCK. The ETH sizer sizes ``t_rxd`` from the absolute ETH deadline; the
#: BTC-family derivation (``scripts/_dust_swap_shared.py``, what the BTC runners negotiate with)
#: derives ``t_btc`` from ``t_rxd`` in wall clock. This named only the ETH sizer — the one the guard
#: was written from — so the BTC<->RXD suite, once it derived its timelocks, read as "evaluated
#: NOTHING".
_DERIVED_FROM_PRODUCTION = ("eth_absolute_to_rxd_relative_blocks", "derive_counter_timelock")


def _calls_a_production_derivation(path: Path) -> bool:
    """True iff the file CALLS one of ``_DERIVED_FROM_PRODUCTION`` — a call, not a mention.

    This was a substring test on the file's text, which accepted a file that merely NAMED the sizer
    in a comment or docstring — and a comment is exactly where a file says it SHOULD derive its
    timelocks. That is the fail-open direction: a blind scan reported as a derived one.
    """
    for node in ast.walk(ast.parse(path.read_text(errors="ignore"))):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in _DERIVED_FROM_PRODUCTION:
                return True
    return False


def _comparisons_made(path: Path) -> int:
    """How many orderings this scan actually EVALUATED in this file.

    Not how many bindings exist. The motivating suite has four `t_rxd`/`t_btc` bindings and the
    scan can compare NONE of them — they are derived expressions, not literals — so it returned an
    empty finding list that read exactly like a clean file.

    "No findings" and "nothing was checked" must not look the same. This is the number that tells
    them apart, and `test_the_scan_is_not_silently_blind` below asserts on it.
    """
    tree = ast.parse(path.read_text(errors="ignore"))
    scope_of = _scope_of_each_site(tree)
    by_scope: dict[str, list[tuple[str, int, int]]] = {}
    offsets = 0
    for name, value, lineno in _timelock_sites(tree):
        blocks = _timelock_blocks(value)
        if blocks is not None:
            by_scope.setdefault(scope_of.get(lineno, "<module>"), []).append((name, blocks, lineno))
        elif name == "t_btc" and isinstance(value, ast.Call) and value.args:
            arg = value.args[0]
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add) and isinstance(arg.right, ast.Constant):
                offsets += 1
    pairs = sum(
        sum(1 for n, _, _ in s if n == "t_btc") for s in by_scope.values() if any(n == "t_rxd" for n, _, _ in s)
    )
    return pairs + offsets


def test_the_scan_finds_the_opt_in_swap_suites() -> None:
    """Non-vacuity. Every assertion below is over a discovered set; an empty set passes them all
    while checking nothing — the exact shape of the guard that let this rot in the first place."""
    suites = _opt_in_swap_suites()
    assert suites, "no opt-in swap suites discovered — the derivation has broken"
    names = {p.name for p in suites}
    assert "test_xchain_eth_glyph_real_rxindexer_e2e.py" in names, "the suite this was found in must be in scope"


#: Suites known to carry the pre-#482 ordering TODAY. Every one of them currently cannot construct
#: its own terms, so every one of them is red the moment anyone stands up its stack.
#:
#: These are xfail(strict=True), not skips: when a suite is fixed the xpass FAILS and whoever fixed
#: it has to delete the entry. That is the difference between debt that gets paid and debt that
#: quietly becomes the baseline.
#:
#: The BTC<->RXD and ETH<->RXD nightly suites were on this list until they were re-derived: they now
#: take their timelocks from the production derivations, and their strict xfails XPASSed, which is
#: what removed them. Neither turned out to be mechanical. Both needed ``t_rxd`` re-derived as well
#: as ``t_btc`` (the ETH suites against the cross-clock gate), and the adversarial
#: ``TestMakerStallAssetOnlyRefundIsTakerLoss`` needed its geometry re-derived, not flipped: under
#: #482 the taker's BTC refund has already opened by the time the asset-only refund can fire.
_KNOWN_BROKEN = {
    "test_xchain_erc20_usdc_lifecycle_e2e.py": (
        "t_btc = t_rxd + 40 passed as a constructor keyword; ALSO its t_rxd (8/60 blocks at 600 s) cannot "
        "clear the cross-clock gate against its 50,000 s ETH deadline, and its flows mine 3 extra covenant "
        "confirmations before funding, so a sizer anchored at now would still be refused. Needs a mainnet "
        "fork RPC to run, so it has not been re-derived blind"
    ),
}


def _blindness_reason(path: Path) -> str | None:
    """None if this file's clean verdict is trustworthy; otherwise why it is not.

    EXTRACTED so it can be tested on a synthetic file. Inline, its failing branch existed nowhere
    in the tree — all four real suites satisfy it — so short-circuiting the whole check left every
    test green. A check whose failure case cannot occur in the corpus it runs over is vacuous, and
    that is precisely the defect this module exists to catch.
    """
    if _comparisons_made(path) > 0:
        return None
    if _calls_a_production_derivation(path):
        return None
    return (
        f"{path.name} builds swap terms, but this scan evaluated NOTHING in it and it does not "
        f"derive them via {' or '.join(_DERIVED_FROM_PRODUCTION)}. A clean result here means the scan "
        "could not read the file, not that the file is correct — extend the scan or derive the timelocks."
    )


@pytest.mark.parametrize("path", _opt_in_swap_suites(), ids=lambda p: p.name)
def test_no_opt_in_fixture_uses_the_pre_482_ordering(path: Path, request) -> None:
    if path.name in _KNOWN_BROKEN:
        request.node.add_marker(
            pytest.mark.xfail(strict=True, reason=f"known pre-#482 fixture: {_KNOWN_BROKEN[path.name]}")
        )
    bad = _inverted_relations(path)
    assert not bad, (
        f"{path.name} builds swap terms with t_btc >= t_rxd: "
        + "; ".join(f"line {ln}: {why}" for ln, why in bad)
        + ". That is the pre-#482 arrangement — the maker refunds its own covenant while p is still "
        "secret and then claims the counter leg, taking both. NegotiatedTerms refuses it, so this "
        "suite cannot run; because it is opt-in, nothing says so until someone stands up Docker."
    )


class TestTheProductionGuardIsWhatWeArePinning:
    """The scan is a proxy. These call the real constructor so the proxy cannot drift from it —
    if the invariant is ever relaxed or reversed, this fails and the scan must be revisited."""

    @staticmethod
    def _terms(t_rxd_blocks: int, t_btc_blocks: int) -> NegotiatedTerms:
        return NegotiatedTerms(
            hashlock=hashlib.sha256(os.urandom(32)).digest(),
            btc_sats=100_000,
            radiant_amount=1000,
            t_btc=bt.Timelock(t_btc_blocks, bt.TimeUnit.BLOCKS),
            t_rxd=bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"\x00" * 36,
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=b"\x00" * 32,
            btc_refund_pubkey_xonly=b"\x00" * 32,
        )

    def test_the_correct_ordering_is_accepted(self) -> None:
        """The control, and it is load-bearing: without it a refusal below could be caused by any
        unrelated argument error and would look identical to the invariant firing. That happened
        while writing this file — a missing `genesis_ref` produced a confident, wrong 'REFUSED'."""
        assert self._terms(100, 60) is not None

    def test_the_inverted_ordering_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="requires t_rxd > t_btc"):
            self._terms(60, 100)

    def test_the_offset_shape_the_suites_used_is_refused(self) -> None:
        """`t_btc = t_rxd + 40`, the exact shape three opt-in suites shipped, at several bases —
        the relation is inverted for every one of them, which is why an eyeball on one value
        would not have caught it."""
        for base in (6, 60, 600):
            with pytest.raises(ValidationError, match="requires t_rxd > t_btc"):
                self._terms(base, base + 40)


def test_the_known_broken_list_names_only_real_files() -> None:
    """The other direction. An entry for a file that no longer exists — renamed, deleted, or
    merged away — is an exemption that has silently stopped applying to anything, and it would
    keep this guard quiet about a suite nobody is watching."""
    present = {p.name for p in _opt_in_swap_suites()}
    stale = set(_KNOWN_BROKEN) - present
    assert not stale, f"_KNOWN_BROKEN names suites that are no longer discovered: {sorted(stale)}"


@pytest.mark.parametrize("path", _opt_in_swap_suites(), ids=lambda p: p.name)
def test_the_scan_is_not_silently_blind(path: Path) -> None:
    """A clean verdict must mean "checked and correct", never "could not read it".

    The scan returned an empty list for `test_xchain_eth_glyph_real_rxindexer_e2e.py` — the suite
    it was WRITTEN from — because that file now derives `t_rxd` from the production sizer, so
    there is no literal to compare. That is the right thing for the file to do and the wrong thing
    for the guard to report as a pass.

    So a file is acceptable on exactly one of two grounds, and it must be clear WHICH:
      * the scan evaluated at least one ordering in it, or
      * it takes its timelocks from the production sizer, where no constant can drift.
    """
    assert _blindness_reason(path) is None, _blindness_reason(path)


class TestTheScanItselfBehaves:
    """Synthetic inputs, because every assertion above is over the FILES CURRENTLY IN THE TREE —
    and none of them happens to contain a masking pair. Planting the old single-slot comparison
    back left the whole module green, which is how the masking bug survived being "verified" by an
    ad-hoc probe that never became a test.
    """

    @staticmethod
    def _scan(tmp_path, body: str):
        f = tmp_path / "sample.py"
        f.write_text(body)
        return _inverted_relations(f)

    def test_an_inversion_is_not_masked_by_a_later_correct_pair(self, tmp_path) -> None:
        """THE REGRESSION. One slot per file meant only the LAST binding of each name was
        compared, so appending an honest test silenced an inverted fixture above it."""
        found = self._scan(
            tmp_path,
            "def t():\n"
            "    t_rxd = bt.Timelock(60, B)\n"
            "    t_btc = bt.Timelock(100, B)\n"
            "    t_rxd = bt.Timelock(100, B)\n"
            "    t_btc = bt.Timelock(60, B)\n",
        )
        assert found, "an inverted pair followed by a correct one must still be reported"
        assert any(ln == 3 for ln, _ in found), f"must name the inverted line, got {found}"

    def test_bindings_in_different_functions_do_not_pair(self, tmp_path) -> None:
        """The other direction. Comparing a `t_rxd` from one test against a `t_btc` from another
        invents an ordering neither test states — a guard refusing valid work."""
        found = self._scan(
            tmp_path,
            "def a():\n    t_rxd = bt.Timelock(100, B)\n    t_btc = bt.Timelock(60, B)\n"
            "def b():\n    t_rxd = bt.Timelock(200, B)\n    t_btc = bt.Timelock(120, B)\n",
        )
        assert found == [], f"two independently correct scopes must be clean, got {found}"

    def test_every_offender_is_reported_not_just_the_first(self, tmp_path) -> None:
        found = self._scan(
            tmp_path,
            "def a():\n    t_rxd = bt.Timelock(60, B)\n    t_btc = bt.Timelock(100, B)\n"
            "def b():\n    t_rxd = bt.Timelock(3, B)\n    t_btc = bt.Timelock(6, B)\n",
        )
        assert len(found) == 2, f"both scopes are inverted; got {found}"

    def test_a_derived_file_reports_zero_COMPARISONS_not_zero_findings(self, tmp_path) -> None:
        """The blindness half, pinned on the scan rather than on a real file — so it keeps holding
        when those files change."""
        f = tmp_path / "derived.py"
        f.write_text(
            "def t():\n    t_rxd = eth_absolute_to_rxd_relative_blocks(x)\n    t_btc = bt.Timelock(t_rxd.value // 2, B)\n"
        )
        assert _inverted_relations(f) == []
        assert _comparisons_made(f) == 0, "a derived file must report that nothing was evaluated"

    def test_a_file_the_scan_cannot_read_is_NOT_called_clean(self, tmp_path) -> None:
        """The blindness check's own failing case, which no real suite provides.

        Planting `if True: return` into it left all 14 tests green, because every file in the tree
        satisfies it for a good reason. This supplies the bad reason."""
        f = tmp_path / "opaque.py"
        f.write_text("def t():\n    t_rxd = compute_it_somehow()\n    t_btc = compute_it_too()\n")
        assert _comparisons_made(f) == 0
        reason = _blindness_reason(f)
        assert reason is not None and "evaluated NOTHING" in reason

    def test_a_file_the_scan_CAN_read_is_accepted(self, tmp_path) -> None:
        """The honest partner, so the check above cannot be satisfied by refusing everything."""
        f = tmp_path / "readable.py"
        f.write_text("def t():\n    t_rxd = bt.Timelock(100, B)\n    t_btc = bt.Timelock(60, B)\n")
        assert _comparisons_made(f) > 0
        assert _blindness_reason(f) is None

    @pytest.mark.parametrize("derivation", _DERIVED_FROM_PRODUCTION)
    def test_a_file_that_only_MENTIONS_a_derivation_is_not_called_derived(self, tmp_path, derivation) -> None:
        """The fail-open case of the old substring test: a comment naming the sizer is where a file
        says it SHOULD derive its timelocks, and the substring test accepted it as having done so."""
        f = tmp_path / "mentions.py"
        f.write_text(
            f"# TODO: take these from {derivation}\n"
            "def t():\n    t_rxd = compute_it_somehow()\n    t_btc = compute_it_too()\n"
        )
        assert _comparisons_made(f) == 0
        reason = _blindness_reason(f)
        assert reason is not None and "evaluated NOTHING" in reason

    @pytest.mark.parametrize(
        "body",
        [
            "def t():\n    t_rxd = eth_absolute_to_rxd_relative_blocks(eth_timeout_unix_s=x)\n"
            "    t_btc = bt.Timelock(t_rxd.value // 2, B)\n",
            "def t():\n    t_rxd = bt.Timelock(n, B)\n"
            "    t_btc = bt.Timelock(shared.derive_counter_timelock(t_rxd_blocks=n), B)\n",
        ],
        ids=["eth-sizer", "btc-derivation-as-attribute"],
    )
    def test_a_file_that_CALLS_a_derivation_is_accepted(self, tmp_path, body) -> None:
        """The honest partner, for each counter-chain clock and for both call shapes (bare name
        and attribute), so the check above cannot be satisfied by refusing every derived file."""
        f = tmp_path / "derived.py"
        f.write_text(body)
        assert _comparisons_made(f) == 0
        assert _blindness_reason(f) is None
