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


def _inverted_relations(path: Path) -> list[tuple[int, str]]:
    """Bindings that give `t_btc` a value provably >= `t_rxd` — the pre-#482 ordering.

    Two detectable forms, both observed in this repo:
      * two int literals, e.g. `t_rxd = Timelock(60)` / `t_btc = Timelock(100)`
      * an OFFSET off a shared base, e.g. `t_btc = Timelock(t_rxd_blocks + 40)` — inverted for
        EVERY value of the base, which a literal comparison alone would never have caught.
    """
    tree = ast.parse(path.read_text(errors="ignore"))
    bad: set[tuple[int, str]] = set()
    literals: dict[str, tuple[int, int]] = {}
    for name, value, lineno in _timelock_sites(tree):
        blocks = _timelock_blocks(value)
        if blocks is not None:
            literals[name] = (blocks, lineno)
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
    if "t_btc" in literals and "t_rxd" in literals:
        (btc, btc_ln), (rxd, _) = literals["t_btc"], literals["t_rxd"]
        if rxd <= btc:
            bad.add((btc_ln, f"t_rxd={rxd} <= t_btc={btc}"))
    return sorted(bad)


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
#: NOT mechanical to fix, which is why they are recorded rather than patched here. At least one
#: (`TestMakerStallAssetOnlyRefundIsTakerLoss` in test_xchain_swap_regtest_e2e.py) uses the
#: inverted ordering DELIBERATELY, to demonstrate that the asset-only refund is not a taker
#: defense. #482 changed the geometry that scenario lives in, so it needs re-deriving rather than
#: flipping — the spec/threat-model trap this repo has hit before.
_KNOWN_BROKEN = {
    "test_xchain_eth_swap_regtest_e2e.py": "t_btc = t_rxd + 40; t_btc is decorative on ETH (HZ-4) so likely a mechanical fix",
    "test_xchain_erc20_usdc_lifecycle_e2e.py": "same shape, passed as a constructor keyword rather than a local",
    "test_xchain_swap_regtest_e2e.py": "BTC<->RXD, where t_btc is REAL; includes an adversarial test that needs re-deriving post-#482",
    "test_xchain_eth_glyph_real_rxindexer_e2e.py": "fixed on the branch for #630; entry goes when that merges",
}


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
