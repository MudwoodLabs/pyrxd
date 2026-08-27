"""The reorg gate's ANCHOR — ``asset_locked_at_height`` — as the mainnet runners supply it.

The gate itself is well covered. What was not covered is the number handed to it, and every runner
had it wrong in a different way:

* the single-process runners snapshotted the RXD tip BEFORE blocking on the covenant funding, so
  the anchor was low by however long funding took;
* the two-host harnesses declared ``--asset-locked-at-height`` with ``default=0`` and validated it
  nowhere, so the two-party adversarial run — the project's stated hard gate before real value —
  read SQUEEZED on its first assessment every time.

Both errors are invisible to the gate's own tests, because the gate is a pure function and its
tests pass it an honest anchor by construction.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(f"_anchor_{name}", _SCRIPTS / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(_SCRIPTS))


@pytest.fixture(scope="module")
def shared():
    return _load("_dust_swap_shared")


@dataclass
class _FakeUtxo:
    """What a chain client hands back. ``height`` is a TRUE BLOCK HEIGHT — the contract every
    producer now honours, including the ssh-tr mainnet shim, which used to overwrite it with a
    confirmation count."""

    tx_hash: str
    tx_pos: int
    value: int
    height: int


class _FakeClient:
    def __init__(self, utxos):
        self._utxos = utxos
        self.registered: list[bytes] = []

    def register_spk(self, spk: bytes) -> None:
        self.registered.append(bytes(spk))

    async def get_utxos(self, _script_hash: bytes):
        return list(self._utxos)


# ---------------------------------------------------------------------------
# FIX 2 — the anchor is the covenant's FUND HEIGHT, read after the lock
# ---------------------------------------------------------------------------


class TestTheAnchorIsAHeightAndNotADepth:
    """The unit conversion, in the one place it lives.

    ``UtxoRecord.height`` spent a long time carrying a CONFIRMATION COUNT on the mainnet shim while
    being named for a height, and a fix that reads it naively swaps one unit bug for another. The
    conversion is therefore named and tested rather than inlined at three call sites.
    """

    def test_a_confirmed_height_passes_through_unchanged(self, shared) -> None:
        assert shared.covenant_fund_height(915_412) == 915_412

    def test_height_zero_is_UNCONFIRMED_and_fails_closed(self, shared) -> None:
        """0 means unconfirmed under both the old and the new convention — the one thing the shim
        change did not touch. Inventing an anchor here surfaces as the coordinator's F-013
        'lying node' refusal much further downstream, where it is far harder to read."""
        with pytest.raises(RuntimeError, match="unconfirmed"):
            shared.covenant_fund_height(0)

    def test_a_negative_height_fails_closed(self, shared) -> None:
        with pytest.raises(RuntimeError, match="unconfirmed"):
            shared.covenant_fund_height(-3)

    def test_a_non_int_fails_closed_rather_than_coercing(self, shared) -> None:
        with pytest.raises(RuntimeError, match="int block height"):
            shared.covenant_fund_height("915412")

    def test_a_bool_is_not_a_height(self, shared) -> None:
        """`True` is an int in Python and would sail through as height 1 — the genesis block."""
        with pytest.raises(RuntimeError, match="int block height"):
            shared.covenant_fund_height(True)


class TestScanningForTheAnchor:
    """The NFT and FT variants lock by SPENDING into the covenant and never call
    ``wait_for_covenant_funding``, so they need their own read of the same output."""

    def test_it_returns_the_funding_outputs_height(self, shared) -> None:
        client = _FakeClient([_FakeUtxo("aa" * 32, 0, 100_000, 915_400)])
        got = asyncio.run(shared.scan_covenant_fund_height(client, covenant_spk=b"\x51" * 25, expected_photons=100_000))
        assert got == 915_400

    def test_it_registers_the_spk_before_scanning(self, shared) -> None:
        """A script-hash-keyed client resolves a hash back to its SPK only from a registry; an
        unregistered covenant SPK scans EMPTY and is misread as 'not funded'."""
        client = _FakeClient([_FakeUtxo("aa" * 32, 0, 100_000, 915_400)])
        asyncio.run(shared.scan_covenant_fund_height(client, covenant_spk=b"\x51" * 25, expected_photons=100_000))
        assert client.registered == [b"\x51" * 25]

    def test_a_wrong_value_output_is_NOT_the_covenant(self, shared) -> None:
        """The covenant pins its amount; a mis-funded output is not the one this swap locked."""
        client = _FakeClient([_FakeUtxo("aa" * 32, 0, 99_999, 915_400)])
        with pytest.raises(RuntimeError, match="no CONFIRMED covenant UTXO"):
            asyncio.run(shared.scan_covenant_fund_height(client, covenant_spk=b"\x51" * 25, expected_photons=100_000))

    def test_an_unconfirmed_output_is_not_an_anchor(self, shared) -> None:
        client = _FakeClient([_FakeUtxo("aa" * 32, 0, 100_000, 0)])
        with pytest.raises(RuntimeError, match="no CONFIRMED covenant UTXO"):
            asyncio.run(shared.scan_covenant_fund_height(client, covenant_spk=b"\x51" * 25, expected_photons=100_000))

    def test_a_LATER_decoy_payment_cannot_push_the_anchor_forward(self, shared) -> None:
        """Anyone can pay the covenant SPK — it is a pure function of public terms. A decoy of the
        same value mined LATER must not become the anchor: a higher anchor means a longer
        ``blocks_left``, which is the optimistic direction and buys the claim less burial than the
        gate believes it has. Take the earliest-mined, i.e. the LOWEST height.

        Under the old confs-in-height convention the same choice was ``max``. The flip is exactly
        the unit bug the named conversion exists to make visible, so it is pinned here.
        """
        client = _FakeClient(
            [
                _FakeUtxo("bb" * 32, 1, 100_000, 915_480),  # decoy, mined later
                _FakeUtxo("aa" * 32, 0, 100_000, 915_400),  # the maker's real lock
            ]
        )
        got = asyncio.run(shared.scan_covenant_fund_height(client, covenant_spk=b"\x51" * 25, expected_photons=100_000))
        assert got == 915_400, "the anchor must be the EARLIEST matching output, not the latest"


def _assignment_source(script: str, func: str, target: str) -> str:
    """The right-hand side of ``target = ...`` inside ``func``, as source text.

    Parsed, not grepped: a comment mentioning ``rxd_blockcount`` beside the assignment would
    satisfy a grep and prove nothing about what actually runs.
    """
    src = (_SCRIPTS / f"{script}.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == target for t in node.targets):
            return ast.unparse(node.value)
    raise AssertionError(f"no assignment to {target} found in {script}.{func}")


class TestTheAnchorIsNotTheTipTakenBeforeTheWait:
    """The defect, pinned structurally, because the alternative is a mainnet run.

    Both runners did::

        rxd_locked_at = rxd_blockcount(rxd_client)   # tip, read BEFORE the wait
        await wait_for_covenant_funding(...)         # blocks on the operator, for hours

    and defended it with "a conservative (slightly-low) value is safe — it can only make the
    reorg-gate squeeze MORE cautious, never less". That is true of the GATE and false of the
    RUNNER, which is what ``TestALowAnchorIsNotTheSafeDirection`` below demonstrates against the
    real library function.
    """

    @pytest.mark.parametrize(
        "script,func",
        [("dust_swap_run", "run_dust_swap"), ("eth_swap_run", "run_sepolia_dust")],
    )
    def test_the_anchor_is_not_a_bare_tip_read(self, script: str, func: str) -> None:
        rhs = _assignment_source(script, func, "rxd_locked_at")
        assert "rxd_blockcount" not in rhs, (
            f"{script}.{func} anchors the reorg gate on `{rhs}` — a TIP read. The tip is not the "
            "height the covenant was mined at, and the gap is the funding latency."
        )

    @pytest.mark.parametrize(
        "script,func",
        [("dust_swap_run", "run_dust_swap"), ("eth_swap_run", "run_sepolia_dust")],
    )
    def test_the_anchor_comes_from_the_named_conversion(self, script: str, func: str) -> None:
        rhs = _assignment_source(script, func, "rxd_locked_at")
        assert "covenant_fund_height" in rhs, (
            f"{script}.{func} derives the anchor as `{rhs}`, bypassing the one named place the "
            "height/depth unit assumption is written down"
        )

    @pytest.mark.parametrize(
        "script,func",
        [("dust_swap_run", "run_dust_swap"), ("eth_swap_run", "run_sepolia_dust")],
    )
    def test_the_anchor_is_read_AFTER_the_asset_is_locked(self, script: str, func: str) -> None:
        """Order is the whole defect: the same expression above the wait is still wrong."""
        src = (_SCRIPTS / f"{script}.py").read_text()
        anchor_at = src.index("rxd_locked_at =")
        locked_at = min(
            (src.index(m) for m in ("wait_for_covenant_funding(", "lock_singleton_into_covenant(") if m in src),
            default=-1,
        )
        assert locked_at != -1
        assert anchor_at > locked_at, (
            f"{script} assigns rxd_locked_at BEFORE the asset lock; the tip it captures predates "
            "the covenant by the whole funding latency"
        )


class TestALowAnchorIsNotTheSafeDirection:
    """The claim the in-code comment made, checked against the real gate.

    "A conservative (slightly-low) value ... can only make the reorg-gate squeeze MORE cautious,
    never less." The gate does squeeze harder. The RUNNER's handler for SQUEEZED is
    ``taker_claim_asset_from_vulnerable``, which is winner-take-all by design and contains ZERO
    calls to ``assess_claim_finality`` — so a more cautious gate produces a LESS gated broadcast,
    unattended under ``--yes``.
    """

    #: The swap as it stands AT CLAIM TIME, which is the only moment the anchor is consumed.
    #: `now` is deliberately LATE in the t_rxd window, because that is where a taker actually is:
    #: it has waited for the maker's reveal and then for the counter leg to finalise before it may
    #: claim at all. An earlier `now` gives `blocks_left` so much slack that NO amount of anchor
    #: error changes the verdict — a fixture that is internally consistent and models a situation
    #: the swap never reaches.
    _FUND_HEIGHT = 915_400
    _T_RXD_BLOCKS = 240
    _BURIAL_BLOCKS = 6
    _NOW = 915_632  # refund opens at 915_640; 8 blocks of room, 6 of them needed

    @classmethod
    def _assess(cls, anchor: int, now: int | None = None):
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
        from pyrxd.gravity.swap_coordinator import (
            CounterClaimFinality,
            CounterClaimState,
            MarginPolicy,
            assess_claim_finality,
        )

        return assess_claim_finality(
            counter_claim_finality=CounterClaimFinality(state=CounterClaimState.FINAL, required_depth=None),
            now_rxd_height=cls._NOW if now is None else now,
            asset_locked_at_height=anchor,
            t_rxd=Timelock(cls._T_RXD_BLOCKS, TimeUnit.BLOCKS),
            policy=MarginPolicy(
                margin=Timelock(36, TimeUnit.BLOCKS),
                block_interval_s=600.0,
                is_measured=False,
                rxd_block_interval_s=300.0,
                rxd_claim_burial=Timelock(cls._BURIAL_BLOCKS, TimeUnit.BLOCKS),
                accept_flat_burial=True,
            ),
        )

    def test_the_fixture_is_a_situation_the_swap_actually_reaches(self) -> None:
        """Checks the fixture against the domain before anything is concluded from it: the taker
        must be INSIDE the t_rxd window with just enough room to bury its claim."""
        refund_opens = self._FUND_HEIGHT + self._T_RXD_BLOCKS
        blocks_left = refund_opens - self._NOW
        assert 0 < blocks_left < self._T_RXD_BLOCKS, "now must be inside the t_rxd window"
        assert blocks_left >= self._BURIAL_BLOCKS, "the honest case must have room to bury"
        assert blocks_left - self._BURIAL_BLOCKS < 10, (
            "the honest case must be near the boundary, or anchor error cannot matter and this "
            "whole class proves nothing"
        )

    def test_the_honest_anchor_is_SAFE_and_the_stale_one_is_SQUEEZED(self) -> None:
        from pyrxd.gravity.swap_coordinator import ClaimFinality

        assert self._assess(self._FUND_HEIGHT) is ClaimFinality.SAFE
        assert self._assess(self._FUND_HEIGHT - 3) is ClaimFinality.SQUEEZED, (
            "three RXD blocks of funding latency must flip the verdict; if it does not, this "
            "fixture cannot demonstrate the defect"
        )

    def test_the_flip_happens_within_the_realistic_latency_band(self) -> None:
        """Bounds the SENSITIVITY rather than asserting a direction only a huge error can show.
        The runner's error is unbounded — it is the whole funding wait — so the band that matters
        is the small one."""
        from pyrxd.gravity.swap_coordinator import ClaimFinality

        flips = [lag for lag in range(0, 60) if self._assess(self._FUND_HEIGHT - lag) is ClaimFinality.SQUEEZED]
        assert flips, "no amount of anchor staleness changed the verdict — the fixture is inert"
        assert min(flips) <= 5, (
            f"the verdict only flips at {min(flips)} blocks of staleness; the brief measured 1-5 "
            "blocks of funding latency flipping it in the realistic band"
        )

    def test_a_TOO_HIGH_anchor_is_the_other_failure_and_reads_optimistically_SAFE(self) -> None:
        """The direction the fix must not overshoot into. A high anchor lengthens `blocks_left`,
        so a claim that should have been SQUEEZED reads SAFE and is broadcast with less burial
        than the gate believes it bought."""
        from pyrxd.gravity.swap_coordinator import ClaimFinality

        genuinely_squeezed_now = self._FUND_HEIGHT + self._T_RXD_BLOCKS - 2
        assert self._assess(self._FUND_HEIGHT, now=genuinely_squeezed_now) is ClaimFinality.SQUEEZED
        assert self._assess(self._FUND_HEIGHT + 20, now=genuinely_squeezed_now) is ClaimFinality.SAFE, (
            "an inflated anchor must read SAFE — it is why the anchor is derived exactly rather "
            "than rounded in a 'conservative' direction"
        )


# ---------------------------------------------------------------------------
# FIX 3 — the two-host anchor: reachable honest value, refused meaningless one
# ---------------------------------------------------------------------------


class _FakeChainIo:
    def __init__(self, height: int, value: int = 100_000):
        self._height, self._value = height, value
        self.asked_for: list[tuple[bytes, int | None]] = []

    async def find_covenant_utxo(self, spk: bytes, *, expected_value=None, pin_outpoint=None):
        self.asked_for.append((bytes(spk), expected_value))
        if expected_value is not None and int(expected_value) != self._value:
            raise RuntimeError("no covenant UTXO matches the expected carrier value; fail-closed")
        return (f"{'aa' * 32}:0", self._value, self._height)


class _FakeLeg:
    def __init__(self, chain_io):
        self.chain_io = chain_io


class TestTheTwoHostAnchorIsReadFromTheChain:
    """``--asset-locked-at-height`` was ``default=0``, passed straight through, validated nowhere —
    while ``--taker-min-rxd-confs >= 1`` IS validated on an adjacent line. At anchor 0 the gate
    computes ``blocks_left = 0 + t_rxd - now``, hugely negative at any realistic tip, so the run
    went SQUEEZED -> ASSET_VULNERABLE -> winner-take-all on the FIRST attempt and never exercised
    the finality wait it exists to prove.
    """

    def test_omitting_the_flag_reads_the_covenants_true_fund_height(self, shared) -> None:
        leg = _FakeLeg(_FakeChainIo(915_400))
        got = asyncio.run(
            shared.resolve_asset_locked_at_height(
                leg, covenant_spk=b"\x51" * 25, expected_photons=100_000, explicit=0, now_rxd_height=915_460
            )
        )
        assert got == 915_400

    def test_the_read_is_PINNED_to_the_agreed_value(self, shared) -> None:
        """The SPK is a pure function of public terms, so anyone can pay it. A covenant funded at
        the wrong amount must be refused, not anchored on."""
        leg = _FakeLeg(_FakeChainIo(915_400, value=100_000))
        with pytest.raises(RuntimeError):
            asyncio.run(
                shared.resolve_asset_locked_at_height(
                    leg, covenant_spk=b"\x51" * 25, expected_photons=999_999, now_rxd_height=915_460, explicit=0
                )
            )
        assert leg.chain_io.asked_for[-1][1] == 999_999, "the value must be bound in the read itself"

    def test_an_explicit_pin_is_honoured(self, shared) -> None:
        """Paired honest path: the override exists for rehearsals and must keep working."""
        leg = _FakeLeg(_FakeChainIo(915_400))
        got = asyncio.run(
            shared.resolve_asset_locked_at_height(
                leg, covenant_spk=b"\x51" * 25, expected_photons=100_000, explicit=915_390, now_rxd_height=915_460
            )
        )
        assert got == 915_390

    def test_a_NEGATIVE_pin_is_refused(self, shared) -> None:
        leg = _FakeLeg(_FakeChainIo(915_400))
        with pytest.raises(SystemExit, match="negative"):
            asyncio.run(
                shared.resolve_asset_locked_at_height(
                    leg, covenant_spk=b"\x51" * 25, expected_photons=100_000, explicit=-1, now_rxd_height=915_460
                )
            )

    def test_a_pin_ABOVE_the_tip_is_refused_here_not_deep_in_the_gate(self, shared) -> None:
        """The coordinator's F-013 check fails closed on ``now < locked_at`` with a message about
        lagging or lying nodes. Catching it here says which ARGUMENT is wrong, before a claim
        decision depends on it."""
        leg = _FakeLeg(_FakeChainIo(915_400))
        with pytest.raises(SystemExit, match="above the current RXD tip"):
            asyncio.run(
                shared.resolve_asset_locked_at_height(
                    leg, covenant_spk=b"\x51" * 25, expected_photons=100_000, explicit=915_999, now_rxd_height=915_460
                )
            )

    def test_an_unconfirmed_covenant_yields_no_anchor(self, shared) -> None:
        leg = _FakeLeg(_FakeChainIo(0))
        with pytest.raises(RuntimeError, match="unconfirmed"):
            asyncio.run(
                shared.resolve_asset_locked_at_height(
                    leg, covenant_spk=b"\x51" * 25, expected_photons=100_000, explicit=0, now_rxd_height=915_460
                )
            )


class TestTheTwoHostClaimUsesTheResolvedAnchor:
    """Reachability. The resolver is only worth anything if the claim call actually reads it —
    the previous version's whole defect was a value that was defined, plumbed, and never checked.
    """

    @pytest.mark.parametrize("script", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_the_claim_call_does_not_pass_the_raw_flag(self, script: str) -> None:
        src = (_SCRIPTS / f"{script}.py").read_text()
        tree = ast.parse(src)
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "taker_scrape_and_claim_asset"
        ]
        assert calls, f"{script} no longer calls taker_scrape_and_claim_asset"
        for call in calls:
            kw = {k.arg: ast.unparse(k.value) for k in call.keywords}
            assert "asset_locked_at_height" in kw
            assert kw["asset_locked_at_height"] != "args.asset_locked_at_height", (
                f"{script} passes the raw, unvalidated flag ({kw['asset_locked_at_height']}) — at "
                "its default of 0 the gate reads SQUEEZED at any realistic tip"
            )

    @pytest.mark.parametrize("script", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_the_value_the_claim_reads_is_RESOLVED_not_aliased(self, script: str) -> None:
        """Follows the assignment rather than the call site. Checking only that the keyword is not
        the literal `args.asset_locked_at_height` is defeated by one local alias — which is exactly
        the shape a well-meaning revert takes, so it is the shape the test has to see."""
        rhs = _assignment_source(script, "taker_phase_claim", "asset_locked_at")
        assert "resolve_asset_locked_at_height" in rhs, (
            f"{script}.taker_phase_claim binds the anchor as `{rhs}` — the raw flag under another "
            "name. At its default of 0 the gate reads SQUEEZED at any realistic tip."
        )

    @pytest.mark.parametrize("script", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_the_resolver_has_a_production_caller(self, script: str) -> None:
        src = (_SCRIPTS / f"{script}.py").read_text()
        tree = ast.parse(src)
        called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "resolve_asset_locked_at_height" in called, f"{script} imports the resolver but never calls it"

    @pytest.mark.parametrize("script", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_a_negative_anchor_is_refused_at_parse_time(self, script: str) -> None:
        """Beside the ``--taker-min-rxd-confs >= 1`` check that was already there — the adjacent
        line that made this flag's total absence of validation conspicuous."""
        mod = _load(script)
        src = (_SCRIPTS / f"{script}.py").read_text()
        assert "args.asset_locked_at_height < 0" in src, (
            f"{script} still accepts a negative Radiant height without complaint"
        )
        assert mod is not None


# ---------------------------------------------------------------------------
# FIX 4 — the two-host harness can be driven in the real-value parameterisation
# ---------------------------------------------------------------------------


def _two_host_margin_args(**kw) -> argparse.Namespace:
    base = dict(
        eth_finalization_window_s=768,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=0,
    )
    base.update(kw)
    return argparse.Namespace(**base)


class TestTheTwoHostHarnessCanCarryAStallBudget:
    """``eth_finality_stall_tolerance_s`` is what ``CrossClockMargin``'s own docstring calls "the
    single most important safety addition": the taker waits for ETH FINALITY before claiming RXD,
    so the RXD refund must not open until it has had a stall-tolerant window. The May-2023 mainnet
    incident ran about an hour.

    ``eth_swap_run.py`` has the flag and REFUSES below 3600 for a real token leg. The two-host
    harness — the one the two-party adversarial run is driven from — built its margin WITHOUT the
    field, so it silently defaulted to 0 and the run could not be rehearsed in the parameterisation
    the project calls mandatory.
    """

    def test_the_stall_budget_reaches_the_margin(self) -> None:
        mod = _load("eth_swap_two_host")
        with_stall = mod._cross_clock_margin(_two_host_margin_args(eth_finality_stall_tolerance_s=3600))
        assert with_stall.eth_finality_stall_tolerance_s == 3600
        without = mod._cross_clock_margin(_two_host_margin_args(eth_finality_stall_tolerance_s=0))
        assert with_stall.total_s() - without.total_s() == 3600, (
            "the stall budget is not reaching the margin total, so the RXD refund is sized against "
            "happy-path finality — the exact bug a stall triggers"
        )

    def test_the_flag_exists_and_defaults_to_the_regtest_value(self) -> None:
        """0 stays the default: this harness is regtest/anvil by design and a mandatory 3600 there
        would be a guard refusing honest work. Reachability, not coercion, is what was missing."""
        mod = _load("eth_swap_two_host")
        sys.argv = ["eth_swap_two_host.py", "--self-check"]
        args = mod._args()
        assert hasattr(args, "eth_finality_stall_tolerance_s")
        assert args.eth_finality_stall_tolerance_s == 0

    def test_the_flag_is_accepted_at_the_real_value_threshold(self) -> None:
        """The point of the fix: the number eth_swap_run.py demands must be expressible here."""
        mod = _load("eth_swap_two_host")
        sys.argv = ["eth_swap_two_host.py", "--self-check", "--eth-finality-stall-tolerance-s", "3600"]
        args = mod._args()
        assert args.eth_finality_stall_tolerance_s == 3600
        assert mod._cross_clock_margin(args).eth_finality_stall_tolerance_s == 3600
