"""#479 — a transient RPC failure must not destroy the preimage.

`maker_claims_btc` zeroizes `p` once a claim has been attempted, which is right: past the submit
boundary `p` may be public and holding a copy buys nothing. It used to zeroize in a `finally`, on
EVERY exit — so a chain-id assertion or a fee read failing, with nothing broadcast, destroyed the
only copy of a still-secret preimage and stranded a swap a retry would have completed.

The legs mark the boundary with `PreRevealAbort`. It is a promise about WHERE a failure happened,
not why: nothing was sent, no `eth_call` carried the calldata, `p` is still secret.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.security.errors import NetworkError, PreRevealAbort, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial


class TestTheBoundaryIsMarkedByTheLegs:
    def test_pre_reveal_abort_is_not_a_network_error_subclass(self) -> None:
        """It must be catchable distinctly. If it were a NetworkError subclass, a caller with
        `except NetworkError` would swallow it and lose the distinction entirely."""
        assert issubclass(PreRevealAbort, Exception)
        assert not issubclass(PreRevealAbort, NetworkError)
        assert not issubclass(NetworkError, PreRevealAbort)

    def test_the_native_claim_reports_a_transport_failure_as_pre_broadcast(self) -> None:
        """`assert_chain` failing means nothing was sent."""
        import json
        import pathlib

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
        from pyrxd.eth_wallet.locator import EthHtlcLocator

        class _Rpc:
            async def latest_block_timestamp(self):
                # The deadline guard reads the LATEST head any endpoint admits to; the staleness abort
                # reads the QUORUM-th. One source has one answer, so all three coincide here. `claim`
                # used to reach through `w3.eth.get_block` directly, which a multi-source RPC cannot serve.
                return int((await self.w3.eth.get_block("latest"))["timestamp"])

            async def latest_block_timestamp_quorum(self):
                return await self.latest_block_timestamp()

            async def latest_block_timestamp_min(self):
                return await self.latest_block_timestamp()

            async def assert_chain(self):
                raise NetworkError("connection refused")

        art = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
        leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=art)
        loc = EthHtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=10**15,
        )
        with pytest.raises(PreRevealAbort, match="still secret"):
            asyncio.run(leg.claim(loc, b"\x11" * 32))

    def test_a_frozen_address_is_NOT_a_pre_reveal_abort(self) -> None:
        """A real freeze means the swap cannot complete, so discarding `p` is correct. Only
        'we could not tell' must preserve it — the two outcomes need different handling."""
        assert not issubclass(ValidationError, PreRevealAbort)


def _both_locked(exc: BaseException):
    """A real `SwapCoordinator` at BOTH_LOCKED whose counter leg fails the way we want.

    Built through the coordinator's own transitions rather than by hand-constructing a record, so
    the state it claims to be in is the state it actually reached.
    """
    import sys

    sys.path.insert(0, "tests")
    from test_swap_coordinator import FakeBtcLeg, FakeRadiantLeg, _coordinator, _terms
    from test_swap_coordinator import generate_secret as _gen

    p_secret, h = _gen()
    terms = _terms(hashlock=h)
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(), radiant_leg=rxd)

    async def _reach():
        await coord.taker_funds_btc(terms)
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))

    asyncio.run(_reach())

    async def _failing_claim(*a, **k):
        raise exc

    coord.counter_leg.claim = _failing_claim
    return coord, p_secret


def _drive_real_coordinator(exc: BaseException) -> bool:
    """Call the REAL `maker_claims_btc`; return True if the preimage survived."""
    from pyrxd.gravity.swap_state import SwapState

    coord, preimage = _both_locked(exc)
    assert coord.record.state is SwapState.BOTH_LOCKED, "setup did not reach the state under test"
    with pytest.raises(type(exc)):
        asyncio.run(coord.maker_claims_btc(preimage))
    try:
        preimage.unsafe_raw_bytes()
        return True
    except Exception:
        return False


class TestTheCoordinatorKeepsTheSecretWhenNothingWasSent:
    """Drives the REAL `SwapCoordinator.maker_claims_btc`.

    The version this replaces defined a local `_drive()` closure that re-implemented the
    coordinator's try/except/else and asserted on THAT — so reverting the coordinator to its old
    `finally: preimage.zeroize()` left every test passing. A regression test for a coordinator fix
    that never executes the coordinator is the "test of the test" pattern, in the one file whose
    entire job is to pin that fix.
    """

    def test_a_pre_broadcast_abort_preserves_the_preimage(self) -> None:
        assert _drive_real_coordinator(PreRevealAbort("rpc blip, nothing sent")) is True

    @pytest.mark.parametrize(
        "exc",
        [NetworkError("failed while waiting for the receipt"), ValidationError("something else")],
        ids=["post-broadcast-transport", "other-failure"],
    )
    def test_anything_else_still_zeroizes(self, exc: BaseException) -> None:
        """The safety property must not regress: once a claim was attempted, the secret goes."""
        assert _drive_real_coordinator(exc) is False


class TestAnUnconfirmedClaimDoesNotAdvanceTheSwap:
    """The production entry point for the claim-confirmation fix.

    The leg-level tests prove `claim` refuses to report an unconfirmed transaction as success.
    This proves the thing that actually matters: the REAL coordinator does not then record the
    swap as claimed. A reverted claim is mined with `p` in its calldata, so the secret is public
    and the counterparty can take the other leg — recording SECRET_REVEALED on top of that would
    have the maker believe it collected, stop pursuing, and let the taker refund unopposed.
    """

    def test_the_FSM_does_not_advance_when_the_claim_could_not_be_confirmed(self) -> None:
        from pyrxd.gravity.swap_state import SwapState
        from pyrxd.security.errors import ClaimNotConfirmed

        coord, preimage = _both_locked(ClaimNotConfirmed("reverted", tx_hash="0x" + "ab" * 32))
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(coord.maker_claims_btc(preimage))
        assert coord.record.state is SwapState.BOTH_LOCKED, (
            "the swap advanced past BOTH_LOCKED on a claim that was never confirmed to have "
            "succeeded — the maker would believe it collected value it did not receive"
        )

    def test_an_unconfirmed_claim_still_ZEROIZES_because_p_is_public(self) -> None:
        """Not a PreRevealAbort. The transaction left the process, so the preimage must be
        assumed public and retention buys nothing — the operator recovers via the tx hash on the
        exception, not via a secret the counterparty can already read off the chain."""
        from pyrxd.security.errors import ClaimNotConfirmed

        assert _drive_real_coordinator(ClaimNotConfirmed("reverted", tx_hash="0x" + "cd" * 32)) is False


class TestNoPreRevealAbortCanEscapeFromPastTheSendBoundary:
    """The coordinator TRUSTS the leg's claim about where it failed — that is what the round-2 fix
    introduced. If a leg could raise `PreRevealAbort` after submitting, the caller would keep a
    preimage that is already public and, worse, treat a sent claim as unsent.

    The property is structural, so it is asserted structurally: every raise site must sit before
    the send. A reviewer cannot re-derive that by eye on each change; a test can.
    """

    @pytest.mark.parametrize(
        ("module", "method"),
        [
            ("pyrxd.eth_wallet.htlc_leg", "EthHtlcContractLeg.claim"),
            # A merge dropped this entry while the sibling scan below kept its allowlist paragraph
            # explaining that erc20_leg.py raises PreRevealAbort from four pre-reveal checks — so
            # for a while this file DOCUMENTED that the ERC-20 leg was in scope and no longer
            # ENFORCED it. Its send token (`super().claim(`) exists only in Erc20HtlcLeg.claim,
            # i.e. the detector below was written for this entry and had nothing to detect.
            ("pyrxd.eth_wallet.erc20_leg", "Erc20HtlcLeg.claim"),
        ],
    )
    def test_every_raise_precedes_the_submit(self, module: str, method: str) -> None:
        """Checked against the AST, not the text. The previous version grepped source LINES for
        `raise PreRevealAbort` / `_sign_and_send(` / `super().claim(`, so a COMMENT containing a
        send token above a real raise would move `min(sends)` up and mask a post-send raise —
        and erc20_leg.py's claim is exactly the kind of heavily-commented code where that
        happens. AST nodes cannot come from comments or docstrings."""
        import ast
        import importlib
        import inspect
        import textwrap

        cls_name, fn_name = method.split(".")
        fn = getattr(getattr(importlib.import_module(module), cls_name), fn_name)
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))

        raises = [
            n.lineno
            for n in ast.walk(tree)
            if isinstance(n, ast.Raise)
            and isinstance(n.exc, ast.Call)
            and isinstance(n.exc.func, ast.Name)
            and n.exc.func.id == "PreRevealAbort"
        ]

        def _is_send(call: ast.Call) -> bool:
            f = call.func
            if not isinstance(f, ast.Attribute):
                return False
            if f.attr == "_sign_and_send":  # the native leg's broadcast
                return True
            # `super().claim(...)` — the ERC-20 leg delegates its broadcast to the parent.
            return (
                f.attr == "claim"
                and isinstance(f.value, ast.Call)
                and isinstance(f.value.func, ast.Name)
                and f.value.func.id == "super"
            )

        sends = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_send(n)]
        if not raises:
            pytest.skip(f"{method} raises no PreRevealAbort directly")
        assert sends, f"{method}: no send found — the boundary this pins has moved"
        assert max(raises) < min(sends), (
            f"{method}: a PreRevealAbort is raised at or after the send (raise at line {max(raises)}, "
            f"first send at line {min(sends)} of the method), so the caller would be told "
            "nothing was broadcast when something may have been"
        )

    def test_the_marker_is_not_raised_anywhere_outside_the_legs(self) -> None:
        """If some other module started raising it, the boundary claim would stop being auditable
        from the two claim paths alone."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "src"
        # Relative PATHS, not basenames. `src/pyrxd/btc_wallet/htlc_leg.py` shares a filename with
        # the ETH leg, so a basename comparison let a raise added THERE pass unnoticed — verified by
        # planting one. The BTC leg has no submit boundary of this shape at all.
        raisers = {str(f.relative_to(root)) for f in root.rglob("*.py") if "raise PreRevealAbort(" in f.read_text()}
        assert raisers <= {
            "pyrxd/eth_wallet/htlc_leg.py",
            # The ERC-20 leg raises it from its own pre-reveal checks — balance, freeze status,
            # gate refusal — each strictly before anything is submitted, which is exactly the
            # boundary this marker denotes. It is a LEG, so it belongs in this set; the assertion
            # is that no module OUTSIDE the legs raises it, not that only one leg may.
            "pyrxd/eth_wallet/erc20_leg.py",
        }, f"unexpected raisers: {sorted(raisers)}"
