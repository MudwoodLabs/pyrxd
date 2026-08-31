"""A cancelled claim must not destroy a preimage that never left the process (#480).

`maker_claims_btc` used to decide by exception TYPE: `PreRevealAbort` meant keep `p`, anything
else meant zeroize. `asyncio.CancelledError` is a `BaseException`, so the legs' `except Exception`
wrappers correctly do not catch it — and it landed in the zeroize branch. Cancelled during the
PRE-BROADCAST reads, nothing was sent, `p` was still secret, and it was destroyed anyway: #479
arriving through the cancel channel instead of the error channel.

The fix records the crossing rather than inferring it, so these tests assert on the RECORD.
"""

from __future__ import annotations

import asyncio

from pyrxd.security.reveal import (
    RevealState,
    mark_reveal_crossed,
    reveal_boundary,
    watching_for_reveal,
)


class TestTheThreeStates:
    def test_an_unreported_boundary_reads_as_MAY_BE_PUBLIC(self) -> None:
        """The safe default. A leg that does not participate — a fake, or one not yet wired — must
        be assumed to have revealed, which is exactly today's behaviour and not a regression."""
        with reveal_boundary() as b:
            assert b.state is RevealState.UNWATCHED
            assert b.may_be_public is True

    def test_a_watched_but_uncrossed_boundary_keeps_the_secret(self) -> None:
        """The whole point: an explicit "I got nowhere" is the ONLY thing that keeps `p`."""
        with reveal_boundary() as b:
            watching_for_reveal()
            assert b.state is RevealState.NOT_CROSSED
            assert b.may_be_public is False

    def test_crossing_is_one_way(self) -> None:
        """A later `watch()` must not un-cross it — that would resurrect a public secret."""
        with reveal_boundary() as b:
            watching_for_reveal()
            mark_reveal_crossed()
            watching_for_reveal()
            assert b.state is RevealState.CROSSED
            assert b.may_be_public is True

    def test_the_helpers_are_a_no_op_without_a_boundary(self) -> None:
        """A leg driven directly, in a test or by an embedder, must not blow up."""
        watching_for_reveal()
        mark_reveal_crossed()


class TestCancellation:
    def test_cancelling_BEFORE_the_send_leaves_the_secret_intact(self) -> None:
        """The bug. A boolean cannot express this: the leg reported it got nowhere, so a
        CancelledError arriving here must NOT be read as "may be public"."""

        async def run() -> bool:
            with reveal_boundary() as b:
                try:
                    watching_for_reveal()
                    raise asyncio.CancelledError()
                except BaseException:
                    return b.may_be_public
            raise AssertionError("unreachable")

        assert asyncio.run(run()) is False

    def test_cancelling_AFTER_the_send_discards_the_secret(self) -> None:
        """The honest-path half, in the other direction. Once `p` may be public, a cancellation
        must still zeroize — a fix that kept the secret on every cancel would be worse."""

        async def run() -> bool:
            with reveal_boundary() as b:
                try:
                    watching_for_reveal()
                    mark_reveal_crossed()
                    raise asyncio.CancelledError()
                except BaseException:
                    return b.may_be_public

            raise AssertionError("unreachable")

        assert asyncio.run(run()) is True


class TestIsolation:
    def test_concurrent_claims_do_not_see_each_others_boundary(self) -> None:
        """Task-local. Two swaps claiming at once must not have one's crossing zeroize the
        other's still-secret preimage."""

        async def crosser() -> bool:
            with reveal_boundary() as b:
                watching_for_reveal()
                await asyncio.sleep(0)
                mark_reveal_crossed()
                return b.may_be_public

        async def bystander() -> bool:
            with reveal_boundary() as b:
                watching_for_reveal()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                return b.may_be_public

        async def run():
            return await asyncio.gather(crosser(), bystander())

        crossed, quiet = asyncio.run(run())
        assert crossed is True
        assert quiet is False, "one task's reveal leaked into another's boundary"


class TestTheRealLegReportsIt:
    """Reachability: the production leg must set these, not just the helpers existing."""

    def test_the_eth_leg_marks_the_boundary_before_sending(self) -> None:
        import inspect

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        src = inspect.getsource(EthHtlcContractLeg.claim)
        assert "watching_for_reveal()" in src, "the leg never declares it reports the boundary"
        assert "mark_reveal_crossed()" in src, "the leg never marks the crossing"
        # Compare against the CALL, not the bare name: the docstring mentions `_sign_and_send`
        # long before the call site, and matching that made this assert pass for the wrong reason.
        call = src.index("await self._sign_and_send(")
        assert src.index("mark_reveal_crossed()") < call, (
            "the crossing must be marked BEFORE the send: on the public path the preflight "
            "eth_call inside it already carries the preimage to a provider"
        )

    def test_the_token_leg_declares_it_too(self) -> None:
        """Its extra pre-reveal reads run BEFORE super().claim, so without its own declaration a
        cancellation there would read as UNWATCHED and zeroize a still-secret preimage."""
        import inspect

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

        assert "watching_for_reveal()" in inspect.getsource(Erc20HtlcLeg.claim)

    def test_both_claim_docstrings_survived(self) -> None:
        """Guard against the edit that introduced this: inserting the call above the docstring
        turns it into a no-op string expression and silently deletes the documentation."""
        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        assert EthHtlcContractLeg.claim.__doc__
        assert Erc20HtlcLeg.claim.__doc__
