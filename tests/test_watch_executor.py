from __future__ import annotations


class TestWhatActuallyBoundsAutonomousMainnetValue:
    """The module docstring claimed TWO structural locks. Only one exists.

    It said `make_refund_broadcaster` "calls the existing fail-closed
    `require_audit_cleared`, so on a value-bearing network without an explicit
    opt-in there is simply no broadcaster" and that "no live broadcaster can
    exist". `require_audit_cleared` has had a body of `return None` since 0.9.0,
    when the audit gate was deliberately made advisory to match Radiant Core's own
    posture — so the `except ValidationError` branch is unreachable and the
    function returns whatever it was handed.

    That sentence was the stated justification for landing an autonomous mainnet
    BTC broadcaster before an external audit. These tests pin what is actually
    true, so the justification cannot silently drift again.

    NOT re-arming the gate: making `require_audit_cleared` block again would undo
    a deliberate product decision. The fix is that the prose describes the real
    control.
    """

    def test_the_audit_gate_does_not_gate(self) -> None:
        from pyrxd.btc_wallet.htlc_leg import require_audit_cleared

        assert require_audit_cleared("bc", audit_cleared=False) is None, "no raise: it is advisory"

    def test_mainnet_without_opt_in_still_returns_a_LIVE_broadcaster(self) -> None:
        """The measured refutation of the old docstring."""
        from pyrxd.gravity.watch.executor import make_refund_broadcaster

        sentinel = object()
        assert make_refund_broadcaster("bc", audit_cleared=False, broadcaster=sentinel) is sentinel

    def test_dormancy_comes_from_the_CALLER_injecting_none(self) -> None:
        """Which is a real control — just a different one from the one claimed."""
        from pyrxd.gravity.watch.executor import make_refund_broadcaster

        assert make_refund_broadcaster("bc", audit_cleared=False, broadcaster=None) is None

    @staticmethod
    def _live_broadcaster():
        class _B:
            async def broadcast(self, raw_tx: bytes) -> str:
                return "00" * 32

        return _B()

    def test_the_dust_ceiling_is_the_bound_that_IS_structural(self, tmp_path) -> None:
        """The lock that does hold, and — with the other one gone — the only one.
        Pinned here because the docstring now says so and a reader will rely on it."""
        import pytest as _pytest

        from pyrxd.gravity.watch.executor import MAINNET_DUST_CEILING_SATS, RefundExecutor
        from pyrxd.security.errors import ValidationError

        with _pytest.raises(ValidationError, match="dust ceiling"):
            RefundExecutor(
                network="bc",
                broadcaster=self._live_broadcaster(),
                blobs_dir=tmp_path,
                cap_sats=MAINNET_DUST_CEILING_SATS + 1,
                refund_spk=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac",
            )

    def test_and_it_permits_the_honest_dust_case(self, tmp_path) -> None:
        """Paired honest path: the ceiling must bound autonomy, not forbid it."""
        from pyrxd.gravity.watch.executor import MAINNET_DUST_CEILING_SATS, RefundExecutor

        ex = RefundExecutor(
            network="bc",
            broadcaster=self._live_broadcaster(),
            blobs_dir=tmp_path,
            cap_sats=MAINNET_DUST_CEILING_SATS,
            refund_spk=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac",
        )
        assert ex is not None
