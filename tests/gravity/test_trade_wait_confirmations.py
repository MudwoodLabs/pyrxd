"""``GravityTrade.wait_confirmations`` — the BTC confirmation wait.

This is the poll a taker sits in while its BTC payment buries, and until now
nothing in the suite called it. That absence is why the defect below survived:
the loop opened each attempt with a bare ``await self._btc.get_tip_height()``
whose result was discarded, placed **outside** the ``try`` that guards the very
next line. A source that failed to answer that one call raised straight out of
the wait, while the identical failure one line later was caught and retried.

Aborting here is not a safe default. The caller is racing a timelock on a chain
with neither RBF nor CPFP; an abort during that race costs the funds the poll
was watching over. The call was also vestigial — the comment beneath it
described computing depth as ``tip - block_height``, an approach the code does
not take (it re-requests the tx at ``min_confirmations`` and lets the source
apply its own view of the tip).

Both halves are pinned here: the wait must survive a source that cannot report
a tip, and it must still refuse to report a confirmation it was never told
about.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.trade import GravityTrade, TradeConfig
from pyrxd.security.errors import NetworkError, ValidationError

pytestmark = pytest.mark.asyncio

_TXID = "b" * 64


class _Btc:
    """Minimal ``BtcDataSource`` stand-in recording what the loop asked for."""

    def __init__(
        self,
        *,
        tip: int | None = 900_000,
        confirmed_at: int | None = None,
        visible: bool = True,
    ) -> None:
        self._tip = tip
        self._confirmed_at = confirmed_at
        self._visible = visible
        self.tip_calls = 0
        self.raw_calls: list[int] = []

    async def get_tip_height(self) -> int:
        self.tip_calls += 1
        if self._tip is None:
            raise NetworkError("tip unavailable")
        return self._tip

    async def get_raw_tx(self, txid: object, *, min_confirmations: int = 0) -> bytes:
        self.raw_calls.append(min_confirmations)
        if not self._visible:
            raise NetworkError("not in mempool")
        if min_confirmations == 0:
            return b"\x00"
        if self._confirmed_at is None or min_confirmations > self._confirmed_at:
            raise NetworkError(f"only {self._confirmed_at} confirmations")
        return b"\x00"


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    """``poll_interval_seconds`` must be > 0, so the wait is made instant here.

    Patched at the module the loop calls it through, not globally — the retry
    *count* is what these tests assert on, and it stays real.
    """

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr("pyrxd.gravity.trade.asyncio.sleep", _instant)


def _trade(btc: _Btc, *, attempts: int = 3) -> GravityTrade:
    cfg = TradeConfig(max_poll_attempts=attempts, poll_interval_seconds=1)
    return GravityTrade(radiant_network=object(), bitcoin_source=btc, config=cfg)  # type: ignore[arg-type]


class TestTheWaitSurvivesWhatItShould:
    """The inverse-bug half: valid work must not be refused."""

    async def test_a_source_that_cannot_report_a_tip_does_not_abort_the_wait(self) -> None:
        """The defect, stated as a test.

        A source whose tip read fails but whose tx reads succeed is an ordinary
        partial outage. Before the fix this raised out of ``wait_confirmations``
        entirely; the taker's confirmation wait ended mid-timelock-race.
        """
        btc = _Btc(tip=None, confirmed_at=6)
        status = await _trade(btc).wait_confirmations(_TXID, min_confirmations=6)

        assert status.confirmed is True
        assert status.confirmations == 6
        assert btc.tip_calls == 0, "the wait must not depend on a tip read it never uses"

    async def test_the_tip_height_is_never_read_at_all(self) -> None:
        """Depth comes from the source, not from arithmetic on a separate read.

        Re-requesting at ``min_confirmations`` lets the source apply its own view
        of the tip in one read. Subtracting a separately fetched tip from a block
        height would reintroduce a two-read race.

        Precisely what "its own view" means, since this used to say
        "quorum-checked": on the ``MultiSourceBtcDataSource`` path the depth is
        judged by each LEAF against its own un-quorumed tip, and the quorum then
        covers the returned bytes plus the count of leaves that independently
        passed. At least as strict, but not a single agreed tip height.
        """
        btc = _Btc(confirmed_at=3)
        await _trade(btc).wait_confirmations(_TXID, min_confirmations=3)

        assert btc.tip_calls == 0
        assert btc.raw_calls == [0, 3], "one visibility probe, then one depth probe"

    async def test_a_tx_not_yet_visible_is_retried_rather_than_raised(self) -> None:
        btc = _Btc(visible=False)
        with pytest.raises(NetworkError, match="not found after"):
            await _trade(btc, attempts=3).wait_confirmations(_TXID, min_confirmations=1)

        assert len(btc.raw_calls) == 3, "every attempt must be spent before giving up"


class TestTheWaitStillRefusesWhatItShould:
    """The other half, so the fix cannot be 'stop checking'."""

    async def test_a_shallow_tx_never_reports_confirmed(self) -> None:
        """Buried 2 deep, asked for 6 — the wait must exhaust and raise."""
        btc = _Btc(confirmed_at=2)
        with pytest.raises(NetworkError, match="did not reach 6 confirmations"):
            await _trade(btc, attempts=2).wait_confirmations(_TXID, min_confirmations=6)

        assert btc.raw_calls == [0, 6, 0, 6]

    async def test_it_reports_the_depth_it_actually_proved(self) -> None:
        btc = _Btc(confirmed_at=99)
        status = await _trade(btc).wait_confirmations(_TXID, min_confirmations=6)

        assert status.confirmations == 6, "report what was asked and proved, not the source's surplus"
        assert status.txid == _TXID

    async def test_a_malformed_txid_is_refused_before_any_network_call(self) -> None:
        btc = _Btc()
        with pytest.raises(ValidationError):
            await _trade(btc).wait_confirmations("not-a-txid", min_confirmations=1)

        assert btc.raw_calls == [], "validation must precede the first poll"
