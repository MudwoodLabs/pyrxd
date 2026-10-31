"""The confirmation depth a quorum of sources vouches for (register R13).

Every BTC depth read that asks several sources — :class:`pyrxd.network.bitcoin.MultiSourceBtcFundingReader`
and the counter-leg disposition reader (:mod:`pyrxd.btc_wallet.disposition`) — reduces their answers
to one number here.

It used to be the MINIMUM. That defeats a source that over-reports, but one source that UNDER-reports
then holds every answer down, however many others agree: a buried claim read as shallow, so the
claim gate waited until its window closed. The depth taken now is the deepest one that at least
``quorum`` of the answering sources report at least: the ``quorum``-th deepest answer.

* A source that over-reports cannot raise it: with ``quorum`` >= 2, at least one other answering
  source must report a depth that deep too. Up to ``quorum - 1`` such sources are tolerated, as
  before.
* A source that under-reports cannot lower it while ``quorum`` others answer.
* When exactly ``quorum`` sources answer, it is their minimum, as before.

With ``quorum`` below 2 (any one source decides alone), or fewer than ``quorum`` answers (a below-dust
read), it stays the minimum: there is no second source to vouch for a deeper answer.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..security.errors import ValidationError

__all__ = ["depth_vouched_by_quorum"]


def depth_vouched_by_quorum(depths: Sequence[int], quorum: int) -> int:
    """The deepest depth that at least *quorum* of *depths* reach (module docstring).

    *depths* holds one answer per answering source, each counted once. Raises
    :class:`ValidationError` on no answers or a *quorum* below 1."""
    if isinstance(quorum, bool) or not isinstance(quorum, int) or quorum < 1:
        raise ValidationError(f"quorum must be a positive int, not {quorum!r}")
    answers = [int(d) for d in depths]
    if not answers:
        raise ValidationError("depth_vouched_by_quorum needs at least one answer")
    if quorum < 2 or len(answers) < quorum:
        return min(answers)
    return sorted(answers, reverse=True)[quorum - 1]
