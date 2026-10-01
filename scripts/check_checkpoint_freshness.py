#!/usr/bin/env python3
"""Say when pyrxd's shipped Radiant checkpoints are about to stop verifying new blocks.

READ-ONLY. It asks pyrxd's shipped public mainnet ElectrumX servers for their tip height and sends
nothing else.

``pyrxd verify`` and the ``/verify/`` and ``/inspect/`` pages link a mark's block to the newest
shipped checkpoint through at most :data:`pyrxd.glyph.mark_block.MAX_HEADERS_FROM_CHECKPOINT` (4,032)
headers. Past that every new mark reads NOT VERIFIED ("needs a newer pyrxd") until a release ships a
refreshed table, and the pages pick it up on their next deploy from ``main``. The swap taker gate's
horizon (:data:`pyrxd.gravity.funding_spv.MAX_HEADERS_FROM_CHECKPOINT_SDK`, 20,160) is longer and is
reported too.

Exit codes — every non-zero one fails the scheduled job:

* ``0`` — at least :data:`WARN_BLOCKS` (864, three days at the 300 s target) remain before the page horizon.
* ``1`` — fewer remain, or it has passed: refresh the table before the next release.
* ``2`` — the check could not run: no server answered with a tip at or above the newest
  checkpoint. That is a broken check, NOT a fresh table.

    PYTHONPATH=src python scripts/check_checkpoint_freshness.py

This is not a pytest test for the same reason ``refresh_radiant_checkpoints.py`` is not: it needs the
network. ``tests/test_checkpoint_freshness_check.py`` tests its decision offline.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

NETWORK = "mainnet"
#: Fail when fewer blocks than this remain before the page horizon: 864 blocks, three days at the
#: 300 s target. The arithmetic (the refresh script's ``MAX_MIN_DEPTH`` is derived from it): a refresh
#: at min-depth ``d`` leaves the newest checkpoint ``d`` to ``d + 2015`` blocks below the tip, and the
#: job is red once that age passes ``4032 - 864 = 3168``. At the default ``d = 288`` the age is 288
#: to 2,303, so every refresh turns the job green, and it stays green for 865 to 2,880 blocks (3.0
#: to 10.0 days) before going red with 864 blocks (3.0 days) of notice before new marks stop
#: verifying.
WARN_BLOCKS = 864
#: Per-server timeout for the tip read, in seconds.
TIMEOUT_S = 30.0

REFRESH = (
    "Refresh the checkpoints with the maintainer's node before the next release:\n"
    '    PYTHONPATH=src python scripts/refresh_radiant_checkpoints.py --write --node-cli "<radiant-cli command>"\n'
    "then merge the regenerated src/pyrxd/spv/radiant_checkpoints.py (the pages redeploy from main)."
)


@dataclass(frozen=True)
class Verdict:
    code: int
    message: str


def assess(
    tips: Mapping[str, int | None],
    *,
    newest_checkpoint: int,
    page_cap: int,
    sdk_cap: int,
    warn_blocks: int = WARN_BLOCKS,
) -> Verdict:
    """The verdict for the tips each server reported (``None``: it did not answer). Pure.

    The highest usable tip decides: a server behind the others would only hide how close the
    horizon is. A tip below the newest checkpoint is not this chain's tip and is not used.
    """
    usable = {
        u: t for u, t in tips.items() if isinstance(t, int) and not isinstance(t, bool) and t >= newest_checkpoint
    }
    answered = ", ".join(f"{u}={t}" for u, t in tips.items())
    if not usable:
        return Verdict(
            2,
            f"could not read a mainnet tip at or above the newest checkpoint ({newest_checkpoint}) from any "
            f"shipped server ({answered or 'none asked'}). The freshness check did not run; this is NOT a "
            "fresh table.",
        )
    tip = max(usable.values())
    page_horizon = newest_checkpoint + page_cap
    sdk_horizon = newest_checkpoint + sdk_cap
    left = page_horizon - tip
    facts = (
        f"tip {tip} (from {', '.join(u for u, t in usable.items() if t == tip)}); newest shipped checkpoint "
        f"{newest_checkpoint}; pyrxd verify and the pages link at most {page_cap} past it (block {page_horizon}), "
        f"{left} block(s) from the tip; the swap taker gate links at most {sdk_cap} (block {sdk_horizon}), "
        f"{sdk_horizon - tip} from the tip"
    )
    if left < warn_blocks:
        state = "has PASSED" if left < 0 else "is near"
        return Verdict(
            1,
            f"The checkpoint horizon {state}: {facts}. Fewer than {warn_blocks} blocks ({warn_blocks * 300 / 86400:g} days at the 300 s target) remain "
            f"before new marks stop verifying.\n{REFRESH}",
        )
    return Verdict(0, f"OK: {facts}.")


async def _tip(url: str) -> int | None:
    from pyrxd.network.electrumx import ElectrumXClient

    try:
        async with ElectrumXClient([url]) as client:
            return int(await asyncio.wait_for(client.get_tip_height(), TIMEOUT_S))
    except Exception as exc:  # one server down is reported, not fatal
        print(f"{url}: no tip ({type(exc).__name__})", file=sys.stderr)
        return None


async def _tips(urls: Sequence[str]) -> dict[str, int | None]:
    got = await asyncio.gather(*(_tip(u) for u in urls))
    return dict(zip(urls, got))


def main(argv: Sequence[str] | None = None) -> int:
    from pyrxd.glyph.mark_block import MAX_HEADERS_FROM_CHECKPOINT
    from pyrxd.gravity.funding_spv import MAX_HEADERS_FROM_CHECKPOINT_SDK
    from pyrxd.network.registry import DEFAULT_ENDPOINTS
    from pyrxd.spv.radiant_checkpoints import CHECKPOINTS

    del argv
    verdict = assess(
        asyncio.run(_tips(tuple(DEFAULT_ENDPOINTS[NETWORK]))),
        newest_checkpoint=CHECKPOINTS[NETWORK][-1][0],
        page_cap=MAX_HEADERS_FROM_CHECKPOINT,
        sdk_cap=MAX_HEADERS_FROM_CHECKPOINT_SDK,
    )
    if verdict.code:
        # A workflow annotation is one line; the full message, with the remedy, follows it.
        print("::error::" + verdict.message.splitlines()[0])
    print(verdict.message)
    return verdict.code


if __name__ == "__main__":
    sys.exit(main())
