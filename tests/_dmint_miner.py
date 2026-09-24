"""Which miner the node-backed dMint suites grind with — chosen here, once, for all three.

Used by ``test_dmint_v1_regtest_e2e.py``, ``test_dmint_v2_regtest_e2e.py`` and
``test_dmint_premine_regtest_e2e.py``. Each hands the result to ``mine_solution_dispatch``, which
runs it through ``mine_solution_external``: the request/response protocol and the local
re-verification of every returned nonce with ``verify_sha256d_solution`` are the same whichever
miner answers.

``DMINT_MINER_CMD``
    Unset (the default, and the fallback): the bundled pure-Python parallel miner,
    ``python -m pyrxd.contrib.miner``, which these suites have always used.
    Set: that command, split as a shell would, which must speak pyrxd's external-miner protocol.
    The nightly integration job builds the native grinder with
    ``python -m pyrxd.contrib.miner.native`` and points this at it.

    A ``DMINT_MINER_CMD`` that names nothing runnable is an error when the suite is imported,
    not a quiet fallback: a nightly job that had slipped back to the slower miner would only
    look like it was running long.
``DMINT_MINE_WORKERS``
    Appended as ``--workers N``. Both the bundled miner and the native grinder accept it; a
    third-party miner named by ``DMINT_MINER_CMD`` has to as well, or leave this unset.
``DMINT_MINE_TIMEOUT_S``
    The per-grind ceiling; each suite passes its own default to :func:`dmint_mine_timeout_s`.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys

_BUNDLED = [sys.executable, "-m", "pyrxd.contrib.miner"]


def dmint_miner_argv() -> list[str]:
    """The ``miner_argv`` for ``mine_solution_dispatch``. Raises if ``DMINT_MINER_CMD`` is set
    but its program cannot be found or is not executable."""
    cmd = os.environ.get("DMINT_MINER_CMD", "").strip()
    if cmd:
        argv = shlex.split(cmd)
        if shutil.which(argv[0]) is None:
            raise RuntimeError(
                f"DMINT_MINER_CMD={cmd!r}: {argv[0]!r} is not an executable file or a command on PATH. "
                "Unset DMINT_MINER_CMD to grind with the bundled Python miner."
            )
    else:
        argv = list(_BUNDLED)
    workers = os.environ.get("DMINT_MINE_WORKERS")
    if workers:
        argv += ["--workers", workers]
    return argv


def dmint_miner_label(argv: list[str]) -> str:
    """A short name for the log line each grind prints, so a run's log says which miner ran."""
    if argv[: len(_BUNDLED)] == _BUNDLED:
        return "bundled Python miner"
    return os.path.basename(argv[0])


def dmint_mine_timeout_s(default: float) -> float:
    """``DMINT_MINE_TIMEOUT_S`` if set, else the calling suite's own default."""
    return float(os.environ.get("DMINT_MINE_TIMEOUT_S", default))
