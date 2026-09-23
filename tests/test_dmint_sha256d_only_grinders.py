"""pyrxd's grinders refuse a proof-of-work hash they do not compute.

Every miner pyrxd runs or speaks to hashes SHA256d: ``mine_solution``, the bundled parallel
miner, and the external-miner protocol ``mine_solution_external`` speaks (its request carries no
algorithm field, and it re-verifies the answer with ``verify_sha256d_solution``). A nonce ground
that way for a BLAKE3 or K12 contract is not a solution to it.

``mine_solution`` already refused BLAKE3/K12 when told the algorithm. ``mine_solution_dispatch``
accepted ``algo`` and DROPPED it on the external path, and ``mine_solution_external`` had no way to
be told at all, so a caller who passed the contract's own algorithm still got a SHA256d grind.
The CLI's refusal (``claim-dmint``, before any grind) is tested in
``tests/cli/test_glyph_cmds.py::TestClaimDmintRefusesContractsPyrxdCannotMine``.

A miner path that does not exist is the probe: a refusal raises ``NotImplementedError`` before
anything is spawned, and a call that gets past the check raises ``FileNotFoundError`` trying to
spawn it — so the honest path (SHA256d) is shown to proceed without grinding anything.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.dmint import DmintAlgo, mine_solution, mine_solution_dispatch, mine_solution_external

_PRE = bytes(64)
_NOWHERE = ["/nonexistent/pyrxd-test-miner"]


@pytest.mark.parametrize("algo", [DmintAlgo.BLAKE3, DmintAlgo.K12])
def test_the_external_protocol_refuses_before_spawning(algo: DmintAlgo) -> None:
    with pytest.raises(NotImplementedError, match=rf"proof of work is {algo.name}.*SHA256d only"):
        mine_solution_external(_PRE, 1, miner_argv=_NOWHERE, nonce_width=8, timeout_s=5, algo=algo)


def test_the_external_protocol_still_runs_for_sha256d() -> None:
    with pytest.raises(FileNotFoundError):
        mine_solution_external(_PRE, 1, miner_argv=_NOWHERE, nonce_width=8, timeout_s=5, algo=DmintAlgo.SHA256D)
    with pytest.raises(FileNotFoundError):  # and the default is SHA256d, as it always was
        mine_solution_external(_PRE, 1, miner_argv=_NOWHERE, nonce_width=8, timeout_s=5)


@pytest.mark.parametrize("miner_argv", [None, _NOWHERE], ids=["in-process", "external"])
@pytest.mark.parametrize("algo", [DmintAlgo.BLAKE3, DmintAlgo.K12])
def test_dispatch_refuses_on_both_paths(algo: DmintAlgo, miner_argv: list[str] | None) -> None:
    """The external path used to ignore ``algo`` entirely."""
    with pytest.raises(NotImplementedError, match=rf"proof of work is {algo.name}"):
        mine_solution_dispatch(_PRE, 1, nonce_width=8, algo=algo, miner_argv=miner_argv, max_attempts=1, timeout_s=5)


def test_dispatch_still_runs_for_sha256d() -> None:
    with pytest.raises(FileNotFoundError):
        mine_solution_dispatch(_PRE, 1, nonce_width=8, algo=DmintAlgo.SHA256D, miner_argv=_NOWHERE, timeout_s=5)


def test_the_in_process_miner_names_the_algorithm_too() -> None:
    with pytest.raises(NotImplementedError, match="proof of work is BLAKE3"):
        mine_solution(_PRE, 1, algo=DmintAlgo.BLAKE3, nonce_width=8)
