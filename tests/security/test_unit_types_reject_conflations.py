"""The unit tags are only worth their annotations if the CHECKER really rejects the bugs.

Three confirmed defects in this codebase were unit conflations between two non-negative
``int``s (see :mod:`pyrxd.security.units`). ``pyrxd.security.units`` makes each pair a
distinct :func:`typing.NewType` so the conflation is a mypy error. This test is the proof
that it is — and, just as importantly, that the corrected form is NOT.

Both halves matter. A checker that rejects everything is as useless as one that rejects
nothing, and "a guard that refuses valid work is a bug" applies to a type as much as to a
runtime check: every REJECTED fixture below is paired with an ACCEPTED one that differs
only in the unit, so a rule that simply fails on contact with these modules cannot pass.

The fixtures reproduce the real defects, not toy ones:

* ``height_confs_bug`` is the ssh-tr mainnet shim's ``tip - height + 1``, which stored a
  CONFIRMATION COUNT in ``UtxoRecord.height`` and inverted ``find_covenant_utxo``'s
  earliest-confirmed anti-poisoning rule into a poison-SELECTING rule.
* ``anchor_bug`` is the downstream compensation for it, feeding a depth to the reorg
  gate's ``asset_locked_at_height`` anchor.
* ``photon_token_bug`` is issue #505, still OPEN: the FT funding gate matching a TOKEN
  COUNT against the covenant carrier's PHOTON value.
* ``seconds_blocks_bug`` is the third pair — a block-count duration reaching a field that
  holds wall-clock seconds, the shape behind two off-by-ones shipped in one week.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("mypy") is None,
    reason="mypy is not installed in this environment (it is in the dev group, which CI installs)",
)


# ---------------------------------------------------------------------------------------
# The fixtures. Each is a complete module; the BUG ones must be rejected on the marked
# line, the OK ones must produce no error at all.
# ---------------------------------------------------------------------------------------

_HEIGHT_CONFS_BUG = '''\
"""The ssh-tr shim's original defect: a confirmation count stored in a height field."""
from __future__ import annotations

from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.units import ChainHeight, Confirmations, PhotonValue


def shim_get_utxos(tip: ChainHeight, mined_at: ChainHeight, txid: str) -> UtxoRecord:
    confs = Confirmations(int(tip) - int(mined_at) + 1)
    return UtxoRecord(tx_hash=txid, tx_pos=0, value=PhotonValue(546), height=confs)
'''

_HEIGHT_CONFS_OK = '''\
"""The same producer, storing the height it was actually given."""
from __future__ import annotations

from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.units import ChainHeight, PhotonValue


def shim_get_utxos(tip: ChainHeight, mined_at: ChainHeight, txid: str) -> UtxoRecord:
    return UtxoRecord(tx_hash=txid, tx_pos=0, value=PhotonValue(546), height=mined_at)
'''

_ANCHOR_BUG = '''\
"""The downstream half: a depth fed to the reorg gate's anchor, which wants a height."""
from __future__ import annotations

from pyrxd.gravity.watch.decide import Observations
from pyrxd.security.units import ChainHeight, Confirmations


def observe(tip: ChainHeight, cov_confs: Confirmations) -> Observations:
    return Observations(maker_has_claimed_btc=False, now_rxd_height=tip, asset_locked_at_height=cov_confs)
'''

_ANCHOR_OK = '''\
"""The conversion written out: depth in, height out, re-tagged where the arithmetic proves it."""
from __future__ import annotations

from pyrxd.gravity.watch.decide import Observations
from pyrxd.security.units import ChainHeight, Confirmations


def observe(tip: ChainHeight, cov_confs: Confirmations) -> Observations:
    mined_at = ChainHeight(int(tip) - int(cov_confs) + 1)
    return Observations(maker_has_claimed_btc=False, now_rxd_height=tip, asset_locked_at_height=mined_at)
'''

_PHOTON_TOKEN_BUG = '''\
"""Issue #505: the FT funding gate matching a token count against a carrier photon value."""
from __future__ import annotations

from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.security.units import TokenUnits


async def gate_ft(io: RadiantChainIO, spk: bytes, ft_amount: TokenUnits) -> str:
    outpoint, _value, _height = await io.find_covenant_utxo(spk, expected_value=ft_amount)
    return outpoint
'''

_PHOTON_TOKEN_OK = '''\
"""The RXD/NFT case, where radiant_amount really IS the carrier's photon value."""
from __future__ import annotations

from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.security.units import PhotonValue


async def gate_rxd(io: RadiantChainIO, spk: bytes, carrier: PhotonValue) -> str:
    outpoint, _value, _height = await io.find_covenant_utxo(spk, expected_value=carrier)
    return outpoint
'''

_SECONDS_BLOCKS_BUG = '''\
"""Pair 3: a duration in BLOCKS handed to a field measured in wall-clock SECONDS."""
from __future__ import annotations

from pyrxd.gravity.watch.decide import Observations
from pyrxd.security.units import BlockSpan, ChainHeight


def observe(tip: ChainHeight, safety_window: BlockSpan) -> Observations:
    return Observations(maker_has_claimed_btc=False, now_rxd_height=tip, now_unix_s=safety_window)
'''

_SECONDS_BLOCKS_OK = '''\
"""The same field fed an actual wall clock."""
from __future__ import annotations

from pyrxd.gravity.watch.decide import Observations
from pyrxd.security.units import ChainHeight, Seconds


def observe(tip: ChainHeight, now: Seconds) -> Observations:
    return Observations(maker_has_claimed_btc=False, now_rxd_height=tip, now_unix_s=now)
'''

#: ``name -> (source, expected error substrings)``. An empty tuple means "must be clean".
_FIXTURES: dict[str, tuple[str, tuple[str, ...]]] = {
    "height_confs_bug": (
        _HEIGHT_CONFS_BUG,
        ('Argument "height"', '"Confirmations"', 'expected "ChainHeight"'),
    ),
    "height_confs_ok": (_HEIGHT_CONFS_OK, ()),
    "anchor_bug": (
        _ANCHOR_BUG,
        ('Argument "asset_locked_at_height"', '"Confirmations"', 'expected "ChainHeight | None"'),
    ),
    "anchor_ok": (_ANCHOR_OK, ()),
    "photon_token_bug": (
        _PHOTON_TOKEN_BUG,
        ('Argument "expected_value"', '"TokenUnits"', 'expected "PhotonValue | None"'),
    ),
    "photon_token_ok": (_PHOTON_TOKEN_OK, ()),
    "seconds_blocks_bug": (
        _SECONDS_BLOCKS_BUG,
        ('Argument "now_unix_s"', '"BlockSpan"', 'expected "Seconds | None"'),
    ),
    "seconds_blocks_ok": (_SECONDS_BLOCKS_OK, ()),
}


@pytest.fixture(scope="module")
def mypy_output(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    """Run mypy ONCE over every fixture; return ``{fixture name: [error lines]}``.

    Module-scoped because a cold mypy run over this package is the expensive part and the
    fixtures are independent. ``follow_imports = silent`` (pyproject) means only the files
    named on the command line report errors, so an unrelated module's pre-existing errors
    cannot leak in and make a bug fixture "pass" for the wrong reason.
    """
    workdir = tmp_path_factory.mktemp("unit_conflation_fixtures")
    for name, (source, _expected) in _FIXTURES.items():
        (workdir / f"{name}.py").write_text(source)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            str(_REPO / "pyproject.toml"),
            "--no-error-summary",
            "--hide-error-context",
            "--cache-dir",
            str(workdir / ".mypy_cache"),
            *[str(workdir / f"{name}.py") for name in _FIXTURES],
        ],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    if "Cannot find implementation" in proc.stdout or proc.stderr.strip():
        raise AssertionError(
            "the fixture run could not resolve pyrxd, so a 'no error' result would be "
            f"meaningless.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    by_fixture: dict[str, list[str]] = {name: [] for name in _FIXTURES}
    for line in proc.stdout.splitlines():
        for name in _FIXTURES:
            if line.startswith(str(workdir / f"{name}.py")) and ": error:" in line:
                by_fixture[name].append(line)
    return by_fixture


@pytest.mark.parametrize("name", [n for n, (_s, exp) in _FIXTURES.items() if exp])
def test_mypy_rejects_the_historical_conflation(name: str, mypy_output: dict[str, list[str]]) -> None:
    """The refusal half: each real defect is a check error, naming both units."""
    _source, expected = _FIXTURES[name]
    errors = mypy_output[name]
    assert errors, f"{name}: mypy accepted the conflation — the unit tags are not load-bearing here"
    joined = "\n".join(errors)
    for fragment in expected:
        assert fragment in joined, f"{name}: expected {fragment!r} in mypy output, got:\n{joined}"


@pytest.mark.parametrize("name", [n for n, (_s, exp) in _FIXTURES.items() if not exp])
def test_mypy_accepts_the_corrected_code(name: str, mypy_output: dict[str, list[str]]) -> None:
    """The honest-path half: the SAME call sites, in the right units, must pass.

    Without this, a rule that rejected every one of these modules would look like success.
    """
    errors = mypy_output[name]
    assert not errors, f"{name}: correct code was refused — a type that rejects valid work is a bug:\n" + "\n".join(
        errors
    )


def test_the_unit_tags_are_free_at_runtime() -> None:
    """A NewType call is the identity. The tags must cost nothing and validate nothing —
    that is why they can be applied at a producer inside a list comprehension where a
    range check would abort the whole read (see `pyrxd.security.units`)."""
    from pyrxd.security.units import ChainHeight, Confirmations, PhotonValue, TokenUnits

    for tag in (ChainHeight, Confirmations, PhotonValue, TokenUnits):
        value = tag(7)
        assert value == 7
        assert type(value) is int, f"{tag} is not zero-cost: it produced a {type(value).__name__}"
    # No range check: a value a validating type would refuse still passes, because these tag
    # the UNIT, not the range. Range lives in pyrxd.security.types.
    assert ChainHeight(10**12) == 10**12
