"""Fuzz tests for the user-facing CLI surface (issue #10).

Complements the library-level property tests (``tests/test_property_based.py``)
and the parser fuzzers (``tests/test_fuzz_parsers.py``) by targeting the
*CLI* boundary — the code that consumes whatever a user (or a script, or a
hostile environment) throws at the command line.

Each target asserts a robustness contract:

    1. ``_normalize_mnemonic(arbitrary str)``
       Never crashes; always returns a ``str`` with no leading/trailing
       whitespace and no internal whitespace runs; is idempotent.

    2. ``config.load(file of arbitrary bytes)``
       Returns a valid ``Config`` or raises ``ValidationError`` — never a
       raw ``TOMLDecodeError`` / ``ValueError`` / other internal failure
       leaking past the config boundary.

    3. CLI argument fuzzing
       Every invocation produces a documented exit code (0–4) and never
       leaks a non-``SystemExit`` exception (which, in production, is the
       difference between a clean "fix:" message and a raw traceback).

Network/disk seams are stubbed so argument fuzzing never performs real
I/O — we are fuzzing the parse + dispatch surface, not the network.

Hypothesis prints the offending input on failure so any finding is
reproducible. ``HYPOTHESIS_PROFILE=deep`` widens the search (see
``tests/conftest.py``).
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.cli import config as _config
from pyrxd.cli.main import cli
from pyrxd.cli.prompts import _normalize_mnemonic
from pyrxd.security.errors import ValidationError

# Documented exit codes the CLI may return (see src/pyrxd/cli/errors.py and
# the _main wrapper): 0 ok, 1 UserError, 2 click usage error, 3 wallet
# decrypt, 4 unexpected (with a "re-run with --debug" hint, never a raw
# traceback).
_DOCUMENTED_EXIT_CODES = frozenset({0, 1, 2, 3, 4})


# ─────────────────────────── 1. _normalize_mnemonic ──────────────────────────


@settings(max_examples=300, deadline=None)
@given(s=st.text())
def test_normalize_mnemonic_never_crashes_and_normalizes(s: str) -> None:
    out = _normalize_mnemonic(s)
    assert isinstance(out, str)
    # No leading/trailing whitespace and no internal whitespace runs.
    assert out == out.strip()
    assert "  " not in out
    # Idempotent: normalizing again is a no-op.
    assert _normalize_mnemonic(out) == out


@settings(max_examples=200, deadline=None)
@given(
    s=st.text(
        alphabet=st.characters(
            # Bias toward the nasty stuff: control chars, NUL, format/combining
            # marks, plus ordinary letters and spaces.
            categories=["Cc", "Cf", "Zs", "Zl", "Zp", "Mn", "Lu", "Ll"],
        ),
        max_size=200,
    )
)
def test_normalize_mnemonic_unicode_whitespace(s: str) -> None:
    # Exotic Unicode whitespace must not survive as a run, and the result
    # must still be a clean single-spaced string.
    out = _normalize_mnemonic(s)
    assert out == " ".join(out.split())


@settings(max_examples=10, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(n=st.integers(min_value=1_000_000, max_value=2_000_000))
def test_normalize_mnemonic_very_long_input(n: int) -> None:
    # Multi-MB input must not blow up or hang.
    out = _normalize_mnemonic(" a " * n)
    assert out.startswith("a ")
    assert "  " not in out


# ───────────────────────────── 2. config.load ────────────────────────────────


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(blob=st.binary(max_size=512))
def test_config_load_random_bytes(blob: bytes, tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_bytes(blob)
    try:
        cfg = _config.load(cfg_file)
    except ValidationError:
        # The documented failure mode for a malformed config file.
        return
    # If it parsed, it must be a usable Config with coerced int fields.
    assert isinstance(cfg, _config.Config)
    assert isinstance(cfg.fee_rate, int)
    assert isinstance(cfg.coin_type, int)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    text=st.text(
        alphabet=st.characters(categories=["Lu", "Ll", "Nd", "Zs", "Po", "Sm"]),
        max_size=200,
    )
)
def test_config_load_near_toml_text(text: str, tmp_path: Path) -> None:
    # Almost-TOML strings (keys, equals, brackets, quotes) must resolve to a
    # Config or a ValidationError — never an uncaught parser error.
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(text, encoding="utf-8")
    try:
        cfg = _config.load(cfg_file)
    except ValidationError:
        return
    assert isinstance(cfg, _config.Config)


@pytest.mark.parametrize(
    "body",
    [
        'fee_rate = "not-a-number"\n',  # non-int scalar string
        "fee_rate = [1, 2, 3]\n",  # array, not scalar
        'coin_type = "five"\n',  # non-numeric string
        "this is = = not toml\n",  # malformed syntax
        "[unclosed\n",  # malformed table header
        '\xff\xfe garbage = "x"\n',  # non-UTF-8 leading bytes
    ],
)
def test_config_load_bad_values_raise_validation_error(body: str, tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    # Encode latin-1 so the non-UTF-8 case writes raw bytes tomllib rejects.
    cfg_file.write_bytes(body.encode("latin-1"))
    with pytest.raises(ValidationError):
        _config.load(cfg_file)


def test_config_load_float_truncates_not_raises(tmp_path: Path) -> None:
    # TOML float -> int() truncation is standard Python semantics and yields a
    # valid Config (not a leaked error). Documented here so the behavior is
    # intentional, not accidental.
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("coin_type = 1.9\n", encoding="utf-8")
    assert _config.load(cfg_file).coin_type == 1


# ─────────────────────────── 3. CLI argument fuzzing ─────────────────────────

# Vocabulary that mixes real tokens (so the parser actually descends into
# commands) with the random text Hypothesis supplies.
_CLI_VOCAB = [
    "--help",
    "--json",
    "--quiet",
    "--debug",
    "--version",
    "--wallet",
    "--network",
    "--fee-rate",
    "setup",
    "wallet",
    "glyph",
    "address",
    "balance",
    "utxos",
    "new",
    "load",
    "recover",
    "export-xpub",
    "--no-interactive",
    "--coin-type",
    "--scan",
    "0",
    "512",
    "-",
    "--",
    "",
]


def _fake_client() -> MagicMock:
    client = MagicMock()
    client.get_history = AsyncMock(return_value=[])
    client.get_utxos = AsyncMock(return_value=[])
    client.get_balance = AsyncMock(return_value=(0, 0))
    client.get_tip_height = AsyncMock(return_value=0)
    client.get_transaction = AsyncMock(return_value="00" * 65)
    client.broadcast = AsyncMock(return_value="ab" * 32)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(
    args=st.lists(
        st.one_of(st.sampled_from(_CLI_VOCAB), st.text(max_size=12)),
        max_size=6,
    )
)
def test_cli_arbitrary_args_return_documented_exit_code(args: list[str], tmp_path: Path) -> None:
    runner = CliRunner()
    missing_config = tmp_path / "nonexistent-config.toml"
    with ExitStack() as stack:
        # Never touch the real ~/.pyrxd, never hit the network or probe ports.
        stack.enter_context(patch.object(_config, "DEFAULT_CONFIG_PATH", missing_config))
        stack.enter_context(patch("pyrxd.cli.context.CliContext.make_client", lambda self: _fake_client()))
        stack.enter_context(patch("pyrxd.cli.setup_cmd._probe_local_node", return_value=False))

        async def _no_electrumx(url: str) -> bool:
            return False

        stack.enter_context(patch("pyrxd.cli.setup_cmd._probe_electrumx", new=_no_electrumx))
        with runner.isolated_filesystem():
            result = runner.invoke(cli, args, input="")

    assert result.exit_code in _DOCUMENTED_EXIT_CODES, (args, result.exit_code, result.output)
    # The only "exception" allowed to reach the runner is click's controlled
    # SystemExit. Any other type leaking is the bug this fuzz hunts for.
    if result.exception is not None:
        assert isinstance(result.exception, SystemExit), (args, repr(result.exception))
