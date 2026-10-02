"""The config-file URLs the CLI redactor knows are THIS invocation's, never an earlier one's.

``cli()`` hands every URL in the loaded config to the redactor so a key that lives only in the
config file is scrubbed from errors and ``--debug`` tracebacks. That registry is process-global,
and it used to be appended to: a test runner (or anything calling ``cli()`` twice in one process)
then redacted the second run's output with the first run's URLs. That can let a test pass on
someone else's registration, and over-redact text — ``?v=2`` rewrites a "line 2" — long after the
URL stopped mattering.
"""

from __future__ import annotations

from click.testing import CliRunner

from pyrxd.cli import errors as _errors
from pyrxd.cli.main import cli


def _invoke_with(tmp_path, name: str, url: str) -> None:
    cfg = tmp_path / f"{name}.toml"
    cfg.write_text(f'network = "mainnet"\nelectrumx_servers = ["{url}"]\n')
    # `address --help` runs the group callback (which loads the config) and touches no network.
    res = CliRunner().invoke(cli, ["--config", str(cfg), "address", "--help"])
    assert res.exit_code == 0, res.output


def test_a_second_invocation_does_not_inherit_the_first_ones_urls(tmp_path) -> None:
    first = "wss://FIRSTKEY0123456789abcdef@one.example:50022/"
    second = "wss://two.example:50022/"
    _invoke_with(tmp_path, "first", first)
    assert first in _errors.endpoint_urls_in_invocation()  # non-vacuity: registration happened
    _invoke_with(tmp_path, "second", second)
    known = _errors.endpoint_urls_in_invocation()
    assert second in known
    assert first not in known, known


def test_a_config_that_fails_to_load_leaves_no_urls_from_before(tmp_path) -> None:
    """Cleared BEFORE the load, so a run whose config is refused does not redact with the
    previous run's URLs either."""
    first = "wss://FIRSTKEY0123456789abcdef@one.example:50022/"
    _invoke_with(tmp_path, "first", first)
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml\n")
    CliRunner().invoke(cli, ["--config", str(bad), "address", "--help"])
    assert first not in _errors.endpoint_urls_in_invocation()
