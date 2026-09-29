"""An outpoint's output index is ASCII decimal digits and nothing else (#746).

``_inspect_outpoint`` parsed the index with ``int()``, which also takes ``1_0`` (as output 10:
underscores are digit separators), `` 1`` (surrounding whitespace is stripped), ``+1`` and
non-ASCII digits. None of those is the documented ``<txid>:<n>`` form. The ``/inspect/`` and
``/verify/`` pages state the parsed number back, so nothing false was shown, but the parser
accepted what nobody types on purpose.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from pyrxd.cli.main import cli
from pyrxd.glyph._inspect_core import _inspect_outpoint
from pyrxd.security.errors import ValidationError

TXID = "ab" * 32


@pytest.mark.parametrize(
    "index",
    ["1_0", " 1", "1 ", "+1", "-1", "", "0x1", "1.0", "١", "１", "1\n"],
    ids=[
        "underscore",
        "lead-space",
        "trail-space",
        "plus",
        "minus",
        "empty",
        "hex",
        "float",
        "arabic",
        "fullwidth",
        "newline",
    ],
)
def test_anything_but_ascii_digits_is_refused(index: str) -> None:
    with pytest.raises(ValidationError, match="vout is not an integer"):
        _inspect_outpoint(f"{TXID}:{index}")


@pytest.mark.parametrize(("index", "vout"), [("0", 0), ("1", 1), ("10", 10), ("007", 7), ("4294967295", 4294967295)])
def test_ascii_digits_still_parse(index: str, vout: int) -> None:
    """The honest path: every plain decimal index still reads as the number it spells."""
    out = _inspect_outpoint(f"{TXID}:{index}")
    assert out["vout"] == vout
    assert out["outpoint"] == f"{TXID}:{vout}"


def test_an_index_too_long_for_int_is_refused_not_crashed() -> None:
    """``int()`` refuses more than 4300 digits with a raw ``ValueError``; that is a refusal, not a crash."""
    with pytest.raises(ValidationError, match="0..2"):
        _inspect_outpoint(f"{TXID}:{'9' * 4301}")
    result = CliRunner().invoke(cli, ["glyph", "inspect", f"{TXID}:{'9' * 4301}"])
    assert result.exit_code == 1, result.output
    assert "unexpected failure" not in result.output


def test_leading_zeros_past_the_int_limit_still_parse() -> None:
    """Zero-padding is not a larger number: 4300 zeros then ``1`` is output 1, like ``0001``."""
    assert _inspect_outpoint(f"{TXID}:{'0' * 4300}1")["vout"] == 1


def test_the_cli_refuses_an_underscored_index_and_accepts_the_plain_one() -> None:
    refused = CliRunner().invoke(cli, ["--json", "glyph", "inspect", f"{TXID}:1_0"])
    assert refused.exit_code != 0
    assert '"vout": 10' not in refused.output
    accepted = CliRunner().invoke(cli, ["--json", "glyph", "inspect", f"{TXID}:10"])
    assert accepted.exit_code == 0, accepted.output
    assert '"vout": 10' in accepted.output
