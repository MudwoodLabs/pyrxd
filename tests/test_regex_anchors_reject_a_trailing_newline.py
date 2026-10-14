"""#769: a regex anchored with ``$`` matches before a trailing newline, so ``"<txid>\\n"`` validated as a
Txid and went on to network calls (and the same for BTC addresses, derivation-path steps and legacy
addresses). Every constant pattern in ``src/`` is now anchored at ``\\Z``.

The defect, as a predicate: *a constant regex literal in ``src/`` ends with an unescaped ``$``.* The
guard below derives the set of regex literals from the source tree and checks every one.

Two of the patterns DETECT secrets rather than accept input (``security/errors.py`` redaction and
``cli/swap_recovery.py``'s private-key screen). For those, ``$`` erring toward a match was the safe
direction, so they strip whitespace before matching: anchoring at ``\\Z`` must not narrow what is
redacted or refused.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyrxd.security.errors import ValidationError

_SRC = Path(__file__).resolve().parents[1] / "src" / "pyrxd"
_RE_CALLS = {"compile", "match", "search", "fullmatch"}

_TXID = "ab" * 32
_BTC_ADDR = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"


def _regex_literals() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr in _RE_CALLS
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                found.append((str(path.relative_to(_SRC)), node.lineno, node.args[0].value))
    return found


def test_no_constant_regex_in_src_is_anchored_with_dollar() -> None:
    literals = _regex_literals()
    assert len(literals) > 20, literals  # the set is derived; an empty scan would prove nothing
    dollar = [f"{f}:{line}: {pat!r}" for f, line, pat in literals if pat.endswith("$") and not pat.endswith("\\$")]
    assert not dollar, "anchor at \\Z (or call fullmatch): `$` also matches before a trailing newline\n" + "\n".join(
        dollar
    )


# --- validators refuse the trailing newline, and still accept the value without it ---------------


def test_txid() -> None:
    from pyrxd.security.types import Txid

    assert Txid(_TXID) == _TXID
    with pytest.raises(ValidationError):
        Txid(_TXID + "\n")


def test_btc_address() -> None:
    from pyrxd.btc_wallet.validate import validate_btc_address

    validate_btc_address(_BTC_ADDR)
    with pytest.raises(ValidationError):
        validate_btc_address(_BTC_ADDR + "\n")


def test_derivation_path_step() -> None:
    from pyrxd.hd.descriptor import normalize_path

    assert normalize_path("m/44'/512'/0'") == "44h/512h/0h"
    with pytest.raises(ValidationError):
        normalize_path("m/44'/512'\n/0'")


def test_legacy_address_decode() -> None:
    from pyrxd.utils import decode_address

    decode_address(_BTC_ADDR)
    with pytest.raises(ValueError):
        decode_address(_BTC_ADDR + "\n")


# --- detectors still catch a secret with surrounding whitespace ---------------------------------


@pytest.mark.parametrize("suffix", ["", "\n", " "])
def test_redaction_still_redacts_a_key_with_a_trailing_newline(suffix) -> None:
    from pyrxd.security.errors import redact

    assert redact("cd" * 32 + suffix) == "<redacted>"
    assert redact("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" + suffix) == "<redacted>"


def test_redaction_still_leaves_prose_alone() -> None:
    from pyrxd.security.errors import redact

    assert redact("not a key, just words\n") == "not a key, just words\n"


@pytest.mark.parametrize("suffix", ["", "\n"])
def test_recovery_screen_still_flags_a_bare_key_with_a_trailing_newline(suffix) -> None:
    from pyrxd.cli.swap_recovery import _carries_private_key

    assert _carries_private_key({"note": "cd" * 32 + suffix}) is True
    # Honest path: the same shape under a public 32-byte field name is not a key.
    assert _carries_private_key({"hashlock_H": "cd" * 32 + suffix}) is False
