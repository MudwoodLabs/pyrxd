"""A vout, an amount or an octet is written in ASCII digits ``0-9`` — never ``str.isdigit()``.

``str.isdigit()`` is true for far more than ``0-9``. For a superscript (``"²"``) it is true while
``int()`` refuses the string, so a check-then-convert raised a bare ``ValueError`` past a handler
that expected a typed error. For Arabic-Indic (``"١"``) and full-width (``"１"``) digits it is true
and ``int()`` CONVERTS them, so ``"<txid>:١"`` silently became vout 1. Plain ``int()`` with no check
also takes ``" 1"``, ``"+1"`` and ``"1_0"``.

Each site that parsed one of these is driven through its own entry point below, with the same
inputs, and the set of ``isdigit()`` calls left in shipped code is pinned so a new one is a
decision, not an accident.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

from pyrxd.cli.errors import UserError
from pyrxd.cli.swap_book_cmds import _parse_outpoint as book_parse_outpoint
from pyrxd.cli.swap_recovery import parse_outpoint as recovery_parse_outpoint
from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.security.errors import ValidationError

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = str(_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import _dust_swap_shared
import swap_run_verify

TXID = "ab" * 32
#: Not ``0-9``: what ``isdigit()`` or ``int()`` let through.
BAD_DIGITS = ["²", "١", "１", "1²", " 1", "1 ", "+1", "-1", "1_0", "", "1.0", "0x1"]
#: More digits than a uint32 vout can hold, but each one ASCII.
TOO_BIG_VOUT = ["4294967296", "99999999999"]


class _Client:
    """Enough of an ElectrumX client for RadiantChainIO; records the reads it is asked for."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def broadcast(self, raw):  # pragma: no cover - not reached
        raise AssertionError

    async def get_transaction_verbose(self, txid):  # pragma: no cover - not reached
        raise AssertionError

    async def get_utxos(self, script_hash):  # pragma: no cover - not reached
        raise AssertionError

    async def txout_unspent_incl_mempool(self, txid, vout):
        self.calls.append(("txout", txid, vout))
        return True

    # The proof reads funding_evidence needs; a refusal must come before any of them.
    async def get_transaction(self, txid):
        self.calls.append(("tx", txid))
        raise RuntimeError("stop here: the outpoint was accepted")

    async def get_transaction_merkle_branch(self, txid, height):  # pragma: no cover
        raise AssertionError

    async def get_transaction_id_from_pos(self, height, pos):  # pragma: no cover
        raise AssertionError

    async def get_block_headers(self, start, count):  # pragma: no cover
        raise AssertionError


@pytest.mark.parametrize("vout", BAD_DIGITS + TOO_BIG_VOUT)
def test_the_makers_btc_counterparty_outpoint_parser_refuses_a_vout_that_is_not_ascii_decimal(vout: str) -> None:
    """The one untrusted input on the maker's BTC gate (``verify_counterparty_funded``) — missed by
    the first sweep (panel finding): bare ``int()`` took ``"١"``, ``"１"``, ``" 1"``, ``"+1"``, ``"1_0"``."""
    from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg

    with pytest.raises(ValidationError):
        BitcoinTaprootLeg._counterparty_outpoint(f"{TXID}:{vout}")


def test_the_makers_btc_counterparty_outpoint_parser_accepts_an_ascii_vout() -> None:
    from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg

    for vout in (0, 1, 4294967295):
        assert BitcoinTaprootLeg._counterparty_outpoint(f"{TXID}:{vout}").vout == vout


async def test_the_makers_btc_gate_refuses_a_non_ascii_vout_before_any_read() -> None:
    """Through the production entry point: the refusal comes before the node is asked anything."""
    from tests.test_btc_htlc_leg import _verify_leg

    leg, terms, reader = _verify_leg()
    asked = []
    real = reader.read_confirmed_unspent_output

    async def spy(txid, vout):
        asked.append((txid, vout))
        return await real(txid, vout)

    reader.read_confirmed_unspent_output = spy
    with pytest.raises(ValidationError, match="ASCII decimal"):
        await leg.verify_counterparty_funded(f"{'cd' * 32}:١", terms)
    assert asked == []
    assert (await leg.verify_counterparty_funded(f"{'cd' * 32}:1", terms)).funding_outpoint.vout == 1
    assert asked == [("cd" * 32, 1)]  # non-vacuity: the honest one does reach the node


@pytest.mark.parametrize("vout", BAD_DIGITS + TOO_BIG_VOUT)
async def test_radiant_leg_refuses_a_vout_that_is_not_ascii_decimal(vout: str) -> None:
    client = _Client()
    io = RadiantChainIO(client)
    with pytest.raises(ValidationError, match="bad covenant outpoint"):
        await io.covenant_unspent_incl_mempool(f"{TXID}:{vout}")
    with pytest.raises(ValidationError, match="bad covenant outpoint"):
        await io.funding_evidence(f"{TXID}:{vout}", 100, header_ranges=())
    assert client.calls == [], "a refused outpoint must not reach the client"


@pytest.mark.parametrize("vout", ["0", "7", "4294967295"])
async def test_radiant_leg_accepts_an_ascii_vout(vout: str) -> None:
    client = _Client()
    io = RadiantChainIO(client)
    assert await io.covenant_unspent_incl_mempool(f"{TXID}:{vout}") is True
    with pytest.raises(Exception, match="stop here"):
        await io.funding_evidence(f"{TXID}:{vout}", 100, header_ranges=())
    assert client.calls == [("txout", TXID, int(vout)), ("tx", TXID)]


@pytest.mark.parametrize("vout", BAD_DIGITS + TOO_BIG_VOUT)
def test_swap_run_verify_refuses_a_vout_that_is_not_ascii_decimal(vout: str) -> None:
    with pytest.raises(ValueError, match="bad outpoint"):
        swap_run_verify.Outpoint.parse(f"{TXID}:{vout}")


def test_swap_run_verify_accepts_an_ascii_vout() -> None:
    assert swap_run_verify.Outpoint.parse(f"{TXID}:3") == swap_run_verify.Outpoint(TXID, 3)


@pytest.mark.parametrize("vout", BAD_DIGITS + TOO_BIG_VOUT)
def test_the_cli_outpoint_parsers_refuse_a_vout_that_is_not_ascii_decimal(vout: str) -> None:
    # Too large for a uint32: refused by the digit bound or by BtcOutpoint, in their own words.
    with pytest.raises(ValidationError, match="32 bits|vout must be an integer"):
        recovery_parse_outpoint(f"{TXID}:{vout}")
    with pytest.raises(UserError):
        book_parse_outpoint(f"{TXID}:{vout}")


def test_the_cli_outpoint_parsers_accept_an_ascii_vout() -> None:
    assert recovery_parse_outpoint(f"{TXID}:2").vout == 2
    assert book_parse_outpoint(f"{TXID}:2") == (TXID, 2)


@pytest.mark.parametrize("amount", [d for d in BAD_DIGITS if d not in (" 1", "1 ")] + ["١٠٠٠"])
def test_the_photon_amount_parser_refuses_non_ascii_digits(amount: str) -> None:
    """Surrounding whitespace is stripped by design, so " 1" is not in this list."""
    with pytest.raises(argparse.ArgumentTypeError):
        _dust_swap_shared.parse_positive_photons(amount)


def test_the_photon_amount_parser_accepts_ascii_digits() -> None:
    assert _dust_swap_shared.parse_positive_photons("1000") == 1000
    assert _dust_swap_shared.parse_positive_photons(" 1000 ") == 1000  # stripped, as before


def _private_link_scanner():
    spec = importlib.util.spec_from_file_location(
        "check_no_private_links_digits", _ROOT / "scripts" / "check-no-private-links.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # its dataclasses look their module up while being defined
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("ip", ["8.8.8.8²", "8.8.8.١", "８.8.8.8"])
def test_the_leak_scanner_does_not_crash_or_match_on_non_ascii_digits(ip: str) -> None:
    scanner = _private_link_scanner()
    assert scanner._is_routable(ip) is False
    assert scanner._is_routable("8.8.8.8") is True  # the honest pair


# --------------------------------------------------------------------------- the set that remains

#: Every ``.isdigit()`` call left in shipped code, and why it is not a parse. Pinned by membership:
#: a new call fails this test until someone decides it is not a parse either.
_ISDIGIT_ALLOWED = {
    # `value.isascii() and value.isdigit()`: on an ASCII string isdigit() is exactly 0-9.
    "src/pyrxd/glyph/wave.py",
    "src/pyrxd/glyph/_inspect_core.py",
    # A heuristic ("does this URL path segment contain a digit?") deciding what to REDACT; a
    # non-ASCII digit can only make it redact more.
    "src/pyrxd/network/redaction.py",
}


def _isdigit_calls() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for base in ("src", "scripts"):
        for path in sorted((_ROOT / base).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            lines = [
                n.lineno
                for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "isdigit"
            ]
            if lines:
                found[path.relative_to(_ROOT).as_posix()] = lines
    return found


def test_every_remaining_isdigit_call_is_one_that_was_decided() -> None:
    found = _isdigit_calls()
    assert found, "the scan found no isdigit() call at all — it is not reading the tree"
    assert set(found) == _ISDIGIT_ALLOWED, (
        f"isdigit() calls in shipped code: {found}. A digit PARSE must use re.fullmatch(r'[0-9]+', ...) "
        "(see this module's docstring); if this one is not a parse, add it to _ISDIGIT_ALLOWED with why."
    )
    for rel in ("src/pyrxd/glyph/wave.py", "src/pyrxd/glyph/_inspect_core.py"):
        text = (_ROOT / rel).read_text(encoding="utf-8").splitlines()
        for line in found[rel]:
            assert "isascii()" in text[line - 1], f"{rel}:{line} relies on an isascii() guard that is gone"
