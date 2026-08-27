"""UtxoRecord.height carries ONE unit — a block height — and every producer is held to it.

Written after it did not. ``UtxoRecord.height`` is documented as "block height at which the
output was confirmed (0 = unconfirmed)", and every consumer reads it that way — including
``RadiantChainIO.find_covenant_utxo``, which resolves a multi-funded covenant SPK by taking
the EARLIEST-confirmED match (min height), because the honest funding necessarily precedes
any poison. But ``SshTrRadiantClient.get_utxos`` — the ssh-tr shim that is the ONLY mainnet
RXD transport, i.e. the one real-value runs use — stored a CONFIRMATION COUNT in the field.

Both units are non-negative ints, so nothing type-checked wrong, and ``height == 0`` means
"unconfirmed" under BOTH readings, so even the unconfirmed guard agreed. But the two units
order OPPOSITELY: ascending height is oldest-first, ascending confs is NEWEST-first. Same
code, same on-chain facts, and the anti-poisoning rule selected the honest funding under
ElectrumX and the attacker's poison under the shim.

Two layers here:

1. **Producer units conformance** — each producer of ``UtxoRecord`` is driven through its
   real code (transport mocked at the subprocess/wire boundary, nothing else faked) with a
   fixture where the block height and the confirmation count DIFFER by orders of magnitude,
   because equal values are exactly what hid this conflation. The produced ``height`` must
   be the block height.

2. **Producer registry (the class-level guard)** — an AST walk over ``src/`` and
   ``scripts/`` finds every construction site of ``UtxoRecord`` in shipped code and requires
   it to be registered here. A new producer fails this test until it is added to the
   registry — and the registry's docstring demands a units test like the ones above for it.
   The walk sees code, not text: comments, docstrings and grep-bait cannot satisfy or
   confuse it.
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.network.electrumx import ElectrumXClient

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts"))

from radiant_mainnet_chainio import SshTrRadiantClient

# ---------------------------------------------------------------------------------------
# Layer 2: the producer registry. EVERY construction of UtxoRecord in shipped code
# (src/ + scripts/) must appear here, and each entry must have a units-conformance test in
# THIS file proving the real code path stores a BLOCK HEIGHT (0 = unconfirmed) in
# ``height`` — never a confirmation count, never anything derived from the current tip.
# ---------------------------------------------------------------------------------------
_REGISTERED_PRODUCERS: frozenset[tuple[str, str]] = frozenset(
    {
        # tested by test_electrumx_client_reports_the_servers_block_height_unchanged
        ("src/pyrxd/network/electrumx.py", "ElectrumXClient.get_utxos"),
        # tested by test_sshtr_shim_reports_the_block_height_not_the_confirmation_count
        ("scripts/radiant_mainnet_chainio.py", "SshTrRadiantClient.get_utxos"),
    }
)

_RECORD_NAME = "UtxoRecord"


def _construction_sites_in(path: Path) -> set[str]:
    """Enclosing qualnames of every UtxoRecord construction in one module.

    Resolves ``from ... import UtxoRecord as X`` aliases and matches attribute
    constructions (``electrumx.UtxoRecord(...)``) too, so renaming the import does not
    smuggle a producer past the registry.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    aliases = {_RECORD_NAME}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == _RECORD_NAME and alias.asname:
                    aliases.add(alias.asname)
    qualnames: set[str] = set()
    scope: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def _scoped(self, node) -> None:
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        visit_ClassDef = _scoped
        visit_FunctionDef = _scoped
        visit_AsyncFunctionDef = _scoped

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            is_ctor = (isinstance(func, ast.Name) and func.id in aliases) or (
                isinstance(func, ast.Attribute) and func.attr == _RECORD_NAME
            )
            if is_ctor:
                qualnames.add(".".join(scope) or "<module>")
            self.generic_visit(node)

    _Visitor().visit(tree)
    return qualnames


def _utxo_record_construction_sites() -> set[tuple[str, str]]:
    """Every ``(relpath, enclosing qualname)`` in src/+scripts/ that constructs UtxoRecord."""
    sites: set[tuple[str, str]] = set()
    for base in ("src", "scripts"):
        for path in sorted((_REPO / base).rglob("*.py")):
            rel = path.relative_to(_REPO).as_posix()
            sites.update((rel, qualname) for qualname in _construction_sites_in(path))
    return sites


def test_every_utxo_record_producer_is_registered_and_units_tested() -> None:
    """The class-level guard: a shared type only stays one unit if no producer can join quietly.

    If this fails on a site you just added: the field you are populating is a BLOCK HEIGHT
    (0 = unconfirmed), NOT a confirmation count — the two sort in opposite directions and
    ``find_covenant_utxo``'s anti-poisoning rule inverts under the wrong one. Add a units
    test in this file that drives your real producer with height != confs and asserts the
    height comes through, then register the site in ``_REGISTERED_PRODUCERS``.
    """
    found = _utxo_record_construction_sites()
    unregistered = found - _REGISTERED_PRODUCERS
    vanished = _REGISTERED_PRODUCERS - found
    assert not unregistered, f"unregistered UtxoRecord producer(s) {sorted(unregistered)} — see this test's docstring"
    assert not vanished, (
        f"registered UtxoRecord producer(s) {sorted(vanished)} no longer construct the record; "
        "update the registry AND move/retire their units tests"
    )


def test_the_registry_scanner_actually_sees_the_known_producers() -> None:
    """Honest-path check on the guard itself: an AST scanner that silently finds nothing
    would 'pass' forever. Both shipped producers must be visible to it."""
    found = _utxo_record_construction_sites()
    assert ("src/pyrxd/network/electrumx.py", "ElectrumXClient.get_utxos") in found
    assert ("scripts/radiant_mainnet_chainio.py", "SshTrRadiantClient.get_utxos") in found


# ---------------------------------------------------------------------------------------
# Layer 1: units conformance, per producer. Fixtures deliberately put the block height and
# the confirmation count ORDERS OF MAGNITUDE apart — equal values are how this bug hid.
# ---------------------------------------------------------------------------------------

_SPK = bytes.fromhex("76a914" + "11" * 20 + "88ac")
_SCRIPT_HASH = hashlib.sha256(_SPK).digest()[::-1]

# tip 810_000, funded at 700_000 -> 110_001 confirmations. If the shim ever goes back to
# storing confs, height reads 110_001 and the assertions below say which unit it stored.
_TIP = 810_000
_FUND_HEIGHT = 700_000


def _scripted_shim(responses: dict[str, object]) -> SshTrRadiantClient:
    """A REAL SshTrRadiantClient with only the ssh subprocess boundary replaced.

    Everything from get_utxos down — SPK registry, scantxoutset descriptor handling,
    UtxoRecord construction — is the shipped code. ``getblockcount`` stays scripted even
    though the fixed code never asks for it: a regression back to confs-arithmetic must
    fail on the UNIT ASSERTION below, not on a missing mock.
    """
    client = SshTrRadiantClient()

    def _fake_run_sync(*cli_args: str) -> object:
        method = cli_args[0]
        if method not in responses:
            raise AssertionError(f"unexpected radiant-cli call {method!r}")
        return responses[method]

    client._run_sync = _fake_run_sync  # type: ignore[method-assign]
    return client


async def test_sshtr_shim_reports_the_block_height_not_the_confirmation_count() -> None:
    """THE regression test for the mainnet unit conflation.

    Reverting the fix in SshTrRadiantClient.get_utxos (storing ``tip - height + 1`` again)
    makes ``height`` read 110_001 here — the confirmation count — and this fails naming
    both numbers.
    """
    client = _scripted_shim(
        {
            "scantxoutset": {"unspents": [{"txid": "aa" * 32, "vout": 1, "amount": 0.001, "height": _FUND_HEIGHT}]},
            "getblockcount": _TIP,
        }
    )
    client.register_spk(_SPK)
    (record,) = await client.get_utxos(_SCRIPT_HASH)
    assert record.height == _FUND_HEIGHT, (
        f"UtxoRecord.height must be the block height ({_FUND_HEIGHT}), got {record.height} "
        f"(the confirmation count at tip {_TIP} would be {_TIP - _FUND_HEIGHT + 1})"
    )
    assert (record.tx_hash, record.tx_pos, record.value) == ("aa" * 32, 1, 100_000)


async def test_sshtr_shim_maps_a_missing_height_to_the_unconfirmed_convention() -> None:
    """0 means unconfirmed under the documented meaning; an unspent with no height field
    must land there, never on a tip-derived number."""
    client = _scripted_shim(
        {
            "scantxoutset": {"unspents": [{"txid": "bb" * 32, "vout": 0, "amount": 0.001}]},
            "getblockcount": _TIP,
        }
    )
    client.register_spk(_SPK)
    (record,) = await client.get_utxos(_SCRIPT_HASH)
    assert record.height == 0


async def test_electrumx_client_reports_the_servers_block_height_unchanged() -> None:
    """The ElectrumX producer passes ``blockchain.scripthash.listunspent``'s height through
    (that wire field IS a block height; 0 = unconfirmed) — no tip arithmetic anywhere."""
    client = ElectrumXClient(["wss://example.com"])
    listunspent = [
        {"tx_hash": "cc" * 32, "tx_pos": 0, "value": 546, "height": _FUND_HEIGHT},
        {"tx_hash": "dd" * 32, "tx_pos": 2, "value": 1_000, "height": 0},  # unconfirmed
    ]
    with patch.object(client, "_call", AsyncMock(return_value=listunspent)):
        confirmed, unconfirmed = await client.get_utxos("ab" * 32)
    assert confirmed.height == _FUND_HEIGHT
    assert unconfirmed.height == 0


# ---------------------------------------------------------------------------------------
# The consequence the units matter FOR: the anti-poisoning selection, driven end-to-end
# through the REAL mainnet transport. Under the confs bug this exact scenario selected the
# poison; tests/test_radiant_leg.py proves the same rule under ElectrumX-style fakes.
# ---------------------------------------------------------------------------------------


async def test_anti_poisoning_rule_picks_the_HONEST_funding_through_the_real_mainnet_shim() -> None:
    """Honest funding confirms at 100_000; an attacker pays the same value to the same SPK
    at 100_010. earliest-confirmed = min height = the honest one. With confs in the field
    (21 vs 11 at tip 100_020) 'min' picked the POISON — this test run against the reverted
    shim fails with the poison outpoint selected.
    """
    honest, poison = "aa" * 32, "ff" * 32
    client = _scripted_shim(
        {
            "scantxoutset": {
                "unspents": [
                    # poison listed FIRST: a "take the first returned" regression fails too
                    {"txid": poison, "vout": 0, "amount": 0.001, "height": 100_010},
                    {"txid": honest, "vout": 1, "amount": 0.001, "height": 100_000},
                ]
            },
            "getblockcount": 100_020,
        }
    )
    io = RadiantChainIO(client)  # registers the SPK itself, like the production leg
    outpoint, value, height = await io.find_covenant_utxo(_SPK, expected_value=100_000)
    assert outpoint == f"{honest}:1", f"selected {outpoint} — the attacker's later payment"
    assert value == 100_000
    assert height == 100_000, "the third tuple element is documented as a height"


async def test_single_honest_funding_resolves_through_the_real_mainnet_shim() -> None:
    """The honest path paired with the adversarial one: one funded output, no ambiguity,
    the shim + leg resolve it with its true outpoint, value and height."""
    client = _scripted_shim(
        {
            "scantxoutset": {"unspents": [{"txid": "ab" * 32, "vout": 0, "amount": 0.001, "height": _FUND_HEIGHT}]},
            "getblockcount": _TIP,
        }
    )
    io = RadiantChainIO(client)
    outpoint, value, height = await io.find_covenant_utxo(_SPK, expected_value=100_000)
    assert (outpoint, value, height) == ("ab" * 32 + ":0", 100_000, _FUND_HEIGHT)
