"""A WAVE name's owner publishes an update whose ``attrs.target`` is not an address.

``--wave-name`` answers "what did this name point at when the mark was made". The answer is
folded from update envelopes the name's owner publishes, and the fold preserves values rather
than stringifying them, so ``target`` can be any CBOR value. Before this, a target that was a
40,000-bit integer, or a list that contains itself, crashed both surfaces that ask the question —
``pyrxd glyph inspect --fetch --wave-name`` and ``pyrxd verify --wave-name`` — with
``ValueError`` (the int-to-text digit limit) or ``Circular reference detected``. The name-at-mark
block is attached AFTER ``_render_safe`` bounds the inspect payload, so the payload bound never
saw it.

Fixed at the source rather than per renderer: the judge degrades to form 1, naming the type,
unless ``target`` is text; the decoder refuses a shared or cyclic value outright.

THE HOSTILE UPDATES ARE DERIVED FROM REAL BYTES. Each is the real mainnet ``UPDATE_B``
transaction with its envelope re-encoded around a different target and its mutable output's
``payload_hash`` recomputed, so the covenant binding the walker checks still holds. Only the
transport is faked, exactly as ``tests/test_name_at_mark_reaches_the_cli.py`` does it.
"""

from __future__ import annotations

import hashlib
import json

import cbor2
import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_inspect
from pyrxd.cli.context import CliContext
from pyrxd.cli.hashmark_cmds import EXIT_VERDICT_DOES_NOT_HOLD
from pyrxd.cli.main import cli
from pyrxd.constants import genesis_hash_for
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.hash import hash256
from pyrxd.hashmark_tx import plan_hashmark
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from tests.test_mutable_chain_is_discovered_from_the_chain import RAW, UPDATE_B
from tests.test_name_at_mark_reaches_the_cli import NAME, _Server

_CONTENT = b"a document the signer marked\n"
_MARK_HEIGHT = 460_000
#: Nine bytes: a list that contains itself twice (CBOR value-sharing tags 28/29).
_CYCLIC_TARGET_CBOR = bytes([0xD8, 0x1C, 0x82, 0xD8, 0x1D, 0x00, 0xD8, 0x1D, 0x00])


def _push(blob: bytes) -> bytes:
    if len(blob) < 0x4C:
        return bytes([len(blob)]) + blob
    if len(blob) <= 0xFF:
        return b"\x4c" + bytes([len(blob)]) + blob
    return b"\x4d" + len(blob).to_bytes(2, "little") + blob


def _update_b_with_target(target_cbor: bytes) -> tuple[str, bytes]:
    """The real UPDATE_B, its envelope's ``attrs.target`` replaced by *target_cbor* (raw CBOR)."""
    tx = Transaction.from_hex(RAW[UPDATE_B])
    inspector = GlyphInspector()
    for inp in tx.inputs:
        scriptsig = bytes(inp.unlocking_script.serialize())
        items, _ = inspector._walk_pushes(scriptsig)
        for i, item in enumerate(items):
            if item != b"gly" or i + 1 >= len(items):
                continue
            old = items[i + 1]
            envelope = cbor2.loads(old)
            assert "p" not in envelope and "target" in envelope["attrs"], "fixture: expected a WAVE update"
            # Re-encode with `target` as a placeholder, then splice the raw target bytes in, so a
            # value cbor2 would not emit from a Python object (a self-containing list) can be used.
            envelope["attrs"]["target"] = "\x00TARGET\x00"
            placeholder = cbor2.dumps("\x00TARGET\x00")
            encoded = cbor2.dumps(envelope)
            assert encoded.count(placeholder) == 1
            new = encoded.replace(placeholder, target_cbor)
            pos = scriptsig.index(_push(old))
            inp.unlocking_script = Script(scriptsig[:pos] + _push(new) + scriptsig[pos + len(_push(old)) :])
            for out in tx.outputs:
                spk = bytes(out.locking_script.serialize())
                if len(spk) > 33 and spk[0] == 0x20 and spk[1:33] == hash256(old):
                    out.locking_script = Script(b"\x20" + hash256(new) + spk[33:])
                    break
            else:  # pragma: no cover - fixture shape
                raise AssertionError("no mutable output commits to the envelope")
            raw = bytes(tx.serialize())
            return Transaction.from_hex(raw).txid(), raw
    raise AssertionError("no envelope found")  # pragma: no cover - fixture shape


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path, target_cbor: bytes, *, command: str, json_mode: bool):
    """Run `glyph inspect --fetch --wave-name` or `verify --wave-name` against a real signed mark."""
    key = PrivateKey()
    signer = key.public_key().address()
    update_txid, update_raw = _update_b_with_target(target_cbor(signer) if callable(target_cbor) else target_cbor)
    mark_script = plan_hashmark(
        hashlib.sha256(_CONTENT).digest(), key, label="doc", network_genesis=genesis_hash_for("mainnet")
    ).op_return_script
    mark_tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(mark_script), 0)])
    spend = TransactionInput(source_txid="ab" * 32, source_output_index=0)
    spend.unlocking_script = Script(b"\x00")
    mark_tx.inputs = [spend]
    mark_txid, mark_raw = mark_tx.txid(), bytes(mark_tx.serialize())

    extra = {update_txid: (update_raw, 458601), mark_txid: (mark_raw, _MARK_HEIGHT)}
    heights = {mark_txid: _MARK_HEIGHT}
    a = _Server(indexer=False, hide=frozenset({UPDATE_B}), extra=extra, mark_heights=heights)
    b = _Server(indexer=True, hide=frozenset({UPDATE_B}), extra=extra, mark_heights=heights)
    monkeypatch.setattr(CliContext, "make_client", lambda self: a)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, "wss://a", b, "wss://b"))

    args = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    args += ["--json"] if json_mode else []
    if command == "inspect":
        args += ["glyph", "inspect", mark_txid, "--fetch"]
    else:
        args += ["verify", mark_txid, "--digest", hashlib.sha256(_CONTENT).hexdigest()]
    args += ["--wave-name", NAME, "--min-confirmations", "6"]
    return CliRunner().invoke(cli, args), signer


def _name_at_mark(output: str) -> dict:
    payload = json.loads(output)
    found = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "name_at_mark" in node:
                found.append(node["name_at_mark"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(payload)
    assert len(found) == 1, payload
    return found[0]


_HOSTILE = {
    "bignum": (cbor2.dumps(2**40_000), "not text (it is int)"),
    "cyclic": (_CYCLIC_TARGET_CBOR, "value-sharing"),
    "map": (cbor2.dumps({"address": "not a string target"}), "not text (it is dict)"),
}


@pytest.mark.parametrize("case", sorted(_HOSTILE))
@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_glyph_inspect_degrades_with_the_reason(monkeypatch, tmp_path, case, json_mode) -> None:
    target_cbor, reason = _HOSTILE[case]
    result, _ = _run(monkeypatch, tmp_path, target_cbor, command="inspect", json_mode=json_mode)
    assert result.exit_code == 0, (result.output[-2000:], repr(result.exception))
    if json_mode:
        nam = _name_at_mark(result.output)
        assert nam["form"] == 1 and nam["target_at_height"] is None
        assert reason in (nam.get("degraded_reason") or ""), nam
    else:
        assert "not established" in result.output and reason in result.output


@pytest.mark.parametrize("case", sorted(_HOSTILE))
@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_verify_degrades_with_the_reason(monkeypatch, tmp_path, case, json_mode) -> None:
    target_cbor, reason = _HOSTILE[case]
    result, _ = _run(monkeypatch, tmp_path, target_cbor, command="verify", json_mode=json_mode)
    # "The verdict does not hold" — the defined answer when the name is not established — and
    # NOT the generic failure a traceback produces.
    assert result.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, (result.output[-2000:], repr(result.exception))
    assert reason in result.output


@pytest.mark.parametrize("command", ["inspect", "verify"])
def test_an_honest_target_that_is_the_signer_still_establishes_form_2(monkeypatch, tmp_path, command) -> None:
    """The honest path through the same derived transaction: a text target equal to the signing
    key's address is form 2, and `verify` holds."""
    result, signer = _run(monkeypatch, tmp_path, lambda address: cbor2.dumps(address), command=command, json_mode=True)
    if command == "verify":
        assert result.exit_code == 0, (result.output[-2000:], repr(result.exception))
    else:
        assert result.exit_code == 0, (result.output[-2000:], repr(result.exception))
        nam = _name_at_mark(result.output)
        assert nam["form"] == 2 and nam["target_at_height"] == signer and nam["signer_is_target_at_height"] is True
