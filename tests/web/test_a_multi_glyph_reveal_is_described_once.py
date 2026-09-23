"""An input whose payload IS read is not also reported as a payload nobody read.

A multi-glyph reveal carries one payload per minted glyph. ``_classify_raw_tx`` lists every one the
reveal reader (``extract_reveal_metadata``) reads — the headline in ``metadata``, the rest in
``metadata_inputs`` — and separately reports, in ``glyph_envelopes``, a ``payload_unrendered``
entry for an input where the envelope classifier sees a full payload that the reveal reader did
NOT return: the two readers disagreeing about the same bytes.

That report skipped only the HEADLINE input. Every other payload was reported as unrendered too,
with the words "the reveal reader did not return — the two readers disagree about these bytes",
while the same input was drawn a few lines above as an other glyph the reader had read. Measured
on the real mainnet GLYPH deploy reveal (``tests/fixtures/glyph_deploy_reveal_mainnet.json``):
"Other glyphs minted (1) | input 33 | nft" and then "Glyph envelopes carrying no full payload (1) |
input 33 | payload_unrendered", in the CLI's output and on the page.

The report is now skipped for every input the reveal reader read. It still fires when the readers
really disagree; no byte string is known today on which they do (``payload_unrendered`` was added
with the change that gave both readers one push walker), so that honest path is exercised by
making the reveal reader decline one input.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "glyph_deploy_reveal_mainnet.json"
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"
_GLUE = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"

_UNRENDERED_WORDS = "the reveal reader did not return"


def _reveal() -> tuple[str, bytes]:
    from pyrxd.hash import hash256

    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["raw"])
    assert hash256(raw)[::-1].hex() == fixture["txid"], "the fixture's bytes are not the transaction it names"
    return fixture["txid"], raw


def _glue():
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_multi_glyph", _GLUE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_multi_glyph"] = module
    spec.loader.exec_module(module)
    return module


def _card(payload: dict) -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the page half is UNGUARDED")
        pytest.fail("node is required to drive inspect.js (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [node, str(_HARNESS), "-"],
        input=json.dumps({"case": {"tx": payload}}),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"render harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)["case"]["fetched_tx_card"]


@pytest.fixture
def transport(monkeypatch):
    """A real ``ElectrumXClient`` answering from a table: only ``_call`` and the socket are fake.
    Same shape as ``tests/cli/test_glyph_inspect_spent_binding.py``."""
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.security.errors import NetworkError

    table: dict[str, str] = {}

    async def _call(self, method, params):
        assert method == "blockchain.transaction.get", method
        if params[0] not in table:
            raise NetworkError("ElectrumX RPC error: No such mempool or blockchain transaction")
        return table[params[0]]

    async def _nothing(self, *a, **kw):
        return None

    monkeypatch.setattr(ElectrumXClient, "_call", _call)
    monkeypatch.setattr(ElectrumXClient, "_ensure_connected", _nothing)
    monkeypatch.setattr(ElectrumXClient, "close", _nothing)
    return table


def _cli(txid: str, tmp_path, monkeypatch, *, as_json: bool) -> str:
    from pyrxd.cli.context import CliContext
    from pyrxd.cli.main import cli
    from pyrxd.network.electrumx import ElectrumXClient

    monkeypatch.setattr(CliContext, "make_client", lambda self: ElectrumXClient(["wss://electrumx.invalid:50022"]))
    args = ["--wallet", str(tmp_path / "w"), "--config", str(tmp_path / "c.toml")]
    args += (["--json"] if as_json else []) + ["glyph", "inspect", txid, "--fetch"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    return result.output


# ────────────────────────────── the real reveal: one input, described once ──


class TestTheMainnetGlyphDeployReveal:
    def test_the_fixture_is_the_multi_glyph_reveal_it_claims_to_be(self) -> None:
        """The premise, checked rather than assumed: BOTH readers read input 33."""
        from pyrxd.glyph.inspector import GlyphInspector
        from pyrxd.transaction.transaction import Transaction

        _txid, raw = _reveal()
        tx = Transaction.from_hex(raw)
        reader = GlyphInspector()
        ss = bytes(tx.inputs[33].unlocking_script.serialize())
        assert reader.classify_glyph_scriptsig(ss).kind == "payload"
        assert reader.extract_reveal_metadata(ss) is not None

    def test_the_classifier_lists_input_33_as_a_glyph_and_not_as_unrendered(self) -> None:
        from pyrxd.glyph._inspect_core import _classify_raw_tx

        txid, raw = _reveal()
        payload = _classify_raw_tx(txid, raw)
        assert payload["metadata"]["input_index"] == 0 and payload["metadata"]["of_n_payloads"] == 2
        assert [row["input_index"] for row in payload["metadata_inputs"]] == [0, 33]
        assert payload["glyph_envelopes"] == [], payload["glyph_envelopes"]

    def test_the_cli_json_says_it_once(self, transport, tmp_path, monkeypatch) -> None:
        txid, raw = _reveal()
        transport[txid] = raw.hex()
        out = json.loads(_cli(txid, tmp_path, monkeypatch, as_json=True))
        payload = out.get("payload", out)
        assert [row["input_index"] for row in payload["metadata_inputs"]] == [0, 33]
        assert payload["glyph_envelopes"] == []
        assert "payload_unrendered" not in json.dumps(out)

    def test_the_cli_human_output_says_it_once(self, transport, tmp_path, monkeypatch) -> None:
        txid, raw = _reveal()
        transport[txid] = raw.hex()
        out = _cli(txid, tmp_path, monkeypatch, as_json=False)
        assert "Other glyphs minted in this transaction (1):" in out
        assert "  input  33: nft" in out
        assert "Glyph envelopes carrying no full payload" not in out
        assert _UNRENDERED_WORDS not in out

    def test_the_page_says_it_once(self) -> None:
        txid, raw = _reveal()
        result = _glue().inspect_txid_with_raw(txid, raw.hex(), 100, 100)
        assert result["ok"], result
        text = _card(result["payload"])
        assert "Other glyphs minted in this transaction (1)" in text
        assert "input 33" in text
        assert "Glyph envelopes carrying no full payload" not in text
        assert "payload_unrendered" not in text and _UNRENDERED_WORDS not in text


# ─────────────────────── the honest path: readers that DO disagree are still reported ──


def _two_glyph_reveal():
    """A reveal whose inputs 0 and 1 each carry a full payload, both readable."""
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    sig = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33
    scriptsigs = []
    for name in ("Head", "Declined"):
        cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
        scriptsigs.append(sig + build_reveal_scriptsig_suffix(cbor))
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(b"\x6a"), 0)])
    tx.inputs = [
        TransactionInput(source_txid=f"{i:064x}", source_output_index=0, unlocking_script=Script(ss))
        for i, ss in enumerate(scriptsigs)
    ]
    return tx, scriptsigs[1]


@pytest.fixture
def the_reveal_reader_declines(monkeypatch):
    """Make ``extract_reveal_metadata`` decline input 1 while the envelope classifier still reads a
    payload there — the drift ``payload_unrendered`` exists to report. Only the reveal reader is
    patched; the classifier, the envelope reader and both renderers run as shipped."""
    from pyrxd.glyph.inspector import GlyphInspector

    tx, declined = _two_glyph_reveal()
    real = GlyphInspector.extract_reveal_metadata

    def declining(self, scriptsig):
        return None if bytes(scriptsig) == declined else real(self, scriptsig)

    monkeypatch.setattr(GlyphInspector, "extract_reveal_metadata", declining)
    return tx


class TestReadersThatReallyDisagreeAreStillReported:
    def test_without_the_patch_the_fixture_is_two_read_glyphs(self) -> None:
        """The control: unpatched, input 1 is read and so is NOT reported."""
        from pyrxd.glyph._inspect_core import _classify_raw_tx

        tx, _ = _two_glyph_reveal()
        payload = _classify_raw_tx(tx.txid(), tx.serialize())
        assert [row["input_index"] for row in payload["metadata_inputs"]] == [0, 1]
        assert payload["glyph_envelopes"] == []

    def test_the_classifier_reports_the_disagreement(self, the_reveal_reader_declines) -> None:
        from pyrxd.glyph._inspect_core import _classify_raw_tx

        tx = the_reveal_reader_declines
        payload = _classify_raw_tx(tx.txid(), tx.serialize())
        assert [row["input_index"] for row in payload["metadata_inputs"]] == [0]
        assert [(env["input_index"], env["kind"]) for env in payload["glyph_envelopes"]] == [(1, "payload_unrendered")]
        assert _UNRENDERED_WORDS in payload["glyph_envelopes"][0]["reason"]

    def test_the_cli_prints_it(self, the_reveal_reader_declines, transport, tmp_path, monkeypatch) -> None:
        tx = the_reveal_reader_declines
        transport[tx.txid()] = tx.serialize().hex()
        out = _cli(tx.txid(), tmp_path, monkeypatch, as_json=False)
        assert "Glyph envelopes carrying no full payload (1):" in out
        assert "  input   1: PAYLOAD the reveal reader did not return" in out
        assert "Other glyphs minted in this transaction" not in out

    def test_the_page_draws_it(self, the_reveal_reader_declines) -> None:
        tx = the_reveal_reader_declines
        result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), 100, 100)
        assert result["ok"], result
        text = _card(result["payload"])
        assert "Glyph envelopes carrying no full payload (1)" in text
        assert "payload_unrendered — PAYLOAD the reveal reader did not return" in text
        assert "The two glyph readers disagree about these bytes" in text
