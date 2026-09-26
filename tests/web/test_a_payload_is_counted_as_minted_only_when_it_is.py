"""The CLI and the page count the glyphs a transaction MINTS from its outputs, and agree.

#743 round 2 (lane C, case G): a transaction whose input 0 carries a decoy envelope on a commit
that mints nothing (``OP_REFTYPE_OUTPUT OP_0``), and whose input 1 is a real mint. A node accepts
it and exactly one glyph is minted. Both surfaces said "1 of 2 glyphs minted here" and "Other
glyphs minted in this transaction (1)", with the decoy "Tether USD" as the headline — because
"minted" was counted from the envelopes.

Now the classifier marks each payload with whether the outputs create a ref from its input's
outpoint (``mints``), counts those (``of_n_minted``), and prefers a minting payload as the
headline. This file checks the two renderers word the result the same way, on case G, on the
mainnet GLYPH deploy reveal (both of its payloads mint: nothing may change there), and on the
mainnet DAT reveal (its one payload mints nothing).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"
_FIXTURES = _REPO_ROOT / "tests" / "fixtures"
_SIG = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33


def _page(payload: dict) -> str:
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


def _cli(payload: dict) -> str:
    from pyrxd.cli.glyph_inspect import _render_txid_human

    return _render_txid_human(payload)


def _classify(txid: str, raw: bytes) -> dict:
    from pyrxd.glyph._inspect_core import _classify_raw_tx

    return _classify_raw_tx(txid, raw)


def _case_g() -> tuple[str, bytes]:
    """Input 0: a decoy envelope on a commit with operand OP_0 (mints nothing). Input 1: a real
    NFT commit's envelope. One output: the singleton for input 1's outpoint."""
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.script import build_nft_locking_script
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
    from pyrxd.script.script import Script
    from pyrxd.security.types import Hex20
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    def suffix(name: str) -> bytes:
        cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
        return build_reveal_scriptsig_suffix(cbor)

    decoy_prev, real_prev = os.urandom(32).hex(), os.urandom(32).hex()
    inputs = []
    for prev, name in ((decoy_prev, "Tether USD"), (real_prev, "RealToken")):
        inp = TransactionInput(source_txid=prev, source_output_index=0)
        inp.unlocking_script = Script(_SIG + suffix(name))
        inputs.append(inp)
    minted = build_nft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=real_prev, vout=0))
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(minted), 1)])
    tx.inputs = inputs
    return tx.txid(), tx.serialize()


def _mainnet(name: str, key: str | None = None) -> tuple[str, bytes]:
    doc = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    entry = doc[key] if key else doc
    return entry["txid"], bytes.fromhex(entry["raw"])


@pytest.fixture(scope="module")
def payload() -> dict:
    """Case G, classified once."""
    payload = _classify(*_case_g())
    assert (payload["metadata"]["of_n_payloads"], payload["metadata"]["of_n_minted"]) == (2, 1)
    return payload


class TestCaseG:
    """One glyph minted, two payloads: both surfaces say so, and neither heads with the decoy."""

    def test_the_headline_is_the_glyph_minted(self, payload) -> None:
        assert (payload["metadata"]["input_index"], payload["metadata"]["name"]) == (1, "RealToken")

    @pytest.mark.parametrize("surface", ["cli", "page"])
    def test_neither_surface_counts_the_decoy_as_minted(self, payload, surface) -> None:
        text = _cli(payload) if surface == "cli" else _page(payload)
        assert "Reveal metadata (from input 1 — 1 of 2 payloads here, 1 minting a token" in text
        assert "glyphs minted here" not in text and "Other glyphs minted" not in text
        assert "Other payloads in this transaction (1), 0 minting a token" in text
        assert "Tether USD" in text and "mints no token" in text

    def test_the_two_surfaces_say_the_same_sentences(self, payload) -> None:
        """Not only each against a literal: the CLI's lines, stripped of its layout, are the
        page's lines for the same facts."""
        cli, page = _cli(payload), _page(payload)
        for sentence in ("1 of 2 payloads here, 1 minting a token", "Other payloads in this transaction (1)"):
            assert sentence in cli and sentence in page, sentence


class TestTheHonestNeighbours:
    @pytest.mark.parametrize("surface", ["cli", "page"])
    def test_the_mainnet_deploy_still_reads_two_glyphs_minted(self, surface) -> None:
        """Both of its payloads mint (input 0 at the 32 dMint contracts, input 33 at output 32), so
        the wording a real two-glyph reveal had before this change must survive it."""
        payload = _classify(*_mainnet("glyph_deploy_reveal_mainnet.json"))
        assert (payload["metadata"]["of_n_payloads"], payload["metadata"]["of_n_minted"]) == (2, 2)
        assert payload["metadata"]["input_index"] == 0 and payload["metadata"]["mints"] is True
        text = _cli(payload) if surface == "cli" else _page(payload)
        assert "1 of 2 glyphs minted here" in text
        assert "Other glyphs minted in this transaction (1)" in text
        assert "mints no token" not in text

    @pytest.mark.parametrize("surface", ["cli", "page"])
    def test_the_mainnet_dat_reveal_says_its_payload_mints_nothing(self, surface) -> None:
        """One payload, no token: no count, and the headline says it mints nothing — which for a
        DAT is simply true."""
        payload = _classify(*_mainnet("dat_65_byte_commit_mainnet.json", "reveal"))
        assert "of_n_payloads" not in payload["metadata"] and payload["metadata"]["mints"] is False
        text = _cli(payload) if surface == "cli" else _page(payload)
        assert "none — this input mints no token here" in text
        assert "glyphs minted" not in text
