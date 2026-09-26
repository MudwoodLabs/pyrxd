"""A marker banner says about the outputs only what the token row says, so the two cannot disagree.

#743 round 3. On the mainnet DAT reveal ``e5c67100…be5d`` — whose outputs are P2PKH — the page's
new token row said "none — this input mints no token here", and the DAT banner on the same card
said "the locking script is an ordinary Glyph NFT singleton". The banner was older than the row:
it read the claim off the protocol marker, never off the bytes. Four sibling banners made the same
claim ("the on-chain script is an ordinary Glyph NFT").

Each marker banner now takes its only sentence about the outputs from ``metadata.mints`` — the
field the token row reads. The CLI prints no marker banner, so there is nothing there to fix;
``test_the_cli_carries_no_banner_that_could_disagree`` checks that stays true.

The WAVE banner also said pyrxd's WAVE support was "currently deferred", false by 0.25.0. It now
says what the page does with a claim — shows it, and asks no indexer — and the tests at the end
check both that wording and the claim about the page's code.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"
_INSPECT_JS = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "inspect.js"
_SIG = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33

TOKEN_ROW_NONE = "none — this input mints no token here"
BANNER_NONE = "No output of this transaction creates a token ref from the payload's input"
BANNER_SOME = "An output of this transaction creates a token ref from the payload's input"

#: A payload that reaches each marker banner, by the protocol number the banner tests for. The
#: set of banners is DERIVED from inspect.js below; this says how to reach each one.
_REACH = {
    "3": {"p": [3], "name": "data"},
    "7": {"p": [2, 7], "name": "coll"},
    "8": {"p": [2, 8], "name": "sealed"},
    "10": {"p": [2, 10], "name": "issuer"},
    "11": {"p": [2, 5, 11], "name": "abc.rxd", "attrs": {"name": "abc"}},
}
#: Banners no payload reaches, or that say nothing about the outputs — each with an executable reason.
_NOT_RENDERED = {
    "6": "BURN's banner makes no claim about a token; it says to read the output rows",
    "9": "TIMELOCK's banner is unreachable: the decoder refuses TIMELOCK without ENCRYPTED, and "
    "ENCRYPTED's banner is tested first",
}


def _banner_markers() -> set[str]:
    """Every protocol number `_detectTxShape` shows a marker banner for, read from inspect.js."""
    source = _INSPECT_JS.read_text(encoding="utf-8")
    body = source[source.index("function _detectTxShape(") :]
    body = body[: body.index("\n}\n")]
    return set(re.findall(r'protocol\.includes\("(\d+)"\)', body))


def _render(payload: dict) -> str:
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


def _payload(body: dict, *, mints: bool) -> dict:
    """A one-input reveal carrying *body*; its one output mints from that input's outpoint, or is
    P2PKH."""
    import cbor2

    from pyrxd.glyph._inspect_core import _classify_raw_tx
    from pyrxd.glyph.payload import _encode_payload_push
    from pyrxd.glyph.script import build_nft_locking_script
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.script.script import Script
    from pyrxd.security.types import Hex20
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    prev = os.urandom(32).hex()
    out = (
        build_nft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=prev, vout=0))
        if mints
        else b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac"
    )
    inp = TransactionInput(source_txid=prev, source_output_index=0)
    inp.unlocking_script = Script(_SIG + b"\x03gly" + _encode_payload_push(cbor2.dumps(body)))
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(out), 1)])
    tx.inputs = [inp]
    payload = _classify_raw_tx(tx.txid(), tx.serialize())
    assert payload["metadata"] is not None and payload["metadata"]["mints"] is mints, "the premise"
    return payload


def _agrees(text: str, *, mints: bool) -> None:
    assert (TOKEN_ROW_NONE in text) is (not mints), text
    assert (BANNER_NONE in text) is (not mints) and (BANNER_SOME in text) is mints, text
    assert "ordinary Glyph NFT" not in text and "NFT singleton" not in text, text


def test_every_marker_banner_is_reached_or_excused() -> None:
    """Both directions: a banner added without a way to reach it here fails, and so does an
    excuse or a reach entry for a banner that no longer exists."""
    markers = _banner_markers()
    assert len(markers) >= 6, sorted(markers)
    assert markers == set(_REACH) | set(_NOT_RENDERED)


def test_the_timelock_excuse_is_still_true() -> None:
    """The reason TIMELOCK is not rendered, evaluated: the decoder refuses it alone."""
    import cbor2

    from pyrxd.glyph.payload import decode_payload
    from pyrxd.security.errors import ValidationError

    with pytest.raises(ValidationError, match="TIMELOCK"):
        decode_payload(cbor2.dumps({"p": [2, 9], "name": "x"}))


@pytest.mark.parametrize("mints", [False, True], ids=["mints-nothing", "mints"])
def test_the_burn_excuse_is_still_true(mints: bool) -> None:
    """BURN's banner is drawn, and says nothing about a token either way."""
    text = _render(_payload({"p": [1, 6], "name": "torch"}, mints=mints))
    assert "(protocol = 6)" in text
    assert "ordinary Glyph NFT" not in text and "NFT singleton" not in text
    assert BANNER_NONE not in text and BANNER_SOME not in text


@pytest.mark.parametrize("mints", [False, True], ids=["mints-nothing", "mints"])
@pytest.mark.parametrize("marker", sorted(_REACH))
def test_the_banner_and_the_token_row_say_the_same(marker: str, mints: bool) -> None:
    text = _render(_payload(_REACH[marker], mints=mints))
    assert f"(protocol = {marker})" in text, "the premise: the banner under test is the one drawn"
    _agrees(text, mints=mints)


def test_the_65_byte_mainnet_dat_reveal() -> None:
    """The card the finding was made on."""
    from pyrxd.glyph._inspect_core import _classify_raw_tx

    pair = json.loads((_REPO_ROOT / "tests" / "fixtures" / "dat_65_byte_commit_mainnet.json").read_text())
    reveal = pair["reveal"]
    text = _render(_classify_raw_tx(reveal["txid"], bytes.fromhex(reveal["raw"])))
    assert "(protocol = 3)" in text
    _agrees(text, mints=False)


def test_an_honest_dat_reveal_built_by_pyrxd() -> None:
    from pyrxd.glyph._inspect_core import _classify_raw_tx
    from pyrxd.glyph.builder import CommitParams, GlyphBuilder
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
    from pyrxd.script.script import Script
    from pyrxd.security.types import Hex20
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    pkh = Hex20(os.urandom(20))
    builder = GlyphBuilder()
    commit = builder.prepare_dat_commit(
        CommitParams(
            metadata=GlyphMetadata(protocol=[GlyphProtocol.DAT], name="my-data"),
            owner_pkh=pkh,
            change_pkh=pkh,
            funding_satoshis=100_000,
        )
    )
    commit_tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(commit.commit_script), 1000)])
    inp = TransactionInput(source_txid=commit_tx.txid(), source_output_index=0)
    inp.unlocking_script = Script(_SIG + builder.prepare_dat_reveal(commit.cbor_bytes).scriptsig_suffix)
    reveal = Transaction(
        tx_inputs=[], tx_outputs=[TransactionOutput(Script(b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"), 900)]
    )
    reveal.inputs = [inp]
    text = _render(_classify_raw_tx(reveal.txid(), reveal.serialize()))
    assert "(protocol = 3)" in text
    _agrees(text, mints=False)


def test_the_cli_carries_no_banner_that_could_disagree() -> None:
    """The page's marker banners have no CLI counterpart — checked, not assumed: the CLI source
    names no marker banner and makes no locking-script claim of this kind."""
    source = (_REPO_ROOT / "src" / "pyrxd" / "cli" / "glyph_inspect.py").read_text(encoding="utf-8")
    assert "marker (protocol =" not in source
    assert "ordinary Glyph NFT" not in source


WAVE_BANNER_SAYS = (
    "This page shows the claim as the payload states it; it does not ask a "
    "WAVE indexer whether the name is registered or what it resolves to."
)


def test_the_wave_banner_says_what_the_page_does_with_a_claim() -> None:
    """It said "WAVE support in pyrxd is currently deferred", false by 0.25.0: pyrxd builds WAVE
    claims and pays their registration fee. It now says what THIS page does with one."""
    text = _render(_payload(_REACH["11"], mints=True))
    assert "(protocol = 11)" in text, "the premise: the WAVE banner is the one drawn"
    assert WAVE_BANNER_SAYS in " ".join(text.split())
    assert "deferred" not in text


def test_the_wave_banners_claim_about_the_page_is_true() -> None:
    """The banner says the page asks no WAVE indexer. That is a claim about the page's code, so it
    is checked against it: the page's one socket is opened inside `electrumxRpc`, and every call of
    that sends one of the two ElectrumX reads. A page that learned to resolve a name would fail
    here, and its banner with it."""
    scripts = "".join(
        (_REPO_ROOT / "docs" / "inspect_static" / "inspect" / name).read_text(encoding="utf-8")
        for name in ("inspect.js", "shared.js")
    )
    assert scripts.count("new WebSocket(") == 1, "a second socket is a second way to ask a server"
    methods = re.findall(r'electrumxRpc\("([^"]+)"', scripts)
    calls = re.findall(r"(?<!function )electrumxRpc\(", scripts)
    assert len(calls) == len(methods) > 0, "a call whose method is not a literal escapes the check"
    assert set(methods) == {"blockchain.transaction.get", "blockchain.headers.subscribe"}, methods


def test_no_surface_still_says_wave_support_is_deferred() -> None:
    """The sentence, anywhere a reader of the inspector or the CLI would meet it."""
    roots = [
        _REPO_ROOT / "docs" / "inspect_static",
        _REPO_ROOT / "src" / "pyrxd" / "cli",
        _REPO_ROOT / "docs" / "concepts",
    ]
    hits = [
        str(path.relative_to(_REPO_ROOT))
        for root in roots
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".js", ".py", ".md", ".html"}
        and "wave support in pyrxd is currently deferred" in " ".join(path.read_text(encoding="utf-8").lower().split())
    ]
    assert hits == []
