"""The page draws a ``payload_binding`` warning for exactly the states that say a node would reject
the transaction as shown — the same states the CLI marks.

Both renderers used to flag ``mismatch`` alone, each by its own string literal. The 0.25.0 panel
added ``commit-unsatisfied`` — a commit whose ``OP_REFTYPE_OUTPUT`` check the transaction fails —
which is the same kind of fact and must be as visible. The set is now ONE Python constant,
``PAYLOAD_BINDING_WARNING_STATES``, which the CLI reads; the page cannot import Python, so its
copy is read out of ``inspect.js`` by the render harness and pinned equal here, and each state is
drawn through the production ``renderFetchedTxCard`` from a payload the real classifier built.
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


def _render(cases: dict) -> dict:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the page half is UNGUARDED")
        pytest.fail("node is required to drive inspect.js (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [node, str(_HARNESS), "-"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"render harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def _payload(state: str) -> dict:
    """A fetched-transaction payload whose ``payload_binding`` is *state*, from the real classifier
    handed the real spent script — the way ``--fetch`` and the page's second step produce it."""
    from pyrxd.glyph._inspect_core import _classify_raw_tx
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.script import build_commit_locking_script, build_nft_locking_script
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
    from pyrxd.hash import hash256
    from pyrxd.script.script import Script
    from pyrxd.security.types import Hex20
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    shown, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"))
    committed = shown
    if state == "mismatch":
        committed, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="other"))
    spent = build_commit_locking_script(hash256(committed), Hex20(b"\x22" * 20), is_nft=True)
    commit_txid = "cd" * 32
    inp = TransactionInput(source_txid=commit_txid, source_output_index=0)
    inp.unlocking_script = Script(
        b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + build_reveal_scriptsig_suffix(shown)
    )
    minted = build_nft_locking_script(Hex20(b"\x33" * 20), GlyphRef(txid=commit_txid, vout=0))
    out = TransactionOutput(Script(b"\x6a" if state == "commit-unsatisfied" else minted), 1)
    tx = Transaction(tx_inputs=[], tx_outputs=[out])
    tx.inputs = [inp]
    payload = _classify_raw_tx(tx.txid(), tx.serialize(), spent_scripts={0: spent})
    assert payload["metadata"]["payload_binding"]["state"] == state, "the premise: the classifier said it"
    return payload


def test_the_page_and_the_cli_flag_the_same_states() -> None:
    from pyrxd.glyph._inspect_core import PAYLOAD_BINDING_WARNING_STATES

    page = _render({"case": {"tx": _payload("bound")}})["__constants__"]["payload_binding_warning_states"]
    assert page is not None, "inspect.js exposes no PAYLOAD_BINDING_WARNING_STATES"
    assert sorted(page) == sorted(PAYLOAD_BINDING_WARNING_STATES)


@pytest.mark.parametrize("state", ["bound", "mismatch", "commit-unsatisfied"])
def test_each_state_is_drawn_with_its_reason_and_warned_only_if_a_node_rejects_it(state: str) -> None:
    from pyrxd.glyph._inspect_core import PAYLOAD_BINDING_WARNING_STATES

    payload = _payload(state)
    card = _render({"case": {"tx": payload}})["case"]
    lines = card["fetched_tx_card"].split("\n")
    pb = payload["metadata"]["payload_binding"]
    assert lines[lines.index("payload binding") + 1] == f"{state} — {pb['reason']}"
    # The payload carries no look-alike name and nothing else this card warns about, so the
    # binding row is the only thing that can carry the warning class.
    warned = "kv-value kv-warning" in card["fetched_tx_card_classes"]
    assert warned == (state in PAYLOAD_BINDING_WARNING_STATES), (state, card["fetched_tx_card_classes"])
