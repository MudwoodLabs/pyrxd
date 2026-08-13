"""The browser inspect renderer must render everything the Python emits.

``docs/inspect_static/inspect/inspect.js`` is a **pure renderer**: it boots
Pyodide, installs the real pyrxd wheel and calls ``_inspect_script`` through
``glue.py``. No classification rule is duplicated in JS, which is exactly why
nothing here re-implements one either — these tests feed payloads produced by
the production classifier into the production render functions and assert on
the text that comes out.

Why this file exists
--------------------

Nothing executed ``inspect.js`` outside a browser, so presentation drifted
silently while the classification stayed correct — and presentation is where a
reader's belief actually forms. Two HIGH findings had accumulated:

* a CSV script with bit 31 set (``SEQUENCE_LOCKTIME_DISABLE_FLAG``) makes
  consensus ignore the relative lock entirely. The CLI prints
  ``*** RELATIVE LOCK DISABLED — SPENDABLE IMMEDIATELY ***`` **before** the
  delay; the browser printed the delay and told the reader their nSequence
  "must carry at least this delay". These shapes are HTLC refund legs, so the
  browser was telling a user they had N blocks of protection that consensus
  does not enforce.
* ``renderOutputRow`` — the fetched-transaction path, the way most people meet
  the tool — read none of ``token_bearing``, ``input_refs``, ``note``,
  ``child_ref_outpoint``, ``script_hash``, ``locktime_*``, ``variant``,
  ``transferability`` or ``bound_ref_outpoint``. The rows are the same dicts
  the script path gets, so the data was present and discarded. The
  token-bearing case is the sharp one: a ref-carrying UTXO spent as plain
  funding **burns its token**.

Both were introduced by adding a field to the Python and not to the JS, and an
earlier ``payload.note`` gating bug was the same shape. So the guard is
structural rather than a list of remembered cases: **every key the classifier
emits must appear in the rendered text**, with the handful of deliberate
omissions named and justified below. A new field that the JS forgets is a test
failure, not a silent omission.

How it runs
-----------

``inspect_render_harness.mjs`` loads ``inspect.js`` verbatim in a Node ``vm``
context against a stub DOM and returns the rendered text. It is not a copy and
not a rewrite: a guard that tests a transformed file guards the transformation.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

# NOTE: every ``pyrxd`` import in this module is LAZY, inside ``_corpus`` /
# ``_tx_rows`` / the fixtures. ``tests/web/test_inspect_imports_pyodide_clean``
# pops every ``pyrxd.*`` entry out of ``sys.modules`` to measure a cold import
# graph, and pytest-randomly can run it either side of this file. A module-level
# ``from pyrxd… import`` binds class objects from the pre-clear import, while
# the lazy imports inside ``_inspect_script`` resolve to the post-clear ones —
# and then ``except ValidationError`` stops catching the ValidationError it was
# written for. Resolving at call time keeps one identity per run.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"
_INSPECT_JS = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "inspect.js"

# A real mainnet soulbound authority token (UTXO
# 4b25a666…3f5b:0) — the structural-markers tier. Not a shape any pyrxd builder
# emits, so there is nothing to build it from; same fixture as
# tests/test_inspect_script_shapes.py.
_DEPLOYED_SOULBOUND_SPK = bytes.fromhex(
    "d8020eab29108de31237293118da44eb870882889ab8c7713a2c5302d73f6b0d7e00000000"
    "7c637576a914716477de74200c2e2416177c53aea716f5035ac288ad00eac0e98767de009c69"
    "76a914716477de74200c2e2416177c53aea716f5035ac288ad5168"
)

# Names only, so parametrisation resolves at collection time without importing
# pyrxd. The scripts themselves are built in ``_corpus()``.
_SHAPE_NAMES = (
    "p2pkh",
    "p2sh",
    "op_return",
    "nft",
    "ft",
    "mut",
    "commit-nft",
    "commit-ft",
    "container-legacy",
    "dmint-v1",
    "dmint-v2",
    "p2pkh-cltv-height",
    "p2pkh-cltv-time",
    "p2pkh-csv-blocks",
    "p2pkh-csv-512s",
    "p2pkh-csv-disabled",
    "soulbound-fixed-index",
    "soulbound-composable",
    "self-replicating-covenant",
    "unknown-ref-free",
    "unknown-token-bearing",
    "unknown-gate-only",
    "unknown-undecodable",
)


@functools.lru_cache(maxsize=1)
def _corpus() -> dict[str, bytes]:
    """Every shape the classifier can name, each from its own production
    builder where one exists — a golden hex blob only proves the classifier
    still agrees with what was pasted the day it was written.

    Built lazily; see the import note at the top of the module.
    """
    from pyrxd.constants import SEQUENCE_LOCKTIME_DISABLE_FLAG
    from pyrxd.glyph.dmint.builders import build_dmint_contract_script, build_dmint_v1_contract_script
    from pyrxd.glyph.dmint.types import DmintDeployParams
    from pyrxd.glyph.script import (
        build_commit_locking_script,
        build_ft_locking_script,
        build_mutable_nft_script,
        build_nft_locking_script,
    )
    from pyrxd.glyph.soulbound_covenant import (
        build_composable_soulbound_nft_covenant,
        build_soulbound_nft_covenant,
    )
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.keys import PrivateKey
    from pyrxd.script.timelock import (
        LOCKTIME_THRESHOLD,
        CsvKind,
        build_csv_sequence,
        build_p2pkh_with_cltv_script,
        build_p2pkh_with_csv_script,
    )
    from pyrxd.utils import encode_int

    # Generated, never hand-typed: a weak inline test key was swept by a live
    # bot once.
    pkh = PrivateKey().public_key().hash160()
    ref = GlyphRef(txid=os.urandom(32).hex(), vout=3)
    ref2 = GlyphRef(txid=os.urandom(32).hex(), vout=1)
    payload_hash = os.urandom(32)

    op_csv, op_drop = 0xB2, 0x75
    # A CSV lock whose bit 31 is set. ``build_p2pkh_with_csv_script`` refuses to
    # emit this, correctly — but it can exist on chain, and there it means the
    # relative lock enforces nothing.
    disabled_csv = (
        encode_int(SEQUENCE_LOCKTIME_DISABLE_FLAG | 144)
        + bytes([op_csv, op_drop])
        + b"\x76\xa9\x14"
        + bytes(pkh)
        + b"\x88\xac"
    )

    shapes = {
        "p2pkh": b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac",
        "p2sh": b"\xa9\x14" + os.urandom(20) + b"\x87",
        "op_return": b"\x6a" + b"\x4c\x28" + os.urandom(40),
        "nft": build_nft_locking_script(pkh, ref),
        "ft": build_ft_locking_script(pkh, ref),
        "mut": build_mutable_nft_script(ref, payload_hash),
        "commit-nft": build_commit_locking_script(payload_hash, pkh, is_nft=True),
        "commit-ft": build_commit_locking_script(payload_hash, pkh, is_nft=False),
        # The dead pre-0.15.0 CONTAINER-with-child-ref output: OP_PUSHINPUTREF
        # <child> then a plain NFT script. Built the way it used to be built.
        "container-legacy": b"\xd0" + ref2.to_bytes() + build_nft_locking_script(pkh, ref),
        "dmint-v1": build_dmint_v1_contract_script(
            height=0, contract_ref=ref, token_ref=ref2, max_height=1000, reward=100_000, target=0x7FFFFFFFFFFFFF
        ),
        "dmint-v2": build_dmint_contract_script(
            DmintDeployParams(contract_ref=ref, token_ref=ref2, max_height=1000, reward=100_000, difficulty=1)
        ),
        "p2pkh-cltv-height": build_p2pkh_with_cltv_script(pkh, 800_000),
        "p2pkh-cltv-time": build_p2pkh_with_cltv_script(pkh, LOCKTIME_THRESHOLD + 86_400),
        "p2pkh-csv-blocks": build_p2pkh_with_csv_script(pkh, build_csv_sequence(144, CsvKind.BLOCKS)),
        "p2pkh-csv-512s": build_p2pkh_with_csv_script(pkh, build_csv_sequence(100, CsvKind.TIME_512_SECONDS)),
        "p2pkh-csv-disabled": disabled_csv,
        "soulbound-fixed-index": build_soulbound_nft_covenant(ref, pkh).funded_spk,
        "soulbound-composable": build_composable_soulbound_nft_covenant(ref, pkh).funded_spk,
        "self-replicating-covenant": _DEPLOYED_SOULBOUND_SPK,
        "unknown-ref-free": b"\x51" * 60,
        "unknown-token-bearing": b"\xd0" + ref.to_bytes() + b"\x51" * 30,
        # A credential GATE — OP_REQUIREINPUTREF names a ref it does not hold.
        "unknown-gate-only": b"\xd1" + ref.to_bytes() + b"\x51" * 30,
        "unknown-undecodable": b"\x51" * 30 + b"\xd0" + b"\x00" * 10,
    }
    assert tuple(shapes) == _SHAPE_NAMES, "the corpus and its parametrisation names disagree"
    return {name: bytes(script) for name, script in shapes.items()}


# --- deliberate omissions --------------------------------------------------
#
# A key listed here is one the renderer is ALLOWED to drop, with the reason.
# Anything not listed must appear in the rendered text. Adding an entry is a
# deliberate act with a justification attached; forgetting a field is not.

_OMITTED_FROM_SCRIPT_CARD = {
    "form": "always 'script' on this path — the card's title carries it",
    "hex": "the bytes the user just pasted, echoed back; the JSON drawer has them",
}

_OMITTED_FROM_OUTPUT_ROW = {
    "form": "popped by _classify_raw_tx before the row is built",
    "hex": "a full scriptPubKey per row is unscannable; the JSON drawer has it. "
    "The CLI's _render_txid_human omits it for the same reason",
    "length": "same — a byte count per row is noise; the CLI omits it too",
}

# Keys whose rendering is prose rather than the literal value. The mapping is
# key -> {value: required substring}. ``None`` means no evidence is required
# (see the note on each).
_PROSE_EVIDENCE = {
    # The container's verdict reads "*** UNSPENDABLE ***", never "false".
    "spendable": {False: "UNSPENDABLE"},
    # True must shout. False must NOT render a warning at all — the absence is
    # the correct rendering, so no evidence is required and
    # ``test_enabled_relative_lock_carries_no_disabled_warning`` asserts the
    # absence directly.
    "relative_lock_disabled": {True: "DISABLED", False: None},
    # A walk that could not finish reports "unknown", not the literal null.
    "token_bearing": {None: "does not decode"},
}


def _js_string(value) -> str:
    """How JavaScript's ``String(value)`` renders a Python value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _required_evidence(key: str, value) -> list[str]:
    """Substrings the rendered text must contain for *key* to count as shown."""
    if key in _PROSE_EVIDENCE and value in _PROSE_EVIDENCE[key]:
        phrase = _PROSE_EVIDENCE[key][value]
        return [] if phrase is None else [phrase]
    if isinstance(value, list):
        # input_refs / referenced_refs: every entry, both fields.
        return [str(field) for entry in value for field in entry.values() if str(field)]
    if value is None or value == "":
        return []
    text = _js_string(value)
    # Long blobs are truncated for scannability (data_hex in a tx row). Match
    # on the head, which is what the renderer promises to show.
    return [text[:64]]


@functools.lru_cache(maxsize=1)
def _payloads() -> dict[str, dict[str, dict]]:
    """``{shape: {"script": <script payload>, "row": <tx-row payload>}}``.

    The rows come from the REAL fetched-transaction path, not from a hand-rolled
    ``dict(payload) | {"vout": …}``: the premise of this whole file is that a tx
    row carries the same fields a script card does, and asserting that premise
    against a reconstruction would prove nothing about the code that actually
    builds rows.
    """
    from pyrxd.glyph._inspect_core import _classify_raw_tx, _inspect_script
    from pyrxd.hash import hash256
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    shapes = _corpus()
    tx = Transaction(
        tx_inputs=[TransactionInput(source_txid="00" * 32, source_output_index=0, unlocking_script=Script(b""))],
        # ``allow_malformed``: one corpus shape ends mid-ref-operand on
        # purpose. Such bytes exist on chain and are exactly the case the
        # inspector answers ``token_bearing: null`` for, so the guard has to be
        # able to put one in a transaction.
        tx_outputs=[
            TransactionOutput(Script(script, allow_malformed=True), 546 + i) for i, script in enumerate(shapes.values())
        ],
    )
    raw = tx.serialize()
    rows = _classify_raw_tx(hash256(raw)[::-1].hex(), raw)["outputs"]
    return {
        name: {"script": _inspect_script(shapes[name].hex()), "row": row}
        for name, row in zip(shapes, rows, strict=True)
    }


@pytest.fixture(scope="module")
def payloads() -> dict[str, dict[str, dict]]:
    return _payloads()


@pytest.fixture(scope="module")
def rendered(payloads) -> dict[str, dict[str, str]]:
    """``{shape: {"script_card": text, "output_row": text}}`` from the real JS."""
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip(
                "node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the browser renderer is UNGUARDED in this run"
            )
        pytest.fail(
            "node is required to run the browser-renderer drift guard (it loads "
            "docs/inspect_static/inspect/inspect.js in a Node vm). Install node, or "
            "set PYRXD_SKIP_JS_RENDER_GUARD=1 to skip it deliberately and accept "
            "that inspect.js is unverified in this run."
        )
    return _run_harness(node, payloads)


def _run_harness(node: str, cases: dict) -> dict:
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


# ─────────────────────────────────────────────── the structural guard ──


class TestEveryFieldIsRendered:
    """A field the classifier emits and the renderer drops is a field the
    reader never learns. Both surfaces, every shape."""

    @pytest.mark.parametrize("shape", _SHAPE_NAMES)
    def test_script_card_renders_every_field(self, shape, payloads, rendered):
        payload = payloads[shape]["script"]
        text = rendered[shape]["script_card"]
        lowered = text.lower()
        for key, value in payload.items():
            if key in _OMITTED_FROM_SCRIPT_CARD:
                continue
            for evidence in _required_evidence(key, value):
                assert evidence.lower() in lowered, (
                    f"renderScriptCard dropped {key!r}={value!r} for shape {shape!r}. "
                    f"Expected {evidence!r} in the rendered card.\n"
                    f"If the omission is deliberate, add {key!r} to "
                    f"_OMITTED_FROM_SCRIPT_CARD with a reason.\n--- rendered ---\n{text}"
                )

    @pytest.mark.parametrize("shape", _SHAPE_NAMES)
    def test_output_row_renders_every_field(self, shape, payloads, rendered):
        row = payloads[shape]["row"]
        text = rendered[shape]["output_row"]
        lowered = text.lower()
        for key, value in row.items():
            if key in _OMITTED_FROM_OUTPUT_ROW:
                continue
            for evidence in _required_evidence(key, value):
                assert evidence.lower() in lowered, (
                    f"renderOutputRow dropped {key!r}={value!r} for shape {shape!r}. "
                    f"This is the fetched-transaction path — the way most people meet "
                    f"the tool. Expected {evidence!r} in the rendered row.\n"
                    f"If the omission is deliberate, add {key!r} to "
                    f"_OMITTED_FROM_OUTPUT_ROW with a reason.\n--- rendered ---\n{text}"
                )

    def test_the_two_surfaces_see_the_same_fields(self, payloads):
        """The premise the guard rests on: a tx row IS the script dict, minus
        ``form``, plus ``vout`` / ``satoshis``. If that ever stops being true,
        the two ``_OMITTED_*`` tables stop describing the same universe and the
        guard quietly narrows."""
        for shape, pair in payloads.items():
            script_keys = set(pair["script"]) - {"form"}
            row_keys = set(pair["row"]) - {"vout", "satoshis"}
            assert script_keys == row_keys, shape


# ───────────────────────────────────────── the disabled relative lock ──


class TestDisabledRelativeLock:
    """Bit 31 set means consensus ignores the lock. Saying otherwise, on a
    shape that is an HTLC refund leg in practice, is the worst thing either
    tool can do."""

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_warning_is_rendered(self, surface, rendered):
        text = rendered["p2pkh-csv-disabled"][surface]
        assert "RELATIVE LOCK DISABLED" in text
        assert "SPENDABLE IMMEDIATELY" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_warning_precedes_the_delay(self, surface, rendered):
        """Ordering is the finding, not just presence. A reader who meets
        "delay: 144 blocks" first and the caveat second walks away with the
        opposite of the truth — which is why the CLI prints them in this order
        and why the browser now does too."""
        text = rendered["p2pkh-csv-disabled"][surface]
        assert text.index("SPENDABLE IMMEDIATELY") < text.index("(ignored)")

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_delay_is_labelled_ignored(self, surface, rendered):
        """A row read in isolation must not read as an enforced delay."""
        assert "(ignored)" in rendered["p2pkh-csv-disabled"][surface]

    @pytest.mark.parametrize("shape", ["p2pkh-csv-blocks", "p2pkh-csv-512s"])
    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_enabled_relative_lock_carries_no_disabled_warning(self, shape, surface, rendered):
        """The other direction. A warning that fires on every CSV script is a
        warning nobody reads."""
        text = rendered[shape][surface]
        assert "DISABLED" not in text
        assert "SPENDABLE IMMEDIATELY" not in text

    def test_the_qualifier_stops_claiming_the_delay_is_enforced(self, rendered):
        """The structural-match footnote used to tell every CSV reader their
        "nSequence must carry at least this delay". For the disabled shape that
        sentence is false, so it is suppressed — as the CLI suppresses it."""
        enabled = rendered["p2pkh-csv-blocks"]["script_card"]
        disabled = rendered["p2pkh-csv-disabled"]["script_card"]
        assert "must carry at least this" in enabled
        assert "must carry at least this" not in disabled


# ──────────────────────────────────── CLI parity on the safety-critical ──


class TestCliParityOnFetchedTxRows:
    """The measured gaps from the review, one test each. These are the facts
    the CLI states in a tx listing and the browser did not."""

    def test_token_bearing_unknown_output_warns(self, payloads, rendered):
        """CLI: ``ref=… (0xd0) TOKEN-BEARING``. A ref-carrying UTXO spent as
        plain funding burns its token, and the warning was invisible on the
        exact screen where users meet these outputs."""
        carried = payloads["unknown-token-bearing"]["row"]["input_refs"]
        text = rendered["unknown-token-bearing"]["output_row"]
        assert "TOKEN-BEARING" in text
        assert "0xd0" in text
        assert carried[0]["ref_outpoint"] in text

    def test_a_gate_only_script_is_not_called_token_bearing(self, rendered):
        """0xd1 OP_REQUIREINPUTREF names a ref; it does not hold one. The burn
        warning must not fire here — a warning that cries wolf on every
        credential gate is how a reader learns to skip the real one."""
        text = rendered["unknown-gate-only"]["output_row"]
        assert "TOKEN-BEARING" not in text
        assert "named, not carried" in text
        assert "0xd1" in text

    def test_container_legacy_row_says_unspendable(self, payloads, rendered):
        """CLI: ``child_ref=…`` + ``UNSPENDABLE``."""
        text = rendered["container-legacy"]["output_row"]
        assert "UNSPENDABLE" in text
        assert payloads["container-legacy"]["row"]["child_ref_outpoint"] in text

    @pytest.mark.parametrize("shape", ["soulbound-fixed-index", "soulbound-composable"])
    def test_soulbound_row_states_the_binding_and_the_verdict(self, shape, payloads, rendered):
        """CLI: ``bound_ref=…`` + ``variant=… (non-transferable at consensus)``."""
        text = rendered[shape]["output_row"]
        assert payloads[shape]["row"]["bound_ref_outpoint"] in text
        assert "non-transferable at consensus" in text

    def test_the_weak_covenant_tier_makes_no_transferability_claim(self, rendered):
        """The two-tier split exists to withhold the soulbound verdict from a
        marker-only match. Rendering it here would hand back the claim the
        classifier deliberately does not make."""
        text = rendered["self-replicating-covenant"]["output_row"]
        assert "non-transferable at consensus" not in text
        assert "NOT proof" in text  # the classifier's own caveat, previously dropped

    def test_p2sh_row_shows_the_script_hash(self, payloads, rendered):
        """CLI: ``script_hash=…``. The browser row showed a badge and nothing
        else."""
        assert payloads["p2sh"]["row"]["script_hash"] in rendered["p2sh"]["output_row"]

    def test_timelock_row_shows_the_lock(self, rendered):
        """CLI: ``lock=144 blocks``."""
        text = rendered["p2pkh-csv-blocks"]["output_row"]
        assert "144" in text
        assert "blocks" in text

    def test_notes_reach_the_tx_path(self, rendered):
        """``note`` is the classifier's own caveat for shapes where naming them
        is only half the answer. The tx path dropped it entirely."""
        assert "UNSPENDABLE" in rendered["container-legacy"]["output_row"]
        assert "pre-external-audit" in rendered["soulbound-fixed-index"]["output_row"]


# ───────────────────────────────────────────── the CLTV earliest block ──


class TestCltvEarliestBlock:
    """``locktime_units`` is a floor on the SPENDING TX's nLockTime;
    ``locktime_earliest`` is the first block that can carry the spend. They are
    one apart and only the second answers "when can I spend this?"."""

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_derived_earliest_block_is_rendered(self, surface, rendered):
        assert "800,001" in rendered["p2pkh-cltv-height"][surface] or "800001" in rendered["p2pkh-cltv-height"][surface]

    def test_the_renderer_does_not_derive_it_itself(self):
        """The renderer's whole value is that it calls the real Python. If the
        +1 ever appears in JS, the two tools can disagree about a consensus
        rule — which is the defect this branch exists to remove."""
        source = _INSPECT_JS.read_text(encoding="utf-8")
        assert "locktime_units + 1" not in source
        assert "locktime_units+1" not in source


# ────────────────────────────────────────────────── the guard's premise ──


class TestHarnessIntegrity:
    """A guard that silently stops guarding is worse than no guard."""

    def test_the_harness_loads_the_real_file(self, rendered):
        """Not a copy, not a rewrite: the harness reads
        docs/inspect_static/inspect/inspect.js off disk and throws if the
        render functions are not reachable afterwards. Any output at all proves
        the load succeeded."""
        assert rendered["p2pkh"]["script_card"].strip()

    def test_error_rows_still_render_their_reason(self):
        """The one row shape no script can produce: a classifier crash inside
        _classify_raw_tx. Rendered separately because there is no script to
        build it from."""
        if shutil.which("node") is None:
            pytest.skip("node missing; covered by the fixture's failure message")
        case = {
            "err": {
                "script": {"form": "script", "type": "unknown", "length": 0, "hex": ""},
                "row": {"vout": 7, "type": "error", "error": "ValidationError", "satoshis": 1234},
            }
        }
        proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
            [shutil.which("node"), str(_HARNESS), "-"],
            input=json.dumps(case),
            capture_output=True,
            text=True,
            check=False,
            cwd=str(_REPO_ROOT),
        )
        assert proc.returncode == 0, proc.stderr
        text = json.loads(proc.stdout)["err"]["output_row"]
        assert "ValidationError" in text
        assert "1234" in text
        assert "vout 7" in text


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
