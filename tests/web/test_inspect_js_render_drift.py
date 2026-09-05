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
    "op_return-msg",
    "op_return-hashmark-v1",
    "op_return-hashmark-v2",
    "nft",
    "ft",
    "mut",
    "commit-nft",
    "commit-ft",
    "commit-dat",
    "op_return-burn",
    "delegate-token",
    "delegate-burn",
    # A commit output carrying the 56-byte delegate prefix. Same emitted TYPE as
    # "commit-nft", deliberately: what it exercises is that every offset in the
    # classifier is taken from the CORE rather than from the start of the
    # script. Built without it, a delegate commit is 131 bytes with each field
    # shifted by 56 and reads as an unrecognised output.
    "commit-nft-delegate",
    "authority-gated-nft",
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
    from pyrxd.glyph.burn import build_burn_proof_script
    from pyrxd.glyph.dmint.builders import build_dmint_contract_script, build_dmint_v1_contract_script
    from pyrxd.glyph.dmint.types import DmintDeployParams
    from pyrxd.glyph.script import (
        build_authority_gated_nft_script,
        build_commit_locking_script,
        build_dat_commit_locking_script,
        build_delegate_burn_script,
        build_delegate_token_script,
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
        # The OP_RETURN payload shapes. Built here rather than imported from a
        # fixture because the point is what the CLASSIFIER emits for real bytes.
        "op_return-msg": b"\x6a\x03msg\x0bhello there",
        "op_return-hashmark-v1": (
            b"\x6a\x08HASHMARK\x02" + bytes([1, 1]) + b"\x20" + os.urandom(32) + b"\x0breport.pdf"
        ),
        # v2 carries a signer and a signature, so it is the shape whose ATTESTATION
        # VERDICT must reach the reader. The signature here is random, so the record
        # decodes and does NOT verify — deliberately, because "does not verify" is
        # the line that was missing from this page entirely.
        "op_return-hashmark-v2": (
            b"\x6a\x08HASHMARK\x02"
            + bytes([2, 1])
            + b"\x20"
            + os.urandom(32)
            + b"\x14"
            + os.urandom(20)
            + b"\x41"
            + bytes([31])
            + os.urandom(64)
        ),
        "nft": build_nft_locking_script(pkh, ref),
        "ft": build_ft_locking_script(pkh, ref),
        "mut": build_mutable_nft_script(ref, payload_hash),
        "commit-nft": build_commit_locking_script(payload_hash, pkh, is_nft=True),
        "commit-ft": build_commit_locking_script(payload_hash, pkh, is_nft=False),
        # No OP_REFTYPE_OUTPUT block and an extra "dat" push: every offset after
        # the payload hash shifts relative to the two commits above.
        "commit-dat": build_dat_commit_locking_script(payload_hash, pkh),
        "op_return-burn": build_burn_proof_script(ref, amount=250, burn_reason="redeemed"),
        # A delegate token is the SAME 63 bytes as "nft" above with a different
        # opcode (0xd0 vs 0xd8), which is exactly why it gets its own shape.
        "delegate-token": build_delegate_token_script(pkh, ref2),
        "delegate-burn": build_delegate_burn_script(ref2),
        "commit-nft-delegate": build_commit_locking_script(payload_hash, pkh, is_nft=True, delegate_ref=ref2),
        # 101 bytes: the item's singleton behind an OP_REQUIREINPUTREF on the
        # issuer's authority ref. ref2 is the authority, ref the item.
        "authority-gated-nft": build_authority_gated_nft_script(pkh, ref, ref2),
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


# Keys INSIDE a nested payload block (hashmark, message, attestation) that the
# renderer may drop. Same rule as the top-level tables: listed with a reason, or
# it must appear. Without this the guard would demand the literal value of every
# leaf, including ones that are deliberately rendered as prose.
_OMITTED_NESTED_KEYS = {
    "outcome": "rendered as prose — 'v2 (sha256)' when ok, 'DOES NOT VERIFY' or the "
    "outcome text otherwise. The literal 'ok' would tell a reader nothing",
    "signature_unverified": "the raw 65-byte signature. The VERDICT is what a reader "
    "needs and the bytes are in the JSON drawer; the CLI omits it for the same reason",
    "assumed_network": "shown beside a VERIFIED signature, where the assumption is "
    "load-bearing. On a failure the reason is the detail, not the chain",
    "is_utf8": "rendered as prose — either the decoded text, or 'not valid UTF-8'",
    "recovered_hash160": "identical to the committed signer whenever it is set, and "
    "the signer is already rendered; printing both invites reading them as two facts",
}


def _required_evidence(key: str, value) -> list[str]:
    """Substrings the rendered text must contain for *key* to count as shown."""
    if key in _PROSE_EVIDENCE and _hashable(value) and value in _PROSE_EVIDENCE[key]:
        phrase = _PROSE_EVIDENCE[key][value]
        return [] if phrase is None else [phrase]
    if isinstance(value, dict):
        # A nested block (hashmark, message, attestation). Recurse to its LEAVES:
        # asserting the dict's repr would be satisfied by nothing a renderer emits,
        # and skipping it entirely is how the whole block went unrendered.
        return [
            evidence
            for sub_key, sub_value in value.items()
            if sub_key not in _OMITTED_NESTED_KEYS
            for evidence in _required_evidence(sub_key, sub_value)
        ]
    if isinstance(value, list):
        # Two list shapes reach this. `input_refs` / `referenced_refs` /
        # `metadata_inputs` are lists of DICTS — every entry, every field.
        # `metadata.protocol` is a list of SCALARS, and `.values()` on a string
        # is an AttributeError, so the two cannot share one line.
        evidence: list[str] = []
        for entry in value:
            if isinstance(entry, dict):
                evidence.extend(str(field) for field in entry.values() if str(field))
            else:
                evidence.extend(_required_evidence("", entry))
        return evidence
    if value is None or value == "":
        return []
    text = _js_string(value)
    # Long blobs are truncated for scannability (data_hex in a tx row). Match
    # on the head, which is what the renderer promises to show.
    return [text[:64]]


def _hashable(value) -> bool:
    try:
        hash(value)
    except TypeError:
        return False
    return True


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


def _require_node() -> str:
    """The node binary, or the run's own verdict on being without it."""
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
    return node


@pytest.fixture(scope="module")
def rendered(payloads) -> dict[str, dict[str, str]]:
    """``{shape: {"script_card": text, "output_row": text}}`` from the real JS."""
    return _run_harness(_require_node(), payloads)


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


class TestTheCorpusCoversEveryShapeTheClassifierCanEmit:
    """The guard above is only as wide as `_SHAPE_NAMES`, which is hand-kept.

    That is how the OP_RETURN payload shapes slipped past it: `hashmark`,
    `attestation` and `message` were added to the Python classifier and to neither
    card, and "every key must be rendered" never fired because no shape in the
    corpus produced those keys. The structural guard was structural about FIELDS and
    hand-kept about SHAPES.

    So the shape list is now checked against the type strings the classifier can
    actually emit, recovered from its source. A new `type` with no corpus entry
    fails here rather than silently narrowing every test in this file.
    """

    #: Types no pasted script can produce, with the reason.
    _UNREACHABLE = {
        "error": "produced only when classification RAISES; there is no script that yields it",
    }

    @staticmethod
    def _emitted_by_the_source() -> set[str]:
        """Every `type` value written as a literal in the classifier, plus the
        prefix of every one built by an f-string."""
        import ast
        import pathlib

        source = pathlib.Path(_REPO_ROOT / "src/pyrxd/glyph/_inspect_core.py").read_text(encoding="utf-8")
        found: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            targets = []
            if isinstance(node, ast.Dict):
                targets = [
                    v
                    for k, v in zip(node.keys, node.values, strict=False)
                    if isinstance(k, ast.Constant) and k.value == "type"
                ]
            elif isinstance(node, ast.Assign):
                targets = [
                    node.value
                    for t in node.targets
                    if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == "type"
                ]
            for value in targets:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    found.add(value.value)
                elif isinstance(value, ast.JoinedStr) and value.values:
                    # f"op_return-hashmark-v{version}" -> the literal prefix, which is
                    # enough to demand SOME corpus shape of that family.
                    head = value.values[0]
                    if isinstance(head, ast.Constant) and isinstance(head.value, str):
                        found.add(head.value)
        if len(found) < 10:
            raise AssertionError(
                f"only {len(found)} type values parsed from _inspect_core.py — the extraction is broken"
            )
        return found

    def test_every_emitted_type_has_a_corpus_shape(self, payloads) -> None:
        produced = {payloads[name]["script"].get("type", "") for name in _SHAPE_NAMES}
        missing = []
        for emitted in sorted(self._emitted_by_the_source()):
            if emitted in self._UNREACHABLE:
                continue
            # Exact for a literal type; prefix for an f-string family.
            if not any(t == emitted or t.startswith(emitted) for t in produced):
                missing.append(emitted)
        assert not missing, (
            f"the classifier can emit {missing} and no corpus shape produces it, so every "
            f"test in this file is blind to those shapes. Add one to `_SHAPE_NAMES` and "
            f"`_corpus()`, or record it in `_UNREACHABLE` with a reason.\n"
            f"currently produced: {sorted(produced)}"
        )

    def test_the_extraction_is_not_vacuous(self) -> None:
        """A parser returning an empty set would make the check above pass forever."""
        emitted = self._emitted_by_the_source()
        assert {"p2pkh", "op_return", "op_return-hashmark-v"} <= emitted

    def test_no_corpus_shape_is_unreachable_from_the_classifier(self, payloads) -> None:
        """The other direction: a shape whose type no longer exists is a test that
        silently stopped covering anything."""
        emitted = self._emitted_by_the_source()
        for name in _SHAPE_NAMES:
            produced = payloads[name]["script"].get("type", "")
            assert any(produced == e or produced.startswith(e) for e in emitted), (
                f"corpus shape {name!r} classifies as {produced!r}, which the classifier "
                f"source no longer emits — this shape is guarding nothing"
            )


class TestTheNestedRequirementIsNotVACUOUS:
    """A nested block must demand SOMETHING on screen.

    `_required_evidence` recurses into `hashmark` / `message` / `attestation` and
    skips leaves listed in `_OMITTED_NESTED_KEYS`. If a block's every leaf ended up
    listed there, it would return no requirements at all and the block would count
    as "rendered" while the card showed nothing — the same shape as the corpus gap
    that let these fields go unrendered in the first place, one level down.

    The omission table is the right mechanism; it just needs a floor under it.
    """

    _NESTED = {"hashmark": ("op_return-hashmark-v2", 3), "message": ("op_return-msg", 1)}

    @pytest.mark.parametrize("key", sorted(_NESTED))
    def test_the_block_demands_evidence(self, key, payloads) -> None:
        shape, minimum = self._NESTED[key]
        block = payloads[shape]["row"][key]
        evidence = _required_evidence(key, block)
        assert len(evidence) >= minimum, (
            f"{key!r} on shape {shape!r} requires only {len(evidence)} evidence strings "
            f"({evidence}). Every leaf that matters has been omitted, so this block now "
            f"passes whether or not the renderer shows it."
        )

    def test_the_digest_specifically_must_be_shown(self, payloads) -> None:
        """The one field that identifies WHICH file was marked. A HashMark card
        without it is decoration."""
        block = payloads["op_return-hashmark-v2"]["row"]["hashmark"]
        assert block["digest"] in _required_evidence("hashmark", block)

    def test_the_attestation_detail_must_be_shown(self, payloads) -> None:
        """The verdict's reason. Dropping it is how "does not verify" becomes a bare
        badge again."""
        block = payloads["op_return-hashmark-v2"]["row"]["hashmark"]
        assert block["attestation"]["detail"] in _required_evidence("hashmark", block)


# ───────────────────────────────────────── the transaction-level card ──
#
# Everything above tests ONE OUTPUT. The claims that mislead hardest are the
# whole-transaction ones — "this is a burn", "N contracts all share the same
# token_ref", "the freshly-minted FT lives in a separate ft output", "these
# characters visually mimic Latin letters" — and every one of them lives in
# ``renderFetchedTxCard`` / ``_detectTxShape``, which nothing executed at all
# until the harness grew a ``tx`` key.
#
# The defect shape is not a dropped field this time. It is an ASSERTED SENTENCE
# with no computation behind it: the data needed to check the claim was already
# in the payload and simply never read. No test can pin that a sentence is TRUE,
# only that it is emitted — so these pin the pairing, the claim against the
# branch of the check that produced it, both ways round.

_GLUE_PATH = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"


@functools.lru_cache(maxsize=1)
def _glue():
    """``glue.py`` imported from its in-repo path, as
    ``tests/web/test_glue_integration.py`` does — it lives outside the package
    tree because Pyodide fetches it, and it is pure Python under CPython.

    Lazy, for the reason at the top of this module.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_render", _GLUE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_render"] = module
    spec.loader.exec_module(module)
    return module


def _reveal_scriptsig(name: str, *, ticker: str = "", protocol=(2,), extra: dict | None = None) -> bytes:
    """``<sig> <pubkey> "gly" <CBOR>`` — a reveal scriptSig as the chain carries it."""
    import cbor2

    from pyrxd.keys import PrivateKey

    body: dict = {"p": list(protocol), "name": name}
    if ticker:
        body["ticker"] = ticker
    if extra:
        body.update(extra)

    def push(b: bytes) -> bytes:
        if len(b) <= 0x4B:
            return bytes([len(b)]) + b
        if len(b) <= 0xFF:
            return b"\x4c" + bytes([len(b)]) + b
        return b"\x4d" + len(b).to_bytes(2, "little") + b

    return push(b"\x30" * 71) + push(PrivateKey().public_key().serialize()) + push(b"gly") + push(cbor2.dumps(body))


def _mint_claim_scriptsig() -> bytes:
    """The 72-byte V1 dMint mint-claim scriptSig: nonce(4), inputHash(32),
    outputHash(32), OP_0. ``parse_mint_scriptsig`` decodes exactly this."""
    return b"\x04" + os.urandom(4) + b"\x20" + os.urandom(32) + b"\x20" + os.urandom(32) + b"\x00"


def _tx_payload(scriptsigs: list[bytes], outputs: list[tuple[bytes, int]]) -> dict:
    """Classify a transaction through the REAL browser entry point.

    ``glue.inspect_txid_with_raw`` is what the page calls after its ElectrumX
    fetch, and it is where ``display_warnings`` is attached. Hand-building the
    dict would exercise the renderer against a payload the browser never
    produces — which is how a banner came to describe a check that does not run.
    """
    from pyrxd.hash import hash256
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(
        tx_inputs=[
            TransactionInput(source_txid="ab" * 32, source_output_index=i, unlocking_script=Script(ss))
            for i, ss in enumerate(scriptsigs)
        ],
        tx_outputs=[
            TransactionOutput(locking_script=Script(spk, allow_malformed=True), satoshis=value)
            for spk, value in outputs
        ],
    )
    raw = tx.serialize()
    result = _glue().inspect_txid_with_raw(hash256(raw)[::-1].hex(), raw.hex())
    assert result["ok"], result
    return result["payload"]


def _tx_payload_single_vout(scriptsigs: list[bytes], outputs: list[tuple[bytes, int]], vout: int) -> dict:
    """The same transaction classified with ``only_vout`` — one output row while
    ``output_count`` still reports the whole transaction.

    Built through ``pyrxd.glyph.inspect.classify_raw_tx`` rather than the glue,
    because the glue has no ``only_vout`` parameter — but the public classifier
    does, and ``renderFetchedTxCard`` renders whatever a txid payload contains.
    A partial list is the shape in which "this transaction has NO ft output" is
    a lie told from an incomplete reading, which is the defect class this whole
    file is about.
    """
    from pyrxd.glyph.inspect import classify_raw_tx
    from pyrxd.hash import hash256
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(
        tx_inputs=[
            TransactionInput(source_txid="ab" * 32, source_output_index=i, unlocking_script=Script(ss))
            for i, ss in enumerate(scriptsigs)
        ],
        tx_outputs=[
            TransactionOutput(locking_script=Script(spk, allow_malformed=True), satoshis=value)
            for spk, value in outputs
        ],
    )
    raw = tx.serialize()
    return classify_raw_tx(hash256(raw)[::-1].hex(), raw, only_vout=vout)


@functools.lru_cache(maxsize=1)
def _tx_payloads() -> dict[str, dict]:
    """One classified transaction per claim the tx card makes, each built to sit
    on a chosen side of the check that claim now depends on."""
    from pyrxd.glyph.dmint.builders import build_dmint_v1_contract_script
    from pyrxd.glyph.script import (
        build_commit_locking_script,
        build_ft_locking_script,
        build_nft_locking_script,
    )
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.keys import PrivateKey

    pkh = PrivateKey().public_key().hash160()
    p2pkh = b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"
    op_return = b"\x6a\x04test"
    token_ref = GlyphRef(txid=os.urandom(32).hex(), vout=0)
    other_token_ref = GlyphRef(txid=os.urandom(32).hex(), vout=1)
    ft = build_ft_locking_script(pkh, token_ref)
    nft = build_nft_locking_script(pkh, token_ref)
    commit_ft = build_commit_locking_script(os.urandom(32), pkh, is_nft=False)
    commit_nft = build_commit_locking_script(os.urandom(32), pkh, is_nft=True)
    empty = b""

    def dmint(height: int, *, tref: GlyphRef, reward: int = 100_000, max_height: int = 1000) -> bytes:
        return build_dmint_v1_contract_script(
            height=height,
            contract_ref=GlyphRef(txid=os.urandom(32).hex(), vout=0),
            token_ref=tref,
            max_height=max_height,
            reward=reward,
            target=0x7FFFFFFFFFFFFF,
        )

    return {
        # BURN declared in CBOR while the transaction hands the ref straight back
        # out to an ordinary FT output — the case the old banner called "removed
        # from circulation".
        "burn": _tx_payload(
            [_reveal_scriptsig("Torch", ticker="TRCH", protocol=(1, 6))],
            [(ft, 1000), (p2pkh, 546)],
        ),
        "single-glyph": _tx_payload([_reveal_scriptsig("Solo", ticker="SOLO")], [(nft, 546)]),
        "multi-glyph": _tx_payload(
            [
                _reveal_scriptsig("First", ticker="ONE"),
                _reveal_scriptsig("Second", ticker="TWO"),
                _reveal_scriptsig("Third", ticker="THREE"),
            ],
            [(nft, 546)],
        ),
        # A TIMELOCK envelope: the page had a banner saying a time condition
        # exists and rendered nothing about what it is.
        "timelock": _tx_payload(
            [
                _reveal_scriptsig(
                    "Sealed",
                    protocol=(2, 8, 9),
                    extra={
                        "crypto": {
                            "timelock": {
                                "mode": "block",
                                "unlock_at": 900_000,
                                "cek_hash": "sha256:" + os.urandom(32).hex(),
                                "hint": "opens after the halving",
                            }
                        }
                    },
                )
            ],
            [(nft, 546)],
        ),
        "ft-deploy": _tx_payload([empty], [(commit_ft, 546), (commit_nft, 546), (ft, 1000), (p2pkh, 546)]),
        "nft-commit-only": _tx_payload([empty], [(commit_nft, 546), (p2pkh, 546)]),
        # dMint deploys: one token in parallel, versus rows that merely LOOK like
        # it because there are several of them.
        "dmint-deploy-one-token": _tx_payload(
            [empty],
            [(dmint(0, tref=token_ref), 546) for _ in range(3)] + [(p2pkh, 546)],
        ),
        "dmint-deploy-mixed-refs": _tx_payload(
            [empty],
            [
                (dmint(0, tref=token_ref), 546),
                (dmint(0, tref=other_token_ref), 546),
                (dmint(0, tref=token_ref), 546),
                (p2pkh, 546),
            ],
        ),
        "dmint-deploy-mixed-terms": _tx_payload(
            [empty],
            [
                (dmint(0, tref=token_ref, reward=100_000), 546),
                (dmint(0, tref=token_ref, reward=250_000), 546),
                (dmint(0, tref=token_ref, reward=100_000), 546),
                (p2pkh, 546),
            ],
        ),
        "dmint-claim-canonical": _tx_payload(
            [_mint_claim_scriptsig()],
            [(dmint(5, tref=token_ref), 546), (ft, 100_000), (op_return, 0), (p2pkh, 546)],
        ),
        # The SAME canonical claim tx, classified one output at a time. Every
        # output-derived verdict has to withhold itself here: the reward output
        # exists and this view cannot see it.
        "dmint-claim-single-vout": _tx_payload_single_vout(
            [_mint_claim_scriptsig()],
            [(dmint(5, tref=token_ref), 546), (ft, 100_000), (op_return, 0), (p2pkh, 546)],
            0,
        ),
        "dmint-claim-no-ft": _tx_payload(
            [_mint_claim_scriptsig()],
            [(dmint(5, tref=token_ref), 546), (p2pkh, 546)],
        ),
        # OP_RETURN at zero photons (the usual shape) and at 777 (where the value
        # is destroyed and the row header prints it).
        "op-return-values": _tx_payload([empty], [(op_return, 0), (op_return, 777), (p2pkh, 546)]),
        # Per-character Latin mimicry: Cyrillic "С" (U+0421) inside ASCII "USD".
        "homoglyph-mixed": _tx_payload([_reveal_scriptsig("USDС")], [(nft, 546)]),
        # An honest Japanese name. `_suspicious_reason` flags it "non-Latin
        # script" from a pure category test — no confusability check runs — and
        # the banner used to tell this token's holder it mimicked Latin letters.
        "homoglyph-non-latin": _tx_payload([_reveal_scriptsig("トークン")], [(nft, 546)]),
    }


@pytest.fixture(scope="module")
def tx_payloads() -> dict[str, dict]:
    return _tx_payloads()


@pytest.fixture(scope="module")
def tx_rendered(tx_payloads) -> dict[str, str]:
    """``{case: fetched-tx-card text}`` from the real JS."""
    cases = {name: {"tx": payload} for name, payload in tx_payloads.items()}
    return {name: out["fetched_tx_card"] for name, out in _run_harness(_require_node(), cases).items()}


# A key the tx card is ALLOWED to drop, with the reason. Same contract as the
# two tables above: anything not listed must appear in the rendered text.
_OMITTED_FROM_TX_CARD = {
    "form": "always 'txid' on this path — the card's title carries it",
    "outputs": "rendered as one row per output, and every field of every row is "
    "guarded field-by-field by test_output_row_renders_every_field. Demanding them "
    "again here would re-demand `hex` and `length`, which the rows omit on purpose",
}


class TestTheTxCardRendersEveryFieldToo:
    """The structural guard, one level up.

    ``renderFetchedTxCard`` had the same hole ``renderOutputRow`` had, for the
    same reason: nothing ran it. ``metadata_inputs`` and
    ``metadata.of_n_payloads`` were emitted by the Python and read by nobody, so
    one glyph's name, ticker and media were presented as the transaction's — on
    an observed mainnet reveal, for 34 refs out of 35.
    """

    @pytest.mark.parametrize("case", sorted(_tx_payloads()))
    def test_every_field_is_rendered(self, case, tx_payloads, tx_rendered):
        payload = tx_payloads[case]
        text = tx_rendered[case]
        lowered = text.lower()
        for key, value in payload.items():
            if key in _OMITTED_FROM_TX_CARD:
                continue
            for evidence in _required_evidence(key, value):
                assert evidence.lower() in lowered, (
                    f"renderFetchedTxCard dropped {key!r}={value!r} for case {case!r}. "
                    f"Expected {evidence!r} in the rendered card.\n"
                    f"If the omission is deliberate, add {key!r} to "
                    f"_OMITTED_FROM_TX_CARD with a reason.\n--- rendered ---\n{text}"
                )

    def test_the_interesting_keys_are_actually_exercised(self, tx_payloads):
        """The guard above is structural about FIELDS and hand-kept about CASES,
        which is exactly how the OP_RETURN payload keys slipped past its sibling.
        A case list that stops producing these keys makes it true and empty."""
        top = {key for payload in tx_payloads.values() for key, value in payload.items() if value}
        meta = {
            key
            for payload in tx_payloads.values()
            if payload.get("metadata")
            for key, value in payload["metadata"].items()
            if value
        }
        assert {"metadata", "metadata_inputs", "mint_scriptsig"} <= top
        assert {"of_n_payloads", "classification", "display_warnings", "timelock"} <= meta


class TestTheBurnBannerStopsAssertingAnOutcome:
    """``protocol.includes("6")`` is one operator-supplied integer in a CBOR
    envelope. It was rendered as two consensus-level facts."""

    def test_the_outcome_claims_are_gone(self, tx_rendered):
        text = tx_rendered["burn"]
        assert "removed from circulation" not in text
        assert "cannot reference the burned ref" not in text

    def test_it_says_what_the_marker_actually_is(self, tx_rendered):
        text = tx_rendered["burn"]
        assert "BURN marker (protocol = 6)" in text
        assert "purely a CBOR metadata flag" in text
        assert "does not verify" in text

    def test_the_fixture_really_hands_the_ref_back_out(self, tx_payloads, tx_rendered):
        """The setup is the finding. This transaction DECLARES a burn and still
        creates a live ref-carrying FT output — the case in which the old
        sentence was not merely unproven but wrong. A fixture without that
        output would have let the old wording look reasonable."""
        ft_rows = [row for row in tx_payloads["burn"]["outputs"] if row.get("type") == "ft"]
        assert len(ft_rows) == 1, "the fixture no longer carries the live ref it exists to carry"
        assert ft_rows[0]["ref_outpoint"] in tx_rendered["burn"]

    def test_the_sibling_markers_keep_their_wording(self, tx_rendered):
        """The other direction: the caveat BURN was missing already existed on
        its siblings, and this fix must not have moved it."""
        assert "metadata-layer convention" in tx_rendered["timelock"]


class TestAMultiGlyphRevealSaysWhichGlyph:
    """One payload per minted glyph; the Python reports the first and lists the
    rest. Under a bare heading, the first read as the transaction's own."""

    def test_the_heading_says_which_of_how_many(self, tx_payloads, tx_rendered):
        payload = tx_payloads["multi-glyph"]
        assert payload["metadata"]["of_n_payloads"] == 3, "the fixture stopped being a multi-glyph reveal"
        assert len(payload["metadata_inputs"]) == 3
        assert "1 of 3 glyphs minted here" in tx_rendered["multi-glyph"]

    def test_every_other_glyph_is_named(self, tx_rendered):
        text = tx_rendered["multi-glyph"]
        assert "Other glyphs minted in this transaction (2)" in text
        for name in ("Second", "TWO", "Third", "THREE"):
            assert name in text, f"{name!r} was minted here and the page does not say so"

    def test_a_one_glyph_reveal_gains_no_count_and_no_list(self, tx_payloads, tx_rendered):
        """The branch that was not built for. A count and an 'others' section on
        every ordinary single-glyph reveal is noise that costs more than it
        buys, and the CLI does not print one either."""
        assert "of_n_payloads" not in tx_payloads["single-glyph"]["metadata"]
        text = tx_rendered["single-glyph"]
        assert "Reveal metadata (from input 0)" in text
        assert "glyphs minted here" not in text
        assert "Other glyphs" not in text


class TestTheCommitNftNoteStopsClaimingAnFtDeploy:
    """The note was applied to EVERY commit-nft output and is false for the
    commonest one: the commit half of a plain NFT mint."""

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_ft_deploy_claim_is_gone(self, surface, rendered):
        text = rendered["commit-nft"][surface]
        assert "every Glyph FT deploy carries" not in text
        assert "separately-mintable collectible" not in text

    def test_it_states_what_the_bytes_do_say(self, rendered):
        text = rendered["commit-nft"]["script_card"]
        assert "OP_REFTYPE_OUTPUT = 2" in text
        assert "SINGLETON" in text

    def test_a_plain_nft_mint_really_does_produce_this_shape(self):
        """Why the old sentence was false, taken from the production builder
        rather than asserted: ``prepare_commit`` on NFT-only metadata emits bytes
        ``is_commit_nft_script`` matches. No FT anywhere."""
        from pyrxd.glyph.builder import CommitParams, GlyphBuilder
        from pyrxd.glyph.script import is_commit_ft_script, is_commit_nft_script
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.keys import PrivateKey

        pkh = PrivateKey().public_key().hash160()
        result = GlyphBuilder().prepare_commit(
            CommitParams(
                metadata=GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Just a collectible"),
                owner_pkh=pkh,
                change_pkh=pkh,
                funding_satoshis=100_000,
            )
        )
        assert is_commit_nft_script(result.commit_script.hex())
        assert not is_commit_ft_script(result.commit_script.hex())

    def test_the_ft_deploy_framing_survives_where_it_is_guarded(self, tx_rendered):
        """The claim is not wrong, it was unguarded. On the branch that has
        checked for a commit-ft beside the commit-nft it still stands."""
        text = tx_rendered["ft-deploy"]
        assert "Glyph FT deploy transaction" in text
        assert "every Glyph FT deploy carries" in text

    def test_the_page_does_not_contradict_its_own_nft_commit_banner(self, tx_rendered):
        """A commit-nft with no commit-ft: the tx banner calls it the anchor for
        an NFT or mutable contract, which is the opposite of what the per-output
        note used to say two inches below it."""
        assert "Glyph NFT or mutable contract" in tx_rendered["nft-commit-only"]
        assert "separately-mintable collectible" not in tx_rendered["nft-commit-only"]


class TestTheDmintDeployBannerComparesTheRowsItTalksAbout:
    """ "All sharing the same token_ref" and "total supply is reward × max_height
    × N" were produced by counting rows of type dmint. Every row carries all
    three fields."""

    def test_matching_contracts_are_called_matching(self, tx_rendered):
        text = tx_rendered["dmint-deploy-one-token"]
        assert "carry the same token_ref and agree on reward" in text
        assert "reward × max_height × 3" in text

    def test_different_token_refs_are_not_called_one_token(self, tx_payloads, tx_rendered):
        """The branch nobody built for: several dmint outputs that are NOT one
        token deployed in parallel. The banner said they were."""
        refs = {
            row["token_ref_outpoint"]
            for row in tx_payloads["dmint-deploy-mixed-refs"]["outputs"]
            if row.get("token_ref_outpoint")
        }
        assert len(refs) == 2, "the fixture stopped carrying two distinct token refs"
        text = tx_rendered["dmint-deploy-mixed-refs"]
        assert "do NOT all carry the same token_ref" in text
        assert "reward × max_height × 3" not in text

    def test_mismatched_terms_withhold_the_supply_formula(self, tx_payloads, tx_rendered):
        """Same token, different rewards — so no single reward × max_height × N
        describes the deploy, and the banner must not offer one."""
        rewards = {row["reward"] for row in tx_payloads["dmint-deploy-mixed-terms"]["outputs"] if "reward" in row}
        assert len(rewards) == 2, "the fixture stopped carrying two distinct rewards"
        text = tx_rendered["dmint-deploy-mixed-terms"]
        assert "carry the same token_ref" in text
        assert "not all equal" in text
        assert "the supply ceiling is reward × max_height × 3" not in text


class TestTheDmintClaimBannerLooksAtTheOutputs:
    """ "The freshly-minted FT lives in a separate ft output in this same tx" and
    "the canonical mint tx has 4 outputs" were stated for every claim tx."""

    def test_the_canonical_shape_is_confirmed_and_the_ft_located(self, tx_rendered):
        text = tx_rendered["dmint-claim-canonical"]
        assert "match the canonical mint shape" in text
        assert "The freshly-minted FT is the ft output at vout 1" in text

    def test_a_claim_tx_with_no_ft_output_says_so(self, tx_payloads, tx_rendered):
        """The branch that ships broken. This transaction has a dmint
        continuation and no reward output at all, and the page announced one."""
        types = [row.get("type") for row in tx_payloads["dmint-claim-no-ft"]["outputs"]]
        assert "ft" not in types, "the fixture stopped being the no-ft case"
        text = tx_rendered["dmint-claim-no-ft"]
        assert "has NO ft output" in text
        assert "do NOT match the canonical mint shape" in text
        assert "lives in a separate ft output" not in text

    def test_a_partial_outputs_list_decides_neither(self, tx_payloads, tx_rendered):
        """The third branch, and the one a fix invents for itself. This is the
        canonical claim tx with a reward output that DOES exist, classified one
        vout at a time — so "NO ft output" would be a fresh false claim made
        from an incomplete reading, in the sentence written to remove one."""
        payload = tx_payloads["dmint-claim-single-vout"]
        assert len(payload["outputs"]) == 1 and payload["output_count"] == 4, (
            "the fixture stopped being a partial classification"
        )
        text = tx_rendered["dmint-claim-single-vout"]
        assert "Only 1 of this transaction's 4 outputs were classified here" in text
        assert "has NO ft output" not in text
        assert "do NOT match the canonical mint shape" not in text
        assert "match the canonical mint shape" not in text


class TestTheOpReturnNoteStopsContradictingItsOwnHeader:
    """ "Does NOT carry value" sat six lines under a header printing
    ``<satoshis> sats``. For a funded OP_RETURN the interesting fact is the
    opposite of the sentence: those photons are destroyed."""

    def test_the_contradiction_is_gone_everywhere(self, rendered, tx_rendered):
        assert "Does NOT carry value" not in rendered["op_return"]["script_card"]
        assert "Does NOT carry value" not in rendered["op_return"]["output_row"]
        assert "Does NOT carry value" not in tx_rendered["op-return-values"]

    def test_a_funded_op_return_says_the_photons_are_destroyed(self, tx_rendered):
        text = tx_rendered["op-return-values"]
        assert "777 sats" in text, "the row header stopped printing the value the note answers"
        assert "carries 777 photons" in text
        assert "those photons are destroyed" in text

    def test_a_zero_value_op_return_says_that_instead(self, tx_rendered):
        """The other branch, and the common one — a warning that fires on every
        ordinary OP_RETURN is a warning nobody reads."""
        assert "carries no photons, which is the usual shape" in tx_rendered["op-return-values"]

    def test_a_pasted_script_makes_no_claim_about_a_value_it_cannot_see(self, rendered):
        """A standalone script has no ``satoshis`` at all, so neither sentence is
        available and the note must not invent one."""
        text = rendered["op_return"]["script_card"]
        assert "carries no photons" not in text
        assert "photons paid to one are destroyed" in text
        assert "paste the transaction to see what this output was funded with" in text


class TestTheHomoglyphBannerReflectsTheReasonItWasGiven:
    """The banner asserted Latin mimicry for every entry in
    ``display_warnings``. One producing branch — ``glue.py``
    ``_suspicious_reason`` — is a pure category test (every Letter is non-Latin,
    therefore flag) with no confusability check in it at all."""

    def test_a_mixed_script_name_is_still_flagged_as_mimicry(self, tx_payloads, tx_rendered):
        """The honest-path half. Cyrillic С inside ASCII USD is the attack the
        banner exists for, and it must still shout."""
        warnings = tx_payloads["homoglyph-mixed"]["metadata"]["display_warnings"]
        assert "mimic Latin letters" in warnings["name"], warnings
        text = tx_rendered["homoglyph-mixed"]
        assert "mimic Latin letters" in text, "the mimicry case must still shout"
        assert "may be imitating Latin ones" in text

    def test_an_honest_japanese_name_is_not_accused_of_mimicry(self, tx_payloads, tx_rendered):
        """The false positive. ``_suspicious_reason`` reports "non-Latin script"
        for any name whose letters are all non-Latin, so every token named in
        Japanese, Chinese or Arabic tripped a banner asserting it imitated Latin
        letters."""
        warnings = tx_payloads["homoglyph-non-latin"]["metadata"]["display_warnings"]
        assert warnings["name"].startswith("non-Latin script"), warnings
        text = tx_rendered["homoglyph-non-latin"]
        assert "contains characters that visually mimic Latin letters" not in text
        assert "non-Latin script" in text
        assert "not by itself evidence of a spoof" in text

    def test_the_banner_quotes_the_field_and_the_reason(self, tx_rendered):
        """Whatever the set of reasons becomes — a TR39 skeleton check lands in
        this same field — the banner states the one it was handed rather than a
        sentence written from one example of it."""
        assert "name: non-Latin script" in tx_rendered["homoglyph-non-latin"]
        # The mixed-script case is now reported by the TR39 SKELETON CHECK rather than
        # by `_suspicious_reason`'s script-mixing heuristic. Both fire on it; the
        # classifier's lands first and `glue.py` uses `setdefault`, so the more SPECIFIC
        # reason wins — which is the intended precedence, and the point of wiring TR39
        # at all. This assertion said "mixed scripts" until the two branches met.
        assert "name: characters that mimic Latin letters" in tx_rendered["homoglyph-mixed"]

    def test_a_clean_name_gets_no_banner_at_all(self, tx_payloads, tx_rendered):
        """The other direction, and the one that keeps the banner worth reading."""
        assert "display_warnings" not in tx_payloads["single-glyph"]["metadata"]
        assert "was flagged" not in tx_rendered["single-glyph"]


class TestTheTimelockSpecReachesTheReader:
    """The page carried a banner saying a TIMELOCK marker means the reveal is
    subject to a time condition, and rendered nothing about what the condition
    is — while the decoded spec sat in the payload."""

    def test_the_unlock_point_is_shown(self, tx_payloads, tx_rendered):
        spec = tx_payloads["timelock"]["metadata"]["timelock"]
        assert spec["unlock_at"] == 900_000, "the fixture stopped carrying a timelock"
        text = tx_rendered["timelock"]
        assert "opens at 900000 (block)" in text
        assert spec["cek_hash"] in text
        assert "opens after the halving" in text

    def test_no_unlocked_verdict_is_invented(self, tx_rendered):
        """Deciding it needs a chain tip for a block-mode lock. The Python
        withholds the verdict for that reason and so does the CLI; a browser
        clock would make it a guess wearing the clothes of a fact."""
        text = tx_rendered["timelock"]
        assert "is_unlocked" in text
        assert "UNLOCKED" not in text.upper().replace("IS_UNLOCKED", "")
        assert "LOCKED" not in text.upper().replace("IS_UNLOCKED", "")
