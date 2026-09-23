"""The browser's SECOND fetch — the spent commit — is the transaction it was asked for, and
every way it can fail says what happened.

``payload_binding`` answers "did the commit this reveal spent commit to the envelope shown?".
The page gets that commit on a second round trip to the one ElectrumX server it talks to, and
hands the bytes to ``glue.inspect_txid_with_raw(..., prev_raw_hex=...)``. Two defects there:

* **Nothing checked the answer against the question.** The first fetch is hash-checked
  (``classify_raw_tx`` refuses a transaction whose hash is not the txid asked for) and the CLI's
  client hash-checks every fetch; this one was not. A server asked for the commit could return
  any transaction — including one it built with a commit to the envelope on screen — and the
  page printed ``bound`` for a payload the real commit never committed to.
* **Every failure was swallowed** (``except Exception: pass``), so the classifier's "the spent
  output ... was not supplied" stood for a transaction that WAS supplied and failed.

Everything here goes through ``inspect_txid_with_raw`` — the page's own entry point — because
no test reached ``prev_raw_hex`` at all before this file. The browser half (the page's fetch
helper refusing the forged answer before it reaches Python, and the page telling Python why)
is ``test_inspect_fetch_flow.py``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY (inside functions): ``test_inspect_imports_pyodide_clean`` pops
# ``pyrxd.*`` out of ``sys.modules`` and can run either side of this file. See the note in
# ``test_inspect_js_render_drift.py``.

_GLUE = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "inspect" / "glue.py"


def _glue():
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_spent", _GLUE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_spent"] = module
    spec.loader.exec_module(module)
    return module


def _envelope(name: str) -> tuple[bytes, bytes]:
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

    cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
    return build_reveal_scriptsig_suffix(cbor), cbor


def _commit_script(cbor: bytes) -> bytes:
    from pyrxd.glyph.script import build_commit_locking_script
    from pyrxd.hash import hash256
    from pyrxd.security.types import Hex20

    return build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=True)


def _tx(outputs: list[tuple[bytes, int]], inputs: list[tuple[str, int, bytes]] | None = None):
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), v) for s, v in outputs])
    ins = []
    for source_txid, vout, unlocking in inputs or []:
        inp = TransactionInput(source_txid=source_txid, source_output_index=vout)
        inp.unlocking_script = Script(unlocking)
        ins.append(inp)
    tx.inputs = ins
    return tx


def _reveal_spending(source_txid: str, vout: int, shown: str, extra_outputs: tuple[bytes, ...] = ()):
    suffix, _ = _envelope(shown)
    unlocking = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + suffix
    return _tx([(b"\x6a", 0), *((s, 0) for s in extra_outputs)], [(source_txid, vout, unlocking)])


def _commit_and_reveal(shown: str, committed: str | None = None, extra_outputs: tuple[bytes, ...] = ()):
    """A reveal spending a real commit output. ``committed`` differing = the attack the binding
    exists to catch: the envelope on screen is not the one the commit committed to."""
    _, committed_cbor = _envelope(committed if committed is not None else shown)
    commit = _tx([(_commit_script(committed_cbor), 1000)])
    return commit, _reveal_spending(commit.txid(), 0, shown, extra_outputs)


def _inspect(reveal, prev_hex: str = "", limit=None, prev_fetch_error: str = "") -> dict:
    result = _glue().inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex(), prev_hex, limit, prev_fetch_error)
    assert result["ok"], result
    return result


def _binding(result: dict) -> dict:
    return result["payload"]["metadata"]["payload_binding"]


# ─────────────────────────────── the answer must be the transaction that was asked for ──


class TestTheSpentTransactionMustBeTheOneAskedFor:
    def test_the_real_commit_binds(self) -> None:
        """The honest path, and the neighbour of every refusal below."""
        commit, reveal = _commit_and_reveal("honest")
        assert _binding(_inspect(reveal, commit.serialize().hex()))["state"] == "bound"

    def test_the_real_commit_still_exposes_a_forged_envelope(self) -> None:
        """What the binding is FOR, through the page's entry point: the attack reads mismatch."""
        commit, reveal = _commit_and_reveal("EVIL", committed="real-token")
        result = _inspect(reveal, commit.serialize().hex())
        assert result["payload"]["metadata"]["name"] == "EVIL", "the decoy is still what is displayed"
        assert _binding(result)["state"] == "mismatch"

    @pytest.mark.parametrize("shown, committed", [("honest", None), ("EVIL", "real-token")])
    def test_a_different_transaction_is_refused_not_read(self, shown, committed) -> None:
        """The reviewer's proof of concept. The server, asked for the commit, returns a transaction
        of its own carrying a commit to the envelope ON SCREEN. It read ``bound`` — including for
        the attack, where the real commit committed to something else entirely."""
        commit, reveal = _commit_and_reveal(shown, committed)
        _, shown_cbor = _envelope(shown)
        forged = _tx([(_commit_script(shown_cbor), 999)])
        assert forged.txid() != commit.txid(), "the premise: the server answered with another transaction"

        binding = _binding(_inspect(reveal, forged.serialize().hex()))
        assert binding["state"] == "unchecked", binding
        assert binding["reason"] == _glue()._SPENT_REFUSED
        assert binding["detail"] == (f"it is not the transaction this input spent: it hashes to {forged.txid()}")


# ──────────────────────────────── every failure says what happened, never "not supplied" ──


def _junk_tx_spent_by_a_reveal(junk: bytes):
    """A reveal whose input spends the txid of ``junk`` — so the hash check PASSES and what is
    tested is the next step. Without this, every unparseable input would stop at the hash."""
    from pyrxd.hash import hash256

    return _reveal_spending(hash256(junk)[::-1].hex(), 0, "honest")


class TestEveryFailureSaysWhatHappened:
    @pytest.mark.parametrize(
        "prev_hex, detail",
        [
            ("zz", "it is not valid hex"),
            ("   ", "it is empty"),
            ("00" * 4_000_001, "hex characters, larger than any transaction"),
        ],
        ids=["not-hex", "blank", "over-the-cap"],
    )
    def test_unreadable_bytes(self, prev_hex, detail) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(_inspect(reveal, prev_hex))
        assert binding["state"] == "unchecked"
        assert binding["reason"] == _glue()._SPENT_REFUSED
        assert detail in binding["detail"]
        assert "was not supplied" not in binding["reason"], "it WAS supplied"

    def test_bytes_that_hash_right_and_do_not_parse(self) -> None:
        junk = b"\x01\x00\x00\x00\xff"
        reveal = _junk_tx_spent_by_a_reveal(junk)
        binding = _binding(_inspect(reveal, junk.hex()))
        assert binding["state"] == "unchecked" and binding["reason"] == _glue()._SPENT_REFUSED
        assert binding["detail"] == "it does not parse as a transaction", "the hash check is not what refused this one"

    def test_the_spent_transaction_has_no_such_output(self) -> None:
        """The right transaction, the wrong shape: the reveal names an output it does not have."""
        _, cbor = _envelope("honest")
        commit = _tx([(_commit_script(cbor), 1000)])
        reveal = _reveal_spending(commit.txid(), 3, "honest")
        binding = _binding(_inspect(reveal, commit.serialize().hex()))
        assert binding["state"] == "unchecked"
        assert binding["detail"] == "it has no output 3 (1 output(s))"

    def test_a_fetch_the_page_could_not_complete_says_the_page_asked(self) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(_inspect(reveal, "", prev_fetch_error="server error: No such transaction"))
        assert binding == {
            "state": "unchecked",
            "reason": _glue()._SPENT_NOT_OBTAINED,
            "detail": "server error: No such transaction",
        }

    def test_nobody_asked_still_reads_not_supplied(self) -> None:
        """The honest neighbour: where the classifier's sentence IS true, it stays."""
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(_inspect(reveal))
        assert binding["state"] == "unchecked"
        assert "was not supplied" in binding["reason"]
        assert "detail" not in binding

    def test_a_failure_leaves_the_rest_of_the_report_standing(self) -> None:
        _commit, reveal = _commit_and_reveal("still-true")
        result = _inspect(reveal, "zz")
        assert result["payload"]["metadata"]["name"] == "still-true"
        assert [row["vout"] for row in result["payload"]["outputs"]] == [0]

    @pytest.mark.parametrize("prev_hex, err", [("zz", ""), ("", "server error: nope")])
    def test_a_transaction_with_no_reveal_is_untouched(self, prev_hex, err) -> None:
        """Nothing attributed, nothing to bind: whatever the page says about a spent transaction,
        a transaction carrying no reveal gains no binding verdict at all."""
        plain = _tx([(b"\x6a" + b"\x00" * 20, 0)], [("ab" * 32, 0, b"\x00")])  # >64 bytes, like any real tx
        result = _inspect(plain, prev_hex, prev_fetch_error=err)
        assert result["payload"]["metadata"] is None

    def test_the_servers_words_are_sanitised_like_every_other_string(self) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(_inspect(reveal, "", prev_fetch_error="server error: ‮evil​"))
        assert "‮" not in binding["detail"] and "​" not in binding["detail"]
        assert "evil" in binding["detail"]

    def test_javascript_null_is_nothing_supplied_not_a_refusal(self) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        result = _glue().inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex(), None)
        assert result["ok"], result
        assert "was not supplied" in _binding(result)["reason"]


# ─────────────── the second step is ONE field, and costs no second round of signature checks ──


def _signed(content: bytes) -> bytes:
    import hashlib

    from pyrxd.constants import genesis_hash_for
    from pyrxd.keys import PrivateKey
    from pyrxd.script.hashmark import encode_hashmark

    return encode_hashmark(hashlib.sha256(content).digest(), PrivateKey(), network_genesis=genesis_hash_for("mainnet"))


class TestTheSecondStepIsOneFieldNotASecondInspect:
    @pytest.mark.parametrize("shown, committed", [("honest", None), ("EVIL", "real-token")])
    def test_it_equals_a_full_reclassification(self, shown, committed) -> None:
        """What the page used to do — re-run the whole classifier with the spent script — and what
        it does now — take ``payload_binding`` from a one-output, no-signature pass — must produce
        the same report. If ``spent_scripts`` ever changes another field, this fails."""
        from pyrxd.glyph import inspect as facade
        from pyrxd.transaction.transaction import Transaction

        marks = (_signed(b"a"), _signed(b"b"))
        commit, reveal = _commit_and_reveal(shown, committed, extra_outputs=marks)
        glue = _glue()
        got = glue.inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex(), commit.serialize().hex())
        spent = bytes(Transaction.from_hex(commit.serialize()).outputs[0].locking_script.serialize())
        full = facade.classify_raw_tx(reveal.txid(), reveal.serialize(), network="mainnet", spent_scripts={0: spent})
        assert got["payload"] == glue._sanitize_payload_strings(full)

    def test_supplying_the_spent_transaction_checks_no_signature_twice(self, monkeypatch) -> None:
        from pyrxd.glyph import _inspect_core

        calls: list = []
        real = _inspect_core.verify_attestation

        def counting(record, **kw):
            calls.append(1)
            return real(record, **kw)

        monkeypatch.setattr(_inspect_core, "verify_attestation", counting)
        marks = tuple(_signed(bytes([i])) for i in range(3))
        commit, reveal = _commit_and_reveal("honest", extra_outputs=marks)
        result = _inspect(reveal, commit.serialize().hex(), limit=2)
        assert _binding(result)["state"] == "bound"
        assert len(calls) == 2, f"{len(calls)} signature checks for a limit of 2"
        outcomes = [
            (r.get("hashmark") or {}).get("attestation", {}).get("outcome") for r in result["payload"]["outputs"]
        ]
        assert outcomes == [None, "valid", "valid", "not_checked_here"]
