"""The spent commit a reveal names is the transaction that was asked for, every way of not
getting it says what happened, and checking it does not classify the transaction again.

``payload_binding`` answers "did the commit this reveal spent commit to the envelope shown?".
The page gets that commit on a second round trip to the one ElectrumX server it talks to, and
hands the bytes — or why it has none — to ``glue.spent_output_binding``, which asks
``pyrxd.glyph.inspect.spent_output_binding``. The CLI's ``--fetch`` asks the same function
(``tests/cli/test_glyph_inspect_spent_binding.py``). Three defects there:

* **Nothing checked the answer against the question.** A server asked for the commit could
  return any transaction — including one it built with a commit to the envelope on screen — and
  the page printed ``bound`` for a payload the real commit never committed to.
* **Every failure was swallowed**, so the classifier's "the spent output ... was not supplied"
  stood for a transaction that WAS asked for, and supplied or refused.
* **The step re-ran the whole classifier** to change one field of its metadata — every output
  classified again, on the page's main thread, for a transaction of any size.

The browser half (the page's fetch helper refusing a forged answer before it reaches Python, and
the page drawing what Python says) is ``test_inspect_fetch_flow.py``.
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


def _binding(reveal, prev_hex: object = "", prev_fetch_error: object = "") -> dict | None:
    """The page's own call, as ``onFetchTxid`` makes it."""
    result = _glue().spent_output_binding(reveal.txid(), reveal.serialize().hex(), prev_hex, prev_fetch_error)
    assert result["ok"], result
    return result["binding"]


def _core():
    from pyrxd.glyph import _inspect_core

    return _inspect_core


# ─────────────────────────────── the answer must be the transaction that was asked for ──


class TestTheSpentTransactionMustBeTheOneAskedFor:
    def test_the_real_commit_binds(self) -> None:
        """The honest path, and the neighbour of every refusal below."""
        commit, reveal = _commit_and_reveal("honest")
        assert _binding(reveal, commit.serialize().hex())["state"] == "bound"

    def test_the_real_commit_still_exposes_a_forged_envelope(self) -> None:
        """What the binding is FOR, through the page's entry point: the attack reads mismatch."""
        commit, reveal = _commit_and_reveal("EVIL", committed="real-token")
        assert _binding(reveal, commit.serialize().hex())["state"] == "mismatch"

    @pytest.mark.parametrize("shown, committed", [("honest", None), ("EVIL", "real-token")])
    def test_a_different_transaction_is_refused_not_read(self, shown, committed) -> None:
        """The reviewer's proof of concept, for a caller that is not the page's fetch helper (which
        refuses it first). The server, asked for the commit, returns a transaction of its own
        carrying a commit to the envelope ON SCREEN. It read ``bound`` — including for the attack,
        where the real commit committed to something else entirely."""
        commit, reveal = _commit_and_reveal(shown, committed)
        _, shown_cbor = _envelope(shown)
        forged = _tx([(_commit_script(shown_cbor), 999)])
        assert forged.txid() != commit.txid(), "the premise: the server answered with another transaction"

        binding = _binding(reveal, forged.serialize().hex())
        assert binding == {
            "state": "unchecked",
            "reason": _core().SPENT_TX_UNUSABLE,
            "detail": f"it is not the transaction this input spent: it hashes to {forged.txid()}",
        }


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
            ("zz", "the answer is not valid hex"),
            ("00" * 4_000_001, "hex characters, larger than any transaction"),
        ],
        ids=["not-hex", "over-the-cap"],
    )
    def test_an_answer_that_is_not_bytes_is_nothing_usable(self, prev_hex, detail) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(reveal, prev_hex)
        assert binding["state"] == "unchecked"
        assert binding["reason"] == _core().SPENT_TX_NOT_OBTAINED
        assert detail in binding["detail"]
        assert "was not supplied" not in binding["reason"]

    def test_bytes_that_hash_right_and_do_not_parse(self) -> None:
        junk = b"\x01\x00\x00\x00\xff"
        reveal = _junk_tx_spent_by_a_reveal(junk)
        binding = _binding(reveal, junk.hex())
        assert binding["state"] == "unchecked" and binding["reason"] == _core().SPENT_TX_UNUSABLE
        assert binding["detail"] == "it does not parse as a transaction", "the hash check is not what refused this one"

    def test_the_spent_transaction_has_no_such_output(self) -> None:
        """The right transaction, the wrong shape: the reveal names an output it does not have."""
        _, cbor = _envelope("honest")
        commit = _tx([(_commit_script(cbor), 1000)])
        reveal = _reveal_spending(commit.txid(), 3, "honest")
        binding = _binding(reveal, commit.serialize().hex())
        assert binding["state"] == "unchecked"
        assert binding["detail"] == "it has no output 3 (1 output(s))"

    def test_a_fetch_the_page_could_not_complete_says_the_page_asked(self) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        assert _binding(reveal, "", "server error: No such transaction") == {
            "state": "unchecked",
            "reason": _core().SPENT_TX_NOT_OBTAINED,
            "detail": "server error: No such transaction",
        }

    @pytest.mark.parametrize("prev_hex, err", [(None, None), ("", ""), ("   ", "")], ids=["js-null", "empty", "blank"])
    def test_nothing_handed_over_is_still_not_supplied_by_nobody(self, prev_hex, err) -> None:
        """The page only calls this after it ASKED. Handed nothing and no reason, it says that —
        not "was not supplied", which is the sentence for a caller that never asked."""
        _commit, reveal = _commit_and_reveal("honest")
        binding = _binding(reveal, prev_hex, err)
        assert binding["reason"] == _core().SPENT_TX_NOT_OBTAINED
        assert binding["detail"] == "the page handed over no spent transaction and no reason"

    def test_nobody_asked_still_reads_not_supplied(self) -> None:
        """The honest neighbour: where the classifier's sentence IS true — the first pass, before
        anything was fetched — it stays."""
        _commit, reveal = _commit_and_reveal("honest")
        result = _glue().inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex())
        binding = result["payload"]["metadata"]["payload_binding"]
        assert binding["state"] == "unchecked" and "was not supplied" in binding["reason"]
        assert "detail" not in binding

    def test_a_transaction_with_no_reveal_has_nothing_to_bind(self) -> None:
        plain = _tx([(b"\x6a" + b"\x00" * 20, 0)], [("ab" * 32, 0, b"\x00")])  # >64 bytes, like any real tx
        assert _binding(plain, "zz") is None
        assert _binding(plain, "", "server error: nope") is None

    def test_the_servers_words_are_sanitised_and_capped(self) -> None:
        _commit, reveal = _commit_and_reveal("honest")
        detail = _binding(reveal, "", "server error: \u202eevil\u200b" + "A" * 5000)["detail"]
        assert "\u202e" not in detail and "\u200b" not in detail
        assert "evil" in detail and len(detail) <= 201, "sanitised and capped at the display cap, not dropped"

    def test_the_transaction_itself_must_still_be_the_one_asked_for(self) -> None:
        """The reveal's own bytes are re-read here, so they get the first pass's checks again."""
        commit, reveal = _commit_and_reveal("honest")
        result = _glue().spent_output_binding("ab" * 32, reveal.serialize().hex(), commit.serialize().hex(), "")
        assert result["ok"] is False and "does not match the requested txid" in result["error"]


# ─────────────── the binding step is ONE field, and classifies nothing ──


def _signed(content: bytes) -> bytes:
    import hashlib

    from pyrxd.constants import genesis_hash_for
    from pyrxd.keys import PrivateKey
    from pyrxd.script.hashmark import encode_hashmark

    return encode_hashmark(hashlib.sha256(content).digest(), PrivateKey(), network_genesis=genesis_hash_for("mainnet"))


def _v1(i: int) -> bytes:
    return b"\x6a\x08HASHMARK\x02\x01\x01\x20" + bytes([i % 256]) * 32


_P2PKH = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
_SIG = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33


def _graft_shapes():
    """The five shapes the review checked the graft on, rebuilt: which input carries the
    headline, which vout of the commit it spends, what else the transactions carry."""
    s1, c1 = _envelope("head")
    s2, _c2 = _envelope("other")
    commit1 = _tx([(_P2PKH, 5), (_v1(1), 0), (_commit_script(c1), 1000)], [("cd" * 32, 0, b"\x00")])
    reveal1 = _tx(
        [(b"\x6a", 0)], [("ef" * 32, 0, b"\x00" * 80), (commit1.txid(), 2, _SIG + s1), ("aa" * 32, 0, _SIG + s2)]
    )
    commit2 = _tx([(_signed(b"x"), 0), (_v1(2), 0), (_commit_script(c1), 1000)], [("cd" * 32, 1, b"\x00")])
    reveal2 = _tx([(_signed(bytes([i % 256, i // 256])), 0) for i in range(150)], [(commit2.txid(), 2, _SIG + s1)])
    _, c_evil = _envelope("real-token")
    commit3 = _tx([(_commit_script(c_evil), 1000)], [("cd" * 32, 2, b"\x00")])
    reveal3 = _tx([(b"\x6a", 0)], [(commit3.txid(), 0, _SIG + s1)])
    commit4 = _tx([(_P2PKH, 1000)], [("cd" * 32, 3, b"\x00")])
    reveal4 = _tx([(b"\x6a", 0)], [(commit4.txid(), 0, _SIG + s1)])
    commit5 = _tx([(_commit_script(c1), 1000)], [("cd" * 32, 4, b"\x00")])
    reveal5 = _tx([], [(commit5.txid(), 0, _SIG + s1)])
    return {
        "headline-at-input-1-spends-vout-2": (reveal1, commit1, "bound"),
        "150-signed-marks-and-a-marked-commit": (reveal2, commit2, "bound"),
        "mismatch": (reveal3, commit3, "mismatch"),
        "not-a-commit": (reveal4, commit4, "not-a-commit"),
        "zero-output-reveal": (reveal5, commit5, "bound"),
    }


class TestTheBindingStepIsOneFieldNotASecondInspect:
    @pytest.mark.parametrize("shape", sorted(_graft_shapes()))
    def test_it_equals_a_full_reclassification(self, shape) -> None:
        """What the page used to do — re-run the whole classifier with the spent script — and what
        it does now must agree, field for field, on every shape: the first pass with its binding
        replaced is the full re-run. If ``spent_scripts`` ever changes another field, or the
        attribution rule drifts from the binding's, this fails."""
        from pyrxd.glyph import inspect as facade
        from pyrxd.transaction.transaction import Transaction

        reveal, commit, state = _graft_shapes()[shape]
        glue = _glue()
        first = glue.inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex())
        binding = _binding(reveal, commit.serialize().hex())
        assert binding["state"] == state
        first["payload"]["metadata"]["payload_binding"] = binding

        md = first["payload"]["metadata"]
        _prev, _, vout = md["input_outpoint"].rpartition(":")
        spent = bytes(Transaction.from_hex(commit.serialize()).outputs[int(vout)].locking_script.serialize())
        full = facade.classify_raw_tx(
            reveal.txid(), reveal.serialize(), network="mainnet", spent_scripts={md["input_index"]: spent}
        )
        assert first["payload"] == glue._sanitize_payload_strings(full)

    def test_it_classifies_no_output_and_checks_no_signature(self, monkeypatch) -> None:
        """The cost the review measured: the second call re-ran every output's classification.
        The binding reads one input and one spent output; nothing else is classified."""
        core = _core()
        calls = {"script": 0, "attest": 0}
        real_script, real_attest = core._classify_script, core.verify_attestation

        def counting_script(*a, **kw):
            calls["script"] += 1
            return real_script(*a, **kw)

        def counting_attest(*a, **kw):
            calls["attest"] += 1
            return real_attest(*a, **kw)

        monkeypatch.setattr(core, "_classify_script", counting_script)
        monkeypatch.setattr(core, "verify_attestation", counting_attest)
        reveal, commit, _state = _graft_shapes()["150-signed-marks-and-a-marked-commit"]
        assert _binding(reveal, commit.serialize().hex())["state"] == "bound"
        assert calls == {"script": 0, "attest": 0}, calls
        # The counters count: the same patch sees the first pass classify.
        _glue().inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex(), 2, 2)
        assert calls["script"] == 150 and calls["attest"] == 2, calls


class TestTheBindingStepReadsOnlyTheInputs:
    """It never parses an output of the reveal — a 4 MB transaction is mostly outputs — so it reads
    the inputs itself. That read must be the whole transaction's, input for input."""

    @pytest.mark.parametrize("shape", sorted(_graft_shapes()))
    def test_the_inputs_are_the_whole_parses_inputs(self, shape) -> None:
        from pyrxd.transaction.transaction import Transaction

        for tx in _graft_shapes()[shape][:2]:
            raw = tx.serialize()
            got = _core()._checked_inputs(tx.txid(), raw)
            whole = Transaction.from_hex(raw).inputs
            assert [i.serialize() for i in got] == [i.serialize() for i in whole]
            assert len(got) == len(whole) > 0

    def test_a_transaction_that_is_not_the_one_named_is_refused(self) -> None:
        from pyrxd.security.errors import ValidationError

        commit, reveal = _commit_and_reveal("honest")
        with pytest.raises(ValidationError, match="does not match the requested txid"):
            _core()._checked_inputs(commit.txid(), reveal.serialize())

    def test_truncated_inputs_are_refused_not_read_short(self) -> None:
        """Bytes that hash to the txid named cannot be truncated, so this reaches the parser only
        by naming the truncated bytes' own hash: the read must still refuse them."""
        from pyrxd.hash import hash256
        from pyrxd.security.errors import ValidationError

        _commit, reveal = _commit_and_reveal("honest")
        cut = reveal.serialize()[:90]
        with pytest.raises(ValidationError, match="could not parse"):
            _core()._checked_inputs(hash256(cut)[::-1].hex(), cut)

    def test_the_outputs_are_never_parsed(self, monkeypatch) -> None:
        from pyrxd.transaction import transaction_output

        calls = []
        real = transaction_output.TransactionOutput.from_hex.__func__

        def counting(cls, stream):
            calls.append(1)
            return real(cls, stream)

        reveal, commit, _state = _graft_shapes()["150-signed-marks-and-a-marked-commit"]
        monkeypatch.setattr(transaction_output.TransactionOutput, "from_hex", classmethod(counting))
        assert _binding(reveal, commit.serialize().hex())["state"] == "bound"
        assert len(calls) == 3, f"{len(calls)} outputs parsed: the spent transaction has 3, the reveal none"
