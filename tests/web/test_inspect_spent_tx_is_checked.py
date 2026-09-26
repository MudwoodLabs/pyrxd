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


def _minted(source_txid: str, vout: int) -> bytes:
    """The singleton an NFT commit at *source_txid*:*vout* demands its reveal create."""
    from pyrxd.glyph.script import build_nft_locking_script
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.security.types import Hex20

    return build_nft_locking_script(Hex20(b"\x33" * 20), GlyphRef(txid=source_txid, vout=vout))


def _reveal_spending(source_txid: str, vout: int, shown: str, extra_outputs: tuple[bytes, ...] = (), *, mint=True):
    """A reveal of *shown* spending *source_txid*:*vout*. With ``mint`` (the default) its first output
    is the singleton an NFT commit there demands — without it, no node accepts the spend, and
    ``payload_binding`` says so (``commit-unsatisfied``) rather than ``bound``."""
    suffix, _ = _envelope(shown)
    unlocking = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + suffix
    first = (_minted(source_txid, vout), 1) if mint else (b"\x6a", 0)
    return _tx([first, *((s, 0) for s in extra_outputs)], [(source_txid, vout, unlocking)])


def _commit_and_reveal(shown: str, committed: str | None = None, extra_outputs: tuple[bytes, ...] = (), *, mint=True):
    """A reveal spending a real commit output. ``committed`` differing from ``shown`` is a spend no
    node accepts — the commit hashes the payload it is handed — so it models bytes that were never
    mined, which is what ``mismatch`` reports."""
    _, committed_cbor = _envelope(committed if committed is not None else shown)
    commit = _tx([(_commit_script(committed_cbor), 1000)])
    return commit, _reveal_spending(commit.txid(), 0, shown, extra_outputs, mint=mint)


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
        """Through the page's entry point: an envelope its commit did not commit to reads mismatch.
        No node accepts that spend, so this models bytes that were never mined — pasted, or served
        for a txid no block holds. The decoy a node DOES accept is in
        ``tests/test_reveal_metadata_says_what_binds_it.py``."""
        commit, reveal = _commit_and_reveal("EVIL", committed="real-token")
        assert _binding(reveal, commit.serialize().hex())["state"] == "mismatch"

    def test_a_reveal_that_creates_nothing_is_unsatisfied_not_bound(self) -> None:
        """The hash matches, and the commit's ``OP_REFTYPE_OUTPUT`` demand is not met. This is what
        every fixture in this file used to be, reading ``bound``."""
        commit, reveal = _commit_and_reveal("honest", mint=False)
        assert _binding(reveal, commit.serialize().hex())["state"] == "commit-unsatisfied"

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
    headline, which vout of the commit it spends, what else the transactions carry — and one
    for each state the 0.25.0 panel's fix added. A reveal expected to read ``bound`` mints the
    singleton its NFT commit demands; before that panel none of them did, and every one of those
    was a spend no node accepts, reading ``bound``."""
    from pyrxd.glyph.payload import build_dat_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.script import build_dat_commit_locking_script
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
    from pyrxd.hash import hash256
    from pyrxd.security.types import Hex20

    s1, c1 = _envelope("head")
    s2, _c2 = _envelope("other")
    commit1 = _tx([(_P2PKH, 5), (_v1(1), 0), (_commit_script(c1), 1000)], [("cd" * 32, 0, b"\x00")])
    reveal1 = _tx(
        [(b"\x6a", 0), (_minted(commit1.txid(), 2), 1)],
        [("ef" * 32, 0, b"\x00" * 80), (commit1.txid(), 2, _SIG + s1), ("aa" * 32, 0, _SIG + s2)],
    )
    commit2 = _tx([(_signed(b"x"), 0), (_v1(2), 0), (_commit_script(c1), 1000)], [("cd" * 32, 1, b"\x00")])
    reveal2 = _tx(
        [(_signed(bytes([i % 256, i // 256])), 0) for i in range(150)] + [(_minted(commit2.txid(), 2), 1)],
        [(commit2.txid(), 2, _SIG + s1)],
    )
    _, c_evil = _envelope("real-token")
    commit3 = _tx([(_commit_script(c_evil), 1000)], [("cd" * 32, 2, b"\x00")])
    reveal3 = _tx([(_minted(commit3.txid(), 0), 1)], [(commit3.txid(), 0, _SIG + s1)])
    commit4 = _tx([(_P2PKH, 1000)], [("cd" * 32, 3, b"\x00")])
    reveal4 = _tx([(b"\x6a", 0)], [(commit4.txid(), 0, _SIG + s1)])
    commit5 = _tx([(_commit_script(c1), 1000)], [("cd" * 32, 4, b"\x00")])
    reveal5 = _tx([], [(commit5.txid(), 0, _SIG + s1)])
    dat, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.DAT], name="data"))
    commit6 = _tx(
        [(build_dat_commit_locking_script(hash256(dat), Hex20(b"\x44" * 20)), 1000)], [("cd" * 32, 5, b"\x00")]
    )
    reveal6 = _tx([(_P2PKH, 900)], [(commit6.txid(), 0, _SIG + build_dat_reveal_scriptsig_suffix(dat))])
    return {
        "headline-at-input-1-spends-vout-2": (reveal1, commit1, "bound"),
        "150-signed-marks-and-a-marked-commit": (reveal2, commit2, "bound"),
        "mismatch": (reveal3, commit3, "mismatch"),
        "not-a-commit": (reveal4, commit4, "not-a-commit"),
        "zero-output-reveal": (reveal5, commit5, "commit-unsatisfied"),
        "dat-commit": (reveal6, commit6, "bound-no-token"),
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
        The binding reads one input, one spent output, and the reveal's output SCRIPTS for one ref;
        nothing is classified."""
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
        assert calls["script"] == len(reveal.outputs) == 151 and calls["attest"] == 2, calls


class TestTheBindingStepReadsOnlyTheInputs:
    """It never parses an output of the reveal — a 4 MB transaction is mostly outputs — so it reads
    the inputs itself. That read must be the whole transaction's, input for input. The output
    SCRIPTS it does need (is the commit's ref created?) are sliced out of the bytes the walk
    already steps over; ``test_the_output_scripts_are_the_whole_parses_scripts`` pins them."""

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

    @pytest.mark.parametrize("shape", sorted(_graft_shapes()))
    def test_the_output_scripts_are_the_whole_parses_scripts(self, shape) -> None:
        """What the binding scans for the commit's ref is every output script, byte for byte, in
        order — the set ``OP_REFTYPE_OUTPUT`` reads — though no output object is built for it."""
        from pyrxd.transaction.transaction import Transaction

        for tx in _graft_shapes()[shape][:2]:
            raw = tx.serialize()
            _inputs, spans = _core()._checked_inputs_and_output_spans(tx.txid(), raw)
            whole = [bytes(o.locking_script.serialize()) for o in Transaction.from_hex(raw).outputs]
            assert [raw[start:end] for start, end in spans] == whole


# ─────────────── the bytes after the inputs are walked, not trusted ──
#
# `_checked_inputs` is reachable from outside through the public
# `pyrxd.glyph.inspect.spent_output_binding`, and it used to stop reading after the inputs,
# relying on its callers having parsed the whole transaction first. A guard beside the operation
# rather than inside it: called directly, it answered `bound` for bytes no parser accepts.


def _malformed_after_the_inputs() -> dict[str, bytes]:
    """The review's table: a well-formed reveal, then each way of breaking what follows its
    inputs, plus a non-canonical input count."""
    from pyrxd.transaction.transaction import Transaction

    # A one-byte OP_RETURN output, which the offsets below are computed for. Its binding is beside
    # the point: these bytes are refused before anything reads it.
    _commit, reveal = _commit_and_reveal("honest", mint=False)
    good = reveal.serialize()
    tx = Transaction.from_hex(good)
    assert len(tx.inputs) == 1 and len(tx.outputs) == 1, "the fixture's layout changed; recompute the offsets"
    in_end = 4 + 1 + len(tx.inputs[0].serialize())
    return {
        "trailing-garbage": good + b"\xde\xad\xbe\xef",
        "output-count-5-with-1-present": good[:in_end] + b"\x05" + good[in_end + 1 :],
        "outputs-section-missing": good[:in_end],
        "output-count-2**64-1": good[:in_end] + b"\xff" + b"\xff" * 8 + good[in_end + 1 :],
        "script-length-over-claims": good[:in_end] + b"\x01" + b"\x00" * 8 + b"\x40" + good[in_end + 10 :],
        "locktime-short": good[:-1],
        "non-canonical-input-count": good[:4] + b"\xfd\x01\x00" + good[5:],
    }


class TestTheBytesAfterTheInputsAreWalked:
    @pytest.mark.parametrize("case", sorted(_malformed_after_the_inputs()))
    def test_what_a_whole_parse_refuses_is_refused(self, case) -> None:
        from pyrxd.glyph import inspect as facade
        from pyrxd.hash import hash256
        from pyrxd.security.errors import ValidationError
        from pyrxd.transaction.transaction import Transaction

        raw = _malformed_after_the_inputs()[case]
        txid = hash256(raw)[::-1].hex()
        assert Transaction.from_hex(raw) is None, "the premise: a whole parse refuses these bytes"
        with pytest.raises(ValidationError, match="could not parse|safety caps|non-canonical"):
            _core()._checked_inputs(txid, raw)
        # Through the public function the review called, and through the page's bridge.
        commit, _reveal = _commit_and_reveal("honest")
        with pytest.raises(ValidationError):
            facade.spent_output_binding(txid, raw, commit.serialize())
        refused = _glue().spent_output_binding(txid, raw.hex(), commit.serialize().hex(), "")
        assert refused["ok"] is False, refused

    def test_a_well_formed_transaction_is_still_bound(self) -> None:
        """The honest neighbour of every refusal above, through the same public function."""
        from pyrxd.glyph import inspect as facade

        commit, reveal = _commit_and_reveal("honest")
        assert facade.spent_output_binding(reveal.txid(), reveal.serialize(), commit.serialize())["state"] == "bound"

    def test_more_outputs_than_the_cap_are_refused_as_the_classifier_refuses_them(self) -> None:
        """Bytes a whole parse ACCEPTS and `_checked_transaction` refuses on its output cap. The
        walk applies the same cap, so the binding step does not answer for a transaction the
        classifier would not look at."""
        from pyrxd.hash import hash256
        from pyrxd.security.errors import ValidationError
        from pyrxd.transaction.transaction import Transaction

        n = _core()._MAX_OUTPUT_COUNT + 1
        raw = (1).to_bytes(4, "little") + b"\x00" + b"\xfe" + n.to_bytes(4, "little") + b"\x00" * 9 * n + b"\x00" * 4
        txid = hash256(raw)[::-1].hex()
        assert len(Transaction.from_hex(raw).outputs) == n, "the premise: these bytes parse whole"
        with pytest.raises(ValidationError, match="safety caps") as whole:
            _core()._checked_transaction(txid, raw)
        with pytest.raises(ValidationError, match="safety caps") as walked:
            _core()._checked_inputs(txid, raw)
        assert f"outputs={n}" in str(whole.value) and f"outputs={n}" in str(walked.value)

    def test_the_walk_agrees_with_a_whole_parse_on_mutated_bytes(self) -> None:
        """Not only the review's table: a seeded sweep of byte flips, cuts, insertions, deletions
        and varint prefixes over transactions with no inputs, no outputs, 0xfd-wide lengths and
        counts. The walk must refuse exactly what `Transaction.from_hex` plus the caps refuse, and
        where both accept, read the same inputs. Counted both ways, so a sweep in which every
        case is refused (or none is) cannot pass by being one-sided."""
        import random

        from pyrxd.hash import hash256
        from pyrxd.security.errors import ValidationError
        from pyrxd.transaction.transaction import Transaction

        rng = random.Random(20260923)

        def raw_tx(n_in: int, outs: list[tuple[bytes, int]]) -> bytes:
            # One push of random bytes: a well-formed script whose length varies.
            pushes = [bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 75))) for _ in range(n_in)]
            ins = [(f"{rng.getrandbits(256):064x}", i, bytes([len(p)]) + p) for i, p in enumerate(pushes)]
            return _tx(outs, ins).serialize()

        bases = [
            raw_tx(1, [(_P2PKH, 5)]),
            raw_tx(2, [(b"\x51" * rng.randint(0, 300), rng.randint(0, 10**9)) for _ in range(12)]),
            raw_tx(3, []),
            raw_tx(0, [(b"\x6a", 0)] * 3),
            raw_tx(1, [(b"\x51" * 300, 1)] * 2),
            raw_tx(1, [(b"", 0)] * 300),
        ]
        caps = (_core()._MAX_INPUT_COUNT, _core()._MAX_OUTPUT_COUNT)

        # Inputs AND output scripts: the binding reads both out of the walk.
        def whole(raw: bytes):
            tx = Transaction.from_hex(raw)
            if tx is None or len(tx.inputs) > caps[0] or len(tx.outputs) > caps[1]:
                return None
            return [i.serialize() for i in tx.inputs], [bytes(o.locking_script.serialize()) for o in tx.outputs]

        def walked(raw: bytes):
            try:
                inputs, spans = _core()._checked_inputs_and_output_spans(hash256(raw)[::-1].hex(), raw)
            except ValidationError:
                return None
            return [i.serialize() for i in inputs], [raw[start:end] for start, end in spans]

        def mutate(b: bytes) -> bytes:
            out = bytearray(b)
            op = rng.randrange(6)
            if op == 0:
                out[rng.randrange(len(out))] = rng.randrange(256)
            elif op == 1:
                del out[rng.randrange(len(out) + 1) :]
            elif op == 2:
                at = rng.randrange(len(out) + 1)
                out[at:at] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 9)))
            elif op == 3:
                at = rng.randrange(len(out))
                del out[at : at + rng.randint(1, 9)]
            elif op == 4:
                out += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 5)))
            else:
                out[rng.randrange(len(out))] = rng.choice([0x00, 0xFC, 0xFD, 0xFE, 0xFF])
            return bytes(out)

        accepted = refused = 0
        for _ in range(3000):
            raw = rng.choice(bases)
            for _ in range(rng.randint(0, 3)):
                raw = mutate(raw) if raw else raw
            if len(raw) <= 64:  # refused by the hash binding before either reader runs
                continue
            expected, got = whole(raw), walked(raw)
            assert got == expected, f"the walk and a whole parse disagree on {raw.hex()[:160]}…"
            accepted += got is not None
            refused += got is None
        assert accepted > 300 and refused > 300, (accepted, refused)
