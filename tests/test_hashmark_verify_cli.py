"""``pyrxd verify`` — the read half, driven through the real click command.

`pyrxd mark` publishes a signed record; `pyrxd glyph inspect --fetch` classifies one. Neither
answers the question a human actually arrives with: *is THIS file what was marked, by whom, and
in which block?* This file drives that command end to end, with one fake standing in for
ElectrumX and everything else — the decoder, `verify_attestation`, the §7.6 machinery, the
anchor, the renderer — real.

WHAT IS FAKED AND WHAT IS NOT. The transport is. The record is not: every mark below is built
by :func:`~pyrxd.hashmark_tx.plan_hashmark` over a freshly generated key, serialised into a
real :class:`~pyrxd.transaction.transaction.Transaction`, and read back out of those bytes by
the classifier — the txid the fake answers to is the sha256d of the bytes it returns, because
the classifier checks that and would refuse otherwise. So the signature each case verifies (or
refuses) is a signature, not a fixture that says "valid".

ONE THING THIS FILE CANNOT PROVE, and it is worth stating rather than leaving as a gap in the
coverage: the §7.6 form-2 AFFIRMATIVE — *the name pointed at the signing key at that block*.
Reaching it through the command needs a mark whose signer is the key behind a specific mainnet
address in the chain fixture, and producing one means forging ECDSA. The form-2 path IS reached
here (`TestFormTwoThroughTheCommand`) and returns the definite negative; the affirmative is
covered against :func:`~pyrxd.cli.hashmark_cmds._name_check` directly, and the composition of
the two is what is untested.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_inspect, hashmark_cmds
from pyrxd.cli.context import CliContext
from pyrxd.cli.hashmark_cmds import (
    EXIT_VERDICT_DOES_NOT_HOLD,
    _block_check,
    _digest_match_lines,
    _name_check,
    _signature_check,
    judge_digest_match,
)
from pyrxd.cli.main import cli
from pyrxd.constants import genesis_hash_for
from pyrxd.hashmark_tx import digest_file, plan_hashmark
from pyrxd.keys import PrivateKey
from pyrxd.script.hashmark import _ALGORITHMS, decode_hashmark
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

MAINNET_GENESIS = genesis_hash_for("mainnet")
TIP = 800_000


# --------------------------------------------------------------------------- fixtures


def _mark_script(content: bytes, key: PrivateKey, *, label: str | None = None) -> bytes:
    """A real signed v2 record over ``content``. No hand-written key, no hand-written signature."""
    return plan_hashmark(
        hashlib.sha256(content).digest(), key, label=label, network_genesis=MAINNET_GENESIS
    ).op_return_script


def _tx_with(*scripts: bytes) -> tuple[str, bytes]:
    """A transaction carrying ``scripts`` as its outputs. Returns ``(txid, raw bytes)``.

    The txid is the transaction's OWN hash rather than a chosen string: ``_classify_raw_tx``
    re-hashes the bytes the server returned and refuses a mismatch, so a fixture that made one
    up would never reach the classifier at all.
    """
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), 0) for s in scripts])
    # One input, so the bytes clear the classifier's >64-byte floor for a real transaction.
    inp = TransactionInput(source_txid="ab" * 32, source_output_index=0)
    inp.unlocking_script = Script(b"\x00")
    tx.inputs = [inp]
    return tx.txid(), tx.serialize()


class _FakeServer:
    """The four calls ``verify`` makes of ElectrumX, over a canned transaction."""

    def __init__(self, raw_by_txid: dict[str, bytes], *, confirmations: int = 100, tip: int = TIP) -> None:
        self.raw = raw_by_txid
        self.confirmations = confirmations
        self.tip = tip
        self.calls: list[tuple[str, str]] = []

    async def __aenter__(self) -> _FakeServer:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get_transaction(self, txid) -> bytes:
        self.calls.append(("get_transaction", str(txid)))
        return self.raw[str(txid).lower()]

    async def get_transaction_verbose(self, txid) -> dict:
        self.calls.append(("get_transaction_verbose", str(txid)))
        return {"txid": str(txid).lower(), "confirmations": self.confirmations}

    async def get_tip_height(self) -> int:
        self.calls.append(("get_tip_height", ""))
        return self.tip

    async def call_extension(self, method: str, params: list | None = None):
        from pyrxd.security.errors import NetworkError

        self.calls.append(("call_extension", method))
        raise NetworkError("ElectrumX RPC error (code -32601)")


def _run(monkeypatch, server, args: list[str], *, tmp_path: Path):
    """Invoke the REAL top-level CLI. Only the transport is swapped."""
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (server, "wss://only", server, "wss://only"))
    return CliRunner().invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), *args])


@pytest.fixture
def marked(tmp_path):
    """An honest mark over a real file, on a fake chain that will serve it back."""
    key = PrivateKey()
    content = b"the advisory, as published\n"
    target = tmp_path / "advisory.txt"
    target.write_bytes(content)
    txid, raw = _tx_with(_mark_script(content, key, label="advisory v1"))
    return {
        "key": key,
        "file": target,
        "content": content,
        "txid": txid,
        "server": _FakeServer({txid: raw}),
        "digest": hashlib.sha256(content).hexdigest(),
    }


# --------------------------------------------------------------------------- the honest path


class TestTheHonestPath:
    """A guard that refuses valid work is a bug. Every refusal below is paired with one of these."""

    def test_a_real_mark_and_its_real_file_verify_and_exit_zero(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 0, r.output
        assert "MATCHES" in r.output
        assert "signature VERIFIED" in r.output
        assert marked["digest"] in r.output
        assert "VERDICT — holds" in r.output

    def test_the_digest_flag_answers_without_the_file(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--digest", marked["digest"].upper(), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 0, r.output
        assert "MATCHES" in r.output

    def test_it_answers_all_five_questions_asked_of_it(self, monkeypatch, tmp_path, marked) -> None:
        """WHO SIGNED, WHAT NAME, WHAT DIGEST, WHAT HEIGHT, DOES THE FILE MATCH."""
        r = _run(
            monkeypatch,
            marked["server"],
            ["--json", "verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 0, r.output
        out = json.loads(r.stdout)
        rec = out["records"][0]
        assert rec["signer_hash160"] == marked["key"].public_key().hash160().hex()  # who signed
        assert rec["attestation"]["signer_address"] == marked["key"].public_key().address()
        assert out["checks"]["name"]["state"] == "NOT CHECKED"  # what name — not asked
        assert rec["digest"] == marked["digest"]  # what digest
        assert out["mark_anchor"]["height"] == TIP - 100 + 1  # what height
        assert out["checks"]["digest"]["state"] == "MATCHES"  # does the file match

    def test_the_block_reaches_the_human_with_its_caveat(self, monkeypatch, tmp_path, marked) -> None:
        """A height is one endpoint's claim. Printing the number without the caveat publishes
        the unqualified sentence `mark_anchor.py` exists to prevent."""
        r = _run(
            monkeypatch, marked["server"], ["verify", marked["txid"], "--min-confirmations", "6"], tmp_path=tmp_path
        )
        assert r.exit_code == 0, r.output
        assert f"block:        {TIP - 99}" in r.output
        assert "NOT verified" in r.output
        assert "wss://only" in r.output

    def test_quiet_mode_prints_the_answer_not_the_question(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["--quiet", "verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.stdout.strip() == "HOLDS"
        assert marked["txid"] not in r.stdout, "the caller already typed the txid; the verdict is the answer"


# --------------------------------------------------------------------------- the file half


class TestTheFileMatchingHalf:
    def test_a_different_file_does_not_match_and_the_exit_code_says_so(self, monkeypatch, tmp_path, marked) -> None:
        other = tmp_path / "other.txt"
        other.write_bytes(marked["content"] + b"tampered")
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--file", str(other), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert "DOES NOT MATCH" in r.output
        assert "VERDICT — DOES NOT HOLD" in r.output
        assert marked["digest"] in r.output, "the record's own digest is shown beside the one supplied"

    def test_the_file_is_hashed_with_the_algorithm_the_RECORD_names(self, monkeypatch, tmp_path, marked) -> None:
        """Not with a spelling chosen by the CLI. `algorithm_for`'s docstring is explicit that a
        caller writing "sha256" itself creates a second source of truth for what was hashed."""
        r = _run(
            monkeypatch,
            marked["server"],
            ["--json", "verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        rec = json.loads(r.stdout)["records"][0]
        assert rec["algorithm_id"] == 0x01
        assert rec["digest_match"]["expected"] == digest_file(marked["file"], algorithm_id=rec["algorithm_id"]).hex()
        # AND WHAT THIS ASSERTION CANNOT SEE, said out loud rather than left as a false
        # comfort. `_ALGORITHMS` has exactly one entry, so "hashed with the algorithm the
        # record names" and "hashed with sha256" produce identical bytes and no assertion
        # over this fixture can tell them apart. The membership is pinned instead: when a
        # second algorithm lands, this fails and forces the real differential test.
        assert set(_ALGORITHMS) == {0x01}, (
            "a second hash algorithm is implemented — this test is now vacuous and must be "
            "re-written to mark under one algorithm and verify the file is not hashed with the other"
        )

    def test_it_says_so_when_no_record_names_an_algorithm_to_hash_with(self, tmp_path) -> None:
        """Proves the algorithm id is READ rather than assumed: with no id there is nothing to
        hash the file with, and that is reported rather than guessed at."""
        target = tmp_path / "f.bin"
        target.write_bytes(os.urandom(64))
        expected, why = hashmark_cmds._digest_expectation(
            [{"outcome": "invalid", "algorithm_id": None}], file_path=target, digest_hex=None
        )
        assert expected is None
        assert "names a hash algorithm" in why

    def test_a_wrong_width_digest_says_why_rather_than_only_no(self) -> None:
        record = {"outcome": "ok", "digest": "ab" * 32, "algorithm": "sha256"}
        v = judge_digest_match(record, "cd" * 20, source="--digest")
        assert v["state"] == "DOES NOT MATCH"
        assert "20 bytes" in v["reason"] and "32-byte sha256" in v["reason"]

    def test_nothing_to_compare_is_NOT_CHECKED_never_a_mismatch(self) -> None:
        """ "I did not check" and "it does not match" are opposite facts and the blind one reads
        as the safe one. They must never collapse."""
        record = {"outcome": "ok", "digest": "ab" * 32, "algorithm": "sha256"}
        assert judge_digest_match(record, None, source="", absent_reason="nothing asked")["state"] == "NOT CHECKED"
        undecodable = {"outcome": "invalid", "digest": None}
        assert judge_digest_match(undecodable, "ab" * 32, source="--digest")["state"] == "NOT CHECKED"

    def test_the_match_line_does_not_claim_authorship(self) -> None:
        """The riskiest text in the output is the parenthetical explaining what the verified
        result MEANS. It inherits the authority of the fact above it."""
        text = "\n".join(_digest_match_lines({"state": "MATCHES", "algorithm": "sha256", "expected": "ab" * 32}))
        assert "Not that" in text
        for word in ("wrote it", "own it", "were first"):
            assert word in text


# --------------------------------------------------------------------------- refusals


class TestEveryRefusal:
    def test_a_tampered_record_does_not_verify_and_fails_the_verdict(self, monkeypatch, tmp_path) -> None:
        """One bit of the DIGEST, not of the signature — the record stays well-formed and the
        signature stays a valid signature over a different statement, so only the
        recovered-key-versus-commitment comparison can refuse it."""
        key = PrivateKey()
        script = bytearray(_mark_script(b"honest", key))
        script[20] ^= 0x01
        assert decode_hashmark(bytes(script)).ok, "must stay well-formed, or this tests the decoder"
        txid, raw = _tx_with(bytes(script))
        r = _run(
            monkeypatch,
            _FakeServer({txid: raw}),
            ["verify", txid, "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        summary, detail = r.output.split("HashMark record at vout", 1)
        assert "signature:  DOES NOT VERIFY" in summary, "the summary must not read VERIFIED over a forgery"
        assert "signature DOES NOT VERIFY" in detail
        assert "VERIFIED" not in summary.replace("DOES NOT VERIFY", "")

    def test_a_transaction_with_no_mark_names_the_txid_digest_ambiguity(self, monkeypatch, tmp_path) -> None:
        """A digest and a txid are the same shape. Whoever pasted the wrong one needs telling."""
        txid, raw = _tx_with(b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac")
        r = _run(monkeypatch, _FakeServer({txid: raw}), ["verify", txid, "--min-confirmations", "6"], tmp_path=tmp_path)
        assert r.exit_code == 1, r.output
        assert "no HashMark record" in r.output
        assert "same shape as a txid" in r.output

    def test_an_unconfirmed_mark_fixes_no_time_and_does_not_hold(self, monkeypatch, tmp_path, marked) -> None:
        marked["server"].confirmations = 0
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert "NO BLOCK" in r.output
        assert "fixes no time" in r.output
        assert "MATCHES" in r.output, "the file half is still answered; only the block half refuses"

    def test_a_mark_below_the_floor_is_provisional_and_does_not_hold(self, monkeypatch, tmp_path, marked) -> None:
        marked["server"].confirmations = 2
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert "PROVISIONAL" in r.output

    def test_min_confirmations_is_required_and_names_the_flag(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(monkeypatch, marked["server"], ["verify", marked["txid"]], tmp_path=tmp_path)
        assert r.exit_code == 1
        assert "--min-confirmations" in r.output
        assert marked["server"].calls == [], "refused before the network was touched"

    def test_file_and_digest_together_are_refused(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            [
                "verify",
                marked["txid"],
                "--file",
                str(marked["file"]),
                "--digest",
                marked["digest"],
                "--min-confirmations",
                "6",
            ],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 1
        assert "both name the thing to compare" in r.output

    def test_a_non_hex_digest_is_refused_before_the_network(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--digest", "not-hex", "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 1
        assert "not an even-length hex" in r.output
        assert marked["server"].calls == []

    def test_a_file_path_where_a_txid_belongs_explains_the_shape(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == 1
        assert "not a transaction id" in r.output
        assert "--digest" in r.output


# --------------------------------------------------------------------------- UNVERIFIABLE


class TestUnverifiableIsNotAnAccusation:
    """The asymmetry the write side established, kept.

    On WRITE, `MarkPlan` treats UNVERIFIABLE as a refusal: funding a broadcast needs the same
    curve library that signs, so a mark nobody could self-check must not be published. On READ
    the same word means the curve library is missing on THIS machine — a capability the reader
    lacks, not a bad signature. Failing the verdict on it accuses an honest signer of forgery
    because of something absent on the verifier's computer.
    """

    def test_it_holds_and_says_what_is_absent(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch,
            marked["server"],
            ["--json", "verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        out = json.loads(r.stdout)
        record = dict(out["records"][0])
        record["attestation"] = {"outcome": "unverifiable", "detail": "secp256k1 is not installed"}
        state, reason = _signature_check([record])
        assert state == "NOT CHECKED"
        assert state in hashmark_cmds._CHECK_HOLDS, "a missing curve library must not fail the verdict"
        assert "secp256k1" in reason

    def test_an_invalid_signature_is_the_opposite_and_does_fail(self) -> None:
        """The pair for the case above: the refusal must still be reachable."""
        state, _ = _signature_check([{"outcome": "ok", "attestation": {"outcome": "invalid_signature"}}])
        assert state == "DOES NOT VERIFY"
        assert state not in hashmark_cmds._CHECK_HOLDS


# --------------------------------------------------------------------------- §7.6


class TestFormTwoThroughTheCommand:
    def test_one_endpoint_degrades_to_form_1_with_a_reason_and_FAILS_CLOSED(
        self, monkeypatch, tmp_path, marked
    ) -> None:
        """The shipped default config cannot reach form 2. `verify --wave-name` on it asks a
        question that cannot be answered — and a gate that passes on "not answered" waves
        everything through in silence, which is the direction that ships."""
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--wave-name", "acme.rxd", "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert "NOT ESTABLISHED" in r.output
        assert "not established" in r.output, "the per-record degrade line, not only the summary"

    def test_an_established_form_2_holds(self) -> None:
        """The affirmative, against the check directly — see this module's docstring for why it
        cannot be composed through the command without forging ECDSA."""
        record = {
            "name_at_mark": {
                "resolved": True,
                "form": 2,
                "name": "acme.rxd",
                "height": 458595,
                "signer_is_target_at_height": True,
            }
        }
        state, reason = _name_check([record], asked=True)
        assert state == "ESTABLISHED" and state in hashmark_cmds._CHECK_HOLDS
        assert "458595" in reason

    def test_form_2_that_names_someone_else_is_a_definite_no(self) -> None:
        record = {
            "name_at_mark": {
                "resolved": True,
                "form": 2,
                "name": "acme.rxd",
                "height": 458595,
                "target_at_height": "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7",
                "signer_is_target_at_height": False,
            }
        }
        state, reason = _name_check([record], asked=True)
        assert state == "NOT THE SIGNER" and state not in hashmark_cmds._CHECK_HOLDS
        assert "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7" in reason

    def test_the_block_is_inherited_from_the_name_lookup_not_asked_again(self, monkeypatch, tmp_path) -> None:
        """A HOSTILE SOURCE MUST NOT MOVE BOTH THE NAME BINDING AND THE BLOCK. The rule lives in
        `_name_at_mark`, which takes the height from whichever endpoint did NOT supply the
        binding. `verify` inherits that anchor; a second lookup here would not re-check the
        rule, it would bypass it — this call cannot see which endpoint answered wave.resolve."""
        ctx = object()
        payload = {
            "txid": "cd" * 32,
            "outputs": [
                {
                    "vout": 0,
                    "hashmark": {
                        "name_at_mark": {
                            "resolved": True,
                            "anchor": {"height": 12345, "confirmations": 9, "source": "wss://not-the-binding"},
                        }
                    },
                }
            ],
        }
        anchor = hashmark_cmds._verify_anchor(ctx, payload, min_confirmations=6)
        assert anchor == {"height": 12345, "confirmations": 9, "source": "wss://not-the-binding"}


# --------------------------------------------------------------------------- it reaches a human


class TestItReachesAHuman:
    def test_the_summary_and_the_detail_cannot_disagree(self, monkeypatch, tmp_path, marked) -> None:
        """Two elements on one screen describing the same quantity. A card fixed in one half
        while the other contradicts it is a defect this project has shipped before."""
        r = _run(
            monkeypatch,
            marked["server"],
            ["verify", marked["txid"], "--file", str(marked["file"]), "--min-confirmations", "6"],
            tmp_path=tmp_path,
        )
        summary, detail = r.output.split("HashMark record at vout", 1)
        assert "signature:  VERIFIED" in summary and "signature VERIFIED" in detail
        assert "file:       MATCHES" in summary and "file/digest: MATCHES" in detail
        assert "DOES NOT VERIFY" not in r.output and "DOES NOT MATCH" not in r.output

    def test_the_claim_is_key_custody_at_a_block_and_says_what_it_is_not(self, monkeypatch, tmp_path, marked) -> None:
        r = _run(
            monkeypatch, marked["server"], ["verify", marked["txid"], "--min-confirmations", "6"], tmp_path=tmp_path
        )
        assert "KEY CUSTODY AT THAT BLOCK" in r.output
        for word in ("authorship", "ownership", "originality", "location"):
            assert word in r.output

    def test_a_hostile_label_cannot_decode_so_it_is_never_rendered(self, monkeypatch, tmp_path) -> None:
        """Someone else wrote those bytes, and they land directly under the one line in this
        output that states an independently checked cryptographic fact.

        The door turns out to be shut one layer down, which is worth pinning rather than
        assuming: §5.4 makes a v2 label with a control character NOT CANONICAL, and a v2 label
        is inside the signed statement — so `encode_hashmark` refuses to write one and
        `decode_hashmark` refuses to read one. `verify` therefore never has a hostile label to
        sanitise; it has an undecodable record, and it must say so rather than fall silent.
        """
        benign = bytearray(_mark_script(b"x", PrivateKey(), label="advisory"))
        hostile = b"ad\x1b[2K\rr"  # same byte length, so only the label bytes change
        assert len(hostile) == len(b"advisory")
        benign[-len(hostile) :] = hostile
        record = decode_hashmark(bytes(benign))
        assert not record.ok and record.label is None, "the DECODER is the gate here, not the renderer"

        txid, raw = _tx_with(bytes(benign))
        r = _run(monkeypatch, _FakeServer({txid: raw}), ["verify", txid, "--min-confirmations", "6"], tmp_path=tmp_path)
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert "RECORD DOES NOT DECODE" in r.output
        assert "\x1b" not in r.output, "a raw ESC reached the terminal"
        assert "U+001B" in r.output, "and the reader is told what is wrong with it"
        assert "2K" not in r.output, "no fragment of the hostile label is rendered"

    def test_indexer_supplied_text_is_sanitised_into_the_summary(self) -> None:
        """The attacker-authored text that CAN reach this output is the name, not the label: a
        WAVE registration is whatever its registrant typed, and it arrives from an indexer."""
        reason = _name_check(
            [{"name_at_mark": {"resolved": False, "reason": "lookup failed: \x1b[2K\rVERIFIED"}}], asked=True
        )[1]
        assert "\x1b" not in reason
        # `_sanitize_display_string` substitutes a literal "?" per stripped codepoint, so the
        # reader can see something WAS filtered rather than silently losing it.
        assert reason == "lookup failed: ?[2K?VERIFIED"


# --------------------------------------------------------------------------- the checks themselves


class TestTheVerdictTable:
    def test_every_state_the_checks_can_emit_is_classified(self) -> None:
        """Non-vacuity, and both directions. A state with no entry in `_CHECK_HOLDS` fails the
        verdict silently; an entry naming a state nothing emits is a rule that stopped running.
        Both sets are derived from the source rather than retyped."""
        import ast
        import inspect

        emitted: set[str] = set()
        for fn in (_signature_check, _digest_check_src := hashmark_cmds._digest_check, _name_check, _block_check):
            tree = ast.parse(inspect.getsource(fn).lstrip())
            for node in ast.walk(tree):
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
                    first = node.value.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        emitted.add(first.value)
        assert emitted, "the scan found nothing — it is broken, not the code"
        assert _digest_check_src is hashmark_cmds._digest_check
        unclassified = (
            emitted
            - hashmark_cmds._CHECK_HOLDS
            - {
                "DOES NOT VERIFY",
                "RECORD DOES NOT DECODE",
                "DOES NOT MATCH",
                "NOT THE SIGNER",
                "NOT ESTABLISHED",
                "PROVISIONAL",
                "NO BLOCK",
            }
        )
        assert not unclassified, f"states neither held nor listed as failing: {unclassified}"
        assert emitted >= hashmark_cmds._CHECK_HOLDS, (
            f"_CHECK_HOLDS names states nothing emits: {hashmark_cmds._CHECK_HOLDS - emitted}"
        )

    def test_the_failure_exit_code_is_not_success_and_not_one_of_the_others(self) -> None:
        """MEASURED GAP, closed here. Every case in this file spells its expectation as
        ``r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD`` — which is tautological in the constant's
        VALUE. Planting ``EXIT_VERDICT_DOES_NOT_HOLD = 0`` broke nothing: 14 tests passed with
        the gate waving every forged mark and mismatched file straight through, and nothing in
        the output looked wrong. A command that does nothing exits 0, and so did this one.
        """
        assert EXIT_VERDICT_DOES_NOT_HOLD == 5
        assert EXIT_VERDICT_DOES_NOT_HOLD != 0, "a verdict that does not hold must not exit success"
        assert EXIT_VERDICT_DOES_NOT_HOLD not in (1, 2, 3, 4), "must not collide with the documented codes"

    def test_the_documented_exit_code_table_names_it(self) -> None:
        """The code and the contract, kept together. Flattened before searching: this file's
        prose is hard-wrapped, and a line-oriented grep for a wrapped phrase finds nothing while
        every word is present."""
        doc = (Path(__file__).resolve().parents[1] / "docs" / "wallet-cli-plan.md").read_text()
        flat = " ".join(doc.split())
        assert f"{EXIT_VERDICT_DOES_NOT_HOLD} a verdict that does not hold" in flat

    def test_a_confirmed_block_holds_and_a_shallow_one_does_not(self) -> None:
        deep = {"height": 5, "confirmations": 9, "min_confirmations": 6, "provisional": False}
        shallow = {"height": 5, "confirmations": 2, "min_confirmations": 6, "provisional": True}
        assert _block_check(deep)[0] == "CONFIRMED"
        assert _block_check(shallow)[0] == "PROVISIONAL"
        assert _block_check(None)[0] == "NO BLOCK"
