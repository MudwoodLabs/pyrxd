"""Mutation-found gaps in ``pyrxd mark`` / ``pyrxd verify`` and the mark transaction builder.

The tests here were written against SURVIVING cosmic-ray mutants of ``src/pyrxd/hashmark_tx.py``
and ``src/pyrxd/cli/hashmark_cmds.py`` (local runs, 2026-09-29): changes to shipped code that no
existing assertion noticed. Each asserts the BEHAVIOUR a mutant changes, never the mutated line's
text, and goes through the real builder or the real click command wherever that reaches it. Two
places are called directly instead: ``_choose_witness`` (its tie-break keys only decide between
check states that are expensive to stage through a chain fixture) and ``_signature_check``'s
UNVERIFIABLE branch (the CLI cannot load without a curve library, so no command reaches it).
``test_a_signature_over_a_different_funding_value_does_not_verify`` is a control, not a killer: it
shows the signature check beside it can fail.

The builder half matters most. A surviving mutant there means a wrong signed transaction would
have passed the suite, and a mark is not free to retry: the fee is spent and the record is public.
So the transaction is checked from the SERIALISED BYTES, re-parsed, with the funding output's
real script and value supplied from the fixture rather than from the builder's own objects — a
signature checked against the builder's in-memory preimage would agree with any mistake the
builder made in both places.

Harnesses are the existing ones: ``_MarkHarness`` / ``_invoke`` (``tests/test_hashmark_mark_cli.py``)
and ``_FakeServer`` / ``_run`` / ``_tx_with`` (``tests/test_hashmark_verify_cli.py``). Every key is
generated per test; nothing touches a network.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from pyrxd.fee_sizing import required_fee
from pyrxd.hashmark_tx import (
    MARK_MODELLED_BYTES,
    build_hashmark_mark,
    digest_file,
    hashmark_mark_funding_bar,
    plan_hashmark,
)
from pyrxd.keys import PrivateKey, PublicKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from tests.test_hashmark_mark_cli import FEE_RATE, _MarkHarness

# ---------------------------------------------------------------------------------------------
# hashmark_tx: what is signed, the fee, the funding, the change
# ---------------------------------------------------------------------------------------------


def _build(h: _MarkHarness, *, label: str | None = None, content: bytes = b"x"):
    plan = plan_hashmark(hashlib.sha256(content).digest(), h.signer_key, label=label)
    return plan, asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))


def _signature_verifies_from_the_bytes(raw: bytes, *, spk: Script, value: int) -> tuple[bool, bytes]:
    """Re-parse ``raw``, give input 0 the funding output's REAL script and value, and check its
    signature against that preimage. Returns ``(verifies, pubkey bytes)``."""
    tx = Transaction.from_hex(raw.hex())
    assert tx is not None
    tx.inputs[0].locking_script = spk
    tx.inputs[0].satoshis = value
    unlock = tx.inputs[0].unlocking_script.serialize()
    sig_len = unlock[0]
    sig_with_type, rest = unlock[1 : 1 + sig_len], unlock[1 + sig_len :]
    pub = rest[1 : 1 + rest[0]]
    return PublicKey(pub).verify(sig_with_type[:-1], tx.preimage(0)), pub


class TestTheSignedMarkTransaction:
    def test_its_bytes_spend_the_funding_utxo_to_the_record_and_change_and_the_signature_verifies(self) -> None:
        h = _MarkHarness(fund_value=50_000_000)
        plan, build = _build(h, label="advisory")
        raw = build.serialize()
        assert raw == bytes(build.tx.serialize())
        tx = Transaction.from_hex(raw.hex())

        assert [(i.source_txid, i.source_output_index) for i in tx.inputs] == [(h.fund_utxo.tx_hash, 1)]
        assert len(tx.outputs) == 2
        assert bytes(tx.outputs[0].locking_script.serialize()) == plan.op_return_script
        assert tx.outputs[0].satoshis == 0
        change_spk = P2PKH().lock(h.fund_key.address())
        assert bytes(tx.outputs[1].locking_script.serialize()) == bytes(change_spk.serialize())
        # Nothing leaks: every photon of the input is either the fee or the change.
        assert tx.outputs[1].satoshis == h.fund_utxo.value - build.fee
        assert build.fee == build.tx.get_fee()
        assert build.has_change is True
        assert build.from_address == h.fund_key.address()
        assert build.plan is plan

        ok, pub = _signature_verifies_from_the_bytes(raw, spk=change_spk, value=h.fund_utxo.value)
        assert ok, "the input's signature does not verify over the real funding output"
        assert pub == h.fund_key.public_key().serialize()
        # SIGHASH_ALL | FORKID: the whole transaction is committed to, record included.
        unlock = tx.inputs[0].unlocking_script.serialize()
        assert unlock[unlock[0]] == 0x41

    def test_a_signature_over_a_different_funding_value_does_not_verify(self) -> None:
        """Non-vacuity for the check above: the preimage commits to the spent value, so the same
        bytes checked against a value one photon off must fail."""
        h = _MarkHarness(fund_value=50_000_000)
        _plan, build = _build(h)
        ok, _ = _signature_verifies_from_the_bytes(
            build.serialize(), spk=P2PKH().lock(h.fund_key.address()), value=h.fund_utxo.value + 1
        )
        assert not ok

    def test_the_fee_is_the_rate_times_the_modelled_size_exactly(self) -> None:
        """The fee model sizes the unlocking script at its 107-byte upper bound, so the fee is
        ``(signed size - real unlock + 107) * rate`` — plus at most ONE photon, because
        ``SatoshisPerKilobyte`` takes ``math.ceil`` of a float product (measured: 343 B at
        10_000/B came out 3_430_001). Never below the signed size's requirement."""
        h = _MarkHarness(fund_value=50_000_000)
        _plan, build = _build(h, label="advisory")
        raw = build.serialize()
        unlock_len = len(Transaction.from_hex(raw.hex()).inputs[0].unlocking_script.serialize())
        modelled = (len(raw) - unlock_len + 107) * FEE_RATE
        assert modelled <= build.fee <= modelled + 1
        assert build.fee >= required_fee(len(raw), FEE_RATE)

    def test_at_the_bar_there_is_no_change_and_the_whole_utxo_is_the_fee(self) -> None:
        probe = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey())
        bar = hashmark_mark_funding_bar(probe.op_return_script, FEE_RATE)
        h = _MarkHarness(fund_value=bar)
        _plan, build = _build(h)
        tx = Transaction.from_hex(build.serialize().hex())
        assert len(tx.outputs) == 1
        assert build.has_change is False
        assert build.fee == bar
        assert build.from_address == h.fund_key.address()

    def test_the_refusal_names_what_was_needed(self) -> None:
        from pyrxd.glyph.transfer import NoFeeFundingError

        probe = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey())
        bar = hashmark_mark_funding_bar(probe.op_return_script, FEE_RATE)
        h = _MarkHarness(fund_value=bar - 1)
        with pytest.raises(NoFeeFundingError) as err:
            _build(h)
        msg = str(err.value)
        assert f"need at least {bar:,} photons" in msg
        assert f"{len(probe.op_return_script)}-byte OP_RETURN" in msg
        assert f"~{MARK_MODELLED_BYTES + len(probe.op_return_script)} B at {FEE_RATE:,} photons/B" in msg


class TestTheFundingBar:
    @pytest.mark.parametrize(("script_len", "varint"), [(252, 1), (253, 3), (254, 3)])
    def test_the_script_length_varint_widens_at_253(self, script_len: int, varint: int) -> None:
        """CompactSize is one byte below 0xFD and three from it. The bar is a public function
        taking any script, so the boundary is its to get right, not only the record cap's."""
        assert hashmark_mark_funding_bar(b"\x6a" * script_len, FEE_RATE) == required_fee(
            MARK_MODELLED_BYTES + varint + script_len, FEE_RATE
        )

    def test_the_bar_is_the_fee_of_the_largest_no_change_mark_exactly(self) -> None:
        """The bar is the no-change transaction's fee with the unlocking script at its 107-byte
        upper bound. A bar one byte high refuses funding the chain would take; one byte low admits
        funding the builder must then refuse. Measured from a real build at the bar."""
        probe = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey(), label="advisory")
        bar = hashmark_mark_funding_bar(probe.op_return_script, FEE_RATE)
        h = _MarkHarness(fund_value=bar)
        _plan, build = _build(h, label="advisory")
        raw = build.serialize()
        tx = Transaction.from_hex(raw.hex())
        assert len(tx.outputs) == 1, "at the bar the mark has no change output"
        modelled = len(raw) - len(tx.inputs[0].unlocking_script.serialize()) + 107
        assert bar == required_fee(modelled, FEE_RATE)


class TestTheFileIsStreamed:
    def test_it_is_read_in_bounded_chunks_that_are_not_tiny(self, tmp_path, monkeypatch) -> None:
        """Streamed, so a large file is never held whole — and in chunks large enough that a
        multi-gigabyte file is not read a byte at a time."""
        import builtins

        blob = b"\x5a" * (2 * 1024 * 1024 + 3)
        target = tmp_path / "big.bin"
        target.write_bytes(blob)
        sizes: list[int] = []
        real_open = builtins.open

        class _Spy:
            def __init__(self, fh):
                self._fh = fh

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return self._fh.__exit__(*exc)

            def read(self, n=-1):
                sizes.append(n)
                return self._fh.read(n)

        monkeypatch.setattr(builtins, "open", lambda p, mode="r", *a, **k: _Spy(real_open(p, mode, *a, **k)))
        assert digest_file(target) == hashlib.sha256(blob).digest()
        assert sizes, "the file was not read through open().read"
        assert all(64 * 1024 <= n <= 16 * 1024 * 1024 for n in sizes), sizes


class TestAPlanAndABuildCannotBeEditedAfterTheirChecks:
    """``MarkPlan`` checks its bytes in ``__post_init__``. That guarantee is worth nothing if the
    bytes can be swapped afterwards: the builder would fund and sign whatever the field then held."""

    def test_a_plans_bytes_cannot_be_replaced_after_they_were_checked(self) -> None:
        import dataclasses

        plan = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey())
        with pytest.raises(dataclasses.FrozenInstanceError):
            plan.op_return_script = b"\x6a\x04spam"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            plan.network_genesis = "00" * 32  # type: ignore[misc]

    def test_a_build_cannot_be_swapped_between_the_prompt_and_the_broadcast(self) -> None:
        import dataclasses

        _plan, build = _build(_MarkHarness())
        with pytest.raises(dataclasses.FrozenInstanceError):
            build.tx = Transaction()  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            build.fee = 0  # type: ignore[misc]


class TestAPlanRefusalSaysWhy:
    def _record(self, version: int, n_pushes: int) -> bytes:
        def push(b: bytes) -> bytes:
            return bytes([len(b)]) + b

        body = [push(b"HASHMARK"), push(bytes([version, 1])), push(b"\x00" * 32)][:n_pushes]
        return b"\x6a" + b"".join(body)

    def test_the_decoders_detail_is_carried_into_the_refusal(self) -> None:
        from pyrxd.hashmark_tx import MarkPlan
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError) as err:
            MarkPlan(op_return_script=self._record(2, 3))
        assert str(err.value) == (
            "these bytes are not a publishable HashMark record: invalid (v2 takes 5 or 6 pushes, found 3)"
        )

    def test_with_no_detail_there_is_no_empty_parenthesis(self) -> None:
        from pyrxd.hashmark_tx import MarkPlan
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError) as err:
            MarkPlan(op_return_script=b"\x6a\x04spam")
        assert str(err.value) == "these bytes are not a publishable HashMark record: not_hashmark"


class TestAFilePlanIsForAKnownChainUnlessAsked:
    def test_an_unknown_genesis_is_refused_by_default(self, tmp_path) -> None:
        from pyrxd.hashmark_tx import plan_hashmark_for_file
        from pyrxd.security.errors import ValidationError

        target = tmp_path / "a.txt"
        target.write_bytes(b"contents")
        unknown = "11" * 32
        with pytest.raises(ValidationError):
            plan_hashmark_for_file(target, PrivateKey(), network_genesis=unknown)
        # The honest pair: the same genesis, when the caller says so.
        plan = plan_hashmark_for_file(target, PrivateKey(), network_genesis=unknown, allow_unknown_genesis=True)
        assert plan.network_genesis == unknown and plan.source == str(target)


class TestEveryMismatchedChainPairIsRefused:
    """Genesis hashes are compared for EQUALITY. A comparison that only refused one ordering of
    the two strings would pass every pair whose hex happens to sort the other way."""

    @pytest.mark.parametrize(
        ("client_net", "plan_net"),
        [(a, b) for a in ("mainnet", "testnet", "regtest") for b in ("mainnet", "testnet", "regtest") if a != b],
    )
    def test_a_plan_through_a_client_declaring_another_chain_is_refused(self, client_net, plan_net) -> None:
        from pyrxd.constants import GENESIS_BLOCK_HASHES
        from pyrxd.network.registry import NetworkProfile
        from pyrxd.security.errors import ValidationError

        h = _MarkHarness()
        h.client.profile = NetworkProfile.build(client_net, ["wss://electrumx.invalid:50022"])
        plan = plan_hashmark(
            hashlib.sha256(b"x").digest(), h.signer_key, network_genesis=GENESIS_BLOCK_HASHES[plan_net]
        )
        with pytest.raises(ValidationError, match="but the client is on the chain"):
            asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        assert h.client.get_transaction.await_count == 0


# ---------------------------------------------------------------------------------------------
# pyrxd mark: the confirmation screen, the flags, the JSON
# ---------------------------------------------------------------------------------------------


@pytest.fixture
def runner():
    from click.testing import CliRunner

    return CliRunner()


def _dry(runner, tmp_path, monkeypatch, *extra: str, top=(), harness: _MarkHarness | None = None):
    from tests.test_hashmark_mark_cli import _invoke

    h = harness or _MarkHarness()
    result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=top, extra=["--dry-run", *extra])
    assert result.exit_code == 0, result.output
    assert h.broadcast_calls == []
    return result


def _label_line(output: str) -> str:
    """What the confirmation summary prints after ``label:`` — the line the operator agrees to."""
    lines = [ln for ln in output.splitlines() if ln.lstrip().startswith("label:")]
    assert lines, output
    return lines[0].split("label:", 1)[1].strip()


class TestTheLabelLineShowsExactlyWhatWillBeSigned:
    """Each case pins one character's rendering on the confirmation line, and each is placed where
    a neighbouring-index mistake in the escaping rule would print it differently."""

    @pytest.mark.parametrize(
        ("label", "shown"),
        [
            # A selector is honest only straight AFTER a symbol. At position 0 there is no "before"
            # — reading label[-1] would find the heart at the far end and let it through.
            ("\ufe0fabc\u2764", "<U+FE0F>abc\u2764"),
            # An ASCII symbol ('+' is Sm) is not an emoji base: the selector selects nothing.
            ("+\ufe0f", "+<U+FE0F>"),
            ("a+\ufe0f", "a+<U+FE0F>"),
            # Honest emoji presentation, at positions where i-1 differs from i>>1 and i^1.
            ("ab\u2764\ufe0f", "ab\u2764\ufe0f"),
            ("a\u2764\ufe0fb", "a\u2764\ufe0fb"),
            # The base is the heart, which is printed; the escaped blanks before it are not the base.
            ("\u2800\u2800\u2764\ufe0f", "<U+2800><U+2800>\u2764\ufe0f"),
            # A joiner does not stop the scan: the TAG character after it is still escaped.
            ("x\u200dy\U000e0041", "x<U+200D>y<U+E0041>"),
            # A joiner needs a printed non-ASCII character on BOTH sides, and at the end has none.
            ("\u00e9\u200d", "\u00e9<U+200D>"),
            ("a\u200d\u00e9", "a<U+200D>\u00e9"),
            ("\u00e9\u200da", "\u00e9<U+200D>a"),
            ("\u00e9a\u200d\u00e9", "\u00e9a<U+200D>\u00e9"),
            ("\u00e9\u00e9\u200da", "\u00e9\u00e9<U+200D>a"),
            ("ab\u200d\u00e9", "ab<U+200D>\u00e9"),
            # At position 0 there is no left neighbour: not the LAST character, read as label[-1].
            ("\u200d\u00e9", "<U+200D>\u00e9"),
            # A private-use character prints as '?' in the reader: escaped here, so it is seen.
            ("a\ue000", "a<U+E000>"),
        ],
    )
    def test_the_confirmation_line(self, runner, tmp_path, monkeypatch, label: str, shown: str) -> None:
        out = _dry(runner, tmp_path, monkeypatch, "--label", label).output
        assert _label_line(out) == shown

    def test_past_eight_distinct_codepoints_the_banner_counts_the_rest(self, runner, tmp_path, monkeypatch) -> None:
        """Seventeen distinct hidden codepoints: eight are named, and the rest are COUNTED — the
        count is how the operator learns there is more than the eight lines show."""
        tags = "".join(chr(0xE0041 + k) for k in range(17))
        out = _dry(runner, tmp_path, monkeypatch, "--label", "x" + tags).output
        assert "THE LABEL HOLDS 17 CHARACTER(S)" in out
        named = [ln for ln in out.splitlines() if "  U+E00" in ln and "TAG" in ln]
        assert len(named) == 8, named
        assert "... and 9 more distinct codepoint(s)" in out

    def test_one_hidden_codepoint_is_named_and_nothing_is_summarised(self, runner, tmp_path, monkeypatch) -> None:
        out = _dry(runner, tmp_path, monkeypatch, "--label", "x\U000e0041").output
        assert "THE LABEL HOLDS 1 CHARACTER(S)" in out
        assert "more distinct codepoint" not in out

    def test_each_codepoint_says_where_IT_appears_not_where_its_neighbours_do(
        self, runner, tmp_path, monkeypatch
    ) -> None:
        """Devanagari's combining marks print as written; a WORD JOINER beside them is escaped. Each
        per-codepoint line is about the positions of THAT codepoint only."""
        out = _dry(runner, tmp_path, monkeypatch, "--label", "\u0928\u092e\u0938\u094d\u0924\u0947\u2060").output
        lines = {ln.split()[1]: ln for ln in out.splitlines() if ln.strip().startswith("***   U+")}
        assert "printed above as written; verify prints it as ?" in lines["U+094D"], out
        assert "printed above as written; verify prints it as ?" in lines["U+0947"], out
        assert "shown above as <U+2060>; verify prints it as ?" in lines["U+2060"], out

    def test_exactly_eight_are_all_named_and_nothing_is_summarised(self, runner, tmp_path, monkeypatch) -> None:
        tags = "".join(chr(0xE0041 + k) for k in range(8))
        out = _dry(runner, tmp_path, monkeypatch, "--label", "x" + tags).output
        named = [ln for ln in out.splitlines() if "  U+E00" in ln and "TAG" in ln]
        assert len(named) == 8, named
        assert "more distinct codepoint" not in out


class TestTheFeeLine:
    def test_with_change_the_fee_line_does_not_claim_the_whole_utxo(self, runner, tmp_path, monkeypatch) -> None:
        out = _dry(runner, tmp_path, monkeypatch).output
        fee_line = next(ln for ln in out.splitlines() if ln.strip().startswith("fee:"))
        assert "photons (" in fee_line and "no change" not in fee_line

    def test_at_the_bar_it_says_the_whole_utxo_is_the_fee(self, runner, tmp_path, monkeypatch) -> None:
        from tests.test_hashmark_mark_cli import _invoke

        # The CLI's record is over the file with the default signer and no label: measure its bar
        # from a plan of the same shape.
        probe = plan_hashmark(hashlib.sha256(b"the advisory text").digest(), PrivateKey())
        h = _MarkHarness(fund_value=hashmark_mark_funding_bar(probe.op_return_script, FEE_RATE))
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, extra=["--dry-run"])
        assert result.exit_code == 0, result.output
        fee_line = next(ln for ln in result.output.splitlines() if ln.strip().startswith("fee:"))
        assert fee_line.endswith("— no change: the whole funding UTXO is the fee"), fee_line


class TestTheMarkCommandsArgumentsAndFlags:
    def test_a_directory_is_refused_by_the_argument_parser(self, runner, tmp_path, monkeypatch) -> None:
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.main import cli

        h = _MarkHarness()
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        (tmp_path / "adir").mkdir()
        r = runner.invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "mark", str(tmp_path / "adir"), "--dry-run"])
        assert r.exit_code == 2, r.output  # click's usage error, before any wallet is opened
        assert "is a directory" in r.output
        assert h.broadcast_calls == []

    def test_a_file_that_does_not_exist_is_a_usage_error(self, runner, tmp_path, monkeypatch) -> None:
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.main import cli

        h = _MarkHarness()
        opened: list[bool] = []
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: opened.append(True) or h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        r = runner.invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "mark", str(tmp_path / "nope.txt"), "--dry-run"])
        assert r.exit_code == 2, r.output
        assert opened == [], "the wallet was opened for a file that does not exist"

    def test_allow_overpay_is_a_flag_not_an_option_taking_a_value(self, runner, tmp_path, monkeypatch) -> None:
        """Written before ``--dry-run``: an option that takes a value would swallow it, and the
        run would reach the confirmation prompt instead of printing a dry run."""
        from tests.test_hashmark_mark_cli import _invoke

        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, extra=["--allow-overpay", "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output
        assert h.broadcast_calls == []

    @pytest.mark.parametrize(("flag", "asked"), [((), False), (("--passphrase",), True), (("--no-passphrase",), False)])
    def test_the_passphrase_is_prompted_for_only_when_asked(self, runner, tmp_path, monkeypatch, flag, asked) -> None:
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.main import cli

        h = _MarkHarness()
        seen: list[bool] = []

        def _load(ctx, *, prompt_passphrase: bool = False):
            seen.append(prompt_passphrase)
            return h.wallet

        monkeypatch.setattr(hc, "_load_wallet", _load)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        target = tmp_path / "f.txt"
        target.write_bytes(b"x")
        r = runner.invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "mark", str(target), "--dry-run", *flag])
        assert r.exit_code == 0, r.output
        assert seen == [asked]


class TestTheJsonSaysWhatWasTyped:
    def test_a_canonicalised_label_reports_what_was_typed(self, runner, tmp_path, monkeypatch) -> None:
        out = json.loads(_dry(runner, tmp_path, monkeypatch, "--label", "  advisory  ", top=["--json"]).stdout)
        assert out["label"] == "advisory"
        assert out["label_as_typed"] == "  advisory  "
        assert out["broadcast"] is False and out["txid"] is None

    def test_a_trailing_space_is_trimmed_announced_and_reported(self, runner, tmp_path, monkeypatch) -> None:
        """The canonical form sorts BEFORE what was typed here ("advisory" < "advisory "), the
        reverse of a leading space. Both are changes, and both must be told."""
        human = _dry(runner, tmp_path, monkeypatch, "--label", "advisory ").output
        assert "*** LABEL CANONICALISED" in human
        assert "you typed:  'advisory '" in human
        out = json.loads(_dry(runner, tmp_path, monkeypatch, "--label", "advisory ", top=["--json"]).stdout)
        assert (out["label"], out["label_as_typed"]) == ("advisory", "advisory ")

    def test_an_unchanged_label_reports_nothing_extra(self, runner, tmp_path, monkeypatch) -> None:
        out = json.loads(_dry(runner, tmp_path, monkeypatch, "--label", "advisory", top=["--json"]).stdout)
        assert out["label"] == "advisory"
        assert out["label_as_typed"] is None


# ---------------------------------------------------------------------------------------------
# pyrxd verify: verdict wording, exit codes, JSON shape
# ---------------------------------------------------------------------------------------------


def _push(b: bytes) -> bytes:
    return bytes([len(b)]) + b


@pytest.fixture
def mark(tmp_path):
    """An honest signed mark over a real file, served by the verify harness's fake ElectrumX."""
    from tests.test_hashmark_verify_cli import _FakeServer, _mark_script, _tx_with

    content = b"the advisory, as published\n"
    target = tmp_path / "advisory.txt"
    target.write_bytes(content)
    txid, raw = _tx_with(_mark_script(content, PrivateKey(), label="advisory v1"))
    return {
        "txid": txid,
        "server": _FakeServer({txid: raw}),
        "file": target,
        "digest": hashlib.sha256(content).hexdigest(),
    }


def _verify(monkeypatch, tmp_path, server, target: str, *extra: str, top=()):
    from tests.test_hashmark_verify_cli import _run

    return _run(monkeypatch, server, [*top, "verify", target, *extra, "--min-confirmations", "6"], tmp_path=tmp_path)


def _summary(output: str) -> str:
    """The VERDICT block only — the part above the per-record detail."""
    return output.split("HashMark record at vout", 1)[0]


class TestAMismatchIsRenderedAsAMismatchWithItsReason:
    def test_the_summary_and_the_detail_both_say_does_not_match_and_why(self, monkeypatch, tmp_path, mark) -> None:
        near = mark["digest"][:-2] + f"{int(mark['digest'][-2:], 16) ^ 1:02x}"
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--digest", near)
        assert r.exit_code == 5, r.output
        summary = _summary(r.output)
        assert "file:       DOES NOT MATCH         the two digests are the same width and differ" in summary
        detail = r.output.split("HashMark record at vout", 1)[1]
        assert "file/digest: DOES NOT MATCH — this is not what the record commits to" in detail
        assert f"you supplied: {near}" in detail
        assert f"the record:   {mark['digest']}" in detail
        assert "(the two digests are the same width and differ)" in detail
        assert "file/digest: MATCHES" not in detail

    def test_a_longer_digest_is_a_width_mismatch_not_a_same_width_one(self, monkeypatch, tmp_path, mark) -> None:
        longer = mark["digest"] + "00"
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--digest", longer, top=["--json"])
        assert r.exit_code == 5, r.output
        dm = json.loads(r.stdout)["records"][0]["digest_match"]
        assert dm["state"] == "DOES NOT MATCH"
        assert dm["reason"] == "you gave 33 bytes; this record commits to a 32-byte sha256 digest"

    def test_a_match_carries_no_reason_and_a_mismatch_carries_one(self, monkeypatch, tmp_path, mark) -> None:
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--digest", mark["digest"], top=["--json"])
        assert r.exit_code == 0, r.output
        dm = json.loads(r.stdout)["records"][0]["digest_match"]
        assert (dm["state"], dm["reason"], dm["algorithm"]) == ("MATCHES", "", "sha256")


class TestAnInabilityIsPrintedWithItsReason:
    def test_cannot_compare_names_why_on_the_detail_line(self, monkeypatch, tmp_path) -> None:
        from tests.test_hashmark_verify_cli import _FakeServer, _tx_with

        digest = hashlib.sha256(b"c").digest()
        broken = b"\x6a" + _push(b"HASHMARK") + _push(bytes([2, 1])) + _push(digest)  # v2 with 3 pushes
        txid, raw = _tx_with(broken)
        r = _verify(monkeypatch, tmp_path, _FakeServer({txid: raw}), txid, "--digest", digest.hex())
        assert r.exit_code == 5, r.output
        assert (
            "file/digest: CANNOT COMPARE — this record is malformed (RECORD DOES NOT DECODE), so no digest "
            "can be read from it"
        ) in r.output
        # The decoder's own words reach the signature line, not a generic fallback.
        assert "RECORD DOES NOT DECODE the record at vout 0: v2 takes 5 or 6 pushes, found 3" in " ".join(
            _summary(r.output).split()
        )


class TestTheSignatureLineCarriesTheAttestationsOwnWords:
    def test_a_forged_signature_says_what_the_attestation_found(self, monkeypatch, tmp_path) -> None:
        from tests.test_hashmark_verify_cli import _FakeServer, _mark_script, _tx_with

        script = bytearray(_mark_script(b"c", PrivateKey()))
        script[-5] ^= 1  # inside the signature: still well-formed, no longer the signer's
        txid, raw = _tx_with(bytes(script))
        r = _verify(monkeypatch, tmp_path, _FakeServer({txid: raw}), txid, top=["--json"])
        assert r.exit_code == 5, r.output
        sig = json.loads(r.stdout)["checks"]["signature"]
        assert sig["state"] == "DOES NOT VERIFY"
        assert sig["reason"].startswith("the record at vout 0: recovered key does not match the committed signer")

    def test_unverifiable_names_the_chain_it_would_have_been_checked_against(self) -> None:
        from pyrxd.cli.hashmark_cmds import _signature_check

        att = {"outcome": "unverifiable", "detail": "no curve", "assumed_network": "radiant-mainnet"}
        assert _signature_check({"outcome": "ok", "attestation": att}) == (
            "NOT CHECKED",
            "no curve (it would be checked against radiant-mainnet)",
        )
        att.pop("assumed_network")
        assert _signature_check({"outcome": "ok", "attestation": att}) == ("NOT CHECKED", "no curve")


def _checks(sig: str, digest: str, name: str) -> dict:
    return {
        "signature": {"state": sig, "reason": ""},
        "digest": {"state": digest, "reason": ""},
        "name": {"state": name, "reason": ""},
    }


class TestWhichRecordTheSummaryIsAbout:
    """``_choose_witness`` decides whose words the summary prints. The rule its docstring states:
    most checks held first, then a verified signature, then a matching digest, then an established
    name, then the LOWEST vout — "so the answer does not depend on iteration order". Each case
    below ties every key but one, with the order of the list arranged so that a key that stopped
    deciding would hand the choice to the other record."""

    def _chosen(self, *per_record) -> object:
        from pyrxd.cli.hashmark_cmds import _choose_witness

        return _choose_witness([(vout, {}, checks) for vout, checks in per_record])[0]

    def test_a_matching_digest_outranks_an_established_name_at_equal_counts(self) -> None:
        # Two holds each; both signatures verify. The digest decides, before the name.
        a = _checks("VERIFIED", "MATCHES", "NOT ESTABLISHED")
        b = _checks("VERIFIED", "DOES NOT MATCH", "ESTABLISHED")
        assert self._chosen((0, b), (1, a)) == 1

    def test_an_established_name_decides_when_everything_before_it_ties(self) -> None:
        # A copied record can commit to a signer whose name IS established while its own signature
        # fails; beside a v1 record over the same digest, both hold two checks and neither verifies.
        forged_copy = _checks("DOES NOT VERIFY", "MATCHES", "ESTABLISHED")
        v1 = _checks("NO SIGNATURE", "MATCHES", "NOT ESTABLISHED")
        assert self._chosen((0, v1), (1, forged_copy)) == 1
        assert self._chosen((0, v1), (1, _checks("DOES NOT VERIFY", "MATCHES", "NOT THE SIGNER"))) == 0

    @pytest.mark.parametrize("vouts", [(1, 0), (2, 1), (0, 1)])
    def test_a_full_tie_goes_to_the_lowest_vout_whatever_the_order(self, vouts) -> None:
        same = _checks("VERIFIED", "NOT CHECKED", "NOT CHECKED")
        assert self._chosen((vouts[0], same), (vouts[1], same)) == min(vouts)


class TestVerifysArgumentsAreRefusedAtTheDoor:
    """Bad input is exit 1 (the command's refusal) or 2 (click's usage error) — never 5, which is a
    verdict about a mark, and never 0."""

    @pytest.mark.parametrize("digest", ["abc", "", "   "])
    def test_an_odd_length_or_empty_digest_is_refused_before_the_network(
        self, monkeypatch, tmp_path, mark, digest
    ) -> None:
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--digest", digest)
        assert r.exit_code == 1, r.output
        assert "--digest is not an even-length hex string" in r.output
        assert mark["server"].calls == [], "refused before anything was fetched"

    def test_the_honest_pair_an_even_length_hex_digest_of_another_width_is_judged(
        self, monkeypatch, tmp_path, mark
    ) -> None:
        """Six hex characters: even, so asked and answered (a width mismatch), not refused."""
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--digest", "abcdef")
        assert r.exit_code == 5, r.output
        assert "you gave 3 bytes" in r.output

    @pytest.mark.parametrize("what", ["directory", "missing"])
    def test_a_file_that_is_not_a_readable_file_is_a_usage_error(self, monkeypatch, tmp_path, mark, what) -> None:
        path = tmp_path / what
        if what == "directory":
            path.mkdir()
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], "--file", str(path))
        assert r.exit_code == 2, r.output
        assert mark["server"].calls == []

    def test_a_floor_of_zero_confirmations_is_refused(self, monkeypatch, tmp_path, mark) -> None:
        """A floor of 0 would accept a mark in the mempool, which fixes no time."""
        from tests.test_hashmark_verify_cli import _run

        r = _run(monkeypatch, mark["server"], ["verify", mark["txid"], "--min-confirmations", "0"], tmp_path=tmp_path)
        assert r.exit_code == 2, r.output
        assert mark["server"].calls == []

    def test_hex_longer_than_a_contract_id_is_not_a_transaction_id(self, monkeypatch, tmp_path, mark) -> None:
        """72 hex characters is a contract id; 80 is neither that nor a txid, and is refused as such
        rather than parsed as a contract id with extra digits."""
        r = _verify(monkeypatch, tmp_path, mark["server"], "ab" * 40)
        assert r.exit_code == 1, r.output
        assert "that is not a transaction id" in r.output
        assert mark["server"].calls == []


class TestTheJsonSaysWhatWasCompared:
    @pytest.mark.parametrize("given", ["digest", "file", "neither"])
    def test_the_comparison_names_its_source(self, monkeypatch, tmp_path, mark, given) -> None:
        extra = {"digest": ("--digest", mark["digest"]), "file": ("--file", str(mark["file"])), "neither": ()}[given]
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], *extra, top=["--json"])
        assert r.exit_code == 0, r.output
        dm = json.loads(r.stdout)["records"][0]["digest_match"]
        assert dm["source"] == {"digest": "--digest", "file": str(mark["file"]), "neither": ""}[given]
        assert dm["state"] == ("NOT CHECKED" if given == "neither" else "MATCHES")

    def test_no_present_tense_wave_lookup_is_made_unless_asked(self, monkeypatch, tmp_path, mark) -> None:
        """``--verify-wave`` sends a lookup keyed on the signer's address to the server. Without the
        flag, nothing about the signer is asked."""
        r = _verify(monkeypatch, tmp_path, mark["server"], mark["txid"], top=["--json"])
        assert r.exit_code == 0, r.output
        assert not [c for c in mark["server"].calls if c[0] == "call_extension"], mark["server"].calls
        assert "wave_identity" not in json.loads(r.stdout)["records"][0]


def _forged(content: bytes) -> bytes:
    """A well-formed signed record whose signature no longer recovers to its committed signer."""
    from tests.test_hashmark_verify_cli import _mark_script

    script = bytearray(_mark_script(content, PrivateKey()))
    script[-5] ^= 1
    return bytes(script)


def _serve(*scripts: bytes):
    from tests.test_hashmark_verify_cli import _FakeServer, _tx_with

    txid, raw = _tx_with(*scripts)
    return txid, _FakeServer({txid: raw})


class TestWhatCouldNotBeReadIsCountedExactly:
    def test_a_file_beside_only_an_unreadable_record_says_nothing_names_an_algorithm(
        self, monkeypatch, tmp_path
    ) -> None:
        """The algorithm is read from records that DECODED. A malformed record's header byte is not
        a readable record naming an algorithm, however well-formed that one byte is."""
        digest = hashlib.sha256(b"c").digest()
        txid, server = _serve(b"\x6a" + _push(b"HASHMARK") + _push(bytes([2, 1])) + _push(digest))
        target = tmp_path / "c.txt"
        target.write_bytes(b"c")
        r = _verify(monkeypatch, tmp_path, server, txid, "--file", str(target), top=["--json"])
        assert r.exit_code == 5, r.output
        dm = json.loads(r.stdout)["records"][0]["digest_match"]
        assert dm["state"] == "CANNOT COMPARE"
        assert (
            dm["reason"] == "no readable record here names a hash algorithm, so there is nothing to hash the file with"
        )

    def test_an_output_the_classifier_DID_read_is_not_counted_as_unread(self, monkeypatch, tmp_path) -> None:
        """A Glyph commit output beside the mark is classified (as ``commit-nft``), so the mark is
        the only record IN the transaction, not merely the only one that could be read."""
        from pyrxd.glyph.script import build_commit_locking_script
        from pyrxd.security.types import Hex20
        from tests.test_hashmark_verify_cli import _mark_script

        commit = build_commit_locking_script(hashlib.sha256(b"p").digest(), Hex20(bytes(range(20))), is_nft=True)
        txid, server = _serve(_mark_script(b"c", PrivateKey()), commit)
        r = _verify(monkeypatch, tmp_path, server, txid)
        assert r.exit_code == 0, r.output
        assert "record:     vout 0                 the only HashMark record in this transaction" in r.output
        assert "could not be classified" not in r.output

    def test_two_other_unread_outputs_are_counted_as_two(self, monkeypatch, tmp_path) -> None:
        from tests.test_hashmark_verify_cli import _mark_script
        from tests.test_verify_names_the_output_you_gave import _CHANGE, _crash_on

        unread_a = b"\x76\xa9\x14" + bytes([7] * 20) + b"\x88\xac"
        unread_b = b"\x76\xa9\x14" + bytes([9] * 20) + b"\x88\xac"
        txid, server = _serve(_mark_script(b"c", PrivateKey()), _CHANGE, unread_a, unread_b)
        _crash_on(monkeypatch, unread_a, unread_b)
        r = _verify(monkeypatch, tmp_path, server, f"{txid}:1")
        flat = " ".join(r.output.split())
        assert (
            "2 other outputs could not be classified here, so whether any of them is a HashMark record is unknown."
        ) in flat, r.output

    def test_a_missing_output_names_the_last_real_one(self, monkeypatch, tmp_path) -> None:
        from tests.test_hashmark_verify_cli import _mark_script
        from tests.test_verify_names_the_output_you_gave import _CHANGE

        txid, server = _serve(_mark_script(b"c", PrivateKey()), _CHANGE, _CHANGE)
        r = _verify(monkeypatch, tmp_path, server, f"{txid}:7")
        assert r.exit_code == 1, r.output
        assert "that transaction has only 3 outputs (numbered 0 to 2), so there is no output 7" in r.output


class TestTheSignatureLineSaysWhichRecordItIsAbout:
    """When a record elsewhere is forged, the signature line is about THAT record — and only then.
    Both halves: saying it when the forged record IS the verdict's record is as false as omitting
    it when it is not."""

    def test_a_forgery_BEFORE_the_verdicts_record_is_named_on_the_record_line(self, monkeypatch, tmp_path) -> None:
        from tests.test_hashmark_verify_cli import _mark_script

        txid, server = _serve(_forged(b"f"), _mark_script(b"c", PrivateKey()))
        r = _verify(monkeypatch, tmp_path, server, txid, top=["--json"])
        out = json.loads(r.stdout)
        assert (out["verdict_record"]["vout"], out["verdict_record"]["refusal_vout"]) == (1, 0)
        human = " ".join(_verify(monkeypatch, tmp_path, server, txid).output.split())
        assert (
            "one of 2 HashMark records; file and name are about THIS one, and the signature line is about the "
            "record at vout 0"
        ) in human

        named = _verify(monkeypatch, tmp_path, server, f"{txid}:1", top=["--json"])
        says = " ".join(json.loads(named.stdout)["named_by"]["says"])
        assert (
            "Output 1, the one you named, holds the HashMark record the verdict below is about, except its "
            "signature line, which is about the record at vout 0."
        ) in says

        # Output 0 holds a record too, at a LOWER vout than the verdict's: it is not the verdict's.
        named0 = json.loads(_verify(monkeypatch, tmp_path, server, f"{txid}:0", top=["--json"]).stdout)["named_by"]
        assert named0["verdict_is_about_it"] is False
        assert named0["output_holds_record"] is True
        assert (
            "Output 0, the one you named, holds a HashMark record, but the verdict below is about the record at vout 1"
        ) in " ".join(named0["says"])

    def test_when_the_forged_record_IS_the_verdicts_record_nothing_is_excepted(self, monkeypatch, tmp_path) -> None:
        txid, server = _serve(_forged(b"f"), _forged(b"g"))
        out = json.loads(_verify(monkeypatch, tmp_path, server, txid, top=["--json"]).stdout)
        assert (out["verdict_record"]["vout"], out["verdict_record"]["refusal_vout"]) == (0, 0)
        human = " ".join(_verify(monkeypatch, tmp_path, server, txid).output.split())
        assert "of the 2 HashMark records here, none passes every check on its own" in human
        assert "the signature line is about the record at vout" not in human

        named = _verify(monkeypatch, tmp_path, server, f"{txid}:0", top=["--json"])
        says = " ".join(json.loads(named.stdout)["named_by"]["says"])
        assert "Output 0, the one you named, holds the HashMark record the verdict below is about." in says
        assert "except its signature line" not in says
