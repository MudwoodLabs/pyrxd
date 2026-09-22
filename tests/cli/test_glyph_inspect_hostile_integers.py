"""A hostile integer anywhere in a transaction must not crash `pyrxd glyph inspect`.

CBOR carries arbitrary-precision integers (tag 2/3 bignums), and CPython refuses to turn
an integer of more than 4,300 decimal digits into text: ``str()``, f-strings and
``json.dumps`` all raise ``ValueError``. So one output a stranger published — a burn
proof whose ``amount`` is a 12,042-digit bignum — made ``inspect <script>`` and
``inspect <txid> --fetch`` exit with a traceback, in human and ``--json`` mode alike.
The same shape was live in a TIMELOCK reveal's ``unlock_at`` and in every value of a
mutable-glyph update envelope, three unrelated fields.

Every test here goes through the real CLI command (``click`` ``CliRunner``), the same
entry point a user runs: the pasted-script form through the top-level ``cli`` group, the
``--fetch`` form through ``inspect_cmd`` with a mocked ElectrumX client, as
``tests/cli/test_glyph_inspect_cmds.py`` does. Each refusal is paired with the honest
value it must still pass.

The guards, and the test that fails when each is removed:

* ``parse_burn_proof`` keeps ``amount`` only in ``0..2**63-1`` —
  ``TestTheBurnAmountIsARangeCheckedCount``.
* ``_inspect_script`` / ``_classify_raw_tx`` return their payload through
  ``_render_safe`` — ``TestTheWholePayloadIsBounded``.
* ``_sanitize_update_fields`` stringifies through ``_display_text`` —
  ``TestUpdateEnvelopeValues``.
* the human dMint renderer computes the cap only from integers —
  ``test_an_oversized_dmint_state_renders_without_a_cap``.
"""

from __future__ import annotations

import json
import sys
from fractions import Fraction
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from click.testing import CliRunner

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_cmds import inspect_cmd
from pyrxd.cli.main import cli
from pyrxd.glyph._inspect_core import _MAX_RENDERED_INT_BITS
from pyrxd.glyph.burn import MAX_BURN_AMOUNT, build_burn_proof_script, parse_burn_proof
from pyrxd.glyph.dmint import DmintDeployParams, build_dmint_contract_script
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix
from pyrxd.glyph.types import GlyphRef
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import RawTx
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

#: 40,001 bits, 12,042 decimal digits — the reproducer's value, and well past the 4,300 limit.
_BIG = 2**40_000
_BIG_TEXT = "<oversized integer: 40001 bits>"

_TOKEN = GlyphRef(txid="ab" * 32, vout=0)
_P2PKH = b"\x76\xa9\x14" + bytes(range(20)) + b"\x88\xac"
_CEK_HASH = "sha256:" + "00" * 32


# --------------------------------------------------------------------------- builders


def _burn_script(amount: object) -> bytes:
    """A burn-proof OP_RETURN carrying *amount* verbatim.

    Hand-encoded rather than built with ``build_burn_proof_script``: the writer now refuses
    exactly the values these tests need to put on chain, and a stranger's wallet is not
    bound by pyrxd's writer.
    """
    cbor = cbor2.dumps({"v": 2, "p": [6], "action": "burn", "token_ref": "ab" * 32 + ":0", "amount": amount})
    push = b"\x4c" + bytes([len(cbor)]) if len(cbor) <= 0xFF else b"\x4d" + len(cbor).to_bytes(2, "little")
    return b"\x6a\x03gly\x01\x02\x01\x06" + push + cbor


def _reveal_input(envelope: object) -> TransactionInput:
    """An input whose scriptSig carries *envelope* as raw CBOR after a ``gly`` marker."""
    suffix = build_reveal_scriptsig_suffix(cbor2.dumps(envelope))
    scriptsig = bytes([0x47]) + bytes(71) + bytes([0x21]) + bytes(33) + suffix
    return TransactionInput(source_txid="aa" * 32, source_output_index=0, unlocking_script=Script(scriptsig))


def _dmint_script(*, max_height: int, reward: int) -> bytes:
    """A V2 dMint contract from the production builder, which accepts any width."""
    return build_dmint_contract_script(
        DmintDeployParams(
            contract_ref=GlyphRef(txid="aa" * 32, vout=1),
            token_ref=GlyphRef(txid="bb" * 32, vout=0),
            max_height=max_height,
            reward=reward,
            difficulty=10,
        )
    )


# --------------------------------------------------------------------------- CLI drivers


def _inspect_script(runner: CliRunner, script: bytes, mode: str):
    """``pyrxd [--json] glyph inspect <hex>`` through the top-level command group."""
    args = (["--json"] if mode == "json" else []) + ["glyph", "inspect", script.hex()]
    return runner.invoke(cli, args)


def _inspect_fetch(runner: CliRunner, mode: str, *, inputs=(), outputs=None):
    """``pyrxd glyph inspect <txid> --fetch`` against a mocked ElectrumX serving one tx.

    Always carries an honest P2PKH output first, so every test also shows that the rest of
    the transaction is still reported — the failure being fixed took the whole listing down.
    """
    tx = Transaction(
        tx_inputs=list(inputs),
        tx_outputs=[TransactionOutput(Script(_P2PKH), 1000), *(outputs or [])],
    )
    raw = bytes(tx.serialize())
    txid = hash256(raw)[::-1].hex()
    client = MagicMock()
    client.get_transaction = AsyncMock(return_value=RawTx(raw))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    ctx = CliContext(
        config=Config(
            network="mainnet",
            electrumx="wss://example.invalid/",
            fee_rate=10_000,
            wallet_path=Path("/nonexistent/wallet.dat"),
        ),
        network="mainnet",
        electrumx_url="wss://example.invalid/",
        fee_rate=10_000,
        wallet_path=Path("/nonexistent/wallet.dat"),
        output_mode=mode,
        client_factory=lambda: client,
    )
    return runner.invoke(inspect_cmd, [txid, "--fetch"], obj=ctx)


def _ok(result) -> str:
    """The output of a run that must have succeeded — with the traceback if it did not."""
    assert result.exit_code == 0, (result.output, repr(result.exception))
    return result.output


def _burn_of(payload: dict) -> dict:
    """The ``burn`` block from either payload form."""
    if payload.get("form") == "txid":
        (row,) = [r for r in payload["outputs"] if r["type"] == "op_return-burn"]
        return row["burn"]
    return payload["burn"]


# --------------------------------------------------------------------------- the burn amount


class TestTheBurnAmountIsARangeCheckedCount:
    """`parse_burn_proof` keeps `amount` only as a count: an int in 0..2**63-1."""

    @pytest.mark.parametrize("form", ["script", "fetch"])
    def test_a_bignum_amount_is_withheld_with_its_reason_in_json(self, runner, form) -> None:
        script = _burn_script(_BIG)
        if form == "script":
            result = _inspect_script(runner, script, "json")
        else:
            result = _inspect_fetch(runner, "json", outputs=[TransactionOutput(Script(script), 0)])
        payload = json.loads(_ok(result))
        burn = _burn_of(payload)
        assert burn["claims"]["amount"] is None
        assert "40001-bit integer" in burn["amount_withheld"]
        # The reason says what the value was NOT — never the value itself.
        assert "above 2**63 - 1" in burn["amount_withheld"]
        if form == "fetch":
            assert payload["outputs"][0]["type"] == "p2pkh"

    @pytest.mark.parametrize("form", ["script", "fetch"])
    def test_a_bignum_amount_is_withheld_with_its_reason_in_human(self, runner, form) -> None:
        script = _burn_script(_BIG)
        if form == "script":
            out = _ok(_inspect_script(runner, script, "human"))
        else:
            out = _ok(_inspect_fetch(runner, "human", outputs=[TransactionOutput(Script(script), 0)]))
            assert "type=p2pkh" in out
        assert "amount: [withheld — it is a 40001-bit integer (above 2**63 - 1)" in out
        # The caveat still travels with the claims.
        assert "anyone can write one about any token" in out

    @pytest.mark.parametrize(
        ("amount", "reason_fragment"),
        [
            (-1, "it is -1 (negative)"),
            (-(2**63), "negative"),
            (2**63, "above 2**63 - 1"),
            pytest.param(-_BIG, "40001-bit integer (negative)", id="negative-bignum"),
            (1.5, "it is a float, not an integer"),
            (True, "it is a boolean, not an integer"),
            ("250", "it is a str, not an integer"),
        ],
    )
    def test_every_value_that_is_not_a_count_is_withheld(self, runner, amount, reason_fragment) -> None:
        payload = json.loads(_ok(_inspect_script(runner, _burn_script(amount), "json")))
        assert payload["type"] == "op_return-burn"
        assert payload["burn"]["claims"]["amount"] is None
        assert reason_fragment in payload["burn"]["amount_withheld"]

    @pytest.mark.parametrize("amount", [0, 1, 250, 2**53, MAX_BURN_AMOUNT])
    def test_every_honest_count_is_kept_exactly(self, runner, amount) -> None:
        """The honest path. Photonic writes a JS number (so <= 2**53); pyrxd's own writer
        allows up to 2**63 - 1. Both must read back as the number they are."""
        script = build_burn_proof_script(_TOKEN, amount=amount)
        payload = json.loads(_ok(_inspect_script(runner, script, "json")))
        assert payload["burn"]["claims"]["amount"] == amount
        assert "amount_withheld" not in payload["burn"]
        out = _ok(_inspect_script(runner, script, "human"))
        assert f"amount: {amount}" in out
        assert "withheld" not in out

    def test_a_proof_with_no_amount_says_nothing_about_one(self, runner) -> None:
        """An NFT burn names no amount. That must not read as a withheld one."""
        payload = json.loads(_ok(_inspect_script(runner, build_burn_proof_script(_TOKEN), "json")))
        assert payload["burn"]["claims"]["amount"] is None
        assert "amount_withheld" not in payload["burn"]
        assert "amount" not in _ok(_inspect_script(runner, build_burn_proof_script(_TOKEN), "human"))

    def test_an_explicit_null_amount_is_the_same_as_none(self) -> None:
        proof = parse_burn_proof(_burn_script(None))
        assert proof is not None and proof.amount is None and proof.amount_withheld is None


class TestTheWriterAndReaderAgree:
    """`build_burn_proof_script` refuses what `parse_burn_proof` withholds, so pyrxd cannot
    write a proof pyrxd will not read back. The crash reproducer was built with the writer."""

    @pytest.mark.parametrize("amount", [-1, MAX_BURN_AMOUNT + 1, pytest.param(_BIG, id="bignum"), True])
    def test_the_writer_refuses_what_the_reader_withholds(self, amount) -> None:
        with pytest.raises(ValidationError, match="must be >= 0"):
            build_burn_proof_script(_TOKEN, amount=amount)

    @pytest.mark.parametrize("amount", [0, 1, MAX_BURN_AMOUNT])
    def test_the_writer_accepts_every_count_the_reader_keeps(self, amount) -> None:
        proof = parse_burn_proof(build_burn_proof_script(_TOKEN, amount=amount))
        assert proof is not None and proof.amount == amount and proof.amount_withheld is None


# --------------------------------------------------------------------------- the payload bound


class TestTheWholePayloadIsBounded:
    """`_inspect_script` and `_classify_raw_tx` return their payload through `_render_safe`."""

    @staticmethod
    def _timelock_reveal(unlock_at: int) -> TransactionInput:
        return _reveal_input(
            {"p": [2], "crypto": {"timelock": {"mode": "block", "unlock_at": unlock_at, "cek_hash": _CEK_HASH}}}
        )

    def test_a_bignum_timelock_unlock_at_is_bounded_in_json(self, runner) -> None:
        """`TimelockSpec.from_dict` takes `int(unlock_at)` with no width limit, and nothing
        in `_classify_raw_tx`'s metadata block is an output row, so only the payload-level
        bound stands between this value and `json.dumps`."""
        payload = json.loads(_ok(_inspect_fetch(runner, "json", inputs=[self._timelock_reveal(_BIG)])))
        assert payload["metadata"]["timelock"]["unlock_at"] == _BIG_TEXT
        assert payload["outputs"][0]["type"] == "p2pkh"

    def test_a_bignum_timelock_unlock_at_is_bounded_in_human(self, runner) -> None:
        out = _ok(_inspect_fetch(runner, "human", inputs=[self._timelock_reveal(_BIG)]))
        assert f"timelock: opens at {_BIG_TEXT} (block)" in out

    def test_an_honest_unlock_at_is_still_a_number(self, runner) -> None:
        payload = json.loads(_ok(_inspect_fetch(runner, "json", inputs=[self._timelock_reveal(900_000)])))
        assert payload["metadata"]["timelock"]["unlock_at"] == 900_000
        out = _ok(_inspect_fetch(runner, "human", inputs=[self._timelock_reveal(900_000)]))
        assert "timelock: opens at 900000 (block)" in out

    @pytest.mark.parametrize("mode", ["human", "json"])
    def test_an_oversized_dmint_state_renders_without_a_cap(self, runner, mode) -> None:
        """A contract script's state pushes are whatever its deployer wrote — the builder and
        parser both take 1,500-bit values. The bound turns them into text, so the human
        renderer's `max_height * reward` must not assume integers."""
        script = _dmint_script(max_height=2**1500, reward=2**1500)
        out = _ok(_inspect_script(runner, script, mode))
        if mode == "json":
            payload = json.loads(out)
            assert payload["type"] == "dmint"
            assert payload["max_height"] == payload["reward"] == "<oversized integer: 1501 bits>"
        else:
            assert "reward:       <oversized integer: 1501 bits> photons/mint" in out
            assert "this contract's cap: not computed" in out

    def test_an_honest_dmint_still_prints_its_cap(self, runner) -> None:
        out = _ok(_inspect_script(runner, _dmint_script(max_height=1000, reward=100), "human"))
        assert "this contract's cap: 100,000 photons (1,000 mints x 100)" in out

    @pytest.mark.parametrize(("bits", "kept"), [(_MAX_RENDERED_INT_BITS, True), (_MAX_RENDERED_INT_BITS + 1, False)])
    def test_the_bound_is_exactly_where_it_says(self, runner, bits, kept) -> None:
        """At the bound a value is still a number; one bit past it is text."""
        value = 2**bits - 1
        payload = json.loads(_ok(_inspect_script(runner, _dmint_script(max_height=value, reward=1), "json")))
        assert payload["max_height"] == (value if kept else f"<oversized integer: {bits} bits>")

    def test_the_bound_renders_under_the_lowest_limit_a_process_can_set(self, runner) -> None:
        """THE REASON FOR 1024, EXECUTED. The widest number a renderer derives from two
        bounded fields is the dMint cap; at the bound it is ~2048 bits, 617 digits, under the
        640-digit floor `sys.set_int_max_str_digits` accepts. So inspect must work with the
        interpreter set to that floor. Raise the bound past ~1060 bits and this fails."""
        floor = getattr(sys.int_info, "str_digits_check_threshold", None)
        if floor is None:  # pragma: no cover - interpreters before the limit existed
            pytest.skip("this interpreter has no int-to-str digit limit")
        widest = 2**_MAX_RENDERED_INT_BITS - 1
        script = _dmint_script(max_height=widest, reward=widest)
        before = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(floor)
        try:
            out = _ok(_inspect_script(runner, script, "human"))
        finally:
            sys.set_int_max_str_digits(before)
        assert "this contract's cap:" in out and "not computed" not in out


# --------------------------------------------------------------------------- update envelopes


class TestUpdateEnvelopeValues:
    """A mutable-glyph update envelope is raw CBOR with no ``p`` — its values are not typed
    by any decoder. ``_sanitize_update_fields`` used to ``str()`` each one inside the
    classifier, so a bignum raised before either output mode ran."""

    _CASES = {
        "top-level value": ({"name": _BIG}, _BIG_TEXT),
        "attrs value": ({"attrs": {"target": _BIG}}, _BIG_TEXT),
        "list element": ({"x": [1, _BIG]}, _BIG_TEXT),
        "set element (tag 258)": ({"x": frozenset({_BIG})}, _BIG_TEXT),
        # Objects whose str() prints the bignum the walk cannot see inside them.
        "unknown tag": ({"x": cbor2.CBORTag(40404, _BIG)}, "<unrenderable CBORTag>"),
        "rational (tag 30)": ({"x": Fraction(_BIG, 3)}, "<unrenderable Fraction>"),
    }

    @pytest.mark.parametrize("case", sorted(_CASES))
    @pytest.mark.parametrize("mode", ["human", "json"])
    def test_a_hostile_value_is_named_not_raised(self, runner, case, mode) -> None:
        envelope, expected = self._CASES[case]
        out = _ok(_inspect_fetch(runner, mode, inputs=[_reveal_input(envelope)]))
        if mode == "json":
            payload = json.loads(out)
            (env,) = payload["glyph_envelopes"]
            assert env["kind"] == "update"
            assert expected in json.dumps(env["fields"])
            assert payload["outputs"][0]["type"] == "p2pkh"
        else:
            assert "UPDATE" in out and expected in out

    def test_nesting_past_the_walk_depth_is_named(self, runner) -> None:
        """The walk stops at `_MAX_RENDER_DEPTH` and says so. This pins that the bound
        exists; it does not show a crash without it, because cbor2 6.x refuses nesting past
        400 on its own."""
        value: object = _BIG
        for _ in range(40):
            value = [value]
        out = _ok(_inspect_fetch(runner, "json", inputs=[_reveal_input({"x": value})]))
        assert "nested more than 32 levels deep" in out

    def test_honest_update_values_render_as_themselves(self, runner) -> None:
        envelope = {"attrs": {"target": "an honest target", "n": 5}, "desc": "renamed"}
        payload = json.loads(_ok(_inspect_fetch(runner, "json", inputs=[_reveal_input(envelope)])))
        (env,) = payload["glyph_envelopes"]
        assert env["fields"] == {"attrs": {"target": "an honest target", "n": "5"}, "desc": "renamed"}
        out = _ok(_inspect_fetch(runner, "human", inputs=[_reveal_input(envelope)]))
        assert "attrs.target = an honest target" in out and "n=5" in out and "desc = renamed" in out
