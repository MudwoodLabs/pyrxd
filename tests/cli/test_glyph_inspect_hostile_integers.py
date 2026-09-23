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
* ``loads_chain_cbor`` refuses shared or cyclic CBOR, and ``_render_safe`` marks cycles and
  bounds repeated structure — ``TestSharedAndCyclicCbor``.
* every integer decoded from CBOR goes through ``cbor_int`` before any coercion —
  ``TestDecimalFractionsAreRefusedBeforeAnyCoercion``.
* a whole float up to 2**53 is read as the integer cbor-x meant —
  ``TestPhotonicAmountsAsCborXWritesThem``.
* ``main.b`` must be bytes-shaped before ``bytes()`` — ``TestMediaBytesMustBeBytes``.

The resource tests run the CLI in a SUBPROCESS under a 2 GB memory ceiling and a timeout, so a
regression fails the test instead of hanging the suite or exhausting the machine.
"""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from click.testing import CliRunner

import pyrxd
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_cmds import inspect_cmd
from pyrxd.cli.main import cli
from pyrxd.glyph._inspect_core import _MAX_RENDERED_INT_BITS, _render_safe
from pyrxd.glyph.burn import MAX_BURN_AMOUNT, build_burn_proof_script, parse_burn_proof
from pyrxd.glyph.dmint import DmintDeployParams, build_dmint_contract_script
from pyrxd.glyph.payload import _encode_payload_push, build_reveal_scriptsig_suffix, decode_payload, loads_chain_cbor
from pyrxd.glyph.types import GlyphRef
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.security.json_guards import cbor_int
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
            (1.5, "a float with a fractional part is not an integer"),
            (float("inf"), "a non-finite float"),
            (float(2**53 + 2), "a float above 2**53 cannot hold an exact integer"),
            (True, "a boolean is not an integer"),
            ("250", "a str is not an integer"),
        ],
    )
    def test_every_value_that_is_not_a_count_is_withheld(self, runner, amount, reason_fragment) -> None:
        payload = json.loads(_ok(_inspect_script(runner, _burn_script(amount), "json")))
        assert payload["type"] == "op_return-burn"
        assert payload["burn"]["claims"]["amount"] is None
        assert reason_fragment in payload["burn"]["amount_withheld"]

    @pytest.mark.parametrize("amount", [0, 1, 250, 2**53, MAX_BURN_AMOUNT])
    def test_every_honest_count_is_kept_exactly(self, runner, amount) -> None:
        """The honest path for pyrxd's own writer, which takes an int up to 2**63 - 1: every one
        must read back as the number it is. Photonic's side of the honest path — cbor-x writes a
        JS number of 2**32 or more as a FLOAT — is `TestPhotonicAmountsAsCborXWritesThem`."""
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

    @pytest.mark.parametrize("amount", [-1, MAX_BURN_AMOUNT + 1, pytest.param(_BIG, id="bignum"), True, 5e9])
    def test_the_writer_refuses_what_the_reader_withholds(self, amount) -> None:
        """A float too: the reader accepts whole floats only because cbor-x writes them, and a
        Python caller of the writer passing one has a bug the writer should name."""
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


# --------------------------------------------------------------------------- Photonic amounts


_PHOTONIC_VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "photonic_burn_proofs_cbor_x.json").read_text()
)


class TestPhotonicAmountsAsCborXWritesThem:
    """An honest Photonic burn of 2**32 units or more arrives as a FLOAT.

    cbor-x — Photonic's encoder — writes every JS number of 2**32 or more as a float64. The
    bytes here were produced by cbor-x itself (`tests/fixtures/photonic_burn_proofs_cbor_x.json`
    records how), not typed by hand. Reading an integral float up to 2**53 as the integer it is
    keeps these honest; past 2**53 the JS number was rounded before it was encoded.
    """

    @staticmethod
    def _script(cbor_hex: str) -> bytes:
        cbor = bytes.fromhex(cbor_hex)
        return b"\x6a\x03gly\x01\x02\x01\x06" + _encode_payload_push(cbor)

    def test_the_fixture_really_holds_floats_where_the_claim_says(self) -> None:
        """Non-vacuity: without this, a fixture that encoded every amount as an integer would
        make the honest-path test below pass for the wrong reason."""
        kinds = {
            v["amount_js"]: type(cbor2.loads(bytes.fromhex(v["cbor_hex"]))["amount"]).__name__
            for v in _PHOTONIC_VECTORS["vectors"]
        }
        assert kinds["4294967295"] == "int" and kinds["250"] == "int"
        assert kinds["4294967296"] == kinds["5000000000"] == kinds["9007199254740992"] == "float"

    @pytest.mark.parametrize(
        "vector",
        [v for v in _PHOTONIC_VECTORS["vectors"] if v["amount_js"] not in ("9007199254740994", "1.5")],
        ids=lambda v: v["amount_js"],
    )
    def test_an_honest_photonic_amount_is_kept_exactly(self, runner, vector) -> None:
        expected = int(vector["amount_js"])
        script = self._script(vector["cbor_hex"])
        payload = json.loads(_ok(_inspect_script(runner, script, "json")))
        assert payload["burn"]["claims"]["amount"] == expected
        assert "amount_withheld" not in payload["burn"]
        assert f"amount: {expected}" in _ok(_inspect_script(runner, script, "human"))

    @pytest.mark.parametrize(
        ("amount_js", "reason"),
        [
            ("9007199254740994", "a float above 2**53 cannot hold an exact integer"),
            ("1.5", "a float with a fractional part is not an integer"),
        ],
    )
    def test_a_photonic_float_that_is_not_an_exact_count_is_withheld(self, runner, amount_js, reason) -> None:
        (vector,) = [v for v in _PHOTONIC_VECTORS["vectors"] if v["amount_js"] == amount_js]
        payload = json.loads(_ok(_inspect_script(runner, self._script(vector["cbor_hex"]), "json")))
        assert payload["burn"]["claims"]["amount"] is None
        assert reason in payload["burn"]["amount_withheld"]


# --------------------------------------------------------------------------- bounded subprocess runs

#: Every run below that exercises a resource bug runs in a SUBPROCESS with a memory ceiling and a
#: wall-clock timeout. In-process, a regression would not fail the test — it would hang the suite
#: or exhaust the machine. The ceilings are generous for the fixed code (each run takes a second or
#: two, most of it interpreter start-up) and far below what the unfixed code needed.
_MEMORY_CEILING = 2 * 1024**3
_TIMEOUT_S = 45
_PYRXD_ROOT = str(Path(pyrxd.__file__).resolve().parents[1])

_FETCH_DRIVER = """
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from click.testing import CliRunner
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_cmds import inspect_cmd
from pyrxd.hash import hash256
from pyrxd.security.types import RawTx

mode, raw = sys.argv[1], bytes.fromhex(sys.stdin.read().strip())
client = MagicMock()
client.get_transaction = AsyncMock(return_value=RawTx(raw))
client.__aenter__ = AsyncMock(return_value=client)
client.__aexit__ = AsyncMock(return_value=None)
wallet = Path("/nonexistent/wallet.dat")
ctx = CliContext(
    config=Config(network="mainnet", electrumx="wss://example.invalid/", fee_rate=10_000, wallet_path=wallet),
    network="mainnet", electrumx_url="wss://example.invalid/", fee_rate=10_000, wallet_path=wallet,
    output_mode=mode, client_factory=lambda: client,
)
r = CliRunner().invoke(inspect_cmd, [hash256(raw)[::-1].hex(), "--fetch"], obj=ctx)
print(f"EXIT={r.exit_code} EXC={type(r.exception).__name__ if r.exception else None}")
print(r.output)
"""


def _bounded(code: str, *args: str, stdin: str = "") -> tuple[subprocess.CompletedProcess[str], float]:
    """Run *code* in a fresh interpreter under the memory ceiling and the timeout."""

    def _limit() -> None:  # pragma: no cover - runs in the child
        resource.setrlimit(resource.RLIMIT_AS, (_MEMORY_CEILING, _MEMORY_CEILING))

    env = dict(os.environ, PYTHONPATH=_PYRXD_ROOT, PYTHONDONTWRITEBYTECODE="1")
    started = time.monotonic()
    try:
        proc = subprocess.run(  # nosec B603 - fixed interpreter, code from this file
            [sys.executable, "-c", code, *args],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
            preexec_fn=_limit,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"did not finish within {_TIMEOUT_S}s — the unbounded work this test guards against")
    return proc, time.monotonic() - started


def _bounded_fetch(mode: str, *, inputs=()) -> tuple[str, float]:
    tx = Transaction(tx_inputs=list(inputs), tx_outputs=[TransactionOutput(Script(_P2PKH), 1000)])
    proc, elapsed = _bounded(_FETCH_DRIVER, mode, stdin=bytes(tx.serialize()).hex())
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.startswith("EXIT=0 EXC=None"), (proc.stdout[:500], proc.stderr[-1500:])
    return proc.stdout, elapsed


def _raw_reveal_input(cbor: bytes) -> TransactionInput:
    suffix = build_reveal_scriptsig_suffix(cbor)
    scriptsig = bytes([0x47]) + bytes(71) + bytes([0x21]) + bytes(33) + suffix
    return TransactionInput(source_txid="aa" * 32, source_output_index=0, unlocking_script=Script(scriptsig))


# --------------------------------------------------------------------------- shared structure

#: Nine bytes: tag 28 (shareable) around a 2-array of two tag-29 references to itself — a list
#: that contains itself twice. `_render_safe` walked it into 2**32 lists (MemoryError, 5.2 s).
_CYCLIC_CBOR = bytes([0xD8, 0x1C, 0x82, 0xD8, 0x1D, 0x00, 0xD8, 0x1D, 0x00])


def _shared_chain(depth: int) -> object:
    """``[x, x]`` nested *depth* times, the same object twice at every level: 2**depth paths."""
    value: object = 1
    for _ in range(depth):
        value = [value, value]
    return value


def _shared_cbor(document: object) -> bytes:
    return cbor2.dumps(document, value_sharing=True)


class TestSharedAndCyclicCbor:
    """CBOR value-sharing (tags 28/29) turns a few bytes into a graph, and every reader that
    prints or walks the result repeats its work per path. Refused at decode; the payload walk
    is bounded too, as the second line."""

    @pytest.mark.parametrize("mode", ["human", "json"])
    @pytest.mark.parametrize(
        "case",
        [
            "cyclic update value",
            "shared-chain update value",
            "shared-chain creator",
            "shared-chain protocol entry",
        ],
    )
    def test_inspect_fetch_stays_bounded(self, mode, case) -> None:
        """Through the real CLI, in a subprocess under a 2 GB ceiling and a timeout.

        The last two predate this branch: `decode_payload` itself ran `str()` / `repr()` over a
        26-level chain (MemoryError from 168 bytes), so they fail without the decode refusal
        even with `_render_safe` bounded.
        """
        cbor = {
            "cyclic update value": b"\xa1\x61x" + _CYCLIC_CBOR,
            "shared-chain update value": _shared_cbor({"x": _shared_chain(30)}),
            "shared-chain creator": _shared_cbor({"p": [2], "creator": _shared_chain(30)}),
            "shared-chain protocol entry": _shared_cbor({"p": [2, _shared_chain(30)]}),
        }[case]
        assert len(cbor) < 300, "the point is that a few hundred bytes are enough"
        out, elapsed = _bounded_fetch(mode, inputs=[_raw_reveal_input(cbor)])
        assert "value-sharing" in out, out[:2000]
        assert elapsed < _TIMEOUT_S

    def test_the_decoder_refuses_a_shared_or_cyclic_value(self) -> None:
        for blob in (_CYCLIC_CBOR, _shared_cbor(_shared_chain(3)), _shared_cbor({"a": (s := [1]), "b": s})):
            with pytest.raises(ValidationError, match="value-sharing"):
                loads_chain_cbor(blob)

    def test_the_decoder_accepts_honest_values(self) -> None:
        """The honest path: repeated EMPTY containers (interned by CPython, so they share an id)
        and real mainnet bytes — the GLYPH deploy reveal's 65 KB payload — decode unchanged."""
        honest = {"a": [], "b": [], (): 1, ("k",): [[], []], "m": {"x": [1, 2], "y": [1, 2]}}
        assert loads_chain_cbor(cbor2.dumps(honest)) == honest
        mainnet = (Path(__file__).resolve().parents[1] / "fixtures" / "glyph_reveal_cbor.bin").read_bytes()
        assert loads_chain_cbor(mainnet) == cbor2.loads(mainnet)

    def test_the_payload_walk_marks_a_cycle(self) -> None:
        cyclic: list = [1]
        cyclic.append(cyclic)
        assert _render_safe({"x": cyclic}) == {"x": [1, "<cycle: this value contains itself>"]}

    def test_the_payload_walk_bounds_shared_structure(self) -> None:
        """A 30-level shared chain has 2**30 paths. In a subprocess under the ceiling."""
        proc, elapsed = _bounded(
            "from pyrxd.glyph._inspect_core import _render_safe\n"
            "v = 1\n"
            "for _ in range(30):\n"
            "    v = [v, v]\n"
            "print('REPEAT-MARKER' if 'shared structure repeated past' in str(_render_safe(v)) else 'NO MARKER')\n"
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert proc.stdout.strip() == "REPEAT-MARKER"
        assert elapsed < _TIMEOUT_S

    def test_an_honest_large_payload_is_not_truncated(self) -> None:
        """The honest path for the budget: a tree of 60,000 containers — more than a 1,000-output
        transaction produces — renders unchanged, because a tree never repeats a container."""
        tree = {"outputs": [{"vout": i, "refs": [{"n": i}]} for i in range(20_000)]}
        assert _render_safe(tree) == tree


# --------------------------------------------------------------------------- decimal fractions

#: A CBOR decimal fraction (tag 4) meaning 10**1_000_000. `cbor2` decodes it in constant time;
#: `int()` of the result took 69.9 s through `inspect --fetch` (measured by review).
_DECIMAL = cbor2.CBORTag(4, [1_000_000, 1])


class TestDecimalFractionsAreRefusedBeforeAnyCoercion:
    """Every `int()` of a decoded CBOR value became `cbor_int`, which types the value first.
    One case per coercion site; each runs in a bounded subprocess, so a site that regresses to
    `int()` fails on the timeout instead of stalling the suite for minutes."""

    @pytest.mark.parametrize(
        ("site", "document", "evidence"),
        [
            ("payload v", {"p": [2], "v": _DECIMAL}, "CBOR field 'v' must be an integer"),
            (
                "timelock unlock_at",
                {
                    "p": [2],
                    "name": "t",
                    "crypto": {"timelock": {"mode": "block", "unlock_at": _DECIMAL, "cek_hash": _CEK_HASH}},
                },
                '"name": "t"',
            ),
            (
                "encrypted main size",
                {"p": [2], "name": "t", "main": {"type": "x", "hash": "h", "size": _DECIMAL}},
                '"name": "t"',
            ),
            (
                "dmint maxHeight",
                {"p": [1, 4], "dmint": {"algo": 0, "maxHeight": _DECIMAL, "reward": 1, "diff": 1}},
                "dmint CBOR field is not usable",
            ),
            (
                # A SCHEDULE entry is decoded by its own helper (`_schedule_from_cbor`), not by the
                # field list above, so it is a separate site that must refuse a Decimal too.
                "dmint daa schedule height",
                {
                    "p": [1, 4],
                    "dmint": {
                        "algo": 0,
                        "maxHeight": 10,
                        "reward": 1,
                        "diff": 1,
                        "daa": {"mode": 4, "schedule": [{"height": _DECIMAL, "difficulty": 1}]},
                    },
                },
                "dmint CBOR field is not usable",
            ),
            ("royalty bps", {"p": [2], "name": "t", "royalty": {"bps": _DECIMAL, "address": "a"}}, '"name": "t"'),
        ],
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_inspect_fetch_refuses_it_promptly(self, site, document, evidence) -> None:
        out, elapsed = _bounded_fetch("json", inputs=[_raw_reveal_input(cbor2.dumps(document))])
        assert evidence in out, (site, out[:2000])
        assert elapsed < _TIMEOUT_S

    @pytest.mark.parametrize("site", ["burn amount", "reveal proof v", "builder declared dmint"])
    def test_the_other_decoders_refuse_it_promptly(self, site) -> None:
        code = {
            "burn amount": (
                "import cbor2\nfrom pyrxd.glyph.burn import parse_burn_proof\n"
                "from pyrxd.glyph.payload import _encode_payload_push\n"
                "c = cbor2.dumps({'v': 2, 'p': [6], 'action': 'burn', 'token_ref': 'ab' * 32 + ':0',"
                " 'amount': cbor2.CBORTag(4, [1_000_000, 1])})\n"
                "p = parse_burn_proof(b'\\x6a\\x03gly\\x01\\x02\\x01\\x06' + _encode_payload_push(c))\n"
                "print('REFUSED' if p.amount is None and 'Decimal' in p.amount_withheld else 'KEPT')\n"
            ),
            "reveal proof v": (
                "import cbor2\nfrom pyrxd.glyph.timelock_reveal_tx import parse_reveal_proof_script\n"
                "from pyrxd.utils import encode_pushdata\n"
                "def script(v):\n"
                "    c = cbor2.dumps({'v': v, 'p': [9], 'action': 'reveal', 'token_ref': 'x', 'cek': 'y',"
                " 'cek_hash': 'z'})\n"
                "    push = lambda b: encode_pushdata(b, minimal_push=False)\n"
                "    return b'\\x6a' + push(b'gly') + push(b'\\x02') + push(b'\\x09') + push(c)\n"
                # NON-VACUITY: the same construction with an honest `v` must parse, or a `None`
                # below would mean "not a reveal proof at all", not "refused".
                "assert parse_reveal_proof_script(script(2)) is not None, 'fixture does not parse'\n"
                "p = parse_reveal_proof_script(script(cbor2.CBORTag(4, [1_000_000, 1])))\n"
                "print('REFUSED' if p is None else 'KEPT')\n"
            ),
            "builder declared dmint": (
                "import cbor2\nfrom types import SimpleNamespace\n"
                "from pyrxd.glyph.builder import _assert_declared_dmint_matches\n"
                "from pyrxd.security.errors import ValidationError\n"
                "declared = cbor2.loads(cbor2.dumps({'dmint': {'reward': cbor2.CBORTag(4, [1_000_000, 1])}}))\n"
                "params = SimpleNamespace(premine_amount=0, reward_photons=1, max_height=1, num_contracts=1,"
                " difficulty=1, algo=0)\n"
                "try:\n"
                "    _assert_declared_dmint_matches(declared, params)\n"
                "    print('KEPT')\n"
                "except ValidationError:\n"
                "    print('REFUSED')\n"
            ),
        }[site]
        proc, elapsed = _bounded(code)
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert proc.stdout.strip() == "REFUSED", (site, proc.stdout)
        assert elapsed < _TIMEOUT_S

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(7, 7), (-7, -7), (5e9, 5_000_000_000), (float(2**53), 2**53)],
    )
    def test_cbor_int_accepts_integers_and_whole_floats_up_to_2_53(self, value, expected) -> None:
        assert cbor_int(value) == expected

    @pytest.mark.parametrize(
        "value",
        [True, 1.5, float("nan"), float(2**53 + 2), "7", b"7", Decimal(7), Fraction(7), None, [7]],
        ids=repr,
    )
    def test_cbor_int_refuses_everything_else(self, value) -> None:
        with pytest.raises(ValueError, match="not an integer|cannot hold an exact integer"):
            cbor_int(value)


class TestMediaBytesMustBeBytes:
    def test_an_integer_media_body_is_refused_not_allocated(self) -> None:
        """`bytes(n)` of an int allocates n zero bytes: 30 bytes of CBOR became 300 MB of media."""
        with pytest.raises(ValidationError, match="must be a byte string"):
            decode_payload(cbor2.dumps({"p": [2], "main": {"t": "image/png", "b": 300_000_000}}))

    def test_honest_media_bodies_still_decode(self) -> None:
        for body in (b"\x89PNG", cbor2.CBORTag(64, b"\x89PNG"), [0x89, 0x50, 0x4E, 0x47]):
            meta = decode_payload(cbor2.dumps({"p": [2], "main": {"t": "image/png", "b": body}}))
            assert meta.main is not None and meta.main.data == b"\x89PNG"
