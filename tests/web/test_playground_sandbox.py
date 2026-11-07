"""The playground's sandbox chain (``docs/inspect_static/playground/playground.py``).

Run under CPython with the real coincurve. Every refusal test is paired with the honest
path it sits beside, so a rule that refuses everything fails here as loudly as one that
refuses nothing.

The page runs the same module under Pyodide; the Pyodide-shape subprocess in
``tests/web/test_playground_lessons.py`` covers that runtime's import graph and shims.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground"


@pytest.fixture(scope="module")
def pg():
    sys.path.insert(0, str(_DIR))
    try:
        spec = importlib.util.spec_from_file_location("playground", _DIR / "playground.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["playground"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path.remove(str(_DIR))
        sys.modules.pop("playground", None)


@pytest.fixture
def sb(pg):
    pg.reset_sandbox()
    return pg.sandbox


def run(coro):
    return asyncio.run(coro)


def _pay(sb, coin, to_address, amount, fee, *, key=None, sign=True, change=True):
    from pyrxd.script.type import P2PKH
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    key = key or sb.wallet.key
    outs = [TransactionOutput(P2PKH().lock(to_address), amount)]
    if change:
        outs.append(TransactionOutput(P2PKH().lock(sb.wallet.address), coin.value - amount - fee))
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=coin.tx,
                source_output_index=coin.vout,
                unlocking_script_template=P2PKH().unlock(key),
            )
        ],
        tx_outputs=outs,
    )
    if sign:
        tx.sign()
    return tx


FEE = 6_000_000  # over the floor for the 1- and 2-input transactions here (<= ~420 B x 10,000)


class TestPlainPayments:
    def test_an_honest_payment_is_accepted_and_mined(self, sb):
        coin = sb.faucet(rxd=10)
        h = sb.height
        txid = sb.broadcast(_pay(sb, coin, sb.friend.address, 100_000_000, FEE))
        assert sb.height == h + 1
        assert sb.balance(sb.friend) == 100_000_000
        assert sb.chain.confirmations(txid) == 1
        assert {c.rule for c in sb.chain.accepted[txid].checks} >= {"parse", "inputs", "value", "fee", "scripts"}

    def test_a_fee_below_the_floor_is_refused_with_the_floor_named(self, pg, sb):
        from pyrxd.fee_sizing import min_relay_fee

        coin = sb.faucet(rxd=10)
        tx = _pay(sb, coin, sb.friend.address, 100_000_000, 1_000)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "fee"
        assert f"{min_relay_fee(len(tx.serialize())):,}" in str(exc.value)

    def test_the_fee_floor_is_exact(self, pg, sb):
        """Paying the floor to the photon passes; one photon less is refused."""
        from pyrxd.fee_sizing import min_relay_fee

        coin = sb.faucet(rxd=10)

        # A DER signature's length (so the transaction's) varies by a byte with the bytes
        # signed. Pick a size, then vary the payment by a photon until a transaction of
        # exactly that size pays exactly its floor, and one pays a photon less.
        size = len(_pay(sb, coin, sb.friend.address, 100_000_000, FEE).serialize())
        floor = min_relay_fee(size)

        def of_size(fee):
            for k in range(256):
                t = _pay(sb, coin, sb.friend.address, 100_000_000 + k, fee)
                if len(t.serialize()) == size:
                    return t
            raise AssertionError("no transaction of the target size in 256 tries")

        short = of_size(floor - 1)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(short)
        assert exc.value.rule == "fee"
        sb.broadcast(of_size(floor))

    def test_overspending_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=1)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(_pay(sb, coin, sb.friend.address, coin.value + 1, 0, change=False))
        assert exc.value.rule == "value"

    def test_a_double_spend_is_refused_and_names_the_spender(self, pg, sb):
        coin = sb.faucet(rxd=10)
        first = sb.broadcast(_pay(sb, coin, sb.friend.address, 100_000_000, FEE))
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(_pay(sb, coin, sb.friend.address, 200_000_000, FEE))
        assert exc.value.rule == "inputs"
        assert first[:12] in str(exc.value)

    def test_an_unknown_input_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=10)
        tx = _pay(sb, coin, sb.friend.address, 100_000_000, FEE, sign=False)
        tx.inputs[0].source_txid = "ab" * 32
        tx.sign()
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "inputs"

    def test_an_unsigned_input_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=10)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(_pay(sb, coin, sb.friend.address, 100_000_000, FEE, sign=False))
        assert exc.value.rule == "scripts"
        assert "tx.sign()" in exc.value.hint

    def test_a_signature_by_the_wrong_key_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=10)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(_pay(sb, coin, sb.friend.address, 100_000_000, FEE, key=sb.friend.key))
        assert exc.value.rule == "scripts"
        assert "does not own" in str(exc.value)

    def test_editing_an_output_after_signing_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=10)
        tx = _pay(sb, coin, sb.friend.address, 100_000_000, FEE)
        tx.outputs[0].satoshis += 1
        tx.outputs[1].satoshis -= 1
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "scripts"
        assert "does not verify" in str(exc.value)

    def test_trailing_bytes_are_refused(self, pg, sb):
        coin = sb.faucet(rxd=10)
        raw = _pay(sb, coin, sb.friend.address, 100_000_000, FEE).serialize()
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.chain.submit(raw + b"\x00")
        assert exc.value.rule == "parse"
        sb.chain.submit(raw)

    def test_a_refused_transaction_changes_nothing(self, pg, sb):
        coin = sb.faucet(rxd=10)
        utxos = dict(sb.chain.utxos)
        h = sb.height
        with pytest.raises(pg.SandboxRejected):
            sb.broadcast(_pay(sb, coin, sb.friend.address, 100_000_000, 1))
        assert sb.chain.utxos == utxos and sb.height == h


class TestUnknownScripts:
    def test_an_unrecognised_script_is_accepted_only_with_a_warning(self, pg, sb):
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        coin = sb.faucet(rxd=10)
        weird = Script(b"\x51")  # OP_1: anyone can spend
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=coin.tx,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(sb.wallet.key),
                )
            ],
            tx_outputs=[TransactionOutput(weird, coin.value - FEE)],
        )
        tx.sign()
        first = sb.broadcast(tx)
        spend = Transaction(
            tx_inputs=[TransactionInput(source_txid=first, source_output_index=0, unlocking_script=Script(b""))],
            tx_outputs=[TransactionOutput(P2PKH().lock(sb.wallet.address), coin.value - 2 * FEE)],
        )
        txid = sb.broadcast(spend)
        checks = sb.chain.accepted[txid].checks
        warn = [c for c in checks if c.rule == "scripts"]
        assert [c.status for c in warn] == ["warn"]
        assert "NOT evaluated" in warn[0].detail


async def _mint(sb, name="g"):
    from pyrxd.glyph import GlyphMetadata, GlyphProtocol

    minter = sb.minter()
    pending = await minter.commit_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
    return pending, await minter.reveal_nft(pending)


class TestGlyphs:
    def test_mint_and_transfer_an_nft(self, sb):
        from pyrxd.glyph.builder import MIN_FEE_RATE
        from pyrxd.glyph.transfer import build_nft_transfer

        sb.faucet(rxd=10)
        _, result = run(_mint(sb))
        assert (
            run(sb.wallet.collect_spendable())
            and sum(1 for c in sb.wallet.coins() if c.value == result.carrier_value) >= 1
        )
        build = run(build_nft_transfer(sb.wallet, result.ref, sb.friend.pkh, client=sb.client, fee_rate=MIN_FEE_RATE))
        txid = sb.broadcast(build.tx)
        refs = [c for c in sb.chain.accepted[txid].checks if c.rule == "refs"]
        assert [c.status for c in refs] == ["pass"]

    def _nft_coin(self, pg, sb, result):
        from pyrxd.glyph.script import is_nft_script

        return next(c for c in sb.wallet.coins() if is_nft_script(c.script.hex()))

    def _spend_nft(self, sb, coin, scripts, fee_coin):
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        outs = [TransactionOutput(Script(s), coin.value) for s in scripts]
        outs.append(
            TransactionOutput(P2PKH().lock(sb.wallet.address), fee_coin.value - FEE - coin.value * (len(scripts) - 1))
        )
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=coin.tx,
                    source_output_index=coin.vout,
                    unlocking_script_template=P2PKH().unlock(sb.wallet.key),
                ),
                TransactionInput(
                    source_transaction=fee_coin.tx,
                    source_output_index=fee_coin.vout,
                    unlocking_script_template=P2PKH().unlock(sb.wallet.key),
                ),
            ],
            tx_outputs=outs,
        )
        tx.sign()
        return tx

    def test_copying_an_nft_into_two_outputs_is_refused(self, pg, sb):
        from pyrxd.glyph.script import build_nft_locking_script

        sb.faucet(rxd=10)
        _, result = run(_mint(sb))
        nft = self._nft_coin(pg, sb, result)
        fee_coin = sb.faucet(rxd=1)
        one = build_nft_locking_script(sb.friend.pkh, result.ref)
        sb_ok = self._spend_nft(sb, nft, [one], fee_coin)
        two = self._spend_nft(sb, nft, [one, build_nft_locking_script(sb.wallet.pkh, result.ref)], fee_coin)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(two)
        assert exc.value.rule == "refs"
        assert "one output" in str(exc.value)
        sb.broadcast(sb_ok)

    def test_a_ref_from_nowhere_is_refused(self, pg, sb):
        from pyrxd.glyph.script import build_nft_locking_script
        from pyrxd.glyph.types import GlyphRef

        sb.faucet(rxd=10)
        _, result = run(_mint(sb))
        nft = self._nft_coin(pg, sb, result)
        fee_coin = sb.faucet(rxd=1)
        forged = GlyphRef(txid="cd" * 32, vout=0)
        tx = self._spend_nft(sb, nft, [build_nft_locking_script(sb.friend.pkh, forged)], fee_coin)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "refs"

    def test_dropping_an_nft_is_accepted_and_reported_as_a_burn(self, pg, sb):
        from pyrxd.script.type import P2PKH

        sb.faucet(rxd=10)
        _, result = run(_mint(sb))
        nft = self._nft_coin(pg, sb, result)
        fee_coin = sb.faucet(rxd=1)
        tx = self._spend_nft(sb, nft, [P2PKH().lock(sb.friend.address).serialize()], fee_coin)
        txid = sb.broadcast(tx)
        refs = [c for c in sb.chain.accepted[txid].checks if c.rule == "refs"]
        assert [c.status for c in refs] == ["warn"] and "burned" in refs[0].detail

    def test_a_reveal_whose_payload_was_changed_is_refused(self, pg, sb):
        from pyrxd.glyph import GlyphMetadata, GlyphProtocol

        sb.faucet(rxd=10)
        minter = sb.minter()
        pending = run(minter.commit_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="a")))
        from pyrxd.script.type import P2PKH

        honest = minter._build_reveal_tx(pending, sb.wallet.key, P2PKH().lock(sb.wallet.address))
        honest.outputs = honest.outputs[:1]  # the whole commit surplus goes to fee
        honest.sign()
        # Swap the CBOR the reveal carries for another, same length, then re-sign.
        cbor = pending.cbor_bytes
        tampered = bytearray(cbor)
        tampered[-1] ^= 1
        unlock = honest.inputs[0].unlocking_script.serialize()
        assert unlock.endswith(cbor)
        from pyrxd.script.script import Script

        untouched = honest.inputs[0].unlocking_script
        honest.inputs[0].unlocking_script = Script(unlock[: -len(cbor)] + bytes(tampered))
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(honest)
        assert exc.value.rule == "scripts" and "does not hash" in str(exc.value)
        honest.inputs[0].unlocking_script = untouched
        sb.broadcast(honest)

    def test_ft_deploy_transfer_and_inflation(self, pg, sb):
        from pyrxd.glyph import GlyphMetadata, GlyphProtocol
        from pyrxd.glyph.builder import MIN_FEE_RATE
        from pyrxd.glyph.transfer import build_ft_transfer

        sb.faucet(rxd=10)
        minter = sb.minter()
        res = run(minter.deploy_ft(GlyphMetadata(protocol=[GlyphProtocol.FT], name="P", ticker="PLAY"), supply=10_000))
        sb.faucet(rxd=1)
        build = run(
            build_ft_transfer(sb.wallet, res.ref, 2_500, sb.friend.pkh, client=sb.client, fee_rate=MIN_FEE_RATE)
        )
        txid = sb.broadcast(build.tx)
        assert pg.chain_state()["friend"]["ft_units"] == 2_500
        assert any(c.rule == "ft" and "in 10,000, out 10,000" in c.detail for c in sb.chain.accepted[txid].checks)

        # Inflate: re-sign a copy whose token output claims one more unit than came in.
        from pyrxd.glyph.script import is_ft_script

        coin = next(c for c in sb.friend.coins() if is_ft_script(c.script.hex()))
        fee_coin = sb.faucet(sb.friend.address, rxd=1)
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        def ft_tx(units):
            t = Transaction(
                tx_inputs=[
                    TransactionInput(
                        source_transaction=coin.tx,
                        source_output_index=coin.vout,
                        unlocking_script_template=P2PKH().unlock(sb.friend.key),
                    ),
                    TransactionInput(
                        source_transaction=fee_coin.tx,
                        source_output_index=fee_coin.vout,
                        unlocking_script_template=P2PKH().unlock(sb.friend.key),
                    ),
                ],
                tx_outputs=[
                    TransactionOutput(Script(coin.script), units),
                    TransactionOutput(P2PKH().lock(sb.friend.address), fee_coin.value - FEE - (units - coin.value)),
                ],
            )
            t.sign()
            return t

        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(ft_tx(coin.value + 1))
        assert exc.value.rule == "ft"
        sb.broadcast(ft_tx(coin.value))


class TestRunner:
    def test_output_and_txids_are_reported(self, pg, sb):
        r = run(pg.run_program("from playground import sandbox\nc = sandbox.faucet(rxd=1)\nprint('hi', c.value)\n"))
        assert r["error"] is None and r["stdout"] == "hi 100000000\n" and len(r["txids"]) == 1

    def test_the_failing_line_is_the_visitors_line(self, pg, sb):
        r = run(pg.run_program("x = 1\n\ny = x / 0\n"))
        assert r["error"]["type"] == "ZeroDivisionError" and r["error"]["line"] == 3

    def test_a_sandbox_refusal_carries_its_rule_and_hint(self, pg, sb):
        src = (
            "from playground import sandbox\n"
            "from pyrxd.script.type import P2PKH\n"
            "from pyrxd.transaction.transaction import Transaction\n"
            "from pyrxd.transaction.transaction_input import TransactionInput\n"
            "from pyrxd.transaction.transaction_output import TransactionOutput\n"
            "c = sandbox.faucet(rxd=1)\n"
            "tx = Transaction(tx_inputs=[TransactionInput(source_transaction=c.tx, source_output_index=0,\n"
            "    unlocking_script_template=P2PKH().unlock(sandbox.wallet.key))],\n"
            "    tx_outputs=[TransactionOutput(P2PKH().lock(sandbox.friend.address), c.value - 10)])\n"
            "tx.sign()\n"
            "sandbox.broadcast(tx)\n"
        )
        r = run(pg.run_program(src))
        assert r["error"]["type"] == "SandboxRejected" and r["error"]["rule"] == "fee" and r["error"]["line"] == 11
        assert "0.1 RXD per kB" in r["error"]["hint"]

    def test_syntax_errors_name_their_line(self, pg, sb):
        r = run(pg.run_program("x = (\n"))
        assert r["error"]["type"] == "SyntaxError" and r["error"]["line"] == 1

    def test_top_level_await_works(self, pg, sb):
        r = run(pg.run_program("import asyncio\nawait asyncio.sleep(0)\nprint('ok')\n"))
        assert r["error"] is None and r["stdout"] == "ok\n"

    def test_describe_tx_marks_refs_and_explains_them(self, pg, sb):
        sb.faucet(rxd=10)
        run(_mint(sb))
        d = pg.describe_tx()
        nft = [o for o in d["outputs"] if o["class"]["kind"] == "nft"]
        assert len(nft) == 1
        first = nft[0]["ops"][0]
        assert (
            first["name"] == "OP_PUSHINPUTREFSINGLETON"
            and first["kind"] == "ref"
            and "exactly one output" in first["note"]
        )
        commit_in = d["inputs"][0]["class"]["kind"]
        assert commit_in == "commit"
        assert {c["rule"] for c in d["checks"]} == {r for r, _ in pg.RULES}


class TestRuntimeShims:
    def test_pure_pbkdf2_matches_hashlib(self, pg):
        for args in [
            ("sha512", b"pw", b"mnemonicsalt", 2048, 64),
            ("sha256", b"", b"", 3, None),
            ("sha512", b"x" * 200, b"s", 5, 130),
        ]:
            assert pg._pbkdf2_hmac_pure(*args) == hashlib.pbkdf2_hmac(*args)

    def test_opcode_notes_name_real_opcodes(self, pg):
        """Every note is keyed by a byte pyrxd's OpCode enum names; derived from the enum, not typed."""
        from pyrxd.constants import OpCode

        names = {m.value[0]: m.name for m in OpCode if len(m.value) == 1}
        assert pg.OPCODE_NOTES
        for byte in pg.OPCODE_NOTES:
            assert byte in names, hex(byte)
        assert names[0xD8] == "OP_PUSHINPUTREFSINGLETON" and names[0xD0] == "OP_PUSHINPUTREF"
