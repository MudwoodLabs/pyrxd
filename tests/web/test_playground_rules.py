"""The sandbox rules a defensive review found too loose, or found no test for.

Each refusal sits beside the honest transaction it is closest to, so a rule that refuses
too much fails here as well as one that refuses too little. Where a refusal is about what a
real node would do, the test docstring says whether that verdict was measured on a node or
only read from the script bytes.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground"
FEE = 6_000_000


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


def _wire(ref) -> bytes:
    return ref.to_bytes()


def _p2pkh(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def _tx(sb, inputs, outs, *, sign=True):
    """``inputs``: (coin, key) pairs, each unlocked P2PKH-style; ``outs``: (script, value)."""
    from pyrxd.script.script import Script
    from pyrxd.script.type import P2PKH
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=c.tx, source_output_index=c.vout, unlocking_script_template=P2PKH().unlock(k)
            )
            for c, k in inputs
        ],
        tx_outputs=[TransactionOutput(Script(s), v) for s, v in outs],
    )
    if sign:
        tx.sign()
    return tx


def _mint_nft(sb, name="n"):
    from pyrxd.glyph import GlyphMetadata, GlyphProtocol
    from pyrxd.glyph.script import is_nft_script

    sb.faucet(rxd=10)
    result = run(sb.minter().mint_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name)))
    coin = next(c for c in sb.wallet.coins() if is_nft_script(c.script.hex()) and c.txid == result.reveal_txid)
    return result, coin


def _deploy_ft(sb, supply=10_000):
    from pyrxd.glyph import GlyphMetadata, GlyphProtocol
    from pyrxd.glyph.script import is_ft_script

    sb.faucet(rxd=10)
    res = run(sb.minter().deploy_ft(GlyphMetadata(protocol=[GlyphProtocol.FT], name="P", ticker="P"), supply=supply))
    coin = next(c for c in sb.wallet.coins() if is_ft_script(c.script.hex()) and c.txid == res.reveal_txid)
    return res, coin


def _change(sb, fee_coin, minus=0):
    return (_p2pkh(sb.wallet.pkh), fee_coin.value - FEE - minus)


class TestSingletonIsPushedOnce:
    """A singleton ref may be pushed once in all of a transaction's outputs (review F1)."""

    def test_moving_an_nft_to_one_output_is_accepted(self, sb):
        from pyrxd.glyph.script import build_nft_locking_script

        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        sb.broadcast(
            _tx(
                sb,
                [(nft, k), (fee, k)],
                [(build_nft_locking_script(sb.friend.pkh, result.ref), nft.value), _change(sb, fee)],
            )
        )

    def test_a_singleton_plus_a_normal_push_in_another_output_is_refused(self, pg, sb):
        """H1. pyrxd's own inspect docs record a node refusing this shape (#743, round 2)."""
        from pyrxd.glyph.script import build_nft_locking_script

        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        normal = b"\xd0" + _wire(result.ref) + b"\x75" + _p2pkh(sb.wallet.pkh)
        tx = _tx(
            sb,
            [(nft, k), (fee, k)],
            [
                (build_nft_locking_script(sb.friend.pkh, result.ref), nft.value),
                (normal, nft.value),
                _change(sb, fee, nft.value),
            ],
        )
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "refs" and "in outputs [0, 1]" in str(exc.value)

    def test_two_outputs_each_pushing_normal_then_singleton_are_refused(self, pg, sb):
        """H2. Not measured on a node; refused because a singleton pushed twice is a copy."""
        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        both = b"\xd0" + _wire(result.ref) + b"\x75\xd8" + _wire(result.ref) + b"\x75" + _p2pkh(sb.wallet.pkh)
        tx = _tx(sb, [(nft, k), (fee, k)], [(both, nft.value), (both, nft.value), _change(sb, fee, nft.value)])
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "refs"


class TestSingletonEdges:
    def test_the_same_singleton_twice_in_one_output_is_accepted(self, sb):
        """Radiant reads each output's refs as a set; the sibling rule is about OTHER outputs.
        From reading Radiant Core's validation.h (see docs/plans/2026-05-23-*); not run on a node."""
        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        twice = b"\xd8" + _wire(result.ref) + b"\x75\xd8" + _wire(result.ref) + b"\x75" + _p2pkh(sb.friend.pkh)
        sb.broadcast(_tx(sb, [(nft, k), (fee, k)], [(twice, nft.value), _change(sb, fee)]))

    def test_a_singleton_downgraded_to_normal_pushes_is_reported(self, sb):
        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        normal = b"\xd0" + _wire(result.ref) + b"\x75" + _p2pkh(sb.wallet.pkh)
        txid = sb.broadcast(
            _tx(sb, [(nft, k), (fee, k)], [(normal, nft.value), (normal, nft.value), _change(sb, fee, nft.value)])
        )
        refs = [c for c in sb.chain.accepted[txid].checks if c.rule == "refs"]
        assert [c.status for c in refs] == ["warn"] and "no output keeps it as a singleton" in refs[0].detail


class TestMalformed:
    @pytest.mark.parametrize("script", [b"\x05ab", b"\x4c", b"\xd0" + b"\x00" * 10])
    def test_an_output_script_that_does_not_decode_is_refused_not_crashed(self, pg, sb, script):
        coin = sb.faucet(rxd=1)
        placeholder = b"\x61" * len(script)  # OP_NOPs: the same length, so the bytes can be swapped in
        raw = _tx(sb, [(coin, sb.wallet.key)], [(placeholder, 1_000), _change(sb, coin, 1_000)]).serialize()
        slot = (1_000).to_bytes(8, "little") + bytes([len(script)])  # value, then the script's length
        assert raw.count(slot + placeholder) == 1
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.chain.submit(raw.replace(slot + placeholder, slot + script))
        assert exc.value.rule == "parse" and "does not decode" in str(exc.value)
        sb.chain.submit(raw)


class TestFtOutputs:
    def test_units_minted_by_a_contract_input_are_a_warning_not_a_refusal(self, pg, sb):
        """A dMint mint: a contract the sandbox cannot run holds the ref and mints. Not refused, not passed."""
        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.glyph.types import GlyphRef

        coin = sb.faucet(rxd=2)
        k = sb.wallet.key
        ref = GlyphRef(txid=coin.txid, vout=coin.vout)
        contract = b"\xd0" + ref.to_bytes() + b"\x75\x51"  # pushes the ref, then OP_1: anyone can spend
        txid = sb.broadcast(_tx(sb, [(coin, k)], [(contract, 10_000), _change(sb, coin, 10_000)]))
        held = sb.chain.utxos[(txid, 0)]
        fee = sb.faucet(rxd=1)
        from pyrxd.script.script import Script

        tx = _tx(
            sb,
            [(held, k), (fee, k)],
            [(contract, 10_000), (build_ft_locking_script(sb.wallet.pkh, ref), 1_000), _change(sb, fee, 1_000)],
            sign=False,
        )
        tx.inputs[0].unlocking_script_template = None
        tx.inputs[0].unlocking_script = Script(b"")
        tx.sign()
        mint = sb.broadcast(tx)
        ft = [c for c in sb.chain.accepted[mint].checks if c.rule == "ft"]
        assert [c.status for c in ft] == ["warn"] and "did NOT evaluate" in ft[0].detail

    def test_an_extra_non_ft_output_pushing_the_ft_ref_is_refused(self, pg, sb):
        """Review F2. The FT covenant counts outputs pushing the ref (read from its bytes, not run on a node)."""
        res, ft = _deploy_ft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        honest = [(ft.script, ft.value), _change(sb, fee)]
        sb_extra = b"\xd0" + _wire(res.ref) + b"\x75" + _p2pkh(sb.wallet.pkh)
        bad = _tx(sb, [(ft, k), (fee, k)], [*honest[:1], (sb_extra, 1_000), _change(sb, fee, 1_000)])
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(bad)
        assert exc.value.rule == "ft" and "not an FT output" in str(exc.value)
        sb.broadcast(_tx(sb, [(ft, k), (fee, k)], honest))

    def test_an_nft_ref_does_not_become_an_ft(self, pg, sb):
        """Review F12. What a node does with this is not measured; the sandbox refuses it."""
        from pyrxd.glyph.script import build_ft_locking_script

        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        tx = _tx(
            sb,
            [(nft, k), (fee, k)],
            [(build_ft_locking_script(sb.wallet.pkh, result.ref), 50_000_000), _change(sb, fee, 50_000_000)],
        )
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "ft" and "neither an FT" in str(exc.value)

    def test_a_deploy_says_it_minted_rather_than_passing_in_zero(self, pg, sb):
        """Review F6: the check line said 'in 0, out 10,000' beside a rule that forbids exactly that."""
        res, _ = _deploy_ft(sb)
        lines = [c.detail for c in sb.chain.accepted[res.reveal_txid].checks if c.rule == "ft"]
        assert lines == [lines[0]] and "deployed, 10,000 units minted" in lines[0]
        assert "deploy" in dict(pg.RULES)["ft"]


class TestScripts:
    def _delegate_reveal(self, sb, *, gly=b"gly", delegate=True):
        """Commit to a payload (behind a delegate prefix), then reveal it into the new NFT."""
        from pyrxd.glyph.script import build_commit_locking_script, build_nft_locking_script
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.hash import hash256
        from pyrxd.script.script import Script, encode_pushdata

        coin = sb.faucet(rxd=2)
        k = sb.wallet.key
        payload = b"\xa1\x01\x02"
        dref = GlyphRef(txid=coin.txid, vout=coin.vout) if delegate else None
        commit = build_commit_locking_script(hash256(payload), sb.wallet.pkh, is_nft=True, delegate_ref=dref)
        txid = sb.broadcast(_tx(sb, [(coin, k)], [(commit, 50_000_000), _change(sb, coin, 50_000_000)]))
        held = sb.chain.utxos[(txid, 0)]
        new_ref = GlyphRef(txid=txid, vout=0)
        tx = _tx(sb, [(held, k)], [(build_nft_locking_script(sb.wallet.pkh, new_ref), held.value - FEE)], sign=False)
        sig = k.sign(tx.preimage(0)) + b"\x41"
        pub = k.public_key().serialize()
        tx.inputs[0].unlocking_script = Script(b"".join(encode_pushdata(x) for x in (sig, pub, gly, payload)))
        return tx

    def test_a_delegate_commit_is_checked_and_warns_about_its_burn(self, pg, sb):
        """Review F3: never 'pass', since the burn is unchecked; but what can be checked still is."""
        txid = sb.broadcast(self._delegate_reveal(sb))
        scripts = [c for c in sb.chain.accepted[txid].checks if c.rule == "scripts"]
        assert [c.status for c in scripts] == ["warn"]
        assert "delegate burn" in scripts[0].detail and "NOT evaluated" in scripts[0].detail
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(self._delegate_reveal(sb, gly=b"glx"))
        assert "'gly'" in str(exc.value)
        plain = sb.broadcast(self._delegate_reveal(sb, delegate=False))
        assert [c.status for c in sb.chain.accepted[plain].checks if c.rule == "scripts"] == ["pass"]

    def _spend_with_pub(self, sb, pub: bytes):
        """Fund hash160(pub), then spend it with a signature from the wallet key and ``pub`` pushed."""
        from pyrxd.hash import hash160
        from pyrxd.script.script import Script, encode_pushdata

        coin = sb.faucet(rxd=1)
        k = sb.wallet.key
        txid = sb.broadcast(_tx(sb, [(coin, k)], [(_p2pkh(hash160(pub)), coin.value - FEE)]))
        held = sb.chain.utxos[(txid, 0)]
        tx = _tx(sb, [(held, k)], [(_p2pkh(sb.wallet.pkh), held.value - FEE)], sign=False)
        sig = k.sign(tx.preimage(0)) + b"\x41"
        tx.inputs[0].unlocking_script = Script(encode_pushdata(sig) + encode_pushdata(pub))
        return tx

    def test_a_hybrid_public_key_is_refused(self, pg, sb):
        """Review F4. A node's STRICTENC refuses 06/07 keys (by reading the node's rules; not run here)."""
        pub = sb.wallet.key.public_key()
        point = pub.serialize(compressed=False)
        compressed = pub.serialize()
        hybrid = bytes([6 + (point[-1] & 1)]) + point[1:]
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(self._spend_with_pub(sb, hybrid))
        assert exc.value.rule == "scripts" and "compressed or uncompressed" in str(exc.value)
        sb.broadcast(self._spend_with_pub(sb, compressed))
        sb.broadcast(self._spend_with_pub(sb, point))

    def test_only_sighash_all_forkid_is_accepted(self, pg, sb):
        from pyrxd.script.script import Script, encode_pushdata

        coin = sb.faucet(rxd=1)
        k = sb.wallet.key
        tx = _tx(sb, [(coin, k)], [(_p2pkh(sb.friend.pkh), coin.value - FEE)], sign=False)
        sig = k.sign(tx.preimage(0))
        pub = k.public_key().serialize()
        tx.inputs[0].unlocking_script = Script(encode_pushdata(sig + b"\x01") + encode_pushdata(pub))
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "scripts" and "0x41" in str(exc.value)
        tx.inputs[0].unlocking_script = Script(encode_pushdata(sig + b"\x41") + encode_pushdata(pub))
        sb.broadcast(tx)

    def test_an_nft_input_must_be_signed_by_its_owner_and_hints_at_tokens(self, pg, sb):
        """Review F8: a token input that does not verify says it holds a token, not 'sign last'."""
        result, nft = _mint_nft(sb)
        fee = sb.faucet(rxd=1)
        k = sb.wallet.key
        from pyrxd.glyph.script import build_nft_locking_script

        outs = [(build_nft_locking_script(sb.friend.pkh, result.ref), nft.value), _change(sb, fee)]
        tx = _tx(sb, [(nft, k), (fee, k)], outs)
        tx.outputs[1].satoshis -= 1
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert "does not verify" in str(exc.value) and "holds a token" in exc.value.hint
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(_tx(sb, [(nft, sb.friend.key), (fee, k)], outs))
        assert "does not own" in str(exc.value)
        sb.broadcast(_tx(sb, [(nft, k), (fee, k)], outs))

    def test_an_ft_input_must_be_signed_by_its_owner(self, pg, sb):
        _, ft = _deploy_ft(sb)
        fee = sb.faucet(rxd=1)
        outs = [(ft.script, ft.value), _change(sb, fee)]
        tx = _tx(sb, [(ft, sb.wallet.key), (fee, sb.wallet.key)], outs)
        tx.outputs[1].satoshis -= 1
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert "Glyph FT" in str(exc.value) and "does not verify" in str(exc.value)
        sb.broadcast(_tx(sb, [(ft, sb.wallet.key), (fee, sb.wallet.key)], outs))


class TestReveals:
    def _build(self, sb, pending, key, outputs=None):
        from pyrxd.script.type import P2PKH

        minter = sb.minter()
        tx = minter._build_reveal_tx(pending, key, P2PKH().lock(sb.wallet.address))
        tx.outputs = outputs(tx) if outputs else tx.outputs[:1]
        tx.sign()
        return tx

    def _pending(self, sb):
        from pyrxd.glyph import GlyphMetadata, GlyphProtocol

        sb.faucet(rxd=10)
        return run(sb.minter().commit_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="r")))

    def test_a_reveal_signed_by_another_key_is_refused(self, pg, sb):
        pending = self._pending(sb)
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(self._build(sb, pending, sb.friend.key))
        assert exc.value.rule == "scripts" and "Glyph commit" in str(exc.value)
        sb.broadcast(self._build(sb, pending, sb.wallet.key))

    def test_a_reveal_without_the_gly_marker_is_refused(self, pg, sb):
        from pyrxd.script.script import Script

        pending = self._pending(sb)
        tx = self._build(sb, pending, sb.wallet.key)
        unlock = tx.inputs[0].unlocking_script.serialize()
        assert unlock.count(b"\x03gly") == 1
        tx.inputs[0].unlocking_script = Script(unlock.replace(b"\x03gly", b"\x03glx"))
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert "'gly'" in str(exc.value)
        tx.inputs[0].unlocking_script = Script(unlock)
        sb.broadcast(tx)

    def test_a_reveal_must_create_the_new_tokens_output(self, pg, sb):
        from pyrxd.script.script import Script
        from pyrxd.transaction.transaction_output import TransactionOutput

        pending = self._pending(sb)

        def no_token(tx):
            return [TransactionOutput(Script(_p2pkh(sb.wallet.pkh)), tx.outputs[0].satoshis)]

        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(self._build(sb, pending, sb.wallet.key, no_token))
        assert exc.value.rule == "scripts" and "demands an output" in str(exc.value)
        sb.broadcast(self._build(sb, pending, sb.wallet.key))


class TestShape:
    def test_a_transaction_with_no_outputs_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=1)
        tx = _tx(sb, [(coin, sb.wallet.key)], [])
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "parse" and "one output" in str(exc.value)

    def test_one_coin_spent_twice_in_one_transaction_is_refused(self, pg, sb):
        coin = sb.faucet(rxd=1)
        k = sb.wallet.key
        tx = _tx(sb, [(coin, k), (coin, k)], [(_p2pkh(sb.friend.pkh), coin.value - FEE)])
        with pytest.raises(pg.SandboxRejected) as exc:
            sb.broadcast(tx)
        assert exc.value.rule == "inputs" and "a second time" in str(exc.value)
        sb.broadcast(_tx(sb, [(coin, k)], [(_p2pkh(sb.friend.pkh), coin.value - FEE)]))


class TestRunReportsWarnings:
    def test_a_run_that_only_warns_says_so(self, pg, sb):
        """Review F7: a burned token used to print a bare 'finished'."""
        src = (
            "from playground import sandbox\n"
            "from pyrxd.glyph import GlyphMetadata, GlyphProtocol\n"
            "from pyrxd.glyph.script import is_nft_script\n"
            "from pyrxd.script.type import P2PKH\n"
            "from pyrxd.transaction.transaction import Transaction\n"
            "from pyrxd.transaction.transaction_input import TransactionInput\n"
            "from pyrxd.transaction.transaction_output import TransactionOutput\n"
            "sandbox.faucet(rxd=10)\n"
            "r = await sandbox.minter().mint_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name='b'))\n"
            "nft = next(c for c in sandbox.coins() if c.txid == r.reveal_txid and is_nft_script(c.script.hex()))\n"
            "fee = sandbox.faucet(rxd=1)\n"
            "k = sandbox.wallet.key\n"
            "tx = Transaction(tx_inputs=[TransactionInput(source_transaction=c.tx, source_output_index=c.vout,\n"
            "    unlocking_script_template=P2PKH().unlock(k)) for c in (nft, fee)],\n"
            "    tx_outputs=[TransactionOutput(P2PKH().lock(sandbox.wallet.address), nft.value + fee.value - 6_000_000)])\n"
            "tx.sign()\n"
            "sandbox.broadcast(tx)\n"
        )
        r = run(pg.run_program(src))
        assert r["error"] is None, r["error"]
        assert [w["rule"] for w in r["warnings"]] == ["refs"] and "burned" in r["warnings"][0]["detail"]
        clean = run(pg.run_program("from playground import sandbox\nsandbox.faucet(rxd=1)\n"))
        assert clean["error"] is None and clean["warnings"] == []
