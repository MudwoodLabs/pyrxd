"""``pyrxd mark`` and the plan type that is the only way to reach it.

Two things are under test here and they are not the same thing.

**The type.** :func:`pyrxd.hashmark_tx.build_hashmark_mark` takes a
:class:`~pyrxd.hashmark_tx.MarkPlan`, never a ``script: bytes``, copying the discipline
``build_timelock_reveal`` states outright: a bytes parameter would let a caller skip the
checks and still get signed bytes back. For a HashMark the two things skippable that way
are label canonicalisation (§5.4 — and in v2 the label is INSIDE the signed statement, so
a trimmed label is a different statement) and the signature verifying at all. The tests
in :class:`TestThePlanCannotHoldAnUnverifiedRecord` go at that from the outside: they
construct :class:`MarkPlan` directly with bytes that should not be publishable, which is
exactly what a caller routing around the encoder would do.

**The command.** §5.4 also obliges an encoder to SHOW the user the canonical label,
"because that is what will be published", and a library function cannot show anyone
anything — which is why ``encode_hashmark`` refuses a non-canonical label rather than
fixing it. The CLI is the half that can, so
:class:`TestTheCommandShowsWhatWillBeSigned` asserts on the rendered output, not on the
payload: a test that checks the dict proves the dict.

Every case that says "the node/the builder refused" is paired with an honest case that
passes, because a guard refusing valid work is its own defect — and a mark is not free
to retry: the fee is spent and the label is public.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.hashmark_tx import (
    MARK_MODELLED_BYTES,
    MarkPlan,
    build_hashmark_mark,
    digest_file,
    hashmark_mark_funding_bar,
    plan_hashmark,
    plan_hashmark_for_file,
)
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.hashmark import (
    RADIANT_MAINNET_GENESIS,
    AttestationOutcome,
    decode_hashmark,
    encode_hashmark,
    verify_attestation,
)
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FEE_RATE = 10_000  # Radiant's relay floor, not a token test rate
REGTEST_GENESIS = GENESIS_BLOCK_HASHES["regtest"]


@pytest.fixture
def runner() -> CliRunner:
    """Local, because ``tests/cli/conftest.py``'s fixtures do not reach this directory."""
    return CliRunner()


def _source_tx(vout: int, spk: bytes, value: int) -> bytes:
    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


class _MarkHarness:
    """A wallet with one plain-RXD UTXO (and optionally a token-bearing one), and a node.

    Fresh keys per construction. Signing is RFC 6979, so whether a given transaction
    underpays is a fixed property of that transaction; a fixed-key fixture signs one
    message forever and proves nothing about the next.

    The wallet stub carries the three methods ``mark`` actually uses —
    ``collect_spendable`` for funding, ``derive_address``/``privkey_for`` for the default
    signing identity, ``privkey_for_address`` for ``--signer-address``. It is not an
    ``HdWallet``: the point of the command's contract being three methods wide is that a
    stub like this is possible, and :class:`TestTheSignerIsAStableIdentity` is what checks
    the default path is the one a real wallet would take.
    """

    def __init__(self, *, fund_value: int = 50_000_000, with_token_utxo: bool = False) -> None:
        self.signer_key = PrivateKey()
        self.signer_address = self.signer_key.address()
        self.other_key = PrivateKey()
        self.fund_key = PrivateKey()
        self.fund_spk = P2PKH().lock(self.fund_key.address()).serialize()
        self.fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=fund_value, height=100)
        txmap = {"cc" * 32: _source_tx(1, self.fund_spk, fund_value)}
        triples = [(self.fund_utxo, self.fund_key.address(), self.fund_key)]

        if with_token_utxo:
            # A fatter UTXO than the plain one, and NOT a bare P2PKH: `find_plain_rxd_utxo`
            # sorts by value descending, so this is the first candidate it sees. Funding a
            # mark from it would burn whatever it carries to publish a hash about a file.
            from pyrxd.glyph.script import build_nft_locking_script
            from pyrxd.glyph.types import GlyphRef

            self.token_spk = build_nft_locking_script(
                self.other_key.public_key().hash160(), GlyphRef(txid="ab" * 32, vout=0)
            )
            self.token_utxo = UtxoRecord(tx_hash="dd" * 32, tx_pos=0, value=fund_value * 10, height=100)
            txmap["dd" * 32] = _source_tx(0, bytes(self.token_spk), self.token_utxo.value)
            triples.insert(0, (self.token_utxo, self.other_key.address(), self.other_key))

        signer_key, signer_address, other_key = self.signer_key, self.signer_address, self.other_key

        class _Wallet:
            async def collect_spendable(self, client):
                return triples

            # A different key at every path but 0/0, rather than an assertion that 0/0 was
            # asked for. An assertion here would catch a moved default through the STUB,
            # which proves the stub; returning a distinct key lets the test catch it
            # through the signer committed in the published record, which is the fact
            # that matters.
            def derive_address(self, change: int, index: int) -> str:
                return signer_address if (change, index) == (0, 0) else other_key.address()

            def privkey_for(self, change: int, index: int) -> PrivateKey:
                return signer_key if (change, index) == (0, 0) else other_key

            def privkey_for_address(self, address: str) -> PrivateKey:
                if address == signer_address:
                    return signer_key
                if address == other_key.address():
                    return other_key
                raise ValidationError(f"address {address} is not known to this wallet")

        self.broadcast_calls: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            self.broadcast_calls.append(raw)
            return Transaction.from_hex(raw.hex()).txid()

        self.client = MagicMock()
        self.client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        self.client.broadcast = _bcast
        self.client.__aenter__ = AsyncMock(return_value=self.client)
        self.client.__aexit__ = AsyncMock(return_value=None)
        self.wallet = _Wallet()


def _invoke(runner, tmp_path, monkeypatch, *, harness, content=b"the advisory text", top=(), extra=()):
    """Drive the real ``pyrxd mark`` with the wallet and node stubbed at the CLI boundary."""
    import pyrxd.cli.hashmark_cmds as hc
    from pyrxd.cli.main import cli

    target = tmp_path / "advisory.txt"
    target.write_bytes(content)
    monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: harness.wallet)
    monkeypatch.setattr(CliContext, "make_client", lambda self: harness.client)
    result = runner.invoke(cli, ["--wallet", str(tmp_path / "w.dat"), *top, "mark", str(target), *extra])
    return result, target


def _published_script(harness: _MarkHarness) -> bytes:
    """The OP_RETURN from the one transaction the harness was asked to broadcast."""
    assert len(harness.broadcast_calls) == 1, harness.broadcast_calls
    sent = Transaction.from_hex(harness.broadcast_calls[0].hex())
    assert sent.outputs[0].satoshis == 0, "the record output must carry no value"
    return bytes(sent.outputs[0].locking_script.serialize())


# ---------------------------------------------------------------------------


class TestThePlanCannotHoldAnUnverifiedRecord:
    """The type is the gate, so the tests attack the type rather than the happy path.

    Each case builds a ``MarkPlan`` the way a caller routing around ``plan_hashmark``
    would — straight from bytes — and requires the construction itself to fail. If any of
    these succeeded, ``build_hashmark_mark``'s ``plan``-not-``bytes`` signature would be a
    naming convention rather than a guarantee.
    """

    def test_the_honest_plan_is_accepted_and_carries_what_it_published(self) -> None:
        """Paired with every refusal below: a gate that refuses honest work is a defect."""
        key = PrivateKey()
        digest = hashlib.sha256(b"honest").digest()
        plan = plan_hashmark(digest, key, label="advisory")
        assert plan.digest_hex == digest.hex()
        assert plan.label == "advisory"
        assert plan.algorithm == "sha256"
        assert plan.signer_hash160_hex == key.public_key().hash160(key.compressed).hex()
        assert plan.attestation.outcome is AttestationOutcome.VALID
        assert plan.record.version == 2
        assert plan.size_bytes == len(plan.op_return_script) <= 223

    def test_bytes_that_are_not_a_hashmark_cannot_become_a_plan(self) -> None:
        with pytest.raises(ValidationError, match="not a publishable HashMark record"):
            MarkPlan(op_return_script=b"\x6a\x04spam")

    def test_an_empty_script_cannot_become_a_plan(self) -> None:
        with pytest.raises(ValidationError, match="not a publishable HashMark record"):
            MarkPlan(op_return_script=b"")

    def test_a_v1_record_cannot_become_a_plan(self) -> None:
        """v1 says WHEN and never WHO. Reading it stays supported; funding one does not,
        because this module's whole job is to publish a statement somebody made."""
        from pyrxd.utils import encode_data_push

        digest = hashlib.sha256(b"unsigned").digest()
        v1 = b"\x6a" + b"".join(encode_data_push(p) for p in (b"HASHMARK", bytes([1, 1]), digest, b"a v1 caption"))
        assert decode_hashmark(v1).ok, "the fixture must be a VALID v1 record, or this proves nothing"
        with pytest.raises(ValidationError, match="v2 records only"):
            MarkPlan(op_return_script=v1)

    def test_a_tampered_signature_cannot_become_a_plan(self) -> None:
        key = PrivateKey()
        script = encode_hashmark(hashlib.sha256(b"x").digest(), key)
        # Flip a bit inside the signature's r, which is the last 65-byte push.
        tampered = bytearray(script)
        tampered[-40] ^= 0x01
        assert decode_hashmark(bytes(tampered)).ok, "still WELL-FORMED — only the claim is broken"
        with pytest.raises(ValidationError, match="signature does not verify"):
            MarkPlan(op_return_script=bytes(tampered))

    def test_a_record_signed_for_another_chain_cannot_be_planned_for_this_one(self) -> None:
        """The genesis is part of the signed statement and is NOT carried by the record.

        So the same bytes are publishable on one chain and a false statement on another,
        and nothing in the bytes says which. This is the case a ``script: bytes``
        parameter could not have caught at all.
        """
        key = PrivateKey()
        mainnet_bytes = encode_hashmark(hashlib.sha256(b"x").digest(), key, network_genesis=RADIANT_MAINNET_GENESIS)
        assert decode_hashmark(mainnet_bytes).ok
        with pytest.raises(ValidationError, match="signature does not verify"):
            MarkPlan(op_return_script=mainnet_bytes, network_genesis=REGTEST_GENESIS)
        # And the honest pairing: the same bytes ARE a plan for the chain they were signed for.
        assert MarkPlan(op_return_script=mainnet_bytes).attestation.valid

    def test_a_non_canonical_label_cannot_reach_a_plan_even_hand_assembled(self) -> None:
        """The label gate ends up STRUCTURAL rather than conventional, and this is why.

        ``canonicalize_label`` transforms and ``encode_hashmark`` refuses — but both are
        the encoder, and the door this test checks is the one that skips the encoder. A
        non-canonical label makes a v2 record INVALID *to the decoder*, because the label
        is inside the signed statement, so a hand-assembled record carrying one is not a
        record at all. There is no spelling of these bytes that reaches ``MarkPlan``.
        """
        from base64 import b64decode
        from dataclasses import replace

        from pyrxd.script.hashmark import canonical_statement
        from pyrxd.utils import encode_data_push, stringify_ecdsa_recoverable, text_digest

        key = PrivateKey()
        digest = hashlib.sha256(b"x").digest()
        signer = key.public_key().hash160(key.compressed)
        untrimmed = "  advisory  "
        record = decode_hashmark(encode_hashmark(digest, key, label="advisory"))
        # Sign the UNTRIMMED spelling honestly, so the only defect is canonicality.
        statement = canonical_statement(replace(record, label=untrimmed))
        sig = b64decode(stringify_ecdsa_recoverable(key.sign_recoverable(text_digest(statement)), key.compressed))
        hand = b"\x6a" + b"".join(
            encode_data_push(p) for p in (b"HASHMARK", bytes([2, 1]), digest, signer, sig, untrimmed.encode("utf-8"))
        )
        assert not decode_hashmark(hand).ok, "the decoder must refuse a non-canonical v2 label"
        with pytest.raises(ValidationError, match="not a publishable HashMark record"):
            MarkPlan(op_return_script=hand)

    def test_an_UNVERIFIABLE_attestation_cannot_become_a_plan(self) -> None:
        """UNVERIFIABLE means "no curve here checked it", and a mark nobody could self-check
        must not be funded. Every other case in this class fails with INVALID_SIGNATURE, so a
        refusal narrowed to ``outcome == 'invalid_signature'`` passed them all and survived the
        full suite as a plant. A backend that cannot run is what produces UNVERIFIABLE; it is
        registered only around the construction, and the same bytes are then a plan again."""
        from pyrxd.script.hashmark import RecoveryUnavailable, set_recovery_backend

        script = encode_hashmark(hashlib.sha256(b"honest").digest(), PrivateKey())

        def _cannot_run(*_args: object) -> bytes:
            raise RecoveryUnavailable("no curve library on this machine")

        set_recovery_backend(_cannot_run)
        try:
            assert verify_attestation(decode_hashmark(script)).outcome is AttestationOutcome.UNVERIFIABLE, (
                "non-vacuity: the registered backend must be what answers, or this tests coincurve"
            )
            with pytest.raises(ValidationError, match="unverifiable"):
                MarkPlan(op_return_script=script)
        finally:
            set_recovery_backend(None)
        assert MarkPlan(op_return_script=script).attestation.valid, "the honest pair: with a curve, it plans"

    def test_the_derived_fields_cannot_be_supplied(self) -> None:
        """``record`` and ``attestation`` are ``init=False``, so they are always the bytes'
        own answer rather than whatever a caller asserted about them."""
        with pytest.raises(TypeError):
            MarkPlan(  # type: ignore[call-arg]
                op_return_script=encode_hashmark(hashlib.sha256(b"x").digest(), PrivateKey()),
                record="anything",
            )


def _hand_signed_for(genesis: str, key: PrivateKey | None = None) -> bytes:
    """A well-formed v2 record signed for *genesis* WITHOUT the encoder.

    The encoder now refuses a genesis nobody can verify against, so the only way to hold such
    bytes is to sign them by hand — which is exactly the door ``MarkPlan`` has to close on its own.
    """
    from base64 import b64decode

    from pyrxd.script.hashmark import HashMarkOutcome, HashMarkRecord, canonical_statement
    from pyrxd.utils import encode_data_push, stringify_ecdsa_recoverable, text_digest

    key = key or PrivateKey()
    digest = hashlib.sha256(b"a statement about some chain").digest()
    signer = key.public_key().hash160(key.compressed)
    draft = HashMarkRecord(
        HashMarkOutcome.OK, version=2, algorithm_id=1, digest_hex=digest.hex(), signer_hash160_hex=signer.hex()
    )
    statement = canonical_statement(draft, network_genesis=genesis)
    sig = b64decode(stringify_ecdsa_recoverable(key.sign_recoverable(text_digest(statement)), key.compressed))
    return b"\x6a" + b"".join(encode_data_push(p) for p in (b"HASHMARK", bytes([2, 1]), digest, signer, sig))


_MAINNET_REVERSED = bytes.fromhex(RADIANT_MAINNET_GENESIS)[::-1].hex()


class TestThePlanIsForAChainSomeoneCanCheck:
    """The genesis is in the signed statement and NOT in the record, and the plan's own check
    verifies against the SAME string it was signed with — so it is circular for exactly this
    field. Bytes signed for ``"mainnet"`` verify against ``"mainnet"``, planned, funded, and would
    have published a record that verifies on no chain at all. §5.6: "A network whose genesis hash
    is unknown cannot be attested to at all."
    """

    @pytest.mark.parametrize(
        "genesis",
        ["mainnet", "", RADIANT_MAINNET_GENESIS.upper(), _MAINNET_REVERSED, "00" * 32],
        ids=["a-network-name", "empty", "uppercase", "reversed-byte-order", "well-formed-but-unknown"],
    )
    def test_bytes_that_self_verify_for_a_non_genesis_cannot_become_a_plan(self, genesis: str) -> None:
        script = _hand_signed_for(genesis)
        assert verify_attestation(decode_hashmark(script), network_genesis=genesis).valid, (
            "non-vacuity: these bytes DO self-verify against the string they were signed for — "
            "that circularity is the defect"
        )
        with pytest.raises(ValidationError, match="network_genesis"):
            MarkPlan(op_return_script=script, network_genesis=genesis)

    @pytest.mark.parametrize("genesis", ["mainnet", RADIANT_MAINNET_GENESIS.upper(), _MAINNET_REVERSED])
    def test_plan_hashmark_refuses_before_signing(self, genesis: str) -> None:
        with pytest.raises(ValidationError, match="network_genesis"):
            plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey(), network_genesis=genesis)

    def test_reversed_byte_order_is_named_for_what_it_is(self) -> None:
        with pytest.raises(ValidationError, match="reversed"):
            plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey(), network_genesis=_MAINNET_REVERSED)

    @pytest.mark.parametrize("network", sorted(GENESIS_BLOCK_HASHES))
    def test_the_honest_pair_every_chain_pyrxd_knows_plans(self, network: str) -> None:
        genesis = GENESIS_BLOCK_HASHES[network]
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey(), network_genesis=genesis)
        assert plan.network_genesis == genesis and plan.attestation.valid
        assert MarkPlan(op_return_script=plan.op_return_script, network_genesis=genesis).attestation.valid

    def test_another_chain_plans_only_when_the_caller_says_so_and_never_with_a_bad_spelling(self) -> None:
        other = "00" * 31 + "01"
        digest, key = hashlib.sha256(b"x").digest(), PrivateKey()
        with pytest.raises(ValidationError, match="allow_unknown_genesis"):
            plan_hashmark(digest, key, network_genesis=other)
        plan = plan_hashmark(digest, key, network_genesis=other, allow_unknown_genesis=True)
        assert plan.attestation.valid and plan.network_genesis == other
        with pytest.raises(ValidationError, match="allow_unknown_genesis"):
            MarkPlan(op_return_script=plan.op_return_script, network_genesis=other)
        with pytest.raises(ValidationError, match="64 lowercase hex"):
            plan_hashmark(digest, key, network_genesis="mainnet", allow_unknown_genesis=True)


class TestTheBuilderComparesThePlansChainWithTheClients:
    """A plan says which chain its statement is about; a client says which chain it is on.
    Nothing compared the two, so a mainnet plan built and would broadcast through a testnet
    client — a record that verifies on neither chain it could be read on."""

    @staticmethod
    def _client_on(h: _MarkHarness, network: str) -> None:
        from pyrxd.network.registry import NetworkProfile

        h.client.profile = NetworkProfile.build(network, ["wss://electrumx.invalid:50022"])

    def test_a_mainnet_plan_through_a_testnet_client_is_refused_before_anything_is_funded(self) -> None:
        h = _MarkHarness()
        self._client_on(h, "testnet")
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key)  # mainnet, the default
        with pytest.raises(ValidationError, match="but the client is on the chain"):
            asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        assert h.client.get_transaction.await_count == 0, "no funding UTXO was even looked at"
        assert h.broadcast_calls == []

    @pytest.mark.parametrize("network", sorted(GENESIS_BLOCK_HASHES))
    def test_the_honest_pair_a_plan_through_a_client_on_its_own_chain_builds(self, network: str) -> None:
        h = _MarkHarness()
        self._client_on(h, network)
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key, network_genesis=GENESIS_BLOCK_HASHES[network])
        build = asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        assert bytes(build.tx.outputs[0].locking_script.serialize()) == plan.op_return_script

    def test_a_client_that_names_no_chain_is_not_refused_for_it(self) -> None:
        """A plain ``ElectrumXClient`` carries no profile. Refusing it would refuse every honest
        caller using one; the comparison is made only when there is something to compare."""
        h = _MarkHarness()
        del h.client.profile  # a MagicMock answers every attribute; a plain client has no `profile`
        assert not hasattr(h.client, "profile")
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key)
        build = asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        assert bytes(build.tx.outputs[0].locking_script.serialize()) == plan.op_return_script


class TestTheBuilderTakesAPlanAndNothingElse:
    def test_a_lookalike_object_is_refused(self) -> None:
        """The annotation is a mypy-time claim; this is the runtime one.

        Without the ``isinstance`` check the one door worth closing — a caller assembling
        an object with the right attribute names — is wide open AND type-clean.
        """
        h = _MarkHarness()

        class _NotAPlan:
            op_return_script = b"\x6a\x04spam"
            network_genesis = RADIANT_MAINNET_GENESIS

        with pytest.raises(ValidationError, match="takes a MarkPlan"):
            asyncio.run(
                build_hashmark_mark(h.wallet, _NotAPlan(), client=h.client, fee_rate=FEE_RATE)  # type: ignore[arg-type]
            )
        assert h.broadcast_calls == []

    def test_the_real_plan_is_accepted_and_the_op_return_is_output_zero_at_value_zero(self) -> None:
        h = _MarkHarness()
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key, label="advisory")
        build = asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        assert build.tx.outputs[0].satoshis == 0
        assert bytes(build.tx.outputs[0].locking_script.serialize()) == plan.op_return_script
        assert build.fee >= len(build.serialize()) * FEE_RATE
        assert h.broadcast_calls == [], "building must not broadcast"

    def test_a_sub_floor_fee_rate_is_refused_before_anything_is_signed(self) -> None:
        """Radiant has neither RBF nor CPFP, so a sub-floor mark squats on its funding
        until mempool expiry and cannot be bumped by any means."""
        h = _MarkHarness()
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key)
        with pytest.raises(ValidationError):
            asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=1))


class TestTheFundingIsPlainRxd:
    def test_a_token_bearing_utxo_is_never_spent_to_publish_a_mark(self) -> None:
        """The token UTXO here is TEN TIMES the plain one, so value-descending selection
        reaches it first. Spending it would burn a singleton to publish a hash."""
        h = _MarkHarness(with_token_utxo=True)
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key)
        build = asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        spent = {(i.source_txid, i.source_output_index) for i in build.tx.inputs}
        assert spent == {(h.fund_utxo.tx_hash, h.fund_utxo.tx_pos)}
        assert (h.token_utxo.tx_hash, h.token_utxo.tx_pos) not in spent

    def test_at_the_funding_bar_it_builds_and_one_photon_under_it_refuses(self) -> None:
        """Both halves. A bar that refused funding the chain would have taken is its own
        fund-safety bug, and one that admitted funding the chain refuses is the original."""
        from pyrxd.glyph.transfer import NoFeeFundingError

        probe = plan_hashmark(hashlib.sha256(b"x").digest(), PrivateKey())
        bar = hashmark_mark_funding_bar(probe.op_return_script, FEE_RATE)

        at = _MarkHarness(fund_value=bar)
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), at.signer_key)
        assert len(plan.op_return_script) == len(probe.op_return_script), "same shape, so same bar"
        build = asyncio.run(build_hashmark_mark(at.wallet, plan, client=at.client, fee_rate=FEE_RATE))
        assert build.fee >= len(build.serialize()) * FEE_RATE

        under = _MarkHarness(fund_value=bar - 1)
        with pytest.raises(NoFeeFundingError, match="no plain-RXD UTXO large enough"):
            asyncio.run(
                build_hashmark_mark(
                    under.wallet,
                    plan_hashmark(hashlib.sha256(b"x").digest(), under.signer_key),
                    client=under.client,
                    fee_rate=FEE_RATE,
                )
            )

    def test_the_bar_covers_a_labelled_record_too(self) -> None:
        """A label adds up to 90 bytes to the record, and the bar is sized from the script
        it is given rather than from the unlabelled shape."""
        key = PrivateKey()
        bare = plan_hashmark(hashlib.sha256(b"x").digest(), key)
        full = plan_hashmark(hashlib.sha256(b"x").digest(), key, label="x" * 88)
        assert full.size_bytes == 223
        assert hashmark_mark_funding_bar(full.op_return_script, FEE_RATE) > hashmark_mark_funding_bar(
            bare.op_return_script, FEE_RATE
        )
        assert (
            hashmark_mark_funding_bar(bare.op_return_script, FEE_RATE)
            == (MARK_MODELLED_BYTES + 1 + bare.size_bytes) * FEE_RATE
        )


class TestDigestingAFile:
    def test_the_digest_is_the_files_sha256_and_the_file_is_streamed(self, tmp_path: Path) -> None:
        # Larger than one read chunk, so the streaming loop actually iterates.
        blob = os.urandom(3 * 1024 * 1024 + 7)
        target = tmp_path / "big.bin"
        target.write_bytes(blob)
        assert digest_file(target) == hashlib.sha256(blob).digest()

    def test_the_hasher_is_derived_from_the_algorithm_id_the_record_declares(self) -> None:
        with pytest.raises(ValidationError, match="not implemented"):
            digest_file(__file__, algorithm_id=0x02)

    def test_plan_for_file_records_the_path_and_signs_the_files_digest(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        target.write_bytes(b"contents")
        plan = plan_hashmark_for_file(target, PrivateKey(), label="a")
        assert plan.digest_hex == hashlib.sha256(b"contents").hexdigest()
        assert plan.source == str(target)


class TestTheCommandShowsWhatWillBeSigned:
    """Assertions on the rendered OUTPUT, deliberately.

    Everything below could be true of the payload dict while the only screen anyone looks
    at showed none of it. §5.4's obligation is about what the user SEES.
    """

    def test_the_dry_run_prints_the_record_its_decoded_fields_and_its_size(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _target = _invoke(runner, tmp_path, monkeypatch, harness=h, extra=["--dry-run", "--label", "advisory"])
        assert result.exit_code == 0, result.output
        expected = encode_hashmark(hashlib.sha256(b"the advisory text").digest(), h.signer_key, label="advisory")
        assert "DRY RUN" in result.output
        assert expected.hex() in result.output, "the script hex itself must be shown"
        assert hashlib.sha256(b"the advisory text").hexdigest() in result.output
        assert f"{len(expected)} B of the 223-byte ceiling" in result.output
        assert "v2 sha256 digest=" in result.output
        assert "label='advisory'" in result.output
        assert h.broadcast_calls == [], "a dry run broadcast something"

    def test_the_dry_run_says_what_a_mark_does_not_prove(self, runner, tmp_path, monkeypatch) -> None:
        """The spec makes this normative for any UI built on the format, and a timestamp
        product that lets a reader infer authorship is the failure that makes it dishonest
        rather than limited."""
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=_MarkHarness(), extra=["--dry-run"])
        assert "does NOT" in result.output
        assert "authorship" in result.output
        assert "permanently public" in result.output

    def test_a_canonicalised_label_is_announced_not_silently_applied(self, runner, tmp_path, monkeypatch) -> None:
        """The whole reason ``encode_hashmark`` refuses instead of trimming.

        In v2 the label is inside the signed statement, so the trimmed spelling is what is
        signed — and if the operator is never told, the string they believe they published
        is not the string anyone will ever read back.
        """
        h = _MarkHarness()
        result, _ = _invoke(
            runner, tmp_path, monkeypatch, harness=h, extra=["--dry-run", "--label", "  advisory 2026-09  "]
        )
        assert result.exit_code == 0, result.output
        assert "LABEL CANONICALISED" in result.output
        assert "'  advisory 2026-09  '" in result.output
        assert "'advisory 2026-09'" in result.output
        assert (
            decode_hashmark(
                encode_hashmark(hashlib.sha256(b"the advisory text").digest(), h.signer_key, label="advisory 2026-09")
            ).label
            == "advisory 2026-09"
        )

    def test_an_nfc_only_change_is_announced_too(self, runner, tmp_path, monkeypatch) -> None:
        """The change here is invisible on screen — same glyphs, different codepoints — so
        a banner that only fired on whitespace would miss the case where the operator has
        the least chance of noticing on their own."""
        result, _ = _invoke(
            runner, tmp_path, monkeypatch, harness=_MarkHarness(), extra=["--dry-run", "--label", "café"]
        )
        assert result.exit_code == 0, result.output
        assert "LABEL CANONICALISED" in result.output

    def test_an_unchanged_label_gets_no_banner(self, runner, tmp_path, monkeypatch) -> None:
        """Paired with the two above. A banner on every labelled mark is a banner nobody
        reads by the third one."""
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=_MarkHarness(), extra=["--dry-run", "--label", "ok"])
        assert result.exit_code == 0, result.output
        assert "LABEL CANONICALISED" not in result.output

    def test_a_label_with_a_bidi_override_is_refused_with_the_reason(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, extra=["--dry-run", "--label", "invoice‮gpj.exe"])
        assert result.exit_code == 1
        assert "cannot be published as typed" in result.output
        assert "U+202E" in result.output
        assert h.broadcast_calls == []

    def test_a_label_over_the_cap_names_the_cap(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, extra=["--dry-run", "--label", "x" * 89])
        assert result.exit_code == 1
        assert "88" in result.output
        assert h.broadcast_calls == []

    def test_an_88_byte_label_is_accepted(self, runner, tmp_path, monkeypatch) -> None:
        """The honest half of the pair above — the cap is a real boundary, not a margin."""
        result, _ = _invoke(
            runner, tmp_path, monkeypatch, harness=_MarkHarness(), extra=["--dry-run", "--label", "x" * 88]
        )
        assert result.exit_code == 0, result.output
        assert "223 B of the 223-byte ceiling" in result.output


#: Unicode TAG characters (category Cf) spelling "pay 9999", then WORD JOINER and SOFT HYPHEN.
#: None is in §5.4's reject table, so the encoder signs them; a terminal that does not render
#: format characters shows only "invoice 42".
_HIDDEN = "".join(chr(0xE0000 + ord(c)) for c in "pay 9999") + "⁠­"
_HIDDEN_LABEL = "invoice 42" + _HIDDEN


class TestALabelsNonPrintingCharactersAreShownBeforeTheyAreSigned:
    """What the operator agrees to must be what is signed, character for character.

    The confirmation printed the label raw, and the canonicalisation banner fires only when
    canonicalising CHANGED the label — which it does not for these characters. So the whole string
    was signed while the screen showed ``invoice 42``, and ``pyrxd verify`` later printed it as
    ``invoice 42??????????``.
    """

    @pytest.mark.parametrize(("top", "extra"), [(["--yes"], []), ([], ["--dry-run"])], ids=["confirm", "dry-run"])
    def test_every_hidden_character_is_escaped_named_and_still_signed(
        self, runner, tmp_path, monkeypatch, top, extra
    ) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=top, extra=["--label", _HIDDEN_LABEL, *extra])
        assert result.exit_code == 0, result.output
        leaked = set(_HIDDEN) & set(result.output)
        assert not leaked, f"reached the terminal raw: {sorted(f'U+{ord(c):04X}' for c in leaked)}"
        escaped = "".join(f"<U+{ord(c):04X}>" for c in _HIDDEN)
        assert f"label:       invoice 42{escaped}" in result.output
        assert "THE LABEL HOLDS 10 CHARACTER(S) THAT DO NOT PRINT AS THEMSELVES" in result.output
        for name in ("TAG LATIN SMALL LETTER P", "TAG DIGIT NINE", "WORD JOINER", "SOFT HYPHEN"):
            assert name in result.output, name
        assert "will print this label as: invoice 42??????????" in result.output
        if not extra:
            assert f"label:      invoice 42{escaped}" in result.output, "the post-broadcast summary too"
            assert decode_hashmark(_published_script(h)).label == _HIDDEN_LABEL, "shown, and signed as typed"

    @pytest.mark.parametrize(
        "label",
        [
            "नमस्ते",  # Devanagari: U+094D VIRAMA and U+0947 are combining marks
            "\U0001f468‍\U0001f469‍\U0001f467",  # family emoji, joined by ZWJ
            "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",  # Scotland flag: TAG chars
        ],
        ids=["devanagari", "zwj-emoji", "tag-flag"],
    )
    def test_the_honest_pair_text_5_4_permits_is_disclosed_never_refused(
        self, runner, tmp_path, monkeypatch, label
    ) -> None:
        """§5.4 calls ZWJ and ZWNJ "load-bearing in Devanagari and emoji sequences", and does not
        reject combining marks or TAG characters, which honest labels use. Refusing them at the
        CLI would refuse a label the spec allows; the banner is the answer instead."""
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"], extra=["--label", label])
        assert result.exit_code == 0, result.output
        assert "DO NOT PRINT AS THEMSELVES" in result.output
        assert decode_hashmark(_published_script(h)).label == label

    def test_an_ordinary_label_is_printed_as_typed_with_no_banner(self, runner, tmp_path, monkeypatch) -> None:
        """A banner on every labelled mark is a banner nobody reads by the third one."""
        result, _ = _invoke(
            runner, tmp_path, monkeypatch, harness=_MarkHarness(), extra=["--dry-run", "--label", "facture café ☀"]
        )
        assert result.exit_code == 0, result.output
        assert "label:       facture café ☀" in result.output
        assert "DO NOT PRINT AS THEMSELVES" not in result.output and "<U+" not in result.output


class TestTheFilePathCannotDriveTheTerminal:
    """``verify`` sanitised the path it printed; ``mark`` printed it raw.

    A file named ``report.pdf\\x1b[8m`` — SGR 8, "concealed" — made a VT100-family terminal render
    every line after the path invisible: the fee, the label and the irreversibility warning. The
    operator marks files other people named, so the name is not the operator's text.
    """

    _NAME = "report.pdf\x1b[8m"

    @staticmethod
    def _mark(runner, tmp_path, monkeypatch, h, name: str, top=(), extra=()):
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.main import cli

        target = tmp_path / name
        target.write_bytes(b"x")
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        # color=True, or click strips ANSI sequences from the captured output and this passes
        # whether or not the command sanitised anything.
        args = ["--wallet", str(tmp_path / "w.dat"), *top, "mark", str(target), "--label", "ok", *extra]
        return runner.invoke(cli, args, color=True), target

    def test_the_runner_really_does_keep_escape_bytes(self, runner) -> None:
        """Non-vacuity for the class: an ESC this runner dropped would make every test here green."""
        import click

        assert "\x1b[8m" in runner.invoke(click.Command("e", callback=lambda: click.echo("\x1b[8m")), color=True).output

    @pytest.mark.parametrize(("top", "extra"), [(["--yes"], []), ([], ["--dry-run"])], ids=["confirm", "dry-run"])
    def test_an_escape_sequence_in_the_filename_never_reaches_the_terminal(
        self, runner, tmp_path, monkeypatch, top, extra
    ) -> None:
        h = _MarkHarness()
        result, _ = self._mark(runner, tmp_path, monkeypatch, h, self._NAME, top, extra)
        assert result.exit_code == 0, result.output
        assert "\x1b" not in result.output
        assert "report.pdf?[8m" in result.output, "shown, sanitised — not dropped"

    def test_nor_through_the_could_not_read_error(self, runner, tmp_path, monkeypatch) -> None:
        """The read fails AFTER click's own checks passed (a file that vanished or went unreadable
        in between, an I/O error). Driven by making the read raise, because a mode-000 file is
        refused by ``click.Path``'s readability check before this handler is ever reached — that
        message is click's, and is not this command's to sanitise."""
        import pyrxd.hashmark_tx as hx

        def _unreadable(path, *_a, **_k):
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(hx, "plan_hashmark_for_file", _unreadable)
        result, _ = self._mark(runner, tmp_path, monkeypatch, _MarkHarness(), self._NAME)
        assert result.exit_code == 1, result.output
        assert "could not read" in result.output and "report.pdf?[8m" in result.output
        assert "\x1b" not in result.output

    def test_the_honest_pair_an_ordinary_path_is_printed_as_it_is(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, target = self._mark(runner, tmp_path, monkeypatch, h, "report.pdf", extra=["--dry-run"])
        assert result.exit_code == 0, result.output
        assert f"file:        {target}" in result.output


class TestTheCommandPublishesWhatItShowed:
    def test_the_bytes_broadcast_carry_the_record_the_prompt_displayed(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"], extra=["--label", "advisory"])
        assert result.exit_code == 0, result.output
        script = _published_script(h)
        expected = encode_hashmark(hashlib.sha256(b"the advisory text").digest(), h.signer_key, label="advisory")
        assert script == expected
        # The reported txid must be THIS transaction's, not whatever the server echoed.
        assert Transaction.from_hex(h.broadcast_calls[0].hex()).txid() in result.output
        assert hashlib.sha256(b"the advisory text").hexdigest() in result.output

    def test_the_published_record_decodes_and_attests_for_a_stranger(self, runner, tmp_path, monkeypatch) -> None:
        """The product-critical property, checked on the bytes that were SENT.

        A record that only verifies against the in-memory object it was built from is
        worth nothing: the reader who matters has the transaction and the chain and
        nothing else.
        """
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"], extra=["--label", "advisory"])
        assert result.exit_code == 0, result.output
        record = decode_hashmark(_published_script(h))
        assert record.ok and record.version == 2
        assert record.digest_hex == hashlib.sha256(b"the advisory text").hexdigest()
        assert record.label == "advisory"
        assert verify_attestation(record).valid

    def test_the_default_signer_is_the_wallets_first_receive_key(self, runner, tmp_path, monkeypatch) -> None:
        """A fixed path, not the funding UTXO's key. The signature IS the identity: if it
        drifted with whichever UTXO paid, two marks by one person would be two strangers."""
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"])
        assert result.exit_code == 0, result.output
        record = decode_hashmark(_published_script(h))
        assert record.signer_hash160_hex == h.signer_key.public_key().hash160(h.signer_key.compressed).hex()
        assert record.signer_hash160_hex != h.fund_key.public_key().hash160().hex()
        assert h.signer_address in result.output

    def test_signer_address_selects_a_different_key(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(
            runner, tmp_path, monkeypatch, harness=h, top=["--yes"], extra=["--signer-address", h.other_key.address()]
        )
        assert result.exit_code == 0, result.output
        record = decode_hashmark(_published_script(h))
        assert record.signer_hash160_hex == h.other_key.public_key().hash160(h.other_key.compressed).hex()

    def test_an_address_this_wallet_never_derived_is_refused(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(
            runner,
            tmp_path,
            monkeypatch,
            harness=h,
            top=["--yes"],
            extra=["--signer-address", PrivateKey().address()],
        )
        assert result.exit_code == 1
        assert "cannot sign with" in result.output
        assert h.broadcast_calls == []

    def test_a_server_that_echoes_the_wrong_txid_does_not_produce_a_success(
        self, runner, tmp_path, monkeypatch
    ) -> None:
        """A mark carries no value, so the thing at risk is the CLAIM.

        `broadcast` returns whatever the server replies and the reply is only
        format-checked, so a server that drops the transaction and echoes a well-formed
        txid would leave the operator believing a file was marked at a height where
        nothing was ever published — which for a timestamping format is the whole
        product. `broadcast_hashmark_mark` compares the echo against hash256 of the bytes
        it signed and raises; without that it would report the server's answer.
        """
        h = _MarkHarness()

        async def _liar(raw: bytes) -> str:
            h.broadcast_calls.append(raw)
            return "ff" * 32

        h.client.broadcast = _liar
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"])
        assert result.exit_code == 1, result.output
        assert "different transaction id" in result.output
        # The forged id appears only inside the complaint about it; what must NOT happen is
        # the success receipt, which is the line a reader would take as "the mark exists".
        assert "Marked:" not in result.output
        assert Transaction.from_hex(h.broadcast_calls[0].hex()).txid() in result.output, (
            "the local txid must be named, because the mark may in fact have relayed"
        )

    def test_declining_the_prompt_broadcasts_nothing(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.main import cli

        target = tmp_path / "advisory.txt"
        target.write_bytes(b"the advisory text")
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        result = runner.invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "mark", str(target)], input="n\n")
        assert result.exit_code == 1
        assert "aborted by user" in result.output
        assert h.broadcast_calls == []


class TestTheNetworkIsPartOfWhatIsSigned:
    def test_a_regtest_mark_is_signed_for_regtest_and_does_not_verify_as_mainnet(
        self, runner, tmp_path, monkeypatch
    ) -> None:
        """``--network`` selects what is SIGNED, not merely where it is sent.

        The genesis hash is inside the statement and absent from the record, so nothing in
        the published bytes says which chain they mean. A mark signed for the wrong one is
        perfectly relayable and permanently false.
        """
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--network", "regtest", "--yes"])
        assert result.exit_code == 0, result.output
        record = decode_hashmark(_published_script(h))
        assert verify_attestation(record, network_genesis=REGTEST_GENESIS).valid
        assert not verify_attestation(record, network_genesis=RADIANT_MAINNET_GENESIS).valid
        assert REGTEST_GENESIS in result.output, "the operator must see which chain they signed for"

    def test_the_mainnet_default_is_signed_for_mainnet(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--yes"])
        assert result.exit_code == 0, result.output
        assert verify_attestation(decode_hashmark(_published_script(h))).valid


class TestTheOtherTwoOutputModesAndTheOverpayFlag:
    """The paths a scripted caller takes, and the one flag that lets a refusal through.

    ``--quiet`` and ``--allow-overpay`` are pass-throughs, which is exactly why they go
    untested: nothing about them looks like new logic. A ``quiet_field`` naming a key the
    payload does not have prints an EMPTY LINE and exits 0 — a scripted caller reads that
    as "no txid" and cannot tell it from a failure, and no assertion about the payload
    dict would notice.
    """

    def test_quiet_mode_prints_the_txid_and_nothing_else(self, runner, tmp_path, monkeypatch) -> None:
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--quiet", "--yes"])
        assert result.exit_code == 0, result.output
        txid = Transaction.from_hex(h.broadcast_calls[0].hex()).txid()
        assert result.stdout.strip() == txid, f"quiet stdout was {result.stdout!r}"

    def test_a_quiet_dry_run_prints_the_digest_instead(self, runner, tmp_path, monkeypatch) -> None:
        """Nothing was broadcast, so there is no txid; printing an empty line would be the
        same output as a broken run."""
        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--quiet"], extra=["--dry-run"])
        assert result.exit_code == 0, result.output
        assert result.stdout.strip() == hashlib.sha256(b"the advisory text").hexdigest()
        assert h.broadcast_calls == []

    def test_the_overpay_bound_is_the_shared_one(self) -> None:
        """What ``--allow-overpay`` forwards to, asserted at the seam rather than through
        the CLI: the CLI has no fee-rate option of its own — the rate comes from the
        config — so driving the bound through ``mark`` would mean writing a config file to
        test somebody else's gate. Named here so the flag is not silently decorative."""
        import inspect

        from pyrxd.hashmark_tx import build_hashmark_mark

        src = inspect.getsource(build_hashmark_mark)
        assert "assert_fee_rate_clears_relay_floor(" in src
        assert "allow_overpay=allow_overpay" in src

    def test_an_overpaying_rate_is_refused_and_the_flag_lets_it_through(self) -> None:
        from pyrxd.fee_sizing import MAX_FEE_OVERPAY_MULTIPLE, relay_floor_photons_per_byte

        over = relay_floor_photons_per_byte() * (MAX_FEE_OVERPAY_MULTIPLE + 1)
        h = _MarkHarness(fund_value=50_000_000 * (MAX_FEE_OVERPAY_MULTIPLE + 1))
        plan = plan_hashmark(hashlib.sha256(b"x").digest(), h.signer_key)
        with pytest.raises(ValidationError):
            asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=over))
        build = asyncio.run(build_hashmark_mark(h.wallet, plan, client=h.client, fee_rate=over, allow_overpay=True))
        assert build.fee >= len(build.serialize()) * over


class TestTheWalletContractHoldsAgainstARealHdWallet:
    """Every case above stubs the wallet, so every case above proves the STUB.

    ``mark`` asks a wallet for four things — ``collect_spendable``,
    ``derive_address``, ``privkey_for`` and ``privkey_for_address`` — and a stub
    answering all four says nothing about whether :class:`~pyrxd.hd.wallet.HdWallet`
    has them, with those names and those signatures. That gap is the one where a
    command ships and fails on first contact with a real wallet: the tests are green
    because they never called the thing under test.

    So this drives the command against a REAL ``HdWallet`` built from a generated
    mnemonic, with only the UTXO source and the node swapped. The funding key is the
    wallet's own change key, so ``collect_spendable``'s triple shape is the real one
    too.
    """

    def test_the_command_signs_and_funds_through_a_real_hd_wallet(self, runner, tmp_path, monkeypatch) -> None:
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.main import cli
        from pyrxd.hd.bip39 import mnemonic_from_entropy
        from pyrxd.hd.wallet import HdWallet

        wallet = HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(32)))
        fund_key = wallet.privkey_for(1, 0)  # a real change key, not a loose PrivateKey
        fund_addr = wallet.derive_address(1, 0)
        fund_spk = P2PKH().lock(fund_addr).serialize()
        fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=50_000_000, height=100)
        txmap = {"cc" * 32: _source_tx(1, fund_spk, fund_utxo.value)}

        async def _collect(_client):
            return [(fund_utxo, fund_addr, fund_key)]

        monkeypatch.setattr(wallet, "collect_spendable", _collect, raising=False)

        sent: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            sent.append(raw)
            return Transaction.from_hex(raw.hex()).txid()

        client = MagicMock()
        client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        client.broadcast = _bcast
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        target = tmp_path / "advisory.txt"
        target.write_bytes(b"real wallet")
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: client)
        result = runner.invoke(
            cli, ["--wallet", str(tmp_path / "w.dat"), "--yes", "mark", str(target), "--label", "real"]
        )
        assert result.exit_code == 0, result.output

        record = decode_hashmark(bytes(Transaction.from_hex(sent[0].hex()).outputs[0].locking_script.serialize()))
        assert record.ok and verify_attestation(record).valid
        # The signer is the wallet's own 0/0 key, derived here the same way the command
        # derives it — and NOT the change key that paid the fee.
        signer = wallet.privkey_for(0, 0)
        assert record.signer_hash160_hex == signer.public_key().hash160(signer.compressed).hex()
        assert record.signer_hash160_hex != fund_key.public_key().hash160(fund_key.compressed).hex()
        assert wallet.derive_address(0, 0) in result.output

    def test_signer_address_resolves_against_a_real_hd_wallet(self, runner, tmp_path, monkeypatch) -> None:
        """``privkey_for_address`` is the fourth method, and the only one the default
        path never touches — so without this it would be unexercised outside the stub."""
        import pyrxd.cli.hashmark_cmds as hc
        from pyrxd.cli.main import cli
        from pyrxd.hd.bip39 import mnemonic_from_entropy
        from pyrxd.hd.wallet import HdWallet

        wallet = HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(32)))
        chosen = wallet.next_receive_address()  # registers it in wallet.addresses
        fund_key = wallet.privkey_for(1, 0)
        fund_addr = wallet.derive_address(1, 0)
        fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=50_000_000, height=100)
        txmap = {"cc" * 32: _source_tx(1, P2PKH().lock(fund_addr).serialize(), fund_utxo.value)}

        async def _collect(_client):
            return [(fund_utxo, fund_addr, fund_key)]

        monkeypatch.setattr(wallet, "collect_spendable", _collect, raising=False)
        sent: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            sent.append(raw)
            return Transaction.from_hex(raw.hex()).txid()

        client = MagicMock()
        client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        client.broadcast = _bcast
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        target = tmp_path / "advisory.txt"
        target.write_bytes(b"real wallet")
        monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: client)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_path / "w.dat"), "--yes", "mark", str(target), "--signer-address", chosen],
        )
        assert result.exit_code == 0, result.output
        record = decode_hashmark(bytes(Transaction.from_hex(sent[0].hex()).outputs[0].locking_script.serialize()))
        key = wallet.privkey_for_address(chosen)
        assert record.signer_hash160_hex == key.public_key().hash160(key.compressed).hex()
        assert verify_attestation(record).valid


class TestTheCommandIsWiredIn:
    def test_mark_is_registered_at_the_top_level(self) -> None:
        """Top level rather than under ``glyph``: HashMark is a third-party format and
        filing it under ``glyph`` would imply pyrxd owns it."""
        from pyrxd.cli.main import cli

        assert "mark" in cli.commands
        from pyrxd.cli.glyph_cmds import glyph_group

        assert "mark" not in glyph_group.commands

    def test_the_encoder_now_has_a_production_caller(self) -> None:
        """W5's stated purpose. Before this, ``encode_hashmark``'s only non-test reference
        was its own lazy-export entry in ``pyrxd.script``."""
        import ast
        from pathlib import Path as _P

        src = _P(__file__).resolve().parent.parent / "src" / "pyrxd"
        callers = {
            p.relative_to(src).as_posix()
            for p in src.rglob("*.py")
            if p.name not in {"hashmark.py", "__init__.py"}
            and any(
                isinstance(n, ast.Name) and n.id == "encode_hashmark"
                for n in ast.walk(ast.parse(p.read_text(encoding="utf-8")))
            )
        }
        assert "hashmark_tx.py" in callers, f"encode_hashmark is called from: {sorted(callers)}"

    def test_the_json_payload_labels_its_own_attestation_as_self_made(self, runner, tmp_path, monkeypatch) -> None:
        """``verify_attestation`` ran over our own bytes before funding. That is a weaker
        claim than a stranger's verdict and the field name has to say so, or a consumer
        will render it as one."""
        import json

        h = _MarkHarness()
        result, _ = _invoke(runner, tmp_path, monkeypatch, harness=h, top=["--json", "--yes"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["self_attestation"] == "valid"
        assert payload["network_genesis"] == RADIANT_MAINNET_GENESIS
        assert payload["record_bytes"] == len(bytes.fromhex(payload["op_return_script_hex"]))
        assert payload["broadcast"] is True
        assert payload["label_as_typed"] is None
