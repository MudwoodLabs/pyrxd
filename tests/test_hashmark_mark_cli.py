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

            def derive_address(self, change: int, index: int) -> str:
                assert (change, index) == (0, 0), "mark must sign with the wallet's FIRST receive key"
                return signer_address

            def privkey_for(self, change: int, index: int) -> PrivateKey:
                assert (change, index) == (0, 0)
                return signer_key

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

    def test_the_derived_fields_cannot_be_supplied(self) -> None:
        """``record`` and ``attestation`` are ``init=False``, so they are always the bytes'
        own answer rather than whatever a caller asserted about them."""
        with pytest.raises(TypeError):
            MarkPlan(  # type: ignore[call-arg]
                op_return_script=encode_hashmark(hashlib.sha256(b"x").digest(), PrivateKey()),
                record="anything",
            )


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
