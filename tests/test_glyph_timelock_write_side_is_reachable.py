"""#556: the timelocked-content WRITE side — mint and reveal — reached from production.

The read half was closed first (``test_glyph_timelock_read_side_is_reachable.py``) and its cause
turned out to be a PARSER gap. This half's cause is the mirror image: an ENCODER gap.
``GlyphMetadata.to_cbor_dict`` emitted no ``crypto`` key under any circumstance, so a mint could
declare ``p = [NFT, ENCRYPTED, TIMELOCK]`` and go on chain carrying no CEK commitment at all —
a token that says it is sealed and holds nothing a reveal could ever be checked against.
``add_timelock_to_metadata`` had no production caller because a production caller could not have
produced anything that worked.

So the tests here drive the transport, not the mechanism: build, CBOR-encode, decode back, and
check the commitment survived. A test that hands ``add_timelock_to_metadata`` a hand-built stub
and inspects the returned object proves the dataclass agrees with itself — which is true whether
or not a single byte of it reaches a chain.

The reveal half is where the irreversibility lives, and every refusal below is paired with an
honest case. Two mistakes on that path are permanent and neither announces itself: publishing a
key that is not the one the token committed to (the reveal is spent, the payload is unreadable
forever) and publishing the right key early (the timelock is over, for everyone). A guard that
refused an honest reveal would be its own defect — there is no way to un-refuse a lot whose
auction has closed — so the pairs are not decoration.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from click.testing import CliRunner

import pyrxd
from pyrxd.cli.context import CliContext
from pyrxd.glyph.client import GlyphClient
from pyrxd.glyph.encrypted_content import EncryptedContentStub
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.timelock import (
    TimelockParams,
    TimelockRecipient,
    build_timelock_mint,
    compute_cek_hash,
    format_cek_hash,
    get_unlock_remaining,
    is_unlocked,
)
from pyrxd.glyph.timelock_reveal_tx import (
    CekCommitmentMismatch,
    TimelockNotExpired,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FEE_RATE = 10_000  # Radiant's relay floor, not a token test rate
UNLOCK_AT = 500_000
TOKEN_REF = "ab" * 32 + ":0"
_VECTORS = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture
def runner() -> CliRunner:
    """Local, because ``tests/cli/conftest.py``'s fixtures do not reach this directory."""
    return CliRunner()


async def _async(value):
    """Wrap a value so a plain lambda can stand in for an async method."""
    return value


def _seal(*, unlock_at: int = UNLOCK_AT, mode: str = "block", hint: str = "", recipients=()):
    """A sealed mint over a FRESH key every call.

    Fresh because a fixed CEK would make ``sha256(cek)`` a constant, and a commitment check that
    passes against a constant cannot tell a real comparison from a hardcoded one.
    """
    return build_timelock_mint(
        name="Sealed Lot",
        content_type="text/plain",
        plaintext=b"the reserve price is 1000 RXD",
        params=TimelockParams(mode=mode, unlock_at=unlock_at, hint=hint),  # type: ignore[arg-type]
        recipients=recipients,
    )


# ---------------------------------------------------------------------------
# The envelope has to survive the wire, or none of the rest means anything
# ---------------------------------------------------------------------------


class TestTheMintCarriesTheCommitmentOnChain:
    def test_the_commitment_survives_the_cbor_round_trip(self) -> None:
        """The encoder gap itself. Everything below depends on this."""
        build = _seal(hint="opens at 500k")
        decoded = decode_payload(encode_payload(build.metadata)[0])

        assert decoded.timelock is not None, "to_cbor_dict dropped crypto.timelock — the #556 encoder gap"
        assert decoded.timelock.cek_hash == build.cek_hash
        assert decoded.timelock.unlock_at == UNLOCK_AT
        assert decoded.timelock.mode == "block"
        assert decoded.timelock.hint == "opens at 500k"

    def test_the_commitment_is_the_hash_of_the_key_that_was_returned(self) -> None:
        """Not merely present — the SAME key. A commitment to some other 32 bytes would round-trip
        just as happily and leave the CEK in hand useless."""
        build = _seal()
        decoded = decode_payload(encode_payload(build.metadata)[0])
        assert decoded.timelock.cek_hash == format_cek_hash(compute_cek_hash(build.cek))
        assert pyrxd.verify_cek_reveal(build.cek, decoded.timelock.cek_hash) is True

    def test_the_plaintext_hash_on_chain_decrypts_the_ciphertext_off_it(self) -> None:
        """``main.hash`` is the AAD prefix every chunk is authenticated against, so a wrong one
        yields a token nobody can open even holding the right key. Proved by decrypting with the
        value taken back OFF the wire rather than the one held in memory."""
        build = _seal()
        decoded_dict = cbor2.loads(encode_payload(build.metadata)[0])
        on_chain_hash = bytes.fromhex(decoded_dict["main"]["hash"].removeprefix("sha256:"))

        recovered = pyrxd.decrypt_chunked(build.ciphertext, build.cek, on_chain_hash)
        assert recovered == b"the reserve price is 1000 RXD"

    def test_the_ciphertext_is_NOT_on_chain(self) -> None:
        """The property that makes the whole scheme work — and the reason the CLI insists on a
        --ciphertext-out path. If the bytes were in the envelope the timelock would gate nothing:
        anyone could take them now and decrypt after the reveal without the minter's help."""
        build = _seal()
        cbor_bytes = encode_payload(build.metadata)[0]
        for chunk in build.ciphertext.chunks:
            assert chunk.ciphertext not in cbor_bytes
            assert chunk.nonce not in cbor_bytes

    def test_the_key_is_NOT_on_chain(self) -> None:
        build = _seal()
        assert build.cek not in encode_payload(build.metadata)[0]

    def test_the_glyph_metadata_and_the_photonic_stub_encode_identically(self) -> None:
        """Two objects describe one envelope; they must not be two envelopes.

        ``stub`` is Photonic's shape and is what the interop vectors are written against;
        ``metadata`` is what the minter accepts. The bridge builds one from the other, so this
        pins that the bridge is lossless in the direction that reaches a chain."""
        build = _seal(hint="h")
        assert build.metadata.to_cbor_dict() == build.stub.to_dict()

    def test_the_envelope_matches_the_photonic_vector(self) -> None:
        """Cross-implementation, against Photonic's own output rather than our idea of it.

        ``tests/fixtures/photonic_timelock_vectors.json`` was generated by calling Photonic's
        actual source. Rebuilding its block-mode case here and comparing the CBOR dict checks the
        one thing a self-consistent round trip cannot: that the bytes are the bytes another
        implementation writes."""
        vec = json.loads(_VECTORS.read_text())["timelock_metadata_block_mode"]
        expected = vec["output_metadata"]
        cek = bytes.fromhex(json.loads(_VECTORS.read_text())["cek_hash_commitment"]["cek"])

        build = build_timelock_mint(
            name=expected["name"],
            content_type=expected["type"],
            plaintext=bytes.fromhex(json.loads(_VECTORS.read_text())["chunked_aead_small"]["plaintext"]),
            params=TimelockParams(mode=vec["mode"], unlock_at=vec["unlock_at"]),
            cek=cek,
        )
        produced = build.metadata.to_cbor_dict()

        assert produced["p"] == expected["p"]
        assert produced["type"] == expected["type"]
        assert produced["name"] == expected["name"]
        assert produced["main"] == expected["main"]
        assert produced["crypto"] == expected["crypto"]


class TestTheMinterRefusesAMintItCannotBackWithACommitment:
    """The paired refusal/honest case for the guard added inside ``GlyphMinter._require_protocol``.

    The refusal side is the one that matters: a TIMELOCK mint with no ``crypto.timelock`` is a
    silent failure — the token looks sealed, the operator holds a CEK, and no reveal can ever be
    verified against anything. The honest side is what stops the guard from being a wall in front
    of the feature it protects.
    """

    def _minter(self):
        from pyrxd.glyph.mint import GlyphMinter, UnsafeNullPendingStore

        return GlyphMinter(MagicMock(), MagicMock(), UnsafeNullPendingStore(), fee_rate=FEE_RATE)

    def test_a_marker_without_a_commitment_is_refused(self) -> None:
        bare = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="looks sealed",
        )
        with pytest.raises(ValidationError, match="no crypto.timelock"):
            self._minter()._require_protocol(bare, GlyphProtocol.NFT, "commit_nft")

    def test_the_built_metadata_passes_the_same_guard(self) -> None:
        """The honest path, through the exact call the refusal above came from."""
        self._minter()._require_protocol(_seal().metadata, GlyphProtocol.NFT, "commit_nft")

    def test_an_ordinary_nft_is_untouched_by_the_guard(self) -> None:
        """The branch that was NOT built for. Every existing mint has no timelock at all, and a
        guard keyed to a protocol marker must be invisible to them."""
        self._minter()._require_protocol(
            GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"), GlyphProtocol.NFT, "commit_nft"
        )

    def test_a_decoded_timelocked_token_is_still_constructible(self) -> None:
        """The read path builds exactly the object the guard refuses, for every timelocked token
        on the chain. Putting this check in ``GlyphMetadata.__post_init__`` instead would have made
        third-party tokens undecodable — a refusal of honest work, aimed at the wrong half."""
        decoded = decode_payload(encode_payload(_seal().metadata)[0])
        assert decoded.timelock is not None
        assert decoded.crypto is None, "decode stays write-side-asymmetric on purpose"


class TestTheStateHelpersReadTheShapeTheParsePathProduces:
    """``is_unlocked`` took only Photonic's stub shape, so asking it about a token read off the
    chain raised ``AttributeError`` and the read-side test had to hand-roll an adapter. Both
    shapes now work; both are checked, because widening one and leaving the other is how the
    original gap looked."""

    @pytest.mark.parametrize("shape", ["stub", "decoded"])
    def test_locked_before_and_open_at_the_unlock_height(self, shape: str) -> None:
        build = _seal()
        meta = build.stub if shape == "stub" else decode_payload(encode_payload(build.metadata)[0])
        assert is_unlocked(meta, current_block=UNLOCK_AT - 1) is False
        assert is_unlocked(meta, current_block=UNLOCK_AT) is True
        assert get_unlock_remaining(meta, current_block=UNLOCK_AT - 7) == 7

    def test_an_object_with_neither_spelling_raises_rather_than_reporting_open(self) -> None:
        """Fail closed. Returning "not timelocked" for an unrecognised object is the optimistic
        answer, and the optimistic answer is the one that costs something here."""
        with pytest.raises(TypeError, match="protocol list"):
            is_unlocked(object(), current_block=UNLOCK_AT)


# ---------------------------------------------------------------------------
# The reveal, through GlyphClient — the production entry point
# ---------------------------------------------------------------------------


def _source_tx(vout: int, spk: bytes, value: int) -> bytes:
    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


class _RevealHarness:
    """A wallet holding one plain-RXD UTXO, and a node with a tip.

    Fresh keys per construction: signing is RFC 6979, so whether a given transaction underpays is
    a fixed property of that transaction. A fixed-key fixture signs one message forever.
    """

    def __init__(self, *, tip: int = UNLOCK_AT, fund_value: int = 50_000_000, tip_time: int = 1_700_000_000) -> None:
        self.fund_key = PrivateKey()
        self.fund_spk = P2PKH().lock(self.fund_key.address()).serialize()
        self.fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=fund_value, height=100)
        txmap = {"cc" * 32: _source_tx(1, self.fund_spk, fund_value)}
        triples = [(self.fund_utxo, self.fund_key.address(), self.fund_key)]

        class _Wallet:
            async def collect_spendable(self, client):
                return triples

        # An 80-byte header whose time field (bytes 68:72, little-endian) is the chain clock the
        # client reads for a time-mode lock.
        header = bytearray(80)
        header[68:72] = int(tip_time).to_bytes(4, "little")

        self.broadcast_calls: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            self.broadcast_calls.append(raw)
            return Transaction.from_hex(raw.hex()).txid()

        self.client = MagicMock()
        self.client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        self.client.get_tip_height = AsyncMock(return_value=tip)
        self.client.get_block_header = AsyncMock(return_value=bytes(header))
        self.client.broadcast = _bcast
        self.wallet = _Wallet()

    @property
    def glyph(self) -> GlyphClient:
        return GlyphClient(self.client, self.wallet, fee_rate=FEE_RATE)


class TestTheRevealRefusesWhatCannotBeUndone:
    def test_a_cek_that_is_not_the_committed_one_is_refused(self) -> None:
        """Publishing it would spend the reveal and leave the payload unreadable forever. The
        refusal comes from inside the build, not from a check the CLI remembered to run."""
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        with pytest.raises(CekCommitmentMismatch, match="on-chain commitment"):
            asyncio.run(h.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=os.urandom(32)))
        assert h.broadcast_calls == [], "a refused reveal must not have sent anything"

    def test_a_reveal_before_the_unlock_point_is_refused(self) -> None:
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT - 1)
        with pytest.raises(TimelockNotExpired, match="unlocks at"):
            asyncio.run(h.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))
        assert h.broadcast_calls == []

    def test_metadata_with_no_commitment_is_refused(self) -> None:
        """There is nothing to check the key against, so a reveal here would publish a key no
        observer could tie to the token."""
        bare = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain")
        h = _RevealHarness()
        with pytest.raises(ValidationError, match="no crypto.timelock"):
            asyncio.run(h.glyph.build_timelock_reveal(bare, token_ref=TOKEN_REF, cek=os.urandom(32)))

    def test_the_wrong_cek_is_refused_EVEN_WITH_allow_early(self) -> None:
        """The override loosens the clock and nothing else. A flag that also waived the commitment
        check would turn "open the lot early" into "brick the lot", which is the mistake nobody
        would knowingly ask for."""
        build = _seal()
        h = _RevealHarness(tip=1)
        with pytest.raises(CekCommitmentMismatch):
            asyncio.run(
                h.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=os.urandom(32), allow_early=True)
            )


class TestTheHonestRevealStillWorks:
    """Paired with every refusal above. A reveal that cannot be published on time is as much a
    failure as one published early — the seller's auction closed either way."""

    def test_an_honest_reveal_builds_signs_and_broadcasts(self) -> None:
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        receipt = asyncio.run(h.glyph.reveal_timelock(build.metadata, token_ref=TOKEN_REF, cek=build.cek))

        assert len(h.broadcast_calls) == 1
        assert receipt.txid == Transaction.from_hex(h.broadcast_calls[0].hex()).txid()
        assert receipt.cek == build.cek.hex()
        assert receipt.commitment == build.cek_hash
        assert receipt.fee > 0

    def test_the_boundary_block_is_open_not_closed(self) -> None:
        """``unlock_at`` itself is revealable. An off-by-one here strands the reveal for a whole
        block on a chain with no way to ask again sooner."""
        build = _seal()
        plan = asyncio.run(
            _RevealHarness(tip=UNLOCK_AT).glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek)
        )
        assert plan.unlocked is True and plan.early_override is False

    def test_allow_early_publishes_and_records_that_it_did(self) -> None:
        """The escape hatch works, and the plan says so — the CLI prints that line, which is the
        only warning an operator gets."""
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT - 250)
        reveal = asyncio.run(
            h.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek, allow_early=True)
        )
        assert reveal.plan.early_override is True
        assert reveal.plan.unlocked is False
        assert reveal.plan.remaining == 250

    def test_the_published_output_is_the_op_return_at_value_zero(self) -> None:
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        reveal = asyncio.run(h.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))

        out = reveal.tx.outputs[0]
        assert out.satoshis == 0
        assert out.locking_script.serialize() == reveal.plan.op_return_script
        assert out.locking_script.serialize()[0] == 0x6A  # OP_RETURN

    def test_a_reveal_may_be_built_from_metadata_read_OFF_THE_CHAIN(self) -> None:
        """The shape a real operator has. They did not keep the build object from months ago; they
        have a ref, a key file, and whatever ``GlyphScanner`` fetches."""
        build = _seal()
        decoded = decode_payload(encode_payload(build.metadata)[0])
        h = _RevealHarness(tip=UNLOCK_AT)
        reveal = asyncio.run(h.glyph.build_timelock_reveal(decoded, token_ref=TOKEN_REF, cek=build.cek))
        assert reveal.plan.commitment == build.cek_hash


class TestTheClockComesFromTheChain:
    def test_a_time_mode_lock_is_judged_by_the_tip_HEADER_not_the_local_clock(self) -> None:
        """A local clock can be wrong by any amount with nothing to say so, and this decision is
        irreversible. Both assertions use timestamps far from any plausible wall clock, so a
        ``time.time()`` implementation cannot pass either by luck."""
        unlock = 2_000_000_000  # year 2033
        build = _seal(mode="time", unlock_at=unlock)

        behind = _RevealHarness(tip_time=unlock - 1)
        with pytest.raises(TimelockNotExpired):
            asyncio.run(behind.glyph.build_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))

        ahead = _RevealHarness(tip_time=unlock)
        plan = asyncio.run(ahead.glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))
        assert plan.unlocked is True
        ahead.client.get_block_header.assert_awaited()

    def test_a_block_mode_lock_does_not_fetch_a_header_at_all(self) -> None:
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        asyncio.run(h.glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))
        h.client.get_block_header.assert_not_awaited()


class TestWhatGoesOnChainIsWhatAnObserverWillRead:
    def test_the_plan_parses_and_validates_as_a_third_party_would(self) -> None:
        """Driven entirely through top-level exports, the way a wallet that is not pyrxd's CLI
        would have to do it: take the script off the chain, parse it, validate it against the
        commitment, then decrypt."""
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        plan = asyncio.run(h.glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))

        proof = pyrxd.parse_reveal_proof_script(plan.op_return_script)
        assert proof is not None
        verdict = pyrxd.validate_reveal_proof(proof, expected_token_ref=TOKEN_REF, expected_cek_hash=build.cek_hash)
        assert verdict.valid, verdict.error

        revealed = bytes.fromhex(proof.cek)
        assert pyrxd.verify_cek_reveal(revealed, build.cek_hash)
        assert pyrxd.decrypt_chunked(build.ciphertext, revealed, build.ciphertext.plaintext_hash) == (
            b"the reserve price is 1000 RXD"
        )

    def test_a_proof_for_a_DIFFERENT_token_does_not_validate(self) -> None:
        """The other half of the check above. ``valid`` that is True for everything proves
        nothing, and ``token_ref`` is the field that binds a published key to one token."""
        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        plan = asyncio.run(h.glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))
        proof = pyrxd.parse_reveal_proof_script(plan.op_return_script)
        verdict = pyrxd.validate_reveal_proof(proof, expected_token_ref="ff" * 32 + ":3")
        assert not verdict.valid and "token_ref mismatch" in verdict.error


class TestARecipientCanOpenItWithoutWaiting:
    def test_a_wrapped_recipient_decrypts_before_the_unlock_point(self) -> None:
        """The half of the protocol that is not the timelock: a wrap on chain lets one named party
        in immediately. Built through the same entry point, so the two cannot diverge."""
        sk = os.urandom(32)
        build = _seal(recipients=[TimelockRecipient(kid="auctioneer", public_key=pyrxd.x25519_public_key(sk))])
        decoded_dict = cbor2.loads(encode_payload(build.metadata)[0])

        wrap = decoded_dict["crypto"]["recipients"][0]
        assert wrap["kid"] == "auctioneer"

        stub = EncryptedContentStub.from_dict(decoded_dict)
        recovered_cek = pyrxd.unwrap_cek_x25519(
            stub.crypto.recipients[0].wrapped_cek,
            stub.crypto.recipients[0].epk,
            sk,
            compute_cek_hash(build.cek),
        )
        assert recovered_cek == build.cek
        assert pyrxd.decrypt_chunked(build.ciphertext, recovered_cek, build.ciphertext.plaintext_hash)

    def test_with_no_recipients_the_envelope_carries_no_wraps(self) -> None:
        assert "recipients" not in cbor2.loads(encode_payload(_seal().metadata)[0])["crypto"]


# ---------------------------------------------------------------------------
# It has to reach a human
# ---------------------------------------------------------------------------


class TestBothCommandsAreRegisteredOnTheGlyphGroup:
    def test_the_group_lists_them(self) -> None:
        from pyrxd.cli.glyph_cmds import glyph_group

        assert "timelock-mint" in glyph_group.commands
        assert "timelock-reveal" in glyph_group.commands


class TestTheDryRunShowsAnOperatorExactlyWhatWouldBePublished:
    """The half that a caller grep cannot check. The reveal can be built correctly, signed
    correctly and covered by every test above while the only screen anyone looks at says nothing
    useful — and the thing being approved here is irreversible."""

    def _invoke(self, runner, tmp_path, monkeypatch, *, cek_hex: str, tip: int, extra=(), top=()):
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        build = self.build
        h = _RevealHarness(tip=tip)
        self.harness = h

        cek_file = tmp_path / "cek.hex"
        cek_file.write_text(cek_hex)

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)

        async def _fetch(self, ref):
            return decode_payload(encode_payload(build.metadata)[0])

        monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
        h.client.__aenter__ = AsyncMock(return_value=h.client)
        h.client.__aexit__ = AsyncMock(return_value=None)

        return runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                *top,
                "glyph",
                "timelock-reveal",
                TOKEN_REF,
                "--cek-file",
                str(cek_file),
                *extra,
            ],
        )

    @pytest.fixture(autouse=True)
    def _build(self):
        self.build = _seal()

    def test_the_dry_run_prints_the_key_and_broadcasts_nothing(self, runner, tmp_path, monkeypatch) -> None:
        result = self._invoke(
            runner, tmp_path, monkeypatch, cek_hex=self.build.cek.hex(), tip=UNLOCK_AT, extra=["--dry-run"]
        )
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output
        assert self.build.cek.hex() in result.output, "the operator must see the key that would become public"
        assert self.build.cek_hash in result.output, "and the commitment it matched"
        assert "cannot be undone" in result.output
        assert TOKEN_REF in result.output
        assert self.harness.broadcast_calls == [], "a dry run broadcast something"

    def test_the_early_override_is_shouted_not_footnoted(self, runner, tmp_path, monkeypatch) -> None:
        result = self._invoke(
            runner,
            tmp_path,
            monkeypatch,
            cek_hex=self.build.cek.hex(),
            tip=UNLOCK_AT - 3,
            extra=["--dry-run", "--allow-early"],
        )
        assert result.exit_code == 0, result.output
        assert "EARLY REVEAL" in result.output
        assert "3 blocks" in result.output
        assert self.harness.broadcast_calls == []

    def test_a_wrong_key_is_refused_in_words_an_operator_can_act_on(self, runner, tmp_path, monkeypatch) -> None:
        result = self._invoke(runner, tmp_path, monkeypatch, cek_hex=os.urandom(32).hex(), tip=UNLOCK_AT)
        assert result.exit_code == 1
        assert "not the one this token committed to" in result.output
        assert "nothing was broadcast" in result.output
        assert self.harness.broadcast_calls == []

    def test_an_early_reveal_without_the_flag_names_the_flag(self, runner, tmp_path, monkeypatch) -> None:
        result = self._invoke(runner, tmp_path, monkeypatch, cek_hex=self.build.cek.hex(), tip=UNLOCK_AT - 10)
        assert result.exit_code == 1
        assert "timelock has not expired" in result.output
        assert "--allow-early" in result.output
        assert self.harness.broadcast_calls == []

    def test_a_short_cek_file_is_a_message_not_a_traceback(self, runner, tmp_path, monkeypatch) -> None:
        result = self._invoke(runner, tmp_path, monkeypatch, cek_hex="deadbeef", tip=UNLOCK_AT)
        assert result.exit_code == 1
        assert "32-byte CEK" in result.output

    def test_the_bytes_broadcast_are_the_bytes_the_prompt_showed(self, runner, tmp_path, monkeypatch) -> None:
        """The honest path through the CLI, and the property a second build would break.

        The prompt prints the key and the fee for a transaction it has already signed. Sending a
        DIFFERENT transaction afterwards — even an equivalent one — is a confirmation that shows
        one artifact and publishes another, which is worse than no confirmation because it looks
        like one. So this asserts the broadcast bytes carry exactly the OP_RETURN the operator was
        shown, and that the reported txid is that transaction's."""
        result = self._invoke(runner, tmp_path, monkeypatch, cek_hex=self.build.cek.hex(), tip=UNLOCK_AT, top=["--yes"])
        assert result.exit_code == 0, result.output
        assert len(self.harness.broadcast_calls) == 1
        sent = Transaction.from_hex(self.harness.broadcast_calls[0].hex())
        assert sent.outputs[0].satoshis == 0

        # Byte-for-byte against the reveal for exactly these inputs, not merely "a reveal for this
        # token". A rebuild that quietly changed any published field — the hint, the ref, the key —
        # would still parse as a valid proof and still report a real txid.
        expected = pyrxd.plan_timelock_reveal(
            self.build.metadata, token_ref=TOKEN_REF, cek=self.build.cek, current_block=UNLOCK_AT
        )
        assert sent.outputs[0].locking_script.serialize() == expected.op_return_script
        assert sent.txid() in result.output, "the reported txid must be the transaction that was sent"
        assert "Timelock revealed" in result.output

    def test_a_RAW_32_byte_cek_file_is_accepted(self, runner, tmp_path, monkeypatch) -> None:
        """Paired with the refusal above. ``timelock-mint`` writes hex, but a key that came out of
        a hardware token or a password manager is 32 raw bytes, and refusing it would be this
        repo's "guard refusing valid work" on the one input that cannot be regenerated."""
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        h = _RevealHarness(tip=UNLOCK_AT)
        raw_file = tmp_path / "cek.bin"
        raw_file.write_bytes(self.build.cek)

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)

        async def _fetch(self, ref):
            return self_metadata

        self_metadata = decode_payload(encode_payload(self.build.metadata)[0])
        monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
        h.client.__aenter__ = AsyncMock(return_value=h.client)
        h.client.__aexit__ = AsyncMock(return_value=None)

        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                "glyph",
                "timelock-reveal",
                TOKEN_REF,
                "--cek-file",
                str(raw_file),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert self.build.cek.hex() in result.output


class TestTheMintCommandRefusesToClobberAKeyFile:
    def test_an_existing_cek_out_aborts_before_anything_is_built(self, runner, tmp_path, monkeypatch) -> None:
        """It may be another token's only key, and that token cannot be re-minted."""
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        content = tmp_path / "secret.txt"
        content.write_text("x")
        existing = tmp_path / "cek.hex"
        existing.write_text("do not clobber me")

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: MagicMock())
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                "glyph",
                "timelock-mint",
                "--content",
                str(content),
                "--name",
                "n",
                "--unlock-at",
                "10",
                "--cek-out",
                str(existing),
                "--ciphertext-out",
                str(tmp_path / "ct.json"),
                "--envelope-out",
                str(tmp_path / "env.cbor"),
            ],
        )
        assert result.exit_code == 1
        assert "already exists" in result.output
        assert existing.read_text() == "do not clobber me"

    def test_the_key_file_is_written_mode_0600(self, tmp_path) -> None:
        from pyrxd.cli.glyph_timelock_cmds import _write_secret

        p = tmp_path / "k.hex"
        _write_secret(p, "aa" * 32)
        assert oct(p.stat().st_mode)[-3:] == "600"
        assert p.read_text() == "aa" * 32


class TestTheHelpTextSaysWhatIsAtStake:
    """The riskiest text in this feature is the sentence an operator reads at the moment they are
    deciding. These pin that it is present, not that it is well written — but an empty warning is
    the failure that would otherwise ship silently."""

    def test_reveal_help_calls_it_irreversible(self, runner) -> None:
        from pyrxd.cli.main import cli

        out = runner.invoke(cli, ["glyph", "timelock-reveal", "--help"]).output
        assert "IRREVERSIBLE" in out
        assert "--dry-run" in out

    def test_mint_help_says_the_key_is_not_on_chain(self, runner) -> None:
        from pyrxd.cli.main import cli

        out = runner.invoke(cli, ["glyph", "timelock-mint", "--help"]).output
        assert "Nothing on chain carries it" in out


class TestTheMetadataFieldsAreMutuallyExclusive:
    def test_setting_both_main_spellings_is_refused(self) -> None:
        """They encode to the same CBOR key, so one would be dropped silently and which one
        depends on statement order in the encoder. For an encrypted mint the dropped field decides
        whether the token carries the plaintext hash a recipient needs."""
        from pyrxd.glyph.types import GlyphMedia

        with pytest.raises(ValidationError, match="both encode to the CBOR 'main' key"):
            GlyphMetadata(
                protocol=[GlyphProtocol.NFT],
                main=GlyphMedia(mime_type="text/plain", data=b"x"),
                encrypted_main=_seal().stub.main,
            )

    def test_either_one_alone_is_fine(self) -> None:
        from pyrxd.glyph.types import GlyphMedia

        assert GlyphMetadata(
            protocol=[GlyphProtocol.NFT], main=GlyphMedia(mime_type="text/plain", data=b"x")
        ).to_cbor_dict()["main"] == {"t": "text/plain", "b": b"x"}
        assert (
            GlyphMetadata(protocol=[GlyphProtocol.NFT], encrypted_main=_seal().stub.main).to_cbor_dict()["main"][
                "scheme"
            ]
            == "chunked-aead-v1"
        )


class TestTheBuilderRefusesEnvelopesItCannotCommit:
    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"name": ""}, "requires a name"),
            ({"content_type": ""}, "requires a content_type"),
        ],
    )
    def test_an_unlabelled_mint_is_refused(self, kwargs: dict, match: str) -> None:
        args = {"name": "n", "content_type": "text/plain", "plaintext": b"x", "params": TimelockParams("block", 1)}
        with pytest.raises(ValidationError, match=match):
            build_timelock_mint(**{**args, **kwargs})

    def test_a_short_cek_is_refused(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            build_timelock_mint(
                name="n",
                content_type="text/plain",
                plaintext=b"x",
                params=TimelockParams("block", 1),
                cek=b"\x00" * 31,
            )

    def test_a_generated_cek_is_not_the_same_twice(self) -> None:
        """The default path. A builder that reused a key would mean revealing one token revealed
        every other token sealed by the same process."""
        assert _seal().cek != _seal().cek

    def test_the_minimum_honest_call_works(self) -> None:
        """Paired with the three refusals above: name, content type, plaintext, params, nothing
        else."""
        build = build_timelock_mint(
            name="n", content_type="text/plain", plaintext=b"x", params=TimelockParams("block", 1)
        )
        assert build.metadata.protocol == (GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK)


class TestTheKeyDoesNotLeakThroughARepr:
    def test_the_build_repr_does_not_carry_the_cek(self) -> None:
        """Same rule and same reason as ``TimelockMintResult``: the printed form of a 32-byte key
        is a working key, and a build object is exactly what ends up in a log line."""
        build = _seal()
        assert build.cek.hex() not in repr(build)
        assert build.cek_hash in repr(build), "the commitment is public and useful in a log"

    def test_the_mint_receipt_repr_does_not_carry_the_cek(self) -> None:
        from pyrxd.glyph.client import TimelockMintReceipt
        from pyrxd.glyph.types import GlyphRef

        build = _seal()
        mint = MagicMock()
        mint.ref = GlyphRef(txid="aa" * 32, vout=0)
        receipt = TimelockMintReceipt(
            mint=mint,
            cek=build.cek,
            cek_hash=build.cek_hash,
            ciphertext=build.ciphertext,
            stub=build.stub,
            unlock_at=UNLOCK_AT,
        )
        assert build.cek.hex() not in repr(receipt)

    def test_the_REVEAL_receipt_DOES_carry_the_cek(self) -> None:
        """The deliberate exception. After the broadcast the key is public; a receipt that hid it
        would be describing the wrong state of the world."""
        from pyrxd.glyph.client import TimelockRevealReceipt

        r = TimelockRevealReceipt(txid="a" * 64, token_ref=TOKEN_REF, cek="bb" * 32, commitment="sha256:x", fee=1)
        assert r.cek == "bb" * 32


class TestTheEndToEndShapeReportedByTheCli:
    def test_the_json_payload_names_every_field_a_script_would_need(self, runner, tmp_path, monkeypatch) -> None:
        """The machine-readable half. Human output is checked above; this is what a wrapper script
        reads, and a missing ``raw_tx_hex`` on a dry run makes the dry run undemonstrable."""
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        build = _seal()
        h = _RevealHarness(tip=UNLOCK_AT)
        cek_file = tmp_path / "cek.hex"
        cek_file.write_text(build.cek.hex())
        metadata = decode_payload(encode_payload(build.metadata)[0])

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)
        monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", lambda self, ref: _async(metadata))
        h.client.__aenter__ = AsyncMock(return_value=h.client)
        h.client.__aexit__ = AsyncMock(return_value=None)

        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                "--json",
                "glyph",
                "timelock-reveal",
                TOKEN_REF,
                "--cek-file",
                str(cek_file),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.find("{") : result.output.rfind("}") + 1])
        assert payload["broadcast"] is False
        assert payload["txid"] is None
        assert payload["cek"] == build.cek.hex()
        assert payload["cek_hash"] == build.cek_hash
        assert payload["unlock_at"] == UNLOCK_AT
        assert payload["op_return_script_hex"].startswith("6a03676c79")
        assert Transaction.from_hex(payload["raw_tx_hex"]) is not None
        assert h.broadcast_calls == []
