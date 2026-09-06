"""Five findings from the post-#625 adversarial review of the Glyph TIMELOCK write side.

Every one of them sits on an operation that cannot be taken back: a mint cannot be amended, and
a published CEK is public forever. So each fix below is paired with the honest case it must not
refuse — on this path a false refusal is not the safe side. A holder whose auction has closed
and whose reveal is refused has lost exactly as much as one whose key went out early.

The five:

1. ``plan_timelock_reveal`` judged the lock by the PROTOCOL MARKER and not by the spec it was
   holding, so an envelope carrying ``crypto.timelock`` without ``9`` in ``p`` came back
   ``unlocked=True`` from a marker that was not there. ``decode_payload`` builds that object off
   the chain: it fills ``timelock`` from ``d["crypto"]["timelock"]`` without consulting ``d["p"]``.
2. The clock the gate compares against is an unauthenticated ElectrumX reading, and no prompt
   ever showed it. The authentication half is NOT fixed here — see the class docstring — but the
   number is now on screen, which is the part that lets a person disagree with it.
3. A malformed on-chain ``cek_hash`` raised a bare ``ValueError`` through the CLI as a traceback,
   and an unrecognised ``mode`` produced a refusal naming a fix that does not exist.
4. ``pyrxd glyph timelock-mint`` broadcast a commit it could not rebuild the reveal for.
5. ``GlyphClient.mint_timelocked_nft`` generated the key inside a call that then blocked on
   confirmation, so a failure in that window lost the only copy.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import cbor2
import pytest
from click.testing import CliRunner

from pyrxd.glyph.client import GlyphClient
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.timelock import (
    TimelockParams,
    TimelockRecipient,
    build_timelock_mint,
    compute_cek_hash,
    format_cek_hash,
    is_unlocked,
)
from pyrxd.glyph.timelock_reveal_tx import TimelockNotExpired, plan_timelock_reveal
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.security.errors import NetworkError, ValidationError

UNLOCK_AT = 500_000
TOKEN_REF = "ab" * 32 + ":0"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _seal(*, unlock_at: int = UNLOCK_AT, mode: str = "block", recipients=()):
    """A sealed mint over a FRESH key every call — a fixed CEK makes ``sha256(cek)`` a constant,
    and a commitment check that passes against a constant cannot tell a real comparison from a
    hardcoded one."""
    return build_timelock_mint(
        name="Sealed Lot",
        content_type="text/plain",
        plaintext=b"the reserve price is 1000 RXD",
        params=TimelockParams(mode=mode, unlock_at=unlock_at),  # type: ignore[arg-type]
        recipients=recipients,
    )


def _off_chain(protocol: list[int], *, cek: bytes, unlock_at: int, mode: str = "block") -> GlyphMetadata:
    """A token READ OFF THE CHAIN, through the real decoder, with a protocol list we choose.

    Built as CBOR and decoded rather than constructed in Python, because the shape at issue is
    one ``decode_payload`` produces and ``build_timelock_mint`` never would: the ``crypto``
    block and the ``p`` list are filled from different places and nothing reconciles them.
    """
    d = {
        "p": protocol,
        "name": "third-party token",
        "crypto": {
            "timelock": {
                "mode": mode,
                "unlock_at": unlock_at,
                "cek_hash": format_cek_hash(compute_cek_hash(cek)),
            }
        },
    }
    return decode_payload(cbor2.dumps(d, canonical=True))


# ---------------------------------------------------------------------------
# 1. The gate judges the spec it is holding, not a marker beside it
# ---------------------------------------------------------------------------


class TestTheUnlockGateJudgesTheSpecNotTheMarker:
    """``spec is None -> raise`` and "has it expired?" were decided from two different sources.

    The planner established the token WAS timelocked from ``crypto.timelock``, then asked
    ``is_unlocked``, which decides from ``GlyphProtocol.TIMELOCK in protocols`` and answers True
    for anything unmarked. A marker-less envelope therefore passed the spec check and skipped the
    gate — and ``early_override`` is ``not unlocked``, so the CLI's ``*** EARLY REVEAL`` banner
    was suppressed by the same wrong boolean.
    """

    def test_a_lock_without_the_marker_is_still_a_lock(self) -> None:
        cek = os.urandom(32)
        md = _off_chain([2, 8], cek=cek, unlock_at=99_000_000)
        assert GlyphProtocol.TIMELOCK not in md.protocol, "the fixture's whole point is the missing marker"
        assert md.timelock is not None, "...while the spec IS there, which is what made it slip through"

        with pytest.raises(TimelockNotExpired) as exc:
            plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=1)
        assert "99000000" in str(exc.value)

    def test_the_refusal_reports_the_real_distance_not_zero(self) -> None:
        """``get_unlock_remaining`` was marker-driven too, so the old path reported 0 remaining on
        a lock 99 million blocks out — the one number that would have told an operator."""
        cek = os.urandom(32)
        md = _off_chain([2, 8], cek=cek, unlock_at=99_000_000)
        with pytest.raises(TimelockNotExpired) as exc:
            plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=1)
        assert "98,999,999" in str(exc.value)

    def test_a_MARKED_token_is_gated_exactly_as_before(self) -> None:
        """The direction that already worked, so the fix is not carrying the pass on its own."""
        build = _seal()
        with pytest.raises(TimelockNotExpired):
            plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek, current_block=UNLOCK_AT - 1)


class TestItDoesNotRefuseTheHonestReveal:
    """The half that makes the gate above safe to tighten. Someone holding a token minted by
    another tool has real work to do here once its unlock point has passed, and there is no way to
    un-refuse a lot whose auction closed."""

    def test_a_marker_less_lock_reveals_once_its_height_arrives(self) -> None:
        cek = os.urandom(32)
        md = _off_chain([2, 8], cek=cek, unlock_at=UNLOCK_AT)
        plan = plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=UNLOCK_AT)
        assert plan.unlocked is True
        assert plan.early_override is False
        assert plan.remaining == 0

    def test_allow_early_still_opens_a_marker_less_lock(self) -> None:
        cek = os.urandom(32)
        md = _off_chain([2, 8], cek=cek, unlock_at=99_000_000)
        plan = plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=1, allow_early=True)
        assert plan.early_override is True, "and it must SAY it was early, which it could not before"

    def test_an_ordinary_reveal_at_the_boundary_block_is_unchanged(self) -> None:
        build = _seal()
        plan = plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek, current_block=UNLOCK_AT)
        assert plan.unlocked is True and plan.early_override is False


class TestTheReadSideHelperKeepsItsOwnMeaning:
    """``is_unlocked`` was not the bug and is not narrowed. Asking it about a plain NFT must still
    answer "yes, readable" — narrowing it to the spec would have made every un-timelocked token
    report LOCKED, which is the same defect pointed the other way."""

    def test_a_plain_nft_is_not_locked(self) -> None:
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="ordinary")
        assert is_unlocked(md, current_block=1) is True

    def test_a_marked_token_before_its_height_is_locked(self) -> None:
        build = _seal()
        assert is_unlocked(build.metadata, current_block=UNLOCK_AT - 1) is False
        assert is_unlocked(build.metadata, current_block=UNLOCK_AT) is True


# ---------------------------------------------------------------------------
# 2. Malformed third-party specs refuse instead of tracebacking
# ---------------------------------------------------------------------------


class TestAThirdPartyTokenRefusesRatherThanTracebacks:
    """``TimelockSpec.from_dict`` stores ``cek_hash`` as whatever string was on chain — the
    decoder is deliberately permissive about third-party bytes — and ``parse_cek_hash`` then
    raised a bare ``ValueError`` from inside the planner. ``ValueError`` is not in the set
    ``timelock_reveal_cmd`` catches, so the operator got a traceback. Nothing is broadcast either
    way; what was lost was any account of which of their two files was wrong."""

    def _malformed(self, cek_hash: str) -> GlyphMetadata:
        d = {
            "p": [2, 8, 9],
            "name": "t",
            "crypto": {"timelock": {"mode": "block", "unlock_at": 5, "cek_hash": cek_hash}},
        }
        return decode_payload(cbor2.dumps(d, canonical=True))

    @pytest.mark.parametrize(
        "bad", ["x", "sha256:zz", "sha256:" + "ab" * 31, "ab" * 32], ids=["junk", "nonhex", "short", "no-prefix"]
    )
    def test_an_unreadable_commitment_is_a_ValidationError(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not a readable sha256 hash"):
            plan_timelock_reveal(self._malformed(bad), token_ref=TOKEN_REF, cek=os.urandom(32), current_block=10)

    def test_a_SHORT_KEY_is_blamed_on_the_key_not_on_the_token(self) -> None:
        """Found by re-attacking the fix above. ``verify_cek_reveal`` raises ``ValueError`` from
        TWO places — ``parse_cek_hash`` on the commitment and ``compute_cek_hash`` on the key —
        and one ``except`` around both reported an operator's truncated key file as a malformed
        on-chain commitment. A confident sentence about the wrong input is worse than a traceback
        at a prompt where the next step is irreversible."""
        build = _seal()
        with pytest.raises(ValidationError, match="32 bytes and this one is 31"):
            plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek[:31], current_block=UNLOCK_AT)

    def test_a_WELL_FORMED_commitment_is_untouched(self) -> None:
        """The honest side of the same check: a real commitment must not be swept up by it."""
        build = _seal()
        plan = plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek, current_block=UNLOCK_AT)
        assert plan.commitment == build.cek_hash

    def test_an_unrecognised_mode_names_the_MODE_not_a_missing_clock(self) -> None:
        """``mode='BLOCK'`` used to report "no current_time was supplied" — while the caller had
        supplied ``current_block``. A message naming a fix the operator has already applied sends
        them looking in the wrong place, and the flag it points at is the one that disables the
        gate."""
        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=5, mode="BLOCK")
        with pytest.raises(TimelockNotExpired) as exc:
            plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=10)
        assert "'BLOCK'" in str(exc.value)
        assert "no current_time was supplied" not in str(exc.value)

    def test_an_unrecognised_mode_can_still_be_opened_deliberately(self) -> None:
        """Refusing it outright would strand the holder of a token some other tool minted. The
        mode is unjudgeable, not the reveal."""
        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=5, mode="BLOCK")
        plan = plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=10, allow_early=True)
        assert plan.early_override is True


# ---------------------------------------------------------------------------
# 3. The clock that decides an irreversible publication is on screen
# ---------------------------------------------------------------------------


def _source_tx(vout: int, spk: bytes, value: int) -> str:
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_output import TransactionOutput

    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


class _RevealHarness:
    """A wallet with one plain-RXD UTXO and a node reporting a tip we choose.

    The tip is the point: it is what ``GlyphClient.plan_timelock_reveal`` reads, and it is a
    number this SDK does not authenticate.
    """

    def __init__(self, *, tip: int, tip_time: int = 1_700_000_000) -> None:
        from pyrxd.keys import PrivateKey
        from pyrxd.network.electrumx import UtxoRecord
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction

        self.fund_key = PrivateKey()
        spk = P2PKH().lock(self.fund_key.address()).serialize()
        utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=50_000_000, height=100)
        txmap = {"cc" * 32: _source_tx(1, spk, 50_000_000)}
        triples = [(utxo, self.fund_key.address(), self.fund_key)]

        class _Wallet:
            async def collect_spendable(self, client):
                return triples

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
        self.client.__aenter__ = AsyncMock(return_value=self.client)
        self.client.__aexit__ = AsyncMock(return_value=None)
        self.wallet = _Wallet()


class TestTheOperatorSeesTheClockThatDecided:
    """A capability can be called, compute correctly and still be invisible on the only screen
    anyone looks at.

    The tip height comes from an ElectrumX server and NOTHING in this SDK verifies it — no proof
    of work, no link to a known header, no second endpoint — and pyrxd's defaults are third-party
    public servers. An endpoint that overstates the tip gets a permanent early reveal past a gate
    that reports itself satisfied, with the ``*** EARLY REVEAL`` banner silent because by its own
    arithmetic the lock HAS expired.

    **That authentication gap is NOT closed here.** Verifying the header chain is a different and
    much larger change, and a half-built version of it would refuse honest reveals. What is closed
    is that the deciding number was never shown: the plan now carries it and the prompt prints it,
    so an operator who knows roughly where the chain is can notice a tip that is wrong.
    """

    def _invoke(self, runner, tmp_path, monkeypatch, *, build=None, metadata=None, cek=None, tip: int, extra=()):
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.main import cli

        h = _RevealHarness(tip=tip)
        self.harness = h
        cek_file = tmp_path / "cek.hex"
        cek_file.write_text((build.cek if build is not None else cek).hex())
        fetched = metadata if metadata is not None else decode_payload(encode_payload(build.metadata)[0])

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)

        async def _fetch(self, ref):
            return fetched

        monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
        return runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                "glyph",
                "timelock-reveal",
                TOKEN_REF,
                "--cek-file",
                str(cek_file),
                *extra,
            ],
        )

    def test_the_prompt_shows_the_height_the_gate_compared_against(self, runner, tmp_path, monkeypatch) -> None:
        build = _seal()
        result = self._invoke(runner, tmp_path, monkeypatch, build=build, tip=812_340, extra=["--dry-run"])
        assert result.exit_code == 0, result.output
        assert "chain says" in result.output
        assert "812,340" in result.output, "the number that decided this must be on screen"
        assert "unverified" in result.output, "and it must not be presented as the chain's own word"
        assert self.harness.broadcast_calls == []

    def test_a_time_mode_lock_shows_the_HEADER_timestamp(self, runner, tmp_path, monkeypatch) -> None:
        """The other branch of the clock read. It is a different field from a different call, and
        showing the tip HEIGHT there would be a number that is correct and measures the wrong
        thing."""
        build = _seal(mode="time", unlock_at=1_600_000_000)
        result = self._invoke(runner, tmp_path, monkeypatch, build=build, tip=812_340, extra=["--dry-run"])
        assert result.exit_code == 0, result.output
        assert "1,700,000,000" in result.output, "the header's nTime, which is what the gate used"
        assert "812,340" not in result.output, "the tip height decided nothing for a time-mode lock"

    def test_the_plan_carries_it_for_a_scripted_caller_too(self, runner, tmp_path, monkeypatch) -> None:
        """A human prompt is no use to `--json`, and JSON mode is where an automated reveal runs."""
        build = _seal()
        result = self._invoke(runner, tmp_path, monkeypatch, build=build, tip=812_340, extra=["--dry-run"])
        assert result.exit_code == 0, result.output

        h = _RevealHarness(tip=812_340)
        glyph = GlyphClient(h.client, h.wallet, fee_rate=10_000)
        plan = asyncio.run(glyph.plan_timelock_reveal(build.metadata, token_ref=TOKEN_REF, cek=build.cek))
        assert plan.judged_at == 812_340

    def test_no_clock_for_the_mode_is_reported_as_such_not_as_a_number(self) -> None:
        """``judged_at`` must not quietly become 0, which reads as "the chain is at height 0"."""
        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=5, mode="time")
        plan = plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, current_block=10, allow_early=True)
        assert plan.judged_at is None

    def test_the_prompt_SURVIVES_a_lock_it_could_not_judge(self, runner, tmp_path, monkeypatch) -> None:
        """The branch this fix introduced and did not build for, found by planting the fix's own
        defect: ``judged_at`` is None whenever the mode is neither ``block`` nor ``time``, and
        ``f"{None:,}"`` is a ``TypeError``. It is a reachable prompt — a third-party token with
        mode ``'BLOCK'`` plus ``--allow-early`` lands exactly here — so an eagerly formatted line
        would have turned the visibility fix into the traceback-instead-of-a-message defect it was
        written next to."""
        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=5, mode="BLOCK")
        result = self._invoke(
            runner, tmp_path, monkeypatch, metadata=md, cek=cek, tip=10, extra=["--dry-run", "--allow-early"]
        )
        assert result.exit_code == 0, result.output
        assert "TypeError" not in result.output
        assert "no clock for lock mode 'BLOCK'" in result.output
        assert self.harness.broadcast_calls == []


# ---------------------------------------------------------------------------
# 4. The CLI mint can rebuild the reveal it might strand
# ---------------------------------------------------------------------------


class TestTheMintSavesTheBytesItsRevealNeeds:
    """``timelock-mint`` broadcasts a commit, waits 10+ minutes, then prompts AGAIN for the reveal.
    The commit output is ``OP_HASH256 <payload_hash> OP_EQUALVERIFY``, spendable only by a reveal
    pushing byte-identical CBOR — and this CLI has no pending store, this command has no metadata
    file, and a timeout, a kill or a declined prompt in that window strands the commit's value
    permanently.
    """

    def _mint(self, runner, tmp_path, monkeypatch, *, inner, extra=(), files=None):
        import pyrxd.cli.glyph_cmds as gc
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        content = tmp_path / "secret.txt"
        content.write_text("the reserve price is 1000 RXD")
        paths = files or {
            "cek": tmp_path / "cek.hex",
            "ct": tmp_path / "ct.json",
            "env": tmp_path / "envelope.cbor",
        }
        self.paths = paths

        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: MagicMock())
        monkeypatch.setattr(gc, "_mint_nft_inner", inner)
        monkeypatch.setattr(
            "pyrxd.cli.context.CliContext.make_client",
            lambda self: MagicMock(__aenter__=AsyncMock(return_value=MagicMock()), __aexit__=AsyncMock()),
        )
        return runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w.dat"),
                "--yes",
                "glyph",
                "timelock-mint",
                "--content",
                str(content),
                "--name",
                "Sealed Lot",
                "--unlock-at",
                str(UNLOCK_AT),
                "--cek-out",
                str(paths["cek"]),
                "--ciphertext-out",
                str(paths["ct"]),
                "--envelope-out",
                str(paths["env"]),
                *extra,
            ],
        )

    def test_the_envelope_is_on_disk_BEFORE_the_commit_is_broadcast(self, runner, tmp_path, monkeypatch) -> None:
        """Ordering is the entire fix. A file written after a successful mint protects nothing —
        the window it has to survive is the one where the mint does not succeed."""
        seen: dict[str, bytes] = {}

        async def _inner(ctx, wallet, metadata, client):
            seen["envelope"] = self.paths["env"].read_bytes()  # KeyError/OSError here IS the failure
            seen["metadata"] = encode_payload(metadata)[0]
            raise NetworkError("the node went away during the confirmation wait")

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner)
        assert result.exit_code != 0, "the mint failed, as the scenario requires"
        assert seen["envelope"] == seen["metadata"], "the saved bytes must be the ones the commit hashes"

    def test_the_saved_envelope_is_what_the_reveal_would_push(self, runner, tmp_path, monkeypatch) -> None:
        """Not "a valid envelope" — THE envelope. ``prepare_reveal`` takes these bytes verbatim,
        and a re-encode from anything else is exactly the drift that leaves the commit unspendable.
        Checked through the commit script's own hash rather than by eye."""
        from pyrxd.glyph.script import hash_payload

        captured: dict[str, bytes] = {}

        async def _inner(ctx, wallet, metadata, client):
            captured["cbor"] = encode_payload(metadata)[0]
            return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"}

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner)
        assert result.exit_code == 0, result.output
        on_disk = self.paths["env"].read_bytes()
        assert hash_payload(on_disk) == hash_payload(captured["cbor"])
        assert on_disk == captured["cbor"]

    def test_a_recipient_envelope_could_NOT_have_been_rebuilt_without_the_file(self) -> None:
        """The fixture check behind the whole finding. If the envelope were reproducible from the
        same inputs, the file would be a convenience; ``wrap_cek_x25519`` draws a fresh ephemeral
        key and a fresh 24-byte nonce per call, so it is not.

        Deliberately holds the CEK FIXED across both builds — the two envelopes differ despite
        everything the operator could re-supply being identical, which is the property that makes
        recovery impossible rather than merely awkward."""
        from pyrxd.crypto.kem import x25519_public_key

        cek = os.urandom(32)
        recipient = TimelockRecipient(kid="buyer", public_key=x25519_public_key(os.urandom(32)))
        kw = dict(
            name="Sealed Lot",
            content_type="text/plain",
            plaintext=b"the reserve price is 1000 RXD",
            params=TimelockParams(mode="block", unlock_at=UNLOCK_AT),
            cek=cek,
            recipients=[recipient],
        )
        first = encode_payload(build_timelock_mint(**kw).metadata)[0]  # type: ignore[arg-type]
        second = encode_payload(build_timelock_mint(**kw).metadata)[0]  # type: ignore[arg-type]
        assert first != second, "if these matched, --envelope-out would be a convenience, not a fix"

    def test_an_existing_envelope_file_is_not_clobbered(self, runner, tmp_path, monkeypatch) -> None:
        """Same reasoning as ``--cek-out``: it may be another token's only route to its commit."""
        existing = tmp_path / "envelope.cbor"
        existing.write_bytes(b"another token's envelope")

        async def _inner(ctx, wallet, metadata, client):  # pragma: no cover - must not be reached
            raise AssertionError("the mint proceeded past an existing envelope file")

        result = self._mint(
            runner,
            tmp_path,
            monkeypatch,
            inner=_inner,
            files={"cek": tmp_path / "k.hex", "ct": tmp_path / "ct.json", "env": existing},
        )
        assert result.exit_code == 1
        assert "already exists" in result.output
        assert existing.read_bytes() == b"another token's envelope"

    def test_the_honest_mint_writes_all_three_and_says_so(self, runner, tmp_path, monkeypatch) -> None:
        """The paired honest path: a third required flag must not make the ordinary mint harder to
        complete, and an operator has to be told what the third file is for."""

        async def _inner(ctx, wallet, metadata, client):
            return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"}

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner)
        assert result.exit_code == 0, result.output
        for key in ("cek", "ct", "env"):
            assert self.paths[key].exists(), key
        assert str(self.paths["env"]) in result.output
        # The saved bytes really are a sealed envelope, not an empty file that happens to exist.
        decoded = decode_payload(self.paths["env"].read_bytes())
        expected = format_cek_hash(compute_cek_hash(bytes.fromhex(self.paths["cek"].read_text().strip())))
        assert decoded.timelock is not None and decoded.timelock.cek_hash == expected


# ---------------------------------------------------------------------------
# 5. The SDK cannot generate a key it might never hand back
# ---------------------------------------------------------------------------


class TestKeyCustodyPrecedesTheCommit:
    """``mint_timelocked_nft`` generated the CEK into a local, then awaited ``mint_nft`` — which
    persists a resumable commit, broadcasts it and blocks for as long as a Radiant block takes.
    A ``NetworkError``, a timeout or a kill in that window and the receipt is never built, while
    the store holds a commit whose CBOR commits to ``sha256(cek)``. The documented recovery,
    ``reveal_nft(pending)``, then SUCCEEDS — and mints a token nobody can ever open.

    ``pyrxd glyph timelock-mint`` never had this problem: it writes its files before broadcasting.
    """

    def _client(self, mint_nft):
        glyph = GlyphClient(MagicMock(), MagicMock(), fee_rate=10_000)
        glyph.mint_nft = mint_nft  # type: ignore[method-assign]
        return glyph

    def _kwargs(self, **extra):
        return dict(
            name="Sealed Lot",
            content_type="text/plain",
            plaintext=b"the reserve price is 1000 RXD",
            params=TimelockParams(mode="block", unlock_at=UNLOCK_AT),
            **extra,
        )

    def test_neither_persist_nor_cek_is_refused_before_any_network_call(self) -> None:
        called: list[object] = []

        async def _mint_nft(metadata, **kw):  # pragma: no cover - must not be reached
            called.append(metadata)
            raise AssertionError("a mint was attempted with nowhere to put the key")

        glyph = self._client(_mint_nft)
        with pytest.raises(ValidationError, match="somewhere to put the key"):
            asyncio.run(glyph.mint_timelocked_nft(**self._kwargs()))  # type: ignore[arg-type]
        assert called == [], "nothing may be broadcast by a call that is going to be refused"

    def test_the_refusal_names_both_ways_out(self) -> None:
        """A caller who hits this is mid-integration; a refusal that does not say what to do
        instead sends them to the source."""

        async def _mint_nft(metadata, **kw):  # pragma: no cover - must not be reached
            raise AssertionError

        with pytest.raises(ValidationError) as exc:
            asyncio.run(self._client(_mint_nft).mint_timelocked_nft(**self._kwargs()))  # type: ignore[arg-type]
        assert "persist=" in str(exc.value) and "cek=" in str(exc.value)

    def test_persist_runs_BEFORE_the_mint(self) -> None:
        """The ordering IS the fix. A hook called after a successful mint protects nothing."""
        order: list[str] = []
        saved: dict[str, bytes] = {}

        async def _mint_nft(metadata, **kw):
            order.append("mint")
            return MagicMock()

        def _persist(build):
            order.append("persist")
            saved["cek"] = build.cek

        glyph = self._client(_mint_nft)
        receipt = asyncio.run(glyph.mint_timelocked_nft(**self._kwargs(persist=_persist)))  # type: ignore[arg-type]
        assert order == ["persist", "mint"]
        assert saved["cek"] == receipt.cek, "the hook must receive the key that was actually committed to"

    def test_a_persist_that_FAILS_stops_the_mint(self) -> None:
        """An un-saved key is a reason not to broadcast, not a warning to log."""
        minted: list[object] = []

        async def _mint_nft(metadata, **kw):  # pragma: no cover - must not be reached
            minted.append(metadata)
            return MagicMock()

        def _persist(build):
            raise OSError("read-only filesystem")

        with pytest.raises(OSError, match="read-only"):
            asyncio.run(self._client(_mint_nft).mint_timelocked_nft(**self._kwargs(persist=_persist)))  # type: ignore[arg-type]
        assert minted == []

    def test_an_ASYNC_persist_is_awaited(self) -> None:
        """Saving a key is I/O, and an async caller's writer is an async writer. A coroutine
        returned and dropped would look exactly like a successful save."""
        saved: dict[str, bytes] = {}

        async def _mint_nft(metadata, **kw):
            assert "cek" in saved, "the mint ran before the coroutine was awaited"
            return MagicMock()

        async def _persist(build):
            await asyncio.sleep(0)
            saved["cek"] = build.cek

        asyncio.run(self._client(_mint_nft).mint_timelocked_nft(**self._kwargs(persist=_persist)))  # type: ignore[arg-type]
        assert len(saved["cek"]) == 32

    def test_a_caller_who_already_holds_the_key_needs_no_hook(self) -> None:
        """The paired honest path. Custody already precedes the commit when the caller supplied the
        key, and demanding a hook as well would be the guard refusing valid work."""
        cek = os.urandom(32)

        async def _mint_nft(metadata, **kw):
            return MagicMock()

        receipt = asyncio.run(self._client(_mint_nft).mint_timelocked_nft(**self._kwargs(cek=cek)))  # type: ignore[arg-type]
        assert receipt.cek == cek
        assert receipt.cek_hash == format_cek_hash(compute_cek_hash(cek))
