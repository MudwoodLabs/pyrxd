"""#556: the timelocked-content READ side, reachable from the top-level package.

WHAT MADE IT UNREACHABLE WAS A PARSER GAP, not a missing convenience method. `is_unlocked` and
`get_unlock_remaining` take metadata carrying a `TimelockSpec`, and `decode_payload` never read
`crypto.timelock` from the CBOR — so pyrxd would classify a token as TIMELOCK (`_classify_metadata_
protocol`) and then discard the only field that says when it opens. The helpers had no caller
because they had no POSSIBLE caller: nothing in the parse path could produce their argument.

So this file drives the whole path — CBOR bytes in, verdict out — rather than hand-building a spec
and calling the helper with it. A test that constructs the input by hand proves the mechanism; the
mechanism was never in doubt.

THE MINT AND REVEAL BUILDERS ARE NOW WIRED TOO, on the maintainer's decision (#556, 2026-09-01:
"WIRE it"). `tests/test_glyph_timelock_write_side_is_reachable.py` covers that half; what survives
here is the one export line that half did NOT take, pinned below.
"""

from __future__ import annotations

import os

import cbor2
import pytest

import pyrxd
from pyrxd.glyph.payload import decode_payload
from pyrxd.glyph.types import GlyphProtocol
from pyrxd.hash import sha256

_UNLOCK_AT = 500_000


def _sealed_cbor(cek: bytes, *, mode: str = "block", unlock_at: int = _UNLOCK_AT, hint: str = "") -> bytes:
    tl: dict = {"mode": mode, "unlock_at": unlock_at, "cek_hash": "sha256:" + sha256(cek).hex()}
    if hint:
        tl["hint"] = hint
    return cbor2.dumps(
        {
            "p": [GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            "name": "sealed",
            "crypto": {"timelock": tl},
        }
    )


class _Stub:
    """The shape `is_unlocked` reads: protocol markers plus `crypto.timelock`."""

    def __init__(self, metadata) -> None:
        self.p = metadata.protocol
        self.crypto = type("_C", (), {"timelock": metadata.timelock})


class TestTheDecoderKeepsTheTimelockSpec:
    """The gap itself. Everything below depends on this."""

    def test_crypto_timelock_survives_the_cbor_round_trip(self) -> None:
        m = decode_payload(_sealed_cbor(os.urandom(32), hint="opens at 500k"))
        assert m.timelock is not None, "decode_payload dropped crypto.timelock — the #556 gap"
        assert m.timelock.mode == "block"
        assert m.timelock.unlock_at == _UNLOCK_AT
        assert m.timelock.hint == "opens at 500k"

    def test_a_token_WITHOUT_a_timelock_decodes_to_None_not_an_error(self) -> None:
        m = decode_payload(cbor2.dumps({"p": [GlyphProtocol.NFT], "name": "plain"}))
        assert m.timelock is None

    def test_a_MALFORMED_timelock_is_dropped_not_raised(self) -> None:
        """Same discipline as creator/royalty/policy/rights: an unparseable OPTIONAL field must not
        make an otherwise-valid token undecodable. A token is not garbage because one block is."""
        m = decode_payload(cbor2.dumps({"p": [GlyphProtocol.NFT], "crypto": {"timelock": {"mode": "block"}}}))
        assert m.timelock is None

    @pytest.mark.parametrize("junk", [42, "nope", [1, 2], None])
    def test_a_non_dict_crypto_block_is_survivable(self, junk: object) -> None:
        assert decode_payload(cbor2.dumps({"p": [GlyphProtocol.NFT], "crypto": junk})).timelock is None


class TestTheReadSideAnswersTheHoldersQuestion:
    """Driven from CBOR through the top-level package — the production path, not the mechanism."""

    def test_locked_before_and_unlocked_at_the_unlock_height(self) -> None:
        stub = _Stub(decode_payload(_sealed_cbor(os.urandom(32))))
        assert pyrxd.is_unlocked(stub, current_block=_UNLOCK_AT - 1) is False
        assert pyrxd.is_unlocked(stub, current_block=_UNLOCK_AT) is True, "the boundary is inclusive"

    def test_remaining_counts_down_and_floors_at_zero(self) -> None:
        stub = _Stub(decode_payload(_sealed_cbor(os.urandom(32))))
        assert pyrxd.get_unlock_remaining(stub, current_block=_UNLOCK_AT - 10) == 10
        assert pyrxd.get_unlock_remaining(stub, current_block=_UNLOCK_AT + 50) == 0

    def test_it_FAILS_CLOSED_when_the_caller_supplies_no_chain_view(self) -> None:
        """A block-mode lock cannot be judged without a tip. Answering "unlocked" there would be a
        guess, and the guess that costs something is the optimistic one."""
        stub = _Stub(decode_payload(_sealed_cbor(os.urandom(32))))
        assert pyrxd.is_unlocked(stub) is False
        assert pyrxd.is_unlocked(stub, current_time=2**40) is False, "a TIME clock cannot judge a BLOCK lock"

    def test_the_cek_commitment_is_checkable_before_trusting_a_revealed_key(self) -> None:
        """The reason `verify_cek_reveal` is exported with the other two: a CEK published on-chain
        is supplied by someone else, and the commitment is what makes it safe to use."""
        cek = os.urandom(32)
        m = decode_payload(_sealed_cbor(cek))
        assert pyrxd.verify_cek_reveal(cek, m.timelock.cek_hash) is True
        assert pyrxd.verify_cek_reveal(os.urandom(32), m.timelock.cek_hash) is False


class TestTheInspectSurfaceSaysWHENItOpens:
    def test_the_payload_carries_the_spec(self) -> None:
        """`classification` already said "timelock". This is the field that answers the question a
        holder is actually asking."""
        from pyrxd.glyph._inspect_core import _sanitize_display_string  # noqa: F401  (import guard)

        m = decode_payload(_sealed_cbor(os.urandom(32), hint="drops at 500k"))
        assert m.timelock is not None and m.timelock.hint == "drops at 500k"

    def test_no_unlocked_verdict_is_emitted_without_a_chain_view(self) -> None:
        """The renderer is handed a payload, not a node. Printing locked/unlocked off this
        process's wall clock would be a guess presented as a fact — and for mode="block" it would
        be meaningless. The CLI states the unlock height and names the helpers instead."""
        import inspect as _inspect

        from pyrxd.cli import glyph_inspect

        src = _inspect.getsource(glyph_inspect)
        assert "timelock: opens at" in src
        assert "is_unlocked" in src, "the human output should name the helper that answers it"


class TestOnlyTheGuardedRevealDoorIsExported:
    """This class used to assert the whole write side was absent from `pyrxd.__all__`, because it
    was unwired: it published a CEK on-chain with no production caller and no real-value run, and
    exporting a workflow nothing reaches would have restated #556 rather than closing it.

    THE MAINTAINER DECIDED TO WIRE IT (#556, 2026-09-01), so that assertion is gone — kept as this
    paragraph rather than deleted, because a pinning test removed without a replacement is how a
    reasoned decision disappears. `build_timelock_mint`, `plan_timelock_reveal`,
    `parse_reveal_proof_script` and `validate_reveal_proof` are now exported and reached from
    `GlyphClient` and two CLI commands; `tests/test_glyph_timelock_write_side_is_reachable.py`
    proves the reaching.

    WHAT SURVIVES IS THE NARROWER DECISION, and it is the part with teeth. `create_reveal_proof`
    stays unexported. It builds a publishable OP_RETURN from a CEK and a token ref alone and is
    never handed the token, so it cannot check the key against the on-chain commitment and cannot
    know whether the lock has expired — and both of those mistakes are permanent. Publishing the
    wrong key spends the reveal and leaves the payload unreadable forever; publishing the right key
    early destroys the timelock for everyone. `plan_timelock_reveal` is the same capability with
    both checks inside it, so exporting the unguarded door beside the guarded one would hand
    callers a footgun with a shorter name.
    """

    def test_the_unchecked_proof_builder_is_not_exported(self) -> None:
        assert "create_reveal_proof" not in pyrxd.__all__, (
            "create_reveal_proof cannot see the token, so it cannot check the CEK against the "
            "on-chain commitment or refuse an early reveal — and both mistakes are permanent. "
            "Export pyrxd.plan_timelock_reveal instead; it is the same capability with both "
            "checks inside it."
        )

    @pytest.mark.parametrize(
        "name",
        ["build_timelock_mint", "plan_timelock_reveal", "parse_reveal_proof_script", "validate_reveal_proof"],
    )
    def test_the_guarded_write_side_IS_exported(self, name: str) -> None:
        """The honest-path half of the pair above: refusing the unchecked builder is only right if
        the checked one is actually available. A test that asserted the absence and not the
        presence would pass just as well with the whole feature deleted."""
        assert name in pyrxd.__all__, f"{name} is the wired write side of #556 and must stay exported"
