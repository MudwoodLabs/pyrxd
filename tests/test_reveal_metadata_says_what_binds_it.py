"""The metadata shown for a transaction need not be the metadata its commit committed to.

A commit output's locking script carries ``sha256d(envelope CBOR)`` as ``payload_hash``.
``GlyphInspector.find_reveal_metadata`` takes the FIRST ``gly`` push in the FIRST input that
decodes, so given inputs ``[decoy, real]`` the decoy wins:

    inputs = [decoy, real]  -> attributed input 0, name='EVIL'
    inputs = [real, decoy]  -> attributed input 0, name='real-token'

Whichever is first. The inspect classifier's headline now prefers the first payload whose
input's outpoint the outputs mint (#743 round 2), so a decoy that mints nothing no longer heads
a transaction that mints something. ``metadata.payload_binding`` says what, if anything, binds
the payload shown — and, since the 0.25.0 panel, to WHAT:

* ``bound`` needs an NFT or FT commit (ref-type operand exactly ``OP_2``/``OP_1``) whose hash
  matches, AND the commit's outpoint among the transaction's OUTPUTS as the ref type that
  commit demands. It names those outputs, and claims nothing about any other.
* ``bound-no-token`` is a DAT commit: bound as data, describing no output.
* ``mismatch`` and ``commit-unsatisfied`` are transactions a node REJECTS — the commit's hash
  check or its ``OP_REFTYPE_OUTPUT`` check fails — so they are bytes that were never mined.
* ``not-a-commit`` says only that pyrxd does not recognise the spent script as a commit —
  NOT that nobody committed (a 65-byte mainnet DAT commit is unrecognised and does bind).
  ``unchecked`` establishes nothing.

TWO THINGS THE PANEL FOUND, AND WHY THE FIXTURES CHANGED.

1. ``bound`` used to be read off the hash alone, against a template that accepted ANY byte as
   the ref-type operand. A commit with ``OP_0`` there demands that its ref appear in NO output —
   it mints nothing — and is otherwise byte-for-byte a commit. Spent first, beside a real mint,
   it read ``bound`` for the decoy's name, on a transaction a node would accept.
2. Every fixture here spent an NFT commit from a reveal whose only output was ``OP_RETURN``. The
   commit demands a singleton output for its outpoint; no node accepts that spend. The
   "forged payload end to end" test likewise spent a commit with a payload of the wrong hash —
   also rejected. The tests passed while describing transactions that cannot exist. The honest
   fixtures below now MINT the token their commit demands, and the one test that still builds
   an unmineable transaction says that is what it models.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.glyph._inspect_core import _HUMAN_STRING_CAP, PAYLOAD_BINDING_WARNING_STATES, _payload_binding
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_dat_reveal_scriptsig_suffix, build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_dat_commit_locking_script,
    build_ft_locking_script,
    build_nft_locking_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_SIGPUB = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33
_P2PKH = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
#: Any txid: the unit tests below name an outpoint without building the transaction behind it.
_OUTPOINT_TXID = "ab" * 32


def _envelope(name: str, proto: GlyphProtocol = GlyphProtocol.NFT) -> tuple[bytes, bytes]:
    """(scriptSig suffix carrying the envelope, the raw CBOR it carries)."""
    cbor, _ = encode_payload(GlyphMetadata(protocol=[proto], name=name))
    suffix = (
        build_dat_reveal_scriptsig_suffix(cbor) if proto == GlyphProtocol.DAT else build_reveal_scriptsig_suffix(cbor)
    )
    return suffix, cbor


def _commit_for(cbor: bytes, *, is_nft: bool = True, delegate_ref: GlyphRef | None = None) -> bytes:
    return build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=is_nft, delegate_ref=delegate_ref)


def _with_reftype(script: bytes, operand: int) -> bytes:
    """The commit with its ref-type operand replaced. Offset 48 of the 75-byte core, located
    here by what precedes it (``OP_REFTYPE_OUTPUT``) rather than by trusting the offset."""
    out = bytearray(script)
    assert out[47] == 0xDA and out[48] in (0x51, 0x52), "the premise: a bare commit's operand is at 48"
    out[48] = operand
    return bytes(out)


def _nft_out(txid: str, vout: int = 0) -> bytes:
    return build_nft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=txid, vout=vout))


def _ft_out(txid: str, vout: int = 0) -> bytes:
    return build_ft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=txid, vout=vout))


def _bind(cbor: bytes | None, spent: bytes | None, outputs: list[bytes], txid: str = _OUTPOINT_TXID) -> dict:
    return _payload_binding(cbor, spent, f"{txid}:0", outputs)


# ---------------------------------------------------------------------------
# Attribution and selection — what the binding qualifies
# ---------------------------------------------------------------------------


def test_the_first_envelope_still_wins_which_is_why_the_binding_is_reported() -> None:
    """Pins the behaviour the binding exists to qualify — not a bug being fixed here.

    Refusing the earlier input would be a behaviour change on a vector nobody has
    demonstrated on a node, and would break honest multi-input reveals. Reporting is
    the honest move; this test exists so the reporting is not mistaken for prevention.
    """
    real, _ = _envelope("real-token")
    decoy, _ = _envelope("EVIL")
    inspector = GlyphInspector()

    first = inspector.find_reveal_metadata([decoy, real])
    assert first is not None and first[1].name == "EVIL", (
        "attribution no longer takes the first decodable envelope — if that changed "
        "deliberately, this test and the payload_binding report should be revisited together"
    )
    second = inspector.find_reveal_metadata([real, decoy])
    assert second is not None and second[1].name == "real-token"


class TestTheHashedPushIsTheDisplayedPush:
    """The hash must be over the payload actually shown, or it answers about something else.

    This used to be one test feeding a scriptSig with ONE ``gly`` push — where "the first push"
    and "the last push" are the same push, so reversing the selection in
    ``extract_reveal_cbor`` survived the whole suite (panel plant PB2). With two envelopes in
    one scriptSig the two rules pick different bytes, and only agreeing on the FIRST passes.
    """

    def _two_envelopes(self) -> tuple[bytes, bytes, bytes]:
        first_suffix, first = _envelope("first-push")
        second_suffix, second = _envelope("second-push")
        return _SIGPUB + first_suffix + second_suffix, first, second

    def test_the_hashed_bytes_and_the_shown_name_are_the_same_push(self) -> None:
        scriptsig, first, second = self._two_envelopes()
        inspector = GlyphInspector()
        hashed = inspector.extract_reveal_cbor(scriptsig)
        shown = inspector.extract_reveal_metadata(scriptsig)
        assert shown is not None and shown.name == "first-push"
        assert hashed == first, "the binding would hash a different push from the one displayed"
        assert hashed != second

    def test_a_commit_to_the_shown_push_binds_and_to_the_other_push_does_not(self) -> None:
        """The same property, through the verdict: which push is hashed decides the state."""
        scriptsig, first, second = self._two_envelopes()
        cbor = GlyphInspector().extract_reveal_cbor(scriptsig)
        outputs = [_nft_out(_OUTPOINT_TXID)]
        assert _bind(cbor, _commit_for(first), outputs)["state"] == "bound"
        assert _bind(cbor, _commit_for(second), outputs)["state"] == "mismatch"

    def test_a_single_push_still_selects_itself(self) -> None:
        """The honest neighbour: the ordinary one-envelope scriptSig."""
        suffix, cbor = _envelope("shared-selection")
        inspector = GlyphInspector()
        assert inspector.extract_reveal_cbor(suffix) == cbor
        metadata = inspector.extract_reveal_metadata(suffix)
        assert metadata is not None and metadata.name == "shared-selection"


# ---------------------------------------------------------------------------
# What each state requires
# ---------------------------------------------------------------------------


class TestBoundRequiresTheTokenTheCommitDemands:
    def test_an_nft_commit_whose_singleton_is_minted_reads_bound_and_names_the_output(self) -> None:
        _, cbor = _envelope("honest")
        verdict = _bind(cbor, _commit_for(cbor), [_P2PKH, _nft_out(_OUTPOINT_TXID)])
        assert verdict["state"] == "bound"
        assert verdict["commit"] == "nft"
        assert (verdict["first_ref_output"], verdict["ref_output_count"]) == (1, 1)
        assert "at output 1" in verdict["reason"] and "not every output" in verdict["reason"]

    def test_an_nft_commit_whose_singleton_is_NOT_minted_is_unsatisfied(self) -> None:
        """demo_pb's shape at unit level: the hash matches, the reveal creates nothing. A node
        rejects the spend (``OP_REFTYPE_OUTPUT OP_2 OP_NUMEQUALVERIFY``)."""
        _, cbor = _envelope("honest")
        verdict = _bind(cbor, _commit_for(cbor), [b"\x6a"])
        assert verdict["state"] == "commit-unsatisfied"
        assert "no output carries it" in verdict["reason"]
        assert "first_ref_output" not in verdict and "ref_output_count" not in verdict

    def test_a_ref_minted_under_ANOTHER_outpoint_does_not_count(self) -> None:
        _, cbor = _envelope("honest")
        assert _bind(cbor, _commit_for(cbor), [_nft_out("cd" * 32)])["state"] == "commit-unsatisfied"
        assert _payload_binding(cbor, _commit_for(cbor), f"{_OUTPOINT_TXID}:1", [_nft_out(_OUTPOINT_TXID, 0)])[
            "state"
        ] == ("commit-unsatisfied"), "vout 0 was minted, vout 1 was spent"

    def test_ref_bytes_inside_pushed_data_are_not_a_ref(self) -> None:
        """The walk is consensus's opcode walk, not a byte search: ``0xd8 <ref>`` sitting inside a
        push is data, and ``GetPushRefs`` files nothing for it."""
        _, cbor = _envelope("honest")
        wire = GlyphRef(txid=_OUTPOINT_TXID, vout=0).to_bytes()
        hidden = bytes([37]) + b"\xd8" + wire + b"\x75" + _P2PKH  # PUSH37 <d8 ref>, OP_DROP, P2PKH
        assert _bind(cbor, _commit_for(cbor), [hidden])["state"] == "commit-unsatisfied"

    def test_an_nft_commit_answered_by_a_NORMAL_ref_is_unsatisfied(self) -> None:
        _, cbor = _envelope("honest")
        verdict = _bind(cbor, _commit_for(cbor), [_ft_out(_OUTPOINT_TXID)])
        assert verdict["state"] == "commit-unsatisfied"
        assert "as a singleton in an output: it is only a normal ref" in verdict["reason"]

    def test_an_ft_commit_answered_by_a_normal_ref_reads_bound(self) -> None:
        _, cbor = _envelope("honest-ft", GlyphProtocol.FT)
        verdict = _bind(cbor, _commit_for(cbor, is_nft=False), [_ft_out(_OUTPOINT_TXID), _ft_out(_OUTPOINT_TXID)])
        assert verdict["state"] == "bound" and verdict["commit"] == "ft"
        assert (verdict["first_ref_output"], verdict["ref_output_count"]) == (0, 2)
        assert "at outputs 0, 1:" in verdict["reason"]

    def test_an_ft_commit_whose_ref_is_ALSO_a_singleton_is_unsatisfied(self) -> None:
        """``getRefTypeOutput`` answers 2 when any output holds the ref as a singleton, and an
        FT commit demands exactly 1."""
        _, cbor = _envelope("honest-ft", GlyphProtocol.FT)
        outputs = [_ft_out(_OUTPOINT_TXID), _nft_out(_OUTPOINT_TXID)]
        verdict = _bind(cbor, _commit_for(cbor, is_nft=False), outputs)
        assert verdict["state"] == "commit-unsatisfied"
        assert "as a normal ref in an output: it is a singleton" in verdict["reason"]

    def test_a_delegate_prefixed_nft_commit_binds_on_the_same_terms(self) -> None:
        _, cbor = _envelope("delegated")
        spent = _commit_for(cbor, delegate_ref=GlyphRef(txid="ef" * 32, vout=2))
        assert len(spent) == 131, "the premise: a 56-byte delegate prefix ahead of the commit"
        assert _bind(cbor, spent, [_nft_out(_OUTPOINT_TXID)])["state"] == "bound"
        assert _bind(cbor, spent, [b"\x6a"])["state"] == "commit-unsatisfied"

    def test_many_carrying_outputs_are_counted_not_listed(self) -> None:
        """An FT's ref can sit in every output. The verdict carries the first and the count — no
        list, so nothing grows with the transaction — and the reason names three."""
        _, cbor = _envelope("split", GlyphProtocol.FT)
        outputs = [_P2PKH] * 4 + [_ft_out(_OUTPOINT_TXID)] * 40
        verdict = _bind(cbor, _commit_for(cbor, is_nft=False), outputs)
        assert (verdict["first_ref_output"], verdict["ref_output_count"]) == (4, 40)
        assert "at outputs 4, 5, 6 and 37 more:" in verdict["reason"]
        assert not any(isinstance(v, list) for v in verdict.values())


class TestOnlyTheTwoRefTypesAreACommit:
    """C-L2: the template matched ANY byte as the ref-type operand."""

    def test_an_op0_commit_mints_nothing_and_is_not_a_commit(self) -> None:
        _, cbor = _envelope("Tether USD")
        decoy = _with_reftype(_commit_for(cbor), 0x00)
        # Whatever the outputs are — this is the "demands NO ref" commit.
        assert _bind(cbor, decoy, [b"\x6a"])["state"] == "not-a-commit"
        assert _bind(cbor, decoy, [_nft_out(_OUTPOINT_TXID)])["state"] == "not-a-commit"

    @pytest.mark.parametrize("operand", [b for b in range(256) if b not in (0x51, 0x52)])
    def test_every_other_operand_is_not_a_commit(self, operand: int) -> None:
        _, cbor = _envelope("x")
        assert _bind(cbor, _with_reftype(_commit_for(cbor), operand), [_nft_out(_OUTPOINT_TXID)])["state"] == (
            "not-a-commit"
        )

    def test_the_two_real_operands_still_are(self) -> None:
        """The honest neighbour of the sweep above."""
        _, cbor = _envelope("x")
        nft = _with_reftype(_commit_for(cbor), 0x52)
        ft = _with_reftype(_commit_for(cbor), 0x51)
        assert _bind(cbor, nft, [_nft_out(_OUTPOINT_TXID)])["state"] == "bound"
        assert _bind(cbor, ft, [_ft_out(_OUTPOINT_TXID)])["state"] == "bound"

    @pytest.mark.parametrize("delegated", [False, True], ids=["bare", "delegate-prefixed"])
    def test_the_template_itself_refuses_other_operands(self, delegated: bool) -> None:
        """``COMMIT_SCRIPT_RE`` — behind ``is_commit_script`` and the two public extractors — is
        the template, not only the binding's reading of it: an ``OP_0`` commit is not a commit to
        any of them, and the two real operands still are."""
        from pyrxd.glyph.script import (
            extract_owner_pkh_from_commit_script,
            extract_payload_hash_from_commit_script,
            is_commit_script,
        )
        from pyrxd.security.errors import ValidationError

        _, cbor = _envelope("x")
        prefix_len = 56 if delegated else 0
        delegate = GlyphRef(txid="ef" * 32, vout=0) if delegated else None
        honest = _commit_for(cbor, delegate_ref=delegate)
        decoy = honest[:prefix_len] + _with_reftype(honest[prefix_len:], 0x00)
        assert is_commit_script(honest.hex()) and extract_payload_hash_from_commit_script(honest) == hash256(cbor)
        assert not is_commit_script(decoy.hex())
        with pytest.raises(ValidationError):
            extract_payload_hash_from_commit_script(decoy)
        with pytest.raises(ValidationError):
            extract_owner_pkh_from_commit_script(decoy)


def test_the_builder_docstring_names_the_offset_the_builder_writes() -> None:
    """INFO from the panel: the docstring said the ref-type byte sits at "offset 54"; it is 48 (54
    is where the DELEGATE PREFIX's own ``OP_1`` sits). Prose is a claim; this evaluates it."""
    import re

    doc = build_commit_locking_script.__doc__ or ""
    (offset,) = {int(n) for n in re.findall(r"at offset (\d+)", doc)}
    for is_nft, operand in ((True, 0x52), (False, 0x51)):
        script = build_commit_locking_script(b"\x11" * 32, Hex20(b"\x22" * 20), is_nft=is_nft)
        assert script[offset] == operand and script[offset - 1] == 0xDA  # OP_REFTYPE_OUTPUT, then it


class TestADatCommitBindsData:
    """C-L3: an honest DAT reveal read ``not-a-commit`` — "no payload hash binds this envelope" —
    while the 70-byte DAT commit binds exactly that."""

    def test_an_honest_dat_commit_reads_bound_no_token(self) -> None:
        _, cbor = _envelope("my-data", GlyphProtocol.DAT)
        spent = build_dat_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)))
        verdict = _bind(cbor, spent, [_P2PKH])
        assert verdict["state"] == "bound-no-token"
        assert verdict["commit"] == "dat"
        assert "creates no token" in verdict["reason"]

    def test_a_dat_commit_to_another_payload_is_a_mismatch(self) -> None:
        _, cbor = _envelope("my-data", GlyphProtocol.DAT)
        _, other = _envelope("other-data", GlyphProtocol.DAT)
        spent = build_dat_commit_locking_script(hash256(other), Hex20(os.urandom(20)))
        assert _bind(cbor, spent, [_P2PKH])["state"] == "mismatch"

    def test_a_delegate_prefixed_dat_commit_binds_too(self) -> None:
        _, cbor = _envelope("my-data", GlyphProtocol.DAT)
        spent = build_dat_commit_locking_script(
            hash256(cbor), Hex20(os.urandom(20)), delegate_ref=GlyphRef(txid="ef" * 32, vout=0)
        )
        assert _bind(cbor, spent, [_P2PKH])["state"] == "bound-no-token"

    def test_a_dat_commit_is_never_read_as_bound_to_a_token(self) -> None:
        """A DAT commit mints nothing, so it is exactly what a decoy placed first would spend: its
        envelope may declare any protocol. Even with an NFT for its outpoint in the outputs, it is
        not ``bound`` — the commit demanded nothing, so nothing ties the payload to that output."""
        _, cbor = _envelope("Tether USD", GlyphProtocol.NFT)
        spent = build_dat_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)))
        assert _bind(cbor, spent, [_nft_out(_OUTPOINT_TXID)])["state"] == "bound-no-token"

    @pytest.mark.parametrize("delegated", [False, True], ids=["bare", "delegate-prefixed"])
    def test_photonics_dat_commit_spelled_from_its_builder_is_recognised(self, delegated: bool) -> None:
        """Photonic ``datCommitScript`` at ``becf41a7`` (``packages/lib/src/script.ts:351-378``),
        transcribed op by op here rather than taken from pyrxd's builder: ``OP_HASH256``
        ``<payloadHash>`` ``OP_EQUALVERIFY``, ``Buffer.from("dat")`` ``OP_EQUALVERIFY``,
        ``glyphMagicBytesBuffer`` ``OP_EQUALVERIFY``, ``buildPublicKeyHashOut``; with a delegate,
        ``addDelegateRefScript`` first (``:267-279``). The only DAT form either builder emits."""
        _, cbor = _envelope("data", GlyphProtocol.DAT)
        pkh = os.urandom(20)
        body = (
            b"\xaa" + b"\x20" + hash256(cbor) + b"\x88"  # OP_HASH256 <payloadHash> OP_EQUALVERIFY
            + b"\x03dat" + b"\x88"  # "dat" OP_EQUALVERIFY
            + b"\x03gly" + b"\x88"  # glyphMagicBytesBuffer OP_EQUALVERIFY
            + b"\x76\xa9\x14" + pkh + b"\x88\xac"  # P2PKH
        )  # fmt: skip
        if delegated:
            ref = GlyphRef(txid="ef" * 32, vout=3).to_bytes()
            # OP_PUSHINPUTREF <ref> OP_DUP OP_REFOUTPUTCOUNT_OUTPUTS OP_0 OP_NUMEQUALVERIFY
            # d1 OP_SWAP 6a0364656c OP_CAT OP_CAT OP_HASH256 OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS OP_1 OP_NUMEQUALVERIFY
            body = b"\xd0" + ref + b"\x76\xde\x00\x9d" + b"\x01\xd1\x7c\x05\x6a\x03del\x7e\x7e\xaa\xe6\x51\x9d" + body
        assert len(body) == (126 if delegated else 70)
        verdict = _bind(cbor, body, [_P2PKH])
        assert (verdict["state"], verdict["commit"]) == ("bound-no-token", "dat")

    def test_the_65_byte_mainnet_dat_commit_is_unrecognised_and_says_only_that(self) -> None:
        """#743 round 2, L1. A real DAT reveal (``e5c67100…be5d``, block 449835) spends a 65-byte
        commit — ``OP_HASH256 <h> OP_EQUALVERIFY "gly" OP_EQUALVERIFY`` + P2PKH, no ``"dat"`` push —
        that neither Photonic's builder nor pyrxd's emits, and whose ``h`` IS the envelope's
        ``sha256d``. It stays unrecognised (the templates are the builders', not inferred from a
        sample), and the verdict says exactly that. It used to add "so nothing here shows that
        anyone committed to this envelope", which this transaction makes false.

        Through the real ``--fetch`` path, with the mainnet bytes."""
        import json
        from pathlib import Path

        from pyrxd.cli.glyph_inspect import _inspect_txid_inner

        pair = json.loads(
            (Path(__file__).resolve().parent / "fixtures" / "dat_65_byte_commit_mainnet.json").read_text()
        )
        commit, reveal = pair["commit"], pair["reveal"]
        craw, rraw = bytes.fromhex(commit["raw"]), bytes.fromhex(reveal["raw"])
        assert hash256(craw)[::-1].hex() == commit["txid"] and hash256(rraw)[::-1].hex() == reveal["txid"]
        # The premises, from the bytes: a 65-byte hash-lock whose hash is the envelope's.
        spent = bytes(Transaction.from_hex(craw).outputs[0].locking_script.serialize())
        assert len(spent) == 65 and spent[:2] == b"\xaa\x20" and spent[34:40] == b"\x88\x03gly\x88"
        envelope = GlyphInspector().extract_reveal_cbor(
            bytes(Transaction.from_hex(rraw).inputs[0].unlocking_script.serialize())
        )
        assert spent[2:34] == hash256(envelope), "the commit DID commit to this envelope"

        client = _StubElectrumX({commit["txid"]: craw, reveal["txid"]: rraw})
        payload = asyncio.run(_inspect_txid_inner(client, reveal["txid"]))
        metadata = payload["metadata"]
        assert commit["txid"] in client.requested
        assert (metadata["classification"], metadata["mints"]) == ("dat", False)
        assert metadata["payload_binding"] == {
            "state": "not-a-commit",
            "reason": "the output the attributed input spent is not a commit template pyrxd recognises",
        }


def test_a_commit_that_committed_to_a_DIFFERENT_payload_reads_mismatch() -> None:
    """Not "unverified" — demonstrably not this payload, so never a transaction a node accepted."""
    _, shown = _envelope("EVIL")
    _, committed = _envelope("real-token")
    verdict = _bind(shown, _commit_for(committed), [_nft_out(_OUTPOINT_TXID)])
    assert verdict["state"] == "mismatch"
    assert "DIFFERENT PAYLOAD" in verdict["reason"] and "A node rejects that spend" in verdict["reason"]


def test_an_input_that_spent_something_other_than_a_commit_says_so() -> None:
    """Distinct from `unchecked`: the spent script is here and pyrxd does not recognise it — and
    that is ALL the reason says. It used to add "so nothing here shows that anyone committed to
    this envelope", which is false for the 65-byte mainnet DAT commit below."""
    _, cbor = _envelope("x")
    verdict = _bind(cbor, _P2PKH, [_nft_out(_OUTPOINT_TXID)])
    assert verdict == {
        "state": "not-a-commit",
        "reason": "the output the attributed input spent is not a commit template pyrxd recognises",
    }


def test_no_spent_script_reads_unchecked_and_never_bound() -> None:
    """The honest degradation. The classifier is network-free; absence of evidence must
    not render as evidence of binding."""
    _, cbor = _envelope("x")
    verdict = _bind(cbor, None, [_nft_out(_OUTPOINT_TXID)])
    assert verdict["state"] == "unchecked"
    assert "not supplied" in verdict["reason"]


def _one_of_each_state() -> dict[str, dict]:
    _, cbor = _envelope("x")
    _, other = _envelope("y")
    _, dat = _envelope("d", GlyphProtocol.DAT)
    minted = [_nft_out(_OUTPOINT_TXID)]
    # The widest `where` a bound reason can carry under the output cap: three five-digit indices
    # and a six-character count of the rest ("outputs 10000, 10001, 10002 and 89,997 more").
    from pyrxd.glyph._inspect_core import _MAX_OUTPUT_COUNT

    assert _MAX_OUTPUT_COUNT == 100_000, "the cap moved; recompute the widest case"
    wide = [b"\x6a"] * 10_000 + [_ft_out(_OUTPOINT_TXID)] * (_MAX_OUTPUT_COUNT - 10_000)
    _, ft_cbor = _envelope("f", GlyphProtocol.FT)
    return {
        "unchecked": _bind(cbor, None, minted),
        "not-a-commit": _bind(cbor, _P2PKH, minted),
        "bound": _bind(cbor, _commit_for(cbor), minted),
        "bound (widest)": _bind(ft_cbor, _commit_for(ft_cbor, is_nft=False), wide),
        "bound-no-token": _bind(dat, build_dat_commit_locking_script(hash256(dat), Hex20(os.urandom(20))), minted),
        "mismatch": _bind(cbor, _commit_for(other), minted),
        "commit-unsatisfied": _bind(cbor, _commit_for(cbor), [b"\x6a"]),
        "commit-unsatisfied (normal)": _bind(cbor, _commit_for(cbor), [_ft_out(_OUTPOINT_TXID)]),
        "commit-unsatisfied (singleton)": _bind(
            ft_cbor, _commit_for(ft_cbor, is_nft=False), [_nft_out(_OUTPOINT_TXID), _ft_out(_OUTPOINT_TXID)]
        ),
    }


def test_every_state_is_distinct_so_none_can_be_read_as_another() -> None:
    """Non-vacuity. If two states collapsed to one string, a renderer showing it would be
    telling the reader something weaker or stronger than what was established."""
    states = {v["state"] for v in _one_of_each_state().values()}
    assert states == {"unchecked", "not-a-commit", "bound", "bound-no-token", "mismatch", "commit-unsatisfied"}
    assert states > PAYLOAD_BINDING_WARNING_STATES, "a warning state no input here produces"


def test_every_reason_fits_the_page_whole() -> None:
    """The page caps every string at ``_HUMAN_STRING_CAP`` and adds an ellipsis. A reason cut
    there loses its LAST clause — which, on the two warning states, is the instruction to treat
    the metadata as unattributed. So each must fit whole, including the widest bound one."""
    for name, verdict in _one_of_each_state().items():
        assert len(verdict["reason"]) <= _HUMAN_STRING_CAP, (name, len(verdict["reason"]), verdict["reason"])


# ---------------------------------------------------------------------------
# Through the production entry point
# ---------------------------------------------------------------------------
#
# The tests above build the input by hand, which proves the MECHANISM. They do not
# prove anyone can reach it: `_payload_binding` reads `unchecked` unless a caller
# supplies the spent script, and when this was written NO caller did — the check
# existed, passed its own tests, and was invisible in every real run.
#
# `_inspect_txid_inner` is the real `glyph inspect --fetch` path. These drive it.


class _StubElectrumX:
    """Returns canned raw transactions by txid, and records what was asked for."""

    def __init__(self, by_txid: dict[str, bytes]) -> None:
        self._by_txid = by_txid
        self.requested: list[str] = []

    async def get_transaction(self, txid):
        self.requested.append(str(txid))
        try:
            return self._by_txid[str(txid)]
        except KeyError:
            raise TimeoutError(f"stub has no {txid}") from None


def _prev(script: bytes, value: int = 1000) -> Transaction:
    """A transaction whose output 0 is *script*. Its own input makes each txid distinct."""
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(script), value)])
    funding = TransactionInput(source_txid=os.urandom(32).hex(), source_output_index=0)
    funding.unlocking_script = Script(b"\x00")
    tx.inputs = [funding]
    return tx


def _spend(prev: Transaction, suffix: bytes) -> TransactionInput:
    inp = TransactionInput(source_txid=prev.txid(), source_output_index=0)
    inp.unlocking_script = Script(_SIGPUB + suffix)
    return inp


def _reveal(inputs: list[TransactionInput], outputs: list[bytes]) -> Transaction:
    tx = Transaction(
        tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), 1 if s[:1] != b"\x6a" else 0) for s in outputs]
    )
    tx.inputs = inputs
    return tx


def _run_cli_fetch(prevs: list[Transaction], reveal: Transaction) -> tuple[dict, _StubElectrumX]:
    from pyrxd.cli.glyph_inspect import _inspect_txid_inner

    client = _StubElectrumX({t.txid(): t.serialize() for t in [*prevs, reveal]})
    return asyncio.run(_inspect_txid_inner(client, reveal.txid())), client


def _commit_and_reveal(shown: str, committed: str | None = None, *, mint: bool = True):
    """A reveal spending a real NFT commit output. With ``mint`` (the default) it creates the
    singleton that commit demands — the only shape a node accepts. ``committed`` differing from
    ``shown`` is a spend a node rejects; see the test that uses it."""
    suffix, cbor = _envelope(shown)
    _, committed_cbor = _envelope(committed) if committed is not None else (None, cbor)
    commit_tx = _prev(_commit_for(committed_cbor))
    outputs = [_nft_out(commit_tx.txid())] if mint else [b"\x6a"]
    return commit_tx, _reveal([_spend(commit_tx, suffix)], outputs)


def test_the_cli_fetch_path_resolves_the_binding_end_to_end() -> None:
    """The reachability test. Everything above passes with zero production callers."""
    commit_tx, reveal_tx = _commit_and_reveal("honest")
    payload, client = _run_cli_fetch([commit_tx], reveal_tx)

    assert commit_tx.txid() in client.requested, (
        "the fetch path never asked for the spent output, so `payload_binding` can only "
        "read `unchecked` in production no matter how well the helper works"
    )
    metadata = payload["metadata"]
    assert metadata["input_outpoint"] == f"{commit_tx.txid()}:0"
    assert metadata["payload_binding"]["state"] == "bound"
    assert metadata["payload_binding"]["first_ref_output"] == 0


def test_a_reveal_no_node_would_accept_reads_mismatch_end_to_end() -> None:
    """WHAT THIS MODELS: NOT A MINED TRANSACTION, AND IT CANNOT BE ONE.

    The shown payload hashes to something other than the commit's ``payload_hash``, so the
    commit's ``OP_HASH256 <payload_hash> OP_EQUALVERIFY`` fails and a node rejects the spend.
    This used to be called "the forged payload end to end" as though it were the attack; the
    attack a node accepts is the decoy below. What this models is bytes that were never mined —
    pasted raw, or served for a txid no block contains — and ``mismatch`` says exactly that.

    Everything else about it is valid: it mints the singleton its commit demands, so the ONE
    thing wrong with it is the hash, and the verdict is the hash's.
    """
    commit_tx, reveal_tx = _commit_and_reveal("EVIL", committed="real-token")
    payload, _client = _run_cli_fetch([commit_tx], reveal_tx)
    assert payload["metadata"]["name"] == "EVIL", "the unattributed payload is still what gets displayed"
    binding = payload["metadata"]["payload_binding"]
    assert binding["state"] == "mismatch"
    assert binding["state"] in PAYLOAD_BINDING_WARNING_STATES


class TestTheDecoyThatANodeAccepts:
    """C-L2 / H-M2 through the real ``--fetch`` path. Each reveal below is one a node ACCEPTS
    (given signatures): every commit it spends is satisfied by its outputs."""

    def test_an_op0_decoy_placed_first_is_no_longer_the_headline(self) -> None:
        """The panel's probe, and #743 round 2's case G. The decoy commit demands its ref in NO
        output, and gets that; the real commit gets its singleton; a node accepts it and exactly
        one glyph is minted. Before: headline "Tether USD", ``bound`` (round 1: ``not-a-commit``,
        still the headline, and "1 of 2 glyphs minted here")."""
        real_suffix, real_cbor = _envelope("RealToken")
        decoy_suffix, decoy_cbor = _envelope("Tether USD")
        decoy_commit = _prev(_with_reftype(_commit_for(decoy_cbor), 0x00))
        real_commit = _prev(_commit_for(real_cbor))
        reveal = _reveal(
            [_spend(decoy_commit, decoy_suffix), _spend(real_commit, real_suffix)],
            [_nft_out(real_commit.txid())],
        )
        payload, client = _run_cli_fetch([decoy_commit, real_commit], reveal)
        metadata = payload["metadata"]
        assert real_commit.txid() in client.requested and decoy_commit.txid() not in client.requested
        assert metadata["input_index"] == 1 and metadata["name"] == "RealToken" and metadata["mints"] is True
        assert metadata["payload_binding"]["state"] == "bound"
        assert (metadata["of_n_payloads"], metadata["of_n_minted"]) == (2, 1), "one glyph is minted, not two"
        decoy = next(row for row in payload["metadata_inputs"] if row["input_index"] == 0)
        assert (decoy["name"], decoy["mints"]) == ("Tether USD", False)

    def test_the_op0_decoy_alone_is_the_headline_and_says_it_mints_nothing(self) -> None:
        """The other branch: no payload mints, so the first one stays the headline — flagged as
        minting nothing, and `not-a-commit`, whose reason no longer says nobody committed."""
        decoy_suffix, decoy_cbor = _envelope("Tether USD")
        decoy_commit = _prev(_with_reftype(_commit_for(decoy_cbor), 0x00))
        reveal = _reveal([_spend(decoy_commit, decoy_suffix)], [_P2PKH])
        payload, _client = _run_cli_fetch([decoy_commit], reveal)
        metadata = payload["metadata"]
        assert (metadata["input_index"], metadata["name"], metadata["mints"]) == (0, "Tether USD", False)
        assert metadata["payload_binding"]["state"] == "not-a-commit"

    def test_a_dat_commit_decoy_placed_first_is_not_the_headline_either(self) -> None:
        """The same decoy built from a LEGITIMATE template: a DAT commit mints nothing either, so
        the minted token is the headline and the DAT payload is listed as minting nothing."""
        real_suffix, real_cbor = _envelope("RealToken")
        _, decoy_cbor = _envelope("Tether USD")  # an NFT-protocol envelope...
        decoy_commit = _prev(build_dat_commit_locking_script(hash256(decoy_cbor), Hex20(os.urandom(20))))
        real_commit = _prev(_commit_for(real_cbor))
        reveal = _reveal(
            [_spend(decoy_commit, build_dat_reveal_scriptsig_suffix(decoy_cbor)), _spend(real_commit, real_suffix)],
            [_nft_out(real_commit.txid())],
        )
        payload, _client = _run_cli_fetch([decoy_commit, real_commit], reveal)
        metadata = payload["metadata"]
        assert (metadata["input_index"], metadata["name"]) == (1, "RealToken")
        assert metadata["payload_binding"]["state"] == "bound"
        decoy = next(row for row in payload["metadata_inputs"] if row["input_index"] == 0)
        assert (decoy["name"], decoy["classification"], decoy["mints"]) == ("Tether USD", "nft", False)

    def test_a_dat_commit_spent_alone_reads_bound_no_token(self) -> None:
        """A DAT commit's binding is still read when its payload is the headline — when nothing
        in the transaction mints, whatever protocol the payload declares."""
        _, decoy_cbor = _envelope("Tether USD")
        decoy_commit = _prev(build_dat_commit_locking_script(hash256(decoy_cbor), Hex20(os.urandom(20))))
        reveal = _reveal([_spend(decoy_commit, build_dat_reveal_scriptsig_suffix(decoy_cbor))], [_P2PKH])
        payload, _client = _run_cli_fetch([decoy_commit], reveal)
        metadata = payload["metadata"]
        assert metadata["classification"] == "nft" and metadata["mints"] is False
        assert metadata["payload_binding"]["state"] == "bound-no-token"

    @pytest.mark.parametrize(
        "decoy_named",
        ["by OP_REQUIREINPUTREF", "inside pushed data"],
    )
    def test_naming_the_decoys_outpoint_without_pushing_it_is_not_a_mint(self, decoy_named: str) -> None:
        """What counts as minted is what consensus counts: an ``OP_PUSHINPUTREF`` /
        ``OP_PUSHINPUTREFSINGLETON`` found by the opcode walk. The decoy's outpoint appears in the
        same output as the real singleton — as a requirement (``0xd1``), or as ``0xd8 <ref>`` bytes
        inside a push — and neither makes the decoy a glyph minted here."""
        real_suffix, real_cbor = _envelope("RealToken")
        decoy_suffix, decoy_cbor = _envelope("Tether USD")
        decoy_commit = _prev(_with_reftype(_commit_for(decoy_cbor), 0x00))
        real_commit = _prev(_commit_for(real_cbor))
        decoy_wire = GlyphRef(txid=decoy_commit.txid(), vout=0).to_bytes()
        named = (
            b"\xd1" + decoy_wire + b"\x75"
            if decoy_named.startswith("by")
            else bytes([37]) + b"\xd8" + decoy_wire + b"\x75"
        )
        reveal = _reveal(
            [_spend(decoy_commit, decoy_suffix), _spend(real_commit, real_suffix)],
            [named + _nft_out(real_commit.txid())],
        )
        payload, _client = _run_cli_fetch([decoy_commit, real_commit], reveal)
        metadata = payload["metadata"]
        assert (metadata["input_index"], metadata["name"]) == (1, "RealToken")
        assert (metadata["of_n_payloads"], metadata["of_n_minted"]) == (2, 1)

    def test_the_documented_decoy_first_vector_names_only_its_own_output(self) -> None:
        """The module's own vector, H-M2's demo: the decoy input first, spending ITS OWN honest
        NFT commit. A node accepts that only if the decoy's singleton is minted too — so the
        transaction mints TWO tokens, and the decoy IS one of them. That cannot be told apart
        from an honest two-token mint, so ``bound`` stays — with its claim cut to size: it names
        the decoy's output, and not the real token's."""
        evil_suffix, evil_cbor = _envelope("EVIL")
        real_suffix, real_cbor = _envelope("real-token")
        c_evil, c_real = _prev(_commit_for(evil_cbor)), _prev(_commit_for(real_cbor))
        reveal = _reveal(
            [_spend(c_evil, evil_suffix), _spend(c_real, real_suffix)],
            [_nft_out(c_real.txid()), _nft_out(c_evil.txid())],
        )
        payload, _client = _run_cli_fetch([c_evil, c_real], reveal)
        metadata = payload["metadata"]
        assert metadata["name"] == "EVIL" and metadata["input_index"] == 0
        binding = metadata["payload_binding"]
        assert binding["state"] == "bound"
        assert (binding["first_ref_output"], binding["ref_output_count"]) == (1, 1), (
            "the binding must name the decoy's token, not output 0"
        )
        assert "at output 1" in binding["reason"] and "not every output" in binding["reason"]
        assert metadata["of_n_payloads"] == 2, "and the header says another glyph is minted here"

    def test_the_documented_vector_exactly_as_demonstrated_is_unsatisfied(self) -> None:
        """demo_pb.py verbatim: two honest commits, and a reveal whose only output is OP_RETURN.
        It printed ``bound``. Neither commit is satisfied, so no node accepts it."""
        evil_suffix, evil_cbor = _envelope("EVIL")
        real_suffix, real_cbor = _envelope("real-token")
        c_evil, c_real = _prev(_commit_for(evil_cbor)), _prev(_commit_for(real_cbor))
        reveal = _reveal([_spend(c_evil, evil_suffix), _spend(c_real, real_suffix)], [b"\x6a"])
        payload, _client = _run_cli_fetch([c_evil, c_real], reveal)
        binding = payload["metadata"]["payload_binding"]
        assert binding["state"] == "commit-unsatisfied"
        assert binding["state"] in PAYLOAD_BINDING_WARNING_STATES


class TestAGuardThatRefusesValidWorkIsABug:
    """The honest path against a commit and a reveal that ARE on chain — the GLYPH Protocol dMint
    deploy, whose reveal mints one FT across 32 dMint contracts from input 0 and one NFT from
    input 33. Every fixture above was built to agree with the code; these bytes were not."""

    @staticmethod
    def _chain() -> tuple[dict, dict]:
        import json
        from pathlib import Path

        fixtures = Path(__file__).resolve().parent / "fixtures"
        reveal = json.loads((fixtures / "glyph_deploy_reveal_mainnet.json").read_text(encoding="utf-8"))
        commit = json.loads((fixtures / "glyph_deploy_commit_mainnet.json").read_text(encoding="utf-8"))
        for tx in (reveal, commit):
            assert hash256(bytes.fromhex(tx["raw"]))[::-1].hex() == tx["txid"], "a fixture is not the tx it names"
        return reveal, commit

    def test_the_mainnet_deploy_reads_bound_through_both_paths(self) -> None:
        from pyrxd.glyph._inspect_core import _classify_raw_tx, _spent_output_binding, _spent_script

        reveal, commit = self._chain()
        raw, commit_raw = bytes.fromhex(reveal["raw"]), bytes.fromhex(commit["raw"])
        fetched = _spent_output_binding(reveal["txid"], raw, commit_raw)
        spent = _spent_script(f"{commit['txid']}:0", commit_raw)
        full = _classify_raw_tx(reveal["txid"], raw, spent_scripts={0: spent})["metadata"]["payload_binding"]
        assert fetched == full
        assert fetched["state"] == "bound" and fetched["commit"] == "ft"
        assert (fetched["first_ref_output"], fetched["ref_output_count"]) == (0, 32), (
            "the 32 dMint contracts carry the token ref"
        )

    def test_its_second_glyph_is_bound_to_its_own_singleton_only(self) -> None:
        """Input 33 is not the attributed one, so no surface shows its binding; asked directly, it
        names output 32 — the singleton its NFT commit demanded — and not the 32 FT outputs."""
        reveal, commit = self._chain()
        rtx = Transaction.from_hex(bytes.fromhex(reveal["raw"]))
        ctx = Transaction.from_hex(bytes.fromhex(commit["raw"]))
        inp = rtx.inputs[33]
        assert (inp.source_txid, inp.source_output_index) == (commit["txid"], 33)
        cbor = GlyphInspector().extract_reveal_cbor(bytes(inp.unlocking_script.serialize()))
        spent = bytes(ctx.outputs[33].locking_script.serialize())
        outputs = [bytes(o.locking_script.serialize()) for o in rtx.outputs]
        verdict = _payload_binding(cbor, spent, f"{commit['txid']}:33", outputs)
        assert verdict["state"] == "bound" and verdict["commit"] == "nft"
        assert (verdict["first_ref_output"], verdict["ref_output_count"]) == (32, 1)


def test_an_honest_dat_mint_built_by_pyrxd_reads_bound_no_token_end_to_end() -> None:
    """C-L3's proof, with pyrxd's own DAT builders from commit to reveal."""
    from pyrxd.glyph.builder import CommitParams, GlyphBuilder

    builder = GlyphBuilder()
    pkh = Hex20(os.urandom(20))
    commit = builder.prepare_dat_commit(
        CommitParams(
            metadata=GlyphMetadata(protocol=[GlyphProtocol.DAT], name="my-data"),
            owner_pkh=pkh,
            change_pkh=pkh,
            funding_satoshis=100_000,
        )
    )
    commit_tx = _prev(commit.commit_script)
    scripts = builder.prepare_dat_reveal(commit.cbor_bytes)
    reveal = _reveal([_spend(commit_tx, scripts.scriptsig_suffix)], [_P2PKH])
    payload, _client = _run_cli_fetch([commit_tx], reveal)
    assert payload["metadata"]["name"] == "my-data"
    assert payload["metadata"]["payload_binding"]["state"] == "bound-no-token"


def test_an_unfetchable_prevout_leaves_it_unchecked_not_crashed() -> None:
    """Same contract as the delegate block: a failed resolution never fails the inspect.

    And it must degrade to `unchecked` — NEVER to `bound`. An unreachable server is
    the case where a reassuring default would be worst.
    """
    _commit_tx, reveal_tx = _commit_and_reveal("honest")
    payload, _client = _run_cli_fetch([], reveal_tx)  # commit absent

    assert payload["metadata"]["payload_binding"]["state"] == "unchecked"
    assert payload["metadata"]["name"] == "honest", "the rest of the report is still true"


def test_the_honest_path_is_not_refused_anywhere() -> None:
    """A guard that refuses valid work is a bug. Nothing here may block an honest
    reveal — the verdict is a report, and the report is the entire behaviour change."""
    commit_tx, reveal_tx = _commit_and_reveal("perfectly-fine")
    payload, _client = _run_cli_fetch([commit_tx], reveal_tx)
    assert payload["metadata"]["name"] == "perfectly-fine"
    assert payload["metadata"]["payload_binding"]["state"] == "bound"
    assert payload["outputs"] is not None


def test_the_cli_flags_both_warning_states_and_nothing_else() -> None:
    """The human renderer marks a warning state with ``***``. It used to test ``== "mismatch"``;
    ``commit-unsatisfied`` is the same kind of fact and must be as loud."""
    from pyrxd.cli.glyph_inspect import _render_txid_human

    marked: dict[str, bool] = {}
    for shown, committed, mint in (("a", None, True), ("a", "b", True), ("a", None, False)):
        commit_tx, reveal_tx = _commit_and_reveal(shown, committed, mint=mint)
        payload, _client = _run_cli_fetch([commit_tx], reveal_tx)
        state = payload["metadata"]["payload_binding"]["state"]
        line = next(x for x in _render_txid_human(payload).splitlines() if "payload_binding=" in x)
        marked[state] = line.startswith("  *** ")
    assert marked == {"bound": False, "mismatch": True, "commit-unsatisfied": True}
