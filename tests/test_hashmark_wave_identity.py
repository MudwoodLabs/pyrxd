"""The key -> name bridge, and the two gates in front of it.

A HashMark v2 signer is a hash160, which is what a P2PKH address encodes, and
WAVE resolves names to addresses.

THIS DOCSTRING USED TO SAY the bridge answers "was this recorded by the holder of
`company.rxd`?" — and that is precisely the question it CANNOT answer. HashMark
§7.6 spells out why: a name resolves to whatever it points at NOW, and a mark was
made at a past block, so a present-tense lookup applied to a past event is wrong in
both directions the moment a name changes hands. A genuine mark by the previous
holder starts failing; and whoever picks up a lapsed name — cheap and ordinary,
since Radiant names have terms — can make NEW marks that truthfully verify as
"signed by whoever owns company.rxd", which a reader hears as "the company made
this". The timestamp is honest; the identity inference is not.

What the bridge answers is narrower and still useful: *which names resolve to this
key right now.* Present tense, stated separately from the mark, never folded into
its verdict.

Two gates, then:

* the SIGNATURE gate, tested below — resolving an unverified signer would dress a
  claim up as an identity, since anyone can put someone else's hash160 in a record;
* the TENSE gate, tested in `test_hashmark_attestation.py` — the result is named
  `names_resolving_now`, carries `point_in_time: False`, and is rendered after the
  mark's own statement closes rather than inside it.

The sound historical form needs point-in-time resolution against the mark's own
block, by verifying the chain of modification transactions rather than trusting an
index (§2.8). That is tracked separately, not approximated here.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.wave import wave_names_for_hash160
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError


class _FakeIndexer:
    """A fake at the REAL seam — the transport `RxinDexerClient` calls.

    `WaveResolver` wraps anything that is not already an `RxinDexerClient` in one,
    so faking `wave_reverse_lookup` would bypass the wrapper the production path
    actually goes through. Faking `call_extension` exercises it.
    """

    def __init__(self, names: dict[str, list[str]] | None = None) -> None:
        self.names = names or {}
        self.asked: list[str] = []

    async def call_extension(self, method: str, params: list):
        assert method == "wave.reverse_lookup", method
        address = params[0]
        self.asked.append(address)
        return self.names.get(address, [])


class TestTheKeyToNameBridge:
    @pytest.mark.asyncio
    async def test_it_looks_up_the_signers_own_address(self) -> None:
        """The join is hash160 -> address -> names, and the address must be the
        one the signing key actually encodes."""
        key = PrivateKey()
        addr = key.public_key().address()
        idx = _FakeIndexer({addr: ["company.rxd", "invoices.company.rxd"]})

        names = await wave_names_for_hash160(idx, key.public_key().hash160())

        assert idx.asked == [addr], "must derive the signer's own address"
        assert names == ["company.rxd", "invoices.company.rxd"]

    @pytest.mark.asyncio
    async def test_a_key_owning_no_name_returns_empty_not_an_error(self) -> None:
        """Most keys own no WAVE name. That is an answer, not a failure."""
        idx = _FakeIndexer()
        assert await wave_names_for_hash160(idx, PrivateKey().public_key().hash160()) == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", [b"", b"\x11" * 19, b"\x11" * 21])
    async def test_a_wrong_width_hash_is_refused(self, bad: bytes) -> None:
        with pytest.raises(ValidationError, match="20 bytes"):
            await wave_names_for_hash160(_FakeIndexer(), bad)


class TestTheGateInFrontOfIt:
    """`_attach_wave_identity` must never resolve an unproven signer."""

    @staticmethod
    def _payload(outcome: str | None) -> dict:
        hm: dict = {"version": 2, "signer_hash160": "aa" * 20}
        if outcome is not None:
            hm["attestation"] = {"outcome": outcome, "recovered_hash160": "aa" * 20}
        return {"hashmark": hm}

    @pytest.mark.parametrize(
        ("outcome", "expect"),
        [
            ("invalid_signature", "unproven signer"),
            ("not_attested", "no verified v2 signature"),
            (None, "no verified v2 signature"),
        ],
    )
    def test_an_unverified_signature_is_NOT_resolved(self, outcome, expect: str) -> None:
        """No network call, and a reason the operator can read."""
        from pyrxd.cli.glyph_inspect import _attach_wave_identity

        payload = self._payload(outcome)
        # ctx is never used on this path — reaching for it would mean the gate failed.
        _attach_wave_identity(None, payload)  # type: ignore[arg-type]

        wi = payload["hashmark"]["wave_identity"]
        assert wi["resolved"] is False
        assert expect in wi["reason"]

    def test_a_payload_with_no_hashmark_is_untouched(self) -> None:
        from pyrxd.cli.glyph_inspect import _attach_wave_identity

        payload: dict = {"type": "op_return"}
        _attach_wave_identity(None, payload)  # type: ignore[arg-type]
        assert payload == {"type": "op_return"}


class TestSection76TheTenseGate:
    """A name may be present-tense context; it may never become part of the mark.

    HashMark §7.6, added after this feature shipped. The rendering said:

        WAVE identity: company.rxd
          (the signing key owns these names — file matches the
           digest AND was recorded by that name's holder)

    which is the unsound form verbatim: a PAST-tense claim ("was recorded by that
    name's holder") manufactured from a PRESENT-tense lookup, printed inside the
    attestation block as though the mark carried it. Both halves are wrong — the
    tense, and the placement.

    §7.6 form 1 is two facts, separately sourced: the signer ADDRESS, which the mark
    really does carry, and the names resolving to it right now, which it does not.
    """

    HM = {
        "outcome": "ok",
        "version": 2,
        "algorithm": "sha256",
        "digest": "cd" * 32,
        "signer_hash160": "26ba056431ec69cf27eabeaab250d99ddbd895d2",
        "attestation": {
            "outcome": "valid",
            "assumed_network": "radiant-mainnet",
            "recovered_hash160": "26ba056431ec69cf27eabeaab250d99ddbd895d2",
            "signer_address": "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i",
        },
        "wave_identity": {
            "resolved": True,
            "names_resolving_now": ["company.rxd"],
            "point_in_time": False,
        },
    }

    def _render(self, **over) -> str:
        from pyrxd.cli.glyph_inspect import _op_return_payload_lines

        hm = {**self.HM, **over}
        return "\n".join(_op_return_payload_lines({"hashmark": hm}))

    def test_the_unsound_phrasing_is_GONE(self) -> None:
        text = self._render().lower()
        for banned in ("owns these names", "was recorded by that name's holder", "recorded by the holder"):
            assert banned not in text, f"the §7.6 phrasing {banned!r} is back"

    def test_the_present_tense_is_explicit(self) -> None:
        assert "RIGHT NOW" in self._render()

    def test_the_name_comes_AFTER_the_marks_own_statement_closes(self) -> None:
        """Placement is half the rule: "never beside the mark as though it were part
        of it". The mark's closing caveat must precede any name."""
        text = self._render()
        assert text.index("not authorship, ownership") < text.index("company.rxd")

    def test_the_name_is_labelled_as_separate_from_the_mark(self) -> None:
        assert "NOT part of the mark above" in self._render()

    def test_the_signer_ADDRESS_is_shown_with_the_signature(self) -> None:
        """The half of §7.6 form 1 that IS a property of the mark, and the form a
        human can compare against a wallet."""
        text = self._render()
        assert "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i" in text
        assert text.index("signature VERIFIED") < text.index("14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i")

    def test_a_mark_with_NO_name_still_renders_its_verdict(self) -> None:
        """The honest path. Nothing about the name may gate the mark's own result."""
        text = self._render(wave_identity={"resolved": True, "names_resolving_now": [], "point_in_time": False})
        assert "signature VERIFIED" in text and "no WAVE name resolves" in text

    def test_a_failed_lookup_says_why_and_does_not_swallow_the_verdict(self) -> None:
        text = self._render(wave_identity={"resolved": False, "reason": "lookup failed: timeout"})
        assert "signature VERIFIED" in text and "lookup failed: timeout" in text

    def test_the_JSON_field_cannot_be_read_as_HISTORICAL(self) -> None:
        """A consumer reaching for a bare `names` would make exactly the inference
        §7.6 forbids, so the field says when it was true and flags what it is not."""
        wi = self.HM["wave_identity"]
        assert "names" not in wi, "a bare `names` invites the unsound reading"
        assert wi["point_in_time"] is False

    def test_the_resolver_emits_that_shape(self) -> None:
        """Reachability: the contract above must be what production actually writes,
        not a shape only this test builds."""
        from pyrxd.cli import glyph_inspect
        from pyrxd.glyph import wave

        async def _names(_client, _hash160):
            return ["company.rxd"]

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        original = wave.wave_names_for_hash160
        wave.wave_names_for_hash160 = _names
        try:
            record = {"attestation": {"outcome": "valid", "recovered_hash160": "ab" * 20}}
            glyph_inspect._resolve_one_wave_identity(type("Ctx", (), {"make_client": lambda self: _Client()})(), record)
        finally:
            wave.wave_names_for_hash160 = original

        wi = record["wave_identity"]
        assert wi["names_resolving_now"] == ["company.rxd"]
        assert wi["point_in_time"] is False and "names" not in wi
        assert "present-tense" in wi["caveat"]
