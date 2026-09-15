"""The metadata shown for a transaction need not be the metadata its commit committed to.

A commit output's locking script carries ``sha256d(envelope CBOR)`` as ``payload_hash``.
Nothing checked a reveal's envelope against it. Both readers take the FIRST ``gly`` push in
the FIRST input that decodes, so given inputs ``[decoy, real]`` the decoy wins:

    inputs = [decoy, real]  -> attributed input 0, name='EVIL'
    inputs = [real, decoy]  -> attributed input 0, name='real-token'

Whichever is first. The name, attrs and creator a human reads are then unattributed.

**Why this reports rather than refuses.** On the commit input itself a second envelope is
unreachable — ``CLEANSTACK`` and ``SIGPUSHONLY`` are set unconditionally for block
connection (``tests/vendor/radiant_core/validation.cpp``) and the commit script's stack
arithmetic is fixed, so its scriptSig must be exactly ``<sig> <pubkey> "gly" <payload>``.
The vector is a SECOND input whose locking script consumes the extra items, placed first —
suspected reachable, never demonstrated on a node. And the classifier is network-free by
design, so the spent script is present only when a fetching caller supplies it.

A verdict that silently meant "I could not check" is the thing being fixed, so every state
is named and every state reaches both renderers. ``mismatch`` is the one that matters: it
does not mean unverified, it means demonstrably a different payload.
"""

from __future__ import annotations

import os

from pyrxd.glyph._inspect_core import _payload_binding
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.script import build_commit_locking_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.hash import hash256
from pyrxd.security.types import Hex20


def _envelope(name: str) -> tuple[bytes, bytes]:
    """(scriptSig suffix carrying the envelope, the raw CBOR it carries)."""
    cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
    return build_reveal_scriptsig_suffix(cbor), cbor


def _commit_for(cbor: bytes) -> bytes:
    return build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=True)


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


def test_extract_reveal_cbor_selects_the_push_the_decoder_used() -> None:
    """The hash must be over the payload actually shown, or it answers about something else.

    Two walkers here have already drifted once, in both directions — OP_0 handling and
    truncated pushes — so the selection rule is shared rather than re-implemented.
    """
    suffix, cbor = _envelope("shared-selection")
    inspector = GlyphInspector()
    assert inspector.extract_reveal_cbor(suffix) == cbor
    metadata = inspector.extract_reveal_metadata(suffix)
    assert metadata is not None and metadata.name == "shared-selection"


def test_a_commit_that_committed_to_this_payload_reads_bound() -> None:
    _, cbor = _envelope("honest")
    assert _payload_binding(cbor, _commit_for(cbor))["state"] == "bound"


def test_a_commit_that_committed_to_a_DIFFERENT_payload_reads_mismatch() -> None:
    """The state that matters. Not "unverified" — demonstrably not this payload."""
    _, shown = _envelope("EVIL")
    _, committed = _envelope("real-token")
    verdict = _payload_binding(shown, _commit_for(committed))
    assert verdict["state"] == "mismatch"
    assert "DIFFERENT PAYLOAD" in verdict["reason"]


def test_an_input_that_spent_something_other_than_a_commit_says_so() -> None:
    """Distinct from `unchecked`: here the evidence exists and shows no binding at all."""
    _, cbor = _envelope("x")
    p2pkh = b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac"
    assert _payload_binding(cbor, p2pkh)["state"] == "not-a-commit"


def test_no_spent_script_reads_unchecked_and_never_bound() -> None:
    """The honest degradation. The classifier is network-free; absence of evidence must
    not render as evidence of binding."""
    _, cbor = _envelope("x")
    verdict = _payload_binding(cbor, None)
    assert verdict["state"] == "unchecked"
    assert verdict["state"] != "bound"
    assert "not supplied" in verdict["reason"]


def test_every_state_is_distinct_so_none_can_be_read_as_another() -> None:
    """Non-vacuity. If two states collapsed to one string, a renderer showing it would be
    telling the reader something weaker or stronger than what was established."""
    _, cbor = _envelope("x")
    _, other = _envelope("y")
    states = {
        _payload_binding(cbor, None)["state"],
        _payload_binding(cbor, b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac")["state"],
        _payload_binding(cbor, _commit_for(cbor))["state"],
        _payload_binding(cbor, _commit_for(other))["state"],
    }
    assert states == {"unchecked", "not-a-commit", "bound", "mismatch"}


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


def _commit_and_reveal(shown: str, committed: str | None = None):
    """A reveal spending a real commit output. ``committed`` differing = the attack."""
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    suffix, cbor = _envelope(shown)
    _, committed_cbor = _envelope(committed) if committed is not None else (None, cbor)

    commit_tx = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(Script(_commit_for(committed_cbor)), 1000)],
    )
    inp = TransactionInput(source_txid=commit_tx.txid(), source_output_index=0)
    inp.unlocking_script = Script(b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + suffix)
    reveal_tx = Transaction(tx_inputs=[], tx_outputs=[])
    reveal_tx.inputs = [inp]
    reveal_tx.outputs = [TransactionOutput(Script(b"\x6a"), 0)]
    return commit_tx, reveal_tx


def _run_cli_fetch(client, txid):
    import asyncio

    from pyrxd.cli.glyph_inspect import _inspect_txid_inner

    return asyncio.run(_inspect_txid_inner(client, txid))


def test_the_cli_fetch_path_resolves_the_binding_end_to_end() -> None:
    """The reachability test. Everything above passes with zero production callers."""
    commit_tx, reveal_tx = _commit_and_reveal("honest")
    reveal_txid = reveal_tx.txid()
    client = _StubElectrumX({reveal_txid: reveal_tx.serialize(), commit_tx.txid(): commit_tx.serialize()})

    payload = _run_cli_fetch(client, reveal_txid)

    assert commit_tx.txid() in client.requested, (
        "the fetch path never asked for the spent output, so `payload_binding` can only "
        "read `unchecked` in production no matter how well the helper works"
    )
    metadata = payload["metadata"]
    assert metadata["input_outpoint"] == f"{commit_tx.txid()}:0"
    assert metadata["payload_binding"]["state"] == "bound"


def test_the_cli_fetch_path_reports_a_forged_payload_end_to_end() -> None:
    """The whole point, reached the way a user reaches it."""
    commit_tx, reveal_tx = _commit_and_reveal("EVIL", committed="real-token")
    reveal_txid = reveal_tx.txid()
    client = _StubElectrumX({reveal_txid: reveal_tx.serialize(), commit_tx.txid(): commit_tx.serialize()})

    payload = _run_cli_fetch(client, reveal_txid)

    assert payload["metadata"]["name"] == "EVIL", "the decoy is still what gets displayed"
    assert payload["metadata"]["payload_binding"]["state"] == "mismatch"


def test_an_unfetchable_prevout_leaves_it_unchecked_not_crashed() -> None:
    """Same contract as the delegate block: a failed resolution never fails the inspect.

    And it must degrade to `unchecked` — NEVER to `bound`. An unreachable server is
    the case where a reassuring default would be worst.
    """
    _commit_tx, reveal_tx = _commit_and_reveal("honest")
    reveal_txid = reveal_tx.txid()
    client = _StubElectrumX({reveal_txid: reveal_tx.serialize()})  # commit absent

    payload = _run_cli_fetch(client, reveal_txid)

    assert payload["metadata"]["payload_binding"]["state"] == "unchecked"
    assert payload["metadata"]["name"] == "honest", "the rest of the report is still true"


def test_the_honest_path_is_not_refused_anywhere() -> None:
    """A guard that refuses valid work is a bug. Nothing here may block an honest
    reveal — the verdict is a report, and the report is the entire behaviour change."""
    commit_tx, reveal_tx = _commit_and_reveal("perfectly-fine")
    client = _StubElectrumX({reveal_tx.txid(): reveal_tx.serialize(), commit_tx.txid(): commit_tx.serialize()})
    payload = _run_cli_fetch(client, reveal_tx.txid())
    assert payload["metadata"]["name"] == "perfectly-fine"
    assert payload["metadata"]["payload_binding"]["state"] == "bound"
    assert payload["outputs"] is not None
