"""The fold rule for WAVE updates is decided; this pins the fixture that can PROVE it.

`docs/solutions/design-decisions/wave-update-fold-omission-means-unchanged.md` decides that an
update omitting a field leaves that field UNCHANGED (replay-merge), because `filterAttrs` in
Photonic drops `null`/`undefined` before merging — so there is no representable way to delete an
attr, and a rule where omission clears one would let a field be destroyed only by accident and
never on purpose.

The fold itself is not written yet: it has no production caller until the chain walker exists to
supply an ordered sequence, and a capability whose only references are its definition and its
tests is not finished.

What IS written now is the thing that makes the future test meaningful. Measured across the seven
real update chains on mainnet, the two candidate rules agree on four of them — so a fold test
built on those four would pass whichever rule was implemented, including the rejected one. This
file pins a chain where they DISAGREE, and asserts that it still disagrees.

`xxl.rxd`: the mint carries `expires`, the single update omits it while changing `target`.

    replay-merge      -> target=1PwiHEAf..., expires=1849006310   (the decision)
    latest-snapshot   -> target=1PwiHEAf..., expires absent
"""

from __future__ import annotations

import json
import pathlib

from pyrxd.glyph.inspector import GlyphInspector

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_fold_discriminating_chain_mainnet.json"
_CHAIN = json.loads(_FIXTURE.read_text())

DECISION_DOC = (
    pathlib.Path(__file__).parent.parent
    / "docs"
    / "solutions"
    / "design-decisions"
    / "wave-update-fold-omission-means-unchanged.md"
)


def _envelopes_in_order() -> list[tuple[int, str, dict]]:
    """(height, kind, attrs) for each transaction, oldest first.

    Reads the envelopes DIRECTLY rather than through `_classify_raw_tx`, because that path's
    `metadata` dict does not carry `attrs` at all — measured, a WAVE mint's own target is absent
    from its result entirely. The fold is a question about envelope contents, so it is asked of
    the reader that has them.
    """
    insp = GlyphInspector()
    out = []
    for tx in sorted(_CHAIN["transactions"], key=lambda t: t["height"]):
        raw = bytes.fromhex(tx["raw"])
        found: tuple[str, dict] | None = None
        for scriptsig in _scriptsigs(raw):
            env = insp.classify_glyph_scriptsig(scriptsig)
            if env is None:
                continue
            if env.kind == "payload":
                found = ("mint", dict(env.metadata.attrs or {}))
            elif env.kind == "update":
                found = ("update", dict(env.fields.get("attrs") or {}))
            if found:
                break
        out.append((tx["height"], *(found or ("transfer", {}))))
    return out


def _scriptsigs(raw: bytes) -> list[bytes]:
    """Every input's scriptSig, via the same parser the inspect path uses."""
    from pyrxd.transaction.transaction import Transaction

    tx = Transaction.from_hex(raw)
    return [bytes(inp.unlocking_script.serialize()) for inp in tx.inputs]


def test_the_chain_is_the_shape_the_decision_needs() -> None:
    """Mint, then a transfer, then an update — and the update must OMIT a field the mint set."""
    seq = _envelopes_in_order()
    kinds = [k for _h, k, _a in seq]
    assert kinds == ["mint", "transfer", "update"], kinds

    mint_attrs = seq[0][2]
    update_attrs = seq[-1][2]
    assert "expires" in mint_attrs, "the mint must carry the field whose omission is the question"
    assert "expires" not in update_attrs, (
        "the update must OMIT it — a chain where the update re-states every field cannot "
        "distinguish replay-merge from latest-snapshot, and four of the seven real chains "
        "are exactly that useless case"
    )


def test_the_two_candidate_rules_really_disagree_here() -> None:
    """THE non-vacuity property. If this ever stops holding, a fold test over this fixture
    proves nothing and the fixture must be replaced, not the assertion relaxed."""
    seq = _envelopes_in_order()

    replay: dict = {}
    for _h, _kind, attrs in seq:
        replay.update(attrs)

    updates = [a for _h, k, a in seq if k == "update"]
    snapshot = dict(updates[-1])

    assert replay != snapshot, "the two rules agree on this chain — it cannot express the decision"
    # `str()` on both sides so this stays about the key's PRESENCE, which is what the two rules
    # actually disagree about, independent of how the readers type the value.
    assert str(replay.get("expires")) == "1849006310"
    assert "expires" not in snapshot


def test_the_two_readers_now_AGREE_on_value_TYPE() -> None:
    """They used to disagree, and this test used to pin that. It is inverted deliberately.

    `GlyphMetadata.attrs` was declared `dict[str, str]`, so the MINT reader stringified every
    value while `decode_update_payload` returned raw CBOR — `expires` was `'1849006310'` from one
    and `1849006310` from the other, and `fold_chain` normalised to `str` to hide the seam.

    `_decode_attr_value` ended that. The blanket `str()` was not merely lossy, it INVERTED
    meaning: an authority token's `revocable: false` became the string `'False'`, which is truthy,
    so a NON-revocable authority read back as revocable, and `permissions: ['mint']` became
    `"['mint']"`. Preserving scalars fixed that at the source — and with both readers preserving
    types, the fold's normalisation stopped being a seam-hider and became the same inversion one
    layer down, so it was removed too.

    Pinned because the fold's rule DEPENDS on this. If a reader ever starts coercing again, the
    fold silently goes back to merging mixed types and this fails first.
    """
    seq = _envelopes_in_order()
    mint_attrs = seq[0][2]
    update_attrs = [a for _h, k, a in seq if k == "update"][-1]

    assert isinstance(mint_attrs["expires"], int) and not isinstance(mint_attrs["expires"], bool), (
        f"the mint reader coerced `expires` to {type(mint_attrs['expires']).__name__} — if it is "
        "stringifying again, `fold_chain` is merging mixed types"
    )
    assert isinstance(mint_attrs["target"], str), "a real string must still arrive as a string"
    assert isinstance(update_attrs["target"], str)


def test_target_is_the_same_under_both_rules() -> None:
    """Worth pinning so nobody over-reads the decision: the disagreement is confined to
    `expires`. `target` — the field §7.6 form 2 actually needs — is identical either way on
    every observed chain, so this choice is about completeness, not about the answer form 2
    gives today."""
    seq = _envelopes_in_order()
    replay: dict = {}
    for _h, _kind, attrs in seq:
        replay.update(attrs)
    snapshot = dict([a for _h, k, a in seq if k == "update"][-1])
    assert replay["target"] == snapshot["target"] == "1PwiHEAf63tFF8JWJYrKrJjGmHgaLjHZp"


def test_the_fixture_states_the_decision_it_serves() -> None:
    """A fixture that outlives the reasoning is how a rule silently flips. The expected answers
    are recorded next to the bytes, and the decision doc must exist to explain them."""
    expected = _CHAIN["_expected_fold"]
    assert expected["decision"] == "replay_merge"
    assert expected["replay_merge"]["expires"] == 1849006310
    assert expected["latest_snapshot"]["expires"] is None
    assert DECISION_DOC.is_file(), f"the decision record is missing: {DECISION_DOC}"


# ---------------------------------------------------------------------------
# The implementation must actually obey the decision
# ---------------------------------------------------------------------------


async def test_fold_chain_implements_REPLAY_MERGE_not_snapshot() -> None:
    """The decision, asserted against the CODE rather than against two rules computed here.

    Everything above compares candidate rules the TEST computes, which proves the fixture can
    express the decision and proves nothing about `fold_chain`. Planting the rejected rule into
    `fold_chain` passed every test in this file and every form-2 test — because the two rules
    differ only on `expires`, and nothing asserted `expires`.

    So this is the link between the decision and the implementation: fold the discriminating
    chain and require the field that only survives under replay-merge.
    """
    from pyrxd.glyph.mutable_chain import fold_chain, walk_mutable_chain
    from pyrxd.transaction.transaction import Transaction

    raw = {t["txid"]: bytes.fromhex(t["raw"]) for t in _CHAIN["transactions"]}
    mint = min(_CHAIN["transactions"], key=lambda t: t["height"])["txid"]

    async def fetch(txid: str):
        return Transaction.from_hex(raw[txid])

    async def unspent(_t: str, _v: int) -> bool:
        return True

    walk = await walk_mutable_chain(mint_txid=mint, candidates=list(raw), fetch_tx=fetch, is_unspent=unspent)
    folded = fold_chain(walk)

    expected = _CHAIN["_expected_fold"]
    assert expected["decision"] == "replay_merge"
    assert folded.attrs["target"] == expected["replay_merge"]["target"]
    # No `str()`: the fold PRESERVES types now (see `fold_chain`). The rules' disagreement here
    # is about the key's PRESENCE, which the type change does not touch.
    assert folded.attrs.get("expires") == expected["replay_merge"]["expires"], (
        "`expires` did not survive the fold — that is the LATEST-SNAPSHOT rule, which this "
        "project rejected: deletion is not representable, so omission cannot mean clear"
    )
    assert expected["latest_snapshot"]["expires"] is None, "the fixture no longer discriminates"


async def test_the_fold_preserves_value_types() -> None:
    """The fold must NOT coerce. Both readers preserve CBOR types now, so stringifying here would
    re-introduce the inversion `_decode_attr_value` was written to stop — a folded
    `revocable: false` becoming the truthy string `'False'` — in the record a consumer reads."""
    from pyrxd.glyph.mutable_chain import fold_chain, walk_mutable_chain
    from pyrxd.transaction.transaction import Transaction

    raw = {t["txid"]: bytes.fromhex(t["raw"]) for t in _CHAIN["transactions"]}
    mint = min(_CHAIN["transactions"], key=lambda t: t["height"])["txid"]

    async def fetch(txid: str):
        return Transaction.from_hex(raw[txid])

    async def unspent(_t: str, _v: int) -> bool:
        return True

    folded = fold_chain(
        await walk_mutable_chain(mint_txid=mint, candidates=list(raw), fetch_tx=fetch, is_unspent=unspent)
    )
    assert folded.attrs, "the fold produced nothing — it is not reaching the envelopes"
    assert isinstance(folded.attrs["expires"], int), (
        f"the fold coerced `expires` to {type(folded.attrs['expires']).__name__}"
    )
    assert isinstance(folded.attrs["target"], str), "a real string must survive as a string"
