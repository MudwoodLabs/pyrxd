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
    # `str()` because the two readers disagree on VALUE TYPE — see the test below. The rules'
    # disagreement is about the key's PRESENCE, and that must not be obscured by the coercion.
    assert str(replay.get("expires")) == "1849006310"
    assert "expires" not in snapshot


def test_the_two_readers_disagree_on_value_TYPE() -> None:
    """A constraint the fold has to handle, recorded where it will be found.

    `GlyphMetadata.attrs` is declared `dict[str, str]`, so the MINT reader stringifies every
    value. `decode_update_payload` returns raw CBOR, so an UPDATE keeps native types. Merge the
    two naively and a field's type depends on which envelope last wrote it — `expires` is
    `'1849006310'` when only the mint set it and `1849006310` when an update did.

    That is not cosmetic: in Python 3 comparing a str to an int raises, so a consumer doing
    `attrs["expires"] > now` would work or crash depending on the name's update history. The
    fold must normalise, or read the mint from raw CBOR rather than through `GlyphMetadata`.
    """
    seq = _envelopes_in_order()
    mint_attrs = seq[0][2]
    assert isinstance(mint_attrs["expires"], str), (
        "the mint reader stopped stringifying — re-check whether the fold still needs to normalise"
    )
    # And the update reader keeps native types: `target` is a string on both sides, but the
    # update's values come straight from CBOR with no coercion layer.
    update_attrs = [a for _h, k, a in seq if k == "update"][-1]
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
