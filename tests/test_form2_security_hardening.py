"""The findings of the form-2 security panel, each pinned by the input that demonstrated it.

Seven reviewers across two model families attacked the #598 stack. Every finding was mine. This
file is the regression net for the fixes; the panel's own demonstrations are the test inputs, so
each test fails if its fix is reverted rather than merely describing it.

Grouped by what was wrong, not by module.
"""

from __future__ import annotations

import json
import pathlib
import re

import cbor2
import pytest

from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mark_anchor import MarkAnchor, resolve_mark_anchor
from pyrxd.glyph.mutable_chain import ChainStep, MutableChainWalk, fold_chain, walk_mutable_chain
from pyrxd.glyph.payload import GLY_MARKER
from pyrxd.glyph.wave import WaveAttrs, classify_glyph_metadata, wave_attrs_from_metadata
from pyrxd.glyph.wave_identity import judge_name_at_mark
from pyrxd.hash import hash256
from pyrxd.security.errors import NetworkError
from pyrxd.transaction.transaction import Transaction

_FIX = pathlib.Path(__file__).parent / "fixtures"
_FOUR = json.loads((_FIX / "wave_update_chain_mainnet.json").read_text())
_RAW = {t["txid"]: bytes.fromhex(t["raw"]) for t in _FOUR["transactions"]}
_HEIGHTS = {t["txid"]: t["height"] for t in _FOUR["transactions"]}
MINT = "f644794b3fb9ab8330b236debbe1989ce1034e5b2a8f8f2516e05f4e54f3cf31"
UPDATE_B = "3c7b43dffe74fe57bc233f5305589714ee54335f9b15e81cc7dde0861c2482be"


async def _fetch(txid: str):
    return Transaction.from_hex(_RAW[txid])


async def _unspent(_t: str, _v: int) -> bool:
    return True


async def _walk(**kw):
    params = {
        "mint_txid": MINT,
        "candidates": list(_RAW),
        "fetch_tx": _fetch,
        "is_unspent": _unspent,
        "candidate_source": "index",
        "tip_source": "node",
    }
    params.update(kw)
    return await walk_mutable_chain(**params)


def _anchor(height: int, *, source: str = "node") -> MarkAnchor:
    return MarkAnchor(txid="ma" * 32, height=height, confirmations=50, min_confirmations=6, source=source)


# ---------------------------------------------------------------------------
# 1. The fold folded steps the range calculation had excluded
# ---------------------------------------------------------------------------


async def test_non_monotonic_heights_degrade_instead_of_folding_an_excluded_step() -> None:
    """`in_range` was a FILTER and `fold_chain(through_index=N)` folds a PREFIX, so a step the
    code ruled out of range was folded in anyway — and its target reported authoritatively with
    an empty reason.

    Heights along a spend-ordered chain are non-decreasing by consensus: a transaction cannot be
    mined before the one it spends. A decrease is therefore evidence the height source is lying
    or that state was read across a reorg — the case that must degrade — and enforcing it makes
    the filter a prefix, so the fold is correct by construction rather than by luck.
    """
    steps = (
        ChainStep(txid="aaaa", mut_vout=1, kind="mint", attrs={"target": "HONEST"}),
        ChainStep(txid="bbbb", mut_vout=1, kind="update", attrs={"target": "ATTACKER"}),
        ChainStep(txid="cccc", mut_vout=1, kind="update", attrs={"note": "cosmetic"}),
    )
    walk = MutableChainWalk(ref="r", steps=steps, tip_txid="cccc", tip_vout=1, tip_proved_unspent=True, complete=True)
    verdict = judge_name_at_mark(
        ref="r",
        binding_source="index",
        anchor=_anchor(1000),
        walk=walk,
        step_heights={"aaaa": 900, "bbbb": 5000, "cccc": 950},
    )
    assert verdict.form == 1
    assert "decrease along a spend-ordered chain" in verdict.degraded_reason
    assert verdict.target_at_height is None


@pytest.mark.parametrize("bad", [False, True, -1, "999", 1.5, None])
async def test_unusable_step_heights_degrade(bad: object) -> None:
    """`(h or 0)` turned `False` into height 0 — the genesis block, i.e. before any mark. A JSON
    string raised TypeError out of a function documented as always degrading.

    `nonneg_int` already existed for this, `mark_anchor` used it for the mark's own depth, and
    `wave._optional_int` refuses a bool with a comment explaining why `isinstance(True, int)`
    matters. The newest and most trust-critical of the four inputs had none of it.
    """
    walk = await _walk()
    heights = {**_HEIGHTS, walk.steps[0].txid: bad}
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source="index", anchor=_anchor(458605), walk=walk, step_heights=heights
    )
    assert verdict.form == 1
    assert verdict.target_at_height is None


async def test_a_verdict_is_refused_when_the_walk_is_of_another_glyph() -> None:
    """`walk.ref` was never compared to `ref`, so a form-2 sentence could name one glyph while
    reporting a target folded from another's chain — false about both halves, no reason given."""
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref="SOME-OTHER-TOKEN:0",
        binding_source="index",
        anchor=_anchor(458605),
        walk=walk,
        step_heights=_HEIGHTS,
    )
    assert verdict.form == 1
    assert "is of ref" in verdict.degraded_reason


# ---------------------------------------------------------------------------
# 2. The envelope was not the one the covenant commits to
# ---------------------------------------------------------------------------


def test_every_real_step_commits_to_its_own_envelope() -> None:
    """The protocol fact the fix rests on, asserted rather than assumed: a mutable output's
    `payload_hash` IS sha256d of that step's envelope CBOR, on every real mainnet step."""
    inspector = GlyphInspector()
    from pyrxd.glyph.script import parse_mutable_nft_script

    checked = 0
    for tx_json in _FOUR["transactions"]:
        tx = Transaction.from_hex(bytes.fromhex(tx_json["raw"]))
        hashes = [parse_mutable_nft_script(bytes(o.locking_script.serialize())) for o in tx.outputs]
        committed = [h[1] for h in hashes if h is not None]
        if not committed:
            continue
        blobs = []
        for inp in tx.inputs:
            items, _ = inspector._walk_pushes(bytes(inp.unlocking_script.serialize()))
            blobs += [items[i + 1] for i, it in enumerate(items) if it == GLY_MARKER and i + 1 < len(items)]
        assert any(hash256(b) in committed for b in blobs), (
            f"{tx_json['txid']} carries no envelope matching its own payload_hash"
        )
        checked += 1
    assert checked >= 3, f"only {checked} steps checked — the fixture stopped exercising this"


async def test_a_decoy_envelope_in_an_earlier_input_is_ignored() -> None:
    """Reading "the first `gly` push in any input" let the publisher choose the record: a decoy
    in an earlier input replaced it wholesale. The covenant says which bytes are the record."""
    real = Transaction.from_hex(_RAW[UPDATE_B])
    decoy_blob = cbor2.dumps({"attrs": {"target": "1DecoyDecoyDecoyDecoyDecoyDecoyDec"}})
    decoy_ss = bytes([len(GLY_MARKER)]) + GLY_MARKER + b"\x4c" + bytes([len(decoy_blob)]) + decoy_blob

    from pyrxd.script.script import Script

    real.inputs[0].unlocking_script = Script(decoy_ss, allow_malformed=True)

    async def fetch(txid: str):
        return real if txid == UPDATE_B else Transaction.from_hex(_RAW[txid])

    walk = await _walk(fetch_tx=fetch)
    targets = [s.attrs.get("target") for s in walk.steps]
    assert "1DecoyDecoyDecoyDecoyDecoyDecoyDec" not in targets, targets


# ---------------------------------------------------------------------------
# 3. One source must not supply both halves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("cand", "tip"), [("same", "same"), ("", ""), ("index", "index")])
async def test_the_candidate_set_and_tip_proof_may_not_share_a_source(cand: str, tip: str) -> None:
    """Omitting the later updates AND certifying the earlier tip needs two lies from one endpoint,
    and produced `complete=True` over a stale record with an empty reason. Unattributed sources
    count as possibly-identical, because they might be."""
    walk = await _walk(candidate_source=cand, tip_source=tip)
    assert not walk.complete
    assert "same source" in walk.reason or "unattributed" in walk.reason


async def test_two_claimants_for_one_outpoint_is_an_ambiguity_not_a_race_to_sort_first() -> None:
    """The spender was chosen by `sorted(pool)`, so one fabricated conflicting txid ground to sort
    first hijacked the chain — and the REAL confirmed update was then reported in `excluded`.
    Nothing here can tell a real spend from a forged one, so two claimants must degrade."""
    forged = Transaction.from_hex(_RAW[UPDATE_B])  # spends the same outpoint as the real update

    async def fetch(txid: str):
        return forged if txid == "0" * 64 else Transaction.from_hex(_RAW[txid])

    walk = await _walk(candidates=[*list(_RAW), "0" * 64], fetch_tx=fetch)
    assert not walk.complete
    assert "claim to spend" in walk.reason


# ---------------------------------------------------------------------------
# 4. The regression, and the shape the real chain actually produces
# ---------------------------------------------------------------------------


def test_a_real_wave_mint_still_classifies_as_wave() -> None:
    """`_optional_int` demanded an int while `GlyphMetadata.attrs` is `dict[str, str]`, so every
    real WAVE mint carrying `expires` stopped being a WAVE name through the public facade —
    strictly worse than the dropped field the change was written to fix."""
    inspector = GlyphInspector()
    for name in ("wave_update_chain_mainnet.json", "wave_fold_discriminating_chain_mainnet.json"):
        chain = json.loads((_FIX / name).read_text())
        mint = min(chain["transactions"], key=lambda t: t["height"])
        tx = Transaction.from_hex(bytes.fromhex(mint["raw"]))
        metadata = None
        for inp in tx.inputs:
            env = inspector.classify_glyph_scriptsig(bytes(inp.unlocking_script.serialize()))
            if env is not None and env.kind == "payload":
                metadata = env.metadata
                break
        assert metadata is not None, name
        assert isinstance(metadata.attrs["expires"], str), "the mint reader stopped stringifying"
        assert classify_glyph_metadata(metadata) == "wave", name
        assert wave_attrs_from_metadata(metadata) is not None, name


@pytest.mark.parametrize("bad", [True, False, "soon", "-1", " 12", "1_2", "١٢", 1.5, [], {}])
def test_expires_still_refuses_everything_that_is_not_a_plain_integer(bad: object) -> None:
    """Accepting the decimal string must not widen into accepting anything `int()` would take."""
    from pyrxd.security.errors import ValidationError

    base = {"name": "n", "domain": "rxd", "target": "t", "target_type": "address"}
    with pytest.raises(ValidationError):
        WaveAttrs.from_dict({**base, "expires": bad})


# ---------------------------------------------------------------------------
# 5. Publisher-chosen shapes must not crash or masquerade
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hostile", ["a string", 7, b"bytes", [1, 2], [["target", "X"]], None])
async def test_a_hostile_attrs_shape_does_not_crash_the_walk(hostile: object) -> None:
    """`dict(attrs)` met whatever the publisher wrote: a string raised ValueError, an int raised
    TypeError — out of a module whose contract says only a ref contradiction raises — and a CBOR
    ARRAY of pairs was silently reinterpreted as a map."""
    from pyrxd.glyph.mutable_chain import _as_attrs

    result = _as_attrs(hostile)
    assert result == {}, f"{hostile!r} was reinterpreted as {result!r}"


def test_non_string_attrs_keys_are_dropped_not_coerced() -> None:
    """`payload.py` refuses non-string keys one level up, saying `str(1)` and `"1"` would collide
    and "let a writer overwrite a field it never named" — and `attrs`, where `target` lives, is
    the level that guard does not reach."""
    from pyrxd.glyph.mutable_chain import _as_attrs

    assert _as_attrs({1: "int-key", "1": "text-key", "target": "t"}) == {"1": "text-key", "target": "t"}


def test_the_fold_normalises_types_on_a_chain_that_can_show_it() -> None:
    """The previous version of this folded the chain whose values are already all strings, so
    removing the normalisation passed it. This one uses the chain whose second update carries
    `expires` as a CBOR int."""
    raw_kinds = set()
    for tx_json in _FOUR["transactions"]:
        tx = Transaction.from_hex(bytes.fromhex(tx_json["raw"]))
        inspector = GlyphInspector()
        for inp in tx.inputs:
            env = inspector.classify_glyph_scriptsig(bytes(inp.unlocking_script.serialize()))
            if env is not None and env.kind == "update":
                raw_kinds |= {type(v).__name__ for v in (env.fields or {}).get("attrs", {}).values()}
    assert "int" in raw_kinds, "no update carries a non-str value — this fixture cannot show it"


async def test_the_fold_output_is_all_strings() -> None:
    folded = fold_chain(await _walk())
    assert folded.attrs
    assert all(isinstance(v, str) for v in folded.attrs.values()), folded.attrs


# ---------------------------------------------------------------------------
# 6. The anchor, against the shape a real node sends
# ---------------------------------------------------------------------------


async def test_a_mined_transaction_is_placed_from_the_tip() -> None:
    """A real node's verbose response carries `confirmations` and no height at all, so the height
    is derived. 463036 - 4446 + 1 = 458591, the real height of that transaction."""
    real = {
        "blockhash": "00" * 32,
        "confirmations": 4446,
        "txid": "ab" * 32,
        "size": 828,
        "version": 1,
        "locktime": 0,
    }

    async def fetch(_t: str) -> dict:
        return real

    anchor = await resolve_mark_anchor(
        txid="ab" * 32, fetch_verbose=fetch, source="node", min_confirmations=6, tip_height=463036
    )
    assert anchor.height == 458591
    assert anchor.usable_for_point_in_time


async def test_a_depth_deeper_than_the_chain_is_refused() -> None:
    async def fetch(_t: str) -> dict:
        return {"confirmations": 999_999, "txid": "ab" * 32}

    with pytest.raises(NetworkError, match="genesis"):
        await resolve_mark_anchor(txid="ab" * 32, fetch_verbose=fetch, source="n", min_confirmations=1, tip_height=100)


# ---------------------------------------------------------------------------
# 7. The degrade paths themselves — the panel found NONE of them exercised
# ---------------------------------------------------------------------------
#
# Rules 2 and 3 of the four in `wave_identity.py`'s module docstring were prose only: no fixture
# contained an unreadable envelope, so the branch that refuses to call a partial fold "the record"
# had never once run. The rule that is never exercised is the rule that silently stops working.


def _mut_script_with(locking: bytes, payload_hash: bytes) -> bytes:
    """The same mutable-NFT script with a different commitment. `script[1:33]` per `script.py`."""
    assert len(payload_hash) == 32
    return locking[:1] + payload_hash + locking[33:]


def _rebuild(txid: str, *, scriptsig: bytes | None, commitment: bytes | None):
    """The real transaction with its envelope and/or its commitment replaced."""
    from pyrxd.glyph.script import parse_mutable_nft_script
    from pyrxd.script.script import Script

    tx = Transaction.from_hex(_RAW[txid])
    if scriptsig is not None:
        tx.inputs[0].unlocking_script = Script(scriptsig, allow_malformed=True)
        for extra in tx.inputs[1:]:
            extra.unlocking_script = Script(b"", allow_malformed=True)
    if commitment is not None:
        for out in tx.outputs:
            locking = bytes(out.locking_script.serialize())
            if parse_mutable_nft_script(locking) is not None:
                out.locking_script = Script(_mut_script_with(locking, commitment), allow_malformed=True)
    return tx


def _envelope_scriptsig(blob: bytes) -> bytes:
    return bytes([len(GLY_MARKER)]) + GLY_MARKER + b"\x4c" + bytes([len(blob)]) + blob


async def _walk_with(tx) -> object:
    async def fetch(txid: str):
        return tx if txid == UPDATE_B else Transaction.from_hex(_RAW[txid])

    return await _walk(fetch_tx=fetch)


def _sha256d(blob: bytes) -> bytes:
    """The same primitive the walker uses, not a second copy of it."""
    return hash256(blob)


async def test_an_unreadable_envelope_refuses_the_walk_and_marks_the_fold() -> None:
    """The committed envelope is present and does not decode. This is the case the third state
    exists for: a walk that cannot parse an entry must never report "the name never changed"."""
    garbage = b"\xff\xfe not cbor at all \x00\x01"
    tx = _rebuild(UPDATE_B, scriptsig=_envelope_scriptsig(garbage), commitment=_sha256d(garbage))
    walk = await _walk_with(tx)

    kinds = [s.kind for s in walk.steps]
    assert "unreadable" in kinds, kinds
    assert walk.has_unreadable_step
    assert not walk.complete
    assert UPDATE_B[:12] in walk.reason

    folded = fold_chain(walk)
    assert folded.incomplete
    assert "not the record" in folded.reason


async def test_an_envelope_that_is_not_the_committed_one_refuses_the_walk() -> None:
    """Bytes are revealed and none of them hash to what the output commits to. Distinct from
    "no envelope": the publisher published something, just not this token's record."""
    other = cbor2.dumps({"attrs": {"target": "1NotTheCommittedRecordAtAllXXXXXXX"}})
    tx = _rebuild(UPDATE_B, scriptsig=_envelope_scriptsig(other), commitment=None)
    walk = await _walk_with(tx)

    assert "unbound" in [s.kind for s in walk.steps]
    assert not walk.complete
    assert "none of them is this token's record" in walk.reason
    assert fold_chain(walk).incomplete


async def test_a_step_that_reveals_no_envelope_is_unknown_not_unchanged() -> None:
    """The output commits to a payload_hash and the transaction publishes nothing. Folding that as
    "unchanged" reports the PREVIOUS target as current — a false form-2 sentence built out of a
    step that said nothing at all."""
    tx = _rebuild(UPDATE_B, scriptsig=b"\x00", commitment=None)
    walk = await _walk_with(tx)

    assert "none" in [s.kind for s in walk.steps]
    assert walk.has_unreadable_step
    assert not walk.complete
    assert "never published" in walk.reason
    assert fold_chain(walk).incomplete


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: _rebuild(
                UPDATE_B,
                scriptsig=_envelope_scriptsig(b"\xff\xfe garbage"),
                commitment=_sha256d(b"\xff\xfe garbage"),
            ),
            id="unreadable",
        ),
        pytest.param(
            lambda: _rebuild(UPDATE_B, scriptsig=_envelope_scriptsig(cbor2.dumps({"a": 1})), commitment=None),
            id="unbound",
        ),
        pytest.param(lambda: _rebuild(UPDATE_B, scriptsig=b"\x00", commitment=None), id="none"),
    ],
)
async def test_rule_3_degrades_the_verdict_for_every_unknown_record(build) -> None:
    """Rule 3 of the module docstring, run rather than read, for all three of its cases."""
    walk = await _walk_with(build())
    verdict = judge_name_at_mark(
        ref=walk.ref,
        binding_source="index",
        anchor=_anchor(458605),
        walk=walk,
        step_heights=_HEIGHTS,
    )
    assert verdict.form == 1
    assert verdict.degraded_reason
    assert verdict.target_at_height is None


def test_every_kind_the_envelope_reader_can_return_is_classified() -> None:
    """The set is DERIVED from the function that produces it, not hand-typed beside it.

    Three sites listed these kinds by hand and they had already drifted apart — `fold_chain` was
    missing `unbound`, and `none` was in no list at all. A new kind added to `_envelope_of` must
    fail here rather than defaulting to the readable side, which is the side that asserts.
    """
    import ast
    import inspect

    from pyrxd.glyph import mutable_chain

    tree = ast.parse(inspect.getsource(mutable_chain))
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_envelope_of")
    produced = {
        node.value
        for ret in ast.walk(func)
        if isinstance(ret, ast.Return) and ret.value is not None
        for node in [ret.value.elts[0] if isinstance(ret.value, ast.Tuple) else ret.value]
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert produced, "the AST scan found no kinds — it has stopped measuring anything"

    record_bearing = {"mint", "update"}
    assert produced == record_bearing | mutable_chain.RECORD_UNKNOWN_KINDS, (
        f"_envelope_of returns {sorted(produced)}; "
        f"classified: {sorted(record_bearing | mutable_chain.RECORD_UNKNOWN_KINDS)}"
    )


# ---------------------------------------------------------------------------
# 8. One committed blob, one reading
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("blob", "expect"),
    [
        pytest.param(
            cbor2.dumps({"attrs": {"target": "REAL"}}) + b"\xff\xff\x00trailing",
            "two readings",
            id="trailing-bytes",
        ),
        pytest.param(
            b"\xa1"
            + cbor2.dumps("attrs")
            + b"\xa2"
            + cbor2.dumps("target")
            + cbor2.dumps("FIRST")
            + cbor2.dumps("target")
            + cbor2.dumps("SECOND"),
            "more than once",
            id="duplicate-keys",
        ),
    ],
)
async def test_an_ambiguously_encoded_envelope_is_unreadable_not_last_wins(blob, expect) -> None:
    """`cbor2` accepts both of these silently — it discards trailing bytes and takes the LAST of a
    repeated key. The `payload_hash` binding stops an attacker substituting the record; it does not
    make the record unambiguous, and form 2 asserts what the record WAS."""
    from pyrxd.glyph.mutable_chain import _ambiguous_encoding

    assert expect in _ambiguous_encoding(blob)

    tx = _rebuild(UPDATE_B, scriptsig=_envelope_scriptsig(blob), commitment=_sha256d(blob))
    walk = await _walk_with(tx)
    assert "unreadable" in [s.kind for s in walk.steps]
    assert not walk.complete
    assert fold_chain(walk).incomplete


def test_the_real_envelopes_are_not_ambiguous() -> None:
    """The honest-path half: a guard that refuses valid work is a bug, and this one sits in front
    of every step of every chain form 2 can answer about."""
    from pyrxd.glyph.mutable_chain import _ambiguous_encoding

    inspector = GlyphInspector()
    checked = 0
    for name in ("wave_update_chain_mainnet.json", "wave_fold_discriminating_chain_mainnet.json"):
        chain = json.loads((_FIX / name).read_text())
        for entry in chain["transactions"]:
            tx = Transaction.from_hex(bytes.fromhex(entry["raw"]))
            for inp in tx.inputs:
                items, _ = inspector._walk_pushes(bytes(inp.unlocking_script.serialize()))
                for i, item in enumerate(items):
                    if item == GLY_MARKER and i + 1 < len(items):
                        checked += 1
                        assert _ambiguous_encoding(items[i + 1]) == "", entry["txid"]
    assert checked >= 5, f"only {checked} envelopes checked — the corpus stopped being measured"


# ---------------------------------------------------------------------------
# 9. Cost, and the cap that bounds it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.0, "8", None])
async def test_a_cap_that_cannot_walk_a_step_is_refused(bad: object) -> None:
    """`max_steps=0` made the loop body unreachable, so the walk returned the MINT as the tip with
    an empty reason — a confident answer about a chain it never walked."""
    from pyrxd.security.errors import ValidationError

    with pytest.raises(ValidationError, match="max_steps"):
        await _walk(max_steps=bad)


async def test_each_candidate_is_fetched_at_most_once() -> None:
    """The spender search reads the whole remaining pool every step, so an uncached walk cost
    `steps x candidates` round trips against the consumer's endpoint. Measured here rather than
    asserted in prose: without the cache this same walk made 3,007 calls for 1,004 candidates."""
    calls: list[str] = []
    filler = Transaction.from_hex(_RAW[MINT])

    async def counting(txid: str):
        calls.append(txid)
        return Transaction.from_hex(_RAW[txid]) if txid in _RAW else filler

    decoys = [f"{i:064x}" for i in range(200)]
    walk = await _walk(candidates=[*list(_RAW), *decoys], fetch_tx=counting)

    assert walk.complete
    assert len(calls) == len(set(c.lower() for c in calls)), "a transaction was fetched twice"
    assert len(calls) <= len(_RAW) + len(decoys)


# ---------------------------------------------------------------------------
# 10. The facade offers what the modules declare
# ---------------------------------------------------------------------------


def test_every_public_name_in_the_form2_modules_is_reachable_from_the_facade() -> None:
    """DERIVED FROM `__all__`, not hand-typed beside it.

    The facade exported the walker, the verdict and their dataclasses but none of the CONSTANTS —
    so a consumer comparing `verdict.expiry` to `EXPIRY_UNKNOWN` had to import a private module or
    retype the string, which is how "unknown" quietly becomes "not expired". Both directions are
    checked: a declared name the facade omits is that gap, and a facade entry naming something the
    module no longer declares is an export that has silently stopped resolving.
    """
    import importlib

    from pyrxd import glyph

    for mod_name in ("mutable_chain", "wave_identity", "mark_anchor"):
        module = importlib.import_module(f"pyrxd.glyph.{mod_name}")
        declared = set(module.__all__)
        assert declared, f"{mod_name} declares no public names — this check has stopped measuring"
        missing = declared - set(glyph.__all__)
        assert not missing, f"pyrxd.glyph omits {sorted(missing)} declared by {mod_name}.__all__"
        for name in declared:
            assert getattr(glyph, name) is getattr(module, name), f"{name} resolves elsewhere"


# ---------------------------------------------------------------------------
# 11. What reaches the terminal
# ---------------------------------------------------------------------------


def _human_with_envelope(envelope: dict) -> str:
    """Render through the REAL producer and renderer, with one envelope swapped in.

    Built from a real transaction rather than a hand-made dict so the payload carries every key
    the renderer reads — a fixture that hands the code a shape the producer never emits verifies
    the fixture, not the renderer.
    """
    from pyrxd.cli.glyph_inspect import _render_txid_human
    from pyrxd.glyph._inspect_core import _classify_raw_tx

    payload = _classify_raw_tx(UPDATE_B, _RAW[UPDATE_B])
    assert payload.get("glyph_envelopes"), "the fixture stopped producing envelopes"
    payload["glyph_envelopes"] = [envelope]
    return _render_txid_human(payload)


def test_a_publisher_chosen_key_cannot_own_the_operators_screen() -> None:
    """Values were truncated and KEYS were not, so a 100,000-character key rendered in full — a
    200,004-character line, measured. And nothing capped how MANY entries an envelope may list,
    so a 256 KB payload of one-byte keys pushed every verified fact off the screen."""
    from pyrxd.glyph._inspect_core import _HUMAN_ENTRY_CAP, _HUMAN_STRING_CAP, _sanitize_update_fields

    hostile = _sanitize_update_fields(
        {
            "attrs": {"K" * 100_000: "V" * 100_000, **{f"k{i:04d}": "v" for i in range(500)}},
            "L" * 100_000: "W" * 100_000,
        }
    )
    text = _human_with_envelope({"input_index": 0, "kind": "update", "fields": hostile})

    longest = max(len(line) for line in text.split("\n"))
    assert longest < _HUMAN_STRING_CAP * _HUMAN_ENTRY_CAP, f"longest rendered line is {longest:,}"
    assert "K" * 1_000 not in text, "an untruncated key reached the terminal"

    # COUNT THE ENTRIES, do not bound the bytes. A byte bound is not a cap on the entry count:
    # 501 short entries render to about 4,000 characters, comfortably under any line limit, so
    # removing the slice left this test green. The plant proved it before this line existed.
    # One of the capped slots goes to the 100,000-character key, which sorts first (uppercase
    # "K" before lowercase "k"), so the cap leaves room for CAP - 1 of the `k####` entries.
    rendered = len(re.findall(r"k\d{4}=v", text))
    assert rendered == _HUMAN_ENTRY_CAP - 1, (
        f"{rendered} of the 500 `k####` attrs rendered; the cap is {_HUMAN_ENTRY_CAP} entries, "
        f"one of which is taken by the oversized key"
    )
    assert "more attrs not shown" in text, "entries were dropped without saying so"


def test_the_render_still_shows_a_normal_update_in_full() -> None:
    """The honest-path half of the cap: a real update is well under it and must be unaffected."""
    from pyrxd.glyph._inspect_core import _sanitize_update_fields

    fields = _sanitize_update_fields(
        {
            "attrs": {
                "name": "custodian-gate-x7f3",
                "domain": "rxd",
                "target": "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i",
                "target_type": "address",
            }
        }
    )
    text = _human_with_envelope({"input_index": 1, "kind": "update", "fields": fields})
    assert "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i" in text
    assert "custodian-gate-x7f3" in text
    assert "not shown" not in text


def test_a_whole_float_expires_is_read_the_way_the_rest_of_the_sdk_reads_numbers() -> None:
    """`finite_int` accepts a whole float and refuses 1.5/Infinity/NaN; `expires` was stricter
    than that for no stated reason, while CBOR can carry any of them."""
    base = {"name": "n", "domain": "rxd", "target": "t", "target_type": "address"}
    assert WaveAttrs.from_dict({**base, "expires": 1850743929.0}).expires == 1850743929
    for bad in (1.5, float("inf"), float("nan")):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            WaveAttrs.from_dict({**base, "expires": bad})


async def test_a_chain_ending_in_a_non_mutable_output_names_the_transaction() -> None:
    """The `or` fallback here was unreachable — every path to a negative tip vout sets a reason
    first — so the generic sentence could never be read. This pins the one that IS."""
    real = Transaction.from_hex(_RAW[UPDATE_B])
    from pyrxd.script.script import Script

    for out in real.outputs:
        out.locking_script = Script(b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac", allow_malformed=True)

    async def fetch(txid: str):
        return real if txid == UPDATE_B else Transaction.from_hex(_RAW[txid])

    walk = await _walk(fetch_tx=fetch)
    assert not walk.complete
    assert "spends the mutable output and produces none" in walk.reason
    assert UPDATE_B in walk.reason, "the reason must name the transaction that ended the chain"


# ---------------------------------------------------------------------------
# 12. One walker, so the two readers cannot drift
# ---------------------------------------------------------------------------
#
# `_scriptsig_pushes` claimed in its own docstring that push handling was expressed over
# `_walk_pushes` "so there is one walker rather than two that can drift", while
# `_parse_reveal_scriptsig` kept a hand-rolled second copy. The claim was false and the two HAD
# drifted — which is what the `payload_unrendered` state was added to surface. These test the
# drift by behaviour rather than by counting implementations.


def _pushdata1(blob: bytes) -> bytes:
    return b"\x4c" + bytes([len(blob)]) + blob


def test_both_readers_see_a_payload_behind_an_OP_0() -> None:
    """A real MUT unlock ends `OP_1 OP_1 OP_0 OP_0`. The reveal reader fell through OP_0 to
    `break`, so it stopped before a marker the classifier could see — the two disagreed about
    real mainnet scripts."""
    inspector = GlyphInspector()
    payload = cbor2.dumps({"p": [1], "name": "behind-an-op-zero"})
    scriptsig = b"\x00" + bytes([len(GLY_MARKER)]) + GLY_MARKER + _pushdata1(payload)

    metadata = inspector._parse_reveal_scriptsig(scriptsig)
    envelope = inspector.classify_glyph_scriptsig(scriptsig)

    assert metadata is not None, "the reveal reader still stops at OP_0"
    assert metadata.name == "behind-an-op-zero"
    assert envelope is not None and envelope.kind == "payload"
    assert envelope.metadata.name == metadata.name, "the two readers disagree"


def test_a_truncated_push_is_not_clamped_into_a_plausible_item() -> None:
    """The hand-rolled copy sliced past the end of the script, and Python CLAMPS — so a push
    declaring more bytes than remain produced a SHORT item and left the position past the end.
    Clamping turns malformed bytes into a plausible-looking item; the shared walker stops."""
    inspector = GlyphInspector()
    real = cbor2.dumps({"p": [1], "name": "real"})
    # A marker, then a PUSHDATA1 declaring 200 bytes with only a few actually present.
    truncated = bytes([len(GLY_MARKER)]) + GLY_MARKER + b"\x4c" + bytes([200]) + real[:10]

    items, complete = inspector._walk_pushes(truncated)
    assert not complete, "a truncated push must report an incomplete walk"
    assert all(len(i) != 10 for i in items), "a clamped short item survived the walk"
    assert inspector._parse_reveal_scriptsig(truncated) is None


def test_the_real_mint_reveals_still_decode() -> None:
    """The honest-path half: the shared walker must not lose what the hand-rolled one read.

    Includes the 65,569-byte PUSHDATA4 body the old docstring called out by name, so the reason
    that copy existed is still covered rather than assumed gone.
    """
    inspector = GlyphInspector()
    decoded = 0
    for name in ("wave_update_chain_mainnet.json", "wave_fold_discriminating_chain_mainnet.json"):
        chain = json.loads((_FIX / name).read_text())
        # MINTS ONLY. This reader is the FULL-payload one: it hands the blob to `decode_payload`,
        # which refuses a `p`-less partial update by design — that refusal is the whole reason
        # `decode_update_payload` exists. Feeding it updates would test that split, not the walker.
        mint = min(chain["transactions"], key=lambda t: t["height"])
        tx = Transaction.from_hex(bytes.fromhex(mint["raw"]))
        for inp in tx.inputs:
            if inspector._parse_reveal_scriptsig(bytes(inp.unlocking_script.serialize())):
                decoded += 1
    assert decoded == 2, f"{decoded} of the 2 mint reveals decoded — the shared walker lost one"

    big = (_FIX / "glyph_reveal_cbor.bin").read_bytes()
    assert len(big) > 0xFFFF, "the PUSHDATA4 fixture shrank below the 0x4e threshold"
    scriptsig = bytes([len(GLY_MARKER)]) + GLY_MARKER + b"\x4e" + len(big).to_bytes(4, "little") + big
    assert inspector._parse_reveal_scriptsig(scriptsig) is not None, "PUSHDATA4 support was lost"
