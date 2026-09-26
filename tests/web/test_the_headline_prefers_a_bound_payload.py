"""The headline goes to a payload whose commit binds it, over one that merely mints — on the CLI and
on the page, which fetch the same outpoints and ask the same function.

#743 round 3, lane C's case K. Input 0 spends ``OP_2DROP`` + P2PKH — a script that drops the
``gly`` marker and the payload without checking either — and an output pushes input 0's OWN
outpoint as a singleton, so input 0 "mints" a decoy "Tether USD". Input 1 spends a real NFT commit
for "RealToken", minted too. A node accepts it. Both surfaces headlined the decoy ("1 of 2 glyphs
minted here", ``not-a-commit``, unflagged) and showed the bound token only as another glyph —
because round 2 preferred the first MINTING payload, and both mint.

Now the fetching surfaces fetch every minting payload's spent transaction (``binding_candidates``,
at most ``_MAX_BINDING_FETCHES``), and ``_reveal_attribution`` prefers, among the minting payloads:
one that reads ``bound``; then one that spent a commit pyrxd recognises; then the first. The decoy
is listed with its verdict, flagged, because another payload in the same transaction IS bound.

The honest neighbours keep their headline: a two-token mint whose payloads are both bound, and
the mainnet GLYPH deploy reveal (input 0).
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.
from tests.web.test_inspect_fetch_flow import _envelope, _first_pass, _flow, _glue, _tx

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SIG = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33
_P2PKH = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"


def _singleton(txid: str, vout: int = 0) -> bytes:
    from pyrxd.glyph.script import build_nft_locking_script
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.security.types import Hex20

    return build_nft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=txid, vout=vout))


def _nft_commit_tx(cbor: bytes):
    from pyrxd.glyph.script import build_commit_locking_script
    from pyrxd.hash import hash256
    from pyrxd.security.types import Hex20

    return _tx([(build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=True), 1000)], [])


def _case_k():
    """(reveal, [the transactions its inputs spend]). Input 0: the decoy on ``OP_2DROP`` + P2PKH,
    minting its own outpoint. Input 1: RealToken on a real NFT commit, minted."""
    decoy_suffix, _ = _envelope("Tether USD")
    real_suffix, real_cbor = _envelope("RealToken")
    decoy_prev = _tx([(b"\x6d" + _P2PKH, 1000)], [])  # OP_2DROP OP_DUP OP_HASH160 <pkh> ...
    real_commit = _nft_commit_tx(real_cbor)
    reveal = _tx(
        [(_singleton(decoy_prev.txid()), 1), (_singleton(real_commit.txid()), 1)],
        [(decoy_prev.txid(), 0, _SIG + decoy_suffix), (real_commit.txid(), 0, _SIG + real_suffix)],
    )
    return reveal, [decoy_prev, real_commit]


def _honest_two_token():
    """Two payloads, both on real NFT commits, both minted: nothing to prefer, input 0 stays."""
    s1, c1 = _envelope("First")
    s2, c2 = _envelope("Second")
    k1, k2 = _nft_commit_tx(c1), _nft_commit_tx(c2)
    reveal = _tx(
        [(_singleton(k1.txid()), 1), (_singleton(k2.txid()), 1)],
        [(k1.txid(), 0, _SIG + s1), (k2.txid(), 0, _SIG + s2)],
    )
    return reveal, [k1, k2]


def _glyph_deploy():
    """The mainnet GLYPH deploy reveal and the commit both its payloads spent (vouts 0 and 33)."""
    from pyrxd.transaction.transaction import Transaction

    fixtures = _REPO_ROOT / "tests" / "fixtures"
    reveal = json.loads((fixtures / "glyph_deploy_reveal_mainnet.json").read_text(encoding="utf-8"))
    commit = json.loads((fixtures / "glyph_deploy_commit_mainnet.json").read_text(encoding="utf-8"))
    return Transaction.from_hex(bytes.fromhex(reveal["raw"])), [Transaction.from_hex(bytes.fromhex(commit["raw"]))]


@functools.lru_cache(maxsize=1)
def _other_tx():
    """What a server answers instead of the transaction asked for: a real, hash-valid
    transaction — just not that one."""
    return _tx([(b"\x51", 7)], [])


class _Stub:
    """*fail*: txids the server refuses. *swap*: txids it answers with another transaction for."""

    def __init__(self, txs, *, fail=(), swap=()) -> None:
        self.by_txid = {t.txid(): t.serialize() for t in txs}
        self.fail, self.swap = set(fail), set(swap)
        self.requested: list[str] = []

    async def get_transaction(self, txid):
        self.requested.append(str(txid))
        if str(txid) in self.fail:
            raise TimeoutError("server refused")
        if str(txid) in self.swap:
            return _other_tx().serialize()
        return self.by_txid[str(txid)]


def _cli(reveal, prevs, *, fail=(), swap=()) -> tuple[dict, str, list[str]]:
    from pyrxd.cli.glyph_inspect import _inspect_txid_inner, _render_txid_human

    client = _Stub([reveal, *prevs], fail=fail, swap=swap)
    payload = asyncio.run(_inspect_txid_inner(client, reveal.txid()))
    return payload, _render_txid_human(payload), client.requested


def _page(reveal, prevs, *, fail=(), swap=()) -> dict:
    """The page's own `onFetchTxid`, with the real glue's answers for the arguments it passed.
    A txid in *fail* is answered with an error frame; one in *swap* with another transaction's
    bytes, which the page's own fetch helper refuses by hash."""
    limit = _flow("00" * 32, {}, [])["__constants__"]["max_rows_shown"]
    server = {t.txid(): {"hex": t.serialize().hex()} for t in [reveal, *prevs]}
    server |= {t: {"error": "daemon busy"} for t in fail}
    server |= {t: {"hex": _other_tx().serialize().hex()} for t in swap}
    first = [_first_pass(reveal, limit)]
    recorded = _flow(reveal.txid(), server, first)
    answers = [_glue().spent_output_bindings(*call) for call in recorded["binding_calls"]]
    flow = _flow(reveal.txid(), server, first, answers)
    assert flow["binding_calls"] == recorded["binding_calls"]
    assert "harness: no canned" not in flow["rendered"]
    flow["answers"] = answers
    return flow


def _lines(text: str) -> list[str]:
    return text.split("\n")


class TestCaseK:
    def test_the_cli_headlines_the_bound_payload_and_flags_the_decoy(self) -> None:
        reveal, prevs = _case_k()
        payload, text, requested = _cli(reveal, prevs)
        assert requested == [reveal.txid(), prevs[0].txid(), prevs[1].txid()], "both minting payloads' commits"
        metadata = payload["metadata"]
        assert (metadata["input_index"], metadata["name"]) == (1, "RealToken")
        assert metadata["payload_binding"]["state"] == "bound"
        decoy = next(row for row in payload["metadata_inputs"] if row["input_index"] == 0)
        assert (decoy["name"], decoy["binding_state"], decoy["binding_warning"]) == ("Tether USD", "not-a-commit", True)
        assert "Reveal metadata (from input 1 — 1 of 2 glyphs minted here" in text
        (row,) = [line for line in _lines(text) if "Tether USD" in line]
        assert row.endswith("— payload binding: not-a-commit *** treat as unattributed"), row

    def test_the_page_headlines_the_bound_payload_and_flags_the_decoy(self) -> None:
        reveal, prevs = _case_k()
        flow = _page(reveal, prevs)
        assert flow["requested"] == [reveal.txid(), prevs[0].txid(), prevs[1].txid()]
        (call,) = flow["binding_calls"]
        assert set(json.loads(call[2])) == {f"{prevs[0].txid()}:0", f"{prevs[1].txid()}:0"}
        assert "payload" in flow["answers"][0], "the headline moved: the page gets the classification redone"
        text = flow["rendered"]
        assert "Reveal metadata (from input 1 — 1 of 2 glyphs minted here)" in text
        lines = _lines(text)
        assert lines[lines.index("payload binding") + 1].startswith("bound — ")
        # The other-glyph row — not the raw-JSON drawer, which names it too.
        (row,) = [line for line in lines if line.startswith("nft — Tether USD")]
        assert row.endswith("— payload binding: not-a-commit *** treat as unattributed"), row

    def test_the_two_surfaces_say_the_same_about_the_decoy(self) -> None:
        reveal, prevs = _case_k()
        _payload, cli, _ = _cli(reveal, prevs)
        page = _page(reveal, prevs)["rendered"]
        for said in ("1 of 2 glyphs minted here", "payload binding: not-a-commit *** treat as unattributed"):
            assert said in cli and said in page, said


class TestTheHonestNeighboursKeepTheirHeadline:
    @pytest.mark.parametrize("world", [_honest_two_token, _glyph_deploy], ids=["two-bound-tokens", "mainnet-deploy"])
    def test_input_0_stays_the_headline_and_nothing_is_flagged(self, world) -> None:
        reveal, prevs = world()
        payload, text, _requested = _cli(reveal, prevs)
        assert payload["metadata"]["input_index"] == 0
        assert payload["metadata"]["payload_binding"]["state"] == "bound"
        others = [row for row in payload["metadata_inputs"] if row["input_index"] != 0]
        assert others and all(row["binding_state"] == "bound" and not row["binding_warning"] for row in others)
        assert "treat as unattributed" not in text
        page = _page(reveal, prevs)["rendered"]
        assert "Reveal metadata (from input 0 — 1 of 2 glyphs minted here)" in page
        assert "treat as unattributed" not in page

    def test_a_reveal_minting_one_glyph_still_costs_one_fetch_and_no_second_classification(self) -> None:
        """The common case must not pay for the decoy's: one candidate, one round trip, and the
        binding is the one field that changes."""
        s, c = _envelope("Solo")
        k = _nft_commit_tx(c)
        reveal = _tx([(_singleton(k.txid()), 1)], [(k.txid(), 0, _SIG + s)])
        flow = _page(reveal, [k])
        assert flow["requested"] == [reveal.txid(), k.txid()]
        assert "payload" not in flow["answers"][0]
        assert flow["answers"][0]["binding"]["state"] == "bound"


class TestTheRanking:
    """The middle tier, and the cap — asked of the function both surfaces call."""

    def test_a_recognised_commit_outranks_a_payload_that_spent_none(self) -> None:
        """No payload binds: input 1's commit committed to a different payload (a spend no node
        accepts — the shape stands in for any recognised-but-unbound commit). It still outranks the
        decoy, which spent no commit at all."""
        from pyrxd.glyph._inspect_core import _spent_output_bindings

        decoy_suffix, _ = _envelope("Tether USD")
        real_suffix, _ = _envelope("RealToken")
        _, other_cbor = _envelope("something else")
        decoy_prev = _tx([(b"\x6d" + _P2PKH, 1000)], [])
        commit = _nft_commit_tx(other_cbor)
        reveal = _tx(
            [(_singleton(decoy_prev.txid()), 1), (_singleton(commit.txid()), 1)],
            [(decoy_prev.txid(), 0, _SIG + decoy_suffix), (commit.txid(), 0, _SIG + real_suffix)],
        )
        spent = {f"{decoy_prev.txid()}:0": decoy_prev.serialize(), f"{commit.txid()}:0": commit.serialize()}
        answer = _spent_output_bindings(reveal.txid(), reveal.serialize(), spent)
        assert (answer["input_index"], answer["binding"]["state"], answer["moved"]) == (1, "mismatch", True)

    def test_without_spent_scripts_the_first_minting_payload_is_the_headline(self) -> None:
        """The network-free rule is round 2's: nothing can be ranked without a commit to read."""
        from pyrxd.glyph._inspect_core import _classify_raw_tx

        reveal, _prevs = _case_k()
        assert _classify_raw_tx(reveal.txid(), reveal.serialize())["metadata"]["input_index"] == 0

    def test_the_fetch_list_is_capped_and_starts_with_the_network_free_headline(self) -> None:
        from pyrxd.glyph._inspect_core import _MAX_BINDING_FETCHES, _classify_raw_tx

        n = _MAX_BINDING_FETCHES + 3
        commits = [_nft_commit_tx(_envelope(f"g{i}")[1]) for i in range(n)]
        reveal = _tx(
            [(_singleton(c.txid()), 1) for c in commits],
            [(c.txid(), 0, _SIG + _envelope(f"g{i}")[0]) for i, c in enumerate(commits)],
        )
        payload = _classify_raw_tx(reveal.txid(), reveal.serialize())
        assert payload["binding_candidates"] == [f"{c.txid()}:0" for c in commits[:_MAX_BINDING_FETCHES]]
        assert payload["binding_candidates"][0] == payload["metadata"]["input_outpoint"]
        # The concept doc states the cap as a number; it is a claim, so it is checked.
        doc = (_REPO_ROOT / "docs" / "concepts" / "glyph-inspect-tool.md").read_text(encoding="utf-8")
        assert f"at most {_MAX_BINDING_FETCHES}" in " ".join(doc.split())


# ─────────────────────────── a check that did not happen is said (#743 round 4) ──
#
# Lane C, round 4. The ranking can only move the headline to a payload whose commit it read. When
# the server refused that fetch (Kfail), answered it with another hash-valid transaction (Kswap),
# or the payload was past the fetch limit (K9), the real payload's row showed NOTHING and the decoy
# kept the headline unflagged — round 2's headline, back, with no sign a check had been skipped.
# Now every other minting payload's row reads `unchecked` with the reason; the number past the
# limit is shown, naming it; and a headline that is not bound says, flagged, that it is not settled.

_UNSETTLED = "a bound one among them would head this card instead, so this headline is not settled"


def _decoys_then_real(n_decoys: int):
    """*n_decoys* uncommitted decoys (``OP_2DROP`` + P2PKH, each minting its own outpoint), then a
    real NFT commit's payload, minted. Returns (reveal, [what its inputs spend], the real commit)."""
    prevs, ins, outs = [], [], []
    for d in range(n_decoys):
        suffix, _ = _envelope(f"Decoy{d}")
        prev = _tx([(b"\x6d" + _P2PKH, 1000 + d)], [])
        prevs.append(prev)
        ins.append((prev.txid(), 0, _SIG + suffix))
        outs.append((_singleton(prev.txid()), 1))
    suffix, cbor = _envelope("RealToken")
    real = _nft_commit_tx(cbor)
    prevs.append(real)
    ins.append((real.txid(), 0, _SIG + suffix))
    outs.append((_singleton(real.txid()), 1))
    return _tx(outs, ins), prevs, real


def _cli_row(text: str, name: str) -> str:
    (row,) = [line for line in _lines(text) if line.startswith("  input ") and line.split(" — ")[0].endswith(name)]
    return row


def _page_row(text: str, name: str) -> str:
    """The other-glyph row naming *name* — not the raw-JSON drawer, which names it too."""
    (row,) = [line for line in _lines(text) if line.startswith(f"nft — {name} — ")]
    return row


def _page_caveat(text: str) -> str | None:
    lines = _lines(text)
    return lines[lines.index("payload binding caveat") + 1] if "payload binding caveat" in lines else None


class TestACheckThatDidNotHappenIsSaid:
    def test_k9_a_real_payload_past_the_fetch_limit(self) -> None:
        from pyrxd.glyph._inspect_core import _MAX_BINDING_FETCHES as cap

        reveal, prevs, _real = _decoys_then_real(cap)
        payload, cli, requested = _cli(reveal, prevs)
        assert len(requested) == 1 + cap, "the reveal, then the first `cap` commits: the real one is past the limit"
        metadata = payload["metadata"]
        assert (metadata["name"], metadata["payload_binding"]["state"]) == ("Decoy0", "not-a-commit")
        assert metadata["bindings_past_cap"] == {"count": 1, "cap": cap}
        past = f"not checked: past the limit of {cap} commits fetched for one transaction"
        caveat = f"1 other minting payload(s) went unchecked (1 past the limit of {cap}); {_UNSETTLED}"
        count = f"(1 minting payload(s) past the limit of {cap} commits fetched were not checked)"
        assert f"  *** {caveat}" in _lines(cli)
        assert _cli_row(cli, "RealToken").endswith(f"payload binding: unchecked ({past})")
        assert f"  {count}" in _lines(cli)
        page = _page(reveal, prevs)["rendered"]
        assert _page_caveat(page) == caveat
        assert _page_row(page, "RealToken").endswith(f"payload binding: unchecked ({past})")
        assert count in _lines(page)
        # The concept doc names the limit in this sentence too; a claim, so it is checked.
        doc = (_REPO_ROOT / "docs" / "concepts" / "glyph-inspect-tool.md").read_text(encoding="utf-8")
        assert f"one past the limit of {cap} reads `unchecked` too" in " ".join(doc.split())

    def test_kfail_the_server_refuses_the_real_commit(self) -> None:
        reveal, prevs, real = _decoys_then_real(1)
        payload, cli, _ = _cli(reveal, prevs, fail={real.txid()})
        assert payload["metadata"]["name"] == "Decoy0"
        assert "bindings_past_cap" not in payload["metadata"], "nothing was past the limit"
        caveat = f"1 other minting payload(s) went unchecked (1 could not be fetched); {_UNSETTLED}"
        assert f"  *** {caveat}" in _lines(cli)
        assert _cli_row(cli, "RealToken").endswith("payload binding: unchecked (server refused)")
        page = _page(reveal, prevs, fail={real.txid()})["rendered"]
        assert _page_caveat(page) == caveat
        assert _page_row(page, "RealToken").endswith("payload binding: unchecked (server error: daemon busy)")
        assert "were not checked" not in page

    def test_kswap_the_server_answers_with_another_transaction(self) -> None:
        reveal, prevs, real = _decoys_then_real(1)
        payload, cli, _ = _cli(reveal, prevs, swap={real.txid()})
        assert payload["metadata"]["name"] == "Decoy0"
        other = _other_tx().txid()
        caveat = f"1 other minting payload(s) went unchecked (1 could not be fetched); {_UNSETTLED}"
        assert f"  *** {caveat}" in _lines(cli)
        assert _cli_row(cli, "RealToken").endswith(
            f"payload binding: unchecked (it is not the transaction this input spent: it hashes to {other})"
        )
        page = _page(reveal, prevs, swap={real.txid()})["rendered"]
        assert _page_caveat(page) == caveat
        assert _page_row(page, "RealToken").endswith(
            f"payload binding: unchecked (the server's answer is not the transaction asked for: it hashes to {other})"
        )

    def test_a_bound_headline_is_settled_though_another_fetch_failed(self) -> None:
        """The other branch of the caveat. It is about a headline that may not be the answer; a
        bound one is, whatever happened to the rest — which still get their own `unchecked` row."""
        reveal, prevs = _honest_two_token()
        payload, cli, _ = _cli(reveal, prevs, fail={prevs[1].txid()})
        binding = payload["metadata"]["payload_binding"]
        assert binding["state"] == "bound" and "unsettled" not in binding
        assert _UNSETTLED not in cli
        assert _cli_row(cli, "Second").endswith("payload binding: unchecked (server refused)")
        page = _page(reveal, prevs, fail={prevs[1].txid()})["rendered"]
        assert _page_caveat(page) is None
        assert _page_row(page, "Second").endswith("payload binding: unchecked (server error: daemon busy)")


class TestTheHonestNeighboursHaveNothingUnchecked:
    @pytest.mark.parametrize("world", [_honest_two_token, _glyph_deploy], ids=["two-bound-tokens", "mainnet-deploy"])
    def test_no_row_is_unchecked_and_the_headline_is_settled(self, world) -> None:
        reveal, prevs = world()
        payload, cli, _ = _cli(reveal, prevs)
        assert "unsettled" not in payload["metadata"]["payload_binding"]
        assert "bindings_past_cap" not in payload["metadata"]
        assert all(row.get("binding_state") != "unchecked" for row in payload["metadata_inputs"])
        assert "unchecked" not in cli and "were not checked" not in cli
        page = _page(reveal, prevs)["rendered"]
        assert _page_caveat(page) is None
        assert "payload binding: unchecked" not in page and "were not checked" not in page

    def test_a_single_glyph_has_nothing_else_to_check(self) -> None:
        s, c = _envelope("Solo")
        k = _nft_commit_tx(c)
        reveal = _tx([(_singleton(k.txid()), 1)], [(k.txid(), 0, _SIG + s)])
        payload, cli, _ = _cli(reveal, [k])
        binding = payload["metadata"]["payload_binding"]
        assert binding["state"] == "bound" and "unsettled" not in binding
        assert "unchecked" not in cli and "were not checked" not in cli
        page = _page(reveal, [k])["rendered"]
        assert _page_caveat(page) is None and "were not checked" not in page
