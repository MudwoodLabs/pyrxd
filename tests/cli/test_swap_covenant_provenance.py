"""The swap's covenant is ONE output — found by provenance, never "any output at the covenant script".

The covenant scriptPubKey is a pure function of the swap's public terms, so anyone can pay it. These
tests drive the REAL ``swap status`` / ``build-claim`` / ``build-refund`` / ``recover-preimage``
commands (the ``swap`` group entered directly, so a fake ElectrumX can be injected) over chains
built from the production transaction builders, with an extra payment to the covenant script:

* the covenant is the pinned outpoint, or the earliest-confirmed payment to the script; whether it
  is live, its value and its height are that output's own, and other outputs are reported only;
* ``build-claim`` / ``build-refund`` resolve a second output by the same rule, and accept
  ``--covenant-outpoint``.

They also pin what each verdict may claim when it rests on ONE server's word: a BTC refund still in
the mempool, a refund report from one Esplora, a covenant spend reported by one ElectrumX.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from pyrxd.btc_wallet.taproot import btc_txid_from_raw
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

from .test_swap_recovery import P, _claim_tx, _refund_tx
from .test_swap_recovery_cmds import (
    _ESPLORA,
    _OUTPOINT,
    FEE_VALUE,
    _build,
    _checked_status,
    _FakeEsplora,
    _funding_and_spend,
    _NoBroadcastClient,
    _recover,
    _serve,
    _status,
)
from .test_swap_recovery_cmds import swap as swap_fixture  # noqa: F401 - registered as a fixture by that name

REPO = Path(__file__).resolve().parents[2]

#: The sentences that used to close a "both legs spent" verdict outright, on one server's word.
_DEFINITIVE = (
    "There is nothing left to claim or refund.",
    "there is nothing left on chain to claim or refund",
    "Nothing is left to claim or refund",
)


@pytest.fixture
def case(request):
    return request.getfixturevalue("swap_fixture")


def _payment_to(spk: bytes, value: int, tag: str) -> Transaction:
    """A transaction paying ``value`` photons to ``spk`` from an unrelated input. ``tag`` keeps txids distinct."""
    return Transaction(
        tx_inputs=[TransactionInput(source_txid=tag * 32, source_output_index=0, unlocking_script=Script(b"\x51"))],
        tx_outputs=[TransactionOutput(Script(spk), value)],
    )


class _Chain(_NoBroadcastClient):
    """A fake ElectrumX serving a covenant script's real history, UTXO set and transaction bytes.

    ``mined`` is ``[(tx, height), ...]`` for every transaction touching the covenant script;
    ``live`` is the subset of ``(tx, vout)`` still unspent. The fee key's UTXO is always served.
    """

    def __init__(self, case, mined: list[tuple[Any, int]], live: list[tuple[Any, int]], *, tip: int) -> None:
        heights = {tx.txid(): h for tx, h in mined}
        utxos = [
            UtxoRecord(tx_hash=tx.txid(), tx_pos=vout, value=int(tx.outputs[vout].satoshis), height=heights[tx.txid()])
            for tx, vout in live
        ]
        super().__init__(
            {case["cov_sh"]: utxos, case["fee_sh"]: [UtxoRecord("cd" * 32, 1, FEE_VALUE, 90)]},
            tip=tip,
        )
        self._cov_sh = case["cov_sh"]
        self._history = [{"tx_hash": tx.txid(), "height": h} for tx, h in mined]
        self._txs = {tx.txid(): tx.serialize() for tx, _ in mined}

    async def get_history(self, sh):
        return self._history if sh == self._cov_sh else []

    async def get_transaction(self, txid):
        if txid not in self._txs:
            raise OSError(f"transaction {txid} not found")
        return self._txs[txid]


def _write(case, **fields: Any) -> None:
    doc = json.loads(case["keys"].read_text())
    doc.update(fields)
    case["keys"].write_text(json.dumps(doc))


def _json_status(case, client, *extra) -> dict[str, Any]:
    res = _checked_status(case, *extra, client=client, output_mode="json")
    assert res.exit_code == 0, res.output
    return json.loads(res.output)


# =========================================================================== outcome 1: swap status


def test_status_a_refunded_covenant_plus_a_payment_to_its_script_still_says_refund_your_btc(case, monkeypatch) -> None:
    """Covenant refunded at 125; another output, of a different value, paid to the same script at 128.

    With the covenant amount recorded, the live output is not a candidate: the covenant is the spent
    funding output, and the verdict is COUNTER_LEG_LOCKED with its refund-now advice — not LOCKED
    with a deadline counted from the other output's height."""
    _write(case, rxd_covenant_amount=100_000)
    funding, refund = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")
    _serve(monkeypatch, _FakeEsplora({"spent": False}))  # the taker's BTC is still in the HTLC

    def chain():
        return _Chain(case, [(funding, 100), (refund, 125), (dust, 128)], [(dust, 0)], tip=130)

    res = _checked_status(case, client=chain())
    assert res.exit_code == 0, res.output
    assert "covenant SPENT" in res.output
    assert "spent by   : MAKER_REFUND" in res.output
    assert "situation  : COUNTER_LEG_LOCKED" in res.output
    assert "refund your BTC now" in res.output
    assert "keep watching" not in res.output
    assert "funded@128" not in res.output
    assert "1 other output" in res.output
    assert "none carries the recorded covenant amount" in res.output

    doc = _json_status(case, chain())
    assert doc["situation"] == "COUNTER_LEG_LOCKED"
    assert doc["chain"]["covenant_state"] == "spent"
    assert doc["chain"]["covenant_outpoint"] == f"{funding.txid()}:0"
    assert doc["chain"]["ignored_outputs"] == 1
    assert "blocks_to_refund" not in doc["chain"]


def test_status_without_a_recorded_amount_a_spent_output_and_a_live_one_name_no_covenant(case, monkeypatch) -> None:
    """The same chain with no amount and no outpoint in the file: the earlier output is spent and a
    later one is live, and either could be the swap's. Neither is named — never LIVE, never SPENT."""
    funding, refund = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")
    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    res = _checked_status(case, client=_Chain(case, [(funding, 100), (refund, 125), (dust, 128)], [(dust, 0)], tip=130))
    assert res.exit_code == 0, res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert f"{funding.txid()}:0" in res.output and f"{dust.txid()}:0" in res.output
    assert "--covenant-outpoint" in res.output
    assert "keep watching" not in res.output
    assert "covenant LIVE" not in res.output and "covenant SPENT" not in res.output


def test_status_a_live_covenant_reports_its_own_value_and_height_not_the_scripts_total(case) -> None:
    """A live covenant plus a later payment to its script: value and height are the covenant's own.

    ``value_photons`` used to be the SUM of every output at the script (100546 here)."""
    funding, _ = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")

    def chain():
        return _Chain(case, [(funding, 100), (dust, 103)], [(funding, 0), (dust, 0)], tip=110)

    res = _status(case, client=chain())
    assert res.exit_code == 0, res.output
    assert "covenant LIVE" in res.output
    assert "funded@100 depth=11 value=100000 ph" in res.output
    assert "1 other output" in res.output
    # Unpinned: the other output is reported as not TAKEN, never asserted to be someone else's.
    assert "the earliest-confirmed one was taken as the covenant" in res.output
    assert "not this swap's covenant" not in res.output

    js = _status(case, client=chain(), output_mode="json")
    chain_doc = json.loads(js.output)["chain"]
    assert chain_doc["value_photons"] == 100_000
    assert chain_doc["funding_height"] == 100
    assert chain_doc["refund_opens_height"] == 120
    assert chain_doc["covenant_outpoint"] == f"{funding.txid()}:0"
    assert chain_doc["covenant_identified_by"] == "earliest-confirmed"


def test_status_an_earlier_payment_of_the_wrong_value_is_not_the_covenant(case) -> None:
    """With the covenant amount in the file, an EARLIER payment of another value is skipped.

    Without the value check the earliest output's height (90) became the covenant's funding height,
    opening the refund window ten blocks early on the screen."""
    _write(case, rxd_covenant_amount=100_000)
    funding, _ = _funding_and_spend(case, "refund")
    early = _payment_to(case["cov"].funded_spk, 546, "77")

    js = _status(
        case,
        client=_Chain(case, [(early, 90), (funding, 100)], [(early, 0), (funding, 0)], tip=110),
        output_mode="json",
    )
    assert js.exit_code == 0, js.output
    chain_doc = json.loads(js.output)["chain"]
    assert chain_doc["funding_height"] == 100
    assert chain_doc["value_photons"] == 100_000
    assert chain_doc["covenant_outpoint"] == f"{funding.txid()}:0"


@pytest.mark.parametrize("how", ["flag", "file"])
def test_status_a_pinned_covenant_outpoint_wins_over_the_selection_rule(case, how) -> None:
    """No amount in the file and a payment EARLIER than the funding: the selection rule alone picks
    the payment. A pin — the ``--covenant-outpoint`` flag or the file's ``rxd_covenant_outpoint`` —
    names the funding instead."""
    funding, _ = _funding_and_spend(case, "refund")
    early = _payment_to(case["cov"].funded_spk, 546, "77")
    pin = f"{funding.txid()}:0"
    extra: tuple[str, ...] = ("--covenant-outpoint", pin) if how == "flag" else ()
    if how == "file":
        _write(case, rxd_covenant_outpoint=pin)

    js = _status(
        case,
        *extra,
        client=_Chain(case, [(early, 90), (funding, 100)], [(early, 0), (funding, 0)], tip=110),
        output_mode="json",
    )
    assert js.exit_code == 0, js.output
    chain_doc = json.loads(js.output)["chain"]
    assert chain_doc["covenant_identified_by"] == "pinned"
    assert chain_doc["covenant_outpoint"] == pin
    assert chain_doc["funding_height"] == 100
    assert chain_doc["value_photons"] == 100_000


def test_status_a_pinned_covenant_that_was_spent_reads_spent_whatever_else_pays_the_script(case) -> None:
    funding, refund = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")
    _write(case, rxd_covenant_outpoint=f"{funding.txid()}:0")
    js = _status(
        case,
        client=_Chain(case, [(funding, 100), (refund, 125), (dust, 128)], [(dust, 0)], tip=130),
        output_mode="json",
    )
    assert js.exit_code == 0, js.output
    doc = json.loads(js.output)
    assert doc["chain"]["covenant_state"] == "spent"
    assert doc["chain"]["covenant_spend"]["kind"] == "MAKER_REFUND"


class _HistoryWithheld(_Chain):
    """Serves the script's history but not the bytes of its funding transaction."""

    def __init__(self, *a: Any, withhold: str, **kw: Any) -> None:
        super().__init__(*a, **kw)
        del self._txs[withhold]


def test_status_an_unreadable_history_names_no_covenant_and_asks_for_the_outpoint(case, monkeypatch) -> None:
    """The refund + stray payment chain, with the funding transaction's bytes withheld: whether an
    earlier, spent output was the covenant cannot be ruled out, so the live payment is NOT taken for
    the covenant — the screen says so and names the flag. With the pin, the read resolves."""
    funding, refund = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")
    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    mined = [(funding, 100), (refund, 125), (dust, 128)]

    res = _checked_status(case, client=_HistoryWithheld(case, mined, [(dust, 0)], tip=130, withhold=funding.txid()))
    assert res.exit_code == 0, res.output
    assert "covenant UNIDENTIFIED" in res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert "--covenant-outpoint" in res.output
    assert "LIVE" not in res.output

    built = _build(
        case,
        "build-claim",
        "--preimage",
        P.hex(),
        client=_HistoryWithheld(case, mined, [(dust, 0)], tip=130, withhold=funding.txid()),
    )
    assert built.exit_code == 1, built.output
    assert "--covenant-outpoint" in built.output


@pytest.mark.parametrize("bad", ["not-an-outpoint", "zz" * 32 + ":0", "ab" * 32 + ":+1"])
def test_status_a_malformed_covenant_outpoint_is_refused_up_front(case, bad) -> None:
    res = _status(case, "--covenant-outpoint", bad)
    assert res.exit_code != 0
    assert "invalid --covenant-outpoint" in res.output


def test_status_without_check_chain_does_not_refuse_a_malformed_file_pin(case) -> None:
    """The pin is only read by --check-chain; the offline identity view must not be refused over it."""
    from .test_swap_recovery_cmds import _ctx, _invoke

    _write(case, rxd_covenant_outpoint="not-an-outpoint")
    res = _invoke(["status", "--swap-file", str(case["keys"])], _ctx())
    assert res.exit_code == 0, res.output
    assert "hashlock H" in res.output
    assert _status(case).exit_code != 0  # and --check-chain does refuse it


def test_status_honest_path_one_covenant_output_reads_live_with_no_warning(case) -> None:
    funding, _ = _funding_and_spend(case, "refund")
    res = _status(case, client=_Chain(case, [(funding, 100)], [(funding, 0)], tip=110))
    assert res.exit_code == 0, res.output
    assert "covenant LIVE" in res.output
    assert "funded@100 depth=11 value=100000 ph" in res.output
    assert "other output" not in res.output
    assert "situation  : LOCKED" in res.output


# =========================================================================== outcome 1: cold builders


def _two_outputs(case, *, confirmations: int, dust_height: int = 103) -> _NoBroadcastClient:
    tip = 100 + confirmations - 1
    return _NoBroadcastClient(
        {
            case["cov_sh"]: [
                UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100),
                UtxoRecord(tx_hash="77" * 32, tx_pos=0, value=546, height=dust_height),
            ],
            case["fee_sh"]: [UtxoRecord(tx_hash="cd" * 32, tx_pos=1, value=FEE_VALUE, height=90)],
        },
        tip=tip,
    )


def test_build_claim_builds_on_the_covenant_when_someone_else_pays_its_script(case) -> None:
    """A second output at the covenant script is resolved by the selection rule, not refused."""
    res = _build(case, "build-claim", "--preimage", P.hex(), client=_two_outputs(case, confirmations=5))
    assert res.exit_code == 0, res.output
    assert f"covenant   : {'ab' * 32}:0   carrier=100000 photons" in res.output
    assert "cannot resolve a single covenant" not in res.output


def test_build_refund_builds_on_the_covenant_when_someone_else_pays_its_script(case) -> None:
    res = _build(case, "build-refund", client=_two_outputs(case, confirmations=25))
    assert res.exit_code == 0, res.output
    assert f"covenant   : {'ab' * 32}:0   carrier=100000 photons" in res.output


def test_build_claim_covenant_outpoint_names_the_covenant_the_rule_cannot(case) -> None:
    """An EARLIER payment, and no amount in the file to tell them apart: the selection rule picks the
    payment, the rebuilt covenant does not match, and the refusal says what to pass. The flag then
    builds the right spend."""
    client = _two_outputs(case, confirmations=5, dust_height=99)
    refused = _build(case, "build-claim", "--preimage", P.hex(), client=client)
    assert refused.exit_code == 1, refused.output
    assert "--covenant-outpoint" in refused.output

    res = _build(
        case,
        "build-claim",
        "--preimage",
        P.hex(),
        "--covenant-outpoint",
        f"{'ab' * 32}:0",
        client=_two_outputs(case, confirmations=5, dust_height=99),
    )
    assert res.exit_code == 0, res.output
    assert f"covenant   : {'ab' * 32}:0   carrier=100000 photons" in res.output


def test_build_refund_accepts_the_covenant_outpoint_flag_too(case) -> None:
    # The payment is EARLIER (99), so without the flag the rule would pick it: the flag decides.
    res = _build(
        case,
        "build-refund",
        "--covenant-outpoint",
        f"{'ab' * 32}:0",
        client=_two_outputs(case, confirmations=25, dust_height=99),
    )
    assert res.exit_code == 0, res.output
    assert f"covenant   : {'ab' * 32}:0" in res.output


def test_build_claim_refuses_a_covenant_outpoint_that_is_not_live(case) -> None:
    res = _build(
        case,
        "build-claim",
        "--preimage",
        P.hex(),
        "--covenant-outpoint",
        f"{'ee' * 32}:0",
        client=_two_outputs(case, confirmations=5),
    )
    assert res.exit_code == 1, res.output
    assert f"{'ee' * 32}:0" in res.output


def test_build_claim_refuses_when_the_covenant_is_spent_and_only_a_stray_payment_remains(case) -> None:
    """The covenant was refunded and another output (of a different value) is still live at its
    script: with the amount recorded, the builder reports the covenant spent and builds nothing on
    the other output. Without it, it refuses as unidentified and names the flag."""
    funding, refund = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")

    def chain():
        return _Chain(case, [(funding, 100), (refund, 125), (dust, 128)], [(dust, 0)], tip=130)

    unrecorded = _build(case, "build-claim", "--preimage", P.hex(), client=chain())
    assert unrecorded.exit_code == 1, unrecorded.output
    assert "--covenant-outpoint" in unrecorded.output
    assert "BUILT, NOT BROADCAST" not in unrecorded.output

    _write(case, rxd_covenant_amount=100_000)
    res = _build(case, "build-claim", "--preimage", P.hex(), client=chain())
    assert res.exit_code == 1, res.output
    assert "already spent" in res.output
    assert "do not carry the recorded covenant amount" in res.output
    assert "BUILT, NOT BROADCAST" not in res.output


def test_build_claim_honest_path_single_output_still_builds(case) -> None:
    funding, _ = _funding_and_spend(case, "refund")
    res = _build(
        case, "build-claim", "--preimage", P.hex(), client=_Chain(case, [(funding, 100)], [(funding, 0)], tip=104)
    )
    assert res.exit_code == 0, res.output
    assert f"covenant   : {funding.txid()}:0   carrier=100000 photons" in res.output


# =========================================================================== outcome 1: the writers


def _persisted_keys(path: Path) -> set[str]:
    """String keys of every dict literal passed to ``merge_into_mode_600`` in ``path``."""
    keys: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "merge_into_mode_600":
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    keys |= {k.value for k in arg.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return keys


def test_every_harness_that_pins_the_covenant_persists_its_outpoint() -> None:
    """The pin ``swap status`` / the cold builders read must have a writer: every in-tree harness that
    writes a recovery file (``rxd_covenant_spk``) and pins the covenant (``post_asset_lock_revalidate``)
    persists ``rxd_covenant_outpoint``. The set is derived from the scripts, not listed."""
    writers = [
        p
        for p in sorted((REPO / "scripts").glob("*.py"))
        if "post_asset_lock_revalidate" in p.read_text() and '"rxd_covenant_spk"' in p.read_text()
    ]
    assert len(writers) >= 3, writers  # non-vacuity: dust_swap_run, eth_swap_run, eth_swap_grief_run
    missing = [p.name for p in writers if "rxd_covenant_outpoint" not in _persisted_keys(p)]
    assert missing == []


def test_the_recovery_file_pin_is_parsed() -> None:
    from pyrxd.cli import swap_recovery as sr

    assert "rxd_covenant_outpoint" in {f.name for f in __import__("dataclasses").fields(sr.RecoveryExtras)}


# =========================================================================== outcome 2: one server's word


def _btc_spent_by(monkeypatch, raw: bytes, *, confirmed: bool | None) -> None:
    spender = btc_txid_from_raw(raw)
    outspend: dict[str, Any] = {"spent": True, "txid": spender, "vin": 0}
    if confirmed is not None:
        outspend["status"] = {"confirmed": confirmed}
    _serve(monkeypatch, _FakeEsplora(outspend, tx_hex={spender: raw.hex()}))


def _spent(case, kind: str, *, spend_height: int = 125):
    funding, spend = _funding_and_spend(case, kind)
    return _Chain(case, [(funding, 100), (spend, spend_height)], [], tip=130)


def test_an_unconfirmed_btc_refund_beside_a_covenant_refund_is_not_settled(case, monkeypatch) -> None:
    """Esplora reports the taker's BTC refund in the mempool. The BTC claim branch has no timelock,
    so until the refund confirms the maker (holding p) can replace it with a claim. This used to read
    SETTLED, "There is nothing left to claim or refund"."""
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=False)
    res = _checked_status(case, client=_spent(case, "refund"))
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): REFUND_REPORTED_UNCONFIRMED" in res.output
    assert "SETTLED" not in res.output
    assert "situation  : COUNTER_LEG_REFUND_UNCONFIRMED" in res.output
    assert "NOT CONFIRMED" in res.output
    assert not any(s in res.output for s in _DEFINITIVE)

    doc = _json_status(case, _spent(case, "refund"))
    assert doc["situation"] == "COUNTER_LEG_REFUND_UNCONFIRMED"
    assert doc["counter_leg"]["state"] == "REFUND_REPORTED_UNCONFIRMED"


def test_an_unconfirmed_btc_refund_beside_a_taker_claim_tells_the_maker_to_claim(case, monkeypatch) -> None:
    """The taker claimed the covenant (p public) and its BTC refund is only in the mempool: the maker
    can still claim the BTC with p. This used to read TAKER_CLAIMED_AND_REFUNDED, "nothing left"."""
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=False)
    res = _checked_status(case, client=_spent(case, "claim"))
    assert res.exit_code == 0, res.output
    assert "TAKER_CLAIMED_AND_REFUNDED" not in res.output
    assert "situation  : COUNTER_LEG_REFUND_UNCONFIRMED" in res.output
    assert "MAKER: claim your BTC with p now" in res.output
    assert not any(s in res.output for s in _DEFINITIVE)


def test_a_refund_with_no_confirmation_status_is_treated_as_unconfirmed(case, monkeypatch) -> None:
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=None)
    doc = _json_status(case, _spent(case, "refund"))
    assert doc["counter_leg"]["state"] == "REFUND_REPORTED_UNCONFIRMED"
    assert doc["situation"] != "SETTLED"


def test_honest_path_a_confirmed_refund_still_reads_settled_but_asks_for_a_second_source(case, monkeypatch) -> None:
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=True)
    res = _checked_status(case, client=_spent(case, "refund"))
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): SPENT_NO_PREIMAGE" in res.output
    assert "situation  : SETTLED" in res.output
    assert "one server's answer" in res.output
    assert "one ElectrumX server's answer" in res.output
    assert "second, independent source" in res.output
    assert not any(s in res.output for s in _DEFINITIVE)


def test_honest_path_a_confirmed_refund_beside_a_taker_claim_is_still_named(case, monkeypatch) -> None:
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=True)
    doc = _json_status(case, _spent(case, "claim"))
    assert doc["situation"] == "TAKER_CLAIMED_AND_REFUNDED"
    assert not any(s in doc["chain"]["next_action"] for s in _DEFINITIVE)


def _btc_claimed(monkeypatch) -> None:
    raw = _claim_tx()
    spender = btc_txid_from_raw(raw)
    _serve(monkeypatch, _FakeEsplora({"spent": True, "txid": spender}, tx_hex={spender: raw.hex()}))


def test_a_covenant_spend_the_server_cannot_show_does_not_tell_the_taker_nothing_is_left(case, monkeypatch) -> None:
    """p is public on BTC. One ElectrumX omits the covenant's UTXO and its history has no spender.
    That used to read "Nothing is left to claim or refund" — to the one party who might still claim."""
    _btc_claimed(monkeypatch)
    funding, _ = _funding_and_spend(case, "refund")
    res = _checked_status(case, client=_Chain(case, [(funding, 100)], [], tip=110))
    assert res.exit_code == 0, res.output
    assert not any(s in res.output for s in _DEFINITIVE)
    assert "one ElectrumX server's answer" in res.output
    assert "second, independent ElectrumX server" in res.output


def test_a_refund_reported_before_the_csv_allows_one_is_not_believed(case, monkeypatch) -> None:
    """A refund 'mined' at 109 for a covenant funded at 100 with a 20-block CSV cannot exist: the
    refund branch is invalid before height 120. It used to read MAKER_REFUNDED_AND_CLAIMED."""
    _btc_claimed(monkeypatch)
    doc = _json_status(case, _spent(case, "refund", spend_height=109))
    assert doc["chain"]["covenant_spend"]["kind"] == "UNKNOWN"
    assert "CSV" in doc["chain"]["covenant_spend"]["reason"]
    assert doc["situation"] != "MAKER_REFUNDED_AND_CLAIMED"


def test_honest_path_a_refund_at_the_first_valid_height_is_still_a_refund(case, monkeypatch) -> None:
    _btc_claimed(monkeypatch)
    doc = _json_status(case, _spent(case, "refund", spend_height=120))
    assert doc["chain"]["covenant_spend"]["kind"] == "MAKER_REFUND"
    assert doc["situation"] == "MAKER_REFUNDED_AND_CLAIMED"
    assert not any(s in doc["chain"]["next_action"] for s in _DEFINITIVE)


def test_not_funded_says_it_is_one_electrumx_servers_answer(case, monkeypatch) -> None:
    _btc_claimed(monkeypatch)
    res = _checked_status(case, client=_Chain(case, [], [], tip=110))
    assert res.exit_code == 0, res.output
    assert "situation  : NOT_FUNDED" in res.output
    assert "one ElectrumX server's answer" in res.output


# =========================================================================== outcome 3: recover-preimage


def test_recover_preimage_does_not_say_keep_watching_for_an_outpoint_a_refund_spent(case, monkeypatch) -> None:
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=True)
    res = _recover(case, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _ESPLORA)
    assert res.exit_code == 1, res.output
    assert "keep watching" not in res.output
    assert "no preimage has been revealed yet" not in res.output
    assert "spent without revealing a preimage" in res.output
    assert "DO-NOT-PRINT" not in res.output


def test_recover_preimage_offline_refund_does_not_say_keep_watching(case) -> None:
    res = _recover(case, "--claim-tx-hex", _refund_tx().hex(), "--btc-funding-outpoint", _OUTPOINT)
    assert res.exit_code == 1, res.output
    assert "keep watching" not in res.output
    assert "spent without revealing a preimage" in res.output


def test_recover_preimage_names_an_unconfirmed_refund_as_unconfirmed(case, monkeypatch) -> None:
    _btc_spent_by(monkeypatch, _refund_tx(), confirmed=False)
    res = _recover(case, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _ESPLORA)
    assert res.exit_code == 1, res.output
    assert "keep watching" not in res.output
    assert "NOT CONFIRMED" in res.output


def test_honest_path_recover_preimage_on_an_unspent_outpoint_still_says_keep_watching(case, monkeypatch) -> None:
    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    res = _recover(case, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _ESPLORA)
    assert res.exit_code == 1, res.output
    assert "no preimage has been revealed yet" in res.output
    assert "keep watching" in res.output


# =========================================================================== ambiguity: an earlier, spent output of the same value


def _refund_of(case, funding: Transaction) -> Any:
    """A real CSV refund (production builder) of output 0 of ``funding``."""
    from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_refund_tx

    fee_key = case["fee_key"]
    fee_spk = b"\x76\xa9\x14" + bytes(fee_key.public_key().hash160()) + b"\x88\xac"
    fee = FeeInput(txid="cd" * 32, vout=1, value=FEE_VALUE, scriptpubkey=fee_spk, wif=fee_key.wif())
    return build_htlc_refund_tx(
        covenant=case["cov"], covenant_outpoint=f"{funding.txid()}:0", carrier_value=100_000, fee=fee
    )


def _earlier_spent_then_live(case):
    """An output of the recorded amount at 60, refunded at 85; the swap's covenant funded at 100, live."""
    earlier = _payment_to(case["cov"].funded_spk, 100_000, "55")
    funding, _ = _funding_and_spend(case, "refund")
    mined = [(earlier, 60), (_refund_of(case, earlier), 85), (funding, 100)]
    return earlier, funding, (lambda: _Chain(case, mined, [(funding, 0)], tip=110))


def test_a_live_covenant_is_never_called_spent_because_an_earlier_output_was(case, monkeypatch) -> None:
    """Old recovery file (amount, no outpoint). The only live output at the script carries the
    recorded amount; an earlier output of the same amount was refunded. Whatever the read decides,
    it must not report the live output's swap as spent, and the builder must not refuse it as spent.
    (At base 36b0fa04 this read LOCKED and build-claim built.)"""
    _write(case, rxd_covenant_amount=100_000)
    _btc_claimed(monkeypatch)
    _earlier, _funding, chain = _earlier_spent_then_live(case)
    doc = _json_status(case, chain())
    assert doc["situation"] in ("LOCKED", "COVENANT_UNIDENTIFIED"), doc["situation"]
    assert doc["chain"]["covenant_state"] != "spent"
    built = _build(case, "build-claim", "--preimage", P.hex(), client=chain())
    assert "already spent" not in built.output


def test_an_earlier_spent_output_of_the_recorded_amount_and_a_live_one_name_no_covenant(case, monkeypatch) -> None:
    """Both outputs carry the recorded amount; the earlier is spent, the later live. Status names
    neither and lists both; build-claim refuses with the same pointer; a pin resolves both."""
    _write(case, rxd_covenant_amount=100_000)
    _btc_claimed(monkeypatch)
    earlier, funding, chain = _earlier_spent_then_live(case)

    res = _checked_status(case, client=chain())
    assert res.exit_code == 0, res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert f"{earlier.txid()}:0" in res.output and f"{funding.txid()}:0" in res.output
    assert "--covenant-outpoint" in res.output

    refused = _build(case, "build-claim", "--preimage", P.hex(), client=chain())
    assert refused.exit_code == 1, refused.output
    assert "--covenant-outpoint" in refused.output
    assert "BUILT, NOT BROADCAST" not in refused.output

    pin = f"{funding.txid()}:0"
    doc = _json_status(case, chain(), "--covenant-outpoint", pin)
    assert doc["chain"]["covenant_state"] == "live"
    assert doc["situation"] == "LOCKED"
    built = _build(case, "build-claim", "--preimage", P.hex(), "--covenant-outpoint", pin, client=chain())
    assert built.exit_code == 0, built.output
    assert f"covenant   : {pin}   carrier=100000 photons" in built.output


def test_honest_path_a_spent_covenant_with_nothing_live_still_reads_spent(case, monkeypatch) -> None:
    _btc_claimed(monkeypatch)
    doc = _json_status(case, _spent(case, "refund"))
    assert doc["chain"]["covenant_state"] == "spent"
    assert doc["situation"] == "MAKER_REFUNDED_AND_CLAIMED"


# =========================================================================== pin refusals


def test_a_pin_the_server_does_not_know_with_a_live_output_names_no_covenant(case) -> None:
    funding, _ = _funding_and_spend(case, "refund")
    missing = "ee" * 32 + ":0"
    res = _status(case, "--covenant-outpoint", missing, client=_Chain(case, [(funding, 100)], [(funding, 0)], tip=110))
    assert res.exit_code == 0, res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert f"the pinned covenant outpoint {missing} was not found" in res.output
    assert f"{funding.txid()}:0" in res.output
    assert "NOT_FUNDED" not in res.output
    assert "not this swap's covenant" not in res.output


def test_a_pin_the_server_does_not_know_with_nothing_live_reads_not_funded_and_says_why(case) -> None:
    missing = "ee" * 32 + ":0"
    res = _status(case, "--covenant-outpoint", missing, client=_Chain(case, [], [], tip=110))
    assert res.exit_code == 0, res.output
    assert "situation  : NOT_FUNDED" in res.output
    assert f"the pinned covenant outpoint {missing} was not found" in res.output


def test_a_pin_to_a_spent_output_that_does_not_pay_the_covenant_script_is_refused(case) -> None:
    """The pinned txid is in the script's history (it spent the covenant), but its output 0 pays the
    taker, not the covenant script: the pin is wrong, and nothing is read as the covenant."""
    funding, refund = _funding_and_spend(case, "refund")
    client = _Chain(case, [(funding, 100), (refund, 125)], [], tip=130)
    res = _status(case, "--covenant-outpoint", f"{refund.txid()}:0", client=client)
    assert res.exit_code == 0, res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert "does not pay this swap's covenant script" in res.output
    assert "MAKER_REFUND" not in res.output


def test_a_pin_to_a_live_output_of_the_wrong_amount_is_refused(case) -> None:
    _write(case, rxd_covenant_amount=100_000)
    funding, _ = _funding_and_spend(case, "refund")
    dust = _payment_to(case["cov"].funded_spk, 546, "99")
    client = _Chain(case, [(funding, 100), (dust, 103)], [(funding, 0), (dust, 0)], tip=110)
    res = _status(case, "--covenant-outpoint", f"{dust.txid()}:0", client=client)
    assert res.exit_code == 0, res.output
    assert "situation  : COVENANT_UNIDENTIFIED" in res.output
    assert "holds 546 photons, not the covenant amount 100000" in res.output
    assert "covenant LIVE" not in res.output
    honest = _status(case, "--covenant-outpoint", f"{funding.txid()}:0", client=client)
    assert "covenant LIVE" in honest.output


# =========================================================================== ft: the recorded amount is the funded value


_FT_AMOUNT = 5_000
_FT_GENESIS = "a1" * 32


def _ft_case(case) -> dict[str, Any]:
    """The swap file rewritten for an FT covenant: same keys, an FT-variant covenant SPK, and only
    ``asset_ft_amount`` recorded (an ft file written before ``rxd_covenant_amount``)."""
    from pyrxd.cli.swap_recovery import electrumx_script_hash
    from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft
    from pyrxd.keys import PrivateKey

    doc = json.loads(case["keys"].read_text())
    cov = build_htlc_covenant_ft(
        genesis_txid=_FT_GENESIS,
        genesis_vout=0,
        amount=_FT_AMOUNT,
        taker_pkh=bytes(PrivateKey(doc["taker_rxd_wif"]).public_key().hash160()),
        maker_pkh=bytes(PrivateKey(doc["maker_rxd_wif"]).public_key().hash160()),
        hashlock=bytes.fromhex(doc["hashlock_H"]),
        refund_csv=doc["t_rxd_blocks"],
    )
    _write(
        case,
        asset_variant="ft",
        asset_genesis_ref=f"{_FT_GENESIS}:0",
        asset_ft_amount=_FT_AMOUNT,
        rxd_covenant_spk=cov.funded_spk.hex(),
    )
    return {**case, "cov": cov, "cov_sh": electrumx_script_hash(cov.funded_spk)}


def _spend_of(tx: Transaction, tag: str) -> Transaction:
    """Any transaction spending output 0 of ``tx`` (to a plain P2PKH)."""
    return Transaction(
        tx_inputs=[TransactionInput(source_txid=tx.txid(), source_output_index=0, unlocking_script=Script(b"\x51"))],
        tx_outputs=[TransactionOutput(Script(b"\x76\xa9\x14" + bytes.fromhex(tag * 20) + b"\x88\xac"), 1)],
    )


def test_ft_an_earlier_spent_output_of_another_value_is_not_a_candidate(case) -> None:
    """FT covenant, unpinned, only ``asset_ft_amount`` recorded. An earlier output at the script of
    another value was spent; the covenant (value = token amount) is live. On Radiant the FT amount IS
    the funded output's value, so the earlier output is filtered out and the covenant reads LIVE —
    it does not fall back to "no amount recorded" and become ambiguous."""
    ft = _ft_case(case)
    earlier = _payment_to(ft["cov"].funded_spk, 3_000, "55")
    funding = _payment_to(ft["cov"].funded_spk, _FT_AMOUNT, "66")
    mined = [(earlier, 60), (_spend_of(earlier, "77"), 85), (funding, 100)]

    def chain():
        return _Chain(ft, mined, [(funding, 0)], tip=110)

    js = _status(ft, client=chain(), output_mode="json")
    assert js.exit_code == 0, js.output
    chain_doc = json.loads(js.output)["chain"]
    assert chain_doc["covenant_state"] == "live", chain_doc
    assert chain_doc["covenant_outpoint"] == f"{funding.txid()}:0"
    assert chain_doc["value_photons"] == _FT_AMOUNT

    built = _build(ft, "build-claim", "--preimage", P.hex(), client=chain())
    assert built.exit_code == 0, built.output
    assert f"covenant   : {funding.txid()}:0   carrier={_FT_AMOUNT} photons" in built.output
