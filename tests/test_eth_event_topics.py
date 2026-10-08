"""The ETH counter-leg event topics must be the ones the shipped contracts actually emit.

``scripts/swap_run_verify.py`` once pinned ``Claimed``/``Refunded`` topic0 values that were
``hashlib.sha3_256`` of the signatures — NIST SHA3-256, not Ethereum Keccak-256. No contract can
emit those, so ``verify_counter_leg_eth`` scored every honest claim and refund ANOMALOUS, its
``eth_getLogs`` discovery never found an uncited spend, and a receipt forged with the bogus topic
was accepted as a claim. Its ``--self-check`` built its synthetic receipts from the same constants,
so it passed with any value.

These tests check the constants against sources that do NOT go through them:

* the ABI of each shipped fixture (``tests/fixtures/EthHtlc.json``, ``Erc20Htlc.json``), hashed here
  with Keccak-256 directly;
* the compiled runtime of each fixture, where solc pushes each topic as a ``PUSH32`` operand
  before ``LOG1`` — no hashing involved at all;
* ``verify_counter_leg_eth`` driven end to end with receipts carrying those runtime-derived topics,
  including the creation-bytecode pin path.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from Cryptodome.Hash import keccak

from pyrxd.eth_wallet import events
from pyrxd.gravity.watch import eth_adapters

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = str(_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import swap_run_verify as v

_FIXTURES = ("EthHtlc.json", "Erc20Htlc.json")

#: What swap_run_verify.py pinned before this fix: sha3_256("Claimed(bytes32)") / sha3_256("Refunded()").
_OLD_SHA3_CLAIMED = "0xb651fac6b68e9074a2da0835d9a5cb12e8cc45ff91d6e79e31a9627866507cc7"
_OLD_SHA3_REFUNDED = "0xa4891be4c05fc4b104f07fbbd9f643c3a98d0f9d3c4e616281bdba972991a558"


def _fixture(name: str) -> dict:
    return json.loads((_ROOT / "tests" / "fixtures" / name).read_text())


def _hex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _keccak_hex(text: str) -> str:
    return "0x" + keccak.new(digest_bits=256, data=text.encode("ascii")).hexdigest()


def _abi_event_topics(abi: list[dict]) -> dict[str, str]:
    """``{event name: keccak256(canonical signature)}`` for every non-anonymous event in the ABI."""
    out: dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "event" or entry.get("anonymous"):
            continue
        sig = f"{entry['name']}({','.join(i['type'] for i in entry['inputs'])})"
        out[entry["name"]] = _keccak_hex(sig)
    return out


def _push32_operands(runtime: bytes) -> set[bytes]:
    """Every PUSH32 operand in *runtime*, walking opcodes so PUSH data is never read as an opcode."""
    found: set[bytes] = set()
    i = 0
    while i < len(runtime):
        op = runtime[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            if op == 0x7F:
                found.add(runtime[i + 1 : i + 1 + n])
            i += 1 + n
        else:
            i += 1
    return found


def test_keccak_primitive_is_ethereum_keccak_not_nist_sha3() -> None:
    # A control with a known answer: the two functions differ on every input, including the empty one.
    assert events.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert hashlib.sha3_256(b"").hexdigest() == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    # and the old pinned values were exactly sha3_256 of the right signatures — the confusion, reproduced
    assert "0x" + hashlib.sha3_256(b"Claimed(bytes32)").hexdigest() == _OLD_SHA3_CLAIMED
    assert "0x" + hashlib.sha3_256(b"Refunded()").hexdigest() == _OLD_SHA3_REFUNDED


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_topics_derived_from_each_fixture_abi_match_every_consumer(fixture: str) -> None:
    topics = _abi_event_topics(_fixture(fixture)["abi"])
    # Non-vacuity, both directions: the ABI declares exactly these two events, so a new or renamed
    # event fails here instead of being silently unrecognised by the verifier.
    assert set(topics) == {"Claimed", "Refunded"}, topics
    for consumer_claimed, consumer_refunded in (
        (v._ETH_CLAIMED_TOPIC, v._ETH_REFUNDED_TOPIC),  # scripts/swap_run_verify.py
        (eth_adapters.CLAIMED_TOPIC0, eth_adapters.REFUNDED_TOPIC0),  # the watchtower
        (events.CLAIMED_TOPIC0, events.REFUNDED_TOPIC0),  # the shared source
    ):
        assert consumer_claimed == topics["Claimed"]
        assert consumer_refunded == topics["Refunded"]


@pytest.mark.parametrize("fixture", _FIXTURES)
@pytest.mark.parametrize("topic_name", ["_ETH_CLAIMED_TOPIC", "_ETH_REFUNDED_TOPIC"])
def test_each_topic_is_a_push32_operand_in_each_shipped_runtime(fixture: str, topic_name: str) -> None:
    """No hashing on this side: solc emits ``PUSH32 <topic0>`` before ``LOG1``, so the value the verifier
    filters on must literally appear in the compiled runtime the contract runs."""
    runtime = _hex(_fixture(fixture)["runtime_bytecode"])
    operands = _push32_operands(runtime)
    topic = _hex(getattr(v, topic_name))
    assert topic in operands
    assert bytes([0x7F]) + topic in runtime
    # the walker can see a PUSH32 at all (it would be vacuous on a runtime it mis-parsed)
    assert len(operands) > 2


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_the_old_sha3_topics_appear_in_no_shipped_runtime(fixture: str) -> None:
    runtime = _hex(_fixture(fixture)["runtime_bytecode"])
    operands = _push32_operands(runtime)
    assert _hex(_OLD_SHA3_CLAIMED) not in operands
    assert _hex(_OLD_SHA3_REFUNDED) not in operands


# ─────────────────────────────── verify_counter_leg_eth, end to end with the real topics ──

_P = b"\x5a" * 32
_H = hashlib.sha256(_P).digest()
_CONTRACT = "0x" + "ab" * 20
_MAKER = "0x" + "33" * 20
_TAKER = "0x" + "44" * 20
_WEI = 10**15


def _runtime_topic(fixture: str, sig_name: str) -> str:
    """The topic as found in the runtime — pick the PUSH32 operand equal to keccak of the ABI signature,
    so the receipt below carries a value the shipped contract can actually emit."""
    want = _hex(_abi_event_topics(_fixture(fixture)["abi"])[sig_name])
    assert want in _push32_operands(_hex(_fixture(fixture)["runtime_bytecode"]))
    return "0x" + want.hex()


def _manifest() -> v.RunManifest:
    return v.RunManifest(
        swap_id="topics",
        asset_variant="rxd",
        counter_chain="eth",
        honest_party="maker",
        h_hex=_H.hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=v.Outpoint("ab" * 32, 0),
        eth_contract=_CONTRACT,
        eth_chain_id=11155111,
        eth_maker_claimant=_MAKER,
        counter_amount=_WEI,
    )


def _funding() -> tuple[dict, dict]:
    """The deploy tx as the chain would carry it: the canonical EthHtlc creation bytecode followed by the
    ABI-encoded constructor(bytes32 hashlock, address claimant, address refundee, uint256 timeout)."""
    creation = _hex(_fixture("EthHtlc.json")["bytecode"])
    args = _H + bytes(12) + _hex(_MAKER) + bytes(12) + _hex(_TAKER) + (1_900_000_000).to_bytes(32, "big")
    deploy_tx = {"input": "0x" + (creation + args).hex(), "value": hex(_WEI)}
    return deploy_tx, {"contractAddress": _CONTRACT}


def _claim() -> tuple[dict, dict]:
    tx = {"input": "0x" + events.function_selector("claim(bytes32)").hex() + _P.hex(), "to": _CONTRACT}
    topic = _runtime_topic("EthHtlc.json", "Claimed")
    rcpt = {"status": 1, "logs": [{"address": _CONTRACT, "topics": [topic], "data": "0x" + _P.hex()}]}
    return tx, rcpt


def _refund() -> tuple[dict, dict]:
    tx = {"input": "0x" + events.function_selector("refund()").hex(), "to": _CONTRACT}
    topic = _runtime_topic("EthHtlc.json", "Refunded")
    return tx, {"status": 1, "logs": [{"address": _CONTRACT, "topics": [topic], "data": "0x"}]}


def test_the_calldata_selectors_used_here_are_dispatched_by_the_runtime() -> None:
    runtime = _hex(_fixture("EthHtlc.json")["runtime_bytecode"])
    for sig in ("claim(bytes32)", "refund()"):
        assert bytes([0x63]) + events.function_selector(sig) in runtime  # PUSH4 <selector> in the dispatcher


@pytest.mark.parametrize("with_funding", [False, True], ids=["receipt-only", "init-code-pin"])
def test_an_honest_claim_is_maker_claimed(with_funding: bool) -> None:
    tx, rcpt = _claim()
    funding = _funding() if with_funding else None
    leg, digest, notes = v.verify_counter_leg_eth(_manifest(), tx, rcpt, funding=funding)
    assert leg is v.CounterLeg.MAKER_CLAIMED, notes
    assert digest == _H
    if with_funding:  # the creation-bytecode pin and the claimant binding both ran and passed
        assert any("claimant==maker" in n for n in notes), notes


@pytest.mark.parametrize("with_funding", [False, True], ids=["receipt-only", "init-code-pin"])
def test_an_honest_refund_is_taker_refunded(with_funding: bool) -> None:
    tx, rcpt = _refund()
    funding = _funding() if with_funding else None
    leg, digest, notes = v.verify_counter_leg_eth(_manifest(), tx, rcpt, funding=funding)
    assert leg is v.CounterLeg.TAKER_REFUNDED, notes
    assert digest is None


def test_the_init_code_pin_is_live_in_this_fixture() -> None:
    """Control for the init-code-pin cases above: a one-byte change to the creation bytecode must flip the
    verdict, or those cases would pass without the pin ever having been exercised."""
    deploy_tx, deploy_rcpt = _funding()
    raw = bytearray(_hex(deploy_tx["input"]))
    raw[0] ^= 0x01
    tx, rcpt = _claim()
    leg, _, notes = v.verify_counter_leg_eth(
        _manifest(), tx, rcpt, funding=({**deploy_tx, "input": "0x" + raw.hex()}, deploy_rcpt)
    )
    assert leg is v.CounterLeg.ANOMALOUS
    assert any("creation bytecode" in n for n in notes), notes


@pytest.mark.parametrize("old_topic", [_OLD_SHA3_CLAIMED, _OLD_SHA3_REFUNDED], ids=["claimed", "refunded"])
def test_a_receipt_with_the_old_sha3_topic_is_not_accepted(old_topic: str) -> None:
    """The contract cannot emit the old value, so a receipt carrying it is not ours to score as a spend."""
    tx, _ = _claim()
    forged = {"status": 1, "logs": [{"address": _CONTRACT, "topics": [old_topic], "data": "0x" + _P.hex()}]}
    leg, digest, _ = v.verify_counter_leg_eth(_manifest(), tx, forged, funding=_funding())
    assert leg is v.CounterLeg.ANOMALOUS
    assert digest is None


async def test_spend_discovery_filters_on_the_real_topics() -> None:
    """``spend_of`` (the eth_getLogs discovery of an uncited spend) must ask for the topics the contract
    emits; with the old constants it asked for values no log carries and always came back empty."""
    seen: dict = {}

    class _Rpc:
        async def get_logs(self, *, address: str, topics: list) -> list[dict]:
            seen["address"], seen["topics"] = address, topics
            return [{"transactionHash": "0x" + "ee" * 32}]

    fetcher = v._EthFetcher.__new__(v._EthFetcher)
    fetcher._rpc = _Rpc()
    assert await fetcher.spend_of(_CONTRACT) == "0x" + "ee" * 32
    assert seen["topics"] == [[_runtime_topic("EthHtlc.json", "Claimed"), _runtime_topic("EthHtlc.json", "Refunded")]]
