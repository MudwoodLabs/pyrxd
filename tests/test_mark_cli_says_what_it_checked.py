"""What `glyph inspect` and `verify` say they checked must be what they checked.

Two sentences on the CLI described the check wrongly, both found while fixing the browser pages
(which could not touch the CLI):

1. ``--min-confirmations N`` was explained as "N is how many blocks must sit on top of the mark's
   block". The check is ``confirmations >= N`` (``MarkAnchor.provisional``), and an endpoint's
   confirmation count INCLUDES the block the transaction is in (``height = tip - confirmations +
   1``). So N counts the block itself: the help promised one block more than the check requires.
   The wording now lives beside the check (``mark_anchor.MIN_CONFIRMATIONS_MEANING``), and the test
   below pins the words and the boundary of the real check together.

2. The attestation's chain was printed only beside a VERIFIED signature. The genesis hash is part
   of the signed statement, so a record honestly signed for TESTNET does not verify against
   mainnet — and with no chain named, that honest record read as a plain forgery on the default
   run. Every outcome that involves a key now names the chain it was checked against (or would
   be). The record below is REALLY signed for testnet, by a key generated here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.errors import UserError
from pyrxd.cli.glyph_inspect import _op_return_payload_lines, _require_min_confirmations
from pyrxd.cli.hashmark_cmds import _block_check, _signature_check
from pyrxd.cli.main import cli
from pyrxd.constants import genesis_hash_for
from pyrxd.glyph._inspect_core import _inspect_script
from pyrxd.glyph.mark_anchor import MIN_CONFIRMATIONS_MEANING, mark_anchor_dict, resolve_mark_anchor
from pyrxd.hashmark_tx import plan_hashmark
from pyrxd.keys import PrivateKey


def _flat(text: str) -> str:
    return " ".join(text.split())


def _invoke(tmp_path: Path, args: list[str]):
    return CliRunner().invoke(cli, ["--wallet", str(tmp_path / "w"), "--config", str(tmp_path / "c.toml"), *args])


# ---------------------------------------------------------------------------
# 1. --min-confirmations N counts the mark's block itself
# ---------------------------------------------------------------------------


async def _anchor(confirmations: int, floor: int):
    async def verbose(txid: str) -> dict:
        return {"txid": txid, "confirmations": confirmations}

    return await resolve_mark_anchor(
        txid="ab" * 32, fetch_verbose=verbose, source="endpoint", min_confirmations=floor, tip_height=1000
    )


async def test_the_words_and_the_real_check_agree_at_the_boundary() -> None:
    """ONE confirmation is the block itself with nothing on top. By the words, a floor of 1 is met
    and a floor of 2 is not; by the check, the same. The old words ("blocks on top") would have
    needed 2 confirmations for N=1."""
    assert MIN_CONFIRMATIONS_MEANING == "N confirmations: the block itself and N−1 built on top of it"

    one_of_one = await _anchor(confirmations=1, floor=1)
    one_of_two = await _anchor(confirmations=1, floor=2)
    assert one_of_one.height == 1000, "the premise: one confirmation means the mark IS the tip block"
    assert one_of_one.usable_for_point_in_time and not one_of_one.provisional
    assert one_of_two.provisional and not one_of_two.usable_for_point_in_time
    # ...and `pyrxd verify`'s block check, which is what the flag gates.
    assert _block_check(mark_anchor_dict(one_of_one))[0] == "CONFIRMED"
    assert _block_check(mark_anchor_dict(one_of_two))[0] == "PROVISIONAL"


@pytest.mark.parametrize("command", [["glyph", "inspect", "--help"], ["verify", "--help"]])
def test_every_help_that_explains_the_flag_uses_those_words(tmp_path, command) -> None:
    r = _invoke(tmp_path, command)
    assert r.exit_code == 0, r.output
    flat = _flat(r.output)
    assert MIN_CONFIRMATIONS_MEANING in flat
    assert "on top of the mark's block" not in flat


@pytest.mark.parametrize(("needed_by", "command"), [("--wave-name", None), ("pyrxd verify", "pyrxd verify <txid>")])
def test_the_refusal_explains_the_flag_the_same_way(needed_by, command) -> None:
    with pytest.raises(UserError) as caught:
        _require_min_confirmations(None, needed_by=needed_by, command=command)
    assert MIN_CONFIRMATIONS_MEANING in caught.value.fix
    assert "on top of the mark's" not in caught.value.fix


# ---------------------------------------------------------------------------
# 2. The chain is named for every attestation outcome
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def testnet_record() -> str:
    """A HashMark v2 record REALLY signed for testnet: the testnet genesis is in the statement."""
    plan = plan_hashmark(
        hashlib.sha256(b"a testnet press kit\n").digest(),
        PrivateKey(),
        label="testnet",
        network_genesis=genesis_hash_for("testnet"),
    )
    return plan.op_return_script.hex()


def test_the_premise_it_verifies_on_testnet_and_not_on_mainnet(testnet_record) -> None:
    on_testnet = _inspect_script(testnet_record, network="testnet")["hashmark"]["attestation"]
    on_mainnet = _inspect_script(testnet_record, network="mainnet")["hashmark"]["attestation"]
    assert on_testnet["outcome"] == "valid"
    assert on_mainnet["outcome"] == "invalid_signature"


def test_an_honest_testnet_record_read_on_mainnet_names_the_chain(testnet_record) -> None:
    flat = _flat("\n".join(_op_return_payload_lines(_inspect_script(testnet_record, network="mainnet"))))
    assert "signature DOES NOT VERIFY" in flat
    assert "checked against radiant-mainnet" in flat
    assert "a record signed for another chain does not verify here" in flat
    assert "re-run with that --network" in flat


def test_through_the_command_both_ways(tmp_path, testnet_record) -> None:
    """The real `pyrxd glyph inspect` on the pasted record: the default network names mainnet
    beside DOES NOT VERIFY; `--network testnet` verifies it and names testnet."""
    default = _invoke(tmp_path, ["glyph", "inspect", testnet_record])
    assert default.exit_code == 0, default.output
    flat = _flat(default.output)
    assert "DOES NOT VERIFY" in flat and "checked against radiant-mainnet" in flat

    testnet = _invoke(tmp_path, ["--network", "testnet", "glyph", "inspect", testnet_record])
    assert testnet.exit_code == 0, testnet.output
    flat = _flat(testnet.output)
    assert "signature VERIFIED" in flat and "radiant-testnet" in flat


@pytest.mark.parametrize(
    "outcome", ["valid", "invalid_signature", "unverifiable", "not_checked_here", "from-a-newer-build"]
)
def test_every_outcome_with_a_signer_names_the_chain(outcome) -> None:
    """Swept over every outcome the renderer can meet, including one it has never heard of —
    the `else` branch, where the chain used to be dropped."""
    hm = {
        "outcome": "ok",
        "version": 2,
        "algorithm": "sha256",
        "digest": "cd" * 32,
        "signer_hash160": "ab" * 20,
        "attestation": {"outcome": outcome, "detail": "", "assumed_network": "radiant-testnet"},
    }
    assert "radiant-testnet" in _flat("\n".join(_op_return_payload_lines({"hashmark": hm})))


def test_verify_summary_names_the_chain_too(testnet_record) -> None:
    """`pyrxd verify`'s summary line is what a gate reader sees first. It read "DOES NOT VERIFY —
    <detail>" with no chain, above the detail that now names it."""
    record = _inspect_script(testnet_record, network="mainnet")["hashmark"]
    state, reason = _signature_check(record)
    assert state == "DOES NOT VERIFY"
    assert "checked against radiant-mainnet" in reason
    ok_state, ok_reason = _signature_check(_inspect_script(testnet_record, network="testnet")["hashmark"])
    assert ok_state == "VERIFIED" and "radiant-testnet" in ok_reason


def test_json_still_carries_the_chain_it_used(tmp_path, testnet_record) -> None:
    r = _invoke(tmp_path, ["--json", "glyph", "inspect", testnet_record])
    assert json.loads(r.stdout)["hashmark"]["attestation"]["assumed_network"] == "radiant-mainnet"
