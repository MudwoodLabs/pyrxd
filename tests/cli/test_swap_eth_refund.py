"""``pyrxd swap build-eth-refund`` (#818): the checks that need no chain.

The behaviour against a real contract (the signed refund settles it, nothing reaches the node, and
each on-chain refusal) is in ``tests/test_build_eth_refund_anvil_integration.py``. Here: the record
and key gates, the artifact pairing, the sign-only rpc, and the refusal of a recorded refund that
is mined, pending or queued. Each refusal has its honest pair.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.cli import swap_eth_refund as mod
from pyrxd.cli.swap_cmds import parse_recovery_file
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg, RefundProgress
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.gravity.swap_state import RecordRole, SwapState
from pyrxd.security.errors import ValidationError
from tests._eth_refund_records import eth_record, write_record

from .test_swap_recovery_cmds import H, _ctx, _eth_swap, _invoke
from .test_swap_recovery_cmds import swap as swap_fixture  # noqa: F401 - registered as a fixture by that name

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
_ETH_ARTIFACT = json.loads((_FIXTURES / "EthHtlc.json").read_text())
_ERC20_ARTIFACT = json.loads((_FIXTURES / "Erc20Htlc.json").read_text())
_CHAIN = 11155111


@pytest.fixture
def swap(request):
    s = request.getfixturevalue("swap_fixture")
    _eth_swap(s)
    doc = json.loads(s["keys"].read_text())
    doc["eth_chain_id"] = _CHAIN
    s["keys"].write_text(json.dumps(doc))
    return s


def _locator(**over: Any) -> EthHtlcLocator:
    fields: dict[str, Any] = dict(
        chain_id=_CHAIN,
        contract_address="0x" + "c0" * 20,
        deploy_tx_hash="0x" + "11" * 32,
        hashlock="0x" + H.hex(),
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=2_000_000_000,
        amount_wei=10**15,
    )
    fields.update(over)
    return EthHtlcLocator(**fields)


def _facts(swap) -> Any:
    return parse_recovery_file(swap["keys"])


# ── the record gate ─────────────────────────────────────────────────────────────────────────────


def test_a_taker_record_for_this_swap_loads(swap) -> None:
    path = write_record(swap["keys"], eth_record(_locator()))
    record, locator = mod.load_eth_locator(path, _facts(swap))
    assert locator == _locator() and record.role is RecordRole.TAKER


def test_a_record_from_before_roles_loads_too(swap) -> None:
    path = write_record(swap["keys"], eth_record(_locator(), role=None))
    assert mod.load_eth_locator(path, _facts(swap))[1] == _locator()


def test_no_record_is_refused_naming_where_the_runner_writes_it(swap) -> None:
    with pytest.raises(ValidationError, match=r"<swap-file>\.swaprec\.json"):
        mod.load_eth_locator(Path(str(swap["keys"]) + ".swaprec.json"), _facts(swap))


def test_a_record_for_another_swap_is_refused(swap) -> None:
    other = os.urandom(32)
    path = write_record(swap["keys"], eth_record(_locator(hashlock="0x" + other.hex())))
    with pytest.raises(ValidationError, match="for another swap"):
        mod.load_eth_locator(path, _facts(swap))


def test_a_maker_record_is_refused(swap) -> None:
    path = write_record(swap["keys"], eth_record(_locator(), role=RecordRole.MAKER))
    with pytest.raises(ValidationError, match="written by the MAKER"):
        mod.load_eth_locator(path, _facts(swap))


def test_a_record_on_another_chain_than_the_recovery_file_is_refused(swap) -> None:
    path = write_record(swap["keys"], eth_record(_locator(chain_id=1)))
    with pytest.raises(ValidationError, match="on chain 1, the recovery file says chain 11155111"):
        mod.load_eth_locator(path, _facts(swap))


def test_a_record_with_no_funded_locator_is_refused(swap) -> None:
    rec = dataclasses.replace(eth_record(_locator()), counterchain_locator=None, state=SwapState.NEGOTIATED)
    path = write_record(swap["keys"], rec)
    with pytest.raises(ValidationError, match="no counter-leg locator"):
        mod.load_eth_locator(path, _facts(swap))


# ── the key ─────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", ["", "zz" * 32, "ab" * 31, "00" * 32])
def test_a_key_that_is_not_one_is_refused_without_echoing_it(text) -> None:
    with pytest.raises(ValidationError) as info:
        mod.parse_eth_key(text)
    if text:
        assert text not in str(info.value)


def test_a_key_parses_with_or_without_0x() -> None:
    raw = os.urandom(32).hex()
    assert mod.parse_eth_key(raw).unsafe_raw_bytes().hex() == raw
    assert mod.parse_eth_key("0x" + raw + "\n").unsafe_raw_bytes().hex() == raw


# ── the artifact must be the contract's kind ────────────────────────────────────────────────────


def _erc20_locator() -> Erc20HtlcLocator:
    base = dataclasses.asdict(_locator(chain_id=31337))
    return Erc20HtlcLocator(**base, token_address="0x" + "70" * 20, deployer="0x" + "55" * 20)


def test_the_artifact_must_match_the_contract_kind() -> None:
    key = mod.parse_eth_key(os.urandom(32).hex())
    with pytest.raises(ValidationError, match="native EthHtlc artifact"):
        mod._leg_for(_erc20_locator(), rpc=None, key=key, artifact=_ETH_ARTIFACT)
    with pytest.raises(ValidationError, match="is the Erc20Htlc artifact"):
        mod._leg_for(_locator(), rpc=None, key=key, artifact=_ERC20_ARTIFACT)
    # Honest pairs.
    assert type(mod._leg_for(_locator(), rpc=None, key=key, artifact=_ETH_ARTIFACT)) is EthHtlcContractLeg
    assert mod._leg_for(_erc20_locator(), rpc=None, key=key, artifact=_ERC20_ARTIFACT).token.address == "0x" + "70" * 20


def test_an_unpinned_token_on_a_value_bearing_chain_is_refused() -> None:
    base = dataclasses.asdict(_locator(chain_id=1))
    loc = Erc20HtlcLocator(**base, token_address="0x" + "70" * 20, deployer=None)
    with pytest.raises(ValidationError, match="no pinned token"):
        mod._token_for(loc)


# ── the sign-only rpc ───────────────────────────────────────────────────────────────────────────


class _Inner:
    expected_chain_id = _CHAIN

    def __init__(self) -> None:
        self.preflighted: list[dict] = []

    async def preflight(self, tx: dict) -> None:
        self.preflighted.append(tx)

    async def send_raw(self, raw: bytes) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("the real rpc's send_raw was called")


def test_the_sign_only_rpc_keeps_the_bytes_answers_their_hash_and_takes_one() -> None:
    from eth_utils import keccak

    inner = _Inner()
    rpc = mod._SignOnlyRpc(inner)
    assert rpc.expected_chain_id == _CHAIN  # reads go through
    asyncio.run(rpc.preflight({"nonce": 3}))
    assert rpc.signed_tx == {"nonce": 3} and inner.preflighted == [{"nonce": 3}]
    raw = os.urandom(120)
    assert asyncio.run(rpc.send_raw(raw)) == "0x" + keccak(raw).hex()
    assert rpc.signed_raw == raw
    with pytest.raises(ValidationError, match="second transaction"):
        asyncio.run(rpc.send_raw(raw))
    with pytest.raises(ValidationError, match="never broadcasts"):
        asyncio.run(rpc.wait_receipt("0x00"))


# ── a refund already on the record ──────────────────────────────────────────────────────────────


class _Rpc:
    expected_chain_id = _CHAIN

    async def latest_block_timestamp_min(self) -> int:
        return 2_100_000_000

    async def get_balance(self, *_: Any) -> int:
        return 10**15


@pytest.mark.parametrize(("kind", "signs"), [("mined", False), ("pending", False), ("nonce_gap", False),
                                             ("dropped", True), ("nonce_taken", True), ("reverted", True)])  # fmt: skip
def test_a_recorded_refund_blocks_a_new_one_only_while_it_can_still_land(monkeypatch, kind, signs) -> None:
    sent: list[str] = []

    async def unsettled(self, locator):
        return False

    async def progress(self, tx_hash, nonce, *, earlier=()):
        return RefundProgress(kind)

    async def refund(self, locator, **_):
        sent.append(locator.contract_address)
        tx = {"nonce": 8, "gas": 150_000, "maxFeePerGas": 3, "maxPriorityFeePerGas": 1}
        await self._rpc.preflight(tx)
        return await self._rpc.send_raw(_sign(self._key, locator, tx))

    async def preflight(self, tx):
        return None

    monkeypatch.setattr(EthHtlcContractLeg, "check_refund_target", unsettled)
    monkeypatch.setattr(EthHtlcContractLeg, "refund_progress", progress)
    monkeypatch.setattr(EthHtlcContractLeg, "refund", refund)
    monkeypatch.setattr(_Rpc, "preflight", preflight, raising=False)
    record = eth_record(_locator(), counter_refund_tx_hash="0x" + "ab" * 32, counter_refund_nonce=7)
    key = mod.parse_eth_key(os.urandom(32).hex())
    go = mod.build_cold_eth_refund(record=record, locator=_locator(), rpc=_Rpc(), key=key, artifact=_ETH_ARTIFACT)
    if signs:
        out = asyncio.run(go)
        assert sent and out.earlier_refund == {"tx_hash": "0x" + "ab" * 32, "nonce": 7, "progress": kind}
        assert out.nonce == 8 and out.raw_hex.startswith("0x02")
    else:
        with pytest.raises(ValidationError, match="already holds a refund"):
            asyncio.run(go)
        assert sent == []


def _sign(key: Any, locator: EthHtlcLocator, tx: dict[str, Any], **over: Any) -> bytes:
    from eth_account import Account
    from eth_utils import to_checksum_address

    full = {"chainId": locator.chain_id, "to": to_checksum_address(locator.contract_address), "value": 0,
            "data": mod._REFUND_SELECTOR, "type": 2, **tx, **over}  # fmt: skip
    return bytes(Account.sign_transaction(full, key.unsafe_raw_bytes()).raw_transaction)


@pytest.mark.parametrize("field", ["nonce", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "chainId", "to"])
def test_a_signed_refund_that_differs_from_the_checked_one_is_not_printed(monkeypatch, field) -> None:
    """The printed fields come from the preflighted dict; the signed bytes must carry the same ones."""
    checked = {"nonce": 8, "gas": 150_000, "maxFeePerGas": 3, "maxPriorityFeePerGas": 1}
    other = {"nonce": 9, "gas": 150_001, "maxFeePerGas": 4, "maxPriorityFeePerGas": 2, "chainId": _CHAIN + 1,
             "to": "0x" + "C1" * 20}[field]  # fmt: skip
    if field == "to":
        from eth_utils import to_checksum_address

        other = to_checksum_address(other)

    async def unsettled(self, locator):
        return False

    async def refund(self, locator, **_):
        await self._rpc.preflight(checked)
        return await self._rpc.send_raw(_sign(self._key, locator, checked, **{field: other}))

    async def preflight(self, tx):
        return None

    monkeypatch.setattr(EthHtlcContractLeg, "check_refund_target", unsettled)
    monkeypatch.setattr(EthHtlcContractLeg, "refund", refund)
    monkeypatch.setattr(_Rpc, "preflight", preflight, raising=False)
    key = mod.parse_eth_key(os.urandom(32).hex())
    go = mod.build_cold_eth_refund(record=eth_record(_locator()), locator=_locator(), rpc=_Rpc(), key=key,
                                   artifact=_ETH_ARTIFACT)  # fmt: skip
    with pytest.raises(ValidationError, match=f"does not match.*{field}"):
        asyncio.run(go)


def test_a_signed_refund_that_matches_the_checked_one_is_printed(monkeypatch) -> None:
    checked = {"nonce": 8, "gas": 150_000, "maxFeePerGas": 3, "maxPriorityFeePerGas": 1}

    async def unsettled(self, locator):
        return False

    async def refund(self, locator, **_):
        await self._rpc.preflight(checked)
        return await self._rpc.send_raw(_sign(self._key, locator, checked))

    async def preflight(self, tx):
        return None

    monkeypatch.setattr(EthHtlcContractLeg, "check_refund_target", unsettled)
    monkeypatch.setattr(EthHtlcContractLeg, "refund", refund)
    monkeypatch.setattr(_Rpc, "preflight", preflight, raising=False)
    key = mod.parse_eth_key(os.urandom(32).hex())
    out = asyncio.run(mod.build_cold_eth_refund(record=eth_record(_locator()), locator=_locator(), rpc=_Rpc(),
                                                key=key, artifact=_ETH_ARTIFACT))  # fmt: skip
    assert (out.nonce, out.gas_limit, out.max_fee_per_gas, out.max_priority_fee_per_gas) == (8, 150_000, 3, 1)


def test_an_empty_key_file_names_the_refund_key(swap, monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(mod.KEY_ENV, raising=False)
    write_record(swap["keys"], eth_record(_locator()))
    empty = tmp_path / "k"
    empty.write_text("\n")
    empty.chmod(0o600)
    res = _cmd(swap, "--eth-key-file", str(empty))
    assert res.exit_code == 1, res.output
    assert "is empty; write the refund key" in res.output and "webhook" not in res.output


def test_an_empty_key_env_names_the_refund_key(swap, monkeypatch) -> None:
    monkeypatch.setenv(mod.KEY_ENV, "  ")
    write_record(swap["keys"], eth_record(_locator()))
    res = _cmd(swap)
    assert res.exit_code == 1, res.output
    assert "set but empty; set the refund key" in res.output and "webhook" not in res.output


# ── the command's own gates ─────────────────────────────────────────────────────────────────────


def _cmd(swap, *extra: str):
    args = ["build-eth-refund", "--swap-file", str(swap["keys"]), "--eth-rpc-url", "http://127.0.0.1:9"]
    return _invoke([*args, "--artifact", str(_FIXTURES / "EthHtlc.json"), *extra], _ctx())


def test_a_btc_swap_is_refused(request) -> None:
    btc = request.getfixturevalue("swap_fixture")
    res = _cmd(btc)
    assert res.exit_code == 1, res.output
    assert "not on Ethereum" in res.output


def test_no_key_anywhere_is_refused_before_any_read(swap, monkeypatch) -> None:
    monkeypatch.delenv(mod.KEY_ENV, raising=False)
    write_record(swap["keys"], eth_record(_locator()))
    res = _cmd(swap)
    assert res.exit_code == 1, res.output
    assert "no refund key" in res.output


def test_the_refund_selector_is_refund_with_no_arguments_in_both_artifacts() -> None:
    from eth_utils import keccak

    for name in ("EthHtlc.json", "Erc20Htlc.json"):
        abi = json.loads((_FIXTURES / name).read_text())["abi"]
        refunds = [f for f in abi if f.get("type") == "function" and f.get("name") == "refund"]
        assert refunds and all(f["inputs"] == [] for f in refunds), name
    assert keccak(b"refund()")[:4] == mod._REFUND_SELECTOR


@pytest.mark.parametrize("over", [{"value": 1}, {"data": b"\x59\x0e\x1a\xe4"}, {"data": b""}])
def test_a_signed_transaction_that_is_not_refund_is_not_printed(over) -> None:
    key = mod.parse_eth_key(os.urandom(32).hex())
    tx = {"nonce": 8, "gas": 150_000, "maxFeePerGas": 3, "maxPriorityFeePerGas": 1}
    raw = _sign(key, _locator(), tx, **{"data": mod._REFUND_SELECTOR, **over})
    with pytest.raises(ValidationError, match="does not match"):
        mod._assert_signed_matches(raw, tx, chain_id=_CHAIN, to=_locator().contract_address)
    honest = _sign(key, _locator(), tx, data=mod._REFUND_SELECTOR)
    mod._assert_signed_matches(honest, tx, chain_id=_CHAIN, to=_locator().contract_address)


def test_legacy_signed_bytes_are_refused_as_a_validation_error() -> None:
    from eth_account import Account
    from eth_utils import to_checksum_address

    key = mod.parse_eth_key(os.urandom(32).hex())
    legacy = Account.sign_transaction(
        {
            "chainId": _CHAIN,
            "to": to_checksum_address(_locator().contract_address),
            "value": 0,
            "nonce": 8,
            "gas": 150_000,
            "gasPrice": 3,
            "data": mod._REFUND_SELECTOR,
        },
        key.unsafe_raw_bytes(),
    ).raw_transaction
    tx = {"nonce": 8, "gas": 150_000, "maxFeePerGas": 3, "maxPriorityFeePerGas": 1}
    with pytest.raises(ValidationError, match="not an EIP-1559"):
        mod._assert_signed_matches(bytes(legacy), tx, chain_id=_CHAIN, to=_locator().contract_address)


def test_a_good_key_file_wins_over_an_empty_env_var(monkeypatch, tmp_path) -> None:
    good = tmp_path / "k"
    good.write_text("ab" * 32 + "\n")
    good.chmod(0o600)
    monkeypatch.setenv(mod.KEY_ENV, "")
    assert mod._resolve_key_source(str(good)) == "ab" * 32


def test_the_env_key_is_used_when_no_file_is_given(monkeypatch) -> None:
    monkeypatch.setenv(mod.KEY_ENV, "cd" * 32)
    assert mod._resolve_key_source(None) == "cd" * 32


def test_the_key_file_goes_through_the_guarded_read(monkeypatch, tmp_path) -> None:
    """A FIFO returns at once, a symlink is refused, and a non-UTF-8 file's bytes are not echoed."""
    monkeypatch.delenv(mod.KEY_ENV, raising=False)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValidationError):
        mod._resolve_key_source(str(fifo))
    target = tmp_path / "t"
    target.write_text("ab" * 32)
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValidationError):
        mod._resolve_key_source(str(link))
    raw = tmp_path / "raw"
    raw.write_bytes(b"\xfe" + os.urandom(31))
    raw.chmod(0o600)
    with pytest.raises(ValidationError) as caught:
        mod._resolve_key_source(str(raw))
    assert "0xfe" not in str(caught.value) and "position" not in str(caught.value)


def _value_bearing_ids() -> list[int]:
    from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS

    ids = [c.chain_id for c in KNOWN_EVM_CHAINS.values() if not c.is_testnet]
    assert ids
    return ids


def test_one_endpoint_on_a_value_bearing_chain_is_refused_without_the_flag() -> None:
    for chain_id in _value_bearing_ids():
        with pytest.raises(ValidationError, match="--single-endpoint"):
            mod._open_rpc(("https://a.example",), chain_id)


def test_one_endpoint_on_a_value_bearing_chain_opens_with_the_flag_or_a_second_operator() -> None:
    for chain_id in _value_bearing_ids():
        assert mod._open_rpc(("https://a.example",), chain_id, single_endpoint=True) is not None
        assert len(mod._open_rpc(("https://a.example", "https://b.example.org"), chain_id).sources) == 2


def test_one_endpoint_on_a_test_chain_needs_no_flag() -> None:
    from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS

    test_ids = [c.chain_id for c in KNOWN_EVM_CHAINS.values() if c.is_testnet]
    assert test_ids
    for chain_id in [*test_ids, 31337]:
        assert mod._open_rpc(("https://a.example",), chain_id) is not None


def test_the_command_refuses_one_mainnet_endpoint_before_any_read(swap, monkeypatch) -> None:
    monkeypatch.setenv(mod.KEY_ENV, os.urandom(32).hex())
    doc = json.loads(swap["keys"].read_text())
    doc.update(eth_chain="ethereum", eth_chain_id=1)
    swap["keys"].write_text(json.dumps(doc))
    write_record(swap["keys"], eth_record(_locator(chain_id=1)))
    res = _cmd(swap)
    assert res.exit_code == 1, res.output
    assert "could not prepare" in res.output and "--single-endpoint" in res.output
