"""The durable ETH-HTLC record (`eth_wallet/locator.py`): what it refuses to persist.

A locator is the surviving reference to a funded contract — lose or corrupt it and the ETH is
stranded. The 2026-09-29 `ethleg` mutation run found its validators mostly exercised only on the
honest path: a hash of the wrong length, a zero chain id or amount, a malformed hashlock and a
missing key in a stored record each had a mutant that turned the refusal off with no test noticing.
Every refusal below is paired with the honest value next to its boundary.
"""

from __future__ import annotations

import time

import pytest

from pyrxd.eth_wallet.locator import (
    Erc20HtlcLocator,
    EthHtlcLocator,
    PendingDeploy,
    check_tx_hash,
    normalise_tx_hash,
)
from pyrxd.security.errors import ValidationError

_HASH = "0x" + "ab" * 32


def _fields(**over) -> dict:
    base = dict(
        chain_id=11155111,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash=_HASH,
        hashlock="0x" + "22" * 32,
        claimant="0x" + "33" * 20,
        refundee="0x" + "44" * 20,
        timeout=int(time.time()) + 86_400,
        amount_wei=10**14,
    )
    base.update(over)
    return base


# ── transaction-hash shape ──────────────────────────────────────────────────────────────────────


def test_check_tx_hash_accepts_exactly_0x_plus_64_hex():
    assert check_tx_hash(_HASH) == _HASH
    assert check_tx_hash("0x" + "AB" * 32) == "0x" + "AB" * 32


@pytest.mark.parametrize(
    "bad",
    [
        "0x" + "ab" * 31 + "a",  # 65 chars: one hex digit short
        "0x" + "ab" * 32 + "a",  # 67 chars
        "ab" * 33,  # 66 chars but no 0x — right length is not enough
        "0x",
    ],
)
def test_check_tx_hash_refuses_the_wrong_shape(bad):
    with pytest.raises(ValidationError, match="66 total"):
        check_tx_hash(bad)


@pytest.mark.parametrize("bad", ["0xg" + "a" * 63, "0x" + "a" * 63 + "z"])
def test_check_tx_hash_refuses_non_hex_at_either_end(bad):
    # First digit after the prefix matters: slicing from the wrong offset would skip it.
    with pytest.raises(ValidationError, match="not hex"):
        check_tx_hash(bad)


def test_check_tx_hash_refuses_a_non_string():
    with pytest.raises(ValidationError, match="must be a string"):
        check_tx_hash(12345)  # type: ignore[arg-type]


def test_normalise_tx_hash_prefixes_once_and_refuses_non_strings():
    assert normalise_tx_hash("ab" * 32) == _HASH
    assert normalise_tx_hash(_HASH) == _HASH
    with pytest.raises(ValidationError, match="non-empty string"):
        normalise_tx_hash("")
    with pytest.raises(ValidationError, match="non-empty string"):
        normalise_tx_hash(0xAB)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="non-empty string"):
        normalise_tx_hash(b"\xab" * 32)  # type: ignore[arg-type]


def test_pending_deploy_checks_the_hash_and_lowercases_the_address():
    pd = PendingDeploy(address="0x" + "AB" * 20, deploy_tx_hash=_HASH)
    assert pd.address == "0x" + "ab" * 20
    with pytest.raises(ValidationError):
        PendingDeploy(address="0x" + "ab" * 20, deploy_tx_hash="0x")


def test_durable_handles_cannot_be_rewritten_in_place():
    # Validation runs once, in __post_init__; a mutable handle could be pointed elsewhere after it.
    import dataclasses

    pd = PendingDeploy(address="0x" + "ab" * 20, deploy_tx_hash=_HASH)
    with pytest.raises(dataclasses.FrozenInstanceError):
        pd.address = "0x" + "cd" * 20  # type: ignore[misc]
    loc = EthHtlcLocator(**_fields())
    with pytest.raises(dataclasses.FrozenInstanceError):
        loc.contract_address = "0x" + "cd" * 20  # type: ignore[misc]


# ── EthHtlcLocator construction ──────────────────────────────────────────────────────────────────


def test_the_honest_locator_and_its_boundaries_are_accepted():
    loc = EthHtlcLocator(**_fields(chain_id=1, amount_wei=1, timeout=0))
    assert (loc.chain_id, loc.amount_wei, loc.timeout) == (1, 1, 0)
    assert loc.hashlock_bytes == b"\x22" * 32


@pytest.mark.parametrize("chain_id", [0, -1, True, "1", 1.0])
def test_a_chain_id_that_is_not_a_positive_int_is_refused(chain_id):
    with pytest.raises(ValidationError, match="chain_id"):
        EthHtlcLocator(**_fields(chain_id=chain_id))


@pytest.mark.parametrize(
    "hashlock",
    [
        "0x" + "22" * 31,  # 31 bytes
        "0x" + "22" * 33,  # 33 bytes
        "22" * 33,  # no prefix, right length
        b"\x22" * 32,  # bytes, not hex
    ],
)
def test_a_hashlock_that_is_not_0x_plus_32_bytes_is_refused(hashlock):
    with pytest.raises(ValidationError, match="hashlock must be"):
        EthHtlcLocator(**_fields(hashlock=hashlock))


def test_a_hashlock_that_is_not_hex_is_refused_as_a_validation_error():
    with pytest.raises(ValidationError, match="not valid hex"):
        EthHtlcLocator(**_fields(hashlock="0x" + "zz" * 32))


@pytest.mark.parametrize("field", ["timeout", "amount_wei"])
@pytest.mark.parametrize("bad", [-1, True, "5"])
def test_timeout_and_amount_must_be_non_negative_ints(field, bad):
    with pytest.raises(ValidationError, match=f"{field} must be a non-negative int"):
        EthHtlcLocator(**_fields(**{field: bad}))


def test_a_zero_amount_is_refused():
    with pytest.raises(ValidationError, match="amount_wei must be > 0"):
        EthHtlcLocator(**_fields(amount_wei=0))


def test_deploy_tx_hash_needs_the_prefix():
    with pytest.raises(ValidationError, match="deploy_tx_hash"):
        EthHtlcLocator(**_fields(deploy_tx_hash="ab" * 32))


# ── durable round trip ───────────────────────────────────────────────────────────────────────────


def test_eth_locator_round_trips_and_a_missing_key_is_a_validation_error():
    loc = EthHtlcLocator(**_fields())
    assert EthHtlcLocator.from_dict(loc.to_dict()) == loc
    d = loc.to_dict()
    del d["refundee"]
    with pytest.raises(ValidationError, match="missing key"):
        EthHtlcLocator.from_dict(d)


def test_erc20_locator_round_trips_and_a_missing_token_is_a_validation_error():
    loc = Erc20HtlcLocator(**_fields(), token_address="0x" + "CC" * 20)
    assert loc.token_address == "0x" + "cc" * 20
    assert loc.amount_base_units == loc.amount_wei
    d = loc.to_dict()
    assert d["token_address"] == "0x" + "cc" * 20
    assert Erc20HtlcLocator.from_dict(d) == loc
    del d["token_address"]
    with pytest.raises(ValidationError, match="missing field"):
        Erc20HtlcLocator.from_dict(d)
