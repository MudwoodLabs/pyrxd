"""Tests for CappedFeeWalletSource — the structural spend ceiling for autonomous RXD fees.

Focus: the ceiling is real (funded bound + software cap), dispense-once never double-spends
(incl. under concurrency), every pool input is a spendable plain-RXD P2PKH the pool key owns,
and every refusal fails closed with a typed FeePoolExhaustedError.
"""

from __future__ import annotations

import os
import threading

import pytest

from pyrxd.gravity.capped_fee_source import CappedFeeWalletSource
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import FeeUtxoSource
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import FeePoolExhaustedError, RxdSdkError, ValidationError
from pyrxd.security.types import Hex20

# A real (generated) pool key — never hand-write key material. A pool wallet has ONE key that
# owns many UTXOs, so all inputs share this key's P2PKH script; only the outpoints differ.
_KEY = PrivateKey(os.urandom(32))
_WIF = _KEY.wif()
_SPK = b"\x76\xa9\x14" + bytes(Hex20(_KEY.public_key().hash160())) + b"\x88\xac"


def _p2pkh_spk(key: PrivateKey) -> bytes:
    return b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"


def _fee(value: int, *, txid: str | None = None, vout: int = 0, wif: str = _WIF, spk: bytes = _SPK) -> FeeInput:
    return FeeInput(txid=txid or os.urandom(32).hex(), vout=vout, value=value, scriptpubkey=spk, wif=wif)


def _pool(*values: int) -> list[FeeInput]:
    return [_fee(v) for v in values]


# --------------------------------------------------------------------------- conformance


def test_satisfies_feeutxosource_protocol():
    src = CappedFeeWalletSource(_pool(1000), total_cap_photons=1000)
    assert isinstance(src, FeeUtxoSource)  # the RadiantCovenantLeg gate accepts it


def test_dispenses_pool_in_order():
    pool = _pool(1000, 2000, 3000)
    src = CappedFeeWalletSource(pool, total_cap_photons=10_000)
    got = [src.next_fee_input() for _ in range(3)]
    assert [f.value for f in got] == [1000, 2000, 3000]
    assert [f.txid for f in got] == [f.txid for f in pool]  # same objects, in order


# --------------------------------------------------------------------------- exhaustion + dispense-once


def test_exhaustion_raises_fail_closed():
    src = CappedFeeWalletSource(_pool(1000, 1000), total_cap_photons=1_000_000)
    src.next_fee_input()
    src.next_fee_input()
    with pytest.raises(FeePoolExhaustedError, match="exhausted"):
        src.next_fee_input()


def test_dispense_once_never_repeats_an_outpoint():
    src = CappedFeeWalletSource(_pool(*([1000] * 5)), total_cap_photons=1_000_000)
    seen = set()
    for _ in range(5):
        f = src.next_fee_input()
        key = (f.txid, f.vout)
        assert key not in seen, "an outpoint was dispensed twice — would double-spend"
        seen.add(key)


def test_concurrent_dispense_no_double_and_no_premature_exhaustion():
    # The lock exists to make the check-and-advance atomic so the same outpoint is never dispensed
    # twice (the "far worse failure"). Exercise it under real concurrency — a refactor that drops
    # the lock must fail this.
    n = 50
    src = CappedFeeWalletSource(_pool(*([1000] * n)), total_cap_photons=1000 * n)
    got: list[tuple[str, int]] = []
    errors: list[Exception] = []
    guard = threading.Lock()

    def worker() -> None:
        try:
            f = src.next_fee_input()
            with guard:
                got.append((f.txid, f.vout))
        except Exception as e:
            with guard:
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors  # exactly n inputs, none should have raised
    assert len(got) == n
    assert len(set(got)) == n  # no outpoint handed out twice


def test_exhaustion_error_is_catchable_as_sdk_error():
    src = CappedFeeWalletSource(_pool(1000), total_cap_photons=1000)
    src.next_fee_input()
    with pytest.raises(RxdSdkError):  # FeePoolExhaustedError subclasses the SDK base
        src.next_fee_input()


# --------------------------------------------------------------------------- the cap binds


def test_cap_refuses_before_overspending_even_with_inputs_left():
    # pool has 30k available, but the cap authorises only 20k.
    src = CappedFeeWalletSource(_pool(10_000, 10_000, 10_000), total_cap_photons=20_000)
    src.next_fee_input()  # 10k
    src.next_fee_input()  # 20k
    assert src.remaining_inputs == 1  # a pool UTXO is still physically there...
    with pytest.raises(FeePoolExhaustedError, match="cap reached"):
        src.next_fee_input()  # ...but the cap fails closed first
    assert src.dispensed_photons == 20_000  # never over-dispensed


def test_cap_at_exact_boundary():
    src = CappedFeeWalletSource(_pool(10_000, 10_000, 10_000), total_cap_photons=20_000)
    assert src.next_fee_input().value == 10_000
    assert src.next_fee_input().value == 10_000
    with pytest.raises(FeePoolExhaustedError):
        src.next_fee_input()


def test_dispensed_never_exceeds_cap_or_funded():
    src = CappedFeeWalletSource(_pool(*([1000] * 10)), total_cap_photons=4500)
    with pytest.raises(FeePoolExhaustedError):
        for _ in range(10):
            src.next_fee_input()
    assert src.dispensed_photons <= 4500
    assert src.dispensed_photons <= src.funded_photons


# --------------------------------------------------------------------------- introspection


def test_funded_photons_is_pool_sum():
    src = CappedFeeWalletSource(_pool(1000, 2000, 3000), total_cap_photons=100_000)
    assert src.funded_photons == 6000  # arithmetic sum; the *real* ceiling also needs key isolation


def test_remaining_photons_is_in_order_dispensable_prefix():
    # cap 4000 over [1000,2000,3000]: 1000+2000 fit (3000); the 3000 input would exceed -> stops.
    src = CappedFeeWalletSource(_pool(1000, 2000, 3000), total_cap_photons=4000)
    assert src.remaining_photons == 3000  # NOT 4000 — the 3rd input is head-of-line blocked
    assert src.remaining_inputs == 3  # physical inventory unchanged
    assert src.next_fee_input().value == 1000
    assert src.remaining_photons == 2000  # [2000] fits, [3000] still blocked
    assert src.dispensed_photons == 1000


def test_remaining_photons_bounded_by_pool_when_cap_is_huge():
    src = CappedFeeWalletSource(_pool(1000, 2000), total_cap_photons=100_000)
    assert src.remaining_photons == 3000  # the whole funded pool fits under the huge cap


def test_remaining_photons_is_zero_when_next_input_blocked_by_cap():
    # The paging-footgun fix: cap=4500 over uniform 1000s. After 4 dispenses, dispensed=4000; the
    # 5th (1000) would hit 5000>4500 and raise. remaining_photons must read 0 (honest "page now"),
    # not 500 — it tracks what next_fee_input will ACTUALLY dispense, not raw leftover headroom.
    src = CappedFeeWalletSource(_pool(*([1000] * 10)), total_cap_photons=4500)
    for _ in range(4):
        src.next_fee_input()
    assert src.dispensed_photons == 4000
    assert src.remaining_photons == 0  # honest: the next input cannot be dispensed
    assert src.remaining_inputs == 6  # physical inventory remains
    with pytest.raises(FeePoolExhaustedError):
        src.next_fee_input()


# --------------------------------------------------------------------------- construction validation


def test_rejects_empty_pool():
    with pytest.raises(ValidationError, match="non-empty"):
        CappedFeeWalletSource([], total_cap_photons=1000)


def test_rejects_non_feeinput():
    with pytest.raises(ValidationError, match="FeeInput"):
        CappedFeeWalletSource(["not-a-feeinput"], total_cap_photons=1000)


def test_rejects_duplicate_outpoint():
    txid = os.urandom(32).hex()
    dup = [_fee(1000, txid=txid, vout=0), _fee(1000, txid=txid, vout=0)]
    with pytest.raises(ValidationError, match="duplicate outpoint"):
        CappedFeeWalletSource(dup, total_cap_photons=1_000_000)


def test_same_txid_different_vout_is_allowed():
    txid = os.urandom(32).hex()
    pool = [_fee(1000, txid=txid, vout=0), _fee(1000, txid=txid, vout=1)]
    src = CappedFeeWalletSource(pool, total_cap_photons=1_000_000)
    assert src.remaining_inputs == 2


def test_rejects_non_p2pkh_input():
    # a non-bare-P2PKH script (e.g. a token / non-standard UTXO) would be destroyed if spent as a fee.
    bad = FeeInput(txid=os.urandom(32).hex(), vout=0, value=1000, scriptpubkey=b"\x51\x51", wif=_WIF)
    with pytest.raises(ValidationError, match="bare P2PKH"):
        CappedFeeWalletSource([bad], total_cap_photons=1_000_000)


def test_rejects_wif_not_controlling_the_utxo():
    # spk owned by a DIFFERENT key than the wif → the pool key can't spend it (stranded fee leg).
    other = PrivateKey(os.urandom(32))
    bad = FeeInput(txid=os.urandom(32).hex(), vout=0, value=1000, scriptpubkey=_p2pkh_spk(other), wif=_WIF)
    with pytest.raises(ValidationError, match="pkh mismatch"):
        CappedFeeWalletSource([bad], total_cap_photons=1_000_000)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_rejects_nonpositive_or_nonint_cap(bad):
    with pytest.raises(ValidationError, match="total_cap_photons"):
        CappedFeeWalletSource(_pool(1000), total_cap_photons=bad)


def test_rejects_oversized_input_when_max_set():
    pool = _pool(1000, 9_999_999)
    with pytest.raises(ValidationError, match="max_per_input_photons"):
        CappedFeeWalletSource(pool, total_cap_photons=100_000_000, max_per_input_photons=1_000_000)


def test_accepts_when_all_within_max_per_input():
    src = CappedFeeWalletSource(_pool(1000, 5000), total_cap_photons=100_000, max_per_input_photons=10_000)
    assert src.remaining_inputs == 2


@pytest.mark.parametrize("bad", [0, -5, True])
def test_rejects_bad_max_per_input(bad):
    with pytest.raises(ValidationError, match="max_per_input_photons"):
        CappedFeeWalletSource(_pool(1000), total_cap_photons=1000, max_per_input_photons=bad)


def test_cannot_grow_inventory_via_constructor_list_mutation():
    # the pool is copied to an immutable tuple; mutating the caller's list must not add inventory.
    caller_list = _pool(1000, 1000)
    src = CappedFeeWalletSource(caller_list, total_cap_photons=1_000_000)
    caller_list.append(_fee(1000))
    assert src.remaining_inputs == 2  # unaffected by the post-construction append
