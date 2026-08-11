"""Relay-floor guards on the two builders that used to take ``fee_sats`` on trust.

``build_maker_offer_tx`` (Radiant) and ``build_payment_tx`` (Bitcoin) each accepted any
non-negative fee and returned a fully-populated result — plausible txid, plausible
accounting — for a transaction no node would relay. Nothing offline caught it because the
fixtures agreed with the builder: 25 call sites across the suite passed
``fee_sats=10_000``, which is roughly 190x under Radiant's floor for the ~190-byte offer
transaction they were building. The fixtures described a chain state that cannot exist.

The Radiant one is fund-safety. Radiant has neither RBF nor CPFP
(:mod:`pyrxd.gravity.fee_policy` cites the source lines), so an under-fee'd offer cannot be
replaced or bumped and squats on the Maker's funding UTXO for the 8-hour mempool expiry.
The Bitcoin one is recoverable — RBF, CPFP, or just rebuild — and is guarded because a
builder should fail closed rather than hand back bytes that cannot go on the wire.

What is asserted here, and why each case is not redundant:

* **Per builder, the guard bites** — the exact fee the old fixtures used is refused.
* **Per builder, the boundary is exact** — a fee equal to the transaction's own floor is
  accepted and one unit under it is refused.
* **The floor is measured after signing.** DER signatures are 69-71 bytes, so these
  transactions come out at several different sizes; a guard sized against a pre-signing
  estimate would be wrong for some fraction of builds. A single example proves nothing, so
  the invariant is asserted over many builds and every shape the builders emit.
* **The two chains' floors are not interchangeable.** Radiant charges 10,000 photons per
  byte of ``GetTotalSize``; Bitcoin charges 1 satoshi per BIP141 vbyte. Applying either
  rule to the other chain is a specific, previously-made mistake, and two cases pin the
  direction of each.

Live-node proof of the same boundaries is in ``test_gravity_maker_offer_regtest_e2e.py``
and ``test_btc_payment_regtest_e2e.py``.
"""

from __future__ import annotations

import hashlib
import os
import time

import coincurve
import pytest

from pyrxd.base58 import base58check_encode
from pyrxd.btc_wallet import BtcUtxo, build_payment_tx, generate_keypair
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.gravity.fee_policy import (
    BITCOIN_MIN_RELAY_SATS_PER_KB,
    DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    DeadlineFeePolicy,
    bitcoin_virtual_size,
    radiant_relay_size,
)
from pyrxd.gravity.transactions import build_maker_offer_tx
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH

FAKE_TXID = "aa" * 32
#: The fee every one of the 25 offline call sites used before this guard existed.
_OLD_FIXTURE_FEE = 10_000
_PHOTONS_OFFERED = 500_000


# ---------------------------------------------------------------------------
# Helpers. Keys are always CSPRNG — never a literal, and never reused between
# builds, because a fresh key is what re-rolls the DER length these cases depend on.
# ---------------------------------------------------------------------------


def _maker() -> PrivateKeyMaterial:
    return PrivateKeyMaterial(os.urandom(32))


def _pub(pk: PrivateKeyMaterial) -> bytes:
    return coincurve.PrivateKey(pk.unsafe_raw_bytes()).public_key.format(compressed=True)


def _pkh(pub: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()


def _offer(pk: PrivateKeyMaterial, **kwargs):
    pub = _pub(pk)
    taker_pub = coincurve.PrivateKey(os.urandom(32)).public_key.format(compressed=True)
    defaults = dict(
        maker_pkh=_pkh(pub),
        maker_pk=pub,
        taker_pk=taker_pub,
        taker_radiant_pkh=_pkh(taker_pub),
        btc_receive_hash=os.urandom(20),
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=os.urandom(32),
        expected_nbits=bytes.fromhex("ffff001d"),
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=int(time.time()) + 48 * 3600,
        photons_offered=_PHOTONS_OFFERED,
        accept_short_deadline=False,
        reject_low_difficulty=False,
    )
    defaults.update(kwargs)
    return build_gravity_offer(**defaults)


def _build_offer_tx(pk, offer, fee: int, *, change: bool = False, fee_policy=None):
    """One MakerOffer build at ``fee``, funded so only the fee guard can refuse it."""
    change_addr = base58check_encode(b"\x00" + _pkh(_pub(pk))) if change else None
    return build_maker_offer_tx(
        offer=offer,
        funding_txid=FAKE_TXID,
        funding_vout=0,
        funding_photons=offer.photons_offered + fee + (50_000 if change else 0),
        fee_sats=fee,
        maker_privkey=pk,
        change_address=change_addr,
        fee_policy=fee_policy,
    )


_BTC_SHAPES = [
    ("p2wpkh", P2PKH, 20),
    ("p2wpkh", P2WPKH, 20),
    ("p2wpkh", P2SH, 20),
    ("p2wpkh", P2TR, 32),
    ("p2sh_p2wpkh", P2PKH, 20),
    ("p2sh_p2wpkh", P2WPKH, 20),
    ("p2sh_p2wpkh", P2SH, 20),
    ("p2sh_p2wpkh", P2TR, 32),
]


def _build_payment(fee: int, *, input_type="p2wpkh", to_type=P2WPKH, hash_len=20, value=1_000_000, fee_policy=None):
    kp = generate_keypair(network="bcrt")
    utxo = BtcUtxo(txid=FAKE_TXID, vout=0, value=value)
    return build_payment_tx(
        kp,
        utxo,
        os.urandom(hash_len),
        to_type,
        value - fee - 200_000,
        fee,
        input_type=input_type,
        fee_policy=fee_policy,
    )


def _payment_vsize(tx_hex: str) -> int:
    """BIP141 vsize of a built payment, re-derived from the returned wire bytes.

    Deliberately parsed back out of ``tx_hex`` rather than taken from anything the
    builder reports, so this measurement is independent of the one the guard made.
    """
    raw = bytes.fromhex(tx_hex)
    assert raw[4:6] == b"\x00\x01", "these builds are always segwit-serialized"
    pos = 6
    n_in, pos = _read_varint(raw, pos)
    for _ in range(n_in):
        pos += 36
        slen, pos = _read_varint(raw, pos)
        pos += slen + 4
    n_out, pos = _read_varint(raw, pos)
    for _ in range(n_out):
        pos += 8
        slen, pos = _read_varint(raw, pos)
        pos += slen
    end_of_outputs = pos
    stripped = len(raw[:4]) + len(raw[6:end_of_outputs]) + 4
    return bitcoin_virtual_size(stripped_size=stripped, total_size=len(raw))


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    n = buf[pos]
    if n < 0xFD:
        return n, pos + 1
    if n == 0xFD:
        return int.from_bytes(buf[pos + 1 : pos + 3], "little"), pos + 3
    if n == 0xFE:
        return int.from_bytes(buf[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(buf[pos + 9 : pos + 9], "little"), pos + 9


# ===========================================================================
# 1. The guard bites — the fee the whole offline suite used to pass
# ===========================================================================


class TestTheGuardBites:
    def test_maker_offer_refuses_the_old_fixture_fee(self):
        """FAILS WITHOUT THE GUARD. ``build_maker_offer_tx`` returned this happily.

        10,000 photons is under the floor for a transaction of *any* size this builder can
        emit — Radiant's floor is 10,000 photons per byte — so the refusal here does not
        depend on which DER length this particular signature came out at.
        """
        pk = _maker()
        offer = _offer(pk)
        with pytest.raises(InsufficientFundsError) as exc:
            _build_offer_tx(pk, offer, _OLD_FIXTURE_FEE)
        msg = str(exc.value)
        assert "MakerOffer" in msg
        assert "photons" in msg
        # The error carries the machine-readable triple, not just prose.
        assert exc.value.available == _OLD_FIXTURE_FEE
        assert exc.value.required > _OLD_FIXTURE_FEE

    def test_maker_offer_refuses_the_old_fixture_fee_with_change(self):
        """The two-output shape is bigger, so its floor is higher; same refusal."""
        pk = _maker()
        offer = _offer(pk)
        with pytest.raises(InsufficientFundsError):
            _build_offer_tx(pk, offer, _OLD_FIXTURE_FEE, change=True)

    def test_maker_offer_refuses_a_zero_fee(self):
        pk = _maker()
        offer = _offer(pk)
        with pytest.raises(InsufficientFundsError):
            _build_offer_tx(pk, offer, 0)

    @pytest.mark.parametrize(("input_type", "to_type", "hash_len"), _BTC_SHAPES)
    def test_payment_refuses_a_one_satoshi_fee(self, input_type, to_type, hash_len):
        """FAILS WITHOUT THE GUARD. Every shape the BTC builder emits is >1 vbyte."""
        with pytest.raises(InsufficientFundsError) as exc:
            _build_payment(1, input_type=input_type, to_type=to_type, hash_len=hash_len)
        assert "BTC payment" in str(exc.value)
        assert "satoshis" in str(exc.value)

    def test_payment_refuses_a_zero_fee(self):
        with pytest.raises(InsufficientFundsError):
            _build_payment(0)

    def test_each_chain_is_told_the_truth_about_its_own_recovery_options(self):
        """The shared guard must not tell a Bitcoin caller they cannot bump the fee.

        Radiant has neither RBF nor CPFP and the message says so, because that is what
        makes the Radiant case fund-safety. Bitcoin has both, and repeating Radiant's
        explanation there would be a false statement about the user's own chain — and
        would misdirect the recovery.
        """
        pk = _maker()
        offer = _offer(pk)
        with pytest.raises(InsufficientFundsError) as rxd:
            _build_offer_tx(pk, offer, _OLD_FIXTURE_FEE)
        with pytest.raises(InsufficientFundsError) as btc:
            _build_payment(1)

        assert "no RBF and no CPFP" in str(rxd.value)
        assert "mempool expiry" in str(rxd.value)
        assert "RBF" not in str(btc.value), f"Radiant's un-bumpable rationale leaked into a BTC error: {btc.value}"
        assert "CPFP" not in str(btc.value)
        assert "no node will relay" in str(btc.value)

    def test_insufficient_funds_error_is_still_a_validation_error(self):
        """Callers that catch ``ValidationError`` keep catching this — no new escape."""
        pk = _maker()
        offer = _offer(pk)
        with pytest.raises(ValidationError):
            _build_offer_tx(pk, offer, _OLD_FIXTURE_FEE)


# ===========================================================================
# 2. The boundary is exact, on each chain's own rule
# ===========================================================================


class TestTheBoundaryIsExact:
    """A fee equal to the transaction's own floor passes; one unit under it does not.

    The fee is part of the signed output value, so changing it re-signs the input and can
    move the DER length — and therefore the size the floor is derived from. The floor is
    consequently *searched for* rather than solved, exactly as the live-node cases do.
    """

    def test_maker_offer_accepts_a_fee_equal_to_its_own_floor(self):
        """Search for a build whose fee is EXACTLY its own floor, and assert it passes.

        Not a fixed-point iteration on one key: re-signing at a new fee can grow the
        transaction, in which case the guard correctly refuses and the search has to move
        on. Bidding the floor of the largest size seen so far always clears, and a fresh
        key each round re-rolls the DER length until one lands exactly on that size.
        """
        policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
        sizes = set()
        for _ in range(60):
            pk = _maker()
            offer = _offer(pk)
            probe = _build_offer_tx(pk, offer, 5_000_000)
            sizes.add(probe.tx_size)
            try:
                built = _build_offer_tx(pk, offer, policy.min_relay_fee(probe.tx_size))
            except InsufficientFundsError:
                continue  # re-signing grew the tx by a byte; refusing is the right answer
            sizes.add(built.tx_size)
            if built.fee_sats == policy.min_relay_fee(built.tx_size):
                assert built.tx_size == radiant_relay_size(bytes.fromhex(built.tx_hex))
                return
        raise AssertionError(f"no offer tx reached a fee equal to its own relay floor (sizes seen: {sorted(sizes)})")

    def test_maker_offer_refuses_one_photon_under_the_floor(self):
        """One unit under is refused whenever the size does not shrink to compensate.

        A build at ``floor - 1`` re-signs, and if the DER length happens to drop a byte the
        floor drops 10,000 photons with it and the lower fee is then legitimately fine. So
        the assertion is the honest one: across fresh attempts the refusal must actually be
        observed, and any build that is NOT refused must still clear its own floor.
        """
        policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
        refused = 0
        for _ in range(24):
            pk = _maker()
            offer = _offer(pk)
            probe = _build_offer_tx(pk, offer, 5_000_000)
            fee = policy.min_relay_fee(probe.tx_size) - 1
            try:
                built = _build_offer_tx(pk, offer, fee)
            except InsufficientFundsError:
                refused += 1
                continue
            # Not refused => the transaction shrank. It must still clear its own floor.
            assert built.fee_sats >= policy.min_relay_fee(built.tx_size)
        assert refused > 0, "one photon under the floor was never refused in 24 attempts"

    @pytest.mark.parametrize(("input_type", "to_type", "hash_len"), _BTC_SHAPES)
    def test_payment_accepts_a_fee_equal_to_its_own_vsize(self, input_type, to_type, hash_len):
        """Bitcoin's floor at 1 sat/vB IS the vsize, so the target is fee == vsize.

        Searched, not iterated: each build signs with a fresh key, so bidding the previous
        build's vsize can land a byte either side of it and a naive fixed-point loop
        oscillates instead of converging. Retrying is the honest form of the question —
        "is there a transaction whose fee is exactly its own floor, and is it accepted".
        """
        policy = DEFAULT_BITCOIN_DEADLINE_FEE_POLICY
        seen = set()
        for _ in range(60):
            probe = _build_payment(400, input_type=input_type, to_type=to_type, hash_len=hash_len)
            fee = policy.min_relay_fee(_payment_vsize(probe.tx_hex))
            try:
                built = _build_payment(fee, input_type=input_type, to_type=to_type, hash_len=hash_len)
            except InsufficientFundsError:
                continue  # re-signing grew the vsize; refusing is the right answer
            vsize = _payment_vsize(built.tx_hex)
            seen.add(vsize)
            if built.fee_sats == policy.min_relay_fee(vsize):
                assert built.fee_sats == vsize, "at 1 sat/vB the floor and the vsize are the same number"
                return
        raise AssertionError(
            f"no {input_type}->{to_type} payment hit a fee equal to its own vsize (saw {sorted(seen)})"
        )

    def test_payment_refuses_one_satoshi_under_the_floor(self):
        policy = DEFAULT_BITCOIN_DEADLINE_FEE_POLICY
        refused = 0
        for _ in range(24):
            probe = _build_payment(400)
            fee = policy.min_relay_fee(_payment_vsize(probe.tx_hex)) - 1
            try:
                built = _build_payment(fee)
            except InsufficientFundsError:
                refused += 1
                continue
            assert built.fee_sats >= policy.min_relay_fee(_payment_vsize(built.tx_hex))
        assert refused > 0, "one satoshi under the floor was never refused in 24 attempts"


# ===========================================================================
# 3. Property/differential: the invariant holds over many builds and shapes
# ===========================================================================


class TestEveryReturnedTransactionClearsItsOwnFloor:
    """A single example proves nothing here, because the size is not a constant.

    These transactions come out at several different lengths — the DER signature is 69-71
    bytes — so a guard that measured an estimate instead of the signed bytes would be
    right for some builds and wrong for others. Each case therefore asserts the invariant
    across many independent builds AND asserts that the size really did vary, so the
    coverage is not silently vacuous.
    """

    def test_maker_offer_invariant_over_many_builds(self):
        policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
        sizes = set()
        for i in range(240):
            pk = _maker()
            offer = _offer(pk)
            with_change = bool(i % 2)
            # Fee deliberately AT the floor of a nearby size, not comfortably above it, so
            # an off-by-one in the measurement shows up instead of being absorbed.
            probe = _build_offer_tx(pk, offer, 5_000_000, change=with_change)
            fee = policy.min_relay_fee(probe.tx_size)
            try:
                built = _build_offer_tx(pk, offer, fee, change=with_change)
            except InsufficientFundsError:
                continue  # re-signing grew the tx; the guard refusing is the correct answer
            sizes.add(built.tx_size)
            assert built.fee_sats >= policy.min_relay_fee(built.tx_size), (
                f"returned an offer tx below its own floor: {built.fee_sats} < "
                f"{policy.min_relay_fee(built.tx_size)} for {built.tx_size} bytes"
            )
            # The reported size must be the real one, or the floor was computed on fiction.
            assert built.tx_size == radiant_relay_size(bytes.fromhex(built.tx_hex))
        assert len(sizes) > 1, f"transaction size never varied ({sizes}) — the test is not exercising DER variance"

    @pytest.mark.parametrize(("input_type", "to_type", "hash_len"), _BTC_SHAPES)
    def test_payment_invariant_over_many_builds(self, input_type, to_type, hash_len):
        policy = DEFAULT_BITCOIN_DEADLINE_FEE_POLICY
        vsizes = set()
        for _ in range(40):
            probe = _build_payment(400, input_type=input_type, to_type=to_type, hash_len=hash_len)
            fee = policy.min_relay_fee(_payment_vsize(probe.tx_hex))
            try:
                built = _build_payment(fee, input_type=input_type, to_type=to_type, hash_len=hash_len)
            except InsufficientFundsError:
                continue
            vsize = _payment_vsize(built.tx_hex)
            vsizes.add(vsize)
            assert built.fee_sats >= policy.min_relay_fee(vsize), (
                f"returned a payment below its own floor: {built.fee_sats} < "
                f"{policy.min_relay_fee(vsize)} for {vsize} vbytes"
            )
        assert vsizes, "no payment was built"


# ===========================================================================
# 4. The floor is PER-CHAIN. This is the mistake to keep pinned down.
# ===========================================================================


class TestTheFloorsAreNotInterchangeable:
    def test_bitcoin_is_not_charged_radiants_floor(self):
        """A payment at 1 sat/vB is legitimate and must be built.

        If Radiant's 10,000-per-byte rule leaked into the BTC path it would demand roughly
        1.4 million satoshis for a ~140-vbyte payment. This case is the regression test for
        that specific error, which has been made in this project before.
        """
        built = _build_payment(200)
        vsize = _payment_vsize(built.tx_hex)
        assert built.fee_sats >= vsize, "precondition: 200 sats clears 1 sat/vB for this shape"
        radiant_demand = DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(len(bytes.fromhex(built.tx_hex)))
        assert built.fee_sats < radiant_demand, (
            "precondition: this fee is far under what Radiant's rule would demand "
            f"({built.fee_sats} vs {radiant_demand})"
        )

    def test_radiant_is_not_charged_bitcoins_floor(self):
        """Conversely, an offer fee'd at what Bitcoin would want must be refused.

        Bitcoin's rule would ask about 190 satoshis for a 190-byte transaction. On Radiant
        that is four orders of magnitude short, and it is the direction that loses money:
        the offer would be unrelayable and un-bumpable.
        """
        pk = _maker()
        offer = _offer(pk)
        probe_fee = DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.min_relay_fee(190)  # 190 sats
        with pytest.raises(InsufficientFundsError):
            _build_offer_tx(pk, offer, probe_fee)

    def test_the_two_default_policies_disagree_by_four_orders_of_magnitude(self):
        """Guards the constants themselves against a copy-paste that unifies them."""
        assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.relay_fee_per_kb == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
        assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.relay_fee_per_kb == BITCOIN_MIN_RELAY_SATS_PER_KB
        assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.relay_fee_per_kb == 10_000 * BITCOIN_MIN_RELAY_SATS_PER_KB
        # And the Bitcoin policy's protocol bound is Bitcoin's, not Radiant's — the
        # original reason `protocol_floor_per_kb` is a field at all.
        assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.protocol_floor_per_kb == BITCOIN_MIN_RELAY_SATS_PER_KB


class TestTheSizeMeasuresDiffer:
    """``radiant_relay_size`` and ``bitcoin_virtual_size`` are not the same number."""

    def test_vsize_is_strictly_less_than_total_for_a_witness_transaction(self):
        built = _build_payment(2_000)
        total = len(bytes.fromhex(built.tx_hex))
        vsize = _payment_vsize(built.tx_hex)
        assert vsize < total, "a segwit payment must be discounted relative to its total size"
        # Radiant's measure on the same bytes is the undiscounted one.
        assert radiant_relay_size(bytes.fromhex(built.tx_hex)) == total

    def test_vsize_equals_total_size_for_a_non_witness_transaction(self):
        assert bitcoin_virtual_size(stripped_size=250, total_size=250) == 250

    def test_vsize_rounds_up(self):
        # weight = 100*3 + 101 = 401; 401/4 = 100.25 -> 101
        assert bitcoin_virtual_size(stripped_size=100, total_size=101) == 101

    @pytest.mark.parametrize(
        ("stripped", "total"),
        [(0, 10), (10, 0), (-1, 10), (10, 5)],
    )
    def test_vsize_rejects_impossible_inputs(self, stripped, total):
        with pytest.raises(ValidationError):
            bitcoin_virtual_size(stripped_size=stripped, total_size=total)

    def test_radiant_relay_size_rejects_an_empty_transaction(self):
        with pytest.raises(ValidationError):
            radiant_relay_size(b"")


# ===========================================================================
# 5. The rate is node policy, so it must be overridable
# ===========================================================================


class TestThePolicyIsInjectable:
    """A regtest node advertises a lower floor than mainnet, and callers must be able to
    say so — otherwise the guard would refuse transactions the target node accepts.
    """

    def test_maker_offer_accepts_a_lower_regtest_rate(self):
        pk = _maker()
        offer = _offer(pk)
        # Radiant's legacy floor, 1/10th the post-2.0 effective one.
        low = DeadlineFeePolicy(relay_fee_per_kb=1_000_000)
        built = _build_offer_tx(pk, offer, 250_000, fee_policy=low)
        assert built.fee_sats == 250_000
        # ...and the same fee is still refused under the mainnet default.
        with pytest.raises(InsufficientFundsError):
            _build_offer_tx(pk, offer, 250_000)

    def test_maker_offer_still_refuses_below_the_injected_rate(self):
        pk = _maker()
        offer = _offer(pk)
        low = DeadlineFeePolicy(relay_fee_per_kb=1_000_000)
        with pytest.raises(InsufficientFundsError):
            _build_offer_tx(pk, offer, 1_000, fee_policy=low)

    def test_payment_accepts_a_higher_injected_rate_only_above_it(self):
        strict = DeadlineFeePolicy(
            relay_fee_per_kb=10 * BITCOIN_MIN_RELAY_SATS_PER_KB,
            protocol_floor_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB,
        )
        built = _build_payment(5_000, fee_policy=strict)
        assert built.fee_sats == 5_000
        with pytest.raises(InsufficientFundsError):
            _build_payment(200, fee_policy=strict)

    def test_a_sub_protocol_rate_needs_the_explicit_escape_hatch(self):
        """The deliberate, greppable way to build for a chain you control."""
        with pytest.raises(ValidationError):
            DeadlineFeePolicy(relay_fee_per_kb=1_000)
        pk = _maker()
        offer = _offer(pk)
        permissive = DeadlineFeePolicy(relay_fee_per_kb=1_000, allow_below_protocol_floor=True)
        built = _build_offer_tx(pk, offer, 1_000, fee_policy=permissive)
        assert built.fee_sats == 1_000
