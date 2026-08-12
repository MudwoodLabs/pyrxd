"""The HTLC covenant spend builders' min-relay fee floor (gap-closure A1).

Before this, the ONLY fee guard on a covenant spend was a flat
``if fee.value < 546: raise`` — a Bitcoin dust floor, ~4,900x below what the
reference Radiant node actually relays for a spend of this size. Radiant has
neither RBF nor CPFP, so an under-fee'd time-critical spend cannot be repaired
after broadcast; the guard has to bind at BUILD time or not at all.

The sizes below are MEASURED (``len(tx.serialize())`` on a genuinely built and
signed transaction), not estimated, and pinned so a change to the covenant, the
holder scripts or the signing path shows up as a fee-requirement change rather
than silently.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets

import pytest

from pyrxd.fee_sizing import MAX_FEE_OVERPAY_MULTIPLE
from pyrxd.gravity.fee_policy import (
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
)
from pyrxd.gravity.htlc_covenant import (
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import (
    DUST_FLOOR_PHOTONS,
    FeeInput,
    build_htlc_claim_tx,
    build_htlc_refund_tx,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20

_P = bytes.fromhex("11" * 32)
_H = hashlib.sha256(_P).digest()
_TAKER_PKH = b"\x11" * 20
_MAKER_PKH = b"\x22" * 20
_REF_TXID = "ab" * 32
_OUTPOINT = "cd" * 32 + ":0"

# A rate low enough that the relay floor cannot bind, for the tests that need to
# exercise something OTHER than the fee guard (1 photon/kB => 1 photon for any
# sub-1000-byte tx). This is the documented escape hatch: an explicit, injected
# policy — never a weakened guard.
# allow_below_protocol_floor: a rate this low is refused by default, because in
# production it can only come from a lying or misconfigured node (security review).
# Opting out here is exactly the deliberate, greppable act the flag exists for.
_NEGLIGIBLE_RATE = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)


def _rand_below(n: int) -> int:
    """A uniform draw in ``[0, n)`` from the OS CSPRNG — no seeded/global RNG state."""
    return secrets.randbelow(n)


def _fee(value: int) -> FeeInput:
    key = PrivateKey(bytes.fromhex("33" * 32))
    pkh = bytes(Hex20(key.public_key().hash160()))
    spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    return FeeInput(txid="ab" * 32, vout=0, value=value, scriptpubkey=spk, wif=key.wif())


def _rxd_cov(csv: int = 6):
    return build_htlc_covenant_rxd(
        amount=100_000, taker_pkh=_TAKER_PKH, maker_pkh=_MAKER_PKH, hashlock=_H, refund_csv=csv
    )


def _ft_cov():
    return build_htlc_covenant_ft(
        genesis_txid=_REF_TXID,
        genesis_vout=0,
        amount=1000,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=6,
    )


def _nft_cov():
    return build_htlc_covenant_nft(
        genesis_txid=_REF_TXID,
        genesis_vout=0,
        nft_carrier_value=1000,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=6,
    )


# --------------------------------------------------------------- measured sizes


def test_measured_covenant_spend_sizes():
    """Pin the MEASURED serialized size of every covenant spend shape.

    These are the numbers the fee requirement is derived from. Note how small they
    are: the covenant script lives in the *funding* output's scriptPubKey, so the
    SPEND only carries a tiny scriptSig (a 33-byte preimage push + a 1-byte selector
    for a claim; a single OP_1 for a refund). A covenant spend is a few hundred
    bytes, not the multi-kB shape the SPV maker covenant has.
    """
    fee = _fee(50_000_000)
    sizes = {
        "rxd_claim": len(
            build_htlc_claim_tx(
                covenant=_rxd_cov(), covenant_outpoint=_OUTPOINT, carrier_value=100_000, preimage=_P, fee=fee
            ).serialize()
        ),
        "rxd_refund": len(
            build_htlc_refund_tx(
                covenant=_rxd_cov(), covenant_outpoint=_OUTPOINT, carrier_value=100_000, fee=fee
            ).serialize()
        ),
        "ft_claim": len(
            build_htlc_claim_tx(
                covenant=_ft_cov(), covenant_outpoint=_OUTPOINT, carrier_value=1000, preimage=_P, fee=fee
            ).serialize()
        ),
        "nft_claim": len(
            build_htlc_claim_tx(
                covenant=_nft_cov(), covenant_outpoint=_OUTPOINT, carrier_value=1000, preimage=_P, fee=fee
            ).serialize()
        ),
    }
    # A DER signature is 70-72 bytes depending on the R/S high bit, so the exact
    # size varies by a byte or two per signing nonce; assert a tight band, not a
    # single value. The point is the ORDER OF MAGNITUDE: hundreds of bytes.
    assert 230 <= sizes["rxd_claim"] <= 270, sizes
    assert 200 <= sizes["rxd_refund"] <= 240, sizes
    assert 280 <= sizes["ft_claim"] <= 320, sizes
    assert 270 <= sizes["nft_claim"] <= 310, sizes
    assert sizes["rxd_refund"] < sizes["rxd_claim"] < sizes["nft_claim"] < sizes["ft_claim"]


def test_546_photons_is_no_longer_sufficient_for_a_realistic_spend():
    """The regression pin: the old flat dust floor alone must NOT pass.

    546 photons clears the dust floor exactly (it IS the dust floor), so before A1
    this built a transaction the reference node would reject on min-relay — and, with
    no RBF and no CPFP, one that could never be fixed.
    """
    assert DUST_FLOOR_PHOTONS == 546  # the floor is retained, not weakened
    with pytest.raises(InsufficientFundsError) as ei:
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(DUST_FLOOR_PHOTONS),
        )
    assert ei.value.available == 546
    # ~2.66M photons for a ~266-byte spend at 0.10 RXD/kB: about 4,900x the dust floor.
    assert ei.value.required is not None
    assert 2_300_000 < ei.value.required < 2_800_000
    assert ei.value.required // DUST_FLOOR_PHOTONS > 4_000

    with pytest.raises(InsufficientFundsError):
        build_htlc_refund_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            fee=_fee(DUST_FLOOR_PHOTONS),
        )


def test_the_guard_names_required_supplied_and_shortfall():
    with pytest.raises(InsufficientFundsError) as ei:
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(1_000_000),
        )
    exc = ei.value
    assert exc.available == 1_000_000
    assert exc.required is not None and exc.required > 1_000_000
    assert exc.shortfall == exc.required - 1_000_000
    msg = str(exc)
    assert "1000000" in msg  # supplied
    assert str(exc.required) in msg  # required
    assert str(exc.shortfall) in msg  # shortfall
    assert "HTLC covenant claim" in msg
    assert "no RBF" in msg and "no CPFP" in msg


def test_the_dust_floor_still_fires_first_and_is_unweakened():
    # Below dust the cheap, size-independent pre-check rejects — unchanged behaviour,
    # and it must NOT have been replaced by the new floor.
    with pytest.raises(ValidationError, match="below the dust floor"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(100),
        )
    # ...and it fires even under a negligible-rate policy, i.e. the injected rate
    # cannot be used to sneak a sub-dust fee input past the floor.
    with pytest.raises(ValidationError, match="below the dust floor"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(100),
            fee_policy=_NEGLIGIBLE_RATE,
        )


def test_a_realistic_fee_input_builds_normally():
    tx = build_htlc_claim_tx(
        covenant=_rxd_cov(),
        covenant_outpoint=_OUTPOINT,
        carrier_value=100_000,
        preimage=_P,
        fee=_fee(10_000_000),
    )
    # The whole fee input IS the miner fee: single output, no change.
    assert len(tx.outputs) == 1
    total_in = sum(i.satoshis for i in tx.inputs)
    assert total_in - tx.outputs[0].satoshis == 10_000_000


def test_the_requirement_tracks_the_injected_rate_not_a_hardcoded_constant():
    # The node's effective_minrelaytxfee is POLICY and can move. A caller pointing at
    # a node with a different rate gets a different requirement, with no code change.
    # 0.01 RXD/kB — the LEGACY minrelaytxfee, a tenth of what the chain now enforces, so
    # it needs the explicit escape hatch (the protocol bound is the EFFECTIVE rate now).
    cheap = DeadlineFeePolicy(relay_fee_per_kb=1_000_000, allow_below_protocol_floor=True)
    tx = build_htlc_claim_tx(
        covenant=_rxd_cov(),
        covenant_outpoint=_OUTPOINT,
        carrier_value=100_000,
        preimage=_P,
        fee=_fee(500_000),
        fee_policy=cheap,
    )
    assert tx is not None
    # The same fee input is refused at the DEFAULT (10x higher) effective rate.
    with pytest.raises(InsufficientFundsError):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(500_000),
        )


def test_the_builders_size_against_the_real_serialized_bytes():
    # The requirement must be derived from len(tx.serialize()) — not a guess.
    probe = build_htlc_claim_tx(
        covenant=_rxd_cov(),
        covenant_outpoint=_OUTPOINT,
        carrier_value=100_000,
        preimage=_P,
        fee=_fee(50_000_000),
    )
    size = len(probe.serialize())
    required = DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(size)
    # One byte costs 10,000 photons at the default rate; allow a 3-byte band for DER
    # signature-length jitter (see test_serialized_size_jitters_with_the_fee_value).
    band = 3 * 10_000
    ok = build_htlc_claim_tx(
        covenant=_rxd_cov(),
        covenant_outpoint=_OUTPOINT,
        carrier_value=100_000,
        preimage=_P,
        fee=_fee(required + band),
    )
    assert abs(len(ok.serialize()) - size) <= 3
    with pytest.raises(InsufficientFundsError) as ei:
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(required - band),
        )
    assert ei.value.required is not None and abs(ei.value.required - required) <= band
    assert "-byte transaction" in str(ei.value)


def test_serialized_size_jitters_with_the_fee_value():
    """Why the guard MEASURES instead of estimating.

    The fee input's value is committed in the sighash preimage, so changing it
    changes the message, the (RFC6979-deterministic) signature, and therefore the DER
    encoding length — a spend is 265-267 bytes depending on the fee value chosen. A
    guard sized off a pre-signing estimate would be wrong by up to a couple of bytes
    (20,000+ photons at the effective rate) in whichever direction the estimate erred.
    """
    sizes = set()
    for value in (5_000_000, 7_500_000, 10_000_000, 12_345_678, 20_000_000):
        tx = build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint=_OUTPOINT,
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(value),
        )
        sizes.add(len(tx.serialize()))
    assert len(sizes) >= 1
    assert max(sizes) - min(sizes) <= 3  # a DER length wobble, not a shape change
    # Whatever the size, the same builder call is deterministic for a given fee value.
    again = build_htlc_claim_tx(
        covenant=_rxd_cov(), covenant_outpoint=_OUTPOINT, carrier_value=100_000, preimage=_P, fee=_fee(10_000_000)
    )
    once = build_htlc_claim_tx(
        covenant=_rxd_cov(), covenant_outpoint=_OUTPOINT, carrier_value=100_000, preimage=_P, fee=_fee(10_000_000)
    )
    assert again.serialize() == once.serialize()


@pytest.mark.parametrize("cov_factory", [_rxd_cov, _ft_cov, _nft_cov])
def test_every_covenant_variant_is_guarded(cov_factory):
    carrier = 100_000 if cov_factory is _rxd_cov else 1000
    with pytest.raises(InsufficientFundsError):
        build_htlc_claim_tx(
            covenant=cov_factory(), covenant_outpoint=_OUTPOINT, carrier_value=carrier, preimage=_P, fee=_fee(1000)
        )


def test_an_explicit_low_rate_policy_is_the_documented_escape_hatch():
    # A caller that genuinely needs a sub-relay fee (a unit test exercising some
    # other property, or a chain whose relay rate really is that low) says so
    # explicitly by injecting a rate. There is no flag that disables the guard.
    tx = build_htlc_claim_tx(
        covenant=_rxd_cov(),
        covenant_outpoint=_OUTPOINT,
        carrier_value=100_000,
        preimage=_P,
        fee=_fee(1000),
        fee_policy=_NEGLIGIBLE_RATE,
    )
    assert len(tx.outputs) == 1


# ------------------------------------------------------- the OTHER end of the rule


class TestTheFeeInputHasAnUpperBoundToo:
    """FO-2. A guard that only checks the lower bound is half a guard.

    ``_check_carrier``'s comment promised a guard against "a mistakenly-huge UTXO or a
    sub-dust one" and only the sub-dust half existed. The covenant enforces exactly one
    output, so there is no change and the **whole fee input is paid to the miner** —
    "choosing the fee" here means choosing which UTXO to burn. Reproduced on this
    builder before the fix, a real RXD HTLC claim with a 500 RXD fee input::

        built OK: 266 bytes, 1 output(s)
        fee actually paid: 50000000000 photons (500.00 RXD)
        relay floor for 266 bytes: 2660000 photons
        OVERPAY MULTIPLE: 18797x            -> no exception, no warning, no log line

    The same shape burned 500 RXD through the cold-recovery toolkit (audit B4), which
    is where the 10x ceiling came from. WARN, never raise: refusing a spend the node
    would have accepted forfeits the asset to the counterparty's CSV refund
    (``docs/threat-model.md`` S21), and that is strictly worse than an overpaid fee.
    """

    #: Draws per property case. Every draw is a fresh key, a fresh hashlock, a fresh
    #: covenant and a fresh outpoint, so each build signs a different message and the
    #: DER length (69-71 bytes) moves the measured size the ceiling is derived from.
    ROUNDS = 25

    @staticmethod
    def _fresh_fee(value: int) -> FeeInput:
        key = PrivateKey()
        pkh = bytes(Hex20(key.public_key().hash160()))
        return FeeInput(
            txid=os.urandom(32).hex(),
            vout=0,
            value=value,
            scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac",
            wif=key.wif(),
        )

    @classmethod
    def _fresh_claim(cls, value: int):
        """A genuinely fresh RXD HTLC claim. Returns ``(tx, floor, multiple)``."""
        preimage = os.urandom(32)
        cov = build_htlc_covenant_rxd(
            amount=100_000,
            taker_pkh=os.urandom(20),
            maker_pkh=os.urandom(20),
            hashlock=hashlib.sha256(preimage).digest(),
            refund_csv=6,
        )
        tx = build_htlc_claim_tx(
            covenant=cov,
            covenant_outpoint=os.urandom(32).hex() + ":0",
            carrier_value=100_000,
            preimage=preimage,
            fee=cls._fresh_fee(value),
        )
        floor = DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(len(tx.serialize()))
        return tx, floor, value / floor

    def test_a_500_rxd_fee_input_is_warned_about_and_still_built(self, caplog) -> None:
        """The verbatim reproduction, and both halves of the decision in one case."""
        with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.htlc_spend"):
            tx, floor, multiple = self._fresh_claim(50_000_000_000)  # 500 RXD
        assert multiple > 18_000, multiple
        assert len(tx.outputs) == 1, "the build still succeeds — refusing would forfeit the asset"
        assert tx.get_fee() == 50_000_000_000
        text = caplog.text
        assert "ENTIRE input is paid to the miner" in text, text
        assert str(floor) in text, text
        # The multiple is REPORTED, not pinned to one digit string: the spend is 265-267
        # bytes depending on the DER length, so 500 RXD is 18,727x-18,797x of it. A test
        # that pinned "18797x" would pass on one signature and fail on the next.
        assert f"{multiple:.0f}x" in text, text
        assert "50000000000 photons" in text, text

    def test_the_refund_path_is_bounded_too(self, caplog) -> None:
        """``build_htlc_refund_tx`` reaches the same gate — it is the maker's exit."""
        preimage = os.urandom(32)
        cov = build_htlc_covenant_rxd(
            amount=100_000,
            taker_pkh=os.urandom(20),
            maker_pkh=os.urandom(20),
            hashlock=hashlib.sha256(preimage).digest(),
            refund_csv=6,
        )
        with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.htlc_spend"):
            tx = build_htlc_refund_tx(
                covenant=cov,
                covenant_outpoint=os.urandom(32).hex() + ":0",
                carrier_value=100_000,
                fee=self._fresh_fee(50_000_000_000),
            )
        assert len(tx.outputs) == 1
        assert "HTLC covenant refund" in caplog.text, caplog.text

    def test_a_normal_fee_is_silent_over_fresh_keys(self, caplog) -> None:
        """The half that matters as much: an ordinary fee must not page anyone.

        A warning that fires on routine work is a warning nobody reads, and the next
        real 500 RXD burn goes past it. Swept at 1x-10x the floor over fresh keys.
        """
        for _ in range(self.ROUNDS):
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.htlc_spend"):
                _tx, _floor, multiple = self._fresh_claim(int(2_700_000 * (1 + _rand_below(9))))
            assert multiple <= MAX_FEE_OVERPAY_MULTIPLE + 0.05, multiple
            assert caplog.text == "", f"warned at {multiple:.2f}x: {caplog.text}"

    def test_the_warning_fires_above_the_ceiling_over_fresh_keys(self, caplog) -> None:
        """The differential: same builder, fee over the ceiling, opposite verdict."""
        fired = 0
        for _ in range(self.ROUNDS):
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.htlc_spend"):
                _tx, _floor, multiple = self._fresh_claim(int(2_700_000 * (11 + _rand_below(20))))
            assert multiple > MAX_FEE_OVERPAY_MULTIPLE
            assert "photons — " in caplog.text, f"no warning at {multiple:.1f}x"
            fired += 1
        assert fired == self.ROUNDS

    def test_the_builder_never_refuses_for_being_over_the_ceiling(self) -> None:
        """A hard refusal here would be fail-closed on a deadline-racing claim.

        ``test_measured_covenant_spend_sizes`` above already routes ~19x headroom
        through this path, which is why the cold CLI's 10x REFUSAL cannot simply be
        lifted into the builder.
        """
        for value in (26_600_000, 50_000_000, 500_000_000, 50_000_000_000):
            tx, _floor, _mult = self._fresh_claim(value)
            assert tx.get_fee() == value

    def test_the_ceiling_is_the_one_the_cold_cli_refuses_on(self) -> None:
        """One definition, two responses — not two numbers that can drift apart."""
        from pyrxd.cli import swap_recovery
        from pyrxd.fee_sizing import fee_overpay_ceiling as canonical

        assert swap_recovery.MAX_FEE_OVERPAY_MULTIPLE is MAX_FEE_OVERPAY_MULTIPLE
        assert swap_recovery.fee_overpay_ceiling is canonical
        assert canonical(floor=2_660_000, target=2_660_000) == 26_600_000
        # The ceiling tracks the deadline-aware TARGET when that is higher, so urgency
        # raises the bar instead of making an urgent fee look like a mistake.
        assert canonical(floor=2_660_000, target=8_000_000) == 80_000_000
