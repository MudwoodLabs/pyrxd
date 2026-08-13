"""Targeted assertions that kill surviving mutants in the BUILDER scope.

Companion to :mod:`tests.test_mutation_hardening`, split out because the
builder scope's fixtures (keys, FT UTXO sets, HD wallets) are heavier than
that file's stdlib-only style and because ``scripts/mutation_test.sh``'s
``builders`` group is the only scope that needs them.

Scope: ``fee_sizing.py``, ``glyph/ft.py``, ``glyph/royalty.py``,
``glyph/builder.py``, ``wallet.py``, ``hd/wallet.py`` — the modules that had
never been mutation-tested before 2026-08, which is where that week's fee
defects lived.

Every test here names the mutant it kills and was PROVED by planting that
mutant and watching the test go red; a test that stays green under its own
mutant would be worse than no test, because it reports coverage that does
not exist. Expected values are derived in-test from the documented rule
(BIP141's weight formula, ``ceil``, the relay floor), never read back out of
the code under test.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.constants import DUST_THRESHOLD_PHOTONS
from pyrxd.fee_sizing import (
    MAX_FEE_OVERPAY_MULTIPLE,
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    SIG_SIZE_SLACK_BYTES,
    WITNESS_SCALE_FACTOR,
    assert_fee_rate_clears_relay_floor,
    bitcoin_virtual_size,
    fee_never_below_relay_floor,
    fee_overpay_ceiling,
    fee_overpay_multiple,
    min_relay_fee,
    radiant_relay_size,
    relay_floor_photons_per_byte,
)
from pyrxd.glyph.builder import GlyphBuilder, TransferParams
from pyrxd.glyph.ft import AirdropFunding, AirdropRecipient, FtUtxo, FtUtxoSet
from pyrxd.glyph.royalty import royalty_due, royalty_payouts
from pyrxd.glyph.script import (
    build_ft_locking_script,
    build_nft_locking_script,
    is_legacy_container_script,
)
from pyrxd.glyph.types import GlyphRef, GlyphRoyalty
from pyrxd.hd.bip39 import mnemonic_from_entropy
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from pyrxd.wallet import SELECTION_BASE_BYTES, SELECTION_INPUT_BYTES, RxdWallet, greedy_select_count

_FLOOR = relay_floor_photons_per_byte()


def _ref() -> GlyphRef:
    return GlyphRef(txid=os.urandom(32).hex(), vout=0)


def _pkh(key: PrivateKey | None = None) -> Hex20:
    return Hex20((key or PrivateKey()).public_key().hash160())


# =========================================================================
# fee_sizing.py
# =========================================================================


class TestBitcoinVirtualSizeIsBip141:
    """``bitcoin_virtual_size`` mutants — the witness discount constant."""

    def test_witness_scale_factor_is_four(self) -> None:
        """Kills ``WITNESS_SCALE_FACTOR = 4`` → any other integer.

        The constant is BIP141's, not a tuning knob: ``weight = stripped*3 +
        total`` and ``vsize = ceil(weight/4)``. Both existing unit cases are
        algebraically INVARIANT to it — ``(250, 250)`` returns ``total`` for
        every scale factor and ``(100, 101)`` returns 101 for every factor in
        2..5 — so before this test a mutant raising it to 5 (which UNDER-states
        a BTC transaction's size, and therefore its fee) survived the whole
        offline suite. The only catch was BTC-regtest-gated.
        """
        assert WITNESS_SCALE_FACTOR == 4

    @pytest.mark.parametrize(
        ("stripped", "total"),
        [(100, 400), (141, 222), (200, 1000), (61, 61), (1, 2)],
    )
    def test_vsize_matches_the_bip141_formula_re_derived_here(self, stripped: int, total: int) -> None:
        """The same kill, behaviourally: a witness-heavy shape where the scale
        factor actually moves the answer. ``(100, 400)`` is 175 at 4, 200 at 3
        and 160 at 5 — so no factor other than 4 can pass this."""
        weight = stripped * 3 + total  # BIP141 GetTransactionWeight
        expected = -(-weight // 4)  # ceil(weight / 4)
        assert bitcoin_virtual_size(stripped_size=stripped, total_size=total) == expected

    def test_vsize_rejects_a_bool_dressed_as_a_size(self) -> None:
        """Kills the ``isinstance(value, bool)`` term. ``True`` is an ``int``
        subclass worth 1, so without this it would size a 1-byte transaction."""
        for kwargs in ({"stripped_size": True, "total_size": 200}, {"stripped_size": 200, "total_size": True}):
            with pytest.raises(ValidationError):
                bitcoin_virtual_size(**kwargs)  # type: ignore[arg-type]


class TestRadiantRelaySizeFailsClosed:
    def test_refuses_a_hex_string(self) -> None:
        """Kills the ``isinstance(raw_tx, (bytes, bytearray))`` guard.

        Without it a hex STRING would sail through ``len()`` and report twice
        the real byte count. Twice is the safe direction for a fee, which is
        exactly why nothing else catches it — but a size that is silently
        wrong by 2x is not a size, and the same slip in the other direction
        (a ``memoryview``, a list of ints) is not bounded at all.
        """
        raw = bytes.fromhex("0200000001")
        assert radiant_relay_size(raw) == 5
        with pytest.raises(ValidationError, match="must be bytes"):
            radiant_relay_size(raw.hex())  # type: ignore[arg-type]

    def test_accepts_bytearray(self) -> None:
        """The inverse bug: the guard must not refuse a legitimate mutable
        buffer, which is what a serializer hands back."""
        assert radiant_relay_size(bytearray(b"\x00" * 12)) == 12


class TestFeeNeverBelowRelayFloor:
    """``fee_never_below_relay_floor`` mutants — the no-opt-out ``max``."""

    def test_the_rate_arm_binds_when_it_exceeds_the_floor(self) -> None:
        """Kills ``max(size*rate, floor)`` → ``floor``.

        Every pre-existing test of this function ran at or below the floor,
        where both arms give the same number, so a mutant that dropped the
        rate term entirely survived. The consequence is the opposite of what
        the function is for: a caller who deliberately pays ABOVE the floor
        (the only reason to call the strict variant on a trusted-but-urgent
        path) would silently get the floor instead.
        """
        size, rate = 226, _FLOOR * 3
        assert fee_never_below_relay_floor(size, rate) == size * rate
        assert fee_never_below_relay_floor(size, rate) > min_relay_fee(size)

    def test_the_floor_arm_binds_when_the_rate_is_below_it(self) -> None:
        assert fee_never_below_relay_floor(226, 1) == min_relay_fee(226)

    @pytest.mark.parametrize("bad", [0, -1, True, 1.0, None, "10000"])
    def test_rejects_a_rate_that_is_not_a_positive_int(self, bad: object) -> None:
        """Kills the dropped ``_check_rate(fee_rate)`` call. This is the
        function documented for rates that cross a TRUST BOUNDARY — a config
        file, an RPC reading — so it is the one place a ``None`` or a float
        must not reach the arithmetic."""
        with pytest.raises((ValueError, TypeError)):
            fee_never_below_relay_floor(226, bad)  # type: ignore[arg-type]


class TestFeeOverpayBound:
    def test_ceiling_takes_the_LARGER_of_floor_and_target(self) -> None:
        """Pins ``max(floor, target)`` against ``min(floor, target)``.

        Taking the min is the inverse bug in its purest form: a
        deadline-critical spend whose target legitimately sits far above the
        node's floor would be refused as an "overpay" by the cold-recovery
        CLI, which is the one caller that REFUSES rather than warns.

        NOT a survivor — ``tests/test_htlc_spend_fee_floor.py`` already kills
        this mutant (2 failures against the full offline suite). Kept as a
        direct unit pin next to the other ``fee_sizing`` bounds, because the
        existing cover reaches it through an HTLC builder several layers away.
        """
        assert fee_overpay_ceiling(floor=1_000, target=8_000_000) == 8_000_000 * MAX_FEE_OVERPAY_MULTIPLE
        assert fee_overpay_ceiling(floor=8_000_000, target=1_000) == 8_000_000 * MAX_FEE_OVERPAY_MULTIPLE

    def test_multiple_survives_a_zero_requirement(self) -> None:
        """Kills the ``, 1)`` clamp in ``max(int(floor), int(target), 1)``.

        Without it a caller with no floor and no target — which is what an
        un-primed policy object hands over — gets ZeroDivisionError out of a
        function whose whole job is to REPORT on a fee, in the middle of the
        error path that was already going wrong.
        """
        assert fee_overpay_multiple(5, floor=0, target=0) == 5.0
        assert fee_overpay_multiple(0, floor=0, target=0) == 0.0


# =========================================================================
# wallet.py — the shared selection algorithm
# =========================================================================


class TestGreedySelectCountContract:
    """``greedy_select_count`` mutants — the documented cushion arithmetic.

    Both in-repo callers re-measure the real signed size afterwards and take
    one more UTXO when the estimate was short, so a mutant here is invisible
    THROUGH THEM. The function is module-level public API with its own
    documented contract, and that contract is what these pin.
    """

    def test_the_per_input_cushion_is_counted_for_every_selected_input(self) -> None:
        """Kills ``total >= photons + base + per_input*i`` → ``total >= photons``.

        900 + 50 + 100 = 1050 is not covered by the first 1000-photon coin, so
        a correct selection takes two. Ignoring the cushion returns one.
        """
        assert greedy_select_count([1000, 500, 100], 900, base_cushion=50, per_input_cushion=100) == 2
        assert greedy_select_count([1000, 500, 100], 900, base_cushion=50, per_input_cushion=25) == 1

    def test_the_base_cushion_is_counted_once(self) -> None:
        """Kills the dropped ``base_cushion`` term: 900 + 200 > 1000."""
        assert greedy_select_count([1000, 500], 900, base_cushion=200, per_input_cushion=0) == 2
        assert greedy_select_count([1000, 500], 900, base_cushion=0, per_input_cushion=0) == 1

    def test_refuses_only_when_the_coins_cannot_cover_the_amount_itself(self) -> None:
        """Both directions at once. Under-covering the AMOUNT must raise; but
        covering the amount while falling short of the CUSHION must NOT — it
        must return every coin and let the caller's re-measurement decide.
        Raising there would refuse to spend spendable coins, which is this
        repo's documented inverse-bug class."""
        with pytest.raises(ValidationError, match="Insufficient funds"):
            greedy_select_count([100, 50], 1000, base_cushion=0, per_input_cushion=0)
        assert greedy_select_count([600, 500], 1000, base_cushion=10**9, per_input_cushion=10**9) == 2

    def test_the_selection_cushion_budgets_at_least_what_the_fee_charges(self) -> None:
        """Kills ``SELECTION_INPUT_BYTES = 148 + SIG_SIZE_SLACK_BYTES`` → ``148``.

        The fee is sized from ``trial_size_with_slack`` — the measured trial
        bytes PLUS ``SIG_SIZE_SLACK_BYTES`` per input. A per-input cushion
        that budgets fewer bytes than that stops the greedy pass ``3n - 2``
        bytes short of the fee it is about to be charged. The re-selection
        loop in the builders absorbs it today, which is exactly why no
        behavioural test can see this constant move; the INEQUALITY is the
        property that has to hold whether or not that loop survives a
        refactor.
        """
        signed_p2pkh_input_bytes = 32 + 4 + 1 + 107 + 4  # txid, vout, scriptLen, scriptSig, sequence
        assert signed_p2pkh_input_bytes + SIG_SIZE_SLACK_BYTES <= SELECTION_INPUT_BYTES
        # version(4) + in/out varints(2) + two P2PKH outputs(2x34) + locktime(4) = 78
        assert SELECTION_BASE_BYTES >= 4 + 2 + 2 * 34 + 4


# =========================================================================
# glyph/ft.py — the airdrop's fail-closed fee backstop
# =========================================================================


class TestFtAirdropFeeBackstopIsReachable:
    """``build_airdrop_tx``'s final ``assert_pays_for_its_size`` mutants.

    The slack in front of it is pinned elsewhere; what was NOT pinned is the
    guard itself. Defeating the comparison (``fee_paid=actual_fee`` →
    ``actual_fee + 10**15``) left the whole offline suite green, so the one
    thing standing between a short fee and a broadcast that Radiant can
    neither replace nor bump was unverified.
    """

    @staticmethod
    def _set() -> tuple[FtUtxoSet, PrivateKey, GlyphRef]:
        key = PrivateKey()
        ref = _ref()
        spk = build_ft_locking_script(_pkh(key), ref)
        utxo = FtUtxo.from_output(txid=os.urandom(32).hex(), vout=0, value=50_000_000, ft_script=spk)
        return FtUtxoSet(ref, [utxo]), key, ref

    def test_a_fee_forced_below_the_rate_raises_instead_of_returning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Force the sizing pass to under-measure and the build MUST refuse."""
        monkeypatch.setattr("pyrxd.glyph.ft.trial_size_with_slack", lambda size, n: max(1, size // 4))
        ft_set, key, _ = self._set()
        funding = [AirdropFunding(txid=os.urandom(32).hex(), vout=0, value=500_000_000, private_key=PrivateKey())]
        with pytest.raises(ValueError, match="fee-sizing invariant violated"):
            ft_set.build_airdrop_tx(
                recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
                private_key=key,
                funding=funding,
                fee_rate=_FLOOR,
            )

    def test_the_same_build_succeeds_with_the_real_sizing(self) -> None:
        """The inverse half: the guard must not be refusing ordinary work."""
        ft_set, key, _ = self._set()
        funding = [AirdropFunding(txid=os.urandom(32).hex(), vout=0, value=500_000_000, private_key=PrivateKey())]
        result = ft_set.build_airdrop_tx(
            recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
            private_key=key,
            funding=funding,
            fee_rate=_FLOOR,
        )
        assert result.tx.outputs[0].satoshis == 250
        assert result.fee >= result.tx.byte_length() * _FLOOR


# =========================================================================
# hd/wallet.py — the sweep builder's backstop
# =========================================================================


class TestHdSweepFeeBackstopIsReachable:
    """``HdWallet.build_send_max_tx``'s final ``assert_tx_pays_for_itself``.

    ``RxdWallet``'s twin is covered (its differential is parametrized over
    ``send`` and ``send_max``); the HD differential only ever called
    ``build_send_tx``, so deleting the sweep's assertion left the suite green.
    A sweep is the shape with NO change output — the payout is the only place
    a shortfall can come from — so this is the builder where the backstop
    matters most.
    """

    @staticmethod
    def _wallet_and_triples(n: int = 3) -> tuple[HdWallet, list]:
        wallet = HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(16)))
        triples = [
            (
                UtxoRecord(tx_hash=f"{i:064x}", tx_pos=0, value=200_000_000, height=1),
                wallet._derive_address(0, i),
                wallet._privkey_for(0, i),
            )
            for i in range(n)
        ]
        return wallet, triples

    def test_a_fee_forced_below_the_rate_raises_instead_of_returning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("pyrxd.hd.wallet.required_fee", lambda size, rate: max(1, size * rate // 4))
        wallet, triples = self._wallet_and_triples()
        with pytest.raises(ValidationError, match="fee-sizing invariant violated"):
            wallet.build_send_max_tx(triples, PrivateKey().public_key().address(), fee_rate=_FLOOR)

    def test_the_sweep_still_builds_with_the_real_sizing(self) -> None:
        wallet, triples = self._wallet_and_triples()
        tx = wallet.build_send_max_tx(triples, PrivateKey().public_key().address(), fee_rate=_FLOOR)
        paid = sum(t[0].value for t in triples) - sum(o.satoshis for o in tx.outputs)
        assert paid >= tx.byte_length() * _FLOOR


# =========================================================================
# glyph/builder.py — the NFT transfer's two refusals
# =========================================================================


class TestNftTransferRefusals:
    @staticmethod
    def _params(value: int, *, script: bytes | None = None, rate: int = _FLOOR) -> TransferParams:
        key = PrivateKey()
        ref = _ref()
        return TransferParams(
            nft_utxo_txid=os.urandom(32).hex(),
            nft_utxo_vout=0,
            nft_utxo_value=value,
            nft_script=script if script is not None else build_nft_locking_script(_pkh(key), ref),
            new_owner_pkh=_pkh(),
            private_key=key,
            fee_rate=rate,
        )

    def test_a_carrier_too_small_for_its_own_fee_is_refused_not_signed(self) -> None:
        """Kills ``if output_value < DUST_THRESHOLD_PHOTONS`` → ``< 0``.

        At the relay floor an NFT transfer costs roughly 2.3 million photons,
        so a 1,000,000-photon carrier leaves a NEGATIVE output value. Nothing
        downstream catches that: ``assert_pays_for_its_size`` is handed
        ``nft_utxo_value - output_value``, which is the fee by construction
        and stays correct however absurd the output becomes. Without this
        guard the builder returns a signed transaction carrying a negative
        satoshi value.
        """
        with pytest.raises(ValueError, match="too small to cover transfer"):
            GlyphBuilder().build_nft_transfer_tx(self._params(1_000_000))

    def test_a_funded_carrier_still_transfers_and_never_lands_below_the_floor(self) -> None:
        """The inverse half, and the property in general form: whatever the
        carrier, a returned transfer's output is at or above the policy floor
        — a build that cannot honour that must raise, never return."""
        builder = GlyphBuilder()
        refused = 0
        for value in (500_000, 1_500_000, 2_320_000, 2_320_546, 5_000_000, 100_000_000):
            try:
                result = builder.build_nft_transfer_tx(self._params(value))
            except ValueError:
                refused += 1
                continue
            assert result.tx.outputs[0].satoshis >= DUST_THRESHOLD_PHOTONS
            assert value - result.tx.outputs[0].satoshis == result.fee
        assert refused > 0, "no carrier in the sweep was too small — the guard is not being exercised"

    def test_a_legacy_container_output_is_named_as_unspendable(self) -> None:
        """Pins the ``is_legacy_container_script`` guard.

        NOT a survivor — ``tests/test_mut_container_wave_builders.py:350``
        already kills this mutant. Kept because it builds the 100-byte dead
        shape from the documented byte layout
        (``d0 <child_ref> d8 <container_ref> 75 76 a9 14 <pkh> 88 ac``) rather
        than from that module's shared fixture, so the two cannot go wrong
        together. A pre-0.15.0 CONTAINER-with-child-ref output is permanently
        unspendable; the holder needs to be told that rather than handed a
        transfer every node rejects with an OP_EQUALVERIFY failure.
        """
        dead = (
            b"\xd0"
            + _ref().to_bytes()
            + b"\xd8"
            + _ref().to_bytes()
            + b"\x75\x76\xa9\x14"
            + bytes(_pkh())
            + b"\x88\xac"
        )
        assert len(dead) == 100
        assert is_legacy_container_script(dead.hex()), "fixture no longer matches the legacy shape"
        with pytest.raises(ValidationError, match="permanently unspendable"):
            GlyphBuilder().build_nft_transfer_tx(self._params(100_000_000, script=dead))


# =========================================================================
# The relay-floor constant, pinned where the builders read it
# =========================================================================


# =========================================================================
# The checks that were MISSING, not merely unverified
# =========================================================================


class TestTheRateGateBindsFromBothEnds:
    """``assert_fee_rate_clears_relay_floor``'s upper bound.

    The gate used to judge only "too low". A fee is ``size x fee_rate``, so a
    rate ``k`` times the floor pays ``k`` times the requirement, and every
    builder that routes through this gate spends the difference irreversibly —
    an NFT transfer and a sweep have no change output at all. Measured before
    the bound existed: ``build_nft_transfer_tx`` at ``fee_rate=10_000_000``,
    which is this module's own per-**kB** constant used as a per-**byte** rate,
    burned 2,320,000,000 photons (23.2 RXD) off a 229-byte transfer and
    reported success.
    """

    _CEILING = _FLOOR * MAX_FEE_OVERPAY_MULTIPLE

    @pytest.mark.parametrize("rate", [_FLOOR, _FLOOR + 1, 90_000, _CEILING])
    def test_a_rate_at_or_under_the_ceiling_is_returned_unchanged(self, rate: int) -> None:
        """The inverse-bug half, and it is the half that matters most: a bound
        that refuses legitimate work is its own defect. 90_000 is the highest
        deliberate rate anywhere in this repository, and the ceiling itself must
        pass — the comparison is ``>``, not ``>=``."""
        assert assert_fee_rate_clears_relay_floor(rate, what="t") == rate

    @pytest.mark.parametrize("rate", [_CEILING + 1, _FLOOR * 100, RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB])
    def test_a_rate_above_the_ceiling_is_refused(self, rate: int) -> None:
        with pytest.raises(ValueError, match="ceiling"):
            assert_fee_rate_clears_relay_floor(rate, what="t")

    def test_the_message_names_the_per_kb_confusion_that_produces_it(self) -> None:
        """The 1000x case is a units error, not a preference, so the error has to
        say which two numbers were swapped rather than only that one is large."""
        with pytest.raises(ValueError) as exc:
            assert_fee_rate_clears_relay_floor(RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB, what="t")
        text = str(exc.value)
        assert "1000x" in text
        assert "per BYTE" in text and "per kB" in text
        assert "allow_overpay=True" in text

    def test_allow_overpay_is_the_escape_hatch_and_skips_only_its_own_bound(self) -> None:
        huge = RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
        assert assert_fee_rate_clears_relay_floor(huge, what="t", allow_overpay=True) == huge
        # ...and it does not smuggle a sub-floor rate through the other bound.
        with pytest.raises(ValueError, match="relay floor"):
            assert_fee_rate_clears_relay_floor(1, what="t", allow_overpay=True)
        # ...nor does the low-end hatch disable the high one.
        with pytest.raises(ValueError, match="ceiling"):
            assert_fee_rate_clears_relay_floor(huge, what="t", allow_below_relay_floor=True)

    def test_the_builders_inherit_the_bound(self) -> None:
        """One gate, so no builder can be the one that forgot. Each of these
        reaches ``assert_fee_rate_clears_relay_floor`` by a different route."""
        key = PrivateKey()
        ref = _ref()
        absurd = RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

        with pytest.raises(ValueError, match="ceiling"):
            GlyphBuilder().build_nft_transfer_tx(
                TransferParams(
                    nft_utxo_txid=os.urandom(32).hex(),
                    nft_utxo_vout=0,
                    nft_utxo_value=5_000_000_000,
                    nft_script=build_nft_locking_script(_pkh(key), ref),
                    new_owner_pkh=_pkh(),
                    private_key=key,
                    fee_rate=absurd,
                )
            )

        ft_set = FtUtxoSet(
            ref,
            [
                FtUtxo.from_output(
                    txid=os.urandom(32).hex(),
                    vout=0,
                    value=50_000_000,
                    ft_script=build_ft_locking_script(_pkh(key), ref),
                )
            ],
        )
        with pytest.raises(ValueError, match="ceiling"):
            ft_set.build_airdrop_tx(
                recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
                private_key=key,
                funding=[AirdropFunding(txid=os.urandom(32).hex(), vout=0, value=10**12, private_key=PrivateKey())],
                fee_rate=absurd,
            )

        wallet = HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(16)))
        triples = [
            (
                UtxoRecord(tx_hash=f"{i:064x}", tx_pos=0, value=10**12, height=1),
                wallet._derive_address(0, i),
                wallet._privkey_for(0, i),
            )
            for i in range(2)
        ]
        with pytest.raises(ValidationError, match="ceiling"):
            wallet.build_send_max_tx(triples, PrivateKey().public_key().address(), fee_rate=absurd)
        with pytest.raises(ValidationError, match="ceiling"):
            wallet.build_send_tx(triples, PrivateKey().public_key().address(), 10**9, fee_rate=absurd)

        with pytest.raises(ValidationError, match="ceiling"):
            RxdWallet(PrivateKey(), "wss://example.invalid", fee_rate=absurd)


class TestNoBuilderSignsAnOutpointTwice:
    """An outpoint is unique on chain, so a repeat is always a caller mistake.

    Before these checks: an ``FtUtxoSet`` holding one UTXO twice reported DOUBLE
    the real balance from ``total()`` and ``select()`` handed the same outpoint
    back twice; ``build_airdrop_tx`` with one funding UTXO passed twice signed a
    transaction carrying a duplicate input — rejected by every node as
    ``bad-txns-inputs-duplicate`` — and reported a fee 4x the real one, because
    ``funding_total`` and the final fee assertion are handed the same
    double-counted number.
    """

    @staticmethod
    def _fixture():
        key = PrivateKey()
        ref = _ref()
        spk = build_ft_locking_script(_pkh(key), ref)
        txid = os.urandom(32).hex()
        return key, ref, spk, txid

    def test_the_utxo_set_refuses_a_repeated_outpoint(self) -> None:
        _key, ref, spk, txid = self._fixture()
        u = FtUtxo.from_output(txid=txid, vout=0, value=1_000_000, ft_script=spk)
        with pytest.raises(ValidationError, match="appears more than once"):
            FtUtxoSet(ref, [u, u])

    def test_the_utxo_set_still_accepts_two_vouts_of_one_transaction(self) -> None:
        """The inverse bug: one transaction paying a holder at several output
        indexes is ordinary, so the check must key on ``(txid, vout)``."""
        _key, ref, spk, txid = self._fixture()
        a = FtUtxo.from_output(txid=txid, vout=0, value=1_000_000, ft_script=spk)
        b = FtUtxo.from_output(txid=txid, vout=1, value=2_000_000, ft_script=spk)
        assert FtUtxoSet(ref, [a, b]).total() == 3_000_000

    def test_the_airdrop_refuses_a_repeated_funding_outpoint(self) -> None:
        key, ref, spk, txid = self._fixture()
        ft_set = FtUtxoSet(ref, [FtUtxo.from_output(txid=txid, vout=0, value=1_000_000, ft_script=spk)])
        f = AirdropFunding(txid=os.urandom(32).hex(), vout=0, value=500_000_000, private_key=PrivateKey())
        with pytest.raises(ValidationError, match="repeats outpoint"):
            ft_set.build_airdrop_tx(
                recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
                private_key=key,
                funding=[f, f],
                fee_rate=_FLOOR,
            )

    def test_the_airdrop_refuses_an_outpoint_that_is_both_token_and_funding(self) -> None:
        """The seam neither list can see on its own: the two input lists are
        built independently and concatenated."""
        key, ref, spk, txid = self._fixture()
        ft_set = FtUtxoSet(ref, [FtUtxo.from_output(txid=txid, vout=0, value=1_000_000, ft_script=spk)])
        with pytest.raises(ValidationError, match="both as an FT UTXO and as plain-RXD funding"):
            ft_set.build_airdrop_tx(
                recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
                private_key=key,
                funding=[AirdropFunding(txid=txid, vout=0, value=500_000_000, private_key=PrivateKey())],
                fee_rate=_FLOOR,
            )

    def test_two_distinct_funding_outpoints_still_build(self) -> None:
        """The inverse half again — including two vouts of one funding tx."""
        key, ref, spk, txid = self._fixture()
        ft_set = FtUtxoSet(ref, [FtUtxo.from_output(txid=txid, vout=0, value=1_000_000, ft_script=spk)])
        ftxid = os.urandom(32).hex()
        result = ft_set.build_airdrop_tx(
            recipients=[AirdropRecipient(pkh=_pkh(), amount=250)],
            private_key=key,
            funding=[
                AirdropFunding(txid=ftxid, vout=0, value=500_000_000, private_key=PrivateKey()),
                AirdropFunding(txid=ftxid, vout=1, value=500_000_000, private_key=PrivateKey()),
            ],
            fee_rate=_FLOOR,
        )
        outpoints = [(i.source_txid, i.source_output_index) for i in result.tx.inputs]
        assert len(outpoints) == len(set(outpoints)) == 3
        assert result.tx.outputs[0].satoshis == 250


class TestAirdropFundingValidatesItsValue:
    """``AirdropFunding.value`` is summed into the RXD budget the fee comes out
    of. Unvalidated, a wrong one surfaced only much later and unhelpfully — as
    ``'float' object has no attribute 'to_bytes'`` from the middle of output
    serialisation, ``OverflowError`` for a negative, and for ``True`` a nonsense
    "budget 1 photons" in the insufficient-funding message."""

    @pytest.mark.parametrize("bad", [True, 1_000_000.5, "500000", None])
    def test_rejects_a_value_that_is_not_an_int(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="must be int"):
            AirdropFunding(txid="bb" * 32, vout=0, value=bad, private_key=PrivateKey())  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", [0, -1, -5_000_000])
    def test_rejects_a_non_positive_value(self, bad: int) -> None:
        with pytest.raises(ValidationError, match="must be > 0"):
            AirdropFunding(txid="bb" * 32, vout=0, value=bad, private_key=PrivateKey())

    def test_accepts_one_photon(self) -> None:
        """Radiant's real output floor is 1 photon; the guard must not invent 546."""
        assert AirdropFunding(txid="bb" * 32, vout=0, value=1, private_key=PrivateKey()).value == 1


class TestRoyaltySplitsGuardsThatNothingReached:
    """``royalty_payouts`` branches no offline test executed.

    The royalty *arithmetic* is well covered — the ``sale_price`` cap, the
    ``minimum`` floor, the flooring direction, the residue and the
    ``sum(payouts) == royalty_due`` identity all die under mutation. These two
    guards are the exceptions, and the first is not a dead branch: it is the
    only thing standing between a legal royalty and a crash.
    """

    @staticmethod
    def _addr() -> str:
        return PrivateKey().public_key().address()

    def test_a_zero_bps_royalty_with_splits_pays_rather_than_crashing(self) -> None:
        """Kills the ``and royalty.bps > 0`` half of the splits branch.

        ``GlyphRoyalty`` requires ``sum(split.bps) <= bps``, so ``bps=0`` forces
        every split to 0 — but that shape is *constructible and legal*, and with
        a ``minimum`` set it resolves to a real payment. Measured against the
        live module: ``GlyphRoyalty(bps=0, minimum=1000, splits=((addr, 0),))``
        at ``sale_price=5000`` yields ``royalty_due == 1000`` and one payout.
        Delete the ``bps > 0`` half and the very next line divides by
        ``royalty.bps`` — ``ZeroDivisionError`` on a token whose terms are
        perfectly valid. Nothing offline executed this branch.
        """
        creator, split = self._addr(), self._addr()
        r = GlyphRoyalty(address=creator, bps=0, minimum=1_000, splits=((split, 0),))
        assert royalty_due(r, 5_000) == 1_000
        payouts = royalty_payouts(r, 5_000)
        assert [p.photons for p in payouts] == [1_000]
        assert [p.address for p in payouts] == [creator], "a 0-bps split is entitled to nothing"

    def test_a_positive_bps_royalty_still_divides_by_bps(self) -> None:
        """The other half of the same branch, so the fix cannot be "always take
        the non-splits path"."""
        creator, split = self._addr(), self._addr()
        r = GlyphRoyalty(address=creator, bps=1_000, minimum=0, splits=((split, 500),))
        payouts = royalty_payouts(r, 100_000)
        assert sum(p.photons for p in payouts) == royalty_due(r, 100_000) == 10_000
        assert dict((p.address, p.photons) for p in payouts) == {split: 5_000, creator: 5_000}

    def test_a_recipient_address_that_decodes_to_the_wrong_length_is_refused(self) -> None:
        """Kills the ``len(pkh) != 20`` guard.

        ``address_to_public_key_hash`` validates the base58check *shape*, not
        the payload length, so this is reachable rather than defensive — and a
        payout built on a short hash produces a locking script that is not
        P2PKH and cannot be spent by the recipient. No offline test reached it.
        """
        import pyrxd.utils

        r = GlyphRoyalty(address=self._addr(), bps=1_000, minimum=0)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(pyrxd.utils, "address_to_public_key_hash", lambda _a: b"\x11" * 19)
            with pytest.raises(ValidationError, match="decoded to 19 bytes, expected 20"):
                royalty_payouts(r, 100_000)


class TestFtUtxoSetTypeGuards:
    """``FtUtxoSet.__init__``'s three constructor type checks.

    All three could be deleted with the whole offline suite green — every test
    builds the set correctly, so nothing ever exercised the refusals. They are
    not cosmetic: a duck-typed stand-in that reaches ``total()`` and
    ``select()`` reports a balance and picks inputs, and the FT fund-loss
    history in this module is precisely about a wrong number arriving from a
    caller and being believed.
    """

    @staticmethod
    def _utxo(ref: GlyphRef, key: PrivateKey) -> FtUtxo:
        return FtUtxo.from_output(
            txid=os.urandom(32).hex(),
            vout=0,
            value=1_000_000,
            ft_script=build_ft_locking_script(_pkh(key), ref),
        )

    def test_refuses_a_ref_that_is_not_a_GlyphRef(self) -> None:
        with pytest.raises(ValidationError, match="ref must be a GlyphRef"):
            FtUtxoSet("ab" * 32, [])  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", [(), None, "utxos"])
    def test_refuses_a_utxos_argument_that_is_not_a_list(self, bad: object) -> None:
        """A tuple is the tempting one: it is the natural thing to pass and
        would otherwise iterate fine, so the guard has to name the type."""
        with pytest.raises(ValidationError, match="utxos must be a list"):
            FtUtxoSet(_ref(), bad)  # type: ignore[arg-type]

    def test_refuses_an_element_that_is_not_an_FtUtxo(self) -> None:
        key, ref = PrivateKey(), _ref()

        class LooksLikeOne:
            txid = "aa" * 32
            vout = 0
            value = 10**9
            ft_amount = 10**9
            ft_script = b""

        with pytest.raises(ValidationError, match="must contain FtUtxo instances"):
            FtUtxoSet(ref, [self._utxo(ref, key), LooksLikeOne()])  # type: ignore[list-item]

    def test_a_correctly_built_set_is_still_accepted(self) -> None:
        key, ref = PrivateKey(), _ref()
        assert FtUtxoSet(ref, [self._utxo(ref, key)]).total() == 1_000_000
        assert FtUtxoSet(ref, []).total() == 0, "an empty holding is a legal set, not an error"


class TestFtTransferAmountTypeGuard:
    def test_build_transfer_tx_rejects_a_bool_amount_as_ValueError(self) -> None:
        """Kills ``build_transfer_tx``'s own ``amount`` int/bool check.

        Deleting it is not silent-but-harmless: a ``bool`` amount is still
        refused one layer down by ``build_airdrop_tx``, but as
        ``ValidationError`` — while this method's docstring documents
        ``ValueError`` for a bad ``amount``. A caller catching what the API
        promises would stop catching it.
        """
        key, ref = PrivateKey(), _ref()
        ft_set = FtUtxoSet(
            ref,
            [
                FtUtxo.from_output(
                    txid=os.urandom(32).hex(),
                    vout=0,
                    value=1_000_000,
                    ft_script=build_ft_locking_script(_pkh(key), ref),
                )
            ],
        )
        for bad in (True, 250.0, "250"):
            with pytest.raises(ValueError, match="amount must be an int"):
                ft_set.build_transfer_tx(bad, _pkh(), key)  # type: ignore[arg-type]


def test_max_airdrop_recipients_is_the_documented_thousand() -> None:
    """Pins the VALUE of ``MAX_AIRDROP_RECIPIENTS``.

    Measured: changing it to 3 leaves the entire offline suite green, because
    the only test that exercises the cap derives its own list length from the
    symbol (``range(MAX_AIRDROP_RECIPIENTS + 1)``). The number is a deliberate
    cost decision documented in ``glyph/ft.py`` — one FT output is 84
    serialised bytes, so 1000 recipients is ~8.4 RXD of fee at the relay floor —
    and a cap that can drift to 3 refuses ordinary work, while one that can
    drift to 10**6 stops being the "deliberate decision" check it claims to be.
    """
    from pyrxd.glyph.ft import MAX_AIRDROP_RECIPIENTS

    assert MAX_AIRDROP_RECIPIENTS == 1000


def test_ft_change_can_never_be_negative_through_the_public_builder() -> None:
    """The honest form of ``build_airdrop_tx``'s ``ft_change < 0`` guard.

    That raise is **unreachable** through the public API: ``select()`` refuses
    when ``total() < amount`` and otherwise stops only once ``running >=
    amount``, so ``ft_in_total - total_out`` is non-negative by construction.
    ``tests/test_glyph_ft_red_team.py:859`` names the guard but dies in
    ``select()`` before reaching it — a tautological test, which is worse than
    none because it reports coverage that does not exist.

    So this pins the PROPERTY that makes the guard unreachable rather than
    pretending to reach it. If a future change to ``select()`` breaks the
    property, this fails here — and the guard behind it is the backstop.
    """
    key, ref = PrivateKey(), _ref()
    spk = build_ft_locking_script(_pkh(key), ref)
    utxos = [
        FtUtxo.from_output(txid=os.urandom(32).hex(), vout=i, value=v, ft_script=spk)
        for i, v in enumerate((1, 7, 250, 1_000, 50_000_000))
    ]
    ft_set = FtUtxoSet(ref, utxos)
    total = ft_set.total()
    for amount in (1, 2, 8, 249, 251, 1_257, 1_258, total - 1, total):
        selected = ft_set.select(amount)
        assert sum(u.ft_amount for u in selected) - amount >= 0, f"select() under-covered {amount}"
    with pytest.raises(ValueError, match="Insufficient FT balance"):
        ft_set.select(total + 1)


def test_the_per_byte_floor_is_the_per_kb_floor_divided_by_a_thousand() -> None:
    """A cheap cross-check that survives a change to either constant: 10_000_000
    photons/kB is 10_000/byte, and ``min_relay_fee`` must agree with both."""
    assert relay_floor_photons_per_byte() * 1000 == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
    assert min_relay_fee(1000) == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
    assert min_relay_fee(1) == relay_floor_photons_per_byte()
