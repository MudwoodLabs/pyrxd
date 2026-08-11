"""Every wallet send must pay for the bytes it actually contains.

Why this is a corpus and not an example
---------------------------------------
``RxdWallet`` sizes its fee from a TRIAL signing pass and then re-signs; the two
passes sign different messages, so their DER signatures differ in length. Signing
is deterministic (RFC 6979), so whether a transaction underpays is a fixed property
of *that* transaction — not a coin flip on each run — and a single hard-coded
example would prove only that one recipient and amount are safe, permanently and
uselessly. Measured over 2000 builds per shape at the default rate, the unfixed
builders paid below their own rate on 25.4% of one-input sends, 31.8% at two
inputs, 33.7% at three and 36.8% at five; ``build_send_max_tx`` on 26.2%-38.1%. So
the assertion has to run over many *different* transactions, across input counts,
output shapes and fee rates — which is what every loop below varies the recipient
for.

Why the corpus is itself under test
-----------------------------------
A green "every build clears its rate" is only meaningful if this corpus could
have gone red. :class:`TestTheCorpusCanCatchTheBug` re-runs the same builds with
the per-input signature headroom removed — the pre-fix sizing — and requires that
the builders then *refuse* to return transactions. That is the differential: same
inputs, one constant changed, opposite outcome. Without it a later refactor could
neuter the headroom and every test here would still pass.

The node-level half of this proof lives in ``test_wallet_send_regtest_e2e.py``,
which broadcasts against a real radiant-core regtest node and quotes its reject
reasons. This module is the fast, always-on half: no docker, no network.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.fee_sizing import (
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    SIG_SIZE_SLACK_BYTES,
    assert_pays_for_its_size,
    assert_tx_pays_for_itself,
    fee_for_kb_rate,
    fee_never_below_relay_floor,
    min_relay_fee,
    relay_floor_photons_per_byte,
    required_fee,
    trial_size_with_slack,
)
from pyrxd.glyph.ft import MIN_FEE_RATE
from pyrxd.hd.bip39 import mnemonic_from_entropy
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.wallet import DEFAULT_FEE_RATE, RxdWallet

_URL = "wss://unused.invalid"  # the builders make no network call

# How many builds per (shape, rate) cell. A build is ~0.2 ms, so this whole module
# runs in about a second while still drawing enough signatures that a 25%-per-build
# failure mode is caught with overwhelming probability: with roughly a quarter of
# distinct transactions affected, missing all 200 is (1 - 0.25) ** 200 ~ 1e-25.
_BUILDS = 200

# Rates to build at. The default IS Radiant's mainnet relay floor, which is exactly
# why a one-byte shortfall there is fatal; the others check that nothing in the
# sizing is accidentally tuned to one particular rate. 1_000 is below the protocol
# floor on purpose — a default regtest node relays at a tenth of mainnet's rate, and
# the e2e suite builds at whatever the node advertises.
_RATES = (1_000, DEFAULT_FEE_RATE, 12_345, 50_000)


def _coin(i: int, value: int = 200_000_000) -> UtxoRecord:
    return UtxoRecord(tx_hash=f"{i:064x}", tx_pos=0, value=value, height=1)


def _wallet(fee_rate: int) -> RxdWallet:
    """A wallet on a freshly generated key — never a hard-coded one.

    ``allow_below_relay_floor`` because ``_RATES`` deliberately includes 1_000, a
    tenth of the mainnet floor, to prove the sizing is not tuned to one rate. The
    constructor otherwise refuses sub-floor rates outright (see
    ``TestTheRateItselfIsJudged``); this is the explicit opt-out that refusal exists
    to make deliberate.
    """
    return RxdWallet(PrivateKey(), _URL, fee_rate=fee_rate, allow_below_relay_floor=True)


def _shortfall(tx: Transaction, fee_rate: int) -> int:
    """``required - paid`` in photons. Positive means the node would reject it."""
    return required_fee(len(tx.serialize()), fee_rate) - tx.get_fee()


# --------------------------------------------------------------------------- the invariant


class TestEveryBuildPaysForItsOwnBytes:
    """The property: over many builds, no transaction pays less than its size demands."""

    @pytest.mark.parametrize("fee_rate", _RATES)
    @pytest.mark.parametrize("n_inputs", [1, 2, 3, 5])
    def test_build_send_tx_never_underpays(self, fee_rate: int, n_inputs: int) -> None:
        wallet = _wallet(fee_rate)
        coins = [_coin(i) for i in range(n_inputs)]
        amount = 150_000_000 * n_inputs
        worst = 0
        for _ in range(_BUILDS):
            tx = wallet.build_send_tx(coins, PrivateKey().public_key().address(), amount)
            short = _shortfall(tx, fee_rate)
            worst = max(worst, short)
            assert short <= 0, (
                f"build_send_tx paid {tx.get_fee()} photons for {len(tx.serialize())} bytes at "
                f"{fee_rate} photons/byte — short by {short}"
            )
        assert worst <= 0

    @pytest.mark.parametrize("fee_rate", _RATES)
    @pytest.mark.parametrize("n_inputs", [1, 2, 3, 5])
    def test_build_send_max_tx_never_underpays(self, fee_rate: int, n_inputs: int) -> None:
        wallet = _wallet(fee_rate)
        coins = [_coin(i) for i in range(n_inputs)]
        for _ in range(_BUILDS):
            tx = wallet.build_send_max_tx(coins, PrivateKey().public_key().address())
            short = _shortfall(tx, fee_rate)
            assert short <= 0, (
                f"build_send_max_tx paid {tx.get_fee()} photons for {len(tx.serialize())} bytes at "
                f"{fee_rate} photons/byte — short by {short}"
            )

    @pytest.mark.parametrize("n_coins", [1, 2, 4])
    def test_uneven_coin_values_and_amounts_still_clear_the_rate(self, n_coins: int) -> None:
        """Selection shape varies with coin values; the invariant must not.

        Descending greedy selection means the number of inputs actually spent
        depends on the values on offer, so sweep a range of them rather than only
        the tidy equal-value case.
        """
        wallet = _wallet(DEFAULT_FEE_RATE)
        for step in range(_BUILDS):
            coins = [_coin(i, 40_000_000 + i * 37_000_000 + step * 101_000) for i in range(n_coins)]
            amount = max(546, sum(c.value for c in coins) // 2)
            tx = wallet.build_send_tx(coins, PrivateKey().public_key().address(), amount)
            assert _shortfall(tx, DEFAULT_FEE_RATE) <= 0

    def test_single_output_builds_clear_the_rate_too(self) -> None:
        """The dropped-change shape: one output, and the fee absorbed the remainder.

        This is the *safe* direction (a smaller transaction than the fee paid for),
        but it is also the shape where the fee is no longer ``size × rate``, so it
        needs its own assertion rather than an assumption.
        """
        wallet = _wallet(DEFAULT_FEE_RATE)
        coin = _coin(0, 500_000_000)
        seen = 0
        for slack in range(1, 546):
            try:
                tx = wallet.build_send_tx([coin], PrivateKey().public_key().address(), 500_000_000 - 2_290_000 - slack)
            except ValidationError:
                continue
            if len(tx.outputs) == 1:
                seen += 1
                assert _shortfall(tx, DEFAULT_FEE_RATE) <= 0
        assert seen > 0, "no sub-floor-change build was produced — this shape went untested"


# --------------------------------------------------------------------------- the HD copies


class TestHdWalletBuildersToo:
    """``HdWallet`` carries its own copy of both builders, and it had the same bug.

    ``hd/wallet.py`` mirrors ``RxdWallet.build_send_tx``/``build_send_max_tx`` so it
    can sign each input with its own derived key — and it mirrored the unmeasured
    trial pass along with everything else. Measured before the fix at the default
    rate, 800 builds per shape: 23.9% / 31.1% / 33.2% of one-, two- and three-input
    sends short, and 23.6% / 28.9% / 32.8% of sweeps. Two builders with one rule
    between them is exactly the drift this repo keeps paying for, so both are held
    to the same corpus.
    """

    @staticmethod
    def _hd_wallet() -> HdWallet:
        """A wallet on freshly generated entropy — never a hard-coded mnemonic."""
        return HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(16)))

    @staticmethod
    def _triples(wallet: HdWallet, n: int) -> list:
        return [
            (
                UtxoRecord(tx_hash=f"{i:064x}", tx_pos=0, value=200_000_000, height=1),
                wallet._derive_address(0, i),
                wallet._privkey_for(0, i),
            )
            for i in range(n)
        ]

    @pytest.mark.parametrize("n_inputs", [1, 2, 3])
    def test_hd_send_and_sweep_never_underpay(self, n_inputs: int) -> None:
        wallet = self._hd_wallet()
        triples = self._triples(wallet, n_inputs)
        for _ in range(_BUILDS):
            tx = wallet.build_send_tx(
                triples, PrivateKey().public_key().address(), 150_000_000 * n_inputs, fee_rate=DEFAULT_FEE_RATE
            )
            assert _shortfall(tx, DEFAULT_FEE_RATE) <= 0, "HdWallet.build_send_tx underpaid its own rate"

            sweep = wallet.build_send_max_tx(triples, PrivateKey().public_key().address(), fee_rate=DEFAULT_FEE_RATE)
            assert _shortfall(sweep, DEFAULT_FEE_RATE) <= 0, "HdWallet.build_send_max_tx underpaid its own rate"

    def test_without_headroom_the_hd_builders_refuse_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same differential, so the HD assertions above cannot go vacuous either."""
        monkeypatch.setattr("pyrxd.hd.wallet.trial_size_with_slack", lambda size, n: size)
        wallet = self._hd_wallet()
        triples = self._triples(wallet, 3)

        refused = 0
        for _ in range(_BUILDS):
            try:
                tx = wallet.build_send_tx(
                    triples, PrivateKey().public_key().address(), 450_000_000, fee_rate=DEFAULT_FEE_RATE
                )
            except ValidationError as exc:
                assert "fee-sizing invariant violated" in str(exc)
                refused += 1
                continue
            assert _shortfall(tx, DEFAULT_FEE_RATE) <= 0
        assert refused > 0, "no HD build underpaid with the headroom removed — the corpus is not exercising it"


# --------------------------------------------------------------------------- the differential


class TestTheCorpusCanCatchTheBug:
    """Remove the headroom and the same builds must fail — otherwise green means nothing."""

    @staticmethod
    def _no_slack(trial_size_bytes: int, n_inputs: int) -> int:
        """The pre-fix sizing: fee the trial bytes and hope the final ones match."""
        return trial_size_bytes

    @pytest.mark.parametrize("builder", ["send", "send_max"])
    def test_without_headroom_the_builders_refuse_rather_than_underpay(
        self, monkeypatch: pytest.MonkeyPatch, builder: str
    ) -> None:
        """With the slack disabled, the final re-measurement must catch the shortfall.

        This proves two things at once: the corpus is capable of producing an
        underpaying build (so the green tests above are not vacuous), and the
        fail-closed guard — not merely the headroom — is what makes the result safe.
        A build that slipped through would be a transaction the network refuses and
        that Radiant cannot fee-bump.
        """
        monkeypatch.setattr("pyrxd.wallet.trial_size_with_slack", self._no_slack)
        wallet = _wallet(DEFAULT_FEE_RATE)
        coins = [_coin(i) for i in range(3)]

        refused = 0
        returned = 0
        for _ in range(_BUILDS):
            try:
                if builder == "send":
                    tx = wallet.build_send_tx(coins, PrivateKey().public_key().address(), 450_000_000)
                else:
                    tx = wallet.build_send_max_tx(coins, PrivateKey().public_key().address())
            except ValidationError as exc:
                assert "fee-sizing invariant violated" in str(exc)
                refused += 1
                continue
            returned += 1
            # Anything the guard DID return still has to be relayable.
            assert _shortfall(tx, DEFAULT_FEE_RATE) <= 0

        assert refused > 0, (
            f"{_BUILDS} builds with the signature headroom removed and not one underpaid — "
            "this corpus cannot detect the defect it exists to detect"
        )
        assert returned > 0, "every build failed; the corpus is no longer exercising the normal path"

    def test_the_guard_is_reached_through_the_public_builder(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A fee forced far below the rate must raise, not return.

        Belt-and-braces for the case where some future change makes the headroom
        adequate but the guard itself is bypassed or deleted.
        """
        monkeypatch.setattr("pyrxd.wallet.required_fee", lambda size, rate: max(1, size * rate // 4))
        wallet = _wallet(DEFAULT_FEE_RATE)
        with pytest.raises(ValidationError, match="fee-sizing invariant violated"):
            wallet.build_send_tx([_coin(0)], PrivateKey().public_key().address(), 100_000_000)
        with pytest.raises(ValidationError, match="fee-sizing invariant violated"):
            wallet.build_send_max_tx([_coin(0)], PrivateKey().public_key().address())


# --------------------------------------------------------------------------- documented trade-offs


class TestTheOverpaymentIsBounded:
    """The headroom is a deliberate, bounded overpayment — hold it to that bound."""

    @pytest.mark.parametrize("n_inputs", [1, 2, 3, 5])
    def test_send_max_payout_is_never_shaved_by_more_than_the_headroom(self, n_inputs: int) -> None:
        """``build_send_max_tx`` decides the payout once, up front, and what it gives
        up to the miner beyond the exact fee stays inside a stated bound.

        Two things make the paid fee exceed ``final_size × rate``: the
        ``SIG_SIZE_SLACK_BYTES`` per input deliberately added to the trial
        measurement, and the final signatures coming out *shorter* than the trial's
        — bounded by the same three-bytes-per-input DER spread, in the other
        direction. So the cap is ``2 × SIG_SIZE_SLACK_BYTES × inputs × rate``:
        0.0006 RXD per input at the default rate, worst case.

        A sweep has no change output, so this comes out of the payout. That is
        answering the question the caller asked ("everything minus the fee"), but it
        is only acceptable while it stays small — hence a bound that is asserted
        rather than asserted-in-prose.
        """
        rate = DEFAULT_FEE_RATE
        wallet = _wallet(rate)
        coins = [_coin(i) for i in range(n_inputs)]
        total_in = sum(c.value for c in coins)
        cap = 2 * SIG_SIZE_SLACK_BYTES * n_inputs * rate
        for _ in range(50):
            tx = wallet.build_send_max_tx(coins, PrivateKey().public_key().address())
            exact = len(tx.serialize()) * rate  # what a perfectly-sized fee would be
            overpaid = tx.get_fee() - exact
            assert 0 <= overpaid <= cap, f"overpaid {overpaid} photons, outside 0..{cap}"
            assert tx.outputs[0].satoshis == total_in - tx.get_fee()

    def test_dropped_change_still_over_estimates_and_that_is_allowed(self) -> None:
        """The pre-existing safe direction must not have been "fixed" into a shave.

        When the change falls below the send-policy floor it is left to the fee, so
        the transaction is smaller than the fee paid for it. Over-paying is fine;
        the regression to watch for is someone tightening this into a re-size that
        reintroduces the trial/final mismatch.
        """
        wallet = _wallet(DEFAULT_FEE_RATE)
        coin = _coin(0, 500_000_000)
        for slack in range(1, 546):
            try:
                tx = wallet.build_send_tx([coin], PrivateKey().public_key().address(), 500_000_000 - 2_290_000 - slack)
            except ValidationError:
                continue
            if len(tx.outputs) == 1:
                assert tx.get_fee() > len(tx.serialize()) * DEFAULT_FEE_RATE
                return
        pytest.fail("no sub-floor-change build was produced")


# --------------------------------------------------------------------------- the shared module


class TestFeeSizingHelpers:
    def test_ceil_matches_a_node_rounding_up_not_down(self) -> None:
        # 1 byte at 10_000_000/kB is 10_000 photons exactly; 1 byte at 1/kB is a
        # fraction, and a fee one photon short is rejected exactly like a zero fee.
        assert fee_for_kb_rate(1, 10_000_000) == 10_000
        assert fee_for_kb_rate(1, 1) == 1  # 0.001 photons rounds UP to 1, not down to 0
        assert fee_for_kb_rate(1500, 1) == 2  # 1.5 -> 2
        assert fee_for_kb_rate(1000, 1) == 1  # exact multiples are not inflated
        assert fee_for_kb_rate(3, 1_000_000) == 3_000

    def test_the_floor_is_derived_from_the_per_kb_constant(self) -> None:
        assert relay_floor_photons_per_byte() == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB // 1000
        assert min_relay_fee(226) == fee_for_kb_rate(226, RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB)

    def test_gravity_fee_policy_and_fee_sizing_are_the_same_definition(self) -> None:
        """One constant, re-exported — not two that happen to agree today."""
        from pyrxd.gravity import fee_policy

        assert fee_policy.RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB is RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
        assert fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(226) == min_relay_fee(226)

    def test_the_wallet_and_glyph_defaults_are_bound_to_the_floor(self) -> None:
        """Anti-drift: these used to be independent literals spelling 10_000."""
        assert relay_floor_photons_per_byte() == DEFAULT_FEE_RATE
        assert relay_floor_photons_per_byte() == MIN_FEE_RATE

    def test_required_fee_binds_both_floors_at_or_above_the_protocol_rate(self) -> None:
        floor = relay_floor_photons_per_byte()
        assert required_fee(226, floor) == 226 * floor == min_relay_fee(226)
        assert required_fee(226, floor * 2) == 226 * floor * 2

    def test_a_sub_floor_rate_is_a_deliberate_opt_out_not_an_upgrade(self) -> None:
        """Regtest relays a tenth of mainnet's floor; forcing it up would make every
        node-level proof of this code vacuous, since the node could never reject."""
        assert required_fee(226, 1_000) == 226_000
        # The no-opt-out variant, for rates that cross a trust boundary.
        assert fee_never_below_relay_floor(226, 1_000) == min_relay_fee(226)

    def test_headroom_is_three_bytes_per_input(self) -> None:
        assert SIG_SIZE_SLACK_BYTES == 3
        assert trial_size_with_slack(226, 1) == 229
        assert trial_size_with_slack(374, 2) == 380
        assert trial_size_with_slack(226, 0) == 226

    @pytest.mark.parametrize(
        "fn, args",
        [
            (fee_for_kb_rate, (0, 10_000_000)),
            (fee_for_kb_rate, (-1, 10_000_000)),
            (fee_for_kb_rate, (True, 10_000_000)),
            (fee_for_kb_rate, (226, 0)),
            (min_relay_fee, (0,)),
            (required_fee, (226, 0)),
            (required_fee, (226, True)),
            (trial_size_with_slack, (0, 1)),
            (trial_size_with_slack, (226, -1)),
        ],
    )
    def test_bad_sizes_and_rates_are_rejected(self, fn, args) -> None:
        with pytest.raises(ValueError):
            fn(*args)

    def test_assert_pays_for_its_size_returns_the_requirement_when_covered(self) -> None:
        assert assert_pays_for_its_size(size_bytes=226, fee_paid=2_260_000, fee_rate=10_000, what="t") == 2_260_000

    def test_assert_pays_for_its_size_raises_one_photon_short(self) -> None:
        """One photon, because that is the real margin — the node's check is ``<``."""
        with pytest.raises(ValueError, match="fee-sizing invariant violated"):
            assert_pays_for_its_size(size_bytes=226, fee_paid=2_259_999, fee_rate=10_000, what="t")

    def test_the_error_names_the_builder_and_the_no_bump_consequence(self) -> None:
        with pytest.raises(ValueError) as exc:
            assert_pays_for_its_size(size_bytes=226, fee_paid=1, fee_rate=10_000, what="build_send_tx")
        message = str(exc.value)
        assert "build_send_tx" in message
        assert "min relay fee not met" in message
        assert "RBF" in message and "CPFP" in message

    def test_the_error_type_is_the_callers_own(self) -> None:
        """``glyph.ft`` documents ValueError, ``wallet`` documents ValidationError."""
        with pytest.raises(ValidationError):
            assert_pays_for_its_size(size_bytes=226, fee_paid=1, fee_rate=10_000, what="t", error_type=ValidationError)

    def test_assert_tx_pays_for_itself_reads_the_transactions_own_numbers(self) -> None:
        """The checked fee must be the one ``get_fee()`` reports to the caller."""
        wallet = _wallet(DEFAULT_FEE_RATE)
        tx = wallet.build_send_tx([_coin(0)], PrivateKey().public_key().address(), 100_000_000)
        assert assert_tx_pays_for_itself(tx, DEFAULT_FEE_RATE, what="t") == required_fee(
            len(tx.serialize()), DEFAULT_FEE_RATE
        )
        assert tx.get_fee() >= len(tx.serialize()) * DEFAULT_FEE_RATE
