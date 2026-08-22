"""Every builder that takes a fee or a fee RATE must refuse what the network won't relay.

Three defects, one shape
------------------------
An 8-reviewer panel found the same hole in three places, each reached from a
different direction, all with the same consequence: a transaction that pays less
than ``AcceptToMemoryPool`` demands. On Radiant that is not a stuck transaction to
be bumped later — there is neither RBF nor CPFP (``Radiant-Core``
``src/validation.cpp:667``/``:866`` reject any mempool conflict), so it holds its
own inputs until ``DEFAULT_MEMPOOL_EXPIRY``, 8 hours, before a rebuild is even
possible.

1. **``build_nft_transfer_tx`` sized its fee off the TRIAL signing pass.** The
   trial and final passes sign different messages, so their DER signatures differ
   in length (69/70/71 bytes), and whenever the final one came out longer the
   transaction paid for fewer bytes than it contained. Measured on this branch over
   3000 builds on FRESH keys at the default rate: **746 (24.9%) short by 1-2
   bytes**, and 0/3000 after the fix. Signing is deterministic (RFC 6979), so an
   affected transfer is short on *every* retry — it is a property of that NFT and
   that recipient, not a flake.

2. **The v3 covenant builders took ``fee`` on trust** (``fee >= 0`` and nothing
   else), while being exported public API. The only thing standing between an SDK
   consumer and an unrelayable spend was the CLI's own ``_assert_relayable``, which
   a library caller never runs — ``examples/rswp_orderbook_demo.py`` passes
   ``fee=300`` for a transaction that needs ~2_300_000 photons.

3. **``RxdWallet``/``HdWallet`` validated ``fee_rate`` only as ``> 0``.** Nothing
   downstream could catch it: ``required_fee`` binds the caller's rate and *only*
   the caller's rate, and ``assert_tx_pays_for_itself`` then checks the built
   transaction against that same rate — so every guard agreed a ``fee_rate=1``
   wallet was correct, and it was, at 1/10_000 of the mainnet floor.

Why the existing tests did not catch (1)
----------------------------------------
``tests/test_glyph_transfer.py`` builds ONE transaction, from a hard-coded key
(``_ALICE_KEY_INT``) with a fixed txid and value. That transaction happens to land
safe, permanently and uselessly — it can never observe a defect that affects a
quarter of *distinct* transactions. So the corpus here runs over many builds with a
FRESH key, a fresh recipient and a fresh ref every time, which is what varies the
message being signed. ``TestTheCorpusCanCatchTheBug`` then removes the headroom and
requires the same builds to start failing, so a green run is never vacuous.

The node-level half lives in ``tests/test_fee_floor_boundary_regtest_e2e.py``,
which runs a regtest node at ``-minrelaytxfee=0.10`` — **the mainnet floor**, the
rate the builders default to — instead of the 1/10th a default regtest node
advertises, and quotes its reject reasons. That difference is the whole reason the
existing NFT regtest coverage could not see this: at a tenth of the built rate a
1-2 byte shortfall is structurally invisible.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.fee_sizing import (
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    SIG_SIZE_SLACK_BYTES,
    assert_fee_rate_clears_relay_floor,
    min_relay_fee,
    relay_floor_photons_per_byte,
    required_fee,
)
from pyrxd.glyph.builder import MIN_FEE_RATE, GlyphBuilder, TransferParams
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20
from pyrxd.swap import Asset, FundingInput, accept_offer, create_offer
from pyrxd.swap.rswp import (
    build_advert_tx,
    build_covenant_cancel_tx,
    build_covenant_refund_tx,
    create_covenant_order,
    create_rswp_order,
    decode_rswp_order,
    prepare_covenant_offer,
    prepare_offered_utxo,
    take_covenant_order,
)
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.wallet import DEFAULT_FEE_RATE

_RATE = relay_floor_photons_per_byte()  # 10_000 photons/byte — Radiant's mainnet floor
_EXPIRY = 840_000

#: Enough builds that a defect affecting ~a quarter of distinct transactions cannot
#: be missed: (1 - 0.25) ** 300 is about 1e-38. A build is ~0.4 ms.
_BUILDS = 300


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, ref: GlyphRef, units: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), units))
    return tx


def _fresh_ref() -> GlyphRef:
    return GlyphRef(txid=os.urandom(32).hex(), vout=0)


# ===========================================================================
# 1. build_nft_transfer_tx
# ===========================================================================


def _nft_transfer(*, fee_rate: int = _RATE, value: int = 100_000_000):
    """One NFT transfer on a brand-new key, ref, recipient and outpoint.

    Everything that feeds the signed message is fresh: the owner key (so ``r``/``s``
    differ), the NFT's ref, the spending outpoint, the value and the recipient. A
    fixed-key fixture varies none of them and therefore signs one message forever.
    """
    owner, owner_pkh = _key()
    nft_script = build_nft_locking_script(owner_pkh, _fresh_ref())
    return GlyphBuilder().build_nft_transfer_tx(
        TransferParams(
            nft_utxo_txid=os.urandom(32).hex(),
            nft_utxo_vout=0,
            nft_utxo_value=value,
            nft_script=nft_script,
            new_owner_pkh=PrivateKey().public_key().hash160(),
            private_key=owner,
            fee_rate=fee_rate,
        )
    )


class TestNftTransferPaysForItsOwnBytes:
    """The property: over many builds, no transfer pays less than its size demands."""

    @pytest.mark.parametrize("fee_rate", [_RATE, 12_345, 50_000])
    def test_no_transfer_underpays_its_own_rate(self, fee_rate: int) -> None:
        worst = 0
        for _ in range(_BUILDS):
            result = _nft_transfer(fee_rate=fee_rate)
            size = len(result.tx.serialize())
            paid = 100_000_000 - result.tx.outputs[0].satoshis
            short = required_fee(size, fee_rate) - paid
            worst = max(worst, short)
            assert short <= 0, (
                f"build_nft_transfer_tx paid {paid} photons for {size} bytes at {fee_rate} "
                f"photons/byte — short by {short}. Radiant cannot fee-bump this."
            )
        assert worst <= 0

    def test_at_the_default_rate_the_shortfall_would_be_below_the_mainnet_floor(self) -> None:
        """The default rate IS the mainnet relay floor, so "short" means "rejected".

        Asserted against ``min_relay_fee`` — the node's own derivation — rather than
        against the rate the builder was handed, so this stays true even if the
        builder's default and the chain's floor ever stop coinciding.
        """
        assert MIN_FEE_RATE == DEFAULT_FEE_RATE == relay_floor_photons_per_byte()
        for _ in range(_BUILDS):
            result = _nft_transfer()
            raw = result.tx.serialize()
            paid = 100_000_000 - result.tx.outputs[0].satoshis
            assert paid >= min_relay_fee(len(raw)), "the node would reject this: 66: min relay fee not met"

    def test_varying_the_carrier_value_varies_the_message_too(self) -> None:
        """The signed preimage commits to the output value, so sweep it as well."""
        for i in range(_BUILDS):
            value = 10_000_000 + i * 977_777
            result = _nft_transfer(value=value)
            paid = value - result.tx.outputs[0].satoshis
            assert paid >= required_fee(len(result.tx.serialize()), _RATE)

    def test_the_reported_fee_is_the_fee_actually_paid(self) -> None:
        """``TransferResult.fee`` must be what the chain will see, not an estimate."""
        for _ in range(50):
            result = _nft_transfer()
            assert result.fee == 100_000_000 - result.tx.outputs[0].satoshis

    def test_overpayment_stays_inside_the_stated_bound(self) -> None:
        """The headroom is a deliberate, bounded overpayment out of the NFT's carrier.

        Cap is ``2 x SIG_SIZE_SLACK_BYTES`` bytes' worth for this one-input builder:
        the headroom in one direction, the final signature coming out shorter than
        the trial's in the other. 0.0006 RXD at the default rate, worst case.
        """
        cap = 2 * SIG_SIZE_SLACK_BYTES * _RATE
        for _ in range(_BUILDS):
            result = _nft_transfer()
            exact = len(result.tx.serialize()) * _RATE
            assert 0 <= result.fee - exact <= cap, f"overpaid {result.fee - exact}, outside 0..{cap}"


class TestTheCorpusCanCatchTheBug:
    """Remove the headroom and the same builds must fail — otherwise green means nothing."""

    def test_without_headroom_the_builder_refuses_rather_than_underpaying(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Restore the pre-fix sizing and require the final re-measurement to catch it.

        Two things at once: the corpus above is capable of producing an underpaying
        build (so its green is not vacuous), and the fail-closed guard — not merely
        the headroom — is what makes the result safe.
        """
        monkeypatch.setattr("pyrxd.glyph.builder.trial_size_with_slack", lambda size, n: size)
        refused = returned = 0
        for _ in range(_BUILDS):
            try:
                result = _nft_transfer()
            except ValueError as exc:
                assert "fee-sizing invariant violated" in str(exc)
                refused += 1
                continue
            returned += 1
            paid = 100_000_000 - result.tx.outputs[0].satoshis
            assert paid >= required_fee(len(result.tx.serialize()), _RATE)
        assert refused > 0, (
            f"{_BUILDS} builds with the signature headroom removed and not one underpaid — "
            "this corpus cannot detect the defect it exists to detect"
        )
        assert returned > 0, "every build failed; the corpus is no longer exercising the normal path"

    def test_the_guard_is_reached_through_the_public_builder(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Belt-and-braces: a fee forced far below the rate must raise, not return."""
        monkeypatch.setattr("pyrxd.glyph.builder.required_fee", lambda size, rate: max(1, size * rate // 4))
        with pytest.raises(ValueError, match="fee-sizing invariant violated"):
            _nft_transfer()


class TestNftTransferJudgesTheRateItself:
    """A sub-floor RATE has to be refused before any bytes exist — nothing later can."""

    @pytest.mark.parametrize("fee_rate", [1, 999, 1_000, 9_999])
    def test_a_sub_floor_rate_is_refused(self, fee_rate: int) -> None:
        with pytest.raises(ValueError, match="relay floor"):
            _nft_transfer(fee_rate=fee_rate)

    def test_exactly_at_the_floor_is_accepted(self) -> None:
        assert _nft_transfer(fee_rate=_RATE).fee > 0

    def test_the_refusal_matches_the_ft_builder_next_door(self) -> None:
        """Both go through one implementation, so they cannot drift apart on the rule."""
        from pyrxd.glyph.ft import _check_fee_rate

        with pytest.raises(ValueError) as ft_exc:
            _check_fee_rate(9_999)
        with pytest.raises(ValueError) as nft_exc:
            _nft_transfer(fee_rate=9_999)
        assert "9999" in str(ft_exc.value) and "9999" in str(nft_exc.value)
        assert str(relay_floor_photons_per_byte()) in str(ft_exc.value)
        assert str(relay_floor_photons_per_byte()) in str(nft_exc.value)

    def test_the_builders_minimum_is_derived_not_a_literal(self) -> None:
        """Anti-drift: ``builder.MIN_FEE_RATE`` was a hardcoded ``10_000``."""
        assert relay_floor_photons_per_byte() == MIN_FEE_RATE
        assert MIN_FEE_RATE * 1000 == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB


# ===========================================================================
# 2. the v3 covenant builders + the partial-swap accept
# ===========================================================================

_RESERVE = 500_000_000  # 5 RXD reserved — big enough to pay a real fee out of


def _funded_covenant(maker: PrivateKey, *, photons: int = _RESERVE) -> Transaction:
    """A covenant reservation built at a comfortable, REAL fee."""
    pkh = maker.public_key().hash160()
    return prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(pkh, photons + 50_000_000), 0, maker)],
        photons=photons,
        owner_pkh=pkh,
        expiry_height=_EXPIRY,
        change_pkh=pkh,
        fee=10_000_000,
    )


def _reserved_state():
    """``(maker_key, maker_pkh, funded_covenant_tx)`` on a fresh key."""
    maker, pkh = _key()
    return maker, pkh, _funded_covenant(maker)


#: Forces an under-floor build into existence so it can be measured. Never a way to
#: make a guard stop complaining — only a way to manufacture the negative control.
#: Same escape hatch, same spelling, as tests/test_remaining_builder_floors_regtest_e2e.
_PERMISSIVE = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

#: Steps of the fee↔size fixed point to take within ONE attempt. For a fixed state the
#: size can take only two adjacent values (the DER signature is 69-71 bytes), so a run
#: that has not settled in four steps is a two-cycle and never will.
_SETTLE_STEPS = 4


def _boundary(setup, make, label: str, policy: DeadlineFeePolicy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY):
    """Find a fee that is EXACTLY this transaction's floor, and prove one under fails.

    Searched rather than solved: the fee is subtracted from a signed output value, so
    changing it re-signs the input and can move the DER length — and with it the size
    the floor is derived from. Not every set of keys admits a build whose size is
    stable across the ``floor`` / ``floor - 1`` pair, so attempts draw fresh keys.

    ``setup()`` returns the per-attempt state (keys, a funded covenant, an offer);
    ``make(state, fee, policy)`` returns the raw bytes. The split matters: WITHIN an
    attempt the state is FIXED, so ``make(state, floor - 1, _PERMISSIVE)`` and
    ``make(state, floor - 1, policy)`` build byte-identical transactions and the
    refusal is a statement about *that* transaction rather than about a differently
    sized one that happened to be built next. Threading fresh keys through every call
    instead makes this test pass or fail on which DER length turned up — measured at
    roughly 40% spurious failures before the split.

    A fresh ``state`` is also a **size-neutral redraw**: the keys it draws contribute a
    fixed 33-byte pubkey and a fixed 20-byte PKH, so a new attempt changes the sighash
    and not the byte count. What it cannot do is make the probe agree with the
    candidate, so the fee↔size fixed point is ITERATED rather than taken from a single
    probe — the same change made to
    ``test_remaining_builder_floors_regtest_e2e._settle_pair``. Demanding that three
    independent DER draws agree left a measured 0.07% non-convergence per case here
    (1/1500 trials, on each of the three cases that flaked), which is 0.27% per run of
    this file. Iterating leaves only ``under`` as an independent draw.

    :returns: ``(at_floor_raw, floor)``.
    """
    for _ in range(25):
        state = setup()
        size = len(make(state, policy.min_relay_fee(400), _PERMISSIVE))
        for _ in range(_SETTLE_STEPS):
            floor = policy.min_relay_fee(size)
            settled = len(make(state, floor, _PERMISSIVE))
            if settled == size:
                break
            size = settled
        else:
            continue  # the fee↔size map is a two-cycle on this state
        cand = make(state, floor, policy)
        # One photon under, forced past the guard, must be the SAME size — otherwise
        # "under" would be a statement about a different transaction.
        under = make(state, floor - 1, _PERMISSIVE)
        if policy.min_relay_fee(len(under)) != floor:
            continue
        with pytest.raises(InsufficientFundsError, match="below the required"):
            make(state, floor - 1, policy)
        return cand, floor
    raise AssertionError(f"{label}: no build landed exactly on its own relay floor")


class TestV3CovenantBuildersGateTheFee:
    """All four were exported public API validating only ``fee >= 0``."""

    def test_prepare_covenant_offer_refuses_a_sub_floor_fee(self) -> None:
        def make(state, fee: int, policy):
            maker, pkh = state
            return prepare_covenant_offer(
                funding=[FundingInput(_rxd_src(pkh, _RESERVE + 50_000_000), 0, maker)],
                photons=_RESERVE,
                owner_pkh=pkh,
                expiry_height=_EXPIRY,
                change_pkh=pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        raw, floor = _boundary(_key, make, "prepare_covenant_offer")
        assert floor == len(raw) * 10_000

    def test_the_demo_fee_is_refused(self) -> None:
        """``examples/rswp_orderbook_demo.py`` passes ``fee=300``. It is off by ~7700x."""
        maker, pkh = _key()
        with pytest.raises(InsufficientFundsError, match="below the required"):
            prepare_covenant_offer(
                funding=[FundingInput(_rxd_src(pkh, _RESERVE + 50_000_000), 0, maker)],
                photons=_RESERVE,
                owner_pkh=pkh,
                expiry_height=_EXPIRY,
                change_pkh=pkh,
                fee=300,
            )

    def test_build_covenant_cancel_tx_refuses_a_sub_floor_fee(self) -> None:
        """The one that matters most: cancel is the ONLY hard revocation.

        An unrelayable cancel leaves the reservation takeable at the advertised price
        while the caller has been handed a transaction, a txid, and the word
        "revoked". That is the reasoning #411 used for the v2 sibling, and the stakes
        are higher here because the value sits in a covenant whose other exit is
        CLTV-gated.
        """

        def make(state, fee: int, policy):
            maker, pkh, reserved = state
            return build_covenant_cancel_tx(
                covenant_source_tx=reserved,
                covenant_vout=0,
                maker_key=maker,
                refund_pkh=pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        _boundary(_reserved_state, make, "build_covenant_cancel_tx")

    def test_build_covenant_refund_tx_refuses_a_sub_floor_fee(self) -> None:
        def make(state, fee: int, policy):
            maker, pkh, reserved = state
            return build_covenant_refund_tx(
                covenant_source_tx=reserved,
                covenant_vout=0,
                maker_key=maker,
                refund_pkh=pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        _boundary(_reserved_state, make, "build_covenant_refund_tx")

    def test_take_covenant_order_refuses_a_sub_floor_fee(self) -> None:
        def setup():
            maker, mk_pkh = _key()
            taker, tk_pkh = _key()
            reserved = _funded_covenant(maker)
            post = create_covenant_order(
                covenant_source_tx=reserved,
                covenant_vout=0,
                maker_key=maker,
                receive=Asset("rxd", 200_000_000),
                maker_receive_pkh=mk_pkh,
            )
            return decode_rswp_order(post.advert_script), reserved, taker, tk_pkh

        def make(state, fee: int, policy):
            order, reserved, taker, tk_pkh = state
            return take_covenant_order(
                order,
                give_source_tx=reserved,
                funding=[FundingInput(_rxd_src(tk_pkh, 900_000_000), 0, taker)],
                taker_receive_pkh=tk_pkh,
                taker_change_pkh=tk_pkh,
                fee=fee,
                current_height=_EXPIRY - 10,
                fee_policy=policy,
            ).serialize()

        _boundary(setup, make, "take_covenant_order")

    def test_the_size_measured_includes_the_branch_selector(self) -> None:
        """``_append_selector`` adds a scriptSig byte AFTER ``sign()``.

        Radiant charges the relay floor against ``GetTotalSize()``, so a gate placed
        before the selector would size the fee against bytes the node never sees. One
        byte at the mainnet floor is 10_000 photons — the exact margin that decides
        ``66: min relay fee not met``.
        """
        maker, pkh = _key()
        reserved = _funded_covenant(maker)
        tx = build_covenant_cancel_tx(
            covenant_source_tx=reserved,
            covenant_vout=0,
            maker_key=maker,
            refund_pkh=pkh,
            fee=10_000_000,
        )
        scriptsig = tx.inputs[0].unlocking_script.serialize()
        assert scriptsig.endswith(b"\x51"), "the SWAP selector must be present on the returned transaction"
        # The gate ran on the full size, so the returned transaction clears its floor
        # WITH the selector counted, not without it.
        assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(len(tx.serialize())) <= 10_000_000

    def test_a_regtest_rate_is_still_expressible(self) -> None:
        """The gate is a floor, not a straitjacket — a lower-relaying node is legal."""
        maker, pkh = _key()
        reserved = _funded_covenant(maker)
        regtest = DeadlineFeePolicy(relay_fee_per_kb=1_000_000, allow_below_protocol_floor=True)
        tx = build_covenant_cancel_tx(
            covenant_source_tx=reserved,
            covenant_vout=0,
            maker_key=maker,
            refund_pkh=pkh,
            fee=regtest.min_relay_fee(300),
            fee_policy=regtest,
        )
        # ...and that same fee is refused under the mainnet default.
        with pytest.raises(InsufficientFundsError):
            build_covenant_cancel_tx(
                covenant_source_tx=reserved,
                covenant_vout=0,
                maker_key=maker,
                refund_pkh=pkh,
                fee=regtest.min_relay_fee(300),
            )
        assert tx.outputs[0].satoshis > 0


class TestPartialSwapAcceptGatesTheFee:
    """``pyrxd.swap.partial.accept_offer`` — same shape, and it is the TAKER's money."""

    @staticmethod
    def _offer_and_funding():
        maker, mk_pkh = _key()
        taker, tk_pkh = _key()
        offer = create_offer(
            give_source_tx=_rxd_src(mk_pkh, 400_000_000),
            give_vout=0,
            maker_key=maker,
            receive=Asset("rxd", 100_000_000),
            maker_receive_pkh=mk_pkh,
        )
        return offer, [FundingInput(_rxd_src(tk_pkh, 900_000_000), 0, taker)], tk_pkh

    def test_a_sub_floor_fee_is_refused(self) -> None:
        offer, funding, tk_pkh = self._offer_and_funding()
        with pytest.raises(InsufficientFundsError, match="below the required"):
            accept_offer(offer, funding=funding, taker_receive_pkh=tk_pkh, taker_change_pkh=tk_pkh, fee=300)

    def test_the_boundary_is_the_floor_for_the_completed_size(self) -> None:
        def make(state, fee: int, policy):
            offer, funding, tk_pkh = state
            return accept_offer(
                offer,
                funding=funding,
                taker_receive_pkh=tk_pkh,
                taker_change_pkh=tk_pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        _boundary(self._offer_and_funding, make, "accept_offer")

    def test_an_ft_swap_is_gated_too(self) -> None:
        maker, mk_pkh = _key()
        taker, tk_pkh = _key()
        ref = _fresh_ref()
        offer = create_offer(
            give_source_tx=_rxd_src(mk_pkh, 400_000_000),
            give_vout=0,
            maker_key=maker,
            receive=Asset("ft", 50, ref),
            maker_receive_pkh=mk_pkh,
        )
        funding = [
            FundingInput(_ft_src(tk_pkh, ref, 60), 0, taker),
            FundingInput(_rxd_src(tk_pkh, 900_000_000), 0, taker),
        ]
        with pytest.raises(InsufficientFundsError, match="below the required"):
            accept_offer(offer, funding=funding, taker_receive_pkh=tk_pkh, taker_change_pkh=tk_pkh, fee=300)


# ===========================================================================
# 3b. the two v2 RSWP builders the floor sweep skipped (FS-2)
# ===========================================================================


class TestV2RswpBuildersGateTheFee:
    """``prepare_offered_utxo`` and ``build_advert_tx`` returned SIGNED sub-floor txs.

    Both are exported from ``pyrxd.swap.rswp``. Called with ``fee=1`` from the public
    package before this change, they each returned a fully signed transaction and a
    txid while their v2 sibling ``build_cancel_tx`` and their v3 analog
    ``prepare_covenant_offer`` refused::

        prepare_offered_utxo    RETURNED a tx: size=225 declared_fee=1 floor=2250000
        build_advert_tx         RETURNED a tx: size=246 declared_fee=1 floor=2460000
        build_cancel_tx  (v2 sibling)       refused: InsufficientFundsError
        prepare_covenant_offer (v3 sibling) refused: InsufficientFundsError

    There is no downstream guard: nothing in ``pyrxd.network`` checks a relay floor on
    any broadcast path.
    """

    @staticmethod
    def _split_state():
        maker, pkh = _key()
        return maker, pkh

    @staticmethod
    def _advert_state():
        maker, pkh = _key()
        post = create_rswp_order(
            give_source_tx=_rxd_src(pkh, 400_000_000),
            give_vout=0,
            maker_key=maker,
            receive=Asset("rxd", 100_000_000),
            maker_receive_pkh=pkh,
        )
        return maker, pkh, post

    def test_prepare_offered_utxo_refuses_a_sub_floor_fee(self) -> None:
        maker, pkh = self._split_state()
        with pytest.raises(InsufficientFundsError, match="below the required"):
            prepare_offered_utxo(
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                asset=Asset("rxd", 100_000_000),
                owner_pkh=pkh,
                change_pkh=pkh,
                fee=1,
            )

    def test_build_advert_tx_refuses_a_sub_floor_fee(self) -> None:
        maker, pkh, post = self._advert_state()
        with pytest.raises(InsufficientFundsError, match="below the required"):
            build_advert_tx(
                advert_script=post.advert_script,
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                change_pkh=pkh,
                fee=1,
            )

    def test_prepare_offered_utxo_boundary_is_its_own_signed_size(self) -> None:
        def make(state, fee: int, policy):
            maker, pkh = state
            return prepare_offered_utxo(
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                asset=Asset("rxd", 100_000_000),
                owner_pkh=pkh,
                change_pkh=pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        raw, floor = _boundary(self._split_state, make, "prepare_offered_utxo")
        assert floor == len(raw) * _RATE

    def test_build_advert_tx_boundary_is_its_own_signed_size(self) -> None:
        def make(state, fee: int, policy):
            maker, pkh, post = state
            return build_advert_tx(
                advert_script=post.advert_script,
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                change_pkh=pkh,
                fee=fee,
                fee_policy=policy,
            ).serialize()

        raw, floor = _boundary(self._advert_state, make, "build_advert_tx")
        assert floor == len(raw) * _RATE

    def test_the_trial_pass_the_cli_needs_is_still_expressible(self) -> None:
        """The guard must not break ``pyrxd swap post``.

        The CLI cannot model the advert's size, so it builds deliberately sub-floor
        trial passes, measures the real bytes and rebuilds — passing
        ``swap_book_cmds._SIZING_TRIAL_POLICY`` exactly as it already does for the
        cancel builders. A gate with no opt-out would refuse the trial and the command
        would never reach its own ``_assert_relayable``. Refusing a legitimate action
        is its own fund-safety bug, so this is asserted, not assumed.
        """
        from pyrxd.cli.swap_book_cmds import _SIZING_TRIAL_POLICY

        maker, pkh, post = self._advert_state()
        trial = build_advert_tx(
            advert_script=post.advert_script,
            funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
            change_pkh=pkh,
            fee=1,
            fee_policy=_SIZING_TRIAL_POLICY,
        )
        assert trial.outputs[0].locking_script.serialize() == post.advert_script
        # ...and the SAME fee is refused under the mainnet default.
        with pytest.raises(InsufficientFundsError):
            build_advert_tx(
                advert_script=post.advert_script,
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                change_pkh=pkh,
                fee=1,
            )

    def test_a_fee_that_clears_the_floor_is_never_refused(self) -> None:
        """The other half of the guard, over fresh keys: it admits what the node admits."""
        for _ in range(50):
            maker, pkh, post = self._advert_state()
            tx = build_advert_tx(
                advert_script=post.advert_script,
                funding=[FundingInput(_rxd_src(pkh, 900_000_000), 0, maker)],
                change_pkh=pkh,
                fee=6_000_000,  # ~460 B advert => floor ~4_600_000
            )
            assert tx.get_fee() >= min_relay_fee(len(tx.serialize()))


# ===========================================================================
# 4. required_fee's docstring, and the rate guard the wallets now use
# ===========================================================================


class TestRequiredFeeBindsOnlyTheCallersRate:
    """The docstring said "Binds BOTH floors". It could not, and it did not."""

    def test_the_protocol_floor_never_binds_at_the_current_constants(self) -> None:
        """``max(size * rate, floor)`` is ``size * rate``, always, for every input.

        Exhaustive over the only region where a ``max`` could possibly bind — rates
        within 3 of the floor — plus a wide deterministic sweep. This is not a
        preference for one implementation; it is what makes the old docstring's
        promise unavailable to callers, which is why every one of them has to gate
        the RATE itself.
        """
        floor_rate = relay_floor_photons_per_byte()
        for size in range(1, 2000):
            for rate in range(floor_rate - 3, floor_rate + 4):
                assert required_fee(size, rate) == size * rate
        for size in (1, 226, 373, 1_000, 12_345, 200_000):
            for rate in (1, 999, floor_rate, floor_rate + 1, 50_000, 1_000_000):
                assert required_fee(size, rate) == size * rate

    def test_the_hole_that_leaves_open(self) -> None:
        """A rate of 1 yields a fee 10_000x under the mainnet requirement."""
        assert required_fee(226, 1) == 226
        assert min_relay_fee(226) == 2_260_000
        assert min_relay_fee(226) == 10_000 * required_fee(226, 1)


class TestTheRateGuard:
    def test_it_refuses_below_the_floor_and_returns_the_rate_above_it(self) -> None:
        floor = relay_floor_photons_per_byte()
        assert assert_fee_rate_clears_relay_floor(floor, what="x") == floor
        assert assert_fee_rate_clears_relay_floor(floor * 3, what="x") == floor * 3
        with pytest.raises(ValueError, match="relay floor"):
            assert_fee_rate_clears_relay_floor(floor - 1, what="x")

    def test_the_message_names_the_caller_and_the_no_bump_consequence(self) -> None:
        with pytest.raises(ValueError) as exc:
            assert_fee_rate_clears_relay_floor(1, what="build_nft_transfer_tx")
        text = str(exc.value)
        assert "build_nft_transfer_tx" in text
        assert "no RBF and no CPFP" in text
        assert "mempool expiry" in text

    def test_the_opt_out_skips_the_floor_but_not_the_type_check(self) -> None:
        assert assert_fee_rate_clears_relay_floor(1, what="x", allow_below_relay_floor=True) == 1
        for bad in (0, -1, True, 1.0, None, "10000"):
            with pytest.raises(ValueError):
                assert_fee_rate_clears_relay_floor(bad, what="x", allow_below_relay_floor=True)  # type: ignore[arg-type]

    def test_the_error_type_is_the_callers_own(self) -> None:
        with pytest.raises(ValidationError):
            assert_fee_rate_clears_relay_floor(1, what="x", error_type=ValidationError)


class TestTheGatesDocstringMatchesTheSignatures:
    """The docstring is the only place this reachability is written down, so it is tested.

    History, because it is the reason these tests are worth their weight.
    ``assert_fee_rate_clears_relay_floor`` once asserted "Both overrides are reachable
    from every public builder behind this gate" and then LISTED the FT builders among
    them. Measured false: no glyph builder took ``allow_below_relay_floor``, so a
    transfer at a regtest rate of 1_000 raised with no opt-out while a MINT at the same
    rate on the same chain succeeded. The claim was corrected to describe the asymmetry
    rather than repair it, and the repair deferred to a change that was about fund
    safety rather than about a docstring.

    #458 is that change. The opt-out now reaches every builder, so these tests assert
    the SYMMETRY — and, critically, that the two bounds stay independent: an
    ``allow_below_relay_floor`` that also widened the ceiling would hand back the
    1000x overpay this module exists to refuse.

    A docstring assertion is worth having because the sentence is load-bearing: a
    reader deciding whether a rate is overridable has nothing else to consult.
    """

    @staticmethod
    def _doc() -> str:
        """The docstring with its line wrapping flattened — the claim spans two lines."""
        return " ".join((assert_fee_rate_clears_relay_floor.__doc__ or "").split())

    def test_the_false_universal_claim_is_gone(self) -> None:
        assert "Both overrides are reachable from every public builder" not in self._doc()

    def test_the_docstring_no_longer_claims_the_glyph_builders_lack_the_opt_out(self) -> None:
        doc = self._doc()
        assert "allow_below_relay_floor" in doc
        assert "No glyph builder accepts ``allow_below_relay_floor``" not in doc

    def test_the_docstring_still_states_the_two_bounds_are_independent(self) -> None:
        """The property a reader most needs, and the one a careless refactor would drop."""
        assert "skips only its own bound" in self._doc()

    @pytest.mark.parametrize(
        ("owner", "method", "below_floor", "overpay"),
        [
            ("pyrxd.glyph.ft:FtUtxoSet", "build_transfer_tx", True, True),
            ("pyrxd.glyph.ft:FtUtxoSet", "build_airdrop_tx", True, True),
            ("pyrxd.hd.wallet:HdWallet", "build_send_tx", True, True),
            ("pyrxd.hd.wallet:HdWallet", "build_send_max_tx", True, True),
            ("pyrxd.agent.watch_only:WatchOnlyTxBuilder", "build_send", True, True),
        ],
    )
    def test_the_measured_reachability_is_what_the_docstring_now_describes(
        self, owner: str, method: str, below_floor: bool, overpay: bool
    ) -> None:
        import importlib
        import inspect

        module_name, class_name = owner.split(":")
        cls = getattr(importlib.import_module(module_name), class_name)
        params = inspect.signature(getattr(cls, method)).parameters
        assert ("allow_below_relay_floor" in params) is below_floor
        assert ("allow_overpay" in params) is overpay

    def test_the_glyph_params_dataclasses_expose_both_opt_outs_defaulting_closed(self) -> None:
        from pyrxd.glyph.builder import FtAirdropParams, FtTransferParams, TransferParams

        for params_cls in (FtTransferParams, FtAirdropParams, TransferParams):
            fields = params_cls.__dataclass_fields__
            for name in ("allow_overpay", "allow_below_relay_floor"):
                assert name in fields, f"{params_cls.__name__}.{name}"
                # Defaulting closed is the whole safety property: a params object built
                # without mentioning fees must not carry an opt-out the caller never asked
                # for. Both of these skip a fund-safety refusal.
                assert fields[name].default is False, f"{params_cls.__name__}.{name} default"


class TestTheSubFloorOptOutReachesTransfers:
    """#458. A MINT could accept a sub-floor rate; a TRANSFER on the same chain could not.

    ``relay_floor_photons_per_byte`` is a fixed MAINNET constant, so on a regtest node —
    whose floor really is a tenth of it, per
    ``docs/solutions/integration-issues/regtest-node-inherited-a-tenth-of-mainnets-relay-floor.md``
    — the transfer refusal was the guard rejecting work valid on the caller's own chain,
    not the chain rejecting it. A guard that refuses valid work is a bug.
    """

    REGTEST_RATE = 1_000  # a tenth of the mainnet floor

    def test_the_ft_gate_refuses_by_default_and_accepts_with_the_opt_out(self) -> None:
        from pyrxd.glyph.ft import _check_fee_rate

        with pytest.raises((ValueError, ValidationError)):
            _check_fee_rate(self.REGTEST_RATE)
        _check_fee_rate(self.REGTEST_RATE, allow_below_relay_floor=True)  # must not raise

    def test_the_opt_out_does_not_widen_the_ceiling(self) -> None:
        """The property that makes two flags necessary rather than one.

        Above the ceiling the overpay is already gone by the time anything downstream
        could notice; below the floor nothing is spent. A single flag covering both
        would hand back the 1000x overpay this module exists to refuse.
        """
        from pyrxd.glyph.ft import _check_fee_rate

        with pytest.raises((ValueError, ValidationError), match="ceiling"):
            _check_fee_rate(10_000_000, allow_below_relay_floor=True)

    def test_the_default_stays_closed_on_every_public_transfer_entry_point(self) -> None:
        """A caller who never mentions fees must not inherit an opt-out."""
        import inspect

        from pyrxd.glyph.transfer import build_ft_transfer, build_nft_transfer

        for fn in (build_ft_transfer, build_nft_transfer):
            param = inspect.signature(fn).parameters["allow_below_relay_floor"]
            assert param.default is False, fn.__name__

    def test_the_client_forwards_its_constructor_flag_to_both_transfer_paths(self) -> None:
        """The gap that made this a real bug rather than a missing kwarg.

        ``GlyphClient(fee_rate=<sub-floor>, allow_below_relay_floor=True)`` constructed
        happily — the constructor gate lets a transfer-only client through — and then the
        build path refused with no way to say what the constructor had already said.
        """
        import inspect

        from pyrxd.glyph.client import GlyphClient

        for name in ("build_ft_transfer", "build_nft_transfer"):
            src = inspect.getsource(getattr(GlyphClient, name))
            assert "allow_below_relay_floor=self._allow_below_relay_floor" in src, name

    def test_the_client_docstring_no_longer_says_transfers_refuse(self) -> None:
        """It documented the limitation as deliberate; leaving that in place would send a
        reader looking for an escape hatch they now have."""
        from pyrxd.glyph.client import GlyphClient

        doc = " ".join((GlyphClient.__init__.__doc__ or "").split())
        assert "Transfers still refuse a sub-floor rate" not in doc
