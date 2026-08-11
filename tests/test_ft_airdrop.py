"""Multi-recipient FT airdrop — offline, no network calls.

Two properties are under test, and the second is the one that took a correction
to get right.

**Conservation.** N recipients must not become a way around it.
``FtUtxoSet.build_airdrop_tx`` reaches the chain through the same two calls
``build_transfer_tx`` does — ``select`` for "do I hold enough" and the
``ft_in - out == change`` identity for "did I create units" — so the assertions
below re-derive unit totals from the built transaction's serialised scripts
rather than trusting the builder's own bookkeeping.

**An FT output's value IS its unit count.** 1 photon = 1 token unit on Radiant
(``docs/concepts/radiant-fts-are-on-chain.md``), so a recipient output's
``satoshis`` is not a free parameter — it must equal the units requested, and
the fee therefore cannot be taken out of it without silently burning tokens.
That is why the UTXO fixtures here set ``value == ft_amount`` (what a real
holding looks like) and pass a separate plain-RXD ``AirdropFunding`` input.

Mirrors the shim/mock pattern in ``tests/test_ft_transfer.py``.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import FtAirdropParams, FtTransferResult, GlyphBuilder
from pyrxd.glyph.ft import (
    DUST_LIMIT,
    MAX_AIRDROP_RECIPIENTS,
    MIN_FEE_RATE,
    AirdropFunding,
    AirdropRecipient,
    FtUtxo,
    FtUtxoSet,
)
from pyrxd.glyph.script import (
    build_ft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
    is_ft_script,
)
from pyrxd.glyph.types import GlyphRef, GlyphRoyalty
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

_ALICE_KEY_INT = 0x1111111111111111111111111111111111111111111111111111111111111111
_FUNDER_KEY_INT = 0x2222222222222222222222222222222222222222222222222222222222222222
_BOB_PKH = bytes(range(20, 40))
_CHARLIE_PKH = bytes(range(40, 60))
_DANA_PKH = bytes(range(60, 80))

_REF_TXID = "cd" * 32
# A 3-in/5-out airdrop at the 10_000 ph/B floor costs well under 0.1 RXD; 0.5 RXD
# of funding leaves headroom for every case here.
_FUNDING_VALUE = 50_000_000


def _alice_key() -> PrivateKey:
    return PrivateKey(_ALICE_KEY_INT)


def _funder_key() -> PrivateKey:
    return PrivateKey(_FUNDER_KEY_INT)


def _alice_pkh() -> bytes:
    return _alice_key().public_key().hash160()


def _token_ref() -> GlyphRef:
    return GlyphRef(txid=Txid(_REF_TXID), vout=0)


def _make_utxo(ft_amount: int, *, txid_byte: int = 0xA0, vout: int = 0) -> FtUtxo:
    """A realistic FT holding: photon value == unit count."""
    return FtUtxo(
        txid=bytes([txid_byte]).hex() * 32,
        vout=vout,
        value=ft_amount,
        ft_amount=ft_amount,
        ft_script=build_ft_locking_script(Hex20(_alice_pkh()), _token_ref()),
    )


def _funding(value: int = _FUNDING_VALUE, *, txid_byte: int = 0xF0) -> AirdropFunding:
    return AirdropFunding(
        txid=bytes([txid_byte]).hex() * 32,
        vout=0,
        value=value,
        private_key=_funder_key(),
    )


def _recipients(*pairs: tuple[bytes, int]) -> list[AirdropRecipient]:
    return [AirdropRecipient(pkh=Hex20(pkh), amount=amount) for pkh, amount in pairs]


def _ft_amounts_out(result) -> dict[bytes, int]:
    """Owner PKH -> FT units, re-derived from the transaction's own scripts."""
    out: dict[bytes, int] = {}
    for o in result.tx.outputs:
        spk = o.locking_script.serialize()
        if not is_ft_script(spk.hex()):
            continue
        pkh = bytes(extract_owner_pkh_from_ft_script(spk))
        out[pkh] = out.get(pkh, 0) + o.satoshis
    return out


class TestConservation:
    def test_units_in_equal_units_out(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 250), (_CHARLIE_PKH, 100), (_DANA_PKH, 50)),
            _alice_key(),
            funding=[_funding()],
        )
        amounts = _ft_amounts_out(result)
        assert amounts[_BOB_PKH] == 250
        assert amounts[_CHARLIE_PKH] == 100
        assert amounts[_DANA_PKH] == 50
        assert amounts[_alice_pkh()] == 600  # change
        assert sum(amounts.values()) == 1_000  # nothing minted, nothing burned

    def test_no_units_are_burned_to_pay_the_fee(self):
        """The whole reason `funding` exists.

        If the fee came off a token output, the airdropped total would be short
        by the fee — silently, and unrecoverably once broadcast.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(_recipients((_BOB_PKH, 400)), _alice_key(), funding=[_funding()])
        assert sum(_ft_amounts_out(result).values()) == 1_000
        assert result.fee > 0
        # The fee came out of the funding input, not the token.
        assert result.rxd_change_photons == _FUNDING_VALUE - result.fee

    def test_exact_spend_emits_no_ft_change(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 600), (_CHARLIE_PKH, 400)),
            _alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is None
        assert _alice_pkh() not in _ft_amounts_out(result)
        assert sum(_ft_amounts_out(result).values()) == 1_000

    def test_over_request_refused_by_the_same_select_path(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.build_airdrop_tx(
                _recipients((_BOB_PKH, 60), (_CHARLIE_PKH, 60)),
                _alice_key(),
                funding=[_funding()],
            )

    def test_spans_multiple_input_utxos(self):
        utxos = [_make_utxo(400, txid_byte=0x01), _make_utxo(300, txid_byte=0x02), _make_utxo(200, txid_byte=0x03)]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 500), (_CHARLIE_PKH, 150)),
            _alice_key(),
            funding=[_funding()],
        )
        # Greedy descending picks 400 + 300 = 700 to cover 650.
        assert sum(_ft_amounts_out(result).values()) == 700
        assert _ft_amounts_out(result)[_alice_pkh()] == 50

    def test_every_recipient_output_carries_the_token_ref(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10), (_CHARLIE_PKH, 20)),
            _alice_key(),
            funding=[_funding()],
        )
        for spk in result.recipient_scripts:
            assert is_ft_script(spk.hex())
            assert extract_ref_from_ft_script(spk) == _token_ref()


class TestOutputLayout:
    def test_recipient_order_is_preserved(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        recips = _recipients((_BOB_PKH, 10), (_CHARLIE_PKH, 20), (_DANA_PKH, 30))
        result = s.build_airdrop_tx(recips, _alice_key(), funding=[_funding()])
        for i, r in enumerate(recips):
            spk = result.tx.outputs[i].locking_script.serialize()
            assert bytes(extract_owner_pkh_from_ft_script(spk)) == bytes(r.pkh)
            assert result.tx.outputs[i].satoshis == r.amount
        assert result.recipients == tuple(recips)

    def test_signature_commits_to_the_final_outputs(self):
        """The trial-pass signature must not survive into the final tx."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding()])
        for inp in result.tx.inputs:
            assert inp.unlocking_script is not None
        # A stale trial signature would have committed to a dust_limit-valued
        # RXD change output; the final one carries the real remainder.
        assert result.tx.outputs[-1].satoshis > DUST_LIMIT

    def test_reported_fee_is_the_real_in_minus_out(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10), (_CHARLIE_PKH, 20)),
            _alice_key(),
            funding=[_funding()],
        )
        value_in = 1_000 + _FUNDING_VALUE
        value_out = sum(o.satoshis for o in result.tx.outputs)
        assert result.fee == value_in - value_out
        assert result.fee >= result.tx.byte_length() * MIN_FEE_RATE

    def test_sub_dust_remainder_is_folded_into_the_fee_not_emitted(self):
        """Folding can only RAISE the fee, so the tx stays relayable.

        That matters because Radiant has no RBF and no CPFP: an under-fee'd
        transaction cannot be fixed, it just holds its inputs for 8 hours.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        probe = s.build_airdrop_tx(_recipients((_BOB_PKH, 1_000)), _alice_key(), funding=[_funding()])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 1_000)),
            _alice_key(),
            funding=[_funding()],
            dust_limit=probe.rxd_change_photons + 1_000_000,
        )
        assert result.rxd_change_photons == 0
        assert len(result.tx.outputs) == 1
        assert result.fee > result.tx.byte_length() * MIN_FEE_RATE

    def test_multiple_funding_inputs_are_summed(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding(30_000_000, txid_byte=0xF1), _funding(30_000_000, txid_byte=0xF2)],
        )
        assert result.rxd_change_photons == 60_000_000 - result.fee


class TestInputValidation:
    def test_value_and_ft_amount_must_agree(self):
        """On chain they are the same number; a mismatch is refused at construction.

        `ft_amount > value` materialises more of the ref than the inputs carry
        (consensus rejects it); `ft_amount < value` sends the surplus photons to
        change or fee, which for a real token means burning units.
        """
        with pytest.raises(ValidationError, match="cannot exist on chain"):
            FtUtxo(
                txid="a0" * 32,
                vout=0,
                value=50_000_000,
                ft_amount=1_000,
                ft_script=build_ft_locking_script(Hex20(_alice_pkh()), _token_ref()),
            )

    def test_airdrop_backstop_still_fires_if_the_type_guarantee_is_bypassed(self):
        """DELIBERATELY IMPOSSIBLE FIXTURE — and it has to be, to test this.

        ``FtUtxo.__post_init__`` makes ``value != ft_amount`` unconstructible, so
        the only way to reach ``build_airdrop_tx``'s defence-in-depth check is to
        force the field past the frozen dataclass with ``object.__setattr__``.
        That is the point of this test: the backstop is a tripwire on somebody
        later loosening the type, so it must be exercised through a bypass. Do
        NOT copy this pattern into a test that is not specifically about the
        tripwire — everywhere else, an impossible ``FtUtxo`` is a bug in the test.
        """
        u = FtUtxo.from_output(
            txid="a0" * 32,
            vout=0,
            value=50_000_000,
            ft_script=build_ft_locking_script(Hex20(_alice_pkh()), _token_ref()),
        )
        s = FtUtxoSet(ref=_token_ref(), utxos=[u])
        object.__setattr__(u, "ft_amount", 1_000)  # bypass the frozen type on purpose
        with pytest.raises(ValidationError, match="ft_amount = value"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding()])


class TestRecipientValidation:
    def test_empty_list_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValidationError, match="must not be empty"):
            s.build_airdrop_tx([], _alice_key(), funding=[_funding()])

    def test_duplicate_pkh_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValidationError, match="repeats PKH"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10), (_BOB_PKH, 20)), _alice_key(), funding=[_funding()])

    def test_zero_amount_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValidationError, match="amount must be > 0"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 0)), _alice_key(), funding=[_funding()])

    def test_bool_amount_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValidationError, match="must be an int"):
            s.build_airdrop_tx(
                [AirdropRecipient(pkh=Hex20(_BOB_PKH), amount=True)],
                _alice_key(),
                funding=[_funding()],
            )

    def test_short_pkh_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        with pytest.raises(ValidationError, match="must be 20 bytes"):
            s.build_airdrop_tx([AirdropRecipient(pkh=b"\x01" * 19, amount=1)], _alice_key(), funding=[_funding()])

    def test_recipient_cap_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(MAX_AIRDROP_RECIPIENTS + 1)])
        too_many = [
            AirdropRecipient(pkh=Hex20(i.to_bytes(20, "big")), amount=1) for i in range(MAX_AIRDROP_RECIPIENTS + 1)
        ]
        with pytest.raises(ValidationError, match="above pyrxd's guard"):
            s.build_airdrop_tx(too_many, _alice_key(), funding=[_funding()])


class TestFeeFloor:
    def test_below_relay_floor_refused(self):
        """New builder, so it binds to gravity.fee_policy's floor.

        Radiant has no RBF and no CPFP, so an under-fee'd transaction cannot be
        bumped — it holds its inputs until mempool expiry.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="effective relay floor"):
            s.build_airdrop_tx(
                _recipients((_BOB_PKH, 10)),
                _alice_key(),
                funding=[_funding()],
                fee_rate=MIN_FEE_RATE - 1,
            )

    def test_floor_matches_gravity_fee_policy(self):
        from pyrxd.gravity.fee_policy import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

        assert MIN_FEE_RATE == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB // 1000

    def test_at_the_floor_accepted(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            fee_rate=MIN_FEE_RATE,
        )
        assert result.fee > 0

    def test_bool_fee_rate_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="must be an int"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding()], fee_rate=True)

    def test_no_funding_at_all_is_refused_not_silently_burned(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="would burn units"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key())

    def test_insufficient_funding_names_the_shortfall(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="short by"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding(10_000)])


class TestDustLimitIsPolicyNotConsensus:
    def test_a_recipient_may_receive_fewer_units_than_546(self):
        """546 is pyrxd wallet policy; Radiant's dust threshold is 1 photon.

        An FT output's value is a token quantity, so a 546 floor on recipients
        would forbid airdropping 100 units of anything.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(_recipients((_BOB_PKH, 1)), _alice_key(), funding=[_funding()])
        assert result.tx.outputs[0].satoshis == 1

    def test_dust_limit_governs_only_the_rxd_change_fold(self):
        """Raising dust_limit past the remainder folds it into the fee.

        Driven from the remainder the builder actually produced rather than a
        precomputed target: DER signature lengths vary by a byte between runs,
        so any assertion pinned to an exact photon count would be flaky.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        emitted = s.build_airdrop_tx(_recipients((_BOB_PKH, 1_000)), _alice_key(), funding=[_funding()])
        assert emitted.rxd_change_photons > 0
        assert len([o for o in emitted.tx.outputs if len(o.locking_script.serialize()) == 25]) == 1

        folded = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 1_000)),
            _alice_key(),
            funding=[_funding()],
            dust_limit=emitted.rxd_change_photons + 1_000_000,
        )
        assert folded.rxd_change_photons == 0
        assert len(folded.tx.outputs) == 1
        assert folded.fee > emitted.fee

    def test_dust_limit_zero_refused(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="dust_limit must be >= 1"):
            s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding()], dust_limit=0)


class TestRoyalty:
    """An airdrop can carry an advisory royalty. It is never token-side."""

    def _royalty(self, *, enforced: bool = True) -> GlyphRoyalty:
        return GlyphRoyalty(bps=500, address=PrivateKey().public_key().address(), enforced=enforced)

    def test_enforced_royalty_is_paid_by_default(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=self._royalty(),
            sale_price=1_000_000,
        )
        assert len(result.royalty_payouts) == 1
        assert result.royalty_payouts[0].photons == 50_000
        paid = [o for o in result.tx.outputs if o.satoshis == 50_000]
        assert len(paid) == 1
        # Plain P2PKH — carries no ref, so it changes no conservation sum.
        assert len(paid[0].locking_script.serialize()) == 25

    def test_unenforced_royalty_is_not_paid_by_default(self):
        """``enforced`` is the creator's own statement about insisting.

        The builder used to ignore it and pay anyway, spending the *sender's*
        funding photons on a payment the creator did not ask to be insisted on.
        ``enforced`` defaults to ``False`` in every path that builds a
        ``GlyphRoyalty``, so this was the common case, not the corner.
        """
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=self._royalty(enforced=False),
            sale_price=1_000_000,
        )
        assert result.royalty_payouts == ()

    def test_pay_royalty_true_honours_an_advisory_royalty_anyway(self):
        """The override survives: advisory must be able to mean "paid by choice"."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=self._royalty(enforced=False),
            sale_price=1_000_000,
            pay_royalty=True,
        )
        assert [p.photons for p in result.royalty_payouts] == [50_000]

    def test_pay_royalty_false_overrides_an_enforced_royalty(self):
        """Nothing on chain compels the output, so ``False`` still wins."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=self._royalty(enforced=True),
            sale_price=1_000_000,
            pay_royalty=False,
        )
        assert result.royalty_payouts == ()

    def test_an_unbounded_minimum_cannot_drain_the_funding(self):
        """``minimum`` is a free integer chosen by the token's creator.

        Before the cap, ``minimum = 10**15`` on a plain transfer (``sale_price =
        0``) resolved to 10**15 photons payable out of the *sender's* funding
        inputs. It is now bounded by the consideration, which for a transfer is
        nothing.
        """
        r = GlyphRoyalty(
            bps=0,
            address=PrivateKey().public_key().address(),
            enforced=True,
            minimum=10**15,
        )
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=r,
            sale_price=0,
        )
        assert result.royalty_payouts == ()

    def test_minimum_is_capped_at_the_sale_price(self):
        r = GlyphRoyalty(
            bps=100,
            address=PrivateKey().public_key().address(),
            enforced=True,
            minimum=10**15,
        )
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=r,
            sale_price=1_000_000,
        )
        assert [p.photons for p in result.royalty_payouts] == [1_000_000]

    def test_pay_royalty_false_is_the_explicit_opt_out(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=self._royalty(),
            sale_price=1_000_000,
            pay_royalty=False,
        )
        assert result.royalty_payouts == ()

    def test_royalty_comes_out_of_funding_never_out_of_the_token(self):
        r = self._royalty(enforced=True)
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        without = s.build_airdrop_tx(_recipients((_BOB_PKH, 10)), _alice_key(), funding=[_funding()])
        with_r = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 10)),
            _alice_key(),
            funding=[_funding()],
            royalty=r,
            sale_price=1_000_000,
        )
        assert _ft_amounts_out(without) == _ft_amounts_out(with_r)
        assert with_r.rxd_change_photons < without.rxd_change_photons

    def test_royalty_larger_than_the_budget_is_refused_not_silently_dropped(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(1_000)])
        with pytest.raises(ValueError, match="royalty"):
            s.build_airdrop_tx(
                _recipients((_BOB_PKH, 10)),
                _alice_key(),
                funding=[_funding()],
                royalty=self._royalty(),
                sale_price=10_000_000_000,
            )


class TestTransferBuilderIsTheAirdropBuilder:
    """`build_transfer_tx` is a single-recipient `build_airdrop_tx`.

    It used to size the transfer output from the inputs' RXD rather than from
    `amount`, which on a real holding delivered the wrong quantity — measured at
    46,739,454 units for `amount=250` out of a 50,000,000-unit UTXO, i.e. the
    sender's whole balance to someone who asked for 250. A tripwire on
    `value == ft_amount` was added and did not fix it: the same call at
    `value == ft_amount ± 1` still delivered ~46.7 million. Delegating removes
    the expression rather than fencing it off.
    """

    def test_coupled_inputs_send_the_exact_amount(self):
        """The shape the tripwire used to refuse is the shape that must work."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(50_000_000)])
        result = s.build_transfer_tx(
            amount=250,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.tx.outputs[0].satoshis == 250
        assert result.tx.outputs[1].satoshis == 49_999_750

    @pytest.mark.parametrize("delta", [-1, 1])
    def test_decoupled_inputs_are_refused(self, delta: int):
        """`value != ft_amount` cannot exist on chain and is refused either way.

        ``±1`` specifically: these are the deltas that defeated the first
        attempted fix, an ``if value == ft_amount: raise`` guard inside the
        builder. The refusal now happens before an ``FtUtxo`` exists at all, so
        there is no expression left for a near-miss to slip through.
        """
        with pytest.raises(ValidationError, match="ft_amount"):
            FtUtxo(
                txid="a0" * 32,
                vout=0,
                value=50_000_000 + delta,
                ft_amount=50_000_000,
                ft_script=build_ft_locking_script(Hex20(_alice_pkh()), _token_ref()),
            )

    def test_transfer_and_one_recipient_airdrop_are_byte_identical(self):
        """One implementation, so the two cannot drift apart again."""
        utxos = [_make_utxo(50_000_000)]
        transfer = FtUtxoSet(ref=_token_ref(), utxos=utxos).build_transfer_tx(
            amount=250,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        airdrop = FtUtxoSet(ref=_token_ref(), utxos=utxos).build_airdrop_tx(
            _recipients((_BOB_PKH, 250)),
            _alice_key(),
            funding=[_funding()],
        )
        assert transfer.tx.serialize() == airdrop.tx.serialize()

    def test_no_royalty_parameter_exists(self):
        """A royalty has to be funded from RXD, and this builder has none."""
        import inspect

        sig = inspect.signature(FtUtxoSet.build_transfer_tx)
        assert "royalty" not in sig.parameters
        assert not hasattr(FtTransferResult, "royalty_payouts")

    def test_the_airdrop_builder_sends_the_exact_amount(self):
        """The replacement, on the same inputs the transfer builder refuses."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(50_000_000)])
        result = s.build_airdrop_tx(
            _recipients((_BOB_PKH, 250)),
            _alice_key(),
            funding=[_funding()],
        )
        assert result.tx.outputs[0].satoshis == 250
        assert _ft_amounts_out(result)[_alice_pkh()] == 50_000_000 - 250


class TestBuilderDelegation:
    def test_glyph_builder_delegates(self):
        params = FtAirdropParams(
            ref=_token_ref(),
            utxos=[_make_utxo(1_000)],
            recipients=_recipients((_BOB_PKH, 10), (_CHARLIE_PKH, 20)),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        result = GlyphBuilder().build_ft_airdrop_tx(params)
        assert len(result.recipient_scripts) == 2
        assert result.ref == _token_ref()

    def test_lazy_exports_are_registered(self):
        import pyrxd.glyph as g

        assert g.AirdropRecipient is AirdropRecipient
        assert g.AirdropFunding is AirdropFunding
        assert "FtAirdropParams" in g.__all__
        assert "FtAirdropResult" in g.__all__
        assert "royalty_payouts" in g.__all__
