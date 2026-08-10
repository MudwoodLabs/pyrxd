"""Tests for FT conservation + transfer — offline, no network calls.

Mirrors the shim/mock pattern in ``tests/test_glyph_transfer.py`` so the
full signing pipeline can be exercised against synthetic UTXOs.

The fixtures build UTXOs the way the chain does — ``ft_amount == value``,
because an FT's quantity IS its output's photons — and fund the fee from a
separate plain-RXD input. The previous fixtures set ``value`` to a fixed
5,000,000 regardless of ``ft_amount``, a shape that cannot exist on chain, and
that is precisely why the transfer builder's fund-loss bug survived: every test
exercised the one input shape the author had in mind.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph.builder import (
    FtTransferParams,
    FtTransferResult,
    FtUtxo,
    GlyphBuilder,
)
from pyrxd.glyph.ft import AirdropFunding, FtUtxoSet
from pyrxd.glyph.script import (
    build_ft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
    is_ft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Keys are GENERATED, never written down. `PrivateKey()` draws from the
# library's own CSPRNG; a hard-coded low-entropy test key in this repo was once
# swept on a live chain by a scanning bot, so no test may introduce another.
_ALICE = PrivateKey()
_FUNDER = PrivateKey()
_BOB_PKH = PrivateKey().public_key().hash160()
_CHARLIE_PKH = PrivateKey().public_key().hash160()

# Token's minting ref (synthetic).
_REF_TXID = "cd" * 32  # 64 hex chars
_REF_VOUT = 0

# Plain-RXD funding for the fee. A 1-FT-input transfer is ~510 bytes, so at the
# 10,000 photons/byte floor the fee is ~5.1M; 50M leaves room for the
# multi-input and higher-fee-rate cases without re-tuning every test.
_FUNDING_VALUE = 50_000_000


def _alice_key() -> PrivateKey:
    return _ALICE


def _alice_pkh() -> bytes:
    return _ALICE.public_key().hash160()


def _token_ref() -> GlyphRef:
    return GlyphRef(txid=Txid(_REF_TXID), vout=_REF_VOUT)


def _ft_script_for(pkh: bytes, ref: GlyphRef | None = None) -> bytes:
    """Build a 75-byte FT locking script owned by ``pkh`` for the given ref."""
    return build_ft_locking_script(Hex20(pkh), ref or _token_ref())


def _make_utxo(
    ft_amount: int,
    *,
    txid_byte: int = 0xA0,
    vout: int = 0,
    value: int | None = None,
    owner_pkh: bytes | None = None,
    ref: GlyphRef | None = None,
) -> FtUtxo:
    """Build a synthetic FT UTXO. ``txid_byte`` seeds a unique txid.

    ``value`` defaults to ``ft_amount`` — the only relationship that exists on
    chain. Pass it explicitly to construct an impossible UTXO on purpose.
    """
    return FtUtxo(
        txid=bytes([txid_byte]).hex() * 32,  # 64-hex txid (all the same byte)
        vout=vout,
        value=ft_amount if value is None else value,
        ft_amount=ft_amount,
        ft_script=_ft_script_for(owner_pkh or _alice_pkh(), ref),
    )


def _funding(value: int = _FUNDING_VALUE, *, txid_byte: int = 0xF0, vout: int = 0) -> AirdropFunding:
    """A plain-P2PKH RXD UTXO that pays the transfer fee."""
    return AirdropFunding(
        txid=bytes([txid_byte]).hex() * 32,
        vout=vout,
        value=value,
        private_key=_FUNDER,
    )


def _ft_outputs(result) -> list:
    """The transaction outputs that carry the token (75-byte FT locks)."""
    return [o for o in result.tx.outputs if is_ft_script(o.locking_script.serialize().hex())]


# ---------------------------------------------------------------------------
# FtUtxoSet.total / .select
# ---------------------------------------------------------------------------


class TestTotal:
    def test_total_empty(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[])
        assert s.total() == 0

    def test_total_single(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(100)])
        assert s.total() == 100

    def test_total_multiple(self):
        utxos = [
            _make_utxo(100, txid_byte=0x01),
            _make_utxo(50, txid_byte=0x02),
            _make_utxo(25, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        assert s.total() == 175


class TestSelect:
    def test_exact_match(self):
        utxos = [_make_utxo(100, txid_byte=0x01), _make_utxo(50, txid_byte=0x02)]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(100)
        # Greedy descending — one UTXO of 100 suffices.
        assert len(selected) == 1
        assert selected[0].ft_amount == 100

    def test_partial_greedy_picks_minimum(self):
        # Amounts: 100, 50, 25. Want 60. Greedy picks 100 (one UTXO).
        utxos = [
            _make_utxo(100, txid_byte=0x01),
            _make_utxo(50, txid_byte=0x02),
            _make_utxo(25, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(60)
        assert len(selected) == 1
        assert selected[0].ft_amount == 100

    def test_requires_multiple_inputs(self):
        # Amounts: 30, 25, 20. Want 60. Greedy picks 30 + 25 = 55 (not enough),
        # so +20 → 75 covers it. Three UTXOs.
        utxos = [
            _make_utxo(30, txid_byte=0x01),
            _make_utxo(25, txid_byte=0x02),
            _make_utxo(20, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(60)
        assert len(selected) == 3
        assert sum(u.ft_amount for u in selected) == 75

    def test_insufficient_total_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(10)])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.select(11)

    def test_empty_set_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[])
        with pytest.raises(ValueError, match="Insufficient FT balance"):
            s.select(1)

    def test_zero_amount_raises(self):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(10)])
        with pytest.raises(ValueError, match="must be > 0"):
            s.select(0)


# ---------------------------------------------------------------------------
# The recipient gets exactly `amount` — the A1 regression surface
# ---------------------------------------------------------------------------


class TestRecipientAmountIsExact:
    """``build_transfer_tx`` must deliver ``amount`` units, never an RXD figure.

    History: the builder sized the recipient output as
    ``rxd_in_total - fee - change_alloc``. On a 50,000,000-unit UTXO an
    ``amount=250`` transfer delivered 46,739,454 units — the sender's whole
    balance. A later patch guarded ``value == ft_amount`` and left the
    expression alone, so the same call at ``value == ft_amount ± 1`` still
    delivered ~46.7 million. These tests pin the property, not the shapes.
    """

    _SHAPES = [
        (1, 1),
        (2, 1),
        (100, 40),
        (100, 100),
        (546, 545),
        (547, 546),
        (1_000, 1),
        (50_000_000, 250),
        (50_000_000, 49_999_999),
        (50_000_000, 50_000_000),
        (2**32, 1),
        (2**32 + 1, 2**32),
        (2**40, 12_345),
    ]

    @pytest.mark.parametrize(("ft_amount", "amount"), _SHAPES)
    def test_recipient_receives_exactly_amount(self, ft_amount: int, amount: int):
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(ft_amount)])
        result = s.build_transfer_tx(
            amount=amount,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        ft_outs = _ft_outputs(result)
        assert ft_outs[0].locking_script.serialize() == result.new_ft_script
        assert ft_outs[0].satoshis == amount

    @pytest.mark.parametrize(("ft_amount", "amount"), _SHAPES)
    def test_conservation_ft_in_equals_ft_out(self, ft_amount: int, amount: int):
        """sum(ft_in) == sum(ft_out): nothing minted, nothing burned."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(ft_amount)])
        result = s.build_transfer_tx(
            amount=amount,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert sum(o.satoshis for o in _ft_outputs(result)) == ft_amount

    @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        ft_amount=st.integers(min_value=1, max_value=2**45),
        frac=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        fee_rate=st.integers(min_value=10_000, max_value=40_000),
    )
    def test_property_amount_and_conservation_hold(self, ft_amount: int, frac: float, fee_rate: int):
        amount = max(1, min(ft_amount, int(ft_amount * frac) or 1))
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(ft_amount)])
        result = s.build_transfer_tx(
            amount=amount,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=fee_rate,
            funding=[_funding(_FUNDING_VALUE * 4)],
        )
        ft_outs = _ft_outputs(result)
        assert ft_outs[0].satoshis == amount
        assert sum(o.satoshis for o in ft_outs) == ft_amount

    def test_recipient_value_does_not_depend_on_the_rxd_budget(self):
        """Differential: the delivered quantity is a function of ``amount`` alone.

        Same token inputs, wildly different fee rates and funding sizes. If any
        part of the recipient output were still derived from the RXD budget —
        the shape of the original bug — these would disagree.
        """
        delivered = set()
        for fee_rate, fund_value in [
            (10_000, 20_000_000),
            (10_000, 900_000_000),
            (37_000, 900_000_000),
            (10_001, 20_500_000),
        ]:
            s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(50_000_000)])
            result = s.build_transfer_tx(
                amount=250,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                fee_rate=fee_rate,
                funding=[_funding(fund_value)],
            )
            ft_outs = _ft_outputs(result)
            delivered.add((ft_outs[0].satoshis, ft_outs[1].satoshis))
        assert delivered == {(250, 49_999_750)}

    def test_original_fund_loss_shape_is_correct_now(self):
        """The exact reported case: 50,000,000 units held, 250 requested."""
        s = FtUtxoSet(ref=_token_ref(), utxos=[_make_utxo(50_000_000)])
        result = s.build_transfer_tx(
            amount=250,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        ft_outs = _ft_outputs(result)
        assert [o.satoshis for o in ft_outs] == [250, 49_999_750]
        assert ft_outs[0].satoshis != 46_739_454  # the number the bug produced

    @pytest.mark.parametrize("delta", [-1_000_000, -1, 1, 1_000_000])
    def test_impossible_value_ft_amount_mismatch_fails_closed(self, delta: int):
        """``value != ft_amount`` cannot exist on chain, in EITHER direction.

        ``ft_amount > value`` would materialise more of the ref than the inputs
        carry and consensus rejects it; ``ft_amount < value`` means the caller
        built ``FtUtxo`` from the wrong field and the surplus photons would be
        burned. Both refuse rather than guess which number the caller meant.
        This is a backstop: the exactness above does not depend on it.
        """
        utxo = _make_utxo(50_000_000, value=50_000_000 + delta)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValidationError, match="value.*ft_amount|ft_amount.*value"):
            s.build_transfer_tx(
                amount=250,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                funding=[_funding()],
            )


# ---------------------------------------------------------------------------
# Conservation
# ---------------------------------------------------------------------------


class TestConservation:
    def test_exact_amount_no_change(self):
        """Transfer exactly the full input ft_amount — no FT change output."""
        utxo = _make_utxo(ft_amount=100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is None
        assert len(_ft_outputs(result)) == 1

    def test_change_case_partial_amount(self):
        """Transfer less than total — change output must exist."""
        utxo = _make_utxo(ft_amount=100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is not None
        assert len(_ft_outputs(result)) == 2

    def test_conservation_ft_in_equals_ft_out(self):
        """sum(input ft) == amount + ft_change (always, by math)."""
        utxos = [
            _make_utxo(80, txid_byte=0x01),
            _make_utxo(40, txid_byte=0x02),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        selected = s.select(90)
        ft_in = sum(u.ft_amount for u in selected)
        amount = 90
        ft_change = ft_in - amount
        result = s.build_transfer_tx(
            amount=amount,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert ft_in == amount + ft_change
        # Change output present iff there is leftover FT.
        assert (result.change_ft_script is not None) == (ft_change > 0)
        # …and the outputs really carry those numbers.
        assert [o.satoshis for o in _ft_outputs(result)] == [amount, ft_change]


# ---------------------------------------------------------------------------
# Output-script structural invariants
# ---------------------------------------------------------------------------


class TestOutputScripts:
    def test_transfer_output_is_ft_script(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        # Classifier passes => script matches the canonical FT layout.
        assert is_ft_script(result.new_ft_script.hex())
        # 0xd0 lives at offset 26 (OP_PUSHINPUTREF) inside the 75-byte layout.
        assert result.new_ft_script[26] == 0xD0
        assert len(result.new_ft_script) == 75

    def test_change_output_is_ft_script_when_present(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=30,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is not None
        assert is_ft_script(result.change_ft_script.hex())
        assert result.change_ft_script[26] == 0xD0
        assert len(result.change_ft_script) == 75

    def test_no_change_output_when_exact_amount(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is None
        assert len(_ft_outputs(result)) == 1

    def test_transfer_output_locked_to_new_owner(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        pkh_in_script = extract_owner_pkh_from_ft_script(result.new_ft_script)
        assert bytes(pkh_in_script) == _BOB_PKH

    def test_change_output_locked_to_sender_by_default(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is not None
        pkh_in_script = extract_owner_pkh_from_ft_script(result.change_ft_script)
        assert bytes(pkh_in_script) == _alice_pkh()

    def test_change_output_locked_to_custom_pkh(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            change_pkh=Hex20(_CHARLIE_PKH),
            funding=[_funding()],
        )
        assert result.change_ft_script is not None
        pkh_in_script = extract_owner_pkh_from_ft_script(result.change_ft_script)
        assert bytes(pkh_in_script) == _CHARLIE_PKH


# ---------------------------------------------------------------------------
# Ref preservation
# ---------------------------------------------------------------------------


class TestRefPreservation:
    def test_ref_preserved_in_transfer_output(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert extract_ref_from_ft_script(result.new_ft_script) == _token_ref()
        assert result.ref == _token_ref()

    def test_ref_preserved_in_change_output(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.change_ft_script is not None
        assert extract_ref_from_ft_script(result.change_ft_script) == _token_ref()

    def test_mismatched_input_ref_raises(self):
        """A UTXO carrying a different ref in its script is refused at construction."""
        other_ref = GlyphRef(txid=Txid("ff" * 32), vout=7)
        utxo_wrong_ref = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=100,
            ft_amount=100,
            ft_script=_ft_script_for(_alice_pkh(), ref=other_ref),
        )
        with pytest.raises(ValidationError, match="differs from the set's ref"):
            FtUtxoSet(ref=_token_ref(), utxos=[utxo_wrong_ref])

    def test_p2pkh_script_rejected_at_construction(self):
        """A plain P2PKH script (not an FT lock) must be refused — the network would
        otherwise reject the broadcast with `bad-txns-inputs-outputs-invalid-
        transaction-reference-operations` because the output materialises a ref that
        no input carries."""
        plain_p2pkh = b"\x76\xa9\x14" + _alice_pkh() + b"\x88\xac"  # 25 bytes, not FT
        utxo = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=100,
            ft_amount=100,
            ft_script=plain_p2pkh,
        )
        with pytest.raises(ValidationError, match="not a valid 75-byte FT locking script"):
            FtUtxoSet(ref=_token_ref(), utxos=[utxo])

    def test_non_bytes_ft_script_rejected(self):
        """A hex-string ft_script (instead of bytes) is rejected with a clear type error."""
        utxo = FtUtxo(
            txid="aa" * 32,
            vout=0,
            value=100,
            ft_amount=100,
            ft_script=_ft_script_for(_alice_pkh()).hex(),  # type: ignore[arg-type]
        )
        with pytest.raises(ValidationError, match="ft_script must be bytes"):
            FtUtxoSet(ref=_token_ref(), utxos=[utxo])


# ---------------------------------------------------------------------------
# Fee and RXD accounting
# ---------------------------------------------------------------------------


class TestFee:
    def test_fee_is_positive(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.fee > 0

    def test_fee_comes_from_funding_not_from_the_token(self):
        """The token side contributes nothing to the fee — it is all units."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert result.fee < _FUNDING_VALUE
        assert sum(o.satoshis for o in _ft_outputs(result)) == 100

    def test_fee_clears_size_times_rate(self):
        """Radiant has no RBF and no CPFP: a sub-floor fee is unfixable.

        ``>=`` not ``==``: a sub-dust RXD remainder is folded into the fee
        rather than emitted as an output, which can only raise what is paid.
        """
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=10_000,
            funding=[_funding()],
        )
        assert result.fee >= result.tx.byte_length() * 10_000

    def test_higher_fee_rate_produces_higher_fee(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        low = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=10_000,
            funding=[_funding()],
        )
        high = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            fee_rate=15_000,
            funding=[_funding()],
        )
        assert high.fee > low.fee

    def test_sub_floor_fee_rate_refused(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValueError, match="relay floor|photons/byte"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                fee_rate=1,
                funding=[_funding()],
            )

    def test_no_funding_raises(self):
        """The token cannot pay its own fee: every photon on it is a unit."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValueError, match="Insufficient RXD"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
            )

    def test_insufficient_funding_raises(self):
        """Funding below the fee must raise, not silently underpay."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        with pytest.raises(ValueError, match="Insufficient RXD"):
            s.build_transfer_tx(
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                funding=[_funding(1_000)],
            )

    def test_rxd_change_is_plain_p2pkh_not_a_token_output(self):
        """Leftover funding comes back as plain RXD — never as extra units."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        ft_outs = _ft_outputs(result)
        assert [o.satoshis for o in ft_outs] == [40, 60]
        rxd_change = [o for o in result.tx.outputs if o not in ft_outs]
        assert len(rxd_change) == 1
        spk = rxd_change[0].locking_script.serialize()
        assert len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac"


# ---------------------------------------------------------------------------
# Two-pass signing correctness
# ---------------------------------------------------------------------------


class TestTwoPassSigning:
    def test_final_signature_over_final_outputs(self):
        """Classic two-pass trap: if we leaked the trial signature, it would
        commit to trial output values. Re-sign an independent tx built with
        the same final outputs — signatures must match byte-for-byte.
        """
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        utxo = _make_utxo(100)
        fund = _funding()
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[fund],
        )

        # Rebuild an equivalent tx from scratch with the *same* final output
        # values and re-sign. Same preimage ⇒ identical unlocking_script bytes.
        padding = TransactionOutput(Script(b""), 0)
        shim_outs = [padding] * utxo.vout + [TransactionOutput(Script(bytes(utxo.ft_script)), utxo.value)]
        src = Transaction(tx_inputs=[], tx_outputs=shim_outs)
        src.txid = lambda: utxo.txid  # type: ignore[method-assign]

        inp = TransactionInput(
            source_transaction=src,
            source_txid=utxo.txid,
            source_output_index=utxo.vout,
            unlocking_script_template=P2PKH().unlock(_alice_key()),
        )
        inp.satoshis = utxo.value
        inp.locking_script = Script(bytes(utxo.ft_script))

        fund_spk = P2PKH().lock(fund.private_key.public_key().hash160())
        fund_shim = [padding] * fund.vout + [TransactionOutput(fund_spk, fund.value)]
        fund_src = Transaction(tx_inputs=[], tx_outputs=fund_shim)
        fund_src.txid = lambda: fund.txid  # type: ignore[method-assign]
        fund_inp = TransactionInput(
            source_transaction=fund_src,
            source_txid=fund.txid,
            source_output_index=fund.vout,
            unlocking_script_template=P2PKH().unlock(fund.private_key),
        )
        fund_inp.satoshis = fund.value
        fund_inp.locking_script = fund_spk

        outs = [TransactionOutput(o.locking_script, o.satoshis) for o in result.tx.outputs]
        independent = Transaction(tx_inputs=[inp, fund_inp], tx_outputs=outs)
        independent.sign()

        assert result.tx.inputs[0].unlocking_script.serialize() == independent.inputs[0].unlocking_script.serialize()

    def test_tx_serializes_cleanly(self):
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        raw = result.tx.serialize()
        assert len(raw) > 0
        assert result.tx.byte_length() == len(raw)


# ---------------------------------------------------------------------------
# Multiple-input consolidation & single-input edge cases
# ---------------------------------------------------------------------------


class TestMultipleInputs:
    def test_multiple_inputs_consolidated(self):
        """Three UTXOs (30 + 25 + 20 = 75), transfer 60 → all three spent."""
        utxos = [
            _make_utxo(30, txid_byte=0x01),
            _make_utxo(25, txid_byte=0x02),
            _make_utxo(20, txid_byte=0x03),
        ]
        s = FtUtxoSet(ref=_token_ref(), utxos=utxos)
        result = s.build_transfer_tx(
            amount=60,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        # 3 FT inputs + 1 funding input.
        assert len(result.tx.inputs) == 4
        # 75 in - 60 out = 15 change → change output present.
        assert result.change_ft_script is not None
        assert [o.satoshis for o in _ft_outputs(result)] == [60, 15]

    def test_single_input_exact_amount(self):
        """Single input, exact amount — no FT change."""
        utxo = _make_utxo(100)
        s = FtUtxoSet(ref=_token_ref(), utxos=[utxo])
        result = s.build_transfer_tx(
            amount=100,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert len(result.tx.inputs) == 2  # FT input + funding input
        assert len(_ft_outputs(result)) == 1
        assert result.change_ft_script is None


# ---------------------------------------------------------------------------
# GlyphBuilder delegation
# ---------------------------------------------------------------------------


class TestGlyphBuilderDelegates:
    def test_build_ft_transfer_tx_returns_ft_transfer_result(self):
        utxo = _make_utxo(100)
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[utxo],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        result = GlyphBuilder().build_ft_transfer_tx(params)
        assert isinstance(result, FtTransferResult)

    def test_delegation_matches_direct_call(self):
        """Builder path and direct FtUtxoSet call must produce the same fee,
        scripts, and number of inputs/outputs."""
        utxo = _make_utxo(100)
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[utxo],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        via_builder = GlyphBuilder().build_ft_transfer_tx(params)
        via_direct = FtUtxoSet(ref=_token_ref(), utxos=[utxo]).build_transfer_tx(
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
            funding=[_funding()],
        )
        assert via_builder.fee == via_direct.fee
        assert via_builder.new_ft_script == via_direct.new_ft_script
        assert via_builder.change_ft_script == via_direct.change_ft_script
        assert len(via_builder.tx.inputs) == len(via_direct.tx.inputs)
        assert len(via_builder.tx.outputs) == len(via_direct.tx.outputs)

    def test_transfer_matches_a_one_recipient_airdrop(self):
        """Differential: the transfer path IS the airdrop path, so a
        single-recipient airdrop must produce a byte-identical transaction."""
        from pyrxd.glyph.builder import FtAirdropParams
        from pyrxd.glyph.ft import AirdropRecipient

        utxo = _make_utxo(100)
        transfer = GlyphBuilder().build_ft_transfer_tx(
            FtTransferParams(
                ref=_token_ref(),
                utxos=[utxo],
                amount=40,
                new_owner_pkh=Hex20(_BOB_PKH),
                private_key=_alice_key(),
                funding=[_funding()],
            )
        )
        airdrop = GlyphBuilder().build_ft_airdrop_tx(
            FtAirdropParams(
                ref=_token_ref(),
                utxos=[utxo],
                recipients=[AirdropRecipient(pkh=Hex20(_BOB_PKH), amount=40)],
                private_key=_alice_key(),
                funding=[_funding()],
            )
        )
        assert transfer.tx.serialize() == airdrop.tx.serialize()
        assert transfer.fee == airdrop.fee


# ---------------------------------------------------------------------------
# FtTransferParams defaults
# ---------------------------------------------------------------------------


class TestFtTransferParamsDefaults:
    def test_default_fee_rate_is_10_000(self):
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[_make_utxo(100)],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert params.fee_rate == 10_000

    def test_default_change_pkh_is_none(self):
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[_make_utxo(100)],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert params.change_pkh is None

    def test_default_funding_is_empty(self):
        params = FtTransferParams(
            ref=_token_ref(),
            utxos=[_make_utxo(100)],
            amount=40,
            new_owner_pkh=Hex20(_BOB_PKH),
            private_key=_alice_key(),
        )
        assert params.funding == []
