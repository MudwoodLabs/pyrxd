"""``GlyphClient`` construction and the change-survived guard.

The guard tests come in pairs on purpose. A bound that refuses valid work is its own
bug — folding a sub-dust remainder into the fee is correct and must keep working —
so every refusal case here is matched by an honest case that must pass.
"""

from __future__ import annotations

import warnings

import pytest

from pyrxd.constants import DUST_THRESHOLD_PHOTONS
from pyrxd.glyph.client import GlyphClient, TransferReceipt
from pyrxd.glyph.mint import JsonFilePendingStore, UnsafeNullPendingStore
from pyrxd.glyph.transfer import assert_fee_matches_size
from pyrxd.security.errors import ValidationError

FEE_RATE = 10_000
SIZE_BYTES = 300


INPUTS = 2


class _StubTx:
    """``serialize()`` and ``inputs`` are what the guard reads.

    ``serialize()`` returns **bytes**, because that is what
    :meth:`pyrxd.transaction.transaction.Transaction.serialize` returns. It used to
    return a hex string, and that single wrong character of contract hid a shipped
    fund-safety bug: the guard divided the length by two, so the stub and the guard
    agreed with each other while both disagreed with the real ``Transaction``, and
    every honest transfer at a realistic fee rate was refused.
    ``TestTheGuardAgreesWithARealTransaction`` below is the seam that would have
    caught it, and is the reason this stub cannot drift again.
    """

    def __init__(self, size_bytes: int, n_inputs: int = INPUTS) -> None:
        self._raw = b"\x00" * size_bytes
        self.inputs = [object()] * n_inputs

    def serialize(self) -> bytes:
        return self._raw


def _exact_fee(size_bytes: int = SIZE_BYTES) -> int:
    return size_bytes * FEE_RATE


def _allowance(n_inputs: int = INPUTS) -> int:
    """What the guard tolerates: the builders' own sizing slack, then dust.

    Derived here from the same constants rather than hardcoded, so a change to
    ``SIG_SIZE_SLACK_BYTES`` moves the tests with the code instead of silently
    loosening them.
    """
    from pyrxd.fee_sizing import SIG_SIZE_SLACK_BYTES

    return (2 * SIG_SIZE_SLACK_BYTES) * n_inputs * FEE_RATE + DUST_THRESHOLD_PHOTONS


class TestChangeSurvivedGuard:
    def test_exact_fee_passes(self) -> None:
        """The ordinary case: fee is exactly what the size demands."""
        assert_fee_matches_size(_exact_fee(), _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_sub_dust_fold_passes(self) -> None:
        """Folding a sub-dust remainder into the fee is correct, not a burn.

        An output below the dust threshold cannot be economically spent, so the
        builder rolls it into the fee. The guard must not mistake that for a loss.
        """
        excess = DUST_THRESHOLD_PHOTONS - 1
        assert_fee_matches_size(_exact_fee() + excess, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_the_builders_own_sizing_slack_passes(self) -> None:
        """THE case that made this guard refuse 100% of honest builds.

        Every builder fees a TRIAL signing pass plus ``SIG_SIZE_SLACK_BYTES`` per
        input, deliberately, so a longer final signature cannot leave the transaction
        underpaid. That overshoot is bytes x rate — 60,000 photons on two inputs at
        the floor rate — while the dust threshold is 546. Measured over 300 real
        single-recipient FT transfers the overshoot ran 4-9 bytes and every one was
        refused before this allowance existed.
        """
        from pyrxd.fee_sizing import SIG_SIZE_SLACK_BYTES

        designed_in = SIG_SIZE_SLACK_BYTES * INPUTS * FEE_RATE
        assert_fee_matches_size(_exact_fee() + designed_in, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_the_worst_measured_overshoot_passes(self) -> None:
        """9 bytes on two inputs was the worst of 300; the allowance is 12."""
        assert_fee_matches_size(_exact_fee() + 9 * FEE_RATE, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_one_photon_past_the_allowance_is_refused(self) -> None:
        """The boundary, stated exactly rather than left to a magic number."""
        with pytest.raises(ValidationError, match="exceeds what this transaction's size demands"):
            assert_fee_matches_size(
                _exact_fee() + _allowance() + 1,
                _StubTx(SIZE_BYTES),
                fee_rate=FEE_RATE,
            )

    def test_exactly_at_the_allowance_passes(self) -> None:
        """The paired honest side of the boundary above."""
        assert_fee_matches_size(_exact_fee() + _allowance(), _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)

    def test_large_burn_refused_and_reports_the_amount(self) -> None:
        """The failure mode worth refusing: a fee wildly past what the size demands.

        23.3 RXD is 2,330,000,000 photons — 233,000 bytes' worth at the floor rate, against an allowance of
        12 — so widening the tolerance for sizing slack costs nothing here.
        """
        burn = 2_330_000_000
        with pytest.raises(ValidationError) as exc:
            assert_fee_matches_size(_exact_fee() + burn, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)
        assert f"{burn:,}" in str(exc.value)

    def test_the_allowance_scales_with_the_input_count(self) -> None:
        """Slack is per input, so a one-input build must NOT get a two-input tolerance."""
        two_input_slack = _allowance(2)
        with pytest.raises(ValidationError):
            assert_fee_matches_size(
                _exact_fee() + two_input_slack,
                _StubTx(SIZE_BYTES, n_inputs=1),
                fee_rate=FEE_RATE,
            )
        assert_fee_matches_size(
            _exact_fee() + _allowance(1),
            _StubTx(SIZE_BYTES, n_inputs=1),
            fee_rate=FEE_RATE,
        )

    def test_allow_overpay_is_the_way_through(self) -> None:
        """Radiant has no RBF/CPFP, so a refusal with no override is its own hazard."""
        assert_fee_matches_size(
            _exact_fee() + 10_000_000,
            _StubTx(SIZE_BYTES),
            fee_rate=FEE_RATE,
            allow_overpay=True,
        )

    def test_underpaying_fee_is_not_flagged_here(self) -> None:
        """A fee *below* size x rate is the relay floor's problem, not this guard's.

        Documents the boundary rather than silently covering two concerns with one
        check — the builders already bound the fee from below.
        """
        assert_fee_matches_size(_exact_fee() - 5_000, _StubTx(SIZE_BYTES), fee_rate=FEE_RATE)


class TestTheGuardAgreesWithARealTransaction:
    """The seam the stub cannot provide: what ``Transaction.serialize()`` really returns.

    Every test above measures the guard against a stub, so any units mistake shared by
    the stub and the guard is invisible to all of them. That is not hypothetical — it
    shipped. ``assert_fee_matches_size`` computed ``len(tx.serialize()) // 2`` while
    ``Transaction.serialize()`` returns bytes, so it judged every transfer against half
    its true size and reported half the fee as burned change.

    These run at **Radiant's real relay floor**, not a token rate. At the 1-photon/byte
    rates convenient for unit tests the halving produces an excess below the dust
    threshold and the guard stays silent; only production parameters expose it. Same
    lesson as the regtest node that inherited a tenth of mainnet's floor.
    """

    def _real_tx(self, n_outputs: int = 6):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_output import TransactionOutput

        tx = Transaction()
        for _ in range(n_outputs):
            tx.add_output(TransactionOutput(P2PKH().lock(PrivateKey().public_key().address()), 1_000))
        return tx

    def test_serialize_returns_bytes_not_hex(self) -> None:
        """The contract the guard depends on, pinned directly.

        If this ever becomes ``str``, the guard's arithmetic is wrong by 2x and the
        test above it would go on passing against its stub.
        """
        assert isinstance(self._real_tx().serialize(), bytes)

    def test_an_honest_transfer_at_the_relay_floor_is_accepted(self) -> None:
        """THE regression test. Fee is exactly what the size demands — nothing is
        burned, nothing is folded — so there is nothing for the guard to object to."""
        from pyrxd.fee_sizing import relay_floor_photons_per_byte

        rate = relay_floor_photons_per_byte()
        tx = self._real_tx()
        honest_fee = len(tx.serialize()) * rate
        assert_fee_matches_size(honest_fee, tx, fee_rate=rate)

    def test_a_real_burn_at_the_relay_floor_is_still_refused(self) -> None:
        """The counterweight: widening the guard must not switch it off."""
        from pyrxd.fee_sizing import relay_floor_photons_per_byte

        rate = relay_floor_photons_per_byte()
        tx = self._real_tx()
        honest_fee = len(tx.serialize()) * rate
        with pytest.raises(ValidationError, match="exceeds what this transaction's size demands"):
            assert_fee_matches_size(honest_fee + 2_330_000_000, tx, fee_rate=rate)

    def test_a_real_build_from_the_real_builder_is_accepted(self) -> None:
        """The end of the chain, and what a stub can never show.

        A synthetic ``fee == size * rate`` is not what a builder produces: it fees a
        trial pass plus per-input slack, so the real fee always sits a few bytes above
        the final size. This drives ``build_ft_airdrop_tx`` — the builder the FT
        transfer path actually calls — and asserts the guard accepts its output.
        Before the allowance existed, 300 of 300 such builds were refused.
        """
        from pyrxd.fee_sizing import relay_floor_photons_per_byte
        from pyrxd.glyph.builder import AirdropFunding, AirdropRecipient, FtAirdropParams, FtUtxo, GlyphBuilder
        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.keys import PrivateKey
        from pyrxd.security.types import Hex20

        rate = relay_floor_photons_per_byte()
        key, ref = PrivateKey(), GlyphRef(txid="aa" * 32, vout=0)
        ftu = FtUtxo.from_output(
            txid="bb" * 32,
            vout=0,
            value=50_000_000,
            ft_script=build_ft_locking_script(Hex20(key.public_key().hash160()), ref),
        )
        result = GlyphBuilder().build_ft_airdrop_tx(
            FtAirdropParams(
                ref=ref,
                utxos=[ftu],
                recipients=[AirdropRecipient(pkh=Hex20(PrivateKey().public_key().hash160()), amount=250)],
                private_key=key,
                funding=[AirdropFunding(txid="cc" * 32, vout=0, value=500_000_000, private_key=PrivateKey())],
                fee_rate=rate,
            )
        )
        assert_fee_matches_size(result.fee, result.tx, fee_rate=rate)


class TestGlyphClientStoreIsOptional:
    def test_constructs_without_a_store(self) -> None:
        """Transfer-only callers must not be taxed with configuring crash recovery."""
        client = GlyphClient(object(), object())
        assert client is not None

    def test_minting_without_a_store_raises_with_the_fix(self) -> None:
        client = GlyphClient(object(), object())
        with pytest.raises(ValidationError, match="PendingStore"):
            _ = client.minter

    def test_minter_is_built_once_and_reused(self, tmp_path) -> None:
        client = GlyphClient(object(), object(), store=JsonFilePendingStore(tmp_path))
        assert client.minter is client.minter

    def test_null_store_is_accepted_as_an_explicit_opt_out(self) -> None:
        client = GlyphClient(object(), object(), store=UnsafeNullPendingStore())
        assert client.minter is not None

    def test_non_store_object_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="PendingStore"):
            GlyphClient(object(), object(), store=object())

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5])
    def test_bad_fee_rate_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="fee_rate"):
            GlyphClient(object(), object(), fee_rate=bad)  # type: ignore[arg-type]


class TestTransferReceipt:
    def test_carries_the_fee_the_caller_cannot_recover_later(self) -> None:
        receipt = TransferReceipt(txid="ab" * 32, ref="r", amount=250, fee=3_000_000, to_pkh="00" * 20)
        assert receipt.amount == 250
        assert receipt.fee == 3_000_000
        assert "3000000" in repr(receipt) or "3_000_000" in repr(receipt) or "fee=3000000" in repr(receipt)


class TestGlyphClientJudgesItsOwnFeeRate:
    """The facade took a ``fee_rate`` and judged only that it was a positive int.

    An over-ceiling rate constructed fine and was refused later by a lazily-built
    ``GlyphMinter`` — in a message naming ``GlyphMinter fee_rate``, a parameter the
    caller never spelled. For a transfer-only client the refusal did not arrive at all,
    because no minter is ever built.
    """

    def test_an_over_ceiling_rate_is_refused_by_name(self):
        with pytest.raises(ValidationError) as exc:
            GlyphClient(object(), object(), fee_rate=10_000_000)
        assert "GlyphClient fee_rate" in str(exc.value), "the message must name the caller's parameter"

    def test_a_sub_floor_rate_is_left_to_the_build_paths(self):
        """The two ends are not symmetric questions.

        An overpay is never legitimate, so it is refused here, before any build can spend
        it. A sub-floor rate is a property of the CHAIN — a regtest node's floor really is
        a tenth of mainnet's — so it belongs to whichever build path knows its context,
        not to a constructor that cannot.
        """
        assert GlyphClient(object(), object(), fee_rate=1_000) is not None

    def test_the_mint_opt_in_is_forwarded_to_the_minter(self):
        client = GlyphClient(
            object(),
            object(),
            store=UnsafeNullPendingStore(),
            fee_rate=1_000,
            allow_below_relay_floor=True,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            assert client.minter is not None, "the minter must accept what the client accepted"


class TestAMintCapableClientJudgesTheFloorUpFront:
    """Deferring the floor entirely meant ``GlyphClient(store=..., fee_rate=1000)``
    constructed, then failed from the lazily-built minter with ``GlyphMinter fee_rate`` —
    a deferred refusal naming a parameter the caller never spelled, which is the fault the
    constructor gate was added to fix, reappearing at the other end of it.
    """

    def test_a_mint_capable_client_refuses_a_sub_floor_rate_by_its_own_name(self):
        with pytest.raises(ValidationError) as exc:
            GlyphClient(object(), object(), store=UnsafeNullPendingStore(), fee_rate=1_000)
        assert "GlyphClient fee_rate" in str(exc.value)

    def test_the_opt_in_still_lets_a_regtest_client_mint(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            assert (
                GlyphClient(
                    object(),
                    object(),
                    store=UnsafeNullPendingStore(),
                    fee_rate=1_000,
                    allow_below_relay_floor=True,
                ).minter
                is not None
            )

    def test_a_transfer_only_client_keeps_the_deferral(self):
        """No store means no mint, and the transfer builders judge the floor themselves
        against their own chain."""
        assert GlyphClient(object(), object(), fee_rate=1_000) is not None


class TestTheFacadeDoesNotForwardAPhantomOverride:
    """``GlyphClient.reveal_nft`` defaulted ``allow_below_relay_floor`` to ``False`` and
    forwarded it.

    Once the minter learned to distinguish "the caller said nothing" (``None``) from "the
    caller re-asserted the floor" (``False``), that default turned every ordinary reveal
    through the facade into a deliberate override. A client built for a sub-floor chain
    committed and then refused to reveal — and the commit is a hashlock with no owner-only
    spend path, so the value goes with it. The constructor flag exists to prevent exactly
    that; the facade reintroduced it one layer up.
    """

    @staticmethod
    def _client(store):
        import sys

        sys.path.insert(0, "tests")
        from test_glyph_mint_facade import FakeClient, FakeWallet, _key

        return GlyphClient(FakeClient(), FakeWallet(_key()), store=store, fee_rate=1_000, allow_below_relay_floor=True)

    def test_a_sub_floor_client_can_finish_the_mint_it_started(self):
        import asyncio
        import sys

        sys.path.insert(0, "tests")
        from test_glyph_mint_facade import RecordingStore, _nft_metadata

        client = self._client(RecordingStore())
        pending = asyncio.run(client.commit_nft(_nft_metadata()))
        assert asyncio.run(client.reveal_nft(pending)).reveal_txid

    def test_an_explicit_false_still_re_asserts_the_floor(self):
        """The override must survive the fix — otherwise the default was replaced by a
        different bug, one that silently ignores the caller instead of obeying a caller
        who never spoke."""
        import asyncio
        import sys

        sys.path.insert(0, "tests")
        from test_glyph_mint_facade import RecordingStore, _nft_metadata

        client = self._client(RecordingStore())
        pending = asyncio.run(client.commit_nft(_nft_metadata()))
        with pytest.raises(ValidationError, match="floor|relay"):
            asyncio.run(client.reveal_nft(pending, allow_below_relay_floor=False))

    def test_the_signature_matches_the_minter_it_forwards_to(self):
        """A structural pin: the two defaults must not drift apart again. This bug was
        created by changing one signature and not the other."""
        import inspect

        from pyrxd.glyph.mint import GlyphMinter

        facade = inspect.signature(GlyphClient.reveal_nft).parameters["allow_below_relay_floor"]
        minter = inspect.signature(GlyphMinter.reveal_nft).parameters["allow_below_relay_floor"]
        assert facade.default == minter.default, "the facade must forward, not decide"
        assert facade.default is None


class TestTheFacadeAndTheMinterDoNotDrift:
    """A generalisation of the single-parameter pin above.

    `GlyphClient` forwards its mint settings to a lazily-built `GlyphMinter`. When the two
    signatures drift, the facade silently starts *deciding* something it was only meant to
    pass on: `reveal_nft`'s `allow_below_relay_floor` was changed to a `bool | None`
    sentinel on the minter and left `bool = False` on the facade, so every ordinary reveal
    through the client forwarded what the minter reads as a deliberate override — a
    sub-floor client broadcast its commit and was then refused its own reveal.

    Checking every shared constructor parameter, rather than the one that broke, is what
    makes this a guard instead of a regression test.
    """

    IGNORE = {"self", "client", "wallet", "store"}

    @staticmethod
    def _shared():
        import inspect

        from pyrxd.glyph.mint import GlyphMinter

        c = inspect.signature(GlyphClient.__init__).parameters
        m = inspect.signature(GlyphMinter.__init__).parameters
        names = [n for n in c if n in m and n not in TestTheFacadeAndTheMinterDoNotDrift.IGNORE]
        return c, m, names

    def test_every_shared_constructor_default_matches(self):
        c, m, names = self._shared()
        assert names, "no shared parameters found — the introspection broke, not the code"
        drift = {n: (c[n].default, m[n].default) for n in names if c[n].default != m[n].default}
        assert not drift, f"facade/minter defaults drifted: {drift}"

    def test_every_shared_parameter_is_actually_forwarded(self):
        """Behavioural, not textual.

        This began as a grep of the `minter` property's source for `name=self._name`. A
        reviewer defeated it in one edit: cross-wiring `__init__` so
        `self._poll_interval_s = confirmation_timeout_s` keeps the property's text intact
        AND matches defaults, so both halves of the guard passed while every caller's value
        was silently dropped — full offline suite green, 9,289 tests.

        So construct a client with a NON-DEFAULT value for each shared name and read back
        what the minter actually received. A text search cannot see cross-wiring; this can.
        """
        import warnings as _w

        _c, _m, names = self._shared()
        assert names, "no shared parameters found — the introspection broke, not the code"

        # A distinct, legal, non-default value per parameter, so a cross-wire between any
        # two of them shows up as a mismatch rather than coincidentally agreeing.
        probes = {
            "fee_rate": 12_345,
            "allow_below_relay_floor": True,
            "min_confirmations": 3,
            "confirmation_timeout_s": 123.5,
            "poll_interval_s": 4.25,
        }
        assert set(names) <= set(probes), f"new shared parameter needs a probe value: {set(names) - set(probes)}"

        with _w.catch_warnings():
            _w.simplefilter("ignore", UserWarning)
            client = GlyphClient(object(), object(), store=UnsafeNullPendingStore(), **{n: probes[n] for n in names})
            minter = client.minter

        wrong = {
            n: (probes[n], getattr(minter, f"_{n}", "<absent>"))
            for n in names
            if getattr(minter, f"_{n}", object()) != probes[n]
        }
        assert not wrong, f"the facade did not forward these (expected, actual): {wrong}"


class TestTheClientsPollIntervalReachesTheWait:
    """The signature-parity guard is a TEXTUAL check — it greps the `minter` property for
    `poll_interval_s=self._poll_interval_s`.

    That passes if `__init__` cross-wires the attribute (`self._poll_interval_s =
    confirmation_timeout_s` — whose default is also forwarded, so the matching-defaults
    half passes too), if the string appears in a comment, or if the minter accepts the
    value and ignores it. The behavioural spy that proves the value reaches both waits
    builds a `GlyphMinter` directly, so the facade layer had only the textual guard.

    This closes it from the outside: set it on the client, observe what the wait receives.
    """

    def test_the_value_set_on_the_client_is_what_the_waits_receive(self):
        import asyncio
        import sys

        sys.path.insert(0, "tests")
        from test_glyph_mint_facade import FakeClient, FakeWallet, RecordingStore, _key, _nft_metadata

        import pyrxd.glyph.mint as mint_mod

        seen: list[float | None] = []
        real = mint_mod.wait_for_confirmation

        async def _spy(*a, **kw):
            seen.append(kw.get("interval_s"))
            return await real(*a, **kw)

        mint_mod.wait_for_confirmation = _spy
        try:
            client = GlyphClient(
                FakeClient(),
                FakeWallet(_key()),
                store=RecordingStore(),
                poll_interval_s=0.005,
            )
            assert asyncio.run(client.mint_nft(_nft_metadata())).reveal_txid
        finally:
            mint_mod.wait_for_confirmation = real

        assert seen == [0.005, 0.005], (
            f"the client's poll_interval_s did not reach both waits: {seen} — a textual parity check cannot see this"
        )


class TestTheClientRefusesBadWaitParametersByItsOwnName:
    """`GlyphClient` accepted both new wait parameters unvalidated, so the refusal arrived
    only on first `.minter` access and named `GlyphMinter` — a class the caller never
    wrote, about a parameter they spelled on this one.

    That is the third time this cycle the same deferred-refusal fault has appeared: first
    on `fee_rate`, then on the sub-floor gate, now on these. Checked here even though the
    minter checks again, because "the layer below will catch it" is what produced the
    other two.
    """

    @pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
    @pytest.mark.parametrize("param", ["poll_interval_s", "confirmation_timeout_s"])
    def test_it_refuses_at_construction_naming_itself(self, param: str, bad: float) -> None:
        with pytest.raises(ValidationError) as exc:
            GlyphClient(object(), object(), store=UnsafeNullPendingStore(), **{param: bad})
        msg = str(exc.value)
        assert "GlyphClient" in msg and param in msg, msg
        assert "GlyphMinter" not in msg, f"names the wrong class: {msg}"

    def test_a_transfer_only_client_is_unaffected(self) -> None:
        """No store means no mint path — but the parameters are still validated, because a
        value that is nonsense is nonsense whether or not it is later used."""
        with pytest.raises(ValidationError, match="GlyphClient"):
            GlyphClient(object(), object(), poll_interval_s=float("nan"))


class TestTheClientValidatesMinConfirmationsToo:
    """The fourth instance of the deferred-refusal fault, found sitting in the very
    function where the other three had just been fixed.

    `fee_rate`, then the sub-floor gate, then `poll_interval_s`/`confirmation_timeout_s` —
    each validated here only after a review found the refusal arriving late and naming
    `GlyphMinter`, a class the caller never wrote. `min_confirmations` was left because the
    fixes chased the parameters reviewers named rather than the ones sharing their shape.
    """

    @pytest.mark.parametrize("bad", [0, -1, True, "x", 1.5])
    def test_it_refuses_at_construction_naming_itself(self, bad) -> None:
        with pytest.raises(ValidationError) as exc:
            GlyphClient(object(), object(), store=UnsafeNullPendingStore(), min_confirmations=bad)
        msg = str(exc.value)
        assert "GlyphClient" in msg and "min_confirmations" in msg, msg
        assert "GlyphMinter" not in msg, f"names the wrong class: {msg}"

    def test_a_legitimate_depth_is_still_accepted(self) -> None:
        import warnings as _w

        with _w.catch_warnings():
            _w.simplefilter("ignore", UserWarning)
            assert GlyphClient(object(), object(), store=UnsafeNullPendingStore(), min_confirmations=6) is not None
