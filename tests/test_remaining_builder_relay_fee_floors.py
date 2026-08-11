"""Relay-floor guards on the builders #407 left unguarded.

#407 closed ``build_maker_offer_tx`` and ``build_payment_tx`` and explicitly flagged the
rest. This file covers them:

===========================  ============================================  =========
builder                      module                                        chain
===========================  ============================================  =========
``build_claim_tx``           ``pyrxd.btc_wallet.taproot``                  Bitcoin
``build_refund_tx``          ``pyrxd.btc_wallet.taproot``                  Bitcoin
``build_cancel_tx``          ``pyrxd.swap.rswp.orders``                    Radiant
``build_claim_tx``           ``pyrxd.gravity.transactions``                Radiant
``build_cancel_tx``          ``pyrxd.gravity.transactions``                Radiant
``build_finalize_tx``        ``pyrxd.gravity.transactions``                Radiant
``build_forfeit_tx``         ``pyrxd.gravity.transactions``                Radiant
===========================  ============================================  =========

Each accepted any non-negative fee and returned a fully-populated result — plausible
txid, plausible accounting — for a transaction no node would relay. Nothing offline
caught it because the fixtures agreed with the builders: 51 fee sites (and the 44 funding
values that had to move with them) across 8 test files paid 1,000-photon fees against
transactions whose floors run from 1,880,000 to 11,500,000. They described chain states
that cannot exist.

**The RSWP cancel is the fund-safety one.** On the v2 orderbook a cancel is the ONLY hard
revocation — the ``0xC3`` advertisement signature stays valid until the offered UTXO is
spent. An unrelayable cancel cannot be replaced (no RBF) or bumped (no CPFP), so the order
stays takeable at the original price while the CLI reports success and hands back a txid.
That is a silent fund-safety failure, not a stuck transaction.

What is asserted here, and why each case earns its place:

* **The guard bites** on every builder, at the exact fee its old fixtures used and at zero.
* **The boundary is exact** — a fee equal to the transaction's own floor is accepted, one
  unit under is refused. Searched for rather than solved: the fee is part of the signed
  output value, so changing it re-signs the input and can move the DER length, and with it
  the size the floor is derived from.
* **Measured after signing, over many builds.** DER signatures are 69-71 bytes, so these
  transactions come out at several sizes and a guard sized against a pre-signing estimate
  would be wrong for a fraction of builds. Every property case asserts the size actually
  varied, so the coverage cannot go silently vacuous. Signing is deterministic per message
  (RFC 6979), so each case re-rolls the recipient/keys rather than repeating one build.
* **The BTC shapes are Schnorr**, fixed at 64 bytes, so their size does NOT vary with the
  signature — asserted explicitly, because "we vary the input and the size moves" is the
  wrong expectation to carry into the taproot builders.
* **The two chains' floors are not interchangeable**, in both directions.
* **The escape hatch still works** — the CLI's sizing loop and the watchtower's
  broken-blob tests both depend on being able to force a sub-floor build into existence.

Live-node proof of the same boundaries is in ``test_remaining_builder_floors_regtest_e2e.py``.
"""

from __future__ import annotations

import hashlib
import os
import time

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as tr
from pyrxd.fee_sizing import bitcoin_virtual_size, radiant_relay_size
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.codehash import compute_p2sh_code_hash
from pyrxd.gravity.fee_policy import (
    DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
)
from pyrxd.gravity.transactions import (
    build_cancel_tx,
    build_claim_tx,
    build_finalize_tx,
    build_forfeit_tx,
)
from pyrxd.gravity.types import GravityOffer
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.security.types import Hex20, Txid
from pyrxd.spv.proof import _BUILDER_TOKEN, CovenantParams, SpvProof
from pyrxd.swap import FundingInput
from pyrxd.swap.rswp import build_cancel_tx as rswp_build_cancel_tx
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FAKE_TXID = "aa" * 32
#: The fee the old offline fixtures used at nearly every one of these call sites.
_OLD_FIXTURE_FEE = 1_000
#: Funding large enough that the FEE, not the input value, is what the guard reacts to.
_FUNDED = 100_000_000

#: The one deliberate, greppable way to build below the floor. Used ONLY to manufacture
#: the under-floor transactions these tests need to compare against; never as a way to
#: make a guard stop complaining.
_PERMISSIVE = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

_MAKER_ADDR = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
_PAST_DEADLINE = 1_735_686_400  # exactly MIN_CLAIM_DEADLINE (2025-01-01)


# ---------------------------------------------------------------------------
# Helpers. Keys are ALWAYS CSPRNG and never reused between builds — a fresh key is
# what re-rolls the DER length these cases depend on.
# ---------------------------------------------------------------------------


def _privkey() -> PrivateKeyMaterial:
    return PrivateKeyMaterial(os.urandom(32))


def _offer(**kw) -> GravityOffer:
    claimed_redeem = bytes.fromhex("bb" * 100)
    defaults: dict = dict(
        btc_receive_hash=b"\x00" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=50_000,
        chain_anchor=b"\x00" * 32,
        anchor_height=840_000,
        merkle_depth=12,
        taker_radiant_pkh=b"\x00" * 20,
        claim_deadline=int(time.time()) + 48 * 3600,
        photons_offered=1_000_000,
        offer_redeem_hex="aa" * 100,
        claimed_redeem_hex="bb" * 100,
        expected_code_hash_hex=compute_p2sh_code_hash(claimed_redeem).hex(),
    )
    defaults.update(kw)
    return GravityOffer(**defaults)


def _spv_proof(headers: list[bytes] | None = None) -> SpvProof:
    params = CovenantParams(
        btc_receive_hash=b"\xaa" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=50_000,
        chain_anchor=b"\x00" * 32,
        anchor_height=840_000,
        merkle_depth=1,
    )
    return SpvProof(
        txid="aa" * 32,
        raw_tx=b"\x01" * 100,
        headers=headers if headers is not None else [b"\x00" * 80],
        branch=b"\x00" * 33,
        pos=1,
        output_offset=0,
        covenant_params=params,
        _token=_BUILDER_TOKEN,
    )


# -- the four gravity builders, each reduced to (fee, policy) -> raw bytes ---------


def _gravity_claim(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    r = build_claim_tx(
        offer=_offer(),
        funding_txid=FAKE_TXID,
        funding_vout=0,
        funding_photons=funded,
        fee_sats=fee,
        taker_privkey=key or _privkey(),
        accept_short_deadline=True,
        fee_policy=policy,
    )
    return bytes.fromhex(r.tx_hex)


def _gravity_cancel(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    r = build_cancel_tx(
        offer=_offer(),
        funding_txid=FAKE_TXID,
        funding_vout=0,
        funding_photons=funded,
        maker_address=_MAKER_ADDR,
        fee_sats=fee,
        maker_privkey=key or _privkey(),
        fee_policy=policy,
    )
    return bytes.fromhex(r.tx_hex)


def _gravity_finalize(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    r = build_finalize_tx(
        spv_proof=_spv_proof(),
        claimed_redeem_hex="ab" * 50,
        funding_txid="cd" * 32,
        funding_vout=0,
        funding_photons=funded,
        to_address=_MAKER_ADDR,
        fee_sats=fee,
        fee_policy=policy,
    )
    return bytes.fromhex(r.tx_hex)


def _gravity_forfeit(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    r = build_forfeit_tx(
        _offer(claim_deadline=_PAST_DEADLINE),
        FAKE_TXID,
        0,
        funded,
        _MAKER_ADDR,
        fee,
        fee_policy=policy,
    )
    return bytes.fromhex(r.tx_hex)


#: name -> builder. Every case below runs over ALL of them rather than picking one,
#: because "the guard exists somewhere in this module" is the property that already
#: held before this change and still missed four builders.
GRAVITY_BUILDERS = {
    "claim": _gravity_claim,
    "cancel": _gravity_cancel,
    "finalize": _gravity_finalize,
    "forfeit": _gravity_forfeit,
}


# -- RSWP cancel ------------------------------------------------------------------

_FT_REF = GlyphRef(txid=Txid("aa" * 32), vout=0)


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), _FT_REF)), value))
    return tx


def _rswp_cancel_rxd(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    k = key or PrivateKey()
    pkh = k.public_key().hash160()
    tx = rswp_build_cancel_tx(
        offered_source_tx=_rxd_src(pkh, funded),
        offered_vout=0,
        maker_key=k,
        refund_pkh=pkh,
        fee=fee,
        fee_policy=policy,
    )
    return tx.serialize()


def _rswp_cancel_ft(fee: int, policy=None, funded: int = _FUNDED, key=None) -> bytes:
    k = key or PrivateKey()
    pkh = k.public_key().hash160()
    tx = rswp_build_cancel_tx(
        offered_source_tx=_ft_src(pkh, 1000),
        offered_vout=0,
        maker_key=k,
        refund_pkh=pkh,
        fee=fee,
        funding=[FundingInput(_rxd_src(pkh, funded), 0, k)],
        fee_policy=policy,
    )
    return tx.serialize()


RSWP_BUILDERS = {"rswp-cancel-rxd": _rswp_cancel_rxd, "rswp-cancel-ft": _rswp_cancel_ft}
RADIANT_BUILDERS = {**GRAVITY_BUILDERS, **RSWP_BUILDERS}


def _key_for(name: str):
    """A fresh signing key of the type this builder wants.

    The gravity builders take ``PrivateKeyMaterial``; the RSWP one takes ``PrivateKey``.
    Pinning the key lets a case build the SAME transaction twice — once permissively to
    measure it, once strictly to assert the refusal — instead of comparing two different
    transactions that happen to have been built a moment apart.
    """
    return PrivateKey() if name.startswith("rswp") else _privkey()


# -- BTC taproot HTLC spends -------------------------------------------------------


def _xonly(sk: coincurve.PrivateKey) -> bytes:
    return sk.public_key.format(compressed=True)[1:]


def _btc_legs(amount: int = 1_000_000):
    """A fresh HTLC locator plus both leaf keys and a fresh destination scriptPubKey."""
    p = os.urandom(32)
    msk, tsk = coincurve.PrivateKey(os.urandom(32)), coincurve.PrivateKey(os.urandom(32))
    timeout = tr.Timelock(144, tr.TimeUnit.BLOCKS)
    htlc = tr.build_htlc(
        hashlock=hashlib.sha256(p).digest(),
        claim_pubkey_xonly=_xonly(msk),
        refund_pubkey_xonly=_xonly(tsk),
        timeout=timeout,
        network="bcrt",
    )
    loc = htlc.with_funding(tr.BtcOutpoint(FAKE_TXID, 0), amount)
    # A fresh 20-byte P2WPKH destination per build: this is what varies the size on the
    # BTC side, since Schnorr signatures do not.
    return loc, p, msk, tsk, timeout, b"\x00\x14" + os.urandom(20)


def _btc_claim(fee: int, policy=None, amount: int = 1_000_000) -> bytes:
    loc, p, msk, _tsk, _to, spk = _btc_legs(amount)
    return tr.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=msk.secret,
        to_scriptpubkey=spk,
        fee_sats=fee,
        aux_rand=os.urandom(32),
        fee_policy=policy,
    )


def _btc_refund(fee: int, policy=None, amount: int = 1_000_000) -> bytes:
    loc, _p, _msk, tsk, timeout, spk = _btc_legs(amount)
    return tr.build_refund_tx(
        locator=loc,
        refund_privkey=tsk.secret,
        timeout=timeout,
        to_scriptpubkey=spk,
        fee_sats=fee,
        aux_rand=os.urandom(32),
        fee_policy=policy,
    )


BTC_BUILDERS = {"btc-claim": _btc_claim, "btc-refund": _btc_refund}


def _vsize(raw: bytes) -> int:
    """BIP141 vsize of a serialized segwit transaction, parsed rather than modelled."""
    pos = 0

    def take(k: int) -> bytes:
        nonlocal pos
        out = raw[pos : pos + k]
        pos += k
        return out

    def cs() -> tuple[int, bytes]:
        nonlocal pos
        v = raw[pos]
        pos += 1
        if v < 0xFD:
            return v, bytes([v])
        rest = take({0xFD: 2, 0xFE: 4, 0xFF: 8}[v])
        return int.from_bytes(rest, "little"), bytes([v]) + rest

    ver = take(4)
    segwit = raw[pos] == 0x00 and raw[pos + 1] == 0x01
    if segwit:
        take(2)
    n_in, n_in_b = cs()
    vin = bytearray(n_in_b)
    for _ in range(n_in):
        vin += take(36)
        ln, ln_b = cs()
        vin += ln_b + take(ln)
        vin += take(4)
    n_out, n_out_b = cs()
    vout = bytearray(n_out_b)
    for _ in range(n_out):
        vout += take(8)
        ln, ln_b = cs()
        vout += ln_b + take(ln)
    if segwit:
        for _ in range(n_in):
            n_items, _ = cs()
            for _ in range(n_items):
                il, _ = cs()
                take(il)
    lt = take(4)
    stripped = ver + bytes(vin) + bytes(vout) + lt
    return bitcoin_virtual_size(stripped_size=len(stripped), total_size=len(raw))


def _radiant_floor(size: int) -> int:
    return DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(size)


def _btc_floor(vsize: int) -> int:
    return DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.min_relay_fee(vsize)


# ===========================================================================
# 1. The guard bites — at the fee the old fixtures used, and at zero.
# ===========================================================================


class TestTheGuardBites:
    @pytest.mark.parametrize("name", sorted(RADIANT_BUILDERS))
    def test_radiant_builder_refuses_the_old_fixture_fee(self, name):
        """Every Radiant builder here used to return a transaction at this fee."""
        with pytest.raises(InsufficientFundsError) as ei:
            RADIANT_BUILDERS[name](_OLD_FIXTURE_FEE)
        assert "min relay" in str(ei.value) or "below the required" in str(ei.value)

    @pytest.mark.parametrize("name", sorted(RADIANT_BUILDERS))
    def test_radiant_builder_refuses_a_zero_fee(self, name):
        with pytest.raises(InsufficientFundsError):
            RADIANT_BUILDERS[name](0)

    @pytest.mark.parametrize("name", sorted(BTC_BUILDERS))
    def test_btc_builder_refuses_a_token_fee(self, name):
        with pytest.raises(InsufficientFundsError):
            BTC_BUILDERS[name](1)

    @pytest.mark.parametrize("name", sorted(BTC_BUILDERS))
    def test_btc_builder_refuses_a_zero_fee(self, name):
        with pytest.raises(InsufficientFundsError):
            BTC_BUILDERS[name](0)

    def test_the_refusal_reports_the_shortfall_machine_readably(self):
        """Callers must be able to act on the number without parsing prose."""
        with pytest.raises(InsufficientFundsError) as ei:
            _rswp_cancel_rxd(_OLD_FIXTURE_FEE)
        exc = ei.value
        assert exc.available == _OLD_FIXTURE_FEE
        assert exc.required > _OLD_FIXTURE_FEE
        assert exc.shortfall == exc.required - _OLD_FIXTURE_FEE

    def test_the_rswp_cancel_message_says_why_it_matters(self):
        """A cancel is the ONLY revocation — the error has to say so, not just 'fee low'.

        An operator who reads "fee too low" on a cancel may reasonably shrug; one who
        reads that the order is still takeable will not.
        """
        with pytest.raises(InsufficientFundsError) as ei:
            _rswp_cancel_rxd(_OLD_FIXTURE_FEE)
        assert "only hard revocation" in str(ei.value)
        assert "takeable" in str(ei.value)


# ===========================================================================
# 2. The boundary is exact, in both directions, per builder.
# ===========================================================================


class TestTheBoundaryIsExact:
    """A fee equal to the transaction's own floor is accepted; one unit under is refused.

    The boundary is SEARCHED FOR, not solved. The fee is part of the signed output value,
    so changing it re-signs the input and can move the DER length by a byte — and with it
    the size the floor is derived from. Each attempt uses fresh keys and retries until a
    build lands exactly on its own floor.
    """

    @pytest.mark.parametrize("name", sorted(RADIANT_BUILDERS))
    def test_radiant_at_floor_accepted_one_under_refused(self, name):
        build = RADIANT_BUILDERS[name]

        at_floor = None
        for _ in range(60):
            probe = build(1, _PERMISSIVE)
            floor = _radiant_floor(len(probe))
            try:
                candidate = build(floor)
            except InsufficientFundsError:
                continue  # the fee moved the DER length; re-roll
            if _radiant_floor(len(candidate)) == floor:
                at_floor = (candidate, floor)
                break
        assert at_floor is not None, f"{name}: no build landed exactly on its own floor"
        tx, floor = at_floor
        assert _radiant_floor(radiant_relay_size(tx)) == floor

        # One photon under. A fresh key per attempt can yield a SHORTER transaction for
        # which `floor - 1` is genuinely sufficient — not a guard failure, just a
        # different transaction. So pin the key: build the very same transaction twice,
        # once permissively to learn its real size, then strictly to demand the refusal.
        refused = False
        for _ in range(60):
            k = _key_for(name)
            under = build(floor - 1, _PERMISSIVE, key=k)
            if _radiant_floor(len(under)) != floor:
                continue  # this key's transaction is a different size class; re-roll
            with pytest.raises(InsufficientFundsError):
                build(floor - 1, key=k)
            refused = True
            break
        assert refused, f"{name}: could not build a same-size transaction one photon under the floor"

    @pytest.mark.parametrize("name", sorted(BTC_BUILDERS))
    def test_btc_at_floor_accepted_one_under_refused(self, name):
        build = BTC_BUILDERS[name]
        probe = build(1, _PERMISSIVE)
        floor = _btc_floor(_vsize(probe))
        # Schnorr is fixed-length, so for a given destination shape the size does not move
        # with the fee: the floor found from the probe is the floor of the real build.
        accepted = build(floor)
        assert _btc_floor(_vsize(accepted)) <= floor
        with pytest.raises(InsufficientFundsError):
            build(floor - 1)


# ===========================================================================
# 3. Property: over many builds and shapes, everything returned pays for itself.
# ===========================================================================


class TestEveryReturnedTransactionPaysForItsOwnBytes:
    """A single example proves nothing when the size varies. These fee AT the floor
    rather than comfortably above it, so any drift shows up immediately."""

    @pytest.mark.parametrize("name", sorted(RADIANT_BUILDERS))
    def test_radiant_property(self, name):
        build = RADIANT_BUILDERS[name]
        sizes = set()
        n_ok = 0
        for _ in range(40):
            probe = build(1, _PERMISSIVE)
            sizes.add(len(probe))
            floor = _radiant_floor(len(probe))
            # Fee at the probe's floor; if the re-sign grew the tx the guard refuses,
            # which is itself the property under test (it must never return a short one).
            try:
                tx = build(floor)
            except InsufficientFundsError:
                continue
            sizes.add(len(tx))
            assert _radiant_floor(radiant_relay_size(tx)) <= floor, (
                f"{name}: returned a {len(tx)}-byte tx paying {floor}, below its own floor"
            )
            n_ok += 1
        assert n_ok > 0, f"{name}: every build was refused — the case proved nothing"

    def test_the_der_signature_really_does_move_the_size(self):
        """Guards against this whole class going vacuous.

        If every build came out the same length, 'measured after signing' would be
        untested and a pre-signing estimate would pass every case above. The signed
        Radiant builders must show more than one size across fresh keys.
        """
        for name in ("claim", "cancel", "rswp-cancel-rxd", "rswp-cancel-ft"):
            sizes = {len(RADIANT_BUILDERS[name](1, _PERMISSIVE)) for _ in range(60)}
            assert len(sizes) > 1, f"{name}: size never varied over 60 builds ({sizes})"

    def test_the_unsigned_radiant_builders_are_deterministic(self):
        """The complement, stated rather than assumed.

        ``finalize`` and ``forfeit`` carry NO signature — their scriptSigs are proof data
        and a selector — so their sizes must be constant. Measuring the real bytes is
        still correct for them; it just is not what varies.
        """
        for name in ("finalize", "forfeit"):
            sizes = {len(RADIANT_BUILDERS[name](1, _PERMISSIVE)) for _ in range(20)}
            assert len(sizes) == 1, f"{name}: unsigned builder varied in size ({sizes})"

    @pytest.mark.parametrize("name", sorted(BTC_BUILDERS))
    def test_btc_property_over_varied_destinations(self, name):
        build = BTC_BUILDERS[name]
        vsizes = set()
        for _ in range(40):
            probe = build(1, _PERMISSIVE)
            v = _vsize(probe)
            vsizes.add(v)
            tx = build(_btc_floor(v))
            assert _btc_floor(_vsize(tx)) <= _btc_floor(v)
        assert vsizes, "no builds ran"

    def test_btc_schnorr_signatures_do_not_move_the_size(self):
        """The BTC shapes are BIP340, fixed at 64 bytes — unlike every DER builder here.

        Worth pinning: carrying the 'signatures vary' intuition into the taproot builders
        would justify slack they do not need, and losing it would hide a regression if a
        future change reintroduced a variable-length signature on this path.
        """
        loc, p, msk, _tsk, _to, spk = _btc_legs()
        sizes = {
            len(
                tr.build_claim_tx(
                    locator=loc,
                    preimage=p,
                    claim_privkey=msk.secret,
                    to_scriptpubkey=spk,
                    fee_sats=100_000,
                    aux_rand=os.urandom(32),  # fresh aux_rand => a different signature
                )
            )
            for _ in range(30)
        }
        assert len(sizes) == 1, f"a BIP340 signature changed the tx size: {sizes}"


# ===========================================================================
# 4. The two chains' floors are not interchangeable.
# ===========================================================================


class TestTheFloorsAreNotInterchangeable:
    def test_bitcoins_rule_would_massively_understate_radiants_floor(self):
        tx = _gravity_cancel(1, _PERMISSIVE)
        radiant = _radiant_floor(radiant_relay_size(tx))
        as_if_bitcoin = _btc_floor(len(tx))
        assert radiant > as_if_bitcoin * 1_000, (
            "applying Bitcoin's 1 sat/vB rule to a Radiant tx would let an unrelayable, "
            f"un-bumpable covenant spend out the door ({as_if_bitcoin} vs {radiant})"
        )

    def test_radiants_rule_would_overcharge_a_bitcoin_spend(self):
        """And by how much: the witness discount on a taproot script-path spend is large.

        Almost the whole transaction is witness (signature + preimage + leaf script +
        control block), so charging total size instead of vsize refuses spends the node
        accepts.
        """
        raw = _btc_claim(1, _PERMISSIVE)
        assert _vsize(raw) < len(raw), "a segwit tx's vsize must be under its total size"
        assert _btc_floor(len(raw)) > _btc_floor(_vsize(raw))

    def test_the_btc_guard_does_not_repeat_radiants_no_rbf_claim(self):
        """Bitcoin HAS RBF and CPFP — the claim leg sets nSequence=0xFFFFFFFD to opt in.

        The shared guard's default consequence text is Radiant's ("cannot be bumped,
        stuck 8h"). Leaking it into a Bitcoin error tells the operator something false
        about their own chain and misdirects the recovery.
        """
        with pytest.raises(InsufficientFundsError) as ei:
            _btc_claim(1)
        msg = str(ei.value)
        assert "no RBF" not in msg and "CPFP" not in msg
        assert "no node will relay this transaction" in msg

    def test_the_radiant_guard_does_keep_the_no_rbf_explanation(self):
        """The complement: on Radiant that sentence is true and load-bearing."""
        with pytest.raises(InsufficientFundsError) as ei:
            _gravity_forfeit(1)
        msg = str(ei.value)
        assert "no RBF" in msg and "CPFP" in msg


# ===========================================================================
# 5. The escape hatch still exists, and legitimate callers still work.
# ===========================================================================


class TestLegitimateCallersAreNotBroken:
    @pytest.mark.parametrize("name", sorted({**RADIANT_BUILDERS, **BTC_BUILDERS}))
    def test_an_explicit_sub_floor_policy_is_still_honoured(self, name):
        """Regtest, a chain you control, and the CLI's trial passes all need this."""
        build = {**RADIANT_BUILDERS, **BTC_BUILDERS}[name]
        assert build(1, _PERMISSIVE)  # must not raise

    def test_a_regtest_rate_policy_is_accepted(self):
        """A regtest node advertises a tenth of the mainnet floor; the builder must take it."""
        regtest = DeadlineFeePolicy(relay_fee_per_kb=1_000_000, allow_below_protocol_floor=True)
        probe = _gravity_cancel(1, _PERMISSIVE)
        floor = regtest.min_relay_fee(len(probe))
        assert floor < _radiant_floor(len(probe)), "regtest floor should be lower than mainnet's"
        assert _gravity_cancel(floor * 2, regtest)

    def test_the_cli_sizing_loop_policy_permits_a_sub_floor_trial_build(self):
        """The CLI's fee loop builds deliberately sub-floor trial transactions to MEASURE
        a size it cannot model, then rebuilds at the real fee.

        A hard guard with no opt-out would refuse the trial pass and break `swap cancel`
        for exactly the funded-FT shape that needs the loop most. The loop therefore
        passes the existing escape hatch and gates the RETURNED transaction with
        `_assert_relayable`. This pins the constant it uses.
        """
        from pyrxd.cli.swap_book_cmds import _SIZING_TRIAL_POLICY

        assert _SIZING_TRIAL_POLICY.allow_below_protocol_floor is True
        # The seed fee for a modelled 1-in/1-out shape, against a real funded-FT cancel.
        under_seeded = _rswp_cancel_ft(2_500_000, _SIZING_TRIAL_POLICY)
        assert _radiant_floor(len(under_seeded)) > 2_500_000, (
            "this shape must genuinely be under-seeded, or the case proves nothing"
        )

    def test_the_taproot_leg_default_fee_clears_its_own_floor(self):
        """`BitcoinTaprootLeg` builds and broadcasts at a fixed `fee_sats` (default 500).

        If that default were under the floor the guard would break the live claim path,
        which is the opposite of the intent.
        """
        from pyrxd.btc_wallet.htlc_leg import FundingPolicy

        default_fee = FundingPolicy().fee_sats
        for build in (_btc_claim, _btc_refund):
            worst = max(_vsize(build(1, _PERMISSIVE)) for _ in range(20))
            assert default_fee >= _btc_floor(worst), (
                f"the leg's default fee {default_fee} is below the {_btc_floor(worst)} floor"
            )


# ===========================================================================
# 6. The sizing helpers now live in fee_sizing, and fee_policy re-exports them.
# ===========================================================================


class TestTheSizingRuleHasOneHome:
    def test_fee_policy_reexports_the_same_objects(self):
        """Not merely equal — the SAME function objects, so there is one definition."""
        from pyrxd import fee_sizing
        from pyrxd.gravity import fee_policy

        assert fee_policy.radiant_relay_size is fee_sizing.radiant_relay_size
        assert fee_policy.bitcoin_virtual_size is fee_sizing.bitcoin_virtual_size
        assert fee_policy.WITNESS_SCALE_FACTOR == fee_sizing.WITNESS_SCALE_FACTOR

    def test_fee_sizing_does_not_drag_in_the_gravity_stack(self):
        """The reason the constants moved here in #405 was an import cycle.

        ``pyrxd.fee_sizing`` must stay reachable from ``pyrxd.wallet`` and
        ``pyrxd.btc_wallet`` without pulling in ``pyrxd.gravity`` (which imports
        ``pyrxd.hd.wallet`` -> ``pyrxd.wallet``, and ``pyrxd.btc_wallet.htlc_leg``).
        """
        import subprocess
        import sys

        out = subprocess.run(
            [sys.executable, "-c", "import pyrxd.fee_sizing, sys; print('pyrxd.gravity' in sys.modules)"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert out.stdout.strip() == "False", "importing fee_sizing pulled in pyrxd.gravity"

    def test_the_btc_payment_module_imports_the_sizing_rule_at_module_level(self):
        """The relocation's concrete payoff.

        ``btc_wallet/payment.py`` used to reach the sizing rule through a deferred,
        inside-a-function import. A rule you can only reach that way is a rule that
        invites a second copy — which is where this repo's worst bugs came from.
        """
        import pyrxd.btc_wallet.payment as payment
        import pyrxd.btc_wallet.taproot as taproot

        assert payment.bitcoin_virtual_size is bitcoin_virtual_size
        assert taproot.bitcoin_virtual_size is bitcoin_virtual_size
