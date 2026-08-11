"""The one place pyrxd decides how many photons a signed transaction must pay.

Why this module exists
----------------------
Every builder in this SDK that pays a miner fee follows the same two-pass shape:
build a **trial** transaction, sign it, measure its bytes, size the fee from that
measurement, then rebuild and re-sign the **final** transaction. The trap is that
the two passes sign *different messages* — the final one commits to the real
output values — so their ECDSA signatures are not the same length. A DER signature
here is 69, 70 or 71 bytes depending on how many leading zero bytes ``r`` and ``s``
carry (measured over 3000 distinct messages: 17 / 1457 / 1526). A fee sized purely
off the trial pass therefore lands **below** the rate it was built for whenever the
final signature is the longer one.

Signing is deterministic (RFC 6979: same key, same message, same signature — verified,
20 signatures over one message are one distinct value), so this is not a flaky
one-in-three. It is a *property of the individual transaction*: a given set of
inputs, recipient and amount either underpays or does not, every time. Retrying does
not help. Roughly a third of distinct sends fall on the wrong side of it.

Measured on ``RxdWallet.build_send_tx`` before the fix, 2000 builds per shape at
10_000 photons/byte: 25.4% short at one input, 31.8% at two, 33.7% at three,
36.8% at five (worst observed shortfall 4 bytes' worth of fee). ``build_send_max_tx``
was the same, 26.2%-38.1%; ``HdWallet``'s copies of the same two builders,
23.6%-33.2%.

At the default rate that shortfall is fatal rather than cosmetic.
:data:`RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB` is *exactly* the mainnet relay
floor, so one byte short is ``66: min relay fee not met`` — and **Radiant has
neither RBF nor CPFP** (``Radiant-Core`` ``src/validation.cpp:667``/``:856`` reject
any mempool conflict; ``src/miner.cpp:380`` selects on the transaction's own
``GetModifiedFeeRate()``), so the transaction cannot be bumped or replaced. It sits
on its own inputs until ``DEFAULT_MEMPOOL_EXPIRY`` — 8 hours — before a rebuild is
even possible.

This module exists so that rule has ONE implementation. It previously had three
(``glyph/ft.py``, ``cli/swap_book_cmds.py``, and — absent, which was the bug —
``wallet.py`` and ``hd/wallet.py``), and this repo has a measured history of the
same rule drifting apart across copies.

Not to be confused with ``pyrxd.fee_models``
--------------------------------------------
``pyrxd.fee_models.SatoshisPerKilobyte`` is a :class:`~pyrxd.fee_model.FeeModel`
for ``Transaction.fee()``: it *models* a transaction's size from its shape
(counting inputs, outputs and varints) so a fee can be estimated before signing.
This module works the other way round — from the **measured serialized length of
an already-signed transaction** — and is what decides whether a build is allowed
to be returned at all. Estimating a size and proving a signed transaction pays
for its own bytes are different jobs; only the second one can fail closed.

The two floors are different things
-----------------------------------
* **The caller's rate.** ``fee_rate`` photons/byte, chosen by whoever built the
  transaction. Always binding: returning a transaction that does not pay the rate
  it was built for is a broken builder regardless of chain.
* **The protocol relay floor.** What ``AcceptToMemoryPool`` demands
  (``nModifiedFees < GetEffectiveMinRelayFee(height).GetFee(nSize)``, sized against
  ``tx.GetTotalSize()`` — the full serialized size, there is no vsize on this
  chain). It is chain policy, not the caller's choice.

They coincide at the default: ``10_000_000`` photons/kB is ``10_000`` per byte
exactly. They part company when a caller deliberately picks a *lower* rate, which
is legitimate on regtest or a chain they control — a default regtest node relays at
a tenth of the mainnet floor. :func:`required_fee` therefore treats a sub-floor
``fee_rate`` as that deliberate opt-out and binds only the caller's rate, rather
than silently multiplying a regtest fee by ten. Callers whose rate arrives from an
untrusted or unvalidated source (a config file, an RPC reading) want
:func:`fee_never_below_relay_floor` instead, which has no opt-out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .security.errors import ValidationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .transaction.transaction import Transaction

__all__ = [
    "RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB",
    "RADIANT_MIN_RELAY_PHOTONS_PER_KB",
    "SIG_SIZE_SLACK_BYTES",
    "WITNESS_SCALE_FACTOR",
    "assert_fee_rate_clears_relay_floor",
    "assert_pays_for_its_size",
    "assert_tx_pays_for_itself",
    "bitcoin_virtual_size",
    "fee_for_kb_rate",
    "fee_never_below_relay_floor",
    "min_relay_fee",
    "radiant_relay_size",
    "relay_floor_photons_per_byte",
    "required_fee",
    "trial_size_with_slack",
]

# Radiant-Core ``src/policy/policy.h``: ``LEGACY_MIN_RELAY_TX_FEE_PER_KB`` (:47) and
# ``RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB`` (:49). ``GetEffectiveMinRelayFee`` returns
# the legacy rate before the 2.0 activation + 5000-block grace period and the higher one
# after; the reference mainnet node reports the higher one (``getmempoolinfo``, read
# 2026-08-09: ``minrelaytxfee`` 0.01, ``effective_minrelaytxfee`` 0.10 RXD/kB).
#
# These live HERE, in a module with no pyrxd imports at all, rather than in
# ``pyrxd.gravity.fee_policy`` where they started, because ``pyrxd.wallet`` needs
# them and cannot import the gravity package: ``pyrxd.gravity.__init__`` pulls in
# ``pyrxd.hd.wallet``, which imports ``pyrxd.wallet`` — a genuine cycle (measured:
# importing ``pyrxd.gravity.fee_policy`` loads 42 modules beyond ``pyrxd.wallet``,
# including the whole spv / btc_wallet / eth_wallet / hd stack).
# ``pyrxd.gravity.fee_policy`` re-exports both names, so its public surface is
# unchanged and there is still exactly one definition.
RADIANT_MIN_RELAY_PHOTONS_PER_KB = 1_000_000  # 0.01 RXD/kB (legacy floor)
RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB = 10_000_000  # 0.10 RXD/kB (post-2.0 floor)

# Per-input headroom added to a TRIAL-pass measurement before the fee is computed.
#
# 3 bytes per input, not 2: a DER signature is usually 70 or 71 bytes, and 69 turns up
# about once in 180 (measured, 3000 signatures) — so the observed spread is 2 and 3 is
# the conservative bound one step beyond it. A review of the FT airdrop builder
# measured a 1000-recipient/2-input build clearing its required fee by a factor of
# 1.000047 at 2 bytes of slack: the whole margin WAS the slack, and one unlucky trial
# signature would have consumed it. Overpaying by at most ``3 × fee_rate`` photons per
# input is the correct trade against a transaction that cannot be repaired.
#
# The slack is what should make :func:`assert_pays_for_its_size` unreachable; that
# function is what proves it, rather than trusting it.
SIG_SIZE_SLACK_BYTES: int = 3

# BIP141 ``WITNESS_SCALE_FACTOR`` (Bitcoin Core ``src/consensus/consensus.h``). Only the
# BTC side has one: Radiant has no segwit, so there is nothing to discount there.
WITNESS_SCALE_FACTOR = 4


# ---------------------------------------------------------------------------
# THE SIZE A RELAY FLOOR IS MEASURED AGAINST IS PER-CHAIN. These two functions are
# the only place that difference is expressed, so a caller picks a chain rather
# than re-deriving a formula.
#
# Getting this wrong is not a rounding error. Applying Radiant's total-size rule to a
# BTC transaction over-states its requirement by roughly the witness discount (measured:
# 222 total bytes vs 141 vbytes on one real P2WPKH payment — 57% over); applying
# Bitcoin's vsize rule to a Radiant transaction would under-state it, and Radiant is the
# chain where under-fee'ing cannot be undone.
#
# They live HERE rather than in ``pyrxd.gravity.fee_policy`` where they were introduced,
# for the same reason the relay-floor constants above moved: this is the single home for
# fee-sizing rules, and ``pyrxd.gravity`` cannot be imported from ``pyrxd.wallet`` or
# ``pyrxd.btc_wallet`` without closing a package cycle. ``pyrxd.gravity.fee_policy``
# re-exports both, so its public surface is unchanged and there is still exactly one
# definition of each. This module now imports ``pyrxd.security.errors`` — a leaf module
# that imports nothing from pyrxd — so the "no pyrxd imports at all" property is
# narrowed, not lost: nothing here can reach a builder.
# ---------------------------------------------------------------------------


def radiant_relay_size(raw_tx: bytes) -> int:
    """Bytes Radiant charges the relay floor against: ``tx.GetTotalSize()``.

    ``AcceptToMemoryPool`` compares against ``GetEffectiveMinRelayFee(height).GetFee(nSize)``
    with ``nSize = tx.GetTotalSize()`` — the **full serialized size**, carrying an explicit
    "Do not change this to use virtualsize without coordinating a network policy upgrade"
    (Radiant-Core ``src/validation.cpp:770``). Radiant has no segwit, so total size is the
    only size there is; this function exists to name the rule, not to compute anything.

    Pass the **signed** transaction: a DER signature is 69-71 bytes run to run, so a size
    taken before signing is an estimate, and an estimate one byte short is a fee below the
    floor.
    """
    if not isinstance(raw_tx, (bytes, bytearray)):
        raise ValidationError("raw_tx must be bytes (the SIGNED, serialized transaction)")
    if not raw_tx:
        raise ValidationError("raw_tx is empty; there is no transaction to measure")
    return len(raw_tx)


def bitcoin_virtual_size(*, stripped_size: int, total_size: int) -> int:
    """Bytes Bitcoin charges the relay floor against: BIP141 ``vsize``.

    ``vsize = ceil(weight / 4)`` where ``weight = stripped_size * 3 + total_size``
    (BIP141; Bitcoin Core ``GetTransactionWeight`` / ``GetVirtualTransactionSize``).

    * ``stripped_size`` — the serialization **without** marker, flag and witness (the
      bytes the txid is hashed over).
    * ``total_size`` — the full serialization **with** them, the bytes that go on the wire.

    For a non-witness transaction the two are equal and ``vsize == total_size``.

    Caveat, stated rather than silently assumed: Bitcoin Core's mempool actually uses
    ``max(weight, nSigOpCost * nBytesPerSigOp * 4) / 4``, so a transaction with an unusually
    high sigop-to-byte ratio is charged more than this returns. For the single-input
    P2WPKH / P2SH-P2WPKH / P2TR shapes this SDK builds, weight dominates by an order of
    magnitude and the two agree; a builder for sigop-dense scripts would need the fuller
    form.
    """
    for name, value in (("stripped_size", stripped_size), ("total_size", total_size)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValidationError(f"{name} must be a positive int")
    if total_size < stripped_size:
        raise ValidationError(
            f"total_size ({total_size}) < stripped_size ({stripped_size}); the witness "
            "serialization can never be shorter than the one it strips"
        )
    weight = stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
    return -(-weight // WITNESS_SCALE_FACTOR)  # ceil


def fee_for_kb_rate(size_bytes: int, per_kb: int) -> int:
    """``ceil(size_bytes × per_kb / 1000)`` — a node's own fee derivation, rounded UP.

    ``CFeeRate::GetFee`` truncates (``ceil=false``, ``Radiant-Core``
    ``src/feerate.cpp:51``). Rounding up instead makes this at most one photon
    stricter than the node — deliberately, because being one photon short is a
    broadcast that cannot be taken back.

    Integer-only: floats would introduce drift in exactly the last photon that
    matters.
    """
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes <= 0:
        raise ValueError("size_bytes must be a positive int (the SERIALIZED transaction size)")
    if isinstance(per_kb, bool) or not isinstance(per_kb, int) or per_kb <= 0:
        raise ValueError("per_kb must be a positive int")
    return -(-size_bytes * per_kb // 1000)  # ceil, integer-only


def relay_floor_photons_per_byte() -> int:
    """Radiant's effective relay floor expressed per BYTE.

    Derived from :data:`RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB` rather than
    written out, so a change to the floor moves every caller at once.
    """
    return RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB // 1000


def min_relay_fee(size_bytes: int) -> int:
    """The protocol relay floor for a ``size_bytes`` transaction, in photons."""
    return fee_for_kb_rate(size_bytes, RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB)


def _check_rate(fee_rate: int) -> None:
    if isinstance(fee_rate, bool) or not isinstance(fee_rate, int) or fee_rate <= 0:
        raise ValueError("fee_rate must be a positive int (photons per byte)")


def required_fee(size_bytes: int, fee_rate: int) -> int:
    """Photons a ``size_bytes`` transaction must pay at ``fee_rate`` photons/byte.

    **This binds the caller's rate and NOTHING ELSE.** Read that literally before
    relying on it — an earlier version of this docstring said it "binds BOTH
    floors", and that claim was false in the only direction that matters.

    The ``max`` below cannot raise anything at the current constants.
    ``RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB`` is 10_000_000, an exact multiple
    of 1000, so ``min_relay_fee(size) == size * 10_000`` with no rounding — and the
    branch is only reached when ``fee_rate >= 10_000``, where ``size * fee_rate`` is
    already ``>=`` that. Measured: **0 differences from ``size * fee_rate`` over
    200_000 random (size, rate) pairs**, and 0 over an exhaustive sweep of
    ``size`` 1..2999 against every rate within 3 of the floor. The ``max`` is kept
    because it stops being dead the moment the per-kB constant is not a multiple of
    1000 (``fee_for_kb_rate`` rounds up while ``relay_floor_photons_per_byte``
    rounds down), not because it is doing work today.

    So the protocol floor is enforced here *only* by the caller having chosen a
    ``fee_rate`` at or above it. A sub-floor rate is passed straight through, on the
    reading that it is a deliberate opt-out (regtest, or a chain the caller
    controls) — see the module docstring for why raising it instead would make
    every node-level proof of this code vacuous.

    That opt-out is only safe where ``fee_rate`` is trusted. It is a HOLE anywhere
    the rate can arrive unvalidated: ``required_fee(226, 1)`` is 226 photons against
    a mainnet requirement of 2_260_000, a factor of 10_000, and every downstream
    assertion built on this function agrees the result is fine. Callers must
    therefore gate the RATE themselves —
    :func:`assert_fee_rate_clears_relay_floor` at the entry point, or
    :func:`fee_never_below_relay_floor` in place of this function — rather than
    expecting this to catch it. ``pyrxd.wallet`` and ``pyrxd.hd.wallet`` do the
    former; ``pyrxd.cli.swap_book_cmds`` does the latter.
    """
    _check_rate(fee_rate)
    floor = min_relay_fee(size_bytes)  # also validates size_bytes
    at_rate = size_bytes * fee_rate
    if fee_rate < relay_floor_photons_per_byte():
        return at_rate
    return max(at_rate, floor)


def assert_fee_rate_clears_relay_floor(
    fee_rate: int,
    *,
    what: str,
    allow_below_relay_floor: bool = False,
    error_type: type[Exception] = ValueError,
) -> int:
    """Refuse a per-byte fee rate the network will not relay. Returns the rate.

    The one implementation of "is this rate even viable", shared by every builder
    that takes a ``fee_rate`` from a caller. It exists because :func:`required_fee`
    does **not** do this (see its docstring): a builder that validates only
    ``fee_rate > 0`` and then sizes with :func:`required_fee` will happily return a
    transaction 10_000x under the mainnet floor, and every guard downstream of it
    will agree the transaction is correct — because it is, at the rate it was asked
    for. The rate is the thing that has to be judged, and it can only be judged
    here, before any bytes exist.

    Radiant has neither RBF nor CPFP, so a sub-floor transaction cannot be bumped
    by any means: it squats on its own inputs until mempool expiry, 8 hours later.
    That makes a sub-floor rate a fund-safety bug rather than a tuning mistake,
    which is why this refuses instead of warning.

    ``allow_below_relay_floor`` is the deliberate, greppable escape hatch — named
    the same way as :attr:`~pyrxd.gravity.fee_policy.DeadlineFeePolicy.allow_below_protocol_floor`
    — for regtest and for chains the caller controls, which legitimately relay
    lower. It only skips the FLOOR; the rate still has to be a positive int.
    """
    _check_rate(fee_rate)
    floor_per_byte = relay_floor_photons_per_byte()
    if allow_below_relay_floor or fee_rate >= floor_per_byte:
        return fee_rate
    raise error_type(
        f"{what}: fee_rate must be >= {floor_per_byte} photons/byte (Radiant's effective relay floor of "
        f"{floor_per_byte * 1000} per kB), got {fee_rate}. A transaction built "
        "below the floor will not relay, and Radiant has no RBF and no CPFP — it cannot be "
        "fee-bumped and will hold its inputs until mempool expiry."
    )


def fee_never_below_relay_floor(size_bytes: int, fee_rate: int) -> int:
    """``max(size × fee_rate, protocol floor)`` with no opt-out.

    For callers whose rate crosses a trust boundary — a config file, an operator
    flag, an RPC reading — where "the caller meant it" is not a safe assumption.
    """
    _check_rate(fee_rate)
    return max(size_bytes * fee_rate, min_relay_fee(size_bytes))  # min_relay_fee validates size_bytes


def trial_size_with_slack(trial_size_bytes: int, n_inputs: int) -> int:
    """A trial-pass byte count plus :data:`SIG_SIZE_SLACK_BYTES` per input.

    Fee this, not the raw trial size, or the final pass's longer signatures are
    paid for by nobody.
    """
    if isinstance(n_inputs, bool) or not isinstance(n_inputs, int) or n_inputs < 0:
        raise ValueError("n_inputs must be a non-negative int")
    if isinstance(trial_size_bytes, bool) or not isinstance(trial_size_bytes, int) or trial_size_bytes <= 0:
        raise ValueError("trial_size_bytes must be a positive int")
    return trial_size_bytes + SIG_SIZE_SLACK_BYTES * n_inputs


def assert_pays_for_its_size(
    *,
    size_bytes: int,
    fee_paid: int,
    fee_rate: int,
    what: str,
    error_type: type[Exception] = ValueError,
) -> int:
    """Fail closed unless a SIGNED transaction pays for the bytes it actually contains.

    Call this on the **final** transaction, after the last :meth:`Transaction.sign`,
    with its measured serialized length — never on the trial pass, which is the
    mistake this whole module exists to prevent.

    ``error_type`` exists only so each caller keeps the exception class its own API
    already documents (``glyph.ft`` raises :class:`ValueError`, ``wallet`` raises
    :class:`~pyrxd.security.errors.ValidationError`); the check and the message are
    identical either way.

    :returns: the required fee, when it is covered.
    :raises error_type: when it is not. Raising costs an aborted build; returning
        instead costs the inputs for 8 hours, because the result cannot be
        fee-bumped on Radiant by any means.
    """
    required = required_fee(size_bytes, fee_rate)
    if fee_paid >= required:
        return required
    raise error_type(
        f"{what}: fee-sizing invariant violated — the built transaction is {size_bytes} bytes "
        f"and pays {fee_paid} photons, below the {required} photons required at {fee_rate} "
        f"photons/byte. Refusing to return a transaction the network will reject as "
        f"'min relay fee not met': Radiant has neither RBF nor CPFP, so it could not be "
        f"fee-bumped and would hold its inputs until mempool expiry, 8 hours later."
    )


def assert_tx_pays_for_itself(
    tx: Transaction,
    fee_rate: int,
    *,
    what: str,
    error_type: type[Exception] = ValueError,
) -> int:
    """:func:`assert_pays_for_its_size` sourced from the transaction itself.

    Uses the transaction's own serialized length and its own
    ``total_value_in - total_value_out``, so the number checked is the number the
    node will compute and the number ``get_fee()`` reports to the caller. Requires
    every input to carry a ``source_transaction``.
    """
    return assert_pays_for_its_size(
        size_bytes=tx.byte_length(),
        fee_paid=tx.get_fee(),
        fee_rate=fee_rate,
        what=what,
        error_type=error_type,
    )
