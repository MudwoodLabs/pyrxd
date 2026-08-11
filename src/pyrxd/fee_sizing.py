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
``wallet.py``), and this repo has a measured history of the same rule drifting
apart across copies.

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

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .transaction.transaction import Transaction

__all__ = [
    "RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB",
    "RADIANT_MIN_RELAY_PHOTONS_PER_KB",
    "SIG_SIZE_SLACK_BYTES",
    "assert_pays_for_its_size",
    "assert_tx_pays_for_itself",
    "fee_for_kb_rate",
    "fee_never_below_relay_floor",
    "min_relay_fee",
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

    Binds BOTH floors — the caller's rate and the chain's — except that a
    ``fee_rate`` already below the protocol floor is read as a deliberate opt-out
    (regtest, or a chain the caller controls) and only the caller's rate binds. See
    the module docstring for why that opt-out is not a hole: raising a regtest fee
    to the mainnet floor would make every node-level proof of this code vacuous,
    since the node could then never reject anything it built.
    """
    _check_rate(fee_rate)
    floor = min_relay_fee(size_bytes)  # also validates size_bytes
    at_rate = size_bytes * fee_rate
    if fee_rate < relay_floor_photons_per_byte():
        return at_rate
    return max(at_rate, floor)


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
