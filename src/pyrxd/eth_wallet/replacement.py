"""Pricing a REPLACEMENT transaction — same nonce, enough more fee that a node accepts it.

A resume that finds its own push still pending cannot simply rebuild and re-send: an
identically-priced transaction at an already-used nonce is rejected as ``transaction already
imported``, which is exactly what the crash-resume run measured (#515). Replacing it requires
raising the fee, and EIP-1559 requires raising BOTH fields:

* ``maxFeePerGas`` and
* ``maxPriorityFeePerGas``

by at least a node-configured percentage. Geth's default is 10% (``txpool.pricebump``), and other
clients use the same figure, so 10% is the floor a replacement must clear rather than a suggestion.

WHY THE EXISTING HEADROOM KNOB CANNOT DO THIS. ``EthHtlcContractLeg._base_tx`` takes a
``basefee_headroom`` that scales the basefee share of ``maxFeePerGas`` and documents itself as
touching "never the tip". A resend through it carries an unchanged ``maxPriorityFeePerGas``, so it
is not a replacement at any headroom — the bump has to be explicit and cover both fields.

This module is pure arithmetic. It does not read a chain, choose when to replace, or decide that
replacing is safe; those are the caller's, and on a funding path the caller must also hold a
durable nonce pin so the replacement lands on the SAME slot rather than adding a second transfer.
"""

from __future__ import annotations

import math
from fractions import Fraction

from pyrxd.security.errors import ValidationError

__all__ = ["MIN_REPLACEMENT_BUMP_PCT", "bump_replacement_fees", "clears_replacement_bump"]

#: The percentage a replacement must exceed the pending transaction's fees by, on BOTH fields.
#: Geth's `txpool.pricebump` default, matched by other clients — a floor, not a preference.
MIN_REPLACEMENT_BUMP_PCT = 10

#: What we actually apply. Above the floor because the comparison happens at the node against the
#: transaction IT holds, and a bump computed to land exactly on the boundary loses to integer
#: truncation somewhere in that path. Cheap insurance: the difference is paid only on a replacement.
DEFAULT_BUMP_PCT = 13


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValidationError(f"{name} must be > 0, got {value}")
    return value


def clears_replacement_bump(new: int, previous: int, *, pct: int = MIN_REPLACEMENT_BUMP_PCT) -> bool:
    """Would ``new`` clear ``previous`` by ``pct``, the way a node compares them?

    ``new >= previous * (100 + pct) / 100``, exactly. Float arithmetic here is the one thing that
    turns a bump computed as sufficient into one the node rejects, so the comparison is done over
    integers.
    """
    _positive_int("previous", previous)
    if isinstance(new, bool) or not isinstance(new, int):
        raise ValidationError("new must be an int")
    return new * 100 >= previous * (100 + _positive_int("pct", pct))


def bump_replacement_fees(previous: dict[str, int], *, pct: int = DEFAULT_BUMP_PCT) -> dict[str, int]:
    """Fee fields that replace ``previous`` — BOTH raised by ``pct``, rounded UP.

    ``previous`` is the PENDING transaction's own fields, not the current network estimate. A bump
    computed against a fresh estimate can come out BELOW what is already pending when fees have
    fallen, and the node then rejects the replacement while the caller believes it raised the
    price — the failure mode is silent and looks like the node misbehaving.

    Rounded up because landing a fraction under the threshold is rejected outright; there is no
    partial credit for nearly clearing it.
    """
    if not isinstance(previous, dict):
        raise ValidationError("previous must be the pending transaction's fee fields")
    missing = [k for k in ("maxFeePerGas", "maxPriorityFeePerGas") if k not in previous]
    if missing:
        raise ValidationError(
            f"previous is missing {', '.join(missing)} — a replacement must raise BOTH fields, so "
            "both must be read off the pending transaction"
        )
    pct = _positive_int("pct", pct)
    if pct < MIN_REPLACEMENT_BUMP_PCT:
        raise ValidationError(
            f"pct {pct} is below the {MIN_REPLACEMENT_BUMP_PCT}% a node requires; a smaller bump "
            "builds a transaction that will be rejected as underpriced"
        )
    out = dict(previous)
    for field in ("maxFeePerGas", "maxPriorityFeePerGas"):
        prev = _positive_int(field, previous[field])
        out[field] = math.ceil(Fraction(prev) * Fraction(100 + pct, 100))
        if not clears_replacement_bump(out[field], prev):  # pragma: no cover - arithmetic guard
            raise ValidationError(f"bumped {field} does not clear the replacement threshold")
    if out["maxPriorityFeePerGas"] > out["maxFeePerGas"]:
        raise ValidationError(
            f"bumped tip {out['maxPriorityFeePerGas']} exceeds maxFeePerGas {out['maxFeePerGas']}: "
            "the pending transaction's fields were already inconsistent, so no valid replacement "
            "exists for them"
        )
    return out
