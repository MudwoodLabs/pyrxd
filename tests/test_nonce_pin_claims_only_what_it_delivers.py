"""The nonce pin delivers exactly-once by REJECTION, not by replacement (#515).

The pin's comment used to assert that a higher-priced transaction at the same nonce "REPLACES
rather than adds — so ... a resume racing its own still-pending push, deliver[s] the value exactly
once". Two things stop that path being reached, and this pins both so the claim cannot come back.
"""

from __future__ import annotations

import inspect

from pyrxd.eth_wallet import erc20_leg, htlc_leg


def test_the_inflight_guard_refuses_the_very_case_replacement_would_serve() -> None:
    """`pending > latest` IS "racing its own still-pending push". The resume stops there, so no
    replacement is ever built — which is why the comment could assert an untested property."""
    src = inspect.getsource(erc20_leg.Erc20HtlcLeg._push_and_bind)
    assert "pending_nonce > latest_nonce" in src
    assert "still in flight" in src


def test_basefee_headroom_cannot_form_a_valid_replacement() -> None:
    """EIP-1559 requires BOTH maxFeePerGas and maxPriorityFeePerGas to rise (geth: >= 10%).

    `_base_tx` documents itself as scaling the basefee share and "never the tip", so a resend
    through it carries an unchanged tip and is not a replacement — matching the measured
    "transaction already imported". Pinned as a property of the helper rather than a comment,
    because the comment was the thing that was wrong.
    """
    src = inspect.getsource(htlc_leg.EthHtlcContractLeg._base_tx)
    assert "never the tip" in src
    assert "maxPriorityFeePerGas" in src
    tip_lines = [ln for ln in src.splitlines() if "maxPriorityFeePerGas" in ln and "=" in ln]
    assert not any("headroom" in ln for ln in tip_lines), (
        "the tip is now scaled by the headroom — if a real bumped-replacement path was added, "
        "revisit the nonce-pin comment in erc20_leg, which states replacement is NOT reachable"
    )


def test_the_push_tx_hash_IS_now_durable_so_a_replacement_can_be_priced() -> None:
    """This test previously asserted the OPPOSITE, and was written to fail when it stopped being
    true — which is what happened.

    It read: "a bumped replacement must clear the PENDING transaction's fees by a margin, which
    means reading it — and only the nonce is persisted", with a failure message telling whoever
    saw it red that the blocker on #515's carve-out was gone. It is: `pending_push_tx_hash` is
    recorded before the broadcast, so `eth_getTransactionByHash` is available on resume, and
    `pyrxd.eth_wallet.replacement` prices the bump.

    WHAT REMAINS is the carve-out itself — relaxing the in-flight guard for the case
    `pending == push_nonce + 1 and latest == push_nonce`, where the pending transaction provably
    IS our own pinned push. Both ingredients now exist; nothing yet consumes them together.
    """
    from pyrxd.gravity.swap_state import SwapRecord

    fields = set(getattr(SwapRecord, "__dataclass_fields__", {}))
    assert "pending_push_nonce" in fields
    assert "pending_push_tx_hash" in fields, "the durable push hash went away; #515 is blocked again"


def test_the_comment_no_longer_claims_replacement() -> None:
    """The specific regression: the old text asserted a property the surrounding code prevents."""
    src = inspect.getsource(erc20_leg.Erc20HtlcLeg._push_and_bind)
    assert "REPLACES rather than adds" not in src.split("WHAT THIS DOES NOT DO")[0], (
        "the pin comment asserts replacement again, above its own correction"
    )
    assert "the chain REJECTING the duplicate" in src
