"""What an ETH counter leg's disposition is read with, for one record (#850 PR 10).

One builder for the coordinator (:meth:`pyrxd.gravity.swap_coordinator.SwapCoordinator._read_counter_disposition`)
and the watchtower's keyless source (:class:`pyrxd.gravity.watch.eth_adapters.RpcEthChainSource`), so
the two ask the shared reader (:func:`pyrxd.eth_wallet.disposition.read_counter_disposition`) the
same question about the same record.
"""

from __future__ import annotations

from typing import Any

from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.gravity.swap_state import SwapRecord, parse_expiry_anchor

__all__ = ["eth_counter_disposition_kwargs", "push_nonce_bound"]


def push_nonce_bound(record: SwapRecord) -> int | None:
    """The highest nonce at which *record*'s key signed a token push for the counter-leg contract,
    or a transaction closing that nonce (design §2.7): ``None`` when neither is recorded (a record
    from before the push nonce was kept)."""
    nonces = [n for n in (record.pending_push_nonce, record.push_close_nonce) if n is not None]
    return max(nonces) if nonces else None


def eth_counter_disposition_kwargs(record: SwapRecord) -> dict[str, Any]:
    """What an ETH counter leg's ``counter_disposition`` is asked with for *record*, beside the
    locator: the one place it is built, for the coordinator (``SwapCoordinator._read_counter_disposition``)
    and the watchtower's keyless source alike (#850 PR 10), so the two read the same evidence.

    Our own recorded refund is nominated alongside the logs, and the expiry anchor offered as a proof
    of refund (#850 PR 5b). Passed only when set, so a leg without them still reads. The token
    arguments (PR 7a) are passed for every token record that needs them: a leg that does not take
    them fails (TypeError) rather than reading without them."""
    kwargs: dict[str, Any] = {}
    if record.counter_refund_tx_hash is not None:
        # Every refund we signed, not only the newest: an earlier one at the same nonce may be the
        # one that mined, and with no log returned its hash is the only proof (Mythos, #894 F1).
        kwargs["recorded_refund_hashes"] = (record.counter_refund_tx_hash, *record.counter_refund_replaced_tx_hashes)
    if record.counter_expiry_anchor is not None:
        kwargs["expiry_anchor"] = parse_expiry_anchor(record.counter_expiry_anchor)
    if record.counter_claim_tx is not None:
        # A claim seen earlier is nominated by its hash, so it is verified by its receipt when its log
        # is no longer served (Mythos review of #850 PR 7b, F1).
        kwargs["recorded_claim_hashes"] = (record.counter_claim_tx,)
    if isinstance(record.counterchain_locator, Erc20HtlcLocator):
        # #850 PR 7a: the highest nonce a push for this contract (or our close of it) was signed
        # at, and the key that signed the push. With no push nonce recorded the close is the only
        # bound, and closing needs the key idle at every endpoint (design §2.7).
        bound = push_nonce_bound(record)
        if bound is not None:
            kwargs["push_nonce_bound"] = bound
        if record.push_signer is not None:
            kwargs["push_signer"] = record.push_signer
        if record.pending_push_nonce is None:
            kwargs["nonce_less"] = True
    return kwargs
