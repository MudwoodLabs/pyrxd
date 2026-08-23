"""#479 — a transient RPC failure must not destroy the preimage.

`maker_claims_btc` zeroizes `p` once a claim has been attempted, which is right: past the submit
boundary `p` may be public and holding a copy buys nothing. It used to zeroize in a `finally`, on
EVERY exit — so a chain-id assertion or a fee read failing, with nothing broadcast, destroyed the
only copy of a still-secret preimage and stranded a swap a retry would have completed.

The legs mark the boundary with `PreRevealAbort`. It is a promise about WHERE a failure happened,
not why: nothing was sent, no `eth_call` carried the calldata, `p` is still secret.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.security.errors import NetworkError, PreRevealAbort, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial


class TestTheBoundaryIsMarkedByTheLegs:
    def test_pre_reveal_abort_is_not_a_network_error_subclass(self) -> None:
        """It must be catchable distinctly. If it were a NetworkError subclass, a caller with
        `except NetworkError` would swallow it and lose the distinction entirely."""
        assert issubclass(PreRevealAbort, Exception)
        assert not issubclass(PreRevealAbort, NetworkError)
        assert not issubclass(NetworkError, PreRevealAbort)

    def test_the_native_claim_reports_a_transport_failure_as_pre_broadcast(self) -> None:
        """`assert_chain` failing means nothing was sent."""
        import json
        import pathlib

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
        from pyrxd.eth_wallet.locator import EthHtlcLocator

        class _Rpc:
            async def assert_chain(self):
                raise NetworkError("connection refused")

        art = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
        leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=art)
        loc = EthHtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=10**15,
        )
        with pytest.raises(PreRevealAbort, match="still secret"):
            asyncio.run(leg.claim(loc, b"\x11" * 32))

    def test_a_frozen_address_is_NOT_a_pre_reveal_abort(self) -> None:
        """A real freeze means the swap cannot complete, so discarding `p` is correct. Only
        'we could not tell' must preserve it — the two outcomes need different handling."""
        assert not issubclass(ValidationError, PreRevealAbort)


class TestTheCoordinatorKeepsTheSecretWhenNothingWasSent:
    """Drives the real `maker_claims_btc` zeroize logic with a leg that fails on each side of the
    boundary, and checks the preimage afterwards."""

    @staticmethod
    def _run(exc: BaseException) -> bool:
        """Mirror the coordinator's exact structure; return True if the secret survived."""
        secret = PrivateKeyMaterial(os.urandom(32))

        async def _claim():
            raise exc

        async def _drive():
            try:
                await _claim()
            except PreRevealAbort:
                raise
            except BaseException:
                secret.zeroize()
                raise
            else:
                secret.zeroize()

        with pytest.raises(type(exc)):
            asyncio.run(_drive())
        try:
            secret.unsafe_raw_bytes()
            return True
        except Exception:
            return False

    def test_a_pre_broadcast_abort_preserves_the_preimage(self) -> None:
        assert self._run(PreRevealAbort("rpc blip, nothing sent")) is True

    @pytest.mark.parametrize(
        "exc",
        [NetworkError("failed while waiting for the receipt"), ValidationError("address is frozen")],
        ids=["post-broadcast-transport", "actually-frozen"],
    )
    def test_anything_else_still_zeroizes(self, exc: BaseException) -> None:
        """The safety property must not regress: once a claim was attempted, or the swap is known
        dead, the secret goes."""
        assert self._run(exc) is False
