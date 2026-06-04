"""Private-inclusion transport for the ETH claim — keep the secret ``p`` out of the public mempool.

The maker's ETH claim is the ONE tx that reveals the preimage ``p``. In the public mempool, ``p``
is visible the instant the claim is broadcast — before it mines — letting anyone (incl. a hostile
taker, or an MEV searcher) read ``p`` and act on the RXD leg while the ETH claim is still
reorg-able. Submitting the claim via a private relay (Flashbots Protect / a builder's private
mempool) closes that window: ``p`` only becomes public when the claim actually lands in a block.

This module provides the ``PrivateSubmitter`` protocol (one method, ``submit_raw``) and a
``FlashbotsSubmitter`` that POSTs the signed raw tx to a Flashbots-style ``eth_sendPrivateRawTransaction``
endpoint. It is OPTIONAL and INJECTED — ``EthHtlcContractLeg`` falls back to the public path when no
submitter is supplied (the operator then explicitly accepts public-mempool exposure). aiohttp +
``eth_account`` are imported lazily so ``eth_wallet`` still loads with no extra deps.

NOTE (Phase-4 / audit): the Flashbots Protect RPC authenticates each request with an
``X-Flashbots-Signature`` header = ``<signing_addr>:<EIP-191 personal_sign of keccak(body)>``. This
submitter builds that header from an injected auth key. The relay URL, the auth-key handling, and
the exact bundle/private-tx semantics (target block, fast vs. max-privacy, refund recipient) are
operator config — pin and review them against the live Flashbots docs before any mainnet use.
"""

from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

__all__ = ["FlashbotsSubmitter", "PrivateSubmitter"]

_MAX_RESP_BYTES = 64 * 1024


@runtime_checkable
class PrivateSubmitter(Protocol):
    """Submit a SIGNED raw tx privately and return its tx hash (0x-hex).

    The one method ``EthHtlcContractLeg`` needs: it hands over the already-signed raw tx bytes for
    the claim and gets back the tx hash, exactly like ``EthRpc.send_raw`` — but off the public
    mempool. Any object with this method can be injected (a real Flashbots client, a builder's
    private endpoint, or a test fake)."""

    async def submit_raw(self, raw_tx: bytes) -> str: ...


def _require_aiohttp():
    try:
        import aiohttp  # type: ignore

        return aiohttp
    except ImportError as exc:  # pragma: no cover - exercised only without the extra installed
        raise ValidationError("FlashbotsSubmitter needs aiohttp (a network dependency); install the eth extra") from exc


def _require_eth_account():
    try:
        from eth_account import Account  # type: ignore
        from eth_account.messages import encode_defunct  # type: ignore

        return Account, encode_defunct
    except ImportError as exc:  # pragma: no cover
        raise ValidationError("FlashbotsSubmitter needs eth_account; install the eth extra") from exc


class FlashbotsSubmitter:
    """Submit the claim via a Flashbots-style private-tx RPC (``eth_sendPrivateRawTransaction``).

    ``relay_url`` is the private endpoint (e.g. ``https://rpc.flashbots.net/fast``). ``auth_key`` is
    a ``PrivateKeyMaterial`` used ONLY to sign the ``X-Flashbots-Signature`` request header — it is
    NOT the tx signing key and need not hold funds (Flashbots uses it as a stable searcher identity
    / reputation key). The tx itself is already signed by the leg's key before it reaches here.

    Fail-closed (``NetworkError``) on any transport/relay error: the caller (the coordinator's
    maker-claim step) must NOT treat a failed private submit as a successful reveal.
    """

    def __init__(self, *, relay_url: str, auth_key: PrivateKeyMaterial, timeout_s: float = 10.0) -> None:
        if not isinstance(relay_url, str) or not relay_url.startswith(("http://", "https://")):
            raise ValidationError("relay_url must be an http(s) URL")
        if not isinstance(auth_key, PrivateKeyMaterial):
            raise ValidationError("auth_key must be PrivateKeyMaterial")
        if not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
            raise ValidationError("timeout_s must be > 0")
        self._url = relay_url
        self._auth_key = auth_key
        self._timeout_s = float(timeout_s)

    def _sign_header(self, body: str) -> str:
        """``X-Flashbots-Signature: <addr>:<EIP-191 personal_sign(keccak256(body) hex)>``.

        Flashbots authenticates on the 0x-PREFIXED hex string of keccak256(body) (red-team MEDIUM:
        ``Web3.keccak(...).hex()`` is UNPREFIXED on this web3, so the prior header signed the wrong
        message and a real relay rejected every private claim — silently disabling the anti-front-run
        defense). We also derive the signer address via the project's own ``derive_address`` rather
        than materializing a plaintext ``eth_account`` LocalAccount (keys.py forbids that escape)."""
        from pyrxd.eth_wallet.keys import derive_address

        Account, encode_defunct = _require_eth_account()
        from web3 import Web3  # type: ignore

        kh = Web3.keccak(text=body).hex()
        digest = kh if kh.startswith("0x") else "0x" + kh  # Flashbots signs the 0x-prefixed hex
        addr = derive_address(self._auth_key)  # no plaintext LocalAccount
        raw = self._auth_key.unsafe_raw_bytes()
        try:
            signed = Account.sign_message(encode_defunct(text=digest), raw)
        finally:
            del raw  # best-effort: drops OUR reference only. `raw` is an immutable `bytes`, so this
            # does NOT zeroize the key buffer (CPython cannot mutate it in place, and eth_account
            # may have copied it internally) — it just lets the GC reclaim it sooner. True
            # zeroization would need a mutable bytearray + an explicit wipe end-to-end; this is the
            # auth/identity key (not the tx key) and never holds funds, so reference-drop is the
            # accepted hygiene here (red-team INFO).
        sig = signed.signature.hex()
        sig = sig if sig.startswith("0x") else "0x" + sig
        return f"{addr}:{sig}"

    async def submit_raw(self, raw_tx: bytes) -> str:
        """Submit ``raw_tx`` privately; return its tx hash.

        NOTE (red-team MEDIUM): a successful submit is NOT inclusion — a relay can ACK and drop the
        tx. The caller MUST drive maker-side confirmation (wait_receipt / finality) before treating
        the reveal as durable; do not infer 'p is on-chain' from this returning. We DO verify the
        relay-returned hash equals keccak256(raw_tx) locally (catches a buggy/wrong-hash relay,
        matching the public ``send_raw`` guarantee that the node computes the hash from the bytes)."""
        if not isinstance(raw_tx, (bytes, bytearray)) or len(raw_tx) == 0:
            raise ValidationError("raw_tx must be non-empty bytes")
        aiohttp = _require_aiohttp()
        raw_hex = "0x" + bytes(raw_tx).hex()
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_sendPrivateRawTransaction", "params": [raw_hex]})
        headers = {"Content-Type": "application/json", "X-Flashbots-Signature": self._sign_header(body)}
        timeout = aiohttp.ClientTimeout(total=self._timeout_s)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self._url, data=body, headers=headers) as resp:
                    payload = await resp.content.read(_MAX_RESP_BYTES + 1)
                    if len(payload) > _MAX_RESP_BYTES:
                        raise NetworkError("flashbots response exceeds size cap")
                    if resp.status != 200:
                        raise NetworkError(f"flashbots relay HTTP {resp.status}: {payload[:200]!r}")
        except NetworkError:
            raise
        except Exception as exc:
            raise NetworkError(f"flashbots private submit failed: {exc}") from exc
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise NetworkError(f"flashbots relay returned non-JSON: {payload[:200]!r}") from exc
        if "error" in data:
            raise NetworkError(f"flashbots relay error: {data['error']}")
        tx_hash = data.get("result")
        if not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
            raise NetworkError(f"flashbots relay returned no tx hash: {data!r}")
        # Bind the returned hash to the bytes we signed (catches a wrong-hash relay).
        from web3 import Web3  # type: ignore

        expected = "0x" + bytes(Web3.keccak(bytes(raw_tx))).hex().removeprefix("0x")
        if tx_hash.lower() != expected.lower():
            raise NetworkError(f"flashbots relay returned hash {tx_hash} != keccak256(raw_tx) {expected}")
        return tx_hash
