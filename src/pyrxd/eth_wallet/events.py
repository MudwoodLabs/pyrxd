"""Event topic0 values of the canonical ETH counter-leg contracts, DERIVED from their signatures.

``contracts/EthHtlc.sol`` and ``contracts/Erc20Htlc.sol`` both declare ``event Claimed(bytes32)``
and ``event Refunded()``. An event's ``topic0`` is the Ethereum **Keccak-256** of its canonical
signature — the pre-NIST padding variant, NOT ``hashlib.sha3_256``. The two produce different
digests for the same input, and the difference is invisible at a glance: a 32-byte hex string
either way. ``scripts/swap_run_verify.py`` once pinned ``sha3_256`` values typed by hand, so it
never recognised a real claim or refund. Computing the topics here, from the signature, with the
Keccak primitive, means there is no literal to mistype; ``tests/test_eth_event_topics.py`` checks
the result against the PUSH32 operands of both shipped runtimes.

This module is web3-free (``pycryptodomex`` is a base dependency), so the base install, the
watchtower and the run verifier can all import it without the ``[eth]`` extra.
"""

from __future__ import annotations

__all__ = [
    "CLAIMED_EVENT_SIGNATURE",
    "CLAIMED_TOPIC0",
    "REFUNDED_EVENT_SIGNATURE",
    "REFUNDED_TOPIC0",
    "event_topic0",
    "function_selector",
    "keccak256",
]

#: The canonical event signatures, exactly as the ABI encodes them (no spaces, no parameter names).
CLAIMED_EVENT_SIGNATURE = "Claimed(bytes32)"
REFUNDED_EVENT_SIGNATURE = "Refunded()"


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 (NOT NIST SHA3-256 — ``hashlib.sha3_256`` is the wrong function here)."""
    from Cryptodome.Hash import keccak  # pycryptodomex — a base dependency, not the [eth] extra

    return keccak.new(digest_bits=256, data=bytes(data)).digest()


def event_topic0(signature: str) -> str:
    """The 0x-prefixed lower-case ``topic0`` of a non-anonymous event: ``keccak256(signature)``."""
    return "0x" + keccak256(signature.encode("ascii")).hex()


def function_selector(signature: str) -> bytes:
    """The 4-byte ABI function selector: ``keccak256(signature)[:4]``."""
    return keccak256(signature.encode("ascii"))[:4]


#: ``keccak256("Claimed(bytes32)")`` — the claim event; ``p`` is in the (non-indexed) log data.
CLAIMED_TOPIC0 = event_topic0(CLAIMED_EVENT_SIGNATURE)
#: ``keccak256("Refunded()")`` — the refund event; emitted when the maker did NOT reveal ``p``.
REFUNDED_TOPIC0 = event_topic0(REFUNDED_EVENT_SIGNATURE)
