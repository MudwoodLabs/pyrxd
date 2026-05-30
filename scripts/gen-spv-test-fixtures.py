"""Pre-mine PoW headers for the SPV test suite's synthetic-block tests.

The two slow tests in ``tests/test_spv.py`` (``test_builder_full_success_synthetic_block``
and ``test_builder_rejects_insufficient_payment``) need a header whose
double-SHA256 hash beats a real difficulty target. Mining one in-process
takes ~5-30s each, dominating the entire pyrxd test suite (~33s).

This script grinds the headers once and saves the nonces (plus the full
header bytes for verification) to a JSON fixture committed under
``tests/fixtures/spv_synthetic_headers.json``. The test class loads from
that fixture on every run; mining only runs as a fallback when the
fixture is missing or no longer satisfies the verifier.

Regenerate manually with:

    python scripts/gen-spv-test-fixtures.py

Each (satoshis, hash20) tuple in :data:`FIXTURES_TO_GENERATE` produces
one fixture entry. Add entries here if the test suite gains new
synthetic-block tests with different inputs.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

# Import grinder + verifier from pyrxd source. Run this script from the
# repo root with the dev venv active.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pyrxd.security.errors import SpvVerificationError
from pyrxd.spv import verify_header_pow

# Match exactly the static parameters used by tests/test_spv.py:
#   - version = 0x20000000 (LE)
#   - prev / anchor = b"\x99" * 32
#   - nbits = 0x1d7fffff (LE: ff ff 7f 1d) — large target, exponent 0x1d
#   - time = 0
#   - merkle_root = hash256(b"\xab"*32 || hash256(raw_tx))
HEADER_VERSION = b"\x00\x00\x00\x20"
HEADER_ANCHOR = b"\x99" * 32
HEADER_NBITS = b"\xff\xff\x7f\x1d"
HEADER_TIME = b"\x00\x00\x00\x00"

MERKLE_SIBLING_LE = b"\xab" * 32


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def p2pkh_output(satoshis: int, hash20: bytes) -> bytes:
    """Match tests/test_spv.py:_p2pkh_output exactly."""
    if len(hash20) != 20:
        raise ValueError(f"hash20 must be 20 bytes, got {len(hash20)}")
    # value (8 bytes LE) + script_len + OP_DUP OP_HASH160 <push 20> <pkh> OP_EQUALVERIFY OP_CHECKSIG
    script = b"\x76\xa9\x14" + hash20 + b"\x88\xac"
    return satoshis.to_bytes(8, "little") + bytes([len(script)]) + script


def build_raw_tx(satoshis: int, hash20: bytes) -> tuple[bytes, bytes]:
    """Build the synthetic raw tx + compute its txid_le. Mirrors test helper."""
    payment_output = p2pkh_output(satoshis, hash20)
    raw_tx = (
        b"\x01\x00\x00\x00"  # version
        + b"\x01"  # 1 input
        + b"\xaa" * 32  # prev txid (non-null; the null outpoint is coinbase-only, audit F-04)
        + b"\xff\xff\xff\xff"  # prev vout
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # sequence
        + b"\x01"  # 1 output
        + payment_output
        + b"\x00\x00\x00\x00"  # locktime
    )
    return raw_tx, hash256(raw_tx)


def grind_header(merkle_root_le: bytes, max_tries: int = 100_000_000) -> tuple[bytes, int]:
    """Grind a nonce until the header passes the verifier. Returns (header, nonce)."""
    base = HEADER_VERSION + HEADER_ANCHOR + merkle_root_le + HEADER_TIME + HEADER_NBITS
    for nonce in range(max_tries):
        header = base + nonce.to_bytes(4, "little")
        h = hash256(header)
        # Fast gate before the full verifier: last 3 LE bytes must be 0
        # (PoW target has 3 leading-zero BE bytes for exponent 0x1d / mantissa 0x7fffff)
        if h[29] == 0 and h[30] == 0 and h[31] == 0:
            try:
                verify_header_pow(header)
                return header, nonce
            except SpvVerificationError:
                continue
    raise RuntimeError(f"could not grind header in {max_tries} tries")


# All (satoshis, hash20_hex) tuples used by synthetic-block tests today.
# Keep this in sync with tests/test_spv.py call sites of _build_synthetic_proof_inputs.
FIXTURES_TO_GENERATE: list[tuple[int, str]] = [
    (5000, "77" * 20),  # test_builder_full_success_synthetic_block + 2 sibling tests
    (500, "77" * 20),  # test_builder_rejects_insufficient_payment
]

OUTPUT_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "spv_synthetic_headers.json"


def main() -> None:
    out: dict = {
        "_meta": {
            "generated_by": "scripts/gen-spv-test-fixtures.py",
            "purpose": (
                "Pre-mined PoW headers for tests/test_spv.py synthetic-block tests. "
                "Saves ~33s on every test run. Regenerate if SPV protocol or verifier "
                "semantics change."
            ),
            "header_params": {
                "version_le_hex": HEADER_VERSION.hex(),
                "anchor_hex": HEADER_ANCHOR.hex(),
                "nbits_le_hex": HEADER_NBITS.hex(),
                "time_le_hex": HEADER_TIME.hex(),
                "merkle_sibling_le_hex": MERKLE_SIBLING_LE.hex(),
            },
            "fixture_count": len(FIXTURES_TO_GENERATE),
        },
        "fixtures": [],
    }

    for satoshis, hash20_hex in FIXTURES_TO_GENERATE:
        hash20 = bytes.fromhex(hash20_hex)
        _raw_tx, txid_le = build_raw_tx(satoshis, hash20)
        merkle_root_le = hash256(MERKLE_SIBLING_LE + txid_le)

        print(f"grinding (satoshis={satoshis}, hash20={hash20_hex})...", flush=True)
        t0 = time.time()
        header, nonce = grind_header(merkle_root_le)
        dt = time.time() - t0
        print(f"  found nonce={nonce} in {dt:.1f}s", flush=True)

        out["fixtures"].append(
            {
                "satoshis": satoshis,
                "hash20_hex": hash20_hex,
                "nonce": nonce,
                "header_hex": header.hex(),
                "header_hash256_le_hex": hash256(header).hex(),
                "grind_seconds": round(dt, 2),
            }
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(out, indent=2) + "\n")
    print(f"\nwrote {OUTPUT_PATH}")
    print(
        f"  {len(out['fixtures'])} fixtures, total grind time: {sum(f['grind_seconds'] for f in out['fixtures']):.1f}s"
    )


if __name__ == "__main__":
    main()
