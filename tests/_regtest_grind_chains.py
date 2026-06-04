#!/usr/bin/env python3
"""Parallel pre-grinder for the regtest covenant-validation matrix
(``tests/test_spv_covenant_differential_regtest.py``).

Grinds every distinct 12-header anchored chain the V/NB/M/S cases need and caches
each to ``/tmp/rgt_chain_<txid>_<nbits>_<nlevels>.json``. Run ONCE before the
integration test; the test reads the caches. Heavy (exp-0x1d, 2^24 gate) and light
(exp 0x1e-0x20) chains grind in a process pool across all cores. Idempotent: skips a
chain whose cache already exists. Underscore-prefixed so pytest does not collect it.

Cache contract (read by the test's ``_chain()``):
  { "headers_hex":[12], "merkle_be":[N sib BE-hex], "pos":1, "n_levels":N }

Run:  python tests/_regtest_grind_chains.py   (from the repo root, or anywhere)
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys

# Make the repo importable regardless of CWD (repo root for `tests`, repo/src for
# `pyrxd`), derived from this file's location and front-inserted so the repo wins.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(_ROOT, "src"), _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pyrxd.spv.merkle import build_branch, compute_root
from pyrxd.spv.payment import P2WPKH
from pyrxd.spv.pow import hash256
from tests.test_spv_covenant_differential_deployed import _SPK, MAKER20, _build

_ANCHOR = b"\x99" * 32
_HEADERS = 12


def _target_be(nbits: bytes) -> bytes:
    """Covenant-style target reconstruction (valid for exponent 3..32)."""
    exp = nbits[3]
    return (bytes(exp - 3) + nbits[0:3] + bytes(32 - exp))[::-1]


def _grind_header(prev_hash: bytes, merkle_root_le: bytes, nbits: bytes) -> bytes:
    """Grind one 80-byte header whose hash256 (BE) < target(nbits)."""
    base = b"\x00\x00\x00\x20" + prev_hash + merkle_root_le + b"\x00\x00\x00\x00" + nbits
    tgt = _target_be(nbits)
    zero_bytes = max(0, 0x20 - nbits[3])  # adaptive pre-gate: exp 0x1d->3, 0x1e->2, 0x1f->1, 0x20->0
    for nonce in range(1 << 31):
        h = base + nonce.to_bytes(4, "little")
        d = hash256(h)  # LE digest; BE bytes are d[31], d[30], ...
        if zero_bytes and any(d[31 - k] != 0 for k in range(zero_bytes)):
            continue
        if d[::-1] < tgt:
            return h
    raise RuntimeError("could not grind header")


def grind_one(spec: tuple) -> str:
    label, value, nbits_hex, n_levels = spec
    nbits = bytes.fromhex(nbits_hex)
    raw = _build([b""], [(value, _SPK[P2WPKH](MAKER20))])
    txid_le = hash256(raw)
    txid_be_hex = txid_le[::-1].hex()
    path = f"/tmp/rgt_chain_{txid_le.hex()}_{nbits_hex}_{n_levels}.json"
    if os.path.exists(path):
        return f"{label}: cached"

    sibs_be = [(bytes([0xAB if n_levels == 1 else (0xA0 + i)]) * 32)[::-1].hex() for i in range(n_levels)]
    branch = build_branch(sibs_be, pos=1)
    root_le = compute_root(txid_be_hex, branch)

    headers, prev = [], _ANCHOR
    for i in range(_HEADERS):
        hdr = _grind_header(prev, root_le if i == 0 else b"\x77" * 32, nbits)
        headers.append(hdr)
        prev = hash256(hdr)

    with open(path, "w") as f:
        json.dump({"headers_hex": [h.hex() for h in headers], "merkle_be": sibs_be, "pos": 1, "n_levels": n_levels}, f)
    return f"{label}: ground {path}"


# (label, output-0 value, nBits hex, merkle levels)
_CHAINS = [
    ("s1", 100_000, "ffff7f1d", 1),
    ("v1", 4_294_967_296, "ffff7f1d", 1),  # 5 sig bytes (2^32)
    ("v2", 2_100_000_000_000_000, "ffff7f1d", 1),  # 7 sig bytes (MAX_MONEY 21M BTC)
    ("v3", 2_000_000_000_000_000, "ffff7f1d", 1),  # 7 sig bytes
    ("v4", 0x7F00000000000000, "ffff7f1d", 1),  # 8 sig bytes, bit-63 clear
    ("v4ctrl", 0x8000000000000000, "ffff7f1d", 1),  # 1<<63, bit-63 set (reject control)
    ("v5", 1_999_999_999_999_999, "ffff7f1d", 1),  # 7-byte value JUST BELOW the 7-byte threshold (reject twin)
    ("nb1", 100_000, "ffff7f1e", 1),
    ("nb2a", 100_000, "ffff7f1f", 1),
    ("nb2b", 100_000, "ffff7f20", 1),
    ("m2", 100_000, "ffff7f1d", 20),  # full 20-level merkle
]


if __name__ == "__main__":
    print(f"grinding {len(_CHAINS)} chains across {mp.cpu_count()} cores...", flush=True)
    with mp.Pool(processes=min(len(_CHAINS), mp.cpu_count())) as pool:
        for msg in pool.imap_unordered(grind_one, _CHAINS):
            print(msg, flush=True)
    print("ALL CHAINS DONE", flush=True)
    sys.exit(0)
