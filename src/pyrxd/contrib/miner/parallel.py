"""Parallel pure-Python SHA256d miner.

Splits the nonce space across N worker processes (default:
``os.cpu_count()``). Uses :mod:`hashlib` (OpenSSL SHA256, the same
primitive as :func:`pyrxd.glyph.dmint.verify_sha256d_solution`), so
bytes are byte-equivalent between miner and verifier. A miner that
calls ``hashlib`` can't silently produce a wrong nonce.

Verification rule (mirrors ``verify_sha256d_solution``):

.. code-block:: text

    full = sha256d(preimage + nonce)
    Valid iff full[0:4] == b"\\x00\\x00\\x00\\x00" AND
              int.from_bytes(full[4:12], "big") < min(target, MAX_SHA256D_TARGET)

Cross-platform note: this module uses :func:`multiprocessing.get_context`
to explicitly request the ``spawn`` start method, which works on Linux,
macOS, and Windows. The default ``fork`` on Linux would also work but
mixing start methods between platforms produced subtle pickled-closure
errors during dev, so we force ``spawn`` everywhere for determinism.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import time
from dataclasses import dataclass

from .protocol import MAX_SHA256D_TARGET, MineExhausted, MineSuccess


@dataclass(frozen=True)
class MineParams:
    """Inputs to :func:`mine`."""

    preimage: bytes
    target: int
    nonce_width: int  # 4 (V1) or 8 (V2)
    n_workers: int  # number of subprocess workers
    nonce_max: int  # exclusive upper bound on nonce search (default: 2 ** (nonce_width * 8))


def _worker(
    preimage: bytes,
    target: int,
    nonce_width: int,
    start: int,
    stop: int,
    stride: int,
    found_event,
    found_value,
    attempts_counter,
) -> None:
    """Search nonces in ``[start, stop)`` stepping by ``stride``.

    Exits when:

    1. A valid nonce is found — stores its int value in ``found_value``
       under the lock, sets ``found_event``, returns.
    2. ``found_event`` is observed set (another worker won) — returns.
    3. The slice is exhausted — returns.

    The shared-state polling check fires every 65 536 attempts (cheap
    bitmask). At ~1 Mh/s per core that's ~16 ms between polls — short
    enough to be responsive, long enough not to thrash the IPC primitive.

    Must be a module-level function (not a closure or method) so the
    ``spawn`` start method can pickle it.
    """
    sha256 = hashlib.sha256
    effective_target = min(target, MAX_SHA256D_TARGET)
    local_attempts = 0
    check_interval = 65536  # 2**16 — bitmask check is one AND, no modulo

    for n in range(start, stop, stride):
        nonce = n.to_bytes(nonce_width, "little")
        digest = sha256(sha256(preimage + nonce).digest()).digest()
        local_attempts += 1
        if digest[:4] == b"\x00\x00\x00\x00":
            value = int.from_bytes(digest[4:12], "big")
            if value < effective_target:
                with found_value.get_lock():
                    if not found_event.is_set():
                        found_value.value = n
                        found_event.set()
                break
        if (local_attempts & (check_interval - 1)) == 0 and found_event.is_set():
            break

    with attempts_counter.get_lock():
        attempts_counter.value += local_attempts


def mine(params: MineParams) -> MineSuccess | MineExhausted:
    """Run the parallel miner.

    Spawns ``params.n_workers`` subprocess workers, splits the
    ``[0, params.nonce_max)`` range across them with stride-N
    interleaving, and waits for one to win or for all to exhaust.

    Returns :class:`MineSuccess` on hit, :class:`MineExhausted` on
    sweep with no hit. Never raises for "no solution" — that's a
    protocol-level signal, not an exception. Real bugs (invalid
    parameters, broken workers) still raise.
    """
    if params.nonce_width not in (4, 8):
        raise ValueError(f"nonce_width must be 4 or 8, got {params.nonce_width}")
    if len(params.preimage) != 64:
        raise ValueError(f"preimage must be 64 bytes, got {len(params.preimage)}")
    if params.target <= 0:
        raise ValueError(f"target must be positive, got {params.target}")
    if params.n_workers < 1:
        raise ValueError(f"n_workers must be ≥ 1, got {params.n_workers}")
    if params.nonce_max < 1:
        raise ValueError(f"nonce_max must be ≥ 1, got {params.nonce_max}")

    # Force the ``spawn`` start method so behaviour is identical on
    # Linux, macOS, and Windows. ``get_context`` returns a fresh
    # context object; the global default is not mutated, so callers
    # who set their own start method elsewhere in the same process
    # are unaffected.
    ctx = mp.get_context("spawn")
    found_event = ctx.Event()

    # found_value: store the winning nonce as an unsigned 64-bit int.
    # "Q" covers both V1 (4 bytes, max 2**32 - 1) and V2 (8 bytes,
    # max 2**64 - 1) without an overflow trap.
    found_value = ctx.Value("Q", 0)

    # attempts_counter: aggregate across workers. "Q" same rationale.
    attempts_counter = ctx.Value("Q", 0)

    procs = []
    started = time.monotonic()
    for worker_id in range(params.n_workers):
        p = ctx.Process(
            target=_worker,
            args=(
                params.preimage,
                params.target,
                params.nonce_width,
                worker_id,  # start
                params.nonce_max,  # stop
                params.n_workers,  # stride
                found_event,
                found_value,
                attempts_counter,
            ),
        )
        p.start()
        procs.append(p)

    for p in procs:
        p.join()

    elapsed = time.monotonic() - started

    if not found_event.is_set():
        return MineExhausted()

    nonce_int = found_value.value
    nonce = nonce_int.to_bytes(params.nonce_width, "little")
    return MineSuccess(
        nonce=nonce,
        attempts=attempts_counter.value,
        elapsed_s=elapsed,
    )


def default_n_workers() -> int:
    """The default worker count: one per logical CPU.

    Capped at 1 if :func:`os.cpu_count` returns ``None`` (some
    sandboxed environments do).
    """
    return max(1, os.cpu_count() or 1)
