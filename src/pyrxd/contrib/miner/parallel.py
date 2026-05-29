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

import ctypes
import hashlib
import multiprocessing as mp
import os
import signal
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .protocol import MAX_SHA256D_TARGET, MineExhausted, MineSuccess

# Linux prctl option: deliver a signal to THIS process when its parent dies.
# (asm-generic/prctl.h — stable kernel ABI value.) This is the ONE defense that
# survives a parent ``kill -9`` / hard crash, which no in-parent handler can catch
# (SIGKILL is untrappable, so mine()'s finally-cleanup never runs). Belt-and-
# suspenders with _ensure_workers_terminated: that handles every CATCHABLE exit;
# this handles the uncatchable one.
_PR_SET_PDEATHSIG = 1


def _parent_is_gone(parent_pid: int) -> bool:
    """True iff this process's spawning parent died (so it should stop grinding).

    A reaped parent reparents the child — to PID 1 on a bare init, but to a
    SUBREAPER (e.g. ``systemd --user``) in a desktop session, so "ppid == 1" is the
    WRONG test (it almost never trips under systemd — the orphans observed in the
    field sat under ``systemd --user``). The robust signal is "my ppid is no longer
    my spawning parent": any change means that parent exited and I was reparented.
    ``parent_pid`` is the spawning process's pid (passed down by mine()), NOT a
    value read here via getppid() — see :func:`_worker` for why that distinction is
    load-bearing under the ``spawn`` start method.
    """
    return os.getppid() != parent_pid


def _install_parent_death_signal(parent_pid: int) -> None:
    """Best-effort: ask the kernel to SIGKILL this worker when its parent dies.

    Linux-only (``prctl(PR_SET_PDEATHSIG, SIGKILL)``); a no-op elsewhere. NEVER
    raises — this is opportunistic hardening, and a miner must still run if prctl
    is unavailable (the in-parent cleanup + the in-loop orphan poll still cover it).

    Closes the orphan-worker race for a parent ``kill -9``/crash: without it, the
    worker is reparented (to init OR a subreaper like ``systemd --user``) and keeps
    grinding nonces forever with nowhere to report. There is a TOCTOU window — under
    ``spawn`` the parent can die between fork and this call, before PDEATHSIG arms —
    so we re-check against ``parent_pid`` afterward and exit if already reparented.
    The in-loop poll (:func:`_parent_is_gone`) is the deterministic backstop for the
    rest of that window.
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
        libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
        # TOCTOU: if the parent already exited before prctl armed, we are already
        # reparented — exit hard rather than orphan-grind.
        if _parent_is_gone(parent_pid):
            os._exit(0)
    except Exception:
        # ctypes/libc unavailable or prctl rejected: fall back to the in-parent
        # cleanup + the in-loop orphan poll. Do not let hardening break the miner.
        return


@dataclass(frozen=True)
class MineParams:
    """Inputs to :func:`mine`."""

    preimage: bytes
    target: int
    nonce_width: int  # 4 (V1) or 8 (V2)
    n_workers: int  # number of subprocess workers
    nonce_max: int  # exclusive upper bound on nonce search (default: 2 ** (nonce_width * 8))


def _worker(
    parent_pid: int,
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
    # FIRST action: arm the parent-death signal so a parent kill -9 / crash can't
    # leave this worker orphaned and grinding (the one path mine()'s finally cannot
    # cover — SIGKILL is untrappable). Best-effort.
    #
    # ``parent_pid`` is the spawning process's pid, passed in by mine() — NOT read
    # here via getppid(). Under ``spawn`` the parent can die during the worker's
    # interpreter-init/import window (before this line); by then getppid() would
    # already return the reparent target, so a locally-read "original" ppid would be
    # WRONG and the orphan check would never trip. The parent's true pid is the only
    # reliable reference.
    _install_parent_death_signal(parent_pid)

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
        if (local_attempts & (check_interval - 1)) == 0:
            if found_event.is_set():
                break
            # Orphan self-check (the deterministic backstop for PR_SET_PDEATHSIG's
            # spawn-window race): PDEATHSIG fires instantly WHEN armed in time, but
            # `spawn` has a fork→re-exec→import→unpickle window before it is armed; a
            # parent kill -9 inside that window leaves it un-armed. If the original
            # parent has since died (we got reparented — to init OR a subreaper like
            # systemd --user), stop grinding and exit. Cross-platform (plain getppid).
            if _parent_is_gone(parent_pid):
                os._exit(0)

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

    procs: list[mp.process.BaseProcess] = []
    started = time.monotonic()
    # The spawning process's pid — passed to each worker so it can detect being
    # orphaned (reparented away from us) even if a parent kill -9 lands during the
    # worker's spawn/import window, before it could read its own ppid reliably.
    parent_pid = os.getpid()
    # All worker management runs under _ensure_workers_terminated so that
    # any exit path — normal return, exception, SIGTERM, SIGINT, KeyboardInterrupt —
    # leaves no orphaned worker processes consuming CPU after this function returns.
    # Historically (pre-2026-05) this code only used `p.join()`; a pytest crash
    # or timeout during mine() would orphan up to N workers that continued
    # grinding until they hit nonce_max, eating cores indefinitely.
    with _ensure_workers_terminated(procs):
        for worker_id in range(params.n_workers):
            p = ctx.Process(
                target=_worker,
                args=(
                    parent_pid,
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


# Grace period for cooperative shutdown after found_event is set.
# Workers poll the event every `check_interval` hashes (~256 hashes in
# the current impl), so this should be near-instantaneous in practice.
_WORKER_TERMINATE_GRACE_S = 1.0
# Hard kill grace after SIGTERM. If a worker is in a tight C loop and
# ignores SIGTERM, SIGKILL after this.
_WORKER_KILL_GRACE_S = 0.5


@contextmanager
def _ensure_workers_terminated(
    procs: list[mp.process.BaseProcess],
) -> Iterator[None]:
    """Guarantee every spawned worker is reaped before this context exits.

    Catches every interrupt path that can leak workers:

    1. Normal completion — procs already joined; terminate() is a no-op.
    2. Unhandled exception inside the with-block — terminate + join all.
    3. KeyboardInterrupt (Ctrl-C) — same as above.
    4. SIGTERM delivered to the parent (pytest --timeout, OOM killer,
       `kill <pid>`) — restored signal handler triggers cleanup via
       a raised KeyboardInterrupt-style interrupt, then we cascade
       terminate() to children.

    The SIGTERM handler is installed only for the duration of the
    context and is restored afterward, so we don't pollute callers'
    signal handling.
    """

    # Install a SIGTERM handler that cascades to children. SIGINT
    # (Ctrl-C) already raises KeyboardInterrupt which the finally
    # block catches; SIGTERM by default just kills the process
    # without finally running, so we explicitly handle it.
    def _sigterm_to_keyboard_interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt("SIGTERM received — terminating mine() workers")

    previous_handler = signal.signal(signal.SIGTERM, _sigterm_to_keyboard_interrupt)
    try:
        yield
    finally:
        # Restore the caller's SIGTERM handler before doing the cleanup
        # work itself, so a second SIGTERM during cleanup behaves
        # normally rather than recursing.
        signal.signal(signal.SIGTERM, previous_handler)
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(_WORKER_TERMINATE_GRACE_S)
            if p.is_alive():
                # Worker ignored SIGTERM — escalate to SIGKILL.
                p.kill()
                p.join(_WORKER_KILL_GRACE_S)


def default_n_workers() -> int:
    """The default worker count: one per logical CPU.

    Capped at 1 if :func:`os.cpu_count` returns ``None`` (some
    sandboxed environments do).
    """
    return max(1, os.cpu_count() or 1)
