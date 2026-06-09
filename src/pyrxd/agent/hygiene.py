"""Best-effort process hardening for the signing daemon (load-bearing §6).

The daemon holds the decrypted seed in memory for the unlock window. These
measures shrink the window in which that seed can leak to disk or another
process:

* ``mlockall`` — keep pages out of swap (no plaintext seed paged to disk).
* ``PR_SET_DUMPABLE 0`` — disallow ptrace/attach by other processes and mark
  the process non-dumpable.
* ``RLIMIT_CORE = 0`` — no core dump (which would contain the seed) on crash.

All are BEST-EFFORT: a container without ``CAP_IPC_LOCK`` can't ``mlock``, etc.
Failures are reported, never fatal. The honest limit (documented in the threat
model): ``SIGKILL`` and hardware faults cannot be scrubbed — these reduce, not
eliminate, residency risk.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import resource
from dataclasses import dataclass

_MCL_CURRENT = 1
_MCL_FUTURE = 2
_PR_SET_DUMPABLE = 4


@dataclass(frozen=True)
class HardeningReport:
    """What actually took effect (for logging / the `status` response)."""

    mlock: bool
    non_dumpable: bool
    core_dumps_disabled: bool

    def as_dict(self) -> dict:
        return {
            "mlock": self.mlock,
            "non_dumpable": self.non_dumpable,
            "core_dumps_disabled": self.core_dumps_disabled,
        }


def harden_process() -> HardeningReport:
    """Apply the hardening measures; return which ones succeeded. Never raises."""
    return HardeningReport(
        mlock=_try_mlockall(),
        non_dumpable=_try_set_non_dumpable(),
        core_dumps_disabled=_try_disable_core_dumps(),
    )


def _libc() -> ctypes.CDLL | None:
    name = ctypes.util.find_library("c")
    if name is None:
        return None
    try:
        return ctypes.CDLL(name, use_errno=True)
    except OSError:
        return None


def _try_mlockall() -> bool:
    libc = _libc()
    if libc is None or not hasattr(libc, "mlockall"):
        return False
    try:
        return libc.mlockall(_MCL_CURRENT | _MCL_FUTURE) == 0
    except OSError:
        return False


def _try_set_non_dumpable() -> bool:
    libc = _libc()
    if libc is None or not hasattr(libc, "prctl"):
        return False
    try:
        return libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    except OSError:
        return False


def _try_disable_core_dumps() -> bool:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, OSError):
        return False
