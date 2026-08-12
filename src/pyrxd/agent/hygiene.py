"""Best-effort process hardening for the signing daemon (load-bearing §6).

The daemon holds the decrypted seed in memory for the unlock window. These
measures shrink the window in which that seed can leak to disk or another
process:

* ``mlockall`` — keep pages out of swap (no plaintext seed paged to disk).
* ``PR_SET_DUMPABLE 0`` — disallow ptrace/attach by other processes and mark
  the process non-dumpable.
* ``RLIMIT_CORE = 0`` — no core dump (which would contain the seed) on crash.

WHEN it runs matters as much as what it does. ``pyrxd agent unlock`` calls
:func:`harden_process` BEFORE prompting for the mnemonic, not after — it used to
run only inside ``AgentDaemon.serve_forever``, the last step of the command, so
the mnemonic was typed, the passphrase prompted and the seed derived in a process
that was still swappable and dumpable. ``mlockall`` is the measure that gain is
about: swap persists across a reboot, and a sub-second memory window does not.

All are BEST-EFFORT: a container without ``CAP_IPC_LOCK`` can't ``mlock``, etc.
Failures are reported, never fatal — and because the call now precedes the
unlock, "never fatal" is a contract the CLI depends on rather than a nicety.

The honest limits, none of which this closes:
* ``SIGKILL`` and hardware faults cannot be scrubbed — these reduce, not
  eliminate, residency risk.
* ``PR_SET_DUMPABLE 0`` does not revoke ALREADY-OPEN descriptors, so a watcher
  that opened ``/proc/<pid>/mem`` before the prctl keeps its read. Hardening
  earlier narrows the race but cannot win it; it closes the attacker who arrives
  after unlock, not one already in position.
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


def _never_raises(attempt) -> bool:
    """Run *attempt*, reporting any failure as ``False`` rather than propagating it.

    The three helpers below already catch ``OSError``, which is what these calls
    fail with in practice. This is the backstop for what they cannot anticipate —
    a ``ctypes`` argument/marshalling error, a libc without the symbol, a
    platform where ``prctl`` means something else. Hardening is defence in depth;
    failing to apply it must never be worse than not attempting it.
    """
    try:
        return attempt()
    except Exception:
        return False


def harden_process() -> HardeningReport:
    """Apply the hardening measures; return which ones succeeded. Never raises.

    "Never raises" is a load-bearing contract, not a courtesy: ``pyrxd agent
    unlock`` calls this BEFORE prompting for the mnemonic, so that ``mlockall``
    is in effect before any secret can be paged to swap. An exception here would
    therefore deny a user their own wallet on a host that merely lacks
    ``CAP_IPC_LOCK`` — trading a real lockout for a speculative one.
    """
    return HardeningReport(
        mlock=_never_raises(_try_mlockall),
        non_dumpable=_never_raises(_try_set_non_dumpable),
        core_dumps_disabled=_never_raises(_try_disable_core_dumps),
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
