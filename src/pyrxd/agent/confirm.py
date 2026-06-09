"""Per-spend confirmation UI for the signing agent (load-bearing control H2).

The confirmation is THE control that separates A′ from a seed-vending agent: a
same-uid process passes ``SO_PEERCRED`` and can *originate* a signing request,
so the only thing standing between it and a signature is a human approving the
*attributed* spend. Therefore the prompt must reach the user through a channel
the requesting process cannot drive — the daemon's own controlling terminal
(``/dev/tty``), never the requester's stdin.

:func:`format_spend_summary` is pure (and unit-tested); :class:`TtyConfirmer`
does the I/O. If there is no controlling tty (a detached daemon with nowhere to
ask), confirmation FAILS CLOSED — the spend is declined, never auto-approved.
"""

from __future__ import annotations

from .protocol import SpendSummary

#: Spends whose total to EXTERNAL payees is at/below this skip the prompt within
#: an unlock window (the plan's UX-fatigue mitigation). 0 = always confirm.
DEFAULT_AUTO_CONFIRM_UNDER = 0


def format_spend_summary(summary: SpendSummary) -> str:
    """Render the verified spend for human review (pure; no I/O).

    Shows every external payee + amount, the change total, the input total, and
    the fee — all derived from the *verified* tx (prevouts checked, change
    re-derived), so what the user sees is what gets signed.
    """
    lines = ["", "  ── pyrxd agent: approve this spend? ──"]
    if summary.external_outputs:
        for e in summary.external_outputs:
            lines.append(f"    send  {e.amount:>16,} photons  →  {e.dest}")
    else:
        lines.append("    (no external payees — self-spend / consolidation)")
    lines.append(f"    change      {summary.change_total:>16,} photons")
    lines.append(f"    inputs      {summary.input_total:>16,} photons")
    lines.append(f"    fee         {summary.fee:>16,} photons")
    flags = ", ".join(f"0x{f:02x}" for f in summary.sighash_flags)
    lines.append(f"    sighash     {flags or '(none)'}")
    return "\n".join(lines)


class TtyConfirmer:
    """Confirms spends on the daemon's controlling terminal (``/dev/tty``).

    ``auto_confirm_under`` lets small spends (total external ≤ threshold) skip
    the prompt — documented as outside the trust boundary. With no tty available
    the call fails closed (returns ``False``).
    """

    def __init__(self, *, auto_confirm_under: int = DEFAULT_AUTO_CONFIRM_UNDER) -> None:
        self._threshold = auto_confirm_under

    def __call__(self, summary: SpendSummary) -> bool:
        if summary.total_external <= self._threshold:
            return True
        try:
            tty = open("/dev/tty", "r+")  # noqa: SIM115 — need explicit lifetime around the prompt
        except OSError:
            # No controlling terminal (detached daemon) → cannot ask → fail closed.
            return False
        try:
            tty.write(format_spend_summary(summary))
            tty.write("\n  approve? [y/N]: ")
            tty.flush()
            answer = tty.readline().strip().lower()
        except OSError:
            return False
        finally:
            tty.close()
        return answer in ("y", "yes")
