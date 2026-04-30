"""Confirmation prompts and the mnemonic-display flow.

The mnemonic display follows the Cut 1 plan:

1. Print the mnemonic in a clearly-flagged box.
2. Wait for the user to press Enter.
3. The mnemonic is never shown again by pyrxd.

The Enter gate slows the user down; it doesn't protect against
scrollback / tmux / screen-share exposure. Documented as the user's
responsibility. See ``docs/wallet-cli-decisions.md`` §6.

Mnemonic and passphrase prompts go through ``click.prompt(hide_input=True)``
rather than ``getpass.getpass`` so the test runner's ``input=`` parameter
can feed values without needing a controlling terminal.
"""

from __future__ import annotations

from collections.abc import Iterable

import click

from .context import CliContext

_MNEMONIC_BOX_TOP = "╔════════════════════════════════════════════════════════════╗"
_MNEMONIC_BOX_MID = "║ Recovery mnemonic — write this down, then never share it.  ║"
_MNEMONIC_BOX_MID2 = "║ pyrxd will NOT show this again.                            ║"
_MNEMONIC_BOX_BOT = "╚════════════════════════════════════════════════════════════╝"


def show_mnemonic(words: Iterable[str], *, ctx: CliContext) -> None:
    """Print the mnemonic in a flagged box and wait for Enter.

    In ``--json`` mode the mnemonic is not displayed; the caller should
    have already errored out. In ``--quiet`` mode we still print the
    box (suppressing it would defeat the safety message) — quiet
    affects results, not safety prompts.
    """
    if ctx.output_mode == "json":
        # Defensive: should never reach here in JSON mode without --yes.
        # Caller is responsible for the gate.
        return

    word_list = list(words)
    line = " ".join(word_list)
    click.echo("")
    click.echo(_MNEMONIC_BOX_TOP)
    click.echo(_MNEMONIC_BOX_MID)
    click.echo(_MNEMONIC_BOX_MID2)
    click.echo(_MNEMONIC_BOX_BOT)
    click.echo("")
    click.echo(line)
    click.echo("")
    click.prompt(
        "Press Enter once you have written it down",
        default="",
        show_default=False,
        prompt_suffix="",
    )


def prompt_mnemonic_input() -> str:
    """Prompt for an existing mnemonic. Input is hidden — never echoed.

    Uses ``click.prompt(hide_input=True)`` rather than ``getpass`` so
    ``CliRunner.invoke(input=...)`` works in tests without a TTY. The
    on-terminal behavior is the same: characters are not displayed.

    The returned string is normalized:
    * leading/trailing whitespace stripped,
    * runs of internal whitespace collapsed to a single space,

    so a user pasting from a multi-line note or with stray tabs
    doesn't trip the BIP39 validator on a benign formatting issue.
    The validator still rejects unknown words and checksum mismatches.
    """
    raw = click.prompt("Mnemonic (input hidden)", hide_input=True, default="", show_default=False)
    return _normalize_mnemonic(str(raw))


def _normalize_mnemonic(s: str) -> str:
    """Collapse runs of whitespace and strip ends. Never logs *s*."""
    return " ".join(s.split())


def prompt_passphrase_input(*, optional: bool = True) -> str:
    """Prompt for a BIP39 passphrase. Empty string is allowed when *optional*.

    Hidden input — characters are not displayed.
    """
    label = "Passphrase (optional, press Enter to skip)" if optional else "Passphrase"
    pw = click.prompt(label, hide_input=True, default="", show_default=False)
    return str(pw)


def confirm_action(
    summary: list[str],
    *,
    ctx: CliContext,
    prompt_text: str = "Proceed?",
) -> bool:
    """Display *summary* lines and ask for y/N. Returns True on confirm.

    With ``--yes`` the prompt is skipped and True is returned
    immediately. ``--json`` mode without ``--yes`` should already have
    been blocked by the destructive-mode gate, but we defensively check
    again here.
    """
    if ctx.yes:
        return True
    if ctx.output_mode == "json":
        # Belt-and-suspenders: never auto-confirm in JSON mode.
        return False
    for line in summary:
        click.echo(line)
    return click.confirm(prompt_text, default=False)
