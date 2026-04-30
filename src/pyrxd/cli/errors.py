"""CLI-side error types and exit-code mapping.

Library code raises typed exceptions (``ValidationError``, ``NetworkError``,
``KeyMaterialError``); this module wraps them in a ``CliError`` subclass
of :class:`click.ClickException` so click handles formatting and exit
codes uniformly across direct ``cli()`` invocations and the test runner.

Exit codes (per docs/wallet-cli-plan.md §"Exit codes"):
  0   success
  1   user-error
  2   network error
  3   wallet decryption failed
  4   unexpected error (bug)

Debug traceback handling
------------------------
When the user passes ``--debug``, ``run()`` sets a module-level flag
that ``CliError.show()`` reads. The traceback printed is the standard
:func:`traceback.format_exception` form — function names, line numbers,
source lines. **Local variables are never captured.** The source lines
themselves may contain variable names like ``mnemonic`` or
``passphrase`` (per Python's standard traceback format) but never their
values; that's the same exposure surface as any uncaught exception in
a Python program. We do NOT use ``capture_locals=True`` anywhere.
"""

from __future__ import annotations

import traceback

import click

# Set by main.run() when --debug is passed. Read by CliError.show().
_DEBUG: bool = False


def set_debug(enabled: bool) -> None:
    """Enable or disable traceback emission for CliError.show().

    Called by ``main.run()`` based on the ``--debug`` flag. Affects the
    process-global state — every CliError raised after the call honors
    the new setting.
    """
    global _DEBUG
    _DEBUG = bool(enabled)


def is_debug() -> bool:
    return _DEBUG


class CliError(click.ClickException):
    """A user-facing CLI error.

    Carries a short ``message`` (one line, action-relevant), a ``cause``
    (one line, what went wrong with sensitive values redacted), and a
    ``fix`` hint (one-line concrete next step, or ``None``). Click's
    machinery prints the formatted block via :meth:`format_message` and
    exits with :attr:`exit_code` automatically.
    """

    exit_code = 1

    def __init__(
        self,
        message: str,
        *,
        cause: str | None = None,
        fix: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.cause = cause
        self.fix = fix
        if exit_code is not None:
            self.exit_code = exit_code

    def format_message(self) -> str:
        parts = [f"error: {self.message}"]
        if self.cause:
            parts.append(f"  cause: {self.cause}")
        if self.fix:
            parts.append(f"  fix: {self.fix}")
        return "\n".join(parts)

    # Override show() so the prefix is just our formatted block (no
    # "Error: " click prefix). When --debug is on, also append the
    # exception traceback (standard format — no captured locals).
    def show(self, file=None) -> None:  # type: ignore[override]
        click.echo(self.format_message(), file=file, err=True)
        if _DEBUG and self.__cause__ is not None:
            tb_lines = traceback.format_exception(
                type(self.__cause__),
                self.__cause__,
                self.__cause__.__traceback__,
            )
            click.echo("".join(tb_lines), file=file, err=True, nl=False)


class UserError(CliError):
    """Bad input, missing file, insufficient funds, etc. Exit code 1."""

    exit_code = 1


class NetworkBoundaryError(CliError):
    """A library-level NetworkError surfaced at the CLI. Exit code 2."""

    exit_code = 2


class WalletDecryptError(CliError):
    """Wallet decryption failed (wrong mnemonic, tampered file, etc.). Exit code 3.

    The cause field NEVER includes the user's input — only generic guidance.
    """

    exit_code = 3

    def __init__(self, message: str = "Could not decrypt wallet file") -> None:
        super().__init__(
            message,
            cause="wrong mnemonic, wrong passphrase, or wallet file is corrupt",
            fix="check the mnemonic and passphrase exactly, then try again",
        )


def render_error(err: CliError) -> str:
    """Format a CliError as the standard three-line block (used by tests)."""
    return err.format_message()
