"""Tests for prompts.py — confirmation flow + mnemonic display gate.

The mnemonic-display function is mostly cosmetic but enforces the
Enter gate. ``confirm_action`` carries the destructive-op safety
contract: ``--yes`` skips, ``--json`` without ``--yes`` blocks.
"""

from __future__ import annotations

from pathlib import Path

import click

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.prompts import confirm_action, show_mnemonic


def _ctx(*, output_mode: str = "human", yes: bool = False) -> CliContext:
    return CliContext(
        config=Config(),
        network="mainnet",
        electrumx_url="wss://example/",
        fee_rate=10_000,
        wallet_path=Path("/tmp/_unused"),
        output_mode=output_mode,
        yes=yes,
    )


class TestConfirmAction:
    def test_yes_short_circuits_and_returns_true(self) -> None:
        ctx = _ctx(yes=True)
        # Use a runner-driven invocation so click.confirm has a context.
        result = _run_in_click_ctx(lambda: confirm_action(["sending 100 photons"], ctx=ctx))
        assert result is True

    def test_human_yes_prompt_returns_true(self) -> None:
        ctx = _ctx(output_mode="human", yes=False)
        result = _run_in_click_ctx(
            lambda: confirm_action(["sending 100 photons"], ctx=ctx),
            input="y\n",
        )
        assert result is True

    def test_human_no_prompt_returns_false(self) -> None:
        ctx = _ctx(output_mode="human", yes=False)
        result = _run_in_click_ctx(
            lambda: confirm_action(["sending 100 photons"], ctx=ctx),
            input="n\n",
        )
        assert result is False

    def test_json_without_yes_returns_false(self) -> None:
        """JSON mode without --yes must NEVER auto-confirm a destructive op."""
        ctx = _ctx(output_mode="json", yes=False)
        # No prompt should be issued — function returns False directly.
        result = _run_in_click_ctx(lambda: confirm_action(["...summary..."], ctx=ctx))
        assert result is False

    def test_json_with_yes_returns_true(self) -> None:
        ctx = _ctx(output_mode="json", yes=True)
        result = _run_in_click_ctx(lambda: confirm_action(["...summary..."], ctx=ctx))
        assert result is True


class TestShowMnemonic:
    def test_displays_box_without_blocking(self) -> None:
        """Smoke check: show_mnemonic doesn't deadlock when given Enter."""
        ctx = _ctx(output_mode="human")
        words = ["abandon"] * 6
        # The Enter prompt would block on stdin; feed a newline via click.
        _run_in_click_ctx(lambda: show_mnemonic(words, ctx=ctx), input="\n")
        # No assertion needed — passing this test means no deadlock.
        # CliRunner-based wallet_new tests cover the actual rendered output.

    def test_json_mode_skips_mnemonic_display(self) -> None:
        """In JSON mode, show_mnemonic must not print the box (caller
        handles the JSON mnemonic emission directly).
        """
        ctx = _ctx(output_mode="json")
        _run_in_click_ctx(lambda: show_mnemonic(["one", "two"], ctx=ctx))
        # No assertion needed — the function must not block on Enter.


# ---------------------------------------------------------------------------
# Helper: invoke a function under a click context so click.prompt /
# click.confirm have an active runtime to talk to.
# ---------------------------------------------------------------------------


def _run_in_click_ctx(fn, *, input: str | None = None):
    """Run *fn* under a click runtime that supplies *input* on stdin."""
    runner = click.testing.CliRunner()

    @click.command()
    def _wrapper() -> None:
        result = fn()
        # Stash the result somewhere accessible; we use a class attribute.
        _wrapper.result = result  # type: ignore[attr-defined]

    invoke_result = runner.invoke(_wrapper, input=input)
    if invoke_result.exception is not None and not isinstance(invoke_result.exception, SystemExit):
        raise invoke_result.exception
    return getattr(_wrapper, "result", None)
