"""``pyrxd new`` — start a project from the pyrxd starter template.

A thin CLI over :func:`pyrxd.starter.write_project`. It writes files only; it installs
nothing and starts no node.
"""

from __future__ import annotations

from pathlib import Path

import click

from ..starter import ProjectNameError, write_project
from .format import emit


@click.command(name="new")
@click.argument("name")
@click.option(
    "--dir",
    "directory",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Where to create the project (default: ./NAME). Must not exist, or be empty.",
)
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
def new_cmd(name: str, directory: Path | None, json_output: bool) -> None:
    """Create a new project NAME with a mint example and a test on a local regtest chain."""
    try:
        target = write_project(name, directory)
    except (ProjectNameError, FileExistsError) as exc:
        raise click.ClickException(str(exc)) from None
    files = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    if json_output:
        click.echo(emit({"directory": str(target), "files": files}, mode="json"))
        return
    click.echo(f"created {target}")
    for f in files:
        click.echo(f"  {f}")
    click.echo("")
    click.echo("next:")
    click.echo(f"  cd {target}")
    click.echo('  pip install -e ".[test]"')
    click.echo("  pyrxd regtest setup   # once: builds the local Radiant node image (needs docker)")
    click.echo("  pytest")
