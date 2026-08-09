"""Shared CLI secret-resolution helper for the watchtower's operational entrypoints.

Split out of ``run.py`` (rather than having ``deadman.py`` import ``run`` directly) so the
dead-man's-switch monitor — deliberately run as an INDEPENDENT process precisely so a
tower crash/wedge can't take the liveness monitor down with it, see ``deadman.py``'s module
docstring — can reuse the exact same flag -> 0600-file -> env-var resolution without pulling
in the tower's much heavier dependency graph (aiohttp, the BTC/RXD/ETH chain adapters, ...).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

_module_logger = logging.getLogger("pyrxd.watchtower")


def resolve_secret(
    inline: str | None,
    file_path: str | None,
    env_name: str,
    *,
    flag: str,
    logger: logging.Logger | None = None,
) -> str | None:
    """Resolve a secret from (in precedence) the inline CLI flag, a 0600 file, or an env var.

    The inline flag is accepted for backward compatibility but warned against: process
    arguments are world-readable via ``/proc/<pid>/cmdline`` / ``ps`` and are captured in
    shell history. The file/env paths keep the secret off the process table.

    The file path's mode is checked (POSIX only) before it is read: a group/world-readable
    secret file is refused rather than silently trusted, mirroring the same 0600 enforcement
    ``HdWallet`` applies to seed files (``pyrxd.hd.wallet._load_existing``).
    """
    log = logger or _module_logger
    if inline:
        log.warning(
            "%s passed on the command line is visible in the process table (ps / /proc/<pid>/cmdline) and "
            "shell history; prefer %s-file or the %s env var.",
            flag,
            flag,
            env_name,
        )
        return inline
    if file_path:
        path = Path(file_path)
        try:
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            raise SystemExit(f"{flag}-file {file_path}: {exc}") from exc
        if (mode & 0o077) and os.name == "posix":
            raise SystemExit(
                f"{flag}-file {file_path} has mode {oct(mode)}; must be 0o600 (owner-only). "
                f"Run `chmod 600 {file_path}` and retry."
            )
        return path.read_text(encoding="utf-8").strip() or None
    return os.environ.get(env_name) or None
