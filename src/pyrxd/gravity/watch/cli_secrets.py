"""Shared CLI secret-resolution helper for the watchtower's operational entrypoints.

Split out of ``run.py`` (rather than having ``deadman.py`` import ``run`` directly) so the
dead-man's-switch monitor — deliberately run as an INDEPENDENT process precisely so a
tower crash/wedge can't take the liveness monitor down with it, see ``deadman.py``'s module
docstring — can reuse the exact same flag -> 0600-file -> env-var resolution without pulling
in the tower's much heavier dependency graph (aiohttp, the BTC/RXD/ETH chain adapters, ...).

This module is *package* code (it ships in the wheel), so every failure here raises a typed
:class:`~pyrxd.security.errors.ValidationError` rather than ``SystemExit``: an embedding
application that calls :func:`resolve_secret` must get a catchable error, not a killed
process. Each entrypoint's ``main()`` translates that error to the same exit code (1) the
bare ``SystemExit`` produced.
"""

from __future__ import annotations

import errno
import logging
import os
import stat
from pathlib import Path

from pyrxd.security.errors import ValidationError

_module_logger = logging.getLogger("pyrxd.watchtower")

#: Ceiling on a credential-file read. A secret is a handful of bytes; anything approaching
#: this is a wrong path or a hostile file, and reading it unbounded would stall the caller.
MAX_SECRET_FILE_BYTES = 64 * 1024


def read_secret_file(
    path: str | Path,
    *,
    label: str,
    max_bytes: int = MAX_SECRET_FILE_BYTES,
) -> str:
    """Read a credential file under an owner-only, symlink-proof, size-bounded gate.

    The whole check runs against **one file descriptor**, so there is no stat/read TOCTOU:

    * ``O_NOFOLLOW`` — a symlink is refused outright. A ``stat()``-then-``read()`` pair
      follows links, so a 0600 symlink owned by the operator could point at a file the
      operator does not control (or at a FIFO that blocks the read forever).
    * ``fstat`` on that same fd — mode and owner are checked on the bytes actually read,
      not on whatever the path resolved to a moment earlier.
    * ``S_ISREG`` (+ ``O_NONBLOCK`` on the open) — a FIFO/device/directory is not a secret
      file, and ``O_NONBLOCK`` means opening one returns instead of blocking forever waiting
      for a writer. ``O_NONBLOCK`` is inert for a regular file.
    * ``st_uid == geteuid()`` — a 0600 file owned by *another* user is somebody else's
      secret (or bait); refuse it rather than trust the mode bits alone.
    * ``max_bytes`` — bounded read, so a huge/endless file cannot wedge the caller.

    POSIX-only enforcement: on a platform without POSIX mode bits (Windows reports dummy
    values, and ``O_NOFOLLOW`` does not exist) the read still happens and is still bounded,
    but the mode/owner gate is skipped rather than raising spuriously.

    Args:
        path: the credential file.
        label: how to name it in errors (e.g. ``"--webhook-secret-file"``).
        max_bytes: refuse anything larger.

    Returns:
        The file's decoded text (NOT stripped — the caller decides).

    Raises:
        ValidationError: the file is missing/unreadable, a symlink, not a regular file,
            group/world-accessible, owned by another user, oversized, or not UTF-8.
    """
    file_path = Path(path)
    if os.name != "posix":  # no POSIX mode bits / no O_NOFOLLOW — bounded read only
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"{label} {file_path}: {exc}") from exc
        if len(data) > max_bytes:
            raise ValidationError(f"{label} {file_path} is larger than {max_bytes} bytes — refusing to read")
        return _decode(data, label=label, file_path=file_path)

    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(file_path), flags)
    except OSError as exc:
        hint = (
            " (it is a symlink; pass the real file — a symlinked secret is refused)" if exc.errno == errno.ELOOP else ""
        )
        raise ValidationError(f"{label} {file_path}: {exc}{hint}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValidationError(f"{label} {file_path} is not a regular file — refusing to read a secret from it")
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise ValidationError(
                f"{label} {file_path} has mode {oct(mode)}; must be 0o600 (owner-only). "
                f"Run `chmod 600 {file_path}` and retry."
            )
        if st.st_uid != os.geteuid():
            raise ValidationError(
                f"{label} {file_path} is owned by uid {st.st_uid}, not this process's uid {os.geteuid()} — "
                "refusing to read a credential owned by another user"
            )
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ValidationError(f"{label} {file_path} is larger than {max_bytes} bytes — refusing to read")
    return _decode(data, label=label, file_path=file_path)


def _decode(data: bytes, *, label: str, file_path: Path) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Deliberately strict (unlike the ACK inbox): a mis-decoded credential silently
        # becomes the WRONG secret, which fails authentication in a way nobody debugs.
        raise ValidationError(f"{label} {file_path} is not valid UTF-8") from exc


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

    The file is read through :func:`read_secret_file`, so it must be an owner-only,
    non-symlink regular file — mirroring the same 0600 enforcement ``HdWallet`` applies to
    seed files (``pyrxd.hd.wallet._load_existing``).

    **Fail closed on an empty secret.** ``None`` (nothing configured) means "no HMAC" and is
    a legitimate configuration. An explicitly configured source that resolves to *empty* —
    a truncated/emptied secret file, ``PYRXD_WATCHTOWER_WEBHOOK_SECRET=""``, ``--webhook-secret ""``
    — used to collapse to that same ``None``, and :class:`WebhookAlertChannel` then posted
    every page UNSIGNED with no warning: a missing file failed closed, an empty one failed
    OPEN. It now raises.

    Raises:
        ValidationError: the file fails the ownership/mode/size gate, or a configured
            source resolved to an empty secret.
    """
    log = logger or _module_logger
    if inline is not None and not inline.strip():
        raise ValidationError(
            f"{flag} was given but is empty — refusing to run with an unsigned/unauthenticated "
            f"webhook. Pass a real secret, or omit {flag} entirely."
        )
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
        value = read_secret_file(file_path, label=f"{flag}-file").strip()
        if not value:
            raise ValidationError(
                f"{flag}-file {file_path} is empty — refusing to run with an unsigned/unauthenticated "
                f"webhook. Write the secret to it, or omit {flag}-file entirely."
            )
        return value
    if env_name in os.environ:
        raw = os.environ[env_name]
        if not raw.strip():
            raise ValidationError(
                f"{env_name} is set but empty — refusing to run with an unsigned/unauthenticated "
                f"webhook. Set a real secret, or unset {env_name} entirely."
            )
        return raw
    return None
