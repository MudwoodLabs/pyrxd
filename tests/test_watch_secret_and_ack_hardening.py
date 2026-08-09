"""Trust-boundary hardening for the watchtower's on-disk control surfaces.

Three of these files are read by an UNATTENDED process that decides whether a claim-race page
fires, so their at-rest posture is part of the security argument, not housekeeping:

* the webhook **secret** file (``cli_secrets.resolve_secret``) — an empty one used to silently
  disable HMAC signing, and the mode check followed symlinks and ran on a different open than
  the read;
* the **ACK inbox** (``alerts.FileAckInbox``) — anyone who can write it can suppress CRITICAL
  re-pages and zero the ``unacked_critical`` escalation signal;
* the pre-signed **refund sidecar** + the refund **private key** file (``presign``) — the
  sidecar was written at umask and chmod'd afterwards, and the key file had no mode check at
  all while the far-lower-value webhook secret had one.

Plus the entrypoint contract: these modules moved from ``scripts/`` into the shipped package, so
a config failure must raise a CATCHABLE typed error, while ``main()`` keeps producing the exact
same exit code (1) an embedded ``SystemExit`` did.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

from pyrxd.gravity.watch import FileAckInbox
from pyrxd.gravity.watch import presign as presign_mod
from pyrxd.gravity.watch.alerts import DedupAlerter
from pyrxd.gravity.watch.cli_secrets import read_secret_file, resolve_secret
from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.security.errors import ValidationError

_POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not _POSIX, reason="POSIX mode bits / O_NOFOLLOW only")

_ENV = "PYRXD_TEST_WATCHTOWER_SECRET"


def _secret_file(tmp_path: Path, content: str = "s3cr3t", *, mode: int = 0o600, name: str = "secret") -> Path:
    p = tmp_path / name
    p.write_text(content)
    p.chmod(mode)
    return p


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)


# ---------------------------------------------------------------- resolve_secret: mode / links


def test_secret_file_0600_is_read_and_stripped(tmp_path):
    p = _secret_file(tmp_path, "  s3cr3t \n")
    assert resolve_secret(None, str(p), _ENV, flag="--webhook-secret") == "s3cr3t"


@posix_only
def test_group_readable_secret_file_is_refused(tmp_path):
    """NEGATIVE: 0644 must fail closed, and as a CATCHABLE error (was a bare SystemExit)."""
    p = _secret_file(tmp_path, "s3cr3t", mode=0o644)
    with pytest.raises(ValidationError, match="must be 0o600"):
        resolve_secret(None, str(p), _ENV, flag="--webhook-secret")


@posix_only
def test_symlinked_secret_file_is_refused(tmp_path):
    """NEGATIVE: ``stat()`` follows links, so a 0600 symlink the operator owns could point at a
    file they do not control. ``O_NOFOLLOW`` refuses the link itself."""
    real = _secret_file(tmp_path, "s3cr3t", name="real")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ValidationError) as exc:
        resolve_secret(None, str(link), _ENV, flag="--webhook-secret")
    assert "symlink" in str(exc.value)


@posix_only
def test_secret_mode_is_checked_on_the_fd_that_is_read(tmp_path, monkeypatch):
    """The mode/owner gate must hold the same fd it reads — no stat/read TOCTOU window.

    Proven by removing the path *after* the open would have happened: a stat-then-read
    implementation would fail on the second lookup; an fstat-based one reads the fd it holds.
    """
    p = _secret_file(tmp_path, "s3cr3t")
    real_open = os.open

    def _open_then_unlink(path, flags, *a, **kw):
        fd = real_open(path, flags, *a, **kw)
        os.unlink(path)  # the path is gone the instant after the open
        return fd

    monkeypatch.setattr(os, "open", _open_then_unlink)
    assert read_secret_file(p, label="--webhook-secret-file") == "s3cr3t"


@posix_only
def test_secret_file_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    """A 0600 file owned by SOMEONE ELSE is their secret (or bait) — mode bits alone are not enough."""
    p = _secret_file(tmp_path, "s3cr3t")
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(p).st_uid + 1)
    with pytest.raises(ValidationError, match="owned by uid"):
        resolve_secret(None, str(p), _ENV, flag="--webhook-secret")


@posix_only
def test_fifo_secret_is_refused_without_blocking(tmp_path):
    """A FIFO at the secret path would block an O_RDONLY open forever; O_NONBLOCK + S_ISREG refuses it."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValidationError, match="not a regular file"):
        resolve_secret(None, str(fifo), _ENV, flag="--webhook-secret")


def test_missing_secret_file_still_names_the_path(tmp_path):
    missing = tmp_path / "nope"
    with pytest.raises(ValidationError, match="nope"):
        resolve_secret(None, str(missing), _ENV, flag="--webhook-secret")


def test_oversized_secret_file_is_refused(tmp_path):
    p = _secret_file(tmp_path, "x" * 200)
    with pytest.raises(ValidationError, match="larger than"):
        read_secret_file(p, label="--webhook-secret-file", max_bytes=100)


@posix_only
def test_non_utf8_secret_file_is_refused(tmp_path):
    p = tmp_path / "secret"
    p.write_bytes(b"\xff\xfe\x00bad")
    p.chmod(0o600)
    with pytest.raises(ValidationError, match="not valid UTF-8"):
        read_secret_file(p, label="--webhook-secret-file")


# ------------------------------------------------------------- resolve_secret: empty = fail OPEN


@posix_only
def test_empty_secret_file_raises_instead_of_disabling_hmac(tmp_path):
    """NEGATIVE: the fail-OPEN bug. A truncated secret file resolved to ``None``, and
    ``WebhookAlertChannel`` then posted every page UNSIGNED with no warning — a *missing* file
    failed closed while an *empty* one failed open."""
    p = _secret_file(tmp_path, "   \n")
    with pytest.raises(ValidationError, match="empty"):
        resolve_secret(None, str(p), _ENV, flag="--webhook-secret")


def test_empty_env_secret_raises(monkeypatch):
    """NEGATIVE: ``PYRXD_WATCHTOWER_WEBHOOK_SECRET=""`` is a configured-but-empty secret."""
    monkeypatch.setenv(_ENV, "")
    with pytest.raises(ValidationError, match="empty"):
        resolve_secret(None, None, _ENV, flag="--webhook-secret")


def test_empty_inline_secret_raises():
    """NEGATIVE: ``--webhook-secret ''`` used to silently fall through to "no HMAC"."""
    with pytest.raises(ValidationError, match="empty"):
        resolve_secret("", None, _ENV, flag="--webhook-secret")


def test_unconfigured_secret_is_still_none(monkeypatch):
    """The legitimate 'no HMAC configured' path must NOT be broken by the empty-secret gate."""
    assert resolve_secret(None, None, _ENV, flag="--webhook-secret") is None


def test_env_secret_value_is_returned_verbatim(monkeypatch):
    """Unchanged behavior: the env path never stripped, and must not start now (a secret may
    legitimately end in whitespace)."""
    monkeypatch.setenv(_ENV, "s3cr3t ")
    assert resolve_secret(None, None, _ENV, flag="--webhook-secret") == "s3cr3t "


def test_inline_secret_warns_but_is_honored(caplog):
    caplog.set_level("WARNING")
    assert resolve_secret("s3cr3t", None, _ENV, flag="--webhook-secret") == "s3cr3t"
    assert "process table" in caplog.text


# --------------------------------------------------------------------------- FileAckInbox gate


def _inbox(tmp_path: Path, content: str, *, mode: int = 0o600) -> tuple[Path, FileAckInbox]:
    p = tmp_path / "acks"
    p.write_text(content)
    p.chmod(mode)
    return p, FileAckInbox(p)


@posix_only
def test_group_writable_ack_inbox_is_refused(tmp_path, caplog):
    """NEGATIVE: an ACK suppresses CRITICAL re-pages and zeroes ``unacked_critical`` — the
    escalation signal — so a 0644 inbox is a local silencing channel. Refusal is fail-closed
    TOWARD paging: the ids are dropped, so the pages keep firing."""
    caplog.set_level("ERROR")
    _, inbox = _inbox(tmp_path, "swap-1\n", mode=0o644)
    assert inbox.drain() == []
    assert "0o644" in caplog.text and "chmod 600" in caplog.text


@posix_only
def test_world_writable_ack_inbox_is_refused(tmp_path):
    _, inbox = _inbox(tmp_path, "swap-1\n", mode=0o666)
    assert inbox.drain() == []


@posix_only
def test_symlinked_ack_inbox_is_refused(tmp_path):
    """A symlink at the inbox path is renamed aside as a LINK, then refused by O_NOFOLLOW —
    otherwise the tower would read whatever it points at."""
    real = tmp_path / "real"
    real.write_text("swap-1\n")
    real.chmod(0o600)
    link = tmp_path / "acks"
    link.symlink_to(real)
    assert FileAckInbox(link).drain() == []


@posix_only
def test_foreign_owned_ack_inbox_is_refused(tmp_path, monkeypatch):
    p, inbox = _inbox(tmp_path, "swap-1\n")
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(p).st_uid + 1)
    assert inbox.drain() == []


@posix_only
def test_fifo_ack_inbox_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "acks"
    os.mkfifo(fifo, 0o600)
    assert FileAckInbox(fifo).drain() == []


def test_missing_ack_inbox_is_silent(tmp_path):
    assert FileAckInbox(tmp_path / "nope").drain() == []


@posix_only
def test_oversized_ack_inbox_is_capped_to_whole_lines(tmp_path, caplog):
    """The drain runs on ``on_tick_start``, OUTSIDE the per-tick watchdog, so an unbounded read
    of a grown file stalls the tower with no timeout to catch it. The cut must land on a line
    boundary — half a swap id must never be ACK'd."""
    caplog.set_level("ERROR")
    lines = "".join(f"swap-{i}\n" for i in range(200))
    _, _ = _inbox(tmp_path, lines)
    inbox = FileAckInbox(tmp_path / "acks", max_bytes=100)
    ids = inbox.drain()
    assert 0 < len(ids) < 200
    assert all(i.startswith("swap-") and i[5:].isdigit() for i in ids), ids  # no truncated id
    assert "exceeded" in caplog.text


def test_ack_inbox_survives_one_bad_byte(tmp_path):
    """The read is decoded with ``errors='replace'``: a strict decode would raise AFTER the
    ``os.replace`` claimed the file, and the ``finally: unlink`` would then destroy every
    pending ACK because of a single corrupt byte."""
    p = tmp_path / "acks"
    p.write_bytes(b"swap-1\n\xff\xfe\n swap-2 \n")
    p.chmod(0o600)
    assert FileAckInbox(p).drain() == ["swap-1", "swap-2"]


def test_malformed_ack_ids_are_dropped(tmp_path, caplog):
    caplog.set_level("WARNING")
    _, inbox = _inbox(tmp_path, "swap-1\n../../etc/passwd\nhas space\n" + "x" * 500 + "\nswap-2\n")
    assert inbox.drain() == ["swap-1", "swap-2"]
    assert "malformed swap id" in caplog.text


def test_ack_for_an_unknown_swap_is_inert():
    """Defence in depth behind the file gate: an id naming no live CRITICAL situation records
    nothing, so a forged id cannot pre-arm a future suppression."""
    alerter = DedupAlerter(channel=_NullChannel())
    assert alerter.ack("never-seen") is False
    assert alerter.unacked_critical_count() == 0


async def test_ack_only_suppresses_a_live_critical_situation():
    ch = _NullChannel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))
    assert alerter.ack("swap-2") is False  # a neighbour's id does not silence swap-1
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack("swap-1") is True
    assert alerter.unacked_critical_count() == 0


def test_ack_inbox_rejects_a_bad_max_bytes(tmp_path):
    with pytest.raises(ValidationError):
        FileAckInbox(tmp_path / "acks", max_bytes=0)


class _NullChannel:
    async def send(self, page) -> None:  # pragma: no cover - trivial
        pass


# ----------------------------------------------------------------- presign: key file + sidecar


@posix_only
def test_refund_key_file_must_be_owner_only(tmp_path):
    """NEGATIVE: this file holds a PRIVATE KEY. It had no mode check at all while the
    (far lower-value) webhook secret file did."""
    key = tmp_path / "key.hex"
    key.write_text("11" * 32)
    key.chmod(0o644)
    with pytest.raises(ValidationError, match="must be 0o600"):
        presign_mod._read_privkey(str(key))


def test_refund_key_file_0600_loads(tmp_path):
    key = tmp_path / "key.hex"
    key.write_text("0x" + "11" * 32 + "\n")
    key.chmod(0o600)
    assert presign_mod._read_privkey(str(key)) == bytes.fromhex("11" * 32)


@pytest.mark.parametrize("body", ["11" * 31, "not-hex-at-all", ""])
def test_refund_key_file_rejects_bad_material(tmp_path, body):
    key = tmp_path / "key.hex"
    key.write_text(body)
    key.chmod(0o600)
    with pytest.raises(ValidationError, match="32-byte hex"):
        presign_mod._read_privkey(str(key))


@posix_only
def test_sidecar_is_never_visible_at_a_wider_mode(tmp_path, monkeypatch):
    """The sidecar is a signed transaction that pays you. ``write_text`` + ``chmod`` left it
    world-readable at the process umask for the window in between; mkstemp + fchmod sets the
    mode on the fd BEFORE any bytes exist."""
    monkeypatch.setattr(os, "umask", os.umask)  # keep the ambient umask (typically 0022)
    seen: list[int] = []
    real_write = os.write

    def _spy_write(fd, data):
        seen.append(os.fstat(fd).st_mode & 0o777)
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", _spy_write)
    dest = tmp_path / "swap1.refund.json"
    presign_mod._atomic_write_0600(dest, b'{"a": 1}')
    assert seen == [0o600], "the mode must be set before the first byte is written"
    assert dest.stat().st_mode & 0o777 == 0o600
    assert json.loads(dest.read_text()) == {"a": 1}


def test_sidecar_write_is_atomic_on_failure(tmp_path):
    """A crash mid-write must not leave a TRUNCATED blob at the armed path for the tower to
    load: the destination is only ever the complete file, or absent."""
    dest = tmp_path / "swap1.refund.json"
    dest.write_text('{"good": true}')
    dest.chmod(0o600)

    real_write = os.write

    def _explode(fd, data):
        real_write(fd, data[: len(data) // 2])  # a partial write, then die
        raise OSError("ENOSPC")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(os, "write", _explode)
        with pytest.raises(OSError):
            presign_mod._atomic_write_0600(dest, b'{"replacement": true}')
    assert json.loads(dest.read_text()) == {"good": True}  # untouched
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]  # temp cleaned up


# ------------------------------------------------------------------- entrypoint exit-code contract


def test_watchtower_main_returns_1_on_a_config_error(capsys):
    """The observable contract is unchanged: a config error is exit code 1 with the message on
    stderr — exactly what ``raise SystemExit("...")`` produced — but nothing escapes as a
    process-killing SystemExit."""
    from pyrxd.gravity.watch import run as run_mod

    code = run_mod.main(["--records-dir", str(Path(os.devnull).parent), "--measured"])
    assert code == 1
    assert "must set --rxd-reorg-cost-per-block" in capsys.readouterr().err


def test_watchtower_config_error_is_catchable_by_an_embedder():
    """The reason for the change: an embedding application must be able to CATCH a bad config."""
    from pyrxd.gravity.watch import run as run_mod

    args = run_mod._parse_args(["--records-dir", "/tmp/x", "--measured"])
    with pytest.raises(ValidationError):
        run_mod._policy_from_args(args)


@posix_only
def test_deadman_main_returns_1_on_a_bad_secret_file(tmp_path, capsys):
    from pyrxd.gravity.watch import deadman as deadman_mod

    bad = _secret_file(tmp_path, "s3cr3t", mode=0o644)
    code = deadman_mod.main(
        [
            "--heartbeat-file",
            str(tmp_path / "hb.json"),
            "--once",
            "--webhook-url",
            "https://example.invalid/hook",
            "--webhook-secret-file",
            str(bad),
        ]
    )
    assert code == 1
    assert "must be 0o600" in capsys.readouterr().err


@posix_only
def test_presign_main_returns_1_on_a_bad_key_file(tmp_path, capsys):
    key = tmp_path / "key.hex"
    key.write_text("11" * 32)
    key.chmod(0o644)
    code = presign_mod.main(
        [
            "--record",
            str(tmp_path / "swap1.json"),
            "--refund-key-file",
            str(key),
            "--to-scriptpubkey",
            "51" + "20" + "11" * 32,
            "--fee-sats",
            "500",
        ]
    )
    assert code == 1
    assert "must be 0o600" in capsys.readouterr().err


def test_presign_main_returns_1_on_a_non_hex_spk(tmp_path, capsys):
    key = tmp_path / "key.hex"
    key.write_text("11" * 32)
    key.chmod(0o600)
    code = presign_mod.main(
        [
            "--record",
            str(tmp_path / "swap1.json"),
            "--refund-key-file",
            str(key),
            "--to-scriptpubkey",
            "zzz",
            "--fee-sats",
            "500",
        ]
    )
    assert code == 1
    assert "--to-scriptpubkey must be hex" in capsys.readouterr().err


def test_no_bare_systemexit_left_in_the_watch_package():
    """A guard against regressing the whole class: ``SystemExit`` in shipped package code kills
    an embedder's process. The only legitimate uses are the ``if __name__ == '__main__'`` guards."""
    watch_dir = Path(sys.modules["pyrxd.gravity.watch"].__file__).parent
    offenders = []
    for path in sorted(watch_dir.glob("*.py")):
        tree = ast.parse(path.read_text())
        # Everything under `if __name__ == "__main__":` is a script shell, not library code.
        guards = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If) and "__name__" in ast.dump(node.test) and "__main__" in ast.dump(node.test)
        ]
        guarded = {id(n) for g in guards for n in ast.walk(g)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or id(node) in guarded:
                continue
            raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(raised, ast.Name) and raised.id == "SystemExit":
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []
