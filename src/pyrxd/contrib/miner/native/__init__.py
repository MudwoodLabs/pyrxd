"""Build the native SHA256d grinder (``sha256d_grind.c``) from source.

The grinder is a small C program that speaks the same external-miner protocol
as :mod:`pyrxd.contrib.miner`, so it plugs into
:func:`pyrxd.glyph.dmint.mine_solution_external` and ``pyrxd glyph claim-dmint
--miner-cmd`` unchanged. pyrxd ships its source, not a binary: nothing here is
needed by ``pip install pyrxd``, and nothing here runs unless you call it.

Build it with the C compiler already on the machine::

    python -m pyrxd.contrib.miner.native --out ./sha256d-grind

which is :func:`build`. It compiles, then runs the binary's ``--selftest``
(SHA-256 known-answer vectors on every compression implementation the CPU can
use) and refuses to hand back a binary that fails it. See ``README.md`` beside
the source for usage, and ``docs/concepts/parallel-mining.md`` for the protocol.

Whatever nonce the binary returns is re-verified by ``mine_solution_external``
with :func:`pyrxd.glyph.dmint.verify_sha256d_solution` before it is used, the
same as for any external miner.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404 -- runs the caller's C compiler and the binary it just built
from pathlib import Path

#: The grinder's C source, shipped inside the package.
SOURCE = Path(__file__).with_name("sha256d_grind.c")

#: Flags every build uses. The SHA-extension code path carries its own function-level
#: target attribute and is chosen at run time by CPUID, so no ``-m`` flag (and no
#: ``-march=native``) is needed or wanted: the binary runs on any CPU of its architecture.
CFLAGS: tuple[str, ...] = ("-O2", "-pthread")

#: Compilers tried, in order, when neither ``cc=`` nor ``$CC`` names one.
_DEFAULT_COMPILERS: tuple[str, ...] = ("cc", "gcc", "clang")

#: Seconds allowed for the compile and for the self-test. A compile of this one file
#: takes about a second; the ceiling only stops a wedged toolchain from hanging a caller.
_BUILD_TIMEOUT_S = 300.0
_SELFTEST_TIMEOUT_S = 60.0


class NativeGrinderBuildError(RuntimeError):
    """The grinder could not be compiled, or the binary failed its self-test."""


def find_compiler(cc: str | None = None) -> list[str] | None:
    """The compiler command to use, as an argv prefix, or ``None`` if there is none.

    ``cc`` wins, then ``$CC``, then the first of ``cc``, ``gcc``, ``clang`` on ``PATH``.
    ``cc`` and ``$CC`` may carry flags (``"gcc -m64"``) and are split as a shell would. An
    explicit choice that is not on ``PATH`` gives ``None`` rather than a different compiler.
    """
    spec = cc or os.environ.get("CC")
    if spec:
        argv = shlex.split(spec)
        return argv if argv and shutil.which(argv[0]) else None
    for name in _DEFAULT_COMPILERS:
        found = shutil.which(name)
        if found:
            return [found]
    return None


def build(out: str | os.PathLike[str], *, cc: str | None = None) -> Path:
    """Compile :data:`SOURCE` to ``out``, run its self-test, and return the binary's path.

    :param out: Where to write the executable. Its directory must exist.
    :param cc:  Compiler command (may include flags). Defaults as in :func:`find_compiler`.
    :raises NativeGrinderBuildError: no compiler was found, the compile failed, or the
        built binary failed ``--selftest`` (the file is then removed, so a caller cannot
        pick up a binary that fails the SHA-256 known-answer vectors).
    """
    compiler = find_compiler(cc)
    if compiler is None:
        raise NativeGrinderBuildError(
            "no C compiler found: set CC, pass cc=, or install cc/gcc/clang "
            "(the bundled Python miner, python -m pyrxd.contrib.miner, needs none)"
        )
    out_path = Path(out).resolve()
    cmd = [*compiler, *CFLAGS, "-o", str(out_path), str(SOURCE)]
    compiled = subprocess.run(  # noqa: S603 # nosec B603 -- argv built above from the caller's compiler choice
        cmd, capture_output=True, text=True, timeout=_BUILD_TIMEOUT_S, check=False
    )
    if compiled.returncode != 0:
        raise NativeGrinderBuildError(
            f"compiling {SOURCE.name} failed (exit {compiled.returncode}): {' '.join(cmd)}\n{compiled.stderr.strip()}"
        )
    try:
        selftest_line(out_path)
    except NativeGrinderBuildError:
        out_path.unlink(missing_ok=True)
        raise
    return out_path


def selftest_line(binary: str | os.PathLike[str]) -> str:
    """Run ``binary --selftest`` and return its one-line report: whether every SHA-256
    implementation the CPU can run passed the known-answer vectors, which one ``auto``
    picks, whether the SHA extensions are available, and the default thread count.

    :raises NativeGrinderBuildError: the self-test failed.
    """
    result = subprocess.run(  # noqa: S603 # nosec B603 -- a grinder binary the caller names
        [str(binary), "--selftest"], capture_output=True, text=True, timeout=_SELFTEST_TIMEOUT_S, check=False
    )
    if result.returncode != 0 or not result.stdout.startswith("selftest ok"):
        raise NativeGrinderBuildError(f"{binary} failed its self-test:\n{result.stdout}{result.stderr}".strip())
    return result.stdout.strip()
