"""The native SHA256d grinder (``src/pyrxd/contrib/miner/native/sha256d_grind.c``) against pyrxd.

Every test here runs the real binary, built from the shipped source by the shipped build
helper (:func:`pyrxd.contrib.miner.native.build`), and checks it against an oracle that does
not share its code: :mod:`hashlib` for the hashing, and
:func:`pyrxd.glyph.dmint.verify_sha256d_solution` for the hit rule.

What each part proves:

* **Digests** — for every nonce in a range, the grinder's SHA256d equals hashlib's, for both
  nonce widths, both SHA-256 implementations (``portable`` and ``auto``, which is the SHA
  extensions wherever the CPU has them), and ranges that end at the top of the nonce space.
* **Never misses** — with a dense test target, the set of hits the grinder reports over a range
  equals, exactly, the set an exhaustive hashlib sweep finds, for several thread counts and a
  range that is not a whole number of the grinder's 65,536-nonce chunks.
* **The production rule** — real difficulty-1 solutions (``_HIT_W4`` / ``_HIT_W8``, each accepted
  by ``verify_sha256d_solution``) are found at their exact nonce, in ranges that start and end on
  them; a range one short of them is reported exhausted; ``target == value`` is refused and
  ``target == value + 1`` accepted; and a digest with four zero bytes but the sign bit set
  (``_NEAR_MISS_W8``) is refused even for a target above the ceiling, which is clamped.
* **The production entry point** — :func:`mine_solution_external` and
  :func:`mine_solution_dispatch`, which ``pyrxd glyph claim-dmint --miner-cmd`` goes through,
  accept the grinder's answers (they re-verify every nonce), receive its progress frames, map its
  exhaustion to ``MaxAttemptsError``, and refuse BLAKE3/K12 before starting it.

The dense target (``--target96``) exists only for tests: it replaces the hit rule's target with
a 96-bit one, so a hit is ``digest[0:12]`` (big-endian) below it. For every target pyrxd can send
(at most ``MAX_SHA256D_TARGET``, below ``2**63``) that is exactly ``verify_sha256d_solution``'s
rule — :func:`test_the_dense_oracle_is_the_verifier_rule_on_real_targets` asserts it on the real
vectors — and the same ``is_hit`` function in the C evaluates both.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pyrxd.contrib.miner.native import NativeGrinderBuildError, build, selftest_line
from pyrxd.contrib.miner.native.__main__ import main as native_main
from pyrxd.contrib.miner.protocol import MineExhausted, MineRequest, MineSuccess, parse_progress_line, parse_response
from pyrxd.glyph.dmint import (
    MAX_SHA256D_TARGET,
    DmintAlgo,
    mine_solution_dispatch,
    mine_solution_external,
    verify_sha256d_solution,
)
from pyrxd.security.errors import MaxAttemptsError

# Real difficulty-1 solutions, found with this grinder on 2026-09-23 and each checked with
# verify_sha256d_solution (the checks below re-assert it, so a wrong vector cannot pass).
_HIT_W4 = {
    "preimage": "976cb952ff480e390517b739e4fd9110ecbe785c7e9d07a508872ea3b58ba4ee"
    "8980cbda5df167675bd585baa884468d2a1ae5112a0becaa36354fc91f8a1868",
    "nonce": "34e0fed4",
    "digest": "000000001fd9f278ee68b3d625180a2a78b03882273cfd59efea0c6b925560a8",
}
_HIT_W8 = {
    "preimage": "41704e9128ead24e0d4a69a3d505b17a8c76091317249166786d4ec446f1f541"
    "0e483ff539d1fbe405d55c8bc4670fe6399d19f7cdb8c20f55328ecfd302db87",
    "nonce": "6e1c08db01000000",
    "digest": "0000000006040314c261b4b9c9a778c7111332dd3f448ac580e07b13196b739a",
}
# Four zero bytes, then 0xe244...: the sign bit is set, so no target can accept it.
_NEAR_MISS_W8 = {
    "preimage": "de4e7bac93eca0074a9418db7226e9e2fb6fdca79e326fb21daf2526db29669e"
    "322a9f4ec325eff7a3afa69a8b8334f6c8f730e5ea6deb05fe009ebfae348f20",
    "nonce": "335759eb01000000",
    "digest": "00000000e244ab38d4c4751ac9d85f69b22435a9db2e4b1e6b9c00e65fe49644",
}

_ALL_HIT = "1" + "0" * 24  # --target96 2**96: every digest's 96-bit prefix is below it
_IMPLS = ("auto", "portable")


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _nonce_int(vector: dict[str, str]) -> int:
    return int.from_bytes(bytes.fromhex(vector["nonce"]), "little")


def _value(vector: dict[str, str]) -> int:
    return int.from_bytes(bytes.fromhex(vector["digest"])[4:12], "big")


def _request(preimage: bytes, width: int, target: int = MAX_SHA256D_TARGET) -> str:
    """The request exactly as mine_solution_external writes it."""
    return json.dumps({"preimage_hex": preimage.hex(), "target_hex": f"{target:016x}", "nonce_width": width})


def _run(grinder: str, request: str | bytes, *flags: str, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    data = request.encode() if isinstance(request, str) else request
    return subprocess.run([grinder, *flags], input=data, capture_output=True, timeout=timeout, check=False)


def _enumerate(grinder: str, preimage: bytes, width: int, start: int, count: int, target96: str, *flags: str):
    """Every hit the grinder reports in [start, start + count), as {nonce: digest}."""
    r = _run(
        grinder,
        _request(preimage, width),
        "--enumerate",
        "--target96",
        target96,
        "--nonce-start",
        str(start),
        "--nonce-count",
        str(count),
        "--quiet",
        *flags,
    )
    assert r.returncode == 0, r.stderr
    hits: dict[int, bytes] = {}
    for line in r.stdout.decode().splitlines():
        nonce_hex, digest_hex = line.split()
        nonce = int.from_bytes(bytes.fromhex(nonce_hex), "little")
        assert len(bytes.fromhex(nonce_hex)) == width
        assert nonce not in hits, f"nonce {nonce} reported twice"
        hits[nonce] = bytes.fromhex(digest_hex)
    return hits


def _solve(grinder: str, preimage: bytes, width: int, start: int, count: int, *flags: str, target: int | None = None):
    """Protocol mode over [start, start + count). Returns (exit code, parsed response)."""
    r = _run(
        grinder,
        _request(preimage, width, MAX_SHA256D_TARGET if target is None else target),
        "--nonce-start",
        str(start),
        "--nonce-count",
        str(count),
        "--quiet",
        *flags,
    )
    assert r.returncode in (0, 2), f"exit {r.returncode}: {r.stderr!r}"
    return r.returncode, parse_response(r.stdout)


# --------------------------------------------------------------------------- the build


class TestBuildAndSelftest:
    def test_the_build_helper_produces_a_binary_that_passes_its_selftest(self, grinder: str) -> None:
        line = selftest_line(grinder)
        assert re.fullmatch(r"selftest ok: impl=(shani|portable) shani_available=[01] threads=\d+", line), line

    def test_sha_extension_detection_agrees_with_the_kernel(self, grinder: str) -> None:
        """A grinder that misdetects the CPU silently falls back to the portable code, about 4x
        slower on the machine this was written on — the kind of regression nothing else would
        report. Where the kernel lists CPU flags, the grinder's CPUID check must agree with it."""
        cpuinfo = Path("/proc/cpuinfo")
        if not cpuinfo.exists():
            pytest.skip("no /proc/cpuinfo on this platform")
        kernel_says = bool(re.search(r"^flags\s*:.*\bsha_ni\b", cpuinfo.read_text(), re.M))
        line = selftest_line(grinder)
        assert f"shani_available={int(kernel_says)}" in line, (kernel_says, line)
        assert ("impl=shani" in line) == kernel_says

    def test_a_missing_compiler_is_reported_not_hidden(self, tmp_path: Path) -> None:
        with pytest.raises(NativeGrinderBuildError, match="no C compiler found"):
            build(tmp_path / "g", cc="definitely-not-a-compiler-xyz")

    def test_a_failing_compile_is_reported_with_the_compiler_output(self, tmp_path: Path) -> None:
        # `false` is a "compiler" that exits 1 without writing anything.
        with pytest.raises(NativeGrinderBuildError, match="compiling sha256d_grind.c failed"):
            build(tmp_path / "g", cc="false")

    def test_a_binary_that_fails_its_selftest_is_removed(self, tmp_path: Path) -> None:
        """The build helper must never hand back a binary whose SHA-256 is wrong. Plant one: a
        'compiler' that writes a script whose --selftest reports failure."""
        fake_cc = tmp_path / "fake-cc"
        fake_cc.write_text(
            "#!/bin/sh\n"
            'while [ "$1" != "-o" ]; do shift; done\n'
            'printf \'#!/bin/sh\\necho "selftest FAILED: impl=portable"\\nexit 1\\n\' > "$2"\n'
            'chmod +x "$2"\n'
        )
        fake_cc.chmod(0o755)
        out = tmp_path / "g"
        with pytest.raises(NativeGrinderBuildError, match="failed its self-test"):
            build(out, cc=str(fake_cc))
        assert not out.exists()

    def test_the_module_entry_point_builds_and_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], grinder: str
    ) -> None:
        del grinder  # only here so this test skips/fails with the others when there is no compiler
        assert native_main(["--out", str(tmp_path / "g")]) == 0
        out = capsys.readouterr().out
        assert "built " in out and "selftest ok" in out
        assert native_main(["--out", str(tmp_path / "h"), "--cc", "definitely-not-a-compiler-xyz"]) == 1
        assert native_main(["--print-source"]) == 0
        assert capsys.readouterr().out.strip().endswith("sha256d_grind.c")
        with pytest.raises(SystemExit):
            native_main([])


# --------------------------------------------------------------------------- digests


@pytest.mark.parametrize("impl", _IMPLS)
@pytest.mark.parametrize("width", [4, 8])
def test_every_digest_matches_hashlib(grinder: str, impl: str, width: int) -> None:
    rng = random.Random(f"digests-{impl}-{width}")
    top = 1 << (8 * width)
    starts = [0, top - 300, rng.randrange(top - 300)]  # the bottom, the top, and a random range
    for i in range(12):
        preimage = rng.randbytes(64)
        start = starts[i % len(starts)]
        count = 300
        hits = _enumerate(grinder, preimage, width, start, count, _ALL_HIT, "--impl", impl, "--workers", "3")
        assert sorted(hits) == list(range(start, start + count)), "a nonce in the range was skipped or invented"
        for nonce, digest in hits.items():
            assert digest == _sha256d(preimage + nonce.to_bytes(width, "little")), (impl, width, nonce)


# --------------------------------------------------------------------------- never misses


@pytest.mark.parametrize("impl", _IMPLS)
@pytest.mark.parametrize("width", [4, 8])
@pytest.mark.parametrize("workers", [1, 3, 8])
def test_the_hits_equal_an_exhaustive_hashlib_sweep(grinder: str, impl: str, width: int, workers: int) -> None:
    """Exactly the oracle's hits: none missed, none invented, none duplicated. The range is two
    chunks plus a remainder, so the chunk boundaries and the short last chunk are both crossed."""
    rng = random.Random(f"sweep-{impl}-{width}-{workers}")
    count = 2 * 65536 + 777
    for _ in range(2):
        preimage = rng.randbytes(64)
        start = rng.randrange((1 << (8 * width)) - count)
        target96 = rng.randrange(1 << 89, 1 << 93)  # a hit rate between 1 in 128 and 1 in 8
        want = set()
        for nonce in range(start, start + count):
            digest = _sha256d(preimage + nonce.to_bytes(width, "little"))
            if int.from_bytes(digest[:12], "big") < target96:
                want.add(nonce)
        assert len(want) > 100, "the target is not dense enough to test anything"
        got = _enumerate(
            grinder, preimage, width, start, count, f"{target96:x}", "--impl", impl, "--workers", str(workers)
        )
        assert set(got) == want


def test_protocol_mode_returns_a_hit_the_oracle_agrees_with_over_the_default_range(grinder: str) -> None:
    """No --nonce-start/--nonce-count: the whole nonce space, as pyrxd's request gets."""
    rng = random.Random("default-range")
    for width in (4, 8):
        preimage = rng.randbytes(64)
        target96 = 1 << 90
        r = _run(grinder, _request(preimage, width), "--target96", f"{target96:x}", "--quiet")
        assert r.returncode == 0, r.stderr
        result = parse_response(r.stdout)
        assert isinstance(result, MineSuccess)
        assert len(result.nonce) == width
        assert int.from_bytes(_sha256d(preimage + result.nonce)[:12], "big") < target96
        assert result.attempts >= 1


# --------------------------------------------------------------------------- the production rule


def test_the_vectors_are_real_solutions() -> None:
    """The fixtures below are only evidence if they are what they claim to be."""
    for vector, is_solution in ((_HIT_W4, True), (_HIT_W8, True), (_NEAR_MISS_W8, False)):
        preimage, nonce = bytes.fromhex(vector["preimage"]), bytes.fromhex(vector["nonce"])
        assert _sha256d(preimage + nonce).hex() == vector["digest"]
        assert vector["digest"].startswith("00000000")
        width = len(nonce)
        assert verify_sha256d_solution(preimage, nonce, MAX_SHA256D_TARGET, nonce_width=width) is is_solution


def test_the_dense_oracle_is_the_verifier_rule_on_real_targets() -> None:
    """For every target pyrxd can send, "96-bit prefix below the target" and
    verify_sha256d_solution agree — on real four-zero-byte digests, where the value compare
    is what decides, and at the boundary on each side."""
    for vector in (_HIT_W4, _HIT_W8, _NEAR_MISS_W8):
        preimage, nonce = bytes.fromhex(vector["preimage"]), bytes.fromhex(vector["nonce"])
        value = _value(vector)
        for target in {1, value, value + 1, value - 1, MAX_SHA256D_TARGET, (1 << 64) - 1}:
            if target < 1:
                continue
            prefix96 = int.from_bytes(bytes.fromhex(vector["digest"])[:12], "big")
            oracle = prefix96 < min(target, MAX_SHA256D_TARGET)
            assert oracle == verify_sha256d_solution(preimage, nonce, target, nonce_width=len(nonce)), (vector, target)


@pytest.mark.parametrize("impl", _IMPLS)
@pytest.mark.parametrize("vector", [_HIT_W4, _HIT_W8], ids=["v1", "v2"])
def test_a_real_solution_is_found_at_its_nonce_and_not_before(grinder: str, impl: str, vector) -> None:
    preimage, width, n = bytes.fromhex(vector["preimage"]), len(bytes.fromhex(vector["nonce"])), _nonce_int(vector)
    flags = ("--impl", impl, "--workers", "4")
    # The oracle: no other solution in the window, so "found n" is the only right answer.
    window = range(n - 5000, n + 5001)
    assert [
        m
        for m in window
        if verify_sha256d_solution(preimage, m.to_bytes(width, "little"), MAX_SHA256D_TARGET, nonce_width=width)
    ] == [n]

    for start, count in ((n - 5000, 10001), (n, 1), (n - 5000, 5001)):  # around it, on it, ending on it
        code, result = _solve(grinder, preimage, width, start, count, *flags)
        assert code == 0 and isinstance(result, MineSuccess), (start, count)
        assert result.nonce == bytes.fromhex(vector["nonce"])
    for start, count in ((n - 5000, 5000), (n + 1, 5000)):  # stopping one short, starting one past
        code, result = _solve(grinder, preimage, width, start, count, *flags)
        assert code == 2 and isinstance(result, MineExhausted), (start, count)


@pytest.mark.parametrize("impl", _IMPLS)
def test_the_target_comparison_is_strict_and_the_ceiling_is_clamped(grinder: str, impl: str) -> None:
    flags = ("--impl", impl)
    for vector in (_HIT_W4, _HIT_W8):
        preimage, width, n, value = (
            bytes.fromhex(vector["preimage"]),
            len(bytes.fromhex(vector["nonce"])),
            _nonce_int(vector),
            _value(vector),
        )
        assert _solve(grinder, preimage, width, n, 1, *flags, target=value)[0] == 2  # value < value: no
        assert _solve(grinder, preimage, width, n, 1, *flags, target=value + 1)[0] == 0  # value < value + 1: yes
    # Four zero bytes, sign bit set: refused at the ceiling AND for a target above it, which
    # pyrxd clamps to the ceiling (an unclamped 0xffff... would accept this digest).
    preimage, n = bytes.fromhex(_NEAR_MISS_W8["preimage"]), _nonce_int(_NEAR_MISS_W8)
    assert _solve(grinder, preimage, 8, n, 1, *flags)[0] == 2
    assert _solve(grinder, preimage, 8, n, 1, *flags, target=(1 << 64) - 1)[0] == 2
    # ...while the dense test target, which is not clamped, does see it — so the refusals
    # above are the rule's doing, not a miss.
    hits = _enumerate(grinder, preimage, 8, n, 1, "1" + "0" * 16, *flags)
    assert list(hits) == [n]


# --------------------------------------------------------------------------- the production entry point


def test_mine_solution_external_accepts_the_grinders_answer(grinder: str) -> None:
    """The funnel `claim-dmint --miner-cmd` and the nightly dMint suites go through. It re-verifies
    the nonce with verify_sha256d_solution, so reaching the return statement is the check."""
    for vector in (_HIT_W4, _HIT_W8):
        preimage, nonce = bytes.fromhex(vector["preimage"]), bytes.fromhex(vector["nonce"])
        n = _nonce_int(vector)
        # The window test_a_real_solution_is_found_at_its_nonce_and_not_before proves holds no other hit.
        argv = [grinder, "--nonce-start", str(n - 5000), "--nonce-count", "10001"]
        result = mine_solution_external(
            preimage, MAX_SHA256D_TARGET, miner_argv=argv, nonce_width=len(nonce), timeout_s=120
        )
        assert result.nonce == nonce
        result = mine_solution_dispatch(
            preimage, MAX_SHA256D_TARGET, miner_argv=argv, nonce_width=len(nonce), timeout_s=120
        )
        assert result.nonce == nonce


def test_exhaustion_reaches_the_caller_as_max_attempts(grinder: str) -> None:
    preimage, n = bytes.fromhex(_HIT_W4["preimage"]), _nonce_int(_HIT_W4)
    argv = [grinder, "--nonce-start", str(n - 5000), "--nonce-count", "5000"]
    with pytest.raises(MaxAttemptsError, match="exhausted"):
        mine_solution_external(preimage, MAX_SHA256D_TARGET, miner_argv=argv, nonce_width=4, timeout_s=120)


def test_progress_frames_reach_the_callers_progress_hook(grinder: str) -> None:
    """One worker over 2**25 nonces with no hit took 2.7 s on the machine this was written on
    (12.6 M/s single-threaded with the SHA extensions), so at least one 0.5 s progress frame is
    written, parsed, and delivered."""
    preimage = bytes.fromhex(_HIT_W4["preimage"])
    seen: list[tuple[int, float]] = []
    argv = [grinder, "--workers", "1", "--nonce-start", "0", "--nonce-count", str(1 << 25)]
    with pytest.raises(MaxAttemptsError):
        mine_solution_external(
            preimage,
            1,
            miner_argv=argv,
            nonce_width=4,
            timeout_s=300,
            progress=lambda a, e: seen.append((a, e)),
            progress_interval_s=0.1,
        )
    assert seen, "no progress frame reached the callback"
    assert all(0 <= a <= 1 << 25 and e >= 0 for a, e in seen)


def test_the_progress_frames_parse_with_the_protocol_parser(grinder: str) -> None:
    preimage = bytes.fromhex(_HIT_W4["preimage"])
    r = _run(grinder, _request(preimage, 4, 1), "--workers", "1", "--nonce-count", str(1 << 25))
    assert r.returncode == 2 and parse_response(r.stdout) == MineExhausted()
    frames = [line for line in r.stderr.decode().splitlines() if line.startswith("{")]
    assert frames, r.stderr
    assert all(parse_progress_line(f) is not None for f in frames)


@pytest.mark.parametrize("algo", [DmintAlgo.BLAKE3, DmintAlgo.K12])
def test_a_non_sha256d_contract_is_refused_before_the_grinder_starts(grinder: str, tmp_path: Path, algo) -> None:
    """The protocol carries no algorithm, so the grinder cannot tell a BLAKE3 preimage from a
    SHA256d one; the refusal is pyrxd's, before any process starts. Prove "before": the argv
    names the real grinder but routes it through a wrapper that records being run."""
    marker = tmp_path / "ran"
    wrapper = tmp_path / "wrapper.sh"
    wrapper.write_text(f'#!/bin/sh\ntouch "{marker}"\nexec "{grinder}" "$@"\n')
    wrapper.chmod(0o755)
    preimage = bytes.fromhex(_HIT_W4["preimage"])
    for call in (mine_solution_external, mine_solution_dispatch):
        with pytest.raises(NotImplementedError, match=algo.name):
            call(preimage, MAX_SHA256D_TARGET, miner_argv=[str(wrapper)], nonce_width=4, algo=algo)
    assert not marker.exists()
    # ...and the same wrapper does run for SHA256d, so the marker is a working witness.
    n = _nonce_int(_HIT_W4)
    argv = [str(wrapper), "--nonce-start", str(n), "--nonce-count", "1"]
    mine_solution_external(preimage, MAX_SHA256D_TARGET, miner_argv=argv, nonce_width=4, algo=DmintAlgo.SHA256D)
    assert marker.exists()


# --------------------------------------------------------------------------- the request


_PRE = "ab" * 64


def _req(**fields) -> str:
    base = {"preimage_hex": _PRE, "target_hex": "7fffffffffffffff", "nonce_width": 4}
    base.update(fields)
    return json.dumps({k: v for k, v in base.items() if v is not ...})


def _raw(value_text: str) -> str:
    """A valid request plus an unknown field whose value is ``value_text`` verbatim."""
    return _req()[:-1] + f', "x": {value_text}}}'


# Requests both parsers accept, and requests both refuse (exit 1 / ProtocolError).
_BOTH_ACCEPT = [
    _req(),
    _req(nonce_width=8),
    _req(protocol=1),
    _req(preimage_hex=_PRE.upper()),
    _req(target_hex="0x7f"),
    _req(target_hex="ffffffffffffffff"),
    _req(target_hex="00000000000000000000000001"),
    _req(target_hex="1" + "0" * 40),
    _req(extra="x", n=3, f=1.5, t=True, z=None),
    " \n" + _req() + "\n ",
    _raw("-0.5e+3"),
    _raw("0"),
    _raw("-0"),
    _raw("1E9"),
    _raw("18446744073709551616"),
]
_BOTH_REFUSE = [
    "",
    "not json",
    "[]",
    _req(preimage_hex=...),
    _req(target_hex=...),
    _req(nonce_width=...),
    _req(nonce_width=5),
    _req(nonce_width=True),
    _req(nonce_width="4"),
    _req(nonce_width=4.0),
    _req(preimage_hex="ab" * 63),
    _req(preimage_hex="zz" * 64),
    _req(target_hex="0"),
    _req(target_hex="xyz"),
    _req(target_hex=""),
    _req(target_hex=127),
    _req(protocol=2),
    _req(protocol="1"),
    _req() + "garbage",
    "{" + " " * 5000 + "}",
    # Not JSON numbers or literals, even in a field nobody reads.
    _raw("-"),
    _raw("01"),
    _raw("1."),
    _raw(".5"),
    _raw("1e"),
    _raw("+1"),
    _raw("truex"),
    _raw("nul"),
    # Not UTF-8.
    _req().encode()[:-1] + b', "x": "\xff"}',
    # A repeated key: the last value wins in both, and here it is invalid.
    _req()[:-1] + ', "nonce_width": 5}',
]
# Accepted by the Python parser, refused by the C one — deliberately: pyrxd's own request never
# contains any of them (it is json.dumps of two lowercase hex strings and an int). Pinned both
# ways, so a change on either side has to be looked at here.
_ONLY_PYTHON_ACCEPTS = [
    _req(target_hex="7f_ff"),
    _req(target_hex=" 7f "),
    _req(target_hex="+7f"),
    _req(preimage_hex=" ".join(["ab"] * 64)),
    _req(extra="\\u0041"),
    _req(extra={"nested": 1}),
    _req(extra=[1, 2]),
    json.dumps({"preimage_hex": _PRE, "target_hex": "7f", "nonce_width": 4, "x": "\u00e9"}, ensure_ascii=False),
    # A repeated key whose FIRST value is invalid: Python keeps only the last, valid one.
    '{"nonce_width": 5, ' + _req()[1:],
]


def _python_accepts(request: str | bytes) -> bool:
    try:
        MineRequest.from_json(request.encode() if isinstance(request, str) else request)
    except ValueError:
        return False
    return True


def _grinder_accepts(grinder: str, request: str | bytes) -> bool:
    r = _run(grinder, request, "--nonce-count", "1", "--quiet", timeout=30)
    assert r.returncode in (0, 1, 2), r
    return r.returncode != 1


@pytest.mark.parametrize("request_text", _BOTH_ACCEPT)
def test_requests_both_parsers_accept(grinder: str, request_text: str | bytes) -> None:
    assert _python_accepts(request_text)
    assert _grinder_accepts(grinder, request_text)


@pytest.mark.parametrize("request_text", _BOTH_REFUSE)
def test_requests_both_parsers_refuse(grinder: str, request_text: str | bytes) -> None:
    assert not _python_accepts(request_text)
    assert not _grinder_accepts(grinder, request_text)


@pytest.mark.parametrize("request_text", _ONLY_PYTHON_ACCEPTS)
def test_requests_only_the_python_parser_accepts(grinder: str, request_text: str | bytes) -> None:
    assert _python_accepts(request_text)
    assert not _grinder_accepts(grinder, request_text)


@pytest.mark.parametrize(
    "flags",
    [
        ("--workers", "0"),
        ("--workers", "x"),
        ("--workers",),
        ("--nonce-count", "0"),
        ("--nonce-start", "-1"),
        ("--nonce-start", str(1 << 32)),
        ("--nonce-start", str((1 << 32) - 1), "--nonce-count", "2"),
        ("--enumerate", "--nonce-count", str((1 << 20) + 1)),
        ("--target96", "0"),
        ("--target96", "1" + "0" * 24 + "1"),
        ("--target96", "g"),
        ("--impl", "bogus"),
        ("--no-such-flag",),
    ],
)
def test_bad_flags_are_usage_errors(grinder: str, flags: tuple[str, ...]) -> None:
    r = _run(grinder, _req(), *flags, timeout=30)
    assert r.returncode == 1, (flags, r)
    assert r.stdout == b""


def test_the_last_nonce_of_the_v1_space_is_searchable(grinder: str) -> None:
    """--nonce-start 2**32 - 1 with a count of 1 is inside the space; one more is not (above)."""
    r = _run(grinder, _req(), "--nonce-start", str((1 << 32) - 1), "--nonce-count", "1", "--target96", _ALL_HIT)
    assert r.returncode == 0, r
    assert json.loads(r.stdout)["nonce_hex"] == "ffffffff"


# --------------------------------------------------------------------------- lifecycle


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the parent-death check is asserted via /proc")
def test_the_grinder_stops_when_its_parent_is_killed(grinder: str, tmp_path: Path) -> None:
    """pyrxd kills the grinder on timeout; if pyrxd itself is SIGKILLed it cannot, and a V2
    request covers 2**64 nonces. The grinder must notice its parent is gone and exit rather than
    hold every core indefinitely."""
    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys, time\n"
            f"p = subprocess.Popen([{grinder!r}, '--quiet', '--workers', '1'], stdin=subprocess.PIPE,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            f"p.stdin.write({_request(bytes(64), 8, 1).encode()!r}); p.stdin.close()\n"
            "print(p.pid, flush=True)\n"
            "time.sleep(600)\n",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        child_pid = int(parent.stdout.readline())
        time.sleep(0.3)
        assert _alive(child_pid), "the grinder should be running before its parent is killed"
    finally:
        parent.send_signal(signal.SIGKILL)
        parent.wait(timeout=10)
        parent.stdout.close()
    deadline = time.monotonic() + 10
    while _alive(child_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    alive = _alive(child_pid)
    if alive:  # do not leave it running whatever the verdict
        os.kill(child_pid, signal.SIGKILL)
    assert not alive, "the grinder kept running after its parent was killed"


def _alive(pid: int) -> bool:
    """Running, as opposed to exited (a zombie waiting to be reaped counts as exited)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] not in ("Z", "X")
