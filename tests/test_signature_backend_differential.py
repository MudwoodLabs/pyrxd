"""The browser's curve and the CLI's curve must reach the same verdict, or neither is trustworthy.

WHY THIS FILE EXISTS. Until the public /verify/ page could check a signature, there
was one signature check in this repository: ``verify_attestation`` over ``coincurve``,
which is what ``pyrxd verify`` prints from. There are now two — the page installs
``docs/inspect_static/inspect/secp256k1-bridge.js``, a vendored ``@noble/secp256k1``,
as a recovery backend, because pyrxd installs under Pyodide with ``deps=False`` and
``coincurve`` has no pure-Python wheel. A second implementation of a security check
in a second language is exactly the situation that ends with two surfaces telling one
person two different things about one mark, and the divergence is invisible from
either side: each is internally consistent, each has passing tests.

So this runs BOTH over the SAME records and requires the same answer. It is a
differential test, not a re-assertion of the expected verdicts: it fails when they
disagree, whichever of them is right.

WHAT IS AND IS NOT COMPARED. ``outcome`` and ``recovered_hash160_hex`` — the two
values a reader acts on, and the two the page renders. ``detail`` is deliberately NOT
compared: it carries the underlying library's own words for a refusal, and coincurve
and noble do not phrase "this is not a point" the same way. Requiring identical prose
would make this test fail on a library bump that changed nothing that matters, and a
guard that cries wolf gets deleted.

WHAT THE JAVASCRIPT ACTUALLY DOES, because the answer bounds what this proves. It
recovers a public key and nothing else. The canonical statement's byte-exact JSON,
the varint framing of the signed preimage, the double-SHA256, the range and low-S
checks, hash160, and the comparison against the committed signer all stay in the one
Python implementation and run identically on both sides. That is deliberate — those
are the rules with the sharp edges — and it means this test covers the whole of what
had to be written twice.

The bridge is reached through ``tests/web/secp256k1_backend_harness.mjs``, which
imports it verbatim by the same relative path the browser resolves, and through
``glue.py``'s ``_recovered_key_bytes``, which is the same result-to-outcome mapping
the page uses. Nothing here re-implements or stubs the curve: a test that stubbed
``@noble/secp256k1`` would prove the stub, and planting into the vendored file (see
``TestThePlantsThatProveThisRuns``) is how that is kept honest.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from pyrxd.script.hashmark import (
    AttestationOutcome,
    AttestationResult,
    HashMarkRecord,
    decode_hashmark,
    recovery_backend,
    set_recovery_backend,
    verify_attestation,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_HARNESS = _REPO_ROOT / "tests" / "web" / "secp256k1_backend_harness.mjs"
_GLUE_PATH = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"
_BRIDGE = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "secp256k1-bridge.js"
_VENDORED = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "vendor" / "noble-secp256k1.js"
_CROSS_IMPL = _REPO_ROOT / "tests" / "fixtures" / "hashmark_cross_implementation_vectors.json"

#: The real mainnet mark the public page opens as its example, at
#: a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916 (height 460,572).
#: Written by the reference TypeScript implementation, not by pyrxd. Identical bytes to
#: ``tests/test_hashmark_mainnet_vectors.py``'s ``_V2_SIGNED``; repeated rather than
#: imported so this file states for itself which record it is making claims about.
_MAINNET_MARK = bytes.fromhex(
    "6a08484153484d41524b02020120e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
    "1426ba056431ec69cf27eabeaab250d99ddbd895d2411f750d18df9ab44ba66ced01285a5a067b9ebf7c8ff6b32d"
    "ddb40cc276c5e98d4c2054937e44a40d7628d80cafdd6a372b0aae8f8bb31dbb4d975273a23e8c9771"
)
_MAINNET_SIGNER_HASH160 = "26ba056431ec69cf27eabeaab250d99ddbd895d2"


def _require_node() -> str:
    """The node binary, or a FAILURE.

    Deliberately not a skip. This is the only thing standing between the public page
    and a verdict about a stranger's mark computed by a different implementation from
    the one the CLI uses, and a guard that quietly skips is a guard that has stopped
    running. Same escape hatch as the other web guards, and the same loud name.
    """
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip(
                "node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the browser's signature "
                "check is UNGUARDED in this run"
            )
        pytest.fail(
            "node is required to run the signature-backend differential (it loads the real "
            "secp256k1-bridge.js and the real vendored @noble/secp256k1). Install node, or "
            "set PYRXD_SKIP_JS_RENDER_GUARD=1 to run without this guard."
        )
    return node


def _load_glue():
    """Import ``glue.py`` by path, the way the other web tests do."""
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_diff", _GLUE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _NodeCurve:
    """The vendored JavaScript curve, as a :data:`RecoveryBackend`.

    One long-lived node process over a line protocol — the alternative, a subprocess
    per recovery, spends more time starting node than doing arithmetic and makes the
    guard slow enough to be worth disabling.
    """

    def __init__(self, glue) -> None:
        self._glue = glue
        self._proc = subprocess.Popen(  # nosec B603 — fixed argv, no shell, repo-local script
            [_require_node(), str(_HARNESS)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(_REPO_ROOT),
        )

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            self._proc.kill()

    def __call__(self, message_hash: bytes, r: bytes, s: bytes, rec_id: int, compressed: bool) -> bytes:
        from pyrxd.script.hashmark import RecoveryUnavailable

        request = {
            "messageHash": message_hash.hex(),
            "r": r.hex(),
            "s": s.hex(),
            "recId": int(rec_id),
            "compressed": bool(compressed),
        }
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:  # pragma: no cover - the harness died
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            raise RecoveryUnavailable(f"the curve harness produced no answer: {stderr[:400]}")
        # The SAME mapping the browser uses, from glue.py, so this test cannot agree
        # with a production page that disagrees with it.
        return self._glue._recovered_key_bytes(json.loads(line))


@pytest.fixture(scope="module")
def node_curve():
    glue = _load_glue()
    curve = _NodeCurve(glue)
    try:
        yield curve
    finally:
        curve.close()


@pytest.fixture
def both_backends(node_curve):
    """Return ``run(record, **kw) -> (coincurve_result, javascript_result)``.

    Restores the registry afterwards whatever happens: it is process-global, and a
    leaked backend would silently re-point every other test's signature check at
    node.
    """
    previous = recovery_backend()

    def run(record: HashMarkRecord, **kwargs) -> tuple[AttestationResult, AttestationResult]:
        set_recovery_backend(None)
        native = verify_attestation(record, **kwargs)
        set_recovery_backend(node_curve)
        try:
            javascript = verify_attestation(record, **kwargs)
        finally:
            set_recovery_backend(None)
        return native, javascript

    try:
        yield run
    finally:
        set_recovery_backend(previous)


def _assert_agree(native: AttestationResult, javascript: AttestationResult, what: str) -> None:
    assert javascript.outcome is native.outcome, (
        f"{what}: coincurve says {native.outcome.value} and the browser's "
        f"@noble/secp256k1 says {javascript.outcome.value}. One of the two surfaces is "
        f"telling a reader the wrong thing about this mark.\n"
        f"  coincurve detail: {native.detail}\n"
        f"  javascript detail: {javascript.detail}"
    )
    assert javascript.recovered_hash160_hex == native.recovered_hash160_hex, (
        f"{what}: the two curves recovered different keys — "
        f"coincurve {native.recovered_hash160_hex}, javascript {javascript.recovered_hash160_hex}"
    )


def _cross_implementation_records() -> list[tuple[str, HashMarkRecord]]:
    data = json.loads(_CROSS_IMPL.read_text(encoding="utf-8"))
    out = []
    for entry in data["records"]:
        record = decode_hashmark(bytes.fromhex(entry["script_hex"]))
        assert record.ok, entry["name"]
        out.append((entry["name"], record))
    return out


class TestTheTwoCurvesAgreeOnEveryRecordWeHave:
    def test_the_real_mainnet_mark_verifies_under_BOTH(self, both_backends) -> None:
        """The record the public page opens as its example, and the one a stranger
        actually sees. Both curves must recover the committed signer."""
        native, javascript = both_backends(decode_hashmark(_MAINNET_MARK))
        _assert_agree(native, javascript, "the mainnet example mark")
        assert native.outcome is AttestationOutcome.VALID
        assert javascript.outcome is AttestationOutcome.VALID
        assert javascript.recovered_hash160_hex == _MAINNET_SIGNER_HASH160

    @pytest.mark.parametrize(
        "field, value",
        [
            # A digest nobody signed for. The statement changes, so the signature
            # recovers to SOME key — just not the committed one.
            ("digest_hex", "00" * 32),
            # A label appearing where the signer put none: the same signature over a
            # different statement.
            ("label", "not what was signed"),
        ],
    )
    def test_a_TAMPERED_mainnet_mark_fails_under_BOTH(self, both_backends, field, value) -> None:
        """The other side of the verdict, which is the branch that ships broken when
        only the happy path is exercised. A page that says VERIFIED for an edited
        record is worse than one that checks nothing."""
        edited = replace(decode_hashmark(_MAINNET_MARK), **{field: value})
        native, javascript = both_backends(edited)
        _assert_agree(native, javascript, f"the mainnet mark with {field} tampered")
        assert javascript.outcome is AttestationOutcome.INVALID_SIGNATURE
        assert javascript.recovered_hash160_hex != _MAINNET_SIGNER_HASH160

    def test_a_FLIPPED_SIGNATURE_BYTE_fails_under_BOTH(self, both_backends) -> None:
        """Tamper with the signature rather than the statement. This is the case that
        can recover to nothing at all rather than to a wrong key, so it exercises the
        refusal path through the bridge — the one where the two libraries phrase the
        same finding differently and must still reach the same verdict."""
        record = decode_hashmark(_MAINNET_MARK)
        assert record.signature_hex
        sig = bytearray(bytes.fromhex(record.signature_hex))
        sig[10] ^= 0xFF  # inside r
        edited = replace(record, signature_hex=bytes(sig).hex())
        native, javascript = both_backends(edited)
        _assert_agree(native, javascript, "the mainnet mark with a flipped signature byte")
        assert javascript.outcome is AttestationOutcome.INVALID_SIGNATURE

    def test_the_mainnet_mark_fails_under_BOTH_on_another_chain(self, both_backends) -> None:
        """The genesis hash is inside the signed statement, so the same bytes read
        against another chain are a different statement. Both curves must say so."""
        native, javascript = both_backends(decode_hashmark(_MAINNET_MARK), network_genesis="00" * 32)
        _assert_agree(native, javascript, "the mainnet mark against a foreign genesis")
        assert javascript.outcome is AttestationOutcome.INVALID_SIGNATURE

    @pytest.mark.parametrize(
        "name, record", _cross_implementation_records(), ids=lambda v: v if isinstance(v, str) else ""
    )
    def test_every_cross_implementation_record_agrees(self, both_backends, name, record) -> None:
        """The eight records the reference TypeScript implementation accepted.

        These are the corpus that matters for the JavaScript side specifically: they
        include a label at the byte cap, 22 emoji, a label containing a quote and a
        backslash, and — the one a port is likeliest to get wrong — an UNCOMPRESSED
        signing key, where the header carries no +4 and the recovered point must be
        hashed in its 65-byte form.
        """
        native, javascript = both_backends(record)
        _assert_agree(native, javascript, name)
        assert javascript.outcome is AttestationOutcome.VALID

    def test_a_tampered_cross_implementation_record_agrees(self, both_backends) -> None:
        """Every record above verifies, so on its own that parametrisation cannot tell
        a working differential from one whose backend is never reached. Break one."""
        _, record = _cross_implementation_records()[0]
        edited = replace(record, digest_hex="11" * 32)
        native, javascript = both_backends(edited)
        _assert_agree(native, javascript, "a tampered cross-implementation record")
        assert javascript.outcome is AttestationOutcome.INVALID_SIGNATURE


class TestTheBackendCannotPaintAnHonestMarkRed:
    """A verifier that refuses to run must degrade to NOT CHECKED, never to a verdict.

    This is the asymmetry the whole design rests on: ``UNVERIFIABLE`` means "this
    browser did not check", and an honest signer whose reader's script failed to load
    must not be shown as a forger.
    """

    def test_a_backend_that_cannot_run_yields_NOT_CHECKED(self, both_backends) -> None:
        from pyrxd.script.hashmark import RecoveryUnavailable

        def broken(*_args, **_kwargs):
            raise RecoveryUnavailable("the curve bridge could not be called")

        previous = recovery_backend()
        set_recovery_backend(broken)
        try:
            result = verify_attestation(decode_hashmark(_MAINNET_MARK))
        finally:
            set_recovery_backend(previous)
        assert result.outcome is AttestationOutcome.UNVERIFIABLE
        assert result.recovered_hash160_hex is None
        assert "not checked" in (result.detail or "")

    def test_a_backend_that_raises_ANYTHING_ELSE_is_a_verdict(self) -> None:
        """The other half, and the reason ``RecoveryUnavailable`` is its own class:
        "these bytes recover to nothing" IS a finding, and must stay one."""

        def refuses(*_args, **_kwargs):
            raise ValueError("no key recovers from these bytes")

        previous = recovery_backend()
        set_recovery_backend(refuses)
        try:
            result = verify_attestation(decode_hashmark(_MAINNET_MARK))
        finally:
            set_recovery_backend(previous)
        assert result.outcome is AttestationOutcome.INVALID_SIGNATURE

    @pytest.mark.parametrize(
        "bridge_result, expected_outcome",
        [
            ({"ok": False, "kind": "no-key", "reason": "point invalid"}, AttestationOutcome.INVALID_SIGNATURE),
            ({"ok": False, "kind": "bad-input", "reason": "r must be hex"}, AttestationOutcome.UNVERIFIABLE),
            ({"ok": False, "kind": "harness", "reason": "unreadable"}, AttestationOutcome.UNVERIFIABLE),
            ({"ok": True, "publicKey": "0203"}, AttestationOutcome.UNVERIFIABLE),
            ({"ok": True}, AttestationOutcome.UNVERIFIABLE),
            ({"nonsense": 1}, AttestationOutcome.UNVERIFIABLE),
        ],
    )
    def test_every_bridge_refusal_shape_lands_on_the_right_side(self, bridge_result, expected_outcome) -> None:
        """``glue.py``'s result mapping, over every shape the bridge can return plus
        two it cannot. Only ``no-key`` is allowed to become a verdict; a short key and
        an unrecognised shape are ignorance, and ignorance is NOT CHECKED."""
        glue = _load_glue()
        previous = recovery_backend()
        set_recovery_backend(lambda *_a, **_k: glue._recovered_key_bytes(bridge_result))
        try:
            result = verify_attestation(decode_hashmark(_MAINNET_MARK))
        finally:
            set_recovery_backend(previous)
        assert result.outcome is expected_outcome


class TestTheRegistryStaysOutOfTheShippedLibrary:
    def test_the_default_is_coincurve(self) -> None:
        """Nothing imported so far may have left a backend registered."""
        assert recovery_backend() is None

    def test_nothing_in_src_registers_a_backend(self) -> None:
        """A registered backend WINS over coincurve, so a call to the setter anywhere
        in the shipped library would silently re-point the CLI's signature check. The
        only production caller is ``glue.py``, which runs in a browser that has no
        coincurve to displace.

        Derived from the tree, not from a hand-kept list of files: a new module that
        called the setter would be caught without anyone remembering to add it here.
        """
        offenders = [
            str(path.relative_to(_REPO_ROOT))
            for path in (_REPO_ROOT / "src").rglob("*.py")
            if "set_recovery_backend" in path.read_text(encoding="utf-8")
            and path.name != "hashmark.py"  # its own definition
        ]
        assert offenders == [], (
            f"these shipped modules register a secp256k1 backend, which overrides coincurve "
            f"for every caller in the process: {offenders}"
        )

    def test_the_setter_refuses_a_non_callable(self) -> None:
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            set_recovery_backend("not a function")  # type: ignore[arg-type]
        assert recovery_backend() is None


class TestThePlantsThatProveThisRuns:
    """A differential passes trivially when nothing reaches the second implementation.

    These two assert the corpus is real, so a green run above cannot mean "the loop
    had nothing to iterate" or "the bridge was never imported". The plants that prove
    the ASSERTIONS bite are recorded in the commit message; these are the ones that
    can be made permanent.
    """

    def test_the_corpus_is_not_empty(self) -> None:
        records = _cross_implementation_records()
        assert len(records) >= 8, f"only {len(records)} cross-implementation records reached the differential"

    def test_the_harness_reaches_the_real_vendored_curve(self) -> None:
        """Not a stub, not a re-implementation, not a copy.

        ``secp256k1-bridge.js`` must import the vendored file by the path the browser
        resolves, and the harness must import the bridge itself. If either is ever
        replaced by a local re-implementation, every test above starts comparing
        Python to Python and passes forever.
        """
        assert _VENDORED.exists(), f"{_VENDORED} is missing — the page has no curve to install"
        bridge = _BRIDGE.read_text(encoding="utf-8")
        assert 'from "./vendor/noble-secp256k1.js"' in bridge, (
            "secp256k1-bridge.js no longer imports the vendored curve by the path the browser "
            "resolves. If it now bundles or re-implements the arithmetic, this differential is "
            "comparing something other than what the page runs."
        )
        harness = _HARNESS.read_text(encoding="utf-8")
        assert "secp256k1-bridge.js" in harness
