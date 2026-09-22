"""No pyrxd dataclass may print a field that looks like secret material.

Why this exists as a DERIVED check
----------------------------------
``UnwrappedCEK`` shipped with a plain ``cek: bytes`` field, so ``repr()`` / ``str()`` of the
value ``unwrap_cek_x25519_detailed`` returns printed the recovered content key — while its
siblings (``TimelockMintBuild.cek``, ``TimelockMintResult.cek_for_caller_to_store``,
``FeeInput.wif``) each hid theirs. ``test_key_material_never_echoed.py`` is written one surface
at a time, so a NEW secret-holding type is invisible to it until someone remembers to add a
case — which is exactly how this one got through.

So this file does not list the classes it checks. It imports every module in the package,
finds every dataclass, and flags each field whose NAME looks secret and whose TYPE could hold
text or bytes. Each flagged field is then checked BEHAVIOURALLY: an instance is built with a
sentinel in that field, and ``repr()``, ``str()`` and ``format()`` (what an f-string calls)
must not contain ANY six-character run of the sentinel, as text or as hex — so a ``__repr__``
that prints ``self.cek[:16]`` is a leak, not a pass. That tests the property rather than the
mechanism, so ``field(repr=False)``, a hand-written ``__repr__`` and ``@dataclass(repr=False)``
all pass, and a hand-written ``__repr__`` or ``__str__`` that prints the field anyway fails.

What it cannot see
------------------
Each of these is a real blind spot, not a solved one:

- A secret under a name the pattern does not recognise — ``content_key``, ``key``, ``blob``,
  ``k``. The pattern is below; widen it when a new spelling appears.
  ``test_the_name_pattern_catches_the_spellings_pyrxd_uses`` pins the known ones.
- A secret typed as something other than text or bytes — an ``int`` scalar, a ``list[int]``.
  The sentinel is text or bytes, so those fields are not flagged at all.
- A field typed as a key OBJECT (``PrivateKey``, ``SecretBytes``, ``PrivateKeyMaterial``).
  Not flagged either; those types redact their own ``repr``, which
  ``test_the_key_types_redact_their_own_repr`` asserts, so a default dataclass ``repr`` of
  them is safe.
- A leak shorter than six characters, or transformed on the way out (base64, reversed,
  interleaved), and any rendering other than ``repr`` / ``str`` / ``format`` — ``vars()``,
  ``dataclasses.asdict``, ``json``, ``pickle``.
- Anything that is not a dataclass: plain classes, ``NamedTuple``, ``__slots__`` classes with
  their own ``repr`` (``GlyphClient``'s ``TimelockMintReceipt`` is one).
- A dataclass that module import does not expose. ``test_every_dataclass_in_the_source_is_seen``
  AST-scans the source, resolving the module's own aliases for ``dataclass``, and fails if any
  decorated class is missing from the runtime set. ``make_dataclass`` and a non-decorator
  ``dataclass(...)`` call cannot be attributed to a class name from source, so each call site
  must be listed in ``REVIEWED_DYNAMIC_DATACLASS_SITES`` (empty today) or the guard fails.

The exemptions are REVIEWED, not derived: each says why the value is public. Membership is
pinned exactly, in both directions — an exempt field that becomes hidden, or disappears, fails
until its entry is removed — so a reason cannot outlive the field it describes. Where a reason
is checkable, a test below checks it.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
import pathlib
import pkgutil
import re
from types import ModuleType

import pytest

import pyrxd

# ── what counts as "looks secret" ─────────────────────────────────────────────

#: Tokens of a snake_case field name that mark it as secret material. A name matches when any
#: ``_``-separated token is one of these, or starts with ``priv`` (private, privkey, priv_key).
_SECRET_TOKENS = frozenset(
    {
        "cek",
        "kek",
        "wif",
        "seed",
        "secret",
        "secrets",
        "mnemonic",
        "passphrase",
        "password",
        "sk",
        "xprv",
        "prv",
        "preimage",
    }
)

#: Annotations that can hold the material as text or bytes. ``Any`` is included on purpose: a
#: field typed ``Any`` will print a ``str`` it is handed exactly as a ``str`` field would.
_TEXTUAL = re.compile(r"\b(bytes|bytearray|memoryview|str|Any)\b")

#: Not English words, so a redacting ``repr`` that prints "SECRET" or "<redacted>" cannot
#: collide with a six-character window of either one.
_SENTINEL_STR = "Qz7Xv9Kw3Jm8Rt2Pb5Lg"
_SENTINEL_BYTES = b"Hn4Wq8Zc1Vx6Ty3Md7Sf"

#: The shortest contiguous run of a sentinel that counts as a leak. Six characters of a
#: 32-byte key's hex is 24 bits; six raw bytes is 48.
_LEAK_WINDOW = 6


def _looks_secret(name: str) -> bool:
    return any(t in _SECRET_TOKENS or t.startswith("priv") for t in name.lower().split("_") if t)


# ── discovery ─────────────────────────────────────────────────────────────────


def _import_everything() -> tuple[list[ModuleType], dict[str, str]]:
    modules: list[ModuleType] = [pyrxd]
    failures: dict[str, str] = {}
    for info in pkgutil.walk_packages(pyrxd.__path__, "pyrxd."):
        try:
            modules.append(importlib.import_module(info.name))
        except Exception as exc:  # a module we cannot import is a module we cannot check
            failures[info.name] = f"{type(exc).__name__}: {exc}"
    return modules, failures


def _dataclasses(modules: list[ModuleType]) -> dict[str, type]:
    """Every dataclass defined in the package, nested classes included, keyed by qualname."""
    found: dict[str, type] = {}
    for mod in modules:
        stack = [c for c in vars(mod).values() if inspect.isclass(c) and c.__module__ == mod.__name__]
        while stack:
            cls = stack.pop()
            if dataclasses.is_dataclass(cls):
                found[f"{cls.__module__}.{cls.__qualname__}"] = cls
            stack.extend(
                v
                for v in vars(cls).values()
                if inspect.isclass(v)
                and v.__module__ == mod.__name__
                and v.__qualname__.startswith(f"{cls.__qualname__}.")
            )
    return found


def _owner_key(cls: type, field_name: str) -> str:
    """The field's identity is the class that DECLARES it, so a subclass does not re-key it."""
    for klass in cls.__mro__:
        if field_name in inspect.get_annotations(klass):
            return f"{klass.__module__}.{klass.__qualname__}.{field_name}"
    raise AssertionError(f"{cls.__qualname__}.{field_name} has no declaring class in its MRO")


def _renderings_with_sentinel(cls: type, field_name: str, sentinel: object) -> str:
    """``repr``, ``str`` and ``format`` of an instance whose ``field_name`` holds ``sentinel``
    and every other field ``None``, joined with NULs so no window can span two of them.

    ``format`` is what an f-string calls; ``str`` is what ``print`` and ``%s`` call. A
    dataclass defines neither, so both normally fall back to ``__repr__`` — but a class that
    defines its own ``__str__`` leaks through them while its ``repr`` stays clean.

    Built with ``object.__new__`` so no constructor validation runs: the question is only what
    the class does with the value, not whether the value is a valid key.
    """
    obj = object.__new__(cls)
    for f in dataclasses.fields(cls):
        object.__setattr__(obj, f.name, sentinel if f.name == field_name else None)
    return "\0".join((repr(obj), str(obj), format(obj, "")))


#: Every six-character run of either sentinel, as text and as hex.
_LEAK_WINDOWS = frozenset(
    form[i : i + _LEAK_WINDOW]
    for form in (_SENTINEL_STR, _SENTINEL_BYTES.decode(), _SENTINEL_STR.encode().hex(), _SENTINEL_BYTES.hex())
    for i in range(len(form) - _LEAK_WINDOW + 1)
)


def _leaks(text: str) -> bool:
    """True if ANY six-character run of a sentinel appears — a prefix or a slice counts."""
    return any(text[i : i + _LEAK_WINDOW] in _LEAK_WINDOWS for i in range(len(text) - _LEAK_WINDOW + 1))


def _audit(classes: dict[str, type]) -> tuple[set[str], set[str], dict[str, str]]:
    """(hidden, exposed, unevaluable) owner-keyed flagged fields across ``classes``.

    Every concrete class that carries a flagged field is checked, with a ``str`` and a
    ``bytes`` sentinel, so a subclass that overrides ``repr`` is judged on its own. A field is
    HIDDEN only if no class and no sentinel exposed it.
    """
    exposed: set[str] = set()
    seen: set[str] = set()
    unevaluable: dict[str, str] = {}
    for cls in classes.values():
        for f in dataclasses.fields(cls):
            if not (_looks_secret(f.name) and _TEXTUAL.search(str(f.type))):
                continue
            key = _owner_key(cls, f.name)
            seen.add(key)
            # Both sentinel types are tried even if one raises: a __str__ calling
            # `self.cek.hex()` fails on the str sentinel and leaks on the bytes one.
            errors: list[str] = []
            for sentinel in (_SENTINEL_STR, _SENTINEL_BYTES):
                try:
                    text = _renderings_with_sentinel(cls, f.name, sentinel)
                except Exception as exc:  # a custom __repr__ / __str__ that needs real values
                    errors.append(f"{type(exc).__name__}: {exc}")
                    continue
                if _leaks(text):
                    exposed.add(key)
            if len(errors) == 2:
                unevaluable[key] = errors[-1]
    return seen - exposed - unevaluable.keys(), exposed, unevaluable


_MODULES, _IMPORT_FAILURES = _import_everything()
_CLASSES = _dataclasses(_MODULES)
_HIDDEN, _EXPOSED, _UNEVALUABLE = _audit(_CLASSES)

# ── the reviewed exemptions ───────────────────────────────────────────────────

_COMMITMENT = "sha256 commitment to the CEK; published on chain by design, it reveals nothing about the key"
_WRAPPED = "the CEK ENCRYPTED to a recipient; published on chain, opaque without the recipient's key"
_POW = "the public block-header preimage a miner hashes, not an HTLC or key secret"
_HOLDS_PRIVATE_KEY = (
    "typed Any but used as a PrivateKey (the builders call .public_key() / P2PKH().unlock() on "
    "it), whose own repr is redacted -- test_a_private_key_in_these_fields_is_not_printed checks "
    "this against a real key. A str WIF here WOULD print; that is a typing gap, not closed here"
)

#: Flagged fields that are allowed to print, each with the reason its value is public.
EXEMPT: dict[str, str] = {
    "pyrxd.glyph.encrypted_content.CryptoMetadata.cek_hash": _COMMITMENT,
    "pyrxd.glyph.encrypted_content.TimelockSpec.cek_hash": _COMMITMENT,
    "pyrxd.glyph.timelock.TimelockMintBuild.cek_hash": _COMMITMENT,
    "pyrxd.glyph.timelock_reveal_tx.RevealProof.cek_hash": _COMMITMENT,
    "pyrxd.crypto.kem.WrappedCEK.wrapped_cek": _WRAPPED,
    "pyrxd.glyph.encrypted_content.CryptoRecipient.wrapped_cek": _WRAPPED,
    "pyrxd.glyph.timelock_reveal_tx.RevealProof.cek": (
        "a reveal proof is the PUBLICATION of the CEK: parsed ones are read off chain, and the "
        "reveal command deliberately shows it before confirming ('PUBLISHES:' in "
        "cli/glyph_timelock_cmds._reveal_lines) -- checked by "
        "test_the_reveal_command_shows_the_cek_it_publishes"
    ),
    "pyrxd.cli.swap_recovery.PreimageRecovery.preimage_hex": (
        "scraped from a counter-chain spend that is already on chain, so public the moment it "
        "exists (its own docstring); the recovery file's preimage_p_hex is never its source"
    ),
    "pyrxd.contrib.miner.parallel.MineParams.preimage": _POW,
    "pyrxd.contrib.miner.protocol.MineRequest.preimage": _POW,
    "pyrxd.glyph.dmint.miner.PowPreimageResult.preimage": _POW,
    "pyrxd.devnet.DevKey.wif": (
        "a key the local regtest node's wallet generated, which `pyrxd regtest up` prints on "
        "purpose -- checked by test_the_regtest_key_is_printed_by_design"
    ),
    "pyrxd.glyph.builder.FtAirdropParams.private_key": _HOLDS_PRIVATE_KEY,
    "pyrxd.glyph.builder.FtTransferParams.private_key": _HOLDS_PRIVATE_KEY,
    "pyrxd.glyph.builder.TransferParams.private_key": _HOLDS_PRIVATE_KEY,
    "pyrxd.glyph.ft.AirdropFunding.private_key": _HOLDS_PRIVATE_KEY,
}

#: Fields known to hold secrets and known to be hidden. The non-vacuity floor: if discovery or
#: the behavioural check broke, these would stop showing up as hidden and the guard would fail
#: instead of passing over nothing.
_KNOWN_HIDDEN = frozenset(
    {
        "pyrxd.crypto.kem.UnwrappedCEK.cek",
        "pyrxd.glyph.timelock.TimelockMintBuild.cek",
        "pyrxd.glyph.timelock.TimelockMintResult.cek_for_caller_to_store",
        "pyrxd.gravity.htlc_spend.FeeInput.wif",
    }
)


# ── the guard ─────────────────────────────────────────────────────────────────


def test_every_module_imports_so_none_is_skipped() -> None:
    assert _IMPORT_FAILURES == {}, f"these modules were not scanned: {_IMPORT_FAILURES}"


def test_no_dataclass_prints_a_secret_looking_field() -> None:
    unexplained = sorted(_EXPOSED - EXEMPT.keys())
    assert not unexplained, (
        "these dataclass fields look like secret material and appear, whole or in part, in "
        "repr() / str() / format(); give them field(repr=False) (and no __str__ that prints them), "
        "or add an EXEMPT entry saying why the value is public:\n  " + "\n  ".join(unexplained)
    )


def test_no_flagged_field_escapes_evaluation() -> None:
    assert _UNEVALUABLE == {}, (
        f"a custom __repr__ could not be evaluated with sentinel values, so these were not checked: {_UNEVALUABLE}"
    )


def test_every_exemption_still_describes_an_exposed_field() -> None:
    """The other direction. An entry whose field was hidden, renamed or deleted is a reason
    nobody is reading any more; it fails here until it is removed."""
    stale = sorted(EXEMPT.keys() - _EXPOSED)
    assert not stale, f"EXEMPT entries that no longer match an exposed field: {stale}"


def test_the_guard_is_not_passing_over_nothing() -> None:
    assert len(_CLASSES) > 100, f"only {len(_CLASSES)} dataclasses discovered; discovery is broken"
    missing = sorted(_KNOWN_HIDDEN - _HIDDEN)
    assert not missing, f"known secret fields not seen as hidden (discovery or the check broke): {missing}"


#: ``make_dataclass`` / non-decorator ``dataclass(...)`` call sites that have been audited by
#: hand, as ``"<module>:<first positional arg, or <dynamic>>"``. Empty today; a new site fails
#: the guard until someone either makes the class reachable by name or reviews it here.
REVIEWED_DYNAMIC_DATACLASS_SITES: frozenset[str] = frozenset()


def _dataclass_sites(source: str, module: str) -> tuple[set[str], set[str]]:
    """(qualnames of ``@dataclass``-decorated classes, dynamic creation sites) in ``source``.

    Resolves the module's OWN spelling of the decorator: ``from dataclasses import dataclass
    as _dc`` makes ``@_dc`` a dataclass decorator here, and ``import dataclasses as d`` makes
    ``@d.dataclass`` one. Matching the literal name ``dataclass`` alone let an alias escape.

    A dataclass built by ``make_dataclass(...)``, or by calling ``dataclass(...)`` on a class
    outside a decorator, has no class statement to name it, so it is returned as a SITE —
    ``"<module>:<name>"`` from the first positional argument when it is a string literal.
    """
    tree = ast.parse(source)
    dc_names = {"dataclass"}
    make_names = {"make_dataclass"}
    dc_modules = {"dataclasses"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "dataclasses":
            for alias in node.names:
                if alias.name == "dataclass":
                    dc_names.add(alias.asname or alias.name)
                elif alias.name == "make_dataclass":
                    make_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "dataclasses":
                    dc_modules.add(alias.asname or alias.name)

    def resolves_to(node: ast.expr, names: set[str], attr: str) -> bool:
        if isinstance(node, ast.Name):
            return node.id in names
        return isinstance(node, ast.Attribute) and node.attr == attr

    def is_decorator(node: ast.expr) -> bool:
        return resolves_to(node.func if isinstance(node, ast.Call) else node, dc_names, "dataclass")

    decorator_ids: set[int] = set()
    classes: set[str] = set()

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                if any(is_decorator(d) for d in child.decorator_list):
                    classes.add(f"{module}.{prefix}{child.name}")
                for d in child.decorator_list:
                    decorator_ids.update(id(n) for n in ast.walk(d))
                walk(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in child.decorator_list:
                    decorator_ids.update(id(n) for n in ast.walk(d))
                walk(child, f"{prefix}{child.name}.<locals>.")
            else:
                walk(child, prefix)

    walk(tree, "")

    sites: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in decorator_ids:
            continue
        if resolves_to(node.func, make_names, "make_dataclass") or resolves_to(node.func, dc_names, "dataclass"):
            first = node.args[0] if node.args else None
            label = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else "<dynamic>"
            sites.add(f"{module}:{label}")
    return classes, sites


def _scan_package_source() -> tuple[set[str], set[str]]:
    root = pathlib.Path(pyrxd.__file__).parent
    classes: set[str] = set()
    sites: set[str] = set()
    for path in root.rglob("*.py"):
        module = ".".join(("pyrxd", *path.relative_to(root).with_suffix("").parts)).removesuffix(".__init__")
        c, s = _dataclass_sites(path.read_text(encoding="utf-8"), module)
        classes |= c
        sites |= s
    return classes, sites


def test_every_dataclass_in_the_source_is_seen() -> None:
    """Runtime discovery walks module attributes; a dataclass defined inside a function, or
    otherwise not reachable that way, would be skipped silently. The AST sees them all."""
    in_source, _sites = _scan_package_source()
    assert len(in_source) > 100, "the AST scan found almost nothing; it is broken, not the package"
    unseen = sorted(in_source - _CLASSES.keys())
    assert not unseen, f"@dataclass classes the runtime scan did not reach, so never checked: {unseen}"


def test_no_dataclass_is_built_where_the_scan_cannot_name_it() -> None:
    """``make_dataclass`` and ``dataclass(cls)`` produce classes no class statement names, so
    neither the runtime walk nor the qualname check above can be trusted to have seen them."""
    _classes, sites = _scan_package_source()
    unreviewed = sorted(sites - REVIEWED_DYNAMIC_DATACLASS_SITES)
    assert not unreviewed, f"dataclasses created dynamically, so never checked by this guard: {unreviewed}"
    stale = sorted(REVIEWED_DYNAMIC_DATACLASS_SITES - sites)
    assert not stale, f"REVIEWED_DYNAMIC_DATACLASS_SITES entries with no site any more: {stale}"


# ── the checker itself, on cases whose answer is known ───────────────────────


def test_the_checker_catches_a_leak_and_passes_a_hidden_field() -> None:
    """A guard that has never been seen to fail proves nothing. These are defined here, so the
    answer is known in advance."""

    @dataclasses.dataclass(frozen=True)
    class Leaky:
        cek: bytes
        label: str

    @dataclasses.dataclass(frozen=True)
    class Hidden:
        cek: bytes = dataclasses.field(repr=False)
        label: str = ""

    @dataclasses.dataclass(frozen=True)
    class CustomButLeaky:
        wif: str

        def __repr__(self) -> str:
            return f"CustomButLeaky(wif={self.wif})"

    @dataclasses.dataclass(frozen=True)
    class PartialLeak:
        cek: bytes

        def __repr__(self) -> str:  # "only a prefix" is still a leak
            return f"PartialLeak(cek={self.cek[:16]!r}...)"

    @dataclasses.dataclass(frozen=True)
    class StrLeak:
        cek: bytes = dataclasses.field(repr=False)

        def __str__(self) -> str:  # repr is clean; print() and f-strings are not
            return f"StrLeak({self.cek.hex()})"

    @dataclasses.dataclass(frozen=True)
    class RedactsHonestly:
        cek: bytes

        def __repr__(self) -> str:
            return "RedactsHonestly(cek=<SECRET 32 bytes redacted>)"

    hidden, exposed, unevaluable = _audit(
        {
            "t.Leaky": Leaky,
            "t.Hidden": Hidden,
            "t.CustomButLeaky": CustomButLeaky,
            "t.PartialLeak": PartialLeak,
            "t.StrLeak": StrLeak,
            "t.RedactsHonestly": RedactsHonestly,
        }
    )
    assert {k.rsplit(".", 2)[-2] for k in exposed} == {"Leaky", "CustomButLeaky", "PartialLeak", "StrLeak"}
    assert {k.rsplit(".", 2)[-2] for k in hidden} == {"Hidden", "RedactsHonestly"}
    assert unevaluable == {}


def test_the_source_scan_resolves_aliases_and_dynamic_creation() -> None:
    source = (
        "import dataclasses as dcs\n"
        "from dataclasses import dataclass as _dc, make_dataclass as mk\n"
        "@_dc\n"
        "class Aliased:\n"
        "    cek: bytes\n"
        "def f():\n"
        "    @dcs.dataclass(frozen=True)\n"
        "    class Local:\n"
        "        wif: str\n"
        "    Made = mk('Made', [('seed', bytes)])\n"
        "    Called = _dc(type('Called', (), {}))\n"
        "    return Local, Made, Called\n"
        "class NotOne:\n"
        "    pass\n"
    )
    classes, sites = _dataclass_sites(source, "m")
    assert classes == {"m.Aliased", "m.f.<locals>.Local"}
    assert sites == {"m:Made", "m:<dynamic>"}


def test_the_name_pattern_catches_the_spellings_pyrxd_uses() -> None:
    for name in (
        "cek",
        "wif",
        "_seed",
        "private_key",
        "privkey",
        "_privkey",
        "mnemonic",
        "preimage_hex",
        "cek_for_caller_to_store",
        "recipient_sk",
        "passphrase",
        "xprv",
        "shared_secret",
    ):
        assert _looks_secret(name), name
    for name in ("pubkey", "public_key", "ephemeral_pubkey", "token_ref", "skip", "seeded_count", "key_format"):
        assert not _looks_secret(name), name


# ── the checkable halves of the exemption reasons ────────────────────────────


def test_the_key_types_redact_their_own_repr() -> None:
    from pyrxd.keys import PrivateKey
    from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes

    key = PrivateKey()
    for text in (repr(key), str(key)):
        assert key.wif() not in text and key.hex() not in text
    material = PrivateKeyMaterial(bytes(range(1, 33)))
    assert bytes(range(1, 33)).hex() not in repr(material)
    assert bytes(range(1, 33)).hex() not in repr(SecretBytes(bytes(range(1, 33))))


@pytest.mark.parametrize("key", sorted(k for k, why in EXEMPT.items() if why == _HOLDS_PRIVATE_KEY))
def test_a_private_key_in_these_fields_is_not_printed(key: str) -> None:
    from pyrxd.keys import PrivateKey

    cls = _CLASSES[key.rsplit(".", 1)[0]]
    field_name = key.rsplit(".", 1)[1]
    real = PrivateKey()
    obj = object.__new__(cls)
    for f in dataclasses.fields(cls):
        object.__setattr__(obj, f.name, real if f.name == field_name else None)
    assert real.wif() not in repr(obj) and real.hex() not in repr(obj)


def test_the_reveal_command_shows_the_cek_it_publishes() -> None:
    from pyrxd.cli import glyph_timelock_cmds

    assert "PUBLISHES:   {plan.proof.cek}" in inspect.getsource(glyph_timelock_cmds._reveal_lines)


def test_the_regtest_key_is_printed_by_design() -> None:
    from pyrxd.cli import regtest_cmds

    assert "{key.wif}" in inspect.getsource(regtest_cmds)
