"""The pure-Python SHA-512/256 behind :func:`pyrxd.hash.radiant_block_hash` (#757).

Radiant's block hash is a double SHA-512/256. CPython's ``hashlib`` has it through OpenSSL;
Pyodide 0.26.4's does not unless Pyodide's OpenSSL package is loaded, and the ``/inspect/`` and
``/verify/`` pages stopped loading that package (it made a CDN-served, end-of-life OpenSSL compute
every hash on the page, the signature check's included). So on the pages, the fallback here is the
block hash — the one that binds a mark's height to its header.

What pins it, and against what:

* **The FIPS 180-4 examples** — the empty string, ``"abc"``, and the two-block message — as literal
  digests, AND against ``hashlib`` on this CPython.
* **Every length across the padding boundaries.** A message of 111 bytes pads into one block; 112
  needs a second (the 1 bit plus the 128-bit length no longer fit). Every length from 0 to 384 is
  compared with ``hashlib``, which crosses that boundary three times.
* **Random inputs** of many lengths, from a seed printed in any failure.
* **Real Radiant mainnet headers**, the fixtures PR #756 measured: each one's block hash is known
  from the CHAIN, not from ``hashlib`` — the genesis hash from the registry, 460,572's from the
  node's verbose reply, and each other one's from the next header's previous-block field.
* **That the fallback is what runs** when ``hashlib.new("sha512_256")`` refuses, as it does on
  Pyodide: the refusal is monkeypatched (and counted, so the test cannot pass without it firing);
  the fallback is not touched.
* **That the refusal path still tells the truth** when the fallback fails too.
"""

from __future__ import annotations

import hashlib
import os
import random

import pytest

import pyrxd.hash as pyrxd_hash
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.hash import _sha512_256_pure_python, radiant_block_hash
from tests.network.test_registry import _MAINNET_GENESIS_HEADER_HEX
from tests.web.test_mark_anchor_bridge import _KNOWN_HEIGHT, _MEASURED_BLOCKHASH, _MEASURED_HEADERS

pytestmark = pytest.mark.unit


def _hashlib_sha512_256(data: bytes) -> bytes:
    return hashlib.new("sha512_256", data).digest()


#: FIPS 180-4 examples for SHA-512/256 (NIST's published example values). The third is 112 bytes,
#: exactly the length at which padding first needs a second block.
_FIPS_EXAMPLES = [
    (b"", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
    (b"abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
        b"mnopqrstnopqrstu",
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    ),
]


def _real_headers() -> dict[str, tuple[bytes, str]]:
    """Every real mainnet header in the suite, with the block hash the CHAIN gives it.

    The hash of block N is written into block N+1's header (bytes 4..36, internal byte order), so
    460,570–460,573 are each named by their successor; 460,572 is also the node's own ``blockhash``
    for the mark's transaction, and genesis is the registry constant. 460,574 has no successor in
    the fixtures, so it is checked against ``hashlib`` only.
    """
    headers = {height: bytes.fromhex(h) for height, h in _MEASURED_HEADERS.items()}
    named: dict[str, tuple[bytes, str]] = {
        "mainnet genesis": (bytes.fromhex(_MAINNET_GENESIS_HEADER_HEX), GENESIS_BLOCK_HASHES["mainnet"]),
    }
    for height, header in headers.items():
        successor = headers.get(height + 1)
        if successor is not None:
            named[f"mainnet {height}"] = (header, successor[4:36][::-1].hex())
    assert named[f"mainnet {_KNOWN_HEIGHT}"][1] == _MEASURED_BLOCKHASH, (
        "the fixtures disagree with each other: the node's block hash for 460,572 is not the "
        "previous-block field of 460,573"
    )
    return named


_REAL_HEADERS = _real_headers()


@pytest.fixture
def hashlib_without_sha512_256(monkeypatch) -> list[str]:
    """``hashlib.new("sha512_256")`` raising exactly what Pyodide 0.26.4's raises without its
    OpenSSL package (measured in headless Chromium for #756). Everything else is untouched, and
    the fallback is not patched. Returns the list of refused calls, so a test can prove the
    refusal actually fired rather than passing because nothing asked."""
    real_new = hashlib.new
    refused: list[str] = []

    def new(name, *args, **kwargs):
        if str(name).lower().replace("-", "").replace("/", "_") == "sha512_256":
            refused.append(name)
            raise ValueError(f"unsupported hash type {name}")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr(hashlib, "new", new)
    return refused


class TestTheFipsExamples:
    @pytest.mark.parametrize(("message", "digest"), _FIPS_EXAMPLES, ids=["empty", "abc", "two-block"])
    def test_the_pure_function_gives_the_published_digest(self, message: bytes, digest: str) -> None:
        assert _sha512_256_pure_python(message).hex() == digest

    @pytest.mark.parametrize(("message", "digest"), _FIPS_EXAMPLES, ids=["empty", "abc", "two-block"])
    def test_and_so_does_hashlib_on_this_cpython(self, message: bytes, digest: str) -> None:
        """The control: the literals above are the digests ``hashlib`` computes, so the two tests
        together tie the pure function to both the standard and the C implementation."""
        assert _hashlib_sha512_256(message).hex() == digest


class TestItAgreesWithHashlib:
    #: The lengths either side of each place the padding changes shape: 111/112 (one block vs
    #: two), 127/128/129 (a whole block of message), and the same one block later.
    BOUNDARIES = (0, 1, 55, 56, 63, 64, 110, 111, 112, 113, 127, 128, 129, 238, 239, 240, 241, 255, 256, 257)

    @pytest.mark.parametrize("length", BOUNDARIES)
    def test_at_the_padding_boundaries(self, length: int) -> None:
        message = bytes((i * 7 + 3) & 0xFF for i in range(length))
        assert _sha512_256_pure_python(message) == _hashlib_sha512_256(message)

    def test_at_every_length_up_to_three_blocks(self) -> None:
        mismatched = [
            n for n in range(3 * 128 + 1) if _sha512_256_pure_python(b"\xa5" * n) != _hashlib_sha512_256(b"\xa5" * n)
        ]
        assert not mismatched, f"lengths where the pure function disagrees with hashlib: {mismatched}"

    def test_on_random_inputs_of_many_lengths(self) -> None:
        seed = int.from_bytes(os.urandom(8), "big")
        rng = random.Random(seed)
        for i in range(400):
            length = rng.randrange(0, 2049) if i % 20 else rng.randrange(2049, 9000)
            message = rng.randbytes(length)
            assert _sha512_256_pure_python(message) == _hashlib_sha512_256(message), (
                f"seed {seed}, input #{i} ({length} bytes) disagrees with hashlib"
            )

    def test_bytearray_and_memoryview_hash_as_their_bytes(self) -> None:
        message = b"radiant header bytes" * 5
        expected = _hashlib_sha512_256(message)
        assert _sha512_256_pure_python(bytearray(message)) == expected
        assert _sha512_256_pure_python(memoryview(message)) == expected


class TestRealRadiantHeaders:
    @pytest.mark.parametrize("name", sorted(_REAL_HEADERS))
    def test_the_pure_double_hash_is_the_chains_block_hash(self, name: str) -> None:
        header, block_hash = _REAL_HEADERS[name]
        once = _sha512_256_pure_python(header)
        assert _sha512_256_pure_python(once)[::-1].hex() == block_hash

    @pytest.mark.parametrize("height", sorted(_MEASURED_HEADERS))
    def test_both_rounds_agree_with_hashlib_on_every_measured_header(self, height: int) -> None:
        """Including 460,574, which no fixture names. Both rounds: the 80-byte header and the
        32-byte digest it hashes to, the two input lengths the block hash ever sees."""
        header = bytes.fromhex(_MEASURED_HEADERS[height])
        once = _sha512_256_pure_python(header)
        assert once == _hashlib_sha512_256(header)
        assert _sha512_256_pure_python(once) == _hashlib_sha512_256(once)

    def test_the_fixture_set_is_not_empty(self) -> None:
        """Non-vacuity: the parametrised tests above iterate these."""
        assert len(_REAL_HEADERS) == 5 and len(_MEASURED_HEADERS) == 5


class TestTheFallbackIsWhatRunsWithoutHashlibs:
    @pytest.mark.parametrize("name", sorted(_REAL_HEADERS))
    def test_the_block_hash_is_still_right(self, hashlib_without_sha512_256: list[str], name: str) -> None:
        """The refusal fires twice per block hash — once per round — and the answer is still the
        chain's. With ``hashlib`` refusing, only the fallback can have produced it."""
        header, block_hash = _REAL_HEADERS[name]
        assert radiant_block_hash(header) == block_hash
        assert hashlib_without_sha512_256 == ["sha512_256", "sha512_256"]

    def test_the_registry_entry_point_reaches_it_too(self, hashlib_without_sha512_256: list[str]) -> None:
        """``pyrxd.network.registry.block_hash_hex`` — the CLI's chain check — delegates here."""
        from pyrxd.network.registry import block_hash_hex

        header, block_hash = _REAL_HEADERS["mainnet genesis"]
        assert block_hash_hex(header) == block_hash
        assert len(hashlib_without_sha512_256) == 2

    def test_the_mark_anchor_binding_reaches_it_too(self, hashlib_without_sha512_256: list[str]) -> None:
        """``resolve_mark_anchor(fetch_header=...)`` — the call both the CLI and the pages make —
        binds 460,572 from the real headers with ``hashlib`` refusing, as on the pages. The tip is
        one low, so the rule hashes 460,571 first (no match) and then 460,572 (the match): the
        fallback has to tell a real non-match from a real match, not merely produce a digest."""
        import asyncio
        import json

        from pyrxd.glyph.mark_anchor import resolve_mark_anchor
        from tests.web.test_mark_anchor_bridge import _MEASURED_TIP, _TXID, _verbose

        verbose = json.loads(_verbose())
        asked: list[int] = []

        async def fetch_verbose(_txid: str) -> dict:
            return verbose

        async def fetch_header(height: int) -> bytes:
            asked.append(height)
            return bytes.fromhex(_MEASURED_HEADERS[height])

        anchor = asyncio.run(
            resolve_mark_anchor(
                txid=_TXID,
                fetch_verbose=fetch_verbose,
                source="s",
                min_confirmations=1,
                tip_height=_MEASURED_TIP - 1,
                fetch_header=fetch_header,
            )
        )
        assert anchor.height == _KNOWN_HEIGHT and anchor.header_bound is True
        assert asked == [_KNOWN_HEIGHT - 1, _KNOWN_HEIGHT]
        assert len(hashlib_without_sha512_256) == 4, "two block hashes, two rounds each, all refused by hashlib"

    def test_when_hashlib_has_it_hashlib_is_used(self, monkeypatch) -> None:
        """The other branch: on CPython the C path is taken and the fallback is not called at all."""

        def must_not_run(payload: bytes) -> bytes:
            raise AssertionError("the pure-Python fallback ran although hashlib has sha512_256")

        monkeypatch.setattr(pyrxd_hash, "_sha512_256_pure_python", must_not_run)
        header, block_hash = _REAL_HEADERS["mainnet genesis"]
        assert radiant_block_hash(header) == block_hash


class TestTheRefusalStillTellsTheTruth:
    def test_a_failing_fallback_is_a_valueerror_naming_both_causes(
        self, hashlib_without_sha512_256: list[str], monkeypatch
    ) -> None:
        """Practically unreachable now, and it must still say what happened: callers — the pages'
        ``glue.py`` above all — catch ``ValueError`` and report that the block hash cannot be
        computed here, rather than blaming the server for a hash this runtime could not do."""

        def broken(payload: bytes) -> bytes:
            raise RuntimeError("simulated fallback failure")

        monkeypatch.setattr(pyrxd_hash, "_sha512_256_pure_python", broken)
        with pytest.raises(ValueError) as caught:
            radiant_block_hash(bytes(80))
        message = str(caught.value)
        assert message.startswith("no SHA-512/256 here: hashlib refused it and the pure-Python fallback failed")
        assert "unsupported hash type sha512_256" in message
        assert "simulated fallback failure" in message
        assert hashlib_without_sha512_256 == ["sha512_256"]

    def test_a_wrong_length_header_is_still_refused_before_any_hash(self) -> None:
        with pytest.raises(ValueError, match="exactly 80 bytes"):
            radiant_block_hash(bytes(79))
