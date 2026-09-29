"""``script_hash_for_output`` names the hash RXinDexer indexes an output under — graded by RXinDexer.

A Radiant ElectrumX does not list an output under ``sha256(script)``. When the script has a
signature check it hashes ``Script.zero_refs(script)``: every ref operand replaced by 36 zero
bytes, and — a quirk, not a design — every ``OP_PUSHDATA1``/``2``/``4`` push with its length
bytes dropped. pyrxd's :func:`~pyrxd.network.electrumx.script_hash_for_output` is a
transcription of that. The first transcription zeroed refs and kept the length bytes, and a
hostile review of #784 found 141 of 27,613 generated scripts hashing somewhere the server lists
nothing; an honest listing of such an output made ``scan_script_hash(strict=True)`` raise
``ServerInconsistencyError``.

So the grader here is not a second transcription. It is the indexer's own ``zero_refs``, imported
from the verbatim copy under ``tests/vendor/rxindexer`` that ``tests/rxindexer_oracle.py`` holds
to the pinned commit's digests, run over a generated corpus of every push form, ref opcode,
signature check and owned token shape, plus unstructured byte soup.
"""

from __future__ import annotations

import asyncio
import hashlib
import random

import pytest

from pyrxd.glyph.scanner import OWNED_TOKEN_SHAPES, GlyphScanner, owned_token_script_hashes
from pyrxd.glyph.script import TruncatedScriptError, iter_script_ops_strict
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_output, script_hash_for_script
from pyrxd.script.script import Script
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from tests import rxindexer_oracle as oracle

_REF_OPS = (0xD0, 0xD1, 0xD2, 0xD3, 0xD8)
_REFHASH_OPS = (0xD4, 0xD5, 0xD6, 0xD7)  # same byte range, no operand
_SIG_OPS = (0xAC, 0xAD, 0xAE, 0xAF)
#: Operand-less opcodes, so a structured script stays decodable (refs are placed explicitly).
_PLAIN_OPS = tuple(op for op in range(0x4F, 0x100) if op not in _REF_OPS)


def _server_hash(upstream_script, script: bytes) -> bytes | None:
    """The hash RXinDexer indexes *script* under, or ``None`` when it does not index it at all."""
    try:
        rewritten = upstream_script.Script.zero_refs(script)
    except upstream_script.ScriptError:
        return None
    return hashlib.sha256(rewritten).digest()[::-1]


def _instruction(rng: random.Random) -> bytes:
    kind = rng.choice(
        ("direct", "pd1", "pd1", "pd2", "pd4", "ref", "refhash", "sig", "p2pkh", "plain", "shape", "drop")
    )
    if kind == "direct":
        n = rng.randint(0, 0x4B)
        return bytes([n]) + rng.randbytes(n)
    if kind == "pd1":
        n = rng.choice((0, 1, 20, 36, 75, 76, 80, 255, rng.randint(0, 255)))
        return b"\x4c" + bytes([n]) + rng.randbytes(n)
    if kind == "pd2":
        n = rng.choice((0, 1, 255, 256, 520, rng.randint(0, 700)))
        return b"\x4d" + n.to_bytes(2, "little") + rng.randbytes(n)
    if kind == "pd4":
        n = rng.choice((0, 1, 80, rng.randint(0, 300)))
        return b"\x4e" + n.to_bytes(4, "little") + rng.randbytes(n)
    if kind == "ref":
        return bytes([rng.choice(_REF_OPS)]) + rng.randbytes(36)
    if kind == "refhash":
        return bytes([rng.choice(_REFHASH_OPS)])
    if kind == "sig":
        return bytes([rng.choice(_SIG_OPS)])
    if kind == "p2pkh":
        return b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac"
    if kind == "plain":
        return bytes([rng.choice(_PLAIN_OPS)])
    if kind == "shape":
        return rng.choice(list(OWNED_TOKEN_SHAPES.values()))(Hex20(rng.randbytes(20)))
    return b"\x75"  # OP_DROP


def _corpus() -> list[bytes]:
    rng = random.Random(784)
    scripts: list[bytes] = []
    for _ in range(30_000):
        s = b"".join(_instruction(rng) for _ in range(rng.randint(0, 8)))
        if s and rng.random() < 0.1:
            s = s[: rng.randrange(len(s))]  # truncated: the indexer refuses these
        scripts.append(s)
    soup_alphabet = (*_REF_OPS, *_REFHASH_OPS, *_SIG_OPS, 0x4C, 0x4D, 0x4E, 0x00, 0x01, 0x14, 0x75, 0x76, 0xA9, 0x88)
    for _ in range(30_000):
        s = bytearray()
        for _ in range(rng.randint(0, 60)):
            r = rng.random()
            if r < 0.5:
                s.append(rng.choice(soup_alphabet))
            elif r < 0.7:
                s += rng.randbytes(rng.choice((36, rng.randint(1, 5))))
            else:
                s.append(rng.randrange(256))
        scripts.append(bytes(s))
    return scripts


def test_every_generated_script_hashes_where_the_pinned_indexer_lists_it() -> None:
    upstream_script = oracle.upstream_script()
    counts = {"compared": 0, "unindexed": 0, "as_is": 0, "refs_only": 0, "length_bytes_dropped": 0}
    disagreements: list[str] = []
    for script in _corpus():
        server = _server_hash(upstream_script, script)
        ours = bytes(script_hash_for_output(script))
        if server is None:
            counts["unindexed"] += 1
            # The indexer does not index an output it cannot walk. pyrxd's walk refuses the same
            # scripts, and then (as documented) falls back to the plain hash.
            with pytest.raises(TruncatedScriptError):
                list(iter_script_ops_strict(script))
            assert ours == bytes(script_hash_for_script(script))
            continue
        counts["compared"] += 1
        rewritten = upstream_script.Script.zero_refs(script)
        if rewritten == script:
            counts["as_is"] += 1
        elif len(rewritten) == len(script):
            counts["refs_only"] += 1
        else:
            counts["length_bytes_dropped"] += 1
        if ours != server:
            disagreements.append(script.hex())

    assert disagreements == [], f"{len(disagreements)} of {counts['compared']} disagree, e.g. {disagreements[:3]}"
    # Non-vacuity: each rewrite the indexer applies was exercised, classified by the INDEXER's
    # output, not pyrxd's. A generator that stopped producing one would pass the loop above.
    assert counts["compared"] >= 20_000, counts
    assert counts["unindexed"] >= 1_000, counts
    assert counts["as_is"] >= 1_000, counts
    assert counts["refs_only"] >= 500, counts
    assert counts["length_bytes_dropped"] >= 1_000, counts


# An 80-byte OP_PUSHDATA1 push, OP_DROP, then P2PKH: the review's proof case. The server hashes
# ``4c`` + the data (no ``50`` length byte) + the rest; the literal is the vendored indexer's answer.
_PUSHDATA_THEN_P2PKH = bytes([0x4C, 80]) + b"\x11" * 80 + b"\x75\x76\xa9\x14" + bytes(range(20)) + b"\x88\xac"
_PUSHDATA_THEN_P2PKH_SERVER_HASH = "8836130ec0e336c02b13b4aa5d14f2a0d7c5ba2f47d14df8484c7d2ea00e828c"


def test_a_pushdata1_push_beside_a_signature_check_hashes_without_its_length_byte() -> None:
    assert _server_hash(oracle.upstream_script(), _PUSHDATA_THEN_P2PKH).hex() == _PUSHDATA_THEN_P2PKH_SERVER_HASH
    assert bytes(script_hash_for_output(_PUSHDATA_THEN_P2PKH)).hex() == _PUSHDATA_THEN_P2PKH_SERVER_HASH
    assert bytes(script_hash_for_script(_PUSHDATA_THEN_P2PKH)).hex() != _PUSHDATA_THEN_P2PKH_SERVER_HASH


def test_an_honest_listing_of_that_output_is_not_a_server_inconsistency() -> None:
    """Through ``scan_script_hash(strict=True)``: the server lists the output at its own hash."""
    tx = Transaction()
    tx.add_input(TransactionInput(source_txid="ab" * 32, source_output_index=0, unlocking_script=Script(b"")))
    tx.add_output(TransactionOutput(Script(_PUSHDATA_THEN_P2PKH), 1000))

    class _Server:
        async def get_utxos(self, script_hash):
            assert bytes(script_hash).hex() == _PUSHDATA_THEN_P2PKH_SERVER_HASH
            return [UtxoRecord(tx_hash=tx.txid(), tx_pos=0, value=1000, height=1)]

        async def get_transaction(self, txid):
            return tx.serialize()

    # Not a token, so nothing is listed; before the fix this raised ServerInconsistencyError.
    assert asyncio.run(GlyphScanner(_Server()).scan_script_hash(_PUSHDATA_THEN_P2PKH_SERVER_HASH, strict=True)) == []


def test_the_owned_token_shapes_hash_where_the_pinned_indexer_lists_them() -> None:
    upstream_script = oracle.upstream_script()
    rng = random.Random(782)
    for _ in range(50):
        owner = Hex20(rng.randbytes(20))
        builders = list(OWNED_TOKEN_SHAPES.values())
        expected = tuple(_server_hash(upstream_script, build(owner)) for build in builders)
        assert tuple(bytes(h) for h in owned_token_script_hashes(owner)) == expected
        # The rewrite really applies to each shape: none is listed under its plain hash.
        assert all(e != bytes(script_hash_for_script(build(owner))) for e, build in zip(expected, builders))
