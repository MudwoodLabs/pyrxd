"""Run RXinDexer's OWN claim path on pyrxd-built transactions — the indexer as a test oracle.

``src/pyrxd/glyph/wave_rules.py`` decides whether a payload registers a WAVE name
(:func:`~pyrxd.glyph.wave_rules.wave_registered_label`) and so owes the registration fee, and
what it costs (:func:`~pyrxd.glyph.wave_rules.wave_registration_price`). Both are pyrxd's
transcriptions of RXinDexer. The tests that grade them used to grade pyrxd with pyrxd — the CLI
suite asked ``wave_registered_label`` whether the reveal registered the name it paid for — or
with a second transcription written into the test file. A transcription that agrees with the
code it was copied beside proves nothing about the indexer (panel D, 0.25.0 review).

This module imports the indexer's code instead: verbatim copies of Radiant-Core/RXinDexer at the
commit ``tests/fixtures/rxindexer_upstream_pin.json`` pins, under ``tests/vendor/rxindexer/``
(MIT; see the README and ``LICENCE`` there). ``test_the_vendored_indexer_is_the_pinned_one``
holds every vendored byte to the manifest, and the two pinned files to the pin's own digests.

What is NOT upstream code here, and why each is safe to supply:

- the ``tx``/``input``/``output`` shims: plain attribute holders with the fields
  ``process_tx`` reads (``inputs[i].script``/``prev_hash``/``prev_idx``,
  ``outputs[i].pk_script``/``value``);
- ``_Db``/``_Env``: an empty database and the handful of settings ``WaveIndex.__init__``
  reads. ``_Env.coin`` answers ``address_to_hashX`` (used only to vet a zone's TARGET address,
  never whether the name registers) and ``hashX_from_script`` (the owner's index key);
- :func:`phase2_envelope`: which input's envelope the block processor hands ``process_tx``.
  That selection lives inside ``GlyphIndex``'s block method in
  ``electrumx/server/glyph_index.py`` (lines 847-880 at the pinned commit), which needs the
  whole index to run, so it is TRANSCRIBED here: the first input whose script carries the
  ``gly`` magic, parses as a reveal envelope, and decodes to a map, with ``get_token_type``
  called on its ``p`` first. ``glyph_index.py`` is digest-pinned but not vendored; when the pin
  moves, re-read those lines against this function;
- the block processor's guards, also transcribed: an exception from ``glyph_index.process_tx``
  (a ``TypeError`` from ``get_token_type``, say) or from ``wave_index.process_tx`` (a non-map
  ``attrs``) is logged and the transaction's overlay skipped, with no rollback of what the index
  had already cached (``electrumx/server/block_processor.py`` lines 859-869 and 877-892 at the
  pinned commit — not vendored and not pinned; re-read them when the pin moves).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import struct
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

VENDOR_DIR = Path(__file__).parent / "vendor" / "rxindexer"
MANIFEST_PATH = VENDOR_DIR / "MANIFEST.json"
PIN_PATH = Path(__file__).parent / "fixtures" / "rxindexer_upstream_pin.json"

#: The block time handed to ``process_tx``: after the indexer's expiry floor, so lifecycle
#: code runs as it does on a live chain rather than on its "block_time unknown" path.
BLOCK_TIME = 1_800_000_000


def manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def pin() -> dict[str, Any]:
    return json.loads(PIN_PATH.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def upstream() -> tuple[ModuleType, ModuleType]:
    """``(electrumx.lib.glyph, electrumx.server.wave_index)`` from the vendored copies.

    Refuses to import anything whose bytes are not the manifest's: a vendored file edited to
    make a test pass would otherwise become the oracle.
    """
    for rel, digest in manifest()["files"].items():
        got = sha256_file(VENDOR_DIR / rel)
        if got != digest:
            raise AssertionError(f"tests/vendor/rxindexer/{rel} is not the vendored file: sha256 {got} != {digest}")
    vendor = str(VENDOR_DIR)
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    glyph = importlib.import_module("electrumx.lib.glyph")
    wave_index = importlib.import_module("electrumx.server.wave_index")
    # The package must be the vendored one, not some other ``electrumx`` on the path.
    assert Path(wave_index.__file__).resolve().is_relative_to(VENDOR_DIR.resolve()), wave_index.__file__
    return glyph, wave_index


# ─────────────────────────────────────────────── what process_tx reads ──


@dataclass
class UpIn:
    script: bytes
    prev_hash: bytes
    prev_idx: int


@dataclass
class UpOut:
    pk_script: bytes
    value: int


@dataclass
class UpTx:
    inputs: list[UpIn]
    outputs: list[UpOut]


class _Db:
    """An empty index database: every lookup misses."""

    db_height = 0

    def __init__(self) -> None:
        self.utxo_db = self

    def get(self, key: bytes, default: Any = None) -> Any:
        return default


class _Coin:
    @staticmethod
    def hashX_from_script(script: bytes) -> bytes:
        return hashlib.sha256(script).digest()[:11]

    @staticmethod
    def address_to_hashX(address: str) -> bytes:
        from pyrxd.utils import decode_address

        pkh, network = decode_address(address)
        if network is None or len(pkh) != 20:
            raise ValueError(f"not a P2PKH address: {address!r}")
        return hashlib.sha256(pkh).digest()[:11]


class _Env:
    wave_index = True
    #: Any well-formed ref: top-level names hang off the genesis ref, and without one the claim
    #: path returns before registering (``if not parent_ref``).
    wave_genesis_ref = "11" * 32 + "_0"
    reorg_limit = 0
    coin = _Coin


def new_index() -> Any:
    _glyph, wave_index = upstream()
    return wave_index.WaveIndex(_Db(), _Env())


def to_upstream_tx(tx: Any) -> UpTx:
    """A :class:`pyrxd.transaction.transaction.Transaction` as the fields ``process_tx`` reads."""
    ins = [
        UpIn(
            script=i.unlocking_script.serialize() if i.unlocking_script is not None else b"",
            prev_hash=bytes.fromhex(i.source_txid)[::-1],
            prev_idx=i.source_output_index,
        )
        for i in tx.inputs
    ]
    outs = [UpOut(pk_script=o.locking_script.serialize(), value=o.satoshis) for o in tx.outputs]
    return UpTx(ins, outs)


def phase2_envelope(tx: UpTx) -> dict[str, Any] | None:
    """The envelope the block processor passes to ``process_tx`` (TRANSCRIBED; see the module docstring)."""
    glyph, _wave_index = upstream()
    for txin in tx.inputs:
        script = txin.script
        if not script or not glyph.contains_glyph_magic(script):
            continue
        envelope = glyph.parse_glyph_envelope(script)
        if not envelope or not envelope.get("is_reveal"):
            continue
        metadata = glyph.parse_glyph_metadata(envelope)
        if not metadata or not isinstance(metadata, dict):
            continue
        glyph.get_token_type(metadata.get("p", []), metadata)
        result = envelope.copy()
        result["metadata"] = metadata
        result["protocols"] = metadata.get("p", [])
        return result
    return None


@dataclass(frozen=True)
class Verdict:
    """What RXinDexer did with a transaction: the full name it registered, and whether as canonical."""

    name: str | None
    canonical: bool

    @property
    def label(self) -> str | None:
        """The bare label a registration fee is priced on (``alice`` for ``alice.rxd``)."""
        if self.name is None:
            return None
        return self.name[: -len(".rxd")] if self.name.endswith(".rxd") else self.name


def registers(tx: UpTx, *, index: Any = None) -> Verdict:
    """Run ``WaveIndex.process_tx`` on ``tx`` and read back what it registered at vout 0.

    ``process_tx`` records ``ref -> "<name>.<parent>"`` for every claim it accepts, canonical or
    duplicate (``refname_cache``), and ``name_hash -> ref`` only for the canonical one. Exceptions
    are handled as the block processor handles them (module docstring): logged, skipped, and
    whatever the index cached before the raise is kept.
    """
    _glyph, wave_index = upstream()
    index = new_index() if index is None else index
    try:
        envelope = phase2_envelope(tx)
    except MemoryError:
        raise
    except Exception:  # block_processor.py:862-869: the glyph overlay is skipped
        envelope = None
    if envelope is None:  # block_processor.py:877: no envelope and no singleton spent, no call
        return Verdict(None, False)
    tx_hash = hashlib.sha256(repr(tx).encode()).digest()
    try:
        index.process_tx(
            tx_hash,
            tx,
            100,
            1,
            glyph_envelope=envelope,
            output_refs_by_vout={},
            spent_singleton_refs=set(),
            block_time=BLOCK_TIME,
        )
    except MemoryError:
        raise
    except Exception:  # block_processor.py:886-892 logs and skips; so does this
        pass
    claim_ref = tx_hash + struct.pack("<I", 0)
    full = index.refname_cache.get(claim_ref)
    if full is None:
        return Verdict(None, False)
    name = full.decode("utf-8")
    label = name.rsplit(".", 1)[0]
    return Verdict(name, index.name_cache.get(wave_index.name_to_hash(label)) == claim_ref)


def price(label: str) -> int:
    """RXinDexer's ``wave_name_price`` — the tier its renewal check compares a payment against."""
    _glyph, wave_index = upstream()
    return int(wave_index.wave_name_price(label))


def treasury_script() -> bytes:
    """The treasury P2PKH script RXinDexer builds from its own default address."""
    _glyph, wave_index = upstream()
    index = new_index()
    assert index.treasury_script is not None, "the indexer could not build its treasury script"
    assert wave_index.WAVE_TREASURY_ADDRESS_DEFAULT  # the address it was built from
    return bytes(index.treasury_script)
