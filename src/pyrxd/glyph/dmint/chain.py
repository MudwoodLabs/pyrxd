"""Chain-walking + on-chain-byte parsing for the dMint subpackage.

Covers ``find_dmint_*_utxo*`` helpers, the ``is_token_bearing_script``
classifier, opcode-walker primitives (``_parse_script_int``,
``_decode_script_le_int``, ``_match_v1_epilogue``), and the
``DmintState``/``DmintContractUtxo``/``DmintMinerFundingUtxo``
dataclasses whose construction depends on parser logic. Depends on
``.types`` and ``.builders`` (the latter via
``_find_v1_contract_utxos_fast`` which uses
``build_dmint_v1_contract_script`` for shape validation, and via
``_match_v1_epilogue`` which uses ``_V1_EPILOGUE_*`` constants).

NOTE ON PLAN DEVIATION: The plan listed ``_V1_EPILOGUE_PREFIX``,
``_V1_EPILOGUE_ALGO_OFFSET``, ``_V1_EPILOGUE_SUFFIX``, and
``_V1_EPILOGUE_LEN`` in this module, and ``_OP_STATESEPARATOR`` here
too. Both were moved: the epilogue constants to ``builders.py``
(because ``build_dmint_v1_code_script`` there uses them, and placing
them here would require a ``builders → chain`` cycle), and
``_OP_STATESEPARATOR`` to ``types.py`` (because ``builders.py``'s
``build_dmint_v1_ft_output_script`` and ``build_dmint_contract_script``
also need it). Both moves preserve the one-way
``types ← builders ← chain ← miner`` dependency graph.
This module re-exports ``_OP_STATESEPARATOR`` and the epilogue
constants so they remain importable from their plan-specified locations
for any downstream that imports from ``chain`` directly.

Symbols (19):
    _OP_STATESEPARATOR (re-export from types),
    _parse_script_int, _decode_script_le_int,
    _V1_EPILOGUE_PREFIX (re-export from builders),
    _V1_EPILOGUE_ALGO_OFFSET (re-export from builders),
    _V1_EPILOGUE_SUFFIX (re-export from builders),
    _V1_EPILOGUE_LEN (re-export from builders),
    _match_v1_epilogue,
    DmintState, DmintContractUtxo, DmintMinerFundingUtxo,
    is_token_bearing_script, find_dmint_funding_utxo,
    _scripthash_for_script, find_dmint_contract_utxos,
    _find_v1_contract_utxos_fast, _find_v1_contract_utxos_walk,
    _s2_verify_contract_utxos
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from pyrxd.security.errors import (
    CovenantError,
    InvalidFundingUtxoError,
    ValidationError,
)

from ..script import TruncatedScriptError, iter_input_refs
from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types
from .builders import (
    _V1_ALGO_BYTE_TO_ENUM,
    _V1_EPILOGUE_ALGO_OFFSET,
    _V1_EPILOGUE_LEN,
    _V1_EPILOGUE_PREFIX,
    _V1_EPILOGUE_SUFFIX,
    build_dmint_v1_contract_script,
)
from .types import (
    _OP_STATESEPARATOR,
    DaaMode,
    DmintAlgo,
    DmintV1ContractInitialState,
)

# Re-export so they are importable from chain as the plan specifies
__all__ = [
    "_OP_STATESEPARATOR",
    "_V1_EPILOGUE_ALGO_OFFSET",
    "_V1_EPILOGUE_LEN",
    "_V1_EPILOGUE_PREFIX",
    "_V1_EPILOGUE_SUFFIX",
]


# ---------------------------------------------------------------------------
# Script integer helpers
# ---------------------------------------------------------------------------


def _parse_script_int(data: bytes, pos: int) -> tuple[int, int]:
    """Parse a Bitcoin script-encoded integer at ``pos``, returning (value, new_pos).

    Handles all push encodings produced by ``_push_minimal`` and
    ``_push_4bytes_le``:

    * ``OP_0`` (0x00)             → 0
    * ``OP_1NEGATE`` (0x4f)       → -1
    * ``OP_1``–``OP_16`` (0x51–0x60) → 1–16
    * ``<length> <data>``         → little-endian signed integer
    * ``0x4c <length> <data>``    → PUSHDATA1
    """
    if pos >= len(data):
        raise ValidationError(f"DmintState.from_script: unexpected end of script at position {pos}")
    op = data[pos]
    # OP_0
    if op == 0x00:
        return 0, pos + 1
    # OP_1NEGATE
    if op == 0x4F:
        return -1, pos + 1
    # OP_1 .. OP_16
    if 0x51 <= op <= 0x60:
        return op - 0x50, pos + 1
    # PUSHDATA1
    if op == 0x4C:
        if pos + 1 >= len(data):
            raise ValidationError("DmintState.from_script: PUSHDATA1 length byte missing")
        n = data[pos + 1]
        start = pos + 2
        raw = data[start : start + n]
        if len(raw) != n:
            raise ValidationError(f"DmintState.from_script: PUSHDATA1 underrun: need {n}, got {len(raw)}")
        return _decode_script_le_int(raw), start + n
    # Direct push (1..75 bytes)
    if 1 <= op <= 75:
        n = op
        start = pos + 1
        raw = data[start : start + n]
        if len(raw) != n:
            raise ValidationError(f"DmintState.from_script: direct push underrun: need {n}, got {len(raw)}")
        return _decode_script_le_int(raw), start + n
    raise ValidationError(f"DmintState.from_script: unrecognised opcode 0x{op:02x} at pos {pos}")


def _decode_script_le_int(raw: bytes) -> int:
    """Decode a Bitcoin script integer from little-endian bytes (with sign bit)."""
    if not raw:
        return 0
    result = int.from_bytes(raw, "little")
    # High bit of last byte is the sign bit.
    if raw[-1] & 0x80:
        # Clear sign bit and negate.
        result ^= 0x80 << (8 * (len(raw) - 1))
        return -result
    return result


# ---------------------------------------------------------------------------
# V1 epilogue fingerprinting
# ---------------------------------------------------------------------------


def _match_v1_epilogue(script: bytes, start: int) -> DmintAlgo | None:
    """Return the algo enum if a V1 epilogue starts at *start*, else ``None``.

    Returning ``None`` means "not a V1 epilogue at this position." Callers
    do not need to distinguish *which* check failed (length / prefix / algo
    byte / suffix) — only "is this a V1 contract or not."
    """
    if start + _V1_EPILOGUE_LEN > len(script):
        return None
    if script[start : start + len(_V1_EPILOGUE_PREFIX)] != _V1_EPILOGUE_PREFIX:
        return None
    algo = _V1_ALGO_BYTE_TO_ENUM.get(script[start + _V1_EPILOGUE_ALGO_OFFSET])
    if algo is None:
        return None
    suffix_start = start + _V1_EPILOGUE_ALGO_OFFSET + 1
    if script[suffix_start : suffix_start + len(_V1_EPILOGUE_SUFFIX)] != _V1_EPILOGUE_SUFFIX:
        return None
    return algo


# ---------------------------------------------------------------------------
# DmintState + related dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DmintState:
    """Parsed dMint contract state (from on-chain UTXO script).

    Supports both V1 (the current Radiant mainnet format) and V2 (Photonic
    Wallet's HEAD spec, not yet seen on mainnet). V1 has 6 state items;
    V2 has 10. ``is_v1`` is True iff this state was parsed from V1 layout
    — in which case ``target_time`` and ``last_time`` are not meaningful
    on-chain values and are set to 0; ``daa_mode`` is always ``FIXED`` for
    V1 (the V1 contract template has no DAA bytecode).
    """

    height: int
    contract_ref: GlyphRef
    token_ref: GlyphRef
    max_height: int
    reward: int
    algo: DmintAlgo
    daa_mode: DaaMode
    target_time: int
    last_time: int
    target: int
    is_v1: bool = False

    @property
    def is_exhausted(self) -> bool:
        return self.height >= self.max_height

    @classmethod
    def from_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a dMint contract UTXO script into a ``DmintState``.

        Tries V2 layout first (10 state items), falls back to V1 (6 items
        + fingerprinted code epilogue). Raises ``ValidationError`` if the
        script matches neither.

        :param script_bytes: Raw script bytes from a dMint contract UTXO output.
        :raises ValidationError: Script is malformed or matches neither V1
            nor V2 layout.
        """
        # Try V2 first. If V2 raises, try V1; if V1 also raises, surface a
        # combined error that names both attempts so callers don't have to
        # guess which version they had.
        try:
            return cls._from_v2_script(script_bytes)
        except ValidationError as v2_exc:
            try:
                return cls._from_v1_script(script_bytes)
            except ValidationError as v1_exc:
                raise ValidationError(
                    f"DmintState.from_script: not a dMint contract (V2: {v2_exc}; V1: {v1_exc})"
                ) from None

    @classmethod
    def _from_v2_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a V2 dMint contract (10 state items + ``bd``).

        Walks the 10 state pushes in declared order, then verifies that the
        next byte is ``OP_STATESEPARATOR`` (0xbd). Closes ultrareview
        re-review N7: the previous implementation searched for the FIRST
        0xbd byte anywhere in the script and sliced the state at that
        position. Because 0xbd is a perfectly valid byte value inside any
        push payload (a 36-byte wire ref, a 4-byte height, a script-int
        target, etc.), an unlucky byte pattern would truncate the state
        at the wrong offset and either fail with a misleading error or —
        if the truncation happened to land on a recognizable opcode — return
        a DmintState built from garbage parsed past the wrong cut point.

        Layout (matches ``build_dmint_state_script``):
          [0] height      — ``_push_minimal`` (variable width; redesign)
          [1] contractRef — ``0xd8`` + 36-byte wire ref
          [2] tokenRef    — ``0xd0`` + 36-byte wire ref
          [3] maxHeight   — ``_push_minimal``
          [4] reward      — ``_push_minimal``
          [5] algoId      — ``_push_minimal``
          [6] daaMode     — ``_push_minimal``
          [7] targetTime  — ``_push_minimal``
          [8] lastTime    — ``_push_4bytes_le`` (opcode 0x04 + 4-byte LE uint32)
          [9] target      — ``_push_minimal`` (may be large for 256-bit algos)
          —— OP_STATESEPARATOR (0xbd) ——
          (code section follows; not parsed here)
        """
        # Walk the full script — do NOT pre-slice on the first 0xbd. The
        # parser consumes exactly the bytes belonging to each push, so by
        # the time we reach position `pos` after item 9, that position is
        # by definition the boundary between state and code regardless of
        # what bytes appeared inside the pushes.
        pos = 0

        # --- Item 0: height (redesign: minimal push, variable width)
        height, pos = _parse_script_int(script_bytes, pos)

        # --- Item 1: contractRef (0xd8 + 36 bytes wire ref)
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD8:
            raise ValidationError(f"DmintState.from_script: expected 0xd8 (OP_PUSHINPUTREFSINGLETON) at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside contractRef")
        contract_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Item 2: tokenRef (0xd0 + 36 bytes wire ref)
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD0:
            raise ValidationError(f"DmintState.from_script: expected 0xd0 (OP_PUSHINPUTREF) at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside tokenRef")
        token_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Items 3–7: variable-length script integers
        max_height, pos = _parse_script_int(script_bytes, pos)
        reward, pos = _parse_script_int(script_bytes, pos)
        algo_id, pos = _parse_script_int(script_bytes, pos)
        daa_id, pos = _parse_script_int(script_bytes, pos)
        target_time, pos = _parse_script_int(script_bytes, pos)

        # --- Item 8: lastTime (always _push_4bytes_le → opcode 0x04 + 4 bytes LE)
        if pos >= len(script_bytes) or script_bytes[pos] != 0x04:
            raise ValidationError(f"DmintState.from_script: expected 0x04 (push-4) at pos {pos} for lastTime")
        if pos + 5 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside lastTime")
        last_time = struct.unpack("<I", script_bytes[pos + 1 : pos + 5])[0]
        pos += 5

        # --- Item 9: target (variable length — large for 256-bit algos)
        target, pos = _parse_script_int(script_bytes, pos)

        # --- After 10 state items, the next byte MUST be OP_STATESEPARATOR.
        # Closes N7: the previous implementation took the first 0xbd
        # byte anywhere in the script as the separator, which a 0xbd
        # inside push-data would defeat. By walking the well-defined
        # state layout first we land on the actual separator position
        # by construction.
        if pos >= len(script_bytes):
            raise ValidationError("DmintState.from_script: script ended before OP_STATESEPARATOR")
        if script_bytes[pos] != _OP_STATESEPARATOR[0]:
            raise ValidationError(
                f"DmintState.from_script: expected OP_STATESEPARATOR (0xbd) "
                f"at pos {pos} after 10-item state, got 0x{script_bytes[pos]:02x}"
            )

        try:
            algo = DmintAlgo(algo_id)
        except ValueError:
            raise ValidationError(f"DmintState.from_script: unknown algo id {algo_id}")
        try:
            daa_mode = DaaMode(daa_id)
        except ValueError:
            raise ValidationError(f"DmintState.from_script: unknown daa_mode id {daa_id}")

        return cls(
            height=height,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=max_height,
            reward=reward,
            algo=algo,
            daa_mode=daa_mode,
            target_time=target_time,
            last_time=last_time,
            target=target,
            is_v1=False,
        )

    @classmethod
    def _from_v1_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a V1 dMint contract (the current mainnet format).

        V1 has 6 state items plus a 145-byte fixed code epilogue (varying
        only in the algo selector byte). Layout:

          [0] height       — ``_push_4bytes_le`` (opcode 0x04 + 4 bytes LE)
          [1] contractRef  — ``0xd8`` + 36-byte wire ref
          [2] tokenRef     — ``0xd0`` + 36-byte wire ref
          [3] maxHeight    — ``_push_minimal``
          [4] reward       — ``_push_minimal``
          [5] target       — full 8-byte push (``0x08`` + 8 LE bytes)
          —— OP_STATESEPARATOR (0xbd) + 144-byte fixed code epilogue ——

        ``daa_mode`` is always ``FIXED`` for V1 (V1 has no DAA bytecode).
        ``target_time`` and ``last_time`` are V2-only and set to 0; the
        ``is_v1`` flag is True so callers can ignore those fields.
        """
        pos = 0

        # --- Item 0: height
        if pos >= len(script_bytes) or script_bytes[pos] != 0x04:
            raise ValidationError(
                f"DmintState._from_v1_script: expected 0x04 (push-4) at pos {pos}, "
                f"got 0x{(script_bytes[pos] if pos < len(script_bytes) else 0):02x}"
            )
        if pos + 5 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside height")
        height = struct.unpack("<I", script_bytes[pos + 1 : pos + 5])[0]
        pos += 5

        # --- Item 1: contractRef
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD8:
            raise ValidationError(f"DmintState._from_v1_script: expected 0xd8 at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside contractRef")
        contract_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Item 2: tokenRef
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD0:
            raise ValidationError(f"DmintState._from_v1_script: expected 0xd0 at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside tokenRef")
        token_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Items 3-4: maxHeight and reward (variable-length pushes)
        max_height, pos = _parse_script_int(script_bytes, pos)
        reward, pos = _parse_script_int(script_bytes, pos)

        # --- Item 5: target (V1 always uses an 8-byte push; never the
        #     algoId/daaMode pushes V2 has).
        if pos >= len(script_bytes) or script_bytes[pos] != 0x08:
            raise ValidationError(f"DmintState._from_v1_script: expected 0x08 (push-8) for target at pos {pos}")
        if pos + 9 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside target")
        target = int.from_bytes(script_bytes[pos + 1 : pos + 9], "little")
        pos += 9

        # --- After 6 state items, fingerprint the V1 code epilogue. The
        # epilogue is byte-identical across V1 deployments except for one
        # algo selector byte; a successful fingerprint match is the
        # discriminator that proves "this is a V1 contract" (rather than
        # a script that happened to start with similar pushes).
        algo = _match_v1_epilogue(script_bytes, pos)
        if algo is None:
            raise ValidationError(f"DmintState._from_v1_script: code epilogue at pos {pos} does not match V1 template")

        return cls(
            height=height,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=max_height,
            reward=reward,
            algo=algo,
            daa_mode=DaaMode.FIXED,  # V1 contracts have no DAA bytecode
            target_time=0,  # not encoded in V1
            last_time=0,  # not encoded in V1
            target=target,
            is_v1=True,
        )


@dataclass(frozen=True)
class DmintContractUtxo:
    """Describes a live dMint contract UTXO to be spent in a mint transaction.

    :param txid:         txid of the UTXO (hex, not reversed)
    :param vout:         output index
    :param value:        photon value locked in the UTXO. For V1 contracts
                         this is the singleton carrier (1 photon on the live
                         RBG-class deploys). For V2 it is the running reward
                         pool that decrements per mint.
    :param script:       full output script bytes (state + OP_STATESEPARATOR + code)
    :param state:        parsed :class:`DmintState` — caller can obtain via
                         ``DmintState.from_script(script)``
    """

    txid: str
    vout: int
    value: int
    script: bytes
    state: DmintState


@dataclass(frozen=True)
class DmintMinerFundingUtxo:
    """A plain RXD UTXO supplied by the miner to fund a V1 mint.

    The V1 covenant takes its FT output value (``reward`` photons) and the
    miner's tx fee from a separate plain-RXD input — the contract output is
    a singleton and never funds the mint. This dataclass describes that
    funding input.

    The locking script must be a plain script with NO Glyph/FT/dMint
    ref pushes (``OP_PUSHINPUTREF*``, opcodes 0xd0–0xd8). Spending a
    token-bearing UTXO as fee silently destroys the token; the V1 mint
    builder validates this and raises :class:`InvalidFundingUtxoError`
    if the funding script carries any ref envelope.

    :param txid:    txid of the UTXO (hex, not reversed)
    :param vout:    output index
    :param value:   photons locked in the UTXO
    :param script:  full locking script bytes (typically 25-byte P2PKH)
    """

    txid: str
    vout: int
    value: int
    script: bytes


def is_token_bearing_script(script: bytes) -> bool:
    """Return True if ``script`` uses any OP_PUSHINPUTREF-family opcode.

    Walks the script as an opcode stream so that only *opcode position* bytes
    are checked against the ref-opcode range — a naive bare-byte scan would
    falsely flag any P2PKH whose 20-byte hash contains a 0xd0–0xd8 byte (~51%
    of random addresses), denying about half of honest miners.

    Truncated push fields are treated as token-bearing — a malformed script of
    ambiguous length should not be accepted as funding.

    Built on the shared opcode walker
    :func:`pyrxd.glyph.script.iter_input_refs` (single source of truth for
    ref detection; see also ``count_input_refs`` for the
    exactly-which-refs covenant guard).
    """
    try:
        for _op, _operand in iter_input_refs(script):
            return True  # found an OP_PUSHINPUTREF-family opcode
    except TruncatedScriptError:
        return True  # malformed / ambiguous length: refuse the funding UTXO
    return False


def _scripthash_for_script(script: bytes) -> str:
    """Return the ElectrumX scripthash for *script* (sha256, then reversed).

    Inline two-line helper rather than a module-level export — used in
    exactly one place (the fast path below). ElectrumX's reverse step
    matches the display-byte-order convention used elsewhere in the
    codebase (see :func:`script_hash_for_address`).
    """
    return hashlib.sha256(script).digest()[::-1].hex()


# ---------------------------------------------------------------------------
# Chain helpers — require an ElectrumXClient
# ---------------------------------------------------------------------------
#
# These functions touch the network — they live here rather than in
# pyrxd.network because the protocol logic (token-burn defense,
# preimage construction binding) is dMint-specific and shouldn't leak
# into the network layer. Imports are lazy so dmint.py stays
# light-import for callers that only need the pure builders/parsers.


async def find_dmint_funding_utxo(
    client: Any,
    miner_address: str,
    needed: int,
    *,
    require_confirmed: bool = True,
) -> DmintMinerFundingUtxo:
    """Scan ``miner_address`` for a plain-RXD UTXO that funds a V1 mint.

    Excludes token-bearing UTXOs (FT, NFT, dMint covenant scripts)
    using :func:`is_token_bearing_script` — the same opcode-aware
    walker the V1 mint builder enforces. Returns the largest qualifying
    candidate to minimise change-output dust risk.

    A plain-RXD funding input is what the V1 covenant requires (V1
    contracts are singletons; reward + fee come from a separate input).
    Spending an FT/NFT/dMint UTXO as fee silently destroys the token —
    this scan is the load-bearing defense.

    :param client:             An already-connected ``pyrxd.network.electrumx.ElectrumXClient``.
    :param miner_address:      Radiant address (R…) of the wallet to scan.
    :param needed:             Minimum photons the candidate must hold.
    :param require_confirmed:  Default ``True``. Skip UTXOs with
        ``height == 0`` (unconfirmed). Picking an unconfirmed UTXO can
        cause "missing inputs" rejection when the parent tx hasn't
        propagated to all relays, or leave a dangling tx if the parent
        gets evicted from mempool. Set ``False`` only if you're
        deliberately funding from a same-tx chain.
    :returns:                  The largest qualifying funding UTXO.
    :raises InvalidFundingUtxoError:
        No plain-RXD UTXO at ``miner_address`` covers ``needed``. The
        error message reports counts of (a) token-bearing skipped,
        (b) too-small skipped, (c) unconfirmed skipped (when
        ``require_confirmed=True``), and (d) network-error skipped, so
        the caller can diagnose why the wallet failed the scan.
    """
    # Lazy imports so callers that only use the pure builders/parsers
    # don't pay the import cost of the network and transaction modules.
    from pyrxd.network.electrumx import script_hash_for_address
    from pyrxd.security.errors import NetworkError
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    raw = await client.get_utxos(script_hash_for_address(miner_address))
    candidates: list[DmintMinerFundingUtxo] = []
    skipped_tokens = 0
    skipped_too_small = 0
    skipped_unconfirmed = 0
    skipped_network_error = 0

    for u in raw:
        if require_confirmed and u.height == 0:
            skipped_unconfirmed += 1
            continue
        try:
            tx_bytes = await client.get_transaction(Txid(u.tx_hash))
        except NetworkError:
            skipped_network_error += 1
            continue
        tx = Transaction.from_hex(bytes(tx_bytes))
        if tx is None or u.tx_pos >= len(tx.outputs):
            continue
        script = tx.outputs[u.tx_pos].locking_script.serialize()
        if is_token_bearing_script(script):
            skipped_tokens += 1
            continue
        if u.value < needed:
            skipped_too_small += 1
            continue
        candidates.append(
            DmintMinerFundingUtxo(
                txid=u.tx_hash,
                vout=u.tx_pos,
                value=u.value,
                script=script,
            )
        )

    if not candidates:
        parts = [f"{skipped_tokens} token-bearing", f"{skipped_too_small} too small"]
        if require_confirmed and skipped_unconfirmed:
            parts.append(f"{skipped_unconfirmed} unconfirmed")
        if skipped_network_error:
            parts.append(f"{skipped_network_error} network-error")
        raise InvalidFundingUtxoError(
            f"no plain-RXD funding UTXO at {miner_address} covers {needed} photons (skipped: {', '.join(parts)})"
        )
    # Largest-first: minimises change-output dust risk.
    candidates.sort(key=lambda u: u.value, reverse=True)
    return candidates[0]


async def find_dmint_contract_utxos(
    client: Any,
    *,
    token_ref: GlyphRef,
    initial_state: DmintV1ContractInitialState | None = None,
    limit: int | None = None,
    min_confirmations: int = 1,
) -> list[DmintContractUtxo]:
    """Discover live V1 dMint contract UTXOs for a given ``token_ref``.

    Two call shapes:

    - **Fast path** — pass ``initial_state``. The function rebuilds each
      contract's expected initial codescript locally
      (``contractRef[i] = (commit_txid, i+1)``, ``tokenRef = token_ref``),
      computes its scripthash inline, and asks the server for the UTXO
      at that scripthash. One ``get_utxos`` call per contract. Use this
      shape immediately after deploy to verify all N contracts went
      live, or any time the caller has the deploy params handy.

    - **Walk-from-reveal fallback** — omit ``initial_state``. The
      function fetches the deploy commit, derives the FT-commit
      hashlock's scripthash, queries history for the reveal txid, then
      fetches the reveal and extracts every fresh V1 contract output
      whose ``tokenRef`` matches. Slower (3+ extra round-trips) but
      works on any live token where you only know the ``token_ref``.

    Both shapes apply the same security S2 cross-check: for each
    candidate UTXO returned, the source transaction is fetched and
    verified to have ``txid()`` matching the server's ``tx_hash``, and
    its output script byte-equal to the script the server claimed.
    Defends against a malicious or buggy ElectrumX serving altered
    bytes (mirrors :func:`find_dmint_funding_utxo`'s round-4 defense).

    The fallback path returns *fresh* contracts only — UTXOs that have
    been mined from at least once are skipped (their state advanced and
    their scripthash drifted; following the spend chain forward to
    locate the current head is filed as deferred work).

    :param client:             An open ``pyrxd.network.electrumx.ElectrumXClient``.
    :param token_ref:          The token's permanent 36-byte ref (the
        deploy commit's vout-0 outpoint, LE-reversed). Equivalently:
        ``GlyphRef(txid=commit_txid, vout=0)``.
    :param initial_state:      If supplied, fast-path. If ``None``, walk
        from the deploy reveal.
    :param limit:              If supplied, cap the result list at this
        many contracts. ``None`` returns all available.
    :param min_confirmations:  Skip UTXOs younger than this many blocks.
        Default 1 (require at least 1 confirmation).
    :returns:                  A list of :class:`DmintContractUtxo` for
        each currently-unspent contract whose script verified S2.
    :raises ValidationError:   Inputs malformed (token_ref must point at
        ``vout=0``); or initial_state has out-of-range fields.
    :raises NetworkError:      Propagated from the ElectrumX client.
    """
    # Lazy imports — keeping dmint.py light for callers that don't touch
    # the network (the inspect tool in particular).
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    if token_ref.vout != 0:
        raise ValidationError(f"token_ref must point at vout=0 of the deploy commit; got vout={token_ref.vout}")
    if limit is not None and limit < 1:
        raise ValidationError(f"limit must be >= 1 if supplied, got {limit}")
    if min_confirmations < 0:
        raise ValidationError(f"min_confirmations must be >= 0, got {min_confirmations}")

    commit_txid = token_ref.txid

    if initial_state is not None:
        if initial_state.num_contracts < 1 or initial_state.num_contracts > 255:
            raise ValidationError(f"num_contracts must be in [1, 255], got {initial_state.num_contracts}")
        candidates = await _find_v1_contract_utxos_fast(
            client,
            token_ref=token_ref,
            commit_txid=commit_txid,
            initial_state=initial_state,
            min_confirmations=min_confirmations,
        )
    else:
        candidates = await _find_v1_contract_utxos_walk(
            client,
            token_ref=token_ref,
            commit_txid=commit_txid,
            min_confirmations=min_confirmations,
        )

    # Security S2 cross-check applied uniformly to whichever shape ran.
    verified = await _s2_verify_contract_utxos(client, candidates, Txid=Txid, Transaction=Transaction)

    if limit is not None:
        verified = verified[:limit]
    return verified


async def _find_v1_contract_utxos_fast(
    client: Any,
    *,
    token_ref: GlyphRef,
    commit_txid: str,
    initial_state: DmintV1ContractInitialState,
    min_confirmations: int,
) -> list[DmintContractUtxo]:
    """Shape A: the caller knows the deploy params, so we can rebuild
    each expected initial codescript and query its scripthash directly.
    """
    from pyrxd.security.types import Txid

    out: list[DmintContractUtxo] = []
    for i in range(initial_state.num_contracts):
        contract_ref = GlyphRef(txid=Txid(commit_txid), vout=i + 1)
        codescript = build_dmint_v1_contract_script(
            height=0,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=initial_state.max_height,
            reward=initial_state.reward_sats,
            target=initial_state.target,
            algo=initial_state.algo,
        )
        sh = _scripthash_for_script(codescript)
        utxos = await client.get_utxos(sh)
        for u in utxos:
            if u.height == 0 and min_confirmations > 0:
                continue
            # State is a known-initial state: we just built the
            # script, so DmintState.from_script(codescript) is the
            # ground truth here. Avoids re-parsing per UTXO.
            state = DmintState.from_script(codescript)
            out.append(
                DmintContractUtxo(
                    txid=u.tx_hash,
                    vout=u.tx_pos,
                    value=u.value,
                    script=codescript,
                    state=state,
                )
            )
    return out


async def _find_v1_contract_utxos_walk(
    client: Any,
    *,
    token_ref: GlyphRef,
    commit_txid: str,
    min_confirmations: int,
) -> list[DmintContractUtxo]:
    """Shape B: the caller has only ``token_ref``. Walk from the deploy
    commit's vout 0 history to locate the reveal, then enumerate the
    reveal's V1 dMint contract outputs and verify each is unspent.
    """
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    # 1. Fetch the commit; extract vout 0's locking script.
    commit_raw = await client.get_transaction(Txid(commit_txid))
    commit_tx = Transaction.from_hex(bytes(commit_raw))
    if commit_tx is None or len(commit_tx.outputs) == 0:
        raise ValidationError(f"deploy commit {commit_txid} has no outputs or did not parse")
    commit_vout0_script = commit_tx.outputs[0].locking_script.serialize()

    # 2. Find the reveal via scripthash history, then disambiguate by
    # input. The FT-commit hashlock script may have been reused across
    # several txs by the same deployer (e.g. failed earlier attempts at
    # the same deploy share the same payload-hash and therefore the same
    # 75-byte hashlock script). The scripthash alone is not unique to
    # this commit instance — we must filter by "spends commit_txid:0".
    sh = _scripthash_for_script(commit_vout0_script)
    history = await client.get_history(sh)
    reveal_txid: str | None = None
    reveal_tx = None
    for entry in history:
        h_txid = entry.get("tx_hash") if isinstance(entry, dict) else None
        if not h_txid or h_txid == commit_txid:
            continue
        # Confirm this candidate actually spends commit_txid:0.
        cand_raw = await client.get_transaction(Txid(h_txid))
        cand_tx = Transaction.from_hex(bytes(cand_raw))
        if cand_tx is None:
            continue
        spends_commit_vout0 = any(
            ti.source_txid == commit_txid and ti.source_output_index == 0 for ti in cand_tx.inputs
        )
        if spends_commit_vout0:
            reveal_txid = h_txid
            reveal_tx = cand_tx
            break
    if reveal_txid is None or reveal_tx is None:
        # Commit unspent (deploy never revealed) or server returned only
        # txs that share the scripthash by hashlock-reuse, none of which
        # actually spend the deploy commit.
        return []

    out: list[DmintContractUtxo] = []
    for vout_i, output in enumerate(reveal_tx.outputs):
        script = output.locking_script.serialize()
        try:
            state = DmintState.from_script(script)
        except ValidationError:
            continue
        if not state.is_v1:
            continue
        if state.token_ref.to_bytes() != token_ref.to_bytes():
            continue

        # 4. Confirm UTXO is currently unspent (skip mined-from contracts —
        # see docstring deferred-work note).
        out_sh = _scripthash_for_script(script)
        utxos = await client.get_utxos(out_sh)
        match = next(
            (u for u in utxos if u.tx_hash == reveal_txid and u.tx_pos == vout_i),
            None,
        )
        if match is None:
            continue
        if match.height == 0 and min_confirmations > 0:
            continue
        out.append(
            DmintContractUtxo(
                txid=match.tx_hash,
                vout=match.tx_pos,
                value=match.value,
                script=script,
                state=state,
            )
        )
    return out


async def _s2_verify_contract_utxos(
    client: Any,
    candidates: list[DmintContractUtxo],
    *,
    Txid: Any,
    Transaction: Any,
) -> list[DmintContractUtxo]:
    """Apply security S2: re-fetch each candidate's source tx, confirm
    txid matches and the output script is byte-equal to what the server
    returned. Rejects altered scripts before they reach the caller.

    Mirrors the round-4 defense in :func:`find_dmint_funding_utxo`.
    """
    verified: list[DmintContractUtxo] = []
    for c in candidates:
        raw = await client.get_transaction(Txid(c.txid))
        tx = Transaction.from_hex(bytes(raw))
        if tx is None:
            raise CovenantError(f"S2 cross-check: source tx {c.txid} did not parse")
        if tx.txid() != c.txid:
            raise CovenantError(f"S2 cross-check: server reported txid {c.txid} but tx parses as {tx.txid()}")
        if c.vout >= len(tx.outputs):
            raise CovenantError(
                f"S2 cross-check: tx {c.txid} has only {len(tx.outputs)} outputs but server claimed vout={c.vout}"
            )
        on_chain_script = tx.outputs[c.vout].locking_script.serialize()
        if on_chain_script != c.script:
            raise CovenantError(
                f"S2 cross-check: script mismatch at {c.txid}:{c.vout} "
                f"(server returned {len(c.script)} bytes; on-chain is {len(on_chain_script)} bytes)"
            )
        verified.append(c)
    return verified
