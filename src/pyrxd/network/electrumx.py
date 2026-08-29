"""ElectrumX JSON-RPC client over WebSocket.

Security notes
--------------
* TLS (``wss://``) is required by default.  Bare ``ws://`` connections raise
  ``NetworkError`` unless the caller explicitly passes ``allow_insecure=True``.
* All method arguments are validated against pyrxd security types before any
  network call is made.
* Raw server responses are NEVER embedded in exception messages verbatim. The one
  deliberate carve-out is a node's **rejection reason**, which is the difference
  between "your script failed verification" and "the socket dropped" and so cannot be
  thrown away. It is passed through ``_sanitize_server_message`` first — first line
  only, non-printables stripped, long tokens run through
  :func:`~pyrxd.security.errors.redact`, then clipped — and surfaced as a typed
  ``PolicyRejection``. Everything else still gets a static description.
* ``script_hash`` parameters follow the ElectrumX convention: the value is
  ``sha256(locking_script)`` with the bytes reversed (little-endian hash).

Usage
-----
    async with ElectrumXClient(["wss://electrumx.server1.com"]) as client:
        tip = await client.get_tip_height()
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.exceptions import WebSocketException

from ..hash import hash256, sha256
from ..merkle_path import MerklePath
from ..script.type import P2PKH
from ..security.errors import NetworkError, PolicyRejection, TlsPinMismatchError, ValidationError, redact
from ..security.types import BlockHeight, Hex32, Photons, RawTx, Txid
from ..security.units import ChainHeight, PhotonValue
from ._guards import finite_int, hex_str, merkle_branch, nonneg_int
from .registry import block_hash_hex
from .tls_pin import normalize_pin, verify_connection_pin

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT: float = 30.0


@dataclass
class UtxoRecord:
    """A single unspent transaction output as returned by ElectrumX.

    Attributes
    ----------
    tx_hash:
        Transaction id in hex (little-endian / display order).
    tx_pos:
        Output index within the transaction.
    value:
        Output value in **photons** (RXD's smallest unit) — this is a Radiant client.

        On Radiant this IS the Glyph FT token quantity when the output carries an FT
        ref: **1 photon = 1 token unit** (``docs/concepts/radiant-fts-are-on-chain.md``).
        ``OP_REFVALUESUM_OUTPUTS`` sums ref-bearing outputs' native ``nValue``
        (Radiant-Core ``src/script/interpreter.cpp``), and :class:`~pyrxd.glyph.ft.FtUtxo`
        REFUSES ``value != ft_amount`` because such an output cannot exist on chain.

        An earlier revision of this docstring said the opposite — that "1000 tokens can
        sit on 546 photons of ordinary dust". That is the Bitcoin colored-coin model
        (Atomicals/Runes), and it is wrong here. The claim originated in issue #505, was
        written into this docstring, and was then cited back as corroboration for #505 —
        the issue and the doc confirming each other while the chain said otherwise.
    height:
        Block height at which the output was confirmed (0 = unconfirmed). A HEIGHT,
        never a confirmation count. Both are non-negative ints, so a producer that
        stores confs here type-checks — and inverts every age ordering built on the
        field, because ascending height is oldest-first while ascending confs is
        NEWEST-first. The mainnet ssh-tr shim did exactly that, which flipped
        ``find_covenant_utxo``'s earliest-confirmed anti-poisoning rule into a
        poison-selecting rule on the real-value path.

    Both fields are unit-TAGGED (:mod:`pyrxd.security.units`), so a producer that
    stores a confirmation count in ``height`` — or a token count in ``value`` — is now
    a mypy error at the construction site rather than a code review that has to notice.
    The tags are :func:`typing.NewType` aliases: zero runtime cost, no validation, no
    behaviour change. The behavioural half of the contract stays where it was: every
    producer is driven through its real code path by ``tests/test_utxo_record_units.py``
    — register any new producer there with a units test as well as tagging it here.
    """

    tx_hash: str
    tx_pos: int
    value: PhotonValue
    height: ChainHeight


_MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# RPC-error classification
# ---------------------------------------------------------------------------
#
# Every RPC error used to collapse to ``NetworkError("ElectrumX RPC error (code N)")``,
# discarding the server's message. That made a script-verification failure, a dust
# output and an unmet min-relay-fee indistinguishable from a dropped socket — the exact
# masking that hid a dMint covenant-rejection bug for weeks (see
# docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md). A node rejection
# now raises the typed ``PolicyRejection``; genuine transport faults stay ``NetworkError``.

# Codes that mean "the node evaluated your transaction and said no".
#   1   ElectrumX's DAEMON_ERROR — how it forwards a bitcoind sendrawtransaction failure
#  -25  RPC_TRANSACTION_ERROR
#  -26  RPC_TRANSACTION_REJECTED
#  -27  RPC_TRANSACTION_ALREADY_IN_CHAIN
_POLICY_ERROR_CODES: frozenset[int] = frozenset({1, -25, -26, -27})

# Reject-reason fragments (matched case-insensitively) that identify a policy/consensus
# rejection even when it arrives under an unexpected code. Kept to strings a node emits
# for a *transaction* verdict — nothing here matches a connection or protocol fault.
_POLICY_MESSAGE_MARKERS: tuple[str, ...] = (
    "rejected by network rules",
    "mandatory-script-verify-flag-failed",
    "non-mandatory-script-verify-flag",
    "min relay fee not met",
    "insufficient priority",
    "insufficient fee",
    "absurdly-high-fee",
    "too-long-mempool-chain",
    "txn-already-",
    "bad-txns-",
    "scriptsig-",
    "scriptpubkey",
    "non-final",
    "dust",
    "missing-inputs",
    "txn-mempool-conflict",
)

# A server message is attacker-influencable text. It never reaches a caller verbatim.
_MAX_SERVER_MESSAGE_CHARS: int = 200
# Tokens at least this long are run through ``redact`` — below it we are looking at
# prose, and ``redact``'s deliberately aggressive base58 heuristic would eat ordinary
# English words ("transaction" is all-base58 characters).
_REDACT_TOKEN_MIN_CHARS: int = 20
# A long token ``redact`` did not flag (e.g. "mandatory-script-verify-flag-failed") is
# kept, but clipped — no unbounded server-controlled run in an exception message.
_MAX_TOKEN_CHARS: int = 64
# How much of an untrusted message is examined AT ALL. Everything below — the line
# split, the per-character printability scan, the per-token ``redact`` — is O(len), and
# this function runs on the receive-loop coroutine, so on a frame at the 10 MB cap it
# blocked the whole client's event loop for ~200 ms (measured: 201 ms on a 10 MB
# single-line message, 281 ms on 10 MB of short tokens), repeatably, on every RPC error a
# hostile or broken server chose to send. Clipping FIRST bounds that to microseconds.
#
# 8 KiB is 40x the 200-char output cap, so it cannot change the result for any message
# whose leading tokens are of sane length; a message that needs more than 8 KiB of input
# to produce 200 characters of output is one built out of multi-KiB tokens, and every
# such token collapses to ``<redacted>`` or a 64-char clip anyway.
_MAX_SCANNED_CHARS: int = 8192


def _sanitize_server_message(message: Any) -> str:
    """Render an untrusted node message safe to embed in an exception.

    Applies, in order: non-``str`` → empty; **clip to** :data:`_MAX_SCANNED_CHARS` (see
    there — this bounds every step below, which would otherwise stall the receive loop
    on a 10 MB frame); first line only (kills multi-line reject dumps and log-injection
    via embedded newlines); non-printable characters → spaces (ANSI escapes, NULs, bidi
    controls); :func:`~pyrxd.security.errors.redact` per long whitespace token (an
    ElectrumX broadcast error historically appended the **entire raw transaction hex**
    to the reason — that token is pure hex and collapses to ``<redacted>``); per-token
    clipping; whole-message clipping.

    The result is what callers and tracebacks see. Raw server bytes are never stored
    on the exception and never chained via ``raise ... from``.
    """
    if not isinstance(message, str) or not message:
        return ""
    head = message[:_MAX_SCANNED_CHARS]
    lines = head.splitlines()
    first_line = lines[0] if lines else ""
    # Did the clip land inside the first line (rather than the line ending first)? If so
    # its final token is a FRAGMENT of a longer one. A fragment at or above
    # _REDACT_TOKEN_MIN_CHARS is fine — it is still redacted/clipped like any long token,
    # and a prefix of hex/base58 is still hex/base58, so a payload that would have
    # collapsed to "<redacted>" still does. A SHORT fragment is the one hazard: it would
    # slip past a redaction the whole token would have triggered. Drop only that.
    clipped_mid_line = len(message) > _MAX_SCANNED_CHARS and len(lines) <= 1
    cleaned = "".join(ch if ch.isprintable() else " " for ch in first_line)
    raw_tokens = cleaned.split()
    if (
        clipped_mid_line
        and len(raw_tokens) > 1
        and cleaned
        and not cleaned[-1].isspace()
        and len(raw_tokens[-1]) < _REDACT_TOKEN_MIN_CHARS
    ):
        raw_tokens = raw_tokens[:-1]
    tokens = []
    for token in raw_tokens:
        if len(token) >= _REDACT_TOKEN_MIN_CHARS:
            scrubbed = str(redact(token))
            token = scrubbed if scrubbed != token else token[:_MAX_TOKEN_CHARS]
        tokens.append(token)
    out = " ".join(tokens)
    if len(out) > _MAX_SERVER_MESSAGE_CHARS:
        out = out[:_MAX_SERVER_MESSAGE_CHARS] + "..."
    return out


def _rpc_error(code: Any, message: Any) -> NetworkError:
    """Build the exception for a JSON-RPC error object.

    Returns :class:`~pyrxd.security.errors.PolicyRejection` (itself a
    ``NetworkError``, so existing ``except NetworkError`` handlers keep working) when
    the code or the sanitized reason says the node rejected a transaction; a plain
    ``NetworkError`` otherwise.

    The sanitized reason is attached **only** to a policy rejection — that is the one
    place where discarding it caused real harm. Every other RPC error keeps the
    original static description, so the module's "no server text in the message"
    invariant still holds everywhere it mattered before.
    """
    reason = _sanitize_server_message(message)
    lowered = reason.lower()
    is_policy = code in _POLICY_ERROR_CODES or any(marker in lowered for marker in _POLICY_MESSAGE_MARKERS)
    if not is_policy:
        return NetworkError(f"ElectrumX RPC error (code {code})")
    detail = f": {reason}" if reason else ""
    return PolicyRejection(
        f"node rejected the transaction (code {code}){detail}",
        code=code,
        reason=reason,
    )


def _coerce_hex32(value: Hex32 | bytes | bytearray | str) -> Hex32:
    """Normalize caller-supplied script_hash to Hex32 at the SDK boundary.

    Accepts Hex32 (passthrough), raw bytes/bytearray of length 32, or a
    hex str of length 64. Anything else raises ValidationError with a
    message that names the offending type — never echoes the value.
    """
    if isinstance(value, Hex32):
        return value
    if isinstance(value, (bytes, bytearray)):
        return Hex32(bytes(value))
    if isinstance(value, str):
        return Hex32.from_hex(value)
    raise ValidationError(f"script_hash must be Hex32, bytes, or hex str; got {type(value).__name__}")


def script_hash_for_script(locking_script: bytes) -> Hex32:
    """Return the ElectrumX ``script_hash`` for a raw *locking_script*.

    ElectrumX indexes **every** output by ``sha256(locking_script)`` with the
    bytes reversed (little-endian display order) — not just address-shaped
    ones. Use this when you hold the script bytes rather than an address, e.g.
    to ask for the history of a Glyph commit output (which is how the scanner
    finds the reveal transaction that spent it).

    Parameters
    ----------
    locking_script:
        Raw scriptPubKey bytes.

    Returns
    -------
    Hex32
        The 32-byte script hash suitable for ElectrumX RPC calls.
    """
    return Hex32(sha256(bytes(locking_script))[::-1])


def script_hash_for_address(address: str) -> Hex32:
    """Return the ElectrumX ``script_hash`` for a P2PKH *address*.

    ElectrumX indexes addresses by ``sha256(locking_script)`` with the bytes
    reversed (little-endian display order). This public helper lets callers
    derive the script hash without constructing a full client.

    Parameters
    ----------
    address:
        Base58Check-encoded P2PKH address.

    Returns
    -------
    Hex32
        The 32-byte script hash suitable for ElectrumX RPC calls.
    """
    return script_hash_for_script(P2PKH().lock(address).serialize())


class ElectrumXClient:
    """Async ElectrumX JSON-RPC client.

    Parameters
    ----------
    urls:
        One or more ElectrumX server URLs.  The client uses the first URL;
        on disconnect it attempts one reconnect, then raises ``NetworkError``.
    allow_insecure:
        If ``False`` (default) ``ws://`` URLs raise ``NetworkError`` immediately.
        Set to ``True`` only for local testing.
    timeout:
        Per-request timeout in seconds (default 30).
    spki_pins:
        Optional TLS SubjectPublicKeyInfo pins (``sha256/<base64>``). Empty (the
        default) leaves pinning OFF — ordinary CA validation only. When supplied,
        every connection is checked against the set before any RPC is sent and a
        mismatch raises :class:`~pyrxd.security.errors.TlsPinMismatchError`. See
        :mod:`pyrxd.network.tls_pin` for the format and for why it is opt-in.
    """

    def __init__(
        self,
        urls: list[str],
        *,
        allow_insecure: bool = False,
        timeout: float = _DEFAULT_TIMEOUT,
        spki_pins: Sequence[str] = (),
    ) -> None:
        if not urls:
            raise ValidationError("ElectrumXClient requires at least one server URL")
        self._urls = urls
        self._allow_insecure = allow_insecure
        self._timeout = timeout
        # Normalised at construction so a malformed pin fails at wiring time, not
        # on the first network hiccup. An unparseable pin must never degrade to
        # "unpinned" — see tls_pin.normalize_pin.
        self._spki_pins: tuple[str, ...] = tuple(normalize_pin(pin) for pin in spki_pins)
        self._ws: Any | None = None  # websockets.WebSocketClientProtocol
        self._id_counter: int = 0
        self._id_lock: asyncio.Lock = asyncio.Lock()
        # Send must be serialized across tasks — websockets.send is not
        # safe to call concurrently from multiple coroutines on the same
        # connection (interleaved fragments).
        self._send_lock: asyncio.Lock = asyncio.Lock()
        # Pending requests keyed by JSON-RPC id. Reader task pops the
        # matching entry and resolves its future when a response arrives.
        # Closes ultrareview Stream C #4 (response correlation race).
        # Without per-id correlation, two concurrent _call() invocations
        # could swap responses — caller A awaits recv() and gets caller
        # B's result, because recv() returns whatever message arrives next
        # rather than the one matching A's request id.
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._reader_task: asyncio.Task[None] | None = None

        # Validate all URLs at construction time (fast-fail).
        for url in self._urls:
            self._validate_url(url)

    # ---------------------------------------------------------------------- context manager

    async def __aenter__(self) -> ElectrumXClient:
        await self._ensure_connected()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying WebSocket connection.

        Cancels the reader task, fails any in-flight requests with
        NetworkError, and closes the socket.
        """
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                # Reader task is being torn down — ignore both cancellation and any final error.
                pass
        self._reader_task = None

        if self._ws is not None:
            try:
                await self._ws.close()
            except (WebSocketException, OSError):
                # Ignore errors on close — the connection is being torn down.
                logger.debug("Error closing ElectrumX WebSocket (ignored)")
            self._ws = None

        self._fail_all_pending(NetworkError("ElectrumX connection closed"))

    # ---------------------------------------------------------------------- public API

    async def call_extension(self, method: str, params: list[Any] | None = None) -> Any:
        """Call an arbitrary JSON-RPC method on the connected server.

        Use this for indexer-extension RPCs that aren't part of the base
        ElectrumX surface — e.g. RXinDexer's ``wave.resolve``,
        ``glyph.get_token``, ``swap.get_unconfirmed_orders``. The
        underlying transport (connection, id correlation, error handling)
        is identical to the built-in methods.

        Returns the raw ``result`` field from the JSON-RPC response. Server
        errors raise :class:`NetworkError`. The caller is responsible for
        validating the result shape.
        """
        return await self._call(method, params or [])

    async def get_transaction(self, txid: Txid) -> RawTx:
        """Fetch the raw transaction bytes for *txid*.

        Returns
        -------
        RawTx
            The serialised transaction (> 64 bytes, Merkle-forgery safe).
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        result = await self._call("blockchain.transaction.get", [str(txid), False])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for transaction hex")
        try:
            raw = bytes.fromhex(result)
        except ValueError:
            raise NetworkError("Server returned invalid hex for transaction")
        # Serialize, don't trust: a server may return ANY transaction for a
        # ``blockchain.transaction.get``. ``swap.resolve.fetch_transaction`` and
        # ``failover._holds_tx`` each re-derived the id themselves, but the Glyph scanner
        # (``glyph/scanner.py``) did not — so a hostile server could feed it a transaction of
        # its choosing and have the token metadata parsed out of it. The txid is
        # ``hash256(raw)`` reversed, so binding needs no parser and cannot itself fail.
        if hash256(raw)[::-1].hex() != str(txid):
            raise NetworkError(
                f"server returned a transaction whose hash is not the requested txid {str(txid)[:16]}…; fail-closed"
            )
        return RawTx(raw)

    async def get_transaction_verbose(self, txid: Txid) -> dict[str, Any]:
        """Fetch the verbose JSON-decoded form of a transaction.

        Calls ``blockchain.transaction.get`` with ``verbose=True`` and
        returns the dict the server provides — including ``confirmations``,
        ``blockhash``, ``blocktime``. Used by confirmation polling.

        Distinct from :meth:`get_transaction` (which returns raw bytes
        for cryptographic operations like merkle-proof checks). Callers
        polling for "is this tx confirmed yet?" want THIS one.

        Bound to the request the same way :meth:`get_transaction` is. The raw form recomputes
        ``hash256(raw)``; the verbose form has no bytes to hash, so it binds the ``txid`` the
        node echoes (``getrawtransaction <txid> true`` always returns it — Radiant-Core
        ``src/rpc/rawtransaction.cpp``, and ElectrumX's ``blockchain.transaction.get`` passes
        the daemon object through verbatim). Without this the ONLY untethered transaction read
        in the client was the one every confirmation gate is built on
        (:func:`pyrxd.network.confirm.wait_for_confirmation`,
        :meth:`pyrxd.gravity.radiant_leg.RadiantCovenantLeg.confirmations`,
        :class:`pyrxd.gravity.watch.adapters.ElectrumRxdChainSource`): a server could answer
        with a DIFFERENT, deeply-buried transaction's body and satisfy the depth threshold
        without fabricating a single field — it just returns a true answer to a question nobody
        asked.
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        result = await self._call("blockchain.transaction.get", [str(txid), True])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for verbose transaction")
        echoed = result.get("txid")
        if not isinstance(echoed, str) or echoed.strip().lower() != str(txid).lower():
            raise NetworkError(
                f"verbose transaction response does not identify the requested txid {str(txid)[:16]}… "
                "(missing or mismatched 'txid'); fail-closed"
            )
        return result

    async def get_transaction_merkle(self, txid: Txid, height: BlockHeight) -> MerklePath:
        """Fetch the Merkle proof for *txid* at block *height*.

        Returns
        -------
        MerklePath
            A parsed Merkle path object.
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        result = await self._call("blockchain.transaction.get_merkle", [str(txid), int(height)])
        # ElectrumX returns {"block_height": N, "merkle": [...], "pos": N}
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for transaction merkle")
        try:
            # `merkle` had NO type check: a JSON string passed through as "the branch", and
            # iterating "deadbeef" yields eight one-character "hashes". `pos` had no sign check
            # and both int() calls could raise OverflowError on a JSON `Infinity` — a class
            # absent from the tuple below, so it escaped past every `except NetworkError`.
            block_height = BlockHeight(nonneg_int(result["block_height"]))
            merkle_hashes: list[str] = merkle_branch(result["merkle"])
            pos: int = nonneg_int(result["pos"])
        except (KeyError, TypeError, ValueError, ValidationError):
            raise NetworkError("Malformed merkle response from server")

        # The proof must be for the block we ASKED about. ElectrumX echoes `block_height`, and
        # without binding it the server chooses which block it proves inclusion in.
        if int(block_height) != int(height):
            raise NetworkError(
                f"merkle proof is for block {int(block_height)}, not the requested {int(height)}; fail-closed"
            )

        # Build a MerklePath from the ElectrumX branch format.
        # ElectrumX returns hashes in display (reversed) order; we pass the
        # txid as the leaf and build a linear proof path.
        path: list[list[Any]] = [[{"offset": pos, "hash_str": str(txid), "txid": True}]]
        current_pos = pos
        for _h, sibling_hex in enumerate(merkle_hashes):
            sibling_offset = current_pos ^ 1
            path[0].append({"offset": sibling_offset, "hash_str": sibling_hex})
            current_pos = current_pos >> 1

        try:
            return MerklePath(int(block_height), path)
        except Exception as exc:
            raise NetworkError(f"Could not construct MerklePath: {exc}") from exc

    async def broadcast(self, raw_tx: bytes) -> Txid:
        """Broadcast a raw transaction to the network.

        Parameters
        ----------
        raw_tx:
            Serialised transaction bytes.

        Returns
        -------
        Txid
            The transaction id returned by the server.
        """
        validated = RawTx(raw_tx)
        result = await self._call("blockchain.transaction.broadcast", [validated.hex()])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for broadcast result")
        try:
            return Txid(result)
        except ValidationError as exc:
            raise NetworkError("Server returned invalid txid after broadcast") from exc

    async def get_balance(self, script_hash: Hex32 | bytes | str) -> tuple[Photons, Photons]:
        """Return the confirmed and unconfirmed balance for *script_hash*, in photons.

        The ``script_hash`` is ``sha256(locking_script)`` with bytes reversed
        (ElectrumX little-endian convention). Accepts ``Hex32``, raw
        ``bytes`` (length 32), or a hex ``str`` (length 64).

        Returns
        -------
        tuple[Photons, Photons]
            ``(confirmed, unconfirmed)``
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.get_balance", [script_hash.hex()])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for balance")
        try:
            # Photons, not Satoshis. Radiant's MAX_MONEY is 1000x Bitcoin's, so the BTC cap
            # rejected any address holding more than 21,000,000 RXD — reporting a truthful
            # answer as a malformed one. See ``pyrxd.security.types``.
            confirmed = Photons(nonneg_int(result["confirmed"]))
            unconfirmed = Photons(nonneg_int(result["unconfirmed"]))
        except (KeyError, TypeError, ValueError, ValidationError):
            raise NetworkError("Malformed balance response from server")
        return confirmed, unconfirmed

    async def get_utxos(self, script_hash: Hex32 | bytes | str) -> list[UtxoRecord]:
        """Return the list of UTXOs for *script_hash*.

        Accepts ``Hex32``, raw ``bytes`` (length 32), or a hex ``str``
        (length 64). Each UTXO is returned as a typed :class:`UtxoRecord`.
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.listunspent", [script_hash.hex()])
        if not isinstance(result, list):
            raise NetworkError("Unexpected response type for UTXOs")
        try:
            # `listunspent` feeds coin selection. `tx_hash` was assigned with no validation at
            # all (a `null` propagated into the outpoint of a tx the wallet was about to sign),
            # a negative `value`/`tx_pos` was returned verbatim, `1.9` was truncated to `1`, and
            # `Infinity` escaped as OverflowError — absent from the tuple below.
            #
            # `value` is bounded by RADIANT MAX_MONEY, not Bitcoin's. It was briefly bounded by
            # `Satoshis` — a cap 1000x too low for this chain — and because this is a list
            # COMPREHENSION, one UTXO over 21,000,000 RXD did not merely lose itself: it aborted
            # the whole list, so every sibling UTXO on that address became invisible and the
            # address unspendable. It surfaced as `NetworkError`, which `FailoverElectrumXClient`
            # reads as a transport fault, so the SDK then discarded one healthy endpoint after
            # another for returning the truth. See ``pyrxd.security.types``.
            return [
                UtxoRecord(
                    tx_hash=hex_str(item["tx_hash"], nbytes=32),
                    tx_pos=nonneg_int(item["tx_pos"]),
                    # `Photons` range-checks against Radiant MAX_MONEY; `PhotonValue` tags the
                    # UNIT so a token count cannot be stored here. The tag is free — see
                    # `pyrxd.security.units` on why a unit tag must not also validate.
                    value=PhotonValue(int(Photons(nonneg_int(item["value"])))),
                    # A HEIGHT. The server's `height` field already is one; nothing in this
                    # method computes a depth, and `ChainHeight` now stops one being stored.
                    height=ChainHeight(nonneg_int(item["height"])),
                )
                for item in result
            ]
        except (KeyError, TypeError, ValueError, ValidationError):
            raise NetworkError("Malformed UTXO entry in server response")

    async def get_history(self, script_hash: Hex32 | bytes | str) -> list[dict[str, Any]]:
        """Return the transaction history for *script_hash*.

        Returns a list of ``{"tx_hash": str, "height": int}`` dicts.
        Unconfirmed transactions have ``height`` of 0 or negative.
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.get_history", [script_hash.hex()])
        if not isinstance(result, list):
            raise NetworkError("Unexpected response type for history")
        try:
            # `height` is the one field where a negative value is protocol-legitimate (ElectrumX
            # reports 0 / -1 for an unconfirmed tx), so only non-numeric and non-finite shapes
            # are refused here.
            return [
                {"tx_hash": hex_str(item["tx_hash"], nbytes=32), "height": finite_int(item["height"])}
                for item in result
            ]
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed history entry in server response")

    async def get_block_header(self, height: BlockHeight) -> bytes:
        """Return the raw 80-byte block header at *height*."""
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        result = await self._call("blockchain.block.header", [int(height)])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for block header")
        try:
            header_bytes = bytes.fromhex(result)
        except ValueError:
            raise NetworkError("Server returned invalid hex for block header")
        if len(header_bytes) != 80:
            raise NetworkError(f"Block header must be 80 bytes, got {len(header_bytes)}")
        return header_bytes

    async def get_tip_height(self) -> BlockHeight:
        """Return the current chain tip block height.

        Uses ``blockchain.headers.subscribe``, whose INITIAL response is the current
        tip header — ``{"height": N, "hex": "..."}`` (standard ElectrumX). The call also
        installs a server-side header-push subscription, but that is harmless here: the
        reader loop drops every id-less server push (see :meth:`_reader_loop`), so later
        header notifications never interfere with request/response matching.

        (The prior implementation called ``blockchain.block.header [0, 0]`` expecting a
        ``{"height", ...}`` dict, but standard ElectrumX returns the bare genesis-header
        hex *string* for that call — so the tip read raised "Unexpected response type"
        against real servers, e.g. electrumx.radiant4people.com.)
        """
        result = await self._call("blockchain.headers.subscribe", [])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for tip height")
        try:
            height = BlockHeight(nonneg_int(result["height"]))
        except (KeyError, TypeError, ValueError, ValidationError):
            raise NetworkError("Malformed tip height response from server")
        return height

    async def assert_chain(self, expected_genesis_hash: str) -> str:
        """Fail closed unless the server is on the chain identified by *expected_genesis_hash*.

        Mirrors :meth:`pyrxd.eth_wallet.rpc.EthRpc.assert_chain` — the ETH leg has
        refused to act on a wrong-chain endpoint since it shipped, and an ElectrumX
        URL carries even less information about which chain is behind it than an
        RPC URL does. Reads block 0 (``blockchain.block.header [0]``, one round
        trip, no state) and compares the Radiant double-SHA-512/256 header hash
        against the expected value.

        This is what turns a *declared* network binding into a *verified* one:
        without it, ``--network regtest`` pointed at a mainnet server is
        indistinguishable from a correct setup until a transaction lands on the
        wrong chain.

        Parameters
        ----------
        expected_genesis_hash:
            Genesis block hash in display order — see
            :data:`pyrxd.network.registry.GENESIS_BLOCK_HASHES`.

        Returns
        -------
        str
            The observed genesis hash (equal to the expected one on success).

        Raises
        ------
        ValidationError
            If the server's genesis hash differs from the expected one. Both
            values are public chain data, so both are named verbatim — that is
            what makes the misconfiguration fixable.
        NetworkError
            On transport failure or a malformed header response.
        """
        expected = str(expected_genesis_hash).strip().lower()
        header = await self.get_block_header(BlockHeight(0))
        observed = block_hash_hex(header)
        if observed != expected:
            raise ValidationError(
                f"ElectrumX endpoint is on the wrong chain: genesis {observed} != expected {expected}. "
                "Check --network and the endpoint configured for it."
            )
        return observed

    # ---------------------------------------------------------------------- internals

    def _validate_url(self, url: str) -> None:
        """Raise NetworkError if *url* is insecure and allow_insecure is False."""
        if url.startswith("ws://") and not self._allow_insecure:
            raise NetworkError("Insecure WebSocket URL rejected. Use wss:// or pass allow_insecure=True.")
        if not (url.startswith("wss://") or url.startswith("ws://")):
            raise NetworkError("URL must start with wss:// or ws:// (got scheme)")

    async def _ensure_connected(self) -> None:
        """Connect to the first available server (if not already connected) and
        ensure the reader task is running.

        With a single URL the previous sequential loop is equivalent; with
        multiple URLs all endpoints are raced in parallel so a single dead
        endpoint no longer adds a full timeout period before failover.
        Closes N18.
        """
        if self._ws is None:
            self._ws = await self._connect_first(self._urls, self._timeout)

        if self._reader_task is None or self._reader_task.done():
            self._reader_task = asyncio.create_task(self._reader_loop())

    async def _connect_first(self, urls: list[str], timeout: float) -> Any:  # websockets.WebSocketClientProtocol
        """Race all *urls* concurrently; return the first successful WebSocket.

        Unlike the previous sequential loop (N18), the worst-case connect
        latency is one ``timeout`` period regardless of how many dead
        endpoints precede the live one.

        Cancellation safety (post-review fix): every successfully-connected
        socket is appended to ``created`` *before* the coroutine returns it,
        so the ``finally`` block can close any socket that wasn't picked as
        the winner — even when the producing task was cancelled mid-flight.
        Without this, a losing ``_try`` whose ``websockets.connect`` resolved
        between ``wait()`` returning and ``task.cancel()`` taking effect
        would leak the socket: ``gather(return_exceptions=True)`` consumes
        the ``CancelledError`` but cannot retrieve the orphaned ws.

        Raises ``NetworkError`` if all connections fail or the overall
        timeout expires before any succeeds. A TLS SPKI pin mismatch is re-raised
        as itself rather than folded into the generic message: "you are not
        talking to the server you pinned" needs a different operator response
        from "nothing answered", and burying it would make an opt-in security
        control look like a flaky network.
        """
        created: list[Any] = []  # every ws actually returned by websockets.connect

        async def _try(url: str) -> Any:
            ws = await websockets.connect(url)
            # Append BEFORE the pin check so the `finally` block below still closes
            # this socket when the check rejects it.
            created.append(ws)
            if self._spki_pins:
                verify_connection_pin(ws, self._spki_pins, url=url)
            return ws

        tasks = [asyncio.create_task(_try(url)) for url in urls]
        winner_ws: Any | None = None
        last_exc: Exception | None = None
        pin_exc: TlsPinMismatchError | None = None
        remaining: set[asyncio.Task[Any]] = set(tasks)

        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout

            while remaining:
                time_left = max(0.0, deadline - loop.time())
                done, remaining = await asyncio.wait(
                    remaining,
                    timeout=time_left,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if not done:
                    last_exc = last_exc or asyncio.TimeoutError(f"No ElectrumX endpoint responded within {timeout}s")
                    break

                for task in done:
                    try:
                        ws = task.result()
                    except TlsPinMismatchError as exc:
                        logger.debug("ElectrumX connect rejected by SPKI pin")
                        pin_exc = pin_exc or exc
                        last_exc = exc
                        continue
                    except Exception as exc:
                        logger.debug("ElectrumX connect failed: %s", exc)
                        last_exc = exc
                        continue

                    if winner_ws is None:
                        winner_ws = ws

                if winner_ws is not None:
                    break

        finally:
            for task in remaining:
                task.cancel()
            if remaining:
                await asyncio.gather(*remaining, return_exceptions=True)
            # Close every connected ws that isn't the winner — covers both
            # "extra winners that completed in the same `done` set" and
            # "sockets that resolved inside a cancelled coroutine."
            for ws in created:
                if ws is winner_ws:
                    continue
                try:
                    await ws.close()
                except Exception:  # nosec B110 — best-effort cleanup of losing race connection
                    pass

        if winner_ws is not None:
            return winner_ws
        if pin_exc is not None:
            raise pin_exc
        raise NetworkError("Failed to connect to any ElectrumX server") from last_exc

    def _fail_all_pending(self, exc: Exception) -> None:
        """Resolve every in-flight future with *exc*; clear the pending map."""
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def _reader_loop(self) -> None:
        """Read messages from the socket and dispatch by JSON-RPC id.

        Runs as a single task per connection. Pops the matching pending
        future for each response's ``id`` and sets its result/exception.
        On socket error or EOF, fails all pending requests and exits;
        the next ``_call`` triggers reconnect via ``_ensure_connected``.

        Orphan responses (id not in ``_pending``, or future already done)
        are logged at debug level and dropped — they cannot be matched
        and trying to "guess" the right caller would re-introduce the
        very swap-bug this design eliminates.
        """
        try:
            while True:
                if self._ws is None:
                    return
                raw = await self._ws.recv()
                # Validate response size before parsing.
                if isinstance(raw, (bytes, bytearray)):
                    if len(raw) > _MAX_RESPONSE_BYTES:
                        # Oversized message — the server is misbehaving;
                        # disconnect and fail all pending so callers retry
                        # against a fresh connection (or another server).
                        self._fail_all_pending(NetworkError("ElectrumX response exceeds maximum allowed size"))
                        return
                    raw_str = raw.decode("utf-8", errors="replace")
                else:
                    if len(raw) > _MAX_RESPONSE_BYTES:
                        self._fail_all_pending(NetworkError("ElectrumX response exceeds maximum allowed size"))
                        return
                    raw_str = raw

                try:
                    data = json.loads(raw_str)
                except json.JSONDecodeError:
                    # One bad message shouldn't poison the whole connection,
                    # but it does mean we can't dispatch this one. Continue.
                    logger.debug("ElectrumX reader skipped non-JSON message")
                    continue

                if not isinstance(data, dict):
                    logger.debug("ElectrumX reader skipped non-dict message")
                    continue

                req_id = data.get("id")
                if not isinstance(req_id, int) or isinstance(req_id, bool):
                    # Server pushes (no id) or malformed — drop. Subscribed
                    # notifications are out of scope for this client.
                    #
                    # `isinstance(True, int)` is True and `hash(True) == hash(1)`, so a message
                    # carrying `"id": true` passed this check and then popped the future for
                    # request id **1** — the first RPC of every connection, which is the tip-height
                    # or genesis read `assert_chain` is built on. The bool exclusion is the same
                    # one `_guards.finite_int` makes for the same reason.
                    logger.debug("ElectrumX reader dropped message without int id")
                    continue

                fut = self._pending.pop(req_id, None)
                if fut is None or fut.done():
                    logger.debug("ElectrumX reader dropped orphan response id=%d", req_id)
                    continue

                if "error" in data and data["error"] is not None:
                    err = data["error"]
                    if isinstance(err, dict):
                        fut.set_exception(_rpc_error(err.get("code", "unknown"), err.get("message")))
                    else:
                        fut.set_exception(NetworkError("ElectrumX RPC error"))
                elif "result" in data:
                    fut.set_result(data["result"])
                else:
                    fut.set_exception(NetworkError("ElectrumX response missing 'result' field"))
        except asyncio.CancelledError:
            # close() asked us to stop — propagate so the awaiter knows.
            self._fail_all_pending(NetworkError("ElectrumX connection closed"))
            raise
        except (WebSocketException, OSError) as exc:
            logger.debug("ElectrumX reader loop ending: %s", exc)
            self._fail_all_pending(NetworkError("ElectrumX connection lost"))
        finally:
            # Ensure next _call triggers a fresh connect.
            self._ws = None

    async def _next_id(self) -> int:
        async with self._id_lock:
            self._id_counter += 1
            return self._id_counter

    async def _call(self, method: str, params: list[Any]) -> Any:
        """Send a JSON-RPC request and return the ``result`` field.

        Concurrency model
        -----------------
        Multiple ``_call`` coroutines may run concurrently. Each registers a
        future in ``self._pending`` keyed on its JSON-RPC id; the single
        reader task dispatches responses to the matching future. Sends are
        serialized through ``self._send_lock`` because ``websockets.send``
        is not safe to call concurrently from multiple tasks on the same
        connection.

        Failure handling
        ----------------
        On send failure, timeout, or disconnect, the corresponding future
        is removed and ``NetworkError`` is raised to the caller. The next
        ``_call`` reconnects lazily via ``_ensure_connected`` — there is no
        in-call retry. Callers that want retry semantics should layer it
        above ``_call``.

        Raw server responses are never embedded in exception messages.
        """
        await self._ensure_connected()
        req_id = await self._next_id()
        payload = json.dumps({"id": req_id, "method": method, "params": params})

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        self._pending[req_id] = fut

        try:
            try:
                async with self._send_lock:
                    if self._ws is None:
                        raise NetworkError("WebSocket connection is not available")
                    await asyncio.wait_for(self._ws.send(payload), timeout=self._timeout)
            except (WebSocketException, OSError) as exc:
                raise NetworkError("ElectrumX request failed (send error)") from exc
            except asyncio.TimeoutError:
                raise NetworkError("ElectrumX request timed out (send)") from None

            try:
                return await asyncio.wait_for(fut, timeout=self._timeout)
            except asyncio.TimeoutError:
                raise NetworkError("ElectrumX request timed out") from None
        finally:
            # Drop the pending entry whether we got a response, errored, or
            # timed out. If the reader has already popped it, this is a no-op.
            self._pending.pop(req_id, None)
