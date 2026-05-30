"""Bitcoin / Radiant data source abstraction layer.

Provides an abstract base class ``BtcDataSource`` and concrete implementations:

* ``MempoolSpaceSource`` — mempool.space HTTP API
* ``BlockstreamSource`` — blockstream.info HTTP API
* ``BitcoinCoreRpcSource`` — Bitcoin Core JSON-RPC over HTTP
* ``MultiSourceBtcDataSource`` — quorum-based multi-source with agreement check

Security notes
--------------
* All URL construction uses ``urllib.parse`` — f-string interpolation with
  external inputs is never used.
* All txids are validated as ``Txid`` before use.
* HTTP responses are bounded to 10 MB to prevent memory exhaustion.
* Auth credentials in ``BitcoinCoreRpcSource`` are stored as ``SecretBytes``
  and never logged.
* Raw HTTP response bodies are never included in exception messages.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any
from urllib.parse import quote, urljoin

import aiohttp

from ..security.errors import InsufficientConfirmationsError, NetworkError, ValidationError
from ..security.secrets import SecretBytes
from ..security.types import BlockHeight, Hex32, RawTx, Txid

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB


# ─────────────────────────────────────────────── Abstract Base Class


class BtcDataSource(ABC):
    """Abstract interface for blockchain data providers."""

    @abstractmethod
    async def get_tip_height(self) -> BlockHeight:
        """Return the current chain tip block height."""

    @abstractmethod
    async def get_block_hash(self, height: BlockHeight) -> Hex32:
        """Return the 32-byte block hash at *height*."""

    @abstractmethod
    async def get_block_header_hex(self, height: BlockHeight) -> bytes:
        """Return the raw 80-byte block header at *height*."""

    @abstractmethod
    async def get_header_chain(self, start_height: BlockHeight, count: int) -> list[bytes]:
        """Return *count* consecutive 80-byte headers starting at *start_height*."""

    @abstractmethod
    async def get_raw_tx(self, txid: Txid, min_confirmations: int = 6) -> RawTx:
        """Return raw transaction bytes, enforcing *min_confirmations*."""

    @abstractmethod
    async def get_tx_output_script_type(self, txid: Txid, output_index: int) -> str:
        """Return the output script type: ``p2pkh``, ``p2wpkh``, ``p2sh``, ``p2tr``, or ``unknown``."""

    @abstractmethod
    async def get_tx_block_height(self, txid: Txid) -> BlockHeight:
        """Return the block height at which *txid* was confirmed.

        Raises ``NetworkError`` if the transaction is unconfirmed or not found.
        """

    @abstractmethod
    async def get_merkle_proof(self, txid: Txid, height: BlockHeight) -> tuple[list[str], int]:
        """Return ``(branch_hashes_hex, leaf_position)`` for *txid* at *height*."""

    @abstractmethod
    async def close(self) -> None:
        """Close any underlying connections held by this source."""

    async def __aenter__(self) -> BtcDataSource:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()


# ─────────────────────────────────────────────── shared HTTP helpers


def _safe_txid_path(txid: Txid) -> str:
    """Return a URL-safe txid path segment (validates input first)."""
    return quote(str(txid), safe="")


def _safe_int_path(value: int) -> str:
    """Return a URL-safe integer path segment."""
    return quote(str(int(value)), safe="")


async def _check_response_size(response: aiohttp.ClientResponse) -> bytes:
    """Read the response body, raising NetworkError if it exceeds 10 MB."""
    body = await response.read()
    if len(body) > _MAX_RESPONSE_BYTES:
        raise NetworkError("HTTP response exceeds maximum allowed size (10 MB)")
    return body


async def _get_json(session: aiohttp.ClientSession, url: str) -> Any:
    """GET *url*, parse JSON, enforce size limit, raise NetworkError on failure."""
    try:
        async with session.get(url) as resp:
            body = await _check_response_size(resp)
            if resp.status != 200:
                raise NetworkError(f"HTTP request failed with status {resp.status}")
            content_type = resp.content_type or ""
            if "json" not in content_type and "text" not in content_type:
                raise NetworkError(f"Unexpected Content-Type from server: {content_type}")
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                raise NetworkError("Server returned non-JSON response")
    except aiohttp.ClientError as exc:
        raise NetworkError("HTTP request failed") from exc


async def _get_hex_bytes(session: aiohttp.ClientSession, url: str, expected_len: int | None = None) -> bytes:
    """GET *url*, decode hex body, return raw bytes."""
    try:
        async with session.get(url) as resp:
            body = await _check_response_size(resp)
            if resp.status != 200:
                raise NetworkError(f"HTTP request failed with status {resp.status}")
            try:
                result = bytes.fromhex(body.decode("ascii").strip())
            except (ValueError, UnicodeDecodeError):
                raise NetworkError("Server returned invalid hex data")
            if expected_len is not None and len(result) != expected_len:
                raise NetworkError(f"Expected {expected_len} bytes, got {len(result)}")
            return result
    except aiohttp.ClientError as exc:
        raise NetworkError("HTTP request failed") from exc


# ─────────────────────────────────────────────── MempoolSpaceSource


class MempoolSpaceSource(BtcDataSource):
    """BtcDataSource backed by the mempool.space HTTP API.

    Parameters
    ----------
    base_url:
        Base URL of the API (default ``https://mempool.space/api``).
    """

    def __init__(self, base_url: str = "https://mempool.space/api") -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _url(self, *parts: str) -> str:
        """Build a URL by joining parts onto the base using urllib.parse."""
        result = self._base_url
        for part in parts:
            result = urljoin(result, part)
        return result

    async def get_tip_height(self) -> BlockHeight:
        session = await self._get_session()
        url = self._url("blocks/tip/height")
        try:
            async with session.get(url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching tip height")
                try:
                    return BlockHeight(int(body.strip()))
                except (ValueError, ValidationError):
                    raise NetworkError("Invalid tip height value from server")
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_block_hash(self, height: BlockHeight) -> Hex32:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        session = await self._get_session()
        url = self._url(f"block-height/{_safe_int_path(height)}")
        try:
            async with session.get(url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching block hash")
                try:
                    hash_hex = body.decode("ascii").strip()
                    return Hex32(bytes.fromhex(hash_hex))
                except (ValueError, UnicodeDecodeError, ValidationError):
                    raise NetworkError("Server returned invalid block hash")
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_block_header_hex(self, height: BlockHeight) -> bytes:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        # First get the block hash, then the header.
        block_hash = await self.get_block_hash(height)
        session = await self._get_session()
        url = self._url(f"block/{block_hash.hex()}/header")
        return await _get_hex_bytes(session, url, expected_len=80)

    async def get_header_chain(self, start_height: BlockHeight, count: int) -> list[bytes]:
        if not isinstance(start_height, BlockHeight):
            start_height = BlockHeight(start_height)
        if count <= 0:
            raise ValidationError("count must be a positive integer")
        headers: list[bytes] = []
        # Fetch headers one at a time (mempool.space doesn't have a batch endpoint).
        tasks = [self.get_block_header_hex(BlockHeight(int(start_height) + i)) for i in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                raise NetworkError("Failed to fetch header in chain") from res
            headers.append(res)  # type: ignore[arg-type]
        return headers

    async def get_raw_tx(self, txid: Txid, min_confirmations: int = 6) -> RawTx:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()

        # Fetch tx status to check confirmations.
        status_url = self._url(f"tx/{_safe_txid_path(txid)}/status")
        status = await _get_json(session, status_url)
        if not isinstance(status, dict):
            raise NetworkError("Unexpected tx status response")
        confirmed = status.get("confirmed", False)
        block_height = status.get("block_height")
        if not confirmed or block_height is None:
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)

        if min_confirmations > 0:
            # To check confirmations we need the tip height.
            tip = await self.get_tip_height()
            # Audit 2026-05-29 F-17: floor block_height to [1, tip]. A source that
            # under-reports block_height inflates confs (an unburied/reorgable tx
            # looks final); a height above tip is inconsistent. Reject either rather
            # than trust the arithmetic (mirrors MempoolSpaceFundingReader.confirmations).
            if int(block_height) < 1 or int(block_height) > int(tip):
                raise NetworkError(
                    f"inconsistent confirmation data: block_height={block_height}, tip={int(tip)} "
                    "(expected 1 <= block_height <= tip)"
                )
            confs = int(tip) - int(block_height) + 1
            if confs < min_confirmations:
                raise InsufficientConfirmationsError(have=confs, required=min_confirmations)

        # Fetch raw hex.
        hex_url = self._url(f"tx/{_safe_txid_path(txid)}/hex")
        try:
            async with session.get(hex_url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching raw tx")
                try:
                    raw = bytes.fromhex(body.decode("ascii").strip())
                except (ValueError, UnicodeDecodeError):
                    raise NetworkError("Server returned invalid hex for transaction")
                _verify_raw_matches_txid(raw, txid)
                return RawTx(raw)
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_tx_block_height(self, txid: Txid) -> BlockHeight:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()
        status_url = self._url(f"tx/{_safe_txid_path(txid)}/status")
        status = await _get_json(session, status_url)
        if not isinstance(status, dict):
            raise NetworkError("Unexpected tx status response")
        confirmed = status.get("confirmed", False)
        block_height = status.get("block_height")
        if not confirmed or block_height is None:
            raise NetworkError(f"tx {str(txid)[:16]}… is unconfirmed")
        try:
            return BlockHeight(int(block_height))
        except (TypeError, ValueError, ValidationError):
            raise NetworkError("Invalid block_height in tx status response")

    async def get_tx_output_script_type(self, txid: Txid, output_index: int) -> str:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()
        url = self._url(f"tx/{_safe_txid_path(txid)}")
        data = await _get_json(session, url)
        try:
            vout = data["vout"][output_index]
            script_type = vout.get("scriptpubkey_type", "unknown")
            # Map mempool.space types to canonical names.
            type_map = {
                "p2pkh": "p2pkh",
                "p2wpkh": "p2wpkh",
                "p2sh": "p2sh",
                "p2tr": "p2tr",
                "v0_p2wpkh": "p2wpkh",
                "v1_p2tr": "p2tr",
            }
            return type_map.get(script_type, "unknown")
        except (KeyError, IndexError, TypeError):
            raise NetworkError("Could not parse output script type from server response")

    async def get_merkle_proof(self, txid: Txid, height: BlockHeight) -> tuple[list[str], int]:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        session = await self._get_session()
        url = self._url(f"tx/{_safe_txid_path(txid)}/merkleblock-proof")
        data = await _get_json(session, url)
        try:
            merkle: list[str] = data["merkle"]
            pos: int = int(data["pos"])
            return merkle, pos
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed merkle proof response from server")


# ─────────────────────────────────────────────── BlockstreamSource


class BlockstreamSource(BtcDataSource):
    """BtcDataSource backed by the blockstream.info HTTP API."""

    def __init__(self, base_url: str = "https://blockstream.info/api") -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _url(self, *parts: str) -> str:
        result = self._base_url
        for part in parts:
            result = urljoin(result, part)
        return result

    async def get_tip_height(self) -> BlockHeight:
        session = await self._get_session()
        url = self._url("blocks/tip/height")
        try:
            async with session.get(url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching tip height")
                try:
                    return BlockHeight(int(body.strip()))
                except (ValueError, ValidationError):
                    raise NetworkError("Invalid tip height value from server")
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_block_hash(self, height: BlockHeight) -> Hex32:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        session = await self._get_session()
        url = self._url(f"block-height/{_safe_int_path(height)}")
        try:
            async with session.get(url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching block hash")
                try:
                    hash_hex = body.decode("ascii").strip()
                    return Hex32(bytes.fromhex(hash_hex))
                except (ValueError, UnicodeDecodeError, ValidationError):
                    raise NetworkError("Server returned invalid block hash")
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_block_header_hex(self, height: BlockHeight) -> bytes:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        block_hash = await self.get_block_hash(height)
        session = await self._get_session()
        url = self._url(f"block/{block_hash.hex()}/header")
        return await _get_hex_bytes(session, url, expected_len=80)

    async def get_header_chain(self, start_height: BlockHeight, count: int) -> list[bytes]:
        if not isinstance(start_height, BlockHeight):
            start_height = BlockHeight(start_height)
        if count <= 0:
            raise ValidationError("count must be a positive integer")
        tasks = [self.get_block_header_hex(BlockHeight(int(start_height) + i)) for i in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        headers: list[bytes] = []
        for res in results:
            if isinstance(res, Exception):
                raise NetworkError("Failed to fetch header in chain") from res
            headers.append(res)  # type: ignore[arg-type]
        return headers

    async def get_raw_tx(self, txid: Txid, min_confirmations: int = 6) -> RawTx:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()

        status_url = self._url(f"tx/{_safe_txid_path(txid)}/status")
        status = await _get_json(session, status_url)
        if not isinstance(status, dict):
            raise NetworkError("Unexpected tx status response")
        confirmed = status.get("confirmed", False)
        block_height = status.get("block_height")
        if not confirmed or block_height is None:
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)

        if min_confirmations > 0:
            tip = await self.get_tip_height()
            # Audit 2026-05-29 F-17: floor block_height to [1, tip] (see above).
            if int(block_height) < 1 or int(block_height) > int(tip):
                raise NetworkError(
                    f"inconsistent confirmation data: block_height={block_height}, tip={int(tip)} "
                    "(expected 1 <= block_height <= tip)"
                )
            confs = int(tip) - int(block_height) + 1
            if confs < min_confirmations:
                raise InsufficientConfirmationsError(have=confs, required=min_confirmations)

        hex_url = self._url(f"tx/{_safe_txid_path(txid)}/hex")
        try:
            async with session.get(hex_url) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching raw tx")
                try:
                    raw = bytes.fromhex(body.decode("ascii").strip())
                except (ValueError, UnicodeDecodeError):
                    raise NetworkError("Server returned invalid hex for transaction")
                _verify_raw_matches_txid(raw, txid)
                return RawTx(raw)
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request failed") from exc

    async def get_tx_block_height(self, txid: Txid) -> BlockHeight:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()
        status_url = self._url(f"tx/{_safe_txid_path(txid)}/status")
        status = await _get_json(session, status_url)
        if not isinstance(status, dict):
            raise NetworkError("Unexpected tx status response")
        confirmed = status.get("confirmed", False)
        block_height = status.get("block_height")
        if not confirmed or block_height is None:
            raise NetworkError(f"tx {str(txid)[:16]}… is unconfirmed")
        try:
            return BlockHeight(int(block_height))
        except (TypeError, ValueError, ValidationError):
            raise NetworkError("Invalid block_height in tx status response")

    async def get_tx_output_script_type(self, txid: Txid, output_index: int) -> str:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        session = await self._get_session()
        url = self._url(f"tx/{_safe_txid_path(txid)}")
        data = await _get_json(session, url)
        try:
            vout = data["vout"][output_index]
            script_type = vout.get("scriptpubkey_type", "unknown")
            type_map = {
                "p2pkh": "p2pkh",
                "p2wpkh": "p2wpkh",
                "p2sh": "p2sh",
                "p2tr": "p2tr",
                "v0_p2wpkh": "p2wpkh",
                "v1_p2tr": "p2tr",
            }
            return type_map.get(script_type, "unknown")
        except (KeyError, IndexError, TypeError):
            raise NetworkError("Could not parse output script type from server response")

    async def get_merkle_proof(self, txid: Txid, height: BlockHeight) -> tuple[list[str], int]:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        session = await self._get_session()
        url = self._url(f"tx/{_safe_txid_path(txid)}/merkle-proof")
        data = await _get_json(session, url)
        try:
            merkle: list[str] = data["merkle"]
            pos: int = int(data["pos"])
            return merkle, pos
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed merkle proof response from server")


# ─────────────────────────────────────────────── BitcoinCoreRpcSource


class BitcoinCoreRpcSource(BtcDataSource):
    """BtcDataSource backed by a Bitcoin Core JSON-RPC endpoint.

    Credentials are stored as ``SecretBytes`` and never logged.

    Parameters
    ----------
    url:
        RPC endpoint URL, e.g. ``http://localhost:8332/``.
    user:
        RPC username.
    password:
        RPC password (stored securely as SecretBytes).
    """

    def __init__(self, url: str, user: str, password: str) -> None:
        self._url = url
        self._user = user
        # Store password as SecretBytes to prevent accidental logging.
        self._password = SecretBytes(password.encode())
        self._session: aiohttp.ClientSession | None = None
        self._id_counter = 0

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            auth = aiohttp.BasicAuth(
                self._user,
                self._password.unsafe_raw_bytes().decode("utf-8"),
            )
            self._session = aiohttp.ClientSession(auth=auth)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _rpc(self, method: str, params: list) -> Any:
        """Execute a Bitcoin Core RPC call."""
        session = await self._get_session()
        self._id_counter += 1
        payload = {
            "jsonrpc": "1.1",
            "id": self._id_counter,
            "method": method,
            "params": params,
        }
        try:
            async with session.post(self._url, json=payload) as resp:
                body = await _check_response_size(resp)
                if resp.status not in (200, 500):
                    raise NetworkError(f"RPC HTTP error: {resp.status}")
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    raise NetworkError("Bitcoin Core returned non-JSON response")
                if data.get("error") is not None:
                    err = data["error"]
                    msg = err.get("message", "Unknown RPC error") if isinstance(err, dict) else "RPC error"
                    raise NetworkError(f"Bitcoin Core RPC error: {msg}")
                return data["result"]
        except aiohttp.ClientError as exc:
            raise NetworkError("HTTP request to Bitcoin Core failed") from exc

    async def get_tip_height(self) -> BlockHeight:
        result = await self._rpc("getblockcount", [])
        try:
            return BlockHeight(int(result))
        except (TypeError, ValueError, ValidationError):
            raise NetworkError("Invalid block count from Bitcoin Core")

    async def get_block_hash(self, height: BlockHeight) -> Hex32:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        result = await self._rpc("getblockhash", [int(height)])
        if not isinstance(result, str):
            raise NetworkError("Unexpected block hash response from Bitcoin Core")
        try:
            return Hex32(bytes.fromhex(result))
        except (ValueError, ValidationError):
            raise NetworkError("Invalid block hash from Bitcoin Core")

    async def get_block_header_hex(self, height: BlockHeight) -> bytes:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        block_hash = await self.get_block_hash(height)
        # verbose=False returns hex string
        result = await self._rpc("getblockheader", [block_hash.hex(), False])
        if not isinstance(result, str):
            raise NetworkError("Unexpected block header response from Bitcoin Core")
        try:
            header = bytes.fromhex(result)
        except ValueError:
            raise NetworkError("Invalid block header hex from Bitcoin Core")
        if len(header) != 80:
            raise NetworkError(f"Block header must be 80 bytes, got {len(header)}")
        return header

    async def get_header_chain(self, start_height: BlockHeight, count: int) -> list[bytes]:
        if not isinstance(start_height, BlockHeight):
            start_height = BlockHeight(start_height)
        if count <= 0:
            raise ValidationError("count must be a positive integer")
        tasks = [self.get_block_header_hex(BlockHeight(int(start_height) + i)) for i in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        headers: list[bytes] = []
        for res in results:
            if isinstance(res, Exception):
                raise NetworkError("Failed to fetch header in chain") from res
            headers.append(res)  # type: ignore[arg-type]
        return headers

    async def get_raw_tx(self, txid: Txid, min_confirmations: int = 6) -> RawTx:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        # getrawtransaction with verbose=True for confirmation count.
        data = await self._rpc("getrawtransaction", [str(txid), True])
        if not isinstance(data, dict):
            raise NetworkError("Unexpected raw tx response from Bitcoin Core")
        confs = data.get("confirmations", 0)
        if confs < min_confirmations:
            raise InsufficientConfirmationsError(have=int(confs), required=min_confirmations)
        hex_str = data.get("hex", "")
        if not isinstance(hex_str, str):
            raise NetworkError("Missing hex field in raw tx response")
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            raise NetworkError("Invalid hex in raw tx response from Bitcoin Core")
        _verify_raw_matches_txid(raw, txid)
        return RawTx(raw)

    async def get_tx_block_height(self, txid: Txid) -> BlockHeight:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        data = await self._rpc("getrawtransaction", [str(txid), True])
        if not isinstance(data, dict):
            raise NetworkError("Unexpected raw tx response from Bitcoin Core")
        block_height = data.get("blockheight")
        if block_height is None:
            raise NetworkError(f"tx {str(txid)[:16]}… is unconfirmed or blockheight missing")
        try:
            return BlockHeight(int(block_height))
        except (TypeError, ValueError, ValidationError):
            raise NetworkError("Invalid blockheight in getrawtransaction response")

    async def get_tx_output_script_type(self, txid: Txid, output_index: int) -> str:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        data = await self._rpc("getrawtransaction", [str(txid), True])
        try:
            vout = data["vout"][output_index]
            script_type = vout["scriptPubKey"].get("type", "unknown")
            type_map = {
                "pubkeyhash": "p2pkh",
                "scripthash": "p2sh",
                "witness_v0_keyhash": "p2wpkh",
                "witness_v1_taproot": "p2tr",
            }
            return type_map.get(script_type, "unknown")
        except (KeyError, IndexError, TypeError):
            raise NetworkError("Could not parse output script type from Bitcoin Core response")

    async def get_merkle_proof(self, txid: Txid, height: BlockHeight) -> tuple[list[str], int]:
        # gettxoutproof returns a hex-encoded merkle block; parsing it fully is
        # out of scope here.  Return a stub that raises unless overridden.
        raise NetworkError(
            "get_merkle_proof is not directly available via Bitcoin Core RPC "
            "in this implementation — use a dedicated indexer or electrumx source."
        )


# ─────────────────────────────────────────────── MultiSourceBtcDataSource


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _verify_raw_matches_txid(raw: bytes, txid: Txid) -> None:
    """Bind server-returned tx bytes to the REQUESTED txid (fail-closed) — F-004.

    A source (or a MITM'd endpoint) can return a *different* transaction than the
    one asked for — e.g. a same-preimage claim with a different txid that happens to
    be buried deeper — and the reorg/claim path would then measure the wrong tx's
    depth, firing an irreversible asset claim off a still-reorgable BTC claim. We
    recompute the txid locally from the returned bytes (witness-stripped, the same
    derivation the BTC leg already trusts) and reject any mismatch.
    """
    from pyrxd.btc_wallet.taproot import btc_txid_from_raw

    try:
        derived = btc_txid_from_raw(bytes(raw))
    except Exception as exc:
        raise NetworkError("could not derive a txid from the returned tx bytes; fail-closed") from exc
    if derived.lower() != str(txid).lower():
        raise NetworkError(f"returned tx bytes do not match the requested txid {str(txid)[:16]}…; fail-closed")


class MultiSourceBtcDataSource(BtcDataSource):
    """A quorum-based composite data source.

    For read operations, all sources are queried concurrently and the result is
    returned only if at least *quorum* sources agree.  For broadcast-style
    operations, sources are tried in order until one succeeds.

    Parameters
    ----------
    sources:
        Two or more ``BtcDataSource`` instances.
    quorum:
        Minimum number of agreeing sources required (default 2).
    """

    def __init__(self, sources: list[BtcDataSource], quorum: int = 2) -> None:
        if not sources:
            raise ValidationError("MultiSourceBtcDataSource requires at least one source")
        self._sources = sources
        self._quorum = quorum

    async def close(self) -> None:
        """Close all underlying sources."""
        for source in self._sources:
            await source.close()

    def _check_quorum_possible(self) -> None:
        if len(self._sources) < self._quorum:
            raise NetworkError(f"Not enough sources: have {len(self._sources)}, need quorum {self._quorum}")

    async def _gather_results(self, coro_factory) -> list[Any]:
        """Run coro_factory(source) for all sources concurrently."""
        tasks = [coro_factory(source) for source in self._sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return list(results)

    def _require_quorum(self, results: list[Any], key_fn) -> Any:
        """Return value agreed on by ≥ quorum sources; raise NetworkError otherwise."""
        counts: dict = {}
        for r in results:
            if isinstance(r, Exception):
                continue
            k = key_fn(r)
            counts[k] = [*counts.get(k, []), r]

        for group in counts.values():
            if len(group) >= self._quorum:
                return group[0]

        successful = sum(1 for r in results if not isinstance(r, Exception))
        raise NetworkError(
            f"Source quorum not reached: {successful}/{len(self._sources)} sources responded, quorum is {self._quorum}"
        )

    async def get_tip_height(self) -> BlockHeight:
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_tip_height())
        return self._require_quorum(results, int)

    async def get_block_hash(self, height: BlockHeight) -> Hex32:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_block_hash(height))
        return self._require_quorum(results, bytes)

    async def get_block_header_hex(self, height: BlockHeight) -> bytes:
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_block_header_hex(height))
        return self._require_quorum(results, lambda h: h)

    async def get_header_chain(self, start_height: BlockHeight, count: int) -> list[bytes]:
        if not isinstance(start_height, BlockHeight):
            start_height = BlockHeight(start_height)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_header_chain(start_height, count))

        # Agreement check: compare concatenated bytes.
        def chain_key(chain: list[bytes]) -> bytes:
            return b"".join(chain)

        return self._require_quorum(results, chain_key)

    async def get_raw_tx(self, txid: Txid, min_confirmations: int = 6) -> RawTx:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_raw_tx(txid, min_confirmations))
        # Agreement: compare hash256 of the raw bytes.
        agreed = self._require_quorum(results, lambda tx: _hash256(bytes(tx)))
        # F-004: even with quorum agreement, bind the agreed bytes to the requested txid.
        _verify_raw_matches_txid(bytes(agreed), txid)
        return agreed

    async def get_tx_block_height(self, txid: Txid) -> BlockHeight:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_tx_block_height(txid))
        return self._require_quorum(results, int)

    async def get_tx_output_script_type(self, txid: Txid, output_index: int) -> str:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_tx_output_script_type(txid, output_index))
        return self._require_quorum(results, lambda t: t)

    async def get_merkle_proof(self, txid: Txid, height: BlockHeight) -> tuple[list[str], int]:
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        self._check_quorum_possible()
        results = await self._gather_results(lambda s: s.get_merkle_proof(txid, height))
        return self._require_quorum(results, lambda r: (tuple(r[0]), r[1]))


# ─────────────────────────────────────────── mempool.space value-moving adapters
#
# The HTLC BtcLeg injects a BtcBroadcaster (POST /api/tx) and a BtcFundingReader
# (read confs/amount). On mainnet there is no Bitcoin node — mempool.space HTTP is
# the proven path. These satisfy the leg's duck-typed Protocols (htlc_leg.py).
# Broadcast is kept OFF the read-only BtcDataSource ABC (a deliberate split): these
# are the value-moving edge and get their own auditable classes.
#
# DECISION (dust-mainnet plan, panel): a single mempool.space endpoint reporting a
# false confirmation depth DEFEATS the reorg gate. For dust this is accepted with an
# explicit SPOF acknowledgement + operator corroboration; for any above-dust value the
# conf reader MUST be backed by a multi-source quorum. The reader below is the
# single-source dust adapter; it is fail-closed (unknown/unconfirmed => 0 => raise),
# never "assume confirmed".


class _MempoolHttpClient:
    """Shared HTTP plumbing for the mempool.space value-moving adapters.

    A thin session + URL helper mirroring MempoolSpaceSource, so the broadcaster and
    funding reader don't each re-implement it. TLS validation stays on (aiohttp
    default) — do NOT disable it; a MITM'd endpoint defeats the reorg gate.

    Sessions carry an EXPLICIT total request timeout. Without one, aiohttp's default
    is "no timeout" — a stalled mempool.space endpoint can hang a request indefinitely,
    blowing through the resume_deadline check at the loop top by minutes per call.
    30s is conservative for the small JSON / hex blobs the adapters fetch.
    (Red-team finding NEW #7 on 44707a3.)
    """

    DEFAULT_TIMEOUT_S: float = 30.0

    def __init__(self, base_url: str = "https://mempool.space/api", *, timeout_s: float | None = None) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._session: aiohttp.ClientSession | None = None
        self._timeout_s = self.DEFAULT_TIMEOUT_S if timeout_s is None else float(timeout_s)

    async def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._timeout_s))
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def url(self, *parts: str) -> str:
        result = self._base_url
        for part in parts:
            result = urljoin(result, part)
        return result

    async def tip_height(self) -> int:
        s = await self.session()
        try:
            async with s.get(self.url("blocks/tip/height")) as resp:
                body = await _check_response_size(resp)
                if resp.status != 200:
                    raise NetworkError(f"HTTP {resp.status} fetching tip height")
                return int(body.strip())
        except (aiohttp.ClientError, ValueError) as exc:
            raise NetworkError("could not fetch tip height") from exc

    async def tx_status(self, txid: Txid) -> dict:
        """``/tx/{txid}/status`` -> dict (confirmed, block_height) or fail-closed."""
        s = await self.session()
        status = await _get_json(s, self.url(f"tx/{_safe_txid_path(txid)}/status"))
        if not isinstance(status, dict):
            raise NetworkError("unexpected tx status response")
        return status

    async def tx_json(self, txid: Txid) -> dict:
        s = await self.session()
        data = await _get_json(s, self.url(f"tx/{_safe_txid_path(txid)}"))
        if not isinstance(data, dict):
            raise NetworkError("unexpected tx json response")
        return data


class MempoolSpaceBroadcaster:
    """``BtcBroadcaster`` over mempool.space ``POST /api/tx`` (the value-moving edge).

    Idempotent: a node that already has the tx ("already in mempool" / "txn-already-
    known" / "already in block chain") is SUCCESS — the txid is derived LOCALLY from
    the raw bytes (no node decode on mainnet), consistent with the reorg gate's
    serialize-don't-trust discipline. Any other error is a fail-closed ``NetworkError``.
    """

    def __init__(
        self, client: _MempoolHttpClient | None = None, *, base_url: str = "https://mempool.space/api"
    ) -> None:
        self._http = client or _MempoolHttpClient(base_url)

    async def broadcast(self, raw_tx: bytes) -> str:
        from ..btc_wallet.taproot import btc_txid_from_raw

        if not isinstance(raw_tx, (bytes, bytearray)) or len(raw_tx) == 0:
            raise ValidationError("raw_tx must be non-empty bytes")
        raw = bytes(raw_tx)
        s = await self._http.session()
        try:
            async with s.post(self._http.url("tx"), data=raw.hex()) as resp:
                body = (await _check_response_size(resp)).decode("ascii", "replace").strip()
                if resp.status == 200:
                    # mempool.space returns the txid as the body on success.
                    try:
                        return str(Txid(body))
                    except ValidationError:
                        raise NetworkError("broadcast returned a non-txid body")
                low = body.lower()
                if any(m in low for m in ("already", "txn-already-known", "in block chain", "in mempool")):
                    # Idempotent success — derive the txid locally (no node on mainnet).
                    return btc_txid_from_raw(raw)
                raise NetworkError(f"broadcast rejected (HTTP {resp.status})")
        except aiohttp.ClientError as exc:
            raise NetworkError("broadcast HTTP request failed") from exc

    async def close(self) -> None:
        """Release the shared HTTP client. Idempotent; mirrors :meth:`MempoolSpaceFundingReader.close`.

        Without this method every caller had to reach into ``_http`` directly to clean
        up — flagged by the post-cbd5fc0 review as a library-API gap that leaked
        through scripts.
        """
        await self._http.close()


class MempoolSpaceFundingReader:
    """``BtcFundingReader`` over mempool.space (single-source; fail-closed).

    Satisfies the leg's reader Protocol: ``read_output_amount_sats`` (funding read-back,
    D4), ``confirmations`` (the reorg gate's depth oracle — SPOF for dust, see module
    note), and ``txid_of`` (local, node-free; the gate derives its own txid but the
    Protocol method exists for non-gate callers). EVERY uncertain outcome reads 0/raises
    — never "assume confirmed".
    """

    def __init__(
        self, client: _MempoolHttpClient | None = None, *, base_url: str = "https://mempool.space/api"
    ) -> None:
        self._http = client or _MempoolHttpClient(base_url)

    async def confirmations(self, txid: str) -> int:
        tx = txid if isinstance(txid, Txid) else Txid(txid)
        status = await self._http.tx_status(tx)
        if not status.get("confirmed", False) or status.get("block_height") is None:
            return 0  # unconfirmed / unknown -> 0 (the gate's >= N check fails closed)
        tip = await self._http.tip_height()
        block_height = int(status["block_height"])
        # F-005: internal consistency check. A tx cannot be in a block above the tip, and
        # a real confirmed tx sits at height >= 1. An inverted/garbage response is a
        # confused or lying source — fail-closed LOUD (raise) rather than silently
        # computing a depth from it. NOTE: over-reporting via a plausible-but-false LOW
        # height is NOT detectable from a single source; above-dust value MUST corroborate
        # across independent sources / SPV header burial (see the module DECISION note).
        if block_height < 1 or block_height > int(tip):
            raise NetworkError(
                f"inconsistent confirmation data for {str(tx)[:16]}…: block_height={block_height}, tip={int(tip)}; "
                "fail-closed"
            )
        confs = int(tip) - block_height + 1
        return confs if confs > 0 else 0

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        tx = txid if isinstance(txid, Txid) else Txid(txid)
        confs = await self.confirmations(tx)
        if confs < min_confirmations:
            raise InsufficientConfirmationsError(have=confs, required=min_confirmations)
        data = await self._http.tx_json(tx)
        try:
            return int(data["vout"][vout]["value"])  # mempool.space vout value is in sats
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise NetworkError(f"could not read output value for {str(tx)[:16]}…:{vout}") from exc

    async def txid_of(self, raw_tx: bytes) -> str:
        from ..btc_wallet.taproot import btc_txid_from_raw

        return btc_txid_from_raw(bytes(raw_tx))

    async def list_address_utxos(self, address: str) -> list[dict]:
        """``/address/{addr}/utxo`` -> [{txid, vout, value_sats, confirmed, height}].

        The operator uses this (no node on mainnet) to find the funding UTXO to hand the
        BtcLeg. Returns confirmed+unconfirmed; the caller filters/conf-gates as needed.
        """
        if not isinstance(address, str) or not address:
            raise ValidationError("address must be a non-empty string")
        s = await self._http.session()
        data = await _get_json(s, self._http.url(f"address/{quote(address, safe='')}/utxo"))
        if not isinstance(data, list):
            raise NetworkError("unexpected address utxo response")
        out: list[dict] = []
        for u in data:
            try:
                st = u.get("status", {}) if isinstance(u, dict) else {}
                out.append(
                    {
                        "txid": str(Txid(u["txid"])),
                        "vout": int(u["vout"]),
                        "value_sats": int(u["value"]),
                        "confirmed": bool(st.get("confirmed", False)),
                        "height": int(st["block_height"]) if st.get("block_height") is not None else None,
                    }
                )
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                raise NetworkError("malformed address utxo entry") from exc
        return out

    async def close(self) -> None:
        await self._http.close()


class MultiSourceBtcFundingReader:
    """Quorum ``BtcFundingReader`` over N independent Esplora-style providers.

    Audit 2026-05-29 F-17: mitigates the single-source confirmation-depth SPOF — a
    lone compromised/MITM'd source that OVER-reports depth (under-reports
    ``block_height``) can make an unburied/reorgable tx look final and trigger a
    premature release.

    Operator policy (decided 2026-05-29):
      * ``quorum`` = 2 of 3 providers (majority): tolerates one source down or lying.
      * ``dust_cap_sats`` = 10_000: at/below the cap a single successful read is
        accepted (the documented dust posture); ABOVE it the quorum is REQUIRED
        (fail-closed).
      * :meth:`confirmations` returns the MINIMUM depth across responding sources — a
        tx is only as buried as the most-pessimistic source, defeating an over-reporter.
      * :meth:`read_output_amount_sats` requires >= ``quorum`` sources to agree on the
        EXACT amount (a deterministic value; disagreement fails closed).

    Satisfies the same duck-typed reader Protocol as :class:`MempoolSpaceFundingReader`,
    so it is a drop-in for the reorg gate / funding read-back on above-dust swaps. A
    failing source is simply dropped from the quorum (never fails the whole read).
    """

    #: Default independent mainnet Esplora endpoints (distinct operators).
    DEFAULT_MAINNET_ENDPOINTS = (
        "https://mempool.space/api",
        "https://blockstream.info/api",
        "https://mempool.emzy.de/api",
    )

    def __init__(self, readers: list, *, quorum: int = 2, dust_cap_sats: int = 10_000) -> None:
        readers = list(readers)
        if quorum < 1:
            raise ValidationError("quorum must be >= 1")
        if len(readers) < quorum:
            raise ValidationError(f"need at least quorum={quorum} readers, got {len(readers)}")
        if dust_cap_sats < 0:
            raise ValidationError("dust_cap_sats must be >= 0")
        self._readers = readers
        self._quorum = quorum
        self._dust_cap_sats = dust_cap_sats

    @classmethod
    def default_mainnet(cls, *, quorum: int = 2, dust_cap_sats: int = 10_000) -> MultiSourceBtcFundingReader:
        """Wire the three default independent mainnet Esplora endpoints (2-of-3)."""
        readers = [MempoolSpaceFundingReader(base_url=u) for u in cls.DEFAULT_MAINNET_ENDPOINTS]
        return cls(readers, quorum=quorum, dust_cap_sats=dust_cap_sats)

    async def _gather(self, coro_fn) -> list:
        """Run ``coro_fn`` on every reader; return only the successful (non-Exception)
        results. A failing source is dropped — it never fails the whole read."""
        results = await asyncio.gather(*(coro_fn(r) for r in self._readers), return_exceptions=True)
        return [x for x in results if not isinstance(x, Exception)]

    async def confirmations(self, txid: str, *, value_sats: int | None = None) -> int:
        """Quorum'd confirmation depth, returning the conservative MINIMUM.

        ``value_sats`` selects the dust gate: ``None`` (the default, used by the
        reorg gate) or any value above ``dust_cap_sats`` REQUIRES the quorum and
        fails closed otherwise; a value at/below the cap accepts a single source.
        """
        oks = [int(c) for c in await self._gather(lambda r: r.confirmations(txid))]
        require_quorum = value_sats is None or int(value_sats) > self._dust_cap_sats
        if require_quorum and len(oks) < self._quorum:
            raise NetworkError(
                f"confirmation depth corroborated by only {len(oks)} source(s); above-dust reads "
                f"require quorum={self._quorum} of {len(self._readers)} (F-17). Fail-closed."
            )
        if not oks:
            return 0  # below-dust, no source responded -> 0 (the gate's >= N check fails closed)
        return min(oks)  # a tx is only as buried as the most-pessimistic source

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        """Quorum'd output-amount read-back. Above the dust cap the exact amount must
        be corroborated by >= ``quorum`` sources; the conf depth is quorum'd separately."""
        # Read amounts WITHOUT each reader's own conf gate (min_confirmations=0); a
        # single quorum'd conf check is applied below.
        amounts = [
            int(a) for a in await self._gather(lambda r: r.read_output_amount_sats(txid, vout, min_confirmations=0))
        ]
        if not amounts:
            raise NetworkError("no source returned the output amount (F-17 fail-closed)")
        agreed, count = Counter(amounts).most_common(1)[0]
        if agreed > self._dust_cap_sats and count < self._quorum:
            raise NetworkError(
                f"above-dust output amount {agreed} sats corroborated by only {count} source(s); "
                f"need quorum={self._quorum} (sources disagree). Fail-closed."
            )
        confs = await self.confirmations(txid, value_sats=agreed)
        if confs < min_confirmations:
            raise InsufficientConfirmationsError(have=confs, required=min_confirmations)
        return agreed

    async def txid_of(self, raw_tx: bytes) -> str:
        from ..btc_wallet.taproot import btc_txid_from_raw

        return btc_txid_from_raw(bytes(raw_tx))

    async def list_address_utxos(self, address: str) -> list[dict]:
        """UTXO discovery (not a value gate): return the first source that responds."""
        for r in self._readers:
            try:
                return await r.list_address_utxos(address)
            except NetworkError:
                continue
        raise NetworkError("no source returned address utxos")

    async def close(self) -> None:
        await asyncio.gather(*(r.close() for r in self._readers if hasattr(r, "close")), return_exceptions=True)
