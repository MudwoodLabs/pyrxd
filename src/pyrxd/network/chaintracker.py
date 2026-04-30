"""ChainTracker — verifies Merkle inclusion proofs against block headers.

Usage
-----
    source = MempoolSpaceSource()
    tracker = ChainTracker(source)
    valid = await tracker.is_valid_root(merkle_root_bytes, block_height)
"""

from __future__ import annotations

from ..security.types import BlockHeight, Hex32
from .bitcoin import BtcDataSource


class ChainTracker:
    """Verifies Merkle inclusion proofs against confirmed block headers.

    Bitcoin block header layout (80 bytes, all fields little-endian):
      - version      :  4 bytes  [0:4]
      - prev_hash    : 32 bytes  [4:36]
      - merkle_root  : 32 bytes  [36:68]  ← compared here
      - time         :  4 bytes  [68:72]
      - bits         :  4 bytes  [72:76]
      - nonce        :  4 bytes  [76:80]

    The ``merkle_root`` in the header is stored in little-endian byte order,
    matching the convention used by ``MerklePath.compute_root()``.
    """

    def __init__(self, btc_source: BtcDataSource) -> None:
        self._source = btc_source

    async def is_valid_root(
        self,
        merkle_root: Hex32,
        height: BlockHeight,
    ) -> bool:
        """Fetch the block header at *height* and check its Merkle root.

        Parameters
        ----------
        merkle_root:
            The 32-byte Merkle root to verify (as ``Hex32``).
        height:
            Block height of the header to check against.

        Returns
        -------
        bool
            ``True`` if the header's Merkle root matches *merkle_root*.
        """
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        if not isinstance(merkle_root, Hex32):
            merkle_root = Hex32(merkle_root)

        header = await self._source.get_block_header_hex(height)
        # Merkle root occupies bytes 36–68 (little-endian, 32 bytes).
        extracted_root = header[36:68]
        return extracted_root == bytes(merkle_root)

    async def is_valid_root_for_height(
        self,
        root_hex: str,
        height: int,
    ) -> bool:
        """Convenience wrapper accepting hex string root and plain int height.

        This matches the signature expected by ``MerklePath.verify()``.

        Parameters
        ----------
        root_hex:
            64-char lowercase hex string (big-endian display order, as returned
            by ``MerklePath.compute_root()``).
        height:
            Block height as a plain ``int``.

        Returns
        -------
        bool
        """
        # ``compute_root()`` returns display-order (reversed) hex.
        # We must reverse to get the little-endian bytes stored in the header.
        root_bytes = bytes.fromhex(root_hex)[::-1]
        return await self.is_valid_root(
            Hex32(root_bytes),
            BlockHeight(height),
        )
