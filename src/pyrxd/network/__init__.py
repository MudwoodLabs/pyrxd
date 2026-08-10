"""pyrxd.network — network layer for Radiant / Bitcoin SPV.

Re-exports the public surface of the sub-modules so callers can do:

    from pyrxd.network import ElectrumXClient, ChainTracker, ...
"""

from __future__ import annotations

from .bitcoin import (
    BitcoinCoreRpcSource,
    BlockstreamSource,
    BtcDataSource,
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
    MultiSourceBtcFundingReader,
    choose_funding_reader,
)
from .chaintracker import ChainTracker
from .confirm import (
    DEFAULT_CONFIRMATION_TIMEOUT_S,
    DEFAULT_POLL_INTERVAL_S,
    wait_for_confirmation,
)
from .electrumx import ElectrumXClient
from .failover import FailoverElectrumXClient
from .registry import (
    DEFAULT_ENDPOINTS,
    GENESIS_BLOCK_HASHES,
    KNOWN_NETWORKS,
    Endpoint,
    NetworkProfile,
    block_hash_hex,
    default_endpoints,
    genesis_hash_for,
)

__all__ = [
    "DEFAULT_CONFIRMATION_TIMEOUT_S",
    "DEFAULT_ENDPOINTS",
    "DEFAULT_POLL_INTERVAL_S",
    "GENESIS_BLOCK_HASHES",
    "KNOWN_NETWORKS",
    "BitcoinCoreRpcSource",
    "BlockstreamSource",
    "BtcDataSource",
    "ChainTracker",
    "ElectrumXClient",
    "Endpoint",
    "FailoverElectrumXClient",
    "MempoolSpaceSource",
    "MultiSourceBtcDataSource",
    "MultiSourceBtcFundingReader",
    "NetworkProfile",
    "block_hash_hex",
    "choose_funding_reader",
    "default_endpoints",
    "genesis_hash_for",
    "wait_for_confirmation",
]
