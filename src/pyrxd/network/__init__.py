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

__all__ = [
    "DEFAULT_CONFIRMATION_TIMEOUT_S",
    "DEFAULT_POLL_INTERVAL_S",
    "BitcoinCoreRpcSource",
    "BlockstreamSource",
    "BtcDataSource",
    "ChainTracker",
    "ElectrumXClient",
    "MempoolSpaceSource",
    "MultiSourceBtcDataSource",
    "MultiSourceBtcFundingReader",
    "choose_funding_reader",
    "wait_for_confirmation",
]
