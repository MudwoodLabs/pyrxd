"""A fresh DISTINCT HOST for a test fake that stands in for one source in a quorum.

Every quorum in pyrxd counts sources by ``source_key`` (see :mod:`pyrxd.network.source_identity`)
and refuses two sources on one host, so a fake that plays "another endpoint" has to BE another
host. The key is derived through the production function from a reserved ``.test`` name, never
typed as a bare label.
"""

from __future__ import annotations

import itertools

from pyrxd.network.source_identity import SourceKey, source_key

_COUNTER = itertools.count()


def distinct_host() -> SourceKey:
    """A host no other call in this process has returned."""
    return source_key(f"https://source-{next(_COUNTER)}.test/")
