"""Did the preimage leave this process? Recorded, not inferred from an exception class.

``SwapCoordinator.maker_claims_btc`` must decide whether to zeroize the preimage after a failed
claim. Destroying a secret that is still secret strands a swap a retry would have completed
(#479); keeping one that is already public buys nothing. The decision hinges on a single fact —
did anything carrying ``p`` leave this process — and that fact was being inferred from the TYPE of
the exception:

    except PreRevealAbort: raise              # nothing sent, keep p
    except BaseException:  zeroize(); raise   # may be public, discard

``asyncio.CancelledError`` is a ``BaseException``, so the legs' ``except Exception`` wrappers
correctly do not catch it, and it lands in the second branch. Cancelled during the PRE-BROADCAST
reads, nothing was sent, ``p`` was still secret, and it is destroyed anyway — #479 arriving
through the cancel channel instead of the error channel (#480).

Exception taxonomy cannot express this. Cancellation carries no such information, and a check
added later on the wrong side of the boundary silently gets it wrong with no test able to see it.
So the leg RECORDS the crossing instead.

THREE STATES, BECAUSE TWO CANNOT BE SAFE AT ONCE
------------------------------------------------
A boolean forces one default onto two different situations, and they need opposite ones:

* a leg that does not participate at all (a fake, or a leg not yet wired) must be assumed to have
  revealed — anything else keeps a possibly-public secret;
* a participating leg that aborted before the send must be assumed NOT to have revealed — anything
  else destroys a still-secret preimage, which is the bug being fixed.

So :class:`RevealBoundary` starts UNWATCHED, the leg calls :func:`watching_for_reveal` on entry to
say "I report this", and :func:`mark_reveal_crossed` immediately before the first operation that
can carry ``p`` off the box. ``may_be_public`` is then True for UNWATCHED and CROSSED, False only
for a leg that explicitly said it got nowhere.

Task-local via :class:`~contextvars.ContextVar`, so concurrent swaps cannot see each other's
boundary and no signature changes ripple through the leg port and its fakes.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

__all__ = [
    "RevealBoundary",
    "RevealState",
    "mark_reveal_crossed",
    "reveal_boundary",
    "watching_for_reveal",
]


class RevealState(enum.Enum):
    """Where a claim got to, from the preimage's point of view."""

    #: No leg reported. Assume the worst: it may have sent something.
    UNWATCHED = "unwatched"
    #: A participating leg is running and has not reached the send.
    NOT_CROSSED = "not_crossed"
    #: Something carrying ``p`` has left, or may have left, this process.
    CROSSED = "crossed"


@dataclass
class RevealBoundary:
    """Mutable record of whether ``p`` can still be treated as secret."""

    state: RevealState = field(default=RevealState.UNWATCHED)

    @property
    def may_be_public(self) -> bool:
        """True unless a participating leg explicitly reported it never reached the send.

        Note the asymmetry: this is the SAFE direction. Being wrong here costs a swap; being
        wrong the other way leaks the reasoning that keeps a public secret in memory.
        """
        return self.state is not RevealState.NOT_CROSSED

    def watch(self) -> None:
        """A leg declares it will report this boundary. Idempotent, and never un-crosses."""
        if self.state is RevealState.UNWATCHED:
            self.state = RevealState.NOT_CROSSED

    def cross(self) -> None:
        """Something carrying ``p`` is about to leave. One-way."""
        self.state = RevealState.CROSSED


_BOUNDARY: ContextVar[RevealBoundary | None] = ContextVar("pyrxd_reveal_boundary", default=None)


@contextmanager
def reveal_boundary() -> Iterator[RevealBoundary]:
    """Install a fresh boundary for the duration of one claim. Used by the caller that owns ``p``."""
    boundary = RevealBoundary()
    token = _BOUNDARY.set(boundary)
    try:
        yield boundary
    finally:
        _BOUNDARY.reset(token)


def watching_for_reveal() -> None:
    """Called by a leg at the start of a claim: "I report my own reveal boundary."

    A no-op when no boundary is installed, so a leg can be driven directly in a test or by an
    embedder without one.
    """
    boundary = _BOUNDARY.get()
    if boundary is not None:
        boundary.watch()


def mark_reveal_crossed() -> None:
    """Called by a leg immediately before the first operation that can carry ``p`` off the box.

    Place this at the boundary itself, not at the top of the send helper: on the public path the
    preflight ``eth_call`` carries the calldata to a provider, so the crossing happens there and
    not at the broadcast.
    """
    boundary = _BOUNDARY.get()
    if boundary is not None:
        boundary.cross()
