"""Typed errors for the signing agent.

A typed taxonomy so the CLI fallback ladder branches on exception *type*,
not on string-matching messages (the design panel called this out). All
inherit the repo's error hierarchy.
"""

from __future__ import annotations

from ..security.errors import NetworkError, ValidationError


class SignerError(ValidationError):
    """A signing request was malformed, unauthorized, or failed validation."""


class SignerDeclined(SignerError):
    """The spend was declined at the confirmation gate (user said no)."""


class SignerUnavailableError(NetworkError):
    """The agent is not reachable (socket absent, locked, or down).

    A :class:`NetworkError` subclass so callers can fall back to the
    mnemonic prompt without conflating it with a validation failure.
    """
