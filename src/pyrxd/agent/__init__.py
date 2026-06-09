"""pyrxd.agent — local sign-on-behalf signing agent (issue #8, Path A').

A daemon holds the unlocked wallet and signs transactions the CLI builds
*watch-only*; the key never leaves the agent. Reaching the agent lets a
caller *request* a signature (gated by per-spend confirmation), never
*take* the key.

This package is the in-process signing brain (:mod:`~pyrxd.agent.signer`)
plus its wire types (:mod:`~pyrxd.agent.protocol`). The Unix-socket
daemon and the CLI client are layered on top (later phases). It is NOT
the generalized ``Signer`` seam (that is the deferred Path B); the agent
simply wraps :class:`~pyrxd.hd.wallet.HdWallet`.

Security model: see docs/plans/2026-06-08-feat-cli-signing-agent-a-prime-plan.md
§ "Load-bearing safety properties". The signer independently verifies
each input's prevout (never trusts caller-claimed values), attributes
outputs (change re-derived and verified, the rest shown as external),
and requires confirmation before signing.
"""

from __future__ import annotations

from .client import AgentClient
from .confirm import TtyConfirmer, format_spend_summary
from .daemon import AgentDaemon
from .discover import WatchOnlyScan, collect_watch_only_utxos
from .errors import SignerDeclined, SignerError, SignerUnavailableError
from .protocol import ChangeClaim, ExternalOutput, InputToSign, SignedResult, SigningRequest, SpendSummary
from .signer import AgentSigner
from .watch_only import UnsignedSend, WatchOnlyTxBuilder, WatchOnlyUtxo

__all__ = [
    "AgentClient",
    "AgentDaemon",
    "AgentSigner",
    "ChangeClaim",
    "ExternalOutput",
    "InputToSign",
    "SignedResult",
    "SignerDeclined",
    "SignerError",
    "SignerUnavailableError",
    "SigningRequest",
    "SpendSummary",
    "TtyConfirmer",
    "UnsignedSend",
    "WatchOnlyScan",
    "WatchOnlyTxBuilder",
    "WatchOnlyUtxo",
    "collect_watch_only_utxos",
    "format_spend_summary",
]
