"""Per-network ElectrumX endpoint registry and chain-binding constants.

Why this module exists
----------------------
An ElectrumX URL is meaningless on its own: the same client code talking to
``wss://electrumx.radiant4people.com:50022/`` is on **mainnet**, and talking to
``ws://127.0.0.1:50022/`` is (probably) on regtest. Nothing in the URL says so.
Before this module, ``pyrxd --network regtest`` carried the *mainnet* default
endpoint forward and reported itself as regtest — a developer "testing on
regtest" could broadcast a real transaction to mainnet.

Two things fix that, and both live here:

1. **Per-network endpoint defaults** (:data:`DEFAULT_ENDPOINTS`). A network with
   no shipped default has an EMPTY tuple, not mainnet's. Callers that find no
   endpoint must fail closed and say what to configure — they must never fall
   back across networks.
2. **A declared genesis hash per network** (:data:`GENESIS_BLOCK_HASHES`), so the
   binding can be *verified* against the server rather than merely asserted.
   :meth:`pyrxd.network.electrumx.ElectrumXClient.assert_chain` reads block 0
   from the server and compares.

Provenance of the genesis hashes
--------------------------------
Every value below was checked twice, from independent sources:

* ``Radiant-Core`` @ tag ``v3.1.2`` (the pin in
  ``tests/vendor/radiant_core/MANIFEST.json``), ``src/chainparams.cpp`` — the
  ``assert(consensus.hashGenesisBlock == uint256S(...))`` in each chainparams
  class: ``CMainParams`` (:182-185), ``CTestNetParams`` (:308-311),
  ``CRegTestParams`` (:508-511). (Re-checked at v3.1.2; the values are unchanged
  from v3.0.0 but the line numbers moved.)
* A live node. mainnet: ``radiant-cli getblockhash 0`` against the reference
  mainnet node (Radiant Core 3.1.2). testnet + regtest: ``radiant-cli
  -testnet/-regtest getblockhash 0`` against a local ``radiant-core:v3.1.1``
  container. All three matched the source constants (checked 2026-08-10).

``CScaleNetParams`` also exists in Radiant-Core but pyrxd exposes no ``scalenet``
network, so it is deliberately absent here.

Block-hash algorithm
--------------------
Radiant does **not** use Bitcoin's SHA-256d for block hashes. ``CBlockHeader::GetHash``
(``src/primitives/block.cpp:15`` -> ``BlockHashCalculator::CalculateBlockHashFromHeader_sha512_256``,
``src/primitives/block.h:129``) is a **double SHA-512/256** over the 80-byte serialised
header, displayed in reversed byte order. :func:`block_hash_hex` implements exactly that
and was validated against the live mainnet genesis header (see the module tests).

Endpoint set — deliberately small
---------------------------------
Only endpoints confirmed reachable are shipped. ``testnet`` and ``regtest`` ship
**none**: no public Radiant testnet ElectrumX server was confirmed, and regtest is
by definition a local, per-developer chain. That is honest rather than convenient
— a guessed endpoint is exactly the failure mode this module exists to remove.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..security.errors import ValidationError
from .tls_pin import normalize_pin

__all__ = [
    "DEFAULT_ENDPOINTS",
    "GENESIS_BLOCK_HASHES",
    "KNOWN_NETWORKS",
    "Endpoint",
    "NetworkProfile",
    "block_hash_hex",
    "default_endpoints",
    "genesis_hash_for",
]

#: Networks the CLI/config layer understands. Mirrors ``--network``'s choices.
KNOWN_NETWORKS: tuple[str, ...] = ("mainnet", "testnet", "regtest")

#: Expected genesis block hash per network, in display (reversed) byte order —
#: the form ``getblockhash 0`` prints. See the module docstring for provenance.
GENESIS_BLOCK_HASHES: Mapping[str, str] = {
    "mainnet": "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4",
    "testnet": "000000000d8ada264d16f87a590b2af320cd3c7e3f9be5482163e830fd00aca2",
    "regtest": "7c1797514a165b0d99953a993a2a42081d6c0706026c36c06fc6fe728f93a5dd",
}

#: Shipped ElectrumX endpoints per network, in preference order.
#:
#: mainnet: two INDEPENDENT public servers (distinct operators), both confirmed
#: live on 2026-08-10 — same tip height, and both served the mainnet genesis
#: header above. This is the same pair the watchtower already ships as
#: ``pyrxd.gravity.watch.run.DEFAULT_RXD_ELECTRUMX``.
#:
#: testnet/regtest: EMPTY, on purpose. Shipping a mainnet URL under a non-mainnet
#: key is the bug this module exists to prevent, and inventing a plausible-looking
#: testnet host would be worse than admitting there isn't one.
DEFAULT_ENDPOINTS: Mapping[str, tuple[str, ...]] = {
    "mainnet": (
        "wss://electrumx.radiant4people.com:50022/",
        "wss://electrumx.radiantcore.org/",
    ),
    "testnet": (),
    "regtest": (),
}


def block_hash_hex(header: bytes) -> str:
    """Return the Radiant block hash of an 80-byte *header*, in display order.

    Double SHA-512/256, reversed — see the module docstring for the Radiant-Core
    reference. Not SHA-256d: feeding a Radiant header through Bitcoin's hash gives
    a value that matches nothing on any Radiant chain.

    Raises:
        ValidationError: if *header* is not exactly 80 bytes.
    """
    if not isinstance(header, (bytes, bytearray)):
        raise ValidationError(f"block header must be bytes, got {type(header).__name__}")
    if len(header) != 80:
        raise ValidationError(f"block header must be 80 bytes, got {len(header)}")
    once = hashlib.new("sha512_256", bytes(header)).digest()
    twice = hashlib.new("sha512_256", once).digest()
    return twice[::-1].hex()


def genesis_hash_for(network: str) -> str | None:
    """Expected genesis hash for *network*, or ``None`` for an unknown network.

    ``None`` means "pyrxd cannot verify this binding", not "the binding is fine";
    callers should treat it as a reason to be *more* explicit, not less.
    """
    return GENESIS_BLOCK_HASHES.get(str(network))


def default_endpoints(network: str) -> tuple[str, ...]:
    """Shipped endpoints for *network* (possibly empty). Never falls across networks."""
    return DEFAULT_ENDPOINTS.get(str(network), ())


def _normalize_pins(pins: Iterable[str]) -> tuple[str, ...]:
    """Validate + canonicalise SPKI pins, dropping duplicates but keeping order."""
    out: list[str] = []
    for pin in pins:
        canonical = normalize_pin(pin)
        if canonical not in out:
            out.append(canonical)
    return tuple(out)


@dataclass(frozen=True)
class Endpoint:
    """One ElectrumX server, with the trust decisions that apply to *it*.

    Attributes
    ----------
    url:
        ``wss://`` (or ``ws://`` with *allow_insecure*) WebSocket URL.
    allow_insecure:
        Permit a plaintext ``ws://`` URL. Needed for a local regtest indexer;
        never appropriate for a public endpoint.
    spki_pins:
        Optional TLS SubjectPublicKeyInfo pins (``sha256/<base64>``). Empty
        (the default) means pinning is OFF for this endpoint. See
        :mod:`pyrxd.network.tls_pin` for why that is the default.
    """

    url: str
    allow_insecure: bool = False
    spki_pins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.strip():
            raise ValidationError("endpoint url must be a non-empty string")
        url = self.url.strip()
        object.__setattr__(self, "url", url)
        if not (url.startswith("wss://") or url.startswith("ws://")):
            raise ValidationError(f"endpoint url must start with wss:// or ws:// (got {url.split(':', 1)[0]!r})")
        if url.startswith("ws://") and not self.allow_insecure:
            raise ValidationError(
                f"insecure endpoint {url!r} rejected. Use wss://, or set allow_insecure for this network."
            )
        if self.spki_pins and url.startswith("ws://"):
            raise ValidationError("TLS SPKI pinning is meaningless on a plaintext ws:// endpoint")
        object.__setattr__(self, "spki_pins", _normalize_pins(self.spki_pins))

    @property
    def key(self) -> str:
        """Normalised identity used for de-duplication (case + trailing slash)."""
        return self.url.rstrip("/").lower()


def _is_loopback_url(url: str) -> bool:
    """True when *url*'s host is unambiguously this machine's loopback interface.

    Deliberately strict, and it fails to ``False`` — the only caller uses this to EXEMPT an
    endpoint from a security rule, so anything it cannot prove is loopback must keep the rule.
    A literal loopback IP (``127.0.0.0/8``, ``::1``) or the exact name ``localhost`` qualifies;
    ``127.0.0.1.evil.com``, ``localhost.evil.com``, a bare ``0.0.0.0``, a LAN address and the
    abbreviated ``127.1`` (which :mod:`ipaddress` rejects) all do not.
    """
    host = urlsplit(url).hostname  # lowercases, strips userinfo and IPv6 brackets
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _assert_uniform_posture(network: str, endpoints: Sequence[Endpoint]) -> None:
    """Refuse a profile whose endpoints do not all carry the same security posture.

    A profile is the statement "these servers are interchangeable for this network", and
    :class:`~pyrxd.network.failover.FailoverElectrumXClient` acts on it: one transport error and
    the next call silently runs against the next endpoint in the list. Nothing compared what that
    move costs. So a profile of ``[wss:// + SPKI pins, wss:// unpinned]`` degraded to *unpinned*
    the first time the pinned primary hiccupped — and a profile mixing ``wss://`` with
    ``ws://`` degraded to *plaintext* — with no error, no warning, and the operator still
    believing the control they configured was in force. That is worse than never configuring it,
    because it is believed.

    Failing here, at wiring time, is the point: the same argument
    :func:`pyrxd.network.tls_pin.normalize_pin` makes for a malformed pin. An operator whose
    endpoints genuinely differ has two honest options — level them up (pin both, or publish both
    pins in one list), or split them into separate profiles and choose deliberately.

    A profile where NO endpoint is pinned is fine (pinning is opt-in, see
    :mod:`pyrxd.network.tls_pin`); the refusal is only for a MIX, where failover would relax.

    **Loopback endpoints are exempt, and are the only exemption.** The rule above is about what
    failover *costs*, and failing over to ``ws://127.0.0.1`` costs nothing it protects: that
    session never leaves the host, so there is no link to eavesdrop, no MITM position to take,
    and no remote identity for TLS or an SPKI pin to authenticate — an attacker who can read
    loopback already owns the process holding the keys. (This is the same judgement
    :class:`Endpoint` already encodes by refusing ``spki_pins`` on a plaintext URL as
    "meaningless".) The mix that motivated the rule is a *remote* plaintext or unpinned server,
    where the downgrade is real and silent, and that is still refused. Mixing a local indexer
    with a public one is the ordinary developer and operator layout — a guard that refuses it
    refuses valid work, and a ``ws://`` URL is already an explicit opt-in via ``allow_insecure``.
    ``_is_loopback_url`` fails closed, so anything it cannot prove local keeps the rule.
    """
    if len(endpoints) < 2:
        return
    remote = [e for e in endpoints if not _is_loopback_url(e.url)]
    if len(remote) < 2:
        return
    plaintext = [e.url for e in remote if e.url.startswith("ws://")]
    if plaintext and len(plaintext) != len(remote):
        raise ValidationError(
            f"network {network!r} mixes TLS and plaintext endpoints ({len(plaintext)} of "
            f"{len(remote)} non-loopback are ws://). Failover between them silently downgrades a "
            "wss:// session to plaintext on the first transport error. Use one transport per "
            "profile (a loopback ws:// endpoint is exempt — it never leaves the host)."
        )
    pinned = [e.url for e in remote if e.spki_pins]
    if pinned and len(pinned) != len(remote):
        raise ValidationError(
            f"network {network!r} mixes TLS-pinned and unpinned endpoints ({len(pinned)} of "
            f"{len(remote)} non-loopback carry spki_pins). Failover to an unpinned endpoint "
            "silently drops the pin, so the check reads as enabled while not being in force. Pin "
            "every endpoint in the profile (one pin list may hold several servers' pins), or "
            "none of them."
        )


@dataclass(frozen=True)
class NetworkProfile:
    """An ordered endpoint list bound to one network, plus its chain fingerprint.

    This is the object the client layer consumes: it answers both "where do I
    connect?" and "how do I know that server is on the chain I asked for?".

    Attributes
    ----------
    network:
        ``mainnet`` / ``testnet`` / ``regtest`` (or any caller-defined name).
    endpoints:
        Preference-ordered, de-duplicated, non-empty.
    genesis_hash:
        Expected genesis block hash in display order, or ``None`` when pyrxd has
        no constant for this network (then no chain check is possible).
    """

    network: str
    endpoints: tuple[Endpoint, ...] = field(default_factory=tuple)
    genesis_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.network, str) or not self.network.strip():
            raise ValidationError("profile network must be a non-empty string")
        object.__setattr__(self, "network", self.network.strip())
        if not self.endpoints:
            raise ValidationError(f"network {self.network!r} has no ElectrumX endpoint configured")
        deduped: list[Endpoint] = []
        seen: set[str] = set()
        for endpoint in self.endpoints:
            if not isinstance(endpoint, Endpoint):
                raise ValidationError(f"profile endpoints must be Endpoint, got {type(endpoint).__name__}")
            if endpoint.key in seen:
                continue
            seen.add(endpoint.key)
            deduped.append(endpoint)
        object.__setattr__(self, "endpoints", tuple(deduped))
        _assert_uniform_posture(self.network, deduped)
        if self.genesis_hash is not None:
            genesis = str(self.genesis_hash).strip().lower()
            if len(genesis) != 64:
                raise ValidationError("genesis_hash must be a 64-character hex string")
            try:
                bytes.fromhex(genesis)
            except ValueError as exc:
                raise ValidationError("genesis_hash must be valid hex") from exc
            object.__setattr__(self, "genesis_hash", genesis)

    @property
    def urls(self) -> tuple[str, ...]:
        return tuple(endpoint.url for endpoint in self.endpoints)

    @classmethod
    def build(
        cls,
        network: str,
        urls: Sequence[str],
        *,
        allow_insecure: bool = False,
        spki_pins: Sequence[str] = (),
        genesis_hash: str | None = None,
    ) -> NetworkProfile:
        """Build a profile from plain URLs, defaulting the genesis hash from the registry.

        Pass ``genesis_hash`` explicitly only to override the shipped constant (a
        custom chain). Leaving it ``None`` looks the network up in
        :data:`GENESIS_BLOCK_HASHES`, so ``build("mainnet", [...])`` is chain-bound
        with no extra ceremony.
        """
        endpoints = tuple(Endpoint(url=url, allow_insecure=allow_insecure, spki_pins=tuple(spki_pins)) for url in urls)
        return cls(
            network=network,
            endpoints=endpoints,
            genesis_hash=genesis_hash if genesis_hash is not None else genesis_hash_for(network),
        )
