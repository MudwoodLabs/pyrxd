"""ONE identity for counting sources: the canonical HOST a URL names.

Every rule in pyrxd that needs "two sources agreed" — the watchtower's RXD quorum, the BTC Esplora
quorums, the ETH RPC quorum, HashMark §7.6 form 2's judge and chain walker — counts sources through
:func:`source_key`, and nothing else. It used to be five identities: one site folded case and a
trailing slash, one only lowercased the host, one compared raw labels, one had no identity at all,
and :attr:`~pyrxd.network.registry.Endpoint.source` alone canonicalised. So ``wss://h`` and
``wss://h:443`` were one source in one place and two in another, and one server reached through
two spellings could corroborate itself wherever the cheap identity was used.

WHAT THE KEY MEANS, EXACTLY: two URLs with the same key name the same DISTINCT HOST. Case, a
trailing dot, the port, the path, the query, userinfo, and the spelling of an IP literal do not
make a second host. That is all a URL can show.

THE OPERATOR LIMIT — stated here, once; every other docstring, help text and doc that needs it
points here. A distinct host is not an independent operator. Independence is a property of
OPERATORS, and nothing in a URL shows who runs a server. Two distinct hosts may be one operator,
may sit behind one CDN, load balancer or RPC aggregator, may read from one upstream node, or may
present certificates from one mis-issuing CA; a hostname and its IP address, or two DNS names for
one machine, are distinct hosts here too. Every quorum built on these keys therefore rests on
DISTINCT HOSTS, and one party running both hosts (or one failure reaching both) defeats it.
Choosing hosts whose operators and upstreams do not overlap is the operator's job. The prose
elsewhere says "distinct host" for this reason, and never "independent operator".

WHERE A QUORUM HOLDS CLIENT OBJECTS rather than URLs, each client carries its own ``source_key``
(a :class:`SourceKey`, derived from the URL it was built with) and the quorum refuses two clients
with one key (:func:`require_distinct_sources`). Several URLs on ONE host are a failover list for
one source, never several sources — :class:`SameHostFailover` is that shape for readers, and
``ElectrumXClient([url, url2])`` already races its URLs.
"""

from __future__ import annotations

import inspect
import ipaddress
import re
import socket
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit

from ..security.errors import NetworkError, ValidationError

__all__ = [
    "SameHostFailover",
    "SourceKey",
    "canonical_host",
    "group_by_source",
    "one_source_label",
    "require_distinct_sources",
    "source_key",
    "source_key_of",
]

#: An IPv4 literal in any spelling ``inet_aton`` accepts: one to four dot-separated parts, each
#: decimal, octal (leading ``0``) or hex (``0x``). ``203.0.113.7``, ``0xcb.0.113.7``,
#: ``0313.0.0161.07``, ``203.113.7`` and ``3405803783`` are all one address.
_INET_ATON_FORM = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}")


def canonical_host(host: str) -> str:
    """One spelling per host: lower-cased, no trailing dot, and an IP literal in its canonical form.

    A URL can spell one address many ways, and a SOURCE count built on spellings counts one server
    several times (0.25.0 panel, round 3): ``[2001:db8::7]`` and ``[2001:db8:0:0:0:0:0:7]`` are one
    IPv6 address; ``203.0.113.7`` and ``0xcb.0.113.7`` are one IPv4 address; ``::ffff:203.0.113.7``
    is that IPv4 address too. Names that are not IP literals are only case- and dot-folded — whether
    two NAMES reach one machine is not visible in a URL, and nothing here claims to see it.
    An internationalised name is folded to its punycode A-label, the spelling that is connected to.

    An IPv6 zone id is kept (lower-cased): ``fe80::1%eth0`` and ``fe80::1%eth1`` are different
    interfaces. Its RFC 6874 URL spelling ``%25eth0`` is decoded by :func:`source_key` before it
    gets here, so ``[fe80::1%25eth0]`` and a bare ``fe80::1%eth0`` are one key.

    Not folded, because the URL does not show them to be one host: a NAT64 (``64:ff9b::/96``) or
    IPv4-compatible IPv6 address next to the IPv4 address it embeds. Whether those reach one
    machine depends on the network, the same limit as a hostname next to its IP address.
    """
    host = host.strip().rstrip(".").lower()
    if ":" in host:  # IPv6 (urlsplit has already removed the brackets); a zone id is kept verbatim
        address, _, zone = host.partition("%")
        try:
            v6 = ipaddress.IPv6Address(address)
        except ValueError:
            return host
        if v6.ipv4_mapped is not None and not zone:
            return str(v6.ipv4_mapped)
        return v6.compressed + (f"%{zone}" if zone else "")
    if _INET_ATON_FORM.fullmatch(host):
        try:
            return str(ipaddress.IPv4Address(socket.inet_aton(host)))
        except OSError:  # e.g. "08": not a valid octal part, so not an address — keep the name
            return host
    if not host.isascii():
        # An internationalised name is one host in two spellings: websockets connects
        # ``bücher.example`` to ``xn--bcher-kva.example`` (#754). Fold to the A-label, the form
        # that goes on the wire. A name the codec cannot encode is kept as typed.
        try:
            # Re-canonicalised: the codec maps ``。`` to ``.`` and full-width digits to ASCII,
            # so the A-label can still carry a trailing dot or spell an IP literal.
            return canonical_host(host.encode("idna").decode("ascii"))
        except UnicodeError:
            return host
    return host


class SourceKey(str):
    """A DISTINCT-HOST key, as :func:`source_key` produced it.

    A ``str`` so it prints, compares and hashes as the host. It is a separate type so a quorum can
    insist that the key it counts came from :func:`source_key` — a caller-chosen label such as
    ``"a"``/``"b"`` for two URLs on one server would otherwise count as two sources.
    """

    __slots__ = ()


def source_key(url: str) -> SourceKey:
    """The distinct-host identity of *url*: THE function every source count keys through.

    Accepts a URL (``wss://h:443/x``), a scheme-less ``host[:port][/path]`` (``localhost:8545``,
    ``user@node.example``, an ssh destination), a bare IPv6 literal (``2001:db8::1``,
    ``fe80::1%eth0``), a bracketed one with or without a port (``[2001:db8::1]:50022``), or a
    bare label. The key is the canonical host (:func:`canonical_host`): port, path, query,
    userinfo, case and a trailing dot are dropped.

    Text with no parseable host (a malformed URL such as ``wss://[::1``) is its own key, folded to
    lower case: identical text is one source, and different text cannot be shown to collide.

    Raises:
        ValidationError: for an empty or non-string *url* — nothing, counted as a source, would be
            a source nobody can name.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("a source is counted by the host of its URL; an empty URL names no host")
    text = url.strip()
    host = _host_in(text)
    return SourceKey(canonical_host(host) if host else text.lower())


def _host_in(text: str) -> str | None:
    """The host *text* names, or ``None`` when no host can be parsed out of it.

    The authority is split by hand rather than by ``urlsplit(...).hostname``, which reads an
    UNBRACKETED IPv6 literal as ``host:port``: ``2001:db8::1`` became host ``"2001"``, which
    ``inet_aton`` then read as ``0.0.7.209``. So an ssh destination ``2001:db8::1`` and
    ``wss://[2001:db8::1]:50022`` — one machine — counted as two sources, and ``2001:db8::1``
    next to ``2001:db9::2`` — two machines — was refused as one.
    """
    if "://" in text:
        try:
            authority = urlsplit(text).netloc
        except ValueError:  # e.g. an unclosed IPv6 bracket (#754)
            return None
    else:
        authority = re.split(r"[/?#]", text.lstrip("/"), maxsplit=1)[0]
    hostport = authority.rpartition("@")[2]  # drop userinfo (``user@host``, ``user:pw@host``)
    if hostport.startswith("["):  # ``[v6]`` or ``[v6]:port``
        close = hostport.find("]")
        if close == -1 or hostport[close + 1 :][:1] not in ("", ":"):
            return None
        inside = hostport[1:close]
        # RFC 6874: inside a URL's brackets the zone delimiter is percent-encoded, ``%25eth0``.
        address, pct, zone = inside.partition("%")
        if pct and zone.startswith("25"):
            zone = zone[2:]
        return f"{address}%{zone}" if pct else address
    if hostport.count(":") >= 2:
        # Two or more colons unbracketed: an IPv6 literal, which cannot carry a port without
        # brackets, so the whole of it is the address (a zone id may follow ``%``).
        try:
            ipaddress.IPv6Address(hostport)
        except ValueError:
            return None
        return hostport
    host = hostport.partition(":")[0]  # ``host`` or ``host:port``
    return host or None


def one_source_label(a: str, b: str) -> str:
    """How to NAME two labels that were judged one source, for a reason string.

    Equal labels print once; two spellings of one host print both and the host, so a reader who
    configured ``wss://h`` and ``wss://h:443`` sees why they were not two sources.
    """
    if a.strip() == b.strip():
        return repr(a)
    return f"{a!r} and {b!r}, which are one host ({str(source_key(a))!r})"


def source_key_of(source: object) -> SourceKey:
    """The ``source_key`` a client object carries, or ``ValidationError`` when it carries none.

    A quorum that holds client OBJECTS cannot see their URLs, so each client says which host it
    reads from. Every shipped reader derives it from its own URL; a client that cannot say is
    refused rather than guessed at, because a guess is exactly how one host became two sources.
    """
    key = getattr(source, "source_key", None)
    if not isinstance(key, SourceKey):
        raise ValidationError(
            f"{type(source).__name__} does not say which host it reads from: a quorum counts sources "
            "by `source_key`, which must come from pyrxd.network.source_identity.source_key(<its URL>)"
        )
    return key


def require_distinct_sources(sources: Sequence[object], *, what: str) -> tuple[SourceKey, ...]:
    """Each source's key, refusing when two sources are the same host.

    Refusal, not silent de-duplication: a caller that hands a quorum the same host twice believes
    it has two sources, and quietly dropping one would leave that belief in place. Several URLs on
    one host belong in ONE failover source (:class:`SameHostFailover`, or an ``ElectrumXClient``
    given all of them), which counts once.
    """
    keys = tuple(source_key_of(s) for s in sources)
    first: dict[SourceKey, int] = {}
    for index, key in enumerate(keys):
        if key in first:
            raise ValidationError(
                f"{what}: sources #{first[key]} and #{index} are the same host ({str(key)!r}). One "
                "host is one source however many URLs reach it, so it cannot corroborate itself. "
                "Give each distinct host once (several URLs on one host form one failover source)."
            )
        first[key] = index
    return keys


def group_by_source(urls: Iterable[str]) -> list[tuple[SourceKey, list[str]]]:
    """``[(key, [url, ...]), ...]`` — URLs grouped by distinct host, in first-seen order.

    What a URL-list builder uses to turn a user's list into sources: one source per host, whose
    URLs are that source's failover list.
    """
    groups: dict[SourceKey, list[str]] = {}
    for url in urls:
        groups.setdefault(source_key(url), []).append(url)
    return list(groups.items())


#: Errors that mean "this URL did not answer", on which a same-host failover tries the next URL.
#: Anything else is an ANSWER (a refusal, a validation failure) and is returned as-is: trying the
#: next spelling of one host until it says something more convenient is not failover.
_UNREACHABLE = (NetworkError, OSError, TimeoutError)


class SameHostFailover:
    """ONE source reachable at several URLs on ONE host: tried in order, counted once.

    Proxies the members' async methods: each call goes to the first member, and on to the next
    only when a member is unreachable (:data:`_UNREACHABLE`). Non-async attributes come from the
    first member. ``close()`` closes every member.
    """

    def __init__(self, members: Sequence[Any]) -> None:
        members = list(members)
        if not members:
            raise ValidationError("SameHostFailover needs at least one member")
        keys = {source_key_of(m) for m in members}
        if len(keys) != 1:
            raise ValidationError(
                f"SameHostFailover members must all be one host, got {sorted(map(str, keys))}; "
                "distinct hosts are distinct sources"
            )
        self._members = members
        self.source_key: SourceKey = keys.pop()

    async def close(self) -> None:
        for member in self._members:
            close = getattr(member, "close", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        head = getattr(self._members[0], name)
        if not inspect.iscoroutinefunction(head):
            return head

        async def _failover(*args: Any, **kwargs: Any) -> Any:
            last: BaseException | None = None
            for member in self._members:
                try:
                    return await getattr(member, name)(*args, **kwargs)
                except _UNREACHABLE as exc:
                    last = exc
            if last is None:  # unreachable: __init__ refuses an empty member list
                raise NetworkError(f"no member of {self.source_key!r} answered {name}")
            raise last

        return _failover
