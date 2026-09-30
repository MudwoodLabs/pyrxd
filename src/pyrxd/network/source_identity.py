"""ONE identity for counting sources: the OPERATOR GROUP a URL belongs to.

Every rule in pyrxd that needs "two sources agreed" — the watchtower's RXD quorum, the BTC Esplora
quorums, the ETH RPC quorum, HashMark §7.6 form 2's judge and chain walker — counts sources through
:func:`source_key`, and nothing else. (It used to be five identities, one per quorum, so one server
reached through two spellings corroborated itself wherever the cheap identity was used; 0.25.0
panel.) Two URLs with the same key are ONE source: they may be one another's failover, and they
never count as two.

WHAT THE KEY IS — distinct operators, as declared, or by registered domain. In this order:

1. A DECLARED operator: ``source_key(url, operator="acme")``. Every URL declared ``"acme"`` is one
   source, whatever its domain. A declaration TRAVELS WITH THE URL IT DESCRIBES and nowhere else:
   an :class:`~pyrxd.network.registry.Endpoint` carries its own ``operator`` (the config file's
   ``operator = "…"``), and anything that counts a set of URLs is HANDED the declarations for that
   set (:func:`source_keys`). There is no process-wide registry, so a declaration made for one
   profile is invisible to another profile, to any quorum, and to a later load.
2. An operator pyrxd SHIPS knowledge of: :data:`pyrxd.network.registry.KNOWN_OPERATORS`, keyed by
   registered domain, recorded from the Radiant maintainer's statement of 2026-09-29.
3. An IP literal: ITSELF, one group per canonical address (every spelling of one address is one).
4. Any other name: its REGISTERED DOMAIN (eTLD+1) under the Public Suffix List, a sha256-pinned
   snapshot vendored in ``network/data/``. So ``x.bladenet.online`` and ``y.bladenet.online`` are one
   source, while ``a.co.uk`` and ``b.co.uk`` stay two, because ``co.uk`` is a public suffix. The
   list's PRIVATE section is included, as browsers include it: ``a.github.io`` and ``b.github.io``
   are two, because that section exists to say those names have different owners.
5. A name with no registered domain (``localhost``, a bare ssh host alias, a name that is itself a
   public suffix): itself.

Case, a trailing dot, the port, the path, the query, userinfo and the spelling of an IP literal
never make a second source. The key of a declared or shipped operator prints as ``operator:<id>``,
so it cannot collide with a domain or an address.

THE OPERATOR LIMIT — stated here, once; every other docstring, help text and doc that needs it
points here. Nothing in a URL shows who runs a server, so the grouping above is the best a client
can do, and it is not proof of independence:

* ONE PARTY CAN REGISTER SEVERAL DOMAINS. Two registered domains (or a name and an IP address, or
  two IP addresses) may be one operator, may sit behind one CDN, load balancer or RPC aggregator,
  may read from one upstream node, or may present certificates from one mis-issuing CA. They count
  as two here, and one party running both — or one failure reaching both — defeats a quorum built
  on them.
* A DECLARED OPERATOR IS ONLY AS GOOD AS THE DECLARATION. ``operator = "…"`` is the configuring
  user's statement, and pyrxd believes it: declaring two hosts as two operators makes them two
  sources. A declaration that contradicts an operator pyrxd ships knowledge of is refused, and so
  is one host counted as two sources within one set (:func:`require_one_key_per_host`); anything
  else is taken as written.

Choosing sources whose operators and upstreams do not overlap remains the operator's job. The prose
elsewhere says "distinct operators (as declared, or by registered domain)" for this reason, and
never "independent".

WHERE A QUORUM HOLDS CLIENT OBJECTS rather than URLs, each client carries its own ``source_key``
(a :class:`SourceKey`, derived from the URL it was built with) and the quorum refuses two clients
with one key (:func:`require_distinct_sources`). Several URLs in ONE group are a failover list for
one source, never several sources — :class:`SameSourceFailover` is that shape for readers, and
``ElectrumXClient([url, url2])`` already races its URLs.

INPUT THAT NAMES NO HOST IS REFUSED. ``[bad``, ``wss://[::1``, ``[::1]x`` and ``wss://`` raise
:class:`~pyrxd.security.errors.ValidationError`. They used to become a key of their own, which
made a typo a source.

INTERNATIONALISED NAMES — one known deviation. Hosts are folded to their A-label with Python's
``idna`` codec, which implements IDNA2003: it maps ``ß`` to ``ss``, so ``faß.de`` and ``fass.de`` are
ONE key here. yarl and aiohttp (IDNA2008) encode ``faß.de`` as ``xn--fa-hia.de``, a different host.
It is rare, and it fails CLOSED: two hosts counted as one source can only lower a count, never
raise one.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import ipaddress
import json
import re
import socket
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..security.errors import NetworkError, ValidationError

__all__ = [
    "SameSourceFailover",
    "SourceKey",
    "canonical_host",
    "describe_source",
    "group_by_source",
    "one_source_label",
    "registered_domain",
    "require_distinct_sources",
    "require_one_key_per_host",
    "source_key",
    "source_key_of",
    "source_keys",
]

#: An IPv4 literal in any spelling ``inet_aton`` accepts: one to four dot-separated parts, each
#: decimal, octal (leading ``0``) or hex (``0x``). ``203.0.113.7``, ``0xcb.0.113.7``,
#: ``0313.0.0161.07`` and ``3405803783`` are all one address. With fewer than four parts the LAST
#: part fills the remaining bytes, so ``203.113.7`` is ``203.113.0.7`` — a different address.
_INET_ATON_FORM = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}")

#: The prefix of an operator group's key. A domain always contains a dot or is a single label and
#: an IP literal is digits, dots and colons, so no domain or address can spell this.
_OPERATOR_PREFIX = "operator:"

#: A declared operator id: lower-case letters, digits, ``.`` and ``-``, 1–64 characters, starting
#: and ending with a letter or digit. Strict on purpose — ``Acme`` and ``acme`` silently being two
#: operators would be a split nobody declared.
_OPERATOR_ID = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?")

_DATA_DIR = Path(__file__).resolve().parent / "data"
_PSL_FILE = "public_suffix_list.dat"


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
    """A SOURCE key — an operator group — as :func:`source_key` produced it.

    A ``str`` so it prints, compares and hashes as the group (``operator:radiantcore``,
    ``bladenet.online``, ``203.0.113.7``). It is a separate type so a quorum can insist that the key
    it counts came from :func:`source_key` — a caller-chosen label such as ``"a"``/``"b"`` for two
    URLs on one server would otherwise count as two sources.

    ``host`` is the canonical host the key was made from (``None`` for a key built by hand). It is
    not part of the key's value — two hosts of one operator are one key — but it lets every set of
    keys refuse ONE host counted as TWO sources (:func:`require_one_key_per_host`), which is what a
    declaration on one of a host's URLs and not another, or two declarations for one host, produce.
    """

    host: str | None

    def __new__(cls, value: str, host: str | None = None) -> SourceKey:
        key = super().__new__(cls, value)
        key.host = host
        return key


# ── The Public Suffix List ───────────────────────────────────────────────────────────────────────


@functools.cache
def _public_suffix_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """``(rules, wildcards, exceptions)`` from the vendored list, each as A-label suffixes.

    Refuses a file whose bytes are not the pinned ones (``data/MANIFEST.json``): a list edited so
    that ``bladenet.online`` became a public suffix would make every ``*.bladenet.online`` host a
    source of its own, and nothing else would notice.
    """
    manifest = json.loads((_DATA_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    raw = (_DATA_DIR / _PSL_FILE).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != manifest["files"][_PSL_FILE]:
        raise ValidationError(
            f"the vendored Public Suffix List is not the pinned file (sha256 {digest}, pinned "
            f"{manifest['files'][_PSL_FILE]}); refusing to group sources by it"
        )
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for line in raw.decode("utf-8").splitlines():
        rule = line.strip().split(maxsplit=1)[0] if line.strip() else ""
        if not rule or rule.startswith("//"):
            continue
        target = rules
        if rule.startswith("!"):
            rule, target = rule[1:], exceptions
        elif rule.startswith("*."):
            rule, target = rule[2:], wildcards
        try:
            rule = rule.encode("idna").decode("ascii").lower()
        except UnicodeError:
            # Not expressible as an A-label by Python's codec (IDNA2003). Leaving a rule out makes
            # its suffix look ONE label shorter, which merges names under it — the closed side.
            continue
        target.add(rule)
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def registered_domain(host: str) -> str | None:
    """The registered domain (eTLD+1) of a canonical host name, or ``None`` when it has none.

    The Public Suffix List algorithm (https://publicsuffix.org/list/): an exception rule wins,
    else the matching rule with the most labels, else the implicit ``*`` (the last label). The
    registered domain is that public suffix plus one label. A name that IS a public suffix, or has
    a single label, has none. *host* is expected from :func:`canonical_host` (lower-case A-labels,
    no trailing dot); an IP literal is not a domain and is the caller's to exclude.
    """
    rules, wildcards, exceptions = _public_suffix_rules()
    labels = host.split(".")
    n = len(labels)
    suffix_len = 1  # the implicit "*" rule
    for i in range(n):
        if ".".join(labels[i:]) in exceptions:
            suffix_len = n - i - 1
            break
    else:
        for i in range(n):  # smallest i = most labels, so the first match is the prevailing rule
            if ".".join(labels[i:]) in rules or (i + 1 < n and ".".join(labels[i + 1 :]) in wildcards):
                suffix_len = max(suffix_len, n - i)
                break
    if n <= suffix_len:
        return None
    return ".".join(labels[n - suffix_len - 1 :])


# ── Operators: declared, and shipped ─────────────────────────────────────────────────────────────


def _operator_id(operator: object) -> str:
    if not isinstance(operator, str) or not _OPERATOR_ID.fullmatch(operator.strip()):
        raise ValidationError(
            f"operator {operator!r} is not a valid operator id: use 1-64 lower-case letters, digits, "
            "'.' or '-', starting and ending with a letter or digit (e.g. \"radiantcore\")"
        )
    return operator.strip()


def _shipped_operator(host: str) -> str | None:
    """The operator pyrxd ships knowledge of for *host* (by its registered domain), if any."""
    from .registry import shipped_operator_domains  # deferred: registry imports this module

    domain = registered_domain(host)
    return shipped_operator_domains().get(domain) if domain else None


def _checked_declaration(host: str, operator: object) -> str:
    """*operator* validated, and refused when it contradicts what pyrxd ships for *host*.

    A contradiction is refused rather than obeyed because the direction it moves is the dangerous
    one: declaring one of radiant4people's two hosts to be someone else would turn one operator into
    two sources. Declaring the SAME operator is fine, and so is declaring a host pyrxd knows nothing
    about — that is the declaration's whole purpose.
    """
    op = _operator_id(operator)
    shipped = _shipped_operator(host)
    if shipped is not None and shipped != op:
        raise ValidationError(
            f"{host!r} is declared as operator {op!r}, but pyrxd records its domain as operator "
            f"{shipped!r} (pyrxd.network.registry.KNOWN_OPERATORS). A declaration cannot split an "
            f"operator pyrxd ships; declare {shipped!r}, or leave the operator out"
        )
    return op


# ── The key ──────────────────────────────────────────────────────────────────────────────────────


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.partition("%")[0])
    except ValueError:
        return False
    return True


def _canonical_host_of(url: object) -> str:
    """The canonical host *url* names, or ``ValidationError`` when it names none."""
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("a source is counted by the host of its URL; an empty URL names no host")
    host = _host_in(url.strip())
    if not host:
        raise ValidationError(
            f"{url.strip()!r} names no host that can be parsed, so it cannot be counted as a source. "
            "Check the URL (an unclosed '[', text after ']', or an empty authority)"
        )
    return canonical_host(host)


def source_key(url: str, *, operator: str | None = None) -> SourceKey:
    """The SOURCE identity of *url*: THE function every source count keys through.

    Distinct operators, as declared, or by registered domain — the rules, in order, are in the
    module docstring. *operator* declares the operator for this one call (an ``Endpoint`` passes its
    own). Nothing else declares one: without *operator* the key is the shipped operator, the IP
    address, or the registered domain, whatever any other code in the process has declared. A key
    for ONE URL cannot see that another URL of the same host was keyed differently; a SET of URLs
    is keyed through :func:`source_keys`, which refuses that.

    Accepts a URL (``wss://h:443/x``), a scheme-less ``host[:port][/path]`` (``localhost:8545``,
    ``user@node.example``, an ssh destination), a bare IPv6 literal (``2001:db8::1``,
    ``fe80::1%eth0``), a bracketed one with or without a port (``[2001:db8::1]:50022``), or a
    bare label.

    Raises:
        ValidationError: for an empty or non-string *url*, for text that names no parseable host
            (``[bad``, ``wss://[::1``, ``[::1]x``, ``wss://``), and for an invalid or contradicting
            *operator*.
    """
    host = _canonical_host_of(url)
    if operator is not None:
        return SourceKey(_OPERATOR_PREFIX + _checked_declaration(host, operator), host)
    if _is_ip_literal(host):
        return SourceKey(host, host)
    shipped = _shipped_operator(host)
    if shipped is not None:
        return SourceKey(_OPERATOR_PREFIX + shipped, host)
    return SourceKey(registered_domain(host) or host, host)


def require_one_key_per_host(keys: Iterable[SourceKey], *, what: str) -> None:
    """Refuse a set of keys in which ONE host is TWO sources.

    One host is one operator. A declaration on ``wss://h:1`` and a different one (or none) on
    ``wss://h:2`` would otherwise make one machine two votes — the single-call
    :func:`source_key` cannot see the other URL, so the refusal lives here, where a SET is keyed:
    :func:`source_keys` (every URL list: a profile's, a quorum builder's, form 2's labels) and
    :func:`require_distinct_sources` (every quorum of client objects) both call it. Keys built by
    hand carry no host and are not checked here.
    """
    seen: dict[str, SourceKey] = {}
    for key in keys:
        host = getattr(key, "host", None)
        if host is None:
            continue
        other = seen.setdefault(host, key)
        if other != key:
            raise ValidationError(
                f"{what}: host {host!r} is counted as two sources ({describe_source(other)} and "
                f"{describe_source(key)}). One host is one operator: give every URL of that host the "
                "same operator, or none"
            )


def _stripped(url: object) -> Any:
    """*url* without surrounding whitespace; a non-string is passed on for :func:`source_key` to refuse."""
    return url.strip() if isinstance(url, str) else url


def source_keys(urls: Iterable[str], operators: Mapping[str, str] | None = None) -> dict[str, SourceKey]:
    """``{url: key}`` for ONE set of URLs, with the declarations made FOR that set, and nothing else.

    *operators* maps a URL (exactly as given) to its declared operator. It is the only way a
    declaration reaches a count: whoever holds the declarations — a profile's endpoints, the
    config that listed them — passes them to whatever counts, and a declaration passed for one set
    is not seen by any other. URLs in *operators* that are not in *urls* are keyed too, so their
    declarations are checked against the set.

    Raises:
        ValidationError: for a URL that names no host, an invalid or contradicting operator id, and
            ONE host keyed as two sources (:func:`require_one_key_per_host`).
    """
    declared = {_stripped(u): op for u, op in (operators or {}).items()}
    keys: dict[str, SourceKey] = {}
    for url in [*urls, *declared]:
        text = _stripped(url)
        key = source_key(text, operator=declared.get(text) if isinstance(text, str) else None)
        keys.setdefault(text, key)
    require_one_key_per_host(keys.values(), what="counting sources")
    return keys


def describe_source(key: str) -> str:
    """How a key reads in a message: ``operator 'x'``, ``IP address '…'``, ``registered domain '…'``."""
    key = str(key)
    if key.startswith(_OPERATOR_PREFIX):
        return f"operator {key[len(_OPERATOR_PREFIX) :]!r}"
    if _is_ip_literal(key):
        return f"IP address {key!r}"
    if "." in key and registered_domain(key) == key:
        return f"registered domain {key!r}"
    return f"host {key!r}"


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
        try:  # brackets hold an IPv6 literal and nothing else
            ipaddress.IPv6Address(address)
        except ValueError:
            return None
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


def one_source_label(a: str, b: str, *, operators: Mapping[str, str] | None = None) -> str:
    """How to NAME two labels that were judged one source, for a reason string.

    Equal labels print once; two different labels print both and the group they share, so a reader
    who configured ``wss://x.example`` and ``wss://y.example`` sees why they were not two sources.
    *operators* are the declarations the labels were judged with (:func:`source_keys`).
    """
    if a.strip() == b.strip():
        return repr(a)
    key = source_keys([a], operators)[a.strip()]
    return f"{a!r} and {b!r}, which are one source ({describe_source(key)})"


def source_key_of(source: object) -> SourceKey:
    """The ``source_key`` a client object carries, or ``ValidationError`` when it carries none.

    A quorum that holds client OBJECTS cannot see their URLs, so each client says which source it
    reads from. Every shipped reader derives it from its own URL; a client that cannot say is
    refused rather than guessed at, because a guess is exactly how one server became two sources.
    """
    key = getattr(source, "source_key", None)
    if not isinstance(key, SourceKey):
        raise ValidationError(
            f"{type(source).__name__} does not say which source it reads from: a quorum counts sources "
            "by `source_key`, which must come from pyrxd.network.source_identity.source_key(<its URL>)"
        )
    return key


def require_distinct_sources(sources: Sequence[object], *, what: str) -> tuple[SourceKey, ...]:
    """Each source's key, refusing when two sources are the same source.

    Refusal, not silent de-duplication: a caller that hands a quorum one operator twice believes it
    has two sources, and quietly dropping one would leave that belief in place. Several URLs in one
    group belong in ONE failover source (:class:`SameSourceFailover`, or an ``ElectrumXClient``
    given all of them), which counts once.
    """
    keys = tuple(source_key_of(s) for s in sources)
    require_one_key_per_host(keys, what=what)
    first: dict[SourceKey, int] = {}
    for index, key in enumerate(keys):
        if key in first:
            raise ValidationError(
                f"{what}: sources #{first[key]} and #{index} are the same source ({describe_source(key)}). "
                "Sources are counted by registered domain, or by an operator pyrxd ships knowledge of, so "
                "one cannot corroborate itself. Give each operator once: several URLs of one operator form "
                "one failover source. Use endpoints of different operators; this count takes no operator "
                "declaration from the config file (that is for ElectrumX endpoints and HashMark form 2)."
            )
        first[key] = index
    return keys


def group_by_source(urls: Iterable[str]) -> list[tuple[SourceKey, list[str]]]:
    """``[(key, [url, ...]), ...]`` — URLs grouped by :func:`source_key`, in first-seen order.

    What a URL-list builder uses to turn a user's list into sources: one source per group, whose
    URLs are that source's failover list.
    """
    urls = list(urls)
    keys = source_keys(urls)
    groups: dict[SourceKey, list[str]] = {}
    for url in urls:
        groups.setdefault(keys[_stripped(url)], []).append(url)
    return list(groups.items())


#: Errors that mean "this URL did not answer", on which a same-source failover tries the next URL.
#: Anything else is an ANSWER (a refusal, a validation failure) and is returned as-is: trying the
#: next URL of one source until it says something more convenient is not failover.
_UNREACHABLE = (NetworkError, OSError, TimeoutError)


class SameSourceFailover:
    """ONE source reachable at several URLs with ONE :func:`source_key`: tried in order, counted once.

    The URLs may be several spellings of one host, or several hosts of one operator group (the two
    radiant4people servers). Either way they are one vote, and failing over between them is allowed.

    Proxies the members' async methods: each call goes to the first member, and on to the next
    only when a member is unreachable (:data:`_UNREACHABLE`). Non-async attributes come from the
    first member. ``close()`` closes every member.
    """

    def __init__(self, members: Sequence[Any]) -> None:
        members = list(members)
        if not members:
            raise ValidationError("SameSourceFailover needs at least one member")
        keys = {source_key_of(m) for m in members}
        if len(keys) != 1:
            raise ValidationError(
                f"SameSourceFailover members must all be one source, got {sorted(map(str, keys))}; "
                "distinct sources are counted separately, not failed over between"
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
