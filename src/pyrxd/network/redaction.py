"""Keep the credential-bearing parts of an endpoint URL out of every message pyrxd prints.

An ElectrumX, node-RPC, Ethereum-RPC or block-explorer URL routinely carries a credential:
``wss://user:password@host/``, ``https://host/v2/<api-key>``, ``https://host/?apikey=<key>``.
Two helpers, used at every place an endpoint is named in text:

* :func:`redacted_url` — the ONE way to name an endpoint in a log line, an error message or a
  ``fix:`` hint. Scheme, host and port only; never userinfo, path, query or fragment.
* :func:`redact_endpoints_in` — for a value about to be RENDERED (a JSON payload, a reason string)
  that carries endpoint URLs as source LABELS. Source-identity rules compare the raw URLs, so the
  labels stay raw internally and are redacted here, where they become output: each whole URL
  becomes :func:`redacted_url`, then :func:`redact_endpoint_secrets` catches any part quoted alone.
* :func:`redact_endpoint_secrets` — for text pyrxd did not write (an exception from a library, an
  RPC's own error body), which may quote the URL or echo the key back. It removes the
  credential-bearing PARTS of each known URL wherever they appear, in any letter case and in their
  percent-encoded or decoded spelling.

The redaction rule (structural, from the URL — not a list of exact strings):

* **userinfo** — the user name and the password: ALWAYS redacted, at any length.
* **each query VALUE, the fragment and each fragment value**: ALWAYS redacted (a query value is
  where a key travels, and pyrxd cannot tell ``?apikey=`` from ``?k=``).
* **a path segment** only when it looks like a credential: 16 characters or more (an Infura,
  Alchemy or QuickNode key), or 8 or more mixing letters and digits (``abc123xyz``), or any
  segment that is not a trivially common token (``api``, ``v2``, ``1``) right after a key-ish
  marker segment (``/key/``, ``/token/``, ``/v3/`` …). A plain word (``testnet``, ``electrumx``)
  or a number (a block height) in a path is not a credential, and scrubbing it deleted that word
  from every message that mentioned it.
* query parameter NAMES (``apikey``) and the host are not secret and are kept.
* matching is WHOLE-TOKEN: a part is replaced only where it is not inside a longer run of letters
  and digits, so a query value that happens to occur inside a txid, or a path word inside a
  hostname, is left alone. A percent-escape counts as a boundary (``%2F<key>``).
* matching is case-insensitive, and each character may appear literally or percent-encoded
  (``~`` or ``%7E``, ``/`` or ``%2F``, a space as ``%20`` or ``+``), so a server that re-encodes or
  upper-cases what it echoes is still caught.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

__all__ = ["redact_endpoint_secrets", "redact_endpoints_in", "redacted_url", "secret_parts"]

_REDACTED = "<redacted>"

#: A trivially common token (``api``, ``v2``, ``1``): never a credential, even after a marker.
_COMMON_TOKEN = re.compile(r"[A-Za-z]{1,5}|[vV]\d{1,3}|\d{1,5}")

#: A path segment after one of these is a credential unless it is a common token.
_KEY_MARKER = re.compile(r"(?i)[vV]\d{1,3}|key|keys|apikey|api[-_]key|token|tokens|auth|secret|access|private")

#: A path segment at least this long is treated as a credential.
_LONG_SEGMENT = 16
#: ...and one at least this long that mixes letters and digits.
_MIXED_SEGMENT = 8


def redacted_url(url: object) -> str:
    """Name an endpoint by scheme, host and port only — the form every message uses.

    ``wss://user:pw@host:50022/key?x=1`` -> ``wss://host:50022``. A URL with no parseable host
    names no host rather than echoing its text, which could be the credential itself.
    """
    if not isinstance(url, str) or not url.strip():
        return "<no endpoint configured>"
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<an endpoint URL that does not parse>"
    if not host:
        return "<an endpoint URL with no parseable host>"
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    scheme = f"{parts.scheme}://" if parts.scheme else ""
    return f"{scheme}{host}" + (f":{port}" if port is not None else "")


def secret_parts(url: str) -> list[str]:
    """Every part of *url* that can carry a credential, percent-decoded (rule: module doc)."""
    try:
        parts = urlsplit(url)
        username, password = parts.username, parts.password
    except ValueError:
        # An unparseable URL: everything after the scheme, and each delimited piece of it.
        rest = url.split("://", 1)[-1]
        pieces = [rest, *re.split(r"[/?#&=@:;\[\]]", rest)]
        return [unquote(p) for p in pieces if p and not _COMMON_TOKEN.fullmatch(unquote(p))]
    out = [unquote(u) for u in (username, password) if u]
    prev = ""
    for raw_seg in parts.path.split("/"):
        seg = unquote(raw_seg)
        if seg and _looks_like_a_credential(seg, after=prev):
            out.append(seg)
        prev = seg or prev
    out += [v for _, v in parse_qsl(parts.query, keep_blank_values=True) if v]
    if parts.fragment:
        out.append(unquote(parts.fragment))
        out += [v for _, v in parse_qsl(parts.fragment, keep_blank_values=True) if v]
    return out


def _looks_like_a_credential(segment: str, *, after: str) -> bool:
    """A path segment that may be a key (rule: module doc). Userinfo and query values do not ask."""
    if len(segment) >= _LONG_SEGMENT:
        return True
    has_letter = any(c.isalpha() for c in segment)
    has_digit = any(c.isdigit() for c in segment)
    if len(segment) >= _MIXED_SEGMENT and has_letter and has_digit:
        return True
    return bool(_KEY_MARKER.fullmatch(after)) and not _COMMON_TOKEN.fullmatch(segment)


def _char_pattern(ch: str) -> str:
    """*ch* literally, or percent-encoded (its UTF-8 bytes), or ``+`` for a space."""
    alts = [re.escape(ch), "".join(f"%{b:02X}" for b in ch.encode("utf-8"))]
    if ch == " ":
        alts.append(r"\+")
    return "(?:" + "|".join(alts) + ")"


def _part_pattern(part: str) -> str:
    """*part* as a WHOLE TOKEN: not preceded or followed by a letter or digit, except that a
    percent-escape before it (``%2F``) is a boundary, not part of a longer word."""
    body = "".join(_char_pattern(ch) for ch in part)
    return rf"(?:(?<![A-Za-z0-9])|(?<=%[0-9A-Fa-f]{{2}})){body}(?![A-Za-z0-9])"


def redact_endpoint_secrets(text: str, urls: str | Sequence[str | None] | None) -> str:
    """Remove from *text* every credential-bearing part of each URL in *urls* (rule: module doc)."""
    if isinstance(urls, str):
        urls = [urls]
    parts: dict[str, None] = {}
    for url in urls or ():
        if isinstance(url, str) and url:
            for part in secret_parts(url):
                parts[part] = None
                # A '+' in a query value may have been a space on the wire, and vice versa.
                parts.setdefault(unquote_plus(part), None)
    for part in sorted(parts, key=len, reverse=True):
        if part:
            text = re.sub(_part_pattern(part), _REDACTED, text, flags=re.IGNORECASE)
    return text


def redact_endpoints_in(value: object, urls: str | Sequence[str | None] | None) -> object:
    """*value* with every endpoint URL in *urls* rendered as :func:`redacted_url` — RENDER-TIME.

    Walks dicts (keys and values), lists and tuples; every string has each whole URL replaced by
    its ``scheme://host:port`` form, then any credential part quoted on its own removed
    (:func:`redact_endpoint_secrets`). Other values are returned unchanged. Apply it where source
    labels become output, never before a rule compares them.
    """
    if isinstance(urls, str):
        urls = [urls]
    known = sorted({u for u in urls or () if isinstance(u, str) and u}, key=len, reverse=True)
    if not known:
        return value

    def walk(v: object) -> object:
        if isinstance(v, str):
            for u in known:
                if u in v:
                    v = v.replace(u, redacted_url(u))
            return redact_endpoint_secrets(v, known)
        if isinstance(v, dict):
            return {walk(k): walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(walk(x) for x in v)
        return v

    return walk(value)
