"""Endpoint redaction is STRUCTURAL: derived from the URL's parts, not a list of exact strings.

The cases below are the ones a hostile review found leaking through the earlier exact-match
scrub: a short password, a server that re-encodes (``~`` -> ``%7E``, ``/`` -> ``%2F``), one that
upper-cases what it echoes, and a fragment. Each pairs with an honest-path check that ordinary
words are NOT deleted from the message.
"""

from __future__ import annotations

import pytest

from pyrxd.network.redaction import redact_endpoint_secrets, redacted_url, secret_parts

LEAKS = [
    # (url, text the server/library echoed, the secret that must not survive)
    ("https://u:SHORTPW@h.io/x", "basic auth failed for u:SHORTPW@h.io", "SHORTPW"),
    ("https://u:pw1@h.io/x", "basic auth failed for u:pw1@h.io", "pw1"),
    ("https://h.io/v2/Ab-Cd_Ef~SECRETKEY", "echo /v2/Ab-Cd_Ef%7ESECRETKEY", "SECRETKEY"),
    ("https://h.io/?apikey=SEC%2FRET99", "echo apikey=SEC/RET99", "RET99"),
    ("https://h.io/?apikey=SEC/RET99", "echo apikey=SEC%2FRET99", "RET99"),
    ("https://h.io/?apikey=SEC/RET99", "echo apikey=sec%2fret99", "ret99"),
    ("https://h.io/v3/abcdef0123456789", "key ABCDEF0123456789 invalid", "ABCDEF0123456789"),
    ("https://h.io/#frag=SECRETFRAG", "x SECRETFRAG", "SECRETFRAG"),
    ("https://h.io/k/SECRET12345", "https://H.IO/k/SECRET12345", "SECRET12345"),
    ("https://h.io/k/SECRET12345?a=1", "'h.io', '/k/SECRET12345'", "SECRET12345"),
    ("https://h.io/k/SECRET 12345", "/k/SECRET%2012345", "12345"),
    ("https://h.io/k/SECRET 12345", "/k/SECRET+12345", "12345"),
    ("wss://FAKEUSER:FAKEPW@127.0.0.1:1/FAKEPATH?key=FAKEQUERY", "wss://fakeuser:fakepw@127.0.0.1:1/", "fakepw"),
]


@pytest.mark.parametrize(("url", "text", "secret"), LEAKS)
def test_secret_parts_never_survive(url: str, text: str, secret: str) -> None:
    out = redact_endpoint_secrets(text, url)
    assert secret.lower() not in out.lower(), out
    assert "<redacted>" in out


def test_common_tokens_and_the_host_are_kept() -> None:
    """Honest path: ``v2``, ``api``, digits-only port-like segments and the host stay readable."""
    url = "https://rpc.example.org:8545/api/v2/1/MYKEY12345"
    out = redact_endpoint_secrets("GET https://rpc.example.org:8545/api/v2/1/MYKEY12345 -> 401", url)
    assert out == "GET https://rpc.example.org:8545/api/v2/1/<redacted> -> 401"
    assert secret_parts(url) == ["MYKEY12345"]


def test_a_short_password_is_matched_only_as_a_whole_token() -> None:
    """A two-letter password must not delete those letters from every word of the message."""
    url = "https://u:ab@h.io/"
    out = redact_endpoint_secrets("about ab tab: ab@h.io", url)
    assert out == "about <redacted> tab: <redacted>@h.io"


def test_query_parameter_names_are_kept() -> None:
    out = redact_endpoint_secrets("apikey=K3Y-VALUE-99", "https://h.io/?apikey=K3Y-VALUE-99")
    assert out == "apikey=<redacted>"


@pytest.mark.parametrize(
    ("url", "label"),
    [
        ("wss://user:pw@host.example:50022/key123456?x=SECRET99#frag", "wss://host.example:50022"),
        ("https://h.io/v2/KEY", "https://h.io"),
        ("http://[::1]:8332/x", "http://[::1]:8332"),
        ("http://[::1/v2/FAKEPATHSECRET0123", "<an endpoint URL that does not parse>"),
        ("http:///v2/FAKEPATHSECRET0123", "<an endpoint URL with no parseable host>"),
        ("", "<no endpoint configured>"),
    ],
)
def test_redacted_url_keeps_scheme_host_port_only(url: str, label: str) -> None:
    assert redacted_url(url) == label


def test_an_unparseable_url_still_has_its_pieces_redacted() -> None:
    url = "http://[::1/v2/FAKEPATHSECRET0123"
    assert "FAKEPATHSECRET0123" not in redact_endpoint_secrets("path FAKEPATHSECRET0123 bad", url)
