"""Endpoint redaction is STRUCTURAL: derived from the URL's parts, not a list of exact strings.

The cases below are the ones a hostile review found leaking through the earlier exact-match
scrub: a short password, a server that re-encodes (``~`` -> ``%7E``, ``/`` -> ``%2F``), one that
upper-cases what it echoes, and a fragment. Each pairs with an honest-path check that ordinary
words are NOT deleted from the message.
"""

from __future__ import annotations

import pytest

from pyrxd.network.redaction import redact_endpoint_secrets, redact_endpoints_in, redacted_url, secret_parts

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


def test_redact_endpoints_in_renders_every_label_in_a_payload() -> None:
    """Render-time: source labels are raw URLs internally; in the output each is scheme://host:port,
    wherever it sits — a value, a key, inside a sentence, in a list — and nothing else changes."""
    url = "wss://U53R:PW0RD@h.example:50022/KEYPATH12345?apikey=QVAL6789"
    payload = {
        "binding_source": url,
        "heights": {"by_source": [{"source": url, "mark": 7}], url: True},
        "reason": f"'{url}' says 458580; also QVAL6789 echoed",
        "steps": ("ab" * 32, 3),
    }
    out = redact_endpoints_in(payload, [url, None, ""])
    assert out == {
        "binding_source": "wss://h.example:50022",
        "heights": {"by_source": [{"source": "wss://h.example:50022", "mark": 7}], "wss://h.example:50022": True},
        "reason": "'wss://h.example:50022' says 458580; also <redacted> echoed",
        "steps": ("ab" * 32, 3),
    }
    assert redact_endpoints_in(payload, ()) is payload  # nothing configured: unchanged


# --------------------------------------------------------------------------- round 3, Q2: whole tokens

TXID = "00deadbeef00112233" + "44" * 23


@pytest.mark.parametrize(
    ("url", "text"),
    [
        # a query value that happens to occur inside a txid
        ("https://h.io/?apikey=deadbeef00112233", f"spent by {TXID}:1"),
        # a path WORD in prose, and in a hostname
        ("wss://h.example:50022/testnet", "switch the wallet to testnet first"),
        ("wss://electrumx.h.example/electrumx", "wss://electrumx.h.example:50022 did not answer"),
        # a block height in a path, and the same number in a message
        ("https://h.io/blocks/458591", "the mark is at height 458591"),
        # a long password inside a longer word is not that password
        ("https://u:hunter2222@h.io/", "hunter2222x is not the password"),
    ],
)
def test_words_txids_and_heights_that_merely_contain_a_part_are_untouched(url: str, text: str) -> None:
    assert redact_endpoint_secrets(text, url) == text


@pytest.mark.parametrize(
    ("url", "text", "secret"),
    [
        ("https://h.io/?apikey=deadbeef00112233", "bad key deadbeef00112233", "deadbeef00112233"),
        ("https://h.io/?k=x1", "k=x1 rejected", "x1"),  # a query value at ANY length
        ("https://u:p@h.io/", "auth u:p@h.io", ":p@"),  # userinfo at any length
        ("https://h.io/v2/shortkey", "/v2/shortkey denied", "shortkey"),  # after a key marker
        ("https://h.io/abc123xyz", "path abc123xyz", "abc123xyz"),  # mixed letters + digits, 8+
        ("https://h.io/v3/" + "f" * 32, "%2Fv3%2F" + "F" * 32, "F" * 32),  # a percent-escape is a boundary
    ],
)
def test_real_keys_are_still_redacted_as_whole_tokens(url: str, text: str, secret: str) -> None:
    out = redact_endpoint_secrets(text, url)
    assert secret.lower() not in out.lower(), out
    assert "<redacted>" in out
