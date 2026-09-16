"""RxinDexerClient discovery wrappers (indexer Glyph schema v4).

Covers ``glyph_get_recent`` and ``glyph_get_tokens_by_type``: positional
param marshalling (aiorpcX maps the list onto the server handler signature),
result-shape validation, and the order guard.
"""

from __future__ import annotations

import pytest

from pyrxd.network.rxindexer import RxinDexerClient, RxinDexerError


class FakeElectrumXClient:
    """Canned-response transport double (mirrors tests/test_glyph_wave.py)."""

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, list]] = []

    async def call_extension(self, method: str, params: list | None = None):
        self.calls.append((method, params or []))
        if method not in self.responses:
            raise RuntimeError(f"no canned response for {method}")
        result = self.responses[method]
        if isinstance(result, Exception):
            raise result
        return result(params) if callable(result) else result


PAGE = {
    "tokens": [
        {
            "ref": "aa" * 32 + "_0",
            "type": 2,
            "type_name": "NFT",
            "name": "T",
            "deploy_height": 447786,
        }
    ],
    "next_cursor": "R1H_-SrW",
}


class TestGlyphGetRecent:
    async def test_returns_page_and_marshals_params(self):
        client = FakeElectrumXClient({"glyph.get_recent": PAGE})
        idx = RxinDexerClient(client)
        page = await idx.glyph_get_recent(limit=2, cursor="CUR", token_type=2)
        assert page["tokens"][0]["deploy_height"] == 447786
        assert page["next_cursor"] == "R1H_-SrW"
        # Positional order must match the server handler signature:
        # glyph_get_recent(limit, cursor, token_type)
        assert client.calls == [("glyph.get_recent", [2, "CUR", 2])]

    async def test_defaults(self):
        client = FakeElectrumXClient({"glyph.get_recent": PAGE})
        idx = RxinDexerClient(client)
        await idx.glyph_get_recent()
        assert client.calls == [("glyph.get_recent", [100, None, None])]

    async def test_non_dict_result_raises(self):
        client = FakeElectrumXClient({"glyph.get_recent": ["not", "a", "dict"]})
        idx = RxinDexerClient(client)
        with pytest.raises(RxinDexerError, match="expected dict"):
            await idx.glyph_get_recent()

    async def test_transport_error_wrapped(self):
        client = FakeElectrumXClient({"glyph.get_recent": RuntimeError("boom")})
        idx = RxinDexerClient(client)
        with pytest.raises(RxinDexerError, match="glyph.get_recent"):
            await idx.glyph_get_recent()


class TestGlyphGetTokensByType:
    async def test_returns_page_and_marshals_params(self):
        client = FakeElectrumXClient({"glyph.get_tokens_by_type": PAGE})
        idx = RxinDexerClient(client)
        page = await idx.glyph_get_tokens_by_type(5, limit=3, cursor="C", order="recent")
        assert page["next_cursor"] == "R1H_-SrW"
        # glyph_get_tokens_by_type(token_type, limit, cursor, order)
        assert client.calls == [("glyph.get_tokens_by_type", [5, 3, "C", "recent"])]

    async def test_default_order_is_legacy_ref(self):
        client = FakeElectrumXClient({"glyph.get_tokens_by_type": PAGE})
        idx = RxinDexerClient(client)
        await idx.glyph_get_tokens_by_type(1)
        assert client.calls == [("glyph.get_tokens_by_type", [1, 100, None, "ref"])]

    async def test_invalid_order_rejected_before_transport(self):
        client = FakeElectrumXClient()
        idx = RxinDexerClient(client)
        with pytest.raises(ValueError, match="order"):
            await idx.glyph_get_tokens_by_type(2, order="sideways")
        assert client.calls == []  # never hit the wire

    async def test_non_dict_result_raises(self):
        client = FakeElectrumXClient({"glyph.get_tokens_by_type": None})
        idx = RxinDexerClient(client)
        with pytest.raises(RxinDexerError, match="expected dict"):
            await idx.glyph_get_tokens_by_type(2)
