"""Output formatter snapshot tests."""

from __future__ import annotations

import json

import pytest

from pyrxd.cli.format import emit, emit_table, format_photons, sanitize_terminal


class TestSanitizeTerminal:
    def test_plain_text_unchanged(self) -> None:
        assert sanitize_terminal("bc1qexample") == "bc1qexample"
        assert sanitize_terminal("rxd ↔ btc") == "rxd ↔ btc"  # printable non-ASCII passes

    def test_escapes_c0_control_and_esc(self) -> None:
        assert sanitize_terminal("\x1b[2J") == "\\x1b[2J"  # ESC escaped, '[2J' printable
        assert sanitize_terminal("a\nb\tc") == "a\\x0ab\\x09c"
        assert sanitize_terminal("x\x7fy") == "x\\x7fy"  # DEL

    def test_escapes_c1_control(self) -> None:
        assert sanitize_terminal("\x9b") == "\\x9b"  # C1 CSI

    def test_none_is_empty(self) -> None:
        assert sanitize_terminal(None) == ""

    def test_max_len_truncates_before_escaping(self) -> None:
        assert sanitize_terminal("abcdef", max_len=3) == "abc…"


class TestFormatPhotons:
    def test_zero(self) -> None:
        assert format_photons(0) == "0 photons (0.00000000 RXD)"

    def test_one_rxd(self) -> None:
        assert "100,000,000 photons" in format_photons(100_000_000)
        assert "1.00000000 RXD" in format_photons(100_000_000)

    def test_with_rxd_false(self) -> None:
        assert format_photons(1234, with_rxd=False) == "1,234 photons"

    def test_rejects_bool(self) -> None:
        with pytest.raises(TypeError):
            format_photons(True)  # type: ignore[arg-type]


class TestEmit:
    def test_human_with_lines(self) -> None:
        out = emit({"a": 1}, mode="human", human_lines=["line one", "line two"])
        assert out == "line one\nline two"

    def test_human_default_kv(self) -> None:
        out = emit({"a": 1, "b": 2}, mode="human")
        assert out == "a: 1\nb: 2"

    def test_json(self) -> None:
        out = emit({"x": 1, "y": "two"}, mode="json")
        parsed = json.loads(out)
        assert parsed == {"x": 1, "y": "two"}

    def test_quiet_with_field(self) -> None:
        out = emit({"address": "1Abc"}, mode="quiet", quiet_field="address")
        assert out == "1Abc"

    def test_quiet_without_field_is_blank(self) -> None:
        assert emit({"x": 1}, mode="quiet") == ""


class TestEmitTable:
    def test_human_renders_header(self) -> None:
        rows = [{"a": "x", "b": "y"}, {"a": "p", "b": "q"}]
        out = emit_table(rows, ["a", "b"], mode="human")
        assert "a  " in out  # padded header
        assert "x" in out
        assert "y" in out

    def test_human_empty_says_none(self) -> None:
        assert emit_table([], ["a"], mode="human") == "(none)"

    def test_json(self) -> None:
        rows = [{"a": 1}]
        parsed = json.loads(emit_table(rows, ["a"], mode="json"))
        assert parsed == rows

    def test_quiet_field(self) -> None:
        rows = [{"x": "one"}, {"x": "two"}]
        assert emit_table(rows, ["x"], mode="quiet", quiet_field="x") == "one\ntwo"
