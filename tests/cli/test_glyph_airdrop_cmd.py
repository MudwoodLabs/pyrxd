"""``pyrxd glyph airdrop-ft`` argument handling — no network.

Everything here fails (or would fail) before the first ElectrumX call, so it
covers exactly the layer this file can cover: recipient parsing from ``--to``
and from a file, and the refusals that must happen before a user is asked to
confirm a spend. The on-chain behaviour is proven in
``tests/test_ft_airdrop_regtest_e2e.py``.

Also covers the ``royalty`` block of a metadata file, which the CLI used to drop
silently — a creator could write one, mint, and get a token with no royalty in
its CBOR at all, permanently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.errors import UserError
from pyrxd.cli.glyph_cmds import _load_recipients_file, _parse_recipient_spec
from pyrxd.cli.glyph_helpers import _read_metadata_file
from pyrxd.cli.main import cli
from pyrxd.keys import PrivateKey

_ADDR_A = PrivateKey().public_key().address()
_ADDR_B = PrivateKey().public_key().address()
_REF = "ab" * 32 + ":0"


def _new_wallet_args(tmp_wallet_path: Path) -> list[str]:
    return ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"]


class TestRecipientSpecParsing:
    def test_address_amount(self):
        assert _parse_recipient_spec(f"{_ADDR_A}:250") == (_ADDR_A, 250)

    def test_splits_on_the_last_colon(self):
        """So a prefixed address form does not break the parse."""
        assert _parse_recipient_spec("rxd:qq1abc:7") == ("rxd:qq1abc", 7)

    def test_missing_amount_refused(self):
        with pytest.raises(UserError, match="malformed recipient") as exc:
            _parse_recipient_spec(_ADDR_A)
        assert exc.value.cause == "expected ADDRESS:AMOUNT"

    def test_non_integer_amount_refused(self):
        with pytest.raises(UserError, match="malformed recipient") as exc:
            _parse_recipient_spec(f"{_ADDR_A}:ten")
        assert "not an integer amount" in (exc.value.cause or "")

    def test_empty_address_refused(self):
        with pytest.raises(UserError, match="malformed recipient"):
            _parse_recipient_spec(":250")


class TestRecipientsFile:
    def test_csv(self, tmp_path: Path):
        p = tmp_path / "holders.csv"
        p.write_text(f"# a comment\n{_ADDR_A},250\n\n{_ADDR_B}, 100\n")
        assert _load_recipients_file(p) == [(_ADDR_A, 250), (_ADDR_B, 100)]

    def test_json(self, tmp_path: Path):
        p = tmp_path / "holders.json"
        p.write_text(json.dumps([{"address": _ADDR_A, "amount": 250}, {"address": _ADDR_B, "amount": 100}]))
        assert _load_recipients_file(p) == [(_ADDR_A, 250), (_ADDR_B, 100)]

    def test_csv_wrong_column_count_names_the_line(self, tmp_path: Path):
        p = tmp_path / "holders.csv"
        p.write_text(f"{_ADDR_A},250\n{_ADDR_B}\n")
        with pytest.raises(UserError, match=r":2 is not `address,amount`"):
            _load_recipients_file(p)

    def test_json_must_be_an_array(self, tmp_path: Path):
        p = tmp_path / "holders.json"
        p.write_text(json.dumps({"address": _ADDR_A, "amount": 1}))
        with pytest.raises(UserError, match="must be an array"):
            _load_recipients_file(p)

    def test_json_row_missing_a_key(self, tmp_path: Path):
        p = tmp_path / "holders.json"
        p.write_text(json.dumps([{"address": _ADDR_A}]))
        with pytest.raises(UserError, match="'address' and 'amount'"):
            _load_recipients_file(p)

    def test_malformed_json(self, tmp_path: Path):
        p = tmp_path / "holders.json"
        p.write_text("{not json")
        with pytest.raises(UserError, match="not valid JSON"):
            _load_recipients_file(p)


class TestAirdropCommandGuards:
    def test_no_recipients_refused(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(cli, ["--wallet", str(tmp_wallet_path), "glyph", "airdrop-ft", _REF])
        assert result.exit_code != 0
        assert "no recipients" in result.output.lower()

    def test_invalid_ref_refused(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "airdrop-ft", "no-colon", "--to", f"{_ADDR_A}:1"],
        )
        assert result.exit_code != 0
        assert "ref" in result.output.lower()

    def test_duplicate_address_refused(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """Paying twice cannot be undone, so a repeated row is refused."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "airdrop-ft",
                _REF,
                "--to",
                f"{_ADDR_A}:10",
                "--to",
                f"{_ADDR_A}:20",
            ],
        )
        assert result.exit_code != 0
        assert "more than once" in result.output.lower()

    def test_zero_amount_refused(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "airdrop-ft", _REF, "--to", f"{_ADDR_A}:0"],
        )
        assert result.exit_code != 0
        assert "must be > 0" in result.output

    def test_bad_address_refused(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "airdrop-ft", _REF, "--to", "not-an-address:10"],
        )
        assert result.exit_code != 0
        assert "invalid recipient address" in result.output.lower()

    def test_missing_recipients_file_refused(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "airdrop-ft",
                _REF,
                "--recipients",
                str(tmp_path / "nope.csv"),
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestMetadataRoyalty:
    """A royalty in metadata.json used to be silently dropped."""

    def _base(self) -> dict:
        return {"protocol": ["NFT"], "name": "T", "description": "d", "attrs": {}}

    def test_royalty_reaches_the_metadata(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 500, "address": _ADDR_A}}))
        md = _read_metadata_file(p)
        assert md.royalty is not None
        assert md.royalty.bps == 500
        assert md.royalty.address == _ADDR_A

    def test_royalty_survives_the_cbor_round_trip(self, tmp_path: Path):
        """The point of recording it: it has to land in the envelope."""
        from pyrxd.glyph.payload import decode_payload, encode_payload

        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {
                        "bps": 1000,
                        "address": _ADDR_A,
                        "enforced": True,
                        "minimum": 42,
                        "splits": [{"address": _ADDR_B, "bps": 400}],
                    },
                }
            )
        )
        md = _read_metadata_file(p)
        cbor_bytes, _payload_hash = encode_payload(md)
        decoded = decode_payload(cbor_bytes)
        assert decoded.royalty is not None
        assert decoded.royalty.bps == 1000
        assert decoded.royalty.minimum == 42
        assert decoded.royalty.splits == ((_ADDR_B, 400),)

    def test_absent_royalty_stays_none(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps(self._base()))
        assert _read_metadata_file(p).royalty is None

    def test_royalty_must_be_an_object(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": 500}))
        with pytest.raises(UserError, match="must be a JSON object"):
            _read_metadata_file(p)

    def test_royalty_needs_bps_and_address(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 500}}))
        with pytest.raises(UserError, match="both 'bps' and 'address'"):
            _read_metadata_file(p)

    def test_out_of_range_bps_refused(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 10_001, "address": _ADDR_A}}))
        with pytest.raises(UserError, match="failed validation"):
            _read_metadata_file(p)

    def test_splits_over_total_refused(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {
                        "bps": 100,
                        "address": _ADDR_A,
                        "splits": [{"address": _ADDR_B, "bps": 900}],
                    },
                }
            )
        )
        with pytest.raises(UserError, match="failed validation"):
            _read_metadata_file(p)

    def test_undecodable_address_refused_before_minting(self, tmp_path: Path):
        """GlyphRoyalty only checks non-empty, so this is the last chance."""
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 500, "address": "definitely-not-an-address"}}))
        with pytest.raises(UserError, match="not a valid Radiant address"):
            _read_metadata_file(p)

    def test_undecodable_split_address_refused(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {"bps": 500, "address": _ADDR_A, "splits": [{"address": "nope", "bps": 500}]},
                }
            )
        )
        with pytest.raises(UserError, match="not a valid Radiant address"):
            _read_metadata_file(p)

    def test_splits_must_be_a_list(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 500, "address": _ADDR_A, "splits": {}}}))
        with pytest.raises(UserError, match="must be a list"):
            _read_metadata_file(p)

    def test_non_integer_split_bps_is_a_clean_error_not_a_traceback(self, tmp_path: Path):
        """`int(s["bps"])` used to sit outside the guard and escape as ValueError."""
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {"bps": 500, "address": _ADDR_A, "splits": [{"address": _ADDR_B, "bps": "five"}]},
                }
            )
        )
        with pytest.raises(UserError, match="splits\\[0\\].bps is not an integer"):
            _read_metadata_file(p)

    def test_null_split_bps_is_a_clean_error(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {"bps": 500, "address": _ADDR_A, "splits": [{"address": _ADDR_B, "bps": None}]},
                }
            )
        )
        with pytest.raises(UserError, match="is not an integer"):
            _read_metadata_file(p)

    def test_top_level_typo_is_caught_even_when_splits_cover_the_whole_rate(self, tmp_path: Path):
        """Validating by running a payout probe missed exactly this.

        With splits summing to `bps` there is no residue, so the top-level
        address is never paid at the probe price and never got decoded — the
        typo was signed into the token's CBOR permanently.
        """
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {
                        "bps": 500,
                        "address": "TYPO-NOT-AN-ADDRESS",
                        "splits": [{"address": _ADDR_A, "bps": 250}, {"address": _ADDR_B, "bps": 250}],
                    },
                }
            )
        )
        with pytest.raises(UserError, match="royalty.address is not a valid Radiant address"):
            _read_metadata_file(p)

    def test_typo_is_caught_when_the_royalty_pays_nothing(self, tmp_path: Path):
        """bps=0 and no minimum: nothing is ever paid, so nothing was decoded."""
        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 0, "address": "TYPO-NOT-AN-ADDRESS"}}))
        with pytest.raises(UserError, match="not a valid Radiant address"):
            _read_metadata_file(p)

    def test_split_typo_names_the_index(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {
                    **self._base(),
                    "royalty": {"bps": 500, "address": _ADDR_A, "splits": [{"address": "TYPO", "bps": 500}]},
                }
            )
        )
        with pytest.raises(UserError, match=r"splits\[0\].address is not a valid"):
            _read_metadata_file(p)

    def test_split_row_missing_keys(self, tmp_path: Path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps({**self._base(), "royalty": {"bps": 500, "address": _ADDR_A, "splits": [{"bps": 500}]}})
        )
        with pytest.raises(UserError, match="'address' and 'bps'"):
            _read_metadata_file(p)

    def test_confirmation_summary_says_advisory(self, tmp_path: Path):
        """A creator must not read the summary as a guarantee."""
        from pyrxd.cli.glyph_helpers import _metadata_summary

        p = tmp_path / "m.json"
        p.write_text(json.dumps({**self._base(), "royalty": {"bps": 500, "address": _ADDR_A}}))
        summary = _metadata_summary(_read_metadata_file(p))
        joined = "\n".join(summary.lines)
        assert "ADVISORY" in joined
        assert "not enforced by consensus" in joined
