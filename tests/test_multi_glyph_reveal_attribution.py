"""A multi-glyph reveal must not report one glyph's metadata as the transaction's.

`GlyphInspector.find_reveal_metadata` returns the FIRST input whose scriptSig
carries a decodable `gly` payload, and that single payload was reported as the
whole transaction's metadata.

Multi-glyph reveals are real and not rare on Radiant mainnet. One observed reveal
mints **35 refs from 36 inputs**; another mints 5 from 7. In the first case
thirty-four refs were being shown a different token's name, description and media.

The fix is additive rather than a shape change, because `inspect --json` has
consumers: `metadata` still carries the first payload and the `input_index` it
came from, and now also `of_n_payloads` when there is more than one, alongside a
new `metadata_inputs` listing every input that carries a payload.
"""

from __future__ import annotations

import cbor2

from pyrxd.glyph._inspect_core import _classify_raw_tx
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput


def _gly_scriptsig(name: str, ticker: str = "") -> bytes:
    """A reveal scriptSig: <sig> <pubkey> "gly" <CBOR>, as the chain carries it."""
    body: dict = {"p": [2], "name": name}
    if ticker:
        body["ticker"] = ticker
    cbor = cbor2.dumps(body)

    def push(b: bytes) -> bytes:
        if len(b) <= 0x4B:
            return bytes([len(b)]) + b
        if len(b) <= 0xFF:
            return b"\x4c" + bytes([len(b)]) + b
        return b"\x4d" + len(b).to_bytes(2, "little") + b

    pub = PrivateKey().public_key().serialize()
    return push(b"\x30" * 71) + push(pub) + push(b"gly") + push(cbor)


def _tx_with(scriptsigs: list[bytes]) -> bytes:
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="ab" * 32,
                source_output_index=i,
                unlocking_script=Script(ss),
            )
            for i, ss in enumerate(scriptsigs)
        ],
        tx_outputs=[TransactionOutput(locking_script=Script(b"\x6a"), satoshis=0)],
    )
    return tx.serialize()


def _classify(scriptsigs: list[bytes]) -> dict:
    from pyrxd.hash import hash256

    raw = _tx_with(scriptsigs)
    txid = hash256(raw)[::-1].hex()
    return _classify_raw_tx(txid, raw)


class TestSingleGlyphIsUnchanged:
    """The common case must not grow noise, or the fix costs more than it buys."""

    def test_one_payload_reports_no_count_and_one_entry(self) -> None:
        row = _classify([_gly_scriptsig("Solo", "SOLO")])
        assert row["metadata"]["name"] == "Solo"
        assert "of_n_payloads" not in row["metadata"], "no count when there is nothing to disambiguate"
        assert [e["input_index"] for e in row["metadata_inputs"]] == [0]


class TestMultiGlyphRevealIsAttributedPerInput:
    def test_every_payload_is_listed_with_its_own_input(self) -> None:
        """The regression: three glyphs in one reveal, three distinct names."""
        row = _classify([_gly_scriptsig(n) for n in ("Alpha", "Beta", "Gamma")])
        assert [(e["input_index"], e["name"]) for e in row["metadata_inputs"]] == [
            (0, "Alpha"),
            (1, "Beta"),
            (2, "Gamma"),
        ]

    def test_the_headline_payload_SAYS_it_is_one_of_several(self) -> None:
        """A caller reading only `metadata` must not mistake one glyph's fields for
        the transaction's — which is exactly what happened before."""
        row = _classify([_gly_scriptsig(n) for n in ("Alpha", "Beta", "Gamma")])
        assert row["metadata"]["of_n_payloads"] == 3
        assert row["metadata"]["input_index"] == 0

    def test_a_payload_on_a_LATER_input_is_not_lost(self) -> None:
        """Funding inputs come first in plenty of real reveals, so the first input
        carrying a payload is often not input 0."""
        row = _classify([b"\x00", b"\x00", _gly_scriptsig("Late")])
        assert row["metadata"]["input_index"] == 2
        assert [e["name"] for e in row["metadata_inputs"]] == ["Late"]

    def test_the_35_of_36_shape_seen_on_mainnet(self) -> None:
        """Scaled shape of a real reveal: one funding input, then a payload each."""
        names = [f"Glyph{i}" for i in range(35)]
        row = _classify([b"\x00"] + [_gly_scriptsig(n) for n in names])
        assert len(row["metadata_inputs"]) == 35
        assert row["metadata"]["of_n_payloads"] == 35
        # every one distinct, and none attributed to the funding input
        assert [e["name"] for e in row["metadata_inputs"]] == names
        assert all(e["input_index"] >= 1 for e in row["metadata_inputs"])
