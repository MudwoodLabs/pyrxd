"""Roundtrip test for the published cross-impl dMint V2 conformance vectors.

Keeps ``conformance/dmint-v2-contract-vectors.json`` honest: a builder change that diverges from the
published canonical bytecode fails CI. Other Radiant implementations byte-compare their own V2 dMint
contract build against this JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintDeployParams, build_dmint_contract_script
from pyrxd.glyph.types import GlyphRef

_VECTORS = Path(__file__).resolve().parent.parent / "conformance" / "dmint-v2-contract-vectors.json"


def _params_from_json(p: dict) -> DmintDeployParams:
    return DmintDeployParams(
        contract_ref=GlyphRef(txid=p["contract_ref"]["txid"], vout=p["contract_ref"]["vout"]),
        token_ref=GlyphRef(txid=p["token_ref"]["txid"], vout=p["token_ref"]["vout"]),
        max_height=p["max_height"],
        reward=p["reward"],
        difficulty=p["difficulty"],
        algo=DmintAlgo[p["algo"]],
        daa_mode=DaaMode[p["daa_mode"]],
        target_time=p["target_time"],
        half_life=p["half_life"],
        height=p["height"],
        last_time=p["last_time"],
        epoch_length=p["epoch_length"],
        max_adjustment_log2=p["max_adjustment_log2"],
        schedule=tuple(tuple(x) for x in p["schedule"]),
    )


def test_conformance_vectors_roundtrip():
    doc = json.loads(_VECTORS.read_text())
    assert doc["schema"] == "radiant-dmint-v2-contract/1"
    assert doc["vectors"], "no conformance vectors"
    for v in doc["vectors"]:
        built = build_dmint_contract_script(_params_from_json(v["params"])).hex()
        assert built == v["contract_script_hex"], (
            f"conformance vector {v['id']!r} diverged from the published bytecode — regenerate the suite "
            "or fix the builder"
        )


def test_suite_covers_all_daa_modes_and_a_mainnet_anchor():
    doc = json.loads(_VECTORS.read_text())
    modes = {v["params"]["daa_mode"] for v in doc["vectors"]}
    assert modes == {"FIXED", "LWMA", "ASERT", "EPOCH", "SCHEDULE"}, f"missing DAA-mode coverage: {modes}"
    assert any(v["source"].startswith("mainnet:") for v in doc["vectors"]), "no mainnet-anchored vector"
