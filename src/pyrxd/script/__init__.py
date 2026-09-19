"""Script types, templates, and evaluation for Radiant transactions.

The public re-exports below are resolved lazily via PEP 562
``__getattr__`` so importing ``pyrxd.script.script`` (used by the
inspect tool's ``Transaction`` parser) doesn't transitively pull
``pyrxd.script.type`` and through it ``pyrxd.keys`` →  ``coincurve``.

See :mod:`pyrxd` for the broader rationale on lazy public re-exports.
"""

from __future__ import annotations

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "BareMultisig": ("pyrxd.script.type", "BareMultisig"),
    "CsvKind": ("pyrxd.script.timelock", "CsvKind"),
    "LOCKTIME_THRESHOLD": ("pyrxd.script.timelock", "LOCKTIME_THRESHOLD"),
    "OpReturn": ("pyrxd.script.type", "OpReturn"),
    "P2PK": ("pyrxd.script.type", "P2PK"),
    "P2PKH": ("pyrxd.script.type", "P2PKH"),
    "Script": ("pyrxd.script.script", "Script"),
    "ScriptChunk": ("pyrxd.script.script", "ScriptChunk"),
    "ScriptTemplate": ("pyrxd.script.type", "ScriptTemplate"),
    "Unknown": ("pyrxd.script.type", "Unknown"),
    "build_csv_sequence": ("pyrxd.script.timelock", "build_csv_sequence"),
    "build_p2pkh_with_cltv_script": (
        "pyrxd.script.timelock",
        "build_p2pkh_with_cltv_script",
    ),
    "build_p2pkh_with_csv_script": (
        "pyrxd.script.timelock",
        "build_p2pkh_with_csv_script",
    ),
    # HashMark, a third-party OP_RETURN format (see `hashmark.py`). Both sides now
    # have in-repo callers: the READ side through the inspector, the WRITE side
    # through `pyrxd.hashmark_tx` and `pyrxd mark` (W5 of
    # `docs/plans/2026-09-18-feat-sealed-attestation-poc-plan.md`). They stay exported
    # as a set because pyrxd is a published library and writing a mark is mostly
    # something a consumer does — one that encodes should be able to decode back
    # without reaching into the submodule.
    #
    # Safe to list here despite this module's no-coincurve rule: `hashmark.py`
    # imports `pyrxd.keys` lazily INSIDE the functions that sign, so importing it
    # pulls no curve binding.
    "algorithm_for": ("pyrxd.script.hashmark", "algorithm_for"),
    "canonicalize_label": ("pyrxd.script.hashmark", "canonicalize_label"),
    "decode_hashmark": ("pyrxd.script.hashmark", "decode_hashmark"),
    "encode_hashmark": ("pyrxd.script.hashmark", "encode_hashmark"),
    "max_label_bytes": ("pyrxd.script.hashmark", "max_label_bytes"),
    "verify_attestation": ("pyrxd.script.hashmark", "verify_attestation"),
}

__all__ = sorted(_LAZY_EXPORTS.keys())


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pyrxd.script' has no attribute {name!r}")
    module_path, attr = target
    import importlib

    obj = getattr(importlib.import_module(module_path), attr)
    globals()[name] = obj
    return obj


def __dir__() -> list[str]:
    return __all__
