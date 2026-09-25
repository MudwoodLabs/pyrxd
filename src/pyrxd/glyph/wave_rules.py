"""What a WAVE claim pyrxd writes must satisfy. ONE definition; every write door calls it.

A WAVE claim is registered by an INDEXER, not by consensus. Radiant accepts any payload
under the ``[NFT, MUT, WAVE]`` marker, so a claim the indexer declines confirms, spends its
fee, and registers nothing, and no error reaches anyone. Through 0.24.0 every claim
:func:`~pyrxd.glyph.wave.build_wave_metadata` built was of that kind (#728): it put
``"alice.rxd"`` in ``attrs.name``, and the indexer refuses the ``.``.

THE LABEL RULE is the intersection of the three sources that define an acceptable name:

- the WAVE protocol: "Register names 3-63 chars (a-z, 0-9, hyphen)"
  (Radiant-Core/WAVE-Protocol ``ANNOUNCEMENT.md:65`` at ``c05b8e7a``);
- Photonic Wallet, the reference client: ``validateWaveName`` refuses under 3 characters
  (``packages/lib/src/wave.ts:32``), and ``isValidWaveName``'s pattern
  ``^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`` allows lowercase only, with no leading or
  trailing hyphen (``packages/lib/src/wavenaming.ts:105-111``); its resolver applies the
  same minimum (``packages/app/src/hooks/useWaveResolver.ts:129``), all at ``becf41a7``;
- RXinDexer, the indexer that registers claims: ``validate_wave_name``
  (``electrumx/server/wave_index.py:287-310`` at ``ca8a6a4e``) — at most 63 characters,
  ``a-z 0-9 -`` after lower-casing, no leading or trailing hyphen, and no ``--`` unless the
  label starts ``xn--``. Its minimum is 1 (``WAVE_MIN_NAME_LENGTH``, line 41); that is the
  outlier, and the protocol and Photonic's 3 are followed here.

So a label is 3-63 characters of ``a-z``, ``0-9`` and ``-``; it does not start or end with
``-``; and it contains ``--`` only if it starts ``xn--``. Uppercase is REFUSED rather than
lower-cased: the indexer would register ``alice`` for ``Alice``, but the claim would then
carry text that is not the name it registers, and Photonic refuses it outright. A non-ASCII
name is written as punycode (``xn--caf-dma`` for ``café``) — the one form every source above
accepts. Because the rule is ASCII-only, a NON-ASCII look-alike label (Cyrillic ``і`` in
``casіno``, U+212A KELVIN SIGN for ``k``) is refused by construction, with no Unicode table.
An ASCII look-alike (``paypa1``, ``rn`` for ``m``) is NOT refused — no rule here, and none in
#698's homograph check before it, judges which all-ASCII names are too similar to another.

THE DOMAIN is exactly ``rxd``. Subdomains (``pay.alice.rxd``) are "Planned" in the WAVE
protocol (``ANNOUNCEMENT.md:70``), and RXinDexer compares the parent against ``'rxd'``
exactly (``wave_index.py:716``), so ``RXD`` would be looked up as a parent name.

THE NAME CHECKED IS THE ONE THE INDEXER READS. RXinDexer's live claim path takes the name
from ``attrs.name``, falling back to ``app.data.name``, and the parent from
``app.data.parent``, falling back to ``attrs.domain`` (``wave_index.py:711-717``). Checking
``attrs.name`` alone would let an ``app.data.name`` of ``alice.rxd``, or a parent hidden in
``app.data``, straight past. The top-level ``name`` is what the indexer's one-time backfill
reads (``wave_index.py:1378-1391``), so it must name the same claim or be absent.
"""

from __future__ import annotations

from typing import Any, Final

import cbor2

from ..security.errors import ValidationError
from .types import GlyphProtocol

WAVE_LABEL_MIN_LENGTH: Final = 3
WAVE_LABEL_MAX_LENGTH: Final = 63
WAVE_LABEL_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
WAVE_ROOT_DOMAIN: Final = "rxd"
#: Where the protocol lists subdomains as not yet specified.
_SUBDOMAINS_PLANNED: Final = (
    "pyrxd writes top-level <label>.rxd names only: subdomains such as pay.alice.rxd are "
    "'Planned' in the WAVE protocol (Radiant-Core/WAVE-Protocol ANNOUNCEMENT.md:70)"
)


def wave_label_problem(label: object) -> str | None:
    """Why ``label`` is not an acceptable WAVE label, or ``None`` if it is. See the module docstring."""
    if not isinstance(label, str):
        return f"must be text, got {type(label).__name__}"
    # Characters before length, so a two-character non-ASCII name (``中文``) is told about
    # punycode — the fix — rather than about its length.
    bad = sorted({c for c in label if c not in WAVE_LABEL_CHARS})
    if bad:
        why = f"contains {''.join(bad)!r}; a WAVE label is lowercase a-z, 0-9 and '-' only"
        if "." in bad:
            why += f" — it is a single label, not a dotted name; {_SUBDOMAINS_PLANNED}"
        elif any(c.isascii() and c.isupper() for c in bad):
            why += " — uppercase is refused, not lower-cased, so the claim carries the name it registers"
        elif any(not c.isascii() for c in bad):
            why += " — write a non-ASCII name as xn-- punycode"
        return why
    if not WAVE_LABEL_MIN_LENGTH <= len(label) <= WAVE_LABEL_MAX_LENGTH:
        return (
            f"is {len(label)} characters; a WAVE label is {WAVE_LABEL_MIN_LENGTH}-{WAVE_LABEL_MAX_LENGTH} "
            f"(WAVE protocol, Photonic)"
        )
    if label.startswith("-") or label.endswith("-"):
        return "starts or ends with '-'"
    if "--" in label and not label.startswith("xn--"):
        return "contains '--'; only an xn-- punycode label may"
    return None


def parse_wave_name(qualified: object) -> str:
    """``"alice.rxd"`` or ``"alice"`` → ``"alice"``. Refuses anything that is not ``<label>.rxd``.

    Splits on the FIRST dot, as Photonic's ``createWaveNameMetadata`` does, and then requires
    everything after it to be exactly ``rxd`` — so a name that would split differently under
    a last-dot rule (``sub.alice.rxd``) is refused either way rather than split into a claim
    nobody asked for.
    """
    if not isinstance(qualified, str):
        raise ValidationError(f"WAVE name must be text, got {type(qualified).__name__}")
    label, dot, domain = qualified.partition(".")
    if dot and domain != WAVE_ROOT_DOMAIN:
        if "." in domain:
            raise ValidationError(f"WAVE name {qualified!r} has more than one '.'; {_SUBDOMAINS_PLANNED}")
        hint = " (it must be lowercase)" if domain.lower() == WAVE_ROOT_DOMAIN else ""
        raise ValidationError(
            f"WAVE name {qualified!r} has domain {domain!r}; the domain must be exactly "
            f"{WAVE_ROOT_DOMAIN!r}{hint}. {_SUBDOMAINS_PLANNED}"
        )
    problem = wave_label_problem(label)
    if problem:
        raise ValidationError(f"WAVE label {label!r} {problem}")
    return label


def _is_wave_marked(d: object) -> bool:
    """Whether RXinDexer treats this payload as WAVE-marked — its own test, transcribed.

    RXinDexer takes ``protocols = metadata.get('p', [])`` (``electrumx/server/glyph_index.py:872``
    and ``:879``) and asks ``GlyphProtocol.GLYPH_WAVE not in protocols``
    (``electrumx/server/wave_index.py:685``), where ``GLYPH_WAVE`` is the plain int 11
    (``electrumx/lib/glyph.py:47``). That is Python's ``in``, so it holds for EVERY container
    CBOR decodes to, not only a list: an array (an element equal to 11), a byte string (a byte
    of value 11 — ``h'02050b'`` is WAVE-marked), and a map (a KEY equal to 11). This checked for
    a list or tuple only, so a payload with ``p: h'02050b'`` and ``attrs.name: "alice.rxd"``
    passed every writer while the indexer read it as a registration and refused the name.

    Where ``in`` cannot search the value (text, a number, null) it raises ``TypeError`` there,
    before the claim path — ``get_token_type`` (``electrumx/lib/glyph.py:727``) is the first
    ``in`` it meets — and the block processor skips that transaction's glyph overlay. So that
    is not a claim, and it is not one here either.
    """
    if not isinstance(d, dict):
        return False
    protocol = d.get("p", [])
    try:
        return int(GlyphProtocol.WAVE) in protocol
    except TypeError:
        return False


def indexed_wave_name(d: dict[str, Any]) -> tuple[object, object]:
    """``(name, parent)`` as RXinDexer's live claim path reads them (``wave_index.py:711-717``).

    Raises ``ValidationError`` where that code would itself raise on the payload (a
    non-map ``attrs``, ``app`` or ``app.data``) — the indexer skips such a claim.
    """
    attrs = d.get("attrs", {})
    app = d.get("app", {})
    data = app.get("data", {}) if isinstance(app, dict) else None
    if not isinstance(attrs, dict) or not isinstance(data, dict):
        raise ValidationError(
            "WAVE claim's attrs, app or app.data is not a map; RXinDexer's claim path cannot read "
            "it and skips the claim"
        )
    name = attrs.get("name", "") or data.get("name", "")
    parent = attrs.get("domain") if not data.get("parent") else data.get("parent")
    return name, parent


def wave_claim_problem(d: object) -> str | None:
    """Why a WAVE-marked payload would not register as a top-level ``.rxd`` name, or ``None``.

    Payloads whose ``p`` does not carry WAVE (11) are not WAVE claims and return ``None``.
    """
    if not isinstance(d, dict) or not _is_wave_marked(d):
        return None
    try:
        name, parent = indexed_wave_name(d)
    except ValidationError as exc:
        return str(exc)
    if not name:
        return (
            "carries no attrs.name. RXinDexer's live claim path registers a WAVE claim only from "
            "attrs.name (or app.data.name) and skips one without (wave_index.py:719-721); a "
            "top-level name alone is read only by a one-time backfill of an empty index"
        )
    problem = wave_label_problem(name)
    if problem:
        return f"attrs.name {name!r} {problem}"
    if parent not in (None, "", WAVE_ROOT_DOMAIN):
        return f"names parent/domain {parent!r}; {_SUBDOMAINS_PLANNED}"
    data_name = (d.get("app") or {}).get("data", {}).get("name")
    if data_name not in (None, "", name):
        return f"attrs.name {name!r} and app.data.name {data_name!r} name different claims"
    qualified = f"{name}.{WAVE_ROOT_DOMAIN}"
    for key in ("name", "n"):
        top = d.get(key)
        if top not in (None, "", qualified, name):
            return (
                f"top-level {key} {top!r} names a different claim from attrs ({qualified!r}); the "
                f"indexer's live path reads one and its backfill the other"
            )
    return None


def refuse_unregistrable_wave_claim(cbor: bytes | dict[str, Any], *, allow_unregistrable_wave: bool = False) -> None:
    """Refuse a WAVE-marked payload the indexer would not register. Every write door calls this.

    Called by :meth:`GlyphBuilder.prepare_commit` — the point of no return, since a commit can
    only be spent by revealing exactly the CBOR it commits to — and by both envelope writers,
    :func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix` (every reveal builder except the
    DAT one) and :func:`~pyrxd.glyph.payload.build_mutable_scriptsig` (an update whose ``p``
    carries WAVE is read by the indexer as a registration).

    ``allow_unregistrable_wave=True`` skips the check. It exists for ONE job: revealing a
    commit that is already on chain, made by pyrxd ≤0.24.0, whose committed CBOR has the old
    shape. That commit can only be spent by revealing those exact bytes, so refusing them
    would strand its value. The claim so revealed WILL NOT REGISTER with the indexer. It is
    accepted only by the reveal paths, never by :meth:`GlyphBuilder.prepare_commit`. How to
    rebuild that commit's exact bytes, and what happens if they are wrong, is in
    :meth:`GlyphBuilder.prepare_wave_reveal`.

    Bytes that are not a CBOR map are left alone: they are not a WAVE claim to any indexer,
    and the callers' own checks own them.
    """
    if allow_unregistrable_wave:
        return
    if isinstance(cbor, (bytes, bytearray)):
        try:
            d: object = cbor2.loads(bytes(cbor))
        except Exception:  # not decodable is not a WAVE claim; see the docstring
            return
    else:
        d = cbor
    problem = wave_claim_problem(d)
    if problem:
        raise ValidationError(
            f"refusing a WAVE claim the indexer will not register: it {problem}. The chain would "
            f"accept it and nothing would say it failed. Build the payload with "
            f"pyrxd.glyph.wave.build_wave_metadata. (Revealing a commit pyrxd <=0.24.0 already "
            f"broadcast? Pass allow_unregistrable_wave=True to the reveal; see "
            f"refuse_unregistrable_wave_claim.)"
        )
