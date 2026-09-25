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

THE REGISTRATION FEE. A registration pays a length-priced fee to the protocol treasury, and
pyrxd pays it by default. The sources:

- the WAVE protocol: "Registration — a one-time, length-based fee registers the name for two
  years", renewal pays "the name's registration price to the protocol treasury", and the fees
  "fund continued protocol development" (Radiant-Core/WAVE-Protocol ``ANNOUNCEMENT.md:51``,
  ``:52`` and ``:57`` at ``c05b8e7a``). It names no amounts and no address;
- Photonic, the reference client: its register page computes
  ``registrationFee = calculateNameCost(fullName)`` and pays it to
  ``feeAddress = "1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG"`` as an extra output of the reveal
  (``packages/app/src/pages/WaveRegister.tsx:132-152``). ``calculateNameCost`` prices the
  label before the first ``.`` by its length (``packages/lib/src/wave.ts:55-66``), all at
  ``becf41a7``;
- RXinDexer: ``wave_name_price`` carries the same tiers, commented "Mirrors Photonic's
  ``calculateNameCost``" (``electrumx/server/wave_index.py:73-86``), and
  ``WAVE_TREASURY_ADDRESS_DEFAULT`` is the same address (``wave_index.py:65``), at
  ``ca8a6a4e``. The indexer CHECKS the payment only on renewal: ``_maybe_process_renewal``
  (``wave_index.py:581-642``) extends the term of a name whose claim singleton a transaction
  spends when that transaction pays the treasury P2PKH at least the price. The claim path in
  ``process_tx`` (``wave_index.py:706-807``) does not look at the outputs at all, so a claim
  that pays nothing still registers.

The mainnet claim ``f644794b…`` (``tests/fixtures/wave_update_chain_mainnet.json``) pays
500,000,000 photons, the 6+ tier, to the treasury P2PKH at vout 2, after its NFT (vout 0) and
mutable contract (vout 1). That is where Photonic puts it: ``mintToken`` builds the reveal's
outputs as the minted token outputs, then related tokens, then the extra outputs
(``packages/lib/src/mint.ts:877-881``), then change (``mint.ts:905-907``); a WAVE claim's
token outputs are the NFT and then the mutable contract (``mint.ts:460``, ``:564``).

Both WAVE envelope writers (:func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix`,
:func:`~pyrxd.glyph.payload.build_mutable_scriptsig`) refuse a payload that registers a name
unless the caller states what the transaction pays for it
(:func:`refuse_unstated_wave_fee`). Every :class:`GlyphBuilder` reveal method that can
register a name hands back the fee output it stated, as ``registration_fee_output``; the two
that cannot are the FT deploy reveal, which refuses a WAVE claim, and the DAT reveal, whose
envelope the indexer does not read. The way out is ``pay_registration_fee=False``, which is
never the default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Final, Literal

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


# ─────────────────────────────────────────────────────────── the registration fee ──

#: The WAVE protocol treasury. MAINNET. Photonic pays the registration fee here
#: (``packages/app/src/pages/WaveRegister.tsx:133`` at ``becf41a7``) and RXinDexer looks here for a
#: renewal payment (``WAVE_TREASURY_ADDRESS_DEFAULT``, ``electrumx/server/wave_index.py:65`` at
#: ``ca8a6a4e``). No source publishes a testnet or regtest treasury, and pyrxd does not invent one:
#: on those chains a caller who wants the output names an address with ``registration_treasury=``
#: or does not pay. The builders cannot tell which chain they build for (they take key hashes,
#: not addresses), so they cannot refuse this for you; ``pyrxd glyph mint-nft`` can, and does.
WAVE_TREASURY_ADDRESS: Final = "1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG"

_PHOTONS_PER_RXD: Final = 100_000_000
#: Photons by bare-label length: ``calculateNameCost`` (``packages/lib/src/wave.ts:62-65``) and
#: ``wave_name_price`` (``electrumx/server/wave_index.py:79-86``) both write ``<= 3``, 4, 5, and
#: everything longer, as 10_000_000_000, 5_000_000_000, 1_000_000_000 and 500_000_000 photons —
#: 100, 50, 10 and 5 RXD, the amounts both sources' comments give. Written in RXD here.
#: pyrxd writes only 3-63 character labels, so ``<= 3`` is exactly 3.
_PRICE_BY_LENGTH: Final = {3: 100 * _PHOTONS_PER_RXD, 4: 50 * _PHOTONS_PER_RXD, 5: 10 * _PHOTONS_PER_RXD}
_PRICE_6_OR_MORE: Final = 5 * _PHOTONS_PER_RXD


def wave_registration_price(name: str) -> int:
    """Registration price in photons for ``name`` (``"alice"`` or ``"alice.rxd"``).

    Tiered by the length of the bare label, as Photonic's ``calculateNameCost`` and RXinDexer's
    ``wave_name_price`` are (see the module docstring):

    ======  ===============  =======
    label   photons          RXD
    ======  ===============  =======
    3       10,000,000,000   100
    4        5,000,000,000    50
    5        1,000,000,000    10
    6-63       500,000,000     5
    ======  ===============  =======

    Both sources price "3 or fewer" at 100 RXD. pyrxd refuses a label under 3 characters
    (:func:`parse_wave_name`), so here that tier is labels of exactly 3. The name is held to the
    same rule as every claim pyrxd writes, and refused with ``ValidationError`` if it fails it.
    """
    label = parse_wave_name(name)
    return _PRICE_BY_LENGTH.get(len(label), _PRICE_6_OR_MORE)


def _treasury_script(address: object) -> bytes:
    """The P2PKH locking script paying ``address``; refuses anything that is not a P2PKH address."""
    from ..script.type import P2PKH
    from ..utils import decode_address

    if not isinstance(address, str):
        raise ValidationError(f"registration treasury must be an address string, got {type(address).__name__}")
    try:
        pkh, network = decode_address(address)
    except Exception as exc:  # Base58Error or a checksum failure
        raise ValidationError(f"registration treasury {address!r} is not a P2PKH address: {exc}") from exc
    if network is None or len(pkh) != 20:
        raise ValidationError(f"registration treasury {address!r} is not a mainnet or testnet P2PKH address")
    return P2PKH().lock(pkh).serialize()


def format_rxd(photons: int) -> str:
    """``500_000_000`` → ``"5 RXD"``. Exact: a ``Decimal``, never a float."""
    rxd = Decimal(photons) / Decimal(_PHOTONS_PER_RXD)
    return f"{rxd.normalize():f} RXD"


@dataclass(frozen=True)
class WaveRegistrationFee:
    """The output a reveal that registers a WAVE name pays to the protocol treasury.

    Put ``TransactionOutput(Script(fee.locking_script), fee.value)`` in the reveal after the
    token outputs and before change. For a WAVE claim that is vout 2, after the NFT and the
    mutable contract, which is where Photonic puts it (see the module docstring).

    ``value`` and ``locking_script`` are DERIVED from the label and the treasury address and
    cannot be passed in, so a fee at the wrong tier, or paying a script that is not the
    treasury's P2PKH, is not a value this type can hold.
    """

    #: The bare label the claim registers (``"alice"``). ``"alice.rxd"`` is accepted and stored
    #: as ``"alice"``.
    label: str
    #: Where the fee goes: the published MAINNET treasury unless the caller names another.
    treasury_address: str = WAVE_TREASURY_ADDRESS
    #: Photons: :func:`wave_registration_price` of ``label``.
    value: int = field(init=False)
    #: ``OP_DUP OP_HASH160 <treasury hash160> OP_EQUALVERIFY OP_CHECKSIG``.
    locking_script: bytes = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", parse_wave_name(self.label))
        object.__setattr__(self, "value", wave_registration_price(self.label))
        object.__setattr__(self, "locking_script", _treasury_script(self.treasury_address))

    @property
    def is_published_treasury(self) -> bool:
        """Whether this pays the published mainnet treasury, :data:`WAVE_TREASURY_ADDRESS`."""
        return self.treasury_address == WAVE_TREASURY_ADDRESS

    def describe(self) -> str:
        """``"5 RXD (500,000,000 photons) to 1Grw…"``, for a confirmation or an error."""
        return f"{format_rxd(self.value)} ({self.value:,} photons) to {self.treasury_address}"

    def to_dict(self) -> dict[str, object]:
        """JSON form, for ``--json`` output."""
        return {
            "name": f"{self.label}.{WAVE_ROOT_DOMAIN}",
            "photons": self.value,
            "rxd": format_rxd(self.value).removesuffix(" RXD"),
            "treasury": self.treasury_address,
            "published_treasury": self.is_published_treasury,
            "locking_script": self.locking_script.hex(),
        }


def wave_registered_label(cbor: bytes | dict[str, Any]) -> str | None:
    """The label RXinDexer's claim path would register from this payload, or ``None``.

    ``None`` for a payload that is not WAVE-marked (the indexer's own membership test, see
    :func:`_is_wave_marked`) and for a WAVE-marked payload the indexer would skip
    (:func:`wave_claim_problem`). The writers reach the second only through
    ``allow_unregistrable_wave=True``, the recovery of a commit pyrxd ≤0.24.0 made. That reveal
    registers nothing, so it owes no registration fee.
    """
    if isinstance(cbor, (bytes, bytearray)):
        try:
            d: object = cbor2.loads(bytes(cbor))
        except Exception:  # not decodable is not a WAVE claim, as in refuse_unregistrable_wave_claim
            return None
    else:
        d = cbor
    if not isinstance(d, dict) or not _is_wave_marked(d) or wave_claim_problem(d) is not None:
        return None
    name, _parent = indexed_wave_name(d)
    return name if isinstance(name, str) else None


def wave_registration_fee_for(
    cbor: bytes | dict[str, Any],
    *,
    pay_registration_fee: bool = True,
    registration_treasury: str | None = None,
) -> WaveRegistrationFee | None:
    """The registration fee a transaction carrying ``cbor`` pays, or ``None`` when it pays none.

    :meth:`~pyrxd.glyph.builder.GlyphBuilder.prepare_commit`, every
    :class:`~pyrxd.glyph.builder.GlyphBuilder` reveal method that can register a name, the
    reveal-fee estimator in :mod:`pyrxd.glyph.fees` and ``pyrxd glyph mint-nft`` derive the
    fee here.

    ``None`` when ``cbor`` registers no name (:func:`wave_registered_label`) or when
    ``pay_registration_fee=False``.

    :param pay_registration_fee: ``True`` unless the caller explicitly opts out. With ``False``
        the name is registered WITHOUT paying the fee. Three facts to weigh first. The published
        WAVE protocol and Photonic expect the fee on every registration. RXinDexer does not
        check it at registration, so the name still registers and resolves: its claim path
        (``wave_index.py:706-807`` at ``ca8a6a4e``) never reads the outputs. And renewing the
        name takes a transaction that spends its claim token and pays the name's price to the
        treasury (``wave_index.py:581-642``; WAVE-Protocol ``ANNOUNCEMENT.md:52``). Must be a
        ``bool``: a truthy string such as ``"False"`` would otherwise pay, and ``0`` would opt
        out without saying so.
    :param registration_treasury: a P2PKH address to pay instead of :data:`WAVE_TREASURY_ADDRESS`.
        The published treasury is a MAINNET address and no testnet or regtest treasury is
        published, so on those chains name one here or pass ``pay_registration_fee=False``.
        Refused together with ``pay_registration_fee=False``, which would ignore it.
    """
    if not isinstance(pay_registration_fee, bool):
        raise ValidationError(f"pay_registration_fee must be True or False, got {pay_registration_fee!r}")
    if registration_treasury is not None:
        if not pay_registration_fee:
            raise ValidationError(
                "registration_treasury was given with pay_registration_fee=False: nothing would be paid to it"
            )
        _treasury_script(registration_treasury)  # a typo is refused whether or not this payload is a claim
    label = wave_registered_label(cbor)
    if label is None or not pay_registration_fee:
        return None
    if registration_treasury is None:
        return WaveRegistrationFee(label)
    return WaveRegistrationFee(label, registration_treasury)


#: The default of a WAVE envelope writer's ``registration_fee``: the caller has not said what
#: the transaction pays. A string, so the writers can type it as ``Literal["unstated"]``.
FEE_UNSTATED: Final = "unstated"


def refuse_unstated_wave_fee(
    cbor: bytes | dict[str, Any], registration_fee: WaveRegistrationFee | Literal["unstated"] | None
) -> None:
    """Refuse to write a payload that registers a WAVE name until its fee has been stated.

    Called by both WAVE envelope writers,
    :func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix` and
    :func:`~pyrxd.glyph.payload.build_mutable_scriptsig`: the narrowest point every pyrxd-built
    reveal and update the indexer reads crosses (the DAT reveal has its own writer, and the
    indexer does not read its envelope). They return script bytes, not a transaction, so they
    cannot add the fee output. What they can do is refuse until the caller says what the
    transaction pays: a :class:`WaveRegistrationFee` matching the claim (and then that output
    goes in the transaction), or ``None`` to opt out. Saying nothing is not an opt-out.
    :class:`~pyrxd.glyph.builder.GlyphBuilder` states it and returns the output on its result.

    A payload that registers nothing (:func:`wave_registered_label` is ``None``) needs no
    statement, and a fee offered for one is refused as a caller mistake.
    """
    label = wave_registered_label(cbor)
    if label is None:
        if isinstance(registration_fee, WaveRegistrationFee):
            raise ValidationError(
                f"a WAVE registration fee for {registration_fee.label!r} was given, but this payload "
                "registers no WAVE name; there is nothing to pay for"
            )
        return
    if registration_fee == FEE_UNSTATED:
        owed = WaveRegistrationFee(label)
        raise ValidationError(
            f"this payload registers the WAVE name {label}.{WAVE_ROOT_DOMAIN}, and the published WAVE "
            f"protocol charges {owed.describe()} for it (Photonic pays it; RXinDexer checks it on renewal "
            f"but not at registration). This function writes script bytes and cannot add that output, "
            f"so say what the transaction pays: registration_fee=wave_registration_fee_for(cbor), and put "
            f"that output in the transaction, or registration_fee=None to register without paying. "
            f"GlyphBuilder's reveal methods do this and return the output as registration_fee_output."
        )
    if registration_fee is None:
        return
    if not isinstance(registration_fee, WaveRegistrationFee):
        raise ValidationError(
            f"registration_fee must be a WaveRegistrationFee or None, got {type(registration_fee).__name__}"
        )
    if registration_fee.label != label:
        raise ValidationError(
            f"the registration fee is for {registration_fee.label!r}, but this payload registers {label!r}"
        )
