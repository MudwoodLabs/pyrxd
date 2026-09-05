from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, overload

import cbor2

from pyrxd.constants import DUST_THRESHOLD_PHOTONS
from pyrxd.fee_sizing import (
    assert_fee_rate_clears_relay_floor,
    assert_pays_for_its_size,
    relay_floor_photons_per_byte,
    required_fee,
    trial_size_with_slack,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import RADIANT_MAX_PHOTONS, Hex20

from .dmint import (
    DmintDeployParams,
    build_dmint_contract_script,
)
from .payload import build_reveal_scriptsig_suffix, encode_payload
from .script import (
    build_commit_locking_script,
    build_delegate_base_script,
    build_delegate_burn_script,
    build_delegate_token_script,
    build_ft_locking_script,
    build_mutable_nft_script,
    build_nft_locking_script,
    extract_delegate_ref_from_commit_script,
    extract_ref_from_nft_script,
    hash_payload,
    is_legacy_container_script,
)
from .types import GlyphMetadata, GlyphProtocol, GlyphRef, GlyphRoyalty

# Minimum fee rate post-V2. DERIVED from the single definition of Radiant's
# effective relay floor in :mod:`pyrxd.fee_sizing` rather than written out — this
# was a hardcoded ``10_000`` literal, the fourth independent spelling of the same
# number in this SDK, and the whole reason ``fee_sizing`` exists is that this repo
# has a measured history of one copy of a fee rule moving while the others did not.
# ``pyrxd.glyph.ft.MIN_FEE_RATE`` and ``pyrxd.wallet.DEFAULT_FEE_RATE`` are bound to
# the same call.
MIN_FEE_RATE: int = relay_floor_photons_per_byte()  # photons per byte

# Radiant MAX_MONEY: 21,000,000,000 RXD x 100,000,000 photons. A dMint premine is
# denominated in photons (1 photon = 1 FT unit), so anything above the money supply
# is a caller mistake that would otherwise surface only as an unfundable reveal.
# Derived from ``pyrxd.security.types`` rather than restated: the same number written out
# in three places is how a BTC supply cap ended up on the Radiant ElectrumX client.
_MAX_PHOTONS = RADIANT_MAX_PHOTONS


def _assert_declared_dmint_matches(decoded_cbor: dict, params: Any) -> None:
    """Refuse a deploy whose metadata advertises numbers it does not emit.

    The token body can carry a ``dmint`` object (Photonic ``DmintPayload``);
    indexers and wallets read it to display supply and mining parameters without
    parsing the reveal or decompiling the contract. **Nothing on chain reconciles
    it** against what the deploy actually emits, so a mismatch is a permanently
    mis-reported token and it is silent. Photonic performs no bounds or
    consistency checks on these fields at all (see
    ``docs/dmint-research-photonic.md`` §9.1) — this is a deliberate pyrxd
    addition, not a divergence in behaviour for correct callers.

    **All the supply-bearing fields, not just ``premine``.** Reconciling one
    field of six left the interesting divergence wide open: metadata advertising
    ``reward=10, maxHeight=10_000, numContracts=1`` — 100,000 total supply —
    deployed against ``--reward 16777215 --max-height 16777215 --num-contracts
    250`` genesises contracts minting 70,368,735,789,056,250 photons, and the
    premine check passes because both premines are 0. Supply is the product of
    three of these numbers; checking one of them is not checking supply.

    ``algo`` and ``diff`` are reconciled too. They do not change the supply, but
    a token whose metadata says SHA256d while its contracts run BLAKE3 tells
    every miner the wrong thing, and it is the same class of silent
    misstatement.

    The ``daa`` sub-object is NOT reconciled: V1 params carry no DAA fields at
    all, so there is nothing on that side to compare against, and the mode does
    not change what is issued — only how fast.

    Every mismatch is reported at once. A caller fixing these one exception at a
    time would re-broadcast a commit per field.
    """
    declared = decoded_cbor.get("dmint")
    if not isinstance(declared, dict):
        return

    # A declared value is only checked when the metadata actually carries the
    # key, so a partial `dmint` object stays legal.
    mismatches: list[str] = []
    for cbor_key, actual in (
        ("premine", params.premine_amount or 0),
        ("reward", params.reward_photons),
        ("maxHeight", params.max_height),
        ("numContracts", params.num_contracts),
        ("diff", params.difficulty),
        ("algo", int(params.algo)),
    ):
        if cbor_key not in declared:
            continue
        try:
            declared_value = int(declared[cbor_key])
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"metadata dmint.{cbor_key}={declared[cbor_key]!r} is not an integer") from exc
        if declared_value != actual:
            mismatches.append(f"dmint.{cbor_key}: metadata says {declared_value}, deploy emits {actual}")

    if mismatches:
        raise ValidationError(
            "the token metadata advertises a dMint contract this deploy does not build — "
            + "; ".join(mismatches)
            + ". Nothing on chain reconciles the two, so the token would permanently misreport "
            "itself. Change the deploy parameters to match the metadata, or edit the metadata to "
            "match the deploy."
        )


@dataclass
class CommitParams:
    """Parameters for the commit transaction."""

    metadata: GlyphMetadata
    owner_pkh: Hex20  # who will own the NFT/FT after reveal
    change_pkh: Hex20  # change output recipient
    funding_satoshis: int  # total input satoshis available
    # pyrxd's uneconomic-change floor, NOT a chain minimum (Radiant's is 1 photon).
    dust_limit: int = DUST_THRESHOLD_PHOTONS
    #: Delegate BASE ref authorising this mint's ``in``/``by`` claims. When set,
    #: the commit script gains the 56-byte prefix of
    #: :func:`~pyrxd.glyph.script.build_delegate_commit_prefix`, the commit tx
    #: MUST spend a delegate token carrying this ref, and the reveal MUST carry
    #: the matching burn output — see :class:`RevealParams`. Leave ``None`` to
    #: back relationships directly (spend-and-recreate) or not at all.
    delegate_ref: GlyphRef | None = None


@dataclass
class CommitResult:
    """Output of prepare_commit — the caller broadcasts and gets a txid back."""

    commit_script: bytes  # nftCommitScript for vout[0]
    cbor_bytes: bytes  # store this — needed for reveal scriptSig
    payload_hash: bytes  # 32-byte hash committed into the script
    estimated_fee: int  # in photons
    #: Echoed back from :class:`CommitParams` so the caller carries it to the
    #: reveal. A commit built with a delegate whose reveal omits the burn output
    #: is rejected by the covenant, stranding the commit value until a correct
    #: reveal is built — so keep this alongside ``cbor_bytes``.
    delegate_ref: GlyphRef | None = None


@dataclass
class RevealParams:
    """Parameters for the reveal transaction.

    Trust model: ``owner_pkh`` is the recipient — who will own the minted
    NFT/FT after reveal. It may differ from the commit script's embedded
    PKH (which is the *spender* of the commit UTXO, i.e. the key that
    signs the reveal tx). Mint-to-recipient is a first-class supported
    flow; pyrxd performs no authorization check on recipient selection.
    The caller is responsible for binding the reveal-signing key to the
    commit script's embedded PKH.
    """

    commit_txid: str  # txid of confirmed commit tx
    commit_vout: int  # which output is the commit script
    commit_value: int  # satoshis in the commit output
    cbor_bytes: bytes  # from CommitResult
    owner_pkh: Hex20  # recipient PKH — can differ from commit spender PKH
    is_nft: bool  # True = NFT, False = FT
    #: The commit output's locking script. Preferred over ``delegate_ref``:
    #: pass the script you are about to spend and the delegate ref is READ from
    #: it, so a delegate-carrying commit cannot be revealed without its burn
    #: output by a caller who simply forgot. If both are given they are
    #: cross-checked and a mismatch raises.
    commit_script: bytes | None = None
    #: Delegate BASE ref, for callers that do not have the commit script to
    #: hand. Prefer ``commit_script``.
    delegate_ref: GlyphRef | None = None


@dataclass
class RevealScripts:
    """Scripts needed to build the reveal tx — caller constructs the full tx."""

    locking_script: bytes  # output scriptPubKey
    scriptsig_suffix: bytes  # the 'gly' + CBOR portion; caller prepends sig+pubkey
    #: When not ``None``, the reveal MUST include this as an additional output
    #: with value 0. The commit covenant counts it (exactly one required), so a
    #: reveal that omits it is rejected outright rather than minting an
    #: unauthorised token — the failure is loud, not silent.
    delegate_burn_script: bytes | None = None


@dataclass
class DelegateSetupScripts:
    """Output scripts for the one-time delegate setup — see :meth:`GlyphBuilder.prepare_delegate_setup`."""

    #: Spend the parent tokens into this. Its outpoint becomes the base ref.
    base_script: bytes
    #: The refs *base_script* authorises, in script order — echoed back so the
    #: caller can assert it built the base it meant to.
    authorised_refs: tuple[GlyphRef, ...]
    #: **The parent NFT outputs the base transaction must ALSO carry**, one per
    #: authorised ref and in the same order, each byte-identical to the output
    #: being spent.
    #:
    #: ``OP_REQUIREINPUTREF`` requires a ref as an INPUT; it does not carry it
    #: forward. So a base transaction whose outputs are the base alone SPENDS
    #: the container and author singletons and re-creates neither — it burns
    #: them, permanently and irrecoverably, and a consumed singleton can never
    #: be re-minted (spec §7.5.1). Photonic builds ``outputs = [base, ...tokens]``
    #: for exactly this reason (``mint.ts:634``). These are those tokens.
    parent_scripts: tuple[bytes, ...] = ()
    #: Built only when ``base_ref`` was supplied (a second transaction, after
    #: the base has confirmed and its outpoint is known).
    token_scripts: tuple[bytes, ...] = ()


@dataclass
class FtDeployRevealScripts:
    """Scripts + output values for an FT deploy reveal with premine.

    Extends :class:`RevealScripts` with the premine amount the caller should
    set as ``vout[0].value`` of the reveal tx. This is the only FT-deploy-
    specific signal not already carried by the reveal scripts themselves —
    reveal script construction is shared with non-premine FT reveals.
    """

    locking_script: bytes  # 75-byte FT locking script for vout[0]
    scriptsig_suffix: bytes  # the 'gly' + CBOR portion
    premine_amount: int  # caller sets vout[0].value = this (1 photon = 1 FT unit)


@dataclass
class MutableRevealScripts:
    """Scripts for a MUT reveal — two inputs and two outputs required.

    See :meth:`GlyphBuilder.prepare_mutable_reveal` for the transaction shape.
    ``ref`` and ``mutable_ref`` are two DIFFERENT outpoints on the same commit
    transaction and both must be spent by the reveal.
    """

    ref: GlyphRef
    nft_script: bytes  # 63-byte NFT singleton (vout[0] typically)
    contract_script: bytes  # 174-byte mutable contract (vout[1] typically)
    scriptsig_suffix: bytes  # 'gly' + CBOR; caller prepends sig + pubkey
    payload_hash: bytes  # sha256d of CBOR payload
    # The contract's own singleton ref: ``commit_txid:(commit_vout + 1)``. A
    # SEPARATE outpoint from ``ref`` — see the builder docstring for why it can
    # never be the same one.
    mutable_ref: GlyphRef | None = None


@dataclass
class ContainerRevealScripts:
    """Scripts for a CONTAINER reveal.

    ``locking_script`` is the plain 63-byte NFT singleton — a container has no
    distinct script shape (see :meth:`GlyphBuilder.prepare_container_reveal`).
    """

    ref: GlyphRef
    locking_script: bytes  # 63-byte NFT singleton
    scriptsig_suffix: bytes
    # Always ``None``. Retained so callers that destructure this dataclass keep
    # working; the child-ref prefix it used to describe was removed in 0.15.0.
    child_ref: GlyphRef | None = None


@dataclass
class ContainerChildRevealScripts:
    """Scripts for revealing a token as a member of a container.

    See :meth:`GlyphBuilder.prepare_container_child_reveal` for the two-input /
    two-output reveal shape these must be placed in.
    """

    ref: GlyphRef  # the child's own genesis ref (its commit outpoint)
    nft_script: bytes  # 63-byte NFT singleton for the child (output 0)
    container_script: bytes  # 63-byte NFT singleton re-creating the container (output 1)
    scriptsig_suffix: bytes  # 'gly' + CBOR; caller prepends sig + pubkey
    container_ref: GlyphRef  # the container this child declares membership in


class GlyphBuilder:
    """Build unsigned Glyph transactions.

    Separate commit and reveal methods — caller is responsible for:

    1. Signing the commit tx and broadcasting it.
    2. Waiting for confirmation.
    3. Passing the confirmed commit txid to the reveal method.
    4. Signing the reveal tx (via ``Transaction`` + ``PrivateKey``).

    Method selection guide (N9 — surface grew to 12 methods across 5 protocols)
    ----------------------------------------------------------------------------

    **Minting (commit → reveal)**

    +--------------------------+-------------------+---------------------------------------+
    | Goal                     | Protocol tag(s)   | Reveal method                         |
    +==========================+===================+=======================================+
    | Mint a singleton NFT     | ``[NFT]``         | :meth:`prepare_reveal`                |
    +--------------------------+-------------------+---------------------------------------+
    | Mint a plain FT          | ``[FT]``          | :meth:`prepare_ft_deploy_reveal`      |
    +--------------------------+-------------------+---------------------------------------+
    | Mint a dMint FT          | ``[FT, DMINT]``   | :meth:`prepare_dmint_deploy` (3 txs)  |
    +--------------------------+-------------------+---------------------------------------+
    | Mint a mutable NFT       | ``[NFT, MUT]``    | :meth:`prepare_mutable_reveal`        |
    +--------------------------+-------------------+---------------------------------------+
    | Mint a collection        | ``[NFT,CONTAINER]`| :meth:`prepare_container_reveal`      |
    +--------------------------+-------------------+---------------------------------------+
    | Mint into a collection   | ``[NFT]`` + ``in``| :meth:`prepare_container_child_reveal`|
    +--------------------------+-------------------+---------------------------------------+
    | Mint a WAVE name         | ``[NFT,MUT,WAVE]``| :meth:`prepare_wave_reveal`           |
    +--------------------------+-------------------+---------------------------------------+

    For every token type the first step is the same: call
    :meth:`prepare_commit` (which derives the commit script from the
    metadata protocol list automatically).  Only the reveal step differs.

    **Transfers (no commit needed)**

    - NFT transfer: :meth:`build_nft_transfer_tx`
    - FT transfer: :meth:`build_ft_transfer_tx` (or :class:`FtUtxoSet` in ``glyph/ft.py``)

    **Low-level (rarely called directly)**

    - :meth:`prepare_reveal` — generic reveal; ``is_nft`` picks singleton vs FT reftype
    - :meth:`build_reveal_scripts` — alternate reveal entry that returns scripts, not params
    - :meth:`build_transfer_locking_script` — bare FT lock without constructing a tx
    - :meth:`build_contract_script` — MUT contract script for mutable NFT reveals
    """

    def prepare_commit(self, params: CommitParams) -> CommitResult:
        """
        Prepare the commit transaction parameters.

        Returns the commit locking script + CBOR bytes + estimated fee.
        Caller must build, sign, and broadcast the actual transaction.

        The commit script's ``OP_REFTYPE_OUTPUT`` check is derived from
        ``metadata.protocol``: NFT (``2`` in protocol) produces an
        ``OP_2``/SINGLETON-expecting commit; any other protocol mix
        (FT, dMint FT, data, etc.) produces an ``OP_1``/NORMAL-expecting
        commit. This means the caller does not hand-pick refType — the
        metadata drives it. Prior versions forced every commit to NFT
        shape; see ``build_commit_locking_script`` for the fix note.
        """
        cbor_bytes, payload_hash = encode_payload(params.metadata)
        is_nft = GlyphProtocol.NFT in params.metadata.protocol
        commit_script = build_commit_locking_script(
            payload_hash,
            params.owner_pkh,
            is_nft=is_nft,
            delegate_ref=params.delegate_ref,
        )
        # Rough estimate: commit tx ~276 bytes, plus the delegate token input
        # (~148 B) and the 56-byte script prefix when this mint is delegated.
        estimated_fee = (276 if params.delegate_ref is None else 276 + 148 + 56) * MIN_FEE_RATE
        return CommitResult(
            commit_script=commit_script,
            cbor_bytes=cbor_bytes,
            payload_hash=payload_hash,
            estimated_fee=estimated_fee,
            delegate_ref=params.delegate_ref,
        )

    def prepare_reveal(self, params: RevealParams) -> RevealScripts:
        """
        Prepare the reveal transaction scripts.

        Returns locking script + scriptSig suffix.
        Caller must build, sign, and broadcast the actual transaction.
        """
        # Cross-check: protocol field in CBOR must be consistent with is_nft.
        try:
            cbor_data = cbor2.loads(params.cbor_bytes)
            protocol = cbor_data.get("p", [])
            if params.is_nft and GlyphProtocol.NFT not in protocol:
                raise ValidationError(
                    f"is_nft=True but CBOR protocol field {protocol!r} does not include "
                    f"GlyphProtocol.NFT ({GlyphProtocol.NFT})"
                )
            if not params.is_nft and GlyphProtocol.FT not in protocol:
                raise ValidationError(
                    f"is_nft=False but CBOR protocol field {protocol!r} does not include "
                    f"GlyphProtocol.FT ({GlyphProtocol.FT})"
                )
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Could not parse CBOR payload for protocol cross-check: {e}") from e

        ref = GlyphRef(
            txid=params.commit_txid,
            vout=params.commit_vout,
        )
        if params.is_nft:
            locking = build_nft_locking_script(params.owner_pkh, ref)
        else:
            locking = build_ft_locking_script(params.owner_pkh, ref)

        # Delegate: prefer READING the ref off the commit script the caller is
        # about to spend, so the burn output cannot be forgotten. A mismatch
        # between the two sources is a caller bug that would produce a reveal
        # the covenant rejects, so it raises rather than picking a winner.
        delegate_ref = params.delegate_ref
        if params.commit_script is not None:
            from_script = extract_delegate_ref_from_commit_script(params.commit_script)
            if delegate_ref is not None and from_script != delegate_ref:
                raise ValidationError(
                    f"delegate_ref {delegate_ref.txid}:{delegate_ref.vout} does not match the delegate ref "
                    f"carried by commit_script ({from_script.txid + ':' + str(from_script.vout) if from_script else 'none'}). "
                    "The commit script is authoritative — it is the covenant that will be evaluated."
                )
            delegate_ref = from_script

        scriptsig_suffix = build_reveal_scriptsig_suffix(params.cbor_bytes)
        return RevealScripts(
            locking_script=locking,
            scriptsig_suffix=scriptsig_suffix,
            delegate_burn_script=(build_delegate_burn_script(delegate_ref) if delegate_ref is not None else None),
        )

    def prepare_ft_deploy_reveal(
        self,
        commit_txid: str,
        commit_vout: int,
        commit_value: int,
        cbor_bytes: bytes,
        premine_pkh: Hex20,
        premine_amount: int,
    ) -> FtDeployRevealScripts:
        """Prepare reveal scripts + premine amount for an FT deploy.

        Thin convenience wrapper around :meth:`prepare_reveal` for the
        FT-deploy-with-premine flow: the reveal produces one FT output
        carrying the full issued supply to ``premine_pkh``. The permanent
        token ref is the **commit** outpoint (``commit_txid:commit_vout``),
        which this method embeds into the reveal's locking script — not the
        reveal's own outpoint.

        Caller still constructs the actual transaction. The returned
        ``premine_amount`` is what ``vout[0].value`` must be on the
        reveal tx — typically the full supply for a premine-only deploy
        (no covenant UTXO). Radiant FT convention: 1 photon = 1 FT unit,
        so ``premine_amount`` is the supply in whole units.

        No dMint-specific logic here. The ``cbor_bytes`` already encode
        whatever protocol markers the caller chose — dMint FT (``[1,4]``),
        plain FT (``[1]``), or any other combination — via
        :class:`GlyphMetadata`. pyrxd treats the protocol markers as
        caller-owned; classification happens at the indexer layer.
        """
        if premine_amount < 0:
            raise ValidationError("premine_amount must be non-negative")
        if premine_amount < DUST_THRESHOLD_PHOTONS:
            # A pyrxd HEURISTIC, not a chain rule — the same one, and the same
            # reasoning, as ``_validate_premine`` further down this file: a whole
            # FT supply below 546 units is almost always a decimals mistake.
            # Radiant would relay it. ``GetDustThreshold`` returns 1 satoshi and
            # ``IsDust`` is ``nValue <= 0``
            # (Radiant-Core/src/policy/policy.cpp:19-25), and standardness is not
            # consulted at all (``fRequireStandard`` hardcoded ``false``,
            # Radiant-Core/src/validation.cpp:271, src/init.cpp:1995). The
            # previous comment here — "non-standard and will be rejected by most
            # mempool policies" — described a rule that does not exist on this
            # chain.
            raise ValidationError(
                f"premine_amount ({premine_amount}) is below pyrxd's {DUST_THRESHOLD_PHOTONS}-unit guard. This is a guard "
                "against a decimals mistake, not a chain limit (Radiant's output floor is 1 photon) — "
                "use a larger supply, or an NFT if the token really is indivisible."
            )
        scripts = self.prepare_reveal(
            RevealParams(
                commit_txid=commit_txid,
                commit_vout=commit_vout,
                commit_value=commit_value,
                cbor_bytes=cbor_bytes,
                owner_pkh=premine_pkh,
                is_nft=False,
            )
        )
        return FtDeployRevealScripts(
            locking_script=scripts.locking_script,
            scriptsig_suffix=scripts.scriptsig_suffix,
            premine_amount=premine_amount,
        )

    @overload
    def prepare_dmint_deploy(
        self,
        params: DmintV1DeployParams,
        *,
        allow_v2_deploy: bool = ...,
    ) -> DmintV1DeployResult: ...
    @overload
    def prepare_dmint_deploy(
        self,
        params: DmintV2DeployParams,
        *,
        allow_v2_deploy: bool = ...,
    ) -> DmintV2DeployResult: ...
    def prepare_dmint_deploy(
        self,
        params: DmintV1DeployParams | DmintV2DeployParams,
        *,
        allow_v2_deploy: bool = True,
    ) -> DmintV1DeployResult | DmintV2DeployResult:
        """Prepare a dMint token deploy.

        Dispatches on the type of ``params``:

        * :class:`DmintV1DeployParams` → returns :class:`DmintV1DeployResult`.
          V1 is the only format on Radiant mainnet today (see GLYPH at
          a443d9df…878b). Two-tx deploy: commit + reveal (the reveal
          directly creates ``params.num_contracts`` parallel contract UTXOs).

        * :class:`DmintV2DeployParams` → returns :class:`DmintV2DeployResult`.
          V2 is consensus-proven on regtest + mainnet (#219) and now deploys
          by default (``allow_v2_deploy=True``). A soft :class:`UserWarning` is
          emitted if the caller explicitly passes ``allow_v2_deploy=False`` so
          the historical opt-out path stays observable without blocking.

        :param params: Either :class:`DmintV1DeployParams` (V1 deploy) or
            :class:`DmintV2DeployParams` (V2 deploy). The deprecated
            :class:`DmintFullDeployParams` is accepted (it's a subclass of
            ``DmintV2DeployParams``) but emits a ``DeprecationWarning`` at
            construction time.
        :param allow_v2_deploy: Retained for backward-compatibility; defaults to
            ``True`` (V2 deploys by default). Ignored for V1.
        :returns: V1 or V2 result, matching the param type via ``@overload``.
        :raises ValidationError: Various per-version invariants — see
            :meth:`_prepare_dmint_v1_deploy` and the V2 implementation
            below for specifics.
        """
        if isinstance(params, DmintV1DeployParams):
            return self._prepare_dmint_v1_deploy(params)
        if isinstance(params, DmintV2DeployParams):
            return self._prepare_dmint_v2_deploy(params, allow_v2_deploy=allow_v2_deploy)
        # Unreachable per the type union — exhaustive-narrowing for mypy strict.
        from typing import assert_never

        assert_never(params)

    def _prepare_dmint_v1_deploy(self, params: DmintV1DeployParams) -> DmintV1DeployResult:
        """Build the V1 deploy commit + placeholder contract scripts.

        Mirrors the on-chain shape decoded in
        ``docs/dmint-research-photonic-deploy.md`` §2 and §3:

        * Commit tx: 1 FT-commit hashlock + ``num_contracts`` ref-seed
          P2PKHs + 1 NFT-commit hashlock + change. (This method builds
          only the FT-commit script; the caller composes the full
          commit-tx outputs using the supplied ref-seed PKH and the
          NFT-commit pattern from the existing builder API.)
        * Reveal tx: spends the commit, emits ``num_contracts`` V1
          dMint contract UTXOs, then an optional premine FT output,
          then an optional OP_RETURN, then change.
          The reveal-output script bytes are built by
          :meth:`DmintV1DeployResult.build_reveal_outputs` once the
          caller has the commit txid.

        The placeholder contract scripts (built with the all-zero commit
        txid) let the caller estimate the reveal-tx fee before broadcasting
        the commit. Their byte length is exactly the final length — only
        the txid component of ``contractRef`` / ``tokenRef`` changes.
        """
        from .dmint import (
            build_dmint_v1_contract_script,
            difficulty_to_target,
        )

        # 1. Encode the CBOR token body.
        cbor_bytes, payload_hash = encode_payload(params.metadata)

        decoded = cbor2.loads(cbor_bytes)

        # Defensive cross-check: V1 must NOT emit a 'v' field (V2 marker).
        # encode_payload draws 'v' from metadata.version; if the caller
        # forgot to leave it at the V1 default, the resulting CBOR would
        # be classified as V2 by RXinDexer.
        #
        # Asked of the DECODED map, not of the raw bytes. The previous form
        # searched the serialised payload for `61 76` — the CBOR encoding of the
        # key "v" — which also matches the two low bytes of any integer whose
        # value happens to be 0x6176 (24_950): `19 61 76`. A `reward: 24950`, or
        # any other field landing on those bytes, refused a perfectly legal V1
        # deploy. Decoding first asks the question that was actually meant.
        if "v" in decoded:
            raise ValidationError(
                "V1 dMint CBOR must NOT include a 'v' field; got one in the "
                "encoded body. Set GlyphMetadata(version=None) or omit it."
            )
        # Belt-and-braces: also pin the 'p' field shape.
        if "p" not in decoded or 1 not in decoded["p"] or 4 not in decoded["p"]:
            raise ValidationError(
                f"V1 dMint CBOR 'p' field must include both 1 (FT) and 4 (DMINT); got p={decoded.get('p')!r}"
            )
        _assert_declared_dmint_matches(decoded, params)

        # 2. Build the FT-commit hashlock (75-byte script — exactly the
        # Photonic ftCommitScript shape; the existing helper produces it).
        commit_script = build_commit_locking_script(
            payload_hash,
            params.owner_pkh,
            is_nft=False,
        )
        # Reveal payload is the bulk; a few hundred bytes for the rest
        # of the commit tx. Round-trip safe for any sane commit size.
        estimated_commit_fee = 276 * MIN_FEE_RATE
        commit_result = CommitResult(
            commit_script=commit_script,
            cbor_bytes=cbor_bytes,
            payload_hash=payload_hash,
            estimated_fee=estimated_commit_fee,
        )

        # 3. Pre-build placeholder contract scripts so the caller can
        # estimate fees before broadcasting the commit. Each is the
        # full 241-byte V1 layout (state + epilogue); only the txid
        # component of contractRef/tokenRef changes at reveal time.
        placeholder_txid = "00" * 32
        placeholder_token_ref = GlyphRef(txid=placeholder_txid, vout=0)
        target = difficulty_to_target(params.difficulty, params.algo)
        placeholder_contract_scripts = tuple(
            build_dmint_v1_contract_script(
                height=0,
                contract_ref=GlyphRef(txid=placeholder_txid, vout=i + 1),
                token_ref=placeholder_token_ref,
                max_height=params.max_height,
                reward=params.reward_photons,
                target=target,
                algo=params.algo,
            )
            for i in range(params.num_contracts)
        )

        return DmintV1DeployResult(
            commit_result=commit_result,
            cbor_bytes=cbor_bytes,
            owner_pkh=params.owner_pkh,
            premine_amount=params.premine_amount,
            num_contracts=params.num_contracts,
            placeholder_contract_scripts=placeholder_contract_scripts,
            max_height=params.max_height,
            reward_photons=params.reward_photons,
            difficulty=params.difficulty,
            algo=params.algo,
            op_return_msg=params.op_return_msg,
            premine_pkh=params.premine_pkh,
        )

    def _prepare_dmint_v2_deploy(
        self,
        params: DmintV2DeployParams,
        *,
        allow_v2_deploy: bool,
    ) -> DmintV2DeployResult:
        """Build the V2 deploy commit + placeholder contract scripts.

        Mirrors :meth:`_prepare_dmint_v1_deploy` (commit + reveal that genesises
        ``num_contracts`` parallel 1-photon V2 contract UTXOs at height 0,
        ``contractRef[i] = commit:(i+1)`` / ``tokenRef = commit:0``), differing
        only in the V2 contract bytecode. Gated on ``allow_v2_deploy``.
        """
        if not allow_v2_deploy:
            # Non-blocking as of 0.9.0: V2 is consensus-proven on regtest +
            # mainnet (#219). The historical opt-out (allow_v2_deploy=False) no
            # longer refuses — it only emits a soft warning so the deliberate
            # opt-out path stays observable.
            import warnings

            warnings.warn(
                "prepare_dmint_deploy was called with allow_v2_deploy=False for a "
                "DmintV2DeployParams; V2 deploy is no longer blocked (consensus-proven "
                "on regtest + mainnet, #219) and proceeds anyway. Drop the "
                "allow_v2_deploy=False argument to silence this warning.",
                UserWarning,
                stacklevel=2,
            )

        # 1. Encode the CBOR token body and pin the FT+DMINT protocol shape.
        cbor_bytes, payload_hash = encode_payload(params.metadata)
        decoded = cbor2.loads(cbor_bytes)
        if "p" not in decoded or 1 not in decoded["p"] or 4 not in decoded["p"]:
            raise ValidationError(
                f"V2 dMint CBOR 'p' field must include both 1 (FT) and 4 (DMINT); got p={decoded.get('p')!r}"
            )
        _assert_declared_dmint_matches(decoded, params)

        # 2. FT-commit hashlock (same 75-byte commit shape as V1).
        commit_script = build_commit_locking_script(payload_hash, params.owner_pkh, is_nft=False)
        commit_result = CommitResult(
            commit_script=commit_script,
            cbor_bytes=cbor_bytes,
            payload_hash=payload_hash,
            estimated_fee=276 * MIN_FEE_RATE,
        )

        # 3. Pre-build placeholder V2 contract scripts (height=0) so the caller can
        # estimate the reveal fee before the commit txid is known. Each is the full
        # V2 layout; only the txid component of contractRef/tokenRef changes at reveal.
        placeholder_txid = "00" * 32
        placeholder_token_ref = GlyphRef(txid=placeholder_txid, vout=0)
        placeholder_contract_scripts = tuple(
            build_dmint_contract_script(
                DmintDeployParams(
                    contract_ref=GlyphRef(txid=placeholder_txid, vout=i + 1),
                    token_ref=placeholder_token_ref,
                    max_height=params.max_height,
                    reward=params.reward_photons,
                    difficulty=params.difficulty,
                    algo=params.algo,
                    daa_mode=params.daa_mode,
                    target_time=params.target_time,
                    half_life=params.half_life,
                    epoch_length=params.epoch_length,
                    max_adjustment_log2=params.max_adjustment_log2,
                    schedule=params.schedule,
                )
            )
            for i in range(params.num_contracts)
        )

        return DmintV2DeployResult(
            commit_result=commit_result,
            cbor_bytes=cbor_bytes,
            owner_pkh=params.owner_pkh,
            premine_amount=params.premine_amount,
            num_contracts=params.num_contracts,
            placeholder_contract_scripts=placeholder_contract_scripts,
            max_height=params.max_height,
            reward_photons=params.reward_photons,
            difficulty=params.difficulty,
            algo=params.algo,
            op_return_msg=params.op_return_msg,
            daa_mode=params.daa_mode,
            target_time=params.target_time,
            half_life=params.half_life,
            epoch_length=params.epoch_length,
            max_adjustment_log2=params.max_adjustment_log2,
            schedule=params.schedule,
            premine_pkh=params.premine_pkh,
        )

    # ------------------------------------------------------------------
    # MUT reveal

    def prepare_mutable_reveal(
        self,
        commit_txid: str,
        commit_vout: int,
        cbor_bytes: bytes,
        owner_pkh: Hex20,
    ) -> MutableRevealScripts:
        """Prepare scripts for a MUT (mutable NFT) reveal.

        Returns the two output locking scripts the caller must place in the
        reveal tx:

        - ``nft_script``:      63-byte NFT singleton (token the owner holds),
          carrying ``ref = commit_txid:commit_vout``
        - ``contract_script``: 174-byte mutable contract UTXO (holds state),
          carrying ``mutable_ref = commit_txid:(commit_vout + 1)``

        The reveal scriptSig suffix is also returned; the caller prepends
        ``<sig> <pubkey>`` to form the full scriptSig.

        Protocol field in ``cbor_bytes`` must include ``GlyphProtocol.MUT``
        (5). Use ``GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT])``.

        The reveal needs TWO inputs
        ---------------------------

        ==========  ==============================================================
        input        outpoint
        ==========  ==============================================================
        ``0``        ``commit_txid:commit_vout`` — the commit (reveal scriptSig)
        ``1``        ``commit_txid:(commit_vout + 1)`` — a plain seed output
        ==========  ==============================================================

        The commit transaction must therefore carry a **second, ordinary output
        at ``commit_vout + 1``** (Photonic funds it with 1 photon; Radiant has no
        dust rule). Spending it is what puts ``mutable_ref`` into the
        transaction's input singleton-ref set, which is the only thing that lets
        an output push it.

        Why the two refs cannot be the same one
        ---------------------------------------

        pyrxd 0.9.0-0.15.0 used ``ref`` for *both* scripts. A reveal built as
        documented above was **rejected by consensus every time** — confirmed
        against a Radiant Core v3.1.1 regtest node
        (``tests/test_mut_wave_regtest_e2e.py``), reject reason
        ``bad-txns-inputs-outputs-invalid-transaction-reference-operations``.
        Two independent chain rules forbid it:

        * ``OP_PUSHINPUTREFSINGLETON`` files its ref into
          ``foundDisallowedSiblingRefs`` as well as the push-ref set
          (``CScript::GetPushRefs``), and ``validateTransactionReferenceOperations``
          rejects a transaction where two outputs claim the same one. Both the
          NFT script and the mutable contract lead with ``0xd8``, so they can
          never carry the same ref.
        * The contract's own body derives the token ref *from* its ref by
          subtracting one from the vout (``OP_DUP 20 OP_SPLIT OP_BIN2NUM OP_1SUB
          OP_4 OP_NUM2BIN OP_CAT``). ``mutable_ref.vout == ref.vout + 1`` is
          therefore not a convention — the covenant computes it. With equal refs
          the contract would look for ``commit_vout - 1`` and match nothing, so
          even a repaired sibling rule would leave the contract unspendable.

        This matches Photonic Wallet (``packages/lib/src/mint.ts``:
        ``Outpoint.fromUTXO(mint.utxo.txid, mint.utxo.vout + 1)``).

        .. note::
           Spending the contract later (the ``mod`` / ``sl`` operations of
           :func:`~pyrxd.glyph.payload.build_mutable_scriptsig`) additionally
           requires the token output to be re-created in Photonic's
           ``nftAuthScript`` shape — an ``OP_REQUIREINPUTREF <mutable_ref>
           <sha256(contract scriptSig)> OP_2DROP`` state prefix ahead of the
           singleton. pyrxd has no builder for that shape yet; the working
           transaction is spelled out in ``tests/test_mut_wave_regtest_e2e.py``.
        """
        try:
            cbor_data = cbor2.loads(cbor_bytes)
            protocol = cbor_data.get("p", [])
            if GlyphProtocol.MUT not in protocol:
                raise ValidationError(
                    f"CBOR protocol field {protocol!r} must include GlyphProtocol.MUT ({GlyphProtocol.MUT})"
                )
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Could not parse CBOR for MUT cross-check: {exc}") from exc

        ref = GlyphRef(txid=commit_txid, vout=commit_vout)
        # NOT ``ref`` — see the docstring. The contract's singleton must be a
        # different outpoint, and specifically the next one: its own body
        # recomputes the token ref as ``mutable_ref.vout - 1``.
        mutable_ref = GlyphRef(txid=commit_txid, vout=commit_vout + 1)
        payload_hash = hash_payload(cbor_bytes)
        nft_script = build_nft_locking_script(owner_pkh, ref)
        contract_script = build_mutable_nft_script(mutable_ref, payload_hash)
        scriptsig_suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        return MutableRevealScripts(
            ref=ref,
            nft_script=nft_script,
            contract_script=contract_script,
            scriptsig_suffix=scriptsig_suffix,
            payload_hash=payload_hash,
            mutable_ref=mutable_ref,
        )

    # ------------------------------------------------------------------
    # CONTAINER reveal

    def prepare_container_reveal(
        self,
        commit_txid: str,
        commit_vout: int,
        cbor_bytes: bytes,
        owner_pkh: Hex20,
        child_ref: GlyphRef | None = None,
    ) -> ContainerRevealScripts:
        """Prepare scripts for a CONTAINER (collection) reveal.

        A container's locking script is the **plain 63-byte NFT singleton** of
        :func:`~pyrxd.glyph.script.build_nft_locking_script`. Container-ness is
        carried by the ``7`` marker in the envelope's ``p`` field, exactly as in
        Photonic Wallet (``packages/lib/src/script.ts`` has one ``nftScript``
        and no container variant). That is what makes a container a first-class
        token: every NFT classifier, the scanner, and
        :meth:`build_nft_transfer_tx` handle it unchanged.

        Membership points **child → parent** and lives in the *child's*
        envelope, in the ``in`` field
        (:attr:`~pyrxd.glyph.types.GlyphMetadata.container_refs`). Use
        :meth:`prepare_container_child_reveal` to mint a member.

        Protocol field must include ``GlyphProtocol.CONTAINER`` (7).

        :param child_ref: **Removed.** Passing anything but ``None`` raises
            :class:`~pyrxd.security.errors.ValidationError`; see below.

        The ``child_ref`` prefix (removed in 0.15.0)
        -------------------------------------------

        pyrxd 0.9.0–0.14.0 prefixed the NFT body with ``OP_PUSHINPUTREF
        <child_ref>`` when ``child_ref`` was given. That 100-byte script was
        never a working token, and both defects were confirmed against a
        Radiant Core v3.1.1 regtest node
        (``tests/test_container_regtest_e2e.py``):

        * **The output could not be spent.** ``OP_PUSHINPUTREF`` leaves the ref
          on the stack and nothing drops it, so the P2PKH tail hashed the *ref*
          and ``OP_EQUALVERIFY`` failed for every possible scriptSig. Any
          photons placed on it were unrecoverable.
        * **Creating one destroyed the child NFT.** ``OP_PUSHINPUTREFSINGLETON``
          also registers its ref as a disallowed *sibling*
          (``CScript::GetPushRefs``), so the child could not be re-created
          alongside the container — and a singleton consumed into a ``0xd0``
          push never re-enters ``inputSingletonRefSet``, so it can never be
          minted again.

        Even with the missing ``OP_DROP`` repaired, a script-level link to a
        live NFT is impossible on Radiant for the second reason, and a repaired
        link would still be droppable by the holder at any transfer. Membership
        is therefore metadata, here as in Photonic.
        """
        if child_ref is not None:
            raise ValidationError(
                "prepare_container_reveal(child_ref=...) was removed in pyrxd 0.15.0: the 100-byte script it "
                "built was permanently unspendable (OP_PUSHINPUTREF left the ref on the stack, so the P2PKH "
                "OP_EQUALVERIFY could never pass) and creating it destroyed the child NFT's singleton ref "
                "irrecoverably. Collection membership lives in the CHILD's envelope: mint the child with "
                "GlyphMetadata(container_refs=[<container ref>]) and build its reveal with "
                "prepare_container_child_reveal(). See docs/reference/glyph-token-protocol-spec.md."
            )
        self._assert_protocol(cbor_bytes, GlyphProtocol.CONTAINER, "CONTAINER")

        ref = GlyphRef(txid=commit_txid, vout=commit_vout)
        return ContainerRevealScripts(
            ref=ref,
            locking_script=build_nft_locking_script(owner_pkh, ref),
            scriptsig_suffix=build_reveal_scriptsig_suffix(cbor_bytes),
            child_ref=None,
        )

    def prepare_delegate_setup(
        self,
        owner_pkh: Hex20,
        authorised_refs: Sequence[GlyphRef],
        *,
        parent_owner_pkh: Hex20 | None = None,
        base_ref: GlyphRef | None = None,
        token_count: int = 0,
    ) -> DelegateSetupScripts:
        """Prepare the one-time delegate setup that authorises ``in``/``by`` claims.

        This is the alternative to :meth:`prepare_container_child_reveal` for a
        minting service, and the only write path pyrxd has for ``by`` at all.
        Where the container-child reveal makes *every* mint spend and re-create
        the parent — permanent custody in the minting wallet, and one serialised
        UTXO every mint contends on — a delegate spends the parents **once**.

        Two transactions, because the second needs the first's outpoint:

        1. Call with *authorised_refs* only. Spend the container and/or author
           tokens, with outputs = :attr:`~DelegateSetupScripts.base_script`
           **plus every script in
           :attr:`~DelegateSetupScripts.parent_scripts`**, which re-create the
           parents unchanged. Consensus refuses the base output unless those
           refs really were among the inputs (``OP_REQUIREINPUTREF`` is
           subset-checked), which is what makes every later claim authorised
           rather than merely asserted.

           **Omitting the parent outputs BURNS the container and author
           tokens.** ``OP_REQUIREINPUTREF`` requires a ref as an input and does
           not carry it forward, so a base transaction that does not re-create
           the parents destroys them — permanently, since a consumed singleton
           can never be re-minted. Only once the parents are back in outputs is
           it true that they can go to cold storage and never be spent again.
        2. Call again with *base_ref* (that output's outpoint) and a
           *token_count*. Spend the base, paying to each of
           :attr:`~DelegateSetupScripts.token_scripts`. Each token authorises one
           mint, so pre-mint as many as you expect to need — N tokens serve N
           concurrent mints with no lock.

        Then each mint passes ``base_ref`` as
        :attr:`CommitParams.delegate_ref`, spends one token in the commit, and
        emits :attr:`RevealScripts.delegate_burn_script` in the reveal.

        What this does NOT prove: that the parent's owner approved this
        particular mint. It proves the mint held a token from a base that held
        the parents. Anyone holding a delegate token can make the claim — that
        is the mechanism working as designed, and why
        :class:`~pyrxd.glyph.relationships.RelationshipBacking` reports
        DELEGATED separately from DIRECT rather than flattening the two.

        :param parent_owner_pkh: who the re-created parent outputs pay to.
            Defaults to *owner_pkh*, which is right when the setup wallet is the
            one holding the parents — the usual case, since it has to spend them.
        :raises ValidationError: *authorised_refs* is empty, or *token_count* is
            given without *base_ref* (or vice versa with no tokens to build).
        """
        if not authorised_refs:
            raise ValidationError(
                "prepare_delegate_setup() needs at least one ref to authorise — a base authorising "
                "nothing delegates nothing and is indistinguishable from a plain P2PKH output."
            )
        if token_count < 0:
            raise ValidationError("token_count must be >= 0")
        if token_count and base_ref is None:
            raise ValidationError(
                "token_count requires base_ref: delegate tokens carry the BASE outpoint, which does "
                "not exist until the base transaction from step 1 has been broadcast. Build the base "
                "first, then call again with base_ref=<that output's outpoint>."
            )
        refs = tuple(authorised_refs)
        # Defaults to the setup wallet: whoever spends a parent singleton IS its
        # owner, so the same key almost always receives it back. Pass it
        # explicitly when a parent should be re-created to a different holder.
        parents_to = owner_pkh if parent_owner_pkh is None else parent_owner_pkh
        return DelegateSetupScripts(
            base_script=build_delegate_base_script(owner_pkh, refs),
            authorised_refs=refs,
            parent_scripts=tuple(build_nft_locking_script(parents_to, ref) for ref in refs),
            token_scripts=tuple(build_delegate_token_script(owner_pkh, base_ref) for _ in range(token_count))
            if base_ref is not None
            else (),
        )

    def prepare_container_child_reveal(
        self,
        commit_txid: str,
        commit_vout: int,
        cbor_bytes: bytes,
        owner_pkh: Hex20,
        container_ref: GlyphRef,
        container_owner_pkh: Hex20,
    ) -> ContainerChildRevealScripts:
        """Prepare scripts for revealing a token **into** a container.

        The child is an ordinary NFT. What makes its membership *checkable* is
        the transaction shape: the reveal spends the container's own NFT UTXO
        and re-creates it unchanged, so the container ref appears among the
        reveal's output-script refs. Photonic's indexer only honours an ``in``
        entry that it can find there (``filterRels``,
        ``packages/app/src/electrum/worker/NFT.ts``) — a claimed ``in`` ref with
        no matching output ref is dropped, which is what stops anyone declaring
        their token part of someone else's collection.

        Build the reveal with **two** inputs — the commit outpoint and the
        container NFT UTXO — and **two** token outputs:

        =========  ==================================================
        output      script
        =========  ==================================================
        ``0``       :attr:`~ContainerChildRevealScripts.nft_script`
        ``1``       :attr:`~ContainerChildRevealScripts.container_script`
        =========  ==================================================

        (plus any change). The container output is byte-identical to the one
        being spent when ``container_owner_pkh`` is unchanged, so the container
        neither moves nor changes hands.

        ``cbor_bytes`` MUST already declare the membership — encode the child's
        metadata with ``container_refs=[container_ref]``. This method
        cross-checks it rather than editing the payload, because the payload
        hash is already committed to on chain by the commit output.

        :raises ValidationError: the envelope is unparseable, does not include
            ``GlyphProtocol.NFT``, or its ``in`` list does not contain
            ``container_ref``.
        """
        self._assert_protocol(cbor_bytes, GlyphProtocol.NFT, "container child")
        try:
            declared = cbor2.loads(cbor_bytes).get("in") or []
        except Exception as exc:
            raise ValidationError(f"Could not parse CBOR for container-membership cross-check: {exc}") from exc
        # Compare the raw wire bytes, unwrapping CBOR tag 64 the way
        # ``decode_payload`` does. Anything that is not a byte string is skipped
        # rather than coerced — ``bytes(<int>)`` would silently manufacture a
        # zero-filled value, and ``bytes(None)`` would raise a TypeError out of
        # a builder whose whole contract is ValidationError.
        wanted = container_ref.to_bytes()
        found = []
        for item in declared if isinstance(declared, (list, tuple)) else []:
            if isinstance(item, cbor2.CBORTag):
                item = item.value
            if isinstance(item, (bytes, bytearray)):
                found.append(bytes(item))
        if wanted not in found:
            raise ValidationError(
                f"child envelope's 'in' list does not contain the container ref "
                f"{container_ref.txid}:{container_ref.vout}. Encode the child metadata with "
                f"container_refs=[GlyphRef(txid={container_ref.txid!r}, vout={container_ref.vout})] — an 'in' "
                "entry with no matching ref in the reveal's outputs is discarded by indexers."
            )

        ref = GlyphRef(txid=commit_txid, vout=commit_vout)
        return ContainerChildRevealScripts(
            ref=ref,
            nft_script=build_nft_locking_script(owner_pkh, ref),
            container_script=build_nft_locking_script(container_owner_pkh, container_ref),
            scriptsig_suffix=build_reveal_scriptsig_suffix(cbor_bytes),
            container_ref=container_ref,
        )

    @staticmethod
    def _assert_protocol(cbor_bytes: bytes, marker: GlyphProtocol, label: str) -> None:
        """Cross-check that ``cbor_bytes`` declares *marker* in its ``p`` field."""
        try:
            protocol = cbor2.loads(cbor_bytes).get("p", [])
            if marker not in protocol:
                raise ValidationError(
                    f"CBOR protocol field {protocol!r} must include GlyphProtocol.{marker.name} ({int(marker)})"
                )
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Could not parse CBOR for {label} cross-check: {exc}") from exc

    # ------------------------------------------------------------------
    # WAVE reveal

    def prepare_wave_reveal(
        self,
        commit_txid: str,
        commit_vout: int,
        cbor_bytes: bytes,
        owner_pkh: Hex20,
        name: str,
    ) -> MutableRevealScripts:
        """Prepare scripts for a WAVE (on-chain naming) reveal.

        WAVE extends MUT with a ``name`` field in the CBOR payload.
        Protocol field must include ``GlyphProtocol.WAVE`` (11).

        ``name`` must be non-empty printable ASCII, max 255 characters.
        The name is validated here but must already be embedded in
        ``cbor_bytes`` by the caller via either ``attrs["name"]`` (the
        Photonic-compatible canonical shape — required for resolution against
        RXinDexer and other indexers) or top-level ``name`` (legacy pyrxd
        shape, accepted for backwards compatibility but not indexer-visible).

        Photonic-compatible CBOR shape (canonical, see Photonic Wallet
        ``packages/lib/src/wave.ts``)::

            {
                "p": [2, 5, 11],
                "attrs": {
                    "name": "alice.rxd",
                    "domain": "rxd",
                    "target": "<radiant_address>",
                    "target_type": "address"
                }
            }

        Use :meth:`build_wave_attrs` (or :func:`pyrxd.glyph.wave.build_wave_metadata`)
        to construct the canonical shape; passing a top-level ``name`` field
        still works but emits a token RXinDexer will not index.

        Protocol requirement: ``[NFT(2), MUT(5), WAVE(11)]``.

        The reveal shape is MUT's, including its **two-input** requirement: the
        commit outpoint plus a seed outpoint at ``commit_vout + 1`` that gives
        the mutable contract its own singleton ref. See
        :meth:`prepare_mutable_reveal` — a WAVE registration built without the
        seed input is rejected by consensus, as every one built through 0.15.0
        was.
        """
        if not name or not name.isprintable() or len(name) > 255:
            raise ValidationError("WAVE name must be non-empty printable ASCII, max 255 characters")
        try:
            cbor_data = cbor2.loads(cbor_bytes)
            protocol = cbor_data.get("p", [])
            if GlyphProtocol.WAVE not in protocol:
                raise ValidationError(
                    f"CBOR protocol field {protocol!r} must include GlyphProtocol.WAVE ({GlyphProtocol.WAVE})"
                )
            if GlyphProtocol.MUT not in protocol:
                raise ValidationError(f"WAVE protocol must also include GlyphProtocol.MUT ({GlyphProtocol.MUT})")
            # Prefer the Photonic-compatible attrs.name; fall back to top-level
            # name/n for backwards compatibility with pre-Photonic-shape pyrxd
            # tokens. Tokens minted without attrs.name will not resolve against
            # RXinDexer — see the docstring above.
            attrs = cbor_data.get("attrs") or {}
            cbor_name = attrs.get("name") if isinstance(attrs, dict) else None
            if not cbor_name:
                cbor_name = cbor_data.get("name") or cbor_data.get("n", "")
            if cbor_name != name:
                raise ValidationError(
                    f"name argument {name!r} does not match CBOR name field {cbor_name!r}. "
                    f"Checked attrs.name then top-level name/n."
                )
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Could not parse CBOR for WAVE cross-check: {exc}") from exc

        # WAVE uses the same two-output structure as MUT.
        return self.prepare_mutable_reveal(
            commit_txid=commit_txid,
            commit_vout=commit_vout,
            cbor_bytes=cbor_bytes,
            owner_pkh=owner_pkh,
        )

    def build_transfer_locking_script(
        self,
        ref: GlyphRef,
        new_owner_pkh: Hex20,
        is_nft: bool,
    ) -> bytes:
        """Build the locking script for a transfer output."""
        if is_nft:
            return build_nft_locking_script(new_owner_pkh, ref)
        return build_ft_locking_script(new_owner_pkh, ref)

    def build_nft_transfer_tx(self, params: TransferParams) -> TransferResult:
        """
        Build a signed NFT transfer transaction.

        Spends an existing NFT UTXO (standard P2PKH scriptSig unlock: <sig> <pubkey>)
        and creates a new NFT output locked to ``new_owner_pkh``. The 36-byte ref is
        preserved across the transfer — it's extracted from the input's NFT script and
        written into the new output's NFT script unchanged.

        Fee calculation is two-pass: build a trial tx, sign it to measure actual
        serialised size, then rebuild with the final value = input_value - size*fee_rate.
        The trial signature is discarded (reset unlocking_script = None before final sign)
        so the final tx carries a signature over the *final* outputs, not the trial ones.

        A CONTAINER is transferred by this method too — its locking script *is*
        the 63-byte NFT singleton, and its collection membership lives in the
        envelope, so a transfer cannot drop it. Nothing extra to do.

        :param params: TransferParams — see dataclass docstring
        :returns: TransferResult — signed tx, new locking script, ref, fee
        :raises ValidationError: nft_script is not a valid 63-byte NFT script
        :raises ValueError: nft_utxo_value - fee below pyrxd's uneconomic-output
            floor :data:`pyrxd.constants.DUST_THRESHOLD_PHOTONS` — a pyrxd policy,
            not a Radiant relay limit
        """
        # Local import to avoid circular import at module load (transaction/script
        # modules don't depend on glyph, but we keep builder.py import-time light).
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        # 0. The RATE has to be judged before any bytes exist, and nothing further
        #    down can do it: `required_fee` binds the caller's rate and only the
        #    caller's rate (see its docstring), so a sub-floor rate produces a
        #    transaction that is internally consistent, passes every later assertion,
        #    and is refused by every node on the network. Same refusal the FT builders
        #    next door make, via the same shared implementation — and, since #458, with
        #    the same sub-floor opt-out. The floor is a fixed MAINNET constant, so
        #    without one this refused a rate that is legitimate on a regtest node whose
        #    floor really is a tenth of it.
        assert_fee_rate_clears_relay_floor(
            params.fee_rate,
            what="build_nft_transfer_tx",
            allow_overpay=params.allow_overpay,
            allow_below_relay_floor=params.allow_below_relay_floor,
        )

        # 1. Validate input script shape and extract ref.
        #    extract_ref_from_nft_script raises ValidationError if len != 63 or
        #    first byte != 0xd8.
        if not isinstance(params.nft_script, (bytes, bytearray)):
            raise ValidationError("nft_script must be bytes")
        if is_legacy_container_script(bytes(params.nft_script).hex()):
            # Say WHY rather than "not a valid NFT script": this output cannot be
            # spent by anyone, and the holder needs to know that instead of
            # hunting for a builder that would move it.
            raise ValidationError(
                "this is a pre-0.15.0 CONTAINER-with-child-ref output (100 bytes) and it is permanently "
                "unspendable: OP_PUSHINPUTREF leaves the child ref on the stack, so the P2PKH tail hashes "
                "the ref and OP_EQUALVERIFY fails for every scriptSig. No transfer of it can succeed. See "
                "pyrxd.glyph.script.is_legacy_container_script."
            )
        ref = extract_ref_from_nft_script(bytes(params.nft_script))

        # 2. Build the new NFT locking script for the recipient (ref unchanged).
        new_nft_script = build_nft_locking_script(params.new_owner_pkh, ref)

        # 3. The existing NFT script is:
        #      OP_PUSHINPUTREFSINGLETON <36B ref> OP_DROP OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
        #    After the leading ref-check + OP_DROP, the remaining tail is a standard
        #    P2PKH. So a standard P2PKH scriptSig (<sig> <pubkey>) unlocks it.
        unlocking_template = P2PKH().unlock(params.private_key)

        # 4. Wire up the input. We need a source_transaction wrapper so
        #    TransactionInput.__init__ and preimage computation can index
        #    source_transaction.outputs[vout] — but we don't have the real parent
        #    tx, only its txid + output info. Pad the shim's output list so vout
        #    is a valid index, then put the actual NFT output at that index.
        padding_output = TransactionOutput(Script(b""), 0)
        shim_outputs = [padding_output] * params.nft_utxo_vout + [
            TransactionOutput(Script(bytes(params.nft_script)), params.nft_utxo_value)
        ]
        src = Transaction(tx_inputs=[], tx_outputs=shim_outputs)
        # Override txid so signing uses the real UTXO's txid, not the shim's hash.
        src.txid = lambda: params.nft_utxo_txid  # type: ignore[method-assign]

        def _make_input() -> TransactionInput:
            inp = TransactionInput(
                source_transaction=src,
                source_txid=params.nft_utxo_txid,
                source_output_index=params.nft_utxo_vout,
                unlocking_script_template=unlocking_template,
            )
            # TransactionInput.__init__ fills satoshis/locking_script from
            # source_transaction.outputs[source_output_index]; re-assert them
            # explicitly in case vout doesn't match the shim's index-0 output.
            inp.satoshis = params.nft_utxo_value
            inp.locking_script = Script(bytes(params.nft_script))
            return inp

        # 5. Two-pass fee calculation. First pass: trial with nft_utxo_value as
        #    output (no fee yet) — sign, measure byte_length, compute fee.
        #
        #    The trial measurement is padded by SIG_SIZE_SLACK_BYTES per input before
        #    it is fee'd. Without that padding this builder fee'd the TRIAL bytes and
        #    handed back the FINAL ones: the two passes sign different messages (the
        #    final one commits to the real output value), so their DER signatures are
        #    not the same length, and whenever the final one came out longer the
        #    transaction paid for fewer bytes than it contained. Measured over 3000
        #    builds on fresh keys at the default rate: 746 (24.9%) landed 1-2 bytes
        #    short. Signing is deterministic (RFC 6979), so an affected transfer is
        #    short on every retry — it is a property of that NFT and that recipient,
        #    not a flake. This is byte-for-byte the defect already fixed in
        #    ``pyrxd.wallet`` / ``pyrxd.hd.wallet``; the rule lives in one place now.
        trial_input = _make_input()
        trial_tx = Transaction(
            tx_inputs=[trial_input],
            tx_outputs=[TransactionOutput(Script(new_nft_script), params.nft_utxo_value)],
        )
        trial_tx.sign()
        # One input, always: this builder spends the NFT UTXO and nothing else.
        size = trial_size_with_slack(trial_tx.byte_length(), len(trial_tx.inputs))
        fee = required_fee(size, params.fee_rate)

        output_value = params.nft_utxo_value - fee
        # pyrxd POLICY floor, not a node rule: Radiant would relay any output of 1
        # photon or more. The guard stays because an NFT carrier left with less than
        # this is worth less than the fee to move it again, and the caller should
        # attach funding instead.
        if output_value < DUST_THRESHOLD_PHOTONS:
            raise ValueError(
                f"NFT UTXO value ({params.nft_utxo_value}) too small to cover transfer "
                f"fee ({fee} for {size} bytes at {params.fee_rate} photons/byte): "
                f"output would be {output_value}, below pyrxd's {DUST_THRESHOLD_PHOTONS}-photon "
                "uneconomic-output floor (a pyrxd policy, NOT a Radiant relay limit — "
                "Radiant's floor is 1 photon). To move a dust-carrying singleton, use "
                "pyrxd.glyph.transfer.build_nft_transfer (or GlyphClient.transfer_nft), "
                "which funds the fee from a separate plain-RXD input and leaves the "
                "singleton's value untouched."
            )

        # 6. Final pass: rebuild from scratch so there's no stale signature. Don't
        #    reuse trial_input — Transaction.sign(bypass=True) only signs inputs
        #    whose unlocking_script is None, and a previously-set trial sig would
        #    be silently kept (signed over trial outputs, not final outputs).
        final_input = _make_input()
        final_tx = Transaction(
            tx_inputs=[final_input],
            tx_outputs=[TransactionOutput(Script(new_nft_script), output_value)],
        )
        final_tx.sign()

        # 7. The fee this transaction ACTUALLY pays must clear the rate it was built
        #    for, measured on the bytes it actually contains. The headroom above is
        #    what should make this unreachable; this is what proves it, rather than
        #    trusting it. Refusing costs an aborted build — returning costs the NFT's
        #    own UTXO for 8 hours, because Radiant has neither RBF nor CPFP and a
        #    below-floor transaction can be neither replaced nor bumped.
        #
        #    ``assert_pays_for_its_size``, not ``assert_tx_pays_for_itself``: the fee
        #    is derived from the caller's ``nft_utxo_value``, which is the number the
        #    node will use, rather than from the SHIM ``source_transaction`` built at
        #    step 4 — a padded stand-in with a monkey-patched ``txid`` that exists
        #    only to make the preimage computable. Reading a fee out of a fake is a
        #    dependency this check should not have.
        assert_pays_for_its_size(
            size_bytes=final_tx.byte_length(),
            fee_paid=params.nft_utxo_value - output_value,
            fee_rate=params.fee_rate,
            what="build_nft_transfer_tx",
        )

        return TransferResult(
            tx=final_tx,
            new_nft_script=new_nft_script,
            ref=ref,
            fee=fee,
        )

    def build_ft_transfer_tx(self, params: FtTransferParams) -> FtTransferResult:
        """Build a signed FT transfer transaction enforcing conservation.

        Thin delegator to :meth:`FtUtxoSet.build_transfer_tx` — the real logic
        (selection, two-pass fee, conservation) lives there so the API surface
        is available both at the builder level and directly on a UTXO-set
        instance. That method is itself a single-recipient
        :meth:`FtUtxoSet.build_airdrop_tx`, so the recipient output's value is
        ``params.amount`` and nothing else.

        :param params: :class:`FtTransferParams` — see dataclass docstring.
        :returns:      :class:`FtTransferResult` — signed tx + scripts + fee.
        :raises ValueError: same conditions as :meth:`FtUtxoSet.build_transfer_tx`
            (insufficient FT balance, sub-floor fee rate, funding too small).
        """
        # Local import: FtUtxoSet depends on this module (for MIN_FEE_RATE
        # parity), but we only need it at call time.
        from .ft import FtUtxoSet

        utxo_set = FtUtxoSet(ref=params.ref, utxos=params.utxos)
        return utxo_set.build_transfer_tx(
            amount=params.amount,
            new_owner_pkh=params.new_owner_pkh,
            private_key=params.private_key,
            funding=params.funding,
            fee_rate=params.fee_rate,
            change_pkh=params.change_pkh,
            dust_limit=params.dust_limit,
            allow_overpay=params.allow_overpay,
            allow_below_relay_floor=params.allow_below_relay_floor,
        )

    def build_ft_airdrop_tx(self, params: FtAirdropParams) -> FtAirdropResult:
        """Build one signed transaction paying FT units to many recipients.

        Thin delegator to :meth:`FtUtxoSet.build_airdrop_tx`, exactly as
        :meth:`build_ft_transfer_tx` delegates to ``build_transfer_tx`` — the
        selection, conservation and two-pass fee logic live on the UTXO set so
        both API surfaces share one implementation rather than two that can
        disagree about how many units exist.

        :param params: :class:`FtAirdropParams` — see dataclass docstring.
        :returns:      :class:`~pyrxd.glyph.ft.FtAirdropResult`.
        :raises ValidationError: bad recipient list, or the conservation backstop.
        :raises ValueError: fee rate below Radiant's relay floor, or the selected
            inputs' RXD cannot cover dust + royalty + fee.
        """
        from .ft import FtUtxoSet

        utxo_set = FtUtxoSet(ref=params.ref, utxos=params.utxos)
        return utxo_set.build_airdrop_tx(
            recipients=params.recipients,
            private_key=params.private_key,
            funding=params.funding,
            fee_rate=params.fee_rate,
            change_pkh=params.change_pkh,
            dust_limit=params.dust_limit,
            royalty=params.royalty,
            sale_price=params.sale_price,
            pay_royalty=params.pay_royalty,
            allow_overpay=params.allow_overpay,
            allow_below_relay_floor=params.allow_below_relay_floor,
        )


# ---------------------------------------------------------------------------
# dMint deploy API dataclasses
# ---------------------------------------------------------------------------

from .dmint import DaaMode, DmintAlgo  # noqa: E402 (after class def — no circular dep)


def _validate_premine(premine_amount: int | None, premine_pkh: Hex20 | None) -> None:
    """Shared V1/V2 bound-check for the dMint deploy premine fields.

    The floor is 1 photon, not 546. Radiant-Core has **no dust threshold**:
    ``GetDustThreshold`` returns 1 satoshi unconditionally and ``IsDust`` is
    ``nValue <= 0`` (``src/policy/policy.cpp:19-25`` @ ``v3.1.2``), so any
    output worth at least one photon is standard regardless of script shape.
    That is why every mainnet dMint contract sits at 1 photon. The 546 in
    :meth:`GlyphBuilder.prepare_ft_deploy_reveal` is a pyrxd-imposed guard on a
    *different* flow (a whole FT supply below 546 units is almost certainly a
    decimals mistake), not a chain rule, and it should not be copied here — a
    deliberate 1-unit premine is a legitimate thing to want.
    """
    if premine_amount is None:
        if premine_pkh is not None:
            raise ValidationError(
                "premine_pkh was set without premine_amount — the premine output would "
                "not be emitted at all. Set premine_amount, or drop premine_pkh."
            )
        return
    if isinstance(premine_amount, bool) or not isinstance(premine_amount, int):
        raise ValidationError(f"premine_amount must be an int or None, got {type(premine_amount).__name__}")
    if premine_amount < 1:
        raise ValidationError(
            f"premine_amount must be >= 1 photon when set (use None for no premine), got {premine_amount}"
        )
    if premine_amount > _MAX_PHOTONS:
        raise ValidationError(f"premine_amount ({premine_amount}) exceeds Radiant's money supply ({_MAX_PHOTONS})")


def _build_premine_script(
    premine_amount: int | None,
    premine_pkh: Hex20 | None,
    owner_pkh: Hex20,
    token_ref: GlyphRef,
) -> bytes | None:
    """The premine output's locking script, or ``None`` when there is no premine.

    Shared by the V1 and V2 ``build_reveal_outputs``; the premine output is
    identical in both (an FT lock on ``tokenRef``) because the token itself is
    version-independent — only the *contract* bytecode differs between V1 and
    V2. It is byte-identical to the FT reward output a mint pays out
    (``build_dmint_v1_ft_output_script``), so the premined units are fungible
    with mined units under the same ``tokenRef``.
    """
    if premine_amount is None:
        return None
    return build_ft_locking_script(premine_pkh if premine_pkh is not None else owner_pkh, token_ref)


@dataclass(frozen=True)
class DmintV1DeployParams:
    """Parameters for a V1 dMint deploy (2-tx: commit + reveal).

    V1 is the only dMint format on Radiant mainnet today. Unlike V2 (which
    uses a separate deploy tx with a reward pool), V1 emits ``num_contracts``
    parallel singleton contract UTXOs directly in the reveal — each is the
    full state+epilogue codescript at height=0. Mining works by spending
    a contract UTXO and re-creating it at height+1 with the same script
    template; the reward is paid from a miner-supplied funding input.

    See ``docs/dmint-research-photonic-deploy.md`` for the byte-by-byte
    chain shape this dataclass drives. Live mainnet example: Radiant
    Glyph Protocol (GLYPH) at commit a443d9df…878b → reveal b965b32d…9dd6.

    :param metadata:           :class:`GlyphMetadata` for the token. Must
        include protocol ``[GlyphProtocol.FT, GlyphProtocol.DMINT]`` ([1, 4])
        and NOT include a ``v`` version field (V2 uses ``v``; V1 omits it).
    :param owner_pkh:          20-byte PKH of the key that signs commit and
        all ref-seed P2PKH inputs in the reveal.
    :param num_contracts:      Count of parallel V1 dMint contract UTXOs to
        emit. Total supply = ``reward_photons * max_height * num_contracts``.
        Validated to ``[1, 250]`` at construction. 250 is a pyrxd ERGONOMICS
        ceiling, not a node limit: at ≈ 241 bytes/contract output it keeps the
        reveal near ~64 KB before the embedded media body. Radiant's own
        ``MAX_STANDARD_TX_SIZE`` is 20_000_000 bytes
        (``Radiant-Core/src/policy/policy.h:69`` @ v3.1.2) and is never even
        consulted, since ``fRequireStandard`` is hardcoded ``false``
        (``src/validation.cpp:271``, ``src/init.cpp:1995`` @ v3.1.2). What
        actually bounds this is fee: every contract output costs ~241 bytes
        × the 10_000 photons/byte relay floor.
    :param max_height:         Maximum mints per contract (3-byte ceiling).
    :param reward_photons:     Photons paid per successful mint (3-byte
        ceiling — see V1 contract state layout).
    :param difficulty:         Initial PoW difficulty (1 = easiest).
        Translated to 8-byte target via :func:`difficulty_to_target`.
    :param premine_amount:     Photons emitted as an additional FT output on
        the reveal tx (1 photon = 1 FT unit), on top of the mineable supply.
        ``None`` = no premine. The photons are real: the deployer must fund
        them, and they are NOT deducted from ``reward_photons * max_height *
        num_contracts`` — total issued supply becomes
        ``reward_photons * max_height * num_contracts + premine_amount``.
        Mirrors Photonic Wallet ``RevealDmintParams.premine`` (``mint.ts``
        ``createRevealOutputs``), which likewise appends one ``ftScript``
        output after the contract outputs.
    :param premine_pkh:        20-byte PKH that receives the premine output.
        ``None`` (default) sends it to ``owner_pkh``, which is what Photonic
        does (it uses the single creator address for both). Only meaningful
        when ``premine_amount`` is set.
    :param op_return_msg:      Optional OP_RETURN data carrier (raw bytes
        after the 0x6a prefix). ``None`` = no OP_RETURN output.
    :param algo:               PoW algorithm. Defaults to ``DmintAlgo.SHA256D``
        (the only algorithm on V1 mainnet today).
    """

    metadata: GlyphMetadata
    owner_pkh: Hex20
    num_contracts: int
    max_height: int
    reward_photons: int
    difficulty: int
    premine_amount: int | None = None
    op_return_msg: bytes | None = None
    algo: DmintAlgo = DmintAlgo.SHA256D
    premine_pkh: Hex20 | None = None

    def __post_init__(self) -> None:
        _validate_premine(self.premine_amount, self.premine_pkh)
        if not (1 <= self.num_contracts <= 250):
            raise ValidationError(
                f"num_contracts must be in [1, 250], got {self.num_contracts} "
                "(250 is a pyrxd ergonomics ceiling on the V1 deploy reveal size, not a node limit "
                "— Radiant never consults standardness; raise it deliberately if you mean it)"
            )
        if self.max_height < 1:
            raise ValidationError(f"max_height must be >= 1, got {self.max_height}")
        if self.max_height > 0xFFFFFF:
            raise ValidationError(f"max_height ({self.max_height}) exceeds V1's 3-byte ceiling (0xFFFFFF)")
        if self.reward_photons < 1:
            raise ValidationError(f"reward_photons must be >= 1, got {self.reward_photons}")
        if self.reward_photons > 0xFFFFFF:
            raise ValidationError(f"reward_photons ({self.reward_photons}) exceeds V1's 3-byte ceiling (0xFFFFFF)")
        if self.difficulty < 1:
            raise ValidationError(f"difficulty must be >= 1, got {self.difficulty}")
        if self.algo != DmintAlgo.SHA256D:
            raise ValidationError(
                f"V1 dMint only supports SHA256d; got {self.algo}. Use DmintV2DeployParams for blake3/k12."
            )


@dataclass
class DmintV2DeployParams:
    """Parameters for a V2 dMint token deploy (2-tx: commit + reveal).

    Mirrors :class:`DmintV1DeployParams`. V2 emits ``num_contracts`` parallel
    **1-photon singleton** contract UTXOs directly in the reveal —
    ``contractRef[i] = commit:(i+1)``, ``tokenRef = commit:0`` — exactly like V1.
    The only consensus differences are the V2 contract bytecode (10-item state +
    the V2 covenant) and the 8-byte mint nonce; the reward + tx fee for each mint
    come from a miner-supplied funding input, not a pool.

    All five ``DaaMode`` values are supported — FIXED, ASERT, LWMA, EPOCH, and
    SCHEDULE — and the redesigned covenant advances ``target``/``last_time``
    on-chain, byte-matched to canonical Photonic ``dMintScript`` (incl. the
    EPOCH/LWMA int64-overflow fix, Radiant-Core/Photonic-Wallet#2). See #219.

    V2 is consensus-proven on regtest + mainnet but still pre-external-audit;
    ``prepare_dmint_deploy`` deploys V2 by default as of 0.9.0 (``allow_v2_deploy``
    defaults to ``True`` and is retained only for backward-compatibility).

    :param metadata:        :class:`GlyphMetadata` (must include ``GlyphProtocol.FT``
        and ``GlyphProtocol.DMINT``; set ``version=2`` so indexers classify it as V2).
    :param owner_pkh:       20-byte PKH of the key that signs commit + the
        ref-seed reveal inputs.
    :param num_contracts:   Count of parallel V2 contract UTXOs (``[1, 250]``).
    :param max_height:      Maximum mints per contract.
    :param reward_photons:  Photons paid per successful mint.
    :param difficulty:      Initial PoW difficulty (1 = easiest).
    :param premine_amount:  Photons emitted as an extra FT output on the reveal,
        on top of the mineable supply (mirrors V1 — see
        :class:`DmintV1DeployParams`). If ``metadata`` carries a ``dmint.premine``
        field, the two must agree or the deploy is refused.
    :param premine_pkh:     PKH receiving the premine; ``None`` = ``owner_pkh``.
    :param op_return_msg:   Optional OP_RETURN data carrier (raw bytes after 0x6a).
    :param algo:            PoW algorithm (default SHA256d; only SHA256D is mined).
    :param daa_mode:        Must be ``DaaMode.FIXED`` (the only mintable mode).
    :param target_time:     Echoed into the state (DAA-only; vestigial for FIXED).
    :param half_life:       Echoed into the code (DAA-only; vestigial for FIXED).
    """

    metadata: GlyphMetadata
    owner_pkh: Hex20
    num_contracts: int
    max_height: int
    reward_photons: int
    difficulty: int
    premine_amount: int | None = None
    op_return_msg: bytes | None = None
    algo: DmintAlgo = DmintAlgo.SHA256D
    daa_mode: DaaMode = DaaMode.FIXED
    target_time: int = 60
    half_life: int = 3600
    epoch_length: int = 2016  # EPOCH: retarget every N blocks
    max_adjustment_log2: int = 2  # EPOCH: max 2^N adjustment per epoch (1..4)
    schedule: tuple[tuple[int, int], ...] = ()  # SCHEDULE: ascending (height, target) entries
    premine_pkh: Hex20 | None = None

    def __post_init__(self) -> None:
        _validate_premine(self.premine_amount, self.premine_pkh)
        if not (1 <= self.num_contracts <= 250):
            raise ValidationError(
                f"num_contracts must be in [1, 250], got {self.num_contracts} "
                "(250 is a pyrxd ergonomics ceiling on the deploy reveal size, not a node limit "
                "— Radiant never consults standardness; raise it deliberately if you mean it)"
            )
        if self.max_height < 1:
            raise ValidationError(f"max_height must be >= 1, got {self.max_height}")
        if self.reward_photons < 1:
            raise ValidationError(f"reward_photons must be >= 1, got {self.reward_photons}")
        if self.difficulty < 1:
            raise ValidationError(f"difficulty must be >= 1, got {self.difficulty}")
        # All five DAA modes are supported (FIXED/ASERT/LWMA/EPOCH/SCHEDULE). EPOCH was
        # temporarily refused here while its canonical bytecode had an int64-overflow that
        # bricked the contract on-chain; that fix is now merged upstream
        # (Radiant-Core/Photonic-Wallet#2 — divide-first + 2^48 clamp on both sides of the
        # retarget multiply) and pyrxd byte-matches it, so EPOCH deploy is re-enabled.
        # Per-mode parameter validation (EPOCH 2^48 target cap + power-of-2 adjustment,
        # SCHEDULE entry shape) is enforced by DmintDeployParams when the scripts are built.


class DmintFullDeployParams(DmintV2DeployParams):
    """Deprecated alias for :class:`DmintV2DeployParams`.

    Kept as a real subclass (NOT a bare type alias) so ``__init__``
    emits a ``DeprecationWarning`` at construction time — a bare alias
    would only warn if callers introspect the class. Scheduled for
    removal in pyrxd v0.6.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        import warnings

        warnings.warn(
            "DmintFullDeployParams is deprecated; use DmintV2DeployParams "
            "(or the new DmintV1DeployParams for V1 deploys, which is what "
            "every live mainnet token uses). DmintFullDeployParams will be "
            "removed in pyrxd v0.6.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


@dataclass(frozen=True)
class DmintV1RevealScripts:
    """Output scripts for the V1 dMint deploy reveal tx.

    Mirrors the shape of :class:`FtDeployRevealScripts` (a flat
    locking-script + scriptsig-suffix bag), but with V1's distinctive
    multi-output structure: N contract scripts + optional premine FT
    + optional OP_RETURN. The caller composes these into a transaction
    in declared order, signs each input, and broadcasts.

    **Output order is part of the contract with this bag.** Place them as::

        vout[0 .. N-1]   contract_scripts, each valued contract_value (1)
        vout[N]          premine_script,   valued premine_amount   (if any)
        vout[N+1]        op_return_script, valued 0                (if any)
        vout[...]        change

    which is what Photonic Wallet's ``createRevealOutputs`` emits
    (``mint.ts``: the ``premine > 0`` ``ftScript`` push comes directly after
    the ``numContracts`` ``dMintScript`` pushes). Nothing in consensus reads
    the ordering — the reveal runs only the commit hashlock, whose
    ``OP_REFTYPE_OUTPUT`` check is position-independent — but indexers key
    off it, so deviating makes a token that pyrxd can spend and other tools
    cannot classify.

    Safety note on the premine script shape: it is an FT lock, so it pushes
    ``tokenRef`` with ``OP_PUSHINPUTREF`` (0xd0, refType NORMAL). The commit
    hashlock the reveal spends asserts ``OP_REFTYPE_OUTPUT == OP_1`` (NORMAL)
    for exactly this ref. Emitting the premine as an NFT/singleton lock
    (0xd8) would flip that to SINGLETON and the reveal would be rejected.

    :param contract_scripts:  Tuple of full V1 dMint contract output
        scripts (state + epilogue), one per parallel contract. Length
        equals the deploy's ``num_contracts``. Each is the 241-byte
        layout at height=0 with ``contractRef[i] = (commit_txid, i+1)``
        and ``tokenRef = (commit_txid, 0)``.
    :param contract_value:    Photons per contract output. Always 1
        (V1 contracts are singletons — the photon value stays at 1
        as the contract advances).
    :param cbor_bytes:        Encoded CBOR token body. Caller pushes
        this in the reveal's vin[0] scriptSig (after sig + pubkey),
        preceded by the ``gly`` magic bytes push.
    :param scriptsig_suffix:  The push sequence ``<gly> <CBOR>`` ready
        to append after ``<sig> <pubkey>`` for vin[0]. Mirrors the
        :class:`FtDeployRevealScripts.scriptsig_suffix` convention.
    :param premine_script:    75-byte FT locking script for the optional
        premine output, bound to ``tokenRef`` (``None`` = no premine).
    :param premine_amount:    Photons for the premine output (``None``
        if no premine). Set it as that output's value verbatim.
    :param op_return_script:  Locking script for an optional OP_RETURN
        data carrier (``None`` if no OP_RETURN).
    """

    contract_scripts: tuple[bytes, ...]
    contract_value: int
    cbor_bytes: bytes
    scriptsig_suffix: bytes
    premine_script: bytes | None
    premine_amount: int | None
    op_return_script: bytes | None


@dataclass(frozen=True)
class DmintV1DeployResult:
    """Output of :meth:`GlyphBuilder.prepare_dmint_deploy` for V1 deploys.

    Carries everything the caller needs to broadcast a V1 deploy:
    the commit-tx script + CBOR body, plus a deferred-builder method
    that produces the reveal-tx outputs once the commit confirms.

    V1 differs from V2 in that there is no separate deploy tx — the
    reveal directly creates the parallel contract UTXOs. So this
    result has no ``deploy_params_template`` / ``initial_pool_photons``
    / ``placeholder_contract_script`` fields; instead it carries
    ``placeholder_contract_scripts`` (one per parallel contract) for
    fee estimation before the commit txid is known.

    :param commit_result:                 :class:`CommitResult` — commit-tx
        script + fee. Same shape as the V2 result's field.
    :param cbor_bytes:                    Encoded CBOR token body.
    :param owner_pkh:                     20-byte PKH of the deploy key.
    :param premine_amount:                Photons for the optional premine
        output, or ``None`` for no premine.
    :param num_contracts:                 Count of parallel V1 contracts.
    :param placeholder_contract_scripts:  Tuple of N contract scripts built
        with the placeholder commit txid (00…00). Each is the same byte
        length as the final contract script — the only difference is the
        ``contractRef`` / ``tokenRef`` txid component. Use the length
        for fee estimation.
    :param max_height:                    Echoed from params for
        ``build_reveal_outputs`` access.
    :param reward_photons:                Echoed from params.
    :param difficulty:                    Echoed from params.
    :param algo:                          Echoed from params.
    :param op_return_msg:                 Echoed from params.
    :param premine_pkh:                   Echoed from params; ``None`` means
        the premine (if any) goes to ``owner_pkh``.
    """

    commit_result: CommitResult
    cbor_bytes: bytes
    owner_pkh: Hex20
    premine_amount: int | None
    num_contracts: int
    placeholder_contract_scripts: tuple[bytes, ...]
    max_height: int
    reward_photons: int
    difficulty: int
    algo: DmintAlgo
    op_return_msg: bytes | None
    premine_pkh: Hex20 | None = None

    def build_reveal_outputs(self, commit_txid: str) -> DmintV1RevealScripts:
        """Build reveal-tx output scripts given the confirmed commit txid.

        The V1 reveal:

        * spends commit vouts 0 (FT-commit hashlock) + 1..N (ref-seeds) + change
        * emits N parallel dMint contract UTXOs at vouts 0..N-1
        * emits the optional premine FT output, then the optional OP_RETURN,
          then change — see :class:`DmintV1RevealScripts` for the ordering rule

        The method name is ``build_reveal_outputs`` (not
        ``build_reveal_scripts`` as in V2) because V1's reveal directly
        creates the *output* contract UTXOs — there is no separate
        deploy tx. The arity also differs from V2's (no commit_vout /
        commit_value needed: V1 input values are protocol constants).
        Distinct names prevent silent polymorphic-call TypeErrors.

        :param commit_txid:  txid of the confirmed commit tx.
        :returns:            :class:`DmintV1RevealScripts` ready to be
            placed into the reveal tx's outputs.
        """
        from .dmint import (
            build_dmint_v1_contract_script,
            difficulty_to_target,
        )

        token_ref = GlyphRef(txid=commit_txid, vout=0)
        target = difficulty_to_target(self.difficulty, self.algo)
        contract_scripts = tuple(
            build_dmint_v1_contract_script(
                height=0,
                contract_ref=GlyphRef(txid=commit_txid, vout=i + 1),
                token_ref=token_ref,
                max_height=self.max_height,
                reward=self.reward_photons,
                target=target,
                algo=self.algo,
            )
            for i in range(self.num_contracts)
        )
        scriptsig_suffix = build_reveal_scriptsig_suffix(self.cbor_bytes)

        op_return_script: bytes | None = None
        if self.op_return_msg is not None:
            # OP_RETURN <push msg>. Use direct push when len <= 75.
            msg = self.op_return_msg
            if len(msg) <= 75:
                op_return_script = bytes([0x6A, len(msg)]) + msg
            elif len(msg) <= 255:
                op_return_script = bytes([0x6A, 0x4C, len(msg)]) + msg  # OP_RETURN OP_PUSHDATA1 <len> <msg>
            else:
                raise ValidationError(f"op_return_msg too long: {len(msg)} bytes (cap at 255 for now)")

        premine_script = _build_premine_script(self.premine_amount, self.premine_pkh, self.owner_pkh, token_ref)

        return DmintV1RevealScripts(
            contract_scripts=contract_scripts,
            contract_value=1,
            cbor_bytes=self.cbor_bytes,
            scriptsig_suffix=scriptsig_suffix,
            premine_script=premine_script,
            premine_amount=self.premine_amount,
            op_return_script=op_return_script,
        )


@dataclass
class DmintV2DeployResult:
    """Output of :meth:`GlyphBuilder.prepare_dmint_deploy` for V2 deploys.

    Mirrors :class:`DmintV1DeployResult`: V2 emits ``num_contracts`` parallel
    1-photon singleton contract UTXOs directly in the reveal (no separate deploy
    tx, no reward pool). Call :meth:`build_reveal_outputs` once the commit
    confirms to get the reveal-tx output scripts.

    :param commit_result:                 :class:`CommitResult` — commit-tx script + fee.
    :param cbor_bytes:                    Encoded CBOR token body.
    :param owner_pkh:                     20-byte PKH of the deploy key.
    :param premine_amount:                Photons for the optional premine output,
        or ``None`` for no premine (mirrors V1).
    :param num_contracts:                 Count of parallel V2 contracts.
    :param placeholder_contract_scripts:  Tuple of N V2 contract scripts built with the
        placeholder commit txid (00…00) — same byte length as the final scripts, for
        fee estimation before the commit txid is known.
    :param max_height, reward_photons, difficulty, algo, op_return_msg, daa_mode,
        target_time, half_life:  Echoed from params for :meth:`build_reveal_outputs`.
    """

    commit_result: CommitResult
    cbor_bytes: bytes
    owner_pkh: Hex20
    premine_amount: int | None
    num_contracts: int
    placeholder_contract_scripts: tuple[bytes, ...]
    max_height: int
    reward_photons: int
    difficulty: int
    algo: DmintAlgo
    op_return_msg: bytes | None
    daa_mode: DaaMode
    target_time: int
    half_life: int
    epoch_length: int = 2016
    max_adjustment_log2: int = 2
    schedule: tuple[tuple[int, int], ...] = ()
    premine_pkh: Hex20 | None = None

    def build_reveal_outputs(self, commit_txid: str) -> DmintV1RevealScripts:
        """Build reveal-tx output scripts given the confirmed commit txid.

        Mirrors :meth:`DmintV1DeployResult.build_reveal_outputs`: emits
        ``num_contracts`` parallel 1-photon V2 contract UTXOs
        (``contractRef[i] = commit:(i+1)``, ``tokenRef = commit:0``) + the
        ``gly``/CBOR reveal scriptSig suffix + optional premine FT output +
        optional OP_RETURN. The returned :class:`DmintV1RevealScripts` bag has
        the same shape — and the same output-ordering rule — for V1 and V2.
        """
        token_ref = GlyphRef(txid=commit_txid, vout=0)
        contract_scripts = tuple(
            build_dmint_contract_script(
                DmintDeployParams(
                    contract_ref=GlyphRef(txid=commit_txid, vout=i + 1),
                    token_ref=token_ref,
                    max_height=self.max_height,
                    reward=self.reward_photons,
                    difficulty=self.difficulty,
                    algo=self.algo,
                    daa_mode=self.daa_mode,
                    target_time=self.target_time,
                    half_life=self.half_life,
                    epoch_length=self.epoch_length,
                    max_adjustment_log2=self.max_adjustment_log2,
                    schedule=self.schedule,
                )
            )
            for i in range(self.num_contracts)
        )
        scriptsig_suffix = build_reveal_scriptsig_suffix(self.cbor_bytes)

        op_return_script: bytes | None = None
        if self.op_return_msg is not None:
            msg = self.op_return_msg
            if len(msg) <= 75:
                op_return_script = bytes([0x6A, len(msg)]) + msg
            elif len(msg) <= 255:
                op_return_script = bytes([0x6A, 0x4C, len(msg)]) + msg
            else:
                raise ValidationError(f"op_return_msg too long: {len(msg)} bytes (cap at 255 for now)")

        premine_script = _build_premine_script(self.premine_amount, self.premine_pkh, self.owner_pkh, token_ref)

        return DmintV1RevealScripts(
            contract_scripts=contract_scripts,
            contract_value=1,
            cbor_bytes=self.cbor_bytes,
            scriptsig_suffix=scriptsig_suffix,
            premine_script=premine_script,
            premine_amount=self.premine_amount,
            op_return_script=op_return_script,
        )


class DmintDeployResult(DmintV2DeployResult):
    """Deprecated alias for :class:`DmintV2DeployResult`.

    Mirrors the params-side ``DmintFullDeployParams`` deprecation alias.
    Kept as a real subclass (NOT a bare type alias) so ``__init__``
    emits a ``DeprecationWarning`` at construction time. Scheduled for
    removal in pyrxd v0.6.

    Callers receiving an instance of this class today are talking to the
    V2 path; the only way to get one is to construct it directly, since
    the dispatcher always returns the concrete V1/V2 result. Tests that
    held the legacy reference type need to be migrated.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        import warnings

        warnings.warn(
            "DmintDeployResult is deprecated; use DmintV2DeployResult "
            "(or DmintV1DeployResult for V1 deploys). DmintDeployResult "
            "will be removed in pyrxd v0.6.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


# Module-level dataclasses for the transfer API. Kept at bottom so the docstring
# in build_nft_transfer_tx can forward-reference "TransferParams" / "TransferResult"
# without needing a TYPE_CHECKING import.


@dataclass
class TransferParams:
    """Parameters for an NFT transfer transaction.

    :param nft_utxo_txid:  txid of the UTXO currently holding the NFT
    :param nft_utxo_vout:  output index within that tx
    :param nft_utxo_value: satoshis (photons) locked in the NFT UTXO
    :param nft_script:     full 63-byte NFT locking script of the UTXO
    :param new_owner_pkh:  recipient's 20-byte public-key hash
    :param private_key:    pyrxd.keys.PrivateKey — current owner's signing key
    :param fee_rate:       photons per byte (Radiant post-V2 minimum is 10_000)
    :param allow_overpay:  accept a ``fee_rate`` above the overpay ceiling
                           (:data:`~pyrxd.fee_sizing.MAX_FEE_OVERPAY_MULTIPLE` x the
                           relay floor). The deliberate, greppable opt-out — the
                           ceiling is here because THIS builder has no change
                           output, so a mistaken rate leaves entirely with the
                           miner (measured: 23.2 RXD off a 229-byte transfer at
                           ``fee_rate=10_000_000``), but a ceiling with no way
                           through refuses valid work, and Radiant has neither RBF
                           nor CPFP to repair a refusal that came too late.

    .. note::
       There is no ``royalty`` here, unlike :class:`FtTransferParams`. This
       builder takes exactly **one** input — the NFT UTXO — and an NFT carrier
       holds dust, so there is no RXD budget a royalty could be paid from; the
       parameter would exist and never be satisfiable. Paying a royalty on an
       NFT needs a funded builder (the CLI's ``transfer-nft`` already sources a
       separate plain-RXD input for its fee, and builds its transaction
       directly rather than through this method). Tracked as the NFT half of the
       royalty work; the FT path in :mod:`pyrxd.glyph.ft` carries it today.
    """

    nft_utxo_txid: str
    nft_utxo_vout: int
    nft_utxo_value: int
    nft_script: bytes
    new_owner_pkh: Hex20
    private_key: Any
    fee_rate: int = MIN_FEE_RATE
    allow_overpay: bool = False
    allow_below_relay_floor: bool = False


@dataclass
class TransferResult:
    """Output of :meth:`GlyphBuilder.build_nft_transfer_tx`.

    :param tx:              signed :class:`Transaction`, ready to broadcast
    :param new_nft_script:  63-byte locking script on the transfer output
    :param ref:             the NFT's :class:`GlyphRef` (unchanged across transfers)
    :param fee:             actual fee paid, in photons
    """

    tx: Any
    new_nft_script: bytes
    ref: GlyphRef
    fee: int


# FT transfer API — parallels TransferParams/TransferResult for the NFT path.
# Importing FtUtxo/FtTransferResult here is safe at module end because
# builder.py does not import ft.py at the top level (avoids circularity —
# ft.py uses build_ft_locking_script / extract_ref_from_ft_script from
# script.py directly).

# PEP 484 explicit re-export pattern (``X as X``). Satisfies CodeQL's
# py/unused-import alert — which does not honour the F401 suppression
# pragma the way ruff does — and makes the re-export intent obvious to
# readers. One real consumer is examples/ft_transfer_demo.py, which
# imports FtUtxo from this module for back-compat with pre-0.4 layouts.
# The airdrop's per-output floor default. Aliased rather than restated so the two
# modules cannot drift; ``ft.py`` owns the value and the note that 546 is pyrxd
# wallet policy, not a Radiant rule.
from .ft import DUST_LIMIT as FT_DUST_LIMIT  # noqa: E402
from .ft import AirdropFunding as AirdropFunding  # noqa: E402
from .ft import AirdropRecipient as AirdropRecipient  # noqa: E402
from .ft import FtAirdropResult as FtAirdropResult  # noqa: E402
from .ft import FtTransferResult as FtTransferResult  # noqa: E402
from .ft import FtUtxo as FtUtxo  # noqa: E402


@dataclass
class FtTransferParams:
    """Parameters for an FT transfer transaction.

    :param ref:            the :class:`GlyphRef` identifying the token
    :param utxos:          list of :class:`FtUtxo` available to spend
    :param amount:         FT units to send to ``new_owner_pkh``
    :param new_owner_pkh:  recipient's 20-byte PKH
    :param private_key:    sender's :class:`pyrxd.keys.PrivateKey`
    :param funding:        plain-RXD :class:`~pyrxd.glyph.ft.AirdropFunding`
                           inputs that pay the fee. **Required in practice**:
                           an FT output's value is its unit count, so taking the
                           fee from the token would burn units and short the
                           recipient. A transfer with no funding raises.
    :param fee_rate:       photons/byte (Radiant post-V2 minimum is 10_000)
    :param change_pkh:     FT- and RXD-change recipient PKH. Defaults to the
                           sender's PKH when ``None``.
    :param dust_limit:     fold-to-fee threshold for the plain-RXD change
                           output. Not a floor on the token output.
    :param allow_overpay:  accept a ``fee_rate`` above the overpay ceiling
                           (:data:`~pyrxd.fee_sizing.MAX_FEE_OVERPAY_MULTIPLE` x the
                           relay floor), forwarded to
                           :meth:`~pyrxd.glyph.ft.FtUtxoSet.build_transfer_tx`.
                           This dataclass had no such field, so the ceiling was
                           unreachable through this API: ``fee_rate=100_001`` raised
                           with no way through, while the identical build via
                           ``FtUtxoSet.build_transfer_tx(..., allow_overpay=True)``
                           succeeded. A bound with no reachable override is a guard
                           that refuses valid work, and Radiant has neither RBF nor
                           CPFP to repair a late refusal.

    .. note::
       No ``royalty`` here, unlike :class:`FtAirdropParams`.
       :class:`~pyrxd.glyph.ft.FtTransferResult` has nowhere to report who was
       paid, and paying a royalty without reporting it would be worse than not
       offering the option. Use :class:`FtAirdropParams` with one recipient.
    """

    ref: GlyphRef
    utxos: list  # list[FtUtxo] — can't use generic here without Python 3.9+ runtime guards already in place; mirror existing style.
    amount: int
    new_owner_pkh: Hex20
    private_key: Any
    funding: list = dc_field(default_factory=list)  # list[AirdropFunding]
    fee_rate: int = MIN_FEE_RATE
    change_pkh: Hex20 | None = None
    dust_limit: int = FT_DUST_LIMIT
    allow_overpay: bool = False
    allow_below_relay_floor: bool = False


@dataclass
class FtAirdropParams:
    """Parameters for a multi-recipient FT airdrop.

    Mirrors :class:`FtTransferParams`, with ``amount`` + ``new_owner_pkh``
    replaced by an ordered list of :class:`~pyrxd.glyph.ft.AirdropRecipient`.

    :param ref:          the :class:`GlyphRef` identifying the token
    :param utxos:        list of :class:`FtUtxo` available to spend
    :param recipients:   ordered destinations. Output order follows this list.
    :param private_key:  sender's :class:`pyrxd.keys.PrivateKey`
    :param funding:      plain-RXD :class:`~pyrxd.glyph.ft.AirdropFunding`
                         inputs that pay the fee. The token cannot pay it —
                         an FT output's value is its unit count.
    :param fee_rate:     photons/byte. Validated against Radiant's effective
                         relay floor by the builder.
    :param change_pkh:   FT- and RXD-change PKH. Defaults to the sender's.
    :param dust_limit:   photons on each recipient output. A pyrxd wallet-policy
                         floor, not a chain rule — Radiant's dust threshold is 1.
    :param royalty:      optional. Advisory — see :mod:`pyrxd.glyph.royalty`.
    :param sale_price:   photons the seller receives; the royalty base, and the
                         cap — a royalty can never exceed it.
    :param pay_royalty:  ``None`` (default) pays iff ``royalty.enforced``;
                         ``True`` pays an advisory royalty anyway; ``False``
                         never pays.
    :param allow_overpay: accept a ``fee_rate`` above the overpay ceiling,
                         forwarded to
                         :meth:`~pyrxd.glyph.ft.FtUtxoSet.build_airdrop_tx`. Same
                         omission, and the same reason it matters, as
                         :class:`FtTransferParams` — see its note.
    """

    ref: GlyphRef
    utxos: list  # list[FtUtxo] — mirrors FtTransferParams' style.
    recipients: list  # list[AirdropRecipient]
    private_key: Any
    funding: list = dc_field(default_factory=list)  # list[AirdropFunding]
    fee_rate: int = MIN_FEE_RATE
    change_pkh: Hex20 | None = None
    dust_limit: int = FT_DUST_LIMIT
    royalty: GlyphRoyalty | None = None
    sale_price: int = 0
    pay_royalty: bool | None = None
    allow_overpay: bool = False
    allow_below_relay_floor: bool = False
