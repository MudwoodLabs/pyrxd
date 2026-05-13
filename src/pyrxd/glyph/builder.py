from __future__ import annotations

from dataclasses import dataclass
from typing import Any, overload

import cbor2

from pyrxd.security.errors import DmintError, ValidationError
from pyrxd.security.types import Hex20

from .dmint import (
    DmintDeployParams,
    build_dmint_contract_script,
)
from .payload import build_reveal_scriptsig_suffix, encode_payload
from .script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_mutable_nft_script,
    build_nft_locking_script,
    extract_ref_from_nft_script,
    hash_payload,
)
from .types import GlyphMetadata, GlyphProtocol, GlyphRef

# Minimum fee rate post-V2: 10,000 photons/byte
MIN_FEE_RATE = 10_000  # photons per byte


@dataclass
class CommitParams:
    """Parameters for the commit transaction."""

    metadata: GlyphMetadata
    owner_pkh: Hex20  # who will own the NFT/FT after reveal
    change_pkh: Hex20  # change output recipient
    funding_satoshis: int  # total input satoshis available
    dust_limit: int = 546  # minimum output value


@dataclass
class CommitResult:
    """Output of prepare_commit — the caller broadcasts and gets a txid back."""

    commit_script: bytes  # nftCommitScript for vout[0]
    cbor_bytes: bytes  # store this — needed for reveal scriptSig
    payload_hash: bytes  # 32-byte hash committed into the script
    estimated_fee: int  # in photons


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


@dataclass
class RevealScripts:
    """Scripts needed to build the reveal tx — caller constructs the full tx."""

    locking_script: bytes  # output scriptPubKey
    scriptsig_suffix: bytes  # the 'gly' + CBOR portion; caller prepends sig+pubkey


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
    """Scripts for a MUT reveal — two outputs required."""

    ref: GlyphRef
    nft_script: bytes  # 63-byte NFT singleton (vout[0] typically)
    contract_script: bytes  # 174-byte mutable contract (vout[1] typically)
    scriptsig_suffix: bytes  # 'gly' + CBOR; caller prepends sig + pubkey
    payload_hash: bytes  # sha256d of CBOR payload


@dataclass
class ContainerRevealScripts:
    """Scripts for a CONTAINER reveal."""

    ref: GlyphRef
    locking_script: bytes  # NFT body, optionally prefixed with child ref
    scriptsig_suffix: bytes
    child_ref: GlyphRef | None


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
        )
        # Rough estimate: commit tx ~276 bytes
        estimated_fee = 276 * MIN_FEE_RATE
        return CommitResult(
            commit_script=commit_script,
            cbor_bytes=cbor_bytes,
            payload_hash=payload_hash,
            estimated_fee=estimated_fee,
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

        scriptsig_suffix = build_reveal_scriptsig_suffix(params.cbor_bytes)
        return RevealScripts(
            locking_script=locking,
            scriptsig_suffix=scriptsig_suffix,
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
        carrying the full issued supply to ``premine_pkh``, and its
        outpoint becomes the permanent token ref.

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
        if premine_amount < 546:
            # Standard dust limit — under this, the reveal output is non-standard
            # and will be rejected by most mempool policies. 546 photons is the
            # conventional dust limit; callers wanting a smaller supply should
            # choose a different token model (NFT) rather than a tiny FT.
            raise ValidationError(
                f"premine_amount ({premine_amount}) is below the dust limit (546). "
                "Use a larger supply or a different token model."
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
        allow_v2_deploy: bool = False,
    ) -> DmintV1DeployResult | DmintV2DeployResult:
        """Prepare a dMint token deploy.

        Dispatches on the type of ``params``:

        * :class:`DmintV1DeployParams` → returns :class:`DmintV1DeployResult`.
          V1 is the only format on Radiant mainnet today (see GLYPH at
          a443d9df…878b). Two-tx deploy: commit + reveal (the reveal
          directly creates ``params.num_contracts`` parallel contract UTXOs).

        * :class:`DmintV2DeployParams` → returns :class:`DmintV2DeployResult`,
          but only if the caller passes ``allow_v2_deploy=True``. V2 has
          no live mainnet contracts; no ecosystem miner (glyph-miner,
          RXinDexer, Photonic explorer) targets V2. Refusing by default
          prevents deploying tokens nobody can mine.

        :param params: Either :class:`DmintV1DeployParams` (V1 deploy) or
            :class:`DmintV2DeployParams` (V2 deploy, requires
            ``allow_v2_deploy=True``). The deprecated
            :class:`DmintFullDeployParams` is accepted (it's a subclass of
            ``DmintV2DeployParams``) but emits a ``DeprecationWarning`` at
            construction time.
        :param allow_v2_deploy: Must be ``True`` to deploy V2. Ignored for V1.
        :returns: V1 or V2 result, matching the param type via ``@overload``.
        :raises DmintError: V2 path without ``allow_v2_deploy=True``.
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
          dMint contract UTXOs + FT-NFT singleton + auth NFT + change.
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

        if params.premine_amount is not None:
            raise ValidationError(
                "V1 deploy with premine is deferred work — see "
                "docs/dmint-research-photonic-deploy.md §7.2. Set "
                "premine_amount=None for now."
            )

        # 1. Encode the CBOR token body.
        cbor_bytes, payload_hash = encode_payload(params.metadata)

        # Defensive cross-check: V1 must NOT emit a 'v' field (V2 marker).
        # encode_payload draws 'v' from metadata.version; if the caller
        # forgot to leave it at the V1 default, the resulting CBOR would
        # be classified as V2 by RXinDexer.
        if b"\x61v" in cbor2.dumps({"v": 1}) and b"\x61v" in cbor_bytes:
            raise ValidationError(
                "V1 dMint CBOR must NOT include a 'v' field; got one in the "
                "encoded body. Set GlyphMetadata(version=None) or omit it."
            )
        # Belt-and-braces: also re-decode and pin the 'p' field shape.
        decoded = cbor2.loads(cbor_bytes)
        if "p" not in decoded or 1 not in decoded["p"] or 4 not in decoded["p"]:
            raise ValidationError(
                f"V1 dMint CBOR 'p' field must include both 1 (FT) and 4 (DMINT); got p={decoded.get('p')!r}"
            )

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
        )

    def _prepare_dmint_v2_deploy(
        self,
        params: DmintV2DeployParams,
        *,
        allow_v2_deploy: bool,
    ) -> DmintV2DeployResult:
        """Original V2 deploy implementation, gated on ``allow_v2_deploy``."""
        if not allow_v2_deploy:
            raise DmintError(
                "prepare_dmint_deploy with DmintV2DeployParams emits V2 dMint "
                "contracts; no ecosystem miner (glyph-miner, etc.) targets V2 "
                "and indexer behavior on V2 deploys is empirically unknown. "
                "Refusing to build a token nobody can mine. For V1 (the only "
                "live mainnet format), pass DmintV1DeployParams instead. To "
                "deploy V2 anyway (e.g. SDK-internal testing), pass "
                "allow_v2_deploy=True."
            )
        # 1. Encode the token metadata payload.
        cbor_bytes, payload_hash = encode_payload(params.metadata)

        # 2. Build commit script (FT shape — dMint tokens are FTs).
        is_nft = GlyphProtocol.NFT in params.metadata.protocol
        commit_script = build_commit_locking_script(
            payload_hash,
            params.owner_pkh,
            is_nft=is_nft,
        )
        estimated_commit_fee = 276 * MIN_FEE_RATE

        commit_result = CommitResult(
            commit_script=commit_script,
            cbor_bytes=cbor_bytes,
            payload_hash=payload_hash,
            estimated_fee=estimated_commit_fee,
        )

        # 3. Build the reveal scripts (token ref UTXO — 75-byte FT locking script).
        if params.premine_amount is not None and params.premine_amount < 546:
            raise ValidationError(f"premine_amount ({params.premine_amount}) is below the dust limit (546).")

        # 4. Build the deploy contract script.
        deploy_params_template = DmintDeployParams(
            contract_ref=params.contract_ref_placeholder,
            token_ref=params.token_ref_placeholder,
            max_height=params.max_height,
            reward=params.reward_photons,
            difficulty=params.difficulty,
            algo=params.algo,
            daa_mode=params.daa_mode,
            target_time=params.target_time,
            half_life=params.half_life,
        )

        # Pre-build with placeholder refs so the caller can inspect the script shape.
        placeholder_contract_script = build_dmint_contract_script(deploy_params_template)

        # 5. Validate reward pool.
        if params.initial_pool_photons < params.reward_photons:
            raise ValidationError(
                f"initial_pool_photons ({params.initial_pool_photons}) must be >= "
                f"reward_photons ({params.reward_photons}) for at least one mint."
            )

        return DmintV2DeployResult(
            commit_result=commit_result,
            cbor_bytes=cbor_bytes,
            owner_pkh=params.owner_pkh,
            premine_amount=params.premine_amount,
            deploy_params_template=deploy_params_template,
            placeholder_contract_script=placeholder_contract_script,
            initial_pool_photons=params.initial_pool_photons,
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
        - ``nft_script``:      63-byte NFT singleton (token the owner holds)
        - ``contract_script``: 174-byte mutable contract UTXO (holds state)

        The reveal scriptSig suffix is also returned; the caller prepends
        ``<sig> <pubkey>`` to form the full scriptSig.

        Protocol field in ``cbor_bytes`` must include ``GlyphProtocol.MUT``
        (5). Use ``GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT])``.
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
        payload_hash = hash_payload(cbor_bytes)
        nft_script = build_nft_locking_script(owner_pkh, ref)
        contract_script = build_mutable_nft_script(ref, payload_hash)
        scriptsig_suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        return MutableRevealScripts(
            ref=ref,
            nft_script=nft_script,
            contract_script=contract_script,
            scriptsig_suffix=scriptsig_suffix,
            payload_hash=payload_hash,
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
        """Prepare scripts for a CONTAINER reveal.

        A container is an NFT with an additional ``OP_PUSHINPUTREF <child_ref>``
        prefix that links it to a child token ref.  When ``child_ref`` is
        ``None`` the container is created empty (no child ref in locking script).

        Protocol field must include ``GlyphProtocol.CONTAINER`` (7).
        """
        try:
            cbor_data = cbor2.loads(cbor_bytes)
            protocol = cbor_data.get("p", [])
            if GlyphProtocol.CONTAINER not in protocol:
                raise ValidationError(
                    f"CBOR protocol field {protocol!r} must include GlyphProtocol.CONTAINER ({GlyphProtocol.CONTAINER})"
                )
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Could not parse CBOR for CONTAINER cross-check: {exc}") from exc

        ref = GlyphRef(txid=commit_txid, vout=commit_vout)
        nft_body = build_nft_locking_script(owner_pkh, ref)

        if child_ref is not None:
            # Prefix: OP_PUSHINPUTREF (0xd0) + 36-byte child ref wire bytes
            prefix = bytes([0xD0]) + child_ref.to_bytes()
            locking_script = prefix + nft_body
        else:
            locking_script = nft_body

        scriptsig_suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        return ContainerRevealScripts(
            ref=ref,
            locking_script=locking_script,
            scriptsig_suffix=scriptsig_suffix,
            child_ref=child_ref,
        )

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
        ``cbor_bytes`` by the caller via ``GlyphMetadata(name=...)``.

        Protocol requirement: ``[NFT(2), MUT(5), WAVE(11)]``.
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
            cbor_name = cbor_data.get("name") or cbor_data.get("n", "")
            if cbor_name != name:
                raise ValidationError(f"name argument {name!r} does not match CBOR name field {cbor_name!r}")
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

        :param params: TransferParams — see dataclass docstring
        :returns: TransferResult — signed tx, new locking script, ref, fee
        :raises ValidationError: nft_script is not a valid 63-byte NFT script
        :raises ValueError: nft_utxo_value - fee < 546 (dust limit)
        """
        # Local import to avoid circular import at module load (transaction/script
        # modules don't depend on glyph, but we keep builder.py import-time light).
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        # 1. Validate input script shape and extract ref.
        #    extract_ref_from_nft_script raises ValidationError if len != 63 or
        #    first byte != 0xd8.
        if not isinstance(params.nft_script, (bytes, bytearray)):
            raise ValidationError("nft_script must be bytes")
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
        trial_input = _make_input()
        trial_tx = Transaction(
            tx_inputs=[trial_input],
            tx_outputs=[TransactionOutput(Script(new_nft_script), params.nft_utxo_value)],
        )
        trial_tx.sign()
        size = trial_tx.byte_length()
        fee = size * params.fee_rate

        output_value = params.nft_utxo_value - fee
        if output_value < 546:
            raise ValueError(
                f"NFT UTXO value ({params.nft_utxo_value}) too small to cover transfer "
                f"fee ({fee} for {size} bytes at {params.fee_rate} photons/byte): "
                f"output would be {output_value}, below 546 dust limit."
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
        instance.

        :param params: :class:`FtTransferParams` — see dataclass docstring.
        :returns:      :class:`FtTransferResult` — signed tx + scripts + fee.
        :raises ValueError: same conditions as :meth:`FtUtxoSet.build_transfer_tx`
            (insufficient FT balance, insufficient RXD for fee + dust).
        """
        # Local import: FtUtxoSet depends on this module (for MIN_FEE_RATE
        # parity), but we only need it at call time.
        from .ft import FtUtxoSet

        utxo_set = FtUtxoSet(ref=params.ref, utxos=params.utxos)
        return utxo_set.build_transfer_tx(
            amount=params.amount,
            new_owner_pkh=params.new_owner_pkh,
            private_key=params.private_key,
            fee_rate=params.fee_rate,
            change_pkh=params.change_pkh,
        )


# ---------------------------------------------------------------------------
# dMint deploy API dataclasses
# ---------------------------------------------------------------------------

from .dmint import DaaMode, DmintAlgo  # noqa: E402 (after class def — no circular dep)


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
        Validated to ``[1, 250]`` at construction. The 250 ceiling is the
        standardness limit for tx size at typical V1 contract bytes
        (≈ 241 bytes/contract output + overhead → 250 contracts fits in
        a ~64 KB reveal before the embedded media body).
    :param max_height:         Maximum mints per contract (3-byte ceiling).
    :param reward_photons:     Photons paid per successful mint (3-byte
        ceiling — see V1 contract state layout).
    :param difficulty:         Initial PoW difficulty (1 = easiest).
        Translated to 8-byte target via :func:`difficulty_to_target`.
    :param premine_amount:     Photons to send to ``owner_pkh`` on the
        reveal tx as an optional premine FT output. ``None`` = no premine.
        Filed as deferred work in M2 (`docs/dmint-research-photonic-deploy.md` §7.2);
        accepted in the dataclass but rejected at build time for now.
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

    def __post_init__(self) -> None:
        if not (1 <= self.num_contracts <= 250):
            raise ValidationError(
                f"num_contracts must be in [1, 250], got {self.num_contracts} "
                f"(250 is the standardness ceiling for V1 deploy reveal size)"
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
    """Parameters for a V2 dMint token deploy (commit + reveal + deploy).

    V2 has no live mainnet deploys; only `prepare_dmint_deploy(..., allow_v2_deploy=True)`
    will accept it. The ecosystem (glyph-miner, RXinDexer) targets V1 only.

    :param metadata:                  :class:`GlyphMetadata` for the token
                                      (must include ``GlyphProtocol.FT`` and
                                      ``GlyphProtocol.DMINT`` in protocol).
    :param owner_pkh:                 20-byte PKH of the key that signs commit/reveal.
    :param max_height:                Maximum number of mints (total supply units).
    :param reward_photons:            Photons paid to the miner per mint.
    :param difficulty:                Initial PoW difficulty (1 = easiest).
    :param initial_pool_photons:      Photons to lock in the contract UTXO as the
                                      reward pool.  Must be >= ``reward_photons``.
    :param premine_amount:            Photons to send to ``owner_pkh`` on the
                                      reveal tx as an optional premine output.
                                      ``None`` = no premine output.
    :param contract_ref_placeholder:  Placeholder :class:`GlyphRef` used to
                                      pre-build the contract script.  The caller
                                      substitutes the real contract outpoint
                                      (deploy tx outpoint) before broadcast.
    :param token_ref_placeholder:     Placeholder :class:`GlyphRef` for the
                                      token ref.  Substituted with the reveal
                                      tx outpoint before broadcast.
    :param algo:                      PoW algorithm (default SHA256d).
    :param daa_mode:                  Difficulty adjustment algorithm (default FIXED).
    :param target_time:               Target seconds between mints (DAA only).
    :param half_life:                 ASERT half-life in seconds (DAA only).
    """

    metadata: GlyphMetadata
    owner_pkh: Hex20
    max_height: int
    reward_photons: int
    difficulty: int
    initial_pool_photons: int
    premine_amount: int | None = None
    contract_ref_placeholder: GlyphRef = None  # type: ignore[assignment]
    token_ref_placeholder: GlyphRef = None  # type: ignore[assignment]
    algo: DmintAlgo = DmintAlgo.SHA256D
    daa_mode: DaaMode = DaaMode.FIXED
    target_time: int = 60
    half_life: int = 3600

    def __post_init__(self) -> None:
        if self.contract_ref_placeholder is None:
            self.contract_ref_placeholder = GlyphRef(txid="00" * 32, vout=0)
        if self.token_ref_placeholder is None:
            self.token_ref_placeholder = GlyphRef(txid="00" * 32, vout=0)
        # V2 quarantine marker — see V2UnvalidatedWarning in pyrxd.glyph.dmint.
        # Subclasses suppress this (DmintFullDeployParams's deprecation warning
        # is the higher-priority signal there).
        if type(self) is DmintV2DeployParams:
            from .dmint import _warn_v2_unvalidated

            _warn_v2_unvalidated()


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
    :param premine_script:    Locking script for an optional premine
        FT output (``None`` = no premine). Deferred work in M2 — the
        builder currently raises if ``premine_amount`` is set.
    :param premine_amount:    Photons for the premine output (``None``
        if no premine).
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
    :param premine_amount:                Photons for optional premine
        output, or ``None``. Deferred work in M2 — must be ``None``.
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

    def build_reveal_outputs(self, commit_txid: str) -> DmintV1RevealScripts:
        """Build reveal-tx output scripts given the confirmed commit txid.

        The V1 reveal:
        * spends commit vouts 0 + 1..N + (N+1 NFT-commit) + (N+2 change)
        * emits N parallel dMint contract UTXOs at vouts 0..N-1
        * emits the FT NFT singleton + auth NFT singleton + change

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

        if self.premine_amount is not None:
            raise NotImplementedError(
                "V1 deploy with premine is deferred work — see "
                "docs/dmint-research-photonic-deploy.md §7.2. Set "
                "premine_amount=None for now."
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

        return DmintV1RevealScripts(
            contract_scripts=contract_scripts,
            contract_value=1,
            cbor_bytes=self.cbor_bytes,
            scriptsig_suffix=scriptsig_suffix,
            premine_script=None,
            premine_amount=None,
            op_return_script=op_return_script,
        )


@dataclass
class DmintV2DeployResult:
    """Output of :meth:`GlyphBuilder.prepare_dmint_deploy` for V2 deploys.

    :param commit_result:               :class:`CommitResult` — scripts + fee for the
                                        commit tx (same as :meth:`prepare_commit` output).
    :param cbor_bytes:                  Encoded CBOR payload (needed for reveal scriptSig).
    :param owner_pkh:                   20-byte PKH of the deploy key.
    :param premine_amount:              Photons for the premine output, or ``None``.
    :param deploy_params_template:      :class:`DmintDeployParams` with placeholder refs —
                                        substitute real refs then call
                                        :func:`build_dmint_contract_script` to get the
                                        final contract output script.
    :param placeholder_contract_script: Pre-built contract script with placeholder refs —
                                        shows the correct byte length for fee estimation.
    :param initial_pool_photons:        Photons to lock in the deploy output (reward pool).
    """

    commit_result: CommitResult
    cbor_bytes: bytes
    owner_pkh: Hex20
    premine_amount: int | None
    deploy_params_template: DmintDeployParams
    placeholder_contract_script: bytes
    initial_pool_photons: int

    def build_reveal_scripts(
        self,
        commit_txid: str,
        commit_vout: int,
        commit_value: int,
    ) -> FtDeployRevealScripts | RevealScripts:
        """Build reveal scripts given the confirmed commit outpoint.

        :param commit_txid:   txid of the confirmed commit tx.
        :param commit_vout:   Output index of the commit UTXO.
        :param commit_value:  Photon value of the commit output.
        :returns: :class:`FtDeployRevealScripts` if ``premine_amount`` is set,
                  otherwise :class:`RevealScripts`.
        """
        builder = GlyphBuilder()
        if self.premine_amount is not None:
            return builder.prepare_ft_deploy_reveal(
                commit_txid=commit_txid,
                commit_vout=commit_vout,
                commit_value=commit_value,
                cbor_bytes=self.cbor_bytes,
                premine_pkh=self.owner_pkh,
                premine_amount=self.premine_amount,
            )
        return builder.prepare_reveal(
            RevealParams(
                commit_txid=commit_txid,
                commit_vout=commit_vout,
                commit_value=commit_value,
                cbor_bytes=self.cbor_bytes,
                owner_pkh=self.owner_pkh,
                is_nft=False,
            )
        )

    def build_contract_script(
        self,
        token_ref: GlyphRef,
        contract_ref: GlyphRef,
    ) -> bytes:
        """Build the final contract output script with real outpoint refs.

        :param token_ref:    :class:`GlyphRef` of the reveal tx outpoint
                             (becomes the token ref in the contract state).
        :param contract_ref: :class:`GlyphRef` of the deploy tx outpoint
                             (becomes the contract ref in the contract state).
        :returns: Full dMint contract output script bytes.
        """
        real_params = DmintDeployParams(
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=self.deploy_params_template.max_height,
            reward=self.deploy_params_template.reward,
            difficulty=self.deploy_params_template.difficulty,
            algo=self.deploy_params_template.algo,
            daa_mode=self.deploy_params_template.daa_mode,
            target_time=self.deploy_params_template.target_time,
            half_life=self.deploy_params_template.half_life,
        )
        return build_dmint_contract_script(real_params)


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
    """

    nft_utxo_txid: str
    nft_utxo_vout: int
    nft_utxo_value: int
    nft_script: bytes
    new_owner_pkh: Hex20
    private_key: Any
    fee_rate: int = MIN_FEE_RATE


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
    :param fee_rate:       photons/byte (Radiant post-V2 minimum is 10_000)
    :param change_pkh:     FT-change recipient PKH. Defaults to the sender's
                           PKH when ``None``.
    """

    ref: GlyphRef
    utxos: list  # list[FtUtxo] — can't use generic here without Python 3.9+ runtime guards already in place; mirror existing style.
    amount: int
    new_owner_pkh: Hex20
    private_key: Any
    fee_rate: int = MIN_FEE_RATE
    change_pkh: Hex20 | None = None
