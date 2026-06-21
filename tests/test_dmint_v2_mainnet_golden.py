"""Mainnet golden-vector test for the V2 dMint contract builder — closes residual ``DMINT-V2-GOLDEN``.

Pins ``build_dmint_contract_script`` (V2) to the EXACT bytes of the first mainnet V2 **FIXED** dMint
deploy (#219), byte-equal against the real chain rather than a synthetic round-trip. Per
``docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md``, builder golden vectors MUST come from
real mainnet bytes — round-trip tests only prove self-consistency, not chain-compatibility.

**LWMA is deliberately not pinned.** The mainnet LWMA deploy (``dea3beb9…``) was made BEFORE the upstream
int64-overflow fix that added the ``OP_0 OP_MAX`` (``00 a4``) timeDelta floor to the LWMA bytecode
([Photonic-Wallet#2]). The current post-fix builder therefore emits exactly 2 bytes MORE than that
on-chain contract — *correctly*: the mainnet LWMA contract is on superseded pre-fix bytecode. The
post-fix LWMA path is covered by the regenerated synthetic vectors + ``test_dmint_v2_regtest_e2e.py``.
Only the FIXED deploy (bytecode unaffected by the fix) is a valid mainnet anchor for the current builder.
"""

from __future__ import annotations

from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintDeployParams, build_dmint_contract_script
from pyrxd.glyph.types import GlyphRef


class TestV2GoldenVectorMainnetFixed:
    """Byte-equal golden vector against the first mainnet V2 FIXED dMint deploy (#219)."""

    # First mainnet V2 FIXED dMint deploy reveal (#219); its change went to the run wallet (later swept).
    _DEPLOY_REVEAL_TXID = "95335028ee31e655c7fada44c6571c3e31552dc15573a250d6f06b64bb16fb09"
    # The carved genesis fanout tx; contract_ref = genesis:1, token_ref = genesis:0 (harness order).
    _GENESIS_TXID = "1e99e7b05d5676104fddbdc31b21a265ab3548a906e290ef4aeb1e9dd8890822"
    # Deploy params used on chain (scripts/dmint_v2_mainnet_run.py, DMINT_RUN_MODE=fixed):
    _MAX_HEIGHT = 10
    _REWARD = 1000  # photons per mint
    _TARGET_TIME = 60

    # Vout 0 of the on-chain deploy reveal — the 380-byte V2 contract (1-photon singleton).
    _CONTRACT_VOUT0_HEX = (
        "00d8220889d89d1eeb4aef90e206a94835ab65a2211bc3bddd4f1076565db0e7991e01000000"
        "d0220889d89d1eeb4aef90e206a94835ab65a2211bc3bddd4f1076565db0e7991e00000000"
        "5a02e8030000013c040000000008ffffffffffffff7f"
        "bdc0c859797ea85d795d797ea87e5e7a7eaabc01147f77587f040000000088817600a26951797ca2696b"
        "75757575577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a81"
        "8b76537a9c537ade789181547ae6939d636c755279cd01d853797e016a7e886778de519d7676009c637501"
        "00677660a163015093518067827c7e68684c52"
        "d8220889d89d1eeb4aef90e206a94835ab65a2211bc3bddd4f1076565db0e7991e01000000"
        "d0220889d89d1eeb4aef90e206a94835ab65a2211bc3bddd4f1076565db0e7991e00000000"
        "5a02e8030000013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c7e6868"
        "7e5379ec78885379eac0e9885379cc519d75686d7551"
    )

    def test_v2_fixed_contract_byte_equals_mainnet_deploy_vout_0(self):
        """The library's V2 FIXED contract script for the on-chain params must byte-equal the real
        mainnet deploy reveal at vout 0 — the chain-compatibility anchor for the V2 builder."""
        params = DmintDeployParams(
            contract_ref=GlyphRef(txid=self._GENESIS_TXID, vout=1),
            token_ref=GlyphRef(txid=self._GENESIS_TXID, vout=0),
            max_height=self._MAX_HEIGHT,
            reward=self._REWARD,
            difficulty=1,
            algo=DmintAlgo.SHA256D,
            daa_mode=DaaMode.FIXED,
            target_time=self._TARGET_TIME,
            height=0,
            last_time=0,
        )
        built = build_dmint_contract_script(params)
        assert built.hex() == self._CONTRACT_VOUT0_HEX, (
            "V2 FIXED contract script must byte-equal the mainnet deploy reveal "
            f"{self._DEPLOY_REVEAL_TXID} vout 0 (DMINT-V2-GOLDEN)"
        )
