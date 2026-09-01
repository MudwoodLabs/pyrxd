"""Guards the top-level ``pyrxd`` SDK surface for the cross-chain swap primitive.

The Tier-2 packaging goal (docs/ROADMAP.md): the proven HTLC cross-chain swap is
embeddable from a clean top-level import. These tests pin that the names resolve via
the PEP 562 lazy ``__getattr__`` and that the headline import doesn't eagerly pull the
optional ``web3`` dependency (the same import-graph discipline the package docstring
documents for the browser inspect tool).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

_CROSS_CHAIN_EXPORTS = [
    "SwapCoordinator",
    "CoordinatorConfig",
    "MarginPolicy",
    "generate_secret",
    "NegotiatedTerms",
    "SwapRecord",
    "SwapState",
    "CounterChainLeg",
    "RadiantCovenantLeg",
    "EthLeg",
    # Counter-chain registries (Tier 2.3)
    "EvmChain",
    "KNOWN_EVM_CHAINS",
    "PowChain",
    "KNOWN_POW_CHAINS",
    # Covenant building blocks (Tier 2.4)
    "HtlcCovenant",
    "build_htlc_covenant_rxd",
    "build_htlc_covenant_ft",
    "build_htlc_covenant_nft",
    "SoulboundNftCovenant",
    "build_soulbound_nft_covenant",
    "verify_ref_authenticity",
]


@pytest.mark.parametrize("name", _CROSS_CHAIN_EXPORTS)
def test_cross_chain_primitive_is_importable_from_top_level(name):
    import pyrxd

    assert name in pyrxd.__all__, f"{name} missing from pyrxd.__all__"
    assert getattr(pyrxd, name) is not None


def test_importing_pyrxd_does_not_eagerly_load_web3():
    # `import pyrxd` must stay light: web3 is an optional dep and only the ETH leg needs
    # it. Lazy exports must not drag it in at package-import time. Checked in a clean
    # subprocess so we never mutate this interpreter's sys.modules (popping web3 here
    # would contaminate other suites that mock it).
    code = "import sys; import pyrxd; sys.exit(1 if 'web3' in sys.modules else 0)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"importing pyrxd eagerly loaded web3 (should be lazy)\n{result.stderr}"


# --------------------------------------------------------------- content encryption (#556) --

_CRYPTO_EXPORTS = [
    "ChunkedCiphertext",
    "EncryptedChunk",
    "WrappedCEK",
    "decrypt_chunked",
    "encrypt_chunked",
    "unwrap_cek_x25519",
    "wrap_cek_x25519",
    "x25519_public_key",
]


@pytest.mark.parametrize("name", _CRYPTO_EXPORTS)
def test_crypto_primitive_is_importable_from_top_level(name):
    import pyrxd

    assert name in pyrxd.__all__, f"{name} missing from pyrxd.__all__"
    assert getattr(pyrxd, name) is not None


def test_the_exported_crypto_surface_is_USABLE_end_to_end_from_the_top_level():
    """The reachability point of #556, and the reason this is not just a `hasattr` sweep.

    The four flagged symbols were unreachable: no CLI, no client method, no export — reached only
    by tests importing `pyrxd.crypto.*` directly. Exporting them is the fix, and an export is only
    a fix if the exported set is SUFFICIENT to do the job. So this drives a full round trip using
    NOTHING but names off the top-level package: wrap a CEK to a recipient, encrypt with it, then
    unwrap and decrypt back.

    A caller cannot produce a recipient public key without `x25519_public_key`, which is why it is
    exported alongside the wrap/unwrap pair. Drop it and this test fails at the second line while
    the per-name checks above all still pass — which is exactly the difference between a symbol
    being importable and a feature being reachable.
    """
    import os

    import pyrxd

    recipient_priv = os.urandom(32)
    recipient_pub = pyrxd.x25519_public_key(recipient_priv)

    cek = os.urandom(32)
    wrapped = pyrxd.wrap_cek_x25519(cek, recipient_pub)
    assert isinstance(wrapped, pyrxd.WrappedCEK)

    plaintext = os.urandom(100_000)  # > CHUNK_SIZE, so the chunked path really chunks
    sealed = pyrxd.encrypt_chunked(plaintext, cek)
    assert isinstance(sealed, pyrxd.ChunkedCiphertext)
    assert len(sealed.chunks) > 1, "fixture too small to exercise the chunked path it is named for"
    assert all(isinstance(c, pyrxd.EncryptedChunk) for c in sealed.chunks)

    recovered_cek = pyrxd.unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, recipient_priv)
    assert recovered_cek == cek

    # `plaintext_hash` is passed SEPARATELY even though `sealed` carries one, and that is the
    # design rather than an awkward signature: the hash is the on-chain commitment, so taking it
    # from the ciphertext object would let whoever supplied the ciphertext also supply the value it
    # is authenticated against. Passing `sealed.plaintext_hash` here is only safe because this test
    # produced both; a real caller reads it from the Glyph metadata.
    assert pyrxd.decrypt_chunked(sealed, recovered_cek, sealed.plaintext_hash) == plaintext

    # ...and a WRONG commitment must fail rather than decrypt, which is what makes the separate
    # argument load-bearing instead of ceremonial.
    with pytest.raises(ValueError):
        pyrxd.decrypt_chunked(sealed, recovered_cek, b"\x00" * 32)


def test_importing_pyrxd_does_not_eagerly_load_the_cipher_backend():
    """The crypto exports must stay lazy like everything else. `Cryptodome` is a real import cost
    and only content encryption needs it; a non-lazy export would put it in every `import pyrxd`."""
    code = "import sys; import pyrxd; sys.exit(1 if 'Cryptodome.Cipher.ChaCha20_Poly1305' in sys.modules else 0)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"importing pyrxd eagerly loaded the cipher backend\n{result.stderr}"
