"""ElectrumX endpoint registry: per-network defaults and chain fingerprints.

The load-bearing property here is NEGATIVE: no network's default endpoint may
ever be another network's. That is the bug this registry exists to make
unrepresentable — before it, ``--network regtest`` inherited the mainnet server.
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.network.registry import (
    DEFAULT_ENDPOINTS,
    GENESIS_BLOCK_HASHES,
    KNOWN_NETWORKS,
    Endpoint,
    NetworkProfile,
    block_hash_hex,
    default_endpoints,
    genesis_hash_for,
)
from pyrxd.security.errors import ValidationError

# The real Radiant mainnet genesis header, 80 bytes, as returned by
# `radiant-cli getblockheader <genesis> false` on the reference mainnet node
# (Radiant Core 3.1.2) and by `blockchain.block.header [0]` from both shipped
# mainnet ElectrumX servers. This is a live-captured vector, not a construction.
_MAINNET_GENESIS_HEADER_HEX = (
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "372cbaf89794aeed5e711b02e78ec4502ad8b315a987c2e2758a85e36a3f7c02"
    "aadeaf62"
    "ffff001d"
    "7980b72a"
)


class TestGenesisConstants:
    def test_every_known_network_has_a_genesis_hash(self) -> None:
        for network in KNOWN_NETWORKS:
            assert genesis_hash_for(network), f"{network} has no genesis constant"

    def test_genesis_hashes_are_distinct(self) -> None:
        # Three networks sharing a fingerprint would make the chain check vacuous.
        values = list(GENESIS_BLOCK_HASHES.values())
        assert len(set(values)) == len(values)

    def test_genesis_hashes_are_64_hex_chars(self) -> None:
        for network, value in GENESIS_BLOCK_HASHES.items():
            assert len(value) == 64, network
            bytes.fromhex(value)

    def test_unknown_network_has_no_genesis(self) -> None:
        assert genesis_hash_for("marsnet") is None


class TestBlockHashHex:
    def test_mainnet_genesis_header_hashes_to_the_registry_constant(self) -> None:
        """The end-to-end vector: real header bytes -> the mainnet genesis hash.

        If this passes, ``assert_chain`` is checking the right thing with the right
        algorithm; if the hash function were wrong, no live server would ever match.
        """
        header = bytes.fromhex(_MAINNET_GENESIS_HEADER_HEX)
        assert block_hash_hex(header) == GENESIS_BLOCK_HASHES["mainnet"]

    def test_is_double_sha512_256_not_bitcoins_sha256d(self) -> None:
        """Radiant replaced the header hash; a "cleanup" to SHA-256d must fail loudly."""
        header = bytes.fromhex(_MAINNET_GENESIS_HEADER_HEX)
        sha256d = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        assert block_hash_hex(header) != sha256d

    def test_rejects_wrong_length_header(self) -> None:
        with pytest.raises(ValidationError, match="80 bytes"):
            block_hash_hex(b"\x00" * 79)

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValidationError, match="must be bytes"):
            block_hash_hex("00" * 80)  # type: ignore[arg-type]


class TestDefaultEndpoints:
    def test_mainnet_ships_the_historical_primary_first(self) -> None:
        """`--network mainnet` must keep working exactly as it did: same first server."""
        assert default_endpoints("mainnet")[0] == "wss://electrumx.radiant4people.com:50022/"

    def test_mainnet_ships_more_than_one_server(self) -> None:
        # Failover needs somewhere to fail over TO.
        assert len(default_endpoints("mainnet")) >= 2

    def test_no_endpoint_is_shared_between_networks(self) -> None:
        """THE registry invariant: one network's server is never another's default."""
        seen: dict[str, str] = {}
        for network, urls in DEFAULT_ENDPOINTS.items():
            for url in urls:
                assert url not in seen, f"{url} is a default for both {seen.get(url)} and {network}"
                seen[url] = network

    def test_testnet_and_regtest_ship_nothing(self) -> None:
        """Honest emptiness. A guessed endpoint here is worse than none — it would be
        the same class of bug (a wrong-chain server reached by default)."""
        assert default_endpoints("testnet") == ()
        assert default_endpoints("regtest") == ()

    def test_unknown_network_gets_nothing_rather_than_a_fallback(self) -> None:
        assert default_endpoints("marsnet") == ()


class TestEndpointValidation:
    def test_plain_ws_requires_allow_insecure(self) -> None:
        with pytest.raises(ValidationError, match="insecure"):
            Endpoint(url="ws://127.0.0.1:50022/")

    def test_plain_ws_allowed_when_opted_in(self) -> None:
        assert Endpoint(url="ws://127.0.0.1:50022/", allow_insecure=True).url == "ws://127.0.0.1:50022/"

    def test_non_websocket_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError, match="wss://"):
            Endpoint(url="https://example.com/")

    def test_empty_url_rejected(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            Endpoint(url="   ")

    def test_pins_on_plaintext_endpoint_rejected(self) -> None:
        # Pinning a plaintext socket would look like a security control and be none.
        pin = "sha256/" + "A" * 43 + "="
        with pytest.raises(ValidationError, match="meaningless"):
            Endpoint(url="ws://127.0.0.1:50022/", allow_insecure=True, spki_pins=(pin,))

    def test_malformed_pin_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            Endpoint(url="wss://example.com/", spki_pins=("not-a-pin",))

    def test_key_normalises_case_and_trailing_slash(self) -> None:
        assert Endpoint(url="wss://Example.com/").key == Endpoint(url="wss://example.com").key


class TestNetworkProfile:
    def test_requires_at_least_one_endpoint(self) -> None:
        with pytest.raises(ValidationError, match="no ElectrumX endpoint"):
            NetworkProfile(network="regtest", endpoints=())

    def test_deduplicates_endpoints(self) -> None:
        """Two spellings of one server must not masquerade as two independent ones."""
        profile = NetworkProfile.build("mainnet", ["wss://a.example/", "wss://A.example", "wss://b.example/"])
        assert profile.urls == ("wss://a.example/", "wss://b.example/")

    def test_build_defaults_genesis_from_the_registry(self) -> None:
        profile = NetworkProfile.build("regtest", ["ws://127.0.0.1:50022/"], allow_insecure=True)
        assert profile.genesis_hash == GENESIS_BLOCK_HASHES["regtest"]

    def test_build_leaves_genesis_none_for_an_unknown_network(self) -> None:
        assert NetworkProfile.build("marsnet", ["wss://a.example/"]).genesis_hash is None

    def test_explicit_genesis_override_wins(self) -> None:
        custom = "ab" * 32
        profile = NetworkProfile.build("mainnet", ["wss://a.example/"], genesis_hash=custom)
        assert profile.genesis_hash == custom

    def test_rejects_malformed_genesis(self) -> None:
        with pytest.raises(ValidationError, match="64-character"):
            NetworkProfile(network="mainnet", endpoints=(Endpoint(url="wss://a.example/"),), genesis_hash="beef")

    def test_rejects_non_hex_genesis(self) -> None:
        with pytest.raises(ValidationError, match="valid hex"):
            NetworkProfile(network="mainnet", endpoints=(Endpoint(url="wss://a.example/"),), genesis_hash="z" * 64)

    def test_rejects_non_endpoint_members(self) -> None:
        with pytest.raises(ValidationError, match="must be Endpoint"):
            NetworkProfile(network="mainnet", endpoints=("wss://a.example/",))  # type: ignore[arg-type]

    def test_rejects_empty_network_name(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            NetworkProfile(network=" ", endpoints=(Endpoint(url="wss://a.example/"),))
