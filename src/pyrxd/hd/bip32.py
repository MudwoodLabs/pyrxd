import hmac
from hashlib import sha512
from typing import Union, List

from .bip39 import seed_from_mnemonic
from ..base58 import base58check_decode, base58check_encode
from ..constants import BIP32_SEED_BYTE_LENGTH
from ..constants import NETWORK_XPUB_PREFIX_DICT, NETWORK_XPRV_PREFIX_DICT
from ..constants import Network, XKEY_BYTE_LENGTH, XKEY_PREFIX_LIST, PUBLIC_KEY_COMPRESSED_PREFIX_LIST
from ..constants import XPUB_PREFIX_NETWORK_DICT, XPRV_PREFIX_NETWORK_DICT, BIP32_DERIVATION_PATH
from ..security.errors import ValidationError
from ..curve import curve, curve_add, curve_multiply
from ..keys import PublicKey, PrivateKey


class Xkey:
    """
    [  : 4] prefix
    [ 4: 5] depth
    [ 5: 9] parent public key fingerprint
    [ 9:13] child index
    [13:45] chain code
    [45:78] key (private/public)
    """

    def __init__(self, xkey: Union[str, bytes]):
        if isinstance(xkey, str):
            self.payload: bytes = base58check_decode(xkey)
        elif isinstance(xkey, bytes):
            self.payload: bytes = xkey
        else:
            raise TypeError("unsupported extended key type")

        if len(self.payload) != XKEY_BYTE_LENGTH:
            raise ValidationError("invalid extended key length")
        self.prefix: bytes = self.payload[:4]
        self.depth: int = self.payload[4]
        self.fingerprint: bytes = self.payload[5:9]
        self.index: int = int.from_bytes(self.payload[9:13], "big")
        # SECURITY: chain code is sensitive — treat as key material
        self.chain_code: bytes = self.payload[13:45]
        self.key_bytes: bytes = self.payload[45:]
        if self.prefix not in XKEY_PREFIX_LIST:
            raise ValidationError("invalid extended key prefix")

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Xkey):
            return self.payload == o.payload
        return super().__eq__(o)  # pragma: no cover

    def __hash__(self) -> int:
        raise TypeError(f"{type(self).__name__} is not hashable")

    def __str__(self) -> str:
        return base58check_encode(self.payload)

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()


class Xpub(Xkey):
    def __init__(self, xpub: Union[str, bytes]):
        super().__init__(xpub)
        self.network: Network = XPUB_PREFIX_NETWORK_DICT.get(self.prefix)
        if not self.network:
            raise ValidationError("unknown xpub prefix")
        if self.payload[45:46] not in PUBLIC_KEY_COMPRESSED_PREFIX_LIST:
            raise ValidationError("invalid public key in xpub")
        self.key: PublicKey = PublicKey(self.key_bytes)

    def ckd(self, index: Union[int, str, bytes]) -> "Xpub":
        if isinstance(index, int):
            index = index.to_bytes(4, "big")
        elif isinstance(index, str):
            index = bytes.fromhex(index)
        if len(index) != 4:
            raise ValidationError("index should be a 4 bytes integer")
        if index[0] >= 0x80:
            raise ValidationError(
                "can't make hardened derivation from xpub. "
                "If you use hardened key, please set xpub with path from xpriv first. Example:\n"
                "  master_xprv = master_xprv_from_seed(seed)\n"
                "  account_xprv = ckd(master_xprv, \"m/44'/0'/0'\")\n"
                "  account_xpub = account_xprv.xpub()"
            )

        payload: bytes = self.prefix
        payload += (self.depth + 1).to_bytes(1, "big")
        payload += self.key.hash160()[:4]
        payload += index

        h: bytes = hmac.new(self.chain_code, self.key.serialize() + index, sha512).digest()
        offset: int = int.from_bytes(h[:32], "big")
        child: PublicKey = PublicKey(curve_add(self.key.point(), curve_multiply(offset, curve.g)))

        payload += h[32:]
        payload += child.serialize()

        return Xpub(payload)

    def public_key(self) -> PublicKey:
        return self.key

    def address(self) -> str:
        return self.key.address(network=self.network)

    @classmethod
    def from_xprv(cls, xprv: Union[str, bytes, "Xprv"]) -> "Xpub":
        if not isinstance(xprv, Xprv):
            xprv = Xprv(xprv)
        payload: bytes = NETWORK_XPUB_PREFIX_DICT.get(xprv.network)
        payload += xprv.depth.to_bytes(1, "big")
        payload += xprv.fingerprint
        payload += xprv.index.to_bytes(4, "big")
        payload += xprv.chain_code
        payload += xprv.key.public_key().serialize()
        return Xpub(payload)


class Xprv(Xkey):
    def __init__(self, xprv: Union[str, bytes]):
        super().__init__(xprv)
        self.network: Network = XPRV_PREFIX_NETWORK_DICT.get(self.prefix)
        if not self.network:
            raise ValidationError("unknown xprv prefix")
        if self.payload[45] != 0:
            raise ValidationError("invalid private key in xprv")
        self.key: PrivateKey = PrivateKey(self.key_bytes[1:], network=self.network)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Xprv):
            import hmac as _hmac
            return _hmac.compare_digest(self.payload, o.payload)
        return NotImplemented

    def __str__(self) -> str:
        return "<Xprv:redacted>"

    def __repr__(self) -> str:
        return "<Xprv:redacted>"

    def serialize(self) -> str:
        """Return the base58check-encoded xprv string. Named explicitly to make audit grep easy."""
        return base58check_encode(self.payload)

    def ckd(self, index: Union[int, str, bytes]) -> "Xprv":
        if isinstance(index, int):
            index = index.to_bytes(4, "big")
        elif isinstance(index, str):
            index = bytes.fromhex(index)
        if len(index) != 4:
            raise ValidationError("index should be a 4 bytes integer")

        payload: bytes = self.prefix
        payload += (self.depth + 1).to_bytes(1, "big")
        payload += self.key.public_key().hash160()[:4]
        payload += index

        message: bytes = (self.key.public_key().serialize() if index[0] < 0x80 else self.key_bytes) + index
        h: bytes = hmac.new(self.chain_code, message, sha512).digest()
        offset: int = int.from_bytes(h[:32], "big")
        child: PrivateKey = PrivateKey((self.key.int() + offset) % curve.n)

        payload += h[32:]
        payload += b"\x00" + child.serialize()

        return Xprv(payload)

    def xpub(self) -> Xpub:
        return Xpub.from_xprv(self)

    def private_key(self) -> PrivateKey:
        return self.key

    def public_key(self) -> PublicKey:
        return self.key.public_key()

    def address(self) -> str:
        return self.key.address()

    @classmethod
    def from_seed(cls, seed: Union[str, bytes], network: Network = Network.MAINNET):
        """
        derive master extended private key from seed
        """
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        if len(seed) != BIP32_SEED_BYTE_LENGTH:
            raise ValidationError("invalid seed byte length")

        payload: bytes = NETWORK_XPRV_PREFIX_DICT.get(network)
        payload += b"\x00"
        payload += b"\x00\x00\x00\x00"
        payload += b"\x00\x00\x00\x00"

        h: bytes = hmac.new(b"Bitcoin seed", seed, sha512).digest()
        payload += h[32:]
        payload += b"\x00" + h[:32]

        return Xprv(payload)


def step_to_index(step: Union[str, int]) -> int:
    """
    convert step (sub path) normal derivation or hardened derivation into child index
    """
    if type(step).__name__ not in ["str", "int"]:
        raise TypeError("unsupported step type")
    if isinstance(step, str):
        if not len(step):
            raise ValidationError("invalid step")
        hardened: bool = step[-1] == "'"
        index: int = (0x80000000 if hardened else 0) + int(step[:-1] if hardened else step)
    else:
        index = step
    if not (0 <= index < 0xFFFFFFFF):
        raise ValidationError("step out of range")
    return index


def ckd(xkey: Union[Xprv, Xpub], path: str) -> Union[Xprv, Xpub]:
    """
    ckd = "Child Key Derivation"
    derive an extended key according to path like "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative)
    """
    steps = path.strip(" ").strip("/").split("/")
    if not (steps and steps[0] in ["m", "."]):
        raise ValidationError("path must start with 'm' or '.'")

    if steps[0] == "m":
        # should be master key
        if not (xkey.depth == 0 and xkey.fingerprint == b"\x00\x00\x00\x00" and xkey.index == 0):
            raise ValidationError("absolute path for non-master key")

    child = xkey
    for step in steps[1:]:
        child = child.ckd(step_to_index(step))
    return child


def master_xprv_from_seed(seed: Union[str, bytes], network: Network = Network.MAINNET) -> Xprv:
    return Xprv.from_seed(seed, network)


def _derive_xkeys_from_xkey(
    xkey: Union[Xprv, Xpub], index_start: Union[str, int], index_end: Union[str, int], change: Union[str, int] = 0
) -> List[Union[Xprv, Xpub]]:
    """
    this function is internal use only within bip32 module
    Use bip32_derive_xkeys_from_xkey instead.
    """
    change_xkey = xkey.ckd(step_to_index(change))
    return [change_xkey.ckd(i) for i in range(step_to_index(index_start), step_to_index(index_end))]


def bip32_derive_xprv_from_mnemonic(  # nosec B107 -- passphrase="" is BIP39 spec default
    mnemonic: str,
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP32_DERIVATION_PATH,
    network: Network = Network.MAINNET,
) -> Xprv:
    """
    Derive the subtree root extended private key from mnemonic and path.
    """
    seed = seed_from_mnemonic(mnemonic, lang, passphrase, prefix)
    master_xprv = Xprv.from_seed(seed, network)
    return ckd(master_xprv, path)


def bip32_derive_xprvs_from_mnemonic(  # nosec B107 -- passphrase="" is BIP39 spec default
    mnemonic: str,
    index_start: Union[str, int],
    index_end: Union[str, int],
    lang: str = "en",
    passphrase: str = "",
    prefix: str = "mnemonic",
    path: str = BIP32_DERIVATION_PATH,
    change: Union[str, int] = 0,
    network: Network = Network.MAINNET,
) -> List[Xprv]:
    """
    Derive a range of extended keys from a nmemonic using BIP32 format
    """
    xprv = bip32_derive_xprv_from_mnemonic(mnemonic, lang, passphrase, prefix, path, network)
    return _derive_xkeys_from_xkey(xprv, index_start, index_end, change)


def bip32_derive_xkeys_from_xkey(
    xkey: Union[Xprv, Xpub],
    index_start: Union[str, int],
    index_end: Union[str, int],
    path: str = BIP32_DERIVATION_PATH,
    change: Union[str, int] = 0,
) -> List[Union[Xprv, Xpub]]:
    """
    Derive a range of extended keys from Xprv and Xpub keys using BIP32 path structure.

    Args:
        xkey: Parent extended key (Xprv or Xpub)
        index_start: Starting index for derivation
        index_end: Ending index for derivation (exclusive)
        path: Base derivation path (default: BIP32_DERIVATION_PATH)
        change: Change level (0 for receiving addresses, 1 for change addresses)

    Returns:
        List[Union[Xprv, Xpub]]: List of derived extended keys
    """
    # Convert index arguments to integers
    start_idx = step_to_index(index_start) if isinstance(index_start, str) else index_start
    end_idx = step_to_index(index_end) if isinstance(index_end, str) else index_end

    # Validate indices
    if start_idx < 0 or end_idx < 0 or start_idx >= end_idx:
        raise ValueError("Invalid index range: start must be non-negative and less than end")

    # Parse the base path and reconstruct with change value
    base_path = path.rstrip("/")  # Remove trailing slashes if any
    if base_path.startswith("m/"):
        # For absolute paths
        derived_path = f"{base_path}/{change}"
    else:
        # For relative paths
        derived_path = f"./{change}"

    # First derive to the change level
    change_level = ckd(xkey, derived_path)

    # Then derive the range of addresses
    derived_keys = []
    for i in range(start_idx, end_idx):
        child_key = change_level.ckd(i)
        derived_keys.append(child_key)

    return derived_keys
