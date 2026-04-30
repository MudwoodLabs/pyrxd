from __future__ import annotations

import os
from contextlib import suppress
from hashlib import pbkdf2_hmac
from secrets import randbits

from ..constants import BIP39_ENTROPY_BIT_LENGTH, BIP39_ENTROPY_BIT_LENGTH_LIST
from ..hash import sha256
from ..security.errors import ValidationError
from ..utils import bits_to_bytes, bytes_to_bits


class WordList:
    """
    BIP39 word list
    """

    LIST_WORDS_COUNT: int = 2048

    path = os.path.join(os.path.dirname(__file__), "wordlist")
    #
    # en
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    # zh-cn
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt
    #
    files: dict[str, str] = {
        "en": os.path.join(path, "english.txt"),
        "zh-cn": os.path.join(path, "chinese_simplified.txt"),
    }
    wordlist: dict[str, list[str]] = {}

    @classmethod
    def load(cls) -> None:
        for lang in WordList.files:
            if not WordList.wordlist.get(lang):
                WordList.wordlist[lang] = WordList.load_wordlist(lang)

    @classmethod
    def load_wordlist(cls, lang: str = "en") -> list[str]:
        if lang not in WordList.files:
            raise ValidationError(f"{lang} wordlist not supported")
        with open(WordList.files[lang], encoding="utf-8") as f:
            words: list[str] = f.read().splitlines()
        if len(words) != WordList.LIST_WORDS_COUNT:
            raise ValidationError("broken wordlist file")
        return words

    @classmethod
    def get_word(cls, index: int | bytes, lang: str = "en") -> str:
        WordList.load()
        if lang not in WordList.wordlist:
            raise ValidationError(f"{lang} wordlist not supported")
        if isinstance(index, bytes):
            index = int.from_bytes(index, "big")
        if not (0 <= index < WordList.LIST_WORDS_COUNT):
            raise ValidationError("index out of range")
        return WordList.wordlist[lang][index]

    @classmethod
    def index_word(cls, word: str, lang: str = "en") -> int:
        WordList.load()
        if lang not in WordList.wordlist:
            raise ValidationError(f"{lang} wordlist not supported")
        with suppress(Exception):
            return WordList.wordlist[lang].index(word)
        raise ValueError("invalid word")


def mnemonic_from_entropy(entropy: bytes | str | None = None, lang: str = "en") -> str:
    # SECURITY: mnemonic is sensitive — caller must not log or store the result unprotected
    if entropy:
        if type(entropy).__name__ not in ["bytes", "str"]:
            raise TypeError("unsupported entropy type")
        entropy_bytes = entropy if isinstance(entropy, bytes) else bytes.fromhex(entropy)
    else:
        # random a new entropy
        entropy_bytes = randbits(BIP39_ENTROPY_BIT_LENGTH).to_bytes(BIP39_ENTROPY_BIT_LENGTH // 8, "big")
    entropy_bits: str = bytes_to_bits(entropy_bytes)
    if len(entropy_bits) not in BIP39_ENTROPY_BIT_LENGTH_LIST:
        raise ValidationError("invalid entropy bit length")
    checksum_bits: str = bytes_to_bits(sha256(entropy_bytes))[: len(entropy_bits) // 32]

    bits: str = entropy_bits + checksum_bits
    indexes_bits: list[str] = [bits[i : i + 11] for i in range(0, len(bits), 11)]
    return " ".join([WordList.get_word(bits_to_bytes(index_bits), lang) for index_bits in indexes_bits])


def validate_mnemonic(mnemonic: str, lang: str = "en"):
    # SECURITY: mnemonic is sensitive — do not log or embed in exceptions
    indexes: list[int] = [WordList.index_word(word, lang) for word in mnemonic.split(" ")]
    bits: str = "".join([bin(index)[2:].zfill(11) for index in indexes])
    entropy_bit_length: int = len(bits) * 32 // 33
    if entropy_bit_length not in BIP39_ENTROPY_BIT_LENGTH_LIST:
        raise ValidationError("invalid mnemonic, bad entropy bit length")
    entropy_bits: str = bits[:entropy_bit_length]
    checksum_bits: str = bytes_to_bits(sha256(bits_to_bytes(entropy_bits)))[: entropy_bit_length // 32]
    if checksum_bits != bits[entropy_bit_length:]:
        raise ValidationError("invalid mnemonic, checksum mismatch")


def seed_from_mnemonic(mnemonic: str, lang: str = "en", passphrase: str = "", prefix: str = "mnemonic") -> bytes:  # nosec B107 -- passphrase="" is the BIP39 spec default (no passphrase), not a hardcoded secret
    # SECURITY: mnemonic and passphrase are sensitive — returned seed is sensitive
    validate_mnemonic(mnemonic, lang)
    hash_name = "sha512"
    password = mnemonic.encode()
    salt = (prefix + passphrase).encode()
    iterations = 2048
    dklen = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
