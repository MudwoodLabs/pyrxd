from __future__ import annotations

import os
from enum import Enum

NUMBER_BYTE_LENGTH: int = 32

TRANSACTION_SEQUENCE: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_SEQUENCE") or 0xFFFFFFFF)
TRANSACTION_VERSION: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_VERSION") or 1)
TRANSACTION_LOCKTIME: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_LOCKTIME") or 0)
TRANSACTION_FEE_RATE: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_FEE_RATE") or 5)  # satoshi per kilobyte
BIP32_DERIVATION_PATH = os.getenv("RXD_PY_SDK_BIP32_DERIVATION_PATH") or "m/"
BIP39_ENTROPY_BIT_LENGTH: int = int(os.getenv("RXD_PY_SDK_BIP39_ENTROPY_BIT_LENGTH") or 128)
BIP44_DERIVATION_PATH = os.getenv("RXD_PY_SDK_BIP44_DERIVATION_PATH") or "m/44'/512'/0'"

HTTP_REQUEST_TIMEOUT: int = int(os.getenv("RXD_PY_SDK_HTTP_REQUEST_TIMEOUT") or 30)
THREAD_POOL_MAX_EXECUTORS: int = int(os.getenv("RXD_PY_SDK_THREAD_POOL_MAX_EXECUTORS") or 10)


class Network(str, Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"


class SIGHASH(int, Enum):
    ALL: int = 0x01
    NONE: int = 0x02
    SINGLE: int = 0x03
    ANYONECANPAY: int = 0x80

    FORKID: int = 0x40

    ALL_FORKID = ALL | FORKID
    NONE_FORKID = NONE | FORKID
    SINGLE_FORKID = SINGLE | FORKID
    ALL_ANYONECANPAY_FORKID = ALL_FORKID | ANYONECANPAY
    NONE_ANYONECANPAY_FORKID = NONE_FORKID | ANYONECANPAY
    SINGLE_ANYONECANPAY_FORKID = SINGLE_FORKID | ANYONECANPAY

    @classmethod
    def validate(cls, sighash: int) -> bool:
        return sighash in [
            cls.ALL_FORKID,
            cls.NONE_FORKID,
            cls.SINGLE_FORKID,
            cls.ALL_ANYONECANPAY_FORKID,
            cls.NONE_ANYONECANPAY_FORKID,
            cls.SINGLE_ANYONECANPAY_FORKID,
        ]


#
# P2PKH address
#
ADDRESS_MAINNET_PREFIX: bytes = b"\x00"
ADDRESS_TESTNET_PREFIX: bytes = b"\x6f"
NETWORK_ADDRESS_PREFIX_DICT: dict[Network, bytes] = {
    Network.MAINNET: ADDRESS_MAINNET_PREFIX,
    Network.TESTNET: ADDRESS_TESTNET_PREFIX,
}
ADDRESS_PREFIX_NETWORK_DICT: dict[bytes, Network] = {
    ADDRESS_MAINNET_PREFIX: Network.MAINNET,
    ADDRESS_TESTNET_PREFIX: Network.TESTNET,
}

#
# WIF
#
WIF_MAINNET_PREFIX: bytes = b"\x80"
WIF_TESTNET_PREFIX: bytes = b"\xef"
NETWORK_WIF_PREFIX_DICT: dict[Network, bytes] = {
    Network.MAINNET: WIF_MAINNET_PREFIX,
    Network.TESTNET: WIF_TESTNET_PREFIX,
}
WIF_PREFIX_NETWORK_DICT: dict[bytes, Network] = {
    WIF_MAINNET_PREFIX: Network.MAINNET,
    WIF_TESTNET_PREFIX: Network.TESTNET,
}

#
# public key
#
PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX: bytes = b"\x02"
PUBLIC_KEY_COMPRESSED_ODD_Y_PREFIX: bytes = b"\x03"
PUBLIC_KEY_COMPRESSED_PREFIX_LIST: list[bytes] = [
    PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX,
    PUBLIC_KEY_COMPRESSED_ODD_Y_PREFIX,
]
PUBLIC_KEY_COMPRESSED_BYTE_LENGTH: int = 33
PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH: int = 65
PUBLIC_KEY_BYTE_LENGTH_LIST: list[int] = [PUBLIC_KEY_COMPRESSED_BYTE_LENGTH, PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH]
PUBLIC_KEY_HASH_BYTE_LENGTH: int = 20

#
# extended private key
#
XPRV_MAINNET_PREFIX: bytes = b"\x04\x88\xad\xe4"
XPRV_TESTNET_PREFX: bytes = b"\x04\x35\x83\x94"
XPRV_PREFIX_LIST: list[bytes] = [XPRV_MAINNET_PREFIX, XPRV_TESTNET_PREFX]
NETWORK_XPRV_PREFIX_DICT: dict[Network, bytes] = {
    Network.MAINNET: XPRV_MAINNET_PREFIX,
    Network.TESTNET: XPRV_TESTNET_PREFX,
}
XPRV_PREFIX_NETWORK_DICT: dict[bytes, Network] = {
    XPRV_MAINNET_PREFIX: Network.MAINNET,
    XPRV_TESTNET_PREFX: Network.TESTNET,
}

#
# extended public key
#
XPUB_MAINNET_PREFIX: bytes = b"\x04\x88\xb2\x1e"
XPUB_TESTNET_PREFIX: bytes = b"\x04\x35\x87\xcf"
XPUB_PREFIX_LIST: list[bytes] = [XPUB_MAINNET_PREFIX, XPUB_TESTNET_PREFIX]
NETWORK_XPUB_PREFIX_DICT: dict[Network, bytes] = {
    Network.MAINNET: XPUB_MAINNET_PREFIX,
    Network.TESTNET: XPUB_TESTNET_PREFIX,
}
XPUB_PREFIX_NETWORK_DICT: dict[bytes, Network] = {
    XPUB_MAINNET_PREFIX: Network.MAINNET,
    XPUB_TESTNET_PREFIX: Network.TESTNET,
}

#
# extended key
#
XKEY_BYTE_LENGTH: int = 78
XKEY_PREFIX_LIST: list[bytes] = XPRV_PREFIX_LIST + XPUB_PREFIX_LIST
#
# BIP32
#
BIP32_SEED_BYTE_LENGTH: int = 64
#
# BIP39
#
BIP39_ENTROPY_BIT_LENGTH_LIST: list[int] = [128, 160, 192, 224, 256]


class OpCode(bytes, Enum):
    """
    Radiant opcodes based on Bitcoin SV opcodes
    """

    # Constants
    OP_0 = b"\x00"
    OP_FALSE = b"\x00"
    OP_PUSHDATA1 = b"\x4c"
    OP_PUSHDATA2 = b"\x4d"
    OP_PUSHDATA4 = b"\x4e"
    OP_1NEGATE = b"\x4f"
    OP_RESERVED = b"\x50"
    OP_1 = b"\x51"
    OP_TRUE = b"\x51"
    OP_2 = b"\x52"
    OP_3 = b"\x53"
    OP_4 = b"\x54"
    OP_5 = b"\x55"
    OP_6 = b"\x56"
    OP_7 = b"\x57"
    OP_8 = b"\x58"
    OP_9 = b"\x59"
    OP_10 = b"\x5a"
    OP_11 = b"\x5b"
    OP_12 = b"\x5c"
    OP_13 = b"\x5d"
    OP_14 = b"\x5e"
    OP_15 = b"\x5f"
    OP_16 = b"\x60"

    # Flow Control
    OP_NOP = b"\x61"
    OP_VER = b"\x62"
    OP_IF = b"\x63"
    OP_NOTIF = b"\x64"
    OP_VERIF = b"\x65"
    OP_VERNOTIF = b"\x66"
    OP_ELSE = b"\x67"
    OP_ENDIF = b"\x68"
    OP_VERIFY = b"\x69"
    OP_RETURN = b"\x6a"

    # Stack
    OP_TOALTSTACK = b"\x6b"
    OP_FROMALTSTACK = b"\x6c"
    OP_2DROP = b"\x6d"
    OP_2DUP = b"\x6e"
    OP_3DUP = b"\x6f"
    OP_2OVER = b"\x70"
    OP_2ROT = b"\x71"
    OP_2SWAP = b"\x72"
    OP_IFDUP = b"\x73"
    OP_DEPTH = b"\x74"
    OP_DROP = b"\x75"
    OP_DUP = b"\x76"
    OP_NIP = b"\x77"
    OP_OVER = b"\x78"
    OP_PICK = b"\x79"
    OP_ROLL = b"\x7a"
    OP_ROT = b"\x7b"
    OP_SWAP = b"\x7c"
    OP_TUCK = b"\x7d"

    # Splice
    OP_CAT = b"\x7e"
    OP_SPLIT = b"\x7f"
    OP_NUM2BIN = b"\x80"
    OP_BIN2NUM = b"\x81"
    OP_SIZE = b"\x82"

    # Bitwise Logic
    OP_INVERT = b"\x83"
    OP_AND = b"\x84"
    OP_OR = b"\x85"
    OP_XOR = b"\x86"
    OP_EQUAL = b"\x87"
    OP_EQUALVERIFY = b"\x88"
    OP_RESERVED1 = b"\x89"
    OP_RESERVED2 = b"\x8a"

    # Arithmetic
    OP_1ADD = b"\x8b"
    OP_1SUB = b"\x8c"
    OP_2MUL = b"\x8d"
    OP_2DIV = b"\x8e"
    OP_NEGATE = b"\x8f"
    OP_ABS = b"\x90"
    OP_NOT = b"\x91"
    OP_0NOTEQUAL = b"\x92"
    OP_ADD = b"\x93"
    OP_SUB = b"\x94"
    OP_MUL = b"\x95"
    OP_DIV = b"\x96"
    OP_MOD = b"\x97"
    OP_LSHIFT = b"\x98"
    OP_RSHIFT = b"\x99"
    OP_BOOLAND = b"\x9a"
    OP_BOOLOR = b"\x9b"
    OP_NUMEQUAL = b"\x9c"
    OP_NUMEQUALVERIFY = b"\x9d"
    OP_NUMNOTEQUAL = b"\x9e"
    OP_LESSTHAN = b"\x9f"
    OP_GREATERTHAN = b"\xa0"
    OP_LESSTHANOREQUAL = b"\xa1"
    OP_GREATERTHANOREQUAL = b"\xa2"
    OP_MIN = b"\xa3"
    OP_MAX = b"\xa4"
    OP_WITHIN = b"\xa5"

    # Cryptography
    OP_RIPEMD160 = b"\xa6"
    OP_SHA1 = b"\xa7"
    OP_SHA256 = b"\xa8"
    OP_HASH160 = b"\xa9"
    OP_HASH256 = b"\xaa"
    OP_CODESEPARATOR = b"\xab"
    OP_CHECKSIG = b"\xac"
    OP_CHECKSIGVERIFY = b"\xad"
    OP_CHECKMULTISIG = b"\xae"
    OP_CHECKMULTISIGVERIFY = b"\xaf"

    # Reserved NOPs
    OP_NOP1 = b"\xb0"
    OP_CHECKLOCKTIMEVERIFY = b"\xb1"
    OP_CHECKSEQUENCEVERIFY = b"\xb2"
    OP_NOP4 = b"\xb3"
    OP_NOP5 = b"\xb4"
    OP_NOP6 = b"\xb5"
    OP_NOP7 = b"\xb6"
    OP_NOP8 = b"\xb7"
    OP_NOP9 = b"\xb8"
    OP_NOP10 = b"\xb9"

    # Radiant specific opcodes
    OP_CHECKDATASIG = b"\xba"
    OP_CHECKDATASIGVERIFY = b"\xbb"
    OP_REVERSEBYTES = b"\xbc"
    OP_STATESEPARATOR = b"\xbd"
    OP_STATESEPARATORINDEX_UTXO = b"\xbe"
    OP_STATESEPARATORINDEX_OUTPUT = b"\xbf"

    OP_INPUTINDEX = b"\xc0"
    OP_ACTIVEBYTECODE = b"\xc1"
    OP_TXVERSION = b"\xc2"
    OP_TXINPUTCOUNT = b"\xc3"
    OP_TXOUTPUTCOUNT = b"\xc4"
    OP_TXLOCKTIME = b"\xc5"
    OP_UTXOVALUE = b"\xc6"
    OP_UTXOBYTECODE = b"\xc7"
    OP_OUTPOINTTXHASH = b"\xc8"
    OP_OUTPOINTINDEX = b"\xc9"
    OP_INPUTBYTECODE = b"\xca"
    OP_INPUTSEQUENCENUMBER = b"\xcb"
    OP_OUTPUTVALUE = b"\xcc"
    OP_OUTPUTBYTECODE = b"\xcd"

    OP_SHA512_256 = b"\xce"
    OP_HASH512_256 = b"\xcf"

    OP_PUSHINPUTREF = b"\xd0"
    OP_REQUIREINPUTREF = b"\xd1"
    OP_DISALLOWPUSHINPUTREF = b"\xd2"
    OP_DISALLOWPUSHINPUTREFSIBLING = b"\xd3"

    OP_REFHASHDATASUMMARY_UTXO = b"\xd4"
    OP_REFHASHVALUESUM_UTXOS = b"\xd5"
    OP_REFHASHDATASUMMARY_OUTPUT = b"\xd6"
    OP_REFHASHVALUESUM_OUTPUTS = b"\xd7"

    OP_PUSHINPUTREFSINGLETON = b"\xd8"
    OP_REFTYPE_UTXO = b"\xd9"
    OP_REFTYPE_OUTPUT = b"\xda"

    OP_REFVALUESUM_UTXOS = b"\xdb"
    OP_REFVALUESUM_OUTPUTS = b"\xdc"
    OP_REFOUTPUTCOUNT_UTXOS = b"\xdd"
    OP_REFOUTPUTCOUNT_OUTPUTS = b"\xde"
    OP_REFOUTPUTCOUNTZEROVALUED_UTXOS = b"\xdf"
    OP_REFOUTPUTCOUNTZEROVALUED_OUTPUTS = b"\xe0"
    OP_REFDATASUMMARY_UTXO = b"\xe1"
    OP_REFDATASUMMARY_OUTPUT = b"\xe2"

    OP_CODESCRIPTHASHVALUESUM_UTXOS = b"\xe3"
    OP_CODESCRIPTHASHVALUESUM_OUTPUTS = b"\xe4"
    OP_CODESCRIPTHASHOUTPUTCOUNT_UTXOS = b"\xe5"
    OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS = b"\xe6"
    OP_CODESCRIPTHASHZEROVALUEDOUTPUTCOUNT_UTXOS = b"\xe7"
    OP_CODESCRIPTHASHZEROVALUEDOUTPUTCOUNT_OUTPUTS = b"\xe8"
    OP_CODESCRIPTBYTECODE_UTXO = b"\xe9"
    OP_CODESCRIPTBYTECODE_OUTPUT = b"\xea"
    OP_STATESCRIPTBYTECODE_UTXO = b"\xeb"
    OP_STATESCRIPTBYTECODE_OUTPUT = b"\xec"

    # Pseudo-words
    OP_DATA = b"\xfb"
    OP_SIG = b"\xfc"
    OP_PUBKEYHASH = b"\xfd"
    OP_PUBKEY = b"\xfe"
    OP_INVALIDOPCODE = b"\xff"


OPCODE_VALUE_NAME_DICT: dict[bytes, str] = {item.value: item.name for item in OpCode}
OPCODE_VALUE_NAME_DICT[b"\x00"] = "OP_0"
