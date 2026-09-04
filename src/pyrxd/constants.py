from __future__ import annotations

import os
from collections.abc import Mapping
from enum import Enum

NUMBER_BYTE_LENGTH: int = 32

TRANSACTION_SEQUENCE: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_SEQUENCE") or 0xFFFFFFFF)
TRANSACTION_VERSION: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_VERSION") or 1)
TRANSACTION_LOCKTIME: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_LOCKTIME") or 0)
# Default fee rate for :meth:`pyrxd.transaction.Transaction.fee`, in photons per KILOBYTE.
#
# This used to default to 5 photons/kB — inherited from a Bitcoin-shaped SDK and
# 2_000_000x under what a Radiant node will relay. Radiant's effective minimum relay
# rate is 10_000_000 photons/kB (`RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB`,
# Radiant-Core `src/policy/policy.h:49` @ v3.1.2), charged against `GetTotalSize()`
# in `AcceptToMemoryPool` (`src/validation.cpp:779` @ v3.1.2, reject reason
# `min relay fee not met`). Any transaction built with the old default was
# unrelayable, so this defaults to the floor itself.
#
# :data:`pyrxd.fee_sizing.RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB` is the OWNER of
# this number; the literal is repeated here only because ``pyrxd.constants`` is the
# leaf module every other module imports and must not import back into the tree.
# ``tests/test_false_consensus_premises.py`` asserts the two cannot drift.
TRANSACTION_FEE_RATE: int = int(os.getenv("RXD_PY_SDK_TRANSACTION_FEE_RATE") or 10_000_000)  # photons per kB

# pyrxd's single uneconomic-change floor, in photons. THE ONE DEFINITION —
# every other module that needs it imports this name rather than re-typing 546.
#
# It is pyrxd POLICY, not a Radiant rule. Radiant has no dust threshold:
# `GetDustThreshold` returns 1 satoshi unconditionally and `IsDust` is
# `nValue <= 0` (Radiant-Core `src/policy/policy.cpp:19-25` @ v3.1.2), and
# standardness is never consulted at all — `fRequireStandard` is hardcoded
# `false` (`src/validation.cpp:271`, re-set unconditionally at `src/init.cpp:1995`,
# both @ v3.1.2). So ANY output of 1 photon or more relays, and pyrxd itself
# depends on that: a dMint contract MUST be a 1-photon singleton because the
# covenant enforces `OP_OUTPUTVALUE == 1`.
#
# 546 is Bitcoin's P2PKH dust convention, kept here only as a conservative
# wallet-level guard against creating change too small to be worth spending.
# It must never be used as a floor on a TOKEN output: an FT output's value IS
# its unit count, so a 546 floor there forbids transferring 100 units of
# anything. (See `pyrxd.btc_wallet.payment.DUST_LIMIT` for the separate,
# genuinely-Bitcoin 546 that governs the BTC leg of a swap.)
DUST_THRESHOLD_PHOTONS: int = 546

# Largest OP_RETURN message body pyrxd will encode, in bytes. THE ONE DEFINITION.
#
# This is an ENCODER limit, not a chain rule and not a relay rule. pyrxd emits
# `OP_RETURN [<"msg" marker>] <push> <message>` and switches to `OP_PUSHDATA1`
# (0x4c) above 75 bytes; `OP_PUSHDATA1` carries a ONE-byte length, so 255 is the
# largest body that encoding can express. Above it the builder must move to
# `OP_PUSHDATA2`, which no pyrxd path emits and no ecosystem parser is known to
# read for the Photonic `msg` convention.
#
# What it is NOT: Bitcoin's 80-byte OP_RETURN standardness cap. That number has
# no force on Radiant twice over. (1) Standardness is never consulted:
# `fRequireStandard` is hardcoded `false` (Radiant-Core `src/validation.cpp:271`,
# re-set unconditionally at `src/init.cpp:1995`, both @ v3.1.2), so `IsStandardTx`
# — the only caller of the OP_RETURN size rule — never runs. (2) Even if it did
# run, the limit it applies is `nMaxDatacarrierBytes`, which defaults to
# `DEFAULT_DATACARRIER_BYTES = 1024` (`src/script/standard.h:35`,
# `src/script/standard.cpp:18` @ v3.1.2) — and Radiant's own
# `MAX_OP_RETURN_RELAY` is 223 (`src/script/standard.h:33`), not 80.
# Consensus caps a single push at `MAX_SCRIPT_ELEMENT_SIZE` = 32_000_000 bytes
# (`src/script/script.h:74`, vendored at `tests/vendor/radiant_core/script.h`).
MAX_OP_RETURN_MSG_BYTES: int = 255

BIP32_DERIVATION_PATH = os.getenv("RXD_PY_SDK_BIP32_DERIVATION_PATH") or "m/"
BIP39_ENTROPY_BIT_LENGTH: int = int(os.getenv("RXD_PY_SDK_BIP39_ENTROPY_BIT_LENGTH") or 128)
BIP44_DERIVATION_PATH = os.getenv("RXD_PY_SDK_BIP44_DERIVATION_PATH") or "m/44'/512'/0'"

HTTP_REQUEST_TIMEOUT: int = int(os.getenv("RXD_PY_SDK_HTTP_REQUEST_TIMEOUT") or 30)
THREAD_POOL_MAX_EXECUTORS: int = int(os.getenv("RXD_PY_SDK_THREAD_POOL_MAX_EXECUTORS") or 10)

# ---------------------------------------------------------------------------
# BIP68 relative time-lock (nSequence) encoding
# ---------------------------------------------------------------------------
# The five constants ``CTxIn`` declares in Radiant Core's
# ``src/primitives/transaction.h`` (lines 119-149), consumed by
# ``GenericTransactionSignatureChecker::CheckSequence`` in
# ``src/script/interpreter.cpp``. ``tests/test_consensus_parser_strictness.py``
# re-derives all five by parsing the vendored copy of that header, so they
# cannot drift from upstream unnoticed.
#
# They live here rather than in the two modules that need them because they had
# been spelled out twice — once in ``script/timelock.py`` (Radiant CSV locking
# scripts) and once in ``btc_wallet/taproot.py`` (the BTC leg) — plus a third
# time inline in a test. BIP68 is chain-agnostic: Bitcoin and Radiant use
# identical values, so one definition serves both legs of a cross-chain swap
# and removes the possibility of the two legs disagreeing.
#
# Why this matters more than it looks: CSV maturity governs HTLC refunds, and
# Radiant supports neither RBF nor CPFP. A refund transaction that misjudges
# maturity by a single block cannot be repaired — it can only be discarded and
# rebuilt, by which time the counterparty's claim window may already be open.

#: ``nSequence`` value that disables ``nLockTime`` for the whole transaction.
SEQUENCE_FINAL: int = 0xFFFFFFFF

#: The largest ``nSequence`` that is still NON-final: ``0xFFFFFFFE``. THE ONE
#: DEFINITION — derived from :data:`SEQUENCE_FINAL` rather than typed, so the two
#: cannot be one apart by accident.
#:
#: Why it needs a name. An input is final iff ``nSequence == SEQUENCE_FINAL``, and a
#: transaction whose inputs are all final skips ``nLockTime`` entirely
#: (``CTransaction::IsFinalTx``). ``OP_CHECKLOCKTIMEVERIFY`` therefore *requires* the
#: spending input to be non-final — it fails outright otherwise — and so does the
#: BIP68 evaluation a CSV refund depends on. This value is the "non-final, but as
#: close to final as possible" choice every timelocked spend in this SDK wants: bit 31
#: is still set, so it disables the BIP68 RELATIVE lock on that input without
#: disabling the absolute one on the transaction.
#:
#: It was written out three times — the RSWP refund spend, the Gravity ``forfeit()``
#: CLTV input, and the HTLC refund's fee input. All three are the same rule, and the
#: one-character slip to ``0xFFFFFFFF`` is silent at build time and fatal at spend
#: time: the refund branch stops being satisfiable, on a chain with no RBF and no
#: CPFP, in the one path a counterparty stall makes load-bearing.
SEQUENCE_LOCKTIME_ENABLED: int = SEQUENCE_FINAL - 1

#: Bit 31. Set on an input's ``nSequence`` means "not a relative lock-time" —
#: ``CheckSequence`` returns false immediately, so the CSV in the script is
#: satisfied by nothing and the branch is simply unspendable via that path.
SEQUENCE_LOCKTIME_DISABLE_FLAG: int = 1 << 31

#: Bit 22. Clear = the count is in blocks; set = the count is in 512-second
#: units. Reading a block count as a time count (or the reverse) is a 512x
#: error in the direction that matters.
SEQUENCE_LOCKTIME_TYPE_FLAG: int = 1 << 22

#: The low 16 bits, which hold the unit count itself.
SEQUENCE_LOCKTIME_MASK: int = 0x0000FFFF

#: Shift, not seconds: time-based units are ``1 << 9`` = 512 seconds each.
#: Upstream stores the shift, so storing 512 under this name would be a 2**9
#: error waiting for the first caller that used it as a shift.
SEQUENCE_LOCKTIME_GRANULARITY: int = 9

#: Everything ``CheckSequence`` compares. Bits outside this mask carry no
#: consensus meaning and are stripped from both sides before the comparison.
SEQUENCE_LOCKTIME_CONSENSUS_MASK: int = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK

#: BIP68 rules only engage at transaction version 2 or above; below it
#: ``CheckSequence`` returns false regardless of the sequence value.
BIP68_MIN_TX_VERSION: int = 2


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
    OP_NOP2 = b"\xb1"  # alias, per Radiant's `OP_NOP2 = OP_CHECKLOCKTIMEVERIFY`
    OP_CHECKSEQUENCEVERIFY = b"\xb2"
    OP_NOP3 = b"\xb2"  # alias, per Radiant's `OP_NOP3 = OP_CHECKSEQUENCEVERIFY`
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
    OP_PUSH_TX_STATE = b"\xed"

    # Glyph v2 dMint hash opcodes (Hard Fork V2)
    OP_BLAKE3 = b"\xee"
    OP_K12 = b"\xef"

    # Pseudo-words.
    #
    # NOT Radiant opcodes. These five are Bitcoin Core legacy names that
    # Radiant's ``enum opcodetype`` does not define at all. Every one of them
    # sits above :data:`MAX_OPCODE`, so ``CScript::HasValidOps`` rejects any
    # script containing these bytes — they can never appear in a valid script
    # and must never be emitted. They are unused anywhere in pyrxd and are
    # retained only so that removing them is a deliberate, separately-reviewed
    # API break rather than a drive-by change.
    #
    # ``tests/test_consensus_opcode_parity.py`` allow-lists exactly these names
    # and asserts each is > MAX_OPCODE, so the exemption stays honest: if one
    # ever drifted down into the valid opcode range the parity test fails.
    OP_DATA = b"\xfb"
    OP_SIG = b"\xfc"
    OP_PUBKEYHASH = b"\xfd"
    OP_PUBKEY = b"\xfe"
    OP_INVALIDOPCODE = b"\xff"


OPCODE_VALUE_NAME_DICT: dict[bytes, str] = {item.value: item.name for item in OpCode}
OPCODE_VALUE_NAME_DICT[b"\x00"] = "OP_0"

# ---------------------------------------------------------------------------
# Ref-operand opcodes (Radiant)
# ---------------------------------------------------------------------------
# The opcodes that consensus follows with a **36-byte immediate operand** and no
# length prefix. This is exactly the set ``GetScriptOp`` special-cases
# (Radiant-Core ``src/script/script.cpp:710-726``); any script walker that does
# not consume those 36 bytes desynchronises from consensus the moment one
# appears, because it starts reading ref bytes as opcodes.
#
# It is NOT the contiguous range 0xd0-0xd8. The four opcodes in between —
# 0xd4 OP_REFHASHDATASUMMARY_UTXO, 0xd5 OP_REFHASHVALUESUM_UTXOS,
# 0xd6 OP_REFHASHDATASUMMARY_OUTPUT, 0xd7 OP_REFHASHVALUESUM_OUTPUTS — are pure
# stack operations carrying NO operand.
#
# Lives here, in the bottom layer, because two different walkers need it: the
# Glyph classifier (:data:`pyrxd.glyph.script.REF_OPCODES`) and the BIP143
# preimage's ``hashOutputHashes`` field
# (:func:`pyrxd.transaction.transaction_preimage._get_push_refs`).
REF_OPERAND_OPCODES: frozenset[int] = frozenset({0xD0, 0xD1, 0xD2, 0xD3, 0xD8})

# Width of that immediate operand, in bytes. ``GetScriptOp`` advances the
# program counter by exactly this much and returns those bytes as the ref
# (``pc += 36``). Centralised for the same reason as the opcode set: a walker
# that hard-codes the width is a walker that can disagree with consensus.
REF_OPERAND_WIDTH: int = 36

# The largest byte Radiant will accept as an opcode —  ``MAX_OPCODE`` in
# ``src/script/script.h``, defined there as ``FIRST_UNDEFINED_OP_VALUE - 1``.
# ``CScript::HasValidOps`` (``src/script/script.cpp``) rejects any script
# containing a byte above this, so it is a real validity boundary and not just
# a table size.
MAX_OPCODE: int = 0xEF

# ---------------------------------------------------------------------------
# Scalar consensus limits (Radiant-Core ``src/script/script.h:71-90``)
# ---------------------------------------------------------------------------
# READ THESE BEFORE ASSUMING BITCOIN'S VALUES. Radiant raised the script limits
# by five orders of magnitude and kept Bitcoin's under ``*_LEGACY`` names. Code
# that "knows" the push limit is 520 is describing a different chain, and a
# builder that enforced 520 here would reject scripts Radiant accepts.
#
# Every value below is asserted against the vendored Radiant Core source by
# ``tests/test_consensus_opcode_parity.py`` via ``consensus_oracle.script_limit``,
# so none of them is a hand-maintained number.

# Largest element pushable to the stack. ``CScript::HasValidOps`` rejects a
# script containing a larger push, which is what makes this a real boundary and
# not just a buffer size. Consumed by :func:`pyrxd.script.consensus.has_valid_ops`.
MAX_SCRIPT_ELEMENT_SIZE: int = 32_000_000

# Bitcoin's 520-byte push limit, which Radiant retains only under this name.
# Kept because the BTC-side code in ``pyrxd.btc_wallet`` builds scripts for a
# chain where 520 IS the live limit, and naming it here is what stops someone
# "unifying" the two into one wrong number.
MAX_SCRIPT_ELEMENT_SIZE_LEGACY: int = 520

# Maximum serialized script length. Consumed by
# :func:`pyrxd.script.consensus.has_valid_ops`.
MAX_SCRIPT_SIZE: int = 32_000_000

# NO CONSUMER IN PYRXD, DELIBERATELY. Both are limits the script *interpreter*
# enforces while executing, and pyrxd has no interpreter — it builds and parses
# scripts, it never runs them. They are pinned (and oracle-checked) so that
# whoever adds an evaluator, or a stack-depth estimator, finds the value already
# derived from source instead of retyping it from a Bitcoin tutorial. Recorded
# as unconsumed rather than wired into a plausible-looking check, because a
# constant with a fake consumer pins nothing and reads as though it does.
MAX_OPS_PER_SCRIPT: int = 32_000_000
MAX_STACK_SIZE: int = 32_000_000

# Genesis block hash per network — the chain's identity, and the value a HashMark
# v2 signature commits to (the same bytes on another chain are a different signed
# statement). Lives HERE, in the dependency-free bottom layer, rather than in
# `network.registry`, because the offline inspect core needs it and importing
# `pyrxd.network` drags in `electrumx` -> `script.type` -> `keys` -> `coincurve`.
#
# That is not hypothetical weight: the browser inspect page runs pyrxd under
# Pyodide WITHOUT coincurve, so a network import there is a hard failure. Reaching
# for the registry from the inspect core broke HashMark classification in the
# browser entirely until this moved.
GENESIS_BLOCK_HASHES: Mapping[str, str] = {
    "mainnet": "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4",
    "testnet": "000000000d8ada264d16f87a590b2af320cd3c7e3f9be5482163e830fd00aca2",
    "regtest": "7c1797514a165b0d99953a993a2a42081d6c0706026c36c06fc6fe728f93a5dd",
}


def genesis_hash_for(network: str) -> str | None:
    """Expected genesis hash for *network*, or ``None`` for an unknown network.

    ``None`` means "pyrxd cannot verify this binding", not "the binding is fine";
    callers should treat it as a reason to be *more* explicit, not less.
    """
    return GENESIS_BLOCK_HASHES.get(str(network))


# Below this an nLockTime is a block height; at or above it, a Unix timestamp.
# Consumed by :mod:`pyrxd.script.timelock`, which used to spell it out again.
LOCKTIME_THRESHOLD: int = 500_000_000

# The subset that contributes to an output's **push-ref set** — the set Radiant
# hashes into the sighash's ``hashOutputHashes`` and returns from
# ``OP_REFDATASUMMARY_OUTPUT``. ``CScript::GetPushRefs``
# (``src/script/script.cpp:585-607``) files 0xd1/0xd2/0xd3 into the *require* and
# *disallow-sibling* sets instead, so they must be WALKED but not COLLECTED.
PUSH_REF_OPCODES: frozenset[int] = frozenset({0xD0, 0xD8})

# The same two opcodes as plain ints, for the FIXED-LAYOUT readers that expect one
# specific opcode at one specific offset rather than testing set membership
# (``glyph/dmint/chain.py`` parses ``0xd8 <ref> 0xd0 <ref>`` positionally). Derived from
# the ``OpCode`` table rather than retyped, so there is still exactly one place any of
# these bytes is written down.
OP_PUSHINPUTREF_BYTE: int = OpCode.OP_PUSHINPUTREF.value[0]
OP_PUSHINPUTREFSINGLETON_BYTE: int = OpCode.OP_PUSHINPUTREFSINGLETON.value[0]
