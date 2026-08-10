"""Output script descriptors for watch-only import.

A descriptor is a single string that tells another wallet *everything* it
needs to watch this wallet: the script type, the extended public key, the
key-origin metadata (which master key, at which BIP44 path), and the
derivation suffix to walk. It is strictly more useful than a bare xpub,
which leaves the consumer guessing the script type and the origin.

pyrxd emits the ``pkh(...)`` form because Radiant is P2PKH-only — there
is no segwit on the chain, so ``wpkh``/``wsh``/``tr`` do not exist in
Radiant Core's parser.

Radiant fork caveat — the checksum
----------------------------------
Radiant Core forked from Bitcoin Core before 0.18, which is the release
that introduced descriptor checksums. Radiant Core's
``src/script/descriptor.cpp`` therefore has **no checksum machinery at
all** — no ``PolyMod``, no ``INPUT_CHARSET``, no ``CHECKSUM_CHARSET``.

The practical consequence is a trap for anyone carrying Bitcoin habits
across: a descriptor with the BIP380 ``#checksum`` suffix is *rejected*
by Radiant's ``scantxoutset`` (``error code: -5, Invalid descriptor``),
because the suffix is unparseable trailing input to that older parser.
Bitcoin Core, meanwhile, *requires* the checksum on most RPCs. The two
forks want opposite things from the same string.

pyrxd resolves this by defaulting to the **unchecksummed** form (what the
only descriptor consumer in the Radiant ecosystem accepts) and offering
:func:`append_checksum` / the CLI's ``--checksum`` flag for
Bitcoin-Core-lineage tools that demand one.

Hardened-path notation
----------------------
BIP380 permits both ``'`` and ``h`` as the hardened marker. pyrxd emits
``h``. Both parse, but ``'`` is a quoting hazard in every POSIX shell —
a descriptor containing ``'`` cannot be pasted inside single quotes
without escaping, which is exactly how ``radiant-cli`` invocations are
usually written. ``h`` pastes cleanly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..security.errors import ValidationError
from .bip32 import Xpub

# --------------------------------------------------------------------------
# BIP380 descriptor checksum.
#
# Transcribed from the BIP380 reference implementation. Proven against the
# BIP's published vector (``raw(deadbeef)#89f8spxm``) in
# ``tests/test_hd_descriptor.py``; do not "clean up" these constants
# without re-running that test — the charset ordering IS the algorithm.

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)

CHECKSUM_LENGTH = 8
"""Length of a BIP380 checksum, excluding the ``#`` separator."""


def _polymod(symbols: list[int]) -> int:
    """BIP380 ``descsum_polymod``."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= _GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def _expand(s: str) -> list[int] | None:
    """BIP380 ``descsum_expand``. Returns None if *s* has an out-of-charset character."""
    groups: list[int] = []
    symbols: list[int] = []
    for c in s:
        v = INPUT_CHARSET.find(c)
        if v < 0:
            return None
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(descriptor: str) -> str:
    """Return the 8-character BIP380 checksum for *descriptor* (no ``#``).

    :raises ValidationError: if *descriptor* already carries a checksum, or
        contains a character outside :data:`INPUT_CHARSET`.
    """
    if "#" in descriptor:
        raise ValidationError("descriptor already contains '#'; pass the bare descriptor without a checksum suffix")
    symbols = _expand(descriptor)
    if symbols is None:
        raise ValidationError("descriptor contains a character outside the BIP380 input charset")
    chk = _polymod(symbols + [0] * CHECKSUM_LENGTH) ^ 1
    return "".join(CHECKSUM_CHARSET[(chk >> (5 * (7 - i))) & 31] for i in range(CHECKSUM_LENGTH))


def append_checksum(descriptor: str) -> str:
    """Return *descriptor* with its BIP380 ``#checksum`` suffix appended.

    Radiant Core **rejects** the result — see the module docstring. Use this
    only for Bitcoin-Core-lineage consumers.
    """
    return f"{descriptor}#{descriptor_checksum(descriptor)}"


def verify_checksum(descriptor: str) -> bool:
    """Return True if *descriptor* ends in a valid BIP380 ``#checksum``.

    False for an unchecksummed descriptor, a malformed suffix, or a payload
    that does not match its checksum. Never raises — this is a predicate for
    validating untrusted input.
    """
    if len(descriptor) < CHECKSUM_LENGTH + 1 or descriptor[-(CHECKSUM_LENGTH + 1)] != "#":
        return False
    tail = descriptor[-CHECKSUM_LENGTH:]
    if not all(c in CHECKSUM_CHARSET for c in tail):
        return False
    symbols = _expand(descriptor[: -(CHECKSUM_LENGTH + 1)])
    if symbols is None:
        return False
    return _polymod(symbols + [CHECKSUM_CHARSET.find(c) for c in tail]) == 1


# --------------------------------------------------------------------------
# Key origin + descriptor construction.

HARDENED_MARKER = "h"
"""Hardened-derivation marker pyrxd emits. See the module docstring for why not ``'``."""

EXTERNAL_CHAIN = 0
"""BIP44 chain index for receive addresses (pyrxd calls this the *external* chain)."""

INTERNAL_CHAIN = 1
"""BIP44 chain index for change addresses (pyrxd calls this the *internal* chain)."""

_BIP32_HARDENED_BIT = 0x80000000
_PATH_STEP_RE = re.compile(r"^(\d+)([h'H])?$")


def normalize_path(path: str) -> str:
    """Normalize a BIP32 path to the descriptor key-origin form.

    ``"m/44'/512'/0'"`` → ``"44h/512h/0h"``. The leading ``m``/``m/`` is
    dropped (the descriptor's ``[fingerprint...]`` already says "from the
    master"), and every hardened marker is rewritten to
    :data:`HARDENED_MARKER`.

    :raises ValidationError: on a malformed step or an out-of-range index.
    """
    stripped = path.strip()
    if stripped in ("m", "m/", ""):
        return ""
    if stripped.startswith("m/"):
        stripped = stripped[2:]
    stripped = stripped.strip("/")
    out: list[str] = []
    for step in stripped.split("/"):
        match = _PATH_STEP_RE.match(step)
        if match is None:
            raise ValidationError(f"malformed derivation-path step {step!r} in path {path!r}")
        index = int(match.group(1))
        if index >= _BIP32_HARDENED_BIT:
            raise ValidationError(
                f"derivation-path step {step!r} is out of BIP32 range; the unhardened index must be below 2**31"
            )
        out.append(f"{index}{HARDENED_MARKER}" if match.group(2) else str(index))
    return "/".join(out)


def key_origin(master_fingerprint: bytes, path: str) -> str:
    """Build the descriptor key-origin field, e.g. ``[1a2b3c4d/44h/512h/0h]``.

    *master_fingerprint* must be the **master** key's fingerprint —
    ``hash160(master_pubkey)[:4]`` for the key at ``m`` — NOT the parent
    fingerprint stored inside the account xpub. Those differ for any account
    at depth > 1, and getting it wrong yields a descriptor that misidentifies
    its own origin: it still derives the right addresses, so nothing looks
    broken, but any consumer trying to match it to a signing device will fail
    to. :meth:`pyrxd.hd.wallet.HdWallet.master_fingerprint` returns the right
    value.

    :raises ValidationError: if *master_fingerprint* is not exactly 4 bytes.
    """
    if not isinstance(master_fingerprint, (bytes, bytearray)):
        raise ValidationError("master_fingerprint must be bytes")
    if len(master_fingerprint) != 4:
        raise ValidationError(
            f"master_fingerprint must be exactly 4 bytes (got {len(master_fingerprint)}); "
            "it is hash160(master public key)[:4]"
        )
    normalized = normalize_path(path)
    suffix = f"/{normalized}" if normalized else ""
    return f"[{bytes(master_fingerprint).hex()}{suffix}]"


def _coerce_xpub(xpub: Xpub | str) -> str:
    """Return the base58 xpub string, refusing anything that is not an xpub.

    An ``Xprv`` (or an xprv string) reaching a descriptor would publish the
    wallet's spending key to whatever the descriptor is pasted into. ``Xpub``
    already rejects a non-xpub prefix; this wrapper makes the intent explicit
    and gives the caller a message that names the hazard.
    """
    if isinstance(xpub, Xpub):
        return str(xpub)
    if not isinstance(xpub, str):
        raise ValidationError("xpub must be an Xpub or a base58 xpub string")
    try:
        return str(Xpub(xpub))
    except (ValidationError, ValueError, TypeError) as exc:
        # base58check_decode raises bare ValueError on a bad checksum, and Xkey
        # raises TypeError on a non-str/bytes; normalize everything to the
        # repo's ValidationError so callers have one thing to catch.
        raise ValidationError(
            "descriptor key must be an extended PUBLIC key (xpub/tpub). "
            "Never place an xprv in a descriptor — it exports spending authority."
        ) from exc


def pkh_descriptor(
    xpub: Xpub | str,
    *,
    master_fingerprint: bytes,
    account_path: str,
    chain: int,
    checksum: bool = False,
) -> str:
    """Build a ranged ``pkh()`` descriptor for one BIP44 chain.

    ``pkh([1a2b3c4d/44h/512h/0h]xpub6.../0/*)``

    *xpub* is the account-level extended public key at *account_path*.
    *chain* is :data:`EXTERNAL_CHAIN` (0, receive) or :data:`INTERNAL_CHAIN`
    (1, change). The trailing ``/*`` makes it a *ranged* descriptor, so the
    consumer walks indices itself.

    *checksum* appends the BIP380 suffix. Defaults to False because Radiant
    Core rejects the checksummed form — see the module docstring.
    """
    if isinstance(chain, bool) or not isinstance(chain, int):
        raise ValidationError("chain must be an int (0 = receive/external, 1 = change/internal)")
    if not 0 <= chain < _BIP32_HARDENED_BIT:
        raise ValidationError(f"chain {chain} out of range; BIP44 chain indices are unhardened, so 0 <= chain < 2**31")
    origin = key_origin(master_fingerprint, account_path)
    descriptor = f"pkh({origin}{_coerce_xpub(xpub)}/{chain}/*)"
    return append_checksum(descriptor) if checksum else descriptor


@dataclass(frozen=True)
class AccountDescriptors:
    """The pair of ranged descriptors that fully describe one BIP44 account.

    Both chains are always present. A watch-only import that takes only the
    receive descriptor silently under-reports the balance, because change
    outputs land on the internal chain and would never be scanned.
    """

    receive: str
    """Descriptor for the external chain (``/0/*``) — addresses you hand out."""

    change: str
    """Descriptor for the internal chain (``/1/*``) — where change lands."""

    master_fingerprint: str
    """Hex master-key fingerprint embedded in both descriptors."""

    account_path: str
    """The BIP44 account path, in descriptor notation (e.g. ``44h/512h/0h``)."""

    def as_dict(self) -> dict[str, str]:
        """Flat dict for CLI/JSON emission."""
        return {
            "descriptor_receive": self.receive,
            "descriptor_change": self.change,
            "master_fingerprint": self.master_fingerprint,
            "descriptor_origin_path": self.account_path,
        }


def account_descriptors(
    xpub: Xpub | str,
    *,
    master_fingerprint: bytes,
    account_path: str,
    checksum: bool = False,
) -> AccountDescriptors:
    """Build the receive + change descriptor pair for a BIP44 account."""
    return AccountDescriptors(
        receive=pkh_descriptor(
            xpub,
            master_fingerprint=master_fingerprint,
            account_path=account_path,
            chain=EXTERNAL_CHAIN,
            checksum=checksum,
        ),
        change=pkh_descriptor(
            xpub,
            master_fingerprint=master_fingerprint,
            account_path=account_path,
            chain=INTERNAL_CHAIN,
            checksum=checksum,
        ),
        master_fingerprint=bytes(master_fingerprint).hex(),
        account_path=normalize_path(account_path),
    )
