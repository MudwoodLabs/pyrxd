"""A malformed signature is a FALSE verification result, not an internal bug.

``PublicKey.verify`` returned ``self.key.verify(...)`` straight through, and
coincurve's strict DER parser raises a bare ``ValueError`` — not an
``RxdSdkError`` — for bytes it cannot parse. That escaped
``swap.partial._verify_owner_signature``, which every ``accept_offer`` and
``take_rswp_order`` crosses, and whose CLI caller (``cli/swap_book_cmds._finish``)
maps only ``RxdSdkError``. It landed on ``cli/main.py``'s catch-all, so a
counterparty sending rubbish made pyrxd print "unexpected failure" and exit 4:
pyrxd blaming itself for a hostile input it handled correctly.

TWO DIRECTIONS, because a guard that refuses honest work is a bug:

* the refusal half — unparseable DER returns ``False``, and reaching the
  production entry point with it raises ``ValidationError``, not ``ValueError``;
* the honest half — a genuine signature still verifies ``True`` through the
  same code path, and a genuine signature over the wrong message still
  verifies ``False`` rather than being swept into the new branch.

AND THE THIRD DIRECTION, which is the one a blanket ``except ValueError``
would have broken: ``coincurve.PublicKey.verify`` raises the SAME exception
type for a message hash of the wrong width. That is a caller mistake — a
``hasher`` that does not return 32 bytes — and swallowing it would turn a
programming error into a silent ``False``. It must still escape.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import RxdSdkError, ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

# Same opt-out as tests/test_swap_partial.py: these fixtures work in toy photon
# values, so their fees sit below the chain's relay floor by design. What is under
# test is the signature-verification branch, not fee sizing.
_TOY_FEE_POLICY = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

_REF_G = GlyphRef(txid=Txid("aa" * 32), vout=0)

#: SINGLE|ANYONECANPAY|FORKID — the only sighash an offer input may carry
#: (``swap.partial.require_offer_sighash``). The tampered signature below keeps
#: this trailing byte so the sighash pin passes and the DER parse is genuinely
#: the next thing reached.
_OFFER_SIGHASH_BYTE = 0xC3


def _unparseable_der_shapes(valid: bytes) -> list[tuple[str, bytes]]:
    """Byte strings coincurve's ``secp256k1_ecdsa_signature_parse_der`` refuses."""
    return [
        ("empty", b""),
        ("not a DER sequence", b"\xde\xad\xbe\xef"),
        ("truncated mid-signature", valid[:10]),
        ("wrong sequence tag", b"\x31" + valid[1:]),
        ("length byte lies about the body", valid[:1] + bytes([len(valid)]) + valid[2:]),
        ("all zero bytes of a plausible length", bytes(len(valid))),
    ]


def test_unparseable_der_verifies_false_rather_than_raising() -> None:
    key = PrivateKey()
    pub = key.public_key()
    message = b"the message that was signed"
    valid = key.sign(message)

    for label, bogus in _unparseable_der_shapes(valid):
        assert pub.verify(bogus, message) is False, f"{label}: expected False"
        # PrivateKey.verify delegates here, so it inherits the same contract.
        assert key.verify(bogus, message) is False, f"{label}: expected False via PrivateKey"


def test_a_valid_signature_still_verifies_true() -> None:
    """The honest path, paired with the refusal above."""
    key = PrivateKey()
    pub = key.public_key()
    message = b"the message that was signed"

    assert pub.verify(key.sign(message), message) is True
    assert key.verify(key.sign(message), message) is True


def test_a_valid_signature_over_a_different_message_still_verifies_false() -> None:
    """Well-formed DER that simply does not match must reach the real verifier.

    Without this, a fix that returned ``False`` for *everything* would pass the
    two tests above.
    """
    key = PrivateKey()
    other = PrivateKey()
    message = b"the message that was signed"
    signature = key.sign(message)

    assert key.public_key().verify(signature, b"a different message") is False
    assert other.public_key().verify(signature, message) is False


def test_a_hasher_of_the_wrong_width_still_raises() -> None:
    """The caller-mistake half: this ValueError is a bug report, not bad input.

    coincurve raises ``ValueError`` for BOTH an unparseable signature and a
    message hash that is not 32 bytes. Only the first is hostile input. A
    ``try/except ValueError`` around the whole ``key.verify`` call would swallow
    the second and hand back a silent ``False`` for a broken ``hasher``.
    """
    key = PrivateKey()
    message = b"the message that was signed"
    signature = key.sign(message)

    with pytest.raises(ValueError, match="32 bytes"):
        key.public_key().verify(signature, message, hasher=lambda _b: b"not 32 bytes")


# ───────────── the production entry point, not the mechanism ─────────────


def _ft_src(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _replace_maker_signature(offer_dict: dict, new_sig_with_flag: bytes) -> dict:
    """Swap the DER bytes in the maker's scriptSig, keeping the real pubkey push.

    The pubkey has to survive: ``_verify_owner_signature`` checks it hashes to
    the prevout owner BEFORE it verifies, so a tampered pubkey would be refused
    by the earlier gate and this test would pass for the wrong reason.
    """
    partial = Transaction.from_hex(bytes.fromhex(offer_dict["partial_tx_hex"]))
    unlocking = partial.inputs[0].unlocking_script.serialize()
    sig_len = unlocking[0]
    pubkey_push = unlocking[1 + sig_len :]
    partial.inputs[0].unlocking_script = Script(bytes([len(new_sig_with_flag)]) + new_sig_with_flag + pubkey_push)
    offer_dict["partial_tx_hex"] = partial.serialize().hex()
    return offer_dict


def _offer_with_maker_signature(new_sig_with_flag: bytes) -> tuple[dict, PrivateKey, bytes]:
    maker = PrivateKey()
    taker = PrivateKey()
    offer = create_offer(
        give_source_tx=_ft_src(maker.public_key().hash160(), _REF_G, 1000),
        give_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 800),
        maker_receive_pkh=maker.public_key().hash160(),
    )
    return _replace_maker_signature(offer.to_dict(), new_sig_with_flag), taker, taker.public_key().hash160()


def test_accept_offer_reports_an_invalid_signature_not_an_internal_bug() -> None:
    """Reached through ``accept_offer``, which is what the CLI and SDK call.

    The mechanism test above proves ``PublicKey.verify`` returns ``False``. This
    proves the production path that made the defect matter now raises an
    ``RxdSdkError`` — the class ``cli/swap_book_cmds._finish`` maps to a clean
    CLI error — rather than a bare ``ValueError`` bound for the exit-4 bug path.
    """
    # 71 rubbish bytes plus the required sighash flag: the right SHAPE for the
    # scriptSig parser and the sighash pin, and not DER.
    bogus = bytes(71) + bytes([_OFFER_SIGHASH_BYTE])
    offer_dict, taker, taker_pkh = _offer_with_maker_signature(bogus)

    with pytest.raises(ValidationError, match="signature does not validate") as excinfo:
        accept_offer(
            SwapOffer.from_dict(offer_dict),
            funding=[FundingInput(_rxd_src(taker_pkh, 2000), 0, taker)],
            taker_receive_pkh=taker_pkh,
            taker_change_pkh=taker_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )
    assert isinstance(excinfo.value, RxdSdkError)


def test_accept_offer_still_completes_an_honest_offer() -> None:
    """The honest path through the same entry point.

    ``_replace_maker_signature`` is re-applied with the maker's REAL signature,
    so this exercises the identical rebuild-and-reserialize step as the refusal
    test — if that helper corrupted the transaction, this would fail too and the
    refusal above would be passing for the wrong reason.
    """
    maker = PrivateKey()
    taker = PrivateKey()
    maker_pkh = maker.public_key().hash160()
    taker_pkh = taker.public_key().hash160()
    offer = create_offer(
        give_source_tx=_ft_src(maker_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 800),
        maker_receive_pkh=maker_pkh,
    )
    offer_dict = offer.to_dict()
    original = Transaction.from_hex(bytes.fromhex(offer_dict["partial_tx_hex"]))
    unlocking = original.inputs[0].unlocking_script.serialize()
    real_sig = unlocking[1 : 1 + unlocking[0]]
    assert real_sig[-1] == _OFFER_SIGHASH_BYTE  # the pin the bogus signature imitates

    tx = accept_offer(
        SwapOffer.from_dict(_replace_maker_signature(offer_dict, real_sig)),
        funding=[FundingInput(_rxd_src(taker_pkh, 2000), 0, taker)],
        taker_receive_pkh=taker_pkh,
        taker_change_pkh=taker_pkh,
        fee=300,
        fee_policy=_TOY_FEE_POLICY,
    )
    assert all(i.unlocking_script is not None for i in tx.inputs)
