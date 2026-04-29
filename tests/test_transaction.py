import pytest

from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
# pytest is used by the additional hardening tests below


def test_init_transaction():
    tx_hex = "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
    transaction = Transaction.from_hex(tx_hex)

    assert transaction is not None

    inputs = transaction.inputs
    assert len(inputs) == 2

    input_0 = inputs[0]
    assert input_0 is not None

    assert input_0.source_txid == "3f36d1e82cd2f327970c84cbf0d4e4d116f9a15dd02259329ac40d7b6a018d9e"
    assert input_0.source_output_index == 0
    assert input_0.unlocking_script.byte_length() == 0x8C
    assert (
        input_0.unlocking_script.hex()
        == "493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2"
    )
    assert input_0.sequence == 4294967295

    input_1 = inputs[1]
    assert input_1 is not None

    assert input_1.source_txid == "6f653a93e7ff01c3317ee9eb9b75c85d4881684f8117f73f4765b61a7a5e19a3"
    assert input_1.source_output_index == 2
    assert input_1.unlocking_script.byte_length() == 0x8B
    assert (
        input_1.unlocking_script.hex()
        == "48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442"
    )
    assert input_1.sequence == 4294967295


    outputs = transaction.outputs
    assert len(outputs) == 2

    output_0 = outputs[0]
    assert output_0 is not None

    assert output_0.satoshis == 1076000
    assert output_0.locking_script.byte_length() == 25
    assert output_0.locking_script.hex() == "76a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"

    output_1 = outputs[1]
    assert output_1 is not None

    assert output_1.satoshis == 117488
    assert output_1.locking_script.byte_length() == 25
    assert output_1.locking_script.hex() == "76a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac"

def test_coinbase_transaction():
    tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff63038d361604747a77610840000000230000004e2f686f77206c6f6e672063616e207468697320626520746573742074657374206170706172656e746c7920707265747479206c6f6e67206f6b20776f772031323334353637383930313220f09fa68d2f0000000001c817a804000000001976a91454b34b1ba228ba1d75dca5a40a114dc0f13a268788ac00000000"
    transaction = Transaction.from_hex(tx_hex)

    assert transaction is not None
    assert transaction.is_coinbase()  

def test_malformed_transaction():
    tx_hex = "FAKE01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
    transaction = Transaction.from_hex(tx_hex)

    assert transaction is None


# ── Additional hardening tests ────────────────────────────────────────────────

_KNOWN_TX_HEX = (
    "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f0000000"
    "08c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022"
    "100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46"
    "d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00"
    "fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc87"
    "59bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f0"
    "7ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91"
    "da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb"
    "8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206"
    "b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001"
    "976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
)


def test_transaction_round_trip():
    """Parse a known transaction hex, re-serialize, and assert the bytes match."""
    # Build canonical hex (remove whitespace from the multiline constant above)
    tx_hex = _KNOWN_TX_HEX.replace("\n", "").replace(" ", "")
    tx = Transaction.from_hex(tx_hex)
    assert tx is not None
    assert tx.serialize().hex() == tx_hex


def test_transaction_preimage_index_out_of_range():
    """Transaction.preimage() must raise ValueError for an out-of-range index."""
    tx = Transaction.from_hex(_KNOWN_TX_HEX.replace("\n", "").replace(" ", ""))
    assert tx is not None
    with pytest.raises(ValueError, match="index out of range"):
        tx.preimage(99)


def test_truncated_hex_returns_none():
    """Truncated transaction hex must return None from from_hex() (not crash)."""
    truncated = _KNOWN_TX_HEX[:40].replace("\n", "").replace(" ", "")
    result = Transaction.from_hex(truncated)
    assert result is None


def test_empty_hex_returns_none():
    """Empty string must return None from from_hex()."""
    result = Transaction.from_hex("")
    assert result is None
