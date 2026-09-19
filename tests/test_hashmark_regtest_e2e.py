"""Live-regtest proof that ``pyrxd mark`` publishes a record a stranger can verify.

**WHAT THE NODE ENFORCES HERE, AND WHAT IT DOES NOT.** HashMark is an ``OP_RETURN``
format. The node has NO opinion about its contents: not the magic, not the version, not
the digest width, not the label's canonicality, and above all not the signature. Every
sentence below is labelled with which side enforces it, because a regtest suite for a
data-carrier format is exactly where a reader will otherwise assume consensus is doing
work it is not. It is the same finding ``tests/test_glyph_timelock_regtest_e2e.py``
records for TIMELOCK — NOT a file in this tree: it lives on the unmerged branch
``test/timelock-lifecycle-regtest`` (commit ``f050527``). That finding — a TIMELOCK
reveal is a value-0 ``OP_RETURN`` with ``nLockTime == 0`` and no CLTV, so early, wrong-key
and duplicate reveals all relay and mine — is why this module attests in pyrxd rather than
leaning on the node. Neither is a weakness: a mark's claim is "someone knew
this digest by this block", and the block is the only part the chain has to supply.

* **NODE-ENFORCED** — that a mark transaction is standard, relays, and confirms; that it
  pays for its own size at mainnet's relay floor; that an underpaid one is refused. These
  are consensus/policy answers, read from ``testmempoolaccept`` and ``getrawtransaction``.
* **PYRXD-ENFORCED** — that the bytes decode as a v2 HashMark, that the label is
  canonical, that the signature recovers to the committed signer against THIS chain's
  genesis, and that a tampered record is rejected. The node relays all of those happily,
  and :class:`TestTheNodeHasNoOpinionAboutTheRecord` broadcasts a deliberately broken one
  to prove it rather than asserting it from the format.

The product-critical case is :class:`TestAStrangerCanVerifyFromChainBytesAlone`: the
record is fetched back with ``getrawtransaction`` and decoded and attested from THOSE
bytes, never from the :class:`~pyrxd.hashmark_tx.MarkPlan` the test built. A record that
only verifies against the object it came from is worth nothing — the reader who matters
has the transaction and the chain and nothing else.

The mark itself goes through ``pyrxd mark`` — the real click command, the real
:func:`~pyrxd.hashmark_tx.build_hashmark_mark`, the real plain-RXD UTXO selection — with
only the wallet and the ElectrumX transport swapped for adapters over the node's JSON-RPC
(the pattern ``tests/test_fee_floor_boundary_regtest_e2e.py`` uses). So what consensus
judges is what the command would actually send.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway container, no real
value, no PoW, and nothing here ever touches mainnet — the genesis assertion in
:class:`TestTheChainIsTheOneWeSignedFor` is what makes that checkable rather than claimed.

Run: ``RADIANT_REGTEST=1 pytest tests/test_hashmark_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from test_container_regtest_e2e import _confirmed, _mint_nft, _out_spk
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _biggest_utxo,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.cli.context import CliContext
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.hashmark_tx import (
    MarkPlan,
    build_hashmark_mark,
    hashmark_mark_funding_bar,
    plan_hashmark,
)
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.hashmark import (
    RADIANT_MAINNET_GENESIS,
    decode_hashmark,
    max_label_bytes,
    verify_attestation,
)
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

#: Radiant's relay floor per byte — what the node fixture is started at, and what the CLI
#: defaults to. Asserted equal to the node's own answer before anything is proved.
_MIN_FEE_RATE = 10_000

#: Plain RXD parked on the funding UTXO for a mark. Comfortably over the funding bar
#: (~3.0-3.9 M photons at the floor) with change left over, so the no-change branch is not
#: what every case here exercises by accident.
_FUND = 100_000_000

REGTEST_GENESIS = GENESIS_BLOCK_HASHES["regtest"]


# --------------------------------------------------------------------------- adapters


class _NodeRefused(Exception):
    """The node's verdict on bytes the builder returned, raised where the CLI broadcasts."""


class _NodeClient:
    """The slice of ``ElectrumXClient`` the mark path uses, over the regtest node.

    ``get_transaction`` reads real bytes back off the chain — which is what makes
    ``find_plain_rxd_utxo``'s "is this output really a bare P2PKH" check a question about
    the chain rather than about the fixture — and ``broadcast`` asks
    ``testmempoolaccept`` first so the node's verdict is recorded even when it is a yes.
    """

    def __init__(self, rt: _RegtestNode) -> None:
        self.node = rt
        self.verdict: dict = {}

    async def __aenter__(self) -> _NodeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get_transaction(self, txid: object) -> bytes:
        return bytes.fromhex(str(self.node.cli("getrawtransaction", str(txid))))

    async def broadcast(self, raw: bytes) -> str:
        self.verdict = self.node.accepts(raw.hex())
        if self.verdict.get("allowed") is not True:
            raise _NodeRefused(f"node refused: {self.verdict}")
        return str(self.node.cli("sendrawtransaction", raw.hex()))


class _NodeWallet:
    """The three methods ``pyrxd mark`` asks a wallet for, over one funded UTXO.

    ``derive_address``/``privkey_for`` return a FIXED signing key for 0/0 and a different
    one elsewhere, so a test asserting on the committed signer is asserting about the path
    the command chose rather than about a stub that answers the same either way.
    """

    def __init__(self, triples, signer: PrivateKey) -> None:
        self._triples = triples
        self._signer = signer
        self._other = PrivateKey()

    async def collect_spendable(self, _client):
        return self._triples

    def derive_address(self, change: int, index: int) -> str:
        return (self._signer if (change, index) == (0, 0) else self._other).address()

    def privkey_for(self, change: int, index: int) -> PrivateKey:
        return self._signer if (change, index) == (0, 0) else self._other

    def privkey_for_address(self, address: str) -> PrivateKey:
        for key in (self._signer, self._other):
            if key.address() == address:
                return key
        raise ValueError(f"address {address} is not known to this wallet")


def _fund(rt: _RegtestNode, key: PrivateKey, amount: int = _FUND):
    """Put ``amount`` plain RXD on a fresh P2PKH output and return its UTXO triple."""
    spk = bytes(P2PKH().lock(key.public_key().address()).serialize())
    txid = _pay_to_spk(rt, spk, amount)
    return [(UtxoRecord(tx_hash=txid, tx_pos=0, value=amount, height=1), key.public_key().address(), key)]


def _mark_via_cli(rt: _RegtestNode, tmp_path: Path, monkeypatch, *, content: bytes, label: str | None = None):
    """Run the real ``pyrxd mark`` against the node. Returns ``(payload, client, signer)``.

    ``--network regtest`` is not cosmetic: the genesis hash is inside the signed statement,
    so this is what decides WHICH CHAIN the record makes its claim about.
    """
    from click.testing import CliRunner

    import pyrxd.cli.hashmark_cmds as hc
    from pyrxd.cli.main import cli

    signer = PrivateKey()
    wallet = _NodeWallet(_fund(rt, PrivateKey()), signer)
    client = _NodeClient(rt)
    target = tmp_path / "advisory.txt"
    target.write_bytes(content)

    monkeypatch.setattr(hc, "_load_wallet", lambda ctx, **kw: wallet)
    monkeypatch.setattr(CliContext, "make_client", lambda self: client)
    result = CliRunner().invoke(
        cli,
        [
            "--wallet",
            str(tmp_path / "w.dat"),
            "--network",
            "regtest",
            "--json",
            "--yes",
            "mark",
            str(target),
            *(["--label", label] if label is not None else []),
        ],
    )
    assert result.exit_code == 0, result.output
    rt.mine(1)
    return json.loads(result.stdout), client, signer


def _record_from_chain(rt: _RegtestNode, txid: str):
    """Decode the HashMark out of the CONFIRMED transaction, as a stranger would.

    Goes back to ``getrawtransaction`` rather than reusing anything the test built. The
    output index is FOUND by decoding, not assumed, because "output 0 is the record" is
    the builder's convention and a verifier does not have it.
    """
    confirmed = _confirmed(rt, txid)
    for i in range(len(confirmed["vout"])):
        record = decode_hashmark(_out_spk(confirmed, i))
        if record.ok:
            return i, _out_spk(confirmed, i), record
    raise AssertionError(f"no HashMark record in any output of {txid}")


def _funded_tx(rt: _RegtestNode, script: bytes, *, fee: int) -> Transaction:
    """A hand-built mark-shaped transaction at an exact fee, for the controls.

    Hand-built precisely because the production builder REFUSES to underpay: the point of
    the control is the node's answer to bytes pyrxd would not produce.
    """
    u = _biggest_utxo(rt)
    key = PrivateKey(str(rt.cli("dumpprivkey", u["address"], wallet=True)))
    pkh = bytes(Hex20(key.public_key().hash160()))
    in_sats = round(u["amount"] * 1e8)
    fin = TransactionInput(
        source_transaction=_src(u["txid"], u["vout"], bytes.fromhex(u["scriptPubKey"]), in_sats),
        source_txid=u["txid"],
        source_output_index=u["vout"],
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(bytes.fromhex(u["scriptPubKey"]))
    tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[
            TransactionOutput(Script(script), 0),
            TransactionOutput(Script(b"\x76\xa9\x14" + pkh + b"\x88\xac"), in_sats - fee),
        ],
    )
    tx.sign()
    return tx


# --------------------------------------------------------------------------- 0. controls


class TestTheChainIsTheOneWeSignedFor:
    """NODE-MEASURED. Nothing below means anything if these two disagree."""

    def test_the_regtest_genesis_constant_is_this_nodes_own_genesis(self, node) -> None:  # noqa: F811
        """A known answer, asked of the node.

        ``GENESIS_BLOCK_HASHES["regtest"]`` is what ``pyrxd mark --network regtest`` puts
        INSIDE the signature, and it is not carried by the record — so if the constant were
        wrong, every mark here would verify against the constant, fail for a real verifier,
        and no other assertion in this file could tell. It is also the one line that proves
        this suite is not on mainnet.
        """
        assert str(node.cli("getblockhash", "0")) == REGTEST_GENESIS
        assert REGTEST_GENESIS != RADIANT_MAINNET_GENESIS
        assert node.cli("getblockchaininfo")["chain"] == "regtest"

    def test_the_node_is_at_mainnets_relay_floor(self, node) -> None:  # noqa: F811
        """A fee proved against a node at a tenth of mainnet's floor proves nothing."""
        assert node.relay_rate() == _MIN_FEE_RATE


# --------------------------------------------------------------------------- 1. the mark


@pytest.fixture(scope="module")
def marked(node, tmp_path_factory, request):  # noqa: F811
    """One labelled mark, published through the CLI and mined. Shared by the read cases."""
    monkeypatch = pytest.MonkeyPatch()
    request.addfinalizer(monkeypatch.undo)
    payload, client, signer = _mark_via_cli(
        node,
        tmp_path_factory.mktemp("marked"),
        monkeypatch,
        content=b"advisory: the fee bar was flat, and it under-paid 25% of transfers\n",
        label="pyrxd advisory 2026-09",
    )
    return {"payload": payload, "client": client, "signer": signer}


class TestTheMarkIsAcceptedByTheNode:
    def test_the_transaction_relayed_and_confirmed(self, node, marked) -> None:  # noqa: F811
        """NODE-ENFORCED: relay policy and consensus. The node was asked
        ``testmempoolaccept`` before the send, so ``allowed`` is its own verdict."""
        assert marked["client"].verdict.get("allowed") is True, marked["client"].verdict
        confirmed = _confirmed(node, marked["payload"]["txid"])
        assert confirmed["confirmations"] >= 1
        print(f"\nmark txid {marked['payload']['txid']} confirmed, fee {marked['payload']['fee']:,} photons")

    def test_the_record_is_output_zero_at_value_zero(self, node, marked) -> None:  # noqa: F811
        confirmed = _confirmed(node, marked["payload"]["txid"])
        assert confirmed["vout"][0]["value"] == 0
        assert _out_spk(confirmed, 0)[0] == 0x6A, "output 0 must be the OP_RETURN"
        assert len(confirmed["vout"]) == 2, "one record, one change output"

    def test_the_fee_covers_the_transactions_real_size_at_the_floor(self, node, marked) -> None:  # noqa: F811
        """NODE-ENFORCED that it relayed at all; measured here so the number is on record."""
        raw = bytes.fromhex(str(node.cli("getrawtransaction", marked["payload"]["txid"])))
        assert marked["payload"]["fee"] >= len(raw) * _MIN_FEE_RATE
        print(
            f"mark tx {len(raw)} B, record {marked['payload']['record_bytes']} B, "
            f"fee {marked['payload']['fee']:,} photons at {_MIN_FEE_RATE:,}/B"
        )

    def test_every_input_it_spent_was_a_bare_p2pkh_on_chain(self, node, marked) -> None:  # noqa: F811
        """A property of the published transaction, read back off the chain.

        NOT a test of ``find_plain_rxd_utxo``: this wallet holds nothing but plain RXD, so
        it would pass with that guard disabled — measured, by replacing the guard's
        condition with ``True``. :class:`TestTheMarkNeverSpendsAToken` is the
        non-vacuous one; this is here because a mark that spent something exotic would be
        worth knowing about however it got there.
        """
        confirmed = _confirmed(node, marked["payload"]["txid"])
        for vin in confirmed["vin"]:
            parent = _confirmed(node, vin["txid"])
            spk = _out_spk(parent, vin["vout"])
            assert len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac", (
                f"the mark spent a non-P2PKH output: {spk.hex()}"
            )


class TestTheMarkNeverSpendsAToken:
    """PYRXD-ENFORCED, against a REAL minted singleton sitting on this chain.

    The node would happily relay a mark funded by burning an NFT — consensus has no
    opinion about why an output was spent — so the only thing between an operator and a
    destroyed token is ``find_plain_rxd_utxo`` checking each candidate's ON-CHAIN script.
    The token here is minted, mined, and deliberately FATTER than the plain UTXO, because
    selection is value-descending: it is the first candidate the builder looks at.
    """

    def test_a_minted_nft_is_passed_over_and_survives_the_mark(self, node) -> None:  # noqa: F811
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

        token = _mint_nft(node, GlyphMetadata(protocol=[GlyphProtocol.NFT], name="REGTEST-NOT-FEE"))
        assert token["value"] > _FUND, "the token must outrank the plain UTXO, or this proves nothing"

        signer = PrivateKey()
        plain = _fund(node, PrivateKey())
        triples = [
            (
                UtxoRecord(tx_hash=token["reveal_txid"], tx_pos=token["vout"], value=token["value"], height=1),
                token["key"].public_key().address(),
                token["key"],
            ),
            *plain,
        ]
        client = _NodeClient(node)
        plan = plan_hashmark(hashlib.sha256(b"not the token").digest(), signer, network_genesis=REGTEST_GENESIS)
        build = asyncio.run(
            build_hashmark_mark(_NodeWallet(triples, signer), plan, client=client, fee_rate=_MIN_FEE_RATE)
        )

        spent = {(i.source_txid, i.source_output_index) for i in build.tx.inputs}
        assert spent == {(plain[0][0].tx_hash, plain[0][0].tx_pos)}
        assert (token["reveal_txid"], token["vout"]) not in spent

        txid = asyncio.run(client.broadcast(build.serialize()))
        node.mine(1)
        assert _confirmed(node, txid)["confirmations"] >= 1
        # And the token is still there — the strongest form of "it was not spent".
        assert node.cli("gettxout", token["reveal_txid"], str(token["vout"])), (
            "the singleton was consumed by a mark about a different thing entirely"
        )
        print(f"\nNFT {token['value']:,} photons passed over; mark funded from {_FUND:,}-photon plain UTXO")


class TestAStrangerCanVerifyFromChainBytesAlone:
    """The product-critical case, and the only one whose inputs are all node-supplied."""

    def test_the_record_decodes_out_of_the_confirmed_transaction(self, node, marked) -> None:  # noqa: F811
        """PYRXD-ENFORCED (the node has no opinion about the contents), on NODE-SUPPLIED
        bytes: nothing here comes from the plan the command built."""
        vout, script, record = _record_from_chain(node, marked["payload"]["txid"])
        assert vout == 0
        assert record.ok and record.version == 2 and record.algorithm == "sha256"
        assert (
            record.digest_hex
            == hashlib.sha256(b"advisory: the fee bar was flat, and it under-paid 25% of transfers\n").hexdigest()
        )
        assert record.label == "pyrxd advisory 2026-09"
        assert len(script) == marked["payload"]["record_bytes"]

    def test_the_signature_attests_against_this_chains_genesis(self, node, marked) -> None:  # noqa: F811
        """PYRXD-ENFORCED. The genesis comes from the node, not from the constant, so this
        is the verdict a stranger who asked this chain what it is would compute."""
        _vout, _script, record = _record_from_chain(node, marked["payload"]["txid"])
        chain_genesis = str(node.cli("getblockhash", "0"))
        verdict = verify_attestation(record, network_genesis=chain_genesis)
        assert verdict.valid, verdict
        assert verdict.recovered_hash160_hex == record.signer_hash160_hex
        signer = marked["signer"]
        assert verdict.recovered_hash160_hex == signer.public_key().hash160(signer.compressed).hex()

    def test_the_same_bytes_do_not_verify_as_a_mainnet_statement(self, node, marked) -> None:  # noqa: F811
        """The chain binding is real and is NOT in the record.

        Paired with the case above deliberately: without it, "it verified" would be equally
        true of an implementation that ignored the genesis entirely.
        """
        _vout, _script, record = _record_from_chain(node, marked["payload"]["txid"])
        assert not verify_attestation(record, network_genesis=RADIANT_MAINNET_GENESIS).valid

    def test_the_block_is_what_fixes_the_time(self, node, marked) -> None:  # noqa: F811
        """A mark's whole claim is "no later than this block", so the height has to be
        recoverable from the transaction a verifier already has."""
        confirmed = _confirmed(node, marked["payload"]["txid"])
        header = node.cli("getblockheader", confirmed["blockhash"])
        assert isinstance(header, dict) and header["height"] >= 101
        print(f"mark anchored at height {header['height']}")


class TestTheCeilingIsReal:
    def test_a_223_byte_record_relays_and_confirms(self, node, tmp_path, monkeypatch) -> None:  # noqa: F811
        """NODE-ENFORCED. §3.2's 223 is the largest record the encoder will emit, and a
        ceiling nobody has broadcast at is a number in a document."""
        label = "x" * max_label_bytes()
        payload, client, _signer = _mark_via_cli(node, tmp_path, monkeypatch, content=b"at the ceiling", label=label)
        assert payload["record_bytes"] == 223
        assert client.verdict.get("allowed") is True, client.verdict
        _vout, script, record = _record_from_chain(node, payload["txid"])
        assert len(script) == 223
        assert record.label == label
        # Genesis from the NODE, not from the constant. Attesting against the same constant
        # the command signed with is circular: a wrong constant would satisfy both sides and
        # this case would stay green — measured, by planting one wrong nibble in
        # GENESIS_BLOCK_HASHES["regtest"] and watching only the node-sourced cases fail.
        assert verify_attestation(record, network_genesis=str(node.cli("getblockhash", "0"))).valid
        print(f"\n223-byte record relayed: {payload['txid']}")

    def test_an_unlabelled_record_is_the_specs_133_bytes(self, node, tmp_path, monkeypatch) -> None:  # noqa: F811
        payload, client, _signer = _mark_via_cli(node, tmp_path, monkeypatch, content=b"no label")
        assert payload["record_bytes"] == 133
        assert client.verdict.get("allowed") is True, client.verdict
        assert _record_from_chain(node, payload["txid"])[2].label is None


# --------------------------------------------------------------------------- 2. negatives


class TestTheNodeHasNoOpinionAboutTheRecord:
    """Broadcast the broken thing and watch it confirm, rather than asserting it.

    This is the section that stops the rest of the file being read as "consensus checks
    HashMark". It does not. A forged record is a permanent, relayable lie, and the only
    thing standing between a reader and believing it is ``verify_attestation``.
    """

    def test_a_tampered_record_is_relayed_and_mined_and_does_not_verify(
        self,
        node,  # noqa: F811
        tmp_path,
        monkeypatch,
    ) -> None:
        payload, _client, _signer = _mark_via_cli(node, tmp_path, monkeypatch, content=b"honest", label="honest")
        _vout, honest, record = _record_from_chain(node, payload["txid"])

        # Flip one bit of the DIGEST, not of the signature, and the choice is load-bearing.
        # A bit flipped in the signature refuses for whichever check happens to trip first
        # — an out-of-range r, a non-low s, a point that will not recover — and WHICH of
        # those fires depends on the key, so a bit-flipped signature refuses for a
        # different reason on each run. Measured: with the recovered-key-versus-commitment
        # comparison deleted from `verify_attestation`, a signature flip still refused
        # (recovery failed on that run) and this case passed with the check GONE.
        # A flipped digest cannot do that. The record stays perfectly well-formed, the
        # signature stays a valid signature, the statement it covers simply changes — so
        # recovery succeeds and yields a DIFFERENT key, and the commitment comparison is
        # the only thing that can refuse it. It is also the forgery that matters: this is
        # someone claiming the mark was about a different file.
        forged = bytearray(honest)
        # The digest push runs 14..45: OP_RETURN, the 9-byte magic push, the 3-byte
        # header push, then 0x20 and the 32 bytes. Asserted below rather than trusted.
        forged[20] ^= 0x01
        forged_record = decode_hashmark(bytes(forged))
        assert forged_record.ok, "must stay WELL-FORMED, or this tests the decoder"
        assert forged_record.digest_hex != record.digest_hex
        assert forged_record.signature_hex == record.signature_hex, "the signature bytes are untouched"
        verdict = verify_attestation(forged_record, network_genesis=REGTEST_GENESIS)
        assert not verdict.valid
        assert verdict.detail == "recovered key does not match the committed signer", verdict

        tx = _funded_tx(node, bytes(forged), fee=20_000_000)
        verdict = node.accepts(tx.serialize().hex())
        assert verdict.get("allowed") is True, f"NODE-MEASURED claim: the node takes it. {verdict}"
        txid = str(node.cli("sendrawtransaction", tx.serialize().hex()))
        node.mine(1)

        # And it is on chain, indistinguishable to the node from the honest one above.
        _v, on_chain, mined = _record_from_chain(node, txid)
        assert on_chain == bytes(forged)
        assert mined.ok, "the decoder calls it well-formed — only attestation refuses it"
        assert not verify_attestation(mined, network_genesis=str(node.cli("getblockhash", "0"))).valid
        print(f"\nforged record MINED at {txid}: node allowed={verdict.get('allowed')}, attestation=INVALID")

    def test_the_forged_record_could_not_have_been_built_by_the_production_path(self) -> None:
        """PYRXD-ENFORCED, and the reason the case above needed a hand-built transaction.

        ``MarkPlan`` decodes and attests its own bytes, so those forged bytes cannot reach
        ``build_hashmark_mark`` at all — the only way onto the chain was around pyrxd.
        """
        from pyrxd.security.errors import ValidationError

        plan = plan_hashmark(hashlib.sha256(b"honest").digest(), PrivateKey(), network_genesis=REGTEST_GENESIS)
        forged = bytearray(plan.op_return_script)
        forged[20] ^= 0x01  # the digest again, for the reason the case above gives
        with pytest.raises(ValidationError, match="signature does not verify"):
            MarkPlan(op_return_script=bytes(forged), network_genesis=REGTEST_GENESIS)


class TestTheNodeCanSayNo:
    """Every "the node accepted it" above is worth exactly as much as this.

    A ``testmempoolaccept`` that returned ``allowed`` for everything — a node started
    without a policy, a verdict read off the wrong key — would make this whole file green
    and meaningless, and nothing in the output would look wrong.
    """

    def test_an_underpaid_mark_is_refused_with_the_fee_reason(self, node) -> None:  # noqa: F811
        """NODE-ENFORCED. Converged by re-signing rather than computed once: a DER
        signature is 70-72 bytes, so aiming at ``size * rate - 1`` from a trial signing
        lands ABOVE the floor whenever the next signature comes out shorter, and an
        overpaid transaction the node then accepts would invert this control without
        changing how it reads."""
        plan = plan_hashmark(hashlib.sha256(b"underpaid").digest(), PrivateKey(), network_genesis=REGTEST_GENESIS)
        rate = node.relay_rate()
        fee = 20_000_000
        for _ in range(8):
            tx = _funded_tx(node, plan.op_return_script, fee=fee)
            raw = tx.serialize()
            if fee < len(raw) * rate:
                break
            fee = len(raw) * rate - 1
        else:  # pragma: no cover - the loop reaches its fixed point in one correction
            raise AssertionError("could not build a mark under the node's floor")
        verdict = node.accepts(raw.hex())
        assert verdict.get("allowed") is not True, verdict
        assert "min relay fee not met" in str(verdict.get("reject-reason", "")), verdict
        print(f"\nunderpaid mark ({fee:,} photons for {len(raw)} B at {rate:,}/B) -> {verdict.get('reject-reason')}")

    def test_the_same_record_one_photon_over_the_floor_is_accepted(self, node) -> None:  # noqa: F811
        """The honest half. A control that refused everything would be as useless as one
        that accepted everything."""
        plan = plan_hashmark(hashlib.sha256(b"paid").digest(), PrivateKey(), network_genesis=REGTEST_GENESIS)
        rate = node.relay_rate()
        fee = 20_000_000
        for _ in range(4):
            tx = _funded_tx(node, plan.op_return_script, fee=fee)
            raw = tx.serialize()
            if fee >= len(raw) * rate:
                break
            fee = len(raw) * rate
        verdict = node.accepts(raw.hex())
        assert verdict.get("allowed") is True, verdict


class TestTheFundingBarAgreesWithTheNode:
    def test_at_the_bar_the_builder_produces_bytes_the_node_accepts(self, node) -> None:  # noqa: F811
        """Both halves against one node. A bar that admitted funding the node refuses is
        the original fund-safety bug; a bar that refuses funding the node would have taken
        is its own."""
        from pyrxd.glyph.transfer import NoFeeFundingError

        signer = PrivateKey()
        probe = plan_hashmark(hashlib.sha256(b"bar").digest(), signer, network_genesis=REGTEST_GENESIS)
        bar = hashmark_mark_funding_bar(probe.op_return_script, _MIN_FEE_RATE)
        assert node.relay_rate() == _MIN_FEE_RATE, "not at the mainnet floor; this proves nothing"
        print(f"\nmark funding bar at {_MIN_FEE_RATE:,} photons/B: {bar:,} photons")

        client = _NodeClient(node)
        at = _NodeWallet(_fund(node, PrivateKey(), bar), signer)
        build = asyncio.run(build_hashmark_mark(at, probe, client=client, fee_rate=_MIN_FEE_RATE))
        verdict = node.accepts(build.serialize().hex())
        assert verdict.get("allowed") is True, f"the builder's own bar produced bytes the node refuses: {verdict}"

        under = _NodeWallet(_fund(node, PrivateKey(), bar - 1), signer)
        with pytest.raises(NoFeeFundingError, match="no plain-RXD UTXO large enough"):
            asyncio.run(build_hashmark_mark(under, probe, client=_NodeClient(node), fee_rate=_MIN_FEE_RATE))


def test_nothing_in_this_file_touched_anything_but_regtest(node) -> None:  # noqa: F811
    """Belt and braces, in an assertion that can fail."""
    assert node.cli("getblockchaininfo")["chain"] == "regtest"
    assert str(node.cli("getblockhash", "0")) == REGTEST_GENESIS
