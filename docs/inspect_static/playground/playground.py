"""The Radiant Playground's sandbox chain, and the code that runs a visitor's program.

WHAT THIS IS. A chain that lives in one browser tab. pyrxd builds and signs real Radiant
transactions in that tab; :meth:`SandboxChain.submit` decides whether to accept them and
mines a block when it does. There is no node behind it and nothing leaves the tab: the
page's ``connect-src`` names no node at all.

WHAT IT CHECKS, which is exactly the list in :data:`RULES` and nothing more. The page shows
that list beside every transaction, so a visitor never has to guess what "accepted" meant:

* the bytes parse and re-serialise to themselves;
* every input exists and is unspent, and no input is spent twice;
* outputs do not spend more than the inputs bring in;
* the fee is at least pyrxd's relay floor for the transaction's size
  (``pyrxd.fee_sizing.min_relay_fee``, the mainnet floor);
* plain P2PKH, Glyph NFT and Glyph FT inputs carry a valid signature by the owning key,
  over the preimage pyrxd signs (``SIGHASH_ALL | FORKID`` only);
* Glyph commit inputs reveal a payload whose hash the commit locked, and produce an
  output holding the new token with the ref type the commit demands;
* the ref rules: every ref an output pushes with ``OP_PUSHINPUTREF`` or
  ``OP_PUSHINPUTREFSINGLETON`` comes from an input (its outpoint, or a ref an input's
  script pushes), and a singleton ref lands in at most one output;
* Glyph FT conservation: per token, the FT outputs hold no more units than the FT inputs.

WHAT IT DOES NOT DO. It does not run Radiant's script interpreter. A script it does not
recognise is ACCEPTED WITH A WARNING that says its input was not evaluated, so a covenant
experiment is never reported as "valid". Faucet coins spend at once (a real node makes a
miner wait 100 blocks). Timelocks are not enforced. The node is the authority on all of
this; ``pyrxd regtest up`` gives you one.

The ref and FT rules here are the sandbox's own statement of them, written from pyrxd's
docstrings (``pyrxd.glyph.script.script_carries_ref``,
``pyrxd.transaction.transaction_preimage._get_push_refs``,
``pyrxd.glyph.script.build_ft_locking_script``), not from Radiant-Core. Nothing here should
be cited as what consensus does.

This module is plain Python. ``tests/web/test_playground_sandbox.py`` runs it under CPython
with the real coincurve; the page runs it under Pyodide with ``sandbox_curve`` standing in.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import hashlib
import hmac
import io
import sys
import traceback
import types
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Runtime preparation (Pyodide only; harmless and skipped under CPython)
# ---------------------------------------------------------------------------


def _pbkdf2_hmac_pure(hash_name: str, password: bytes, salt: bytes, iterations: int, dklen: int | None = None) -> bytes:
    """``hashlib.pbkdf2_hmac`` for a Python built without OpenSSL.

    Python 3.12 dropped its pure-Python fallback, and Pyodide's ``hashlib`` (without the
    OpenSSL package the inspect pages deliberately do not load, #757) has none, so
    ``pyrxd.hd.bip39`` cannot import. RFC 8018 §5.2, checked against CPython's own
    ``pbkdf2_hmac`` in ``tests/web/test_playground_sandbox.py``.
    """
    digest_size = hashlib.new(hash_name).digest_size
    dklen = dklen or digest_size
    blocks = []
    i = 1
    while len(b"".join(blocks)) < dklen:
        u = hmac.new(password, salt + i.to_bytes(4, "big"), hash_name).digest()
        acc = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hash_name).digest()
            acc ^= int.from_bytes(u, "big")
        blocks.append(acc.to_bytes(digest_size, "big"))
        i += 1
    return b"".join(blocks)[:dklen]


class _NoNetwork(types.ModuleType):
    """Stands in for ``aiohttp`` / ``websockets``, which pyrxd imports but the sandbox never uses."""

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        return type(name, (Exception,), {"__module__": self.__name__})


def prepare_runtime() -> list[str]:
    """Make ``pyrxd.keys``, ``pyrxd.hd`` and ``pyrxd.glyph.mint`` importable under Pyodide.

    Returns what it changed, so the page can print it in its runtime footer.
    """
    changed: list[str] = []
    try:
        import coincurve  # noqa: F401
    except ImportError:
        import sandbox_curve

        sandbox_curve.install()
        changed.append("secp256k1: sandbox_curve (pure Python, playground only)")
    if not hasattr(hashlib, "pbkdf2_hmac"):
        hashlib.pbkdf2_hmac = _pbkdf2_hmac_pure  # type: ignore[attr-defined]
        changed.append("pbkdf2_hmac: pure Python")
    for name in ("aiohttp", "websockets", "websockets.exceptions"):
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = _NoNetwork(name)
            changed.append(f"{name}: absent (the sandbox has no network)")
    try:
        import Cryptodome  # noqa: F401
    except ImportError:
        try:
            import Crypto
            import Crypto.Cipher

            sys.modules["Cryptodome"] = Crypto
            sys.modules["Cryptodome.Cipher"] = Crypto.Cipher
            changed.append("Cryptodome: aliased to Crypto")
        except ImportError:
            pass
    return changed


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------

SIGHASH_ALL_FORKID = 0x41
FAUCET_LIMIT_PHOTONS = 1_000 * 100_000_000

#: The checks :meth:`SandboxChain.submit` runs, in order. The page prints these.
RULES: tuple[tuple[str, str], ...] = (
    ("parse", "The bytes are one well-formed transaction."),
    ("inputs", "Every input exists, is unspent, and is spent once."),
    ("value", "Outputs spend no more than the inputs bring in."),
    ("fee", "The fee meets the relay floor for the transaction's size."),
    ("scripts", "Each P2PKH, Glyph NFT, Glyph FT and Glyph commit input is unlocked correctly."),
    ("refs", "Every ref an output holds comes from an input; a singleton's ref is in one output only."),
    (
        "ft",
        "A Glyph FT's outputs hold no more units than its inputs (a deploy mints its supply once; a "
        "contract the sandbox does not run may mint more, with a warning), and when an FT is spent, "
        "every output that pushes its ref is an FT output.",
    ),
)


class SandboxRejected(Exception):
    """The sandbox refused a transaction. ``rule`` is a key of :data:`RULES`."""

    def __init__(self, rule: str, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.rule = rule
        self.hint = hint


@dataclass
class Coin:
    """One unspent output, with the transaction that created it."""

    txid: str
    vout: int
    value: int
    script: bytes
    tx: object  # pyrxd.transaction.Transaction
    height: int

    @property
    def outpoint(self) -> str:
        return f"{self.txid}:{self.vout}"


@dataclass
class Check:
    rule: str
    status: str  # "pass" | "warn" | "fail"
    detail: str


@dataclass
class Accepted:
    txid: str
    raw: bytes
    height: int
    checks: list[Check]
    spent: list[Coin]
    faucet: bool = False


@dataclass
class Block:
    height: int
    txids: list[str] = field(default_factory=list)


def _p2pkh_pkh(script: bytes) -> bytes | None:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return script[3:23]
    return None


def _split_pushes(script: bytes) -> list[bytes] | None:
    """The data of a push-only script, or ``None`` if it is anything else."""
    from pyrxd.script.consensus import iter_script_ops

    pushes: list[bytes] = []
    end = 0
    for op in iter_script_ops(script):
        if op.opcode > 0x4E and op.opcode != 0x00:
            return None
        pushes.append(op.operand)
        end = op.next_pos
    if end != len(script):
        return None
    return pushes


class SandboxChain:
    def __init__(self) -> None:
        self.height = 0
        self.blocks: list[Block] = [Block(0, [])]
        self.utxos: dict[tuple[str, int], Coin] = {}
        self.spent_by: dict[tuple[str, int], str] = {}
        self.accepted: dict[str, Accepted] = {}
        self.order: list[str] = []
        self._faucet_n = 0

    # -- blocks ------------------------------------------------------------

    def mine(self, n: int = 1) -> int:
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 10_000:
            raise ValueError("mine() takes a whole number of blocks from 1 to 10,000")
        for _ in range(n):
            self.height += 1
            self.blocks.append(Block(self.height, []))
        return self.height

    def _confirm(self, txid: str) -> int:
        self.mine(1)
        self.blocks[-1].txids.append(txid)
        self.accepted[txid].height = self.height
        for coin in self.utxos.values():
            if coin.txid == txid:
                coin.height = self.height
        return self.height

    # -- faucet ------------------------------------------------------------

    def fund(self, address: str, photons: int) -> Coin:
        """Pay ``photons`` to ``address`` from nowhere, in a new block. Sandbox only."""
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        if not isinstance(photons, int) or isinstance(photons, bool) or not 0 < photons <= FAUCET_LIMIT_PHOTONS:
            raise ValueError(f"the faucet pays 1 to {FAUCET_LIMIT_PHOTONS:,} photons at a time")
        self._faucet_n += 1
        tag = (self.height + 1).to_bytes(4, "little") + self._faucet_n.to_bytes(4, "little")
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_txid="00" * 32,
                    source_output_index=0xFFFFFFFF,
                    unlocking_script=Script(b"\x08" + tag),
                )
            ],
            tx_outputs=[TransactionOutput(P2PKH().lock(address), photons)],
        )
        raw = tx.serialize()
        txid = tx.txid()
        self.utxos[(txid, 0)] = Coin(txid, 0, photons, tx.outputs[0].locking_script.serialize(), tx, 0)
        self.accepted[txid] = Accepted(
            txid, raw, 0, [Check("faucet", "pass", f"faucet paid {photons:,} photons")], [], faucet=True
        )
        self.order.append(txid)
        self._confirm(txid)
        return self.utxos[(txid, 0)]

    # -- queries -----------------------------------------------------------

    def coins_for_script(self, script: bytes) -> list[Coin]:
        return [c for c in self.utxos.values() if c.script == script]

    def confirmations(self, txid: str) -> int:
        acc = self.accepted.get(txid)
        if acc is None or acc.height == 0:
            return 0
        return self.height - acc.height + 1

    # -- the mempool rules -------------------------------------------------

    def submit(self, raw: bytes) -> Accepted:
        """Check ``raw`` against :data:`RULES`; accept and mine it, or raise :class:`SandboxRejected`."""
        from pyrxd.fee_sizing import min_relay_fee, radiant_relay_size
        from pyrxd.transaction.transaction import Transaction

        if isinstance(raw, str):
            try:
                raw = bytes.fromhex(raw)
            except ValueError:
                raise SandboxRejected("parse", "that is not hex") from None
        if not isinstance(raw, (bytes, bytearray)):
            raise SandboxRejected("parse", f"expected transaction bytes, got {type(raw).__name__}")
        raw = bytes(raw)
        checks: list[Check] = []

        tx = Transaction.from_hex(raw)
        if tx is None or tx.serialize() != raw:
            raise SandboxRejected("parse", "the bytes are not exactly one well-formed transaction")
        if not tx.inputs or not tx.outputs:
            raise SandboxRejected("parse", "a transaction needs at least one input and one output")
        from pyrxd.glyph.script import iter_script_ops_strict

        for j, out in enumerate(tx.outputs):
            try:
                for _ in iter_script_ops_strict(out.locking_script.serialize()):
                    pass
            except Exception:  # a push or ref operand runs past the end of the script
                raise SandboxRejected(
                    "parse",
                    f"output {j}'s script does not decode: a push runs past its end",
                    hint="pyrxd's own script parser refuses it as Radiant's GetScriptOp would. Build scripts with pyrxd's builders.",
                ) from None
        txid = tx.txid()
        if txid in self.accepted:
            raise SandboxRejected("inputs", f"transaction {txid} is already on the sandbox chain")
        checks.append(Check("parse", "pass", f"{len(raw)} bytes, {len(tx.inputs)} in, {len(tx.outputs)} out"))

        # inputs
        spent: list[Coin] = []
        seen: set[tuple[str, int]] = set()
        for i, txin in enumerate(tx.inputs):
            key = (txin.source_txid, txin.source_output_index)
            if key in seen:
                raise SandboxRejected(
                    "inputs", f"input {i} spends {key[0]}:{key[1]} a second time in the same transaction"
                )
            seen.add(key)
            coin = self.utxos.get(key)
            if coin is None:
                if key in self.spent_by:
                    raise SandboxRejected(
                        "inputs",
                        f"input {i} spends {key[0][:12]}…:{key[1]}, which transaction {self.spent_by[key][:12]}… already spent",
                        hint="Each output can be spent once. Use the change output of your last transaction instead.",
                    )
                raise SandboxRejected(
                    "inputs", f"input {i} spends {key[0][:12]}…:{key[1]}, which the sandbox chain has never seen"
                )
            txin.satoshis = coin.value
            txin.locking_script = _script(coin.script)
            spent.append(coin)
        checks.append(Check("inputs", "pass", f"{len(spent)} unspent input(s)"))

        # value and fee
        value_in = sum(c.value for c in spent)
        value_out = 0
        for j, out in enumerate(tx.outputs):
            if out.satoshis < 0:
                raise SandboxRejected("value", f"output {j} has a negative value")
            value_out += out.satoshis
        if value_out > value_in:
            raise SandboxRejected(
                "value",
                f"outputs spend {value_out:,} photons but the inputs bring only {value_in:,}",
                hint="Leave room for the fee: change = inputs - payment - fee.",
            )
        checks.append(Check("value", "pass", f"in {value_in:,}, out {value_out:,} photons"))
        fee = value_in - value_out
        size = radiant_relay_size(raw)
        floor = min_relay_fee(size)
        if fee < floor:
            raise SandboxRejected(
                "fee",
                f"fee {fee:,} photons is below the relay floor of {floor:,} for {size} bytes",
                hint="Radiant's floor is 0.1 RXD per kB, 10,000 photons per byte (pyrxd.fee_sizing.min_relay_fee). Raise the fee.",
            )
        checks.append(Check("fee", "pass", f"fee {fee:,} photons, floor {floor:,} for {size} bytes"))

        # scripts
        warnings = []
        for i, coin in enumerate(spent):
            verdict = self._check_input(tx, i, coin)
            if verdict is not None:
                warnings.append(verdict)
        if warnings:
            for w in warnings:
                checks.append(Check("scripts", "warn", w))
        else:
            checks.append(Check("scripts", "pass", "every input unlocked by its owner"))

        # refs
        checks.extend(self._check_refs(tx, spent))
        checks.extend(self._check_ft(tx, spent))

        # accept
        acc = Accepted(txid, raw, 0, checks, spent)
        self.accepted[txid] = acc
        self.order.append(txid)
        for coin in spent:
            del self.utxos[(coin.txid, coin.vout)]
            self.spent_by[(coin.txid, coin.vout)] = txid
        for j, out in enumerate(tx.outputs):
            self.utxos[(txid, j)] = Coin(txid, j, out.satoshis, out.locking_script.serialize(), tx, 0)
        self._confirm(txid)
        return acc

    def _check_input(self, tx, i: int, coin: Coin) -> str | None:
        """Raise on a bad unlock; return a warning string for a script the sandbox cannot evaluate."""
        from pyrxd.glyph.script import (
            extract_owner_pkh_from_commit_script,
            extract_owner_pkh_from_ft_script,
            extract_owner_pkh_from_nft_script,
            extract_payload_hash_from_commit_script,
            is_commit_script,
            is_ft_script,
            is_nft_script,
        )

        script = coin.script
        unlock = tx.inputs[i].unlocking_script.serialize() if tx.inputs[i].unlocking_script else b""
        pushes = _split_pushes(unlock)
        hexs = script.hex()
        if _p2pkh_pkh(script) is not None:
            self._check_sig(tx, i, pushes, _p2pkh_pkh(script), "P2PKH", extra=0)
            return None
        if is_nft_script(hexs):
            self._check_sig(tx, i, pushes, bytes(extract_owner_pkh_from_nft_script(script)), "Glyph NFT", extra=0)
            return None
        if is_ft_script(hexs):
            self._check_sig(tx, i, pushes, bytes(extract_owner_pkh_from_ft_script(script)), "Glyph FT", extra=0)
            return None
        if is_commit_script(hexs):
            from pyrxd.glyph.script import split_delegate_commit_prefix

            delegate = split_delegate_commit_prefix(script)[0] is not None
            owner = bytes(extract_owner_pkh_from_commit_script(script))
            self._check_sig(tx, i, pushes, owner, "Glyph commit", extra=2)
            assert pushes is not None
            if pushes[2] != b"gly":
                raise SandboxRejected("scripts", f"input {i}: a Glyph reveal must push 'gly' before the payload")
            want = extract_payload_hash_from_commit_script(script)
            from pyrxd.hash import hash256

            if hash256(pushes[3]) != want:
                raise SandboxRejected(
                    "scripts",
                    f"input {i}: the revealed payload does not hash to the one the commit locked",
                    hint="The reveal must carry the exact CBOR the commit hashed. Changing metadata after commit strands the commit.",
                )
            self._check_commit_output(tx, i, script)
            if delegate:
                return (
                    f"input {i} is a delegate commit: its signature, reveal and token output were checked, but "
                    "the delegate burn its prefix demands was NOT evaluated. Test it on `pyrxd regtest up`."
                )
            return None
        return (
            f"input {i}'s script was NOT evaluated: the sandbox does not run Radiant's script "
            "interpreter, so this spend is unchecked. Test it on `pyrxd regtest up`."
        )

    def _check_sig(self, tx, i: int, pushes, pkh: bytes, kind: str, *, extra: int) -> None:
        from pyrxd.hash import hash160
        from pyrxd.keys import PublicKey

        if pushes is None or len(pushes) != 2 + extra:
            raise SandboxRejected(
                "scripts",
                f"input {i} ({kind}): the unlocking script must be <signature> <public key>"
                + (" 'gly' <payload>" if extra else ""),
                hint="Did you forget tx.sign()? An unsigned input has an empty unlocking script.",
            )
        sig, pub = pushes[0], pushes[1]
        if not ((len(pub) == 33 and pub[0] in (2, 3)) or (len(pub) == 65 and pub[0] == 4)):
            # STRICTENC: a node accepts only compressed (02/03) and uncompressed (04) keys;
            # libsecp256k1 alone would also parse hybrid (06/07) ones.
            raise SandboxRejected(
                "scripts", f"input {i} ({kind}): the public key is not a compressed or uncompressed key"
            )
        if len(sig) < 9 or sig[-1] != SIGHASH_ALL_FORKID:
            raise SandboxRejected(
                "scripts", f"input {i} ({kind}): the sandbox accepts only SIGHASH_ALL|FORKID (0x41) signatures"
            )
        if hash160(pub) != pkh:
            raise SandboxRejected(
                "scripts",
                f"input {i} ({kind}): signed by a key that does not own this output",
                hint="The public key's hash must match the one in the output's script. Sign with the owner's key.",
            )
        try:
            ok = PublicKey(pub).verify(sig[:-1], tx.preimage(i))
        except Exception as exc:  # malformed key or DER
            raise SandboxRejected("scripts", f"input {i} ({kind}): signature or key is malformed ({exc})") from None
        if not ok:
            token = kind in ("Glyph NFT", "Glyph FT")
            raise SandboxRejected(
                "scripts",
                f"input {i} ({kind}): the signature does not verify",
                hint=(
                    "This input holds a token. If a builder took it as plain RXD to pay with, it signed it as a "
                    "plain coin; spend tokens only with pyrxd's token builders."
                    if token
                    else "Changing any output or input after tx.sign() invalidates the signature. Sign last."
                ),
            )

    def _check_commit_output(self, tx, i: int, script: bytes) -> None:
        from pyrxd.glyph.script import script_carries_ref

        txin = tx.inputs[i]
        wire_ref = bytes.fromhex(txin.source_txid)[::-1] + txin.source_output_index.to_bytes(4, "little")
        nft = script[-27] == 0x52 if len(script) >= 27 else True
        want_op = 0xD8 if nft else 0xD0
        for out in tx.outputs:
            body = out.locking_script.serialize()
            if script_carries_ref(body, wire_ref) and _first_ref_opcode(body, wire_ref) == want_op:
                return
        kind = (
            "a singleton (OP_PUSHINPUTREFSINGLETON) for an NFT" if nft else "a normal ref (OP_PUSHINPUTREF) for an FT"
        )
        raise SandboxRejected(
            "scripts",
            f"input {i}: the commit demands an output holding the new token's ref as {kind}, and no output does",
        )

    def _check_refs(self, tx, spent: list[Coin]) -> list[Check]:
        from pyrxd.transaction.transaction_preimage import _get_push_refs

        available: set[bytes] = set()
        held_in: dict[bytes, int] = {}
        for txin in tx.inputs:
            available.add(bytes.fromhex(txin.source_txid)[::-1] + txin.source_output_index.to_bytes(4, "little"))
        for coin in spent:
            for ref in _get_push_refs(coin.script):
                available.add(bytes(ref))
                held_in[bytes(ref)] = held_in.get(bytes(ref), 0) + 1
        from pyrxd.glyph.script import iter_input_refs

        out_refs: set[bytes] = set()
        for j, out in enumerate(tx.outputs):
            body = out.locking_script.serialize()
            for ref in _get_push_refs(body):
                ref = bytes(ref)
                out_refs.add(ref)
                if ref not in available:
                    raise SandboxRejected(
                        "refs",
                        f"output {j} pushes ref {_ref_label(ref)}, which no input provides",
                        hint="A token's ref can only move from an input that holds it, or be minted from an outpoint this transaction spends.",
                    )
        # A singleton push needs a singleton to come from: an input that held the ref as a
        # singleton, or an outpoint this transaction spends (a mint). A normal push does not.
        outpoints = {
            bytes.fromhex(t.source_txid)[::-1] + t.source_output_index.to_bytes(4, "little") for t in tx.inputs
        }
        singleton_in = outpoints | {bytes(o) for coin in spent for op, o in iter_input_refs(coin.script) if op == 0xD8}
        for j, out in enumerate(tx.outputs):
            for op, operand in iter_input_refs(out.locking_script.serialize()):
                if op == 0xD8 and bytes(operand) not in singleton_in:
                    raise SandboxRejected(
                        "refs",
                        f"output {j} pushes {_ref_label(bytes(operand))} as a singleton, but no input holds it as one",
                        hint="A singleton can only come from an input that holds it as a singleton, or be minted from an outpoint this transaction spends.",
                    )
        # Every push of a ref (0xd0 or 0xd8) in every output, not just the first in each: a
        # singleton is one push in the whole transaction's outputs, so the same ref pushed
        # again anywhere, by either opcode, copies it.
        pushes: dict[bytes, list[tuple[int, int]]] = {}
        for j, out in enumerate(tx.outputs):
            for op, operand in iter_input_refs(out.locking_script.serialize()):
                if op in (0xD0, 0xD8):
                    pushes.setdefault(bytes(operand), []).append((j, op))
        # Consensus reads each output's refs as a set, and refuses a singleton ref in more than
        # one output, by either opcode (Radiant Core validation.h, the disallowed-siblings rule).
        for ref, where in pushes.items():
            outs = sorted({j for j, _ in where})
            if any(op == 0xD8 for _, op in where) and len(outs) > 1:
                raise SandboxRejected(
                    "refs",
                    f"singleton ref {_ref_label(ref)} is in outputs {outs}; a singleton's ref may be in one output only",
                    hint="A singleton ref is one of a kind. It can move to one output, never be copied into two.",
                )
        checks = []
        held_singleton = {
            bytes(operand) for coin in spent for op, operand in iter_input_refs(coin.script) if op == 0xD8
        }
        kept_singleton = {ref for ref, where in pushes.items() if any(op == 0xD8 for _, op in where)}
        for ref in sorted(held_singleton & out_refs - kept_singleton):
            checks.append(
                Check(
                    "refs",
                    "warn",
                    f"singleton {_ref_label(ref)} was held by an input and no output keeps it as a singleton: "
                    "the NFT is gone, even though its ref is still pushed",
                )
            )
        burned = [r for r in held_in if r not in out_refs]
        for ref in burned:
            checks.append(
                Check(
                    "refs", "warn", f"token {_ref_label(ref)} was held by an input and no output keeps it: it is burned"
                )
            )
        if not burned and not checks:
            n = len(out_refs)
            checks.append(Check("refs", "pass", f"{n} ref(s) carried, all provided by inputs" if n else "no refs"))
        return checks

    def _check_ft(self, tx, spent: list[Coin]) -> list[Check]:
        from pyrxd.glyph.script import (
            extract_ref_from_ft_script,
            is_commit_script,
            is_ft_script,
            split_delegate_commit_prefix,
        )
        from pyrxd.transaction.transaction_preimage import _get_push_refs

        ins: dict[bytes, int] = {}
        for coin in spent:
            if is_ft_script(coin.script.hex()):
                ref = extract_ref_from_ft_script(coin.script).to_bytes()
                ins[ref] = ins.get(ref, 0) + coin.value
        # An FT is minted only by revealing an FT commit: its ref is that commit's outpoint.
        minted: set[bytes] = set()
        for txin, coin in zip(tx.inputs, spent):
            core = split_delegate_commit_prefix(coin.script)[1]
            if is_commit_script(coin.script.hex()) and len(core) >= 27 and core[-27] != 0x52:
                minted.add(bytes.fromhex(txin.source_txid)[::-1] + txin.source_output_index.to_bytes(4, "little"))
        # A ref an unrecognised input script pushes normally (a dMint contract, say) may mint FT
        # units under that contract's own rules, which the sandbox does not run.
        contract_held: set[bytes] = set()
        for coin in spent:
            h = coin.script.hex()
            if is_ft_script(h) or _owner_pkh(coin.script) is not None or is_commit_script(h):
                continue
            from pyrxd.glyph.script import iter_input_refs

            contract_held |= {bytes(o) for op, o in iter_input_refs(coin.script) if op == 0xD0}
        outs: dict[bytes, int] = {}
        ft_outputs: dict[bytes, set[int]] = {}
        for j, out in enumerate(tx.outputs):
            body = out.locking_script.serialize()
            if is_ft_script(body.hex()):
                ref = extract_ref_from_ft_script(body).to_bytes()
                outs[ref] = outs.get(ref, 0) + out.satoshis
                ft_outputs.setdefault(ref, set()).add(j)
        for ref in outs:
            if ref not in ins and ref not in minted and ref not in contract_held:
                raise SandboxRejected(
                    "ft",
                    f"an FT output holds ref {_ref_label(ref)}, which is neither an FT this transaction spends "
                    "nor one it deploys",
                    hint="FT units come from FT inputs, or from revealing an FT commit. Another token's ref does not become an FT.",
                )
        # The FT covenant counts outputs: every output that pushes the FT's ref must be an FT output.
        for j, out in enumerate(tx.outputs):
            for ref in _get_push_refs(out.locking_script.serialize()):
                ref = bytes(ref)
                if ref in ins and j not in ft_outputs.get(ref, set()):
                    raise SandboxRejected(
                        "ft",
                        f"output {j} pushes FT ref {_ref_label(ref)} but is not an FT output",
                        hint="A spent FT's covenant requires as many FT outputs as outputs pushing its ref.",
                    )
        for ref, n in outs.items():
            if ref in ins and n > ins[ref]:
                raise SandboxRejected(
                    "ft",
                    f"FT {_ref_label(ref)}: outputs hold {n:,} units but inputs bring {ins[ref]:,}",
                    hint="The FT script's covenant forbids creating units. 1 unit = 1 photon of the output's value.",
                )
        if not outs and not ins:
            return [Check("ft", "pass", "no fungible tokens")]
        checks = []
        for r in sorted(set(ins) | set(outs)):
            if r in ins:
                checks.append(Check("ft", "pass", f"{_ref_label(r)}: in {ins[r]:,}, out {outs.get(r, 0):,} units"))
            elif r in minted:
                checks.append(Check("ft", "pass", f"{_ref_label(r)}: deployed, {outs[r]:,} units minted"))
            else:
                checks.append(
                    Check(
                        "ft",
                        "warn",
                        f"{_ref_label(r)}: {outs[r]:,} units minted through an input script the sandbox did NOT evaluate",
                    )
                )
        return checks


def _script(b: bytes):
    from pyrxd.script.script import Script

    return Script(b)


def _first_ref_opcode(script: bytes, wire_ref: bytes) -> int | None:
    """Which opcode first pushes ``wire_ref`` in ``script``: 0xd0, 0xd8, or ``None``.

    Not a possession test (``script_carries_ref`` answers that); this asks only WHICH of the
    two possession opcodes is used, to tell a singleton from a normal ref.
    """
    from pyrxd.glyph.script import iter_input_refs

    for op, operand in iter_input_refs(script):
        if operand == wire_ref and op in (0xD0, 0xD8):
            return op
    return None


def _ref_label(ref: bytes) -> str:
    txid = ref[:32][::-1].hex()
    return f"{txid[:8]}…:{int.from_bytes(ref[32:], 'little')}"


# ---------------------------------------------------------------------------
# The objects a visitor's code talks to
# ---------------------------------------------------------------------------


class SandboxClient:
    """The ElectrumX-shaped surface pyrxd's builders and minter call, backed by the sandbox."""

    def __init__(self, chain: SandboxChain) -> None:
        self._chain = chain

    async def broadcast(self, raw_tx: bytes) -> str:
        if isinstance(raw_tx, str):
            raw_tx = bytes.fromhex(raw_tx)
        return self._chain.submit(bytes(raw_tx)).txid

    async def get_transaction(self, txid) -> bytes:
        from pyrxd.security.errors import NetworkError

        acc = self._chain.accepted.get(str(txid))
        if acc is None:
            raise NetworkError(f"sandbox has no transaction {txid}")
        return acc.raw

    async def get_transaction_verbose(self, txid) -> dict:
        acc = self._chain.accepted.get(str(txid))
        if acc is None:
            return {}
        return {"txid": acc.txid, "hex": acc.raw.hex(), "confirmations": self._chain.confirmations(acc.txid)}


class SandboxWallet:
    """A key ring with the two methods ``GlyphMinter`` and the transfer builders use."""

    def __init__(self, chain: SandboxChain, name: str) -> None:
        from pyrxd.keys import PrivateKey

        self._chain = chain
        self.name = name
        self.key = PrivateKey()
        self.address = self.key.address()

    @property
    def pkh(self) -> bytes:
        return self.key.public_key().hash160()

    async def collect_spendable(self, client=None) -> list:
        from pyrxd.network.electrumx import UtxoRecord
        from pyrxd.script.type import P2PKH

        mine = P2PKH().lock(self.address).serialize()
        triples = []
        for coin in self._chain.utxos.values():
            if _owner_pkh(coin.script) == self.pkh or coin.script == mine:
                rec = UtxoRecord(tx_hash=coin.txid, tx_pos=coin.vout, value=coin.value, height=max(coin.height, 1))
                triples.append((rec, self.address, self.key))
        return triples

    def privkey_for_address(self, address: str):
        if address != self.address:
            raise KeyError(f"{self.name} does not own {address}")
        return self.key

    def coins(self) -> list[Coin]:
        return [c for c in self._chain.utxos.values() if _owner_pkh(c.script) == self.pkh]

    def balance(self) -> int:
        return sum(c.value for c in self.coins() if _p2pkh_pkh(c.script) is not None)

    def __repr__(self) -> str:
        return f"<sandbox wallet {self.name} {self.address}>"


def _owner_pkh(script: bytes) -> bytes | None:
    from pyrxd.glyph.script import (
        extract_owner_pkh_from_ft_script,
        extract_owner_pkh_from_nft_script,
        is_ft_script,
        is_nft_script,
    )

    pkh = _p2pkh_pkh(script)
    if pkh is not None:
        return pkh
    h = script.hex()
    if is_nft_script(h):
        return bytes(extract_owner_pkh_from_nft_script(script))
    if is_ft_script(h):
        return bytes(extract_owner_pkh_from_ft_script(script))
    return None


def _memory_store():
    from pyrxd.glyph.mint import PendingMintNotFound, PendingStore

    class MemoryPendingStore(PendingStore):
        """Keeps pending mints for as long as the tab is open. Fine for a chain that dies with it."""

        def __init__(self) -> None:
            self._records: dict = {}
            self._archived: dict = {}

        def save(self, pending) -> None:
            self._records[pending.commit_txid] = pending.to_dict()

        def load(self, commit_txid: str):
            from pyrxd.glyph.mint import PendingMint

            if commit_txid not in self._records:
                raise PendingMintNotFound(commit_txid)
            return PendingMint.from_dict(self._records[commit_txid])

        def delete(self, commit_txid: str) -> None:
            self._records.pop(commit_txid, None)

        def archive(self, commit_txid: str) -> None:
            if commit_txid in self._records:
                self._archived[commit_txid] = self._records.pop(commit_txid)

        def list_pending(self) -> list[str]:
            return list(self._records)

    return MemoryPendingStore()


class Sandbox:
    """What ``from playground import sandbox`` gives a visitor."""

    def __init__(self) -> None:
        # Not reset() here: that makes keys, and under Pyodide there is no curve until
        # prepare_runtime() has run. _install_playground_module() resets on first use.
        self.chain: SandboxChain | None = None  # type: ignore[assignment]

    def reset(self) -> None:
        self.chain = SandboxChain()
        self.client = SandboxClient(self.chain)
        self.wallet = SandboxWallet(self.chain, "you")
        self.friend = SandboxWallet(self.chain, "friend")
        self.store = _memory_store()
        self.last_txid: str | None = None

    @property
    def height(self) -> int:
        return self.chain.height

    def faucet(self, address: str | None = None, rxd: float = 10) -> Coin:
        """Pay sandbox RXD to ``address`` (your wallet by default). Sandbox coins have no value."""
        photons = round(float(rxd) * 100_000_000)
        coin = self.chain.fund(address or self.wallet.address, photons)
        self.last_txid = coin.txid
        return coin

    def broadcast(self, tx) -> str:
        """Submit a signed ``Transaction`` (or its bytes or hex). Returns the txid, or raises SandboxRejected."""
        raw = tx.serialize() if hasattr(tx, "serialize") else tx
        acc = self.chain.submit(raw)
        self.last_txid = acc.txid
        return acc.txid

    def mine(self, blocks: int = 1) -> int:
        return self.chain.mine(blocks)

    def coins(self, wallet: SandboxWallet | None = None) -> list[Coin]:
        return (wallet or self.wallet).coins()

    def balance(self, wallet: SandboxWallet | None = None) -> int:
        return (wallet or self.wallet).balance()

    def minter(self):
        """A ``GlyphMinter`` wired to the sandbox (mainnet fee floor, one confirmation)."""
        from pyrxd.glyph.mint import GlyphMinter

        return GlyphMinter(self.client, self.wallet, self.store, poll_interval_s=0.05, confirmation_timeout_s=30)


sandbox = Sandbox()


def _install_playground_module() -> None:
    """Make ``from playground import sandbox`` work in a visitor's code."""
    mod = sys.modules.get("playground")
    if mod is None:
        mod = types.ModuleType("playground")
        sys.modules["playground"] = mod
    if sandbox.chain is None:
        sandbox.reset()
    mod.sandbox = sandbox  # type: ignore[attr-defined]
    mod.SandboxRejected = SandboxRejected  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Running a visitor's program
# ---------------------------------------------------------------------------

USER_FILENAME = "<playground>"
MAX_SOURCE_CHARS = 100_000
MAX_OUTPUT_CHARS = 200_000


class _BoundedIO(io.StringIO):
    def write(self, s: str) -> int:
        if self.tell() > MAX_OUTPUT_CHARS:
            return len(s)
        return super().write(s)


def _user_line(tb) -> int | None:
    line = None
    for frame in traceback.extract_tb(tb):
        if frame.filename == USER_FILENAME:
            line = frame.lineno
    return line


async def run_program(source: str) -> dict:
    """Run a visitor's program against the sandbox. Never raises; returns a JSON-shaped dict.

    ``error`` is ``None`` on success, else ``{"type", "message", "line", "rule", "hint"}``,
    where ``line`` is the line in the visitor's code that raised (or ``None``), and ``rule``
    and ``hint`` are set when the sandbox refused a transaction. ``txids`` lists the
    transactions this run added to the chain, oldest first, and ``warnings`` every check on
    them that passed with a warning (an unevaluated script, a burned token).
    """
    _install_playground_module()
    if not isinstance(source, str):
        return _result("", _err("TypeError", "the program must be text", None), [])
    if len(source) > MAX_SOURCE_CHARS:
        return _result("", _err("ValueError", f"the program is over {MAX_SOURCE_CHARS:,} characters", None), [])
    before = len(sandbox.chain.order)
    out = _BoundedIO()
    error = None
    try:
        code = compile(source, USER_FILENAME, "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT, dont_inherit=True)
    except SyntaxError as exc:
        return _result("", _err("SyntaxError", exc.msg, exc.lineno), [])
    namespace: dict = {"__name__": "__main__"}
    try:
        with contextlib.redirect_stdout(out):
            maybe = eval(code, namespace)  # noqa: S307 — the visitor's own code, in their own tab
            if asyncio.iscoroutine(maybe):
                await maybe
    except SandboxRejected as exc:
        error = _err("SandboxRejected", str(exc), _user_line(exc.__traceback__), rule=exc.rule, hint=exc.hint)
    except Exception as exc:  # the visitor's bug, reported to the visitor
        error = _err(type(exc).__name__, str(exc), _user_line(exc.__traceback__), hint=_hint_for(exc))
    except BaseException as exc:  # SystemExit, KeyboardInterrupt from user code
        error = _err(type(exc).__name__, str(exc), _user_line(exc.__traceback__))
    return _result(out.getvalue(), error, sandbox.chain.order[before:])


def _hint_for(exc: BaseException) -> str:
    name = type(exc).__name__
    text = str(exc)
    if name == "NameError":
        return "Check the spelling, and that you imported it at the top."
    if "relay floor" in text or "fee_rate" in text:
        return "Radiant's relay floor is 10,000 photons per byte (0.1 RXD per kB)."
    if name in ("InsufficientFundsError", "NoFeeFundingError", "NoHoldingsError", "InsufficientFunds"):
        return "Ask the faucet for more: sandbox.faucet(rxd=10)."
    return ""


def _err(type_: str, message: str, line: int | None, *, rule: str = "", hint: str = "") -> dict:
    return {"type": type_, "message": message, "line": line, "rule": rule, "hint": hint}


def _result(stdout: str, error: dict | None, txids: list[str]) -> dict:
    warnings = []
    for txid in txids:
        acc = sandbox.chain.accepted.get(txid)
        for c in acc.checks if acc is not None else ():
            if c.status == "warn":
                warnings.append({"txid": txid, "rule": c.rule, "detail": c.detail})
    return {
        "stdout": stdout,
        "error": error,
        "txids": list(txids),
        "warnings": warnings,
        "height": sandbox.chain.height,
    }


def lesson_list() -> list[dict]:
    import lessons

    return lessons.lesson_list()


def reset_sandbox() -> dict:
    sandbox.reset()
    _install_playground_module()
    return chain_state()


def chain_state() -> dict:
    """Blocks, balances and token counts for the Chain & wallet tab."""
    _install_playground_module()
    from pyrxd.glyph.script import is_ft_script, is_nft_script

    def holdings(w: SandboxWallet) -> dict:
        coins = w.coins()
        return {
            "address": w.address,
            "rxd_photons": sum(c.value for c in coins if _p2pkh_pkh(c.script) is not None),
            "nfts": sum(1 for c in coins if is_nft_script(c.script.hex())),
            "ft_units": sum(c.value for c in coins if is_ft_script(c.script.hex())),
        }

    blocks = [{"height": b.height, "txids": list(b.txids)} for b in sandbox.chain.blocks[-8:]]
    return {
        "height": sandbox.chain.height,
        "blocks": blocks,
        "you": holdings(sandbox.wallet),
        "friend": holdings(sandbox.friend),
        "last_txid": sandbox.last_txid,
    }


# ---------------------------------------------------------------------------
# The Transaction tab
# ---------------------------------------------------------------------------

#: Plain-language notes for the opcodes a newcomer from Bitcoin or Ethereum has not seen.
#: Names come from ``pyrxd.constants.OpCode``; the notes are the playground's own.
OPCODE_NOTES: dict[int, tuple[str, str]] = {
    0xD0: ("ref", "Pushes a ref this output holds. A normal ref: many outputs may carry it (fungible tokens)."),
    0xD8: ("ref", "Pushes a singleton ref: exactly one output may carry it. This is what makes an NFT unique."),
    0xD1: ("ref", "Requires some input to carry this ref. A condition on the spender, not a holding."),
    0xD2: ("ref", "Forbids any output from pushing this ref."),
    0xD3: ("ref", "Forbids sibling outputs from pushing this ref."),
    0xBD: ("covenant", "State separator: bytes before it are state, bytes after it are the code a covenant compares."),
    0xC0: ("covenant", "Introspection: the index of the input being spent."),
    0xC8: ("covenant", "Introspection: the txid of an input's outpoint."),
    0xC9: ("covenant", "Introspection: the output index of an input's outpoint."),
    0xDA: ("covenant", "Introspection: the ref type (none, normal, singleton) an output gives a ref."),
    0xDE: ("covenant", "Introspection: how many outputs carry a ref."),
    0xE3: ("covenant", "Sum of input values whose code script hashes to the given hash."),
    0xE4: ("covenant", "Sum of output values whose code script hashes to the given hash."),
    0xE6: ("covenant", "How many outputs have a code script with the given hash."),
    0xE9: ("covenant", "The code script (after the state separator) of an input's UTXO."),
    0xAA: ("op", "Double SHA-256."),
    0x76: ("op", "Duplicates the top stack item."),
    0xA9: ("op", "RIPEMD-160 of SHA-256: turns a public key into its 20-byte hash."),
    0x88: ("op", "Fails unless the top two items are equal."),
    0xAC: ("op", "Checks a signature against a public key and this transaction."),
    0x75: ("op", "Drops the top stack item."),
    0x9D: ("op", "Fails unless the top two numbers are equal."),
}


def _opcode_name(op: int) -> str:
    from pyrxd.constants import OpCode

    for member in OpCode:
        if member.value == bytes([op]):
            return member.name
    return f"0x{op:02x}"


def disassemble(script: bytes) -> list[dict]:
    from pyrxd.script.consensus import iter_script_ops

    ops = []
    for op in iter_script_ops(script):
        if op.opcode in (0xD0, 0xD1, 0xD2, 0xD3, 0xD8):
            kind, note = OPCODE_NOTES[op.opcode]
            ops.append(
                {
                    "name": _opcode_name(op.opcode),
                    "kind": kind,
                    "note": note,
                    "data": _ref_label(op.operand),
                    "hex": op.operand.hex(),
                }
            )
        elif 0x01 <= op.opcode <= 0x4E:
            ops.append(
                {
                    "name": f"PUSH {len(op.operand)}",
                    "kind": "push",
                    "note": "",
                    "data": op.operand.hex(),
                    "hex": op.operand.hex(),
                }
            )
        else:
            kind, note = OPCODE_NOTES.get(op.opcode, ("op", ""))
            ops.append({"name": _opcode_name(op.opcode), "kind": kind, "note": note, "data": "", "hex": ""})
    return ops


def classify(script: bytes) -> dict:
    from pyrxd.glyph.script import (
        extract_ref_from_ft_script,
        extract_ref_from_nft_script,
        is_commit_script,
        is_ft_script,
        is_nft_script,
    )

    h = script.hex()
    owner = _owner_pkh(script)
    if _p2pkh_pkh(script) is not None:
        return {"kind": "p2pkh", "label": "Plain RXD (P2PKH)", "owner": _who(owner)}
    if is_nft_script(h):
        return {
            "kind": "nft",
            "label": "Glyph NFT",
            "owner": _who(owner),
            "ref": _ref_label(extract_ref_from_nft_script(script).to_bytes()),
        }
    if is_ft_script(h):
        return {
            "kind": "ft",
            "label": "Glyph FT",
            "owner": _who(owner),
            "ref": _ref_label(extract_ref_from_ft_script(script).to_bytes()),
        }
    if is_commit_script(h):
        return {"kind": "commit", "label": "Glyph commit (hashlock)", "owner": ""}
    if script[:1] == b"\x6a" or script[:2] == b"\x00\x6a":
        return {"kind": "opreturn", "label": "OP_RETURN data", "owner": ""}
    return {"kind": "other", "label": "Other script", "owner": ""}


def _who(pkh: bytes | None) -> str:
    if pkh is None:
        return ""
    if pkh == sandbox.wallet.pkh:
        return "you"
    if pkh == sandbox.friend.pkh:
        return "friend"
    return pkh.hex()[:10] + "…"


def describe_tx(txid: str | None = None) -> dict | None:
    """Everything the Transaction tab draws for ``txid`` (default: the newest)."""
    _install_playground_module()
    from pyrxd.transaction.transaction import Transaction

    chain = sandbox.chain
    if txid is None:
        txid = chain.order[-1] if chain.order else None
    if txid is None or txid not in chain.accepted:
        return None
    acc = chain.accepted[txid]
    tx = Transaction.from_hex(acc.raw)
    inputs = []
    for i, _txin in enumerate(tx.inputs):
        if acc.faucet:
            inputs.append(
                {
                    "outpoint": "faucet",
                    "value": None,
                    "class": {"kind": "faucet", "label": "Sandbox faucet", "owner": ""},
                }
            )
            continue
        coin = acc.spent[i]
        inputs.append(
            {"outpoint": f"{coin.txid[:8]}…:{coin.vout}", "value": coin.value, "class": classify(coin.script)}
        )
    outputs = []
    for j, out in enumerate(tx.outputs):
        body = out.locking_script.serialize()
        outputs.append(
            {"index": j, "value": out.satoshis, "class": classify(body), "ops": disassemble(body), "hex": body.hex()}
        )
    fee = sum(c.value for c in acc.spent) - sum(o.satoshis for o in tx.outputs) if not acc.faucet else 0
    return {
        "txid": txid,
        "size": len(acc.raw),
        "fee": fee,
        "height": acc.height,
        "confirmations": chain.confirmations(txid),
        "faucet": acc.faucet,
        "inputs": inputs,
        "outputs": outputs,
        "checks": [{"rule": c.rule, "status": c.status, "detail": c.detail} for c in acc.checks],
        "rules": [{"rule": k, "text": v} for k, v in RULES],
        "order": list(chain.order),
    }


# ---------------------------------------------------------------------------
# Export as project
# ---------------------------------------------------------------------------

EXPORT_NOTE = """\
# {file}: exported from the Radiant Playground.
#
# This ran against the playground's sandbox chain, which lives in a browser tab. The
# `playground` module it imports does not exist outside that page, so this file does not
# run as it is. It is here so you keep what you wrote. To run the same steps on a real
# local node, start from src/{package}/mint.py and tests/test_mint.py, which use
# `pyrxd regtest up` and pyrxd.testing (see README.md).

"""

EXPORT_README = """\
# playground/

`{file}` is the code you had in the Radiant Playground when you pressed Export.

It imports `from playground import sandbox`, the in-tab sandbox chain, so it does not run
outside the page. The rest of this project is what `pyrxd new {name}` makes: a Glyph NFT
mint in `src/{package}/mint.py` and a test, `tests/test_mint.py`, that mints on a
throwaway regtest node and checks the result with the node. Swap the sandbox objects for
the ones those files use:

| playground              | local regtest chain (`main()` in mint.py) | tests                 |
|-------------------------|-------------------------------------------|-----------------------|
| `sandbox.client`        | `RegtestClient(RegtestNode())`            | `regtest_client`      |
| `sandbox.wallet`        | `RegtestWallet.funded(node, 1.0)`         | `regtest_wallet`      |
| `sandbox.faucet(rxd=1)` | funded by `RegtestWallet.funded`          | funded by the fixture |
| `sandbox.minter()`      | `GlyphMinter(client, wallet, JsonFilePendingStore(dir))` | as in mint.py |

For mainnet, mint.py's docstring says what to pass instead.

The sandbox does not run Radiant's script interpreter; a real node does, so a transaction
the sandbox accepted can still be refused there.
"""


def export_available() -> bool:
    """True when the loaded pyrxd has the starter kit (`pyrxd new`) the export builds on."""
    try:
        import pyrxd.starter  # noqa: F401
    except ImportError:
        return False
    return True


def export_project(project_name: str, lesson_id: str, code: str) -> dict:
    """The starter project for ``project_name`` with the visitor's code added, as a zip.

    Returns ``{"zip": bytes, "filename": str, "files": [paths]}``. The project is
    ``pyrxd.starter.render_project`` unchanged, plus ``playground/<lesson file>`` (the code,
    under a note that it needs the sandbox) and ``playground/README.md``. Raises
    ``pyrxd.starter.ProjectNameError`` for an unusable name and ``KeyError`` for an
    unknown lesson.
    """
    import zipfile

    from pyrxd.starter import package_name_for, render_project

    lesson = {x["id"]: x for x in lesson_list()}[lesson_id]
    package = package_name_for(project_name)
    fname = lesson["file"]
    fields = {"file": fname, "package": package, "name": project_name}
    files = render_project(
        project_name,
        overrides={
            f"playground/{fname}": EXPORT_NOTE.format(**fields) + code,
            "playground/README.md": EXPORT_README.format(**fields),
        },
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            info = zipfile.ZipInfo(f"{project_name}/{path}", date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[path].encode("utf-8"))
    return {"zip": buf.getvalue(), "filename": f"{project_name}.zip", "files": sorted(files)}
