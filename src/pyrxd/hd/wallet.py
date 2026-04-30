"""Persistent BIP44 HD wallet with gap-limit scanning for Radiant (coin type 236).

Usage
-----
    async with ElectrumXClient(urls) as client:
        wallet = HdWallet.from_mnemonic("word1 ... word12")
        await wallet.refresh(client)
        addr = wallet.next_receive_address()
        balance = await wallet.get_balance(client)
        wallet.save(Path("wallet.dat"))

    # Later:
    wallet = HdWallet.load(Path("wallet.dat"), mnemonic="word1 ... word12")
    # or, if the file may not yet exist:
    wallet = HdWallet.load_or_create(Path("wallet.dat"), mnemonic="...")

File format (v2)
----------------
``[version(1B)][scrypt_salt(16B)][gcm_nonce(12B)][gcm_tag(16B)][ciphertext]``

Stream C/HD-hardening rationale (closes ultrareview re-review N1-N6):
- N1: ``_seed`` lives in :class:`SecretBytes` so repr/copy/pickle cannot
  exfiltrate it and ``zeroize()`` is available.
- N2: ``save()`` is atomic — mkstemp + fchmod 0o600 + fsync + os.replace.
  Mode 0o600 is set BEFORE any bytes are written so the file is never
  visible at a wider mode.
- N3: encryption key is derived via scrypt (per-file random salt) instead
  of static ``hash256(seed)[:32]``. Slow per-attempt cost limits offline
  brute force when the seed leaks but the file is recoverable.
- N4: AES-256-GCM (AEAD) replaces AES-256-CBC. A tampered ciphertext now
  fails ``decrypt_and_verify`` with ``ValueError`` instead of returning
  attacker-controlled JSON that would silently corrupt wallet state.
- N5: gap-scan re-raises network errors instead of silently treating
  failed lookups as "address unused" — a flaky network used to make a
  funded wallet look empty.
- N6: ``load()`` raises :class:`FileNotFoundError` when the file is
  missing. The previous silent-fresh-wallet behavior is preserved
  behind ``load_or_create()`` so callers opt in explicitly. A typo'd
  path no longer overwrites a real wallet on the next save.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from Cryptodome.Cipher import AES

from ..hd.bip32 import Xprv, bip32_derive_xprv_from_mnemonic
from ..hd.bip39 import seed_from_mnemonic
from ..keys import PrivateKey
from ..network.electrumx import UtxoRecord, script_hash_for_address
from ..script.type import P2PKH
from ..security.errors import ValidationError
from ..security.secrets import SecretBytes
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from ..utils import validate_address
from ..wallet import DEFAULT_FEE_RATE, DUST_THRESHOLD

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient

_GAP_LIMIT = 20
_COIN_TYPE = 236
_RADIANT_PATH = f"m/44'/{_COIN_TYPE}'"

# File-format constants. v2 changed encryption from CBC to GCM and the
# KDF from raw hash256 to scrypt — incompatible with v1 by design (v1
# never carried a salt or auth tag, so loading it under the new code path
# is impossible without a one-shot conversion). Pre-Stream-C-hard
# wallets must be re-saved to upgrade.
_FILE_VERSION_V2 = 2

# Header layout for v2: version || salt || nonce || tag || ciphertext.
_SALT_LEN = 16  # scrypt
_NONCE_LEN = 12  # AES-GCM standard
_TAG_LEN = 16  # AES-GCM tag
_HEADER_LEN = 1 + _SALT_LEN + _NONCE_LEN + _TAG_LEN  # 45

# scrypt parameters. Lower-cost than the signer-key scrypt because the
# input here (BIP39 seed) is already 64 bytes of high-entropy material —
# the protection is per-attempt slowness, not entropy stretching. n=2^14
# stays under OpenSSL's default memory cap so callers don't need to
# tune ``maxmem``.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


@dataclass
class AddressRecord:
    address: str
    change: int  # 0 = external, 1 = internal
    index: int
    used: bool


@dataclass
class HdWallet:
    """BIP44 HD wallet for Radiant with gap-limit discovery and encrypted persistence.

    Attributes
    ----------
    account:
        BIP44 account index (usually 0).
    external_tip:
        Highest derived index on external chain (change=0).
    internal_tip:
        Highest derived index on internal chain (change=1).
    addresses:
        ``{path_key: AddressRecord}`` where path_key is ``f"{change}/{index}"``.
    """

    _xprv: Xprv = field(repr=False)
    _seed: SecretBytes = field(repr=False)
    account: int = 0
    external_tip: int = 0
    internal_tip: int = 0
    addresses: dict[str, AddressRecord] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Construction

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str,
        passphrase: str = "",  # nosec B107 — BIP39 passphrase, not a hardcoded password
        account: int = 0,
    ) -> HdWallet:
        """Create a fresh wallet from a BIP39 mnemonic."""
        seed = seed_from_mnemonic(mnemonic, passphrase=passphrase)
        path = f"{_RADIANT_PATH}/{account}'"
        xprv = bip32_derive_xprv_from_mnemonic(mnemonic, passphrase=passphrase, path=path)
        return cls(_xprv=xprv, _seed=SecretBytes(seed), account=account)

    @classmethod
    def load(
        cls,
        path: Path,
        mnemonic: str,
        passphrase: str = "",  # nosec B107 — BIP39 passphrase, not a hardcoded password
    ) -> HdWallet:
        """Load a previously saved wallet from *path*.

        The mnemonic is needed to derive the decryption key. Raises
        :class:`FileNotFoundError` if *path* does not exist — a typo'd
        path will not silently produce an empty wallet that subsequently
        overwrites a real wallet on save. Callers that explicitly want
        the create-on-missing behavior should use :meth:`load_or_create`.
        """
        if not path.exists():
            raise FileNotFoundError(
                f"Wallet file not found: {path}. Use HdWallet.load_or_create(...) "
                f"if you intended to create a new wallet on this path."
            )
        return cls._load_existing(path, mnemonic, passphrase)

    @classmethod
    def load_or_create(
        cls,
        path: Path,
        mnemonic: str,
        passphrase: str = "",  # nosec B107 — BIP39 passphrase, not a hardcoded password
        account: int = 0,
    ) -> HdWallet:
        """Load a wallet from *path*, or build a fresh one if the file is missing.

        Spelled separately from :meth:`load` so the create-on-missing
        intent is explicit at the call site. A common safety failure
        with the old single-load API was that a typo in *path* would
        produce an empty wallet that subsequently overwrote the real
        wallet on save.
        """
        if path.exists():
            return cls._load_existing(path, mnemonic, passphrase)
        return cls.from_mnemonic(mnemonic, passphrase=passphrase, account=account)

    @classmethod
    def _load_existing(cls, path: Path, mnemonic: str, passphrase: str) -> HdWallet:
        # Mode check: refuse to load a wallet that's group/world readable.
        # ``save()`` always writes 0o600, but a user who restored from
        # backup with ``cp`` or ``rsync`` might end up with a wider
        # mode and not realize it. Catch it at load rather than silently
        # operating with a world-readable seed file.
        # Skipped on platforms without POSIX mode bits (Windows: stat.st_mode
        # returns dummy values, so the check is meaningless). We fall back to
        # warning-via-exception only when stat reports POSIX-shaped bits.
        try:
            mode = path.stat().st_mode & 0o777
        except OSError:
            mode = None
        if mode is not None and (mode & 0o077) and os.name == "posix":
            raise ValidationError(
                f"Wallet file at {path} has mode {oct(mode)}; "
                "must be 0o600 (owner-only). Run `chmod 0600 <path>` and retry."
            )

        seed = seed_from_mnemonic(mnemonic, passphrase=passphrase)

        raw = path.read_bytes()
        if len(raw) < _HEADER_LEN:
            raise ValidationError("Wallet file too short to contain header")

        version = raw[0]
        if version != _FILE_VERSION_V2:
            raise ValidationError(
                f"Unsupported wallet file version: {version} (expected {_FILE_VERSION_V2}). "
                "Pre-v2 wallets used unauthenticated AES-CBC and a static KDF — "
                "re-create the wallet from mnemonic and save it under the new format."
            )

        salt = raw[1 : 1 + _SALT_LEN]
        nonce = raw[1 + _SALT_LEN : 1 + _SALT_LEN + _NONCE_LEN]
        tag = raw[1 + _SALT_LEN + _NONCE_LEN : _HEADER_LEN]
        ciphertext = raw[_HEADER_LEN:]

        enc_key = _derive_enc_key(seed, salt)
        try:
            cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError) as exc:
            # GCM tag mismatch raises ValueError; bad key length raises
            # ValueError too. Surface a single static message (no
            # context-leaking detail) — closes Stream C #4 finding pattern.
            raise ValidationError(
                "Could not decrypt wallet file — wrong mnemonic, wrong passphrase, or ciphertext tampered."
            ) from exc

        try:
            data = json.loads(plaintext.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # Should not happen with AEAD: a tampered ciphertext would
            # have failed the tag check above. If we land here the disk
            # is corrupt or someone bypassed the AEAD layer — surface
            # explicitly, do not return a partial wallet.
            raise ValidationError("Wallet file decrypted but contains invalid JSON — disk corruption?") from exc

        try:
            account = int(data.get("account", 0))
            account_xprv = bip32_derive_xprv_from_mnemonic(
                mnemonic, passphrase=passphrase, path=f"{_RADIANT_PATH}/{account}'"
            )
            wallet = cls(
                _xprv=account_xprv,
                _seed=SecretBytes(seed),
                account=account,
                external_tip=int(data.get("external_tip", 0)),
                internal_tip=int(data.get("internal_tip", 0)),
            )
            for key, rec in data.get("addresses", {}).items():
                wallet.addresses[key] = AddressRecord(
                    address=rec["address"],
                    change=int(rec["change"]),
                    index=int(rec["index"]),
                    used=bool(rec["used"]),
                )
        except (KeyError, TypeError, ValueError) as exc:
            # AEAD makes structural corruption an "impossible" path —
            # if we land here the disk is genuinely damaged or someone
            # has bypassed the AEAD layer. Refuse to return a partial
            # wallet rather than silently dropping the malformed bits;
            # users would otherwise lose external_tip / address records
            # without any indication.
            raise ValidationError(
                "Wallet file decrypted but contains malformed wallet state — disk corruption?"
            ) from exc
        return wallet

    # ------------------------------------------------------------------
    # Persistence

    def save(self, path: Path) -> None:
        """Encrypt and atomically save wallet state to *path*.

        Atomicity & permissions
        -----------------------
        Writes via mkstemp + fchmod(0o600) + fsync + os.replace, so:
          - The file is never visible at a wider mode than 0o600 — the
            mode is set on the fd before any bytes are written.
          - A crash mid-write cannot leave a half-encrypted blob in
            place — either the old file remains, or the new
            fully-fsynced file does.

        Encryption
        ----------
        AES-256-GCM under a key derived from the BIP39 seed via scrypt
        with a per-file random salt. Tampering with the ciphertext
        breaks the GCM tag — :meth:`load` raises rather than returning
        attacker-shaped JSON.
        """
        salt = secrets.token_bytes(_SALT_LEN)
        nonce = secrets.token_bytes(_NONCE_LEN)
        enc_key = _derive_enc_key(self._seed.unsafe_raw_bytes(), salt)

        data = {
            "version": _FILE_VERSION_V2,
            "account": self.account,
            "coin_type": _COIN_TYPE,
            "external_tip": self.external_tip,
            "internal_tip": self.internal_tip,
            "addresses": {
                k: {
                    "address": r.address,
                    "change": r.change,
                    "index": r.index,
                    "used": r.used,
                }
                for k, r in self.addresses.items()
            },
        }
        plaintext = json.dumps(data).encode()

        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        blob = bytes([_FILE_VERSION_V2]) + salt + nonce + tag + ciphertext

        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, blob)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp_path, path)
        except Exception:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    # Best-effort cleanup; original exception is re-raised below.
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                # Best-effort cleanup; original exception is re-raised below.
                pass
            raise

    # ------------------------------------------------------------------
    # Address derivation

    def _derive_address(self, change: int, index: int) -> str:
        """Derive the P2PKH address at change/index on the account key."""
        child = self._xprv.ckd(change).ckd(index)
        return child.address()

    def _path_key(self, change: int, index: int) -> str:
        return f"{change}/{index}"

    # ------------------------------------------------------------------
    # Gap-limit scanning

    async def refresh(self, client: ElectrumXClient) -> int:
        """Run BIP44 gap-limit scan on both external and internal chains.

        Discovers which derived addresses have on-chain history.  Stops
        after :data:`_GAP_LIMIT` (20) consecutive unused addresses per chain.

        Network errors (a transient ElectrumX outage, a server hangup
        mid-scan) propagate to the caller as :class:`NetworkError` —
        previously they were silently treated as "address unused",
        which made a funded wallet look empty after a flaky lookup.

        Returns the count of newly discovered used addresses.
        """
        newly_used = 0
        for change in (0, 1):
            newly_used += await self._scan_chain(client, change)
        return newly_used

    async def _scan_chain(self, client: ElectrumXClient, change: int) -> int:
        consecutive_unused = 0
        index = 0
        newly_used = 0
        while consecutive_unused < _GAP_LIMIT:
            # Fetch one address at a time — correct BIP44 gap-limit semantics.
            addr = self._derive_address(change, index)
            pkey = self._path_key(change, index)
            # Closes N5: do NOT swallow the exception. A failed lookup
            # cannot be safely interpreted as "unused" — the seemingly-
            # empty result would mark a real funded address as
            # unused, hide it from get_balance/get_utxos, and
            # potentially cause duplicate-spend scenarios when next-
            # receive picks it again.
            hist = await client.get_history(script_hash_for_address(addr))
            is_used = bool(hist)
            old = self.addresses.get(pkey)
            self.addresses[pkey] = AddressRecord(address=addr, change=change, index=index, used=is_used)
            if is_used:
                consecutive_unused = 0
                if old is None or not old.used:
                    newly_used += 1
            else:
                consecutive_unused += 1
            index += 1

        if change == 0:
            self.external_tip = (
                max(
                    (r.index for r in self.addresses.values() if r.change == 0 and r.used),
                    default=-1,
                )
                + 1
            )
        else:
            self.internal_tip = (
                max(
                    (r.index for r in self.addresses.values() if r.change == 1 and r.used),
                    default=-1,
                )
                + 1
            )
        return newly_used

    # ------------------------------------------------------------------
    # Public query API

    def next_receive_address(self) -> str:
        """Return the first external (change=0) address with no recorded history."""
        for idx in range(self.external_tip + _GAP_LIMIT):
            pkey = self._path_key(0, idx)
            rec = self.addresses.get(pkey)
            if rec is None or not rec.used:
                if rec is None:
                    addr = self._derive_address(0, idx)
                    self.addresses[pkey] = AddressRecord(address=addr, change=0, index=idx, used=False)
                else:
                    addr = rec.address
                return addr
        # Extend if all known addresses are used (edge case)
        idx = self.external_tip + _GAP_LIMIT
        addr = self._derive_address(0, idx)
        self.addresses[self._path_key(0, idx)] = AddressRecord(address=addr, change=0, index=idx, used=False)
        return addr

    def known_addresses(self, *, change: int | None = None) -> list[AddressRecord]:
        """Return all known address records, optionally filtered by chain."""
        recs = list(self.addresses.values())
        if change is not None:
            recs = [r for r in recs if r.change == change]
        return recs

    async def get_utxos(self, client: ElectrumXClient) -> list[UtxoRecord]:
        """Return all UTXOs across all known addresses."""
        all_utxos: list[UtxoRecord] = []
        used = [r for r in self.addresses.values() if r.used]
        if not used:
            return []
        results = await asyncio.gather(
            *[client.get_utxos(script_hash_for_address(r.address)) for r in used],
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, list):
                all_utxos.extend(result)
        return all_utxos

    async def get_balance(self, client: ElectrumXClient) -> int:
        """Return total confirmed + unconfirmed satoshis across all known addresses.

        Uses ``ElectrumXClient.get_balance`` per address.  Call ``refresh()``
        first to ensure the address set is current.
        """
        used = [r for r in self.addresses.values() if r.used]
        if not used:
            return 0
        results = await asyncio.gather(
            *[client.get_balance(script_hash_for_address(r.address)) for r in used],
            return_exceptions=True,
        )
        total = 0
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                confirmed, unconfirmed = result
                total += int(confirmed) + int(unconfirmed)
        return total

    # ------------------------------------------------------------------
    # Spending — Cut 1A of v0.3 wallet/CLI plan.
    #
    # Mirrors RxdWallet.send / send_max but signs each input with the
    # per-UTXO derived key (BIP44 m/44'/236'/account'/change/index). The
    # fee uses the same two-pass trial→measure→rebuild pattern that
    # RxdWallet uses; see test_preimage.py for the stale-signature
    # pitfall that motivated the reset between passes.

    def _privkey_for(self, change: int, index: int) -> PrivateKey:
        """Return the PrivateKey at ``m/.../change/index`` from the account xprv."""
        return self._xprv.ckd(change).ckd(index).private_key()

    def _next_change_index(self) -> int:
        """Return the next unused internal-chain index for change outputs.

        Picks the lowest internal index whose ``AddressRecord.used`` is
        False, falling back to ``internal_tip`` if all known indices are
        used. The returned index is NOT marked used here — the wallet
        only flips the bit after a subsequent ``refresh()`` confirms
        chain history.
        """
        for idx in range(self.internal_tip + _GAP_LIMIT):
            pkey = self._path_key(1, idx)
            rec = self.addresses.get(pkey)
            if rec is None or not rec.used:
                if rec is None:
                    addr = self._derive_address(1, idx)
                    self.addresses[pkey] = AddressRecord(address=addr, change=1, index=idx, used=False)
                return idx
        # Edge case: every known internal index is used. Extend.
        return self.internal_tip + _GAP_LIMIT

    def _build_utxo_input(self, utxo: UtxoRecord, address: str, privkey: PrivateKey) -> TransactionInput:
        """Build a signable TransactionInput for *utxo* spending *address*.

        Mirrors :meth:`RxdWallet._make_input` but parameterizes the
        signing key (different per address in HD wallets).
        """
        if utxo.value <= 0:
            raise ValidationError("UTXO value must be positive")

        locking = P2PKH().lock(address)
        tx_input = TransactionInput(
            source_txid=utxo.tx_hash,
            source_output_index=utxo.tx_pos,
            unlocking_script_template=P2PKH().unlock(privkey),
        )
        tx_input.satoshis = utxo.value
        tx_input.locking_script = locking

        # Stub source-tx so fee()/preimage() can read this output's value.
        stub_out = TransactionOutput(locking, utxo.value)
        vout = utxo.tx_pos

        class _SrcTx:
            outputs = {vout: stub_out}

        tx_input.source_transaction = _SrcTx()
        return tx_input

    async def collect_spendable(self, client: ElectrumXClient) -> list[tuple[UtxoRecord, str, PrivateKey]]:
        """Return ``(utxo, address, privkey)`` triples for every UTXO across known addresses.

        Address→key mapping is preserved so signing works correctly per
        UTXO. Falls back gracefully if any per-address fetch fails (the
        failed address contributes nothing rather than crashing the whole
        collection — the caller decides whether the resulting balance is
        enough).
        """
        used = [r for r in self.addresses.values() if r.used]
        if not used:
            return []

        # Fan out one get_utxos call per used address; preserve the
        # address (and therefore the key derivation path) per result.
        results = await asyncio.gather(
            *[client.get_utxos(script_hash_for_address(r.address)) for r in used],
            return_exceptions=True,
        )

        triples: list[tuple[UtxoRecord, str, PrivateKey]] = []
        for rec, result in zip(used, results, strict=True):
            if not isinstance(result, list):
                # Network error for this one address — log via the
                # client's own error handling, drop on the floor here.
                continue
            privkey = self._privkey_for(rec.change, rec.index)
            for utxo in result:
                triples.append((utxo, rec.address, privkey))
        return triples

    def build_send_tx(
        self,
        triples: list[tuple[UtxoRecord, str, PrivateKey]],
        to_address: str,
        photons: int,
        *,
        fee_rate: int = DEFAULT_FEE_RATE,
        change_address: str | None = None,
    ) -> Transaction:
        """Build and sign a P2PKH transfer from HD UTXOs to *to_address*.

        Pure offline operation. Mirrors :meth:`RxdWallet.build_send_tx`
        but accepts (utxo, address, privkey) triples so each input is
        signed by the correct HD-derived key.

        ``change_address`` defaults to the next unused internal index;
        callers can override (e.g. to keep change on the external chain
        for a single-address-style wallet).
        """
        if not isinstance(photons, int) or isinstance(photons, bool):
            raise ValidationError("photons must be int")
        if photons <= 0:
            raise ValidationError("photons must be > 0")
        if photons < DUST_THRESHOLD:
            raise ValidationError(f"photons below dust threshold ({DUST_THRESHOLD})")
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("fee_rate must be a positive int")
        if not triples:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        if change_address is None:
            change_idx = self._next_change_index()
            change_address = self._derive_address(1, change_idx)
        elif not validate_address(change_address):
            raise ValidationError("change_address is not a valid P2PKH address")

        # Greedy descending-by-value selection.
        sorted_triples = sorted(triples, key=lambda t: t[0].value, reverse=True)

        recipient_script = P2PKH().lock(to_address)
        change_script = P2PKH().lock(change_address)

        min_input_bytes = 148
        per_input_fee_cushion = min_input_bytes * fee_rate
        base_fee_cushion = 80 * fee_rate

        selected: list[tuple[UtxoRecord, str, PrivateKey]] = []
        total_in = 0
        for triple in sorted_triples:
            selected.append(triple)
            total_in += triple[0].value
            target = photons + base_fee_cushion + per_input_fee_cushion * len(selected)
            if total_in >= target:
                break

        if total_in < photons:
            raise ValidationError("Insufficient funds for requested amount")

        # Trial pass.
        inputs = [self._build_utxo_input(u, addr, pk) for u, addr, pk in selected]
        trial_change = max(DUST_THRESHOLD, total_in - photons - base_fee_cushion)
        trial_outputs = [
            TransactionOutput(recipient_script, photons),
            TransactionOutput(change_script, trial_change),
        ]
        trial_tx = Transaction(tx_inputs=inputs, tx_outputs=trial_outputs)
        trial_tx.sign()
        trial_size = trial_tx.byte_length()
        fee = trial_size * fee_rate

        if total_in < photons + fee:
            raise ValidationError("Insufficient funds after fee")

        change_value = total_in - photons - fee

        # Reset unlocking scripts so sign() rebuilds signatures over the
        # FINAL outputs, not the trial outputs (test_preimage.py).
        for inp in inputs:
            inp.unlocking_script = None

        final_outputs = [TransactionOutput(recipient_script, photons)]
        if change_value >= DUST_THRESHOLD:
            final_outputs.append(TransactionOutput(change_script, change_value))

        final_tx = Transaction(tx_inputs=inputs, tx_outputs=final_outputs)
        final_tx.sign()
        return final_tx

    def build_send_max_tx(
        self,
        triples: list[tuple[UtxoRecord, str, PrivateKey]],
        to_address: str,
        *,
        fee_rate: int = DEFAULT_FEE_RATE,
    ) -> Transaction:
        """Sweep all *triples* to *to_address* minus fee. No change output."""
        if not validate_address(to_address):
            raise ValidationError("to_address is not a valid P2PKH address")
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("fee_rate must be a positive int")
        if not triples:
            raise ValidationError("Insufficient funds: no UTXOs supplied")

        total_in = sum(t[0].value for t in triples)
        if total_in <= DUST_THRESHOLD:
            raise ValidationError("Insufficient funds: total below dust threshold")

        recipient_script = P2PKH().lock(to_address)
        inputs = [self._build_utxo_input(u, addr, pk) for u, addr, pk in triples]

        trial_tx = Transaction(
            tx_inputs=inputs,
            tx_outputs=[TransactionOutput(recipient_script, total_in - DUST_THRESHOLD)],
        )
        trial_tx.sign()
        size = trial_tx.byte_length()
        fee = size * fee_rate
        out_value = total_in - fee
        if out_value < DUST_THRESHOLD:
            raise ValidationError("Insufficient funds to cover fee")

        for inp in inputs:
            inp.unlocking_script = None

        final_tx = Transaction(
            tx_inputs=inputs,
            tx_outputs=[TransactionOutput(recipient_script, out_value)],
        )
        final_tx.sign()
        return final_tx

    async def send(
        self,
        client: ElectrumXClient,
        to_address: str,
        photons: int,
        *,
        fee_rate: int = DEFAULT_FEE_RATE,
        change_address: str | None = None,
    ) -> str:
        """Fetch UTXOs, build, sign, broadcast. Returns broadcast txid.

        Raises :class:`ValidationError` on bad inputs or insufficient
        funds, :class:`NetworkError` on RPC failure.
        """
        triples = await self.collect_spendable(client)
        tx = self.build_send_tx(
            triples,
            to_address,
            photons,
            fee_rate=fee_rate,
            change_address=change_address,
        )
        txid = await client.broadcast(tx.serialize())
        return str(txid)

    async def send_max(
        self,
        client: ElectrumXClient,
        to_address: str,
        *,
        fee_rate: int = DEFAULT_FEE_RATE,
    ) -> str:
        """Sweep all UTXOs to *to_address* minus fee. Returns broadcast txid."""
        triples = await self.collect_spendable(client)
        tx = self.build_send_max_tx(triples, to_address, fee_rate=fee_rate)
        txid = await client.broadcast(tx.serialize())
        return str(txid)


def _derive_enc_key(seed: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256-GCM key from the BIP39 seed and a per-file salt.

    scrypt with n=2^14 puts a per-attempt CPU+memory cost on offline
    cracking even if the file salt is known. The seed itself is the
    high-entropy secret — scrypt's role here is slowing brute-force
    rather than entropy stretching.

    Closes ultrareview re-review N3 (was previously hash256(seed)[:32],
    a single SHA-256d round with no salt — a precomputed table built
    once would attack every wallet derived from the same mnemonic).
    """
    return hashlib.scrypt(
        seed,
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=128 * 1024 * 1024,
        dklen=32,
    )
