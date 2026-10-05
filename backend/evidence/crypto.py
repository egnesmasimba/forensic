"""AES-128-GCM encryption for recorded evidence.

The key length is fixed at 128 bits to match the recorded-data requirement.
AES-GCM is used rather than bare AES-CBC so that every recorded byte is
authenticated; a modified record fails to decrypt instead of yielding plausible
plaintext. Nothing here is a substitute for a court-admissibility opinion: the
module supplies tamper evidence, not legal weight.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"EFMTTAES"
VERSION = 1
KEY_BYTES = 16  # AES-128
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK_BYTES = 1 << 20
KEY_ID_LIMIT = 64
MIN_CHUNK = 4096
MAX_CHUNK = 1 << 24
PBKDF2_ROUNDS = 600000  # Matches the password hashing cost used by app.auth.


class EvidenceEncryptionError(ValueError):
    """Raised for malformed envelopes, unknown keys, or failed authentication."""


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=128)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 128-bit key from an operator passphrase.

    A passphrase is weaker than a random key; the keyring records which method
    produced each key so verification does not have to guess.
    """
    if not passphrase or len(passphrase) > 1024:
        raise EvidenceEncryptionError("Passphrase must be 1-1024 characters")
    if len(salt) < 16:
        raise EvidenceEncryptionError("Key derivation salt must be at least 16 bytes")
    material = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ROUNDS, KEY_BYTES)
    return material


@dataclass(frozen=True)
class EvidenceKey:
    key_id: str
    key: bytes
    derived: bool = False
    salt: bytes = b""

    def fingerprint(self) -> str:
        return hashlib.sha256(b"efmtt-key-fingerprint\0" + self.key).hexdigest()[:32]

    def describe(self) -> dict:
        return {"key_id": self.key_id, "algorithm": "AES-128-GCM",
                "derived_from_passphrase": self.derived, "fingerprint": self.fingerprint()}


class Keyring:
    """Keyed set of AES-128 keys with one active key for new recordings."""

    def __init__(self, keys: Iterable[EvidenceKey] = (), active: str | None = None):
        self._keys: dict[str, EvidenceKey] = {}
        self.active: str | None = None
        for item in keys:
            self.add(item)
        if active is not None and active not in self._keys:
            raise EvidenceEncryptionError("Active key is not present in the keyring")
        self.active = active or (next(iter(self._keys), None))

    def add(self, item: EvidenceKey):
        if not item.key_id or len(item.key_id) > KEY_ID_LIMIT or not item.key_id.isprintable():
            raise EvidenceEncryptionError("Key identifier must be 1-64 printable characters")
        if len(item.key) != KEY_BYTES:
            raise EvidenceEncryptionError("Evidence keys must be exactly 128 bits")
        if item.key_id in self._keys:
            raise EvidenceEncryptionError("Key identifier already exists")
        self._keys[item.key_id] = item
        if self.active is None:
            self.active = item.key_id

    def __contains__(self, key_id: object) -> bool:
        return key_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def get(self, key_id: str) -> EvidenceKey:
        item = self._keys.get(key_id)
        if item is None:
            raise EvidenceEncryptionError("Record references a key that this keyring does not hold")
        return item

    def add_random(self, key_id: str) -> EvidenceKey:
        item = EvidenceKey(key_id, generate_key())
        self.add(item)
        self.active = key_id
        return item

    def add_derived(self, key_id: str, passphrase: str) -> EvidenceKey:
        salt = secrets.token_bytes(16)
        item = EvidenceKey(key_id, derive_key(passphrase, salt), derived=True, salt=salt)
        self.add(item)
        self.active = key_id
        return item

    def describe(self) -> dict:
        return {"active": self.active, "keys": [item.describe() for item in self._keys.values()]}

    def export(self, wrap_with: str | None = None) -> dict:
        """Serialise the keyring.

        With `wrap_with` the key material is encrypted under a key derived from
        that passphrase; without it the material is written as base64 and the
        caller is responsible for protecting the file.
        """
        keys = [{"key_id": item.key_id, "derived": item.derived,
                 "salt": base64.b64encode(item.salt).decode(), "key": base64.b64encode(item.key).decode()}
                for item in self._keys.values()]
        payload = {"version": VERSION, "algorithm": "AES-128-GCM", "active": self.active, "keys": keys}
        if wrap_with is None:
            return payload
        salt = secrets.token_bytes(16)
        wrapped = AESGCM(derive_key(wrap_with, salt)).encrypt(
            salt, json_bytes(payload), MAGIC + b"keyring")
        return {"version": VERSION, "algorithm": "AES-128-GCM", "encrypted": True, "kdf": "pbkdf2-sha256",
                "rounds": PBKDF2_ROUNDS, "salt": base64.b64encode(salt).decode(),
                "wrapped_key": base64.b64encode(wrapped).decode()}

    @classmethod
    def load(cls, document: dict, wrap_with: str | None = None) -> "Keyring":
        if document.get("version") != VERSION:
            raise EvidenceEncryptionError("Unsupported keyring version")
        if document.get("encrypted"):
            if not wrap_with:
                raise EvidenceEncryptionError("This keyring is encrypted; supply its passphrase")
            try:
                salt = base64.b64decode(document["salt"], validate=True)
                opener = AESGCM(derive_key(wrap_with, salt))
                raw = opener.decrypt(salt, base64.b64decode(document["wrapped_key"], validate=True),
                                     MAGIC + b"keyring")
            except (InvalidTag, ValueError, KeyError) as error:
                raise EvidenceEncryptionError("Keyring passphrase is incorrect") from error
            document = json.loads(raw)
        keys = [EvidenceKey(entry["key_id"], base64.b64decode(entry["key"], validate=True),
                            bool(entry.get("derived")), base64.b64decode(entry.get("salt", ""), validate=True))
                for entry in document.get("keys", [])]
        return cls(keys, document.get("active"))

    def save(self, path: Path | str, wrap_with: str | None = None) -> Path:
        target = Path(path)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(json_bytes(self.export(wrap_with)))
        try:
            os.replace(temporary, target)
            if os.name != "nt":
                target.chmod(0o600)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
        return target

    @classmethod
    def open(cls, path: Path | str, wrap_with: str | None = None) -> "Keyring":
        source = Path(path)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise EvidenceEncryptionError(f"Cannot read keyring: {error}") from error
        return cls.load(document, wrap_with)


def generate_keyring(key_id: str = "default", passphrase: str | None = None) -> Keyring:
    ring = Keyring()
    if passphrase:
        ring.add_derived(key_id, passphrase)
    else:
        ring.add_random(key_id)
    return ring


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EvidenceCipher:
    """Authenticated AES-128-GCM envelope encryption for recorded bytes."""

    def __init__(self, keyring: Keyring):
        if not len(keyring):
            raise EvidenceEncryptionError("Keyring holds no evidence keys")
        self.keyring = keyring

    # -- single buffer ----------------------------------------------------
    def encrypt(self, plaintext: bytes, associated: bytes = b"") -> bytes:
        key = self.keyring.get(self.keyring.active)
        nonce = os.urandom(NONCE_BYTES)
        header = MAGIC + bytes([VERSION]) + _key_prefix(key.key_id)
        body = AESGCM(key.key).encrypt(nonce, plaintext, header + associated)
        return header + nonce + body

    def decrypt(self, blob: bytes, associated: bytes = b"") -> bytes:
        key_id, header, offset = _split_prefix(blob)
        key = self.keyring.get(key_id)
        if len(blob) - offset < NONCE_BYTES + TAG_BYTES:
            raise EvidenceEncryptionError("Record is truncated")
        nonce, body = blob[offset:offset + NONCE_BYTES], blob[offset + NONCE_BYTES:]
        try:
            return AESGCM(key.key).decrypt(nonce, body, header + associated)
        except InvalidTag as error:
            raise EvidenceEncryptionError("Record failed authentication; it was altered or the key is wrong") from error

    def encrypt_stream(self, source: BinaryIO, sink: BinaryIO, associated: bytes = b"", chunk_bytes: int = CHUNK_BYTES) -> int:
        return _encrypt_stream(self, source, sink, associated, chunk_bytes)

    def decrypt_stream(self, source: BinaryIO, sink: BinaryIO, associated: bytes = b"", chunk_bytes: int = CHUNK_BYTES) -> int:
        return _decrypt_stream(self, source, sink, associated, chunk_bytes)


def _key_prefix(key_id: str) -> bytes:
    raw = key_id.encode("utf-8")
    if not raw or len(raw) > 255:
        raise EvidenceEncryptionError("Key identifier must be 1-64 printable characters")
    return bytes([len(raw)]) + raw


def _split_prefix(blob: bytes) -> tuple[str, bytes, int]:
    """Split MAGIC|VERSION|keylen|key_id into (key_id, prefix, offset)."""
    if len(blob) < len(MAGIC) + 2 or blob[:len(MAGIC)] != MAGIC:
        raise EvidenceEncryptionError("Not an EFMTT encrypted record")
    if blob[len(MAGIC)] != VERSION:
        raise EvidenceEncryptionError("Unsupported encrypted record version")
    length = blob[len(MAGIC) + 1]
    if length == 0 or len(blob) < len(MAGIC) + 2 + length:
        raise EvidenceEncryptionError("Record is truncated")
    end = len(MAGIC) + 2 + length
    return blob[len(MAGIC) + 2:end].decode("utf-8", errors="replace"), blob[:end], end


def _chunks(stream: BinaryIO, chunk_bytes: int) -> Iterator[bytes]:
    while True:
        block = stream.read(chunk_bytes)
        if not block:
            return
        yield block


SEED_BYTES = 8


def _stream_aad(prefix: bytes, seed: bytes, chunk_bytes: int, associated: bytes) -> bytes:
    """Bind every chunk tag to the header, the caller's context, and the seed."""
    return hashlib.sha256(prefix + seed + struct.pack("!I", chunk_bytes) + associated).digest()


def _write_stream_header(sink: BinaryIO, key: EvidenceKey, chunk_bytes: int, associated: bytes) -> tuple[bytes, bytes]:
    prefix = MAGIC + bytes([VERSION]) + _key_prefix(key.key_id)
    seed = os.urandom(SEED_BYTES)
    sink.write(prefix + struct.pack("!I", chunk_bytes) + seed)
    return _stream_aad(prefix, seed, chunk_bytes, associated), seed


def _read_stream_header(source: BinaryIO, associated: bytes) -> tuple[str, int, bytes, bytes]:
    raw = source.read(len(MAGIC))
    if raw != MAGIC:
        raise EvidenceEncryptionError("Not an EFMTT encrypted record")
    rest = source.read(2)
    if len(rest) != 2 or rest[0] != VERSION:
        raise EvidenceEncryptionError("Unsupported encrypted record version")
    prefix = raw + rest + _read_exactly(source, rest[1], "key identifier")
    tail = _read_exactly(source, 4 + SEED_BYTES, "chunk configuration")
    chunk_bytes = struct.unpack("!I", tail[:4])[0]
    if not MIN_CHUNK <= chunk_bytes <= MAX_CHUNK:
        raise EvidenceEncryptionError("Record declares an unusable chunk size")
    seed = tail[4:]
    return _split_prefix(prefix)[0], chunk_bytes, _stream_aad(prefix, seed, chunk_bytes, associated), seed


def _read_exactly(source: BinaryIO, count: int, what: str) -> bytes:
    body = source.read(count) if 0 <= count <= 0xFFFFFF else b""
    if len(body) != count:
        raise EvidenceEncryptionError(f"Record is truncated before its {what}")
    return body


def _encrypt_stream(cipher: EvidenceCipher, source: BinaryIO, sink: BinaryIO, associated: bytes, chunk_bytes: int) -> int:
    if not MIN_CHUNK <= chunk_bytes <= MAX_CHUNK:
        raise EvidenceEncryptionError(f"Chunk size must be {MIN_CHUNK}-{MAX_CHUNK} bytes")
    key = cipher.keyring.get(cipher.keyring.active)
    engine = AESGCM(key.key)
    aad, seed = _write_stream_header(sink, key, chunk_bytes, associated)
    total = index = 0
    for block in _chunks(source, chunk_bytes):
        body = engine.encrypt(_counter_nonce(seed, index), block, aad + index.to_bytes(4, "big"))
        sink.write(struct.pack("!I", len(body)) + body)
        total += len(block)
        index += 1
    # The final tag binds the plaintext length, so truncation is detected.
    sink.write(b"\0\0\0\0" + engine.encrypt(_counter_nonce(seed, index), b"", aad + b"final" + total.to_bytes(8, "big")))
    return total


def _decrypt_stream(cipher: EvidenceCipher, source: BinaryIO, sink: BinaryIO, associated: bytes, chunk_bytes: int) -> int:
    key_id, chunk_bytes, aad, seed = _read_stream_header(source, associated)
    engine = AESGCM(cipher.keyring.get(key_id).key)
    total = index = 0
    while True:
        length = struct.unpack("!I", _read_exactly(source, 4, "chunk length"))[0]
        if length == 0:
            break
        if not TAG_BYTES < length <= chunk_bytes + TAG_BYTES:
            raise EvidenceEncryptionError("Record declares an unusable chunk length")
        body = _read_exactly(source, length, "chunk")
        try:
            block = engine.decrypt(_counter_nonce(seed, index), body, aad + index.to_bytes(4, "big"))
        except InvalidTag as error:
            raise EvidenceEncryptionError("Record failed authentication; it was altered or the key is wrong") from error
        sink.write(block)
        total += len(block)
        index += 1
    trailer = _read_exactly(source, TAG_BYTES, "final authentication tag")
    try:
        engine.decrypt(_counter_nonce(seed, index), trailer, aad + b"final" + total.to_bytes(8, "big"))
    except InvalidTag as error:
        raise EvidenceEncryptionError("Record failed authentication; it was altered or the key is wrong") from error
    return total


def _counter_nonce(seed: bytes, index: int) -> bytes:
    # 4-byte random seed plus a 64-bit counter keeps every chunk nonce unique
    # for a key; the seed is unique per record, so records never collide.
    return seed + struct.pack("!Q", index)


def file_digest(path: Path | str, algorithm: str = "sha256", chunk_bytes: int = 1 << 20) -> str:
    digest = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        while block := stream.read(chunk_bytes):
            digest.update(block)
    return digest.hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
