"""MD5 digests with RSA digital signatures for recorded evidence.

The MD5-with-RSA construction is what the product requirement specifies for
recorded data. MD5 is not collision resistant, so a SHA-256 digest is computed
and signed alongside it: verification reports the MD5 match the requirement asks
for, while the signed SHA-256 is the value that actually detects substitution.
Neither scheme is a legal claim of admissibility; they establish tamper evidence
only, and that assessment belongs to a court.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGNATURE_ALGORITHM = "MD5withRSA"
SUPPLEMENTARY_ALGORITHM = "SHA256withRSA"
MIN_KEY_BITS = 2048
MAX_KEY_BITS = 4096
READ_CHUNK = 1 << 20
SIGNATURE_BYTES_LIMIT = 4096


class EvidenceSignatureError(ValueError):
    """Raised for unusable keys, oversized input, or malformed signature files."""


@dataclass(frozen=True)
class SignatureVerification:
    valid: bool
    md5_matches: bool
    sha256_matches: bool
    reason: str
    key_id: str = ""
    size: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def generate_keypair(bits: int = 3072, key_id: str = "") -> tuple[bytes, bytes, str]:
    """Return (private PEM, public PEM, key id). RSA keys are generated locally."""
    if not MIN_KEY_BITS <= bits <= MAX_KEY_BITS:
        raise EvidenceSignatureError(f"RSA key size must be {MIN_KEY_BITS}-{MAX_KEY_BITS} bits")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    identifier = key_id or hashlib.sha256(public_pem).hexdigest()[:16]
    return private_pem, public_pem, identifier


def key_identifier(public_pem: bytes) -> str:
    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as error:
        raise EvidenceSignatureError("Public key is not a valid PEM RSA key") from error
    if not isinstance(key, rsa.RSAPublicKey):
        raise EvidenceSignatureError("Only RSA public keys are supported")
    return hashlib.sha256(public_pem).hexdigest()[:16]


def _load_private(pem: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as error:
        raise EvidenceSignatureError("Private key is not an unencrypted PEM RSA key") from error
    if not isinstance(key, rsa.RSAPrivateKey):
        raise EvidenceSignatureError("Only RSA private keys are supported")
    if key.key_size < MIN_KEY_BITS:
        raise EvidenceSignatureError(f"RSA keys must be at least {MIN_KEY_BITS} bits")
    return key


def _load_public(pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as error:
        raise EvidenceSignatureError("Public key is not a valid PEM RSA key") from error
    if not isinstance(key, rsa.RSAPublicKey):
        raise EvidenceSignatureError("Only RSA public keys are supported")
    return key


def digest_file(path: Path | str) -> tuple[bytes, bytes, int]:
    """Return (md5, sha256, size) for a file, reading it in bounded chunks."""
    md5, sha256, size = hashlib.md5(), hashlib.sha256(), 0
    try:
        with Path(path).open("rb") as stream:
            while block := stream.read(READ_CHUNK):
                md5.update(block)
                sha256.update(block)
                size += len(block)
    except OSError as error:
        raise EvidenceSignatureError(f"Cannot read {Path(path).name}: {error}") from error
    return md5.digest(), sha256.digest(), size


class EvidenceSigner:
    """Signs recorded evidence with RSA over the MD5 and SHA-256 digests."""

    def __init__(self, private_pem: bytes, key_id: str = ""):
        self._key = _load_private(private_pem)
        self._public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_id = key_id or hashlib.sha256(self._public_pem).hexdigest()[:16]

    @property
    def public_pem(self) -> bytes:
        return self._public_pem

    def describe(self) -> dict:
        return {"key_id": self.key_id, "algorithm": SIGNATURE_ALGORITHM,
                "supplementary_algorithm": SUPPLEMENTARY_ALGORITHM,
                "rsa_bits": self._key.key_size}

    def sign_bytes(self, data: bytes, subject: str = "", actor: str = "") -> dict:
        if len(data) > 256 * 1024 * 1024:
            raise EvidenceSignatureError("Refusing to sign more than 256 MB in memory; use sign_file")
        return self._sign_digests(hashlib.md5(data).digest(), hashlib.sha256(data).digest(),
                                  len(data), subject, actor)

    def sign_file(self, path: Path | str, subject: str = "", actor: str = "") -> dict:
        source = Path(path)
        md5, sha256, size = digest_file(source)
        return self._sign_digests(md5, sha256, size, subject or source.name, actor)

    def _sign_digests(self, md5: bytes, sha256: bytes, size: int, subject: str, actor: str) -> dict:
        # The statement binds both digests to the signer and the subject, so a
        # valid MD5 cannot be replayed onto different content.
        statement = json.dumps({
            "subject": subject[:512],
            "signed_by": actor[:120],
            "algorithm": SIGNATURE_ALGORITHM,
            "supplementary_algorithm": SUPPLEMENTARY_ALGORITHM,
            "md5": md5.hex(),
            "sha256": sha256.hex(),
            "size": size,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {
            "version": 1,
            "key_id": self.key_id,
            "rsa_bits": self._key.key_size,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "size": size,
            "md5": md5.hex(),
            "sha256": sha256.hex(),
            "statement": base64.b64encode(statement).decode(),
            "signature": base64.b64encode(
                self._key.sign(statement, padding.PKCS1v15(), hashes.MD5())).decode(),
            "supplementary_signature": base64.b64encode(
                self._key.sign(statement, padding.PKCS1v15(), hashes.SHA256())).decode(),
        }


def verify_signature(record: dict, public_pem: bytes, subject: str = "", data: bytes | None = None,
                     path: Path | str | None = None) -> SignatureVerification:
    """Verify a signature record against content, a byte buffer, or a file.

    Content is only read when one of `data`/`path` is supplied; without it the
    digests inside the record are reported but not re-derived, and the reason
    says so rather than implying a match was confirmed.
    """
    for name in ("md5", "sha256", "signature", "statement", "key_id"):
        if not isinstance(record.get(name), str) or not record[name]:
            return SignatureVerification(False, False, False, f"Signature record is missing {name}")
    try:
        statement = base64.b64decode(record["statement"], validate=True)
        signature = base64.b64decode(record["signature"], validate=True)
        supplementary = base64.b64decode(record.get("supplementary_signature", ""), validate=True) if record.get("supplementary_signature") else None
    except (ValueError, TypeError):
        return SignatureVerification(False, False, False, "Signature record is not valid base64",
                                    str(record.get("key_id", ""))[:64])
    if len(signature) > SIGNATURE_BYTES_LIMIT:
        return SignatureVerification(False, False, False, "Signature is larger than a single RSA block")
    try:
        key = _load_public(public_pem)
    except EvidenceSignatureError as error:
        return SignatureVerification(False, False, False, str(error), str(record["key_id"])[:64])

    supplied = None
    if data is not None:
        supplied = (hashlib.md5(data).digest(), hashlib.sha256(data).digest(), len(data))
    elif path is not None:
        supplied = digest_file(Path(path))

    matches = None
    if supplied is not None:
        md5, sha256, size = supplied
        matches = (md5.hex() == record["md5"] and sha256.hex() == record["sha256"] and size == record.get("size"))

    def _subject_ok() -> bool:
        if not subject:
            return True
        try:
            return json.loads(statement).get("subject") == subject[:512]
        except ValueError:
            return False

    if not _subject_ok():
        return SignatureVerification(False, bool(matches), bool(matches),
                                    "Signature was created for a different subject",
                                    str(record["key_id"])[:64], record.get("size", 0))
    try:
        key.verify(signature, statement, padding.PKCS1v15(), hashes.MD5())
        md5_signature_valid = True
    except InvalidSignature:
        md5_signature_valid = False
    supplementary_valid = None
    if supplementary:
        try:
            key.verify(supplementary, statement, padding.PKCS1v15(), hashes.SHA256())
            supplementary_valid = True
        except InvalidSignature:
            supplementary_valid = False
    if not md5_signature_valid:
        return SignatureVerification(False, bool(matches), bool(matches),
                                    "RSA signature does not match the signing key",
                                    str(record["key_id"])[:64], record.get("size", 0))
    if supplementary_valid is False:
        return SignatureVerification(False, bool(matches), False,
                                    "Supplementary SHA-256 signature does not verify",
                                    str(record["key_id"])[:64], record.get("size", 0))
    if matches is None:
        return SignatureVerification(True, False, False,
                                    "Signature is authentic; no content was supplied to re-derive the digests",
                                    str(record["key_id"])[:64], record.get("size", 0))
    if not matches:
        return SignatureVerification(False, False, False,
                                    "Content digest does not match the signed record",
                                    str(record["key_id"])[:64], record.get("size", 0))
    return SignatureVerification(True, True, True, "Signature and content digests verify",
                                str(record["key_id"])[:64], record.get("size", 0))


def signature_document(record: dict) -> str:
    return json.dumps(record, indent=2, sort_keys=True) + "\n"


def write_keypair(directory: Path | str, key_id: str = "", bits: int = 3072) -> dict:
    """Write a fresh private/public key pair with owner-only permissions."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem, identifier = generate_keypair(bits, key_id)
    private_path, public_path = target / f"{identifier}.key", target / f"{identifier}.pub"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    if os.name != "nt":
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    return {"key_id": identifier, "private_key": str(private_path), "public_key": str(public_path),
            "rsa_bits": bits, "algorithm": SIGNATURE_ALGORITHM}


def store_signatures(directory: Path | str) -> Path:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        target.chmod(0o700)
    return target
