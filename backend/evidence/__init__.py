"""Forensic evidence protection: AES-128 encryption and MD5-with-RSA signatures.

Shared by the web application, the network sensor, and tooling. Recorded payloads
are authenticated so tampering is detected on read, not trusted on write.
"""

from .crypto import (
    CHUNK_BYTES,
    EvidenceCipher,
    EvidenceEncryptionError,
    Keyring,
    generate_key,
    generate_keyring,
)
from .signing import (
    EvidenceSigner,
    EvidenceSignatureError,
    SignatureVerification,
    generate_keypair,
    verify_signature,
)

__all__ = [
    "CHUNK_BYTES",
    "EvidenceCipher",
    "EvidenceEncryptionError",
    "EvidenceSignatureError",
    "EvidenceSigner",
    "Keyring",
    "SignatureVerification",
    "generate_key",
    "generate_keypair",
    "generate_keyring",
    "verify_signature",
]
