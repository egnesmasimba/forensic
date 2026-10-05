"""Encrypted-at-rest capture container.

A capture file is a classic PCAP stream, so it is encrypted as one authenticated
stream. The container prefix records the format version and link type in the
clear because both are needed to open the file at all; they are additionally
bound into the encryption associated data, so an attacker cannot retag a file as
a different link type without breaking authentication.

Layout: ``EFMTTCAP1`` | version u8 | linktype u32 | AES-128-GCM stream(PCAP bytes)
"""
from __future__ import annotations

import io
import struct
import tempfile
from pathlib import Path

from evidence.crypto import EvidenceCipher, EvidenceEncryptionError, Keyring

MAGIC = b"EFMTTCAP1"
VERSION = 1
HEADER_SIZE = len(MAGIC) + 5


class SecureCaptureError(ValueError):
    pass


def _associated(key_id: str, linktype: int) -> bytes:
    return b"efmtt-capture\x00" + key_id.encode() + b"\x00" + struct.pack("!I", linktype)


def open_cipher(config, passphrase: str | None = None) -> tuple[EvidenceCipher, str]:
    """Build the evidence cipher for the sensor's configured keyring."""
    if not config.encryption_keyring:
        raise SecureCaptureError("No keyring is configured for capture encryption")
    keyring = Keyring.open(Path(config.encryption_keyring), wrap_with=passphrase)
    key_id = config.encryption_key_id
    if key_id not in keyring:
        raise SecureCaptureError(f"Key {key_id} is not present in the keyring")
    return EvidenceCipher(keyring), key_id


def write_encrypted_capture(path: Path, linktype: int, frames, cipher: EvidenceCipher,
                            key_id: str, context: str = "network-sensor") -> dict:
    """Encrypt frames into ``path`` and return a manifest describing the result."""
    with SecureCaptureWriter(path, linktype, cipher, key_id, context) as writer:
        for record in frames:
            writer.write(*record[:3])
    return writer.manifest


class SecureCaptureWriter:
    """Buffers a live capture and writes one authenticated container on close.

    Frames accumulate in memory up to ``memory_limit`` bytes. Beyond that the
    buffer spills to a private temporary file so a long capture cannot exhaust
    RAM. The manifest reports when that happened, because a spilled buffer means
    plaintext briefly existed outside the encrypted container.
    """

    def __init__(self, path: Path, linktype: int, cipher: EvidenceCipher, key_id: str,
                 context: str = "network-sensor", memory_limit: int = 64 * 1024 * 1024):
        self.path = Path(path)
        self.linktype = linktype
        self.cipher = cipher
        self.key_id = key_id
        self.context = context
        self.packets = 0
        self.plaintext_bytes = 0
        self.manifest: dict = {}
        self._buffer = tempfile.SpooledTemporaryFile(max_size=memory_limit)
        from .packets import PcapWriter
        self._writer = PcapWriter(self._buffer, linktype)

    def write(self, timestamp: float, data: bytes, original: int | None = None) -> None:
        self._writer.write(timestamp, data, original)
        self.packets += 1
        self.plaintext_bytes += len(data)

    def size(self) -> int:
        return self._buffer.tell()

    def close(self) -> dict:
        try:
            self._buffer.seek(0)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("xb") as handle:
                handle.write(MAGIC + bytes([VERSION]) + struct.pack("!I", self.linktype))
                self.cipher.encrypt_stream(
                    self._buffer, handle, associated=_associated(self.key_id, self.linktype) + self.context.encode())
        finally:
            spilled = getattr(self._buffer, "_rolled", True)
            try:
                self._buffer.close()
            except OSError:
                pass
        self.manifest = {"path": str(self.path), "packets": self.packets,
                         "plaintext_bytes": self.plaintext_bytes,
                         "stored_bytes": self.path.stat().st_size, "linktype": self.linktype,
                         "key_id": self.key_id, "encrypted": True,
                         "buffer_spilled_to_disk": bool(spilled)}
        return self.manifest

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is None or kind is KeyboardInterrupt:
            self.close()
        else:
            self._buffer.close()
        return False


class PlainCaptureWriter:
    """Unencrypted capture sink with the same interface, used when no keyring is configured."""

    def __init__(self, path: Path, linktype: int):
        from .packets import PcapWriter
        self.path = Path(path)
        self.manifest = None
        self._stream = self.path.open("xb")
        self._writer = PcapWriter(self._stream, linktype)
        self._size = 0

    def write(self, timestamp: float, data: bytes, original: int | None = None) -> None:
        self._writer.write(timestamp, data, original)
        self._size += len(data)

    def size(self) -> int:
        return self._stream.tell()

    def close(self) -> None:
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()
        return False


def open_sink(config: SensorConfig, path: Path, linktype: int, passphrase: str | None = None):
    """Return the capture sink the configuration asks for."""
    if not config.encryption_enabled:
        return PlainCaptureWriter(path, linktype)
    cipher, key_id = open_cipher(config, passphrase or None)
    return SecureCaptureWriter(path, linktype, cipher, key_id, config.encryption_context)


def read_encrypted_capture(path: Path, cipher: EvidenceCipher, key_id: str,
                           context: str = "network-sensor") -> io.BytesIO:
    """Decrypt a container back into a PCAP stream in memory for analysis."""
    with Path(path).open("rb") as handle:
        header = handle.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
            raise SecureCaptureError("Not an encrypted EFMTT capture file")
        version, linktype = header[len(MAGIC)], struct.unpack("!I", header[len(MAGIC) + 1:])[0]
        if version != VERSION:
            raise SecureCaptureError(f"Unsupported capture container version {version}")
        sink = io.BytesIO()
        try:
            cipher.decrypt_stream(handle, sink, _associated(key_id, linktype) + context.encode())
        except EvidenceEncryptionError as error:
            raise SecureCaptureError(f"Encrypted capture failed authentication: {error}") from error
    sink.seek(0)
    return sink


def container_info(path: Path) -> dict:
    """Read container metadata without decrypting, for evidence inventories."""
    with Path(path).open("rb") as handle:
        header = handle.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
        return {"encrypted": False}
    version, linktype = header[len(MAGIC)], struct.unpack("!I", header[len(MAGIC) + 1:])[0]
    return {"encrypted": True, "version": version, "linktype": linktype,
            "stored_bytes": Path(path).stat().st_size, "container": "efmtt-cap1"}
