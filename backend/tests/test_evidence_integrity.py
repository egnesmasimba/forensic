"""Evidence integrity: AES-128-GCM encryption, chunked streaming, RSA signing.

These tests cover the security-critical paths: authenticated encryption,
truncation and tamper detection, keyring passphrase handling, and signature
verification including the MD5 digest the spec requires.
"""
import base64
import io
import json

import pytest

from evidence.crypto import (
    TAG_BYTES,
    EvidenceCipher,
    EvidenceEncryptionError,
    Keyring,
    generate_keyring,
)
from evidence.signing import EvidenceSigner, generate_keypair, key_identifier, verify_signature


@pytest.fixture
def keyring():
    return generate_keyring("test-key")


@pytest.fixture
def cipher(keyring):
    return EvidenceCipher(keyring)


# -- single buffer encryption -------------------------------------------------

def test_roundtrip(cipher):
    blob = cipher.encrypt(b"chain of custody", b"case-7")
    assert cipher.decrypt(blob, b"case-7") == b"chain of custody"


def test_associated_data_is_bound(cipher):
    blob = cipher.encrypt(b"payload", b"case-7")
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt(blob, b"case-8")


def test_ciphertext_tamper_is_detected(cipher):
    blob = bytearray(cipher.encrypt(b"payload", b""))
    blob[0] ^= 0x01
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt(bytes(blob))


def test_tag_tamper_is_detected(cipher):
    blob = bytearray(cipher.encrypt(b"payload", b""))
    blob[-1] ^= 0x01
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt(bytes(blob))


def test_unknown_key_is_refused(keyring):
    other = EvidenceCipher(generate_keyring("other-key"))
    with pytest.raises(EvidenceEncryptionError):
        other.decrypt(EvidenceCipher(keyring).encrypt(b"payload", b""), b"")


# -- chunked streaming --------------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, 100, 65536, 1 << 20, (1 << 20) + 7, 5 << 20])
def test_stream_roundtrip(cipher, size):
    data = bytes(size)
    sink = io.BytesIO()
    written = cipher.encrypt_stream(io.BytesIO(data), sink, b"ctx", chunk_bytes=1 << 18)
    recovered = io.BytesIO()
    read = cipher.decrypt_stream(io.BytesIO(sink.getvalue()), recovered, b"ctx")
    assert written == read == size
    assert recovered.getvalue() == data


def test_stream_context_is_bound(cipher):
    sink = io.BytesIO()
    cipher.encrypt_stream(io.BytesIO(b"payload"), sink, b"ctx-a")
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt_stream(io.BytesIO(sink.getvalue()), io.BytesIO(), b"ctx-b")


@pytest.mark.parametrize("truncate", [1, 8, 16, TAG_BYTES, 64])
def test_stream_truncation_is_detected(cipher, truncate):
    sink = io.BytesIO()
    cipher.encrypt_stream(io.BytesIO(bytes(300000)), sink, b"ctx", chunk_bytes=1 << 18)
    blob = sink.getvalue()
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt_stream(io.BytesIO(blob[:-truncate]), io.BytesIO(), b"ctx")


def test_stream_body_tamper_is_detected(cipher):
    sink = io.BytesIO()
    cipher.encrypt_stream(io.BytesIO(bytes(200000)), sink, b"ctx", chunk_bytes=1 << 16)
    blob = bytearray(sink.getvalue())
    blob[1000] ^= 0xFF
    with pytest.raises(EvidenceEncryptionError):
        cipher.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), b"ctx")


# -- keyring ------------------------------------------------------------------

def test_keyring_plaintext_roundtrip(tmp_path):
    path = generate_keyring("k1").save(tmp_path / "ring.json")
    loaded = Keyring.open(path)
    assert "k1" in loaded
    assert loaded.active == "k1"


def test_keyring_wrapped_roundtrip(tmp_path):
    original = generate_keyring("k1")
    path = original.save(tmp_path / "ring.json", wrap_with="correct horse")
    loaded = Keyring.open(path, wrap_with="correct horse")
    assert loaded.get("k1").fingerprint() == original.get("k1").fingerprint()


def test_wrapped_keyring_requires_passphrase(tmp_path):
    path = generate_keyring("k1").save(tmp_path / "ring.json", wrap_with="correct horse")
    with pytest.raises(EvidenceEncryptionError):
        Keyring.open(path)
    with pytest.raises(EvidenceEncryptionError):
        Keyring.open(path, wrap_with="wrong")


def test_keyring_loads_keys_from_document(keyring):
    document = json.loads(json.dumps(keyring.export()))
    assert Keyring.load(document).active == "test-key"


def test_keyring_rejects_unknown_version():
    with pytest.raises(EvidenceEncryptionError):
        Keyring.load({"version": 99, "keys": []})


def test_keyring_write_is_atomic(tmp_path):
    target = tmp_path / "ring.json"
    generate_keyring("k1").save(target)
    generate_keyring("k2").save(target)
    assert not list(tmp_path.glob("*.tmp"))
    assert Keyring.open(target).active == "k2"


# -- signing ------------------------------------------------------------------

@pytest.fixture(scope="module")
def signing_pair():
    return generate_keypair(2048, "signer-1")


@pytest.fixture(scope="module")
def signed(signing_pair):
    private, public, key_id = signing_pair
    record = EvidenceSigner(private, key_id).sign_bytes(b"evidence payload", subject="capture-1", actor="admin")
    return record, public


def test_signature_verifies(signed):
    record, public = signed
    result = verify_signature(record, public, "capture-1", data=b"evidence payload")
    assert result.valid and result.md5_matches and result.sha256_matches
    assert result.key_id == "signer-1"


def test_required_md5_digest_is_present(signed):
    record, _ = signed
    assert len(record["md5"]) == 32
    assert len(record["sha256"]) == 64


def test_modified_content_fails(signed):
    record, public = signed
    result = verify_signature(record, public, "capture-1", data=b"altered payload")
    assert not result.valid and not result.md5_matches and not result.sha256_matches


def test_subject_mismatch_fails(signed):
    record, public = signed
    result = verify_signature(record, public, "capture-2", data=b"evidence payload")
    assert not result.valid
    assert "subject" in result.reason


def test_wrong_key_fails(signed):
    record, _ = signed
    _, other_public, _ = generate_keypair(2048, "other")
    assert not verify_signature(record, other_public, "capture-1", data=b"evidence payload").valid


def test_forged_digest_field_fails(signed):
    record, public = signed
    forged = dict(record, md5="0" * 32)
    assert not verify_signature(forged, public, "capture-1", data=b"evidence payload").valid


def test_tampered_statement_fails(signed):
    record, public = signed
    statement = dict(json.loads(base64.b64decode(record["statement"])), actor="root")
    forged = dict(record, statement=base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()).decode())
    assert not verify_signature(forged, public, "capture-1", data=b"evidence payload").valid


def test_signature_without_content_still_authenticates(signed):
    record, public = signed
    result = verify_signature(record, public, "capture-1")
    assert result.valid
    assert not result.md5_matches and not result.sha256_matches


def test_key_identifier_is_stable(signing_pair):
    _, public, _ = signing_pair
    assert key_identifier(public) == key_identifier(public)
    assert len(key_identifier(public)) == 16
    assert key_identifier(public) != key_identifier(generate_keypair(2048, "x")[1])


def test_weak_keys_are_rejected():
    with pytest.raises(ValueError):
        generate_keypair(1024, "weak")