"""Bounded content inspection shared by the agent and investigation server.

No attachment is executed and archives are inspected in memory, never extracted.
Encrypted/unsupported content is reported explicitly rather than guessed as readable.
"""
import gzip
import hashlib
import io
import math
import re
import tarfile
import zipfile
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree

MAX_FILE = 8 * 1024 * 1024
MAX_TEXT = 32768
MAX_EXPANSION = 2 * 1024 * 1024
DEFAULT_TERMS = ("confidential", "private key", "password", "customer data", "bank account", "internal only")


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "template"):
            self.hidden.append(tag)

    def handle_endtag(self, tag):
        if tag in self.hidden:
            self.hidden = self.hidden[:self.hidden.index(tag)]

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def html_text(value):
    parser = VisibleText()
    parser.feed(value[:MAX_FILE])
    return " ".join(" ".join(parser.parts).split())[:MAX_TEXT]


def normalize_domain(value):
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid recipient domain")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or "." not in value:
        raise ValueError("Invalid recipient domain")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise ValueError("Invalid recipient domain")
    return value


def safe_url(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return ""
        return urlunsplit((parsed.scheme, parsed.hostname, parsed.path[:500], "", ""))[:600]
    except ValueError:
        return ""


def analyze_text(value, terms=DEFAULT_TERMS):
    lower = value.casefold()
    return {"characters": len(value), "sensitive_terms": [term for term in terms if term.casefold() in lower][:100],
            "links": list(dict.fromkeys(filter(None, (safe_url(url.rstrip(".,);>")) for url in re.findall(r"https?://[^\s\"<]+", value)))))[:50]}


def scan_bytes(data, filename="", *, terms=DEFAULT_TERMS):
    result = {"filename": Path(filename.replace("\\", "/")).name[:255], "size": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "format": "binary", "archive": False,
              "encryption": "unknown", "encryption_basis": "No recognized encryption indicator",
              "text": "", "partial": False, "notes": [], "members": []}
    if len(data) > MAX_FILE:
        result.update(partial=True, notes=["File exceeds the 8 MB content-scanning limit"])
        return result
    lower_name = filename.lower()
    text_value = ""
    try:
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                office = any(i.filename.startswith(("word/", "xl/", "ppt/")) for i in infos)
                result.update(format="office_zip" if office else "zip", archive=not office,
                              encryption="confirmed" if any(i.flag_bits & 1 for i in infos) else "not_detected",
                              encryption_basis="ZIP member encryption flag")
                budget = MAX_EXPANSION
                for item in infos[:100]:
                    member = {"name": item.filename[:255], "size": item.file_size, "encrypted": bool(item.flag_bits & 1)}
                    result["members"].append(member)
                    if item.is_dir() or member["encrypted"]:
                        continue
                    if item.file_size > min(budget, 512 * 1024) or item.file_size / max(1, item.compress_size) > 100:
                        result["partial"] = True
                        result["notes"].append("Archive expansion limit reached")
                        continue
                    raw = archive.read(item)
                    budget -= len(raw)
                    if item.filename.lower().endswith((".xml", ".txt", ".csv", ".json", ".html", ".htm", ".log")):
                        value = raw.decode("utf-8", errors="replace")
                        if item.filename.lower().endswith(".xml"):
                            root = ElementTree.fromstring(raw)
                            value = " ".join(root.itertext())
                        elif item.filename.lower().endswith((".html", ".htm")):
                            value = html_text(value)
                        text_value += "\n" + value[:MAX_TEXT]
                        text_value = text_value[:MAX_TEXT]
                result["partial"] |= len(infos) > 100 or len(text_value) >= MAX_TEXT
        elif data.startswith(b"\x1f\x8b"):
            result.update(format="gzip", archive=True, encryption="not_detected", encryption_basis="Gzip has no native encryption")
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                raw = stream.read(MAX_EXPANSION + 1)
            result["partial"] = len(raw) > MAX_EXPANSION
            if not result["partial"]:
                text_value = raw.decode("utf-8", errors="replace")[:MAX_TEXT]
        elif len(data) > 262 and data[257:262] == b"ustar":
            result.update(format="tar", archive=True, encryption="not_detected", encryption_basis="Tar has no native encryption")
            budget = MAX_EXPANSION
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for index, item in enumerate(archive):
                    if index >= 100:
                        result["partial"] = True
                        break
                    result["members"].append({"name": item.name[:255], "size": item.size, "encrypted": False})
                    if item.isfile() and item.size <= min(budget, 512 * 1024) and item.name.lower().endswith((".txt", ".csv", ".json", ".log")):
                        stream = archive.extractfile(item)
                        raw = stream.read(min(item.size, budget)) if stream else b""
                        budget -= len(raw)
                        text_value = (text_value + "\n" + raw.decode("utf-8", errors="replace"))[:MAX_TEXT]
                    elif item.isfile():
                        result["partial"] = True
        elif data.startswith(b"%PDF-"):
            result["format"] = "pdf"
            try:
                from pypdf import PdfReader
                reader = PdfReader(io.BytesIO(data))
                result.update(encryption="confirmed" if reader.is_encrypted else "not_detected", encryption_basis="PDF encryption dictionary")
                if not reader.is_encrypted:
                    for page in reader.pages[:10]:
                        text_value = (text_value + "\n" + (page.extract_text() or ""))[:MAX_TEXT]
                    result["partial"] = len(reader.pages) > 10 or len(text_value) >= MAX_TEXT
            except ImportError:
                result.update(encryption="probable" if re.search(rb"/Encrypt\s+(?:\d+\s+\d+\s+R|<<)", data) else "unknown", partial=True)
                result["notes"].append("Install pypdf for PDF text and full encryption inspection")
            except Exception as error:
                result["partial"] = True
                result["notes"].append("Unreadable PDF: " + type(error).__name__)
        elif data.startswith(b"-----BEGIN PGP MESSAGE-----") or data.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----") or data.startswith(b"age-encryption.org/v1"):
            result.update(format="encrypted_envelope", encryption="confirmed", encryption_basis="Recognized encrypted-envelope header")
        elif data.startswith(b"7z\xbc\xaf\x27\x1c") or data.startswith(b"Rar!\x1a\x07"):
            result.update(format="7z" if data.startswith(b"7z") else "rar", archive=True, partial=True)
            result["notes"].append("Archive recognized; encrypted headers and member contents require a vendor decoder")
        elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            result["format"] = "ole"
            if "EncryptedPackage".encode("utf-16-le") in data and "EncryptionInfo".encode("utf-16-le") in data:
                result.update(encryption="probable", encryption_basis="Office encryption stream-name indicators")
            result["partial"] = True
        elif lower_name.endswith((".txt", ".csv", ".json", ".xml", ".log", ".html", ".htm", ".md", ".sql")) or b"\0" not in data[:8192]:
            try:
                value = data.decode("utf-8-sig")
                if lower_name.endswith((".html", ".htm")) or value.lstrip().lower().startswith(("<!doctype html", "<html")):
                    result["format"], text_value = "html", html_text(value)
                else:
                    result["format"], text_value = "text", value[:MAX_TEXT]
                result.update(encryption="not_detected", encryption_basis="Readable text; not an encryption guarantee", partial=len(value) > MAX_TEXT)
            except UnicodeDecodeError:
                result["notes"].append("Unsupported text encoding or opaque binary content")
    except (ValueError, OSError, EOFError, zipfile.BadZipFile, tarfile.TarError, ElementTree.ParseError, RuntimeError) as error:
        result["partial"] = True
        result["notes"].append("Malformed or unsupported content: " + type(error).__name__)
    sample = data[:65536]
    if sample:
        counts = Counter(sample)
        entropy = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts.values())
        result["entropy"] = round(entropy, 3)
        if result["encryption"] == "unknown" and len(sample) >= 1024 and entropy > 7.5:
            result["notes"].append("High entropy can indicate compression or encryption; it does not prove encryption")
    result["text"] = text_value[:MAX_TEXT]
    result["analysis"] = analyze_text(result["text"], terms)
    return result


def parse_email(raw, *, client="eml", direction="unknown", observed_at=None):
    if len(raw) > MAX_FILE:
        raise ValueError("Message exceeds the 8 MB parsing limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    recipients = []
    for field in ("to", "cc", "bcc"):
        for name, address in getaddresses(message.get_all(field, [])):
            if "@" not in address:
                continue
            try:
                domain = normalize_domain(address.rsplit("@", 1)[1])
            except ValueError:
                continue
            recipients.append({"kind": field, "address": address[:320], "domain": domain})
    when = observed_at or datetime.now(timezone.utc)
    try:
        dated = parsedate_to_datetime(str(message.get("date", "")))
        if dated and dated.tzinfo:
            when = dated.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    body, attachments, notes, parts = [], [], [], 0
    expansion = MAX_FILE
    encrypted_message = message.get_content_type() == "multipart/encrypted" or (
        message.get_content_type() in ("application/pkcs7-mime", "application/x-pkcs7-mime") and message.get_param("smime-type") == "enveloped-data")
    for part in message.walk():
        parts += 1
        if parts > 200:
            notes.append("MIME part limit reached")
            break
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True) or b""
        expansion -= len(data)
        if expansion < 0:
            notes.append("Decoded message size limit reached")
            break
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            if len(attachments) >= 30:
                notes.append("Attachment count limit reached")
                break
            scan = scan_bytes(data, filename or "attachment.bin")
            attachments.append(scan)
        elif part.get_content_type() in ("text/plain", "text/html"):
            charset = part.get_content_charset() or "utf-8"
            try:
                value = data.decode(charset, errors="replace")
            except LookupError:
                value = data.decode("utf-8", errors="replace")
                notes.append("Unknown message charset")
            body.append(html_text(value) if part.get_content_type() == "text/html" else value[:MAX_TEXT])
    text_value = "\n".join(dict.fromkeys(body))[:MAX_TEXT]
    if message.defects:
        notes.extend(type(d).__name__ for d in message.defects)
    return {"message_id": str(message.get("message-id") or hashlib.sha256(raw).hexdigest())[:200],
            "client": client, "direction": direction, "sender": str(message.get("from", ""))[:320],
            "subject": str(message.get("subject", ""))[:200], "recipients": recipients[:200],
            "occurred_at": when.astimezone(timezone.utc).isoformat(), "body": text_value,
            "body_analysis": analyze_text(text_value), "attachments": attachments, "encrypted_message": encrypted_message,
            "sha256": hashlib.sha256(raw).hexdigest(), "partial": bool(notes) or len(text_value) >= MAX_TEXT or len(recipients) > 200 or bool(message.get("X-Capture-Partial")),
            "notes": notes[:30]}
