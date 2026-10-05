"""Native messaging bridge for the optional Chrome/Edge capture extension."""
import base64
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

from endpoint_agent.config import Config
from endpoint_agent.content_scan import parse_email, safe_url
from endpoint_agent.protocol import AgentClient
from endpoint_agent import tls


MAX_FRAME = 4 * 1024 * 1024


def read_message(stream):
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError("Incomplete native-message header")
    length = struct.unpack("<I", header)[0]
    if not 0 < length <= MAX_FRAME:
        raise ValueError("Native-message size limit exceeded")
    body = stream.read(length)
    if len(body) != length:
        raise ValueError("Incomplete native-message body")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("Native message must be an object")
    return value


def write_message(stream, message):
    raw = json.dumps(message).encode()
    stream.write(struct.pack("<I", len(raw)) + raw)
    stream.flush()


def event_from_browser(message):
    key = str(message.get("event_key", ""))
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise ValueError("Capture needs a stable event key")
    when = datetime.fromisoformat(str(message["occurred_at"]).replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("Include a capture timezone")
    if message.get("kind") == "download":
        size = int(message.get("bytes", 0))
        if not 0 <= size <= 10**15:
            raise ValueError("Invalid download size")
        return {"type": "browser_download", "severity": "low", "event_key": key, "occurred_at": when.isoformat(),
                "payload": {"channel": "downloads", "bytes": size, "path": str(message.get("path", ""))[:2000],
                            "browser": "chrome/edge extension", "source_url": safe_url(str(message.get("source_url", ""))),
                            "transfer_status": "browser_download_completed"}}
    if message.get("kind") != "mail":
        raise ValueError("Unsupported browser capture type")
    source = safe_url(str(message.get("source_url", "")))
    from urllib.parse import urlsplit
    if urlsplit(source).hostname not in ("mail.google.com", "outlook.office.com", "outlook.office365.com", "outlook.live.com"):
        raise ValueError("Unsupported webmail origin")
    mime = EmailMessage()
    mime["Subject"] = str(message.get("subject", ""))[:200].replace("\r", " ").replace("\n", " ")
    mime["From"] = str(message.get("sender", ""))[:320].replace("\r", " ").replace("\n", " ")
    mime["Message-ID"] = "<" + key + "@webmail.capture>"
    mime["Date"] = format_datetime(when.astimezone(timezone.utc))
    recipients = message.get("recipients", [])
    if not isinstance(recipients, list) or len(recipients) > 200:
        raise ValueError("Too many recipients")
    for kind in ("to", "cc", "bcc"):
        addresses = [str(r.get("address", "")) for r in recipients if r.get("kind", "to") == kind]
        if any("\r" in address or "\n" in address or len(address) > 320 for address in addresses):
            raise ValueError("Invalid recipient")
        if addresses:
            mime[kind] = ", ".join(addresses)
    text = str(message.get("body", ""))
    mime.set_content(text[:32768])
    omitted, total = len(text) > 32768, 0
    attachments = message.get("attachments", [])
    if not isinstance(attachments, list) or len(attachments) > 30:
        raise ValueError("Too many attachments")
    metadata = []
    for attachment in attachments:
        size = int(attachment.get("size", 0))
        if size < 0 or size > 10**15:
            raise ValueError("Invalid attachment size")
        if not attachment.get("data_base64"):
            metadata.append({"filename": str(attachment.get("filename", "attachment"))[:255], "size": size,
                             "format": "unavailable", "encryption": "unknown", "text": "", "partial": True,
                             "notes": ["Webmail exposed attachment metadata only; file contents were not available"]})
            omitted = True
            continue
        raw = base64.b64decode(attachment["data_base64"], validate=True)
        total += len(raw)
        if total > 2 * 1024 * 1024 or len(raw) != size:
            raise ValueError("Attachment capture limit or size mismatch")
        mime.add_attachment(raw, maintype="application", subtype="octet-stream", filename=str(attachment.get("filename", "attachment"))[:255])
    direction = "send_intent" if message.get("send_intent") else "unknown"
    report = parse_email(mime.as_bytes(), client="webmail", direction=direction)
    report["attachments"].extend(metadata)
    report["partial"] |= omitted
    report["notes"].append("Visible DOM capture; attachment contents are available only for files selected while the extension was active")
    # Stable capture identity avoids MIME boundary changes during native-host retries.
    report["sha256"] = hashlib.sha256(json.dumps(message, sort_keys=True).encode()).hexdigest()
    return {"type": "email_capture", "severity": "low", "event_key": key, "occurred_at": when.isoformat(), "payload": report}


def run(config_path=None, origin=None, *, input_stream=None, output_stream=None):
    config = Config(config_path)
    config.load()
    allowed = config.get("browser_capture.allowed_origins", [])
    if not config.get("browser_capture.enabled", False) or origin not in allowed:
        raise ValueError("Browser capture is disabled or the extension origin is not approved")
    server, token = config.get("server_url"), config.get("agent_token")
    if not server or not token:
        raise ValueError("Configure the agent server and token before browser capture")
    input_stream, output_stream = input_stream or sys.stdin.buffer, output_stream or sys.stdout.buffer
    queue = config.get("browser_capture.queue_path") or str(config.path.parent / "browser-offline.jsonl")
    transport = tls.settings_from_config(config.data)
    with AgentClient(server, token, queue_path=queue, retries=0, timeout=10,
                     allow_insecure_http=bool(transport.get("allow_insecure_http", False)),
                     **tls.transport_options(transport, url=server)) as client:
        while True:
            message = read_message(input_stream)
            if message is None:
                return
            try:
                event = event_from_browser(message)
                sent = client.post_event(event)
                write_message(output_stream, {"ok": True, "queued": not sent})
            except (ValueError, TypeError, KeyError):
                write_message(output_stream, {"ok": False, "error": "Invalid or oversized capture"})


if __name__ == "__main__":
    try:
        run(origin=sys.argv[1] if len(sys.argv) > 1 else None)
    except (ValueError, OSError):
        write_message(sys.stdout.buffer, {"ok": False, "error": "Configure the native host, approved extension origin and agent token"})
