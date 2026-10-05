"""Stored-message metadata. Encrypted payloads stay opaque."""
from __future__ import annotations

import base64
import hashlib
import re

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION",
}
SMB2_COMMANDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT",
    5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL",
    12: "CANCEL", 13: "ECHO", 14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO",
    17: "SET_INFO", 18: "OPLOCK_BREAK",
}
SMB1_COMMANDS = {0x72: "NEGOTIATE", 0x73: "SESSION_SETUP", 0x75: "TREE_CONNECT", 0x04: "CLOSE", 0x2E: "READ", 0x2F: "WRITE"}
TNS_TYPES = {1: "CONNECT", 2: "ACCEPT", 4: "REFUSE", 5: "REDIRECT", 6: "DATA", 11: "RESEND", 12: "MARKER"}
DRDA_CODES = {0x1041: "EXCSAT", 0x2001: "ACCRDB", 0x2412: "PRPSQLSTT", 0x2414: "SQLSTT"}
FIX_REQUIRED = ("8", "9", "35", "49", "56", "34", "52")
FIX_ENCODED = {"95", "96", "354", "355"}
FIX_NAMES = {
    "8": "BeginString", "9": "BodyLength", "35": "MsgType", "34": "MsgSeqNum", "49": "SenderCompID",
    "52": "SendingTime", "56": "TargetCompID", "10": "CheckSum",
    "95": "RawDataLength", "96": "RawData", "354": "EncodedTextLen", "355": "EncodedText",
}


def http2_frames(data: bytes) -> list[dict] | None:
    if not data.startswith(HTTP2_PREFACE):
        return None
    frames = []
    index = len(HTTP2_PREFACE)
    while index + 9 <= len(data) and len(frames) < 100:
        length = int.from_bytes(data[index:index + 3], "big")
        kind = data[index + 3]
        stream = int.from_bytes(data[index + 5:index + 9], "big") & 0x7FFFFFFF
        if length > 16777215 or index + 9 + length > len(data):
            frames.append({"type": "http2_frame", "truncated": True})
            break
        frames.append({"type": "http2_frame", "frame_type": HTTP2_TYPES.get(kind, str(kind)),
                       "length": length, "stream": stream})
        index += 9 + length
    return frames


def _smb_file_bytes(payload: bytes, command: int) -> bytes | None:
    """READ response or WRITE request bytes when the declared buffer sits inside the message."""
    if len(payload) < 80:
        return None
    body = payload[64:]
    if command == 9 and len(body) >= 48 and int.from_bytes(body[:2], "little") == 49:
        data_offset = int.from_bytes(body[2:4], "little")
        length = int.from_bytes(body[4:8], "little")
    elif command == 8 and len(body) >= 16 and int.from_bytes(body[:2], "little") == 17:
        data_offset = body[2]
        length = int.from_bytes(body[4:8], "little")
    else:
        return None
    if length <= 0 or length > 65536 or data_offset < 64 or data_offset + length > len(payload):
        return None
    return payload[data_offset:data_offset + length]


def smb_message(data: bytes) -> dict | None:
    payload = data[4:] if len(data) >= 8 and data[4:8] in (b"\xfeSMB", b"\xffSMB", b"\xfdSMB") else data
    if payload.startswith(b"\xfdSMB"):
        return {"type": "smb_transform", "encrypted": True}
    if payload.startswith(b"\xfeSMB") and len(payload) >= 64:
        command = int.from_bytes(payload[12:14], "little")
        message = {"type": "smb2_header", "command": command, "command_name": SMB2_COMMANDS.get(command, f"command-{command}"),
                   "message_id": int.from_bytes(payload[24:32], "little")}
        located = _smb_file_bytes(payload, command)
        if located is not None:
            review = content_review(located)
            message["file_length"] = len(located)
            message["sha256"] = review["sha256"]
            if review.get("sensitive"):
                message["sensitive"] = review["sensitive"]
        return message
    if payload.startswith(b"\xffSMB") and len(payload) >= 32:
        command = payload[4]
        return {"type": "smb1_header", "command": command, "command_name": SMB1_COMMANDS.get(command, f"command-{command}")}
    return None


def mq_messages(data: bytes) -> tuple[list[dict], list[str]]:
    if not data.startswith(b"TSH") or len(data) < 8:
        return [], ["IBM MQ TSH was not found"]
    segment_length = int.from_bytes(data[4:8], "big")
    message = {"type": "mq_tsh", "struct_id": data[:4].decode("ascii", "replace"), "segment_length": segment_length}
    notes = ["IBM MQ TSH layout after the segment length is version-dependent and is not named"]
    window = data[8:8 + 80]
    marker = window.find(b"MD  ")
    if marker < 0:
        return [message], notes
    start = 8 + marker
    if start + 40 > len(data):
        return [message], notes
    version = int.from_bytes(data[start + 4:start + 8], "big")
    if version not in (1, 2):
        notes.append("MQMD version is not 1 or 2 in big-endian form")
        return [message], notes
    format_name = data[start + 32:start + 40].decode("ascii", "replace")
    message["mqmd_format"] = format_name
    header = 364 if version == 2 else 324
    if format_name.startswith("MQSTR"):
        body_end = min(len(data), start + header + 256, segment_length if 8 < segment_length <= len(data) else len(data))
        body = data[start + header:body_end]
        if body and all(32 <= byte < 127 or byte in (9, 10, 13) for byte in body):
            message["mqstr"] = body.decode("ascii")
        else:
            notes.append("MQSTR body is empty or not ASCII")
    else:
        notes.append("Non-character MQMD format is left opaque")
    return [message], notes


def msmq_message(data: bytes) -> dict | None:
    if len(data) < 16 or data[0] != 0x10 or data[4:8] != b"LIOR":
        return None
    flags = int.from_bytes(data[2:4], "little")
    return {"type": "msmq_base", "packet_size": int.from_bytes(data[8:12], "little"),
            "priority": flags & 0x07, "internal": bool(flags & 0x08),
            "time_to_reach_queue": int.from_bytes(data[12:16], "little")}


def tds_messages(data: bytes) -> tuple[list[dict], list[str]]:
    messages, notes, batches = [], [], []
    index = 0
    while index + 8 <= len(data) and len(messages) < 100:
        kind, length = data[index], int.from_bytes(data[index + 2:index + 4], "big")
        if length < 8 or index + length > len(data):
            notes.append("Incomplete TDS packet")
            break
        payload = data[index + 8:index + length]
        header = {"type": "tds_header", "packet_type": kind, "status": data[index + 1], "length": length}
        if kind == 1 and len(payload) % 2 == 0:
            batches.append(payload)
        elif kind in (16, 17, 18):
            notes.append("TDS login or prelogin payload is not decoded")
        messages.append(header)
        index += length
    if batches:
        text = b"".join(batches).decode("utf-16le", errors="strict")
        if text.isprintable() or "\n" in text or "\r" in text:
            messages.append({"type": "tds_sql_batch", "query": text[:4000]})
        else:
            notes.append("TDS SQL batch is not UTF-16LE text")
    if not messages:
        notes.append("TDS payload decoding pending")
    return messages, notes


def sqlnet_messages(data: bytes) -> tuple[list[dict], list[str]]:
    if len(data) < 8:
        return [], ["Oracle SQLNET payload decoding pending"]
    kind = data[4]
    message = {"type": "oracle_net_header", "length": int.from_bytes(data[:2], "big"),
               "packet_type": kind, "packet_name": TNS_TYPES.get(kind, f"type-{kind}")}
    notes = ["Encrypted Oracle Net payloads are not decoded"]
    if kind == 6:
        text = data[8:500].decode("ascii", errors="ignore")
        match = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\s+[ -~]{1,180}", text)
        if match:
            message["statement_span"] = match[0]
            notes.append("ASCII statement span inside a data packet; this is not a full SQL*Net decoder")
    return [message], notes


def drda_messages(data: bytes) -> tuple[list[dict], list[str]]:
    if len(data) < 6 or data[2] != 0xD0:
        return [{"type": "drda_dss_header", "length": int.from_bytes(data[:2], "big"), "marker": data[2]}] if len(data) >= 6 else [], ["DRDA commands and values pending"]
    code = int.from_bytes(data[6:8], "big") if len(data) >= 8 else None
    return [{"type": "drda_dss_header", "length": int.from_bytes(data[:2], "big"), "marker": data[2],
             "codepoint": code, "codepoint_name": DRDA_CODES.get(code, f"cp-{code:04x}" if code is not None else "absent")}], [
        "DRDA SQL text and values stay opaque; only the DSS header and a known code point are named"]


def fix_named(fields: list[str]) -> tuple[list[dict], bool, list[dict]]:
    present = {}
    named, encoded = [], []
    for part in fields:
        tag, separator, value = part.partition("=")
        if not separator:
            continue
        present[tag] = value
        if tag in FIX_ENCODED:
            encoded.append({"tag": tag, "name": FIX_NAMES[tag], "length": len(value)})
            named.append({"tag": tag, "name": FIX_NAMES[tag], "value": f"{len(value)} bytes"})
        elif tag in FIX_NAMES:
            named.append({"tag": tag, "name": FIX_NAMES[tag], "value": value})
    complete = all(tag in present for tag in FIX_REQUIRED) and bool(re.fullmatch(r"[A-Za-z0-9]{1,3}", present.get("35", "")))
    return named, complete, encoded


def iso8583_message(data: bytes, lengths: dict | None = None) -> dict | None:
    if len(data) < 12 or not data[:4].isdigit():
        return None
    bitmap = data[4:12]
    present = []
    for bit in range(1, 65):
        if bitmap[(bit - 1) // 8] & (1 << (7 - (bit - 1) % 8)):
            present.append(bit)
    cursor = 12
    if 1 in present and len(data) >= 20:
        secondary = data[12:20]
        cursor = 20
        for bit in range(65, 129):
            offset = bit - 65
            if secondary[offset // 8] & (1 << (7 - offset % 8)):
                present.append(bit)
    values = {}
    supplied = {int(key): value for key, value in (lengths or {}).items()}
    for bit in present:
        if bit == 1:
            continue
        width = supplied.get(bit)
        if width is None or cursor + width > len(data):
            break
        values[str(bit)] = data[cursor:cursor + width].decode("ascii", errors="replace")
        cursor += width
    message = {"type": "iso8583", "mti": data[:4].decode("ascii"), "present_fields": present}
    if values:
        message["values"] = values
    return message


_CARD = re.compile(r"(?:\d[ -]?){13,19}")
_SENSITIVE_TERMS = ("confidential", "proprietary", "trade secret", "password", "private key")
_SCAN_LIMIT = 32768


def _luhn(digits: str) -> bool:
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    alternate = False
    for character in reversed(digits):
        number = int(character)
        if alternate:
            number *= 2
            if number > 9:
                number -= 9
        total += number
        alternate = not alternate
    return total % 10 == 0


def content_review(payload: bytes) -> dict:
    """Hash reconstructed plaintext and name a sensitive marker without returning the bytes."""
    text = payload[:_SCAN_LIMIT].decode("utf-8", errors="replace")
    label = None
    for match in _CARD.finditer(text):
        digits = "".join(character for character in match.group() if character.isdigit())
        if _luhn(digits):
            label = f"card ending {digits[-4:]}"
            break
    if label is None and any(term in text.casefold() for term in _SENSITIVE_TERMS):
        label = "confidential term"
    review = {"sha256": hashlib.sha256(payload).hexdigest()}
    if label:
        review["sensitive"] = label
    return review


ftp_content_review = content_review


def ftp_transfer(lines: list[str]) -> dict | None:
    encrypted = False
    command = name = ""
    for line in lines:
        upper = line.upper()
        if upper.startswith(("AUTH TLS", "AUTH SSL", "PROT P")):
            encrypted = True
        for verb in ("RETR", "STOR", "STOU"):
            if upper.startswith(verb + " "):
                command = verb
                name = line.split(" ", 1)[1].strip()[:120]
    if not command and not encrypted:
        return None
    return {"command": command, "name": name, "encrypted": encrypted}


def swift_message(data: bytes) -> dict | None:
    if not data.startswith(b"{1:") or len(data) > 8192:
        return None
    text = data.decode("ascii", errors="replace")
    blocks = re.findall(r"\{([1-5]):([^{}]*)\}", text)
    tags = [{"tag": match[0], "value": match[1][:80]} for match in re.findall(r":(\d{2}[A-Z]?):([^\r\n:]{0,80})", text)][:30]
    if not blocks:
        return None
    return {"type": "swift_mt", "blocks": [{"block": number, "length": len(body)} for number, body in blocks], "tags": tags}


_HEADER_NAMES = ("subject", "from", "to", "message-id")
_FILE_LIMIT = 65536


def _mail_header(line: str) -> dict | None:
    if ":" not in line or line.startswith((" ", "\t")):
        return None
    name, value = line.split(":", 1)
    if name.casefold() not in _HEADER_NAMES:
        return None
    return {"name": name.casefold(), "value": value.strip()[:200]}


def _header_map(lines: list[str]) -> dict[str, str]:
    found = {}
    for line in lines:
        if ":" not in line or line.startswith((" ", "\t")):
            continue
        name, value = line.split(":", 1)
        key = name.casefold().strip()
        if key not in found:
            found[key] = value.strip()[:300]
    return found


def _attachment_name(headers: dict[str, str]) -> str:
    for source in (headers.get("content-disposition", ""), headers.get("content-type", "")):
        match = re.search(r'(?:filename|name)\s*=\s*"?([^";]+)"?', source, re.IGNORECASE)
        if match and match.group(1).strip():
            return match.group(1).strip()[:120]
    return ""


def _transfer_bytes(text: str, encoding: str) -> bytes | None:
    encoding = encoding.casefold().strip()
    if encoding == "base64":
        compact = "".join(text.split())
        if not compact or len(compact) > 88000:
            return None
        try:
            raw = base64.b64decode(compact, validate=True)
        except ValueError:
            return None
    elif encoding in ("", "7bit", "8bit", "binary"):
        raw = text.encode("utf-8", errors="replace")
    else:
        return None
    if not raw:
        return None
    return raw[:_FILE_LIMIT]


def _file_record(kind: str, name: str, raw: bytes) -> dict:
    review = content_review(raw)
    record = {"type": kind, "name": name, "length": len(raw), "sha256": review["sha256"]}
    if review.get("sensitive"):
        record["sensitive"] = review["sensitive"]
    return record


def _named_files(header_lines: list[str], body: str, kind: str) -> list[dict]:
    """Hash a named plaintext MIME attachment. The part text is not returned."""
    headers = _header_map(header_lines)
    files = []
    match = re.search(r'boundary\s*=\s*"?([^";]+)"?', headers.get("content-type", ""), re.IGNORECASE)
    if match:
        marker = "--" + match.group(1)
        for chunk in body.split(marker)[1:]:
            if chunk.lstrip("\n").startswith("--") or len(files) >= 5:
                break
            text = chunk.replace("\r\n", "\n").strip("\n")
            if "\n\n" not in text:
                continue
            head, rest = text.split("\n\n", 1)
            part_headers = _header_map(head.split("\n"))
            name = _attachment_name(part_headers)
            if not name:
                continue
            raw = _transfer_bytes(rest, part_headers.get("content-transfer-encoding", ""))
            if raw is not None:
                files.append(_file_record(kind, name, raw))
        return files
    name = _attachment_name(headers)
    if not name:
        return files
    raw = _transfer_bytes(body, headers.get("content-transfer-encoding", ""))
    if raw is not None:
        files.append(_file_record(kind, name, raw))
    return files


def _append_files(messages: list, header_lines: list[str], body_lines: list[str], kind: str) -> None:
    for record in _named_files(header_lines, "\n".join(body_lines), kind):
        if len(messages) >= 30:
            break
        messages.append(record)


def smtp_messages(data: bytes) -> dict:
    """Envelope, selected headers, and a hash of a named attachment. The body is not kept."""
    messages = []
    notes = ["The SMTP message body is not stored. A named attachment is hashed and its bytes are not copied. SMTPS is not decrypted."]
    sender = ""
    recipients = []
    header_lines = []
    body_lines = []
    phase = "command"
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if phase == "command":
            if line.upper().startswith("AUTH "):
                mechanism = line.split(" ", 2)[1] if " " in line else ""
                messages.append({"type": "smtp_auth", "mechanism": mechanism[:40]})
                continue
            mail = re.match(r"MAIL FROM:\s*<?([^>\s]+)>?", line, re.IGNORECASE)
            rcpt = re.match(r"RCPT TO:\s*<?([^>\s]+)>?", line, re.IGNORECASE)
            if mail:
                sender = mail.group(1)[:320]
            elif rcpt and len(recipients) < 20:
                recipients.append(rcpt.group(1)[:320])
            elif line.upper() == "DATA":
                phase = "headers"
            continue
        if line == ".":
            break
        if phase == "headers":
            if line == "":
                phase = "body"
                continue
            header_lines.append(line)
            header = _mail_header(line)
            if header and len(messages) < 30:
                messages.append({"type": "smtp_header", **header})
            continue
        body_lines.append(line)
    _append_files(messages, header_lines, body_lines, "smtp_file")
    if sender or recipients:
        messages.insert(0, {"type": "smtp_envelope", "sender": sender, "recipients": recipients})
    if not any(item.get("type") != "smtp_file" for item in messages):
        notes.append("SMTP envelope was not found")
    return {"messages": messages, "notes": notes}


def imap_messages(data: bytes) -> dict:
    """Login name, selected headers, and a hash of a named attachment. The body and password are not kept."""
    messages = []
    notes = ["The IMAP message body is not stored. A named attachment is hashed and its bytes are not copied. IMAPS is not decrypted."]
    lines = [raw.strip() for raw in data.decode("utf-8", errors="replace").splitlines()]
    index = 0
    skip_next = False
    while index < len(lines):
        line = lines[index]
        index += 1
        if skip_next:
            skip_next = False
            continue
        login = re.match(r"^\S+\s+LOGIN\s+(\S+)", line, re.IGNORECASE)
        auth = re.match(r"^\S+\s+AUTHENTICATE\s+(\S+)", line, re.IGNORECASE)
        if login and len(messages) < 30:
            messages.append({"type": "imap_login", "username": login.group(1)[:120]})
            continue
        if auth and len(messages) < 30:
            messages.append({"type": "imap_auth", "mechanism": auth.group(1)[:40]})
            skip_next = True
            continue
        if not re.search(r"\bFETCH\b", line, re.IGNORECASE):
            continue
        if len(messages) < 30:
            messages.append({"type": "imap_fetch"})
        header_lines = []
        body_lines = []
        phase = "headers"
        while index < len(lines):
            current = lines[index]
            index += 1
            if current == ")" or re.match(r"^\S+\s+OK\b", current, re.IGNORECASE):
                break
            if phase == "headers":
                if current == "":
                    phase = "body"
                    continue
                header_lines.append(current)
                header = _mail_header(current)
                if header and len(messages) < 30:
                    messages.append({"type": "imap_header", **header})
                continue
            body_lines.append(current)
        _append_files(messages, header_lines, body_lines, "imap_file")
    if not messages:
        notes.append("IMAP envelope was not found")
    return {"messages": messages, "notes": notes}


def pop3_messages(data: bytes) -> dict:
    """Mailbox name, selected headers, and a hash of a named attachment. The body and password are not kept."""
    messages = []
    notes = ["The POP3 message body is not stored. A named attachment is hashed and its bytes are not copied. POP3S is not decrypted."]
    lines = [raw.strip() for raw in data.decode("utf-8", errors="replace").splitlines()]
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if line.upper().startswith("USER ") and len(messages) < 30:
            messages.append({"type": "pop3_user", "username": line.split(" ", 1)[1].strip()[:120]})
            continue
        if line.upper().startswith("PASS "):
            if len(messages) < 30:
                messages.append({"type": "pop3_auth"})
            continue
        if line.upper().startswith("APOP ") and len(messages) < 30:
            parts = line.split()
            messages.append({"type": "pop3_user", "username": parts[1][:120] if len(parts) > 1 else ""})
            continue
        if not line.upper().startswith(("RETR ", "TOP ")):
            continue
        if len(messages) < 30:
            messages.append({"type": "pop3_retr"})
        header_lines = []
        body_lines = []
        phase = "headers"
        while index < len(lines):
            current = lines[index]
            index += 1
            if current == ".":
                break
            if phase == "headers":
                if current == "":
                    phase = "body"
                    continue
                header_lines.append(current)
                header = _mail_header(current)
                if header and len(messages) < 30:
                    messages.append({"type": "pop3_header", **header})
                continue
            body_lines.append(current)
        _append_files(messages, header_lines, body_lines, "pop3_file")
    if not messages:
        notes.append("POP3 envelope was not found")
    return {"messages": messages, "notes": notes}


def _xdr_u32(data: bytes, index: int):
    if index + 4 > len(data):
        return None
    return int.from_bytes(data[index:index + 4], "big"), index + 4


def _xdr_skip_opaque(data: bytes, index: int, limit: int):
    found = _xdr_u32(data, index)
    if not found:
        return None
    length, index = found
    if length > limit:
        return None
    padded = (length + 3) & ~3
    if index + padded > len(data):
        return None
    return index + padded


def nfs_message(data: bytes) -> dict | None:
    """Hash an NFSv3 WRITE buffer inside one stored RPC call. The bytes are not returned."""
    cursor = 0
    fields = []
    for _ in range(6):
        item = _xdr_u32(data, cursor)
        if not item:
            return None
        value, cursor = item
        fields.append(value)
    _xid, message_type, rpc_version, program, version, procedure = fields
    if message_type != 0 or rpc_version != 2 or program != 100003 or version != 3 or procedure != 7:
        return None
    for _ in range(2):
        flavor = _xdr_u32(data, cursor)
        if not flavor:
            return None
        if flavor[0] == 6:
            return {"type": "nfs_rpc", "encrypted": True}
        cursor = _xdr_skip_opaque(data, flavor[1], 400)
        if cursor is None:
            return None
    cursor = _xdr_skip_opaque(data, cursor, 64)
    if cursor is None or cursor + 16 > len(data):
        return None
    offset = int.from_bytes(data[cursor:cursor + 8], "big")
    cursor += 8
    count = _xdr_u32(data, cursor)
    stable = _xdr_u32(data, count[1]) if count else None
    if not stable:
        return None
    declared = _xdr_u32(data, stable[1])
    if not declared or declared[0] != count[0] or declared[0] > 65536:
        return None
    length, cursor = declared
    if cursor + length > len(data):
        return None
    review = content_review(data[cursor:cursor + length])
    record = {"type": "nfs_write", "length": length, "offset": offset, "sha256": review["sha256"]}
    if review.get("sensitive"):
        record["sensitive"] = review["sensitive"]
    return record


def ftp_endpoint(line: str) -> list | None:
    port = re.search(r"PORT\s+(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})", line, re.I)
    passive = re.search(r"\((\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\)", line)
    match = port or passive
    if match:
        numbers = [int(value) for value in match.groups()]
        if any(number > 255 for number in numbers):
            return None
        return [".".join(str(number) for number in numbers[:4]), numbers[4] * 256 + numbers[5]]
    extended = re.search(r"\(\|\|\|(\d{1,5})\|\)", line)
    if extended:
        number = int(extended[1])
        if 0 < number < 65536:
            return ["*", number]
    return None


_LDAP_OPERATIONS = {
    0x60: "bind", 0x61: "bind result", 0x42: "unbind", 0x63: "search",
    0x64: "search entry", 0x65: "search done", 0x66: "modify", 0x68: "add",
    0x4A: "delete", 0x6C: "moddn", 0x6E: "compare",
}
_LDAP_SCOPES = {0: "base", 1: "one", 2: "subtree"}


def _ber(data: bytes, index: int):
    if index >= len(data):
        return None
    tag = data[index]
    index += 1
    if index >= len(data):
        return None
    first = data[index]
    index += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 3 or index + count > len(data):
            return None
        length = int.from_bytes(data[index:index + count], "big")
        index += count
    if index + length > len(data):
        return None
    return tag, data[index:index + length], index + length


def _ldap_integer(data: bytes, index: int):
    item = _ber(data, index)
    if not item or item[0] != 0x02 or not item[1] or len(item[1]) > 4:
        return None
    return int.from_bytes(item[1], "big"), item[2]


def _ldap_text(value: bytes) -> str:
    return value[:120].decode("utf-8", errors="replace")


def _ldap_filter_names(tag: int, value: bytes, found: list[str]) -> None:
    if len(found) >= 12:
        return
    if tag in (0xA0, 0xA1):
        index = 0
        while index < len(value):
            child = _ber(value, index)
            if not child:
                break
            _ldap_filter_names(child[0], child[1], found)
            index = child[2]
    elif tag == 0xA2:
        child = _ber(value, 0)
        if child:
            _ldap_filter_names(child[0], child[1], found)
    elif tag in (0xA3, 0xA4, 0xA5, 0xA6, 0xA8, 0xA9):
        attribute = _ber(value, 0)
        if attribute and attribute[0] == 0x04 and attribute[1]:
            name = _ldap_text(attribute[1])
            if name not in found:
                found.append(name)
    elif tag == 0x87 and value:
        name = _ldap_text(value)
        if name not in found:
            found.append(name)


def ldap_messages(data: bytes) -> dict:
    """Operation names from a stored plaintext LDAP message. Credentials and filter values stay out."""
    messages = []
    notes = ["LDAP simple credentials are not stored. LDAPS is not decrypted."]
    cursor = 0
    while cursor < len(data) and len(messages) < 20:
        outer = _ber(data, cursor)
        if not outer or outer[0] != 0x30:
            break
        body, cursor = outer[1], outer[2]
        ident = _ldap_integer(body, 0)
        if ident is None:
            break
        message_id, op_at = ident
        operation = _ber(body, op_at)
        if not operation:
            break
        tag, value, _ = operation
        name = _LDAP_OPERATIONS.get(tag)
        if name is None:
            notes.append(f"LDAP operation 0x{tag:02x} is not reconstructed")
            continue
        item = {"type": "ldap", "id": message_id, "operation": name}
        if tag == 0x60:
            version = _ldap_integer(value, 0)
            distinguished = _ber(value, version[1]) if version else None
            if not distinguished or distinguished[0] != 0x04:
                continue
            item["name"] = _ldap_text(distinguished[1])
            choice = _ber(value, distinguished[2])
            if choice and choice[0] == 0x80:
                item["authentication"] = "simple"
            elif choice and choice[0] == 0xA3:
                item["authentication"] = "sasl"
            else:
                item["authentication"] = "other"
        elif tag == 0x63:
            base = _ber(value, 0)
            if not base or base[0] != 0x04:
                continue
            item["base"] = _ldap_text(base[1])
            index = base[2]
            scope = _ber(value, index)
            if scope and scope[0] == 0x0A and scope[1]:
                item["scope"] = _LDAP_SCOPES.get(scope[1][0], "other")
                index = scope[2]
            for _ in range(4):
                skipped = _ber(value, index)
                if not skipped:
                    index = None
                    break
                index = skipped[2]
            if index is not None:
                found = []
                filt = _ber(value, index)
                if filt:
                    _ldap_filter_names(filt[0], filt[1], found)
                item["filter_attributes"] = found
        elif tag == 0x4A:
            item["name"] = _ldap_text(value)
        messages.append(item)
    if not messages:
        notes.append("LDAP message was not decoded")
    return {"messages": messages, "notes": notes}
