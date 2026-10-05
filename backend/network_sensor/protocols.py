"""Bounded decoders. Unsupported/encrypted traffic is explicitly metadata-only."""
import re

from . import application
from . import sna as sna_decoder
from . import tn3270e
from . import tn5250

PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
         143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
         636: "ldaps", 993: "imaps", 995: "pop3s", 2049: "nfs",
         1414: "mq", 1433: "tds", 1521: "sqlnet", 446: "drda", 1801: "msmq",
         12000: "enterprise_extender", 12001: "enterprise_extender", 12002: "enterprise_extender",
         12003: "enterprise_extender", 12004: "enterprise_extender"}
PROTOCOLS = ["http", "https", "ftp", "ssh", "telnet", "tn3270", "tn5250", "dns", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ldap", "ldaps", "smb", "nfs",
             "mq", "msmq", "sqlnet", "drda", "tds", "fix", "iso8583", "swift",
             "sna", "enterprise_extender", "oracle_forms", "unknown"]
CAPABILITIES = {
    "http": "HTTP/1.x headers, a SHA-256 of a cleartext body, and cleartext HTTP/2 frame length, type, and stream id. The body is not copied into the decoded record. HPACK, HTTP/3, and encrypted content stay unavailable",
    "fix": "FIX tag-value framing, BodyLength, CheckSum, required header tags, and encoded-data lengths",
    "ftp": "Plaintext FTP control lines, PORT/PASV/EPSV data-channel bytes, and a RETR/STOR transfer summary; TLS-wrapped FTP stays metadata-only",
    "telnet": "Telnet negotiation stripping and VT100 erase, cursor, and saved-cursor rendering on stored plaintext",
    "tn3270": tn3270e.CAPABILITY,
    "tn5250": tn5250.CAPABILITY,
    "ssh": "SSH identification banner; encrypted content unavailable",
    "https": "TLS record headers only; encrypted content unavailable",
    "dns": "DNS question names from a stored datagram. The name is not a website visit and the answer is not decoded",
    "smtp": "SMTP envelope, Subject, From, To, and Message-ID headers, and a SHA-256 of a named plaintext attachment. The message body and attachment bytes are not stored",
    "smtps": "SMTPS is identified and left encrypted",
    "imap": "IMAP login name, Subject, From, To, and Message-ID headers, and a SHA-256 of a named plaintext attachment. The password, message body, and attachment bytes are not stored",
    "imaps": "IMAPS is identified and left encrypted",
    "pop3": "POP3 mailbox name, Subject, From, To, and Message-ID headers, and a SHA-256 of a named plaintext attachment. The password, message body, and attachment bytes are not stored",
    "pop3s": "POP3S is identified and left encrypted",
    "nfs": "SHA-256 of a plaintext NFSv3 WRITE buffer inside one stored RPC call. The bytes are not copied. RPCSEC_GSS and NFSv4 are not reconstructed",
    "ldap": "LDAP operation, bind name, and search base from a stored plaintext message. Simple credentials and filter values are not stored",
    "ldaps": "LDAPS is identified and left encrypted",
    "smb": "SMB1/SMB2 command names, SMB2 message IDs, and a SHA-256 of a plaintext READ or WRITE buffer inside the message. The bytes are not copied into the decoded record. An SMB transform header is not decrypted",
    "tds": "TDS headers and a UTF-16LE SQL batch joined across packets; login, prelogin, and encrypted content stay opaque",
    "sqlnet": "Oracle Net packet type and one ASCII statement span inside a data packet; encrypted content stays opaque",
    "drda": "DRDA DSS header and known code point; SQL text and values stay opaque",
    "mq": "IBM MQ TSH segment length and an MQSTR body when a big-endian MQMD is present",
    "msmq": "MSMQ base header version, signature, packet size, and priority; the user message stays opaque",
    "iso8583": "ISO 8583 MTI, bitmap field presence, and values for fields named in a supplied length map",
    "swift": "SWIFT MT block lengths and tag text when the message starts with {1:}",
    "oracle_forms": "Configured-port identification and opaque recording only",
    "sna": sna_decoder.decode_sna(b"")["coverage"],
    "enterprise_extender": ("Enterprise Extender CEE framing with the nested SNA transport and request "
                            "headers; request/response payloads are not decoded"),
}


def classify(data, ports, overrides):
    for port in ports:
        if str(port) in overrides:
            return overrides[str(port)], "configured_port"
    if data.startswith(application.HTTP2_PREFACE) or data.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"HTTP/")):
        return "http", "signature"
    if data.startswith(b"{1:"):
        return "swift", "signature"
    if len(data) >= 8 and data[0] == 0x10 and data[4:8] == b"LIOR":
        return "msmq", "signature"
    if data.startswith(b"8=FIX"):
        return "fix", "signature"
    if data.startswith(b"SSH-"):
        return "ssh", "signature"
    if data.startswith((b"\xfeSMB", b"\xffSMB", b"\xfdSMB")) or data[4:8] in (b"\xfeSMB", b"\xffSMB", b"\xfdSMB"):
        return "smb", "signature"
    if data.startswith(b"TSH"):
        return "mq", "signature"
    if b"IBM-327" in data[:4096]:
        return "tn3270", "negotiation"
    if b"IBM-525" in data[:4096]:
        return "tn5250", "negotiation"
    if 23 in ports:
        return "telnet", "port_hint"
    if 53 in ports:
        return "dns", "port_hint"
    if 389 in ports:
        return "ldap", "port_hint"
    if 636 in ports:
        return "ldaps", "port_hint"
    if 25 in ports or 587 in ports:
        return "smtp", "port_hint"
    if 465 in ports:
        return "smtps", "port_hint"
    if 143 in ports:
        return "imap", "port_hint"
    if 993 in ports:
        return "imaps", "port_hint"
    if 110 in ports:
        return "pop3", "port_hint"
    if 995 in ports:
        return "pop3s", "port_hint"
    if 2049 in ports:
        return "nfs", "port_hint"
    if sna_decoder.parse_enterprise_extender(data)["present"]:
        return "enterprise_extender", "cee_signature"
    if sna_decoder.looks_like_sna(data):
        return "sna", "transport_header"
    for port in ports:
        if port in PORTS:
            return PORTS[port], "port_hint"
    return "unknown", "unidentified"


def telnet_records(data):
    plain, records = bytearray(), []
    index = 0
    while index < len(data):
        value = data[index]
        index += 1
        if value != 255:
            plain.append(value)
            continue
        if index == len(data):
            break
        command = data[index]
        index += 1
        if command == 255:
            plain.append(255)
        elif command in (251, 252, 253, 254):
            index += 1
        elif command == 250:
            end = data.find(b"\xff\xf0", index)
            if end < 0:
                break
            index = end + 2
        elif command == 239:
            records.append(bytes(plain))
            plain.clear()
    return records, bytes(plain)


def vt100_screen(data, rows=24, columns=80):
    text = data.decode("utf-8", errors="replace")
    screen = [[" "] * columns for _ in range(rows)]
    row = column = 0
    unsupported = False
    saved = None
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\x1b":
            match = re.match(r"\x1b\[([0-9;?]*)([A-Za-z])", text[index:])
            if not match:
                unsupported = True
                index += 1
                continue
            values = [int(value) if value.isdigit() else 0 for value in match[1].split(";")]
            command = match[2]
            amount = values[0] or 1
            if command in ("H", "f"):
                row = min(rows - 1, max(0, amount - 1))
                column = min(columns - 1, max(0, (values[1] if len(values) > 1 else 1) - 1))
            elif command == "J":
                if values[0] == 2:
                    screen = [[" "] * columns for _ in range(rows)]
                elif values[0] == 0:
                    screen[row][column:] = [" "] * (columns - column)
                    for later in range(row + 1, rows):
                        screen[later] = [" "] * columns
                elif values[0] == 1:
                    screen[row][:column + 1] = [" "] * (column + 1)
                    for earlier in range(row):
                        screen[earlier] = [" "] * columns
                else:
                    unsupported = True
            elif command == "K":
                if values[0] == 0:
                    screen[row][column:] = [" "] * (columns - column)
                elif values[0] == 1:
                    screen[row][:column + 1] = [" "] * (column + 1)
                elif values[0] == 2:
                    screen[row] = [" "] * columns
                else:
                    unsupported = True
            elif command == "s":
                saved = (row, column)
            elif command == "u" and saved is not None:
                row, column = saved
            elif command in ("A", "B", "C", "D"):
                row = min(rows - 1, max(0, row + (amount if command == "B" else -amount if command == "A" else 0)))
                column = min(columns - 1, max(0, column + (amount if command == "C" else -amount if command == "D" else 0)))
            elif command != "m":
                unsupported = True
            index += len(match[0])
            continue
        if character == "\r":
            column = 0
        elif character == "\n":
            row += 1
            if row == rows:
                screen.pop(0)
                screen.append([" "] * columns)
                row = rows - 1
        elif character == "\b":
            column = max(0, column - 1)
        elif character == "\t":
            column = min(columns - 1, (column // 8 + 1) * 8)
        elif ord(character) >= 32:
            screen[row][column] = character
            column += 1
            if column == columns:
                column = 0
                row = min(rows - 1, row + 1)
        index += 1
    return {"kind": "vt100_subset", "rows": ["".join(line).rstrip() for line in screen],
            "partial": unsupported, "cursor": [row + 1, column + 1]}


def screen3270(records):
    screen = [" "] * 1920
    snapshots = []
    for record in records[:100]:
        if len(record) < 2 or record[0] not in (0xF1, 0xF5, 0x7E):
            continue
        if record[0] in (0xF5, 0x7E):
            screen = [" "] * 1920
        address, index, partial = 0, 2, False
        while index < len(record):
            value = record[index]
            index += 1
            if value in (0x11, 0x3C):
                if index + 2 > len(record):
                    partial = True
                    break
                a, b = record[index:index + 2]
                index += 2
                target = (((a & 0x3F) << 6) | (b & 0x3F)) if a & 0xC0 else ((a << 8) | b)
                if target >= 1920:
                    partial = True
                    break
                if value == 0x11:
                    address = target
                else:
                    if index >= len(record):
                        partial = True
                        break
                    char = bytes([record[index]]).decode("cp037")
                    index += 1
                    while address != target:
                        screen[address] = char
                        address = (address + 1) % 1920
            elif value == 0x1D:
                if index == len(record):
                    partial = True
                    break
                index += 1  # Field attribute, not a display character.
                screen[address] = " "
                address = (address + 1) % 1920
            elif value == 0x13:
                pass
            elif value in (0x12, 0x28, 0x29, 0x2C):
                partial = True
                break  # Unsupported orders must not become plausible text.
            else:
                char = bytes([value]).decode("cp037") if value >= 0x40 else " "
                screen[address] = char
                address = (address + 1) % 1920
        snapshots.append({"kind": "3270_subset", "partial": partial,
                          "rows": ["".join(screen[start:start + 80]).rstrip() for start in range(0, 1920, 80)]})
    return snapshots


def _chunk_body(data, cursor):
    parts = []
    while cursor < len(data):
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0 or line_end - cursor > 64:
            return None
        token = data[cursor:line_end].split(b";", 1)[0]
        try:
            size = int(token, 16)
        except ValueError:
            return None
        if not 0 <= size <= 1048576:
            return None
        start = line_end + 2
        if size == 0:
            if data.startswith(b"\r\n", start):
                return b"".join(parts), start + 2
            trailer = data.find(b"\r\n\r\n", start)
            return None if trailer < 0 else (b"".join(parts), trailer + 4)
        end = start + size
        if end + 2 > len(data) or data[end:end + 2] != b"\r\n":
            return None
        parts.append(data[start:end])
        cursor = end + 2
    return None


def _dns_name(data, cursor, jumps=0):
    labels = []
    while cursor < len(data):
        length = data[cursor]
        if length == 0:
            return ".".join(labels), cursor + 1
        if length & 0xC0 == 0xC0:
            if jumps >= 4 or cursor + 1 >= len(data):
                return None, None
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data):
                return None, None
            rest, _ = _dns_name(data, pointer, jumps + 1)
            if rest is None:
                return None, None
            return ".".join(part for part in (*labels, rest) if part), cursor + 2
        if length > 63 or cursor + 1 + length > len(data):
            return None, None
        label = data[cursor + 1:cursor + 1 + length]
        if not re.fullmatch(rb"[A-Za-z0-9_-]+", label):
            return None, None
        labels.append(label.decode("ascii").casefold())
        cursor += 1 + length
        if len(labels) > 20:
            return None, None
    return None, None


def dns_queries(data):
    """Question names from one stored DNS message. Answers and HTTPS visits are not derived."""
    if len(data) < 12:
        return {"messages": [], "notes": ["DNS header is incomplete"]}
    if data[2] & 0x80:
        return {"messages": [], "notes": ["DNS response answers are not decoded"]}
    count = int.from_bytes(data[4:6], "big")
    if count < 1 or count > 20:
        return {"messages": [], "notes": ["DNS question count is outside 1 to 20"]}
    messages, cursor = [], 12
    types = {1: "A", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
    for _ in range(count):
        name, cursor = _dns_name(data, cursor)
        if name is None or cursor is None or cursor + 4 > len(data):
            return {"messages": messages, "notes": ["A DNS question was incomplete"]}
        qtype = int.from_bytes(data[cursor:cursor + 2], "big")
        qclass = int.from_bytes(data[cursor + 2:cursor + 4], "big")
        cursor += 4
        if qclass == 1 and name:
            messages.append({"type": "dns_query", "name": name[:253], "qtype": types.get(qtype, str(qtype))})
    return {"messages": messages, "notes": []}


def decode(protocol, data, iso_fields=None):
    messages, screens, notes = [], [], []
    if protocol == "http":
        frames = application.http2_frames(data)
        if frames is not None:
            messages = frames
            notes.append("HTTP/2 HPACK header blocks are not expanded")
            return {"messages": messages, "screens": screens, "notes": notes, "urls": [],
                    "coverage": CAPABILITIES["http"]}
        cursor = 0
        while len(messages) < 100:
            end = data.find(b"\r\n\r\n", cursor)
            if end < 0:
                break
            lines = data[cursor:end].decode("iso-8859-1").split("\r\n")
            if not re.match(r"(?:[A-Z]+ \S+ HTTP/1\.[01]|HTTP/1\.[01] \d{3})", lines[0]):
                break
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    # Credentials/cookies are retained only in the original capture, not indexed metadata.
                    headers[key.lower()] = "[redacted]" if key.lower() in ("authorization", "proxy-authorization", "cookie", "set-cookie") else value.strip()
            messages.append({"type": "http_headers", "start_line": lines[0], "headers": headers})
            if "chunked" in headers.get("transfer-encoding", "").lower():
                found = _chunk_body(data, end + 4)
                if found is None:
                    notes.append("Incomplete chunked body")
                    break
                body, cursor = found
                if body:
                    messages.append(_http_body(body))
                continue
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                notes.append("Invalid Content-Length")
                break
            if length < 0 or end + 4 + length > len(data):
                notes.append("Incomplete HTTP body")
                break
            body = data[end + 4:end + 4 + length]
            cursor = end + 4 + length
            if body:
                messages.append(_http_body(body))
    elif protocol == "fix":
        cursor = 0
        while cursor < len(data) and len(messages) < 100:
            match = re.match(rb"8=(FIX[^\x01]+)\x019=(\d+)\x01", data[cursor:])
            if not match:
                break
            body_start = cursor + len(match[0])
            checksum_start = body_start + int(match[2])
            checksum = data[checksum_start:checksum_start + 7]
            if not re.fullmatch(rb"10=\d{3}\x01", checksum):
                notes.append("Incomplete FIX frame or invalid BodyLength")
                break
            raw = data[cursor:checksum_start + 7]
            valid = sum(data[cursor:checksum_start]) % 256 == int(checksum[3:6])
            fields = [part.decode("ascii", errors="replace") for part in raw.split(b"\x01") if part]
            named, complete, encoded = application.fix_named(fields)
            messages.append({"type": "fix", "fields": fields, "named": named, "encoded": encoded,
                             "checksum_valid": valid, "header_complete": complete})
            cursor = checksum_start + 7
    elif protocol in ("telnet", "tn3270", "tn5250"):
        if protocol == "tn3270":
            decoded = tn3270e.decode_tn3270e(data)
            messages = decoded["records"] or [{"type": "tn3270_record", "note": "no records decoded"}]
            screens = decoded["screens"]
            notes = decoded["notes"]
        elif protocol == "telnet":
            records, tail = telnet_records(data)
            plain = b"".join(records) + tail
            messages = [{"type": "telnet_text", "text": plain[:16384].decode("utf-8", errors="replace")}]
            screens = [vt100_screen(plain)]
            notes = []
        else:
            decoded = tn5250.decode_tn5250(data)
            messages, screens, notes = decoded["messages"], decoded["screens"], decoded["notes"]
    elif protocol in ("sna", "enterprise_extender"):
        result = sna_decoder.decode_sna(data)
        messages, notes = result["messages"], result["notes"]
    elif protocol == "ftp":
        for line in data.decode("ascii", errors="replace").split("\r\n")[:-1][:100]:
            shown = "[credential command redacted]" if line.upper().startswith(("PASS ", "ACCT ")) else line
            item = {"type": "ftp_control", "line": shown}
            endpoint = None if shown != line else application.ftp_endpoint(line)
            if endpoint:
                item["data_endpoint"] = endpoint
            messages.append(item)
        notes.append("TLS-wrapped FTP is not decrypted")
    elif protocol == "ssh":
        if data.startswith(b"SSH-") and b"\n" in data:
            messages = [{"type": "ssh_banner", "banner": data.split(b"\n", 1)[0][:255].decode("ascii", errors="replace")}]
        notes.append("SSH payload is encrypted")
    elif protocol == "dns":
        found = dns_queries(data)
        messages, notes = found["messages"], found["notes"]
        notes.append("A DNS question name is not recorded as a website visit")
    elif protocol == "ldap":
        found = application.ldap_messages(data)
        messages, notes = found["messages"], found["notes"]
    elif protocol == "ldaps":
        notes.append("LDAPS payload is encrypted")
    elif protocol == "smtp":
        found = application.smtp_messages(data)
        messages, notes = found["messages"], found["notes"]
    elif protocol == "smtps":
        notes.append("SMTPS payload is encrypted")
    elif protocol == "imap":
        found = application.imap_messages(data)
        messages, notes = found["messages"], found["notes"]
    elif protocol == "imaps":
        notes.append("IMAPS payload is encrypted")
    elif protocol == "pop3":
        found = application.pop3_messages(data)
        messages, notes = found["messages"], found["notes"]
    elif protocol == "pop3s":
        notes.append("POP3S payload is encrypted")
    elif protocol == "nfs":
        found = application.nfs_message(data)
        if found and found.get("encrypted"):
            messages = [found]
            notes.append("RPCSEC_GSS NFS is not decrypted")
        elif found and found.get("sha256"):
            messages = [found]
            notes.append("NFSv3 WRITE bytes are hashed. The bytes are not copied into the decoded record")
        else:
            notes.append("NFS file bytes were not located in this message. NFSv4 and encrypted RPC are not reconstructed")
    elif protocol == "https":
        index = 0
        while index + 5 <= len(data) and len(messages) < 100:
            kind, major, minor, high, low = data[index:index + 5]
            length = high * 256 + low
            if kind not in (20, 21, 22, 23) or major != 3 or index + 5 + length > len(data):
                break
            messages.append({"type": "tls_record", "content_type": kind, "legacy_version": f"{major}.{minor}", "length": length})
            index += 5 + length
        notes.append("TLS payload is encrypted; no HTTPS content decoding")
    elif protocol == "smb":
        found = application.smb_message(data)
        if found:
            messages = [found]
        if found and found.get("encrypted"):
            notes.append("SMB transform header is not decrypted")
        elif found and found.get("sha256"):
            notes.append("SMB READ or WRITE bytes are hashed. The bytes are not copied into the decoded record")
        else:
            notes.append("SMB file bytes were not located in this message. Encrypted SMB is not decrypted")
    elif protocol == "tds" and len(data) >= 8:
        messages, notes = application.tds_messages(data)
    elif protocol == "sqlnet" and len(data) >= 8:
        messages, notes = application.sqlnet_messages(data)
    elif protocol == "drda" and len(data) >= 6:
        messages, notes = application.drda_messages(data)
    elif protocol == "mq":
        messages, notes = application.mq_messages(data)
    elif protocol == "msmq":
        found = application.msmq_message(data)
        messages = [found] if found else []
        notes.append("MSMQ user-message body stays opaque")
    elif protocol == "iso8583":
        found = application.iso8583_message(data, iso_fields)
        messages = [found] if found else []
        notes.append("ISO 8583 values follow the supplied field lengths; unspecified fields stay opaque" if found and found.get("values") else "ISO 8583 field values require the deployment specification")
    elif protocol == "swift":
        found = application.swift_message(data)
        messages = [found] if found else []
        if not found:
            notes.append("SWIFT block text was not found")
    elif protocol == "oracle_forms":
        notes.append("Oracle Forms is identified by the configured port and recorded opaquely")
    else:
        notes.append("Identification/opaque recording only; application decoder pending")
    result = {"messages": messages, "screens": screens, "notes": notes,
              "coverage": CAPABILITIES.get(protocol, "Identification/opaque recording only")}
    if protocol == "http":
        result["urls"] = http_request_urls(messages)
    return result


def _http_body(body: bytes) -> dict:
    review = application.content_review(body)
    item = {"type": "http_body", "length": len(body), "sha256": review["sha256"]}
    if review.get("sensitive"):
        item["sensitive"] = review["sensitive"]
    return item


def http_request_urls(messages):
    """Host and path from a stored cleartext HTTP/1 request. The query string is omitted."""
    found = []
    for message in messages:
        if message.get("type") != "http_headers":
            continue
        match = re.match(r"[A-Z]+ (\S+) HTTP/1\.[01]", message.get("start_line", ""))
        if not match:
            continue
        path = match.group(1).split("?", 1)[0]
        host = message.get("headers", {}).get("host", "").split(":")[0].strip().lower()
        if host and path.startswith("/") and len(host) <= 253 and "." in host:
            found.append({"host": host, "path": path[:500]})
    return found
