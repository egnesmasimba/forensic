"""Command lines taken from decoded session text. Credentials are not copied into the list."""
import re

_PASSWORD_PROMPT = re.compile(r"password\s*:", re.IGNORECASE)
_LIMIT = 40


def collect(session) -> list[dict]:
    commands = []
    for direction in session.get("directions", []):
        for message in direction.get("decoded", {}).get("messages", []):
            for protocol, text in _from_message(message):
                commands.append({"protocol": protocol, "text": text[:200]})
                if len(commands) >= _LIMIT:
                    return commands
    return commands


def _from_message(message: dict):
    kind = message.get("type")
    if kind == "ftp_control":
        line = str(message.get("line") or "").strip()
        if line and line != "[credential command redacted]":
            yield "ftp", line
    elif kind == "telnet_text":
        yield from (("telnet", line) for line in _telnet_lines(str(message.get("text") or "")))
    elif kind == "ldap":
        label = str(message.get("operation") or "").strip()
        name = str(message.get("name") or message.get("base") or "").strip()
        text = f"{label} {name}".strip()
        if text:
            yield "ldap", text
    elif kind == "tds_sql_batch":
        query = str(message.get("query") or "").strip()
        if query:
            yield "tds", query
    elif kind == "oracle_net_header" and message.get("statement_span"):
        yield "sqlnet", str(message["statement_span"]).strip()
    elif kind == "imap_login":
        username = str(message.get("username") or "").strip()
        if username:
            yield "imap", f"LOGIN {username}"
    elif kind == "imap_header":
        yield "imap", f"{message.get('name')}: {message.get('value')}".strip()
    elif kind == "pop3_user":
        username = str(message.get("username") or "").strip()
        if username:
            yield "pop3", f"USER {username}"
    elif kind == "pop3_header":
        yield "pop3", f"{message.get('name')}: {message.get('value')}".strip()


def _telnet_lines(text: str) -> list[str]:
    found = []
    hide_next = False
    for raw in text.splitlines():
        line = raw.strip()
        if hide_next:
            hide_next = False
            continue
        if _PASSWORD_PROMPT.search(line):
            hide_next = True
            continue
        if line:
            found.append(line)
        if len(found) >= _LIMIT:
            break
    return found
