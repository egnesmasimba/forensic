import hashlib
import json
import mailbox
import os
import tempfile
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

from endpoint_agent.content_scan import MAX_FILE, parse_email
from . import Collector
from .capture_state import CaptureState, bounded_int


def outlook_messages(limit=100):
    """Read classic Outlook's running MAPI session; never launch or send mail."""
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    try:
        app = win32com.client.GetActiveObject("Outlook.Application")
        session = app.GetNamespace("MAPI")
        for folder_number, direction in ((5, "outgoing"), (6, "incoming")):
            items = session.GetDefaultFolder(folder_number).Items
            items.Sort("[LastModificationTime]", True)
            for index in range(1, min(items.Count, limit) + 1):
                item = items.Item(index)
                if item.Class != 43:
                    continue
                message = EmailMessage()
                message["Subject"] = str(item.Subject or "")[:200]
                message["Message-ID"] = "<" + str(item.EntryID)[:180] + "@outlook.local>"
                sender = str(item.SenderEmailAddress or "")
                if getattr(item, "SenderEmailType", "") == "EX":
                    exchange_user = item.Sender.GetExchangeUser()
                    if exchange_user:
                        sender = str(exchange_user.PrimarySmtpAddress)
                message["From"] = sender
                addresses = {1: [], 2: [], 3: []}
                for recipient in item.Recipients:
                    entry = recipient.AddressEntry
                    address = str(entry.Address or "")
                    if entry.Type == "EX":
                        user = entry.GetExchangeUser()
                        if user:
                            address = str(user.PrimarySmtpAddress)
                        else:
                            group = entry.GetExchangeDistributionList()
                            if group:
                                address = str(group.PrimarySmtpAddress)
                    if "@" in address:
                        addresses.setdefault(recipient.Type, []).append(address)
                for number, header in ((1, "To"), (2, "Cc"), (3, "Bcc")):
                    if addresses[number]:
                        message[header] = ", ".join(addresses[number][:200])
                when = item.SentOn if direction == "outgoing" else item.ReceivedTime
                message["Date"] = format_datetime(when.astimezone(timezone.utc))
                message.set_content(str(item.Body or "")[:32768])
                total = 0
                with tempfile.TemporaryDirectory(prefix="mail-inspection-") as temporary:
                    for attachment_index in range(1, min(item.Attachments.Count, 30) + 1):
                        attachment = item.Attachments.Item(attachment_index)
                        if total + int(attachment.Size) > 5 * 1024 * 1024:
                            message["X-Capture-Partial"] = "Attachment size limit"
                            break
                        path = Path(temporary) / f"attachment-{attachment_index}.bin"
                        attachment.SaveAsFile(str(path))
                        data = path.read_bytes()
                        total += len(data)
                        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=str(attachment.FileName)[:255])
                yield message.as_bytes(), direction
    finally:
        pythoncom.CoUninitialize()


class MailCollector(Collector):
    name = "email"
    default_interval_seconds = 30

    def __init__(self, config=None, *, outlook_provider=None):
        config = {"enabled": False, **(config or {})}
        super().__init__(config)
        self.state = CaptureState(config.get("state_path", "mail-state.sqlite")) if self._enabled else None
        self.sources = config.get("sources", [])
        if len(self.sources) > 30:
            raise ValueError("Use at most 30 mailbox sources")
        for source in self.sources:
            if source.get("format") not in ("mbox", "maildir", "eml_directory") or not source.get("path"):
                raise ValueError("Mail sources need a path and mbox, maildir or eml_directory format")
            if source.get("direction", "unknown") not in ("incoming", "outgoing", "unknown"):
                raise ValueError("Invalid mailbox direction")
        self.limit = bounded_int(config, "max_messages", 100, 1, 200)
        self.outlook_provider = outlook_provider or outlook_messages
        self.coverage = "not_started"

    @classmethod
    def supports_current_os(cls):
        return True

    def status(self):
        return {**super().status(), "coverage": self.coverage, "sources": len(self.sources), "outlook": bool(self._config.get("outlook"))}

    def _source_messages(self, source):
        path = Path(source["path"])
        if path.is_symlink():
            raise OSError("Symbolic-link mail sources are not followed")
        if source["format"] == "mbox":
            if path.stat().st_size > 128 * 1024 * 1024:
                self.coverage = "partial"
                return
            # create=False guarantees monitoring never creates a mailbox.
            box = mailbox.mbox(path, create=False)
            try:
                keys = list(box.iterkeys())
                if len(keys) > self.limit:
                    self.coverage = "partial"
                for key in keys[-self.limit:]:
                    raw = box.get_bytes(key)
                    if len(raw) <= MAX_FILE:
                        yield raw
                    else:
                        self.coverage = "partial"
            finally:
                box.close()
        else:
            folders = [path / "cur", path / "new"] if source["format"] == "maildir" else [path]
            files = []
            for folder in folders:
                files.extend(p for p in folder.iterdir() if p.is_file() and not p.is_symlink() and
                             (source["format"] == "maildir" or p.suffix.lower() == ".eml"))
            files.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
            if len(files) > self.limit:
                self.coverage = "partial"
            for item in files[:self.limit]:
                if item.stat().st_size <= MAX_FILE:
                    yield item.read_bytes()
                else:
                    self.coverage = "partial"

    def _capture(self, name, messages, client):
        previous = self.state.get(name)
        seen = dict(previous or {})
        events = []
        iterator = iter(messages)
        failed = False
        while True:
            try:
                raw, direction = next(iterator)
            except StopIteration:
                break
            except Exception:
                failed = True
                self.coverage = "partial"
                self._errors += 1
                break
            report = parse_email(raw, client=client, direction=direction)
            if client == "outlook":
                # COM serializes a fresh MIME boundary each poll. Identify content,
                # not those randomly generated transport bytes.
                identity = {key: val for key, val in report.items() if key not in ("sha256", "observed_at")}
                digest = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()
                report["sha256"] = digest
            else:
                digest = hashlib.sha256(raw).hexdigest()
            if digest in seen:
                continue
            seen[digest] = report["message_id"]
            if previous is None and not self._config.get("capture_existing", False):
                continue
            events.append({"type": "email_capture", "severity": "low", "event_key": hashlib.sha256((name + digest).encode()).hexdigest(), "payload": report})
        # Retain enough identities to cover the monitored latest-message window.
        if seen or previous is not None or not failed:
            self.state.put(name, dict(list(seen.items())[-2000:]))
        return events

    def _collect(self):
        if not self.state:
            return []
        self.coverage = "complete"
        events = []
        for source in self.sources:
            try:
                messages = ((raw, source.get("direction", "unknown")) for raw in self._source_messages(source))
                events.extend(self._capture("mail:" + source["path"], messages, source.get("client", "thunderbird")))
            except (OSError, ValueError):
                self.coverage = "partial"
                self._errors += 1
        if self._config.get("outlook", False):
            try:
                events.extend(self._capture("outlook", self.outlook_provider(self.limit), "outlook"))
            except Exception:
                # COM availability, Outlook profile and permission prompts are reported,
                # never bypassed. Other configured mailbox sources continue polling.
                self.coverage = "outlook_unavailable"
                self._errors += 1
        return events
