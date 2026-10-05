import re

from sqlalchemy.orm import Session

from app.analytics import current_score
from app.models import (
    Alert, CloudAllow, CommandAudit, DlpAudit, DlpSetting, FileChange, PermissionAllow, PermissionChange,
    PrintJob, ScreenshotAttempt, UsbActivity, UsbDevice,
)

CARD = re.compile(r"(?:\d[ -]?){13,19}")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PERSONAL_CLOUDS = ("dropbox.com", "drive.google.com", "onedrive.live.com", "icloud.com", "box.com")
GENAI_HOSTS = (
    "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com",
    "perplexity.ai", "ollama.com", "lmstudio.ai",
)
SENSITIVE_EXTENSIONS = {"doc", "docx", "xls", "xlsx", "csv", "pdf", "sql", "txt"}
DISGUISE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "tmp", "temp", "log", "bak"}
COMMANDS = (
    (re.compile(r"\brm\s+-rf\b", re.IGNORECASE), "destructive delete"),
    (re.compile(r"\bdd\b", re.IGNORECASE), "disk copy"),
    (re.compile(r"\b(?:nc|ncat)\b", re.IGNORECASE), "netcat"),
    (re.compile(r"\bwget\b", re.IGNORECASE), "download"),
    (re.compile(r"\b(?:scp|rsync)\b", re.IGNORECASE), "remote copy"),
    (re.compile(r"\b(?:sudo|su)\b", re.IGNORECASE), "privilege"),
    (re.compile(r"\b(?:apt(?:-get)?|yum|dnf)\s+install\b", re.IGNORECASE), "package install"),
)


def seed_dlp(db: Session) -> None:
    if db.get(DlpSetting, 1) is None:
        db.add(DlpSetting(id=1))
        db.commit()


def dlp_setting(db: Session) -> DlpSetting:
    row = db.get(DlpSetting, 1)
    if row is None:
        row = DlpSetting(id=1)
        db.add(row)
        db.flush()
    return row


def _terms(value: str) -> list[str]:
    return [part.strip().casefold() for part in value.split(",") if part.strip()]


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


def inspect_text(text: str, setting: DlpSetting) -> dict:
    folded = text.casefold()
    cards = []
    for match in CARD.finditer(text):
        digits = "".join(character for character in match.group() if character.isdigit())
        if _luhn(digits):
            cards.append(f"card ending {digits[-4:]}")
    emails = EMAIL.findall(text)
    categories = []
    keyword_hits = 0
    if any(term in folded for term in _terms(setting.ip_terms)):
        categories.append("intellectual property")
        keyword_hits += 1
    customer_terms = any(term in folded for term in _terms(setting.customer_terms))
    if emails or customer_terms:
        categories.append("customer data")
    if customer_terms:
        keyword_hits += 1
    financial_terms = any(term in folded for term in _terms(setting.financial_terms))
    if cards or financial_terms:
        categories.append("financial record")
    if financial_terms:
        keyword_hits += 1
    matches = len(cards) + len(emails) + keyword_hits
    return {"categories": categories, "cards": cards[:5], "emails": len(emails), "matches": matches}


def band_for(score: int, setting: DlpSetting) -> tuple[str, int]:
    if score >= 100:
        return "high", max(1, setting.min_matches // 2)
    if score <= 20:
        return "low", setting.min_matches * 2
    return "standard", setting.min_matches


def review_text(db: Session, user: str, text: str, actor: str) -> dict:
    setting = dlp_setting(db)
    score = current_score(db, "user", user) if user else 0
    band, needed = band_for(score, setting)
    found = inspect_text(text, setting)
    opened = False
    if found["matches"] >= needed and found["categories"]:
        db.add(Alert(
            title="DLP review",
            score=setting.score,
            status="open",
            entity_type="user",
            entity_ref=user or "unknown",
            channel="dlp",
            description=f"{band} band. Categories: {', '.join(found['categories'])}. Action: review.",
        ))
        opened = True
    db.add(DlpAudit(actor=actor, change=f"Reviewed {user or 'unknown'} at band {band}, needed {needed}, found {found['matches']}."))
    return {"action": "review", "opened": opened, "band": band, "needed": needed, "risk_score": score, **found}


def record_usb(db: Session, serial: str, user: str, action: str, size: int, occurred_at: str) -> dict:
    device = db.query(UsbDevice).filter_by(serial=serial).one_or_none()
    allowed = device is not None and device.allowed
    db.add(UsbActivity(serial=serial, user=user, action=action, bytes=size, occurred_at=occurred_at))
    opened = False
    if not allowed and size > 0:
        db.add(Alert(
            title="USB device",
            score=70,
            status="open",
            entity_type="user",
            entity_ref=user,
            channel="dlp",
            description=f"Transfer of {size} bytes on {serial}. The device is not on the allow list.",
        ))
        opened = True
    return {"allowed": allowed, "opened": opened}


def host_kind(host: str) -> str:
    name = host.casefold().strip(".")
    for known in GENAI_HOSTS:
        if name == known or name.endswith("." + known):
            return "genai"
    for known in PERSONAL_CLOUDS:
        if name == known or name.endswith("." + known):
            return "personal"
    return ""


def review_cloud(db: Session, host: str, user: str, size: int) -> dict:
    kind = host_kind(host)
    row = db.query(CloudAllow).filter_by(host=host.casefold()).one_or_none()
    allowed = row is not None and row.allowed
    opened = False
    if kind and not allowed and size > 0:
        db.add(Alert(
            title="Cloud destination",
            score=75,
            status="open",
            entity_type="user",
            entity_ref=user,
            channel="dlp",
            description=f"{kind} destination {host} received {size} bytes.",
        ))
        opened = True
    return {"kind": kind, "allowed": allowed, "opened": opened}


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].casefold()


def record_file_changes(db: Session, user: str, changes: list[dict]) -> dict:
    disguised = 0
    for change in changes:
        db.add(FileChange(
            user=user, action=change["action"], source=change["source"], target=change["target"],
            occurred_at=change["occurred_at"],
        ))
        source = _extension(change["source"])
        target = _extension(change["target"])
        if source in SENSITIVE_EXTENSIONS and target in DISGUISE_EXTENSIONS:
            disguised += 1
    opened = []
    if disguised:
        alert = Alert(
            title="File disguise", score=80, status="open", entity_type="user", entity_ref=user, channel="dlp",
            description=f"{disguised} files changed from a document extension to an image or temporary extension.",
        )
        db.add(alert)
        opened.append("disguise")
    if len(changes) >= 5:
        db.add(Alert(
            title="File pattern", score=65, status="open", entity_type="user", entity_ref=user, channel="dlp",
            description=f"{len(changes)} renames or moves were submitted together.",
        ))
        opened.append("pattern")
    return {"stored": len(changes), "opened": opened}


def record_permission(db: Session, user: str, path: str, principal: str, change: str, occurred_at: str) -> dict:
    db.add(PermissionChange(user=user, path=path, principal=principal, change=change, occurred_at=occurred_at))
    allowed = db.query(PermissionAllow).filter_by(principal=principal).one_or_none() is not None
    opened = False
    if not allowed:
        db.add(Alert(
            title="Permission change", score=70, status="open", entity_type="user", entity_ref=user, channel="dlp",
            description=f"{change} for {principal} on {path}. The principal is not on the allow list.",
        ))
        opened = True
    return {"allowed": allowed, "opened": opened}


def record_print(db: Session, user: str, printer: str, document: str, pages: int, size: int, occurred_at: str) -> dict:
    db.add(PrintJob(user=user, printer=printer, document=document, pages=pages, size=size, occurred_at=occurred_at))
    db.add(Alert(
        title="Print job", score=40, status="open", entity_type="user", entity_ref=user, channel="dlp",
        description=f"{document} on {printer}, {pages} pages, {size} bytes. Page content is not stored.",
    ))
    return {"opened": True}


def record_screenshot_attempt(db: Session, user: str, application: str, occurred_at: str) -> dict:
    db.add(ScreenshotAttempt(user=user, application=application, occurred_at=occurred_at))
    db.add(Alert(
        title="Screenshot attempt", score=50, status="open", entity_type="user", entity_ref=user, channel="dlp",
        description=f"{application} at {occurred_at}. No image is stored.",
    ))
    return {"opened": True}


def review_commands(db: Session, user: str, commands: list[str]) -> dict:
    findings = []
    joined = "\n".join(commands)
    if re.search(r"\bwget\b", joined, re.IGNORECASE) and re.search(r"\b(?:chmod|bash|sh)\b", joined, re.IGNORECASE):
        findings.append("command sequence")
    for command in commands:
        label = ""
        for pattern, name in COMMANDS:
            if pattern.search(command):
                label = name
                break
        if label:
            findings.append(label)
            db.add(CommandAudit(user=user, command=command[:300], finding=label))
    if "command sequence" in findings:
        db.add(CommandAudit(user=user, command=joined[:300], finding="command sequence"))
        db.add(Alert(
            title="Command sequence", score=80, status="open", entity_type="user", entity_ref=user, channel="dlp",
            description="A submitted command log contains a download followed by a shell or permission change.",
        ))
    elif findings:
        db.add(Alert(
            title="Command review", score=70, status="open", entity_type="user", entity_ref=user, channel="dlp",
            description=f"Submitted commands matched: {', '.join(sorted(set(findings)))}.",
        ))
    return {"findings": sorted(set(findings)), "opened": bool(findings)}
