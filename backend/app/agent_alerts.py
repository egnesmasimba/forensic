import hashlib
import json
from typing import Any

from app.models import Alert, EndpointEvent, EndpointTamperEvent, utcnow

SENSITIVE_KEYWORDS = (
    "password", "secret", "token", "ssn", "credit card", "cvv",
    "bank account", "private key", "internal", "confidential", "salary",
    "client data", "customer", "proprietary",
)
PROCESS_BLACKLIST = (
    "mimikatz", "psexec", "nmap", "nc.exe", "netcat", "wireshark", "procdump",
    "cain.exe", "hashcat", "john", "metasploit", "cobaltstrike", "ransom",
)
USB_TRANSFER_TYPES = {"file_write", "file_create", "file_rename", "usb_insert"}


def _pl(e: EndpointEvent) -> dict:
    try:
        return json.loads(e.payload) if e.payload else {}
    except Exception:
        return {}


def _score(severity: str) -> int:
    return {"low": 20, "medium": 50, "high": 75, "critical": 95}.get(severity, 20)


def make_alert_for(
    event: EndpointEvent,
    *,
    title: str,
    score: int,
    channel: str,
    entity_type: str = "endpoint",
    entity_ref: str = "",
    description: str = "",
    include_payload: bool = True,
) -> Alert:
    payload_desc = f"{description} Event payload: {event.payload[:600]}" if include_payload and event.payload else description
    return Alert(
        title=title[:200],
        score=max(0, min(1000, score)),
        status="open",
        entity_type=entity_type,
        entity_ref=entity_ref or f"agent:{event.agent_id}",
        channel=channel or event.type,
        description=payload_desc[:4000],
    )


def evaluate_agent_event(db, event: EndpointEvent) -> Alert | None:
    if event.type == "behavioral_biometrics":
        from app.biometrics import store_sample
        return store_sample(db, event)
    p = _pl(event)
    payload_text = json.dumps(p).lower()

    if event.type == "email_capture":
        from app.mail_analysis import store_mail
        captured, duplicate = store_mail(db, p, captured_by=f"agent:{event.agent_id}", agent_id=event.agent_id, event_id=event.id)
        return db.get(Alert, captured.alert_id) if captured.alert_id and not duplicate else None

    if event.type == "print_document":
        from app.exfiltration import print_document_alert
        return print_document_alert(db, event)

    if event.type in ("transfer_observed", "file_observation", "browser_download"):
        from app.exfiltration import transfer_alert
        return transfer_alert(db, event)

    if event.type == "tamper":
        alert = make_alert_for(
            event,
            title=f"Tamper detected on agent #{event.agent_id}",
            score=95,
            channel="tamper",
            description=f"Tamper type: {p.get('type', 'unknown')}. Detail: {p.get('detail', '')}",
        )
        db.add(alert)
        db.flush()
        return alert

    if event.type.startswith("file_") or event.type == "fschange":
        bytes_ = int(p.get("bytes") or p.get("size") or 0)
        dest = str(p.get("destination") or p.get("path") or "").lower()
        is_usb = "usb" in dest or "removable" in dest or event.type == "usb_insert" or p.get("drive_type") == "removable"
        if is_usb and bytes_ >= 10 * 1024 * 1024:
            title = f"USB file transfer: {p.get('path', 'path')[:120]}"
            alert = make_alert_for(event, title=title, score=80, channel="usb",
                                   description=f"{event.type} {bytes_} bytes to removable media")
            db.add(alert)
            db.flush()
            return alert
        if bytes_ >= 1000:
            recs = int(p.get("records") or 0)
            if recs >= 1000 or bytes_ >= 50 * 1024 * 1024:
                title = f"Bulk data export: {p.get('path', '')[:120]}"
                alert = make_alert_for(event, title=title, score=70, channel="data_export",
                                       description=f"export {bytes_} bytes, {recs} records")
                db.add(alert)
                db.flush()
                return alert

    if event.type == "clipboard_change":
        text = str(p.get("content_preview") or p.get("text") or "")[:32768]
        if text:
            from app.dlp import dlp_setting, inspect_text
            found = inspect_text(text, dlp_setting(db))
            folded = text.casefold()
            markers = [word for word in ("password", "secret", "private key", "cvv") if word in folded]
            if found["cards"] or found["categories"] or markers:
                parts = []
                if found["cards"]:
                    parts.append(", ".join(dict.fromkeys(found["cards"])))
                if found["categories"]:
                    parts.append("categories: " + ", ".join(found["categories"]))
                if markers:
                    parts.append("credential markers: " + ", ".join(markers))
                alert = make_alert_for(
                    event,
                    title="Sensitive clipboard copy",
                    score=65,
                    channel="clipboard",
                    description="Clipboard preview matched " + "; ".join(parts) + ". The preview is not copied into this alert.",
                    include_payload=False,
                )
                db.add(alert)
                db.flush()
                return alert

    if event.type == "screenshot":
        window_title = str(p.get("window_title") or "").lower()
        private_markers = ("incognito", "inprivate", "private browsing", "private window", "virustotal", "have i been pwned", "dark web")
        if any(m in window_title for m in private_markers):
            title = f"Screenshot captured in private window"
            alert = make_alert_for(event, title=title, score=75, channel="screenshot",
                                   description=f"Window title: {p.get('window_title', '')}")
            db.add(alert)
            db.flush()
            return alert

    if event.type == "process_start" or event.type == "process_modules":
        exe = str(p.get("exe") or p.get("executable") or "").lower()
        cmd = str(p.get("cmdline") or p.get("command") or "").lower()
        name = str(p.get("name") or "").lower()
        for bad in PROCESS_BLACKLIST:
            if bad in exe or bad in cmd or bad in name:
                title = f"Blacklisted process: {bad}"
                alert = make_alert_for(event, title=title, score=90, channel="process_blacklist",
                                       description=f"exe={exe[:200]} cmd={cmd[:200]}")
                db.add(alert)
                db.flush()
                return alert
        cmdline_hashes = ("-enc ", "-e ", "base64", "powershell -enc", "invoke-", "downloadstring", "iex (")
        if any(h in cmd for h in cmdline_hashes) and len(cmd) > 100:
            title = "Suspicious PowerShell command"
            alert = make_alert_for(event, title=title, score=85, channel="powershell",
                                   description=f"cmd={cmd[:300]}")
            db.add(alert)
            db.flush()
            return alert

    if event.type == "registry_change":
        key = str(p.get("key") or "").lower()
        autorun_markers = (
            r"software\microsoft\windows\currentversion\run",
            r"software\microsoft\windows\currentversion\runonce",
            "logon script", "image file execution options", "appinit_dlls",
        )
        if any(m in key for m in autorun_markers):
            title = f"Autorun registry change: {key.rsplit('\\', 1)[-1]}"
            alert = make_alert_for(event, title=title, score=70, channel="registry_autorun",
                                   description=f"key={key[:300]} value={str(p.get('value', ''))[:300]}")
            db.add(alert)
            db.flush()
            return alert

    if event.type == "incognito_detected":
        title = "Incognito/private browsing detected"
        alert = make_alert_for(event, title=title, score=55, channel="privacy_evasion",
                               description=f"{p.get('browser', 'browser')} process={p.get('process_name', '')} window={p.get('window_title', '')}")
        db.add(alert)
        db.flush()
        return alert

    if event.type in ("rdp_connect", "rdp_disconnect"):
        score = 75 if event.type == "rdp_connect" else 60
        alert = make_alert_for(event, title=f"RDP {event.type.split('_')[1]}", score=score,
                               channel="rdp", description=f"user={p.get('user', '')} client={p.get('client_address', '')}")
        db.add(alert)
        db.flush()
        return alert

    if event.type in ("citrix_start", "citrix_clipboard"):
        alert = make_alert_for(event, title=f"Citrix {event.type}", score=60,
                               channel="citrix", description=payload_text[:400])
        db.add(alert)
        db.flush()
        return alert

    if event.type == "usb_block_attempt":
        alert = make_alert_for(event, title="USB block triggered", score=70,
                               channel="usb", description=payload_text[:400])
        db.add(alert)
        db.flush()
        return alert

    if event.severity == "critical" and event.type != "agent_log":
        alert = make_alert_for(event, title=f"Critical {event.type} event", score=_score(event.severity),
                               channel=event.type, description=payload_text[:400])
        db.add(alert)
        db.flush()
        return alert

    from app.applications import match_application
    return match_application(db, event, p)


def evaluate_tamper_events(db, agent_id: int, tamper_list: list[dict]) -> int:
    created = 0
    for te in tamper_list:
        detail = str(te.get("detail", ""))
        ttype = str(te.get("type", "tamper"))[:40]
        dbrow = EndpointTamperEvent(agent_id=agent_id, type=ttype, detail=detail)
        db.add(dbrow)
        db.flush()
        ev = EndpointEvent(
            agent_id=agent_id,
            type="tamper",
            severity="critical",
            payload=json.dumps({"type": ttype, "detail": detail}, default=str, ensure_ascii=False),
        )
        db.add(ev)
        db.flush()
        alert = evaluate_agent_event(db, ev)
        if alert is not None:
            created += 1
    return created


__all__ = ["evaluate_agent_event", "evaluate_tamper_events", "make_alert_for",
           "SENSITIVE_KEYWORDS", "PROCESS_BLACKLIST"]
