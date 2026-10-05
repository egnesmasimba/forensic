from typing import Literal

from pydantic import BaseModel, Field

from app.ingest import load_rules
from app.mail_analysis import AttachmentObservation, mail_policy
from app.models import Alert
from endpoint_agent.content_scan import analyze_text


class TransferObservation(BaseModel):
    channel: Literal["local", "usb", "network_share", "cloud", "downloads"]
    path: str = Field(default="", max_length=2000)
    bytes: int = Field(ge=0, le=10**15)
    destination: str = Field(default="", max_length=200)
    transfer_status: str = Field(default="destination_write_observed", max_length=80)
    file_scan: AttachmentObservation | None = None


def print_document_alert(db, event):
    """Alert on a policy-matched printed document.

    The agent already decided the document matched the endpoint's print policy.
    This evaluates the retained scan against the server's own sensitive-term
    list and records the match terms, so an alert always states what was
    observed rather than merely that printing happened. Whether a copy of the
    source was actually retained is reported from the agent's
    ``retained_copy`` result: a policy match with no retained bytes is not
    described as a capture. A ``skip`` decision never raises an alert; it exists
    so that a missing capture is explainable.
    """
    import json
    payload = json.loads(event.payload or "{}")
    if payload.get("decision") != "capture":
        return None
    hits: list[str] = []
    terms = list(payload.get("matched_terms") or [])
    scan = payload.get("file_scan") or {}
    retained = payload.get("retained_copy") or {}
    did_retain = bool(retained.get("retained"))
    text = str(scan.get("text") or "")
    if text:
        sensitive = analyze_text(text, mail_policy(db)["sensitive_terms"])["sensitive_terms"]
        if sensitive:
            hits.append("Sensitive content in the printed document: " + ", ".join(sensitive[:10]))
    if scan.get("encryption") == "confirmed":
        hits.append("Printed document is encrypted")
    if not hits and not terms:
        return None
    if did_retain:
        custody = (
            f"A bounded copy of the source was retained by the endpoint agent "
            f"(SHA-256 {str(retained.get('sha256') or '')[:16]}, "
            f"{int(retained.get('size') or 0)} bytes)."
        )
    else:
        # Never claim a retained copy that was not taken: the policy matched
        # but the bytes were not kept, and the reason is stated instead.
        custody = (
            "The endpoint print policy matched but no copy was retained ("
            + str(retained.get("reason") or "reason unreported") + ")."
        )
    description = "; ".join(hits) or "Endpoint print policy matched"
    if terms:
        description += ". Matched policy terms: " + ", ".join(terms[:10])
    printer = str(payload.get("printer") or "")[:200]
    document = str(payload.get("document") or "")[:300]
    alert = Alert(
        title="Sensitive document printed: " + (document or "Untitled document")[:130],
        score=90,
        channel="print",
        entity_type="user",
        entity_ref=str(payload.get("user") or f"agent:{event.agent_id}")[:120],
        description=(description + f". Printer: {printer}. Location: "
                     f"{str(payload.get('printer_location') or 'unreported')[:200]}. "
                     f"Pages: {payload.get('pages', 0)}; copies: {payload.get('copies')}; "
                     f"colour: {payload.get('color')}; duplex: {payload.get('duplex')}. "
                     + custody + " "
                     "This confirms a print job, not delivery of any physical pages."),
    )
    db.add(alert)
    db.flush()
    return alert


def transfer_alert(db, event):
    import json
    observation = TransferObservation.model_validate(json.loads(event.payload))
    rules, hits = load_rules(db), []
    rule = {"usb": "large-external-transfer", "network_share": "network-share", "cloud": "cloud-sync", "downloads": "browser-download"}.get(observation.channel)
    if rule and rules[rule][0] and observation.bytes >= rules[rule][1]:
        hits.append((rules[rule][2], rules[rule][3]))
    if observation.file_scan:
        scan = observation.file_scan
        for rule, matched in (("archive", scan.archive), ("encryption", scan.encryption == "confirmed")):
            if matched and rules[rule][0] and observation.bytes >= rules[rule][1]:
                hits.append((rules[rule][2], rules[rule][3]))
        sensitive = analyze_text(scan.text, mail_policy(db)["sensitive_terms"])["sensitive_terms"]
        if sensitive and observation.channel in ("usb", "network_share", "cloud"):
            hits.append((85, "Sensitive content observed at an external destination"))
    if not hits:
        return None
    alert = Alert(title="Endpoint transfer review: " + hits[0][1][:150], score=max(score for score, _ in hits),
                  channel=observation.channel, entity_type="endpoint", entity_ref=f"agent:{event.agent_id}",
                  description="; ".join(reason for _, reason in hits) + f". {observation.bytes} bytes. Path: {observation.path[:500]}. " +
                              f"Observation: {observation.transfer_status}; this does not confirm remote delivery.")
    db.add(alert)
    db.flush()
    return alert
