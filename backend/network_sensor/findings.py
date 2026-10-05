"""Searches over findings already stored on a capture. This is not a threat feed."""

TACTICS = (
    "exfiltration", "privilege", "command-and-control", "ioc",
    "impact", "discovery", "persistence", "lateral-movement", "collection", "protocol-anomaly", "ttp",
)

_COMMAND_LABELS = {
    "impact": {"destructive delete", "disk copy"},
    "discovery": {"discovery"},
    "persistence": {"persistence"},
    "lateral-movement": {"lateral movement"},
    "collection": {"download", "remote copy"},
}


def matches(finding: dict, tactic: str) -> bool:
    category = finding.get("category")
    evidence = finding.get("evidence") or {}
    if tactic == "exfiltration":
        return category == "file"
    if tactic == "privilege":
        return category == "command" and evidence.get("label") == "privilege"
    if tactic == "command-and-control":
        return category == "c2"
    if tactic == "ioc":
        return category in ("malware_callback", "c2") and bool(evidence.get("address"))
    labels = _COMMAND_LABELS.get(tactic)
    if labels is not None:
        return category == "command" and evidence.get("label") in labels
    if tactic == "protocol-anomaly":
        return category == "protocol_anomaly"
    if tactic == "ttp":
        return any(matches(finding, name) for name in TACTICS if name != "ttp")
    return False
