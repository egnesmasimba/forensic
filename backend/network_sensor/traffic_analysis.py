"""Deterministic, evidence-bearing indicators over retained capture sessions."""
import re
from collections import defaultdict
from statistics import mean, pstdev

from .protocols import PORTS

COMMAND_PATTERNS = (
    (re.compile(r"\brm\s+-rf\b", re.IGNORECASE), "destructive delete"),
    (re.compile(r"\bdd\b", re.IGNORECASE), "disk copy"),
    (re.compile(r"\b(?:nc|ncat)\b", re.IGNORECASE), "netcat"),
    (re.compile(r"\bwget\b", re.IGNORECASE), "download"),
    (re.compile(r"\b(?:scp|rsync)\b", re.IGNORECASE), "remote copy"),
    (re.compile(r"\b(?:sudo|su)\b", re.IGNORECASE), "privilege"),
    (re.compile(r"\b(?:apt(?:-get)?|yum|dnf)\s+install\b", re.IGNORECASE), "package install"),
    (re.compile(r"\bwhoami\b", re.IGNORECASE), "discovery"),
    (re.compile(r"\b(?:uname|hostname|ipconfig|ifconfig|netstat)\b", re.IGNORECASE), "discovery"),
    (re.compile(r"\bcrontab\b", re.IGNORECASE), "persistence"),
    (re.compile(r"\bschtasks\b", re.IGNORECASE), "persistence"),
    (re.compile(r"\bsystemctl\s+enable\b", re.IGNORECASE), "persistence"),
    (re.compile(r"\b(?:psexec|wmiexec|winexe)\b", re.IGNORECASE), "lateral movement"),
    (re.compile(r"\bnet\s+use\b", re.IGNORECASE), "lateral movement"),
)


def analyze_traffic(sessions, config=None):
    config = config or {}
    findings = []
    applications = defaultdict(lambda: {"payload_bytes": 0, "packets": 0, "sessions": 0})
    peers = defaultdict(list)
    scans = defaultdict(set)

    def add(category, severity, title, ids, evidence):
        findings.append({"category": category, "severity": severity, "title": title,
                         "session_ids": sorted(set(ids)), "evidence": evidence})

    for session in sessions:
        sid = session["id"]
        protocol = session["protocol"]
        volume = session.get("payload_bytes", sum(d["length"] for d in session["directions"]))
        app = applications[protocol]
        app["payload_bytes"] += volume
        app["packets"] += session["packets"]
        app["sessions"] += 1
        for address, port in session["endpoints"]:
            if address in config.get("malware_ips", []):
                add("malware_callback", "high", "Traffic involving a configured malware address", [sid], {"address": address, "port": port})
            if address in config.get("c2_ips", []):
                add("c2", "high", "Traffic involving a configured C2 address", [sid], {"address": address, "port": port})
        if protocol == "unknown" or (session["classification_basis"] == "signature" and protocol in PORTS.values() and not any(PORTS.get(p) == protocol for _, p in session["endpoints"])):
            add("unusual_protocol", "medium", "Unidentified or nonstandard-port protocol", [sid], {"protocol": protocol, "endpoints": session["endpoints"], "basis": session["classification_basis"]})
            if protocol != "unknown" and session["classification_basis"] == "signature":
                add("protocol_anomaly", "medium", "Protocol anomaly", [sid], {
                    "protocol": protocol, "ports": [port for _, port in session["endpoints"]],
                })
        if any(d.get("overlap_conflict") for d in session["directions"]):
            add("network_threat", "high", "Conflicting TCP overlap", [sid], {"reason": "Overlapping segments contain different bytes"})
        initiator = session.get("initiator")
        if initiator is not None:
            source = session["endpoints"][initiator]
            target = session["endpoints"][1 - initiator]
            peers[(source[0], target[0], target[1], protocol)].append(session)
            if session.get("syn_attempt") and not volume:
                scans[source[0]].add((target[0], target[1], sid))
        if volume >= config.get("heavy_bytes", 1048576):
            duration = max(0, session["last"] - session["first"])
            add("traffic_anomaly", "medium", "Large traffic session", [sid], {"payload_bytes": volume, "duration_seconds": duration})
        for direction in session.get("directions", []):
            for message in direction.get("decoded", {}).get("messages", []):
                kind = message.get("type")
                if kind in ("http_body", "smb2_header", "nfs_write", "smtp_file", "imap_file", "pop3_file") and message.get("sensitive"):
                    add("file", "high", "Sensitive file transfer", [sid], {
                        "label": message["sensitive"], "protocol": protocol, "sha256": message.get("sha256"),
                    })
                    continue
                if kind == "ftp_control":
                    text = str(message.get("line") or "")
                elif kind == "telnet_text":
                    text = str(message.get("text") or "")
                else:
                    continue
                for pattern, label in COMMAND_PATTERNS:
                    if pattern.search(text):
                        add("command", "high", f"Suspicious command: {label}", [sid], {"label": label, "protocol": protocol})
                        break
        transfer = session.get("transfer") or {}
        label = transfer.get("sensitive")
        if label and not transfer.get("encrypted"):
            add("file", "high", "Sensitive file transfer", [sid], {
                "label": label, "protocol": protocol, "sha256": transfer.get("sha256"),
            })

    for source, targets in scans.items():
        destinations = {(ip, port) for ip, port, _ in targets}
        if len(destinations) >= 10:
            add("network_threat", "medium", "Possible port or host scan", [sid for _, _, sid in targets], {"source": source, "distinct_destinations": len(destinations)})
    for peer, flows in peers.items():
        starts = sorted(set(s["first"] for s in flows))
        if len(starts) < 6:
            continue
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        average = mean(intervals)
        variation = pstdev(intervals) / average if average else 1
        if average >= 1 and variation <= 0.1:
            add("c2", "medium", "Possible periodic callback / C2 beacon", [s["id"] for s in flows],
                {"source": peer[0], "destination": peer[1], "port": peer[2], "connections": len(starts),
                 "interval_seconds": round(average, 3), "interval_variation": round(variation, 4)})
    ranked = sorted(({"application": name, **values} for name, values in applications.items()), key=lambda row: (-row["payload_bytes"], row["application"]))
    total = sum(row["payload_bytes"] for row in ranked)
    for row in ranked:
        row["share_percent"] = round(100 * row["payload_bytes"] / total, 2) if total else 0
    return {"findings": findings, "applications": ranked, "total_payload_bytes": total,
            "limitations": ["Indicators require investigation; periodic legitimate services can resemble callbacks.",
                            "Analysis covers retained TCP/UDP sessions; packet loss, filters and retention limits reduce coverage.",
                            "Bytes count observed transport payload, including retransmissions, not wire bandwidth or decrypted content.",
                            "Malware and C2 address matches use operator-supplied indicators, not a built-in threat feed."]}
