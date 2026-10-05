import base64
import hashlib
from dataclasses import dataclass, field
from collections import deque

from . import application
from .commands import collect
from .files import collect as collect_files
from .protocols import CAPABILITIES, PROTOCOLS, classify, decode


@dataclass
class Direction:
    origin: int | None = None
    segments: list = field(default_factory=list)
    stored_bytes: int = 0
    clipped: bool = False
    truncated: bool = False
    syn_seen: bool = False

    def add(self, packet, budget):
        if packet.flags & 2:
            self.origin = (packet.sequence + 1) & 0xFFFFFFFF
            self.syn_seen = True
        self.truncated |= packet.truncated
        if not packet.payload:
            return
        sequence = (packet.sequence + (1 if packet.flags & 2 else 0)) & 0xFFFFFFFF
        if any(seq == sequence and body == packet.payload for seq, body in self.segments):
            return
        remaining = budget - self.stored_bytes
        if remaining <= 0 or len(self.segments) >= 2048:
            self.clipped = True
            return
        payload = packet.payload[:remaining]
        self.clipped |= len(payload) < len(packet.payload)
        self.segments.append((sequence, payload))
        self.stored_bytes += len(payload)

    def reconstruct(self):
        if not self.segments:
            return b"", [], False
        origin = self.origin
        if origin is None:
            origin = min(sequence for sequence, _ in self.segments)
        segments = sorted((((sequence - origin) & 0xFFFFFFFF, data) for sequence, data in self.segments), key=lambda item: item[0])
        result = bytearray()
        gaps, conflict = [], False
        # Only decode the first contiguous span; never join data across missing bytes.
        for offset, data in segments:
            if offset > len(result):
                gaps.append({"from": len(result), "to": offset})
                break
            overlap = min(len(data), len(result) - offset)
            if result[offset:offset + overlap] != data[:overlap]:
                conflict = True
            result.extend(data[overlap:])
        return bytes(result), gaps, conflict


class SessionTable:
    def __init__(self, enabled=None, port_map=None, max_sessions=256, bytes_per_direction=65536, session_idle_seconds=300,
                 session_max_seconds=3600, closed_session_grace_seconds=5, max_completed_sessions=256, iso_fields=None):
        self.enabled = set(PROTOCOLS if enabled is None else enabled)
        self.port_map = port_map or {}
        self.iso_fields = iso_fields or {}
        self.max_sessions, self.byte_limit = max_sessions, bytes_per_direction
        self.sessions = {}
        self.current = {}
        self.overflow = 0
        self.completed = deque(maxlen=max_completed_sessions)
        self.completed_omitted = self.retired = self.capacity_rotations = 0
        self.serial = 0
        self.watermark = float("-inf")
        self.idle_limit = session_idle_seconds
        self.age_limit = session_max_seconds
        self.close_grace = closed_session_grace_seconds

    def retire(self, key, reason):
        session = self.sessions.pop(key)
        flow = key[:-1]
        if self.current.get(flow) == key:
            del self.current[flow]
        session["termination_reason"] = reason
        self.retired += 1
        if len(self.completed) == self.completed.maxlen:
            self.completed_omitted += 1
        self.completed.append((key, session))

    def expire(self, timestamp):
        # Capture timestamps, rather than wall time, keep offline replay deterministic.
        self.watermark = max(self.watermark, timestamp)
        for key, session in list(self.sessions.items()):
            reason = None
            if session["closed"] and self.watermark - session["last"] >= self.close_grace:
                reason = "closed"
            elif self.watermark - session["last"] >= self.idle_limit:
                reason = "idle"
            elif self.watermark - session["first"] >= self.age_limit:
                reason = "duration"
            if reason:
                self.retire(key, reason)

    def finish(self):
        for key in list(self.sessions):
            self.retire(key, "capture_end")

    def consume(self, packet):
        self.expire(packet.timestamp)
        endpoints = sorted([(packet.source, packet.source_port), (packet.destination, packet.destination_port)])
        flow = (packet.capture_source, packet.transport, *endpoints[0], *endpoints[1])
        key = self.current.get(flow)
        session = self.sessions.get(key)
        index = 0 if (packet.source, packet.source_port) == endpoints[0] else 1
        if session and packet.transport == "tcp" and packet.flags & 2 and not packet.flags & 16:
            self.retire(key, "connection_reuse")
            session = None
        if session is None:
            if len(self.sessions) >= self.max_sessions:
                oldest = min(self.sessions, key=lambda item: (not self.sessions[item]["closed"], self.sessions[item]["last"]))
                self.retire(oldest, "capacity")
                self.capacity_rotations += 1
            session = {"endpoints": endpoints, "transport": packet.transport, "first": packet.timestamp,
                       "last": packet.timestamp, "packets": 0, "directions": [Direction(), Direction()], "closed": False,
                       "payload_bytes": 0, "initiator": index, "syn_attempt": bool(packet.transport == "tcp" and packet.flags & 2 and not packet.flags & 16), "datagrams": [], "fin_seen": [False, False], "termination_reason": None}
            key = (*flow, self.serial)
            self.serial += 1
            self.current[flow] = key
            self.sessions[key] = session
        session["first"] = min(packet.timestamp, session["first"])
        session["last"] = max(packet.timestamp, session["last"])
        session["packets"] += 1
        session["payload_bytes"] += len(packet.payload)
        if packet.transport == "tcp":
            session["directions"][index].add(packet, self.byte_limit)
            session["fin_seen"][index] |= bool(packet.flags & 1)
            session["closed"] |= bool(packet.flags & 4) or all(session["fin_seen"])
        elif len(session["datagrams"]) < 100:
            session["datagrams"].append({"direction": index, "timestamp": packet.timestamp,
                                        "payload_base64": base64.b64encode(packet.payload[:4096]).decode(),
                                        "truncated": packet.truncated or len(packet.payload) > 4096})

    def report(self):
        reports = []
        for key, session in [*self.completed, *self.sessions.items()]:
            assembled = [direction.reconstruct() for direction in session["directions"]]
            sample = b"".join(data[:4096] for data, _, _ in assembled)
            if not sample and session["datagrams"]:
                sample = base64.b64decode(session["datagrams"][0]["payload_base64"])
            protocol, basis = classify(sample, [endpoint[1] for endpoint in session["endpoints"]], self.port_map)
            if protocol not in self.enabled:
                continue
            dns_messages, dns_notes = [], []
            if protocol == "dns":
                for datagram in session["datagrams"]:
                    found = decode("dns", base64.b64decode(datagram["payload_base64"]))
                    dns_messages.extend(found["messages"])
                    dns_notes.extend(found["notes"])
                    if datagram.get("truncated"):
                        dns_notes.append("DNS datagram was truncated before decoding")
            directions = []
            for index, direction in enumerate(session["directions"]):
                data, gaps, conflict = assembled[index]
                directions.append({"source": list(session["endpoints"][index]), "length": len(data),
                                   "syn_seen": direction.syn_seen, "gaps": gaps, "overlap_conflict": conflict,
                                   "truncated": direction.truncated or direction.clipped,
                                   "payload_base64": base64.b64encode(data).decode(),
                                   "decoded": decode(protocol, data, self.iso_fields) if data and not conflict else
                                   {"messages": [], "screens": [], "notes": ["No contiguous data or conflicting TCP overlap"]}})
            if protocol == "dns" and directions:
                directions[session["initiator"]]["decoded"] = {
                    "messages": dns_messages[:100], "screens": [],
                    "notes": list(dict.fromkeys(dns_notes))[:20],
                    "coverage": CAPABILITIES["dns"],
                }
            reports.append({"id": hashlib.sha256(repr(key).encode()).hexdigest()[:16],
                            "capture_source": key[0], "transport": session["transport"], "endpoints": [list(endpoint) for endpoint in session["endpoints"]],
                            "protocol": protocol, "classification_basis": basis,
                            "first": session["first"], "last": session["last"], "packets": session["packets"],
                            "payload_bytes": session["payload_bytes"], "initiator": session["initiator"], "syn_attempt": session["syn_attempt"],
                            "closed": session["closed"], "termination_reason": session["termination_reason"],
                            "finalized": session["termination_reason"] is not None, "directions": directions, "datagrams": session["datagrams"],
                            "commands": [],
                            "limitations": ["A flow without its opening SYN is reconstructed from the lowest captured sequence and stops at the first gap. A TCP SYN starts a new session on the same endpoints. IPv4 fragments are reassembled when every piece is present and overlaps agree."]})
        for source in {row["capture_source"] for row in reports}:
            self._attach_ftp_data([row for row in reports if row["capture_source"] == source])
        for row in reports:
            row["commands"] = collect(row)
            row["files"] = collect_files(row)
        return reports

    def _attach_ftp_data(self, reports):
        peers = []
        control_lines = []
        for session in reports:
            if session["protocol"] != "ftp":
                continue
            for direction in session["directions"]:
                for message in direction["decoded"]["messages"]:
                    line = message.get("line")
                    if line:
                        control_lines.append(line)
                    endpoint = message.get("data_endpoint")
                    if endpoint:
                        peers.append(endpoint)
        for session in reports:
            if session["protocol"] != "unknown":
                continue
            endpoints = {tuple(endpoint) for endpoint in session["endpoints"]}
            ports = {endpoint[1] for endpoint in session["endpoints"]}
            matched = None
            for host, port in peers:
                if host == "*" and port in ports:
                    matched = ["*", port]
                elif (host, port) in endpoints:
                    matched = [host, port]
            if not matched:
                continue
            session["protocol"] = "ftp-data"
            session["classification_basis"] = "ftp_control"
            length = sum(direction["length"] for direction in session["directions"])
            transfer = application.ftp_transfer(control_lines)
            if transfer:
                transfer["bytes"] = length
                if not transfer["encrypted"]:
                    payload = b""
                    for direction in session["directions"]:
                        raw = base64.b64decode(direction.get("payload_base64") or "")
                        if raw:
                            payload = raw
                            break
                    if payload:
                        review = application.ftp_content_review(payload)
                        transfer["sha256"] = review["sha256"]
                        if review.get("sensitive"):
                            transfer["sensitive"] = review["sensitive"]
                    transfer["preview"] = payload[:64].decode("ascii", errors="replace")
                session["transfer"] = transfer
            note = (f"Encrypted FTP data channel {matched[0]}:{matched[1]} recorded {length} bytes and was not decoded"
                    if transfer and transfer["encrypted"] else
                    f"Plaintext FTP data channel {matched[0]}:{matched[1]} reconstructed {length} bytes; encrypted FTP is not decoded")
            session["directions"][0]["decoded"]["notes"].append(note)
