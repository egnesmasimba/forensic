"""Capture-point, VLAN and backend verification for the passive network sensor.

Two kinds of check are produced and they are never conflated:

* Self-checks run everywhere. They exercise the VLAN and frame analysis code
  against synthetic frames so the analyser itself is proven correct without any
  hardware.
* Hardware checks require a real tap or SPAN/mirror port. They report what was
  actually observed on the wire. When no interface or no traffic is available
  the report says ``verified: false`` and lists the reason, so an absent mirror
  port can never be mistaken for a working one.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .config import CapturePointConfig, SensorConfig
from .engines import CaptureEngine, describe_backend, npcap_installed, npcap_version, normalise_timestamp
from .packets import CaptureError

VLAN_TPIDS = (0x8100, 0x88A8)
MAX_QINQ_TAGS = 4


@dataclass
class FrameFacts:
    """Link-layer facts about one captured frame."""

    vlan_ids: tuple[int, ...]
    ethertype: int
    source_mac: str
    destination_mac: str
    tagged: bool

    def as_dict(self) -> dict:
        return {"vlan_ids": list(self.vlan_ids), "ethertype": hex(self.ethertype),
                "source_mac": self.source_mac, "destination_mac": self.destination_mac,
                "tagged": self.tagged}


def _mac(raw: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in raw)


def frame_facts(frame: bytes, linktype: int = 1) -> FrameFacts | None:
    """Extract VLAN tags and MACs, returning None for non-Ethernet link types.

    Stacked tags (QinQ) are reported outer-first so a double-tagged frame shows
    the SPAN-port service VLAN ahead of the customer VLAN.
    """
    if linktype != 1 or len(frame) < 14:
        return None
    source, destination = frame[:6], frame[6:12]
    kind = int.from_bytes(frame[12:14], "big")
    data = frame[14:]
    vlan_ids: list[int] = []
    while kind in VLAN_TPIDS:
        if len(data) < 4 or len(vlan_ids) >= MAX_QINQ_TAGS:
            raise CaptureError("Invalid VLAN header")
        vlan_ids.append(int.from_bytes(data[:2], "big") & 0x0FFF)
        kind, data = int.from_bytes(data[2:4], "big"), data[4:]
    return FrameFacts(tuple(vlan_ids), kind, _mac(source), _mac(destination), bool(vlan_ids))


class CapturePointObservations:
    """Accumulates what a capture point actually carried."""

    def __init__(self, expected: CapturePointConfig | None = None):
        self.expected = expected
        self.frames = 0
        self.analysable = 0
        self.tagged = 0
        self.untagged = 0
        self.bytes = 0
        self.vlans: dict[int, int] = {}
        self.sources: dict[str, int] = {}
        self.clock_sources: dict[str, int] = {}
        self.errors = 0

    def observe(self, frame: bytes, original: int, linktype: int, clock_source: str = "capture_clock") -> None:
        self.frames += 1
        self.bytes += len(frame)
        self.clock_sources[clock_source] = self.clock_sources.get(clock_source, 0) + 1
        try:
            facts = frame_facts(frame, linktype)
        except CaptureError:
            self.errors += 1
            return
        if facts is None:
            return
        self.analysable += 1
        self.sources[facts.source_mac] = self.sources.get(facts.source_mac, 0) + 1
        if facts.tagged:
            self.tagged += 1
            for vlan in facts.vlan_ids:
                self.vlans[vlan] = self.vlans.get(vlan, 0) + 1
        else:
            self.untagged += 1

    def report(self) -> dict:
        expected = set(self.expected.vlan_ids) if self.expected else set()
        observed = set(self.vlans)
        missing = sorted(expected - observed) if expected else []
        unexpected = sorted(observed - expected) if expected else []
        findings, verified = [], False
        if self.frames == 0:
            findings.append("No frames were observed; the mirror port, tap or VLAN range is not delivering traffic")
        elif expected:
            if missing:
                findings.append(f"Configured VLANs never appeared: {missing}")
            elif unexpected:
                findings.append(f"Observed VLANs outside the configured list: {unexpected}")
            else:
                findings.append(f"All configured VLANs observed: {sorted(observed)}")
                verified = True
        else:
            findings.append(f"{self.frames} frames observed across VLANs {sorted(observed) or ['untagged only']}")
        if self.untagged and expected:
            findings.append(f"{self.untagged} untagged frames were seen; confirm the SPAN port carries tags")
        if self.errors:
            findings.append(f"{self.errors} frames were too short to parse as Ethernet")
        substituted = self.clock_sources.get("host_clock_substituted", 0)
        if substituted:
            findings.append(
                f"{substituted} frames had no capture timestamp; host clock was substituted and marked")
        return {
            "frames_observed": self.frames,
            "bytes_observed": self.bytes,
            "ethernet_frames": self.analysable,
            "tagged_frames": self.tagged,
            "untagged_frames": self.untagged,
            "vlans_observed": {str(key): value for key, value in sorted(self.vlans.items())},
            "distinct_source_macs": len(self.sources),
            "top_sources": sorted(self.sources.items(), key=lambda item: -item[1])[:8],
            "unparseable_frames": self.errors,
            "clock_sources": self.clock_sources,
            "verified": verified,
            "findings": findings,
        }


def self_check() -> dict:
    """Prove the VLAN analysis path on synthetic frames, with no hardware needed."""
    def ethernet(ethertype, vlan=None, double_tag=None):
        frame = bytes.fromhex("020000000001") + bytes.fromhex("020000000002")
        for tag in (double_tag, vlan):
            if tag is not None:
                priority, vid = tag
                frame += (0x8100).to_bytes(2, "big") + ((priority << 13) | vid).to_bytes(2, "big")
        return frame + ethertype.to_bytes(2, "big")

    cases = {
        "untagged_ipv4": (ethernet(0x0800), ()),
        "single_vlan_100": (ethernet(0x0800, vlan=(0, 100)), (100,)),
        "vlan_4094": (ethernet(0x0800, vlan=(3, 4094)), (4094,)),
        "qinq_outer_inner": (ethernet(0x0800, vlan=(0, 200), double_tag=(0, 100)), (100, 200)),
        "sflow_ipv6": (ethernet(0x86DD, vlan=(0, 300)), (300,)),
    }
    results = {}
    for name, (frame, expected) in cases.items():
        facts = frame_facts(frame, 1)
        results[name] = {"vlan_ids": list(facts.vlan_ids) if facts else None,
                         "matches_expected": bool(facts) and facts.vlan_ids == expected}
    passed = all(item["matches_expected"] for item in results.values())
    short_frame_safe = frame_facts(b"\x00" * 8, 1) is None
    cooked_ignored = frame_facts(b"\x00" * 16, 113) is None
    malformed_rejected = False
    # A VLAN TPID with fewer than the four tag bytes present must be refused.
    truncated_tag = bytes.fromhex("020000000001020000000002") + (0x8100).to_bytes(2, "big") + b"\x00\x64"
    try:
        frame_facts(truncated_tag, 1)
    except CaptureError:
        malformed_rejected = True
    return {"passed": passed and short_frame_safe and cooked_ignored and malformed_rejected,
            "cases": results,
            "short_frame_ignored": short_frame_safe,
            "non_ethernet_ignored": cooked_ignored,
            "malformed_vlan_rejected": malformed_rejected}


def backend_report(backend: str) -> dict:
    detail = describe_backend(backend)
    detail["npcap_installed"] = npcap_installed() if os.name == "nt" else None
    detail["npcap_version"] = npcap_version() if os.name == "nt" else None
    return detail


def preflight(config: SensorConfig, interface: str | None = None, check_backend: bool = True) -> dict:
    """Check everything that can be checked before opening a capture handle.

    ``check_backend`` is turned off when the caller injects its own engine, since
    the native library probe would then describe something other than the engine
    actually in use.
    """
    backend = backend_report(config.backend)
    result = {
        "backend": backend,
        "encryption_required": config.encryption_enabled,
        "encryption_keyring_present": bool(config.encryption_keyring and os.path.isfile(config.encryption_keyring)),
        "capture_filter": config.capture_filter(),
        "capture_point": config.capture_point.model_dump() if config.capture_point else None,
        "promiscuous": config.promiscuous,
        "checks": [],
        "blocking": [],
    }
    if not check_backend:
        result["checks"].append("Backend probing skipped because a capture engine was supplied")
    elif not backend["available"]:
        result["blocking"].append(f"Capture backend {config.backend} is unavailable: {backend['error']}")
    if config.backend == "dpdk" and not config.eal_args:
        result["checks"].append("No DPDK EAL arguments configured; defaults to '-l 0 -n 1' (one lcore, one memory channel)")
    if check_backend and os.name == "nt" and not npcap_installed():
        result["blocking"].append("Npcap is not installed")
    if config.encryption_enabled and not result["encryption_keyring_present"]:
        result["blocking"].append(f"Keyring {config.encryption_keyring} is missing")
    if interface is None and config.capture_point:
        interface = config.capture_point.interface
    if interface is None:
        result["checks"].append("No interface selected; live capture will not start")
    return result


@dataclass
class ThroughputMeter:
    """Counts packets, bytes and wall time for the benchmark harness."""

    packets: int = 0
    bytes: int = 0
    started: float = field(default_factory=time.monotonic)

    def add(self, size: int, now: float | None = None) -> None:
        self.packets += 1
        self.bytes += size
        if now is not None:
            self.started = min(self.started, now)

    @property
    def elapsed(self) -> float:
        return max(time.monotonic() - self.started, 1e-9)

    def as_dict(self) -> dict:
        return {"packets": self.packets, "bytes": self.bytes,
                "seconds": round(self.elapsed, 6),
                "packets_per_second": round(self.packets / self.elapsed, 1),
                "mbits_per_second": round(self.bytes * 8 / self.elapsed / 1e6, 2)}


def benchmark_offline(config: SensorConfig, frames, linktype: int = 1, limit: int = 200000) -> dict:
    """Measure decode throughput over recorded frames; no capture hardware needed."""
    from .packets import decode_packet

    meter, decoded, truncated, failures = ThroughputMeter(), 0, 0, 0
    for index, record in enumerate(frames):
        if index >= limit:
            break
        timestamp, frame, original, frame_linktype = record
        meter.add(len(frame))
        try:
            packet = decode_packet(timestamp, frame, original, frame_linktype or linktype)
        except CaptureError:
            failures += 1
            continue
        if packet is None:
            continue
        decoded += 1
        truncated += bool(packet.truncated)
    return {**meter.as_dict(), "decoded_packets": decoded, "truncated_packets": truncated,
            "decode_failures": failures}


def synthetic_traffic(count: int, vlan_id: int | None = None, payload_size: int = 64,
                      linktype: int = 1):
    """Yield well-formed Ethernet/IPv4/TCP frames for benchmarking without a mirror port.

    Header lengths are exact and checksums are filled in, so the frames pass the
    same decoder that live captures go through.
    """
    import struct

    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\0"
        total = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    payload = bytes(payload_size)
    frame = bytearray(bytes.fromhex("020000000001020000000002"))
    if vlan_id is not None:
        frame += (0x8100).to_bytes(2, "big") + vlan_id.to_bytes(2, "big")
    frame += (0x0800).to_bytes(2, "big")
    total_length = 20 + 20 + payload_size
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    transport = struct.pack("!HHIIBBHHH", 50000, 23, 1, 0, 5 << 4, 0x18, 8192, 0, 0)
    frame += header + transport + payload
    frozen = bytes(frame)
    now = time.time()
    for index in range(count):
        yield (now + index / 1000.0, frozen, len(frozen), linktype)


def benchmark_harness(config: SensorConfig, count: int = 100000, vlan_id: int | None = None) -> dict:
    """Self-contained benchmark that runs on any host, with no capture hardware."""
    report = benchmark_offline(config, synthetic_traffic(count, vlan_id))
    report["traffic"] = {"packets": count, "vlan_id": vlan_id,
                         "payload_bytes": 64, "linktype": 1, "synthetic": True}
    report["note"] = "Synthetic traffic: measures decode and queue throughput only, not NIC or mirror capacity"
    return report


def run_verification(config: SensorConfig, interface: str | None = None, duration: int = 10,
                     engine: CaptureEngine | None = None) -> dict:
    """Observe a live capture point for ``duration`` seconds and report the findings."""
    from .engines import create_engine

    interface = interface or (config.capture_point.interface if config.capture_point else None)
    report = {"preflight": preflight(config, interface, check_backend=engine is None),
              "self_check": self_check(), "observation": None, "verified": False}
    if not report["self_check"]["passed"]:
        report["reason"] = "The VLAN self-check failed, so observation results would not be trustworthy"
        return report
    if interface is None:
        report["reason"] = "No interface was given; pass --interface or configure capture_point.interface"
        return report
    if report["preflight"]["blocking"]:
        report["reason"] = "; ".join(report["preflight"]["blocking"])
        return report

    observations = CapturePointObservations(config.capture_point)
    owns_engine = engine is None
    engine = engine or create_engine(config.backend, config.eal_args)
    try:
        engine.open(interface, config.capture_filter(), config.promiscuous)
        deadline = time.monotonic() + max(duration, 1)
        while time.monotonic() < deadline:
            record = engine.next_packet()
            if record is None:
                time.sleep(0.005)
                continue
            timestamp, frame, original, linktype, clock = normalise_timestamp(record)
            observations.observe(frame, original, linktype, clock)
        statistics = engine.statistics()
    except CaptureError as error:
        report["reason"] = f"Capture failed: {error}"
        return report
    finally:
        if owns_engine:
            engine.close()

    report["observation"] = observations.report()
    report["capture_statistics"] = statistics
    report["verified"] = observations.report()["verified"]
    report["reason"] = "Capture point verified" if report["verified"] else "; ".join(observations.report()["findings"])
    return report