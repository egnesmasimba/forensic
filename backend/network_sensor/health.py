"""Health transitions and SNMPv2c notifications (opt-in, community from environment)."""
import socket
import time


def tlv(tag, data):
    length = len(data)
    raw = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
    return bytes([tag]) + (bytes([length]) if length < 128 else bytes([0x80 | len(raw)]) + raw) + data


def integer(value, tag=2):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 128:
        raw = b"\0" + raw
    return tlv(tag, raw)


def oid(value):
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray()
    for number in [parts[0] * 40 + parts[1], *parts[2:]]:
        octets = [number & 127]
        number >>= 7
        while number:
            octets.insert(0, (number & 127) | 128)
            number >>= 7
        encoded.extend(octets)
    return tlv(6, bytes(encoded))


def trap_packet(community, notification_oid, message, uptime=0, request_id=1):
    def binding(name, value):
        return tlv(0x30, oid(name) + value)
    bindings = binding("1.3.6.1.2.1.1.3.0", integer(uptime, 0x43))
    bindings += binding("1.3.6.1.6.3.1.1.4.1.0", oid(notification_oid))
    # 32473 is reserved for documentation; deployments must configure their own enterprise OID.
    bindings += binding(notification_oid + ".1", tlv(4, message.encode()[:240]))
    pdu = tlv(0xA7, integer(request_id) + integer(0) + integer(0) + tlv(0x30, bindings))
    return tlv(0x30, integer(1) + tlv(4, community.encode()) + pdu)


class HealthMonitor:
    def __init__(self, idle_seconds=60, empty_seconds=30, backlog_ratio=0.8, min_disk_bytes=128 * 1024 * 1024,
                 repeat_seconds=300, notify=None):
        self.started = time.monotonic()
        self.last_packet = self.started
        self.empty_since = self.started
        self.active = {}
        self.idle_seconds, self.empty_seconds = idle_seconds, empty_seconds
        self.backlog_ratio, self.min_disk_bytes = backlog_ratio, min_disk_bytes
        self.repeat_seconds, self.notify = repeat_seconds, notify

    def packet_seen(self, now=None):
        self.last_packet = time.monotonic() if now is None else now

    def check(self, queue_size, capacity, disk_free, now=None):
        now = time.monotonic() if now is None else now
        if queue_size:
            self.empty_since = now
        conditions = {"not_capturing": now - self.last_packet >= self.idle_seconds,
                      "empty_queue": queue_size == 0 and now - self.empty_since >= self.empty_seconds,
                      "backlog": queue_size / capacity >= self.backlog_ratio,
                      "low_disk": disk_free < self.min_disk_bytes}
        events = []
        for name, triggered in conditions.items():
            if triggered and (name not in self.active or now - self.active[name] >= self.repeat_seconds):
                event = {"condition": name, "status": "active", "queue_size": queue_size, "disk_free": disk_free}
                self.active[name] = now
                events.append(event)
            elif not triggered and name in self.active:
                self.active.pop(name)
                events.append({"condition": name, "status": "recovered", "queue_size": queue_size, "disk_free": disk_free})
        if self.notify:
            for event in events:
                self.notify(event)
        return events


class SnmpNotifier:
    def __init__(self, host, port, community, enterprise_oid):
        if not community or len(community) > 64:
            raise ValueError("SNMP community must have 1–64 characters")
        parts = [int(part) for part in enterprise_oid.split(".")]
        if parts[:6] != [1, 3, 6, 1, 4, 1] or len(parts) < 7 or any(part < 0 or part > 2**32 - 1 for part in parts):
            raise ValueError("Configure a valid private enterprise OID")
        self.address, self.community, self.enterprise_oid = (host, port), community, enterprise_oid
        self.started, self.counter = time.monotonic(), 0

    def __call__(self, event):
        code = ["not_capturing", "empty_queue", "backlog", "low_disk"].index(event["condition"]) + 1
        self.counter = (self.counter + 1) % 2147483647
        packet = trap_packet(self.community, self.enterprise_oid + f".{code}",
                             f"{event['condition']}: {event['status']}", int((time.monotonic() - self.started) * 100), self.counter)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(packet, self.address)
