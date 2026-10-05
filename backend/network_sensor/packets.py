import ipaddress
import struct
from dataclasses import dataclass


@dataclass
class Packet:
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    transport: str
    payload: bytes
    sequence: int = 0
    flags: int = 0
    truncated: bool = False
    capture_source: str = "default"


class CaptureError(ValueError):
    pass


def pcap_records(stream):
    """Read classic PCAP or timestamped PCAPNG without requiring a seekable stream."""
    magic = stream.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        from .pcapng import pcapng_records
        yield from pcapng_records(stream, magic)
        return
    header = magic + stream.read(20)
    if len(header) != 24:
        raise CaptureError("Missing PCAP header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if header[:4] not in formats:
        raise CaptureError("Unrecognized capture format; use PCAP or PCAPNG")
    endian, resolution = formats[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 1048576:
        raise CaptureError("Unsupported PCAP version or snapshot length")
    if linktype not in (1, 101, 113, 276):
        raise CaptureError(f"Unsupported capture link type {linktype}")
    while True:
        record = stream.read(16)
        if not record:
            return
        if len(record) != 16:
            raise CaptureError("Incomplete PCAP packet header")
        seconds, fraction, size, original = struct.unpack(endian + "IIII", record)
        if size > snaplen or size > original or fraction >= resolution:
            raise CaptureError("Invalid PCAP packet length or timestamp")
        data = stream.read(size)
        if len(data) != size:
            raise CaptureError("Incomplete PCAP packet data")
        yield seconds + fraction / resolution, data, original, linktype


def decode_packet(timestamp, frame, original, linktype=1):
    """Ethernet/VLAN, raw IP, Linux cooked; TCP/UDP over unfragmented IPv4/IPv6."""
    data = frame
    if linktype == 1:
        if len(data) < 14:
            raise CaptureError("Short Ethernet header")
        kind = int.from_bytes(data[12:14], "big")
        data = data[14:]
        vlan_count = 0
        while kind in (0x8100, 0x88A8):
            vlan_count += 1
            if len(data) < 4 or vlan_count > 4:
                raise CaptureError("Invalid VLAN header")
            kind, data = int.from_bytes(data[2:4], "big"), data[4:]
    elif linktype == 113:
        if len(data) < 16:
            raise CaptureError("Short Linux cooked header")
        kind, data = int.from_bytes(data[14:16], "big"), data[16:]
    elif linktype == 276:
        if len(data) < 20:
            raise CaptureError("Short Linux cooked v2 header")
        kind, data = int.from_bytes(data[:2], "big"), data[20:]
    else:
        kind = 0x86DD if data and data[0] >> 4 == 6 else 0x0800
    if kind == 0x0800:
        if len(data) < 20 or data[0] >> 4 != 4:
            raise CaptureError("Invalid IPv4 header")
        offset = (data[0] & 15) * 4
        total = int.from_bytes(data[2:4], "big")
        if offset < 20 or total < offset or len(data) < offset:
            raise CaptureError("Invalid IPv4 lengths")
        if int.from_bytes(data[6:8], "big") & 0x3FFF:
            return None  # Fragment reassembly is deliberately not inferred.
        protocol = data[9]
        source, destination = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
        truncated = len(frame) < original or len(data) < total
        data = data[offset:total]
    elif kind == 0x86DD:
        if len(data) < 40 or data[0] >> 4 != 6:
            raise CaptureError("Invalid IPv6 header")
        total = 40 + int.from_bytes(data[4:6], "big")
        protocol = data[6]
        source, destination = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
        truncated = len(frame) < original or len(data) < total
        data = data[40:total]
        extensions = 0
        while protocol in (0, 43, 60, 51):
            extensions += 1
            if len(data) < 2 or extensions > 8:
                raise CaptureError("Invalid IPv6 extension chain")
            length = (data[1] + 2) * 4 if protocol == 51 else (data[1] + 1) * 8
            if len(data) < length:
                raise CaptureError("Short IPv6 extension")
            protocol, data = data[0], data[length:]
        if protocol == 44:
            return None
    else:
        return None
    if protocol == 6:
        if len(data) < 20:
            raise CaptureError("Short TCP header")
        source_port, destination_port, sequence = struct.unpack("!HHI", data[:8])
        offset = (data[12] >> 4) * 4
        if offset < 20 or offset > len(data):
            raise CaptureError("Invalid TCP header length")
        return Packet(timestamp, source, destination, source_port, destination_port, "tcp",
                      data[offset:], sequence, data[13], truncated)
    if protocol == 17:
        if len(data) < 8:
            raise CaptureError("Short UDP header")
        source_port, destination_port, length = struct.unpack("!HHH", data[:6])
        if length < 8:
            raise CaptureError("Invalid UDP length")
        return Packet(timestamp, source, destination, source_port, destination_port, "udp",
                      data[8:length], truncated=truncated or length > len(data))
    return None


class PcapWriter:
    def __init__(self, stream, linktype=1):
        self.stream = stream
        stream.write(struct.pack("<I H H i I I I", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, timestamp, data, original=None):
        seconds = int(timestamp)
        data = data[:65535]
        self.stream.write(struct.pack("<IIII", seconds, int((timestamp - seconds) * 1e6), len(data), original or len(data)))
        self.stream.write(data)


def _l3(frame, linktype):
    data = frame
    if linktype == 1:
        if len(data) < 14:
            return None
        kind = int.from_bytes(data[12:14], "big")
        data = data[14:]
        while kind in (0x8100, 0x88A8):
            if len(data) < 4:
                return None
            kind, data = int.from_bytes(data[2:4], "big"), data[4:]
    elif linktype == 113:
        if len(data) < 16:
            return None
        kind, data = int.from_bytes(data[14:16], "big"), data[16:]
    elif linktype == 276:
        if len(data) < 20:
            return None
        kind, data = int.from_bytes(data[:2], "big"), data[20:]
    else:
        kind = 0x86DD if data and data[0] >> 4 == 6 else 0x0800
    return kind, data


class FragmentTable:
    """Reassemble IPv4 fragments only when every piece is present and overlaps agree."""

    def __init__(self, max_sets=32):
        self.sets = {}
        self.max_sets = max_sets

    def consider(self, timestamp, frame, original, linktype, capture_source="default"):
        parsed = _l3(frame, linktype)
        if parsed is None or parsed[0] != 0x0800:
            return None
        data = parsed[1]
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        header = (data[0] & 15) * 4
        total = int.from_bytes(data[2:4], "big")
        word = int.from_bytes(data[6:8], "big")
        if header < 20 or total < header or len(data) < total or not word & 0x3FFF:
            return None
        offset = (word & 0x1FFF) * 8
        payload = data[header:total]
        if offset + len(payload) > 65535 or not payload:
            return None
        key = (data[12:16], data[16:20], data[9], data[4:6], capture_source)
        entry = self.sets.get(key)
        if entry is None:
            if len(self.sets) >= self.max_sets:
                return None
            entry = self.sets[key] = {"parts": {}, "end": None, "timestamp": timestamp, "truncated": len(frame) < original}
        previous = entry["parts"].get(offset)
        if previous is not None and previous != payload:
            self.sets.pop(key, None)
            return None
        entry["parts"][offset] = payload
        entry["truncated"] |= len(frame) < original
        if not word & 0x2000:
            entry["end"] = offset + len(payload)
        if entry["end"] is None:
            return []
        blob = bytearray()
        cursor = 0
        for part_offset in sorted(entry["parts"]):
            chunk = entry["parts"][part_offset]
            if part_offset > cursor:
                return []
            if part_offset < cursor and chunk[:cursor - part_offset] != bytes(blob[part_offset:cursor]):
                self.sets.pop(key, None)
                return None
            end = part_offset + len(chunk)
            if end > cursor:
                blob.extend(chunk[cursor - part_offset:])
                cursor = end
        if cursor < entry["end"]:
            return []
        self.sets.pop(key, None)
        source = str(ipaddress.ip_address(key[0]))
        destination = str(ipaddress.ip_address(key[1]))
        return _transport(entry["timestamp"], source, destination, key[2], bytes(blob), entry["truncated"])


def _transport(timestamp, source, destination, protocol, data, truncated):
    if protocol == 6:
        if len(data) < 20:
            return None
        source_port, destination_port, sequence = struct.unpack("!HHI", data[:8])
        offset = (data[12] >> 4) * 4
        if offset < 20 or offset > len(data):
            return None
        return [Packet(timestamp, source, destination, source_port, destination_port, "tcp",
                       data[offset:], sequence, data[13], truncated)]
    if protocol == 17:
        if len(data) < 8:
            return None
        source_port, destination_port, length = struct.unpack("!HHH", data[:6])
        if length < 8:
            return None
        return [Packet(timestamp, source, destination, source_port, destination_port, "udp",
                       data[8:length], truncated=truncated or length > len(data))]
    return None
