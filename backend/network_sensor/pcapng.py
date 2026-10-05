"""Bounded PCAPNG reader for timestamped Enhanced and legacy Packet Blocks.

Simple Packet Blocks lack timestamps and are rejected rather than assigning
invented times to evidence. Unknown metadata blocks are safely skipped.
"""
import struct

from .packets import CaptureError

MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_BLOCK = 2 * 1024 * 1024


class CaptureRecord(tuple):
    def __new__(cls, values, source):
        record = super().__new__(cls, values)
        record.capture_source = source
        return record


def options(data, endian):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise CaptureError("Incomplete PCAPNG option")
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            if length or offset != len(data):
                raise CaptureError("Invalid PCAPNG option terminator")
            return
        padded = (length + 3) & ~3
        if offset + padded > len(data):
            raise CaptureError("Invalid PCAPNG option length")
        yield code, data[offset:offset + length]
        offset += padded


def pcapng_records(stream, magic=MAGIC):
    endian, interfaces, section, blocks = None, [], -1, 0
    prefix = magic
    while prefix:
        blocks += 1
        if blocks > 1_000_000:
            raise CaptureError("PCAPNG exceeds block limit")
        header = prefix + stream.read(8)
        if len(header) != 12:
            raise CaptureError("Incomplete PCAPNG block header")
        is_section = prefix == MAGIC
        if is_section:
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12])
            if endian is None:
                raise CaptureError("Invalid PCAPNG byte-order magic")
        if endian is None:
            raise CaptureError("PCAPNG must start with a section header")
        kind, length = struct.unpack(endian + "II", header[:8])
        if length < (28 if is_section else 12) or length % 4 or length > MAX_BLOCK:
            raise CaptureError("Invalid or oversized PCAPNG block")
        rest = stream.read(length - 12)
        if len(rest) != length - 12:
            raise CaptureError("Incomplete PCAPNG block")
        block = header + rest
        if struct.unpack(endian + "I", block[-4:])[0] != length:
            raise CaptureError("PCAPNG block lengths disagree")
        body = block[8:-4]
        if is_section:
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise CaptureError("Unsupported PCAPNG version")
            list(options(body[16:], endian))
            section += 1
            interfaces = []
        elif kind == 1:
            if len(body) < 8 or len(interfaces) >= 64:
                raise CaptureError("Invalid PCAPNG interface or interface limit exceeded")
            linktype, reserved, snaplen = struct.unpack_from(endian + "HHI", body)
            if reserved or (snaplen and snaplen > 1048576):
                raise CaptureError("Invalid PCAPNG interface snapshot length")
            resolution, time_offset, seen = 1e6, 0, set()
            for code, value in options(body[8:], endian):
                if code in (9, 14):
                    if code in seen or len(value) != (1 if code == 9 else 8):
                        raise CaptureError("Invalid PCAPNG timestamp option")
                    seen.add(code)
                    if code == 9:
                        exponent = value[0]
                        resolution = (2 if exponent & 128 else 10) ** (exponent & 127)
                    else:
                        time_offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((linktype, snaplen, resolution, time_offset))
        elif kind in (2, 6):
            if len(body) < 20:
                raise CaptureError("Incomplete PCAPNG packet header")
            if kind == 6:
                interface, high, low, size, original = struct.unpack_from(endian + "IIIII", body)
            else:
                interface, _, high, low, size, original = struct.unpack_from(endian + "HHIIII", body)
            if interface >= len(interfaces):
                raise CaptureError("Unknown PCAPNG packet interface")
            linktype, snaplen, resolution, time_offset = interfaces[interface]
            if linktype not in (1, 101, 113, 276):
                raise CaptureError(f"Unsupported capture link type {linktype}")
            padded = (size + 3) & ~3
            if size > original or size > (snaplen or 1048576) or 20 + padded > len(body):
                raise CaptureError("Invalid PCAPNG packet length")
            list(options(body[20 + padded:], endian))
            timestamp = ((high << 32) | low) / resolution + time_offset
            yield CaptureRecord((timestamp, body[20:20 + size], original, linktype), f"section-{section}/interface-{interface}")
        elif kind == 3:
            raise CaptureError("PCAPNG Simple Packet Blocks have no timestamps; export timestamped packets")
        prefix = stream.read(4)
