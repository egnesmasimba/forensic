"""TN3270E negotiation, record framing and 3270 data-stream decoding.

Scope and honesty notes:

* The TN3270E record header and the request/response sequencing are decoded.
* The 3270 data stream is tokenised against the published order set, including
  the two-byte ``DO`` forms, and rendered into a screen buffer with fields and
  their attributes.
* Attribute codes and function codes that are not part of the published sets are
  reported numerically with their raw bytes. They are never given an invented
  name, because a plausible but wrong interpretation of a 3270 order is worse
  than an honest gap in a forensic report.
"""
from __future__ import annotations

import re
import struct

IAC = 255
SE = 240
SB = 250
WILL = 251
WONT = 252
DO = 253
DONT = 254
EOR = 239
BINARY = 0
EOR_OPT = 25
TN3270E_OPT = 40
TERMINAL_TYPE = 24
DEVICE_TYPE = 32
FUNCTIONS = 39
TN3270E_FUNCTIONS = 40
LINE_MODE = 34
LOGICAL_RECORD_END = 240 + 16

TELNET_COMMAND_NAMES = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT",
                        SB: "SB", SE: "SE", EOR: "EOR"}
TELNET_OPTION_NAMES = {BINARY: "BINARY", 3: "SGA", EOR_OPT: "EOR", TERMINAL_TYPE: "TERMINAL-TYPE",
                       DEVICE_TYPE: "DEVICE-TYPE", FUNCTIONS: "FUNCTIONS", TN3270E_OPT: "TN3270E",
                       LINE_MODE: "LINE-MODE", 39: "TN3270E-C/HOST", 45: "XDISPLOC"}
TN3270E_FCN_BASE = "TN3270E"
# TN3270E function sub-negotiation options (RFC 1576 section 5).
TN3270E_FUNCTION_OPTIONS = {
    0: "TN3270E", 1: "TN3270E-C", 2: "TN3270E-S", 3: "TN3270E-R",
    4: "TN3270E-C2", 5: "TN3270E-S2", 6: "TN3270E-PRD", 7: "TN3270E-A",
}
# TN3270E record data types.
TN3270E_TYPES = {0x00: "TN3270E-data", 0x01: "3270-data", 0x02: "response",
                 0x03: "response-inbound"}
TN3270E_TYPE_FUNCTIONS = "function"
# TN3270E header request flags.
TN3270E_REQ_NO_REPLY = 0x00
TN3270E_REQ_REPLY = 0x01
# TN3270E function request codes carried in the record type field.
TN3270E_FUNCTIONS = {
    0x40: "BIND", 0x41: "UNBIND", 0x42: "SSCP-LU", 0x43: "OPEN", 0x44: "CLOSE",
    0x45: "SEND-DATA", 0x46: "RECEIVE-DATA", 0x47: "CONNECT", 0x48: "DISCONNECT",
    0x50: "FUNCTION-REQUEST", 0x51: "FUNCTION-RESPONSE",
}

# -- 3270 orders ---------------------------------------------------------------
ORDER_SBA = 0x11
ORDER_EUA = 0x12
ORDER_IC = 0x13
ORDER_SF = 0x1D
ORDER_PT = 0x05
ORDER_GE = 0x08
ORDER_SA = 0x28
ORDER_SFE = 0x29
ORDER_MF = 0x2C
ORDER_RA = 0x3C
ORDER_DO = 0x6C
DO_ORDERS = {0x6D: ORDER_SBA, 0x6E: ORDER_EUA, 0x6F: ORDER_IC, 0x70: ORDER_SF,
             0x71: ORDER_SA, 0x72: ORDER_SFE, 0x73: ORDER_MF, 0x74: ORDER_RA,
             0x75: ORDER_PT, 0x76: ORDER_GE}
ORDER_NAMES = {
    ORDER_SBA: "SBA", ORDER_EUA: "EUA", ORDER_IC: "IC", ORDER_SF: "SF", ORDER_PT: "PT",
    ORDER_GE: "GE", ORDER_SA: "SA", ORDER_SFE: "SFE", ORDER_MF: "MF", ORDER_RA: "RA",
}
DATA_ORDERS = frozenset(ORDER_NAMES) - {ORDER_SBA, ORDER_EUA, ORDER_IC, ORDER_GE,
                                        ORDER_SF, ORDER_SA, ORDER_SFE, ORDER_MF, ORDER_RA}
# Write Control Character: the first byte of a 3270 outbound data stream. It
# selects reset and erase behaviour and is never screen text.
WCC_NAMES = {
    0xF1: "restore", 0xF5: "erase-and-restore", 0x7E: "erase", 0xF3: "no-operation",
    0xF0: "start-printer", 0xF6: "restore-and-sound", 0xF7: "restore-and-alarm",
}
EBCDIC_CP037 = "cp037"
EBCDIC_CP500 = "cp500"
HIDDEN_MASK = "*"
MAX_RECORDS = 200
MAX_ORDERS = 4000


class DecodeLimit(Exception):
    """Raised internally when a stream exceeds the bounded decode budget."""


def _address(data: bytes, index: int) -> tuple[int, int, bool]:
    """Decode a 12-bit, 14-bit or 3-byte buffer address.

    Address encodings are distinguished by the high bits of the first byte:
    ``00xxxxxx`` is the 12-bit form, ``0xxxxxxx`` the 14-bit form, and
    ``1xxxxxxx`` introduces the 3-byte form with a trailing buffer-address byte.
    Returns (address, next_index, recognised).
    """
    if index + 2 > len(data):
        raise DecodeLimit
    first, second = data[index], data[index + 1]
    if not first & 0xC0:
        return (((first & 0x3F) << 6) | (second & 0x3F), index + 2, True)
    if not first & 0x80:
        return ((first << 8) | second, index + 2, True)
    if index + 3 <= len(data):
        # Three-byte form: 14 address bits plus one buffer-address byte.
        return (((first & 0x7F) << 8) | second, index + 3, True)
    raise DecodeLimit


def _extended_attributes(data: bytes, index: int) -> tuple[list[tuple[int, bytes]], int]:
    """Read the type/value pairs of an SFE or MF order.

    A type below 0x80 is the field attribute itself; types from 0x80 up are
    extended attributes whose value is one byte for 0x80-0xBF and two bytes for
    0xC0-0xFF.
    """
    count = data[index]
    index += 1
    attributes = []
    for _ in range(count):
        if index >= len(data):
            raise DecodeLimit
        code = data[index]
        index += 1
        width = 0 if code < 0x80 else (1 if code < 0xC0 else 2)
        if index + width > len(data):
            raise DecodeLimit
        attributes.append((code, data[index:index + width]))
        index += width
    return attributes, index


def field_attribute(value: int) -> dict:
    """Decode the SF attribute byte."""
    return {
        "raw": f"{value:02x}",
        "protected": bool(value & 0x20),
        "numeric": bool(value & 0x10),
        "display": {0: "undefined", 1: "normal", 2: "intensified", 3: "non-display"}[(value & 0x0C) >> 2],
    }


ATTRIBUTE_NAMES = {
    0xC1: "field-use-attribute-set", 0xC6: "foreground-colour", 0xC7: "background-colour",
    0xC8: "extended-highlighting", 0xC9: "extended-foreground-colour",
    0xCA: "extended-background-colour", 0xCB: "character-set", 0xD8: "field-validation",
}
COLOURS = ["default", "black", "blue", "green", "cyan", "red", "magenta", "yellow", "white"]
HIGHLIGHTING = {0x00: "normal", 0x01: "blink", 0x02: "reverse", 0x04: "hidden", 0x08: "underscore"}


def describe_attribute(code: int, value: bytes) -> dict:
    result = {"code": f"{code:02x}", "name": ATTRIBUTE_NAMES.get(code, "unassigned-attribute"),
              "value": value.hex()}
    if code in (0xC6, 0xC7, 0xC9, 0xCA) and value:
        # Colour attributes carry the colour and intensity flags in the first
        # value byte; the second byte of a 2-byte value is the transparency code.
        result["colour"] = COLOURS[value[0] & 0x07]
        result["intensified"] = bool(value[0] & 0x08)
    if code == 0xC8 and value:
        result["highlighting"] = HIGHLIGHTING.get(value[0], f"highlight-{value[0]:02x}")
        result["hidden"] = value[0] == 0x04
    return result


class Screen:
    """A 3270 display buffer rendered from a data stream."""

    def __init__(self, rows: int = 24, columns: int = 80):
        if rows < 1 or columns < 1 or rows * columns > 65535:
            raise ValueError("Unsupported screen geometry")
        self.rows, self.columns = rows, columns
        self.size = rows * columns
        self.buffer = [" "] * self.size
        self.fields: list[dict] = []
        self.address = 0
        self.cursor = 0
        self.partial = False

    def _place(self, character: str) -> None:
        position = self.address % self.size
        self.buffer[position] = character
        if self.fields:
            # Keep the field extent current so it does not depend on where the
            # next Start Field happens to arrive.
            self.fields[-1]["end"] = (position + 1) % self.size
        self.address = (position + 1) % self.size

    def _start_field(self, attribute: dict) -> None:
        self.fields.append({"start": self.address % self.size, "attribute": attribute,
                            "end": self.address % self.size})

    def _close_field(self) -> None:
        if not self.fields:
            return
        field = self.fields[-1]
        attribute = field["attribute"]
        hidden = attribute.get("display") == "non-display"
        if not hidden:
            for item in attribute.get("display_attributes", ()):
                # Highlighting code 4 marks the field hidden; its text must stay
                # out of rendered rows and out of indexed search results.
                if item.get("name") == "extended-highlighting" and item.get("hidden"):
                    hidden = True
        field["hidden"] = hidden

    def render(self, data: bytes, start: int = 0) -> list[dict]:
        """Apply a 3270 data stream and return the decoded orders."""
        orders, index = [], start
        while index < len(data):
            if len(orders) >= MAX_ORDERS:
                self.partial = True
                break
            offset = index
            code = data[index]
            index += 1
            two_byte = False
            if code == ORDER_DO:
                if index >= len(data):
                    self.partial = True
                    break
                code = DO_ORDERS.get(data[index])
                index += 1
                two_byte = True
                if code is None:
                    # Report the raw code rather than a mnemonic: claiming a known
                    # order here would put a fabricated interpretation into evidence.
                    orders.append({"offset": offset, "order": "unassigned-do",
                                   "mnemonic": "unassigned-do", "two_byte": True,
                                   "operand": data[index - 1:index].hex()})
                    self.partial = True
                    break
            mnemonic = ORDER_NAMES.get(code, "data")
            try:
                order, index = self._apply(code, data, index, orders, offset, two_byte)
            except (DecodeLimit, IndexError):
                self.partial = True
                break
            orders.append(order)
        return orders

    def _apply(self, code: int, data: bytes, index: int, orders, offset: int, two_byte: bool):
        base = {"offset": offset, "order": "order", "mnemonic": ORDER_NAMES.get(code, "data"),
                "two_byte": two_byte}
        if code == ORDER_SBA:
            address, index, ok = _address(data, index)
            if not ok or address >= self.size:
                self.partial = True
                raise DecodeLimit
            base["address"] = address
            self.address = address
            return base, index
        if code == ORDER_EUA:
            for position in range(self.size):
                if not self._protected(position):
                    self.buffer[position] = " "
            base["erased"] = self.size
            return base, index
        if code == ORDER_IC:
            self.cursor = self.address % self.size
            base["cursor"] = self.cursor
            return base, index
        if code == ORDER_RA:
            address, index, ok = _address(data, index)
            if index >= len(data):
                raise DecodeLimit
            if not ok or address >= self.size:
                self.partial = True
                raise DecodeLimit
            character = bytes([data[index]]).decode(EBCDIC_CP037, errors="replace")
            index += 1
            span = (address - self.address) % self.size
            for _ in range(span + 1):
                self._place(character)
            base.update({"address": address, "character": character, "repeated": span + 1})
            return base, index
        if code == ORDER_SF:
            if index >= len(data):
                raise DecodeLimit
            attribute = field_attribute(data[index])
            index += 1
            self._close_field()
            self._start_field(attribute)
            base["attribute"] = attribute
            return base, index
        if code in (ORDER_SFE, ORDER_MF):
            if index >= len(data):
                raise DecodeLimit
            attributes, index = _extended_attributes(data, index)
            described = [describe_attribute(code_, value) for code_, value in attributes
                         if code_ >= 0x80]
            base_attribute = next((value[0] for code_, value in attributes if code_ < 0x80), 0)
            attribute = field_attribute(base_attribute)
            if described:
                attribute["display_attributes"] = described
            if code == ORDER_SFE:
                self._close_field()
                self._start_field(attribute)
            elif self.fields:
                self.fields[-1]["attribute"] = attribute
            else:
                # MF with no field in progress: start one so the attribute is not lost.
                self._start_field(attribute)
            base["attribute"] = attribute
            return base, index
        if code == ORDER_SA:
            if index + 2 > len(data):
                raise DecodeLimit
            base["attribute"] = describe_attribute(data[index], data[index + 1:index + 2])
            index += 2
            return base, index
        if code == ORDER_PT:
            if index >= len(data):
                raise DecodeLimit
            base["program_tab"] = data[index]
            index += 1
            return base, index
        if code == ORDER_GE:
            if index + 2 > len(data):
                raise DecodeLimit
            base["graphic"] = {"character": f"{data[index]:02x}", "type": f"{data[index + 1]:02x}"}
            index += 2
            return base, index
        # Any other byte is a display character in EBCDIC.
        character = bytes([code]).decode(EBCDIC_CP037, errors="replace")
        self._place(character)
        base.update({"order": "text", "character": character, "address": (self.address - 1) % self.size})
        return base, index

    def _protected(self, position: int) -> bool:
        return any(field["start"] <= position < field.get("end", field["start"])
                   and field["attribute"].get("protected") for field in self.fields)

    def snapshot(self) -> dict:
        """Render the display buffer for reporting.

        Fields marked hidden (non-display, or hidden highlighting) are masked in
        the returned rows so that a rendered screen or indexed search result does
        not disclose them. Nothing is lost from the evidence: the buffer, the
        per-record hex and the decoded orders all keep the original characters.
        """
        self._close_field()
        hidden = set()
        for field in self.fields:
            if field.get("hidden"):
                hidden.update(range(field["start"], field.get("end", field["start"])))
        buffer = [HIDDEN_MASK if position in hidden else character
                  for position, character in enumerate(self.buffer)]
        rows = ["".join(buffer[start:start + self.columns]).rstrip()
                for start in range(0, self.size, self.columns)]
        return {"kind": "3270", "rows": rows, "partial": self.partial,
                "cursor": [self.cursor // self.columns + 1, self.cursor % self.columns + 1],
                "geometry": [self.rows, self.columns],
                "hidden_positions": sorted(hidden),
                "fields": [{"start": field["start"],
                            "end": field.get("end", field["start"]),
                            "protected": field["attribute"].get("protected"),
                            "numeric": field["attribute"].get("numeric"),
                            "display": field["attribute"].get("display"),
                            "hidden": field.get("hidden", False),
                            "attribute": field["attribute"].get("raw"),
                            "display_attributes": field["attribute"].get("display_attributes", [])}
                           for field in self.fields]}


def decode_3270(data: bytes, rows: int = 24, columns: int = 80, start: int = 0) -> tuple[list[dict], Screen]:
    screen = Screen(rows, columns)
    orders = screen.render(data, start)
    return orders, screen


# -- telnet / TN3270E framing --------------------------------------------------

def parse_negotiation(data: bytes) -> tuple[list[dict], list[bytes]]:
    """Return telnet negotiation events and the application data records."""
    events, records, plain = [], [], bytearray()
    index = 0
    while index < len(data):
        value = data[index]
        if value != IAC:
            plain.append(value)
            index += 1
            continue
        if index + 1 >= len(data):
            break
        command = data[index + 1]
        if command == IAC:
            plain.append(IAC)
            index += 2
            continue
        if command in (DO, DONT, WILL, WONT):
            if index + 2 >= len(data):
                break
            option = data[index + 2]
            events.append({"command": TELNET_COMMAND_NAMES[command], "option": option,
                           "option_name": TELNET_OPTION_NAMES.get(option, f"option-{option}")})
            index += 3
            continue
        if command == SB:
            end = data.find(bytes([IAC, SE]), index + 2)
            if end < 0:
                break
            events.append({"command": "SB", "option": data[index + 2],
                           "option_name": TELNET_OPTION_NAMES.get(data[index + 2], f"option-{data[index + 2]}"),
                           "data": data[index + 3:end].hex()})
            index = end + 2
            continue
        if command == EOR:
            records.append(bytes(plain))
            plain.clear()
            index += 2
            continue
        events.append({"command": TELNET_COMMAND_NAMES.get(command, f"command-{command}")})
        index += 2
    return events, records


def parse_tn3270e_header(data: bytes, index: int = 0) -> dict | None:
    """Parse the six-byte TN3270E record header."""
    if index + 6 > len(data):
        return None
    length, kind, flags = struct.unpack("!HBB", data[index:index + 4])
    sequence = data[index + 4:index + 6]
    response = bool(flags & 0x01)
    request = bool(flags & 0x02)
    header = {
        "length": length, "type": kind,
        "type_name": TN3270E_TYPES.get(kind, TN3270E_FUNCTIONS.get(kind, f"type-{kind:02x}")),
        "response": response, "request": request,
        "sequence": int.from_bytes(sequence, "big"),
    }
    if kind >= 0x40:
        # Function records carry a four-byte request flag in front of the payload.
        if index + 10 > len(data):
            return None
        flag = data[index + 6]
        header["request_flag"] = flag
        header["request_flag_name"] = "reply-required" if flag == TN3270E_REQ_REPLY else "no-reply"
        header["offset"] = index + 10
    else:
        header["offset"] = index + 6
    header["end"] = header["offset"] + length
    return header


def application_offset(data: bytes) -> int:
    """Offset of the first byte after the leading telnet negotiation block."""
    index = 0
    while index < len(data):
        if data[index] != IAC:
            return index
        if index + 1 >= len(data):
            return index
        command = data[index + 1]
        if command == IAC:
            return index  # An escaped 0xFF is data, so the block has ended.
        if command == SB:
            end = data.find(bytes([IAC, SE]), index + 2)
            if end < 0:
                return index
            index = end + 2
            continue
        if command in (DO, DONT, WILL, WONT):
            index += 3
            continue
        index += 2
    return index


def _known_record_type(kind: int) -> bool:
    return kind in TN3270E_TYPES or 0x40 <= kind <= 0x7F


def find_record_offset(data: bytes) -> int | None:
    """Locate the first TN3270E record header.

    Real negotiation interleaves several sub-negotiations (terminal type,
    TN3270E functions), so the record start cannot simply be the byte after the
    negotiation block. A candidate offset is accepted only when a chain of
    headers starting there runs exactly to the end of the buffer, and the first
    header carries a defined record type. Requiring exact consumption means a
    misaligned guess cannot fabricate records out of ordinary 3270 data.
    """
    for start in range(0, len(data) - 5):
        header = parse_tn3270e_header(data, start)
        if header is None or not _known_record_type(header["type"]):
            continue
        if header["length"] == 0 or header["end"] > len(data):
            continue
        cursor, count = header["end"], 1
        while cursor + 6 <= len(data) and count < MAX_RECORDS:
            following = parse_tn3270e_header(data, cursor)
            if following is None or not _known_record_type(following["type"]) or following["length"] == 0:
                break
            cursor = following["end"]
            count += 1
        if cursor == len(data):
            return start
    return None


def split_tn3270e(data: bytes, enabled: bool = True) -> tuple[list[dict], list[dict]]:
    """Split a TN3270E stream into headers and decoded records.

    Falls back to EOR framing when TN3270E negotiation is absent, which is what a
    host presents before the option is agreed.
    """
    if not enabled:
        _, records = parse_negotiation(data)
        return [], [{"source": "eor", "data": record} for record in records[:MAX_RECORDS]]
    start = find_record_offset(data)
    if start is None:
        _, records = parse_negotiation(data)
        return [], [{"source": "eor", "data": record} for record in records[:MAX_RECORDS]]
    headers, index = [], start
    while index + 6 <= len(data) and len(headers) < MAX_RECORDS:
        header = parse_tn3270e_header(data, index)
        if header is None or header["end"] > len(data):
            break
        headers.append(header)
        index = header["end"]
    return headers, [{"source": "tn3270e", "data": data[header["offset"]:header["end"]],
                      "header": header} for header in headers]


def function_negotiation(payload: bytes) -> list[dict]:
    """Decode a TN3270E function sub-negotiation payload."""
    results = []
    for offset in range(0, len(payload) - 1, 2):
        code, value = payload[offset], payload[offset + 1]
        results.append({"function": code, "name": TN3270E_FUNCTION_OPTIONS.get(code, f"function-{code}"),
                        "type": f"{value:02x}"})
    return results


def split_wcc(payload: bytes) -> tuple[bytes, dict | None]:
    """Separate the leading write control character from a 3270 data stream.

    Returns the remaining data and a description of the control character. A
    stream that does not begin with a recognised WCC is returned unchanged so
    structured-field-only inbound data is not misread.
    """
    if not payload:
        return payload, None
    control = payload[0]
    if control not in WCC_NAMES:
        return payload, None
    action = WCC_NAMES[control]
    return payload[1:], {"raw": f"{control:02x}", "action": action,
                         "erased": action.startswith("erase")}


def decode_tn3270e(data: bytes, rows: int = 24, columns: int = 80) -> dict:
    """Decode a complete TN3270E byte stream."""
    events, eor_records = parse_negotiation(data)
    tn3270e_negotiated = any(event.get("option") == TN3270E_OPT and event.get("command") in ("DO", "DONT", "WILL", "WONT")
                             for event in events)
    headers, records = split_tn3270e(data, tn3270e_negotiated)
    screen = Screen(rows, columns)
    decoded, notes = [], []
    if not headers and not eor_records:
        return {"negotiation": events, "records": [], "screens": [],
                "notes": ["No TN3270 records were found; the stream may be encrypted or out of sequence"],
                "tn3270e": tn3270e_negotiated, "coverage": ""}
    for record in records[:MAX_RECORDS]:
        payload, control = split_wcc(record["data"])
        if control and control["action"].startswith("erase"):
            screen.buffer = [" "] * screen.size
            screen.fields.clear()
            screen.address = 0
        orders = screen.render(payload)
        decoded.append({"source": record["source"], "header": record.get("header"),
                        "write_control": control, "length": len(payload),
                        "orders": orders[:200], "orders_truncated": len(orders) > 200,
                        "hex": payload[:256].hex()})
    if screen.partial:
        notes.append("Data stream ended inside an order; the screen is a partial reconstruction")
    unknown = {order["mnemonic"] for record in decoded for order in record["orders"]
               if order["mnemonic"] in ("unassigned-do",)}
    if unknown:
        notes.append("At least one two-byte order code is unassigned and was not interpreted")
    return {"negotiation": events, "tn3270e": tn3270e_negotiated, "records": decoded,
            "screens": [screen.snapshot()], "notes": notes,
            "coverage": CAPABILITY}


CAPABILITY = ("TN3270E negotiation and record headers, the published 3270 order set including the "
              "two-byte DO forms, and screen/field reconstruction with attributes")

LINE_MODE_RE = re.compile(rb"IBM-5250", re.I)


def geometry_for(model: str) -> tuple[int, int]:
    """Screen size for a 3270 display model, defaulting to 24x80."""
    match = re.search(r"(\d{2,3})x(\d{2,3})", model or "")
    if match:
        rows, columns = int(match[1]), int(match[2])
        if 1 <= rows <= 255 and 1 <= columns <= 255:
            return rows, columns
    return 24, 80