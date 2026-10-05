"""SNA transport headers and Enterprise Extender framing.

Only fields that are fixed by the SNA transport and Network Services layouts are
decoded. Format IDs, request-unit types and name types outside the tables below
are reported as numeric values with their raw bytes: naming an RU or name type
from a half-remembered table would put a wrong label in a forensic report, which
is worse than an explicit gap.

Enterprise Extender is located by its CEE signature rather than by assuming a
fixed header length, so the decoder keeps working across EE and EE2 variants.
"""
from __future__ import annotations

import struct

CEE_SIGNATURE = b"\xc3\xc5\xc5"
CEE_SEARCH_WINDOW = 32
FID_MINIMUM = 0x08
TH_SIZE = 4
RH_SIZE = 12

# Format IDs that are common enough to name with confidence.
FID_NAMES = {
    0x11: "FID2-SNC", 0x16: "FID2-SNC", 0x17: "FID2-SNC", 0x18: "FID2-SNC",
    0x19: "FID2-PID", 0x1A: "FID2-TID", 0x1B: "FID2-NID",
    0x1D: "FID3-SNC", 0x1E: "FID3-PID", 0x1F: "FID3-TID", 0x20: "FID3-NID",
    0x24: "FID4-SNC", 0x25: "FID4-PID", 0x26: "FID4-TID", 0x27: "FID4-NID",
    0x2F: "FID5-SNC", 0x30: "FID5-PID", 0x31: "FID5-TID", 0x32: "FID5-NID",
    0x34: "FID6-SNC", 0x35: "FID6-PID", 0x36: "FID6-TID", 0x37: "FID6-NID",
    0x38: "FID7-PID", 0x39: "FID7-TID", 0x3A: "FID7-NID",
    0x3B: "FID8-PID", 0x3C: "FID8-TID", 0x3D: "FID8-NID",
    0x3E: "FID9-SNC", 0x3F: "FID9-PID", 0x40: "FID9-TID", 0x41: "FID9-NID",
}
THI_NAMES = {0: "GHI", 1: "RHI", 2: "HI", 3: "LI"}
RESPONSE_TYPES = {0: "FTN", 1: "FSN", 2: "RSN"}
RU_NAMES = {
    0x00: "NOP", 0x04: "ACTLU", 0x09: "DSC", 0x31: "BIND", 0x32: "UNBIND",
    0x43: "FCS", 0x47: "FCS", 0x50: "FC", 0x51: "NFGM", 0x60: "FIM", 0x70: "CCW", 0x81: "EXCS",
}
# Name/address types that are unambiguous when they appear in the DS/NS area.
NAME_TYPES = {
    0x00: "SCNA", 0x04: "BIND-RQ", 0x10: "SCNL", 0x18: "UNBIND-RQ",
    0x23: "CTC", 0xE0: "CLASSDR", 0xE1: "CLMSDR", 0xE2: "LU-NAME",
    0xE3: "CP-NAME", 0xE4: "TP-NAME", 0xE5: "DP-NAME",
}
EBCDIC = "cp037"


def _ebcdic(raw: bytes) -> str:
    return raw.decode(EBCDIC, errors="replace")


def parse_sna(data: bytes, offset: int = 0) -> dict:
    """Decode an SNA Transport Header and, when present, its Request Header."""
    if offset + TH_SIZE > len(data):
        return {"error": "Truncated SNA transport header", "length": len(data)}
    fid, thi_first, reserved, control = data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
    th_type = control & 0x03
    thi_second = (control >> 6) & 0x03
    header = {
        "offset": offset,
        "fid": fid,
        "fid_name": FID_NAMES.get(fid, f"fid-{fid:02x}"),
        "thi_first": THI_NAMES.get(thi_first & 0x03, f"thi-{thi_first & 0x03}"),
        "reserved": reserved,
        "th_type": THI_NAMES.get(th_type, f"th-{th_type}"),
        "rh_present": thi_second == 1,
        "raw": data[offset:offset + TH_SIZE].hex(),
    }
    cursor = offset + TH_SIZE
    if not header["rh_present"]:
        return header
    if cursor + RH_SIZE > len(data):
        header["error"] = "Request header flagged present but truncated"
        return header
    flags = data[cursor]
    header["rh"] = {
        "offset": cursor,
        "rhqd": bool(flags & 0x80),
        "rho": bool(flags & 0x40),
        "response_type": RESPONSE_TYPES.get((flags >> 4) & 0x03, f"rtyp-{(flags >> 4) & 0x03}"),
        "rhd": (flags >> 2) & 0x03,
        "reserved": flags & 0x03,
        "rid": int.from_bytes(data[cursor + 1:cursor + 3], "big"),
        "ru_code": int.from_bytes(data[cursor + 3:cursor + 5], "big"),
        "rsrc": int.from_bytes(data[cursor + 5:cursor + 7], "big"),
        "sequence": int.from_bytes(data[cursor + 7:cursor + 9], "big"),
        "raw": data[cursor:cursor + RH_SIZE].hex(),
    }
    header["rh"]["ru_name"] = RU_NAMES.get(header["rh"]["ru_code"], f"ru-{header['rh']['ru_code']:04x}")
    return header


def parse_name_field(data: bytes, offset: int) -> dict:
    """Decode a length-coded SNA name or address field.

    The name-type field is exposed as ``name_type`` rather than ``type`` so that
    these fields can be merged into message dictionaries without shadowing a
    message's own ``type``.
    """
    if offset >= len(data):
        return {"error": "Name field beyond end of data"}
    length = data[offset]
    value = data[offset + 1:offset + 1 + length]
    name_type = data[offset + 1] if value else None
    return {
        "offset": offset,
        "name_type": name_type,
        "type_name": NAME_TYPES.get(name_type, f"name-{name_type:02x}" if name_type is not None else "empty"),
        "length": length,
        "text": _ebcdic(value[1:] if length else b""),
        "raw": value.hex(),
    }


def parse_enterprise_extender(data: bytes) -> dict:
    """Locate the Enterprise Extender header and decode the SNA header inside it.

    The CEE signature is searched within a small window rather than assuming a
    fixed header length, so both EE and EE2 style headers are handled.
    """
    window = data[:CEE_SEARCH_WINDOW]
    position = window.find(CEE_SIGNATURE)
    if position < 0:
        return {"present": False, "sna": parse_sna(data)}
    sna_offset = position + len(CEE_SIGNATURE) + 5
    result = {
        "present": True,
        "cee_offset": position,
        "version_reserved": f"{data[position + 3]:02x}",
        "header_raw": data[position:sna_offset].hex(),
        "sna": parse_sna(data, sna_offset),
    }
    lu_offset = sna_offset + TH_SIZE + (RH_SIZE if result["sna"].get("rh_present") else 0)
    if lu_offset < len(data):
        result["name"] = parse_name_field(data, lu_offset)
    return result


def looks_like_sna(data: bytes) -> bool:
    """Heuristic used by protocol classification.

    The transport header requires a plausible FID plus a control byte whose
    reserved bits (4-5) are zero, which is what keeps ordinary ASCII payloads
    such as HTTP requests from being mistaken for SNA.
    """
    if len(data) < TH_SIZE:
        return False
    fid, control = data[0], data[3]
    if fid < FID_MINIMUM or control > 0xFF:
        return False
    return not (control >> 4) & 0x03 and control & 0x03 <= 3 and (control >> 6) <= 1


def decode_sna(data: bytes) -> dict:
    """Decode a payload that may be Enterprise Extender framed or bare SNA."""
    extender = parse_enterprise_extender(data)
    messages = []
    if extender["present"]:
        messages.append({**{key: value for key, value in extender.items() if key != "sna"},
                         "type": "enterprise_extender"})
    sna = extender["sna"]
    messages.append({**sna, "type": "sna_th"})
    if sna.get("rh"):
        messages.append({**sna["rh"], "type": "sna_rh"})
    if not extender.get("name") and sna.get("rh"):
        name_offset = sna["rh"]["offset"] + RH_SIZE
        if name_offset < len(data):
            candidate = parse_name_field(data, name_offset)
            declared = name_offset + 1 + candidate.get("length", 0)
            if "error" not in candidate and candidate.get("name_type") in NAME_TYPES and declared <= len(data):
                extender["name"] = candidate
    if extender.get("name"):
        messages.append({**extender["name"], "type": "sna_name"})
    consumed = 0
    if extender.get("name") and "length" in extender["name"] and "error" not in extender["name"]:
        consumed = extender["name"]["offset"] + 1 + extender["name"]["length"]
    elif sna.get("rh"):
        consumed = sna["rh"]["offset"] + RH_SIZE
    elif "offset" in sna and "error" not in sna:
        consumed = sna["offset"] + TH_SIZE
    notes = [] if not sna.get("error") else [sna["error"]]
    if consumed and consumed < len(data):
        messages[-1]["payload_length"] = len(data) - consumed
        messages[-1]["payload_preview_hex"] = data[consumed:consumed + 32].hex()
        notes.append("LU payload bytes are preserved and not field-decoded")
    return {"messages": messages, "notes": notes,
            "coverage": ("SNA transport and request header metadata, Enterprise Extender CEE framing, "
                         "length-coded name fields, and named BIND, UNBIND, and ACTLU session requests; "
                         "request/response payloads are not decoded")}


def build_lu_packet(ru_code: int = 0x81, rid: int = 1, fid: int = 0x11, rh: bool = True,
                    name_type: int = 0xE0, name: bytes = b"EFMTTLU1") -> bytes:
    """Build a minimal SNA frame for tests and documentation examples."""
    # Bits 6-7 of the control byte flag that a Request Header follows the TH.
    header = struct.pack("!BBBB", fid, 0x00, 0x00, (0x40 if rh else 0x00) | 0x00)
    if not rh:
        return header
    request = struct.pack("!BHH", 0x00, rid, ru_code) + b"\x00" * 7
    return header + request + bytes([len(name) + 1, name_type]) + name