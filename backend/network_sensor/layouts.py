"""Strict fixed-width layout subsets, never a compiler for vendor source languages."""
import re

from .packets import CaptureError


def _align(offset, alignment):
    return offset + (alignment - offset % alignment) % alignment


def _cobol_display(line):
    match = re.fullmatch(r"\d{2}\s+([\w-]+)\s+PIC(?:TURE)?\s+([X9])(?:\((\d+)\))?(?:\s+DISPLAY)?\.", line, re.I)
    if not match:
        return None
    name, kind, width = match.groups()
    return name, int(width or 1), "text" if kind.upper() == "X" else "decimal_text"


def _cobol_ibm(line):
    match = re.fullmatch(r"\d{2}\s+([\w-]+)\s+PIC(?:TURE)?\s+(S?)9(?:\((\d+)\))?\s+COMP(?:-5)?\.", line, re.I)
    if match:
        name, signed, width = match.groups()
        digits = int(width or 1)
        if digits <= 4:
            size = 2
        elif digits <= 9:
            size = 4
        elif digits <= 18:
            size = 8
        else:
            return None
        return name, size, "int" if signed else "uint"
    match = re.fullmatch(r"\d{2}\s+([\w-]+)\s+PIC(?:TURE)?\s+(S?)9(?:\((\d+)\))?\s+COMP-3\.", line, re.I)
    if match:
        name, _signed, width = match.groups()
        digits = int(width or 1)
        if not 1 <= digits <= 18:
            return None
        return name, (digits + 2) // 2, "packed_decimal"
    return _cobol_display(line)


def _c_field(line):
    if line in ("{", "};") or re.fullmatch(r"(?:typedef\s+)?struct(?:\s+\w+)?\s*\{", line):
        return "skip", 0, None, 1
    match = re.fullmatch(r"char\s+(\w+);", line)
    if match:
        return match[1], 1, "text", 1
    match = re.fullmatch(r"char\s+(\w+)\[(\d+)\];", line)
    if match:
        name, width = match.groups()
        return name, int(width), "text", 1
    match = re.fullmatch(r"(u?int(?:8|16|32|64)_t)\s+(\w+);", line)
    if match:
        type_name, name = match.groups()
        size = int(re.search(r"\d+", type_name)[0]) // 8
        return name, size, "uint" if type_name.startswith("u") else "int", size
    return None


def import_layout(language, text):
    if len(text) > 65536:
        raise CaptureError("Layout is limited to 64 KB")
    if language not in ("cobol", "cobol-ibm", "c", "c-msvc", "vb"):
        raise CaptureError("Choose cobol, cobol-ibm, c, c-msvc, or vb")
    fields, offset, alignment = [], 0, 1
    for original in text.splitlines():
        line = original.strip()
        if not line or line.startswith(("*", "//", "'")):
            continue
        name = kind = None
        size = 0
        field_alignment = 1
        if language in ("cobol", "cobol-ibm"):
            if re.fullmatch(r"01\s+[\w-]+\.?", line, re.I):
                continue
            parsed = _cobol_ibm(line) if language == "cobol-ibm" else _cobol_display(line)
            if parsed:
                name, size, kind = parsed
        elif language in ("c", "c-msvc"):
            parsed = _c_field(line)
            if parsed == "skip" or (isinstance(parsed, tuple) and parsed[0] == "skip"):
                continue
            if parsed:
                name, size, kind, field_alignment = parsed
                if language == "c":
                    field_alignment = 1
        elif language == "vb":
            if re.fullmatch(r"(?:Public\s+|Private\s+)?Type\s+\w+|End\s+Type", line, re.I):
                continue
            match = re.fullmatch(r"(\w+)\s+As\s+String\s*\*\s*(\d+)", line, re.I)
            if match:
                name, width = match.groups()
                size, kind = int(width), "text"
        if language == "c-msvc" and name:
            offset = _align(offset, field_alignment)
            alignment = max(alignment, field_alignment)
        if not name or not 1 <= size <= 8192 or offset + size > 65536:
            raise CaptureError(f"Unsupported or oversized layout declaration: {line[:120]}")
        if name in {field["name"] for field in fields}:
            raise CaptureError("Duplicate field name")
        fields.append({"name": name, "offset": offset, "size": size, "kind": kind})
        offset += size
    if not fields:
        raise CaptureError("Layout contains no supported fields")
    if language == "c-msvc":
        offset = _align(offset, alignment)
    assumptions = {
        "cobol": "Sequential display bytes without compiler padding.",
        "cobol-ibm": "IBM Enterprise COBOL COMP sizes without SYNC slack, and COMP-3 packed decimal.",
        "c": "Sequential bytes without compiler padding. Integers require an explicit byte order.",
        "c-msvc": "MSVC-style alignment of 1, 2, 4, or 8, including trailing padding.",
        "vb": "Sequential single-byte strings without compiler padding.",
    }
    return {"language": language, "size": offset, "fields": fields, "assumptions": assumptions[language]}


def decode_layout(layout, data, encoding="ascii", byteorder="big"):
    if byteorder not in ("big", "little") or encoding not in ("ascii", "cp037", "latin-1"):
        raise CaptureError("Unsupported byte order or encoding")
    if len(data) < layout["size"]:
        raise CaptureError("Message is shorter than the imported layout")
    output = {}
    for field in layout["fields"]:
        raw = data[field["offset"]:field["offset"] + field["size"]]
        kind = field["kind"]
        if kind in ("uint", "int"):
            output[field["name"]] = int.from_bytes(raw, byteorder, signed=kind == "int")
        elif kind == "packed_decimal":
            nibbles = [nibble for byte in raw for nibble in (byte >> 4, byte & 0x0F)]
            sign, digits = nibbles[-1], nibbles[:-1]
            if sign not in (0x0C, 0x0D, 0x0F) or any(digit > 9 for digit in digits):
                raise CaptureError(f"Invalid packed decimal in {field['name']}")
            output[field["name"]] = ("-" if sign == 0x0D else "") + "".join(str(digit) for digit in digits)
        else:
            value = raw.decode(encoding, errors="strict").rstrip(" \x00")
            if kind == "decimal_text" and not value.isdecimal():
                raise CaptureError(f"Nondecimal data in {field['name']}")
            output[field["name"]] = value
    return output
