import base64
import json

from .layouts import decode_layout
from .packets import CaptureError


def apply_layouts(session, layouts, budget=None):
    """Interpret fixed-width records only in explicitly bound, complete TCP streams."""
    session["layout_results"] = []
    if budget is None:
        budget = {"records": 500, "bytes": 1024 * 1024}
    for binding in layouts:
        if binding.protocol != session["protocol"]:
            continue
        definition = json.loads(binding.definition)
        for index, direction in enumerate(session["directions"]):
            if binding.direction != "both" and binding.direction != str(index):
                continue
            result = {"layout_id": binding.id, "name": binding.name, "version": binding.version,
                      "direction": index, "offset": binding.offset, "records": [], "status": "decoded"}
            session["layout_results"].append(result)
            if session["transport"] != "tcp" or not direction["syn_seen"] or direction["gaps"] or direction["overlap_conflict"] or direction["truncated"]:
                result["status"] = "skipped_incomplete_stream"
                continue
            data = base64.b64decode(direction["payload_base64"])
            if binding.offset > len(data):
                result["status"] = "offset_beyond_stream"
                continue
            data = data[binding.offset:]
            try:
                spans, trailing, limited = record_spans(data, definition, binding.byteorder)
            except CaptureError as error:
                result["status"] = "invalid_record"
                result["error"] = str(error)
                result["trailing_bytes"] = len(data)
                continue
            result["trailing_bytes"] = trailing
            result["record_limit_reached"] = limited
            if trailing and result["status"] == "decoded":
                result["status"] = "partial_record"
            for position, start, field_bytes in spans:
                if budget["records"] <= 0 or budget["bytes"] < definition["size"]:
                    result["status"] = "report_budget_reached"
                    result["record_limit_reached"] = True
                    break
                budget["records"] -= 1
                budget["bytes"] -= definition["size"]
                try:
                    decoded = decode_layout(definition, field_bytes, binding.encoding, binding.byteorder)
                except (CaptureError, UnicodeError) as error:
                    result["status"] = "invalid_record"
                    result["error"] = str(error)
                    result["failed_record"] = position
                    break
                message_type = ""
                identify_field = getattr(binding, "identify_field", "") or ""
                if identify_field:
                    message_type = str(decoded.get(identify_field, ""))[:80]
                result["records"].append({
                    "index": position,
                    "stream_offset": binding.offset + start,
                    "message_type": message_type,
                    "fields": decoded,
                })


def record_spans(data, definition, byteorder):
    """Return field slices, leftover bytes, and whether the 100-record cap was hit."""
    framing = definition.get("framing", "fixed")
    envelope = int(definition.get("envelope", 0) or 0)
    if framing == "fixed":
        stride = definition["size"] + envelope
        count, trailing = divmod(len(data), stride)
        limited = count > 100
        spans = []
        for position in range(min(count, 100)):
            start = position * stride
            spans.append((position, start, data[start + envelope:start + envelope + definition["size"]]))
        return spans, trailing, limited
    width = int(definition.get("length_width", 2) or 2)
    if byteorder not in ("big", "little") or width not in (2, 4):
        raise CaptureError("Unsupported length prefix")
    spans = []
    cursor = 0
    minimum = width + envelope + definition["size"]
    while cursor < len(data) and len(spans) < 100:
        if cursor + width > len(data):
            return spans, len(data) - cursor, False
        length = int.from_bytes(data[cursor:cursor + width], byteorder)
        if length < minimum or length > 65536 or cursor + length > len(data):
            raise CaptureError("Record length does not fit the remaining stream")
        field_at = cursor + width + envelope
        spans.append((len(spans), cursor, data[field_at:field_at + definition["size"]]))
        cursor += length
    return spans, len(data) - cursor, cursor < len(data) and len(spans) >= 100
