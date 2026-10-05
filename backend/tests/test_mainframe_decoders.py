"""TN3270E, 3270 order set and SNA/Enterprise Extender decoding.

The tests assert decoder behaviour on hand-built data streams rather than on
recorded captures, so every expectation is checkable against the published
format definitions in the module docstrings.
"""
import pytest

from network_sensor import protocols
from network_sensor import sna
from network_sensor import tn3270e


def sba(address: int) -> bytes:
    """Encode a 12-bit Set Buffer Address operand."""
    return bytes([0x11, (address >> 6) & 0x3F, address & 0x3F])


def ebcdic(text: str) -> bytes:
    return text.encode("cp037")


def tn3270e_stream(*payloads, sequence_start: int = 1, negotiate: bool = True) -> bytes:
    prefix = b""
    if negotiate:
        prefix = bytes([255, 253, 40, 255, 251, 40])
        prefix += bytes([255, 250, 24, 0, 0, 255, 240]) + b"IBM-3278-2-E"
        prefix += bytes([255, 250, 24, 0, 1, 255, 240])
        prefix += bytes([255, 250, 40, 3, 1, 255, 240])
    frame = b""
    for index, payload in enumerate(payloads):
        frame += len(payload).to_bytes(2, "big") + bytes([0x00, 0x00])
        frame += (sequence_start + index).to_bytes(2, "big") + payload
    return prefix + frame


# -- addressing ---------------------------------------------------------------

@pytest.mark.parametrize("address", [0, 1, 63, 64, 400, 1919])
def test_twelve_bit_addresses(address):
    # _address reads the operand only; the SBA opcode byte is not part of it.
    assert tn3270e._address(sba(address)[1:], 0) == (address, 2, True)


def test_fourteen_bit_address():
    # A first byte with bit 7 clear but bit 6 set selects the 14-bit form.
    assert tn3270e._address(bytes([0x41, 0x00]), 0) == (0x4100, 2, True)


def test_three_byte_address():
    assert tn3270e._address(bytes([0x80, 0x10, 0x00]), 0) == (0x10, 3, True)


def test_address_needs_two_bytes():
    with pytest.raises(tn3270e.DecodeLimit):
        tn3270e._address(b"\x11", 0)


# -- negotiation --------------------------------------------------------------

def test_negotiation_events_are_typed():
    events, _ = tn3270e.parse_negotiation(bytes([255, 253, 40, 255, 251, 40]))
    assert [(event["command"], event["option_name"]) for event in events] == [
        ("DO", "TN3270E"), ("WILL", "TN3270E")]


def test_subnegotiation_is_captured():
    events, _ = tn3270e.parse_negotiation(bytes([255, 250, 40, 3, 1, 255, 240]))
    assert events[0]["command"] == "SB" and events[0]["data"] == "0301"


def test_function_negotiation_names():
    assert tn3270e.function_negotiation(bytes([0, 0, 1, 1, 2, 2]))[0]["name"] == "TN3270E"
    assert tn3270e.function_negotiation(bytes([3, 1]))[0]["name"] == "TN3270E-R"


def test_unknown_function_is_not_invented():
    assert "unassigned" not in tn3270e.function_negotiation(bytes([200, 0]))[0]["name"]
    assert tn3270e.function_negotiation(bytes([200, 0]))[0]["function"] == 200


# -- record framing -----------------------------------------------------------

def test_record_header_fields():
    payload = bytes([0xF1]) + sba(0) + ebcdic("HI")
    result = tn3270e.decode_tn3270e(tn3270e_stream(payload))
    header = result["records"][0]["header"]
    assert header["length"] == len(payload)
    assert header["type_name"] == "TN3270E-data"
    assert header["sequence"] == 1
    assert header["response"] is False and header["request"] is False


def test_sequence_numbers_increase():
    payloads = [bytes([0xF1]) + ebcdic("ONE"), bytes([0xF1]) + ebcdic("TWO")]
    result = tn3270e.decode_tn3270e(tn3270e_stream(*payloads))
    assert [record["header"]["sequence"] for record in result["records"]] == [1, 2]


def test_interleaved_negotiation_does_not_hide_records():
    payload = bytes([0xF1]) + ebcdic("LOGON")
    result = tn3270e.decode_tn3270e(tn3270e_stream(payload))
    assert len(result["records"]) == 1
    assert result["tn3270e"] is True


def test_eor_fallback_without_negotiation():
    # No TN3270E option is offered, so framing falls back to IAC EOR.
    stream = bytes([255, 239]) + bytes([0xF1]) + ebcdic("PLAIN") + bytes([255, 239])
    result = tn3270e.decode_tn3270e(stream)
    assert result["tn3270e"] is False
    assert result["records"][0]["source"] == "eor"
    assert result["screens"][0]["rows"][0].startswith("PLAIN")


def test_response_flag_is_reported():
    payload = bytes([0xF1]) + ebcdic("OK")
    frame = len(payload).to_bytes(2, "big") + bytes([0x02, 0x01]) + (9).to_bytes(2, "big") + payload
    stream = bytes([255, 253, 40, 255, 251, 40]) + frame
    header = tn3270e.decode_tn3270e(stream)["records"][0]["header"]
    assert header["response"] is True and header["type_name"] == "response"


def test_random_data_is_not_mistaken_for_records():
    result = tn3270e.decode_tn3270e(bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
    assert result["records"] == []
    assert result["notes"]


# -- write control character --------------------------------------------------

@pytest.mark.parametrize("code,action", [(0xF1, "restore"), (0xF5, "erase-and-restore"),
                                         (0x7E, "erase"), (0xF3, "no-operation")])
def test_write_control_character(code, action):
    remainder, control = tn3270e.split_wcc(bytes([code]) + sba(0) + ebcdic("TEXT"))
    assert control["action"] == action and remainder == sba(0) + ebcdic("TEXT")


def test_erase_control_clears_the_screen():
    first = bytes([0xF1]) + sba(0) + ebcdic("OLD")
    second = bytes([0xF5]) + sba(0) + ebcdic("NEW")
    result = tn3270e.decode_tn3270e(tn3270e_stream(first, second))
    rows = result["screens"][0]["rows"]
    assert rows[0].startswith("NEW")
    assert "OLD" not in "".join(rows)


def test_wcc_is_not_rendered_as_text():
    result = tn3270e.decode_tn3270e(tn3270e_stream(bytes([0xF1]) + ebcdic("A")))
    assert not result["screens"][0]["rows"][0].startswith("1")


# -- orders -------------------------------------------------------------------

def mnemonics(payload):
    return [order["mnemonic"] for order in tn3270e.Screen().render(payload)]


def test_sba_positions_data():
    screen = tn3270e.Screen()
    screen.render(sba(10) + ebcdic("AT10"))
    assert screen.snapshot()["rows"][0].startswith("          AT10")


def test_start_field_is_recorded():
    screen = tn3270e.Screen()
    screen.render(sba(0) + ebcdic("LBL") + bytes([0x1D, 0x30]) + ebcdic("VAL"))
    fields = screen.snapshot()["fields"]
    assert len(fields) == 1
    assert fields[0]["start"] == 3 and fields[0]["protected"] and fields[0]["numeric"]


def test_extended_field_colour():
    screen = tn3270e.Screen()
    # 0x0D = red intensified, 0x02 = blue, in the low colour/intensity bits.
    screen.render(sba(0) + bytes([0x29, 0x02, 0xC6, 0x0D, 0x00, 0xC7, 0x02, 0x00]))
    attribute = screen.snapshot()["fields"][0]
    colours = {item["name"]: item for item in attribute["display_attributes"]}
    assert colours["foreground-colour"]["colour"] == "red"
    assert colours["foreground-colour"]["intensified"] is True
    assert colours["background-colour"]["colour"] == "blue"
    assert colours["background-colour"]["intensified"] is False


def test_unassigned_attribute_is_reported_as_such():
    screen = tn3270e.Screen()
    screen.render(sba(0) + bytes([0x29, 0x01, 0xDF, 0x00, 0x01]))
    attribute = screen.snapshot()["fields"][0]["display_attributes"][0]
    assert attribute["name"] == "unassigned-attribute"
    assert attribute["code"] == "df"
    assert attribute["value"] == "0001"


def test_erase_unprotected_areas_keeps_protected_text():
    screen = tn3270e.Screen()
    screen.render(sba(0) + ebcdic("FREE") + bytes([0x1D, 0x30]) + ebcdic("SAFE"))
    screen.render(bytes([0x12]))
    row = screen.snapshot()["rows"][0]
    assert "FREE" not in row and "SAFE" in row


def test_repeat_to_address():
    screen = tn3270e.Screen()
    screen.render(bytes([0x3C]) + sba(10)[1:] + ebcdic("*"))
    assert screen.snapshot()["rows"][0][:11] == "*" * 11


def test_insert_cursor():
    screen = tn3270e.Screen()
    screen.render(sba(5) + bytes([0x13]))
    assert screen.snapshot()["cursor"] == [1, 6]


def test_set_attribute_highlighting():
    screen = tn3270e.Screen()
    screen.render(bytes([0x28, 0xC8, 0x04]))
    assert screen.snapshot()["fields"] == []  # SA is screen-level, not field-level


def test_hidden_highlighting_marks_field_hidden():
    screen = tn3270e.Screen()
    screen.render(sba(0) + bytes([0x29, 0x02, 0xC8, 0x04, 0x00]) + ebcdic("HIDDEN"))
    assert screen.snapshot()["fields"][0]["hidden"] is True


def test_hidden_field_text_is_masked_in_rendered_rows():
    screen = tn3270e.Screen()
    screen.render(sba(0) + ebcdic("PW") + bytes([0x1D, 0x0C]) + ebcdic("SECRET"))
    snapshot = screen.snapshot()
    rendered = "".join(snapshot["rows"])
    assert "SECRET" not in rendered
    assert "*****" in rendered
    assert snapshot["fields"][0]["hidden"] is True
    # The unmasked characters are still recoverable from the evidence itself.
    assert screen.buffer[2:8] == list("SECRET")


def test_hidden_field_is_reported_by_position():
    screen = tn3270e.Screen()
    screen.render(sba(0) + bytes([0x1D, 0x0C]) + ebcdic("AB"))
    assert screen.snapshot()["hidden_positions"] == [0, 1]


def test_non_display_field_is_hidden():
    screen = tn3270e.Screen()
    screen.render(sba(0) + bytes([0x1D, 0x0C]) + ebcdic("PWD"))
    assert screen.snapshot()["fields"][0]["hidden"] is True


def test_graphics_escape_and_program_tab():
    assert "GE" in mnemonics(bytes([0x08, 0x5F, 0xF1]))
    assert "PT" in mnemonics(bytes([0x05, 0x0C]))


def test_two_byte_do_order():
    assert "MF" in [order["mnemonic"] for order in
                    tn3270e.Screen().render(bytes([0x6C, 0x73, 0x01, 0xC6, 0xF1, 0x00]))]


def test_unassigned_do_order_marks_partial():
    screen = tn3270e.Screen()
    result = screen.render(bytes([0x6C, 0x7F]))
    assert result[-1]["mnemonic"] == "unassigned-do" and screen.partial is True


def test_truncated_order_marks_partial():
    screen = tn3270e.Screen()
    screen.render(bytes([0x08, 0x5F]))
    assert screen.partial is True


def test_out_of_range_address_marks_partial():
    screen = tn3270e.Screen()
    screen.render(bytes([0x11, 0x41, 0x40]))
    assert screen.partial is True


def test_all_orders_in_one_stream():
    stream = (sba(0) + ebcdic("A") + bytes([0x1D, 0x30]) + ebcdic("B") + bytes([0x12])
              + bytes([0x3C]) + sba(200)[1:] + ebcdic("*") + bytes([0x08, 0x5F, 0xF1])
              + bytes([0x05, 0x0C]) + bytes([0x28, 0xC8, 0x02])
              + bytes([0x6C, 0x73, 0x01, 0xC6, 0xF1, 0x00]) + bytes([0x13]))
    screen = tn3270e.Screen()
    result = screen.render(stream)
    found = {order["mnemonic"] for order in result}
    assert {"SBA", "SF", "EUA", "RA", "GE", "PT", "SA", "MF", "IC"} <= found
    assert screen.partial is False


# -- geometry -----------------------------------------------------------------

@pytest.mark.parametrize("model,expected", [("IBM-3278-2-E", (24, 80)), ("", (24, 80)),
                                           ("IBM-3174-2 80x24", (80, 24))])
def test_geometry(model, expected):
    assert tn3270e.geometry_for(model) == expected


def test_invalid_geometry_is_rejected():
    with pytest.raises(ValueError):
        tn3270e.Screen(0, 80)


# -- protocol integration -----------------------------------------------------

def test_classification_by_negotiation():
    stream = bytes([255, 253, 40, 255, 251, 40, 255, 250, 24, 0, 0, 255, 240]) + b"IBM-3278-2-E"
    assert protocols.classify(stream, (), {}) == ("tn3270", "negotiation")


def test_tn3270_decode_returns_screen():
    payload = bytes([0xF1]) + sba(0) + ebcdic("PANEL")
    result = protocols.decode("tn3270", tn3270e_stream(payload))
    assert result["screens"][0]["rows"][0].startswith("PANEL")
    assert "TN3270E" in result["coverage"]


# -- SNA ----------------------------------------------------------------------

def test_transport_header_only():
    header = sna.parse_sna(sna.build_lu_packet(rh=False))
    assert header["fid_name"] == "FID2-SNC"
    assert header["rh_present"] is False
    assert header["th_type"] in ("GHI", "RHI", "HI", "LI")


def test_request_header_fields():
    header = sna.parse_sna(sna.build_lu_packet(ru_code=0x81, rid=1))
    assert header["rh_present"] is True
    assert header["rh"]["rid"] == 1
    assert header["rh"]["ru_name"] == "EXCS"


def test_bind_names_the_session_and_keeps_the_payload_opaque():
    result = sna.decode_sna(sna.build_lu_packet(ru_code=0x31) + b"\x01\x02")
    assert result["messages"][1]["ru_name"] == "BIND"
    assert result["messages"][-1]["payload_preview_hex"] == "0102"
    assert "not field-decoded" in result["notes"][-1]


def test_unknown_ru_is_not_invented():
    header = sna.parse_sna(sna.build_lu_packet(ru_code=0x7ABC))
    assert header["rh"]["ru_name"] == "ru-7abc"


def test_truncated_transport_header():
    assert "error" in sna.parse_sna(b"\x11\x00")


def test_request_header_flagged_but_missing():
    assert "error" in sna.parse_sna(bytes([0x11, 0x00, 0x00, 0x40, 0x00]))


def test_enterprise_extender_framing():
    frame = b"\xc3\xc5\xc5\x33\x00\x00\x00\x01" + sna.build_lu_packet(name=ebcdic("EFMTTLU1"))
    result = sna.parse_enterprise_extender(frame)
    assert result["present"] is True
    assert result["sna"]["rh"]["ru_name"] == "EXCS"
    assert result["name"]["text"] == "EFMTTLU1"
    assert result["name"]["type_name"] == "CLASSDR"


def test_bare_sna_has_no_extender():
    assert sna.parse_enterprise_extender(sna.build_lu_packet())["present"] is False


def test_sna_message_types_are_not_shadowed():
    frame = b"\xc3\xc5\xc5\x33\x00\x00\x00\x01" + sna.build_lu_packet(name=ebcdic("LU1"))
    types = [message["type"] for message in sna.decode_sna(frame)["messages"]]
    assert types == ["enterprise_extender", "sna_th", "sna_rh", "sna_name"]


@pytest.mark.parametrize("payload,expected", [
    (b"GET / HTTP/1.1\r\n", False),
    (sna.build_lu_packet(), True),
    (b"\x11\x00\x00\x40" + b"\x00" * 12, True),
    (b"short", False),
])
def test_sna_classification_heuristic(payload, expected):
    assert sna.looks_like_sna(payload) is expected


def test_sna_classification_in_protocols():
    frame = b"\xc3\xc5\xc5\x33\x00\x00\x00\x01" + sna.build_lu_packet(name=ebcdic("LU1"))
    assert protocols.classify(frame, (), {}) == ("enterprise_extender", "cee_signature")
    assert protocols.classify(sna.build_lu_packet(), (), {}) == ("sna", "transport_header")


def test_http_is_not_classified_as_sna():
    assert protocols.classify(b"POST /login HTTP/1.1\r\n", (), {})[0] not in ("sna", "enterprise_extender")


def test_capability_statements_are_specific():
    assert "TN3270E" in protocols.CAPABILITIES["tn3270"]
    assert "not decoded" in protocols.CAPABILITIES["sna"]