import base64
import hashlib
import io
import json
import struct
import threading

import pytest
from pydantic import ValidationError

from app.models import User
from network_sensor.config import SensorConfig
from network_sensor.health import HealthMonitor, SnmpNotifier, trap_packet
from network_sensor.layouts import decode_layout, import_layout
from network_sensor.packets import CaptureError, Packet, PcapWriter, decode_packet, pcap_records
from network_sensor.pipeline import Pipeline, analyze_pcap
from network_sensor.protocols import decode, vt100_screen
from network_sensor.sessions import Direction, SessionTable
from test_api import make_client


def ipv4_fragment(ident, offset_units, more, payload):
    flags = (0x2000 if more else 0) | (offset_units & 0x1FFF)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags, 64, 17, 0, b"\x0a\0\0\1", b"\x0a\0\0\2")
    return b"\0" * 12 + b"\x08\0" + header + payload


def tcp_frame(sequence, payload=b"", flags=0x18, source_port=41000, destination_port=80):
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, sequence, 0, (5 << 12) | flags, 4096, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, b"\x0a\0\0\1", b"\x0a\0\0\2")
    return b"\0" * 12 + b"\x08\0" + ip + tcp


def sample_capture():
    request = b"GET /review HTTP/1.1\r\nHost: example.test\r\nAuthorization: secret\r\n\r\n"
    output = io.BytesIO()
    writer = PcapWriter(output)
    frames = [tcp_frame(100, flags=2), tcp_frame(121, request[20:]), tcp_frame(101, request[:20]), tcp_frame(101, request[:20])]
    for index, frame in enumerate(frames):
        writer.write(1700000000 + index / 10, frame)
    return output.getvalue()


def test_pcap_and_tcp_reconstruction_with_retransmissions():
    report = analyze_pcap(io.BytesIO(sample_capture()))
    assert report["metrics"]["processed"] == 4
    assert report["metrics"]["dropped"] == 0
    session = report["sessions"][0]
    assert session["protocol"] == "http"
    direction = session["directions"][0]
    assert direction["syn_seen"] and not direction["gaps"]
    message = direction["decoded"]["messages"][0]
    assert message["start_line"] == "GET /review HTTP/1.1"
    assert message["headers"]["authorization"] == "[redacted]"
    assert base64.b64decode(direction["payload_base64"]).count(b"GET ") == 1


def test_live_queue_overflow_counts_loss_and_shutdown_drains(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = decode_packet
    def slow_decode(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr("network_sensor.pipeline.decode_packet", slow_decode)
    pipeline = Pipeline({"queue_capacity": 1})
    record = (1, tcp_frame(100, b"payload"), len(tcp_frame(100, b"payload")), 1)
    pipeline.enqueue(record)
    assert entered.wait(5)
    pipeline.enqueue(record)
    pipeline.enqueue(record)
    release.set()
    pipeline.close()
    report = pipeline.report()
    assert report["metrics"]["received"] == 3
    assert report["metrics"]["processed"] == 2
    assert report["metrics"]["dropped"] == 1
    assert report["metrics"]["queue_depth"] == 0


def test_gap_overlap_wrap_and_limits():
    direction = Direction()
    def packet(sequence, data=b"", flags=0):
        return Packet(0, "a", "b", 1, 2, "tcp", data, sequence, flags)
    direction.add(packet(0xFFFFFFFE, flags=2), 1024)
    direction.add(packet(0xFFFFFFFF, b"ab"), 1024)
    direction.add(packet(1, b"cd"), 1024)
    assert direction.reconstruct()[0] == b"abcd"
    direction.add(packet(0xFFFFFFFF, b"ax"), 1024)
    assert direction.reconstruct()[2]
    gap = Direction()
    gap.add(packet(100, flags=2), 1024)
    gap.add(packet(101, b"ab"), 1024)
    gap.add(packet(105, b"ef"), 1024)
    assert gap.reconstruct()[:2] == (b"ab", [{"from": 2, "to": 4}])
    clipped = Direction()
    clipped.add(packet(10, b"abcdefgh"), 4)
    assert clipped.clipped and clipped.reconstruct()[0] == b"abcd"
    table = SessionTable(max_sessions=1)
    table.consume(packet(10, b"data"))
    table.consume(Packet(0, "c", "d", 3, 4, "tcp", b"other"))
    assert table.capacity_rotations == 1
    assert len(table.sessions) == 1
    assert len(table.report()) == 2
    connections = SessionTable()
    connections.consume(packet(100, flags=2))
    connections.consume(packet(101, b"first"))
    connections.consume(packet(106, flags=1))
    connections.consume(packet(200, flags=2))
    connections.consume(packet(201, b"second"))
    assert len(connections.report()) == 2
    assert [base64.b64decode(item["directions"][0]["payload_base64"]) for item in connections.report()] == [b"first", b"second"]


def test_capture_validation_and_link_layers():
    with pytest.raises(CaptureError):
        list(pcap_records(io.BytesIO(b"bad")))
    with pytest.raises(CaptureError, match="Incomplete"):
        analyze_pcap(io.BytesIO(sample_capture()[:-1]))
    with pytest.raises(CaptureError, match="exceeds"):
        analyze_pcap(io.BytesIO(sample_capture()), max_packets=1)
    frame = tcp_frame(10, b"hello")
    vlan = frame[:12] + b"\x81\0\0\1\x08\0" + frame[14:]
    assert decode_packet(1, vlan, len(vlan)).payload == b"hello"
    ip = frame[14:]
    assert decode_packet(1, ip, len(ip), 101).source == "10.0.0.1"
    cooked = b"\0" * 14 + b"\x08\0" + ip
    assert decode_packet(1, cooked, len(cooked), 113).payload == b"hello"
    ipv6 = bytes([0x60, 0, 0, 0]) + struct.pack("!HBB", 12, 17, 64) + b"\0" * 15 + b"\1" + b"\0" * 15 + b"\2"
    udp = struct.pack("!HHHH", 123, 456, 12, 0) + b"test"
    packet = decode_packet(1, ipv6 + udp, 52, 101)
    assert packet.transport == "udp" and packet.payload == b"test"
    fragmented = bytearray(frame)
    fragmented[20:22] = b"\x20\0"
    assert decode_packet(1, bytes(fragmented), len(fragmented)) is None
    header = struct.pack("!HHHH", 9, 9, 16, 0)
    body = b"hello!!!"
    first = ipv4_fragment(1, 0, True, header)
    second = ipv4_fragment(1, 1, False, body)
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, first)
    writer.write(2, second)
    assembled = analyze_pcap(io.BytesIO(output.getvalue()))
    assert assembled["metrics"]["unsupported"] == 0
    datagrams = assembled["sessions"][0]["datagrams"]
    assert base64.b64decode(datagrams[0]["payload_base64"]) == body


def test_fix_telnet_3270_and_encrypted_metadata():
    body = b"35=D\x0149=CLIENT\x0156=SERVER\x01"
    raw = b"8=FIX.4.4\x019=" + str(len(body)).encode() + b"\x01" + body
    raw += b"10=" + f"{sum(raw) % 256:03d}".encode() + b"\x01"
    assert decode("fix", raw)["messages"][0]["checksum_valid"]
    assert decode("fix", raw)["messages"][0]["named"][2] == {"tag": "35", "name": "MsgType", "value": "D"}
    chunked = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    )
    http = decode("http", chunked)
    # The decoder emits a typed event stream: header records interleaved with
    # body records that carry a hash instead of the payload, so filter to the
    # headers rather than assuming every entry is a message.
    starts = [item["start_line"] for item in http["messages"]
              if item["type"] == "http_headers"]
    assert starts == ["HTTP/1.1 200 OK", "HTTP/1.1 204 No Content"]
    # The chunked body is decoded and hashed rather than retained.
    bodies = [item for item in http["messages"] if item["type"] == "http_body"]
    assert [item["length"] for item in bodies] == [5]
    assert bodies[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert http["notes"] == []
    broken = raw[:-4] + b"999\x01"
    assert not decode("fix", broken)["messages"][0]["checksum_valid"]
    terminal = decode("telnet", b"\xff\xfb\x01\x1b[2J\x1b[2;3HHello\r\nWorld")
    assert terminal["screens"][0]["rows"][1] == "  Hello"
    assert terminal["screens"][0]["rows"][2] == "World"
    record = b"\xf5\0\x11\0\0" + "HELLO".encode("cp037") + b"\xff\xef"
    assert decode("tn3270", record)["screens"][0]["rows"][0] == "HELLO"
    tls = decode("https", b"\x17\x03\x03\0\x04abcd")
    assert tls["messages"][0]["length"] == 4 and "encrypted" in tls["notes"][0]
    assert decode("tn5250", b"opaque")["screens"] == []
    plain = "HELLO".encode("cp037")
    screen = decode("tn5250", bytes([0x04, 0x11, 0x00, 0x00, 0x11, 1, 1]) + plain)
    assert screen["screens"][0]["rows"][0] == "HELLO"
    repeated = decode("tn5250", bytes([0x04, 0x11, 0x00, 0x00, 0x11, 1, 1, 0x02, 1, 6, 0xC1]))
    assert repeated["screens"][0]["rows"][0] == "AAAAA"
    erased = vt100_screen(b"ABCDE\x1b[1;2H\x1b[1K")
    assert erased["rows"][0] == "  CDE"


def test_monitor_configuration_and_layout_subsets():
    selected = analyze_pcap(io.BytesIO(sample_capture()), SensorConfig(protocols=["fix"]).model_dump())
    assert selected["sessions"] == []
    with pytest.raises(ValidationError):
        SensorConfig(port_map={"70000": "http"})
    with pytest.raises(ValidationError):
        SensorConfig(protocols=["invented"])
    cobol = import_layout("cobol", "01 RECORD.\n05 NAME PIC X(4).\n05 AMOUNT PIC 9(3).")
    assert decode_layout(cobol, b"JOE 123") == {"NAME": "JOE", "AMOUNT": "123"}
    c = import_layout("c", "struct message {\nchar name[4];\nuint16_t count;\n};")
    assert decode_layout(c, b"TEST\x02\0", byteorder="little")["count"] == 2
    vb = import_layout("vb", "Type Message\nName As String * 4\nEnd Type")
    assert decode_layout(vb, b"JOE ")["Name"] == "JOE"
    with pytest.raises(CaptureError):
        import_layout("cobol", "05 VALUE PIC 9(4) COMP-3.")
    ibm = import_layout("cobol-ibm", "05 AMOUNT PIC 9(3) COMP-3.\n05 COUNT PIC S9(4) COMP.")
    assert decode_layout(ibm, bytes([0x12, 0x3C, 0x00, 0x02])) == {"AMOUNT": "123", "COUNT": 2}
    aligned = import_layout("c-msvc", "struct row {\nchar flag;\nuint16_t count;\n};")
    assert aligned["fields"][1]["offset"] == 2 and aligned["size"] == 4
    assert decode_layout(aligned, b"\x01\x00\x02\x00", byteorder="little")["count"] == 2
    with pytest.raises(CaptureError):
        decode_layout(cobol, b"short")


def test_health_transitions_and_snmp_notifications(monkeypatch):
    monitor = HealthMonitor(idle_seconds=10, empty_seconds=5, min_disk_bytes=100, repeat_seconds=50)
    start = monitor.started
    assert monitor.check(0, 10, 1000, start) == []
    events = monitor.check(0, 10, 1000, start + 11)
    assert {event["condition"] for event in events} == {"not_capturing", "empty_queue"}
    assert monitor.check(0, 10, 1000, start + 12) == []
    monitor.packet_seen(start + 12)
    events = monitor.check(9, 10, 10, start + 12)
    assert {event["condition"] for event in events if event["status"] == "active"} == {"backlog", "low_disk"}
    assert {event["condition"] for event in events if event["status"] == "recovered"} == {"not_capturing", "empty_queue"}
    sent = []
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def sendto(self, packet, address): sent.append((packet, address))
    monkeypatch.setattr("network_sensor.health.socket.socket", lambda *args: FakeSocket())
    notifier = SnmpNotifier("127.0.0.1", 1162, "test-community", "1.3.6.1.4.1.32473.1")
    notifier({"condition": "low_disk", "status": "active"})
    packet, address = sent[0]
    assert address == ("127.0.0.1", 1162)
    assert packet[0] == 0x30 and b"test-community" in packet and b"low_disk: active" in packet
    assert b"\xa7" in packet
    # Mandatory snmpTrapOID.0 and sysUpTime.0 names in their BER OID encodings.
    assert b"\x06\x0a\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00" in packet
    assert b"\x06\x08\x2b\x06\x01\x02\x01\x01\x03\x00" in packet


def test_network_api_permissions_recording_and_layout(tmp_path):
    with make_client(tmp_path) as client:
        raw = sample_capture()
        response = client.post("/api/network/pcap", files={"file": ("example.pcap", raw)})
        assert response.status_code == 201
        capture_id = response.json()["id"]
        assert response.json()["imported_by"] == "investigator"
        detail = client.get(f"/api/network/captures/{capture_id}").json()
        assert detail["session_details"][0]["protocol"] == "http"
        assert "payload_base64" not in detail["session_details"][0]["directions"][0]
        download = client.get(f"/api/network/captures/{capture_id}/download")
        assert download.content == raw
        assert download.headers["x-capture-sha256"] == response.json()["sha256"]
        assert client.post("/api/network/pcap", files={"file": ("broken", b"not pcap")}).status_code == 422
        assert len(client.get("/api/network/captures").json()) == 1
        layout = client.post("/api/network/layouts/preview", json={"language": "vb", "declaration": "Name As String * 4", "message_base64": base64.b64encode(b"TEST").decode()})
        assert layout.status_code == 200 and layout.json()["decoded"]["Name"] == "TEST"
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").first().role = "viewer"
            db.commit()
        assert client.post("/api/network/pcap", files={"file": ("example", raw)}).status_code == 403
        assert client.get(f"/api/network/captures/{capture_id}").status_code == 200
        assert client.post("/api/network/layouts/preview", json={"language": "vb", "declaration": "Name As String * 4"}).status_code == 403
        client.cookies.clear()
        assert client.get("/api/network/capabilities").status_code == 401
        assert client.get(f"/api/network/captures/{capture_id}/download").status_code == 401


def test_stored_capture_accepts_later_indicators_without_changing_bytes(tmp_path):
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("example.pcap", sample_capture())})
        assert uploaded.status_code == 201, uploaded.text
        capture_id = uploaded.json()["id"]
        digest = uploaded.json()["sha256"]
        assert not any(item["category"] == "c2" for item in uploaded.json()["traffic_analysis"]["findings"])
        assert client.post(f"/api/network/captures/{capture_id}/indicators", json={}).status_code == 422
        assert client.post(f"/api/network/captures/{capture_id}/indicators", json={"c2_ips": ["not-an-address"]}).status_code == 422
        checked = client.post(f"/api/network/captures/{capture_id}/indicators", json={"c2_ips": ["10.0.0.2"]})
        assert checked.status_code == 200, checked.text
        assert checked.json()["sha256"] == digest
        assert any(item["title"] == "Traffic involving a configured C2 address" for item in checked.json()["traffic_analysis"]["findings"])
        assert client.get(f"/api/network/captures/{capture_id}/download").content == sample_capture()
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").first().role = "viewer"
            db.commit()
        assert client.post(f"/api/network/captures/{capture_id}/indicators", json={"c2_ips": ["10.0.0.2"]}).status_code == 403


def test_stored_decoders_midstream_and_ftp_data():
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    frame = (5).to_bytes(3, "big") + bytes([0, 0]) + (1).to_bytes(4, "big") + b"hello"
    http2 = decode("http", preface + frame)
    assert http2["messages"][0]["frame_type"] == "DATA" and http2["messages"][0]["stream"] == 1
    smb = bytearray(64)
    smb[:4] = b"\xfeSMB"
    smb[12:14] = (5).to_bytes(2, "little")
    assert decode("smb", bytes(smb))["messages"][0]["command_name"] == "CREATE"
    query = "SELECT".encode("utf-16le")
    rest = " 1".encode("utf-16le")
    tds = bytes([1, 0]) + (8 + len(query)).to_bytes(2, "big") + b"\x00\x00\x01\x00" + query
    tds += bytes([1, 1]) + (8 + len(rest)).to_bytes(2, "big") + b"\x00\x00\x01\x00" + rest
    assert decode("tds", tds)["messages"][-1]["query"] == "SELECT 1"
    statement = b"SELECT 1 FROM T"
    sqlnet = (8 + len(statement)).to_bytes(2, "big") + b"\x00\x00" + bytes([6, 0, 0, 0]) + statement
    assert decode("sqlnet", sqlnet)["messages"][0]["statement_span"] == "SELECT 1 FROM T"
    drda = (10).to_bytes(2, "big") + bytes([0xD0, 0x01, 0x00, 0x01]) + (0x2414).to_bytes(2, "big") + b"\x00\x00"
    assert decode("drda", drda)["messages"][0]["codepoint_name"] == "SQLSTT"
    body = b"MQSTR-body"
    descriptor = b"MD  " + (1).to_bytes(4, "big") + b"\x00" * 24 + b"MQSTR   " + b"\x00" * (324 - 40) + body
    segment = b"TSH " + (8 + len(descriptor)).to_bytes(4, "big") + descriptor
    assert decode("mq", segment)["messages"][0]["mqstr"] == "MQSTR-body"
    msmq = bytes([0x10, 0xC0, 0x03, 0x00]) + b"LIOR" + (32).to_bytes(4, "little") + b"\xff" * 4
    assert decode("msmq", msmq)["messages"][0]["priority"] == 3
    iso = decode("iso8583", b"0200" + bytes([0x20, 0, 0, 0, 0, 0, 0, 0]) + b"000123", {"3": 6})
    assert iso["messages"][0]["values"]["3"] == "000123"
    assert "values" not in decode("iso8583", b"0200" + bytes([0x20, 0, 0, 0, 0, 0, 0, 0]) + b"000123")["messages"][0]
    swift = decode("swift", b"{1:F01BANK}{4:\r\n:20:REF\r\n-}")
    assert swift["messages"][0]["tags"][0] == {"tag": "20", "value": "REF"}
    encoded = b"35=D\x0134=1\x0149=CLIENT\x0152=20261003-12:00:00\x0156=SERVER\x0196=ABCD\x01"
    raw = b"8=FIX.4.4\x019=" + str(len(encoded)).encode() + b"\x01" + encoded
    raw += b"10=" + f"{sum(raw) % 256:03d}".encode() + b"\x01"
    message = decode("fix", raw)["messages"][0]
    assert message["header_complete"] and message["encoded"][0]["length"] == 4
    from network_sensor.protocols import classify
    assert classify(b"opaque", [9000], {"9000": "oracle_forms"}) == ("oracle_forms", "configured_port")
    assert "opaquely" in decode("oracle_forms", b"opaque")["notes"][0]
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(50, b"RETR report.csv\r\nPORT 10,0,0,2,7,208\r\n", destination_port=21))
    writer.write(2, tcp_frame(10, b"stored-file", destination_port=2000, source_port=41001))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    control = next(item for item in report["sessions"] if item["protocol"] == "ftp")
    data = next(item for item in report["sessions"] if item["protocol"] == "ftp-data")
    assert control["directions"][0]["syn_seen"] is False
    assert data["directions"][0]["length"] + data["directions"][1]["length"] == len(b"stored-file")
    assert "10.0.0.2:2000" in " ".join(note for direction in data["directions"] for note in direction["decoded"]["notes"])
    assert data["transfer"]["command"] == "RETR" and data["transfer"]["name"] == "report.csv"
    assert data["transfer"]["preview"] == "stored-file" and data["transfer"]["encrypted"] is False
    assert data["transfer"]["sha256"] == hashlib.sha256(b"stored-file").hexdigest()
    assert "sensitive" not in data["transfer"]


def test_stored_ftp_command_is_named_without_copying_the_line():
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, b"USER ada\r\nrm -rf /tmp\r\n", destination_port=21))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    finding = next(item for item in report["traffic_analysis"]["findings"] if item["category"] == "command")
    assert finding["title"] == "Suspicious command: destructive delete"
    assert finding["evidence"] == {"label": "destructive delete", "protocol": "ftp"}
    assert "rm -rf" not in json.dumps(finding)


def test_stored_ftp_file_names_a_card_without_copying_it():
    body = b"Pay 4242424242424242 now"
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(50, b"RETR payroll.csv\r\nPORT 10,0,0,2,7,208\r\n", destination_port=21))
    writer.write(2, tcp_frame(10, body, destination_port=2000, source_port=41001))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    data = next(item for item in report["sessions"] if item["protocol"] == "ftp-data")
    finding = next(item for item in report["traffic_analysis"]["findings"] if item["category"] == "file")
    assert data["transfer"]["sha256"] == hashlib.sha256(body).hexdigest()
    assert data["transfer"]["sensitive"] == "card ending 4242"
    assert finding["title"] == "Sensitive file transfer"
    assert finding["evidence"]["label"] == "card ending 4242"
    assert finding["evidence"]["sha256"] == data["transfer"]["sha256"]
    rendered = json.dumps(finding)
    assert "4242424242424242" not in rendered
    assert "Pay 4242" not in rendered


def test_encrypted_ftp_transfer_stays_opaque():
    table = SessionTable()
    reports = [
        {"protocol": "ftp", "endpoints": [["10.0.0.1", 21], ["10.0.0.2", 5000]], "directions": [{"decoded": {"messages": [
            {"type": "ftp_control", "line": "AUTH TLS"},
            {"type": "ftp_control", "line": "RETR secret.csv", "data_endpoint": ["10.0.0.2", 2000]},
        ], "notes": []}}]},
        {"protocol": "unknown", "endpoints": [["10.0.0.2", 2000], ["10.0.0.1", 41001]], "directions": [
            {"length": 4, "payload_base64": base64.b64encode(b"FILE").decode(), "decoded": {"notes": []}},
            {"length": 0, "payload_base64": "", "decoded": {"notes": []}},
        ]},
    ]
    table._attach_ftp_data(reports)
    assert reports[1]["protocol"] == "ftp-data"
    assert reports[1]["transfer"]["encrypted"] is True and "preview" not in reports[1]["transfer"]
    assert "sha256" not in reports[1]["transfer"] and "sensitive" not in reports[1]["transfer"]
    assert "not decoded" in reports[1]["directions"][0]["decoded"]["notes"][0]
    with pytest.raises(ValidationError):
        SensorConfig(iso_field_lengths={"1": 8})


def _ber(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else bytes([0x81, len(value)])
    return bytes([tag]) + length + value


def test_stored_ldap_command_omits_the_simple_credential():
    password = b"s3cret-value"
    bind = _ber(0x60, _ber(0x02, b"\x03") + _ber(0x04, b"uid=ada,dc=example") + _ber(0x80, password))
    message = _ber(0x30, _ber(0x02, b"\x01") + bind)
    equality = _ber(0xA3, _ber(0x04, b"userPassword") + _ber(0x04, password))
    search = _ber(0x63, _ber(0x04, b"dc=example") + _ber(0x0A, b"\x02") + _ber(0x0A, b"\x00")
                  + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + _ber(0x01, b"\x00") + equality + _ber(0x30, b""))
    query = _ber(0x30, _ber(0x02, b"\x02") + search)
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, message + query, destination_port=389))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "ldap")
    decoded = session["directions"][0]["decoded"]
    rendered = json.dumps(decoded)
    assert decoded["messages"][0]["operation"] == "bind"
    assert decoded["messages"][0]["name"] == "uid=ada,dc=example"
    assert decoded["messages"][0]["authentication"] == "simple"
    assert decoded["messages"][1]["operation"] == "search"
    assert decoded["messages"][1]["base"] == "dc=example"
    assert decoded["messages"][1]["scope"] == "subtree"
    assert decoded["messages"][1]["filter_attributes"] == ["userPassword"]
    assert password.decode() not in rendered
    assert decode("ldaps", message)["messages"] == []
    assert "encrypted" in decode("ldaps", message)["notes"][0]


def test_stored_commands_keep_telnet_and_sql_without_a_password_line(tmp_path):
    secret = "secret-line"
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, b"\xff\xfd\x01ls -l\r\nPassword: \r\n" + secret.encode() + b"\r\n", destination_port=23))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "telnet")
    texts = [item["text"] for item in session["commands"]]
    assert texts == ["ls -l"]
    assert secret not in json.dumps(session["commands"])
    query = "SELECT".encode("utf-16le")
    rest = " 1".encode("utf-16le")
    tds = bytes([1, 0]) + (8 + len(query)).to_bytes(2, "big") + b"\x00\x00\x01\x00" + query
    tds += bytes([1, 1]) + (8 + len(rest)).to_bytes(2, "big") + b"\x00\x00\x01\x00" + rest
    sql_out = io.BytesIO()
    sql_writer = PcapWriter(sql_out)
    sql_writer.write(1, tcp_frame(1, tds, destination_port=1433))
    sql_raw = sql_out.getvalue()
    sql_report = analyze_pcap(io.BytesIO(sql_raw))
    sql_session = next(item for item in sql_report["sessions"] if item["protocol"] == "tds")
    assert sql_session["commands"] == [{"protocol": "tds", "text": "SELECT 1"}]
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("telnet.pcap", output.getvalue())})
        assert uploaded.status_code == 201, uploaded.text
        found = client.get("/api/network/commands/search", params={"q": "ls -l"})
        assert found.status_code == 200
        assert found.json()[0]["text"] == "ls -l"
        assert found.json()[0]["protocol"] == "telnet"
        assert client.get("/api/network/commands/search", params={"q": secret}).json() == []
        client.post("/api/network/pcap", files={"file": ("sql.pcap", sql_raw)})
        sql_hit = client.get("/api/network/commands/search", params={"q": "SELECT"})
        assert sql_hit.json()[0]["text"] == "SELECT 1"


def test_stored_session_search_returns_the_flow_without_payload(tmp_path):
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("example.pcap", sample_capture())})
        assert uploaded.status_code == 201, uploaded.text
        found = client.get("/api/network/sessions/search", params={"q": "http"})
        assert found.status_code == 200
        hit = found.json()[0]
        assert hit["protocol"] == "http" and hit["transport"] == "tcp"
        assert "10.0.0.1:41000" in hit["session"]
        rendered = json.dumps(found.json())
        assert "payload" not in rendered and "secret" not in rendered
        assert client.get("/api/network/sessions/search", params={"q": "rdp"}).json() == []


def test_stored_http_body_names_a_card_without_copying_it():
    body = b"Pay 4242424242424242 now"
    request = (b"POST /payroll HTTP/1.1\r\nHost: files.example\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, request, destination_port=80))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "http")
    message = next(item for direction in session["directions"] for item in direction["decoded"]["messages"] if item.get("type") == "http_body")
    finding = next(item for item in report["traffic_analysis"]["findings"] if item["category"] == "file")
    assert message["sha256"] == hashlib.sha256(body).hexdigest()
    assert message["sensitive"] == "card ending 4242"
    assert finding["evidence"]["label"] == "card ending 4242"
    assert "4242424242424242" not in json.dumps(message)
    assert "4242424242424242" not in json.dumps(finding)
    chunked = b"5\r\nhello\r\n0\r\n\r\n"
    request = b"POST /note HTTP/1.1\r\nHost: files.example\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
    assert decode("http", request)["messages"][1] == {"type": "http_body", "length": 5, "sha256": hashlib.sha256(b"hello").hexdigest()}


def test_stored_smb_write_names_a_card_without_copying_it():
    body = b"Pay 4242424242424242 now"
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[12:14] = (9).to_bytes(2, "little")
    packet = bytes(header) + struct.pack("<HHI", 49, 112, len(body)) + b"\x00" * 40 + body
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, packet, destination_port=445))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "smb")
    message = next(item for direction in session["directions"] for item in direction["decoded"]["messages"] if item.get("type") == "smb2_header")
    finding = next(item for item in report["traffic_analysis"]["findings"] if item["category"] == "file")
    assert message["command_name"] == "WRITE"
    assert message["sha256"] == hashlib.sha256(body).hexdigest()
    assert message["sensitive"] == "card ending 4242"
    assert finding["evidence"]["sha256"] == message["sha256"]
    rendered = json.dumps(message) + json.dumps(finding)
    assert "4242424242424242" not in rendered
    encrypted = decode("smb", b"\xfdSMB" + b"\x00" * 20)
    assert encrypted["messages"][0]["encrypted"] is True
    assert "sha256" not in encrypted["messages"][0]
    assert "not decrypted" in encrypted["notes"][0]


def test_stored_file_list_keeps_the_http_hash_without_the_body(tmp_path):
    body = b"Pay 4242424242424242 now"
    request = (b"POST /payroll HTTP/1.1\r\nHost: files.example\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, request, destination_port=80))
    raw = output.getvalue()
    report = analyze_pcap(io.BytesIO(raw))
    session = next(item for item in report["sessions"] if item["protocol"] == "http")
    assert session["files"] == [{
        "protocol": "http", "length": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        "sensitive": "card ending 4242",
    }]
    assert body.decode() not in json.dumps(session["files"])
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("http.pcap", raw)})
        assert uploaded.status_code == 201, uploaded.text
        found = client.get("/api/network/files/search", params={"q": "http"})
        assert found.status_code == 200
        assert found.json()[0]["sha256"] == hashlib.sha256(body).hexdigest()
        assert "4242424242424242" not in found.text


def test_stored_finding_search_names_exfiltration_and_privilege(tmp_path):
    body = b"Pay 4242424242424242 now"
    request = (b"POST /payroll HTTP/1.1\r\nHost: files.example\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    http_out = io.BytesIO()
    writer = PcapWriter(http_out)
    writer.write(1, tcp_frame(1, request, destination_port=80))
    telnet_out = io.BytesIO()
    writer = PcapWriter(telnet_out)
    writer.write(1, tcp_frame(1, b"sudo id\r\n", destination_port=23))
    with make_client(tmp_path) as client:
        assert client.post("/api/network/pcap", files={"file": ("http.pcap", http_out.getvalue())}).status_code == 201
        assert client.post("/api/network/pcap", files={"file": ("telnet.pcap", telnet_out.getvalue())}).status_code == 201
        leaked = client.get("/api/network/findings/search", params={"tactic": "exfiltration"})
        assert leaked.status_code == 200
        assert leaked.json()[0]["title"] == "Sensitive file transfer"
        assert "4242424242424242" not in leaked.text
        privileged = client.get("/api/network/findings/search", params={"tactic": "privilege"})
        assert privileged.json()[0]["title"] == "Suspicious command: privilege"
        assert "sudo" not in privileged.text
        assert client.get("/api/network/findings/search", params={"tactic": "malware-signature"}).status_code == 422


def _rpc_u32(value):
    return struct.pack("!I", value)


def _nfs_write(payload, flavor=0):
    header = b"".join(_rpc_u32(value) for value in (1, 0, 2, 100003, 3, 7))
    auth = _rpc_u32(flavor) + _rpc_u32(0)
    handle = _rpc_u32(4) + b"file"
    tail = struct.pack("!QII", 0, len(payload), 0) + _rpc_u32(len(payload)) + payload
    tail += b"\x00" * ((4 - len(payload) % 4) % 4)
    return header + auth + auth + handle + tail


def test_stored_imap_and_pop3_sessions_keep_headers_without_the_body():
    secret = "4242424242424242"
    imap = (
        "A1 LOGIN ada s3cret-value\r\nA2 AUTHENTICATE PLAIN\r\nAHNlY3JldA==\r\n"
        "* 1 FETCH (BODY[HEADER] {40}\r\nSubject: payroll\r\nFrom: ada@example\r\n\r\n"
        "Pay " + secret + " now\r\n"
    ).encode()
    pop3 = (
        "USER ada\r\nPASS s3cret-value\r\nRETR 1\r\n+OK\r\nSubject: payroll\r\n\r\n"
        "Pay " + secret + " now\r\n.\r\n"
    ).encode()
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, imap, destination_port=143))
    writer.write(2, tcp_frame(2, pop3, source_port=41001, destination_port=110))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    imap_session = next(item for item in report["sessions"] if item["protocol"] == "imap")
    pop_session = next(item for item in report["sessions"] if item["protocol"] == "pop3")
    imap_decoded = next(direction["decoded"] for direction in imap_session["directions"] if direction["decoded"]["messages"])
    pop_decoded = next(direction["decoded"] for direction in pop_session["directions"] if direction["decoded"]["messages"])
    rendered = json.dumps({"imap": imap_decoded, "pop3": pop_decoded, "commands": imap_session["commands"] + pop_session["commands"]})
    assert {"type": "imap_login", "username": "ada"} in imap_decoded["messages"]
    assert {"type": "imap_header", "name": "subject", "value": "payroll"} in imap_decoded["messages"]
    assert {"type": "pop3_user", "username": "ada"} in pop_decoded["messages"]
    assert {"type": "pop3_header", "name": "subject", "value": "payroll"} in pop_decoded["messages"]
    assert "s3cret-value" not in rendered
    assert "AHNlY3JldA==" not in rendered
    assert secret not in rendered
    assert decode("imaps", imap)["messages"] == []
    assert decode("pop3s", pop3)["messages"] == []


def test_stored_nfs_write_names_a_card_without_copying_it():
    body = b"Pay 4242424242424242 now"
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, _nfs_write(body), destination_port=2049))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "nfs")
    message = next(item for direction in session["directions"] for item in direction["decoded"]["messages"])
    assert message["type"] == "nfs_write"
    assert message["sha256"] == hashlib.sha256(body).hexdigest()
    assert message["sensitive"] == "card ending 4242"
    assert body.decode() not in json.dumps(message)
    assert session["files"][0]["protocol"] == "nfs"
    assert decode("nfs", _nfs_write(body, flavor=6))["messages"][0]["encrypted"] is True


def test_stored_rules_rerun_names_discovery_without_the_command(tmp_path):
    output = io.BytesIO()
    writer = PcapWriter(output)
    samples = (
        (41000, b"whoami\r\n", "discovery", "Suspicious command: discovery", "whoami"),
        (41001, b"rm -rf /tmp\r\n", "impact", "Suspicious command: destructive delete", "rm -rf"),
        (41002, b"crontab -l\r\n", "persistence", "Suspicious command: persistence", "crontab"),
        (41003, b"psexec \\\\host\r\n", "lateral-movement", "Suspicious command: lateral movement", "psexec"),
        (41004, b"wget http://files.example\r\n", "collection", "Suspicious command: download", "wget"),
    )
    for index, (port, payload, _tactic, _title, _hidden) in enumerate(samples, start=1):
        writer.write(index, tcp_frame(index, payload, source_port=port, destination_port=23))
    raw = output.getvalue()
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("telnet.pcap", raw)})
        assert uploaded.status_code == 201, uploaded.text
        capture_id = uploaded.json()["id"]
        digest = uploaded.json()["sha256"]
        applied = client.post(f"/api/network/captures/{capture_id}/rules")
        assert applied.status_code == 200, applied.text
        assert applied.json()["sha256"] == digest
        for _port, _payload, tactic, title, hidden in samples:
            found = client.get("/api/network/findings/search", params={"tactic": tactic})
            assert found.status_code == 200
            assert found.json()[0]["title"] == title
            assert hidden not in found.text
        tactics = client.get("/api/network/findings/search", params={"tactic": "ttp"})
        assert any(item["title"].startswith("Suspicious command:") for item in tactics.json())


def _mail_attachment(secret: bytes) -> str:
    encoded = base64.b64encode(secret).decode()
    return (
        "Subject: payroll\r\n"
        "Content-Type: multipart/mixed; boundary=abc\r\n"
        "\r\n"
        "--abc\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Pay " + secret.decode() + " now\r\n"
        "--abc\r\n"
        "Content-Disposition: attachment; filename=\"pay.txt\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        + encoded + "\r\n"
        "--abc--\r\n"
    )


def test_stored_mail_attachment_is_hashed_without_the_bytes():
    secret = b"Pay 4242424242424242 now"
    message = _mail_attachment(secret)
    smtp = ("EHLO client.example\r\nMAIL FROM:<ada@example>\r\nRCPT TO:<bob@example>\r\nDATA\r\n" + message + ".\r\n").encode()
    imap = ("A1 LOGIN ada s3cret-value\r\n* 1 FETCH (BODY[] {1}\r\n" + message + ")\r\n").encode()
    pop3 = ("USER ada\r\nPASS s3cret-value\r\nRETR 1\r\n+OK\r\n" + message + ".\r\n").encode()
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, smtp, destination_port=25))
    writer.write(2, tcp_frame(2, imap, source_port=41001, destination_port=143))
    writer.write(3, tcp_frame(3, pop3, source_port=41002, destination_port=110))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    visible = []
    for session in report["sessions"]:
        visible.append({
            "protocol": session["protocol"],
            "files": session["files"],
            "messages": [message for direction in session["directions"] for message in direction["decoded"]["messages"]],
        })
    rendered = json.dumps(visible)
    assert secret.decode() not in rendered
    assert "s3cret-value" not in rendered
    assert base64.b64encode(secret).decode() not in rendered
    for protocol in ("smtp", "imap", "pop3"):
        session = next(item for item in report["sessions"] if item["protocol"] == protocol)
        stored = session["files"][0]
        assert stored["protocol"] == protocol
        assert stored["name"] == "pay.txt"
        assert stored["sha256"] == hashlib.sha256(secret).hexdigest()
        assert stored["sensitive"] == "card ending 4242"


def test_stored_protocol_anomaly_names_the_port_without_the_request(tmp_path):
    request = b"GET /review HTTP/1.1\r\nHost: files.example\r\n\r\n"
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, request, destination_port=25))
    with make_client(tmp_path) as client:
        uploaded = client.post("/api/network/pcap", files={"file": ("mail-port.pcap", output.getvalue())})
        assert uploaded.status_code == 201, uploaded.text
        found = client.get("/api/network/findings/search", params={"tactic": "protocol-anomaly"})
        assert found.status_code == 200
        assert found.json()[0]["title"] == "Protocol anomaly"
        assert found.json()[0]["evidence"]["protocol"] == "http"
        assert 25 in found.json()[0]["evidence"]["ports"]
        assert "GET" not in found.text


def test_stored_smtp_session_keeps_the_envelope_without_the_body():
    secret = "4242424242424242"
    payload = (
        "EHLO client.example\r\nAUTH PLAIN AHNlY3JldA==\r\n"
        "MAIL FROM:<ada@example>\r\nRCPT TO:<bob@example>\r\nDATA\r\n"
        "Subject: payroll\r\n\r\nPay " + secret + " now\r\n.\r\n"
    ).encode()
    output = io.BytesIO()
    writer = PcapWriter(output)
    writer.write(1, tcp_frame(1, payload, destination_port=25))
    report = analyze_pcap(io.BytesIO(output.getvalue()))
    session = next(item for item in report["sessions"] if item["protocol"] == "smtp")
    decoded = next(direction["decoded"] for direction in session["directions"] if direction["decoded"]["messages"])
    rendered = json.dumps(decoded)
    assert decoded["messages"][0] == {"type": "smtp_envelope", "sender": "ada@example", "recipients": ["bob@example"]}
    assert {"type": "smtp_header", "name": "subject", "value": "payroll"} in decoded["messages"]
    assert decoded["messages"][1]["type"] == "smtp_auth"
    assert "AHNlY3JldA==" not in rendered
    assert secret not in rendered
    assert decode("smtps", payload)["messages"] == []
    assert "encrypted" in decode("smtps", payload)["notes"][0]


def test_cleartext_http_request_records_host_and_path_without_query():
    request = b"GET /reports/today?token=secret HTTP/1.1\r\nHost: files.example:8080\r\nCookie: session=hidden\r\n\r\n"
    decoded = decode("http", request)
    assert decoded["urls"] == [{"host": "files.example", "path": "/reports/today"}]
    assert "secret" not in json.dumps(decoded["urls"])
    assert decoded["messages"][0]["headers"]["cookie"] == "[redacted]"
    assert decode("https", request)["messages"] == []


def _dns_query(name):
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00\x00\x01\x00\x01"
    return header + question


def test_stored_dns_query_records_the_name_without_a_website_visit():
    table = SessionTable()
    table.consume(Packet(1, "10.0.0.8", "10.0.0.1", 53000, 53, "udp", _dns_query("Files.Example")))
    table.finish()
    session = table.report()[0]
    assert session["protocol"] == "dns"
    message = session["directions"][session["initiator"]]["decoded"]["messages"][0]
    assert message == {"type": "dns_query", "name": "files.example", "qtype": "A"}
    assert "website visit" in session["directions"][session["initiator"]]["decoded"]["coverage"]
    pointed = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x03www\xc0\x1c" + b"\x00\x01\x00\x01" + b"\x00" * 6 + b"\x07example\x00"
    assert decode("dns", pointed)["messages"][0]["name"] == "www.example"
    response = bytearray(_dns_query("files.example"))
    response[2] |= 0x80
    assert decode("dns", bytes(response))["messages"] == []
