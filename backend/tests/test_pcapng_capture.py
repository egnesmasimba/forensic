import hashlib
import io
import struct

import pytest

from network_sensor.packets import CaptureError, pcap_records
from network_sensor.pipeline import analyze_pcap
from test_api import make_client
from test_network_sensor import tcp_frame, ipv4_fragment


def block(kind, body, endian="<"):
    assert len(body) % 4 == 0
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def interface(endian="<", resolution=6, offset=0, linktype=1):
    opts = option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + "q", offset), endian)
    return block(1, struct.pack(endian + "HHI", linktype, 0, 65535) + opts, endian)


def packet(frame, endian="<", interface_id=0, ticks=1_000_000, legacy=False):
    header = struct.pack(endian + ("HHIIII" if legacy else "IIIII"),
                         *([interface_id, 0] if legacy else [interface_id]),
                         ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame))
    return block(2 if legacy else 6, header + frame + b"\0" * (-len(frame) % 4), endian)


@pytest.mark.parametrize("endian,resolution,ticks,offset,expected", [
    ("<", 6, 1_500_000, 0, 1.5), (">", 9, 1_500_000_000, -1, .5),
    ("<", 138, 1536, 3, 4.5),
])
def test_timestamp_resolution_and_endianness(endian, resolution, ticks, offset, expected):
    frame = tcp_frame(100, flags=2)
    raw = section(endian) + interface(endian, resolution, offset) + packet(frame, endian, ticks=ticks)
    records = list(pcap_records(io.BytesIO(raw)))
    assert records[0] == (expected, frame, len(frame), 1)
    assert records[0].capture_source == "section-0/interface-0"


def test_interface_and_section_streams_do_not_merge():
    frame = tcp_frame(100, b"GET / HTTP/1.1\r\n\r\n")
    raw = section() + interface() + interface(linktype=101)
    raw += packet(frame) + packet(frame[14:], interface_id=1)
    raw += section(">") + interface(">") + packet(frame, ">", legacy=True)
    report = analyze_pcap(io.BytesIO(raw))
    assert report["metrics"]["processed"] == 3
    assert len(report["sessions"]) == 3
    assert len({row["capture_source"] for row in report["sessions"]}) == 3
    assert all(row["packets"] == 1 for row in report["sessions"])


def test_fragment_reassembly_cannot_cross_interfaces():
    udp = struct.pack("!HHHH", 12345, 53, 16, 0) + b"12345678"
    raw = section() + interface() + interface()
    raw += packet(ipv4_fragment(1, 0, True, udp[:8]))
    raw += packet(ipv4_fragment(1, 1, False, udp[8:]), interface_id=1)
    report = analyze_pcap(io.BytesIO(raw))
    assert not report["sessions"]
    raw += packet(ipv4_fragment(1, 1, False, udp[8:]))
    assert len(analyze_pcap(io.BytesIO(raw))["sessions"]) == 1


@pytest.mark.parametrize("bad", [
    b"\x0a\x0d\x0d\x0a", section()[:-1],
    section() + struct.pack("<III", 1, 0xFFFFFFFC, 0),
    section() + interface() + packet(b"hello", interface_id=3),
    section() + interface() + block(3, struct.pack("<I", 0)),
    section() + interface() + packet(b"abc")[:-4] + b"\0" * 4,
    section() + block(1, struct.pack("<HHI", 1, 0, 65535) + option(9, b"\x06\x06")),
])
def test_malformed_and_untimed_capture_is_rejected(bad):
    with pytest.raises(CaptureError):
        list(pcap_records(io.BytesIO(bad)))


def test_unknown_metadata_is_skipped_and_packet_budget_applies():
    raw = section() + interface() + block(0x40000001, b"metadata")
    raw += packet(tcp_frame(100)) * 2
    assert len(list(pcap_records(io.BytesIO(raw)))) == 2
    with pytest.raises(CaptureError, match="exceeds 1 packets"):
        analyze_pcap(io.BytesIO(raw), max_packets=1)


def test_pcapng_upload_download_preserves_evidence(tmp_path):
    raw = section() + interface() + packet(tcp_frame(100, b"GET / HTTP/1.1\r\n\r\n"))
    with make_client(tmp_path) as client:
        response = client.post("/api/network/pcap", files={"file": ("trace.pcapng", raw)})
        assert response.status_code == 201, response.text
        row = response.json()
        assert row["format"] == "pcapng"
        assert row["sha256"] == hashlib.sha256(raw).hexdigest()
        download = client.get(f"/api/network/captures/{row['id']}/download")
        assert download.content == raw
        assert download.headers["content-disposition"].endswith(".pcapng")
        invalid = client.post("/api/network/pcap", files={"file": ("bad.pcapng", raw[:-1])})
        assert invalid.status_code == 422


def test_verification_accepts_explicit_interface():
    from network_sensor.__main__ import build_parser
    args = build_parser().parse_args(["--verify", "--interface", "test0"])
    assert args.verify and args.interface == "test0"


def test_interrupted_encrypted_capture_is_finalized_and_never_overwrites(tmp_path):
    from evidence.crypto import EvidenceCipher, generate_keyring
    from network_sensor.secure_store import SecureCaptureWriter, read_encrypted_capture
    cipher = EvidenceCipher(generate_keyring("capture-key"))
    path = tmp_path / "interrupted.efmcap"
    frame = tcp_frame(100)
    with pytest.raises(KeyboardInterrupt):
        with SecureCaptureWriter(path, 1, cipher, "capture-key") as sink:
            assert sink.size() == 24
            sink.write(1.0, frame, len(frame))
            assert sink.size() == 24 + 16 + len(frame)
            raise KeyboardInterrupt
    original = path.read_bytes()
    assert len(list(pcap_records(read_encrypted_capture(path, cipher, "capture-key")))) == 1
    with pytest.raises(FileExistsError):
        with SecureCaptureWriter(path, 1, cipher, "capture-key") as sink:
            sink.write(2.0, frame, len(frame))
    assert path.read_bytes() == original


def test_plain_capture_size_includes_record_headers(tmp_path):
    from network_sensor.secure_store import PlainCaptureWriter
    with PlainCaptureWriter(tmp_path / "count.pcap", 1) as sink:
        assert sink.size() == 24
        sink.write(1.0, b"abc")
        assert sink.size() == 43
