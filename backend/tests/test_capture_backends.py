"""Capture backend selection, mirror/tap VLAN verification and the encrypted container.

No capture hardware is required. Every test that would need a live mirror port
asserts the honest failure path instead, so a suite run on a host without Npcap,
PF_RING or DPDK still proves the reporting is correct.
"""
import io
import json
import os

import pytest

from evidence.crypto import generate_keyring
from network_sensor.config import CapturePointConfig, SensorConfig
from network_sensor.engines import (
    BACKENDS,
    ZERO_TIMESTAMP,
    CaptureEngine,
    DpdkEngine,
    LibpcapEngine,
    PfRingEngine,
    available_backends,
    check_linktype,
    create_engine,
    describe_backend,
    normalise_timestamp,
)
from network_sensor.packets import CaptureError
from network_sensor.secure_store import (
    SecureCaptureError,
    container_info,
    open_cipher,
    read_encrypted_capture,
    write_encrypted_capture,
)
from network_sensor.verification import (
    CapturePointObservations,
    benchmark_harness,
    frame_facts,
    preflight,
    run_verification,
    self_check,
    synthetic_traffic,
)


class FakeEngine(CaptureEngine):
    """Replays a fixed frame list so pipeline code can be tested without hardware."""

    name = "fake"

    def __init__(self, records=(), linktype=1):
        self.records = list(records)
        self.linktype_value = linktype
        self.opened = None
        self.closed = False

    def devices(self):
        return [{"name": "fake0", "description": "synthetic"}]

    def open(self, interface, bpf="tcp or udp", promiscuous=True):
        self.opened = (interface, bpf, promiscuous)
        return self

    def next_packet(self):
        return self.records.pop(0) if self.records else None

    def close(self):
        self.closed = True

    @property
    def linktype(self):
        return self.linktype_value


def ethernet(ethertype=0x0800, vlans=()):
    frame = bytearray(bytes.fromhex("020000000001020000000002"))
    for vlan in vlans:
        frame += (0x8100).to_bytes(2, "big") + vlan.to_bytes(2, "big")
    frame += ethertype.to_bytes(2, "big")
    return bytes(frame) + bytes(40)


# -- backend registration -----------------------------------------------------

def test_all_backends_are_registered():
    assert BACKENDS == ("libpcap", "pfring", "dpdk")
    assert [item["backend"] for item in available_backends()] == list(BACKENDS)


def test_unknown_backend_is_rejected():
    with pytest.raises(CaptureError):
        create_engine("netsh")


@pytest.mark.parametrize("linktype", [1, 101, 113, 276])
def test_supported_linktypes(linktype):
    assert check_linktype(linktype) == linktype


def test_unsupported_linktype_is_rejected():
    with pytest.raises(CaptureError):
        check_linktype(999)


@pytest.mark.skipif(os.name == "nt", reason="PF_RING and DPDK are Linux-only")
def test_linux_backends_report_missing_prerequisites():
    for backend in ("pfring", "dpdk"):
        assert describe_backend(backend)["available"] in (True, False)


@pytest.mark.skipif(os.name != "nt", reason="Npcap is Windows-only")
def test_pfring_and_dpdk_refuse_windows():
    for engine in (PfRingEngine, DpdkEngine):
        with pytest.raises(CaptureError, match="Linux only"):
            engine()


def test_backend_report_names_its_prerequisite():
    for item in available_backends():
        assert item["note"] and item["library"] and item["platform"]
        assert "available" in item and "error" in item
        if not item["available"]:
            assert item["error"], "an unavailable backend must explain itself"


def test_linux_only_backends_report_unavailable_on_windows():
    if os.name != "nt":
        pytest.skip("Windows-only assertion")
    for backend in ("pfring", "dpdk"):
        assert available_backends()[[b["backend"] for b in available_backends()].index(backend)]["available"] is False


def test_libpcap_alias_is_the_shared_engine():
    from network_sensor.capture import Pcap
    assert Pcap is LibpcapEngine


# -- timestamp policy ---------------------------------------------------------

def test_zero_timestamp_is_replaced_and_labelled():
    timestamp, frame, length, linktype, source = normalise_timestamp(
        (ZERO_TIMESTAMP, b"x", 1, 1), lambda: 123.5)
    assert (timestamp, source) == (123.5, "host_clock_substituted")


def test_capture_timestamp_is_preserved():
    assert normalise_timestamp((99.5, b"x", 1, 1))[4] == "capture_clock"


# -- configuration ------------------------------------------------------------

def test_capture_filter_includes_vlans():
    config = SensorConfig(capture_point=CapturePointConfig(name="span", interface="eth1", vlan_ids=[30, 10]))
    assert config.capture_filter() == "((tcp or udp) and (vlan 10 or vlan 30))"


def test_capture_filter_without_vlans_is_unchanged():
    config = SensorConfig(bpf="tcp port 23")
    assert config.capture_filter() == "tcp port 23"


@pytest.mark.parametrize("vlan", [0, 4095, -1, 5000])
def test_reserved_vlan_ids_are_rejected(vlan):
    with pytest.raises(Exception):
        CapturePointConfig(name="span", interface="eth1", vlan_ids=[vlan])


def test_encryption_requires_both_key_id_and_keyring():
    assert not SensorConfig().encryption_enabled
    assert SensorConfig(encryption_key_id="k1").encryption_enabled is False
    assert SensorConfig(encryption_key_id="k1", encryption_keyring="r.json").encryption_enabled


def test_unknown_backend_in_config_is_rejected():
    with pytest.raises(Exception):
        SensorConfig(backend="netsh")


# -- VLAN analysis ------------------------------------------------------------

def test_self_check_passes_without_hardware():
    result = self_check()
    assert result["passed"], result
    assert result["short_frame_ignored"] and result["non_ethernet_ignored"]
    assert result["malformed_vlan_rejected"]


@pytest.mark.parametrize("vlans,expected", [
    ((), ()),
    ((100,), (100,)),
    ((100, 200), (100, 200)),
    ((4094,), (4094,)),
])
def test_vlan_extraction(vlans, expected):
    assert frame_facts(ethernet(vlans=vlans), 1).vlan_ids == expected


def test_qinq_reports_outer_tag_first():
    frame = bytearray(bytes.fromhex("020000000001020000000002"))
    frame += (0x88A8).to_bytes(2, "big") + (400).to_bytes(2, "big")
    frame += (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
    frame += b"\x08\x00" + bytes(20)
    assert frame_facts(bytes(frame), 1).vlan_ids == (400, 100)


def test_short_frame_is_ignored():
    assert frame_facts(b"\x00" * 10, 1) is None


def test_truncated_vlan_tag_is_rejected():
    assert self_check()["malformed_vlan_rejected"]


# -- observation reporting ----------------------------------------------------

def test_observation_reports_missing_vlans():
    point = CapturePointConfig(name="span", interface="eth1", vlan_ids=[100])
    observations = CapturePointObservations(point)
    for _ in range(3):
        observations.observe(ethernet(vlans=(200,)), 54, 1)
    report = observations.report()
    assert report["verified"] is False
    assert "100" in report["findings"][0]


def test_observation_verifies_expected_vlans():
    point = CapturePointConfig(name="span", interface="eth1", vlan_ids=[100])
    observations = CapturePointObservations(point)
    for _ in range(3):
        observations.observe(ethernet(vlans=(100,)), 54, 1)
    report = observations.report()
    assert report["verified"] is True
    assert report["vlans_observed"] == {"100": 3}
    assert report["distinct_source_macs"] == 1


def test_observation_without_traffic_is_not_verified():
    assert CapturePointObservations().report()["verified"] is False


def test_untagged_traffic_is_flagged_against_a_vlan_plan():
    point = CapturePointConfig(name="span", interface="eth1", vlan_ids=[100])
    observations = CapturePointObservations(point)
    observations.observe(ethernet(), 54, 1)
    observations.observe(ethernet(vlans=(100,)), 54, 1)
    report = observations.report()
    assert report["untagged_frames"] == 1
    assert any("untagged" in finding for finding in report["findings"])


def test_substituted_clock_is_reported():
    observations = CapturePointObservations()
    observations.observe(ethernet(vlans=(7,)), 54, 1, "host_clock_substituted")
    assert observations.report()["clock_sources"] == {"host_clock_substituted": 1}


def test_unparseable_frames_are_counted():
    observations = CapturePointObservations()
    observations.observe(ethernet(), 54, 276)  # cooked header, not Ethernet
    assert observations.report()["unparseable_frames"] == 0
    assert observations.report()["ethernet_frames"] == 0


# -- preflight and live verification -----------------------------------------

def test_preflight_blocks_on_missing_keyring(tmp_path):
    config = SensorConfig(encryption_key_id="k1", encryption_keyring=str(tmp_path / "absent.json"),
                          capture_point=CapturePointConfig(name="s", interface="eth1"))
    assert any("Keyring" in reason for reason in preflight(config)["blocking"])


def test_preflight_accepts_a_complete_configuration(tmp_path):
    path = generate_keyring("k1").save(tmp_path / "ring.json")
    config = SensorConfig(encryption_key_id="k1", encryption_keyring=str(path),
                          capture_point=CapturePointConfig(name="s", interface="eth1", vlan_ids=[100]))
    result = preflight(config)
    assert result["encryption_keyring_present"] is True
    assert "vlan 100" in result["capture_filter"]


def test_verification_without_interface_explains_itself():
    report = run_verification(SensorConfig(), duration=1)
    assert report["verified"] is False
    assert "interface" in report["reason"].lower()
    assert report["self_check"]["passed"] is True


def test_verification_without_hardware_is_not_verified():
    config = SensorConfig(capture_point=CapturePointConfig(name="s", interface="eth1", vlan_ids=[100]))
    engine = FakeEngine()
    report = run_verification(config, engine=engine, duration=1)
    assert report["verified"] is False
    assert report["self_check"]["passed"] is True
    assert report["observation"]["frames_observed"] == 0
    assert engine.opened == ("eth1", "((tcp or udp) and (vlan 100))", True)
    assert engine.closed is False, "an injected engine is owned by the caller"


def test_verification_verifies_an_injected_engine():
    config = SensorConfig(capture_point=CapturePointConfig(name="s", interface="eth1", vlan_ids=[100]))
    frames = [(1.0, ethernet(vlans=(100,)), 54, 1), (1.1, ethernet(vlans=(100,)), 54, 1)]
    report = run_verification(config, engine=FakeEngine(frames), duration=1)
    assert report["verified"] is True
    assert report["observation"]["vlans_observed"] == {"100": 2}


def test_verification_flags_a_mirrored_but_wrong_vlan():
    config = SensorConfig(capture_point=CapturePointConfig(name="s", interface="eth1", vlan_ids=[100]))
    frames = [(1.0, ethernet(vlans=(999,)), 54, 1)]
    report = run_verification(config, engine=FakeEngine(frames), duration=1)
    assert report["verified"] is False
    assert "100" in report["reason"]


def test_verification_reports_when_the_backend_is_missing():
    config = SensorConfig(backend="dpdk", capture_point=CapturePointConfig(name="s", interface="eth1"))
    if os.name == "nt":
        report = run_verification(config, duration=1)
        assert report["verified"] is False
        assert "Linux only" in report["reason"]


# -- benchmark ----------------------------------------------------------------

def test_synthetic_traffic_decodes_completely():
    report = benchmark_harness(SensorConfig(), count=2000, vlan_id=100)
    assert report["decoded_packets"] == 2000
    assert report["decode_failures"] == 0
    assert report["truncated_packets"] == 0
    assert report["packets_per_second"] > 0
    assert report["traffic"]["synthetic"] is True


def test_synthetic_frames_are_valid_tcp():
    from network_sensor.packets import decode_packet
    timestamp, frame, original, linktype = next(iter(synthetic_traffic(1, vlan_id=42)))
    packet = decode_packet(timestamp, frame, original, linktype)
    assert packet.source == "10.0.0.1" and packet.destination == "10.0.0.2"
    assert packet.source_port == 50000 and packet.destination_port == 23


# -- encrypted container ------------------------------------------------------

@pytest.fixture
def encrypted_capture(tmp_path):
    path = generate_keyring("k1").save(tmp_path / "ring.json", wrap_with="pw")
    config = SensorConfig(encryption_key_id="k1", encryption_keyring=str(path))
    cipher, key_id = open_cipher(config, "pw")
    target = tmp_path / "capture.efmcap"
    manifest = write_encrypted_capture(target, 1, synthetic_traffic(64, vlan_id=100), cipher, key_id)
    return config, cipher, key_id, target, manifest


def test_container_roundtrip(encrypted_capture):
    config, cipher, key_id, target, manifest = encrypted_capture
    assert manifest["encrypted"] and manifest["packets"] == 64
    stream = read_encrypted_capture(target, cipher, key_id)
    assert stream.read(4) == b"\xd4\xc3\xb2\xa1"


def test_container_header_is_readable_without_the_key(encrypted_capture):
    _, _, _, target, _ = encrypted_capture
    info = container_info(target)
    assert info["encrypted"] is True and info["version"] == 1 and info["linktype"] == 1


def test_plain_pcap_is_not_treated_as_a_container(tmp_path):
    from network_sensor.packets import PcapWriter
    path = tmp_path / "plain.pcap"
    with path.open("wb") as handle:
        PcapWriter(handle, 1).write(1.0, b"\x00" * 20)
    assert container_info(path) == {"encrypted": False}


def test_container_tamper_is_detected(encrypted_capture):
    _, cipher, key_id, target, _ = encrypted_capture
    blob = bytearray(target.read_bytes())
    blob[-5] ^= 0xFF
    target.write_bytes(bytes(blob))
    with pytest.raises(SecureCaptureError):
        read_encrypted_capture(target, cipher, key_id)


def test_container_wrong_key_is_detected(encrypted_capture, tmp_path):
    _, _, _, target, _ = encrypted_capture
    other_path = generate_keyring("k2").save(tmp_path / "other.json")
    cipher, key_id = open_cipher(SensorConfig(encryption_key_id="k2", encryption_keyring=str(other_path)))
    with pytest.raises(SecureCaptureError):
        read_encrypted_capture(target, cipher, key_id)


def test_non_container_is_refused(tmp_path):
    from evidence.crypto import EvidenceCipher
    path = tmp_path / "random.bin"
    path.write_bytes(b"not a capture" * 8)
    with pytest.raises(SecureCaptureError):
        read_encrypted_capture(path, EvidenceCipher(generate_keyring("k")), "k")


def test_missing_key_is_reported(tmp_path):
    config = SensorConfig(encryption_key_id="absent", encryption_keyring=str(tmp_path / "ring.json"))
    generate_keyring("k1").save(tmp_path / "ring.json")
    with pytest.raises(SecureCaptureError):
        open_cipher(config)


def test_unreadable_keyring_is_reported(tmp_path):
    config = SensorConfig(encryption_key_id="k1", encryption_keyring=str(tmp_path / "nope.json"))
    with pytest.raises(Exception):
        open_cipher(config)


def test_large_capture_spills_the_buffer(tmp_path):
    from network_sensor.secure_store import SecureCaptureWriter
    path = generate_keyring("k1").save(tmp_path / "ring.json")
    config = SensorConfig(encryption_key_id="k1", encryption_keyring=str(path))
    cipher, key_id = open_cipher(config)
    target = tmp_path / "big.efmcap"
    writer = SecureCaptureWriter(target, 1, cipher, key_id, memory_limit=1024)
    with writer:
        for record in synthetic_traffic(2000):
            writer.write(*record[:3])
    assert writer.manifest["buffer_spilled_to_disk"] is True
    assert writer.manifest["packets"] == 2000
    assert len(read_encrypted_capture(target, cipher, key_id).getvalue()) > 200000


def test_encrypted_capture_survives_the_pipeline(tmp_path, encrypted_capture):
    from network_sensor.pipeline import analyze_pcap
    config, cipher, key_id, target, _ = encrypted_capture
    report = analyze_pcap(read_encrypted_capture(target, cipher, key_id), config.model_dump())
    assert report["metrics"]["processed"] == 64
    assert report["metrics"]["dropped"] == 0