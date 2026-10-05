from network_sensor.traffic_analysis import analyze_traffic
from network_sensor.config import SensorConfig
import pytest

def flow(i=0, **changes):
    return {"id": str(i), "protocol": "http", "classification_basis": "signature", "endpoints": [["10.0.0.1", 40000+i], ["10.0.0.2", 80]], "first": i*10, "last": i*10+1, "packets": 2, "directions": [], "payload_bytes": 100, "initiator": 0, "syn_attempt": True, **changes}

def test_beacon_and_negative():
    rows = [flow(i) for i in range(6)]
    assert any(f["category"] == "c2" for f in analyze_traffic(rows)["findings"])
    rows[-1]["first"] = 100
    assert not analyze_traffic(rows)["findings"]

def test_categories_and_bandwidth():
    rows = [flow(i, endpoints=[["10.0.0.1", 40000], ["10.0.0.2", 100+i]], payload_bytes=0) for i in range(10)]
    rows.append(flow(20, protocol="unknown", payload_bytes=2000, directions=[{"length": 0, "overlap_conflict": True}]))
    result = analyze_traffic(rows, {"malware_ips": ["10.0.0.2"], "c2_ips": ["10.0.0.2"], "heavy_bytes": 1000})
    assert {f["category"] for f in result["findings"]} == {"network_threat", "malware_callback", "c2", "unusual_protocol", "protocol_anomaly", "traffic_anomaly"}
    assert result["applications"][0]["application"] == "unknown"
    assert result["total_payload_bytes"] == 2000
    assert any(f["title"] == "Possible port or host scan" for f in result["findings"])

def test_empty_and_validation():
    assert analyze_traffic([])["total_payload_bytes"] == 0
    with pytest.raises(ValueError): SensorConfig(malware_ips=["invalid"])

def test_volume_not_clipped():
    from network_sensor.sessions import SessionTable
    from network_sensor.packets import Packet
    table = SessionTable(bytes_per_direction=4)
    table.consume(Packet(0, "10.0.0.1", "10.0.0.2", 40000, 80, "tcp", b"abcdefgh"))
    session = table.report()[0]
    assert session["payload_bytes"] == 8
    assert session["directions"][0]["length"] == 4
