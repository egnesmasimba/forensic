from types import SimpleNamespace
import base64
import json

from app.models import User
from network_sensor.layout_application import apply_layouts
from network_sensor.layouts import import_layout
from test_api import make_client
from test_network_sensor import sample_capture


def test_saved_versions_apply_to_captures_and_enforce_permissions(tmp_path):
    with make_client(tmp_path) as client:
        capture = client.post("/api/network/pcap", files={"file": ("test.pcap", sample_capture())}).json()
        payload = {"name":"HTTP prefix", "version":1, "protocol":"http", "direction":"0", "language":"c", "declaration":"char method[4];"}
        result = client.post("/api/network/layouts", json=payload)
        assert result.status_code == 201
        layout = result.json()
        assert layout["created_by"] == "investigator"
        assert client.post("/api/network/layouts", json=payload).status_code == 409
        payload["version"] = 2
        assert client.post("/api/network/layouts", json=payload).status_code == 201
        detail = client.get(f"/api/network/captures/{capture['id']}").json()
        decoded = detail["session_details"][0]["layout_results"]
        assert len(decoded) == 2
        assert decoded[0]["records"][0]["fields"]["method"] == "GET"
        identified = dict(payload, name="HTTP type", version=3, identify_field="method")
        assert client.post("/api/network/layouts", json=identified).status_code == 201
        typed = client.get(f"/api/network/captures/{capture['id']}").json()["session_details"][0]["layout_results"]
        named = next(item for item in typed if item["name"] == "HTTP type")
        assert named["records"][0]["message_type"] == "GET"
        found = client.get("/api/network/messages/search", params={"q": "GET"})
        assert found.status_code == 200
        assert any(hit["message_type"] == "GET" for hit in found.json())
        assert client.post("/api/network/layouts", json=dict(payload, name="Missing field", version=4, identify_field="absent")).status_code == 422
        assert decoded[0]["status"] == "partial_record"
        assert decoded[0]["trailing_bytes"] == 3
        assert client.patch(f"/api/network/layouts/{layout['id']}", json={"enabled":False}).status_code == 200
        assert len(client.get(f"/api/network/captures/{capture['id']}").json()["session_details"][0]["layout_results"]) == 2
        payload.update(name="Encrypted", protocol="https")
        assert client.post("/api/network/layouts", json=payload).status_code == 422
        with client.app.state.session_factory() as db:
            db.query(User).filter_by(username="investigator").first().role = "viewer"
            db.commit()
        assert client.get("/api/network/layouts").status_code == 200
        assert client.post("/api/network/layouts", json=payload).status_code == 403
        assert client.patch(f"/api/network/layouts/{layout['id']}", json={"enabled":True}).status_code == 403
        client.cookies.clear()
        assert client.get("/api/network/layouts").status_code == 401


def test_length_prefix_and_envelope_frame_each_record():
    definition = import_layout("cobol", "05 COUNT PIC 9(2).")
    definition.update(framing="length_prefix", length_width=2, envelope=1)
    payload = b"\x00\x05" + b"X12" + b"\x00\x05" + b"Y34"
    binding = SimpleNamespace(id=2, name="Framed", version=1, protocol="unknown", direction="0", offset=0,
                              definition=json.dumps(definition), encoding="ascii", byteorder="big", identify_field="COUNT")
    direction = {"syn_seen": True, "gaps": [], "overlap_conflict": False, "truncated": False,
                 "payload_base64": base64.b64encode(payload).decode()}
    session = {"protocol": "unknown", "transport": "tcp", "directions": [direction]}
    apply_layouts(session, [binding])
    result = session["layout_results"][0]
    assert result["status"] == "decoded"
    assert [record["fields"]["COUNT"] for record in result["records"]] == ["12", "34"]
    assert result["records"][0]["message_type"] == "12"
    short = dict(direction, payload_base64=base64.b64encode(b"\x00\x02").decode())
    broken = {"protocol": "unknown", "transport": "tcp", "directions": [short]}
    apply_layouts(broken, [binding])
    assert broken["layout_results"][0]["status"] == "invalid_record"


def test_incomplete_streams_and_invalid_records_are_explicit():
    definition = import_layout("cobol", "05 COUNT PIC 9(2).")
    binding = SimpleNamespace(id=1, name="Count", version=1, protocol="unknown", direction="0", offset=1,
                              definition=json.dumps(definition), encoding="ascii", byteorder="big")
    direction = {"syn_seen":True,"gaps":[],"overlap_conflict":False,"truncated":False,
                 "payload_base64":base64.b64encode(b"X12zz").decode()}
    session = {"protocol":"unknown","transport":"tcp","directions":[direction]}
    apply_layouts(session, [binding])
    result = session["layout_results"][0]
    assert result["status"] == "invalid_record" and result["failed_record"] == 1
    assert result["records"][0]["fields"] == {"COUNT":"12"}
    for flag, value in (("gaps",[{"from":1,"to":2}]),("overlap_conflict",True),("truncated",True),("syn_seen",False)):
        original = direction[flag]
        direction[flag] = value
        apply_layouts(session, [binding])
        assert session["layout_results"][0]["status"] == "skipped_incomplete_stream"
        assert not session["layout_results"][0]["records"]
        direction[flag] = original
    direction["payload_base64"] = base64.b64encode(b"X" + b"12" * 101).decode()
    apply_layouts(session, [binding])
    assert len(session["layout_results"][0]["records"]) == 100
    assert session["layout_results"][0]["record_limit_reached"]
    apply_layouts(session, [binding], {"records":1,"bytes":2})
    assert len(session["layout_results"][0]["records"]) == 1
    assert session["layout_results"][0]["status"] == "report_budget_reached"
