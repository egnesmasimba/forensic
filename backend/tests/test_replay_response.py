import base64,io,json,os
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from PIL import Image
from app.models import User,utcnow
from app.response_models import ResponseCommand
from endpoint_agent.response_actions import ResponseExecutor,SnapshotStore,WindowsIsolation
from endpoint_agent.desktop_control import DesktopController
from test_api import make_client

def admin(client):
    with client.app.state.session_factory() as db:
        db.query(User).first().role="administrator";db.commit()
def agent(client,name="fixture"):
    r=client.post("/api/agents/register",json={"machine_id":name,"hostname":name,"os":"windows"})
    assert r.status_code==201,r.text
    return r.json()["agent_id"],{"X-Agent-Token":r.json()["agent_token"]}
def queue(client,identity,action,args=None):
    r=client.post(f"/api/response/agents/{identity}/commands",json={"action":action,"arguments":args or {},"reason":"Controlled test"})
    assert r.status_code==202,r.text
    return r.json()
def image():
    s=io.BytesIO();Image.new("RGB",(120,80),"white").save(s,format="JPEG");return base64.b64encode(s.getvalue()).decode()
def command(identity,action,args=None):
    return {"id":identity,"action":action,"arguments":args or {},"actor":"fixture-admin","expires_at":(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}

def test_replay_fields_paging_search_and_original(tmp_path):
    with make_client(tmp_path) as c:
        session=c.post("/api/replay/sessions",json={"title":"Account terminal","platform":"mainframe"}).json();sid=session["id"]
        for seq,value in [(0,"100"),(4,"200"),(9,"300")]:
            r=c.post(f"/api/replay/sessions/{sid}/frames",json={"sequence":seq,"occurred_at":"2026-10-03T10:00:00+02:00","text":f"Account {value}","fields":{"Balance":value},"image_base64":image()})
            assert r.status_code==201,r.text
        assert r.json()["changes"]==[{"field":"Balance","before":"200","after":"300"}]
        assert r.json()["occurred_at"].startswith("2026-10-03T08:")
        assert c.get(f"/api/replay/sessions/{sid}/frames?after=0&limit=1").json()[0]["sequence"]==4
        assert c.get(f"/api/replay/sessions/{sid}/frames?before=9&limit=1").json()[0]["sequence"]==4
        found=c.get("/api/search?q=Balance&platform=mainframe&start=2026-10-03T07:00:00Z&end=2026-10-03T09:00:00Z").json()
        assert found["total"]==3
        assert c.get(f"/api/replay/from-search/{found['results'][0]['id']}").json()["session"]["id"]==sid
        assert c.post(f"/api/replay/sessions/{sid}/frames",json={"sequence":0,"occurred_at":"2026-10-03T10:00:00Z","text":"Duplicate"}).status_code==409
        assert c.post(f"/api/replay/sessions/{sid}/frames",json={"sequence":10,"occurred_at":"2026-10-03T10:00:00Z","image_base64":"bm90IEpQRUc="}).status_code==422
        web=c.post("/api/replay/sessions",json={"title":"Order","platform":"web"}).json()["id"]
        html='<h1>Order 987</h1><script>private-script-marker</script>'
        frame=c.post(f"/api/replay/sessions/{web}/frames",json={"sequence":0,"occurred_at":"2026-10-03T10:00:00Z","original_html":html}).json()
        assert frame["original_html"]==html and "private-script-marker" not in frame["text"]
        assert c.get("/api/search?q=private-script-marker").json()["total"]==0
        c.post("/api/auth/logout");assert c.get("/api/replay/sessions").status_code==401

def test_commands_auth_receipts_and_audit(tmp_path):
    with make_client(tmp_path) as c:
        aid,headers=agent(c)
        assert c.post(f"/api/response/agents/{aid}/commands",json={"action":"process_list","reason":"Test"}).status_code==403
        admin(c);queued=queue(c,aid,"process_list");cid=queued["id"]
        assert queued["actor"]=="investigator" and queued["state"]=="queued"
        assert c.get("/api/response/poll").status_code==401
        assert c.get("/api/response/poll",headers=headers).json()["command"]["id"]==cid
        assert c.get("/api/response/poll",headers=headers).json()["command"] is None
        result={"state":"succeeded","detail":{"processes":[{"pid":44,"name":"fixture","create_time":12}]}}
        assert c.post(f"/api/response/commands/{cid}/result",headers=headers,json=result).json()["acknowledged"]
        assert c.post(f"/api/response/commands/{cid}/result",headers=headers,json=result).json()["duplicate"]
        assert c.post(f"/api/response/commands/{cid}/result",headers=headers,json={"state":"failed","detail":{}}).status_code==409
        assert [row["action"] for row in c.get(f"/api/response/agents/{aid}/audit").json()]==["command_result","command_dispatched","command_queued"]
        _,other=agent(c,"other")
        assert c.post(f"/api/response/commands/{cid}/result",headers=other,json=result).status_code==404
        for action,args in [("process_terminate",{"pid":1,"create_time":12}),("rollback",{"point_id":"../../etc"}),("isolate",{"script":"whoami"})]:
            assert c.post(f"/api/response/agents/{aid}/commands",json={"action":action,"arguments":args,"reason":"Test"}).status_code==422

def test_live_control_recording_scope_stop_and_expiry(tmp_path):
    with make_client(tmp_path) as c:
        admin(c);aid,headers=agent(c);_,other=agent(c,"other")
        start=queue(c,aid,"live_start",{"mode":"control","duration":60});sid=start["arguments"]["session_id"]
        data={"sequence":0,"occurred_at":"2026-10-03T10:00:00Z","image_base64":image()}
        assert c.post(f"/api/replay/agent/sessions/{sid}/frames",headers=headers,json=data).status_code==409
        c.get("/api/response/poll",headers=headers)
        assert c.post(f"/api/response/commands/{start['id']}/result",headers=headers,json={"state":"succeeded","detail":{"local_consent":True}}).status_code==200
        assert c.post(f"/api/replay/agent/sessions/{sid}/frames",headers=other,json=data).status_code==403
        assert c.post(f"/api/replay/agent/sessions/{sid}/frames",headers=headers,json=data).status_code==201
        control=queue(c,aid,"control_input",{"session_id":sid,"event":"text","text":"private typed secret"})
        assert control["arguments"]["text"]=="[redacted]"
        assert c.get("/api/response/poll",headers=headers).json()["command"]["arguments"]["text"]=="private typed secret"
        with c.app.state.session_factory() as db:
            row=db.get(ResponseCommand,control["id"]);row.expires_at=utcnow()-timedelta(seconds=1);db.commit()
        c.get("/api/response/poll",headers=headers)
        assert c.get(f"/api/response/agents/{aid}/commands").json()[0]["state"]=="indeterminate"
        queue(c,aid,"live_stop",{"session_id":sid})
        assert c.post(f"/api/replay/agent/sessions/{sid}/frames",headers=headers,json={**data,"sequence":1}).status_code==409
        assert c.post("/api/response/session-ended",headers=headers,json={"session_id":sid,"reason":"Local Stop button"}).status_code==200
        assert c.get(f"/api/replay/sessions/{sid}").json()["status"]=="stopped"
        assert c.get(f"/api/replay/sessions/{sid}/frames").json()[0]["image_base64"]

def test_snapshots_restore_backup_verify_corruption_and_roots(tmp_path):
    root=tmp_path/"selected";root.mkdir();file=root/"config.txt";file.write_text("before")
    store=SnapshotStore(tmp_path/"state",[root]);point=store.create();assert point["verified"]
    file.write_text("after");(root/"new.txt").write_text("preserve")
    assert not store.verify(point["point_id"])["verified"]
    result=store.rollback(point["point_id"])
    assert result["verified"] and file.read_text()=="before" and (root/"new.txt").exists()
    assert len(store.manifest(result["backup_point_id"])["files"])==2
    manifest=store.manifest(point["point_id"])
    (store.directory/point["point_id"]/manifest["files"][0]["sha256"]).write_text("tampered");file.write_text("current")
    with pytest.raises(ValueError,match="corrupt"):store.rollback(point["point_id"])
    assert file.read_text()=="current"
    with pytest.raises(ValueError):store.safe_target(0,"../outside")
    with pytest.raises(ValueError):SnapshotStore(root/"state",[root])

def test_process_pid_identity_confirmation_and_journal(tmp_path):
    class Process:
        terminated=0
        def create_time(self):return 100
        def name(self):return "fixture.exe"
        def terminate(self):self.terminated+=1
        def wait(self,timeout):return 0
    process=Process();ps=SimpleNamespace(Process=lambda pid:process,TimeoutExpired=TimeoutError)
    config={"enabled":True,"allowed_actions":["process_terminate"]};executor=ResponseExecutor(config,tmp_path,ps=ps)
    assert executor.execute(command(1,"process_terminate",{"pid":123456,"create_time":99}))["state"]=="failed"
    assert not process.terminated
    target=command(2,"process_terminate",{"pid":123456,"create_time":100})
    assert executor.execute(target)["detail"]["terminated"]
    assert ResponseExecutor(config,tmp_path,ps=ps).execute(target)["state"]=="succeeded" and process.terminated==1
    executor.state.put("3",{"started":1})
    assert executor.execute(command(3,"process_terminate",{"pid":123456,"create_time":100}))["state"]=="indeterminate"
    assert process.terminated==1
    assert ResponseExecutor({},tmp_path/"disabled",ps=ps).execute(target)["state"]=="failed"

def test_desktop_consent_input_and_local_stop():
    calls=[];auto=SimpleNamespace(size=lambda:(100,100),click=lambda x,y:calls.append((x,y)))
    config={"desktop_enabled":True,"control_enabled":True}
    denied=DesktopController(config,consent=lambda *args:False,capture=lambda:Image.new("RGB",(120,80)),automation=auto)
    with pytest.raises(ValueError,match="declined"):denied.start({"mode":"control","session_id":1,"duration":60},"admin")
    desktop=DesktopController(config,consent=lambda *args:True,capture=lambda:Image.new("RGB",(120,80)),automation=auto)
    assert desktop.start({"mode":"control","session_id":1,"duration":60},"admin")["recording"]
    assert desktop.frame()[1]["sequence"]==0
    desktop.input({"session_id":1,"event":"click","x":0.5,"y":0.5},"admin");assert calls==[(50,50)]
    with pytest.raises(ValueError):desktop.input({"session_id":1,"event":"key","key":"enter"},"other")
    desktop.stop_event.set();assert desktop.frame() is None
    with pytest.raises(ValueError):desktop.input({"session_id":1,"event":"key","key":"enter"},"admin")

def test_isolation_management_exceptions_and_failed_verification():
    import ipaddress
    scripts=[]
    def runner(script):scripts.append(script);return {"isolated":True,"rules":2}
    isolation=WindowsIsolation(["192.0.2.10","2001:db8::1"],runner=runner)
    for allowed in isolation.allowed:
        assert not any(ipaddress.ip_address(left).version==allowed.version and int(ipaddress.ip_address(left))<=int(allowed)<=int(ipaddress.ip_address(right)) for left,right in (item.split("-") for item in isolation.ranges()))
    assert isolation.isolate()["isolated"]
    assert "New-NetFirewallRule" in scripts[0] and "Set-NetFirewallProfile" not in scripts[0]
    with pytest.raises(ValueError):WindowsIsolation([])
    with pytest.raises(ValueError,match="active"):WindowsIsolation(["192.0.2.10"],runner=lambda script:{"isolated":False}).isolate()


def test_agent_registration_renewal_cannot_steal_existing_identity(tmp_path):
    with make_client(tmp_path) as c:
        aid,headers=agent(c)
        payload={"machine_id":"fixture","hostname":"fixture","os":"windows"}
        assert c.post("/api/agents/register",json=payload).status_code==409
        assert c.post("/api/agents/register",headers=headers,json=payload).status_code==201
        assert c.get("/api/response/poll",headers=headers).status_code==401


def test_native_windows_restore_point_pending_reboot_and_verification(tmp_path):
    from endpoint_agent.response_actions import WindowsRestore
    scripts=[];boot=["first-boot"]
    def runner(script):
        scripts.append(script)
        if "Checkpoint-Computer" in script:
            import re
            return {"sequence":17,"description":re.search("ZANAQ-[a-f0-9]{32}",script).group()}
        if "shutdown.exe" in script:return {"restart_scheduled":True}
        if "GetLastRestoreStatus" in script:return {"boot":boot[0],"restore_status":1}
        return {"boot":boot[0]}
    store=WindowsRestore(tmp_path,runner=runner);point=store.create()
    assert point["scope"]=="windows_system" and point["verified"]
    assert store.rollback(point["point_id"])["restart_scheduled"]
    assert not store.verify(point["point_id"])["verified"]
    boot[0]="new-boot";assert store.verify(point["point_id"])["verified"]
    assert any("shutdown.exe /r /t 30" in script for script in scripts)


def test_pending_windows_rollback_requires_verification_ack(tmp_path):
    with make_client(tmp_path) as c:
        admin(c);aid,headers=agent(c);point="a"*32
        queued=queue(c,aid,"rollback",{"point_id":point,"scope":"windows_system"})
        c.get("/api/response/poll",headers=headers)
        result={"state":"pending_verification","detail":{"point_id":point,"scope":"windows_system","restart_scheduled":True,"verified":False}}
        assert c.post(f"/api/response/commands/{queued['id']}/result",headers=headers,json=result).status_code==200
        assert c.get(f"/api/response/agents/{aid}/commands").json()[0]["state"]=="pending_verification"
        verify=queue(c,aid,"verify_rollback",{"point_id":point,"scope":"windows_system"})
        c.get("/api/response/poll",headers=headers)
        result={"state":"succeeded","detail":{"point_id":point,"scope":"windows_system","verified":True,"windows_restore_status":1}}
        assert c.post(f"/api/response/commands/{verify['id']}/result",headers=headers,json=result).status_code==200
        rows=c.get(f"/api/response/agents/{aid}/commands").json()
        assert all(row["state"]=="succeeded" for row in rows)


def test_original_display_strips_navigation_and_network_resources():
    from app.replay_display import display_html
    source='<meta http-equiv="refresh" content="0;url=https://example.invalid"><script>evil()</script><iframe src="https://example.invalid"></iframe><img src="https://example.invalid/pixel"><a href="https://example.invalid" onclick="evil()">Order</a><input value="123">'
    shown=display_html(source)
    assert "example.invalid" not in shown and "evil" not in shown
    assert "Order" in shown and 'value="123"' in shown and 'disabled="disabled"' in shown


def test_response_actions_reach_the_case_timeline(tmp_path):
    with make_client(tmp_path) as c:
        admin(c)
        first,first_headers=agent(c,"alpha");other,_=agent(c,"beta")
        case=c.post("/api/cases",json={"title":"Endpoint containment","case_type":"Information Leakage"}).json()
        linked=c.post("/api/alerts",json={"title":"Suspicious process","score":80,"entity_type":"other","entity_ref":f"agent:{first}","case_id":case["id"]})
        assert linked.status_code==201,linked.text
        queued=c.post(f"/api/response/agents/{first}/commands",
                      json={"action":"process_list","arguments":{},"reason":"Containment test","case_id":case["id"]})
        assert queued.status_code==202,queued.text
        assert queued.json()["case_id"]==case["id"]
        command=c.get("/api/response/poll",headers=first_headers).json()["command"]
        assert command["id"]==queued.json()["id"]
        done=c.post(f"/api/response/commands/{queued.json()['id']}/result",
                    json={"state":"succeeded","detail":{"processes":[{"pid":44,"name":"x","create_time":12,"username":"u"}],"partial":False}},
                    headers=first_headers)
        assert done.status_code==200,done.text
        actions=c.get(f"/api/cases/{case['id']}").json()["response_actions"]
        recorded={row["action"] for row in actions}
        assert {"command_queued","command_dispatched","command_result"}<=recorded,recorded
        assert all(row["agent_id"]==first for row in actions)
        # The reason an operator gave must survive into the case record.
        assert any(row["detail"].get("reason")=="Containment test" for row in actions)

def test_case_link_rejects_unrelated_endpoint_and_missing_case(tmp_path):
    with make_client(tmp_path) as c:
        admin(c)
        first,_=agent(c,"alpha");other,_=agent(c,"beta")
        case=c.post("/api/cases",json={"title":"Scoped","case_type":"Information Leakage"}).json()
        assert c.post("/api/alerts",json={"title":"From alpha","score":70,"entity_type":"other",                                            "entity_ref":f"agent:{first}","case_id":case["id"]}).status_code==201
        # Beta has no alert in this case, so filing its containment here would be
        # evidence fabrication rather than record-keeping.
        hijack=c.post(f"/api/response/agents/{other}/commands",
                      json={"action":"process_list","arguments":{},"reason":"Unrelated","case_id":case["id"]})
        assert hijack.status_code==409,hijack.text
        absent=c.post(f"/api/response/agents/{other}/commands",
                      json={"action":"process_list","arguments":{},"reason":"No case","case_id":999999})
        assert absent.status_code==404,absent.text
        # An empty case cannot be used as a filing destination either.
        empty=c.post("/api/cases",json={"title":"Empty","case_type":"Information Leakage"}).json()
        blocked=c.post(f"/api/response/agents/{other}/commands",
                       json={"action":"process_list","arguments":{},"reason":"No alert","case_id":empty["id"]})
        assert blocked.status_code==409,blocked.text
        assert c.get(f"/api/cases/{case['id']}").json()["response_actions"]==[]


def test_enforcement_classification_is_internally_consistent():
    from app.enforcement import CAPABILITIES, automatable_actions
    keys=[entry["key"] for entry in CAPABILITIES]
    assert len(keys)==len(set(keys)),"duplicate capability key"
    for entry in CAPABILITIES:
        # Nothing may be automatable unless the agent can genuinely enforce it,
        # and nothing may be automatable while unimplemented.
        if entry["automatable"]:
            assert entry["implemented"],entry["key"]
            assert entry["agent_can_enforce"],entry["key"]
            assert entry["enforced_by"]=="agent",entry["key"]
        if entry["implemented"]:
            assert entry["enforced_by"]=="agent",entry["key"]
        # An agent that cannot enforce must say where enforcement really lives.
        if not entry["agent_can_enforce"]:
            assert entry["enforced_by"]!="agent",entry["key"]
            assert entry["note"],entry["key"]
    assert "account_lockout" not in automatable_actions()
    assert "control_input" not in automatable_actions()

def test_capabilities_endpoint_lists_real_and_unimplemented_controls(tmp_path):
    with make_client(tmp_path) as c:
        admin(c)
        payload=c.get("/api/response/capabilities").json()
        assert c.get("/api/response/capabilities").status_code==200
        table={entry["key"]:entry for entry in payload["capabilities"]}
        assert table["process_terminate"]["implemented"] is True
        assert table["account_lockout"]["implemented"] is False
        assert table["account_lockout"]["enforced_by"]=="identity_provider"
        assert table["usb_block"]["agent_can_observe"] is True
        assert table["usb_block"]["agent_can_enforce"] is False
        assert payload["automatable"]==sorted(payload["automatable"])
