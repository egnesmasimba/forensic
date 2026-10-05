import json
from datetime import timedelta
import pytest
from app.models import utcnow, User, Fact, IndicatorDefinition, LibraryRule
from test_api import make_client


def admin(c):
    with c.app.state.session_factory() as db: db.query(User).first().role='administrator'; db.commit()


def agent(c,n='1'):
    r=c.post('/api/agents/register',json={'machine_id':'phase3-machine-'+n,'hostname':'Endpoint '+n,'os':'windows'}).json()
    return r['agent_id'],{'X-Agent-Token':r['agent_token']}


def metrics(f=1):
    return dict(key_count=50,mouse_count=50,duration_seconds=10,hold_mean_ms=100*f,hold_sd_ms=15*f,interval_mean_ms=150*f,interval_sd_ms=30*f,flight_mean_ms=50*f,mouse_speed_mean=300*f,mouse_turn_mean=.5*f)


def sample(c,h,f=1):
    r=c.post('/api/agents/events',json={'events':[{'type':'behavioral_biometrics','payload':metrics(f)}]},headers=h)
    assert r.status_code==200,r.text
    return r.json()


def test_catalog_and_live_retry_atomicity(tmp_path):
    with make_client(tmp_path) as c:
        catalog=c.get('/api/analytics/catalog').json()
        assert len(catalog['behavioral_measures'])==160 and len(catalog['insider_threat_rules'])==320
        with c.app.state.session_factory() as db:
            assert db.query(IndicatorDefinition).count()==170 and db.query(LibraryRule).count()==328
        now=utcnow().isoformat()
        data={'stream':'capture','events':[dict(event_id=str(i),entity_ref='subject',name='login_failure',occurred_at=now,text_value=str(i)) for i in range(3)]}
        r=c.post('/api/analytics/stream',json=data); assert r.status_code==201,r.text
        assert r.json()['alerts_created']>=1
        assert c.post('/api/analytics/stream',json=data).json()['duplicates']==3
        data['events'].insert(0,dict(event_id='new',entity_ref='subject',name='login_failure',occurred_at=now))
        data['events'][1]['numeric_value']=99
        assert c.post('/api/analytics/stream',json=data).status_code==409
        with c.app.state.session_factory() as db: assert db.query(Fact).filter_by(name='login_failure').count()==3
        rows=c.get('/api/analytics/indicators',params={'entity_ref':'subject'}).json()
        assert next(r for r in rows if r['key']=='bi_login_failure_day')['total']==3
        assert any(r['coverage']=='no observations' for r in rows)
        c.put('/api/profiles/library/it_login_failure_acute',json={'enabled':False,'threshold':77,'score':10})
        assert c.post('/api/profiles/library/update').json()['added']==0
        assert next(r for r in c.get('/api/profiles/library').json() if r['key']=='it_login_failure_acute')['threshold']==77


def test_biometric_consent_enrollment_and_takeover(tmp_path):
    with make_client(tmp_path) as c:
        admin(c); aid,h=agent(c)
        c.put(f'/api/biometrics/bindings/{aid}',json={'subject':'subject'})
        assert c.post('/api/agents/events',json={'events':[{'type':'behavioral_biometrics','payload':metrics()}]},headers=h).status_code==403
        c.post('/api/biometrics/agent/consent',json={'granted':True},headers=h)
        for _ in range(5): sample(c,h)
        ids=[r['id'] for r in c.get('/api/biometrics/samples').json()]
        data=dict(subject='subject',sample_ids=ids,trusted_identity_confirmed=False)
        assert c.post('/api/biometrics/enroll',json=data).status_code==422
        data['trusted_identity_confirmed']=True
        assert c.post('/api/biometrics/enroll',json=data).status_code==201
        sample(c,h); assert c.get('/api/biometrics/samples').json()[0]['status']=='consistent'
        assert sample(c,h,3)['alerts_created']==0
        assert sample(c,h,3)['alerts_created']==1
        assert any(r['title']=='Possible account takeover' for r in c.get('/api/alerts').json())
        c.post('/api/biometrics/agent/consent',json={'granted':False},headers=h)
        assert not c.post('/api/agents/heartbeat',json={},headers=h).json()['biometrics_permitted']
        assert c.post('/api/agents/events',json={'events':[{'type':'behavioral_biometrics','payload':metrics()}]},headers=h).status_code==403
        c.post('/api/biometrics/agent/consent',json={'granted':True},headers=h)
        assert c.post('/api/agents/events',json={'events':[{'type':'behavioral_biometrics','payload':{**metrics(),'characters':'secret'}}]},headers=h).status_code==422


def test_sharing_and_rebinding_revokes_consent(tmp_path):
    with make_client(tmp_path) as c:
        admin(c); first,h=agent(c); second,other=agent(c,'2')
        for aid,token in [(first,h),(second,other)]:
            c.put(f'/api/biometrics/bindings/{aid}',json={'subject':'shared-subject'})
            c.post('/api/biometrics/agent/consent',json={'granted':True},headers=token)
        for _ in range(5): sample(c,h)
        ids=[r['id'] for r in c.get('/api/biometrics/samples').json()]
        assert c.post('/api/biometrics/enroll',json={'subject':'shared-subject','sample_ids':ids,'trusted_identity_confirmed':True}).status_code==201
        sample(c,h); sample(c,other,3)
        assert any(r['title']=='Possible credential sharing' for r in c.get('/api/alerts').json())
        c.put(f'/api/biometrics/bindings/{second}',json={'subject':'different-subject'})
        assert not c.get('/api/biometrics/agent/status',headers=other).json()['permitted']


def test_local_capture_and_lease():
    from endpoint_agent.collectors.biometrics import BiometricCollector
    from endpoint_agent.biometric_capture import update_consent
    col=BiometricCollector(); assert not col._enabled
    update_consent(False); col.press('private-key',0); assert col.keys==0
    update_consent(True)
    for i in range(30): col.press('private-key',i*.2); col.release('private-key',i*.2+.08); col.move(500+i*10,200+i,i*.2)
    event=col.snapshot(10); assert event['payload']['key_count']==30
    assert event['payload']['hold_mean_ms']==pytest.approx(80)
    assert 'private-key' not in json.dumps(event) and not col.held and not col.last_mouse
    update_consent(False); col.press('private-key',20); assert col.keys==0


def test_synthetic_budget_and_cache(tmp_path):
    with make_client(tmp_path) as c:
        now=utcnow().isoformat(); subjects=['private-'+str(i) for i in range(6)]
        data={'stream':'aggregate','events':[dict(event_id=str(i),entity_ref=s,name='transfer',occurred_at=now) for i,s in enumerate(subjects)]}
        assert c.post('/api/analytics/stream',json=data).status_code==201
        assert c.post('/api/profiles/synthetic-aggregate',json={'subjects':[subjects[0]]*5}).status_code==422
        r=c.post('/api/profiles/synthetic-aggregate',json={'subjects':subjects[:5]}); assert r.status_code==200,r.text
        assert 'private-' not in r.text and 'token' not in r.json()
        assert c.post('/api/profiles/synthetic-aggregate',json={'subjects':subjects[:5]}).json()==r.json()
        assert c.post('/api/profiles/synthetic-aggregate',json={'subjects':subjects[1:]}).status_code==429


def test_sensor_delta_bridge():
    from network_sensor.analytic_stream import AnalyticSink
    class Client:
        def __init__(self):self.events=[]
        def post_events(self,rows):self.events.extend(rows);return True
    client=Client(); sink=AnalyticSink(client,'sensor')
    report={'sessions':[dict(id='session',packets=10,payload_bytes=500,protocol='http')]}
    assert sink.publish(report)==2 and sink.publish(report)==0
    report['sessions'][0]['packets']=12
    assert sink.publish(report)==1 and client.events[-1]['payload']['numeric_value']==2


def test_overlapping_keys_flight_and_expired_lease():
    from endpoint_agent.collectors.biometrics import BiometricCollector
    from endpoint_agent.biometric_capture import update_consent
    collector=BiometricCollector(); update_consent(True)
    collector.press('a',0); collector.press('b',.05); collector.release('a',.08); collector.release('b',.13)
    assert collector.snapshot(1)['payload']['flight_mean_ms']==pytest.approx(-30)
    update_consent(True,lease_seconds=0)
    collector.press('a',2); assert collector.keys==0


def test_endpoint_live_batch_evaluation(tmp_path):
    with make_client(tmp_path) as c:
        aid,h=agent(c)
        c.post('/api/analytics/rules',json={'name':'Endpoint live sum','version':1,'entity_type':'user','fact_name':'network_packets','aggregation':'sum','threshold':10})
        events=[{'type':'analytic_fact','event_key':str(i+1)*64,'payload':{'entity_ref':'sensor','name':'network_packets','numeric_value':6}} for i in range(2)]
        r=c.post('/api/agents/events',json={'events':events},headers=h)
        assert r.status_code==200 and r.json()['alerts_created']==1,r.text
        assert c.post('/api/agents/events',json={'events':events},headers=h).json()['duplicates']==2


def test_biometric_retention_invalidates_baseline(tmp_path):
    from app.analytic_models import BiometricProfile, BiometricSample
    from app.models import EndpointEvent
    with make_client(tmp_path) as c:
        admin(c); aid,h=agent(c)
        c.put(f'/api/biometrics/bindings/{aid}',json={'subject':'subject'})
        c.post('/api/biometrics/agent/consent',json={'granted':True},headers=h)
        for _ in range(5):sample(c,h)
        ids=[r['id'] for r in c.get('/api/biometrics/samples').json()]
        c.post('/api/biometrics/enroll',json={'subject':'subject','sample_ids':ids,'trusted_identity_confirmed':True})
        with c.app.state.session_factory() as db:
            old=utcnow()-timedelta(days=60)
            db.get(BiometricProfile,'subject').created_at=old
            for row in db.query(BiometricSample):row.received_at=old
            for row in db.query(EndpointEvent):row.received_at=old
            db.commit()
        result=c.post('/api/privacy/retention?dry_run=false').json()
        assert result['biometric_profiles']==1 and result['biometric_samples']==5
        with c.app.state.session_factory() as db:
            assert db.get(BiometricProfile,'subject') is None
            assert all(row.metrics=='{}' and row.status=='expired' for row in db.query(BiometricSample))


def test_repeated_same_key_flight_is_positive():
    from endpoint_agent.collectors.biometrics import BiometricCollector
    from endpoint_agent.biometric_capture import update_consent
    collector=BiometricCollector();update_consent(True)
    collector.press('a',0);collector.release('a',.08)
    collector.press('a',.2);collector.release('a',.28)
    assert collector.snapshot(1)['payload']['flight_mean_ms']==pytest.approx(120)
    update_consent(False)
