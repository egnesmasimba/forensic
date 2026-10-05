from datetime import timedelta
import base64
import io
import json
import pytest
from PIL import Image
from test_api import make_client
from app.models import User, EndpointEvent, utcnow
from app.privacy import setting, masked_image, pseudonym
from app.privacy_models import PolicyWarning, EducationAudit
from app.response_models import ReplaySession, ReplayFrame


def admin(client):
    with client.app.state.session_factory() as db:
        db.query(User).filter_by(username='investigator').first().role = 'administrator'; db.commit()


def register(client, suffix='1'):
    result = client.post('/api/agents/register', json={'machine_id':'machine-'+suffix, 'hostname':'Private Name '+suffix, 'os':'windows'})
    assert result.status_code == 201, result.text
    data = result.json()
    return data['agent_id'] if 'agent_id' in data else data['id'], {'X-Agent-Token':data['agent_token'] if 'agent_token' in data else data['token']}


def configure(client, **changes):
    data = {'enabled':True, 'purpose':'Investigate threats', 'legal_basis':'consent', **changes}
    response = client.put('/api/privacy/settings', json=data)
    assert response.status_code == 200, response.text


def test_privacy_boundary_and_pseudonyms(tmp_path):
    with make_client(tmp_path) as client:
        admin(client); agent, headers = register(client)
        configure(client)
        assert client.get('/api/cases').status_code == 403
        assert client.get('/api/search?q=private').status_code == 403
        assert client.get('/api/network/captures/1/download').status_code == 403
        assert client.get('/api/cases', headers={'X-Privacy-Raw':'1'}).status_code == 200
        with client.app.state.session_factory() as db:
            db.add(EndpointEvent(agent_id=agent, type='window', severity='high', payload=json.dumps({'user':'Secret User','email':'person@example.com'}))); db.commit()
        response = client.get('/api/privacy/dashboard')
        assert response.headers['cache-control'] == 'no-store'
        assert 'Secret' not in response.text and 'Private Name' not in response.text and 'person@example.com' not in response.text
        assert response.json()['aggregates'] == []
        alias = response.json()['subjects'][0]['subject']
        assert alias.startswith('subject-') and client.get('/api/privacy/dashboard').json()['subjects'][0]['subject'] == alias
        with client.app.state.session_factory() as db:
            db.query(User).first().role='viewer'; db.commit()
        assert client.get('/api/cases', headers={'X-Privacy-Raw':'1'}).status_code == 403
        assert client.put('/api/privacy/settings', json={}).status_code == 403
        assert client.get('/api/privacy/settings').status_code == 403


def test_consent_withdrawal_and_council_expiry(tmp_path):
    with make_client(tmp_path) as client:
        admin(client); agent, headers = register(client)
        configure(client)
        event = {'events':[{'type':'screenshot','payload':{'image_b64':''}}]}
        assert client.post('/api/agents/events', json=event, headers=headers).status_code == 403
        assert client.post('/api/privacy/agent/consent', json={'granted':True,'purpose':'Investigate threats'}, headers=headers).status_code == 201
        assert client.post('/api/agents/events', json=event, headers=headers).status_code == 200
        client.post('/api/privacy/agent/consent', json={'granted':False,'purpose':'Investigate threats'}, headers=headers)
        assert client.post('/api/agents/events', json=event, headers=headers).status_code == 403
        assert client.put('/api/privacy/settings', json={'enabled':True,'purpose':'test','legal_basis':'consent','council_required':True}).status_code == 422
        client.post('/api/privacy/agent/consent', json={'granted':True,'purpose':'Investigate threats'}, headers=headers)
        configure(client, council_required=True,council_reference='Agreement-1',council_expires_at=(utcnow()+timedelta(days=1)).isoformat())
        with client.app.state.session_factory() as db:
            setting(db).council_expires_at=utcnow()-timedelta(days=1); db.commit()
        assert client.post('/api/agents/events', json=event, headers=headers).status_code == 403


def test_masked_screenshots_and_recordings(tmp_path):
    with make_client(tmp_path) as client:
        admin(client); agent, headers=register(client)
        out=io.BytesIO(); Image.new('RGB',(12,12),'white').save(out,format='JPEG'); raw=out.getvalue()
        with client.app.state.session_factory() as db:
            event=EndpointEvent(agent_id=agent,type='screenshot',payload=json.dumps({'image_b64':base64.b64encode(raw).decode()})); db.add(event)
            session=ReplaySession(title='Secret person',platform='desktop',created_by='investigator'); db.add(session); db.flush()
            frame=ReplayFrame(session_id=session.id, sequence=0, occurred_at=utcnow(), text='person@example.com', fields='{"name":"Secret"}', image=raw); db.add(frame); db.commit(); event_id=event.id; session_id=session.id
        configure(client)
        image=client.get(f'/api/privacy/screenshots/{event_id}').json()['image_base64']
        with Image.open(io.BytesIO(base64.b64decode(image))) as parsed: assert parsed.getpixel((5,5)) == (0,0,0)
        frames=client.get(f'/api/privacy/recordings/{session_id}/frames')
        assert 'person@example.com' not in frames.text and 'Secret' not in frames.text
        assert client.get(f'/api/replay/sessions/{session_id}/frames').status_code == 403


def test_retention_preview_and_linked_preservation(tmp_path):
    from app.models import Case
    from app.search_models import SearchDocument
    with make_client(tmp_path) as client:
        admin(client); agent, headers=register(client)
        with client.app.state.session_factory() as db:
            old=utcnow()-timedelta(days=60)
            case=Case(title='Protected',case_type='Other'); db.add(case); db.flush()
            rows=[EndpointEvent(agent_id=agent,type='window',payload='{"screen_text":"expire-secret"}', received_at=old), EndpointEvent(agent_id=agent,type='window',payload='{"screen_text":"protected-secret"}',received_at=old,case_id=case.id)]
            db.add_all(rows); db.commit(); ids=[row.id for row in rows]
        preview=client.post('/api/privacy/retention').json(); assert preview['events'] == 1
        with client.app.state.session_factory() as db: assert 'expire-secret' in db.get(EndpointEvent,ids[0]).payload
        assert client.post('/api/privacy/retention?dry_run=false').json()['events'] == 1
        with client.app.state.session_factory() as db:
            assert 'expire-secret' not in db.get(EndpointEvent,ids[0]).payload
            assert 'protected-secret' in db.get(EndpointEvent,ids[1]).payload
            assert not any('expire-secret' in doc.body for doc in db.query(SearchDocument))
        assert client.post('/api/privacy/retention?dry_run=false').json()['events'] == 0


def test_warnings_delivery_ack_escalation_and_audit(tmp_path):
    from app.education import create_warning
    with make_client(tmp_path) as client:
        admin(client); agent, headers=register(client); other, other_headers=register(client,'2')
        saved=client.put('/api/education/policy',json={'manager':'investigator','escalation_count':1,'training_url':'https://training.example.test/course'})
        assert saved.status_code == 200, saved.text
        for index in range(2):
            response=client.post('/api/agents/events',json={'events':[{'type':'clipboard_change','payload':{'text':'confidential customer list ' * 500}, 'event_key':str(index+1)*64}]},headers=headers)
            assert response.status_code == 200, response.text
            assert response.json()['alerts_created'] == 1
        duplicate = client.post('/api/agents/events',json={'events':[{'type':'clipboard_change','payload':{'text':'confidential customer list ' * 500}, 'event_key':'2'*64}]},headers=headers)
        assert duplicate.json()['duplicates'] == 1 and duplicate.json()['alerts_created'] == 0
        with client.app.state.session_factory() as db:
            generated = db.query(PolicyWarning).order_by(PolicyWarning.id).all()
            assert len(generated) == 2 and generated[1].level == 2
        # A deliberate reminder is independent of finding rules.
        notice=client.post(f'/api/education/reminders/{agent}').json(); wid=notice['id']
        offered=client.get('/api/education/agent/warnings',headers=headers).json()['warnings']
        assert any(w['id']==wid for w in offered)
        assert not client.get('/api/education/agent/warnings',headers=headers).json()['warnings']
        assert client.post(f'/api/education/agent/warnings/{wid}/receipt',json={'action':'acknowledged'},headers=other_headers).status_code == 404
        assert client.post(f'/api/education/agent/warnings/{wid}/receipt',json={'action':'acknowledged'},headers=headers).json()['state']=='acknowledged'
        assert client.post(f'/api/education/agent/warnings/{wid}/receipt',json={'action':'training_completed'},headers=headers).json()['training_state']=='completed'
        with client.app.state.session_factory() as db:
            row=db.get(PolicyWarning,wid); row.state='delivered'; row.deliveries=2; row.next_delivery_at=utcnow()-timedelta(minutes=1); db.commit()
        client.get('/api/education/agent/warnings',headers=headers)
        assert client.get('/api/education/inbox').json()
        actions=[row['action'] for row in client.get('/api/education/audit').json()]
        assert 'unacknowledged_escalation' in actions and 'training_self_reported' in actions and 'manager_notified' in actions
        assert client.put('/api/education/policy',json={'training_url':'javascript:alert(1)'}).status_code == 422


def test_notifier_ack_only_on_successful_user_action():
    from endpoint_agent.education import EducationNotifier
    class Client:
        calls=[]
        def response_request(self, method, path, payload=None):
            self.calls.append((path,payload))
            if path.endswith('/notice'): return {'enabled':False}
            if path.endswith('/warnings'): return {'warnings':[{'id':1,'title':'Policy','message':'Review'}]}
            return {}
    client=Client(); EducationNotifier(client,show=lambda w:False).process()
    assert any(p and p['action']=='displayed' for _,p in client.calls)
    assert not any(p and p['action']=='acknowledged' for _,p in client.calls)
    client.calls=[]
    def fail(w): raise RuntimeError('No desktop')
    EducationNotifier(client,show=fail).process()
    assert not any(p for _,p in client.calls)

def test_training_provider_auth_and_no_downgrade(tmp_path, monkeypatch):
    with make_client(tmp_path) as client:
        admin(client); agent, headers=register(client)
        client.put('/api/education/policy',json={'training_url':'https://training.example.test/course'})
        warning=client.post(f'/api/education/reminders/{agent}').json()
        wid=warning['id']
        path=f'/api/education/training/{wid}/complete'
        assert client.post(path,json={'reference':'course-1'}).status_code == 401
        monkeypatch.setenv('ZANAQ_TRAINING_WEBHOOK_TOKEN', 'a'*32)
        assert client.post(path,json={'reference':'course-1'},headers={'Authorization':'Bearer bad'}).status_code == 401
        for _ in range(2):
            assert client.post(path,json={'reference':'course-1'},headers={'Authorization':'Bearer '+'a'*32}).status_code == 200
        completed=client.post(f'/api/education/agent/warnings/{wid}/receipt',json={'action':'training_completed'},headers=headers)
        assert completed.json()['training_state'] == 'verified'
        with client.app.state.session_factory() as db:
            assert db.query(EducationAudit).filter_by(warning_id=wid,action='training_verified').count() == 1


def test_recording_retention_removes_search_and_pixels(tmp_path):
    from app.search_models import SearchDocument, SearchOutbox
    with make_client(tmp_path) as client:
        admin(client)
        sid=client.post('/api/replay/sessions',json={'title':'Review','platform':'desktop'}).json()['id']
        frame=client.post(f'/api/replay/sessions/{sid}/frames',json={'sequence':0,'occurred_at':(utcnow()-timedelta(days=60)).isoformat(),'text':'Secret replay value','fields':{'name':'Private Name'}})
        assert frame.status_code == 201, frame.text
        doc_id=frame.json()['document_id']
        assert doc_id
        assert client.post('/api/privacy/retention?dry_run=false').json()['frames']==1
        with client.app.state.session_factory() as db:
            assert db.get(SearchDocument,doc_id) is None
            row=db.query(ReplayFrame).first()
            assert row.text=='[retention expired]' and row.fields=='{}' and row.document_id is None
            assert db.get(SearchOutbox,f'replay:{row.id}').payload is None


def test_purpose_change_and_expired_consent(tmp_path):
    from app.privacy_models import PrivacyConsent
    with make_client(tmp_path) as client:
        admin(client); agent, headers=register(client); configure(client)
        client.post('/api/privacy/agent/consent',json={'granted':True,'purpose':'Investigate threats'},headers=headers)
        with client.app.state.session_factory() as db:
            db.query(PrivacyConsent).first().expires_at=utcnow()-timedelta(days=1); db.commit()
        assert client.post('/api/agents/events',json={'events':[{'type':'screenshot'}]},headers=headers).status_code==403
        configure(client,purpose='New purpose')
        assert client.post('/api/privacy/agent/consent',json={'granted':True,'purpose':'Investigate threats'},headers=headers).status_code==409
        assert client.post(f'/api/agents/{agent}/screenshot-command',headers={'X-Privacy-Raw':'1'}).status_code==403
