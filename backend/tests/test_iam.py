import base64
import hashlib
import json
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app.auth import hash_password
from app.iam import hotp
from app.iam_models import IdentityFactor, IdentityPolicy, IdentityAudit, PrivilegedRequest, IdentitySession
from app.models import User, LoginThrottle, Alert, utcnow
from test_api import make_client

PASSWORD='test-password-123'
SECRET=base64.b32encode(b'12345678901234567890').decode()


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv('ZANAQ_IAM_KEY',Fernet.generate_key().decode())


def reset_limit(client):
    with client.app.state.session_factory() as db:
        db.query(LoginThrottle).delete(); db.commit()


def enroll(client):
    result=client.post('/api/iam/factors/enroll',json={'password':PASSWORD,'kind':'hotp','hardware_secret':SECRET})
    assert result.status_code==200,result.text
    result=client.post('/api/iam/factors/confirm',json={'otp':hotp(SECRET,0)})
    assert result.status_code==200,result.text


def login(client, username='investigator', **extra):
    result=client.post('/api/auth/login',json={'username':username,'password':PASSWORD,**extra})
    if result.status_code==200: client.headers['X-CSRF-Token']=result.json()['csrf']
    return result


def add_admin(client):
    with client.app.state.session_factory() as db:
        row=User(username='admin',password_hash=hash_password(PASSWORD),role='administrator')
        db.add(row); db.commit(); return row.id


def test_rfc_hotp_vectors_and_totp():
    from app.iam import matched_counter
    assert [hotp(SECRET,n) for n in range(3)]==['755224','287082','359152']
    assert hotp(SECRET,59//30,8)=='94287082'
    assert matched_counter('hotp',SECRET,hotp(SECRET,1),0)==1
    assert matched_counter('hotp',SECRET,hotp(SECRET,0),0) is None


def test_factor_enrollment_login_replay_and_session_revocation(tmp_path):
    with make_client(tmp_path) as client:
        enroll(client)
        with client.app.state.session_factory() as db:
            factor=db.query(IdentityFactor).one()
            assert SECRET not in factor.secret and factor.counter==0
        assert login(client).status_code==401
        assert login(client,otp=hotp(SECRET,1)).status_code==200
        reset_limit(client)
        assert login(client,otp=hotp(SECRET,1)).status_code==401
        assert client.get('/api/iam/me').json()['mfa_verified'] is True
        sessions=client.get('/api/iam/sessions').json()
        assert client.delete('/api/iam/sessions/'+sessions[0]['id']).status_code==204
        assert client.get('/api/cases').status_code==401


def test_factor_attempts_are_rate_limited(tmp_path):
    with make_client(tmp_path) as client:
        enroll(client);reset_limit(client)
        for _ in range(5): assert login(client,otp='bad').status_code==401
        assert login(client,otp=hotp(SECRET,1)).status_code==429


def test_totp_confirmation_and_replay(tmp_path,monkeypatch):
    monkeypatch.setattr('app.iam.time.time',lambda:1700000000)
    with make_client(tmp_path) as client:
        response=client.post('/api/iam/factors/enroll',json={'password':PASSWORD,'kind':'totp'})
        assert response.status_code==200,response.text
        secret=response.json()['secret']; code=hotp(secret,1700000000//30)
        assert client.post('/api/iam/factors/confirm',json={'otp':code}).status_code==200
        assert login(client,otp=code).status_code==401
        monkeypatch.setattr('app.iam.time.time',lambda:1700000030)
        assert login(client,otp=hotp(secret,1700000030//30)).status_code==200


def test_sms_codes_are_delivered_hashed_bound_and_single_use(tmp_path,monkeypatch):
    sent=[]
    monkeypatch.setattr('app.iam.send_sms',lambda phone,code:sent.append((phone,code)))
    with make_client(tmp_path) as client:
        response=client.post('/api/iam/factors/enroll',json={'password':PASSWORD,'kind':'sms','phone':'+27123456789'})
        assert response.status_code==200,response.text
        challenge=response.json()['challenge_id']
        assert sent[0][1] not in response.text
        assert client.post('/api/iam/factors/confirm',json={'otp':sent[0][1],'challenge_id':challenge}).status_code==200
        reset_limit(client)
        response=client.post('/api/iam/factors/sms',json={'username':'investigator','password':PASSWORD})
        challenge=response.json()['challenge_id']
        assert login(client,otp=sent[-1][1],challenge_id=challenge).status_code==200
        assert login(client,otp=sent[-1][1],challenge_id=challenge).status_code==401


def test_shared_identity_attribution_and_module_isolation(tmp_path):
    with make_client(tmp_path) as client:
        enroll(client)
        with client.app.state.session_factory() as db:
            individual=db.query(User).filter_by(username='investigator').one()
            shared=User(username='shared',password_hash=hash_password(PASSWORD),role='investigator')
            db.add(shared); db.flush()
            shared_id=shared.id
            db.add(IdentityPolicy(user_id=shared.id,shared=True,members=json.dumps([individual.id]),modules='["network"]'))
            db.commit()
        reset_limit(client)
        assert login(client,'shared').status_code==401
        response=login(client,'shared',personal_username='investigator',personal_password=PASSWORD,otp=hotp(SECRET,1))
        assert response.status_code==200,response.text
        assert response.json()['username']=='investigator'
        assert client.get('/api/iam/me').json()['shared_account']==shared_id
        assert client.get('/api/network/captures').status_code==200
        assert client.get('/api/cases').status_code==403
        assert client.get('/api/reports/cases.csv').status_code==403
        assert client.get('/api/search?q=secret').status_code==403
        with client.app.state.session_factory() as db:
            db.get(IdentityPolicy,shared_id).members='[]';db.commit()
        assert client.get('/api/network/captures').status_code==401


def test_overlapping_terminal_alert_and_recording(tmp_path):
    with make_client(tmp_path) as first:
        with TestClient(first.app) as second:
            second.headers['User-Agent']='Different terminal'
            assert login(second).status_code==200
            with first.app.state.session_factory() as db:
                assert db.query(Alert).filter_by(channel='identity').count()==1
                assert db.query(IdentityAudit).filter_by(action='different_terminal').count()==1


def test_privileged_approval_activation_pam_and_revoke(tmp_path,monkeypatch):
    monkeypatch.setenv('ZANAQ_PAM_KEYS',json.dumps({'linux:ssh':'k'*40}))
    with make_client(tmp_path) as client:
        enroll(client);admin_id=add_admin(client)
        request=client.post('/api/iam/privileged/requests',json={'resource':'linux:ssh','reason':'Investigate approved incident'})
        assert request.status_code==201,request.text
        identifier=request.json()['id']
        assert client.post(f'/api/iam/privileged/requests/{identifier}/decision',json={'approve':True}).status_code==403
        with TestClient(client.app) as admin_client:
            assert login(admin_client,'admin').status_code==200
            assert admin_client.post(f'/api/iam/privileged/requests/{identifier}/decision',json={'approve':True}).status_code==200
            assert admin_client.post(f'/api/iam/privileged/requests/{identifier}/decision',json={'approve':True}).status_code==409
            reset_limit(client)
            assert client.post(f'/api/iam/privileged/requests/{identifier}/activate',json={'password':PASSWORD,'otp':hotp(SECRET,1)}).status_code==200
            assert client.get('/api/iam/pam/authorize?resource=other').status_code==403
            ticket=client.post('/api/iam/pam/ticket?resource=linux:ssh').json()['ticket']
            body={'username':'investigator','resource':'linux:ssh','ticket':ticket}
            assert client.post('/api/iam/pam/redeem',json=body).status_code==401
            assert client.post('/api/iam/pam/redeem',json=body,headers={'X-PAM-Key':'k'*40}).status_code==200
            assert client.post('/api/iam/pam/redeem',json=body,headers={'X-PAM-Key':'k'*40}).status_code==403
            session=client.get('/api/iam/sessions').json()[0]['id']
            assert admin_client.get(f'/api/iam/recordings/{session}').json()
            assert admin_client.delete(f'/api/iam/privileged/requests/{identifier}').status_code==204
            assert client.get('/api/iam/pam/authorize?resource=linux:ssh').status_code==403


def test_ad_sync_mapping_authentication_and_removal(tmp_path,monkeypatch):
    monkeypatch.setenv('ZANAQ_AD_GROUP_MAP',json.dumps({'CN=Analysts,DC=test':{'role':'viewer','modules':['network']}}))
    entries=[{'dn':'CN=Person,DC=test','attributes':{'sAMAccountName':'Person','memberOf':['CN=Analysts,DC=test'],'userAccountControl':512}}]
    monkeypatch.setattr('app.iam_directory.directory_entries',lambda:entries)
    monkeypatch.setattr('app.iam_directory.authenticate',lambda dn,password:dn=='CN=Person,DC=test' and password==PASSWORD)
    with make_client(tmp_path) as client:
        with client.app.state.session_factory() as db:
            db.query(User).first().role='administrator';db.commit()
        response=client.post('/api/iam/directory/sync')
        assert response.status_code==200,response.text
        with TestClient(client.app) as ad:
            assert login(ad,'person').status_code==200
            assert ad.get('/api/network/captures').status_code==200
            assert ad.get('/api/cases').status_code==403
            entries.clear()
            assert client.post('/api/iam/directory/sync').status_code==200
            assert ad.get('/api/network/captures').status_code==401


def test_missing_key_and_sms_provider_fail_closed(tmp_path,monkeypatch):
    with make_client(tmp_path) as client:
        monkeypatch.delenv('ZANAQ_IAM_KEY')
        assert client.post('/api/iam/factors/enroll',json={'password':PASSWORD}).status_code==503
        monkeypatch.setenv('ZANAQ_IAM_KEY',Fernet.generate_key().decode())
        monkeypatch.delenv('TWILIO_ACCOUNT_SID',raising=False)
        assert client.post('/api/iam/factors/enroll',json={'password':PASSWORD,'kind':'sms','phone':'+27123456789'}).status_code==503


def test_role_changes_and_login_hours(tmp_path):
    with make_client(tmp_path) as client:
        admin_id=add_admin(client)
        with TestClient(client.app) as admin_client:
            assert login(admin_client,'admin').status_code==200
            with client.app.state.session_factory() as db:
                uid=db.query(User).filter_by(username='investigator').one().id
            assert admin_client.put(f'/api/iam/accounts/{admin_id}/role',json={'role':'viewer'}).status_code==403
            assert admin_client.put(f'/api/iam/accounts/{uid}/role',json={'role':'viewer'}).status_code==200
            assert client.get('/api/cases').status_code==401
            start=(utcnow().hour+1)%24;end=(start+1)%24
            assert admin_client.put(f'/api/iam/accounts/{uid}/login-hours',json={'start_hour_utc':start,'end_hour_utc':end}).status_code==200
            assert login(client).json()['role']=='viewer'
            with client.app.state.session_factory() as db:
                assert db.query(Alert).filter_by(title='Outside approved login hours').count()==1


def test_privileged_recording_consent_and_revocation(tmp_path):
    from test_replay_response import agent
    from app.privacy import setting
    from app.response_models import ReplaySession,ResponseCommand
    with make_client(tmp_path) as client:
        enroll(client);add_admin(client)
        aid,headers=agent(client)
        identifier=client.post('/api/iam/privileged/requests',json={'resource':f'agent:{aid}','reason':'Record approved investigation'}).json()['id']
        with TestClient(client.app) as admin_client:
            assert login(admin_client,'admin').status_code==200
            assert admin_client.post(f'/api/iam/privileged/requests/{identifier}/decision',json={'approve':True}).status_code==200
            reset_limit(client)
            assert client.post(f'/api/iam/privileged/requests/{identifier}/activate',json={'password':PASSWORD,'otp':hotp(SECRET,1)}).status_code==200
            with client.app.state.session_factory() as db:
                setting(db).consent_required=True;setting(db).purpose='Approved investigation';db.commit()
            assert admin_client.post(f'/api/iam/privileged/requests/{identifier}/record').status_code==403
            consent=client.post('/api/privacy/agent/consent',headers=headers,json={'granted':True,'purpose':'Approved investigation'})
            assert consent.status_code==201,consent.text
            result=admin_client.post(f'/api/iam/privileged/requests/{identifier}/record')
            assert result.status_code==202,result.text
            replay_id=result.json()['replay_id']
            with client.app.state.session_factory() as db:
                db.get(ReplaySession,replay_id).status='active';db.commit()
            frame={'sequence':0,'occurred_at':utcnow().isoformat(),'text':'Approved frame'}
            assert client.post(f'/api/replay/agent/sessions/{replay_id}/frames',json=frame,headers=headers).status_code==201
            assert client.post('/api/privacy/agent/consent',headers=headers,json={'granted':False,'purpose':'Approved investigation'}).status_code==201
            frame['sequence']=1
            assert client.post(f'/api/replay/agent/sessions/{replay_id}/frames',json=frame,headers=headers).status_code==403
            assert client.post('/api/privacy/agent/consent',headers=headers,json={'granted':True,'purpose':'Approved investigation'}).status_code==201
            with client.app.state.session_factory() as db:
                identity=db.query(IdentitySession).filter_by(user_id=1).first()
                shared=User(username='revoked-shared',password_hash=hash_password(PASSWORD),role='viewer')
                db.add(shared);db.flush()
                db.add(IdentityPolicy(user_id=shared.id,shared=True,members='[]'))
                identity.shared_user_id=shared.id;db.commit()
            assert client.post(f'/api/replay/agent/sessions/{replay_id}/frames',json=frame,headers=headers).status_code==403
            with client.app.state.session_factory() as db:
                db.query(IdentitySession).filter_by(user_id=1).first().shared_user_id=None;db.commit()
            assert client.delete(f'/api/iam/privileged/requests/{identifier}').status_code==204
            frame['sequence']=1
            assert client.post(f'/api/replay/agent/sessions/{replay_id}/frames',json=frame,headers=headers).status_code==403
            with client.app.state.session_factory() as db:
                assert db.query(ResponseCommand).filter_by(action='live_stop').count()==1


def test_expired_privileged_grant_rejects_activation(tmp_path):
    with make_client(tmp_path) as client:
        enroll(client)
        with client.app.state.session_factory() as db:
            uid=db.query(User).one().id
            row=PrivilegedRequest(user_id=uid,resource='host:ssh',reason='Expired request',status='approved',expires_at=utcnow()-timedelta(seconds=1))
            db.add(row);db.commit();identifier=row.id
        assert client.post(f'/api/iam/privileged/requests/{identifier}/activate',json={'password':PASSWORD,'otp':hotp(SECRET,1)}).status_code==403
