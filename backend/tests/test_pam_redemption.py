"""Ticket redemption must revalidate authorization at use time."""
import hashlib
import json
from datetime import timedelta

import pytest

from app.iam_models import IdentityChallenge, PrivilegedRequest
from app.models import LoginSession, User, utcnow
from test_api import make_client


@pytest.mark.parametrize('invalidated', [
    'expired_ticket', 'expired_session', 'revoked_session', 'disabled_user',
    'expired_grant', 'revoked_grant', 'wrong_user', 'wrong_resource', 'wrong_key',
])
def test_ticket_rechecks_authorization(tmp_path, monkeypatch, invalidated):
    monkeypatch.setenv('ZANAQ_PAM_KEYS', json.dumps({'linux:ssh': 'k' * 40,
                                                  'linux:other': 'k' * 40}))
    with make_client(tmp_path) as client:
        token = 'A' * 43
        identifier = hashlib.sha256(token.encode()).hexdigest()
        with client.app.state.session_factory() as db:
            user = db.query(User).one()
            session = db.query(LoginSession).one()
            grant = PrivilegedRequest(user_id=user.id, resource='linux:ssh',
                reason='Disposable authentication verification', status='active',
                expires_at=utcnow() + timedelta(minutes=5),
                activated_session=session.token_hash)
            ticket = IdentityChallenge(id=identifier, user_id=user.id,
                purpose='pam:linux:ssh', digest=session.token_hash,
                expires_at=utcnow() + timedelta(seconds=60))
            db.add_all([grant, ticket])
            if invalidated == 'expired_ticket': ticket.expires_at = utcnow() - timedelta(seconds=1)
            if invalidated == 'expired_session': session.expires_at = utcnow() - timedelta(seconds=1)
            if invalidated == 'revoked_session': db.delete(session)
            if invalidated == 'disabled_user': user.disabled = True
            if invalidated == 'expired_grant': grant.expires_at = utcnow() - timedelta(seconds=1)
            if invalidated == 'revoked_grant': grant.status = 'revoked'
            db.commit()
        body = {'username': 'other' if invalidated == 'wrong_user' else 'investigator',
                'resource': 'linux:other' if invalidated == 'wrong_resource' else 'linux:ssh',
                'ticket': token}
        headers = {'X-PAM-Key': 'bad' if invalidated == 'wrong_key' else 'k' * 40}
        response = client.post('/api/iam/pam/redeem', json=body, headers=headers)
        assert response.status_code == (401 if invalidated == 'wrong_key' else 403), response.text
        with client.app.state.session_factory() as db:
            assert db.get(IdentityChallenge, identifier).used is False
