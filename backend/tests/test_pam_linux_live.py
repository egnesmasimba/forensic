"""Real Linux PAM -> pam_exec -> Python bridge -> HTTPS -> backend.

Opt in on a disposable root Linux runner; never modifies /etc/pam.d.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from datetime import timedelta

import pytest
import uvicorn

from app.iam_models import IdentityChallenge, PrivilegedRequest
from app.models import LoginSession, User, utcnow
from app.transport_security import generate_certificate
from test_api import make_client


@pytest.mark.skipif(os.environ.get('FORENSIC_LINUX_PAM_TEST') != '1',
                    reason='Requires opt-in disposable root Linux environment')
def test_live_linux_authentication(tmp_path, monkeypatch):
    assert sys.platform.startswith('linux') and os.geteuid() == 0
    root = Path(__file__).resolve().parents[2]
    module = tmp_path / 'collector.so'
    harness = tmp_path / 'stack-test'
    for args in [
        ['-fPIC', '-shared', str(root / 'native/pam-ticket/pam_forensic_ticket.c'), '-o', str(module)],
        [str(root / 'native/pam-ticket/tests/linux_stack.c'), '-o', str(harness)],
    ]:
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', *args, '-lpam'], check=True)
    monkeypatch.setenv('ZANAQ_PAM_KEYS', json.dumps({'linux:ssh': 'k' * 40}))
    with make_client(tmp_path) as client:
        material = generate_certificate(tmp_path / 'tls', ['127.0.0.1'], days=1)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(client.app, log_level='error',
            ssl_certfile=material['server'], ssl_keyfile=material['server']))
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 15
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert server.started
            config = tmp_path / 'bridge.json'
            config.write_text(json.dumps({'server': f'https://127.0.0.1:{port}',
                'resource': 'linux:ssh', 'service_key': 'k' * 40,
                'ca_bundle': material['ca']}))
            config.chmod(0o600)
            (tmp_path / 'forensic-test').write_text(
                f'auth [ignore=ignore default=die] {module}\n'
                f'auth required pam_exec.so expose_authtok {sys.executable} '
                f'{root / "backend/pam_bridge.py"} --config {config}\n')
            def issue(expired=False):
                import secrets
                token = secrets.token_urlsafe(32)
                with client.app.state.session_factory() as db:
                    user = db.query(User).one()
                    session = db.query(LoginSession).one()
                    if not db.query(PrivilegedRequest).first():
                        db.add(PrivilegedRequest(user_id=user.id, resource='linux:ssh',
                            reason='Disposable Linux integration test', status='active',
                            expires_at=utcnow() + timedelta(minutes=5),
                            activated_session=session.token_hash))
                    db.add(IdentityChallenge(id=hashlib.sha256(token.encode()).hexdigest(),
                        user_id=user.id, purpose='pam:linux:ssh', digest=session.token_hash,
                        expires_at=utcnow() + timedelta(seconds=-1 if expired else 60)))
                    db.commit()
                return token
            def authenticate(token, username='investigator'):
                result = subprocess.run([str(harness), str(tmp_path), username],
                    input=token + '\n', text=True, capture_output=True, timeout=20)
                assert result.returncode in (0, 1), result.stderr
                return result.returncode
            token = issue()
            assert authenticate(token) == 0
            assert authenticate(token) == 1  # Single use through the complete stack.
            assert authenticate(issue(expired=True)) == 1
            assert authenticate(issue(), 'other-user') == 1
            token = issue()
            settings = json.loads(config.read_text())
            untrusted = dict(settings)
            untrusted.pop('ca_bundle')
            config.write_text(json.dumps(untrusted))
            assert authenticate(token) == 1  # A private CA must be explicitly trusted.
            config.write_text(json.dumps(settings))
            config.chmod(0o644)
            assert authenticate(token) == 1  # Reject readable service secrets.
            config.chmod(0o600)
            assert authenticate(token) == 0  # Failed transport/config checks did not consume it.
            token = issue()
            with client.app.state.session_factory() as db:
                db.query(PrivilegedRequest).one().status = 'revoked'
                db.commit()
            assert authenticate(token) == 1
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            listener.close()
            assert not thread.is_alive()
