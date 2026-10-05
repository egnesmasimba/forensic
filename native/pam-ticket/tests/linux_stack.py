"""Exercise real PAM without changing /etc/pam.d or authenticating host users.

The downstream executable is a test double; backend redemption is not certified.
Run as root in a disposable Linux CI runner (pam_exec preserves the caller UID).
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
if os.name != 'posix' or os.geteuid() != 0:
    raise SystemExit('Run on a disposable Linux runner as root')
with tempfile.TemporaryDirectory(prefix='forensic-pam-') as temporary:
    directory = Path(temporary)
    module = directory / 'collector.so'
    harness = directory / 'stack-test'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC',
                    '-shared', str(root / 'native/pam-ticket/pam_forensic_ticket.c'),
                    '-lpam', '-o', str(module)], check=True)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(Path(__file__).with_suffix('.c')), '-lpam', '-o', str(harness)],
                   check=True)
    bridge = directory / 'handoff.py'
    bridge.write_text(
        '#!/usr/bin/python3\nimport os, sys\n'
        'ticket = sys.stdin.buffer.read(128).rstrip(b"\\0")\n'
        'ok = (os.environ.get("PAM_TYPE") == "auth" and '
        'os.environ.get("PAM_USER") == "test-user" and '
        'ticket == b"01234567890123456789")\n'
        'sys.exit(0 if ok else 1)\n', encoding='utf-8')
    bridge.chmod(0o700)
    (directory / 'forensic-test').write_text(
        f'auth [ignore=ignore default=die] {module}\n'
        f'auth required pam_exec.so expose_authtok {bridge}\n', encoding='utf-8')
    subprocess.run([str(harness), str(directory)], check=True, timeout=30)
