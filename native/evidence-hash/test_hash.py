"""Cross-check compiled C++ hashing against Python hashlib, including failure exits."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as root:
    path = Path(root) / 'evidence.bin'
    for data in (b'', b'abc', bytes(range(256)) * 1000):
        path.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        result = subprocess.run([binary, str(path), expected.upper()], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected
        assert subprocess.run([binary, str(path), '0' * 64], capture_output=True).returncode == 1
    assert subprocess.run([binary, str(path), 'invalid'], capture_output=True).returncode == 2
    assert subprocess.run([binary, str(path.with_name('missing'))], capture_output=True).returncode == 1
print('Evidence hashing checks passed')
