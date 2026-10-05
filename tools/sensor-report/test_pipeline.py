"""Verify the Go executable consumes the real Python sensor's report contract."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'backend'))
from network_sensor.pipeline import analyze_pcap

binary = str(Path(sys.argv[1]).resolve())
with (root / 'backend/network_sensor/example-http.pcap').open('rb') as capture:
    report = analyze_pcap(capture)
assert report['sessions'], 'Fixture must exercise a real session'
expected = {}
for session in report['sessions']:
    entry = expected.setdefault(session['protocol'] or 'unknown', {'sessions': 0, 'payload_bytes': 0})
    entry['sessions'] += 1
    entry['payload_bytes'] += session['payload_bytes']
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'sessions.json'
    path.write_text(json.dumps(report), encoding='utf-8')
    result = subprocess.run([binary, str(path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected, result.stdout
    path.write_text('{"metrics":{},"sessions":[]} trailing', encoding='utf-8')
    assert subprocess.run([binary, str(path)], capture_output=True, timeout=30).returncode == 1
    assert subprocess.run([binary], capture_output=True, timeout=30).returncode == 2
print('Python sensor to Go report contract and CLI failure checks passed')
