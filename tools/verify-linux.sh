#!/usr/bin/env bash
# Run from a disposable Linux checkout with PAM headers and backend dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pytest backend/tests/test_iam.py backend/tests/test_pam_redemption.py -q
sudo python3 native/pam-ticket/tests/linux_stack.py
sudo env FORENSIC_LINUX_PAM_TEST=1 "$(command -v python3)" -m pytest backend/tests/test_pam_linux_live.py -q --basetemp=/tmp/forensic-live-pam-verification
(
  cd tools/sensor-report
  go vet ./...
  go test ./...
  go build .
)
python3 tools/sensor-report/test_pipeline.py tools/sensor-report/sensor-report
(
  cd tools/sensor
  go vet ./...
  go test ./...
  go build .
)
