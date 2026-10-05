"""Consent lease for local input collection. Offline collection stops after the lease."""
import time
_deadline = 0.0


def update_consent(allowed, lease_seconds=15):
    global _deadline
    _deadline = time.monotonic() + min(max(lease_seconds, 0), 30) if allowed else 0.0


def permitted():
    return time.monotonic() < _deadline
