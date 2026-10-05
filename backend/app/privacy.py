"""Privacy projections, conservative media masking, and scoped retention."""
import base64
import hashlib
import hmac
import io
import json
import re
import secrets
from datetime import timedelta, timezone
from fastapi import HTTPException
from app.models import EndpointEvent, utcnow
from app.privacy_models import PrivacySetting, PrivacyConsent, PrivacyAudit


def setting(db):
    row = db.get(PrivacySetting, 1)
    if row is None:
        row = PrivacySetting(id=1, secret=secrets.token_hex(32))
        db.add(row); db.flush()
    return row


def audit(db, actor, action, **detail):
    db.add(PrivacyAudit(actor=actor, action=action, detail=json.dumps(detail)))


def pseudonym(settings, value):
    return 'subject-' + hmac.new(bytes.fromhex(settings.secret), str(value).encode(), hashlib.sha256).hexdigest()[:24]


def mask_text(value):
    # Deliberately conservative: text redaction is a helper, not an anonymity guarantee.
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[email]', str(value))
    text = re.sub(r'(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)', '[number]', text)
    return text


def masked_image(data):
    # OCR can miss names and small text. Cover every pixel for the restricted view.
    from PIL import Image
    with Image.open(io.BytesIO(data)) as image:
        if image.width > 4096 or image.height > 2160:
            raise ValueError('Image exceeds privacy mask bounds')
        image = Image.new('RGB', image.size, 'black')
        out = io.BytesIO(); image.save(out, format='JPEG')
        return base64.b64encode(out.getvalue()).decode()


def capture_allowed(db, agent_id):
    settings = setting(db)
    if not settings.enabled:
        return
    now = utcnow()
    if settings.council_required and (not settings.council_reference or not settings.council_expires_at or settings.council_expires_at.replace(tzinfo=timezone.utc) <= now):
        raise HTTPException(403, 'Current works council approval is required for visual capture')
    if settings.consent_required:
        consent = db.query(PrivacyConsent).filter_by(agent_id=agent_id).order_by(PrivacyConsent.id.desc()).first()
        if not consent or not consent.granted or consent.purpose != settings.purpose or consent.expires_at.replace(tzinfo=timezone.utc) <= now:
            raise HTTPException(403, 'Current endpoint consent is required for visual capture')


def retention(db, actor='retention', dry_run=True):
    from app.response_models import ReplayFrame, ReplaySession
    from app.search_models import SearchDocument
    from app.mail_models import MailEvidence
    from app.privacy_models import PolicyWarning
    settings = setting(db)
    cutoff = utcnow() - timedelta(days=settings.retention_days)
    events = db.query(EndpointEvent).filter(EndpointEvent.received_at < cutoff, EndpointEvent.case_id.is_(None), EndpointEvent.alert_id.is_(None), EndpointEvent.payload != '{"privacy_retained": true}').limit(1000).all()
    # Mail and warnings can still depend on event evidence. Preserve those records.
    events = [row for row in events if not db.query(MailEvidence.id).filter_by(event_id=row.id).first() and not db.query(PolicyWarning.id).filter_by(event_id=row.id).first()]
    frames = db.query(ReplayFrame).join(ReplaySession).filter(ReplayFrame.occurred_at < cutoff, ReplaySession.mode == 'recorded', ReplayFrame.text != '[retention expired]').limit(1000).all()
    from app.analytic_models import BiometricSample, BiometricProfile
    biometric_samples = db.query(BiometricSample).join(EndpointEvent, BiometricSample.event_id == EndpointEvent.id).filter(
        BiometricSample.received_at < cutoff, BiometricSample.status != 'expired', EndpointEvent.case_id.is_(None), EndpointEvent.alert_id.is_(None)).limit(1000).all()
    biometric_profiles = db.query(BiometricProfile).filter(BiometricProfile.created_at < cutoff).limit(1000).all()
    result = {'biometric_samples': len(biometric_samples), 'biometric_profiles': len(biometric_profiles), 'events': len(events), 'frames': len(frames), 'dry_run': dry_run, 'scope': 'Unlinked endpoint payloads and recorded replay frames; up to 1000 of each per pass'}
    if not dry_run:
        for row in events:
            row.payload = '{"privacy_retained": true}'
        for row in frames:
            if row.document_id:
                doc = db.get(SearchDocument, row.document_id)
                row.document_id = None
                if doc: db.delete(doc)
            row.text = '[retention expired]'; row.fields = '{}'; row.original_html = ''; row.image = None
        for row in biometric_samples:
            row.metrics = '{}'; row.status = 'expired'; row.distance = None
        for row in biometric_profiles: db.delete(row)
        audit(db, actor, 'retention_applied', **result)
        db.flush()
    return result
