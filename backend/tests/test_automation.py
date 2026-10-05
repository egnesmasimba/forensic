from app import automation
from app.delivery import DeliveryResult, DeliveryService, SmtpChannel, SmsChannel
from app.models import Alert, Delivery, Notice, Ticket
from test_api import make_client


def test_playbook_notifies_and_opens_local_records(tmp_path):
    with make_client(tmp_path) as client:
        created = client.post("/api/automation/playbooks", json={
            "name": "DLP follow-up", "trigger": "dlp", "steps": "notify, email, ticket, incident",
        })
        assert created.status_code == 201
        review = client.post("/api/dlp/inspect", json={"user": "casey", "text": "ada@example.com and bo@example.com"})
        assert review.json()["opened"] is True
        notices = client.get("/api/automation/notices").json()
        assert {row["channel"] for row in notices} >= {"app", "email"}
        assert client.get("/api/automation/incidents").json()[0]["status"] == "open"
        ticket = client.get("/api/automation/runs").json()[0]
        assert "ticket" in ticket["steps_done"]
        alert_id = client.get("/api/alerts").json()[0]["id"]
        mailed = client.post("/api/automation/playbooks", json={
            "name": "Second mail", "trigger": "dlp", "steps": "email",
        })
        again = client.post(f"/api/automation/playbooks/{mailed.json()['id']}/run", json={"alert_id": alert_id})
        assert again.json()["steps"] == []
        texted = client.post("/api/automation/playbooks", json={"name": "Text", "trigger": "dlp", "steps": "sms"})
        assert client.post(f"/api/automation/playbooks/{texted.json()['id']}/run", json={"alert_id": alert_id}).json()["steps"] == ["sms"]
        assert any(row["channel"] == "sms" for row in client.get("/api/automation/notices").json())
        client.put("/api/automation/template", json={
            "subject": "Review {title}", "body": "{user}: {title} scored {score}.",
            "throttle_minutes": 15, "escalate_minutes": 0,
        })
        assert client.post("/api/automation/escalate").json()["created"] == 1
        assert client.post("/api/automation/escalate").json()["created"] == 0
        incident = client.get("/api/automation/incidents").json()[0]
        assert client.put(f"/api/automation/incidents/{incident['id']}", json={"status": "resolved"}).json()["status"] == "resolved"
        assert client.get("/api/alerts").json()[0]["status"] == "closed"
        download = client.post("/api/alerts", json={"title": "Large browser download", "entity_type": "user", "entity_ref": "casey", "channel": "import"})
        book = client.post("/api/automation/playbooks", json={"name": "Downloads", "trigger": "download", "steps": "notify"})
        assert client.post(f"/api/automation/playbooks/{book.json()['id']}/run", json={"alert_id": download.json()["id"]}).json()["steps"] == ["notify"]
        printed = client.post("/api/automation/playbooks", json={"name": "Printing", "trigger": "print", "steps": "notify"})
        assert printed.status_code == 201
        upload_alert = client.post("/api/alerts", json={"title": "Cloud destination", "entity_type": "user", "entity_ref": "casey", "channel": "dlp"})
        upload = client.post("/api/automation/playbooks", json={"name": "Uploads", "trigger": "upload", "steps": "notify"})
        assert client.post(f"/api/automation/playbooks/{upload.json()['id']}/run", json={"alert_id": upload_alert.json()['id']}).json()["steps"] == ["notify"]
        mail_alert = client.post("/api/alerts", json={"title": "Email attachment review", "entity_type": "user", "entity_ref": "casey", "channel": "mail"})
        mail = client.post("/api/automation/playbooks", json={"name": "Email", "trigger": "email", "steps": "notify"})
        assert client.post(f"/api/automation/playbooks/{mail.json()['id']}/run", json={"alert_id": mail_alert.json()['id']}).json()["steps"] == ["notify"]
        other = client.post("/api/automation/playbooks", json={"name": "Other actions", "trigger": "other", "steps": "notify"})
        assert client.post(f"/api/automation/playbooks/{other.json()['id']}/run", json={"alert_id": mail_alert.json()['id']}).json()["steps"] == ["notify"]
        notice = client.post("/api/automation/notices", json={"user": "casey", "message": "Please review the open alert."})
        assert notice.status_code == 201
        recorded = client.post("/api/automation/triggers", json={"name": "Local handoff", "detail": "Confirm after review"})
        confirmed = client.post(f"/api/automation/triggers/{recorded.json()['id']}/confirm")
        assert confirmed.json()["confirmed"] is True
        assert any(row["change"].startswith("Confirmed") for row in client.get("/api/automation/audit").json())
        custom = client.post("/api/automation/tickets", json={"title": "Follow the download"})
        assert custom.json()["system"] == "custom"
        assert client.put(f"/api/automation/tickets/{custom.json()['id']}", json={"status": "closed"}).json()["status"] == "closed"


# --- outbound delivery -----------------------------------------------------


class RecordingChannel:
    """A transport stub that records sends and replays scripted results."""

    name = "email"

    def __init__(self, *results, configured=True):
        self.results = list(results) or [DeliveryResult("sent")]
        self.configured = configured
        self.sent = []

    def send(self, recipient, subject, body):
        self.sent.append((recipient, subject, body))
        return self.results[min(len(self.sent) - 1, len(self.results) - 1)]


def install(monkeypatch, channel):
    """Route the playbook delivery step through a stubbed transport."""
    monkeypatch.setattr(automation, "_service", DeliveryService())
    automation._service._channels["email"] = channel
    return channel


def arm(client, steps="email"):
    """Register a playbook and fire the DLP alert that triggers it."""
    created = client.post("/api/automation/playbooks", json={
        "name": "Mail follow-up", "trigger": "dlp", "steps": steps})
    assert created.status_code == 201, created.text
    fired = client.post("/api/dlp/inspect", json={
        "user": "casey", "text": "ada@example.com and bo@example.com"})
    assert fired.json()["opened"] is True


def test_delivery_is_not_attempted_without_configuration(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel(DeliveryResult("sent"), configured=False))
    with make_client(tmp_path) as client:
        arm(client)
        # The notice exists, and the absence of a send is recorded rather than
        # left looking like a silent success.
        assert any(n["channel"] == "email" for n in client.get("/api/automation/notices").json())
        assert [row["status"] for row in client.get("/api/automation/deliveries").json()] == ["not_configured"]
        assert channel.sent == []


def test_delivery_never_targets_the_subject_of_the_alert(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel())
    with make_client(tmp_path) as client:
        arm(client)
        # The alert's entity_ref is the person under investigation, so it must
        # never be used as a delivery target.
        assert channel.sent == []
        rows = client.get("/api/automation/deliveries").json()
        assert all(row["recipient"] != "casey" for row in rows)


def test_configured_recipient_receives_the_message(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel())
    with make_client(tmp_path) as client:
        assert client.post("/api/automation/recipients", json={
            "channel": "email", "address": "soc@example.org"}).status_code == 201
        arm(client)
        rows = client.get("/api/automation/deliveries").json()
        assert [(row["recipient"], row["status"]) for row in rows] == [("soc@example.org", "sent")]
        assert len(channel.sent) == 1
        assert channel.sent[0][0] == "soc@example.org"


def test_transient_failure_is_retried_then_recorded(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel(
        DeliveryResult("failed", "HTTP 503"),
        DeliveryResult("failed", "HTTP 503"),
        DeliveryResult("sent"),
    ))
    slept = []
    automation._service.sleeper = slept.append
    with make_client(tmp_path) as client:
        client.post("/api/automation/recipients", json={"channel": "email", "address": "soc@example.org"})
        arm(client)
        row = client.get("/api/automation/deliveries").json()[0]
        assert row["status"] == "sent"
        assert row["attempts"] == 3
        # Backoff grows, so a struggling relay is not hammered.
        assert slept == [0.5, 1.0]
        assert len(channel.sent) == 3


def test_permanent_rejection_is_not_retried(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel(
        DeliveryResult("bounced", "recipient refused", permanent=True)))
    with make_client(tmp_path) as client:
        client.post("/api/automation/recipients", json={"channel": "email", "address": "gone@example.org"})
        arm(client)
        row = client.get("/api/automation/deliveries").json()[0]
        assert row["status"] == "bounced"
        assert row["attempts"] == 1
        assert len(channel.sent) == 1


def test_transport_failure_does_not_abort_the_playbook(monkeypatch, tmp_path):
    install(monkeypatch, RecordingChannel(DeliveryResult("failed", "connection refused")))
    with make_client(tmp_path) as client:
        client.post("/api/automation/recipients", json={"channel": "email", "address": "soc@example.org"})
        arm(client, steps="email,ticket,incident")
        run = client.get("/api/automation/runs").json()[0]
        # Every step still completed: an unreachable relay is not a reason to
        # drop the ticket and the incident.
        assert "email" in run["steps_done"]
        assert "ticket" in run["steps_done"]
        assert "incident" in run["steps_done"]
        assert client.get("/api/automation/incidents").json()[0]["status"] == "open"
        with client.app.state.session_factory() as db:
            assert db.query(Ticket).count() == 1


def test_recipients_must_look_like_an_address_or_number(tmp_path):
    with make_client(tmp_path) as client:
        assert client.post("/api/automation/recipients", json={
            "channel": "email", "address": "soc@example.org"}).status_code == 201
        assert client.post("/api/automation/recipients", json={
            "channel": "email", "address": "not-an-address"}).status_code == 422
        assert client.post("/api/automation/recipients", json={
            "channel": "carrier_pigeon", "address": "soc@example.org"}).status_code == 422
        assert client.post("/api/automation/recipients", json={
            "channel": "sms", "address": "+15551234567"}).status_code == 201


def test_disabled_recipient_is_not_used(monkeypatch, tmp_path):
    channel = install(monkeypatch, RecordingChannel())
    with make_client(tmp_path) as client:
        created = client.post("/api/automation/recipients", json={
            "channel": "email", "address": "soc@example.org"}).json()
        assert client.put(f"/api/automation/recipients/{created['id']}",
                          json={"enabled": False}).status_code == 200
        arm(client)
        assert channel.sent == []
        assert client.get("/api/automation/recipients").json()["recipients"][0]["enabled"] is False


def test_transport_status_never_exposes_a_credential():
    status = DeliveryService({"ZANAQ_SMTP_HOST": "mail.example.org", "ZANAQ_SMTP_FROM": "a@b.c",
                              "ZANAQ_SMTP_PASS": "super-secret"}).status()
    assert status["email"]["configured"] is True
    assert "super-secret" not in str(status)


def test_transport_reads_configuration_from_the_environment():
    smtp = SmtpChannel({"ZANAQ_SMTP_HOST": "mail.example.org", "ZANAQ_SMTP_FROM": "alerts@example.org",
                        "ZANAQ_SMTP_STARTTLS": "0"})
    assert smtp.configured is True
    assert smtp.starttls is False
    assert SmsChannel({"ZANAQ_SMS_URL": "https://sms.example.org/send"}).configured is True
    assert SmsChannel({}).configured is False


def test_sms_channel_sends_subject_and_body():
    captured = {}

    class Sms(RecordingChannel):
        name = "sms"

        def send(self, recipient, subject, body):
            captured.update(recipient=recipient, subject=subject, body=body)
            return DeliveryResult("sent")

    service = DeliveryService({})
    service._channels["sms"] = Sms()
    assert service.deliver("sms", "+15551234567", "Review alert", "detail").status == "sent"
    assert captured["subject"] == "Review alert"
    assert "detail" in captured["body"]


def test_duplicate_delivery_is_not_recorded_twice(monkeypatch, tmp_path):
    install(monkeypatch, RecordingChannel())
    with make_client(tmp_path) as client:
        client.post("/api/automation/recipients", json={"channel": "email", "address": "soc@example.org"})
        arm(client)
        with client.app.state.session_factory() as db:
            alert = db.query(Alert).first()
            notice = db.query(Notice).first()
            # Replaying the same message must not create a second row.
            automation._record_delivery(db, alert, notice, "email", "soc@example.org",
                                        "fixed-key", DeliveryResult("sent"))
            db.flush()
            assert db.query(Delivery).filter_by(message_id="fixed-key").count() == 1
