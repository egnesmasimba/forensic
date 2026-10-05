# ZANAQ Forensic Centre

Enterprise Forensic Monitoring, Tracking & Response Platform. Cross-platform surveillance and investigation system that provides unparalleled visibility of end-user activity across corporate applications — from Mainframe (3270, 5250, SNA/APPC), web, and thin-client terminals to modern Windows, Linux, and macOS endpoints.

## Ownership

Owned by **ZANAQ**.

---

## Repository layout

```
forensic/
├── backend/                   FastAPI server + SQLite database
│   ├── app/                   Web UI, API routers, auth, ORM models
│   │   ├── routers/           API modules (cases, alerts, network, agents,
│   │   │                      privacy, analytics, IAM, reports, search, ...)
│   │   ├── static/            Single-page UI: index.html, app.js, styles.css
│   │   └── ...
│   ├── endpoint_agent/        Cross-platform endpoint agent (Windows/Linux/macOS)
│   │   ├── collectors/        fileops, usb, clipboard, print, screenshot,
│   │   │                      process, rdp/citrix, registry, biometrics, ...
│   │   ├── install/           Installers (Windows .ps1, Linux .sh, macOS .sh)
│   │   └── README.md
│   ├── evidence/              Crypto (AES-GCM encryption), signing (RSA-SHA256)
│   ├── network_sensor/        Passive PCAP/PCAPNG sensor with decoders
│   │   ├── README.md
│   │   └── example-config.json
│   ├── tests/                 pytest suites (166+ regressions)
│   ├── README.md              Detailed server runbook
│   └── requirements.txt
├── database/                  Reporting views / SQL exports
├── frontend/                  TypeScript sources for report builder UI
├── native/                    C helpers: evidence hashing, PAM ticket bridge
├── tools/                     Rust + Go utilities: pcap-check, capture-bound,
│                              sensor-report
├── ui/                        Supplementary TS sources
├── doc.md                     Product architecture, feature reference
├── add-features.md            Competitive feature addendum (v2.1)
├── todolist.md                Implementation tracking
└── otherforensic.md           Additional feature context
```

## Core capabilities

- **Case management** — Cases, alerts, notes, attachments, custom fields, status
  workflows, role-based accounts (admin / investigator / viewer).
- **Endpoint monitoring** — Agented collectors for file ops, removable media,
  clipboard, print jobs, screenshots/live frames, process tracking,
  RDP / Citrix sessions, registry changes, idle state, browser downloads,
  mail capture, print policy enforcement, optional behavioral biometrics.
  Stealth-mode installers and tamper-proof watchdog.
- **Network capture & decoders** — PCAPNG import, TCP session reconstruction,
  TN3270E / TN5250 / VT / SNA-APPC / HTTP metadata coverage, saved COBOL/C
  layout message framing, traffic threat analysis (SYN scan, C2 callback,
  malware/C2 IP matching, port/protocol mismatch, heavy transfer flags).
- **Visual replay** — Reconstructed terminal, web, and thin-client screens
  from captured activity, with response actions and desktop recording.
- **Activity import** — CSV (activity, email metadata, traffic summaries) with
  built-in alerting rules for bulk export, USB/cloud exfiltration, browser
  download, archive/encrypt, external email recipients, heavy bandwidth,
  unusual protocols, and login failures.
- **Free-text search** — SQLite FTS5 (default) or optional Elasticsearch.
  Indexes case text, alerts, notes, imported events, endpoint events,
  OCR, decoded network screens/messages.
- **Analytics & insider-threat library** — 170 behavioral measures, 328 prebuilt
  library rules across identity/access/data/network/system/financial/
  communication/policy categories, live stream evaluation, behavioral
  biometrics enrollment, privacy-protected synthetic cohort aggregates.
- **Privacy & compliance** — Privacy mode with pseudonymized views, consent
  lifecycle, retention/erasure, access/portability/erasure/consent request
  records, privacy audit export, control inventory. Policy-education
  in-agent warnings, escalation, training tracking.
- **IAM & privileged access** — Password + TOTP/HOTP/SMS MFA, shared-account
  member-attribution, role/module allowlists, off-hours enforcement,
  privileged access request/activation workflow, AD/LDAPS directory sync,
  Linux PAM bridge with one-time tickets.
- **Evidence integrity** — AES-GCM envelope encryption (ZANAQAES v1), signed
  capture containers (ZANAQCAP1 v1), keyring with optional passphrase wrap,
  SHA-256 fingerprinting, tamper detection at decrypt time.
- **Transport security** — Self-signed TLS CA/server cert generator,
  HSTS + security headers, optional mTLS for agent/server, secure
  `zanaq_session` cookie with HttpOnly/SameSite/Secure, session CSRF tokens.

## Quick start (local dev)

Prerequisites: Python 3.11+.

```powershell
cd backend
python -m venv .runtime
.runtime/Scripts/python.exe -m pip install -r requirements.txt
```

Create the first administrator (no default account):

```powershell
.runtime/Scripts/python.exe -m app.create_admin
```

Start the application and sign in at http://127.0.0.1:8000 :

```powershell
.runtime/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run the test suite:

```powershell
.runtime/Scripts/python.exe -m pytest tests -q
```

See `backend/README.md` for:
- TLS / HTTPS setup and transport-security environment variables
- CSV import column reference and alert rules
- Network capture viewer, saved layouts, and threat analysis
- Search, Elasticsearch configuration, and backfill API
- Privacy mode, consent, retention, and policy education
- Live analytics catalog, biometrics, synthetic aggregates
- Report builder, filters, drilldown, and NDJSON export tool
- IAM, MFA, Active Directory sync, Linux PAM bridge

## Endpoint agent deployment

See `backend/endpoint_agent/README.md` for collector availability, optional
dependencies (`doctor` command), and installation scripts.

```powershell
python -m endpoint_agent doctor --strict
python -m endpoint_agent.privacy --config agent_config.json --grant
python -m endpoint_agent.biometrics --config agent_config.json --grant
```

Installers (stealth, tamper-proof watchdog) are provided per platform:
`backend/endpoint_agent/install/windows/install.ps1`, `linux/install.sh`,
`macos/install_mac.sh`.

## Naming conventions

- Session cookie: `zanaq_session` (force `Secure` via `ZANAQ_SECURE_COOKIES=1`
  behind a TLS-terminating proxy).
- Database file: `zanaq.db`.
- Evidence encryption magic: `ZANAQAES` v1.
- Secure PCAP container magic: `ZANAQCAP1` v1.
- Environment variable prefix: `ZANAQ_`.

## License

Internal-use product documentation and implementation repository.
