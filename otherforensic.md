# EFMTT 2.1 — Programmer Implementation Todo List

## Complete Development Roadmap

### Current Implementation — 4 October 2026

The local Investigation Center supports case creation and review, notes, conclusions, evidence attachments, alert linking, case scoring, filtering, custom case fields, routing rules, link analysis, and CSV/Excel/PDF reports. Login protects case, alert, evidence, report, and import APIs. Administrators create accounts; administrators and investigators can make changes; viewers have read-only access. New case activity and evidence uploads use the signed-in username.

Activity CSV imports validate and retain source events, skip identical duplicates, reject conflicting IDs, and roll back the whole upload on invalid data. Two initial rules generate alerts: exports of at least 1,000 records (score 70), and USB/cloud transfers of at least 10,485,760 bytes (score 80). The Activity & alerts inbox supports review, dismissal, and linking alerts to cases. Investigators can also collect text and binary files, logs, XML, SQLite tables, fixed or delimited layouts, and queue messages. Imported activity also raises review alerts for large browser downloads, named cloud-sync destinations, network shares, archives, and encrypted files. Email metadata imports record sender, recipient domain, attachment name, size, and an encrypted flag, and traffic summaries raise review alerts for unusual protocols, flows of at least 100 MB, and flows with at least 100 connections. Signed-in users can change their password. Administrators can disable accounts, keep one administrator enabled, and set a replacement password. Evidence files store a SHA-256 hash that can be checked later. Review thresholds are editable, and three or more login failures in one activity import raise one alert. A case timeline lists the notes, alerts, files, and activity already stored on that case. Saved reports keep the current search, status, minimum score, sort, and selected columns, and a case package downloads the PDF, timeline, and attached evidence. A scheduled inbox scan runs while the server is up, and imported users are matched to entities already stored on alerts.

The endpoint agent package covers Windows, Linux, and macOS collectors for files, USB, clipboard, print-job metadata, screenshots, processes, windows, idle time, registry changes, Citrix client presence, and private-browsing markers. All nineteen implemented collectors are registered and report whether they can actually collect on the host, naming any missing optional library and the command that installs it; `python -m endpoint_agent doctor` prints that matrix and can gate a deployment. Collectors that capture window titles, clipboard contents, screen images, or user activity stay disabled until an operator enables them by name. It heartbeats to the server and can apply a hashed update. Hiding from Task Manager, resisting uninstall, and recording RDP or Citrix desktops are not in that package. Investigators can read text from PNG and JPEG files already attached to a case. The reading keeps the Tesseract language and average word confidence, and Image text on the case list searches those readings.

A business process names an ordered set of screens. Each screen is identified by text markers and can capture fields by line and column. Saving an image reading, or submitting a transcript that follows the screen order, records an audit row and the field values. Uploaded captures can name a message-identifying field, search decoded values, list records in order, and step through reconstructed terminal screens. A website visit import maps hostnames onto 42 categories, totals time spent, and raises a review alert when the category is denied. A saved message layout can frame each record with a 2- or 4-byte length and skip an envelope before the fields. Uploaded captures reassemble complete IPv4 fragments, treat a TCP SYN as a new session, skip a chunked HTTP/1 body, and name the standard FIX header tags. Analytic rule versions aggregate stored facts with sum, count, min, or max, including a recheck of facts already imported. The Analytics dialog also saves list, text, after-hours, department, terminal, beneficiary, and ordered-step rules, and can test a version before saving it. Each new finding adds that rule's score to the entity. The running total and each change are kept, and crossing the configured threshold opens one Risk score alert.

Ten behavioral indicators average stored facts over the trailing 90 days, and a writer can add another indicator. Each user's baseline is the mean and standard deviation of earlier periods. A latest period above that band, after enough earlier activity, opens one Behavior baseline alert for that period. Phone, email, chat, and system events for one user are listed together. A rising transfer trend, a heavy workload, a stored turnover signal, and stored sentiment signals each open one review alert for that week. Work, meeting, and idle minutes are totaled from stored facts. A synthetic profile publishes indicator averages under a token. Users can be compared with peers in the same department or role, and with a named group. Eight starter library rules from NIST, MITRE, CERT, and FS-ISAC can be disabled or given a new threshold. DLP review inspects submitted text for customer, financial, and intellectual-property markers, and the match count follows the user's risk score. USB serials, cloud hosts, file renames and moves, permission changes, and submitted command logs can each open a review alert. Allow lists skip the USB, cloud, and permission alerts.

A playbook can notify a user, queue an email or SMS message, open a custom ticket, and open an incident. Resolving the incident closes the linked alert. Messages stay in the Investigation Center, repeat messages for the same alert are throttled, and an unacknowledged notice can be escalated. A local trigger can be confirmed. A local response executor applies operator allow-listed containment actions: process termination with a PID-reuse guard, host network isolation with declared management-server exceptions, file and Windows System Restore snapshots, verified rollback, and a live response view. Every one of those steps is recorded on the case timeline with the operator's reason attached, and an action may only be filed under a case that already holds an alert from that same endpoint. `GET /api/response/capabilities` states for each control whether the agent can enforce it or only observe it, and names the real enforcement point; account lockout, email, print, clipboard, USB, cloud-upload, and share blocking are not agent-side controls and need Active Directory, the mail transport, Group Policy, a print server, or a DLP proxy. Containment is operator-driven: playbook automation can notify and escalate on a violation but does not dispatch response commands unattended.

Stored captures also reconstruct a 24x80 TN5250 screen subset, name SMB commands and SNA BIND, UNBIND, and ACTLU, and record cleartext HTTP/2 frame headers, an MQSTR body, an MSMQ base header, a plaintext FTP data-channel match, and limited TDS, SQL*Net, DRDA, FIX, SWIFT, and ISO 8583 fields. Encrypted content stays opaque. Layout import accepts IBM COBOL COMP and COMP-3 sizes, MSVC-style C alignment, and a 2- or 4-byte length prefix. A suppression or whitelist rule marks a matching new open alert suppressed. A saved route assigns that alert and writes an in-app notice; mail, SMS, and outside systems are not contacted. Related alerts lists an entity with two or more open or linked alerts. A case report can list each custom field. Administrators can record access, portability, erasure, consent, and opt-out requests, archive facts past a 6-to-12-month window, and export the privacy audit. Those records are a local register, not a legal certification.

**Verification:** Three hundred seventy-seven automated tests passed, with two skipped: PF_RING and DPDK are Linux-only, and POSIX file modes are not meaningful on this Windows host. Coverage includes case workflow, custom fields and routing, link analysis, attachments and report exports, saved report columns, case packages, role permissions, session expiry and logout, password change, account disabling, evidence hashes, configurable thresholds, authenticated attribution, import validation and rollback, file, log, XML, SQLite, layout, and queue collection, scheduled inbox scan, alert correlation, duplicate handling, exfiltration-channel thresholds, email metadata, traffic summaries, alert-to-case linking, image-text readings with confidence and search, screen definitions that record a navigation audit with field values, message identification and search on uploaded captures, website category time, policy alerts, and reports, business-rule previews with risk-score history, behavioral averages, baselines, channel views, threat and workload scores, synthetic profiles, the starter rule library, and DLP review of submitted text, devices, files, permissions, and commands. Transport security is covered by real TLS handshakes against a generated certificate authority, including rejection of an untrusted certificate, rejection of a certificate issued for the wrong name, mutual TLS, and a live uvicorn HTTPS listener serving the API. Collector availability is covered by tests asserting that a missing optional dependency is reported with its module name and install command, that an inert collector cannot tick, that capture collectors stay opt-in, and that platform restrictions stay distinct from missing modules. No coverage percentage, production readiness, or compliance certification is claimed. Later checks of alert suppression and routing, report field drilldown, compliance records, and the stored-capture decoders passed on their own. This paragraph does not replace that recorded full-suite count.

**Checklist convention:** Checked items describe the local implementation only and are kept in [done-todolist.md](done-todolist.md). Open items stay in this file. When only part of a feature is implemented, the parent stays open here and the completed substep is recorded in the done list. Phase week ranges are the original planning estimates, not verified delivery dates. Setup and import instructions are in [backend/README.md](backend/README.md). The product specification is [doc.md](doc.md). The competitive addendum is [add-features.md](add-features.md).

---

## Phase 0: Foundation & Architecture (Weeks 1–4)

### 0.1 Environment Setup
- [ ] Set up development, staging, and production environments
- [ ] Configure version control (Git) with branching strategy
- [ ] Set up CI/CD pipelines
- [ ] Configure containerization (Docker/Kubernetes)
- [ ] Set up monitoring and logging infrastructure
- [ ] Configure secrets management (Vault, AWS Secrets Manager)
- [ ] Establish coding standards and linting rules

### 0.2 Core Architecture Design
- [ ] Design microservices vs. monolith architecture decision
- [ ] Define API contracts (REST/GraphQL/gRPC)
- [ ] Design database schema (PostgreSQL, MongoDB, TimescaleDB)
- [ ] Design message queue architecture (Kafka, RabbitMQ, MQ Series)
- [ ] Define data flow between network sensors and analyzers
- [ ] Design high-availability and failover strategy
- [ ] Document architecture decision records (ADRs)

### 0.3 Security Foundation
- [ ] Implement AES-128 encryption for recorded data
- [ ] Implement MD5 with RSA digital signatures
  - [ ] Add certificate rotation and expiry alerting
- [ ] Implement Active Directory integration
- [ ] Implement PAM integration for UNIX
- [ ] Implement audit logging for all system access

---

## Phase 1: Network Sniffing & Data Capture (Weeks 5–12)

### 1.1 Network Sensor Development

**Status:** Windows Npcap/libpcap adapter and offline classic-PCAP analysis implemented. Live capture is not verified because Npcap is not installed on this machine. Open **Network captures** for authenticated upload, session/message review, original capture download, stored screen replay, and decoder coverage. See [network_sensor/README.md](backend/network_sensor/README.md) for setup, commands, resource limits, and remaining protocol work.

- [ ] Build packet capture engine (libpcap, PF_RING, DPDK)
  - [ ] Install Npcap and verify live capture on the deployment interface
  - [ ] Implement and benchmark PF_RING and DPDK backends on Linux
- [ ] Implement mirror port and tap device support
  - [ ] Verify capture against the actual mirror/tap hardware and VLAN setup
- [ ] Build protocol decoders:
  - [ ] IBM Mainframe 3270 (SNA, TN3270, Enterprise Extender)
    - [ ] Verify screen reconstruction against representative captures from a real host
  - [ ] IBM iSeries 5250 (SNA, TN5250, MPTN)
    - [ ] Implement 5250 orders/screens, SNA and MPTN decoding against representative captures
  - [ ] TCP/IP, MQ Series, MSMQ
  - [ ] IBM SNA LU0 and LU6.2 (raw non-IP frames remain preserved)
    - [ ] Decode LU session state and request/response payloads against representative captures
  - [ ] SMB, HTTP, HTTPS, Web Services
    - [ ] Add HTTP/2/3, web-service schemas, SMB operations/files, and encrypted-content decoding
  - [ ] Telnet/VT100, SSH
    - [ ] Complete terminal control coverage and support authorized decrypted SSH streams
  - [ ] FTP
    - [ ] Reconstruct FTP data-channel transfers and handle encrypted FTP variants
  - [ ] Oracle SQLNET, DB/2 DRDA, MS SQL TDS
    - [ ] Implement query/value/parameter decoders, multi-packet application framing, and encrypted variants
  - [ ] SWIFT, FIX, ISO8583
    - [ ] Implement SWIFT and ISO8583 fields using the deployment's message specifications and captures; currently opaque recording only
- [ ] Implement real-time screen reconstruction for thin clients
  - [ ] Add a streaming browser viewer for reconstructed screens
  - [ ] Implement full TN5250 screen reconstruction
- [ ] Build message layout import system (Cobol, C, VB)
  - [ ] Support compiler-specific layouts and infer protocol envelopes
- [ ] Implement SNMP health alerts:
  - [ ] Verify delivery against the deployment's SNMP manager; configure its enterprise OID/community
  - [ ] Add SNMPv3 authentication/encryption and a registered MIB

**Layout-library validation:** Two additional tests verify immutable named versions, duplicate rejection, automatic decoding on capture review, enable/disable behavior, authentication and role restrictions, incomplete-stream skipping, invalid-record diagnostics, and per-report resource budgets.

**Validation:** Network-sensor tests cover packet parsing, VLAN/IPv6, malformed/truncated captures, retransmission/order/wrap/gap/conflict handling, connection reuse, a midstream flow without SYN, monitoring selection, FIX header checks, terminal and TN5250 screens, HTTP/2 frame headers, SMB command names, MQ/MSMQ/TDS/SQL*Net/DRDA/SWIFT/ISO 8583 metadata, plaintext FTP data-channel matching, layout dialects, health transitions/SNMP encoding, recording integrity, and API permissions. Eighty tests in the decoder, layout, and session modules passed. Live driver capture, real-host screen verification, and real SNMP-manager delivery remain unverified.

### 1.3 Endpoint Agent Development

- [ ] Validate the resolved gaps against real hosts running each optional library
- [ ] Implement stealth mode (invisible in Task Manager) — **not implemented, and not planned**
  - [ ] Hide the process from Task Manager
- [ ] Implement tamper-proof installation — **not implemented, and not planned**
  - [ ] Resist uninstall or service removal
  - [ ] Store a copy of the printed pages
- [ ] Build RDP session recording — **not implemented, and not planned**
  - [ ] Record the remote desktop
  - [ ] Record the Citrix desktop

**Collector availability:** A collector whose dependency is missing produces no events at all, which is indistinguishable from a host where nothing happened, so the gap is reported rather than only logged. All 19 implemented collectors are registered through `collectors/catalog.py` (previously three were constructed inline and sixteen never appeared in any report). Each declares `requires`, resolved per platform by `effective_requires()`, so a macOS-only module is not reported missing on Linux and a Windows-only module is not reported missing on macOS. Missing requirements are reported per collector with an install command, and the worker heartbeat carries the aggregate. Sixteen tests cover the registry, opt-in defaults, platform-versus-dependency distinctions, and the `doctor` command.

**Deliberately not implemented:** Hiding the agent from Task Manager, resisting uninstall or service removal, keeping a copy of printed pages, and recording RDP or Citrix desktops are all absent from the package. These capabilities are what malware and unwanted monitoring tools do; they defeat the administrator's ability to see, stop, or remove the agent, and hidden capture of another user's desktop or printed output is surveillance rather than evidence collection. Acceptable substitutes are already partly in place: `install`, `update --rollback-on-fail`, and `uninstall` are documented and reversible, `self_monitor_exclude` makes the watchdog's own processes visible, and capture collectors (`clipboard`, `screenshot`, `window`, `idle`, `usb`, `incognito`) require an explicit per-collector opt-in that is recorded in the collector status. If session-level video is genuinely required, capture it with visible, consented, policy-governed recording and retain it only for the retention period the organisation already applies to other endpoint telemetry.

### 1.5 Email Attachment & Content Monitoring (NEW)

- [ ] Validate classic Outlook COM permissions and the selected Thunderbird stores on target machines
- [ ] Validate current Gmail/Outlook DOM layouts and install the native messaging host
- [ ] Validate actual removable drives, network shares and each configured cloud sync root

### 1.6 Network Traffic Analysis (NEW)

- [ ] Build network-layer threat detection
- [ ] Build malware callback detection
- [ ] Build C2 traffic detection
- [ ] Build unusual protocol detection
- [ ] Build bandwidth-heavy application identification
- [ ] Build anomalous traffic pattern detection

---

## Phase 2: Data Analysis Engine (Weeks 13–18)

### 2.1 Free-Text Indexing

- [ ] Verify against a running Elasticsearch deployment; adapter contract, outage/retry and partial-failure tests currently use simulated responses. Solr is not implemented.
- [ ] Add language-specific analyzers, fuzzy queries and dynamic-page rendering if required; current parser/index limits are documented.

### 2.2 Optical Character Recognition (Feature 61)

- [ ] Integrate OCR engine (Tesseract, ABBYY)
  - [ ] Integrate ABBYY
- [ ] Build screenshot text extraction

### 2.3 User Process Analysis

- [ ] Build screen identification engine
  - [ ] Identify screens from a live desktop recording
- [ ] Build real-time screen checking
  - [ ] Check screens as they are recorded from a desktop
- [ ] Build navigation scenario capture
  - [ ] Capture a user's live navigation
- [ ] Build field-level audit trail
  - [ ] Derive read and update actions from recorded keystrokes

### 2.4 Thin vs. Fat Client Support

- [ ] Build thin-client screen reconstruction
  - [ ] Reconstruct full TN5250 screens
- [ ] Build visual screen replay for thin clients
  - [ ] Stream a live terminal viewer
- [ ] Build message layout import system
  - [ ] Import compiler-specific layouts

### 2.5 Website Categorization (NEW – Feature 72)

- [ ] Build URL capture from network and endpoint
  - [ ] Capture URLs from the network or the endpoint agent

---

## Phase 3: Profiling, Scoring & Alerting (Weeks 19–24)

### 3.1 Analytic Engine Core

- [ ] Evaluate a live capture stream

### 3.4 Behavioral Indicators (Feature 22)

- [ ] Implement 150+ behavioral indicators:
  - [ ] The published catalog of 150 named indicators is not included. The ten named indicators above are calculated, and further indicators are added by definition.

### 3.10 Behavioral Biometrics (Feature 28)

- [ ] Build keystroke rhythm capture
- [ ] Build mouse movement pattern capture
- [ ] Build typing cadence analysis
- [ ] Build identity verification
- [ ] Build account takeover detection
- [ ] Build credential sharing detection
- Keystroke rhythm, mouse movement, and typing-cadence capture are not part of this Investigation Center.

### 3.11 Synthetic Data Analytics (Feature 29)

- [ ] Build GDPR-compliant analytics
  - [ ] This export is not a legal compliance certification.

### 3.14 Insider Threat Library (NEW – Feature 73)

- [ ] Implement 320+ pre-built indicators
  - [ ] The published catalog of 320 indicators is not included.

### 3.15 Alerting

- [ ] Build real-time alert generation
- [ ] Build alert routing
  - [ ] Add automatic routing and notification delivery
- [ ] Build email alerts
- [ ] Build SMS alerts
- [ ] Build MQ/Web Service alerts
- [ ] Build alert suppression/whitelisting
- [ ] Build alert correlation

---

## Phase 4: Investigation & Case Management (Weeks 25–30)

### 4.6 Reporting Function (Original)

- [ ] Build input filter definition
- [ ] Build drilldown to field level
- [ ] Build external tool integration

---

## Phase 5: Data Loss Prevention & Active Blocking (Weeks 31–36)

Configured-file snapshots/backup/restore with hash verification, plus optional native Windows System Restore. Native restore schedules a restart and stays pending until Windows-reported post-boot verification; neither scope is a full disk image.

Deployment validation remains:
- [ ] Validate interactive desktop consent/capture/control on a Windows test endpoint
- [ ] Validate firewall isolation, DNS/management exceptions and local recovery on that endpoint
- [ ] Validate native Windows System Restore and post-reboot reconnect/verification on a disposable test endpoint

### 5.2 USB Device Detection & Blocking (Feature 2)

- [ ] Build data transfer blocking
- USB transfer blocking is not part of this Investigation Center.

### 5.3 Clipboard Monitoring (Feature 3)

- [ ] Build clipboard content capture
- [ ] Build cross-application tracking
- [ ] Build sensitive data detection in clipboard
- [ ] Build clipboard blocking
- Clipboard capture and clipboard blocking are not part of this Investigation Center.

### 5.4 Cloud Upload Blocking (Feature 4)

- [ ] Build upload interception
- [ ] Build personal cloud drive blocking
- [ ] Build GenAI tool blocking
- Upload interception and destination blocking are not part of this Investigation Center.

### 5.5 Email Attachment Interception (Feature 5)

- [ ] Build attachment detection
- [ ] Build content scanning
- [ ] Build context analysis
- [ ] Build attachment blocking
- [ ] Build email quarantine
- Attachment blocking, message-body scanning, and email quarantine are not part of this Investigation Center.

### 5.6 Print Control (Feature 6)

- [ ] Build print job capture
- [ ] Build print restriction
- [ ] Build print audit trail
- [ ] Build print content inspection
- Print restriction and print-page content inspection are not part of this Investigation Center.

### 5.10 Screenshot Blocking (Feature 10)

- [ ] Build screenshot attempt detection
- [ ] Build screenshot blocking
- [ ] Build screenshot audit logging
- Screenshot blocking is not part of this Investigation Center.

### 5.11 Linux Command Prevention (NEW – Feature 74)

- [ ] Build Linux command interception
- [ ] Build command blocking rules
- [ ] Block specific commands (rm -rf, dd, nc, wget)
- [ ] Block privilege escalation (sudo abuse, su)
- [ ] Block data exfiltration commands (scp, rsync)
- [ ] Block untrusted package installation
- [ ] Block attack pattern sequences
- Command interception and command blocking are not part of this Investigation Center.

---

## Phase 6: Real-Time Response & Automation (Weeks 37–40)

### 6.1 Real-Time User Blocking (Feature 31)

- [ ] Build immediate action blocking

### 6.4 SOAR Integration (Feature 34)

- [ ] Build SOAR platform connectors

### 6.5 Ticketing System Integration (Feature 35)

- [ ] Build ServiceNow integration
- [ ] Build Jira integration
- [ ] Build Remedy integration

### 6.6 Email/SMS Alerts (Feature 36)

- [ ] Build email alert engine
- [ ] Build SMS alert engine

### 6.7 External System Triggering (Feature 37)

- [ ] Build MQ trigger
- [ ] Build Web Service trigger
- [ ] Build custom protocol trigger

### 6.8 Forcible Logoff / Application Closure (Feature 75)

- [ ] Build forced logoff and account lockout commands — these are directory and session state, not agent-local state. Agent-side lockout would leave the user able to authenticate on another host, which is worse than appearing to work; this needs Active Directory or the identity provider.
- [ ] Build application closure and session termination — process termination exists; closing an application cleanly or ending a whole interactive session is not implemented.
- [ ] Build process prevention (deny-list) as distinct from termination — a watcher can refuse to relaunch a known-bad binary, but a determined user can still execute a copy from elsewhere, so this raises cost rather than enforcing.
- [ ] Block email send, print, clipboard, USB, cloud upload, and network shares from the agent — the agent can *observe* these transfers, but only the enforcement point can prevent them: mail transport rules, the print server, Group Policy, or a DLP proxy. An agent-side flag is not a block.

---

## Phase 7: Identity & Access Management (Weeks 41–43)

### 7.1 Shared Account Authentication (Feature 39)

- [ ] Build shared account detection
- [ ] Build identity verification for shared logins
- [ ] Build accountability tracking

### 7.2 Two-Factor Authentication (Feature 40)

- [ ] Build 2FA integration
- [ ] Build TOTP support
- [ ] Build SMS-based 2FA
- [ ] Build hardware token support

### 7.3 One-Time Passwords (Feature 41)

- [ ] Build OTP generation
- [ ] Build OTP validation
- [ ] Build OTP for privileged access

### 7.4 Privileged Account Management (Feature 42)

- [ ] Build privileged account identification
- [ ] Build privileged session recording
- [ ] Build privileged access approval workflow
- [ ] Build privileged activity monitoring

### 7.5 Role-Based Access Control (Feature 43)

- [ ] Build dashboard access isolation
- [ ] Build data access isolation

### 7.6 Active Directory Integration (Feature 44)

- [ ] Build AD authentication
- [ ] Build AD user/group sync
- [ ] Build AD permission mapping

### 7.7 PAM Integration (Feature 45)

- [ ] Build PAM module
- [ ] Build PAM authentication
- [ ] Build PAM authorization

### 7.8 Multi-Factor Anomalous Login Detection (Feature 68)

- [ ] Build simultaneous login detection
- [ ] Build different terminal detection
- [ ] Build credential sharing alert
- [ ] Build account takeover alert

---

## Phase 8: User Privacy & Anonymization (Weeks 44–45)

### 8.1 User Anonymization / Privacy Mode (NEW – Feature 76)

- [ ] Build anonymized dashboards
- [ ] Build pseudonymization engine
- [ ] Build PII masking in screenshots
- [ ] Build PII masking in recordings
- [ ] Build consent management
- [ ] Build retention controls
- [ ] Build role-based access to raw vs. anonymized data
- [ ] Build GDPR-compliant anonymization
- [ ] Build works council compliance features

---

## Phase 9: User Education & Policy Notification (Weeks 46–47)

### 9.1 Out-of-Policy User Notifications (NEW – Feature 77)

- [ ] Build real-time popup warnings
- [ ] Build policy reminder system
- [ ] Build educational message system
- [ ] Build warning escalation
- [ ] Build manager notification
- [ ] Build training assignment integration
- [ ] Build notification audit trail
- [ ] Build notification customization

---

## Phase 10: Compliance & Audit Support (Weeks 48–50)

### 10.1 GDPR Compliance (Feature 46)

- [ ] Build data subject access request handling
- [ ] Build right to erasure
- [ ] Build data portability
- [ ] Build consent tracking
- [ ] Build privacy impact assessment support

### 10.2 HIPAA Compliance (Feature 47)

- [ ] Build PHI detection
- [ ] Build access controls
- [ ] Build audit controls
- [ ] Build integrity controls
- [ ] Build transmission security

### 10.3 PCI-DSS Compliance (Feature 48)

- [ ] Build cardholder data detection
- [ ] Build access control
- [ ] Build network security
- [ ] Build vulnerability management
- [ ] Build logging and monitoring

### 10.4 SOC 2 Type II (Feature 49)

- [ ] Build security controls
- [ ] Build availability controls
- [ ] Build processing integrity controls
- [ ] Build confidentiality controls
- [ ] Build privacy controls

### 10.5 CCPA Compliance (Feature 50)

- [ ] Build consumer rights handling
- [ ] Build data disclosure tracking
- [ ] Build opt-out mechanisms

### 10.6 FINRA Audit Support (Feature 51)

- [ ] Build financial industry compliance
- [ ] Build audit trail
- [ ] Build record retention
- [ ] Build supervisory controls

### 10.7 Exportable Audit Logs (Feature 52)

- [ ] Build structured log export
- [ ] Build compliance documentation export
- [ ] Build log format customization

### 10.8 Retention Policy Configuration (Feature 53)

- [ ] Build retention period configuration
- [ ] Build 6-12 month online retention
- [ ] Build automatic data aging

### 10.9 Data Archiving (Feature 54)

- [ ] Build automatic archiving
- [ ] Build archive retrieval
- [ ] Build archive integrity verification

**Compliance validation:** One automated test covers access and portability export, legal-hold refusal, erasure of facts and archives, consent, impact notes, supervisory review, masked SSN and card review, 6-month aging, archive tamper detection, CSV column selection, and the non-administrator refusal. The parents stay open because this is a local record set, not a certification, vulnerability program, or transmission-security proof.

---

## Phase 11: Integration & Extensibility (Weeks 51–53)

### 11.1 SIEM Integration (Feature 55)

- [ ] Build Splunk integration
- [ ] Build ArcSight integration
- [ ] Build QRadar integration
- [ ] Build custom SIEM integration
- [ ] Build event forwarding
- [ ] Build bidirectional sync

### 11.2 API Export (Feature 56)

- [ ] Build GraphQL API
- [ ] Build API rate limiting
  - [ ] Add throttling for other API endpoints
- [ ] Build API documentation

### 11.3 CSV/PDF Export (Feature 57)

- [ ] Build export scheduling

### 11.4 Project Management Tool Integration (Feature 58)

- [ ] Build Jira integration
- [ ] Build Asana integration
- [ ] Build Monday.com integration
- [ ] Build workflow bottleneck detection

### 11.5 Custom Web/App Monitoring (Feature 59)

- [ ] Build custom application definition
- [ ] Build custom screen capture
- [ ] Build custom event generation

### 11.6 Geographic Productivity Comparison (Feature 60)

- [ ] Build location tracking
- [ ] Build productivity metrics by location
- [ ] Build office vs. remote comparison
- [ ] Build geographic reporting

### 11.7 Instant Messaging Monitoring (Feature 62)

- [ ] Build Teams integration
- [ ] Build Slack integration
- [ ] Build WhatsApp integration
- [ ] Build message content capture
- [ ] Build IM policy enforcement

### 11.8 Social Media Monitoring (Feature 63)

- [ ] Build social media detection
- [ ] Build usage tracking
- [ ] Build brand reputation monitoring
- [ ] Build policy violation alerting

### 11.9 Geolocation Tracking (Feature 66)

- [ ] Build device location capture
- [ ] Build anomalous login detection
- [ ] Build location-based policies
- [ ] Build geographic reporting

---

## Phase 12: System Administration & Infrastructure (Weeks 54–56)

### 12.1 Scalability

- [ ] Build horizontal scaling for sensors
- [ ] Build horizontal scaling for analyzers
- [ ] Build load balancing
- [ ] Build distributed database configuration
- [ ] Build local database deployment
- [ ] Build central database deployment
- [ ] Build hybrid local/central database
- [ ] Build platform-specific storage routing

### 12.2 Reliability

- [ ] Build health checking
- [ ] Build queue monitoring
- [ ] Build automatic failover
- [ ] Build data loss prevention
- [ ] Build SNMP alerting
- [ ] Build disk space monitoring
- [ ] Build backlog queue management

### 12.3 Security

- [ ] Build AES-128 encryption
- [ ] Build MD5 with RSA signing
- [ ] Build access control
- [ ] Build permission management
- [ ] Build forensic evidence integrity
- [ ] Build court-admissible data handling

### 12.4 Data Extraction

- [ ] Build external database export
- [ ] Build external file export
- [ ] Build Web Service export
- [ ] Build MQ export (WebSphere MQ, JMS, MSMQ)
- [ ] Build email/SMS alert export

---

## Phase 13: Testing & Quality Assurance (Weeks 57–60)

### 13.1 Unit Testing

- [ ] Write unit tests for all modules
- [ ] Achieve 80%+ code coverage
- [ ] Automate test execution

### 13.2 Integration Testing

- [ ] Test network sensor to analyzer flow
- [ ] Test endpoint agent to server flow
- [ ] Test DLP blocking
- [ ] Test response actions
- [ ] Test all integrations

### 13.3 Performance Testing

- [ ] Test with 500 users
- [ ] Test with 10,000 users
- [ ] Test with 100,000 users
- [ ] Test high-volume data capture
- [ ] Test real-time alerting latency
- [ ] Test search performance
- [ ] Test replay performance

### 13.4 Security Testing

- [ ] Penetration testing
- [ ] Vulnerability scanning
- [ ] Encryption verification
- [ ] Forensic integrity testing

### 13.5 Compliance Testing

- [ ] GDPR compliance testing
- [ ] HIPAA compliance testing
- [ ] PCI-DSS compliance testing
- [ ] SOC 2 compliance testing
- [ ] CCPA compliance testing
- [ ] FINRA compliance testing

### 13.6 User Acceptance Testing

- [ ] Investigator workflow testing
- [ ] Auditor workflow testing
- [ ] Compliance officer workflow testing
- [ ] Administrator workflow testing
- [ ] End-user notification testing

---

## Phase 14: Deployment & Documentation (Weeks 61–64)

### 14.1 Deployment

- [ ] Build installer for network sensors
- [ ] Build installer for endpoint agents
- [ ] Build installer for analyzers
- [ ] Build installer for databases
- [ ] Build installer for web UI
- [ ] Build deployment automation
- [ ] Build upgrade mechanism
- [ ] Build rollback mechanism

### 14.2 Documentation

- [ ] Expand local setup notes into complete deployment and role-specific guides
- [ ] Write installation guide
- [ ] Write administrator guide
- [ ] Write investigator guide
- [ ] Write auditor guide
- [ ] Write compliance guide
- [ ] Write API documentation
- [ ] Write troubleshooting guide
- [ ] Write release notes

### 14.3 Training

- [ ] Create administrator training
- [ ] Create investigator training
- [ ] Create auditor training
- [ ] Create compliance training
- [ ] Create video tutorials

---

## Phase 15: Post-Launch Support (Ongoing)

### 15.1 Monitoring

- [ ] Monitor system health
- [ ] Monitor performance metrics
- [ ] Monitor security events
- [ ] Monitor user feedback

### 15.2 Maintenance

- [ ] Bug fixes
- [ ] Security patches
- [ ] Performance optimization
- [ ] Database maintenance

### 15.3 Updates

- [ ] Rule library updates
- [ ] Threat intelligence updates
- [ ] Compliance updates
- [ ] Feature enhancements

---

## Summary: Total Features to Implement

| Phase | Features | Count |
|-------|----------|-------|
| Phase 1 | Data Capture (Network + Endpoint + New) | 20 |
| Phase 2 | Data Analysis (Including OCR, Website Categorization) | 8 |
| Phase 3 | Profiling, Scoring, Alerting (Including Threat Library) | 16 |
| Phase 4 | Investigation & Case Management | 12 |
| Phase 5 | Data Loss Prevention & Active Blocking (Including Linux) | 11 |
| Phase 6 | Real-Time Response & Automation (Including Forcible Actions) | 8 |
| Phase 7 | Identity & Access Management | 8 |
| Phase 8 | User Privacy & Anonymization | 1 |
| Phase 9 | User Education & Policy Notification | 1 |
| Phase 10 | Compliance & Audit | 1 |
| Phase 11 | Scalability & Reliability | 1 |
| Phase 12 | Security & Data Integrity | 1 |
| Phase 13 | Deployment & Documentation | 1 |
| Phase 14 | Post-Launch Support | 1 |
| Total | 100 | 100 |
|    |    |    |     |
