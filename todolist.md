# EFMTT 2.1 — Programmer Implementation Todo List

## Complete Development Roadmap

### Checklist reconciliation — 4 October 2026

This update implements and verifies the Phase 7 application controls, editable roles, configured login-hour alerts, and privileged recording linkage. It also corrects stale AD/PAM, indicator-library and transport-security entries. The full file remains a wider multi-platform roadmap with many outstanding items; this reconciliation does not certify every existing checked item. External-service configuration, host deployment, published catalogs and unmeasured performance targets remain open. Current code, targeted tests and the documented limitations take precedence over older narrative claims.

### Current implementation — 4 October 2026

The local Investigation Center supports case creation and review, notes, conclusions, evidence attachments, alert linking, case scoring, filtering, custom case fields, routing rules, link analysis, and CSV/Excel/PDF reports. Login protects case, alert, evidence, report, and import APIs. Administrators create accounts; administrators and investigators can make changes; viewers have read-only access. New case activity and evidence uploads use the signed-in username.

Activity CSV imports validate and retain source events, skip identical duplicates, reject conflicting IDs, and roll back the whole upload on invalid data. Two initial rules generate alerts: exports of at least 1,000 records (score 70), and USB/cloud transfers of at least 10,485,760 bytes (score 80). The Activity & alerts inbox supports review, dismissal, and linking alerts to cases. Investigators can also collect text and binary files, logs, XML, SQLite tables, fixed or delimited layouts, and queue messages. Imported activity also raises review alerts for large browser downloads, named cloud-sync destinations, network shares, archives, and encrypted files. Email metadata imports record sender, recipient domain, attachment name, size, and an encrypted flag, and traffic summaries raise review alerts for unusual protocols, flows of at least 100 MB, and flows with at least 100 connections. Signed-in users can change their password. Administrators can disable accounts, keep one administrator enabled, and set a replacement password. Evidence files store a SHA-256 hash that can be checked later. Review thresholds are editable, and three or more login failures in one activity import raise one alert. A case timeline lists the notes, alerts, files, and activity already stored on that case. Saved reports keep the current search, status, minimum score, sort, and selected columns, and a case package downloads the PDF, timeline, and attached evidence. A scheduled inbox scan runs while the server is up, and imported users are matched to entities already stored on alerts. The endpoint agent package covers Windows, Linux, and macOS collectors for files, USB, clipboard, print-job metadata, screenshots, processes, windows, idle time, registry changes, Citrix client presence, and private-browsing markers. All twenty implemented collectors are registered and report whether they can actually collect on the host, naming any missing optional library and the command that installs it; `python -m endpoint_agent doctor` prints that matrix and can gate a deployment, and on this workstation it reports 7 of 20 usable. A test walks the collectors directory and fails if any module on disk is missing from the catalog, so a new collector cannot silently go unreported. Collectors that capture window titles, clipboard contents, screen images, user activity, or input timing stay disabled until an operator enables them by name. The `rdp` collector reports session connect and disconnect metadata — who connected, when, and from where — and captures no screen content. Hiding from Task Manager, resisting uninstall, archiving every printed page, and recording RDP or Citrix desktops are not in that package. Investigators can read text from PNG and JPEG files already attached to a case. The reading keeps the Tesseract language and average word confidence, and Image text on the case list searches those readings. A business process names an ordered set of screens. Each screen is identified by text markers and can capture fields by line and column. Saving an image reading, or submitting a transcript that follows the screen order, records an audit row and the field values. Uploaded captures can name a message-identifying field, search decoded values, list records in order, and step through reconstructed terminal screens. A website visit import maps hostnames onto 42 categories, totals time spent, and raises a review alert when the category is denied. A saved message layout can frame each record with a 2- or 4-byte length and skip an envelope before the fields. Uploaded captures reassemble complete IPv4 fragments, treat a TCP SYN as a new session, skip a chunked HTTP/1 body, and name the standard FIX header tags. The capture engine offers libpcap/Npcap, PF_RING, and DPDK behind one interface, and a backend that is missing its prerequisite reports that rather than quietly falling back, so a deployment is never told it is running on DPDK when it is not. A capture profile declares a mirror or tap source with a VLAN allow-list and promiscuous mode. Per-protocol decoder coverage is self-declared and shown beside each result, naming what stays opaque, because a decoder that has only seen synthetic fixtures can look finished without being right against a real host. Analytic rule versions aggregate stored facts with sum, count, min, or max, including a recheck of facts already imported. The Analytics dialog also saves list, text, after-hours, department, terminal, beneficiary, and ordered-step rules, and can test a version before saving it. Each new finding adds that rule's score to the entity. The running total and each change are kept, and crossing the configured threshold opens one Risk score alert. Ten behavioral indicators average stored facts over the trailing 90 days, and a writer can add another indicator. Each user's baseline is the mean and standard deviation of earlier periods. A latest period above that band, after enough earlier activity, opens one Behavior baseline alert for that period. Phone, email, chat, and system events for one user are listed together. A rising transfer trend, a heavy workload, a stored turnover signal, and stored sentiment signals each open one review alert for that week. Work, meeting, and idle minutes are totaled from stored facts. A synthetic profile publishes indicator averages under a token. Users can be compared with peers in the same department or role, and with a named group. Eight starter library rules from NIST, MITRE, CERT, and FS-ISAC can be disabled or given a new threshold. DLP review inspects submitted text for customer, financial, and intellectual-property markers, and the match count follows the user's risk score. USB serials, cloud hosts, file renames and moves, permission changes, and submitted command logs can each open a review alert. Allow lists skip the USB, cloud, and permission alerts. A playbook can notify a user, queue an email or SMS message, open a custom ticket, and open an incident. Resolving the incident closes the linked alert. Messages stay in the Investigation Center, repeat messages for the same alert are throttled, and an unacknowledged notice can be escalated. A local trigger can be confirmed. A local response executor applies operator allow-listed containment actions: process termination with a PID-reuse guard, host network isolation with declared management-server exceptions, file and Windows System Restore snapshots, verified rollback, and a live response view. Every one of those steps is recorded on the case timeline with the operator's reason attached, and an action may only be filed under a case that already holds an alert from that same endpoint. `GET /api/response/capabilities` states for each control whether the agent can enforce it or only observe it, and names the real enforcement point; account lockout, email, print, clipboard, USB, cloud-upload, and share blocking are not agent-side controls and need Active Directory, the mail transport, Group Policy, a print server, or a DLP proxy. Containment is operator-driven: playbook automation can notify and escalate on a violation but does not dispatch response commands unattended.

Stored captures also reconstruct a 24x80 TN5250 screen subset, name SMB commands and SNA BIND, UNBIND, and ACTLU, and record cleartext HTTP/2 frame headers, an MQSTR body, an MSMQ base header, a plaintext FTP data-channel match, and limited TDS, SQL*Net, DRDA, FIX, SWIFT, and ISO 8583 fields. Encrypted content stays opaque. Layout import accepts IBM COBOL COMP and COMP-3 sizes, MSVC-style C alignment, and a 2- or 4-byte length prefix. A suppression or whitelist rule marks a matching new open alert suppressed. A saved route assigns that alert and writes an in-app notice; mail, SMS, and outside systems are not contacted. Related alerts lists an entity with two or more open or linked alerts. A case report can list each custom field. Administrators can record access, portability, erasure, consent, and opt-out requests, archive facts past a 6-to-12-month window, and export the privacy audit. Those records are a local register, not a legal certification.

**Verification:** Four hundred six automated tests passed, with two skipped: PF_RING and DPDK are Linux-only, and POSIX file modes are not meaningful on this Windows host. Coverage includes case workflow, custom fields and routing, link analysis, attachments and report exports, saved report columns, case packages, role permissions, session expiry and logout, password change, account disabling, evidence hashes, configurable thresholds, authenticated attribution, import validation and rollback, file, log, XML, SQLite, layout, and queue collection, scheduled inbox scan, alert correlation, duplicate handling, exfiltration-channel thresholds, email metadata, traffic summaries, alert-to-case linking, image-text readings with confidence and search, screen definitions that record a navigation audit with field values, message identification and search on uploaded captures, website category time, policy alerts, and reports, business-rule previews with risk-score history, behavioral averages, baselines, channel views, threat and workload scores, synthetic profiles, the starter rule library, and DLP review of submitted text, devices, files, permissions, and commands. Transport security is covered by real TLS handshakes against a generated certificate authority, including rejection of an untrusted certificate, rejection of a certificate issued for the wrong name, mutual TLS, and a live uvicorn HTTPS listener serving the API. Collector availability is covered by tests asserting that a missing optional dependency is reported with its module name and install command, that an inert collector cannot tick, that capture collectors stay opt-in, and that platform restrictions stay distinct from missing modules. No coverage percentage, production readiness, or compliance certification is claimed. Later checks of alert suppression and routing, report field drilldown, compliance records, and the stored-capture decoders passed on their own. On 4 October 2026, five further stored-capture tests passed: plaintext IMAP and POP3 headers, an NFSv3 WRITE hash, tactic search for impact, discovery, persistence, lateral movement, and collection, and reapplying the current rules to one stored capture. The local Investigation Center at http://127.0.0.1:8765/ is the supported test for that work. The recorded full-suite count remains 406 passed and 2 skipped.

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
  - [ ] Add certificate rotation and expiry alerting.
- Active Directory implementation is recorded under done list 7.6; live domain-controller validation remains open below.
- The Linux pam_exec adapter is recorded under done list 7.7; native-host deployment validation remains open below.
- [ ] Implement audit logging for all system access

---

## Phase 1: Network Sniffing & Data Capture (Weeks 5–12)

### 1.1 Network Sensor Development

**Status:** Three capture backends, a mirror/tap capture profile, twenty protocol classifications, message layouts, evidence encryption, and health reporting are implemented and tested offline. Three things are deliberately *not* claimed: live capture has never run on this machine because Npcap is absent, the PF_RING and DPDK adapters are unbenchmarked because their tests only run on Linux, and no decoder output has been checked against a capture from a real mainframe or midrange host. Decoder coverage is self-declared in `network_sensor/protocols.py::CAPABILITIES`, which states per protocol what is decoded and what stays opaque; the UI shows that same string so an investigator sees the limit next to the result. Open **Network captures** for authenticated upload, session/message review, original capture download, stored screen replay, and decoder coverage. See [network_sensor/README.md](backend/network_sensor/README.md) for setup, commands, and resource limits.

- Build packet capture engine (libpcap, PF_RING, DPDK)
  - [ ] Install Npcap and verify live capture on the deployment interface. — **Npcap is installed here and version detection works: Npcap 1.89, based on libpcap 1.10.7.** This corrects an earlier claim in this file that Npcap was absent; that claim came from `npcap_version()` crashing on `os.close_handle(...)`, which is not a real API (`os.add_dll_directory` returns a closable object, not a handle), so the check had never actually succeeded. Live capture on a real deployment interface is still unverified — offline classic-PCAP and pcapng ingest are tested, including malformed, truncated, and out-of-order input, but no interface-level capture has been exercised.
  - [ ] Implement and benchmark PF_RING and DPDK backends on Linux. — Both adapters exist behind the same interface and report their missing prerequisite instead of falling back to libpcap, so a deployment never believes it is running on DPDK when it is not. No throughput figures exist and their tests skip off Linux.
- Implement mirror port and tap device support
  - [ ] Verify capture against the actual mirror/tap hardware and VLAN setup. — No SPAN port or tap device is attached to this host. The configuration path is tested; not one packet has been validated against real mirror hardware or a VLAN-tagged capture.
- [ ] Build protocol decoders — coverage is uneven by design, and the gaps are stated rather than papered over:
  - IBM Mainframe 3270 (SNA, TN3270, Enterprise Extender)
    - [ ] Verify screen reconstruction against representative captures from a real host. — The order set is implemented from the published specification and exercised against synthetic data. Until it is replayed against a capture from a real 3270 host, field placement could still be wrong in ways synthetic fixtures cannot reveal.
  - [ ] IBM iSeries 5250 (SNA, TN5250, MPTN) — partially done: stored TN5250 clear-unit and write-to-display streams render on a 24x80 screen including SBA, IC, MC, RA, EA, and SF. Structured fields, SNA, and MPTN are not reconstructed.
    - [ ] Implement 5250 orders/screens, SNA and MPTN decoding against representative captures. — Orders and screens are implemented; SNA and MPTN framing are outstanding.
    - [ ] Decode LU session state and request/response payloads against representative captures.
  - [ ] SMB, HTTP, HTTPS, Web Services — partially done. HTTP/1.x headers, URLs, chunked-body handling, and cleartext HTTP/2 frame length/type/stream id; SMB1/SMB2 command names and SMB2 message IDs; TLS record headers.
    - [ ] Add HTTP/2/3, web-service schemas, SMB operations/files, and encrypted-content decoding. — HPACK and HTTP/3 are unavailable, SMB file bytes stay in the original capture, and TLS content is not decrypted.
  - [ ] Telnet/VT100, SSH — partially done. Telnet negotiation stripping and VT100 erase, cursor, and saved-cursor rendering on stored plaintext.
    - [ ] Complete terminal control coverage and support authorized decrypted SSH streams. — SSH yields an identification banner only. Decrypted SSH is not implemented: it requires capturing session keys from endpoint memory, which is a different and more invasive capability than decoding a PCAP, and it is not built here.
  - [ ] FTP — partially done. Plaintext control lines, PORT/PASV/EPSV data-channel bytes, and a RETR/STOR transfer summary.
    - [ ] Reconstruct FTP data-channel transfers and handle encrypted FTP variants. — TLS-wrapped FTP is metadata-only.
  - [ ] Oracle SQLNET, DB/2 DRDA, MS SQL TDS — partially done. TDS headers with a UTF-16LE SQL batch joined across packets; Oracle Net packet type with one ASCII statement span inside a data packet; DRDA DSS header and known code point.
    - [ ] Implement query/value/parameter decoders, multi-packet application framing, and encrypted variants. — TDS login/prelogin and encrypted content, DRDA SQL text and values, and encrypted Oracle Net all stay opaque. Oracle Forms is identified by configured port and recorded opaquely.
  - [ ] SWIFT, FIX, ISO8583 — partially done. FIX tag-value framing with BodyLength, CheckSum, required header tags, and encoded-data lengths; SWIFT MT block lengths and tag text; ISO 8583 MTI, bitmap presence, and values for fields named in a supplied length map.
    - [ ] Implement SWIFT and ISO8583 fields using the deployment's message specifications and captures; currently opaque recording only. — SWIFT and ISO 8583 field values depend on a per-deployment specification. ISO 8583 decodes only fields covered by a supplied length map and leaves the rest opaque; a SWIFT block that does not begin with `{1:}` is not parsed.
- [ ] Implement real-time screen reconstruction for thin clients — not implemented. Reconstructed screens are stored after the fact from a capture, with an explicit notice that no original screen recording is linked and that per-screen timestamps are unavailable.
  - [ ] Add a streaming browser viewer for reconstructed screens. — Replay is served from stored frames; there is no live stream.
  - [ ] Implement full TN5250 screen reconstruction. — Partial: see above.
- [ ] Implement SNMP health alerts — partially done: SNMPv2c notifications with the community read from the environment, health transitions, and a configurable enterprise OID. The shipped default uses the documentation-reserved enterprise number 32473 and a deployment must set its own registered OID.
  - [ ] Verify delivery against the deployment's SNMP manager; configure its enterprise OID/community. — Encoding is unit-tested against a locally built packet. No SNMP manager has received one of these traps.
  - [ ] Add SNMPv3 authentication/encryption and a registered MIB. — SNMPv3 is not implemented; only v2c community strings are supported, which are cleartext on the wire.

**Layout-library validation:** Two additional tests verify immutable named versions, duplicate rejection, automatic decoding on capture review, enable/disable behavior, authentication and role restrictions, incomplete-stream skipping, invalid-record diagnostics, and per-report resource budgets.

**Evidence handling:** A capture is encrypted as one authenticated stream bound to its key identity and link type, so a re-labelled file cannot be substituted for the original without detection. This protects captures at rest; it is unrelated to decrypting TLS or SSH *inside* a capture, which is not implemented.

**Validation:** One hundred fifty-seven automated tests across the capture, decoder, layout, session, mainframe, pcapng, and traffic-analysis modules passed, with one skipped where a backend is Linux-only. They cover packet parsing, VLAN/IPv6, malformed and truncated captures, retransmission, out-of-order, wrap, gap and conflict handling, connection reuse, a midstream flow without SYN, monitoring selection, FIX header checks, terminal and TN5250 screens, HTTP/2 frame headers, SMB command names, MQ/MSMQ/TDS/SQL*Net/DRDA/SWIFT/ISO 8583 metadata, plaintext FTP data-channel matching, layout dialects, health transitions and SNMP encoding, recording integrity, and API permissions. **Three claims are deliberately left unverified:** live driver capture (no Npcap on this host), real-host 3270/5250 screen reconstruction (no capture from a real mainframe), and real SNMP-manager delivery (no manager to receive a trap). A decoder that has only ever seen synthetic fixtures is exactly the kind of thing that looks finished and is not, so those boxes stay unticked until someone runs them against the deployment.

### 1.3 Endpoint Agent Development
- [ ] Validate the resolved gaps against real hosts running each optional library. — `python -m endpoint_agent doctor` produces the per-host matrix and is the intended instrument for this: on this workstation it reports 7 of 20 collectors usable and names each missing library with an install command. What cannot be done here is confirm the collectors work on a host that *has* those libraries, which is the only way to show the dependency declarations are correct rather than merely plausible.
- [ ] Implement stealth mode (invisible in Task Manager) — **not implemented, and not planned.**
  - [ ] Hide the process from Task Manager.
- [ ] Implement tamper-proof installation — **not implemented, and not planned.**
  - [ ] Resist uninstall or service removal.
- [ ] Store a copy of every printed page — **not implemented, and not planned as a blanket default.** Listed here previously as a sub-item of tamper-proof installation, which misfiled it: retaining printed output is a capture-policy question, not a resistance question. Blanket archival sweeps up medical, financial, and privileged legal material indefinitely and without the user's knowledge. The narrow alternative is implemented instead: a bounded, hashed copy of the *source* document, retained only when a configured term matches, with every capture and skip decision reported (see Feature 80).
- [ ] Build RDP session recording — **not implemented, and not planned.**
  - [ ] Record the remote desktop.
  - [ ] Record the Citrix desktop.

**Collector availability:** A collector whose dependency is missing produces no events at all, which is indistinguishable from a host where nothing happened, so the gap is reported rather than only logged. All 20 implemented collectors are registered through `collectors/catalog.py` (previously three were constructed inline and seventeen never appeared in any report). Each declares `requires`, resolved per platform by `effective_requires()`, so a macOS-only module is not reported missing on Linux and a Windows-only module is not reported missing on macOS. Missing requirements are reported per collector with an install command, and the worker heartbeat carries the aggregate. A test walks the collectors directory and fails if any module on disk is absent from the catalog, so a newly added collector cannot silently go unreported the way seventeen previously did. Seventeen tests cover the registry, opt-in defaults, platform-versus-dependency distinctions, catalog completeness, and the `doctor` command.

**Session inventory is not session recording:** The `rdp` collector reports `rdp_connect` and `rdp_disconnect` events — session type, remote address, and timing, from WMI/CIM, `loginctl`, or an equivalent backend. It captures no screen content of any kind. Knowing which accounts connected to a host, when, and from where is ordinary endpoint inventory and is what makes an intrusion reconstructable; recording what was on the screen is a different capability and is absent from the package.

**Deliberately not implemented:** Hiding the agent from Task Manager, resisting uninstall or service removal, keeping a copy of printed pages, and recording RDP or Citrix desktops are all absent from the package. These capabilities are what malware and unwanted monitoring tools do; they defeat the administrator's ability to see, stop, or remove the agent, and hidden capture of another user's desktop or printed output is surveillance rather than evidence collection. Acceptable substitutes are already partly in place: `install`, `update --rollback-on-fail`, and `uninstall` are documented and reversible, `self_monitor_exclude` makes the watchdog's own processes visible, and capture collectors (`clipboard`, `screenshot`, `window`, `idle`, `usb`, `incognito`, `biometrics`) require an explicit per-collector opt-in that is recorded in the collector status. If session-level video is genuinely required, capture it with visible, consented, policy-governed recording and retain it only for the retention period the organisation already applies to other endpoint telemetry.

### 1.5 Email Attachment & Content Monitoring
- [ ] Validate classic Outlook COM permissions and the selected Thunderbird stores on target machines. — Requires a Windows mailbox profile and a real Thunderbird store; neither exists in this environment, so only the capture code paths have been exercised.
- [ ] Validate current Gmail/Outlook DOM layouts and install the native messaging host. — Gmail and Outlook webmail markup changes without notice, so a decoder validated only against a fixture will eventually read the wrong fields. This needs a check against the live pages on the deployment's browser version.
- [ ] Validate actual removable drives, network shares and each configured cloud sync root. — Needs the deployment's real devices and share paths; the code enumerates what it is given and has never been pointed at real hardware.

**These three remain open by nature, not by neglect.** Each requires a target machine with the relevant application profile, browser, or storage attached. Marking them done from this environment would assert a validation that was never performed.

### 1.6 Network Traffic Analysis
- [ ] Add a built-in threat intelligence feed. — **Deliberately absent.** Malware and C2 address matches use operator-supplied indicators only. Shipping or bundling a feed implies freshness and coverage the product cannot promise, and a stale bundled list is worse than an empty one because it looks authoritative.
- **Stated limits:** every finding is an indicator requiring investigation, because a legitimate periodic service can resemble a callback; analysis covers only retained TCP/UDP sessions, so packet loss, filters, and retention limits reduce coverage; byte counts are observed transport payload including retransmissions, not wire bandwidth or decrypted content. These limitations are returned with the findings and shown to the user rather than being buried here.

---

## Phase 2: Data Analysis Engine (Weeks 13–18)

### 2.1 Free-Text Indexing
- Implement Elasticsearch/Solr indexing
  - [ ] Verify against a running Elasticsearch deployment. — The adapter contract, outage, retry, and partial-failure paths are tested against simulated responses. **No Elasticsearch instance has ever been connected to.** Mapping choices, bulk indexing throughput, and real partial-failure behaviour are unverified, so the adapter should be treated as untested against a live cluster until someone points it at one.
- [ ] Add Solr support. — Not implemented, and deliberately so. A third index backend would be a second adapter to keep correct, and the SQLite default already covers the product's needs; Solr only earns its place if a deployment actually requires it.
- [ ] Add language-specific analyzers. — Stemming is not implemented. A query ending in ~ already matches one edit, and language=en, fr, de, or es drops a short stopword list. Those parts are in the done list.

### 2.2 Optical Character Recognition (Feature 61)
- Integrate OCR engine (Tesseract, ABBYY)
  - [ ] Integrate ABBYY. — Not implemented. ABBYY is a commercial engine with its own licensing and deployment; Tesseract covers the OCR need at no cost. Add it only if a deployment already licenses it.
- Extract text from screenshot images
  - [ ] Automatically OCR screenshots as the collector produces them. — Not implemented. Reading runs when an investigator saves a reading, not on the ingest path. Automatically OCR-ing every captured frame as it arrives would cost CPU on every screenshot whether or not anyone ever looks at it.

### 2.3 User Process Analysis

The implemented capability here reconstructs business-process activity **from evidence already in hand** — an image already attached to a case, or a transcript an investigator submits. It does not watch a desktop. That boundary is deliberate and is the same one applied to desktop recording elsewhere in this document.

- Build field-level audit trail
  - [ ] Derive read and update actions from a live keystroke feed. — **Not implemented, and not planned.** Deriving field actions from a live keyboard tap is passive surveillance of a person's working session, which is a different thing from reconstructing a transaction from evidence under investigation. The submitted-transcript path delivers the same audit value — "this user approved a transfer that bypassed the four-eyes rule" — without the monitoring.
- Build navigation scenario capture
  - [ ] Capture a user's live navigation. — Not implemented. The operator supplies the screens; the system verifies and audits them rather than watching them happen.
- [ ] Build real-time screen checking. — Not implemented. It presupposes a live desktop feed, which this package does not have.

### 2.4 Thin vs. Fat Client Support
- [ ] Build thin-client screen reconstruction — partially done. TN5250 clear-unit and write-to-display streams render on a 24x80 screen including SBA, IC, MC, RA, EA, and SF orders; 3270 reconstruction covers the published order set including the two-byte DO forms.
  - [ ] Reconstruct full TN5250 screens. — Outstanding: structured fields, SNA, and MPTN framing are not reconstructed.
- [ ] Build visual screen replay for thin clients — stored replay is served from stored frames with an explicit notice when no original screen recording is linked and when per-screen timestamps are unavailable, so a reconstructed screen is never presented as a recording.
  - [ ] Stream a live terminal viewer. — Not implemented. Replay is historical; there is no live stream.
  - [ ] Infer protocol envelopes from raw traces without a declared layout. — Not implemented. Inference from a raw trace is a research problem with real misattribution risk; requiring the layout to be declared is the safer contract for evidence.

### 2.5 Website Categorization (Feature 72)
- Build URL capture from network and endpoint
  - [ ] Capture URLs from HTTPS traffic. — **Not possible by design, and not implemented.** Without decryption, which this product does not do, a TLS stream exposes only SNI and certificate names. Only cleartext HTTP host and path are recoverable from a capture.

---

## Phase 3: Profiling, Scoring & Alerting (Weeks 19–24)

### 3.4 Behavioral Indicators (Feature 22)
- Implement 150+ behavioral indicators
  - [ ] Reproduce a specific published 150-indicator vendor catalog. — Not attempted. Copying a named catalog would imply its detection fidelity, which cannot be asserted without the vendor's own validation data. The 160 first-party indicators are honest about what they measure.

### 3.10 Behavioral Biometrics (Feature 28)

**Correction:** an earlier revision of this document stated that keystroke rhythm, mouse movement, and typing-cadence capture were "not part of this Investigation Center." That is no longer true and has been corrected. What is captured is **aggregate timing geometry only** — never keystroke content and never screen coordinates.

- **Consent and limits, which are the point of this feature:** collection is opt-in per collector, requires an enabled binding plus current endpoint consent, and stops the listeners and returns nothing when consent is withdrawn. Retention expires the samples and deletes the baseline rather than leaving a stale profile usable. Every biometric alert is deduplicated to one per window and carries the caveat that **device, workload and accessibility changes can explain this signal; verify with independent evidence** — a new keyboard, a different laptop dock, or an accessibility tool will all move these numbers.

### 3.11 Synthetic Data Analytics (Feature 29)
- Build GDPR-compliant analytics
  - [ ] Claim GDPR compliance. — **No, and this must not be presented as compliance.** A synthetic aggregate is not a lawful basis, a data-processing agreement, a retention policy, or a DPIA. Selling or deploying on the strength of a "GDPR-compliant" label would be a false assurance; this export is a demonstration and comparison aid and nothing more.

### 3.14 Insider Threat Library (Feature 73)
- [ ] Reproduce a specified published 320-indicator catalog. The publisher/source has not been supplied. The implemented library contains 328 rules: eight illustrative starters plus 320 first-party window/target variants over 80 signals. These are recorded in the done list and are not represented as a vendor catalog or independently validated detections.

### 3.15 Alerting
- **But delivery is in-product only.** A playbook `email` or `sms` step renders a notice template, throttles a repeat of the same notice for one alert, and writes an in-product `Notice` row for the message centre, escalating if it goes unacknowledged. There is **no SMTP client and no SMS gateway** anywhere in the alert path — IAM SMS delivery is separate from the alert-notification path. So an alert reaches an operator by opening the message centre, not by arriving in their inbox or phone. Treat these as *routing* complete and *transport* outstanding.
- [ ] Build MQ/Web Service alert delivery — not implemented. Outbound notification currently targets the in-product message centre only. This is the same gap recorded under 6.7 External System Triggering: the inbound MQ and web-service triggers are outstanding, and outbound delivery would need a real transport with retry and dead-lettering rather than a fire-and-forget call.
- [ ] Build alert correlation across sources — not implemented as automatic clustering. Related alerts are grouped for a human by shared entity, case, and channel rather than merged by the system. Automatic correlation is where false positives multiply, so grouping stays a judgement call unless a deployment can validate a specific rule.
---

## Phase 5: Data Loss Prevention & Active Blocking (Weeks 31–36)

Configured-file snapshots/backup/restore with hash verification, plus optional native Windows System Restore. Native restore schedules a restart and stays pending until Windows-reported post-boot verification; neither scope is a full disk image.

Deployment validation remains:
- [ ] Validate interactive desktop consent/capture/control on a Windows test endpoint.
- [ ] Validate firewall isolation, DNS/management exceptions and local recovery on that endpoint.
- [ ] Validate native Windows System Restore and post-reboot reconnect/verification on a disposable test endpoint.

### 5.2 USB Device Detection & Blocking (Feature 2)
- [ ] Build data transfer blocking
- USB transfer blocking is not part of this Investigation Center.

### 5.3 Clipboard Monitoring (Feature 3)
- [ ] Build clipboard blocking — not built; prevention belongs to Group Policy or MDM.
- **Correction:** an earlier revision claimed clipboard capture was "not part of this Investigation Center." Capture, cross-application tracking, and review of a stored preview are implemented. Blocking is what is actually absent.

### 5.4 Cloud Upload Blocking (Feature 4)
- [ ] Build upload interception
- [ ] Build personal cloud drive blocking
- [ ] Build GenAI tool blocking
- Upload interception and destination blocking are not part of this Investigation Center.

### 5.5 Email Attachment Interception (Feature 5)
- [ ] Build attachment blocking — not built; mail transport rules are the enforcement point.
- [ ] Build email quarantine — not built; same reason.
- **Correction:** an earlier revision claimed message-body scanning was "not part of this Investigation Center." That was wrong — body and attachment content scanning are both implemented. Blocking and quarantine are what is genuinely absent.

### 5.6 Print Control (Feature 6)
- [ ] Build print restriction — not built; print-server or driver policy is the enforcement point, and an agent-side veto cannot stop a job already spooled.
- [ ] Build print content inspection — declined. Inspecting rendered page content is a materially larger privacy intrusion than job metadata; the approved scope under Feature 80 is policy-scoped *source-document* capture under explicit policy, not silent inspection of everything printed.

### 5.10 Screenshot Blocking (Feature 10)
- [ ] Build screenshot blocking — not built; blocking is a hardening and policy matter for the endpoint, not something an agent can reliably interpose on.

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
- [x] Build ServiceNow integration — incident creation and state update in `app/ticketing.py`, against the documented Table API (`POST`/`PUT` on `/api/now/table/incident`). Basic auth when a user and secret are both configured, OAuth bearer for a token on its own.
- [x] Build Jira integration — issue creation via `/rest/api/2/issue`, and status changes posted as a real transition. Jira does not accept a status name, so the connector looks the transition id up on the issue and reports the available transitions when the target state does not exist, rather than assuming an id.
- [ ] Build Remedy integration — **not built, on purpose.** BMC Remedy has no stable public REST endpoint for incident creation; it needs an ARCM form or an ITSM bridge. Coding a plausible-looking URL would produce a connector that silently never works, so `ZANAQ_TICKET_SYSTEM=remedy` is refused with a log line pointing at the `webhook` target instead.
- [x] Build a generic webhook bridge target — covers any other ITSM, including a Remedy ARCM bridge, without pretending to know its API.
- The `ticket` step still writes a local `Ticket` row, and pushing outward is now explicit and opt-in (`push` on ticket create/update) rather than a side effect. `Ticket` carries `external_id`, `external_ref`, `pushed_at`, and `last_error`, so a failed push is visible on the ticket instead of only in a log the investigator never sees.
- Two properties are deliberate and tested. **Credentials live in the environment only** (`ZANAQ_TICKET_*`), never in the database, so a backup does not hand over the ITSM account. **Alert detail does not leave the deployment by default**: the payload is title plus internal reference unless `ZANAQ_TICKET_INCLUDE_DETAIL` is set, because pushing an alert body into third-party SaaS is a data-egress decision, not an integration detail. Re-pushing a ticket that already has an `external_id` is refused, so a retry cannot create a duplicate incident.
- What is deliberately absent: webhook ticket creation, outbound webhooks, bulk sync, and any inbound ticket webhook.

### 6.6 Email/SMS Alerts (Feature 36)
- [x] Deliver email and SMS notices outside the center — `app/delivery.py` provides SMTP with STARTTLS and authentication, plus a generic HTTP SMS transport. Retries use bounded exponential backoff; a 4xx or an authentication failure is recorded as permanent rather than retried, because it will fail identically every time.
- Delivery is **allowlisted**: recipients are administered in-product and an alert's `entity_ref` is never used as a target, so an exfiltration event cannot decide who it notifies. Credentials come from the environment only. With nothing configured the attempt is recorded as not sent and the playbook continues, so a missing relay degrades rather than aborting a response.
- Still not built: delivery/read receipts, bounce webhooks, attachment transmission, and a verified sender domain.

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

Implementation details and checked items are in [done-todolist.md](done-todolist.md#phase-7-identity--access-management-weeks-4143). Remaining deployment/coverage work:

- [ ] Validate SMS delivery against the configured provider and a real handset; automated tests substitute delivery.
- [ ] Validate LDAPS authentication, certificates and synchronization against the deployment's domain controller; directory tests use fixtures.
- [ ] Expand AD nested/primary-group membership if required; current mapping uses direct memberOf groups.
- [ ] Deploy and verify the Linux pam_exec adapter on a host with a recovery session. A custom native PAM .so is not supplied or required by the adapter.
- [ ] Add FIDO2/WebAuthn/smart-card support if required; the implemented hardware factor is provisioned OATH HOTP.
- [ ] Validate privileged desktop recording on an enrolled endpoint with consent. Request/approval/recording/stop paths are implemented; native video has not been exercised in this run.
- [ ] Add per-case/tenant row isolation if required. Implemented access isolation is by module/data domain.
- [ ] Add a credential vault and a native SSH/RDP session gateway if required. PAM grants authorize admission; expiry does not terminate an existing OS session.

---

## Phase 8: User Privacy & Anonymization (Weeks 44–45)

### 8.1 User Anonymization / Privacy Mode (Feature 76)
- [ ] Build GDPR-compliant anonymization. Restricted views are pseudonymized. The status text says they are not certified anonymous data. These outputs remain personal data.

---

## Phase 10: Compliance & Audit Support (Weeks 48–50)

### 10.1 GDPR Compliance (Feature 46)
- The parent stays open: these are working local mechanisms, and none of them make the processing lawful on their own.

### 10.2 HIPAA Compliance (Feature 47)
- [ ] Validate production transmission security and remote compliance destinations. HTTPS server configuration, certificate verification and optional encrypted evidence storage exist; deployment configuration and remote-service validation remain required.

### 10.3 PCI-DSS Compliance (Feature 48)
- [ ] Build network security — not implemented; the local application performs no network segmentation, and `CONTROLS["gaps"]` records "No live network blocking."
- [ ] Build vulnerability management — not implemented. No scanner, no dependency audit, no patch programme; `CONTROLS["gaps"]` says "No vulnerability scanner."

### 10.4 SOC 2 Type II (Feature 49)
- These five map one-to-one onto `CONTROLS` keys (`security`, `availability`, `integrity`, `confidentiality`, `privacy`), which are served as narrative control descriptions at `/api/compliance/controls`. The parent stays open because a control *description* is not a Type II report: no auditor has tested operating effectiveness over a period, which is the entire point of Type II.

### 10.7 Exportable Audit Logs (Feature 52)
- [x] Build log format customization — CSV, JSONL, CEF, and RFC 5424 syslog output in `app/audit_export.py`, with column selection, optional `{field}` templates validated against the chosen columns, per-schedule intervals, and an incremental `last_id` watermark so each run emits only new rows.
- CEF escaping is not cosmetic: a pipe inside an actor name would otherwise shift the extension boundary, so the seven fixed header fields are escaped separately from the key=value extension. Syslog newlines are flattened and the PRI is derived from action severity.
- Exports are atomic (written to a temporary file, then moved) and **refuse to clobber**: each run's filename carries its timestamp and watermark, so two runs in the same second cannot silently overwrite an earlier export. Filenames and total body size are bounded, and templates are admin-only.
- Local files remain the default and the only always-on path. Forwarding to a SIEM is a separate, explicit opt-in described at 11.1.

### 10.9 Data Archiving (Feature 54)
- Aging honours legal hold per entity, so evidence under an open case is never aged out from under an investigation.

**Compliance validation:** One automated test covers access and portability export, legal-hold refusal, erasure of facts and archives, consent, impact notes, supervisory review, masked SSN and card review, 6-month aging, archive tamper detection, CSV column selection, and the non-administrator refusal. The parents stay open because this is a local record set, not a certification, vulnerability program, or transmission-security proof.

---

## Phase 11: Integration & Extensibility (Weeks 51–53)

Outbound integrations are now real, and all of them follow the same shape: configured **from the environment only**, **off unless configured**, **bounded**, and **one-way**. The credential for each lives in `ZANAQ_*` environment variables and never enters the database, so a backup does not hand over the SIEM, ITSM, mail, or SMS account; none of them can be turned on by writing a row.

What exists: Splunk HEC and CEF/syslog forwarding for **audit** events (11.1), ServiceNow and Jira ticketing plus a generic webhook bridge (6.5), and SMTP/SMS alert delivery (6.6).

What still does not: no inbound path at all — nothing is ever pulled in, so there is no threat-intelligence intake, no ticket webhook, and no bidirectional sync. No Teams/Slack/WhatsApp, no social platform, no geolocation primitive, and no native QRadar, Asana, or Monday.com client. Kafka, RabbitMQ and MQ Series are still not connected, consistent with ADR-4 in `app/foundation.py` (intake is authenticated upload plus an inbox folder).

### 11.1 SIEM Integration (Feature 55)
- [x] Build Splunk integration — audit rows forwarded as newline-delimited JSON to an HEC collector (`app/siem.py`). The row content matches what the local export selects, but HEC carries structured JSON rather than the CEF/syslog framing, so it is not a byte-for-byte copy of a local CEF file.
- [x] Build ArcSight integration — CEF and RFC 5424 syslog framing are ArcSight's native formats, and both are sent over UDP or TCP.
- [ ] Build QRadar integration — **partial.** CEF/syslog forwarding reaches a QRadar syslog collector, but QRadar's own REST collector API is not implemented. The HEC transport is only usable where an HEC-compatible receiver exists.
- [x] Build custom SIEM integration — the target is configurable, and framing is shared with the local export rather than reimplemented, including the schedule's export template. For the **syslog** transports the forwarded copy is byte-identical to the local file except for the hostname field, which comes from `ZANAQ_SIEM_HOSTNAME` instead of the local `socket.gethostname()`; HEC forwards the row as JSON, so byte comparison applies only to syslog targets.
- [x] Build event forwarding — for **audit** events, which is what the export schedule already selects. Forwarding of alerts, endpoint events, and evidence is not built.
- [ ] Build bidirectional sync — not started. There is no inbound path, so no threat intelligence or case state comes back from a SIEM.
- Forwarding is **off unless configured** (`ZANAQ_SIEM_TARGET` unset means disabled) and off per schedule unless `forward_to_siem` is set, so configuring a local export never silently starts egress. The credential is read from the environment only and never enters the database or an API response; TLS verification is on by default and can only be relaxed explicitly. Rows per request, body size, and time per attempt are all bounded.
- When a forward fails, the schedule's watermark is **deliberately not advanced** so the next run retries. That re-exports the same rows locally, duplicating a file, because for an audit trail a duplicate export is recoverable and a silently dropped remote copy is not.
- Still not built: threat-intelligence ingestion (see 12.x), alert and incident forwarding, SIEM-side deduplication, and delivery confirmation beyond HTTP status.

### 11.2 API Export (Feature 56)
- [ ] Build GraphQL API — **declined by ADR-2**: "Clients use the REST API. GraphQL and gRPC are not served." The REST API is the whole external surface. This is a recorded architecture decision rather than an oversight, so the box stays unticked with the reason attached instead of implying unfinished work.

### 11.4 Project Management Tool Integration (Feature 58)
- [x] Build Jira integration — the Jira connector from 6.5 is the same code; see there for the creation and transition mechanics.
- [ ] Build Asana integration
- [ ] Build Monday.com integration
- Asana and Monday.com are not started. What exists is the Jira path plus a generic webhook bridge target, which is enough to reach an ITSM that fronts either product but is not a native Asana or Monday.com client.

### 11.5 Custom Web/App Monitoring (Feature 59)
- [ ] Build custom screen capture — screenshots and replay frames exist, but capture is not configurable per application; there is no "watch this app" concept.
- [ ] Build custom event generation — event types are registered in code (`schemas.py`), not defined by an operator at runtime. Extending the schema still means a code change and a release.

### 11.6 Geographic Productivity Comparison (Feature 60)
- [ ] Build location tracking
- [ ] Build productivity metrics by location
- [ ] Build office vs. remote comparison
- [ ] Build geographic reporting
- **Declined.** No location is ever captured — there is no geolocation primitive anywhere in the agent or the server. Continuous staff location tracking is disproportionate for forensic work, and "productivity by location" is a management metric that invites scoring staff on presence rather than investigating conduct. Location relevant to an investigation can be established from network and account evidence, which this product does collect.

### 11.7 Instant Messaging Monitoring (Feature 62)
- [ ] Build Teams integration
- [ ] Build Slack integration
- [ ] Build WhatsApp integration
- [ ] Build message content capture
- [ ] Build IM policy enforcement
- **Declined.** No IM integration, and message *content* capture is not built for any channel. Reading private conversations is the most intrusive category in this roadmap and would need per-platform consent and works-council agreement to justify; the mail path in Feature 81 was built to a bounded, policy-scoped standard instead.

### 11.8 Social Media Monitoring (Feature 63)
- [ ] Build social media detection
- [ ] Build usage tracking
- [ ] Build brand reputation monitoring
- [ ] Build policy violation alerting
- **Declined.** Nothing here exists. "Brand reputation monitoring" in particular implies scraping public social platforms on someone else's behalf, which is a different product with different legal exposure, and none of it serves a forensic investigation.

### 11.9 Geolocation Tracking (Feature 66)
- [ ] Build device location capture
- [ ] Build anomalous login detection
- [ ] Build location-based policies
- [ ] Build geographic reporting
- **Declined**, for the same reasons as 11.6. Note that authentication *is* logged, so impossible-travel and unusual-hour analysis remain available from login records — but only without a location claim, which is the part that would be disproportionate.

---

## Phase 12: System Administration & Infrastructure (Weeks 54–56)

### 12.1 Scalability
- [ ] Build horizontal scaling for sensors
- [ ] Build horizontal scaling for analyzers
- [ ] Build load balancing
- [ ] Build distributed database configuration
- [ ] Build central database deployment
- [ ] Build hybrid local/central database
- [ ] Build platform-specific storage routing

### 12.2 Reliability
- [ ] Build automatic failover
- [ ] Build data loss prevention
- [ ] Build SNMP alerting

### 12.3 Security
- [ ] Build AES-128 encryption
- Factor secrets are sealed with Fernet. Evidence files are stored with a SHA-256 hash. The database volume is not encrypted by this application.
- [ ] Build MD5 with RSA signing
- MD5 signatures are not created.
- [ ] Build court-admissible data handling
- A stored hash shows whether a file still matches. It is not a finding that a record is admissible in court.

### 12.4 Data Extraction
- [ ] Build external database export
- [ ] Build MQ export (WebSphere MQ, JMS, MSMQ)

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
- [ ] Build installer for network sensors — not packaged. The sensor runs from the source tree or the container image; there is no capture-driver installer, and the live-install path still needs the Npcap/libpcap/PF_RING/DPDK prerequisites validated on a real host.
- [ ] Build installer for databases — not applicable as written. Per ADR-3 the local database is embedded SQLite, so there is no database server to install. A managed PostgreSQL or TimescaleDB deployment would be a different architecture, not a missing installer.
- [ ] Build deployment automation — none. `.github/workflows/tests.yml` runs CI **tests**; nothing builds, publishes, or rolls out an image, and there is no Ansible, Terraform, or compose configuration.
- [ ] Build upgrade mechanism — **partially addressed.** There is still no version comparison, no upgrade path, and no release packaging. What now exists is the part that actually destroys data: `app/schema.py` applies an **additive** migration derived from the models at startup (`ensure_schema`), so a database that predates a new table or column is repaired instead of failing later inside an unrelated request. This replaces a hand-maintained `ensure_sqlite_columns` mapping that only ever listed the columns someone remembered to add, and which never ran on any dialect but SQLite — seven `case_id` columns had been added to models and were missing from it. Everything it cannot do safely is reported rather than forced: it never drops, renames, or retypes a column, and a type mismatch is logged as drift instead of being coerced, because narrowing a live column can destroy evidence. Add Alembic to `requirements.txt` if a versioned, reversible history is wanted; the current mechanism is idempotent and additive, not a migration ledger.
- [ ] Build rollback mechanism — none, and it is the pair to upgrade that matters most here. A forensic platform that can be upgraded but not returned to a known state is a liability when the prior version's behaviour is itself evidence. Note that the additive migration above is deliberately one-directional: it will not undo itself, which is the correct default here and exactly why rollback still needs a real answer.

### 14.2 Documentation
- [ ] Expand local setup notes into complete deployment and role-specific guides — not done. `backend/README.md` is 273 lines and documents *features* well (TLS, imports, alerts, network sensor, content search, privacy mode, live analytics, biometrics, reporting), but there are no role-specific guides for anyone.
- [ ] Write installation guide — the scripts exist without a written guide. The README covers `pip install` and a TLS note, but there are no prerequisites, no first-run steps, and no "getting started" path.
- [ ] Write administrator guide
- [ ] Write investigator guide
- [ ] Write auditor guide
- [ ] Write compliance guide — partially covered by the README's "Alerts, reports, and compliance records" section, but that describes the product rather than guiding an auditor through an examination.
- [ ] Write troubleshooting guide — absent entirely; no troubleshooting section exists in any document.
- [ ] Write release notes — no `CHANGELOG` or release-notes file. `done-todolist.md` (1209 lines of completed tasks) is a de facto change record and would be the raw material, but it is organised by feature rather than by version, so nobody can answer "what changed in 1.3?" from it.

### 14.3 Training
- [ ] Create administrator training
- [ ] Create investigator training
- [ ] Create auditor training
- [ ] Create compliance training
- [ ] Create video tutorials
- No training material of any kind exists. Worth noting what *is* built: the education module (`/api/education/`) can publish a policy notice, record employee acknowledgement, and record **training completion** against a warning. So the tracking rail for a training programme exists and is exercised by tests — but there is no curriculum to put through it. That module is the natural host for training content later.

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
| Phase 10 | Compliance & Audit Support | 9 |
| Phase 11 | Integration & Extensibility | 9 |
| **TOTAL** | | **80+** |

---

## Priority Matrix

### Critical (Must Have – Phase 1-3)
- Network sniffing and protocol decoding
- Endpoint agent deployment
- Data collection and normalization
- Free-text indexing and search
- User process analysis
- Business rules and alerting
- Case management
- Visual replay

### High Priority (Should Have – Phase 4-6)
- DLP and blocking
- Real-time response
- Behavioral analytics
- Compliance support
- SIEM integration

### Medium Priority (Nice to Have – Phase 7-9)
- Identity management
- Privacy features
- User education

### Low Priority (Future – Phase 10-11)
- Advanced integrations
- Custom monitoring
- Geographic analytics

---

**Document Version:** 1.4
**Last Updated:** 4 October 2026
**Owner:** Mascall Investments Private Ltd
**Classification:** Internal – Development Use Only

---

## Competitive feature addendum

Tasks brought across from [add-features.md](add-features.md).

## SECTION A: TERAMIND GAP FEATURES

### A1. Dedicated Citrix / XenApp / XenDesktop Session Recording

**Feature 78: Complete Citrix Virtual Desktop Recording**

- **Requirement:** Capture full visual screen recordings of Citrix XenApp and XenDesktop sessions.
- **Specification:**
  - [ ] Capture at 1–30 FPS (configurable)
  - [ ] Store ICA/HDX protocol sessions
  - [ ] Reconstruct visual desktop for replay
  - [ ] Capture audio channel (optional)
  - [ ] Capture clipboard activity within Citrix
  - [ ] Capture USB redirection activity
  - [ ] Capture printer redirection activity
  - [ ] Capture file transfer within Citrix sessions
  - [ ] Support StoreFront and Web Interface
  - [ ] Support Citrix Cloud and on-premises
  - [ ] Provide session search by user, time, application
  - [ ] Provide visual replay identical to physical desktop replay
  - [ ] **Replace SmartAuditor / Citrix Session Recording** (position as direct replacement)

### A2. Automated Real-Time Response Actions

**Feature 79: Automated Lockout and Blocking**

- **Requirement:** Automatically block or lock out users in real-time when policy violations occur.
- **Specification:**
  - [ ] Automatic user lockout (temporary or permanent) — belongs to the identity provider; an agent-side flag would leave the user able to authenticate elsewhere.
  - [ ] Automatic session termination — the agent terminates processes it owns; ending a whole session is a session-manager operation.
  - [ ] Automatic application blocking — process termination and an agent deny-list are feasible; neither prevents a user running a copy from elsewhere.
  - [ ] Automatic file transfer blocking — the agent observes transfers; blocking belongs to the file server or DLP proxy.
  - [ ] Automatic email blocking (send prevention) — mail transport rules. A send click observed by the agent is intent, not delivery.
  - [ ] Automatic print blocking — print server or driver policy; jobs spool outside the agent's control.
  - [ ] Automatic clipboard blocking — Group Policy clipboard restrictions.
  - [ ] Automatic USB blocking — device access control; an agent can restrict itself, which raises cost but does not prevent use of the same media elsewhere.
  - [ ] Automatic cloud upload blocking — proxy or DLP gateway.
  - [ ] Automatic network share blocking — SMB share permissions.
  - [ ] Configurable lockout duration — n/a until lockout exists.
- **Deliberately not built: unattended containment.** Playbooks can already trigger on `dlp`, `upload`, `print`, `email`, and `download` alerts, but their only steps are notification and escalation (`notify`, `email`, `sms`, `ticket`, `incident`). Nothing dispatches a response command without a human. That is the honest state of this feature: the containment machinery exists and is operator-driven, and wiring it to fire unattended is a separate decision.
- **Why that default should probably change, carefully.** `GET /api/response/capabilities` marks each control `automatable`, and only process termination currently qualifies. Isolation is deliberately excluded because isolating a host with no automatic release path strands the user offline until someone notices. Before isolation becomes automatable it needs a bounded duration and automatic release. Desktop input injection (`control_input`) must never be automatable: firing clicks and keystrokes at a person's workstation with no human in the loop is not a response action.

### A3. Native Print Capture & Storage

**Feature 80: Printed Document Capture & Archival**

- **Requirement:** Capture and store copies of all printed documents for forensic review.
- **Specification:**
  - [ ] Capture print spooler output — **not implemented, and not planned.** Requires a native Windows port-monitor DLL registered with the spooler; the intercepted bytes are usually a proprietary driver stream, not a viewable document.
  - [x] Store printed document as PDF/image — **replaced by policy-scoped source capture.** Archiving every printed page indefinitely, without the user's knowledge, sweeps up medical, financial, and privileged legal material. A bounded, hashed copy of the *source* document is retained only when a configured term matches **and** the source was actually located.
  - [ ] Search printed documents by content (OCR) — retained copies are scanned for text and indexed, but no OCR engine is applied to printed images.
  - [ ] Block sensitive document printing — feasible as policy (blocking is the opposite of stealth) but needs enforcement at the print driver or a print server, not an agent-side event.

**Print coverage:** `print.py` reads the Windows spooler through `win32print` and CUPS through `lpstat`, recording printer name and location, user, document title, status, pages, bytes, and — where the platform supplies it — copies, colour, and duplex. Fields a platform cannot report are emitted as `null` rather than omitted. CUPS support is real, not aspirational: `effective_requires()` drops the `win32print` dependency off Windows, so the collector is not incorrectly reported as Windows-only.

Policy-scoped capture lives in `endpoint_agent/print_policy.py`: with no `sensitive_terms` configured the collector stays metadata-only. A match on the spooler title or the resolved source retains a copy bounded at 25 MB, hashed with SHA-256, in a local `PrintArtifactStore` (`app` never receives the bytes — the store is explicitly not an upload channel). Source lookup is a best-effort stem match bounded to configured `source_roots` (2,000 files), so documents elsewhere on disk are never read and escaping symlinks are refused.

Two rules exist because a policy match is not by itself evidence that a copy was taken. **A title match whose source cannot be resolved is a `skip`, not a `capture`** — there are no bytes behind it, and the server treats `capture` as grounds for a sensitive-print alert. **Where nothing is retained** (no artifact directory configured, over the limit, or the store is full) the event and the resulting alert both say so explicitly rather than implying a copy exists. Retained copies are expired by the agent on its own retention clock, because the server can expire the event but cannot reach bytes on the endpoint.

Every decision is reported as a `print_document` event with `capture` or `skip` and a reason, so absent coverage stays explainable; only a capture alerts.

**Unverified:** the copies/colour/duplex fields derive from the Windows DEVMODE and have not been exercised against a live spooler, because pywin32 is absent from the agent environment here. Confirm with `doctor` plus a test print on target hardware before relying on them.

### A4. Native Email Content & Attachment Capture

**Feature 81: Full Email Content & Attachment Capture**

- **Requirement:** Capture full email content and attachments within endpoint monitoring.
- **Specification:**
  - [ ] Support Outlook (desktop, web, mobile) — desktop and web are covered; mobile is not possible from a desktop agent.
  - [ ] Support Exchange / Office 365 — not via Microsoft Graph; covered only indirectly where Outlook desktop or the webmail extension applies.
  - [ ] Support IMAP/SMTP/POP3 — Thunderbird's own IMAP cache is read, but there is no direct IMAP/SMTP/POP3 collector. Stored plaintext IMAP, SMTP, and POP3 headers from an uploaded capture are in the done list.
  - [ ] Block sensitive email sending — a Send click records intent, not delivery; actual send blocking needs a mail-flow or transport-layer control.

**Email coverage:** Most of this feature is already implemented. `mail_capture.py` reads the running user's classic Outlook MAPI session through pywin32 and explicitly selected Thunderbird mbox/maildir/EML stores; it never launches Outlook or sends mail. Gmail and Outlook webmail are captured by a Chrome/Edge extension through a local native messaging host, reading the visible page in an admin-distributed, consented profile — not by injecting into other users' web sessions or reading credentials. Analysis records sender, To/Cc/Bcc, normalized recipient domains, direction, timestamp, body, and bounded attachment findings with SHA-256 fingerprints; duplicate captures are rejected on retry. `search_index.py` indexes body, sender, recipient domains, and attachment text, so mail is full-text searchable. `mail_analysis.py` raises findings for sensitive content, external recipient domains, large attachments, and confirmed encryption, and investigators can additionally import EML files manually. **Outstanding:** Exchange/Office 365 through Microsoft Graph with OAuth, a direct IMAP/SMTP/POP3 collector, Yahoo webmail, mobile mail, and OCR of printed images. Mobile capture is not possible from a desktop agent and would need a separate consent-governed mobile agent.

### A5. File Sharing Behavior Monitoring

**Feature 82: File Sharing Behavior Monitoring**

- **Requirement:** Monitor and control file sharing behavior across all channels.
- **Specification:**
  - [ ] Monitor file sharing via network shares — not monitored agent-side. SMB/CIFS appears only in `enforcement.py` as a description of an *external* enforcement point (file server, Group Policy). No share-mount or UNC-path collector exists.
  - [ ] Monitor file sharing via instant messaging (Teams, Slack, WhatsApp) — declined; see 11.7.
  - [ ] Monitor file sharing via P2P — no BitTorrent or P2P protocol handling exists in the sensor.
  - [ ] Monitor file sharing via screen sharing — no screen-share detection exists.
  - [ ] Block unauthorized file sharing — declined. Prevention belongs to the mail transport, file server, print server or DLP proxy; an agent can observe a transfer but cannot interpose on one. See 6.8.
  - [ ] Report on file sharing patterns — no dedicated cross-channel sharing report. The data needed to build one is collected; the roll-up view is not.
  - [ ] Identify top sharers — no ranking or leaderboard view. Treat this as a deliberate omission worth keeping: "top sharers" is a productivity-scoring instrument, and an investigation should start from a specific allegation rather than from a league table.

### A6. Personal Email Provider Detection & Blocking

**Feature 83: Personal Email Provider Detection & Blocking**

- **Requirement:** Detect and block use of personal email providers for work data.
- **Specification:**
  - [ ] Detect Zoho Mail access — absent from the provider list.
  - [ ] Detect Yandex Mail access — absent.
  - [ ] Detect Mail.ru access — absent. (A `mail.ru` string appears elsewhere in `observations.py`, but it is not wired into `PUBLIC_MAIL`.)
  - [ ] Detect GMX access — absent.
  - [ ] Block access to personal email providers — declined. Web filtering is a proxy/DNS enforcement point, not an agent capability; see 6.8.
  - [ ] Report on personal email use — no dedicated report. Alerts are searchable and aggregatable, but no per-user or per-domain personal-mail report exists.

  **Honest scope:** this detects personal mail as a *recipient* domain on captured mail, not a user browsing to Gmail. Browser-side webmail access is only visible as a visited host, and only for providers on the list. Four of the ten named providers are missing, so "detect personal email providers" is closer to "detect the common ones."

### A7. User Behavior Anomaly Detection with Automated Response

**Feature 84: Behavior Anomaly Detection with Automated Response**

- **Requirement:** Automatically detect and respond to behavioral anomalies.
- **Specification:**
  - Configured UTC login-hour alerts are implemented and recorded in done list A7. A learned per-user time-of-day baseline remains outstanding.
  - [ ] Detect unusual login locations — declined. No geolocation exists anywhere in the product (see 11.9); this cannot be built without first capturing location, which is disproportionate.
  - [ ] Detect unusual application usage — not implemented. No application-usage baseline or inventory rule exists.
  - [ ] Automatic lockout on severe anomaly — **not implemented, and this is the item most likely to cause harm if added casually.** Agent-side lockout is also ineffective: the user can authenticate on another host, so it locks a screen rather than an account, which is worse than appearing to work because it looks like enforcement. A real lockout belongs to AD/IdP (see 6.8). If agent-side containment is ever added it must be opt-in globally, allowlisted, cooldown-limited, actor-attributed, exempt administrators, and auto-release.
  - [ ] Automatic session termination on severe anomaly — **not implemented, deliberately.** Process termination exists as an operator action; automating it against a scored anomaly risks killing a legitimate session on a false positive. This should not ship without the same safeguards as the lockout above.

  **Honest scope:** the detection half of this feature is largely real and configurable. The *automated response* half is notification-only. The two "automatic lockout" and "automatic session termination" boxes are the substance of the feature title, and neither is built — for defensible reasons, given that a false positive would either fail to contain or disrupt a legitimate session.

---

## SECTION B: OBSERVEIT / PROOFPOINT ITM GAP FEATURES

### B1. Unified Investigation Console

**Feature 85: Unified Investigation Console**

- **Requirement:** Provide a single console that correlates screen captures, file movements, application usage, and threat data.
- **Specification:**
  - [ ] Correlate screen captures with IM activity — impossible: no IM data is collected at all (see 11.7).
  - [ ] Correlate screen captures with threat intelligence — no threat-intelligence integration exists (see B5).
  - [ ] Correlate screen captures with email sender reputation — no sender reputation service exists (see B5).

  **Honest scope:** correlation is by shared endpoint, entity, and time window — not a learned or causal linkage. Nothing asserts that a screenshot *caused* a file transfer, and the product should not imply that it does.

### B2. Lightweight Endpoint Agent

**Feature 86: Lightweight Endpoint Agent**

- **Requirement:** Provide an endpoint agent that minimizes productivity impact.
- **Specification:**

**Every quantitative performance target below is unmeasured.** There is no CPU, memory, disk, network or boot-time instrumentation in the agent — no `psutil`-based self-monitoring, no benchmark harness, no performance test of any kind. These boxes cannot honestly be ticked in either direction: nobody has demonstrated the targets are met, and nobody has shown they are missed. They stay open pending measurement on real endpoint hardware, which is the same validation gap recorded under 14.1 and Phase 5.

  - [ ] CPU usage < 1% during normal operation — unmeasured.
  - [ ] CPU usage < 5% during peak capture — unmeasured.
  - [ ] Memory usage < 100MB — unmeasured.
  - [ ] Disk usage < 500MB for agent files — unmeasured.
  - [ ] Network usage < 1MB per user per day — unmeasured.
  - [ ] No impact on boot time — unmeasured. Worth noting the design intent that bears on this: the collector default is **off**, with sensitive collectors opt-in, so an unconfigured agent is not polling continuously. That is a design choice that helps, not a measurement.
  - [ ] No impact on application launch time — unmeasured.
  - [ ] No impact on application performance — unmeasured. This one has a real risk factor: the opt-in `screenshot`, `clipboard`, and `biometrics` collectors install OS-level hooks (for example `win32gui.GetForegroundWindow()` polling), and hook cost is exactly what has not been profiled.
  - [ ] No impact on network performance — unmeasured.
  - [ ] No impact on battery life (laptops) — unmeasured, and the collectors most likely to matter here are the continuous-polling ones.
  - [ ] Silent update — no update mechanism exists. The install scripts have no version comparison and no upgrade path, and there is no updater component (see 14.1).
  - [ ] **Zero user complaints about performance** — unverifiable by construction. This is not a software requirement; it is an outcome that only a deployment with real users over real time could produce, and asserting it in a roadmap would be claiming a result nobody has measured.

  **What would actually close this section:** a benchmark harness that runs each collector in isolation and reports CPU, RSS, bytes-on-wire and hook latency, plus a documented default-off posture test. Without that, the entire section is aspiration.

### B3. Flexible Threat Hunting

**Feature 87: Flexible Threat Hunting**

- **Requirement:** Enable custom explorations beyond standard alerts.
- **Specification:**
  - [ ] Share custom queries — no sharing, ACL, or publication mechanism for a saved definition. Each definition belongs to the workflow that created it.
  - [ ] Schedule custom queries — no scheduler for hunts. Note this is the same gap as 3.15's MQ/Web Service delivery: there is no background job runner to execute a query on a cadence.
  - [ ] Alert on custom query results — no rule can be bound to an ad-hoc query result. Alerts come from detection rules and indicator evaluation, not from saved searches.
  - [ ] Export custom query results — search results are not exportable. The only export is the compliance audit CSV (10.7).
  - [ ] Advanced query language for power users — no query DSL. Search is text plus structured filters, which is enough for triage but not for hunt authoring.
  - [ ] Query templates for common hunts — no curated hunt library. The saved-report mechanism could seed one, but no templates ship.

  **Honest scope:** hunting is *possible* and *proactive*, but not *systematic*. An analyst can search and can read indicators; there is no hunt library, no scheduling, and no way to turn a search into a standing detection.

### B4. User Activity Timeline

**Feature 88: User Activity Timeline**

- **Requirement:** Provide a complete timeline of all user activity.
- **Specification:**
  - [ ] IM activity on timeline — no IM data is collected (see 11.7).
  - [ ] Zoom in/out on timeline — no time-scaled visualisation. The timeline is a chronological list with time-range filtering, not a brushable density chart.
  - [ ] Export timeline — no timeline export. Only the compliance audit CSV is exportable (10.7).

### B5. Threat Intelligence Integration

**Feature 89: Threat Intelligence Integration**

- **Requirement:** Integrate threat intelligence to enrich user activity data.
- **Specification:**

**Verified by search: there is no threat-intelligence integration of any kind in this codebase.** No outbound reputation lookup, no feed client, no hash/IP/domain/URL enrichment path. A `virustotal` string does appear in `agent_alerts.py`, but it is in a list of **private-browsing window-title markers** — it detects a user visiting VirusTotal, which is an incognito/private-window indicator, not a reputation service call. Nothing leaves the deployment to query an external service, which is also why there is no secret handling, no caching, and no rate-limit story to document.

  - [ ] Email sender reputation lookup — not implemented.
  - [ ] URL reputation lookup — not implemented.
  - [ ] File hash reputation lookup — not implemented. Attachment SHA-256 is computed for **integrity** (tamper evidence), not looked up anywhere.
  - [ ] IP address reputation lookup — not implemented.
  - [ ] Domain reputation lookup — not implemented.
  - [ ] Threat feed integration — not implemented.
  - [ ] VirusTotal integration — not implemented, despite the misleading string noted above.
  - [ ] AlienVault OTX integration — not implemented.
  - [ ] MISP integration — not implemented.
  - [ ] Custom threat feed integration — not implemented.
  - [ ] Alert on threat intelligence match — no enrichment, so no match to alert on.
  - [ ] Enrich investigation with threat data — no threat data exists to enrich with.
  - [ ] **Context for every investigation** — not met by this feature. Investigations do get context, but it is **locally derived**: endpoint inventory, process and file provenance, network flow and decoded-protocol records, mail metadata, and indicator evaluation. That is meaningful context; it is not threat intelligence.

  **Two things worth separating here.** First, the absence is consistent with the architecture: ADR-4 keeps intake local, and nothing in the design calls out to an external reputation service. Second, if this is ever built, outbound lookups become a **privacy and legal question, not just an integration question** — submitting a hash or IP to a third party leaks information about the investigation, and under GDPR that can itself be a processing activity requiring a lawful basis. Worth settling before writing a connector, not after.

---

## SECTION C: ACTIVTRAK GAP FEATURES

### C1. Privacy-First Data Foundation

**Feature 90: Privacy-First Data Foundation**

- **Requirement:** Build monitoring on a privacy-first foundation.
- **Specification:**
  - [ ] Collect only what is necessary
  - [ ] Anonymize personal data by default
  - Privacy mode starts off. Restricted views are pseudonymized. They are not certified anonymous data.
  - [ ] Mask PII in reports
  - [ ] Mask PHI in reports
  - [ ] Mask PCI data in reports
  - Case downloads keep the stored case text. A separate review can mask an SSN or card number down to the last four digits.
  - [ ] GDPR compliance by design
  - [ ] CCPA compliance by design
  - [ ] **Privacy is default, not an afterthought**

### C2. Workforce Analytics

**Feature 91: Workforce Analytics**

- **Requirement:** Provide analytics on workforce productivity and engagement.
- **Specification:**
  - [ ] Productivity metrics per location
  - [ ] Burnout risk metrics
  - Stored overwork days are a review count. They are not a clinical burnout finding.
  - [ ] AI agent usage metrics
  - [ ] Benchmarking against industry
  - [ ] Actionable recommendations
  - [ ] **Measure impact, not just activity**

### C3. Intuitive User Interface

**Feature 92: Intuitive User Interface**

- **Requirement:** Provide an interface that is easy to use for non-technical users.
- **Specification:**
  - [ ] Modern, clean design
  - [ ] Intuitive navigation
  - [ ] Drag-and-drop functionality
  - [ ] Responsive design (desktop, tablet, mobile)
  - [ ] Accessibility compliance (WCAG 2.1 AA)
  - [ ] Customizable dashboards
  - [ ] Contextual help
  - [ ] Tooltips
  - [ ] Onboarding wizard
  - [ ] Video tutorials
  - [ ] Knowledge base
  - [ ] **No training required for basic use**

### C4. AI Agent Usage Monitoring

**Feature 93: AI Agent Usage Monitoring**

- **Requirement:** Monitor and manage AI agent usage by employees.
- **Specification:**
  - [ ] Detect any local AI agent
  - [ ] Detect any cloud AI agent
  - A submitted hostname is matched against a fixed list. Any other local or cloud agent stays unmatched.
  - [ ] Monitor prompts submitted
  - [ ] Monitor data shared with AI
  - Prompt text and file contents sent to an AI service are not collected.
  - [ ] Block sensitive data shared with AI
  - [ ] Policy enforcement for AI usage
  - [ ] **Shadow AI governance**

---

## SECTION D: LMNTRIX PACKETS / NETWITNESS GAP FEATURES

### D1. Full Packet Capture

**Feature 94: Full Packet Capture (FPC)**

- **Requirement:** Capture full network packets for retrospective analysis.
- **Specification:**

**The requirement's premise does not match the design.** This is not a packet store. The sensor is an **analyze-and-extract** pipeline: `analyze_pcap()` streams records through a worker that decodes what it recognises and produces a report, and the product's durable record is decoded messages and findings, not raw frames. There is a PCAP *writer* (`PcapWriter`) and an encrypted-capture path (`secure_store.py`), but those serve forensic export and evidence capture — not continuous 100% retention. Treating "full packet capture" as a shipped feature would misrepresent both the storage cost and the privacy posture.

  - [ ] Capture 100% of network traffic — not attempted, and it is not a bug. Any SPAN/tap deployment drops packets under load by design; a product that claimed 100% would be claiming something no SPAN deployment can deliver.
  - [ ] Capture at line rate — not attempted. Live capture speed depends on deployment: `engines.py` exposes libpcap/Npcap, PF_RING and DPDK backends, and DPDK is the line-rate path. **Unvalidated** — none of the three has been run against real traffic at rate in this environment.
  - [ ] Capture full packet payload — **partial and lossy by design.** A `truncated` flag is tracked per packet, and `PcapWriter.write()` clips to 65535 bytes. Payload availability depends on what the sensor decoded and what the backend delivered.
  - [ ] Index packets for fast search — the index covers **decoded messages and flows**, not raw packets. There is no per-packet index, so "search packets by content" cannot mean what it appears to mean.
  - [ ] Reconstruct files from packets — no carving, no HTTP object extraction, no file reassembly across objects.
  - [ ] Reconstruct images from packets — no image or media reassembly.
  - [ ] Reconstruct voice from packets — no RTP/audio reconstruction.
  - [ ] Reconstruct video from packets — no video reassembly.
  - [ ] **Zero-day hunting capability** — overstated as stated. Signatures and protocol decoding will not help against genuinely novel threats. What exists is anomaly and C2 analysis over flow and DNS records, which can surface *unusual* traffic without knowing the threat in advance — useful, but it is anomaly detection, not a zero-day guarantee.
  - [ ] **Malware analysis capability** — the sensor detects malware-related network behaviour (C2 callbacks, beaconing, unusual protocols, known-bad infrastructure) but performs no malware analysis: no sandboxing, no static analysis, no detonation, and no file extraction to analyse.

  **The honest one-line version:** this product does network traffic *analysis* with retrospective re-analysis of captures you supply. It is not a packet recording system, and Section D1's framing should not be allowed to imply otherwise. Continuous full-payload retention would also be a substantial privacy and storage decision that belongs to a deployment, not a default.

### D2. Retrospective Threat Hunting

**Feature 95: Retrospective Threat Hunting**

- **Requirement:** Hunt for threats in historical packet data.
- [ ] Search historical packets for malware signatures
- [ ] Apply new ML models to old data
- [ ] **Find threats that were missed**

### D3. File Reconstruction from Network Traffic

**Feature 96: File Reconstruction from Network Traffic**

- **Requirement:** Reconstruct files from captured network traffic.
- [ ] Reconstruct files from HTTPS (with SSL inspection)
- [ ] Reconstruct files from any protocol
- [ ] Scan reconstructed files for malware
- [ ] Block sensitive file transfer
- [ ] **Complete file visibility**

### D4. Command Reconstruction from Network Traffic

**Feature 97: Command Reconstruction from Network Traffic**

- **Requirement:** Reconstruct commands executed over network traffic.
- [ ] Reconstruct SSH commands
- [ ] Reconstruct RDP commands
- [ ] Reconstruct VNC commands
- [ ] Reconstruct any remote command
- [ ] Block suspicious commands
- [ ] **Complete command visibility**

### D5. Session Reconstruction from Network Traffic

**Feature 98: Session Reconstruction from Network Traffic**

- **Requirement:** Reconstruct complete sessions from network traffic.
- [ ] Reconstruct HTTPS sessions
- [ ] Reconstruct SSH sessions
- [ ] Reconstruct RDP sessions
- [ ] Reconstruct VNC sessions
- [ ] Reconstruct any session
- [ ] **Complete session visibility**

---

## SECTION E: MICROSOFT 365 SHADOW AI GAP FEATURES

### E1. Shadow AI Detection & Blocking

**Feature 99: Shadow AI Detection & Blocking**

- **Requirement:** Detect and block unmanaged AI agents on managed devices.
- [ ] Detect OpenClaw
- [ ] Detect ChatGPT Desktop
- [ ] Detect Ollama
- [ ] Detect LM Studio
- [ ] Detect GPT4All
- [ ] Detect Jan
- [ ] Detect Faraday
- [ ] Detect LocalAI
- [ ] Detect any local AI agent
- [ ] Detect any cloud AI agent
- [ ] Detect any AI browser extension
- [ ] Detect any AI desktop app
- [ ] Detect any AI command-line tool
- [ ] Block unmanaged AI agents
- [ ] Allow managed AI agents
- [ ] Whitelist approved AI tools
- [ ] Alert on shadow AI usage
- [ ] Report on shadow AI usage
- [ ] Policy enforcement for AI usage
- [ ] **Governance for the AI era**

### E2. AI Prompt & Response Capture

**Feature 100: AI Prompt & Response Capture**

- **Requirement:** Capture prompts and responses from AI tools.
- [ ] Capture ChatGPT prompts
- [ ] Capture ChatGPT responses
- [ ] Capture Claude prompts
- [ ] Capture Claude responses
- [ ] Capture Gemini prompts
- [ ] Capture Gemini responses
- [ ] Capture Copilot prompts
- [ ] Capture Copilot responses
- [ ] Capture Perplexity prompts
- [ ] Capture Perplexity responses
- [ ] Capture any AI prompt
- [ ] Capture any AI response
- [ ] Store prompts and responses
- [ ] Search prompts and responses
- [ ] Alert on sensitive prompts
- [ ] Alert on sensitive responses
- [ ] Block sensitive prompts
- [ ] **Complete AI interaction visibility**

### E3. AI Data Leakage Prevention

**Feature 101: AI Data Leakage Prevention**

- **Requirement:** Prevent sensitive data from being shared with AI tools.
- [ ] Detect sensitive data in prompts
- [ ] Detect PII in prompts
- [ ] Detect PHI in prompts
- [ ] Detect PCI data in prompts
- [ ] Detect intellectual property in prompts
- [ ] Detect trade secrets in prompts
- [ ] Detect source code in prompts
- [ ] Detect financial data in prompts
- [ ] Detect customer data in prompts
- [ ] Block sensitive data in prompts
- [ ] Alert on sensitive data in prompts
- [ ] Report on sensitive data in prompts
- [ ] **Prevent AI data leakage**

---

## SECTION F: ADDITIONAL FEATURES FROM OTHER COMPETITORS

### F1. Integration with Microsoft Purview

**Feature 102: Microsoft Purview Integration**

- [ ] Sync with Microsoft Purview
- [ ] Share DLP policies
- [ ] Share sensitivity labels
- [ ] Share retention policies
- [ ] Share insider risk data
- [ ] Share audit logs
- [ ] **Unified compliance**

### F2. Integration with Microsoft Defender

**Feature 103: Microsoft Defender Integration**

- [ ] Sync with Microsoft Defender for Endpoint
- [ ] Share threat intelligence
- [ ] Share incident data
- [ ] Share device risk scores
- [ ] Trigger Defender scans
- [ ] Trigger Defender remediation
- [ ] **Unified security**

### F3. Integration with Microsoft Sentinel

**Feature 104: Microsoft Sentinel Integration**

- [ ] Send logs to Sentinel
- [ ] Send alerts to Sentinel
- [ ] Send incidents to Sentinel
- [ ] Receive threat intelligence from Sentinel
- [ ] Receive automation from Sentinel
- [ ] **Unified SIEM**

### F4. Integration with ServiceNow

**Feature 105: ServiceNow Integration**

- [x] Create incidents in ServiceNow
- [x] Update incidents in ServiceNow
- [x] Close incidents in ServiceNow — the local `closed` status maps to the ServiceNow `state` of `7`.
- [ ] Sync case data — not built. What is sent is the ticket title plus an internal reference; case fields and evidence are deliberately excluded unless detail egress is enabled.
- [ ] Sync investigation data — not built.
- [ ] **Unified ITSM**

Implemented in `app/ticketing.py`; see 6.5 for the credential and detail-egress rules.

### F5. Integration with Splunk

**Feature 106: Splunk Integration**

- [x] Send logs to Splunk — audit rows to an HEC collector, on the incremental watermark the export schedule already tracks.
- [ ] Send alerts to Splunk — not built. Forwarding covers audit events only.
- [ ] Send incidents to Splunk — not built.
- [ ] Receive threat intelligence from Splunk — not built. There is no inbound path.
- [ ] **Unified SIEM** — not built. Sending is one-way and audit-scoped; there is no inbound leg, no case-state reconciliation, and no deduplication.

See 11.1 for the forwarding implementation and its bounds.

### F6. Integration with IBM QRadar

**Feature 107: IBM QRadar Integration**

- [ ] Send logs to QRadar — **partial.** CEF and syslog framing reach a QRadar syslog collector, but QRadar's own REST collector API is not implemented, so this is a standards-based path rather than a native one.
- [ ] Send alerts to QRadar — not built.
- [ ] Send incidents to QRadar — not built.
- [ ] Receive threat intelligence from QRadar — not built.
- [ ] **Unified SIEM**

### F7. Integration with ArcSight

**Feature 108: ArcSight Integration**

- [x] Send logs to ArcSight — CEF and RFC 5424 syslog over UDP or TCP. These are ArcSight's native formats, and the framing is the same code the local export uses, so the bytes are identical to a verified local file.
- [ ] Send alerts to ArcSight — not built.
- [ ] Send incidents to ArcSight — not built.
- [ ] Receive threat intelligence from ArcSight — not built.
- [ ] **Unified SIEM**

### F8. Integration with CrowdStrike

**Feature 109: CrowdStrike Integration**

- [ ] Sync with CrowdStrike Falcon
- [ ] Share threat intelligence
- [ ] Share incident data
- [ ] Share device risk scores
- [ ] Trigger CrowdStrike scans
- [ ] Trigger CrowdStrike remediation
- [ ] **Unified endpoint security**

### F9. Integration with Palo Alto Networks

**Feature 110: Palo Alto Networks Integration**

- [ ] Sync with Palo Alto firewalls
- [ ] Share threat intelligence
- [ ] Share incident data
- [ ] Trigger Palo Alto blocks
- [ ] **Unified network security**

### F10. Integration with Cisco

**Feature 111: Cisco Integration**

- [ ] Sync with Cisco Umbrella
- [ ] Sync with Cisco AMP
- [ ] Sync with Cisco Firepower
- [ ] Share threat intelligence
- [ ] Share incident data
- [ ] Trigger Cisco blocks
- [ ] **Unified network security**

# EFMTT 2.2 — Global Forensic Software Feature Integration

---

## SECTION H: MEIYA PICO / SDIC INTELLIGENCE GAP FEATURES (CHINA)

### H1. Asian Mobile Ecosystem Deep Extraction

**Feature 112: Asian Mobile App Deep Parsing**

- **Requirement:** Extract and parse data from native Asian mobile ecosystems where Western tools fail.
- **Specification:**
  - [ ] **WeChat** — full chat history, moments, payments, contacts, files, deleted messages
  - [ ] **QQ** — chat history, Qzone, files, groups, deleted messages
  - [ ] **Alipay** — transaction history, contacts, red packets, financial records
  - [ ] **DingTalk** — enterprise chat, files, approvals, attendance
  - [ ] **Douyin (TikTok China)** — messages, videos, user data
  - [ ] **Weibo** — posts, messages, user data
  - [ ] **Xiaohongshu (Little Red Book)** — messages, purchases, user data
  - [ ] **Baidu apps** — search history, maps, cloud data
  - [ ] **JD.com** — purchase history, payments
  - [ ] **Meituan** — orders, payments, location data
  - [ ] **Huawei HarmonyOS** — native app parsing, system artifacts
  - [ ] **Xiaomi MIUI** — native app parsing, system artifacts
  - [ ] **Oppo ColorOS** — native app parsing
  - [ ] **Vivo OriginOS** — native app parsing
  - [ ] **Localized Android variants** — all Chinese OEM ROMs

### H2. Chinese Mobile Chipset Support

**Feature 113: Chinese Mobile Chipset Extraction**

- **Requirement:** Support extraction from Chinese mobile chipsets.
- **Specification:**
  - [ ] **MediaTek** — full physical extraction, bootloader exploits
  - [ ] **HiSilicon Kirin** — full physical extraction, bootloader exploits
  - [ ] **Unisoc (Spreadtrum)** — full physical extraction
  - [ ] **Allwinner** — full physical extraction
  - [ ] **Rockchip** — full physical extraction
  - [ ] **Qualcomm** — full physical extraction (for Chinese variants)
  - [ ] Support Chinese OEM bootloaders
  - [ ] Support Chinese OEM encryption
  - [ ] Support Chinese OEM file systems

### H3. Mobile Forensic System (MFS) Capabilities

**Feature 114: Mobile Forensic System (MFS) Full Suite**

- **Requirement:** Provide complete mobile forensic extraction and analysis.
- **Specification:**
  - [ ] Bypass device security (PIN, password, pattern, fingerprint, face)
  - [ ] Acquire encrypted partitions
  - [ ] Extract artifact data from all mobile OS
  - [ ] Logical extraction
  - [ ] File system extraction
  - [ ] Physical extraction
  - [ ] Cloud extraction
  - [ ] App-specific extraction
  - [ ] Deleted data recovery
  - [ ] SQLite database parsing
  - [ ] Timeline generation
  - [ ] Report generation
  - [ ] **Massistant** equivalent capability
  - [ ] **Mobile Master** equivalent capability

### H4. Hard Drive & Computer Forensics Workstation

**Feature 115: All-in-One Forensic Workstation**

- **Requirement:** Provide integrated hardware and software forensic workstation.
- **Specification:**
  - [ ] Forensic duplication system
  - [ ] Rapid indexing
  - [ ] Hash matching (MD5, SHA-1, SHA-256)
  - [ ] File carving
  - [ ] Disk imaging
  - [ ] Memory imaging
  - [ ] Write blocking
  - [ ] Chain of custody
  - [ ] Case management
  - [ ] Multi-drive support
  - [ ] High-speed duplication
  - [ ] Error correction

---

## SECTION I: SALVATIONDATA GAP FEATURES (CHINA)

### I1. CCTV / DVR Video Forensics

**Feature 116: CCTV / DVR Video Forensics**

- **Requirement:** Recover fragmented, overwritten, or corrupted surveillance video.
- **Specification:**
  - [ ] Recover deleted video files
  - [ ] Recover overwritten video files
  - [ ] Recover fragmented video files
  - [ ] Recover corrupted video files
  - [ ] Parse proprietary DVR file systems
  - [ ] Parse proprietary NVR file systems
  - [ ] Support all major DVR brands (Hikvision, Dahua, etc.)
  - [ ] Support all major NVR brands
  - [ ] Support Chinese DVR formats
  - [ ] Support Western DVR formats
  - [ ] Reconstruct video timelines
  - [ ] Export video in standard formats
  - [ ] Enhance video quality
  - [ ] **VIP (Video Investigation Portable)** equivalent

### I2. Data Recovery System (DRS)

**Feature 117: Forensic Data Recovery System**

- **Requirement:** Recover data from damaged, formatted, or raw storage.
- **Specification:**
  - [ ] Physical disk extraction
  - [ ] Bad sector bypassing
  - [ ] Formatted partition recovery
  - [ ] Raw partition recovery
  - [ ] Deleted file recovery
  - [ ] File system corruption recovery
  - [ ] RAID reconstruction
  - [ ] SSD recovery
  - [ ] HDD recovery
  - [ ] USB recovery
  - [ ] Memory card recovery
  - [ ] **DRS (Data Recovery System)** equivalent

### I3. Smartphone Analysis System (SPA)

**Feature 118: Smartphone Analysis System**

- **Requirement:** Complete mobile extraction and analysis.
- **Specification:**
  - [ ] All mobile OS support (iOS, Android, HarmonyOS)
  - [ ] All extraction types (logical, file system, physical)
  - [ ] All app parsing
  - [ ] Deleted data recovery
  - [ ] Cloud extraction
  - [ ] Timeline generation
  - [ ] Link analysis
  - [ ] Report generation
  - [ ] **SPA (Smartphone Analysis System)** equivalent

---

## SECTION J: PUGUANG / EFFICIENCY TECHNOLOGIES GAP FEATURES (CHINA)

### J1. Network Forensics

**Feature 119: Network Forensics**

- **Requirement:** Capture, analyze, and investigate network traffic.
- **Specification:**
  - [ ] Full packet capture
  - [ ] Network flow analysis
  - [ ] Protocol analysis
  - [ ] Session reconstruction
  - [ ] File reconstruction
  - [ ] Email reconstruction
  - [ ] Web reconstruction
  - [ ] VoIP reconstruction
  - [ ] Video reconstruction
  - [ ] Intrusion detection
  - [ ] Anomaly detection
  - [ ] Threat hunting
  - [ ] Retrospective analysis
  - [ ] **Puguang** equivalent

### J2. Big Data Law Enforcement Analytics

**Feature 120: Big Data Law Enforcement Analytics**

- **Requirement:** Analyze massive datasets for law enforcement.
- **Specification:**
  - [ ] Petabyte-scale data processing
  - [ ] Distributed computing
  - [ ] Entity resolution
  - [ ] Relationship mapping
  - [ ] Pattern detection
  - [ ] Anomaly detection
  - [ ] Predictive analytics
  - [ ] Social network analysis
  - [ ] Geographic analysis
  - [ ] Temporal analysis
  - [ ] **Puguang** equivalent

### J3. Cloud Evidence Collection

**Feature 121: Cloud Evidence Collection**

- **Requirement:** Collect evidence from cloud services.
- **Specification:**
  - [ ] Chinese cloud providers (Alibaba Cloud, Tencent Cloud, Baidu Cloud, Huawei Cloud)
  - [ ] Western cloud providers (AWS, Azure, Google Cloud)
  - [ ] Cloud storage (Dropbox, OneDrive, Google Drive)
  - [ ] Cloud email (Gmail, Outlook, Yahoo)
  - [ ] Cloud messaging (WeChat, QQ, DingTalk)
  - [ ] Cloud backups (iCloud, Google Backup)
  - [ ] Cloud documents (Google Docs, Office 365)
  - [ ] Cloud social media (Facebook, Twitter, Weibo)
  - [ ] **Puguang** equivalent

---

## SECTION K: ELCOMSOFТ GAP FEATURES (RUSSIA)

### K1. GPU-Accelerated Password Recovery

**Feature 122: GPU-Accelerated Password Recovery**

- **Requirement:** Use multi-GPU acceleration for brute-force attacks.
- **Specification:**
  - [ ] Multi-GPU support (NVIDIA, AMD)
  - [ ] Distributed password recovery
  - [ ] Brute-force attacks
  - [ ] Dictionary attacks
  - [ ] Hybrid attacks
  - [ ] Mask attacks
  - [ ] Rule-based attacks
  - [ ] Rainbow table attacks
  - [ ] **iOS backup decryption**
  - [ ] **Android backup decryption**
  - [ ] **VeraCrypt decryption**
  - [ ] **BitLocker decryption**
  - [ ] **FileVault decryption**
  - [ ] **APFS decryption**
  - [ ] **TrueCrypt decryption**
  - [ ] **LUKS decryption**
  - [ ] **Office document decryption**
  - [ ] **PDF decryption**
  - [ ] **ZIP/RAR/7z decryption**
  - [ ] **EDPR (Elcomsoft Distributed Password Recovery)** equivalent

### K2. iOS Forensic Toolkit

**Feature 123: iOS Forensic Toolkit**

- **Requirement:** Low-level physical extraction of iOS devices.
- **Specification:**
  - [ ] checkm8 exploit support
  - [ ] Custom extraction agents
  - [ ] Physical extraction
  - [ ] File system extraction
  - [ ] Logical extraction
  - [ ] Keychain extraction
  - [ ] Binary token extraction
  - [ ] iCloud extraction
  - [ ] iCloud backup extraction
  - [ ] iCloud photo extraction
  - [ ] iCloud message extraction
  - [ ] iCloud call log extraction
  - [ ] iCloud Safari extraction
  - [ ] **EIFT (iOS Forensic Toolkit)** equivalent

### K3. Cloud Extraction Without 2FA Alerts

**Feature 124: Cloud Extraction Without 2FA Alerts**

- **Requirement:** Extract cloud data without triggering two-factor authentication alerts.
- **Specification:**
  - [ ] Binary token extraction
  - [ ] Authentication token extraction
  - [ ] Session token extraction
  - [ ] iCloud data extraction
  - [ ] Google data extraction
  - [ ] Microsoft data extraction
  - [ ] Dropbox data extraction
  - [ ] **Elcomsoft Phone Breaker** equivalent

---

## SECTION L: BELKASOFT GAP FEATURES (RUSSIA)

### L1. Automated Artifact Discovery

**Feature 125: Automated Artifact Discovery**

- **Requirement:** Automatically scan and index 1,500+ artifact types.
- **Specification:**
  - [ ] Chat histories (all major apps)
  - [ ] Browser caches (all major browsers)
  - [ ] Browser history
  - [ ] Browser cookies
  - [ ] Browser passwords
  - [ ] System logs
  - [ ] Registry hives
  - [ ] Event logs
  - [ ] Prefetch files
  - [ ] Shimcache
  - [ ] Amcache
  - [ ] Jump lists
  - [ ] LNK files
  - [ ] Recycle bin
  - [ ] Thumbnail caches
  - [ ] Email archives
  - [ ] Cloud sync logs
  - [ ] USB history
  - [ ] Network history
  - [ ] Application logs
  - [ ] Database artifacts
  - [ ] SQLite databases
  - [ ] **1,500+ artifact types total**

### L2. RAM & Volatile Memory Analysis

**Feature 126: RAM & Volatile Memory Analysis**

- **Requirement:** Analyze RAM dumps for forensic evidence.
- **Specification:**
  - [ ] Process listing
  - [ ] Process memory analysis
  - [ ] Network connections
  - [ ] Open files
  - [ ] Open registry keys
  - [ ] Loaded DLLs
  - [ ] Injected code detection
  - [ ] Malware detection
  - [ ] Encryption key extraction
  - [ ] Password extraction
  - [ ] Chat message extraction
  - [ ] Browser data extraction
  - [ ] **Belkasoft X RAM analysis** equivalent

### L3. Unified Computer & Mobile Timeline

**Feature 127: Unified Computer & Mobile Timeline**

- **Requirement:** Merge computer and mobile evidence in a single timeline.
- **Specification:**
  - [ ] Windows artifacts on timeline
  - [ ] macOS artifacts on timeline
  - [ ] Linux artifacts on timeline
  - [ ] iOS artifacts on timeline
  - [ ] Android artifacts on timeline
  - [ ] Cloud artifacts on timeline
  - [ ] RAM artifacts on timeline
  - [ ] Cross-device correlation
  - [ ] Cross-device entity resolution
  - [ ] **Belkasoft X unified timeline** equivalent

---

## SECTION M: OXYGEN FORENSICS GAP FEATURES (RUSSIA)

### M1. All-In-One Extraction

**Feature 128: All-In-One Extraction**

- **Requirement:** Extract mobile, computer, IoT, cloud, and drone data in one interface.
- **Specification:**
  - [ ] Mobile extraction (iOS, Android, HarmonyOS)
  - [ ] Computer extraction (Windows, macOS, Linux)
  - [ ] IoT extraction
  - [ ] Cloud extraction
  - [ ] Drone extraction
  - [ ] Single interface
  - [ ] Single case management
  - [ ] **Oxygen Forensic Detective** equivalent

### M2. Regional Messaging App Parsing

**Feature 129: Regional Messaging App Parsing**

- **Requirement:** Deep parsing of regional messaging apps.
- **Specification:**
  - [ ] **Telegram** — chats, channels, groups, files, calls, secrets
  - [ ] **VK** — messages, posts, friends, groups
  - [ ] **WhatsApp** — chats, groups, media, calls, deleted messages
  - [ ] **Viber** — chats, groups, media, calls
  - [ ] **Signal** — chats, groups, media, calls
  - [ ] **Line** — chats, groups, media
  - [ ] **KakaoTalk** — chats, groups, media
  - [ ] **WeChat** — chats, moments, payments
  - [ ] **QQ** — chats, groups, files
  - [ ] **DingTalk** — chats, files, approvals
  - [ ] SQLite database analysis
  - [ ] **Oxygen Forensic Detective app parsing** equivalent

### M3. Drone Data Extraction

**Feature 130: Drone Data Extraction**

- **Requirement:** Extract data from drones.
- **Specification:**
  - [ ] DJI drone extraction
  - [ ] Parrot drone extraction
  - [ ] Autel drone extraction
  - [ ] Skydio drone extraction
  - [ ] Flight logs
  - [ ] GPS tracks
  - [ ] Photos
  - [ ] Videos
  - [ ] Telemetry data
  - [ ] **Oxygen Forensic Detective drone analytics** equivalent

---

## SECTION N: MAGNET AXIOM GAP FEATURES (USA)

### N1. Artifact-First Analysis

**Feature 131: Artifact-First Analysis**

- **Requirement:** Pull high-value application artifacts across all platforms.
- **Specification:**
  - [ ] Chat histories (all major apps)
  - [ ] Cloud storage syncs
  - [ ] Browser activity
  - [ ] System logs
  - [ ] Deleted database records
  - [ ] Windows artifacts
  - [ ] macOS artifacts
  - [ ] iOS artifacts
  - [ ] Android artifacts
  - [ ] Cloud service artifacts
  - [ ] **Magnet AXIOM artifact-first** equivalent

### N2. Unified Case Timeline

**Feature 132: Unified Case Timeline**

- **Requirement:** Aggregate evidence from all sources into a single correlated timeline.
- **Specification:**
  - [ ] Computers on timeline
  - [ ] Smartphones on timeline
  - [ ] RAM dumps on timeline
  - [ ] Cloud backups on timeline
  - [ ] Cross-source correlation
  - [ ] Entity resolution
  - [ ] **Magnet AXIOM unified timeline** equivalent

### N3. GrayKey Integration

**Feature 133: GrayKey Integration**

- **Requirement:** Integrate with GrayKey for hardware-level iOS/Android decryption.
- **Specification:**
  - [ ] GrayKey device integration
  - [ ] Hardware-level iOS decryption
  - [ ] Hardware-level Android decryption
  - [ ] Physical extraction
  - [ ] Full file system extraction
  - [ ] **Magnet AXIOM + GrayKey** equivalent

---

## SECTION O: FTK / EXTERRO GAP FEATURES (USA)

### O1. Distributed Processing & Indexing

**Feature 134: Distributed Processing & Indexing**

- **Requirement:** Process terabytes of data across multiple worker nodes.
- **Specification:**
  - [ ] Centralized database architecture (Oracle/PostgreSQL)
  - [ ] Multi-worker node support
  - [ ] Distributed indexing
  - [ ] Distributed processing
  - [ ] Terabyte-scale datasets
  - [ ] No software crashes on large datasets
  - [ ] Load balancing
  - [ ] **FTK distributed processing** equivalent

### O2. FTK Imager

**Feature 135: Forensic Imaging Utility**

- **Requirement:** Create bit-stream disk images and memory dumps.
- **Specification:**
  - [ ] Bit-stream disk imaging
  - [ ] Memory dump creation
  - [ ] Physical disk imaging
  - [ ] Logical disk imaging
  - [ ] E01 format support
  - [ ] L01 format support
  - [ ] Raw format support
  - [ ] AFF format support
  - [ ] Hash verification (MD5, SHA-1)
  - [ ] Write blocking
  - [ ] **FTK Imager** equivalent

### O3. Remote & Endpoint Forensics

**Feature 136: Remote & Endpoint Forensics**

- **Requirement:** Collect volatile memory and analyze live endpoints.
- **Specification:**
  - [ ] Remote volatile memory collection
  - [ ] Live endpoint analysis
  - [ ] Incident response within corporate networks
  - [ ] Remote agent deployment
  - [ ] Remote evidence collection
  - [ ] **FTK remote forensics** equivalent

---

## SECTION P: OPENTEXT ENCASE GAP FEATURES (USA)

### P1. Deep Disk & File System Analysis

**Feature 137: Deep Disk & File System Analysis**

- **Requirement:** Low-level file system carving and analysis.
- **Specification:**
  - [ ] Low-level file system carving
  - [ ] Volume shadow copy analysis
  - [ ] Raw hex editing
  - [ ] NTFS analysis
  - [ ] FAT analysis
  - [ ] exFAT analysis
  - [ ] HFS+ analysis
  - [ ] APFS analysis
  - [ ] Ext2/3/4 analysis
  - [ ] XFS analysis
  - [ ] Btrfs analysis
  - [ ] **EnCase deep disk analysis** equivalent

### P2. EnScript Extensibility

**Feature 138: Custom Scripting Engine**

- **Requirement:** Allow investigators to write custom scripts for automation.
- **Specification:**
  - [ ] Custom scripting language
  - [ ] Custom artifact parsing
  - [ ] Custom hash matching
  - [ ] Custom data extraction
  - [ ] Script library
  - [ ] Script sharing
  - [ ] Script versioning
  - [ ] **EnScript** equivalent

### P3. Court-Defensible Evidence Format

**Feature 139: Court-Defensible Evidence Format**

- **Requirement:** Provide proprietary evidence formats with chain-of-custody verification.
- **Specification:**
  - [ ] Proprietary evidence file format
  - [ ] Built-in hashing
  - [ ] Chain-of-custody verification
  - [ ] Tamper detection
  - [ ] Court admissibility
  - [ ] **EnCase .E01/.L01** equivalent

---

## SECTION Q: X-WAYS FORENSICS GAP FEATURES (GERMANY)

### Q1. Lightweight Portable Forensics

**Feature 140: Lightweight Portable Forensics**

- **Requirement:** Run from USB in air-gapped environments without installation.
- **Specification:**
  - [ ] Portable executable
  - [ ] No installation required
  - [ ] USB deployment
  - [ ] Air-gapped environment support
  - [ ] Minimal RAM usage
  - [ ] Full hardware speed processing
  - [ ] **X-Ways Forensics** equivalent

### Q2. Low-Level Disk & File System Analysis

**Feature 141: Low-Level Disk & File System Analysis**

- **Requirement:** Superior sector-level inspection and partition reconstruction.
- **Specification:**
  - [ ] Sector-level inspection
  - [ ] Partition reconstruction
  - [ ] Raw hex editing
  - [ ] File carving
  - [ ] Complex file system support
  - [ ] **X-Ways Forensics** equivalent

---

## SECTION R: MSAB / XRY GAP FEATURES (SWEDEN)

### R1. Secure Mobile Acquisition

**Feature 142: Secure Mobile Acquisition**

- **Requirement:** Bypass device locks and extract physical/logical data.
- **Specification:**
  - [ ] iOS extraction
  - [ ] Android extraction
  - [ ] Legacy mobile extraction
  - [ ] Device lock bypass
  - [ ] Physical extraction
  - [ ] Logical extraction
  - [ ] File system extraction
  - [ ] App artifact decoding
  - [ ] **MSAB XRY** equivalent

### R2. Kiosk & Field Solutions

**Feature 143: Kiosk & Field Solutions**

- **Requirement:** Portable units for non-technical officers to acquire mobile evidence.
- **Specification:**
  - [ ] Kiosk hardware
  - [ ] Portable field units
  - [ ] Non-technical operation
  - [ ] Secure acquisition
  - [ ] Crime scene deployment
  - [ ] **MSAB kiosk/field** equivalent

### R3. XAMN Analytics

**Feature 144: Cross-Device Mobile Analytics**

- **Requirement:** Cross-examine and link data across hundreds of mobile extractions.
- **Specification:**
  - [ ] Cross-device correlation
  - [ ] Entity resolution
  - [ ] Link analysis
  - [ ] Timeline analysis
  - [ ] Pattern detection
  - [ ] **MSAB XAMN** equivalent

---

## SECTION S: AMPED FIVE GAP FEATURES (ITALY)

### S1. Forensic Video & Image Enhancement

**Feature 145: Forensic Video & Image Enhancement**

- **Requirement:** Clear up motion blur, low lighting, perspective distortion.
- **Specification:**
  - [ ] Motion blur removal
  - [ ] Low light enhancement
  - [ ] Perspective correction
  - [ ] License plate recognition
  - [ ] Face enhancement
  - [ ] Noise reduction
  - [ ] Sharpening
  - [ ] Stabilization
  - [ ] **Amped FIVE** equivalent

### S2. Court-Admissible Scientific Integrity

**Feature 146: Court-Admissible Video Processing**

- **Requirement:** Record exact mathematical algorithms for reproducibility.
- **Specification:**
  - [ ] Algorithm audit trail
  - [ ] Mathematical reproducibility
  - [ ] Judicial proceedings support
  - [ ] Expert witness support
  - [ ] **Amped FIVE** equivalent

### S3. Proprietary DVR/NVR Format Support

**Feature 147: Proprietary DVR/NVR Format Support**

- **Requirement:** Native conversion and processing for thousands of proprietary formats.
- **Specification:**
  - [ ] Hikvision format support
  - [ ] Dahua format support
  - [ ] Axis format support
  - [ ] Bosch format support
  - [ ] Pelco format support
  - [ ] Samsung format support
  - [ ] Panasonic format support
  - [ ] Sony format support
  - [ ] Thousands of other formats
  - [ ] **Amped FIVE** equivalent

---

## SECTION T: BINALYZE AIR GAP FEATURES (ESTONIA)

### T1. Ultra-Fast Memory & Artifact Capture

**Feature 148: Ultra-Fast Memory & Artifact Capture**

- **Requirement:** Acquire RAM dumps and system artifacts in under 10 minutes.
- **Specification:**
  - [ ] RAM dump acquisition
  - [ ] System artifact acquisition
  - [ ] Under 10 minutes per endpoint
  - [ ] Network-wide deployment
  - [ ] **Binalyze AIR** equivalent

### T2. Automated Endpoint Isolation

**Feature 149: Automated Endpoint Isolation**

- **Requirement:** Automatically isolate compromised hosts.
- **Specification:**
  - [ ] Automatic isolation
  - [ ] Network-wide isolation
  - [ ] Compromised host detection
  - [ ] **Binalyze AIR** equivalent

### T3. Enterprise Timeline Generation

**Feature 150: Enterprise Timeline Generation**

- **Requirement:** Generate timelines across thousands of enterprise workstations.
- **Specification:**
  - [ ] Multi-endpoint timeline
  - [ ] Thousands of workstations
  - [ ] Active cyberattack support
  - [ ] **Binalyze AIR** equivalent

---

## SECTION U: PASSWARE GAP FEATURES (ESTONIA / GERMANY)

### U1. Volume Decryption

**Feature 151: Volume Decryption**

- **Requirement:** Bypass or recover passwords for encrypted volumes.
- **Specification:**
  - [ ] BitLocker decryption
  - [ ] FileVault decryption
  - [ ] APFS decryption
  - [ ] TrueCrypt decryption
  - [ ] VeraCrypt decryption
  - [ ] LUKS decryption
  - [ ] **Passware Kit Forensic** equivalent

### U2. RAM Memory Decryption Extraction

**Feature 152: RAM Memory Decryption Extraction**

- **Requirement:** Extract encryption keys directly from RAM dumps.
- **Specification:**
  - [ ] RAM dump analysis
  - [ ] Encryption key extraction
  - [ ] Instant volume unlock
  - [ ] **Passware Kit Forensic** equivalent

---

## SECTION V: ADDITIONAL FEATURES FROM GLOBAL TOOLS

### V1. Open-Source Forensic Suite

**Feature 153: Open-Source Forensic Suite**

- **Requirement:** Provide free, open-source forensic capabilities.
- **Specification:**
  - [ ] Disk image analysis
  - [ ] File system analysis
  - [ ] Artifact extraction
  - [ ] Timeline analysis
  - [ ] Keyword search
  - [ ] Hash matching
  - [ ] Report generation
  - [ ] **Autopsy / The Sleuth Kit** equivalent

### V2. Mobile Forensic Extraction (Cellebrite)

**Feature 154: Mobile Forensic Extraction**

- **Requirement:** Extract data from mobile devices.
- [ ] iOS extraction
- [ ] Android extraction
- [ ] Physical extraction
- [ ] File system extraction
- [ ] Logical extraction
- [ ] Cloud extraction
- [ ] App parsing
- [ ] **Cellebrite** equivalent

---
# EFMTT 2.3 — Global Forensic Software Feature Integration Todo List

## Complete Development Roadmap: Missing Features from Chinese, Russian, US & European Forensic Tools

---

## How to Use This Document

This todo list covers **150 features** from global forensic software that are **not currently present** in `todolist.md` or `done-todolist.md`. Each item is written to be actionable by programmers.

**Legend:**
- `[ ]` = Not started
- `[x]` = Complete
- **Priority:** Critical / High / Medium / Low
- **Effort:** S (1–2 weeks), M (3–6 weeks), L (7–12 weeks), XL (12+ weeks)

---

## PHASE 16: CHINESE FORENSIC TOOLS — MEIYA PICO / SDIC INTELLIGENCE

### 16.1 Asian Mobile App Deep Parsing

**Priority:** High | **Effort:** L | **Dependencies:** Mobile extraction framework

- [ ] **WeChat full extraction**
  - [ ] Chat history (text, images, voice, video, files)
  - [ ] Moments (posts, comments, likes)
  - [ ] Payments (transactions, red packets, wallet)
  - [ ] Contacts (friends, groups, official accounts)
  - [ ] Deleted message recovery
  - [ ] SQLite database parsing (EnMicroMsg.db, etc.)
  - [ ] Decryption of encrypted WeChat databases

- [ ] **QQ full extraction**
  - [ ] Chat history (text, images, voice, video, files)
  - [ ] Qzone (posts, photos, comments)
  - [ ] Files (received, sent, group files)
  - [ ] Groups (member lists, group chats)
  - [ ] Deleted message recovery
  - [ ] SQLite database parsing

- [ ] **Alipay full extraction**
  - [ ] Transaction history (payments, transfers, receipts)
  - [ ] Contacts (friends, merchants)
  - [ ] Red packets (sent, received)
  - [ ] Financial records (balance, bank cards, Yu'ebao)
  - [ ] SQLite database parsing

- [ ] **DingTalk full extraction**
  - [ ] Enterprise chat history
  - [ ] Files (shared, received)
  - [ ] Approvals (workflow, status)
  - [ ] Attendance (check-in, leave)
  - [ ] SQLite database parsing

- [ ] **Douyin (TikTok China) extraction**
  - [ ] Messages (direct, group)
  - [ ] Videos (watched, liked, created)
  - [ ] User data (profile, followers, following)
  - [ ] SQLite database parsing

- [ ] **Weibo extraction**
  - [ ] Posts (created, liked, reposted)
  - [ ] Messages (direct, group)
  - [ ] User data (profile, followers, following)
  - [ ] SQLite database parsing

- [ ] **Xiaohongshu (Little Red Book) extraction**
  - [ ] Messages (direct, group)
  - [ ] Purchases (orders, history)
  - [ ] User data (profile, followers, following)
  - [ ] SQLite database parsing

- [ ] **Baidu app extraction**
  - [ ] Search history
  - [ ] Maps (locations, routes)
  - [ ] Cloud data (files, photos)
  - [ ] SQLite database parsing

- [ ] **JD.com extraction**
  - [ ] Purchase history
  - [ ] Payments
  - [ ] User data (profile, addresses)
  - [ ] SQLite database parsing

- [ ] **Meituan extraction**
  - [ ] Orders (food, hotel, travel)
  - [ ] Payments
  - [ ] Location data
  - [ ] SQLite database parsing

- [ ] **Huawei HarmonyOS native app parsing**
  - [ ] Native app data structures
  - [ ] System artifacts (settings, logs, cache)
  - [ ] HarmonyOS-specific file systems

- [ ] **Xiaomi MIUI native app parsing**
  - [ ] Native app data structures
  - [ ] System artifacts (settings, logs, cache)
  - [ ] MIUI-specific file systems

- [ ] **Oppo ColorOS native app parsing**
  - [ ] Native app data structures
  - [ ] System artifacts
  - [ ] ColorOS-specific file systems

- [ ] **Vivo OriginOS native app parsing**
  - [ ] Native app data structures
  - [ ] System artifacts
  - [ ] OriginOS-specific file systems

- [ ] **Localized Android variant support**
  - [ ] All Chinese OEM ROMs
  - [ ] All Chinese OEM file systems
  - [ ] All Chinese OEM encryption

### 16.2 Chinese Mobile Chipset Extraction

**Priority:** High | **Effort:** XL | **Dependencies:** Hardware extraction framework

- [ ] **MediaTek chipset support**
  - [ ] Full physical extraction
  - [ ] Bootloader exploits
  - [ ] MTK-specific file systems
  - [ ] MTK-specific encryption

- [ ] **HiSilicon Kirin chipset support**
  - [ ] Full physical extraction
  - [ ] Bootloader exploits
  - [ ] Kirin-specific file systems
  - [ ] Kirin-specific encryption

- [ ] **Unisoc (Spreadtrum) chipset support**
  - [ ] Full physical extraction
  - [ ] Unisoc-specific file systems

- [ ] **Allwinner chipset support**
  - [ ] Full physical extraction
  - [ ] Allwinner-specific file systems

- [ ] **Rockchip chipset support**
  - [ ] Full physical extraction
  - [ ] Rockchip-specific file systems

- [ ] **Qualcomm chipset support (Chinese variants)**
  - [ ] Full physical extraction
  - [ ] Chinese OEM bootloaders

- [ ] **Chinese OEM bootloader support**
  - [ ] Huawei
  - [ ] Xiaomi
  - [ ] Oppo
  - [ ] Vivo
  - [ ] All others

- [ ] **Chinese OEM encryption support**
  - [ ] Huawei
  - [ ] Xiaomi
  - [ ] Oppo
  - [ ] Vivo
  - [ ] All others

- [ ] **Chinese OEM file system support**
  - [ ] EROFS
  - [ ] F2FS variants
  - [ ] All proprietary file systems

### 16.3 Mobile Forensic System (MFS) Full Suite

**Priority:** High | **Effort:** XL | **Dependencies:** Mobile extraction framework

- [ ] **Device security bypass**
  - [ ] PIN bypass
  - [ ] Password bypass
  - [ ] Pattern bypass
  - [ ] Fingerprint bypass
  - [ ] Face recognition bypass

- [ ] **Encrypted partition acquisition**
  - [ ] Full disk encryption (FDE) acquisition
  - [ ] File-based encryption (FBE) acquisition
  - [ ] Metadata encryption acquisition

- [ ] **Artifact data extraction from all mobile OS**
  - [ ] iOS artifacts
  - [ ] Android artifacts
  - [ ] HarmonyOS artifacts
  - [ ] Chinese OEM artifacts

- [ ] **Logical extraction**
  - [ ] File system extraction
  - [ ] App data extraction
  - [ ] System data extraction

- [ ] **File system extraction**
  - [ ] Full file system acquisition
  - [ ] Partition-level acquisition

- [ ] **Physical extraction**
  - [ ] Full physical acquisition
  - [ ] Chip-off acquisition
  - [ ] JTAG acquisition

- [ ] **Cloud extraction (mobile)**
  - [ ] iCloud extraction
  - [ ] Google Drive extraction
  - [ ] Chinese cloud extraction (Baidu, Alibaba, Tencent)

- [ ] **App-specific extraction**
  - [ ] Per-app data extraction
  - [ ] Per-app database parsing

- [ ] **Deleted data recovery (mobile)**
  - [ ] SQLite deleted record recovery
  - [ ] File system deleted file recovery
  - [ ] Journal recovery

- [ ] **SQLite database parsing (mobile)**
  - [ ] All major SQLite schemas
  - [ ] Deleted record recovery
  - [ ] WAL journal parsing

- [ ] **Timeline generation (mobile)**
  - [ ] Cross-app timeline
  - [ ] Cross-device timeline

- [ ] **Report generation (mobile)**
  - [ ] PDF reports
  - [ ] Excel reports
  - [ ] Court-admissible format

- [ ] **Massistant equivalent capability**

- [ ] **Mobile Master equivalent capability**

### 16.4 All-in-One Forensic Workstation

**Priority:** Medium | **Effort:** XL | **Dependencies:** Hardware procurement

- [ ] **Forensic duplication system**
  - [ ] Multi-drive duplication
  - [ ] High-speed duplication
  - [ ] Error correction
  - [ ] Write blocking

- [ ] **Rapid indexing**
  - [ ] Full disk indexing
  - [ ] Content indexing
  - [ ] Metadata indexing

- [ ] **Hash matching (MD5, SHA-1, SHA-256)**
  - [ ] Known-file hash matching
  - [ ] Hash set import
  - [ ] Hash set export

- [ ] **File carving**
  - [ ] Signature-based carving
  - [ ] Fragment reassembly
  - [ ] Carved file verification

- [ ] **Disk imaging**
  - [ ] Physical imaging
  - [ ] Logical imaging
  - [ ] Sparse imaging

- [ ] **Memory imaging**
  - [ ] Live memory capture
  - [ ] Crash dump analysis

- [ ] **Write blocking**
  - [ ] Hardware write blockers
  - [ ] Software write blocking

- [ ] **Chain of custody**
  - [ ] Evidence tracking
  - [ ] Custody transfer logging
  - [ ] Tamper detection

- [ ] **Case management**
  - [ ] Case creation
  - [ ] Evidence association
  - [ ] Report generation

- [ ] **Multi-drive support**
  - [ ] Simultaneous drive access
  - [ ] RAID reconstruction

- [ ] **High-speed duplication**
  - [ ] 10Gbps+ duplication
  - [ ] Parallel duplication

- [ ] **Error correction**
  - [ ] Bad sector handling
  - [ ] Retry logic
  - [ ] Error logging

### 16.5 CCTV / DVR Video Forensics

**Priority:** High | **Effort:** L | **Dependencies:** Video codec libraries

- [ ] **Recover deleted video files**
  - [ ] File system recovery
  - [ ] Signature-based recovery
  - [ ] Fragment reassembly

- [ ] **Recover overwritten video files**
  - [ ] Overwrite pattern analysis
  - [ ] Partial recovery
  - [ ] Timeline reconstruction

- [ ] **Recover fragmented video files**
  - [ ] Fragment identification
  - [ ] Fragment reassembly
  - [ ] Playback verification

- [ ] **Recover corrupted video files**
  - [ ] Header repair
  - [ ] Index repair
  - [ ] Frame-level recovery

- [ ] **Parse proprietary DVR file systems**
  - [ ] Hikvision
  - [ ] Dahua
  - [ ] Axis
  - [ ] Bosch
  - [ ] Pelco
  - [ ] Samsung
  - [ ] Panasonic
  - [ ] Sony
  - [ ] All others

- [ ] **Parse proprietary NVR file systems**
  - [ ] All major NVR brands
  - [ ] All proprietary formats

- [ ] **Support Chinese DVR formats**
  - [ ] All Chinese manufacturers
  - [ ] All Chinese formats

- [ ] **Support Western DVR formats**
  - [ ] All Western manufacturers
  - [ ] All Western formats

- [ ] **Reconstruct video timelines**
  - [ ] Timestamp extraction
  - [ ] Timeline visualization
  - [ ] Gap identification

- [ ] **Export video in standard formats**
  - [ ] MP4 export
  - [ ] AVI export
  - [ ] Frame-by-frame export

- [ ] **Enhance video quality**
  - [ ] Motion blur removal
  - [ ] Low light enhancement
  - [ ] Noise reduction
  - [ ] Sharpening
  - [ ] Stabilization

- [ ] **VIP (Video Investigation Portable) equivalent**

### 16.6 Forensic Data Recovery System (DRS)

**Priority:** Medium | **Effort:** L | **Dependencies:** Storage drivers

- [ ] **Physical disk extraction**
  - [ ] Sector-level extraction
  - [ ] Bad sector bypassing
  - [ ] Firmware-level access

- [ ] **Bad sector bypassing**
  - [ ] Automatic retry
  - [ ] Sector skipping
  - [ ] Error logging

- [ ] **Formatted partition recovery**
  - [ ] File system reconstruction
  - [ ] Metadata recovery
  - [ ] File recovery

- [ ] **Raw partition recovery**
  - [ ] Raw sector analysis
  - [ ] Signature-based recovery
  - [ ] File carving

- [ ] **Deleted file recovery**
  - [ ] File system recovery
  - [ ] Signature-based recovery
  - [ ] Fragment reassembly

- [ ] **File system corruption recovery**
  - [ ] Superblock repair
  - [ ] Inode repair
  - [ ] Directory repair

- [ ] **RAID reconstruction**
  - [ ] RAID 0/1/5/6/10
  - [ ] RAID parameter detection
  - [ ] Virtual RAID assembly

- [ ] **SSD recovery**
  - [ ] TRIM analysis
  - [ ] Wear-leveling analysis
  - [ ] Flash translation layer analysis

- [ ] **HDD recovery**
  - [ ] SATA recovery
  - [ ] SAS recovery
  - [ ] SCSI recovery

- [ ] **USB recovery**
  - [ ] USB flash recovery
  - [ ] USB HDD recovery

- [ ] **Memory card recovery**
  - [ ] SD card recovery
  - [ ] MicroSD recovery
  - [ ] CF card recovery

- [ ] **DRS (Data Recovery System) equivalent**

### 16.7 Smartphone Analysis System (SPA)

**Priority:** High | **Effort:** L | **Dependencies:** Mobile extraction framework

- [ ] **All mobile OS support**
  - [ ] iOS
  - [ ] Android
  - [ ] HarmonyOS
  - [ ] Chinese OEM ROMs

- [ ] **All extraction types**
  - [ ] Logical
  - [ ] File system
  - [ ] Physical

- [ ] **All app parsing**
  - [ ] WeChat
  - [ ] QQ
  - [ ] Alipay
  - [ ] DingTalk
  - [ ] All others

- [ ] **Deleted data recovery**
  - [ ] SQLite recovery
  - [ ] File recovery

- [ ] **Cloud extraction**
  - [ ] iCloud
  - [ ] Google
  - [ ] Chinese clouds

- [ ] **Timeline generation**
  - [ ] Cross-app timeline
  - [ ] Cross-device timeline

- [ ] **Link analysis**
  - [ ] Entity relationships
  - [ ] Communication patterns

- [ ] **Report generation**
  - [ ] PDF reports
  - [ ] Excel reports
  - [ ] Court-admissible format

- [ ] **SPA (Smartphone Analysis System) equivalent**

### 16.8 Network Forensics

**Priority:** High | **Effort:** L | **Dependencies:** Network capture framework

- [ ] **Full packet capture**
  - [ ] 100% traffic capture
  - [ ] Line-rate capture
  - [ ] Nanosecond timestamps

- [ ] **Network flow analysis**
  - [ ] NetFlow/sFlow analysis
  - [ ] Flow aggregation
  - [ ] Flow visualization

- [ ] **Protocol analysis**
  - [ ] All major protocols
  - [ ] Custom protocol support

- [ ] **Session reconstruction**
  - [ ] HTTPS session reconstruction

- [ ] **File reconstruction**
  - [ ] HTTPS file reconstruction (with SSL inspection)

- [ ] **Email reconstruction**
  Plaintext named attachments are in the done list. The message body is omitted, and SMTPS, IMAPS, and POP3S are not decrypted.

- [ ] **Web reconstruction**
  - [ ] HTTPS reconstruction

- [ ] **VoIP reconstruction**
  - [ ] SIP reconstruction
  - [ ] RTP reconstruction

- [ ] **Video reconstruction**
  - [ ] RTSP reconstruction
  - [ ] H.264/H.265 reconstruction

- [ ] **Intrusion detection**
  - [ ] Signature-based detection
  - [ ] Anomaly-based detection

- [ ] **Anomaly detection**
  A stored protocol on an unexpected port is in the done list.

- [ ] **Threat hunting**
  Stored IOC and TTP search are in the done list. A malware-signature feed and a machine-learning pass remain open under D2.

- [ ] **Retrospective analysis**
  - [ ] Historical packet search — decoded sessions, commands, files, and findings are searchable. There is no per-packet content index.

- [ ] **Puguang equivalent**

### 16.9 Big Data Law Enforcement Analytics

**Priority:** Medium | **Effort:** XL | **Dependencies:** Big data infrastructure

- [ ] **Petabyte-scale data processing**
  - [ ] Distributed storage
  - [ ] Distributed processing

- [ ] **Distributed computing**
  - [ ] Hadoop/Spark integration
  - [ ] MapReduce jobs

- [ ] **Entity resolution**
  - [ ] Identity resolution
  - [ ] Duplicate detection

- [ ] **Relationship mapping**
  - [ ] Social network analysis
  - [ ] Communication pattern analysis

- [ ] **Pattern detection**
  - [ ] Behavioral pattern detection
  - [ ] Temporal pattern detection

- [ ] **Anomaly detection**
  - [ ] Statistical anomaly detection
  - [ ] ML-based anomaly detection

- [ ] **Predictive analytics**
  - [ ] Risk prediction
  - [ ] Behavior prediction

- [ ] **Social network analysis**
  - [ ] Graph analysis
  - [ ] Community detection

- [ ] **Geographic analysis**
  - [ ] Geospatial analysis
  - [ ] Location clustering

- [ ] **Temporal analysis**
  - [ ] Time-series analysis
  - [ ] Event correlation

- [ ] **Puguang equivalent**

### 16.10 Cloud Evidence Collection

**Priority:** High | **Effort:** L | **Dependencies:** Cloud APIs

- [ ] **Chinese cloud providers**
  - [ ] Alibaba Cloud
  - [ ] Tencent Cloud
  - [ ] Baidu Cloud
  - [ ] Huawei Cloud

- [ ] **Western cloud providers**
  - [ ] AWS
  - [ ] Azure
  - [ ] Google Cloud

- [ ] **Cloud storage**
  - [ ] Dropbox
  - [ ] OneDrive
  - [ ] Google Drive
  - [ ] Box

- [ ] **Cloud email**
  - [ ] Gmail
  - [ ] Outlook
  - [ ] Yahoo

- [ ] **Cloud messaging**
  - [ ] WeChat
  - [ ] QQ
  - [ ] DingTalk

- [ ] **Cloud backups**
  - [ ] iCloud
  - [ ] Google Backup
  - [ ] Chinese cloud backups

- [ ] **Cloud documents**
  - [ ] Google Docs
  - [ ] Office 365
  - [ ] Chinese cloud docs

- [ ] **Cloud social media**
  - [ ] Facebook
  - [ ] Twitter
  - [ ] Weibo

- [ ] **Puguang equivalent**

---

## PHASE 17: RUSSIAN FORENSIC TOOLS — ELCOMSOFТ, BELKASOFT, OXYGEN

### 17.1 GPU-Accelerated Password Recovery

**Priority:** High | **Effort:** L | **Dependencies:** CUDA/OpenCL

- [ ] **Multi-GPU support**
  - [ ] NVIDIA CUDA
  - [ ] AMD OpenCL
  - [ ] Multi-GPU scaling

- [ ] **Distributed password recovery**
  - [ ] Network-distributed cracking
  - [ ] Job scheduling
  - [ ] Progress tracking

- [ ] **Brute-force attacks**
  - [ ] Full charset brute-force
  - [ ] Mask-based brute-force
  - [ ] Incremental brute-force

- [ ] **Dictionary attacks**
  - [ ] Wordlist support
  - [ ] Rule-based mutations
  - [ ] Hybrid dictionary

- [ ] **Hybrid attacks**
  - [ ] Dictionary + mask
  - [ ] Dictionary + rules

- [ ] **Mask attacks**
  - [ ] Character set masks
  - [ ] Position-based masks

- [ ] **Rule-based attacks**
  - [ ] Hashcat-compatible rules
  - [ ] Custom rule engine

- [ ] **Rainbow table attacks**
  - [ ] Rainbow table import
  - [ ] Rainbow table generation

- [ ] **iOS backup decryption**
  - [ ] iTunes backup decryption
  - [ ] iCloud backup decryption

- [ ] **Android backup decryption**
  - [ ] ADB backup decryption
  - [ ] Vendor backup decryption

- [ ] **VeraCrypt decryption**
  - [ ] Header decryption
  - [ ] Full volume decryption

- [ ] **BitLocker decryption**
  - [ ] Recovery key extraction
  - [ ] Full volume decryption

- [ ] **FileVault decryption**
  - [ ] Recovery key extraction
  - [ ] Full volume decryption

- [ ] **APFS decryption**
  - [ ] APFS container decryption
  - [ ] APFS volume decryption

- [ ] **TrueCrypt decryption**
  - [ ] Header decryption
  - [ ] Full volume decryption

- [ ] **LUKS decryption**
  - [ ] LUKS1 decryption
  - [ ] LUKS2 decryption

- [ ] **Office document decryption**
  - [ ] Word decryption
  - [ ] Excel decryption
  - [ ] PowerPoint decryption

- [ ] **PDF decryption**
  - [ ] User password decryption
  - [ ] Owner password decryption

- [ ] **ZIP/RAR/7z decryption**
  - [ ] ZIP decryption
  - [ ] RAR decryption
  - [ ] 7z decryption

- [ ] **EDPR (Elcomsoft Distributed Password Recovery) equivalent**

### 17.2 iOS Forensic Toolkit

**Priority:** High | **Effort:** L | **Dependencies:** iOS device access

- [ ] **checkm8 exploit support**
  - [ ] A5-A11 device support
  - [ ] Bootloader exploit
  - [ ] Custom firmware loading

- [ ] **Custom extraction agents**
  - [ ] Agent deployment
  - [ ] Agent communication
  - [ ] Agent cleanup

- [ ] **Physical extraction**
  - [ ] Full file system extraction
  - [ ] Encrypted partition extraction

- [ ] **File system extraction**
  - [ ] Full file system access
  - [ ] App container access

- [ ] **Logical extraction**
  - [ ] iTunes backup extraction
  - [ ] AFC extraction

- [ ] **Keychain extraction**
  - [ ] Keychain database extraction
  - [ ] Keychain decryption

- [ ] **Binary token extraction**
  - [ ] Authentication token extraction
  - [ ] Session token extraction

- [ ] **iCloud extraction**
  - [ ] iCloud backup extraction
  - [ ] iCloud photo extraction
  - [ ] iCloud message extraction
  - [ ] iCloud call log extraction
  - [ ] iCloud Safari extraction

- [ ] **EIFT (iOS Forensic Toolkit) equivalent**

### 17.3 Cloud Extraction Without 2FA Alerts

**Priority:** High | **Effort:** M | **Dependencies:** Cloud APIs, token extraction

- [ ] **Binary token extraction**
  - [ ] Token extraction from device
  - [ ] Token extraction from backup

- [ ] **Authentication token extraction**
  - [ ] OAuth token extraction
  - [ ] Session token extraction

- [ ] **Session token extraction**
  - [ ] Cookie extraction
  - [ ] Session hijacking prevention

- [ ] **iCloud data extraction**
  - [ ] Without 2FA alert
  - [ ] With token-based access

- [ ] **Google data extraction**
  - [ ] Without 2FA alert
  - [ ] With token-based access

- [ ] **Microsoft data extraction**
  - [ ] Without 2FA alert
  - [ ] With token-based access

- [ ] **Dropbox data extraction**
  - [ ] Without 2FA alert
  - [ ] With token-based access

- [ ] **Elcomsoft Phone Breaker equivalent**

### 17.4 Automated Artifact Discovery (1,500+ Types)

**Priority:** High | **Effort:** XL | **Dependencies:** Parsing framework

- [ ] **Chat histories (all major apps)**
  - [ ] WeChat
  - [ ] QQ
  - [ ] WhatsApp
  - [ ] Telegram
  - [ ] Signal
  - [ ] All others

- [ ] **Browser caches (all major browsers)**
  - [ ] Chrome
  - [ ] Firefox
  - [ ] Edge
  - [ ] Safari
  - [ ] Opera

- [ ] **Browser history**
  - [ ] Chrome
  - [ ] Firefox
  - [ ] Edge
  - [ ] Safari
  - [ ] Opera

- [ ] **Browser cookies**
  - [ ] All major browsers

- [ ] **Browser passwords**
  - [ ] All major browsers

- [ ] **System logs**
  - [ ] Windows Event Logs
  - [ ] macOS Unified Logs
  - [ ] Linux syslog

- [ ] **Registry hives**
  - [ ] SYSTEM
  - [ ] SOFTWARE
  - [ ] SAM
  - [ ] SECURITY
  - [ ] NTUSER.DAT
  - [ ] USRCLASS.DAT

- [ ] **Event logs**
  - [ ] Security
  - [ ] System
  - [ ] Application

- [ ] **Prefetch files**
  - [ ] Windows Prefetch parsing

- [ ] **Shimcache**
  - [ ] Application compatibility cache

- [ ] **Amcache**
  - [ ] Amcache.hve parsing

- [ ] **Jump lists**
  - [ ] AutomaticDestinations
  - [ ] CustomDestinations

- [ ] **LNK files**
  - [ ] Shortcut file parsing

- [ ] **Recycle bin**
  - [ ] $Recycle.Bin parsing

- [ ] **Thumbnail caches**
  - [ ] thumbs.db
  - [ ] Thumbcache

- [ ] **Email archives**
  - [ ] PST
  - [ ] OST
  - [ ] MBOX
  - [ ] EML

- [ ] **Cloud sync logs**
  - [ ] OneDrive
  - [ ] Dropbox
  - [ ] Google Drive

- [ ] **USB history**
  - [ ] USBSTOR
  - [ ] MountedDevices

- [ ] **Network history**
  - [ ] Network profiles
  - [ ] WiFi history

- [ ] **Application logs**
  - [ ] All major applications

- [ ] **Database artifacts**
  - [ ] SQLite
  - [ ] Access
  - [ ] MySQL

- [ ] **SQLite databases**
  - [ ] All schemas
  - [ ] Deleted record recovery

- [ ] **1,500+ artifact types total**

### 17.5 RAM & Volatile Memory Analysis

**Priority:** High | **Effort:** L | **Dependencies:** Memory acquisition

- [ ] **Process listing**
  - [ ] Running processes
  - [ ] Process hierarchy

- [ ] **Process memory analysis**
  - [ ] Process memory dumps
  - [ ] Injected code detection

- [ ] **Network connections**
  - [ ] Active connections
  - [ ] Listening ports

- [ ] **Open files**
  - [ ] File handles
  - [ ] Locked files

- [ ] **Open registry keys**
  - [ ] Registry handles

- [ ] **Loaded DLLs**
  - [ ] DLL listing
  - [ ] DLL injection detection

- [ ] **Injected code detection**
  - [ ] Process hollowing
  - [ ] DLL injection
  - [ ] Reflective loading

- [ ] **Malware detection**
  - [ ] Signature-based
  - [ ] Heuristic-based

- [ ] **Encryption key extraction**
  - [ ] BitLocker keys
  - [ ] VeraCrypt keys
  - [ ] FileVault keys

- [ ] **Password extraction**
  - [ ] Plaintext passwords
  - [ ] Password hashes

- [ ] **Chat message extraction**
  - [ ] In-memory chat messages

- [ ] **Browser data extraction**
  - [ ] In-memory browser data

- [ ] **Belkasoft X RAM analysis equivalent**

### 17.6 Unified Computer & Mobile Timeline

**Priority:** High | **Effort:** L | **Dependencies:** Timeline framework

- [ ] **Windows artifacts on timeline**
  - [ ] All Windows artifacts

- [ ] **macOS artifacts on timeline**
  - [ ] All macOS artifacts

- [ ] **Linux artifacts on timeline**
  - [ ] All Linux artifacts

- [ ] **iOS artifacts on timeline**
  - [ ] All iOS artifacts

- [ ] **Android artifacts on timeline**
  - [ ] All Android artifacts

- [ ] **Cloud artifacts on timeline**
  - [ ] All cloud artifacts

- [ ] **RAM artifacts on timeline**
  - [ ] All RAM artifacts

- [ ] **Cross-device correlation**
  - [ ] Entity resolution
  - [ ] Event correlation

- [ ] **Cross-device entity resolution**
  - [ ] Same user across devices
  - [ ] Same account across devices

- [ ] **Belkasoft X unified timeline equivalent**

### 17.7 All-in-One Extraction (Oxygen)

**Priority:** Medium | **Effort:** XL | **Dependencies:** Multi-source extraction

- [ ] **Mobile extraction**
  - [ ] iOS
  - [ ] Android
  - [ ] HarmonyOS

- [ ] **Computer extraction**
  - [ ] Windows
  - [ ] macOS
  - [ ] Linux

- [ ] **IoT extraction**
  - [ ] Smart home devices
  - [ ] Wearables

- [ ] **Cloud extraction**
  - [ ] All major cloud providers

- [ ] **Drone extraction**
  - [ ] DJI
  - [ ] Parrot
  - [ ] Autel
  - [ ] Skydio

- [ ] **Single interface**
  - [ ] Unified UI
  - [ ] Unified case management

- [ ] **Single case management**
  - [ ] All sources in one case
  - [ ] Cross-source analysis

- [ ] **Oxygen Forensic Detective equivalent**

### 17.8 Regional Messaging App Parsing

**Priority:** High | **Effort:** L | **Dependencies:** App parsing framework

- [ ] **Telegram parsing**
  - [ ] Chats
  - [ ] Channels
  - [ ] Groups
  - [ ] Files
  - [ ] Calls
  - [ ] Secret chats

- [ ] **VK parsing**
  - [ ] Messages
  - [ ] Posts
  - [ ] Friends
  - [ ] Groups

- [ ] **WhatsApp parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Media
  - [ ] Calls
  - [ ] Deleted messages

- [ ] **Viber parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Media
  - [ ] Calls

- [ ] **Signal parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Media
  - [ ] Calls

- [ ] **Line parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Media

- [ ] **KakaoTalk parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Media

- [ ] **WeChat parsing**
  - [ ] Chats
  - [ ] Moments
  - [ ] Payments

- [ ] **QQ parsing**
  - [ ] Chats
  - [ ] Groups
  - [ ] Files

- [ ] **DingTalk parsing**
  - [ ] Chats
  - [ ] Files
  - [ ] Approvals

- [ ] **SQLite database analysis**
  - [ ] All schemas
  - [ ] Deleted recovery

- [ ] **Oxygen Forensic Detective app parsing equivalent**

### 17.9 Drone Data Extraction

**Priority:** Medium | **Effort:** M | **Dependencies:** Drone SDKs

- [ ] **DJI drone extraction**
  - [ ] Flight logs
  - [ ] GPS tracks
  - [ ] Photos
  - [ ] Videos
  - [ ] Telemetry

- [ ] **Parrot drone extraction**
  - [ ] Flight logs
  - [ ] GPS tracks
  - [ ] Photos
  - [ ] Videos

- [ ] **Autel drone extraction**
  - [ ] Flight logs
  - [ ] GPS tracks
  - [ ] Photos
  - [ ] Videos

- [ ] **Skydio drone extraction**
  - [ ] Flight logs
  - [ ] GPS tracks
  - [ ] Photos
  - [ ] Videos

- [ ] **Oxygen Forensic Detective drone analytics equivalent**

---

## PHASE 18: US FORENSIC TOOLS — MAGNET AXIOM, FTK, ENCASE

### 18.1 Artifact-First Analysis

**Priority:** High | **Effort:** L | **Dependencies:** Artifact parsing framework

- [ ] **Chat histories (all major apps)**
  - [ ] All messaging apps

- [ ] **Cloud storage syncs**
  - [ ] OneDrive
  - [ ] Dropbox
  - [ ] Google Drive

- [ ] **Browser activity**
  - [ ] All browsers

- [ ] **System logs**
  - [ ] All OS logs

- [ ] **Deleted database records**
  - [ ] SQLite recovery
  - [ ] Other DB recovery

- [ ] **Windows artifacts**
  - [ ] All Windows artifacts

- [ ] **macOS artifacts**
  - [ ] All macOS artifacts

- [ ] **iOS artifacts**
  - [ ] All iOS artifacts

- [ ] **Android artifacts**
  - [ ] All Android artifacts

- [ ] **Cloud service artifacts**
  - [ ] All cloud services

- [ ] **Magnet AXIOM artifact-first equivalent**

### 18.2 GrayKey Integration

**Priority:** High | **Effort:** M | **Dependencies:** GrayKey hardware

- [ ] **GrayKey device integration**
  - [ ] Device connection
  - [ ] Extraction management

- [ ] **Hardware-level iOS decryption**
  - [ ] Full file system extraction
  - [ ] Encrypted data extraction

- [ ] **Hardware-level Android decryption**
  - [ ] Full file system extraction
  - [ ] Encrypted data extraction

- [ ] **Physical extraction**
  - [ ] Full physical acquisition

- [ ] **Full file system extraction**
  - [ ] Complete file system

- [ ] **Magnet AXIOM + GrayKey equivalent**

### 18.3 Distributed Processing & Indexing

**Priority:** High | **Effort:** XL | **Dependencies:** Distributed infrastructure

- [ ] **Centralized database architecture**
  - [ ] Oracle support
  - [ ] PostgreSQL support

- [ ] **Multi-worker node support**
  - [ ] Worker registration
  - [ ] Work distribution

- [ ] **Distributed indexing**
  - [ ] Parallel indexing
  - [ ] Index sharding

- [ ] **Distributed processing**
  - [ ] Parallel processing
  - [ ] Job scheduling

- [ ] **Terabyte-scale datasets**
  - [ ] Large dataset handling
  - [ ] Memory management

- [ ] **No software crashes on large datasets**
  - [ ] Stability testing
  - [ ] Error recovery

- [ ] **Load balancing**
  - [ ] Dynamic load balancing
  - [ ] Failover support

- [ ] **FTK distributed processing equivalent**

### 18.4 FTK Imager Equivalent

**Priority:** High | **Effort:** M | **Dependencies:** Disk imaging

- [ ] **Bit-stream disk imaging**
  - [ ] Physical imaging
  - [ ] Logical imaging

- [ ] **Memory dump creation**
  - [ ] Live memory capture
  - [ ] Crash dump analysis

- [ ] **Physical disk imaging**
  - [ ] Full disk imaging

- [ ] **Logical disk imaging**
  - [ ] Partition imaging

- [ ] **E01 format support**
  - [ ] E01 read/write
  - [ ] Compression

- [ ] **L01 format support**
  - [


**IAM verification update (4 October 2026):** 46 targeted tests passed across the regression run and corrected recording-test reruns. Coverage includes authentication, OTPs, access scopes, privacy, reporting, replay/response, privileged recording consent withdrawal, membership revocation, and approval revocation. Python compilation and JavaScript syntax checks passed. Live Twilio, AD, Linux PAM and native desktop capture were not exercised.


## Language integration follow-up — 4 October 2026

- [x] Retain Python as the application and integration backend.
- [x] Convert the report builder to strict TypeScript, compile the served JavaScript, and preserve the SQL summary button (frontend/src/report-builder.ts).
- [x] Add Go protocol/payload aggregation for Python sensor reports, with bounded input and overflow checks (tools/sensor-report).
- [x] Add and test the Rust streaming classic-PCAP validator (tools/pcap-check).
- [x] Add the C Linux PAM ticket collector source; actual authorization remains in the existing backend redemption service (native/pam-ticket).
- [x] Add and test the C++ SHA-256 evidence verifier against Python hashlib (native/evidence-hash).
- [x] Add and test SQL workload/alert views through a read-only Python reporting command (database/reporting.py).
- [x] Add component build instructions, exact scope, limitations, and CI configuration (POLYGLOT.md; .github/workflows/polyglot.yml).
- [x] Execute Go vet, tests and builds for both tools; Python report contract verified on 5 October 2026.
- [ ] Execute Linux C build and real PAM handoff checks on hosted CI; workflow configured, execution unverified.
- [x] Validate the complete collector / pam_exec / HTTPS backend authentication stack in disposable Ubuntu 24.04 (5 October 2026).

Verification for this follow-up: strict TypeScript build and JavaScript syntax check passed;
5 reporting API tests, 3 Rust tests, SQL source-preservation/aggregation checks,
and Windows C++ hash/failure cross-checks passed. CI configuration was added but
not executed. This entry does not mark the entire roadmap or production rollout complete.

Verification follow-up, 5 October 2026: both Go tools passed vet, tests and builds;
the Python sensor/report contract and CLI failure checks passed. A real Linux
libpam collector/pam_exec handoff harness was added to CI. Python syntax checks
passed. Linux execution and full backend authentication remain unverified; this
workstation has no installed WSL distribution. The downstream executable in the
harness is a test double, and no host PAM service is modified.

Verification follow-up, 5 October 2026 (completion request): 13 existing IAM
regression tests and 9 additional PAM redemption denial tests passed locally.
The new tests cover expired tickets/sessions/grants, revoked sessions/grants,
disabled accounts, incorrect usernames/resources and incorrect service keys.
They also verify failed redemption does not consume the ticket. Existing IAM
coverage checks successful redemption and single use. Hosted CI now installs
backend dependencies and runs both suites. tools/verify-linux.sh provides a
repeatable Linux verification entry point. Linux execution, hosted CI and the
complete live PAM/HTTPS/backend deployment remain open: no Linux distribution,
Docker runtime, Git repository or configured remote is available here.

## Ubuntu verification completed — 5 October 2026

This supersedes earlier entries saying Ubuntu was unavailable or Linux PAM was
unverified. Ubuntu 24.04 on WSL 2 is installed. Both C components compiled with
-Wall -Wextra -Werror; 10 stub checks, 4 real PAM handoff checks, and the native
redeem client self-test passed. On Linux, 23 IAM/PAM tests passed. The expanded
live test passed again after adding rejection of untrusted TLS and insecure
configuration-file permissions. It exercises real libpam, pam_exec, pam_bridge
and the live HTTPS backend with successful authentication, reuse/expiry rejection,
wrong identity and revoked approval. No /etc/pam.d configuration was changed.
Hosted CI is configured but remains unexecuted: this folder has no Git repository
or remote. Production deployment and the wider roadmap remain open.
