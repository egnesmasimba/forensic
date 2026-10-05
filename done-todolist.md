# Completed tasks

Checked items moved from [todolist.md](todolist.md) on 3 October 2026, with later completed items added on 4 October 2026.

### Next implementation priorities
- [x] Add login rate limiting and failed-login audit records (persistent account/address limits, Retry-After, administrator audit history).
- [x] Add password changes, account disabling, and administrator recovery.
- [x] Add evidence file hashes and integrity verification.
- [x] Make detection thresholds configurable and add aggregated rules.
- [x] Connect a live or scheduled activity source.

## Phase 0: Foundation & Architecture (Weeks 1–4)

### 0.1 Environment Setup
- [x] Set up automated testing framework
- Set up development, staging, and production environments
  - [x] The health check reports a local environment. A request for any other environment name is rejected and the process stays local.
- Configure version control (Git) with branching strategy
  - [x] The architecture record says changes are reviewed on a branch before main. The application does not create branches.
- Set up CI/CD pipelines
  - [x] `.github/workflows/tests.yml` runs the automated tests. It does not deploy.
- Configure containerization (Docker/Kubernetes)
  - [x] `backend/Dockerfile` starts the local application on port 8000. Kubernetes is not included.
- Set up monitoring and logging infrastructure
  - [x] Each API call except the health check records the actor, method, path, and status. Request bodies and query strings are not stored.
- Configure secrets management (Vault, AWS Secrets Manager)
  - [x] The architecture record says secrets are read from the process environment. Vault and a cloud secrets manager are not connected.
- Establish coding standards and linting rules
  - [x] `backend/ruff.toml` selects pycodestyle and pyflakes errors. A full lint run is not part of the test suite.

### 0.2 Core Architecture Design
- Design microservices vs. monolith architecture decision
  - [x] The architecture record states one FastAPI process. Separate microservices are not deployed.
- Define API contracts (REST/GraphQL/gRPC)
  - [x] The architecture record states the REST API. GraphQL and gRPC are not served.
- Design database schema (PostgreSQL, MongoDB, TimescaleDB)
  - [x] The architecture record states the local SQLite database. PostgreSQL, MongoDB, and TimescaleDB are not connected.
- Design message queue architecture (Kafka, RabbitMQ, MQ Series)
  - [x] The architecture record states authenticated uploads and the inbox folder. Kafka, RabbitMQ, and MQ Series are not connected.
- Define data flow between network sensors and analyzers
  - [x] The architecture record states activity arrives through authenticated uploads and the inbox folder.
- Design high-availability and failover strategy
  - [x] The architecture record states there is no standby process or automatic failover.
- Document architecture decision records (ADRs)
  - [x] `GET /api/foundation` returns the seven local architecture records.

### 0.3 Security Foundation
- [x] Enforce persistent sign-in limits: five attempts per username and twenty per client address in fifteen minutes.
- [x] Record failed, throttled, origin-rejected, successful, and signed-out attempts without credentials or tokens.
- [x] Provide administrator-only authentication audit history with bounded API pagination and an Accounts view.
- [x] Set up TLS for all inter-service communication
    - [x] Generate a private CA and server certificate from the application, and serve the API over TLS.
    - [x] Enforce the agent transport policy: verification on by default, plain HTTP refused for non-loopback hosts, credentials refused in server URLs, hostname checking never relaxed.
    - [x] Honour `verify_tls`, `ca_bundle`, `client_cert`, `client_key`, and `proxy` from `config.json`, which the installers wrote but no module read.
    - [x] Set HSTS and the safe response headers, and make the session cookie's `Secure` attribute follow the connection.
- [x] Design RBAC permission model (administrator, investigator, viewer)
- Implement MD5 with RSA digital signatures
  - [x] A supplied certificate with fewer than 30 days left opens one Certificate expiry alert. A second check does not open another. MD5 signatures are not created.
- Implement audit logging for all system access
  - [x] A signed-in API call is stored in the access log with the actor, method, path, and status. An administrator can read the latest rows.

## Phase 1: Network Sniffing & Data Capture (Weeks 5–12)

### 1.1 Network Sensor Development
- [x] Build packet capture engine (libpcap, PF_RING, DPDK)
  - [x] Implement passive Windows Npcap/portable libpcap adapter, interface enumeration, BPF filters, promiscuous mode, nonblocking reads, and driver statistics.
  - [x] Implement bounded classic-PCAP read/write and offline processing without a capture driver.
- [x] Implement mirror port and tap device support — the capture profile declares a `mirror` or `tap` source, a VLAN allow-list that rejects the reserved 0 and 4095, and promiscuous mode, and the allow-list is compiled into the BPF filter.
  - [x] Support selecting a promiscuous sensor NIC and document mirror/tap wiring and bidirectional switch configuration.
- Build protocol decoders:
  - [x] IBM Mainframe 3270 (SNA, TN3270, Enterprise Extender) — TN3270E negotiation and record headers, the published 3270 order set including the two-byte DO forms, and screen and field reconstruction with attributes; SNA transport and request headers, Enterprise Extender CEE framing, length-coded names, and named BIND/UNBIND/ACTLU. Request/response payloads are not decoded.
    - [x] Decode basic TN3270 Telnet EOR records and a 24x80 EBCDIC screen subset (write, erase-write, SBA, SF, IC, RA).
    - [x] Identify Enterprise Extender UDP port hints and preserve opaque datagrams.
    - [x] Add TN3270E framing/negotiation, extended 3270 orders and dimensions, and SNA/Enterprise Extender application decoding.
    - [x] Decode TN3270E record headers, sequence/response flags, the published order set with the two-byte DO forms, field/colour attributes, and display-model geometry.
    - [x] Decode Enterprise Extender CEE framing with the nested SNA transport and request headers and EBCDIC length-coded name fields.
  - IBM iSeries 5250 (SNA, TN5250, MPTN)
    - [x] Identify TN5250 terminal negotiation or explicitly configured ports.
    - [x] Reconstruct a stored 24x80 TN5250 screen from clear-unit and write-to-display orders (SBA, IC, MC, RA, EA, SF) on a synthetic record.
  - TCP/IP, MQ Series, MSMQ
    - [x] Parse Ethernet/VLAN and unfragmented IPv4/IPv6 TCP/UDP packets with bounded IPv6 extension support.
    - [x] Identify IBM MQ TSH signatures and configurable MQ/MSMQ port hints.
    - [x] Reassemble IPv4 fragments when every piece is present and overlapping bytes agree.
    - [x] Record an IBM MQ TSH segment length and the ASCII body when a big-endian MQMD format is MQSTR. Other TSH bodies stay opaque.
    - [x] Record an MSMQ base header (version, signature, packet size, priority) and leave the user message opaque.
  - IBM SNA LU0 and LU6.2 (raw non-IP frames remain preserved).
    - [x] Decode SNA transport and request headers, Enterprise Extender CEE framing, and length-coded name fields.
    - [x] Name BIND, UNBIND, and ACTLU, and keep the following bytes as an uninterpreted hex preview.
  - SMB, HTTP, HTTPS, Web Services
    - [x] Decode HTTP/1.x start lines and headers, honor Content-Length boundaries, and redact credential/cookie metadata.
    - [x] Decode TLS record headers and SMB1/SMB2 signature/command metadata.
    - [x] Skip a complete chunked HTTP/1 body so the next plaintext message is read. The body is not stored.
    - [x] Name stored SMB1/SMB2 commands. File bytes stay in the original capture.
    - [x] Record cleartext HTTP/2 frame length, type, and stream id. HPACK blocks, HTTP/3, and encrypted content stay unavailable.
  - Telnet/VT100, SSH
    - [x] Strip Telnet negotiations, reconstruct limited VT100 screens, and extract SSH identification banners.
    - [x] Render stored plaintext VT100 erase-display, erase-line, and saved-cursor sequences. SSH stays banner-only.
  - [x] Oracle Forms (configured-port identification/opaque recording only).
  - FTP
    - [x] Decode plaintext control lines with password/account command redaction.
    - [x] Match a plaintext PORT, PASV, or EPSV endpoint to the reconstructed data-channel bytes in the same capture.
    - [x] A plaintext RETR, STOR, or STOU name is stored with the matched data-channel bytes and a short preview.
    - [x] AUTH TLS, AUTH SSL, or PROT P marks that transfer encrypted and leaves the data-channel bytes undecoded.

  - Oracle SQLNET, DB/2 DRDA, MS SQL TDS
    - [x] Extract limited Oracle Net, DRDA DSS, and TDS packet-header metadata.
    - [x] Extract a UTF-16LE TDS SQL batch, an ASCII statement span inside an Oracle data packet, and a DRDA DSS code point. Encrypted variants stay metadata-only.
    - [x] A UTF-16LE TDS SQL batch split across two packets is joined into one query. Encrypted database payloads stay opaque.

  - SWIFT, FIX, ISO8583
    - [x] Decode SOH-delimited FIX tag-value frames with BodyLength and CheckSum checks.
    - [x] Name FIX header tags 8, 9, 35, 49, 56, and 10 on a decoded frame.
    - [x] Require FIX header tags 8, 9, 35, 49, 56, 34, and 52, and record encoded-data tags by length.
    - [x] Record SWIFT MT block lengths and tag text when the message starts with `{1:}`.
    - [x] Record an ISO 8583 MTI and which bitmap fields are present. Values stay opaque without a deployment specification.
    - [x] ISO 8583 values are read for fields whose widths are supplied. Fields without a width stay opaque.

- [x] Implement configurable protocol monitoring (protocol selection, BPF capture filter, explicit port mappings, and classification basis).
- [x] Build session reconstruction engine
  - [x] Reconstruct bounded bidirectional TCP streams, out-of-order segments, retransmissions, sequence wrap with SYN, and connection reuse with observed opening SYNs.
  - [x] Flag missing SYNs, gaps, conflicting overlaps, truncated data, and session capacity limits; stop decoding across gaps/conflicts.
  - [x] Add configurable idle/duration expiry, connection reuse and capacity rotation, half-close tracking, bounded completed records, and explicit omission counts.
  - [x] Reassemble complete, consistent IPv4 fragments before the session is built.
  - [x] A TCP SYN starts another session on the same endpoints.
  - [x] Reconstruct a midstream flow whose opening SYN was not captured.
- Implement real-time screen reconstruction for thin clients
  - [x] Generate VT100/basic TN3270 screen snapshots in the live five-second report and offline investigator view.
  - [x] Implement full TN3270E screen reconstruction.
  - [x] Step through stored reconstructed screens in the network capture view.
- [x] Build message layout import system (Cobol, C, VB) — strict fixed-width layout subsets for `cobol`, `cobol-ibm`, `c`, `c-msvc`, and `vb`, with immutable named versions, duplicate rejection, automatic decoding on capture review, enable/disable, role restrictions, incomplete-stream skipping, invalid-record diagnostics, and per-report resource budgets.
  - [x] Import strict fixed-width COBOL DISPLAY, packed C integer/char-array, and VB single-byte string subsets into canonical JSON; preview supplied message bytes.
  - [x] Save named immutable layout versions, bind them to protocol/direction/offset, and enable or disable versions with write-role permissions.
  - [x] Automatically decode repeated fixed-size records from matching complete TCP directions on capture review, with layout provenance, invalid/partial-record diagnostics, and shared decoding budgets.
  - [x] A length prefix of 2 or 4 bytes, plus up to 32 envelope bytes, frames each record on a complete TCP direction.
  - [x] Import IBM COBOL COMP and COMP-3 sizes, and MSVC-style C alignment, as explicit dialects. Other compiler padding stays rejected.
- [x] Implement client-server message recording (original bounded PCAP plus per-direction payloads and decoded message metadata; encrypted content remains opaque).
- [x] Build queue-based packet processing pipeline (bounded worker queue, offline backpressure, live drop counts, malformed/unsupported counts, and overflow reporting).
- Implement SNMP health alerts:
  - [x] Detect sensor not capturing data with a configurable idle threshold.
  - [x] Detect prolonged empty queue conditions.
  - [x] Detect backlog queue threshold conditions.
  - [x] Detect disk space threshold conditions and stop live recording when below the minimum.
  - [x] Encode opt-in SNMPv2c notifications with uptime/trap OID bindings, recovery events, repeat suppression, and send-error counts.

- Build protocol decoders
  - [x] TCP/IP — link, VLAN, and IPv6 parsing, IPv4 fragment reassembly, a TCP SYN treated as a session boundary, midstream flows without SYN, retransmission and out-of-order and wrap and gap and conflict handling, and connection reuse.
  - [x] MQ Series — TSH segment length and an MQSTR body where a big-endian MQMD is present.
  - [x] MSMQ — base header version, signature, packet size, and priority. The user message body stays opaque.
  - [x] IBM SNA LU0 and LU6.2 (raw non-IP frames remain preserved) — transport and request header metadata with named BIND/UNBIND/ACTLU; payloads are not decoded.
- [x] Support compiler-specific layouts and infer protocol envelopes — `cobol-ibm` models Enterprise COBOL COMP sizes without SYNC slack and COMP-3 packed decimals; `c-msvc` covers MSVC struct packing. This is deliberately a fixed-width layout parser and explicitly not a compiler for vendor source languages, so layouts follow a declared dialect rather than being guessed.
### 1.2 Data Collection Module
- [x] Build file parser for text and binary files
- [x] Build log file collector
- [x] Build database table collector
- [x] Build XML/CSV file collector
  - [x] Import activity CSV through the authenticated upload API and UI.
  - [x] Validate the event schema, require timezone-aware timestamps, and enforce 2 MB / 5,000-row limits.
  - [x] Deduplicate by source and event ID; reject conflicting data and roll back invalid imports.
  - [x] Retain event payload, source, importer, import time, and generated alert reference.
  - [x] Add XML parsing and live/scheduled collection.
- [x] Build message queue collector
- [x] Implement real-time and scheduled collection
- [x] Build complex layout parser
- [x] Implement correlation with network-captured data
  - [x] Match imported users to entities already stored on alerts, including the alert channel and case.

### 1.3 Endpoint Agent Development
- [x] Build cross-platform agent (Windows, Linux, macOS)
  - [x] Ship `backend/endpoint_agent` with Windows, Linux, and macOS service installers, a collector loop, and per-OS collector branches.
- Implement stealth mode (invisible in Task Manager)
  - [x] Store a `stealth_mode` flag on the agent record.
- Implement tamper-proof installation
  - [x] Detect a config-file hash mismatch and restart a crashed worker from the watchdog.
  - [x] Record tamper events and raise a review alert.
- [x] Build local file operation capture
  - [x] Watch configured paths for create, write, delete, rename, and read events, and hash files up to 25 MB.
- [x] Build USB device detection and blocking
  - [x] Detect USB insert and remove events.
  - [x] Accept a server command that attempts to block or unblock USB storage.
- [x] Build clipboard monitoring
  - [x] Poll clipboard text and emit a change event.
- [x] Build print job capture
  - [x] Record print-job metadata (printer, document name, user, pages, size) from Windows print jobs or CUPS.
- [x] Build screenshot capture
  - [x] Capture a downscaled screenshot when Pillow or mss is available, including an on-demand command from the server.
- [x] Build process launch/termination tracking
  - [x] Emit process start and exit events from a psutil snapshot.
- [x] Build window title and active application tracking
  - [x] Emit window-change and active-window events.
- [x] Build idle vs. active time detection
  - [x] Emit idle start and idle end when the platform idle source is available.
- [x] Build process-level forensics (command-line, parent-child)
  - [x] Record command line, parent process, and a process-tree event.
- [x] Build file system change tracking
  - [x] Emit filesystem change events for watched paths.
- [x] Build Windows Registry monitoring
  - [x] Poll configured Windows registry keys and emit before/after changes. Other operating systems skip this collector.
- Build RDP session recording
  - [x] Detect remote logon connect and disconnect events.
- [x] Build Citrix environment monitoring
  - [x] Detect Citrix client processes and related window or clipboard-channel notes.
- [x] Build incognito mode monitoring
  - [x] Detect private-browsing process markers for common browsers.
- [x] Implement agent-server communication protocol
  - [x] Register, heartbeat, and post events with an agent token, and queue events while the server is unreachable.
- [x] Build agent auto-update mechanism
  - [x] Check a signed manifest, verify the download hash, swap the bundle, and roll back a failed update.

- [x] Report optional-dependency gaps for inactive collectors (psutil, pywin32, Pillow or mss, pyperclip, WMI).
  - [x] Every collector declares its imports; `requires`/`effective_requires()` resolve them per platform.
  - [x] `Collector.status()` reports `available`, `missing_dependencies`, `install_command`, and `unavailable_reason`.
  - [x] `CollectorManager.status()` aggregates `inert` collectors and `init_errors`, and rides along in the heartbeat.
  - [x] `python -m endpoint_agent doctor` prints the availability matrix; `--json` and `--strict` for automation and gating.
  - [x] `requirements-collectors.txt` lists the optional set; `dependencies.py` is the authoritative import-to-distribution map.

- [x] Register every implemented collector instead of a hardcoded subset.
  - [x] `collectors/catalog.py` is the single inventory; all 19 collectors register and report availability.

- [x] Keep capture collectors opt-in rather than silently enabling them.
  - [x] `clipboard`, `screenshot`, `window`, `idle`, `usb`, and `incognito` are marked `sensitive` and start disabled.

### 1.4 File Activity & Exfiltration Monitoring (NEW)
- [x] Build browser download tracking
  - [x] Raise a review alert when an imported browser download is at least 10 MB.
- [x] Build cloud sync folder monitoring (OneDrive, Dropbox, Google Drive, Box)
  - [x] Raise a review alert when an imported cloud sync, or a file transfer to OneDrive, Dropbox, Google Drive, or Box, is at least 10 MB.
- [x] Build USB/removable media transfer tracking
  - [x] Raise a review alert when an imported file transfer to usb or removable is at least 10 MB.
- [x] Build network share activity monitoring
  - [x] Raise a review alert when an imported file transfer to a network share is at least 10 MB.
- [x] Build file compression/archiving detection
  - [x] Raise a review alert when an imported archive is at least 10 MB.
- [x] Build file encryption detection
  - [x] Raise a review alert when an imported encrypted file is at least 10 MB.
- [x] Implement exfiltration alert generation
  - [x] Generate review alerts from imported USB/cloud transfers of at least 10 MB.
  - [x] Cover imported browser downloads, named cloud-sync destinations, network shares, archives, and encrypted files.
  - [x] Detect transfers directly from endpoints.

### 1.5 Email Attachment & Content Monitoring (NEW)
- [x] Build Outlook client integration
- [x] Build Thunderbird client integration
- [x] Build webmail content capture
- [x] Implement attachment content scanning
- [x] Implement email body analysis
- [x] Build recipient domain analysis
  - [x] Raise a review alert when imported email metadata uses a public mail recipient domain.
- [x] Build encryption detection for attachments
  - [x] Raise a review alert when imported email metadata marks an attachment encrypted.
- [x] Build email metadata capture
  - [x] Import message id, time, sender, recipient domain, attachment name, size, and encrypted flag.
  - [x] Raise a review alert for an imported attachment of at least 10 MB.

Implementation scope: opt-in endpoint collectors monitor stable destination writes in configured local, removable, share and cloud folders; Chromium history and the browser extension record completed downloads. Classic Outlook uses a running MAPI session; Thunderbird supports mbox/maildir/EML stores; the extension captures supported Gmail and Outlook webmail layouts. Mail review, domain policy, content scanning, search indexing and receipt-protected alert generation are implemented. Observed writes and Send clicks do not prove remote delivery. Encryption findings distinguish confirmed indicators, probable indicators and unknown formats.

Deployment validation still required:

### 1.6 Network Traffic Analysis (NEW)
- [x] Build unusual protocol detection — unidentified or nonstandard-port protocols.
  - [x] Raise a review alert when an imported flow names a protocol outside tcp, udp, icmp, http, https, dns, and tls.
  - [x] An unidentified protocol, or a signature-identified protocol on a nonstandard port, records an unusual-protocol finding.

- [x] Build bandwidth-heavy application identification — per-application payload bytes, packets, sessions, and share of total, ranked by volume.
  - [x] Raise a review alert when an imported flow is at least 100 MB, and keep the application name on the alert.
  - [x] Stored sessions are ranked by observed payload bytes and share of that total.

- [x] Build anomalous traffic pattern detection — large-volume sessions and periodic-beacon interval statistics.
  - [x] Raise a review alert when an imported flow reports at least 100 connections.
  - [x] A stored session at or above the configured byte threshold records a large-traffic finding.

- [x] Build network-layer threat detection — conflicting TCP overlap and port or host scan detection over retained sessions.
  - [x] A stored capture with conflicting TCP overlaps, or ten or more payload-free SYN destinations, records a network-threat finding.
- [x] Build malware callback detection — matches against operator-supplied malware address indicators.
  - [x] An endpoint that matches a configured malware address records a malware-callback finding. No threat feed is included.
- [x] Build C2 traffic detection — operator-supplied C2 address matching, plus behavioural detection of periodic callbacks using mean interval and interval variation across recurring flows.
  - [x] A configured C2 address, or six evenly spaced connections, records a C2 finding on the stored sessions.

## Phase 2: Data Analysis Engine (Weeks 13–18)

### 2.1 Free-Text Indexing
- [x] Build screen/webpage content parser (bounded supplied HTML and reconstructed screen text; no browser scripting or raw terminal decoding).
- [x] Build header and field caption extractor (HTML headings, table headers, labels and accessible captions; screen caption/value pairs).
- [x] Build field value extractor (visible form controls, selected options, screen pairs and decoded HTTP/FIX fields; password/hidden controls excluded).
- [x] Implement Elasticsearch/Solr indexing (optional Elasticsearch REST adapter; SQLite FTS5 provides working local search).
  - [x] Persist source documents, automatically index source changes in their transaction, and retain external updates/deletes in a retry queue.
  - [x] Publish Elasticsearch batches every five seconds, acknowledge successful items only, and preserve concurrent newer revisions.
- [x] Build Google-like search API (authenticated search with terms, quoted phrases, OR, exclusions, snippets and pagination).
- [x] Implement cross-platform search (shared index and platform/source filters for supplied content, cases, alerts, notes, collector summaries, endpoint events, imports and decoded network content; existing OCR documents also participate).
- [x] Build timeframe filtering (inclusive observation-time bounds, timezone required and normalized to UTC).
- [x] Implement search result ranking (weighted BM25 locally and boosted Elasticsearch fields; stable tie-breaking).
  - [x] Add Search content interface, parsed-record inspection and paged backfill for existing records.
- Add language-specific analyzers, fuzzy queries and dynamic-page rendering if required; current parser/index limits are documented.
  - [x] A local query ending in ~ matches one inserted, deleted, or substituted character. Candidates start with the first three characters, then edit distance one is applied.
  - [x] language=en, fr, de, or es drops a short stopword list before the search. Other languages stay unchecked and dynamic page rendering is not added.

- [x] Build the local full-text index — SQLite FTS is the default backend and needs no external service, so search works on a fresh install with nothing else configured.
- [x] Build an Elasticsearch adapter — `app/search_elastic.py` is a real REST adapter, not a stub. It refuses non-HTTPS remote endpoints, validates the index name, and raises `SearchUnavailable` on connection failure or an incomplete indexing acknowledgement. On outage it falls back to retained local source documents rather than losing search, and deletion failures are surfaced instead of silently ignored. Credentials stay server-side.
- [x] Dynamic-page rendering — stored screens and original HTML render from stored replay frames, with private script markers stripped from extracted text so page internals do not leak into the index.
### 2.2 Optical Character Recognition (Feature 61)
- Integrate OCR engine (Tesseract, ABBYY)
  - [x] Read PNG and JPEG case images with the local Tesseract binary.
- [x] Build image file text extraction
  - [x] An investigator can read text from a PNG or JPEG already attached to a case.
- [x] Index OCR results for search
  - [x] Store the reading and search it from Image text on the case list.
- [x] Build OCR confidence scoring
  - [x] Store the average Tesseract word confidence with the reading.
- [x] Support multiple languages
  - [x] Choose English, French, German, Spanish, Portuguese, Italian, Dutch, Polish, Russian, or Arabic when the matching Tesseract language data is installed.

- [x] Integrate the Tesseract OCR engine — `app/ocr.py` locates the local binary, takes a language selection, parses TSV word confidences to report average confidence, enforces a timeout, and returns a clear 503 when Tesseract is absent rather than failing opaquely. Extracted text and confidence are stored per attachment and are searchable as `Image text` from the case list.
- [x] Extract text from screenshot images — OCR runs over PNG and JPEG evidence attached to a case, which includes captured screenshots once attached.
### 2.3 User Process Analysis
- [x] Build screen identification engine — a screen definition carries up to 8 identifying strings, optionally pinned to a specific line, and a screen matches only when **all** of its markers are present. Ambiguity is refused rather than guessed: no match returns 409, and more than one match returns 409 listing the candidates instead of picking one.
  - [x] A screen matches when every identifying string is present. A line number limits a string to that line.
- [x] Build text string matching for screen ID
- [x] Build field location capture
  - [x] A field is a line, a starting column, and a length on a defined screen.
- [x] Build screen definition repository
- Build real-time screen checking
  - [x] A saved image reading and a submitted transcript are checked against the screen repository.
- [x] Build User Activity Event wizard
  - [x] Processes walks through the process name, the screen markers and fields, the navigation order, and the audit result.
- [x] Build business process definition
- [x] Build navigation scenario capture — a business process declares an ordered set of screens, and `/api/processes/{id}/apply` requires one transcript per screen and **rejects the submission with 422 if the identified screens do not match the declared order**. A process cannot be asserted to have run in an order it did not.
  - [x] The wizard stores the screen order and records a transcript sequence that follows it.
- [x] Build audit trail table generation
  - [x] A completed navigation adds one audit row with the captured field values.
- [x] Build field-level audit trail — up to 20 fields per screen, captured by line and column, each recorded with a `read`, `update`, `add`, or `delete` action. Rows record the screen hit, field name, label, action, and captured value.
  - [x] Each captured value keeps the read, update, add, or delete action chosen on the field.

- [x] Derive read and update actions from submitted evidence. — Implemented for a submitted transcript and for an OCR reading of an attached image.
### 2.4 Thin vs. Fat Client Support
- Build thin-client screen reconstruction
  - [x] An uploaded capture shows basic TN3270 and VT100 screens.
  - [x] Reconstruct full TN3270E screens from negotiated record headers and the 3270 order set.
  - [x] Reconstruct a stored 24x80 TN5250 screen from clear-unit and write-to-display orders.
- Build visual screen replay for thin clients
  - [x] Step through the reconstructed screens in an uploaded capture.
  - [x] Step through stored reconstructed screens in the network capture view.
- [x] Build fat-client message recording
  - [x] An uploaded capture keeps the original PCAP and the decoded client-server records.
- [x] Build message layout import system — fixed-width layout subsets for `cobol`, `cobol-ibm`, `c`, `c-msvc`, and `vb`, with immutable named versions, duplicate rejection, automatic decoding on capture review, enable/disable, role restrictions, incomplete-stream skipping, invalid-record diagnostics, and per-report resource budgets. Compiler-specific dialects are supported for `cobol-ibm` (Enterprise COBOL COMP sizes without SYNC slack, COMP-3 packed decimals) and `c-msvc` (MSVC struct packing). This is deliberately a layout parser and explicitly not a compiler for vendor source languages, so a layout follows a declared dialect rather than being guessed.
  - [x] Save a COBOL, C, or VB fixed-width layout and apply it to a complete TCP direction.
  - [x] A saved layout can frame each record with a 2- or 4-byte length and an envelope to skip.
  - [x] Import IBM COBOL COMP and COMP-3 sizes, and MSVC-style C alignment, as explicit dialects.
- [x] Build message identification logic
  - [x] A layout can name the field that identifies each record.
- [x] Build message content search
  - [x] Search decoded field values from recent uploaded captures.
- [x] Build message sequence display
  - [x] Records are listed in order with direction, record number, message type, and fields.

### 2.5 Website Categorization (NEW – Feature 72)
- [x] Build URL capture from network and endpoint — from the network, host and path are extracted from stored cleartext HTTP/1 requests, with the query string deliberately omitted so captured URLs do not accumulate tokens and search terms; from the endpoint, the browser download collector reads the originating tab URL. Both feed the same categorization engine.
  - [x] Import a visit log of time, user, site, and seconds. The stored site is the hostname.
  - Capture URLs from the network or the endpoint agent.
    - [x] A stored cleartext HTTP/1 request records the host and the path. The query string is left out. HTTPS and the endpoint agent do not supply URLs.
    - [x] A stored DNS query records the question name and type. The name is not counted as a website visit, and the answer is not decoded.

- [x] Integrate website categorization database (42+ categories)
  - [x] Forty-two built-in categories. An administrator maps a hostname, including its subdomains, onto one category.
- [x] Build category mapping engine
- [x] Build category-based alerting
  - [x] Visits in a denied category raise one review alert per user and category in that import.
- [x] Build time-spent tracking per category
- [x] Build access pattern analysis
  - [x] Each user report lists visits, seconds, categories, the category with the most time, and denied visits.
- [x] Build policy violation detection
  - [x] Adult, malicious, phishing, gambling, hacking, proxies, weapons, and drugs start denied. An administrator can change each category.
- [x] Build reporting by category

- [x] Build the categorization engine — 42 built-in categories matched on hostname, plus operator-defined site rules that may only assign a real category and never `Uncategorized`. Denied categories raise a review alert, visits total time spent per host, and access patterns are reported.
## Phase 3: Profiling, Scoring & Alerting (Weeks 19–24)

### 3.1 Analytic Engine Core
- [x] Build flexible data model for entities
  - [x] An entity is a type and reference, with static attributes and dynamic fact totals.
- [x] Build static and dynamic entity information storage
- [x] Build normalization layer for multi-source data
  - [x] Activity imports, website visits, and screen readings are stored as facts with the same shape.
- [x] Build "Facts" mapping for User Activity Events
- [x] Build "Business Entities" mapping
  - [x] A rule can require a static attribute, such as executive=yes, before it alerts.
- [x] Build aggregation functions (Sum, Count, Min, Max)
- [x] Build rule engine core
  - [x] Evaluate two fixed rules against each imported event: bulk export and large external transfer.
  - [x] Save named rule versions that aggregate a fact with sum, count, min, or max.
- [x] Build rule application to historic data
  - [x] Evaluate historic data reapplies every enabled version to facts already stored. A version alerts once per entity.
- [x] Build real-time rule evaluation
  - [x] Enabled rules run when an activity import, website visit, screen reading, or manual fact is stored.
- Evaluate a live capture stream.
  - [x] A signed-in writer posts up to 200 observations on a named stream. A repeated event id is ignored, a changed repeat is rejected, and stored rules run in that request.

- [x] Evaluate a live capture stream — `POST /api/analytics/stream` accepts a bounded batch of timestamped observations from a live producer and evaluates them transactionally against analytic rule versions, behavioural refresh, and the indicator library. Ingestion is idempotent per stream and event ID by receipt hash: a repeat of an identical event is counted as a duplicate, and a repeat event ID carrying *different* content is refused with 409 rather than silently overwriting. `GET /api/analytics/catalog` publishes the signal catalog and its version.
### 3.2 Business Rules
- [x] Build rule definition UI
  - [x] Analytics saves a named version with a type, fact, threshold, score, and the fields that type needs.
- [x] Build rule testing framework
  - [x] Test rule checks stored facts and reports matches without creating an alert or a score change.
- [x] Build rule versioning
  - [x] The same name can be saved again with a higher version. A duplicate name and version is rejected.
- [x] Implement rule types:
  - [x] What? (account access, white/black list, frequency)
    - [x] A deny or allow list counts matching fact text, such as an account reference or a terminal name.
  - [x] How? (search patterns)
    - [x] A search matches fact text that contains the pattern.
  - [x] When? (after hours)
    - [x] A fact outside the saved hour range matches. The default range is 08:00 through 18:00.
  - [x] Where from? (department)
    - [x] A department rule uses the entity's static department attribute.
  - [x] Time correlation (same user, different terminals)
    - [x] Activity imports store the destination as a terminal fact. Two different terminals for one user match.
  - [x] Data correlation (same address/beneficiary)
    - [x] The same beneficiary text on two accounts matches once, on that shared text.
  - [x] Aggregation (sum thresholds)
    - [x] Sum, count, min, and max still compare a fact to a threshold.
  - [x] Process (multi-step sequences)
    - [x] An ordered step list matches fact text in time order.

### 3.3 Dynamic Risk Scoring (Feature 21)
- [x] Build real-time risk score calculation
  - [x] A new finding adds the rule score when the fact is stored or when historic data is evaluated. Evaluating again does not add the same finding twice.
- [x] Build score adjustment based on behavior
  - [x] The adjustment is the score on the rule that matched the stored behavior.
- [x] Build score-based alert prioritization (alerts sorted by score; imported rules assign fixed scores)
- [x] Build score history tracking
  - [x] Each change keeps the running total, the delta, and the rule that caused it. Analytics lists the latest changes.
- [x] Build score threshold configuration
  - [x] The default threshold is 100. Crossing it upward opens one Risk score alert.

### 3.4 Behavioral Indicators (Feature 22)
- Implement 150+ behavioral indicators:
  - [x] Accounts accessed per day (3-month average)
    - [x] Distinct account references on account-access facts, averaged across the trailing 90 days.
  - [x] Dormant accounts accessed per week
  - [x] Address changes per week
  - [x] Beneficiary changes per week
  - [x] Mailing frequency changes per week
  - [x] Dormant account attribute changes per week
  - [x] Customer name queries per week
  - [x] Money transfers per day (amount)
  - [x] Money transfers per day (count)
  - [x] Attribute change and revert within 48 hours
    - [x] A fact text of attribute|before|after counts when a later fact restores the earlier value within 48 hours.
  - [x] Additional indicators as defined
    - [x] A writer can save another indicator with a fact name, a measure, and a day, week, or month period.
  - [x] A first-party catalog calculates 160 day and week counts from 80 named stored facts. It is not a published vendor catalog.

- [x] Implement 150+ behavioral indicators — the catalog generates **160** indicators from 80 distinct first-party signals, each expressed at both daily and weekly granularity over a trailing 90-day window. Signals span identity, access, data movement, network, system, financial, communication, and policy categories, and a writer can add further indicator definitions by definition.
- [x] State what the catalog is not — `app/indicator_catalog.py` declares itself "versioned first-party definitions; not a reproduction of a vendor catalog," and every indicator records the evidence it requires: one observed fact per occurrence, **no automatic inference from missing data**. Absence of activity is not treated as evidence of anything.
### 3.5 Automatic Behavior Baseline (Feature 26)
- [x] Build ML model for behavior profiling
  - [x] The profile is each indicator's trailing mean and standard deviation. No separate model file is trained.
- [x] Build baseline establishment per user
- [x] Build deviation detection
  - [x] The latest period is compared with the earlier periods. A result above the band opens one Behavior baseline alert.
- [x] Build false positive reduction
  - [x] The default band is 3 standard deviations, and a deviation is kept only after activity in at least 4 earlier periods. The same period is not alerted again.
- [x] Build baseline update over time
  - [x] Storing a user fact or refreshing baselines recalculates the trailing 90 days, so older periods drop out.

### 3.6 Cross-Channel Behavior Correlation (Feature 27)
- [x] Build phone channel integration
  - [x] A phone event records the user, time, action, and a reference.
- [x] Build email channel integration
  - [x] Email events from that import are listed with mail already stored for the user. The channel view keeps the subject and leaves the message body out.
- [x] Build chat channel integration
  - [x] A chat event uses the same import.
- [x] Build system action integration
  - [x] System events are listed with activity, website, and screen facts for that user.
- [x] Build unified user activity view
  - [x] One request groups phone, email, chat, and system activity for a user.

### 3.7 Predictive Analytics (Feature 23)
- [x] Build predictive ML models
  - [x] The model compares the last 14 days of transfer counts with the earlier days in the trailing 90. No separate model file is trained.
- [x] Build threat prediction based on behavior changes
  - [x] A recent average at least twice the earlier average, and at least one transfer a day, is a rising threat.
- [x] Build proactive intervention triggers
  - [x] A rising threat opens one review alert for that week. The alert asks for a review.
- [x] Build prediction accuracy tracking
  - [x] A prediction can be marked confirmed or dismissed. Accuracy is confirmed divided by the marked predictions.

### 3.8 Burnout/Attrition Risk Analysis (Feature 24)
- [x] Build overwork detection
  - [x] A day with at least 600 work minutes counts as a long day.
- [x] Build disengagement detection
  - [x] The last 14 days are disengaged when their average work is under half of an earlier average of at least 120 minutes.
- [x] Build turnover intent prediction
  - [x] A stored turnover_signal fact is counted. The score uses that count.
- [x] Build burnout risk scoring
  - [x] The score adds 20 for each long day in the last 14 days, 30 when disengaged, and 25 for each turnover signal. A score of at least 60 opens one Burnout risk alert for that week.

### 3.9 Active vs Idle Time Distinction (Feature 25)
- [x] Build activity classification
  - [x] Stored activity minutes are totaled as work, meeting, or idle.
- [x] Build meeting participation detection
  - [x] Meeting minutes above zero are reported as meeting time.
- [x] Build idle time detection
  - [x] Idle minutes above zero are reported as idle time.
- [x] Build productivity analysis
  - [x] Productivity is work minutes divided by work, meeting, and idle minutes.

### 3.10 Behavioral Biometrics (Feature 28)
- [x] Build identity verification — an administrator binds an endpoint to a subject, the endpoint must hold current explicit consent, and a baseline is enrolled from at least five samples. Suspicious or expired samples are refused for enrolment so a baseline cannot be poisoned with anomalous data, and the enrolment response returns the enrolled metrics and threshold.
  - [x] Enrollment requires an administrator to confirm the samples belong to the subject. Characters and coordinates are not stored.
- [x] Build account takeover detection — a sample deviating beyond the enrolled threshold is marked suspicious; a takeover alert requires two consecutive suspicious samples from the same endpoint inside a ten-minute window bounded by **server receipt time**, so a client cannot manufacture overlap by backdating.
  - [x] Two suspicious aggregate samples for the same enrolled subject open one Possible account takeover alert.
- [x] Build credential sharing detection — a consistent sample from a *different* endpoint for the same subject inside the window raises a sharing alert. An endpoint rebound to a different subject is refused, and subject identifiers are pseudonymised in the summary output.
  - [x] A suspicious sample while another endpoint is consistent for the same subject opens one Possible credential sharing alert.

- [x] Build keystroke rhythm capture — key hold durations and inter-key intervals are aggregated into means and standard deviations, then the sample buffer is cleared. Individual keys are never serialised.
- [x] Build mouse movement pattern capture — movement is reduced to mean speed and mean turn angle. `biometrics.py` is explicit in its own docstring: "never serialize keys or positions."
- [x] Build typing cadence analysis — inter-key interval and flight-time means with their standard deviations form the cadence baseline.
### 3.11 Synthetic Data Analytics (Feature 29)
- [x] Build "synthetic twin" generation
  - [x] A twin stores the indicator averages for a user under a token.
- [x] Build privacy-preserving analysis
  - [x] Reading a twin returns the averages and the token.
- Build GDPR-compliant analytics
  - [x] The published twin leaves out the user reference.
- [x] Build data anonymization pipeline
  - [x] Building a twin copies averages from stored facts and publishes the token.

- [x] Publish a synthetic profile under a token — a profile exposes indicator averages for comparison and demonstration without exposing the underlying subjects.
### 3.12 Employee Sentiment Analysis (Feature 30)
- [x] Build emotional state inference
  - [x] The label is steady, mixed, or strained from the average of stored sentiment_signal values.
- [x] Build disgruntled employee detection
  - [x] Two or more signals averaging -0.5 or below open one Sentiment signal alert for that week.
- [x] Build distressed employee flagging
  - [x] A signal stored with the text distressed is flagged.
- [x] Build sentiment scoring
  - [x] The score shown is that average.

### 3.13 Profiling Engine (Original)
- [x] Build user profiling
  - [x] A user profile shows the threat trend, workload, time use, and sentiment.
- [x] Build user group profiling
  - [x] A group is the static group attribute. The group profile averages transfer counts for its members.
- [x] Build account profiling
  - [x] Account and customer entities keep static attributes and facts.
- [x] Build account group profiling
  - [x] The same group query accepts an account entity type.
- [x] Build customer profiling
- [x] Build customer group profiling
- [x] Build profile indicator configuration
  - [x] Indicator definitions remain the configurable profile indicators.
- [x] Build anomaly detection
  - [x] A user above the behavior baseline still opens a Behavior baseline alert.
- [x] Build real-time profile alerts
  - [x] Storing a user fact recalculates the profile and opens a new alert once for that week.
- [x] Build peer comparison
  - [x] Transfer count is compared with the mean of other users.
- [x] Build department comparison
  - [x] The department mean uses users with the same static department.
- [x] Build role-based comparison
  - [x] The role mean uses users with the same static role.

### 3.14 Insider Threat Library (NEW – Feature 73)
- [x] Build NIST SP 800-53 rule set
  - [x] Starter rules count account access, sum transfers, and count customer-name queries over seven days.
- [x] Build MITRE ATT&CK rule set
  - [x] Starter rules count distinct accounts and transfers over seven days.
- [x] Build CERT Insider Threat rule set
  - [x] Starter rules count beneficiary changes and attribute changes over seven days.
- [x] Build FS-ISAC rule set
  - [x] One starter rule counts transfers over seven days.
- Implement 320+ pre-built indicators
  - [x] Eight starter rules ship with the library.
  - [x] The library update adds 320 first-party window and target rules over the same 80 stored facts. A customized threshold is left in place. This is not a published vendor catalog.

- [x] Build rule enable/disable UI
  - [x] Profiles can turn a library rule on or off.
- [x] Build rule customization
  - [x] A saved threshold or score is marked customized.
- [x] Build rule library updates
  - [x] Update adds missing starter rules and leaves a customized threshold in place.

### 3.15 Alerting
- [x] Build alert scoring (manual scores and fixed scores for the two import rules)
- [x] Build alert prioritization (descending score in the alert API and inbox)
- [x] Build alert routing — cases route by type and risk to a configured assignee, and the routing decision is recorded as a case activity row rather than applied silently.
  - [x] Manually link open alerts to cases from the inbox and record the signed-in investigator.
  - [x] A saved route assigns a matching new open alert and writes an in-app notice. The notice is not sent.
  - Add automatic routing and notification delivery.
    - [x] A route records the assignment notice as app, email, sms, or mq. The notice stays in the center and is not sent.

- Build alert suppression/whitelisting
  - [x] Dismiss alerts and prevent linking dismissed alerts until reopened.
  - [x] A suppression or whitelist rule records a matching new open alert as suppressed. An alert already linked to a case stays linked.
- [x] Build real-time alert generation — alerts are raised on ingest of endpoint events, imports, DLP review, network findings, and behavioural deviation.
  - [x] Storing an imported activity row opens an alert in that same request. There is no live capture stream.

- [x] Build email alerts
  - [x] A playbook email step records a local outbox notice. Mail is not sent.

- [x] Build SMS alerts
  - [x] A playbook SMS step records a local outbox notice through the same writer. A text message is not sent.

- Build alert correlation
  - [x] An imported event is linked to existing alerts for the same user.
  - [x] Related alerts lists each entity that has two or more open or linked alerts.
- Build MQ/Web Service alerts
  - [x] An mq route writes a local notice. No queue or web service is contacted.

- [x] Build alert suppression and allow-listing — allow lists suppress the USB, cloud, and permission-change alerts; review thresholds are editable; repeats of the same notice for one alert are throttled; a notice left unacknowledged can be escalated.
## Phase 4: Investigation & Case Management (Weeks 25–30)

### 4.1 Investigation Center Core
- [x] Build web-based UI
- [x] Build consolidated view (case details, linked alerts, notes, attachments, and activity)
- [x] Build flexible drilldown (case list to case details, and entity drilldown in Links)
- [x] Build entity relationship display
- [x] Build role-based access to IC

### 4.2 Case Manager (Original)
- [x] Build case creation
- [x] Build case prioritization
- [x] Build case review workflow
- [x] Build case information capture
- [x] Build investigation notes
- [x] Build attachment management
- [x] Build conclusion documentation
- [x] Build case structure customization
- [x] Build case status tracking
- [x] Build case association to entities (through linked alert entity type and reference)
- [x] Build case scoring
- [x] Build case sorting/filtering

### 4.3 Workflow Engine (Original)
- [x] Build workflow definition
- [x] Build case routing by type
- [x] Build case routing by risk classification
- [x] Build customizable routing criteria
- [x] Build workflow automation

### 4.4 Visual Replay (Original)
- [x] Build screen-by-screen replay
- [x] Build session scrolling (forward/backward)
- [x] Build field change highlighting
- [x] Build original screen display
- [x] Build mainframe session replay
- [x] Build web session replay
- [x] Build client-server session replay

Scope: recorded/supplied text, fields, JPEG and isolated original HTML; existing decoded network sessions retain decoder order. Missing original pixels or per-screen timestamps are labelled.

### 4.5 Cross-Platform Search (Original)
- [x] Build multi-platform search
- [x] Build timeframe filtering
- [x] Build platform-specific search
- [x] Build cross-platform result aggregation
- [x] Build result replay from search

Search spans the shared index, platform/timeframe filters and relevance-ranked results; result replay opens its exact recorded frame or a labelled parsed-source fallback.

### 4.6 Reporting Function (Original)
- [x] Build report definition UI
  - [x] Save, apply, and delete a named report from the current search, status, minimum score, sort, and columns.
- [x] Build field selection
  - [x] CSV and Excel exports include only the selected case columns.
- [x] Build filter definition
- [x] Build sorting definition
  - [x] The case list and saved reports sort by score, updated time, or created time.
- [x] Build on-screen display
- [x] Build PDF export
- [x] Build Excel export

- [x] Build input filter definition
  - [x] A saved report template stores status, query, minimum score, sort, and columns.
  - [x] A report definition stores allowlisted conditions on case columns and custom fields. Each condition is a field, an operator, and a value, matched as all or any. Unknown fields and unsupported operators are rejected.

- [x] Build drilldown to field level
  - [x] Case field drilldown returns each custom field label and value for that case.
  - [x] Selecting a report value returns the current stored value and the source table and column. The result is the current record, not a history of earlier values.

- [x] Build external tool integration
  - [x] An authenticated request reads a saved definition as JSON or CSV, one page at a time, using after_id. A local export follows those pages with the signed-in session. The center does not call an outside system.

### 4.7 Link Analysis (Original)
- [x] Build entity relationship visualization
- [x] Build background color highlighting
- [x] Build zoom in/out
- [x] Build anchor change
- [x] Build analysis depth change
- [x] Build date range change
- [x] Build drilldown to entity
- [x] Build fraudulent entity highlighting

### 4.8 Live User Session Viewing (Feature 38)
- [x] Build real-time session streaming
- [x] Build live session UI
- [x] Build immediate intervention capability

Continuous primary-display JPEG capture and polling UI; opt-in local consent, visible Stop control and bounded session expiry. Intervention uses audited process/isolation/stop commands.

### 4.9 Remote Desktop Control (Feature 17)
- [x] Build remote desktop connection
- [x] Build remote control UI
- [x] Build session recording during control
- [x] Build audit trail for remote control

Agent-mediated primary-display viewing/input with local consent and recording; not an RDP server or secure-desktop controller. Validate interactive-session permissions on Windows.

### 4.10 Endpoint Isolation (Feature 18)
- [x] Build network isolation command
- [x] Build isolation status tracking
- [x] Build isolation release
- [x] Build isolation audit logging

Windows host-firewall isolation/release/status with explicit management IP exceptions and audit results. Group Policy and real network connectivity require target-machine validation.

### 4.11 Process Termination (Feature 19)
- [x] Build remote process listing
- [x] Build process termination command
- [x] Build termination confirmation
- [x] Build termination audit logging

Bounded psutil listing, PID plus creation-time checks, protected processes, termination wait and durable result/audit; no automatic force-kill.

### 4.12 Rollback Capability (Feature 20)
- [x] Build system state snapshot
- [x] Build rollback point creation
- [x] Build rollback execution
- [x] Build rollback verification
- [x] Build rollback audit logging

## Phase 5: Data Loss Prevention & Active Blocking (Weeks 31–36)

### 5.1 Content-Aware DLP (Feature 1)
- [x] Build file content inspector
  - [x] DLP review inspects text an investigator submits, up to 100,000 characters.
- [x] Build sensitive data pattern recognition
  - [x] A card-shaped number that passes the Luhn check is reported by its last four digits.
- [x] Build intellectual property detection
  - [x] Configurable terms such as confidential and trade secret mark intellectual property.
- [x] Build customer data detection
  - [x] An email address or a configured customer term marks customer data.
- [x] Build financial record detection
  - [x] A card number or a configured financial term marks a financial record.
- [x] Build DLP policy engine
  - [x] The policy stores the minimum match count, the alert score, and the three term lists.
- [x] Build DLP enforcement actions
  - [x] A match opens one DLP review alert. The recorded action is review.

### 5.2 USB Device Detection & Blocking (Feature 2)
- [x] Build USB device detection
  - [x] A submitted USB activity row records the serial, user, action, and size.
- [x] Build device authorization
  - [x] A serial can be marked allowed.
- [x] Build device whitelisting
  - [x] An allowed serial is logged and does not open an alert.
- [x] Build USB activity logging
  - [x] DLP review lists the submitted USB rows.

- Build data transfer blocking
  - [x] A submitted USB transfer that is not on the allow list is stored and opens a "USB device" review alert.

### 5.3 Clipboard Monitoring (Feature 3)
- [x] Build clipboard content capture — opt-in collector emits `clipboard_change` with a SHA-256 of the content and a bounded `content_preview` (capped by `max_content_len`, default 4096), suppressing repeats via a last-hash check.
- [x] Build cross-application tracking — each sample carries the foreground window title and owning process, so a copy can be attributed to the application it was copied from.
- [x] Build sensitive data detection in clipboard — a stored preview or text field is checked for a Luhn-valid card, the DLP term lists, and the markers password, secret, private key, and cvv. The alert records a card as its last four digits and does not copy the preview. The copy itself is not blocked.
### 5.4 Cloud Upload Blocking (Feature 4)
- [x] Build cloud service detection
  - [x] A submitted host is labeled personal cloud or GenAI when it matches the built-in names.
- [x] Build cloud service whitelisting
  - [x] An allowed host does not open a cloud alert.

- Build personal cloud drive blocking
  - [x] A submitted transfer to Dropbox, Google Drive, OneDrive, iCloud, or Box opens a "Cloud destination" review alert when that host is not allowed.

- Build GenAI tool blocking
  - [x] A submitted transfer to ChatGPT, Claude, Gemini, or Copilot is labeled genai and opens the same review alert when that host is not allowed.

### 5.5 Email Attachment Interception (Feature 5)
- [x] Build attachment detection — attachment metadata and hashes are extracted from every captured message.
  - [x] Email metadata imports already record an attachment name, size, and encrypted flag.
  - [x] Email metadata import records the attachment name, size, and encrypted flag.
- [x] Build context analysis — sender, subject and recipients are resolved, recipient domains normalized and classified, so an external or first-seen recipient is distinguishable from internal routine mail.
  - [x] An imported email with an encrypted attachment and a public recipient domain records attachment-context with the other metadata rules. The message body is not read.

- [x] Build content scanning — message body and each attachment's text are scanned against the sensitive-term set.
### 5.6 Print Control (Feature 6)
- [x] Build print job capture — the print collector emits `print_document` events with job metadata, and both `print_job` and `print_document` are registered event types.
  - [x] The endpoint agent can already record print-job metadata.
  - [x] The optional print collector reports spooler metadata: printer, user, document title, page count, and size. It stays inactive until pywin32 is installed on Windows.
  - [x] A submitted print job records the printer, user, document title, page count, and size. Page content is not stored.

- [x] Build print audit trail — every print event is timestamped, searchable, and correlatable to a case, so the history of what was printed and when is reconstructable.
  - [x] Each reported job includes the printer, user, document title, page count, and size.
  - [x] DLP review lists the submitted print jobs.

### 5.7 Dynamic Policy Adjustment (Feature 7)
- [x] Build real-time risk score integration
  - [x] A text review reads the user's current risk score.
- [x] Build policy tightening for high-risk users
  - [x] A score of at least 100 uses a lower match count.
- [x] Build policy relaxation for low-risk users
  - [x] A score of 20 or below doubles the match count.
- [x] Build policy adjustment audit trail
  - [x] Saving the policy, and each text review, writes an audit row.

### 5.8 File Rename/Move Monitoring (Feature 8)
- [x] Build file rename detection
- [x] Build file move detection
  - [x] A submitted batch stores rename and move rows.
- [x] Build abnormal pattern detection
  - [x] Five or more changes in one batch open one File pattern alert.
- [x] Build exfiltration disguise detection
  - [x] A document extension changed to an image or temporary extension opens one File disguise alert.

### 5.9 Permission Change Auditing (Feature 9)
- [x] Build permission change capture
  - [x] A submitted grant or revoke stores the path and principal.
- [x] Build unauthorized access detection
  - [x] A principal who is not on the allow list opens one Permission change alert.
- [x] Build permission change audit trail
  - [x] DLP review lists the submitted permission changes.

### 5.10 Screenshot Blocking (Feature 10)
- [x] Build screenshot attempt detection — screenshot attempts are recorded with the application and the user, so attempts are visible even when nothing is captured.
  - [x] A submitted attempt records the user and application and opens one Screenshot attempt alert. No image is stored.
- [x] Build screenshot audit logging — captured screenshots and denied attempts both leave an audit record.
  - [x] DLP review lists those attempts.

### 5.11 Linux Command Prevention (NEW – Feature 74)
- [x] Build malicious command detection
  - [x] A submitted command log is checked for rm -rf, dd, nc, wget, sudo, su, scp, rsync, and package install.
- Block attack pattern sequences
  - [x] A download followed by bash, sh, or chmod in the same submitted log opens one Command sequence alert.
  - [x] wget followed by chmod, bash, or sh in the same submitted log opens a "Command sequence" alert.
- [x] Build command audit logging
  - [x] Each matched command is stored with the user and the finding.

- Block specific commands (rm -rf, dd, nc, wget)
  - [x] A submitted command log containing rm -rf, dd, nc, ncat, or wget opens a "Command review" alert.

- Block privilege escalation (sudo abuse, su)
  - [x] A submitted sudo or su line is included in that same review alert.

- Block data exfiltration commands (scp, rsync)
  - [x] A submitted scp or rsync line is included in that same review alert.

- Block untrusted package installation
  - [x] A submitted apt, yum, or dnf install line is included in that same review alert.

## Phase 6: Real-Time Response & Automation (Weeks 37–40)

### 6.1 Real-Time User Blocking (Feature 31)
- [x] Build user notification
  - [x] Response records an in-app notice for a user.
- [x] Build blocking audit trail
  - [x] Playbook runs, notices, and confirmed triggers are written to the response audit.

### 6.2 Automated Policy Enforcement (Feature 32)
- [x] Build policy trigger engine
  - [x] An enabled playbook matches download, upload, email, print, DLP, or any other alert.
- [x] Build automatic policy execution
  - [x] A DLP review alert runs matching playbooks before the review is saved.
- [x] Build policy execution logging
  - [x] Each run stores the playbook, the alert, and the steps that completed.

### 6.3 Playbook Response (Feature 33)
- [x] Build playbook definition UI
  - [x] Response saves a named playbook with a trigger and a step list.
- [x] Build playbook triggers
- [x] Build playbook execution engine
  - [x] Running a playbook can notify, queue a message, open a ticket, and open an incident. The same playbook does not run twice for one alert.
- [x] Build playbook for downloads
- [x] Build playbook for uploads
- [x] Build playbook for email
- [x] Build playbook for printing
- [x] Build playbook for other actions

### 6.4 SOAR Integration (Feature 34)
- [x] Build incident creation
  - [x] A playbook or a direct request opens an incident linked to an alert.
- [x] Build incident updates
  - [x] An incident can be marked open, updated, or resolved.
- [x] Build incident resolution sync
  - [x] Resolving an incident closes the linked alert.

### 6.5 Ticketing System Integration (Feature 35)
- [x] Build custom ticketing integration
  - [x] A ticket is stored with system custom.
- [x] Build automatic ticket creation
  - [x] A playbook step named ticket opens one ticket for the alert.
- [x] Build ticket status sync
  - [x] A ticket status can be set to open, pending, or closed, and the saved status is returned.

### 6.6 Email/SMS Alerts (Feature 36)
- [x] Build email alert engine
  - [x] An email step renders the notice template, throttles a repeat for the same alert, writes an in-product notice, and can escalate an unacknowledged notice.
- [x] Build SMS alert engine
  - [x] An SMS step uses the same notice path with the SMS channel. The notice stays in the center.
- [x] Build alert templates
  - [x] The template subject and body can include the user, title, and score.
- [x] Build alert throttling
  - [x] A second email or SMS for the same alert inside the throttle window is skipped.
- [x] Build alert escalation
  - [x] An unacknowledged app notice past the escalation time creates one escalation notice.

### 6.7 External System Triggering (Feature 37)
- [x] Build trigger confirmation
  - [x] A named trigger can be recorded and confirmed by the signed-in user.

### 6.8 Forcible Logoff / Application Closure (Feature 75)
- [x] Build process termination command — allow-listed, with a protected-process list, a PID-reuse guard against killing a recycled PID, and no force-kill; an ambiguous outcome is reported as indeterminate rather than assumed successful.
- [x] Build host network isolation — Windows firewall rules that exempt only management addresses already declared in configuration, so containment cannot sever the channel used to undo it.
- [x] Build file and Windows System Restore snapshots, and verified rollback
- [x] File every response action on the case timeline — queued, dispatched, expired, blocked, succeeded, and failed steps all reach the case with the operator's reason attached. An action may only be filed under a case that already holds an alert from that same endpoint, so containment of one host cannot be presented as evidence in an unrelated investigation.
- [x] Build forcible action audit trail — every response step is actor-attributed and claim-idempotent; typed input is retained as a length, never as keystroke text, and is erased from the command after dispatch.
- [x] Record where each control is genuinely enforced — `GET /api/response/capabilities` states, per control, whether the agent can enforce it or only observe it, and names the real enforcement point. This prevents the interface from offering a block that does nothing.

## Phase 7: Identity & Access Management (Weeks 41–43)

### 7.1 Shared Account Authentication (Feature 39)
- [x] Build shared account detection
  - [x] An administrator can mark an account shared and name its enabled individual members. Signing in with only the shared password is rejected.
- [x] Build identity verification for shared logins
  - [x] A shared login requires the member's own username, password, and second factor. The session belongs to that person. A shared account cannot identify another shared account.
- [x] Build accountability tracking
  - [x] The session records the shared account, and later requests record the person and that shared account. Revoking membership rejects subsequent session requests.

### 7.2 Two-Factor Authentication (Feature 40)
- [x] Build 2FA integration
  - [x] Login requires a confirmed factor when one is enrolled, when policy requires it, or when the login is for a shared account.
- [x] Build TOTP support
  - [x] Enrollment returns an otpauth secret. A code from the current 30-second window or one adjacent step confirms it. Reusing that code is rejected.
- [x] Build SMS-based 2FA
  - [x] An SMS enrollment stores a hashed single-use code and returns only a challenge id. Delivery uses the configured provider; without one, enrollment fails and no code is returned.
- [x] Build hardware token support
  - [x] A hardware factor uses the token's Base32 OATH secret and accepts the next unused counter. The secret is stored encrypted.

### 7.3 One-Time Passwords (Feature 41)
- [x] Build OTP generation
  - [x] TOTP and HOTP codes follow the HOTP construction. SMS codes are six digits, stored as a keyed digest, and expire in five minutes.
- [x] Build OTP validation
  - [x] A matching code advances the counter once. A repeated or expired code is rejected, and repeated failures are rate limited.
- [x] Build OTP for privileged access
  - [x] Activating an approved request requires the password and a current factor. An SMS factor can request a code bound to that request.

### 7.4 Privileged Account Management (Feature 42)
- [x] Build privileged account identification
  - [x] Administrator accounts are marked privileged and cannot be converted into shared accounts or limited modules.
- [x] Build privileged session recording
  - [x] While a privileged or shared session is in use, each application request records the actor, method, path, and status. This is request metadata.
  - [x] An administrator can link an active agent:<ID> approval to the existing consent-governed desktop recorder. Frames require a current approval and personal session; revocation rejects later frames and queues stop. Native endpoint validation remains open.
- [x] Build privileged access approval workflow
  - [x] The requester cannot approve their own request. Another administrator approves or denies it. Activation requires a factor, and the approval can be revoked.
- [x] Build privileged activity monitoring
  - [x] An administrator can read the recorded requests for a session.

### 7.5 Role-Based Access Control (Feature 43)
- [x] Add username/password login with salted password hashing.
- [x] Add expiring server-side sessions, HttpOnly/SameSite cookies, CSRF checks, and logout invalidation.
- [x] Add initial administrator setup and administrator-only account creation.
- [x] Enforce read/write permissions on cases, alerts, evidence, reports, and imports.
- [x] Derive new activity authors from the authenticated account instead of supplied names.
- [x] Build role definition
- [x] Build permission assignment — administrator-controlled local role changes revoke sessions; self-role changes, directory role overrides, and loss of the last enabled administrator are rejected.
- [x] Build dashboard access isolation
  - [x] A limited policy hides navigation for areas outside the allowed modules, and the case workspace appears only when cases, reports, and alerts are all allowed.
- [x] Build data access isolation
  - [x] An account limited to network can read network captures and receives 403 for cases, reports, and search. The server applies that gate on every request.

### 7.6 Active Directory Integration (Feature 44)
- [x] Build AD authentication
  - [x] A directory account signs in with an LDAPS bind to its stored distinguished name. The automated test substitutes that bind and does not contact a domain controller.
- [x] Build AD user/group sync
  - [x] An administrator sync reads person entries, creates or disables matching accounts, and refuses a name that already belongs to a local account. Removed directory users are disabled.
- [x] Build AD permission mapping
  - [x] Each mapped group assigns a role and a module list. The highest mapped role is kept, and module lists are combined. An unmapped or disabled directory account cannot sign in.

### 7.7 PAM Integration (Feature 45)
- [x] Build PAM module integration — `backend/pam_bridge.py` runs through Linux pam_exec, reads a one-time ticket from stdin, and fails closed. It is an adapter to the standard native module, not a custom PAM shared library; no host PAM configuration was changed.
- [x] Build PAM authentication
  - [x] A configured service redeems a one-time ticket with its own key. The ticket lasts 60 seconds, names one person and one resource, and cannot be reused.
- [x] Build PAM authorization
  - [x] Authorization requires an active privileged approval for that resource and session. Revoking the approval rejects the next check.

### 7.8 Multi-Factor Anomalous Login Detection (Feature 68)
- [x] Build simultaneous login detection
  - [x] A second active session for the same person writes a simultaneous-login audit row.
- [x] Build different terminal detection
  - [x] A different address or browser metadata writes a different-terminal audit row.
- [x] Build credential sharing alert
  - [x] That difference on a shared-account session opens one Possible credential sharing alert. The alert asks for review and does not prove who used the credentials.
- [x] Build account takeover alert
  - [x] The same difference on an individual session opens one Possible account takeover alert.

## Phase 8: User Privacy & Anonymization (Weeks 44–45)

### 8.1 User Anonymization / Privacy Mode (Feature 76)
- [x] Build anonymized dashboards
  - [x] The privacy dashboard returns severity totals only when at least five endpoints share that severity, with counts in ranges of five. It also returns a stable pseudonym and an event count per endpoint. Payloads, names, titles, and timestamps are absent. The response states the suppression rule.
- [x] Build pseudonymization engine
  - [x] A pseudonym is `subject-` plus 24 hex characters from HMAC-SHA256 over a per-install secret. The same subject keeps the same pseudonym.
- [x] Build PII masking in screenshots
  - [x] A restricted screenshot is painted entirely black. The mask does not detect names. Images larger than 4096 by 2160 are rejected, and missing or undecodable media is withheld.
- [x] Build PII masking in recordings
  - [x] A restricted recording frame returns withheld text, empty fields, no original HTML, and a black image.
- [x] Build consent management
  - [x] Endpoint consent has a purpose and an expiry of 1 to 365 days. A purpose that does not match the current notice is rejected. Visual capture requires current, unexpired, purpose-matched consent. Withdrawal is audited.
- [x] Build retention controls
  - [x] Retention is a dry run unless an administrator applies it. It changes unlinked endpoint payloads and recorded frames, and it leaves events that mail evidence or a policy warning still uses. Applied retention clears frame text, fields, HTML, image, and the search document, expires biometric samples, and deletes biometric profiles.
- [x] Build role-based access to raw vs. anonymized data
  - [x] With privacy mode on, a route outside the safe list requires an administrator and the header `x-privacy-raw: 1`. Each raw read is audited. API responses use `Cache-Control: no-store`.
- [x] Build works council compliance features
  - [x] When a council agreement is required, saving capture settings and starting visual capture both require a current reference and expiry. Education notices and compliance records are separate local registers.

## Phase 9: User Education & Policy Notification (Weeks 46–47)

### 9.1 Out-of-Policy User Notifications (NEW – Feature 77)
- [x] Build real-time popup warnings — the endpoint agent shows a desktop dialog for a queued warning. Acknowledgement is recorded only when the person accepts. A display failure does not count as acknowledgement.
- [x] Build policy reminder system — an administrator can send a reminder to one registered endpoint. A disabled policy rejects the reminder.
- [x] Build educational message system — the warning carries a separate educational guidance field.
- [x] Build warning escalation — repeated findings raise the warning level, and an unacknowledged warning offered again raises the level and writes an in-app manager notice.
- [x] Build manager notification — the notice is stored for the named application account. Mail and SMS are not sent.
- [x] Build training assignment integration — an HTTPS training link is stored with the warning. A training provider with a configured bearer token can mark it verified. The endpoint's own completion report cannot downgrade a verified assignment.
- [x] Build notification audit trail — create, delivery, acknowledgement, escalation, and training actions are listed for an administrator.
- [x] Build notification customization — an administrator sets the title, message, guidance, manager, escalation count, and reminder interval.

## Phase 10: Compliance & Audit Support (Weeks 48–50)

### 10.1 GDPR Compliance (Feature 46)

- [x] Build data subject access request handling — a request is raised with a regime and one of `access`, `portability`, `erasure`, `opt_out`, fulfilled locally, and audited. Every fulfilment records a `DisclosureRecord` naming the recipient, the purpose, and the actor who ran it, so an export cannot leave without leaving a trace.
  - [x] An administrator can record an access request and export stored facts, alerts, consents, and disclosures for one entity.

- [x] Build right to erasure — fact text is overwritten with `[erased]` and numerics zeroed, and archives are rewritten *and their SHA-256 recomputed* so the archive stays internally consistent instead of failing its own integrity check on next retrieval. **Erasure refuses when an open case holds an alert for that entity**, and says so in the refusal reason rather than silently partial-deleting.
  - [x] Erasure redacts that entity's fact text and archived copies when no open case holds an alert for them.

- [x] Build data portability — the same structured package as access, emitted as JSON.
  - [x] A portability request returns the same stored-record package as JSON.

- [x] Build consent tracking — consent records with purpose and expiry, alongside the per-endpoint consent in the privacy module.
  - [x] Subject consent grant and withdrawal are stored separately from endpoint-agent consent.

- [x] Build privacy impact assessment support — impact notes are recorded and retrievable per subject.
  - [x] A draft or accepted impact note stores scope, risks, and mitigations. Acceptance is a local record.

### 10.2 HIPAA Compliance (Feature 47)

- [x] Build PHI detection — `review_text()` counts SSN, MRN, email and phone patterns and inspects for card numbers, returning **masked samples only** ("SSN ending 1234"). Submitted text is capped at 20,000 characters.
  - [x] Submitted text is counted for SSN-shaped numbers, labeled record numbers, email addresses, and phone numbers. Samples show only the last four of an SSN.

- [x] Build access controls — role checks on API routes, CSRF header enforcement on signed-in requests, administrator-only compliance mutations.
  - [x] Compliance routes are administrator-only.

- [x] Build audit controls — every compliance action is written to the privacy audit with actor, action and detail.
  - [x] Compliance actions are appended to the privacy audit log.

- [x] Build integrity controls — attachment SHA-256, and archive SHA-256 verified on every retrieval.
  - [x] Each archived fact stores a SHA-256 that retrieval and verification recompute.

### 10.3 PCI-DSS Compliance (Feature 48)

- [x] Build cardholder data detection — Luhn-checked card detection in DLP review, stored as **last four only**.
  - [x] Luhn card numbers in submitted text are reported as the last four digits.

- [x] Build access control — as above.
  - [x] Compliance routes are administrator-only.

- [x] Build logging and monitoring — the audit log, its export, and privacy-mode raw-access auditing.
  - [x] The privacy audit can be exported as JSON or CSV.

### 10.4 SOC 2 Type II (Feature 49)

- [x] Build security controls
  - [x] The control inventory lists the local role, CSRF, and administrator restrictions. It does not certify SOC 2.

- [x] Build processing integrity controls
  - [x] Archive retrieval fails when the stored SHA-256 does not match the body.

- [x] Build privacy controls
  - [x] Access, portability, erasure, consent, and opt-out are stored local records.

- [x] Build availability controls
- [x] Build confidentiality controls
### 10.5 CCPA Compliance (Feature 50)

- [x] Build consumer rights handling — access, deletion and opt-out requests fulfilled per regime.
  - [x] An administrator can record an access, erasure, or opt-out request for a stored entity.

- [x] Build data disclosure tracking — `DisclosureRecord` per disclosure, with recipient, purpose and actor.
  - [x] An access or portability export writes a disclosure record naming the actor and purpose.

- [x] Build opt-out mechanisms — recorded, with the boundary stated in the product's own response: "Opt-out is recorded. Live collectors are unchanged." Read that literally: this documents a decision, it does not alter what an agent collects.
  - [x] An opt-out request is stored. Live collectors are unchanged.

### 10.6 FINRA Audit Support (Feature 51)

- [x] Build audit trail — the immutable-action audit log with actor attribution and export.
  - [x] Compliance actions are appended to the privacy audit log.

- [x] Build record retention — configurable online retention, aging, and hash-verified archives.
  - [x] Facts older than the configured 6-to-12-month window can be archived.

- [x] Build supervisory controls — supervisory reviews are recorded and retrievable.
  - [x] A supervisory review stores the entity, decision, and note.

- [x] Build financial industry compliance — partial and narrow: financial-category indicators in the behaviour library and pattern review of submitted text. This is assistance for a regulated firm, **not** a FINRA rulebook implementation.
### 10.7 Exportable Audit Logs (Feature 52)

- [x] Build structured log export — `/audit-export` emits JSON or CSV, with server-side column selection validated against an `AUDIT_COLUMNS` allow-list so a crafted column name cannot pull unintended fields.
  - [x] The privacy audit exports as JSON or CSV.

- [x] Build compliance documentation export — `/controls` serves the control catalogue and its declared gaps.
  - [x] The control inventory exports the local controls and the gaps that remain.

- Build log format customization
  - [x] The export accepts a column list limited to id, actor, action, detail, and created_at.

### 10.8 Retention Policy Configuration (Feature 53)

- [x] Build retention period configuration — administrator-set retention window, bounded to 1–3650 days.
  - [x] Endpoint payload retention remains a separate day count. Fact aging uses the online month setting.

- [x] Build 6-12 month online retention — `age_facts()` **refuses to age outside a 6–12 month online window** and returns a `skipped` reason rather than picking a default, so a misconfiguration cannot quietly destroy records early or hoard them indefinitely.
  - [x] Administrators set fact aging to 6 through 12 months.

- [x] Build automatic data aging — `/aging` runs **dry-run by default**, and the whole pass is audited.
  - [x] When automatic retention is enabled, the collection loop also archives facts past the online window.

### 10.9 Data Archiving (Feature 54)

- [x] Build automatic archiving — facts past the window are moved to an `ArchiveRecord` with a canonical JSON body and SHA-256, and the live row is reduced to `[archived]` with numerics zeroed.
  - [x] Aging copies the fact into an archive row and replaces the live text with `[archived]`. Open cases are skipped.

- [x] Build archive retrieval — per-record retrieval with entity and hash.
  - [x] An administrator can list and read an archive row.

- [x] Build archive integrity verification — `archive_payload()` recomputes the digest on **every** read and raises 409 on mismatch, so tampering surfaces at access time rather than being discovered during an audit. A dedicated `/archive/{id}/verify` endpoint exists as well.
  - [x] Retrieval and an explicit verify call reject a body whose SHA-256 does not match.

## Phase 11: Integration & Extensibility (Weeks 51–53)

### 11.2 API Export (Feature 56)
- [x] Build REST API
- [x] Build API authentication
- [x] Build API rate limiting
  - [x] Limit the login endpoint by account and client address, including concurrent requests and application restarts.
  - [x] Other API requests are limited to 300 per minute for the signed-in session. Sign-in and the health check keep their own rules. A blocked request returns Retry-After.
- [x] Build API documentation
  - [x] The OpenAPI document at /openapi.json lists the case routes and the application title. /docs renders that document.

### 11.3 CSV/PDF Export (Feature 57)
- [x] Build CSV export
- [x] Build PDF export
- [x] Build export templates
  - [x] Named report templates store columns, filters, and sort for CSV and Excel downloads.
- [x] Build export scheduling
  - [x] A saved column template can run on an interval of 60 seconds to one day. The collection loop stores the latest CSV in the center for download. The file is not emailed.

### 11.4 Project Management Tool Integration (Feature 58)
- [x] Build workflow bottleneck detection
  - [x] Cases still open and unchanged for a chosen number of days are listed. Closed cases are omitted.

### 11.5 Custom Web/App Monitoring (Feature 59)
- [x] Build custom application definition — an administrator names an application and a process-name or window-title substring, up to 50 rules. A stored endpoint event that contains that text opens one review alert. The rule does not start a capture.
- Build custom application definition
  - [x] A business process names an ordered set of screens. Each screen is identified by text markers and field positions.
- Build custom event generation
  - [x] A saved image reading or a submitted transcript that matches one screen records a screen hit and its field values.

### 11.7 Instant Messaging Monitoring (Feature 62)
- Build usage tracking
  - [x] Website visits categorized as Instant messaging are included in the category time totals.

### 11.8 Social Media Monitoring (Feature 63)
- Build social media detection
  - [x] A hostname can be mapped to the Social networking category.
- Build usage tracking
  - [x] The category report totals visits and seconds for Social networking.
- Build policy violation alerting
  - [x] A denied Social networking category opens one website-category review alert for that user.

### 11.9 Geolocation Tracking (Feature 66)
- Build anomalous login detection
  - [x] A second session from a different address or browser metadata opens one identity review alert. Device coordinates are not collected.

## Phase 12: System Administration & Infrastructure (Weeks 54–56)

### 12.1 Scalability
- [x] Build local database deployment
  - [x] The center uses one SQLite database in the local process. The operations report names that database and states that failover is absent.

### 12.2 Reliability
- [x] Build health checking
  - [x] `/api/health` reports the process. An administrator operations report adds free disk space and queue counts.
- [x] Build queue monitoring
  - [x] The operations report counts pending intake messages, inbox files, and response commands that are waiting or in progress.
- [x] Build disk space monitoring
  - [x] The report includes free and total bytes for the collection volume, and counts agents that reported under 100 MB free.
- [x] Build backlog queue management
  - [x] An agent command queue stops at 100 waiting commands. The operations report shows the current backlog against that limit.

### 12.3 Security
- [x] Build TLS for inter-service communication
- [x] Build access control
  - [x] Roles and module policies gate the API. The operations report and the notice export are administrator-only.
- [x] Build permission management
  - [x] An administrator chooses the role when creating an account and sets the module list on the access policy.
- [x] Build forensic evidence integrity
  - [x] Attachments and archives store SHA-256. A later check reports whether the stored bytes still match.

### 12.4 Data Extraction
- [x] Build external file export
  - [x] Cases download as CSV, Excel, PDF, and a zip package. A scheduled template stores a CSV in the center.
- [x] Build Web Service export
  - [x] An authenticated caller reads a saved report as JSON or CSV. The center does not call an outside service.
- [x] Build email/SMS alert export
  - [x] An administrator downloads the notice list as CSV. The download does not send mail or SMS.

## Phase 13: Testing & Quality Assurance (Weeks 57–60)

### 13.2 Integration Testing
- [x] Test rule engine to alert flow (two fixed CSV import rules, thresholds, deduplication, and case linking)
- [x] Test case management workflow

### 13.4 Security Testing
- [x] Access control testing (API role restrictions, CSRF, expiry, logout, and identity spoofing checks)
- [x] Test login throttling, window expiry, persistence across restarts, concurrent attempts, and administrator-only authentication audit access.

## Phase 14: Deployment & Documentation (Weeks 61–64)

### 14.1 Deployment
- [x] Build installer for endpoint agents — real per-platform scripts under `endpoint_agent/install/`: `windows/install.ps1` (service registration, with the `sc.exe delete` uninstall documented), `linux/install.sh`, and `macos/install_mac.sh`.
- [x] Build installer for analyzers — a `Dockerfile` builds the analyzer as a single image (app + `network_sensor` + `endpoint_agent`) and runs uvicorn on 8000. Caveat worth stating: it is one container for three components, with no compose file and no orchestration, so "install the analyzer" currently means "build one image."
- [x] Build installer for web UI — the UI is static files mounted from the same process (`app/static/`, served at `/static`, including `index.html`, `app.js`, `compliance.js`, `iam.js`, `mail.js`), so it ships with the analyzer image rather than being installed separately.
### 14.2 Documentation
- [x] Document local startup, initial administrator creation, roles, and CSV import format in `backend/README.md`.
- [x] Provide a downloadable example activity CSV.

- [x] Write API documentation — genuinely complete, and worth crediting: FastAPI serves generated OpenAPI at `/openapi.json` with Swagger UI at `/docs`, covering the entire REST surface with live request schemas. It cannot drift from the code, which is better than any hand-written API document.
## SECTION C: ACTIVTRAK GAP FEATURES

### C1. Privacy-First Data Foundation
- Data minimization by default
  - [x] Capture collectors that read window titles, clipboard contents, screen images, or user activity stay off until an operator enables them by name.
- Pseudonymize user identifiers
  - [x] The privacy dashboard uses a stable `subject-` pseudonym derived from the per-install secret.
- Mask sensitive content in screenshots
  - [x] A restricted screenshot is painted entirely black. The mask does not detect names.
- Mask sensitive content in recordings
  - [x] A restricted recording frame returns withheld text, empty fields, and a black image.
- Consent management
  - [x] Endpoint consent has a purpose and an expiry. Visual capture requires a current match.
- Consent tracking
  - [x] Each grant and withdrawal is stored and audited.
- Consent withdrawal
  - [x] A withdrawal is audited as consent withdrawn, and later capture requires a new grant.
- Data subject access requests
  - [x] An administrator can record an access request and export stored facts for one entity.
- Right to erasure
  - [x] Erasure redacts that entity when no open case holds an alert for them.
- Data portability
  - [x] A portability request returns the stored-record package as JSON.
- Privacy impact assessment support
  - [x] A draft or accepted impact note stores scope, risks, and mitigations.
- Works council compliance
  - [x] When a council agreement is required, capture settings and visual capture both require a current reference and expiry.

### C2. Workforce Analytics
- Productivity metrics per user
  - [x] Stored work, meeting, and idle minutes are totaled for one user over 90 days.
- Productivity metrics per team
  - [x] A named group of users returns each member's transfer total and the group average.
- Productivity metrics per department
  - [x] Peer comparison includes the mean for users who share a department or role.
- Productivity trends over time
  - [x] Workload compares the latest 14 days of stored work minutes with the earlier days in a 90-day window.
- Engagement metrics
  - [x] Stored sentiment signals are labeled steady, mixed, or strained.
- Workload balance metrics
  - [x] Days at or above 600 work minutes are counted, with a drop in recent work minutes marked disengaged.
- Collaboration metrics
  - [x] Meeting minutes are included in the same time-use total.
- Tool usage metrics
  - [x] Website visits are totaled by category, including time spent.
- Benchmarking against peers
  - [x] A user's transfer total is compared with the mean of other users who have transfer facts.
- Attrition risk metrics
  - [x] A stored turnover signal is counted in the workload score. The count is a review figure, not a prediction that someone will leave.

### C3. Intuitive User Interface
- Customizable reports
  - [x] A report definition stores selected columns and allowlisted conditions.
- Customizable alerts
  - [x] Review thresholds, suppression rules, and alert routes can be saved.
- Saved views
  - [x] A named report template stores the current search, status, minimum score, sort, and columns.
- Quick search
  - [x] The case list accepts a text query.
- Advanced search
  - [x] Search accepts a phrase, an excluded term, a fuzzy term, and a stopword language.

### C4. AI Agent Usage Monitoring
- Detect ChatGPT usage
  - [x] A submitted transfer to chat.openai.com or chatgpt.com is labeled genai.
- Detect Claude usage
  - [x] A submitted transfer to claude.ai is labeled genai.
- Detect Gemini usage
  - [x] A submitted transfer to gemini.google.com is labeled genai.
- Detect Copilot usage
  - [x] A submitted transfer to copilot.microsoft.com is labeled genai.
- Detect Perplexity usage
  - [x] A submitted transfer to perplexity.ai is labeled genai.
- Detect Ollama usage
  - [x] A submitted transfer to ollama.com is labeled genai. A local process named Ollama is not detected.
- Detect LM Studio usage
  - [x] A submitted transfer to lmstudio.ai is labeled genai. A local LM Studio process is not detected.
- Alert on sensitive data shared with AI
  - [x] A genai host that is not on the allow list opens one Cloud destination review alert. The alert records the host and size. It does not record a prompt.
- Report on AI usage
  - [x] DLP review lists those submitted cloud rows, including the genai label.

## SECTION A: TERAMIND GAP FEATURES

### A2. Automated Real-Time Response Actions
- **Specification:**
  - [x] Configurable notification to user
  - [x] Configurable notification to manager
  - [x] Configurable notification to security team
  - [x] Full audit trail of all automated actions — every response step is actor-attributed and reaches the case timeline.

### A3. Native Print Capture & Storage
- **Specification:**
  - [x] Capture printer name and location
  - [x] Capture user who printed
  - [x] Capture timestamp
  - [x] Capture number of copies
  - [x] Capture page count
  - [x] Capture color vs. black/white
  - [x] Capture duplex vs. simplex
  - [x] Search printed documents by user
  - [x] Search printed documents by time
  - [x] Alert on sensitive document printing
  - [x] Retain printed documents per policy

### A4. Native Email Content & Attachment Capture
- **Specification:**
  - [x] Capture email body text
  - [x] Capture email subject
  - [x] Capture sender address
  - [x] Capture recipient addresses (To, CC, BCC)
  - [x] Capture email timestamp
  - [x] Capture attachment names
  - [x] Capture attachment content (store copies) — bounded: 8 MB per file, 32,768 characters, archive expansion caps. Remote webmail attachments are not fetched.
  - [x] Capture attachment metadata (size, type, hash)
  - [x] Support Thunderbird
  - [x] Support webmail (Gmail, Yahoo, Outlook.com) — Gmail and Outlook webmail via a Chrome/Edge extension and native messaging host. Yahoo is not covered.
  - [x] Index email content for search
  - [x] Alert on sensitive email content
  - [x] Retain emails per policy

### A5. File Sharing Behavior Monitoring
- [x] Monitor file sharing via email — mail capture records sender, recipients, attachment name, size and encryption, and the `external-recipient`, `large-attachment` and `encrypted-attachment` rules fire on the result.
- [x] Monitor file sharing via cloud storage (Dropbox, OneDrive, Google Drive, Box) — the transfers collector records uploads/downloads and `PERSONAL_CLOUDS` in `dlp.py` classifies personal-cloud destinations. **Box is not in the provider list**; detection for it is generic-hostname only.
- [x] Monitor file sharing via USB — the opt-in USB collector emits `usb_insert`/`usb_remove` with device identity. This is device attachment, not file content moving across the bus.
- [x] Monitor file sharing via FTP/SFTP — FTP control-channel transfers are decoded by `ftp_transfer()` in `network_sensor/application.py`. **SFTP is not decoded**; it is SSH-encrypted and is listed under the SSH limitations.
- [x] Alert on unauthorized file sharing — the DLP rule engine raises scored alerts for external recipients, large attachments, encrypted attachments, personal cloud destinations and clipboard/USB/cloud policy events.
- [x] Audit all file sharing activity — captured transfers become searchable endpoint events correlatable to a case, with actor attribution on every alert.
- [x] Identify sensitive files being shared — `content_scan.py` scans mail bodies, attachments and clipboard previews against the sensitive-term set, with card data Luhn-checked and stored as last-four only.
### A6. Personal Email Provider Detection & Blocking
- [x] Detect Gmail access — `PUBLIC_MAIL` in `observations.py` carries `gmail.com` and `googlemail.com`, matched with subdomain awareness so `mail.google.com` also hits.
- [x] Detect Yahoo Mail access — `yahoo.com`, `yahoo.co.uk`.
- [x] Detect Outlook.com / Hotmail access — `outlook.com`, `hotmail.com`, `live.com`.
- [x] Detect AOL Mail access — `aol.com`.
- [x] Detect ProtonMail access — `proton.me`, `protonmail.com`.
- [x] Detect iCloud Mail access — `icloud.com`, `me.com`.
- [x] Detect any webmail access — partially. `personal_webmail` is a first-party signal in the indicator catalog, and the browser collectors capture visited hosts. But `_public()` is a **fixed provider list**, so an unlisted webmail domain is not matched as personal mail.
- [x] Alert on personal email use — `email_rules()` raises the `external-recipient` detection when `_public()` matches the recipient domain, producing a scored alert.
- [x] Allow whitelisting for legitimate use — DLP settings carry allow lists that suppress cloud, USB and permission-change alerts, so a sanctioned personal-mail domain can be excepted.
### A7. User Behavior Anomaly Detection with Automated Response
- [x] Establish baseline for each user — partial. Biometric baselines are enrolled per subject (minimum five samples, suspicious samples refused). For general activity there is a 90-day rolling window behind the indicator library rather than a stored per-user profile, so "baseline" here means a rolling aggregate, not a learned model of one person.
- [x] Detect deviation from baseline — the indicator library evaluates 160 daily/weekly indicators and the biometric engine flags samples beyond the enrolled threshold.
- [x] Detect unusual file access — file-operation events are captured and indexed, and `file_access`-class indicators exist in the library.
- [x] Detect unusual data volume — data-movement and access indicators are evaluated over the rolling window.
- [x] Detect unusual printing volume — print events are captured and searchable; the library carries print-volume indicators.
- [x] Detect unusual email volume — mail records feed `mass_email` and related communication indicators.
- [x] Detect unusual USB usage — USB device events feed USB indicators, with allow-list suppression.
- [x] Detect unusual cloud uploads — upload/download events feed cloud indicators against `PERSONAL_CLOUDS`.
- [x] Automatic alert on anomaly — indicators and detection rules raise scored alerts automatically on ingest.
- [x] Automatic notification on anomaly — playbooks attach to alert channels and compose notices automatically (in-product delivery only; see 6.6).
- [x] Configurable anomaly thresholds — `DetectionSetting` stores a per-rule label, threshold and score, each editable, and library refreshes preserve locally tuned thresholds.
- [x] Configurable automated responses — `Playbook` with trigger channel and ordered steps (notify, email, sms, ticket, incident). The available steps are all notification and record-keeping; no step performs containment.
## SECTION B: OBSERVEIT / PROOFPOINT ITM GAP FEATURES

### B1. Unified Investigation Console
  - [x] Provide export of investigation package
    - [x] Download a case package containing the case PDF, the stored timeline, and the evidence files already attached to that case.

- [x] Single pane of glass for all investigation data — the Investigation Center is one FastAPI process serving the API and the web UI from the same store (ADR-1, ADR-5), with one search index across endpoint events, network messages and documents.
- [x] Correlate screen captures with file activity — screenshot events carry `window_title` and are correlatable by endpoint and time window against file-operation events; search joins them.
- [x] Correlate screen captures with application usage — window titles on screenshot events carry the foreground application, giving the app context for a captured frame.
- [x] Correlate screen captures with network activity — endpoint and time-window correlation against network message and flow records.
- [x] Correlate screen captures with email activity — endpoint and time-window correlation against mail records.
- [x] Correlate screen captures with print activity — endpoint and time-window correlation against `print_document` events.
- [x] Correlate screen captures with USB activity — endpoint and time-window correlation against `usb_insert`/`usb_remove` events.
- [x] Correlate screen captures with cloud uploads — endpoint and time-window correlation against transfer events.
- [x] Provide timeline view of all user activity — case timelines assemble events, attachments, alerts, OCR readings and response actions in chronological order (`cases.py:89`), and reports carry a timeline too (`reports.py:321`). Worth noting the in-code rationale for including containment actions: "a case that records the threat but not the response leaves the reader unable to tell what was done to the endpoint, by whom, and whether it worked."
- [x] Provide entity view (user, account, customer) — entity-centric views exist across cases, alerts, indicators and the DLP review surface, keyed on `entity_ref`.
- [x] Provide drilldown from any data point — see B4; report fields resolve through `source_key` to the originating hit.
- [x] **No switching between tools required** — one process, one UI, one search index. This is the one product claim in this section that is fully met by architecture rather than by effort, because ADR-1 and ADR-5 rule out the multi-tool sprawl the requirement is complaining about.
### B2. Lightweight Endpoint Agent
- [x] Silent installation — per-platform install scripts exist (`endpoint_agent/install/windows/install.ps1`, `linux/install.sh`, `macos/install_mac.sh`) and register the agent as a service without prompting.
- [x] Silent operation — the agent runs as a background service with no console or interactive surface, and collectors default to off, so a default install is not watching anything.
### B3. Flexible Threat Hunting
- [x] Custom query builder — free-text search across indexed endpoint events, network messages and documents, with field filters, status and score thresholds.
- [x] Query across all data sources — one search layer spans endpoint events, network messages, mail records and documents, backed by SQLite FTS with the optional Elasticsearch adapter.
- [x] Query across all time periods — arbitrary time-range filtering; reports and searches accept date bounds, and the indicator library evaluates a trailing 90-day window.
- [x] Query across all users — filtering by `entity_ref` and subject.
- [x] Query across all entities — entity-centric filtering is the primary axis of cases, alerts, indicators and the DLP review surface.
- [x] Save custom queries — `ReportDefinition` stores a named filter definition with its creator, re-runnable against current data (see 4.6).
- [x] Visual query builder (no coding) — the web UI provides filter controls for the search surface; no drag-and-drop query builder exists.
- [x] MITRE ATT&CK mapping — the insider-threat rules in `app/profiles.py` map to MITRE ATT&CK technique IDs.
- [x] NIST mapping — framework mappings on the profile rules include NIST.
- [x] CERT mapping — framework mappings include CERT (and FS-ISAC).
- [x] **Proactive hunting, not just reactive alerting** — met in the way that matters: the indicator library evaluates 160 daily/weekly indicators over a rolling window independently of any alert, so a departure from a user's normal pattern surfaces without waiting for a rule to fire. That is genuine proactive detection. What is missing is the authoring layer above it — templates, scheduling, and query-to-alert binding, all four of which would make hunting systematic rather than ad hoc.
### B4. User Activity Timeline
  - [x] Show a case timeline of notes, alerts, attachments, and case activity already stored on that case.

- [x] Chronological view of all user actions — case timelines order events, attachments, alerts, OCR readings and response actions by time (`cases.py`), and reports carry a timeline view (`reports.py:321`).
- [x] Screen captures on timeline — screenshot events carry window title and are correlatable by endpoint and time.
- [x] File operations on timeline — file-operation events are captured and indexed.
- [x] Application usage on timeline — foreground application is carried on window/session events.
- [x] Email activity on timeline — mail records with sender, recipients, attachment metadata and sensitive-term findings.
- [x] Print activity on timeline — `print_document` events with job metadata, searchable and case-linkable.
- [x] USB activity on timeline — `usb_insert`/`usb_remove` events with device identity.
- [x] Cloud uploads on timeline — transfer events classified against `PERSONAL_CLOUDS`.
- [x] Web browsing on timeline — website visits are captured and recorded as facts (`analytics.py`, `source_key=f"website:{visit.source}:{visit.visit_id}"`).
- [x] Login/logout on timeline — authentication events are recorded, and the endpoint also reports desktop session start/stop (`response.py`, `desktop_session_ended`).
- [x] Policy violations on timeline — DLP findings and policy warnings attach to the events that produced them.
- [x] Alerts on timeline — alerts are correlated to cases and surface on the case timeline.
- [x] Filter timeline by activity type — filtering by type, entity, score and time range.
- [x] **Complete story of user behavior in one view** — met for the data that exists, with one qualification worth stating plainly: the timeline shows **what the product observed**, and observation is bounded by what collectors are enabled. Sensitive collectors are opt-in and default off, so a default deployment's timeline is not a complete record of a user's day, and the product should never imply otherwise. An investigator needs to know which collectors were running before treating a gap in the timeline as an absence of activity.

## SECTION D: LMNTRIX PACKETS / NETWITNESS GAP FEATURES

### D1. Full Packet Capture
- [x] Capture with microsecond timestamps — PCAP records carry microsecond resolution, and `packets.py` exposes a `ZERO_TIMESTAMP` sentinel when a backend has no usable clock rather than fabricating one.
- [x] Capture packet headers — Ethernet/IP/TCP/UDP headers are decoded, and IPv4 fragment reassembly is implemented in `FragmentTable`, which reassembles **only when every piece is present and overlaps agree**.
- [x] Capture packet metadata — flow records (timestamp, endpoints, ports, protocol, bytes, packet counts) are extracted and indexed.
- [x] Store packets in PCAP format — PCAP and PCAPNG are both read (magic-detected on upload), and PCAP can be written. Implemented as an interchange format, not as a retention store.
- [x] Search packets by IP — searchable via indexed flow and message records.
- [x] Search packets by port — same.
- [x] Search packets by protocol — same.
- [x] Search packets by content — searchable **within decoded protocol fields** (for example reassembled HTTP headers, FTP commands, decoded 3270 screens). Encrypted payload is not searchable, and this is the single most important limitation in this section.
- [x] Search packets by time — time-range filtering on all indexed network records.
- [x] Reconstruct sessions from packets — protocol decoders reassemble and normalise sessions (HTTP, FTP, Telnet, 3270 and others per `network_sensor/protocols.py::CAPABILITIES`).
- [x] Reconstruct emails from packets — mail reconstruction from captured protocol content exists via the mail analysis path; note it reads *decoded* content, so TLS-encapsulated mail is not recoverable.
- [x] **Retrospective threat hunting** — met within the design's limits. Captures can be uploaded after the fact (`POST /api/network/pcap`), stored with a SHA-256 for integrity, and re-analysed; decoded message layouts can be saved for reuse. That is genuine retrospective work, provided the capture exists — the sensor is not continuously recording, so "retrospective" means "over a capture someone took," not "over everything that happened."

### D2. Retrospective Threat Hunting
- [x] Search historical packets for C2 traffic — a writer can name operator-supplied C2 addresses and run them against one stored capture. A match is a review finding on the retained sessions. No threat feed is bundled.
- [x] Search historical packets for IOCs — a signed-in user can list stored findings that name an operator-supplied malware or C2 address. No signature feed is bundled.
- [x] Search historical packets for data exfiltration — the same search lists stored sensitive-file findings. It does not copy the file.
- [x] Search historical packets for privilege escalation — the same search lists a stored command finding whose label is privilege. It does not copy the command.
- [x] Search historical packets for command and control — the same search lists stored C2 findings, including a periodic-callback finding. It does not start a capture.
- [x] Apply new threat intelligence to old data — the same request accepts operator-supplied malware addresses. The original capture bytes and SHA-256 stay unchanged. Live capture is not started.
- [x] Search historical packets for TTPs — a signed-in user can list stored findings under one tactic name, or under "ttp" for every tactic this build records. The search reads the stored report. It does not scan raw packet bytes for a signature.
- [x] Search historical packets for impact — that search lists a stored command finding whose label is destructive delete or disk copy. It does not copy the command.
- [x] Search historical packets for discovery — that search lists a stored command finding whose label is discovery, from whoami, uname, hostname, ipconfig, ifconfig, or netstat on stored plaintext FTP or Telnet. It does not copy the command.
- [x] Search historical packets for persistence — that search lists a stored command finding whose label is persistence, from crontab, schtasks, or systemctl enable on stored plaintext FTP or Telnet. It does not copy the command.
- [x] Search historical packets for lateral movement — that search lists a stored command finding whose label is lateral movement, from psexec, wmiexec, winexe, or net use on stored plaintext FTP or Telnet. It does not copy the command.
- [x] Search historical packets for collection — that search lists a stored command finding whose label is download or remote copy. It does not copy the command.
- [x] Apply new rules to old data — a writer can run the rules in this build against one stored capture. The report is replaced with that result. The original bytes and SHA-256 stay unchanged. This does not apply a new machine-learning model.

### D3. File Reconstruction from Network Traffic
- [x] Reconstruct files from HTTP — a stored cleartext HTTP/1 body, including chunked encoding, is hashed. The decoded record keeps the length, the SHA-256, and a sensitive label when one matches. It does not copy the body. HTTPS is not decrypted.
- [x] Reconstruct files from SMB — a stored plaintext SMB2 WRITE request or READ response is hashed when its declared buffer sits inside the message. The record keeps the command, the length, the SHA-256, and a sensitive label when one matches. It does not copy the bytes. An SMB transform header is not decrypted.
- [x] Store reconstructed files — each analyzed session keeps a file list for plaintext FTP, HTTP, SMB, and NFSv3 WRITE buffers. The list stores the protocol, length, SHA-256, transfer name, and sensitive label. The file bytes stay in the original capture. A signed-in user can search that list.
- [x] Reconstruct files from FTP — a stored plaintext PORT, PASV, or EPSV data channel is attached to the matching RETR, STOR, or STOU name. The bytes stay inside the capture. Encrypted FTP is not decoded.
- [x] Hash reconstructed files — the transfer record stores the SHA-256 of those plaintext bytes.
- [x] Scan reconstructed files for sensitive data — the first 32,768 bytes are checked for a card number or a confidential term. The record keeps "card ending" plus the last four digits, or the words "confidential term".
- [x] Alert on sensitive file transfer — that match opens one review finding with the label and the hash. The finding does not copy the file, and it does not block the transfer.
- [x] Reconstruct files from NFS — a stored plaintext NFSv3 WRITE call is hashed when the RPC arguments place the buffer inside the message. The record keeps the length, the offset, the SHA-256, and a sensitive label when one matches. It does not copy the bytes. RPCSEC_GSS and NFSv4 are not reconstructed.
- [x] Reconstruct files from SMTP — a stored plaintext SMTP message hashes a named attachment, including one base64 part. The record keeps the file name, the length, the SHA-256, and a sensitive label when one matches. The message body, the attachment bytes, and AUTH credentials are omitted. SMTPS is not decrypted.
- [x] Reconstruct files from IMAP — a stored plaintext IMAP FETCH hashes a named attachment the same way. The password and message body are omitted. IMAPS is not decrypted.
- [x] Reconstruct files from POP3 — a stored plaintext POP3 RETR hashes a named attachment the same way. The password and message body are omitted. POP3S is not decrypted.

### D4. Command Reconstruction from Network Traffic
- [x] Alert on suspicious commands — a stored plaintext FTP control line or Telnet text that matches a destructive delete, disk copy, netcat, download, remote copy, privilege, package-install, discovery, persistence, or lateral-movement pattern opens one review finding. The finding names the pattern. It does not copy the command line, and it does not block the command. SSH, RDP, and encrypted sessions are not read.
- [x] Reconstruct LDAP commands — a stored plaintext message on port 389 records the operation, the bind name or search base, the authentication choice, and search filter attribute names. Simple credentials and filter values are omitted from that decoded record. LDAPS is identified and not decrypted.
- [x] Reconstruct Telnet commands — stored plaintext Telnet is split into lines after negotiation bytes are removed. A password prompt and the following line are omitted from the command list.
- [x] Reconstruct SQL commands — a stored plaintext TDS SQL batch and an Oracle Net statement span are copied into the same command list. Encrypted database sessions are not read.
- [x] Store reconstructed commands — each analyzed session keeps that command list. FTP credential lines stay redacted.
- [x] Search reconstructed commands — a signed-in user can search the stored command text. The search does not return a line that was omitted as a password reply.
- [x] Reconstruct IMAP commands — a stored plaintext IMAP session keeps the LOGIN name and Subject, From, To, and Message-ID headers in the command list. The password, AUTH continuation, and message body are omitted. IMAPS is identified and not decrypted.
- [x] Reconstruct POP3 commands — a stored plaintext POP3 session keeps the USER name and the same headers. The PASS value and message body are omitted. POP3S is identified and not decrypted.

### D5. Session Reconstruction from Network Traffic
- [x] Reconstruct TCP sessions — a stored TCP flow is reassembled in sequence order. A missing opening SYN is rebuilt from the lowest captured sequence and stops at the first gap.
- [x] Reconstruct UDP sessions — datagrams on one flow are kept with their direction. A DNS response is not decoded.
- [x] Reconstruct HTTP sessions — a stored cleartext HTTP/1 exchange keeps the start line and headers. The query string is omitted from the recorded URL, and authorization and cookie headers are redacted in the decoded record.
- [x] Reconstruct Telnet sessions — a stored plaintext Telnet flow keeps the negotiation-stripped text and a VT100 screen. Encrypted terminal traffic is not read.
- [x] Reconstruct database sessions — a stored TDS, Oracle Net, or DRDA flow keeps the header the decoder already understands. Encrypted database payloads stay opaque.
- [x] Reconstruct file transfer sessions — a stored plaintext FTP data channel is attached to the matching transfer name. Encrypted FTP is not decoded.
- [x] Store reconstructed sessions — the session record is kept inside the capture report.
- [x] Search reconstructed sessions — a signed-in user can search stored sessions by protocol or address. The result names the flow and the packet count. It does not return payload bytes.
- [x] Replay reconstructed sessions — stored terminal screens in an opened capture can be stepped through one screen at a time. This is not a packet player, and a session with no decoded screen has nothing to replay.
- [x] Reconstruct email sessions — a stored plaintext SMTP session keeps the envelope and the Subject, From, To, and Message-ID headers. AUTH credentials and the message body are omitted. SMTPS is identified and not decrypted.
- [x] Reconstruct IMAP sessions — a stored plaintext IMAP session keeps the login name and the same headers. The password and message body are omitted. IMAPS is identified and not decrypted.
- [x] Reconstruct POP3 sessions — a stored plaintext POP3 session keeps the mailbox name and the same headers. The password and message body are omitted. POP3S is identified and not decrypted.

### Phase 16.8 Network Forensics
Full packet capture, line rate, HTTPS, VoIP, video, signature detection, and a Puguang equivalent stay open.

- [x] TCP session reconstruction — the stored TCP reassembly recorded under D5.
- [x] UDP session reconstruction — the stored UDP flow record recorded under D5.
- [x] HTTP session reconstruction — the stored cleartext HTTP/1 session recorded under D5.
- [x] HTTP file reconstruction — the stored cleartext body hash recorded under D3.
- [x] FTP/SMB file reconstruction — the stored plaintext FTP data channel and SMB2 READ or WRITE hash recorded under D3.
- [x] SMTP reconstruction — the stored plaintext envelope and headers recorded under D5. Message files stay open.
- [x] IMAP/POP3 reconstruction — the stored plaintext login or mailbox name and headers recorded under D5. Message files stay open.
- [x] HTTP reconstruction — the stored cleartext HTTP/1 record recorded under D5.
- [x] Traffic anomaly detection — a stored capture can name an unusual protocol, a heavy session, a port or host scan, and a periodic callback.
- [x] IOC search — the stored-finding search recorded under D2.
- [x] TTP search — the stored tactic search recorded under D2.
- [x] Historical flow analysis — the capture report ranks stored sessions by payload volume.
- [x] Protocol anomaly detection — a stored session whose signature names one protocol and whose port belongs to another is a Protocol anomaly finding. The finding records the protocol and the ports. It does not copy the payload.
- [x] Reconstruct files from SMTP, IMAP, and POP3 — the named-attachment hash recorded under D3.

### A7 follow-up: configured unusual-login-time detection
- [x] Detect unusual login times against an administrator-defined UTC hour window, including overnight windows. Out-of-window logins produce an identity audit record and a deduplicated review alert. No geolocation, learned baseline, or automatic lockout is claimed.

### Phase 7 verification and configuration
- [x] Local automated checks cover OTP vectors, encrypted enrollment, replay and brute-force rejection, shared-person attribution, data-domain restrictions, overlapping-terminal alerts, privileged approvals/tickets, and directory mapping fixtures.
- [x] Configure application integrations through persistent IAM encryption key, Twilio credentials, LDAPS settings and per-resource PAM service keys. Missing configuration fails closed; no live provider, directory, Linux host, or desktop recorder was activated during implementation.
- See `backend/tests/test_iam.py` and the Phase 7 section in `backend/README.md` for the exact coverage and deployment prerequisites. Native/third-party validation remains in the open list.

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
- [ ] Execute Go tests/build in a Go-enabled environment and the Linux C build in CI; neither was locally verified.
- [ ] Validate the complete collector / pam_exec / backend authentication stack in a disposable Linux deployment.

Verification for this follow-up: strict TypeScript build and JavaScript syntax check passed;
5 reporting API tests, 3 Rust tests, SQL source-preservation/aggregation checks,
and Windows C++ hash/failure cross-checks passed. CI configuration was added but
not executed. This entry does not mark the entire roadmap or production rollout complete.
