# Investigation Center

From this directory, create the initial administrator interactively:

```powershell
.runtime/Scripts/python.exe -m app.create_admin
```

Choose your own username and a password with at least 12 characters. No default account or password is installed. Existing cases and alerts remain in the database; new account and session tables are created automatically.

Start the local application:

```powershell
.runtime/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 and sign in. Administrators can use **Accounts** to create administrators, investigators, or viewers. Investigators can edit cases, notes, alerts, and attachments. Viewers can read cases and download evidence and reports. All new activity records use the authenticated username; historical records retain their original attribution.

Sessions expire after eight hours and are invalidated when signing out. Passwords are salted and hashed with PBKDF2-SHA256. Browser sessions use HttpOnly, SameSite cookies and a session verification token for changes. The session cookie carries the `Secure` attribute whenever the request arrived over TLS, so it does not need to be switched on by hand; set `ZANAQ_SECURE_COOKIES=1` to force it on when TLS is terminated by a proxy. A signed-in user can change their own password. An administrator can disable an account, keep at least one administrator enabled, and set a replacement password. This version is intended for local development.

The `.runtime` environment was created because the previous `.venv` points to an unavailable Python installation. To recreate it with a working Python installation:

```powershell
python -m venv .runtime
.runtime/Scripts/python.exe -m pip install -r requirements.txt
```

## Transport security (TLS)

An on-premises deployment has no publicly trusted certificate, so the application can generate its own. This writes a private CA, a server certificate for the hosts you name, and the server key material in one file:

```powershell
.runtime/Scripts/python.exe -m app.transport_security generate-cert --host localhost --host 127.0.0.1 --out-dir tls
```

Start the server with the generated material and tell each agent to trust the CA:

```powershell
.runtime/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 `
    --ssl-certfile tls/server.pem --ssl-keyfile tls/server.pem
```

```json
{
  "server_url": "https://forensics.example.com:8000",
  "tls": { "ca_bundle": "C:\\ProgramData\\Zanaq\\tls\\ca.pem" }
}
```

Certificate verification is on by default. The agent refuses plain HTTP to any non-loopback host, refuses to disable verification for a remote host, never embeds credentials in the server URL, and never weakens hostname checking. `allow_insecure_http` exists for loopback development only. For mutual TLS, set `tls.client_cert` and `tls.client_key`; a client key readable by other local users is refused. `python -m app.transport_security show` prints the effective server-side policy.

Responses carry `Strict-Transport-Security` when they arrive over TLS, plus `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options`. Environment settings:

| Variable | Default | Effect |
| --- | --- | --- |
| `ZANAQ_REQUIRE_HTTPS` | `0` | Redirect plain HTTP requests to HTTPS. |
| `ZANAQ_TRUST_PROXY_HEADERS` | `0` | Believe `X-Forwarded-Proto`. Leave off unless a trusted proxy sets it, or a client could claim its own request was secure. |
| `ZANAQ_SECURE_COOKIES` | auto | Force the session cookie's `Secure` attribute on or off. |
| `ZANAQ_HSTS` | `1` | Send HSTS over TLS. |
| `ZANAQ_HSTS_MAX_AGE` | `31536000` | HSTS lifetime in seconds, capped at one year. |

The keys the platform installers wrote into `config.json` (`verify_tls`, `ca_bundle`, `proxy`) were never read by any module, so an agent could look configured while using plain HTTP. They are now honoured, in the nested `tls` section and in their original flat form.


## Import activity and review alerts

Sign in and open **Activity & alerts**. Download the example CSV to see the required format, then upload your own UTF-8 CSV and give it a stable source name. Imports are limited to 2 MB and 5,000 rows. Viewers may review imported events and alerts; only administrators and investigators may import, link, or dismiss alerts.

Required columns are `event_id,occurred_at,user,action,destination,bytes,records`. Each event needs a stable ID within its source and a timestamp with a timezone (for example `2026-10-03T09:00:00+02:00`). `bytes` and `records` must be nonnegative integers; use zero when not applicable. Supported actions are `file_transfer`, `data_export`, `login_success`, `login_failure`, `browser_download`, `cloud_sync`, `archive`, and `encrypt`.

These rules apply to each imported event. Destination matching is case insensitive, and repeated spaces are collapsed.

- A `data_export` of at least 1,000 records creates a bulk-export alert with score 70.
- A `file_transfer` of at least 10,485,760 bytes to `usb`, `removable`, `cloud`, `onedrive`, `dropbox`, `google drive`, `googledrive`, `gdrive`, or `box` creates an external-transfer alert with score 80.
- A `cloud_sync` of at least 10,485,760 bytes to one of those cloud destinations creates a cloud-sync alert with score 80.
- A `browser_download` of at least 10,485,760 bytes creates a browser-download alert with score 75. The destination can be the file name.
- A `file_transfer` of at least 10,485,760 bytes to `share`, `network`, `smb`, or `unc` creates a network-share alert with score 75.
- An `archive` or `encrypt` event of at least 10,485,760 bytes creates an archive alert (score 65) or an encryption alert (score 75).

Other valid events are retained without generating an alert. These rules are review indicators, not proof of misconduct. Review thresholds are editable. Three or more login failures in one activity import raise one alert.

Reuploading identical IDs and data under the same source skips duplicates. Changed data for an existing ID rejects the whole file, as does an invalid row; no events or alerts from that upload are committed. Use a different source name only for a genuinely different source. Imported records preserve the event details, importing username, import time, and generated alert reference.

Email metadata uses `POST /api/imports/email` and the columns `message_id,occurred_at,sender,recipient_domain,attachment_name,attachment_bytes,encrypted`. The file records the sender, recipient domain, attachment name, size, and an encrypted yes/no flag. A public-mail recipient domain (including Gmail, Outlook.com, Yahoo, iCloud, and Proton) creates an external-recipient alert with score 70. An attachment of at least 10,485,760 bytes creates a large-attachment alert with score 75. An encrypted attachment creates an encrypted-attachment alert with score 75. When several match, one alert is stored at the highest score and the description lists every matching rule.

Traffic summaries use `POST /api/imports/traffic` and the columns `flow_id,occurred_at,user,protocol,application,destination,bytes,connections`. A protocol other than tcp, udp, icmp, http, https, dns, or tls creates an unusual-protocol alert with score 60. A flow of at least 104,857,600 bytes creates a bandwidth-heavy alert with score 70 and keeps the application name. A flow with at least 100 connections creates a repeated-connections alert with score 65.

Open alerts can be linked to an existing case from the inbox. If needed, close the dialog and create a case first. Linking records the investigator identity and raises the case score. The API supports multipart uploads at `POST /api/imports/csv` (`source` and `file`) using the existing signed-in session and CSRF header; `GET /api/imports/events` returns the latest 100 imported events. This is a manual CSV connection. The separate endpoint agent is documented below; it is not started by a CSV import.

## Alerts, reports, and compliance records

A writer can save a suppression rule or an entity whitelist. A matching new open alert is stored as suppressed and stays out of the open inbox. An alert already linked to a case stays linked. A saved route assigns a matching new open alert and writes an in-app notice. That notice is not emailed, texted, or sent to a message queue or web service. Related alerts lists each entity that has two or more open or linked alerts. A playbook email or SMS step records the same kind of local notice and does not send it.

Saved report templates store status, query, minimum score, sort, and columns. `GET /api/reports/cases/{id}/fields` returns each custom field label and value on that case.

**Compliance** is administrator-only. An administrator can record an access, portability, erasure, consent, or opt-out request for a stored entity, write an impact note, and record a supervisory review. Access and portability export stored facts, alerts, consents, and disclosures. Erasure redacts fact text and archived copies when no open case holds an alert for that entity. Fact aging uses a 6-to-12-month setting and, when automatic retention is enabled, archives older facts unless an open case holds them. Archive retrieval checks a SHA-256. The privacy audit exports as JSON or CSV with the columns id, actor, action, detail, and created_at. The control inventory lists the local restrictions and the gaps that remain. None of this is a GDPR, HIPAA, PCI, SOC 2, CCPA, or FINRA certification.


## Sign-in protection and audit history

Sign-in attempts are limited to five per normalized username and twenty per client address within a fixed fifteen-minute window. Attempts include successful and failed sign-ins. Once either limit is reached, sign-in returns HTTP 429 with a `Retry-After` header; no new session is issued. Attempts during a blocked window do not extend it. Limits persist across application restarts and use atomic database updates for concurrent requests.

Administrators can open **Accounts** to review the latest fifty authentication records and refresh the list. Records include the username attempted, client address, time, and outcome (`invalid_credentials`, `throttled`, `origin_rejected`, `signed_in`, or `signed_out`). Passwords, cookies, and session tokens are never included. This audit covers authentication; it is not comprehensive logging of every system access. Malformed requests rejected before reaching the login handler are not audited here.

`GET /api/auth/audit` is administrator-only. It accepts `limit` (1–100) and `before_id` for paging backward. Audit retention and scheduled pruning of expired throttle buckets remain pending.

The application uses the address supplied by the web server and does not parse forwarded headers itself. For a direct local deployment, disable proxy headers explicitly:

```powershell
.runtime/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

When deploying behind a reverse proxy, configure the web server to trust only that proxy; otherwise forwarded addresses can bypass address limits. Shared addresses also share the twenty-attempt limit. Account recovery and broader request throttling remain separate work.


## Network sensor

Open **Network captures** to analyze PCAP and timestamped PCAPNG files and inspect reconstructed TCP sessions, protocol messages, terminal screen subsets, and decoder coverage. The separate Windows Npcap sensor supports passive NIC capture, BPF filters, a bounded processing queue, health monitoring, and opt-in SNMPv2c notifications. See [network_sensor/README.md](network_sensor/README.md) for installation, mirror/tap wiring, commands, limits, and per-protocol coverage. Npcap is not installed on the current machine; live capture requires the driver. PF_RING/DPDK adapters require a suitable Linux deployment. Full vendor decoders, encrypted-content decoding, and a live browser screen viewer remain pending.


### Saved network message layouts

In **Network captures**, expand **Import a fixed-width message layout**. Preview a supported COBOL, IBM COBOL, C, MSVC-style C, or VB declaration, then save it with a name, version, protocol, direction, byte offset, encoding, and byte order. A saved layout can frame each record with a 2- or 4-byte length and skip up to 32 envelope bytes. Reopen a matching capture to see decoded records. Saved versions can be enabled or disabled; changing a definition requires a new version. Layout decoding skips incomplete TCP streams, preserves original capture data, and reports malformed records and resource limits. Other compiler padding and inferred envelopes stay rejected; see the sensor guide for the supported subsets and limits.


## Free-text content search

Open **Search content** after signing in. Search terms are combined with AND; use `"wire transfer"` for a phrase, `wire OR payment` for alternatives, or `wire -denied` to exclude a term. Exclusions apply to their OR group. Select a platform/source and optional inclusive From/To times. The interface converts local time to UTC. Results rank title matches ahead of headers, captions, field values and body text. Select a result to inspect its parsed headers, fields and text. Content is rendered as text, never executed as HTML.

Case text, alerts, notes, collector summaries, imported events, endpoint events, and decoded network screens/messages are indexed automatically when saved or changed. OCR documents created by the existing image-reading workflow also appear in this shared index. Original packets, binary attachments and screenshot bytes are not read into this index. Decoded network metadata retains the sensor's existing credential redaction. HTTP bodies and encrypted webpage contents are not decoded by this feature. Use **Index existing records** to backfill supported sources already present before this feature was installed. This processes up to 10,000 records per source; larger imports use the returned API cursor. Backfilling preserves manually added HTML/screen records. It does not repair records changed outside the application's ORM or purge orphaned records introduced by direct database edits.

Investigators and administrators can add supplied HTML or reconstructed screen text with a platform and observed timestamp. The HTML parser reads headings, table headers, labels, accessible captions, text inputs, textareas and selected options. It omits scripts, styles, templates, hidden elements and password/hidden input values. It does not render JavaScript, interpret external CSS or recognize arbitrary vendor-specific screen layouts. Plain screens support explicit `Caption: value` and `Caption = value` pairs. Content is limited to 262,144 characters, 200 headers/fields, 20,000 HTML elements and nesting depth 100. Automatically indexed sources are clipped with a partial-content flag when necessary; oversized manual input is rejected. Each capture indexes at most 500 decoded records plus a visible limit marker. The index reflects the sensor's own truncation and incomplete-stream flags. Collector entries index retained summaries, not an entire original binary file. OCR requires the separate image-reading workflow.

SQLite FTS5 is the default, persistent local engine, with Unicode tokenization and weighted BM25 ranking (title 8, headers 5, captions 4, values 3, body 1). Search permits 20 query terms, 500 query characters, 100 results per page and a maximum offset of 9,900. There is no fuzzy matching, stemming or full Google query syntax. Non-SQLite application databases currently require additional local-index integration.

API:

- `GET /api/search?q=...&platform=...&source_kind=...&start=...&end=...&limit=20&offset=0` returns ranked results and plain snippets. Include timezone offsets in timeframe values.
- `GET /api/search/status` reports indexed/partial counts, platform/source options and pending external updates.
- `POST /api/search/documents` accepts `kind` (`html` or `screen`), `content`, optional `title`, `platform` and timezone-aware `occurred_at`.
- `GET /api/search/documents/{id}` returns parsed content; `DELETE` removes manually supplied content. Automatically managed records must be changed through their source.
- `POST /api/search/backfill?source_kind=case&after=0&limit=100` processes a bounded page, returning `next_after` and `has_more`. Supported source kinds are case, alert, note, artifact, endpoint, import and network. Import cursors are string keys.
- `POST /api/search/sync?limit=100` retries one batch of external updates. Writers require the existing session and CSRF header; read-only accounts can search and inspect content.

### Optional Elasticsearch

Set server environment variables before starting the application:

```powershell
$env:EFMTT_SEARCH_BACKEND = "elasticsearch"
$env:EFMTT_ELASTICSEARCH_URL = "https://your-search-service:9200"
$env:EFMTT_ELASTICSEARCH_INDEX = "zanaq-content-v1"
$env:EFMTT_ELASTICSEARCH_API_KEY = "your-server-api-key"
```

The application creates a dedicated index with explicit text, keyword and date mappings, then publishes batches through the Bulk API. Local source documents and a transactional retry queue remain authoritative. A background worker publishes up to 100 updates every five seconds; manual sync can publish up to 500. Failed items remain pending. Each request has a ten-second timeout. HTTPS certificate verification is enabled; plain HTTP is accepted only for localhost. API keys remain on the server. Use one application worker for external publication; the publication lock is process-local. Multiple processes require a shared delivery coordinator. Use a dedicated index per application database to avoid source-key collisions. The configured service is an authorized destination for indexed content; no service is contacted with default local settings.

During an outage, Elasticsearch search returns 503 and local source records remain intact. Search status displays pending updates and the latest delivery error. External hits are checked against current local documents, suppressing deleted or changed content while updates wait. The external total may therefore exceed the number of visible results on a page. New or edited text becomes searchable after successful publication. Both engines implement the same query grammar; analyzer behavior and exact scores may differ.

The adapter follows the official [Elasticsearch mappings](https://www.elastic.co/docs/manage-data/data-store/mapping/explicit-mapping) and [multi-match query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-multi-match-query) APIs. Adapter tests cover mappings, query/filter requests, retry retention, partial failures, newer revisions and delete delivery through simulated HTTP responses. No Elasticsearch service is running on this workstation; real-cluster validation remains pending. Solr is not included.


Email review and endpoint transfer collectors are documented in [MAIL_TRANSFERS.md](endpoint_agent/MAIL_TRANSFERS.md), with an opt-in [configuration example](endpoint_agent/example-mail-transfers.json).

Agent collector availability and optional dependencies are documented in the [endpoint agent README](endpoint_agent/README.md). Run `python -m endpoint_agent doctor` to see which collectors can collect on a host and which optional library each missing one needs; `--strict` exits non-zero so deployment can be gated on it.

Visual replay and endpoint response setup: [REPLAY_RESPONSE.md](endpoint_agent/REPLAY_RESPONSE.md) and [example-response.json](endpoint_agent/example-response.json).

## Network traffic threat analysis

New PCAP imports include evidence-bearing findings in the capture viewer and `traffic_analysis` in the API and sensor reports. Rules flag conflicting TCP overlaps, at least 10 distinct destinations in payload-free SYN sessions from one source, unknown protocols or signature-identified protocols on nonstandard ports, and sessions with at least 1 MiB observed transport payload. Application rankings use protocol classification and count payload bytes before reconstruction limits, including retransmissions; they do not identify executable processes or measure full wire bandwidth.

Six or more distinct connection start times to the same destination address/port with mean spacing of at least one second and interval coefficient of variation at most 0.1 produce a possible callback/C2 finding. Scheduled legitimate traffic can match. These rules use the retained capture, without a learned historical baseline. The first observed sender supplies the source attribution and can be ambiguous in midstream captures.

The capture import form accepts comma-separated malware and C2 IP indicators. CLI/API configuration accepts `malware_ips`, `c2_ips`, and `heavy_bytes` (default 1048576). IP matches concern either endpoint and require investigation; no external intelligence feed or encrypted-payload inspection is provided. Findings reference session IDs and show their evidence. Reimport older captures to generate analysis. Protocol filters, packet loss, and session retention limits constrain coverage.

## Privacy mode and policy education (Features 76–77)

Open **Privacy** as an administrator to configure the processing purpose, selected legal basis, visual-upload consent, works council agreement reference and expiry, and retention period. Enabling privacy mode switches the main interface to aggregate and pseudonymized endpoint counts. Aggregate groups with fewer than five endpoints are suppressed; event counts are shown in ranges of five. Pseudonymized endpoint counts are a separate view. Stable HMAC pseudonyms use a random per-installation secret held in the settings table and never returned by the settings API. Restrict access to the database and backups: the raw records and pseudonym secret remain sensitive.

Privacy mode enforces a server boundary across existing evidence routes, including search, exports, attachments, network capture downloads, email, and replay. Viewers and investigators use the restricted views; administrators must explicitly enable the audited raw-access switch in the browser (or supply `X-Privacy-Raw: 1` in API requests). Raw-route access is recorded with actor, path and method. Account administration and administrator-only privacy/education controls remain available. API responses are not cached. The default is privacy mode off so existing investigation workflows remain available until an administrator configures this policy.

Restricted screenshot and recording previews cover every pixel and withhold text, fields, HTML and timestamps. This intentionally conservative mask does not depend on OCR finding every piece of PII. Invalid images are withheld. Originals remain available to authorized administrators; this is access-controlled masking, not destructive image anonymization. The image routes are `/api/privacy/screenshots/{event_id}` and `/api/privacy/recordings/{session_id}/frames`.

When privacy mode is enabled, screenshot-command creation, live-start commands, screenshot event uploads and live frame uploads require current approval and consent according to the configured policy. Consent records are append-only, tied to the endpoint and exact processing purpose, and expire. A withdrawal, expired grant, purpose change or expired required council approval blocks visual uploads. Newly requested consent appears visibly on an interactive endpoint. The endpoint token attributes the local decision to that enrolled endpoint; it does not independently authenticate the employee's identity. Existing endpoint capture permissions and local desktop-control consent still apply. This gate controls server command dispatch and upload acceptance; it does not erase images already held in endpoint offline queues or stop unrelated third-party capture tools.

To withdraw or renew consent deliberately on the enrolled endpoint:

```powershell
python -m endpoint_agent.privacy --config agent_config.json --withdraw
python -m endpoint_agent.privacy --config agent_config.json --grant
```

The grant command requires a visible local decision. Automatic prompts do not silently renew declined or expired consent. The authenticated endpoint API can also submit grants/withdrawals at `/api/privacy/agent/consent`; administrators review records and audits in Privacy. Agreement references and expiry are recorded safeguards, not legal validation of an agreement. Organizational review must establish the applicable lawful basis, workforce consultation and country-specific obligations; employee consent is not automatically an adequate basis for monitoring.

Retention provides a preview and an explicit apply action, plus an optional automatic pass in the collection loop. It expires up to 1,000 unlinked endpoint payloads and 1,000 imported/recorded replay frames per pass, based on the configured age. Events linked to cases, alerts, mail evidence or policy warnings are preserved, as are live recordings. Frame text, fields, HTML and image bytes are removed; associated search documents are deleted and external search deletions enter the existing outbox. Endpoint payloads are replaced with a retention marker and the search index refreshes. Metadata, receipt fingerprints, audit/consent records, case evidence, unrelated attachments, backups, external search copies awaiting synchronization, and endpoint offline queues require their own retention arrangements. This is scoped application-content expiry, not complete subject erasure or guaranteed physical deletion from database pages/backups. No retention is applied automatically unless explicitly enabled.

Open **Policy education** to customize warning title, message, educational guidance, HTTPS training link, manager application username, warning-count escalation and reminder interval. New endpoint findings that create alerts queue warnings in the same transaction. Duplicate event receipts do not create duplicate warnings. Deliberate policy reminders can target an enrolled endpoint. The running endpoint agent polls after successful event delivery and on heartbeat (default ten seconds), showing nonblocking visible popup warnings on an interactive desktop. Headless/service sessions can leave notifications undelivered; failed popup display never acknowledges them. Offered delivery, confirmed display, acknowledgment, escalation, manager notification, training assignment and completion each have audit records. This is near-real-time notification after server detection, not synchronous blocking of the original action.

Unacknowledged warnings repeat at the configured interval and escalate; repeated finding warnings also raise the level within a 30-day window. Manager notifications go to that account's authenticated application inbox; no external email/SMS is sent. Training links create local assignments. Endpoint-reported completion is marked `completed`; provider-confirmed completion is separately marked `verified` and cannot be downgraded by an endpoint. For a generic LMS callback, configure a random `ZANAQ_TRAINING_WEBHOOK_TOKEN` of at least 32 characters, then POST `{"reference":"provider-completion-reference"}` to `/api/education/training/{warning_id}/complete` with `Authorization: Bearer <token>`. Configure your provider to map the warning ID to its assignment. No vendor-specific LMS connector is preconfigured.

Pseudonymization and masking do not establish irreversible anonymization or certify GDPR compliance. The privacy controls support an organizational privacy program; assess re-identification risk and required legal/organizational measures before treating an output as anonymous. See the European Commission's GDPR guidance: https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en

## Phase 3 completion: live analytics, catalogs, biometrics, and private aggregates

Open **Live analytics & biometrics** for enrollment controls, pseudonymized comparison status, and privacy-protected aggregate generation. Existing Analytics and Profiles panels expose the expanded indicator and rule definitions.

### Catalog provenance and coverage

This implementation includes **170 behavioral measures** (the ten original measures plus 160 daily/weekly occurrence measures) and **328 prebuilt library rules** (eight original examples plus 320 new rules). The added catalog covers 80 named signals in identity, access, data, network, system, financial, communication and policy categories. Each signal has two measurement periods and four rule variants: acute occurrence count over one rolling day, weekly count, monthly count, and distinct targets over a week. This explicitly counts measures and window/target variants; it does not claim 150 or 320 independent underlying behaviors. The definitions, units, evidence requirements, thresholds, origin and version are returned by `GET /api/analytics/catalog` and live in `app/indicator_catalog.py`.

No published vendor catalog was supplied. The added definitions are labeled first-party (`framework: local`), with operational defaults that need organizational calibration. The eight retained framework-labeled examples are illustrative mappings, not an official framework-endorsed indicator catalog. Additional signal types require corresponding facts from a producer: adding a definition does not manufacture a sensor for it. An unobserved measure says **no observations**, rather than implying a measured zero or that no threat exists. Existing custom definitions and customized library thresholds are preserved by catalog updates. Library evaluation honors each rule's rolling window and suppresses repeat findings by rule, subject and evaluation period.

### Live stream evaluation

`POST /api/analytics/stream` accepts an authenticated investigator/administrator's bounded batch of at most 200 observations. Each observation has `event_id`, `entity_type`, `entity_ref`, `name`, `numeric_value`, `text_value` and a timezone-aware `occurred_at`. The stable stream name and event ID identify retries. An identical retry adds no facts or alerts; a changed payload under the same ID rejects the transaction. Finite numeric values are required. Analytic rules, behavioral baselines and the insider-threat library evaluate after each accepted batch. Existing analytic rules retain their one-finding-per-rule-version-and-entity semantics; the library has its own day/week/month suppression periods.

Authenticated endpoints may submit `analytic_fact` observations through the existing event pipeline. Known catalog signal event types also map to count facts. Endpoint batches evaluate once after their new observations have been stored, while the existing receipt mechanism prevents duplicate capture delivery. Explicit `analytic_fact` subject attribution is supplied by the trusted producer; it is not independent proof of the employee's identity.

The live network sensor can publish reconstructed session deltas and supported threat findings through the same endpoint channel. Configure `analytics_server_url`, `analytics_subject`, optional `analytics_ca_bundle`, and `analytics_agent_token_env` (default `ZANAQ_ANALYTICS_AGENT_TOKEN`) in its JSON configuration. Set the environment variable to an enrolled endpoint token; tokens are never embedded in reports. The sensor sends transport payload-byte and packet deltas and mapped evidence at its five-second report interval, with a bounded offline queue in the capture output folder. Packet capture continues when analytics delivery fails. This integration does not decrypt encrypted payloads, and capture still requires the appropriate driver/permissions. Local threshold rules can use `network_packets`, `network_payload_bytes`, and the documented signal facts.

### Behavioral biometrics

Biometrics collect only aggregate key-hold, inter-press interval, release-to-next-press timing (including overlapping negative flight times), relative mouse speed and turning-angle summaries. Typed characters, key sequences and absolute mouse positions never enter serialized observations. Key objects and positions exist briefly in bounded volatile callback state to calculate timing/movement, and are cleared on each snapshot. The new collector is sensitive and **off by default**. Its optional dependency is `pynput`; an interactive desktop and operating-system input permissions are required. The implementation follows the [keyboard](https://pynput.readthedocs.io/en/latest/keyboard.html) and [mouse](https://pynput.readthedocs.io/en/latest/mouse.html) listener interfaces. No dependency was installed by this change.

To configure capture deliberately:

1. An administrator binds an enrolled endpoint ID to a subject in the new panel.
2. The endpoint user grants consent through a visible dialog:

   ```powershell
   python -m endpoint_agent.biometrics --config agent_config.json --grant
   ```

3. Enable `collectors.biometrics.enabled` in the endpoint configuration and restart that worker. Collection requires both local enablement and the authenticated server heartbeat's short consent lease. A withdrawal, disabled/rebound endpoint, expired consent, expired required works council approval, or lost server heartbeat stops local collection once the lease expires (at most 30 seconds). Server uploads reject invalid consent immediately. Withdraw through the same command with `--withdraw`. Consent lasts 30 days and is not silently renewed.
4. An administrator reviews at least five samples with sufficient comparable input activity, independently verifies their subject identity, selects their IDs and explicitly enrolls a baseline. Suspicious or retention-expired samples cannot become enrollment evidence. Rebinding an endpoint invalidates its previous consent.

New samples are compared with frozen baseline means and variation, with minimum tolerance floors to avoid division by near-zero variance. At least three comparable metrics are required; sparse samples show insufficient data. The score reports behavioral consistency, not a standalone authentication result. Two consecutive suspicious samples from one endpoint within a server-receipt window can raise **Possible account takeover**. A divergent sample while a second endpoint recently matches the same subject can raise **Possible credential sharing**. These are review indicators: device, task, network, accessibility or health changes can explain deviations. No validated population-level error rate or identity assurance is claimed, and an endpoint can forge its own observations. Trusted enrollment and independent evidence remain necessary. The baseline never adapts automatically to suspicious samples.

Biometric consent, bindings and enrollment enter the privacy audit. Existing privacy mode blocks raw biometric routes; its pseudonymized summary remains available. Retention also expires unlinked biometric summaries and old enrollment profiles, preserving samples linked to case/alert evidence. A retained profile expires after the configured age unless independently reenrolled, and then comparisons return to unenrolled. Offline queues and backups require separate retention arrangements.

### Privacy-protected synthetic aggregates

`POST /api/profiles/synthetic-aggregate` accepts at least five distinct registered subject references and exports five clipped, noisy 30-day occurrence means. It publishes no individual identifier/token, user-defined label, exact average or exact observation timestamp. The cohort is a fixed registered domain: subjects with no matching activity contribute zero, so report eligibility does not depend on whether their sensitive activity occurred.

Each subject's contribution to each of the five counts is clipped to 20. Independent Laplace noise uses epsilon 1 and scale `5 * 20 / cohort_size`; outputs are clamped and rounded as postprocessing. This mechanism protects add/remove activity for one subject **conditional on fixed/public cohort membership and trusted registered-domain selection**. It does not protect the cohort-membership validation endpoint itself. A single global cohort release is permitted per UTC day; repeat requests for that cohort receive the identical cached result, and a different cohort is rejected after the daily budget is used. Concurrent requests reserve the same persisted daily row. Releases across days compose, and the software does not implement a lifetime privacy accountant. The deliberately strong noise can reduce utility, especially for small cohorts.

Existing per-subject SyntheticProfile exports remain pseudonymized personal data; they have not become legally anonymous. The new aggregate mechanism, access boundaries, consent, audits and retention support privacy review, but no software export is a legal compliance certification. Decide the lawful basis, biometric safeguards, public-domain membership assumptions and permitted disclosure budget with the organization's responsible reviewers.

## Reporting function: input filters, drilldown and external tools

Open **Report builder** beside the existing CSV/Excel exports. Select built-in case fields or named custom fields, add up to 20 input conditions, and choose **All conditions** or **Any condition**. Text supports equality and literal substring matching (percent/underscore are not wildcards); scores and IDs support integer comparisons; dates require an ISO timestamp with a timezone. Custom fields are scoped to their case type and filter only recorded values. Absent/inapplicable custom fields appear as null. Select up to 30 columns, run the report, and click any value to inspect its current source table, record ID, and custom-field definition. Drilldown shows current provenance, not a historical change log.

Administrators and investigators can save and delete named definitions. Viewers can run reports and read existing definitions. Definitions are separate from the older basic saved reports; they preserve output columns, match mode, and field filters together. Deleting a referenced custom field makes the definition invalid until a replacement is saved.

External integrations use the same authenticated data:

- `GET /api/reports/input-fields`: available fields and supported operators.
- `POST /api/reports/query?after_id=0&limit=100`: preview a definition with `columns`, `filters` and `match`.
- `GET /api/reports/definitions/{id}/data?after_id=0&limit=500`: JSON schema version 1, column metadata, case IDs, values and `next_after_id`.
- Add `format=csv` for a CSV page. Continue with the `X-Next-After-ID` response header until absent. The UI download is explicitly the first page.
- `GET /api/reports/cases/{id}/drilldown?field=score`: source-level detail. Custom keys use `field:{definition_id}`.

The JSON feed supports BI/ETL consumers; the included command downloads all pages into NDJSON for tools that accept line-delimited JSON:

```powershell
# Supply a current zanaq_session cookie through REPORT_SESSION in your environment.
.runtime/Scripts/python.exe report_export.py --server https://investigations.example --definition 1 --output report.ndjson
```

The connector verifies TLS, refuses remote plaintext HTTP, never follows redirects, and preserves existing output files. Failure leaves a `.partial` file; successful export publishes the requested filename. It does not configure or send data to any third-party account. Session expiry, disabled accounts, and privacy restrictions apply on every request. POST operations also require the login response's CSRF token. Privacy mode blocks raw reporting unless an administrator explicitly requests audited raw access; the command does not request that override. CSV and Excel exports neutralize formula-like text, while JSON retains exact stored strings.

Pagination orders by increasing case ID and returns at most 500 cases per page. Results are live reads, not a frozen database snapshot: concurrent edits/deletions may change later pages. No scheduling or vendor-specific connector credentials are configured by this feature.

## Phase 7 identity and access management

Open **Identity & access** after signing in. Existing password sessions remain supported until a factor is enrolled or required by policy. Enrolling TOTP, OATH HOTP, or SMS requires the current password (and the current factor when replacing one), then a code confirming the new factor. Enrollment revokes other sessions. Shared logins require the shared password plus an authorized individual member's password and factor; all work is attributed to that individual, with the shared-account ID retained. Membership revocation is checked on subsequent requests. Shared accounts cannot be administrators or identify another shared account.

Set `ZANAQ_IAM_KEY` to a persistent Fernet key before enrollment. Generate it once with `cryptography.fernet.Fernet.generate_key()`, supply it through your deployment secret mechanism, and retain a protected backup. Factor secrets and SMS destinations are encrypted under it. Losing/changing the key without migrating stored secrets prevents verification. TOTP uses 30-second SHA-1 windows with one-step clock tolerance and atomic replay rejection. HOTP accepts the next ten counters and requires a provisionable Base32 secret; FIDO2/WebAuthn, smart cards and USB transport are not implemented. Codes and verification attempts use persistent per-account/address limits. A different administrator can reset a factor, with audit and session revocation; mandatory MFA must first be temporarily removed for a supervised recovery.

SMS uses Twilio's HTTPS Messages API. Configure `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM`. No message is sent until a user requests enrollment or an SMS code. Codes expire after five minutes and are stored as keyed digests; login, enrollment and privileged-activation challenges have distinct purposes. No provider configured means no successful SMS enrollment. Provider delivery is not verified on this workstation. Do not treat a provider API acceptance as proof the handset received a message.

Administrators can set module allowlists per account, change local roles, require an enrolled factor, define shared members, revoke sessions and set permitted UTC login hours. Restricted accounts receive 403 from APIs outside their allowed data areas, including export paths. The UI hides unavailable areas. Shared sessions use the intersection of individual and shared-account scopes. This is module/data-domain isolation, not per-case or multi-tenant row isolation. Directory roles remain controlled by their group mapping. Off-hours login and overlapping sessions with differing IP/browser metadata generate review alerts. Browser metadata is not hardware attestation, addresses are not geolocation, and the alerts do not establish who used credentials.

Privileged access requests name an exact resource and reason. A different administrator approves for 1–240 minutes. Activation requires password plus an unused factor and binds approval to that application session; no application role or OS privilege is silently elevated. Application requests during administrator, shared, or activated privileged sessions record identity, path, method and status without request bodies, OTPs or query strings. For a resource named `agent:<endpoint ID>`, an administrator can request a desktop recording through the existing endpoint response workflow. Current endpoint consent is mandatory for privileged recording even when privacy mode is off. Configured council requirements also apply; the endpoint must allow and confirm recording. A recording segment is limited to 10 minutes and the remaining approval lifetime. Revocation rejects subsequent frames and queues stop; offline endpoints may take until their local expiry to stop capture. Grant/session expiry and account disable also reject frame ingestion. This does not establish an automatic SSH/RDP gateway or continuous four-hour video archive.

### Active Directory

Configure `ZANAQ_AD_HOST` (DNS hostname), `ZANAQ_AD_BASE_DN`, `ZANAQ_AD_BIND_DN`, `ZANAQ_AD_BIND_PASSWORD`, optional `ZANAQ_AD_CA`, and `ZANAQ_AD_GROUP_MAP`. The mapping is JSON from exact group DN to `{"role":"viewer","modules":["network"]}` (administrator mappings require `["*"]`). The admin sync uses LDAPS on port 636 with certificate verification and referrals disabled. It fetches a bounded, complete search (maximum 5,000 entries) before changing local accounts. Direct `memberOf` memberships determine the highest mapped role and union of permitted modules. Unmapped, AD-disabled, and removed managed users are disabled; local username/DN conflicts abort the transaction. Sync revokes managed sessions. A synced user authenticates by binding the stored DN over LDAPS; local password replacement does not change the AD password. Nested/primary group expansion, Kerberos/SSO, automatic scheduled sync, and a live domain-controller deployment are not included. Keep an independent local administrator for recovery.

### Linux PAM bridge

`pam_bridge.py` integrates through the standard `pam_exec.so` module. A logged-in individual activates an approved resource and generates a 60-second, single-use ticket using `POST /api/iam/pam/ticket?resource=linux:ssh`. The root-owned helper reads that ticket from PAM's authentication input, sends it to `/api/iam/pam/redeem`, and succeeds only if the individual, exact resource, unexpired session, current policy and active grant still match. Configure `ZANAQ_PAM_KEYS` as a JSON map of resource to a random service key of at least 32 characters. Use the same resource/key in a root-owned 0600 JSON file on the Linux host:

```json
{"server":"https://investigations.example","resource":"linux:ssh","service_key":"REPLACE_WITH_A_RANDOM_SERVICE_KEY"}
```

Deploy the helper, its parent directories, and a Python interpreter with httpx under root ownership. A PAM service can invoke `/path/to/python -I /path/to/pam_bridge.py --config /etc/zanaq-pam.json` through `pam_exec.so expose_authtok`, as a required authentication check; keep the host's account/session modules. Test with a separate recovery session before changing host authentication. The helper accepts HTTPS only, verifies certificates, ignores proxy environment settings, rejects redirects, and returns failure on errors. No PAM configuration is installed or modified by this application. This is a pam_exec adapter, not a new native PAM shared library. `native/pam_ticket.c` is a C client for the same one-time ticket redeem. It does not read the account password, and it does not install a PAM module. Approval expiry prevents new authentication; it does not forcibly terminate an already-open host session. Native PAM execution remains unverified on Windows.

Source contracts: [TOTP RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [ldap3 TLS verification](https://ldap3.readthedocs.io/en/latest/ssltls.html), [Twilio Messages API](https://www.twilio.com/docs/messaging/api/message-resource), and [Linux pam_exec](https://www.man7.org/linux/man-pages/man8/pam_exec.8.html).

### Linux PAM private certificate authorities

The root-controlled pam_bridge.py configuration may include `ca_bundle`, an
absolute path to a trusted PEM CA bundle, for an enterprise HTTPS backend.
Protect this file against unauthorized changes. Without ca_bundle, normal
system certificate trust applies. TLS and hostname verification stay enabled.

The full Linux authentication test is opt-in and uses a private temporary PAM
service rather than changing /etc/pam.d. In a disposable root Linux environment:

```bash
FORENSIC_LINUX_PAM_TEST=1 python -m pytest backend/tests/test_pam_linux_live.py -q --basetemp=/tmp/forensic-live-pam-tests
```

Ubuntu 24.04 verification on 5 October 2026 passed the live test and 22 IAM/ticket
regressions. Production PAM configuration still requires deployment-specific
account mapping, service credentials, trusted certificates and access policy.
