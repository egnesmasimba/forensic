# Email and endpoint transfer monitoring

## Included

The agent worker registers three opt-in collectors: `email`, `transfers`, and `browser_downloads`. Classic Outlook reads the running user's MAPI session through pywin32; it never launches Outlook or sends messages. Thunderbird reads explicitly selected mbox, maildir, or EML stores. The Chrome/Edge extension captures supported visible Gmail and Outlook webmail content, Send intent, and completed downloads through a local native messaging host. Completed Chromium downloads can also be read from a configured History database without the extension.

Stable destination writes are observed in configured removable, network-share, cloud and download roots. Configured local source roots permit SHA-256 copy correlation. Initial contents form a baseline unless `capture_existing` is enabled. A changed file must remain stable across two observations before capture. Persistent checkpoints prevent restart replay. Polling can miss short-lived writes or activity between observations; a destination write or Send click is evidence for review, not proof of upload, SMTP acceptance, or remote delivery. Cloud monitoring covers local sync roots for OneDrive, Dropbox, Google Drive and Box, not their provider APIs.

Email analysis records sender, To/Cc/Bcc, normalized recipient domains, message identity, timestamp, direction, body and bounded attachment findings. Administrators configure internal domains and sensitive terms in **Email review**. Policies apply to new captures. Investigators can import an EML file or paste its original RFC message, inspect findings and attachments, and search indexed mail text. Existing alert thresholds govern large attachments/transfers and confirmed encryption; sensitive external content also produces review alerts. Read-only users can review records but cannot import mail or change policy.

## Agent configuration

Copy `example-mail-transfers.json` to your agent config and replace the token, user/profile names and paths. Keep state files outside monitored roots. Set only the desired collectors to `enabled: true`; set `email.outlook: true` for classic Outlook and install pywin32 in the agent Python environment. Run the normal agent worker from the backend directory with `ENDPOINT_AGENT_CONFIG` pointing to this config. Check collector coverage in agent heartbeats. `partial`, `outlook_unavailable`, locked History databases and inaccessible roots require investigation.

Select Thunderbird Sent stores with direction `outgoing`, Inbox stores with `incoming`, and uncertain stores with `unknown`. Thunderbird IMAP caches may contain only downloaded mail. Large mailbox stores above 128 MB are reported partial rather than read; use supported smaller stores/EML exports. The collector checks the latest configured message window and does not guarantee historical completeness. New Outlook does not expose classic Outlook COM; use supported webmail capture or EML import for that environment.

## Chrome / Edge native host

Load the `browser_extension` directory as an unpacked extension in a controlled browser profile, or distribute it through your organization's extension policy. Copy its resulting extension ID into both the native host manifest's `allowed_origins` and the agent's `browser_capture.allowed_origins`, using the exact `chrome-extension://ID/` origin. Set `browser_capture.enabled: true`.

Adapt `native-capture.example.cmd` to the installed Python runtime and config path. Ensure `endpoint_agent` is importable by that runtime (run from backend or install the package). Adapt `native-host.example.json` to the wrapper's absolute path. Register the manifest's absolute path as the default value of the per-user registry key `Software\Google\Chrome\NativeMessagingHosts\com.zanaq.endpoint_capture` for Chrome, or `Software\Microsoft\Edge\NativeMessagingHosts\com.zanaq.endpoint_capture` for Edge. No registry changes or extension installation are performed automatically by this implementation.

Keep the normal agent worker running: it drains the browser native host's persistent offline queue as connectivity returns. The extension retains failed requests and retries on its one-minute alarm. The native host stores accepted requests before attempting delivery. Both producers use a cross-process queue lock; server receipts reject mismatched event keys and prevent duplicate alerts on retries. Offline retention is bounded and oldest entries can be discarded at capacity; monitor queue/storage health. API credentials remain in the local agent config, not the extension.

DOM capture requires current provider selectors to match the visible page. Only attachment files selected during this extension session have readable content; existing remote attachments are not fetched. A Send click records intent, not delivery. Validate multiple compose windows and recipient chip layouts before deployment. Incoming/read-message recipient details may be unavailable in collapsed headers. Unsupported layouts must be treated as incomplete coverage.

## Content limits and interpretation

The scanner does not execute files or provide antivirus verdicts. It scans up to 8 MB per file, 32,768 text characters, 100 archive entries, 500 KB per member and 2 MB expanded archive data. ZIP, gzip and tar text can be inspected without extracting files to disk; supported Office ZIP XML text is included. PDF text is optional through pypdf. RAR/7z signatures are recognized, but their contents and encryption remain unknown without additional decoders. ZIP encryption flags and supported PGP/AGE envelopes produce confirmed indicators; Office OLE stream-name markers and fallback PDF markers are probable indicators. Entropy or an `.enc` suffix alone never confirms encryption. Partial and unknown results are displayed explicitly. Encryption is not decrypted.

Manual imports retain the original bounded EML in the application database; agent captures retain parsed reports rather than raw mailbox files. Bodies and extracted text are sensitive evidence and use the application's existing authenticated access. Link URLs omit query strings, fragments and credentials. Folder roots, recipient metadata and selected file contents should be configured according to the deployment's approved collection scope.

## API and validation

Authenticated endpoints: `GET /api/mail/messages`, `GET /api/mail/messages/{id}`, writer `POST /api/mail/eml` and `POST /api/mail/scan`, administrator `PUT /api/mail/policy`, and authenticated `GET /api/mail/policy`. Agent events use `/api/agents/events` and heartbeats `/api/agents/heartbeat`. Mail is automatically indexed as source `mail`; existing mail can be included in search backfill.

Controlled tests cover MIME/HTML parsing, domains, archive limits, encryption indicators, role restrictions, alerts, indexing, event receipts, batch rollback, timezone normalization, Thunderbird fixtures, Outlook provider deduplication, transfer baselines/copy correlation, Chromium completion and native framing, and outage queue retry. Live COM permissions, webmail layouts, physical removable devices and cloud/share behavior still need target-machine validation.

Primary integration references: [Outlook COM support](https://learn.microsoft.com/en-us/office/dev/add-ins/outlook/one-outlook), [Thunderbird storage](https://support.mozilla.org/en-US/kb/compacting-folders), [Chrome downloads](https://developer.chrome.com/docs/extensions/reference/api/downloads), [Native messaging installation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
