# Endpoint Agent

Cross-platform endpoint agent shipped as a standalone [zipapp][zipapp] (`.pyz`) bundle.
Runs as a native service (Windows Service / systemd / LaunchDaemon), heartbeats back to
the server, forwards collector events, and self-updates by pulling a signed manifest.

```
backend/endpoint_agent/
├── __init__.py
├── __main__.py           # CLI entry: run / install / update / uninstall
├── config.py             # JSON config loader with hash integrity
├── protocol.py           # AgentClient (heartbeat, events, offline queue)
├── update.py             # StagedUpdater: check → download → extract → atomic swap
├── watchdog.py           # SubprocessWatchdog: restarts stalled/crashed worker
├── collectors/           # Per-module data collectors (plugin-style)
├── install/              # OS-native service installers
│   ├── windows/install.ps1
│   ├── linux/install.sh
│   └── macos/install_mac.sh
├── packages/             # Built .pyz bundles + manifest.json
│   └── .gitkeep
└── tools/
    └── build_manifest.py # Scan packages/*.pyz → manifest.json
```

[zipapp]: https://docs.python.org/3/library/zipapp.html

---

## 1. Build the `.pyz` bundle (zipapp)

The agent is a normal Python package with a `__main__.py` so it can be executed
directly by the interpreter once wrapped into a zip. Dependencies that are not
part of the standard library must either be vendored inside the `.pyz` or
provided by an embedded runtime shipped alongside it.

### Prerequisites
- Python 3.9+ (with the `zipapp` module in stdlib)
- Dependencies installed into a staging directory so they can be bundled

### Quick build
Run from the `backend/` directory (one level *above* `endpoint_agent/`):

```bash
# 1) Prepare a clean staging area
STAGE=$(mktemp -d)
cp -r endpoint_agent "$STAGE/endpoint_agent"

# 2) Optional: install runtime deps (example — httpx is used by StagedUpdater)
python -m pip install --target "$STAGE" "httpx>=0.27,<1"

# 3) Create the zipapp. zipapp will write a shebang line if --python is passed.
python -m zipapp \
    --compress \
    --python "/usr/bin/env python3" \
    --output "endpoint_agent/packages/system-update-linux-x86_64.pyz" \
    "$STAGE"
```

Repeat the last step per platform, changing the output filename so
`build_manifest.py` can infer `os` and `arch`:

| Target            | Filename convention                          |
| ----------------- | -------------------------------------------- |
| Windows x86_64    | `system-update-windows-x86_64-<version>.pyz` |
| Linux x86_64      | `system-update-linux-x86_64-<version>.pyz`   |
| Linux arm64       | `system-update-linux-arm64-<version>.pyz`    |
| macOS Universal 2 | `system-update-macos-universal2-<version>.pyz`|
| macOS arm64       | `system-update-macos-arm64-<version>.pyz`    |

The version suffix is optional but recommended: `build_manifest.py` parses the
filename and falls back to the `--version` CLI flag for anything not present.

### Running the built pyz directly

```bash
# On the target host, once installed:
/opt/system-update/system-update.pyz --config /etc/system-update/config.json run --watchdog
# Or via the wrapper:
/opt/system-update/system-update run
```

---

## 2. Per-platform install

Each installer:
1. Copies the `.pyz` (and optional embedded Python runtime) to a standard location.
2. Drops a wrapper shell/batch script that resolves the interpreter.
3. Writes a default `config.json` with a unique `machine_id`.
4. Registers a native service (auto-start, restart on failure, runs with
   high privileges).
5. Starts the service immediately.

### Windows (PowerShell, elevated)

Service name: `SystemUpdateSvc` (display: `System Update Service`), registered
via `sc.exe`. Failure recovery restarts the service at 5s / 10s / 30s
intervals then every 24 h. Runs as `LocalSystem`.

```powershell
# Elevated PowerShell
cd endpoint_agent\install\windows
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Installed layout:
- `%ProgramFiles%\SystemUpdate\` — `.pyz`, wrapper, optional embedded Python
- `%ProgramData%\SystemUpdate\config.json` — configuration (protected ACL)
- `%ProgramData%\SystemUpdate\Logs\` — rotating log files

Admin commands:
```powershell
sc.exe   query   SystemUpdateSvc
net.exe  start   SystemUpdateSvc
net.exe  stop    SystemUpdateSvc
sc.exe   delete  SystemUpdateSvc   # uninstall service registration
```

### Linux (systemd, sudo/root)

Unit file installed to `/etc/systemd/system/system-update.service`.
`Restart=on-failure` with `RestartSec=5s`, enabled for `multi-user.target`.
Hardened with `ProtectSystem=strict`, `PrivateTmp`, `ProtectHome=true` and a
scoped `ReadWritePaths` whitelist. Runs as `root`.

```bash
cd endpoint_agent/install/linux
chmod +x install.sh
sudo ./install.sh
```

Installed layout:
- `/opt/system-update/` — `.pyz`, wrapper, optional Python runtime
- `/etc/system-update/config.json` — configuration (mode `0600`)
- `/var/lib/system-update/` — state, offline queue
- `/var/log/system-update/` — log files
- `/etc/default/system-update` — env overrides (proxy, etc.)

Admin commands:
```bash
sudo systemctl status   system-update.service
sudo systemctl start    system-update.service
sudo systemctl stop     system-update.service
sudo systemctl restart  system-update.service
sudo systemctl enable   system-update.service
sudo journalctl -u      system-update.service -f
```

### macOS (LaunchDaemon, sudo/root)

Plist installed to `/Library/LaunchDaemons/com.system.update.plist`, label
`com.system.update`. `KeepAlive` restarts the process on any non-zero exit or
network state change. `RunAtLoad=true`, runs as `root:wheel`.

```bash
cd endpoint_agent/install/macos
chmod +x install_mac.sh
sudo ./install_mac.sh
```

Installed layout:
- `/Library/Application Support/SystemUpdate/` — `.pyz`, wrapper, optional runtime
- `/Library/Preferences/SystemUpdate/config.json` — configuration
- `/Library/Logs/SystemUpdate/` — stdout/stderr + rotating agent logs

Admin commands:
```bash
sudo launchctl print   system/com.system.update
sudo launchctl start   system/com.system.update
sudo launchctl stop    system/com.system.update
sudo launchctl kickstart -k system/com.system.update   # force restart
```

---

## 3. Configuration keys reference

Config is a single JSON file. Dotted paths (e.g. `logging.level`) work with
`Config.get()` / `Config.set()` in `config.py:60` / `config.py:70`.

| Key                                   | Default                     | Description                                                                   |
| ------------------------------------- | --------------------------- | ----------------------------------------------------------------------------- |
| `server_url`                          | `http://localhost:8000`     | Server base URL used for heartbeats, events, and (if `update_url` empty) the manifest. |
| `update_url`                          | `""`                        | Override server URL used *only* for update manifest lookups.                  |
| `agent_token`                         | `""`                        | `X-Agent-Token` header attached to all outbound HTTP calls.                   |
| `current_version`                     | `"0.1.0"`                   | Current agent version, compared against the manifest for upgrades.            |
| `poll_interval_seconds`               | `30`                        | How often the worker flushes the offline queue.                               |
| `heartbeat_interval_seconds`          | `10`                        | Heartbeat cadence to the server.                                              |
| `stall_timeout_seconds`               | `120`                       | Watchdog: restart the worker if no heartbeat within N seconds.                |
| `max_restarts_per_hour`               | `6`                         | Watchdog: rate-limit worker restarts.                                         |
| `offline_queue_path`                  | `"offline_queue.jsonl"`     | Path to the JSONL offline event queue (relative to CWD or absolute).          |
| `offline_queue_max_mb`                | `100`                       | Cap the queue file size; oldest events dropped first when full.               |
| `update_poll_hours`                   | `24`                        | Suggested update-check interval (enforced by caller, not the main loop).      |
| `logging.level`                       | `"INFO"`                    | Python logging level: `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL`.    |
| `logging.file`                        | `"agent.log"`               | Rotating log file path. `null` disables file logging.                         |
| `logging.max_bytes`                   | `5242880`                   | Rotate when the log file reaches this size.                                   |
| `logging.backup_count`                | `3`                         | Number of rotated backups to keep.                                            |
| `collectors.*`                        | `{}`                        | Per-collector configuration keyed by collector name.                           |
| `collectors.<name>.enabled`            | `true` (`false` if sensitive) | Explicitly enable/disable one collector. Sensitive collectors default off.  |
| `state_dir` (installer-only)          | per-platform path           | Where runtime state (staging dir, backups, manifest) is kept.                 |
| `tls.verify_tls`                      | `true`                      | Verify the server certificate. Refused for a non-loopback host.               |
| `tls.ca_bundle`                       | `null`                      | PEM trust anchor for the server certificate.                                   |
| `tls.client_cert` / `tls.client_key`  | `null`                      | Client certificate for mutual TLS. The key must not be readable by others.     |
| `tls.proxy`                           | `null`                      | HTTPS proxy URL; otherwise the `HTTPS_PROXY` environment variable is honoured.|
| `tls.allow_insecure_http`             | `false`                     | Permit plain HTTP. Intended for loopback development only.                    |
| `self_monitor_exclude` (installer)    | varies per OS               | Process/service names the watchdog/monitor must NOT flag as suspicious.       |
| `machine_id` (installer-only)         | generated on install        | Unique host identifier (machine-id, IOKit UUID, or GUID).                     |
| `tenant_id` (installer-only)          | `"default"`                 | Tenant grouping for multi-tenant servers.                                     |
| `log_file` (installer-only)           | per-platform log path       | Overrides `logging.file` when set by installers.                              |
| `check_interval_sec` (installer-only) | `3600`                      | Suggested update-check interval (seconds).                                    |

### Collector availability and optional dependencies

Collectors rely on third-party libraries (`psutil`, `pywin32`, `Pillow`, `mss`,
`pyperclip`, `watchdog`, `pyudev`, `pyobjc`). A collector whose dependency is
missing collects **nothing at all**, which is indistinguishable from a host where
nothing happened. That gap is therefore reported rather than only logged:

- Every collector declares its imports via `requires` / `effective_requires()`.
- `Collector.status()` reports `available`, `requires`, `missing_dependencies`,
  `install_command`, and a human-readable `unavailable_reason`.
- `CollectorManager.status()` aggregates `inert`, `missing_dependencies`, and
  `init_errors` (collectors that failed to construct), all of which ride along in
  the worker heartbeat.
- `dependencies.py` is the authoritative import-name → distribution mapping.

Check a host before trusting it, and gate deployment on it:

```bash
python -m endpoint_agent doctor            # human-readable report
python -m endpoint_agent doctor --json     # machine-readable
python -m endpoint_agent doctor --strict   # exit 1 if any collector is inert
```

Install the optional set with `pip install -r requirements-collectors.txt`, then
re-run `doctor` to confirm.

Two details worth knowing:

- **All 20 collectors are registered** (via `collectors/catalog.py`). They are
  no longer a hardcoded subset, so an implemented collector can never silently
  fail to appear in the inventory.
- **Capture collectors are opt-in.** `clipboard`, `screenshot`, `window`, `idle`,
  `usb`, and `incognito` are marked `sensitive` and start disabled, because they
  collect window titles, clipboard contents, screen images or user activity.
  Enable one explicitly by name:

```json
{
  "collectors": {
    "screenshot": {"enabled": true, "interval_seconds": 300},
    "clipboard":  {"enabled": true}
  }
}
```

A collector can also be restricted to specific platforms via the `platforms`
class attribute, which keeps "wrong operating system" distinguishable from
"missing module" in the reported reason.

### Print monitoring and policy-scoped capture

The `print` collector records spooler metadata from the Windows print spooler
(`win32print`) and from CUPS: printer name and location, user, document title,
status, page count, byte size, and — where the platform reports it — copy count,
colour versus black-and-white, and duplex mode. Fields a platform cannot supply
are reported as `null` rather than omitted, so "not reported" is distinguishable
from "absent".

> The DEVMODE-derived fields (`copies`, `color`, `duplex`) require pywin32 and a
> live spooler and have **not** been validated on a real print host. Treat them
> as unverified until confirmed with `doctor` and a test print on target
> hardware.

**Capturing printed content.** Archiving a copy of every document any user
prints is not implemented, and should not be: it sweeps up medical, financial,
and privileged legal material indefinitely and without the user's knowledge.
What *is* implemented is policy-scoped capture — a bounded, hashed copy of the
source document, retained only when a configured term matches:

```json
{
  "collectors": {
    "print": {
      "enabled": true,
      "content_policy": {
        "enabled": true,
        "sensitive_terms": ["payroll", "medical record"],
        "source_roots": ["C:/Users/alice/Documents"],
        "max_capture_bytes": 26214400,
        "max_per_pass": 5
      }
    }
  }
}
```

Behaviour worth knowing before enabling it:

- **Nothing is captured unless a term matches.** With no `sensitive_terms`
  configured the collector stays metadata-only.
- **Source lookup is bounded to `source_roots`.** The spooler usually reports
  only a document *title*, so resolution is a best-effort stem match inside the
  configured roots, bounded to 2,000 files. Documents outside those roots are
  never read, and symlinks that escape a root are refused.
- **Every decision is reported**, including skips, via `print_document` events
  with `decision: "capture" | "skip"` and a reason. A missing capture is
  therefore explainable rather than indistinguishable from a missed print. Only
  `capture` raises a server-side alert.
- Captured copies are hashed and bounded at 25 MB; retention is left to the
  server's existing `privacy.retention()` job.

Spool-stream interception is deliberately **not** implemented: it needs a native
Windows port-monitor DLL registered with the spooler, and the intercepted bytes
are usually a proprietary driver stream rather than a viewable document.

### Transport security

`verify_tls`, `ca_bundle`, and `proxy` were originally written into `config.json` by the
platform installers but read by no module, so an agent could appear configured while using
plain HTTP. They are now enforced by `endpoint_agent/tls.py`, which every client in the
process shares: the sync client, the async client, the browser-capture bridge, and the
staged updater.

The policy is deliberately strict. Plain HTTP to a non-loopback host is refused before any
connection is attempted, as is a server URL with credentials in it. Disabling certificate
verification is only permitted for loopback, so a development override cannot be deployed by
accident. No setting relaxes hostname checking: the certificate must match the host in
`server_url`. The effective posture is logged at startup, and the keys are still accepted in
their original flat form so an existing configuration keeps working.

File is optionally wrapped in an envelope with `{ "config": {...}, "hash": "sha256" }`
(`config.py:98`) so a changed configuration is detected at load time. This checks the
configuration file. It does not hide the agent or resist uninstall.

The `ENDPOINT_AGENT_CONFIG` environment variable overrides the path resolved by
`Config.__init__` (`config.py:43`).

---

## 4. Update flow (`update.py` + packages/manifest.json)

The agent ships its own updater. A server publishes `manifest.json`, the agent
periodically (or on trigger) calls `endpoint_agent update`, and the new bundle
is swapped in atomically.

### 4a. Publishing (server side)

1. Build per-platform `.pyz` files into `packages/` using the filename
   convention above.
2. Run `tools/build_manifest.py`:

    ```bash
    cd backend/endpoint_agent
    python tools/build_manifest.py \
        --version 1.4.2 \
        --base-url  https://update.example.com/downloads \
        --notes     "RELEASE_NOTES.md" \
        --channel   stable
    ```

3. Upload every `.pyz` plus `packages/manifest.json` to the public download
   area that matches `--base-url`.

`manifest.json` schema (written by `build_manifest.py`, consumed by the
server `/api/agent/releases` endpoint, and parsed by `UpdateManifest.from_dict`
at `update.py:38`):

```json
{
  "schema_version": 1,
  "channel": "stable",
  "generated_at": "2025-01-15T10:00:00Z",
  "base_url": "https://update.example.com/downloads",
  "version": "1.4.2",
  "release_notes": "...",
  "active": true,
  "releases": [
    {
      "version": "1.4.2",
      "os": "linux",
      "arch": "x86_64",
      "filename": "system-update-linux-x86_64-1.4.2.pyz",
      "sha256": "deadbeefcafebabe...",
      "size": 3827412,
      "published_at": "2025-01-15T10:00:00Z",
      "download_url": "https://update.example.com/downloads/system-update-linux-x86_64-1.4.2.pyz",
      "url": "https://update.example.com/downloads/system-update-linux-x86_64-1.4.2.pyz",
      "release_notes": "...",
      "active": true
    }
  ]
}
```

### 4b. Applying (agent side)

The `update` subcommand in `__main__.py:239` does:

```
StagedUpdater(target_dir = ...)
  ├─ check_for_updates(manifest_url or <server>/api/agent/releases)
  │    ├─ GET manifest list
  │    ├─ UpdateManifest.from_dict per candidate
  │    └─ pick best where version > current_version and version >= min_version
  ├─ download(manifest)
  │    ├─ streaming GET to <staging>/<file>
  │    ├─ on-the-fly SHA256
  │    └─ abort if digest != manifest.sha256
  ├─ extract_package(archive)              — .zip / .tar* supported
  ├─ stage_apply(root, manifest)           — copy into staging + take backup
  └─ atomic_swap(manifest)
       ├─ copy staged → <target>.swap.<ts>
       ├─ os.replace(<target>, <target>.backup)
       └─ os.replace(swap, <target>)
```

Update check / apply can also be triggered manually:

```bash
# Linux example
sudo /opt/system-update/system-update update \
    --config /etc/system-update/config.json \
    --channel stable
```

Use `--check-only` to report without applying, or `--manifest <URL>` to fetch a
manifest from an absolute location. `--rollback-on-fail` (default: on) calls
`StagedUpdater.rollback()` after any error during `full_update()`.

The watchdog process (`run --watchdog`) restarts the worker after the swap,
effectively activating the new version on next heartbeat.

---

## 5. Uninstall

### Windows (elevated)
```powershell
net.exe stop  SystemUpdateSvc
sc.exe  delete SystemUpdateSvc
Remove-Item -Recurse -Force "$env:ProgramFiles\SystemUpdate"
Remove-Item -Recurse -Force "$env:ProgramData\SystemUpdate"
```

### Linux
```bash
sudo systemctl stop    system-update.service
sudo systemctl disable system-update.service
sudo rm -f             /etc/systemd/system/system-update.service
sudo systemctl daemon-reload
sudo rm -rf /opt/system-update \
            /etc/system-update \
            /var/lib/system-update \
            /etc/default/system-update
```

### macOS
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.system.update.plist
sudo rm -f      /Library/LaunchDaemons/com.system.update.plist
sudo rm -rf     "/Library/Application Support/SystemUpdate" \
                "/Library/Preferences/SystemUpdate" \
                "/Library/Logs/SystemUpdate"
```

The `uninstall` subcommand (`__main__.py:293`) only removes the local config
file, offline queue, and log files created by the agent itself from its own
working directory — it does **not** remove the service registration or install
tree because that requires OS-specific privileged steps (see commands above).

## Opt-in behavioral biometrics

The registered `biometrics` collector is sensitive and disabled by default. It requires the optional packages in `requirements-biometrics.txt`, an interactive desktop, explicit local configuration (`collectors.biometrics.enabled`), a server-side subject binding, and separately recorded local consent. Use `python -m endpoint_agent.biometrics --config agent_config.json --grant` for a visible decision, or `--withdraw` to revoke it. The authenticated heartbeat grants a short collection lease; offline/expired/revoked collection is stopped. Keyboard key identities and mouse coordinates are processed transiently in bounded volatile state but are never included in observations. Only summary durations, variability, speed and angles are serialized. Consult the backend README's Phase 3 section before enrollment or operational use; comparisons do not establish identity on their own.
