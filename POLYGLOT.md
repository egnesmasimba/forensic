# Language components

Python remains the application backend and integration layer. These additions have
specific jobs and use existing files, API contracts, or authentication services.
They do not require a backend rewrite.

Every component below is built and tested by `.github/workflows/polyglot.yml`.

## TypeScript: report builder

`frontend/src/report-builder.ts` is the source for the served
`backend/app/static/report-builder.js`. It preserves the report filters, saved
definitions, drilldown, external export links, and SQL status summary.
From `frontend`, run `npm ci --ignore-scripts` then `npm run build`.
Commit both the source and generated JavaScript. Edit the TypeScript source for
future report builder changes. This migrates this component, not the entire UI.

## TypeScript: network search

`ui/network-search.ts` is the source for the served
`backend/app/static/network-search.js`. It types the four reconstructed-search
responses (findings, sessions, files, commands) that the shared untyped `api()`
helper would otherwise leave unconstrained.

It builds as a separate TypeScript project, `frontend/tsconfig.ui.json`, which
pins `rootDir` to `ui/`. This is deliberate: adding `ui/` to the report builder's
`include` would change the inferred common root and emit `static/src/...` and
`static/ui/...` instead of the flat paths `index.html` loads. The two projects
are also kept separate so the ambient `declare function` helpers (`$`, `el`,
`api`, `run`, `openCapture`) are not declared twice in one program.

`npm run build` compiles both projects; `npm run check` type-checks both.

## Go: sensor report summary

From `tools/sensor-report`, run `go test ./...` and `go build .`.
Run the binary with the path to the Python network sensor's `sessions.json`.
It emits JSON counts and captured payload totals grouped by protocol, without
endpoint identities. Input is limited to 32 MiB and integer overflow is rejected.
These totals cover the retained sessions in the report, not all traffic ever
observed by the sensor. This is a local reporting tool, not a deployed agent.

## Go: capture inventory

`tools/sensor` counts records in a classic PCAP **without copying or printing any
packet bytes**. Run `go test ./...` and `go build .` from that directory, then
pass the path to a capture file.

Bounds are 10,000 records and 8 MiB; a record claiming more than 65535 bytes is
rejected as malformed rather than allocated or skipped. The output is counts, the
link type, and whether the run stopped at the byte budget, the packet budget, or
end of file. It reads a file and never opens a capture device.

This is deliberately not a copy: use `tools/capture_bound` when a bounded extract
is needed.

## Rust: capture validation

From `tools/pcap-check`, run `cargo test --locked` and
`cargo run --locked -- ../../backend/network_sensor/example-http.pcap`.
The checker validates classic PCAP headers, timestamp fractions, snapshot limits,
supported link types and complete record payloads before printing counts. It
streams in 8 KiB chunks, rejecting captures above one million records or one GiB
of captured payload. It supports microsecond/nanosecond and both byte orders.
PCAPNG and encrypted capture containers remain handled by the Python sensor.
This optional command does not replace the server's own input validation.

## Rust: bounded capture extraction

`tools/capture_bound` copies a bounded **prefix** of a classic PCAP into a new
capture file:

```text
capture_bound <input.pcap> <output.pcap>
```

Bounds are 1,000 records and 1,000,000 captured bytes, and a record that would
cross the byte budget is excluded rather than partially written, so the output is
always a structurally complete capture. It refuses to write over its own input.
The result is reported as JSON with a `stop_reason` of `end`, `packet budget`, or
`byte budget`.

Unlike `tools/sensor` this does emit packet bytes, because its purpose is to
produce a shareable extract. Treat the output as evidence-derived data subject to
the same handling rules as the source capture.

## C: Linux PAM ticket collector

`native/pam-ticket/pam_forensic_ticket.c` is a Linux PAM shared module that prompts
for an IAM access ticket without echoing it, validates its characters, places it
in `PAM_AUTHTOK`, and erases its temporary buffer. It returns `PAM_IGNORE` on
successful collection and cannot authenticate an account on its own.

Build on Linux with PAM development headers:

```sh
cc -std=c11 -Wall -Wextra -Werror -fPIC -shared native/pam-ticket/pam_forensic_ticket.c -lpam -o pam_forensic_ticket.so
```

On Windows, `native/pam-ticket/test-windows.cmd` builds it against the PAM test
doubles in `native/pam-ticket/tests/stubs` and runs the unit checks, without
linking real PAM.

It is intended to precede the existing root-configured Python `pam_bridge.py`
via `pam_exec.so expose_authtok`, which performs the actual server-side ticket
redemption, session validation and resource authorization. A dedicated test PAM
service would use the collector control `[ignore=ignore default=die]` followed
by a `required` pam_exec bridge. No host PAM configuration has been installed or
modified. Validate the complete stack in a disposable Linux environment before
deployment; compilation alone does not establish authentication correctness.
See the [PAM conversation API](https://www.man7.org/linux/man-pages/man3/pam_prompt.3.html)
and [pam_exec documentation](https://www.man7.org/linux/man-pages/man8/pam_exec.8.html).

## C: PAM ticket redeem client

`native/pam_ticket.c` is the other half of that flow and is **not** a PAM module.
It never calls `pam_get_authtok` and never reads or stores an account password.
It reads the ticket that `pam_exec.so expose_authtok` placed on standard input
and redeems it over HTTPS.

`--self-test` runs the offline checks only, on any platform:

```sh
cc -std=c11 -Wall -Wextra -Werror native/pam_ticket.c -o pam-ticket && ./pam-ticket --self-test
```

On Windows the redeem path uses WinHTTP and must link `winhttp.lib`. Use
`native/build-windows.cmd`, which locates a Visual Studio 2022 environment,
compiles under `/W4 /WX`, and runs the self-test. Objects are directed under
`native/build/` so they do not land in the caller's working directory.

Configuration comes from a JSON file named as the single argument, holding
`server`, `resource`, and a `service_key` of at least 32 characters. The server
URL is rejected unless it is a bare `https://` origin: credentials in the URL,
custom ports, path components, and plain `http` are all refused, so the ticket
cannot be redirected to another host. `PAM_TYPE` must be `auth` and `PAM_USER`
must be a plausible account name.

## C++: evidence integrity verification

`native/evidence-hash` streams a read-only evidence file through SHA-256. It uses
Windows BCrypt on Windows and OpenSSL EVP on other platforms. Run:

```text
evidence-hash FILE [EXPECTED_SHA256]
```

Compare with the backend attachment's `sha256` value. A mismatch or read error
exits with status 1; malformed arguments exit with status 2. The tool hashes file
contents only; it does not establish provenance or replace chain-of-custody records.
Build with CMake, or use `build-windows.cmd` for the installed Visual Studio 2022
Community toolchain. The Python test cross-checks empty, small and multi-buffer
inputs and verifies mismatch and missing-file failures.

## SQL: local workload reporting

`database/reporting_views.sql` defines case workload and alert-channel summaries.
`python database/reporting.py REPORTING_COPY.sqlite` creates temporary views on
a read-only connection and prints JSON; it does not modify the source database.
This is an administrator's local tool, outside application role enforcement.
Use an appropriately access-controlled reporting copy. Aggregate counts alone
do not provide anonymity, particularly for small populations.

The view definitions are rewritten to `CREATE TEMP VIEW` case-insensitively and
idempotently, and the run then confirms the views exist in `sqlite_temp_master`.
A SQL file that drifts into a form the rewrite cannot convert raises rather than
quietly attempting a write against the evidence database.

## Verification, 4 October 2026

Local, this machine:

- TypeScript: both projects compile under `strict`, and both committed
  JavaScript artifacts are reproduced byte-for-byte by a fresh build.
- Existing Python report API regression suite: 5 passed.
- `database`: 5 passed, covering the view rewrite and unchanged-source checks.
- Rust `pcap-check`: 3 unit tests passed; sample PCAP produced 4 packets /
  303 captured bytes; Clippy clean.
- Rust `capture_bound`: unit test passed; Clippy clean under `-D warnings`.
- Go `sensor-report`: `go vet`, tests, and build passed; the Python contract and
  CLI-failure cross-check passed.
- Go `sensor`: `go vet`, 3 tests, and build passed.
- C++: Windows build and cross-language SHA-256/failure checks passed.
- C `pam_forensic_ticket`: Windows stub build passed 10 unit checks.
- C `pam_ticket`: `/W4 /WX` build and `--self-test` passed on Windows.
- SQL: aggregation, unchanged source database, and missing-file rejection passed
  against both a synthetic fixture and a copy of the real database.

Known limits:

- Linux PAM compilation, live PAM deployment, and end-to-end authentication
  remain unverified; CI compiles and self-tests them on Linux only.
- CI has not been executed on a hosted runner from this machine.
- `tools/sensor-report`, `tools/sensor`, `tools/pcap-check`, and
  `tools/capture_bound` handle classic PCAP only. PCAPNG and encrypted capture
  containers remain the Python sensor's responsibility.

## Verification follow-up, 5 October 2026

Both Go tools passed vet, tests and builds on Windows, using a project-local
cache. The Python sensor report contract and CLI failure checks passed.

CI now runs `sudo python3 native/pam-ticket/tests/linux_stack.py`. It builds
against real Linux PAM and uses pam_start_confdir with a private temporary
service directory. Four scenarios exercise valid pam_exec ticket handoff,
short/invalid ticket rejection, and downstream denial. No host PAM configuration
is modified. The downstream executable is a test double, so backend redemption,
TLS, authorization and deployment are not certified by this harness.

Python syntax validation passed locally. Linux compilation/execution and hosted
CI remain unverified; no WSL distribution is installed on this workstation.
The complete collector/pam_exec/backend deployment remains pending.

Completion follow-up: 13 IAM tests and 9 new PAM redemption rejection tests
passed locally on 5 October 2026. Hosted CI installs backend dependencies and
runs both suites. On a disposable Linux checkout with Go, Python dependencies,
PAM development headers and a C compiler, run `bash tools/verify-linux.sh` to
execute backend authorization, real PAM handoff and Go verification together.
This entry point still tests native handoff and backend authorization separately;
it does not claim a complete live PAM/HTTPS/backend deployment. Hosted execution
remains pending because this folder has no Git repository/remote and this host
has no installed Linux distribution or Docker runtime.

## Ubuntu verification completed — 5 October 2026

Ubuntu 24.04 on WSL 2 is now available; earlier missing-Linux limitations are
superseded. Both native C components compiled with strict warnings. The collector
passed 10 stub checks and 4 real PAM handoff checks; the redeem client self-test
passed. The Linux IAM/PAM suite passed 23 tests. The live integration test passed
again after adding TLS trust and configuration-permission rejection checks.

backend/tests/test_pam_linux_live.py exercises the real collector, pam_exec,
Python bridge and a temporary HTTPS backend with disposable accounts. It checks
success, single-use tickets, expiry, wrong identity, revoked approval, untrusted
TLS and unsafe service-secret permissions. Run it on disposable root Linux with
FORENSIC_LINUX_PAM_TEST=1 and a /tmp pytest base directory. It never modifies
/etc/pam.d. The bridge now accepts an optional ca_bundle in its root-controlled
JSON configuration for private enterprise certificate authorities; certificate
and hostname verification remain enabled. The CA file must be administratively
managed and protected against unauthorized changes.

CI includes this live test. Hosted CI execution still needs a configured Git
repository/remote; no production authentication service has been installed.
