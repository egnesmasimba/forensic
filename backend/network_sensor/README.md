# Network sensor: implementation and operation

This is a bounded passive sensor for Windows Npcap, with a portable libpcap adapter and PCAP/PCAPNG offline processing. The network sensor runs independently of the web server. The investigator interface provides **Network captures** for uploading and reviewing its output. It does not start interface capture from a web request.

## Windows live capture

Install Npcap from its [official site](https://npcap.com/). The driver is not bundled or installed automatically. Run from the `backend` directory:

```powershell
.runtime/Scripts/python.exe -m network_sensor --list-interfaces
```

Select the exact interface name returned by this command. Connect that NIC to the switch SPAN/mirror destination or a passive tap output. Configure the switch/tap to copy both traffic directions and any required VLANs. Setting promiscuous mode cannot itself configure a switch or expose traffic that the NIC does not receive. Capture permission depends on the installed Npcap policy.

```powershell
.runtime/Scripts/python.exe -m network_sensor --interface '\Device\NPF_{REPLACE-WITH-INTERFACE-GUID}' --config network_sensor/example-config.json --output data/sensor-run-001 --duration 60 --max-capture-mb 64
```

Use a new output directory for each run. Capture stops at the duration, file-size limit, low-disk threshold, or Ctrl+C. `capture.pcap` contains the original packets. `sessions.json` is refreshed every five seconds and finalized on exit; it includes reconstructed directions, messages, terminal snapshots, health events, queue metrics, and Npcap statistics where available. Dropped packets from the processing queue are counted separately from driver drops. There is no packet injection.

The current machine has no Npcap library at the standard path. The live adapter cannot be validated here until Npcap and a capture interface are available. PF_RING and DPDK adapters require their Linux native libraries and deployment prerequisites; use `--list-backends` to inspect availability. Their presence in code does not verify hardware performance.

## Offline processing and web review

```powershell
.runtime/Scripts/python.exe -m network_sensor --read path/to/capture.pcap --config network_sensor/example-config.json --output data/offline-run-001
```

The standalone offline command produces `sessions.json`. In the web app, sign in and open **Network captures**, select protocols, and upload a PCAP or timestamped PCAPNG up to 10 MB. Upload analysis is limited to 100,000 packets, 256 active sessions and 256 completed sessions, 64 KB of stored TCP segments per direction, 2,048 segments per direction, and 100 UDP datagrams per session. Further data is reported as dropped, omitted, or truncated. Active sessions rotate at capacity instead of rejecting new flows. Completed records retain reconstructed data until the completed-record limit is exceeded; `completed_sessions_omitted` counts older records removed from the report. Original packets remain in the PCAP. Read-only viewers may inspect existing captures; administrators and investigators may upload captures and preview layouts. The system preserves original uploaded packets with an SHA-256 digest and authenticated download.

Classic PCAP supports little/big endian microsecond/nanosecond headers. Supported link layers are Ethernet with VLAN tags, raw IP, Linux cooked v1/v2. IPv4 and IPv6 TCP/UDP are parsed, including a bounded IPv6 extension chain. Complete, consistent IPv4 fragments are reassembled before the session is built. Non-IP SNA link-layer decoding and jumbo IPv6 payloads are not implemented. Unsupported packets are counted. The original capture still preserves their bytes.

## Reconstruction and decoding coverage

TCP is reconstructed independently in both directions, using observed SYN sequence numbers when available and preserving sequence-number wrap. Out-of-order packets and retransmissions are handled within configured bounds. Missing bytes stop decoding at the first gap. Conflicting overlaps suppress application decoding. Truncation, gaps, conflicts, and missing SYNs are visible in the UI. A new opening SYN starts a new session when a tuple is reused. A flow whose opening SYN was not captured starts at the lowest observed sequence and stops at the first gap. This implementation is not a complete TCP endpoint emulator.

Protocol selection controls which sessions appear in the report; raw capture still records the configured BPF traffic. Use `bpf` to restrict captured packets and `port_map` for vendor ports. The example mappings are examples for a test deployment, not universal protocol ports. Classification records whether it came from a configured port, observed signature/negotiation, or a default port hint. A port hint is not proof of protocol identity.

- **HTTP/Web Services:** HTTP/1.x start lines and headers; Content-Length boundaries are honored, and a complete chunked body is skipped so the next plaintext message can be read. The body is not stored. A cleartext request also records the host and path, without the query string. Credential and cookie headers are redacted in indexed metadata. Cleartext HTTP/2 frames record length, type, and stream id. HPACK blocks, HTTP/3, body-value interpretation, web-service schemas, and encrypted content stay unavailable.
- **FIX:** SOH-delimited FIX framing with BodyLength and CheckSum validation. A complete header requires tags 8, 9, 35, 49, 56, 34, and 52. Encoded-data tags are recorded by length. Business validation, dictionaries, and session-level sequencing remain pending.
- **FTP:** Plaintext control lines, with password/account command redaction. A plaintext PORT, PASV, or EPSV endpoint is matched to the reconstructed data-channel bytes in the same capture. A RETR, STOR, or STOU name is recorded with a short plaintext preview. AUTH TLS, AUTH SSL, and PROT P mark the transfer encrypted and leave the bytes undecoded.
- **Telnet/VT100:** Telnet negotiation stripping and a limited 24x80 renderer for printable text, positioning, erase-display, erase-line, saved and restored cursor, CR/LF/backspace/tab. Unsupported terminal controls produce partial screens. The rendering applies to each direction; the source endpoint is displayed so client keystrokes are not mistaken for server screens. SSH stays banner-only.
- **TN3270/TN3270E:** Telnet negotiation is decoded and typed, including the `TERMINAL-TYPE`, `DEVICE-TYPE`, and TN3270E function sub-negotiations. TN3270E record headers, response/request flags, and sequence numbers are decoded. The record start is located by requiring a header chain that runs exactly to the end of the stream, so an interleaved negotiation block cannot hide records and ordinary 3270 data is never turned into invented records. When TN3270E is not negotiated, IAC EOR framing is used instead. The data stream is tokenised against the published 3270 order set including the two-byte `DO` forms (`SBA`, `EUA`, `SF`, `SFE`, `MF`, `IC`, `RA`, `PT`, `GE`, `SA`) and rendered into a screen buffer with field attributes, extended and highlighted colours, and cursor position. Geometry follows the negotiated display model. Fields marked non-display, or hidden by highlighting, are masked in the rendered rows so that a screen or indexed search result does not disclose them; the raw characters remain in the buffer, in the per-record hex, and in the decoded orders. Unassigned order and attribute codes are reported numerically with their raw bytes instead of being given an invented name. Configure the port explicitly where terminal negotiation is absent.
- **TN5250:** A stored 24x80 screen is reconstructed from clear-unit and write-to-display orders (SBA, IC, MC, RA, EA, and SF) on a synthetic record. Structured fields, SNA, and MPTN are not reconstructed, and full 5250 coverage against a real host is not claimed.
- **HTTPS and SSH:** TLS record headers and SSH identification banners only. Passive capture does not decode encrypted content.
- **SMB:** SMB1/SMB2 signatures, command names, and limited message-ID header metadata. File bytes stay in the original capture. Operations, authentication, and encrypted SMB payloads remain pending.
- **Oracle SQLNET, DB2 DRDA, and MS SQL TDS:** A UTF-16LE TDS SQL batch joined across packets, an ASCII statement span inside an Oracle data packet, and a DRDA DSS code point can be extracted. Encrypted variants stay metadata-only. Parameter values are not decoded.
- **IBM MQ:** A TSH segment records its length, and the ASCII body is kept when a big-endian MQMD format is MQSTR. Other TSH bodies stay opaque. **MSMQ:** the base header records version, signature, packet size, and priority; the user message stays opaque. **Oracle Forms:** a configured port identifies the session and the recording stays opaque. **SWIFT:** MT block lengths and tag text are recorded when the message starts with `{1:}`. **ISO 8583:** the MTI and which bitmap fields are present are recorded. Values are read only for fields whose widths are supplied in `iso_field_lengths`. Other values stay opaque.
- **SNA and Enterprise Extender:** The Enterprise Extender CEE signature is recognised, and the nested SNA transport header (FID, TH type, RH-present flag) and request header (RID, RU name, RSRC, sequence) are decoded, along with length-coded name/address fields such as `CLASSDR` and LU names decoded from EBCDIC CP037. BIND, UNBIND, and ACTLU are named, and the following bytes stay an uninterpreted hex preview. Unknown FIDs and RU codes are reported numerically. LU session state and non-IP SNA link layers are not decoded. IBM Enterprise Extender UDP ports 12000–12004 are recognized as hints.

Screens are reconstructed from bounded captured streams and included in the five-second live report. A continuously streaming browser screen viewer is not implemented. Raw captures and payload bytes may contain sensitive content: uploaded captures are protected by app authentication. The sensor supports optional encrypted capture containers when a keyring is configured; reports and uploads are not covered by that container encryption. No court-admissibility or signature claim is made.

## Layout import subsets

The **Network captures** layout preview imports sequential fixed-width declarations and can decode supplied Base64 message bytes. Unsupported declarations fail explicitly. The preview returns a canonical JSON layout. Save a named, immutable version with a protocol, source direction (endpoint 0/1 in sorted address/port order, or both), stream offset, encoding, and byte order. Saved versions persist in the database and can be enabled or disabled. Administrators and investigators may save or toggle them; viewers can read the library and decoded results. To change a declaration, save a new version rather than rewriting an old one.

Active versions are automatically applied when a capture is opened. Interpretation starts after the selected byte offset and reads repeated fixed-size records from a contiguous TCP direction. It skips directions with a missing SYN, gaps, conflicting overlaps, or truncation, and does not apply to HTTPS/SSH or UDP. Protocol binding and byte offset must match the application's framing. A saved layout can use a configured 2- or 4-byte length prefix and a fixed envelope skip. The sensor does not infer that framing on its own. Results retain layout ID/version, source direction, stream offsets, trailing-byte count, invalid-record errors, and resource-limit status.

Original capture bytes and stored sensor reports stay intact. Layout results are recomputed using the currently enabled library whenever a capture is opened, so disabling a version removes that interpretation from the view. The library holds at most 100 versions, with at most 100 fields per saved version. Decoding is limited to 100 records per binding/direction and a shared report budget of 500 records / 1 MB of interpreted bytes. A length prefix of 2 or 4 bytes, plus up to 32 envelope bytes, can frame each record on a complete TCP direction. Other compiler padding and inferred envelopes stay rejected.

- COBOL: flat `PIC X(n)` or unsigned `PIC 9(n)` DISPLAY fields; CP037 is available for EBCDIC exports. The `cobol-ibm` dialect adds COMP sizes without SYNC and COMP-3 packed decimals. REDEFINES, OCCURS, and nested groups stay rejected. Plain `cobol` still rejects COMP-3.
- C: `char name[n];` and fixed-width `int8_t`/`uint8_t` through 64-bit integer declarations. The plain dialect assumes contiguous packed bytes; the caller selects byte order. The `c-msvc` dialect aligns 2-, 4-, and 8-byte fields and pads the struct. Pointers, nesting, unions, and variable arrays stay rejected.
- VB: `Name As String * n` single-byte fixed strings. Native UTF-16 or another compiler's UDT layout is not inferred.

## Health alerts and SNMP

Health monitors include no captured packets for `idle_seconds`, a queue empty for `empty_seconds`, queue occupancy at `backlog_ratio`, and disk space below `min_disk_bytes`. Empty queue and idle can be normal on quiet networks; tune thresholds accordingly. Events include recovery transitions and repeat active conditions at most every five minutes. At a live low-disk threshold the sensor stops recording. Health output is bounded to the latest 1,000 events.

Set `snmp_host` in the config to opt into SNMPv2c trap delivery, and set the named environment variable for the community. No notification is sent unless configured. `snmp_enterprise_oid` must be replaced with your organization's enterprise OID: the example `1.3.6.1.4.1.32473.1` is for documentation, not a production registration. Notification suffixes are `.1` no-capture, `.2` empty queue, `.3` backlog, and `.4` low disk; recovery uses the same suffix with a recovered status. Mandatory sysUpTime.0 and snmpTrapOID.0 bindings are present. Delivery failures are counted; UDP delivery has no acknowledgement. SNMPv3 authentication/encryption and a registered MIB remain pending.

## References used

- [Npcap API and mirror-port/promiscuous capture](https://npcap.com/guide/wpcap/pcap.html)
- [TN3270E framing, RFC 2355](https://datatracker.ietf.org/doc/html/rfc2355)
- [5250 Telnet interface, RFC 1205](https://datatracker.ietf.org/doc/html/rfc1205)
- [SNMPv2 protocol operations, RFC 3416](https://www.rfc-editor.org/rfc/rfc3416)
- [FIX TagValue specification](https://www.fixtrading.org/packages/fix-tagvalue-encoding-technical-specification/)
- [IBM Enterprise Extender ports](https://www.ibm.com/support/pages/enterprise-extender-and-vpn-connectivity)

Session lifecycle settings: `session_idle_seconds` (300), `session_max_seconds` (3600), `closed_session_grace_seconds` (5), and `max_completed_sessions` (256). Expiry uses capture timestamps; live reports also expire idle sessions when the processing queue is drained. One FIN is a half-close; both FINs or a reset mark a connection closed. Records include `finalized` and `termination_reason` (idle, duration, closed, connection_reuse, capacity, or capture_end). Duration/capacity continuations without a new SYN are midstream and cannot qualify for complete-stream layout decoding. Final shutdown drains the queue before finalizing active sessions.

## Live analytics bridge

Live capture optionally publishes packet and transport-payload byte deltas and selected evidence-derived facts through an enrolled endpoint token. Set `analytics_server_url`, `analytics_subject`, optional `analytics_ca_bundle`, and the environment-variable name `analytics_agent_token_env` in sensor JSON. The default variable is `ZANAQ_ANALYTICS_AGENT_TOKEN`; store the token in that environment variable rather than configuration or report files. Delivery follows the endpoint client's TLS verification policy, queues offline summaries beside the capture, and never sends packet bodies. Every five-second report can drive server analytic rules, behavioral baselines and library rules. The capture output's `analytics_error`, if present, identifies a delivery failure by exception type. Driver/backend availability and capture permissions are unchanged; this bridge does not start capture from a web request.


## Phase 1 capture interoperability and recording reliability

The upload screen and `--read` command auto-detect PCAPNG from its bytes. Timestamped Enhanced Packet Blocks and obsolete Packet Blocks support little- and big-endian sections, decimal/binary timestamp resolution, signed interface time offsets, and multiple link types. Sessions, fragmented datagrams and FTP data-channel matching stay separated by section/interface; the source appears in session details. Original uploads, hashes, and downloads preserve every input byte. Unknown metadata blocks are skipped; decryption secrets are never used to decrypt traffic.

The reader bounds each block to 2 MB, each section to 64 interfaces, and each file to one million blocks, in addition to existing packet/session/upload limits. It rejects malformed lengths, undefined interfaces, unsupported packet link types, and Simple Packet Blocks without timestamps. This avoids assigning invented times to evidence. Nanosecond input is accepted, but timestamps use floating-point seconds internally, so exact nanosecond precision is not guaranteed. See the [PCAPNG format draft](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html) for the source format.

Verify an explicit capture interface before a live run:

```powershell
.runtime/Scripts/python.exe -m network_sensor --verify --interface '\Device\NPF_{REPLACE-WITH-INTERFACE-GUID}' --verify-duration 10 --output data/verify-run-001
```

Verification duration is bounded to 1–300 seconds. `--verify` can use `--interface`; incompatible read/list/benchmark combinations are rejected. Ctrl+C finalizes an encrypted recording before propagating the interrupt to the capture loop. Encrypted files use exclusive creation to prevent overwriting existing evidence. Both storage modes count the PCAP header and per-packet record headers toward the capture limit; an encrypted container adds encryption overhead beyond that plaintext PCAP limit. A forced process termination or power loss before encrypted finalization is still not recoverable by this buffered format.
