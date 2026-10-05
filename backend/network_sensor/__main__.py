"""Command line entry point for the passive network sensor."""
import argparse
import json
import os
import shutil
import time
from pathlib import Path

from .config import SensorConfig
from .engines import create_engine
from .health import HealthMonitor, SnmpNotifier
from .packets import CaptureError
from .pipeline import Pipeline, analyze_pcap
from .secure_store import SecureCaptureError, container_info, open_cipher, open_sink, read_encrypted_capture
from .verification import backend_report, benchmark_harness, run_verification


def write_report(path, report):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report), encoding="utf-8")
    temporary.replace(path)


def build_parser():
    parser = argparse.ArgumentParser(description="EFMTT passive network sensor")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--list-interfaces", action="store_true")
    modes.add_argument("--list-backends", action="store_true")
    modes.add_argument("--verify", action="store_true", help="verify the mirror port, VLANs and capture backend")
    modes.add_argument("--benchmark", action="store_true", help="measure decode throughput on synthetic traffic")
    parser.add_argument("--interface", help="capture interface, also used by --verify")
    modes.add_argument("--read", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/sensor"))
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--max-capture-mb", type=int, default=64)
    parser.add_argument("--backend", choices=("libpcap", "pfring", "dpdk"))
    parser.add_argument("--keyring-passphrase-env", default="EFMTT_KEYRING_PASSPHRASE",
                        help="environment variable holding the keyring passphrase")
    parser.add_argument("--verify-duration", type=int, default=10,
                        help="seconds to observe the capture point during --verify")
    return parser


def load_config(args):
    config = SensorConfig.model_validate_json(args.config.read_text()) if args.config else SensorConfig()
    if args.backend and args.backend != config.backend:
        config = config.model_copy(update={"backend": args.backend})
    return config


def run_offline(path: Path, config: SensorConfig, output: Path, args):
    """Analyse a recorded capture, decrypting it when it is a secure container."""
    if container_info(path).get("encrypted"):
        passphrase = os.environ.get(args.keyring_passphrase_env)
        cipher, key_id = open_cipher(config, passphrase or None)
        with read_encrypted_capture(path, cipher, key_id, config.encryption_context) as stream:
            report = analyze_pcap(stream, config.model_dump())
    else:
        with path.open("rb") as stream:
            report = analyze_pcap(stream, config.model_dump())
    write_report(output / "sessions.json", report)
    print(json.dumps(report["metrics"]))


def run_verification_mode(config: SensorConfig, interface, args, output: Path):
    report = run_verification(config, interface, duration=args.verify_duration)
    write_report(output / "verification.json", report)
    print(json.dumps({"verified": report["verified"], "reason": report.get("reason", ""),
                      "backend": report["preflight"]["backend"]["backend"],
                      "backend_available": report["preflight"]["backend"]["available"]}, indent=1))
    return 0 if report["verified"] else 1


def run_live(config: SensorConfig, interface: str, args, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    encrypted = config.encryption_enabled
    target = output / ("capture.efmcap" if encrypted else "capture.pcap")
    if target.exists():
        raise CaptureError(f"Use a new output directory to avoid overwriting {target.name}")
    passphrase = os.environ.get(args.keyring_passphrase_env) if encrypted else None

    notify = None
    if config.snmp_host:
        notify = SnmpNotifier(config.snmp_host, config.snmp_port,
                              os.environ.get(config.snmp_community_env, ""), config.snmp_enterprise_oid)
    monitor = HealthMonitor(config.idle_seconds, config.empty_seconds, config.backlog_ratio, config.min_disk_bytes)
    analytics_client = analytics_sink = None
    if config.analytics_server_url:
        from endpoint_agent.protocol import AgentClient
        from endpoint_agent.tls import transport_options
        from .analytic_stream import AnalyticSink
        token=os.environ.get(config.analytics_agent_token_env, '')
        if not token: raise CaptureError('Analytics agent token environment variable is unset')
        options=transport_options({'ca_bundle':config.analytics_ca_bundle},url=config.analytics_server_url)
        analytics_client=AgentClient(config.analytics_server_url,token,retries=0,timeout=2,queue_path=str(output/'analytics-offline.jsonl'),**options)
        analytics_sink=AnalyticSink(analytics_client,config.analytics_subject)
    capture = create_engine(config.backend, config.eal_args).open(interface, config.capture_filter(), config.promiscuous)
    pipeline = Pipeline(config.model_dump())
    started = time.monotonic()
    last_report = started - 5
    health_events, notification_errors, sink = [], 0, None
    limit = args.max_capture_mb * 1024 * 1024
    try:
        sink = open_sink(config, target, capture.linktype, passphrase)
        with sink:
            while time.monotonic() - started < args.duration:
                record = capture.next_packet()
                if record:
                    monitor.packet_seen()
                    if sink.size() + len(record[1]) + 16 > limit:
                        break
                    sink.write(*record[:3])
                    pipeline.enqueue(record)
                else:
                    time.sleep(0.01)
                now = time.monotonic()
                if now - last_report >= 5:
                    free = shutil.disk_usage(output).free
                    events = monitor.check(pipeline.queue.qsize(), pipeline.queue.maxsize, free, now)
                    health_events = (health_events + events)[-1000:]
                    for event in events:
                        if notify:
                            try:
                                notify(event)
                            except OSError:
                                notification_errors += 1
                    report = pipeline.report(timestamp=time.time())
                    report["capture_statistics"] = capture.statistics()
                    report.update(health=health_events, notification_errors=notification_errors)
                    if analytics_sink:
                        try: analytics_sink.publish(report)
                        except Exception as error: report["analytics_error"] = type(error).__name__
                    write_report(output / "sessions.json", report)
                    last_report = now
                    if free < config.min_disk_bytes:
                        break
    except KeyboardInterrupt:
        pass
    finally:
        capture_statistics = capture.statistics()
        capture.close()
        pipeline.close()
        report = pipeline.report()
        report["capture_statistics"] = capture_statistics
        report.update(health=health_events, notification_errors=notification_errors)
        if encrypted and sink is not None and sink.manifest:
            report["capture"] = sink.manifest
        if analytics_sink:
            try: analytics_sink.publish(report)
            except Exception as error: report["analytics_error"] = type(error).__name__
            finally: analytics_client.close()
        write_report(output / "sessions.json", report)
    print(json.dumps(report["metrics"]))
    return 0


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.interface and (args.read or args.list_interfaces or args.list_backends or args.benchmark):
        parser.error("--interface can be used for live capture or --verify only")
    if not 1 <= args.duration <= 86400 or not 1 <= args.max_capture_mb <= 1024:
        parser.error("Duration must be 1-86400 seconds and capture limit 1-1024 MB")
    if not 1 <= args.verify_duration <= 300:
        parser.error("Verification duration must be 1-300 seconds")
    if args.list_backends:
        print(json.dumps([backend_report(name) for name in ("libpcap", "pfring", "dpdk")], indent=1))
        return 0
    config = load_config(args)
    args.output.mkdir(parents=True, exist_ok=True)
    if args.list_interfaces:
        engine = create_engine(config.backend, config.eal_args)
        try:
            print(json.dumps(engine.devices(), indent=1))
        finally:
            engine.close()
        return 0
    if args.benchmark:
        print(json.dumps(benchmark_harness(config, count=args.max_capture_mb * 1000), indent=1))
        return 0
    if args.verify:
        return run_verification_mode(config, args.interface, args, args.output)
    if bool(args.read) == bool(args.interface):
        parser.error("Choose exactly one of --read or --interface")
    if args.read:
        run_offline(args.read, config, args.output, args)
        return 0
    return run_live(config, args.interface, args, args.output)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CaptureError, SecureCaptureError, ValueError, OSError) as error:
        raise SystemExit(str(error))
