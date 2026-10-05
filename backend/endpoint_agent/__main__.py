from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import logging
import logging.handlers
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from . import tls


def _setup_logging(level: str = "INFO", log_file: Optional[str] = None,
                   max_bytes: int = 5 * 1024 * 1024, backup_count: int = 3) -> None:
    root = logging.getLogger()
    try:
        lvl = getattr(logging, level.upper(), logging.INFO)
    except AttributeError:
        lvl = logging.INFO
    root.setLevel(lvl)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    has_console = any(isinstance(h, logging.StreamHandler) and h.stream is sys.stderr for h in root.handlers)
    if not has_console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(fmt)
        root.addHandler(ch)
    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(path),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except (OSError, ValueError) as exc:
            logging.warning("Cannot open log file %s: %s", log_file, exc)


def _load_config_from_args(args: argparse.Namespace):
    from .config import Config, ConfigError
    cfg = Config(args.config)
    try:
        cfg.load()
    except ConfigError as exc:
        logging.warning("Config load failed, using defaults: %s", exc)
    if args.server:
        cfg.set("server_url", args.server)
    if args.token:
        cfg.set("agent_token", args.token)
    return cfg


def _cmd_run(args: argparse.Namespace) -> int:
    from .config import ConfigError
    try:
        cfg = _load_config_from_args(args)
    except Exception as exc:  # noqa: BLE001
        logging.error("Setup failed: %s", exc)
        return 2
    log_cfg = cfg.get("logging") or {}
    _setup_logging(
        level=str(log_cfg.get("level", "INFO")),
        log_file=str(log_cfg.get("file")) if log_cfg.get("file") else None,
        max_bytes=int(log_cfg.get("max_bytes", 5 * 1024 * 1024)),
        backup_count=int(log_cfg.get("backup_count", 3)),
    )
    if args.watchdog:
        return _run_watchdog(cfg, args)
    return _run_worker(cfg, args)


def _make_worker_argv(cfg, args: argparse.Namespace) -> list[str]:
    py = sys.executable
    base = [py, "-m", "endpoint_agent", "run"]
    if args.config:
        base.extend(["--config", str(args.config)])
    srv = cfg.get("server_url")
    if srv:
        base.extend(["--server", str(srv)])
    tok = cfg.get("agent_token")
    if tok:
        base.extend(["--token", str(tok)])
    return base


def _run_watchdog(cfg, args: argparse.Namespace) -> int:
    from .watchdog import SubprocessWatchdog, WatchdogError
    argv = _make_worker_argv(cfg, args)
    stall = float(cfg.get("stall_timeout_seconds", 120))
    poll = float(cfg.get("poll_interval_seconds", 30))
    max_rph = int(cfg.get("max_restarts_per_hour", 6))
    stop_called = {"v": False}

    def _handle_signal(signum, frame):  # type: ignore[no-untyped-def]
        stop_called["v"] = True

    watchdog = SubprocessWatchdog(
        argv,
        cwd=Path.cwd(),
        stall_timeout_seconds=stall,
        poll_interval_seconds=min(5.0, poll),
        max_restarts_per_hour=max_rph,
    )
    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (AttributeError, ValueError, OSError):
        pass
    try:
        watchdog.start_background()
        while not stop_called["v"]:
            time.sleep(1.0)
    finally:
        watchdog.stop()
    return 0


def _run_worker(cfg, args: argparse.Namespace) -> int:
    from .protocol import AgentClient, ProtocolError
    try:
        from .collectors import CollectorManager
    except Exception:  # noqa: BLE001
        CollectorManager = None  # type: ignore[assignment, name-defined]

    stop = {"v": False}
    try:
        def _handle_signal(signum, frame):  # type: ignore[no-untyped-def]
            stop["v"] = True
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (AttributeError, ValueError, OSError):
        pass

    server = cfg.get("server_url", "")
    token = cfg.get("agent_token", "")
    if not server or not token:
        logging.error("server_url and agent_token must be configured to run worker")
        return 2
    # Resolve the transport once, so every client in this process authenticates
    # the server the same way, and record the resulting posture in the log.
    transport_settings = tls.settings_from_config(cfg.data)
    try:
        transport = tls.transport_options(transport_settings, url=str(server))
    except tls.TlsConfigError as exc:
        logging.error("Transport security refused: %s", exc)
        return 2
    logging.info("Transport security: %s", tls.describe(transport_settings, url=str(server)))
    qpath = cfg.get("offline_queue_path", None)
    qmax = int(cfg.get("offline_queue_max_mb", 100))
    poll = float(cfg.get("poll_interval_seconds", 30))
    hb = float(cfg.get("heartbeat_interval_seconds", 10))
    last_heartbeat = 0.0
    last_flush = 0.0

    from .response_actions import ResponseExecutor
    from .desktop_control import DesktopController
    response_config = {**cfg.get("response", {}), "server_url": str(server)}
    desktop = DesktopController(response_config)
    responder = ResponseExecutor(response_config, cfg.get("response.state_dir", str(cfg.path.parent / "response-state")), desktop=desktop)
    last_response_poll = 0.0
    mgr = None
    if CollectorManager is not None:
        try:
            from .collectors.catalog import load_collector_classes
            classes, import_errors = load_collector_classes()
            for mod, err in import_errors.items():
                logging.warning("Collector module unavailable: %s", err)
            # Every implemented collector is registered so its state is visible
            # in the heartbeat; those whose dependencies are missing report
            # themselves as unavailable rather than silently collecting nothing.
            mgr = CollectorManager(cfg.data.get("collectors") or {}, collectors=classes)
            mgr.start_all()
            if import_errors:
                logging.warning(
                    "Collector inventory incomplete: %d module(s) failed to import",
                    len(import_errors),
                )
        except Exception as exc:  # noqa: BLE001
            logging.warning("CollectorManager init failed: %s", exc)
            mgr = None

    notifier = None

    def _emit(events):  # type: ignore[no-untyped-def]
        try:
            if client.post_events(events) and notifier is not None:
                notifier.poll()
        except Exception as exc:  # noqa: BLE001
            logging.warning("Event delivery failed: %s", exc)

    try:
        with ExitStack() as deliveries:
            client = deliveries.enter_context(AgentClient(
            server_url=str(server),
            agent_token=str(token),
            queue_path=qpath,
            queue_max_mb=qmax,
            retries=0,
            timeout=10,
            allow_insecure_http=bool(transport_settings.get("allow_insecure_http", False)),
            **transport,
            ))
            from .education import EducationNotifier
            notifier = EducationNotifier(client)
            browser_client = None
            if cfg.get("browser_capture.enabled", False):
                browser_client = deliveries.enter_context(AgentClient(str(server), str(token), retries=0, timeout=10,
                    queue_path=cfg.get("browser_capture.queue_path") or str(cfg.path.parent / "browser-offline.jsonl"),
                    allow_insecure_http=bool(transport_settings.get("allow_insecure_http", False)),
                    **transport))
            while not stop["v"]:
                now = time.time()
                if now - last_heartbeat >= hb:
                    try:
                        status = {
                            "pid": os.getpid(),
                            "start_count": 1,
                        }
                        if mgr is not None:
                            status["collectors"] = mgr.status()
                        heartbeat = client.heartbeat(status)
                        from .biometric_capture import update_consent
                        update_consent(bool(heartbeat.get("biometrics_permitted")), lease_seconds=min(hb+5,30))
                        notifier.poll()
                    except ProtocolError as exc:
                        logging.warning("Heartbeat failed: %s", exc)
                    last_heartbeat = now
                if response_config.get("enabled", False):
                    if now - last_response_poll >= 2:
                        try:
                            instruction = client.response_request("GET", "/api/response/poll").get("command")
                            if instruction:
                                result = responder.execute(instruction)
                                client.response_request("POST", f"/api/response/commands/{instruction['id']}/result", result)
                        except Exception as exc:
                            logging.warning("Response command delivery failed: %s", exc)
                        last_response_poll = now
                    try:
                        frame = desktop.frame()
                        if frame:
                            session_id, payload = frame
                            client.response_request("POST", f"/api/replay/agent/sessions/{session_id}/frames", payload)
                        if desktop.closed:
                            client.response_request("POST", "/api/response/session-ended", desktop.closed)
                            desktop.closed = None
                    except Exception as exc:
                        logging.warning("Desktop recording unavailable: %s", exc)
                        if desktop.active:
                            desktop.stop({"session_id": desktop.active["session_id"]})
                if mgr is not None:
                    try:
                        events = mgr.flush_all()
                        if events:
                            _emit(events)
                    except Exception as exc:  # noqa: BLE001
                        logging.warning("Collector flush failed: %s", exc)
                if now - last_flush >= max(poll, 60.0):
                    try:
                        sent, total = client.flush_queue()
                        if browser_client:
                            browser_client.flush_queue()
                        if sent or total:
                            logging.info("Flushed offline queue: sent=%d remaining=%d", sent, total - sent)
                    except ProtocolError as exc:
                        logging.warning("Queue flush failed: %s", exc)
                    last_flush = now
                time.sleep(min(hb, poll, 1.0))
    finally:
        if desktop.active:
            desktop.stop({"session_id": desktop.active["session_id"]})
        if mgr is not None:
            try:
                mgr.stop_all()
            except Exception:  # noqa: BLE001
                pass
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    from .config import Config, ConfigError
    cfg = Config(args.config)
    try:
        cfg.load()
    except ConfigError:
        pass
    if args.server:
        cfg.set("server_url", args.server)
    if args.token:
        cfg.set("agent_token", args.token)
    if args.config:
        try:
            cfg.save(with_hash=True)
            logging.info("Config written to %s", cfg.path)
        except ConfigError as exc:
            logging.error("Save failed: %s", exc)
            return 1
    else:
        logging.info("Would persist server=%s token=%s", cfg.get("server_url"), bool(cfg.get("agent_token")))
    return 0


def _cmd_update(args: argparse.Namespace) -> int:
    from .config import Config, ConfigError
    from .update import StagedUpdater, UpdateError
    cfg = Config(args.config)
    try:
        cfg.load()
    except ConfigError:
        pass
    if args.server:
        cfg.set("server_url", args.server)
    if args.token:
        cfg.set("agent_token", args.token)
    server = cfg.get("update_url") or cfg.get("server_url", "")
    token = cfg.get("agent_token", "")
    version = cfg.get("current_version", "0.0.0")
    target = Path(args.target).resolve() if args.target else Path(__file__).parent.resolve()
    try:
        updater = StagedUpdater(
            target,
            server_url=str(server),
            agent_token=str(token),
            current_version=str(version),
            allow_insecure_http=bool(tls.settings_from_config(cfg.data).get("allow_insecure_http", False)),
            **tls.transport_options(tls.settings_from_config(cfg.data), url=str(server)),
        )
    except tls.TlsConfigError as exc:
        logging.error("Transport security refused: %s", exc)
        return 2
    manifest_url = args.manifest
    try:
        manifest = updater.check_for_updates(manifest_url=manifest_url or "", channel=args.channel)
    except UpdateError as exc:
        logging.error("Update check failed: %s", exc)
        return 1
    if manifest is None:
        logging.info("No updates available (current=%s)", version)
        return 0
    logging.info("Update available: %s -> %s", version, manifest.version)
    if args.check_only:
        return 0
    try:
        new_version = updater.full_update(manifest)
    except UpdateError as exc:
        logging.error("Update failed: %s", exc)
        if args.rollback_on_fail:
            logging.info("Attempting rollback...")
            if updater.rollback():
                logging.info("Rollback succeeded")
            else:
                logging.error("Rollback failed")
        return 1
    logging.info("Successfully updated to %s", new_version)
    try:
        cfg.set("current_version", new_version)
        cfg.save()
    except ConfigError:
        pass
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    from .config import Config
    cfg = Config(args.config)
    removed = 0
    if cfg.path.exists():
        try:
            cfg.path.unlink()
            logging.info("Removed config: %s", cfg.path)
            removed += 1
        except OSError as exc:
            logging.error("Cannot remove %s: %s", cfg.path, exc)
            return 1
    if args.remove_queue:
        qpath = Path.cwd() / "offline_queue.jsonl"
        if qpath.exists():
            try:
                qpath.unlink()
                logging.info("Removed queue: %s", qpath)
                removed += 1
            except OSError as exc:
                logging.warning("Cannot remove %s: %s", qpath, exc)
    if args.remove_logs:
        log = Path.cwd() / "agent.log"
        for cand in [log] + list(log.parent.glob(log.name + ".*")):
            if cand.exists():
                try:
                    cand.unlink()
                    removed += 1
                except OSError as exc:
                    logging.warning("Cannot remove %s: %s", cand, exc)
    logging.info("Uninstall complete; %d item(s) removed", removed)
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Report which collectors can actually collect here, and why not.

    Exit code 0 when every collector is usable, 1 when at least one is inert.
    This is a deployment check: a collector that is silently producing nothing
    is indistinguishable from a host with nothing to report.
    """
    from .collectors import current_os_tag, dependencies
    from .collectors.catalog import catalog_report

    report = catalog_report()
    as_json = bool(getattr(args, "json", False))
    collectors = report["collectors"]

    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Endpoint agent collector check ({current_os_tag()})")
        print("=" * 72)
        for entry in collectors:
            state = "OK     " if entry["available"] else "INERT  "
            flag = " (opt-in)" if entry["sensitive"] else ""
            print(f"[{state}] {entry['name']:<20}{flag}")
            if entry["unavailable_reason"]:
                print(f"           reason: {entry['unavailable_reason']}")
            elif entry["sensitive"]:
                print("           disabled by default; enable to collect")
        for mod, err in sorted(report["import_errors"].items()):
            print(f"[BROKEN ] {mod}\n           {err}")

        deps = report["dependencies"]
        missing = deps["missing_relevant"]
        print("-" * 72)
        if missing:
            print(f"Missing optional dependencies: {', '.join(missing)}")
            print(f"Install with: {deps['install_command']}")
        else:
            print("All optional dependencies relevant to this platform are installed.")
        inert = [e["name"] for e in collectors if not e["available"]]
        print(f"Collectors usable: {len(collectors) - len(inert)}/{len(collectors)}")

    inert = [e for e in collectors if not e["available"]]
    broken = report["import_errors"]
    if getattr(args, "strict", False):
        return 1 if (inert or broken) else 0
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpoint_agent",
        description="Endpoint agent core: collectors, transport, watchdog, updater.",
    )
    parser.add_argument("--config", default=None, help="Path to agent config JSON")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase logging verbosity")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run the agent (worker mode unless --watchdog)")
    p_run.add_argument("--server", default=None, help="Override server URL")
    p_run.add_argument("--token", default=None, help="Override X-Agent-Token value")
    p_run.add_argument("--watchdog", action="store_true", help="Run as supervisor, restarting worker subprocess")
    p_run.set_defaults(func=_cmd_run)

    p_ins = sub.add_parser("install", help="Persist initial configuration")
    p_ins.add_argument("--server", default=None, help="Server URL")
    p_ins.add_argument("--token", default=None, help="Agent token")
    p_ins.set_defaults(func=_cmd_install)

    p_upd = sub.add_parser("update", help="Check/apply staged auto-update")
    p_upd.add_argument("--server", default=None, help="Override server URL")
    p_upd.add_argument("--token", default=None, help="Override token")
    p_upd.add_argument("--target", default=None, help="Target directory (default: this package)")
    p_upd.add_argument("--manifest", default=None, help="Direct manifest URL")
    p_upd.add_argument("--channel", default="stable", help="Release channel")
    p_upd.add_argument("--check-only", action="store_true", help="Report, do not apply")
    p_upd.add_argument("--rollback-on-fail", action="store_true", default=True)
    p_upd.set_defaults(func=_cmd_update)

    p_un = sub.add_parser("uninstall", help="Remove local config/state")
    p_un.add_argument("--remove-queue", action="store_true", default=True)
    p_un.add_argument("--remove-logs", action="store_true", default=True)
    p_un.set_defaults(func=_cmd_uninstall)

    p_doc = sub.add_parser(
        "doctor",
        help="Report collector availability and missing optional dependencies",
    )
    p_doc.add_argument("--json", action="store_true", help="Emit the full report as JSON")
    p_doc.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any collector is unavailable",
    )
    p_doc.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.verbose >= 2:
        _setup_logging(level="DEBUG")
    elif args.verbose >= 1:
        _setup_logging(level="INFO")
    else:
        _setup_logging(level="WARNING")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
