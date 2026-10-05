import queue
import threading

from .packets import CaptureError, FragmentTable, decode_packet, pcap_records
from .sessions import SessionTable
from .traffic_analysis import analyze_traffic


class Pipeline:
    def __init__(self, config=None):
        config = config or {}
        self.analysis_config = config
        self.queue = queue.Queue(maxsize=config.get("queue_capacity", 512))
        self.table = SessionTable(enabled=config.get("protocols"), port_map=config.get("port_map"),
                                  max_sessions=config.get("max_sessions", 256),
                                  bytes_per_direction=config.get("bytes_per_direction", 65536),
                                  iso_fields=config.get("iso_field_lengths"),
                                  **{name: config[name] for name in ("session_idle_seconds", "session_max_seconds",
                                     "closed_session_grace_seconds", "max_completed_sessions") if name in config})
        self.lock = threading.Lock()
        self.fragments = FragmentTable()
        self.received = self.processed = self.dropped = self.malformed = self.unsupported = self.peak = 0
        self.error = None
        self.thread = threading.Thread(target=self._work, name="sensor-packet-worker", daemon=True)
        self.thread.start()

    def enqueue(self, record, block=False):
        self.received += 1
        try:
            self.queue.put(record, block=block)
            self.peak = max(self.peak, self.queue.qsize())
        except queue.Full:
            self.dropped += 1

    def _work(self):
        while True:
            record = self.queue.get()
            try:
                if record is None:
                    return
                try:
                    packet = decode_packet(*record)
                    if packet:
                        ready = [packet]
                    else:
                        ready = self.fragments.consider(*record, capture_source=getattr(record, "capture_source", "default"))
                    if ready:
                        with self.lock:
                            for item in ready:
                                item.capture_source = getattr(record, "capture_source", "default")
                                self.table.consume(item)
                    elif ready is None:
                        self.unsupported += 1
                except CaptureError:
                    self.malformed += 1
                self.processed += 1
            except Exception as error:
                self.error = f"{type(error).__name__}: {error}"
            finally:
                self.queue.task_done()

    def report(self, timestamp=None):
        with self.lock:
            if timestamp is not None and not self.queue.unfinished_tasks:
                self.table.expire(timestamp)
            sessions = self.table.report()
            lifecycle = {"active_sessions": len(self.table.sessions), "retired_sessions": self.table.retired,
                         "capacity_rotations": self.table.capacity_rotations,
                         "completed_sessions_omitted": self.table.completed_omitted}
        return {"metrics": {**lifecycle, "received": self.received, "processed": self.processed, "queue_depth": self.queue.qsize(),
                            "queue_peak": self.peak, "dropped": self.dropped, "malformed": self.malformed,
                            "unsupported": self.unsupported, "session_overflow": self.table.overflow, "worker_error": self.error},
                "sessions": sessions, "traffic_analysis": analyze_traffic(sessions, self.analysis_config)}

    def close(self):
        self.queue.put(None)
        self.queue.join()
        self.thread.join(timeout=5)
        with self.lock:
            self.table.finish()


def analyze_pcap(stream, config=None, max_packets=100000):
    pipeline = Pipeline(config)
    try:
        for count, record in enumerate(pcap_records(stream), start=1):
            if count > max_packets:
                raise CaptureError(f"Capture exceeds {max_packets} packets")
            pipeline.enqueue(record, block=True)
    finally:
        pipeline.close()
    if pipeline.error:
        raise CaptureError("Packet worker failed: " + pipeline.error)
    return pipeline.report()
